//! Behaviour 1: the directional reference contract of ADR-0013.
//!
//! `Mailbox.spec.providerRef` and `MailIdentity.spec.mailboxRef` are
//! required, `MailProvider.spec.gatewayRef` is optional and singular, there is
//! no default gateway, and an invalid or dangling explicit reference is an
//! error rather than a fallback.

use mail_operator::model::{
    Authorization, AuthorizationMode, CorviGateway, GatewaySpec, Listener, Listeners, LocalRef,
    MailIdentity, MailIdentitySpec, MailProvider, MailProviderSpec, Mailbox, MailboxSpec,
    ObjectMeta, ParseError, ProviderRole, ResourceList, ResourceRequirements, StateBackend,
    StateSpec, parse_provider,
};
use mail_operator::ownership::{ProviderBinding, ResourceGraph};
use mail_operator::references::{ReferenceError, ResourceKey};

const NS: &str = "corvi-system";

fn key(name: &str) -> ResourceKey {
    ResourceKey::new(NS, name)
}

fn gateway(name: &str) -> CorviGateway {
    CorviGateway {
        metadata: ObjectMeta::new(NS, name),
        spec: GatewaySpec {
            replicas: 1,
            suspended: false,
            listeners: Listeners {
                http: Listener { enabled: true },
                smtp_submission: Listener { enabled: false },
            },
            authorization: Authorization {
                mode: AuthorizationMode::External,
                config_secret_ref: LocalRef::new("corvi-resource-server"),
            },
            state: StateSpec {
                backend: StateBackend::Ephemeral,
                existing_claim_name: None,
                connection_secret_ref: None,
            },
            resources: ResourceRequirements {
                requests: ResourceList {
                    cpu: Some("100m".to_owned()),
                    memory: Some("128Mi".to_owned()),
                    ephemeral_storage: None,
                },
                limits: ResourceList {
                    cpu: None,
                    memory: Some("512Mi".to_owned()),
                    ephemeral_storage: None,
                },
            },
        },
    }
}

fn provider(name: &str, gateway: Option<&str>) -> MailProvider {
    MailProvider {
        metadata: ObjectMeta::new(NS, name),
        spec: MailProviderSpec {
            gateway_ref: gateway.map(LocalRef::new),
            suspended: false,
            role: ProviderRole::Serving,
        },
    }
}

fn mailbox(name: &str, provider: Option<&str>) -> Mailbox {
    Mailbox {
        metadata: ObjectMeta::new(NS, name),
        spec: MailboxSpec {
            provider_ref: provider.map(LocalRef::new),
        },
    }
}

fn identity(name: &str, mailbox: Option<&str>) -> MailIdentity {
    MailIdentity {
        metadata: ObjectMeta::new(NS, name),
        spec: MailIdentitySpec {
            mailbox_ref: mailbox.map(LocalRef::new),
            address: Some(format!("{name}@example.com")),
            isolation: Some(mail_operator::IsolationMode::Dedicated),
        },
    }
}

#[test]
fn a_mailbox_without_a_provider_reference_is_rejected() {
    let mut graph = ResourceGraph::new();
    graph.insert_mailbox(mailbox("personal", None)).unwrap();

    let error = graph
        .resolve_mailbox(&key("personal"))
        .expect_err("a mailbox without a provider cannot be resolved");

    assert_eq!(
        error,
        ReferenceError::MissingRequiredReference {
            kind: mail_operator::model::ResourceKind::Mailbox,
            field: "spec.providerRef",
        }
    );
}

#[test]
fn an_identity_without_a_mailbox_reference_is_rejected() {
    let mut graph = ResourceGraph::new();
    graph.insert_identity(identity("me", None)).unwrap();

    let error = graph
        .resolve_identity(&key("me"))
        .expect_err("an identity without a mailbox cannot be resolved");

    assert_eq!(
        error,
        ReferenceError::MissingRequiredReference {
            kind: mail_operator::model::ResourceKind::MailIdentity,
            field: "spec.mailboxRef",
        }
    );
}

#[test]
fn a_provider_without_a_gateway_reference_is_unbound() {
    let mut graph = ResourceGraph::new();
    graph
        .insert_provider(provider("administration-only", None))
        .unwrap();

    let binding = graph
        .resolve_provider_binding(&key("administration-only"))
        .expect("an unbound provider is a valid state");

    assert_eq!(binding, ProviderBinding::Unbound);
}

#[test]
fn an_unbound_provider_contributes_no_identity_to_any_gateway() {
    let mut graph = ResourceGraph::new();
    graph
        .insert_provider(provider("administration-only", None))
        .unwrap();
    graph
        .insert_mailbox(mailbox("unserved-mailbox", Some("administration-only")))
        .unwrap();
    graph
        .insert_identity(identity("unserved", Some("unserved-mailbox")))
        .unwrap();

    let view = graph.gateway_view(&key("primary"));

    assert!(
        view.identities.is_empty(),
        "an unbound provider must contribute no identities to any gateway"
    );
    assert!(view.providers.is_empty());
}

#[test]
fn a_dangling_gateway_reference_is_an_error_and_never_falls_back() {
    let mut graph = ResourceGraph::new();
    graph
        .insert_provider(provider("fastmail", Some("missing-gateway")))
        .unwrap();

    let error = graph
        .resolve_provider_binding(&key("fastmail"))
        .expect_err("a dangling gateway reference must fail closed");

    assert_eq!(
        error,
        ReferenceError::DanglingReference {
            kind: mail_operator::model::ResourceKind::MailProvider,
            field: "spec.gatewayRef",
            target: key("missing-gateway"),
            expected: mail_operator::model::ResourceKind::CorviGateway,
        }
    );
}

#[test]
fn a_reference_may_not_cross_a_namespace() {
    let mut graph = ResourceGraph::new();
    let mut crossing = provider("fastmail", None);
    crossing.spec.gateway_ref = Some(LocalRef {
        name: "primary".to_owned(),
        namespace: Some("other-namespace".to_owned()),
    });
    graph.insert_provider(crossing).unwrap();

    let error = graph
        .resolve_provider_binding(&key("fastmail"))
        .expect_err("a cross-namespace reference must be rejected");

    assert_eq!(
        error,
        ReferenceError::CrossNamespaceReference {
            kind: mail_operator::model::ResourceKind::MailProvider,
            field: "spec.gatewayRef",
            referenced: "other-namespace".to_owned(),
            owner: NS.to_owned(),
        }
    );
}

#[test]
fn an_empty_reference_name_is_malformed() {
    let mut graph = ResourceGraph::new();
    graph.insert_mailbox(mailbox("personal", Some(""))).unwrap();

    let error = graph
        .resolve_mailbox(&key("personal"))
        .expect_err("an empty reference name must be rejected");

    assert_eq!(
        error,
        ReferenceError::MalformedReference {
            kind: mail_operator::model::ResourceKind::Mailbox,
            field: "spec.providerRef",
            reason: "the name is empty",
        }
    );
}

#[test]
fn a_mailbox_whose_provider_does_not_exist_is_dangling() {
    let mut graph = ResourceGraph::new();
    graph
        .insert_mailbox(mailbox("personal", Some("fastmail")))
        .unwrap();

    let error = graph
        .resolve_mailbox(&key("personal"))
        .expect_err("a mailbox without its provider must fail closed");

    assert_eq!(
        error,
        ReferenceError::DanglingReference {
            kind: mail_operator::model::ResourceKind::Mailbox,
            field: "spec.providerRef",
            target: key("fastmail"),
            expected: mail_operator::model::ResourceKind::MailProvider,
        }
    );
}

#[test]
fn a_provider_may_name_at_most_one_gateway() {
    let document = r#"
apiVersion: corvi.naktis.eu/v1alpha1
kind: MailProvider
metadata:
  name: fastmail
  namespace: corvi-system
spec:
  gatewayRefs:
    - name: primary
    - name: secondary
"#;

    let error = parse_provider(document).expect_err("a provider may not name two gateways");

    match error {
        ParseError::Yaml(message) => assert!(
            message.contains("gatewayRefs"),
            "the error must name the offending field: {message}"
        ),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn effective_identities_follow_the_whole_chain() {
    let mut graph = ResourceGraph::new();
    graph.insert_gateway(gateway("primary")).unwrap();
    graph
        .insert_provider(provider("fastmail", Some("primary")))
        .unwrap();
    graph
        .insert_mailbox(mailbox("personal", Some("fastmail")))
        .unwrap();
    graph
        .insert_identity(identity("me", Some("personal")))
        .unwrap();

    let view = graph.gateway_view(&key("primary"));

    assert_eq!(view.providers, vec![key("fastmail")]);
    assert_eq!(view.identities.len(), 1);
    assert_eq!(view.identities[0].identity, key("me"));
    assert_eq!(view.identities[0].mailbox, key("personal"));
    assert_eq!(view.identities[0].provider, key("fastmail"));
    assert_eq!(
        view.identities[0].binding,
        ProviderBinding::Bound {
            gateway: key("primary")
        }
    );
    assert!(view.problems.is_empty());
}

#[test]
fn an_identity_in_another_namespace_does_not_resolve() {
    let mut graph = ResourceGraph::new();
    graph
        .insert_mailbox(mailbox("personal", Some("fastmail")))
        .unwrap();

    let error = graph
        .resolve_mailbox(&ResourceKey::new("other-namespace", "personal"))
        .expect_err("a mailbox in another namespace does not resolve here");

    assert_eq!(
        error,
        ReferenceError::UnknownResource {
            kind: mail_operator::model::ResourceKind::Mailbox,
            target: ResourceKey::new("other-namespace", "personal"),
        }
    );
}
