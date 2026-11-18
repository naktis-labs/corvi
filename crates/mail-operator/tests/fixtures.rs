//! The checked-in CRD-shaped and rendered-workload fixtures.
//!
//! These tests are the guard against drift: the renderer's output is compared
//! with the checked-in workload fixtures, the invalid fixtures are shown to
//! be rejected, and the independently installed policy fixture is shown to be
//! dual-stack and default-deny.

mod common;

use std::fmt::Write as _;
use std::{fs, path::Path};

use serde::Deserialize;
use serde_yaml::Value;

use common::profile;
use mail_operator::model::{
    API_GROUP_VERSION, ParseError, parse_gateway, parse_identity, parse_mailbox, parse_provider,
};
use mail_operator::ownership::{ProviderBinding, ResourceGraph};
use mail_operator::references::{ReferenceError, ResourceKey};
use mail_operator::workload::{
    Deployment, NetworkPolicy, RenderError, StatefulSet, WorkloadViolation,
    render_gateway_workload, validate_network_policy, validate_workload,
};

const API: &str = "../../api/operator/fixtures";
const DEPLOY: &str = "../../deploy/operator";

fn read(path: &str) -> String {
    fs::read_to_string(Path::new(path)).expect("fixture is present")
}

/// Drop the leading comment block of a fixture, leaving the document.
fn strip_header(text: &str) -> String {
    let body: Vec<&str> = text
        .lines()
        .skip_while(|line| line.starts_with('#') || line.trim().is_empty())
        .collect();
    let mut out = body.join("\n");
    out.push('\n');
    out
}

/// Every YAML document in a fixture.
fn documents(text: &str) -> Vec<Value> {
    serde_yaml::Deserializer::from_str(text)
        .map(|document| Value::deserialize(document).expect("a valid YAML document"))
        .filter(|document| !document.is_null())
        .collect()
}

/// Build a graph from a multi-document fixture.
fn graph_from(text: &str) -> ResourceGraph {
    let mut graph = ResourceGraph::new();
    for document in documents(text) {
        let kind = document
            .get("kind")
            .and_then(Value::as_str)
            .expect("every document declares a kind")
            .to_owned();
        let yaml = serde_yaml::to_string(&document).expect("a document serialises");
        match kind.as_str() {
            "CorviGateway" => graph.insert_gateway(parse_gateway(&yaml).unwrap()).unwrap(),
            "MailProvider" => graph
                .insert_provider(parse_provider(&yaml).unwrap())
                .unwrap(),
            "Mailbox" => graph.insert_mailbox(parse_mailbox(&yaml).unwrap()).unwrap(),
            "MailIdentity" => graph
                .insert_identity(parse_identity(&yaml).unwrap())
                .unwrap(),
            other => panic!("unknown kind {other}"),
        };
    }
    graph
}

fn key(name: &str) -> ResourceKey {
    ResourceKey::new(common::NS, name)
}

// ---------------------------------------------------------------------------
// The valid chain resolves, and the unbound provider is excluded.
// ---------------------------------------------------------------------------

#[test]
fn the_provider_chain_resolves_and_excludes_the_unbound_provider() {
    let graph = graph_from(&read(&format!("{API}/provider-chain.yaml")));

    let view = graph.gateway_view(&key("primary"));

    assert_eq!(
        view.providers,
        vec![key("fastmail"), key("migadu")],
        "only the explicitly bound providers are effective"
    );
    let identities: Vec<&str> = view
        .identities
        .iter()
        .map(|resolved| resolved.identity.name.as_str())
        .collect();
    assert_eq!(identities, vec!["me", "noreply"]);
    assert!(
        !identities.contains(&"unserved-identity"),
        "an unbound provider contributes no identity to any gateway"
    );
    assert!(view.problems.is_empty(), "{:?}", view.problems);

    let unserved = graph.resolve_identity(&key("unserved-identity")).unwrap();
    assert_eq!(
        unserved.binding,
        ProviderBinding::Unbound,
        "the identity resolves but is served by no gateway"
    );
}

#[test]
fn the_reference_contract_matches_the_ownership_schema() {
    let graph = graph_from(&read(&format!("{API}/provider-chain.yaml")));

    // The chain is child -> parent only: the gateway holds no inverse list.
    let view = graph.gateway_view(&key("primary"));
    assert_eq!(view.identities.len(), 2);
    for identity in &view.identities {
        assert_eq!(identity.mailbox, identity.mailbox.clone());
    }

    // Every reference stays in one namespace.
    for resolved in &view.identities {
        assert_eq!(resolved.identity.namespace, common::NS);
        assert_eq!(resolved.mailbox.namespace, common::NS);
        assert_eq!(resolved.provider.namespace, common::NS);
    }
}

#[test]
fn the_api_version_contract_holds_for_every_fixture() {
    for entry in [
        "provider-chain.yaml",
        "gateway-primary.yaml",
        "gateway-sqlite.yaml",
    ] {
        for document in documents(&read(&format!("{API}/{entry}"))) {
            assert_eq!(
                document.get("apiVersion").and_then(Value::as_str),
                Some(API_GROUP_VERSION)
            );
        }
    }
}

// ---------------------------------------------------------------------------
// The invalid fixtures are rejected.
// ---------------------------------------------------------------------------

#[test]
fn a_dangling_gateway_reference_is_rejected() {
    let graph = graph_from(&read(&format!("{API}/invalid-dangling-gateway-ref.yaml")));

    let error = graph
        .resolve_provider_binding(&key("fastmail"))
        .expect_err("the referenced gateway does not exist");

    assert!(matches!(error, ReferenceError::DanglingReference { .. }));
}

#[test]
fn a_missing_provider_reference_is_rejected() {
    let graph = graph_from(&read(&format!("{API}/invalid-missing-provider-ref.yaml")));

    let error = graph
        .resolve_mailbox(&key("orphan"))
        .expect_err("a mailbox needs a provider");

    assert_eq!(
        error,
        ReferenceError::MissingRequiredReference {
            kind: mail_operator::model::ResourceKind::Mailbox,
            field: "spec.providerRef",
        }
    );
}

#[test]
fn a_missing_mailbox_reference_is_rejected() {
    let graph = graph_from(&read(&format!("{API}/invalid-missing-mailbox-ref.yaml")));

    let error = graph
        .resolve_identity(&key("nobody"))
        .expect_err("an identity needs a mailbox");

    assert_eq!(
        error,
        ReferenceError::MissingRequiredReference {
            kind: mail_operator::model::ResourceKind::MailIdentity,
            field: "spec.mailboxRef",
        }
    );
}

#[test]
fn a_cross_namespace_reference_is_rejected() {
    let graph = graph_from(&read(&format!("{API}/invalid-cross-namespace-ref.yaml")));

    let error = graph
        .resolve_provider_binding(&key("fastmail"))
        .expect_err("references stay in one namespace");

    assert!(matches!(
        error,
        ReferenceError::CrossNamespaceReference { .. }
    ));
}

#[test]
fn a_management_only_provider_cannot_own_a_mailbox() {
    let mut graph = ResourceGraph::new();
    graph
        .insert_gateway(parse_gateway(&read(&format!("{API}/gateway-primary.yaml"))).unwrap())
        .unwrap();
    for document in documents(&read(&format!(
        "{API}/invalid-management-only-mailbox.yaml"
    ))) {
        let yaml = serde_yaml::to_string(&document).unwrap();
        match document.get("kind").and_then(Value::as_str) {
            Some("MailProvider") => graph
                .insert_provider(parse_provider(&yaml).unwrap())
                .unwrap(),
            Some("Mailbox") => graph.insert_mailbox(parse_mailbox(&yaml).unwrap()).unwrap(),
            other => panic!("unexpected kind {other:?}"),
        }
    }

    let error = graph
        .resolve_mailbox(&key("personal"))
        .expect_err("a management-only provider owns no mailbox");

    assert!(matches!(
        error,
        ReferenceError::ManagementOnlyProvider { .. }
    ));
}

#[test]
fn a_suspended_provider_is_rejected() {
    let graph = graph_from(&read(&format!("{API}/invalid-suspended-provider.yaml")));

    let error = graph
        .resolve_mailbox(&key("personal"))
        .expect_err("a suspended provider invalidates its mailbox");

    assert!(matches!(error, ReferenceError::SuspendedProvider { .. }));
}

#[test]
fn a_podspec_injection_is_rejected() {
    let error = parse_gateway(&read(&format!("{API}/invalid-podspec-injection.yaml")))
        .expect_err("a PodSpec may not be injected into a CorviGateway");

    assert!(matches!(error, ParseError::PodSpecInjection { .. }));
}

#[test]
fn an_owner_reference_injection_is_rejected() {
    let error = parse_provider(&read(&format!(
        "{API}/invalid-owner-reference-injection.yaml"
    )))
    .expect_err("user-supplied ownerReferences are refused");

    assert_eq!(error, ParseError::OwnerReferenceInjection);
}

#[test]
fn a_sqlite_gateway_with_two_replicas_is_rejected() {
    let gateway = parse_gateway(&read(&format!("{API}/invalid-sqlite-two-replicas.yaml"))).unwrap();

    let error =
        render_gateway_workload(&gateway, &profile()).expect_err("SQLite has exactly one writer");

    assert_eq!(error, RenderError::SqliteReplicaLimit { replicas: 2 });
}

#[test]
fn an_embedded_issuer_with_ephemeral_state_is_rejected() {
    let gateway = parse_gateway(&read(&format!(
        "{API}/invalid-ephemeral-embedded-issuer.yaml"
    )))
    .unwrap();

    let error = render_gateway_workload(&gateway, &profile())
        .expect_err("an embedded issuer needs durable state");

    assert_eq!(error, RenderError::EphemeralEmbeddedIssuer);
}

// ---------------------------------------------------------------------------
// The rendered workload fixtures match the renderer.
// ---------------------------------------------------------------------------

#[test]
fn the_rendered_gateway_matches_the_checked_in_fixture() {
    let gateway = parse_gateway(&read(&format!("{API}/gateway-primary.yaml"))).unwrap();
    let rendered = render_gateway_workload(&gateway, &profile())
        .expect("the gateway renders")
        .to_yaml();
    let path = format!("{DEPLOY}/rendered/corvi-gateway-primary.yaml");
    let Ok(fixture) = fs::read_to_string(&path) else {
        panic!("missing fixture {path}; write:\n\n{rendered}");
    };

    assert_eq!(strip_header(&fixture), rendered, "the fixture drifted");
}

#[test]
fn the_rendered_sqlite_gateway_matches_the_checked_in_fixture() {
    let gateway = parse_gateway(&read(&format!("{API}/gateway-sqlite.yaml"))).unwrap();
    let rendered = render_gateway_workload(&gateway, &profile())
        .expect("the gateway renders")
        .to_yaml();
    let path = format!("{DEPLOY}/rendered/corvi-gateway-sqlite.yaml");
    let Ok(fixture) = fs::read_to_string(&path) else {
        panic!("missing fixture {path}; write:\n\n{rendered}");
    };

    assert_eq!(strip_header(&fixture), rendered, "the fixture drifted");
}

#[test]
fn the_checked_in_workloads_pass_the_mandatory_profile() {
    let primary = read(&format!("{DEPLOY}/rendered/corvi-gateway-primary.yaml"));
    let sqlite = read(&format!("{DEPLOY}/rendered/corvi-gateway-sqlite.yaml"));

    let deployment: Deployment = serde_yaml::from_str(&primary).expect("a Deployment");
    let stateful_set: StatefulSet = serde_yaml::from_str(&sqlite).expect("a StatefulSet");

    assert_eq!(deployment.kind, "Deployment");
    assert_eq!(stateful_set.kind, "StatefulSet");
    assert_eq!(stateful_set.spec.replicas, 1, "SQLite is a single writer");
    validate_workload(
        &mail_operator::workload::Workload::Deployment(deployment),
        &profile(),
    )
    .expect("the Deployment is hardened");
    validate_workload(
        &mail_operator::workload::Workload::StatefulSet(stateful_set),
        &profile(),
    )
    .expect("the StatefulSet is hardened");
}

#[test]
fn the_rendered_workload_never_owns_a_claim() {
    let sqlite = read(&format!("{DEPLOY}/rendered/corvi-gateway-sqlite.yaml"));
    let stateful_set: StatefulSet = serde_yaml::from_str(&sqlite).expect("a StatefulSet");

    let volumes = &stateful_set.spec.template.spec.volumes;
    let claim = volumes
        .iter()
        .find(|volume| volume.name == "state")
        .expect("the SQLite gateway mounts its claim");
    match &claim.source {
        mail_operator::workload::VolumeSource::PersistentVolumeClaim { claim_name, .. } => {
            assert_eq!(claim_name, "corvi-gateway-sqlite-data");
        }
        other => panic!("unexpected volume source {other:?}"),
    }
    for volume in volumes {
        // The volume source vocabulary has no host-path variant at all, so a
        // host path is not representable rather than merely rejected.
        match &volume.source {
            mail_operator::workload::VolumeSource::EmptyDir { .. }
            | mail_operator::workload::VolumeSource::ConfigMap { .. }
            | mail_operator::workload::VolumeSource::PersistentVolumeClaim { .. }
            | mail_operator::workload::VolumeSource::Secret { .. } => {}
        }
    }
}

// ---------------------------------------------------------------------------
// The independently installed policy fixture.
// ---------------------------------------------------------------------------

#[test]
fn the_checked_in_network_policy_is_default_deny_and_dual_stack() {
    let policy: NetworkPolicy = serde_yaml::from_str(&read(&format!(
        "{DEPLOY}/policy/corvi-gateway-default-deny.networkpolicy.yaml"
    )))
    .expect("a NetworkPolicy");

    validate_network_policy(&policy)
        .expect("the policy denies by default and covers both families");
    assert_eq!(
        policy.source,
        mail_operator::workload::PolicySource::IndependentlyInstalled
    );

    // The operator is the one component that may not own it.
    let managed_by = policy
        .metadata
        .annotations
        .get("app.kubernetes.io/managed-by")
        .map(String::as_str)
        .unwrap_or_default();
    assert_ne!(managed_by, "corvi-operator");
}

#[test]
fn the_operator_never_trusts_a_policy_it_derived_itself() {
    // The source of a policy is decided by its own provenance, so the
    // operator-derived variant is produced by re-reading the policy with the
    // operator's own marker on it.
    let text = read(&format!(
        "{DEPLOY}/policy/corvi-gateway-default-deny.networkpolicy.yaml"
    ));
    let derived = text.replace(
        "app.kubernetes.io/managed-by: gitops",
        "app.kubernetes.io/managed-by: corvi-operator",
    );
    assert_ne!(derived, text, "the fixture carries a provenance marker");
    let policy: NetworkPolicy = serde_yaml::from_str(&derived).expect("a NetworkPolicy");
    assert_eq!(
        policy.source,
        mail_operator::workload::PolicySource::OperatorDerived
    );

    let expected = profile().network_policy;
    let observed = mail_operator::workload::ObservedPolicies {
        admission: None,
        network: vec![policy],
    };

    let error = mail_operator::workload::check_policy_trust(&expected, &observed)
        .expect_err("a policy the operator derived is not a boundary");

    assert_eq!(
        error,
        WorkloadViolation::NetworkPolicyNotIndependent {
            name: "corvi-gateway-default-deny".to_owned(),
        }
    );
}

// ---------------------------------------------------------------------------
// The operator's own RBAC boundary.
// ---------------------------------------------------------------------------

#[test]
fn the_operator_role_grants_no_privileged_access() {
    let text = read(&format!("{DEPLOY}/policy/corvi-operator.rbac.yaml"));
    let documents = documents(&text);

    let forbidden = [
        "secrets",
        "pods/exec",
        "pods/attach",
        "pods/portforward",
        "serviceaccounts",
        "serviceaccounts/token",
        "clusterroles",
        "clusterrolebindings",
        "roles",
        "rolebindings",
        "nodes",
        "*",
    ];
    let mut report = String::new();
    for document in &documents {
        let kind = document
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if kind != "Role" {
            assert_ne!(kind, "ClusterRole", "the operator is namespaced only");
            continue;
        }
        let rules = document
            .get("rules")
            .and_then(Value::as_sequence)
            .expect("a Role has rules");
        for rule in rules {
            for resource in rule
                .get("resources")
                .and_then(Value::as_sequence)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                if forbidden.contains(&resource) {
                    let _ = writeln!(report, "{resource}");
                }
            }
            for verb in rule
                .get("verbs")
                .and_then(Value::as_sequence)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                if verb == "*" {
                    let _ = writeln!(report, "wildcard verb");
                }
            }
        }
    }
    assert_eq!(report, String::new(), "forbidden RBAC grants: {report}");
}

#[test]
fn the_operator_and_the_gateway_use_separate_service_accounts() {
    let text = read(&format!("{DEPLOY}/policy/corvi-operator.rbac.yaml"));
    let accounts: Vec<String> = documents(&text)
        .iter()
        .filter(|document| document.get("kind").and_then(Value::as_str) == Some("ServiceAccount"))
        .filter_map(|document| {
            document
                .get("metadata")
                .and_then(|m| m.get("name").and_then(Value::as_str))
        })
        .map(str::to_owned)
        .collect();

    assert_eq!(accounts, vec!["corvi-operator", "corvi-gateway"]);

    // The rendered gateway workload uses the gateway's account, never the
    // operator's, and mounts no token.
    let primary = read(&format!("{DEPLOY}/rendered/corvi-gateway-primary.yaml"));
    let deployment: Deployment = serde_yaml::from_str(&primary).expect("a Deployment");
    let pod = &deployment.spec.template.spec;
    assert_eq!(pod.service_account_name, "corvi-gateway");
    assert!(!pod.automount_service_account_token);
    assert_ne!(pod.service_account_name, "corvi-operator");
}

// ---------------------------------------------------------------------------
// Unused helper warning guard.
// ---------------------------------------------------------------------------

#[allow(dead_code)]
fn _unused(_provider: &ProviderBinding) {}
