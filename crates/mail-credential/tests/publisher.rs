//! Publication of the connection Secret of a MailCredential.

use std::collections::BTreeMap;

use mail_credential::admission::{
    ConnectionAuthority, ConnectionMode, CredentialGranularity, ObservedEndpoint,
    SmtpAuthMechanism, SmtpRoute, TlsMode,
};
use mail_credential::model::{Permission, ProtocolType, default_secret_name};
use mail_credential::policy::SecretPolicy;
use mail_credential::publisher::{
    IssuedMaterial, PublishError, PublishRequest, PublisherGrant, RevocationOutcome,
    RevocationRequest, SecretObject, SecretPublisher, SecretStore, assert_no_forbidden_material,
    build_secret_data,
};
use mail_credential::revalidate::RevalidationDecision;
use mail_credential::testing::{
    FIXTURE_NAMESPACE, FakeSecretStore, direct_endpoints, gateway_endpoints,
};

fn grant() -> PublisherGrant {
    PublisherGrant::for_namespace(FIXTURE_NAMESPACE)
}

fn policy() -> SecretPolicy {
    SecretPolicy::deny_all().allow_prefix("example.com/")
}

fn gateway_authority() -> ConnectionAuthority {
    ConnectionAuthority {
        mode: ConnectionMode::Gateway,
        credential_type: ProtocolType::Mcp,
        granularity: CredentialGranularity::CorviIdentity,
        provider_name: "fastmail".to_string(),
        identity_name: Some("me".to_string()),
        mailbox_name: None,
        permissions: vec![Permission::MessagesList, Permission::MessagesRead],
    }
}

fn native_smtp_authority() -> ConnectionAuthority {
    ConnectionAuthority {
        mode: ConnectionMode::ProviderDirect,
        credential_type: ProtocolType::Smtp,
        granularity: CredentialGranularity::ProviderMailbox,
        provider_name: "administration-only".to_string(),
        identity_name: None,
        mailbox_name: Some("unserved-mailbox".to_string()),
        permissions: Vec::new(),
    }
}

fn oauth_request() -> PublishRequest {
    let mut request = PublishRequest::new(
        FIXTURE_NAMESPACE,
        "me-mcp",
        "credential-uid",
        "me-mcp-app",
        gateway_authority(),
        IssuedMaterial::OAuth2Client {
            token_url: "https://auth.example.test/oauth/token".to_string(),
            client_id: "client-id".to_string(),
            client_secret: "client-secret".to_string(),
            resource: "https://mail.example.test".to_string(),
            scopes: vec![
                "mail:messages:list".to_string(),
                "mail:messages:read".to_string(),
            ],
        },
    );
    request.observed.endpoints = gateway_endpoints();
    request.revision = "revision-42".to_string();
    request
}

fn smtp_request() -> PublishRequest {
    let mut request = PublishRequest::new(
        FIXTURE_NAMESPACE,
        "alerts-direct",
        "credential-uid",
        "alerts-direct-smtp",
        native_smtp_authority(),
        IssuedMaterial::SmtpPassword {
            username: "alerts@example.test".to_string(),
            password: "provider-app-password".to_string(),
        },
    );
    request.observed.endpoints = direct_endpoints();
    request.observed.smtp = Some(SmtpRoute {
        host: "smtp.provider.test".to_string(),
        port: 587,
        tls_mode: TlsMode::StartTls,
        server_name: "smtp.provider.test".to_string(),
        auth_mechanism: SmtpAuthMechanism::Plain,
    });
    request.observed.from_address = Some("alerts@example.test".to_string());
    request
}

fn secret_of(store: &FakeSecretStore, name: &str) -> SecretObject {
    store
        .get(FIXTURE_NAMESPACE, name)
        .expect("the store is readable")
        .expect("the Secret exists")
}

#[test]
fn a_gateway_mcp_secret_carries_only_the_mcp_keys() {
    let store = FakeSecretStore::new();
    let publisher_grant = grant();
    let publisher_policy = policy();
    let publisher = SecretPublisher::new(&store, &publisher_grant, &publisher_policy);
    let outcome = publisher
        .publish(&oauth_request())
        .expect("the Secret is published");

    assert!(outcome.created);
    assert!(!outcome.updated);
    let secret = secret_of(&store, "me-mcp-app");
    assert_eq!(
        secret.data.keys().map(String::as_str).collect::<Vec<_>>(),
        vec![
            "AUTH_TYPE",
            "CONNECTION_MODE",
            "CONNECTION_TYPE",
            "CREDENTIAL_GRANULARITY",
            "CREDENTIAL_REVISION",
            "IDENTITY_NAME",
            "MCP_URL",
            "OAUTH_CLIENT_ID",
            "OAUTH_CLIENT_SECRET",
            "OAUTH_RESOURCE",
            "OAUTH_SCOPES",
            "OAUTH_TOKEN_URL",
            "PROVIDER_NAME",
        ]
    );
    assert_eq!(secret.data["MCP_URL"], "https://mail.example.test/mcp");
    assert_eq!(
        secret.data["OAUTH_SCOPES"],
        "mail:messages:list mail:messages:read"
    );
    assert_eq!(secret.data["AUTH_TYPE"], "oauth2_client_credentials");
    assert_eq!(secret.data["CONNECTION_MODE"], "gateway");
    assert_eq!(secret.data["CONNECTION_TYPE"], "mcp");
    assert_eq!(secret.data["CREDENTIAL_GRANULARITY"], "corviIdentity");
    assert_eq!(secret.data["PROVIDER_NAME"], "fastmail");
    assert_eq!(secret.data["CREDENTIAL_REVISION"], "revision-42");
    assert_eq!(secret.data["IDENTITY_NAME"], "me");
    assert_eq!(secret.data["OAUTH_RESOURCE"], "https://mail.example.test");
    assert_eq!(secret.owner_uid.as_deref(), Some("credential-uid"));
}

#[test]
fn a_provider_native_smtp_secret_carries_only_the_smtp_keys() {
    let store = FakeSecretStore::new();
    let publisher_grant = grant();
    let publisher_policy = policy();
    let publisher = SecretPublisher::new(&store, &publisher_grant, &publisher_policy);
    publisher
        .publish(&smtp_request())
        .expect("the Secret is published");

    let secret = secret_of(&store, "alerts-direct-smtp");
    assert_eq!(
        secret.data.keys().map(String::as_str).collect::<Vec<_>>(),
        vec![
            "AUTH_TYPE",
            "CONNECTION_MODE",
            "CONNECTION_TYPE",
            "CREDENTIAL_GRANULARITY",
            "CREDENTIAL_REVISION",
            "MAILBOX_NAME",
            "PROVIDER_NAME",
            "SMTP_AUTH_MECHANISM",
            "SMTP_FROM_ADDRESS",
            "SMTP_HOST",
            "SMTP_PASSWORD",
            "SMTP_PORT",
            "SMTP_SERVER_NAME",
            "SMTP_TLS_MODE",
            "SMTP_USERNAME",
        ]
    );
    assert_eq!(secret.data["SMTP_HOST"], "smtp.provider.test");
    assert_eq!(secret.data["SMTP_PORT"], "587");
    assert_eq!(secret.data["SMTP_TLS_MODE"], "starttls");
    assert_eq!(secret.data["SMTP_AUTH_MECHANISM"], "PLAIN");
    assert_eq!(secret.data["SMTP_FROM_ADDRESS"], "alerts@example.test");
    assert_eq!(secret.data["CREDENTIAL_GRANULARITY"], "providerMailbox");
    assert_eq!(secret.data["CONNECTION_MODE"], "providerDirect");
    assert!(!secret.data.contains_key("API_TOKEN"));
    assert!(!secret.data.contains_key("OAUTH_CLIENT_SECRET"));
}

#[test]
fn the_publisher_needs_its_own_authorization() {
    let store = FakeSecretStore::new();
    let foreign_grant = PublisherGrant::for_namespace("other-namespace");
    let publisher_policy = policy();
    let publisher = SecretPublisher::new(&store, &foreign_grant, &publisher_policy);

    let error = publisher
        .publish(&oauth_request())
        .expect_err("the publisher is not authorized");

    assert_eq!(error, PublishError::NotAuthorized);
    assert!(
        store
            .get(FIXTURE_NAMESPACE, "me-mcp-app")
            .unwrap()
            .is_none()
    );
}

#[test]
fn an_admitted_credential_is_not_published_without_the_publishers_own_grant() {
    // Admission and publication are separate roles. A credential that
    // admission approved still needs the publisher's own authorization.
    let graph = mail_credential::testing::FakeGraph::new()
        .with_provider(mail_credential::testing::provider_bound(
            "fastmail", "primary",
        ))
        .with_mailbox(mail_credential::testing::mailbox("personal", "fastmail"))
        .with_identity(mail_credential::testing::identity("me", "personal"))
        .with_gateway(mail_credential::testing::gateway("primary"));
    let spec = mail_credential::model::MailCredentialSpec::parse(
        "type: mcp\ntargetRef:\n  kind: MailIdentity\n  name: me\npermissions:\n  - mail:messages:read\n",
    )
    .unwrap();
    let credential = mail_credential::model::MailCredential::new(
        "me-mcp",
        FIXTURE_NAMESPACE,
        "credential-uid",
        1,
        spec,
    );
    let decision = mail_credential::admission::admit(
        &mail_credential::admission::AdmissionRequest::new(
            credential,
            mail_credential::admission::AdmissionOperation::Create,
            false,
        ),
        &graph,
        &policy(),
    );
    assert!(decision.is_allowed(), "{decision:?}");

    let store = FakeSecretStore::new();
    let publisher_grant = PublisherGrant::for_namespace("elsewhere");
    let publisher_policy = policy();
    let publisher = SecretPublisher::new(&store, &publisher_grant, &publisher_policy);
    assert_eq!(
        publisher
            .publish(&oauth_request())
            .expect_err("not authorized"),
        PublishError::NotAuthorized
    );
    assert!(
        store
            .get(FIXTURE_NAMESPACE, "me-mcp-app")
            .unwrap()
            .is_none()
    );
}

#[test]
fn a_foreign_secret_is_never_overwritten() {
    let store = FakeSecretStore::new();
    store.insert(SecretObject {
        namespace: FIXTURE_NAMESPACE.to_string(),
        name: "me-mcp-app".to_string(),
        uid: "foreign-secret".to_string(),
        resource_version: "1".to_string(),
        data: BTreeMap::from([("API_TOKEN".to_string(), "foreign".to_string())]),
        annotations: BTreeMap::new(),
        owner_uid: Some("other-credential".to_string()),
    });

    let publisher_grant = grant();
    let publisher_policy = policy();
    let publisher = SecretPublisher::new(&store, &publisher_grant, &publisher_policy);
    let error = publisher
        .publish(&oauth_request())
        .expect_err("the name belongs to another owner");

    assert_eq!(
        error,
        PublishError::SecretNameConflict {
            name: "me-mcp-app".to_string()
        }
    );
    let secret = secret_of(&store, "me-mcp-app");
    assert_eq!(secret.data["API_TOKEN"], "foreign");
    assert_eq!(secret.owner_uid.as_deref(), Some("other-credential"));
}

#[test]
fn the_secret_data_is_replaced_and_never_merged() {
    let store = FakeSecretStore::new();
    let publisher_grant = grant();
    let publisher_policy = policy();
    let publisher = SecretPublisher::new(&store, &publisher_grant, &publisher_policy);

    let mut first = oauth_request();
    first.observed.tls_ca_pem = Some("-----BEGIN CERTIFICATE-----".to_string());
    publisher
        .publish(&first)
        .expect("the first revision is published");
    assert!(
        secret_of(&store, "me-mcp-app")
            .data
            .contains_key("TLS_CA_PEM")
    );

    let mut second = oauth_request();
    second.revision = "revision-43".to_string();
    let outcome = publisher
        .publish(&second)
        .expect("the rotation is published");

    assert!(outcome.updated);
    assert!(!outcome.created);
    let secret = secret_of(&store, "me-mcp-app");
    assert_eq!(secret.data["CREDENTIAL_REVISION"], "revision-43");
    // The whole map was replaced: the key that is no longer part of the
    // connection is gone rather than left behind.
    assert!(!secret.data.contains_key("TLS_CA_PEM"));
    assert_eq!(secret.data.len(), 13);
}

#[test]
fn a_racing_publisher_fails_closed_instead_of_clobbering() {
    let store = FakeSecretStore::new();
    store.race_next_create();

    let publisher_grant = grant();
    let publisher_policy = policy();
    let publisher = SecretPublisher::new(&store, &publisher_grant, &publisher_policy);
    let error = publisher
        .publish(&oauth_request())
        .expect_err("the name was taken in the race");

    assert_eq!(
        error,
        PublishError::SecretNameConflict {
            name: "me-mcp-app".to_string()
        }
    );
    let secret = secret_of(&store, "me-mcp-app");
    assert_eq!(secret.data["API_TOKEN"], "foreign");
    assert_eq!(secret.owner_uid.as_deref(), Some("foreign-owner"));
}

#[test]
fn a_secret_that_changed_underneath_the_publisher_fails_closed() {
    let store = FakeSecretStore::new();
    let publisher_grant = grant();
    let publisher_policy = policy();
    let publisher = SecretPublisher::new(&store, &publisher_grant, &publisher_policy);
    publisher
        .publish(&oauth_request())
        .expect("the first publication");

    // Another writer replaces the Secret between the publisher's read and
    // its write.
    store.race_next_replace();
    let before = secret_of(&store, "me-mcp-app").resource_version.clone();

    let mut second = oauth_request();
    second.revision = "revision-43".to_string();
    let error = publisher
        .publish(&second)
        .expect_err("the resource version moved");

    assert!(matches!(error, PublishError::SecretNameConflict { .. }));
    // The concurrent write moved the Secret on, and the publisher's own
    // data never landed.
    assert_ne!(secret_of(&store, "me-mcp-app").resource_version, before);
    assert_eq!(
        secret_of(&store, "me-mcp-app").data["CREDENTIAL_REVISION"],
        "revision-42"
    );
}

#[test]
fn a_revoked_credential_leaves_no_usable_secret_behind() {
    let store = FakeSecretStore::new();
    let publisher_grant = grant();
    let publisher_policy = policy();
    let publisher = SecretPublisher::new(&store, &publisher_grant, &publisher_policy);
    publisher
        .publish(&oauth_request())
        .expect("the Secret is published");

    let outcome = publisher
        .revoke(&RevocationRequest {
            namespace: FIXTURE_NAMESPACE.to_string(),
            credential_uid: "credential-uid".to_string(),
            secret_name: "me-mcp-app".to_string(),
            upstream_revoked: true,
        })
        .expect("the Secret is withdrawn");

    assert_eq!(outcome, RevocationOutcome::Revoked);
    assert!(
        store
            .get(FIXTURE_NAMESPACE, "me-mcp-app")
            .unwrap()
            .is_none()
    );
}

#[test]
fn an_unconfirmed_upstream_revocation_still_withdraws_the_output() {
    let store = FakeSecretStore::new();
    let publisher_grant = grant();
    let publisher_policy = policy();
    let publisher = SecretPublisher::new(&store, &publisher_grant, &publisher_policy);
    publisher
        .publish(&oauth_request())
        .expect("the Secret is published");

    let outcome = publisher
        .revoke(&RevocationRequest {
            namespace: FIXTURE_NAMESPACE.to_string(),
            credential_uid: "credential-uid".to_string(),
            secret_name: "me-mcp-app".to_string(),
            upstream_revoked: false,
        })
        .expect("the Secret is withdrawn");

    assert_eq!(outcome, RevocationOutcome::OutputWithdrawn);
    assert!(
        store
            .get(FIXTURE_NAMESPACE, "me-mcp-app")
            .unwrap()
            .is_none()
    );
}

#[test]
fn a_revocation_never_removes_another_owners_secret() {
    let store = FakeSecretStore::new();
    store.insert(SecretObject {
        namespace: FIXTURE_NAMESPACE.to_string(),
        name: "me-mcp-app".to_string(),
        uid: "foreign-secret".to_string(),
        resource_version: "1".to_string(),
        data: BTreeMap::from([("API_TOKEN".to_string(), "foreign".to_string())]),
        annotations: BTreeMap::new(),
        owner_uid: Some("other-credential".to_string()),
    });

    let publisher_grant = grant();
    let publisher_policy = policy();
    let publisher = SecretPublisher::new(&store, &publisher_grant, &publisher_policy);
    let error = publisher
        .revoke(&RevocationRequest {
            namespace: FIXTURE_NAMESPACE.to_string(),
            credential_uid: "credential-uid".to_string(),
            secret_name: "me-mcp-app".to_string(),
            upstream_revoked: true,
        })
        .expect_err("the name belongs to another owner");

    assert!(matches!(error, PublishError::SecretNameConflict { .. }));
    assert_eq!(secret_of(&store, "me-mcp-app").data["API_TOKEN"], "foreign");
}

#[test]
fn the_published_secret_never_carries_provider_or_issuer_material() {
    let store = FakeSecretStore::new();
    let publisher_grant = grant();
    let publisher_policy = policy();
    let publisher = SecretPublisher::new(&store, &publisher_grant, &publisher_policy);
    publisher
        .publish(&oauth_request())
        .expect("the Secret is published");

    let secret = secret_of(&store, "me-mcp-app");
    assert_no_forbidden_material(&secret.data).expect("no forbidden key is published");
    for key in secret.data.keys() {
        let upper = key.to_ascii_uppercase();
        assert!(
            !upper.contains("ADMIN"),
            "{key} names administration material"
        );
        assert!(!upper.contains("REFRESH"), "{key} names a refresh token");
        assert!(!upper.contains("PRIVATE_KEY"), "{key} names a private key");
    }
}

#[test]
fn forbidden_material_is_refused_by_name() {
    let data = BTreeMap::from([("PROVIDER_ADMIN_TOKEN".to_string(), "secret".to_string())]);
    assert_eq!(
        assert_no_forbidden_material(&data).expect_err("administration material is refused"),
        PublishError::ForbiddenMaterial {
            key: "PROVIDER_ADMIN_TOKEN".to_string()
        }
    );

    let gateway_token = BTreeMap::from([("GATEWAY_API_TOKEN".to_string(), "secret".to_string())]);
    assert!(assert_no_forbidden_material(&gateway_token).is_err());

    let issuer_key = BTreeMap::from([("ISSUER_KEY".to_string(), "secret".to_string())]);
    assert!(assert_no_forbidden_material(&issuer_key).is_err());
}

#[test]
fn material_that_does_not_match_the_protocol_is_refused() {
    let mut request = oauth_request();
    request.material = IssuedMaterial::BearerToken {
        token: "provider-token".to_string(),
    };

    let error = build_secret_data(&request).expect_err("the material does not match");
    assert_eq!(
        error,
        PublishError::MaterialMismatch {
            expected: "oauth2_client_credentials"
        }
    );

    let mut smtp = smtp_request();
    smtp.material = IssuedMaterial::BearerToken {
        token: "provider-token".to_string(),
    };
    assert!(build_secret_data(&smtp).is_err());
}

#[test]
fn only_the_observed_endpoint_is_published() {
    let store = FakeSecretStore::new();
    let publisher_grant = grant();
    let publisher_policy = policy();
    let publisher = SecretPublisher::new(&store, &publisher_grant, &publisher_policy);
    publisher
        .publish(&oauth_request())
        .expect("the Secret is published");
    assert_eq!(
        secret_of(&store, "me-mcp-app").data["MCP_URL"],
        "https://mail.example.test/mcp"
    );

    let mut unverified = oauth_request();
    unverified.observed.endpoints = vec![ObservedEndpoint::new(
        ProtocolType::Mcp,
        "https://mail.example.test/mcp",
        false,
    )];
    assert_eq!(
        build_secret_data(&unverified).expect_err("an unverified endpoint is refused"),
        PublishError::UnverifiedEndpoint {
            protocol: ProtocolType::Mcp
        }
    );

    let mut missing = oauth_request();
    missing.observed.endpoints = Vec::new();
    assert_eq!(
        build_secret_data(&missing).expect_err("no endpoint is refused"),
        PublishError::NoObservedEndpoint {
            protocol: ProtocolType::Mcp
        }
    );
}

#[test]
fn only_approved_annotations_are_published() {
    let store = FakeSecretStore::new();
    let publisher_grant = grant();
    let publisher_policy = policy();
    let publisher = SecretPublisher::new(&store, &publisher_grant, &publisher_policy);

    let mut request = oauth_request();
    request.annotations.insert(
        "example.com/application".to_string(),
        "mail-agent".to_string(),
    );

    publisher
        .publish(&request)
        .expect("the annotation is approved");
    assert_eq!(
        secret_of(&store, "me-mcp-app").annotations["example.com/application"],
        "mail-agent"
    );

    let mut refused = oauth_request();
    refused.annotations.insert(
        "other.example.com/application".to_string(),
        "mail-agent".to_string(),
    );
    let error = publisher
        .publish(&refused)
        .expect_err("the annotation is not approved");
    assert_eq!(
        error,
        PublishError::UnsafeAnnotation {
            key: "other.example.com/application".to_string()
        }
    );
}

#[test]
fn a_dry_run_publishes_nothing() {
    let store = FakeSecretStore::new();
    let publisher_grant = grant();
    let publisher_policy = policy();
    let publisher = SecretPublisher::new(&store, &publisher_grant, &publisher_policy);

    let mut request = oauth_request();
    request.dry_run = true;
    let outcome = publisher
        .publish(&request)
        .expect("the request is evaluated");

    assert!(outcome.dry_run);
    assert!(!outcome.created);
    assert!(!outcome.updated);
    assert!(
        store
            .get(FIXTURE_NAMESPACE, "me-mcp-app")
            .unwrap()
            .is_none()
    );
}

#[test]
fn a_credential_that_lost_its_authority_is_not_published() {
    let store = FakeSecretStore::new();
    let publisher_grant = grant();
    let publisher_policy = policy();
    let publisher = SecretPublisher::new(&store, &publisher_grant, &publisher_policy);

    let revoked = RevalidationDecision::Revoke {
        reason: mail_credential::Reason::GatewayUnavailable,
        message: "the bound gateway is suspended".to_string(),
    };
    let error = publisher
        .publish_after_revalidation(&oauth_request(), &revoked)
        .expect_err("a revoked credential is not published");
    assert_eq!(
        error,
        PublishError::AuthorityChanged {
            reason: mail_credential::Reason::GatewayUnavailable
        }
    );
    assert!(
        store
            .get(FIXTURE_NAMESPACE, "me-mcp-app")
            .unwrap()
            .is_none()
    );

    let withheld = RevalidationDecision::Withhold {
        reason: mail_credential::Reason::StaleCapabilityStatus,
        message: "the capability status is not fresh".to_string(),
    };
    let error = publisher
        .publish_after_revalidation(&oauth_request(), &withheld)
        .expect_err("a credential whose graph cannot be resolved is not published");
    assert_eq!(
        error,
        PublishError::AuthorityChanged {
            reason: mail_credential::Reason::StaleCapabilityStatus
        }
    );
    assert!(
        store
            .get(FIXTURE_NAMESPACE, "me-mcp-app")
            .unwrap()
            .is_none()
    );

    let outcome = publisher
        .publish_after_revalidation(&oauth_request(), &RevalidationDecision::Keep)
        .expect("a credential that still holds its authority is published");
    assert!(outcome.created);
}

#[test]
fn the_secret_name_comes_from_the_template_or_from_the_credential_itself() {
    let named = mail_credential::model::MailCredentialSpec::parse(
        "type: smtp\ntargetRef:\n  kind: MailIdentity\n  name: me\nsecretTemplate:\n  metadata:\n    name: me-app\n",
    )
    .unwrap();
    assert_eq!(named.secret_name("me-mcp", "uid-1234"), "me-app");

    let derived = mail_credential::model::MailCredentialSpec::parse(
        "targetRef:\n  kind: MailIdentity\n  name: me\n",
    )
    .unwrap();
    assert_eq!(derived.secret_name("me-mcp", "uid-1234"), "me-mcp-uid1234");
}

#[test]
fn the_default_secret_name_is_stable_and_dns_compliant() {
    assert_eq!(default_secret_name("me-mcp", "uid-1234"), "me-mcp-uid1234");
    assert_eq!(
        default_secret_name("me-mcp", "uid-1234"),
        default_secret_name("me-mcp", "uid-1234")
    );
    assert_ne!(
        default_secret_name("me-mcp", "uid-1234"),
        default_secret_name("me-mcp", "uid-5678")
    );

    let long = default_secret_name(&"n".repeat(80), "uid-1234");
    assert!(long.len() <= 63, "{long}");
    assert!(long.starts_with("n"), "{long}");
}
