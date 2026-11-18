//! Shared fixtures for the operator's integration tests.
#![allow(dead_code)]

use mail_operator::model::{
    Authorization, AuthorizationMode, CorviGateway, GatewaySpec, Listener, Listeners, LocalRef,
    MailIdentity, MailIdentitySpec, MailProvider, MailProviderSpec, Mailbox, MailboxSpec,
    ObjectMeta, ProviderRole, ResourceList, ResourceRequirements, StateBackend, StateSpec,
};
use mail_operator::references::ResourceKey;
use mail_operator::workload::{OperatorProfile, PolicyExpectation, PolicyKind, PolicySource};

/// The namespace every fixture lives in.
pub const NS: &str = "corvi-system";

/// The key of a fixture object.
pub fn key(name: &str) -> ResourceKey {
    ResourceKey::new(NS, name)
}

/// A gateway with the given replica count and state backend.
pub fn gateway_with(replicas: u32, backend: StateBackend, mode: AuthorizationMode) -> CorviGateway {
    CorviGateway {
        metadata: ObjectMeta::new(NS, "primary"),
        spec: GatewaySpec {
            replicas,
            suspended: false,
            listeners: Listeners {
                http: Listener { enabled: true },
                smtp_submission: Listener { enabled: true },
            },
            authorization: Authorization {
                mode,
                config_secret_ref: LocalRef::new("corvi-resource-server"),
            },
            state: StateSpec {
                backend,
                existing_claim_name: match backend {
                    StateBackend::Sqlite => Some("corvi-gateway-primary-data".to_owned()),
                    _ => None,
                },
                connection_secret_ref: match backend {
                    StateBackend::Postgres => Some(LocalRef::new("corvi-runtime-db")),
                    _ => None,
                },
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
                    ephemeral_storage: Some("256Mi".to_owned()),
                },
            },
        },
    }
}

/// A gateway with one replica and ephemeral state.
pub fn gateway() -> CorviGateway {
    gateway_with(1, StateBackend::Ephemeral, AuthorizationMode::External)
}

/// A provider bound to `gateway`.
pub fn provider(name: &str, gateway: Option<&str>) -> MailProvider {
    MailProvider {
        metadata: ObjectMeta::new(NS, name),
        spec: MailProviderSpec {
            gateway_ref: gateway.map(LocalRef::new),
            suspended: false,
            role: ProviderRole::Serving,
        },
    }
}

/// A mailbox owned by `provider`.
pub fn mailbox(name: &str, provider: Option<&str>) -> Mailbox {
    Mailbox {
        metadata: ObjectMeta::new(NS, name),
        spec: MailboxSpec {
            provider_ref: provider.map(LocalRef::new),
        },
    }
}

/// An identity over `mailbox`.
pub fn identity(name: &str, mailbox: Option<&str>) -> MailIdentity {
    MailIdentity {
        metadata: ObjectMeta::new(NS, name),
        spec: MailIdentitySpec {
            mailbox_ref: mailbox.map(LocalRef::new),
            address: Some(format!("{name}@example.com")),
            isolation: Some(mail_operator::IsolationMode::Dedicated),
        },
    }
}

/// The operator-approved profile used by the fixtures.
pub fn profile() -> OperatorProfile {
    OperatorProfile {
        gateway_image: "ghcr.io/naktis-labs/corvi-gateway@sha256:".to_owned() + &"a".repeat(64),
        operator_service_account: "corvi-operator".to_owned(),
        gateway_service_account: "corvi-gateway".to_owned(),
        http_port: 8080,
        smtp_submission_port: 2525,
        admission_policy: PolicyExpectation {
            name: "corvi-restricted-workload".to_owned(),
            kind: PolicyKind::Admission,
            source: PolicySource::IndependentlyInstalled,
        },
        network_policy: PolicyExpectation {
            name: "corvi-gateway-default-deny".to_owned(),
            kind: PolicyKind::Network,
            source: PolicySource::IndependentlyInstalled,
        },
    }
}
