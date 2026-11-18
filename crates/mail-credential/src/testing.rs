//! Fixtures for testing admission, revalidation and publication.
//!
//! The crate has no cluster client and no network, so the two seams that
//! touch the outside world are faked here: a
//! [`ParentStatusReader`] that answers from a table of resources, and a
//! [`SecretStore`] that behaves like the Kubernetes API where it matters —
//! creation only succeeds when a name is free, and replacement only
//! succeeds when the Secret still has the version that was read.
//!
//! The fakes are part of the crate rather than of a test file so that a
//! later task can reuse them when it wires a real reader and a real store
//! to the same decision logic.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

use crate::admission::{
    CredentialGranularity, GatewayStatus, IdentityStatus, MailboxStatus, ObservedEndpoint,
    ParentStatusReader, ProviderCapabilities, ProviderStatus, SmtpAuthMechanism, SmtpRoute,
    StatusReadError, TlsMode,
};
use crate::model::ProtocolType;
use crate::publisher::{SecretObject, SecretStore, SecretStoreError};

/// The namespace the fixtures live in.
pub const FIXTURE_NAMESPACE: &str = "corvi-system";

/// One read the fake graph served.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphCall {
    /// A provider was read.
    Provider(String),
    /// A mailbox was read.
    Mailbox(String),
    /// An identity was read.
    Identity(String),
    /// A gateway was read.
    Gateway(String),
}

/// A resource graph that answers from a table.
///
/// The graph is deliberately namespace-insensitive: a lookup ignores the
/// namespace it was asked for and returns the fixture, so a test can place
/// a resource in another namespace and watch the cross-namespace refusal.
#[derive(Debug, Default)]
pub struct FakeGraph {
    providers: BTreeMap<String, ProviderStatus>,
    mailboxes: BTreeMap<String, MailboxStatus>,
    identities: BTreeMap<String, IdentityStatus>,
    gateways: BTreeMap<String, GatewayStatus>,
    unavailable: bool,
    calls: RefCell<Vec<GraphCall>>,
}

impl FakeGraph {
    /// An empty graph.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a provider.
    pub fn with_provider(mut self, provider: ProviderStatus) -> Self {
        self.providers.insert(provider.name.clone(), provider);
        self
    }

    /// Add a mailbox.
    pub fn with_mailbox(mut self, mailbox: MailboxStatus) -> Self {
        self.mailboxes.insert(mailbox.name.clone(), mailbox);
        self
    }

    /// Add an identity.
    pub fn with_identity(mut self, identity: IdentityStatus) -> Self {
        self.identities.insert(identity.name.clone(), identity);
        self
    }

    /// Add a gateway.
    pub fn with_gateway(mut self, gateway: GatewayStatus) -> Self {
        self.gateways.insert(gateway.name.clone(), gateway);
        self
    }

    /// Make every read fail, as an unreachable dependency would.
    pub fn set_unavailable(&mut self, unavailable: bool) {
        self.unavailable = unavailable;
    }

    /// The reads this graph served.
    pub fn calls(&self) -> Vec<GraphCall> {
        self.calls.borrow().clone()
    }

    /// The status of one provider, for a test that changes it.
    pub fn providers_mut(&mut self, name: &str) -> &mut ProviderStatus {
        self.providers
            .get_mut(name)
            .expect("the fixture holds this provider")
    }

    /// The status of one mailbox, for a test that changes it.
    pub fn mailboxes_mut(&mut self, name: &str) -> &mut MailboxStatus {
        self.mailboxes
            .get_mut(name)
            .expect("the fixture holds this mailbox")
    }

    /// The status of one identity, for a test that changes it.
    pub fn identities_mut(&mut self, name: &str) -> &mut IdentityStatus {
        self.identities
            .get_mut(name)
            .expect("the fixture holds this identity")
    }

    /// The status of one gateway, for a test that changes it.
    pub fn gateways_mut(&mut self, name: &str) -> &mut GatewayStatus {
        self.gateways
            .get_mut(name)
            .expect("the fixture holds this gateway")
    }
}

impl ParentStatusReader for FakeGraph {
    fn provider(&self, _namespace: &str, name: &str) -> Result<ProviderStatus, StatusReadError> {
        self.calls
            .borrow_mut()
            .push(GraphCall::Provider(name.to_string()));
        if self.unavailable {
            return Err(StatusReadError::Unavailable);
        }
        self.providers
            .get(name)
            .cloned()
            .ok_or(StatusReadError::NotFound)
    }

    fn mailbox(&self, _namespace: &str, name: &str) -> Result<MailboxStatus, StatusReadError> {
        self.calls
            .borrow_mut()
            .push(GraphCall::Mailbox(name.to_string()));
        if self.unavailable {
            return Err(StatusReadError::Unavailable);
        }
        self.mailboxes
            .get(name)
            .cloned()
            .ok_or(StatusReadError::NotFound)
    }

    fn identity(&self, _namespace: &str, name: &str) -> Result<IdentityStatus, StatusReadError> {
        self.calls
            .borrow_mut()
            .push(GraphCall::Identity(name.to_string()));
        if self.unavailable {
            return Err(StatusReadError::Unavailable);
        }
        self.identities
            .get(name)
            .cloned()
            .ok_or(StatusReadError::NotFound)
    }

    fn gateway(&self, _namespace: &str, name: &str) -> Result<GatewayStatus, StatusReadError> {
        self.calls
            .borrow_mut()
            .push(GraphCall::Gateway(name.to_string()));
        if self.unavailable {
            return Err(StatusReadError::Unavailable);
        }
        self.gateways
            .get(name)
            .cloned()
            .ok_or(StatusReadError::NotFound)
    }
}

/// A provider that is attached to a gateway.
pub fn provider_bound(name: &str, gateway: &str) -> ProviderStatus {
    ProviderStatus {
        name: name.to_string(),
        namespace: FIXTURE_NAMESPACE.to_string(),
        uid: format!("{name}-uid"),
        generation: 1,
        observed_generation: 1,
        gateway_ref: Some(crate::admission::LocalRef::new(gateway)),
        suspended: false,
        capabilities: full_capabilities(),
        capabilities_observed_generation: 1,
        direct_endpoints: direct_endpoints(),
        smtp_route: Some(direct_smtp_route()),
    }
}

/// A provider that is not attached to a gateway.
pub fn provider_unbound(name: &str) -> ProviderStatus {
    ProviderStatus {
        gateway_ref: None,
        ..provider_bound(name, "unused-gateway")
    }
}

/// A mailbox that belongs to a provider.
pub fn mailbox(name: &str, provider: &str) -> MailboxStatus {
    MailboxStatus {
        name: name.to_string(),
        namespace: FIXTURE_NAMESPACE.to_string(),
        uid: format!("{name}-uid"),
        generation: 1,
        observed_generation: 1,
        provider_ref: crate::admission::LocalRef::new(provider),
        suspended: false,
        address: Some(format!("{name}@example.test")),
    }
}

/// A verified identity that belongs to a mailbox.
pub fn identity(name: &str, mailbox: &str) -> IdentityStatus {
    IdentityStatus {
        name: name.to_string(),
        namespace: FIXTURE_NAMESPACE.to_string(),
        uid: format!("{name}-uid"),
        generation: 1,
        observed_generation: 1,
        mailbox_ref: crate::admission::LocalRef::new(mailbox),
        verified: true,
        suspended: false,
        address: Some(format!("{name}@example.test")),
    }
}

/// A ready gateway that serves every protocol.
pub fn gateway(name: &str) -> GatewayStatus {
    GatewayStatus {
        name: name.to_string(),
        namespace: FIXTURE_NAMESPACE.to_string(),
        uid: format!("{name}-uid"),
        generation: 1,
        observed_generation: 1,
        ready: true,
        suspended: false,
        supported_types: vec![ProtocolType::Smtp, ProtocolType::Rest, ProtocolType::Mcp],
        endpoints: gateway_endpoints(),
        smtp_route: Some(gateway_smtp_route()),
    }
}

/// The capabilities of a provider that can issue every protocol.
pub fn full_capabilities() -> ProviderCapabilities {
    ProviderCapabilities {
        supported: true,
        types: vec![ProtocolType::Smtp, ProtocolType::Rest, ProtocolType::Mcp],
        granularities: vec![
            CredentialGranularity::ProviderIdentity,
            CredentialGranularity::ProviderMailbox,
        ],
        revoke_supported: true,
    }
}

/// The endpoints a provider advertises for direct connections.
pub fn direct_endpoints() -> Vec<ObservedEndpoint> {
    vec![
        ObservedEndpoint::new(ProtocolType::Mcp, "https://mcp.provider.test/mcp", true),
        ObservedEndpoint::new(ProtocolType::Rest, "https://api.provider.test/rest", true),
        ObservedEndpoint::new(ProtocolType::Smtp, "smtp://smtp.provider.test:587", true),
    ]
}

/// The endpoints a gateway exposes.
pub fn gateway_endpoints() -> Vec<ObservedEndpoint> {
    vec![
        ObservedEndpoint::new(ProtocolType::Mcp, "https://mail.example.test/mcp", true),
        ObservedEndpoint::new(ProtocolType::Rest, "https://mail.example.test/rest", true),
        ObservedEndpoint::new(ProtocolType::Smtp, "smtp://mail.example.test:587", true),
    ]
}

/// The SMTP route a provider advertises.
pub fn direct_smtp_route() -> SmtpRoute {
    SmtpRoute {
        host: "smtp.provider.test".to_string(),
        port: 587,
        tls_mode: TlsMode::StartTls,
        server_name: "smtp.provider.test".to_string(),
        auth_mechanism: SmtpAuthMechanism::Plain,
    }
}

/// The SMTP route a gateway exposes.
pub fn gateway_smtp_route() -> SmtpRoute {
    SmtpRoute {
        host: "mail.example.test".to_string(),
        port: 587,
        tls_mode: TlsMode::StartTls,
        server_name: "mail.example.test".to_string(),
        auth_mechanism: SmtpAuthMechanism::Plain,
    }
}

/// One write the fake store served.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreCall {
    /// A Secret was read.
    Get(String),
    /// A Secret was created.
    Create(String),
    /// A Secret was replaced.
    Replace(String),
    /// A Secret was removed.
    Delete(String),
}

/// A Secret store that behaves like the Kubernetes API where it matters.
///
/// Creation only succeeds when the name is free, and replacement only
/// succeeds when the Secret still has the resource version that was read.
/// Those two rules are what make a lost race visible instead of silent.
#[derive(Debug, Default)]
pub struct FakeSecretStore {
    secrets: RefCell<BTreeMap<(String, String), SecretObject>>,
    versions: RefCell<BTreeMap<(String, String), u64>>,
    next_uid: Cell<u64>,
    race_create: Cell<bool>,
    race_replace: Cell<bool>,
    calls: RefCell<Vec<StoreCall>>,
}

impl FakeSecretStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// The writes this store served.
    pub fn calls(&self) -> Vec<StoreCall> {
        self.calls.borrow().clone()
    }

    /// Simulate another publisher taking the name first.
    ///
    /// The next creation finds a Secret that another owner already wrote
    /// and reports that the name is taken.
    pub fn race_next_create(&self) {
        self.race_create.set(true);
    }

    /// Simulate another writer replacing the Secret between the
    /// publisher's read and its write.
    ///
    /// The next replacement sees a Secret that has moved on, so the
    /// publisher's precondition no longer holds.
    pub fn race_next_replace(&self) {
        self.race_replace.set(true);
    }

    /// Put a Secret into the store as if another producer had written it.
    pub fn insert(&self, secret: SecretObject) {
        let key = (secret.namespace.clone(), secret.name.clone());
        self.versions.borrow_mut().insert(key.clone(), 1);
        self.secrets.borrow_mut().insert(key, secret);
    }

    /// Move a Secret to a new resource version.
    fn bump_version(&self, key: &(String, String)) -> u64 {
        let mut versions = self.versions.borrow_mut();
        let version = versions.entry(key.clone()).or_insert(0);
        *version += 1;
        let next = *version;
        drop(versions);
        if let Some(secret) = self.secrets.borrow_mut().get_mut(key) {
            secret.resource_version = next.to_string();
        }
        next
    }
}

impl SecretStore for FakeSecretStore {
    fn get(&self, namespace: &str, name: &str) -> Result<Option<SecretObject>, SecretStoreError> {
        self.calls
            .borrow_mut()
            .push(StoreCall::Get(name.to_string()));
        let key = (namespace.to_string(), name.to_string());
        Ok(self.secrets.borrow().get(&key).cloned())
    }

    fn create_if_absent(&self, secret: &SecretObject) -> Result<SecretObject, SecretStoreError> {
        self.calls
            .borrow_mut()
            .push(StoreCall::Create(secret.name.clone()));
        let key = (secret.namespace.clone(), secret.name.clone());

        if self.race_create.replace(false) {
            // Another publisher won the name between the read and the
            // write. The loser must not touch the winner's Secret.
            let foreign = SecretObject {
                namespace: secret.namespace.clone(),
                name: secret.name.clone(),
                uid: "foreign-uid".to_string(),
                resource_version: "1".to_string(),
                data: BTreeMap::from([("API_TOKEN".to_string(), "foreign".to_string())]),
                annotations: BTreeMap::new(),
                owner_uid: Some("foreign-owner".to_string()),
            };
            self.secrets.borrow_mut().insert(key.clone(), foreign);
            self.versions.borrow_mut().insert(key, 1);
            return Err(SecretStoreError::AlreadyExists);
        }

        if self.secrets.borrow().contains_key(&key) {
            return Err(SecretStoreError::AlreadyExists);
        }

        let uid = self.next_uid.get() + 1;
        self.next_uid.set(uid);
        let mut stored = secret.clone();
        stored.uid = format!("secret-uid-{uid}");
        stored.resource_version = "1".to_string();
        self.versions.borrow_mut().insert(key.clone(), 1);
        self.secrets.borrow_mut().insert(key, stored.clone());
        Ok(stored)
    }

    fn replace_if_version_matches(
        &self,
        secret: &SecretObject,
        expected_resource_version: &str,
    ) -> Result<SecretObject, SecretStoreError> {
        self.calls
            .borrow_mut()
            .push(StoreCall::Replace(secret.name.clone()));
        let key = (secret.namespace.clone(), secret.name.clone());

        if self.race_replace.replace(false) {
            // Another writer moved the Secret on between the publisher's
            // read and its write.
            self.bump_version(&key);
        }

        let current = self.secrets.borrow().get(&key).cloned();
        let Some(current) = current else {
            return Err(SecretStoreError::Conflict);
        };
        if current.resource_version != expected_resource_version {
            return Err(SecretStoreError::Conflict);
        }

        let next = self.bump_version(&key);
        let mut stored = secret.clone();
        stored.uid = current.uid.clone();
        stored.resource_version = next.to_string();
        self.secrets.borrow_mut().insert(key, stored.clone());
        Ok(stored)
    }

    fn delete_if_version_matches(
        &self,
        namespace: &str,
        name: &str,
        expected_resource_version: &str,
    ) -> Result<(), SecretStoreError> {
        self.calls
            .borrow_mut()
            .push(StoreCall::Delete(name.to_string()));
        let key = (namespace.to_string(), name.to_string());
        let current = self.secrets.borrow().get(&key).cloned();
        let Some(current) = current else {
            return Err(SecretStoreError::Conflict);
        };
        if current.resource_version != expected_resource_version {
            return Err(SecretStoreError::Conflict);
        }
        self.secrets.borrow_mut().remove(&key);
        self.versions.borrow_mut().remove(&key);
        Ok(())
    }
}
