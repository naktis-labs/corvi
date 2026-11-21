//! Bridge lifecycle, publication and failure isolation.
//!
//! ADR-0006 section 4 makes a bridge an infrastructure lifecycle dependency:
//! once a bridge is healthy, controller outages do not block the gateway, but
//! a bridge outage does block the mailboxes attached to it.
//!
//! Three rules are implemented here:
//!
//! * **Readiness precedes publication.** A bridge backed endpoint enters the
//!   gateway configuration snapshot only after the bridge reported ready.
//! * **Failure is local.** A failing bridge makes its own mailboxes report
//!   `bridge unavailable`; every other mailbox keeps working.
//! * **Existing bridges stay independent.** An already installed bridge keeps
//!   its own configuration: Corvi neither adopts nor reconfigures it, and a
//!   managed bridge is only provisioned from an approved digest whose
//!   authenticated capabilities agree with it.

use std::collections::BTreeMap;
use std::fmt;

use crate::descriptor::{BridgeMode, BridgeProtocol};
use crate::trust::ApprovedBridge;

/// The identity of a bridge instance.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BridgeId(String);

impl BridgeId {
    /// A bridge identity.
    pub fn new(name: &str) -> Self {
        Self(name.to_string())
    }

    /// The name of the bridge instance.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BridgeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

/// One endpoint of a bridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointAddress {
    /// The host the bridge listens on.
    pub host: String,
    /// The port the bridge listens on.
    pub port: u16,
}

/// The endpoints of a bridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeEndpoint {
    /// The IMAP endpoint, when the bridge serves IMAP.
    pub imap: Option<EndpointAddress>,
    /// The SMTP endpoint, when the bridge serves SMTP.
    pub smtp: Option<EndpointAddress>,
    /// The identity of the peer certificate the bridge presents.
    pub tls_peer: String,
}

/// The state of a bridge instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeState {
    /// A bridge that is installed and operated independently. Its endpoint is
    /// administrator configured, so it is usable as it is.
    Existing,
    /// A managed bridge that is being provisioned. It is not usable yet.
    Provisioning,
    /// A bridge that reported ready.
    Ready,
    /// A bridge that failed.
    Failed(String),
}

/// The capabilities a bridge reported over its authenticated channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedCapabilities {
    /// The digest of the image the bridge actually runs.
    pub image_digest: String,
    /// The identity of the bridge runtime.
    pub runtime_id: String,
    /// The protocol version the bridge speaks.
    pub protocol_version: String,
}

/// Why a lifecycle operation was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleError {
    /// The bridge is not known.
    UnknownBridge,
    /// The bridge has not reported ready.
    NotReady,
    /// The operation does not apply to this kind of bridge.
    NotManaged,
    /// A bridge with this name already exists.
    AlreadyExists,
    /// The authenticated capabilities disagree with the approved digest.
    CapabilityMismatch {
        /// The approved digest.
        expected: String,
        /// The digest the bridge reported.
        actual: String,
    },
    /// The mailbox is already attached to a bridge.
    MailboxAlreadyAttached,
}

impl fmt::Display for LifecycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LifecycleError::UnknownBridge => write!(formatter, "the bridge is not known"),
            LifecycleError::NotReady => {
                write!(formatter, "the bridge has not reported ready")
            }
            LifecycleError::NotManaged => {
                write!(formatter, "the bridge is not managed by Corvi")
            }
            LifecycleError::AlreadyExists => {
                write!(formatter, "a bridge with this name already exists")
            }
            LifecycleError::CapabilityMismatch { expected, actual } => write!(
                formatter,
                "the bridge reported the digest {actual}, the approved digest is {expected}"
            ),
            LifecycleError::MailboxAlreadyAttached => {
                write!(formatter, "the mailbox is already attached to a bridge")
            }
        }
    }
}

impl std::error::Error for LifecycleError {}

/// Whether a mailbox can be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailboxStatus {
    /// The mailbox is usable.
    Ready,
    /// The mailbox is attached to a bridge that is not usable.
    BridgeUnavailable {
        /// Why the bridge is not usable.
        reason: String,
    },
}

/// A bridge endpoint that may enter the gateway configuration snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedEndpoint {
    /// The bridge the endpoint belongs to.
    pub bridge_id: BridgeId,
    /// The endpoint.
    pub endpoint: BridgeEndpoint,
    /// The protocols the bridge serves.
    pub protocols: Vec<BridgeProtocol>,
}

/// The gateway configuration snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GatewaySnapshot {
    /// The bridge endpoints that are published.
    pub endpoints: Vec<PublishedEndpoint>,
}

/// One bridge instance.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BridgeRecord {
    name: String,
    mode: BridgeMode,
    state: BridgeState,
    endpoint: Option<BridgeEndpoint>,
    protocols: Vec<BridgeProtocol>,
    image_digest: Option<String>,
}

/// The bridge instances and the mailboxes attached to them.
#[derive(Debug, Clone, Default)]
pub struct BridgeSupervisor {
    bridges: BTreeMap<BridgeId, BridgeRecord>,
    mailboxes: BTreeMap<String, BridgeId>,
}

impl BridgeSupervisor {
    /// A supervisor without any bridge.
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach an already installed bridge.
    ///
    /// The endpoint is the administrator's configuration. Corvi records it and
    /// publishes it as it is: it neither adopts the bridge into its own
    /// lifecycle nor reconfigures it.
    pub fn attach_existing(
        &mut self,
        name: &str,
        endpoint: BridgeEndpoint,
        protocols: Vec<BridgeProtocol>,
    ) -> Result<BridgeId, LifecycleError> {
        let id = BridgeId::new(name);
        if self.bridges.contains_key(&id) {
            return Err(LifecycleError::AlreadyExists);
        }
        self.bridges.insert(
            id.clone(),
            BridgeRecord {
                name: name.to_string(),
                mode: BridgeMode::Existing,
                state: BridgeState::Existing,
                endpoint: Some(endpoint),
                protocols,
                image_digest: None,
            },
        );
        Ok(id)
    }

    /// Provision a managed bridge from an approved digest.
    ///
    /// The authenticated capabilities of the running bridge must agree with the
    /// approved digest: a bridge that reports a different image than the one
    /// that was approved is refused.
    pub fn provision_managed(
        &mut self,
        name: &str,
        approved: &ApprovedBridge,
        capabilities: &AuthenticatedCapabilities,
    ) -> Result<BridgeId, LifecycleError> {
        if approved.mode != BridgeMode::Managed {
            return Err(LifecycleError::NotManaged);
        }
        let image = approved.image.as_ref().ok_or(LifecycleError::NotManaged)?;
        if capabilities.image_digest != image.digest() {
            return Err(LifecycleError::CapabilityMismatch {
                expected: image.digest().to_string(),
                actual: capabilities.image_digest.clone(),
            });
        }

        let id = BridgeId::new(name);
        if self.bridges.contains_key(&id) {
            return Err(LifecycleError::AlreadyExists);
        }
        self.bridges.insert(
            id.clone(),
            BridgeRecord {
                name: name.to_string(),
                mode: BridgeMode::Managed,
                state: BridgeState::Provisioning,
                endpoint: None,
                protocols: approved.protocols.clone(),
                image_digest: Some(capabilities.image_digest.clone()),
            },
        );
        Ok(id)
    }

    /// Record that a bridge reported ready.
    pub fn mark_ready(
        &mut self,
        id: &BridgeId,
        endpoint: BridgeEndpoint,
    ) -> Result<(), LifecycleError> {
        let record = self.record_mut(id)?;
        if record.mode != BridgeMode::Managed {
            return Err(LifecycleError::NotManaged);
        }
        record.state = BridgeState::Ready;
        record.endpoint = Some(endpoint);
        Ok(())
    }

    /// Record that a bridge failed.
    pub fn mark_failed(&mut self, id: &BridgeId, reason: &str) {
        if let Ok(record) = self.record_mut(id) {
            record.state = BridgeState::Failed(reason.to_string());
        }
    }

    /// The endpoint of a bridge, if it may be published.
    pub fn publish(&self, id: &BridgeId) -> Result<PublishedEndpoint, LifecycleError> {
        let record = self.bridges.get(id).ok_or(LifecycleError::UnknownBridge)?;

        match &record.state {
            BridgeState::Ready | BridgeState::Existing => {}
            BridgeState::Provisioning | BridgeState::Failed(_) => {
                return Err(LifecycleError::NotReady);
            }
        }

        let endpoint = record.endpoint.clone().ok_or(LifecycleError::NotReady)?;

        Ok(PublishedEndpoint {
            bridge_id: id.clone(),
            endpoint,
            protocols: record.protocols.clone(),
        })
    }

    /// Attach a mailbox to a bridge.
    pub fn attach_mailbox(
        &mut self,
        mailbox: &str,
        bridge: &BridgeId,
    ) -> Result<(), LifecycleError> {
        if !self.bridges.contains_key(bridge) {
            return Err(LifecycleError::UnknownBridge);
        }
        if self.mailboxes.contains_key(mailbox) {
            return Err(LifecycleError::MailboxAlreadyAttached);
        }
        self.mailboxes.insert(mailbox.to_string(), bridge.clone());
        Ok(())
    }

    /// Whether a mailbox can be used.
    ///
    /// Only the mailboxes attached to a failing bridge are affected.
    pub fn mailbox_status(&self, mailbox: &str) -> MailboxStatus {
        let Some(bridge) = self.mailboxes.get(mailbox) else {
            return MailboxStatus::Ready;
        };
        let Some(record) = self.bridges.get(bridge) else {
            return MailboxStatus::BridgeUnavailable {
                reason: "the bridge is gone".to_string(),
            };
        };

        match &record.state {
            BridgeState::Ready | BridgeState::Existing => MailboxStatus::Ready,
            BridgeState::Provisioning => MailboxStatus::BridgeUnavailable {
                reason: "the bridge is not ready".to_string(),
            },
            BridgeState::Failed(reason) => MailboxStatus::BridgeUnavailable {
                reason: reason.clone(),
            },
        }
    }

    /// The configuration snapshot of the ready bridges.
    pub fn snapshot(&self) -> GatewaySnapshot {
        let mut endpoints = Vec::new();
        for (id, record) in &self.bridges {
            if !matches!(record.state, BridgeState::Ready | BridgeState::Existing) {
                continue;
            }
            if let Some(endpoint) = record.endpoint.clone() {
                endpoints.push(PublishedEndpoint {
                    bridge_id: id.clone(),
                    endpoint,
                    protocols: record.protocols.clone(),
                });
            }
        }
        GatewaySnapshot { endpoints }
    }

    /// The state of a bridge.
    pub fn bridge_state(&self, id: &BridgeId) -> Option<&BridgeState> {
        self.bridges.get(id).map(|record| &record.state)
    }

    /// The name of a bridge instance.
    pub fn bridge_name(&self, id: &BridgeId) -> Option<&str> {
        self.bridges.get(id).map(|record| record.name.as_str())
    }

    /// The record of a bridge.
    fn record_mut(&mut self, id: &BridgeId) -> Result<&mut BridgeRecord, LifecycleError> {
        self.bridges
            .get_mut(id)
            .ok_or(LifecycleError::UnknownBridge)
    }
}
