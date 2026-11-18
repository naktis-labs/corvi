//! Authenticated provider-management contracts, separate from mail request handling.
//!
//! This crate holds the vocabulary the control plane and a provider plugin
//! share: the operations a provider may be asked to perform, the transport
//! protocols it may advertise, the status classes a provider may report, the
//! shape of a bounded request payload and the identity of the peer on the
//! other side of the connection.
//!
//! Three rules shape the types here.
//!
//! * **Nothing is implied.** A capability is advertised or it is not. A
//!   destructive upstream action is not part of the advertised vocabulary at
//!   all, so no capability set can imply support for one.
//! * **Untrusted input stays untrusted.** A secret identifier is an opaque
//!   name, never a path, and a payload is bounded before it is accepted.
//! * **Failure is typed.** A caller can tell an unsupported capability from a
//!   validation failure, a provider outage and a peer mismatch, so it fails
//!   closed instead of retrying the wrong thing.
//!
//! # What is not implemented
//!
//! This crate is a contract. It has no server, no transport, no TLS
//! termination, no peer verification and no provider integration: nothing
//! here opens a socket. The peer identity, the deadline and the bounded
//! payload are the values a server would have to enforce, and the types make
//! them explicit so a server cannot quietly omit one.

use std::{collections::BTreeSet, fmt, time::Duration, time::Instant};

/// The version of the provider contract this crate implements.
pub const PROTOCOL_VERSION: u32 = 1;

/// The largest configuration snapshot document that may be published (1 MiB).
pub const MAX_SNAPSHOT_BYTES: usize = 1_048_576;

/// The largest provider request payload that may be accepted (1 MiB).
pub const MAX_EXECUTE_PAYLOAD_BYTES: usize = 1_048_576;

pub mod publication;

pub use publication::{Ack, Snapshot, SnapshotStore};

/// The provider management operations this contract defines.
///
/// Destructive upstream actions are deliberately absent. ADR-0001 forbids
/// inventing destructive reconciliation for operations a provider does not
/// support, so `delete_domain` and `delete_mailbox` are not operations this
/// contract can advertise, request or dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Operation {
    ListDomains,
    GetDomain,
    CreateDomain,
    UpdateDomain,
    ListMailboxes,
    GetMailbox,
    CreateMailbox,
    UpdateMailbox,
    RotateMailboxPassword,
    ListAliases,
    CreateAlias,
    UpdateAlias,
    ListForwardings,
    CreateForwarding,
    UpdateForwarding,
    ListSenderIdentities,
    CreateSenderIdentity,
    UpdateSenderIdentity,
    GetUsage,
    GetHealth,
}

impl Operation {
    /// Every operation in the vocabulary.
    pub const ALL: [Operation; 20] = [
        Operation::ListDomains,
        Operation::GetDomain,
        Operation::CreateDomain,
        Operation::UpdateDomain,
        Operation::ListMailboxes,
        Operation::GetMailbox,
        Operation::CreateMailbox,
        Operation::UpdateMailbox,
        Operation::RotateMailboxPassword,
        Operation::ListAliases,
        Operation::CreateAlias,
        Operation::UpdateAlias,
        Operation::ListForwardings,
        Operation::CreateForwarding,
        Operation::UpdateForwarding,
        Operation::ListSenderIdentities,
        Operation::CreateSenderIdentity,
        Operation::UpdateSenderIdentity,
        Operation::GetUsage,
        Operation::GetHealth,
    ];

    /// The wire name of the operation.
    pub fn as_wire(self) -> &'static str {
        match self {
            Operation::ListDomains => "list_domains",
            Operation::GetDomain => "get_domain",
            Operation::CreateDomain => "create_domain",
            Operation::UpdateDomain => "update_domain",
            Operation::ListMailboxes => "list_mailboxes",
            Operation::GetMailbox => "get_mailbox",
            Operation::CreateMailbox => "create_mailbox",
            Operation::UpdateMailbox => "update_mailbox",
            Operation::RotateMailboxPassword => "rotate_mailbox_password",
            Operation::ListAliases => "list_aliases",
            Operation::CreateAlias => "create_alias",
            Operation::UpdateAlias => "update_alias",
            Operation::ListForwardings => "list_forwardings",
            Operation::CreateForwarding => "create_forwarding",
            Operation::UpdateForwarding => "update_forwarding",
            Operation::ListSenderIdentities => "list_sender_identities",
            Operation::CreateSenderIdentity => "create_sender_identity",
            Operation::UpdateSenderIdentity => "update_sender_identity",
            Operation::GetUsage => "get_usage",
            Operation::GetHealth => "get_health",
        }
    }

    /// Parse a wire operation name.
    ///
    /// Only the allowlist is accepted. An unknown name and a destructive
    /// action are both refused, because neither is an operation this contract
    /// can dispatch.
    pub fn from_wire(name: &str) -> Result<Self, ProviderError> {
        Self::ALL
            .into_iter()
            .find(|operation| operation.as_wire() == name)
            .ok_or_else(|| ProviderError::UnsupportedOperation {
                name: name.to_string(),
            })
    }
}

/// The protocols a provider may serve mail reads from.
///
/// ADR-0007 fixes the read dimension to IMAP and JMAP. There is no third
/// value and no automatic fallback to IMAP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReadProtocol {
    Imap,
    Jmap,
}

impl ReadProtocol {
    /// Every read protocol.
    pub const ALL: [ReadProtocol; 2] = [ReadProtocol::Imap, ReadProtocol::Jmap];

    /// The wire name of the protocol.
    pub fn as_wire(self) -> &'static str {
        match self {
            ReadProtocol::Imap => "imap",
            ReadProtocol::Jmap => "jmap",
        }
    }

    /// Parse a wire protocol name.
    pub fn from_wire(name: &str) -> Result<Self, ProviderError> {
        Self::ALL
            .into_iter()
            .find(|protocol| protocol.as_wire() == name)
            .ok_or_else(|| ProviderError::InvalidCapability {
                name: name.to_string(),
            })
    }
}

/// The protocols a provider may submit mail through.
///
/// ADR-0007 fixes the submission dimension to SMTP, JMAP or `disabled`.
/// `disabled` is a client-side choice, not a provider capability: a provider
/// never advertises it, and a control plane may always select it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SubmissionProtocol {
    Smtp,
    Jmap,
    Disabled,
}

impl SubmissionProtocol {
    /// Every submission protocol.
    pub const ALL: [SubmissionProtocol; 3] = [
        SubmissionProtocol::Smtp,
        SubmissionProtocol::Jmap,
        SubmissionProtocol::Disabled,
    ];

    /// The protocols a provider may advertise.
    ///
    /// `disabled` is excluded: it describes a client that does not submit,
    /// not a capability the provider offers.
    pub const ADVERTISABLE: [SubmissionProtocol; 2] =
        [SubmissionProtocol::Smtp, SubmissionProtocol::Jmap];

    /// The wire name of the protocol.
    pub fn as_wire(self) -> &'static str {
        match self {
            SubmissionProtocol::Smtp => "smtp",
            SubmissionProtocol::Jmap => "jmap",
            SubmissionProtocol::Disabled => "disabled",
        }
    }

    /// Parse a wire protocol name.
    pub fn from_wire(name: &str) -> Result<Self, ProviderError> {
        Self::ALL
            .into_iter()
            .find(|protocol| protocol.as_wire() == name)
            .ok_or_else(|| ProviderError::InvalidCapability {
                name: name.to_string(),
            })
    }
}

/// What a provider may be asked to do, and which transport protocols it
/// offers.
///
/// A capability set is what a provider advertises and what a caller is
/// allowed to assume. It never implies support for an operation that is not
/// in the set.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Capabilities {
    operations: BTreeSet<Operation>,
    read_protocols: BTreeSet<ReadProtocol>,
    submission_protocols: BTreeSet<SubmissionProtocol>,
}

impl Capabilities {
    /// Capabilities that advertise management operations only.
    pub fn new(operations: impl IntoIterator<Item = Operation>) -> Self {
        Self {
            operations: operations.into_iter().collect(),
            read_protocols: BTreeSet::new(),
            submission_protocols: BTreeSet::new(),
        }
    }

    /// Advertise the transport protocols the provider offers.
    pub fn with_protocols(
        mut self,
        read: impl IntoIterator<Item = ReadProtocol>,
        submission: impl IntoIterator<Item = SubmissionProtocol>,
    ) -> Self {
        self.read_protocols = read.into_iter().collect();
        self.submission_protocols = submission.into_iter().collect();
        self
    }

    /// Whether the provider advertises the operation.
    pub fn supports(&self, operation: Operation) -> bool {
        self.operations.contains(&operation)
    }

    /// Require an advertised operation.
    pub fn require(&self, operation: Operation) -> Result<(), ProviderError> {
        self.supports(operation)
            .then_some(())
            .ok_or(ProviderError::Unsupported(operation))
    }

    /// Whether the provider advertises the read protocol.
    pub fn supports_read(&self, protocol: ReadProtocol) -> bool {
        self.read_protocols.contains(&protocol)
    }

    /// Require an advertised read protocol.
    pub fn require_read(&self, protocol: ReadProtocol) -> Result<(), ProviderError> {
        self.supports_read(protocol)
            .then_some(())
            .ok_or(ProviderError::ProtocolNotAdvertised {
                protocol: protocol.as_wire().to_string(),
            })
    }

    /// Whether the selection may use the submission protocol.
    ///
    /// `disabled` is always permitted: it selects no upstream submission.
    pub fn supports_submission(&self, protocol: SubmissionProtocol) -> bool {
        protocol == SubmissionProtocol::Disabled || self.submission_protocols.contains(&protocol)
    }

    /// Require a usable submission protocol.
    pub fn require_submission(&self, protocol: SubmissionProtocol) -> Result<(), ProviderError> {
        self.supports_submission(protocol).then_some(()).ok_or(
            ProviderError::ProtocolNotAdvertised {
                protocol: protocol.as_wire().to_string(),
            },
        )
    }

    /// The advertised operations.
    pub fn operations(&self) -> impl Iterator<Item = Operation> + '_ {
        self.operations.iter().copied()
    }

    /// The advertised read protocols.
    pub fn read_protocols(&self) -> impl Iterator<Item = ReadProtocol> + '_ {
        self.read_protocols.iter().copied()
    }

    /// The advertised submission protocols.
    pub fn submission_protocols(&self) -> impl Iterator<Item = SubmissionProtocol> + '_ {
        self.submission_protocols.iter().copied()
    }

    /// The wire form of the advertised operations.
    pub fn wire_operations(&self) -> Vec<&'static str> {
        self.operations().map(Operation::as_wire).collect()
    }

    /// The wire form of the advertised read protocols.
    pub fn wire_read_protocols(&self) -> Vec<&'static str> {
        self.read_protocols().map(ReadProtocol::as_wire).collect()
    }

    /// The wire form of the advertised submission protocols.
    pub fn wire_submission_protocols(&self) -> Vec<&'static str> {
        self.submission_protocols()
            .map(SubmissionProtocol::as_wire)
            .collect()
    }

    /// Parse an advertised capability set.
    ///
    /// Every name must be in the contract vocabulary. A provider that
    /// advertises an unknown operation or protocol is refused rather than
    /// trusted, and `disabled` is refused as a submission capability.
    pub fn from_wire(
        operations: &[&str],
        read_protocols: &[&str],
        submission_protocols: &[&str],
    ) -> Result<Self, ProviderError> {
        let operations = operations
            .iter()
            .map(|name| Operation::from_wire(name))
            .collect::<Result<BTreeSet<_>, _>>()?;
        let read_protocols = read_protocols
            .iter()
            .map(|name| ReadProtocol::from_wire(name))
            .collect::<Result<BTreeSet<_>, _>>()?;
        let submission_protocols = submission_protocols
            .iter()
            .map(|name| {
                let protocol = SubmissionProtocol::from_wire(name)?;
                if protocol == SubmissionProtocol::Disabled {
                    return Err(ProviderError::InvalidCapability {
                        name: name.to_string(),
                    });
                }
                Ok(protocol)
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        Ok(Self {
            operations,
            read_protocols,
            submission_protocols,
        })
    }
}

/// An independent read and submission protocol selection.
///
/// ADR-0007: the read dimension is `imap` or `jmap` and the submission
/// dimension is `smtp`, `jmap` or `disabled`. The two are chosen
/// independently and neither falls back to the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolSelection {
    read: ReadProtocol,
    submission: SubmissionProtocol,
}

impl ProtocolSelection {
    /// Select a read protocol and a submission protocol independently.
    pub fn new(
        read: impl Into<String>,
        submission: impl Into<String>,
    ) -> Result<Self, ProviderError> {
        let (read, submission) = (read.into(), submission.into());
        let read =
            ReadProtocol::from_wire(&read).map_err(|_| ProviderError::InvalidProtocolSelection)?;
        let submission = SubmissionProtocol::from_wire(&submission)
            .map_err(|_| ProviderError::InvalidProtocolSelection)?;
        Ok(Self { read, submission })
    }

    /// The selected read protocol.
    pub fn read(&self) -> ReadProtocol {
        self.read
    }

    /// The selected submission protocol.
    pub fn submission(&self) -> SubmissionProtocol {
        self.submission
    }

    /// The wire form of the selection.
    pub fn wire(&self) -> (&'static str, &'static str) {
        (self.read.as_wire(), self.submission.as_wire())
    }
}

/// An opaque name only. Resolution and authorization belong to a trusted secret broker.
///
/// ADR-0001 requires plugin-supplied secret identifiers to be mapped through
/// a control-plane-owned allowlist and never to be treated as arbitrary
/// paths, so the identifier is a two-segment name whose segments are neither
/// empty nor a dot segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRef(String);

impl SecretRef {
    /// Build an opaque secret identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, ProviderError> {
        let value = value.into();
        let mut parts = value.split('/');
        let valid = match (parts.next(), parts.next(), parts.next()) {
            (Some(namespace), Some(name), None) => [namespace, name]
                .iter()
                .all(|segment| valid_segment(segment)),
            _ => false,
        };
        if valid {
            Ok(Self(value))
        } else {
            Err(ProviderError::InvalidSecretRef)
        }
    }

    /// The identifier as an opaque string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A segment is a plain name: not empty, not a dot segment, bounded in length
/// and restricted to characters that carry no path meaning.
fn valid_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && segment.len() <= 253
        && segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

/// A request payload that respects the contract size limit.
///
/// The provider surface accepts at most 1 MiB per message. The limit is
/// enforced here rather than trusted from the peer, so an oversized payload
/// is refused before it is dispatched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedPayload(Vec<u8>);

impl BoundedPayload {
    /// Build a bounded payload.
    pub fn new(bytes: Vec<u8>) -> Result<Self, ProviderError> {
        if bytes.len() > MAX_EXECUTE_PAYLOAD_BYTES {
            return Err(ProviderError::PayloadTooLarge);
        }
        Ok(Self(bytes))
    }

    /// The payload bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The payload length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the payload is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// The status classes a provider may report.
///
/// ADR-0001 requires status to distinguish an unsupported capability, a
/// provider that is not configured, a validation failure, a provider outage
/// and actual drift. The vocabulary is closed: a status outside it is not a
/// status Corvi understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProviderStatus {
    Ok,
    UnsupportedOperation,
    NotConfigured,
    ValidationFailed,
    ProviderOutage,
    Drift,
}

impl ProviderStatus {
    /// Every status.
    pub const ALL: [ProviderStatus; 6] = [
        ProviderStatus::Ok,
        ProviderStatus::UnsupportedOperation,
        ProviderStatus::NotConfigured,
        ProviderStatus::ValidationFailed,
        ProviderStatus::ProviderOutage,
        ProviderStatus::Drift,
    ];

    /// The wire name of the status.
    pub fn as_wire(self) -> &'static str {
        match self {
            ProviderStatus::Ok => "ok",
            ProviderStatus::UnsupportedOperation => "unsupported_operation",
            ProviderStatus::NotConfigured => "not_configured",
            ProviderStatus::ValidationFailed => "validation_failed",
            ProviderStatus::ProviderOutage => "provider_outage",
            ProviderStatus::Drift => "drift",
        }
    }

    /// Parse a wire status name.
    pub fn from_wire(name: &str) -> Result<Self, ProviderError> {
        Self::ALL
            .into_iter()
            .find(|status| status.as_wire() == name)
            .ok_or_else(|| ProviderError::InvalidStatus {
                name: name.to_string(),
            })
    }
}

/// Why a provider request was refused.
///
/// Every variant is a permanent condition: the request is wrong, the peer is
/// not who it claims to be, or the contract does not allow it. A provider
/// that is merely unavailable reports a [`ProviderStatus`] instead, so a
/// caller never retries a request that cannot succeed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderError {
    /// The provider does not advertise this operation.
    Unsupported(Operation),
    /// The requested operation name is not in the contract allowlist.
    ///
    /// Destructive actions and unknown names both land here: neither is an
    /// operation this contract can dispatch.
    UnsupportedOperation { name: String },
    /// An advertised capability name is not in the contract vocabulary.
    InvalidCapability { name: String },
    /// A status name is not in the contract vocabulary.
    InvalidStatus { name: String },
    /// The read and submission protocols are not a legal pair.
    InvalidProtocolSelection,
    /// The provider does not advertise the selected protocol.
    ProtocolNotAdvertised { protocol: String },
    /// The secret identifier is malformed or path-like.
    InvalidSecretRef,
    /// The request payload exceeds the contract limit.
    PayloadTooLarge,
    /// The snapshot candidate is empty, partial or otherwise invalid.
    InvalidSnapshot,
    /// The published document carries a different generation than the
    /// publication it was offered under.
    GenerationMismatch { published: u64, document: u64 },
    /// The snapshot document exceeds the contract limit.
    SnapshotTooLarge,
    /// The peer speaks a different contract version.
    IncompatibleVersion,
    /// The snapshot generation is not newer than the one in service.
    StaleGeneration,
    /// The acknowledgement does not match the pending snapshot.
    AckMismatch,
    /// The digest the publisher stated does not match the snapshot bytes.
    DigestMismatch,
    /// The peer identity is not the identity that was expected.
    PeerMismatch { expected: String, actual: String },
}

impl ProviderError {
    /// Whether repeating the same request could succeed.
    ///
    /// Contract errors are permanent. A provider outage is reported as a
    /// [`ProviderStatus`], not as an error, so the retry decision stays with
    /// the caller that owns the outage policy.
    pub fn is_retryable(&self) -> bool {
        false
    }
}

impl fmt::Display for ProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ProviderError {}

/// The deadline that accompanies one provider call.
///
/// ADR-0001 requires plugin RPCs to use deadlines. The deadline travels with
/// the call so the boundary that performs the call can abandon work that
/// outlives its budget instead of blocking the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deadline {
    at: Instant,
}

impl Deadline {
    /// A deadline that expires after the given duration.
    pub fn after(duration: Duration) -> Self {
        Self {
            at: Instant::now() + duration,
        }
    }

    /// The time left before the deadline, or `None` once it has passed.
    pub fn remaining(&self) -> Option<Duration> {
        self.at.checked_duration_since(Instant::now())
    }

    /// Whether the deadline has passed.
    pub fn expired(&self) -> bool {
        self.remaining().is_none()
    }
}

/// Transport authentication contract. The implementation must verify peer identity, not only TLS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedPeer {
    pub identity: String,
    pub contract_version: u32,
}

impl AuthenticatedPeer {
    /// Check the peer identity and the contract version.
    ///
    /// A mismatched identity is a peer error, not a snapshot error: it is
    /// reported separately so a caller fails closed instead of retrying a
    /// request that reached the wrong peer.
    pub fn validate(&self, expected_identity: &str, version: u32) -> Result<(), ProviderError> {
        if self.identity != expected_identity {
            return Err(ProviderError::PeerMismatch {
                expected: expected_identity.to_string(),
                actual: self.identity.clone(),
            });
        }
        if self.contract_version != version {
            return Err(ProviderError::IncompatibleVersion);
        }
        Ok(())
    }
}
