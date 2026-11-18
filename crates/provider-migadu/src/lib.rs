//! Migadu management adapter. It is not linked into the mail request path.
//!
//! The adapter is a capability gate in front of a provider API, not a client
//! for one. It refuses a request the provider does not advertise, it never
//! dispatches a destructive upstream action, and it classifies what comes
//! back so a caller can tell an unsupported capability from a provider that
//! is not configured, a validation failure, an outage and real drift.
//!
//! The authenticated HTTPS call itself is supplied by the host as a closure.
//! This crate does not open a socket, does not terminate TLS and does not
//! know the provider's credentials.

use mail_admin::{
    Capabilities, Deadline, Operation, ProtocolSelection, ProviderError, ProviderStatus,
};
use std::fmt;

/// A management request.
///
/// The destructive variants are deliberately typed but never dispatched. The
/// contract has no destructive operation, so no capability set can enable
/// one, and a request that names one is refused with a typed error before
/// the provider is contacted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    ListDomains,
    GetDomain(String),
    CreateDomain(String),
    UpdateDomain {
        name: String,
        config: Vec<u8>,
    },
    ListMailboxes(String),
    GetMailbox {
        domain: String,
        local_part: String,
    },
    CreateMailbox {
        domain: String,
        local_part: String,
    },
    UpdateMailbox {
        domain: String,
        local_part: String,
        config: Vec<u8>,
    },
    RotateMailboxPassword {
        domain: String,
        local_part: String,
    },
    ListAliases(String),
    CreateAlias {
        address: String,
        destination: String,
    },
    UpdateAlias {
        address: String,
        destination: String,
    },
    ListForwardings(String),
    CreateForwarding {
        address: String,
        destination: String,
    },
    UpdateForwarding {
        address: String,
        destination: String,
    },
    ListSenderIdentities(String),
    CreateSenderIdentity {
        mailbox: String,
        address: String,
    },
    UpdateSenderIdentity {
        mailbox: String,
        address: String,
    },
    GetUsage {
        domain: Option<String>,
        mailbox: Option<String>,
    },
    GetHealth,
    DeleteDomain(String),
    DeleteMailbox {
        domain: String,
        local_part: String,
    },
}

impl Request {
    /// The capability this request needs.
    ///
    /// A destructive request needs no capability, because there is none to
    /// hold: it maps to nothing and is refused.
    pub fn operation(&self) -> Option<Operation> {
        Some(match self {
            Self::ListDomains => Operation::ListDomains,
            Self::GetDomain(_) => Operation::GetDomain,
            Self::CreateDomain(_) => Operation::CreateDomain,
            Self::UpdateDomain { .. } => Operation::UpdateDomain,
            Self::ListMailboxes(_) => Operation::ListMailboxes,
            Self::GetMailbox { .. } => Operation::GetMailbox,
            Self::CreateMailbox { .. } => Operation::CreateMailbox,
            Self::UpdateMailbox { .. } => Operation::UpdateMailbox,
            Self::RotateMailboxPassword { .. } => Operation::RotateMailboxPassword,
            Self::ListAliases(_) => Operation::ListAliases,
            Self::CreateAlias { .. } => Operation::CreateAlias,
            Self::UpdateAlias { .. } => Operation::UpdateAlias,
            Self::ListForwardings(_) => Operation::ListForwardings,
            Self::CreateForwarding { .. } => Operation::CreateForwarding,
            Self::UpdateForwarding { .. } => Operation::UpdateForwarding,
            Self::ListSenderIdentities(_) => Operation::ListSenderIdentities,
            Self::CreateSenderIdentity { .. } => Operation::CreateSenderIdentity,
            Self::UpdateSenderIdentity { .. } => Operation::UpdateSenderIdentity,
            Self::GetUsage { .. } => Operation::GetUsage,
            Self::GetHealth => Operation::GetHealth,
            Self::DeleteDomain(_) | Self::DeleteMailbox { .. } => return None,
        })
    }

    /// The wire name of the requested operation.
    ///
    /// The name is what a provider request carries, including the names this
    /// contract refuses to dispatch.
    pub fn wire_name(&self) -> &'static str {
        match self {
            Self::ListDomains => "list_domains",
            Self::GetDomain(_) => "get_domain",
            Self::CreateDomain(_) => "create_domain",
            Self::UpdateDomain { .. } => "update_domain",
            Self::ListMailboxes(_) => "list_mailboxes",
            Self::GetMailbox { .. } => "get_mailbox",
            Self::CreateMailbox { .. } => "create_mailbox",
            Self::UpdateMailbox { .. } => "update_mailbox",
            Self::RotateMailboxPassword { .. } => "rotate_mailbox_password",
            Self::ListAliases(_) => "list_aliases",
            Self::CreateAlias { .. } => "create_alias",
            Self::UpdateAlias { .. } => "update_alias",
            Self::ListForwardings(_) => "list_forwardings",
            Self::CreateForwarding { .. } => "create_forwarding",
            Self::UpdateForwarding { .. } => "update_forwarding",
            Self::ListSenderIdentities(_) => "list_sender_identities",
            Self::CreateSenderIdentity { .. } => "create_sender_identity",
            Self::UpdateSenderIdentity { .. } => "update_sender_identity",
            Self::GetUsage { .. } => "get_usage",
            Self::GetHealth => "get_health",
            Self::DeleteDomain(_) => "delete_domain",
            Self::DeleteMailbox { .. } => "delete_mailbox",
        }
    }
}

/// How a provider call failed, as classified at the call boundary.
///
/// The boundary that performs the call knows whether it had credentials, what
/// the provider answered and whether it could reach the provider at all. It
/// reports that distinction here; this crate does not guess it from an
/// opaque error string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallFailure {
    /// The provider has no configured admin credential or endpoint.
    NotConfigured,
    /// The provider rejected the request as invalid.
    ValidationFailed,
    /// The provider was unreachable or failed.
    ProviderOutage,
    /// The observed upstream state differs from the requested state.
    Drift,
    /// The call outlived its deadline.
    DeadlineExceeded,
}

impl CallFailure {
    /// The status class the failure maps to.
    ///
    /// A deadline overrun is not a provider status: it is a boundary
    /// condition of this call, and it keeps its own error.
    pub fn status(&self) -> ProviderStatus {
        match self {
            CallFailure::NotConfigured => ProviderStatus::NotConfigured,
            CallFailure::ValidationFailed => ProviderStatus::ValidationFailed,
            CallFailure::ProviderOutage => ProviderStatus::ProviderOutage,
            CallFailure::Drift => ProviderStatus::Drift,
            CallFailure::DeadlineExceeded => ProviderStatus::ProviderOutage,
        }
    }
}

/// Why a management call did not produce a result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigaduError {
    /// The request was refused before the provider was contacted.
    ///
    /// The contract does not allow it, or the provider does not advertise the
    /// capability it needs.
    Contract(ProviderError),
    /// The provider reported a typed status.
    Status(ProviderStatus),
    /// The call deadline expired before or during the call.
    DeadlineExceeded,
}

impl fmt::Display for MigaduError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for MigaduError {}
impl From<ProviderError> for MigaduError {
    fn from(error: ProviderError) -> Self {
        Self::Contract(error)
    }
}
impl From<CallFailure> for MigaduError {
    fn from(failure: CallFailure) -> Self {
        match failure {
            CallFailure::DeadlineExceeded => MigaduError::DeadlineExceeded,
            other => MigaduError::Status(other.status()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigaduResponse {
    Empty,
    Document(Vec<u8>),
    Usage {
        measured: Option<u64>,
        configured_limit: Option<u64>,
    },
}
impl MigaduResponse {
    /// Migadu delivery metadata is not treated as trusted envelope provenance.
    pub fn trusted_recipient(&self) -> Option<&str> {
        None
    }
}

/// The capability-gated Migadu management adapter.
#[derive(Debug, Clone)]
pub struct Migadu {
    capabilities: Capabilities,
}

impl Migadu {
    /// An adapter for a provider that advertises the given capabilities.
    pub fn new(capabilities: Capabilities) -> Self {
        Self { capabilities }
    }

    /// The capabilities the provider advertises.
    pub fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    /// Select the read and submission protocols the provider offers.
    ///
    /// The selection is refused unless the provider advertises both halves:
    /// a provider that offers no JMAP cannot be asked for a JMAP transport.
    pub fn protocol_selection(
        &self,
        read: &str,
        submission: &str,
    ) -> Result<ProtocolSelection, ProviderError> {
        let selection = ProtocolSelection::new(read, submission)?;
        self.capabilities.require_read(selection.read())?;
        self.capabilities
            .require_submission(selection.submission())?;
        Ok(selection)
    }

    /// Resolve a wire operation name against the advertised capabilities.
    ///
    /// This is the check a server performs before it dispatches a request. A
    /// name outside the contract allowlist and an operation the provider does
    /// not advertise are refused with distinct typed errors.
    pub fn resolve_operation(&self, name: &str) -> Result<Operation, MigaduError> {
        let operation = Operation::from_wire(name).map_err(MigaduError::Contract)?;
        self.capabilities
            .require(operation)
            .map_err(MigaduError::Contract)?;
        Ok(operation)
    }

    /// Perform one management call.
    ///
    /// The closure is the authenticated HTTPS API boundary supplied by the
    /// host. It runs only for management calls; a provider outage returns a
    /// typed failure, never fabricated state. The deadline travels with the
    /// call, and a call that has outlived it is never started.
    pub fn execute<F>(
        &self,
        request: Request,
        deadline: Deadline,
        call: F,
    ) -> Result<MigaduResponse, MigaduError>
    where
        F: FnOnce(&Request, Deadline) -> Result<MigaduResponse, CallFailure>,
    {
        let Some(operation) = request.operation() else {
            // Destructive operations are intentionally not dispatched, even if a
            // caller provides a permissive capability set, until an official
            // supported endpoint is verified.
            return Err(MigaduError::Contract(ProviderError::UnsupportedOperation {
                name: request.wire_name().to_string(),
            }));
        };
        self.capabilities
            .require(operation)
            .map_err(MigaduError::Contract)?;
        if deadline.expired() {
            return Err(MigaduError::DeadlineExceeded);
        }
        call(&request, deadline).map_err(MigaduError::from)
    }
}
