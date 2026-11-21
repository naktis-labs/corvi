//! Why a JMAP operation failed.
//!
//! ADR-0007 section 7 names the capability statuses a transport must be able
//! to report, so a broken mailbox blocks only the operation it affects
//! instead of the whole gateway. Every variant here maps onto one of those
//! statuses, and none of them carries a backend secret: the reason a
//! credential was rejected is not the same as the credential.

use std::fmt;

use crate::trust::TrustError;

/// Why a JMAP operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JmapError {
    /// The transport cannot speak JMAP at all.
    UnsupportedTransport(String),
    /// The upstream does not offer a capability the operation needs.
    CapabilityMissing(String),
    /// The credential must be reauthorized before the operation can proceed.
    NeedsAuthorization(String),
    /// The configured account selector does not name a usable account.
    AccountSelectionInvalid(String),
    /// The account cannot submit mail.
    SubmissionUnavailable(String),
    /// The synchronization state token is no longer valid.
    SyncStateInvalid(String),
    /// The upstream could not be reached.
    UpstreamUnavailable(String),
    /// The upstream answered something the client could not parse.
    Protocol(String),
    /// The upstream rejected the credential.
    Unauthorized,
    /// The requested object does not exist.
    NotFound,
    /// The upstream refused the operation.
    Rejected(String),
    /// The payload exceeded a size limit.
    TooLarge {
        /// The limit that was exceeded.
        limit: u64,
    },
    /// A URL the client was about to use failed the trust checks.
    Trust(TrustError),
    /// The outcome of the operation cannot be determined.
    ///
    /// A submission that was issued but whose result was lost is the
    /// important case: retrying it can deliver the message twice.
    Ambiguous(String),
}

impl fmt::Display for JmapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JmapError::UnsupportedTransport(reason) => {
                write!(f, "the transport cannot speak JMAP: {reason}")
            }
            JmapError::CapabilityMissing(capability) => {
                write!(f, "the upstream does not offer {capability}")
            }
            JmapError::NeedsAuthorization(reason) => {
                write!(f, "the upstream credential must be reauthorized: {reason}")
            }
            JmapError::AccountSelectionInvalid(reason) => {
                write!(f, "the account selection is not usable: {reason}")
            }
            JmapError::SubmissionUnavailable(reason) => {
                write!(f, "the account cannot submit mail: {reason}")
            }
            JmapError::SyncStateInvalid(reason) => {
                write!(f, "the synchronization state is no longer valid: {reason}")
            }
            JmapError::UpstreamUnavailable(reason) => {
                write!(f, "the upstream is unavailable: {reason}")
            }
            JmapError::Protocol(reason) => write!(f, "protocol error: {reason}"),
            JmapError::Unauthorized => write!(f, "the upstream rejected the credential"),
            JmapError::NotFound => write!(f, "not found"),
            JmapError::Rejected(reason) => {
                write!(f, "the upstream refused the operation: {reason}")
            }
            JmapError::TooLarge { limit } => {
                write!(f, "the payload exceeds the limit of {limit} bytes")
            }
            JmapError::Trust(error) => write!(f, "the endpoint is not trusted: {error}"),
            JmapError::Ambiguous(reason) => {
                write!(f, "the outcome of the operation is unknown: {reason}")
            }
        }
    }
}

impl std::error::Error for JmapError {}

impl From<mail_core::TransportError> for JmapError {
    fn from(error: mail_core::TransportError) -> Self {
        match error {
            mail_core::TransportError::Unavailable => {
                JmapError::UpstreamUnavailable("the upstream is unavailable".to_owned())
            }
            mail_core::TransportError::Timeout => {
                JmapError::UpstreamUnavailable("the upstream did not answer in time".to_owned())
            }
            mail_core::TransportError::TooLarge { limit } => JmapError::TooLarge { limit },
            mail_core::TransportError::NotFound => JmapError::NotFound,
            mail_core::TransportError::Unauthorized => JmapError::Unauthorized,
            mail_core::TransportError::TlsRejected(reason) => JmapError::NeedsAuthorization(reason),
            mail_core::TransportError::Protocol(reason) => JmapError::Protocol(reason),
            mail_core::TransportError::InvalidState(reason) => JmapError::SyncStateInvalid(reason),
            mail_core::TransportError::Rejected(reason) => JmapError::Rejected(reason),
            mail_core::TransportError::Ambiguous(reason) => JmapError::Ambiguous(reason),
        }
    }
}

impl From<TrustError> for JmapError {
    fn from(error: TrustError) -> Self {
        JmapError::Trust(error)
    }
}

impl From<JmapError> for mail_core::TransportError {
    fn from(error: JmapError) -> Self {
        match error {
            JmapError::UpstreamUnavailable(_) => mail_core::TransportError::Unavailable,
            JmapError::Unauthorized => mail_core::TransportError::Unauthorized,
            JmapError::NotFound => mail_core::TransportError::NotFound,
            JmapError::Protocol(reason) => mail_core::TransportError::Protocol(reason),
            JmapError::Rejected(reason) => mail_core::TransportError::Rejected(reason),
            JmapError::TooLarge { limit } => mail_core::TransportError::TooLarge { limit },
            JmapError::Ambiguous(reason) => mail_core::TransportError::Ambiguous(reason),
            other => mail_core::TransportError::InvalidState(other.to_string()),
        }
    }
}
