//! Why a queue operation failed.
//!
//! The variants are few on purpose. A caller of the queue needs to know
//! three things: whether the optional feature it asked for is switched on at
//! all, whether its write was refused because its fence is stale, and
//! whether the failure is a refusal by the authority behind the item rather
//! than a technical error.
//!
//! Nothing here carries a subject, a body, an address or a credential. A
//! queue error is a diagnostic, and diagnostics are read by people who do
//! not necessarily have the right to read the mail.

use std::fmt;

use mail_storage::StorageError;

use crate::config::Feature;

/// The result of a queue operation.
pub type QueueResult<T> = Result<T, QueueError>;

/// Why a queue operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueueError {
    /// The optional feature is not enabled in this deployment.
    ///
    /// The queue is off by default, so this is the answer a caller usually
    /// gets. It is an explicit refusal, never a silent no-op: the caller is
    /// told that the feature is unavailable instead of believing that work
    /// was scheduled.
    FeatureDisabled(Feature),
    /// The worker's fence token is stale, so its write was refused.
    ///
    /// The work was taken over by another worker, and the store refused the
    /// write. The worker must not repeat the work under the old fence.
    StaleFence(String),
    /// The authority behind the item refused it.
    ///
    /// The grant was revoked or narrowed after the item was queued, so the
    /// item is not executed under stale authority.
    Refused(String),
    /// The upstream transport failed.
    Upstream(String),
    /// The request is not valid.
    Invalid(String),
    /// The payload is larger than the queue accepts.
    PayloadTooLarge {
        /// The limit that was exceeded, in bytes.
        limit: u64,
    },
    /// The storage layer failed.
    Storage(StorageError),
}

impl fmt::Display for QueueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QueueError::FeatureDisabled(feature) => {
                write!(f, "the {} feature is not enabled", feature.as_str())
            }
            QueueError::StaleFence(what) => {
                write!(f, "the fence is stale, so the write was refused: {what}")
            }
            QueueError::Refused(reason) => write!(f, "the item was refused: {reason}"),
            QueueError::Upstream(reason) => write!(f, "the upstream failed: {reason}"),
            QueueError::Invalid(reason) => write!(f, "the request is not valid: {reason}"),
            QueueError::PayloadTooLarge { limit } => {
                write!(f, "the payload exceeds the limit of {limit} bytes")
            }
            QueueError::Storage(error) => write!(f, "the storage layer failed: {error}"),
        }
    }
}

impl std::error::Error for QueueError {}

impl From<StorageError> for QueueError {
    fn from(error: StorageError) -> Self {
        QueueError::Storage(error)
    }
}
