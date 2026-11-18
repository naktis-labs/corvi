//! The seam between the gateway and whatever holds the mail.
//!
//! The gateway never speaks IMAP, SMTP or JMAP itself: it asks an
//! [`Upstream`] for messages and for submission, and everything it receives
//! is treated as untrusted until the policy engine has seen it. Keeping the
//! seam narrow is what lets the REST and MCP adapters share one pipeline and
//! lets the same pipeline be exercised without a provider.
//!
//! An adapter reports [`UpstreamError::Ambiguous`] whenever it cannot tell
//! whether a submission reached the upstream. The gateway turns that into a
//! submission with status `unknown`, because a blind retry of an ambiguous
//! send can deliver a message twice.

use std::fmt;

use mail_core::{
    BlobContent, BlobRequest, MailIdentity, MessageId, MessagePage, OutgoingMessage,
    SubmissionReceipt,
};

/// Why an upstream operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamError {
    /// The upstream could not be reached, and nothing was sent.
    Unavailable,
    /// The upstream was reached but the outcome cannot be determined.
    Ambiguous(String),
    /// The requested item does not exist.
    NotFound,
    /// The upstream refused the operation.
    Rejected(String),
    /// The upstream rejected the credential.
    Unauthorized,
    /// The payload exceeded a size limit.
    TooLarge {
        /// The limit that was exceeded.
        limit: u64,
    },
    /// The upstream sent something the adapter could not parse.
    Protocol(String),
}

impl fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UpstreamError::Unavailable => write!(f, "upstream unavailable"),
            UpstreamError::Ambiguous(reason) => write!(f, "ambiguous upstream outcome: {reason}"),
            UpstreamError::NotFound => write!(f, "not found"),
            UpstreamError::Rejected(reason) => write!(f, "rejected: {reason}"),
            UpstreamError::Unauthorized => write!(f, "credential rejected"),
            UpstreamError::TooLarge { limit } => write!(f, "payload exceeds {limit} bytes"),
            UpstreamError::Protocol(reason) => write!(f, "protocol error: {reason}"),
        }
    }
}

impl std::error::Error for UpstreamError {}

/// The mail the gateway serves.
pub trait Upstream: Send + Sync + fmt::Debug {
    /// List one page of messages for an identity.
    fn list(
        &self,
        identity: &MailIdentity,
        query: &mail_core::ListQuery,
    ) -> Result<MessagePage, UpstreamError>;

    /// Read one message, or `None` when the upstream does not have it.
    fn get(
        &self,
        identity: &MailIdentity,
        message_id: &MessageId,
    ) -> Result<Option<mail_core::UntrustedMessage>, UpstreamError>;

    /// Read the bytes of one attachment.
    fn read_blob(
        &self,
        identity: &MailIdentity,
        request: &BlobRequest,
    ) -> Result<BlobContent, UpstreamError>;

    /// Submit one message.
    fn submit(
        &self,
        identity: &MailIdentity,
        message: &OutgoingMessage,
    ) -> Result<SubmissionReceipt, UpstreamError>;
}
