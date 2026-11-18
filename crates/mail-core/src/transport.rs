//! Provider-neutral upstream transport capabilities.
//!
//! ADR-0007 requires four distinct capabilities: `MailReader`,
//! `MailSubmitter`, `MailChangeTracker` and `BlobReader`. Every adapter
//! implements them over the same untrusted upstream DTOs, so the identity and
//! disclosure policies applied to a message never depend on which protocol
//! delivered it.
//!
//! Two rules hold across all four:
//!
//! 1. What an adapter returns is **untrusted**. The bytes came from a remote
//!    server that a sender controls in part, so an adapter parses structure
//!    and nothing else. It does not decide that a message is visible, and it
//!    does not record trusted provenance it did not actually receive.
//! 2. What an adapter returns is **bounded**. Sizes and time are limits, not
//!    hints, so a hostile upstream cannot turn a large message into a large
//!    amount of work.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::{Address, AttachmentMeta, MailboxRef, MessageId, NormalizedMessage, Provenance};

/// A message as received from an upstream transport.
///
/// The type is named for what it is: an upstream's account of a message. It
/// becomes a [`NormalizedMessage`] only through
/// [`UntrustedMessage::into_normalized`], and even then it is not disclosed:
/// disclosure is the policy engine's decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UntrustedMessage {
    /// The identifier the transport uses for this message.
    ///
    /// This is the upstream's identifier, not a message-authored `Message-ID`
    /// header, which a sender controls.
    pub id: MessageId,
    /// The mailbox the message was read from.
    pub mailbox: MailboxRef,
    /// Message-authored sender.
    #[serde(default)]
    pub from: Option<Address>,
    /// Message-authored reply-to.
    #[serde(default)]
    pub reply_to: Vec<Address>,
    /// Message-authored recipients.
    #[serde(default)]
    pub to: Vec<Address>,
    /// Message-authored `cc` recipients.
    #[serde(default)]
    pub cc: Vec<Address>,
    /// Message-authored subject.
    #[serde(default)]
    pub subject: Option<String>,
    /// Decoded plain-text body, if the message had one.
    #[serde(default)]
    pub text_body: Option<String>,
    /// HTML body, if the message had one. Untrusted and unsanitized.
    #[serde(default)]
    pub html_body: Option<String>,
    /// Attachment metadata.
    #[serde(default)]
    pub attachments: Vec<AttachmentMeta>,
    /// Message flags such as `seen` or `flagged`.
    #[serde(default)]
    pub flags: Vec<String>,
    /// Internal date of the message.
    #[serde(default)]
    pub date: Option<String>,
    /// Trusted delivery evidence, if the transport could establish any.
    ///
    /// This is empty for transports that cannot distinguish provider-recorded
    /// delivery metadata from message-authored headers. An adapter that
    /// cannot tell the difference must leave this empty rather than guess:
    /// an identity in `verified` isolation mode then fails closed.
    #[serde(default)]
    pub provenance: Provenance,
}

impl UntrustedMessage {
    /// Convert into the normalized model that filters evaluate.
    pub fn into_normalized(self) -> NormalizedMessage {
        NormalizedMessage {
            id: self.id,
            mailbox: self.mailbox,
            from: self.from,
            reply_to: self.reply_to,
            to: self.to,
            cc: self.cc,
            subject: self.subject,
            text_body: self.text_body,
            html_body: self.html_body,
            links: Vec::new(),
            attachments: self.attachments,
            provenance: self.provenance,
            folders: Vec::new(),
            flags: self.flags,
            date: self.date,
        }
    }
}

/// A request for a page of messages.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListQuery {
    /// Maximum number of messages to return.
    pub limit: u32,
    /// An opaque cursor from a previous page.
    pub cursor: Option<String>,
}

/// One page of messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessagePage {
    /// The messages in this page.
    pub messages: Vec<UntrustedMessage>,
    /// The cursor for the next page, if there is one.
    pub next_cursor: Option<String>,
}

/// A message to submit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutgoingMessage {
    /// The envelope sender.
    pub sender: String,
    /// The envelope recipients.
    pub recipients: Vec<String>,
    /// The subject header.
    pub subject: Option<String>,
    /// Additional headers, in order.
    pub headers: Vec<(String, String)>,
    /// The plain-text body.
    pub body: String,
}

/// The result of a submission attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmissionReceipt {
    /// The transport's identifier for the submission.
    pub id: String,
    /// Whether the upstream accepted the message.
    pub accepted: bool,
    /// The upstream's rejection reason, if it rejected the message.
    pub rejection: Option<String>,
}

/// A position in a mailbox's change stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeCursor {
    /// An opaque token produced by the transport.
    pub token: String,
}

/// What happened to a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChangeKind {
    /// The message is new.
    Added,
    /// The message's content or flags changed.
    Modified,
    /// The message is no longer in the mailbox.
    Removed,
}

/// One change in a mailbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    /// The message the change applies to.
    pub id: MessageId,
    /// What happened.
    pub kind: ChangeKind,
}

/// A set of changes and the cursor that follows them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeSet {
    /// The changes, in the order the transport reported them.
    pub changes: Vec<Change>,
    /// The cursor to pass to the next call.
    pub next_cursor: Option<ChangeCursor>,
}

/// A request for one blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobRequest {
    /// The mailbox the blob belongs to.
    pub mailbox: MailboxRef,
    /// The message the blob belongs to.
    pub message_id: MessageId,
    /// The transport's identifier for the blob.
    pub blob_id: String,
}

/// The bytes of one blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobContent {
    /// The bytes.
    pub bytes: Vec<u8>,
    /// The declared content type, which is attacker-controlled metadata.
    pub content_type: Option<String>,
}

/// Why a transport operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// The transport is not reachable.
    Unavailable,
    /// The operation exceeded its time budget.
    Timeout,
    /// The payload exceeded a size limit.
    TooLarge {
        /// The limit that was exceeded.
        limit: u64,
    },
    /// The requested item does not exist.
    NotFound,
    /// The credential was rejected.
    Unauthorized,
    /// The transport refused to proceed because TLS could not be established
    /// or was not trusted.
    TlsRejected(String),
    /// The upstream sent something the adapter could not parse.
    Protocol(String),
    /// The request reached the upstream, but the outcome cannot be
    /// determined.
    ///
    /// A submission that was issued and whose answer was lost is the
    /// important case: retrying it can deliver the message twice, so an
    /// adapter must report it rather than report a failure.
    Ambiguous(String),
    /// The operation is not valid in the transport's current state.
    InvalidState(String),
    /// The upstream rejected the operation.
    Rejected(String),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::Unavailable => f.write_str("transport is unavailable"),
            TransportError::Timeout => f.write_str("transport operation timed out"),
            TransportError::TooLarge { limit } => {
                write!(f, "payload exceeds the limit of {limit} bytes")
            }
            TransportError::NotFound => f.write_str("not found"),
            TransportError::Unauthorized => f.write_str("credential was rejected"),
            TransportError::TlsRejected(reason) => write!(f, "TLS was refused: {reason}"),
            TransportError::Protocol(reason) => write!(f, "protocol error: {reason}"),
            TransportError::Ambiguous(reason) => {
                write!(f, "the outcome of the operation is unknown: {reason}")
            }
            TransportError::InvalidState(reason) => write!(f, "invalid state: {reason}"),
            TransportError::Rejected(reason) => write!(f, "rejected: {reason}"),
        }
    }
}

impl std::error::Error for TransportError {}

/// Bounds applied to every transport operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportLimits {
    /// Maximum size of a single message in bytes.
    pub max_message_bytes: u64,
    /// Maximum size of a single protocol response line in bytes.
    pub max_response_bytes: u64,
    /// Maximum number of messages in one page.
    pub max_page_size: u32,
    /// The time budget for one operation.
    pub io_timeout: Duration,
}

impl Default for TransportLimits {
    fn default() -> Self {
        Self {
            max_message_bytes: 25 * 1024 * 1024,
            max_response_bytes: 64 * 1024,
            max_page_size: 100,
            io_timeout: Duration::from_secs(30),
        }
    }
}

/// A bidirectional byte stream to a transport.
///
/// The adapters are written against this rather than against a socket, so the
/// protocol logic can be exercised against recorded server behaviour, and so
/// the TLS layer stays outside the protocol code.
pub trait ByteStream {
    /// Read one line, without its terminator.
    ///
    /// A line longer than `limit` bytes is an error rather than a truncated
    /// line: a truncated line would be parsed as a different command.
    fn read_line(&mut self, limit: u64) -> Result<String, TransportError>;

    /// Read exactly `length` bytes.
    ///
    /// A short read is an error rather than a partial result, because a
    /// truncated body would parse as a different message.
    fn read_exact(&mut self, length: u64) -> Result<Vec<u8>, TransportError>;

    /// Write bytes to the transport.
    fn write(&mut self, data: &[u8]) -> Result<(), TransportError>;

    /// Close the stream.
    fn close(&mut self) -> Result<(), TransportError>;
}

/// Reads messages from a mailbox.
pub trait MailReader {
    /// List a page of messages in a mailbox.
    fn list(
        &mut self,
        mailbox: &MailboxRef,
        query: &ListQuery,
    ) -> Result<MessagePage, TransportError>;

    /// Read one message.
    fn get(
        &mut self,
        mailbox: &MailboxRef,
        id: &MessageId,
    ) -> Result<UntrustedMessage, TransportError>;
}

/// Submits messages.
pub trait MailSubmitter {
    /// Submit a message.
    fn submit(&mut self, message: &OutgoingMessage) -> Result<SubmissionReceipt, TransportError>;
}

/// Reports changes in a mailbox.
pub trait MailChangeTracker {
    /// Report the changes since a cursor.
    fn changes_since(
        &mut self,
        mailbox: &MailboxRef,
        cursor: Option<&ChangeCursor>,
    ) -> Result<ChangeSet, TransportError>;
}

/// Reads attachment bytes.
pub trait BlobReader {
    /// Read one blob.
    fn read_blob(&mut self, request: &BlobRequest) -> Result<BlobContent, TransportError>;
}

/// How TLS is established with an upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    /// TLS is negotiated before the protocol starts.
    ImplicitTls,
    /// The protocol starts in plaintext and is upgraded with `STARTTLS`.
    StartTls,
}

/// How the upstream's certificate is verified.
///
/// There is deliberately no "do not verify" option. ADR-0006 requires that a
/// self-signed local bridge be trusted by pinning its certificate or by
/// configuring a local CA, and never by disabling verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerVerification {
    /// Trust the platform's certificate store.
    SystemTrust,
    /// Trust a configured local certificate authority.
    TrustedCa(String),
    /// Trust exactly one pinned certificate.
    PinnedCertificate(String),
}

/// The TLS configuration of an upstream endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsConfig {
    /// How TLS is established.
    pub mode: TlsMode,
    /// How the peer's certificate is verified.
    pub peer_verification: PeerVerification,
}

/// How the gateway reaches an upstream IMAP or SMTP service.
///
/// ADR-0006 distinguishes a direct connection from one through a bridge that
/// is already installed. A managed bridge is a later, optional lifecycle and
/// is not representable here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Topology {
    /// The gateway connects to the upstream service itself.
    Direct,
    /// The gateway connects to a bridge that is already running nearby.
    ExistingBridge,
}

/// A validated upstream endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// The host to connect to.
    pub host: String,
    /// The port to connect to.
    pub port: u16,
    /// The TLS configuration.
    pub tls: TlsConfig,
    /// The topology the endpoint belongs to.
    pub topology: Topology,
}

/// Why an endpoint was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointError {
    /// The host was empty.
    EmptyHost,
    /// The port was zero.
    InvalidPort,
    /// A bridge endpoint relied on the platform trust store.
    ///
    /// A bridge commonly presents a certificate no public authority issued, so
    /// it must be trusted explicitly rather than accidentally.
    UntrustedBridgePeer,
}

impl std::fmt::Display for EndpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EndpointError::EmptyHost => f.write_str("endpoint host is empty"),
            EndpointError::InvalidPort => f.write_str("endpoint port is invalid"),
            EndpointError::UntrustedBridgePeer => f.write_str(
                "a bridge endpoint must pin its certificate or use a configured local CA",
            ),
        }
    }
}

impl std::error::Error for EndpointError {}

impl Endpoint {
    /// Check that the endpoint is usable.
    ///
    /// Cleartext is not an option at all: the only TLS modes are implicit
    /// TLS and `STARTTLS`, so a plaintext upstream cannot be configured even
    /// by mistake.
    pub fn validate(&self) -> Result<(), EndpointError> {
        if self.host.trim().is_empty() {
            return Err(EndpointError::EmptyHost);
        }
        if self.port == 0 {
            return Err(EndpointError::InvalidPort);
        }
        if self.topology == Topology::ExistingBridge
            && self.tls.peer_verification == PeerVerification::SystemTrust
        {
            return Err(EndpointError::UntrustedBridgePeer);
        }
        Ok(())
    }
}
