//! The wire types the REST and MCP adapters serialize.
//!
//! The shapes here mirror `api/openapi.yaml` and `api/mcp-tools.json`. Field
//! names are camelCase on the wire because both contracts say so, while the
//! Rust fields keep snake_case.

use serde::{Deserialize, Serialize};

/// The response of `listIdentities` and of the `corvi:///context/identities`
/// MCP resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentitiesResponse {
    /// The identities the caller may act on.
    pub items: Vec<IdentityView>,
}

/// One authorized identity and the actions the caller may perform on it.
///
/// The permissions are the effective actions of **this** identity only. They
/// are never unioned with another identity's permissions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityView {
    /// The opaque identity identifier.
    pub id: String,
    /// The address the identity sends from.
    pub address: String,
    /// The human-readable name, when the configuration declares one.
    #[serde(rename = "displayName", skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// The actions granted for this identity.
    pub permissions: Vec<String>,
}

/// A mail address with an optional display name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailAddress {
    /// The addr-spec.
    pub email: String,
    /// The optional human-readable name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// A message in a page of results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageSummary {
    /// The message identifier.
    pub id: String,
    /// The identity the message was disclosed under.
    #[serde(rename = "identityId")]
    pub identity_id: String,
    /// When the message was received.
    #[serde(rename = "receivedAt")]
    pub received_at: String,
    /// The conversation the message belongs to, when the upstream reports one.
    #[serde(
        rename = "conversationId",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub conversation_id: Option<String>,
    /// The subject, after redaction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// The sender, after redaction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<MailAddress>,
    /// A short excerpt of the **projected** body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
    /// Whether the message carries the `seen` flag.
    #[serde(rename = "isRead", default, skip_serializing_if = "Option::is_none")]
    pub is_read: Option<bool>,
}

/// A disclosed message projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailMessage {
    /// The message identifier.
    pub id: String,
    /// The identity the message was disclosed under.
    #[serde(rename = "identityId")]
    pub identity_id: String,
    /// When the message was received.
    #[serde(rename = "receivedAt")]
    pub received_at: String,
    /// The conversation the message belongs to, when the upstream reports one.
    #[serde(
        rename = "conversationId",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub conversation_id: Option<String>,
    /// The subject, after redaction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// The sender, after redaction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<MailAddress>,
    /// The primary recipients.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<Vec<MailAddress>>,
    /// The carbon-copy recipients.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cc: Option<Vec<MailAddress>>,
    /// The reply-to addresses.
    #[serde(rename = "replyTo", default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<Vec<MailAddress>>,
    /// The plain-text body, after redaction.
    #[serde(rename = "textBody", default, skip_serializing_if = "Option::is_none")]
    pub text_body: Option<String>,
    /// The sanitized HTML body, when the policy permits HTML at all.
    #[serde(rename = "htmlBody", default, skip_serializing_if = "Option::is_none")]
    pub html_body: Option<String>,
    /// Whether the message carries the `seen` flag.
    #[serde(rename = "isRead", default, skip_serializing_if = "Option::is_none")]
    pub is_read: Option<bool>,
    /// The attachments the policy permits to be listed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attachments: Option<Vec<AttachmentDescriptor>>,
}

/// One attachment the caller may see the metadata of.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentDescriptor {
    /// The opaque attachment identifier.
    pub id: String,
    /// The declared filename.
    #[serde(rename = "fileName")]
    pub file_name: String,
    /// The declared content type.
    #[serde(rename = "contentType")]
    pub content_type: String,
    /// The size of the encoded part in bytes.
    #[serde(rename = "sizeBytes")]
    pub size_bytes: u64,
}

/// One page of messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessagePage {
    /// The messages in this page.
    pub items: Vec<MessageSummary>,
    /// The cursor for the next page.
    #[serde(
        rename = "nextCursor",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub next_cursor: Option<String>,
}

/// The status of one outgoing submission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SubmissionStatus {
    /// Accepted for processing but not yet handed to the upstream.
    Queued,
    /// The upstream accepted the message.
    ///
    /// This says the upstream took the message, not that a recipient read it.
    Submitted,
    /// The submission failed before the upstream accepted it.
    Failed,
    /// The outcome is ambiguous and must not be retried blindly.
    Unknown,
}

/// The state of one outgoing submission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Submission {
    /// The opaque submission identifier.
    pub id: String,
    /// The identity the message was sent from.
    #[serde(rename = "identityId")]
    pub identity_id: String,
    /// The submission status.
    pub status: SubmissionStatus,
    /// When the submission was created.
    #[serde(rename = "createdAt")]
    pub created_at: String,
    /// When the submission last changed.
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
    /// Whether replay suppression survives a process restart.
    #[serde(rename = "idempotencyDurable")]
    pub idempotency_durable: bool,
    /// A stable failure code, when the submission did not succeed.
    #[serde(
        rename = "failureCode",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub failure_code: Option<String>,
}

/// The body of `POST /v1/messages/search`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchRequest {
    /// The identity to search under.
    #[serde(rename = "identityId")]
    pub identity_id: String,
    /// The literal, case-insensitive query.
    pub query: String,
    /// The maximum number of results.
    #[serde(default)]
    pub limit: Option<u32>,
    /// The cursor of a previous page.
    #[serde(default)]
    pub cursor: Option<String>,
}

/// The body of `POST /v1/messages/send`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendRequest {
    /// The identity to send from.
    #[serde(rename = "identityId")]
    pub identity_id: String,
    /// The primary recipients.
    pub to: Vec<MailAddress>,
    /// The carbon-copy recipients.
    #[serde(default)]
    pub cc: Vec<MailAddress>,
    /// The blind carbon-copy recipients.
    #[serde(default)]
    pub bcc: Vec<MailAddress>,
    /// The subject.
    pub subject: String,
    /// The plain-text body.
    #[serde(rename = "textBody")]
    pub text_body: String,
}
