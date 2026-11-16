//! The normalized message representation that filters operate on.
//!
//! ADR-0003 section 1 requires that filters evaluate against a normalized
//! model rather than raw header text. The split between [`Provenance`] and
//! the message-authored fields is the point of this module: a rule must not
//! be able to reach trusted delivery evidence through an untrusted header.

use serde::{Deserialize, Serialize};

/// Stable identifier of a message within a mailbox.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MessageId(String);

impl MessageId {
    /// Create a message id.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Borrow the identifier as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for MessageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Identifier of a physical upstream mailbox.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MailboxRef(String);

impl MailboxRef {
    /// Create a mailbox reference.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Borrow the reference as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for MailboxRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A mail address with an optional display name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Address {
    /// The addr-spec, for example `user@example.com`.
    pub address: String,
    /// Optional human-readable name.
    #[serde(default)]
    pub display_name: Option<String>,
}

impl Address {
    /// Create a bare address.
    pub fn new(address: impl Into<String>) -> Self {
        Self {
            address: address.into(),
            display_name: None,
        }
    }
}

/// A link extracted from message content, with its resolved destination.
///
/// The destination matters as much as the visible text: a login link carries
/// its token in the URL, not in the anchor text (ADR-0003 section 5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Link {
    /// Visible anchor text.
    #[serde(default)]
    pub text: Option<String>,
    /// The resolved destination, if it was extractable.
    #[serde(default)]
    pub href: Option<String>,
}

/// Attachment metadata.
///
/// The declared MIME type is attacker-controlled, so it is carried as
/// metadata only and never treated as evidence of content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentMeta {
    /// Attachment identifier, stable within the message.
    pub id: String,
    /// Declared filename, if any.
    #[serde(default)]
    pub filename: Option<String>,
    /// Declared content type, if any.
    #[serde(default)]
    pub content_type: Option<String>,
    /// Size in bytes of the encoded part.
    pub size: u64,
    /// Whether the attachment is inline rather than a separate part.
    #[serde(default)]
    pub inline: bool,
}

/// Trusted delivery metadata recorded by the upstream provider.
///
/// This is the only evidence that can justify `verified` identity isolation.
/// A `To` or `Delivered-To` header is authored by the sender or by an
/// intermediate, and is deliberately not represented here.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// The original envelope recipient, when the provider preserves it.
    #[serde(default)]
    pub original_recipient: Option<TrustedRecipient>,
    /// The route the message took through the provider's infrastructure.
    #[serde(default)]
    pub delivery_route: Option<String>,
}

/// An envelope recipient recorded by the upstream provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedRecipient {
    /// The address as the provider recorded it.
    pub address: String,
    /// How the provider obtained this value.
    pub source: String,
}

/// A message normalized from an upstream transport.
///
/// Constructing one of these is an adapter's job; the fields are then the
/// only thing a filter can read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedMessage {
    /// Identifier within the mailbox.
    pub id: MessageId,
    /// The mailbox the message lives in.
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
    /// Sanitized HTML body, if the message had one.
    #[serde(default)]
    pub html_body: Option<String>,
    /// Links found in the body.
    #[serde(default)]
    pub links: Vec<Link>,
    /// Attachment metadata.
    #[serde(default)]
    pub attachments: Vec<AttachmentMeta>,
    /// Trusted delivery metadata.
    #[serde(default)]
    pub provenance: Provenance,
    /// Folders the message appears in.
    #[serde(default)]
    pub folders: Vec<String>,
    /// Message flags such as `seen` or `flagged`.
    #[serde(default)]
    pub flags: Vec<String>,
    /// Internal date of the message.
    #[serde(default)]
    pub date: Option<String>,
}

impl NormalizedMessage {
    /// Whether the message carries a flag.
    pub fn has_flag(&self, flag: &str) -> bool {
        self.flags.iter().any(|f| f.eq_ignore_ascii_case(flag))
    }

    /// The trusted envelope recipient, if the provider recorded one.
    pub fn trusted_recipient(&self) -> Option<&TrustedRecipient> {
        self.provenance.original_recipient.as_ref()
    }

    /// Every address visible in the message, whatever its trustworthiness.
    ///
    /// Used for display and for non-security matching only.
    pub fn visible_addresses(&self) -> impl Iterator<Item = &Address> {
        self.from
            .iter()
            .chain(self.reply_to.iter())
            .chain(self.to.iter())
            .chain(self.cc.iter())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message() -> NormalizedMessage {
        NormalizedMessage {
            id: MessageId::new("m1"),
            mailbox: MailboxRef::new("personal"),
            from: Some(Address::new("sender@example.com")),
            reply_to: Vec::new(),
            to: vec![Address::new("me@example.com")],
            cc: Vec::new(),
            subject: Some("hello".to_owned()),
            text_body: Some("body".to_owned()),
            html_body: None,
            links: Vec::new(),
            attachments: Vec::new(),
            provenance: Provenance::default(),
            folders: vec!["INBOX".to_owned()],
            flags: vec!["seen".to_owned()],
            date: None,
        }
    }

    #[test]
    fn flags_are_matched_case_insensitively() {
        assert!(message().has_flag("SEEN"));
        assert!(!message().has_flag("answered"));
    }

    #[test]
    fn provenance_is_absent_by_default() {
        assert!(message().trusted_recipient().is_none());
    }

    #[test]
    fn visible_addresses_include_from_and_to() {
        let message = message();
        let addresses: Vec<_> = message
            .visible_addresses()
            .map(|a| a.address.as_str())
            .collect();
        assert_eq!(addresses, vec!["sender@example.com", "me@example.com"]);
    }
}
