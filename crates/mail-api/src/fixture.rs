//! An offline upstream backed by a fixture file.
//!
//! The standalone gateway must be runnable with a local configuration and no
//! external service, and the tests must exercise the pipeline without a
//! provider. This module is that backend: a JSON document of messages that
//! the gateway reads exactly as it would read an upstream.
//!
//! It is a development and test backend. It is not a mail store, it never
//! talks to a network, and a deployment that points a gateway at it serves
//! fixture mail only.

use std::sync::Mutex;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;

use mail_core::{
    Address, AttachmentMeta, BlobContent, BlobRequest, MailIdentity, MessageId, MessagePage,
    OutgoingMessage, SubmissionReceipt, UntrustedMessage,
};

use crate::upstream::{Upstream, UpstreamError};

/// A fixture document.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureFile {
    /// The messages the fixture holds.
    #[serde(default)]
    pub messages: Vec<FixtureMessage>,
}

/// One message in a fixture.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureMessage {
    /// The identifier the upstream uses.
    pub id: String,
    /// The mailbox the message lives in.
    #[serde(default = "default_mailbox")]
    pub mailbox: String,
    /// The sender.
    #[serde(default)]
    pub from: Option<FixtureAddress>,
    /// The primary recipients.
    #[serde(default)]
    pub to: Vec<FixtureAddress>,
    /// The carbon-copy recipients.
    #[serde(default)]
    pub cc: Vec<FixtureAddress>,
    /// The reply-to addresses.
    #[serde(default)]
    pub reply_to: Vec<FixtureAddress>,
    /// The subject.
    #[serde(default)]
    pub subject: Option<String>,
    /// The plain-text body.
    #[serde(default, rename = "textBody")]
    pub text_body: Option<String>,
    /// The HTML body.
    #[serde(default, rename = "htmlBody")]
    pub html_body: Option<String>,
    /// The internal date.
    #[serde(default)]
    pub date: Option<String>,
    /// The message flags.
    #[serde(default)]
    pub flags: Vec<String>,
    /// The attachments.
    #[serde(default)]
    pub attachments: Vec<FixtureAttachment>,
    /// The provider-recorded envelope recipient.
    ///
    /// A fixture that names it can exercise `verified` isolation; a fixture
    /// that omits it fails closed, exactly as an adapter that cannot record
    /// the evidence must.
    #[serde(default, rename = "trustedRecipient")]
    pub trusted_recipient: Option<String>,
}

fn default_mailbox() -> String {
    "INBOX".to_owned()
}

/// One address in a fixture.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureAddress {
    /// The addr-spec.
    pub address: String,
    /// The optional display name.
    #[serde(default, rename = "displayName")]
    pub display_name: Option<String>,
}

/// One attachment in a fixture.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureAttachment {
    /// The attachment identifier.
    pub id: String,
    /// The declared filename.
    #[serde(default)]
    pub filename: Option<String>,
    /// The declared content type.
    #[serde(default, rename = "contentType")]
    pub content_type: Option<String>,
    /// The base64 content.
    #[serde(default)]
    pub base64: String,
}

/// How the fixture answers a submission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SubmissionBehavior {
    /// The upstream accepts the message.
    #[default]
    Accept,
    /// The upstream rejects the message.
    Reject,
    /// The upstream accepts the message but cannot say what happened.
    Ambiguous,
}

/// An upstream that serves fixture mail.
#[derive(Debug)]
pub struct FixtureUpstream {
    messages: Vec<FixtureMessage>,
    behavior: Mutex<SubmissionBehavior>,
    submissions: Mutex<Vec<OutgoingMessage>>,
}

impl FixtureUpstream {
    /// Build an upstream from a parsed fixture.
    pub fn new(fixture: FixtureFile) -> Self {
        Self {
            messages: fixture.messages,
            behavior: Mutex::new(SubmissionBehavior::Accept),
            submissions: Mutex::new(Vec::new()),
        }
    }

    /// Build an upstream from a JSON document.
    pub fn from_json(document: &str) -> Result<Self, serde_json::Error> {
        Ok(Self::new(serde_json::from_str(document)?))
    }

    /// Set how the fixture answers submissions.
    pub fn with_behavior(mut self, behavior: SubmissionBehavior) -> Self {
        self.behavior = Mutex::new(behavior);
        self
    }

    /// Change how the fixture answers submissions.
    pub fn set_behavior(&self, behavior: SubmissionBehavior) {
        if let Ok(mut current) = self.behavior.lock() {
            *current = behavior;
        }
    }

    /// How the fixture answers submissions.
    pub fn behavior(&self) -> SubmissionBehavior {
        self.behavior
            .lock()
            .map(|behavior| *behavior)
            .unwrap_or(SubmissionBehavior::Accept)
    }

    /// The messages submitted so far.
    pub fn submissions(&self) -> Vec<OutgoingMessage> {
        self.submissions
            .lock()
            .map(|items| items.clone())
            .unwrap_or_default()
    }

    /// The messages of a mailbox, newest first.
    fn mailbox(&self, identity: &MailIdentity) -> Vec<&FixtureMessage> {
        let mut messages: Vec<&FixtureMessage> = self
            .messages
            .iter()
            .filter(|message| message.mailbox == identity.mailbox.as_str())
            .collect();
        messages.sort_by(|left, right| {
            right
                .date
                .as_deref()
                .unwrap_or_default()
                .cmp(left.date.as_deref().unwrap_or_default())
                .then_with(|| right.id.cmp(&left.id))
        });
        messages
    }
}

impl Upstream for FixtureUpstream {
    fn list(
        &self,
        identity: &MailIdentity,
        query: &mail_core::ListQuery,
    ) -> Result<MessagePage, UpstreamError> {
        let messages = self.mailbox(identity);
        let start = match query.cursor.as_deref() {
            Some(cursor) => messages
                .iter()
                .position(|message| message.id == cursor)
                .map(|position| position + 1)
                .unwrap_or(messages.len()),
            None => 0,
        };
        let limit = query.limit.max(1) as usize;
        let page: Vec<&FixtureMessage> = messages.iter().copied().skip(start).take(limit).collect();
        let consumed = start + page.len();
        let next_cursor = if consumed < messages.len() {
            page.last().map(|message| message.id.clone())
        } else {
            None
        };
        Ok(MessagePage {
            messages: page.into_iter().map(to_untrusted).collect(),
            next_cursor,
        })
    }

    fn get(
        &self,
        identity: &MailIdentity,
        message_id: &MessageId,
    ) -> Result<Option<UntrustedMessage>, UpstreamError> {
        Ok(self
            .mailbox(identity)
            .into_iter()
            .find(|message| message.id == message_id.as_str())
            .map(to_untrusted))
    }

    fn read_blob(
        &self,
        identity: &MailIdentity,
        request: &BlobRequest,
    ) -> Result<BlobContent, UpstreamError> {
        let message = self
            .mailbox(identity)
            .into_iter()
            .find(|message| message.id == request.message_id.as_str())
            .ok_or(UpstreamError::NotFound)?;
        let attachment = message
            .attachments
            .iter()
            .find(|attachment| attachment.id == request.blob_id)
            .ok_or(UpstreamError::NotFound)?;
        let bytes = STANDARD.decode(attachment.base64.as_bytes()).map_err(|_| {
            UpstreamError::Protocol("the fixture attachment is not base64".to_owned())
        })?;
        Ok(BlobContent {
            bytes,
            content_type: attachment.content_type.clone(),
        })
    }

    fn submit(
        &self,
        identity: &MailIdentity,
        message: &OutgoingMessage,
    ) -> Result<SubmissionReceipt, UpstreamError> {
        if message.sender != identity.address {
            return Err(UpstreamError::Rejected(
                "the envelope sender does not match the identity".to_owned(),
            ));
        }
        if let Ok(mut submissions) = self.submissions.lock() {
            submissions.push(message.clone());
        }
        match self.behavior() {
            SubmissionBehavior::Accept => Ok(SubmissionReceipt {
                id: crate::time::random_id(),
                accepted: true,
                rejection: None,
            }),
            SubmissionBehavior::Reject => Ok(SubmissionReceipt {
                id: crate::time::random_id(),
                accepted: false,
                rejection: Some("fixture refused the message".to_owned()),
            }),
            SubmissionBehavior::Ambiguous => Err(UpstreamError::Ambiguous(
                "the fixture lost the connection after the message was written".to_owned(),
            )),
        }
    }
}

/// Convert a fixture message into the untrusted upstream model.
fn to_untrusted(message: &FixtureMessage) -> UntrustedMessage {
    UntrustedMessage {
        id: MessageId::new(message.id.clone()),
        mailbox: mail_core::MailboxRef::new(message.mailbox.clone()),
        from: message.from.as_ref().map(address),
        reply_to: message.reply_to.iter().map(address).collect(),
        to: message.to.iter().map(address).collect(),
        cc: message.cc.iter().map(address).collect(),
        subject: message.subject.clone(),
        text_body: message.text_body.clone(),
        html_body: message.html_body.clone(),
        attachments: message
            .attachments
            .iter()
            .map(|attachment| AttachmentMeta {
                id: attachment.id.clone(),
                filename: attachment.filename.clone(),
                content_type: attachment.content_type.clone(),
                size: STANDARD
                    .decode(attachment.base64.as_bytes())
                    .map(|bytes| bytes.len() as u64)
                    .unwrap_or(0),
                inline: false,
            })
            .collect(),
        flags: message.flags.clone(),
        date: message.date.clone(),
        provenance: mail_core::Provenance {
            original_recipient: message.trusted_recipient.as_ref().map(|address| {
                mail_core::TrustedRecipient {
                    address: address.clone(),
                    source: "fixture".to_owned(),
                }
            }),
            delivery_route: None,
        },
    }
}

/// Convert a fixture address into the upstream model.
fn address(value: &FixtureAddress) -> Address {
    Address {
        address: value.address.clone(),
        display_name: value.display_name.clone(),
    }
}
