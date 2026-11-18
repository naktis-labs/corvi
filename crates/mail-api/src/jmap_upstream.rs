//! The JMAP-backed upstream of the gateway.
//!
//! ADR-0007 makes JMAP an alternative upstream protocol, not a second
//! source of truth: the gateway asks its [`Upstream`] for mail, and this
//! adapter answers over JMAP. Everything the gateway already guarantees
//! therefore holds for a JMAP deployment as well — the identity is selected
//! first, the action is authorized, and the disclosure policy runs before a
//! byte reaches a caller.
//!
//! Two things happen here that the protocol itself does not do:
//!
//! 1. **Upstream identifiers become opaque.** A JMAP `Email.id`, blob id
//!    and submission id are the upstream's identifiers, and ADR-0007 forbids
//!    them from becoming public identifiers. This adapter maps each one to
//!    an opaque Corvi identifier and keeps the mapping, so the gateway, the
//!    REST API and the MCP tools only ever see the opaque form.
//! 2. **Identities are routed to accounts.** A deployment may serve
//!    identities from several upstream accounts, and may serve some of them
//!    over a different transport entirely. An identity this adapter does not
//!    serve is passed to the remaining upstream, so one gateway can serve a
//!    mixed deployment.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use mail_core::{
    BlobContent, BlobRequest, MailIdentity, MessageId, MessagePage, OutgoingMessage,
    SubmissionReceipt,
};
use mail_jmap::{
    client::JmapClient, error::JmapError, reader, submission, transport::TransportLimits,
};
use sha2::{Digest, Sha256};

use crate::upstream::{Upstream, UpstreamError};

/// The upstream that serves the identities this adapter does not.
type Remaining = Arc<dyn Upstream>;

/// An upstream that reads and writes through JMAP.
#[derive(Debug)]
pub struct JmapUpstream {
    client: Mutex<JmapClient>,
    accounts: HashMap<String, String>,
    identifiers: Mutex<Identifiers>,
    remaining: Option<Remaining>,
    limits: TransportLimits,
}

impl JmapUpstream {
    /// An upstream that serves the given identities over JMAP.
    ///
    /// The map names the JMAP account each identity reads from. An identity
    /// that is not in the map is not served here.
    pub fn new(client: JmapClient, accounts: HashMap<String, String>) -> Self {
        Self {
            client: Mutex::new(client),
            accounts,
            identifiers: Mutex::new(Identifiers::default()),
            remaining: None,
            limits: TransportLimits::default(),
        }
    }

    /// Serve the identities this adapter does not serve with another
    /// upstream.
    pub fn with_remaining(mut self, remaining: Remaining) -> Self {
        self.remaining = Some(remaining);
        self
    }

    /// Apply transport limits.
    pub fn with_limits(mut self, limits: TransportLimits) -> Self {
        self.limits = limits;
        self
    }

    /// The JMAP account an identity reads from.
    fn account(&self, identity: &MailIdentity) -> Option<&str> {
        self.accounts.get(identity.id.as_str()).map(String::as_str)
    }

    /// The upstream that serves an identity this adapter does not.
    fn remaining(&self, identity: &MailIdentity) -> Option<&Remaining> {
        if self.account(identity).is_some() {
            return None;
        }
        self.remaining.as_ref()
    }
}

impl Upstream for JmapUpstream {
    fn list(
        &self,
        identity: &MailIdentity,
        query: &mail_core::ListQuery,
    ) -> Result<MessagePage, UpstreamError> {
        let Some(account) = self.account(identity) else {
            return match self.remaining(identity) {
                Some(remaining) => remaining.list(identity, query),
                None => Err(UpstreamError::NotFound),
            };
        };
        let mut client = self.client.lock().map_err(|_| UpstreamError::Unavailable)?;
        let page =
            reader::list_messages(&mut client, account, &identity.mailbox, query, &self.limits)
                .map_err(map_error)?;
        let mut identifiers = self
            .identifiers
            .lock()
            .map_err(|_| UpstreamError::Unavailable)?;
        let mut messages = page.messages;
        for message in &mut messages {
            message.id = identifiers.public_message(message.id.as_str());
            for attachment in &mut message.attachments {
                attachment.id = identifiers.public_attachment(&attachment.id);
            }
        }
        Ok(MessagePage {
            messages,
            next_cursor: page.next_cursor,
        })
    }

    fn get(
        &self,
        identity: &MailIdentity,
        message_id: &MessageId,
    ) -> Result<Option<mail_core::UntrustedMessage>, UpstreamError> {
        let Some(account) = self.account(identity) else {
            return match self.remaining(identity) {
                Some(remaining) => remaining.get(identity, message_id),
                None => Err(UpstreamError::NotFound),
            };
        };
        let upstream_id = self
            .identifiers
            .lock()
            .map_err(|_| UpstreamError::Unavailable)?
            .upstream_message(message_id);
        let Some(upstream_id) = upstream_id else {
            return Ok(None);
        };
        let mut client = self.client.lock().map_err(|_| UpstreamError::Unavailable)?;
        let message = match reader::get_message(
            &mut client,
            account,
            &identity.mailbox,
            &MessageId::new(upstream_id),
        ) {
            Ok(message) => message,
            Err(JmapError::NotFound) => return Ok(None),
            Err(error) => return Err(map_error(error)),
        };
        let mut identifiers = self
            .identifiers
            .lock()
            .map_err(|_| UpstreamError::Unavailable)?;
        let mut message = message;
        message.id = identifiers.public_message(message.id.as_str());
        for attachment in &mut message.attachments {
            attachment.id = identifiers.public_attachment(&attachment.id);
        }
        Ok(Some(message))
    }

    fn read_blob(
        &self,
        identity: &MailIdentity,
        request: &BlobRequest,
    ) -> Result<BlobContent, UpstreamError> {
        let Some(account) = self.account(identity) else {
            return match self.remaining(identity) {
                Some(remaining) => remaining.read_blob(identity, request),
                None => Err(UpstreamError::NotFound),
            };
        };
        let upstream_blob = self
            .identifiers
            .lock()
            .map_err(|_| UpstreamError::Unavailable)?
            .upstream_attachment(&request.blob_id);
        let Some(upstream_blob) = upstream_blob else {
            return Err(UpstreamError::NotFound);
        };
        let mut client = self.client.lock().map_err(|_| UpstreamError::Unavailable)?;
        reader::read_blob(
            &mut client,
            account,
            &BlobRequest {
                mailbox: request.mailbox.clone(),
                message_id: request.message_id.clone(),
                blob_id: upstream_blob,
            },
            &self.limits,
        )
        .map_err(map_error)
    }

    fn submit(
        &self,
        identity: &MailIdentity,
        message: &OutgoingMessage,
    ) -> Result<SubmissionReceipt, UpstreamError> {
        let Some(account) = self.account(identity) else {
            return match self.remaining(identity) {
                Some(remaining) => remaining.submit(identity, message),
                None => Err(UpstreamError::NotFound),
            };
        };
        let mut client = self.client.lock().map_err(|_| UpstreamError::Unavailable)?;
        let receipt =
            submission::submit_message(&mut client, account, identity.address.as_str(), message)
                .map_err(map_error)?;
        let mut identifiers = self
            .identifiers
            .lock()
            .map_err(|_| UpstreamError::Unavailable)?;
        Ok(SubmissionReceipt {
            id: identifiers.public_submission(&receipt.id),
            accepted: receipt.accepted,
            rejection: receipt.rejection,
        })
    }
}

/// The mapping between upstream identifiers and the opaque ones.
#[derive(Debug, Default)]
struct Identifiers {
    messages: HashMap<String, String>,
    attachments: HashMap<String, String>,
    submissions: HashMap<String, String>,
}

impl Identifiers {
    /// The opaque identifier of an upstream message.
    fn public_message(&mut self, upstream: &str) -> MessageId {
        let public = public_id("msg", upstream);
        self.messages.insert(upstream.to_owned(), public.clone());
        MessageId::new(public)
    }

    /// The upstream identifier of an opaque message identifier.
    fn upstream_message(&self, public: &MessageId) -> Option<String> {
        self.messages
            .iter()
            .find(|(_, opaque)| opaque.as_str() == public.as_str())
            .map(|(upstream, _)| upstream.clone())
    }

    /// The opaque identifier of an upstream attachment.
    fn public_attachment(&mut self, upstream: &str) -> String {
        let public = public_id("att", upstream);
        self.attachments.insert(upstream.to_owned(), public.clone());
        public
    }

    /// The upstream identifier of an opaque attachment identifier.
    fn upstream_attachment(&self, public: &str) -> Option<String> {
        self.attachments
            .iter()
            .find(|(_, opaque)| opaque.as_str() == public)
            .map(|(upstream, _)| upstream.clone())
    }

    /// The opaque identifier of an upstream submission.
    fn public_submission(&mut self, upstream: &str) -> String {
        let public = public_id("sub", upstream);
        self.submissions.insert(upstream.to_owned(), public.clone());
        public
    }
}

/// An opaque identifier derived from an upstream identifier.
///
/// The derivation is one-way, so the upstream identifier cannot be read back
/// out of a public identifier, and the prefix says what the identifier is
/// without saying where it came from.
fn public_id(prefix: &str, upstream: &str) -> String {
    let digest = Sha256::digest(upstream.as_bytes());
    let encoded = digest
        .iter()
        .take(12)
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("{prefix}_{encoded}")
}

/// Map a JMAP error onto an upstream error.
fn map_error(error: JmapError) -> UpstreamError {
    match error {
        JmapError::UpstreamUnavailable(_) => UpstreamError::Unavailable,
        JmapError::Unauthorized | JmapError::NeedsAuthorization(_) => UpstreamError::Unauthorized,
        JmapError::NotFound => UpstreamError::NotFound,
        JmapError::Rejected(reason) => UpstreamError::Rejected(reason),
        JmapError::TooLarge { limit } => UpstreamError::TooLarge { limit },
        JmapError::Ambiguous(reason) => UpstreamError::Ambiguous(reason),
        other => UpstreamError::Protocol(other.to_string()),
    }
}
