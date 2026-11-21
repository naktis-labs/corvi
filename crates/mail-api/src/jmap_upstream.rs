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
//! 1. **Upstream identifiers stay private.** Public IDs are keyed by a
//!    process-local secret and scoped to the configured identity/account pair.
//!    Their reverse mappings are bounded and expire, so an ID replayed in a
//!    different scope fails closed.
//! 2. **Identities are routed to accounts.** A deployment may serve
//!    identities from several upstream accounts, and may serve some of them
//!    over a different transport entirely. An identity this adapter does not
//!    serve is passed to the remaining upstream, so one gateway can serve a
//!    mixed deployment.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use mail_core::{
    BlobContent, BlobRequest, MailIdentity, MessageId, MessagePage, OutgoingMessage,
    SubmissionReceipt,
};
use mail_jmap::{
    client::JmapClient, error::JmapError, reader, submission, transport::TransportLimits,
};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;
const MAX_IDENTIFIER_ENTRIES: usize = 100_000;
/// The most identifiers one identity/account scope may hold.
///
/// The identifiers of one scope are evicted together, so one identity
/// cannot invalidate the identifiers of another.
const MAX_SCOPE_ENTRIES: usize = 10_000;

/// The current time in seconds since the Unix epoch.
fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
const IDENTIFIER_TTL_SECONDS: u64 = 24 * 60 * 60;

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
            identifiers: Mutex::new(Identifiers::new(crate::time::random_bytes(32))),
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
        let scope = identifier_scope(identity, account);
        let mut messages = page.messages;
        for message in &mut messages {
            message.id = identifiers.public_message(&scope, message.id.as_str());
            for attachment in &mut message.attachments {
                attachment.id = identifiers.public_attachment(&scope, &attachment.id);
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
        let scope = identifier_scope(identity, account);
        let upstream_id = self
            .identifiers
            .lock()
            .map_err(|_| UpstreamError::Unavailable)?
            .upstream_message(&scope, message_id);
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
        message.id = identifiers.public_message(&scope, message.id.as_str());
        for attachment in &mut message.attachments {
            attachment.id = identifiers.public_attachment(&scope, &attachment.id);
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
        let scope = identifier_scope(identity, account);
        let upstream_blob = self
            .identifiers
            .lock()
            .map_err(|_| UpstreamError::Unavailable)?
            .upstream_attachment(&scope, &request.blob_id);
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
        let scope = identifier_scope(identity, account);
        let mut identifiers = self
            .identifiers
            .lock()
            .map_err(|_| UpstreamError::Unavailable)?;
        Ok(SubmissionReceipt {
            id: identifiers.public_submission(&scope, &receipt.id),
            accepted: receipt.accepted,
            rejection: receipt.rejection,
        })
    }
}

/// The scope an upstream identifier belongs to.
///
/// The identity and the account are kept apart. One concatenated string
/// would let two scopes collide - the identity `a` with the account `b:c`
/// and the identity `a:b` with the account `c` - and an identifier minted
/// for one of them would then be accepted for the other.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Scope {
    identity: String,
    account: String,
}

fn identifier_scope(identity: &MailIdentity, account: &str) -> Scope {
    Scope {
        identity: identity.id.as_str().to_owned(),
        account: account.to_owned(),
    }
}

/// The identifiers of one scope, in the order they were minted.
#[derive(Debug, Default)]
struct ScopeEntries {
    /// The public identifiers of the scope, oldest first.
    order: VecDeque<String>,
    /// The upstream identifier behind each public identifier.
    ids: HashMap<String, IdentifierEntry>,
}

/// A bounded mapping from keyed, identity/account-scoped public identifiers to upstream IDs.
#[derive(Debug)]
struct Identifiers {
    key: Vec<u8>,
    scopes: HashMap<Scope, ScopeEntries>,
    /// How many identifiers are held in total.
    count: usize,
}

#[derive(Debug)]
struct IdentifierEntry {
    upstream: String,
    expires_at: u64,
}

impl Identifiers {
    fn new(key: Vec<u8>) -> Self {
        Self {
            key,
            scopes: HashMap::new(),
            count: 0,
        }
    }

    fn public_message(&mut self, scope: &Scope, upstream: &str) -> MessageId {
        MessageId::new(self.public("msg", scope, "message", upstream))
    }

    fn upstream_message(&self, scope: &Scope, public: &MessageId) -> Option<String> {
        self.upstream(scope, "message", public.as_str())
    }

    fn public_attachment(&mut self, scope: &Scope, upstream: &str) -> String {
        self.public("att", scope, "attachment", upstream)
    }

    fn upstream_attachment(&self, scope: &Scope, public: &str) -> Option<String> {
        self.upstream(scope, "attachment", public)
    }

    fn public_submission(&mut self, scope: &Scope, upstream: &str) -> String {
        self.public("sub", scope, "submission", upstream)
    }

    fn public(&mut self, prefix: &str, scope: &Scope, kind: &str, upstream: &str) -> String {
        let id = format!("{prefix}_{}", self.mac(scope, kind, upstream));
        let now = now_seconds();
        let expires_at = now.saturating_add(IDENTIFIER_TTL_SECONDS);
        let minted = {
            let entries = self.scopes.entry(scope.clone()).or_default();
            match entries.ids.get_mut(&id) {
                Some(entry) => {
                    entry.expires_at = expires_at;
                    false
                }
                None => {
                    entries.ids.insert(
                        id.clone(),
                        IdentifierEntry {
                            upstream: upstream.to_owned(),
                            expires_at,
                        },
                    );
                    entries.order.push_back(id.clone());
                    true
                }
            }
        };
        if minted {
            self.count += 1;
        }
        self.make_room(scope, now);
        id
    }

    /// Make room for one more identifier of one scope.
    ///
    /// The identifiers of one scope are evicted together: an identifier
    /// minted for one identity stays valid until it expires, whatever
    /// another identity does. Identifiers of other scopes are only dropped
    /// when the whole process is full, and then the oldest ones go first.
    fn make_room(&mut self, scope: &Scope, now: u64) {
        // The scope's own identifiers go first.
        while self.scope_len(scope) > MAX_SCOPE_ENTRIES {
            if !self.drop_scope_oldest(scope) {
                break;
            }
        }
        if self.count < MAX_IDENTIFIER_ENTRIES {
            return;
        }
        // Expired identifiers are dead weight, whoever owns them.
        self.drop_expired(now);
        // Only when the whole process is full do identifiers of other scopes
        // go, and then the oldest ones go first.
        while self.count >= MAX_IDENTIFIER_ENTRIES {
            if !self.drop_oldest_overall() {
                break;
            }
        }
    }

    /// How many identifiers one scope holds.
    fn scope_len(&self, scope: &Scope) -> usize {
        self.scopes
            .get(scope)
            .map_or(0, |entries| entries.ids.len())
    }

    /// Drop the oldest identifier of one scope.
    ///
    /// It reports whether one was dropped.
    fn drop_scope_oldest(&mut self, scope: &Scope) -> bool {
        let Some(entries) = self.scopes.get_mut(scope) else {
            return false;
        };
        while let Some(id) = entries.order.pop_front() {
            if entries.ids.remove(&id).is_some() {
                self.count -= 1;
                return true;
            }
        }
        false
    }

    /// Drop the oldest identifier of the whole process.
    ///
    /// It reports whether one was dropped.
    fn drop_oldest_overall(&mut self) -> bool {
        let mut oldest: Option<(Scope, String)> = None;
        let mut oldest_at = u64::MAX;
        for (scope, entries) in &self.scopes {
            let Some(id) = entries.order.front() else {
                continue;
            };
            let Some(entry) = entries.ids.get(id) else {
                continue;
            };
            if entry.expires_at < oldest_at {
                oldest_at = entry.expires_at;
                oldest = Some((scope.clone(), id.clone()));
            }
        }
        match oldest {
            Some((scope, _)) => self.drop_scope_oldest(&scope),
            None => false,
        }
    }

    /// Drop the identifiers that have expired.
    fn drop_expired(&mut self, now: u64) {
        for scope in self.scopes.keys().cloned().collect::<Vec<_>>() {
            let Some(entries) = self.scopes.get_mut(&scope) else {
                continue;
            };
            while let Some(id) = entries.order.front().cloned() {
                match entries.ids.get(&id) {
                    Some(entry) if entry.expires_at >= now => break,
                    _ => {
                        entries.order.pop_front();
                        if entries.ids.remove(&id).is_some() {
                            self.count -= 1;
                        }
                    }
                }
            }
        }
    }

    fn upstream(&self, scope: &Scope, kind: &str, public: &str) -> Option<String> {
        let prefix = match kind {
            "message" => "msg_",
            "attachment" => "att_",
            _ => "sub_",
        };
        let suffix = public.strip_prefix(prefix)?;
        let entry = self.scopes.get(scope)?.ids.get(public)?;
        if entry.expires_at < now_seconds() {
            return None;
        }
        (suffix == self.mac(scope, kind, &entry.upstream)).then(|| entry.upstream.clone())
    }

    #[cfg(test)]
    fn test_new(key: Vec<u8>) -> Self {
        Self::new(key)
    }

    fn mac(&self, scope: &Scope, kind: &str, upstream: &str) -> String {
        let mut mac =
            HmacSha256::new_from_slice(&self.key).expect("HMAC accepts arbitrary key lengths");
        // Every part is length-prefixed, so no two different scopes can
        // produce the same sequence of parts.
        for part in [
            scope.identity.as_bytes(),
            scope.account.as_bytes(),
            kind.as_bytes(),
            upstream.as_bytes(),
        ] {
            mac.update(&(part.len() as u64).to_be_bytes());
            mac.update(part);
        }
        mac.finalize()
            .into_bytes()
            .iter()
            .take(24)
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
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

#[cfg(test)]
mod identifier_tests {
    use super::*;

    /// The scope of one identity/account pair.
    fn scope(identity: &str, account: &str) -> Scope {
        Scope {
            identity: identity.to_owned(),
            account: account.to_owned(),
        }
    }

    #[test]
    fn identifiers_are_keyed_scoped_and_do_not_expose_small_upstream_ids() {
        let mut ids = Identifiers::test_new(vec![7; 32]);
        let first = ids.public_message(&scope("identity-a", "account-a"), "1");
        assert_ne!(first.as_str(), "msg_1");
        assert_ne!(first.as_str(), "msg_M-email-1");
        assert!(
            ids.upstream_message(&scope("identity-a", "account-a"), &first)
                .is_some()
        );
        assert!(
            ids.upstream_message(&scope("identity-a", "account-b"), &first)
                .is_none()
        );
        assert!(
            ids.upstream_message(&scope("identity-b", "account-a"), &first)
                .is_none()
        );
        assert!(
            Identifiers::test_new(vec![8; 32])
                .upstream_message(&scope("identity-a", "account-a"), &first)
                .is_none()
        );
    }

    #[test]
    fn scopes_of_different_identities_do_not_collide() {
        let mut ids = Identifiers::test_new(vec![7; 32]);
        // The identity "a" with the account "b:c" and the identity "a:b" with
        // the account "c" are two different scopes. One concatenated string
        // would give them the same scope.
        let first = ids.public_message(&scope("a", "b:c"), "1");
        let second = ids.public_message(&scope("a:b", "c"), "1");
        assert_ne!(first, second, "two scopes must not share an identifier");
        assert!(ids.upstream_message(&scope("a", "b:c"), &first).is_some());
        assert!(
            ids.upstream_message(&scope("a:b", "c"), &first).is_none(),
            "an identifier of one scope is not valid in another scope"
        );
    }

    #[test]
    fn mappings_are_bounded() {
        let mut ids = Identifiers::test_new(vec![7; 32]);
        for n in 0..=MAX_IDENTIFIER_ENTRIES {
            ids.public_message(&scope("identity-a", "account-a"), &n.to_string());
        }
        ids.public_message(&scope("identity-a", "account-a"), "overflow");
        assert!(ids.count <= MAX_IDENTIFIER_ENTRIES);
    }

    #[test]
    fn evicting_one_scope_leaves_the_other_scope_intact() {
        let mut ids = Identifiers::test_new(vec![7; 32]);
        let kept = ids.public_message(&scope("identity-a", "account-a"), "kept");
        for n in 0..=MAX_IDENTIFIER_ENTRIES {
            ids.public_message(&scope("identity-b", "account-b"), &n.to_string());
        }
        assert!(
            ids.upstream_message(&scope("identity-a", "account-a"), &kept)
                .is_some(),
            "one identity's identifiers are not invalidated by another's eviction"
        );
    }
}
