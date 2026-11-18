//! The one service pipeline both protocol adapters drive.
//!
//! ADR-0005 requires the REST and MCP surfaces to be projections over the
//! same application service, and ADR-0003 section 7 requires the disclosure
//! filter to run before anything is disclosed. This module is that service:
//! it authenticates the caller, resolves exactly one identity, authorizes the
//! action against that identity alone, checks the message's provenance
//! against the identity's isolation mode, evaluates the disclosure policy,
//! builds the safe projection and only then serves or submits.
//!
//! The order of those steps is the point. A failure anywhere fails closed:
//! an unevaluable filter hides the message rather than showing it, and a
//! message that does not belong to the identity is indistinguishable from one
//! that does not exist.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;

use mail_config::SnapshotStore;
use mail_core::{
    Action, BlobRequest, GrantDecision, IdentityId, ListQuery, MailIdentity, MessageId,
    OutgoingMessage, ScopedGrants,
};
use mail_policy::apply_redactions;
use mail_policy::{AttachmentAccess, FilterPolicy, RedactedMessage};

use crate::approval::{ApprovalGrant, ApprovalRequest, ApprovalStore};
use crate::cursor::{CursorScope, CursorStore, digest};
use crate::policy::PolicyStore;
use crate::problem::Problem;
use crate::submission::{SubmissionRecord, SubmissionStore};
use crate::upstream::{Upstream, UpstreamError};
use crate::view::{
    AttachmentDescriptor, IdentitiesResponse, IdentityView, MailAddress, MailMessage, MessagePage,
    MessageSummary, Submission, SubmissionStatus,
};

/// The default number of results in a page.
pub const DEFAULT_LIMIT: u32 = 25;

/// The largest number of results a page may contain.
pub const MAX_LIMIT: u32 = 100;

/// The largest number of upstream pages one request may consume.
const MAX_UPSTREAM_PAGES: usize = 10;

/// The tool name an approval is sealed for.
pub const SEND_TOOL: &str = "mail_send";

/// The clock the gateway reads the time from.
pub trait Clock: Send + Sync + fmt::Debug {
    /// The current time, in seconds since the Unix epoch.
    fn now(&self) -> u64;
}

/// The wall clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        crate::time::now_epoch()
    }
}

/// A clock that always reports the same instant.
#[derive(Debug, Clone, Copy)]
pub struct FixedClock(u64);

impl FixedClock {
    /// Create a clock that reports `epoch_seconds`.
    pub fn new(epoch_seconds: u64) -> Self {
        Self(epoch_seconds)
    }
}

impl Clock for FixedClock {
    fn now(&self) -> u64 {
        self.0
    }
}

/// An authenticated caller.
#[derive(Debug, Clone)]
pub struct Caller {
    credential_id: String,
    grants: ScopedGrants,
}

impl Caller {
    /// Build a caller from a credential identifier and its grants.
    pub fn new(credential_id: impl Into<String>, grants: ScopedGrants) -> Self {
        Self {
            credential_id: credential_id.into(),
            grants,
        }
    }

    /// The credential the caller authenticated with.
    pub fn credential_id(&self) -> &str {
        &self.credential_id
    }

    /// The identity-scoped grants the caller holds.
    pub fn grants(&self) -> &ScopedGrants {
        &self.grants
    }
}

/// A request to list messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListRequest {
    /// The identity to list under.
    pub identity: IdentityId,
    /// The maximum number of results.
    pub limit: u32,
    /// The cursor of a previous page.
    pub cursor: Option<String>,
}

/// A request to search messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchRequest {
    /// The identity to search under.
    pub identity: IdentityId,
    /// The literal, case-insensitive query.
    pub query: String,
    /// The maximum number of results.
    pub limit: u32,
    /// The cursor of a previous page.
    pub cursor: Option<String>,
}

/// A request to read one message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetMessageRequest {
    /// The identity to read under.
    pub identity: IdentityId,
    /// The message to read.
    pub message_id: String,
}

/// A request to read one attachment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetAttachmentRequest {
    /// The identity to read under.
    pub identity: IdentityId,
    /// The message the attachment belongs to.
    pub message_id: String,
    /// The attachment to read.
    pub attachment_id: String,
}

/// A request to send a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendRequest {
    /// The identity to send from.
    pub identity: IdentityId,
    /// The primary recipients.
    pub to: Vec<MailAddress>,
    /// The carbon-copy recipients.
    pub cc: Vec<MailAddress>,
    /// The blind carbon-copy recipients.
    pub bcc: Vec<MailAddress>,
    /// The subject.
    pub subject: String,
    /// The plain-text body.
    pub text_body: String,
    /// The client-generated idempotency key.
    pub idempotency_key: String,
    /// Whether the protocol requires an approval round trip.
    pub approval_required: bool,
    /// The approval the client returned, when there is one.
    pub approval: Option<ApprovalGrant>,
}

/// A request to read one submission's status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetSubmissionRequest {
    /// The identity to read under.
    pub identity: IdentityId,
    /// The submission to read.
    pub submission_id: String,
}

/// The result of a send attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendOutcome {
    /// The message was handed to the upstream, or its outcome is recorded.
    Submitted {
        /// The submission record.
        submission: Submission,
        /// Whether the submission is a replay of an earlier send.
        replayed: bool,
    },
    /// The send needs the user's approval before anything is sent.
    ApprovalRequired(ApprovalRequest),
}

/// The bytes of one attachment, with the metadata the caller may see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentPayload {
    /// The attachment metadata.
    pub descriptor: AttachmentDescriptor,
    /// The content type the upstream declared.
    pub content_type: Option<String>,
    /// The bytes.
    pub bytes: Vec<u8>,
}

/// The gateway.
#[derive(Debug, Clone)]
pub struct Gateway {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    config: Arc<SnapshotStore>,
    policies: Arc<PolicyStore>,
    upstream: Arc<dyn Upstream>,
    cursors: Arc<CursorStore>,
    submissions: Arc<SubmissionStore>,
    approvals: Arc<ApprovalStore>,
    clock: Arc<dyn Clock>,
}

/// Assembles a [`Gateway`].
#[derive(Debug)]
pub struct GatewayBuilder {
    config: Arc<SnapshotStore>,
    policies: Arc<PolicyStore>,
    upstream: Arc<dyn Upstream>,
    clock: Arc<dyn Clock>,
    sealing_key: Option<Vec<u8>>,
}

impl GatewayBuilder {
    /// Start a gateway from its configuration and its upstream.
    pub fn new(
        config: Arc<SnapshotStore>,
        policies: Arc<PolicyStore>,
        upstream: Arc<dyn Upstream>,
    ) -> Self {
        Self {
            config,
            policies,
            upstream,
            clock: Arc::new(SystemClock),
            sealing_key: None,
        }
    }

    /// Use a specific clock.
    pub fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Use a specific sealing key for cursors and approvals.
    ///
    /// The key seals cursors and approvals only; it is not an authentication
    /// secret and never authenticates a caller.
    pub fn sealing_key(mut self, key: Vec<u8>) -> Self {
        self.sealing_key = Some(key);
        self
    }

    /// Build the gateway.
    pub fn build(self) -> Gateway {
        let key = self
            .sealing_key
            .unwrap_or_else(|| crate::time::random_bytes(32));
        Gateway {
            inner: Arc::new(Inner {
                config: self.config,
                policies: self.policies,
                upstream: self.upstream,
                cursors: Arc::new(CursorStore::new(key.clone())),
                submissions: Arc::new(SubmissionStore::new()),
                approvals: Arc::new(ApprovalStore::new(key)),
                clock: self.clock,
            }),
        }
    }
}

impl Gateway {
    /// Authenticate a presented credential secret.
    ///
    /// A credential that is unknown, expired, or whose secret file cannot be
    /// read is refused in exactly the same way as a wrong secret, so the
    /// caller learns nothing about which credentials exist.
    pub fn authenticate(&self, presented_secret: &str) -> Result<Caller, Problem> {
        if presented_secret.is_empty() {
            return Err(Problem::unauthorized());
        }
        let now = self.inner.clock.now();
        let snapshot = self.inner.config.active();
        for credential in snapshot.credentials() {
            if credential.is_expired(now) {
                continue;
            }
            if let Ok(true) = credential.authenticate(presented_secret) {
                return Ok(Caller::new(credential.id(), credential.grants().clone()));
            }
        }
        Err(Problem::unauthorized())
    }

    /// List the identities the caller may act on.
    ///
    /// Each entry carries the effective permissions of that identity alone.
    /// The identities are never unioned, and an identity the caller holds no
    /// grant for never appears.
    pub fn list_identities(&self, caller: &Caller) -> Result<IdentitiesResponse, Problem> {
        let snapshot = self.inner.config.active();
        let mut items = Vec::new();
        let mut may_list = false;
        for identity in caller.grants.identities() {
            let Some(config) = snapshot.identity(identity) else {
                continue;
            };
            let mut permissions: Vec<String> = caller
                .grants
                .actions_for(identity)
                .map(|actions| {
                    actions
                        .iter()
                        .map(|action| action.as_str().to_owned())
                        .collect()
                })
                .unwrap_or_default();
            permissions.sort();
            if permissions
                .iter()
                .any(|permission| permission == Action::ListIdentities.as_str())
            {
                may_list = true;
            }
            items.push(IdentityView {
                id: config.id.as_str().to_owned(),
                address: config.address.clone(),
                display_name: config.display_name.clone(),
                permissions,
            });
        }
        if !may_list {
            return Err(Problem::forbidden());
        }
        Ok(IdentitiesResponse { items })
    }

    /// List the messages the caller may see for one identity.
    pub fn list_messages(
        &self,
        caller: &Caller,
        request: &ListRequest,
    ) -> Result<MessagePage, Problem> {
        let identity = self.authorize(caller, &request.identity, Action::List)?;
        let scope = CursorScope::listing(
            caller.credential_id(),
            identity.id.as_str(),
            Action::List.as_str(),
            self.inner.policies.generation(),
        );
        let position = self.resolve_cursor(request.cursor.as_deref(), &scope)?;
        let limit = clamp_limit(request.limit);
        self.collect(caller, &identity, &scope, position, limit, |_| true)
    }

    /// Search the messages the caller may see for one identity.
    ///
    /// The query is a case-insensitive literal substring matched against the
    /// **projected** subject and body, so a match can never reveal content
    /// the policy hid, and a hidden message can never match.
    pub fn search_messages(
        &self,
        caller: &Caller,
        request: &SearchRequest,
    ) -> Result<MessagePage, Problem> {
        let identity = self.authorize(caller, &request.identity, Action::Search)?;
        let query = request.query.trim();
        if query.is_empty() {
            return Err(Problem::invalid_input("the query must not be empty"));
        }
        let scope = CursorScope::search(
            caller.credential_id(),
            identity.id.as_str(),
            Action::Search.as_str(),
            query,
            self.inner.policies.generation(),
        );
        let position = self.resolve_cursor(request.cursor.as_deref(), &scope)?;
        let limit = clamp_limit(request.limit);
        let needle = query.to_lowercase();
        self.collect(caller, &identity, &scope, position, limit, |projected| {
            projected
                .message
                .subject
                .as_deref()
                .is_some_and(|subject| subject.to_lowercase().contains(&needle))
                || projected
                    .message
                    .text_body
                    .as_deref()
                    .is_some_and(|body| body.to_lowercase().contains(&needle))
        })
    }

    /// Read one message.
    ///
    /// A message that the policy hides, that the identity does not own, or
    /// that does not exist is answered with the same not-found response.
    pub fn get_message(
        &self,
        caller: &Caller,
        request: &GetMessageRequest,
    ) -> Result<MailMessage, Problem> {
        let identity = self.authorize(caller, &request.identity, Action::Read)?;
        let untrusted = self
            .inner
            .upstream
            .get(&identity, &MessageId::new(request.message_id.clone()))
            .map_err(map_upstream)?;
        let Some(untrusted) = untrusted else {
            return Err(Problem::not_found());
        };
        let projected = self
            .project(&identity, untrusted)
            .ok_or_else(Problem::not_found)?;
        Ok(message_view(&identity, &projected))
    }

    /// Read the bytes of one attachment.
    ///
    /// The message is fetched and filtered again for this request: an
    /// attachment identifier is not a capability, and a policy that has
    /// changed since the message was listed is applied before the bytes are
    /// read.
    pub fn get_attachment(
        &self,
        caller: &Caller,
        request: &GetAttachmentRequest,
        max_bytes: u64,
    ) -> Result<AttachmentPayload, Problem> {
        let identity = self.authorize(caller, &request.identity, Action::ReadAttachment)?;
        let message_id = MessageId::new(request.message_id.clone());
        let untrusted = self
            .inner
            .upstream
            .get(&identity, &message_id)
            .map_err(map_upstream)?;
        let Some(untrusted) = untrusted else {
            return Err(Problem::not_found());
        };
        let projected = self
            .project(&identity, untrusted)
            .ok_or_else(Problem::not_found)?;
        if projected.decision.rendering.attachments != AttachmentAccess::Full {
            return Err(Problem::not_found());
        }
        let descriptor = projected
            .message
            .attachments
            .iter()
            .find(|attachment| attachment.id == request.attachment_id)
            .ok_or_else(Problem::not_found)?;
        let blob = self
            .inner
            .upstream
            .read_blob(
                &identity,
                &BlobRequest {
                    mailbox: identity.mailbox.clone(),
                    message_id: message_id.clone(),
                    blob_id: descriptor.id.clone(),
                },
            )
            .map_err(map_upstream)?;
        if blob.bytes.len() as u64 > max_bytes {
            return Err(Problem::attachment_too_large());
        }
        Ok(AttachmentPayload {
            descriptor: descriptor_view(descriptor),
            content_type: blob.content_type.clone(),
            bytes: blob.bytes,
        })
    }

    /// Send a message from one identity.
    ///
    /// The envelope sender is derived from the authorized identity; the
    /// caller never supplies it. When the protocol requires an approval, the
    /// first call produces the approval request and touches no upstream.
    pub fn send_message(
        &self,
        caller: &Caller,
        request: &SendRequest,
    ) -> Result<SendOutcome, Problem> {
        let identity = self.authorize(caller, &request.identity, Action::Send)?;
        validate_send(request)?;
        let recipients = envelope_recipients(request);
        let payload_digest = digest(&canonical_payload(&identity, request, &recipients));
        let now = self.inner.clock.now();

        if let Some(record) = self.inner.submissions.idempotency_record(
            caller.credential_id(),
            identity.id.as_str(),
            &request.idempotency_key,
        ) {
            if record.payload_digest != payload_digest {
                return Err(Problem::idempotency_conflict());
            }
            let submission = self
                .inner
                .submissions
                .get(&record.submission_id)
                .ok_or_else(Problem::not_found)?;
            return Ok(SendOutcome::Submitted {
                submission: submission.to_view(),
                replayed: true,
            });
        }

        let approval_required =
            request.approval_required && !self.inner.policies.allows_unattended_send(&identity.id);
        let binding = crate::approval::ApprovalBinding {
            principal: caller.credential_id(),
            identity: identity.id.as_str(),
            tool: SEND_TOOL,
            payload_digest: &payload_digest,
            idempotency_key: &request.idempotency_key,
            generation: self.inner.policies.generation(),
        };
        if approval_required {
            match &request.approval {
                None => {
                    let message = approval_message(&identity, request, &recipients);
                    let approval = self.inner.approvals.seal(&binding, message, now);
                    return Ok(SendOutcome::ApprovalRequired(approval));
                }
                Some(grant) => {
                    self.inner.approvals.verify(grant, &binding, now)?;
                }
            }
        }

        let submission_id = crate::time::random_id();
        self.inner.submissions.record_idempotency(
            caller.credential_id(),
            identity.id.as_str(),
            &request.idempotency_key,
            &payload_digest,
            &submission_id,
        );
        self.inner.submissions.insert(SubmissionRecord {
            id: submission_id.clone(),
            principal: caller.credential_id().to_owned(),
            identity: identity.id.as_str().to_owned(),
            status: SubmissionStatus::Queued,
            created_at: now,
            updated_at: now,
            failure_code: None,
        });

        let outgoing = OutgoingMessage {
            sender: identity.address.clone(),
            recipients,
            subject: Some(request.subject.clone()),
            headers: Vec::new(),
            body: request.text_body.clone(),
        };
        let outcome = self.inner.upstream.submit(&identity, &outgoing);
        let (status, failure_code) = match outcome {
            Ok(receipt) if receipt.accepted => (SubmissionStatus::Submitted, None),
            Ok(receipt) => (
                SubmissionStatus::Failed,
                Some(
                    receipt
                        .rejection
                        .unwrap_or_else(|| "UPSTREAM_REJECTED".to_owned()),
                ),
            ),
            Err(UpstreamError::Ambiguous(_)) => (
                SubmissionStatus::Unknown,
                Some("SEND_OUTCOME_UNKNOWN".to_owned()),
            ),
            Err(UpstreamError::Unavailable) => (
                SubmissionStatus::Failed,
                Some("UPSTREAM_UNAVAILABLE".to_owned()),
            ),
            Err(_) => (SubmissionStatus::Failed, Some("UPSTREAM_ERROR".to_owned())),
        };
        self.inner
            .submissions
            .update_status(&submission_id, status, failure_code.clone(), now);
        let record = self
            .inner
            .submissions
            .get(&submission_id)
            .ok_or_else(Problem::internal)?;
        Ok(SendOutcome::Submitted {
            submission: record.to_view(),
            replayed: false,
        })
    }

    /// Read the status of one of the caller's own submissions.
    pub fn get_submission(
        &self,
        caller: &Caller,
        request: &GetSubmissionRequest,
    ) -> Result<Submission, Problem> {
        let identity = self.authorize(caller, &request.identity, Action::ReadSubmission)?;
        let record = self
            .inner
            .submissions
            .get(&request.submission_id)
            .ok_or_else(Problem::not_found)?;
        if record.identity != identity.id.as_str() || record.principal != caller.credential_id() {
            return Err(Problem::not_found());
        }
        Ok(record.to_view())
    }

    /// The identities the caller may act on, for the MCP identity resource.
    pub fn identities_for(&self, caller: &Caller) -> IdentitiesResponse {
        self.list_identities(caller)
            .unwrap_or(IdentitiesResponse { items: Vec::new() })
    }

    /// The active configuration snapshot.
    pub fn snapshot(&self) -> Arc<mail_config::ValidatedSnapshot> {
        self.inner.config.active()
    }

    /// Whether an identity may send without an interactive approval.
    pub fn allows_unattended_send(&self, identity: &IdentityId) -> bool {
        self.inner.policies.allows_unattended_send(identity)
    }

    /// The policy revision in force.
    pub fn policy_generation(&self) -> u64 {
        self.inner.policies.generation()
    }

    /// The policy that applies to an identity.
    pub fn policy_for(&self, identity: &IdentityId) -> Option<&FilterPolicy> {
        self.inner.policies.policy_for(identity)
    }

    /// Authorize one action against one explicitly selected identity.
    ///
    /// An identity the caller holds no grant for is not found, and an
    /// identity the caller may act on but not with this action is forbidden.
    /// The two are different answers, and neither leaks the existence of
    /// another identity's mail.
    fn authorize(
        &self,
        caller: &Caller,
        identity: &IdentityId,
        action: Action,
    ) -> Result<MailIdentity, Problem> {
        match caller.grants.decide(identity, action) {
            GrantDecision::UnknownIdentity => return Err(Problem::not_found()),
            GrantDecision::ActionDenied => return Err(Problem::forbidden()),
            GrantDecision::Granted => {}
        }
        let snapshot = self.inner.config.active();
        snapshot
            .identity(identity)
            .cloned()
            .ok_or_else(Problem::not_found)
    }

    /// Resolve a cursor into the upstream position it names.
    fn resolve_cursor(
        &self,
        cursor: Option<&str>,
        scope: &CursorScope,
    ) -> Result<Option<String>, Problem> {
        let Some(cursor) = cursor else {
            return Ok(None);
        };
        let now = self.inner.clock.now();
        self.inner.cursors.resolve(cursor, scope, now)
    }

    /// Collect one page of visible messages.
    ///
    /// The upstream is consumed page by page, and a page is only left behind
    /// once every message in it has been projected. A page that holds fewer
    /// visible messages than the caller asked for is therefore continued
    /// rather than truncated, and the next cursor resumes exactly where the
    /// visible listing stopped.
    fn collect(
        &self,
        caller: &Caller,
        identity: &MailIdentity,
        scope: &CursorScope,
        position: Option<String>,
        limit: u32,
        matches: impl Fn(&Projected) -> bool,
    ) -> Result<MessagePage, Problem> {
        let mut items: Vec<MessageSummary> = Vec::new();
        let mut cursor = position;
        let mut next_position: Option<String> = None;
        let mut wanted = limit;

        for _ in 0..MAX_UPSTREAM_PAGES {
            let page = self
                .inner
                .upstream
                .list(
                    identity,
                    &ListQuery {
                        limit: wanted,
                        cursor: cursor.clone(),
                    },
                )
                .map_err(map_upstream)?;
            let mut consumed = 0_usize;
            let page_len = page.messages.len();
            for untrusted in page.messages {
                consumed += 1;
                let Some(projected) = self.project(identity, untrusted) else {
                    continue;
                };
                if !matches(&projected) {
                    continue;
                }
                items.push(summary_view(identity, &projected));
                if items.len() as u32 >= limit {
                    break;
                }
            }
            // The next cursor may only continue where this page ended. When
            // the page held more messages than the page asked for, the
            // position inside it cannot be expressed, so the listing ends
            // rather than skipping the messages in between.
            let page_fully_consumed = consumed == page_len;
            next_position = if page_fully_consumed {
                page.next_cursor.clone()
            } else {
                None
            };
            if items.len() as u32 >= limit {
                break;
            }
            wanted = limit.saturating_sub(items.len() as u32);
            let Some(next) = page.next_cursor.clone() else {
                next_position = None;
                break;
            };
            cursor = Some(next);
        }

        let next_cursor = match next_position {
            Some(position) => Some(self.inner.cursors.issue(
                scope,
                Some(position),
                self.inner.clock.now(),
            )?),
            None => None,
        };
        let _ = caller;
        Ok(MessagePage { items, next_cursor })
    }

    /// Filter one message into the projection the caller may see.
    ///
    /// The message is checked against the identity's isolation mode first,
    /// then against the disclosure policy. A message that fails either check
    /// is not projected at all, so no later stage can leak it.
    fn project(
        &self,
        identity: &MailIdentity,
        untrusted: mail_core::UntrustedMessage,
    ) -> Option<Projected> {
        let normalized = untrusted.into_normalized();
        if !identity.owns_message(&normalized) {
            return None;
        }
        let policy = self.inner.policies.policy_for(&identity.id)?;
        let decision = policy.evaluate(&normalized);
        if !decision.permits_disclosure() {
            return None;
        }
        let message = apply_redactions(&normalized, &decision);
        let received_at = self.received_at(normalized.date.as_deref());
        Some(Projected {
            message,
            decision,
            received_at,
            is_read: Some(
                normalized
                    .flags
                    .iter()
                    .any(|flag| flag.eq_ignore_ascii_case("seen")),
            ),
        })
    }

    /// The timestamp a message is disclosed with.
    fn received_at(&self, upstream_date: Option<&str>) -> String {
        if let Some(date) = upstream_date {
            if let Some(epoch) = crate::time::parse_rfc3339(date) {
                return crate::time::format_rfc3339(epoch);
            }
            if let Ok(epoch) = date.trim().parse::<u64>() {
                return crate::time::format_rfc3339(epoch);
            }
        }
        crate::time::format_rfc3339(self.inner.clock.now())
    }
}

/// One message after the disclosure filter ran.
#[derive(Debug)]
struct Projected {
    message: RedactedMessage,
    decision: mail_policy::Decision,
    received_at: String,
    is_read: Option<bool>,
}

/// Clamp a requested page size to the contract's bounds.
fn clamp_limit(limit: u32) -> u32 {
    if limit == 0 {
        DEFAULT_LIMIT
    } else {
        limit.min(MAX_LIMIT)
    }
}

/// Map an upstream failure onto a problem.
fn map_upstream(error: UpstreamError) -> Problem {
    match error {
        UpstreamError::NotFound => Problem::not_found(),
        UpstreamError::Unauthorized => Problem::unauthorized(),
        UpstreamError::TooLarge { .. } => Problem::attachment_too_large(),
        UpstreamError::Unavailable | UpstreamError::Protocol(_) => Problem::upstream_unavailable(),
        UpstreamError::Ambiguous(_) | UpstreamError::Rejected(_) => Problem::upstream_unavailable(),
    }
}

/// Check that a send request is well formed.
fn validate_send(request: &SendRequest) -> Result<(), Problem> {
    if request.to.is_empty() {
        return Err(Problem::invalid_input("at least one recipient is required"));
    }
    if request.to.len() > MAX_LIMIT as usize
        || request.cc.len() > MAX_LIMIT as usize
        || request.bcc.len() > MAX_LIMIT as usize
    {
        return Err(Problem::invalid_input("too many recipients"));
    }
    for address in request
        .to
        .iter()
        .chain(request.cc.iter())
        .chain(request.bcc.iter())
    {
        validate_address(&address.email)?;
    }
    if request.subject.is_empty() || request.subject.len() > 998 {
        return Err(Problem::invalid_input("the subject is empty or too long"));
    }
    if request.text_body.is_empty() || request.text_body.len() > 1_000_000 {
        return Err(Problem::invalid_input("the body is empty or too long"));
    }
    if request.idempotency_key.is_empty() || request.idempotency_key.len() > 128 {
        return Err(Problem::invalid_input(
            "the idempotency key is empty or too long",
        ));
    }
    Ok(())
}

/// Check that one address is usable as a recipient.
fn validate_address(address: &str) -> Result<(), Problem> {
    if address.is_empty() || address.len() > 320 {
        return Err(Problem::invalid_input("a recipient address is invalid"));
    }
    if address.chars().any(|character| character.is_control()) {
        return Err(Problem::invalid_input("a recipient address is invalid"));
    }
    let Some((local, domain)) = address.split_once('@') else {
        return Err(Problem::invalid_input("a recipient address is invalid"));
    };
    if local.is_empty() || domain.is_empty() || !domain.contains('.') {
        return Err(Problem::invalid_input("a recipient address is invalid"));
    }
    Ok(())
}

/// The envelope recipients of a send.
fn envelope_recipients(request: &SendRequest) -> Vec<String> {
    request
        .to
        .iter()
        .chain(request.cc.iter())
        .chain(request.bcc.iter())
        .map(|address| address.email.clone())
        .collect()
}

/// The canonical payload an idempotency key is bound to.
fn canonical_payload(
    identity: &MailIdentity,
    request: &SendRequest,
    recipients: &[String],
) -> String {
    let mut payload = String::new();
    payload.push_str(identity.id.as_str());
    payload.push('\u{1e}');
    payload.push_str(&request.subject);
    payload.push('\u{1e}');
    payload.push_str(&request.text_body);
    payload.push('\u{1e}');
    payload.push_str(&recipients.join(","));
    payload
}

/// The message the user is asked to approve.
fn approval_message(
    identity: &MailIdentity,
    request: &SendRequest,
    recipients: &[String],
) -> String {
    format!(
        "Send from {} to {}? Subject: {}",
        identity.address,
        recipients.join(", "),
        request.subject
    )
}

/// The summary projection of one message.
fn summary_view(identity: &MailIdentity, projected: &Projected) -> MessageSummary {
    MessageSummary {
        id: projected.message.id.as_str().to_owned(),
        identity_id: identity.id.as_str().to_owned(),
        received_at: projected.received_at.clone(),
        conversation_id: None,
        subject: projected.message.subject.clone(),
        from: projected.message.from.as_ref().map(address_view),
        snippet: snippet(projected.message.text_body.as_deref()),
        is_read: projected.is_read,
    }
}

/// The full projection of one message.
fn message_view(identity: &MailIdentity, projected: &Projected) -> MailMessage {
    let attachments = projected
        .message
        .attachments
        .iter()
        .map(attachment_view)
        .collect::<Vec<_>>();
    MailMessage {
        id: projected.message.id.as_str().to_owned(),
        identity_id: identity.id.as_str().to_owned(),
        received_at: projected.received_at.clone(),
        conversation_id: None,
        subject: projected.message.subject.clone(),
        from: projected.message.from.as_ref().map(address_view),
        to: Some(projected.message.to.iter().map(address_view).collect()),
        cc: Some(projected.message.cc.iter().map(address_view).collect()),
        reply_to: Some(
            projected
                .message
                .reply_to
                .iter()
                .map(address_view)
                .collect(),
        ),
        text_body: projected.message.text_body.clone(),
        html_body: projected.message.html_body.clone(),
        is_read: projected.is_read,
        attachments: Some(attachments),
    }
}

/// The metadata of one attachment.
fn attachment_view(attachment: &mail_core::AttachmentMeta) -> AttachmentDescriptor {
    AttachmentDescriptor {
        id: attachment.id.clone(),
        file_name: attachment.filename.clone().unwrap_or_default(),
        content_type: attachment.content_type.clone().unwrap_or_default(),
        size_bytes: attachment.size,
    }
}

/// The descriptor of one attachment.
fn descriptor_view(attachment: &mail_core::AttachmentMeta) -> AttachmentDescriptor {
    attachment_view(attachment)
}

/// The wire projection of one address.
fn address_view(address: &mail_core::Address) -> MailAddress {
    MailAddress {
        email: address.address.clone(),
        name: address.display_name.clone(),
    }
}

/// A short excerpt of the projected body.
fn snippet(body: Option<&str>) -> Option<String> {
    let body = body?;
    let collapsed = body.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        return None;
    }
    Some(collapsed.chars().take(200).collect())
}

/// The actions a caller holds for an identity, as a set.
pub fn granted_actions(caller: &Caller, identity: &IdentityId) -> BTreeSet<Action> {
    caller
        .grants
        .actions_for(identity)
        .cloned()
        .unwrap_or_default()
}
