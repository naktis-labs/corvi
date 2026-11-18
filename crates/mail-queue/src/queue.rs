//! The durable queue: submissions, tasks and their recovery.
//!
//! This module is the queue's half of ADR-0010. The durable state itself
//! lives in the storage layer: the submission store owns the submission and
//! its idempotency reservation, the task store owns the task, and the
//! mailbox state store owns the leases and the checkpoints. **The queue
//! owns no state of its own**, which is what keeps the storage layer the
//! single owner of durable truth.
//!
//! Five rules shape the API:
//!
//! 1. **The queue is off by default.** Every entry point checks the feature
//!    first and refuses with [`crate::QueueError::FeatureDisabled`] when it
//!    is off, so a disabled queue creates nothing and says so.
//! 2. **The intent comes first.** A submission and its idempotency
//!    reservation are written together, before the caller is told the item
//!    was queued, and before the payload is staged.
//! 3. **The fence decides who works.** A worker whose fence token is stale
//!    does not perform the work; its writes are refused by the store.
//! 4. **The authority is asked again.** The grant behind a queued item may
//!    have been revoked or narrowed while the item waited, so the item is
//!    not executed under stale authority.
//! 5. **An unknown outcome stays unknown.** A submission that was dispatched
//!    and whose answer was lost is recovered as unknown and is never retried
//!    on the strength of a guess.

use std::fmt;

use mail_core::{Action, TransportError};
use mail_storage::{
    IDEMPOTENCY_RETENTION_SECONDS, IdempotencyReservation, MailboxStateStore, StorageError,
    Submission, SubmissionState, SubmissionStore, Task, TaskState, TaskStore,
};
use sha2::{Digest, Sha256};

use crate::authority::{Authority, AuthorizationOutcome, AuthorizationRequest};
use crate::config::{Feature, QueueFeatures};
use crate::error::{QueueError, QueueResult};
use crate::fence::{FencedLease, lease_name_for_submission};
use crate::payload::{PayloadStore, account_of, payload_key_for_submission};

/// The largest payload a queued submission may carry, in bytes.
///
/// The bound matches the transport limit in [`mail_core::TransportLimits`].
/// A payload beyond it is refused rather than truncated: a truncated
/// message is a different message.
pub const MAX_QUEUED_PAYLOAD_BYTES: u64 = 25 * 1024 * 1024;

/// How long a queued payload is kept, in seconds.
///
/// The payload is removed when the item reaches a terminal state, so this
/// window only has to outlive an item that waits for a worker; it is the
/// backstop for an item whose worker never came back.
pub const PAYLOAD_TTL_SECONDS: u64 = 24 * 60 * 60;

/// A request to queue an outgoing submission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueRequest {
    /// The principal that asked for the submission.
    pub principal: String,
    /// The identity the message is sent from.
    pub identity: String,
    /// The client the request came from.
    pub client_id: String,
    /// The idempotency key, when the caller supplied one.
    pub idempotency_key: Option<String>,
    /// The digest of the queued payload, when the caller supplied one.
    ///
    /// When a payload is queued, the queue computes the digest of the bytes
    /// it holds and refuses a request whose digest disagrees with them.
    pub payload_digest: Option<String>,
    /// The payload to queue.
    pub payload: Option<Vec<u8>>,
    /// The upstream protocol the submission will be issued over.
    pub upstream_protocol: Option<String>,
}

impl QueueRequest {
    /// A request without a payload.
    pub fn new(
        principal: impl Into<String>,
        identity: impl Into<String>,
        client_id: impl Into<String>,
    ) -> Self {
        Self {
            principal: principal.into(),
            identity: identity.into(),
            client_id: client_id.into(),
            idempotency_key: None,
            payload_digest: None,
            payload: None,
            upstream_protocol: None,
        }
    }

    /// Attach an idempotency key.
    pub fn with_idempotency_key(mut self, key: impl Into<String>) -> Self {
        self.idempotency_key = Some(key.into());
        self
    }

    /// Attach the payload to queue.
    pub fn with_payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = Some(payload);
        self
    }
}

/// A queued item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedItem {
    /// The identifier of the submission.
    pub id: String,
    /// The state the submission is in.
    pub state: SubmissionState,
    /// The principal the submission belongs to.
    pub principal: String,
    /// The identity the submission acts on.
    pub identity: String,
}

/// An item a worker has claimed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedItem {
    /// The claimed submission.
    pub submission: Submission,
    /// The fenced lease over the item.
    pub lease: FencedLease,
}

/// What happened to a claimed item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionOutcome {
    /// The upstream accepted the message.
    ///
    /// The generation is the revision of the grant the item was authorized
    /// under, so a caller can tell which authority the send happened under.
    /// It is reported, not persisted: the storage schema has no column for
    /// it.
    Accepted {
        /// The revision of the grant that authorized the send.
        grant_generation: u64,
    },
    /// The upstream refused the message.
    Rejected {
        /// Why it was refused.
        reason: String,
    },
    /// The message was dispatched and the outcome cannot be determined.
    Unknown {
        /// Why the outcome is unknown.
        reason: String,
    },
    /// The authority behind the item refused it.
    Refused {
        /// Why it was refused.
        reason: String,
    },
    /// The item failed before the upstream accepted it.
    Failed {
        /// Why it failed.
        reason: String,
    },
}

/// Something that can dispatch a queued submission.
///
/// This is the seam where the SMTP or JMAP transport attaches. The queue
/// itself never opens a connection to an upstream.
pub trait SubmissionExecutor: fmt::Debug {
    /// Dispatch the message.
    ///
    /// The errors are the transport's own vocabulary: an
    /// [`TransportError::Ambiguous`] means the message may or may not have
    /// been delivered, and the queue records that as unknown rather than as
    /// a failure that invites a retry.
    fn dispatch(
        &self,
        submission: &Submission,
        payload: Option<&[u8]>,
    ) -> Result<(), TransportError>;
}

/// What a recovery pass found.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RecoveryReport {
    /// Items that were never dispatched and are safe to claim again.
    pub requeued: usize,
    /// Items that were dispatched and are now unknown.
    pub marked_unknown: usize,
    /// Items that were already unknown and were left alone.
    pub kept_unknown: usize,
    /// Items that failed or were refused and stay failed.
    pub kept_failed: usize,
    /// Items that were accepted before the restart.
    pub kept_accepted: usize,
    /// Tasks that were running and are waiting for a worker again.
    pub tasks_requeued: usize,
    /// Tasks that were already waiting for a worker.
    pub tasks_pending: usize,
}

/// What a maintenance pass removed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SweepReport {
    /// The staged writes that expired and that nothing referred to.
    pub expired_staged: usize,
    /// The objects that expired.
    pub expired_objects: usize,
    /// The idempotency reservations that expired.
    pub purged_idempotency: usize,
}

/// A request to schedule a durable task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRequest {
    /// The identifier of the task.
    pub task_id: String,
    /// The principal the task belongs to.
    pub principal: String,
    /// The identity the task runs under.
    pub identity: String,
}

impl TaskRequest {
    /// A request for one task.
    pub fn new(
        task_id: impl Into<String>,
        principal: impl Into<String>,
        identity: impl Into<String>,
    ) -> Self {
        Self {
            task_id: task_id.into(),
            principal: principal.into(),
            identity: identity.into(),
        }
    }
}

/// The handle of a scheduled task.
///
/// The handle is returned only after the task is persisted, so a client
/// that receives it can always wait for the task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskHandle {
    /// The identifier of the task.
    pub task_id: String,
    /// The state the task is in.
    pub state: TaskState,
}

/// A task a worker has claimed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedTask {
    /// The claimed task.
    pub task: Task,
}

/// The durable queue.
pub struct QueueEngine<'a> {
    features: QueueFeatures,
    submissions: &'a dyn SubmissionStore,
    tasks: &'a dyn TaskStore,
    mailbox: &'a dyn MailboxStateStore,
    payloads: &'a dyn PayloadStore,
}

impl fmt::Debug for QueueEngine<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QueueEngine")
            .field("features", &self.features)
            .finish_non_exhaustive()
    }
}

impl<'a> QueueEngine<'a> {
    /// Build a queue over the storage layer.
    pub fn new(
        features: QueueFeatures,
        submissions: &'a dyn SubmissionStore,
        tasks: &'a dyn TaskStore,
        mailbox: &'a dyn MailboxStateStore,
        payloads: &'a dyn PayloadStore,
    ) -> Self {
        Self {
            features,
            submissions,
            tasks,
            mailbox,
            payloads,
        }
    }

    /// Which optional features are enabled.
    pub fn features(&self) -> &QueueFeatures {
        &self.features
    }

    /// Refuse an operation on a feature that is not enabled.
    pub fn require(&self, feature: Feature) -> QueueResult<()> {
        if self.features.is_enabled(feature) {
            Ok(())
        } else {
            Err(QueueError::FeatureDisabled(feature))
        }
    }

    /// Queue an outgoing submission.
    ///
    /// The submission and its idempotency reservation are written in one
    /// transaction, before the payload is staged and before the caller is
    /// told the item was queued. A repeated key with the same payload
    /// returns the item that already exists, and a repeated key with a
    /// different payload is a conflict.
    pub fn enqueue(&self, request: QueueRequest, now: u64) -> QueueResult<QueuedItem> {
        self.require(Feature::DurableQueue)?;
        // The payload is checked before anything is written, so a refused
        // request leaves no intent behind.
        let payload = request.payload.clone().unwrap_or_default();
        if request.payload.is_some() && payload.len() as u64 > MAX_QUEUED_PAYLOAD_BYTES {
            return Err(QueueError::PayloadTooLarge {
                limit: MAX_QUEUED_PAYLOAD_BYTES,
            });
        }
        let digest = match (&request.payload, &request.payload_digest) {
            (Some(bytes), Some(declared)) => {
                let computed = digest_of(bytes);
                if &computed != declared {
                    return Err(QueueError::Invalid(
                        "the declared payload digest does not match the payload".to_owned(),
                    ));
                }
                Some(computed)
            }
            (Some(bytes), None) => Some(digest_of(bytes)),
            (None, _) => None,
        };
        let id = new_id()?;
        let submission = Submission {
            id: id.clone(),
            principal: request.principal.clone(),
            identity: request.identity.clone(),
            client_id: request.client_id.clone(),
            idempotency_key: request.idempotency_key.clone(),
            payload_digest: digest.clone(),
            state: SubmissionState::Reserved,
            upstream_protocol: request.upstream_protocol.clone(),
            attempts: 0,
            lease_owner: None,
            lease_expires_at: None,
            fencing_token: 0,
            created_at: now,
            updated_at: now,
            failure_code: None,
        };
        let stored = match &request.idempotency_key {
            Some(key) => {
                let reservation = IdempotencyReservation {
                    key: key.clone(),
                    principal: request.principal.clone(),
                    identity: request.identity.clone(),
                    client_id: request.client_id.clone(),
                    payload_digest: digest.clone().unwrap_or_default(),
                    submission_id: id.clone(),
                    created_at: now,
                    expires_at: now + IDEMPOTENCY_RETENTION_SECONDS,
                };
                self.submissions
                    .reserve_submission(&reservation, &submission)?
            }
            None => {
                self.submissions.put_submission(&submission)?;
                submission
            }
        };
        if stored.id != id {
            // The key was already used: this is a replay of an intent that
            // exists, not a second send.
            return Ok(QueuedItem {
                id: stored.id,
                state: stored.state,
                principal: stored.principal,
                identity: stored.identity,
            });
        }
        if let Some(bytes) = &request.payload {
            self.payloads.stage(
                &account_of(&stored.identity),
                &payload_key_for_submission(&stored.id),
                bytes,
                now,
                PAYLOAD_TTL_SECONDS,
            )?;
        }
        Ok(QueuedItem {
            id: stored.id,
            state: stored.state,
            principal: stored.principal,
            identity: stored.identity,
        })
    }

    /// Claim the next item that is waiting to be sent.
    ///
    /// The claim carries the store's fencing token, and the queue takes a
    /// fenced lease over the item on top of it, so the worker that holds
    /// the item can prove that it still holds it.
    pub fn claim_next(&self, owner: &str, now: u64, ttl: u64) -> QueueResult<Option<ClaimedItem>> {
        self.require(Feature::DurableQueue)?;
        let Some(submission) = self.submissions.claim_next(owner, now, ttl)? else {
            return Ok(None);
        };
        let lease = FencedLease::acquire(
            self.mailbox,
            &lease_name_for_submission(&submission.id),
            owner,
            now,
            ttl,
        )?;
        Ok(Some(ClaimedItem { submission, lease }))
    }

    /// Perform a claimed item.
    ///
    /// The order of the checks is the contract:
    ///
    /// 1. The fence. A worker whose lease was taken over does not perform
    ///    the work at all.
    /// 2. The authority. An item whose grant was revoked or narrowed is
    ///    refused rather than executed under stale authority.
    /// 3. The payload. A payload that is missing or that does not match its
    ///    digest fails the item instead of sending something else.
    /// 4. The dispatch, and then the outcome: accepted, rejected, unknown
    ///    or failed.
    pub fn execute(
        &self,
        item: &ClaimedItem,
        executor: &dyn SubmissionExecutor,
        authority: &dyn Authority,
        now: u64,
        ttl: u64,
    ) -> QueueResult<ExecutionOutcome> {
        item.lease.assert_current(self.mailbox, now, ttl)?;
        let request = AuthorizationRequest {
            principal: item.submission.principal.clone(),
            identity: item.submission.identity.clone(),
            action: Action::Send,
            subject: Some(item.submission.id.clone()),
        };
        let grant_generation = match authority.authorize(&request) {
            AuthorizationOutcome::Refused { reason } => {
                self.terminate(
                    item,
                    SubmissionState::Failed,
                    Some("authorization_revoked"),
                    now,
                )?;
                return Ok(ExecutionOutcome::Refused { reason });
            }
            AuthorizationOutcome::Permitted { grant_generation } => grant_generation,
        };
        let payload = match self.load_payload(&item.submission) {
            Ok(payload) => payload,
            Err(error) => {
                self.terminate(item, SubmissionState::Failed, Some("payload_unusable"), now)?;
                return Ok(ExecutionOutcome::Failed {
                    reason: error.to_string(),
                });
            }
        };
        // The item is marked as dispatched before it is dispatched, so a
        // crash in the middle of the send is recovered as unknown rather
        // than as an item that was never sent.
        self.submissions
            .transition(&item.submission.id, SubmissionState::Submitted, now, None)?;
        match executor.dispatch(&item.submission, payload.as_deref()) {
            Ok(()) => {
                self.terminate(item, SubmissionState::Accepted, None, now)?;
                Ok(ExecutionOutcome::Accepted { grant_generation })
            }
            Err(TransportError::Rejected(reason)) => {
                self.terminate(
                    item,
                    SubmissionState::Rejected,
                    Some("upstream_rejected"),
                    now,
                )?;
                Ok(ExecutionOutcome::Rejected { reason })
            }
            Err(TransportError::Ambiguous(reason)) => {
                self.terminate(item, SubmissionState::Unknown, Some("outcome_unknown"), now)?;
                Ok(ExecutionOutcome::Unknown { reason })
            }
            Err(error) => {
                self.terminate(item, SubmissionState::Failed, Some("dispatch_failed"), now)?;
                Ok(ExecutionOutcome::Failed {
                    reason: error.to_string(),
                })
            }
        }
    }

    /// Abandon a claimed item.
    ///
    /// The item is failed and its payload is removed, so a worker that
    /// gives up does not leave the bytes of the message behind.
    pub fn abandon(&self, item: &ClaimedItem, reason: &str, now: u64) -> QueueResult<()> {
        self.terminate(item, SubmissionState::Failed, Some(reason), now)
    }

    /// Recover the work that was in flight when the process stopped.
    ///
    /// An item that was dispatched and whose outcome is unknown becomes
    /// unknown, and stays unknown: it is not retried on the strength of a
    /// guess, because a retry can deliver the message twice. An item that
    /// was never dispatched stays claimable, and a clean rejection stays
    /// failed.
    pub fn recover(&self, identities: &[String], now: u64) -> QueueResult<RecoveryReport> {
        let mut report = RecoveryReport::default();
        for identity in identities {
            for submission in self.submissions.list_by_identity(identity)? {
                match submission.state {
                    SubmissionState::Reserved => report.requeued += 1,
                    SubmissionState::Submitted => {
                        self.submissions.transition(
                            &submission.id,
                            SubmissionState::Unknown,
                            now,
                            Some("outcome_unknown_after_restart".to_owned()),
                        )?;
                        report.marked_unknown += 1;
                    }
                    SubmissionState::Unknown => report.kept_unknown += 1,
                    SubmissionState::Rejected | SubmissionState::Failed => {
                        report.kept_failed += 1;
                    }
                    SubmissionState::Accepted => report.kept_accepted += 1,
                }
            }
        }
        for task in self.tasks.list_tasks(Some(TaskState::Running))? {
            // The worker that owned the task is gone. The task goes back to
            // the queue with a higher fencing token, so the worker that
            // died cannot come back and write over the new owner's work.
            let mut requeued = task.clone();
            requeued.state = TaskState::Pending;
            requeued.owner = None;
            requeued.fencing_token = task.fencing_token.saturating_add(1);
            requeued.updated_at = now;
            self.tasks.put_task(&requeued)?;
            report.tasks_requeued += 1;
        }
        report.tasks_pending = self.tasks.list_tasks(Some(TaskState::Pending))?.len();
        Ok(report)
    }

    /// Remove what expired and what nothing refers to.
    pub fn sweep(&self, identities: &[String], now: u64) -> QueueResult<SweepReport> {
        let pending = self.pending_blobs(identities)?;
        let cleanup = self.payloads.cleanup(now, &pending)?;
        let purged = self.submissions.purge_expired_idempotency(now)?;
        Ok(SweepReport {
            expired_staged: cleanup.expired_staged,
            expired_objects: cleanup.expired_objects,
            purged_idempotency: purged,
        })
    }

    /// Schedule a durable task.
    ///
    /// The task is persisted before the handle is returned, so a client that
    /// is told "this is a task" can always wait for it.
    pub fn schedule_task(&self, request: TaskRequest, now: u64) -> QueueResult<TaskHandle> {
        self.require(Feature::DurableTasks)?;
        let task = Task {
            task_id: request.task_id.clone(),
            principal: request.principal,
            identity: request.identity,
            owner: None,
            state: TaskState::Pending,
            progress: None,
            result_ref: None,
            fencing_token: 0,
            created_at: now,
            updated_at: now,
        };
        self.tasks.put_task(&task)?;
        Ok(TaskHandle {
            task_id: task.task_id,
            state: task.state,
        })
    }

    /// Claim a task for a worker.
    pub fn claim_task(&self, task_id: &str, owner: &str, now: u64) -> QueueResult<ClaimedTask> {
        self.require(Feature::DurableTasks)?;
        let task = self.tasks.claim_task(task_id, owner, now)?;
        Ok(ClaimedTask { task })
    }

    /// Report progress on a task the caller still owns.
    pub fn report_progress(&self, task: &ClaimedTask, progress: &str, now: u64) -> QueueResult<()> {
        self.require(Feature::DurableTasks)?;
        let accepted = self.tasks.set_progress(
            &task.task.task_id,
            &task.task.owner.clone().unwrap_or_default(),
            task.task.fencing_token,
            progress,
            now,
        )?;
        if !accepted {
            return Err(QueueError::StaleFence(format!(
                "the task {} was taken over by another worker",
                task.task.task_id
            )));
        }
        Ok(())
    }

    /// Finish a task the caller still owns.
    pub fn complete_task(&self, task: &ClaimedTask, result_ref: &str, now: u64) -> QueueResult<()> {
        self.require(Feature::DurableTasks)?;
        let accepted = self.tasks.complete_task(
            &task.task.task_id,
            &task.task.owner.clone().unwrap_or_default(),
            task.task.fencing_token,
            result_ref,
            now,
        )?;
        if !accepted {
            return Err(QueueError::StaleFence(format!(
                "the task {} was taken over by another worker",
                task.task.task_id
            )));
        }
        Ok(())
    }

    /// Fail a task the caller still owns.
    pub fn fail_task(&self, task: &ClaimedTask, now: u64) -> QueueResult<()> {
        self.require(Feature::DurableTasks)?;
        let accepted = self.tasks.fail_task(
            &task.task.task_id,
            &task.task.owner.clone().unwrap_or_default(),
            task.task.fencing_token,
            now,
        )?;
        if !accepted {
            return Err(QueueError::StaleFence(format!(
                "the task {} was taken over by another worker",
                task.task.task_id
            )));
        }
        Ok(())
    }

    /// The payloads of the items that are still in flight.
    fn pending_blobs(&self, identities: &[String]) -> QueueResult<Vec<mail_storage::PendingBlob>> {
        let mut pending = Vec::new();
        for identity in identities {
            for submission in self.submissions.list_by_identity(identity)? {
                if submission.state.is_terminal() {
                    continue;
                }
                pending.push(mail_storage::PendingBlob {
                    account: account_of(&submission.identity),
                    key: payload_key_for_submission(&submission.id),
                });
            }
        }
        Ok(pending)
    }

    /// Read the payload of an item and check it against its digest.
    fn load_payload(&self, submission: &Submission) -> QueueResult<Option<Vec<u8>>> {
        let Some(expected) = &submission.payload_digest else {
            return Ok(None);
        };
        let account = account_of(&submission.identity);
        let key = payload_key_for_submission(&submission.id);
        let Some(bytes) = self.payloads.read(&account, &key)? else {
            return Err(QueueError::Invalid(
                "the queued payload is missing, so the message cannot be sent".to_owned(),
            ));
        };
        if digest_of(&bytes) != *expected {
            return Err(QueueError::Invalid(
                "the queued payload does not match its digest".to_owned(),
            ));
        }
        Ok(Some(bytes))
    }

    /// Move a claimed item to a terminal state and remove its payload.
    fn terminate(
        &self,
        item: &ClaimedItem,
        state: SubmissionState,
        failure_code: Option<&str>,
        now: u64,
    ) -> QueueResult<()> {
        match self.submissions.release_claim(
            &item.submission.id,
            item.submission.fencing_token,
            state,
            now,
            failure_code.map(str::to_owned),
        ) {
            Ok(_) => {}
            Err(StorageError::Conflict(_)) => {
                // The claim was taken over: the write is refused, and the
                // new owner is the one that cleans the payload up.
                return Err(QueueError::StaleFence(format!(
                    "the submission {} was taken over by another worker",
                    item.submission.id
                )));
            }
            Err(error) => return Err(error.into()),
        }
        self.payloads.discard(
            &account_of(&item.submission.identity),
            &payload_key_for_submission(&item.submission.id),
        )?;
        let _ = item.lease.release(self.mailbox);
        Ok(())
    }
}

/// The digest of a payload.
fn digest_of(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// A new opaque identifier.
fn new_id() -> QueueResult<String> {
    Ok(hex::encode(mail_storage::crypto::random_bytes(16)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::BlobPayloadStore;
    use mail_storage::{EncryptedDirectoryBlobStore, SqliteStore};

    #[derive(Debug)]
    struct Accepting;

    impl SubmissionExecutor for Accepting {
        fn dispatch(
            &self,
            _submission: &Submission,
            _payload: Option<&[u8]>,
        ) -> Result<(), TransportError> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct FixedAuthority {
        outcome: AuthorizationOutcome,
    }

    impl Authority for FixedAuthority {
        fn authorize(&self, _request: &AuthorizationRequest) -> AuthorizationOutcome {
            self.outcome.clone()
        }
    }

    fn engine<'a>(
        features: QueueFeatures,
        store: &'a SqliteStore,
        payloads: &'a BlobPayloadStore<EncryptedDirectoryBlobStore>,
    ) -> QueueEngine<'a> {
        QueueEngine::new(features, store, store, store, payloads)
    }

    fn payloads(name: &str) -> BlobPayloadStore<EncryptedDirectoryBlobStore> {
        let directory = std::env::temp_dir().join(format!("corvi-queue-engine-{name}"));
        let _ = std::fs::remove_dir_all(&directory);
        BlobPayloadStore::new(
            EncryptedDirectoryBlobStore::open(directory, b"a wrapping key long enough").unwrap(),
        )
    }

    #[test]
    fn a_disabled_queue_refuses_to_queue_anything() {
        let store = SqliteStore::open_in_memory().unwrap();
        let payloads = payloads("disabled");
        let engine = engine(QueueFeatures::none(), &store, &payloads);
        let error = engine
            .enqueue(
                QueueRequest::new("alice", "alice@example.test", "client"),
                100,
            )
            .unwrap_err();
        assert_eq!(error, QueueError::FeatureDisabled(Feature::DurableQueue));
        assert!(
            store
                .list_by_identity("alice@example.test")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn a_permitted_item_is_accepted_and_its_payload_removed() {
        let store = SqliteStore::open_in_memory().unwrap();
        let payloads = payloads("accepted");
        let engine = engine(
            QueueFeatures::none().with_durable_queue(true),
            &store,
            &payloads,
        );
        let queued = engine
            .enqueue(
                QueueRequest::new("alice", "alice@example.test", "client")
                    .with_payload(b"the body".to_vec()),
                100,
            )
            .unwrap();
        let item = engine.claim_next("worker", 110, 60).unwrap().unwrap();
        let outcome = engine
            .execute(
                &item,
                &Accepting,
                &FixedAuthority {
                    outcome: AuthorizationOutcome::Permitted {
                        grant_generation: 3,
                    },
                },
                120,
                60,
            )
            .unwrap();
        assert_eq!(
            outcome,
            ExecutionOutcome::Accepted {
                grant_generation: 3
            }
        );
        let submission = store.get_submission(&queued.id).unwrap().unwrap();
        assert_eq!(submission.state, SubmissionState::Accepted);
        assert_eq!(
            payloads
                .read(
                    &account_of("alice@example.test"),
                    &payload_key_for_submission(&queued.id)
                )
                .unwrap(),
            None
        );
    }

    #[test]
    fn a_refused_item_is_not_dispatched() {
        let store = SqliteStore::open_in_memory().unwrap();
        let payloads = payloads("refused");
        let engine = engine(
            QueueFeatures::none().with_durable_queue(true),
            &store,
            &payloads,
        );
        let queued = engine
            .enqueue(
                QueueRequest::new("alice", "alice@example.test", "client"),
                100,
            )
            .unwrap();
        let item = engine.claim_next("worker", 110, 60).unwrap().unwrap();
        let outcome = engine
            .execute(
                &item,
                &Accepting,
                &FixedAuthority {
                    outcome: AuthorizationOutcome::Refused {
                        reason: "the grant was revoked".to_owned(),
                    },
                },
                120,
                60,
            )
            .unwrap();
        assert!(matches!(outcome, ExecutionOutcome::Refused { .. }));
        let submission = store.get_submission(&queued.id).unwrap().unwrap();
        assert_eq!(submission.state, SubmissionState::Failed);
        assert_eq!(
            submission.failure_code.as_deref(),
            Some("authorization_revoked")
        );
    }

    #[test]
    fn a_stale_worker_cannot_finish_the_item() {
        let store = SqliteStore::open_in_memory().unwrap();
        let payloads = payloads("stale");
        let engine = engine(
            QueueFeatures::none().with_durable_queue(true),
            &store,
            &payloads,
        );
        engine
            .enqueue(
                QueueRequest::new("alice", "alice@example.test", "client"),
                100,
            )
            .unwrap();
        let first = engine.claim_next("worker-one", 110, 60).unwrap().unwrap();
        // The lease of the first worker expires and the second worker takes
        // the item over.
        let second = engine.claim_next("worker-two", 200, 60).unwrap().unwrap();
        let error = engine
            .execute(
                &first,
                &Accepting,
                &FixedAuthority {
                    outcome: AuthorizationOutcome::Permitted {
                        grant_generation: 1,
                    },
                },
                210,
                60,
            )
            .unwrap_err();
        assert!(matches!(error, QueueError::StaleFence(_)));
        let submission = store
            .get_submission(&second.submission.id)
            .unwrap()
            .unwrap();
        assert_eq!(submission.state, SubmissionState::Reserved);
    }

    #[test]
    fn a_dispatched_item_is_recovered_as_unknown() {
        let store = SqliteStore::open_in_memory().unwrap();
        let payloads = payloads("recover");
        let engine = engine(
            QueueFeatures::none().with_durable_queue(true),
            &store,
            &payloads,
        );
        let queued = engine
            .enqueue(
                QueueRequest::new("alice", "alice@example.test", "client"),
                100,
            )
            .unwrap();
        let item = engine.claim_next("worker", 110, 60).unwrap().unwrap();
        store
            .transition(&queued.id, SubmissionState::Submitted, 115, None)
            .unwrap();
        let report = engine
            .recover(&["alice@example.test".to_owned()], 200)
            .unwrap();
        assert_eq!(report.marked_unknown, 1);
        let submission = store.get_submission(&queued.id).unwrap().unwrap();
        assert_eq!(submission.state, SubmissionState::Unknown);
        assert_eq!(item.submission.state, SubmissionState::Reserved);
    }

    #[test]
    fn a_clean_rejection_stays_failed_after_a_restart() {
        let store = SqliteStore::open_in_memory().unwrap();
        let payloads = payloads("rejected");
        let engine = engine(
            QueueFeatures::none().with_durable_queue(true),
            &store,
            &payloads,
        );
        let queued = engine
            .enqueue(
                QueueRequest::new("alice", "alice@example.test", "client"),
                100,
            )
            .unwrap();
        store
            .transition(
                &queued.id,
                SubmissionState::Rejected,
                115,
                Some("upstream_rejected".to_owned()),
            )
            .unwrap();
        let report = engine
            .recover(&["alice@example.test".to_owned()], 200)
            .unwrap();
        assert_eq!(report.kept_failed, 1);
        assert_eq!(report.marked_unknown, 0);
        let submission = store.get_submission(&queued.id).unwrap().unwrap();
        assert_eq!(submission.state, SubmissionState::Rejected);
    }

    #[test]
    fn a_task_is_only_scheduled_when_tasks_are_enabled() {
        let store = SqliteStore::open_in_memory().unwrap();
        let payloads = payloads("tasks");
        let engine = engine(QueueFeatures::none(), &store, &payloads);
        let error = engine
            .schedule_task(
                TaskRequest::new("task-1", "alice", "alice@example.test"),
                100,
            )
            .unwrap_err();
        assert_eq!(error, QueueError::FeatureDisabled(Feature::DurableTasks));
        assert!(store.list_tasks(None).unwrap().is_empty());
    }

    #[test]
    fn a_running_task_is_requeued_after_a_restart() {
        let store = SqliteStore::open_in_memory().unwrap();
        let payloads = payloads("task-recover");
        let engine = engine(
            QueueFeatures::none().with_durable_tasks(true),
            &store,
            &payloads,
        );
        engine
            .schedule_task(
                TaskRequest::new("task-1", "alice", "alice@example.test"),
                100,
            )
            .unwrap();
        engine.claim_task("task-1", "worker", 110).unwrap();
        let report = engine.recover(&[], 200).unwrap();
        assert_eq!(report.tasks_requeued, 1);
        let task = store.get_task("task-1").unwrap().unwrap();
        assert_eq!(task.state, TaskState::Pending);
        assert_eq!(task.owner, None);
    }
}
