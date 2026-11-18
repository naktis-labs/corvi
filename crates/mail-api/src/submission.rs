//! Outgoing submissions and idempotency replay suppression.
//!
//! ADR-0005 requires that a stable idempotency key binds principal,
//! identity and canonical payload, that a replay returns the existing
//! submission, and that the same key with a different payload is a conflict.
//! This module holds both the submission records and the replay table.
//!
//! The store is in memory, so `idempotencyDurable` is `false`: replay
//! suppression does not survive a restart. The contract states that
//! explicitly rather than implying a durability the standalone gateway does
//! not have.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::view::{Submission, SubmissionStatus};

/// One recorded submission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmissionRecord {
    /// The opaque submission identifier.
    pub id: String,
    /// The principal that requested the submission.
    pub principal: String,
    /// The identity the message was sent from.
    pub identity: String,
    /// The submission status.
    pub status: SubmissionStatus,
    /// When the submission was created, as a Unix timestamp.
    pub created_at: u64,
    /// When the submission last changed, as a Unix timestamp.
    pub updated_at: u64,
    /// A stable failure code, when the submission did not succeed.
    pub failure_code: Option<String>,
}

impl SubmissionRecord {
    /// The wire projection of this submission.
    pub fn to_view(&self) -> Submission {
        Submission {
            id: self.id.clone(),
            identity_id: self.identity.clone(),
            status: self.status,
            created_at: crate::time::format_rfc3339(self.created_at),
            updated_at: crate::time::format_rfc3339(self.updated_at),
            idempotency_durable: false,
            failure_code: self.failure_code.clone(),
        }
    }
}

/// The replay record of one idempotency key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdempotencyRecord {
    /// The key the caller supplied.
    pub key: String,
    /// The principal that used it.
    pub principal: String,
    /// The identity it was used for.
    pub identity: String,
    /// A digest of the canonical payload.
    pub payload_digest: String,
    /// The submission the key produced.
    pub submission_id: String,
}

/// The in-memory store of submissions and replay records.
#[derive(Debug, Default)]
pub struct SubmissionStore {
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    submissions: HashMap<String, SubmissionRecord>,
    idempotency: HashMap<String, IdempotencyRecord>,
}

/// The result of atomically claiming an idempotency key and submission slot.
#[derive(Debug)]
pub enum Reservation {
    /// The key already belongs to a matching send.
    Existing(SubmissionRecord),
    /// This call created the in-memory submission record.
    Created(String),
}

impl SubmissionStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Take the store's lock.
    ///
    /// A poisoned lock is recovered rather than ignored: every mutation in
    /// this store is a single map update, and `reserve` orders its two
    /// writes so that an interrupted reservation fails closed instead of
    /// leaving a submission without a claim. Ignoring the poison instead
    /// would silently drop writes, and refusing everything would turn one
    /// panicking thread into a permanently dead gateway.
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Look up the replay record of an idempotency key.
    pub fn idempotency_record(
        &self,
        principal: &str,
        identity: &str,
        key: &str,
    ) -> Option<IdempotencyRecord> {
        let state = self.lock();
        state
            .idempotency
            .get(&idempotency_key(principal, identity, key))
            .cloned()
    }

    /// Atomically find an existing idempotency claim or reserve a submission.
    pub fn reserve(
        &self,
        principal: &str,
        identity: &str,
        key: &str,
        payload_digest: &str,
        record: SubmissionRecord,
    ) -> Result<Reservation, crate::problem::Problem> {
        let mut state = self.lock();
        let supplied_key = key.to_owned();
        let key = idempotency_key(principal, identity, key);
        if let Some(existing) = state.idempotency.get(&key) {
            if existing.payload_digest != payload_digest {
                return Err(crate::problem::Problem::idempotency_conflict());
            }
            let submission = state
                .submissions
                .get(&existing.submission_id)
                .cloned()
                .ok_or_else(crate::problem::Problem::internal)?;
            return Ok(Reservation::Existing(submission));
        }
        let id = record.id.clone();
        // The claim is written before the submission it names. If the
        // process dies between the two writes, the claim points at a
        // submission that does not exist, and the next reservation for this
        // key fails closed instead of creating a second submission. The
        // other order would leave an unclaimed submission, which the next
        // reservation would duplicate.
        state.idempotency.insert(
            key,
            IdempotencyRecord {
                key: supplied_key,
                principal: principal.to_owned(),
                identity: identity.to_owned(),
                payload_digest: payload_digest.to_owned(),
                submission_id: id.clone(),
            },
        );
        state.submissions.insert(id.clone(), record);
        Ok(Reservation::Created(id))
    }

    /// Release an idempotency claim after a definite failure.
    ///
    /// A claim is released only when the message was definitely not
    /// delivered, so that the caller may retry with the same key. An
    /// ambiguous outcome keeps the claim: the message may have reached the
    /// upstream, and a retry could deliver it twice.
    ///
    /// The claim is only released when it still carries the digest of the
    /// payload that failed, so a claim that a later attempt already reused
    /// is never withdrawn.
    pub fn release(&self, principal: &str, identity: &str, key: &str, payload_digest: &str) {
        let mut state = self.lock();
        let composite = idempotency_key(principal, identity, key);
        let Some(existing) = state.idempotency.get(&composite) else {
            return;
        };
        if existing.payload_digest != payload_digest {
            return;
        }
        state.idempotency.remove(&composite);
    }

    /// Look up a submission.
    pub fn get(&self, id: &str) -> Option<SubmissionRecord> {
        let state = self.lock();
        state.submissions.get(id).cloned()
    }

    /// Replace the status of a submission.
    pub fn update_status(
        &self,
        id: &str,
        status: SubmissionStatus,
        failure_code: Option<String>,
        now: u64,
    ) {
        let mut state = self.lock();
        if let Some(record) = state.submissions.get_mut(id) {
            record.status = status;
            record.failure_code = failure_code;
            record.updated_at = now;
        }
    }
}

/// The map key under which a replay record is stored.
///
/// The key is scoped to the principal and the identity, so two identities
/// that happen to use the same client-chosen key do not collide and one
/// principal cannot read another principal's receipt.
fn idempotency_key(principal: &str, identity: &str, key: &str) -> String {
    format!("{principal}\u{1f}{identity}\u{1f}{key}")
}
