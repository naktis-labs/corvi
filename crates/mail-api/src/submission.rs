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

impl SubmissionStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up the replay record of an idempotency key.
    pub fn idempotency_record(
        &self,
        principal: &str,
        identity: &str,
        key: &str,
    ) -> Option<IdempotencyRecord> {
        let state = self.state.lock().ok()?;
        state
            .idempotency
            .get(&idempotency_key(principal, identity, key))
            .cloned()
    }

    /// Record that an idempotency key produced a submission.
    pub fn record_idempotency(
        &self,
        principal: &str,
        identity: &str,
        key: &str,
        payload_digest: &str,
        submission_id: &str,
    ) {
        if let Ok(mut state) = self.state.lock() {
            state.idempotency.insert(
                idempotency_key(principal, identity, key),
                IdempotencyRecord {
                    key: key.to_owned(),
                    principal: principal.to_owned(),
                    identity: identity.to_owned(),
                    payload_digest: payload_digest.to_owned(),
                    submission_id: submission_id.to_owned(),
                },
            );
        }
    }

    /// Store a submission.
    pub fn insert(&self, record: SubmissionRecord) {
        if let Ok(mut state) = self.state.lock() {
            state.submissions.insert(record.id.clone(), record);
        }
    }

    /// Look up a submission.
    pub fn get(&self, id: &str) -> Option<SubmissionRecord> {
        let state = self.state.lock().ok()?;
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
        if let Ok(mut state) = self.state.lock() {
            if let Some(record) = state.submissions.get_mut(id) {
                record.status = status;
                record.failure_code = failure_code;
                record.updated_at = now;
            }
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
