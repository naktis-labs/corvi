//! The submission store: idempotency, the submission state machine and
//! queue ownership.
//!
//! ADR-0010 section 6 is the contract this module implements:
//!
//! - The intent and the idempotency reservation are persisted
//!   **transactionally before** a queued submission is acknowledged, and
//!   at most one Corvi intent is reserved per key.
//! - The key is scoped to the principal, the client and the identity, and a
//!   reuse with a different payload is a **conflict**, not a new send.
//! - The states are monotonic, and an uncertain send is recorded as
//!   `unknown`: the store never turns an unknown into a failure that
//!   invites a retry, because a retry can deliver the message twice.
//! - Exactly-once upstream delivery is never claimed. A submission that
//!   was issued and whose answer was lost stays unknown until somebody
//!   reconciles it.
//!
//! The retention of an idempotency reservation is at least 24 hours where
//! the API promises it, and the store enforces the promise itself rather
//! than trusting a caller to remember it.

use crate::error::{StorageError, StorageResult};

/// How long an idempotency reservation is kept by default.
///
/// ADR-0010 asks for at least 24 hours wherever the API promises replay
/// suppression, and a shorter window would break that promise quietly.
pub const IDEMPOTENCY_RETENTION_SECONDS: u64 = 24 * 60 * 60;

/// The state of a submission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmissionState {
    /// The intent is recorded and nothing has been sent.
    Reserved,
    /// The submission was issued to the upstream.
    Submitted,
    /// The upstream accepted the message.
    Accepted,
    /// The upstream refused the message.
    Rejected,
    /// The submission failed before it reached the upstream.
    Failed,
    /// The outcome cannot be determined.
    ///
    /// The message may or may not have been delivered. It must not be
    /// resent on the strength of this state.
    Unknown,
}

impl SubmissionState {
    /// The name of the state.
    pub fn as_str(&self) -> &'static str {
        match self {
            SubmissionState::Reserved => "reserved",
            SubmissionState::Submitted => "submitted",
            SubmissionState::Accepted => "accepted",
            SubmissionState::Rejected => "rejected",
            SubmissionState::Failed => "failed",
            SubmissionState::Unknown => "unknown",
        }
    }

    /// Parse a state name.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "reserved" => Some(SubmissionState::Reserved),
            "submitted" => Some(SubmissionState::Submitted),
            "accepted" => Some(SubmissionState::Accepted),
            "rejected" => Some(SubmissionState::Rejected),
            "failed" => Some(SubmissionState::Failed),
            "unknown" => Some(SubmissionState::Unknown),
            _ => None,
        }
    }

    /// Whether the state is a terminal one.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            SubmissionState::Accepted | SubmissionState::Rejected | SubmissionState::Failed
        )
    }

    /// The position of the state in the order the states are moved through.
    ///
    /// A submission is reserved, then submitted, then it reaches an
    /// outcome. The outcomes share a rank: which one it is does not matter
    /// for the order, only that there is no way back.
    pub fn rank(&self) -> u8 {
        match self {
            SubmissionState::Reserved => 0,
            SubmissionState::Submitted => 1,
            SubmissionState::Accepted
            | SubmissionState::Rejected
            | SubmissionState::Failed
            | SubmissionState::Unknown => 2,
        }
    }

    /// Whether a submission may move from this state to `next`.
    ///
    /// The states are monotonic:
    ///
    /// - a submission that has been sent is not sendable again, so it never
    ///   moves back to `reserved`;
    /// - an uncertain send stays uncertain, because the message may have
    ///   been delivered and a retry would deliver it twice;
    /// - a finished submission is not reopened.
    pub fn may_move_to(&self, next: SubmissionState) -> bool {
        if *self == SubmissionState::Unknown {
            return next == SubmissionState::Unknown;
        }
        if self.is_terminal() {
            return false;
        }
        next.rank() >= self.rank()
    }
}

/// One submission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Submission {
    /// The opaque submission identifier.
    pub id: String,
    /// The principal that requested the submission.
    pub principal: String,
    /// The identity the message is sent from.
    pub identity: String,
    /// The client the submission came from.
    pub client_id: String,
    /// The idempotency key, when the caller supplied one.
    pub idempotency_key: Option<String>,
    /// The digest of the canonical payload.
    pub payload_digest: Option<String>,
    /// The state of the submission.
    pub state: SubmissionState,
    /// The upstream protocol the submission was issued over.
    pub upstream_protocol: Option<String>,
    /// How many times the submission was attempted.
    pub attempts: u32,
    /// The worker that holds the claim, when one does.
    pub lease_owner: Option<String>,
    /// When the claim expires.
    pub lease_expires_at: Option<u64>,
    /// The fencing token of the claim.
    pub fencing_token: u64,
    /// When the submission was created.
    pub created_at: u64,
    /// When the submission last changed.
    pub updated_at: u64,
    /// A stable failure code, when the submission did not succeed.
    pub failure_code: Option<String>,
}

/// One idempotency reservation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdempotencyReservation {
    /// The key the caller supplied.
    pub key: String,
    /// The principal that used the key.
    pub principal: String,
    /// The identity the key was used for.
    pub identity: String,
    /// The client the key came from.
    pub client_id: String,
    /// The digest of the canonical payload.
    pub payload_digest: String,
    /// The submission the key produced.
    pub submission_id: String,
    /// When the reservation was made.
    pub created_at: u64,
    /// When the reservation may be forgotten.
    pub expires_at: u64,
}

/// The submission store.
pub trait SubmissionStore {
    /// Atomically persist a new reservation and its submission intent.
    ///
    /// This is the **only** way a keyed submission comes into existence. The
    /// key and the intent are written in one transaction, so a crash or a
    /// competing writer cannot leave a key reserved without a submission, and
    /// cannot create a second submission for a key that already has one.
    ///
    /// A repeated key with the same payload returns the existing intent, so
    /// a retried request does not create a second send. A repeated key with a
    /// different payload is [`StorageError::Conflict`].
    fn reserve_submission(
        &self,
        reservation: &IdempotencyReservation,
        submission: &Submission,
    ) -> StorageResult<Submission>;
    /// Look up an idempotency reservation that has not expired.
    fn lookup_idempotency(
        &self,
        principal: &str,
        client_id: &str,
        identity: &str,
        key: &str,
        now: u64,
    ) -> StorageResult<Option<IdempotencyReservation>>;
    /// Store a submission that carries no idempotency key.
    ///
    /// A submission with a key is created by [`Self::reserve_submission`],
    /// because the key and the intent have to be written together. An
    /// existing submission is never overwritten: the state machine moves
    /// forward through [`Self::transition`] and the claim operations, so a
    /// second write cannot roll a finished submission back to a sendable
    /// state.
    fn put_submission(&self, submission: &Submission) -> StorageResult<()>;
    /// Look up a submission.
    fn get_submission(&self, id: &str) -> StorageResult<Option<Submission>>;
    /// Move a submission to a new state.
    fn transition(
        &self,
        id: &str,
        state: SubmissionState,
        now: u64,
        failure_code: Option<String>,
    ) -> StorageResult<Submission>;
    /// List the submissions whose outcome is unknown.
    ///
    /// These are the submissions that need reconciliation: they may have
    /// been delivered.
    fn list_unknown(&self) -> StorageResult<Vec<Submission>>;
    /// List the submissions of one identity.
    fn list_by_identity(&self, identity: &str) -> StorageResult<Vec<Submission>>;
    /// Claim the next submission that is waiting to be sent.
    fn claim_next(&self, owner: &str, now: u64, ttl: u64) -> StorageResult<Option<Submission>>;
    /// Release a claimed submission, recording the outcome.
    fn release_claim(
        &self,
        id: &str,
        fencing_token: u64,
        state: SubmissionState,
        now: u64,
        failure_code: Option<String>,
    ) -> StorageResult<Submission>;
    /// Forget the idempotency reservations that have expired.
    fn purge_expired_idempotency(&self, now: u64) -> StorageResult<usize>;
}

/// The scope key under which an idempotency reservation is stored.
///
/// The key is scoped to the principal, the client and the identity, so two
/// identities that happen to use the same client-chosen key do not collide
/// and one principal cannot read another principal's receipt.
pub fn idempotency_scope(principal: &str, client_id: &str, identity: &str, key: &str) -> String {
    format!("{principal}\u{1f}{client_id}\u{1f}{identity}\u{1f}{key}")
}

/// Check that a reservation may be made.
///
/// The digest is what binds the key to a payload: the same key with a
/// different payload is a conflict, because it is either a mistake or an
/// attempt to make one key stand for two sends.
pub fn check_reservation(
    existing: Option<&IdempotencyReservation>,
    wanted: &IdempotencyReservation,
) -> StorageResult<()> {
    let Some(existing) = existing else {
        return Ok(());
    };
    if existing.payload_digest != wanted.payload_digest {
        return Err(StorageError::Conflict(
            "the idempotency key was already used with a different payload".to_owned(),
        ));
    }
    Ok(())
}
