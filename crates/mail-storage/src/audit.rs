//! The audit store: bounded, access-controlled records of what happened.
//!
//! ADR-0010 asks for "bounded, access-controlled relational audit records
//! or dedicated observability sink, with no content or secret values", and
//! section 7 names the records: authorization and client grant changes,
//! provider connection updates and send outcomes.
//!
//! The type enforces the "no content" rule by construction. An audit event
//! carries identifiers, an action and an outcome; there is no field for a
//! subject line, a sender, a body, a token or a key, so an event cannot
//! carry one by accident.

use crate::error::StorageResult;

/// One audit event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    /// When the event happened.
    pub at: u64,
    /// Who caused it.
    pub actor: String,
    /// What happened.
    pub action: String,
    /// What it happened to.
    pub subject: String,
    /// How it ended.
    pub outcome: String,
}

/// The audit store.
pub trait AuditStore {
    /// Append an event.
    fn append(&self, event: &AuditEvent) -> StorageResult<()>;
    /// List the events after a moment, newest last.
    fn list(&self, since: u64, limit: u32) -> StorageResult<Vec<AuditEvent>>;
    /// Forget the events older than a moment and report how many went.
    fn prune(&self, before: u64) -> StorageResult<usize>;
}
