//! The mailbox state store: sync cursors, opaque identifiers and leases.
//!
//! ADR-0010 lists three things under "message sync state": IMAP
//! UIDVALIDITY/UID pairs, JMAP account state tokens, and the opaque
//! identifier mappings that let a caller hold a stable handle on an
//! upstream object.
//!
//! The opaque mapping is the security-relevant part of this module. An
//! opaque identifier is scoped to the identity that owns it, and the
//! lookup takes that identity. A public identifier from one identity
//! therefore cannot be resolved against another identity's upstream
//! objects, which is what stops a cross-principal leak through an
//! identifier that happened to be shared.
//!
//! The lease is fenced. Every acquisition increases a fencing token, and a
//! worker whose token is stale cannot renew, complete or release the
//! lease. A worker that was paused long enough to lose its lease cannot
//! come back and write over the work of the worker that took over.

use crate::error::StorageResult;

/// What an opaque identifier stands for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpaqueKind {
    /// A message.
    Message,
    /// An attachment.
    Attachment,
    /// A submission.
    Submission,
}

impl OpaqueKind {
    /// The name of the kind.
    pub fn as_str(&self) -> &'static str {
        match self {
            OpaqueKind::Message => "message",
            OpaqueKind::Attachment => "attachment",
            OpaqueKind::Submission => "submission",
        }
    }

    /// Parse a kind name.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "message" => Some(OpaqueKind::Message),
            "attachment" => Some(OpaqueKind::Attachment),
            "submission" => Some(OpaqueKind::Submission),
            _ => None,
        }
    }
}

/// The synchronization state of one mailbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    /// The identity the mailbox belongs to.
    pub identity: String,
    /// The mailbox name.
    pub mailbox: String,
    /// The upstream cursor: a UIDVALIDITY/UID pair, a JMAP state token, or
    /// whatever else the transport uses.
    pub upstream_cursor: String,
    /// The generation of the checkpoint.
    pub generation: u64,
    /// When the checkpoint was written.
    pub updated_at: u64,
}

/// One opaque identifier mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpaqueId {
    /// The identity that owns the object.
    pub identity: String,
    /// What the object is.
    pub kind: OpaqueKind,
    /// The public identifier.
    pub public_id: String,
    /// The upstream identifier, which never leaves the transport.
    pub upstream_id: String,
}

/// A lease on a unit of work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerLease {
    /// The name of the leased resource.
    pub name: String,
    /// The owner of the lease.
    pub owner: String,
    /// The fencing token; it increases on every acquisition.
    pub fencing_token: u64,
    /// When the lease expires.
    pub expires_at: u64,
}

/// The mailbox state store.
pub trait MailboxStateStore {
    /// Store a checkpoint.
    fn put_checkpoint(&self, checkpoint: &Checkpoint) -> StorageResult<()>;
    /// Look up a checkpoint.
    fn get_checkpoint(&self, identity: &str, mailbox: &str) -> StorageResult<Option<Checkpoint>>;
    /// Store an opaque identifier mapping.
    fn put_opaque_id(&self, mapping: &OpaqueId) -> StorageResult<()>;
    /// Resolve an opaque identifier for one identity.
    ///
    /// The identity is part of the lookup, so an identifier that belongs to
    /// another identity resolves to nothing.
    fn lookup_opaque_id(
        &self,
        identity: &str,
        kind: OpaqueKind,
        public_id: &str,
    ) -> StorageResult<Option<String>>;
    /// Resolve the public identifier an upstream identifier already has
    /// for one identity.
    ///
    /// This is the reverse of [`Self::lookup_opaque_id`]: the caller holds
    /// the upstream identifier and asks for the stable public handle that
    /// was minted for it, so the same upstream object keeps one public
    /// identifier instead of collecting a new one on every observation.
    ///
    /// The default finds nothing, which sends the caller down the
    /// mint-a-new-identifier path: a store that cannot answer in reverse
    /// keeps working, it only never reuses an identifier.
    fn lookup_public_id(
        &self,
        _identity: &str,
        _kind: OpaqueKind,
        _upstream_id: &str,
    ) -> StorageResult<Option<String>> {
        Ok(None)
    }
    /// Acquire a lease, fencing off any earlier owner.
    fn acquire_lease(
        &self,
        name: &str,
        owner: &str,
        now: u64,
        ttl: u64,
    ) -> StorageResult<WorkerLease>;
    /// Renew a lease the caller still holds.
    fn renew_lease(
        &self,
        name: &str,
        owner: &str,
        fencing_token: u64,
        now: u64,
        ttl: u64,
    ) -> StorageResult<bool>;
    /// Release a lease.
    fn release_lease(&self, name: &str, fencing_token: u64) -> StorageResult<bool>;
}
