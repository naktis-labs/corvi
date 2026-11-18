//! Corvi's durable state and secret custody.
//!
//! ADR-0010 splits storage by security and ownership boundary, and this
//! crate is the data plane's half of that split. It holds:
//!
//! - the **grant store** of the OAuth authorization service (clients,
//!   consent, single-use authorization codes, access-token verifiers,
//!   rotating refresh families and revocations),
//! - the **provider connection store** of the data plane's token broker,
//! - the **mailbox state store** (sync checkpoints, opaque identifier
//!   mappings and fenced worker leases),
//! - the **submission store** (idempotency reservations, the submission
//!   state machine and queue ownership),
//! - the **task store** (durable MCP task ownership, progress and results),
//! - the **audit store** (bounded events without content),
//! - the **secret store** (encrypted envelopes under a separately held
//!   wrapping key),
//! - the **blob store** (encrypted, staged objects with a cleanup pass).
//!
//! What this crate does **not** hold:
//!
//! - **No operator state.** The desired state of a provider, a mailbox or
//!   a policy belongs to the Kubernetes CRDs the operator reconciles. This
//!   crate is never a second source of truth for it.
//! - **No inbound raw mail.** The provider's mailbox is the source of
//!   truth for incoming mail. The schema has no table for raw MIME and no
//!   attachment of an incoming message, and the configuration refuses to
//!   ask for one.
//! - **No plaintext secret.** A relational row holds a reference to a
//!   secret; only the secret store can turn that reference back into a
//!   value.
//!
//! The backends are SQLite for one instance and, for now, memory for the
//! ephemeral mode. The PostgreSQL backend that ADR-0010 describes for
//! several replicas is **not implemented**: a configuration that asks for
//! it is refused with a clear message rather than silently degraded, and
//! no claim of multi-replica durability is made.

pub mod audit;
pub mod blob;
pub mod config;
pub mod crypto;
pub mod error;
pub mod grants;
pub mod mailbox;
pub mod migration;
pub mod provider;
pub mod revocation;
pub mod secret;
pub mod sqlite;
pub mod storage;
pub mod submission;
pub mod task;

pub use audit::{AuditEvent, AuditStore};
pub use blob::{
    BlobCleanup, BlobRef, BlobStore, EncryptedDirectoryBlobStore, PendingBlob, StagedBlob,
};
pub use config::{StateBackend, StorageConfig};
pub use error::{StorageError, StorageResult};
pub use grants::{
    AccessToken, AuthCode, Grant, GrantStore, OAuthClient, RefreshFamily, Revocation,
    RevocationKind,
};
pub use mailbox::{Checkpoint, MailboxStateStore, OpaqueId, OpaqueKind, WorkerLease};
pub use provider::{ConnectionStatus, ProviderConnection, ProviderConnectionStore, RefreshState};
pub use revocation::{LedgerEntry, RevocationLedger};
pub use secret::{EncryptedFileSecretStore, SecretAad, SecretRef, SecretStore};
pub use sqlite::SqliteStore;
pub use storage::Storage;
pub use submission::{
    IDEMPOTENCY_RETENTION_SECONDS, IdempotencyReservation, Submission, SubmissionState,
    SubmissionStore,
};
pub use task::{Task, TaskState, TaskStore};
