//! Corvi's optional durable queue, tasks and filtered synchronization.
//!
//! This crate is the data plane's operational half of ADR-0010. It holds
//! the machinery for three things that ADR-0010 calls "explicit
//! feature-dependent commitments" rather than mandatory background
//! infrastructure:
//!
//! - a **durable submission queue** with idempotent reservations, fenced
//!   ownership, reauthorization and restart recovery,
//! - **durable tasks** whose handle is persisted before a caller is told
//!   that it may wait for the task,
//! - **filtered synchronization** that never mentions a message the
//!   disclosure policy hides.
//!
//! Four rules hold everywhere in this crate, and they are the reason the
//! crate is shaped the way it is.
//!
//! 1. **Everything is opt-in.** The queue, the tasks, the synchronization
//!    and the content cache are off unless a deployment switches them on.
//!    A disabled feature is *reported* as unavailable, never silently
//!    ignored, so a caller cannot mistake "nothing happened" for "the work
//!    was scheduled".
//! 2. **No inbound raw mail by default.** Nothing in this crate stores a
//!    message body, its headers or its attachment bytes unless the
//!    encrypted cache is explicitly enabled. What synchronization persists
//!    by default is a cursor.
//! 3. **The storage layer owns the durable state.** The submission store,
//!    the task store, the mailbox state store and the blob store are the
//!    owners; this crate refers to them. It holds no second source of
//!    truth for operator or provider management state, and it does not own
//!    a database of its own.
//! 4. **Fail closed.** An ambiguous ownership, a missing payload, a stale
//!    fence and a revoked grant all end in a refusal, never in a guess.
//!
//! What this crate does **not** contain, and what a caller has to supply:
//!
//! - **No scheduler and no broker.** Nothing here wakes a worker up or
//!   hands work between processes. [`QueueEngine::claim_next`] is the seam
//!   a scheduler polls; the lease and the fencing token are the seam a
//!   broker would have to respect.
//! - **No transport.** [`queue::SubmissionExecutor`] is the seam where the
//!   SMTP or JMAP transport attaches; the queue never opens a connection.
//! - **No synchronization loop.** [`sync::SyncEngine::sync_once`] performs
//!   one pass; the timer, the transport adapter and the delivery of a
//!   notification are the caller's.
//! - **No operator state.** The authority behind a queued item is asked
//!   through [`authority::Authority`], and the disclosure policy is
//!   supplied through [`sync::DisclosureGate`]. The queue can refer to
//!   both and can own neither.
//!
//! ```
//! use mail_queue::{Feature, QueueError, QueueFeatures, QueueRequest};
//! # use mail_storage::SqliteStore;
//! # let store = SqliteStore::open_in_memory().unwrap();
//! # let directory = std::env::temp_dir().join("corvi-queue-doctest");
//! # let _ = std::fs::remove_dir_all(&directory);
//! # let blobs = mail_storage::EncryptedDirectoryBlobStore::open(directory, b"a wrapping key long enough").unwrap();
//! # let payloads = mail_queue::BlobPayloadStore::new(blobs);
//! let engine = mail_queue::QueueEngine::new(
//!     QueueFeatures::default(),
//!     &store,
//!     &store,
//!     &store,
//!     &payloads,
//! );
//! let error = engine
//!     .enqueue(QueueRequest::new("alice", "alice@example.test", "client"), 100)
//!     .unwrap_err();
//! assert_eq!(error, QueueError::FeatureDisabled(Feature::DurableQueue));
//! ```

pub mod authority;
pub mod cache;
pub mod config;
pub mod error;
pub mod fence;
pub mod payload;
pub mod queue;
pub mod sync;

pub use authority::{Authority, AuthorizationOutcome, AuthorizationRequest, GrantAuthority};
pub use cache::{CacheEntry, ContentCache, EncryptedContentCache, MAX_CACHED_CONTENT_BYTES};
pub use config::{CachePolicy, Feature, QueueFeatures};
pub use error::{QueueError, QueueResult};
pub use fence::{FencedLease, lease_name_for_submission, lease_name_for_sync};
pub use payload::{
    BlobPayloadStore, PayloadStore, account_of, cache_key_for_message, payload_key_for_submission,
};
pub use queue::{
    ClaimedItem, ClaimedTask, ExecutionOutcome, MAX_QUEUED_PAYLOAD_BYTES, PAYLOAD_TTL_SECONDS,
    QueueEngine, QueueRequest, QueuedItem, RecoveryReport, SubmissionExecutor, SweepReport,
    TaskHandle, TaskRequest,
};
pub use sync::{
    ChangeSource, Disclosure, DisclosureGate, EventSink, Notifier, PolicyGate, SyncEngine,
    SyncEvent, SyncRequest, SyncRun,
};
