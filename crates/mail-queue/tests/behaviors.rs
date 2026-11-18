//! The behaviours the optional queue, tasks and synchronization promise.
//!
//! Each test below is one requirement of Task 12 of the implementation
//! plan, and each uses the real storage layer rather than a fake: a SQLite
//! store, an encrypted blob store and the queue's own seams. The fakes
//! here are only the seams that a deployment supplies — the transport, the
//! authority, the event sink and the notification sink.

use std::path::{Path, PathBuf};

use mail_core::{
    Action, Change, ChangeCursor, ChangeKind, ChangeSet, IdentityGrant, IdentityId, MailboxRef,
    MessageId, ScopedGrants, TransportError, UntrustedMessage,
};
use mail_policy::{
    BooleanOp, DefaultVisibility, FilterPolicy, OnIndeterminate, Predicate, Rendering, Rule,
    RuleEffect, SubjectField, TextMatch, TextPredicate, Visibility,
};
use mail_queue::{
    Authority, AuthorizationOutcome, AuthorizationRequest, BlobPayloadStore, CachePolicy,
    ChangeSource, ContentCache, EncryptedContentCache, EventSink, ExecutionOutcome, Feature,
    FencedLease, GrantAuthority, Notifier, PayloadStore, PolicyGate, QueueEngine, QueueFeatures,
    QueueRequest, SubmissionExecutor, SyncEngine, SyncEvent, SyncRequest, account_of,
    cache_key_for_message, payload_key_for_submission,
};
use mail_storage::{
    BlobStore, EncryptedDirectoryBlobStore, GrantStore, MailboxStateStore, ProviderConnectionStore,
    SqliteStore, StorageResult, Submission, SubmissionState, SubmissionStore, TaskStore,
};

/// A directory that is removed when it is dropped.
struct Scratch {
    path: PathBuf,
}

impl Scratch {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("corvi-queue-behaviour-{name}"));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("the scratch directory is created");
        Self { path }
    }

    fn child(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// The wrapping key of the test stores.
const KEY: &[u8] = b"a wrapping key long enough";

/// A blob store in a scratch directory.
fn blobs(scratch: &Scratch) -> EncryptedDirectoryBlobStore {
    EncryptedDirectoryBlobStore::open(scratch.child("blobs"), KEY).expect("the blob store opens")
}

/// Every byte that the store wrote to disk.
fn persisted_bytes(scratch: &Scratch) -> Vec<u8> {
    let mut bytes = Vec::new();
    for entry in walk(scratch.path.as_path()) {
        if let Ok(content) = std::fs::read(&entry) {
            bytes.extend_from_slice(&content);
        }
    }
    bytes
}

/// Every file under a directory.
fn walk(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return files;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            files.extend(walk(&path));
        } else {
            files.push(path);
        }
    }
    files
}

/// Whether the bytes contain a needle.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty()
        || haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// An executor that records what it was asked to send.
#[derive(Debug, Default)]
struct RecordingExecutor {
    dispatched: std::cell::RefCell<Vec<Vec<u8>>>,
    failure: Option<TransportError>,
}

impl RecordingExecutor {
    fn accepting() -> Self {
        Self::default()
    }

    fn failing(error: TransportError) -> Self {
        Self {
            dispatched: std::cell::RefCell::new(Vec::new()),
            failure: Some(error),
        }
    }

    /// What the executor was asked to send.
    fn dispatched(&self) -> Vec<Vec<u8>> {
        self.dispatched.borrow().clone()
    }
}

impl SubmissionExecutor for RecordingExecutor {
    fn dispatch(
        &self,
        _submission: &Submission,
        payload: Option<&[u8]>,
    ) -> Result<(), TransportError> {
        let mut recorded = Vec::new();
        if let Some(bytes) = payload {
            recorded.extend_from_slice(bytes);
        }
        self.dispatched.borrow_mut().push(recorded);
        match &self.failure {
            Some(error) => Err(error.clone()),
            None => Ok(()),
        }
    }
}

/// An authority that always answers the same way.
#[derive(Debug)]
struct FixedAuthority {
    outcome: AuthorizationOutcome,
    asked: std::cell::RefCell<Vec<AuthorizationRequest>>,
}

impl FixedAuthority {
    fn permitting(grant_generation: u64) -> Self {
        Self {
            outcome: AuthorizationOutcome::Permitted { grant_generation },
            asked: std::cell::RefCell::new(Vec::new()),
        }
    }

    fn refusing(reason: &str) -> Self {
        Self {
            outcome: AuthorizationOutcome::Refused {
                reason: reason.to_owned(),
            },
            asked: std::cell::RefCell::new(Vec::new()),
        }
    }
}

impl Authority for FixedAuthority {
    fn authorize(&self, request: &AuthorizationRequest) -> AuthorizationOutcome {
        self.asked.borrow_mut().push(request.clone());
        self.outcome.clone()
    }
}

/// A change source that replays a fixed script.
#[derive(Debug)]
struct ScriptedSource {
    changes: Vec<Change>,
    messages: Vec<UntrustedMessage>,
}

impl ScriptedSource {
    fn new(changes: Vec<Change>, messages: Vec<UntrustedMessage>) -> Self {
        Self { changes, messages }
    }
}

impl ChangeSource for ScriptedSource {
    fn changes_since(
        &mut self,
        _mailbox: &MailboxRef,
        cursor: Option<&str>,
    ) -> Result<ChangeSet, TransportError> {
        let token = match cursor {
            Some(cursor) => format!("{cursor}+"),
            None => "cursor-1".to_owned(),
        };
        Ok(ChangeSet {
            changes: self.changes.clone(),
            next_cursor: Some(ChangeCursor { token }),
        })
    }

    fn message(
        &mut self,
        _mailbox: &MailboxRef,
        id: &MessageId,
    ) -> Result<UntrustedMessage, TransportError> {
        self.messages
            .iter()
            .find(|message| &message.id == id)
            .cloned()
            .ok_or(TransportError::NotFound)
    }
}

/// A sink that records what it was given.
#[derive(Debug, Default)]
struct Recorder {
    events: Vec<SyncEvent>,
}

impl EventSink for Recorder {
    fn publish(&mut self, event: &SyncEvent) -> mail_queue::QueueResult<()> {
        self.events.push(event.clone());
        Ok(())
    }
}

impl Notifier for Recorder {
    fn notify(&mut self, event: &SyncEvent) -> mail_queue::QueueResult<()> {
        self.events.push(event.clone());
        Ok(())
    }
}

/// A message with a distinctive body.
fn message(id: &str, subject: &str, body: &str) -> UntrustedMessage {
    UntrustedMessage {
        id: MessageId::new(id),
        mailbox: MailboxRef::new("INBOX"),
        from: Some(mail_core::Address::new("sender@example.test")),
        reply_to: Vec::new(),
        to: vec![mail_core::Address::new("alice@example.test")],
        cc: Vec::new(),
        subject: Some(subject.to_owned()),
        text_body: Some(body.to_owned()),
        html_body: Some("<p>the body</p>".to_owned()),
        attachments: vec![mail_core::AttachmentMeta {
            id: "part-1".to_owned(),
            filename: Some("statement.pdf".to_owned()),
            content_type: Some("application/pdf".to_owned()),
            size: 4096,
            inline: false,
        }],
        flags: Vec::new(),
        date: None,
        provenance: Default::default(),
    }
}

/// A policy that hides the messages whose subject contains a marker.
fn marker_policy(marker: &str) -> FilterPolicy {
    FilterPolicy {
        id: "hide-marker".to_owned(),
        default_visibility: DefaultVisibility::Show,
        on_indeterminate: OnIndeterminate::Hide,
        rendering: Rendering::default(),
        rules: vec![Rule {
            id: "hide-marker".to_owned(),
            predicate: Predicate::Boolean {
                op: BooleanOp::All,
                operands: vec![Predicate::Text(TextPredicate {
                    field: SubjectField::Subject,
                    comparison: TextMatch::Contains,
                    value: marker.to_owned(),
                    case_insensitive: true,
                })],
            },
            effect: RuleEffect::Visibility {
                value: Visibility::Hide,
            },
        }],
    }
}

/// The features of a deployment that opted into everything but the cache.
fn everything_but_the_cache() -> QueueFeatures {
    QueueFeatures::none()
        .with_durable_queue(true)
        .with_durable_tasks(true)
        .with_persistent_sync(true)
}

/// Behaviour 1: the queue and the tasks are off by default.
#[test]
fn the_queue_and_the_tasks_are_disabled_by_default() {
    let scratch = Scratch::new("opt-in");
    let store = SqliteStore::open_in_memory().unwrap();
    let payloads = BlobPayloadStore::new(blobs(&scratch));
    let engine = QueueEngine::new(QueueFeatures::default(), &store, &store, &store, &payloads);

    let error = engine
        .enqueue(
            QueueRequest::new("alice", "alice@example.test", "client"),
            100,
        )
        .expect_err("a disabled queue refuses to queue anything");
    assert_eq!(
        error,
        mail_queue::QueueError::FeatureDisabled(Feature::DurableQueue)
    );

    let error = engine
        .schedule_task(
            mail_queue::TaskRequest::new("task-1", "alice", "alice@example.test"),
            100,
        )
        .expect_err("a disabled queue refuses to schedule anything");
    assert_eq!(
        error,
        mail_queue::QueueError::FeatureDisabled(Feature::DurableTasks)
    );

    // Nothing was created: the feature is unavailable, not silently idle.
    assert!(
        store
            .list_by_identity("alice@example.test")
            .unwrap()
            .is_empty()
    );
    assert!(store.list_tasks(None).unwrap().is_empty());
    assert!(
        store
            .list_connections("alice@example.test")
            .unwrap()
            .is_empty()
    );
}

/// Behaviour 1: the synchronization engine reports the feature as unavailable.
#[test]
fn a_disabled_synchronization_engine_reports_the_feature_as_unavailable() {
    let scratch = Scratch::new("opt-in-sync");
    let store = SqliteStore::open_in_memory().unwrap();
    let cache = EncryptedContentCache::new(blobs(&scratch), CachePolicy::disabled());
    let engine = SyncEngine::new(QueueFeatures::default(), &store, &cache);
    let policy = marker_policy("secret");
    let gate = PolicyGate::new(&policy);
    let mut source = ScriptedSource::new(Vec::new(), Vec::new());
    let mut events = Recorder::default();
    let mut notifications = Recorder::default();
    let error = engine
        .sync_once(
            SyncRequest {
                identity: "alice@example.test",
                mailbox: &MailboxRef::new("INBOX"),
                owner: "worker",
                now: 100,
                ttl: 60,
            },
            &mut source,
            &gate,
            &mut events,
            &mut notifications,
        )
        .expect_err("a disabled engine refuses to synchronize");
    assert_eq!(
        error,
        mail_queue::QueueError::FeatureDisabled(Feature::PersistentSync)
    );
    assert!(
        store
            .get_checkpoint("alice@example.test", "INBOX")
            .unwrap()
            .is_none()
    );
}

/// Behaviour 2: by default no raw message body, headers or attachments are stored.
#[test]
fn the_default_synchronization_persists_no_raw_mail() {
    let scratch = Scratch::new("no-raw-mail");
    let store = SqliteStore::open(scratch.child("state.db")).unwrap();
    let cache = EncryptedContentCache::new(
        EncryptedDirectoryBlobStore::open(scratch.child("cache-blobs"), KEY).unwrap(),
        CachePolicy::disabled(),
    );
    let engine = SyncEngine::new(
        QueueFeatures::none().with_persistent_sync(true),
        &store,
        &cache,
    );
    let policy = marker_policy("secret");
    let gate = PolicyGate::new(&policy);
    let body = "the very secret body of the message";
    let mut source = ScriptedSource::new(
        vec![Change {
            id: MessageId::new("m-1"),
            kind: ChangeKind::Added,
        }],
        vec![message("m-1", "an ordinary subject", body)],
    );
    let mut events = Recorder::default();
    let mut notifications = Recorder::default();
    engine
        .sync_once(
            SyncRequest {
                identity: "alice@example.test",
                mailbox: &MailboxRef::new("INBOX"),
                owner: "worker",
                now: 100,
                ttl: 60,
            },
            &mut source,
            &gate,
            &mut events,
            &mut notifications,
        )
        .unwrap();

    // The persisted state holds a cursor and nothing else that came from the
    // message.
    let persisted = persisted_bytes(&scratch);
    assert!(
        !contains(&persisted, body.as_bytes()),
        "the body was persisted"
    );
    assert!(
        !contains(&persisted, b"an ordinary subject"),
        "the subject was persisted"
    );
    assert!(
        !contains(&persisted, b"statement.pdf"),
        "the attachment name was persisted"
    );
    assert!(
        !contains(&persisted, b"the body"),
        "the html body was persisted"
    );
    // No message was cached either.
    let objects = cache.blobs().root().join("objects");
    let cached = std::fs::read_dir(&objects)
        .map(|entries| entries.count())
        .unwrap_or(0);
    assert_eq!(cached, 0, "the cache holds an object");
}

/// Behaviour 3: an opted-in cache stores the content encrypted.
#[test]
fn an_opted_in_cache_stores_the_content_encrypted() {
    let scratch = Scratch::new("encrypted-cache");
    let store = SqliteStore::open_in_memory().unwrap();
    let blob_store = EncryptedDirectoryBlobStore::open(scratch.child("cache-blobs"), KEY).unwrap();
    let cache = EncryptedContentCache::new(blob_store, CachePolicy::enabled(600).unwrap());
    let engine = SyncEngine::new(
        QueueFeatures::none()
            .with_persistent_sync(true)
            .with_encrypted_cache(true),
        &store,
        &cache,
    );
    let policy = marker_policy("secret");
    let gate = PolicyGate::new(&policy);
    let body = "the very secret body of the message";
    let mut source = ScriptedSource::new(
        vec![Change {
            id: MessageId::new("m-1"),
            kind: ChangeKind::Added,
        }],
        vec![message("m-1", "an ordinary subject", body)],
    );
    let mut events = Recorder::default();
    let mut notifications = Recorder::default();
    let run = engine
        .sync_once(
            SyncRequest {
                identity: "alice@example.test",
                mailbox: &MailboxRef::new("INBOX"),
                owner: "worker",
                now: 100,
                ttl: 60,
            },
            &mut source,
            &gate,
            &mut events,
            &mut notifications,
        )
        .unwrap();
    assert_eq!(run.cached, 1);

    // The bytes on disk are not the plaintext.
    let objects = cache.blobs().root().join("objects");
    let mut on_disk = Vec::new();
    for entry in std::fs::read_dir(&objects).unwrap().flatten() {
        on_disk.extend_from_slice(&std::fs::read(entry.path()).unwrap());
    }
    assert!(!on_disk.is_empty(), "nothing was cached");
    assert!(
        !contains(&on_disk, body.as_bytes()),
        "the cache is plaintext"
    );
    assert!(
        !contains(&on_disk, b"an ordinary subject"),
        "the cache is plaintext"
    );
}

/// Behaviour 3: the retention window is bounded and expiry removes the entry.
#[test]
fn an_expired_cache_entry_is_removed() {
    let scratch = Scratch::new("cache-expiry");
    let store = SqliteStore::open_in_memory().unwrap();
    let blob_store = EncryptedDirectoryBlobStore::open(scratch.child("cache-blobs"), KEY).unwrap();
    let cache = EncryptedContentCache::new(blob_store, CachePolicy::enabled(600).unwrap());
    let engine = SyncEngine::new(
        QueueFeatures::none()
            .with_persistent_sync(true)
            .with_encrypted_cache(true),
        &store,
        &cache,
    );
    let policy = marker_policy("secret");
    let gate = PolicyGate::new(&policy);
    let mut source = ScriptedSource::new(
        vec![Change {
            id: MessageId::new("m-1"),
            kind: ChangeKind::Added,
        }],
        vec![message("m-1", "an ordinary subject", "the body")],
    );
    let mut events = Recorder::default();
    let mut notifications = Recorder::default();
    engine
        .sync_once(
            SyncRequest {
                identity: "alice@example.test",
                mailbox: &MailboxRef::new("INBOX"),
                owner: "worker",
                now: 100,
                ttl: 60,
            },
            &mut source,
            &gate,
            &mut events,
            &mut notifications,
        )
        .unwrap();
    let message_id = events.events[0].message_id.clone();
    assert!(
        cache
            .load("alice@example.test", &message_id)
            .unwrap()
            .is_some()
    );

    // The window is bounded: a longer one is refused.
    assert!(CachePolicy::enabled(CachePolicy::MAX_RETENTION_SECONDS + 1).is_err());

    // After the window, the entry is gone.
    assert_eq!(cache.purge_expired(500).unwrap(), 0);
    assert_eq!(cache.purge_expired(800).unwrap(), 1);
    assert_eq!(cache.load("alice@example.test", &message_id).unwrap(), None);
    assert_eq!(
        cache
            .blobs()
            .get("alice@example.test", &cache_key_for_message(&message_id))
            .unwrap(),
        None
    );
}

/// Behaviour 4: a worker whose fence is stale must not perform the work.
#[test]
fn a_stale_fence_is_refused() {
    let scratch = Scratch::new("stale-fence");
    let store = SqliteStore::open_in_memory().unwrap();
    let payloads = BlobPayloadStore::new(blobs(&scratch));
    let engine = QueueEngine::new(
        everything_but_the_cache(),
        &store,
        &store,
        &store,
        &payloads,
    );
    let queued = engine
        .enqueue(
            QueueRequest::new("alice", "alice@example.test", "client")
                .with_payload(b"the body of the message".to_vec()),
            100,
        )
        .unwrap();

    let first = engine.claim_next("worker-one", 110, 60).unwrap().unwrap();
    // The lease of the first worker expires and the second worker takes the
    // item over.
    let second = engine.claim_next("worker-two", 200, 60).unwrap().unwrap();
    assert!(second.lease.fencing_token() > first.lease.fencing_token());

    let executor = RecordingExecutor::accepting();
    let error = engine
        .execute(&first, &executor, &FixedAuthority::permitting(1), 210, 60)
        .expect_err("the stale worker is refused");
    assert!(matches!(error, mail_queue::QueueError::StaleFence(_)));
    assert!(
        executor.dispatched().is_empty(),
        "the stale worker dispatched"
    );

    // The item is untouched: the worker that holds the fence may still
    // finish it.
    let submission = store.get_submission(&queued.id).unwrap().unwrap();
    assert_eq!(submission.state, SubmissionState::Reserved);
    let outcome = engine
        .execute(&second, &executor, &FixedAuthority::permitting(1), 220, 60)
        .unwrap();
    assert!(
        matches!(outcome, ExecutionOutcome::Accepted { .. }),
        "the upstream accepted the message, got {outcome:?}"
    );
    assert_eq!(executor.dispatched().len(), 1);
}

/// Behaviour 4: the lease itself fences the previous owner off.
#[test]
fn a_lease_that_was_taken_over_fences_the_previous_owner_off() {
    let store = SqliteStore::open_in_memory().unwrap();
    let first = FencedLease::acquire(&store, "queue/submission/x", "worker-one", 100, 60).unwrap();
    let second = FencedLease::acquire(&store, "queue/submission/x", "worker-two", 110, 60).unwrap();
    let error = first
        .assert_current(&store, 120, 60)
        .expect_err("the previous owner is fenced off");
    assert!(matches!(error, mail_queue::QueueError::StaleFence(_)));
    assert!(second.assert_current(&store, 120, 60).is_ok());
}

/// Behaviour 5: after a restart, a dispatched item is recovered as unknown.
#[test]
fn a_restart_recovers_a_dispatched_item_as_unknown() {
    let scratch = Scratch::new("restart-unknown");
    let database = scratch.child("state.db");
    let store = SqliteStore::open(&database).unwrap();
    let payloads = BlobPayloadStore::new(blobs(&scratch));
    let queued;
    {
        let engine = QueueEngine::new(
            everything_but_the_cache(),
            &store,
            &store,
            &store,
            &payloads,
        );
        queued = engine
            .enqueue(
                QueueRequest::new("alice", "alice@example.test", "client"),
                100,
            )
            .unwrap();
        let _claimed = engine.claim_next("worker", 110, 60).unwrap().unwrap();
        // The worker was dispatched and the process stopped before the
        // outcome was recorded.
        store
            .transition(&queued.id, SubmissionState::Submitted, 115, None)
            .unwrap();
    }
    drop(store);

    // The process comes back.
    let store = SqliteStore::open(&database).unwrap();
    let payloads = BlobPayloadStore::new(blobs(&scratch));
    let engine = QueueEngine::new(
        everything_but_the_cache(),
        &store,
        &store,
        &store,
        &payloads,
    );
    let report = engine
        .recover(&["alice@example.test".to_owned()], 200)
        .unwrap();
    assert_eq!(report.marked_unknown, 1);
    let submission = store.get_submission(&queued.id).unwrap().unwrap();
    assert_eq!(submission.state, SubmissionState::Unknown);
    // The item is not handed out again: an unknown item is never retried on
    // the strength of a guess.
    assert!(engine.claim_next("worker", 210, 60).unwrap().is_none());
}

/// Behaviour 5: a clean rejection stays failed after a restart.
#[test]
fn a_clean_rejection_stays_failed_after_a_restart() {
    let scratch = Scratch::new("restart-rejected");
    let database = scratch.child("state.db");
    let store = SqliteStore::open(&database).unwrap();
    let payloads = BlobPayloadStore::new(blobs(&scratch));
    let queued;
    {
        let engine = QueueEngine::new(
            everything_but_the_cache(),
            &store,
            &store,
            &store,
            &payloads,
        );
        queued = engine
            .enqueue(
                QueueRequest::new("alice", "alice@example.test", "client"),
                100,
            )
            .unwrap();
        let item = engine.claim_next("worker", 110, 60).unwrap().unwrap();
        let executor =
            RecordingExecutor::failing(TransportError::Rejected("no such mailbox".to_owned()));
        let outcome = engine
            .execute(&item, &executor, &FixedAuthority::permitting(1), 120, 60)
            .unwrap();
        assert!(matches!(outcome, ExecutionOutcome::Rejected { .. }));
    }
    drop(store);

    let store = SqliteStore::open(&database).unwrap();
    let payloads = BlobPayloadStore::new(blobs(&scratch));
    let engine = QueueEngine::new(
        everything_but_the_cache(),
        &store,
        &store,
        &store,
        &payloads,
    );
    let report = engine
        .recover(&["alice@example.test".to_owned()], 200)
        .unwrap();
    assert_eq!(report.kept_failed, 1);
    assert_eq!(report.marked_unknown, 0);
    let submission = store.get_submission(&queued.id).unwrap().unwrap();
    assert_eq!(submission.state, SubmissionState::Rejected);
    assert!(engine.claim_next("worker", 210, 60).unwrap().is_none());
}

/// Behaviour 5: work that was never dispatched is recovered, not lost.
#[test]
fn work_that_was_never_dispatched_is_recovered() {
    let scratch = Scratch::new("restart-reserved");
    let database = scratch.child("state.db");
    let store = SqliteStore::open(&database).unwrap();
    let payloads = BlobPayloadStore::new(blobs(&scratch));
    {
        let engine = QueueEngine::new(
            everything_but_the_cache(),
            &store,
            &store,
            &store,
            &payloads,
        );
        engine
            .enqueue(
                QueueRequest::new("alice", "alice@example.test", "client"),
                100,
            )
            .unwrap();
    }
    drop(store);

    let store = SqliteStore::open(&database).unwrap();
    let payloads = BlobPayloadStore::new(blobs(&scratch));
    let engine = QueueEngine::new(
        everything_but_the_cache(),
        &store,
        &store,
        &store,
        &payloads,
    );
    let report = engine
        .recover(&["alice@example.test".to_owned()], 200)
        .unwrap();
    assert_eq!(report.requeued, 1);
    // The item is claimable again: it was never dispatched.
    assert!(engine.claim_next("worker", 210, 60).unwrap().is_some());
}

/// Behaviour 6: a revoked authorization refuses the item.
#[test]
fn a_revoked_authorization_refuses_the_item() {
    let scratch = Scratch::new("revoked");
    let store = SqliteStore::open_in_memory().unwrap();
    let payloads = BlobPayloadStore::new(blobs(&scratch));
    let engine = QueueEngine::new(
        everything_but_the_cache(),
        &store,
        &store,
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
    let executor = RecordingExecutor::accepting();
    let authority = FixedAuthority::refusing("the grant was revoked");
    let outcome = engine
        .execute(&item, &executor, &authority, 120, 60)
        .unwrap();
    assert!(matches!(outcome, ExecutionOutcome::Refused { .. }));
    assert!(executor.dispatched().is_empty(), "the item was dispatched");
    let submission = store.get_submission(&queued.id).unwrap().unwrap();
    assert_eq!(submission.state, SubmissionState::Failed);
    assert_eq!(
        submission.failure_code.as_deref(),
        Some("authorization_revoked")
    );
    // The authority was asked again, not remembered.
    assert_eq!(authority.asked.borrow().len(), 1);
    assert_eq!(authority.asked.borrow()[0].action, Action::Send);
}

/// Behaviour 6: a narrowed authorization refuses the item.
#[test]
fn a_narrowed_authorization_refuses_the_item() {
    let scratch = Scratch::new("narrowed");
    let store = SqliteStore::open_in_memory().unwrap();
    let payloads = BlobPayloadStore::new(blobs(&scratch));
    let engine = QueueEngine::new(
        everything_but_the_cache(),
        &store,
        &store,
        &store,
        &payloads,
    );
    engine
        .enqueue(
            QueueRequest::new("alice", "alice@example.test", "client"),
            100,
        )
        .unwrap();
    let item = engine.claim_next("worker", 110, 60).unwrap().unwrap();

    // The grant still exists for the identity, but sending was narrowed
    // away after the item was queued.
    let grants = ScopedGrants::new([IdentityGrant::new(
        IdentityId::new("alice@example.test"),
        [Action::List],
    )]);
    let authority = GrantAuthority::new(grants, 9);
    let executor = RecordingExecutor::accepting();
    let outcome = engine
        .execute(&item, &executor, &authority, 120, 60)
        .unwrap();
    match outcome {
        ExecutionOutcome::Refused { reason } => assert!(
            reason.contains("may not"),
            "the refusal does not name the narrowed action: {reason}"
        ),
        other => panic!("the item was not refused: {other:?}"),
    }
    assert!(executor.dispatched().is_empty(), "the item was dispatched");
}

/// Behaviour 6: an authorization that still permits the action is used, and
/// the item is executed under the current grant.
#[test]
fn a_current_authorization_is_used_for_the_item() {
    let scratch = Scratch::new("current-authorization");
    let store = SqliteStore::open_in_memory().unwrap();
    let payloads = BlobPayloadStore::new(blobs(&scratch));
    let engine = QueueEngine::new(
        everything_but_the_cache(),
        &store,
        &store,
        &store,
        &payloads,
    );
    engine
        .enqueue(
            QueueRequest::new("alice", "alice@example.test", "client"),
            100,
        )
        .unwrap();
    let item = engine.claim_next("worker", 110, 60).unwrap().unwrap();

    // The grant set still allows sending, but at a newer revision than the
    // one the item was queued under.
    let grants = ScopedGrants::new([IdentityGrant::new(
        IdentityId::new("alice@example.test"),
        [Action::Send],
    )]);
    let authority = GrantAuthority::new(grants, 9);
    let executor = RecordingExecutor::accepting();
    let outcome = engine
        .execute(&item, &executor, &authority, 120, 60)
        .unwrap();
    assert!(
        matches!(outcome, ExecutionOutcome::Accepted { .. }),
        "the upstream accepted the message, got {outcome:?}"
    );
    assert_eq!(executor.dispatched().len(), 1);
}

/// Behaviour 7: a hidden change produces no event and no notification.
#[test]
fn a_hidden_change_produces_no_event_and_no_notification() {
    let scratch = Scratch::new("hidden-change");
    let store = SqliteStore::open_in_memory().unwrap();
    let cache = EncryptedContentCache::new(blobs(&scratch), CachePolicy::disabled());
    let engine = SyncEngine::new(
        QueueFeatures::none().with_persistent_sync(true),
        &store,
        &cache,
    );
    let policy = marker_policy("secret");
    let gate = PolicyGate::new(&policy);
    let mut source = ScriptedSource::new(
        vec![Change {
            id: MessageId::new("m-1"),
            kind: ChangeKind::Added,
        }],
        vec![message("m-1", "a secret subject", "the body")],
    );
    let mut events = Recorder::default();
    let mut notifications = Recorder::default();
    let run = engine
        .sync_once(
            SyncRequest {
                identity: "alice@example.test",
                mailbox: &MailboxRef::new("INBOX"),
                owner: "worker",
                now: 100,
                ttl: 60,
            },
            &mut source,
            &gate,
            &mut events,
            &mut notifications,
        )
        .unwrap();
    assert_eq!(run.observed, 1);
    assert_eq!(run.suppressed, 1);
    assert_eq!(run.published, 0);
    assert!(events.events.is_empty(), "a hidden change was published");
    assert!(
        notifications.events.is_empty(),
        "a hidden change was notified"
    );
}

/// Behaviour 7: a visible change next to a hidden one publishes only the
/// visible one.
#[test]
fn only_the_visible_change_is_published() {
    let scratch = Scratch::new("mixed-change");
    let store = SqliteStore::open_in_memory().unwrap();
    let cache = EncryptedContentCache::new(blobs(&scratch), CachePolicy::disabled());
    let engine = SyncEngine::new(
        QueueFeatures::none().with_persistent_sync(true),
        &store,
        &cache,
    );
    let policy = marker_policy("secret");
    let gate = PolicyGate::new(&policy);
    let mut source = ScriptedSource::new(
        vec![
            Change {
                id: MessageId::new("m-1"),
                kind: ChangeKind::Added,
            },
            Change {
                id: MessageId::new("m-2"),
                kind: ChangeKind::Added,
            },
        ],
        vec![
            message("m-1", "a secret subject", "the hidden body"),
            message("m-2", "an ordinary subject", "the visible body"),
        ],
    );
    let mut events = Recorder::default();
    let mut notifications = Recorder::default();
    let run = engine
        .sync_once(
            SyncRequest {
                identity: "alice@example.test",
                mailbox: &MailboxRef::new("INBOX"),
                owner: "worker",
                now: 100,
                ttl: 60,
            },
            &mut source,
            &gate,
            &mut events,
            &mut notifications,
        )
        .unwrap();
    assert_eq!(run.suppressed, 1);
    assert_eq!(run.published, 1);
    assert_eq!(events.events.len(), 1);
    assert_eq!(notifications.events.len(), 1);
    // The event carries the opaque identifier, never the upstream one.
    assert_ne!(events.events[0].message_id, "m-2");
}

/// Behaviour 8: a completed item leaves no blob behind.
#[test]
fn a_completed_item_leaves_no_blob_behind() {
    let scratch = Scratch::new("blob-complete");
    let store = SqliteStore::open_in_memory().unwrap();
    let payloads = BlobPayloadStore::new(blobs(&scratch));
    let engine = QueueEngine::new(
        everything_but_the_cache(),
        &store,
        &store,
        &store,
        &payloads,
    );
    let queued = engine
        .enqueue(
            QueueRequest::new("alice", "alice@example.test", "client")
                .with_payload(b"the body of the message".to_vec()),
            100,
        )
        .unwrap();
    let key = payload_key_for_submission(&queued.id);
    assert!(
        payloads
            .blobs()
            .get("alice@example.test", &key)
            .unwrap()
            .is_some()
    );

    let item = engine.claim_next("worker", 110, 60).unwrap().unwrap();
    let executor = RecordingExecutor::accepting();
    let outcome = engine
        .execute(&item, &executor, &FixedAuthority::permitting(1), 120, 60)
        .unwrap();
    assert!(
        matches!(outcome, ExecutionOutcome::Accepted { .. }),
        "the upstream accepted the message, got {outcome:?}"
    );
    assert_eq!(
        executor.dispatched(),
        vec![b"the body of the message".to_vec()]
    );

    assert_eq!(
        payloads.blobs().get("alice@example.test", &key).unwrap(),
        None
    );
    assert_no_blobs_left(payloads.blobs());
}

/// Behaviour 8: a failed item leaves no blob behind.
#[test]
fn a_failed_item_leaves_no_blob_behind() {
    let scratch = Scratch::new("blob-failed");
    let store = SqliteStore::open_in_memory().unwrap();
    let payloads = BlobPayloadStore::new(blobs(&scratch));
    let engine = QueueEngine::new(
        everything_but_the_cache(),
        &store,
        &store,
        &store,
        &payloads,
    );
    let queued = engine
        .enqueue(
            QueueRequest::new("alice", "alice@example.test", "client")
                .with_payload(b"the body of the message".to_vec()),
            100,
        )
        .unwrap();
    let key = payload_key_for_submission(&queued.id);
    let item = engine.claim_next("worker", 110, 60).unwrap().unwrap();
    let executor = RecordingExecutor::failing(TransportError::Rejected("no".to_owned()));
    engine
        .execute(&item, &executor, &FixedAuthority::permitting(1), 120, 60)
        .unwrap();
    assert_eq!(
        payloads.blobs().get("alice@example.test", &key).unwrap(),
        None
    );
    assert_no_blobs_left(payloads.blobs());
}

/// Behaviour 8: an abandoned item leaves no blob behind.
#[test]
fn an_abandoned_item_leaves_no_blob_behind() {
    let scratch = Scratch::new("blob-abandoned");
    let store = SqliteStore::open_in_memory().unwrap();
    let payloads = BlobPayloadStore::new(blobs(&scratch));
    let engine = QueueEngine::new(
        everything_but_the_cache(),
        &store,
        &store,
        &store,
        &payloads,
    );
    let queued = engine
        .enqueue(
            QueueRequest::new("alice", "alice@example.test", "client")
                .with_payload(b"the body of the message".to_vec()),
            100,
        )
        .unwrap();
    let key = payload_key_for_submission(&queued.id);
    let item = engine.claim_next("worker", 110, 60).unwrap().unwrap();
    engine.abandon(&item, "abandoned", 120).unwrap();
    assert_eq!(
        payloads.blobs().get("alice@example.test", &key).unwrap(),
        None
    );
    assert_no_blobs_left(payloads.blobs());
    let submission = store.get_submission(&queued.id).unwrap().unwrap();
    assert_eq!(submission.state, SubmissionState::Failed);
}

/// Behaviour 8: no staged write is left in the staging area.
fn assert_no_blobs_left(blob_store: &EncryptedDirectoryBlobStore) {
    let staging = blob_store.root().join("staging");
    let staged = std::fs::read_dir(&staging)
        .map(|entries| entries.count())
        .unwrap_or(0);
    assert_eq!(staged, 0, "a staged write was left behind");
    let objects = blob_store.root().join("objects");
    let objects = std::fs::read_dir(&objects)
        .map(|entries| entries.count())
        .unwrap_or(0);
    assert_eq!(objects, 0, "an object was left behind");
}

/// Behaviour 9: the queue creates no operator or provider management state.
#[test]
fn the_queue_creates_no_operator_or_provider_state() {
    let scratch = Scratch::new("no-second-truth");
    let store = SqliteStore::open_in_memory().unwrap();
    let payloads = BlobPayloadStore::new(blobs(&scratch));
    let engine = QueueEngine::new(
        everything_but_the_cache(),
        &store,
        &store,
        &store,
        &payloads,
    );
    engine
        .enqueue(
            QueueRequest::new("alice", "alice@example.test", "client"),
            100,
        )
        .unwrap();
    engine
        .schedule_task(
            mail_queue::TaskRequest::new("task-1", "alice", "alice@example.test"),
            100,
        )
        .unwrap();

    // The authorization service and the provider management own their own
    // state; the queue wrote nothing there.
    let grants: Vec<_> = store.list_grants("alice").unwrap();
    assert!(grants.is_empty(), "the queue wrote a grant");
    assert!(
        store
            .list_connections("alice@example.test")
            .unwrap()
            .is_empty()
    );

    // The queue holds no persistence of its own: its manifest has no
    // database dependency, so it cannot be a second store.
    let manifest = include_str!("../Cargo.toml");
    for forbidden in ["rusqlite", "sqlx", "diesel", "postgres", "redis", "sqlite"] {
        assert!(
            !manifest.contains(forbidden),
            "the queue manifest depends on {forbidden}"
        );
    }
}

/// The queue does not schedule a task when tasks are off, and does when
/// they are on.
#[test]
fn a_task_is_persisted_before_its_handle_is_returned() {
    let scratch = Scratch::new("tasks");
    let store = SqliteStore::open_in_memory().unwrap();
    let payloads = BlobPayloadStore::new(blobs(&scratch));
    let engine = QueueEngine::new(
        everything_but_the_cache(),
        &store,
        &store,
        &store,
        &payloads,
    );
    let handle = engine
        .schedule_task(
            mail_queue::TaskRequest::new("task-1", "alice", "alice@example.test"),
            100,
        )
        .unwrap();
    assert_eq!(handle.task_id, "task-1");
    // The task is already in the store when the handle exists.
    let task = store.get_task("task-1").unwrap().unwrap();
    assert_eq!(task.state, mail_storage::TaskState::Pending);

    // A worker claims it, and a worker whose fence is stale cannot finish
    // it.
    let claimed = engine.claim_task("task-1", "worker-one", 110).unwrap();
    let taken = engine.claim_task("task-1", "worker-two", 120).unwrap();
    let error = engine
        .complete_task(&claimed, "result-1", 130)
        .expect_err("the stale worker cannot finish the task");
    assert!(matches!(error, mail_queue::QueueError::StaleFence(_)));
    engine.complete_task(&taken, "result-1", 140).unwrap();
    let task = store.get_task("task-1").unwrap().unwrap();
    assert_eq!(task.state, mail_storage::TaskState::Completed);
    assert_eq!(task.result_ref.as_deref(), Some("result-1"));
}

/// The payload of an item is verified against its digest before it is sent.
#[test]
fn a_payload_that_does_not_match_its_digest_is_not_sent() {
    let scratch = Scratch::new("payload-digest");
    let store = SqliteStore::open_in_memory().unwrap();
    let payloads = BlobPayloadStore::new(blobs(&scratch));
    let engine = QueueEngine::new(
        everything_but_the_cache(),
        &store,
        &store,
        &store,
        &payloads,
    );
    let queued = engine
        .enqueue(
            QueueRequest::new("alice", "alice@example.test", "client")
                .with_payload(b"the body of the message".to_vec()),
            100,
        )
        .unwrap();
    // The stored payload is replaced by something else.
    payloads
        .stage(
            "alice@example.test",
            &payload_key_for_submission(&queued.id),
            b"a different body",
            105,
            600,
        )
        .unwrap();
    let item = engine.claim_next("worker", 110, 60).unwrap().unwrap();
    let executor = RecordingExecutor::accepting();
    let outcome = engine
        .execute(&item, &executor, &FixedAuthority::permitting(1), 120, 60)
        .unwrap();
    assert!(matches!(outcome, ExecutionOutcome::Failed { .. }));
    assert!(
        executor.dispatched().is_empty(),
        "the wrong payload was sent"
    );
}

/// The queue refuses a request whose declared digest disagrees with the
/// payload it was given.
#[test]
fn a_declared_digest_that_disagrees_with_the_payload_is_refused() {
    let scratch = Scratch::new("digest-mismatch");
    let store = SqliteStore::open_in_memory().unwrap();
    let payloads = BlobPayloadStore::new(blobs(&scratch));
    let engine = QueueEngine::new(
        everything_but_the_cache(),
        &store,
        &store,
        &store,
        &payloads,
    );
    let mut request = QueueRequest::new("alice", "alice@example.test", "client")
        .with_payload(b"the body of the message".to_vec());
    request.payload_digest = Some("0000".to_owned());
    let error = engine
        .enqueue(request, 100)
        .expect_err("the request is refused");
    assert!(matches!(error, mail_queue::QueueError::Invalid(_)));
    assert!(
        store
            .list_by_identity("alice@example.test")
            .unwrap()
            .is_empty()
    );
}

/// The store's own interfaces are the only durable state the queue uses.
#[test]
fn the_queue_uses_the_storage_layer_for_its_durable_state() {
    let scratch = Scratch::new("storage-layer");
    let store = SqliteStore::open_in_memory().unwrap();
    let blob_store = blobs(&scratch);
    let payloads: &dyn PayloadStore = &BlobPayloadStore::new(blob_store);
    let engine = QueueEngine::new(everything_but_the_cache(), &store, &store, &store, payloads);
    let queued = engine
        .enqueue(
            QueueRequest::new("alice", "alice@example.test", "client"),
            100,
        )
        .unwrap();
    let submission: StorageResult<Option<Submission>> = store.get_submission(&queued.id);
    assert!(submission.unwrap().is_some());
    assert_eq!(
        account_of("alice@example.test"),
        "alice@example.test".to_owned()
    );
}
