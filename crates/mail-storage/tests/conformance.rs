//! The conformance suite of the storage boundaries.
//!
//! The suite is written against the store interfaces rather than against
//! SQLite, because the properties that matter are the properties of the
//! contract: an idempotency key that is reused with a different payload is
//! a conflict, a revoked grant does not come back, a stale worker cannot
//! write over the worker that took over from it, and an uncertain send
//! stays uncertain.
//!
//! The suite runs against both backends the build has: the ephemeral one
//! (memory) and the SQLite one (a file). A property that only holds for
//! one of them is a defect in the other.

use std::path::PathBuf;

use mail_storage::audit::{AuditEvent, AuditStore};
use mail_storage::config::StorageConfig;
use mail_storage::error::StorageError;
use mail_storage::grants::{
    AccessToken, AuthCode, Grant, GrantStore, OAuthClient, RefreshFamily, RevocationKind,
};
use mail_storage::mailbox::{Checkpoint, MailboxStateStore, OpaqueId, OpaqueKind, WorkerLease};
use mail_storage::migration::SCHEMA_VERSION;
use mail_storage::provider::{
    ConnectionStatus, ProviderConnection, ProviderConnectionStore, RefreshState,
};
use mail_storage::revocation::RevocationLedger;
use mail_storage::sqlite::SqliteStore;
use mail_storage::storage::Storage;
use mail_storage::submission::{
    IDEMPOTENCY_RETENTION_SECONDS, IdempotencyReservation, Submission, SubmissionState,
    SubmissionStore,
};
use mail_storage::task::{Task, TaskState, TaskStore};

/// A temporary directory that holds one test's files.
fn directory(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("corvi-storage-{name}"));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("the directory can be created");
    path
}

/// Run the suite against one store.
fn conformance(name: &str, store: &SqliteStore) {
    grants(name, store);
    provider(store);
    mailbox(store);
    submissions(name, store);
    tasks(store);
    audit(store);
}

/// The grant store properties.
fn grants(name: &str, store: &SqliteStore) {
    let client = OAuthClient {
        client_id: "client-1".to_owned(),
        name: "An agent".to_owned(),
        redirect_uris: vec!["https://app.example/callback".to_owned()],
        secret_hash: Some("hash".to_owned()),
        confidential: true,
    };
    store.put_client(&client).expect("the client is stored");
    let read = store
        .get_client("client-1")
        .expect("the client is read")
        .expect("the client is there");
    assert_eq!(read.redirect_uris, client.redirect_uris);

    let grant = Grant {
        grant_id: "grant-1".to_owned(),
        client_id: "client-1".to_owned(),
        principal: "principal-1".to_owned(),
        identity: "identity-1".to_owned(),
        scopes: vec!["mail:messages:read".to_owned()],
        revision: 1,
        created_at: 100,
        revoked_at: None,
    };
    store.put_grant(&grant).expect("the grant is stored");
    assert_eq!(
        store
            .list_grants("principal-1")
            .expect("the grants list")
            .len(),
        1
    );
    assert!(
        store
            .revoke_grant("grant-1", 200)
            .expect("the grant is revoked")
    );
    let revoked = store
        .get_grant("grant-1")
        .expect("the grant is read")
        .expect("the grant is there");
    assert_eq!(revoked.revoked_at, Some(200));
    // Replaying a stale grant must not clear a durable revocation.
    store
        .put_grant(&grant)
        .expect("the stale grant update is accepted");
    assert_eq!(
        store
            .get_grant("grant-1")
            .expect("the grant is read")
            .unwrap()
            .revoked_at,
        Some(200)
    );
    // A second revocation is not a second fact.
    assert!(
        !store
            .revoke_grant("grant-1", 300)
            .expect("the grant is revoked")
    );

    // The revocation is a fact that outlives the grant row.
    let revocations = store.revoked_after(100).expect("the revocations list");
    assert!(
        revocations
            .iter()
            .any(|revocation| revocation.subject == "grant-1"
                && revocation.kind == RevocationKind::Grant
                && revocation.at == 200)
    );

    // An authorization code is exchanged exactly once.
    let code = AuthCode {
        code_hash: "code-hash-1".to_owned(),
        client_id: "client-1".to_owned(),
        redirect_uri: "https://app.example/callback".to_owned(),
        principal: "principal-1".to_owned(),
        scopes: vec!["mail:messages:read".to_owned()],
        expires_at: 1_000,
        used_at: None,
    };
    store.put_auth_code(&code).expect("the code is stored");
    let exchanged = store
        .exchange_auth_code("code-hash-1", 500)
        .expect("the code is exchanged");
    assert_eq!(exchanged.used_at, Some(500));
    assert_eq!(
        store.exchange_auth_code("code-hash-1", 600),
        Err(StorageError::Conflict(
            "the authorization code was already exchanged".to_owned()
        ))
    );

    // An expired code is refused.
    let expired = AuthCode {
        code_hash: "code-hash-2".to_owned(),
        expires_at: 400,
        ..code.clone()
    };
    store.put_auth_code(&expired).expect("the code is stored");
    assert!(matches!(
        store.exchange_auth_code("code-hash-2", 500),
        Err(StorageError::Conflict(_))
    ));

    // An access token is looked up by its verifier. A live token of a live
    // grant is found.
    let live_grant = Grant {
        grant_id: "grant-2".to_owned(),
        client_id: "client-1".to_owned(),
        principal: "principal-1".to_owned(),
        identity: "identity-1".to_owned(),
        scopes: vec!["mail:messages:read".to_owned()],
        revision: 1,
        created_at: 100,
        revoked_at: None,
    };
    store.put_grant(&live_grant).expect("the grant is stored");
    let token = AccessToken {
        token_hash: "token-hash-1".to_owned(),
        grant_id: "grant-2".to_owned(),
        principal: "principal-1".to_owned(),
        scopes: vec!["mail:messages:read".to_owned()],
        expires_at: 1_000,
        revoked_at: None,
    };
    store.put_access_token(&token).expect("the token is stored");
    let found = store
        .lookup_access_token("token-hash-1", 500)
        .expect("the token is looked up")
        .expect("the live token is there");
    assert_eq!(found.token_hash, "token-hash-1");

    // An expired token is not a token.
    assert!(
        store
            .lookup_access_token("token-hash-1", 2_000)
            .expect("the token is looked up")
            .is_none(),
        "an expired token was found"
    );

    // A revoked token is not a token, and storing it again does not clear
    // the revocation.
    let revoked_token = AccessToken {
        token_hash: "token-hash-2".to_owned(),
        revoked_at: Some(300),
        ..token.clone()
    };
    store
        .put_access_token(&revoked_token)
        .expect("the revoked token is stored");
    assert!(
        store
            .lookup_access_token("token-hash-2", 400)
            .expect("the token is looked up")
            .is_none(),
        "a revoked token was found"
    );
    store
        .put_access_token(&revoked_token)
        .expect("the revoked token is stored again");
    assert!(
        store
            .lookup_access_token("token-hash-2", 400)
            .expect("the token is looked up")
            .is_none(),
        "a revoked token came back"
    );

    // A token of a revoked grant is not a token: grant-1 was revoked above.
    let of_revoked_grant = AccessToken {
        token_hash: "token-hash-3".to_owned(),
        grant_id: "grant-1".to_owned(),
        ..token.clone()
    };
    store
        .put_access_token(&of_revoked_grant)
        .expect("the token is stored");
    assert!(
        store
            .lookup_access_token("token-hash-3", 400)
            .expect("the token is looked up")
            .is_none(),
        "a token of a revoked grant was found"
    );

    // A token that was never stored is not found.
    assert!(
        store
            .lookup_access_token("token-hash-absent", 400)
            .expect("the token is looked up")
            .is_none(),
        "a token that was never stored was found"
    );

    // A refresh rotation is a compare-and-swap: only one worker wins.
    let family = RefreshFamily {
        family_id: "family-1".to_owned(),
        grant_id: "grant-1".to_owned(),
        generation: 1,
        current_token_hash: "refresh-hash-1".to_owned(),
        rotated_at: 100,
        revoked_at: None,
    };
    store
        .put_refresh_family(&family)
        .expect("the family is stored");
    let rotated = store
        .rotate_refresh("family-1", 1, "refresh-hash-2", 200)
        .expect("the family rotates");
    assert_eq!(rotated.generation, 2);
    assert_eq!(rotated.current_token_hash, "refresh-hash-2");
    assert_eq!(
        store.rotate_refresh("family-1", 1, "refresh-hash-3", 300),
        Err(StorageError::Conflict(
            "the refresh family moved on before this rotation".to_owned()
        ))
    );
    let _ = name;
}

/// The provider connection properties.
fn provider(store: &SqliteStore) {
    let connection = ProviderConnection {
        connection_id: "conn-1".to_owned(),
        provider: "fastmail".to_owned(),
        account_ref: "acct-1".to_owned(),
        identity: "identity-1".to_owned(),
        capabilities: vec!["read".to_owned(), "submit".to_owned()],
        status: ConnectionStatus::Active,
        generation: 1,
        updated_at: 100,
    };
    store
        .put_connection(&connection)
        .expect("the connection is stored");
    assert_eq!(
        store
            .list_connections("identity-1")
            .expect("the connections list")
            .len(),
        1
    );

    store
        .put_refresh_state(&RefreshState {
            connection_id: "conn-1".to_owned(),
            generation: 1,
            secret_ref: "identity-1/refresh".to_owned(),
            expires_at: 1_000,
            needs_reauthorization: false,
        })
        .expect("the refresh state is stored");

    // A refresh is claimed once. A second worker at the same generation
    // does not get a second claim.
    assert!(
        store
            .claim_refresh("conn-1", 1, "worker-1")
            .expect("the refresh is claimed")
    );
    assert!(
        !store
            .complete_refresh("conn-1", 1, "worker-2", "refresh-3", 3_000, 150)
            .expect("non-owner completion is refused")
    );
    assert!(
        !store
            .claim_refresh("conn-1", 1, "worker-2")
            .expect("a competing refresh is refused")
    );
    assert!(
        store
            .complete_refresh("conn-1", 1, "worker-1", "identity-1/refresh-2", 2_000, 200)
            .expect("the refresh is completed")
    );
    // The old generation cannot commit again.
    assert!(
        !store
            .complete_refresh("conn-1", 1, "worker-1", "identity-1/refresh-3", 3_000, 300)
            .expect("the stale commit is refused")
    );
    assert!(
        !store
            .claim_refresh("conn-1", 1, "worker-2")
            .expect("the stale claim is refused")
    );

    // Disconnecting invalidates the credential.
    assert!(
        store
            .disconnect("conn-1", 400)
            .expect("the connection is disconnected")
    );
    assert!(
        store
            .get_refresh_state("conn-1")
            .expect("the refresh state is read")
            .is_none()
    );
    let connection = store
        .get_connection("conn-1")
        .expect("the connection is read")
        .expect("the connection is there");
    assert_eq!(connection.status, ConnectionStatus::Disconnected);
}

/// The mailbox state properties.
fn mailbox(store: &SqliteStore) {
    let checkpoint = Checkpoint {
        identity: "identity-1".to_owned(),
        mailbox: "INBOX".to_owned(),
        upstream_cursor: "uid-42".to_owned(),
        generation: 3,
        updated_at: 100,
    };
    store
        .put_checkpoint(&checkpoint)
        .expect("the checkpoint is stored");
    let read = store
        .get_checkpoint("identity-1", "INBOX")
        .expect("the checkpoint is read")
        .expect("the checkpoint is there");
    assert_eq!(read.upstream_cursor, "uid-42");

    // An opaque identifier belongs to the identity that owns it.
    store
        .put_opaque_id(&OpaqueId {
            identity: "identity-1".to_owned(),
            kind: OpaqueKind::Message,
            public_id: "msg_1".to_owned(),
            upstream_id: "M-upstream-1".to_owned(),
        })
        .expect("the mapping is stored");
    assert_eq!(
        store
            .lookup_opaque_id("identity-1", OpaqueKind::Message, "msg_1")
            .expect("the mapping is read")
            .as_deref(),
        Some("M-upstream-1")
    );
    // Another identity cannot resolve it, even with the same public id.
    assert!(
        store
            .lookup_opaque_id("identity-2", OpaqueKind::Message, "msg_1")
            .expect("the mapping is read")
            .is_none()
    );

    // A lease is fenced: taking it over increases the token and makes the
    // earlier owner's token stale.
    let first: WorkerLease = store
        .acquire_lease("sync:identity-1", "worker-1", 100, 60)
        .expect("the lease is acquired");
    assert_eq!(first.fencing_token, 1);
    let second = store
        .acquire_lease("sync:identity-1", "worker-2", 120, 60)
        .expect("the lease is taken over");
    assert_eq!(second.fencing_token, 2);
    assert!(
        !store
            .renew_lease("sync:identity-1", "worker-1", first.fencing_token, 130, 60)
            .expect("the stale renewal is refused")
    );
    assert!(
        store
            .renew_lease("sync:identity-1", "worker-2", second.fencing_token, 130, 60)
            .expect("the renewal is accepted")
    );
    assert!(
        !store
            .release_lease("sync:identity-1", first.fencing_token)
            .expect("the stale release is refused")
    );
}

/// The submission properties.
fn submissions(name: &str, store: &SqliteStore) {
    let reservation = IdempotencyReservation {
        key: "key-1".to_owned(),
        principal: "principal-1".to_owned(),
        identity: "identity-1".to_owned(),
        client_id: "client-1".to_owned(),
        payload_digest: "digest-1".to_owned(),
        submission_id: "sub-1".to_owned(),
        created_at: 100,
        expires_at: 100 + IDEMPOTENCY_RETENTION_SECONDS,
    };
    let submission = Submission {
        id: "sub-1".to_owned(),
        principal: "principal-1".to_owned(),
        identity: "identity-1".to_owned(),
        client_id: "client-1".to_owned(),
        idempotency_key: Some("key-1".to_owned()),
        payload_digest: Some("digest-1".to_owned()),
        state: SubmissionState::Reserved,
        upstream_protocol: Some("smtp".to_owned()),
        attempts: 0,
        lease_owner: None,
        lease_expires_at: None,
        fencing_token: 0,
        created_at: 100,
        updated_at: 100,
        failure_code: None,
    };
    let intent = store
        .reserve_submission(&reservation, &submission)
        .expect("intent is atomically reserved");
    assert_eq!(intent.id, "sub-1");

    // The same key with the same payload is the same reservation.
    let replay = store
        .reserve_submission(&reservation, &submission)
        .expect("the same reservation is accepted");
    assert_eq!(replay.id, "sub-1");
    let found = store
        .lookup_idempotency("principal-1", "client-1", "identity-1", "key-1", 200)
        .expect("the reservation is read")
        .expect("the reservation is there");
    assert_eq!(found.submission_id, "sub-1");

    // The same key with a different payload is a conflict.
    let different = IdempotencyReservation {
        payload_digest: "digest-2".to_owned(),
        ..reservation.clone()
    };
    let different_submission = Submission {
        payload_digest: Some("digest-2".to_owned()),
        ..submission.clone()
    };
    assert!(matches!(
        store.reserve_submission(&different, &different_submission),
        Err(StorageError::Conflict(_))
    ));

    // Another identity's key does not collide.
    let other_identity = IdempotencyReservation {
        identity: "identity-2".to_owned(),
        submission_id: "sub-2".to_owned(),
        ..reservation.clone()
    };
    let other_submission = Submission {
        id: "sub-2".to_owned(),
        identity: "identity-2".to_owned(),
        ..submission.clone()
    };
    store
        .reserve_submission(&other_identity, &other_submission)
        .expect("the other identity reserves its own key");

    // The reservation is kept for at least a day.
    assert!(
        store
            .lookup_idempotency(
                "principal-1",
                "client-1",
                "identity-1",
                "key-1",
                100 + 23 * 60 * 60
            )
            .expect("the reservation is read")
            .is_some()
    );

    // The submission was created by the atomic reservation above; it is not
    // written a second time.

    // A worker claims the submission, and only that worker's token may
    // release it.
    let claimed = store
        .claim_next("worker-1", 200, 60)
        .expect("the submission is claimed")
        .expect("there is a submission to claim");
    assert_eq!(claimed.id, "sub-1");
    assert_eq!(
        store.release_claim(
            "sub-1",
            claimed.fencing_token + 10,
            SubmissionState::Accepted,
            300,
            None,
        ),
        Err(StorageError::Conflict(
            "the claim was taken over by another worker".to_owned()
        ))
    );

    // An uncertain send stays unknown, and it is listed for reconciliation.
    let unknown = Submission {
        id: "sub-unknown".to_owned(),
        idempotency_key: None,
        payload_digest: None,
        state: SubmissionState::Unknown,
        ..submission.clone()
    };
    store
        .put_submission(&unknown)
        .expect("the unknown submission is stored");
    let unknown_list = store.list_unknown().expect("the unknown list");
    assert!(
        unknown_list
            .iter()
            .any(|entry| entry.id == "sub-unknown" && entry.state == SubmissionState::Unknown)
    );
    assert!(matches!(
        store.transition("sub-unknown", SubmissionState::Reserved, 300, None),
        Err(StorageError::Conflict(_))
    ));

    // An expired reservation may be forgotten, and a live one may not.
    assert_eq!(
        store
            .purge_expired_idempotency(100 + IDEMPOTENCY_RETENTION_SECONDS + 1)
            .expect("the reservations are purged"),
        2
    );
    assert!(
        store
            .lookup_idempotency("principal-1", "client-1", "identity-1", "key-1", 200)
            .expect("the reservation is read")
            .is_none()
    );
    let _ = name;
}

/// The task properties.
fn tasks(store: &SqliteStore) {
    let task = Task {
        task_id: "task-1".to_owned(),
        principal: "principal-1".to_owned(),
        identity: "identity-1".to_owned(),
        owner: None,
        state: TaskState::Pending,
        progress: None,
        result_ref: None,
        fencing_token: 0,
        created_at: 100,
        updated_at: 100,
    };
    store.put_task(&task).expect("the task is stored");
    let claimed = store
        .claim_task("task-1", "worker-1", 200)
        .expect("the task is claimed");
    assert_eq!(claimed.state, TaskState::Running);
    assert!(
        !store
            .set_progress("task-1", "worker-2", claimed.fencing_token, "half", 210)
            .expect("the progress is recorded")
    );
    assert!(
        store
            .complete_task("task-1", "worker-1", claimed.fencing_token, "result-1", 220)
            .expect("the task finishes")
    );
    let read = store
        .get_task("task-1")
        .expect("the task is read")
        .expect("the task is there");
    assert_eq!(read.state, TaskState::Completed);
    assert_eq!(read.result_ref.as_deref(), Some("result-1"));
    // A finished task is not claimed again.
    assert!(matches!(
        store.claim_task("task-1", "worker-2", 300),
        Err(StorageError::Conflict(_))
    ));
}

/// The audit properties.
fn audit(store: &SqliteStore) {
    store
        .append(&AuditEvent {
            at: 100,
            actor: "principal-1".to_owned(),
            action: "grant.revoked".to_owned(),
            subject: "grant-1".to_owned(),
            outcome: "ok".to_owned(),
        })
        .expect("the event is appended");
    store
        .append(&AuditEvent {
            at: 200,
            actor: "principal-1".to_owned(),
            action: "submission.sent".to_owned(),
            subject: "sub-1".to_owned(),
            outcome: "unknown".to_owned(),
        })
        .expect("the event is appended");
    let events = store.list(0, 10).expect("the events list");
    assert_eq!(events.len(), 2);
    assert_eq!(events[1].action, "submission.sent");
    assert_eq!(store.prune(150).expect("the events are pruned"), 1);
}

/// A submission without a key, used by the tests that need one.
fn plain_submission(id: &str) -> Submission {
    Submission {
        id: id.to_owned(),
        principal: "principal-1".to_owned(),
        identity: "identity-1".to_owned(),
        client_id: "client-1".to_owned(),
        idempotency_key: None,
        payload_digest: None,
        state: SubmissionState::Reserved,
        upstream_protocol: Some("smtp".to_owned()),
        attempts: 0,
        lease_owner: None,
        lease_expires_at: None,
        fencing_token: 0,
        created_at: 100,
        updated_at: 100,
        failure_code: None,
    }
}

/// A reservation and the submission it belongs to.
fn keyed_pair(
    key: &str,
    digest: &str,
    submission_id: &str,
) -> (IdempotencyReservation, Submission) {
    let reservation = IdempotencyReservation {
        key: key.to_owned(),
        principal: "principal-1".to_owned(),
        identity: "identity-1".to_owned(),
        client_id: "client-1".to_owned(),
        payload_digest: digest.to_owned(),
        submission_id: submission_id.to_owned(),
        created_at: 100,
        expires_at: 100 + IDEMPOTENCY_RETENTION_SECONDS,
    };
    let submission = Submission {
        idempotency_key: Some(key.to_owned()),
        payload_digest: Some(digest.to_owned()),
        ..plain_submission(submission_id)
    };
    (reservation, submission)
}

#[test]
fn a_keyed_submission_cannot_be_created_outside_the_reservation() {
    let store = SqliteStore::open_in_memory().expect("the store opens");
    let (_, submission) = keyed_pair("key-1", "digest-1", "sub-1");
    let error = store
        .put_submission(&submission)
        .expect_err("a keyed submission needs the atomic reservation path");
    assert!(
        matches!(error, StorageError::Invalid(_)),
        "unexpected error: {error:?}"
    );
    // Nothing was written.
    assert!(
        store
            .get_submission("sub-1")
            .expect("the submission is read")
            .is_none()
    );
}

#[test]
fn an_existing_submission_is_not_overwritten() {
    let store = SqliteStore::open_in_memory().expect("the store opens");
    let submission = plain_submission("sub-1");
    store
        .put_submission(&submission)
        .expect("the submission is stored");
    // A second write may not roll the state back.
    let rewritten = Submission {
        state: SubmissionState::Accepted,
        ..submission.clone()
    };
    let error = store
        .put_submission(&rewritten)
        .expect_err("an existing submission is not overwritten");
    assert!(
        matches!(error, StorageError::Conflict(_)),
        "unexpected error: {error:?}"
    );
    let read = store
        .get_submission("sub-1")
        .expect("the submission is read")
        .expect("the submission is there");
    assert_eq!(read.state, SubmissionState::Reserved);
}

#[test]
fn a_failed_reservation_leaves_no_orphan_key() {
    let store = SqliteStore::open_in_memory().expect("the store opens");
    // The submission identifier is already taken, so the second half of the
    // atomic unit fails after the key was written.
    store
        .put_submission(&plain_submission("sub-1"))
        .expect("the submission is stored");
    let (reservation, submission) = keyed_pair("key-1", "digest-1", "sub-1");
    let error = store
        .reserve_submission(&reservation, &submission)
        .expect_err("the reservation fails");
    assert!(
        matches!(error, StorageError::Backend(_)),
        "unexpected error: {error:?}"
    );
    // The key was not left behind without a submission.
    assert!(
        store
            .lookup_idempotency("principal-1", "client-1", "identity-1", "key-1", 200)
            .expect("the reservation is read")
            .is_none()
    );
}

#[test]
fn one_key_yields_one_submission_under_concurrency() {
    let store = std::sync::Arc::new(SqliteStore::open_in_memory().expect("the store opens"));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let store = std::sync::Arc::clone(&store);
        handles.push(std::thread::spawn(move || {
            let (reservation, submission) = keyed_pair("key-1", "digest-1", "sub-1");
            store.reserve_submission(&reservation, &submission)
        }));
    }
    let mut ids = Vec::new();
    for handle in handles {
        let intent = handle
            .join()
            .expect("the thread ends")
            .expect("the reservation succeeds");
        ids.push(intent.id);
    }
    assert!(
        ids.iter().all(|id| id == "sub-1"),
        "the key produced more than one submission: {ids:?}"
    );
    let submissions = store
        .list_by_identity("identity-1")
        .expect("the submissions list");
    assert_eq!(
        submissions.len(),
        1,
        "the key produced more than one submission: {submissions:?}"
    );
}

/// A provider connection at a generation.
fn connection_at(generation: u64) -> ProviderConnection {
    ProviderConnection {
        connection_id: "conn-2".to_owned(),
        provider: "fastmail".to_owned(),
        account_ref: "acct-1".to_owned(),
        identity: "identity-1".to_owned(),
        capabilities: vec!["read".to_owned()],
        status: ConnectionStatus::Active,
        generation,
        updated_at: 100,
    }
}

#[test]
fn a_stale_owner_cannot_commit_a_refreshed_token() {
    let store = SqliteStore::open_in_memory().expect("the store opens");
    store
        .put_connection(&connection_at(1))
        .expect("the connection is stored");
    assert!(
        store
            .claim_refresh("conn-2", 1, "worker-1")
            .expect("the refresh is claimed")
    );
    // Another writer rotates the credential, so the connection moves on.
    store
        .put_connection(&connection_at(2))
        .expect("the connection is stored");
    // The owner of the stale claim may not commit against the new
    // generation, and it may not commit against its own stale one either.
    assert!(
        !store
            .complete_refresh("conn-2", 2, "worker-1", "identity-1/refresh-2", 2_000, 200)
            .expect("the stale commit is refused")
    );
    assert!(
        !store
            .complete_refresh("conn-2", 1, "worker-1", "identity-1/refresh-2", 2_000, 200)
            .expect("the stale commit is refused")
    );
}

#[test]
fn a_new_owner_can_claim_after_the_generation_moved() {
    let store = SqliteStore::open_in_memory().expect("the store opens");
    store
        .put_connection(&connection_at(1))
        .expect("the connection is stored");
    assert!(
        store
            .claim_refresh("conn-2", 1, "worker-1")
            .expect("the refresh is claimed")
    );
    // The connection moves on, so the claim of the first worker is stale.
    store
        .put_connection(&connection_at(2))
        .expect("the connection is stored");
    assert!(
        store
            .claim_refresh("conn-2", 2, "worker-2")
            .expect("the new owner claims the refresh")
    );
    // The new owner commits, and the first worker is locked out.
    assert!(
        store
            .complete_refresh("conn-2", 2, "worker-2", "identity-1/refresh-2", 2_000, 200)
            .expect("the refresh is completed")
    );
    assert!(
        !store
            .complete_refresh("conn-2", 2, "worker-1", "identity-1/refresh-3", 3_000, 300)
            .expect("the stale owner is refused")
    );
}

/// The environment variable that tells the helper test which database a
/// child process should open.
const CHILD_DATABASE: &str = "CORVI_STORAGE_TEST_CHILD_DATABASE";

/// The environment variable that tells the helper test to die while it
/// holds the database open.
const CHILD_CRASH: &str = "CORVI_STORAGE_TEST_CHILD_CRASH";

#[test]
fn a_second_process_cannot_open_the_database() {
    let path = directory("writer-process").join("state.sqlite");
    let store = SqliteStore::open(&path).expect("the store opens");
    let binary = std::env::current_exe().expect("the test binary path");
    let output = std::process::Command::new(binary)
        .args(["--exact", "the_child_process_opens_the_database"])
        .env(CHILD_DATABASE, &path)
        .output()
        .expect("the child process runs");
    assert!(
        output.status.success(),
        "the second process was not refused: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    drop(store);
}

#[test]
fn the_child_process_opens_the_database() {
    let Ok(path) = std::env::var(CHILD_DATABASE) else {
        // Not a child run.
        return;
    };
    let error = SqliteStore::open(&path).expect_err("the second process is refused");
    assert!(
        matches!(error, StorageError::Conflict(_)),
        "unexpected error: {error:?}"
    );
}

#[test]
fn a_crashed_writer_does_not_keep_the_database_out_of_reach() {
    let path = directory("writer-crash").join("state.sqlite");
    let binary = std::env::current_exe().expect("the test binary path");
    let status = std::process::Command::new(binary)
        .args(["--exact", "the_child_process_dies_with_the_database_open"])
        .env(CHILD_CRASH, &path)
        .status()
        .expect("the child process runs");
    assert!(
        !status.success(),
        "the child was expected to die while it held the database"
    );
    // The lock of the dead writer was released by the operating system, so
    // the database opens without an operator removing anything.
    let store = SqliteStore::open(&path).expect("the store opens after the crash");
    // And a second writer is still refused.
    let error = SqliteStore::open(&path).expect_err("a second writer is refused");
    assert!(matches!(error, StorageError::Conflict(_)));
    drop(store);
}

#[test]
fn the_child_process_dies_with_the_database_open() {
    let Ok(path) = std::env::var(CHILD_CRASH) else {
        // Not a child run.
        return;
    };
    let _store = SqliteStore::open(&path).expect("the child opens the database");
    // Die without unwinding, the way a crash does.
    let killed = std::process::Command::new("sh")
        .args(["-c", "kill -9 $PPID"])
        .status();
    assert!(killed.is_ok(), "the child kills itself");
    // The kill is asynchronous; if it did not arrive, this process ends.
    std::thread::sleep(std::time::Duration::from_secs(5));
    std::process::exit(1);
}

/// The environment variable that tells the helper test to commit a row and
/// die while it holds the database open.
const CHILD_WAL: &str = "CORVI_STORAGE_TEST_CHILD_WAL";

#[test]
fn a_committed_write_survives_a_crash() {
    let path = directory("wal-recovery").join("state.sqlite");
    let binary = std::env::current_exe().expect("the test binary path");
    let status = std::process::Command::new(binary)
        .args(["--exact", "the_child_process_writes_and_dies"])
        .env(CHILD_WAL, &path)
        .status()
        .expect("the child process runs");
    assert!(
        !status.success(),
        "the child was expected to die while it held the database"
    );
    // The write was still in the write-ahead log: the child died without
    // closing its connection, so nothing checkpointed the log into the
    // database file.
    let wal = path.with_file_name("state.sqlite-wal");
    let wal_size = std::fs::metadata(&wal)
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    assert!(wal_size > 0, "the committed write was not in the log");
    // The write-ahead log of the dead writer is replayed, so the row it
    // committed is still there and the database is intact.
    let store = SqliteStore::open(&path).expect("the store opens after the crash");
    let checkpoint = store
        .get_checkpoint("identity-1", "INBOX")
        .expect("the checkpoint is read")
        .expect("the committed checkpoint survived the crash");
    assert_eq!(checkpoint.upstream_cursor, "uid-42");
    assert_eq!(store.integrity_check().expect("the integrity check"), "ok");
}

#[test]
fn the_child_process_writes_and_dies() {
    let Ok(path) = std::env::var(CHILD_WAL) else {
        // Not a child run.
        return;
    };
    let store = SqliteStore::open(&path).expect("the child opens the database");
    store
        .put_checkpoint(&Checkpoint {
            identity: "identity-1".to_owned(),
            mailbox: "INBOX".to_owned(),
            upstream_cursor: "uid-42".to_owned(),
            generation: 1,
            updated_at: 100,
        })
        .expect("the checkpoint is committed");
    // Die without unwinding, the way a crash does: the connection is not
    // closed and the write-ahead log is not checkpointed.
    let killed = std::process::Command::new("sh")
        .args(["-c", "kill -9 $PPID"])
        .status();
    assert!(killed.is_ok(), "the child kills itself");
    // The kill is asynchronous; if it did not arrive, this process ends.
    std::thread::sleep(std::time::Duration::from_secs(5));
    std::process::exit(1);
}

#[test]
fn a_database_that_is_behind_the_ledger_catches_up() {
    let directory = directory("catch-up");
    let path = directory.join("state.sqlite");
    let store = SqliteStore::open(&path).expect("the store opens");
    store
        .put_grant(&revocable_grant())
        .expect("the grant is stored");
    store
        .put_access_token(&AccessToken {
            token_hash: "token-hash-1".to_owned(),
            grant_id: "grant-1".to_owned(),
            principal: "principal-1".to_owned(),
            scopes: vec!["mail:messages:read".to_owned()],
            expires_at: 1_000,
            revoked_at: None,
        })
        .expect("the token is stored");
    store
        .revoke_grant("grant-1", 200)
        .expect("the grant is revoked");
    drop(store);

    // The ledger was written and the database was not: the write of the
    // revocation is lost, the way it would be if the process died between
    // the two.
    let connection = rusqlite::Connection::open(&path).expect("the database opens");
    connection
        .execute("UPDATE revocation_state SET watermark = 0 WHERE id = 1", [])
        .expect("the watermark is rolled back");
    connection
        .execute("DELETE FROM revocations WHERE subject = 'grant-1'", [])
        .expect("the revocation is rolled back");
    connection
        .execute(
            "UPDATE grants SET revoked_at = NULL WHERE grant_id = 'grant-1'",
            [],
        )
        .expect("the grant is rolled back");
    drop(connection);

    // The store catches up with the ledger on open, so the revoked grant
    // and the token of that grant are refused again.
    let store = SqliteStore::open(&path).expect("the store opens again");
    let grant = store
        .get_grant("grant-1")
        .expect("the grant is read")
        .expect("the grant is there");
    assert_eq!(
        grant.revoked_at,
        Some(200),
        "the revocation was not caught up with"
    );
    assert!(
        store
            .lookup_access_token("token-hash-1", 300)
            .expect("the token is looked up")
            .is_none(),
        "a token of a revoked grant was found"
    );
}

#[test]
fn a_restore_over_a_crashed_database_installs_the_backup() {
    let directory = directory("restore-over-crash");
    let crashed = directory.join("crashed.sqlite");
    let source = directory.join("source.sqlite");
    let backup = directory.join("backup.sqlite");

    // The backup holds a checkpoint of its own.
    {
        let store = SqliteStore::open(&source).expect("the store opens");
        store
            .put_checkpoint(&Checkpoint {
                identity: "identity-1".to_owned(),
                mailbox: "INBOX".to_owned(),
                upstream_cursor: "uid-from-the-backup".to_owned(),
                generation: 1,
                updated_at: 100,
            })
            .expect("the checkpoint is stored");
        store.backup_to(&backup).expect("the backup is written");
    }
    // The backup carries its ledger with it.
    let ledger = directory.join("backup.sqlite.revocations");
    assert!(ledger.exists(), "the backup has no ledger of its own");

    // The destination is a database whose writer was killed: its
    // write-ahead log is still there, with a committed row in it.
    let binary = std::env::current_exe().expect("the test binary path");
    let status = std::process::Command::new(binary)
        .args(["--exact", "the_child_process_writes_and_dies"])
        .env(CHILD_WAL, &crashed)
        .status()
        .expect("the child process runs");
    assert!(
        !status.success(),
        "the child was expected to die while it held the database"
    );
    let wal = directory.join("crashed.sqlite-wal");
    assert!(
        wal.metadata().map(|meta| meta.len()).unwrap_or(0) > 0,
        "the crashed writer left no log"
    );

    SqliteStore::restore_from(&backup, &crashed, &ledger).expect("the backup is restored");

    // The restored database holds the state of the backup, not the state
    // the crashed writer left in its log.
    let store = SqliteStore::open(&crashed).expect("the restored store opens");
    let checkpoint = store
        .get_checkpoint("identity-1", "INBOX")
        .expect("the checkpoint is read")
        .expect("the checkpoint is there");
    assert_eq!(checkpoint.upstream_cursor, "uid-from-the-backup");
    assert_eq!(store.integrity_check().expect("the integrity check"), "ok");
}

#[test]
fn an_emptied_ledger_is_refused() {
    let directory = directory("emptied-ledger");
    let path = directory.join("state.sqlite");
    let store = SqliteStore::open(&path).expect("the store opens");
    store
        .put_grant(&revocable_grant())
        .expect("the grant is stored");
    store
        .revoke_grant("grant-1", 200)
        .expect("the grant is revoked");
    drop(store);

    // The ledger was truncated. The database still records the revocation,
    // so it is ahead of its ledger, and the freshness of the database can
    // no longer be proven.
    std::fs::write(directory.join("state.sqlite.revocations"), b"").expect("the ledger is emptied");
    let error = SqliteStore::open(&path).expect_err("a database ahead of its ledger is refused");
    assert!(
        matches!(error, StorageError::Conflict(_)),
        "unexpected error: {error:?}"
    );
}

#[test]
fn a_restore_that_would_lose_a_revocation_is_refused() {
    let directory = directory("restore-ahead");
    let source = directory.join("source.sqlite");
    let backup = directory.join("backup.sqlite");
    let destination = directory.join("restored.sqlite");

    // The source has no revocations at all.
    {
        let store = SqliteStore::open(&source).expect("the store opens");
        store
            .put_grant(&revocable_grant())
            .expect("the grant is stored");
        store.backup_to(&backup).expect("the backup is written");
    }
    let ledger = directory.join("backup.sqlite.revocations");

    // The destination holds a revocation the backup does not have.
    {
        let store = SqliteStore::open(&destination).expect("the store opens");
        store
            .put_grant(&revocable_grant())
            .expect("the grant is stored");
        store
            .revoke_grant("grant-1", 200)
            .expect("the grant is revoked");
    }
    let error = SqliteStore::restore_from(&backup, &destination, &ledger)
        .expect_err("a restore that would lose a revocation is refused");
    assert!(
        matches!(error, StorageError::Conflict(_)),
        "unexpected error: {error:?}"
    );
    // The destination is untouched.
    let store = SqliteStore::open(&destination).expect("the store opens");
    let grant = store
        .get_grant("grant-1")
        .expect("the grant is read")
        .expect("the grant is there");
    assert_eq!(grant.revoked_at, Some(200));
}

#[test]
fn a_backup_that_is_not_a_database_is_refused() {
    let directory = directory("not-a-database");
    let source = directory.join("source.sqlite");
    let store = SqliteStore::open(&source).expect("the store opens");
    store
        .backup_to(directory.join("backup.sqlite"))
        .expect("the backup is written");
    let ledger = directory.join("backup.sqlite.revocations");
    let rubbish = directory.join("rubbish.sqlite");
    std::fs::write(&rubbish, b"this is not a database").expect("the file is written");
    let error = SqliteStore::restore_from(&rubbish, directory.join("restored.sqlite"), &ledger)
        .expect_err("a file that is not a database is refused");
    assert!(
        matches!(error, StorageError::Invalid(_)),
        "unexpected error: {error:?}"
    );
}

#[test]
fn a_submission_that_was_sent_is_not_queued_again() {
    let path = directory("not-queued-again").join("state.sqlite");
    let store = SqliteStore::open(&path).expect("the store opens");
    store
        .put_submission(&plain_submission("sub-1"))
        .expect("the submission is stored");
    let claimed = store
        .claim_next("worker-1", 200, 60)
        .expect("the submission is claimed")
        .expect("there is a submission to claim");
    store
        .transition("sub-1", SubmissionState::Submitted, 250, None)
        .expect("the submission is submitted");
    // Neither a transition nor a late report may put a submission that was
    // sent back into the queue: it would be sent a second time.
    assert!(matches!(
        store.transition("sub-1", SubmissionState::Reserved, 300, None),
        Err(StorageError::Conflict(_))
    ));
    assert!(matches!(
        store.release_claim(
            "sub-1",
            claimed.fencing_token,
            SubmissionState::Reserved,
            300,
            None,
        ),
        Err(StorageError::Conflict(_))
    ));
    // And it is not handed to another worker.
    assert!(
        store
            .claim_next("worker-2", 400, 60)
            .expect("the claim is taken")
            .is_none(),
        "a submission that was sent was claimed again"
    );
}

#[test]
fn a_stale_write_does_not_roll_the_state_back() {
    let store = SqliteStore::open_in_memory().expect("the store opens");
    // The revision of a grant only grows.
    let grant = Grant {
        revision: 3,
        ..revocable_grant()
    };
    store.put_grant(&grant).expect("the grant is stored");
    store
        .put_grant(&Grant {
            revision: 1,
            ..grant.clone()
        })
        .expect("the stale grant is accepted");
    assert_eq!(
        store
            .get_grant("grant-1")
            .expect("the grant is read")
            .expect("the grant is there")
            .revision,
        3
    );

    // The generation of a refresh family only grows, so the rotation stays
    // a compare-and-swap: a stale write cannot make the family rotatable
    // again.
    let family = RefreshFamily {
        family_id: "family-1".to_owned(),
        grant_id: "grant-1".to_owned(),
        generation: 2,
        current_token_hash: "hash-2".to_owned(),
        rotated_at: 200,
        revoked_at: None,
    };
    store
        .put_refresh_family(&family)
        .expect("the family is stored");
    store
        .put_refresh_family(&RefreshFamily {
            generation: 1,
            current_token_hash: "hash-1".to_owned(),
            ..family.clone()
        })
        .expect("the stale family is accepted");
    assert!(matches!(
        store.rotate_refresh("family-1", 1, "hash-3", 300),
        Err(StorageError::Conflict(_))
    ));
    let rotated = store
        .rotate_refresh("family-1", 2, "hash-3", 300)
        .expect("the family rotates");
    assert_eq!(rotated.generation, 3);

    // The record of an access token is written once: a later write does
    // not rebind the token to another grant or widen its scopes.
    let token = AccessToken {
        token_hash: "token-hash-1".to_owned(),
        grant_id: "grant-1".to_owned(),
        principal: "principal-1".to_owned(),
        scopes: vec!["mail:messages:read".to_owned()],
        expires_at: 1_000,
        revoked_at: None,
    };
    store.put_access_token(&token).expect("the token is stored");
    store
        .put_access_token(&AccessToken {
            grant_id: "grant-2".to_owned(),
            scopes: vec!["mail:messages:write".to_owned()],
            expires_at: 9_000,
            ..token.clone()
        })
        .expect("the stale token is accepted");
    let read = store
        .lookup_access_token("token-hash-1", 500)
        .expect("the token is looked up")
        .expect("the token is there");
    assert_eq!(read.grant_id, "grant-1");
    assert_eq!(read.scopes, vec!["mail:messages:read".to_owned()]);
    assert_eq!(read.expires_at, 1_000);
}

#[test]
fn a_reservation_that_does_not_match_the_intent_is_refused() {
    let store = SqliteStore::open_in_memory().expect("the store opens");
    let (reservation, submission) = keyed_pair("key-1", "digest-1", "sub-1");
    let mismatched = Submission {
        id: "sub-2".to_owned(),
        ..submission.clone()
    };
    let error = store
        .reserve_submission(&reservation, &mismatched)
        .expect_err("a reservation that does not match the intent is refused");
    assert!(
        matches!(error, StorageError::Invalid(_)),
        "unexpected error: {error:?}"
    );
    // Nothing was written: the key and the intent are one unit.
    assert!(
        store
            .lookup_idempotency("principal-1", "client-1", "identity-1", "key-1", 200)
            .expect("the reservation is read")
            .is_none()
    );
}

#[test]
fn the_database_and_its_files_are_owner_only() {
    let directory = directory("permissions");
    let path = directory.join("state.sqlite");
    let store = SqliteStore::open(&path).expect("the store opens");
    store
        .put_checkpoint(&Checkpoint {
            identity: "identity-1".to_owned(),
            mailbox: "INBOX".to_owned(),
            upstream_cursor: "uid-42".to_owned(),
            generation: 1,
            updated_at: 100,
        })
        .expect("the checkpoint is stored");
    let backup = directory.join("backup.sqlite");
    store.backup_to(&backup).expect("the backup is written");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for file in [
            path.clone(),
            directory.join("state.sqlite-wal"),
            directory.join("state.sqlite-shm"),
            directory.join("state.sqlite.writer.lock"),
            directory.join("state.sqlite.revocations"),
            backup.clone(),
            directory.join("backup.sqlite.revocations"),
        ] {
            let mode = std::fs::metadata(&file)
                .expect("the file is there")
                .permissions()
                .mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "the file {} is readable by other users",
                file.display()
            );
        }
    }
}

#[test]
fn a_stale_lock_file_does_not_allow_a_second_writer() {
    let path = directory("writer-stale").join("state.sqlite");
    // A writer crashed and left its lock file behind. The file alone must
    // not decide who may write.
    let lock = directory("writer-stale").join("state.sqlite.writer.lock");
    std::fs::write(&lock, "999999999").expect("the stale lock is written");
    let store = SqliteStore::open(&path).expect("the store opens past the stale lock");
    let error = SqliteStore::open(&path).expect_err("the second writer is refused");
    assert!(matches!(error, StorageError::Conflict(_)));
    drop(store);
}

#[test]
fn a_lock_file_that_names_a_live_process_does_not_lock_the_database_out() {
    let path = directory("writer-pid-reuse").join("state.sqlite");
    // A writer crashed and left its lock file behind. The process id in it
    // was taken over by another process that has nothing to do with this
    // database. The file must not decide who may write.
    let lock = directory("writer-pid-reuse").join("state.sqlite.writer.lock");
    std::fs::write(&lock, format!("{}", std::process::id())).expect("the stale lock is written");
    let store = SqliteStore::open(&path).expect("the store opens past the stale lock");
    let error = SqliteStore::open(&path).expect_err("the second writer is refused");
    assert!(matches!(error, StorageError::Conflict(_)));
    drop(store);
}

#[test]
fn a_postgres_configuration_is_refused_by_the_store() {
    let document = "\
apiVersion: corvi.naktis.eu/v1alpha1
kind: CorviStorage
state:
  backend: postgres
  postgres:
    dsnRef: secret://local/corvi-postgres-dsn
    tlsMode: verify-full
    poolSize: 8
    schema: corvi
secrets:
  backend: encryptedFile
  encryptedFile:
    path: /var/lib/corvi/secrets.enc
    wrappingKeyRef: secret://local/corvi-storage-key
blobs:
  backend: disabled
features:
  integratedOAuthIssuer: true
  durableSubmission: true
  durableTasks: false
  persistentMailboxSync: false
  persistInboundMail: false
  multiReplica: true
";
    let error = StorageConfig::from_yaml(document)
        .and_then(|config| Storage::open(&config).map(|_| ()))
        .expect_err("the PostgreSQL backend is not implemented");
    assert!(
        matches!(error, StorageError::Unsupported(_)),
        "unexpected error: {error:?}"
    );
}

#[test]
fn the_ephemeral_backend_holds_the_contract() {
    let store = SqliteStore::open_in_memory().expect("the store opens");
    conformance("ephemeral", &store);
}

#[test]
fn the_sqlite_backend_holds_the_contract() {
    let path = directory("sqlite").join("state.sqlite");
    let store = SqliteStore::open(&path).expect("the store opens");
    conformance("sqlite", &store);
}

#[test]
fn the_state_survives_a_restart() {
    let path = directory("restart").join("state.sqlite");
    {
        let store = SqliteStore::open(&path).expect("the store opens");
        store
            .put_checkpoint(&Checkpoint {
                identity: "identity-1".to_owned(),
                mailbox: "INBOX".to_owned(),
                upstream_cursor: "uid-42".to_owned(),
                generation: 1,
                updated_at: 100,
            })
            .expect("the checkpoint is stored");
        store
            .put_submission(&Submission {
                id: "sub-1".to_owned(),
                principal: "principal-1".to_owned(),
                identity: "identity-1".to_owned(),
                client_id: "client-1".to_owned(),
                idempotency_key: None,
                payload_digest: None,
                state: SubmissionState::Unknown,
                upstream_protocol: None,
                attempts: 1,
                lease_owner: None,
                lease_expires_at: None,
                fencing_token: 0,
                created_at: 100,
                updated_at: 100,
                failure_code: None,
            })
            .expect("the submission is stored");
    }
    let store = SqliteStore::open(&path).expect("the store reopens");
    let checkpoint = store
        .get_checkpoint("identity-1", "INBOX")
        .expect("the checkpoint is read")
        .expect("the checkpoint survived");
    assert_eq!(checkpoint.upstream_cursor, "uid-42");
    let unknown = store.list_unknown().expect("the unknown list");
    assert_eq!(unknown.len(), 1);
    assert_eq!(unknown[0].id, "sub-1");
}

#[test]
fn the_schema_is_migrated_and_versioned() {
    let path = directory("migration").join("state.sqlite");
    let store = SqliteStore::open(&path).expect("the store opens");
    assert_eq!(
        store.schema_version().expect("the version is read"),
        SCHEMA_VERSION
    );
    // Opening again does not migrate twice.
    drop(store);

    let store = SqliteStore::open(&path).expect("the store reopens");
    assert_eq!(
        store.schema_version().expect("the version is read"),
        SCHEMA_VERSION
    );
    assert_eq!(store.integrity_check().expect("the integrity check"), "ok");
}

#[test]
fn a_second_writer_is_refused() {
    let path = directory("writer").join("state.sqlite");
    let store = SqliteStore::open(&path).expect("the store opens");
    let error = SqliteStore::open(&path).expect_err("the second writer is refused");
    assert!(matches!(error, StorageError::Conflict(_)));
    drop(store);
    // Once the first writer is gone, the lock may be taken over.
    let store = SqliteStore::open(&path).expect("the store opens again");
    assert!(store.integrity_check().expect("the integrity check") == "ok");
}

#[test]
fn the_schema_holds_no_inbound_mail() {
    let path = directory("inbound").join("state.sqlite");
    let _store = SqliteStore::open(&path).expect("the store opens");
    let connection = rusqlite::Connection::open(&path).expect("the database opens");
    let mut statement = connection
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
        .expect("the tables list");
    let tables = statement
        .query_map([], |row| row.get::<_, String>(0))
        .expect("the tables list")
        .collect::<Result<Vec<_>, _>>()
        .expect("the tables list");
    for table in tables {
        assert!(
            !table.contains("raw_mail")
                && !table.contains("mime")
                && !table.contains("inbound")
                && !table.contains("message_body"),
            "the schema holds an inbound mail table: {table}"
        );
    }
}

/// A grant that is stored by the restore tests.
fn revocable_grant() -> Grant {
    Grant {
        grant_id: "grant-1".to_owned(),
        client_id: "client-1".to_owned(),
        principal: "principal-1".to_owned(),
        identity: "identity-1".to_owned(),
        scopes: vec!["mail:messages:read".to_owned()],
        revision: 1,
        created_at: 100,
        revoked_at: None,
    }
}

#[test]
fn a_backup_that_predates_a_revocation_is_refused() {
    let directory = directory("stale-backup");
    let path = directory.join("state.sqlite");
    let backup = directory.join("backup.sqlite");
    let store = SqliteStore::open(&path).expect("the store opens");
    store
        .put_grant(&revocable_grant())
        .expect("the grant is stored");
    store.backup_to(&backup).expect("the backup is written");
    // The revocation happens after the backup was taken, so the backup
    // still holds a grant that was consented.
    store
        .revoke_grant("grant-1", 200)
        .expect("the grant is revoked");
    let ledger = store
        .revocation_ledger_path()
        .expect("the ledger is there")
        .to_path_buf();
    drop(store);

    let restored = directory.join("restored.sqlite");
    let error = SqliteStore::restore_from(&backup, &restored, &ledger)
        .expect_err("a backup that predates a revocation is refused");
    assert!(
        matches!(error, StorageError::Conflict(_)),
        "unexpected error: {error:?}"
    );
    assert!(!restored.exists(), "the stale backup was restored");
}

#[test]
fn a_restore_without_a_ledger_is_refused() {
    let directory = directory("no-ledger");
    let path = directory.join("state.sqlite");
    let backup = directory.join("backup.sqlite");
    let store = SqliteStore::open(&path).expect("the store opens");
    store
        .put_grant(&revocable_grant())
        .expect("the grant is stored");
    store.backup_to(&backup).expect("the backup is written");
    drop(store);

    // The ledger of the deployment is gone, so the freshness of the backup
    // cannot be established.
    let ledger = directory.join("state.sqlite.revocations");
    std::fs::remove_file(&ledger).expect("the ledger is removed");
    let restored = directory.join("restored.sqlite");
    let error = SqliteStore::restore_from(&backup, &restored, &ledger)
        .expect_err("a restore without a ledger is refused");
    assert!(
        matches!(error, StorageError::Unsupported(_)),
        "unexpected error: {error:?}"
    );
    assert!(!restored.exists(), "the restore happened without a ledger");
}

#[test]
fn a_current_backup_restores_with_the_revocation_intact() {
    let directory = directory("current-backup");
    let path = directory.join("state.sqlite");
    let backup = directory.join("backup.sqlite");
    let store = SqliteStore::open(&path).expect("the store opens");
    store
        .put_grant(&revocable_grant())
        .expect("the grant is stored");
    store
        .revoke_grant("grant-1", 200)
        .expect("the grant is revoked");
    store.backup_to(&backup).expect("the backup is written");
    let ledger = store
        .revocation_ledger_path()
        .expect("the ledger is there")
        .to_path_buf();
    drop(store);

    let restored = directory.join("restored.sqlite");
    SqliteStore::restore_from(&backup, &restored, &ledger).expect("the backup is restored");

    let store = SqliteStore::open(&restored).expect("the restored store opens");
    let grant = store
        .get_grant("grant-1")
        .expect("the grant is read")
        .expect("the grant is there");
    assert_eq!(
        grant.revoked_at,
        Some(200),
        "the revocation did not survive the restore"
    );
    assert!(
        store
            .revoked_after(150)
            .expect("the revocations list")
            .iter()
            .any(|revocation| revocation.subject == "grant-1"),
        "the revocation did not survive the restore"
    );
}

#[test]
fn a_database_whose_ledger_is_lost_is_refused() {
    let directory = directory("lost-ledger");
    let path = directory.join("state.sqlite");
    let store = SqliteStore::open(&path).expect("the store opens");
    store
        .put_grant(&revocable_grant())
        .expect("the grant is stored");
    store
        .revoke_grant("grant-1", 200)
        .expect("the grant is revoked");
    drop(store);

    // The ledger was lost. The database still records the revocation, and
    // nothing can prove that it is the only one, so the store refuses to
    // open rather than carry on without the authority.
    std::fs::remove_file(directory.join("state.sqlite.revocations"))
        .expect("the ledger is removed");
    let error = SqliteStore::open(&path).expect_err("a database without its ledger is refused");
    assert!(
        matches!(error, StorageError::Conflict(_)),
        "unexpected error: {error:?}"
    );
}

#[test]
fn a_revoked_access_token_is_recorded_outside_the_database() {
    let directory = directory("token-ledger");
    let path = directory.join("state.sqlite");
    let store = SqliteStore::open(&path).expect("the store opens");
    store
        .put_access_token(&AccessToken {
            token_hash: "token-hash-1".to_owned(),
            grant_id: "grant-1".to_owned(),
            principal: "principal-1".to_owned(),
            scopes: vec!["mail:messages:read".to_owned()],
            expires_at: 1_000,
            revoked_at: Some(300),
        })
        .expect("the revoked token is stored");
    let ledger =
        RevocationLedger::open(store.revocation_ledger_path().expect("the ledger is there"))
            .expect("the ledger opens");
    let entries = ledger.entries().expect("the entries");
    assert!(
        entries.iter().any(|entry| entry.subject == "token-hash-1"
            && entry.kind == "accessToken"
            && entry.at == 300),
        "the revocation of the token was not recorded: {entries:?}"
    );
}

#[test]
fn an_uncertain_send_is_not_reopened_by_a_late_worker() {
    let path = directory("monotonic").join("state.sqlite");
    let store = SqliteStore::open(&path).expect("the store opens");
    store
        .put_submission(&Submission {
            id: "sub-1".to_owned(),
            principal: "principal-1".to_owned(),
            identity: "identity-1".to_owned(),
            client_id: "client-1".to_owned(),
            idempotency_key: None,
            payload_digest: None,
            state: SubmissionState::Reserved,
            upstream_protocol: Some("smtp".to_owned()),
            attempts: 0,
            lease_owner: None,
            lease_expires_at: None,
            fencing_token: 0,
            created_at: 100,
            updated_at: 100,
            failure_code: None,
        })
        .expect("the submission is stored");
    let claimed = store
        .claim_next("worker-1", 200, 60)
        .expect("the submission is claimed")
        .expect("there is a submission to claim");
    // The worker cannot say what happened to the message, so the send stays
    // uncertain.
    store
        .release_claim(
            "sub-1",
            claimed.fencing_token,
            SubmissionState::Unknown,
            300,
            None,
        )
        .expect("the claim is released");

    // A late report may not turn the uncertain send back into a sendable
    // one: the message may have been delivered.
    let error = store
        .release_claim(
            "sub-1",
            claimed.fencing_token,
            SubmissionState::Reserved,
            400,
            None,
        )
        .expect_err("an uncertain send is not reopened");
    assert!(
        matches!(error, StorageError::Conflict(_)),
        "unexpected error: {error:?}"
    );
    assert_eq!(
        store
            .get_submission("sub-1")
            .expect("the submission is read")
            .expect("the submission is there")
            .state,
        SubmissionState::Unknown
    );
    // And it is not handed out to another worker.
    assert!(
        store
            .claim_next("worker-2", 500, 60)
            .expect("the claim is taken")
            .is_none(),
        "an uncertain send was claimed again"
    );
}
