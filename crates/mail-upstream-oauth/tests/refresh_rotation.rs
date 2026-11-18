//! Encrypted, recoverable, atomically rotated refresh credentials.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use mail_storage::{
    ConnectionStatus, ProviderConnection, ProviderConnectionStore, RefreshState, SecretRef,
    SecretStore, SqliteStore, StorageResult,
};
use mail_upstream_oauth::clock::FixedClock;
use mail_upstream_oauth::error::UpstreamOAuthError;
use mail_upstream_oauth::onboarding::DeliveryReceipt;
use mail_upstream_oauth::profile::ProviderRegistry;
use mail_upstream_oauth::testing::{FixtureTransport, MapClientSecrets};
use mail_upstream_oauth::token_broker::{
    REFRESH_SECRET_OWNER, RecoveryOutcome, RotationOutcome, TokenBroker, refresh_secret_aad,
};

use common::*;

/// A store that can be told to refuse a commit, which is what the crash
/// window looks like from inside a rotation.
#[derive(Debug)]
struct FlakyCommitStore {
    inner: Arc<SqliteStore>,
    fail_commit: AtomicBool,
}

impl FlakyCommitStore {
    fn new(inner: Arc<SqliteStore>) -> Self {
        Self {
            inner,
            fail_commit: AtomicBool::new(false),
        }
    }
}

impl ProviderConnectionStore for FlakyCommitStore {
    fn put_connection(&self, connection: &ProviderConnection) -> StorageResult<()> {
        self.inner.put_connection(connection)
    }

    fn get_connection(&self, connection_id: &str) -> StorageResult<Option<ProviderConnection>> {
        self.inner.get_connection(connection_id)
    }

    fn list_connections(&self, identity: &str) -> StorageResult<Vec<ProviderConnection>> {
        self.inner.list_connections(identity)
    }

    fn put_refresh_state(&self, state: &RefreshState) -> StorageResult<()> {
        self.inner.put_refresh_state(state)
    }

    fn get_refresh_state(&self, connection_id: &str) -> StorageResult<Option<RefreshState>> {
        self.inner.get_refresh_state(connection_id)
    }

    fn claim_refresh(
        &self,
        connection_id: &str,
        generation: u64,
        owner: &str,
    ) -> StorageResult<bool> {
        self.inner.claim_refresh(connection_id, generation, owner)
    }

    fn complete_refresh(
        &self,
        connection_id: &str,
        generation: u64,
        owner: &str,
        secret_ref: &str,
        expires_at: u64,
        now: u64,
    ) -> StorageResult<bool> {
        if self.fail_commit.load(Ordering::SeqCst) {
            return Ok(false);
        }
        self.inner.complete_refresh(
            connection_id,
            generation,
            owner,
            secret_ref,
            expires_at,
            now,
        )
    }

    fn mark_needs_reauthorization(&self, connection_id: &str, now: u64) -> StorageResult<bool> {
        self.inner.mark_needs_reauthorization(connection_id, now)
    }

    fn disconnect(&self, connection_id: &str, now: u64) -> StorageResult<bool> {
        self.inner.disconnect(connection_id, now)
    }
}

struct World {
    broker: TokenBroker,
    connections: Arc<FlakyCommitStore>,
    raw_connections: Arc<SqliteStore>,
    secrets: Arc<dyn SecretStore>,
    transport: Arc<FixtureTransport>,
    secret_path: std::path::PathBuf,
}

fn world() -> World {
    let clock = Arc::new(FixedClock::new(NOW));
    let transport = gmail_transport();
    let (_service, escrow) = gmail_service(transport.clone(), clock.clone());
    let (secrets, secret_path) = secret_store("rotation");
    let secrets: Arc<dyn SecretStore> = Arc::new(secrets);
    let raw_connections = connection_store();
    let connections = Arc::new(FlakyCommitStore::new(raw_connections.clone()));
    let registry = Arc::new(ProviderRegistry::builtin());
    let broker = TokenBroker::new(
        connections.clone(),
        secrets.clone(),
        transport.clone(),
        registry,
        Arc::new(mail_upstream_oauth::onboarding::RoleAuthorizer),
        Arc::new(MapClientSecrets::new()),
        escrow,
        clock.clone(),
    );
    World {
        broker,
        connections,
        raw_connections,
        secrets,
        transport,
        secret_path,
    }
}

fn seed_connection(
    connections: &dyn ProviderConnectionStore,
    secrets: &dyn SecretStore,
) -> DeliveryReceipt {
    let connection_id = "rotation-connection".to_owned();
    let aad = refresh_secret_aad("gmail", &connection_id, "identity-1");
    let reference = secrets
        .put(
            REFRESH_SECRET_OWNER,
            &connection_id,
            FIRST_REFRESH_TOKEN.as_bytes(),
            &aad,
        )
        .unwrap();
    let secret_ref = format!(
        "{}/{}@{}",
        reference.owner, reference.name, reference.version
    );
    connections
        .put_refresh_state(&RefreshState {
            connection_id: connection_id.clone(),
            generation: 0,
            secret_ref: secret_ref.clone(),
            expires_at: NOW + 3600,
            needs_reauthorization: false,
        })
        .unwrap();
    connections
        .put_connection(&ProviderConnection {
            connection_id: connection_id.clone(),
            provider: "gmail".into(),
            account_ref: ACCOUNT.into(),
            identity: "identity-1".into(),
            capabilities: vec!["read".into()],
            status: ConnectionStatus::Active,
            generation: 0,
            updated_at: NOW,
        })
        .unwrap();
    DeliveryReceipt {
        connection_id,
        provider: "gmail".into(),
        secret_ref,
        expires_at: Some(NOW + 3600),
        generation: 0,
    }
}

fn connect(world: &World) -> DeliveryReceipt {
    seed_connection(world.raw_connections.as_ref(), world.secrets.as_ref())
}

#[test]
fn credential_is_encrypted_and_rotation_uses_it() {
    let world = world();
    let receipt = connect(&world);
    let connection_id = receipt.connection_id.clone();

    let contents = std::fs::read_to_string(&world.secret_path).expect("the secret file is there");
    assert!(
        !contents.contains(FIRST_REFRESH_TOKEN),
        "the refresh credential is never in the file"
    );

    let recovery = world
        .broker
        .recover(&connection_id)
        .expect("the recovery check runs");
    assert!(matches!(
        recovery,
        RecoveryOutcome::NeedsReauthorization { .. }
    ));

    world.transport.clear();
    let outcome = world
        .broker
        .rotate(&connection_id, "worker-1")
        .expect("the rotation works");
    match &outcome {
        RotationOutcome::Committed {
            generation,
            secret_ref,
            ..
        } => {
            assert_eq!(*generation, 1);
            assert!(secret_ref.ends_with("@2"), "{secret_ref}");
        }
        other => panic!("expected Committed, got {other:?}"),
    }

    let refresh = world
        .transport
        .requests()
        .into_iter()
        .find(|request| request.form_value("grant_type") == Some("refresh_token"))
        .expect("the rotation refreshed the credential");
    assert_eq!(
        refresh.form_value("refresh_token"),
        Some(FIRST_REFRESH_TOKEN),
        "the rotation used the credential that was stored"
    );

    // The new credential is on disk encrypted, and the old one is gone.
    let contents = std::fs::read_to_string(&world.secret_path).expect("the secret file is there");
    assert!(!contents.contains(FIRST_REFRESH_TOKEN));
    assert!(!contents.contains("rt-second-credential"));

    let state = world
        .raw_connections
        .get_refresh_state(&connection_id)
        .expect("the refresh state is there")
        .expect("the connection has a refresh state");
    assert_eq!(state.generation, 1);
    assert!(!state.needs_reauthorization);
}

#[test]
fn a_rotation_is_a_compare_and_swap_on_the_generation() {
    let world = world();
    let receipt = connect(&world);
    let connection_id = receipt.connection_id.clone();

    world
        .broker
        .rotate(&connection_id, "worker-1")
        .expect("the first rotation commits");
    let outcome = world
        .broker
        .rotate(&connection_id, "worker-2")
        .expect("a second rotation after the first commits");
    assert!(matches!(
        outcome,
        RotationOutcome::Committed { generation: 2, .. }
    ));

    let connection = world
        .raw_connections
        .get_connection(&connection_id)
        .expect("the connection is there")
        .expect("the connection is recorded");
    assert_eq!(connection.generation, 2);
    assert_eq!(connection.status, ConnectionStatus::Active);
}

#[test]
fn two_workers_cannot_both_rotate() {
    let world = world();
    let receipt = connect(&world);
    let connection_id = receipt.connection_id.clone();

    // Worker A claims the current generation and is mid-rotation.
    let claimed = world
        .raw_connections
        .claim_refresh(&connection_id, 0, "worker-a")
        .expect("the claim runs");
    assert!(claimed, "worker A holds the claim");

    // Worker B must not talk to the provider at all.
    world.transport.clear();
    let outcome = world
        .broker
        .rotate(&connection_id, "worker-b")
        .expect("the rotation is reported, not failed");
    assert_eq!(
        outcome,
        RotationOutcome::AlreadyRotated { generation: 0 },
        "worker B does not refresh behind worker A's back"
    );
    assert_eq!(
        world.transport.request_count(),
        0,
        "the provider was never asked for a second credential"
    );

    // Worker A finishes its rotation.
    let aad = refresh_secret_aad("gmail", &connection_id, "identity-1");
    let reference = world
        .secrets
        .put(
            REFRESH_SECRET_OWNER,
            &connection_id,
            b"rt-from-worker-a",
            &aad,
        )
        .expect("worker A stores its credential");
    let committed = world
        .raw_connections
        .complete_refresh(
            &connection_id,
            0,
            "worker-a",
            &format!(
                "{}/{}@{}",
                REFRESH_SECRET_OWNER, connection_id, reference.version
            ),
            NOW + 3600,
            NOW,
        )
        .expect("the commit runs");
    assert!(committed, "worker A's commit succeeds");
}

#[test]
fn an_uncommitted_rotation_needs_reauthorization() {
    let world = world();
    let receipt = connect(&world);
    let connection_id = receipt.connection_id.clone();

    // The commit is lost, which is the crash window: the provider has
    // already invalidated the credential the connection still names.
    world.connections.fail_commit.store(true, Ordering::SeqCst);
    let error = world
        .broker
        .rotate(&connection_id, "worker-1")
        .expect_err("a rotation that cannot be committed does not pretend it did");
    match &error {
        UpstreamOAuthError::NeedsReauthorization {
            connection_id,
            reason,
        } => {
            assert_eq!(connection_id, &receipt.connection_id);
            assert!(reason.contains("could not be committed"), "{reason}");
        }
        other => panic!("expected NeedsReauthorization, got {other:?}"),
    }
    assert_eq!(error.status().as_str(), "needsReauthorization");

    let connection = world
        .raw_connections
        .get_connection(&receipt.connection_id)
        .expect("the connection is there")
        .expect("the connection is recorded");
    assert_eq!(connection.status, ConnectionStatus::NeedsReauthorization);

    // The broker does not reuse the credential it already gave away: the
    // next rotation refuses without asking the provider anything.
    world.transport.clear();
    world.connections.fail_commit.store(false, Ordering::SeqCst);
    let error = world
        .broker
        .rotate(&connection_id, "worker-2")
        .expect_err("the connection is marked");
    assert!(matches!(
        error,
        UpstreamOAuthError::NeedsReauthorization { .. }
    ));
    assert_eq!(
        world.transport.request_count(),
        0,
        "no credential was sent to the provider again"
    );
}

#[test]
fn recovery_refuses_even_when_rotation_is_interrupted() {
    let world = world();
    let receipt = connect(&world);
    let connection_id = receipt.connection_id.clone();

    // A rotation wrote its new credential and crashed before the commit:
    // the store now holds a credential the refresh state does not name.
    let aad = refresh_secret_aad("gmail", &connection_id, "identity-1");
    let orphan = world
        .secrets
        .put(
            REFRESH_SECRET_OWNER,
            &connection_id,
            b"rt-uncommitted",
            &aad,
        )
        .expect("the interrupted rotation left a credential");

    let recovery = world
        .broker
        .recover(&connection_id)
        .expect("the recovery check runs");
    match &recovery {
        RecoveryOutcome::NeedsReauthorization { reason } => {
            assert!(reason.contains("atomic coordination"), "{reason}");
        }
        other => panic!("expected NeedsReauthorization, got {other:?}"),
    }
    let _ = orphan;

    let connection = world
        .raw_connections
        .get_connection(&connection_id)
        .expect("the connection is there")
        .expect("the connection is recorded");
    assert_eq!(connection.status, ConnectionStatus::Active);
}

#[test]
fn an_invalid_grant_fails_closed() {
    let clock = Arc::new(FixedClock::new(NOW));
    let transport = gmail_transport_with(|transport| {
        transport.route_form(
            mail_upstream_oauth::transport::HttpMethod::Post,
            "https://oauth2.googleapis.com/token",
            "grant_type=refresh_token",
            mail_upstream_oauth::transport::OAuthResponse::json(
                400,
                &mail_upstream_oauth::testing::error_response("invalid_grant"),
            ),
        )
    });
    let (_service, escrow) = gmail_service(transport.clone(), clock.clone());
    let (secrets, _path) = secret_store("invalid-grant");
    let secrets: Arc<dyn SecretStore> = Arc::new(secrets);
    let connections = connection_store();
    let registry = Arc::new(ProviderRegistry::builtin());
    let token_broker = TokenBroker::new(
        connections.clone(),
        secrets.clone(),
        transport,
        registry,
        Arc::new(mail_upstream_oauth::onboarding::RoleAuthorizer),
        Arc::new(MapClientSecrets::new()),
        escrow,
        clock,
    );
    let receipt = seed_connection(connections.as_ref(), secrets.as_ref());

    let error = token_broker
        .rotate(&receipt.connection_id, "worker-1")
        .expect_err("a refused refresh fails closed");
    assert!(matches!(
        error,
        UpstreamOAuthError::NeedsReauthorization { .. }
    ));

    let connection = connections
        .get_connection(&receipt.connection_id)
        .expect("the connection is there")
        .expect("the connection is recorded");
    assert_eq!(connection.status, ConnectionStatus::NeedsReauthorization);

    let state = connections
        .get_refresh_state(&receipt.connection_id)
        .expect("the refresh state is there")
        .expect("the connection has a refresh state");
    assert!(state.needs_reauthorization);
}

#[test]
fn a_missing_credential_needs_reauthorization() {
    let world = world();
    let receipt = connect(&world);
    let connection_id = receipt.connection_id.clone();

    let references = world
        .secrets
        .list(REFRESH_SECRET_OWNER)
        .expect("the secret store lists its credentials");
    for reference in references {
        let removed = world
            .secrets
            .delete(&SecretRef {
                owner: reference.owner,
                name: reference.name,
                key_id: reference.key_id,
                version: reference.version,
            })
            .expect("the credential is removed");
        assert!(removed);
    }

    let error = world
        .broker
        .rotate(&connection_id, "worker-1")
        .expect_err("a connection without a credential cannot refresh");
    assert!(matches!(
        error,
        UpstreamOAuthError::NeedsReauthorization { .. }
    ));
    let connection = world
        .raw_connections
        .get_connection(&connection_id)
        .expect("the connection is there")
        .expect("the connection is recorded");
    assert_eq!(connection.status, ConnectionStatus::NeedsReauthorization);
}

#[test]
fn no_credential_appears_in_the_rotation_output() {
    let world = world();
    let receipt = connect(&world);
    let outcome = world
        .broker
        .rotate(&receipt.connection_id, "worker-1")
        .expect("the rotation works");
    let printed = format!("{outcome:?}");
    assert!(!printed.contains(FIRST_REFRESH_TOKEN), "{printed}");
    assert!(!printed.contains("rt-second-credential"), "{printed}");
    assert!(!printed.contains("at-second-credential"), "{printed}");

    for request in world.transport.requests() {
        let printed = format!("{request:?}");
        assert!(
            !printed.contains(FIRST_REFRESH_TOKEN) && !printed.contains("rt-second-credential"),
            "a recorded request must not print its credential: {printed}"
        );
    }
}

#[test]
fn recovery_refuses_an_outstanding_refresh_claim() {
    let world = world();
    let receipt = connect(&world);
    assert!(
        world
            .raw_connections
            .claim_refresh(&receipt.connection_id, 0, "crashed-worker")
            .unwrap()
    );
    assert!(matches!(
        world.broker.recover(&receipt.connection_id).unwrap(),
        RecoveryOutcome::NeedsReauthorization { .. }
    ));
}

#[test]
fn ambiguous_provider_failure_does_not_report_recoverable() {
    let clock = Arc::new(FixedClock::new(NOW));
    let transport = gmail_transport_with(|transport| {
        transport.route_failure(
            mail_upstream_oauth::transport::HttpMethod::Post,
            "https://oauth2.googleapis.com/token",
            mail_upstream_oauth::transport::TransportFailure::new("connection lost after request"),
        )
    });
    let (_service, escrow) = gmail_service(transport.clone(), clock.clone());
    let (secrets, _) = secret_store("ambiguous-refresh");
    let secrets: Arc<dyn SecretStore> = Arc::new(secrets);
    let connections = connection_store();
    let receipt = seed_connection(connections.as_ref(), secrets.as_ref());
    let broker = TokenBroker::new(
        connections.clone(),
        secrets,
        transport,
        Arc::new(ProviderRegistry::builtin()),
        Arc::new(mail_upstream_oauth::onboarding::RoleAuthorizer),
        Arc::new(MapClientSecrets::new()),
        escrow,
        clock,
    );
    assert!(broker.rotate(&receipt.connection_id, "worker").is_err());
    assert!(matches!(
        broker.recover(&receipt.connection_id).unwrap(),
        RecoveryOutcome::NeedsReauthorization { .. }
    ));
    assert!(
        !connections
            .claim_refresh(&receipt.connection_id, 0, "another-worker")
            .unwrap()
    );
}
