//! Privileged onboarding is separate from scoped secret delivery.

mod common;

use std::sync::Arc;

use mail_storage::SecretStore;
use mail_upstream_oauth::clock::FixedClock;
use mail_upstream_oauth::error::UpstreamOAuthError;
use mail_upstream_oauth::profile::ProviderRegistry;
use mail_upstream_oauth::testing::MapClientSecrets;
use mail_upstream_oauth::token_broker::TokenBroker;

use common::*;

struct Fixtures {
    service: mail_upstream_oauth::onboarding::OnboardingService,
    broker: TokenBroker,
    escrow: Arc<mail_upstream_oauth::onboarding::DeliveryEscrow>,
    secrets: Arc<dyn SecretStore>,
}

fn fixtures() -> Fixtures {
    let clock = Arc::new(FixedClock::new(NOW));
    let transport = gmail_transport();
    let (service, escrow) = gmail_service(transport.clone(), clock.clone());
    let (secrets, _secret_path) = secret_store("onboarding");
    let secrets: Arc<dyn SecretStore> = Arc::new(secrets);
    let registry = Arc::new(ProviderRegistry::builtin());
    let broker = TokenBroker::new(
        connection_store(),
        secrets.clone(),
        transport.clone(),
        registry,
        Arc::new(mail_upstream_oauth::onboarding::RoleAuthorizer),
        Arc::new(MapClientSecrets::new()),
        escrow.clone(),
        clock,
    );
    Fixtures {
        service,
        broker,
        escrow,
        secrets,
    }
}

#[test]
fn an_onboarding_admin_may_complete_but_not_deliver() {
    let fixtures = fixtures();
    let callback = authorize(&fixtures.service);
    let outcome = fixtures
        .service
        .complete(&callback)
        .expect("the onboarding completes");

    let error = fixtures
        .broker
        .deliver(&outcome.delivery_ticket, &admin())
        .expect_err("the onboarding administrator may not take the credential");
    match &error {
        UpstreamOAuthError::NotAuthorized { principal, action } => {
            assert_eq!(principal, "admin-1");
            assert_eq!(*action, "deliver a scoped secret");
        }
        other => panic!("expected NotAuthorized, got {other:?}"),
    }
    assert_eq!(error.status().as_str(), "unavailable");
}

#[test]
fn a_mailbox_reader_may_do_neither() {
    let fixtures = fixtures();
    let mut request = gmail_request();
    request.principal = reader();
    let error = fixtures
        .service
        .start(&request)
        .expect_err("a mailbox reader may not start an onboarding");
    assert!(matches!(error, UpstreamOAuthError::NotAuthorized { .. }));

    let error = fixtures
        .broker
        .deliver("any-ticket", &reader())
        .expect_err("a mailbox reader may not take a credential");
    assert!(matches!(error, UpstreamOAuthError::NotAuthorized { .. }));
}

#[test]
fn unsupported_delivery_preserves_ticket_and_writes_no_secret() {
    let fixtures = fixtures();
    let outcome = fixtures
        .service
        .complete(&authorize(&fixtures.service))
        .unwrap();
    for _ in 0..2 {
        let error = fixtures
            .broker
            .deliver(&outcome.delivery_ticket, &broker())
            .unwrap_err();
        assert!(
            matches!(error, UpstreamOAuthError::Storage { ref reason } if reason.contains("durable connection store"))
        );
    }
    assert!(
        fixtures
            .escrow
            .peek(&outcome.delivery_ticket, NOW)
            .unwrap()
            .is_some()
    );
    assert!(
        fixtures
            .secrets
            .list(mail_upstream_oauth::token_broker::REFRESH_SECRET_OWNER)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn the_outcome_and_the_ticket_carry_no_token() {
    let fixtures = fixtures();
    let callback = authorize(&fixtures.service);
    let outcome = fixtures
        .service
        .complete(&callback)
        .expect("the onboarding completes");

    let printed = format!("{outcome:?}");
    assert!(!printed.contains(ACCESS_TOKEN), "{printed}");
    assert!(!printed.contains(FIRST_REFRESH_TOKEN), "{printed}");
    assert!(
        !printed.contains("access_token") && !printed.contains("refresh_token"),
        "the outcome has no token field at all: {printed}"
    );

    // The ticket is opaque: it carries no credential material and no
    // reference to one.
    let printed = format!("{:?}", outcome.delivery_ticket);
    assert!(!printed.contains(FIRST_REFRESH_TOKEN), "{printed}");
    assert!(!printed.contains(ACCESS_TOKEN), "{printed}");
}

#[test]
fn a_credential_that_arrived_in_a_handoff_takes_the_same_delivery_path() {
    let escrow = Arc::new(mail_upstream_oauth::onboarding::DeliveryEscrow::new());
    let guard = mail_upstream_oauth::handoff::DurableOneTimeUseGuard::over(Arc::new(
        mail_storage::SqliteStore::open(std::env::temp_dir().join(format!(
            "corvi-handoff-accept-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )))
        .unwrap(),
    ))
    .unwrap();
    let key = b"a shared key that is long enough";

    // The companion CLI sealed the credential on its own machine.
    let payload = mail_upstream_oauth::handoff::HandoffPayload {
        provider: "gmail".to_owned(),
        connection_id: "conn-handoff".to_owned(),
        identity: "identity-1".to_owned(),
        expected_account: ACCOUNT.to_owned(),
        capabilities: vec![mail_upstream_oauth::scope::Capability::Read],
        tokens: mail_upstream_oauth::flow::ProviderTokens {
            access_token: ACCESS_TOKEN.to_owned(),
            refresh_token: Some(FIRST_REFRESH_TOKEN.to_owned()),
            expires_at: Some(NOW + 3600),
            scopes: vec!["https://mail.google.com/".to_owned()],
        },
    };
    let envelope =
        mail_upstream_oauth::handoff::issue_handoff(&payload, key, "controller-1", NOW, 120)
            .expect("the handoff is issued");

    let ticket = escrow
        .accept_handoff(
            &envelope,
            key,
            "controller-1",
            NOW,
            &mail_upstream_oauth::handoff::HandoffLifetime::unbounded(),
            &guard,
        )
        .expect("a durable guard redeems the handoff and escrows the credential");
    assert!(!ticket.is_empty());
    assert!(!escrow.is_empty(), "the credential sits in the escrow");

    // A replay — the same envelope, even over the same durable guard — is
    // refused and escrows nothing.
    let error = escrow
        .accept_handoff(
            &envelope,
            key,
            "controller-1",
            NOW,
            &mail_upstream_oauth::handoff::HandoffLifetime::unbounded(),
            &guard,
        )
        .expect_err("a redeemed handoff does not redeem twice");
    assert!(matches!(
        error,
        UpstreamOAuthError::HandoffRejected {
            reason: mail_upstream_oauth::error::HandoffFailure::Replayed
        }
    ));
}

#[test]
fn a_credential_without_a_refresh_token_is_not_delivered() {
    let clock = Arc::new(FixedClock::new(NOW));
    let transport = gmail_transport_with(|transport| {
        transport.route_form(
            mail_upstream_oauth::transport::HttpMethod::Post,
            "https://oauth2.googleapis.com/token",
            "grant_type=authorization_code",
            mail_upstream_oauth::transport::OAuthResponse::json(
                200,
                &mail_upstream_oauth::testing::token_response(
                    "at-1",
                    None,
                    Some(3600),
                    Some("https://mail.google.com/"),
                ),
            ),
        )
    });
    let (service, escrow) = gmail_service(transport.clone(), clock.clone());
    let (secrets, _path) = secret_store("no-refresh");
    let registry = Arc::new(ProviderRegistry::builtin());
    let token_broker = TokenBroker::new(
        durable_connection_store(),
        Arc::new(secrets),
        transport,
        registry,
        Arc::new(mail_upstream_oauth::onboarding::RoleAuthorizer),
        Arc::new(MapClientSecrets::new()),
        escrow,
        clock,
    );
    let callback = authorize(&service);
    let outcome = service
        .complete(&callback)
        .expect("the onboarding completes");
    let error = token_broker
        .deliver(&outcome.delivery_ticket, &broker())
        .expect_err("a connection without a refresh credential cannot be stored");
    assert!(
        matches!(error, UpstreamOAuthError::Storage { ref reason } if reason.contains("no refresh token"))
    );
}

/// Two deliveries of one ticket at once.
///
/// The file secret store keeps one versioned envelope per owner and name:
/// a second write replaces the envelope and raises its version, and a
/// reference that names the old version no longer opens anything. So a
/// delivery that writes the credential while another delivery of the same
/// ticket is still in flight must not be possible: the loser would leave
/// the winner's reference pointing at an envelope that no longer exists.

#[test]
fn direct_claim_cannot_bypass_delivery_window() {
    use mail_upstream_oauth::onboarding::DeliveryEscrow;
    use std::sync::{Arc, mpsc};
    use std::time::Duration;
    let escrow = Arc::new(DeliveryEscrow::new());
    let window = escrow.delivery_window().unwrap();
    let (send, recv) = mpsc::channel();
    let other = escrow.clone();
    let thread = std::thread::spawn(move || {
        let _ = other.claim("missing", NOW);
        send.send(()).unwrap();
    });
    let blocked = recv.recv_timeout(Duration::from_millis(100)).is_err();
    drop(window);
    thread.join().unwrap();
    assert!(blocked, "direct claim must respect the delivery window");
}

#[test]
fn separate_escrows_same_connection_fail_closed_without_consuming_credentials() {
    use mail_upstream_oauth::flow::ProviderTokens;
    use mail_upstream_oauth::onboarding::{DeliveryEscrow, EscrowedCredential, RoleAuthorizer};
    let clock = Arc::new(FixedClock::new(NOW));
    let transport = gmail_transport();
    let connections = connection_store();
    let (secrets, _) = secret_store("unsupported-cross-instance");
    let secrets = Arc::new(secrets);
    let credential = EscrowedCredential {
        provider: "gmail".into(),
        connection_id: "same-connection".into(),
        identity: "identity".into(),
        expected_account: "account".into(),
        capabilities: vec![],
        tokens: ProviderTokens {
            access_token: "access".into(),
            refresh_token: Some("refresh".into()),
            expires_at: None,
            scopes: vec![],
        },
        issued_at: NOW,
        expires_at: NOW + 600,
    };
    let first = Arc::new(DeliveryEscrow::new());
    let second = Arc::new(DeliveryEscrow::new());
    let first_ticket = first.issue(credential.clone()).unwrap();
    let second_ticket = second.issue(credential).unwrap();
    for (escrow, ticket) in [
        (first.clone(), &first_ticket),
        (second.clone(), &second_ticket),
    ] {
        let delivery = TokenBroker::new(
            connections.clone(),
            secrets.clone(),
            transport.clone(),
            Arc::new(ProviderRegistry::builtin()),
            Arc::new(RoleAuthorizer),
            Arc::new(MapClientSecrets::new()),
            escrow.clone(),
            clock.clone(),
        );
        assert!(delivery.deliver(ticket, &broker()).is_err());
        assert!(escrow.peek(ticket, NOW).unwrap().is_some());
    }
    assert!(
        secrets
            .list(mail_upstream_oauth::token_broker::REFRESH_SECRET_OWNER)
            .unwrap()
            .is_empty()
    );
}

#[cfg(test)]
mod durable_delivery {
    use std::sync::{Arc, Barrier};
    use std::thread;

    use mail_storage::{
        ConnectionStatus, ProviderConnection, ProviderConnectionStore, RefreshState, SecretAad,
        SecretRef, SecretStore, StorageError,
    };
    use mail_upstream_oauth::clock::FixedClock;
    use mail_upstream_oauth::error::UpstreamOAuthError;
    use mail_upstream_oauth::flow::ProviderTokens;
    use mail_upstream_oauth::onboarding::{DeliveryEscrow, EscrowedCredential, RoleAuthorizer};
    use mail_upstream_oauth::profile::ProviderRegistry;
    use mail_upstream_oauth::scope::Capability;
    use mail_upstream_oauth::testing::MapClientSecrets;
    use mail_upstream_oauth::token_broker::{
        REFRESH_SECRET_OWNER, TokenBroker, refresh_secret_aad,
    };

    use crate::common::durable_connection_store;
    use crate::common::*;

    const CONNECTION: &str = "delivery-connection";

    fn credential() -> EscrowedCredential {
        EscrowedCredential {
            provider: "gmail".into(),
            connection_id: CONNECTION.into(),
            identity: "identity-1".into(),
            expected_account: ACCOUNT.into(),
            capabilities: vec![Capability::Read],
            tokens: ProviderTokens {
                access_token: "access-delivery".into(),
                refresh_token: Some(FIRST_REFRESH_TOKEN.into()),
                expires_at: Some(NOW + 3600),
                scopes: vec!["https://mail.google.com/".into()],
            },
            issued_at: NOW,
            expires_at: NOW + 600,
        }
    }

    fn broker_for(
        connections: Arc<dyn ProviderConnectionStore>,
        secrets: Arc<dyn SecretStore>,
        escrow: Arc<DeliveryEscrow>,
    ) -> TokenBroker {
        TokenBroker::new(
            connections,
            secrets,
            gmail_transport(),
            Arc::new(ProviderRegistry::builtin()),
            Arc::new(RoleAuthorizer),
            Arc::new(MapClientSecrets::new()),
            escrow,
            Arc::new(FixedClock::new(NOW)),
        )
    }

    #[test]
    fn two_escrows_of_one_connection_cannot_both_deliver() {
        let connections = durable_connection_store();
        let (secrets, _path) = secret_store("delivery-exactly-once");
        let secrets: Arc<dyn SecretStore> = Arc::new(secrets);
        let first = Arc::new(DeliveryEscrow::new());
        let second = Arc::new(DeliveryEscrow::new());
        let first_ticket = first.issue(credential()).unwrap();
        let second_ticket = second.issue(credential()).unwrap();

        let winner = broker_for(connections.clone(), secrets.clone(), first.clone());
        let receipt = winner
            .deliver(&first_ticket, &broker())
            .expect("the first delivery of the connection wins");
        assert_eq!(receipt.connection_id, CONNECTION);

        let loser = broker_for(connections.clone(), secrets.clone(), second.clone());
        let error = loser
            .deliver(&second_ticket, &broker())
            .expect_err("the second delivery of the connection is refused");
        assert!(
            matches!(&error, UpstreamOAuthError::Storage { reason }
                if reason.contains("already delivered")),
            "{error:?}"
        );

        // The winner's credential was consumed; the loser's is untouched.
        assert!(first.peek(&first_ticket, NOW).unwrap().is_none());
        assert!(second.peek(&second_ticket, NOW).unwrap().is_some());

        // One secret, one version, and it reads back under the credential's AAD.
        let references = secrets.list(REFRESH_SECRET_OWNER).unwrap();
        assert_eq!(references.len(), 1);
        assert_eq!(references[0].version, 1);
        let aad = refresh_secret_aad("gmail", CONNECTION, "identity-1");
        let plaintext = secrets.get(&references[0], &aad).unwrap().unwrap();
        assert_eq!(plaintext, FIRST_REFRESH_TOKEN.as_bytes());

        // The connection is active and carries its refresh state.
        let connection = connections.get_connection(CONNECTION).unwrap().unwrap();
        assert_eq!(connection.status, ConnectionStatus::Active);
        let state = connections.get_refresh_state(CONNECTION).unwrap().unwrap();
        assert_eq!(state.secret_ref, receipt.secret_ref);
        assert!(!state.needs_reauthorization);
    }

    #[test]
    fn concurrent_deliveries_of_one_connection_release_exactly_once() {
        let connections = durable_connection_store();
        let (secrets, _path) = secret_store("delivery-concurrent");
        let secrets = Arc::new(secrets);
        let escrows: Vec<_> = (0..2).map(|_| Arc::new(DeliveryEscrow::new())).collect();
        let tickets: Vec<String> = escrows
            .iter()
            .map(|escrow| escrow.issue(credential()).unwrap())
            .collect();
        let barrier = Arc::new(Barrier::new(2));
        let threads: Vec<_> = escrows
            .iter()
            .zip(&tickets)
            .map(|(escrow, ticket)| {
                let connections = connections.clone();
                let secrets = secrets.clone();
                let escrow = escrow.clone();
                let ticket = ticket.clone();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    barrier.wait();
                    // The concrete stores are shared; the trait objects are
                    // built inside the thread.
                    let connections: Arc<dyn ProviderConnectionStore> = connections.clone();
                    let secrets: Arc<dyn SecretStore> = secrets.clone();
                    broker_for(connections, secrets, escrow).deliver(&ticket, &broker())
                })
            })
            .collect();
        let results: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
        assert_eq!(secrets.list(REFRESH_SECRET_OWNER).unwrap().len(), 1);
        let (winner, _) = results
            .iter()
            .enumerate()
            .find(|(_, result)| result.is_ok())
            .unwrap();
        let loser = 1 - winner;
        assert!(escrows[loser].peek(&tickets[loser], NOW).unwrap().is_some());
    }

    #[test]
    fn a_failed_secret_write_leaves_the_ticket_recoverable_and_unclaimed() {
        let connections = durable_connection_store();
        let escrow = Arc::new(DeliveryEscrow::new());
        let ticket = escrow.issue(credential()).unwrap();

        struct BrokenSecrets;
        impl SecretStore for BrokenSecrets {
            fn put(
                &self,
                _owner: &str,
                _name: &str,
                _plaintext: &[u8],
                _aad: &SecretAad,
            ) -> Result<SecretRef, StorageError> {
                Err(StorageError::Backend("the secret store is broken".into()))
            }
            fn get(
                &self,
                _reference: &SecretRef,
                _aad: &SecretAad,
            ) -> Result<Option<Vec<u8>>, StorageError> {
                Ok(None)
            }
            fn rotate(
                &self,
                _reference: &SecretRef,
                _plaintext: &[u8],
                _aad: &SecretAad,
            ) -> Result<SecretRef, StorageError> {
                Err(StorageError::Backend("the secret store is broken".into()))
            }
            fn delete(&self, _reference: &SecretRef) -> Result<bool, StorageError> {
                Ok(false)
            }
            fn list(&self, _owner: &str) -> Result<Vec<SecretRef>, StorageError> {
                Ok(Vec::new())
            }
        }

        let broken = broker_for(connections.clone(), Arc::new(BrokenSecrets), escrow.clone());
        assert!(broken.deliver(&ticket, &broker()).is_err());
        // The ticket is recoverable and unclaimed.
        assert!(escrow.peek(&ticket, NOW).unwrap().is_some());
        // The claim was released: a delivery through a working secret store
        // of the same ticket still succeeds.
        let (secrets, _path) = secret_store("delivery-retry");
        let healthy = broker_for(connections, Arc::new(secrets), escrow);
        healthy
            .deliver(&ticket, &broker())
            .expect("the retry delivers");
    }

    #[test]
    fn a_failed_refresh_state_write_never_leaves_an_active_connection() {
        let connections = durable_connection_store();
        let escrow = Arc::new(DeliveryEscrow::new());
        let ticket = escrow.issue(credential()).unwrap();

        /// A connection store whose refresh-state writes fail.
        struct FailingConnections {
            inner: Arc<mail_storage::SqliteStore>,
        }
        impl ProviderConnectionStore for FailingConnections {
            fn put_connection(&self, connection: &ProviderConnection) -> Result<(), StorageError> {
                self.inner.put_connection(connection)
            }
            fn get_connection(
                &self,
                connection_id: &str,
            ) -> Result<Option<ProviderConnection>, StorageError> {
                self.inner.get_connection(connection_id)
            }
            fn list_connections(
                &self,
                identity: &str,
            ) -> Result<Vec<ProviderConnection>, StorageError> {
                self.inner.list_connections(identity)
            }
            fn put_refresh_state(&self, _state: &RefreshState) -> Result<(), StorageError> {
                Err(StorageError::Backend(
                    "the refresh state cannot be written".into(),
                ))
            }
            fn get_refresh_state(
                &self,
                connection_id: &str,
            ) -> Result<Option<RefreshState>, StorageError> {
                self.inner.get_refresh_state(connection_id)
            }
            fn claim_refresh(
                &self,
                connection_id: &str,
                generation: u64,
                owner: &str,
            ) -> Result<bool, StorageError> {
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
            ) -> Result<bool, StorageError> {
                self.inner.complete_refresh(
                    connection_id,
                    generation,
                    owner,
                    secret_ref,
                    expires_at,
                    now,
                )
            }
            fn mark_needs_reauthorization(
                &self,
                connection_id: &str,
                now: u64,
            ) -> Result<bool, StorageError> {
                self.inner.mark_needs_reauthorization(connection_id, now)
            }
            fn disconnect(&self, connection_id: &str, now: u64) -> Result<bool, StorageError> {
                self.inner.disconnect(connection_id, now)
            }
            fn vouches_durability(&self) -> bool {
                self.inner.vouches_durability()
            }
            fn claim_delivery(
                &self,
                connection_id: &str,
                owner: &str,
                now: u64,
            ) -> Result<mail_storage::DeliveryClaim, StorageError> {
                self.inner.claim_delivery(connection_id, owner, now)
            }
            fn complete_delivery(
                &self,
                connection_id: &str,
                owner: &str,
                now: u64,
            ) -> Result<(), StorageError> {
                self.inner.complete_delivery(connection_id, owner, now)
            }
            fn release_delivery(
                &self,
                connection_id: &str,
                owner: &str,
            ) -> Result<(), StorageError> {
                self.inner.release_delivery(connection_id, owner)
            }
        }

        let failing: Arc<dyn ProviderConnectionStore> = Arc::new(FailingConnections {
            inner: connections.clone(),
        });
        let (secrets, _path) = secret_store("delivery-failing-state");
        let broken = broker_for(failing, Arc::new(secrets), escrow.clone());
        assert!(broken.deliver(&ticket, &broker()).is_err());
        // No active connection without refresh state: the connection write
        // never happened at all.
        assert!(connections.get_connection(CONNECTION).unwrap().is_none());
        assert!(connections.get_refresh_state(CONNECTION).unwrap().is_none());
        // The ticket is recoverable and unclaimed.
        assert!(escrow.peek(&ticket, NOW).unwrap().is_some());
        // The claim was released: a delivery through a working store still
        // succeeds.
        let (secrets, _path) = secret_store("delivery-failing-retry");
        let healthy = broker_for(connections, Arc::new(secrets), escrow);
        healthy
            .deliver(&ticket, &broker())
            .expect("the retry delivers");
    }

    #[test]
    fn a_delivery_claim_survives_a_restart() {
        let path =
            std::env::temp_dir().join(format!("corvi-delivery-restart-{}", unique_suffix_pub()));
        let connections = mail_storage::SqliteStore::open(&path).unwrap();
        let (secrets, _path_secret) = secret_store("delivery-restart");
        let secrets = Arc::new(secrets);
        let escrow = Arc::new(DeliveryEscrow::new());
        let first_ticket = escrow.issue(credential()).unwrap();
        let first = broker_for(Arc::new(connections), secrets.clone(), escrow.clone());
        first
            .deliver(&first_ticket, &broker())
            .expect("the first delivery wins");

        // A restart: the store is closed and reopened, the escrow is gone
        // with the old process, and a new escrow holds a second credential
        // for the same connection.
        drop(first);
        drop(escrow);
        let connections = mail_storage::SqliteStore::open(&path).unwrap();
        let second = Arc::new(DeliveryEscrow::new());
        let second_ticket = second.issue(credential()).unwrap();
        let restarted = broker_for(Arc::new(connections), secrets, second.clone());
        let error = restarted
            .deliver(&second_ticket, &broker())
            .expect_err("the connection was already delivered before the restart");
        assert!(
            matches!(&error, UpstreamOAuthError::Storage { reason }
                if reason.contains("already delivered")),
            "{error:?}"
        );
        assert!(second.peek(&second_ticket, NOW).unwrap().is_some());
        let _ = std::fs::remove_file(&path);
    }
}
