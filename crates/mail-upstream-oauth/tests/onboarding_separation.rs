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
            matches!(error, UpstreamOAuthError::Storage { ref reason } if reason.contains("shared durable connection coordination"))
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
    let guard = mail_upstream_oauth::handoff::SingleProcessOneTimeUseGuard::new();
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

    let error = escrow
        .accept_handoff(
            &envelope,
            key,
            "controller-1",
            NOW,
            &mail_upstream_oauth::handoff::HandoffLifetime::unbounded(),
            &guard,
        )
        .unwrap_err();
    assert!(
        matches!(error, UpstreamOAuthError::Storage { ref reason } if reason.contains("durable replay"))
    );
    assert!(escrow.is_empty());
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
        connection_store(),
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
        matches!(error, UpstreamOAuthError::Storage { ref reason } if reason.contains("shared durable connection coordination"))
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
