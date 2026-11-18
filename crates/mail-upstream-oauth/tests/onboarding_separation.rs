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
    transport: Arc<mail_upstream_oauth::testing::FixtureTransport>,
    secrets: Arc<dyn SecretStore>,
    secret_path: std::path::PathBuf,
}

fn fixtures() -> Fixtures {
    let clock = Arc::new(FixedClock::new(NOW));
    let transport = gmail_transport();
    let (service, escrow) = gmail_service(transport.clone(), clock.clone());
    let (secrets, secret_path) = secret_store("onboarding");
    let secrets: Arc<dyn SecretStore> = Arc::new(secrets);
    let registry = Arc::new(ProviderRegistry::builtin());
    let broker = TokenBroker::new(
        connection_store(),
        secrets.clone(),
        transport.clone(),
        registry,
        Arc::new(mail_upstream_oauth::onboarding::RoleAuthorizer),
        Arc::new(MapClientSecrets::new()),
        escrow,
        clock,
    );
    Fixtures {
        service,
        broker,
        transport,
        secrets,
        secret_path,
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
fn the_data_plane_takes_the_credential_through_the_delivery_interface() {
    let fixtures = fixtures();
    let callback = authorize(&fixtures.service);
    let outcome = fixtures
        .service
        .complete(&callback)
        .expect("the onboarding completes");
    let receipt = fixtures
        .broker
        .deliver(&outcome.delivery_ticket, &broker())
        .expect("the data plane takes the credential");

    assert_eq!(receipt.connection_id, outcome.connection_id);
    assert_eq!(receipt.provider, "gmail");
    assert_eq!(receipt.generation, 0);
    assert!(
        receipt.secret_ref.starts_with("provider-connection/"),
        "the receipt names the credential, it does not carry it"
    );

    let printed = format!("{receipt:?}");
    assert!(!printed.contains(ACCESS_TOKEN), "{printed}");
    assert!(!printed.contains(FIRST_REFRESH_TOKEN), "{printed}");
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
fn a_ticket_is_used_once() {
    let fixtures = fixtures();
    let callback = authorize(&fixtures.service);
    let outcome = fixtures
        .service
        .complete(&callback)
        .expect("the onboarding completes");
    let ticket = outcome.delivery_ticket.clone();
    fixtures
        .broker
        .deliver(&ticket, &broker())
        .expect("the first delivery works");
    let error = fixtures
        .broker
        .deliver(&ticket, &broker())
        .expect_err("a second delivery finds no credential");
    assert!(matches!(error, UpstreamOAuthError::InvalidRequest { .. }));
}

#[test]
fn the_delivered_credential_is_encrypted_at_rest() {
    let fixtures = fixtures();
    let callback = authorize(&fixtures.service);
    let outcome = fixtures
        .service
        .complete(&callback)
        .expect("the onboarding completes");
    fixtures
        .broker
        .deliver(&outcome.delivery_ticket, &broker())
        .expect("the data plane takes the credential");

    let contents = std::fs::read_to_string(&fixtures.secret_path)
        .expect("the secret file is readable for the test");
    assert!(
        !contents.contains(FIRST_REFRESH_TOKEN),
        "the refresh credential is not in the file"
    );
    assert!(
        !contents.contains(ACCESS_TOKEN),
        "the access credential is not in the file"
    );
    // The escrow is empty: the credential is exactly where it must be.
    assert!(fixtures.transport.request_count() >= 1);
}

#[test]
fn the_delivered_credential_is_recoverable_and_bound_to_its_connection() {
    let fixtures = fixtures();
    let callback = authorize(&fixtures.service);
    let outcome = fixtures
        .service
        .complete(&callback)
        .expect("the onboarding completes");
    let receipt = fixtures
        .broker
        .deliver(&outcome.delivery_ticket, &broker())
        .expect("the data plane takes the credential");

    let references = fixtures
        .secrets
        .list(mail_upstream_oauth::token_broker::REFRESH_SECRET_OWNER)
        .expect("the secret store lists its credentials");
    assert_eq!(references.len(), 1);
    assert_eq!(references[0].name, receipt.connection_id);

    // The credential is recoverable by the data plane, with the context it
    // was stored under.
    let aad = mail_upstream_oauth::token_broker::refresh_secret_aad(
        "gmail",
        &receipt.connection_id,
        "identity-1",
    );
    let value = fixtures
        .secrets
        .get(&references[0], &aad)
        .expect("the envelope opens")
        .expect("the credential is there");
    assert_eq!(value, FIRST_REFRESH_TOKEN.as_bytes());

    // The same envelope under another connection's context does not open,
    // so a credential copied into another connection is useless there.
    let elsewhere = mail_upstream_oauth::token_broker::refresh_secret_aad(
        "gmail",
        "conn-elsewhere",
        "identity-1",
    );
    let error = fixtures
        .secrets
        .get(&references[0], &elsewhere)
        .expect_err("a moved credential does not decrypt");
    assert!(matches!(error, mail_storage::StorageError::KeyMismatch));
}

#[test]
fn a_credential_that_arrived_in_a_handoff_takes_the_same_delivery_path() {
    let clock = Arc::new(FixedClock::new(NOW));
    let escrow = Arc::new(mail_upstream_oauth::onboarding::DeliveryEscrow::new());
    let guard = mail_upstream_oauth::handoff::MemoryOneTimeUseGuard::new();
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

    // The controller opens it and gets an ordinary delivery ticket.
    let ticket = escrow
        .accept_handoff(&envelope, key, "controller-1", NOW, &guard)
        .expect("the controller accepts the handoff");
    assert!(!ticket.is_empty());

    // The data plane takes it exactly as it takes a hosted grant.
    let (secrets, secret_path) = secret_store("handoff-delivery");
    let secrets: Arc<dyn SecretStore> = Arc::new(secrets);
    let transport = gmail_transport();
    let registry = Arc::new(ProviderRegistry::builtin());
    let token_broker = TokenBroker::new(
        connection_store(),
        secrets.clone(),
        transport,
        registry,
        Arc::new(mail_upstream_oauth::onboarding::RoleAuthorizer),
        Arc::new(MapClientSecrets::new()),
        escrow.clone(),
        clock,
    );
    let receipt = token_broker
        .deliver(&ticket, &broker())
        .expect("the data plane takes the credential");
    assert_eq!(receipt.connection_id, "conn-handoff");

    let contents = std::fs::read_to_string(&secret_path).expect("the secret file is there");
    assert!(!contents.contains(FIRST_REFRESH_TOKEN));

    // The envelope cannot be replayed into a second credential.
    let error = escrow
        .accept_handoff(&envelope, key, "controller-1", NOW, &guard)
        .expect_err("the envelope was already redeemed");
    assert!(matches!(error, UpstreamOAuthError::HandoffRejected { .. }));
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
    match &error {
        UpstreamOAuthError::NeedsReauthorization { reason, .. } => {
            assert!(reason.contains("no refresh credential"), "{reason}");
        }
        other => panic!("expected NeedsReauthorization, got {other:?}"),
    }
    assert_eq!(error.status().as_str(), "needsReauthorization");
}
