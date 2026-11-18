//! The authorization code flow: PKCE, state, issuer binding and account
//! validation.

mod common;

use std::sync::Arc;

use mail_upstream_oauth::clock::FixedClock;
use mail_upstream_oauth::error::UpstreamOAuthError;
use mail_upstream_oauth::onboarding::CallbackRequest;
use mail_upstream_oauth::pkce::{challenge_for, random_token};
use mail_upstream_oauth::profile::ProviderRegistry;
use mail_upstream_oauth::testing::FixtureTransport;
use mail_upstream_oauth::transaction::TransactionStore;

use common::*;

#[test]
fn the_pkce_challenge_is_the_one_rfc_7636_defines() {
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    assert_eq!(
        challenge_for(verifier),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
}

#[test]
fn base64url_round_trips_without_padding() {
    for length in 0..40 {
        let bytes: Vec<u8> = (0..length).map(|index| (index * 37 % 256) as u8).collect();
        let encoded = mail_upstream_oauth::pkce::base64url_encode(&bytes);
        assert!(
            !encoded.contains('='),
            "base64url does not use padding characters"
        );
        assert_eq!(
            mail_upstream_oauth::pkce::base64url_decode(&encoded).as_deref(),
            Some(bytes.as_slice())
        );
    }
    assert!(mail_upstream_oauth::pkce::base64url_decode("a+b/").is_none());
}

#[test]
fn the_url_and_the_transaction_carry_the_whole_binding() {
    let clock = Arc::new(FixedClock::new(NOW));
    let transport = gmail_transport();
    let (service, _escrow) = gmail_service(transport, clock);
    let start = service
        .start(&gmail_request())
        .expect("the onboarding starts");

    let url = &start.authorization_url;
    assert!(url.starts_with("https://accounts.google.com/o/oauth2/v2/auth?"));
    assert_eq!(query(url, "response_type"), "code");
    assert_eq!(
        query(url, "client_id"),
        "gmail-example-client-id.apps.googleusercontent.com"
    );
    assert_eq!(
        query(url, "redirect_uri"),
        "http%3A%2F%2F127.0.0.1%3A8400%2Foauth%2Fupstream%2Fcallback%2Fgmail",
        "the callback is carried in the URL, properly encoded"
    );
    assert_eq!(
        query(url, "scope"),
        "https%3A%2F%2Fmail.google.com%2F",
        "the scopes are carried in the URL, properly encoded"
    );
    assert_eq!(query(url, "code_challenge_method"), "S256");
    let challenge = query(url, "code_challenge");
    assert_eq!(challenge.len(), 43, "S256 of a 43 character verifier");
    assert!(
        !url.contains("code_verifier"),
        "the verifier is never in the URL"
    );
    let state = query(url, "state");
    assert_eq!(state.len(), 43, "the state is unguessable");
    assert!(state != challenge, "the state and the challenge differ");

    // The transaction persists before the browser is sent anywhere, and it
    // binds everything the callback will be checked against.
    let store = mail_upstream_oauth::transaction::MemoryTransactionStore::new();
    let transaction = mail_upstream_oauth::transaction::OnboardingTransaction {
        transaction_id: "tx-1".to_owned(),
        connection_id: "conn-1".to_owned(),
        provider: "gmail".to_owned(),
        issuer: "https://accounts.google.com".to_owned(),
        client_id: "client-1".to_owned(),
        redirect_uri: GMAIL_REDIRECT.to_owned(),
        code_verifier: "verifier-value".to_owned(),
        code_challenge: challenge.clone(),
        state: state.clone(),
        nonce: "nonce".to_owned(),
        scopes: vec!["https://mail.google.com/".to_owned()],
        capabilities: Vec::new(),
        expected_account: ACCOUNT.to_owned(),
        identity: "identity-1".to_owned(),
        principal: "admin-1".to_owned(),
        principal_roles: Vec::new(),
        issued_at: NOW,
        expires_at: NOW + 300,
    };
    store
        .insert(&transaction)
        .expect("the transaction is stored");
    let taken = store
        .take(&state)
        .expect("the store can be read")
        .expect("the transaction is there");
    assert_eq!(taken.issuer, "https://accounts.google.com");
    assert_eq!(taken.expected_account, ACCOUNT);
    assert_eq!(
        taken.expires_at,
        NOW + 300,
        "the transaction is short lived"
    );
}

#[test]
fn a_mismatched_issuer_is_refused() {
    let clock = Arc::new(FixedClock::new(NOW));
    let transport = gmail_transport();
    let (service, _escrow) = gmail_service(transport, clock);
    let mut callback = authorize(&service);
    callback.issuer = Some("https://attacker.example".to_owned());
    let error = service
        .complete(&callback)
        .expect_err("a callback from another issuer is refused");
    assert!(matches!(
        error,
        UpstreamOAuthError::InvalidTransaction { .. }
    ));
}

#[test]
fn a_mismatched_redirect_is_refused() {
    let clock = Arc::new(FixedClock::new(NOW));
    let transport = gmail_transport();
    let (service, _escrow) = gmail_service(transport, clock);
    let mut callback = authorize(&service);
    callback.redirect_uri = Some("https://attacker.example/callback".to_owned());
    let error = service
        .complete(&callback)
        .expect_err("a code issued for another callback is refused");
    assert!(matches!(
        error,
        UpstreamOAuthError::CallbackNotAllowed { .. }
    ));
}

#[test]
fn a_mismatched_client_is_refused() {
    let clock = Arc::new(FixedClock::new(NOW));
    let transport = gmail_transport();
    let (service, _escrow) = gmail_service(transport, clock);
    let mut callback = authorize(&service);
    callback.client_id = Some("attacker-client".to_owned());
    let error = service
        .complete(&callback)
        .expect_err("a code issued for another client is refused");
    assert!(matches!(
        error,
        UpstreamOAuthError::InvalidTransaction { .. }
    ));
}

#[test]
fn a_callback_for_another_provider_is_refused() {
    let clock = Arc::new(FixedClock::new(NOW));
    let transport = gmail_transport();
    let (service, _escrow) = gmail_service(transport, clock);
    let mut callback = authorize(&service);
    callback.provider = Some("microsoft365".to_owned());
    let error = service
        .complete(&callback)
        .expect_err("the provider comes from the transaction, not the browser");
    assert!(matches!(
        error,
        UpstreamOAuthError::InvalidTransaction { .. }
    ));
}

#[test]
fn a_callback_without_a_code_is_refused() {
    let clock = Arc::new(FixedClock::new(NOW));
    let transport = gmail_transport();
    let (service, _escrow) = gmail_service(transport, clock);
    let mut callback = authorize(&service);
    callback.code = None;
    let error = service
        .complete(&callback)
        .expect_err("a callback without a code cannot be exchanged");
    assert!(matches!(
        error,
        UpstreamOAuthError::InvalidTransaction { .. }
    ));
}

#[test]
fn a_state_is_used_once() {
    let clock = Arc::new(FixedClock::new(NOW));
    let transport = gmail_transport();
    let (service, _escrow) = gmail_service(transport.clone(), clock);
    let callback = authorize(&service);
    service
        .complete(&callback)
        .expect("the first callback completes the grant");
    let after_first = transport.request_count();
    let error = service
        .complete(&callback)
        .expect_err("a replayed callback finds no transaction");
    assert!(matches!(
        error,
        UpstreamOAuthError::InvalidTransaction { .. }
    ));
    assert_eq!(
        transport.request_count(),
        after_first,
        "the provider was not asked a second time"
    );
}

#[test]
fn an_expired_transaction_is_refused() {
    let clock = Arc::new(FixedClock::new(NOW));
    let transport = gmail_transport();
    let (service, _escrow) = gmail_service(transport, clock.clone());
    let callback = authorize(&service);
    clock.advance(301);
    let error = service
        .complete(&callback)
        .expect_err("an expired authorization is refused");
    assert!(matches!(
        error,
        UpstreamOAuthError::InvalidTransaction { .. }
    ));
}

#[test]
fn a_provider_error_is_refused_without_its_text() {
    let clock = Arc::new(FixedClock::new(NOW));
    let transport = gmail_transport();
    let (service, _escrow) = gmail_service(transport, clock);
    let mut callback = authorize(&service);
    callback.error = Some("access_denied".to_owned());
    let error = service
        .complete(&callback)
        .expect_err("the provider refused the authorization");
    assert!(matches!(
        error,
        UpstreamOAuthError::InvalidTransaction { .. }
    ));
}

#[test]
fn the_account_must_be_the_expected_one() {
    let clock = Arc::new(FixedClock::new(NOW));
    let transport = gmail_transport();
    let (service, _escrow) = gmail_service(transport, clock);
    let mut request = gmail_request();
    request.expected_account = "acct-attacker".to_owned();
    // The session still names acct-1, so the onboarding must stop.
    let start = service.start(&request).expect("the onboarding starts");
    let state = query(&start.authorization_url, "state");
    let callback = CallbackRequest {
        provider: Some("gmail".to_owned()),
        state,
        code: Some("auth-code-1".to_owned()),
        error: None,
        issuer: None,
        redirect_uri: Some(GMAIL_REDIRECT.to_owned()),
        client_id: Some("gmail-example-client-id.apps.googleusercontent.com".to_owned()),
    };
    let error = service
        .complete(&callback)
        .expect_err("the provider account is not the expected one");
    match &error {
        UpstreamOAuthError::AccountMismatch { expected, actual } => {
            assert_eq!(expected, "acct-attacker");
            assert_eq!(actual, ACCOUNT);
        }
        other => panic!("expected AccountMismatch, got {other:?}"),
    }
    assert_eq!(error.status().as_str(), "accountMismatch");
}

#[test]
fn a_provider_that_grants_more_than_was_asked_is_refused() {
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
                    Some("rt-1"),
                    Some(3600),
                    Some("https://mail.google.com/ https://www.googleapis.test/auth/drive"),
                ),
            ),
        )
    });
    let (service, _escrow) = gmail_service(transport, clock);
    let callback = authorize(&service);
    let error = service
        .complete(&callback)
        .expect_err("the provider granted a scope nobody asked for");
    match &error {
        UpstreamOAuthError::ScopeWidening { provider, scope } => {
            assert_eq!(provider, "gmail");
            assert_eq!(scope, "https://www.googleapis.test/auth/drive");
        }
        other => panic!("expected ScopeWidening, got {other:?}"),
    }
}

#[test]
fn a_confidential_client_authenticates_with_its_secret() {
    let clock = Arc::new(FixedClock::new(NOW));
    let transport = Arc::new(
        FixtureTransport::new()
            .route_form(
                mail_upstream_oauth::transport::HttpMethod::Post,
                "https://oauth.fastmail.example/oauth/token",
                "grant_type=authorization_code",
                mail_upstream_oauth::transport::OAuthResponse::json(
                    200,
                    &mail_upstream_oauth::testing::token_response(
                        "fm-at-1",
                        Some("fm-rt-1"),
                        Some(3600),
                        Some("jmap"),
                    ),
                ),
            )
            .route(
                mail_upstream_oauth::transport::HttpMethod::Get,
                SESSION_URL,
                mail_upstream_oauth::transport::OAuthResponse::json(
                    200,
                    &serde_json::json!({ "accounts": { "fm-account-1": {} } }),
                ),
            ),
    );
    let registry = Arc::new(ProviderRegistry::builtin());
    let transactions = Arc::new(mail_upstream_oauth::transaction::MemoryTransactionStore::new());
    let validator = Arc::new(
        mail_upstream_oauth::onboarding::SessionAccountValidator::new(
            transport.clone(),
            SESSION_URL.to_owned(),
        ),
    );
    let escrow = Arc::new(mail_upstream_oauth::onboarding::DeliveryEscrow::new());
    let service = mail_upstream_oauth::onboarding::OnboardingService::new(
        registry,
        transactions,
        transport.clone(),
        Arc::new(mail_upstream_oauth::onboarding::RoleAuthorizer),
        validator,
        Arc::new(mail_upstream_oauth::testing::MapClientSecrets::new().with(
            "secret://provider/fastmail-client-secret",
            FASTMAIL_CLIENT_SECRET,
        )),
        escrow,
        clock,
    );

    let mut request = gmail_request();
    request.provider = "fastmail".to_owned();
    request.redirect_uri = "https://auth.corvi.example/oauth/upstream/callback/fastmail".to_owned();
    request.expected_account = "fm-account-1".to_owned();
    let start = service.start(&request).expect("fastmail onboards");
    let state = query(&start.authorization_url, "state");
    let callback = mail_upstream_oauth::onboarding::CallbackRequest {
        provider: Some("fastmail".to_owned()),
        state,
        code: Some("fm-code-1".to_owned()),
        error: None,
        issuer: None,
        redirect_uri: Some(
            "https://auth.corvi.example/oauth/upstream/callback/fastmail".to_owned(),
        ),
        client_id: Some("fastmail-example-client-id".to_owned()),
    };
    service
        .complete(&callback)
        .expect("the confidential client completes the grant");

    let exchange = transport
        .requests()
        .into_iter()
        .find(|request| request.form_value("grant_type") == Some("authorization_code"))
        .expect("the code was exchanged");
    assert_eq!(
        exchange.form_value("client_secret"),
        Some(FASTMAIL_CLIENT_SECRET),
        "a confidential client authenticates with its secret"
    );
    assert_eq!(exchange.form_value("code_verifier").map(|_| ()), Some(()),);
    let printed = format!("{exchange:?}");
    assert!(
        !printed.contains(FASTMAIL_CLIENT_SECRET),
        "the printed request never shows the client secret"
    );
}

#[test]
fn no_credential_appears_in_debug_output() {
    let tokens = mail_upstream_oauth::flow::ProviderTokens {
        access_token: "at-secret-marker".to_owned(),
        refresh_token: Some("rt-secret-marker".to_owned()),
        expires_at: Some(NOW),
        scopes: Vec::new(),
    };
    let printed = format!("{tokens:?}");
    assert!(!printed.contains("at-secret-marker"), "{printed}");
    assert!(!printed.contains("rt-secret-marker"), "{printed}");

    let transaction = mail_upstream_oauth::transaction::OnboardingTransaction {
        transaction_id: "tx-1".to_owned(),
        connection_id: "conn-1".to_owned(),
        provider: "gmail".to_owned(),
        issuer: "https://accounts.google.com".to_owned(),
        client_id: "client-1".to_owned(),
        redirect_uri: GMAIL_REDIRECT.to_owned(),
        code_verifier: "verifier-secret-marker".to_owned(),
        code_challenge: "challenge".to_owned(),
        state: "state-secret-marker".to_owned(),
        nonce: "nonce-secret-marker".to_owned(),
        scopes: Vec::new(),
        capabilities: Vec::new(),
        expected_account: ACCOUNT.to_owned(),
        identity: "identity-1".to_owned(),
        principal: "admin-1".to_owned(),
        principal_roles: Vec::new(),
        issued_at: NOW,
        expires_at: NOW + 300,
    };
    let printed = format!("{transaction:?}");
    assert!(!printed.contains("verifier-secret-marker"), "{printed}");
    assert!(!printed.contains("state-secret-marker"), "{printed}");
    assert!(!printed.contains("nonce-secret-marker"), "{printed}");

    let printed = format!("{:?}", random_token().expect("a token is made"));
    assert_eq!(
        printed.len(),
        45,
        "a redacted token prints as a quoted string of 43 characters plus two quotes"
    );
}
