//! Reconnect: no silent owner change, no widened grants.

mod common;

use mail_storage::ProviderConnection;
use mail_upstream_oauth::profile::ProviderRegistry;
use mail_upstream_oauth::reconnect::{ReconnectRefusal, ReconnectRequest, evaluate_reconnect};
use mail_upstream_oauth::scope::Capability;

use common::*;

fn connection() -> ProviderConnection {
    ProviderConnection {
        connection_id: "conn-1".to_owned(),
        provider: "gmail".to_owned(),
        account_ref: ACCOUNT.to_owned(),
        identity: "identity-1".to_owned(),
        capabilities: vec!["read".to_owned()],
        status: mail_storage::ConnectionStatus::Active,
        generation: 3,
        updated_at: NOW,
    }
}

fn profile() -> mail_upstream_oauth::profile::ProviderProfile {
    ProviderRegistry::builtin()
        .get("gmail")
        .expect("gmail is known")
        .clone()
}

fn request() -> ReconnectRequest {
    ReconnectRequest {
        connection_id: "conn-1".to_owned(),
        identity: "identity-1".to_owned(),
        expected_account: ACCOUNT.to_owned(),
        capabilities: vec![Capability::Read],
        redirect_uri: GMAIL_REDIRECT.to_owned(),
    }
}

#[test]
fn a_reconnection_may_not_change_the_mailbox_owner() {
    let mut request = request();
    request.expected_account = "acct-somebody-else".to_owned();
    let refusal = evaluate_reconnect(&connection(), &request, &profile())
        .expect_err("the owner may not change silently");
    match &refusal {
        ReconnectRefusal::OwnerChanged {
            recorded,
            requested,
        } => {
            assert_eq!(recorded, ACCOUNT);
            assert_eq!(requested, "acct-somebody-else");
        }
        other => panic!("expected OwnerChanged, got {other:?}"),
    }
}

#[test]
fn a_reconnection_may_not_change_the_corvi_identity() {
    let mut request = request();
    request.identity = "identity-2".to_owned();
    let refusal = evaluate_reconnect(&connection(), &request, &profile())
        .expect_err("the identity may not change silently");
    match &refusal {
        ReconnectRefusal::IdentityChanged {
            recorded,
            requested,
        } => {
            assert_eq!(recorded, "identity-1");
            assert_eq!(requested, "identity-2");
        }
        other => panic!("expected IdentityChanged, got {other:?}"),
    }
}

#[test]
fn a_reconnection_may_not_widen_the_grants() {
    let mut request = request();
    request.capabilities = vec![Capability::Read, Capability::Send];
    let refusal = evaluate_reconnect(&connection(), &request, &profile())
        .expect_err("the grants may not grow on a reconnect");
    match &refusal {
        ReconnectRefusal::ScopeWidening { requested, granted } => {
            assert_eq!(requested, &vec!["read".to_owned(), "send".to_owned()]);
            assert_eq!(granted, &vec!["read".to_owned()]);
        }
        other => panic!("expected ScopeWidening, got {other:?}"),
    }
}

#[test]
fn a_reconnection_may_not_use_an_unregistered_callback() {
    let mut request = request();
    request.redirect_uri = "https://attacker.example/callback".to_owned();
    let refusal = evaluate_reconnect(&connection(), &request, &profile())
        .expect_err("the callback is still the provider's choice");
    assert!(matches!(
        refusal,
        ReconnectRefusal::CallbackNotAllowed { .. }
    ));
}

#[test]
fn a_reconnection_that_changes_nothing_is_allowed() {
    evaluate_reconnect(&connection(), &request(), &profile())
        .expect("the same account, identity and capabilities reconnect");
}

#[test]
fn the_refusals_name_what_would_have_changed() {
    let mut request = request();
    request.expected_account = "acct-2".to_owned();
    request.capabilities = vec![Capability::Read, Capability::Send];
    let refusal = evaluate_reconnect(&connection(), &request, &profile())
        .expect_err("the owner check comes first");
    let printed = refusal.to_string();
    assert!(printed.contains("acct-2"), "{printed}");
    assert!(!printed.contains("identity-2"), "{printed}");
}

#[test]
fn no_credential_appears_in_any_debug_output() {
    // The escrowed credential, the outcome and the receipt are the objects
    // that carry credential material, and none of them may print it.
    let escrow = mail_upstream_oauth::onboarding::DeliveryEscrow::new();
    let credential = mail_upstream_oauth::onboarding::EscrowedCredential {
        provider: "gmail".to_owned(),
        connection_id: "conn-1".to_owned(),
        identity: "identity-1".to_owned(),
        expected_account: ACCOUNT.to_owned(),
        capabilities: vec![Capability::Read],
        tokens: mail_upstream_oauth::flow::ProviderTokens {
            access_token: "at-debug-marker".to_owned(),
            refresh_token: Some("rt-debug-marker".to_owned()),
            expires_at: Some(NOW + 3600),
            scopes: vec!["https://mail.google.com/".to_owned()],
        },
        issued_at: NOW,
        expires_at: NOW + 60,
    };
    let printed = format!("{credential:?}");
    assert!(!printed.contains("at-debug-marker"), "{printed}");
    assert!(!printed.contains("rt-debug-marker"), "{printed}");

    let ticket = escrow
        .issue(credential)
        .expect("the credential is escrowed");
    let printed = format!("{escrow:?}");
    assert!(!printed.contains("at-debug-marker"), "{printed}");
    assert!(!printed.contains("rt-debug-marker"), "{printed}");
    assert!(!ticket.contains("at-debug-marker"), "{printed}");

    // A request that carries a client secret must not print it either.
    let request = mail_upstream_oauth::transport::OAuthRequest::post_form(
        "https://oauth2.googleapis.test/token",
        vec![
            ("grant_type".to_owned(), "refresh_token".to_owned()),
            ("refresh_token".to_owned(), "rt-debug-marker".to_owned()),
            ("client_secret".to_owned(), "cs-debug-marker".to_owned()),
        ],
    );
    let printed = format!("{request:?}");
    assert!(!printed.contains("rt-debug-marker"), "{printed}");
    assert!(!printed.contains("cs-debug-marker"), "{printed}");
}
