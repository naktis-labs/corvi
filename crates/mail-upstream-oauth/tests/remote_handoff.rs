//! The one-time, encrypted, authenticated handoff of a credential to a
//! remote controller.

mod common;

use std::sync::Arc;

use mail_upstream_oauth::clock::{Clock, FixedClock};
use mail_upstream_oauth::error::{HandoffFailure, UpstreamOAuthError};
use mail_upstream_oauth::flow::ProviderTokens;
use mail_upstream_oauth::handoff::{
    MAX_HANDOFF_TTL_SECONDS, MemoryOneTimeUseGuard, issue_handoff, redeem_handoff,
};
use mail_upstream_oauth::scope::Capability;

use common::*;

fn payload() -> mail_upstream_oauth::handoff::HandoffPayload {
    mail_upstream_oauth::handoff::HandoffPayload {
        provider: "gmail".to_owned(),
        connection_id: "conn-1".to_owned(),
        identity: "identity-1".to_owned(),
        expected_account: ACCOUNT.to_owned(),
        capabilities: vec![Capability::Read],
        tokens: ProviderTokens {
            access_token: "at-handoff-marker".to_owned(),
            refresh_token: Some("rt-handoff-marker".to_owned()),
            expires_at: Some(NOW + 3600),
            scopes: vec!["https://mail.google.com/".to_owned()],
        },
    }
}

const KEY: &[u8] = b"a shared key that is long enough";
const RECIPIENT: &str = "controller-1";

fn envelope(clock: &FixedClock) -> mail_upstream_oauth::handoff::HandoffEnvelope {
    issue_handoff(&payload(), KEY, RECIPIENT, clock.now(), 120).expect("the handoff is issued")
}

#[test]
fn a_handoff_round_trips() {
    let clock = Arc::new(FixedClock::new(NOW));
    let guard = MemoryOneTimeUseGuard::new();
    let envelope = envelope(&clock);
    let redeemed = redeem_handoff(&envelope, KEY, RECIPIENT, clock.now(), &guard)
        .expect("the handoff redeems");
    assert_eq!(redeemed.provider, "gmail");
    assert_eq!(redeemed.expected_account, ACCOUNT);
    assert_eq!(
        redeemed.tokens.refresh_token.as_deref(),
        Some("rt-handoff-marker")
    );
}

#[test]
fn the_envelope_leaks_nothing() {
    let clock = Arc::new(FixedClock::new(NOW));
    let envelope = envelope(&clock);
    let printed = format!("{envelope:?}");
    assert!(!printed.contains("at-handoff-marker"), "{printed}");
    assert!(!printed.contains("rt-handoff-marker"), "{printed}");
    assert!(
        printed.contains("[redacted]"),
        "the ciphertext is not printed"
    );

    let encoded = serde_json::to_string(&envelope).expect("the envelope serializes");
    assert!(!encoded.contains("at-handoff-marker"), "{encoded}");
    assert!(!encoded.contains("rt-handoff-marker"), "{encoded}");
    // The ciphertext is opaque: it is the only part that travels.
    assert!(
        envelope
            .ciphertext
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'),
        "the ciphertext is base64url"
    );
}

#[test]
fn a_handoff_is_used_once() {
    let clock = Arc::new(FixedClock::new(NOW));
    let guard = MemoryOneTimeUseGuard::new();
    let envelope = envelope(&clock);
    redeem_handoff(&envelope, KEY, RECIPIENT, clock.now(), &guard)
        .expect("the first redemption works");
    let error = redeem_handoff(&envelope, KEY, RECIPIENT, clock.now(), &guard)
        .expect_err("a replayed envelope is refused");
    match error {
        UpstreamOAuthError::HandoffRejected { reason } => {
            assert_eq!(reason, HandoffFailure::Replayed);
        }
        other => panic!("expected HandoffRejected, got {other:?}"),
    }
}

#[test]
fn a_tampered_envelope_is_refused() {
    let clock = Arc::new(FixedClock::new(NOW));
    let guard = MemoryOneTimeUseGuard::new();
    let mut envelope = envelope(&clock);
    let mut ciphertext =
        mail_upstream_oauth::pkce::base64url_decode(&envelope.ciphertext).expect("the ciphertext");
    let last = ciphertext.len() - 1;
    ciphertext[last] ^= 0x01;
    envelope.ciphertext = mail_upstream_oauth::pkce::base64url_encode(&ciphertext);
    let error = redeem_handoff(&envelope, KEY, RECIPIENT, clock.now(), &guard)
        .expect_err("a modified envelope does not authenticate");
    match error {
        UpstreamOAuthError::HandoffRejected { reason } => {
            assert_eq!(reason, HandoffFailure::Tampered);
        }
        other => panic!("expected HandoffRejected, got {other:?}"),
    }
}

#[test]
fn a_tampered_expiry_is_refused() {
    let clock = Arc::new(FixedClock::new(NOW));
    let guard = MemoryOneTimeUseGuard::new();
    let mut envelope = envelope(&clock);
    envelope.expires_at += 10_000;
    let error = redeem_handoff(&envelope, KEY, RECIPIENT, clock.now(), &guard)
        .expect_err("the expiry is inside the authenticated data");
    match error {
        UpstreamOAuthError::HandoffRejected { reason } => {
            assert_eq!(reason, HandoffFailure::Tampered);
        }
        other => panic!("expected HandoffRejected, got {other:?}"),
    }
}

#[test]
fn a_tampered_recipient_is_refused() {
    let clock = Arc::new(FixedClock::new(NOW));
    let guard = MemoryOneTimeUseGuard::new();
    let mut envelope = envelope(&clock);
    envelope.recipient = "controller-2".to_owned();
    let error = redeem_handoff(&envelope, KEY, "controller-2", clock.now(), &guard)
        .expect_err("the recipient is inside the authenticated data");
    match error {
        UpstreamOAuthError::HandoffRejected { reason } => {
            assert_eq!(reason, HandoffFailure::Tampered);
        }
        other => panic!("expected HandoffRejected, got {other:?}"),
    }
}

#[test]
fn an_expired_envelope_is_refused() {
    let clock = Arc::new(FixedClock::new(NOW));
    let guard = MemoryOneTimeUseGuard::new();
    let envelope = envelope(&clock);
    clock.advance(121);
    let error = redeem_handoff(&envelope, KEY, RECIPIENT, clock.now(), &guard)
        .expect_err("an expired envelope is refused");
    match error {
        UpstreamOAuthError::HandoffRejected { reason } => {
            assert_eq!(reason, HandoffFailure::Expired);
        }
        other => panic!("expected HandoffRejected, got {other:?}"),
    }
}

#[test]
fn an_envelope_for_somebody_else_is_refused() {
    let clock = Arc::new(FixedClock::new(NOW));
    let guard = MemoryOneTimeUseGuard::new();
    let envelope = envelope(&clock);
    let error = redeem_handoff(&envelope, KEY, "controller-2", clock.now(), &guard)
        .expect_err("an envelope addressed elsewhere is refused");
    match error {
        UpstreamOAuthError::HandoffRejected { reason } => {
            assert_eq!(reason, HandoffFailure::UnknownRecipient);
        }
        other => panic!("expected HandoffRejected, got {other:?}"),
    }
}

#[test]
fn a_wrong_key_is_refused() {
    let clock = Arc::new(FixedClock::new(NOW));
    let guard = MemoryOneTimeUseGuard::new();
    let envelope = envelope(&clock);
    let error = redeem_handoff(
        &envelope,
        b"a different key that is long enough",
        RECIPIENT,
        clock.now(),
        &guard,
    )
    .expect_err("a key that does not match does not open the envelope");
    match error {
        UpstreamOAuthError::HandoffRejected { reason } => {
            assert_eq!(reason, HandoffFailure::Tampered);
        }
        other => panic!("expected HandoffRejected, got {other:?}"),
    }
}

#[test]
fn a_handoff_is_short_lived() {
    let clock = Arc::new(FixedClock::new(NOW));
    let error = issue_handoff(
        &payload(),
        KEY,
        RECIPIENT,
        clock.now(),
        MAX_HANDOFF_TTL_SECONDS + 1,
    )
    .expect_err("a handoff may not live longer than the bound");
    assert!(matches!(error, UpstreamOAuthError::InvalidRequest { .. }));

    let error = issue_handoff(&payload(), KEY, RECIPIENT, clock.now(), 0)
        .expect_err("a handoff with no lifetime is refused");
    assert!(matches!(error, UpstreamOAuthError::InvalidRequest { .. }));

    let error = issue_handoff(&payload(), b"short", RECIPIENT, clock.now(), 120)
        .expect_err("a short key is refused");
    assert!(matches!(error, UpstreamOAuthError::InvalidRequest { .. }));
}

#[test]
fn every_handoff_envelope_is_unique() {
    let clock = Arc::new(FixedClock::new(NOW));
    let first = envelope(&clock);
    let second = envelope(&clock);
    assert_ne!(first.envelope_id, second.envelope_id);
    assert_ne!(first.ciphertext, second.ciphertext);
}
