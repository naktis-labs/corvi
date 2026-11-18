//! The one-time, encrypted, authenticated handoff of a credential to a
//! remote controller.

mod common;

use std::sync::Arc;

use mail_upstream_oauth::clock::{Clock, FixedClock};
use mail_upstream_oauth::error::{HandoffFailure, UpstreamOAuthError};
use mail_upstream_oauth::flow::ProviderTokens;
use mail_upstream_oauth::handoff::{
    HandoffLifetime, MAX_HANDOFF_TTL_SECONDS, SingleProcessOneTimeUseGuard, issue_handoff,
    redeem_handoff,
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
fn authenticated_handoff_fails_closed_without_durable_guard() {
    let guard = SingleProcessOneTimeUseGuard::new();
    let envelope = envelope(&FixedClock::new(NOW));
    let error = redeem_handoff(
        &envelope,
        KEY,
        RECIPIENT,
        NOW,
        &HandoffLifetime::unbounded(),
        &guard,
    )
    .unwrap_err();
    assert!(
        matches!(error, UpstreamOAuthError::Storage { ref reason } if reason.contains("durable replay"))
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
fn repeated_unsupported_redemptions_do_not_consume_guard() {
    use mail_upstream_oauth::handoff::OneTimeUseGuard;
    let guard = SingleProcessOneTimeUseGuard::new();
    let envelope = envelope(&FixedClock::new(NOW));
    for _ in 0..2 {
        assert!(
            redeem_handoff(
                &envelope,
                KEY,
                RECIPIENT,
                NOW,
                &HandoffLifetime::unbounded(),
                &guard
            )
            .is_err()
        );
    }
    assert!(guard.consume(&envelope.envelope_id, NOW).unwrap());
}

#[test]
fn a_tampered_envelope_is_refused() {
    let clock = Arc::new(FixedClock::new(NOW));
    let guard = SingleProcessOneTimeUseGuard::new();
    let mut envelope = envelope(&clock);
    let mut ciphertext = hex::decode(&envelope.ciphertext).expect("the ciphertext");
    let last = ciphertext.len() - 1;
    ciphertext[last] ^= 0x01;
    envelope.ciphertext = hex::encode(&ciphertext);
    let error = redeem_handoff(
        &envelope,
        KEY,
        RECIPIENT,
        clock.now(),
        &mail_upstream_oauth::handoff::HandoffLifetime::unbounded(),
        &guard,
    )
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
    let guard = SingleProcessOneTimeUseGuard::new();
    let mut envelope = envelope(&clock);
    envelope.expires_at += 10_000;
    let error = redeem_handoff(
        &envelope,
        KEY,
        RECIPIENT,
        clock.now(),
        &mail_upstream_oauth::handoff::HandoffLifetime::unbounded(),
        &guard,
    )
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
    let guard = SingleProcessOneTimeUseGuard::new();
    let mut envelope = envelope(&clock);
    envelope.recipient = "controller-2".to_owned();
    let error = redeem_handoff(
        &envelope,
        KEY,
        "controller-2",
        clock.now(),
        &mail_upstream_oauth::handoff::HandoffLifetime::unbounded(),
        &guard,
    )
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
    let guard = SingleProcessOneTimeUseGuard::new();
    let envelope = envelope(&clock);
    clock.advance(121);
    let error = redeem_handoff(
        &envelope,
        KEY,
        RECIPIENT,
        clock.now(),
        &mail_upstream_oauth::handoff::HandoffLifetime::unbounded(),
        &guard,
    )
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
    let guard = SingleProcessOneTimeUseGuard::new();
    let envelope = envelope(&clock);
    let error = redeem_handoff(
        &envelope,
        KEY,
        "controller-2",
        clock.now(),
        &mail_upstream_oauth::handoff::HandoffLifetime::unbounded(),
        &guard,
    )
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
    let guard = SingleProcessOneTimeUseGuard::new();
    let envelope = envelope(&clock);
    let error = redeem_handoff(
        &envelope,
        b"a different key that is long enough",
        RECIPIENT,
        clock.now(),
        &mail_upstream_oauth::handoff::HandoffLifetime::unbounded(),
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

#[test]
fn an_envelope_issued_in_the_future_is_refused() {
    let clock = Arc::new(FixedClock::new(NOW));
    let guard = SingleProcessOneTimeUseGuard::new();
    let mut envelope = envelope(&clock);
    // The issuance moment is on the envelope in the clear; a deployment
    // that finds an envelope from the future is looking at one that this
    // deployment cannot have issued with a clock it trusts.
    envelope.issued_at = NOW + 10_000;
    let error = redeem_handoff(
        &envelope,
        KEY,
        RECIPIENT,
        clock.now(),
        &HandoffLifetime::unbounded(),
        &guard,
    )
    .expect_err("an envelope from the future is refused");
    match error {
        UpstreamOAuthError::HandoffRejected { reason } => {
            assert_eq!(reason, HandoffFailure::Unknown);
        }
        other => panic!("expected HandoffRejected, got {other:?}"),
    }
}

#[test]
fn an_envelope_issued_before_the_floor_is_refused() {
    let clock = Arc::new(FixedClock::new(NOW));
    let guard = SingleProcessOneTimeUseGuard::new();
    // The envelope was issued at NOW; a deployment that starts accepting
    // handoffs from NOW + 60 refuses it.
    let envelope = envelope(&clock);
    let error = redeem_handoff(
        &envelope,
        KEY,
        RECIPIENT,
        clock.now(),
        &HandoffLifetime::since(NOW + 60),
        &guard,
    )
    .expect_err("an envelope older than the floor is refused");
    match error {
        UpstreamOAuthError::HandoffRejected { reason } => {
            assert_eq!(reason, HandoffFailure::Unknown);
        }
        other => panic!("expected HandoffRejected, got {other:?}"),
    }
}

#[test]
fn an_envelope_at_the_floor_reaches_the_disabled_boundary() {
    let clock = Arc::new(FixedClock::new(NOW));
    let guard = SingleProcessOneTimeUseGuard::new();
    let envelope = envelope(&clock);
    redeem_handoff(
        &envelope,
        KEY,
        RECIPIENT,
        clock.now(),
        &HandoffLifetime::since(NOW),
        &guard,
    )
    .expect_err("redemption is disabled without durable replay protection");
}

#[test]
fn tampering_issued_at_cannot_bypass_the_floor() {
    let clock = FixedClock::new(NOW);
    let guard = SingleProcessOneTimeUseGuard::new();
    let original = envelope(&clock);
    let mut altered = original.clone();
    altered.issued_at += 1;
    assert!(matches!(
        redeem_handoff(
            &altered,
            KEY,
            RECIPIENT,
            NOW + 1,
            &HandoffLifetime::since(NOW + 1),
            &guard
        ),
        Err(UpstreamOAuthError::HandoffRejected {
            reason: HandoffFailure::Tampered
        })
    ));
    assert!(matches!(
        redeem_handoff(
            &original,
            KEY,
            RECIPIENT,
            NOW + 1,
            &HandoffLifetime::unbounded(),
            &guard
        ),
        Err(UpstreamOAuthError::Storage { .. })
    ));
}

#[test]
fn legacy_v1_envelope_is_rejected_without_consuming_id() {
    use mail_storage::crypto::{Cipher, derive_key};
    let clock = FixedClock::new(NOW);
    let guard = SingleProcessOneTimeUseGuard::new();
    let mut old = envelope(&clock);
    let valid = old.clone();
    let salt = hex::decode(&old.salt).unwrap();
    let context = format!(
        "corvi-upstream-oauth-handoff/v1|{}|{}",
        old.recipient, old.envelope_id
    );
    let key = derive_key(KEY, &salt, context.as_bytes()).unwrap();
    let aad = format!(
        "corvi-upstream-oauth-handoff/v1\nrecipient={}\nenvelope={}\nexpires_at={}",
        old.recipient, old.envelope_id, old.expires_at
    );
    let (nonce, ciphertext) = Cipher::new(&key)
        .unwrap()
        .seal(&serde_json::to_vec(&payload()).unwrap(), aad.as_bytes())
        .unwrap();
    old.nonce = hex::encode(nonce);
    old.ciphertext = hex::encode(ciphertext);
    assert!(matches!(
        redeem_handoff(
            &old,
            KEY,
            RECIPIENT,
            NOW,
            &HandoffLifetime::unbounded(),
            &guard
        ),
        Err(UpstreamOAuthError::HandoffRejected {
            reason: HandoffFailure::Tampered
        })
    ));
    assert!(matches!(
        redeem_handoff(
            &valid,
            KEY,
            RECIPIENT,
            NOW,
            &HandoffLifetime::unbounded(),
            &guard
        ),
        Err(UpstreamOAuthError::Storage { .. })
    ));
}

#[test]
fn separate_process_local_guards_cannot_redeem() {
    let envelope = envelope(&FixedClock::new(NOW));
    for guard in [
        SingleProcessOneTimeUseGuard::new(),
        SingleProcessOneTimeUseGuard::new(),
    ] {
        assert!(
            redeem_handoff(
                &envelope,
                KEY,
                RECIPIENT,
                NOW,
                &HandoffLifetime::unbounded(),
                &guard
            )
            .is_err()
        );
    }
}
