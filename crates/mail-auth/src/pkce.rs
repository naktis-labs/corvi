//! PKCE, S256 only.
//!
//! ADR-0009 requires the authorization code flow to use PKCE, and the
//! contract lists `S256` as the only method. `plain` sends the verifier as
//! the challenge, which leaks the value to anyone who sees the challenge,
//! so it is refused rather than accepted with a warning.
//!
//! The comparison is constant time and the verifier is never written to a
//! log, an error or a store.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

use crate::config::PkceMethod;
use crate::error::AuthError;

/// A code challenge carried by an authorization request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkceChallenge {
    /// The method the challenge uses.
    pub method: PkceMethod,
    /// The challenge value.
    pub value: String,
}

/// The smallest verifier RFC 7636 accepts.
const MIN_VERIFIER_LENGTH: usize = 43;
/// The largest verifier RFC 7636 accepts.
const MAX_VERIFIER_LENGTH: usize = 128;

/// Compute the S256 challenge of a verifier.
pub fn s256_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

/// Check a code verifier against a challenge.
///
/// The challenge method must be `S256`: `plain` is refused, and a challenge
/// that is not a well formed S256 value is refused rather than compared.
pub fn verify_challenge(challenge: &PkceChallenge, verifier: &str) -> Result<(), AuthError> {
    check_challenge(challenge)?;
    if !is_valid_verifier(verifier) {
        return Err(AuthError::InvalidPkce(
            "the code verifier is not a valid RFC 7636 verifier".to_owned(),
        ));
    }
    let expected = s256_challenge(verifier);
    if !constant_time_eq(expected.as_bytes(), challenge.value.as_bytes()) {
        return Err(AuthError::InvalidPkce(
            "the code verifier does not match the code challenge".to_owned(),
        ));
    }
    Ok(())
}

/// Check that a challenge is one this issuer accepts.
///
/// The method must be `S256` and the value must be a base64url encoded
/// SHA-256 digest. `plain` is refused here, before any verifier is
/// presented.
pub fn check_challenge(challenge: &PkceChallenge) -> Result<(), AuthError> {
    if challenge.method != PkceMethod::S256 {
        return Err(AuthError::UnsupportedPkceMethod(
            "only the S256 code challenge method is supported".to_owned(),
        ));
    }
    if !is_s256_value(&challenge.value) {
        return Err(AuthError::InvalidPkce(
            "the code challenge is not an S256 value".to_owned(),
        ));
    }
    Ok(())
}

/// Compare two byte strings without leaking where they differ.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left, right) in left.iter().zip(right.iter()) {
        difference |= left ^ right;
    }
    difference == 0
}

/// Whether a string is a code verifier RFC 7636 allows.
fn is_valid_verifier(verifier: &str) -> bool {
    let length = verifier.len();
    if !(MIN_VERIFIER_LENGTH..=MAX_VERIFIER_LENGTH).contains(&length) {
        return false;
    }
    verifier
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
}

/// Whether a string is a base64url encoded SHA-256 digest.
fn is_s256_value(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s256(verifier: &str) -> PkceChallenge {
        PkceChallenge {
            method: PkceMethod::S256,
            value: s256_challenge(verifier),
        }
    }

    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    #[test]
    fn the_rfc_example_verifier_matches_its_challenge() {
        assert_eq!(
            s256_challenge(VERIFIER),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        assert_eq!(verify_challenge(&s256(VERIFIER), VERIFIER), Ok(()));
    }

    #[test]
    fn a_wrong_verifier_is_refused() {
        assert!(matches!(
            verify_challenge(
                &s256(VERIFIER),
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            ),
            Err(AuthError::InvalidPkce(_))
        ));
    }

    #[test]
    fn the_plain_method_is_refused() {
        let challenge = PkceChallenge {
            method: PkceMethod::Plain,
            value: VERIFIER.to_owned(),
        };
        assert!(matches!(
            verify_challenge(&challenge, VERIFIER),
            Err(AuthError::UnsupportedPkceMethod(_))
        ));
    }

    #[test]
    fn a_malformed_challenge_is_refused() {
        for value in ["", "not base64!", &"A".repeat(42), &"A".repeat(44)] {
            let challenge = PkceChallenge {
                method: PkceMethod::S256,
                value: value.to_owned(),
            };
            assert!(
                matches!(
                    verify_challenge(&challenge, VERIFIER),
                    Err(AuthError::InvalidPkce(_))
                ),
                "the challenge {value:?} should have been refused"
            );
        }
    }

    #[test]
    fn a_malformed_verifier_is_refused() {
        assert!(matches!(
            verify_challenge(&s256(VERIFIER), "short"),
            Err(AuthError::InvalidPkce(_))
        ));
        assert!(matches!(
            verify_challenge(&s256(VERIFIER), &"A".repeat(129)),
            Err(AuthError::InvalidPkce(_))
        ));
        assert!(matches!(
            verify_challenge(&s256(VERIFIER), &"!".repeat(43)),
            Err(AuthError::InvalidPkce(_))
        ));
    }

    #[test]
    fn the_verifier_is_never_part_of_the_error() {
        let error = verify_challenge(
            &s256(VERIFIER),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )
        .expect_err("the wrong verifier must be refused");
        let rendered = error.to_string();
        assert!(!rendered.contains("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
    }
}
