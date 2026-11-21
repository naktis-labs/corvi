//! PKCE, state and the one-time values of an authorization transaction.
//!
//! RFC 7636 requires PKCE for every public client, and RFC 9700 requires
//! S256 rather than "plain". This module implements the S256 challenge and
//! nothing else: there is no "plain" method to fall back to, so a
//! deployment cannot accidentally downgrade.
//!
//! The values themselves are random, unguessable and single use. They are
//! never logged, never put in a URL fragment and never carried in a query
//! argument other than the `state` and the challenge, both of which are
//! public by design.

use ring::digest::{SHA256, digest};
use ring::rand::{SecureRandom, SystemRandom};

use crate::error::UpstreamOAuthError;
use crate::profile::PkceMethod;

/// The number of random bytes behind a state or verifier.
const TOKEN_BYTES: usize = 32;

/// The base64url alphabet of RFC 4648 section 5.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// The verifier and its challenge.
#[derive(Clone, PartialEq, Eq)]
pub struct Pkce {
    /// The code verifier. This is a secret until the token exchange.
    verifier: String,
    /// The S256 challenge of the verifier.
    challenge: String,
    /// The challenge method.
    method: PkceMethod,
}

impl std::fmt::Debug for Pkce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pkce")
            .field("verifier", &"[redacted]")
            .field("challenge", &self.challenge)
            .field("method", &self.method)
            .finish()
    }
}

impl Pkce {
    /// The code verifier.
    pub fn verifier(&self) -> &str {
        &self.verifier
    }

    /// The S256 challenge.
    pub fn challenge(&self) -> &str {
        &self.challenge
    }

    /// The challenge method.
    pub fn method(&self) -> PkceMethod {
        self.method
    }
}

/// A fresh PKCE pair.
pub fn new_pkce() -> Result<Pkce, UpstreamOAuthError> {
    let verifier = random_token()?;
    let challenge = challenge_for(&verifier);
    Ok(Pkce {
        verifier,
        challenge,
        method: PkceMethod::S256,
    })
}

/// The S256 challenge of a verifier.
///
/// The challenge is `BASE64URL(SHA256(ASCII(verifier)))`, as RFC 7636
/// section 4.2 defines it.
pub fn challenge_for(verifier: &str) -> String {
    let digest = digest(&SHA256, verifier.as_bytes());
    base64url_encode(digest.as_ref())
}

/// A fresh, unguessable, URL-safe token.
///
/// The token carries 256 bits of randomness, which is what makes the
/// `state` of a transaction unguessable and the loopback listener of a
/// native client safe to bind.
pub fn random_token() -> Result<String, UpstreamOAuthError> {
    let mut bytes = vec![0u8; TOKEN_BYTES];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| UpstreamOAuthError::Protocol {
            reason: "the random source failed".to_owned(),
        })?;
    Ok(base64url_encode(&bytes))
}

/// Encode bytes as base64url without padding.
pub fn base64url_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((triple >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((triple >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((triple >> 6) & 0x3f) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(triple & 0x3f) as usize] as char);
        }
    }
    out
}

/// Decode base64url without padding.
///
/// The decoder is strict: a character outside the alphabet, a padding
/// character or a length that cannot occur is refused rather than
/// silently truncated.
pub fn base64url_decode(text: &str) -> Option<Vec<u8>> {
    let mut values: Vec<u8> = Vec::with_capacity(text.len());
    for character in text.bytes() {
        let value = ALPHABET.iter().position(|c| *c == character)? as u8;
        values.push(value);
    }
    let remainder = values.len() % 4;
    if remainder == 1 {
        return None;
    }
    let mut bytes = Vec::with_capacity(values.len() * 3 / 4);
    for chunk in values.chunks(4) {
        let mut triple = 0u32;
        for (index, value) in chunk.iter().enumerate() {
            triple |= (*value as u32) << (18 - 6 * index);
        }
        bytes.push(((triple >> 16) & 0xff) as u8);
        if chunk.len() > 2 {
            bytes.push(((triple >> 8) & 0xff) as u8);
        }
        if chunk.len() > 3 {
            bytes.push((triple & 0xff) as u8);
        }
    }
    Some(bytes)
}
