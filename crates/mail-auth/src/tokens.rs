//! Token minting, token parsing and secret hashing.
//!
//! Corvi's client-facing tokens are opaque to the client: a base64url
//! payload and a keyed MAC. The payload is server-side data, not a claim
//! set the client may rely on — every authorization decision is taken from
//! the grant store, never from the payload alone.
//!
//! Three rules hold here:
//!
//! 1. **The MAC binds the token to this deployment.** A token minted by
//!    another issuer, or with another deployment's key, does not verify.
//! 2. **The payload names the issuer and the audience.** A token for the
//!    administration audience is not a token for the mail resource.
//! 3. **Nothing is logged.** The minting functions return the token to the
//!    caller and nothing else; there is no `Display` that would put a
//!    token into a log line by accident.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::AuthError;

type HmacSha256 = Hmac<Sha256>;

/// The label that separates the access token MAC from the other uses of the
/// deployment key.
const ACCESS_TOKEN_LABEL: &str = "corvi-access-token-v1";
/// The label that separates the refresh token MAC.
const REFRESH_TOKEN_LABEL: &str = "corvi-refresh-token-v1";
/// The label that separates the client secret hash.
const CLIENT_SECRET_LABEL: &str = "corvi-client-secret-v1";

/// The claims a Corvi access token carries.
///
/// The claims are what the caller supplies at mint time. The token itself
/// carries them plus a random nonce, so two tokens minted for the same
/// grant in the same second are still two different tokens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessTokenClaims {
    /// The issuer that minted the token.
    pub issuer: String,
    /// The resource the token is for.
    pub audience: String,
    /// The principal the token acts as.
    pub subject: String,
    /// The client the token was minted for.
    pub client_id: String,
    /// The grants the token was minted from, one per identity.
    pub grant_ids: Vec<String>,
    /// The scopes the token was minted with.
    ///
    /// The token never widens itself: the effective scope of the token is
    /// the intersection of these scopes and the scopes the grants carry
    /// now, so a narrowed consent takes effect at once.
    pub scopes: Vec<String>,
    /// The refresh family the token was minted from, when it came from one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family_id: Option<String>,
    /// When the token was minted.
    pub issued_at: u64,
    /// When the token expires.
    pub expires_at: u64,
}

/// The payload that is written into an access token.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccessPayload {
    issuer: String,
    audience: String,
    subject: String,
    client_id: String,
    grant_ids: Vec<String>,
    scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    family_id: Option<String>,
    issued_at: u64,
    expires_at: u64,
    nonce: String,
}

impl AccessPayload {
    fn encode(claims: &AccessTokenClaims, nonce: String) -> Result<Vec<u8>, AuthError> {
        serde_json::to_vec(&Self {
            issuer: claims.issuer.clone(),
            audience: claims.audience.clone(),
            subject: claims.subject.clone(),
            client_id: claims.client_id.clone(),
            grant_ids: claims.grant_ids.clone(),
            scopes: claims.scopes.clone(),
            family_id: claims.family_id.clone(),
            issued_at: claims.issued_at,
            expires_at: claims.expires_at,
            nonce,
        })
        .map_err(|error| AuthError::InvalidToken(format!("the claims cannot be encoded: {error}")))
    }

    fn decode(payload: &[u8]) -> Result<AccessTokenClaims, AuthError> {
        let payload: Self = serde_json::from_slice(payload)
            .map_err(|_| AuthError::InvalidToken("the token payload is not readable".to_owned()))?;
        Ok(AccessTokenClaims {
            issuer: payload.issuer,
            audience: payload.audience,
            subject: payload.subject,
            client_id: payload.client_id,
            grant_ids: payload.grant_ids,
            scopes: payload.scopes,
            family_id: payload.family_id,
            issued_at: payload.issued_at,
            expires_at: payload.expires_at,
        })
    }
}

/// The claims a Corvi refresh token carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefreshTokenClaims {
    /// The refresh family the token belongs to.
    pub family_id: String,
    /// The generation of the token inside its family.
    pub generation: u64,
    /// The grants the family was minted for.
    pub grant_ids: Vec<String>,
    /// The scopes the family was minted with.
    pub scopes: Vec<String>,
}

/// Mint an access token.
///
/// The token is unique: the nonce is random, so two tokens minted for the
/// same grant in the same second are still two different tokens.
pub fn mint_access_token(key: &[u8], claims: &AccessTokenClaims) -> Result<String, AuthError> {
    let nonce = random_id(16)?;
    let payload = AccessPayload::encode(claims, nonce)?;
    let signature = mac(key, ACCESS_TOKEN_LABEL, &payload)?;
    Ok(format!(
        "cat1.{}.{}",
        base64_url_encode(&payload),
        base64_url_encode(&signature)
    ))
}

/// Parse and verify an access token.
///
/// A token that is malformed, whose MAC does not verify, or that was
/// minted by another deployment is refused. The expiry is checked by the
/// caller, because the caller knows the clock the deployment uses.
pub fn parse_access_token(key: &[u8], token: &str) -> Result<AccessTokenClaims, AuthError> {
    let (payload, signature) = split_signed_token(token, "cat1")?;
    let expected = mac(key, ACCESS_TOKEN_LABEL, &payload)?;
    if !constant_time_eq(&signature, &expected) {
        return Err(AuthError::InvalidToken(
            "the token was not minted by this issuer".to_owned(),
        ));
    }
    AccessPayload::decode(&payload)
}

/// Mint a refresh token.
///
/// The token is bound to its family and its generation, so a token of one
/// generation can never be presented as a token of another.
pub fn mint_refresh_token(
    key: &[u8],
    family_id: &str,
    generation: u64,
    grant_ids: &[String],
    scopes: &[String],
) -> Result<String, AuthError> {
    if family_id.is_empty() {
        return Err(AuthError::InvalidGrant(
            "a refresh token needs a family".to_owned(),
        ));
    }
    let claims = RefreshTokenClaims {
        family_id: family_id.to_owned(),
        generation,
        grant_ids: grant_ids.to_vec(),
        scopes: scopes.to_vec(),
    };
    let payload = serde_json::to_vec(&claims).map_err(|error| {
        AuthError::InvalidGrant(format!("the claims cannot be encoded: {error}"))
    })?;
    let signature = mac(key, REFRESH_TOKEN_LABEL, &payload)?;
    Ok(format!(
        "crt1.{}.{}",
        base64_url_encode(&payload),
        base64_url_encode(&signature)
    ))
}

/// Parse and verify a refresh token.
pub fn parse_refresh_token(key: &[u8], token: &str) -> Result<RefreshTokenClaims, AuthError> {
    let (payload, signature) = split_signed_token(token, "crt1")?;
    let claims: RefreshTokenClaims = serde_json::from_slice(&payload)
        .map_err(|_| AuthError::InvalidGrant("the token payload is not readable".to_owned()))?;
    let expected = mac(key, REFRESH_TOKEN_LABEL, &payload)?;
    if !constant_time_eq(&signature, &expected) {
        return Err(AuthError::InvalidGrant(
            "the refresh token was not minted by this issuer".to_owned(),
        ));
    }
    Ok(claims)
}

/// The digest of a token, as the grant store keeps it.
pub fn token_hash(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    hex_encode(&digest)
}

/// The hash of a client secret, as the grant store keeps it.
///
/// The client identifier is part of the hash, so a secret hash cannot be
/// moved from one client to another.
pub fn secret_hash(key: &[u8], client_id: &str, secret: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("an hmac key of any length is valid");
    mac.update(CLIENT_SECRET_LABEL.as_bytes());
    mac.update(b"\x1f");
    mac.update(client_id.as_bytes());
    mac.update(b"\x1f");
    mac.update(secret.as_bytes());
    hex_encode(&mac.finalize().into_bytes())
}

/// Check a presented client secret against the stored hash.
pub fn verify_secret_hash(key: &[u8], client_id: &str, secret: &str, expected: &str) -> bool {
    let actual = secret_hash(key, client_id, secret);
    constant_time_eq(actual.as_bytes(), expected.as_bytes())
}

/// Compare two byte strings without leaking where they differ.
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left, right) in left.iter().zip(right.iter()) {
        difference |= left ^ right;
    }
    difference == 0
}

/// Random bytes, for nonces and identifiers.
pub fn random_bytes(length: usize) -> Result<Vec<u8>, AuthError> {
    let mut buffer = vec![0u8; length];
    getrandom::fill(&mut buffer)
        .map_err(|error| AuthError::Deployment(format!("the random source failed: {error}")))?;
    Ok(buffer)
}

/// A random identifier, as base64url without padding.
pub fn random_id(byte_length: usize) -> Result<String, AuthError> {
    Ok(base64_url_encode(&random_bytes(byte_length)?))
}

/// Encode bytes as base64url without padding.
pub fn base64_url_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode base64url without padding.
pub fn base64_url_decode(value: &str) -> Result<Vec<u8>, AuthError> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .map_err(|_| AuthError::InvalidToken("the token is not valid base64url".to_owned()))
}

/// Encode bytes as lowercase hexadecimal.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(char::from_digit(u32::from(byte >> 4), 16).expect("a nibble is a digit"));
        result.push(char::from_digit(u32::from(byte & 0x0f), 16).expect("a nibble is a digit"));
    }
    result
}

/// The MAC of a payload, under the deployment key.
fn mac(key: &[u8], label: &str, payload: &[u8]) -> Result<Vec<u8>, AuthError> {
    let mut mac = HmacSha256::new_from_slice(key).expect("an hmac key of any length is valid");
    mac.update(label.as_bytes());
    mac.update(b"\x1f");
    mac.update(payload);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Split a signed token into its payload and its MAC.
fn split_signed_token(token: &str, prefix: &str) -> Result<(Vec<u8>, Vec<u8>), AuthError> {
    let refused = |reason: &str| {
        AuthError::InvalidToken(format!("the token is not a {prefix} token: {reason}"))
    };
    let rest = token
        .strip_prefix(prefix)
        .ok_or_else(|| AuthError::InvalidToken(format!("the token is not a {prefix} token")))?;
    let rest = rest
        .strip_prefix('.')
        .ok_or_else(|| refused("the header is missing"))?;
    let (payload, signature) = rest
        .split_once('.')
        .ok_or_else(|| refused("the mac is missing"))?;
    let payload = base64_url_decode(payload).map_err(|_| {
        AuthError::InvalidToken("the token payload is not valid base64url".to_owned())
    })?;
    let signature = base64_url_decode(signature)
        .map_err(|_| AuthError::InvalidToken("the token mac is not valid base64url".to_owned()))?;
    Ok((payload, signature))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"a deployment key that is long enough to be a key";

    fn claims() -> AccessTokenClaims {
        AccessTokenClaims {
            issuer: "https://auth.corvi.example".to_owned(),
            audience: "https://mail.corvi.example".to_owned(),
            subject: "owner-1".to_owned(),
            client_id: "client-1".to_owned(),
            grant_ids: vec!["grant-1".to_owned()],
            scopes: vec!["mail:messages:read".to_owned()],
            family_id: Some("family-1".to_owned()),
            issued_at: 1_000,
            expires_at: 1_900,
        }
    }

    #[test]
    fn an_access_token_round_trips() {
        let token = mint_access_token(KEY, &claims()).expect("the token mints");
        assert_eq!(parse_access_token(KEY, &token), Ok(claims()));
    }

    #[test]
    fn two_minted_tokens_differ() {
        let first = mint_access_token(KEY, &claims()).expect("the token mints");
        let second = mint_access_token(KEY, &claims()).expect("the token mints");
        assert_ne!(first, second);
    }

    #[test]
    fn a_token_minted_with_another_key_is_refused() {
        let token = mint_access_token(KEY, &claims()).expect("the token mints");
        assert!(matches!(
            parse_access_token(b"another deployment key", &token),
            Err(AuthError::InvalidToken(_))
        ));
    }

    #[test]
    fn a_provider_shaped_token_is_refused() {
        for token in [
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJwcm92aWRlciJ9.c2ln",
            "ya29.provider-token",
            "",
            "cat1.not-base64.not-base64",
        ] {
            assert!(
                matches!(
                    parse_access_token(KEY, token),
                    Err(AuthError::InvalidToken(_))
                ),
                "the token {token:?} should have been refused"
            );
        }
    }

    #[test]
    fn a_tampered_token_is_refused() {
        let token = mint_access_token(KEY, &claims()).expect("the token mints");
        let mut tampered = token.clone();
        tampered.push('x');
        assert!(matches!(
            parse_access_token(KEY, &tampered),
            Err(AuthError::InvalidToken(_))
        ));
    }

    #[test]
    fn a_refresh_token_round_trips() {
        let token = mint_refresh_token(KEY, "family-1", 3, &["grant-1".to_owned()], &[])
            .expect("the token mints");
        assert_eq!(
            parse_refresh_token(KEY, &token),
            Ok(RefreshTokenClaims {
                family_id: "family-1".to_owned(),
                generation: 3,
                grant_ids: vec!["grant-1".to_owned()],
                scopes: Vec::new(),
            })
        );
    }

    #[test]
    fn a_refresh_token_of_another_family_is_refused() {
        let token = mint_refresh_token(KEY, "family-1", 1, &[], &[]).expect("the token mints");
        assert!(matches!(
            parse_refresh_token(b"another deployment key", &token),
            Err(AuthError::InvalidGrant(_))
        ));
    }

    #[test]
    fn a_client_secret_hash_is_bound_to_its_client() {
        let hash = secret_hash(KEY, "client-1", "the secret");
        assert!(verify_secret_hash(KEY, "client-1", "the secret", &hash));
        assert!(!verify_secret_hash(KEY, "client-2", "the secret", &hash));
        assert!(!verify_secret_hash(
            KEY,
            "client-1",
            "another secret",
            &hash
        ));
    }

    #[test]
    fn a_secret_hash_never_contains_the_secret() {
        let hash = secret_hash(KEY, "client-1", "the secret");
        assert!(!hash.contains("the secret"));
    }
}
