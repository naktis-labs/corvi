//! The one-time, encrypted, authenticated handoff to a remote controller.
//!
//! ADR-0008 section 2.B: "for a remote Corvi gateway, a `localhost`
//! redirect refers to the computer running the browser/CLI, not the remote
//! server or its Kubernetes Pod. A separately authenticated, one-time
//! short-lived **connection-import/authorization handoff** is therefore
//! required to deliver credentials securely to the controller/data-plane
//! secret store; the transport must be encrypted, authenticated,
//! recipient-bound and resistant to replay."
//!
//! The envelope is ChaCha20-Poly1305 under a key derived from a shared
//! secret, bound to the recipient, the envelope identifier and the expiry.
//! Modifying any of it fails to authenticate. Redeeming it twice is
//! refused by the one-time guard, and redeeming it after the expiry is
//! refused by the clock. Nothing in the envelope is readable without the
//! key, so it can travel through a channel that is not private — but it
//! still must not travel through a channel that logs.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Mutex;

use mail_storage::crypto::{Cipher, derive_key, random_bytes};
use serde::{Deserialize, Serialize};

use crate::error::{HandoffFailure, UpstreamOAuthError};
use crate::flow::ProviderTokens;
use crate::scope::Capability;

/// The longest lifetime of a handoff payload.
pub const MAX_HANDOFF_TTL_SECONDS: u64 = 600;

/// The shortest shared secret a handoff accepts.
pub const MIN_HANDOFF_KEY_BYTES: usize = 16;

/// The key derivation context of a handoff.
const KEY_INFO: &str = "corvi-upstream-oauth-handoff/v1";

/// The credential a companion CLI hands over.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandoffPayload {
    /// The provider the credential belongs to.
    pub provider: String,
    /// The connection the credential belongs to.
    pub connection_id: String,
    /// The Corvi identity the connection serves.
    pub identity: String,
    /// The upstream account the operator expects.
    pub expected_account: String,
    /// The capabilities that were granted.
    pub capabilities: Vec<Capability>,
    /// The tokens the provider issued.
    pub tokens: ProviderTokens,
}

impl fmt::Debug for HandoffPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandoffPayload")
            .field("provider", &self.provider)
            .field("connection_id", &self.connection_id)
            .field("identity", &self.identity)
            .field("expected_account", &self.expected_account)
            .field("capabilities", &self.capabilities)
            .field("tokens", &self.tokens)
            .finish()
    }
}

/// The encrypted envelope that travels between the CLI and the controller.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandoffEnvelope {
    /// The identifier of the envelope.
    pub envelope_id: String,
    /// The recipient the envelope is addressed to.
    pub recipient: String,
    /// When the envelope was issued.
    pub issued_at: u64,
    /// When the envelope stops being usable.
    pub expires_at: u64,
    /// The salt the key was derived with.
    pub salt: String,
    /// The nonce of the ciphertext.
    pub nonce: String,
    /// The ciphertext of the payload.
    pub ciphertext: String,
}

impl fmt::Debug for HandoffEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandoffEnvelope")
            .field("envelope_id", &self.envelope_id)
            .field("recipient", &self.recipient)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("salt", &self.salt)
            .field("nonce", &self.nonce)
            .field("ciphertext", &"[redacted]")
            .finish()
    }
}

/// What keeps an identifier from being used twice.
pub trait OneTimeUseGuard: fmt::Debug + Send + Sync {
    /// Mark an identifier as used.
    ///
    /// The answer is `false` when the identifier was already used, which
    /// is how a replay is refused.
    fn consume(&self, id: &str, now: u64) -> Result<bool, UpstreamOAuthError>;
}

/// A guard that keeps the used identifiers in memory.
#[derive(Debug, Default)]
pub struct MemoryOneTimeUseGuard {
    used: Mutex<BTreeMap<String, u64>>,
}

impl MemoryOneTimeUseGuard {
    /// A guard that has not seen anything yet.
    pub fn new() -> Self {
        Self::default()
    }
}

impl OneTimeUseGuard for MemoryOneTimeUseGuard {
    fn consume(&self, id: &str, now: u64) -> Result<bool, UpstreamOAuthError> {
        let mut used = self.used.lock().map_err(|_| UpstreamOAuthError::Storage {
            reason: "the one-time guard lock is poisoned".to_owned(),
        })?;
        if used.contains_key(id) {
            return Ok(false);
        }
        used.insert(id.to_owned(), now);
        Ok(true)
    }
}

/// The context an envelope is bound to.
fn aad(envelope: &HandoffEnvelope) -> Vec<u8> {
    format!(
        "{KEY_INFO}\nrecipient={}\nenvelope={}\nexpires_at={}",
        envelope.recipient, envelope.envelope_id, envelope.expires_at
    )
    .into_bytes()
}

/// The key derivation context of an envelope.
fn key_info(recipient: &str, envelope_id: &str) -> Vec<u8> {
    format!("{KEY_INFO}|{recipient}|{envelope_id}").into_bytes()
}

/// Seal a credential into an envelope.
///
/// The lifetime is bounded: a handoff is a short handover between two
/// machines, not a stored credential.
pub fn issue_handoff(
    payload: &HandoffPayload,
    shared_key: &[u8],
    recipient: &str,
    now: u64,
    ttl_seconds: u64,
) -> Result<HandoffEnvelope, UpstreamOAuthError> {
    if shared_key.len() < MIN_HANDOFF_KEY_BYTES {
        return Err(UpstreamOAuthError::InvalidRequest {
            reason: "the handoff key is too short to be a key".to_owned(),
        });
    }
    if recipient.trim().is_empty() {
        return Err(UpstreamOAuthError::InvalidRequest {
            reason: "the handoff has no recipient".to_owned(),
        });
    }
    if ttl_seconds == 0 || ttl_seconds > MAX_HANDOFF_TTL_SECONDS {
        return Err(UpstreamOAuthError::InvalidRequest {
            reason: "the handoff lifetime is not a short one".to_owned(),
        });
    }
    let envelope_id = crate::pkce::random_token()?;
    let salt = random_bytes(16).map_err(|error| UpstreamOAuthError::Storage {
        reason: error.to_string(),
    })?;
    let mut envelope = HandoffEnvelope {
        envelope_id: envelope_id.clone(),
        recipient: recipient.to_owned(),
        issued_at: now,
        expires_at: now.saturating_add(ttl_seconds),
        salt: hex::encode(&salt),
        nonce: String::new(),
        ciphertext: String::new(),
    };
    let key =
        derive_key(shared_key, &salt, &key_info(recipient, &envelope_id)).map_err(|error| {
            UpstreamOAuthError::Storage {
                reason: error.to_string(),
            }
        })?;
    let cipher = Cipher::new(&key).map_err(|error| UpstreamOAuthError::Storage {
        reason: error.to_string(),
    })?;
    let plaintext = serde_json::to_vec(payload).map_err(|_| UpstreamOAuthError::Storage {
        reason: "the handoff payload cannot be encoded".to_owned(),
    })?;
    let (nonce, ciphertext) =
        cipher
            .seal(&plaintext, &aad(&envelope))
            .map_err(|error| UpstreamOAuthError::Storage {
                reason: error.to_string(),
            })?;
    envelope.nonce = hex::encode(nonce);
    envelope.ciphertext = hex::encode(ciphertext);
    Ok(envelope)
}

/// Open an envelope and take the credential out of it.
///
/// The order matters: the expiry and the recipient are checked first, the
/// ciphertext is authenticated next, and only a payload that authenticated
/// is allowed to consume the one-time identifier. A tampered envelope
/// therefore never burns the identifier of a legitimate one.
pub fn redeem_handoff(
    envelope: &HandoffEnvelope,
    shared_key: &[u8],
    recipient: &str,
    now: u64,
    guard: &dyn OneTimeUseGuard,
) -> Result<HandoffPayload, UpstreamOAuthError> {
    if now > envelope.expires_at {
        return Err(UpstreamOAuthError::HandoffRejected {
            reason: HandoffFailure::Expired,
        });
    }
    if envelope.recipient != recipient {
        return Err(UpstreamOAuthError::HandoffRejected {
            reason: HandoffFailure::UnknownRecipient,
        });
    }
    let salt = hex::decode(&envelope.salt).map_err(|_| UpstreamOAuthError::HandoffRejected {
        reason: HandoffFailure::Tampered,
    })?;
    let nonce = hex::decode(&envelope.nonce).map_err(|_| UpstreamOAuthError::HandoffRejected {
        reason: HandoffFailure::Tampered,
    })?;
    let ciphertext =
        hex::decode(&envelope.ciphertext).map_err(|_| UpstreamOAuthError::HandoffRejected {
            reason: HandoffFailure::Tampered,
        })?;
    let key = derive_key(
        shared_key,
        &salt,
        &key_info(&envelope.recipient, &envelope.envelope_id),
    )
    .map_err(|_| UpstreamOAuthError::HandoffRejected {
        reason: HandoffFailure::Tampered,
    })?;
    let cipher = Cipher::new(&key).map_err(|_| UpstreamOAuthError::HandoffRejected {
        reason: HandoffFailure::Tampered,
    })?;
    let plaintext = cipher
        .open(&nonce, &ciphertext, &aad(envelope))
        .map_err(|_| UpstreamOAuthError::HandoffRejected {
            reason: HandoffFailure::Tampered,
        })?;
    let payload = serde_json::from_slice::<HandoffPayload>(&plaintext).map_err(|_| {
        UpstreamOAuthError::HandoffRejected {
            reason: HandoffFailure::Tampered,
        }
    })?;
    if !guard.consume(&envelope.envelope_id, now)? {
        return Err(UpstreamOAuthError::HandoffRejected {
            reason: HandoffFailure::Replayed,
        });
    }
    Ok(payload)
}
