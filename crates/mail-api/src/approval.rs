//! Multi Round-Trip Request approval for sends.
//!
//! `docs/spec/mcp.md` section 4 requires that `mail_send` produces an
//! approval round trip before anything reaches the upstream, and that the
//! approval state is sealed and bound to the principal, the identity, the
//! tool, the canonical payload, the idempotency key, the policy revision, an
//! expiry and a one-time nonce.
//!
//! The state here is sealed with a verified MAC. A client cannot mint one,
//! cannot move one to another message and cannot replay one: the nonce is
//! spent the first time an approval is accepted.

use std::collections::HashSet;
use std::sync::Mutex;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::problem::Problem;

/// How long an approval stays usable.
pub const APPROVAL_TTL_SECONDS: u64 = 5 * 60;

type HmacSha256 = Hmac<Sha256>;

/// The sealed description of one approval.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ApprovalPayload {
    /// The one-time nonce.
    #[serde(rename = "n")]
    nonce: String,
    /// The principal the approval was issued to.
    #[serde(rename = "p")]
    principal: String,
    /// The identity the approval was issued for.
    #[serde(rename = "i")]
    identity: String,
    /// The tool the approval was issued for.
    #[serde(rename = "t")]
    tool: String,
    /// The digest of the canonical payload.
    #[serde(rename = "h")]
    payload_digest: String,
    /// The idempotency key.
    #[serde(rename = "k")]
    idempotency_key: String,
    /// The policy revision.
    #[serde(rename = "g")]
    generation: u64,
    /// When the approval expires.
    #[serde(rename = "x")]
    expires_at: u64,
}

/// An approval the client returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalGrant {
    /// The opaque state the server issued.
    pub request_state: String,
    /// Whether the user approved the send.
    pub approved: bool,
}

/// The approval the server asks the client for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRequest {
    /// The opaque state to send back.
    pub request_state: String,
    /// The message to show the user.
    pub message: String,
}

/// What an approval is bound to.
///
/// The bindings are the ones `docs/spec/mcp.md` section 4 names: the
/// principal, the identity, the tool, the canonical payload, the idempotency
/// key and the policy revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalBinding<'a> {
    /// The principal the approval is for.
    pub principal: &'a str,
    /// The identity the approval is for.
    pub identity: &'a str,
    /// The tool the approval is for.
    pub tool: &'a str,
    /// The digest of the canonical payload.
    pub payload_digest: &'a str,
    /// The idempotency key of the send.
    pub idempotency_key: &'a str,
    /// The policy revision.
    pub generation: u64,
}

/// The store that seals approvals and remembers the spent nonces.
#[derive(Debug)]
pub struct ApprovalStore {
    key: Vec<u8>,
    spent: Mutex<HashSet<String>>,
    ttl_seconds: u64,
}

impl ApprovalStore {
    /// Create a store with a sealing key.
    pub fn new(key: Vec<u8>) -> Self {
        Self {
            key,
            spent: Mutex::new(HashSet::new()),
            ttl_seconds: APPROVAL_TTL_SECONDS,
        }
    }

    /// Create a store with a sealing key and a custom lifetime.
    pub fn with_ttl(key: Vec<u8>, ttl_seconds: u64) -> Self {
        let mut store = Self::new(key);
        store.ttl_seconds = ttl_seconds;
        store
    }

    /// Seal an approval for a specific send.
    pub fn seal(
        &self,
        binding: &ApprovalBinding<'_>,
        message: String,
        now: u64,
    ) -> ApprovalRequest {
        let nonce = crate::time::random_id();
        let payload = ApprovalPayload {
            nonce,
            principal: binding.principal.to_owned(),
            identity: binding.identity.to_owned(),
            tool: binding.tool.to_owned(),
            payload_digest: binding.payload_digest.to_owned(),
            idempotency_key: binding.idempotency_key.to_owned(),
            generation: binding.generation,
            expires_at: now.saturating_add(self.ttl_seconds),
        };
        ApprovalRequest {
            request_state: self.encode(&payload),
            message,
        }
    }

    /// Check an approval against the request it is supposed to approve.
    ///
    /// The nonce is spent here, so an approval can be used exactly once.
    pub fn verify(
        &self,
        grant: &ApprovalGrant,
        binding: &ApprovalBinding<'_>,
        now: u64,
    ) -> Result<(), Problem> {
        if !grant.approved {
            return Err(Problem::invalid_input("the send was not approved"));
        }
        let payload = self.decode(&grant.request_state)?;
        if payload.expires_at < now {
            return Err(Problem::invalid_input("the approval has expired"));
        }
        if payload.principal != binding.principal
            || payload.identity != binding.identity
            || payload.tool != binding.tool
            || payload.payload_digest != binding.payload_digest
            || payload.idempotency_key != binding.idempotency_key
            || payload.generation != binding.generation
        {
            return Err(Problem::invalid_input(
                "the approval does not match this request",
            ));
        }
        let mut spent = self.spent.lock().map_err(|_| Problem::internal())?;
        if !spent.insert(payload.nonce) {
            return Err(Problem::invalid_input("the approval was already used"));
        }
        Ok(())
    }

    /// Encode a payload into the opaque state string.
    fn encode(&self, payload: &ApprovalPayload) -> String {
        let body = serde_json::to_vec(payload).unwrap_or_default();
        let mac = self.sign(&body);
        format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(body),
            URL_SAFE_NO_PAD.encode(mac)
        )
    }

    /// Decode and verify an opaque state string.
    fn decode(&self, state: &str) -> Result<ApprovalPayload, Problem> {
        let (body, mac) = state
            .split_once('.')
            .ok_or_else(|| Problem::invalid_input("the approval state is not valid"))?;
        let body = URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|_| Problem::invalid_input("the approval state is not valid"))?;
        let mac = URL_SAFE_NO_PAD
            .decode(mac)
            .map_err(|_| Problem::invalid_input("the approval state is not valid"))?;
        if !self.verify_mac(&body, &mac) {
            return Err(Problem::invalid_input("the approval state is not valid"));
        }
        serde_json::from_slice(&body)
            .map_err(|_| Problem::invalid_input("the approval state is not valid"))
    }

    /// Sign the sealed body.
    fn sign(&self, body: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("hmac accepts any key length");
        mac.update(body);
        mac.finalize().into_bytes().to_vec()
    }

    /// Verify the signature of a sealed body in constant time.
    fn verify_mac(&self, body: &[u8], mac: &[u8]) -> bool {
        let mut verifier =
            HmacSha256::new_from_slice(&self.key).expect("hmac accepts any key length");
        verifier.update(body);
        verifier.verify_slice(mac).is_ok()
    }
}
