//! Opaque, scoped paging cursors.
//!
//! `docs/spec/mcp.md` section 8 requires a cursor to be cryptographically
//! bound to the caller's grants, the identity, the operation, the search
//! query, the policy revision and a safe mailbox iteration position, and
//! forbids encoding privileged upstream identifiers in the cursor bytes.
//!
//! The cursor therefore carries a sealed description of those bindings and a
//! random nonce; the upstream iteration position stays on the server, keyed
//! by that nonce. A caller can neither read the upstream position nor move a
//! cursor to another identity, another query or another policy revision.

use std::collections::HashMap;
use std::sync::Mutex;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::problem::Problem;

/// How long a cursor stays usable.
pub const CURSOR_TTL_SECONDS: u64 = 15 * 60;

type HmacSha256 = Hmac<Sha256>;

/// What a cursor is bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorScope {
    /// The authenticated principal the cursor was issued to.
    pub principal: String,
    /// The identity the cursor was issued for.
    pub identity: String,
    /// The action the cursor was issued for.
    pub action: String,
    /// A digest of the query the cursor was issued for.
    pub query: String,
    /// The policy revision the cursor was issued under.
    pub policy_generation: u64,
}

impl CursorScope {
    /// The scope of a listing, which has no query.
    pub fn listing(principal: &str, identity: &str, action: &str, policy_generation: u64) -> Self {
        Self {
            principal: principal.to_owned(),
            identity: identity.to_owned(),
            action: action.to_owned(),
            query: digest(""),
            policy_generation,
        }
    }

    /// The scope of a search, which is bound to the literal query.
    pub fn search(
        principal: &str,
        identity: &str,
        action: &str,
        query: &str,
        policy_generation: u64,
    ) -> Self {
        Self {
            principal: principal.to_owned(),
            identity: identity.to_owned(),
            action: action.to_owned(),
            query: digest(query),
            policy_generation,
        }
    }
}

/// The sealed description inside a cursor.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CursorPayload {
    /// The random nonce that names the server-side iteration position.
    #[serde(rename = "n")]
    nonce: String,
    /// The principal the cursor was issued to.
    #[serde(rename = "p")]
    principal: String,
    /// The identity the cursor was issued for.
    #[serde(rename = "i")]
    identity: String,
    /// The action the cursor was issued for.
    #[serde(rename = "a")]
    action: String,
    /// The digest of the query.
    #[serde(rename = "q")]
    query: String,
    /// The policy revision.
    #[serde(rename = "g")]
    generation: u64,
    /// When the cursor was issued.
    #[serde(rename = "t")]
    issued_at: u64,
}

/// The server-side half of a cursor.
#[derive(Debug, Clone)]
struct CursorEntry {
    upstream_cursor: Option<String>,
    expires_at: u64,
}

/// The store that issues and resolves cursors.
#[derive(Debug)]
pub struct CursorStore {
    key: Vec<u8>,
    entries: Mutex<HashMap<String, CursorEntry>>,
    ttl_seconds: u64,
}

impl CursorStore {
    /// Create a store with a sealing key.
    pub fn new(key: Vec<u8>) -> Self {
        Self {
            key,
            entries: Mutex::new(HashMap::new()),
            ttl_seconds: CURSOR_TTL_SECONDS,
        }
    }

    /// Create a store with a sealing key and a custom lifetime.
    pub fn with_ttl(key: Vec<u8>, ttl_seconds: u64) -> Self {
        let mut store = Self::new(key);
        store.ttl_seconds = ttl_seconds;
        store
    }

    /// Issue a cursor for a scope and an upstream iteration position.
    pub fn issue(
        &self,
        scope: &CursorScope,
        upstream_cursor: Option<String>,
        now: u64,
    ) -> Result<String, Problem> {
        let nonce = crate::time::random_id();
        let payload = CursorPayload {
            nonce: nonce.clone(),
            principal: scope.principal.clone(),
            identity: scope.identity.clone(),
            action: scope.action.clone(),
            query: scope.query.clone(),
            generation: scope.policy_generation,
            issued_at: now,
        };
        let sealed = self.seal(&payload)?;
        let expires_at = now.saturating_add(self.ttl_seconds);
        let mut entries = self.entries.lock().map_err(|_| Problem::internal())?;
        entries.retain(|_, entry| entry.expires_at >= now);
        entries.insert(
            nonce,
            CursorEntry {
                upstream_cursor,
                expires_at,
            },
        );
        Ok(sealed)
    }

    /// Resolve a cursor into the upstream iteration position it names.
    ///
    /// The returned position is `None` for the first page. A cursor that was
    /// issued for another principal, identity, action, query or policy
    /// revision is stale; one that cannot be verified, or that has expired,
    /// is invalid. The two are distinct so a client can tell "start again"
    /// from "start from the beginning".
    pub fn resolve(
        &self,
        cursor: &str,
        scope: &CursorScope,
        now: u64,
    ) -> Result<Option<String>, Problem> {
        let payload = self.open(cursor)?;
        if payload.principal != scope.principal
            || payload.identity != scope.identity
            || payload.action != scope.action
            || payload.query != scope.query
        {
            return Err(Problem::cursor_stale());
        }
        if payload.generation != scope.policy_generation {
            return Err(Problem::cursor_stale());
        }
        let entries = self.entries.lock().map_err(|_| Problem::internal())?;
        let entry = entries
            .get(&payload.nonce)
            .ok_or_else(Problem::cursor_invalid)?;
        if entry.expires_at < now {
            return Err(Problem::cursor_invalid());
        }
        Ok(entry.upstream_cursor.clone())
    }

    /// Seal a payload into the cursor string.
    fn seal(&self, payload: &CursorPayload) -> Result<String, Problem> {
        let body = serde_json::to_vec(payload).map_err(|_| Problem::internal())?;
        let mac = self.sign(&body);
        Ok(format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(body),
            URL_SAFE_NO_PAD.encode(mac)
        ))
    }

    /// Open and verify a cursor string.
    fn open(&self, cursor: &str) -> Result<CursorPayload, Problem> {
        let (body, mac) = cursor.split_once('.').ok_or_else(Problem::cursor_invalid)?;
        let body = URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|_| Problem::cursor_invalid())?;
        let mac = URL_SAFE_NO_PAD
            .decode(mac)
            .map_err(|_| Problem::cursor_invalid())?;
        if !self.verify(&body, &mac) {
            return Err(Problem::cursor_invalid());
        }
        serde_json::from_slice(&body).map_err(|_| Problem::cursor_invalid())
    }

    /// Sign the sealed body.
    fn sign(&self, body: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("hmac accepts any key length");
        mac.update(body);
        mac.finalize().into_bytes().to_vec()
    }

    /// Verify the signature of a sealed body in constant time.
    fn verify(&self, body: &[u8], mac: &[u8]) -> bool {
        let mut verifier =
            HmacSha256::new_from_slice(&self.key).expect("hmac accepts any key length");
        verifier.update(body);
        verifier.verify_slice(mac).is_ok()
    }
}

/// The digest of a query string.
pub fn digest(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> CursorScope {
        CursorScope::listing("principal", "identity", "mail:messages:list", 1)
    }

    #[test]
    fn a_cursor_round_trips_its_position() {
        let store = CursorStore::new(vec![7_u8; 32]);
        let cursor = store
            .issue(&scope(), Some("upstream-token".to_owned()), 100)
            .unwrap();
        assert_eq!(
            store.resolve(&cursor, &scope(), 100).unwrap(),
            Some("upstream-token".to_owned())
        );
    }

    #[test]
    fn the_cursor_does_not_carry_the_upstream_position() {
        let store = CursorStore::new(vec![7_u8; 32]);
        let cursor = store
            .issue(&scope(), Some("upstream-token".to_owned()), 100)
            .unwrap();
        assert!(!cursor.contains("upstream-token"));
    }

    #[test]
    fn a_tampered_cursor_is_invalid() {
        let store = CursorStore::new(vec![7_u8; 32]);
        let cursor = store.issue(&scope(), None, 100).unwrap();
        let tampered = format!("{}x", cursor);
        assert_eq!(
            store
                .resolve(&tampered, &scope(), 100)
                .unwrap_err()
                .error_code(),
            "CURSOR_INVALID"
        );
    }

    #[test]
    fn a_cursor_from_another_principal_is_stale() {
        let store = CursorStore::new(vec![7_u8; 32]);
        let cursor = store.issue(&scope(), None, 100).unwrap();
        let other = CursorScope::listing("other", "identity", "mail:messages:list", 1);
        assert_eq!(
            store
                .resolve(&cursor, &other, 100)
                .unwrap_err()
                .error_code(),
            "CURSOR_STALE"
        );
    }

    #[test]
    fn a_cursor_from_another_policy_revision_is_stale() {
        let store = CursorStore::new(vec![7_u8; 32]);
        let cursor = store.issue(&scope(), None, 100).unwrap();
        let other = CursorScope::listing("principal", "identity", "mail:messages:list", 2);
        assert_eq!(
            store
                .resolve(&cursor, &other, 100)
                .unwrap_err()
                .error_code(),
            "CURSOR_STALE"
        );
    }

    #[test]
    fn an_expired_cursor_is_invalid() {
        let store = CursorStore::new(vec![7_u8; 32]);
        let cursor = store.issue(&scope(), None, 100).unwrap();
        assert_eq!(
            store
                .resolve(&cursor, &scope(), 100 + CURSOR_TTL_SECONDS + 1)
                .unwrap_err()
                .error_code(),
            "CURSOR_INVALID"
        );
    }

    #[test]
    fn a_search_cursor_is_bound_to_its_query() {
        let store = CursorStore::new(vec![7_u8; 32]);
        let cursor = store
            .issue(
                &CursorScope::search("p", "i", "mail:messages:search", "invoice", 1),
                None,
                0,
            )
            .unwrap();
        let other = CursorScope::search("p", "i", "mail:messages:search", "receipt", 1);
        assert_eq!(
            store.resolve(&cursor, &other, 0).unwrap_err().error_code(),
            "CURSOR_STALE"
        );
    }
}
