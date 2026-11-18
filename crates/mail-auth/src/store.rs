//! The grant state the authorization server keeps.
//!
//! ADR-0010 gives the grant, consent, code, token, refresh-family and
//! revocation records to the authorization service, and keeps them out of
//! the operator and out of the mail data plane. This module is the seam
//! between that store and this crate: the authorization logic asks for
//! *what it needs* and does not know whether the records live in SQLite,
//! in PostgreSQL or in a test double.
//!
//! Two things the seam adds to the storage trait:
//!
//! - **Durability.** The built-in issuer may only run on state that
//!   survives a restart, because a refresh token that survives a restart
//!   but whose revocation does not would be a revoked grant that still
//!   works. A deployment that cannot say that its state is persistent gets
//!   an issuer that refuses to start.
//! - **One error type.** A store that cannot do what the operation needs
//!   says so, and the caller fails closed.

use std::path::Path;

use mail_storage::GrantStore;
use mail_storage::error::StorageError;
use mail_storage::grants::{AccessToken, AuthCode, Grant, OAuthClient, RefreshFamily, Revocation};
use mail_storage::sqlite::SqliteStore;

use crate::client::ClientPolicy;
use crate::config::GrantType;
use crate::error::AuthError;
use mail_core::Action;

/// Whether the grant state survives a restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Durability {
    /// The state is durable.
    Persistent,
    /// The state is lost when the process ends.
    Ephemeral,
}

/// The grant state the authorization server needs.
pub trait GrantState {
    /// Whether the state survives a restart.
    fn durability(&self) -> Durability;

    /// Store a client.
    fn put_client(&self, client: &OAuthClient) -> Result<(), AuthError>;
    /// Look up a client.
    fn get_client(&self, client_id: &str) -> Result<Option<OAuthClient>, AuthError>;

    /// Store the policy an administrator gave a client.
    ///
    /// The policy is part of the client's persisted state, not a private
    /// note of one process: a registry that restarts must still know which
    /// grant types, actions and identities a client was allowed.
    fn put_client_policy(&self, policy: &ClientPolicy) -> Result<(), AuthError>;
    /// Look up the policy of a client, when one was stored.
    fn get_client_policy(&self, client_id: &str) -> Result<Option<ClientPolicy>, AuthError>;

    /// Store a grant.
    fn put_grant(&self, grant: &Grant) -> Result<(), AuthError>;
    /// Look up a grant.
    fn get_grant(&self, grant_id: &str) -> Result<Option<Grant>, AuthError>;
    /// List the grants of one principal.
    fn list_grants(&self, principal: &str) -> Result<Vec<Grant>, AuthError>;
    /// Revoke a grant.
    fn revoke_grant(&self, grant_id: &str, at: u64) -> Result<bool, AuthError>;

    /// Store an authorization code.
    fn put_auth_code(&self, code: &AuthCode) -> Result<(), AuthError>;
    /// Exchange an authorization code exactly once.
    fn exchange_auth_code(&self, code_hash: &str, now: u64) -> Result<AuthCode, AuthError>;
    /// Atomically validate client and redirect before consuming the code.
    fn exchange_bound_auth_code(
        &self,
        code_hash: &str,
        client_id: &str,
        redirect_uri: &str,
        now: u64,
    ) -> Result<AuthCode, AuthError>;

    /// Store an access token verifier.
    fn put_access_token(&self, token: &AccessToken) -> Result<(), AuthError>;
    /// Look up an access token.
    fn lookup_access_token(
        &self,
        token_hash: &str,
        now: u64,
    ) -> Result<Option<AccessToken>, AuthError>;

    /// Store a refresh family.
    fn put_refresh_family(&self, family: &RefreshFamily) -> Result<(), AuthError>;
    /// Rotate the token of a refresh family.
    fn rotate_refresh(
        &self,
        family_id: &str,
        expected_generation: u64,
        new_token_hash: &str,
        now: u64,
    ) -> Result<RefreshFamily, AuthError>;
    /// Revoke a refresh family.
    fn revoke_refresh_family(&self, family_id: &str, at: u64) -> Result<bool, AuthError>;
    /// List the revocations recorded after a moment.
    fn revoked_after(&self, at: u64) -> Result<Vec<Revocation>, AuthError>;
}

/// The grant state backed by the workspace grant store.
///
/// The durability is stated when the state is built, because only the
/// deployment knows which backend it opened. A claim the backend cannot
/// honor is refused at construction: an issuer that believes its state is
/// durable while it is not would hand out refresh tokens whose revocation
/// a restart forgets. The helpers below make the honest answers easy to
/// give: a SQLite file is durable, an in-memory SQLite is not.
#[derive(Debug)]
pub struct GrantStoreState<S> {
    store: S,
    durability: Durability,
}

/// The proof a backend gives that its state really has a durability.
///
/// Every backend vouches for itself, with evidence: a store that cannot
/// answer for its own durability may only be wrapped as ephemeral. The
/// vouching is checked at construction, so a wrong claim fails closed
/// before the issuer ever starts.
pub trait VouchesDurability {
    /// Whether this store can honestly hold the claimed durability.
    fn vouches_durability(&self, claimed: Durability) -> bool;
}

impl VouchesDurability for SqliteStore {
    fn vouches_durability(&self, claimed: Durability) -> bool {
        match claimed {
            Durability::Ephemeral => true,
            // An in-memory database keeps nothing across a restart, no
            // matter what the deployment says about it.
            Durability::Persistent => self.path() != std::path::Path::new(":memory:"),
        }
    }
}

impl<S: VouchesDurability> GrantStoreState<S> {
    /// Build a state over a store whose durability is known.
    ///
    /// The claim is checked against the store itself: a store that cannot
    /// honor it is refused here, in the same way the issuer refuses to
    /// start on state it does not believe is durable.
    pub fn new(store: S, durability: Durability) -> Result<Self, AuthError> {
        if !store.vouches_durability(durability) {
            return Err(AuthError::Deployment(
                "the grant store cannot honor the claimed durability: state that does not \
                 survive a restart may not be wrapped as persistent"
                    .to_owned(),
            ));
        }
        Ok(Self { store, durability })
    }

    /// Borrow the underlying store.
    pub fn store(&self) -> &S {
        &self.store
    }
}

impl GrantStoreState<SqliteStore> {
    /// Open a durable grant state in a SQLite file.
    pub fn sqlite_file(path: impl AsRef<Path>) -> Result<Self, AuthError> {
        let store = SqliteStore::open(path).map_err(map_storage_error)?;
        Self::new(store, Durability::Persistent)
    }

    /// Open a grant state that is lost when the process ends.
    pub fn sqlite_memory() -> Result<Self, AuthError> {
        let store = SqliteStore::open_in_memory().map_err(map_storage_error)?;
        Self::new(store, Durability::Ephemeral)
    }
}

/// The prefix of the grant identifier a stored client policy sits under.
const CLIENT_POLICY_GRANT_PREFIX: &str = "client-policy:";

/// The synthetic principal and identity of a stored client policy.
///
/// The policy is kept as a grant-store row because the store the clients
/// use has no other table for it. The row is addressed by an identifier the
/// issuer never mints for a real grant, and its principal and identity are
/// this sentinel, so it never appears in the grant listing of a real
/// principal unless a deployment names a principal exactly `corvi:client-policy`.
const CLIENT_POLICY_MARKER: &str = "corvi:client-policy";

/// Encode a client policy as the record the grant store keeps.
fn client_policy_record(policy: &ClientPolicy) -> Grant {
    let mut scopes = Vec::new();
    for grant_type in &policy.grant_types {
        scopes.push(format!("grant:{}", grant_type.as_str()));
    }
    for action in &policy.allowed_actions {
        scopes.push(format!("action:{}", action.as_str()));
    }
    for identity in &policy.allowed_identity_ids {
        scopes.push(format!("identity:{identity}"));
    }
    Grant {
        grant_id: format!("{CLIENT_POLICY_GRANT_PREFIX}{}", policy.client_id),
        client_id: policy.client_id.clone(),
        principal: CLIENT_POLICY_MARKER.to_owned(),
        identity: CLIENT_POLICY_MARKER.to_owned(),
        scopes,
        revision: 1,
        created_at: 0,
        revoked_at: None,
    }
}

/// Decode a stored record back into the policy it carries.
fn client_policy_of(grant: &Grant) -> Result<ClientPolicy, AuthError> {
    let refused = || AuthError::Storage("the stored client policy is not readable".to_owned());
    let client_id = grant
        .grant_id
        .strip_prefix(CLIENT_POLICY_GRANT_PREFIX)
        .ok_or_else(refused)?;
    let mut policy = ClientPolicy {
        client_id: client_id.to_owned(),
        grant_types: Vec::new(),
        allowed_actions: Vec::new(),
        allowed_identity_ids: Vec::new(),
    };
    for scope in &grant.scopes {
        if let Some(name) = scope.strip_prefix("grant:") {
            let grant_type = match name {
                "authorization_code" => GrantType::AuthorizationCode,
                "refresh_token" => GrantType::RefreshToken,
                "client_credentials" => GrantType::ClientCredentials,
                other => {
                    return Err(AuthError::Storage(format!(
                        "the stored client policy names an unknown grant type {other}"
                    )));
                }
            };
            policy.grant_types.push(grant_type);
        } else if let Some(name) = scope.strip_prefix("action:") {
            let action = name.parse::<Action>().map_err(|_| refused())?;
            policy.allowed_actions.push(action);
        } else if let Some(name) = scope.strip_prefix("identity:") {
            policy.allowed_identity_ids.push(name.to_owned());
        } else {
            return Err(refused());
        }
    }
    Ok(policy)
}

impl<S: GrantStore> GrantState for GrantStoreState<S> {
    fn durability(&self) -> Durability {
        self.durability
    }

    fn put_client(&self, client: &OAuthClient) -> Result<(), AuthError> {
        self.store.put_client(client).map_err(map_storage_error)
    }

    fn get_client(&self, client_id: &str) -> Result<Option<OAuthClient>, AuthError> {
        self.store.get_client(client_id).map_err(map_storage_error)
    }

    fn put_client_policy(&self, policy: &ClientPolicy) -> Result<(), AuthError> {
        self.store
            .put_grant(&client_policy_record(policy))
            .map_err(map_storage_error)
    }

    fn get_client_policy(&self, client_id: &str) -> Result<Option<ClientPolicy>, AuthError> {
        let grant_id = format!("{CLIENT_POLICY_GRANT_PREFIX}{client_id}");
        match self.store.get_grant(&grant_id).map_err(map_storage_error)? {
            Some(grant) => Ok(Some(client_policy_of(&grant)?)),
            None => Ok(None),
        }
    }

    fn put_grant(&self, grant: &Grant) -> Result<(), AuthError> {
        self.store.put_grant(grant).map_err(map_storage_error)
    }

    fn get_grant(&self, grant_id: &str) -> Result<Option<Grant>, AuthError> {
        self.store.get_grant(grant_id).map_err(map_storage_error)
    }

    fn list_grants(&self, principal: &str) -> Result<Vec<Grant>, AuthError> {
        self.store.list_grants(principal).map_err(map_storage_error)
    }

    fn revoke_grant(&self, grant_id: &str, at: u64) -> Result<bool, AuthError> {
        self.store
            .revoke_grant(grant_id, at)
            .map_err(map_storage_error)
    }

    fn put_auth_code(&self, code: &AuthCode) -> Result<(), AuthError> {
        self.store.put_auth_code(code).map_err(map_storage_error)
    }

    fn exchange_auth_code(&self, code_hash: &str, now: u64) -> Result<AuthCode, AuthError> {
        self.store
            .exchange_auth_code(code_hash, now)
            .map_err(map_storage_error)
    }

    fn exchange_bound_auth_code(
        &self,
        code_hash: &str,
        client_id: &str,
        redirect_uri: &str,
        now: u64,
    ) -> Result<AuthCode, AuthError> {
        self.store
            .exchange_bound_auth_code(code_hash, client_id, redirect_uri, now)
            .map_err(|error| match error {
                StorageError::NotFound(reason) | StorageError::Conflict(reason) => {
                    AuthError::InvalidGrant(reason)
                }
                other => map_storage_error(other),
            })
    }

    fn put_access_token(&self, token: &AccessToken) -> Result<(), AuthError> {
        self.store
            .put_access_token(token)
            .map_err(map_storage_error)
    }

    fn lookup_access_token(
        &self,
        token_hash: &str,
        now: u64,
    ) -> Result<Option<AccessToken>, AuthError> {
        self.store
            .lookup_access_token(token_hash, now)
            .map_err(map_storage_error)
    }

    fn put_refresh_family(&self, family: &RefreshFamily) -> Result<(), AuthError> {
        self.store
            .put_refresh_family(family)
            .map_err(map_storage_error)
    }

    fn rotate_refresh(
        &self,
        family_id: &str,
        expected_generation: u64,
        new_token_hash: &str,
        now: u64,
    ) -> Result<RefreshFamily, AuthError> {
        self.store
            .rotate_refresh(family_id, expected_generation, new_token_hash, now)
            .map_err(map_storage_error)
    }

    fn revoke_refresh_family(&self, family_id: &str, at: u64) -> Result<bool, AuthError> {
        self.store
            .revoke_refresh_family(family_id, at)
            .map_err(map_storage_error)
    }

    fn revoked_after(&self, at: u64) -> Result<Vec<Revocation>, AuthError> {
        self.store.revoked_after(at).map_err(map_storage_error)
    }
}

/// Turn a storage failure into an authorization failure.
fn map_storage_error(error: StorageError) -> AuthError {
    match error {
        StorageError::Unsupported(reason) => AuthError::StorageUnsupported(reason),
        other => AuthError::Storage(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_persistent_claim_an_in_memory_store_cannot_honor_is_refused() {
        let store = SqliteStore::open_in_memory().expect("the store opens");
        let refused = GrantStoreState::new(store, Durability::Persistent);
        assert!(
            matches!(&refused, Err(AuthError::Deployment(_))),
            "an in-memory store must not be accepted as persistent: {refused:?}"
        );
    }

    #[test]
    fn an_ephemeral_claim_over_an_in_memory_store_is_accepted() {
        let store = SqliteStore::open_in_memory().expect("the store opens");
        let state = GrantStoreState::new(store, Durability::Ephemeral).expect("the claim holds");
        assert_eq!(state.durability(), Durability::Ephemeral);
    }

    #[test]
    fn the_adapter_delegates_to_the_grant_store() {
        let state = GrantStoreState::sqlite_memory().expect("the state opens");
        assert_eq!(state.durability(), Durability::Ephemeral);
        let client = OAuthClient {
            client_id: "client-1".to_owned(),
            name: "A client".to_owned(),
            redirect_uris: vec!["https://client.example/callback".to_owned()],
            secret_hash: None,
            confidential: false,
        };
        state.put_client(&client).expect("the client is stored");
        assert_eq!(state.get_client("client-1"), Ok(Some(client)));
        assert_eq!(state.get_client("client-2"), Ok(None));
    }
}

#[cfg(test)]
mod bound_exchange_tests {
    use mail_storage::grants::{AuthCode, GrantStore};
    use mail_storage::sqlite::SqliteStore;
    use std::sync::{Arc, Barrier};

    #[test]
    fn sqlite_bound_exchange_rejects_mismatches_and_consumes_once_concurrently() {
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        store
            .put_auth_code(&AuthCode {
                code_hash: "hash".into(),
                client_id: "client".into(),
                redirect_uri: "https://example.test/cb".into(),
                principal: "p".into(),
                scopes: vec![],
                expires_at: 100,
                used_at: None,
            })
            .unwrap();
        assert!(
            store
                .exchange_bound_auth_code("hash", "foreign", "https://example.test/cb", 1)
                .is_err()
        );
        assert!(
            store
                .exchange_bound_auth_code("hash", "client", "https://example.test/wrong", 1)
                .is_err()
        );
        let barrier = Arc::new(Barrier::new(3));
        let workers: Vec<_> = (0..2)
            .map(|_| {
                let store = store.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    store
                        .exchange_bound_auth_code("hash", "client", "https://example.test/cb", 1)
                        .is_ok()
                })
            })
            .collect();
        barrier.wait();
        assert_eq!(
            workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .filter(|won| *won)
                .count(),
            1
        );
    }
}
