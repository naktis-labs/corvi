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

use crate::error::AuthError;

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
/// deployment knows which backend it opened. The helpers below make the
/// honest answers easy to give: a SQLite file is durable, an in-memory
/// SQLite is not.
#[derive(Debug)]
pub struct GrantStoreState<S> {
    store: S,
    durability: Durability,
}

impl<S> GrantStoreState<S> {
    /// Build a state over a store whose durability is known.
    pub fn new(store: S, durability: Durability) -> Self {
        Self { store, durability }
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
        Ok(Self::new(store, Durability::Persistent))
    }

    /// Open a grant state that is lost when the process ends.
    pub fn sqlite_memory() -> Result<Self, AuthError> {
        let store = SqliteStore::open_in_memory().map_err(map_storage_error)?;
        Ok(Self::new(store, Durability::Ephemeral))
    }
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
