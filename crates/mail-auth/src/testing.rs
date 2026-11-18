//! A grant state that lives in memory.
//!
//! The state is a test double and a reference implementation of the
//! [`GrantState`] contract: it keeps the same rules the durable store
//! keeps — an authorization code is exchanged exactly once, a refresh
//! family rotates under a compare-and-swap, a revocation is a record — so
//! that the authorization logic can be exercised without a database.
//!
//! It is **not** a substitute for the durable store. An issuer built on it
//! refuses to start, because refresh tokens and revocations must survive a
//! restart.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use mail_storage::grants::RevocationKind;
use mail_storage::grants::{AccessToken, AuthCode, Grant, OAuthClient, RefreshFamily, Revocation};

use crate::error::AuthError;
use crate::store::{Durability, GrantState};

/// The records a grant state keeps.
#[derive(Debug, Default)]
struct Records {
    clients: HashMap<String, OAuthClient>,
    grants: HashMap<String, Grant>,
    codes: HashMap<String, AuthCode>,
    access_tokens: HashMap<String, AccessToken>,
    families: HashMap<String, RefreshFamily>,
    revocations: Vec<Revocation>,
}

/// A grant state that lives in memory.
#[derive(Debug, Clone)]
pub struct MemoryGrantState {
    records: Arc<Mutex<Records>>,
    durability: Durability,
}

impl MemoryGrantState {
    /// Build a state whose durability is stated.
    pub fn new(durability: Durability) -> Self {
        Self {
            records: Arc::new(Mutex::new(Records::default())),
            durability,
        }
    }

    /// Build a state that a durable store would replace.
    pub fn ephemeral() -> Self {
        Self::new(Durability::Ephemeral)
    }

    /// Build a state that stands in for a durable store.
    pub fn durable() -> Self {
        Self::new(Durability::Persistent)
    }

    /// Open the same records again, as a restarted process would.
    ///
    /// The records survive; nothing else does.
    pub fn reopen(&self) -> Self {
        Self {
            records: Arc::clone(&self.records),
            durability: self.durability,
        }
    }
}

impl GrantState for MemoryGrantState {
    fn durability(&self) -> Durability {
        self.durability
    }

    fn put_client(&self, client: &OAuthClient) -> Result<(), AuthError> {
        let mut records = self.records.lock().expect("the lock is not poisoned");
        records
            .clients
            .insert(client.client_id.clone(), client.clone());
        Ok(())
    }

    fn get_client(&self, client_id: &str) -> Result<Option<OAuthClient>, AuthError> {
        let records = self.records.lock().expect("the lock is not poisoned");
        Ok(records.clients.get(client_id).cloned())
    }

    fn put_grant(&self, grant: &Grant) -> Result<(), AuthError> {
        let mut records = self.records.lock().expect("the lock is not poisoned");
        records.grants.insert(grant.grant_id.clone(), grant.clone());
        Ok(())
    }

    fn get_grant(&self, grant_id: &str) -> Result<Option<Grant>, AuthError> {
        let records = self.records.lock().expect("the lock is not poisoned");
        Ok(records.grants.get(grant_id).cloned())
    }

    fn list_grants(&self, principal: &str) -> Result<Vec<Grant>, AuthError> {
        let records = self.records.lock().expect("the lock is not poisoned");
        let mut grants: Vec<Grant> = records
            .grants
            .values()
            .filter(|grant| grant.principal == principal)
            .cloned()
            .collect();
        grants.sort_by(|left, right| left.grant_id.cmp(&right.grant_id));
        Ok(grants)
    }

    fn revoke_grant(&self, grant_id: &str, at: u64) -> Result<bool, AuthError> {
        let mut records = self.records.lock().expect("the lock is not poisoned");
        let Some(grant) = records.grants.get_mut(grant_id) else {
            return Ok(false);
        };
        if grant.revoked_at.is_some() {
            return Ok(false);
        }
        grant.revoked_at = Some(at);
        records.revocations.push(Revocation {
            subject: grant_id.to_owned(),
            kind: RevocationKind::Grant,
            at,
        });
        Ok(true)
    }

    fn put_auth_code(&self, code: &AuthCode) -> Result<(), AuthError> {
        let mut records = self.records.lock().expect("the lock is not poisoned");
        records.codes.insert(code.code_hash.clone(), code.clone());
        Ok(())
    }

    fn exchange_auth_code(&self, code_hash: &str, now: u64) -> Result<AuthCode, AuthError> {
        let mut records = self.records.lock().expect("the lock is not poisoned");
        let code = records.codes.get_mut(code_hash).ok_or_else(|| {
            AuthError::InvalidGrant("the authorization code is not known".to_owned())
        })?;
        if code.used_at.is_some() {
            return Err(AuthError::InvalidGrant(
                "the authorization code was already exchanged".to_owned(),
            ));
        }
        if code.expires_at <= now {
            return Err(AuthError::InvalidGrant(
                "the authorization code has expired".to_owned(),
            ));
        }
        code.used_at = Some(now);
        Ok(code.clone())
    }

    fn put_access_token(&self, token: &AccessToken) -> Result<(), AuthError> {
        let mut records = self.records.lock().expect("the lock is not poisoned");
        records
            .access_tokens
            .insert(token.token_hash.clone(), token.clone());
        Ok(())
    }

    fn lookup_access_token(
        &self,
        token_hash: &str,
        _now: u64,
    ) -> Result<Option<AccessToken>, AuthError> {
        let records = self.records.lock().expect("the lock is not poisoned");
        Ok(records.access_tokens.get(token_hash).cloned())
    }

    fn put_refresh_family(&self, family: &RefreshFamily) -> Result<(), AuthError> {
        let mut records = self.records.lock().expect("the lock is not poisoned");
        records
            .families
            .insert(family.family_id.clone(), family.clone());
        Ok(())
    }

    fn rotate_refresh(
        &self,
        family_id: &str,
        expected_generation: u64,
        new_token_hash: &str,
        now: u64,
    ) -> Result<RefreshFamily, AuthError> {
        let mut records = self.records.lock().expect("the lock is not poisoned");
        let family = records
            .families
            .get_mut(family_id)
            .ok_or_else(|| AuthError::InvalidGrant("the refresh family is not known".to_owned()))?;
        if family.revoked_at.is_some() {
            return Err(AuthError::InvalidGrant(
                "the refresh family is revoked".to_owned(),
            ));
        }
        if family.generation != expected_generation {
            return Err(AuthError::InvalidGrant(
                "the refresh family moved on before this rotation".to_owned(),
            ));
        }
        family.generation = expected_generation + 1;
        family.current_token_hash = new_token_hash.to_owned();
        family.rotated_at = now;
        Ok(family.clone())
    }

    fn revoke_refresh_family(&self, family_id: &str, at: u64) -> Result<bool, AuthError> {
        let mut records = self.records.lock().expect("the lock is not poisoned");
        let Some(family) = records.families.get_mut(family_id) else {
            return Ok(false);
        };
        if family.revoked_at.is_some() {
            return Ok(false);
        }
        family.revoked_at = Some(at);
        records.revocations.push(Revocation {
            subject: family_id.to_owned(),
            kind: RevocationKind::RefreshFamily,
            at,
        });
        Ok(true)
    }

    fn revoked_after(&self, at: u64) -> Result<Vec<Revocation>, AuthError> {
        let records = self.records.lock().expect("the lock is not poisoned");
        let mut revocations: Vec<Revocation> = records
            .revocations
            .iter()
            .filter(|revocation| revocation.at > at)
            .cloned()
            .collect();
        revocations.sort_by_key(|revocation| (revocation.at, revocation.subject.clone()));
        Ok(revocations)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_authorization_code_is_exchanged_once() {
        let state = MemoryGrantState::durable();
        let code = AuthCode {
            code_hash: "hash".to_owned(),
            client_id: "client".to_owned(),
            redirect_uri: "https://client.example/callback".to_owned(),
            principal: "owner".to_owned(),
            scopes: vec!["mail:messages:list".to_owned()],
            expires_at: 100,
            used_at: None,
        };
        state.put_auth_code(&code).expect("the code is stored");
        assert!(state.exchange_auth_code("hash", 10).is_ok());
        assert!(state.exchange_auth_code("hash", 11).is_err());
    }

    #[test]
    fn a_revocation_is_a_record() {
        let state = MemoryGrantState::durable();
        let grant = Grant {
            grant_id: "grant-1".to_owned(),
            client_id: "client".to_owned(),
            principal: "owner".to_owned(),
            identity: "identity-a".to_owned(),
            scopes: vec!["mail:messages:list".to_owned()],
            revision: 1,
            created_at: 1,
            revoked_at: None,
        };
        state.put_grant(&grant).expect("the grant is stored");
        assert!(
            state
                .revoke_grant("grant-1", 5)
                .expect("the grant is revoked")
        );
        assert_eq!(state.revoked_after(0).expect("the revocations").len(), 1);
    }

    #[test]
    fn a_reopened_state_keeps_the_records() {
        let state = MemoryGrantState::durable();
        let grant = Grant {
            grant_id: "grant-1".to_owned(),
            client_id: "client".to_owned(),
            principal: "owner".to_owned(),
            identity: "identity-a".to_owned(),
            scopes: vec!["mail:messages:list".to_owned()],
            revision: 1,
            created_at: 1,
            revoked_at: None,
        };
        state.put_grant(&grant).expect("the grant is stored");
        let reopened = state.reopen();
        assert!(
            reopened
                .get_grant("grant-1")
                .expect("the grant is there")
                .is_some()
        );
    }
}
