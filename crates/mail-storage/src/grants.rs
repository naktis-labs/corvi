//! The grant store: the OAuth authorization service's own state.
//!
//! ADR-0010 assigns the grant, consent, token and revocation records to the
//! authorization service, not to the operator and not to the mail data
//! plane. This module holds that boundary: clients, consented grants, single
//! use authorization codes, opaque access-token verifiers, rotating refresh
//! families and revocations.
//!
//! Two rules hold across the whole store:
//!
//! 1. **An access token is stored as a verifier.** Only a keyed hash of the
//!    token is kept, so a database dump does not yield a usable bearer
//!    token. The refresh token is different: the outgoing transport has to
//!    present it, so it is recoverable — and therefore belongs in the
//!    [`crate::secret`] custody boundary, not in this table.
//! 2. **A revocation is a fact, not a state.** Revoked grants and token
//!    families are recorded with the moment they were revoked, so a restore
//!    can tell an old grant from a revoked one instead of silently
//!    resurrecting it.

use crate::error::StorageResult;

/// An OAuth client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthClient {
    /// The client identifier.
    pub client_id: String,
    /// The human-readable name.
    pub name: String,
    /// The redirect URIs the client may use.
    pub redirect_uris: Vec<String>,
    /// The hash of the client secret, when the client is confidential.
    pub secret_hash: Option<String>,
    /// Whether the client can keep a secret.
    pub confidential: bool,
}

/// A consented grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// The grant identifier.
    pub grant_id: String,
    /// The client the grant was issued to.
    pub client_id: String,
    /// The principal the grant is for.
    pub principal: String,
    /// The identity the grant covers.
    pub identity: String,
    /// The scopes the grant carries.
    pub scopes: Vec<String>,
    /// The revision of the grant; every change increases it.
    pub revision: u64,
    /// When the grant was created.
    pub created_at: u64,
    /// When the grant was revoked.
    pub revoked_at: Option<u64>,
}

/// An authorization code, held as a hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthCode {
    /// The hash of the code.
    pub code_hash: String,
    /// The client the code was issued to.
    pub client_id: String,
    /// The redirect URI the code is bound to.
    pub redirect_uri: String,
    /// The principal the code is for.
    pub principal: String,
    /// The scopes the code carries.
    pub scopes: Vec<String>,
    /// When the code expires.
    pub expires_at: u64,
    /// When the code was exchanged; an exchanged code is never exchanged
    /// again.
    pub used_at: Option<u64>,
}

/// An access token, held as a verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessToken {
    /// The keyed hash of the token.
    pub token_hash: String,
    /// The grant the token belongs to.
    pub grant_id: String,
    /// The principal the token is for.
    pub principal: String,
    /// The scopes the token carries.
    pub scopes: Vec<String>,
    /// When the token expires.
    pub expires_at: u64,
    /// When the token was revoked.
    pub revoked_at: Option<u64>,
}

/// A family of refresh tokens that rotate around one grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshFamily {
    /// The family identifier.
    pub family_id: String,
    /// The grant the family belongs to.
    pub grant_id: String,
    /// The generation of the current token.
    pub generation: u64,
    /// The hash of the current token.
    pub current_token_hash: String,
    /// When the current token was issued.
    pub rotated_at: u64,
    /// When the family was revoked.
    pub revoked_at: Option<u64>,
}

/// What was revoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationKind {
    /// A grant.
    Grant,
    /// A refresh family.
    RefreshFamily,
    /// An access token.
    AccessToken,
}

impl RevocationKind {
    /// The name of the kind.
    pub fn as_str(&self) -> &'static str {
        match self {
            RevocationKind::Grant => "grant",
            RevocationKind::RefreshFamily => "refreshFamily",
            RevocationKind::AccessToken => "accessToken",
        }
    }
}

/// One revocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revocation {
    /// The identifier of the revoked thing.
    pub subject: String,
    /// What kind of thing it was.
    pub kind: RevocationKind,
    /// When it was revoked.
    pub at: u64,
}

/// The grant store.
pub trait GrantStore {
    /// Store a client, replacing any earlier record with the same id.
    fn put_client(&self, client: &OAuthClient) -> StorageResult<()>;
    /// Look up a client.
    fn get_client(&self, client_id: &str) -> StorageResult<Option<OAuthClient>>;
    /// Store a grant.
    ///
    /// A later write of the same grant does not lower its revision and
    /// does not clear a revocation: the revision only ever grows, and a
    /// revoked grant stays revoked.
    fn put_grant(&self, grant: &Grant) -> StorageResult<()>;
    /// Look up a grant.
    fn get_grant(&self, grant_id: &str) -> StorageResult<Option<Grant>>;
    /// List the grants of one principal.
    fn list_grants(&self, principal: &str) -> StorageResult<Vec<Grant>>;
    /// Revoke a grant and record the revocation.
    fn revoke_grant(&self, grant_id: &str, at: u64) -> StorageResult<bool>;
    /// Store an authorization code.
    fn put_auth_code(&self, code: &AuthCode) -> StorageResult<()>;
    /// Exchange an authorization code exactly once.
    ///
    /// A code that was already exchanged, that has expired, or that does
    /// not exist is refused: an authorization code is single use, and
    /// reusing one is the sign of a replay.
    fn exchange_auth_code(&self, code_hash: &str, now: u64) -> StorageResult<AuthCode>;
    /// Store an access-token verifier.
    ///
    /// The record of a token is written once: the grant, the principal,
    /// the scopes and the expiry of a token do not change afterwards, and a
    /// later write of the same verifier does not rebind it to another
    /// grant. Only the revocation is added, and it is never cleared.
    fn put_access_token(&self, token: &AccessToken) -> StorageResult<()>;
    /// Look up an access token.
    ///
    /// A token that does not exist, that has expired, that was revoked, or
    /// that belongs to a revoked grant is not returned. The revocation
    /// ledger outside the database is consulted as well, so a revocation
    /// that the database has not caught up with yet still refuses the
    /// token.
    fn lookup_access_token(&self, token_hash: &str, now: u64)
    -> StorageResult<Option<AccessToken>>;

    /// Store a refresh family.
    ///
    /// A later write of the same family does not lower its generation: the
    /// generation is the compare-and-swap of the rotation, and a stale
    /// write that lowered it would let a worker rotate the family twice.
    fn put_refresh_family(&self, family: &RefreshFamily) -> StorageResult<()>;
    /// Rotate the token of a refresh family.
    ///
    /// The rotation is a compare-and-swap on the generation: two workers
    /// that both believe they may refresh cannot both succeed, so a
    /// provider token is never rotated twice.
    fn rotate_refresh(
        &self,
        family_id: &str,
        expected_generation: u64,
        new_token_hash: &str,
        now: u64,
    ) -> StorageResult<RefreshFamily>;
    /// Revoke a refresh family and record the revocation.
    fn revoke_refresh_family(&self, family_id: &str, at: u64) -> StorageResult<bool>;
    /// List the revocations recorded after a moment.
    fn revoked_after(&self, at: u64) -> StorageResult<Vec<Revocation>>;
}
