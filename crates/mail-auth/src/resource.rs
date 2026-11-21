//! The protected resource server.
//!
//! This is the side of Corvi that REST and MCP sit on: it takes a bearer
//! token and answers what the token may do. Three trust domains meet
//! here, and only one of them is accepted:
//!
//! - A **Corvi token** is minted by this deployment, is bound to this
//!   issuer and to one audience, and names the grants it came from.
//! - A **provider token** belongs to an upstream mail provider. It is
//!   never a Corvi token, and it is refused here.
//! - A **management credential** belongs to another audience. A mail
//!   resource token does not open the administration API, and the
//!   administration audience is a different resource identifier.
//!
//! The token is never enough. The server resolves the grants behind it and
//! takes the intersection of what the token was minted with and what those
//! grants allow now, so a narrowed or revoked consent takes effect at
//! once rather than when the token happens to expire.

use mail_core::Action;
use mail_storage::grants::RevocationKind;

use crate::config::AuthConfig;
use crate::error::AuthError;
use crate::store::GrantState;
use crate::tokens::{self, AccessTokenClaims};

/// What one identity of a bearer token authorizes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityAuthorization {
    /// The identity the grant is about.
    pub identity_id: String,
    /// The actions the token may perform on that identity.
    pub actions: Vec<Action>,
}

/// What a bearer token authorizes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authorization {
    /// The principal the token acts as.
    pub principal: String,
    /// The client the token was minted for.
    pub client_id: String,
    /// The scopes the token carries now.
    pub scopes: Vec<String>,
    /// The identities the token may act on, with their actions.
    pub identities: Vec<IdentityAuthorization>,
    /// When the token expires.
    pub expires_at: u64,
}

/// The protected resource server.
pub struct ResourceServer<'a> {
    config: &'a AuthConfig,
    state: &'a dyn GrantState,
    key: &'a [u8],
}

impl std::fmt::Debug for ResourceServer<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResourceServer")
            .field("resource", &self.config.resource)
            .finish_non_exhaustive()
    }
}

impl<'a> ResourceServer<'a> {
    /// Build the resource server.
    pub fn new(config: &'a AuthConfig, state: &'a dyn GrantState, key: &'a [u8]) -> Self {
        Self { config, state, key }
    }

    /// Check a bearer token against a resource.
    ///
    /// The audience is the resource identifier the caller is trying to
    /// reach: the mail resource for REST and MCP, the administration
    /// resource for the management API. A token minted for one is not a
    /// token for the other.
    pub fn authorize(
        &self,
        token: &str,
        audience: &str,
        now: u64,
    ) -> Result<Authorization, AuthError> {
        let claims = tokens::parse_access_token(self.key, token)?;
        self.check_claims(&claims, audience, now)?;
        let record = self
            .state
            .lookup_access_token(&tokens::token_hash(token), now)?
            .ok_or_else(|| AuthError::InvalidToken("the token is not known".to_owned()))?;
        if record.revoked_at.is_some() {
            return Err(AuthError::InvalidToken("the token is revoked".to_owned()));
        }
        if record.expires_at <= now {
            return Err(AuthError::InvalidToken("the token has expired".to_owned()));
        }
        if record.principal != claims.subject {
            return Err(AuthError::InvalidToken(
                "the token does not match its record".to_owned(),
            ));
        }
        if let Some(family_id) = &claims.family_id {
            self.check_family(family_id, claims.issued_at, now)?;
        }
        let identities = self.resolve_grants(&claims, now)?;
        Ok(Authorization {
            principal: claims.subject.clone(),
            client_id: claims.client_id.clone(),
            scopes: claims.scopes.clone(),
            identities,
            expires_at: claims.expires_at,
        })
    }

    /// Whether this deployment accepts an OAuth bearer at the SMTP
    /// interface.
    ///
    /// It does not. ADR-0009 section 6 allows a separately implemented
    /// SMTP OAuth mode with its own audience, its own token profile and
    /// its own send grants; this slice implements none of them, so an
    /// OAuth bearer does not authenticate an SMTP submission.
    pub fn accepts_oauth_at_smtp(&self) -> bool {
        false
    }

    /// Authorize an SMTP submission that presented an OAuth bearer.
    pub fn authorize_smtp_oauth(&self, token: &str) -> Result<(), AuthError> {
        let _ = token;
        Err(AuthError::InvalidToken(
            "this deployment implements no SMTP OAuth mode: an OAuth bearer does not \
             authenticate an SMTP submission"
                .to_owned(),
        ))
    }

    /// Check the bindings a token carries.
    fn check_claims(
        &self,
        claims: &AccessTokenClaims,
        audience: &str,
        now: u64,
    ) -> Result<(), AuthError> {
        if claims.issuer != self.config.issuer {
            return Err(AuthError::InvalidToken(
                "the token was minted by another issuer".to_owned(),
            ));
        }
        if claims.audience != audience {
            return Err(AuthError::InvalidToken(
                "the token is not for this resource".to_owned(),
            ));
        }
        if claims.expires_at <= now {
            return Err(AuthError::InvalidToken("the token has expired".to_owned()));
        }
        Ok(())
    }

    /// Check that the refresh family a token came from is not revoked.
    fn check_family(&self, family_id: &str, issued_at: u64, now: u64) -> Result<(), AuthError> {
        let revocations = self.state.revoked_after(issued_at.saturating_sub(1))?;
        let revoked = revocations.iter().any(|revocation| {
            revocation.kind == RevocationKind::RefreshFamily && revocation.subject == family_id
        });
        if revoked {
            return Err(AuthError::InvalidToken(
                "the refresh family of the token is revoked".to_owned(),
            ));
        }
        let _ = now;
        Ok(())
    }

    /// Resolve the grants a token names into per-identity permissions.
    fn resolve_grants(
        &self,
        claims: &AccessTokenClaims,
        _now: u64,
    ) -> Result<Vec<IdentityAuthorization>, AuthError> {
        let mut identities = Vec::new();
        for grant_id in &claims.grant_ids {
            let grant = self
                .state
                .get_grant(grant_id)?
                .ok_or_else(|| AuthError::InvalidToken("the grant is gone".to_owned()))?;
            if grant.revoked_at.is_some() {
                return Err(AuthError::InvalidToken("the grant is revoked".to_owned()));
            }
            if grant.principal != claims.subject {
                return Err(AuthError::InvalidToken(
                    "the grant belongs to another principal".to_owned(),
                ));
            }
            if grant.client_id != claims.client_id {
                return Err(AuthError::InvalidToken(
                    "the grant belongs to another client".to_owned(),
                ));
            }
            let mut actions = Vec::new();
            for scope in &grant.scopes {
                if !claims.scopes.contains(scope) {
                    continue;
                }
                if let Ok(action) = scope.parse::<Action>() {
                    actions.push(action);
                }
            }
            if actions.is_empty() {
                // The token asks for something the grant no longer allows.
                // The scope alone authorizes nothing.
                continue;
            }
            identities.push(IdentityAuthorization {
                identity_id: grant.identity.clone(),
                actions,
            });
        }
        Ok(identities)
    }
}
