//! The authorization server.
//!
//! This module holds the protocol logic of the built-in Corvi issuer:
//! the authorization code flow with PKCE, the consent that produces
//! per-identity grants, the token endpoint with its refresh rotation, and
//! the revocation endpoint.
//!
//! There is no HTTP here. The shapes below are what an HTTP layer maps
//! onto: a request struct, a response struct, and typed errors that carry
//! the OAuth error code they map to.
//!
//! The rules the code holds:
//!
//! - The issuer identifier is compared exactly, on the request and on the
//!   code, so a request bound to another issuer never reaches a grant.
//! - The redirect URI is compared exactly, on the request and on the
//!   exchange.
//! - An authorization code is exchanged exactly once, and the exchange
//!   needs the code verifier that matches the challenge.
//! - The consent grants the intersection of what was asked for and what
//!   the identity allows, and a request outside the allowance is refused.
//! - A refresh token rotates; presenting an old one revokes the family.

use mail_core::Action;
use mail_storage::grants::{AccessToken, AuthCode, Grant, RefreshFamily};
use serde::{Deserialize, Serialize};

use crate::client::{ClientRegistry, RegisteredClient};
use crate::config::{AuthConfig, GrantType, PkceMethod};
use crate::consent::{self, Allowances, AuthorizationDetail};
use crate::discovery;
use crate::error::AuthError;
use crate::pkce::{self, PkceChallenge};
use crate::store::{Durability, GrantState};
use crate::tokens::{self, AccessTokenClaims};

/// The prefix of a Corvi authorization code.
const CODE_PREFIX: &str = "cod1";

/// An authorization request, as the authorization endpoint receives it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationRequest {
    /// The issuer the request is bound to.
    pub issuer: String,
    /// The client that asks.
    pub client_id: String,
    /// The redirect URI the code is delivered to.
    pub redirect_uri: String,
    /// The response type; only `code` is supported.
    pub response_type: String,
    /// The requested scopes.
    pub scope: Vec<String>,
    /// The state the client wants echoed.
    pub state: Option<String>,
    /// The PKCE code challenge.
    pub code_challenge: String,
    /// The PKCE code challenge method; only `S256` is supported.
    pub code_challenge_method: String,
    /// The resource the client asks for.
    pub resource: Option<String>,
    /// The `corvi_mail` authorization details the client asks for.
    pub authorization_details: Vec<AuthorizationDetail>,
}

/// The answer of the authorization endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationResponse {
    /// The authorization code.
    pub code: String,
    /// The state, echoed unchanged.
    pub state: Option<String>,
    /// The redirect URI the code belongs to.
    pub redirect_uri: String,
    /// The issuer the code is bound to.
    pub issuer: String,
    /// When the code expires.
    pub expires_at: u64,
    /// The grants the code carries.
    pub grant_ids: Vec<String>,
}

/// A token request, as the token endpoint receives it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenRequest {
    /// The grant type the client asks for.
    pub grant_type: String,
    /// The client that asks.
    pub client_id: String,
    /// The client secret, for a confidential client.
    pub client_secret: Option<String>,
    /// The authorization code, for the authorization code grant.
    pub code: Option<String>,
    /// The code verifier, for the authorization code grant.
    pub code_verifier: Option<String>,
    /// The redirect URI, for the authorization code grant.
    pub redirect_uri: Option<String>,
    /// The refresh token, for the refresh grant.
    pub refresh_token: Option<String>,
    /// The resource the client asks for.
    pub resource: Option<String>,
}

/// The answer of the token endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenResponse {
    /// The access token.
    pub access_token: String,
    /// The token type.
    pub token_type: String,
    /// How long the access token lives, in seconds.
    pub expires_in: u64,
    /// The refresh token, when the deployment issues one.
    pub refresh_token: Option<String>,
    /// The granted scopes, space delimited.
    pub scope: String,
    /// The granted `corvi_mail` authorization details, one per identity.
    pub authorization_details: Vec<serde_json::Value>,
    /// The issuer, as RFC 9207 asks.
    pub issuer: String,
}

/// A revocation request, as the revocation endpoint receives it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationRequest {
    /// The client that asks.
    pub client_id: String,
    /// The client secret, for a confidential client.
    pub client_secret: Option<String>,
    /// The token to revoke.
    pub token: String,
}

/// The bindings an authorization code carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CodePayload {
    issuer: String,
    challenge: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    state: Option<String>,
    resource: String,
    grant_ids: Vec<String>,
    scopes: Vec<String>,
}

/// The built-in Corvi authorization server.
pub struct Issuer<'a> {
    config: &'a AuthConfig,
    state: &'a dyn GrantState,
    key: &'a [u8],
    clients: ClientRegistry<'a>,
}

impl std::fmt::Debug for Issuer<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Issuer")
            .field("issuer", &self.config.issuer)
            .field("resource", &self.config.resource)
            .finish_non_exhaustive()
    }
}

impl<'a> Issuer<'a> {
    /// Build the issuer.
    ///
    /// The built-in issuer refuses to start on state that does not survive
    /// a restart: a refresh token that outlives the process while its
    /// revocation does not would be a revoked grant that still works.
    pub fn new(
        config: &'a AuthConfig,
        state: &'a dyn GrantState,
        key: &'a [u8],
        administrator_secret_hash: Option<&'a str>,
    ) -> Result<Self, AuthError> {
        config.validate()?;
        if config.built_in_issuer_enabled() && state.durability() != Durability::Persistent {
            return Err(AuthError::Deployment(
                "the built-in issuer requires a persistent grant store: an ephemeral one loses \
                 refresh tokens and revocations at restart"
                    .to_owned(),
            ));
        }
        Ok(Self {
            clients: ClientRegistry::new(config, state, key, administrator_secret_hash),
            config,
            state,
            key,
        })
    }

    /// The client registry, so that an administrator may provision clients.
    pub fn clients(&mut self) -> &mut ClientRegistry<'a> {
        &mut self.clients
    }

    /// The configuration the issuer runs with.
    pub fn config(&self) -> &AuthConfig {
        self.config
    }

    /// Start an authorization.
    ///
    /// The request is checked against the issuer, the client and the
    /// principal's allowance before anything is written down. The consent
    /// decisions are the identities the owner selected; the caller supplies
    /// them because the consent screen itself is not part of this crate.
    pub fn authorize(
        &self,
        request: &AuthorizationRequest,
        principal: &str,
        allowance: &Allowances,
        consented_identities: &[String],
        now: u64,
    ) -> Result<AuthorizationResponse, AuthError> {
        discovery::check_issuer(self.config, &request.issuer)?;
        if request.response_type != "code" {
            return Err(AuthError::InvalidRequest(
                "only the code response type is supported".to_owned(),
            ));
        }
        let client = self.clients.lookup(&request.client_id)?;
        ClientRegistry::check_grant_type(&client, GrantType::AuthorizationCode)?;
        ClientRegistry::check_redirect_uri(&client, &request.redirect_uri)?;
        if let Some(resource) = &request.resource {
            if resource != &self.config.resource {
                return Err(AuthError::InvalidResource(
                    "the request asks for a resource this issuer does not serve".to_owned(),
                ));
            }
        }
        let challenge = PkceChallenge {
            method: PkceMethod::parse(&request.code_challenge_method).ok_or_else(|| {
                AuthError::InvalidPkce("the code challenge method is not known".to_owned())
            })?,
            value: request.code_challenge.clone(),
        };
        pkce::check_challenge(&challenge)?;

        let allowed_actions: Vec<Action> = self
            .config
            .scopes_supported
            .iter()
            .copied()
            .filter(|action| client.policy.allowed_actions.contains(action))
            .collect();
        let requested_scopes = consent::resolve_requested_scopes(&request.scope, &allowed_actions)?;

        let consented = if request.authorization_details.is_empty() {
            consent::resolve_flat_consent(allowance, &requested_scopes, consented_identities)?
        } else {
            consent::resolve_consent(
                allowance,
                &request.authorization_details,
                consented_identities,
            )?
        };

        let mut grant_ids = Vec::new();
        let mut granted_scopes: Vec<String> = Vec::new();
        for grant in &consented {
            ClientRegistry::check_identity(&client, &grant.identity_id)?;
            for action in &grant.actions {
                ClientRegistry::check_action(&client, *action)?;
            }
            let grant_id = tokens::random_id(16)?;
            let record = Grant {
                grant_id: grant_id.clone(),
                client_id: client.record.client_id.clone(),
                principal: principal.to_owned(),
                identity: grant.identity_id.clone(),
                scopes: grant
                    .actions
                    .iter()
                    .map(|action| action.as_str().to_owned())
                    .collect(),
                revision: 1,
                created_at: now,
                revoked_at: None,
            };
            self.state.put_grant(&record)?;
            grant_ids.push(grant_id);
            for action in &grant.actions {
                let name = action.as_str().to_owned();
                if !granted_scopes.contains(&name) {
                    granted_scopes.push(name);
                }
            }
        }

        let expires_at = now + self.config.authorization_code_lifetime_seconds;
        let payload = CodePayload {
            issuer: self.config.issuer.clone(),
            challenge: challenge.value,
            state: request.state.clone(),
            resource: request
                .resource
                .clone()
                .unwrap_or_else(|| self.config.resource.clone()),
            grant_ids: grant_ids.clone(),
            scopes: granted_scopes.clone(),
        };
        let code = mint_code(&payload)?;
        self.state.put_auth_code(&AuthCode {
            code_hash: tokens::token_hash(&code),
            client_id: client.record.client_id.clone(),
            redirect_uri: request.redirect_uri.clone(),
            principal: principal.to_owned(),
            scopes: granted_scopes,
            expires_at,
            used_at: None,
        })?;

        Ok(AuthorizationResponse {
            code,
            state: request.state.clone(),
            redirect_uri: request.redirect_uri.clone(),
            issuer: self.config.issuer.clone(),
            expires_at,
            grant_ids,
        })
    }

    /// Exchange a grant for tokens.
    pub fn token(&self, request: &TokenRequest, now: u64) -> Result<TokenResponse, AuthError> {
        let grant_type = match request.grant_type.as_str() {
            "authorization_code" => GrantType::AuthorizationCode,
            "refresh_token" => GrantType::RefreshToken,
            other => {
                return Err(AuthError::UnsupportedGrantType(other.to_owned()));
            }
        };
        if !self.config.supports_grant_type(grant_type) {
            return Err(AuthError::UnsupportedGrantType(
                "the grant type is not supported by this issuer".to_owned(),
            ));
        }
        let client = self
            .clients
            .authenticate(&request.client_id, request.client_secret.as_deref())?;
        ClientRegistry::check_grant_type(&client, grant_type)?;
        match grant_type {
            GrantType::AuthorizationCode => self.exchange_code(&client, request, now),
            GrantType::RefreshToken => self.refresh(&client, request, now),
            GrantType::ClientCredentials => Err(AuthError::UnsupportedGrantType(
                "the client credentials grant is not implemented in this slice".to_owned(),
            )),
        }
    }

    /// Revoke a token.
    ///
    /// An unknown token is not an error: the endpoint answers the same way
    /// for a token that exists and one that does not, so it cannot be used
    /// to probe which tokens are real.
    pub fn revoke(&self, request: &RevocationRequest, now: u64) -> Result<(), AuthError> {
        let client = self
            .clients
            .authenticate(&request.client_id, request.client_secret.as_deref())?;
        if request.token.starts_with("crt1.") {
            if let Ok(claims) = tokens::parse_refresh_token(self.key, &request.token) {
                for grant_id in &claims.grant_ids {
                    if let Some(grant) = self.state.get_grant(grant_id)? {
                        if grant.client_id != client.record.client_id {
                            return Err(AuthError::InvalidClient(
                                "the token belongs to another client".to_owned(),
                            ));
                        }
                    }
                }
                self.state.revoke_refresh_family(&claims.family_id, now)?;
            }
            return Ok(());
        }
        let hash = tokens::token_hash(&request.token);
        if let Some(record) = self.state.lookup_access_token(&hash, now)? {
            let mut record = record;
            record.revoked_at = Some(now);
            self.state.put_access_token(&record)?;
        }
        Ok(())
    }

    /// Exchange an authorization code for tokens.
    fn exchange_code(
        &self,
        client: &RegisteredClient,
        request: &TokenRequest,
        now: u64,
    ) -> Result<TokenResponse, AuthError> {
        let code = request.code.as_ref().ok_or_else(|| {
            AuthError::InvalidRequest("the authorization code is missing".to_owned())
        })?;
        let payload = parse_code(code)?;
        discovery::check_issuer(self.config, &payload.issuer)?;
        let record = self
            .state
            .exchange_auth_code(&tokens::token_hash(code), now)
            .map_err(|error| match error {
                AuthError::InvalidGrant(reason) => AuthError::InvalidGrant(reason),
                other => other,
            })?;
        if record.client_id != client.record.client_id {
            return Err(AuthError::InvalidGrant(
                "the authorization code was issued to another client".to_owned(),
            ));
        }
        let redirect_uri = request
            .redirect_uri
            .as_ref()
            .ok_or_else(|| AuthError::InvalidRequest("the redirect uri is missing".to_owned()))?;
        if &record.redirect_uri != redirect_uri {
            return Err(AuthError::InvalidRedirectUri(
                "the redirect uri does not match the one the code was issued for".to_owned(),
            ));
        }
        let verifier = request
            .code_verifier
            .as_ref()
            .ok_or_else(|| AuthError::InvalidPkce("the code verifier is missing".to_owned()))?;
        pkce::verify_challenge(
            &PkceChallenge {
                method: PkceMethod::S256,
                value: payload.challenge.clone(),
            },
            verifier,
        )?;
        if let Some(resource) = &request.resource {
            if resource != &self.config.resource {
                return Err(AuthError::InvalidResource(
                    "the request asks for a resource this issuer does not serve".to_owned(),
                ));
            }
        }
        let (grants, scopes, principal) =
            self.load_grants(&payload.grant_ids, client, &payload.scopes)?;
        self.issue(
            &client.record.client_id,
            &grants,
            &scopes,
            &principal,
            FamilyPlan::New,
            now,
        )
    }

    /// Refresh an access token.
    fn refresh(
        &self,
        client: &RegisteredClient,
        request: &TokenRequest,
        now: u64,
    ) -> Result<TokenResponse, AuthError> {
        let presented = request
            .refresh_token
            .as_ref()
            .ok_or_else(|| AuthError::InvalidRequest("the refresh token is missing".to_owned()))?;
        let claims = tokens::parse_refresh_token(self.key, presented)?;
        let next_generation = claims.generation + 1;
        let next_token = tokens::mint_refresh_token(
            self.key,
            &claims.family_id,
            next_generation,
            &claims.grant_ids,
            &claims.scopes,
        )?;
        // The rotation is the currency check: the compare-and-swap only
        // succeeds while the presented token is the current one. A failure
        // means the token was already used, so the whole family goes.
        let rotation = self.state.rotate_refresh(
            &claims.family_id,
            claims.generation,
            &tokens::token_hash(&next_token),
            now,
        );
        match rotation {
            Ok(_) => {}
            Err(_) => {
                self.state.revoke_refresh_family(&claims.family_id, now)?;
                return Err(AuthError::InvalidGrant(
                    "the refresh token was already used; the refresh family is revoked".to_owned(),
                ));
            }
        }
        let (grants, scopes, principal) =
            self.load_grants(&claims.grant_ids, client, &claims.scopes)?;
        self.issue(
            &client.record.client_id,
            &grants,
            &scopes,
            &principal,
            FamilyPlan::Existing {
                family_id: claims.family_id.clone(),
                token: next_token,
            },
            now,
        )
    }

    /// Load the grants a token refers to and work out the effective scopes.
    ///
    /// The effective scopes are the intersection of the scopes the token
    /// was minted with and the scopes the grants carry now. A grant that
    /// was narrowed therefore narrows the token at once, and a grant that
    /// was revoked ends it.
    fn load_grants(
        &self,
        grant_ids: &[String],
        client: &RegisteredClient,
        token_scopes: &[String],
    ) -> Result<(Vec<Grant>, Vec<String>, String), AuthError> {
        let mut grants = Vec::new();
        let mut scopes: Vec<String> = Vec::new();
        let mut principal: Option<String> = None;
        for grant_id in grant_ids {
            let grant = self
                .state
                .get_grant(grant_id)?
                .ok_or_else(|| AuthError::InvalidGrant("the grant is gone".to_owned()))?;
            if grant.revoked_at.is_some() {
                return Err(AuthError::InvalidGrant("the grant is revoked".to_owned()));
            }
            if grant.client_id != client.record.client_id {
                return Err(AuthError::InvalidGrant(
                    "the grant belongs to another client".to_owned(),
                ));
            }
            match &principal {
                None => principal = Some(grant.principal.clone()),
                Some(existing) if existing != &grant.principal => {
                    return Err(AuthError::InvalidGrant(
                        "the grants belong to different principals".to_owned(),
                    ));
                }
                Some(_) => {}
            }
            for scope in &grant.scopes {
                if token_scopes.contains(scope) && !scopes.contains(scope) {
                    scopes.push(scope.clone());
                }
            }
            grants.push(grant);
        }
        let principal = principal
            .ok_or_else(|| AuthError::InvalidGrant("the token refers to no grant".to_owned()))?;
        if scopes.is_empty() {
            return Err(AuthError::InvalidGrant(
                "the token carries no scope the grants still allow".to_owned(),
            ));
        }
        Ok((grants, scopes, principal))
    }

    /// Mint the tokens of a grant.
    fn issue(
        &self,
        client_id: &str,
        grants: &[Grant],
        scopes: &[String],
        principal: &str,
        family: FamilyPlan,
        now: u64,
    ) -> Result<TokenResponse, AuthError> {
        let grant_ids: Vec<String> = grants.iter().map(|grant| grant.grant_id.clone()).collect();
        let expires_at = now + self.config.access_token_lifetime_seconds;
        let (family_id, refresh_token) = match (
            self.config.supports_grant_type(GrantType::RefreshToken),
            family,
        ) {
            (false, _) => (None, None),
            (true, FamilyPlan::New) => {
                let family_id = tokens::random_id(16)?;
                let token =
                    tokens::mint_refresh_token(self.key, &family_id, 1, &grant_ids, scopes)?;
                self.state.put_refresh_family(&RefreshFamily {
                    family_id: family_id.clone(),
                    grant_id: grant_ids
                        .first()
                        .cloned()
                        .unwrap_or_else(|| "no-grant".to_owned()),
                    generation: 1,
                    current_token_hash: tokens::token_hash(&token),
                    rotated_at: now,
                    revoked_at: None,
                })?;
                (Some(family_id), Some(token))
            }
            (
                true,
                FamilyPlan::Existing {
                    family_id, token, ..
                },
            ) => {
                // The rotation already moved the family onto this token.
                (Some(family_id), Some(token))
            }
        };
        let claims = AccessTokenClaims {
            issuer: self.config.issuer.clone(),
            audience: self.config.resource.clone(),
            subject: principal.to_owned(),
            client_id: client_id.to_owned(),
            grant_ids: grant_ids.clone(),
            scopes: scopes.to_vec(),
            family_id: family_id.clone(),
            issued_at: now,
            expires_at,
        };
        let access_token = tokens::mint_access_token(self.key, &claims)?;
        self.state.put_access_token(&AccessToken {
            token_hash: tokens::token_hash(&access_token),
            grant_id: grant_ids
                .first()
                .cloned()
                .unwrap_or_else(|| "no-grant".to_owned()),
            principal: principal.to_owned(),
            scopes: scopes.to_vec(),
            expires_at,
            revoked_at: None,
        })?;

        let details = grants
            .iter()
            .map(|grant| {
                let actions: Vec<Action> = grant
                    .scopes
                    .iter()
                    .filter_map(|scope| scope.parse::<Action>().ok())
                    .collect();
                crate::consent::ConsentGrant {
                    identity_id: grant.identity.clone(),
                    actions,
                    constraints: None,
                }
            })
            .collect::<Vec<_>>();
        let authorization_details = consent::authorization_details(&details);

        Ok(TokenResponse {
            access_token,
            token_type: "Bearer".to_owned(),
            expires_in: self.config.access_token_lifetime_seconds,
            refresh_token,
            scope: scopes.join(" "),
            authorization_details,
            issuer: self.config.issuer.clone(),
        })
    }
}

/// How the refresh family of a token is managed.
enum FamilyPlan {
    /// A new family is created for the grant.
    New,
    /// The family exists and was just rotated onto a new token.
    Existing {
        /// The family the token belongs to.
        family_id: String,
        /// The token the family was rotated onto.
        token: String,
    },
}

/// Mint an authorization code.
fn mint_code(payload: &CodePayload) -> Result<String, AuthError> {
    let encoded = serde_json::to_vec(payload).map_err(|error| {
        AuthError::InvalidRequest(format!("the code cannot be encoded: {error}"))
    })?;
    Ok(format!(
        "{CODE_PREFIX}.{}.{}",
        tokens::base64_url_encode(&encoded),
        tokens::base64_url_encode(&tokens::random_bytes(24)?)
    ))
}

/// Parse an authorization code.
fn parse_code(code: &str) -> Result<CodePayload, AuthError> {
    let refused = || AuthError::InvalidGrant("the authorization code is not readable".to_owned());
    let rest = code.strip_prefix(CODE_PREFIX).ok_or_else(refused)?;
    let rest = rest.strip_prefix('.').ok_or_else(refused)?;
    let (payload, _random) = rest.split_once('.').ok_or_else(refused)?;
    let decoded = tokens::base64_url_decode(payload).map_err(|_| refused())?;
    serde_json::from_slice(&decoded).map_err(|_| refused())
}
