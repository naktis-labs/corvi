//! The onboarding service: who may start a connection, and how a
//! credential reaches the data plane.
//!
//! ADR-0008 keeps the onboarding surface apart from everything else:
//!
//! - "Upstream connection administration belongs to an authenticated,
//!   separately authorized management/onboarding interface."
//! - "The controller/onboarding component may receive the initial OAuth
//!   tokens when completing the grant, but must hand them off through a
//!   **separate scoped, authenticated secret-delivery interface** to the
//!   data-plane token store/broker."
//! - "A user allowed to read an already connected mailbox is **not**
//!   automatically allowed to initiate provider OAuth, inspect provider
//!   scopes/identities, reconnect an account or extract tokens."
//!
//! So this module has two halves that never mix. The onboarding half
//! starts and completes a grant, and it ends with an opaque delivery
//! ticket. The delivery half — [`ScopedSecretDelivery`] — is what the data
//! plane implements, and it is authorized separately. The onboarding path
//! never hands a provider refresh token to the data plane; it hands over a
//! ticket that carries no credential.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use crate::callback::check_callback;
use crate::clock::Clock;
use crate::error::{ConnectionStatus, UpstreamOAuthError};
use crate::flow::{
    AuthorizationRequest, ProviderTokens, TokenExchange, build_authorization_url,
    exchange_authorization_code,
};
use crate::pkce::{new_pkce, random_token};
use crate::profile::{OnboardingFlow, ProviderProfile, ProviderRegistry};
use crate::scope::{Capability, ScopeRequest, resolve_scopes, unexpected_scope};
use crate::transaction::{MAX_TRANSACTION_TTL_SECONDS, OnboardingTransaction, TransactionStore};
use crate::transport::{OAuthRequest, OAuthTransport};

/// The roles a principal may hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum OnboardingRole {
    /// May start, complete and manage provider connections.
    ProviderOnboardingAdmin,
    /// May take a delivered credential into the data plane secret store.
    DataPlaneTokenBroker,
    /// May read a connected mailbox. Nothing else.
    MailboxReader,
}

/// The operations that are authorized separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnboardingAction {
    /// Look at what a provider supports.
    InspectCapabilities,
    /// Start an interactive onboarding.
    StartOnboarding,
    /// Finish an interactive onboarding.
    CompleteOnboarding,
    /// Take a delivered credential into the secret store.
    DeliverScopedSecret,
    /// Reauthorize or disconnect a connection.
    ManageConnection,
}

impl OnboardingAction {
    /// The name of the action, as it appears in a refusal.
    pub fn as_str(&self) -> &'static str {
        match self {
            OnboardingAction::InspectCapabilities => "inspect the provider capabilities",
            OnboardingAction::StartOnboarding => "start an onboarding",
            OnboardingAction::CompleteOnboarding => "complete an onboarding",
            OnboardingAction::DeliverScopedSecret => "deliver a scoped secret",
            OnboardingAction::ManageConnection => "manage a provider connection",
        }
    }
}

/// The authenticated principal behind an onboarding request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnboardingPrincipal {
    /// The identifier of the principal.
    pub id: String,
    /// The roles it holds.
    pub roles: Vec<OnboardingRole>,
}

impl OnboardingPrincipal {
    /// A principal with the given roles.
    pub fn new(id: impl Into<String>, roles: Vec<OnboardingRole>) -> Self {
        Self {
            id: id.into(),
            roles,
        }
    }

    /// Whether the principal holds a role.
    pub fn has_role(&self, role: OnboardingRole) -> bool {
        self.roles.contains(&role)
    }
}

/// What decides whether a principal may perform an operation.
pub trait OnboardingAuthorizer: fmt::Debug + Send + Sync {
    /// Authorize an operation, or refuse it.
    fn authorize(
        &self,
        principal: &OnboardingPrincipal,
        action: OnboardingAction,
    ) -> Result<(), UpstreamOAuthError>;
}

/// The authorizer of the built-in roles.
///
/// The mapping is deliberately narrow. An onboarding administrator may
/// start and complete a grant, but may **not** take the credential into
/// the secret store: that belongs to the data plane's own broker. A
/// mailbox reader may do neither.
#[derive(Debug, Clone, Copy, Default)]
pub struct RoleAuthorizer;

impl OnboardingAuthorizer for RoleAuthorizer {
    fn authorize(
        &self,
        principal: &OnboardingPrincipal,
        action: OnboardingAction,
    ) -> Result<(), UpstreamOAuthError> {
        let allowed = match action {
            OnboardingAction::InspectCapabilities
            | OnboardingAction::StartOnboarding
            | OnboardingAction::CompleteOnboarding
            | OnboardingAction::ManageConnection => {
                principal.has_role(OnboardingRole::ProviderOnboardingAdmin)
            }
            OnboardingAction::DeliverScopedSecret => {
                principal.has_role(OnboardingRole::DataPlaneTokenBroker)
            }
        };
        if allowed {
            return Ok(());
        }
        Err(UpstreamOAuthError::NotAuthorized {
            principal: principal.id.clone(),
            action: action.as_str(),
        })
    }
}

/// Resolves a client secret reference to the secret itself.
pub trait ClientSecretResolver: fmt::Debug + Send + Sync {
    /// Read the secret behind a reference.
    fn resolve(&self, reference: &str) -> Result<String, UpstreamOAuthError>;
}

/// An upstream account, as the provider names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamAccount {
    /// The provider's identifier for the account.
    pub account_id: String,
}

/// Checks that the provider account behind a token is the expected one.
///
/// The provider profile names the strategy, but the implementation is the
/// deployment's: an IMAP probe needs an IMAP client, which this crate
/// does not have.
pub trait AccountValidator: fmt::Debug + Send + Sync {
    /// Name the upstream account behind the tokens.
    fn validate(
        &self,
        profile: &ProviderProfile,
        tokens: &ProviderTokens,
    ) -> Result<UpstreamAccount, UpstreamOAuthError>;
}

/// Validates the account through a JMAP session.
///
/// The session is the provider's own statement about which accounts the
/// token can reach, which is what ADR-0008 asks for: "verify session
/// accounts/capabilities".
#[derive(Debug)]
pub struct SessionAccountValidator {
    transport: Arc<dyn OAuthTransport>,
    session_url: String,
}

impl SessionAccountValidator {
    /// A validator that reads the session at the given URL.
    pub fn new(transport: Arc<dyn OAuthTransport>, session_url: impl Into<String>) -> Self {
        Self {
            transport,
            session_url: session_url.into(),
        }
    }
}

impl AccountValidator for SessionAccountValidator {
    fn validate(
        &self,
        _profile: &ProviderProfile,
        tokens: &ProviderTokens,
    ) -> Result<UpstreamAccount, UpstreamOAuthError> {
        let request = OAuthRequest::get(self.session_url.clone())
            .with_header("Authorization", format!("Bearer {}", tokens.access_token));
        let response =
            self.transport
                .send(&request)
                .map_err(|failure| UpstreamOAuthError::Transport {
                    reason: failure.reason,
                })?;
        if response.status >= 400 {
            return Err(UpstreamOAuthError::Transport {
                reason: "the session refused the token".to_owned(),
            });
        }
        let body = response
            .json_body()
            .map_err(|_| UpstreamOAuthError::Protocol {
                reason: "the session response is not JSON".to_owned(),
            })?;
        if let Some(accounts) = body.get("accounts").and_then(|value| value.as_object())
            && let Some(account_id) = accounts.keys().next()
        {
            return Ok(UpstreamAccount {
                account_id: account_id.clone(),
            });
        }
        if let Some(account_id) = body
            .get("account_id")
            .or_else(|| body.get("account"))
            .and_then(|value| value.as_str())
        {
            return Ok(UpstreamAccount {
                account_id: account_id.to_owned(),
            });
        }
        Err(UpstreamOAuthError::Protocol {
            reason: "the session names no account".to_owned(),
        })
    }
}

/// A credential waiting to be taken into the secret store.
#[derive(Clone, PartialEq, Eq)]
pub struct EscrowedCredential {
    /// The provider the credential belongs to.
    pub provider: String,
    /// The connection the credential belongs to.
    pub connection_id: String,
    /// The Corvi identity the connection serves.
    pub identity: String,
    /// The upstream account the operator expected.
    pub expected_account: String,
    /// The capabilities that were granted.
    pub capabilities: Vec<Capability>,
    /// The tokens the provider issued.
    pub tokens: ProviderTokens,
    /// When the credential was escrowed.
    pub issued_at: u64,
    /// When the credential stops being deliverable.
    pub expires_at: u64,
}

impl fmt::Debug for EscrowedCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EscrowedCredential")
            .field("provider", &self.provider)
            .field("connection_id", &self.connection_id)
            .field("identity", &self.identity)
            .field("expected_account", &self.expected_account)
            .field("capabilities", &self.capabilities)
            .field("tokens", &self.tokens)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// The short-lived place where a completed grant waits for the data plane.
///
/// The escrow holds the credential in memory and hands it over exactly
/// once, against an opaque ticket. The ticket carries no credential
/// material, so it can travel through the management interface without
/// becoming a secret in its own right.
#[derive(Debug, Default)]
pub struct DeliveryEscrow {
    entries: Mutex<BTreeMap<String, EscrowedCredential>>,
}

impl DeliveryEscrow {
    /// An empty escrow.
    pub fn new() -> Self {
        Self::default()
    }

    /// Put a credential into the escrow and return its ticket.
    pub fn issue(&self, credential: EscrowedCredential) -> Result<String, UpstreamOAuthError> {
        let ticket = random_token()?;
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| UpstreamOAuthError::Storage {
                reason: "the escrow lock is poisoned".to_owned(),
            })?;
        entries.insert(ticket.clone(), credential);
        Ok(ticket)
    }

    /// Take a credential out of the escrow.
    ///
    /// The credential is removed, so a ticket works once.
    pub fn claim(
        &self,
        ticket: &str,
        now: u64,
    ) -> Result<Option<EscrowedCredential>, UpstreamOAuthError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| UpstreamOAuthError::Storage {
                reason: "the escrow lock is poisoned".to_owned(),
            })?;
        let Some(credential) = entries.remove(ticket) else {
            return Ok(None);
        };
        if now > credential.expires_at {
            return Ok(None);
        }
        Ok(Some(credential))
    }

    /// How many credentials are waiting.
    pub fn len(&self) -> usize {
        self.entries
            .lock()
            .map(|entries| entries.len())
            .unwrap_or_default()
    }

    /// Whether the escrow is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Accept a credential that arrived in a remote handoff.
    ///
    /// This is the other end of [`crate::handoff`]: a companion CLI that
    /// completed the grant on its own machine seals the credential into an
    /// envelope, and the controller opens it here. The envelope is
    /// authenticated, single use and short lived, and what comes out of it
    /// is an ordinary delivery ticket — the same kind the hosted flow
    /// produces. The data plane therefore has exactly one way to receive a
    /// credential, whichever end it came from.
    pub fn accept_handoff(
        &self,
        envelope: &crate::handoff::HandoffEnvelope,
        shared_key: &[u8],
        recipient: &str,
        now: u64,
        guard: &dyn crate::handoff::OneTimeUseGuard,
    ) -> Result<String, UpstreamOAuthError> {
        let payload = crate::handoff::redeem_handoff(envelope, shared_key, recipient, now, guard)?;
        let credential = EscrowedCredential {
            provider: payload.provider,
            connection_id: payload.connection_id,
            identity: payload.identity,
            expected_account: payload.expected_account,
            capabilities: payload.capabilities,
            tokens: payload.tokens,
            issued_at: now,
            expires_at: now.saturating_add(crate::transaction::MAX_TRANSACTION_TTL_SECONDS),
        };
        self.issue(credential)
    }
}

/// What the delivery interface reports back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryReceipt {
    /// The connection the credential belongs to.
    pub connection_id: String,
    /// The provider the credential belongs to.
    pub provider: String,
    /// The reference of the credential in the secret store.
    pub secret_ref: String,
    /// When the access token expires.
    pub expires_at: Option<u64>,
    /// The generation of the credential.
    pub generation: u64,
}

/// The separate interface that hands a credential to the data plane.
///
/// This is the only way a provider credential reaches the secret store,
/// and it is authorized on its own.
pub trait ScopedSecretDelivery: fmt::Debug {
    /// Take the credential behind a ticket and store it.
    fn deliver(
        &self,
        ticket: &str,
        principal: &OnboardingPrincipal,
    ) -> Result<DeliveryReceipt, UpstreamOAuthError>;
}

/// What an operator asks for when they start an onboarding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnboardingRequest {
    /// The provider to connect.
    pub provider: String,
    /// The administrator who starts the onboarding.
    pub principal: OnboardingPrincipal,
    /// The Corvi identity the connection will serve.
    pub identity: String,
    /// The upstream account the operator expects to connect.
    pub expected_account: String,
    /// What the connection needs to be able to do.
    pub capabilities: Vec<Capability>,
    /// Exact provider scope strings, when the deployment names them.
    pub extra_scopes: Vec<String>,
    /// The callback to use. It must be one of the registered ones.
    pub redirect_uri: String,
    /// How long the authorization may take.
    pub ttl_seconds: u64,
}

/// What the browser is sent to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationStart {
    /// The provider.
    pub provider: String,
    /// The identifier of the transaction.
    pub transaction_id: String,
    /// The URL of the provider's authorization page.
    pub authorization_url: String,
    /// When the transaction expires.
    pub expires_at: u64,
    /// The scope strings that were requested.
    pub scopes: Vec<String>,
}

/// What the provider sends back to the callback.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CallbackRequest {
    /// The provider named in the callback path.
    pub provider: Option<String>,
    /// The one-time state.
    pub state: String,
    /// The authorization code.
    pub code: Option<String>,
    /// The provider's error code.
    pub error: Option<String>,
    /// The issuer, when the provider sends one (RFC 9207).
    pub issuer: Option<String>,
    /// The callback the code was issued for.
    pub redirect_uri: Option<String>,
    /// The client the code was issued to.
    pub client_id: Option<String>,
}

/// What a completed onboarding reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnboardingOutcome {
    /// The provider.
    pub provider: String,
    /// The connection that is being created.
    pub connection_id: String,
    /// The Corvi identity the connection serves.
    pub identity: String,
    /// The upstream account the provider named.
    pub account: String,
    /// The scopes the provider granted.
    pub granted_scopes: Vec<String>,
    /// The capabilities that were granted.
    pub capabilities: Vec<Capability>,
    /// When the access token expires.
    pub expires_at: Option<u64>,
    /// The ticket the data plane uses to take the credential.
    pub delivery_ticket: String,
    /// The status of the connection.
    pub status: ConnectionStatus,
}

/// The onboarding service.
#[derive(Debug)]
pub struct OnboardingService {
    registry: Arc<ProviderRegistry>,
    transactions: Arc<dyn TransactionStore>,
    transport: Arc<dyn OAuthTransport>,
    authorizer: Arc<dyn OnboardingAuthorizer>,
    validator: Arc<dyn AccountValidator>,
    client_secrets: Arc<dyn ClientSecretResolver>,
    escrow: Arc<DeliveryEscrow>,
    clock: Arc<dyn Clock>,
    delivery_ttl_seconds: u64,
}

impl OnboardingService {
    /// A service with the given collaborators.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        registry: Arc<ProviderRegistry>,
        transactions: Arc<dyn TransactionStore>,
        transport: Arc<dyn OAuthTransport>,
        authorizer: Arc<dyn OnboardingAuthorizer>,
        validator: Arc<dyn AccountValidator>,
        client_secrets: Arc<dyn ClientSecretResolver>,
        escrow: Arc<DeliveryEscrow>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            registry,
            transactions,
            transport,
            authorizer,
            validator,
            client_secrets,
            escrow,
            clock,
            delivery_ttl_seconds: MAX_TRANSACTION_TTL_SECONDS,
        }
    }

    /// What an authorized management surface may show about a provider.
    pub fn capabilities(
        &self,
        provider: &str,
        principal: &OnboardingPrincipal,
    ) -> Result<crate::profile::AuthCapabilities, UpstreamOAuthError> {
        self.authorizer
            .authorize(principal, OnboardingAction::InspectCapabilities)?;
        let profile = self.registry.get_validated(provider)?;
        Ok(profile.capabilities())
    }

    /// Start an interactive onboarding.
    ///
    /// Every check happens before anything is sent to the provider: the
    /// provider must exist, the flow must be one it offers, the callback
    /// must be registered, the scopes must be ones it has, and the
    /// registration constraints must be met.
    pub fn start(
        &self,
        request: &OnboardingRequest,
    ) -> Result<AuthorizationStart, UpstreamOAuthError> {
        self.authorizer
            .authorize(&request.principal, OnboardingAction::StartOnboarding)?;
        let profile = self.registry.get_validated(&request.provider)?;
        if !profile.supports_flow(OnboardingFlow::AuthorizationCodePkce) {
            return Err(UpstreamOAuthError::UnsupportedProvider {
                provider: request.provider.clone(),
                reason: "the provider does not offer an authorization code flow".to_owned(),
            });
        }
        check_callback(profile, &request.redirect_uri)?;
        let scope_request = ScopeRequest::new(request.capabilities.clone())
            .with_scopes(request.extra_scopes.clone());
        let resolved = resolve_scopes(profile, &scope_request)?;
        if request.ttl_seconds == 0 || request.ttl_seconds > MAX_TRANSACTION_TTL_SECONDS {
            return Err(UpstreamOAuthError::InvalidRequest {
                reason: "the authorization lifetime is not a short one".to_owned(),
            });
        }

        let endpoints = profile.endpoints.clone().ok_or_else(|| {
            UpstreamOAuthError::UnsupportedRegistration {
                provider: request.provider.clone(),
                reason: "no endpoints are configured".to_owned(),
            }
        })?;
        let issuer =
            profile
                .issuer
                .clone()
                .ok_or_else(|| UpstreamOAuthError::UnsupportedRegistration {
                    provider: request.provider.clone(),
                    reason: "no issuer is configured".to_owned(),
                })?;

        let now = self.clock.now();
        let pkce = new_pkce()?;
        let state = random_token()?;
        let nonce = random_token()?;
        let transaction_id = random_token()?;
        let connection_id = random_token()?;
        let transaction = OnboardingTransaction {
            transaction_id: transaction_id.clone(),
            connection_id: connection_id.clone(),
            provider: request.provider.clone(),
            issuer: issuer.clone(),
            client_id: profile.client.client_id.clone(),
            redirect_uri: request.redirect_uri.clone(),
            code_verifier: pkce.verifier().to_owned(),
            code_challenge: pkce.challenge().to_owned(),
            state: state.clone(),
            nonce,
            scopes: resolved.scopes.clone(),
            capabilities: resolved.capabilities.clone(),
            expected_account: request.expected_account.clone(),
            identity: request.identity.clone(),
            principal: request.principal.id.clone(),
            principal_roles: request.principal.roles.clone(),
            issued_at: now,
            expires_at: now.saturating_add(request.ttl_seconds),
        };
        self.transactions.insert(&transaction)?;

        let authorization_url = build_authorization_url(&AuthorizationRequest {
            authorization_endpoint: endpoints.authorization.clone(),
            client_id: profile.client.client_id.clone(),
            redirect_uri: request.redirect_uri.clone(),
            scopes: resolved.scopes.clone(),
            state,
            code_challenge: pkce.challenge().to_owned(),
            issuer: Some(issuer),
            resource: None,
        })?;

        Ok(AuthorizationStart {
            provider: request.provider.clone(),
            transaction_id,
            authorization_url,
            expires_at: transaction.expires_at,
            scopes: resolved.scopes,
        })
    }

    /// Finish an interactive onboarding.
    ///
    /// The transaction is consumed, so a second callback with the same
    /// state finds nothing. The issuer, the callback and the client are
    /// checked against the transaction, the account is validated against
    /// the account the operator expected, and the credential ends up in the
    /// escrow behind an opaque ticket.
    pub fn complete(
        &self,
        callback: &CallbackRequest,
    ) -> Result<OnboardingOutcome, UpstreamOAuthError> {
        let transaction = self.transactions.take(&callback.state)?.ok_or_else(|| {
            UpstreamOAuthError::InvalidTransaction {
                reason: "the state is unknown or was already used".to_owned(),
            }
        })?;
        let now = self.clock.now();
        if transaction.is_expired(now) {
            return Err(UpstreamOAuthError::InvalidTransaction {
                reason: "the authorization has expired".to_owned(),
            });
        }
        let principal = OnboardingPrincipal::new(
            transaction.principal.clone(),
            transaction.principal_roles.clone(),
        );
        self.authorizer
            .authorize(&principal, OnboardingAction::CompleteOnboarding)?;

        if let Some(provider) = &callback.provider
            && provider != &transaction.provider
        {
            return Err(UpstreamOAuthError::InvalidTransaction {
                reason: "the callback names another provider".to_owned(),
            });
        }
        if let Some(issuer) = &callback.issuer
            && issuer != &transaction.issuer
        {
            return Err(UpstreamOAuthError::InvalidTransaction {
                reason: "the callback comes from another issuer".to_owned(),
            });
        }
        if let Some(redirect_uri) = &callback.redirect_uri
            && redirect_uri != &transaction.redirect_uri
        {
            return Err(UpstreamOAuthError::CallbackNotAllowed {
                provider: transaction.provider.clone(),
                redirect_uri: redirect_uri.clone(),
            });
        }
        if let Some(client_id) = &callback.client_id
            && client_id != &transaction.client_id
        {
            return Err(UpstreamOAuthError::InvalidTransaction {
                reason: "the callback names another client".to_owned(),
            });
        }
        if let Some(error) = &callback.error {
            return Err(UpstreamOAuthError::InvalidTransaction {
                reason: format!("the provider refused the authorization: {error}"),
            });
        }
        let Some(code) = callback.code.clone() else {
            return Err(UpstreamOAuthError::InvalidTransaction {
                reason: "the callback carries no code".to_owned(),
            });
        };

        let profile = self.registry.get_validated(&transaction.provider)?;
        let client_secret = self.client_secret(profile)?;
        let endpoints = profile.endpoints.clone().ok_or_else(|| {
            UpstreamOAuthError::UnsupportedRegistration {
                provider: transaction.provider.clone(),
                reason: "no endpoints are configured".to_owned(),
            }
        })?;
        let tokens = exchange_authorization_code(
            self.transport.as_ref(),
            &TokenExchange {
                token_endpoint: endpoints.token.clone(),
                client_id: transaction.client_id.clone(),
                client_secret,
                redirect_uri: transaction.redirect_uri.clone(),
                code,
                code_verifier: transaction.code_verifier.clone(),
                scopes: transaction.scopes.clone(),
            },
            now,
        )?;

        let granted = if tokens.scopes.is_empty() {
            transaction.scopes.clone()
        } else {
            tokens.scopes.clone()
        };
        if let Some(scope) = unexpected_scope(&transaction.scopes, &granted) {
            return Err(UpstreamOAuthError::ScopeWidening {
                provider: transaction.provider.clone(),
                scope,
            });
        }
        for capability in &transaction.capabilities {
            let needed = profile.scopes.for_capability(*capability);
            if !needed.is_empty() && !needed.iter().all(|scope| granted.contains(scope)) {
                return Err(UpstreamOAuthError::ScopeInsufficient {
                    provider: transaction.provider.clone(),
                    missing: needed,
                });
            }
        }

        let account = self.validator.validate(profile, &tokens)?;
        if account.account_id != transaction.expected_account {
            return Err(UpstreamOAuthError::AccountMismatch {
                expected: transaction.expected_account.clone(),
                actual: account.account_id,
            });
        }

        let credential = EscrowedCredential {
            provider: transaction.provider.clone(),
            connection_id: transaction.connection_id.clone(),
            identity: transaction.identity.clone(),
            expected_account: transaction.expected_account.clone(),
            capabilities: transaction.capabilities.clone(),
            tokens: tokens.clone(),
            issued_at: now,
            expires_at: now.saturating_add(self.delivery_ttl_seconds),
        };
        let delivery_ticket = self.escrow.issue(credential)?;

        Ok(OnboardingOutcome {
            provider: transaction.provider.clone(),
            connection_id: transaction.connection_id.clone(),
            identity: transaction.identity.clone(),
            account: account.account_id,
            granted_scopes: granted,
            capabilities: transaction.capabilities.clone(),
            expires_at: tokens.expires_at,
            delivery_ticket,
            status: ConnectionStatus::PendingAuthorization,
        })
    }

    /// The client secret of a confidential client, when it has one.
    fn client_secret(
        &self,
        profile: &ProviderProfile,
    ) -> Result<Option<String>, UpstreamOAuthError> {
        let Some(reference) = &profile.client.client_secret_ref else {
            return Ok(None);
        };
        match self.client_secrets.resolve(reference) {
            Ok(secret) => Ok(Some(secret)),
            Err(_) => Err(UpstreamOAuthError::UnsupportedRegistration {
                provider: profile.provider_id.clone(),
                reason: "the configured client secret cannot be read".to_owned(),
            }),
        }
    }
}
