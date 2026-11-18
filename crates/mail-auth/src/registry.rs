//! Dynamic client registration.
//!
//! MCP 2026-07-28 deprecates dynamic client registration, and ADR-0009
//! leaves it disabled by default with an optional, rate-limited legacy
//! compatibility mode. The rules this module keeps:
//!
//! - **Off by default.** A deployment that did not enable the legacy mode
//!   refuses the registration; it does not fall back to a pre-registered
//!   client.
//! - **No secret is ever issued.** The legacy mode registers a public
//!   client. An endpoint that hands out a secret to an anonymous caller is
//!   not a compatibility mode, it is an open credential factory.
//! - **The registration is validated like any other.** The redirect URIs
//!   are checked against the same rules an administrator-provisioned
//!   client is checked against.

use std::time::{Duration, Instant};

use mail_core::Action;

use crate::client::{ClientPolicy, ClientType, RegisteredClient, check_redirect_uri_value};
use crate::config::{AuthConfig, GrantType};
use crate::error::AuthError;
use crate::store::GrantState;
use crate::tokens;

/// How many legacy registrations one process accepts in an hour.
pub const MAX_LEGACY_REGISTRATIONS_PER_HOUR: usize = 100;

/// A registration a client asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicRegistrationRequest {
    /// The name the client shows.
    pub client_name: Option<String>,
    /// The redirect URIs the client wants.
    pub redirect_uris: Vec<String>,
    /// The grant types the client wants.
    pub grant_types: Vec<String>,
    /// How the client wants to authenticate.
    pub token_endpoint_auth_method: Option<String>,
}

/// The registry that answers dynamic registrations.
pub struct RegistrationRegistry<'a> {
    config: &'a AuthConfig,
    state: &'a dyn GrantState,
    registrations: usize,
    window_started: Instant,
}

impl std::fmt::Debug for RegistrationRegistry<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistrationRegistry")
            .field("registrations", &self.registrations)
            .finish_non_exhaustive()
    }
}

impl<'a> RegistrationRegistry<'a> {
    /// Build the registry.
    pub fn new(config: &'a AuthConfig, state: &'a dyn GrantState) -> Self {
        Self {
            config,
            state,
            registrations: 0,
            window_started: Instant::now(),
        }
    }

    /// Register a client dynamically.
    ///
    /// The legacy mode is refused unless the configuration enabled it.
    pub fn register(
        &mut self,
        request: &DynamicRegistrationRequest,
    ) -> Result<RegisteredClient, AuthError> {
        if !self
            .config
            .client_registration
            .legacy_dynamic_client_registration
        {
            return Err(AuthError::RegistrationDisabled(
                "dynamic client registration is disabled; MCP 2026-07-28 deprecates it".to_owned(),
            ));
        }
        self.check_rate()?;
        if request.redirect_uris.is_empty() {
            return Err(AuthError::InvalidClient(
                "a registration needs at least one redirect uri".to_owned(),
            ));
        }
        for redirect_uri in &request.redirect_uris {
            check_redirect_uri_value(redirect_uri)?;
        }
        if request
            .token_endpoint_auth_method
            .as_deref()
            .is_some_and(|method| method != "none")
        {
            return Err(AuthError::InvalidClient(
                "a dynamic registration may not ask for a client secret".to_owned(),
            ));
        }
        let mut grant_types = Vec::new();
        for grant_type in &request.grant_types {
            let grant_type = match grant_type.as_str() {
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
            grant_types.push(grant_type);
        }
        if grant_types.is_empty() {
            grant_types.push(GrantType::AuthorizationCode);
        }
        let client_id = format!("dcr_{}", tokens::random_id(12)?);
        let record = mail_storage::grants::OAuthClient {
            client_id: client_id.clone(),
            name: request
                .client_name
                .clone()
                .unwrap_or_else(|| "a dynamically registered client".to_owned()),
            redirect_uris: request.redirect_uris.clone(),
            secret_hash: None,
            confidential: false,
        };
        self.state.put_client(&record)?;
        // The registration is stored with its policy, so a restarted
        // issuer still knows what the client registered for.
        let policy = ClientPolicy {
            client_id: client_id.clone(),
            grant_types,
            allowed_actions: Action::ALL.to_vec(),
            allowed_identity_ids: Vec::new(),
        };
        self.state.put_client_policy(&policy)?;
        self.registrations += 1;
        Ok(RegisteredClient { record, policy })
    }

    /// Refuse a burst of registrations.
    fn check_rate(&mut self) -> Result<(), AuthError> {
        if self.window_started.elapsed() >= Duration::from_secs(3600) {
            self.window_started = Instant::now();
            self.registrations = 0;
        }
        if self.registrations >= MAX_LEGACY_REGISTRATIONS_PER_HOUR {
            return Err(AuthError::RegistrationDisabled(
                "the legacy registration rate for this process is exhausted".to_owned(),
            ));
        }
        Ok(())
    }
}

/// The kind of client a dynamic registration produces.
///
/// It is always public: a legacy registration never receives a secret.
pub const DYNAMIC_CLIENT_TYPE: ClientType = ClientType::Public;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::MemoryGrantState;

    fn config() -> AuthConfig {
        AuthConfig::integrated("https://auth.corvi.example", "https://mail.corvi.example")
    }

    fn request() -> DynamicRegistrationRequest {
        DynamicRegistrationRequest {
            client_name: Some("a client".to_owned()),
            redirect_uris: vec!["https://client.example/callback".to_owned()],
            grant_types: vec!["authorization_code".to_owned()],
            token_endpoint_auth_method: Some("none".to_owned()),
        }
    }

    #[test]
    fn dynamic_registration_is_refused_by_default() {
        let config = config();
        assert!(
            !config
                .client_registration
                .legacy_dynamic_client_registration
        );
        let state = MemoryGrantState::durable();
        let mut registry = RegistrationRegistry::new(&config, &state);
        assert!(matches!(
            registry.register(&request()),
            Err(AuthError::RegistrationDisabled(_))
        ));
    }

    #[test]
    fn dynamic_registration_works_when_it_is_enabled_explicitly() {
        let mut config = config();
        config
            .client_registration
            .legacy_dynamic_client_registration = true;
        let state = MemoryGrantState::durable();
        let mut registry = RegistrationRegistry::new(&config, &state);
        let client = registry
            .register(&request())
            .expect("the registration succeeds");
        assert!(!client.record.confidential);
        assert!(client.record.secret_hash.is_none());
        assert_eq!(
            client.record.redirect_uris,
            vec!["https://client.example/callback"]
        );
    }

    #[test]
    fn a_dynamic_registration_never_asks_for_a_secret() {
        let mut config = config();
        config
            .client_registration
            .legacy_dynamic_client_registration = true;
        let state = MemoryGrantState::durable();
        let mut registry = RegistrationRegistry::new(&config, &state);
        let mut request = request();
        request.token_endpoint_auth_method = Some("client_secret_basic".to_owned());
        assert!(matches!(
            registry.register(&request),
            Err(AuthError::InvalidClient(_))
        ));
    }

    #[test]
    fn a_dynamic_registration_may_not_register_an_unsafe_redirect_uri() {
        let mut config = config();
        config
            .client_registration
            .legacy_dynamic_client_registration = true;
        let state = MemoryGrantState::durable();
        let mut registry = RegistrationRegistry::new(&config, &state);
        let mut request = request();
        request.redirect_uris = vec!["http://attacker.example/callback".to_owned()];
        assert!(matches!(
            registry.register(&request),
            Err(AuthError::InvalidClient(_))
        ));
    }

    #[test]
    fn a_dynamic_registration_may_not_ask_for_an_unsupported_grant_type() {
        let mut config = config();
        config
            .client_registration
            .legacy_dynamic_client_registration = true;
        let state = MemoryGrantState::durable();
        let mut registry = RegistrationRegistry::new(&config, &state);
        let mut request = request();
        request.grant_types = vec!["password".to_owned()];
        assert!(matches!(
            registry.register(&request),
            Err(AuthError::UnsupportedGrantType(_))
        ));
    }
}
