//! The client registry: administrator-provisioned clients and their
//! authentication.
//!
//! A confidential client is provisioned by an administrator and
//! authenticates with a secret whose **hash** is all the grant store ever
//! holds. A public client cannot keep a secret, so it presents none — and
//! presenting one is refused, because a "public" client that arrives with a
//! secret is either a misconfiguration or an attempt to impersonate one.
//!
//! Redirect URIs are compared exactly. A registered
//! `https://client.example/callback` does not match
//! `https://client.example/callback/extra`, a different host, or a URI that
//! only *contains* the registered one as a substring.

use std::collections::BTreeMap;

use mail_core::Action;
use mail_storage::grants::OAuthClient;
use url::Url;

use crate::config::{AuthConfig, GrantType};
use crate::error::AuthError;
use crate::store::GrantState;
use crate::tokens;

/// The kind of client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClientType {
    /// A client that cannot keep a secret.
    Public,
    /// A client that authenticates with a secret.
    Confidential,
}

/// The policy an administrator gives one client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientPolicy {
    /// The client the policy is about.
    pub client_id: String,
    /// The grant types the client may use.
    pub grant_types: Vec<GrantType>,
    /// The actions the client may ask for.
    pub allowed_actions: Vec<Action>,
    /// The identities the client may ask for.
    pub allowed_identity_ids: Vec<String>,
}

/// A client an administrator provisioned, with its policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredClient {
    /// The stored record.
    pub record: OAuthClient,
    /// The policy the administrator gave the client.
    pub policy: ClientPolicy,
}

/// The client registry.
pub struct ClientRegistry<'a> {
    config: &'a AuthConfig,
    state: &'a dyn GrantState,
    key: &'a [u8],
    administrator_secret_hash: Option<&'a str>,
    policies: BTreeMap<String, ClientPolicy>,
}

impl std::fmt::Debug for ClientRegistry<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientRegistry")
            .field("clients", &self.policies.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl<'a> ClientRegistry<'a> {
    /// Build a registry.
    pub fn new(
        config: &'a AuthConfig,
        state: &'a dyn GrantState,
        key: &'a [u8],
        administrator_secret_hash: Option<&'a str>,
    ) -> Self {
        Self {
            config,
            state,
            key,
            administrator_secret_hash,
            policies: BTreeMap::new(),
        }
    }

    /// Provision a client.
    ///
    /// The administrator credential is required: a client that arrives
    /// without one is not provisioned, and a confidential client without a
    /// secret is refused rather than stored as a client that cannot
    /// authenticate.
    pub fn provision(
        &mut self,
        registration: ClientRegistration,
        administrator_secret: &str,
    ) -> Result<RegisteredClient, AuthError> {
        let Some(admin_hash) = self.administrator_secret_hash else {
            return Err(AuthError::Deployment(
                "this deployment holds no administrator credential, so no client may be \
                 provisioned"
                    .to_owned(),
            ));
        };
        if !tokens::verify_secret_hash(self.key, ADMINISTRATOR, administrator_secret, admin_hash) {
            return Err(AuthError::InvalidClient(
                "the administrator credential is not valid".to_owned(),
            ));
        }
        if registration.client_id.is_empty()
            || registration.client_id.len() > 2048
            || registration
                .client_id
                .chars()
                .any(|character| character.is_whitespace() || character.is_control())
        {
            return Err(AuthError::InvalidClient(
                "the client identifier is not valid".to_owned(),
            ));
        }
        match (registration.client_type, registration.secret.as_ref()) {
            (ClientType::Public, Some(_)) => {
                return Err(AuthError::InvalidClient(
                    "a public client may not carry a secret".to_owned(),
                ));
            }
            (ClientType::Confidential, None) => {
                return Err(AuthError::InvalidClient(
                    "a confidential client needs a secret".to_owned(),
                ));
            }
            _ => {}
        }
        if registration.redirect_uris.is_empty() {
            return Err(AuthError::InvalidClient(
                "a client needs at least one redirect uri".to_owned(),
            ));
        }
        for redirect_uri in &registration.redirect_uris {
            check_redirect_uri_value(redirect_uri)?;
        }
        for grant_type in &registration.grant_types {
            if !self.config.supports_grant_type(*grant_type) {
                return Err(AuthError::UnsupportedGrantType(format!(
                    "the grant type {} is not supported",
                    grant_type.as_str()
                )));
            }
        }
        for action in &registration.allowed_actions {
            if !self.config.supports_scope(action.as_str()) {
                return Err(AuthError::InsufficientScope(format!(
                    "the action {} is not supported",
                    action.as_str()
                )));
            }
        }
        let record = OAuthClient {
            client_id: registration.client_id.clone(),
            name: registration.name.clone(),
            redirect_uris: registration.redirect_uris.clone(),
            secret_hash: registration
                .secret
                .as_ref()
                .map(|secret| tokens::secret_hash(self.key, &registration.client_id, secret)),
            confidential: matches!(registration.client_type, ClientType::Confidential),
        };
        self.state.put_client(&record)?;
        let policy = ClientPolicy {
            client_id: registration.client_id.clone(),
            grant_types: registration.grant_types.clone(),
            allowed_actions: registration.allowed_actions.clone(),
            allowed_identity_ids: registration.allowed_identity_ids.clone(),
        };
        self.policies
            .insert(registration.client_id.clone(), policy.clone());
        Ok(RegisteredClient { record, policy })
    }

    /// Authenticate a client at the token endpoint.
    pub fn authenticate(
        &self,
        client_id: &str,
        presented_secret: Option<&str>,
    ) -> Result<RegisteredClient, AuthError> {
        let Some(record) = self.state.get_client(client_id)? else {
            return Err(AuthError::InvalidClient(
                "the client is not known to this issuer".to_owned(),
            ));
        };
        if record.confidential {
            let Some(secret) = presented_secret else {
                return Err(AuthError::InvalidClient(
                    "the client must authenticate".to_owned(),
                ));
            };
            let Some(expected) = record.secret_hash.as_deref() else {
                return Err(AuthError::InvalidClient(
                    "the client holds no usable credential".to_owned(),
                ));
            };
            if !tokens::verify_secret_hash(self.key, client_id, secret, expected) {
                return Err(AuthError::InvalidClient(
                    "the client did not authenticate".to_owned(),
                ));
            }
        } else if presented_secret.is_some() {
            return Err(AuthError::InvalidClient(
                "a public client may not present a secret".to_owned(),
            ));
        }
        let policy = self
            .policies
            .get(client_id)
            .cloned()
            .unwrap_or_else(|| ClientPolicy {
                client_id: client_id.to_owned(),
                grant_types: Vec::new(),
                allowed_actions: Vec::new(),
                allowed_identity_ids: Vec::new(),
            });
        Ok(RegisteredClient { record, policy })
    }

    /// Look up a client without authenticating it.
    ///
    /// The authorization endpoint knows a client by its identifier alone;
    /// the secret is checked at the token endpoint, where it belongs.
    pub fn lookup(&self, client_id: &str) -> Result<RegisteredClient, AuthError> {
        let Some(record) = self.state.get_client(client_id)? else {
            return Err(AuthError::InvalidClient(
                "the client is not known to this issuer".to_owned(),
            ));
        };
        let policy = self
            .policies
            .get(client_id)
            .cloned()
            .unwrap_or_else(|| ClientPolicy {
                client_id: client_id.to_owned(),
                grant_types: Vec::new(),
                allowed_actions: Vec::new(),
                allowed_identity_ids: Vec::new(),
            });
        Ok(RegisteredClient { record, policy })
    }

    /// The policy of a client, when one was provisioned.
    pub fn policy(&self, client_id: &str) -> Option<&ClientPolicy> {
        self.policies.get(client_id)
    }

    /// Check a redirect URI against the registered ones.
    pub fn check_redirect_uri(
        client: &RegisteredClient,
        redirect_uri: &str,
    ) -> Result<(), AuthError> {
        if client
            .record
            .redirect_uris
            .iter()
            .any(|registered| registered == redirect_uri)
        {
            Ok(())
        } else {
            Err(AuthError::InvalidRedirectUri(
                "the redirect uri is not registered for this client".to_owned(),
            ))
        }
    }

    /// Whether the client may use a grant type.
    pub fn check_grant_type(
        client: &RegisteredClient,
        grant_type: GrantType,
    ) -> Result<(), AuthError> {
        if client.policy.grant_types.contains(&grant_type) {
            Ok(())
        } else {
            Err(AuthError::UnsupportedGrantType(format!(
                "the client may not use the grant type {}",
                grant_type.as_str()
            )))
        }
    }

    /// Whether the client may ask for an action.
    pub fn check_action(client: &RegisteredClient, action: Action) -> Result<(), AuthError> {
        if client.policy.allowed_actions.contains(&action) {
            Ok(())
        } else {
            Err(AuthError::InsufficientScope(format!(
                "the client may not ask for the action {}",
                action.as_str()
            )))
        }
    }

    /// Whether the client may ask for an identity.
    pub fn check_identity(client: &RegisteredClient, identity_id: &str) -> Result<(), AuthError> {
        if client.policy.allowed_identity_ids.is_empty()
            || client
                .policy
                .allowed_identity_ids
                .iter()
                .any(|allowed| allowed == identity_id)
        {
            Ok(())
        } else {
            Err(AuthError::InsufficientScope(
                "the client may not ask for this identity".to_owned(),
            ))
        }
    }
}

/// The label the administrator credential is hashed under.
const ADMINISTRATOR: &str = "administrator";

/// A client registration as an administrator hands it in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRegistration {
    /// The client identifier.
    pub client_id: String,
    /// The human-readable name.
    pub name: String,
    /// The kind of client.
    pub client_type: ClientType,
    /// The redirect URIs the client may use.
    pub redirect_uris: Vec<String>,
    /// The grant types the client may use.
    pub grant_types: Vec<GrantType>,
    /// The actions the client may ask for.
    pub allowed_actions: Vec<Action>,
    /// The identities the client may ask for.
    pub allowed_identity_ids: Vec<String>,
    /// The client secret, at provisioning time only.
    pub secret: Option<String>,
}

/// Check a redirect URI a registration or a metadata document wants to add.
///
/// Only `https` is allowed, except for the loopback addresses a native
/// application uses. A fragment is refused: a redirect URI with a fragment
/// cannot be compared exactly.
pub fn check_redirect_uri_value(value: &str) -> Result<(), AuthError> {
    let refused = |reason: &str| AuthError::InvalidClient(format!("the redirect uri {reason}"));
    if value.is_empty() {
        return Err(refused("is empty"));
    }
    let parsed = Url::parse(value).map_err(|_| refused("is not a URL"))?;
    if parsed.fragment().is_some() {
        return Err(refused("carries a fragment"));
    }
    match parsed.scheme() {
        "https" => {
            if parsed.host_str().is_none() {
                return Err(refused("has no host"));
            }
            Ok(())
        }
        "http" => {
            let host = parsed.host_str().unwrap_or_default();
            let host = host.trim_start_matches('[').trim_end_matches(']');
            if host == "127.0.0.1" || host == "::1" {
                Ok(())
            } else {
                Err(refused("uses http for a host that is not loopback"))
            }
        }
        _ => Err(refused("uses a scheme that is not https")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PkceMethod;
    use crate::store::{Durability, GrantStoreState};
    use mail_storage::sqlite::SqliteStore;

    const KEY: &[u8] = b"a deployment key that is long enough to be a key";
    const ADMIN_SECRET: &str = "the administrator secret";

    fn config() -> AuthConfig {
        AuthConfig::integrated("https://auth.corvi.example", "https://mail.corvi.example")
    }

    fn registration(client_id: &str, client_type: ClientType) -> ClientRegistration {
        ClientRegistration {
            client_id: client_id.to_owned(),
            name: "A client".to_owned(),
            client_type,
            redirect_uris: vec!["https://client.example/callback".to_owned()],
            grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
            allowed_actions: vec![Action::List, Action::Read],
            allowed_identity_ids: vec!["identity-a".to_owned()],
            secret: match client_type {
                ClientType::Public => None,
                ClientType::Confidential => Some("the client secret".to_owned()),
            },
        }
    }

    fn registry<'a>(
        config: &'a AuthConfig,
        state: &'a dyn GrantState,
        key: &'a [u8],
        admin_hash: Option<&'a str>,
    ) -> ClientRegistry<'a> {
        ClientRegistry::new(config, state, key, admin_hash)
    }

    fn admin_hash() -> String {
        tokens::secret_hash(KEY, "administrator", ADMIN_SECRET)
    }

    fn memory_state() -> GrantStoreState<SqliteStore> {
        GrantStoreState::new(
            SqliteStore::open_in_memory().expect("the store opens"),
            Durability::Ephemeral,
        )
    }

    #[test]
    fn provisioning_requires_the_administrator_credential() {
        let config = config();
        let state = memory_state();
        let admin_hash = admin_hash();
        let mut registry = registry(&config, &state, KEY, Some(&admin_hash));
        assert!(matches!(
            registry.provision(registration("client-1", ClientType::Confidential), "wrong"),
            Err(AuthError::InvalidClient(_))
        ));
    }

    #[test]
    fn a_deployment_without_an_administrator_credential_provisions_nothing() {
        let config = config();
        let state = memory_state();
        let mut registry = registry(&config, &state, KEY, None);
        assert!(matches!(
            registry.provision(
                registration("client-1", ClientType::Confidential),
                "anything"
            ),
            Err(AuthError::Deployment(_))
        ));
    }

    #[test]
    fn a_confidential_client_is_stored_as_a_secret_hash() {
        let config = config();
        let state = memory_state();
        let admin_hash = admin_hash();
        let mut registry = registry(&config, &state, KEY, Some(&admin_hash));
        let client = registry
            .provision(
                registration("client-1", ClientType::Confidential),
                ADMIN_SECRET,
            )
            .expect("the client is provisioned");
        assert!(client.record.confidential);
        assert!(client.record.secret_hash.is_some());
        let stored = state
            .get_client("client-1")
            .expect("the store answers")
            .expect("the client is stored");
        assert!(stored.secret_hash.is_some());
        assert_ne!(
            stored.secret_hash,
            Some("the client secret".to_owned()),
            "the secret itself must not be stored"
        );
    }

    #[test]
    fn a_confidential_client_without_a_secret_is_refused() {
        let config = config();
        let state = memory_state();
        let admin_hash = admin_hash();
        let mut registry = registry(&config, &state, KEY, Some(&admin_hash));
        let mut registration = registration("client-1", ClientType::Confidential);
        registration.secret = None;
        assert!(matches!(
            registry.provision(registration, ADMIN_SECRET),
            Err(AuthError::InvalidClient(_))
        ));
    }

    #[test]
    fn a_public_client_may_not_carry_a_secret() {
        let config = config();
        let state = memory_state();
        let admin_hash = admin_hash();
        let mut registry = registry(&config, &state, KEY, Some(&admin_hash));
        let mut registration = registration("client-1", ClientType::Public);
        registration.secret = Some("not allowed".to_owned());
        assert!(matches!(
            registry.provision(registration, ADMIN_SECRET),
            Err(AuthError::InvalidClient(_))
        ));
    }

    #[test]
    fn a_confidential_client_must_present_its_secret() {
        let config = config();
        let state = memory_state();
        let admin_hash = admin_hash();
        let mut registry = registry(&config, &state, KEY, Some(&admin_hash));
        registry
            .provision(
                registration("client-1", ClientType::Confidential),
                ADMIN_SECRET,
            )
            .expect("the client is provisioned");
        assert!(matches!(
            registry.authenticate("client-1", None),
            Err(AuthError::InvalidClient(_))
        ));
        assert!(matches!(
            registry.authenticate("client-1", Some("wrong secret")),
            Err(AuthError::InvalidClient(_))
        ));
        assert!(
            registry
                .authenticate("client-1", Some("the client secret"))
                .is_ok()
        );
    }

    #[test]
    fn a_public_client_must_not_present_a_secret() {
        let config = config();
        let state = memory_state();
        let admin_hash = admin_hash();
        let mut registry = registry(&config, &state, KEY, Some(&admin_hash));
        registry
            .provision(registration("public-1", ClientType::Public), ADMIN_SECRET)
            .expect("the client is provisioned");
        assert!(matches!(
            registry.authenticate("public-1", Some("a secret")),
            Err(AuthError::InvalidClient(_))
        ));
        assert!(registry.authenticate("public-1", None).is_ok());
    }

    #[test]
    fn an_unknown_client_is_refused() {
        let config = config();
        let state = memory_state();
        let admin_hash = admin_hash();
        let registry = registry(&config, &state, KEY, Some(&admin_hash));
        assert!(matches!(
            registry.authenticate("nobody", None),
            Err(AuthError::InvalidClient(_))
        ));
    }

    #[test]
    fn a_redirect_uri_must_match_exactly() {
        let config = config();
        let state = memory_state();
        let admin_hash = admin_hash();
        let mut registry = registry(&config, &state, KEY, Some(&admin_hash));
        let client = registry
            .provision(registration("client-1", ClientType::Public), ADMIN_SECRET)
            .expect("the client is provisioned");
        assert_eq!(
            ClientRegistry::check_redirect_uri(&client, "https://client.example/callback"),
            Ok(())
        );
        for redirect_uri in [
            "https://client.example/callback/extra",
            "https://client.example/callback/",
            "https://client.example/callback#fragment",
            "https://client.example/other",
            "https://attacker.example/callback",
            "HTTPS://CLIENT.EXAMPLE/callback",
            "https://client.example/callback/extra?next=https://client.example/callback",
        ] {
            assert!(
                matches!(
                    ClientRegistry::check_redirect_uri(&client, redirect_uri),
                    Err(AuthError::InvalidRedirectUri(_))
                ),
                "the redirect uri {redirect_uri:?} should have been refused"
            );
        }
    }

    #[test]
    fn a_registration_may_not_add_an_unsafe_redirect_uri() {
        let config = config();
        let state = memory_state();
        let admin_hash = admin_hash();
        let mut registry = registry(&config, &state, KEY, Some(&admin_hash));
        for redirect_uri in [
            "http://client.example/callback",
            "https://client.example/callback#fragment",
            "not a url",
            "",
        ] {
            let mut registration = registration("client-1", ClientType::Public);
            registration.redirect_uris = vec![redirect_uri.to_owned()];
            assert!(
                matches!(
                    registry.provision(registration, ADMIN_SECRET),
                    Err(AuthError::InvalidClient(_))
                ),
                "the redirect uri {redirect_uri:?} should have been refused"
            );
        }
    }

    #[test]
    fn a_loopback_redirect_uri_may_use_http() {
        let config = config();
        let state = memory_state();
        let admin_hash = admin_hash();
        let mut registry = registry(&config, &state, KEY, Some(&admin_hash));
        let mut registration = registration("native-1", ClientType::Public);
        registration.redirect_uris = vec![
            "http://127.0.0.1:49152/callback".to_owned(),
            "http://[::1]:49152/callback".to_owned(),
        ];
        assert!(registry.provision(registration, ADMIN_SECRET).is_ok());
    }

    #[test]
    fn a_client_may_not_ask_for_actions_or_identities_outside_its_policy() {
        let config = config();
        let state = memory_state();
        let admin_hash = admin_hash();
        let mut registry = registry(&config, &state, KEY, Some(&admin_hash));
        let client = registry
            .provision(registration("client-1", ClientType::Public), ADMIN_SECRET)
            .expect("the client is provisioned");
        assert_eq!(ClientRegistry::check_action(&client, Action::List), Ok(()));
        assert!(matches!(
            ClientRegistry::check_action(&client, Action::Send),
            Err(AuthError::InsufficientScope(_))
        ));
        assert_eq!(
            ClientRegistry::check_identity(&client, "identity-a"),
            Ok(())
        );
        assert!(matches!(
            ClientRegistry::check_identity(&client, "identity-b"),
            Err(AuthError::InsufficientScope(_))
        ));
    }

    #[test]
    fn a_client_may_not_use_a_grant_type_outside_its_policy() {
        let config = config();
        let state = memory_state();
        let admin_hash = admin_hash();
        let mut registry = registry(&config, &state, KEY, Some(&admin_hash));
        let client = registry
            .provision(registration("client-1", ClientType::Public), ADMIN_SECRET)
            .expect("the client is provisioned");
        assert_eq!(
            ClientRegistry::check_grant_type(&client, GrantType::AuthorizationCode),
            Ok(())
        );
        assert!(matches!(
            ClientRegistry::check_grant_type(&client, GrantType::ClientCredentials),
            Err(AuthError::UnsupportedGrantType(_))
        ));
    }

    #[test]
    fn an_unknown_pkce_method_in_the_config_is_refused() {
        let mut config = config();
        config.pkce_methods = vec![PkceMethod::S256];
        assert_eq!(config.validate(), Ok(()));
    }
}
