//! The configuration of Corvi's authorization side.
//!
//! ADR-0009 keeps three trust domains apart, and this module is where the
//! deployment says which one it runs. A standalone installation may run the
//! built-in issuer, an external-issuer-only deployment runs none, and both
//! serve the same protected resource.
//!
//! The configuration is validated once, at construction, and a configuration
//! that cannot be served is refused rather than repaired: an issuer that
//! advertised `plain` PKCE, or that issued access tokens without a bound,
//! would be a working implementation of the wrong protocol.

use mail_core::Action;
use url::Url;

use crate::error::AuthError;

/// How the deployment authorizes its clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    /// The built-in Corvi issuer is enabled.
    Integrated,
    /// Only an external authorization server is trusted.
    ///
    /// No built-in issuer is required, and none may be enabled.
    ExternalResourceServer,
}

/// An OAuth grant type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantType {
    /// The authorization code flow with PKCE.
    AuthorizationCode,
    /// Refreshing an access token with a refresh token.
    RefreshToken,
    /// A service principal authenticating itself.
    ClientCredentials,
}

impl GrantType {
    /// The wire name of the grant type.
    pub fn as_str(self) -> &'static str {
        match self {
            GrantType::AuthorizationCode => "authorization_code",
            GrantType::RefreshToken => "refresh_token",
            GrantType::ClientCredentials => "client_credentials",
        }
    }
}

/// The PKCE code challenge methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkceMethod {
    /// The verifier is sent as the challenge. Never supported.
    Plain,
    /// The challenge is the SHA-256 of the verifier.
    S256,
}

impl PkceMethod {
    /// The wire name of the method.
    pub fn as_str(self) -> &'static str {
        match self {
            PkceMethod::Plain => "plain",
            PkceMethod::S256 => "S256",
        }
    }

    /// Parse a method name.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "plain" => Some(PkceMethod::Plain),
            "S256" => Some(PkceMethod::S256),
            _ => None,
        }
    }
}

/// How clients may be registered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRegistrationConfig {
    /// Whether a client may identify itself with a client-id metadata
    /// document.
    pub client_id_metadata_documents: bool,
    /// Whether pre-registered clients are accepted.
    pub pre_registered_clients: bool,
    /// Whether the legacy dynamic client registration endpoint is enabled.
    ///
    /// Disabled by default. MCP 2026-07-28 deprecates dynamic client
    /// registration, and an unauthenticated endpoint that issues clients is
    /// not something a deployment turns on by accident.
    pub legacy_dynamic_client_registration: bool,
}

impl Default for ClientRegistrationConfig {
    fn default() -> Self {
        Self {
            client_id_metadata_documents: false,
            pre_registered_clients: true,
            legacy_dynamic_client_registration: false,
        }
    }
}

/// The rules a client-id metadata document must satisfy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CimdPolicy {
    /// How old a metadata document may be.
    pub max_age_seconds: u64,
    /// The hosts a metadata document may be fetched from.
    ///
    /// An empty list means any public host that passes the address rules.
    pub allowed_hosts: Vec<String>,
    /// The largest document that is read.
    pub max_document_bytes: usize,
}

impl Default for CimdPolicy {
    fn default() -> Self {
        Self {
            max_age_seconds: 24 * 60 * 60,
            allowed_hosts: Vec::new(),
            max_document_bytes: 64 * 1024,
        }
    }
}

/// The configuration of the authorization side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthConfig {
    /// Whether the built-in issuer runs.
    pub mode: AuthMode,
    /// The issuer identifier of this deployment.
    pub issuer: String,
    /// The canonical protected resource identifier.
    pub resource: String,
    /// The administration resource, when it is a separate audience.
    pub admin_resource: Option<String>,
    /// The external issuers this deployment trusts directly.
    pub trusted_external_issuers: Vec<String>,
    /// Where a client sends the user to consent.
    pub authorization_endpoint: String,
    /// Where a client exchanges a code or refreshes a token.
    pub token_endpoint: String,
    /// Where a client revokes a token.
    pub revocation_endpoint: String,
    /// The grant types this issuer supports.
    pub grant_types: Vec<GrantType>,
    /// The PKCE methods this issuer supports.
    pub pkce_methods: Vec<PkceMethod>,
    /// The scopes this issuer understands.
    pub scopes_supported: Vec<Action>,
    /// How long an access token lives, in seconds.
    pub access_token_lifetime_seconds: u64,
    /// How long a refresh token lives, in seconds.
    pub refresh_token_lifetime_seconds: u64,
    /// How long an authorization code lives, in seconds.
    pub authorization_code_lifetime_seconds: u64,
    /// Whether refresh tokens rotate.
    pub refresh_rotation: bool,
    /// How clients are registered.
    pub client_registration: ClientRegistrationConfig,
    /// The client-id metadata document rules.
    pub cimd: CimdPolicy,
}

impl AuthConfig {
    /// The configuration of a standalone deployment with the built-in issuer.
    pub fn integrated(issuer: &str, resource: &str) -> Self {
        Self {
            mode: AuthMode::Integrated,
            issuer: issuer.to_owned(),
            resource: resource.to_owned(),
            admin_resource: None,
            trusted_external_issuers: Vec::new(),
            authorization_endpoint: format!("{issuer}/oauth/authorize"),
            token_endpoint: format!("{issuer}/oauth/token"),
            revocation_endpoint: format!("{issuer}/oauth/revoke"),
            grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
            pkce_methods: vec![PkceMethod::S256],
            scopes_supported: Action::ALL.to_vec(),
            access_token_lifetime_seconds: 900,
            refresh_token_lifetime_seconds: 30 * 24 * 60 * 60,
            authorization_code_lifetime_seconds: 300,
            refresh_rotation: true,
            client_registration: ClientRegistrationConfig::default(),
            cimd: CimdPolicy::default(),
        }
    }

    /// The configuration of a deployment that trusts only an external issuer.
    pub fn external_resource_server(resource: &str, external_issuers: &[String]) -> Self {
        let mut config = Self::integrated("https://external.invalid", resource);
        config.mode = AuthMode::ExternalResourceServer;
        config.trusted_external_issuers = external_issuers.to_vec();
        config
    }

    /// Whether the built-in issuer is part of this deployment.
    pub fn built_in_issuer_enabled(&self) -> bool {
        matches!(self.mode, AuthMode::Integrated)
    }

    /// Whether a grant type is supported.
    pub fn supports_grant_type(&self, grant_type: GrantType) -> bool {
        self.grant_types.contains(&grant_type)
    }

    /// Whether a scope name is one this issuer understands.
    pub fn supports_scope(&self, scope: &str) -> bool {
        self.scopes_supported
            .iter()
            .any(|action| action.as_str() == scope)
    }

    /// Check the configuration.
    pub fn validate(&self) -> Result<(), AuthError> {
        check_https_url("the issuer", &self.issuer)?;
        check_https_url("the resource", &self.resource)?;
        if let Some(admin) = &self.admin_resource {
            check_https_url("the administration resource", admin)?;
            if admin == &self.resource {
                return Err(AuthError::Deployment(
                    "the administration resource must not be the mail resource".to_owned(),
                ));
            }
        }
        for issuer in &self.trusted_external_issuers {
            check_https_url("a trusted external issuer", issuer)?;
        }
        check_https_url("the authorization endpoint", &self.authorization_endpoint)?;
        check_https_url("the token endpoint", &self.token_endpoint)?;
        check_https_url("the revocation endpoint", &self.revocation_endpoint)?;

        if self.scopes_supported.is_empty() {
            return Err(AuthError::Deployment(
                "the issuer supports no scope at all".to_owned(),
            ));
        }
        for action in &self.scopes_supported {
            if !Action::ALL.contains(action) {
                return Err(AuthError::Deployment(
                    "the issuer advertises an action Corvi does not implement".to_owned(),
                ));
            }
        }
        if self.grant_types.is_empty() {
            return Err(AuthError::Deployment(
                "the issuer supports no grant type".to_owned(),
            ));
        }
        if self.built_in_issuer_enabled() && !self.supports_grant_type(GrantType::AuthorizationCode)
        {
            return Err(AuthError::Deployment(
                "the built-in issuer must support the authorization code grant".to_owned(),
            ));
        }
        if self.pkce_methods != vec![PkceMethod::S256] {
            return Err(AuthError::Deployment(
                "the issuer supports only the S256 pkce method".to_owned(),
            ));
        }
        if self.supports_grant_type(GrantType::RefreshToken) && !self.refresh_rotation {
            return Err(AuthError::Deployment(
                "refresh tokens must rotate".to_owned(),
            ));
        }
        if !(60..=86_400).contains(&self.access_token_lifetime_seconds) {
            return Err(AuthError::Deployment(
                "the access token lifetime must be between 60 and 86400 seconds".to_owned(),
            ));
        }
        if !(30..=600).contains(&self.authorization_code_lifetime_seconds) {
            return Err(AuthError::Deployment(
                "the authorization code lifetime must be between 30 and 600 seconds".to_owned(),
            ));
        }
        if !(300..=2_592_000).contains(&self.refresh_token_lifetime_seconds) {
            return Err(AuthError::Deployment(
                "the refresh token lifetime must be between 300 and 2592000 seconds".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Check that a URL is one this deployment may publish.
fn check_https_url(what: &str, value: &str) -> Result<(), AuthError> {
    let parsed = Url::parse(value)
        .map_err(|error| AuthError::Deployment(format!("{what} is not a URL: {error}")))?;
    if parsed.scheme() != "https" {
        return Err(AuthError::Deployment(format!(
            "{what} must use the https scheme"
        )));
    }
    if parsed.host_str().is_none() {
        return Err(AuthError::Deployment(format!("{what} has no host")));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(AuthError::Deployment(format!(
            "{what} must not carry a query or a fragment"
        )));
    }
    if parsed.path().len() > 1 && parsed.path().ends_with('/') {
        return Err(AuthError::Deployment(format!(
            "{what} must not end with a slash"
        )));
    }
    if value.ends_with('/') {
        return Err(AuthError::Deployment(format!(
            "{what} must be written without a trailing slash"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_standalone_configuration_validates() {
        let config =
            AuthConfig::integrated("https://auth.corvi.example", "https://mail.corvi.example");
        assert_eq!(config.validate(), Ok(()));
        assert!(config.built_in_issuer_enabled());
        assert!(config.supports_scope("mail:messages:read"));
        assert!(!config.supports_scope("mail:everything"));
    }

    #[test]
    fn an_external_only_configuration_needs_no_built_in_issuer() {
        let config = AuthConfig::external_resource_server(
            "https://mail.corvi.example",
            &["https://idp.corvi.example".to_owned()],
        );
        assert_eq!(config.validate(), Ok(()));
        assert!(!config.built_in_issuer_enabled());
    }

    #[test]
    fn a_plain_pkce_method_is_refused() {
        let mut config =
            AuthConfig::integrated("https://auth.corvi.example", "https://mail.corvi.example");
        config.pkce_methods = vec![PkceMethod::S256, PkceMethod::Plain];
        assert!(matches!(config.validate(), Err(AuthError::Deployment(_))));
    }

    #[test]
    fn an_unbounded_access_token_lifetime_is_refused() {
        let mut config =
            AuthConfig::integrated("https://auth.corvi.example", "https://mail.corvi.example");
        config.access_token_lifetime_seconds = 86_401;
        assert!(matches!(config.validate(), Err(AuthError::Deployment(_))));
        config.access_token_lifetime_seconds = 59;
        assert!(matches!(config.validate(), Err(AuthError::Deployment(_))));
    }

    #[test]
    fn a_refresh_token_that_does_not_rotate_is_refused() {
        let mut config =
            AuthConfig::integrated("https://auth.corvi.example", "https://mail.corvi.example");
        config.refresh_rotation = false;
        assert!(matches!(config.validate(), Err(AuthError::Deployment(_))));
    }

    #[test]
    fn a_plain_http_issuer_is_refused() {
        let config =
            AuthConfig::integrated("http://auth.corvi.example", "https://mail.corvi.example");
        assert!(matches!(config.validate(), Err(AuthError::Deployment(_))));
    }

    #[test]
    fn the_administration_resource_may_not_be_the_mail_resource() {
        let mut config =
            AuthConfig::integrated("https://auth.corvi.example", "https://mail.corvi.example");
        config.admin_resource = Some("https://mail.corvi.example".to_owned());
        assert!(matches!(config.validate(), Err(AuthError::Deployment(_))));
    }

    #[test]
    fn dynamic_client_registration_is_off_by_default() {
        let config =
            AuthConfig::integrated("https://auth.corvi.example", "https://mail.corvi.example");
        assert!(
            !config
                .client_registration
                .legacy_dynamic_client_registration
        );
    }
}
