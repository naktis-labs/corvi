//! Discovery documents.
//!
//! RFC 9728 for the protected resource, RFC 8414 for the authorization
//! server. Both are produced from the configuration and both advertise only
//! what the deployment actually implements: a document that advertised a
//! grant type, a scope or a PKCE method the code refuses would be a working
//! lie.
//!
//! The issuer identifier is compared exactly. `https://auth.example` and
//! `https://auth.example/` are different strings and only one of them is
//! the configured issuer, so a request bound to the other is a mix-up and
//! is refused.

use crate::config::AuthConfig;
use crate::error::AuthError;

/// Build the RFC 9728 protected-resource metadata document.
pub fn protected_resource_metadata(config: &AuthConfig) -> Result<serde_json::Value, AuthError> {
    let mut issuers = Vec::new();
    if config.built_in_issuer_enabled() {
        issuers.push(config.issuer.clone());
    }
    for issuer in &config.trusted_external_issuers {
        if !issuers.contains(issuer) {
            issuers.push(issuer.clone());
        }
    }
    Ok(serde_json::json!({
        "resource": config.resource,
        "authorization_servers": issuers,
        "scopes_supported": scope_names(config),
        "bearer_methods_supported": ["header"],
    }))
}

/// Build the RFC 8414 authorization-server metadata document.
///
/// Only the built-in issuer has one: an external-issuer-only deployment
/// publishes no authorization-server metadata of its own.
pub fn authorization_server_metadata(config: &AuthConfig) -> Result<serde_json::Value, AuthError> {
    if !config.built_in_issuer_enabled() {
        return Err(AuthError::Deployment(
            "this deployment runs no built-in issuer, so it publishes no authorization server \
             metadata of its own"
                .to_owned(),
        ));
    }
    Ok(serde_json::json!({
        "issuer": config.issuer,
        "authorization_endpoint": config.authorization_endpoint,
        "token_endpoint": config.token_endpoint,
        "revocation_endpoint": config.revocation_endpoint,
        "response_types_supported": ["code"],
        "grant_types_supported": grant_type_names(config),
        "code_challenge_methods_supported": config
            .pkce_methods
            .iter()
            .map(|method| method.as_str())
            .collect::<Vec<_>>(),
        "scopes_supported": scope_names(config),
        "token_endpoint_auth_methods_supported": ["none", "client_secret_basic"],
        "revocation_endpoint_auth_methods_supported": ["none", "client_secret_basic"],
        "authorization_details_types_supported": ["corvi_mail"],
    }))
}

/// Check that a request is bound to this issuer.
///
/// The comparison is exact: a different issuer, a different case, a trailing
/// slash or an added path segment is another issuer.
pub fn check_issuer(config: &AuthConfig, presented: &str) -> Result<(), AuthError> {
    if presented == config.issuer {
        Ok(())
    } else {
        Err(AuthError::IssuerMismatch(
            "the request is not bound to this issuer".to_owned(),
        ))
    }
}

/// The scopes of a metadata document, as wire names.
fn scope_names(config: &AuthConfig) -> Vec<&'static str> {
    config
        .scopes_supported
        .iter()
        .map(|action| action.as_str())
        .collect()
}

/// The grant types of a metadata document, as wire names.
fn grant_type_names(config: &AuthConfig) -> Vec<&'static str> {
    config
        .grant_types
        .iter()
        .map(|grant_type| grant_type.as_str())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> AuthConfig {
        AuthConfig::integrated("https://auth.corvi.example", "https://mail.corvi.example")
    }

    #[test]
    fn the_resource_metadata_names_the_resource_and_the_trusted_issuers() {
        let metadata = protected_resource_metadata(&config()).expect("the metadata is built");
        assert_eq!(metadata["resource"], "https://mail.corvi.example");
        assert_eq!(
            metadata["authorization_servers"],
            serde_json::json!(["https://auth.corvi.example"])
        );
        assert!(
            metadata["scopes_supported"]
                .as_array()
                .expect("the scopes are listed")
                .iter()
                .any(|scope| scope == "mail:messages:read")
        );
        assert_eq!(
            metadata["bearer_methods_supported"],
            serde_json::json!(["header"])
        );
    }

    #[test]
    fn the_resource_metadata_advertises_only_configured_trusted_issuers() {
        let mut config = config();
        config.trusted_external_issuers = vec!["https://idp.corvi.example".to_owned()];
        let metadata = protected_resource_metadata(&config).expect("the metadata is built");
        assert_eq!(
            metadata["authorization_servers"],
            serde_json::json!(["https://auth.corvi.example", "https://idp.corvi.example"])
        );
    }

    #[test]
    fn the_as_metadata_names_the_configured_issuer_exactly() {
        let metadata = authorization_server_metadata(&config()).expect("the metadata is built");
        assert_eq!(metadata["issuer"], "https://auth.corvi.example");
        assert_eq!(
            metadata["authorization_endpoint"],
            "https://auth.corvi.example/oauth/authorize"
        );
        assert_eq!(
            metadata["token_endpoint"],
            "https://auth.corvi.example/oauth/token"
        );
        assert_eq!(
            metadata["revocation_endpoint"],
            "https://auth.corvi.example/oauth/revoke"
        );
    }

    #[test]
    fn the_as_metadata_advertises_only_what_is_implemented() {
        let metadata = authorization_server_metadata(&config()).expect("the metadata is built");
        assert_eq!(
            metadata["response_types_supported"],
            serde_json::json!(["code"])
        );
        assert_eq!(
            metadata["code_challenge_methods_supported"],
            serde_json::json!(["S256"])
        );
        assert_eq!(
            metadata["grant_types_supported"],
            serde_json::json!(["authorization_code", "refresh_token"])
        );
        assert_eq!(
            metadata["authorization_details_types_supported"],
            serde_json::json!(["corvi_mail"])
        );
        let scopes = metadata["scopes_supported"].as_array().expect("the scopes");
        assert!(scopes.iter().any(|scope| scope == "mail:messages:read"));
    }

    #[test]
    fn an_external_only_deployment_publishes_no_as_metadata_of_its_own() {
        let config = AuthConfig::external_resource_server("https://mail.corvi.example", &[]);
        assert!(matches!(
            authorization_server_metadata(&config),
            Err(AuthError::Deployment(_))
        ));
    }

    #[test]
    fn a_request_for_another_issuer_is_refused() {
        assert_eq!(
            check_issuer(&config(), "https://auth.corvi.example"),
            Ok(())
        );
        for issuer in [
            "https://attacker.example",
            "https://auth.corvi.example/",
            "https://auth.corvi.example/oauth",
            "HTTPS://AUTH.CORVI.EXAMPLE",
            "http://auth.corvi.example",
        ] {
            assert!(
                matches!(
                    check_issuer(&config(), issuer),
                    Err(AuthError::IssuerMismatch(_))
                ),
                "the issuer {issuer:?} should have been refused"
            );
        }
    }
}
