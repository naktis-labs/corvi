//! Why an authorization request failed.
//!
//! The variants are the OAuth error codes the protocol uses plus the two
//! failure modes that are not the client's fault at all: the deployment
//! cannot authorize anything, or the store cannot prove that a token is
//! still fresh. Every one of them fails closed.
//!
//! Nothing in this module carries a token, a code, a secret or a verifier.
//! An error says *what kind* of thing was refused, never *which* secret was
//! presented, so an error can be logged without becoming a credential leak.

use std::fmt;

/// Why an authorization or token request was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// The request is malformed or violates a rule the protocol states.
    ///
    /// This maps onto OAuth's `invalid_request`.
    InvalidRequest(String),
    /// The client is unknown, disabled, or failed authentication.
    ///
    /// This maps onto OAuth's `invalid_client`.
    InvalidClient(String),
    /// The grant type is not one this issuer supports.
    UnsupportedGrantType(String),
    /// The requested scope is not allowed, or is outside the consent.
    ///
    /// This maps onto OAuth's `invalid_scope`.
    InvalidScope(String),
    /// The redirect URI is not registered for the client.
    ///
    /// This maps onto OAuth's `invalid_request`, because a redirect that is
    /// not registered must never receive an error page either.
    InvalidRedirectUri(String),
    /// The request carries an issuer that is not this issuer.
    ///
    /// This is the issuer mix-up defence: a request bound to another issuer
    /// is refused rather than answered with this issuer's metadata.
    IssuerMismatch(String),
    /// The PKCE challenge is absent, malformed or does not match.
    InvalidPkce(String),
    /// The PKCE code challenge method is one this issuer does not support.
    ///
    /// `plain` lands here: it is not a malformed challenge, it is a
    /// method Corvi refuses.
    UnsupportedPkceMethod(String),
    /// The address a document would be fetched from is not a public one.
    UnsafeAddress(String),
    /// The authorization code, refresh token or access token is not usable.
    ///
    /// This maps onto OAuth's `invalid_grant`.
    InvalidGrant(String),
    /// The token was refused because its issuer, audience or client binding
    /// does not match this deployment.
    InvalidToken(String),
    /// The token is well formed but carries no permission for the operation.
    InsufficientScope(String),
    /// The requested resource is not the one this deployment serves.
    InvalidResource(String),
    /// The client is not allowed to register itself.
    ///
    /// Dynamic client registration is disabled by default.
    RegistrationDisabled(String),
    /// The client metadata document may not be used.
    InvalidClientMetadata(String),
    /// The deployment cannot answer: the grant state is not persistent, or a
    /// capability the operation needs is missing.
    ///
    /// This is not a client error. It is the reason an issuer refuses to
    /// start at all.
    Deployment(String),
    /// The grant store failed or cannot prove freshness.
    Storage(String),
    /// The store does not implement what this operation needs.
    StorageUnsupported(String),
}

impl AuthError {
    /// The OAuth error code this failure maps onto, when it has one.
    ///
    /// A deployment failure has no OAuth code on purpose: it is not the
    /// client's mistake, and answering with `invalid_request` would tell a
    /// client to retry something that will never work.
    pub fn oauth_code(&self) -> Option<&'static str> {
        match self {
            AuthError::InvalidRequest(_) | AuthError::InvalidRedirectUri(_) => {
                Some("invalid_request")
            }
            AuthError::InvalidClient(_) => Some("invalid_client"),
            AuthError::UnsupportedGrantType(_) => Some("unsupported_grant_type"),
            AuthError::InvalidScope(_) => Some("invalid_scope"),
            AuthError::InvalidPkce(_) => Some("invalid_request"),
            AuthError::UnsupportedPkceMethod(_) => Some("invalid_request"),
            AuthError::UnsafeAddress(_) => Some("invalid_request"),
            AuthError::InvalidGrant(_) => Some("invalid_grant"),
            AuthError::InvalidToken(_) => Some("invalid_token"),
            AuthError::InsufficientScope(_) => Some("insufficient_scope"),
            AuthError::InvalidResource(_) => Some("invalid_target"),
            AuthError::IssuerMismatch(_) => Some("invalid_request"),
            AuthError::RegistrationDisabled(_) => Some("invalid_request"),
            AuthError::InvalidClientMetadata(_) => Some("invalid_client_metadata"),
            AuthError::Deployment(_) | AuthError::Storage(_) | AuthError::StorageUnsupported(_) => {
                None
            }
        }
    }
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::InvalidRequest(reason) => write!(f, "the request is not valid: {reason}"),
            AuthError::InvalidClient(reason) => write!(f, "the client is not valid: {reason}"),
            AuthError::UnsupportedGrantType(reason) => {
                write!(f, "the grant type is not supported: {reason}")
            }
            AuthError::InvalidScope(reason) => write!(f, "the scope is not valid: {reason}"),
            AuthError::InvalidRedirectUri(reason) => {
                write!(f, "the redirect uri is not valid: {reason}")
            }
            AuthError::IssuerMismatch(reason) => write!(f, "the issuer does not match: {reason}"),
            AuthError::InvalidPkce(reason) => {
                write!(f, "the pkce challenge is not valid: {reason}")
            }
            AuthError::UnsupportedPkceMethod(reason) => {
                write!(f, "the pkce method is not supported: {reason}")
            }
            AuthError::UnsafeAddress(reason) => write!(f, "the address is not usable: {reason}"),
            AuthError::InvalidGrant(reason) => write!(f, "the grant is not usable: {reason}"),
            AuthError::InvalidToken(reason) => write!(f, "the token is not valid: {reason}"),
            AuthError::InsufficientScope(reason) => {
                write!(f, "the token is missing a scope: {reason}")
            }
            AuthError::InvalidResource(reason) => write!(f, "the resource is not valid: {reason}"),
            AuthError::RegistrationDisabled(reason) => {
                write!(f, "the registration is not allowed: {reason}")
            }
            AuthError::InvalidClientMetadata(reason) => {
                write!(f, "the client metadata is not valid: {reason}")
            }
            AuthError::Deployment(reason) => write!(f, "the deployment cannot authorize: {reason}"),
            AuthError::Storage(reason) => write!(f, "the grant store failed: {reason}"),
            AuthError::StorageUnsupported(reason) => {
                write!(f, "the grant store does not support this: {reason}")
            }
        }
    }
}

impl std::error::Error for AuthError {}
