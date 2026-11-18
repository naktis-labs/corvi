//! Why an upstream OAuth operation failed.
//!
//! The statuses here are the ones `api/upstream-oauth.schema.json` names in
//! its `connectionStatus` enumeration, because the status is what an
//! authorized management surface is allowed to show. A status is a closed
//! vocabulary: an operator sees "unsupportedRegistration", not a provider's
//! raw error text, and never a token, a code or a verifier.
//!
//! Nothing in this module carries credential material. Provider error
//! descriptions are dropped rather than formatted, because a provider is
//! free to echo the request into its error text.

use std::fmt;

use serde::{Deserialize, Serialize};

/// The safe, non-secret status of a provider connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ConnectionStatus {
    /// The account is not connected.
    Unconnected,
    /// An authorization is in flight.
    PendingAuthorization,
    /// The account is connected and usable.
    Connected,
    /// The credential must be reauthorized before the account works again.
    NeedsReauthorization,
    /// The provider granted less than the connection needs.
    ScopeInsufficient,
    /// The provider account is not the account that was expected.
    AccountMismatch,
    /// The deployment cannot register a client for this provider.
    UnsupportedRegistration,
    /// The provider could not be reached or understood.
    Unavailable,
}

impl ConnectionStatus {
    /// The name of the status, as the schema spells it.
    pub fn as_str(&self) -> &'static str {
        match self {
            ConnectionStatus::Unconnected => "unconnected",
            ConnectionStatus::PendingAuthorization => "pendingAuthorization",
            ConnectionStatus::Connected => "connected",
            ConnectionStatus::NeedsReauthorization => "needsReauthorization",
            ConnectionStatus::ScopeInsufficient => "scopeInsufficient",
            ConnectionStatus::AccountMismatch => "accountMismatch",
            ConnectionStatus::UnsupportedRegistration => "unsupportedRegistration",
            ConnectionStatus::Unavailable => "unavailable",
        }
    }

    /// Parse a status name.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "unconnected" => Some(ConnectionStatus::Unconnected),
            "pendingAuthorization" => Some(ConnectionStatus::PendingAuthorization),
            "connected" => Some(ConnectionStatus::Connected),
            "needsReauthorization" => Some(ConnectionStatus::NeedsReauthorization),
            "scopeInsufficient" => Some(ConnectionStatus::ScopeInsufficient),
            "accountMismatch" => Some(ConnectionStatus::AccountMismatch),
            "unsupportedRegistration" => Some(ConnectionStatus::UnsupportedRegistration),
            "unavailable" => Some(ConnectionStatus::Unavailable),
            _ => None,
        }
    }
}

/// Why a handoff payload was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoffFailure {
    /// The payload did not authenticate: it was modified or the key is wrong.
    Tampered,
    /// The payload is older than its expiry.
    Expired,
    /// The payload was already redeemed.
    Replayed,
    /// The payload is addressed to somebody else.
    UnknownRecipient,
    /// The payload is not one this deployment issued.
    Unknown,
}

impl fmt::Display for HandoffFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HandoffFailure::Tampered => write!(f, "the payload did not authenticate"),
            HandoffFailure::Expired => write!(f, "the payload has expired"),
            HandoffFailure::Replayed => write!(f, "the payload was already redeemed"),
            HandoffFailure::UnknownRecipient => write!(f, "the payload is addressed elsewhere"),
            HandoffFailure::Unknown => write!(f, "the payload is not one this deployment issued"),
        }
    }
}

/// Why an upstream OAuth operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamOAuthError {
    /// The provider is not one this deployment can onboard.
    UnsupportedProvider {
        /// The provider that was asked for.
        provider: String,
        /// Why it cannot be onboarded.
        reason: String,
    },
    /// The deployment cannot register or use a client for this provider.
    ///
    /// This is the explicit answer ADR-0008 asks for: a provider that
    /// cannot do unattended registration says so instead of failing
    /// somewhere deep in a token exchange.
    UnsupportedRegistration {
        /// The provider that was asked for.
        provider: String,
        /// Which constraint is unmet.
        reason: String,
    },
    /// A scope the provider does not offer was requested.
    UnsupportedScope {
        /// The provider that was asked for.
        provider: String,
        /// The scope or capability that is not offered.
        scope: String,
    },
    /// The provider cannot grant what the connection needs.
    ScopeInsufficient {
        /// The provider that was asked for.
        provider: String,
        /// What is missing.
        missing: Vec<String>,
    },
    /// The provider granted more than was requested.
    ScopeWidening {
        /// The provider that was asked for.
        provider: String,
        /// The scope that was granted unexpectedly.
        scope: String,
    },
    /// The callback URI is not one the provider registered.
    CallbackNotAllowed {
        /// The provider that was asked for.
        provider: String,
        /// The callback that was refused.
        redirect_uri: String,
    },
    /// The authorization transaction is missing, expired, replayed or does
    /// not match the request.
    InvalidTransaction {
        /// What did not line up.
        reason: String,
    },
    /// The provider account is not the account that was expected.
    AccountMismatch {
        /// The account the operator asked for.
        expected: String,
        /// The account the provider returned.
        actual: String,
    },
    /// A remote handoff payload was refused.
    HandoffRejected {
        /// Why it was refused.
        reason: HandoffFailure,
    },
    /// The principal may not perform this operation.
    NotAuthorized {
        /// The principal that asked.
        principal: String,
        /// The operation it asked for.
        action: &'static str,
    },
    /// The provider refused the grant.
    InvalidGrant {
        /// The provider's error code, without its description.
        reason: String,
    },
    /// The credential cannot be recovered and must be reauthorized.
    NeedsReauthorization {
        /// The connection that needs attention.
        connection_id: String,
        /// Why it needs attention.
        reason: String,
    },
    /// The request itself is not usable.
    InvalidRequest {
        /// What is wrong with it.
        reason: String,
    },
    /// The provider could not be reached.
    Transport {
        /// What went wrong, without request material.
        reason: String,
    },
    /// The provider answered something that could not be understood.
    Protocol {
        /// What went wrong.
        reason: String,
    },
    /// The storage layer failed.
    Storage {
        /// What went wrong.
        reason: String,
    },
}

impl UpstreamOAuthError {
    /// The safe status this failure reports.
    ///
    /// The mapping is total and closed: a failure never degrades into
    /// "some error", because an operator has to be able to act on the
    /// status without reading a provider's error text.
    pub fn status(&self) -> ConnectionStatus {
        match self {
            UpstreamOAuthError::UnsupportedProvider { .. }
            | UpstreamOAuthError::UnsupportedRegistration { .. }
            | UpstreamOAuthError::CallbackNotAllowed { .. } => {
                ConnectionStatus::UnsupportedRegistration
            }
            UpstreamOAuthError::UnsupportedScope { .. }
            | UpstreamOAuthError::ScopeInsufficient { .. }
            | UpstreamOAuthError::ScopeWidening { .. } => ConnectionStatus::ScopeInsufficient,
            UpstreamOAuthError::AccountMismatch { .. } => ConnectionStatus::AccountMismatch,
            UpstreamOAuthError::InvalidGrant { .. }
            | UpstreamOAuthError::NeedsReauthorization { .. } => {
                ConnectionStatus::NeedsReauthorization
            }
            UpstreamOAuthError::InvalidTransaction { .. } => ConnectionStatus::PendingAuthorization,
            UpstreamOAuthError::HandoffRejected { .. }
            | UpstreamOAuthError::NotAuthorized { .. }
            | UpstreamOAuthError::Transport { .. }
            | UpstreamOAuthError::Protocol { .. }
            | UpstreamOAuthError::Storage { .. } => ConnectionStatus::Unavailable,
            UpstreamOAuthError::InvalidRequest { .. } => ConnectionStatus::Unconnected,
        }
    }
}

impl fmt::Display for UpstreamOAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UpstreamOAuthError::UnsupportedProvider { provider, reason } => {
                write!(f, "the provider {provider} is not supported: {reason}")
            }
            UpstreamOAuthError::UnsupportedRegistration { provider, reason } => {
                write!(f, "the provider {provider} cannot be onboarded: {reason}")
            }
            UpstreamOAuthError::UnsupportedScope { provider, scope } => {
                write!(
                    f,
                    "the provider {provider} does not offer the scope {scope}"
                )
            }
            UpstreamOAuthError::ScopeInsufficient { provider, missing } => {
                write!(
                    f,
                    "the provider {provider} did not grant {}",
                    missing.join(", ")
                )
            }
            UpstreamOAuthError::ScopeWidening { provider, scope } => {
                write!(
                    f,
                    "the provider {provider} granted the unexpected scope {scope}"
                )
            }
            UpstreamOAuthError::CallbackNotAllowed {
                provider,
                redirect_uri,
            } => {
                write!(
                    f,
                    "the callback {redirect_uri} is not registered for {provider}"
                )
            }
            UpstreamOAuthError::InvalidTransaction { reason } => {
                write!(f, "the authorization transaction is not usable: {reason}")
            }
            UpstreamOAuthError::AccountMismatch { expected, actual } => {
                write!(
                    f,
                    "the provider account {actual} is not the expected account {expected}"
                )
            }
            UpstreamOAuthError::HandoffRejected { reason } => {
                write!(f, "the handoff payload was refused: {reason}")
            }
            UpstreamOAuthError::NotAuthorized { principal, action } => {
                write!(f, "the principal {principal} may not {action}")
            }
            UpstreamOAuthError::InvalidGrant { reason } => {
                write!(f, "the provider refused the grant: {reason}")
            }
            UpstreamOAuthError::NeedsReauthorization {
                connection_id,
                reason,
            } => {
                write!(
                    f,
                    "the connection {connection_id} needs reauthorization: {reason}"
                )
            }
            UpstreamOAuthError::InvalidRequest { reason } => {
                write!(f, "the request is not usable: {reason}")
            }
            UpstreamOAuthError::Transport { reason } => {
                write!(f, "the provider could not be reached: {reason}")
            }
            UpstreamOAuthError::Protocol { reason } => {
                write!(f, "the provider answered something unexpected: {reason}")
            }
            UpstreamOAuthError::Storage { reason } => {
                write!(f, "the storage failed: {reason}")
            }
        }
    }
}

impl std::error::Error for UpstreamOAuthError {}

impl From<mail_storage::StorageError> for UpstreamOAuthError {
    fn from(error: mail_storage::StorageError) -> Self {
        match error {
            mail_storage::StorageError::KeyMismatch => UpstreamOAuthError::NeedsReauthorization {
                connection_id: String::new(),
                reason: "the credential cannot be decrypted".to_owned(),
            },
            other => UpstreamOAuthError::Storage {
                reason: other.to_string(),
            },
        }
    }
}
