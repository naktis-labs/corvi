//! The rules a reconnection must not break.
//!
//! ADR-0008 section 3: "Reconnect/re-consent must not silently reassign
//! existing Corvi `MailIdentity` grants or expand agent access to new
//! physical mailboxes; changes to upstream account owner, issuer or
//! privilege require an explicit review." And ADR-0008 section 8 of the
//! release gates: "connecting/remapping/reconnecting never silently changes
//! existing identity grants".
//!
//! So a reconnection is checked against what the connection already has,
//! before anything is sent to the provider. Three things may not change
//! silently: the upstream account owner, the Corvi identity that serves
//! the connection, and the set of capabilities the connection was granted.
//! A reconnection that wants more than the connection has is refused, and
//! the operator has to widen the grant through the ordinary, explicit
//! route.

use mail_storage::ProviderConnection;

use crate::callback::check_callback;
use crate::error::UpstreamOAuthError;
use crate::profile::ProviderProfile;
use crate::scope::Capability;

/// Why a reconnection was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconnectRefusal {
    /// The reconnection would bind a different upstream account.
    OwnerChanged {
        /// The account the connection serves.
        recorded: String,
        /// The account that was asked for.
        requested: String,
    },
    /// The reconnection would serve a different Corvi identity.
    IdentityChanged {
        /// The identity the connection serves.
        recorded: String,
        /// The identity that was asked for.
        requested: String,
    },
    /// The reconnection would widen the granted capabilities.
    ScopeWidening {
        /// The capabilities that were asked for.
        requested: Vec<String>,
        /// The capabilities the connection already has.
        granted: Vec<String>,
    },
    /// The callback is not one the provider registered.
    CallbackNotAllowed {
        /// The callback that was refused.
        redirect_uri: String,
    },
}

impl std::fmt::Display for ReconnectRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReconnectRefusal::OwnerChanged {
                recorded,
                requested,
            } => {
                write!(
                    f,
                    "the connection owns {recorded} and may not become {requested}"
                )
            }
            ReconnectRefusal::IdentityChanged {
                recorded,
                requested,
            } => {
                write!(
                    f,
                    "the connection serves {recorded} and may not become {requested}"
                )
            }
            ReconnectRefusal::ScopeWidening { requested, granted } => {
                write!(
                    f,
                    "the connection may not widen its capabilities from {} to {}",
                    granted.join(", "),
                    requested.join(", ")
                )
            }
            ReconnectRefusal::CallbackNotAllowed { redirect_uri } => {
                write!(f, "the callback {redirect_uri} is not registered")
            }
        }
    }
}

impl std::error::Error for ReconnectRefusal {}

impl From<ReconnectRefusal> for UpstreamOAuthError {
    fn from(refusal: ReconnectRefusal) -> Self {
        match refusal {
            ReconnectRefusal::CallbackNotAllowed { redirect_uri } => {
                UpstreamOAuthError::CallbackNotAllowed {
                    provider: String::new(),
                    redirect_uri,
                }
            }
            other => UpstreamOAuthError::InvalidRequest {
                reason: other.to_string(),
            },
        }
    }
}

/// What an operator asks for when they reconnect an account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconnectRequest {
    /// The connection being reconnected.
    pub connection_id: String,
    /// The Corvi identity that must keep serving it.
    pub identity: String,
    /// The upstream account that must keep owning it.
    pub expected_account: String,
    /// The capabilities the connection needs. They may not exceed the ones
    /// it already has.
    pub capabilities: Vec<Capability>,
    /// The callback to use.
    pub redirect_uri: String,
}

/// Check a reconnection against what the connection already has.
pub fn evaluate_reconnect(
    existing: &ProviderConnection,
    request: &ReconnectRequest,
    profile: &ProviderProfile,
) -> Result<(), ReconnectRefusal> {
    if existing.identity != request.identity {
        return Err(ReconnectRefusal::IdentityChanged {
            recorded: existing.identity.clone(),
            requested: request.identity.clone(),
        });
    }
    if existing.account_ref != request.expected_account {
        return Err(ReconnectRefusal::OwnerChanged {
            recorded: existing.account_ref.clone(),
            requested: request.expected_account.clone(),
        });
    }
    let granted = existing.capabilities.clone();
    let requested: Vec<String> = request
        .capabilities
        .iter()
        .map(|capability| capability.as_str().to_owned())
        .collect();
    if requested
        .iter()
        .any(|capability| !granted.contains(capability))
    {
        return Err(ReconnectRefusal::ScopeWidening { requested, granted });
    }
    if check_callback(profile, &request.redirect_uri).is_err() {
        return Err(ReconnectRefusal::CallbackNotAllowed {
            redirect_uri: request.redirect_uri.clone(),
        });
    }
    Ok(())
}
