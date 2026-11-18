//! Which upstream scopes a connection may ask for.
//!
//! Two rules from ADR-0008 meet here. The first is that Corvi must not ask
//! for more provider scope than the intended transport needs: "avoid asking
//! for more provider scopes than the intended transport/actions need". The
//! second is that a provider scope is not a Corvi grant: what an agent may
//! do with the account is decided by Corvi's own identity and policy
//! objects, never by the provider's scope string.
//!
//! So the resolution here is deliberately narrow. A request names
//! capabilities (read, send) and, if a deployment insists, exact provider
//! scope strings. Anything the provider does not offer is refused
//! explicitly, by name, before anything is sent to the provider.

use crate::error::UpstreamOAuthError;
use crate::profile::ProviderProfile;

/// What a connection wants to do with the upstream account.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
pub enum Capability {
    /// Read mail.
    Read,
    /// Submit mail.
    Send,
    /// Keep access while the account is offline.
    Offline,
    /// Administer the upstream account.
    Management,
}

impl Capability {
    /// The name of the capability.
    pub fn as_str(&self) -> &'static str {
        match self {
            Capability::Read => "read",
            Capability::Send => "send",
            Capability::Offline => "offline",
            Capability::Management => "management",
        }
    }

    /// Parse a capability name.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "read" => Some(Capability::Read),
            "send" => Some(Capability::Send),
            "offline" => Some(Capability::Offline),
            "management" => Some(Capability::Management),
            _ => None,
        }
    }
}

/// What an onboarding asks the provider for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopeRequest {
    /// The capabilities the connection needs.
    pub capabilities: Vec<Capability>,
    /// Exact provider scope strings, when a deployment names them.
    pub extra_scopes: Vec<String>,
}

impl ScopeRequest {
    /// A request for the given capabilities.
    pub fn new(capabilities: Vec<Capability>) -> Self {
        Self {
            capabilities,
            extra_scopes: Vec::new(),
        }
    }

    /// A request that also names exact provider scopes.
    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.extra_scopes = scopes;
        self
    }
}

/// The provider scope strings a request resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedScopes {
    /// The exact scope strings to request.
    pub scopes: Vec<String>,
    /// The capabilities that were resolved.
    pub capabilities: Vec<Capability>,
}

/// Resolve a request into the provider scope strings to ask for.
///
/// Every refusal names the scope or capability that is not offered, so an
/// operator can see which provider rule they hit.
pub fn resolve_scopes(
    profile: &ProviderProfile,
    request: &ScopeRequest,
) -> Result<ResolvedScopes, UpstreamOAuthError> {
    let provider = profile.provider_id.clone();
    let mut scopes: Vec<String> = Vec::new();
    let mut capabilities: Vec<Capability> = Vec::new();

    for capability in &request.capabilities {
        let offered = profile.scopes.for_capability(*capability);
        if offered.is_empty() {
            return Err(UpstreamOAuthError::UnsupportedScope {
                provider,
                scope: capability.as_str().to_owned(),
            });
        }
        scopes.extend(offered);
        capabilities.push(*capability);
    }

    let supported = profile.scopes.all();
    for scope in &request.extra_scopes {
        if !supported.contains(scope) {
            return Err(UpstreamOAuthError::UnsupportedScope {
                provider,
                scope: scope.clone(),
            });
        }
        scopes.push(scope.clone());
    }

    scopes.sort();
    scopes.dedup();
    capabilities.sort();
    capabilities.dedup();
    Ok(ResolvedScopes {
        scopes,
        capabilities,
    })
}

/// The first scope the provider granted that was not requested.
///
/// A provider that grants more than was asked for is a deployment
/// surprise, and ADR-0008 forbids silent widening.
pub fn unexpected_scope(requested: &[String], granted: &[String]) -> Option<String> {
    granted
        .iter()
        .find(|scope| !requested.contains(scope))
        .cloned()
}

/// The scopes of a granted set that the request asked for.
pub fn granted_subset(requested: &[String], granted: &[String]) -> Vec<String> {
    granted
        .iter()
        .filter(|scope| requested.contains(scope))
        .cloned()
        .collect()
}
