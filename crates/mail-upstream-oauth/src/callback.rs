//! The callback allowlist.
//!
//! ADR-0008 requires "exact redirect URI matching", "approved
//! provider/issuer/redirect allowlists" and that "only explicitly permitted
//! loopback callbacks may use HTTP". A callback that is not on the list is
//! refused before the browser is sent anywhere, and the refusal says which
//! provider rejected it.
//!
//! The rule is exact string equality against the URIs that were registered
//! with the provider. There is no prefix match, no wildcard and no
//! "same host, different path" rule, because a redirect that the provider
//! does not expect is exactly how an authorization code ends up in the
//! wrong hands.

use crate::error::UpstreamOAuthError;
use crate::profile::ProviderProfile;

/// Whether a URI names the loopback interface.
///
/// Only the literal loopback addresses count. A hostname is not enough:
/// "localhost" can be resolved to something else, and the callback of a
/// native client must stay on the machine that started the flow.
pub fn is_loopback_uri(uri: &str) -> bool {
    let Some(rest) = uri.strip_prefix("http://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority
        .rsplit_once(':')
        .map_or(authority, |(host, _)| host);
    matches!(host, "127.0.0.1" | "[::1]" | "::1")
}

/// Whether a URI is an HTTPS URI.
pub fn is_https_uri(uri: &str) -> bool {
    uri.starts_with("https://")
}

/// Check that a callback may be used for this provider.
///
/// The callback must be one the provider registered, and it must be HTTPS
/// unless it is on the loopback interface.
pub fn check_callback(
    profile: &ProviderProfile,
    redirect_uri: &str,
) -> Result<(), UpstreamOAuthError> {
    let refused = || UpstreamOAuthError::CallbackNotAllowed {
        provider: profile.provider_id.clone(),
        redirect_uri: redirect_uri.to_owned(),
    };
    if !profile
        .client
        .redirect_uris
        .iter()
        .any(|uri| uri == redirect_uri)
    {
        return Err(refused());
    }
    if !is_https_uri(redirect_uri) && !is_loopback_uri(redirect_uri) {
        return Err(refused());
    }
    Ok(())
}
