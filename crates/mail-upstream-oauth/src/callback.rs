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
use url::{Host, Url};

/// Whether a URI names the loopback interface.
///
/// The URI is parsed, not cut apart by hand: the userinfo of a URI is not
/// its host, and `http://127.0.0.1:80@evil.example/callback` sends the
/// browser to `evil.example`. A URI with userinfo is refused outright — a
/// loopback callback has no business carrying credentials in its authority
/// — and only the literal loopback addresses count. A hostname is not
/// enough: "localhost" can be resolved to something else, and the callback
/// of a native client must stay on the machine that started the flow.
pub fn is_loopback_uri(uri: &str) -> bool {
    let Ok(url) = Url::parse(uri) else {
        return false;
    };
    if url.scheme() != "http" {
        return false;
    }
    if !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    match url.host() {
        Some(Host::Ipv4(host)) => host.octets() == [127, 0, 0, 1],
        Some(Host::Ipv6(host)) => host == std::net::Ipv6Addr::LOCALHOST,
        _ => false,
    }
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
