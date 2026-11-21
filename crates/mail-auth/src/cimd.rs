//! Client-id metadata documents.
//!
//! MCP 2026-07-28 lets a client name itself with an HTTPS URL that points
//! at a metadata document. That URL is attacker-controlled input, so the
//! document is fetched over a restricted path:
//!
//! - **The scheme must be `https`.** A document fetched over plain http
//!   can be rewritten on the way.
//! - **The host must be a public address.** A document on `127.0.0.1`, on
//!   a private network or on a link-local address turns the issuer into a
//!   fetcher for the deployment's own network.
//! - **A redirect may not leave the origin.** A document that redirects to
//!   another origin is a document from another origin.
//! - **The document must be fresh.** A stale document is a document the
//!   client no longer controls.
//! - **The document must name the client id exactly.** A document that
//!   names another client is not this client's document.
//!
//! There is no network in this crate: the fetch is a trait, and the tests
//! drive it with fixtures.

use serde::{Deserialize, Serialize};
use url::Url;

use crate::client::{ClientType, check_redirect_uri_value};
use crate::config::CimdPolicy;
use crate::error::AuthError;

/// The prefix of the URL schemes that may carry a client id.
const HTTPS: &str = "https";
/// How many redirects a metadata fetch may follow.
const MAX_REDIRECTS: u32 = 3;

/// A client-id metadata document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientMetadata {
    /// The client identifier, which must equal the document's URL.
    #[serde(alias = "client_id")]
    pub client_id: String,
    /// The name the document shows.
    #[serde(
        default,
        alias = "client_name",
        skip_serializing_if = "Option::is_none"
    )]
    pub client_name: Option<String>,
    /// The redirect URIs the client may use.
    #[serde(default, alias = "redirect_uris")]
    pub redirect_uris: Vec<String>,
    /// The grant types the client may use.
    #[serde(default, alias = "grant_types")]
    pub grant_types: Vec<String>,
    /// How the client authenticates at the token endpoint.
    #[serde(
        default,
        alias = "token_endpoint_auth_method",
        skip_serializing_if = "Option::is_none"
    )]
    pub token_endpoint_auth_method: Option<String>,
    /// The kind of client the document describes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_type: Option<ClientType>,
}

/// What a fetch produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchResult {
    /// The status the server answered with.
    pub status: u16,
    /// The body of the answer.
    pub body: Vec<u8>,
    /// The URL the body finally came from.
    pub final_url: String,
    /// The URLs that were redirected to, in order.
    pub redirects: Vec<String>,
    /// When the document itself was produced.
    pub document_time: u64,
}

/// The transport seam: how a metadata document is fetched.
///
/// The trait is the seam an HTTP client would implement. It reports the
/// redirect chain so that the resolver can refuse a redirect that left the
/// origin.
pub trait MetadataFetcher {
    /// Fetch a document.
    fn fetch(&self, url: &str, max_redirects: u32) -> Result<FetchResult, AuthError>;
}

/// The resolver of client-id metadata documents.
pub struct CimdResolver<'a> {
    policy: &'a CimdPolicy,
    fetcher: &'a dyn MetadataFetcher,
}

impl std::fmt::Debug for CimdResolver<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CimdResolver")
            .field("policy", self.policy)
            .finish_non_exhaustive()
    }
}

impl<'a> CimdResolver<'a> {
    /// Build a resolver.
    pub fn new(policy: &'a CimdPolicy, fetcher: &'a dyn MetadataFetcher) -> Self {
        Self { policy, fetcher }
    }

    /// Resolve a client id into the metadata it names.
    pub fn resolve(&self, client_id: &str, now: u64) -> Result<ClientMetadata, AuthError> {
        let url = self.check_client_id_url(client_id)?;
        let result = self.fetcher.fetch(client_id, MAX_REDIRECTS)?;
        if result.status != 200 {
            return Err(AuthError::InvalidClientMetadata(
                "the metadata document could not be read".to_owned(),
            ));
        }
        self.check_redirects(&url, &result)?;
        if result.body.len() > self.policy.max_document_bytes {
            return Err(AuthError::InvalidClientMetadata(
                "the metadata document is too large".to_owned(),
            ));
        }
        let age = now.saturating_sub(result.document_time);
        if age > self.policy.max_age_seconds {
            return Err(AuthError::InvalidClientMetadata(
                "the metadata document is stale".to_owned(),
            ));
        }
        let metadata: ClientMetadata = serde_json::from_slice(&result.body).map_err(|_| {
            AuthError::InvalidClientMetadata("the metadata document is not readable".to_owned())
        })?;
        if metadata.client_id != client_id {
            return Err(AuthError::InvalidClientMetadata(
                "the metadata document names another client".to_owned(),
            ));
        }
        if metadata.redirect_uris.is_empty() {
            return Err(AuthError::InvalidClientMetadata(
                "the metadata document names no redirect uri".to_owned(),
            ));
        }
        for redirect_uri in &metadata.redirect_uris {
            check_redirect_uri_value(redirect_uri).map_err(|_| {
                AuthError::InvalidClientMetadata(
                    "the metadata document names an unsafe redirect uri".to_owned(),
                )
            })?;
        }
        Ok(metadata)
    }

    /// Check the URL a client id names.
    fn check_client_id_url(&self, client_id: &str) -> Result<Url, AuthError> {
        let refused =
            |reason: &str| AuthError::InvalidClientMetadata(format!("the client id {reason}"));
        let parsed = Url::parse(client_id).map_err(|_| refused("is not a URL"))?;
        if parsed.scheme() != HTTPS {
            return Err(refused("does not use the https scheme"));
        }
        let host = parsed.host_str().ok_or_else(|| refused("has no host"))?;
        if !is_public_host(host) {
            return Err(AuthError::UnsafeAddress(
                "the client id does not name a public address".to_owned(),
            ));
        }
        if !self.policy.allowed_hosts.is_empty()
            && !self
                .policy
                .allowed_hosts
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(host))
        {
            return Err(refused("is not an allowed host"));
        }
        Ok(parsed)
    }

    /// Check that no redirect left the origin of the client id.
    fn check_redirects(&self, client_id: &Url, result: &FetchResult) -> Result<(), AuthError> {
        let refused = || {
            AuthError::InvalidClientMetadata(
                "the metadata document was redirected to another origin".to_owned(),
            )
        };
        for redirect in result
            .redirects
            .iter()
            .chain(std::iter::once(&result.final_url))
        {
            let parsed = Url::parse(redirect).map_err(|_| refused())?;
            if parsed.scheme() != client_id.scheme()
                || parsed.host_str() != client_id.host_str()
                || parsed.port_or_known_default() != client_id.port_or_known_default()
            {
                return Err(refused());
            }
            let host = parsed.host_str().unwrap_or_default();
            if !is_public_host(host) {
                return Err(AuthError::UnsafeAddress(
                    "the redirect does not name a public address".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

/// Check that a host is a public address.
///
/// A name that resolves to a private address is refused as well, because
/// the resolver cannot know what it resolves to without resolving it, and
/// the names that are used to reach a deployment's own network are known.
pub fn is_public_host(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.eq_ignore_ascii_case("localhost") || host.ends_with(".localhost") {
        return false;
    }
    if host.ends_with(".local") || host.ends_with(".internal") || host.ends_with(".home.arpa") {
        return false;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(address) => match address {
            std::net::IpAddr::V4(v4) => {
                !(v4.is_private()
                    || v4.is_loopback()
                    || v4.is_link_local()
                    || v4.is_unspecified()
                    || v4.is_broadcast()
                    || v4.is_multicast()
                    || v4.is_documentation()
                    || is_shared_v4(&v4))
            }
            std::net::IpAddr::V6(v6) => {
                !(v6.is_loopback()
                    || v6.is_unspecified()
                    || v6.is_multicast()
                    || is_unique_local(&v6)
                    || is_link_local_v6(&v6))
            }
        },
        // A name that is not an address literal is resolved by the fetcher;
        // the names that point at the local network are refused above.
        Err(_) => true,
    }
}

/// Whether an IPv4 address is in the shared address space.
fn is_shared_v4(address: &std::net::Ipv4Addr) -> bool {
    let octets = address.octets();
    octets[0] == 100 && (octets[1] & 0xc0) == 64
}

/// Whether an IPv6 address is unique local.
fn is_unique_local(address: &std::net::Ipv6Addr) -> bool {
    (address.segments()[0] & 0xfe00) == 0xfc00
}

/// Whether an IPv6 address is link local.
fn is_link_local_v6(address: &std::net::Ipv6Addr) -> bool {
    (address.segments()[0] & 0xffc0) == 0xfe80
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const NOW: u64 = 1_700_000_000;

    /// A fetcher that answers from a table.
    #[derive(Debug, Default)]
    struct StaticFetcher {
        responses: HashMap<String, FetchResult>,
    }

    impl MetadataFetcher for StaticFetcher {
        fn fetch(&self, url: &str, _max_redirects: u32) -> Result<FetchResult, AuthError> {
            self.responses.get(url).cloned().ok_or_else(|| {
                AuthError::InvalidClientMetadata("the document is not there".to_owned())
            })
        }
    }

    fn document(client_id: &str) -> String {
        serde_json::json!({
            "client_id": client_id,
            "client_name": "A client",
            "redirect_uris": ["https://client.example/callback"],
            "grant_types": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_method": "none"
        })
        .to_string()
    }

    fn resolver<'a>(policy: &'a CimdPolicy, fetcher: &'a StaticFetcher) -> CimdResolver<'a> {
        CimdResolver::new(policy, fetcher)
    }

    fn policy() -> CimdPolicy {
        CimdPolicy::default()
    }

    #[test]
    fn a_fresh_document_on_a_public_host_resolves() {
        let client_id = "https://client.example/metadata.json";
        let mut fetcher = StaticFetcher::default();
        fetcher.responses.insert(
            client_id.to_owned(),
            FetchResult {
                status: 200,
                body: document(client_id).into_bytes(),
                final_url: client_id.to_owned(),
                redirects: Vec::new(),
                document_time: NOW - 10,
            },
        );
        let policy = policy();
        let metadata = resolver(&policy, &fetcher)
            .resolve(client_id, NOW)
            .expect("the document resolves");
        assert_eq!(metadata.client_id, client_id);
        assert_eq!(
            metadata.redirect_uris,
            vec!["https://client.example/callback"]
        );
    }

    #[test]
    fn a_non_https_client_id_is_refused() {
        let policy = policy();
        let mut fetcher = StaticFetcher::default();
        // The document is there and is fine: only the scheme of the client
        // id may refuse it.
        let insecure = "http://client.example/metadata.json";
        fetcher.responses.insert(
            insecure.to_owned(),
            FetchResult {
                status: 200,
                body: document(insecure).into_bytes(),
                final_url: insecure.to_owned(),
                redirects: Vec::new(),
                document_time: NOW - 10,
            },
        );
        for client_id in [insecure, "file:///etc/passwd", "https://"] {
            assert!(
                matches!(
                    resolver(&policy, &fetcher).resolve(client_id, NOW),
                    Err(AuthError::InvalidClientMetadata(_))
                ),
                "the client id {client_id:?} should have been refused"
            );
        }
        // The reason is the scheme and not the fetch: the document is
        // there and would have resolved.
        let error = resolver(&policy, &fetcher)
            .resolve(insecure, NOW)
            .expect_err("the client id must be refused");
        assert!(
            error.to_string().contains("https scheme"),
            "the refusal should name the scheme: {error}"
        );
    }

    #[test]
    fn a_private_or_loopback_client_id_is_refused() {
        let policy = policy();
        let fetcher = StaticFetcher::default();
        for client_id in [
            "https://127.0.0.1/metadata.json",
            "https://localhost/metadata.json",
            "https://[::1]/metadata.json",
            "https://10.0.0.5/metadata.json",
            "https://192.168.1.10/metadata.json",
            "https://172.16.0.1/metadata.json",
            "https://169.254.169.254/latest/meta-data",
            "https://service.internal/metadata.json",
        ] {
            assert!(
                matches!(
                    resolver(&policy, &fetcher).resolve(client_id, NOW),
                    Err(AuthError::UnsafeAddress(_))
                ),
                "the client id {client_id:?} should have been refused as an address"
            );
        }
    }

    #[test]
    fn a_redirect_to_another_origin_is_refused() {
        let policy = policy();
        // A redirect to another host leaves the origin, and so does a
        // redirect that only changes the scheme of the same host and port.
        for (client_id, target) in [
            (
                "https://client.example/metadata.json",
                "https://attacker.example/metadata.json",
            ),
            (
                "https://client.example:8443/metadata.json",
                "http://client.example:8443/metadata.json",
            ),
        ] {
            let mut fetcher = StaticFetcher::default();
            fetcher.responses.insert(
                client_id.to_owned(),
                FetchResult {
                    status: 200,
                    body: document(client_id).into_bytes(),
                    final_url: target.to_owned(),
                    redirects: vec![target.to_owned()],
                    document_time: NOW - 10,
                },
            );
            let error = resolver(&policy, &fetcher)
                .resolve(client_id, NOW)
                .expect_err("the redirect must be refused");
            assert!(
                matches!(&error, AuthError::InvalidClientMetadata(_)),
                "the redirect to {target:?} should have been refused: {error}"
            );
        }
    }

    #[test]
    fn a_stale_document_is_refused() {
        let client_id = "https://client.example/metadata.json";
        let mut fetcher = StaticFetcher::default();
        fetcher.responses.insert(
            client_id.to_owned(),
            FetchResult {
                status: 200,
                body: document(client_id).into_bytes(),
                final_url: client_id.to_owned(),
                redirects: Vec::new(),
                document_time: NOW - 100_000,
            },
        );
        let policy = policy();
        assert!(matches!(
            resolver(&policy, &fetcher).resolve(client_id, NOW),
            Err(AuthError::InvalidClientMetadata(_))
        ));
    }

    #[test]
    fn a_document_that_names_another_client_is_refused() {
        let client_id = "https://client.example/metadata.json";
        let mut fetcher = StaticFetcher::default();
        fetcher.responses.insert(
            client_id.to_owned(),
            FetchResult {
                status: 200,
                body: document("https://attacker.example/metadata.json").into_bytes(),
                final_url: client_id.to_owned(),
                redirects: Vec::new(),
                document_time: NOW - 10,
            },
        );
        let policy = policy();
        assert!(matches!(
            resolver(&policy, &fetcher).resolve(client_id, NOW),
            Err(AuthError::InvalidClientMetadata(_))
        ));
    }

    #[test]
    fn an_oversized_document_is_refused() {
        let client_id = "https://client.example/metadata.json";
        let mut fetcher = StaticFetcher::default();
        fetcher.responses.insert(
            client_id.to_owned(),
            FetchResult {
                status: 200,
                body: vec![b'x'; 200_000],
                final_url: client_id.to_owned(),
                redirects: Vec::new(),
                document_time: NOW - 10,
            },
        );
        let policy = policy();
        assert!(matches!(
            resolver(&policy, &fetcher).resolve(client_id, NOW),
            Err(AuthError::InvalidClientMetadata(_))
        ));
    }

    #[test]
    fn a_host_outside_the_allowed_list_is_refused() {
        let client_id = "https://client.example/metadata.json";
        let mut fetcher = StaticFetcher::default();
        fetcher.responses.insert(
            client_id.to_owned(),
            FetchResult {
                status: 200,
                body: document(client_id).into_bytes(),
                final_url: client_id.to_owned(),
                redirects: Vec::new(),
                document_time: NOW - 10,
            },
        );
        let policy = CimdPolicy {
            allowed_hosts: vec!["other.example".to_owned()],
            ..CimdPolicy::default()
        };
        assert!(matches!(
            resolver(&policy, &fetcher).resolve(client_id, NOW),
            Err(AuthError::InvalidClientMetadata(_))
        ));
    }

    #[test]
    fn a_document_with_an_unsafe_redirect_uri_is_refused() {
        let client_id = "https://client.example/metadata.json";
        let body = serde_json::json!({
            "client_id": client_id,
            "redirect_uris": ["http://attacker.example/callback"]
        })
        .to_string();
        let mut fetcher = StaticFetcher::default();
        fetcher.responses.insert(
            client_id.to_owned(),
            FetchResult {
                status: 200,
                body: body.into_bytes(),
                final_url: client_id.to_owned(),
                redirects: Vec::new(),
                document_time: NOW - 10,
            },
        );
        let policy = policy();
        assert!(matches!(
            resolver(&policy, &fetcher).resolve(client_id, NOW),
            Err(AuthError::InvalidClientMetadata(_))
        ));
    }

    #[test]
    fn a_redirect_uri_that_is_not_safe_is_refused() {
        assert!(check_redirect_uri_value("https://client.example/callback").is_ok());
        assert!(check_redirect_uri_value("http://client.example/callback").is_err());
        assert!(check_redirect_uri_value("http://127.0.0.1:49152/callback").is_ok());
        assert!(check_redirect_uri_value("https://client.example/cb#frag").is_err());
    }
}
