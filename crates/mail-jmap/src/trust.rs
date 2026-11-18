//! Trust rules for every URL the JMAP client is told to use.
//!
//! ADR-0007 section 3 requires that "discovery documents, templates,
//! server-directed API/blob/push URLs and redirects" be treated as untrusted
//! URL inputs: a session object is written by the upstream server, so every
//! URL in it is an instruction from a party that may be hostile. The client
//! therefore validates each URL before it uses it, and validates each
//! redirect target again rather than trusting the first answer.
//!
//! Three rules hold:
//!
//! 1. Only `https` is allowed, unless an operator explicitly allows
//!    plaintext for a local test upstream. There is no "trust any
//!    certificate" option at all.
//! 2. A URL must resolve to a public address. A hostname that resolves to a
//!    loopback, private, link-local or metadata address is refused, so a
//!    hostile session cannot point the gateway at `169.254.169.254`.
//! 3. A redirect may only stay inside the origin the client already
//!    trusted. A redirect to another host is refused rather than followed.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

use url::Url;

/// Why a URL was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustError {
    /// The URL could not be parsed.
    InvalidUrl(String),
    /// The scheme is not allowed.
    SchemeNotAllowed {
        /// The scheme that was refused.
        scheme: String,
    },
    /// The URL carries credentials.
    CredentialsInUrl,
    /// The host is not one of the allowed origins.
    HostNotAllowed {
        /// The host that was refused.
        host: String,
    },
    /// The port is not allowed.
    PortNotAllowed {
        /// The port that was refused.
        port: u16,
    },
    /// The host resolves to an address that is not routable on the public
    /// internet.
    PrivateAddress {
        /// The host that was checked.
        host: String,
        /// The address that was refused.
        address: String,
    },
    /// A redirect pointed somewhere the client does not trust.
    UntrustedRedirect {
        /// The URL the client was at.
        from: String,
        /// The URL the upstream pointed at.
        to: String,
    },
    /// The host name could not be resolved.
    ResolutionFailed {
        /// The host that could not be resolved.
        host: String,
        /// Why the resolution failed.
        reason: String,
    },
}

impl fmt::Display for TrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrustError::InvalidUrl(url) => write!(f, "{url} is not a valid URL"),
            TrustError::SchemeNotAllowed { scheme } => {
                write!(f, "the {scheme} scheme is not allowed")
            }
            TrustError::CredentialsInUrl => {
                write!(f, "a URL that carries credentials is not allowed")
            }
            TrustError::HostNotAllowed { host } => {
                write!(f, "the host {host} is not an allowed origin")
            }
            TrustError::PortNotAllowed { port } => {
                write!(f, "the port {port} is not allowed")
            }
            TrustError::PrivateAddress { host, address } => {
                write!(
                    f,
                    "the host {host} resolves to the non-public address {address}"
                )
            }
            TrustError::UntrustedRedirect { from, to } => {
                write!(f, "the redirect from {from} to {to} is not trusted")
            }
            TrustError::ResolutionFailed { host, reason } => {
                write!(f, "the host {host} could not be resolved: {reason}")
            }
        }
    }
}

impl std::error::Error for TrustError {}

/// A scheme, host and port the client may talk to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    scheme: String,
    host: String,
    port: u16,
}

impl Origin {
    /// Parse an origin such as `https://api.example.com`.
    pub fn parse(value: &str) -> Result<Self, TrustError> {
        let url = Url::parse(value).map_err(|error| TrustError::InvalidUrl(error.to_string()))?;
        let host = url
            .host_str()
            .ok_or_else(|| TrustError::InvalidUrl(value.to_owned()))?
            .to_ascii_lowercase();
        let port = url.port_or_known_default().unwrap_or(443);
        Ok(Self {
            scheme: url.scheme().to_owned(),
            host,
            port,
        })
    }

    /// The host of the origin.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port of the origin.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Whether a URL belongs to this origin.
    pub fn matches(&self, url: &Url) -> bool {
        let Some(host) = url.host_str() else {
            return false;
        };
        let port = url.port_or_known_default().unwrap_or(443);
        url.scheme() == self.scheme && host.eq_ignore_ascii_case(&self.host) && port == self.port
    }
}

/// The egress rules of one deployment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressPolicy {
    origins: Vec<Origin>,
    allow_private_networks: bool,
    allow_plaintext: bool,
}

impl EgressPolicy {
    /// A policy that only allows the given origins over TLS.
    pub fn new(origins: Vec<Origin>) -> Self {
        Self {
            origins,
            allow_private_networks: false,
            allow_plaintext: false,
        }
    }

    /// Allow addresses on private networks.
    ///
    /// This exists for a local upstream under the operator's own control. It
    /// is never on by default, because a hostile session can point the
    /// client at a private address.
    pub fn allowing_private_networks(mut self) -> Self {
        self.allow_private_networks = true;
        self
    }

    /// Allow plaintext `http` URLs.
    ///
    /// This exists for a local fixture upstream. It is never on by default.
    pub fn allowing_plaintext(mut self) -> Self {
        self.allow_plaintext = true;
        self
    }

    /// The allowed origins.
    pub fn origins(&self) -> &[Origin] {
        &self.origins
    }

    /// Whether private networks are allowed.
    pub fn allows_private_networks(&self) -> bool {
        self.allow_private_networks
    }

    /// Check a URL against the policy, without resolving its host.
    pub fn check(&self, url: &str) -> Result<Url, TrustError> {
        let parsed = Url::parse(url).map_err(|error| TrustError::InvalidUrl(error.to_string()))?;
        self.check_parsed(&parsed)
    }

    /// Check an already parsed URL against the policy.
    pub fn check_parsed(&self, url: &Url) -> Result<Url, TrustError> {
        if !url.username().is_empty() || url.password().is_some() {
            return Err(TrustError::CredentialsInUrl);
        }
        if url.scheme() != "https" && !(url.scheme() == "http" && self.allow_plaintext) {
            return Err(TrustError::SchemeNotAllowed {
                scheme: url.scheme().to_owned(),
            });
        }
        let host = url
            .host_str()
            .ok_or_else(|| TrustError::InvalidUrl(url.to_string()))?
            .to_ascii_lowercase();
        let port = url.port_or_known_default().unwrap_or(443);
        if port != 443 && !(port == 80 && self.allow_plaintext) {
            return Err(TrustError::PortNotAllowed { port });
        }
        if self.origins.is_empty() {
            return Err(TrustError::HostNotAllowed { host });
        }
        if !self.origins.iter().any(|origin| origin.matches(url)) {
            return Err(TrustError::HostNotAllowed { host });
        }
        let literal_host = host.trim_start_matches('[').trim_end_matches(']');
        if let Ok(address) = literal_host.parse::<IpAddr>()
            && !is_public_address(&address)
            && !self.allows_private_networks()
        {
            return Err(TrustError::PrivateAddress {
                host,
                address: address.to_string(),
            });
        }
        Ok(url.clone())
    }

    /// Check a redirect target.
    ///
    /// A redirect may only point at the same origin the client already
    /// trusted. Anything else is refused, because a redirect is the one
    /// place where a trusted origin can hand the client to an untrusted one.
    pub fn check_redirect(&self, from: &Url, to: &str) -> Result<Url, TrustError> {
        let target = from
            .join(to)
            .map_err(|error| TrustError::InvalidUrl(error.to_string()))?;
        let same_origin = self
            .origins
            .iter()
            .any(|origin| origin.matches(from) && origin.matches(&target));
        if !same_origin {
            return Err(TrustError::UntrustedRedirect {
                from: from.to_string(),
                to: target.to_string(),
            });
        }
        self.check_parsed(&target)
    }

    /// Check the addresses a host resolved to.
    pub fn check_addresses(&self, host: &str, addresses: &[IpAddr]) -> Result<(), TrustError> {
        if self.allow_private_networks {
            return Ok(());
        }
        for address in addresses {
            if !is_public_address(address) {
                return Err(TrustError::PrivateAddress {
                    host: host.to_owned(),
                    address: address.to_string(),
                });
            }
        }
        Ok(())
    }
}

/// Resolves host names to addresses.
///
/// The client never talks to a name it has not resolved and checked, so the
/// resolution step is a seam: a deployment can pin an address, and a test
/// can answer without a network.
pub trait HostResolver: fmt::Debug + Send {
    /// Resolve a host name to the addresses it points at.
    fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, TrustError>;
}

/// The resolver that asks the platform.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemResolver;

impl HostResolver for SystemResolver {
    fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, TrustError> {
        let mut addresses = Vec::new();
        let iterator =
            (host, 443u16)
                .to_socket_addrs()
                .map_err(|error| TrustError::ResolutionFailed {
                    host: host.to_owned(),
                    reason: error.to_string(),
                })?;
        for address in iterator {
            addresses.push(address.ip());
        }
        if addresses.is_empty() {
            return Err(TrustError::ResolutionFailed {
                host: host.to_owned(),
                reason: "the host resolved to no address".to_owned(),
            });
        }
        Ok(addresses)
    }
}

/// A resolver that answers from a table.
///
/// It exists so the trust rules can be tested against a hostile session
/// without a network, and so a deployment can pin an upstream address.
#[derive(Debug, Clone, Default)]
pub struct StaticResolver {
    hosts: Vec<(String, Vec<IpAddr>)>,
}

impl StaticResolver {
    /// A resolver that knows nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// Teach the resolver about a host.
    pub fn with_host(mut self, host: impl Into<String>, addresses: Vec<IpAddr>) -> Self {
        self.hosts.push((host.into(), addresses));
        self
    }
}

impl HostResolver for StaticResolver {
    fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, TrustError> {
        self.hosts
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(host))
            .map(|(_, addresses)| addresses.clone())
            .ok_or_else(|| TrustError::ResolutionFailed {
                host: host.to_owned(),
                reason: "the host is not known".to_owned(),
            })
    }
}

/// Whether an address is routable on the public internet.
///
/// Everything that is not is refused: loopback, private ranges, link-local
/// addresses (which is where cloud metadata lives), carrier-grade NAT,
/// documentation ranges, multicast and the unspecified address.
pub fn is_public_address(address: &IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_v4(address),
        IpAddr::V6(address) => is_public_v6(address),
    }
}

/// Whether an IPv4 address is routable on the public internet.
fn is_public_v4(address: &Ipv4Addr) -> bool {
    let octets = address.octets();
    match octets[0] {
        0 => false,
        10 => false,
        127 => false,
        100 if (64..128).contains(&octets[1]) => false,
        169 if octets[1] == 254 => false,
        172 if (16..32).contains(&octets[1]) => false,
        192 if octets[1] == 168 => false,
        192 if octets[1] == 0 && octets[2] == 0 => false,
        192 if octets[1] == 0 && octets[2] == 2 => false,
        198 if octets[1] == 18 || octets[1] == 19 => false,
        198 if octets[1] == 51 && octets[2] == 100 => false,
        203 if octets[1] == 0 && octets[2] == 113 => false,
        224..=255 => false,
        _ => true,
    }
}

/// Whether an IPv6 address is routable on the public internet.
fn is_public_v6(address: &Ipv6Addr) -> bool {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return is_public_v4(&mapped);
    }
    // IPv4-compatible and NAT64 forms embed a destination that may bypass
    // the intended IPv4 address checks. Only explicit mapped addresses above
    // are normalized; other transition ranges are denied by the global rule.
    let segments = address.segments();
    if address.is_unspecified() || address.is_loopback() || address.is_multicast() {
        return false;
    }
    // Only global unicast (2000::/3) is eligible for public egress.
    if segments[0] & 0xe000 != 0x2000 {
        return false;
    }
    // Unique local addresses (fc00::/7).
    if segments[0] & 0xfe00 == 0xfc00 {
        return false;
    }
    // Link-local addresses (fe80::/10).
    if segments[0] & 0xffc0 == 0xfe80 {
        return false;
    }
    // 6to4 embeds an IPv4 destination and should not bypass IPv4 checks.
    if segments[0] == 0x2002 {
        return false;
    }
    // IETF protocol assignments (2001::/23), including Teredo and benchmarking.
    if segments[0] == 0x2001 && segments[1] <= 0x01ff {
        return false;
    }
    // Documentation range (2001:db8::/32).
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return false;
    }
    true
}

/// The socket address a URL points at, once the host is resolved.
pub fn resolve_endpoint(
    resolver: &dyn HostResolver,
    host: &str,
    port: u16,
) -> Result<Vec<SocketAddr>, TrustError> {
    let addresses = resolver.resolve(host)?;
    Ok(addresses
        .into_iter()
        .map(|address| SocketAddr::new(address, port))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> EgressPolicy {
        EgressPolicy::new(vec![Origin::parse("https://api.example.com").unwrap()])
    }

    #[test]
    fn an_https_url_on_an_allowed_origin_is_accepted() {
        let url = policy()
            .check("https://api.example.com/jmap/session")
            .expect("the URL is trusted");
        assert_eq!(url.host_str(), Some("api.example.com"));
    }

    #[test]
    fn a_plaintext_url_is_refused() {
        let error = policy()
            .check("http://api.example.com/jmap/session")
            .expect_err("plaintext is refused");
        assert_eq!(
            error,
            TrustError::SchemeNotAllowed {
                scheme: "http".to_owned()
            }
        );
    }

    #[test]
    fn a_url_with_credentials_is_refused() {
        let error = policy()
            .check("https://user:secret@api.example.com/jmap")
            .expect_err("credentials are refused");
        assert_eq!(error, TrustError::CredentialsInUrl);
    }

    #[test]
    fn a_foreign_host_is_refused() {
        let error = policy()
            .check("https://evil.example.net/jmap/session")
            .expect_err("a foreign host is refused");
        assert_eq!(
            error,
            TrustError::HostNotAllowed {
                host: "evil.example.net".to_owned()
            }
        );
    }

    #[test]
    fn an_unusual_port_is_refused() {
        let error = policy()
            .check("https://api.example.com:8443/jmap/session")
            .expect_err("an unusual port is refused");
        assert_eq!(error, TrustError::PortNotAllowed { port: 8443 });
    }

    #[test]
    fn a_metadata_address_is_refused() {
        let error = policy()
            .check("https://169.254.169.254/latest/meta-data/")
            .expect_err("a metadata address is refused");
        assert!(matches!(error, TrustError::HostNotAllowed { .. }));
    }

    #[test]
    fn a_private_address_literal_is_refused() {
        let policy = EgressPolicy::new(vec![Origin::parse("https://127.0.0.1").unwrap()]);
        let error = policy
            .check("https://127.0.0.1/jmap/session")
            .expect_err("a loopback address is refused");
        assert!(matches!(error, TrustError::PrivateAddress { .. }));
    }

    #[test]
    fn a_redirect_to_another_origin_is_refused() {
        let from = Url::parse("https://api.example.com/jmap/session").unwrap();
        let error = policy()
            .check_redirect(&from, "https://evil.example.net/jmap/session")
            .expect_err("a foreign redirect is refused");
        assert!(matches!(error, TrustError::UntrustedRedirect { .. }));
    }

    #[test]
    fn a_redirect_inside_the_origin_is_accepted() {
        let from = Url::parse("https://api.example.com/jmap/session").unwrap();
        let target = policy()
            .check_redirect(&from, "https://api.example.com/jmap/api/")
            .expect("a same-origin redirect is accepted");
        assert_eq!(target.path(), "/jmap/api/");
    }

    #[test]
    fn relative_redirects_are_resolved_against_the_current_url() {
        let from = Url::parse("https://api.example.com/jmap/session").unwrap();
        let target = policy()
            .check_redirect(&from, "../api/")
            .expect("a relative same-origin redirect is accepted");
        assert_eq!(target.as_str(), "https://api.example.com/api/");
    }

    #[test]
    fn private_addresses_are_recognised() {
        assert!(!is_public_address(&"127.0.0.1".parse().unwrap()));
        assert!(!is_public_address(&"10.0.0.1".parse().unwrap()));
        assert!(!is_public_address(&"169.254.169.254".parse().unwrap()));
        assert!(!is_public_address(&"::1".parse().unwrap()));
        assert!(!is_public_address(&"fe80::1".parse().unwrap()));
        assert!(!is_public_address(&"fd00::1".parse().unwrap()));
        assert!(is_public_address(&"93.184.216.34".parse().unwrap()));
        assert!(is_public_address(&"2606:4700::1".parse().unwrap()));
    }

    #[test]
    fn ipv6_addresses_outside_global_unicast_are_not_public() {
        for address in ["2001::1", "2002::1", "64:ff9b::1", "::ffff:10.0.0.1"] {
            assert!(
                !is_public_address(&address.parse().unwrap()),
                "{address} is not accepted as globally routable"
            );
        }
        assert!(is_public_address(&"2606:4700::1".parse().unwrap()));
    }

    #[test]
    fn a_public_ipv6_literal_is_allowed_when_explicitly_trusted() {
        let policy = EgressPolicy::new(vec![Origin::parse("https://[2606:4700::1]").unwrap()]);
        assert!(policy.check("https://[2606:4700::1]/jmap").is_ok());
    }

    #[test]
    fn a_private_ipv6_literal_is_refused() {
        let policy = EgressPolicy::new(vec![Origin::parse("https://[fd00::1]").unwrap()]);
        let error = policy
            .check("https://[fd00::1]/jmap/session")
            .expect_err("a unique-local IPv6 literal is refused");
        assert!(
            matches!(error, TrustError::PrivateAddress { .. }),
            "a bracketed IPv6 literal is classified like any other: {error:?}"
        );
    }

    #[test]
    fn a_resolved_private_address_is_refused() {
        let error = policy()
            .check_addresses("api.example.com", &["127.0.0.1".parse().unwrap()])
            .expect_err("a private address is refused");
        assert!(matches!(error, TrustError::PrivateAddress { .. }));
    }
}
