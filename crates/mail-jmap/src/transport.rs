//! The HTTP seam the JMAP client speaks through.
//!
//! ADR-0007 requires the client to validate "the allowed HTTPS origins,
//! certificate identities, URL schemes, ports, DNS resolution, redirect
//! targets and deployment egress policy" for every endpoint, including
//! downloads and event-source reconnects. Those checks live in
//! [`crate::trust`] and run before every request, so the transport itself
//! only has to move bytes.
//!
//! Keeping the transport behind a trait has two purposes. The TLS layer
//! stays outside the protocol code, and the protocol code can be exercised
//! against recorded server behaviour without a network.

use std::fmt;

/// The largest response the client accepts by default.
pub const DEFAULT_MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;

/// The bounds applied to every request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportLimits {
    /// The largest response body the client accepts.
    pub max_response_bytes: u64,
    /// The largest attachment the client downloads.
    pub max_blob_bytes: u64,
    /// The largest page of messages the client asks for.
    pub max_page_size: u32,
}

impl Default for TransportLimits {
    fn default() -> Self {
        Self {
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            max_blob_bytes: 25 * 1024 * 1024,
            max_page_size: 100,
        }
    }
}

/// One HTTP request.
#[derive(Clone, PartialEq, Eq)]
pub struct HttpRequest {
    /// The HTTP method.
    pub method: String,
    /// The absolute URL to call.
    pub url: String,
    /// The request headers.
    pub headers: Vec<(String, String)>,
    /// The request body.
    pub body: Vec<u8>,
}

impl fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let headers: Vec<_> = self
            .headers
            .iter()
            .map(|(name, value)| {
                if name.eq_ignore_ascii_case("authorization") {
                    (name, "[redacted]")
                } else {
                    (name, value.as_str())
                }
            })
            .collect();
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &headers)
            .field("body", &self.body)
            .finish()
    }
}

impl HttpRequest {
    /// The value of a header, matched case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// One HTTP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    /// The status code.
    pub status: u16,
    /// The response headers.
    pub headers: Vec<(String, String)>,
    /// The response body.
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// A response with a JSON body.
    pub fn json(status: u16, body: &serde_json::Value) -> Self {
        Self {
            status,
            headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
            body: serde_json::to_vec(body).unwrap_or_default(),
        }
    }

    /// The value of a header, matched case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// The transport the client speaks through.
pub trait HttpTransport: fmt::Debug + Send {
    /// Whether this transport binds connections to the validated addresses.
    /// Fixture transports may return true because they perform no network I/O.
    fn enforces_address_pinning(&self) -> bool {
        false
    }

    /// Send one request and return the response.
    ///
    /// A transport that cannot tell whether the request reached the server
    /// reports [`mail_core::TransportError::Ambiguous`], because a client
    /// that retries an ambiguous submission can deliver a message twice.
    fn send(&mut self, request: &HttpRequest) -> Result<HttpResponse, mail_core::TransportError>;
}
