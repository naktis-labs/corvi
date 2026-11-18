//! The HTTP seam the upstream OAuth flow speaks through.
//!
//! This crate performs no network I/O. The protocol logic — building the
//! authorization request, exchanging the code, polling the device grant,
//! refreshing a token — is written against [`OAuthTransport`], so it can be
//! exercised against recorded provider behaviour without a network and
//! without a TLS stack in the data plane.
//!
//! The request type redacts the fields that carry credentials when it is
//! printed. A test fixture records the requests it was given, and a
//! recorded request must not become a log line that leaks an authorization
//! code, a verifier or a client secret.

use std::fmt;

/// The HTTP methods this crate uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    /// A GET request.
    Get,
    /// A POST request.
    Post,
}

impl HttpMethod {
    /// The name of the method.
    pub fn as_str(&self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
        }
    }
}

/// The form fields that must never appear in a printed request.
const SECRET_FORM_FIELDS: &[&str] = &[
    "client_secret",
    "code",
    "code_verifier",
    "refresh_token",
    "device_code",
];

/// One request to a provider.
#[derive(Clone, PartialEq, Eq)]
pub struct OAuthRequest {
    /// The method.
    pub method: HttpMethod,
    /// The absolute URL.
    pub url: String,
    /// The headers.
    pub headers: Vec<(String, String)>,
    /// The form fields, for a POST.
    pub form: Vec<(String, String)>,
}

impl fmt::Debug for OAuthRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let headers: Vec<(&str, &str)> = self
            .headers
            .iter()
            .map(|(name, value)| {
                if name.eq_ignore_ascii_case("authorization") {
                    (name.as_str(), "[redacted]")
                } else {
                    (name.as_str(), value.as_str())
                }
            })
            .collect();
        let form: Vec<(&str, &str)> = self
            .form
            .iter()
            .map(|(name, value)| {
                if SECRET_FORM_FIELDS.iter().any(|field| field == name) {
                    (name.as_str(), "[redacted]")
                } else {
                    (name.as_str(), value.as_str())
                }
            })
            .collect();
        f.debug_struct("OAuthRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &headers)
            .field("form", &form)
            .finish()
    }
}

impl OAuthRequest {
    /// A GET request.
    pub fn get(url: impl Into<String>) -> Self {
        Self {
            method: HttpMethod::Get,
            url: url.into(),
            headers: Vec::new(),
            form: Vec::new(),
        }
    }

    /// A POST request with form fields.
    pub fn post_form(url: impl Into<String>, form: Vec<(String, String)>) -> Self {
        Self {
            method: HttpMethod::Post,
            url: url.into(),
            headers: Vec::new(),
            form,
        }
    }

    /// Add a header.
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// The value of a form field.
    pub fn form_value(&self, name: &str) -> Option<&str> {
        self.form
            .iter()
            .find(|(field, _)| field == name)
            .map(|(_, value)| value.as_str())
    }
}

/// One response from a provider.
///
/// The body of a token response carries the tokens themselves, so the
/// `Debug` of a response never prints it; it says how long it was.
#[derive(Clone, PartialEq, Eq)]
pub struct OAuthResponse {
    /// The status code.
    pub status: u16,
    /// The headers.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
}

impl fmt::Debug for OAuthResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthResponse")
            .field("status", &self.status)
            .field("headers", &self.headers)
            .field(
                "body",
                &format_args!("[{} bytes redacted]", self.body.len()),
            )
            .finish()
    }
}

impl OAuthResponse {
    /// A response with a JSON body.
    pub fn json(status: u16, body: &serde_json::Value) -> Self {
        Self {
            status,
            headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
            body: serde_json::to_vec(body).unwrap_or_default(),
        }
    }

    /// A response with a form-encoded body.
    pub fn form(status: u16, fields: &[(&str, &str)]) -> Self {
        let body = fields
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<String>>()
            .join("&");
        Self {
            status,
            headers: vec![(
                "Content-Type".to_owned(),
                "application/x-www-form-urlencoded".to_owned(),
            )],
            body: body.into_bytes(),
        }
    }

    /// The body as JSON.
    pub fn json_body(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::from_slice(&self.body)
    }
}

/// Why a request could not be made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportFailure {
    /// What went wrong, without request material.
    pub reason: String,
}

impl TransportFailure {
    /// A failure with a reason.
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

impl fmt::Display for TransportFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.reason)
    }
}

impl std::error::Error for TransportFailure {}

/// The seam that moves bytes to and from a provider.
pub trait OAuthTransport: fmt::Debug + Send + Sync {
    /// Send one request.
    fn send(&self, request: &OAuthRequest) -> Result<OAuthResponse, TransportFailure>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_response_prints_no_body() {
        let response = OAuthResponse::json(
            200,
            &serde_json::json!({
                "access_token": "the-access-token-SECRET",
                "refresh_token": "the-refresh-token-SECRET",
            }),
        );
        let printed = format!("{response:?}");
        assert!(
            !printed.contains("the-access-token-SECRET"),
            "the body of a response is credential material: {printed}"
        );
        assert!(
            !printed.contains("the-refresh-token-SECRET"),
            "the body of a response is credential material: {printed}"
        );
        assert!(printed.contains("200"), "the status is shown: {printed}");
    }
}
