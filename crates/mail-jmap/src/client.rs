//! The JMAP client: session discovery and method calls.
//!
//! The client owns the rules that make a JMAP upstream safe to talk to:
//!
//! 1. Every URL it uses is checked against the deployment's egress policy
//!    ([`crate::trust`]), whether the URL came from the configuration or
//!    from the session object. A session is written by the upstream server,
//!    so its URLs are instructions, not facts.
//! 2. Every redirect target is checked again, and a redirect may only stay
//!    inside the origin the client already trusts.
//! 3. The credential is presented on every request and is never written
//!    into a log, a URL or a query string.
//!
//! The HTTP transport itself is a seam ([`HttpTransport`]). This slice ships
//! the fixture transport only; the transport that terminates TLS and speaks
//! to a provider lives outside this crate, because ADR-0015 keeps
//! HTTP-client dependencies out of the data plane.

use serde_json::Value;

use crate::error::JmapError;
use crate::protocol::{JmapRequest, JmapResponse};
use crate::session::Session;
use crate::transport::{HttpRequest, HttpResponse, TransportLimits};
use crate::trust::{EgressPolicy, HostResolver, SystemResolver, TrustError};

/// The credential presented to the upstream.
///
/// JMAP uses a bearer token for both an OAuth access token and a
/// provider-issued API token. They are different things with different
/// scopes, so the client never assumes one is the other: it presents what it
/// was given and lets the upstream refuse it.
#[derive(Clone, PartialEq, Eq)]
pub struct Credential {
    token: String,
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("token", &"[redacted]")
            .finish()
    }
}

impl Credential {
    /// A credential that presents the given token.
    pub fn bearer(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
        }
    }

    /// The value of the `Authorization` header.
    pub fn header_value(&self) -> String {
        format!("Bearer {}", self.token)
    }
}

/// A JMAP client.
#[derive(Debug)]
pub struct JmapClient {
    transport: Box<dyn crate::transport::HttpTransport>,
    policy: EgressPolicy,
    resolver: Box<dyn HostResolver>,
    credential: Option<Credential>,
    session: Option<Session>,
    limits: TransportLimits,
    max_redirects: usize,
}

/// How much is known about a failed call.
///
/// A call that fails before the request was dispatched did not reach the
/// upstream. A call that fails after it was dispatched may have: the
/// upstream may have acted on the request and lost the answer, and a caller
/// that repeats such a call can act twice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallFailure {
    /// The call failed and the upstream did not carry out the request.
    Failed(JmapError),
    /// The call failed after the request was dispatched, and the upstream may
    /// have carried it out.
    Unknown(JmapError),
}

impl CallFailure {
    /// The error behind the failure.
    pub fn error(&self) -> &JmapError {
        match self {
            CallFailure::Failed(error) | CallFailure::Unknown(error) => error,
        }
    }

    /// A failure reported by the transport after the request was sent.
    ///
    /// A transport that cannot say whether the upstream received the request
    /// leaves the outcome unknown, unless it refused the request outright.
    fn from_transport(error: mail_core::TransportError) -> Self {
        let refused = matches!(
            error,
            mail_core::TransportError::Unauthorized
                | mail_core::TransportError::TlsRejected(_)
                | mail_core::TransportError::Rejected(_)
                | mail_core::TransportError::NotFound
                | mail_core::TransportError::TooLarge { .. }
        );
        let error = JmapError::from(error);
        if refused {
            CallFailure::Failed(error)
        } else {
            CallFailure::Unknown(error)
        }
    }

    /// A failure of a check that runs before a request is sent.
    ///
    /// Once a request has been dispatched, a later check that fails leaves
    /// the outcome of the first request unknown.
    fn before_dispatch(dispatched: bool, error: JmapError) -> Self {
        if dispatched {
            CallFailure::Unknown(error)
        } else {
            CallFailure::Failed(error)
        }
    }
}

impl JmapClient {
    /// A client that speaks through the given transport.
    pub fn new(transport: Box<dyn crate::transport::HttpTransport>, policy: EgressPolicy) -> Self {
        Self {
            transport,
            policy,
            resolver: Box::new(SystemResolver),
            credential: None,
            session: None,
            limits: TransportLimits::default(),
            max_redirects: 3,
        }
    }

    /// Use a specific resolver instead of the platform's.
    pub fn with_resolver(mut self, resolver: Box<dyn HostResolver>) -> Self {
        self.resolver = resolver;
        self
    }

    /// Present a credential to the upstream.
    pub fn with_credential(mut self, credential: Credential) -> Self {
        self.credential = Some(credential);
        self
    }

    /// Apply transport limits.
    pub fn with_limits(mut self, limits: TransportLimits) -> Self {
        self.limits = limits;
        self
    }

    /// The session the client discovered.
    pub fn session(&self) -> Option<&Session> {
        self.session.as_ref()
    }

    /// The egress policy in force.
    pub fn policy(&self) -> &EgressPolicy {
        &self.policy
    }

    /// Discover the session.
    ///
    /// The session URL is the one the deployment configured. It is checked
    /// against the egress policy like every other URL, and the host it names
    /// is resolved and checked before the request goes out.
    pub fn discover(&mut self, session_url: &str) -> Result<Session, JmapError> {
        let response = self
            .request("GET", session_url, None, self.limits.max_response_bytes)
            .map_err(|failure| failure.error().clone())?;
        if response.status != 200 {
            return Err(status_error(
                response.status,
                "the session could not be fetched",
            ));
        }
        let value: Value = serde_json::from_slice(&response.body)
            .map_err(|error| JmapError::Protocol(format!("the session is not JSON: {error}")))?;
        let session = Session::parse(&value)?;
        self.session = Some(session.clone());
        Ok(session)
    }

    /// Send a JMAP request to the session's API endpoint.
    pub fn call(&mut self, request: &JmapRequest) -> Result<JmapResponse, JmapError> {
        self.call_dispatched(request)
            .map_err(|failure| failure.error().clone())
    }

    /// Send a JMAP request and report how much is known when it fails.
    ///
    /// A submission needs this: once the request is dispatched, a failure
    /// that carries no definite answer leaves the outcome of the submission
    /// unknown, and repeating such a call can deliver the message twice.
    pub fn call_dispatched(&mut self, request: &JmapRequest) -> Result<JmapResponse, CallFailure> {
        let api_url = self
            .session
            .as_ref()
            .map(Session::api_url)
            .ok_or_else(|| {
                CallFailure::Failed(JmapError::Protocol(
                    "the session was not discovered".to_owned(),
                ))
            })?
            .to_owned();
        self.validate_account_capabilities(request)
            .map_err(CallFailure::Failed)?;
        let body = serde_json::to_vec(&request.to_json()).map_err(|error| {
            CallFailure::Failed(JmapError::Protocol(format!(
                "the request is not JSON: {error}"
            )))
        })?;
        let response = self.request(
            "POST",
            &api_url,
            Some(&body),
            self.limits.max_response_bytes,
        )?;
        if response.status != 200 {
            let error = status_error(response.status, "the request was refused");
            // A server error may have come after the upstream acted on the
            // request. Every other answer is a refusal.
            return Err(match error {
                JmapError::UpstreamUnavailable(_) => CallFailure::Unknown(error),
                _ => CallFailure::Failed(error),
            });
        }
        // A body the client cannot read leaves the outcome unknown: the
        // upstream may have acted on the request and lost the answer.
        JmapResponse::parse(&response.body).map_err(CallFailure::Unknown)
    }

    /// Send one HTTP request, applying the trust rules and following
    /// redirects only within the trusted origin.
    fn request(
        &mut self,
        method: &str,
        url: &str,
        body: Option<&[u8]>,
        max_bytes: u64,
    ) -> Result<HttpResponse, CallFailure> {
        let mut current = self
            .policy
            .check(url)
            .map_err(|error| CallFailure::Failed(JmapError::from(error)))?;
        let mut redirects = 0;
        let mut dispatched = false;
        loop {
            self.check_resolved(&current)
                .map_err(|error| CallFailure::before_dispatch(dispatched, error))?;
            if !self.transport.enforces_address_pinning() {
                return Err(CallFailure::before_dispatch(
                    dispatched,
                    JmapError::Rejected(
                        "transport does not enforce validated DNS address pinning".to_owned(),
                    ),
                ));
            }
            let request = HttpRequest {
                method: method.to_owned(),
                url: current.to_string(),
                headers: self.headers(body.is_some()),
                body: body.unwrap_or_default().to_vec(),
            };
            // The request has left the client: from here on the upstream may
            // have acted on it.
            let response = self
                .transport
                .send(&request)
                .map_err(CallFailure::from_transport)?;
            dispatched = true;
            if (300..400).contains(&response.status) {
                if redirects >= self.max_redirects {
                    return Err(CallFailure::Unknown(JmapError::Rejected(
                        "too many redirects".to_owned(),
                    )));
                }
                let location = response.header("location").ok_or_else(|| {
                    CallFailure::Unknown(JmapError::Rejected("a redirect had no target".to_owned()))
                })?;
                current = self
                    .policy
                    .check_redirect(&current, location)
                    .map_err(|error| CallFailure::Unknown(JmapError::Trust(error)))?;
                redirects += 1;
                continue;
            }
            if response.body.len() as u64 > max_bytes {
                return Err(CallFailure::Unknown(JmapError::TooLarge {
                    limit: max_bytes,
                }));
            }
            return Ok(response);
        }
    }

    /// Download a URL the session pointed at.
    ///
    /// The URL is checked against the egress policy like any other: a
    /// download URL is written by the upstream server and may point
    /// anywhere.
    pub fn download(&mut self, url: &str) -> Result<HttpResponse, JmapError> {
        let response = self
            .request("GET", url, None, self.limits.max_blob_bytes)
            .map_err(|failure| failure.error().clone())?;
        if response.status != 200 {
            return Err(status_error(
                response.status,
                "the download could not be fetched",
            ));
        }
        Ok(response)
    }

    fn validate_account_capabilities(&self, request: &JmapRequest) -> Result<(), JmapError> {
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| JmapError::Protocol("the session was not discovered".to_owned()))?;
        for call in &request.method_calls {
            let account = call
                .arguments
                .get("accountId")
                .and_then(Value::as_str)
                .ok_or_else(|| JmapError::Protocol("JMAP call has no accountId".to_owned()))?;
            let capability = match call.name.as_str() {
                "Mailbox/get" | "Email/query" | "Email/get" | "Email/queryChanges"
                | "Email/changes" => crate::session::MAIL,
                "Identity/get" | "Email/set" | "EmailSubmission/set" => crate::session::SUBMISSION,
                other => return Err(JmapError::CapabilityMissing(other.to_owned())),
            };
            session.select_account(&crate::session::AccountSelector::by_id(account), capability)?;
        }
        Ok(())
    }

    /// The headers every request carries.
    fn headers(&self, has_body: bool) -> Vec<(String, String)> {
        let mut headers = vec![("Accept".to_owned(), "application/json".to_owned())];
        if has_body {
            headers.push(("Content-Type".to_owned(), "application/json".to_owned()));
        }
        if let Some(credential) = &self.credential {
            headers.push(("Authorization".to_owned(), credential.header_value()));
        }
        headers
    }

    /// Resolve the host of a URL and refuse a non-public address.
    fn check_resolved(&self, url: &url::Url) -> Result<(), JmapError> {
        if self.policy.allows_private_networks() {
            return Ok(());
        }
        let Some(host) = url.host_str() else {
            return Err(JmapError::Trust(TrustError::InvalidUrl(url.to_string())));
        };
        let literal_host = host.trim_start_matches('[').trim_end_matches(']');
        if literal_host.parse::<std::net::IpAddr>().is_ok() {
            // A literal address was already checked against the policy.
            return Ok(());
        }
        let addresses = self.resolver.resolve(host)?;
        self.policy
            .check_addresses(host, &addresses)
            .map_err(JmapError::from)
    }
}

/// The error an HTTP status maps to.
fn status_error(status: u16, context: &str) -> JmapError {
    match status {
        401 => JmapError::NeedsAuthorization("the upstream rejected the credential".to_owned()),
        403 => JmapError::Rejected("the upstream refused the operation".to_owned()),
        404 => JmapError::NotFound,
        413 => JmapError::TooLarge {
            limit: crate::transport::TransportLimits::default().max_blob_bytes,
        },
        500..=599 => JmapError::UpstreamUnavailable(context.to_owned()),
        _ => JmapError::Rejected(format!("the upstream answered {status}")),
    }
}
