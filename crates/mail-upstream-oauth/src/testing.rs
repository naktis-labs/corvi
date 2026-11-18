//! A fixture transport and the other test doubles of this crate.
//!
//! The transport is the seam that keeps the protocol logic testable without
//! a provider: a test tells the fixture what the provider answers, and then
//! asserts on the requests the flow made. The same seam is what a real
//! HTTPS transport will implement later, in the layer that owns TLS.
//!
//! This module is public on purpose. A future crate that drives the
//! onboarding flow — an admin API, a CLI — needs the same fixture, and
//! copying it would be worse than sharing it.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use crate::onboarding::ClientSecretResolver;
use crate::transport::{HttpMethod, OAuthRequest, OAuthResponse, OAuthTransport, TransportFailure};

/// One canned answer.
#[derive(Debug, Clone)]
struct Route {
    method: HttpMethod,
    url_needle: String,
    form_needle: Option<String>,
    answer: Result<OAuthResponse, TransportFailure>,
}

/// A transport that answers from a table of routes.
#[derive(Debug, Clone, Default)]
pub struct FixtureTransport {
    routes: Vec<Route>,
    log: Arc<Mutex<Vec<OAuthRequest>>>,
}

impl FixtureTransport {
    /// A transport that answers nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// Answer a request whose method and URL contain the given fragments.
    ///
    /// Routes are matched newest first, so a route added later replaces
    /// what the provider answered before.
    pub fn route(mut self, method: HttpMethod, url_needle: &str, response: OAuthResponse) -> Self {
        self.routes.insert(
            0,
            Route {
                method,
                url_needle: url_needle.to_owned(),
                form_needle: None,
                answer: Ok(response),
            },
        );
        self
    }

    /// Answer a request whose form contains the given fragment.
    pub fn route_form(
        mut self,
        method: HttpMethod,
        url_needle: &str,
        form_needle: &str,
        response: OAuthResponse,
    ) -> Self {
        self.routes.insert(
            0,
            Route {
                method,
                url_needle: url_needle.to_owned(),
                form_needle: Some(form_needle.to_owned()),
                answer: Ok(response),
            },
        );
        self
    }

    /// Fail a request whose method and URL contain the given fragments.
    pub fn route_failure(
        mut self,
        method: HttpMethod,
        url_needle: &str,
        failure: TransportFailure,
    ) -> Self {
        self.routes.insert(
            0,
            Route {
                method,
                url_needle: url_needle.to_owned(),
                form_needle: None,
                answer: Err(failure),
            },
        );
        self
    }

    /// The requests the transport was given.
    pub fn requests(&self) -> Vec<OAuthRequest> {
        self.log
            .lock()
            .map(|log| log.clone())
            .unwrap_or_else(|_| Vec::new())
    }

    /// How many requests the transport was given.
    pub fn request_count(&self) -> usize {
        self.log.lock().map(|log| log.len()).unwrap_or_default()
    }

    /// Forget the recorded requests.
    pub fn clear(&self) {
        if let Ok(mut log) = self.log.lock() {
            log.clear();
        }
    }
}

impl OAuthTransport for FixtureTransport {
    fn send(&self, request: &OAuthRequest) -> Result<OAuthResponse, TransportFailure> {
        if let Ok(mut log) = self.log.lock() {
            log.push(request.clone());
        }
        let body = request
            .form
            .iter()
            .fold(String::new(), |mut text, (name, value)| {
                if !text.is_empty() {
                    text.push('&');
                }
                text.push_str(name);
                text.push('=');
                text.push_str(value);
                text
            });
        for route in &self.routes {
            if route.method != request.method || !request.url.contains(&route.url_needle) {
                continue;
            }
            if let Some(needle) = &route.form_needle
                && !body.contains(needle.as_str())
            {
                continue;
            }
            return route.answer.clone();
        }
        Err(TransportFailure::new(format!(
            "the fixture transport has no route for {} {}",
            request.method.as_str(),
            request.url
        )))
    }
}

/// A token response body, as a provider would send it.
pub fn token_response(
    access_token: &str,
    refresh_token: Option<&str>,
    expires_in: Option<u64>,
    scope: Option<&str>,
) -> serde_json::Value {
    let mut body = serde_json::json!({
        "access_token": access_token,
        "token_type": "Bearer",
    });
    if let Some(refresh_token) = refresh_token {
        body["refresh_token"] = serde_json::Value::String(refresh_token.to_owned());
    }
    if let Some(expires_in) = expires_in {
        body["expires_in"] = serde_json::Value::from(expires_in);
    }
    if let Some(scope) = scope {
        body["scope"] = serde_json::Value::String(scope.to_owned());
    }
    body
}

/// An OAuth error response body.
pub fn error_response(error: &str) -> serde_json::Value {
    serde_json::json!({ "error": error })
}

/// A client secret resolver that answers from a table.
#[derive(Debug, Clone, Default)]
pub struct MapClientSecrets {
    secrets: BTreeMap<String, String>,
}

impl MapClientSecrets {
    /// A resolver without secrets.
    pub fn new() -> Self {
        Self::default()
    }

    /// Answer one reference with one secret.
    pub fn with(mut self, reference: &str, secret: &str) -> Self {
        self.secrets.insert(reference.to_owned(), secret.to_owned());
        self
    }
}

impl ClientSecretResolver for MapClientSecrets {
    fn resolve(&self, reference: &str) -> Result<String, crate::error::UpstreamOAuthError> {
        self.secrets.get(reference).cloned().ok_or_else(|| {
            crate::error::UpstreamOAuthError::InvalidRequest {
                reason: "the client secret reference is not configured".to_owned(),
            }
        })
    }
}
