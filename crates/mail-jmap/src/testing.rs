//! A fixture transport for the JMAP client.
//!
//! The transport is the seam that keeps the protocol logic testable without
//! a provider: a test tells the fixture what the upstream answers, and then
//! asserts on the requests the client made. The same seam is what a real
//! HTTPS transport will implement later.
//!
//! A route matches on the method, on a fragment of the URL and optionally on
//! a fragment of the request body. Matching on the body is what makes it
//! possible to answer the several method calls that share one JMAP API
//! endpoint differently.

use std::sync::{Arc, Mutex};

use serde_json::Value;

use mail_core::TransportError;

use crate::transport::{HttpRequest, HttpResponse, HttpTransport};

/// One canned answer.
#[derive(Debug, Clone)]
struct Route {
    method: String,
    url_needle: String,
    body_needle: Option<String>,
    answer: Result<HttpResponse, TransportError>,
}

/// A transport that answers from a table of routes.
#[derive(Debug, Clone, Default)]
pub struct FixtureTransport {
    routes: Vec<Route>,
    log: Arc<Mutex<Vec<HttpRequest>>>,
}

impl FixtureTransport {
    /// A transport that answers nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// A handle on the requests the client made.
    ///
    /// The handle stays valid after the transport has been handed to a
    /// client, so a test can assert on what the client did.
    pub fn log(&self) -> Arc<Mutex<Vec<HttpRequest>>> {
        Arc::clone(&self.log)
    }

    /// The requests the client made so far.
    pub fn requests(&self) -> Vec<HttpRequest> {
        self.log.lock().map(|log| log.clone()).unwrap_or_default()
    }

    /// Answer a `GET` whose URL contains the given text.
    pub fn on_get(self, needle: &str, body: Value) -> Self {
        self.on_body("GET", needle, None, HttpResponse::json(200, &body))
    }

    /// Answer a `POST` whose URL contains the given text.
    pub fn on_post(self, needle: &str, body: Value) -> Self {
        self.on_body("POST", needle, None, HttpResponse::json(200, &body))
    }

    /// Answer a `POST` whose URL and body contain the given text.
    pub fn on_post_body(self, url_needle: &str, body_needle: &str, body: Value) -> Self {
        self.on_body(
            "POST",
            url_needle,
            Some(body_needle.to_owned()),
            HttpResponse::json(200, &body),
        )
    }

    /// Answer with a specific response.
    pub fn on(self, method: &str, needle: &str, response: HttpResponse) -> Self {
        self.on_body(method, needle, None, response)
    }

    /// Answer a request whose body contains the given text.
    pub fn on_body(
        self,
        method: &str,
        needle: &str,
        body_needle: Option<String>,
        response: HttpResponse,
    ) -> Self {
        let mut routes = self.routes;
        routes.push(Route {
            method: method.to_owned(),
            url_needle: needle.to_owned(),
            body_needle,
            answer: Ok(response),
        });
        Self {
            routes,
            log: self.log,
        }
    }

    /// Fail with a transport error.
    pub fn failing(self, method: &str, needle: &str, error: TransportError) -> Self {
        self.failing_body(method, needle, None, error)
    }

    /// Fail with a transport error when the body contains the given text.
    pub fn failing_body(
        self,
        method: &str,
        needle: &str,
        body_needle: Option<String>,
        error: TransportError,
    ) -> Self {
        let mut routes = self.routes;
        routes.push(Route {
            method: method.to_owned(),
            url_needle: needle.to_owned(),
            body_needle,
            answer: Err(error),
        });
        Self {
            routes,
            log: self.log,
        }
    }
}

impl HttpTransport for FixtureTransport {
    fn send(&mut self, request: &HttpRequest) -> Result<HttpResponse, TransportError> {
        if let Ok(mut log) = self.log.lock() {
            log.push(request.clone());
        }
        let body = String::from_utf8_lossy(&request.body).to_string();
        for route in &self.routes {
            if !route.method.eq_ignore_ascii_case(&request.method) {
                continue;
            }
            if !request.url.contains(&route.url_needle) {
                continue;
            }
            if let Some(needle) = &route.body_needle
                && !body.contains(needle)
            {
                continue;
            }
            return route.answer.clone();
        }
        Ok(HttpResponse {
            status: 404,
            headers: Vec::new(),
            body: b"no route matched".to_vec(),
        })
    }
}
