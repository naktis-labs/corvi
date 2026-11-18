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
#[derive(Clone, Default)]
pub struct MapClientSecrets {
    secrets: BTreeMap<String, String>,
}

impl std::fmt::Debug for MapClientSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MapClientSecrets")
            .field(
                "secrets",
                &format_args!("[{} redacted]", self.secrets.len()),
            )
            .finish()
    }
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

#[cfg(test)]
mod debug_redaction {
    use super::*;

    #[test]
    fn the_map_client_secrets_fixture_prints_no_secret() {
        let resolver = MapClientSecrets::new().with(
            "secret://provider/client-secret",
            "the-client-secret-SECRET",
        );
        let printed = format!("{resolver:?}");
        assert!(
            !printed.contains("the-client-secret-SECRET"),
            "a fixture that prints its secrets teaches the pattern: {printed}"
        );
    }
}

/// A secret store whose writes fail, for the delivery failure windows.
#[derive(Debug, Default)]
pub struct FailingSecretStore;

impl mail_storage::SecretStore for FailingSecretStore {
    fn put(
        &self,
        _owner: &str,
        _name: &str,
        _plaintext: &[u8],
        _aad: &mail_storage::SecretAad,
    ) -> mail_storage::StorageResult<mail_storage::SecretRef> {
        Err(mail_storage::StorageError::Backend(
            "the secret store is down".to_owned(),
        ))
    }

    fn get(
        &self,
        _reference: &mail_storage::SecretRef,
        _aad: &mail_storage::SecretAad,
    ) -> mail_storage::StorageResult<Option<Vec<u8>>> {
        Err(mail_storage::StorageError::Backend(
            "the secret store is down".to_owned(),
        ))
    }

    fn rotate(
        &self,
        _reference: &mail_storage::SecretRef,
        _plaintext: &[u8],
        _aad: &mail_storage::SecretAad,
    ) -> mail_storage::StorageResult<mail_storage::SecretRef> {
        Err(mail_storage::StorageError::Backend(
            "the secret store is down".to_owned(),
        ))
    }

    fn delete(&self, _reference: &mail_storage::SecretRef) -> mail_storage::StorageResult<bool> {
        Err(mail_storage::StorageError::Backend(
            "the secret store is down".to_owned(),
        ))
    }

    fn list(&self, _owner: &str) -> mail_storage::StorageResult<Vec<mail_storage::SecretRef>> {
        Err(mail_storage::StorageError::Backend(
            "the secret store is down".to_owned(),
        ))
    }
}

/// A connection store whose refresh-state write fails, for the delivery
/// failure window between the two writes of a delivery: the connection is
/// announced Active before the state that makes it usable exists.
pub struct FailingConnectionStore {
    inner: Arc<dyn mail_storage::ProviderConnectionStore + Send + Sync>,
}

impl std::fmt::Debug for FailingConnectionStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FailingConnectionStore")
            .finish_non_exhaustive()
    }
}

impl FailingConnectionStore {
    /// A store that delegates everything but the refresh-state write.
    pub fn new(inner: Arc<dyn mail_storage::ProviderConnectionStore + Send + Sync>) -> Self {
        Self { inner }
    }
}
impl mail_storage::ProviderConnectionStore for FailingConnectionStore {
    fn put_connection(
        &self,
        connection: &mail_storage::ProviderConnection,
    ) -> mail_storage::StorageResult<()> {
        self.inner.put_connection(connection)
    }

    fn get_connection(
        &self,
        connection_id: &str,
    ) -> mail_storage::StorageResult<Option<mail_storage::ProviderConnection>> {
        self.inner.get_connection(connection_id)
    }

    fn list_connections(
        &self,
        identity: &str,
    ) -> mail_storage::StorageResult<Vec<mail_storage::ProviderConnection>> {
        self.inner.list_connections(identity)
    }

    fn put_refresh_state(
        &self,
        _state: &mail_storage::RefreshState,
    ) -> mail_storage::StorageResult<()> {
        Err(mail_storage::StorageError::Backend(
            "the refresh state cannot be written".to_owned(),
        ))
    }

    fn get_refresh_state(
        &self,
        connection_id: &str,
    ) -> mail_storage::StorageResult<Option<mail_storage::RefreshState>> {
        self.inner.get_refresh_state(connection_id)
    }

    fn claim_refresh(
        &self,
        connection_id: &str,
        generation: u64,
        owner: &str,
    ) -> mail_storage::StorageResult<bool> {
        self.inner.claim_refresh(connection_id, generation, owner)
    }

    fn claim_refresh_at(
        &self,
        connection_id: &str,
        generation: u64,
        owner: &str,
        now: u64,
        ttl: u64,
    ) -> mail_storage::StorageResult<bool> {
        self.inner
            .claim_refresh_at(connection_id, generation, owner, now, ttl)
    }

    fn complete_refresh(
        &self,
        connection_id: &str,
        generation: u64,
        owner: &str,
        secret_ref: &str,
        expires_at: u64,
        now: u64,
    ) -> mail_storage::StorageResult<bool> {
        self.inner.complete_refresh(
            connection_id,
            generation,
            owner,
            secret_ref,
            expires_at,
            now,
        )
    }

    fn mark_needs_reauthorization(
        &self,
        connection_id: &str,
        now: u64,
    ) -> mail_storage::StorageResult<bool> {
        self.inner.mark_needs_reauthorization(connection_id, now)
    }

    fn disconnect(&self, connection_id: &str, now: u64) -> mail_storage::StorageResult<bool> {
        self.inner.disconnect(connection_id, now)
    }
}
