//! Shared fixtures for the gateway tests.

#![allow(dead_code)]

use std::path::Path;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use http_body_util::BodyExt;
use mail_api::mcp::McpServer;
use mail_api::rest::{AppState, router};
use mail_api::testing::{
    DEFAULT_FIXTURE, HIDING_POLICIES, PERMISSIVE_POLICIES, TestDirectory, TestEnvironment,
};
use serde_json::Value;
use tower::ServiceExt;

/// Every action the vocabulary declares.
pub const ALL_ACTIONS: &str = "          - mail:identities:list\n          - mail:messages:list\n          - mail:messages:read\n          - mail:messages:search\n          - mail:attachments:read\n          - mail:messages:send\n          - mail:submissions:read\n          - mail:messages:subscribe\n";

/// The actions a reader holds, without the attachment action.
pub const READ_ACTIONS: &str = "          - mail:identities:list\n          - mail:messages:list\n          - mail:messages:read\n          - mail:messages:search\n          - mail:submissions:read\n";

/// The actions a lister holds.
pub const LIST_ACTIONS: &str = "          - mail:identities:list\n          - mail:messages:list\n          - mail:messages:search\n";

/// A gateway with one identity and one credential.
pub fn environment(name: &str, grants: &str) -> TestEnvironment {
    TestEnvironment::build(name, grants, PERMISSIVE_POLICIES, DEFAULT_FIXTURE, None)
}

/// A gateway whose policy hides a message.
pub fn hiding_environment(name: &str, grants: &str) -> TestEnvironment {
    TestEnvironment::build(name, grants, HIDING_POLICIES, DEFAULT_FIXTURE, None)
}

/// A gateway with two identities and one credential that holds grants on both.
pub fn two_identity_environment(
    name: &str,
    personal_actions: &str,
    work_actions: &str,
) -> TestEnvironment {
    let directory = TestDirectory::new(name);
    let secret = directory.write_secret("agent.token", "test-token");
    let yaml = two_identity_snapshot(&secret, personal_actions, work_actions);
    TestEnvironment::from_documents(directory, &yaml, PERMISSIVE_POLICIES, DEFAULT_FIXTURE, None)
}

/// A snapshot document with two identities and two grants.
pub fn two_identity_snapshot(secret: &Path, personal_actions: &str, work_actions: &str) -> String {
    format!(
        "generation: 1\n\
         listen: \"127.0.0.1:0\"\n\
         allow_loopback_plaintext: true\n\
         identities:\n  \
         - id: personal\n    \
         mailbox: INBOX\n    \
         address: me@example.com\n    \
         display_name: Me\n    \
         isolation: verified\n  \
         - id: work\n    \
         mailbox: WORK\n    \
         address: me@work.example\n    \
         isolation: dedicated\n\
         credentials:\n  \
         - id: agent\n    \
         token:\n      \
         secret: \"file://{secret}\"\n    \
         grants:\n      \
         - identity: personal\n        \
         actions:\n{personal_actions}      \
         - identity: work\n        \
         actions:\n{work_actions}",
        secret = secret.display()
    )
}

/// The REST router of an environment.
pub fn app(env: &TestEnvironment) -> Router {
    router(AppState {
        gateway: env.gateway.clone(),
        mcp: McpServer::new(env.gateway.clone()),
    })
}

/// The outcome of one REST request.
pub struct RestResponse {
    /// The status code.
    pub status: StatusCode,
    /// The headers.
    pub headers: HeaderMap,
    /// The body, parsed as JSON.
    pub body: Value,
}

/// Send one request to the router.
pub async fn send(
    app: &Router,
    method: Method,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
    headers: &[(&str, &str)],
) -> RestResponse {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let body = match body {
        Some(value) => {
            builder = builder.header("content-type", "application/json");
            Body::from(serde_json::to_vec(&value).expect("the body is JSON"))
        }
        None => Body::empty(),
    };
    let request = builder.body(body).expect("the request is well formed");
    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("the router answers");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("the body is collected")
        .to_bytes();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    RestResponse {
        status,
        headers,
        body,
    }
}

/// Send one GET request.
pub async fn get(app: &Router, uri: &str, token: Option<&str>) -> RestResponse {
    send(app, Method::GET, uri, token, None, &[]).await
}

/// Send one POST request.
pub async fn post(
    app: &Router,
    uri: &str,
    token: Option<&str>,
    body: Value,
    headers: &[(&str, &str)],
) -> RestResponse {
    send(app, Method::POST, uri, token, Some(body), headers).await
}
