//! The REST adapter.
//!
//! The adapter maps the seven `/v1` operations of `api/openapi.yaml` onto
//! the service pipeline and renders the results as JSON or as an RFC 9457
//! problem document. It holds no business rule: the identity, the action and
//! the filter decisions all come from the service.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::Value;

use crate::mcp::{JsonRpcError, JsonRpcRequest, McpServer};
use crate::problem::Problem;
use crate::service::{
    Caller, Gateway, GetAttachmentRequest, GetMessageRequest, GetSubmissionRequest, ListRequest,
    SearchRequest, SendOutcome, SendRequest,
};
use crate::view::{SearchRequest as SearchBody, SendRequest as SendBody};

/// The largest attachment the REST adapter returns.
pub const REST_ATTACHMENT_LIMIT: u64 = 8 * 1024 * 1024;

/// The shared state of the adapter.
#[derive(Debug, Clone)]
pub struct AppState {
    /// The service pipeline.
    pub gateway: Gateway,
    /// The MCP adapter, which shares the same pipeline.
    pub mcp: McpServer,
}

/// Build the REST router.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/identities", get(list_identities))
        .route("/v1/messages", get(list_messages))
        .route("/v1/messages/search", post(search_messages))
        .route("/v1/messages/send", post(send_message))
        .route("/v1/messages/{messageId}", get(get_message))
        .route(
            "/v1/messages/{messageId}/attachments/{attachmentId}",
            get(get_attachment),
        )
        .route("/v1/submissions/{submissionId}", get(get_submission))
        .route("/mcp", post(mcp_endpoint))
        .with_state(Arc::new(state))
}

/// The query of a listing.
#[derive(Debug, Deserialize)]
struct ListParams {
    #[serde(rename = "identityId")]
    identity_id: Option<String>,
    limit: Option<u32>,
    cursor: Option<String>,
}

/// The query of a single-resource read.
#[derive(Debug, Deserialize)]
struct IdentityParams {
    #[serde(rename = "identityId")]
    identity_id: Option<String>,
}

/// `GET /v1/identities`.
async fn list_identities(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let caller = match authenticate(&state, &headers) {
        Ok(caller) => caller,
        Err(problem) => return problem_response(problem),
    };
    match state.gateway.list_identities(&caller) {
        Ok(body) => json_response(StatusCode::OK, &body),
        Err(problem) => problem_response(problem),
    }
}

/// `GET /v1/messages`.
async fn list_messages(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<ListParams>,
) -> Response {
    let caller = match authenticate(&state, &headers) {
        Ok(caller) => caller,
        Err(problem) => return problem_response(problem),
    };
    let Some(identity_id) = params.identity_id else {
        return problem_response(Problem::invalid_input("identityId is required"));
    };
    let identity = match parse_identity(&identity_id) {
        Ok(identity) => identity,
        Err(problem) => return problem_response(problem),
    };
    match state.gateway.list_messages(
        &caller,
        &ListRequest {
            identity,
            limit: params.limit.unwrap_or(crate::service::DEFAULT_LIMIT),
            cursor: params.cursor,
        },
    ) {
        Ok(body) => json_response(StatusCode::OK, &body),
        Err(problem) => problem_response(problem),
    }
}

/// `POST /v1/messages/search`.
async fn search_messages(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<SearchBody>,
) -> Response {
    let caller = match authenticate(&state, &headers) {
        Ok(caller) => caller,
        Err(problem) => return problem_response(problem),
    };
    let identity = match parse_identity(&body.identity_id) {
        Ok(identity) => identity,
        Err(problem) => return problem_response(problem),
    };
    match state.gateway.search_messages(
        &caller,
        &SearchRequest {
            identity,
            query: body.query,
            limit: body.limit.unwrap_or(crate::service::DEFAULT_LIMIT),
            cursor: body.cursor,
        },
    ) {
        Ok(body) => json_response(StatusCode::OK, &body),
        Err(problem) => problem_response(problem),
    }
}

/// `POST /v1/messages/send`.
async fn send_message(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<SendBody>,
) -> Response {
    let caller = match authenticate(&state, &headers) {
        Ok(caller) => caller,
        Err(problem) => return problem_response(problem),
    };
    let Some(idempotency_key) = header_value(&headers, "idempotency-key") else {
        return problem_response(Problem::invalid_input(
            "the Idempotency-Key header is required",
        ));
    };
    let identity = match parse_identity(&body.identity_id) {
        Ok(identity) => identity,
        Err(problem) => return problem_response(problem),
    };
    let request = SendRequest {
        identity,
        to: body.to,
        cc: body.cc,
        bcc: body.bcc,
        subject: body.subject,
        text_body: body.text_body,
        idempotency_key,
        approval_required: false,
        approval: None,
    };
    match state.gateway.send_message(&caller, &request) {
        Ok(SendOutcome::Submitted {
            submission,
            replayed,
        }) => {
            let status = if replayed {
                StatusCode::OK
            } else {
                StatusCode::ACCEPTED
            };
            json_response(status, &submission)
        }
        Ok(SendOutcome::ApprovalRequired(_)) => problem_response(Problem::confirmation_required()),
        Err(problem) => problem_response(problem),
    }
}

/// `GET /v1/messages/{messageId}`.
async fn get_message(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(message_id): Path<String>,
    Query(params): Query<IdentityParams>,
) -> Response {
    let caller = match authenticate(&state, &headers) {
        Ok(caller) => caller,
        Err(problem) => return problem_response(problem),
    };
    let Some(identity_id) = params.identity_id else {
        return problem_response(Problem::invalid_input("identityId is required"));
    };
    let identity = match parse_identity(&identity_id) {
        Ok(identity) => identity,
        Err(problem) => return problem_response(problem),
    };
    match state.gateway.get_message(
        &caller,
        &GetMessageRequest {
            identity,
            message_id,
        },
    ) {
        Ok(body) => json_response(StatusCode::OK, &body),
        Err(problem) => problem_response(problem),
    }
}

/// `GET /v1/messages/{messageId}/attachments/{attachmentId}`.
async fn get_attachment(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((message_id, attachment_id)): Path<(String, String)>,
    Query(params): Query<IdentityParams>,
) -> Response {
    let caller = match authenticate(&state, &headers) {
        Ok(caller) => caller,
        Err(problem) => return problem_response(problem),
    };
    let Some(identity_id) = params.identity_id else {
        return problem_response(Problem::invalid_input("identityId is required"));
    };
    let identity = match parse_identity(&identity_id) {
        Ok(identity) => identity,
        Err(problem) => return problem_response(problem),
    };
    match state.gateway.get_attachment(
        &caller,
        &GetAttachmentRequest {
            identity,
            message_id,
            attachment_id,
        },
        REST_ATTACHMENT_LIMIT,
    ) {
        Ok(payload) => {
            let filename = sanitize_filename(&payload.descriptor.file_name);
            let mut response = (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/octet-stream".to_owned())],
                payload.bytes,
            )
                .into_response();
            if let Ok(value) =
                header::HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
            {
                response
                    .headers_mut()
                    .insert(header::CONTENT_DISPOSITION, value);
            }
            response.headers_mut().insert(
                header::CACHE_CONTROL,
                header::HeaderValue::from_static("private, no-store"),
            );
            response
        }
        Err(problem) => problem_response(problem),
    }
}

/// `GET /v1/submissions/{submissionId}`.
async fn get_submission(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(submission_id): Path<String>,
    Query(params): Query<IdentityParams>,
) -> Response {
    let caller = match authenticate(&state, &headers) {
        Ok(caller) => caller,
        Err(problem) => return problem_response(problem),
    };
    let Some(identity_id) = params.identity_id else {
        return problem_response(Problem::invalid_input("identityId is required"));
    };
    let identity = match parse_identity(&identity_id) {
        Ok(identity) => identity,
        Err(problem) => return problem_response(problem),
    };
    match state.gateway.get_submission(
        &caller,
        &GetSubmissionRequest {
            identity,
            submission_id,
        },
    ) {
        Ok(body) => json_response(StatusCode::OK, &body),
        Err(problem) => problem_response(problem),
    }
}

/// `POST /mcp`.
async fn mcp_endpoint(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let caller = match authenticate(&state, &headers) {
        Ok(caller) => caller,
        Err(problem) => return problem_response(problem),
    };
    let protocol_version = header_value(&headers, "mcp-protocol-version");
    let document: Value = match serde_json::from_slice(&body) {
        Ok(document) => document,
        Err(_) => {
            return protocol_error(
                None,
                JsonRpcError::invalid_params("the request body is not valid JSON"),
            );
        }
    };
    let request = match JsonRpcRequest::parse(&document, protocol_version) {
        Ok(request) => request,
        Err(error) => return protocol_error(None, error),
    };
    if let Some(declared) = header_value(&headers, "mcp-method") {
        if declared != request.method {
            return protocol_error(
                request.id.clone(),
                JsonRpcError::invalid_params("the Mcp-Method header does not match the body"),
            );
        }
    }
    if request.method == "tools/call" {
        let name = request
            .params
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if let Some(declared) = header_value(&headers, "mcp-name") {
            if declared != name {
                return protocol_error(
                    request.id.clone(),
                    JsonRpcError::invalid_params("the Mcp-Name header does not match the body"),
                );
            }
        }
    }
    let response = state.mcp.handle(&caller, &request);
    let status = if response.error.is_some() {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::OK
    };
    let mut http = (status, Json(response.to_json())).into_response();
    http.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("private, no-store"),
    );
    http
}

/// Authenticate the bearer credential of a request.
fn authenticate(state: &AppState, headers: &HeaderMap) -> Result<Caller, Problem> {
    let Some(token) = bearer_token(headers) else {
        return Err(Problem::unauthorized());
    };
    state
        .gateway
        .authenticate(token)
        .map_err(|_| Problem::unauthorized())
}

/// The bearer credential of a request.
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    if token.is_empty() { None } else { Some(token) }
}

/// A header value, lowercased.
fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

/// A successful JSON response.
fn json_response<T: serde::Serialize>(status: StatusCode, body: &T) -> Response {
    let mut response = (status, Json(body)).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("private, no-store"),
    );
    response
}

/// A problem response.
fn problem_response(problem: Problem) -> Response {
    let status = StatusCode::from_u16(problem.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let unauthenticated = status == StatusCode::UNAUTHORIZED;
    let mut response = (status, Json(problem)).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/problem+json"),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("private, no-store"),
    );
    if unauthenticated {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            header::HeaderValue::from_static("Bearer"),
        );
    }
    response
}

/// A protocol-level JSON-RPC error.
fn protocol_error(id: Option<Value>, error: JsonRpcError) -> Response {
    let response = crate::mcp::JsonRpcResponse::error(id, error);
    let mut http = (StatusCode::BAD_REQUEST, Json(response.to_json())).into_response();
    http.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("private, no-store"),
    );
    http
}

/// Parse an identity identifier.
fn parse_identity(value: &str) -> Result<mail_core::IdentityId, Problem> {
    use std::str::FromStr;
    mail_core::IdentityId::from_str(value)
        .map_err(|_| Problem::invalid_input("the identity id is invalid"))
}

/// Make a filename safe for a header.
fn sanitize_filename(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .filter(|character| !character.is_control() && *character != '"' && *character != '\\')
        .take(255)
        .collect();
    if cleaned.trim().is_empty() {
        "attachment".to_owned()
    } else {
        cleaned
    }
}
