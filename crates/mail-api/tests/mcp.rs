//! The MCP surface: tools, resources, approval and error mapping.

mod common;

use common::{ALL_ACTIONS, LIST_ACTIONS, app, environment, post};
use mail_api::fixture::SubmissionBehavior;
use mail_api::mcp::{JsonRpcRequest, JsonRpcResponse, MCP_PROTOCOL_VERSION, McpServer};
use mail_api::service::Caller;
use serde_json::{Value, json};

/// Build a request the way a modern MCP client sends one.
fn request(id: u64, method: &str, params: Value) -> JsonRpcRequest {
    JsonRpcRequest {
        id: Some(json!(id)),
        method: method.to_owned(),
        params,
        protocol_version: Some(MCP_PROTOCOL_VERSION.to_owned()),
        client_capabilities: json!({"elicitation": {}}),
    }
}

/// The result of a tool call.
fn tool_result(response: &JsonRpcResponse) -> &Value {
    response
        .result
        .as_ref()
        .expect("the call returned a result")
        .get("structuredContent")
        .expect("the result carries structured content")
}

/// The error code of a failed tool call.
fn tool_error_code(response: &JsonRpcResponse) -> String {
    response
        .result
        .as_ref()
        .expect("the call returned a result")
        .get("structuredContent")
        .and_then(|content| content.get("code"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// The arguments of a send.
fn send_arguments(idempotency_key: &str) -> Value {
    json!({
        "identityId": "personal",
        "to": [{"email": "someone@example.org"}],
        "subject": "Hello",
        "textBody": "A body.",
        "idempotencyKey": idempotency_key,
    })
}

#[test]
fn the_tool_list_is_exactly_the_checked_in_catalogue() {
    let env = environment("mcp-tools", ALL_ACTIONS);
    let server = McpServer::new(env.gateway.clone());
    let caller = env.caller();

    let response = server.handle(
        &caller,
        &request(
            1,
            "tools/list",
            json!({"_meta": {"io.modelcontextprotocol/clientCapabilities": {}}}),
        ),
    );
    let result = response.result.expect("the listing succeeds");
    let tools = result["tools"].as_array().expect("the tools are listed");

    let catalogue = mail_api::mcp::ToolCatalogue::load();
    assert_eq!(tools.len(), catalogue.tools().len());
    for tool in catalogue.tools() {
        let served = tools
            .iter()
            .find(|served| served["name"] == tool.name)
            .unwrap_or_else(|| panic!("the tool {} is served", tool.name));
        assert_eq!(served["inputSchema"], tool.input_schema);
        assert_eq!(served["outputSchema"], tool.output_schema);
        assert_eq!(served["annotations"], tool.annotations);
        assert_eq!(served["_meta"], tool.meta);
    }
    assert_eq!(result["ttlMs"], 0);
    assert_eq!(result["cacheScope"], "private");
}

#[test]
fn the_tool_list_only_shows_the_tools_the_caller_may_use() {
    let env = environment("mcp-tools-filtered", LIST_ACTIONS);
    let server = McpServer::new(env.gateway.clone());
    let caller = env.caller();

    let response = server.handle(&caller, &request(1, "tools/list", json!({})));
    let tools = response.result.expect("the listing succeeds")["tools"]
        .as_array()
        .expect("the tools are listed")
        .clone();

    let names: Vec<String> = tools
        .iter()
        .map(|tool| tool["name"].as_str().unwrap_or_default().to_owned())
        .collect();
    assert!(names.contains(&"mail_list".to_owned()));
    assert!(names.contains(&"mail_search".to_owned()));
    assert!(!names.contains(&"mail_get".to_owned()));
    assert!(!names.contains(&"mail_send".to_owned()));
}

#[test]
fn a_send_needs_an_approval_and_sends_nothing_before_it() {
    let env = environment("mcp-approval", ALL_ACTIONS);
    let server = McpServer::new(env.gateway.clone());
    let caller = env.caller();

    let response = server.handle(
        &caller,
        &request(
            1,
            "tools/call",
            json!({"name": "mail_send", "arguments": send_arguments("key-1")}),
        ),
    );
    let result = response.result.expect("the call returned a result");
    assert_eq!(result["resultType"], "input_required");
    assert_eq!(
        result["inputRequests"]["confirm_send"]["method"],
        "elicitation/create"
    );
    assert_eq!(
        result["inputRequests"]["confirm_send"]["params"]["mode"],
        "form"
    );
    assert!(result["requestState"].is_string());
    assert!(env.upstream.submissions().is_empty());
}

#[test]
fn an_approved_send_reaches_the_upstream() {
    let env = environment("mcp-approved", ALL_ACTIONS);
    let server = McpServer::new(env.gateway.clone());
    let caller = env.caller();

    let first = server.handle(
        &caller,
        &request(
            1,
            "tools/call",
            json!({"name": "mail_send", "arguments": send_arguments("key-1")}),
        ),
    );
    let state = first.result.expect("the call returned a result")["requestState"]
        .as_str()
        .expect("the state is a string")
        .to_owned();

    let second = server.handle(
        &caller,
        &request(
            2,
            "tools/call",
            json!({
                "name": "mail_send",
                "arguments": send_arguments("key-1"),
                "inputResponses": {"confirm_send": {"approved": true}},
                "requestState": state,
            }),
        ),
    );
    let result = second.result.as_ref().expect("the call returned a result");
    assert_eq!(result["resultType"], "complete");
    assert_eq!(result["isError"], false);
    assert_eq!(tool_result(&second)["status"], "submitted");

    let submissions = env.upstream.submissions();
    assert_eq!(submissions.len(), 1);
    assert_eq!(submissions[0].sender, "me@example.com");
}

#[test]
fn a_declined_approval_sends_nothing() {
    let env = environment("mcp-declined", ALL_ACTIONS);
    let server = McpServer::new(env.gateway.clone());
    let caller = env.caller();

    let first = server.handle(
        &caller,
        &request(
            1,
            "tools/call",
            json!({"name": "mail_send", "arguments": send_arguments("key-1")}),
        ),
    );
    let state = first.result.expect("the call returned a result")["requestState"]
        .as_str()
        .expect("the state is a string")
        .to_owned();

    let second = server.handle(
        &caller,
        &request(
            2,
            "tools/call",
            json!({
                "name": "mail_send",
                "arguments": send_arguments("key-1"),
                "inputResponses": {"confirm_send": {"approved": false}},
                "requestState": state,
            }),
        ),
    );
    assert_eq!(second.result.as_ref().expect("a result")["isError"], true);
    assert!(env.upstream.submissions().is_empty());
}

#[test]
fn an_approval_cannot_be_used_for_a_second_send() {
    let env = environment("mcp-replay", ALL_ACTIONS);
    let server = McpServer::new(env.gateway.clone());
    let caller = env.caller();

    let first = server.handle(
        &caller,
        &request(
            1,
            "tools/call",
            json!({"name": "mail_send", "arguments": send_arguments("key-1")}),
        ),
    );
    let state = first.result.expect("the call returned a result")["requestState"]
        .as_str()
        .expect("the state is a string")
        .to_owned();

    let approved = json!({
        "name": "mail_send",
        "arguments": send_arguments("key-1"),
        "inputResponses": {"confirm_send": {"approved": true}},
        "requestState": state.clone(),
    });
    let sent = server.handle(&caller, &request(2, "tools/call", approved.clone()));
    let submission_id = tool_result(&sent)["id"].clone();
    assert_eq!(env.upstream.submissions().len(), 1);

    // The same approval replays the submission it produced rather than
    // sending again.
    let replay = server.handle(&caller, &request(3, "tools/call", approved));
    assert_eq!(tool_result(&replay)["id"], submission_id);
    assert_eq!(env.upstream.submissions().len(), 1);

    // The same approval cannot approve another message.
    let other = server.handle(
        &caller,
        &request(
            4,
            "tools/call",
            json!({
                "name": "mail_send",
                "arguments": send_arguments("key-2"),
                "inputResponses": {"confirm_send": {"approved": true}},
                "requestState": state,
            }),
        ),
    );
    assert_eq!(other.result.as_ref().expect("a result")["isError"], true);
    assert_eq!(tool_error_code(&other), "INVALID_INPUT");
    assert_eq!(env.upstream.submissions().len(), 1);
}

#[test]
fn a_tampered_approval_is_refused() {
    let env = environment("mcp-tampered", ALL_ACTIONS);
    let server = McpServer::new(env.gateway.clone());
    let caller = env.caller();

    let first = server.handle(
        &caller,
        &request(
            1,
            "tools/call",
            json!({"name": "mail_send", "arguments": send_arguments("key-1")}),
        ),
    );
    let state = first.result.expect("the call returned a result")["requestState"]
        .as_str()
        .expect("the state is a string")
        .to_owned();

    let tampered = server.handle(
        &caller,
        &request(
            2,
            "tools/call",
            json!({
                "name": "mail_send",
                "arguments": send_arguments("key-1"),
                "inputResponses": {"confirm_send": {"approved": true}},
                "requestState": format!("{state}x"),
            }),
        ),
    );
    assert_eq!(tampered.result.as_ref().expect("a result")["isError"], true);
    assert!(env.upstream.submissions().is_empty());
}

#[test]
fn an_approval_for_another_message_is_refused() {
    let env = environment("mcp-other-payload", ALL_ACTIONS);
    let server = McpServer::new(env.gateway.clone());
    let caller = env.caller();

    let first = server.handle(
        &caller,
        &request(
            1,
            "tools/call",
            json!({"name": "mail_send", "arguments": send_arguments("key-1")}),
        ),
    );
    let state = first.result.expect("the call returned a result")["requestState"]
        .as_str()
        .expect("the state is a string")
        .to_owned();

    let other = server.handle(
        &caller,
        &request(
            2,
            "tools/call",
            json!({
                "name": "mail_send",
                "arguments": send_arguments("key-2"),
                "inputResponses": {"confirm_send": {"approved": true}},
                "requestState": state,
            }),
        ),
    );
    assert_eq!(other.result.as_ref().expect("a result")["isError"], true);
    assert!(env.upstream.submissions().is_empty());
}

#[test]
fn an_idempotency_key_replays_and_a_different_payload_conflicts() {
    let env = environment("mcp-idempotency", ALL_ACTIONS);
    let server = McpServer::new(env.gateway.clone());
    let caller = env.caller();

    let first = server.handle(
        &caller,
        &request(
            1,
            "tools/call",
            json!({"name": "mail_send", "arguments": send_arguments("key-1")}),
        ),
    );
    let state = first.result.expect("the call returned a result")["requestState"]
        .as_str()
        .expect("the state is a string")
        .to_owned();
    let approved = json!({
        "name": "mail_send",
        "arguments": send_arguments("key-1"),
        "inputResponses": {"confirm_send": {"approved": true}},
        "requestState": state,
    });
    let sent = server.handle(&caller, &request(2, "tools/call", approved.clone()));
    let submission_id = tool_result(&sent)["id"].clone();

    let replay = server.handle(&caller, &request(3, "tools/call", approved));
    assert_eq!(tool_result(&replay)["id"], submission_id);
    assert_eq!(env.upstream.submissions().len(), 1);

    let other = server.handle(
        &caller,
        &request(
            4,
            "tools/call",
            json!({
                "name": "mail_send",
                "arguments": {
                    "identityId": "personal",
                    "to": [{"email": "someone@example.org"}],
                    "subject": "A different subject",
                    "textBody": "A body.",
                    "idempotencyKey": "key-1"
                }
            }),
        ),
    );
    assert_eq!(tool_error_code(&other), "IDEMPOTENCY_CONFLICT");
}

#[test]
fn an_ambiguous_submission_is_unknown_and_must_not_be_resent() {
    let env = environment("mcp-ambiguous", ALL_ACTIONS);
    env.upstream.set_behavior(SubmissionBehavior::Ambiguous);
    let server = McpServer::new(env.gateway.clone());
    let caller = env.caller();

    let first = server.handle(
        &caller,
        &request(
            1,
            "tools/call",
            json!({"name": "mail_send", "arguments": send_arguments("key-1")}),
        ),
    );
    let state = first.result.expect("the call returned a result")["requestState"]
        .as_str()
        .expect("the state is a string")
        .to_owned();
    let sent = server.handle(
        &caller,
        &request(
            2,
            "tools/call",
            json!({
                "name": "mail_send",
                "arguments": send_arguments("key-1"),
                "inputResponses": {"confirm_send": {"approved": true}},
                "requestState": state,
            }),
        ),
    );

    assert_eq!(tool_result(&sent)["status"], "unknown");
    assert_eq!(tool_result(&sent)["failureCode"], "SEND_OUTCOME_UNKNOWN");
}

#[test]
fn a_tool_call_with_arguments_that_do_not_match_the_schema_is_refused() {
    let env = environment("mcp-schema", ALL_ACTIONS);
    let server = McpServer::new(env.gateway.clone());
    let caller = env.caller();

    let response = server.handle(
        &caller,
        &request(
            1,
            "tools/call",
            json!({
                "name": "mail_get",
                "arguments": {"identityId": "personal", "messageId": "m-1", "unexpected": true}
            }),
        ),
    );

    assert_eq!(response.result.as_ref().expect("a result")["isError"], true);
    assert_eq!(tool_error_code(&response), "INVALID_INPUT");
}

#[test]
fn an_unknown_tool_is_refused() {
    let env = environment("mcp-unknown-tool", ALL_ACTIONS);
    let server = McpServer::new(env.gateway.clone());
    let caller = env.caller();

    let response = server.handle(
        &caller,
        &request(1, "tools/call", json!({"name": "mail_everything"})),
    );

    assert_eq!(response.result.as_ref().expect("a result")["isError"], true);
    assert_eq!(tool_error_code(&response), "INVALID_INPUT");
}

#[test]
fn an_unsupported_protocol_version_is_refused() {
    let env = environment("mcp-version", ALL_ACTIONS);
    let server = McpServer::new(env.gateway.clone());
    let caller = env.caller();

    let mut call = request(1, "tools/list", json!({}));
    call.protocol_version = Some("2025-11-25".to_owned());
    let response = server.handle(&caller, &call);

    let error = response.error.expect("the call failed");
    assert_eq!(error.code, -32000);
    assert_eq!(
        error.data.expect("the data lists the versions")["supportedProtocolVersions"],
        json!(["2026-07-28"])
    );
}

#[test]
fn an_unsupported_method_is_a_protocol_error() {
    let env = environment("mcp-method", ALL_ACTIONS);
    let server = McpServer::new(env.gateway.clone());
    let caller = env.caller();

    let response = server.handle(&caller, &request(1, "initialize", json!({})));
    assert_eq!(response.error.expect("the call failed").code, -32601);
}

#[test]
fn the_context_resources_are_readable_and_carry_no_private_policy() {
    let env = environment("mcp-resources", ALL_ACTIONS);
    let server = McpServer::new(env.gateway.clone());
    let caller = env.caller();

    let listed = server.handle(&caller, &request(1, "resources/list", json!({})));
    let resources = listed.result.expect("the listing succeeds")["resources"]
        .as_array()
        .expect("the resources are listed")
        .clone();
    let uris: Vec<String> = resources
        .iter()
        .map(|resource| resource["uri"].as_str().unwrap_or_default().to_owned())
        .collect();
    assert!(uris.contains(&"corvi:///context/overview".to_owned()));
    assert!(uris.contains(&"corvi:///context/identities".to_owned()));
    assert!(uris.contains(&"corvi:///context/policy-summary".to_owned()));

    let read = server.handle(
        &caller,
        &request(
            2,
            "resources/read",
            json!({"uri": "corvi:///context/policy-summary"}),
        ),
    );
    let result = read.result.expect("the read succeeds");
    assert_eq!(result["ttlMs"], 0);
    assert_eq!(result["cacheScope"], "private");
    let text = result["contents"][0]["text"]
        .as_str()
        .expect("the payload is text");
    assert!(!text.contains("hide-codes"));
    assert!(!text.contains("one-time"));
}

#[test]
fn a_guessed_identity_resource_is_not_found() {
    let env = environment("mcp-guessed-resource", ALL_ACTIONS);
    let server = McpServer::new(env.gateway.clone());
    let caller = env.caller();

    let read = server.handle(
        &caller,
        &request(
            1,
            "resources/read",
            json!({"uri": "corvi:///identities/other/context"}),
        ),
    );
    assert_eq!(read.result.as_ref().expect("a result")["isError"], true);
    assert_eq!(tool_error_code(&read), "NOT_FOUND");
}

#[test]
fn the_visible_mail_signal_needs_the_subscribe_grant() {
    let env = environment(
        "mcp-visible-mail",
        "          - mail:identities:list\n          - mail:messages:list\n",
    );
    let server = McpServer::new(env.gateway.clone());
    let caller = env.caller();

    let listed = server.handle(&caller, &request(1, "resources/list", json!({})));
    let uris: Vec<String> = listed.result.as_ref().expect("a result")["resources"]
        .as_array()
        .expect("the resources are listed")
        .iter()
        .map(|resource| resource["uri"].as_str().unwrap_or_default().to_owned())
        .collect();
    assert!(uris.contains(&"corvi:///identities/personal/context".to_owned()));
    assert!(!uris.contains(&"corvi:///identities/personal/visible-mail".to_owned()));

    let read = server.handle(
        &caller,
        &request(
            2,
            "resources/read",
            json!({"uri": "corvi:///identities/personal/visible-mail"}),
        ),
    );
    assert_eq!(read.result.as_ref().expect("a result")["isError"], true);
    assert_eq!(tool_error_code(&read), "NOT_FOUND");
}

#[test]
fn a_caller_with_the_subscribe_grant_sees_the_visible_mail_signal() {
    let env = environment("mcp-visible-mail-granted", ALL_ACTIONS);
    let server = McpServer::new(env.gateway.clone());
    let caller = env.caller();

    let read = server.handle(
        &caller,
        &request(
            1,
            "resources/read",
            json!({"uri": "corvi:///identities/personal/visible-mail"}),
        ),
    );
    let result = read.result.as_ref().expect("a result");
    assert_eq!(result["resultType"], "complete");
    let text = result["contents"][0]["text"]
        .as_str()
        .expect("a text payload");
    let payload: Value = serde_json::from_str(text).expect("the payload is JSON");
    assert_eq!(payload["identityId"], "personal");
    assert!(payload["revision"].is_string());
}

#[tokio::test]
async fn the_mcp_endpoint_checks_its_headers() {
    let env = environment("mcp-http", ALL_ACTIONS);
    let app = app(&env);

    let response = post(
        &app,
        "/mcp",
        Some(&env.token),
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        }),
        &[
            ("mcp-protocol-version", MCP_PROTOCOL_VERSION),
            ("mcp-method", "tools/list"),
        ],
    )
    .await;
    assert_eq!(response.status, 200);
    assert!(response.body["result"]["tools"].is_array());

    let mismatched = post(
        &app,
        "/mcp",
        Some(&env.token),
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        }),
        &[
            ("mcp-protocol-version", MCP_PROTOCOL_VERSION),
            ("mcp-method", "tools/call"),
        ],
    )
    .await;
    assert_eq!(mismatched.status, 400);
    assert_eq!(mismatched.body["error"]["code"], -32602);
}

/// The caller the MCP tests use.
fn _caller_is_used(caller: &Caller) -> &Caller {
    caller
}
