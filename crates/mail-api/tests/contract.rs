//! The checked-in contracts are the contract.
//!
//! These tests read `api/openapi.yaml`, `api/mcp-tools.json` and
//! `api/mcp-resources.json` and check the gateway's answers against them, so
//! the implementation and the published contract cannot drift apart without
//! a test failing.

mod common;

use common::{ALL_ACTIONS, app, environment, get, post};
use mail_api::mcp::{JsonRpcRequest, MCP_PROTOCOL_VERSION, McpServer};
use serde_json::{Value, json};

const OPENAPI: &str = include_str!("../../../api/openapi.yaml");
const MCP_TOOLS: &str = include_str!("../../../api/mcp-tools.json");
const MCP_RESOURCES: &str = include_str!("../../../api/mcp-resources.json");

/// The component schemas of the OpenAPI document.
fn schemas() -> Value {
    let document: Value =
        serde_yaml::from_str(OPENAPI).expect("the OpenAPI document is valid YAML");
    document["components"]["schemas"].clone()
}

/// The whole OpenAPI document, which is the root its references resolve in.
fn openapi() -> Value {
    serde_yaml::from_str(OPENAPI).expect("the OpenAPI document is valid YAML")
}

/// One schema of the OpenAPI document.
fn schema(name: &str) -> Value {
    schemas()
        .get(name)
        .cloned()
        .unwrap_or_else(|| panic!("the OpenAPI document declares {name}"))
}

/// Check a value against one component schema of the OpenAPI document.
fn check_schema(name: &str, value: &Value) {
    let document = openapi();
    mail_api::schema::validate_in(value, &schema(name), &document).unwrap_or_else(|errors| {
        panic!("the {name} answer does not match the contract: {errors:?}")
    });
}

/// A tool of the checked-in MCP catalogue.
fn tool(name: &str) -> Value {
    let document: Value =
        serde_json::from_str(MCP_TOOLS).expect("the tool catalogue is valid JSON");
    document["tools"]
        .as_array()
        .expect("the catalogue lists tools")
        .iter()
        .find(|tool| tool["name"] == name)
        .cloned()
        .unwrap_or_else(|| panic!("the catalogue declares {name}"))
}

/// The schema definitions of the resource catalogue.
fn resource_definitions() -> Value {
    let document: Value =
        serde_json::from_str(MCP_RESOURCES).expect("the resource catalogue is valid JSON");
    document["$defs"].clone()
}

/// The structured content of a tool result.
fn structured(response: &mail_api::mcp::JsonRpcResponse) -> &Value {
    response
        .result
        .as_ref()
        .expect("a result")
        .get("structuredContent")
        .expect("the result carries structured content")
}

/// Check a value against a tool's output schema.
fn check_tool_output(tool_name: &str, value: &Value) {
    let tool = tool(tool_name);
    let mut root = json!({});
    if let Some(defs) = tool["outputSchema"].get("$defs") {
        root["$defs"] = defs.clone();
    }
    mail_api::schema::validate_in(value, &tool["outputSchema"], &root).unwrap_or_else(|errors| {
        panic!("{tool_name} output does not match the schema: {errors:?}")
    });
}

#[tokio::test]
async fn the_rest_answers_match_the_openapi_schemas() {
    let env = environment("contract-rest", ALL_ACTIONS);
    let app = app(&env);

    let identities = get(&app, "/v1/identities", Some(&env.token)).await;
    assert_eq!(identities.status, 200);
    check_schema("IdentitiesResponse", &identities.body);

    let page = get(&app, "/v1/messages?identityId=personal", Some(&env.token)).await;
    assert_eq!(page.status, 200);
    check_schema("MessagePage", &page.body);

    let message = get(
        &app,
        "/v1/messages/m-1?identityId=personal",
        Some(&env.token),
    )
    .await;
    assert_eq!(message.status, 200);
    check_schema("MailMessage", &message.body);

    let sent = post(
        &app,
        "/v1/messages/send",
        Some(&env.token),
        json!({
            "identityId": "personal",
            "to": [{"email": "someone@example.org"}],
            "subject": "Hello",
            "textBody": "A body."
        }),
        &[("idempotency-key", "key-1")],
    )
    .await;
    assert_eq!(sent.status, 202);
    check_schema("Submission", &sent.body);

    let submission = get(
        &app,
        &format!(
            "/v1/submissions/{}?identityId=personal",
            sent.body["id"].as_str().unwrap()
        ),
        Some(&env.token),
    )
    .await;
    assert_eq!(submission.status, 200);
    check_schema("Submission", &submission.body);

    let problem = get(&app, "/v1/messages/m-1", Some(&env.token)).await;
    assert_eq!(problem.status, 400);
    check_schema("Problem", &problem.body);
}

#[tokio::test]
async fn the_search_answer_matches_the_openapi_schemas() {
    let env = environment("contract-search", ALL_ACTIONS);
    let app = app(&env);

    let page = post(
        &app,
        "/v1/messages/search",
        Some(&env.token),
        json!({"identityId": "personal", "query": "invoice"}),
        &[],
    )
    .await;
    assert_eq!(page.status, 200);
    check_schema("MessagePage", &page.body);
}

#[test]
fn the_mcp_answers_match_the_tool_output_schemas() {
    let env = environment("contract-mcp", ALL_ACTIONS);
    let server = McpServer::new(env.gateway.clone());
    let caller = env.caller();

    let call = |id: u64, name: &str, arguments: Value| {
        server.handle(
            &caller,
            &JsonRpcRequest {
                id: Some(json!(id)),
                method: "tools/call".to_owned(),
                params: json!({"name": name, "arguments": arguments}),
                protocol_version: Some(MCP_PROTOCOL_VERSION.to_owned()),
                client_capabilities: json!({"elicitation": {}}),
            },
        )
    };

    let identities = call(1, "mail_list_identities", json!({}));
    check_tool_output("mail_list_identities", structured(&identities));

    let list = call(2, "mail_list", json!({"identityId": "personal"}));
    check_tool_output("mail_list", structured(&list));

    let search = call(
        3,
        "mail_search",
        json!({"identityId": "personal", "query": "invoice"}),
    );
    check_tool_output("mail_search", structured(&search));

    let message = call(
        4,
        "mail_get",
        json!({"identityId": "personal", "messageId": "m-1"}),
    );
    check_tool_output("mail_get", structured(&message));

    let attachment = call(
        5,
        "mail_get_attachment",
        json!({"identityId": "personal", "messageId": "m-1", "attachmentId": "a-1"}),
    );
    check_tool_output("mail_get_attachment", structured(&attachment));
}

#[test]
fn the_mcp_resource_payloads_match_the_resource_schemas() {
    let env = environment("contract-resources", ALL_ACTIONS);
    let server = McpServer::new(env.gateway.clone());
    let caller = env.caller();

    let read = |uri: &str| {
        server.handle(
            &caller,
            &JsonRpcRequest {
                id: Some(json!(1)),
                method: "resources/read".to_owned(),
                params: json!({"uri": uri}),
                protocol_version: Some(MCP_PROTOCOL_VERSION.to_owned()),
                client_capabilities: json!({}),
            },
        )
    };

    for (uri, definition) in [
        ("corvi:///context/overview", "serverOverview"),
        ("corvi:///context/identities", "identitiesContext"),
        ("corvi:///context/policy-summary", "policySummary"),
        ("corvi:///identities/personal/context", "identityContext"),
        (
            "corvi:///identities/personal/visible-mail",
            "visibleMailSignal",
        ),
    ] {
        let response = read(uri);
        let result = response.result.as_ref().expect("a result");
        let text = result["contents"][0]["text"]
            .as_str()
            .unwrap_or_else(|| panic!("{uri} has a text payload"));
        let payload: Value = serde_json::from_str(text).expect("the payload is JSON");
        let schema = resource_definitions()
            .get(definition)
            .cloned()
            .unwrap_or_else(|| panic!("the catalogue declares {definition}"));
        let mut root = json!({});
        root["$defs"] = resource_definitions();
        mail_api::schema::validate_in(&payload, &schema, &root).unwrap_or_else(|errors| {
            panic!("the {uri} payload does not match {definition}: {errors:?}")
        });
    }
}

#[test]
fn the_seven_operations_are_the_ones_the_contract_declares() {
    let document: Value =
        serde_yaml::from_str(OPENAPI).expect("the OpenAPI document is valid YAML");
    let paths = document["paths"]
        .as_object()
        .expect("the document declares paths");
    assert_eq!(paths.len(), 7);

    let catalogue: Value =
        serde_json::from_str(MCP_TOOLS).expect("the tool catalogue is valid JSON");
    let tools = catalogue["tools"]
        .as_array()
        .expect("the catalogue lists tools");
    assert_eq!(tools.len(), 7);
    let names: Vec<&str> = tools
        .iter()
        .map(|tool| tool["name"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(
        names,
        vec![
            "mail_list_identities",
            "mail_list",
            "mail_search",
            "mail_get",
            "mail_get_attachment",
            "mail_send",
            "mail_get_send_status",
        ]
    );
}
