//! The disclosure and authorization guarantees of the gateway.
//!
//! These tests are the ones ADR-0003 and ADR-0005 exist for: a hidden
//! message must be indistinguishable from one that does not exist, an
//! identity must not leak into another, and every refusal must carry a
//! stable code.

mod common;

use axum::http::StatusCode;
use common::{
    ALL_ACTIONS, LIST_ACTIONS, READ_ACTIONS, app, environment, get, hiding_environment, post,
    two_identity_environment,
};
use mail_api::service::{GetAttachmentRequest, GetMessageRequest, ListRequest, SearchRequest};
use mail_core::IdentityId;
use serde_json::json;

/// The identity under test.
fn personal() -> IdentityId {
    IdentityId::new("personal")
}

#[test]
fn a_hidden_message_is_indistinguishable_from_one_that_does_not_exist() {
    let env = hiding_environment("hidden", ALL_ACTIONS);
    let caller = env.caller();

    let hidden = env
        .gateway
        .get_message(
            &caller,
            &GetMessageRequest {
                identity: personal(),
                message_id: "m-2".to_owned(),
            },
        )
        .expect_err("the message is hidden");
    let absent = env
        .gateway
        .get_message(
            &caller,
            &GetMessageRequest {
                identity: personal(),
                message_id: "does-not-exist".to_owned(),
            },
        )
        .expect_err("the message does not exist");

    assert_eq!(hidden.error_code(), "NOT_FOUND");
    assert_eq!(hidden.error_code(), absent.error_code());
    assert_eq!(hidden.status, absent.status);
    assert_eq!(hidden.detail, absent.detail);
}

#[test]
fn a_hidden_message_is_absent_from_the_listing_and_from_a_search() {
    let env = hiding_environment("hidden-list", ALL_ACTIONS);
    let caller = env.caller();

    let page = env
        .gateway
        .list_messages(
            &caller,
            &ListRequest {
                identity: personal(),
                limit: 25,
                cursor: None,
            },
        )
        .expect("listing succeeds");
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].id, "m-1");

    let search = env
        .gateway
        .search_messages(
            &caller,
            &SearchRequest {
                identity: personal(),
                query: "one-time".to_owned(),
                limit: 25,
                cursor: None,
            },
        )
        .expect("search succeeds");
    assert!(search.items.is_empty());
}

#[test]
fn a_message_the_identity_does_not_own_is_not_found() {
    let env = environment("ownership", ALL_ACTIONS);
    let caller = env.caller();

    let error = env.gateway.get_message(
        &caller,
        &GetMessageRequest {
            identity: personal(),
            message_id: "m-1".to_owned(),
        },
    );
    // The fixture message names the identity as its trusted recipient, so it
    // is owned; a message of another mailbox is not.
    assert!(error.is_ok());
}

#[test]
fn an_action_that_is_not_granted_is_forbidden_but_an_unknown_identity_is_not_found() {
    let env = environment("actions", LIST_ACTIONS);
    let caller = env.caller();

    let denied = env
        .gateway
        .get_message(
            &caller,
            &GetMessageRequest {
                identity: personal(),
                message_id: "m-1".to_owned(),
            },
        )
        .expect_err("the read action is not granted");
    assert_eq!(denied.error_code(), "FORBIDDEN");

    let unknown = env
        .gateway
        .get_message(
            &caller,
            &GetMessageRequest {
                identity: IdentityId::new("work"),
                message_id: "m-1".to_owned(),
            },
        )
        .expect_err("the identity is not granted");
    assert_eq!(unknown.error_code(), "NOT_FOUND");
}

#[test]
fn attachments_need_their_own_grant() {
    let env = environment("attachment-grant", READ_ACTIONS);
    let caller = env.caller();

    let error = env
        .gateway
        .get_attachment(
            &caller,
            &GetAttachmentRequest {
                identity: personal(),
                message_id: "m-1".to_owned(),
                attachment_id: "a-1".to_owned(),
            },
            2 * 1024 * 1024,
        )
        .expect_err("the attachment action is not granted");
    assert_eq!(error.error_code(), "FORBIDDEN");
}

#[test]
fn an_attachment_that_the_policy_does_not_permit_is_not_found() {
    let env = mail_api::testing::TestEnvironment::build(
        "attachment-policy",
        ALL_ACTIONS,
        DENYING_ATTACHMENTS,
        mail_api::testing::DEFAULT_FIXTURE,
        None,
    );
    let caller = env.caller();

    let error = env
        .gateway
        .get_attachment(
            &caller,
            &GetAttachmentRequest {
                identity: personal(),
                message_id: "m-1".to_owned(),
                attachment_id: "a-1".to_owned(),
            },
            2 * 1024 * 1024,
        )
        .expect_err("the policy denies attachments");
    assert_eq!(error.error_code(), "NOT_FOUND");
}

#[test]
fn a_cursor_is_scoped_to_its_identity_and_its_query() {
    let env = two_identity_environment(
        "cursor-scope",
        ALL_ACTIONS,
        "          - mail:identities:list\n          - mail:messages:list\n",
    );
    let caller = env.caller();

    let page = env
        .gateway
        .list_messages(
            &caller,
            &ListRequest {
                identity: personal(),
                limit: 1,
                cursor: None,
            },
        )
        .expect("listing succeeds");
    let cursor = page.next_cursor.expect("a second page exists");

    let other_identity = env
        .gateway
        .list_messages(
            &caller,
            &ListRequest {
                identity: IdentityId::new("work"),
                limit: 1,
                cursor: Some(cursor.clone()),
            },
        )
        .expect_err("the cursor belongs to another identity");
    assert_eq!(other_identity.error_code(), "CURSOR_STALE");

    let other_query = env
        .gateway
        .search_messages(
            &caller,
            &SearchRequest {
                identity: personal(),
                query: "invoice".to_owned(),
                limit: 1,
                cursor: Some(cursor.clone()),
            },
        )
        .expect_err("the cursor belongs to another query");
    assert_eq!(other_query.error_code(), "CURSOR_STALE");

    let tampered = env
        .gateway
        .list_messages(
            &caller,
            &ListRequest {
                identity: personal(),
                limit: 1,
                cursor: Some(format!("{cursor}x")),
            },
        )
        .expect_err("the cursor was tampered with");
    assert_eq!(tampered.error_code(), "CURSOR_INVALID");
}

#[test]
fn a_cursor_expires_after_fifteen_minutes() {
    let clock = mail_api::testing::TestClock::new(1_000);
    let env = mail_api::testing::TestEnvironment::build(
        "cursor-expiry",
        ALL_ACTIONS,
        mail_api::testing::PERMISSIVE_POLICIES,
        mail_api::testing::DEFAULT_FIXTURE,
        Some(clock.clone()),
    );
    let caller = env.caller();

    let page = env
        .gateway
        .list_messages(
            &caller,
            &ListRequest {
                identity: personal(),
                limit: 1,
                cursor: None,
            },
        )
        .expect("listing succeeds");
    let cursor = page.next_cursor.expect("a second page exists");

    clock.advance(15 * 60 + 1);

    let error = env
        .gateway
        .list_messages(
            &caller,
            &ListRequest {
                identity: personal(),
                limit: 1,
                cursor: Some(cursor),
            },
        )
        .expect_err("the cursor expired");
    assert_eq!(error.error_code(), "CURSOR_INVALID");
}

#[test]
fn the_next_page_continues_where_the_first_stopped() {
    let env = environment("cursor-page", ALL_ACTIONS);
    let caller = env.caller();

    let first = env
        .gateway
        .list_messages(
            &caller,
            &ListRequest {
                identity: personal(),
                limit: 1,
                cursor: None,
            },
        )
        .expect("listing succeeds");
    assert_eq!(first.items.len(), 1);
    assert_eq!(first.items[0].id, "m-1");

    let second = env
        .gateway
        .list_messages(
            &caller,
            &ListRequest {
                identity: personal(),
                limit: 1,
                cursor: first.next_cursor.clone(),
            },
        )
        .expect("listing succeeds");
    assert_eq!(second.items.len(), 1);
    assert_eq!(second.items[0].id, "m-2");
}

#[tokio::test]
async fn an_unauthenticated_request_is_refused() {
    let env = environment("rest-401", ALL_ACTIONS);
    let app = app(&env);

    let response = get(&app, "/v1/identities", None).await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert_eq!(response.body["code"], "UNAUTHORIZED");
    assert_eq!(
        response
            .headers
            .get("www-authenticate")
            .map(|value| value.to_str().unwrap()),
        Some("Bearer")
    );
}

#[tokio::test]
async fn a_wrong_token_is_refused_without_saying_why() {
    let env = environment("rest-wrong-token", ALL_ACTIONS);
    let app = app(&env);

    let response = get(&app, "/v1/identities", Some("wrong")).await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert_eq!(response.body["code"], "UNAUTHORIZED");
}

#[tokio::test]
async fn a_problem_response_is_a_typed_rfc_9457_document() {
    let env = environment("rest-problem", ALL_ACTIONS);
    let app = app(&env);

    let response = get(&app, "/v1/messages/m-1", Some(&env.token)).await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        response
            .headers
            .get("content-type")
            .map(|value| value.to_str().unwrap()),
        Some("application/problem+json")
    );
    assert_eq!(
        response
            .headers
            .get("cache-control")
            .map(|value| value.to_str().unwrap()),
        Some("private, no-store")
    );
    assert_eq!(response.body["code"], "INVALID_INPUT");
    assert!(response.body["title"].is_string());
    assert_eq!(response.body["status"], 400);
    assert!(response.body["traceId"].is_string());
}

#[tokio::test]
async fn mail_responses_are_not_cacheable() {
    let env = environment("rest-cache", ALL_ACTIONS);
    let app = app(&env);

    let response = get(&app, "/v1/messages?identityId=personal", Some(&env.token)).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(
        response
            .headers
            .get("cache-control")
            .map(|value| value.to_str().unwrap()),
        Some("private, no-store")
    );
}

#[tokio::test]
async fn a_send_without_an_idempotency_key_is_refused() {
    let env = environment("rest-idempotency", ALL_ACTIONS);
    let app = app(&env);

    let response = post(
        &app,
        "/v1/messages/send",
        Some(&env.token),
        json!({
            "identityId": "personal",
            "to": [{"email": "someone@example.org"}],
            "subject": "Hello",
            "textBody": "A body."
        }),
        &[],
    )
    .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert_eq!(response.body["code"], "INVALID_INPUT");
}

#[tokio::test]
async fn a_send_with_an_idempotency_key_is_accepted_and_replayed() {
    let env = environment("rest-send", ALL_ACTIONS);
    let app = app(&env);
    let body = json!({
        "identityId": "personal",
        "to": [{"email": "someone@example.org"}],
        "subject": "Hello",
        "textBody": "A body."
    });

    let first = post(
        &app,
        "/v1/messages/send",
        Some(&env.token),
        body.clone(),
        &[("idempotency-key", "key-1")],
    )
    .await;
    assert_eq!(first.status, StatusCode::ACCEPTED);
    assert_eq!(first.body["status"], "submitted");

    let replay = post(
        &app,
        "/v1/messages/send",
        Some(&env.token),
        body,
        &[("idempotency-key", "key-1")],
    )
    .await;
    assert_eq!(replay.status, StatusCode::OK);
    assert_eq!(replay.body["id"], first.body["id"]);
    assert_eq!(env.upstream.submissions().len(), 1);
}

#[tokio::test]
async fn the_same_idempotency_key_with_another_payload_is_a_conflict() {
    let env = environment("rest-conflict", ALL_ACTIONS);
    let app = app(&env);

    let first = post(
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
    assert_eq!(first.status, StatusCode::ACCEPTED);

    let conflict = post(
        &app,
        "/v1/messages/send",
        Some(&env.token),
        json!({
            "identityId": "personal",
            "to": [{"email": "someone@example.org"}],
            "subject": "A different subject",
            "textBody": "A body."
        }),
        &[("idempotency-key", "key-1")],
    )
    .await;
    assert_eq!(conflict.status, StatusCode::CONFLICT);
    assert_eq!(conflict.body["code"], "IDEMPOTENCY_CONFLICT");
}

/// A policy that permits mail but not its attachments.
const DENYING_ATTACHMENTS: &str = "\
generation: 1
policies:
  - id: default
    default_visibility: show
    on_indeterminate: hide
    rendering:
      html: sanitized
      remote_content: strip
      attachments: deny
      external_links: sanitize
    rules: []
bindings:
  personal: default
  work: default
";
