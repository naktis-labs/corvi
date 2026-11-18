//! The seven operations of the public mail API.
//!
//! Every test here drives the service pipeline, which is the same pipeline
//! the REST and MCP adapters drive.

mod common;

use common::{ALL_ACTIONS, READ_ACTIONS, environment, two_identity_environment};
use mail_api::service::{
    GetAttachmentRequest, GetMessageRequest, GetSubmissionRequest, ListRequest, SearchRequest,
    SendOutcome, SendRequest,
};
use mail_api::view::MailAddress;
use mail_core::IdentityId;

/// The identity under test.
fn personal() -> IdentityId {
    IdentityId::new("personal")
}

/// A recipient.
fn recipient(email: &str) -> MailAddress {
    MailAddress {
        email: email.to_owned(),
        name: None,
    }
}

#[test]
fn list_identities_returns_the_authorized_identities_with_their_own_permissions() {
    let env = environment("identities", ALL_ACTIONS);
    let caller = env.caller();

    let response = env
        .gateway
        .list_identities(&caller)
        .expect("listing succeeds");

    assert_eq!(response.items.len(), 1);
    assert_eq!(response.items[0].id, "personal");
    assert_eq!(response.items[0].address, "me@example.com");
    assert!(
        response.items[0]
            .permissions
            .contains(&"mail:messages:read".to_owned())
    );
    assert!(
        response.items[0]
            .permissions
            .contains(&"mail:identities:list".to_owned())
    );
}

#[test]
fn list_identities_does_not_union_permissions_across_identities() {
    let env = two_identity_environment(
        "identities-union",
        "          - mail:identities:list\n          - mail:messages:read\n",
        "          - mail:identities:list\n          - mail:messages:send\n",
    );
    let caller = env.caller();

    let response = env
        .gateway
        .list_identities(&caller)
        .expect("listing succeeds");

    assert_eq!(response.items.len(), 2);
    let personal = response
        .items
        .iter()
        .find(|item| item.id == "personal")
        .expect("the personal identity is listed");
    let work = response
        .items
        .iter()
        .find(|item| item.id == "work")
        .expect("the work identity is listed");
    assert!(
        personal
            .permissions
            .contains(&"mail:messages:read".to_owned())
    );
    assert!(
        !personal
            .permissions
            .contains(&"mail:messages:send".to_owned())
    );
    assert!(work.permissions.contains(&"mail:messages:send".to_owned()));
    assert!(!work.permissions.contains(&"mail:messages:read".to_owned()));
}

#[test]
fn list_messages_returns_the_visible_messages_newest_first() {
    let env = environment("list", ALL_ACTIONS);
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

    assert_eq!(page.items.len(), 2);
    assert_eq!(page.items[0].id, "m-1");
    assert_eq!(page.items[0].identity_id, "personal");
    assert_eq!(page.items[0].received_at, "2026-01-02T10:00:00Z");
    assert_eq!(page.items[0].subject.as_deref(), Some("Invoice 2026"));
    assert!(page.next_cursor.is_none());
}

#[test]
fn search_matches_the_literal_query_over_the_projection() {
    let env = environment("search", ALL_ACTIONS);
    let caller = env.caller();

    let page = env
        .gateway
        .search_messages(
            &caller,
            &SearchRequest {
                identity: personal(),
                query: "invoice".to_owned(),
                limit: 25,
                cursor: None,
            },
        )
        .expect("search succeeds");

    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].id, "m-1");
}

#[test]
fn search_is_case_insensitive_and_does_not_match_a_regular_expression() {
    let env = environment("search-case", ALL_ACTIONS);
    let caller = env.caller();

    let upper = env
        .gateway
        .search_messages(
            &caller,
            &SearchRequest {
                identity: personal(),
                query: "INVOICE".to_owned(),
                limit: 25,
                cursor: None,
            },
        )
        .expect("search succeeds");
    assert_eq!(upper.items.len(), 1);

    let pattern = env
        .gateway
        .search_messages(
            &caller,
            &SearchRequest {
                identity: personal(),
                query: ".*".to_owned(),
                limit: 25,
                cursor: None,
            },
        )
        .expect("search succeeds");
    assert_eq!(pattern.items.len(), 0);
}

#[test]
fn get_message_returns_the_projection() {
    let env = environment("get", ALL_ACTIONS);
    let caller = env.caller();

    let message = env
        .gateway
        .get_message(
            &caller,
            &GetMessageRequest {
                identity: personal(),
                message_id: "m-1".to_owned(),
            },
        )
        .expect("the message is readable");

    assert_eq!(message.id, "m-1");
    assert_eq!(message.identity_id, "personal");
    assert_eq!(message.subject.as_deref(), Some("Invoice 2026"));
    assert_eq!(
        message.text_body.as_deref(),
        Some("Please pay the invoice of 42 euros.")
    );
    assert_eq!(message.attachments.as_ref().map(Vec::len), Some(1));
}

#[test]
fn get_attachment_returns_the_bytes_after_a_fresh_authorization() {
    let env = environment("attachment", ALL_ACTIONS);
    let caller = env.caller();

    let payload = env
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
        .expect("the attachment is readable");

    assert_eq!(payload.bytes, b"invoice");
    assert_eq!(payload.descriptor.file_name, "invoice.txt");
    assert_eq!(payload.descriptor.content_type, "text/plain");
}

#[test]
fn send_message_submits_from_the_authorized_identity() {
    let env = environment("send", ALL_ACTIONS);
    let caller = env.caller();

    let outcome = env
        .gateway
        .send_message(
            &caller,
            &SendRequest {
                identity: personal(),
                to: vec![recipient("someone@example.org")],
                cc: Vec::new(),
                bcc: Vec::new(),
                subject: "Hello".to_owned(),
                text_body: "A body.".to_owned(),
                idempotency_key: "key-1".to_owned(),
                approval_required: false,
                approval: None,
            },
        )
        .expect("the send succeeds");

    let SendOutcome::Submitted { submission, .. } = outcome else {
        panic!("the send was not submitted");
    };
    assert_eq!(submission.identity_id, "personal");
    assert_eq!(
        submission.status,
        mail_api::view::SubmissionStatus::Submitted
    );

    let submissions = env.upstream.submissions();
    assert_eq!(submissions.len(), 1);
    assert_eq!(submissions[0].sender, "me@example.com");
    assert_eq!(submissions[0].recipients, vec!["someone@example.org"]);
}

#[test]
fn get_submission_returns_the_callers_own_submission() {
    let env = environment("submission", ALL_ACTIONS);
    let caller = env.caller();

    let SendOutcome::Submitted { submission, .. } = env
        .gateway
        .send_message(
            &caller,
            &SendRequest {
                identity: personal(),
                to: vec![recipient("someone@example.org")],
                cc: Vec::new(),
                bcc: Vec::new(),
                subject: "Hello".to_owned(),
                text_body: "A body.".to_owned(),
                idempotency_key: "key-1".to_owned(),
                approval_required: false,
                approval: None,
            },
        )
        .expect("the send succeeds")
    else {
        panic!("the send was not submitted");
    };

    let status = env
        .gateway
        .get_submission(
            &caller,
            &GetSubmissionRequest {
                identity: personal(),
                submission_id: submission.id.clone(),
            },
        )
        .expect("the submission is readable");

    assert_eq!(status.id, submission.id);
    assert_eq!(status.status, mail_api::view::SubmissionStatus::Submitted);
    assert!(!status.idempotency_durable);
}

#[test]
fn a_submission_of_one_identity_is_not_readable_under_another() {
    let env = two_identity_environment(
        "submission-scope",
        ALL_ACTIONS,
        "          - mail:identities:list\n          - mail:submissions:read\n",
    );
    let caller = env.caller();

    let SendOutcome::Submitted { submission, .. } = env
        .gateway
        .send_message(
            &caller,
            &SendRequest {
                identity: personal(),
                to: vec![recipient("someone@example.org")],
                cc: Vec::new(),
                bcc: Vec::new(),
                subject: "Hello".to_owned(),
                text_body: "A body.".to_owned(),
                idempotency_key: "key-1".to_owned(),
                approval_required: false,
                approval: None,
            },
        )
        .expect("the send succeeds")
    else {
        panic!("the send was not submitted");
    };

    let error = env
        .gateway
        .get_submission(
            &caller,
            &GetSubmissionRequest {
                identity: IdentityId::new("work"),
                submission_id: submission.id,
            },
        )
        .expect_err("the submission belongs to another identity");
    assert_eq!(error.error_code(), "NOT_FOUND");
}

#[test]
fn a_credential_without_the_identity_grant_sees_nothing() {
    let env = environment("no-grant", READ_ACTIONS);
    let caller = env.caller();

    let error = env
        .gateway
        .list_messages(
            &caller,
            &ListRequest {
                identity: IdentityId::new("work"),
                limit: 25,
                cursor: None,
            },
        )
        .expect_err("the identity is not granted");
    assert_eq!(error.error_code(), "NOT_FOUND");
}
