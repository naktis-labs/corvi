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
fn concurrent_identical_sends_reserve_one_submission_and_conflicts_are_rejected() {
    let env = environment("send-race", ALL_ACTIONS);
    let caller = env.caller();
    let request = SendRequest {
        identity: personal(),
        to: vec![recipient("someone@example.org")],
        cc: Vec::new(),
        bcc: Vec::new(),
        subject: "Hello".to_owned(),
        text_body: "A body.".to_owned(),
        idempotency_key: "shared-key".to_owned(),
        approval_required: false,
        approval: None,
    };

    let gateway = env.gateway.clone();
    let caller1 = caller.clone();
    let request1 = request.clone();
    let first = std::thread::spawn(move || gateway.send_message(&caller1, &request1));
    let gateway = env.gateway.clone();
    let second = std::thread::spawn(move || gateway.send_message(&caller, &request));

    first
        .join()
        .expect("first request completes")
        .expect("send succeeds");
    second
        .join()
        .expect("second request completes")
        .expect("replay succeeds");
    assert_eq!(env.upstream.submissions().len(), 1);

    let conflict = SendRequest {
        identity: personal(),
        to: vec![recipient("someone@example.org")],
        cc: Vec::new(),
        bcc: Vec::new(),
        subject: "Different payload".to_owned(),
        text_body: "A body.".to_owned(),
        idempotency_key: "shared-key".to_owned(),
        approval_required: false,
        approval: None,
    };
    assert_eq!(
        env.gateway
            .send_message(&env.caller(), &conflict)
            .unwrap_err()
            .code,
        mail_api::problem::ErrorCode::IdempotencyConflict.as_str()
    );
}

/// The race between two identical sends must be caught every time.
///
/// A single pair of threads proves little: the old implementation
/// separated the idempotency lookup, the claim and the submission insert
/// into three lock acquisitions, and two threads would often not overlap
/// inside that window. This test starts both threads on a barrier, runs
/// many rounds with a fresh key each round, and requires that every round
/// produced exactly one upstream delivery and that the loser of the race
/// replayed the winner's submission rather than sending a second message.
#[test]
fn two_racing_identical_sends_never_deliver_the_message_twice() {
    const ROUNDS: usize = 50;

    let env = environment("send-race-barrrier", ALL_ACTIONS);
    let caller = env.caller();

    for round in 0..ROUNDS {
        let key = format!("race-{round}");
        let request = SendRequest {
            identity: personal(),
            to: vec![recipient("someone@example.org")],
            cc: Vec::new(),
            bcc: Vec::new(),
            subject: "Hello".to_owned(),
            text_body: "A body.".to_owned(),
            idempotency_key: key.clone(),
            approval_required: false,
            approval: None,
        };

        let before = env.upstream.submissions().len();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));

        let mut handles = Vec::new();
        for _ in 0..2 {
            let gateway = env.gateway.clone();
            let caller = caller.clone();
            let request = request.clone();
            let barrier = barrier.clone();
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                gateway.send_message(&caller, &request)
            }));
        }

        let mut outcomes = Vec::new();
        for handle in handles {
            let outcome = handle
                .join()
                .expect("the request completes")
                .expect("the send succeeds");
            let SendOutcome::Submitted {
                submission,
                replayed,
            } = outcome
            else {
                panic!("the send was not submitted");
            };
            outcomes.push((submission.id, replayed));
        }

        assert_eq!(
            env.upstream.submissions().len(),
            before + 1,
            "round {round} delivered the message more than once"
        );
        let (first, second) = (&outcomes[0], &outcomes[1]);
        assert_eq!(
            first.0, second.0,
            "round {round} produced two different submissions"
        );
        assert!(
            first.1 != second.1,
            "round {round} sent the message twice instead of replaying it"
        );
    }
}

/// The recipient roles are part of what an idempotency key binds to.
///
/// `{to: [a], cc: [b]}` and `{to: [a, b]}` describe different envelopes.
/// If they shared a digest, the second request would replay the first
/// submission and the message would go to the wrong recipients.
#[test]
fn the_recipient_roles_are_part_of_the_idempotency_digest() {
    let env = environment("send-digest-roles", ALL_ACTIONS);
    let caller = env.caller();

    let first = SendRequest {
        identity: personal(),
        to: vec![recipient("someone@example.org")],
        cc: vec![recipient("other@example.org")],
        bcc: Vec::new(),
        subject: "Hello".to_owned(),
        text_body: "A body.".to_owned(),
        idempotency_key: "role-key".to_owned(),
        approval_required: false,
        approval: None,
    };
    env.gateway
        .send_message(&caller, &first)
        .expect("the first send succeeds");

    let second = SendRequest {
        identity: personal(),
        to: vec![
            recipient("someone@example.org"),
            recipient("other@example.org"),
        ],
        cc: Vec::new(),
        bcc: Vec::new(),
        subject: "Hello".to_owned(),
        text_body: "A body.".to_owned(),
        idempotency_key: "role-key".to_owned(),
        approval_required: false,
        approval: None,
    };
    assert_eq!(
        env.gateway.send_message(&caller, &second).unwrap_err().code,
        mail_api::problem::ErrorCode::IdempotencyConflict.as_str(),
        "a different envelope must not replay the first send"
    );
    assert_eq!(env.upstream.submissions().len(), 1);
}

/// A send the upstream definitely refused releases the key.
///
/// Nothing was delivered, so the caller may retry with the same key. If the
/// key stayed claimed, a transient upstream failure would burn the key
/// forever.
#[test]
fn a_definitely_refused_send_releases_the_idempotency_key() {
    let env = environment("send-reject-release", ALL_ACTIONS);
    let caller = env.caller();
    env.upstream
        .set_behavior(mail_api::fixture::SubmissionBehavior::Reject);

    let request = SendRequest {
        identity: personal(),
        to: vec![recipient("someone@example.org")],
        cc: Vec::new(),
        bcc: Vec::new(),
        subject: "Hello".to_owned(),
        text_body: "A body.".to_owned(),
        idempotency_key: "retry-key".to_owned(),
        approval_required: false,
        approval: None,
    };

    let outcome = env
        .gateway
        .send_message(&caller, &request)
        .expect("the refusal is reported, not raised");
    let SendOutcome::Submitted { submission, .. } = outcome else {
        panic!("the send was not submitted");
    };
    assert_eq!(submission.status, mail_api::view::SubmissionStatus::Failed);

    env.upstream
        .set_behavior(mail_api::fixture::SubmissionBehavior::Accept);
    let outcome = env
        .gateway
        .send_message(&caller, &request)
        .expect("the retry succeeds");
    let SendOutcome::Submitted {
        submission,
        replayed,
    } = outcome
    else {
        panic!("the retry was not submitted");
    };
    assert!(!replayed, "the retry was replayed instead of sent");
    assert_eq!(
        submission.status,
        mail_api::view::SubmissionStatus::Submitted
    );
    // Both attempts reached the upstream: the fixture records every message
    // it was handed, whether it accepted or refused it.
    assert_eq!(env.upstream.submissions().len(), 2);
}

/// A send whose outcome is unknown keeps the key claimed.
///
/// The message may have reached the upstream. Retrying it under the same key
/// could deliver it twice, so the key stays claimed and the caller is told
/// the outcome is unknown.
#[test]
fn an_ambiguous_send_keeps_the_idempotency_key_claimed() {
    let env = environment("send-ambiguous-claim", ALL_ACTIONS);
    let caller = env.caller();
    env.upstream
        .set_behavior(mail_api::fixture::SubmissionBehavior::Ambiguous);

    let request = SendRequest {
        identity: personal(),
        to: vec![recipient("someone@example.org")],
        cc: Vec::new(),
        bcc: Vec::new(),
        subject: "Hello".to_owned(),
        text_body: "A body.".to_owned(),
        idempotency_key: "ambiguous-key".to_owned(),
        approval_required: false,
        approval: None,
    };

    let outcome = env
        .gateway
        .send_message(&caller, &request)
        .expect("the ambiguity is reported, not raised");
    let SendOutcome::Submitted { submission, .. } = outcome else {
        panic!("the send was not submitted");
    };
    assert_eq!(submission.status, mail_api::view::SubmissionStatus::Unknown);

    env.upstream
        .set_behavior(mail_api::fixture::SubmissionBehavior::Accept);
    let outcome = env
        .gateway
        .send_message(&caller, &request)
        .expect("the retry is answered from the claim");
    let SendOutcome::Submitted {
        submission,
        replayed,
    } = outcome
    else {
        panic!("the retry was not submitted");
    };
    assert!(
        replayed,
        "an ambiguous send was retried instead of replayed"
    );
    assert_eq!(submission.status, mail_api::view::SubmissionStatus::Unknown);
    assert_eq!(
        env.upstream.submissions().len(),
        1,
        "the ambiguous message was delivered a second time"
    );
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
