//! The conformance cases ADR-0007 section 8 requires of the JMAP transport.
//!
//! The cases are written against the transport's own contract rather than
//! against a provider, because the failure modes this file checks are the
//! ones a provider cannot be trusted to exercise: a hostile session, a
//! hostile redirect, a missing scope, a revoked credential and an ambiguous
//! submission.

use std::sync::{Arc, Mutex};

use mail_core::{
    BlobReader, ChangeCursor, ListQuery, MailChangeTracker, MailReader, MailSubmitter, MailboxRef,
    MessageId, OutgoingMessage, TransportError,
};
use mail_jmap::{
    Credential, HttpRequest,
    client::JmapClient,
    error::JmapError,
    protocol::{JmapRequest, MethodCall},
    reader::{JmapChangeTracker, JmapReader},
    session::{AccountSelector, CORE, MAIL, SUBMISSION, Session},
    submission::JmapSubmitter,
    testing::FixtureTransport,
    trust::{EgressPolicy, Origin, StaticResolver, TrustError},
};
use serde_json::{Value, json};

const SESSION: &str = include_str!("fixtures/session.json");
const SESSION_READ_ONLY: &str = include_str!("fixtures/session-read-only.json");
const SESSION_HOSTILE: &str = include_str!("fixtures/session-hostile.json");
const MAILBOXES: &str = include_str!("fixtures/mailboxes.json");
const QUERY: &str = include_str!("fixtures/query.json");
const EMAILS: &str = include_str!("fixtures/emails.json");
const CHANGES: &str = include_str!("fixtures/changes.json");
const CHANGES_UNCOMPUTABLE: &str = include_str!("fixtures/changes-uncomputable.json");
const IDENTITIES: &str = include_str!("fixtures/identities.json");
const EMAIL_SET: &str = include_str!("fixtures/email-set.json");
const SUBMISSION_SET: &str = include_str!("fixtures/submission-set.json");
const SUBMISSION_REFUSED: &str = include_str!("fixtures/submission-refused.json");

/// Wrap a fixture in the JMAP response envelope.
///
/// The fixtures hold the arguments a method answers with, so a test states
/// what the upstream says rather than repeating the envelope.
fn envelope(method: &str, call_id: &str, arguments: Value) -> Value {
    json!({"methodResponses": [[method, arguments, call_id]]})
}

/// The egress policy of the tests: one trusted origin, nothing else.
fn policy() -> EgressPolicy {
    EgressPolicy::new(vec![
        Origin::parse("https://api.example.com").expect("a valid origin"),
    ])
}

/// A resolver that answers with a public address.
fn resolver() -> StaticResolver {
    StaticResolver::new().with_host(
        "api.example.com",
        vec!["93.184.216.34".parse().expect("an address")],
    )
}

/// A client that speaks to the fixture transport.
fn client(transport: FixtureTransport) -> JmapClient {
    JmapClient::new(Box::new(transport), policy())
        .with_resolver(Box::new(resolver()))
        .with_credential(Credential::bearer("upstream-token"))
}

/// A transport that serves the session and the calls the tests make.
fn transport() -> FixtureTransport {
    FixtureTransport::new()
        .on_get(
            "/jmap/session",
            serde_json::from_str(SESSION).expect("a valid session"),
        )
        .on_post_body(
            "/jmap/api",
            "\"Mailbox/get\"",
            envelope(
                "Mailbox/get",
                "m0",
                serde_json::from_str(MAILBOXES).expect("valid"),
            ),
        )
        .on_post_body(
            "/jmap/api",
            "\"Email/query\"",
            envelope(
                "Email/query",
                "m0",
                serde_json::from_str(QUERY).expect("valid"),
            ),
        )
        .on_post_body(
            "/jmap/api",
            "\"Email/get\"",
            envelope(
                "Email/get",
                "m1",
                serde_json::from_str(EMAILS).expect("valid"),
            ),
        )
}

/// The requests the client made.
fn requests(log: &Arc<Mutex<Vec<HttpRequest>>>) -> Vec<HttpRequest> {
    log.lock().map(|log| log.clone()).unwrap_or_default()
}

/// The bodies of the requests the client made.
fn bodies(log: &Arc<Mutex<Vec<HttpRequest>>>) -> Vec<String> {
    requests(log)
        .iter()
        .map(|request| String::from_utf8_lossy(&request.body).to_string())
        .collect()
}

/// Discover the session over the fixture transport.
fn discovered(transport: FixtureTransport) -> (JmapClient, Arc<Mutex<Vec<HttpRequest>>>) {
    let log = transport.log();
    let mut client = client(transport);
    client
        .discover("https://api.example.com/jmap/session")
        .expect("the session is discovered");
    (client, log)
}

/// A client that has already discovered the session.
fn connected(transport: FixtureTransport) -> JmapClient {
    let (client, _log) = discovered(transport);
    client
}

/// The message the fixture upstream serves.
fn message() -> OutgoingMessage {
    OutgoingMessage {
        sender: "me@example.com".to_owned(),
        recipients: vec!["someone@example.org".to_owned()],
        subject: Some("Invoice".to_owned()),
        headers: Vec::new(),
        body: "A body.".to_owned(),
    }
}

#[test]
fn the_request_path_rejects_account_not_in_authenticated_session() {
    let (mut client, log) = discovered(transport());
    let request = JmapRequest::new(vec![MAIL.to_owned()]).with(MethodCall::new(
        "Email/query",
        json!({"accountId": "not-in-session"}),
    ));
    let error = client
        .call(&request)
        .expect_err("unknown session account is rejected");
    assert!(matches!(error, JmapError::AccountSelectionInvalid(_)));
    assert_eq!(requests(&log).len(), 1, "only discovery reached transport");
}

#[test]
fn the_session_is_discovered_and_its_capabilities_are_validated() {
    let transport = FixtureTransport::new().on_get(
        "/jmap/session",
        serde_json::from_str(SESSION).expect("a valid session"),
    );
    let mut client = client(transport);
    let session = client
        .discover("https://api.example.com/jmap/session")
        .expect("the session is discovered");

    assert!(session.supports(CORE));
    assert!(session.supports(MAIL));
    assert!(session.supports(SUBMISSION));
    assert_eq!(session.primary_account(MAIL), Some("acct-personal"));
    assert_eq!(session.username(), Some("me@example.com"));
}

#[test]
fn the_credential_is_presented_on_every_request() {
    let transport = FixtureTransport::new().on_get(
        "/jmap/session",
        serde_json::from_str(SESSION).expect("a valid session"),
    );
    let log = transport.log();
    let mut client = client(transport);
    client
        .discover("https://api.example.com/jmap/session")
        .expect("the session is discovered");

    let requests = log.lock().map(|log| log.clone()).unwrap_or_default();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].header("authorization"),
        Some("Bearer upstream-token")
    );
}

#[test]
fn the_read_account_and_the_submission_account_are_selected_independently() {
    let transport = FixtureTransport::new().on_get(
        "/jmap/session",
        serde_json::from_str(SESSION).expect("a valid session"),
    );
    let mut client = client(transport);
    let session = client
        .discover("https://api.example.com/jmap/session")
        .expect("the session is discovered");

    let read = session
        .select_account(&AccountSelector::primary_for(MAIL), MAIL)
        .expect("the read account is selected");
    assert_eq!(read.account_id, "acct-personal");
    let submission = session
        .select_account(&AccountSelector::primary_for(SUBMISSION), SUBMISSION)
        .expect("the submission account is selected");
    assert_eq!(submission.account_id, "acct-personal");

    // A named account that does not exist is refused, and so is an account
    // that lacks the capability the operation needs.
    assert!(matches!(
        session.select_account(&AccountSelector::by_id("acct-other"), MAIL),
        Err(JmapError::AccountSelectionInvalid(_))
    ));
    assert_eq!(
        session.select_account(&AccountSelector::by_id("acct-readonly"), SUBMISSION),
        Err(JmapError::CapabilityMissing(SUBMISSION.to_owned()))
    );
}

#[test]
fn a_read_only_credential_cannot_submit() {
    let transport = FixtureTransport::new().on_get(
        "/jmap/session",
        serde_json::from_str(SESSION_READ_ONLY).expect("a valid session"),
    );
    let mut client = client(transport);
    let session = client
        .discover("https://api.example.com/jmap/session")
        .expect("the session is discovered");

    assert!(!session.supports(SUBMISSION));
    assert_eq!(
        session.select_account(&AccountSelector::primary_for(SUBMISSION), SUBMISSION),
        Err(JmapError::CapabilityMissing(SUBMISSION.to_owned()))
    );
}

#[test]
fn a_session_that_points_at_a_metadata_address_is_refused() {
    let transport = FixtureTransport::new().on_get(
        "/jmap/session",
        serde_json::from_str(SESSION_HOSTILE).expect("a valid session"),
    );
    let log = transport.log();
    let mut client = client(transport);
    client
        .discover("https://api.example.com/jmap/session")
        .expect("the session itself is fetched from the configured URL");

    let request = mail_jmap::protocol::JmapRequest::new(vec![CORE.to_owned(), MAIL.to_owned()])
        .with(mail_jmap::protocol::MethodCall::new(
            "Mailbox/get",
            json!({"accountId": "acct-personal"}),
        ));
    let error = client
        .call(&request)
        .expect_err("the hostile API URL is refused");
    assert!(matches!(error, JmapError::Trust(_)));
    // Only the session was fetched; the hostile endpoint was never called.
    assert_eq!(log.lock().map(|log| log.len()).unwrap_or_default(), 1);
}

#[test]
fn a_download_url_that_leaves_the_trusted_origin_is_refused() {
    let transport = FixtureTransport::new().on_get(
        "/jmap/session",
        serde_json::from_str(SESSION_HOSTILE).expect("a valid session"),
    );
    let mut client = client(transport);
    client
        .discover("https://api.example.com/jmap/session")
        .expect("the session is discovered");
    let error = client
        .download("http://169.254.169.254/jmap/download/a/b/c")
        .expect_err("the hostile download URL is refused");
    assert!(matches!(
        error,
        JmapError::Trust(TrustError::SchemeNotAllowed { .. })
    ));
}

#[test]
fn a_host_that_resolves_to_a_private_address_is_refused() {
    let transport = FixtureTransport::new().on_get(
        "/jmap/session",
        serde_json::from_str(SESSION).expect("a valid session"),
    );
    let mut client = JmapClient::new(Box::new(transport), policy()).with_resolver(Box::new(
        StaticResolver::new().with_host(
            "api.example.com",
            vec!["127.0.0.1".parse().expect("an address")],
        ),
    ));
    let error = client
        .discover("https://api.example.com/jmap/session")
        .expect_err("a private address is refused");
    assert!(matches!(
        error,
        JmapError::Trust(TrustError::PrivateAddress { .. })
    ));
}

#[test]
fn a_redirect_out_of_the_trusted_origin_is_refused() {
    let transport = FixtureTransport::new().on(
        "GET",
        "/jmap/session",
        mail_jmap::HttpResponse {
            status: 302,
            headers: vec![(
                "Location".to_owned(),
                "https://evil.example.net/jmap/session".to_owned(),
            )],
            body: Vec::new(),
        },
    );
    let mut client = client(transport);
    let error = client
        .discover("https://api.example.com/jmap/session")
        .expect_err("the redirect is refused");
    assert!(matches!(
        error,
        JmapError::Trust(TrustError::UntrustedRedirect { .. })
    ));
}

#[test]
fn a_revoked_credential_is_reported_as_needing_reauthorization() {
    let transport = FixtureTransport::new()
        .on_get(
            "/jmap/session",
            serde_json::from_str(SESSION).expect("a valid session"),
        )
        .on(
            "POST",
            "/jmap/api",
            mail_jmap::HttpResponse {
                status: 401,
                headers: Vec::new(),
                body: b"unauthorized".to_vec(),
            },
        );
    let mut client = client(transport);
    client
        .discover("https://api.example.com/jmap/session")
        .expect("the session is discovered");
    let request = mail_jmap::protocol::JmapRequest::new(vec![CORE.to_owned(), MAIL.to_owned()])
        .with(mail_jmap::protocol::MethodCall::new(
            "Mailbox/get",
            json!({"accountId": "acct-personal"}),
        ));
    let error = client
        .call(&request)
        .expect_err("the credential is refused");
    assert!(matches!(error, JmapError::NeedsAuthorization(_)));
}

#[test]
fn a_message_is_read_without_upstream_counts_or_snippets() {
    let (client, log) = discovered(transport());
    let mut reader = JmapReader::new(client, "acct-personal");
    let page = reader
        .list(
            &MailboxRef::new("INBOX"),
            &ListQuery {
                limit: 10,
                cursor: None,
            },
        )
        .expect("the page is read");

    assert_eq!(page.messages.len(), 1);
    let message = &page.messages[0];
    assert_eq!(message.id.as_str(), "M-email-1");
    assert_eq!(message.subject.as_deref(), Some("Invoice 2026"));
    assert_eq!(
        message.from.as_ref().map(|from| from.address.as_str()),
        Some("sender@example.com")
    );
    assert_eq!(message.attachments.len(), 1);
    assert_eq!(message.attachments[0].id, "B-blob-1");
    // A JMAP read establishes no trusted provenance, so an identity in
    // `verified` isolation fails closed.
    assert!(message.provenance.original_recipient.is_none());

    let bodies = bodies(&log);
    let query = bodies
        .iter()
        .find(|body| body.contains("Email/query"))
        .expect("the upstream was queried");
    assert!(query.contains("\"calculateTotal\":false"));
    assert!(!query.contains("\"text\""));
}

#[test]
fn the_account_identifier_never_reaches_the_message() {
    let (client, _log) = discovered(transport());
    let mut reader = JmapReader::new(client, "acct-personal");
    let page = reader
        .list(
            &MailboxRef::new("INBOX"),
            &ListQuery {
                limit: 10,
                cursor: None,
            },
        )
        .expect("the page is read");
    let encoded = serde_json::to_string(&page.messages[0]).expect("the message is JSON");
    assert!(!encoded.contains("acct-personal"));
}

#[test]
fn an_attachment_is_downloaded_from_the_validated_url() {
    let transport = transport().on_get("/jmap/download", json!({"bytes": "aW52b2ljZSAyMDI2"}));
    let mut reader = JmapReader::new(connected(transport), "acct-personal");
    let blob = reader
        .read_blob(&mail_core::BlobRequest {
            mailbox: MailboxRef::new("INBOX"),
            message_id: MessageId::new("M-email-1"),
            blob_id: "B-blob-1".to_owned(),
        })
        .expect("the blob is downloaded");
    assert!(!blob.bytes.is_empty());
}

#[test]
fn the_changes_of_one_mailbox_are_reported() {
    let transport = transport().on_post_body(
        "/jmap/api",
        "\"Email/queryChanges\"",
        envelope(
            "Email/queryChanges",
            "m0",
            serde_json::from_str(CHANGES).expect("valid"),
        ),
    );
    let mut tracker = JmapChangeTracker::new(connected(transport), "acct-personal");
    let changes = tracker
        .changes_since(&MailboxRef::new("INBOX"), None)
        .expect("the changes are reported");
    assert_eq!(changes.changes.len(), 3);
    assert_eq!(
        changes.next_cursor.map(|cursor| cursor.token),
        Some("state-2".to_owned())
    );
}

#[test]
fn a_state_the_upstream_cannot_compute_is_reported_as_invalid() {
    let transport = transport().on_post_body(
        "/jmap/api",
        "\"Email/queryChanges\"",
        envelope(
            "Email/queryChanges",
            "m0",
            serde_json::from_str(CHANGES_UNCOMPUTABLE).expect("valid"),
        ),
    );
    let mut tracker = JmapChangeTracker::new(connected(transport), "acct-personal");
    let error = tracker
        .changes_since(
            &MailboxRef::new("INBOX"),
            Some(&ChangeCursor {
                token: "state-1".to_owned(),
            }),
        )
        .expect_err("the state is invalid");
    assert!(matches!(error, TransportError::InvalidState(_)));
}

#[test]
fn a_submission_creates_a_message_and_then_sends_it() {
    let transport = transport()
        .on_post_body(
            "/jmap/api",
            "\"Identity/get\"",
            envelope(
                "Identity/get",
                "m0",
                serde_json::from_str(IDENTITIES).expect("valid"),
            ),
        )
        .on_post_body(
            "/jmap/api",
            "\"Email/set\"",
            envelope(
                "Email/set",
                "m0",
                serde_json::from_str(EMAIL_SET).expect("valid"),
            ),
        )
        .on_post_body(
            "/jmap/api",
            "\"EmailSubmission/set\"",
            envelope(
                "EmailSubmission/set",
                "m0",
                serde_json::from_str(SUBMISSION_SET).expect("valid"),
            ),
        );
    let (client, log) = discovered(transport);
    let mut submitter = JmapSubmitter::new(client, "acct-personal", "me@example.com");
    let receipt = submitter.submit(&message()).expect("the message is sent");
    assert!(receipt.accepted);
    assert_eq!(receipt.id, "S-submission-1");

    let bodies = bodies(&log);
    let submission = bodies
        .iter()
        .find(|body| body.contains("EmailSubmission/set"))
        .expect("the submission was sent");
    // The upstream identity comes from the session, never from the caller.
    assert!(submission.contains("id-personal"));
    assert!(submission.contains("me@example.com"));
    // The draft is created first, and the send is the submission: the
    // submission refers to the draft the upstream created.
    let create = bodies
        .iter()
        .position(|body| body.contains("\"Email/set\""))
        .expect("the message was created");
    let send = bodies
        .iter()
        .position(|body| body.contains("\"EmailSubmission/set\""))
        .expect("the message was sent");
    assert!(create < send);
    assert!(bodies[send].contains("M-draft-1"));
}

#[test]
fn a_refused_submission_is_not_a_success() {
    let transport = transport()
        .on_post_body(
            "/jmap/api",
            "\"Identity/get\"",
            envelope(
                "Identity/get",
                "m0",
                serde_json::from_str(IDENTITIES).expect("valid"),
            ),
        )
        .on_post_body(
            "/jmap/api",
            "\"Email/set\"",
            envelope(
                "Email/set",
                "m0",
                serde_json::from_str(EMAIL_SET).expect("valid"),
            ),
        )
        .on_post_body(
            "/jmap/api",
            "\"EmailSubmission/set\"",
            envelope(
                "EmailSubmission/set",
                "m0",
                serde_json::from_str(SUBMISSION_REFUSED).expect("valid"),
            ),
        );
    let (client, _log) = discovered(transport);
    let mut submitter = JmapSubmitter::new(client, "acct-personal", "me@example.com");
    let error = submitter
        .submit(&message())
        .expect_err("the upstream refused the submission");
    assert!(matches!(error, TransportError::Rejected(_)));
}

#[test]
fn a_submission_for_an_address_the_account_does_not_own_is_refused() {
    let transport = transport().on_post_body(
        "/jmap/api",
        "\"Identity/get\"",
        envelope(
            "Identity/get",
            "m0",
            serde_json::from_str(IDENTITIES).expect("valid"),
        ),
    );
    let (client, _log) = discovered(transport);
    let mut submitter = JmapSubmitter::new(client, "acct-personal", "unknown@example.com");
    let unknown = OutgoingMessage {
        sender: "unknown@example.com".to_owned(),
        ..message()
    };
    let error = submitter
        .submit(&unknown)
        .expect_err("the account has no such identity");
    assert!(matches!(error, TransportError::InvalidState(_)));
}

#[test]
fn an_ambiguous_submission_is_reported_as_unknown_and_is_not_retried() {
    let transport = transport()
        .on_post_body(
            "/jmap/api",
            "\"Identity/get\"",
            envelope(
                "Identity/get",
                "m0",
                serde_json::from_str(IDENTITIES).expect("valid"),
            ),
        )
        .on_post_body(
            "/jmap/api",
            "\"Email/set\"",
            envelope(
                "Email/set",
                "m0",
                serde_json::from_str(EMAIL_SET).expect("valid"),
            ),
        )
        .failing_body(
            "POST",
            "/jmap/api",
            Some("\"EmailSubmission/set\"".to_owned()),
            TransportError::Unavailable,
        );
    let (client, _log) = discovered(transport);
    let mut submitter = JmapSubmitter::new(client, "acct-personal", "me@example.com");
    let error = submitter
        .submit(&message())
        .expect_err("the outcome is unknown");
    assert!(matches!(error, TransportError::Ambiguous(_)));
}

#[test]
fn malformed_submission_response_is_ambiguous_after_dispatch() {
    let transport = transport()
        .on_post_body(
            "/jmap/api",
            "\"Identity/get\"",
            envelope(
                "Identity/get",
                "m0",
                serde_json::from_str(IDENTITIES).unwrap(),
            ),
        )
        .on_post_body(
            "/jmap/api",
            "\"Email/set\"",
            envelope("Email/set", "m0", serde_json::from_str(EMAIL_SET).unwrap()),
        )
        .on_post_body(
            "/jmap/api",
            "\"EmailSubmission/set\"",
            json!({"methodResponses": []}),
        );
    let (client, _) = discovered(transport);
    let error = JmapSubmitter::new(client, "acct-personal", "me@example.com")
        .submit(&message())
        .expect_err("a dispatched submission with an unusable response has unknown outcome");
    assert!(matches!(error, TransportError::Ambiguous(_)));
}

#[test]
fn a_jmap_failure_never_falls_back_to_another_protocol() {
    let transport = transport()
        .on_post_body(
            "/jmap/api",
            "\"Identity/get\"",
            envelope(
                "Identity/get",
                "m0",
                serde_json::from_str(IDENTITIES).expect("valid"),
            ),
        )
        .on_post_body(
            "/jmap/api",
            "\"Email/set\"",
            envelope(
                "Email/set",
                "m0",
                serde_json::from_str(EMAIL_SET).expect("valid"),
            ),
        )
        .failing_body(
            "POST",
            "/jmap/api",
            Some("\"EmailSubmission/set\"".to_owned()),
            TransportError::Unavailable,
        );
    let (client, log) = discovered(transport);
    let mut submitter = JmapSubmitter::new(client, "acct-personal", "me@example.com");
    let error = submitter
        .submit(&message())
        .expect_err("the upstream is unavailable");
    assert!(matches!(error, TransportError::Ambiguous(_)));

    // Every request went to the JMAP API endpoint, and none was repeated:
    // there is no second transport to fall back to.
    let requests = requests(&log);
    for request in &requests {
        assert!(
            request.url.contains("/jmap/"),
            "unexpected request to {}",
            request.url
        );
    }
    // The session, the identity lookup, the draft and the submission: four
    // requests, and no second attempt at any of them.
    assert_eq!(requests.len(), 4);
}

#[test]
fn a_session_object_is_parsed_into_a_validated_session() {
    let session = Session::parse(&serde_json::from_str(SESSION).expect("a valid session"))
        .expect("the session is valid");
    assert_eq!(session.accounts().len(), 2);
    assert!(session.accounts().contains_key("acct-readonly"));
    assert_eq!(
        session.download_url(),
        Some("https://api.example.com/jmap/download/{accountId}/{blobId}/{name}")
    );
    assert_eq!(
        session.event_source_url(),
        Some("https://api.example.com/jmap/events")
    );
}

#[test]
fn credential_debug_never_exposes_bearer_token() {
    let credential = Credential::bearer("sensitive-test-token");
    assert!(!format!("{credential:?}").contains("sensitive-test-token"));
    let http_request = HttpRequest {
        method: "GET".to_owned(),
        url: "https://example.test/".to_owned(),
        headers: vec![(
            "Authorization".to_owned(),
            "Bearer sensitive-test-token".to_owned(),
        )],
        body: Vec::new(),
    };
    assert!(!format!("{http_request:?}").contains("sensitive-test-token"));
}

#[test]
fn the_client_and_the_fixture_transport_never_expose_the_credential() {
    let transport = FixtureTransport::new().on_get(
        "/jmap/session",
        serde_json::from_str(SESSION).expect("a valid session"),
    );
    // The clone shares the request log, so it shows what the client sent.
    let handle = transport.clone();
    let (client, log) = discovered(transport);

    // The client holds the credential and the transport that carries it.
    let client_debug = format!("{client:?}");
    assert!(
        !client_debug.contains("upstream-token"),
        "the client debug output leaks the credential: {client_debug}"
    );

    // The fixture transport keeps the requests it was given, and they carry
    // the credential.
    let transport_debug = format!("{handle:?}");
    assert!(
        !transport_debug.contains("upstream-token"),
        "the transport debug output leaks the credential: {transport_debug}"
    );

    // The recorded requests carry it too.
    let logged = requests(&log);
    assert_eq!(logged.len(), 1);
    let log_debug = format!("{logged:?}");
    assert!(
        !log_debug.contains("upstream-token"),
        "the request log leaks the credential: {log_debug}"
    );
}

#[test]
fn an_unusable_submission_response_is_ambiguous_after_dispatch() {
    let transport = transport()
        .on_post_body(
            "/jmap/api",
            "\"Identity/get\"",
            envelope(
                "Identity/get",
                "m0",
                serde_json::from_str(IDENTITIES).expect("valid"),
            ),
        )
        .on_post_body(
            "/jmap/api",
            "\"Email/set\"",
            envelope(
                "Email/set",
                "m0",
                serde_json::from_str(EMAIL_SET).expect("valid"),
            ),
        )
        .on(
            "POST",
            "/jmap/api",
            mail_jmap::HttpResponse {
                status: 200,
                headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
                // A truncated body: the upstream may have accepted the
                // submission and lost the answer.
                body: b"{\"methodResponses\":".to_vec(),
            },
        );
    let (client, _log) = discovered(transport);
    let error = JmapSubmitter::new(client, "acct-personal", "me@example.com")
        .submit(&message())
        .expect_err("a dispatched submission with an unusable body has an unknown outcome");
    assert!(matches!(error, TransportError::Ambiguous(_)));
}

#[test]
fn a_method_level_error_response_is_a_definite_refusal() {
    let transport = transport()
        .on_post_body(
            "/jmap/api",
            "\"Identity/get\"",
            envelope(
                "Identity/get",
                "m0",
                serde_json::from_str(IDENTITIES).expect("valid"),
            ),
        )
        .on_post_body(
            "/jmap/api",
            "\"Email/set\"",
            envelope(
                "Email/set",
                "m0",
                serde_json::from_str(EMAIL_SET).expect("valid"),
            ),
        )
        .on_post_body(
            "/jmap/api",
            "\"EmailSubmission/set\"",
            json!({"methodResponses": [["error", {"type": "notFound"}, "m0"]]}),
        );
    let (client, _log) = discovered(transport);
    let error = JmapSubmitter::new(client, "acct-personal", "me@example.com")
        .submit(&message())
        .expect_err("the upstream refused the submission");
    assert!(
        matches!(error, TransportError::Rejected(_)),
        "a method-level error is a refusal, not an unknown outcome: {error:?}"
    );
}

#[test]
fn list_rejects_a_message_outside_the_requested_mailbox() {
    let transport = FixtureTransport::new()
        .on_get("/jmap/session", serde_json::from_str(SESSION).unwrap())
        .on_post_body(
            "/jmap/api",
            "\"Mailbox/get\"",
            envelope(
                "Mailbox/get",
                "m0",
                json!({"list": [{"id": "work-id", "name": "WORK"}]}),
            ),
        )
        .on_post_body(
            "/jmap/api",
            "\"Email/query\"",
            envelope("Email/query", "m0", json!({"ids": ["m1"]})),
        )
        .on_post_body(
            "/jmap/api",
            "\"Email/get\"",
            envelope(
                "Email/get",
                "m1",
                // The upstream answers with a message that lives in another
                // mailbox.
                json!({"list": [{"id": "m1", "mailboxIds": {"other-id": true}}]}),
            ),
        );
    let mut client = connected(transport);
    let page = mail_jmap::reader::list_messages(
        &mut client,
        "acct-personal",
        &MailboxRef::new("WORK"),
        &ListQuery {
            limit: 10,
            cursor: None,
        },
        &mail_jmap::transport::TransportLimits::default(),
    )
    .expect("the page is read");
    assert!(
        page.messages.is_empty(),
        "a message outside the requested mailbox is not disclosed: {:?}",
        page.messages
    );
}

#[test]
fn a_transport_without_address_pinning_fails_closed() {
    let transport = FixtureTransport::new()
        .without_address_pinning()
        .on_get("/jmap/session", serde_json::from_str(SESSION).unwrap());
    let mut client = client(transport);
    let error = client
        .discover("https://api.example.com/jmap/session")
        .expect_err("a transport that cannot pin the validated address is refused");
    assert!(
        matches!(error, JmapError::Rejected(_)),
        "the pinning gate fails closed: {error:?}"
    );
}

#[test]
fn the_attachment_properties_are_requested() {
    let (client, log) = discovered(transport());
    let mut reader = JmapReader::new(client, "acct-personal");
    let page = reader
        .list(
            &MailboxRef::new("INBOX"),
            &ListQuery {
                limit: 10,
                cursor: None,
            },
        )
        .expect("the page is read");

    let bodies = bodies(&log);
    let get = bodies
        .iter()
        .find(|body| body.contains("\"Email/get\""))
        .expect("the upstream was asked for the messages");
    assert!(
        get.contains("\"attachments\""),
        "the attachment properties are requested: {get}"
    );
    let attachment = &page.messages[0].attachments[0];
    assert_eq!(attachment.id, "B-blob-1");
    assert_eq!(attachment.filename.as_deref(), Some("invoice.txt"));
    assert_eq!(attachment.content_type.as_deref(), Some("text/plain"));
    assert_eq!(attachment.size, 17);
}

#[test]
fn get_rejects_message_outside_requested_mailbox() {
    let transport = FixtureTransport::new()
        .on_get("/jmap/session", serde_json::from_str(SESSION).unwrap())
        .on_post_body(
            "/jmap/api",
            "\"Mailbox/get\"",
            envelope(
                "Mailbox/get",
                "m0",
                json!({"list": [{"id":"work-id", "name":"WORK"}]}),
            ),
        )
        .on_post_body(
            "/jmap/api",
            "\"Email/get\"",
            envelope(
                "Email/get",
                "m0",
                json!({"list": [{"id":"m1", "mailboxIds":{"inbox-id":true}}]}),
            ),
        );
    let mut client = connected(transport);
    assert!(matches!(
        mail_jmap::reader::get_message(
            &mut client,
            "acct-personal",
            &MailboxRef::new("WORK"),
            &MessageId::new("m1")
        ),
        Err(JmapError::NotFound)
    ));
}
