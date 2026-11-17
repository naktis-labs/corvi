//! Fixture-driven tests for the IMAP adapter.
//!
//! The adapter is driven against scripted server responses, so the protocol
//! logic is exercised without a network and every server behaviour is
//! visible in the test itself.

use mail_core::testing::ScriptedStream;
use mail_core::{
    IsolationMode, MailChangeTracker, MailIdentity, MailboxRef, TransportError, TransportLimits,
};
use mail_imap::{ImapReader, ImapSession, Mailbox};

/// A message the scripted server returns.
const RAW_MESSAGE: &str = concat!(
    "Subject: Invoice\r\n",
    "From: Billing <billing@invoices.example>\r\n",
    "To: me@example.test\r\n",
    "\r\n",
    "Body text"
);

/// Build a stream that replays the given responses.
fn stream(responses: &[&str]) -> ScriptedStream {
    ScriptedStream::new(responses.iter().map(|s| s.to_string()))
}

/// Limits with a generous page size.
fn limits() -> TransportLimits {
    TransportLimits {
        max_page_size: 100,
        ..TransportLimits::default()
    }
}

/// The responses a scripted server sends for a login and a select.
fn login_and_select(uidvalidity: u32) -> Vec<String> {
    vec![
        "* OK IMAP4rev1 server ready".to_owned(),
        "a0001 OK LOGIN completed".to_owned(),
        format!("* OK [UIDVALIDITY {uidvalidity}] UIDs valid"),
        format!("* {uidvalidity} EXISTS"),
        "a0002 OK SELECT completed".to_owned(),
    ]
}

#[test]
fn a_greeting_that_is_not_ok_refuses_the_session() {
    let mut stream = stream(&["* BYE server is closing"]);
    let mut session = ImapSession::new(&mut stream, limits());
    assert!(matches!(session.greet(), Err(TransportError::Rejected(_))));
}

#[test]
fn capabilities_are_recorded() {
    let mut stream = stream(&[
        "* OK ready",
        "* CAPABILITY IMAP4rev1 AUTH=PLAIN",
        "a0001 OK CAPABILITY completed",
    ]);
    let mut session = ImapSession::new(&mut stream, limits());
    session.greet().unwrap();
    let capabilities = session.capability().unwrap();
    assert!(capabilities.contains("IMAP4rev1"));
    assert!(capabilities.contains("AUTH=PLAIN"));
    assert!(session.capabilities().contains("AUTH=PLAIN"));
}

#[test]
fn a_login_is_sent_to_the_server_and_never_echoed() {
    let mut stream = stream(&["* OK ready", "a0001 OK LOGIN completed"]);
    let mut session = ImapSession::new(&mut stream, limits());
    session.greet().unwrap();
    session.login("user", "s3cret").unwrap();

    let written = stream.written_text();
    assert!(written.contains("a0001 LOGIN"));
    assert!(written.contains("user"));
    // The secret is sent to the server, but the adapter keeps no copy of it
    // and never puts it in an error.
    assert!(written.contains("s3cret"));
}

#[test]
fn a_rejected_login_is_an_error_and_leaks_no_secret() {
    let mut stream = stream(&["* OK ready", "a0001 NO LOGIN failed"]);
    let mut session = ImapSession::new(&mut stream, limits());
    session.greet().unwrap();
    let error = session.login("user", "s3cret-password").unwrap_err();
    let rendered = error.to_string();
    assert!(!rendered.contains("s3cret-password"), "leaked: {rendered}");
}

#[test]
fn select_records_the_uid_validity_value() {
    let responses = login_and_select(3857529045);
    let borrowed: Vec<&str> = responses.iter().map(String::as_str).collect();
    let mut stream = stream(&borrowed);
    let mut session = ImapSession::new(&mut stream, limits());
    session.greet().unwrap();
    session.login("user", "secret").unwrap();
    let state = session.select(&Mailbox::Inbox).unwrap();
    assert_eq!(state.uidvalidity, 3857529045);
    assert_eq!(state.exists, 3857529045);
    assert_eq!(session.uidvalidity(), Some(3857529045));
}

#[test]
fn a_select_that_reports_no_uid_validity_is_refused() {
    let mut stream = stream(&["* OK ready", "a0001 OK SELECT completed"]);
    let mut session = ImapSession::new(&mut stream, limits());
    session.greet().unwrap();
    // A server that does not report UIDVALIDITY leaves every UID ambiguous,
    // so the select fails rather than proceeding with unknown semantics.
    assert!(matches!(
        session.select(&Mailbox::Inbox),
        Err(TransportError::Protocol(_))
    ));
}

#[test]
fn a_fetched_message_is_projected_into_the_shared_model() {
    let responses = login_and_select(1);
    let mut script: Vec<String> = responses;
    script.push("* 1 FETCH (BODY[] ".to_owned());
    script.push(format!("{{{}}}", RAW_MESSAGE.len()));
    script.push(RAW_MESSAGE.to_owned());
    script.push(")".to_owned());
    script.push("a0003 OK UID FETCH completed".to_owned());
    let borrowed: Vec<&str> = script.iter().map(String::as_str).collect();

    let mut stream = stream(&borrowed);
    let mut session = ImapSession::new(&mut stream, limits());
    session.greet().unwrap();
    session.login("user", "secret").unwrap();
    session.select(&Mailbox::Named("INBOX".to_owned())).unwrap();
    let message = session.fetch(1).unwrap();

    assert_eq!(message.subject.as_deref(), Some("Invoice"));
    let from = message.from.expect("a sender");
    assert_eq!(from.address, "billing@invoices.example");
    assert_eq!(from.display_name.as_deref(), Some("Billing"));
    assert_eq!(message.to.len(), 1);
    assert_eq!(message.to[0].address, "me@example.test");
    assert_eq!(message.text_body.as_deref(), Some("Body text"));
}

/// IMAP records no provider envelope recipient, so a `verified` identity
/// cannot see a message read over IMAP.
#[test]
fn imap_records_no_delivery_provenance() {
    let responses = login_and_select(1);
    let mut script: Vec<String> = responses;
    script.push("* 1 FETCH (BODY[] ".to_owned());
    script.push(format!("{{{}}}", RAW_MESSAGE.len()));
    script.push(RAW_MESSAGE.to_owned());
    script.push(")".to_owned());
    script.push("a0003 OK UID FETCH completed".to_owned());
    let borrowed: Vec<&str> = script.iter().map(String::as_str).collect();

    let mut stream = stream(&borrowed);
    let mut session = ImapSession::new(&mut stream, limits());
    session.greet().unwrap();
    session.login("user", "secret").unwrap();
    session.select(&Mailbox::Named("INBOX".to_owned())).unwrap();
    let message = session.fetch(1).unwrap();

    assert!(message.provenance.original_recipient.is_none());
    assert!(message.provenance.delivery_route.is_none());

    let identity = MailIdentity {
        id: mail_core::IdentityId::new("alice"),
        mailbox: MailboxRef::new("INBOX"),
        address: "me@example.test".to_owned(),
        aliases: Vec::new(),
        display_name: None,
        isolation: IsolationMode::Verified,
    };
    // The message names the identity among its visible addresses, but that
    // is message-authored and therefore not delivery evidence.
    assert!(!identity.owns_message(&message.into_normalized()));
}

/// A `dedicated` identity owns the messages in its own mailbox.
#[test]
fn a_dedicated_identity_owns_the_messages_of_its_mailbox() {
    let responses = login_and_select(1);
    let mut script: Vec<String> = responses;
    script.push("* 1 FETCH (BODY[] ".to_owned());
    script.push(format!("{{{}}}", RAW_MESSAGE.len()));
    script.push(RAW_MESSAGE.to_owned());
    script.push(")".to_owned());
    script.push("a0003 OK UID FETCH completed".to_owned());
    let borrowed: Vec<&str> = script.iter().map(String::as_str).collect();

    let mut stream = stream(&borrowed);
    let mut session = ImapSession::new(&mut stream, limits());
    session.greet().unwrap();
    session.login("user", "secret").unwrap();
    session
        .select(&Mailbox::Named("account-a".to_owned()))
        .unwrap();
    let message = session.fetch(1).unwrap();

    let identity = MailIdentity {
        id: mail_core::IdentityId::new("alice"),
        mailbox: MailboxRef::new("account-a"),
        address: "me@example.test".to_owned(),
        aliases: Vec::new(),
        display_name: None,
        isolation: IsolationMode::Dedicated,
    };
    let normalized = message.into_normalized();
    assert!(identity.owns_message(&normalized));

    // The same message in another mailbox belongs to another identity.
    let other = MailIdentity {
        id: mail_core::IdentityId::new("bob"),
        mailbox: MailboxRef::new("account-b"),
        address: "other@example.test".to_owned(),
        aliases: Vec::new(),
        display_name: None,
        isolation: IsolationMode::Dedicated,
    };
    assert!(!other.owns_message(&normalized));
}

#[test]
fn a_literal_beyond_the_size_limit_is_refused() {
    let responses = login_and_select(1);
    let mut script: Vec<String> = responses;
    script.push("* 1 FETCH (BODY[] {999999999}".to_owned());
    let borrowed: Vec<&str> = script.iter().map(String::as_str).collect();

    let mut stream = stream(&borrowed);
    let mut session = ImapSession::new(&mut stream, limits());
    session.greet().unwrap();
    session.login("user", "secret").unwrap();
    session.select(&Mailbox::Inbox).unwrap();
    assert!(matches!(
        session.fetch(1),
        Err(TransportError::TooLarge { .. })
    ));
}

#[test]
fn a_malformed_message_is_a_protocol_error() {
    let responses = login_and_select(1);
    let mut script: Vec<String> = responses;
    let malformed = "this has no header separator";
    script.push("* 1 FETCH (BODY[] ".to_owned());
    script.push(format!("{{{}}}", malformed.len()));
    script.push(malformed.to_owned());
    script.push(")".to_owned());
    script.push("a0003 OK UID FETCH completed".to_owned());
    let borrowed: Vec<&str> = script.iter().map(String::as_str).collect();

    let mut stream = stream(&borrowed);
    let mut session = ImapSession::new(&mut stream, limits());
    session.greet().unwrap();
    session.login("user", "secret").unwrap();
    session.select(&Mailbox::Inbox).unwrap();
    assert!(matches!(session.fetch(1), Err(TransportError::Protocol(_))));
}

/// A UID is only meaningful within one validity value, so a change
/// invalidates the cursors held from before it.
#[test]
fn a_uid_validity_change_invalidates_a_held_cursor() {
    let mut script = login_and_select(1);
    // The mailbox is selected a second time and the server has renumbered it.
    script.push("* OK [UIDVALIDITY 2] UIDs valid".to_owned());
    script.push("a0003 OK SELECT completed".to_owned());
    let borrowed: Vec<&str> = script.iter().map(String::as_str).collect();

    let mut stream = stream(&borrowed);
    let mut session = ImapSession::new(&mut stream, limits());
    session.greet().unwrap();
    session.login("user", "secret").unwrap();

    let mut reader = ImapReader::new(session, Mailbox::Inbox);
    reader.open().unwrap();

    // The server renumbers the mailbox.
    reader.session().select(&Mailbox::Inbox).unwrap();

    let error = reader
        .changes_since(&MailboxRef::new("INBOX"), None)
        .unwrap_err();
    assert!(
        matches!(error, TransportError::InvalidState(_)),
        "unexpected error: {error}"
    );
}

#[test]
fn changes_since_reports_the_new_uids() {
    let mut script = login_and_select(1);
    script.push("* SEARCH 1 2 3".to_owned());
    script.push("a0003 OK UID SEARCH completed".to_owned());
    let borrowed: Vec<&str> = script.iter().map(String::as_str).collect();

    let mut stream = stream(&borrowed);
    let mut session = ImapSession::new(&mut stream, limits());
    session.greet().unwrap();
    session.login("user", "secret").unwrap();

    let mut reader = ImapReader::new(session, Mailbox::Inbox);
    reader.open().unwrap();

    let changes = reader
        .changes_since(&MailboxRef::new("INBOX"), None)
        .unwrap();
    assert_eq!(changes.changes.len(), 3);
    assert_eq!(changes.changes[0].id.as_str(), "1");
    let cursor = changes.next_cursor.expect("a cursor");
    assert_eq!(cursor.token, "3");
}

#[test]
fn a_malformed_cursor_is_refused() {
    let script = login_and_select(1);
    let borrowed: Vec<&str> = script.iter().map(String::as_str).collect();

    let mut stream = stream(&borrowed);
    let mut session = ImapSession::new(&mut stream, limits());
    session.greet().unwrap();
    session.login("user", "secret").unwrap();

    let mut reader = ImapReader::new(session, Mailbox::Inbox);
    reader.open().unwrap();

    let cursor = mail_core::ChangeCursor {
        token: "not-a-number".to_owned(),
    };
    assert!(matches!(
        reader.changes_since(&MailboxRef::new("INBOX"), Some(&cursor)),
        Err(TransportError::InvalidState(_))
    ));
}

/// A timeout is a bound, not a hint.
#[test]
fn an_expired_time_budget_fails_the_operation() {
    let mut stream = stream(&["* OK ready"]);
    let limits = TransportLimits {
        io_timeout: std::time::Duration::ZERO,
        ..TransportLimits::default()
    };
    let mut session = ImapSession::new(&mut stream, limits);
    assert!(matches!(session.greet(), Err(TransportError::Timeout)));
}

/// A response line beyond the limit is an error, not a truncated read.
#[test]
fn a_response_line_beyond_the_limit_is_refused() {
    let mut stream = stream(&["* OK a very long greeting that will not fit"]);
    let limits = TransportLimits {
        max_response_bytes: 8,
        ..TransportLimits::default()
    };
    let mut session = ImapSession::new(&mut stream, limits);
    assert!(matches!(
        session.greet(),
        Err(TransportError::TooLarge { .. })
    ));
}

/// A search that returns something other than numbers is a protocol error.
#[test]
fn a_search_returning_nonsense_is_refused() {
    let mut script = login_and_select(1);
    script.push("* SEARCH one two".to_owned());
    script.push("a0003 OK UID SEARCH completed".to_owned());
    let borrowed: Vec<&str> = script.iter().map(String::as_str).collect();

    let mut stream = stream(&borrowed);
    let mut session = ImapSession::new(&mut stream, limits());
    session.greet().unwrap();
    session.login("user", "secret").unwrap();
    session.select(&Mailbox::Inbox).unwrap();
    assert!(matches!(
        session.search("ALL"),
        Err(TransportError::Protocol(_))
    ));
}
