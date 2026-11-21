//! Fixture-driven tests for the SMTP adapter.
//!
//! The adapter is driven against scripted server responses, so the protocol
//! logic is exercised without a network and every server behaviour is
//! visible in the test itself.

use mail_core::testing::ScriptedStream;
use mail_core::{MailSubmitter, OutgoingMessage, TransportError, TransportLimits};
use mail_smtp::{SmtpSession, SmtpSubmitter};

/// Build a stream that replays the given responses.
fn stream(responses: &[&str]) -> ScriptedStream {
    ScriptedStream::new(responses.iter().map(|s| s.to_string()))
}

/// The responses a scripted server sends for a greeting and a capability
/// exchange.
fn greeting() -> Vec<String> {
    vec![
        "220 smtp.example.test ESMTP ready".to_owned(),
        "250-smtp.example.test".to_owned(),
        "250 SIZE 52428800".to_owned(),
    ]
}

/// A message addressed from one identity to one recipient.
fn message() -> OutgoingMessage {
    OutgoingMessage {
        sender: "me@example.test".to_owned(),
        recipients: vec!["you@example.test".to_owned()],
        subject: Some("Hello".to_owned()),
        headers: Vec::new(),
        body: "Body".to_owned(),
    }
}

#[test]
fn a_greeting_that_is_not_a_positive_reply_refuses_the_session() {
    let mut stream = stream(&["554 no service here"]);
    let mut session = SmtpSession::new(&mut stream, TransportLimits::default());
    assert!(matches!(session.greet(), Err(TransportError::Rejected(_))));
}

#[test]
fn the_capabilities_are_recorded() {
    let responses = greeting();
    let borrowed: Vec<&str> = responses.iter().map(String::as_str).collect();
    let mut stream = stream(&borrowed);
    let mut session = SmtpSession::new(&mut stream, TransportLimits::default());
    session.greet().unwrap();
    let capabilities = session.ehlo("client").unwrap();
    assert_eq!(capabilities.len(), 2);
    assert!(session.capabilities().iter().any(|c| c.contains("SIZE")));
}

#[test]
fn an_envelope_sender_that_is_not_the_identity_is_refused_before_any_write() {
    let mut stream = stream(&[]);
    let mut submitter = SmtpSubmitter::new(
        SmtpSession::new(&mut stream, TransportLimits::default()),
        "me@example.test",
        "client",
    );

    let mut wrong = message();
    wrong.sender = "someone-else@example.test".to_owned();
    let error = submitter.submit(&wrong).unwrap_err();
    assert!(
        matches!(error, TransportError::InvalidState(_)),
        "unexpected error: {error}"
    );
    // Nothing reached the wire.
    assert!(stream.written_text().is_empty());
}

#[test]
fn an_envelope_sender_that_differs_only_in_case_is_accepted() {
    let mut stream = stream(&["250 OK", "250 OK", "354 go ahead", "250 queued"]);
    let mut submitter = SmtpSubmitter::new(
        SmtpSession::new(&mut stream, TransportLimits::default()),
        "me@example.test",
        "client",
    );

    let mut same = message();
    same.sender = "Me@Example.test".to_owned();
    assert!(submitter.submit(&same).unwrap().accepted);
}

#[test]
fn a_message_with_no_recipients_is_refused() {
    let mut stream = stream(&[]);
    let mut submitter = SmtpSubmitter::new(
        SmtpSession::new(&mut stream, TransportLimits::default()),
        "me@example.test",
        "client",
    );

    let mut empty = message();
    empty.recipients.clear();
    assert!(matches!(
        submitter.submit(&empty),
        Err(TransportError::InvalidState(_))
    ));
    assert!(stream.written_text().is_empty());
}

#[test]
fn a_submission_writes_the_expected_commands() {
    let mut stream = stream(&["250 OK", "250 OK", "354 go ahead", "250 queued"]);
    let mut submitter = SmtpSubmitter::new(
        SmtpSession::new(&mut stream, TransportLimits::default()),
        "me@example.test",
        "client",
    );

    let receipt = submitter.submit(&message()).unwrap();
    assert!(receipt.accepted);

    let written = stream.written_text();
    assert!(written.contains("MAIL FROM:<me@example.test>"));
    assert!(written.contains("RCPT TO:<you@example.test>"));
    assert!(written.contains("DATA"));
    assert!(written.contains("Subject: Hello"));
    assert!(written.ends_with(".\r\n"));
}

/// A recipient that carries a newline cannot append a command of its own.
#[test]
fn a_recipient_that_could_inject_a_command_is_refused() {
    let mut stream = stream(&[]);
    let mut submitter = SmtpSubmitter::new(
        SmtpSession::new(&mut stream, TransportLimits::default()),
        "me@example.test",
        "client",
    );

    let mut injected = message();
    injected.recipients = vec!["victim@example.test\r\nRCPT TO:<other@example.test>".to_owned()];
    assert!(matches!(
        submitter.submit(&injected),
        Err(TransportError::InvalidState(_))
    ));
    assert!(stream.written_text().is_empty());
}

/// A body line that is a single dot cannot terminate the message early.
#[test]
fn a_body_that_looks_like_the_terminator_is_stuffed() {
    let mut stream = stream(&["250 OK", "250 OK", "354 go ahead", "250 queued"]);
    let mut submitter = SmtpSubmitter::new(
        SmtpSession::new(&mut stream, TransportLimits::default()),
        "me@example.test",
        "client",
    );

    let mut dotted = message();
    dotted.body = "before\r\n.hidden\r\nafter".to_owned();
    submitter.submit(&dotted).unwrap();

    let written = stream.written_text();
    assert!(written.contains("..hidden"));
    assert!(written.ends_with(".\r\n"));
}

#[test]
fn a_message_beyond_the_size_limit_is_refused() {
    let mut stream = stream(&[]);
    let limits = TransportLimits {
        max_message_bytes: 64,
        ..TransportLimits::default()
    };
    let mut submitter = SmtpSubmitter::new(
        SmtpSession::new(&mut stream, limits),
        "me@example.test",
        "client",
    );

    let mut large = message();
    large.body = "x".repeat(4096);
    assert!(matches!(
        submitter.submit(&large),
        Err(TransportError::TooLarge { .. })
    ));
    assert!(stream.written_text().is_empty());
}

#[test]
fn a_rejected_recipient_yields_an_unaccepted_receipt() {
    let mut stream = stream(&["250 OK", "550 no such user"]);
    let mut submitter = SmtpSubmitter::new(
        SmtpSession::new(&mut stream, TransportLimits::default()),
        "me@example.test",
        "client",
    );

    let receipt = submitter.submit(&message()).unwrap();
    assert!(!receipt.accepted);
    assert!(receipt.rejection.is_some());
}

#[test]
fn a_rejected_message_is_reported_as_a_refusal() {
    let mut stream = stream(&["250 OK", "250 OK", "354 go ahead", "550 message rejected"]);
    let mut submitter = SmtpSubmitter::new(
        SmtpSession::new(&mut stream, TransportLimits::default()),
        "me@example.test",
        "client",
    );

    let error = submitter.submit(&message()).unwrap_err();
    assert!(
        matches!(error, TransportError::Rejected(_)),
        "unexpected error: {error}"
    );
}

#[test]
fn a_deferred_message_is_reported_as_a_refusal() {
    let mut stream = stream(&["250 OK", "250 OK", "354 go ahead", "451 try later"]);
    let mut submitter = SmtpSubmitter::new(
        SmtpSession::new(&mut stream, TransportLimits::default()),
        "me@example.test",
        "client",
    );

    let error = submitter.submit(&message()).unwrap_err();
    assert!(
        matches!(error, TransportError::Rejected(_)),
        "unexpected error: {error}"
    );
    assert!(error.to_string().contains("deferred"));
}

/// An unparseable reply is a protocol error, not a silent success.
#[test]
fn an_unparseable_reply_is_refused() {
    let mut stream = stream(&["not a reply at all"]);
    let mut session = SmtpSession::new(&mut stream, TransportLimits::default());
    assert!(matches!(session.greet(), Err(TransportError::Protocol(_))));
}

#[test]
fn a_failed_authentication_is_reported_as_unauthorized() {
    let mut stream = stream(&["535 authentication failed"]);
    let mut session = SmtpSession::new(&mut stream, TransportLimits::default());
    assert!(matches!(
        session.auth_login("user", "secret"),
        Err(TransportError::Unauthorized)
    ));
}

/// The secret is sent to the server but never appears in an error.
#[test]
fn a_failed_authentication_leaks_no_secret() {
    let mut stream = stream(&["535 authentication failed"]);
    let mut session = SmtpSession::new(&mut stream, TransportLimits::default());
    let error = session.auth_login("user", "sup3r-s3cret").unwrap_err();
    assert!(!error.to_string().contains("sup3r-s3cret"));
}

#[test]
fn a_starttls_that_is_refused_stops_the_upgrade() {
    let mut stream = stream(&["454 TLS not available"]);
    let mut session = SmtpSession::new(&mut stream, TransportLimits::default());
    assert!(matches!(
        session.starttls(),
        Err(TransportError::Rejected(_))
    ));
}

/// A timeout is a bound, not a hint.
#[test]
fn an_expired_time_budget_fails_the_operation() {
    let mut stream = stream(&["220 ready"]);
    let limits = TransportLimits {
        io_timeout: std::time::Duration::ZERO,
        ..TransportLimits::default()
    };
    let mut session = SmtpSession::new(&mut stream, limits);
    assert!(matches!(session.greet(), Err(TransportError::Timeout)));
}
