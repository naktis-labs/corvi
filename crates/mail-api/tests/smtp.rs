//! The SMTP AUTH submission adapter.
//!
//! These tests drive the adapter over an in-memory stream, so they exercise
//! the same session code the listener runs.

mod common;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::{ALL_ACTIONS, environment, two_identity_environment};
use mail_api::smtp::SmtpSession;

/// A session and the buffer it wrote to.
struct Session {
    gateway: mail_api::service::Gateway,
    output: Vec<u8>,
}

impl Session {
    /// Start a session against an environment's gateway.
    fn new(gateway: mail_api::service::Gateway) -> Self {
        Self {
            gateway,
            output: Vec::new(),
        }
    }

    /// Feed lines to the session and return the replies.
    fn run(&mut self, lines: &[&str]) -> String {
        let mut input = String::new();
        for line in lines {
            input.push_str(line);
            input.push_str("\r\n");
        }
        let mut reader = std::io::BufReader::new(input.as_bytes());
        let mut writer = std::io::Cursor::new(Vec::new());
        let mut session = SmtpSession::new(&self.gateway);
        session
            .serve(&mut reader, &mut writer)
            .expect("the session runs");
        let output = writer.into_inner();
        self.output = output.clone();
        String::from_utf8_lossy(&output).to_string()
    }
}

/// The base64 encoding of an SMTP AUTH PLAIN response.
fn plain(username: &str, secret: &str) -> String {
    STANDARD.encode(format!("\0{username}\0{secret}").as_bytes())
}

#[test]
fn an_unauthenticated_submission_is_refused() {
    let env = environment("smtp-auth", ALL_ACTIONS);
    let mut session = Session::new(env.gateway.clone());

    let replies = session.run(&[
        "EHLO client",
        "MAIL FROM:<me@example.com>",
        "RCPT TO:<someone@example.org>",
    ]);

    assert!(replies.contains("220 corvi-gateway"));
    assert!(replies.contains("530 5.7.0 Authentication required"));
    assert!(env.upstream.submissions().is_empty());
}

#[test]
fn an_authenticated_submission_reaches_the_upstream() {
    let env = environment("smtp-send", ALL_ACTIONS);
    let mut session = Session::new(env.gateway.clone());

    let replies = session.run(&[
        "EHLO client",
        &format!("AUTH PLAIN {}", plain("personal", "test-token")),
        "MAIL FROM:<me@example.com>",
        "RCPT TO:<someone@example.org>",
        "DATA",
        "Subject: Hello",
        "",
        "A body.",
        ".",
        "QUIT",
    ]);

    assert!(replies.contains("235 2.7.0 Authentication successful"));
    assert!(replies.contains("250 2.0.0 Ok: queued as"));

    let submissions = env.upstream.submissions();
    assert_eq!(submissions.len(), 1);
    assert_eq!(submissions[0].sender, "me@example.com");
    assert_eq!(submissions[0].recipients, vec!["someone@example.org"]);
    assert_eq!(submissions[0].subject.as_deref(), Some("Hello"));
    assert_eq!(submissions[0].body, "A body.");
}

#[test]
fn a_wrong_secret_is_refused() {
    let env = environment("smtp-wrong-secret", ALL_ACTIONS);
    let mut session = Session::new(env.gateway.clone());

    let replies = session.run(&[
        "EHLO client",
        &format!("AUTH PLAIN {}", plain("personal", "wrong")),
        "MAIL FROM:<me@example.com>",
    ]);

    assert!(replies.contains("535 5.7.8"));
    assert!(replies.contains("530 5.7.0 Authentication required"));
    assert!(env.upstream.submissions().is_empty());
}

#[test]
fn an_identity_the_credential_may_not_send_as_is_refused() {
    let env = environment("smtp-identity", ALL_ACTIONS);
    let mut session = Session::new(env.gateway.clone());

    let replies = session.run(&[
        "EHLO client",
        &format!("AUTH PLAIN {}", plain("work", "test-token")),
    ]);

    assert!(replies.contains("535 5.7.8"));
    assert!(env.upstream.submissions().is_empty());
}

#[test]
fn a_credential_that_may_send_as_another_identity_cannot_impersonate_it() {
    let env = two_identity_environment(
        "smtp-impersonation",
        ALL_ACTIONS,
        "          - mail:identities:list\n          - mail:messages:send\n",
    );
    let mut session = Session::new(env.gateway.clone());

    let replies = session.run(&[
        "EHLO client",
        &format!("AUTH PLAIN {}", plain("work", "test-token")),
        "MAIL FROM:<me@example.com>",
        "RCPT TO:<someone@example.org>",
    ]);

    // The credential may send as `work`, but the envelope sender it named
    // belongs to `personal`, so the submission is refused.
    assert!(replies.contains("235 2.7.0 Authentication successful"));
    assert!(replies.contains("550 5.7.1 Sender address not authorized"));
    assert!(env.upstream.submissions().is_empty());
}

#[test]
fn a_from_header_naming_another_address_is_refused() {
    let env = environment("smtp-from-header", ALL_ACTIONS);
    let mut session = Session::new(env.gateway.clone());

    let replies = session.run(&[
        "EHLO client",
        &format!("AUTH PLAIN {}", plain("personal", "test-token")),
        "MAIL FROM:<me@example.com>",
        "RCPT TO:<someone@example.org>",
        "DATA",
        "Subject: Hello",
        "From: someone-else@example.org",
        "",
        "A body.",
        ".",
    ]);

    assert!(replies.contains("550 5.7.1 Header From not authorized"));
    assert!(env.upstream.submissions().is_empty());
}

#[test]
fn the_session_reports_its_state() {
    let env = environment("smtp-state", ALL_ACTIONS);
    let mut session = SmtpSession::new(&env.gateway);
    let script = format!(
        "EHLO client\r\nAUTH PLAIN {}\r\n",
        plain("personal", "test-token")
    );
    let mut input = std::io::BufReader::new(script.as_bytes());
    let mut writer = std::io::Cursor::new(Vec::new());
    session
        .serve(&mut input, &mut writer)
        .expect("the session runs");

    assert!(session.is_authenticated());
    assert_eq!(
        session
            .identity()
            .map(|identity| identity.as_str().to_owned()),
        Some("personal".to_owned())
    );
}
