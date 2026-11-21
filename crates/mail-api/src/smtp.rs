//! The SMTP AUTH submission adapter.
//!
//! ADR-0001 section 13 describes SMTP submission as "a legacy compatibility
//! listener with per-identity SMTP AUTH and strict server-side sender
//! enforcement", and ADR-0005 requires that it "calls the same
//! action/identity policy layer; it is not mapped into arbitrary MCP tool
//! calls". This module is that adapter: it speaks just enough SMTP to
//! accept an authenticated submission, and it hands the submission to the
//! same [`crate::service::Gateway`] pipeline the REST and MCP adapters use.
//!
//! Two rules shape the implementation:
//!
//! 1. The client authenticates with **SMTP AUTH**, naming the identity it
//!    wants to send as. The credential secret is checked against the
//!    configured credentials, and the credential must hold
//!    `mail:messages:send` **for that identity**. A credential that may
//!    send as one identity cannot send as another.
//! 2. The envelope sender is derived from the identity, not from the
//!    client. A `MAIL FROM` that names another address is refused, and a
//!    `From:` header that names another address is refused too, so a
//!    submission cannot impersonate an unauthorized sender.
//!
//! The listener speaks plaintext SMTP. TLS termination is a deployment
//! concern that ADR-0006 has not implemented; the binary therefore only
//! binds a loopback address for this listener.

use std::io::{BufRead, BufReader, Write};
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use crate::problem::Problem;
use crate::service::{Caller, Gateway};

/// The largest line the adapter accepts.
const MAX_LINE: usize = 8_192;

/// The largest message body the adapter accepts.
const MAX_BODY: usize = 1_000_000;

/// The greeting of the submission listener.
pub const GREETING: &str = "220 corvi-gateway ESMTP submission";

/// The result of one submission attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmtpOutcome {
    /// The message was accepted and a submission was recorded.
    Accepted {
        /// The identifier of the submission.
        submission_id: String,
    },
    /// The message was refused.
    Refused {
        /// The SMTP reply code.
        code: u16,
        /// The SMTP reply text.
        message: String,
    },
}

/// The state of one SMTP session.
#[derive(Debug)]
pub struct SmtpSession<'a> {
    gateway: &'a Gateway,
    caller: Option<Caller>,
    identity: Option<mail_core::IdentityId>,
    sender: Option<String>,
    recipients: Vec<String>,
}

impl<'a> SmtpSession<'a> {
    /// Start a session against a gateway.
    pub fn new(gateway: &'a Gateway) -> Self {
        Self {
            gateway,
            caller: None,
            identity: None,
            sender: None,
            recipients: Vec::new(),
        }
    }

    /// Whether the session has authenticated.
    pub fn is_authenticated(&self) -> bool {
        self.caller.is_some()
    }

    /// The identity the session sends as.
    pub fn identity(&self) -> Option<&mail_core::IdentityId> {
        self.identity.as_ref()
    }

    /// Run one session over a reader and a writer.
    ///
    /// The reader supplies the client's lines and the writer receives the
    /// replies. A session ends when the client quits or the connection
    /// fails; neither is an error the caller has to handle.
    pub fn serve<R: BufRead, W: Write>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
    ) -> std::io::Result<()> {
        writeln!(writer, "{GREETING}")?;
        writer.flush()?;
        loop {
            let mut line = String::new();
            let read = reader.read_line(&mut line)?;
            if read == 0 {
                return Ok(());
            }
            let line = line.trim_end_matches(['\r', '\n']);
            if line.len() > MAX_LINE {
                writeln!(writer, "500 5.5.2 Line too long")?;
                writer.flush()?;
                continue;
            }
            let (command, argument) = split_command(line);
            match command.to_ascii_uppercase().as_str() {
                "EHLO" => {
                    writeln!(
                        writer,
                        "250-corvi-gateway\r\n250-AUTH PLAIN\r\n250-8BITMIME\r\n250 SIZE 1048576"
                    )?;
                }
                "HELO" => {
                    writeln!(writer, "250 corvi-gateway")?;
                }
                "AUTH" => {
                    self.handle_auth(argument, reader, writer)?;
                }
                "MAIL" => {
                    self.handle_mail(argument, writer)?;
                }
                "RCPT" => {
                    self.handle_rcpt(argument, writer)?;
                }
                "DATA" => {
                    self.handle_data(reader, writer)?;
                }
                "RSET" => {
                    self.sender = None;
                    self.recipients.clear();
                    writeln!(writer, "250 2.0.0 Reset")?;
                }
                "NOOP" => {
                    writeln!(writer, "250 2.0.0 Ok")?;
                }
                "VRFY" | "EXPN" => {
                    writeln!(
                        writer,
                        "252 2.5.2 Cannot VRFY user, but will accept message"
                    )?;
                }
                "QUIT" => {
                    writeln!(writer, "221 2.0.0 Bye")?;
                    writer.flush()?;
                    return Ok(());
                }
                _ => {
                    writeln!(writer, "500 5.5.1 Command not recognized")?;
                }
            }
            writer.flush()?;
        }
    }

    /// Handle an `AUTH` command.
    fn handle_auth<R: BufRead, W: Write>(
        &mut self,
        argument: &str,
        reader: &mut R,
        writer: &mut W,
    ) -> std::io::Result<()> {
        if self.caller.is_some() {
            writeln!(writer, "503 5.5.1 Already authenticated")?;
            return Ok(());
        }
        let mut parts = argument.split_whitespace();
        let mechanism = parts.next().unwrap_or_default();
        if !mechanism.eq_ignore_ascii_case("PLAIN") {
            writeln!(writer, "504 5.5.4 Unrecognized authentication type")?;
            return Ok(());
        }
        let encoded = match parts.next() {
            Some(encoded) => encoded.to_owned(),
            None => {
                writeln!(writer, "334 ")?;
                writer.flush()?;
                let mut challenge = String::new();
                reader.read_line(&mut challenge)?;
                challenge.trim().to_owned()
            }
        };
        let decoded = match STANDARD.decode(encoded.as_bytes()) {
            Ok(decoded) => decoded,
            Err(_) => {
                writeln!(
                    writer,
                    "501 5.5.2 Cannot decode the authentication response"
                )?;
                return Ok(());
            }
        };
        let fields: Vec<&[u8]> = decoded.split(|byte| *byte == 0).collect();
        if fields.len() < 3 {
            writeln!(writer, "501 5.5.2 Malformed authentication response")?;
            return Ok(());
        }
        let username = String::from_utf8_lossy(fields[1]).to_string();
        let secret = String::from_utf8_lossy(fields[2]).to_string();
        match self.authenticate(&username, &secret) {
            Ok(()) => {
                writeln!(writer, "235 2.7.0 Authentication successful")?;
            }
            Err(problem) => {
                writeln!(writer, "535 5.7.8 {}", problem.error_code())?;
            }
        }
        Ok(())
    }

    /// Authenticate the session and select the identity it sends as.
    fn authenticate(&mut self, username: &str, secret: &str) -> Result<(), Problem> {
        let identity =
            mail_core::IdentityId::from_str(username).map_err(|_| Problem::unauthorized())?;
        let caller = self.gateway.authenticate(secret)?;
        match caller.grants().decide(&identity, mail_core::Action::Send) {
            mail_core::GrantDecision::Granted => {}
            mail_core::GrantDecision::ActionDenied => return Err(Problem::forbidden()),
            mail_core::GrantDecision::UnknownIdentity => return Err(Problem::not_found()),
        }
        self.caller = Some(caller);
        self.identity = Some(identity);
        Ok(())
    }

    /// Handle a `MAIL FROM` command.
    fn handle_mail<W: Write>(&mut self, argument: &str, writer: &mut W) -> std::io::Result<()> {
        if self.caller.is_none() {
            writeln!(writer, "530 5.7.0 Authentication required")?;
            return Ok(());
        }
        let Some(address) = address_of(argument, "FROM") else {
            writeln!(writer, "501 5.5.4 Syntax: MAIL FROM:<address>")?;
            return Ok(());
        };
        let Some(identity) = self.identity.clone() else {
            writeln!(writer, "530 5.7.0 Authentication required")?;
            return Ok(());
        };
        let Some(configured) = self.gateway.snapshot().identity(&identity).cloned() else {
            writeln!(writer, "550 5.1.0 No such identity")?;
            return Ok(());
        };
        if !configured.address.eq_ignore_ascii_case(&address) {
            // The envelope sender is the identity's own address. A client
            // that names another one is refused rather than rewritten, so
            // the client learns that it may not send as that address.
            writeln!(
                writer,
                "550 5.7.1 Sender address not authorized for this identity"
            )?;
            return Ok(());
        }
        self.sender = Some(address);
        self.recipients.clear();
        writeln!(writer, "250 2.1.0 Ok")?;
        Ok(())
    }

    /// Handle a `RCPT TO` command.
    fn handle_rcpt<W: Write>(&mut self, argument: &str, writer: &mut W) -> std::io::Result<()> {
        if self.sender.is_none() {
            writeln!(writer, "503 5.5.1 Need MAIL before RCPT")?;
            return Ok(());
        }
        let Some(address) = address_of(argument, "TO") else {
            writeln!(writer, "501 5.5.4 Syntax: RCPT TO:<address>")?;
            return Ok(());
        };
        if !address.contains('@') || address.chars().any(|character| character.is_control()) {
            writeln!(writer, "501 5.1.3 Bad recipient address syntax")?;
            return Ok(());
        }
        self.recipients.push(address);
        writeln!(writer, "250 2.1.5 Ok")?;
        Ok(())
    }

    /// Handle the `DATA` command and the message that follows it.
    fn handle_data<R: BufRead, W: Write>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
    ) -> std::io::Result<()> {
        if self.recipients.is_empty() {
            writeln!(writer, "503 5.5.1 Need RCPT before DATA")?;
            return Ok(());
        }
        writeln!(writer, "354 End data with <CR><LF>.<CR><LF>")?;
        writer.flush()?;
        let mut raw = String::new();
        let mut lines = Vec::new();
        loop {
            let mut line = String::new();
            let read = reader.read_line(&mut line)?;
            if read == 0 {
                break;
            }
            let line = line.trim_end_matches(['\r', '\n']);
            if line == "." {
                break;
            }
            // A leading dot is stuffed by the client and unstuffed here.
            let line = line.strip_prefix('.').unwrap_or(line);
            lines.push(line.to_owned());
            if raw.len() + line.len() > MAX_BODY {
                writeln!(writer, "552 5.3.4 Message body too large")?;
                self.sender = None;
                self.recipients.clear();
                return Ok(());
            }
            raw.push_str(line);
            raw.push('\n');
        }
        let (headers, body) = split_headers(&lines);
        if let Some(from) = headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("from"))
            .map(|(_, value)| value.clone())
        {
            if !from_matches(&from, self.sender.as_deref().unwrap_or_default()) {
                writeln!(
                    writer,
                    "550 5.7.1 Header From not authorized for this identity"
                )?;
                self.sender = None;
                self.recipients.clear();
                return Ok(());
            }
        }
        let subject = headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("subject"))
            .map(|(_, value)| value.clone())
            .unwrap_or_default();
        let outcome = self.submit(subject, body);
        match outcome {
            SmtpOutcome::Accepted { submission_id } => {
                writeln!(writer, "250 2.0.0 Ok: queued as {submission_id}")?;
            }
            SmtpOutcome::Refused { code, message } => {
                writeln!(writer, "{code} 5.7.0 {message}")?;
            }
        }
        self.sender = None;
        self.recipients.clear();
        Ok(())
    }

    /// Hand the message to the service pipeline.
    fn submit(&self, subject: String, body: String) -> SmtpOutcome {
        let (Some(caller), Some(identity)) = (self.caller.clone(), self.identity.clone()) else {
            return SmtpOutcome::Refused {
                code: 530,
                message: "AUTHENTICATION_REQUIRED".to_owned(),
            };
        };
        let recipients: Vec<crate::view::MailAddress> = self
            .recipients
            .iter()
            .map(|email| crate::view::MailAddress {
                email: email.clone(),
                name: None,
            })
            .collect();
        let request = crate::service::SendRequest {
            identity,
            to: recipients,
            cc: Vec::new(),
            bcc: Vec::new(),
            subject,
            text_body: body,
            // A client that speaks SMTP has no idempotency key, so the
            // submission is not replay suppressed. The submission is still
            // recorded, and its status is readable through the same API.
            idempotency_key: crate::time::random_id(),
            approval_required: false,
            approval: None,
        };
        match self.gateway.send_message(&caller, &request) {
            Ok(crate::service::SendOutcome::Submitted { submission, .. }) => {
                SmtpOutcome::Accepted {
                    submission_id: submission.id,
                }
            }
            Ok(crate::service::SendOutcome::ApprovalRequired(_)) => SmtpOutcome::Refused {
                code: 451,
                message: "SEND_REQUIRES_APPROVAL".to_owned(),
            },
            Err(problem) => SmtpOutcome::Refused {
                code: 550,
                message: problem.error_code().to_owned(),
            },
        }
    }
}

/// Accept SMTP sessions on a listener until the process ends.
///
/// The listener speaks plaintext SMTP and is only ever bound to a loopback
/// address, because TLS termination is not implemented. Each connection is
/// served on its own thread: the protocol is line oriented and a submission
/// is short, so a thread per connection is simpler than an async state
/// machine and keeps the adapter's rules in one place.
pub fn serve(
    gateway: std::sync::Arc<Gateway>,
    listener: std::net::TcpListener,
) -> std::io::Result<()> {
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(stream) => stream,
            Err(_) => continue,
        };
        let gateway = gateway.clone();
        std::thread::spawn(move || {
            let mut reader = match stream.try_clone() {
                Ok(clone) => BufReader::new(clone),
                Err(_) => return,
            };
            let mut writer = stream;
            let mut session = SmtpSession::new(&gateway);
            let _ = session.serve(&mut reader, &mut writer);
        });
    }
    Ok(())
}

/// Split a command line into its verb and its argument.
fn split_command(line: &str) -> (&str, &str) {
    match line.split_once(' ') {
        Some((command, argument)) => (command, argument.trim()),
        None => (line, ""),
    }
}

/// The address of a `MAIL FROM` or `RCPT TO` argument.
fn address_of(argument: &str, keyword: &str) -> Option<String> {
    let rest = argument.trim();
    let rest = rest
        .strip_prefix(&format!("{keyword}:"))
        .or_else(|| rest.strip_prefix(&format!("{keyword} :")))?;
    let rest = rest.trim();
    let address = rest.strip_prefix('<').unwrap_or(rest);
    let address = address.split('>').next().unwrap_or(address);
    let address = address.trim();
    if address.is_empty() {
        None
    } else {
        Some(address.to_owned())
    }
}

/// Split the message into its headers and its body.
fn split_headers(lines: &[String]) -> (Vec<(String, String)>, String) {
    let mut headers = Vec::new();
    let mut body = Vec::new();
    let mut in_body = false;
    for line in lines {
        if !in_body && line.is_empty() {
            in_body = true;
            continue;
        }
        if in_body {
            body.push(line.clone());
            continue;
        }
        match line.split_once(':') {
            Some((name, value)) => headers.push((name.trim().to_owned(), value.trim().to_owned())),
            None => headers.push((String::new(), line.clone())),
        }
    }
    (headers, body.join("\n"))
}

/// Whether a `From` header names the address the client may send as.
///
/// The header may carry a display name and several addresses, so every
/// address in it is compared and one mismatch refuses the message.
fn from_matches(header: &str, sender: &str) -> bool {
    let addresses: Vec<String> = header
        .split(',')
        .map(|part| part.trim())
        .filter_map(|part| {
            let without_name = match part.split_once('<') {
                Some((_, rest)) => rest.trim_end_matches('>').trim(),
                None => part,
            };
            if without_name.is_empty() {
                None
            } else {
                Some(without_name.to_owned())
            }
        })
        .collect();
    if addresses.is_empty() {
        return true;
    }
    addresses
        .iter()
        .all(|address| address.eq_ignore_ascii_case(sender))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_address_of_a_mail_from() {
        assert_eq!(
            address_of("FROM:<me@example.com>", "FROM"),
            Some("me@example.com".to_owned())
        );
        assert_eq!(
            address_of("TO:<someone@example.org> NOTIFY=NEVER", "TO"),
            Some("someone@example.org".to_owned())
        );
        assert_eq!(address_of("FROM:<>", "FROM"), None);
    }

    #[test]
    fn matches_a_from_header_with_a_display_name() {
        assert!(from_matches("Me <me@example.com>", "me@example.com"));
        assert!(!from_matches("Other <other@example.com>", "me@example.com"));
        assert!(!from_matches(
            "Me <me@example.com>, Other <other@example.com>",
            "me@example.com"
        ));
    }

    #[test]
    fn splits_headers_from_the_body() {
        let lines = vec![
            "Subject: Hello".to_owned(),
            "From: me@example.com".to_owned(),
            String::new(),
            "The body.".to_owned(),
        ];
        let (headers, body) = split_headers(&lines);
        assert_eq!(headers.len(), 2);
        assert_eq!(body, "The body.");
    }
}
