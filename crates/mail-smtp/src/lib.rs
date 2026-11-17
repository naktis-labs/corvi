//! The SMTP submission adapter.
//!
//! This crate submits a message to an upstream SMTP service. It is written
//! against the [`ByteStream`] abstraction rather than against a socket, so
//! the protocol logic can be exercised against recorded server behaviour and
//! so the TLS layer stays outside the protocol code.
//!
//! Four properties matter more than coverage of the protocol:
//!
//! 1. **The envelope sender is enforced, not requested.** A submitter is
//!    bound to one identity address. A message whose envelope sender is any
//!    other address is refused before a byte reaches the wire, because a
//!    submission that can choose its own envelope sender can send as any
//!    identity the upstream will accept.
//! 2. **The command channel is injection-safe.** Every value that reaches a
//!    command is validated: an address may not carry a space, a control
//!    character or a newline, so no caller-supplied value can terminate the
//!    command and append another one.
//! 3. **Bounds are enforced.** A message larger than the limit is refused
//!    before transmission, and every response line is bounded.
//! 4. **TLS is not optional.** An endpoint carries its TLS configuration, and
//!    there is no plaintext mode to fall back to.

use std::time::Instant;

use mail_core::{
    ByteStream, MailSubmitter, OutgoingMessage, SubmissionReceipt, TransportError, TransportLimits,
};

/// An SMTP session over a byte stream.
pub struct SmtpSession<'a> {
    stream: &'a mut dyn ByteStream,
    limits: TransportLimits,
    deadline: Option<Instant>,
    capabilities: Vec<String>,
    last_was_continuation: bool,
}

impl std::fmt::Debug for SmtpSession<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpSession")
            .field("limits", &self.limits)
            .field("capabilities", &self.capabilities)
            .finish_non_exhaustive()
    }
}

impl<'a> SmtpSession<'a> {
    /// Start a session over a stream.
    pub fn new(stream: &'a mut dyn ByteStream, limits: TransportLimits) -> Self {
        Self {
            stream,
            limits,
            deadline: None,
            capabilities: Vec::new(),
            last_was_continuation: false,
        }
    }

    /// The capabilities the server announced.
    pub fn capabilities(&self) -> &[String] {
        &self.capabilities
    }

    /// Read the server's greeting.
    ///
    /// A greeting that is not a positive reply means the server refused the
    /// connection, and the session is not usable.
    pub fn greet(&mut self) -> Result<(), TransportError> {
        self.begin_operation();
        let (code, _) = self.read_reply()?;
        if code != 220 {
            return Err(TransportError::Rejected(format!("greeting was {code}")));
        }
        Ok(())
    }

    /// Say hello and record the server's capabilities.
    pub fn ehlo(&mut self, name: &str) -> Result<Vec<String>, TransportError> {
        self.begin_operation();
        self.send(&format!("EHLO {}", validate_atom(name)?))?;
        self.read_greeting_multiline()
    }

    /// Say hello using the older verb, for a server without `EHLO`.
    pub fn helo(&mut self, name: &str) -> Result<(), TransportError> {
        self.begin_operation();
        self.send(&format!("HELO {}", validate_atom(name)?))?;
        let (code, _) = self.read_reply()?;
        if code != 250 {
            return Err(TransportError::Rejected(format!("HELO was {code}")));
        }
        Ok(())
    }

    /// Start a TLS upgrade.
    ///
    /// The caller performs the handshake once the server has accepted, so the
    /// protocol code stays free of certificate handling.
    pub fn starttls(&mut self) -> Result<(), TransportError> {
        self.begin_operation();
        self.send("STARTTLS")?;
        let (code, _) = self.read_reply()?;
        if code != 220 {
            return Err(TransportError::Rejected(format!("STARTTLS was {code}")));
        }
        Ok(())
    }

    /// Authenticate with a username and secret.
    ///
    /// The secret is written to the stream and is never retained, logged or
    /// included in an error.
    pub fn auth_login(&mut self, user: &str, secret: &str) -> Result<(), TransportError> {
        self.begin_operation();
        self.send(&format!(
            "AUTH PLAIN {}",
            base64(format!("\0{user}\0{secret}").as_bytes())
        ))?;
        let (code, _) = self.read_reply()?;
        match code {
            235 => Ok(()),
            535 | 538 => Err(TransportError::Unauthorized),
            _ => Err(TransportError::Rejected(format!(
                "authentication was {code}"
            ))),
        }
    }

    /// Begin a message, naming the envelope sender.
    pub fn mail_from(&mut self, sender: &str) -> Result<(), TransportError> {
        self.begin_operation();
        self.send(&format!("MAIL FROM:<{}>", validate_address(sender)?))?;
        self.expect(250)
    }

    /// Name one envelope recipient.
    pub fn rcpt_to(&mut self, recipient: &str) -> Result<(), TransportError> {
        self.begin_operation();
        self.send(&format!("RCPT TO:<{}>", validate_address(recipient)?))?;
        self.expect(250)
    }

    /// Send the message body.
    ///
    /// The body is dot-stuffed, so a line consisting of a single dot cannot
    /// terminate the message early.
    pub fn data(&mut self, body: &str) -> Result<(), TransportError> {
        self.begin_operation();
        if body.len() as u64 > self.limits.max_message_bytes {
            return Err(TransportError::TooLarge {
                limit: self.limits.max_message_bytes,
            });
        }
        self.send("DATA")?;
        self.expect(354)?;

        let mut payload = Vec::with_capacity(body.len() + 16);
        for line in body.split('\n') {
            let line = line.strip_suffix('\r').unwrap_or(line);
            if line.starts_with('.') {
                payload.push(b'.');
            }
            payload.extend_from_slice(line.as_bytes());
            payload.extend_from_slice(b"\r\n");
        }
        // The terminating dot is on its own line.
        payload.extend_from_slice(b".\r\n");
        self.stream.write(&payload)?;

        let (code, lines) = self.read_reply()?;
        let text = lines.join("; ");
        match code {
            250 => Ok(()),
            450..=452 => Err(TransportError::Rejected(format!(
                "message was deferred: {text}"
            ))),
            _ => Err(TransportError::Rejected(format!(
                "message was refused: {text}"
            ))),
        }
    }

    /// End the session.
    pub fn quit(&mut self) -> Result<(), TransportError> {
        self.begin_operation();
        self.send("QUIT")?;
        let _ = self.read_reply();
        Ok(())
    }

    /// Read a greeting that may span several lines.
    ///
    /// Every line of the reply is a capability in its own right, so the whole
    /// reply is returned rather than only its last line.
    fn read_greeting_multiline(&mut self) -> Result<Vec<String>, TransportError> {
        let (code, lines) = self.read_reply()?;
        if code != 250 {
            return Err(TransportError::Rejected(format!("EHLO was {code}")));
        }
        self.capabilities = lines.clone();
        Ok(lines)
    }

    /// Start a timed operation.
    fn begin_operation(&mut self) {
        self.deadline = Some(Instant::now() + self.limits.io_timeout);
    }

    /// Write a command.
    fn send(&mut self, command: &str) -> Result<(), TransportError> {
        self.stream.write(format!("{command}\r\n").as_bytes())
    }

    /// Read one reply, returning its code and every line of its text.
    ///
    /// A multiline reply is read to its end here, so a caller sees every
    /// line the server sent rather than only the last one.
    fn read_reply(&mut self) -> Result<(u16, Vec<String>), TransportError> {
        let mut lines = Vec::new();
        loop {
            let line = self.read_line()?;
            let Some((code, rest)) = parse_reply(&line) else {
                return Err(TransportError::Protocol(format!(
                    "unparseable reply: {line}"
                )));
            };
            lines.push(rest.to_owned());
            // A hyphen after the code means another line follows.
            let continuation = line.as_bytes().get(3) == Some(&b'-');
            self.last_was_continuation = continuation;
            if !continuation {
                return Ok((code, lines));
            }
        }
    }

    /// Expect a reply with exactly this code.
    fn expect(&mut self, expected: u16) -> Result<(), TransportError> {
        let (code, lines) = self.read_reply()?;
        if code == expected {
            Ok(())
        } else {
            Err(TransportError::Rejected(format!(
                "expected {expected}, got {code}: {}",
                lines.join("; ")
            )))
        }
    }

    /// Read one response line, enforcing the time and size bounds.
    fn read_line(&mut self) -> Result<String, TransportError> {
        if let Some(deadline) = self.deadline
            && Instant::now() >= deadline
        {
            return Err(TransportError::Timeout);
        }
        self.stream.read_line(self.limits.max_response_bytes)
    }
}

/// A submitter bound to one identity address.
///
/// The binding is the security-relevant part: the adapter will only submit
/// on behalf of the identity it was created for.
#[derive(Debug)]
pub struct SmtpSubmitter<'a> {
    session: SmtpSession<'a>,
    identity_address: String,
    helo_name: String,
}

impl<'a> SmtpSubmitter<'a> {
    /// Create a submitter for one identity.
    pub fn new(
        session: SmtpSession<'a>,
        identity_address: impl Into<String>,
        helo_name: impl Into<String>,
    ) -> Self {
        Self {
            session,
            identity_address: identity_address.into(),
            helo_name: helo_name.into(),
        }
    }

    /// The identity address this submitter is bound to.
    pub fn identity_address(&self) -> &str {
        &self.identity_address
    }

    /// The inner session.
    pub fn session(&mut self) -> &mut SmtpSession<'a> {
        &mut self.session
    }

    /// Say hello to the server.
    pub fn greet(&mut self) -> Result<(), TransportError> {
        self.session.greet()?;
        self.session.ehlo(&self.helo_name)?;
        Ok(())
    }
}

impl MailSubmitter for SmtpSubmitter<'_> {
    fn submit(&mut self, message: &OutgoingMessage) -> Result<SubmissionReceipt, TransportError> {
        // The envelope sender must be the identity the submitter is bound
        // to. This is checked before anything is written, so a mismatch
        // never reaches the upstream.
        if !same_address(&message.sender, &self.identity_address) {
            return Err(TransportError::InvalidState(
                "the envelope sender is not the authorized identity".to_owned(),
            ));
        }
        if message.recipients.is_empty() {
            return Err(TransportError::InvalidState(
                "the message has no envelope recipients".to_owned(),
            ));
        }

        // Every envelope value is validated before a single command is
        // written, so a value that could inject a command is refused
        // before it reaches the wire rather than after `MAIL FROM` has
        // already been sent.
        validate_address(&message.sender)?;
        for recipient in &message.recipients {
            validate_address(recipient)?;
        }

        let body = render(message);
        if body.len() as u64 > self.session.limits.max_message_bytes {
            return Err(TransportError::TooLarge {
                limit: self.session.limits.max_message_bytes,
            });
        }

        self.session.mail_from(&message.sender)?;
        let mut accepted = Vec::new();
        let mut rejection = None;
        for recipient in &message.recipients {
            match self.session.rcpt_to(recipient) {
                Ok(()) => accepted.push(recipient.clone()),
                Err(error) => {
                    rejection = Some(error.to_string());
                    break;
                }
            }
        }
        if accepted.is_empty() {
            return Ok(SubmissionReceipt {
                id: String::new(),
                accepted: false,
                rejection,
            });
        }

        self.session.data(&body)?;
        Ok(SubmissionReceipt {
            id: format!("{}-{}", self.identity_address, accepted.len()),
            accepted: true,
            rejection,
        })
    }
}

/// Render an outgoing message as an RFC 5322 document.
fn render(message: &OutgoingMessage) -> String {
    let mut out = String::new();
    out.push_str("From: ");
    out.push_str(&message.sender);
    out.push_str("\r\n");
    if let Some(subject) = &message.subject {
        out.push_str("Subject: ");
        out.push_str(subject);
        out.push_str("\r\n");
    }
    for (name, value) in &message.headers {
        out.push_str(name);
        out.push_str(": ");
        out.push_str(value);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    out.push_str(&message.body);
    out
}

/// Whether two addresses are the same.
///
/// Comparison is case-insensitive on the whole address, which is what SMTP
/// itself requires of the local part.
fn same_address(left: &str, right: &str) -> bool {
    left.trim().eq_ignore_ascii_case(right.trim())
}

/// Validate a value that reaches an SMTP command as an atom.
///
/// An atom may not contain a space or a control character, so a value that
/// passes this check cannot terminate its command.
fn validate_atom(value: &str) -> Result<&str, TransportError> {
    if value.is_empty() {
        return Err(TransportError::InvalidState(
            "an empty value is not valid".to_owned(),
        ));
    }
    if value.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(TransportError::InvalidState(
            "a value may not contain whitespace or control characters".to_owned(),
        ));
    }
    Ok(value)
}

/// Validate an address that reaches an SMTP command.
///
/// An address may not contain a space, a control character, an angle bracket
/// or a newline, so it cannot close its own command and start another.
///
/// A value carrying a control character is refused rather than trimmed. A
/// newline at the end of an address would otherwise be silently removed,
/// which would mean the envelope sender was quietly rewritten; refusing it
/// keeps the address that was authorized the address that is sent.
fn validate_address(value: &str) -> Result<&str, TransportError> {
    if value.chars().any(|c| c.is_control()) {
        return Err(TransportError::InvalidState(
            "an address may not contain control characters".to_owned(),
        ));
    }
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(TransportError::InvalidState(
            "an empty address is not valid".to_owned(),
        ));
    }
    if trimmed
        .chars()
        .any(|c| c.is_whitespace() || c == '<' || c == '>')
    {
        return Err(TransportError::InvalidState(
            "an address may not contain whitespace or angle brackets".to_owned(),
        ));
    }
    Ok(trimmed)
}

/// Parse a reply into its code and text.
fn parse_reply(line: &str) -> Option<(u16, &str)> {
    let bytes = line.as_bytes();
    if bytes.len() < 3 || !bytes[..3].iter().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let code = line[..3].parse().ok()?;
    let rest = line[3..].trim_start_matches(['-', ' ']);
    Some((code, rest))
}

/// Encode bytes as base64.
///
/// The encoding is written out rather than pulled in as a dependency, because
/// the transport crates are held to a narrow dependency set and the encoding
/// is small enough to state here.
fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(triple >> 18 & 0x3f) as usize] as char);
        out.push(ALPHABET[(triple >> 12 & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(triple >> 6 & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(triple & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_reply() {
        assert_eq!(parse_reply("250 OK"), Some((250, "OK")));
        assert_eq!(parse_reply("250-SIZE 100"), Some((250, "SIZE 100")));
        assert_eq!(parse_reply("not a reply"), None);
    }

    #[test]
    fn rejects_an_address_that_could_inject_a_command() {
        for value in [
            "a@b.test\r\nRCPT TO:<victim@example.test>",
            "a@b.test evil",
            "a@b.test\r\n",
            "",
        ] {
            assert!(
                validate_address(value).is_err(),
                "value {value:?} was accepted"
            );
        }
    }

    #[test]
    fn rejects_an_atom_that_could_inject_a_command() {
        assert!(validate_atom("client").is_ok());
        assert!(validate_atom("client evil").is_err());
        assert!(validate_atom("").is_err());
    }

    #[test]
    fn base64_matches_the_known_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
        assert_eq!(base64(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn renders_a_message_with_its_headers() {
        let message = OutgoingMessage {
            sender: "me@example.test".to_owned(),
            recipients: vec!["you@example.test".to_owned()],
            subject: Some("Hello".to_owned()),
            headers: vec![("X-Test".to_owned(), "1".to_owned())],
            body: "Body".to_owned(),
        };
        let rendered = render(&message);
        assert!(rendered.starts_with("From: me@example.test\r\n"));
        assert!(rendered.contains("Subject: Hello\r\n"));
        assert!(rendered.contains("X-Test: 1\r\n"));
        assert!(rendered.ends_with("\r\n\r\nBody"));
    }

    #[test]
    fn addresses_are_compared_case_insensitively() {
        assert!(same_address("Me@Example.test", "me@example.test"));
        assert!(!same_address("me@example.test", "other@example.test"));
    }
}
