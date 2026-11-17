//! The IMAP adapter.
//!
//! This crate speaks enough of IMAP4rev1 to read a mailbox and nothing more.
//! It is deliberately written against the [`ByteStream`] abstraction rather
//! than against a socket, so the protocol logic can be exercised against
//! recorded server behaviour and so the TLS layer stays outside the protocol
//! code.
//!
//! Three properties matter more than coverage of the protocol:
//!
//! 1. **The server is not trusted.** Everything it sends is parsed into
//!    bounded structures, and nothing it says is recorded as delivery
//!    evidence.
//! 2. **Bounds are enforced.** A response line that exceeds the configured
//!    limit is an error, not a truncated read, because a truncated response
//!    parses as a different response.
//! 3. **Provenance fails closed.** IMAP does not carry provider-recorded
//!    envelope recipients, so this adapter never fabricates any. An identity
//!    in `verified` isolation mode therefore cannot see messages read over
//!    IMAP unless the caller supplies evidence from a source that does
//!    record it.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use mail_core::mime::{self, MimeLimits};
use mail_core::{
    ByteStream, Change, ChangeCursor, ChangeKind, ChangeSet, ListQuery, MailChangeTracker,
    MailReader, MessageId, MessagePage, TransportError, TransportLimits, UntrustedMessage,
};

/// The mailbox a session reports when none has been selected.
///
/// A message fetched before a successful `SELECT` cannot be attributed to a
/// mailbox, so it is attributed to the server's default rather than to a
/// mailbox that was never chosen.
const DEFAULT_MAILBOX: &str = "INBOX";

/// How a mailbox is addressed to the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mailbox {
    /// A mailbox by name.
    Named(String),
    /// The server's `INBOX`.
    Inbox,
}

impl Mailbox {
    /// The name as the server knows it.
    pub fn name(&self) -> &str {
        match self {
            Mailbox::Inbox => "INBOX",
            Mailbox::Named(name) => name,
        }
    }
}

/// The state of a selected mailbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailboxState {
    /// The mailbox's UID validity value.
    ///
    /// UIDs are only meaningful within one validity value. A server that
    /// changes it has renumbered the mailbox, and every UID held from before
    /// the change now refers to a different message.
    pub uidvalidity: u32,
    /// How many messages the mailbox holds.
    pub exists: u32,
}

/// An IMAP session over a byte stream.
pub struct ImapSession<'a> {
    stream: &'a mut dyn ByteStream,
    limits: TransportLimits,
    mime_limits: MimeLimits,
    next_tag: u32,
    capabilities: BTreeSet<String>,
    uidvalidity: Option<u32>,
    /// The name of the selected mailbox.
    ///
    /// A fetched message is stamped with this, because identity isolation
    /// compares a message's mailbox against the identity's own mailbox.
    mailbox: Option<String>,
    deadline: Option<Instant>,
}

impl std::fmt::Debug for ImapSession<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImapSession")
            .field("limits", &self.limits)
            .field("capabilities", &self.capabilities)
            .field("uidvalidity", &self.uidvalidity)
            .finish_non_exhaustive()
    }
}

impl<'a> ImapSession<'a> {
    /// Start a session over a stream.
    pub fn new(stream: &'a mut dyn ByteStream, limits: TransportLimits) -> Self {
        Self {
            stream,
            limits,
            mime_limits: MimeLimits::default(),
            next_tag: 0,
            capabilities: BTreeSet::new(),
            uidvalidity: None,
            mailbox: None,
            deadline: None,
        }
    }

    /// The capabilities the server announced.
    pub fn capabilities(&self) -> &BTreeSet<String> {
        &self.capabilities
    }

    /// The UID validity value of the selected mailbox.
    pub fn uidvalidity(&self) -> Option<u32> {
        self.uidvalidity
    }

    /// Read the server's greeting.
    ///
    /// A greeting that is not an `OK` means the server refused the
    /// connection, and the session is not usable.
    pub fn greet(&mut self) -> Result<(), TransportError> {
        self.begin_operation();
        let line = self.read_line()?;
        if !is_positive_response(&line, "OK") {
            return Err(TransportError::Rejected(line));
        }
        Ok(())
    }

    /// Ask the server for its capabilities.
    pub fn capability(&mut self) -> Result<BTreeSet<String>, TransportError> {
        self.begin_operation();
        let tag = self.next_tag();
        self.send(&format!("{tag} CAPABILITY"))?;
        let mut capabilities = BTreeSet::new();
        loop {
            let line = self.read_line()?;
            if let Some(rest) = line.strip_prefix("* CAPABILITY ") {
                capabilities.extend(rest.split_whitespace().map(str::to_owned));
                continue;
            }
            if is_tagged(&line, &tag, "OK") {
                break;
            }
            if is_tagged(&line, &tag, "NO") || is_tagged(&line, &tag, "BAD") {
                return Err(TransportError::Rejected(line));
            }
        }
        self.capabilities = capabilities.clone();
        Ok(capabilities)
    }

    /// Authenticate.
    ///
    /// The secret is written to the stream and is never retained, logged or
    /// included in an error.
    pub fn login(&mut self, user: &str, secret: &str) -> Result<(), TransportError> {
        self.begin_operation();
        let tag = self.next_tag();
        self.send(&format!(
            "{tag} LOGIN {} {}",
            quote_atom(user)?,
            quote_atom(secret)?
        ))?;
        self.expect_ok(tag)
    }

    /// Select a mailbox.
    ///
    /// The UID validity value is recorded, because a UID is only meaningful
    /// within one.
    pub fn select(&mut self, mailbox: &Mailbox) -> Result<MailboxState, TransportError> {
        self.begin_operation();
        let tag = self.next_tag();
        self.send(&format!("{tag} SELECT {}", quote_atom(mailbox.name())?))?;
        let mut uidvalidity = None;
        let mut exists = 0u32;
        loop {
            let line = self.read_line()?;
            if let Some(value) = parse_code(&line, "UIDVALIDITY") {
                uidvalidity = Some(value.parse().map_err(|_| {
                    TransportError::Protocol("UIDVALIDITY is not a number".to_owned())
                })?);
                continue;
            }
            if let Some(rest) = line.strip_prefix("* ") {
                if let Some(count) = rest.strip_suffix(" EXISTS") {
                    exists = count.parse().map_err(|_| {
                        TransportError::Protocol("EXISTS is not a number".to_owned())
                    })?;
                    continue;
                }
            }
            if is_tagged(&line, &tag, "OK") {
                break;
            }
            if is_tagged(&line, &tag, "NO") || is_tagged(&line, &tag, "BAD") {
                return Err(TransportError::Rejected(line));
            }
        }
        let uidvalidity = uidvalidity.ok_or_else(|| {
            TransportError::Protocol("server did not report UIDVALIDITY".to_owned())
        })?;
        self.uidvalidity = Some(uidvalidity);
        self.mailbox = Some(mailbox.name().to_owned());
        Ok(MailboxState {
            uidvalidity,
            exists,
        })
    }

    /// Fetch one message by UID.
    ///
    /// The returned message is untrusted: its headers are authored by the
    /// sender, and it carries no delivery provenance, because IMAP does not
    /// record any.
    pub fn fetch(&mut self, uid: u32) -> Result<UntrustedMessage, TransportError> {
        self.begin_operation();
        let tag = self.next_tag();
        self.send(&format!("{tag} UID FETCH {uid} (BODY.PEEK[])"))?;

        let mut raw: Option<Vec<u8>> = None;
        loop {
            let line = self.read_line()?;
            if let Some(length) = literal_length(&line) {
                if length > self.limits.max_message_bytes {
                    return Err(TransportError::TooLarge {
                        limit: self.limits.max_message_bytes,
                    });
                }
                let bytes = self.stream.read_exact(length)?;
                // The literal is followed by the remainder of the response
                // line, which carries no further content for this fetch.
                let _ = self.read_line()?;
                raw = Some(bytes);
                continue;
            }
            if is_tagged(&line, &tag, "OK") {
                break;
            }
            if is_tagged(&line, &tag, "NO") || is_tagged(&line, &tag, "BAD") {
                return Err(TransportError::Rejected(line));
            }
        }

        let raw = raw.ok_or(TransportError::NotFound)?;
        self.to_untrusted(uid, &raw)
    }

    /// Parse a fetched message into the shared untrusted model.
    fn to_untrusted(&self, uid: u32, raw: &[u8]) -> Result<UntrustedMessage, TransportError> {
        let node = mime::parse(raw, &self.mime_limits)
            .map_err(|error| TransportError::Protocol(error.to_string()))?;
        let projection = mime::project(&node, &self.mime_limits)
            .map_err(|error| TransportError::Protocol(error.to_string()))?;
        Ok(UntrustedMessage {
            id: MessageId::new(format!("{uid}")),
            mailbox: mail_core::MailboxRef::new(self.mailbox.as_deref().unwrap_or(DEFAULT_MAILBOX)),
            from: projection.from.into_iter().next(),
            reply_to: projection.reply_to,
            to: projection.to,
            cc: projection.cc,
            subject: projection.subject,
            text_body: projection.text_body,
            html_body: projection.html_body,
            attachments: projection.attachments,
            flags: Vec::new(),
            date: None,
            // IMAP does not record provider envelope recipients, so there is
            // no evidence to record here. Leaving this empty is what makes a
            // `verified` identity fail closed over IMAP.
            provenance: mail_core::Provenance::default(),
        })
    }

    /// Run an IMAP search and return the matching UIDs.
    pub fn search(&mut self, criteria: &str) -> Result<Vec<u32>, TransportError> {
        self.begin_operation();
        let tag = self.next_tag();
        self.send(&format!("{tag} UID SEARCH {criteria}"))?;
        let mut uids = Vec::new();
        loop {
            let line = self.read_line()?;
            if let Some(rest) = line.strip_prefix("* SEARCH ") {
                for value in rest.split_whitespace() {
                    uids.push(value.parse().map_err(|_| {
                        TransportError::Protocol("search returned a non-numeric UID".to_owned())
                    })?);
                }
                continue;
            }
            if is_tagged(&line, &tag, "OK") {
                break;
            }
            if is_tagged(&line, &tag, "NO") || is_tagged(&line, &tag, "BAD") {
                return Err(TransportError::Rejected(line));
            }
        }
        Ok(uids)
    }

    /// Start a timed operation.
    fn begin_operation(&mut self) {
        self.deadline = Some(Instant::now() + self.limits.io_timeout);
    }

    /// The next command tag.
    fn next_tag(&mut self) -> String {
        self.next_tag += 1;
        format!("a{:04}", self.next_tag)
    }

    /// Write a command.
    fn send(&mut self, command: &str) -> Result<(), TransportError> {
        self.stream.write(format!("{command}\r\n").as_bytes())
    }

    /// Read one response line, enforcing the time and size bounds.
    fn read_line(&mut self) -> Result<String, TransportError> {
        if let Some(deadline) = self.deadline
            && Instant::now() >= deadline
        {
            return Err(TransportError::Timeout);
        }
        let line = self.stream.read_line(self.limits.max_response_bytes)?;
        Ok(line)
    }

    /// Expect a tagged `OK` response.
    fn expect_ok(&mut self, tag: String) -> Result<(), TransportError> {
        loop {
            let line = self.read_line()?;
            if is_tagged(&line, &tag, "OK") {
                return Ok(());
            }
            if is_tagged(&line, &tag, "NO") || is_tagged(&line, &tag, "BAD") {
                return Err(TransportError::Rejected(line));
            }
        }
    }
}

/// Whether a response is an untagged positive response of the given status.
fn is_positive_response(line: &str, status: &str) -> bool {
    line.starts_with("* ") && line[2..].starts_with(status)
}

/// Whether a response is the tagged completion of a command.
fn is_tagged(line: &str, tag: &str, status: &str) -> bool {
    line.starts_with(tag)
        && line[tag.len()..].starts_with(' ')
        && line[tag.len() + 1..].starts_with(status)
}

/// Extract the number from a response code such as `[UIDVALIDITY 42]`.
fn parse_code<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let open = line.find('[')?;
    let close = line[open..].find(']')? + open;
    let code = &line[open + 1..close];
    let (key, value) = code.split_once(' ')?;
    if key == name { Some(value) } else { None }
}

/// The length of a literal at the end of a response line, if it has one.
fn literal_length(line: &str) -> Option<u64> {
    if !line.ends_with('}') {
        return None;
    }
    let open = line.rfind('{')?;
    let digits = &line[open + 1..line.len() - 1];
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// Quote a value as an IMAP quoted string.
///
/// A quoted string cannot contain a carriage return or a newline, so a value
/// that carries one is refused rather than escaped: it would otherwise close
/// the quoted string and start another command.
fn quote_atom(value: &str) -> Result<String, TransportError> {
    if value
        .chars()
        .any(|c| c.is_control() || c == '\r' || c == '\n')
    {
        return Err(TransportError::InvalidState(
            "a value may not contain control characters".to_owned(),
        ));
    }
    let mut result = String::with_capacity(value.len() + 2);
    result.push('"');
    for c in value.chars() {
        if c == '"' || c == '\\' {
            result.push('\\');
        }
        result.push(c);
    }
    result.push('"');
    Ok(result)
}

/// Read the pages of a mailbox as an IMAP-backed reader.
///
/// The reader keeps the UID validity value of the selected mailbox, because a
/// change to it invalidates every UID held before it.
pub struct ImapReader<'a> {
    session: ImapSession<'a>,
    mailbox: Mailbox,
    uidvalidity: Option<u32>,
}

impl std::fmt::Debug for ImapReader<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImapReader")
            .field("mailbox", &self.mailbox)
            .field("uidvalidity", &self.uidvalidity)
            .finish_non_exhaustive()
    }
}

impl<'a> ImapReader<'a> {
    /// Wrap a session as a reader for one mailbox.
    pub fn new(session: ImapSession<'a>, mailbox: Mailbox) -> Self {
        Self {
            session,
            mailbox,
            uidvalidity: None,
        }
    }

    /// Select the mailbox and record its UID validity value.
    pub fn open(&mut self) -> Result<MailboxState, TransportError> {
        let state = self.session.select(&self.mailbox)?;
        self.uidvalidity = Some(state.uidvalidity);
        Ok(state)
    }

    /// The UID validity value the reader is operating under.
    pub fn uidvalidity(&self) -> Option<u32> {
        self.uidvalidity
    }

    /// The inner session.
    pub fn session(&mut self) -> &mut ImapSession<'a> {
        &mut self.session
    }
}

impl MailReader for ImapReader<'_> {
    fn list(
        &mut self,
        _mailbox: &mail_core::MailboxRef,
        query: &ListQuery,
    ) -> Result<MessagePage, TransportError> {
        let uids = self.session.search("ALL")?;
        let limit = if query.limit == 0 {
            self.session.limits.max_page_size
        } else {
            query.limit.min(self.session.limits.max_page_size)
        };
        let mut messages = Vec::new();
        for uid in uids.into_iter().take(limit as usize) {
            messages.push(self.session.fetch(uid)?);
        }
        Ok(MessagePage {
            messages,
            next_cursor: None,
        })
    }

    fn get(
        &mut self,
        _mailbox: &mail_core::MailboxRef,
        id: &MessageId,
    ) -> Result<UntrustedMessage, TransportError> {
        let uid: u32 = id.as_str().parse().map_err(|_| TransportError::NotFound)?;
        self.session.fetch(uid)
    }
}

impl MailChangeTracker for ImapReader<'_> {
    fn changes_since(
        &mut self,
        _mailbox: &mail_core::MailboxRef,
        cursor: Option<&ChangeCursor>,
    ) -> Result<ChangeSet, TransportError> {
        let since = match cursor {
            Some(cursor) => cursor
                .token
                .parse::<u32>()
                .map_err(|_| TransportError::InvalidState("malformed change cursor".to_owned()))?,
            None => 0,
        };
        // A UID validity change renumbers the mailbox, so a cursor from
        // before the change would refer to different messages.
        if let (Some(expected), Some(actual)) = (self.uidvalidity, self.session.uidvalidity())
            && expected != actual
        {
            return Err(TransportError::InvalidState(
                "the mailbox's UID validity changed".to_owned(),
            ));
        }
        let criteria = format!("UID {since}:*");
        let uids = self.session.search(&criteria)?;
        let mut changes = Vec::new();
        let mut last = since;
        for uid in &uids {
            changes.push(Change {
                id: MessageId::new(uid.to_string()),
                kind: ChangeKind::Added,
            });
            last = last.max(*uid);
        }
        Ok(ChangeSet {
            changes,
            next_cursor: Some(ChangeCursor {
                token: last.to_string(),
            }),
        })
    }
}

/// A reader with a fixed time budget, for callers that need one.
pub fn with_timeout(limits: TransportLimits, timeout: Duration) -> TransportLimits {
    TransportLimits {
        io_timeout: timeout,
        ..limits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_atoms_and_escapes_quotes() {
        assert_eq!(quote_atom("simple").unwrap(), "\"simple\"");
        assert_eq!(quote_atom("with\"quote").unwrap(), "\"with\\\"quote\"");
        assert_eq!(quote_atom("with\\slash").unwrap(), "\"with\\\\slash\"");
    }

    #[test]
    fn refuses_an_atom_that_could_inject_a_command() {
        for value in ["user\r\na0002 LOGIN other secret", "user\n", "user\r"] {
            assert!(quote_atom(value).is_err(), "value {value:?} was accepted");
        }
    }

    #[test]
    fn parses_response_codes() {
        assert_eq!(
            parse_code("* OK [UIDVALIDITY 3857529045] UIDs valid", "UIDVALIDITY"),
            Some("3857529045")
        );
        assert_eq!(
            parse_code("* OK [UIDNEXT 4392] Predicted", "UIDVALIDITY"),
            None
        );
    }

    #[test]
    fn parses_literal_lengths() {
        assert_eq!(literal_length("* 1 FETCH (BODY[] {123}"), Some(123));
        assert_eq!(literal_length("* 1 FETCH (BODY[] {0}"), Some(0));
        assert_eq!(literal_length("* 1 FETCH (FLAGS (\\Seen))"), None);
        assert_eq!(literal_length("* 1 FETCH (BODY[] {abc}"), None);
    }

    #[test]
    fn recognises_tagged_responses() {
        assert!(is_tagged("a0001 OK SELECT completed", "a0001", "OK"));
        assert!(!is_tagged("a0002 OK SELECT completed", "a0001", "OK"));
        assert!(is_tagged("a0001 NO mailbox does not exist", "a0001", "NO"));
        assert!(!is_tagged("a0001 OK", "a0001", "NO"));
    }
}
