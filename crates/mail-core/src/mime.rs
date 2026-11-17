//! MIME parsing for untrusted upstream mail.
//!
//! Upstream messages are attacker-controlled, so this parser is written to
//! fail rather than guess: a structure it cannot make sense of is an error,
//! not a partially-parsed message. Every size is bounded, because a message
//! that expands a hundredfold while being decoded is a denial-of-service
//! vector rather than a large message.
//!
//! Nothing here interprets the *meaning* of a message. Provenance, policy and
//! disclosure are decided elsewhere; this module only produces structure.

use std::fmt;

/// Limits applied while parsing a message.
///
/// These are security limits, not tuning knobs: an unbounded parse is how a
/// hostile message turns into a hostile process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MimeLimits {
    /// Maximum size of the whole raw message in bytes.
    pub max_message_bytes: u64,
    /// Maximum number of MIME parts in one message.
    pub max_parts: usize,
    /// Maximum size of any single decoded part in bytes.
    pub max_part_bytes: u64,
    /// Maximum number of header bytes in one part.
    pub max_header_bytes: usize,
}

impl Default for MimeLimits {
    fn default() -> Self {
        Self {
            max_message_bytes: 25 * 1024 * 1024,
            max_parts: 200,
            max_part_bytes: 10 * 1024 * 1024,
            max_header_bytes: 64 * 1024,
        }
    }
}

/// Why a message could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MimeError {
    /// The message exceeded a size limit.
    TooLarge {
        /// What was being limited.
        what: &'static str,
        /// The limit that was exceeded.
        limit: u64,
    },
    /// The message contained more parts than allowed.
    TooManyParts {
        /// The limit that was exceeded.
        limit: usize,
    },
    /// The message structure was not valid MIME.
    Malformed(&'static str),
}

impl fmt::Display for MimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MimeError::TooLarge { what, limit } => {
                write!(f, "{what} exceeds the limit of {limit} bytes")
            }
            MimeError::TooManyParts { limit } => {
                write!(f, "message has more than {limit} parts")
            }
            MimeError::Malformed(reason) => write!(f, "malformed MIME: {reason}"),
        }
    }
}

impl std::error::Error for MimeError {}

/// The headers of one MIME part.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Headers {
    entries: Vec<(String, String)>,
}

impl Headers {
    /// The value of the first header with this name, matched case-insensitively.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// Every header, in the order they appeared.
    pub fn entries(&self) -> &[(String, String)] {
        &self.entries
    }

    /// The decoded `Content-Type` of this part.
    pub fn content_type(&self) -> (String, Option<String>) {
        let raw = self.get("content-type").unwrap_or("text/plain");
        parse_content_type(raw)
    }

    /// The declared `Content-Transfer-Encoding`, lowercased.
    pub fn transfer_encoding(&self) -> String {
        self.get("content-transfer-encoding")
            .unwrap_or("7bit")
            .trim()
            .to_ascii_lowercase()
    }

    /// The declared filename, from `Content-Disposition` or `Content-Type`.
    pub fn filename(&self) -> Option<String> {
        if let Some(disposition) = self.get("content-disposition") {
            if let Some(name) = parameter(disposition, "filename") {
                return Some(name);
            }
        }
        let (_, parameters) = self.content_type();
        parameters.as_ref().and_then(|p| parameter(p, "name"))
    }
}

/// One node of a parsed MIME tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MimeNode {
    /// A part with a body.
    Leaf {
        /// The part's headers.
        headers: Headers,
        /// The raw, still-encoded body.
        body: Vec<u8>,
    },
    /// A multipart container.
    Multipart {
        /// The container's headers.
        headers: Headers,
        /// The contained parts.
        parts: Vec<MimeNode>,
    },
}

impl MimeNode {
    /// The headers of this node.
    pub fn headers(&self) -> &Headers {
        match self {
            MimeNode::Leaf { headers, .. } | MimeNode::Multipart { headers, .. } => headers,
        }
    }
}

/// Parse a raw message into a MIME tree.
pub fn parse(raw: &[u8], limits: &MimeLimits) -> Result<MimeNode, MimeError> {
    if raw.len() as u64 > limits.max_message_bytes {
        return Err(MimeError::TooLarge {
            what: "message",
            limit: limits.max_message_bytes,
        });
    }
    let (headers, body) = split_headers_and_body(raw, limits.max_header_bytes)?;
    let mut parts = 0usize;
    parse_part(headers, body, limits, 0, &mut parts)
}

fn parse_part(
    headers: Headers,
    body: Vec<u8>,
    limits: &MimeLimits,
    depth: usize,
    parts: &mut usize,
) -> Result<MimeNode, MimeError> {
    if depth > 32 {
        return Err(MimeError::Malformed("MIME nesting is too deep"));
    }
    // A message may hold many parts, and each one is work. The count is
    // bounded so that a message with thousands of parts cannot turn a
    // single read into thousands of projections.
    *parts += 1;
    if *parts > limits.max_parts {
        return Err(MimeError::TooManyParts {
            limit: limits.max_parts,
        });
    }
    let (content_type, parameters) = headers.content_type();
    let is_multipart = content_type.starts_with("multipart/");
    let boundary = parameters.as_deref().and_then(|p| parameter(p, "boundary"));

    if !is_multipart {
        return Ok(MimeNode::Leaf { headers, body });
    }

    let Some(boundary) = boundary else {
        return Err(MimeError::Malformed("multipart part has no boundary"));
    };
    if boundary.is_empty() {
        return Err(MimeError::Malformed("multipart part has an empty boundary"));
    }

    let raw_parts = split_multipart(&body, &boundary, limits)?;
    let mut parsed = Vec::with_capacity(raw_parts.len());
    for (part_headers, part_body) in raw_parts {
        parsed.push(parse_part(
            part_headers,
            part_body,
            limits,
            depth + 1,
            parts,
        )?);
    }
    Ok(MimeNode::Multipart {
        headers,
        parts: parsed,
    })
}

fn split_headers_and_body(
    raw: &[u8],
    max_header_bytes: usize,
) -> Result<(Headers, Vec<u8>), MimeError> {
    let separator = find_header_separator(raw)
        .ok_or(MimeError::Malformed("message has no header/body separator"))?;
    if separator.start > max_header_bytes {
        return Err(MimeError::TooLarge {
            what: "headers",
            limit: max_header_bytes as u64,
        });
    }
    let header_bytes = &raw[..separator.start];
    let body = raw[separator.end..].to_vec();
    Ok((parse_headers(header_bytes)?, body))
}

fn find_header_separator(raw: &[u8]) -> Option<HeaderSeparator> {
    let mut index = 0;
    while index + 1 < raw.len() {
        if raw[index] == b'\n' {
            if raw[index + 1] == b'\n' {
                return Some(HeaderSeparator {
                    start: index,
                    end: index + 2,
                });
            }
            if index + 2 < raw.len() && raw[index + 1] == b'\r' && raw[index + 2] == b'\n' {
                return Some(HeaderSeparator {
                    start: index,
                    end: index + 3,
                });
            }
        }
        index += 1;
    }
    None
}

struct HeaderSeparator {
    start: usize,
    end: usize,
}

fn parse_headers(raw: &[u8]) -> Result<Headers, MimeError> {
    let text = String::from_utf8_lossy(raw);
    let mut headers = Headers::default();
    let mut current: Option<(String, String)> = None;

    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            // A continuation of the previous header.
            if let Some((_, value)) = current.as_mut() {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    value.push(' ');
                    value.push_str(trimmed);
                }
                continue;
            }
            return Err(MimeError::Malformed("header continuation without a header"));
        }
        if let Some((name, value)) = current.take() {
            headers.entries.push((name, value));
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(MimeError::Malformed("header line has no colon"));
        };
        let name = name.trim();
        if name.is_empty() {
            return Err(MimeError::Malformed("header has an empty name"));
        }
        current = Some((name.to_owned(), value.trim().to_owned()));
    }
    if let Some((name, value)) = current {
        headers.entries.push((name, value));
    }
    Ok(headers)
}

fn split_multipart(
    body: &[u8],
    boundary: &str,
    limits: &MimeLimits,
) -> Result<Vec<(Headers, Vec<u8>)>, MimeError> {
    let delimiter = format!("--{boundary}").into_bytes();
    let mut parts: Vec<(Headers, Vec<u8>)> = Vec::new();
    let mut current: Option<(usize, usize)> = None;
    let mut index = 0;

    while index < body.len() {
        let Some(line_end) = find_line_end(body, index) else {
            break;
        };
        let line = &body[index..line_end.content_end];
        if line.starts_with(&delimiter) {
            if let Some((start, end)) = current.take() {
                parts.push(part_from(&body[start..end], limits)?);
            }
            let after = &line[delimiter.len()..];
            let trimmed = after.trim_ascii();
            if trimmed == b"--" {
                // The closing delimiter: the body ends here.
                return Ok(parts);
            }
            current = Some((line_end.next_start, body.len()));
        }
        index = line_end.next_start;
    }

    if let Some((start, end)) = current.take() {
        parts.push(part_from(&body[start..end.min(body.len())], limits)?);
    }
    if parts.is_empty() {
        return Err(MimeError::Malformed("multipart body has no parts"));
    }
    Ok(parts)
}

struct LineEnd {
    content_end: usize,
    next_start: usize,
}

fn find_line_end(body: &[u8], from: usize) -> Option<LineEnd> {
    let mut index = from;
    while index < body.len() {
        if body[index] == b'\n' {
            let content_end = if index > from && body[index - 1] == b'\r' {
                index - 1
            } else {
                index
            };
            return Some(LineEnd {
                content_end,
                next_start: index + 1,
            });
        }
        index += 1;
    }
    None
}

fn part_from(raw: &[u8], limits: &MimeLimits) -> Result<(Headers, Vec<u8>), MimeError> {
    let (headers, body) = split_headers_and_body(raw, limits.max_header_bytes)?;
    if body.len() as u64 > limits.max_part_bytes {
        return Err(MimeError::TooLarge {
            what: "part",
            limit: limits.max_part_bytes,
        });
    }
    Ok((headers, body))
}

/// Decode a part body according to its transfer encoding.
pub fn decode_body(headers: &Headers, body: &[u8]) -> Result<Vec<u8>, MimeError> {
    match headers.transfer_encoding().as_str() {
        "base64" => decode_base64(body),
        "quoted-printable" => Ok(decode_quoted_printable(body)),
        _ => Ok(body.to_vec()),
    }
}

/// Decode standard base64, ignoring whitespace and rejecting invalid input.
fn decode_base64(body: &[u8]) -> Result<Vec<u8>, MimeError> {
    let mut output = Vec::with_capacity(body.len() / 4 * 3);
    let mut accumulator: u32 = 0;
    let mut bits = 0u32;
    let mut padding = 0usize;

    for byte in body {
        let value = match byte {
            b'A'..=b'Z' => (byte - b'A') as u32,
            b'a'..=b'z' => (byte - b'a') as u32 + 26,
            b'0'..=b'9' => (byte - b'0') as u32 + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => {
                padding += 1;
                if padding > 2 {
                    return Err(MimeError::Malformed("base64 body has excess padding"));
                }
                continue;
            }
            b' ' | b'\t' | b'\r' | b'\n' => continue,
            _ => return Err(MimeError::Malformed("base64 body has an invalid character")),
        };
        if padding > 0 {
            return Err(MimeError::Malformed("base64 body has data after padding"));
        }
        accumulator = (accumulator << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push(((accumulator >> bits) & 0xff) as u8);
        }
    }
    Ok(output)
}

/// Decode quoted-printable content.
fn decode_quoted_printable(body: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(body.len());
    let mut index = 0;
    while index < body.len() {
        if body[index] == b'=' {
            // A soft line break is `=` at the end of a line.
            if index + 2 < body.len() && body[index + 1] == b'\r' && body[index + 2] == b'\n' {
                index += 3;
                continue;
            }
            if index + 1 < body.len() && body[index + 1] == b'\n' {
                index += 2;
                continue;
            }
            if index + 2 < body.len() {
                let hex = &body[index + 1..index + 3];
                if let Ok(value) = u8::from_str_radix(&String::from_utf8_lossy(hex), 16) {
                    output.push(value);
                    index += 3;
                    continue;
                }
            }
            output.push(b'=');
            index += 1;
            continue;
        }
        output.push(body[index]);
        index += 1;
    }
    output
}

/// Split a `Content-Type` or `Content-Disposition` value into its type and
/// its parameters.
pub fn parse_content_type(raw: &str) -> (String, Option<String>) {
    let mut parts = raw.split(';');
    let content_type = parts.next().unwrap_or("").trim().to_ascii_lowercase();
    let parameters: Vec<&str> = parts.collect();
    if parameters.is_empty() {
        (content_type, None)
    } else {
        (content_type, Some(parameters.join(";")))
    }
}

/// Extract one parameter value from a header value.
///
/// The value may be quoted, and a quoted value may contain an escaped quote.
pub fn parameter(raw: &str, name: &str) -> Option<String> {
    let mut rest = raw;
    while let Some(position) = rest.to_ascii_lowercase().find(&name.to_ascii_lowercase()) {
        let before_ok = position == 0
            || rest[..position]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_whitespace() || c == ';');
        let after = &rest[position + name.len()..];
        let trimmed = after.trim_start();
        if before_ok && trimmed.starts_with('=') {
            let value = trimmed[1..].trim_start();
            if let Some(stripped) = value.strip_prefix('"') {
                let mut result = String::new();
                let mut chars = stripped.chars();
                while let Some(c) = chars.next() {
                    if c == '\\' {
                        if let Some(escaped) = chars.next() {
                            result.push(escaped);
                        }
                        continue;
                    }
                    if c == '"' {
                        break;
                    }
                    result.push(c);
                }
                return Some(result);
            }
            let end = value
                .find(|c: char| c == ';' || c.is_whitespace())
                .unwrap_or(value.len());
            return Some(value[..end].to_owned());
        }
        rest = &rest[position + name.len()..];
    }
    None
}

/// Parse an address list header value.
///
/// The value may hold several addresses separated by commas, each with an
/// optional display name in quotes or angle brackets. A malformed entry is
/// kept as a bare address rather than dropped, because a dropped recipient
/// would change who a message appears to be addressed to.
pub fn parse_address_list(raw: &str) -> Vec<crate::message::Address> {
    let mut addresses = Vec::new();
    for entry in split_addresses(raw) {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        addresses.push(parse_address(entry));
    }
    addresses
}

/// Split a header value on the commas that separate addresses.
fn split_addresses(raw: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut in_angle = false;
    let mut escaped = false;

    for c in raw.chars() {
        if escaped {
            current.push(c);
            escaped = false;
            continue;
        }
        match c {
            '\\' if in_quotes => {
                current.push(c);
                escaped = true;
            }
            '"' => {
                in_quotes = !in_quotes;
                current.push(c);
            }
            '<' if !in_quotes => {
                in_angle = true;
                current.push(c);
            }
            '>' if !in_quotes => {
                in_angle = false;
                current.push(c);
            }
            ',' if !in_quotes && !in_angle => {
                parts.push(std::mem::take(&mut current));
            }
            _ => current.push(c),
        }
    }
    parts.push(current);
    parts
}

/// Parse one address.
fn parse_address(entry: &str) -> crate::message::Address {
    let entry = entry.trim();
    if let (Some(open), Some(close)) = (entry.rfind('<'), entry.rfind('>')) {
        if open < close {
            let address = entry[open + 1..close].trim();
            let display = entry[..open].trim().trim_matches('"').trim();
            return crate::message::Address {
                address: address.to_owned(),
                display_name: (!display.is_empty()).then(|| display.to_owned()),
            };
        }
    }
    crate::message::Address::new(entry.trim_matches('"').trim())
}

/// The parts of a message that a MIME tree carries.
///
/// This is the projection every adapter shares: whatever the upstream
/// protocol, a message becomes the same set of authored headers, bodies and
/// attachment metadata.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MimeProjection {
    /// The subject header.
    pub subject: Option<String>,
    /// The authored sender.
    pub from: Vec<crate::message::Address>,
    /// The authored recipients.
    pub to: Vec<crate::message::Address>,
    /// The authored carbon-copy recipients.
    pub cc: Vec<crate::message::Address>,
    /// The authored reply-to addresses.
    pub reply_to: Vec<crate::message::Address>,
    /// The plain-text body.
    pub text_body: Option<String>,
    /// The HTML body, untrusted and unsanitized.
    pub html_body: Option<String>,
    /// The attachment metadata.
    pub attachments: Vec<crate::message::AttachmentMeta>,
}

/// Project a parsed MIME tree into the shared message parts.
///
/// Nothing here is trusted: the headers are authored by the sender, and the
/// declared content types and filenames are metadata an attacker controls.
///
/// The projection is bounded: a tree with more parts than the limit allows,
/// or a part whose decoded body exceeds the part limit, is an error rather
/// than a larger result.
pub fn project(node: &MimeNode, limits: &MimeLimits) -> Result<MimeProjection, MimeError> {
    let mut projection = MimeProjection {
        subject: node.headers().get("subject").map(|value| value.to_owned()),
        from: node
            .headers()
            .get("from")
            .map(parse_address_list)
            .unwrap_or_default(),
        to: node
            .headers()
            .get("to")
            .map(parse_address_list)
            .unwrap_or_default(),
        cc: node
            .headers()
            .get("cc")
            .map(parse_address_list)
            .unwrap_or_default(),
        reply_to: node
            .headers()
            .get("reply-to")
            .map(parse_address_list)
            .unwrap_or_default(),
        ..MimeProjection::default()
    };

    let mut attachment_index = 0usize;
    let mut parts = 0usize;
    collect_parts(
        node,
        limits,
        &mut projection,
        &mut attachment_index,
        &mut parts,
    )?;
    Ok(projection)
}

/// Collect the bodies and attachments of a MIME tree.
fn collect_parts(
    node: &MimeNode,
    limits: &MimeLimits,
    projection: &mut MimeProjection,
    attachment_index: &mut usize,
    parts: &mut usize,
) -> Result<(), MimeError> {
    *parts += 1;
    if *parts > limits.max_parts {
        return Err(MimeError::TooManyParts {
            limit: limits.max_parts,
        });
    }
    match node {
        MimeNode::Multipart {
            parts: children, ..
        } => {
            for part in children {
                collect_parts(part, limits, projection, attachment_index, parts)?;
            }
        }
        MimeNode::Leaf { headers, body } => {
            let (content_type, _) = headers.content_type();
            // A body that cannot be decoded is not a body: it is left as an
            // opaque attachment rather than projected as text, because a
            // half-decoded body would disclose something the sender chose
            // to encode.
            let decoded = decode_body(headers, body).ok();
            if let Some(decoded) = &decoded
                && decoded.len() as u64 > limits.max_part_bytes
            {
                return Err(MimeError::TooLarge {
                    what: "decoded part",
                    limit: limits.max_part_bytes,
                });
            }
            let is_attachment = headers
                .get("content-disposition")
                .is_some_and(|value| value.to_ascii_lowercase().starts_with("attachment"))
                || decoded.is_none();

            match content_type.as_str() {
                "text/plain" if !is_attachment => {
                    let decoded = decoded.as_deref().unwrap_or_default();
                    let text = String::from_utf8_lossy(decoded).into_owned();
                    projection.text_body = Some(match projection.text_body.take() {
                        Some(existing) => format!("{existing}\n{text}"),
                        None => text,
                    });
                }
                "text/html" if !is_attachment => {
                    let decoded = decoded.as_deref().unwrap_or_default();
                    let html = String::from_utf8_lossy(decoded).into_owned();
                    projection.html_body = Some(match projection.html_body.take() {
                        Some(existing) => format!("{existing}\n{html}"),
                        None => html,
                    });
                }
                _ => {
                    *attachment_index += 1;
                    projection.attachments.push(crate::message::AttachmentMeta {
                        id: format!("part-{attachment_index}"),
                        filename: headers.filename(),
                        content_type: Some(content_type),
                        size: body.len() as u64,
                        inline: !is_attachment,
                    });
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_simple_message() {
        let raw = b"Subject: hello\r\nFrom: a@example.com\r\n\r\nbody text\r\n";
        let node = parse(raw, &MimeLimits::default()).unwrap();
        assert_eq!(node.headers().get("subject"), Some("hello"));
        match node {
            MimeNode::Leaf { body, .. } => {
                assert_eq!(String::from_utf8_lossy(&body).trim(), "body text")
            }
            MimeNode::Multipart { .. } => panic!("expected a leaf"),
        }
    }

    #[test]
    fn rejects_a_message_without_a_header_separator() {
        assert!(matches!(
            parse(b"no separator here", &MimeLimits::default()),
            Err(MimeError::Malformed(_))
        ));
    }

    #[test]
    fn rejects_a_message_over_the_size_limit() {
        let limits = MimeLimits {
            max_message_bytes: 10,
            ..MimeLimits::default()
        };
        assert!(matches!(
            parse(b"Subject: a\r\n\r\nbody", &limits),
            Err(MimeError::TooLarge { .. })
        ));
    }

    #[test]
    fn splits_a_multipart_message() {
        let raw = b"Content-Type: multipart/mixed; boundary=\"b1\"\r\n\r\n\
--b1\r\nContent-Type: text/plain\r\n\r\nhello\r\n\
--b1\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"a.pdf\"\r\n\r\n%PDF\r\n\
--b1--\r\n";
        let node = parse(raw, &MimeLimits::default()).unwrap();
        match node {
            MimeNode::Multipart { parts, .. } => {
                assert_eq!(parts.len(), 2);
                assert_eq!(parts[0].headers().content_type().0, "text/plain");
                assert_eq!(parts[1].headers().filename().as_deref(), Some("a.pdf"));
            }
            MimeNode::Leaf { .. } => panic!("expected a multipart"),
        }
    }

    #[test]
    fn rejects_a_multipart_without_a_boundary() {
        let raw = b"Content-Type: multipart/mixed\r\n\r\nbody\r\n";
        assert!(matches!(
            parse(raw, &MimeLimits::default()),
            Err(MimeError::Malformed(_))
        ));
    }

    #[test]
    fn rejects_a_message_with_too_many_parts() {
        let mut raw = String::from("Content-Type: multipart/mixed; boundary=\"b1\"\r\n\r\n");
        for index in 0..5 {
            raw.push_str("--b1\r\nContent-Type: text/plain\r\n\r\n");
            raw.push_str(&format!("part {index}\r\n"));
        }
        raw.push_str("--b1--\r\n");
        let limits = MimeLimits {
            max_parts: 3,
            ..MimeLimits::default()
        };
        assert!(matches!(
            parse(raw.as_bytes(), &limits),
            Err(MimeError::TooManyParts { .. })
        ));
    }

    #[test]
    fn projects_a_message_into_its_shared_parts() {
        let raw =
            b"Subject: hello\r\nFrom: sender@example.com\r\nTo: me@example.com\r\n\r\nbody\r\n";
        let node = parse(raw, &MimeLimits::default()).unwrap();
        let projection = project(&node, &MimeLimits::default()).unwrap();
        assert_eq!(projection.subject.as_deref(), Some("hello"));
        assert_eq!(projection.from[0].address, "sender@example.com");
        assert_eq!(projection.to[0].address, "me@example.com");
        assert_eq!(projection.text_body.as_deref(), Some("body\r\n"));
    }

    /// A body that cannot be decoded is not projected as text: a
    /// half-decoded body would disclose something the sender chose to
    /// encode.
    #[test]
    fn a_body_that_cannot_be_decoded_is_not_projected_as_text() {
        let raw =
            b"Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\nnot*valid\r\n";
        let node = parse(raw, &MimeLimits::default()).unwrap();
        let projection = project(&node, &MimeLimits::default()).unwrap();
        assert!(projection.text_body.is_none());
        assert_eq!(projection.attachments.len(), 1);
    }

    #[test]
    fn decodes_base64_and_rejects_invalid_characters() {
        let mut headers = Headers::default();
        headers
            .entries
            .push(("content-transfer-encoding".to_owned(), "base64".to_owned()));
        assert_eq!(decode_body(&headers, b"aGk=").unwrap(), b"hi");
        assert!(decode_body(&headers, b"a*i=").is_err());
    }

    #[test]
    fn decodes_quoted_printable() {
        assert_eq!(decode_quoted_printable(b"a=3Db"), b"a=b");
        assert_eq!(decode_quoted_printable(b"long=\r\nline"), b"longline");
    }

    #[test]
    fn extracts_parameters_from_headers() {
        assert_eq!(
            parameter("attachment; filename=\"a b.pdf\"", "filename").as_deref(),
            Some("a b.pdf")
        );
        assert_eq!(
            parameter("attachment; filename=plain.pdf", "filename").as_deref(),
            Some("plain.pdf")
        );
        assert_eq!(parameter("attachment", "filename"), None);
    }

    #[test]
    fn unfolds_continued_header_lines() {
        let raw = b"Subject: a very\r\n long subject\r\n\r\nbody\r\n";
        let node = parse(raw, &MimeLimits::default()).unwrap();
        assert_eq!(node.headers().get("subject"), Some("a very long subject"));
    }
}
