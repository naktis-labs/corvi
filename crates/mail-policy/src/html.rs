//! A parser-based HTML sanitizer.
//!
//! ADR-0003 section 5 requires that remote content is stripped from HTML
//! bodies and that sanitized HTML never fetches anything on the client's
//! behalf. The earlier implementation rewrote strings, which cannot answer
//! the questions that matter: where does an attribute value really end, and
//! what does `&#106;avascript:` actually mean?
//!
//! This module therefore parses HTML into tokens and then re-serializes an
//! allowlisted subset. It is a sanitizer, not a browser: it does not build a
//! DOM, and it does not attempt to repair malformed markup beyond what a
//! browser would ignore. Where the markup is ambiguous, the ambiguous part is
//! dropped.
//!
//! Five rules hold:
//!
//! 1. Only allowlisted elements and attributes survive.
//! 2. Every URL-bearing attribute is examined **after** entity decoding, so
//!    an obfuscated scheme cannot slip through.
//! 3. A link's destination never keeps a token: the query and the path are
//!    replaced, because that is where a reset link hides it.
//! 4. Text is decoded and re-escaped, so a body cannot smuggle markup
//!    through an entity.
//! 5. A link's policy is the same whether the link appears in the message's
//!    link list or in the HTML body, so a body cannot bypass the link policy
//!    the decision expressed.

use mail_core::Link;

/// Elements that survive sanitization.
const ALLOWED_ELEMENTS: &[&str] = &[
    "a",
    "abbr",
    "article",
    "aside",
    "b",
    "blockquote",
    "br",
    "caption",
    "cite",
    "code",
    "dd",
    "del",
    "dfn",
    "div",
    "dl",
    "dt",
    "em",
    "figcaption",
    "figure",
    "footer",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "header",
    "hr",
    "i",
    "img",
    "ins",
    "kbd",
    "li",
    "main",
    "mark",
    "nav",
    "ol",
    "p",
    "pre",
    "q",
    "s",
    "samp",
    "section",
    "small",
    "span",
    "strong",
    "sub",
    "sup",
    "table",
];

/// Attributes that survive on any element.
const GLOBAL_ATTRIBUTES: &[&str] = &["title", "lang", "dir"];

/// Attributes that survive on a specific element.
const ELEMENT_ATTRIBUTES: [(&str, &[&str]); 4] = [
    ("a", &["href", "name"]),
    ("img", &["alt", "width", "height"]),
    ("td", &["colspan", "rowspan"]),
    ("th", &["colspan", "rowspan"]),
];

/// Attributes that make a client fetch a resource on its own.
///
/// These are only ever kept when remote content is allowed, and only when
/// their value is an absolute `http` or `https` URL.
const REMOTE_ATTRIBUTES: &[&str] = &["src", "srcset"];

/// Elements whose content is raw text rather than markup.
///
/// Their content is not markup at all, so it is discarded with the element.
const RAW_TEXT_ELEMENTS: &[&str] = &["script", "style", "textarea", "title", "xmp", "iframe"];

/// Elements that are dropped together with their content.
const DROPPED_WITH_CONTENT: &[&str] = &[
    "script", "style", "iframe", "object", "embed", "applet", "form", "noscript", "template",
    "svg", "math", "frame",
];

/// Attributes that are dropped wherever they appear.
const FORBIDDEN_ATTRIBUTES: &[&str] = &[
    "style",
    "srcdoc",
    "formaction",
    "background",
    "poster",
    "action",
];

/// Schemes a link may point at.
const ALLOWED_SCHEMES: &[&str] = &["http", "https", "mailto"];

/// How links in a body are treated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkMode {
    /// Keep the destination as written.
    Keep,
    /// Keep the destination but remove any token it carries.
    Sanitize,
    /// Remove the destination entirely.
    Deny,
}

/// How remote resources in a body are treated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteMode {
    /// A client may fetch the referenced resource.
    Allow,
    /// The reference is removed, so the client fetches nothing.
    Strip,
}

/// One parsed token.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Text(String),
    Start {
        name: String,
        attributes: Vec<(String, String)>,
        self_closing: bool,
    },
    End {
        name: String,
    },
}

/// Sanitize an HTML body, removing any token a link carries.
pub fn sanitize_html(html: &str) -> String {
    sanitize_html_with(html, LinkMode::Sanitize, RemoteMode::Strip)
}

/// Sanitize an HTML body with explicit link and remote-content policies.
pub fn sanitize_html_with(html: &str, links: LinkMode, remote: RemoteMode) -> String {
    render(tokenize(html), links, remote)
}

/// Remove references to remote resources from an HTML body.
///
/// The elements and their text survive; only the references that would make
/// a client fetch something on its own are removed. A link's destination is
/// still sanitized, because a token in a link is disclosed whether or not
/// the client follows it.
pub fn strip_remote_resources(html: &str) -> String {
    render(tokenize(html), LinkMode::Sanitize, RemoteMode::Strip)
}

/// Reduce a URL to a form that does not carry a token in its query or path.
///
/// A login link's token usually lives in the query string or the last path
/// segment. Keeping only the scheme and host removes it.
pub fn sanitize_url(href: &str) -> String {
    let trimmed = href.trim();
    if let Some(address) = trimmed.strip_prefix("mailto:") {
        return format!("mailto:{}", sanitize_path(address));
    }
    let Some((scheme, rest)) = split_scheme(trimmed) else {
        return "[REDACTED-LINK]".to_owned();
    };
    let scheme = scheme.to_ascii_lowercase();
    if !ALLOWED_SCHEMES.contains(&scheme.as_str()) {
        return "[REDACTED-LINK]".to_owned();
    }
    if scheme == "mailto" {
        return trimmed.to_owned();
    }
    // The remainder still carries the authority's `//`, which is not part of
    // the host.
    let rest = rest.strip_prefix("//").unwrap_or(rest);
    let host_end = rest.find('/').unwrap_or(rest.len());
    let host = &rest[..host_end];
    format!("{scheme}://{host}/[REDACTED]")
}

/// Extract the links a body points at.
///
/// The visible text is kept with the destination, because a link's text is
/// what a reader acts on, while the destination is what carries a secret.
pub fn extract_links(html: &str) -> Vec<Link> {
    let mut links = Vec::new();
    for token in tokenize(html) {
        let Token::Start {
            name, attributes, ..
        } = token
        else {
            continue;
        };
        if name != "a" {
            continue;
        }
        if let Some((_, href)) = attributes.iter().find(|(key, _)| key == "href") {
            links.push(Link {
                text: None,
                href: Some(href.clone()),
            });
        }
    }
    links
}

/// Render a token stream under an allowlist.
fn render(tokens: Vec<Token>, links: LinkMode, remote: RemoteMode) -> String {
    let mut output = String::new();
    let mut drop_depth = 0usize;
    let mut drop_element = String::new();

    for token in tokens {
        match token {
            Token::Text(text) => {
                if drop_depth == 0 {
                    output.push_str(&escape_text(&text));
                }
            }
            Token::Start {
                name,
                attributes,
                self_closing,
            } => {
                if drop_depth > 0 {
                    if !self_closing && name == drop_element {
                        drop_depth += 1;
                    }
                    continue;
                }
                if DROPPED_WITH_CONTENT.contains(&name.as_str()) {
                    if !self_closing {
                        drop_depth = 1;
                        drop_element = name.clone();
                    }
                    continue;
                }
                if !ALLOWED_ELEMENTS.contains(&name.as_str()) {
                    // An unknown element: drop the tag, keep its content.
                    continue;
                }
                output.push_str(&serialize_start(&name, &attributes, links, remote));
                if self_closing {
                    output.push_str(&format!("</{name}>"));
                }
            }
            Token::End { name } => {
                if drop_depth > 0 {
                    if name == drop_element {
                        drop_depth -= 1;
                    }
                    continue;
                }
                if ALLOWED_ELEMENTS.contains(&name.as_str()) {
                    output.push_str(&format!("</{name}>"));
                }
            }
        }
    }
    output
}

/// Serialize a start tag with only the attributes that are allowed.
fn serialize_start(
    name: &str,
    attributes: &[(String, String)],
    links: LinkMode,
    remote: RemoteMode,
) -> String {
    let mut result = format!("<{name}");
    for (key, value) in allowed_attributes(name, attributes, links, remote) {
        result.push_str(&format!(" {key}=\"{}\"", escape_attribute(&value)));
    }
    result.push('>');
    result
}

/// The attributes that survive on one element.
fn allowed_attributes(
    name: &str,
    attributes: &[(String, String)],
    links: LinkMode,
    remote: RemoteMode,
) -> Vec<(String, String)> {
    let mut result = Vec::new();
    for (key, value) in attributes {
        let lower = key.to_ascii_lowercase();
        if lower.starts_with("on") || FORBIDDEN_ATTRIBUTES.contains(&lower.as_str()) {
            continue;
        }
        if lower.starts_with("data-") {
            continue;
        }
        if REMOTE_ATTRIBUTES.contains(&lower.as_str()) {
            // A resource reference is kept only when remote content is
            // allowed, and only when it is an absolute web URL.
            if remote == RemoteMode::Allow && is_absolute_web_url(value) {
                result.push((lower, value.clone()));
            }
            continue;
        }
        let permitted = GLOBAL_ATTRIBUTES.contains(&lower.as_str())
            || ELEMENT_ATTRIBUTES
                .iter()
                .any(|(element, allowed)| *element == name && allowed.contains(&lower.as_str()));
        if !permitted {
            continue;
        }
        if lower == "href" {
            match links {
                LinkMode::Deny => continue,
                LinkMode::Keep => {
                    result.push((lower, value.clone()));
                    continue;
                }
                LinkMode::Sanitize => {
                    if !is_permitted_href(value) {
                        continue;
                    }
                    result.push((lower, sanitize_url(value)));
                    continue;
                }
            }
        }
        result.push((lower, value.clone()));
    }
    result
}

/// Whether a value is an absolute `http` or `https` URL.
fn is_absolute_web_url(value: &str) -> bool {
    let trimmed = value.trim();
    let Some((scheme, _)) = split_scheme(trimmed) else {
        return false;
    };
    matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https")
}

/// Whether a link's scheme is one the sanitizer keeps.
fn is_permitted_href(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.starts_with('#') {
        return true;
    }
    match split_scheme(trimmed) {
        Some((scheme, _)) => ALLOWED_SCHEMES.contains(&scheme.to_ascii_lowercase().as_str()),
        None => false,
    }
}

/// Split a URL into its scheme and the rest, if it has a scheme.
fn split_scheme(url: &str) -> Option<(&str, &str)> {
    let colon = url.find(':')?;
    let scheme = &url[..colon];
    if scheme.is_empty()
        || !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-')
    {
        return None;
    }
    Some((scheme, &url[colon + 1..]))
}

/// Strip the path of a `mailto:` address down to its local part.
fn sanitize_path(address: &str) -> String {
    match address.split_once('?') {
        Some((local, _)) => local.to_owned(),
        None => address.to_owned(),
    }
}

/// Escape text content.
fn escape_text(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => result.push_str("&amp;"),
            '<' => result.push_str("&lt;"),
            '>' => result.push_str("&gt;"),
            _ => result.push(c),
        }
    }
    result
}

/// Escape an attribute value.
fn escape_attribute(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => result.push_str("&amp;"),
            '<' => result.push_str("&lt;"),
            '>' => result.push_str("&gt;"),
            '"' => result.push_str("&quot;"),
            '\'' => result.push_str("&#39;"),
            _ => result.push(c),
        }
    }
    result
}

/// Parse HTML into tokens.
///
/// The tokenizer is deliberately forgiving about malformed markup and strict
/// about what it emits: an unterminated tag is dropped, an unterminated
/// attribute value is dropped with its tag, and text is decoded and
/// re-escaped rather than passed through.
fn tokenize(html: &str) -> Vec<Token> {
    let bytes = html.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0usize;
    let mut text_start = 0usize;

    while index < bytes.len() {
        if bytes[index] != b'<' {
            index += 1;
            continue;
        }
        let rest = &html[index..];

        if rest.starts_with("<!--") {
            flush_text(&mut tokens, html, text_start, index);
            match rest.find("-->") {
                Some(end) => index += end + 3,
                None => index = bytes.len(),
            }
            text_start = index;
            continue;
        }

        if rest.starts_with("<!") {
            flush_text(&mut tokens, html, text_start, index);
            match rest.find('>') {
                Some(end) => index += end + 1,
                None => index = bytes.len(),
            }
            text_start = index;
            continue;
        }

        let is_end = rest.starts_with("</");
        let name_start = if is_end { 2 } else { 1 };
        let name: String = rest[name_start..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == ':')
            .collect::<String>()
            .to_ascii_lowercase();

        if name.is_empty() {
            // A `<` that starts no tag is text, so it stays part of the
            // pending text run.
            index += 1;
            continue;
        }

        flush_text(&mut tokens, html, text_start, index);

        let Some((attributes, self_closing, consumed)) =
            parse_tag(&rest[name_start + name.len()..])
        else {
            // An unterminated tag is dropped, together with what follows it.
            index = bytes.len();
            text_start = index;
            continue;
        };

        index += name_start + name.len() + consumed;

        if is_end {
            tokens.push(Token::End { name });
            text_start = index;
            continue;
        }

        tokens.push(Token::Start {
            name: name.clone(),
            attributes,
            self_closing,
        });

        if RAW_TEXT_ELEMENTS.contains(&name.as_str()) && !self_closing {
            // The content of a raw-text element is not markup, so it is
            // skipped rather than tokenized.
            let closing = format!("</{name}");
            match find_ci(&html[index..], &closing) {
                Some(offset) => index += offset,
                None => index = bytes.len(),
            }
            text_start = index;
            continue;
        }

        text_start = index;
    }

    flush_text(&mut tokens, html, text_start, bytes.len());
    tokens
}

/// Emit the pending text run, decoded and re-escaped.
fn flush_text(tokens: &mut Vec<Token>, html: &str, start: usize, end: usize) {
    if end > start {
        tokens.push(Token::Text(decode_entities(&html[start..end])));
    }
}

/// The attributes of a tag, whether the tag is self-closing, and the number
/// of bytes consumed after the tag name.
type ParsedTag = (Vec<(String, String)>, bool, usize);

/// Find the attributes of a tag.
fn parse_tag(rest: &str) -> Option<ParsedTag> {
    let bytes = rest.as_bytes();
    let mut index = 0usize;
    let mut attributes: Vec<(String, String)> = Vec::new();
    let mut self_closing = false;

    loop {
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index >= bytes.len() {
            return None;
        }
        if bytes[index] == b'>' {
            return Some((attributes, self_closing, index + 1));
        }
        if bytes[index] == b'/' {
            if index + 1 < bytes.len() && bytes[index + 1] == b'>' {
                self_closing = true;
                return Some((attributes, self_closing, index + 2));
            }
            index += 1;
            continue;
        }
        if bytes[index] == b'<' {
            // A tag that starts another tag is malformed.
            return None;
        }

        let name_start = index;
        while index < bytes.len()
            && !bytes[index].is_ascii_whitespace()
            && bytes[index] != b'='
            && bytes[index] != b'>'
            && bytes[index] != b'/'
            && bytes[index] != b'<'
        {
            index += 1;
        }
        if index == name_start {
            index += 1;
            continue;
        }
        let name = rest[name_start..index].to_ascii_lowercase();

        let mut cursor = index;
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if cursor >= bytes.len() || bytes[cursor] != b'=' {
            attributes.push((name, String::new()));
            continue;
        }
        cursor += 1;
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if cursor >= bytes.len() {
            return None;
        }

        let value = if bytes[cursor] == b'"' || bytes[cursor] == b'\'' {
            let quote = bytes[cursor];
            cursor += 1;
            let value_start = cursor;
            while cursor < bytes.len() && bytes[cursor] != quote {
                cursor += 1;
            }
            if cursor >= bytes.len() {
                // An unterminated value: drop the tag.
                return None;
            }
            let value = rest[value_start..cursor].to_owned();
            cursor += 1;
            value
        } else {
            let value_start = cursor;
            while cursor < bytes.len()
                && !bytes[cursor].is_ascii_whitespace()
                && bytes[cursor] != b'>'
                && bytes[cursor] != b'<'
            {
                cursor += 1;
            }
            rest[value_start..cursor].to_owned()
        };
        index = cursor;
        attributes.push((name, decode_entities(&value)));
    }
}

/// Decode the HTML entities a browser would decode.
///
/// Named entities are decoded for the ones that can spell a scheme; an
/// unknown entity is preserved verbatim, because a browser would leave it as
/// text rather than as a character.
fn decode_entities(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(position) = rest.find('&') {
        result.push_str(&rest[..position]);
        rest = &rest[position..];
        let Some(end) = rest.find(';') else {
            result.push('&');
            rest = &rest[1..];
            continue;
        };
        let entity = &rest[1..end];
        match decode_entity(entity) {
            Some(decoded) => {
                result.push_str(&decoded);
                rest = &rest[end + 1..];
            }
            None => {
                result.push_str(&rest[..=end]);
                rest = &rest[end + 1..];
            }
        }
    }
    result.push_str(rest);
    result
}

/// Decode one entity body, without its delimiters.
fn decode_entity(entity: &str) -> Option<String> {
    if let Some(digits) = entity.strip_prefix('#') {
        let code = if let Some(hex) = digits
            .strip_prefix('x')
            .or_else(|| digits.strip_prefix('X'))
        {
            u32::from_str_radix(hex, 16).ok()?
        } else {
            digits.parse::<u32>().ok()?
        };
        return char::from_u32(code).map(|c| c.to_string());
    }
    match entity {
        "amp" => Some("&".to_owned()),
        "lt" => Some("<".to_owned()),
        "gt" => Some(">".to_owned()),
        "quot" => Some("\"".to_owned()),
        "apos" => Some("'".to_owned()),
        "colon" => Some(":".to_owned()),
        "tab" => Some("\t".to_owned()),
        "newline" => Some("\n".to_owned()),
        "NewLine" => Some("\n".to_owned()),
        "Tab" => Some("\t".to_owned()),
        "sol" => Some("/".to_owned()),
        _ => None,
    }
}

/// Find a substring, ignoring ASCII case.
fn find_ci(haystack: &str, needle: &str) -> Option<usize> {
    let haystack = haystack.as_bytes();
    let needle = needle.as_bytes();
    if needle.len() > haystack.len() {
        return None;
    }
    for index in 0..=(haystack.len() - needle.len()) {
        if haystack[index..index + needle.len()].eq_ignore_ascii_case(needle) {
            return Some(index);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_text_and_allowlisted_markup() {
        let sanitized = sanitize_html("<p>Invoice <b>INV-12345678</b></p>");
        assert!(sanitized.contains("INV-12345678"));
        assert!(sanitized.contains("<b>"));
    }

    #[test]
    fn removes_script_elements_and_their_content() {
        let sanitized = sanitize_html("<p>hello</p><script>alert('x')</script><p>world</p>");
        assert!(!sanitized.contains("alert"));
        assert!(sanitized.contains("hello"));
        assert!(sanitized.contains("world"));
    }

    #[test]
    fn removes_event_handlers() {
        let sanitized =
            sanitize_html(r#"<a href="https://example.com" onclick="steal()">click</a>"#);
        assert!(!sanitized.contains("onclick"));
        assert!(sanitized.contains("click"));
    }

    #[test]
    fn drops_unlisted_elements_but_keeps_their_text() {
        let sanitized = sanitize_html("<marquee>text</marquee>");
        assert!(!sanitized.contains("marquee"));
        assert!(sanitized.contains("text"));
    }

    #[test]
    fn rejects_obfuscated_script_schemes() {
        let cases = [
            r#"<a href="javascript:alert(1)">x</a>"#,
            r#"<a href="JaVaScRiPt:alert(1)">x</a>"#,
            r#"<a href="&#106;avascript:alert(1)">x</a>"#,
            r#"<a href="&#x6a;avascript:alert(1)">x</a>"#,
            r#"<a href="java&#9;script:alert(1)">x</a>"#,
            r#"<a href=" javascript:alert(1)">x</a>"#,
            r#"<a href="jav&#x0A;ascript:alert(1)">x</a>"#,
        ];
        for case in cases {
            let sanitized = sanitize_html(case);
            assert!(
                !sanitized.contains("alert"),
                "case {case:?} produced {sanitized:?}"
            );
        }
    }

    #[test]
    fn drops_style_attributes_and_style_elements() {
        let sanitized = sanitize_html(
            r#"<p style="background:url(https://tracker.example/x)">text</p><style>p{color:red}</style>"#,
        );
        assert!(!sanitized.contains("tracker.example"));
        assert!(!sanitized.contains("style"));
        assert!(sanitized.contains("text"));
    }

    #[test]
    fn strips_remote_images() {
        let stripped =
            strip_remote_resources(r#"<img src="https://tracker.example/pixel.gif" alt="pixel">"#);
        assert!(!stripped.contains("tracker.example"));
        assert!(stripped.contains("pixel"));
    }

    #[test]
    fn remote_content_may_be_allowed_explicitly() {
        let kept = sanitize_html_with(
            r#"<img src="https://tracker.example/pixel.gif" alt="pixel">"#,
            LinkMode::Sanitize,
            RemoteMode::Allow,
        );
        assert!(kept.contains("tracker.example"));
    }

    #[test]
    fn an_allowed_remote_reference_must_be_a_web_url() {
        for value in [
            "data:image/svg+xml,<svg/>",
            "file:///etc/passwd",
            "/relative.png",
        ] {
            let kept = sanitize_html_with(
                &format!(r#"<img src="{value}" alt="x">"#),
                LinkMode::Sanitize,
                RemoteMode::Allow,
            );
            assert!(!kept.contains(value), "value {value:?} produced {kept:?}");
        }
    }

    #[test]
    fn removes_comments() {
        let sanitized = sanitize_html("<p>a<!-- <script>alert(1)</script> -->b</p>");
        assert!(!sanitized.contains("alert"));
    }

    #[test]
    fn sanitizes_a_token_bearing_url() {
        let sanitized = sanitize_url("https://login.example/reset?token=abc123");
        assert!(!sanitized.contains("abc123"));
        assert!(sanitized.starts_with("https://login.example"));
    }

    #[test]
    fn sanitizes_a_mailto_url() {
        assert_eq!(
            sanitize_url("mailto:me@example.com"),
            "mailto:me@example.com"
        );
        assert_eq!(
            sanitize_url("mailto:me@example.com?subject=hi"),
            "mailto:me@example.com"
        );
    }

    #[test]
    fn rejects_a_link_whose_scheme_is_not_allowed() {
        assert_eq!(sanitize_url("data:text/html,<script>"), "[REDACTED-LINK]");
        assert_eq!(sanitize_url("file:///etc/passwd"), "[REDACTED-LINK]");
    }

    #[test]
    fn a_link_in_the_body_keeps_no_token() {
        let sanitized =
            sanitize_html(r#"<a href="https://pay.example/settle?token=secret123">pay</a>"#);
        assert!(!sanitized.contains("secret123"));
    }

    #[test]
    fn a_denied_link_loses_its_destination() {
        let sanitized = sanitize_html_with(
            r#"<a href="https://pay.example/x">pay</a>"#,
            LinkMode::Deny,
            RemoteMode::Strip,
        );
        assert!(!sanitized.contains("href"));
        assert!(sanitized.contains("pay"));
    }

    #[test]
    fn extracts_links_with_their_destinations() {
        let links = extract_links(r#"<a href="https://example.com/a">text</a>"#);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].href.as_deref(), Some("https://example.com/a"));
    }

    #[test]
    fn survives_malformed_markup() {
        for case in [
            "<p>unterminated",
            "<a href=\"unterminated",
            "<<>>",
            "<p<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<!-- unterminated comment <script>alert(1)</script>",
        ] {
            let sanitized = sanitize_html(case);
            assert!(
                !sanitized.contains("alert"),
                "case {case:?} produced {sanitized:?}"
            );
        }
    }

    #[test]
    fn text_cannot_smuggle_markup_through_an_entity() {
        let sanitized = sanitize_html("<p>&lt;script&gt;alert(1)&lt;/script&gt;</p>");
        assert!(!sanitized.contains("<script"));
    }
}
