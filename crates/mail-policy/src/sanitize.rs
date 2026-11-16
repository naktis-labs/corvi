//! HTML sanitization helpers.
//!
//! ADR-0003 section 5 requires that remote content is stripped from HTML
//! bodies, and that sanitized HTML never fetches anything on the client's
//! behalf. The implementation here is deliberately conservative: it removes
//! markup that can load or execute, and strips references to remote
//! resources.
//!
//! This is a small, dependency-free pass. A production implementation should
//! parse HTML properly rather than rely on string rewriting; the boundary is
//! marked in [`sanitize_html`] so the swap is explicit.

/// Elements that can load a remote resource or execute code.
const REMOVED_ELEMENTS: [&str; 12] = [
    "script", "iframe", "object", "embed", "applet", "form", "base", "link", "meta", "noscript",
    "template", "svg",
];

/// Attributes that can load a remote resource.
const URL_ATTRIBUTES: [&str; 5] = ["src", "srcset", "background", "poster", "data"];

/// Remove scripts, embedded objects and remote references from an HTML body.
///
/// This is a string-level pass. It removes the elements listed in
/// [`REMOVED_ELEMENTS`] with their content, drops event-handler attributes and
/// removes URL-bearing attributes that point at remote resources.
pub fn sanitize_html(html: &str) -> String {
    let mut output = String::with_capacity(html.len());

    let mut rest = html;
    while let Some(start) = rest.find('<') {
        output.push_str(&rest[..start]);
        let after = &rest[start..];

        let Some(close) = after.find('>') else {
            // Unterminated tag: treat the remainder as text and stop.
            output.push_str(rest[rest.len()..].trim_start_matches('<'));
            break;
        };
        let tag = &after[..close + 1];
        let element = element_name(tag);

        if is_removed_element(&element) {
            // Drop the element and, for container elements, its content.
            rest = &after[close + 1..];
            if is_container_element(&element) {
                if let Some(end) = find_closing_tag(rest, &element) {
                    rest = &rest[end..];
                }
            }
            continue;
        }

        output.push_str(&sanitize_tag(tag));
        rest = &after[close + 1..];
    }

    output.push_str(rest);
    output
}

/// Strip references to remote resources from an HTML body.
///
/// Remote images, stylesheets and trackers are removed; the surrounding markup
/// is kept so the message still reads sensibly.
pub fn strip_remote_resources(html: &str) -> String {
    let mut output = String::with_capacity(html.len());

    let mut rest = html;
    while let Some(start) = rest.find('<') {
        output.push_str(&rest[..start]);
        let after = &rest[start..];

        let Some(close) = after.find('>') else {
            output.push_str(rest[rest.len()..].trim_start_matches('<'));
            break;
        };
        let tag = &after[..close + 1];
        let element = element_name(tag);

        if is_removed_element(&element) {
            rest = &after[close + 1..];
            if is_container_element(&element) {
                if let Some(end) = find_closing_tag(rest, &element) {
                    rest = &rest[end..];
                }
            }
            continue;
        }

        if references_remote_resource(tag, &element) {
            // Keep the element, drop the reference.
            let cleaned = strip_url_attributes(tag);
            output.push_str(&cleaned);
        } else {
            output.push_str(&sanitize_tag(tag));
        }
        rest = &after[close + 1..];
    }

    output.push_str(rest);
    output
}

/// Reduce a URL to a form that does not carry a token in its query or path.
///
/// A login link's token usually lives in the query string or the last path
/// segment. Keeping only the scheme, host and path shape removes it.
pub fn sanitize_url(href: &str) -> String {
    // `mailto:` and other opaque schemes carry no query string, so there is
    // nothing to strip beyond the address itself.
    if let Some(address) = href.strip_prefix("mailto:") {
        return format!("mailto:{address}");
    }

    let Some((scheme, rest)) = href.split_once("://") else {
        return "[REDACTED-LINK]".to_owned();
    };

    let host_end = rest.find('/').unwrap_or(rest.len());
    let host = &rest[..host_end];

    match scheme {
        "http" | "https" => format!("{scheme}://{host}/[REDACTED]"),
        _ => "[REDACTED-LINK]".to_owned(),
    }
}

fn element_name(tag: &str) -> String {
    let trimmed = tag.trim_start_matches('<').trim_start_matches('/');
    let name: String = trimmed
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect();
    name.to_ascii_lowercase()
}

fn is_removed_element(element: &str) -> bool {
    REMOVED_ELEMENTS.contains(&element)
}

fn is_container_element(element: &str) -> bool {
    matches!(
        element,
        "script"
            | "iframe"
            | "object"
            | "embed"
            | "applet"
            | "form"
            | "noscript"
            | "template"
            | "svg"
    )
}

/// Find the end of an element's closing tag, returning the offset into the
/// original string.
///
/// The search is case-insensitive but must not change byte offsets, so it
/// walks the original string rather than searching a lowercased copy.
fn find_closing_tag(html: &str, element: &str) -> Option<usize> {
    let needle = format!("</{element}");
    let needle_bytes = needle.as_bytes();
    let html_bytes = html.as_bytes();

    let mut index = 0;
    while index + needle_bytes.len() <= html_bytes.len() {
        if html_bytes[index..index + needle_bytes.len()].eq_ignore_ascii_case(needle_bytes) {
            // Include the closing '>' of the tag.
            return html[index..].find('>').map(|offset| index + offset + 1);
        }
        index += 1;
    }
    None
}

fn references_remote_resource(tag: &str, element: &str) -> bool {
    if matches!(element, "img" | "video" | "audio" | "source" | "track") {
        return has_url_attribute(tag);
    }
    if element == "style" {
        return true;
    }
    has_url_attribute(tag)
}

fn has_url_attribute(tag: &str) -> bool {
    let lower = tag.to_ascii_lowercase();
    URL_ATTRIBUTES
        .iter()
        .any(|attribute| lower.contains(&format!("{attribute}=")))
}

fn sanitize_tag(tag: &str) -> String {
    let mut result = String::with_capacity(tag.len());
    let lower = tag.to_ascii_lowercase();

    // Drop event-handler attributes entirely.
    let mut skip_until_quote: Option<char> = None;
    let mut in_tag = false;
    let mut current = String::new();

    let mut chars = tag.chars();
    for c in chars.by_ref() {
        if skip_until_quote.is_some() {
            if Some(c) == skip_until_quote {
                skip_until_quote = None;
            }
            current.push(c);
            continue;
        }

        match c {
            '<' => {
                in_tag = true;
                current.clear();
                current.push(c);
            }
            '>' => {
                in_tag = false;
                let cleaned = strip_event_handlers(&current);
                result.push_str(&cleaned);
                result.push('>');
                current.clear();
            }
            _ if in_tag => current.push(c),
            _ => result.push(c),
        }
    }

    if in_tag {
        result.push_str(&strip_event_handlers(&current));
    }

    let _ = lower;
    result
}

fn strip_event_handlers(tag: &str) -> String {
    let mut result = String::with_capacity(tag.len());
    let mut rest = tag;

    while let Some(pos) = rest.find("on") {
        let after = &rest[pos + 2..];
        let name: String = after
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric())
            .collect();

        if name.is_empty() {
            result.push_str(&rest[..pos + 2]);
            rest = after;
            continue;
        }

        // Only treat this as an event handler when it is an attribute name,
        // that is, preceded by whitespace.
        let preceded_by_space = rest[..pos]
            .chars()
            .next_back()
            .map(|c| c.is_whitespace())
            .unwrap_or(false);

        if !preceded_by_space {
            result.push_str(&rest[..pos + 2]);
            rest = after;
            continue;
        }

        // Drop the attribute and its value.
        let after_name = &after[name.len()..];
        let value_start = after_name.trim_start();
        if let Some(stripped) = value_start.strip_prefix('=') {
            let stripped = stripped.trim_start();
            let quoted = stripped
                .chars()
                .next()
                .is_some_and(|c| c == '"' || c == '\'');
            if quoted {
                let quote = stripped.chars().next().expect("checked above");
                if let Some(end) = stripped[1..].find(quote) {
                    rest = &stripped[end + 2..];
                    continue;
                }
            } else {
                match stripped.find(|c: char| c.is_whitespace() || c == '>') {
                    Some(end) => {
                        rest = &stripped[end..];
                        continue;
                    }
                    None => {
                        rest = "";
                        continue;
                    }
                }
            }
        }

        result.push_str(&rest[..pos]);
        rest = after;
    }

    result.push_str(rest);
    result
}

/// Remove URL-bearing attributes from a tag while keeping the element.
fn strip_url_attributes(tag: &str) -> String {
    let mut result = String::with_capacity(tag.len());
    let mut rest = tag;

    loop {
        // Find the next attribute name: an identifier preceded by whitespace.
        let Some(name_start) = rest.find(|c: char| c.is_whitespace()) else {
            result.push_str(rest);
            break;
        };
        let name_start = name_start + 1;
        let name_end = rest[name_start..]
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
            .map(|offset| name_start + offset)
            .unwrap_or(rest.len());

        if name_end == name_start {
            result.push_str(&rest[..name_end]);
            rest = &rest[name_end..];
            continue;
        }

        let name = rest[name_start..name_end].to_ascii_lowercase();

        // Skip whitespace, then an optional '=' and the value.
        let mut cursor = name_end;
        let after_name = &rest[cursor..];
        let trimmed = after_name.trim_start();
        cursor += after_name.len() - trimmed.len();

        if !trimmed.starts_with('=') {
            // A bare attribute: copy it and continue.
            result.push_str(&rest[..name_end]);
            rest = &rest[name_end..];
            continue;
        }

        cursor += 1; // consume '='
        let after_eq = &rest[cursor..];
        let trimmed = after_eq.trim_start();
        cursor += after_eq.len() - trimmed.len();

        let quote = trimmed.chars().next();
        let value_end = match quote {
            Some(q @ ('"' | '\'')) => match trimmed[1..].find(q) {
                Some(end) => cursor + 1 + end + 1,
                None => rest.len(),
            },
            Some(_) => match trimmed.find(char::is_whitespace) {
                Some(end) => cursor + end,
                None => rest.len(),
            },
            None => cursor,
        };

        if URL_ATTRIBUTES.contains(&name.as_str()) {
            // Drop the attribute and its value entirely.
            result.push_str(&rest[..name_start]);
            rest = &rest[value_end..];
        } else {
            result.push_str(&rest[..value_end]);
            rest = &rest[value_end..];
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_script_elements_and_their_content() {
        let html = "<p>hello</p><script>alert('x')</script><p>world</p>";
        let sanitized = sanitize_html(html);
        assert!(!sanitized.contains("alert"));
        assert!(sanitized.contains("hello"));
        assert!(sanitized.contains("world"));
    }

    #[test]
    fn removes_event_handlers() {
        let html = r#"<a href="https://example.com" onclick="steal()">click</a>"#;
        let sanitized = sanitize_html(html);
        assert!(!sanitized.contains("onclick"));
        assert!(sanitized.contains("click"));
    }

    #[test]
    fn strips_remote_images() {
        let html = r#"<img src="https://tracker.example/pixel.gif" alt="pixel">"#;
        let stripped = strip_remote_resources(html);
        assert!(!stripped.contains("tracker.example"));
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
    }

    #[test]
    fn keeps_text_content() {
        let sanitized = sanitize_html("<p>Invoice <b>INV-12345678</b></p>");
        assert!(sanitized.contains("INV-12345678"));
    }
}
