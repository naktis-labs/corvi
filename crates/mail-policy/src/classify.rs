//! Deterministic content classification.
//!
//! ADR-0003 section 4 asks for deterministic classifiers for common
//! authentication content, and is careful about what that means: a classifier
//! is heuristic, it has false positives and false negatives, and it must never
//! be the sole gate for particularly sensitive mail.
//!
//! The classifiers here are intentionally conservative. They look for
//! authentication **context** alongside a code, rather than treating every
//! short digit string as an OTP, because the ADR calls out invoice numbers as
//! a false-positive case that must not be classified as a credential.

use mail_core::{Class, Classification, Confidence, Evidence, NormalizedMessage};

/// Words that put a message in an authentication context.
const AUTH_CONTEXT_TERMS: [&str; 24] = [
    "verification code",
    "verification code is",
    "one-time code",
    "one time code",
    "onetime code",
    "security code",
    "login code",
    "sign-in code",
    "signin code",
    "access code",
    "confirm code",
    "confirmation code",
    "otp",
    "two-factor",
    "two factor",
    "2fa",
    "auth code",
    "your code",
    "code is",
    "passcode",
    "pin code",
    "authentication code",
    "verify your identity",
    "one-time passcode",
];

/// Words that indicate a password-reset or recovery flow.
const RESET_CONTEXT_TERMS: [&str; 14] = [
    "reset your password",
    "reset password",
    "password reset",
    "forgot your password",
    "forgot password",
    "recover your password",
    "recover your account",
    "account recovery",
    "recovery link",
    "reset link",
    "change your password",
    "new password",
    "restore access",
    "password has been reset",
];

/// Words that indicate a sign-in or magic-link flow.
const LOGIN_LINK_TERMS: [&str; 12] = [
    "sign in",
    "signin",
    "log in",
    "login",
    "magic link",
    "click below to sign",
    "confirm your email",
    "confirm your identity",
    "activate your account",
    "activate account",
    "verify your email",
    "continue to sign in",
];

/// Words that indicate a second-factor or security-approval flow.
const MFA_CONTEXT_TERMS: [&str; 12] = [
    "two-factor",
    "two factor",
    "2fa",
    "multi-factor",
    "multifactor",
    "security approval",
    "approve sign-in",
    "approve your login",
    "requested access",
    "new sign-in",
    "new sign in",
    "device verification",
];

/// Domains whose mail is treated as financial by default.
const FINANCIAL_DOMAINS: [&str; 8] = [
    "bank.example",
    "paypal.example",
    "stripe.example",
    "revolut.example",
    "wise.example",
    "americanexpress.example",
    "chase.example",
    "hsbc.example",
];

/// The largest body the classifier will scan.
pub const MAX_SCAN_BYTES: usize = 512 * 1024;

/// Classify a message, returning the classifications that were found.
///
/// A message that cannot be scanned at all must not come back as "clean".
/// [`classify_message`] returns an empty list in that case, so callers that
/// need to distinguish "nothing found" from "could not look" should check
/// [`scan_text`] first.
pub fn classify_message(message: &NormalizedMessage) -> Vec<Classification> {
    let mut found = Vec::new();

    let subject = message.subject.as_deref().unwrap_or_default();
    let text = message.text_body.as_deref().unwrap_or_default();
    let html = message.html_body.as_deref().unwrap_or_default();

    let body_text = strip_html(html);
    let scan = format!("{subject}\n{text}\n{body_text}");
    let lower = scan.to_lowercase();

    if let Some(class) = classify_auth(&lower, &scan) {
        found.push(class);
    }
    if let Some(class) = classify_reset(&lower, &scan) {
        found.push(class);
    }
    if let Some(class) = classify_login_link(&lower, &scan) {
        found.push(class);
    }
    if let Some(class) = classify_mfa(&lower) {
        found.push(class);
    }
    if let Some(class) = classify_financial(message) {
        found.push(class);
    }

    found
}

/// Extract the scannable text of a message, if it can be scanned at all.
///
/// Returns `None` when the message has no content to scan or is too large to
/// scan within the budget. Callers must treat `None` as indeterminate.
pub fn scan_text(message: &NormalizedMessage) -> Option<String> {
    let subject = message.subject.as_deref().unwrap_or_default();
    let text = message.text_body.as_deref().unwrap_or_default();
    let html = message.html_body.as_deref().unwrap_or_default();

    if subject.is_empty() && text.is_empty() && html.is_empty() {
        return None;
    }

    let scan = format!("{subject}\n{text}\n{}", strip_html(html));
    if scan.len() > MAX_SCAN_BYTES {
        return None;
    }

    Some(scan)
}

/// Whether a context term appears in the scanned text.
fn has_context(lower: &str, terms: &[&str]) -> bool {
    terms.iter().any(|term| lower.contains(term))
}

/// Whether the text looks like it contains a one-time code.
///
/// A bare digit run is not enough: the message must also carry authentication
/// context. This is the false-positive case ADR-0003 warns about, where an
/// invoice number must not be treated as a credential.
fn looks_like_code(scan: &str) -> bool {
    let digits: Vec<char> = scan.chars().collect();
    let mut run = 0usize;
    let mut longest = 0usize;

    for c in digits {
        if c.is_ascii_digit() {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }

    // Six digits is the most common OTP length; four is the shortest worth
    // flagging, and it needs strong context to count.
    longest >= 6 || longest >= 4
}

fn classify_auth(lower: &str, scan: &str) -> Option<Classification> {
    let strong = has_context(lower, &AUTH_CONTEXT_TERMS);
    if !strong || !looks_like_code(scan) {
        return None;
    }

    Some(Classification {
        class: Class::AuthOtp,
        confidence: if has_context(
            lower,
            &["verification code", "one-time code", "security code"],
        ) {
            Confidence::High
        } else {
            Confidence::Medium
        },
        evidence: Evidence::BodyText,
    })
}

fn classify_reset(lower: &str, _scan: &str) -> Option<Classification> {
    if !has_context(lower, &RESET_CONTEXT_TERMS) {
        return None;
    }
    Some(Classification {
        class: Class::AuthPasswordReset,
        confidence: Confidence::High,
        evidence: Evidence::BodyText,
    })
}

fn classify_login_link(lower: &str, scan: &str) -> Option<Classification> {
    if !has_context(lower, &LOGIN_LINK_TERMS) {
        return None;
    }
    if !scan.contains("http://") && !scan.contains("https://") {
        return None;
    }
    Some(Classification {
        class: Class::AuthLoginLink,
        confidence: Confidence::Medium,
        evidence: Evidence::LinkTarget,
    })
}

fn classify_mfa(lower: &str) -> Option<Classification> {
    if !has_context(lower, &MFA_CONTEXT_TERMS) {
        return None;
    }
    Some(Classification {
        class: Class::AuthMfa,
        confidence: Confidence::Medium,
        evidence: Evidence::BodyText,
    })
}

fn classify_financial(message: &NormalizedMessage) -> Option<Classification> {
    let from = message.from.as_ref()?;
    let domain = from.address.rsplit_once('@')?.1.to_ascii_lowercase();
    if !FINANCIAL_DOMAINS.contains(&domain.as_str()) {
        return None;
    }
    Some(Classification {
        class: Class::FinancialAccountIdentifier,
        confidence: Confidence::Medium,
        evidence: Evidence::Sender,
    })
}

/// Remove HTML tags, leaving text content.
fn strip_html(html: &str) -> String {
    let mut output = String::with_capacity(html.len());
    let mut inside_tag = false;

    for c in html.chars() {
        match c {
            '<' => inside_tag = true,
            '>' => inside_tag = false,
            _ if !inside_tag => output.push(c),
            _ => {}
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use mail_core::{Address, MailboxRef, MessageId};

    fn message(subject: &str, text: &str) -> NormalizedMessage {
        NormalizedMessage {
            id: MessageId::new("m1"),
            mailbox: MailboxRef::new("personal"),
            from: Some(Address::new("noreply@example.com")),
            reply_to: Vec::new(),
            to: vec![Address::new("me@example.com")],
            cc: Vec::new(),
            subject: Some(subject.to_owned()),
            text_body: Some(text.to_owned()),
            html_body: None,
            links: Vec::new(),
            attachments: Vec::new(),
            provenance: Default::default(),
            folders: Vec::new(),
            flags: Vec::new(),
            date: None,
        }
    }

    #[test]
    fn detects_a_verification_code_in_authentication_context() {
        let found = classify_message(&message(
            "Your verification code",
            "Your verification code is 123456. Do not share it.",
        ));
        assert!(found.iter().any(|c| c.class == Class::AuthOtp));
    }

    #[test]
    fn an_invoice_number_is_not_an_otp() {
        let found = classify_message(&message(
            "Invoice 12345678",
            "Your invoice number is 12345678 and payment is due.",
        ));
        assert!(!found.iter().any(|c| c.class == Class::AuthOtp));
    }

    #[test]
    fn detects_a_password_reset() {
        let found = classify_message(&message(
            "Reset your password",
            "Click to reset your password.",
        ));
        assert!(found.iter().any(|c| c.class == Class::AuthPasswordReset));
    }

    #[test]
    fn detects_a_login_link() {
        let found = classify_message(&message(
            "Sign in to your account",
            "Use this link to sign in: https://login.example/abc",
        ));
        assert!(found.iter().any(|c| c.class == Class::AuthLoginLink));
    }

    #[test]
    fn detects_an_mfa_approval() {
        let found = classify_message(&message(
            "Security approval",
            "A two-factor sign-in was requested.",
        ));
        assert!(found.iter().any(|c| c.class == Class::AuthMfa));
    }

    #[test]
    fn a_message_with_no_content_cannot_be_scanned() {
        let empty = message("", "");
        assert!(scan_text(&empty).is_none());
    }

    #[test]
    fn an_oversized_message_cannot_be_scanned() {
        let mut big = message("subject", &"a".repeat(MAX_SCAN_BYTES + 1));
        big.text_body = Some("a".repeat(MAX_SCAN_BYTES + 1));
        assert!(scan_text(&big).is_none());
    }

    #[test]
    fn html_only_content_is_still_scanned() {
        let mut message = message("", "");
        message.html_body = Some("<p>Your verification code is 987654</p>".to_owned());
        let found = classify_message(&message);
        assert!(found.iter().any(|c| c.class == Class::AuthOtp));
    }
}
