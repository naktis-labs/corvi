//! Content classification for sensitive mail.
//!
//! ADR-0003 section 4 asks for deterministic classifiers for common
//! authentication content, and is explicit that classification is heuristic:
//! it is not a cryptographic guarantee, and a classifier failure must never be
//! read as "not sensitive".
//!
//! The types here carry the distinction between a *matched* classification and
//! an *indeterminate* one, because the two lead to different filter
//! behaviour.

use serde::{Deserialize, Serialize};

/// A classification label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Class {
    /// A likely one-time code in an authentication context.
    #[serde(rename = "auth.otp")]
    AuthOtp,
    /// Password-reset or account-recovery content.
    #[serde(rename = "auth.password_reset")]
    AuthPasswordReset,
    /// A magic link or sign-in confirmation flow.
    #[serde(rename = "auth.login_link")]
    AuthLoginLink,
    /// A second-factor or security-approval message.
    #[serde(rename = "auth.mfa")]
    AuthMfa,
    /// A financial account identifier.
    #[serde(rename = "financial.account_identifier")]
    FinancialAccountIdentifier,
    /// A credential or secret of unknown shape.
    #[serde(rename = "credential.secret")]
    CredentialSecret,
    /// A government or personal identity document.
    #[serde(rename = "personal.identity_document")]
    PersonalIdentityDocument,
}

impl Class {
    /// The wire name of this class.
    pub fn as_str(self) -> &'static str {
        match self {
            Class::AuthOtp => "auth.otp",
            Class::AuthPasswordReset => "auth.password_reset",
            Class::AuthLoginLink => "auth.login_link",
            Class::AuthMfa => "auth.mfa",
            Class::FinancialAccountIdentifier => "financial.account_identifier",
            Class::CredentialSecret => "credential.secret",
            Class::PersonalIdentityDocument => "personal.identity_document",
        }
    }
}

/// How confident a classifier is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// The classifier found a strong signal.
    High,
    /// The classifier found a weak or contextual signal.
    Medium,
    /// The classifier could not decide.
    Unknown,
}

/// Where a classification signal came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Evidence {
    /// The message subject.
    Subject,
    /// The decoded plain-text body.
    BodyText,
    /// The sanitized HTML body.
    BodyHtml,
    /// A link destination.
    LinkTarget,
    /// The message sender.
    Sender,
    /// The attachment metadata.
    Attachment,
}

/// The result of classifying a message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Classification {
    /// The class that was detected.
    pub class: Class,
    /// How confident the classifier is.
    pub confidence: Confidence,
    /// Which part of the message produced the signal.
    pub evidence: Evidence,
}

/// The overall classification state of a message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Classified {
    /// The message carries at least one classification.
    Classified(Vec<Classification>),
    /// Classification could not be completed.
    ///
    /// This is deliberately distinct from "nothing matched": an indeterminate
    /// result must never be treated as clean (ADR-0003 section 2.3).
    Indeterminate,
}

impl Classified {
    /// Whether this result carries any classification at all.
    pub fn is_classified(&self) -> bool {
        match self {
            Classified::Classified(found) => !found.is_empty(),
            Classified::Indeterminate => false,
        }
    }

    /// Whether classification failed to complete.
    pub fn is_indeterminate(&self) -> bool {
        matches!(self, Classified::Indeterminate)
    }

    /// The classes detected, if any.
    pub fn classes(&self) -> &[Classification] {
        match self {
            Classified::Classified(found) => found,
            Classified::Indeterminate => &[],
        }
    }

    /// Whether any detected classification is in `wanted`.
    pub fn contains_any(&self, wanted: &[Class]) -> bool {
        self.classes()
            .iter()
            .any(|found| wanted.contains(&found.class))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Classification {
        Classification {
            class: Class::AuthOtp,
            confidence: Confidence::High,
            evidence: Evidence::BodyText,
        }
    }

    #[test]
    fn an_indeterminate_result_is_not_a_clean_result() {
        let result = Classified::Indeterminate;
        assert!(result.is_indeterminate());
        assert!(!result.is_classified());
        assert!(!result.contains_any(&[Class::AuthOtp]));
    }

    #[test]
    fn empty_classification_is_classified_but_has_no_classes() {
        let result = Classified::Classified(Vec::new());
        assert!(!result.is_indeterminate());
        assert!(!result.is_classified());
    }

    #[test]
    fn contains_any_matches_on_class() {
        let result = Classified::Classified(vec![sample()]);
        assert!(result.contains_any(&[Class::AuthOtp]));
        assert!(!result.contains_any(&[Class::AuthMfa]));
    }
}
