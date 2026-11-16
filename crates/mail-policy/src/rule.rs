//! Filter rule model.
//!
//! ADR-0003 section 2.2 requires an auditable declarative subset: no
//! arbitrary policy scripts, no remote lookups, no agent-generated decisions
//! and no unconstrained user-supplied code in the mail request path.
//!
//! Every matcher below is a bounded, local predicate over the normalized
//! message model.

use mail_core::Class;
use serde::{Deserialize, Serialize};

/// Which part of the message a matcher reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectField {
    /// The message subject.
    Subject,
    /// The decoded plain-text body.
    BodyText,
    /// The sanitized HTML body.
    BodyHtml,
    /// The sender address.
    SenderAddress,
    /// The sender's domain.
    SenderDomain,
    /// The sender's display name.
    SenderName,
    /// Every visible recipient address.
    RecipientAddress,
    /// Every link destination in the body.
    LinkTarget,
    /// Every attachment filename.
    AttachmentFilename,
}

/// How a text matcher compares.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TextMatch {
    /// The field contains the value.
    Contains,
    /// The field equals the value.
    Equals,
    /// The field starts with the value.
    StartsWith,
    /// The field ends with the value.
    EndsWith,
    /// The field matches a regular expression.
    Matches,
}

/// A match against one text field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TextPredicate {
    /// The field to read.
    pub field: SubjectField,
    /// How to compare.
    #[serde(rename = "match")]
    pub comparison: TextMatch,
    /// The value to compare against.
    pub value: String,
    /// Whether the comparison ignores ASCII case.
    #[serde(default = "default_true")]
    pub case_insensitive: bool,
}

fn default_true() -> bool {
    true
}

/// A boolean combination of predicates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BooleanOp {
    /// Every nested predicate must hold.
    All,
    /// At least one nested predicate must hold.
    Any,
    /// The nested predicate must not hold.
    Not,
}

/// A predicate over the normalized message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Predicate {
    /// Match against a text field.
    Text(TextPredicate),
    /// Match against one or more classification classes.
    ClassificationAny {
        /// The classes that trigger a match.
        classes: Vec<Class>,
    },
    /// Match when the message carries any of these flags.
    HasFlag {
        /// The flags to look for.
        flags: Vec<String>,
    },
    /// Match when the message is in any of these folders.
    InFolder {
        /// The folders to look for.
        folders: Vec<String>,
    },
    /// Match when the message has at least this many attachments.
    HasAttachments {
        /// The minimum attachment count.
        #[serde(default = "default_one")]
        count: usize,
    },
    /// Combine nested predicates.
    Boolean {
        /// How to combine them.
        op: BooleanOp,
        /// The nested predicates.
        operands: Vec<Predicate>,
    },
}

fn default_one() -> usize {
    1
}

/// What a rule does when it matches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleEffect {
    /// Set the visibility.
    Visibility {
        /// The visibility to apply.
        value: crate::decision::Visibility,
    },
    /// Add redactions and keep the current visibility.
    Redact {
        /// The redactions to apply.
        redactions: Vec<crate::decision::Redaction>,
    },
    /// Narrow the rendering restrictions.
    Restrict {
        /// The restrictions to apply.
        rendering: crate::decision::Rendering,
    },
}

/// One filter rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    /// The rule's identifier, reported in audit events.
    pub id: String,
    /// The condition that triggers the rule.
    #[serde(rename = "when")]
    pub predicate: Predicate,
    /// What the rule does.
    #[serde(rename = "then")]
    pub effect: RuleEffect,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::{RedactableField, Visibility};

    #[test]
    fn a_visibility_rule_parses_from_yaml_shaped_json() {
        let json = r#"{
            "id": "hide-authentication",
            "when": { "classification_any": { "classes": ["auth.otp", "auth.mfa"] } },
            "then": { "visibility": { "value": "hide" } }
        }"#;
        let rule: Rule = serde_json::from_str(json).expect("rule parses");
        assert_eq!(rule.id, "hide-authentication");
        match rule.effect {
            RuleEffect::Visibility { value } => assert_eq!(value, Visibility::Hide),
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    #[test]
    fn a_redaction_rule_carries_its_pattern() {
        let json = r#"{
            "id": "redact-reference",
            "when": { "text": { "field": "body_text", "match": "matches", "value": "INV-[0-9]{8}" } },
            "then": { "redact": { "redactions": [
                { "field": "body_text", "pattern": "INV-[0-9]{8}", "replacement": "[REDACTED]" }
            ] } }
        }"#;
        let rule: Rule = serde_json::from_str(json).expect("rule parses");
        match rule.effect {
            RuleEffect::Redact { redactions } => {
                assert_eq!(redactions.len(), 1);
                assert_eq!(redactions[0].field, RedactableField::BodyText);
                assert_eq!(redactions[0].replacement, "[REDACTED]");
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }
}
