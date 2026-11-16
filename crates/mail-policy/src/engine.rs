//! The disclosure filter engine.
//!
//! This is the component ADR-0003 exists to specify: it decides what a
//! principal may learn about a message, and it runs **locally in the data
//! plane**. The control plane publishes policies; it never evaluates a mail
//! request, and provider plugins are never consulted to decide whether a
//! message is safe.
//!
//! Two invariants drive the implementation:
//!
//! 1. `hide` wins. Once any applicable rule hides a message, nothing can
//!    make it visible again.
//! 2. Indeterminate is not clean. When a rule cannot be evaluated, the
//!    policy's `on_indeterminate` decides, and the secure default is `hide`.

use mail_core::{Class, NormalizedMessage};

use crate::decision::{
    Decision, DefaultVisibility, OnIndeterminate, RedactableField, Redaction, Rendering, Visibility,
};
use crate::rule::{BooleanOp, Predicate, Rule, SubjectField, TextMatch, TextPredicate};

/// A disclosure filter policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterPolicy {
    /// The policy's identifier.
    pub id: String,
    /// What is visible when no rule matched.
    pub default_visibility: DefaultVisibility,
    /// What to do when a rule's condition cannot be evaluated.
    pub on_indeterminate: OnIndeterminate,
    /// The baseline rendering restrictions.
    pub rendering: Rendering,
    /// The policy's rules.
    pub rules: Vec<Rule>,
}

impl FilterPolicy {
    /// Evaluate this policy against a message.
    ///
    /// The returned decision is what the caller may disclose, not a boolean.
    pub fn evaluate(&self, message: &NormalizedMessage) -> Decision {
        let mut decision = Decision {
            visibility: self.default_visibility.visibility(),
            redactions: Vec::new(),
            rendering: self.rendering,
            matched_rules: Vec::new(),
            indeterminate: false,
        };

        for rule in &self.rules {
            let outcome = evaluate_predicate(&rule.predicate, message);

            // An indeterminate condition is not a clean non-match, and it is
            // not the rule's own effect either: the policy decides what an
            // unevaluable rule means for the whole message. `hide` withdraws
            // the message outright; `show` treats the rule as not having
            // matched. In neither case may the rule's effect be applied,
            // because the condition that would justify it is unknown.
            let matched = match outcome {
                MatchOutcome::Matched => true,
                MatchOutcome::NotMatched => false,
                MatchOutcome::Indeterminate => {
                    decision.indeterminate = true;
                    match self.on_indeterminate {
                        OnIndeterminate::Hide => {
                            decision.visibility = Visibility::Hide;
                            decision.matched_rules.push(crate::decision::MatchedRule {
                                id: rule.id.clone(),
                            });
                            break;
                        }
                        OnIndeterminate::Show => false,
                    }
                }
            };

            if !matched {
                continue;
            }

            decision.matched_rules.push(crate::decision::MatchedRule {
                id: rule.id.clone(),
            });

            match &rule.effect {
                crate::rule::RuleEffect::Visibility { value } => {
                    // `hide` is terminal. A later permissive rule cannot undo it.
                    if *value == Visibility::Hide {
                        decision.visibility = Visibility::Hide;
                        break;
                    }
                    if decision.visibility != Visibility::Hide {
                        decision.visibility = *value;
                    }
                }
                crate::rule::RuleEffect::Redact { redactions } => {
                    if decision.visibility != Visibility::Hide {
                        decision.redactions.extend(redactions.iter().cloned());
                        if decision.visibility == Visibility::Show {
                            decision.visibility = Visibility::Redact;
                        }
                    }
                }
                crate::rule::RuleEffect::Restrict { rendering } => {
                    if decision.visibility != Visibility::Hide {
                        decision.rendering = decision.rendering.most_restrictive(*rendering);
                    }
                }
            }
        }

        decision
    }
}

/// The outcome of evaluating one predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchOutcome {
    /// The predicate held.
    Matched,
    /// The predicate did not hold.
    NotMatched,
    /// The predicate could not be evaluated.
    Indeterminate,
}

impl MatchOutcome {
    /// Combine two outcomes under a logical AND.
    ///
    /// Indeterminate combined with a definite result is definite: a rule with
    /// one unmatched conjunct and one indeterminate conjunct did not match.
    pub fn and(self, other: MatchOutcome) -> MatchOutcome {
        match (self, other) {
            (MatchOutcome::NotMatched, _) | (_, MatchOutcome::NotMatched) => {
                MatchOutcome::NotMatched
            }
            (MatchOutcome::Indeterminate, _) | (_, MatchOutcome::Indeterminate) => {
                MatchOutcome::Indeterminate
            }
            _ => MatchOutcome::Matched,
        }
    }

    /// Combine two outcomes under a logical OR.
    pub fn or(self, other: MatchOutcome) -> MatchOutcome {
        match (self, other) {
            (MatchOutcome::Matched, _) | (_, MatchOutcome::Matched) => MatchOutcome::Matched,
            (MatchOutcome::NotMatched, MatchOutcome::NotMatched) => MatchOutcome::NotMatched,
            _ => MatchOutcome::Indeterminate,
        }
    }

    /// Negate an outcome.
    pub fn negated(self) -> MatchOutcome {
        match self {
            MatchOutcome::Matched => MatchOutcome::NotMatched,
            MatchOutcome::NotMatched => MatchOutcome::Matched,
            MatchOutcome::Indeterminate => MatchOutcome::Indeterminate,
        }
    }
}

fn evaluate_predicate(predicate: &Predicate, message: &NormalizedMessage) -> MatchOutcome {
    match predicate {
        Predicate::Text(text) => evaluate_text(text, message),
        Predicate::ClassificationAny { classes } => {
            if classes.is_empty() {
                return MatchOutcome::Indeterminate;
            }
            match classify(message, classes) {
                Some(true) => MatchOutcome::Matched,
                Some(false) => MatchOutcome::NotMatched,
                None => MatchOutcome::Indeterminate,
            }
        }
        Predicate::HasFlag { flags } => {
            if flags.is_empty() {
                return MatchOutcome::Indeterminate;
            }
            let matched = flags.iter().any(|flag| message.has_flag(flag));
            if matched {
                MatchOutcome::Matched
            } else {
                MatchOutcome::NotMatched
            }
        }
        Predicate::InFolder { folders } => {
            if folders.is_empty() {
                return MatchOutcome::Indeterminate;
            }
            let matched = folders.iter().any(|folder| {
                message
                    .folders
                    .iter()
                    .any(|f| f.eq_ignore_ascii_case(folder))
            });
            if matched {
                MatchOutcome::Matched
            } else {
                MatchOutcome::NotMatched
            }
        }
        Predicate::HasAttachments { count } => {
            if message.attachments.len() >= *count {
                MatchOutcome::Matched
            } else {
                MatchOutcome::NotMatched
            }
        }
        Predicate::Boolean { op, operands } => match op {
            BooleanOp::All => operands
                .iter()
                .map(|operand| evaluate_predicate(operand, message))
                .fold(MatchOutcome::Matched, |acc, item| acc.and(item)),
            BooleanOp::Any => operands
                .iter()
                .map(|operand| evaluate_predicate(operand, message))
                .fold(MatchOutcome::NotMatched, |acc, item| acc.or(item)),
            BooleanOp::Not => {
                if operands.len() != 1 {
                    // A negation with the wrong arity cannot be evaluated.
                    MatchOutcome::Indeterminate
                } else {
                    evaluate_predicate(&operands[0], message).negated()
                }
            }
        },
    }
}

fn evaluate_text(predicate: &TextPredicate, message: &NormalizedMessage) -> MatchOutcome {
    let values = text_values(predicate.field, message);
    if values.is_empty() {
        // An absent field is not an empty field: matching "contains" against
        // nothing would silently succeed for the wrong reason.
        return MatchOutcome::NotMatched;
    }

    for value in values {
        let matched = match predicate.comparison {
            TextMatch::Contains => value.contains(&predicate.value),
            TextMatch::Equals => value == predicate.value,
            TextMatch::StartsWith => value.starts_with(&predicate.value),
            TextMatch::EndsWith => value.ends_with(&predicate.value),
            TextMatch::Matches => {
                match crate::pattern::compile_bounded(&predicate.value, predicate.case_insensitive)
                {
                    Some(re) => re.is_match(&value),
                    // An invalid pattern cannot be evaluated, and an invalid
                    // pattern is a policy error, not a silent non-match.
                    None => return MatchOutcome::Indeterminate,
                }
            }
        };

        let matched = if predicate.case_insensitive && predicate.comparison != TextMatch::Matches {
            if matched {
                true
            } else {
                value
                    .to_lowercase()
                    .contains(&predicate.value.to_lowercase())
                    && matches!(
                        predicate.comparison,
                        TextMatch::Contains
                            | TextMatch::Equals
                            | TextMatch::StartsWith
                            | TextMatch::EndsWith
                    )
            }
        } else {
            matched
        };

        if matched {
            return MatchOutcome::Matched;
        }
    }

    MatchOutcome::NotMatched
}

fn text_values(field: SubjectField, message: &NormalizedMessage) -> Vec<String> {
    match field {
        SubjectField::Subject => message.subject.clone().into_iter().collect(),
        SubjectField::BodyText => message.text_body.clone().into_iter().collect(),
        SubjectField::BodyHtml => message.html_body.clone().into_iter().collect(),
        SubjectField::SenderAddress => message.from.iter().map(|a| a.address.clone()).collect(),
        SubjectField::SenderDomain => message
            .from
            .iter()
            .filter_map(|a| domain_of(&a.address).map(str::to_owned))
            .collect(),
        SubjectField::SenderName => message
            .from
            .iter()
            .filter_map(|a| a.display_name.clone())
            .collect(),
        SubjectField::RecipientAddress => message
            .to
            .iter()
            .chain(message.cc.iter())
            .map(|a| a.address.clone())
            .collect(),
        SubjectField::LinkTarget => message
            .links
            .iter()
            .filter_map(|link| link.href.clone())
            .collect(),
        SubjectField::AttachmentFilename => message
            .attachments
            .iter()
            .filter_map(|attachment| attachment.filename.clone())
            .collect(),
    }
}

fn domain_of(address: &str) -> Option<&str> {
    let (_, domain) = address.rsplit_once('@')?;
    if domain.is_empty() {
        None
    } else {
        Some(domain)
    }
}

/// Classify a message against a set of classes.
///
/// Returns `None` when classification could not be completed, which the
/// caller must treat as indeterminate rather than as a clean result.
fn classify(message: &NormalizedMessage, wanted: &[Class]) -> Option<bool> {
    // `None` means the message could not be scanned at all, which the caller
    // must treat as indeterminate. A scan that completes and finds nothing is
    // a clean non-match, and must not be confused with the two.
    crate::classify::scan_text(message)?;
    let found = crate::classify::classify_message(message);
    Some(found.iter().any(|c| wanted.contains(&c.class)))
}

/// Apply the redactions of a decision to a message projection.
///
/// This produces the only representation a client may see. The original
/// message is never mutated (ADR-0003 section 8).
pub fn apply_redactions(message: &NormalizedMessage, decision: &Decision) -> RedactedMessage {
    let mut projected = RedactedMessage {
        id: message.id.clone(),
        mailbox: message.mailbox.clone(),
        from: message.from.clone(),
        to: message.to.clone(),
        cc: message.cc.clone(),
        subject: message.subject.clone(),
        text_body: message.text_body.clone(),
        html_body: message.html_body.clone(),
        links: message.links.clone(),
        attachments: message.attachments.clone(),
    };

    for redaction in &decision.redactions {
        apply_one(&mut projected, redaction);
    }

    if decision.rendering.html == crate::decision::HtmlRendering::Deny {
        projected.html_body = None;
    }
    if decision.rendering.remote_content == crate::decision::RemoteContent::Strip {
        strip_remote_content(&mut projected);
    }
    if decision.rendering.external_links == crate::decision::ExternalLinkPolicy::Deny {
        projected.links.clear();
    } else if decision.rendering.external_links == crate::decision::ExternalLinkPolicy::Sanitize {
        for link in &mut projected.links {
            link.href = link.href.as_ref().map(|href| sanitize_href(href));
        }
    }
    if decision.rendering.attachments == crate::decision::AttachmentAccess::Deny {
        projected.attachments.clear();
    } else if decision.rendering.attachments == crate::decision::AttachmentAccess::Metadata {
        // Metadata only: filenames are the part most likely to leak a title.
        for attachment in &mut projected.attachments {
            attachment.filename = None;
        }
    }

    projected
}

/// A message projection that may be disclosed to a scoped caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactedMessage {
    /// The message id.
    pub id: mail_core::MessageId,
    /// The mailbox the message belongs to.
    pub mailbox: mail_core::MailboxRef,
    /// The sender.
    pub from: Option<mail_core::Address>,
    /// The primary recipients.
    pub to: Vec<mail_core::Address>,
    /// The carbon-copy recipients.
    pub cc: Vec<mail_core::Address>,
    /// The subject, possibly redacted.
    pub subject: Option<String>,
    /// The plain-text body, possibly redacted.
    pub text_body: Option<String>,
    /// The HTML body, possibly redacted.
    pub html_body: Option<String>,
    /// The links, possibly sanitized.
    pub links: Vec<mail_core::Link>,
    /// The attachment metadata.
    pub attachments: Vec<mail_core::AttachmentMeta>,
}

fn apply_one(projected: &mut RedactedMessage, redaction: &Redaction) {
    let Some(regex) = crate::pattern::compile_bounded(&redaction.pattern, true) else {
        // An invalid pattern cannot redact anything. Failing closed here means
        // dropping the affected field entirely.
        match redaction.field {
            RedactableField::Subject => projected.subject = None,
            RedactableField::BodyText => projected.text_body = None,
            RedactableField::BodyHtml => projected.html_body = None,
            RedactableField::SenderAddress => projected.from = None,
            RedactableField::RecipientAddress => {
                projected.to.clear();
                projected.cc.clear();
            }
            RedactableField::LinkTarget => {
                for link in &mut projected.links {
                    link.href = None;
                }
            }
            RedactableField::AttachmentFilename => {
                for attachment in &mut projected.attachments {
                    attachment.filename = None;
                }
            }
        }
        return;
    };

    match redaction.field {
        RedactableField::Subject => {
            projected.subject = projected.subject.as_deref().map(|value| {
                regex
                    .replace_all(value, redaction.replacement.as_str())
                    .into_owned()
            });
        }
        RedactableField::BodyText => {
            projected.text_body = projected.text_body.as_deref().map(|value| {
                regex
                    .replace_all(value, redaction.replacement.as_str())
                    .into_owned()
            });
        }
        RedactableField::BodyHtml => {
            projected.html_body = projected.html_body.as_deref().map(|value| {
                regex
                    .replace_all(value, redaction.replacement.as_str())
                    .into_owned()
            });
        }
        RedactableField::SenderAddress => {
            if let Some(from) = projected.from.as_mut() {
                from.address = regex
                    .replace_all(&from.address, redaction.replacement.as_str())
                    .into_owned();
            }
        }
        RedactableField::RecipientAddress => {
            for address in projected.to.iter_mut().chain(projected.cc.iter_mut()) {
                address.address = regex
                    .replace_all(&address.address, redaction.replacement.as_str())
                    .into_owned();
            }
        }
        RedactableField::LinkTarget => {
            for link in &mut projected.links {
                if let Some(href) = link.href.as_mut() {
                    *href = regex
                        .replace_all(href, redaction.replacement.as_str())
                        .into_owned();
                }
            }
        }
        RedactableField::AttachmentFilename => {
            for attachment in &mut projected.attachments {
                if let Some(filename) = attachment.filename.as_mut() {
                    *filename = regex
                        .replace_all(filename, redaction.replacement.as_str())
                        .into_owned();
                }
            }
        }
    }
}

/// Remove references to remote resources from an HTML body.
fn strip_remote_content(projected: &mut RedactedMessage) {
    let Some(html) = projected.html_body.as_deref() else {
        return;
    };
    projected.html_body = Some(crate::sanitize::strip_remote_resources(html));
}

/// Reduce a URL to a form that does not carry a token in its query or path.
fn sanitize_href(href: &str) -> String {
    crate::sanitize::sanitize_url(href)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::{Rule, RuleEffect};
    use mail_core::{Address, Class, Classification, Confidence, Evidence, MailboxRef, MessageId};

    fn message() -> NormalizedMessage {
        NormalizedMessage {
            id: MessageId::new("m1"),
            mailbox: MailboxRef::new("personal"),
            from: Some(Address::new("billing@invoices.example")),
            reply_to: Vec::new(),
            to: vec![Address::new("me@example.com")],
            cc: Vec::new(),
            subject: Some("Your invoice".to_owned()),
            text_body: Some("Invoice INV-12345678 is due".to_owned()),
            html_body: Some("<p>INV-12345678</p>".to_owned()),
            links: Vec::new(),
            attachments: Vec::new(),
            provenance: Default::default(),
            folders: vec!["INBOX".to_owned()],
            flags: Vec::new(),
            date: None,
        }
    }

    fn policy(default_visibility: DefaultVisibility) -> FilterPolicy {
        FilterPolicy {
            id: "test".to_owned(),
            default_visibility,
            on_indeterminate: OnIndeterminate::Hide,
            rendering: Rendering::default(),
            rules: Vec::new(),
        }
    }

    #[test]
    fn default_visibility_show_exposes_when_no_rule_matches() {
        let decision = policy(DefaultVisibility::Show).evaluate(&message());
        assert_eq!(decision.visibility, Visibility::Show);
        assert!(decision.permits_disclosure());
    }

    #[test]
    fn default_visibility_hide_withholds_when_no_rule_matches() {
        let decision = policy(DefaultVisibility::Hide).evaluate(&message());
        assert_eq!(decision.visibility, Visibility::Hide);
        assert!(!decision.permits_disclosure());
    }

    #[test]
    fn hide_wins_over_a_later_show_rule() {
        let mut policy = policy(DefaultVisibility::Show);
        policy.rules = vec![
            Rule {
                id: "hide-billing".to_owned(),
                predicate: Predicate::Text(TextPredicate {
                    field: SubjectField::SenderDomain,
                    comparison: TextMatch::Equals,
                    value: "invoices.example".to_owned(),
                    case_insensitive: true,
                }),
                effect: RuleEffect::Visibility {
                    value: Visibility::Hide,
                },
            },
            Rule {
                id: "allow-all".to_owned(),
                predicate: Predicate::Boolean {
                    op: BooleanOp::All,
                    operands: vec![Predicate::HasFlag {
                        flags: vec!["never-set".to_owned()],
                    }],
                },
                effect: RuleEffect::Visibility {
                    value: Visibility::Show,
                },
            },
        ];

        let decision = policy.evaluate(&message());
        assert_eq!(decision.visibility, Visibility::Hide);
    }

    #[test]
    fn redaction_rewrites_the_targeted_field_only() {
        let mut policy = policy(DefaultVisibility::Show);
        policy.rules = vec![Rule {
            id: "redact-reference".to_owned(),
            predicate: Predicate::Text(TextPredicate {
                field: SubjectField::BodyText,
                comparison: TextMatch::Contains,
                value: "INV-".to_owned(),
                case_insensitive: true,
            }),
            effect: RuleEffect::Redact {
                redactions: vec![Redaction {
                    field: RedactableField::BodyText,
                    pattern: r"INV-[0-9]{8}".to_owned(),
                    replacement: "[REDACTED-REFERENCE]".to_owned(),
                }],
            },
        }];

        let decision = policy.evaluate(&message());
        assert_eq!(decision.visibility, Visibility::Redact);

        let projected = apply_redactions(&message(), &decision);
        assert_eq!(
            projected.text_body.as_deref(),
            Some("Invoice [REDACTED-REFERENCE] is due")
        );
        assert_eq!(projected.subject.as_deref(), Some("Your invoice"));
    }

    #[test]
    fn an_indeterminate_predicate_follows_the_policy() {
        let mut policy = policy(DefaultVisibility::Show);
        policy.on_indeterminate = OnIndeterminate::Hide;
        policy.rules = vec![Rule {
            id: "bad-regex".to_owned(),
            predicate: Predicate::Text(TextPredicate {
                field: SubjectField::Subject,
                comparison: TextMatch::Matches,
                value: "([unclosed".to_owned(),
                case_insensitive: true,
            }),
            effect: RuleEffect::Visibility {
                value: Visibility::Show,
            },
        }];

        let decision = policy.evaluate(&message());
        assert!(decision.indeterminate);
        // The rule could not be evaluated, so its own effect was not applied
        // and the policy's on_indeterminate decided instead.
        assert_eq!(decision.visibility, Visibility::Hide);
    }

    #[test]
    fn an_indeterminate_predicate_can_be_treated_as_not_matching() {
        let mut policy = policy(DefaultVisibility::Show);
        policy.on_indeterminate = OnIndeterminate::Show;
        policy.rules = vec![Rule {
            id: "bad-regex".to_owned(),
            predicate: Predicate::Text(TextPredicate {
                field: SubjectField::Subject,
                comparison: TextMatch::Matches,
                value: "([unclosed".to_owned(),
                case_insensitive: true,
            }),
            effect: RuleEffect::Visibility {
                value: Visibility::Hide,
            },
        }];

        let decision = policy.evaluate(&message());
        assert!(decision.indeterminate);
        // The rule wanted to hide, but it could not be evaluated, so its
        // effect was not applied.
        assert_eq!(decision.visibility, Visibility::Show);
    }

    #[test]
    fn attachment_denial_clears_attachment_metadata() {
        let mut message = message();
        message.attachments.push(mail_core::AttachmentMeta {
            id: "a1".to_owned(),
            filename: Some("statement.pdf".to_owned()),
            content_type: Some("application/pdf".to_owned()),
            size: 1024,
            inline: false,
        });

        let decision = policy(DefaultVisibility::Show).evaluate(&message);
        let projected = apply_redactions(&message, &decision);
        assert!(projected.attachments.is_empty());
    }

    #[test]
    fn classification_predicate_hides_a_detected_class() {
        let mut policy = policy(DefaultVisibility::Show);
        policy.rules = vec![Rule {
            id: "hide-auth".to_owned(),
            predicate: Predicate::ClassificationAny {
                classes: vec![Class::AuthOtp],
            },
            effect: RuleEffect::Visibility {
                value: Visibility::Hide,
            },
        }];

        let mut auth = message();
        auth.subject = Some("Your verification code".to_owned());
        auth.text_body = Some("Your verification code is 123456".to_owned());

        let decision = policy.evaluate(&auth);
        assert!(!decision.indeterminate);
        assert_eq!(decision.visibility, Visibility::Hide);
    }

    #[test]
    fn classification_predicate_leaves_an_unrelated_message_visible() {
        let mut policy = policy(DefaultVisibility::Show);
        policy.rules = vec![Rule {
            id: "hide-auth".to_owned(),
            predicate: Predicate::ClassificationAny {
                classes: vec![Class::AuthOtp],
            },
            effect: RuleEffect::Visibility {
                value: Visibility::Hide,
            },
        }];

        // The message scans cleanly and is not an OTP, so the rule does not
        // match and the message stays visible.
        let decision = policy.evaluate(&message());
        assert!(!decision.indeterminate);
        assert_eq!(decision.visibility, Visibility::Show);
    }

    #[test]
    fn matched_rules_are_reported_for_audit() {
        let mut policy = policy(DefaultVisibility::Show);
        policy.rules = vec![Rule {
            id: "billing-domain".to_owned(),
            predicate: Predicate::Text(TextPredicate {
                field: SubjectField::SenderDomain,
                comparison: TextMatch::Equals,
                value: "invoices.example".to_owned(),
                case_insensitive: true,
            }),
            effect: RuleEffect::Visibility {
                value: Visibility::Show,
            },
        }];

        let decision = policy.evaluate(&message());
        assert_eq!(decision.matched_rules.len(), 1);
        assert_eq!(decision.matched_rules[0].id, "billing-domain");
    }

    #[test]
    fn classification_helpers_report_evidence() {
        let classification = Classification {
            class: Class::AuthOtp,
            confidence: Confidence::High,
            evidence: Evidence::Subject,
        };
        assert_eq!(classification.class, Class::AuthOtp);
    }
}
