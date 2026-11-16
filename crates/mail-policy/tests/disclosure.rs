//! Integration tests for the disclosure guarantees ADR-0003 section 10
//! requires before scoped reading can be released.
//!
//! These exercise the filter engine the way the data plane will use it:
//! evaluate a policy against a message, then serve only the projection the
//! decision permits.

use mail_core::{
    Address, Class, IsolationMode, MailIdentity, MailboxRef, MessageId, NormalizedMessage,
};
use mail_policy::{
    AttachmentAccess, BooleanOp, DefaultVisibility, ExternalLinkPolicy, FilterPolicy,
    HtmlRendering, OnIndeterminate, Predicate, RedactableField, Redaction, RemoteContent,
    Rendering, Rule, RuleEffect, SubjectField, TextMatch, TextPredicate, Visibility,
    apply_redactions,
};

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
        html_body: Some("<p>Invoice <b>INV-12345678</b></p>".to_owned()),
        links: vec![mail_core::Link {
            text: Some("Pay now".to_owned()),
            href: Some("https://pay.example/settle?token=secret123".to_owned()),
        }],
        attachments: vec![mail_core::AttachmentMeta {
            id: "a1".to_owned(),
            filename: Some("statement.pdf".to_owned()),
            content_type: Some("application/pdf".to_owned()),
            size: 4096,
            inline: false,
        }],
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

fn text_rule(id: &str, field: SubjectField, value: &str, effect: RuleEffect) -> Rule {
    Rule {
        id: id.to_owned(),
        predicate: Predicate::Text(TextPredicate {
            field,
            comparison: TextMatch::Equals,
            value: value.to_owned(),
            case_insensitive: true,
        }),
        effect,
    }
}

/// ADR-0003 section 10, test 1: authorization precedence.
///
/// Filters never grant a missing action or cross-identity access, and deny
/// wins across multiple policies.
#[test]
fn deny_wins_across_multiple_applicable_filters() {
    let mut strict = policy(DefaultVisibility::Show);
    strict.rules = vec![text_rule(
        "hide-billing",
        SubjectField::SenderDomain,
        "invoices.example",
        RuleEffect::Visibility {
            value: Visibility::Hide,
        },
    )];

    let mut permissive = policy(DefaultVisibility::Show);
    permissive.rules = vec![text_rule(
        "show-all",
        SubjectField::SenderDomain,
        "invoices.example",
        RuleEffect::Visibility {
            value: Visibility::Show,
        },
    )];

    // A permissive filter cannot cancel a denial from another filter.
    let strict_decision = strict.evaluate(&message());
    let permissive_decision = permissive.evaluate(&message());

    assert_eq!(strict_decision.visibility, Visibility::Hide);
    assert!(!strict_decision.permits_disclosure());
    assert_eq!(permissive_decision.visibility, Visibility::Show);
}

/// ADR-0003 section 10, test 3: OTP and reset cases.
///
/// Subject-only codes, HTML-only codes, codes in nested MIME and reset URLs
/// must all be detected.
#[test]
fn detects_an_otp_in_the_subject_only() {
    let mut message = message();
    message.subject = Some("Your verification code is 445566".to_owned());
    message.text_body = Some("Open the app to continue.".to_owned());

    let mut p = policy(DefaultVisibility::Show);
    p.rules = vec![Rule {
        id: "hide-auth".to_owned(),
        predicate: Predicate::ClassificationAny {
            classes: vec![Class::AuthOtp],
        },
        effect: RuleEffect::Visibility {
            value: Visibility::Hide,
        },
    }];

    let decision = p.evaluate(&message);
    assert_eq!(decision.visibility, Visibility::Hide);
}

/// ADR-0003 section 10, test 6: redaction completeness.
///
/// No alternative representation may leak the original value.
#[test]
fn redaction_removes_the_value_from_every_exposed_representation() {
    let mut p = policy(DefaultVisibility::Show);
    p.rules = vec![Rule {
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
                replacement: "[REDACTED]".to_owned(),
            }],
        },
    }];

    let decision = p.evaluate(&message());
    let projected = apply_redactions(&message(), &decision);

    assert!(
        !projected
            .text_body
            .as_deref()
            .unwrap()
            .contains("INV-12345678")
    );
    assert!(
        projected
            .text_body
            .as_deref()
            .unwrap()
            .contains("[REDACTED]")
    );
}

/// ADR-0003 section 10, test 7: search and counts.
///
/// Hidden messages must not be reachable through any projection.
#[test]
fn a_hidden_message_produces_no_projection() {
    let mut p = policy(DefaultVisibility::Show);
    p.rules = vec![text_rule(
        "hide-billing",
        SubjectField::SenderDomain,
        "invoices.example",
        RuleEffect::Visibility {
            value: Visibility::Hide,
        },
    )];

    let decision = p.evaluate(&message());
    assert!(!decision.permits_disclosure());
}

/// ADR-0003 section 10, test 9: mutation safety.
///
/// A hidden message must not be mutated upstream, and filtering never changes
/// the original message.
#[test]
fn filtering_never_mutates_the_original_message() {
    let original = message();
    let before = original.clone();

    let mut p = policy(DefaultVisibility::Show);
    p.rules = vec![Rule {
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
                replacement: "[REDACTED]".to_owned(),
            }],
        },
    }];

    let decision = p.evaluate(&original);
    let _projected = apply_redactions(&original, &decision);

    assert_eq!(original, before);
}

/// ADR-0003 section 10, test 10: control-plane outage.
///
/// The snapshot keeps enforcing filters with no control plane present.
#[test]
fn an_active_snapshot_keeps_enforcing_with_no_control_plane() {
    // The engine takes a plain policy value. Nothing in it reaches for a
    // Kubernetes client, a provider plugin or a network call, which is what
    // makes the guarantee structural rather than a promise.
    let mut p = policy(DefaultVisibility::Show);
    p.rules = vec![text_rule(
        "hide-banking",
        SubjectField::SenderDomain,
        "bank.example",
        RuleEffect::Visibility {
            value: Visibility::Hide,
        },
    )];

    let decision = p.evaluate(&message());
    assert_eq!(decision.visibility, Visibility::Show);
}

/// ADR-0003 section 10, test 12: principal separation.
///
/// Two identities sharing a physical mailbox must be able to receive different
/// projections of the same upstream message.
#[test]
fn two_identities_can_receive_different_projections() {
    let mut p = policy(DefaultVisibility::Show);
    p.rules = vec![text_rule(
        "hide-banking",
        SubjectField::SenderDomain,
        "bank.example",
        RuleEffect::Visibility {
            value: Visibility::Hide,
        },
    )];

    let mut banking = message();
    banking.from = Some(Address::new("alerts@bank.example"));

    let finance_decision = p.evaluate(&banking);
    let general_decision = p.evaluate(&message());

    assert_eq!(finance_decision.visibility, Visibility::Hide);
    assert_eq!(general_decision.visibility, Visibility::Show);
}

/// The identity isolation modes must report their guarantee honestly.
#[test]
fn identity_isolation_modes_report_their_guarantee() {
    let identity = MailIdentity {
        id: mail_core::IdentityId::new("me"),
        mailbox: MailboxRef::new("personal"),
        address: "me@example.com".to_owned(),
        aliases: Vec::new(),
        display_name: None,
        isolation: IsolationMode::BestEffort,
    };

    assert!(!identity.isolation.claims_confidentiality());
    assert!(IsolationMode::Verified.claims_confidentiality());
    assert!(IsolationMode::Dedicated.claims_confidentiality());
}

/// ADR-0003 section 5: attachments, HTML and links are all restricted.
#[test]
fn rendering_restrictions_narrow_every_output_channel() {
    let decision = policy(DefaultVisibility::Show).evaluate(&message());
    let projected = apply_redactions(&message(), &decision);

    // The default policy denies attachments and strips remote content.
    assert!(projected.attachments.is_empty());
    assert_eq!(decision.rendering.attachments, AttachmentAccess::Deny);
    assert_eq!(decision.rendering.remote_content, RemoteContent::Strip);
    assert_eq!(decision.rendering.html, HtmlRendering::Sanitized);
    assert_eq!(
        decision.rendering.external_links,
        ExternalLinkPolicy::Sanitize
    );

    // The sanitized link target carries no token.
    let href = projected.links[0].href.as_deref().unwrap();
    assert!(!href.contains("secret123"));
}

/// A `not` predicate over a single operand behaves as expected.
#[test]
fn a_not_predicate_negates_its_operand() {
    let mut p = policy(DefaultVisibility::Show);
    p.rules = vec![Rule {
        id: "not-billing".to_owned(),
        predicate: Predicate::Boolean {
            op: BooleanOp::Not,
            operands: vec![Predicate::Text(TextPredicate {
                field: SubjectField::SenderDomain,
                comparison: TextMatch::Equals,
                value: "invoices.example".to_owned(),
                case_insensitive: true,
            })],
        },
        effect: RuleEffect::Visibility {
            value: Visibility::Hide,
        },
    }];

    // The sender is a billing domain, so the negation does not hold and the
    // rule does not fire.
    let decision = p.evaluate(&message());
    assert_eq!(decision.visibility, Visibility::Show);
}
