//! The typed policy decision contract (ADR-0004 sections 1, 2 and 5).
//!
//! These tests pin three properties:
//!
//! 1. A valid `ALLOW` that carries malformed obligations is an **error**, not
//!    permission to ignore them.
//! 2. An engine may only narrow a locally computed decision; it can never
//!    widen a local deny nor remove a local restriction.
//! 3. The request type handed to an engine has no field for provider
//!    administrative secrets and no field for message bodies.

use mail_policy_engine::contract::{
    AttributePolicy, DecisionError, Effect, LocalDecision, Obligation, ObligationKind,
    PolicyDecision, PolicyRequest, RedactableField, WireDecision, WireObligation, restrict,
};

fn wire_decision(effect: &str, obligations: Vec<WireObligation>) -> WireDecision {
    WireDecision {
        effect: effect.to_string(),
        obligations,
    }
}

fn obligation(kind: ObligationKind, field: Option<&str>) -> Obligation {
    Obligation {
        kind,
        field_path: field.map(str::to_string),
    }
}

fn request() -> PolicyRequest {
    PolicyRequest::new(
        "principal-1",
        "scope-1",
        "message.read",
        "message-42",
        "identity-1",
        "cfg-7",
    )
}

#[test]
fn an_allow_with_a_malformed_obligation_is_an_error() {
    let decision = wire_decision(
        "allow",
        vec![WireObligation {
            kind: "redact_field".to_string(),
            field_path: None,
        }],
    );

    let error = decision
        .validate()
        .expect_err("a redact_field obligation without a field path is malformed");
    assert!(
        matches!(error, DecisionError::MalformedObligation { .. }),
        "unexpected error: {error:?}"
    );
}

#[test]
fn an_allow_with_an_obligation_on_an_unknown_field_is_an_error() {
    let decision = wire_decision(
        "allow",
        vec![WireObligation {
            kind: "redact_field".to_string(),
            field_path: Some("body.full_text".to_string()),
        }],
    );

    let error = decision
        .validate()
        .expect_err("only allowlisted field paths may be redacted");
    assert!(
        matches!(error, DecisionError::MalformedObligation { .. }),
        "unexpected error: {error:?}"
    );
}

#[test]
fn an_unknown_obligation_is_never_silently_ignored() {
    let decision = wire_decision(
        "allow",
        vec![WireObligation {
            kind: "exfiltrate_everything".to_string(),
            field_path: None,
        }],
    );

    let error = decision
        .validate()
        .expect_err("an unknown obligation fails closed");
    assert!(
        matches!(&error, DecisionError::UnknownObligation(kind) if kind == "exfiltrate_everything"),
        "unexpected error: {error:?}"
    );
}

#[test]
fn an_unknown_effect_is_never_silently_ignored() {
    let decision = wire_decision("probably", vec![]);

    let error = decision
        .validate()
        .expect_err("unknown effects fail closed");
    assert!(
        matches!(&error, DecisionError::UnknownEffect(effect) if effect == "probably"),
        "unexpected error: {error:?}"
    );
}

#[test]
fn a_valid_allow_is_accepted() {
    let decision = wire_decision(
        "allow",
        vec![
            WireObligation {
                kind: "sanitize_html".to_string(),
                field_path: None,
            },
            WireObligation {
                kind: "redact_field".to_string(),
                field_path: Some(RedactableField::Subject.path().to_string()),
            },
        ],
    );

    let validated = decision.validate().expect("a well formed allow");
    assert_eq!(validated.effect, Effect::Allow);
    assert_eq!(validated.obligations.len(), 2);
}

#[test]
fn an_engine_cannot_widen_a_local_deny() {
    let local = LocalDecision {
        effect: Effect::Deny,
        obligations: vec![obligation(ObligationKind::HideMessage, None)],
    };
    let engine = PolicyDecision {
        effect: Effect::Allow,
        obligations: vec![],
    };

    let restricted = restrict(&local, &engine);

    assert_eq!(restricted.effect, Effect::Deny);
    assert!(
        restricted
            .obligations
            .contains(&obligation(ObligationKind::HideMessage, None))
    );
}

#[test]
fn an_engine_cannot_remove_a_local_restriction() {
    let local = LocalDecision {
        effect: Effect::Allow,
        obligations: vec![
            obligation(ObligationKind::SanitizeHtml, None),
            obligation(ObligationKind::RedactField, Some("subject")),
        ],
    };
    let engine = PolicyDecision {
        effect: Effect::Allow,
        obligations: vec![],
    };

    let restricted = restrict(&local, &engine);

    assert_eq!(restricted.effect, Effect::Allow);
    assert!(
        restricted
            .obligations
            .contains(&obligation(ObligationKind::SanitizeHtml, None))
    );
    assert!(
        restricted
            .obligations
            .contains(&obligation(ObligationKind::RedactField, Some("subject")))
    );
}

#[test]
fn an_engine_deny_narrows_a_local_allow() {
    let local = LocalDecision {
        effect: Effect::Allow,
        obligations: vec![],
    };
    let engine = PolicyDecision {
        effect: Effect::Deny,
        obligations: vec![obligation(ObligationKind::HideMessage, None)],
    };

    let restricted = restrict(&local, &engine);

    assert_eq!(restricted.effect, Effect::Deny);
}

#[test]
fn an_indeterminate_engine_fails_closed() {
    let local = LocalDecision {
        effect: Effect::Allow,
        obligations: vec![],
    };
    let engine = PolicyDecision {
        effect: Effect::Indeterminate,
        obligations: vec![],
    };

    let restricted = restrict(&local, &engine);

    assert_eq!(restricted.effect, Effect::Deny);
}

#[test]
fn an_indeterminate_local_decision_fails_closed() {
    let local = LocalDecision {
        effect: Effect::Indeterminate,
        obligations: vec![],
    };
    let engine = PolicyDecision {
        effect: Effect::Allow,
        obligations: vec![],
    };

    let restricted = restrict(&local, &engine);

    assert_eq!(restricted.effect, Effect::Deny);
}

#[test]
fn an_engine_obligation_is_kept_alongside_the_local_one() {
    let local = LocalDecision {
        effect: Effect::Allow,
        obligations: vec![obligation(ObligationKind::SanitizeHtml, None)],
    };
    let engine = PolicyDecision {
        effect: Effect::Allow,
        obligations: vec![obligation(ObligationKind::DenyAttachments, None)],
    };

    let restricted = restrict(&local, &engine);

    assert_eq!(restricted.obligations.len(), 2);
    assert!(
        restricted
            .obligations
            .contains(&obligation(ObligationKind::DenyAttachments, None))
    );
}

#[test]
fn the_request_carries_no_secrets_and_no_bodies() {
    let policy = AttributePolicy::new(["department".to_string()], 64);
    let mut request = request();
    request.classifications = vec!["auth.otp".to_string()];
    request
        .set_attribute(&policy, "department", "support")
        .expect("the department attribute is allowlisted");

    let payload = serde_json::to_value(&request).expect("the request is serializable");
    let object = payload.as_object().expect("the request is an object");
    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();

    assert_eq!(
        keys,
        [
            "action",
            "attributes",
            "classifications",
            "configuration_revision",
            "credential_scope_id",
            "identity_id",
            "principal_id",
            "resource_id",
        ]
    );

    let text = serde_json::to_string(&payload)
        .expect("serializable")
        .to_lowercase();
    for forbidden in [
        "secret",
        "token",
        "password",
        "body",
        "mime",
        "attachment",
        "raw",
        "content",
    ] {
        assert!(
            !text.contains(forbidden),
            "the request payload must not mention {forbidden}: {text}"
        );
    }
}

#[test]
fn an_attribute_outside_the_allowlist_is_refused() {
    let policy = AttributePolicy::new(["department".to_string()], 64);
    let mut request = request();

    let error = request
        .set_attribute(&policy, "provider_admin_token", "secret")
        .expect_err("only allowlisted attributes may be released");

    assert!(
        matches!(error, mail_policy_engine::contract::RequestError::AttributeNotAllowed(name) if name == "provider_admin_token")
    );
}

#[test]
fn an_oversized_attribute_value_is_refused() {
    let policy = AttributePolicy::new(["department".to_string()], 4);
    let mut request = request();

    let error = request
        .set_attribute(&policy, "department", "support-team")
        .expect_err("attribute values are bounded");

    assert!(matches!(
        error,
        mail_policy_engine::contract::RequestError::AttributeValueTooLong { .. }
    ));
}
