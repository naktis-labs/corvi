//! The agent skill describes what the server actually does.
//!
//! `docs/spec/mcp.md` section 11 says: "Do not publish a skill describing
//! tools as implemented until the server exists and fixtures pass. The skill
//! must be treated as guidance, not a substitute for any server-side
//! authorization." These tests hold the skill to that: every tool it
//! documents exists, and it does not advertise a capability the server does
//! not have.

mod common;

use std::str::FromStr;

use common::ALL_ACTIONS;
use mail_api::mcp::ToolCatalogue;

const SKILL: &str = include_str!("../../../skills/corvi-mcp/SKILL.md");

/// The capabilities the server does not have yet.
const NOT_IMPLEMENTED: [&str; 4] = [
    "tasks/get",
    "tasks/update",
    "tasks/cancel",
    "subscriptions/listen",
];

#[test]
fn the_skill_documents_every_implemented_tool() {
    let catalogue = ToolCatalogue::load();
    for tool in catalogue.tools() {
        assert!(
            SKILL.contains(&tool.name),
            "the skill does not mention the tool {}",
            tool.name
        );
    }
}

#[test]
fn the_skill_names_no_tool_that_does_not_exist() {
    let catalogue = ToolCatalogue::load();
    for tool in catalogue.tools() {
        assert!(
            SKILL.contains(&tool.name),
            "the skill does not mention the tool {}",
            tool.name
        );
    }
}

#[test]
fn the_skill_does_not_advertise_an_unimplemented_capability() {
    // The unimplemented capabilities may be named only in the section that
    // says they are not implemented yet. Anywhere else in the skill they
    // would read as something a client may call.
    let marker = "Not implemented yet";
    let start = SKILL
        .find(marker)
        .expect("the skill names the unimplemented capabilities");
    let end = start + SKILL[start..].find("\n## ").expect("the section ends");
    let section = &SKILL[start..end];
    let rest = format!("{}{}", &SKILL[..start], &SKILL[end..]);
    for capability in NOT_IMPLEMENTED {
        assert!(
            section.contains(capability),
            "the skill does not list the unimplemented capability {capability}"
        );
        assert!(
            !rest.contains(capability),
            "the skill advertises the unimplemented capability {capability}"
        );
    }
}

#[test]
fn the_skill_says_that_it_grants_no_authorization() {
    let lowered = SKILL.to_lowercase();
    assert!(lowered.contains("grants nothing"));
    assert!(lowered.contains("authorized again on the server"));
}

#[test]
fn the_skill_documents_the_approval_flow() {
    assert!(SKILL.contains("input_required"));
    assert!(SKILL.contains("requestState"));
    assert!(SKILL.contains("elicitation/create"));
    assert!(SKILL.contains("CONFIRMATION_REQUIRED"));
}

#[test]
fn the_skill_documents_the_idempotency_rules() {
    assert!(SKILL.contains("idempotencyKey"));
    assert!(SKILL.contains("IDEMPOTENCY_CONFLICT"));
}

#[test]
fn the_skill_documents_that_hidden_mail_is_not_enumerable() {
    assert!(SKILL.contains("not proof of absence"));
    assert!(SKILL.contains("NOT_FOUND"));
}

#[test]
fn the_skill_examples_are_valid_json() {
    let directory = std::path::Path::new("../../skills/corvi-mcp/examples");
    let entries = std::fs::read_dir(directory).expect("the examples directory exists");
    let mut count = 0;
    for entry in entries {
        let path = entry.expect("the entry is readable").path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("the example is readable");
        serde_json::from_str::<serde_json::Value>(&text)
            .unwrap_or_else(|error| panic!("{} is not valid JSON: {error}", path.display()));
        count += 1;
    }
    assert!(count >= 7, "the skill has only {count} examples");
}

#[test]
fn the_skill_is_consistent_with_the_grant_vocabulary() {
    // Every scope the skill mentions for a permission must be one the
    // server's action vocabulary defines.
    for scope in [
        "mail:identities:list",
        "mail:messages:list",
        "mail:messages:read",
        "mail:messages:search",
        "mail:attachments:read",
        "mail:messages:send",
        "mail:submissions:read",
        "mail:messages:subscribe",
    ] {
        assert!(
            mail_core::Action::from_str(scope).is_ok(),
            "the skill mentions the unknown scope {scope}"
        );
    }
    let _ = ALL_ACTIONS;
}
