//! The Rust action vocabulary must match the checked-in contract vocabulary.
//!
//! The scope names in `api/` are authoritative. A grant parsed from an OAuth
//! token scope or an authorization-details entry names one of those scopes,
//! so an action Corvi cannot parse would make a contract-conformant grant
//! unusable, and an action Corvi invented would produce a scope no contract
//! declares. This test pins the two vocabularies together.

use std::collections::BTreeSet;

use mail_core::Action;

fn contract_scopes() -> BTreeSet<String> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../api/corvi-oauth.schema.json"
    );
    let text = std::fs::read_to_string(path).expect("contract schema is readable");
    let document: serde_json::Value = serde_json::from_str(&text).expect("contract schema parses");
    let items = document
        .pointer("/$defs/authorizationDetail/properties/actions/items/enum")
        .and_then(serde_json::Value::as_array)
        .expect("authorization details declare an action enum");
    items
        .iter()
        .map(|item| item.as_str().expect("scope names are strings").to_owned())
        .collect()
}

fn rust_scopes() -> BTreeSet<String> {
    Action::ALL
        .iter()
        .map(|action| action.as_str().to_owned())
        .collect()
}

#[test]
fn every_contract_scope_is_an_action_corvi_implements() {
    let contract = contract_scopes();
    for scope in &contract {
        assert!(
            scope.parse::<Action>().is_ok(),
            "contract scope {scope:?} has no matching Action"
        );
    }
}

#[test]
fn corvi_declares_no_scope_the_contract_does_not() {
    let contract = contract_scopes();
    let rust = rust_scopes();
    let extra: Vec<&String> = rust.difference(&contract).collect();
    assert!(
        extra.is_empty(),
        "Action declares scopes the contract does not: {extra:?}"
    );
    let missing: Vec<&String> = contract.difference(&rust).collect();
    assert!(
        missing.is_empty(),
        "Action is missing contract scopes: {missing:?}"
    );
}
