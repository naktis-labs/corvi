//! The contract artifacts the crate must stay true to.
//!
//! The `corvi_mail` authorization details a token response carries are
//! declared in `api/oauth/corvi-authorization-details.schema.json`. The
//! test below reads that file and checks the emitted details against it,
//! so a change to the wire shape that nobody updates the contract fails
//! here.

use std::path::PathBuf;

use mail_auth::consent::{ConsentGrant, Constraints, authorization_details};
use mail_core::Action;

/// The checked-in contract.
fn schema_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../api/oauth/corvi-authorization-details.schema.json")
}

fn schema() -> serde_json::Value {
    let path = schema_path();
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("the contract at {path:?} cannot be read: {error}"));
    serde_json::from_str(&text).expect("the contract is readable")
}

#[test]
fn the_emitted_details_match_the_checked_in_contract() {
    let schema = schema();
    let properties = schema["items"]["properties"]
        .as_object()
        .expect("the contract declares the properties");
    let required = schema["items"]["required"]
        .as_array()
        .expect("the contract declares the required fields");
    let allowed_actions: Vec<&str> = schema["items"]["properties"]["actions"]["items"]["enum"]
        .as_array()
        .expect("the contract declares the actions")
        .iter()
        .filter_map(|action| action.as_str())
        .collect();

    let details = authorization_details(&[
        ConsentGrant {
            identity_id: "identity-a".to_owned(),
            actions: vec![Action::List, Action::Read],
            constraints: None,
        },
        ConsentGrant {
            identity_id: "identity-b".to_owned(),
            actions: vec![Action::Send],
            constraints: Some(Constraints {
                recipient_domains: vec!["alerts.example.com".to_owned()],
                unattended_send: Some(false),
                max_messages_per_hour: Some(60),
            }),
        },
    ]);

    assert_eq!(details.len(), 2);
    for detail in &details {
        let object = detail.as_object().expect("a detail is an object");
        for key in object.keys() {
            assert!(
                properties.contains_key(key),
                "the emitted key {key:?} is not in the contract"
            );
        }
        for key in required {
            let key = key.as_str().expect("a required field is a string");
            assert!(
                detail.get(key).is_some(),
                "the emitted detail is missing the required field {key:?}"
            );
        }
        assert_eq!(detail["type"], "corvi_mail");
        for action in detail["actions"]
            .as_array()
            .expect("the actions are listed")
            .iter()
        {
            let action = action.as_str().expect("an action is a string");
            assert!(
                allowed_actions.contains(&action),
                "the emitted action {action:?} is not in the contract"
            );
        }
    }
}

#[test]
fn the_contract_forbids_a_self_approved_unattended_send() {
    let schema = schema();
    assert_eq!(
        schema["$defs"]["constraints"]["properties"]["unattendedSend"]["const"],
        false
    );
}
