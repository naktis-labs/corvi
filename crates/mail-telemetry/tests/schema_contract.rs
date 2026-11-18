//! The published telemetry schema and the Rust model must agree, and the
//! schema must not describe any private field.
//!
//! `api/telemetry/telemetry-event.schema.json` is the wire contract a later
//! exporter task implements. If it drifted from the model, a real backend
//! could start accepting fields the model refuses.

use std::path::PathBuf;

use mail_telemetry::{LabelKey, MetricName};
use serde_json::Value;

fn schema_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../api/telemetry/telemetry-event.schema.json")
}

fn schema() -> Value {
    let path = schema_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{} must be readable: {error}", path.display()));
    serde_json::from_str(&raw)
        .unwrap_or_else(|error| panic!("{} must be JSON: {error}", path.display()))
}

fn sorted(values: impl Iterator<Item = String>) -> Vec<String> {
    let mut values: Vec<String> = values.collect();
    values.sort();
    values
}

#[test]
fn the_schema_is_published() {
    assert!(
        schema_path().is_file(),
        "the telemetry schema must be published"
    );
    assert!(schema().is_object());
}

#[test]
fn the_schema_forbids_unexpected_fields() {
    let schema = schema();

    assert_eq!(schema["additionalProperties"], Value::Bool(false));
    assert_eq!(
        schema["properties"]["labels"]["additionalProperties"],
        Value::Bool(false)
    );
}

#[test]
fn the_schema_lists_exactly_the_allowlisted_label_keys() {
    let schema = schema();
    let labels = schema["properties"]["labels"]["properties"]
        .as_object()
        .expect("the schema must list label properties");

    assert_eq!(
        sorted(labels.keys().cloned()),
        sorted(LabelKey::ALL.iter().map(|key| key.as_str().to_string()))
    );
}

#[test]
fn the_schema_lists_exactly_the_allowlisted_metric_names() {
    let schema = schema();
    let names = schema["properties"]["name"]["enum"]
        .as_array()
        .expect("the schema must enumerate metric names");

    assert_eq!(
        sorted(names.iter().map(|name| name.as_str().unwrap().to_string())),
        sorted(MetricName::ALL.iter().map(|name| name.as_str().to_string()))
    );
}

#[test]
fn the_schema_describes_no_private_field() {
    let text = serde_json::to_string(&schema()).unwrap().to_lowercase();

    for forbidden in [
        "recipient",
        "subject",
        "body",
        "token",
        "secret",
        "credential",
        "url",
        "hostname",
        "mailbox",
        "address",
        "content",
        "message_id",
    ] {
        assert!(
            !text.contains(forbidden),
            "the schema mentions a private field: {forbidden}"
        );
    }
}

#[test]
fn the_schema_requires_a_name_and_a_value() {
    let schema = schema();
    let required = schema["required"]
        .as_array()
        .expect("required must be a list");

    assert!(required.iter().any(|item| item == "name"));
    assert!(required.iter().any(|item| item == "value"));
}
