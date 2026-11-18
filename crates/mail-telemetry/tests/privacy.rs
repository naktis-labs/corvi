//! Behaviours 3, 5 and 6: privacy.
//!
//! ADR-0001 section 8.1 forbids capturing tokens, message bodies,
//! authentication headers or mail contents in telemetry, and forbids
//! labelling with tokens, arbitrary error strings or message identifiers.
//! ADR-0003 section 6 extends the same rule to logs, traces and metrics.
//!
//! The event type therefore carries no free-form string at all: every value
//! is a closed enum, and every label key is checked against an allowlist.

use mail_telemetry::{
    Component, Direction, DurationBucket, EventValue, FailureClass, LabelError, LabelKey, LabelSet,
    LabelValue, MetricName, Outcome, Protocol, RecordOutcome, TelemetryConfig, TelemetryEvent,
    TelemetryRecorder,
};
use serde_json::Value;

fn event() -> TelemetryEvent {
    TelemetryEvent::new(MetricName::GatewayRequests, EventValue::Count(1))
}

/// Every string a serialized event may contain.
fn vocabulary() -> Vec<String> {
    let mut words: Vec<String> = Vec::new();
    words.extend(MetricName::ALL.iter().map(|name| name.as_str().to_string()));
    words.extend(LabelKey::ALL.iter().map(|key| key.as_str().to_string()));
    words.extend(Outcome::ALL.iter().map(|value| value.as_str().to_string()));
    words.extend(Protocol::ALL.iter().map(|value| value.as_str().to_string()));
    words.extend(
        Direction::ALL
            .iter()
            .map(|value| value.as_str().to_string()),
    );
    words.extend(
        Component::ALL
            .iter()
            .map(|value| value.as_str().to_string()),
    );
    words.extend(
        FailureClass::ALL
            .iter()
            .map(|value| value.as_str().to_string()),
    );
    words.extend(
        DurationBucket::ALL
            .iter()
            .map(|value| value.as_str().to_string()),
    );
    words
}

fn collect_strings(value: &Value, found: &mut Vec<String>) {
    match value {
        Value::String(text) => found.push(text.clone()),
        Value::Array(items) => items.iter().for_each(|item| collect_strings(item, found)),
        Value::Object(fields) => fields
            .values()
            .for_each(|item| collect_strings(item, found)),
        _ => {}
    }
}

#[test]
fn a_private_label_key_is_refused() {
    let private_keys = [
        "recipient",
        "recipient_address",
        "to",
        "cc",
        "bcc",
        "subject",
        "mailbox",
        "mailbox_name",
        "provider",
        "provider_host",
        "hostname",
        "body",
        "token",
        "secret",
        "credential",
        "email",
        "message_id",
        "url",
    ];

    for key in private_keys {
        let mut event = event();
        assert_eq!(
            event.set_label_key(key, LabelValue::Outcome(Outcome::Success)),
            Err(LabelError::DisallowedKey),
            "label key {key} must be refused"
        );
        assert!(event.labels().is_empty(), "refused key {key} was retained");
    }
}

#[test]
fn a_refused_label_never_reaches_the_buffer() {
    let mut recorder = TelemetryRecorder::new(
        &TelemetryConfig::opt_in(8),
        mail_telemetry::testing::RecordingExporter::new(),
    );

    let outcome = recorder.record_labeled(
        MetricName::GatewayRequests,
        EventValue::Count(1),
        &[("recipient", LabelValue::Outcome(Outcome::Success))],
    );

    assert_eq!(outcome, RecordOutcome::Refused);
    assert_eq!(recorder.buffered_len(), 0);
    assert_eq!(recorder.buffered_events().len(), 0);
}

#[test]
fn allowlisted_label_keys_are_accepted() {
    let mut event = event();

    assert_eq!(
        event.set_label_key("outcome", LabelValue::Outcome(Outcome::Success)),
        Ok(())
    );
    assert_eq!(
        event.set_label_key("protocol", LabelValue::Protocol(Protocol::Http)),
        Ok(())
    );
    assert_eq!(
        event.set_label_key("direction", LabelValue::Direction(Direction::Inbound)),
        Ok(())
    );
    assert_eq!(
        event.set_label_key("component", LabelValue::Component(Component::Gateway)),
        Ok(())
    );
    assert_eq!(
        event.set_label_key("failure", LabelValue::Failure(FailureClass::Upstream)),
        Ok(())
    );
    assert_eq!(event.labels().len(), 5);
}

#[test]
fn a_label_value_must_match_its_key() {
    let mut event = event();

    assert_eq!(
        event.set_label(LabelKey::Outcome, LabelValue::Protocol(Protocol::Http)),
        Err(LabelError::MismatchedValue)
    );
    assert!(event.labels().is_empty());
}

#[test]
fn an_event_carries_no_message_content_credential_or_endpoint() {
    let mut event = event();
    event
        .set_label(LabelKey::Outcome, LabelValue::Outcome(Outcome::Success))
        .unwrap();
    event
        .set_label(LabelKey::Protocol, LabelValue::Protocol(Protocol::Imap))
        .unwrap();

    let json = serde_json::to_string(&event).unwrap();

    assert!(!json.contains('@'), "event carries an address: {json}");
    assert!(!json.contains("http"), "event carries a URL: {json}");
    assert!(!json.contains("body"), "event carries content: {json}");
    assert!(!json.contains("token"), "event carries a token: {json}");
    assert!(!json.contains("secret"), "event carries a secret: {json}");
}

#[test]
fn every_string_in_an_event_belongs_to_the_fixed_vocabulary() {
    let mut event = TelemetryEvent::new(
        MetricName::UpstreamLatency,
        EventValue::Duration(DurationBucket::Under100Ms),
    );
    for (key, value) in [
        (LabelKey::Outcome, LabelValue::Outcome(Outcome::Failure)),
        (LabelKey::Protocol, LabelValue::Protocol(Protocol::Jmap)),
        (
            LabelKey::Direction,
            LabelValue::Direction(Direction::Outbound),
        ),
        (LabelKey::Component, LabelValue::Component(Component::Jmap)),
        (
            LabelKey::Failure,
            LabelValue::Failure(FailureClass::Timeout),
        ),
    ] {
        event.set_label(key, value).unwrap();
    }

    let mut found = Vec::new();
    collect_strings(&serde_json::to_value(&event).unwrap(), &mut found);

    let allowed = vocabulary();
    for text in found {
        assert!(
            allowed.contains(&text),
            "event contains a free-form string {text:?}"
        );
    }
}

#[test]
fn an_upstream_error_is_recorded_as_a_bounded_class() {
    let upstream = "550 5.1.1 <alice@example.com>: mailbox unavailable at https://imap.example.com";
    let failure = FailureClass::from_upstream_message(upstream);

    assert_eq!(failure, FailureClass::Upstream);

    let mut event = TelemetryEvent::new(MetricName::UpstreamFailures, EventValue::Count(1));
    event
        .set_label(LabelKey::Failure, LabelValue::Failure(failure))
        .unwrap();

    let json = serde_json::to_string(&event).unwrap();
    assert!(
        !json.contains("alice@example.com"),
        "event leaks an address"
    );
    assert!(
        !json.contains("imap.example.com"),
        "event leaks an endpoint"
    );
    assert!(json.contains("upstream"));
}

#[test]
fn an_upstream_error_string_is_never_retained() {
    let upstream = "timeout talking to imap.example.com";
    let failure = FailureClass::from_upstream_message(upstream);

    assert_eq!(failure, FailureClass::Timeout);
    assert_eq!(
        FailureClass::from_upstream_message("authentication failed for alice@example.com"),
        FailureClass::Auth
    );
    assert_eq!(
        FailureClass::from_upstream_message("rate limit exceeded"),
        FailureClass::RateLimited
    );
}

#[test]
fn the_label_set_holds_at_most_one_value_per_allowlisted_key() {
    let mut labels = LabelSet::new();

    labels
        .insert(LabelKey::Outcome, LabelValue::Outcome(Outcome::Success))
        .unwrap();
    labels
        .insert(LabelKey::Outcome, LabelValue::Outcome(Outcome::Failure))
        .unwrap();

    assert_eq!(labels.len(), 1);
    assert!(labels.len() <= LabelKey::ALL.len());
}

#[test]
fn only_allowlisted_metric_names_are_known() {
    assert_eq!(
        MetricName::parse("corvi_gateway_requests_total"),
        Some(MetricName::GatewayRequests)
    );
    assert_eq!(MetricName::parse("corvi_mail_body_bytes"), None);
    assert_eq!(MetricName::parse("alice@example.com"), None);
}
