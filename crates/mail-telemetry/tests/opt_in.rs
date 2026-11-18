//! Behaviour 1: telemetry is opt-in and switched off by default.
//!
//! ADR-0001 section 8 describes telemetry as an optional operational feature.
//! Nothing may be produced, allocated or collected unless an operator turned
//! it on.

use mail_telemetry::testing::RecordingExporter;
use mail_telemetry::{
    EventValue, MetricName, RecordOutcome, TelemetryConfig, TelemetryEvent, TelemetryRecorder,
};

fn event(count: u64) -> TelemetryEvent {
    TelemetryEvent::new(MetricName::GatewayRequests, EventValue::Count(count))
}

#[test]
fn telemetry_is_disabled_by_default() {
    let config = TelemetryConfig::default();
    assert!(!config.enabled());
}

#[test]
fn a_disabled_recorder_produces_no_event() {
    let mut recorder = TelemetryRecorder::disabled();

    assert!(!recorder.is_enabled());
    assert_eq!(recorder.record(event(1)), RecordOutcome::Skipped);
    assert_eq!(recorder.buffered_len(), 0);
    assert!(recorder.buffered_events().is_empty());
}

#[test]
fn a_disabled_recorder_allocates_no_buffer() {
    let recorder = TelemetryRecorder::disabled();

    assert_eq!(recorder.buffer_capacity(), None);
    assert_eq!(recorder.dropped_count(), 0);
}

#[test]
fn a_disabled_recorder_never_calls_the_collector() {
    let exporter = RecordingExporter::new();
    let mut recorder = TelemetryRecorder::new(&TelemetryConfig::default(), exporter.clone());

    assert_eq!(recorder.record(event(1)), RecordOutcome::Skipped);
    let outcome = recorder.flush();

    assert_eq!(outcome.delivered, 0);
    assert_eq!(outcome.failed, 0);
    assert!(!outcome.panicked);
    assert_eq!(exporter.call_count(), 0);
    assert_eq!(exporter.event_count(), 0);
}

#[test]
fn the_default_configuration_keeps_the_recorder_disabled() {
    let exporter = RecordingExporter::new();
    let mut recorder = TelemetryRecorder::new(&TelemetryConfig::default(), exporter.clone());

    assert!(!recorder.is_enabled());
    assert_eq!(recorder.buffer_capacity(), None);
    assert_eq!(recorder.record(event(1)), RecordOutcome::Skipped);
    recorder.flush();
    assert_eq!(exporter.call_count(), 0);
}

#[test]
fn an_opted_in_recorder_produces_events() {
    let exporter = RecordingExporter::new();
    let mut recorder = TelemetryRecorder::new(&TelemetryConfig::opt_in(4), exporter.clone());

    assert!(recorder.is_enabled());
    assert_eq!(recorder.buffer_capacity(), Some(4));
    assert_eq!(recorder.record(event(1)), RecordOutcome::Recorded);
    assert_eq!(recorder.buffered_len(), 1);

    let outcome = recorder.flush();
    assert_eq!(outcome.delivered, 1);
    assert_eq!(exporter.event_count(), 1);
}
