//! Behaviour 2: a collection failure never breaks mail.
//!
//! ADR-0001 section 8.3 requires telemetry failures to stay independent of the
//! mail data plane, and ADR-0001 section 9 requires existing mail operations
//! to remain available during collector outages. A collector that errors, times
//! out or panics must therefore be contained inside the telemetry crate.

use mail_telemetry::testing::{FailingExporter, PanickingExporter};
use mail_telemetry::{
    EventValue, ExporterError, MetricName, TelemetryConfig, TelemetryEvent, TelemetryRecorder,
};

fn event() -> TelemetryEvent {
    TelemetryEvent::new(MetricName::GatewayRequests, EventValue::Count(1))
}

/// A stand-in for a gateway mail operation: it does its own work, records
/// telemetry and delivers it. The operation must succeed whatever the
/// collector does.
fn mail_operation(recorder: &mut TelemetryRecorder) -> Result<&'static str, String> {
    let accepted = "message accepted";
    recorder.record(event());
    recorder.flush();
    Ok(accepted)
}

#[test]
fn a_failing_collector_does_not_break_the_mail_operation() {
    let mut recorder = TelemetryRecorder::new(
        &TelemetryConfig::opt_in(8),
        FailingExporter::new(ExporterError::Unavailable),
    );

    assert_eq!(mail_operation(&mut recorder).unwrap(), "message accepted");

    let outcome = recorder.flush();
    assert_eq!(outcome.failed, 1);
    assert_eq!(outcome.delivered, 0);
    assert!(!outcome.panicked);
}

#[test]
fn a_timing_out_collector_does_not_break_the_mail_operation() {
    let mut recorder = TelemetryRecorder::new(
        &TelemetryConfig::opt_in(8),
        FailingExporter::new(ExporterError::Timeout),
    );

    assert_eq!(mail_operation(&mut recorder).unwrap(), "message accepted");

    let outcome = recorder.flush();
    assert_eq!(outcome.failed, 1);
    assert!(!outcome.panicked);
}

#[test]
fn a_rejecting_collector_does_not_break_the_mail_operation() {
    let mut recorder = TelemetryRecorder::new(
        &TelemetryConfig::opt_in(8),
        FailingExporter::new(ExporterError::Rejected),
    );

    assert_eq!(mail_operation(&mut recorder).unwrap(), "message accepted");
}

#[test]
fn a_panicking_collector_does_not_break_the_mail_operation() {
    let mut recorder =
        TelemetryRecorder::new(&TelemetryConfig::opt_in(8), PanickingExporter::new());

    assert_eq!(mail_operation(&mut recorder).unwrap(), "message accepted");

    let outcome = recorder.flush();
    assert!(outcome.panicked);
    assert_eq!(outcome.failed, 1);
    assert_eq!(outcome.delivered, 0);
}

#[test]
fn a_failing_collector_does_not_grow_the_buffer_without_limit() {
    let mut recorder = TelemetryRecorder::new(
        &TelemetryConfig::opt_in(2),
        FailingExporter::new(ExporterError::Unavailable),
    );

    for _ in 0..10 {
        recorder.record(event());
        recorder.flush();
    }

    assert_eq!(recorder.buffered_len(), 2);
    assert!(recorder.buffer_capacity().is_some_and(|cap| cap == 2));
}
