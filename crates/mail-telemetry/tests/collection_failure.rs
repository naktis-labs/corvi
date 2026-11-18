//! Behaviour 2: a collection failure never breaks mail.
//!
//! ADR-0001 section 8.3 requires telemetry failures to stay independent of the
//! mail data plane, and ADR-0001 section 9 requires existing mail operations
//! to remain available during collector outages. A collector that errors, times
//! out or panics must therefore be contained inside the telemetry crate.

use std::time::{Duration, Instant};

use mail_telemetry::testing::{BlockingExporter, FailingExporter, PanickingExporter};
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
    // A collector that *reports* a timeout is bounded and stays in use; only
    // an export the recorder itself had to abandon is a deadline miss.
    assert!(!outcome.timed_out);
}

#[test]
fn a_blocking_collector_cannot_block_the_mail_operation() {
    // A collector that genuinely blocks — not one that returns a Timeout
    // error — must not hold the mail path past the flush deadline.
    let mut recorder = TelemetryRecorder::new(
        &TelemetryConfig::opt_in(8).with_flush_deadline(Duration::from_millis(50)),
        BlockingExporter::blocking_for(Duration::from_secs(1)),
    );

    let started = Instant::now();
    recorder.record(event());
    let outcome = recorder.flush();
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_millis(300),
        "a blocking collector held the flush for {elapsed:?}, past the 50 ms deadline"
    );
    assert!(outcome.timed_out, "the abandoned export must be visible");
    assert_eq!(outcome.failed, 1);
    assert_eq!(outcome.delivered, 0);
    assert!(!outcome.panicked);
    assert_eq!(recorder.buffered_len(), 1, "the batch stays queued");

    // The mail operation itself succeeds, bounded, whatever the collector
    // does, and the abandoned collector is never called again.
    let started = Instant::now();
    assert_eq!(mail_operation(&mut recorder).unwrap(), "message accepted");
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_millis(300),
        "the mail operation took {elapsed:?} with no collector left to call"
    );
    assert!(recorder.flush().timed_out, "the abandonment stays visible");
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
