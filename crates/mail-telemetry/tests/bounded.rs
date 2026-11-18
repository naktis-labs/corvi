//! Behaviour 4: the telemetry model and its buffer are bounded.
//!
//! ADR-0001 section 8.1 asks for bounded labels and metric families. An
//! unbounded buffer would turn a telemetry fault into a gateway fault.

use mail_telemetry::testing::RecordingExporter;
use mail_telemetry::{
    BoundedEventBuffer, EventValue, MAX_BUFFER_CAPACITY, MetricName, TelemetryConfig,
    TelemetryEvent, TelemetryRecorder,
};

fn event(count: u64) -> TelemetryEvent {
    TelemetryEvent::new(MetricName::GatewayRequests, EventValue::Count(count))
}

fn counts(recorder: &TelemetryRecorder) -> Vec<u64> {
    recorder
        .buffered_events()
        .iter()
        .map(|event| match event.value() {
            EventValue::Count(count) => *count,
            other => panic!("unexpected value {other:?}"),
        })
        .collect()
}

#[test]
fn the_buffer_has_a_fixed_capacity() {
    let mut recorder =
        TelemetryRecorder::new(&TelemetryConfig::opt_in(3), RecordingExporter::new());

    assert_eq!(recorder.buffer_capacity(), Some(3));
    for count in 0..10 {
        recorder.record(event(count));
    }

    assert_eq!(recorder.buffered_len(), 3);
    assert!(recorder.buffered_len() <= recorder.buffer_capacity().unwrap());
}

#[test]
fn a_full_buffer_drops_the_oldest_event_deterministically() {
    let mut recorder =
        TelemetryRecorder::new(&TelemetryConfig::opt_in(2), RecordingExporter::new());

    recorder.record(event(1));
    recorder.record(event(2));
    recorder.record(event(3));

    assert_eq!(counts(&recorder), vec![2, 3]);
    assert_eq!(recorder.dropped_count(), 1);
}

#[test]
fn the_drop_policy_is_stable_across_many_events() {
    let mut recorder =
        TelemetryRecorder::new(&TelemetryConfig::opt_in(3), RecordingExporter::new());

    for count in 1..=10 {
        recorder.record(event(count));
    }

    assert_eq!(counts(&recorder), vec![8, 9, 10]);
    assert_eq!(recorder.dropped_count(), 7);
}

#[test]
fn a_delivered_batch_never_exceeds_the_capacity() {
    let exporter = RecordingExporter::new();
    let mut recorder = TelemetryRecorder::new(&TelemetryConfig::opt_in(2), exporter.clone());

    for count in 0..10 {
        recorder.record(event(count));
    }
    recorder.flush();

    for batch in exporter.batches() {
        assert!(batch.len() <= 2, "batch of {} events", batch.len());
    }
    assert_eq!(exporter.event_count(), 2);
}

#[test]
fn a_flushed_buffer_is_emptied() {
    let exporter = RecordingExporter::new();
    let mut recorder = TelemetryRecorder::new(&TelemetryConfig::opt_in(4), exporter.clone());

    recorder.record(event(1));
    assert_eq!(recorder.buffered_len(), 1);

    let outcome = recorder.flush();
    assert_eq!(outcome.delivered, 1);
    assert_eq!(recorder.buffered_len(), 0);
    assert_eq!(recorder.buffered_events().len(), 0);
}

#[test]
fn a_buffer_capacity_above_the_crate_maximum_fails_closed_to_the_maximum() {
    // "Bounded" is enforced by the crate, not by the operator's discipline:
    // a capacity past the crate ceiling is clamped, so no configuration can
    // ask this crate for an unbounded buffer.
    let config = TelemetryConfig::opt_in(usize::MAX);
    assert_eq!(config.buffer_capacity(), MAX_BUFFER_CAPACITY);
    assert_eq!(
        TelemetryConfig::opt_in(4)
            .with_buffer_capacity(usize::MAX)
            .buffer_capacity(),
        MAX_BUFFER_CAPACITY
    );

    let mut recorder = TelemetryRecorder::new(
        &TelemetryConfig::opt_in(usize::MAX),
        RecordingExporter::new(),
    );
    for count in 0..(MAX_BUFFER_CAPACITY as u64 + 2) {
        recorder.record(event(count));
    }

    assert_eq!(recorder.buffer_capacity(), Some(MAX_BUFFER_CAPACITY));
    assert_eq!(recorder.buffered_len(), MAX_BUFFER_CAPACITY);
}

#[test]
fn a_restored_batch_honours_the_capacity_and_drops_the_oldest() {
    // restore() is public, so a restored batch must not be able to push the
    // buffer past the capacity it was built with. The drop policy stays the
    // buffer's own: the oldest events go first, deterministically.
    let mut buffer = BoundedEventBuffer::with_capacity(3);
    buffer.push(event(4));
    buffer.push(event(5));

    buffer.restore(vec![event(1), event(2), event(3)]);

    assert_eq!(buffer.capacity(), 3);
    assert!(
        buffer.len() <= buffer.capacity(),
        "restored to {}",
        buffer.len()
    );
    let counts: Vec<u64> = buffer
        .events()
        .iter()
        .map(|event| match event.value() {
            EventValue::Count(count) => *count,
            other => panic!("unexpected value {other:?}"),
        })
        .collect();
    assert_eq!(counts, vec![3, 4, 5]);
    assert_eq!(buffer.dropped_count(), 2);
}

#[test]
fn a_restored_batch_larger_than_the_capacity_keeps_the_newest_events() {
    let mut buffer = BoundedEventBuffer::with_capacity(2);

    buffer.restore(vec![event(1), event(2), event(3), event(4)]);

    let counts: Vec<u64> = buffer
        .events()
        .iter()
        .map(|event| match event.value() {
            EventValue::Count(count) => *count,
            other => panic!("unexpected value {other:?}"),
        })
        .collect();
    assert_eq!(counts, vec![3, 4]);
    assert_eq!(buffer.dropped_count(), 2);
}

#[test]
fn a_restored_batch_within_the_capacity_keeps_every_event_in_order() {
    let mut buffer = BoundedEventBuffer::with_capacity(5);
    buffer.push(event(2));

    buffer.restore(vec![event(1)]);

    let counts: Vec<u64> = buffer
        .events()
        .iter()
        .map(|event| match event.value() {
            EventValue::Count(count) => *count,
            other => panic!("unexpected value {other:?}"),
        })
        .collect();
    assert_eq!(counts, vec![1, 2]);
    assert_eq!(buffer.dropped_count(), 0);
}
