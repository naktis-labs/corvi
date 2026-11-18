//! A collector panic must not leak its payload.
//!
//! ADR-0001 forbids writing private values to telemetry or logs. A panic
//! payload is written by the process panic hook *before* `catch_unwind` can
//! act, so a collector whose `panic!` carries an identity would otherwise
//! write it to the log stream even though the recorder catches the unwind.
//! The recorder must keep a collector's panic payload out of the hook's
//! output, while every other panic in the process still reaches the hook
//! that was installed before telemetry.
//!
//! This file is deliberately a single test in its own binary: the panic hook
//! is process-global, and any other test running concurrently would
//! interfere with what it observes.

use std::panic::{self, AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex};

use mail_telemetry::{
    EventValue, ExporterError, MetricName, TelemetryConfig, TelemetryEvent, TelemetryExporter,
    TelemetryRecorder,
};

const IDENTITY: &str = "secret-identity-alice@example.test";

/// A stand-in for a third-party collector that panics with a private value
/// in its payload — exactly the thing the crate must never let into a log.
struct IdentityPanickingExporter;

impl TelemetryExporter for IdentityPanickingExporter {
    fn export_batch(&mut self, _batch: &[TelemetryEvent]) -> Result<(), ExporterError> {
        panic!("collector saw {IDENTITY}");
    }
}

#[test]
fn a_panicking_collector_leaves_no_identity_in_the_panic_output() {
    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let observer = {
        let captured = Arc::clone(&captured);
        move |info: &panic::PanicHookInfo<'_>| {
            let payload = info.payload();
            let text = if let Some(text) = payload.downcast_ref::<&str>() {
                (*text).to_string()
            } else if let Some(text) = payload.downcast_ref::<String>() {
                text.clone()
            } else {
                "<non-string panic payload>".to_string()
            };
            // A real hook writes the payload to the log stream; write it here
            // too, so what the hook emits is observable.
            eprintln!("PANIC HOOK SAW: {text}");
            captured.lock().unwrap().push(text);
        }
    };
    let previous = panic::take_hook();
    panic::set_hook(Box::new(observer));

    let mut recorder =
        TelemetryRecorder::new(&TelemetryConfig::opt_in(4), IdentityPanickingExporter);
    recorder.record(TelemetryEvent::new(
        MetricName::GatewayRequests,
        EventValue::Count(1),
    ));
    let outcome = recorder.flush();

    assert!(outcome.panicked);
    let leaked = captured.lock().unwrap().clone();
    assert!(
        leaked.iter().all(|text| !text.contains(IDENTITY)),
        "a collector panic leaked its payload to the panic hook: {leaked:?}"
    );

    // A panic outside the collector still reaches the hook that was installed
    // before, unchanged: containment is scoped to the collector, not to the
    // whole process.
    let _ = catch_unwind(AssertUnwindSafe(|| {
        panic!("surface panic outside the collector")
    }));
    let observed = captured.lock().unwrap();
    assert!(
        observed
            .iter()
            .any(|text| text.contains("surface panic outside the collector")),
        "the hook installed before telemetry must keep seeing other panics: {observed:?}"
    );
    drop(observed);
    panic::set_hook(previous);
}
