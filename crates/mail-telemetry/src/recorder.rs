//! The telemetry recorder.
//!
//! The recorder is the only thing the mail path touches. It is opt-in, its
//! buffer is bounded, and every failure of the exporter is contained here so
//! that telemetry can never break mail (ADR-0001 sections 8.3 and 9).
//!
//! Containment includes time. The collector is driven on its own worker
//! thread and the flush waits for the result only for the configured flush
//! deadline: a collector that blocks cannot hold the mail path past that
//! deadline, no matter what it does inside `export_batch`.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use crate::buffer::BoundedEventBuffer;
use crate::config::TelemetryConfig;
use crate::event::{EventValue, LabelValue, MetricName, TelemetryEvent};
use crate::exporter::TelemetryExporter;
use crate::panic_suppression;

/// What happened to a recorded event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordOutcome {
    /// Telemetry is disabled, so nothing was produced and nothing was
    /// collected.
    Skipped,
    /// The event was refused, usually because it carried a label that is not
    /// on the allowlist.
    Refused,
    /// The event was accepted into the bounded buffer.
    Recorded,
}

/// What happened to a delivery attempt.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FlushOutcome {
    /// How many events were handed to a successful export.
    pub delivered: usize,
    /// How many events could not be delivered.
    pub failed: usize,
    /// Whether the collector panicked. This stays set once the collector has
    /// panicked, because the collector is not used again afterwards.
    pub panicked: bool,
    /// Whether an export was abandoned because it outlived the flush
    /// deadline. This stays set once the collector has been abandoned,
    /// because an abandoned collector is never called again: it may still be
    /// blocked inside the call that overran its deadline.
    pub timed_out: bool,
}

enum Inner {
    Disabled,
    Enabled {
        buffer: BoundedEventBuffer,
        exporter: Option<Box<dyn TelemetryExporter + Send>>,
        flush_deadline: Duration,
    },
}

/// Records telemetry without ever affecting the caller.
///
/// A disabled recorder holds neither a buffer nor a collector: it produces no
/// event, allocates nothing and never calls out. An enabled recorder keeps a
/// bounded buffer and hands batches to a collector on a dedicated worker
/// thread, containing every failure of that collector — errors, panics and
/// calls that outlive the flush deadline.
pub struct TelemetryRecorder {
    inner: Inner,
    panicked: bool,
    timed_out: bool,
}

impl std::fmt::Debug for TelemetryRecorder {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TelemetryRecorder")
            .field("enabled", &self.is_enabled())
            .field("buffered", &self.buffered_len())
            .field("dropped", &self.dropped_count())
            .field("panicked", &self.panicked)
            .finish()
    }
}

impl TelemetryRecorder {
    /// A recorder with telemetry switched off.
    ///
    /// It holds no buffer and no collector.
    pub fn disabled() -> Self {
        TelemetryRecorder {
            inner: Inner::Disabled,
            panicked: false,
            timed_out: false,
        }
    }

    /// Build a recorder from configuration.
    ///
    /// Telemetry stays off unless `config.enabled` is set, in which case the
    /// collector is dropped and never called. The exporter must be `Send`
    /// because each export runs on a dedicated worker thread, so a blocked
    /// export cannot block the caller.
    pub fn new(
        config: &TelemetryConfig,
        exporter: impl TelemetryExporter + Send + 'static,
    ) -> Self {
        if !config.enabled() {
            return TelemetryRecorder::disabled();
        }
        TelemetryRecorder {
            inner: Inner::Enabled {
                buffer: BoundedEventBuffer::with_capacity(config.buffer_capacity()),
                exporter: Some(Box::new(exporter)),
                flush_deadline: config.flush_deadline(),
            },
            panicked: false,
            timed_out: false,
        }
    }

    /// Whether telemetry is enabled.
    pub fn is_enabled(&self) -> bool {
        matches!(self.inner, Inner::Enabled { .. })
    }

    /// The capacity of the event buffer, or `None` when telemetry is disabled
    /// and no buffer exists.
    pub fn buffer_capacity(&self) -> Option<usize> {
        match &self.inner {
            Inner::Disabled => None,
            Inner::Enabled { buffer, .. } => Some(buffer.capacity()),
        }
    }

    /// How many events are waiting to be delivered.
    pub fn buffered_len(&self) -> usize {
        match &self.inner {
            Inner::Disabled => 0,
            Inner::Enabled { buffer, .. } => buffer.len(),
        }
    }

    /// The events waiting to be delivered, oldest first.
    pub fn buffered_events(&self) -> &[TelemetryEvent] {
        match &self.inner {
            Inner::Disabled => &[],
            Inner::Enabled { buffer, .. } => buffer.events(),
        }
    }

    /// How many events were dropped because the buffer was full.
    pub fn dropped_count(&self) -> u64 {
        match &self.inner {
            Inner::Disabled => 0,
            Inner::Enabled { buffer, .. } => buffer.dropped_count(),
        }
    }

    /// Record an event.
    ///
    /// This never fails: the outcome says whether the event was skipped,
    /// refused or recorded.
    pub fn record(&mut self, event: TelemetryEvent) -> RecordOutcome {
        let Inner::Enabled { buffer, .. } = &mut self.inner else {
            return RecordOutcome::Skipped;
        };
        buffer.push(event);
        RecordOutcome::Recorded
    }

    /// Record an event whose labels are named at runtime.
    ///
    /// A label key that is not on the allowlist refuses the whole event, so
    /// a refused label never reaches the buffer or a collector.
    pub fn record_labeled(
        &mut self,
        name: MetricName,
        value: EventValue,
        labels: &[(&str, LabelValue)],
    ) -> RecordOutcome {
        if !self.is_enabled() {
            return RecordOutcome::Skipped;
        }

        let mut event = TelemetryEvent::new(name, value);
        for (key, label) in labels {
            if event.set_label_key(key, *label).is_err() {
                return RecordOutcome::Refused;
            }
        }
        self.record(event)
    }

    /// Deliver the buffered events to the collector.
    ///
    /// A collector that errors, times out, panics or blocks past the flush
    /// deadline cannot affect the caller: the failure is reported in the
    /// outcome and the events stay queued. A batch that could not be delivered
    /// is retried by the next flush, while the buffer keeps its fixed
    /// capacity. A collector that panicked, or whose export had to be
    /// abandoned, is retired and not used again, so its events age out of the
    /// buffer.
    pub fn flush(&mut self) -> FlushOutcome {
        let Inner::Enabled {
            buffer,
            exporter,
            flush_deadline,
        } = &mut self.inner
        else {
            return FlushOutcome::default();
        };

        if buffer.is_empty() {
            return FlushOutcome {
                panicked: self.panicked,
                timed_out: self.timed_out,
                ..FlushOutcome::default()
            };
        }

        let Some(collector) = exporter.take() else {
            return FlushOutcome {
                failed: buffer.len(),
                panicked: self.panicked,
                timed_out: self.timed_out,
                ..FlushOutcome::default()
            };
        };

        let batch = buffer.take_batch();
        let count = batch.len();
        let attempt = export_with_deadline(collector, &batch, *flush_deadline);

        match attempt {
            Attempt::Returned { collector, result } => {
                *exporter = Some(collector);
                match result {
                    Ok(()) => FlushOutcome {
                        delivered: count,
                        panicked: self.panicked,
                        timed_out: self.timed_out,
                        ..FlushOutcome::default()
                    },
                    Err(_) => {
                        buffer.restore(batch);
                        FlushOutcome {
                            failed: count,
                            panicked: self.panicked,
                            timed_out: self.timed_out,
                            ..FlushOutcome::default()
                        }
                    }
                }
            }
            Attempt::Panicked => {
                buffer.restore(batch);
                self.panicked = true;
                // The collector just panicked; it is not used again.
                FlushOutcome {
                    failed: count,
                    panicked: true,
                    timed_out: self.timed_out,
                    ..FlushOutcome::default()
                }
            }
            Attempt::Abandoned => {
                // The export outlived its deadline and the worker may still be
                // blocked inside it, holding the collector. The collector is
                // never used again; the batch stays queued here.
                buffer.restore(batch);
                self.timed_out = true;
                FlushOutcome {
                    failed: count,
                    panicked: self.panicked,
                    timed_out: true,
                    ..FlushOutcome::default()
                }
            }
            Attempt::Lost => {
                // No worker could be started, so nothing ran and the collector
                // was dropped with the closure that never ran. The batch waits
                // for the next flush.
                buffer.restore(batch);
                FlushOutcome {
                    failed: count,
                    panicked: self.panicked,
                    timed_out: self.timed_out,
                    ..FlushOutcome::default()
                }
            }
        }
    }
}

/// What one deadline-bounded export attempt produced.
enum Attempt {
    /// The collector answered within the deadline. The collector comes back
    /// and stays in use.
    Returned {
        collector: Box<dyn TelemetryExporter + Send>,
        result: Result<(), crate::exporter::ExporterError>,
    },
    /// The collector panicked during the call. It is not used again.
    Panicked,
    /// The call outlived the deadline and was abandoned; the worker may still
    /// be running it, holding the collector. The collector is not used again.
    Abandoned,
    /// No worker thread could be started, so the collector never ran and was
    /// dropped with the closure that never ran.
    Lost,
}

/// Run one export on a worker thread, waiting no longer than `deadline`.
///
/// The batch handed to the worker is a copy: when the call is abandoned, the
/// original stays with the caller so it can be queued again. An abandoned
/// worker keeps running to completion in the background, holding the collector
/// copy it was given, and its result is discarded.
fn export_with_deadline(
    mut collector: Box<dyn TelemetryExporter + Send>,
    batch: &[TelemetryEvent],
    deadline: Duration,
) -> Attempt {
    let (sender, receiver) = mpsc::channel();
    let batch_for_worker = batch.to_vec();
    let worker = thread::Builder::new()
        .name("mail-telemetry-export".to_string())
        .spawn(move || {
            // The suppression keeps the collector's panic payload — which may
            // carry a private value — out of the panic hook's output. None
            // stands for "the collector panicked": the payload is
            // deliberately not sent anywhere.
            let outcome = panic_suppression::with_suppressed_output(|| {
                catch_unwind(AssertUnwindSafe(|| {
                    collector.export_batch(&batch_for_worker)
                }))
                .ok()
            });
            // If the caller has stopped waiting, nobody is left to receive
            // this; the send failing is the abandonment working as designed.
            let _ = sender.send((collector, outcome));
        });

    let Ok(_worker) = worker else {
        return Attempt::Lost;
    };

    match receiver.recv_timeout(deadline) {
        Ok((collector, Some(result))) => Attempt::Returned { collector, result },
        // The worker answered "panicked", or died before answering at all.
        Ok((_, None)) | Err(mpsc::RecvTimeoutError::Disconnected) => Attempt::Panicked,
        Err(mpsc::RecvTimeoutError::Timeout) => Attempt::Abandoned,
    }
}
