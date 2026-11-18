//! The telemetry recorder.
//!
//! The recorder is the only thing the mail path touches. It is opt-in, its
//! buffer is bounded, and every failure of the exporter is contained here so
//! that telemetry can never break mail (ADR-0001 sections 8.3 and 9).

use std::panic::{AssertUnwindSafe, catch_unwind};

use crate::buffer::BoundedEventBuffer;
use crate::config::TelemetryConfig;
use crate::event::{EventValue, LabelValue, MetricName, TelemetryEvent};
use crate::exporter::TelemetryExporter;

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
}

enum Inner {
    Disabled,
    Enabled {
        buffer: BoundedEventBuffer,
        exporter: Option<Box<dyn TelemetryExporter>>,
    },
}

/// Records telemetry without ever affecting the caller.
///
/// A disabled recorder holds neither a buffer nor a collector: it produces no
/// event, allocates nothing and never calls out. An enabled recorder keeps a
/// bounded buffer and hands batches to a collector, containing every failure
/// of that collector.
pub struct TelemetryRecorder {
    inner: Inner,
    panicked: bool,
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
        }
    }

    /// Build a recorder from configuration.
    ///
    /// Telemetry stays off unless `config.enabled` is set, in which case the
    /// collector is dropped and never called.
    pub fn new(config: &TelemetryConfig, exporter: impl TelemetryExporter + 'static) -> Self {
        if !config.enabled() {
            return TelemetryRecorder::disabled();
        }
        TelemetryRecorder {
            inner: Inner::Enabled {
                buffer: BoundedEventBuffer::with_capacity(config.buffer_capacity()),
                exporter: Some(Box::new(exporter)),
            },
            panicked: false,
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
    /// A collector that errors, times out or panics cannot affect the caller:
    /// the failure is reported in the outcome and the events stay queued. A
    /// batch that could not be delivered is retried by the next flush, while
    /// the buffer keeps its fixed capacity. A collector that panicked is
    /// retired and not used again, so its events age out of the buffer.
    pub fn flush(&mut self) -> FlushOutcome {
        let Inner::Enabled { buffer, exporter } = &mut self.inner else {
            return FlushOutcome::default();
        };

        if buffer.is_empty() {
            return FlushOutcome {
                panicked: self.panicked,
                ..FlushOutcome::default()
            };
        }

        let Some(collector) = exporter.as_mut() else {
            return FlushOutcome {
                failed: buffer.len(),
                panicked: self.panicked,
                ..FlushOutcome::default()
            };
        };

        let batch = buffer.take_batch();
        let count = batch.len();
        let outcome = catch_unwind(AssertUnwindSafe(|| collector.export_batch(&batch)));

        match outcome {
            Ok(Ok(())) => FlushOutcome {
                delivered: count,
                panicked: self.panicked,
                ..FlushOutcome::default()
            },
            Ok(Err(_)) => {
                buffer.restore(batch);
                FlushOutcome {
                    failed: count,
                    panicked: self.panicked,
                    ..FlushOutcome::default()
                }
            }
            Err(_) => {
                buffer.restore(batch);
                self.panicked = true;
                // The collector just panicked; it is not used again.
                exporter.take();
                FlushOutcome {
                    failed: count,
                    panicked: true,
                    ..FlushOutcome::default()
                }
            }
        }
    }
}
