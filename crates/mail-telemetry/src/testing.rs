//! Fixtures for exercising the telemetry seam.
//!
//! These doubles stand in for a real exporter so that the collection rules
//! can be tested without a backend, a network or a vendor SDK.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::event::TelemetryEvent;
use crate::exporter::{ExporterError, TelemetryExporter};

#[derive(Debug, Default)]
struct Recorded {
    batches: Vec<Vec<TelemetryEvent>>,
}

/// A collector that keeps everything it is given.
#[derive(Debug, Clone, Default)]
pub struct RecordingExporter {
    recorded: Arc<Mutex<Recorded>>,
}

impl RecordingExporter {
    /// A new recording collector.
    pub fn new() -> Self {
        RecordingExporter::default()
    }

    /// How many times the collector was called.
    pub fn call_count(&self) -> usize {
        self.recorded
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .batches
            .len()
    }

    /// How many events were delivered.
    pub fn event_count(&self) -> usize {
        self.recorded
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .batches
            .iter()
            .map(Vec::len)
            .sum()
    }

    /// Every delivered batch.
    pub fn batches(&self) -> Vec<Vec<TelemetryEvent>> {
        self.recorded
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .batches
            .clone()
    }

    /// Every delivered event, in delivery order.
    pub fn exported(&self) -> Vec<TelemetryEvent> {
        self.batches().into_iter().flatten().collect()
    }
}

impl TelemetryExporter for RecordingExporter {
    fn export_batch(&mut self, batch: &[TelemetryEvent]) -> Result<(), ExporterError> {
        let mut recorded = self
            .recorded
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        recorded.batches.push(batch.to_vec());
        Ok(())
    }
}

/// A collector that always fails.
#[derive(Debug, Clone)]
pub struct FailingExporter {
    error: ExporterError,
    calls: Arc<Mutex<usize>>,
}

impl FailingExporter {
    /// A collector that fails with `error`.
    pub fn new(error: ExporterError) -> Self {
        FailingExporter {
            error,
            calls: Arc::new(Mutex::new(0)),
        }
    }

    /// How many times the collector was called.
    pub fn call_count(&self) -> usize {
        *self.calls.lock().unwrap_or_else(|error| error.into_inner())
    }
}

impl TelemetryExporter for FailingExporter {
    fn export_batch(&mut self, _batch: &[TelemetryEvent]) -> Result<(), ExporterError> {
        let mut calls = self.calls.lock().unwrap_or_else(|error| error.into_inner());
        *calls += 1;
        Err(self.error)
    }
}

/// A collector that panics.
#[derive(Debug, Clone, Default)]
pub struct PanickingExporter {
    calls: Arc<Mutex<usize>>,
}
impl PanickingExporter {
    /// A new panicking collector.
    pub fn new() -> Self {
        PanickingExporter::default()
    }

    /// How many times the collector was called.
    pub fn call_count(&self) -> usize {
        *self.calls.lock().unwrap_or_else(|error| error.into_inner())
    }
}

impl TelemetryExporter for PanickingExporter {
    fn export_batch(&mut self, _batch: &[TelemetryEvent]) -> Result<(), ExporterError> {
        let mut calls = self.calls.lock().unwrap_or_else(|error| error.into_inner());
        *calls += 1;
        panic!("the telemetry collector panicked");
    }
}

/// A collector whose export genuinely blocks, the way a stuck backend client
/// would: it does not answer early and it does not return an error, it just
/// keeps the caller waiting for `block_for`.
#[derive(Debug, Clone)]
pub struct BlockingExporter {
    block_for: Duration,
}

impl BlockingExporter {
    /// A collector that blocks every export for `block_for`.
    pub fn blocking_for(block_for: Duration) -> Self {
        BlockingExporter { block_for }
    }
}

impl TelemetryExporter for BlockingExporter {
    fn export_batch(&mut self, _batch: &[TelemetryEvent]) -> Result<(), ExporterError> {
        std::thread::sleep(self.block_for);
        Ok(())
    }
}
