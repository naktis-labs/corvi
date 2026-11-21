//! The exporter seam.
//!
//! ADR-0001 section 8 asks for OpenTelemetry instrumentation with Prometheus
//! pull and/or OTLP push support. This crate implements neither backend: it
//! defines the seam a later task plugs one into, the bounded model that goes
//! across it, and the rules that keep the seam from ever affecting mail.

use crate::event::TelemetryEvent;

/// Why an export attempt failed.
///
/// Every variant is bounded. An upstream or backend error message is
/// classified before it reaches this type, because such a message may carry a
/// private value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExporterError {
    /// The backend was not reachable.
    Unavailable,
    /// The backend did not answer within its deadline.
    Timeout,
    /// The backend refused the batch.
    Rejected,
}

/// The seam a telemetry backend is plugged into.
///
/// A later task implements this trait over an OTLP push client or over the
/// cached samples a Prometheus scrape reads. ADR-0001 section 8.3 requires
/// that a scrape never calls an upstream provider API, so an implementation
/// reads cached samples and never reaches out on the scrape path.
///
/// Implementations should be bounded in size, and should report a deadline
/// miss as [`ExporterError::Timeout`] so a caller can tell it from an outage.
/// Time is not left to the implementation: the recorder drives every export
/// on its own worker thread and abandons one that outlives the configured
/// flush deadline, so an implementation that blocks cannot block the caller.
/// The recorder contains every failure, including a panic, so an
/// implementation cannot break mail.
pub trait TelemetryExporter {
    /// Export a batch of events.
    fn export_batch(&mut self, batch: &[TelemetryEvent]) -> Result<(), ExporterError>;
}
