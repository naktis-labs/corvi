//! Bounded, privacy-preserving telemetry for the Corvi gateway.
//!
//! This crate provides the telemetry *model* and the *collection seam*. It
//! deliberately provides no backend: ADR-0001 section 8 asks for OpenTelemetry
//! instrumentation with Prometheus pull and/or OTLP push support, and this
//! crate implements neither. A later task plugs a real exporter into
//! [`TelemetryExporter`].
//!
//! The rules the crate enforces:
//!
//! - **Opt-in.** Telemetry is off by default. A disabled recorder produces no
//!   event, allocates no buffer and never calls a collector.
//! - **Mail first.** A collector that errors, times out or panics is
//!   contained: the operation that produced the event still succeeds.
//! - **Private by construction.** An event carries a metric name from a
//!   fixed allowlist, a numeric or bucketed value and at most one value per
//!   allowlisted label key. There is no free-form string field, so no body,
//!   credential, token, endpoint or recipient address can be attached.
//! - **Bounded.** The event buffer has a fixed capacity and drops the oldest
//!   event when it is full; the metric names and label keys are fixed sets.
//!
//! See ADR-0001 (system architecture) section 8 and ADR-0003 (mail filtering
//! and disclosure policies) section 6.

pub mod buffer;
pub mod config;
pub mod event;
pub mod exporter;
pub mod recorder;
pub mod testing;

pub use buffer::BoundedEventBuffer;
pub use config::{DEFAULT_BUFFER_CAPACITY, TelemetryConfig};
pub use event::{
    Component, Direction, DurationBucket, EventValue, FailureClass, LabelError, LabelKey, LabelSet,
    LabelValue, MetricName, Outcome, Protocol, TelemetryEvent,
};
pub use exporter::{ExporterError, TelemetryExporter};
pub use recorder::{FlushOutcome, RecordOutcome, TelemetryRecorder};
