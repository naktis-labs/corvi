//! Telemetry configuration.
//!
//! Telemetry is an optional operational feature (ADR-0001 sections 8 and 9),
//! so it is off unless an operator turns it on.

use std::time::Duration;

/// The default number of events kept in memory.
pub const DEFAULT_BUFFER_CAPACITY: usize = 256;

/// The default deadline for delivering one batch to the collector.
///
/// A flush runs on the mail path, so the collector gets this long and no
/// more: an export that has not finished within the deadline is abandoned.
pub const DEFAULT_FLUSH_DEADLINE: Duration = Duration::from_secs(1);

/// The largest number of events this crate will keep in memory.
///
/// "Bounded" is a property of the crate, not of the operator's discipline: a
/// configured capacity above this ceiling is clamped to it at construction,
/// so no configuration can ask this crate for an unbounded buffer. The
/// ceiling is far above any operational need for a drop-oldest buffer of
/// fixed-size events, and the effective capacity stays visible through
/// [`TelemetryConfig::buffer_capacity`].
pub const MAX_BUFFER_CAPACITY: usize = 4_096;

/// How telemetry behaves for one gateway instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TelemetryConfig {
    enabled: bool,
    buffer_capacity: usize,
    flush_deadline: Duration,
}

impl TelemetryConfig {
    /// Configuration with telemetry switched on.
    ///
    /// A capacity above [`MAX_BUFFER_CAPACITY`] is clamped to the ceiling, so
    /// the buffer this configuration describes is always bounded.
    pub fn opt_in(buffer_capacity: usize) -> Self {
        TelemetryConfig {
            enabled: true,
            buffer_capacity: clamped_capacity(buffer_capacity),
            flush_deadline: DEFAULT_FLUSH_DEADLINE,
        }
    }

    /// Whether telemetry is enabled.
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// How many events are kept in memory.
    pub fn buffer_capacity(&self) -> usize {
        self.buffer_capacity
    }

    /// The deadline one flush may spend delivering a batch to the collector.
    pub fn flush_deadline(&self) -> Duration {
        self.flush_deadline
    }

    /// Set whether telemetry is enabled.
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Set how many events are kept in memory.
    ///
    /// A capacity above [`MAX_BUFFER_CAPACITY`] is clamped to the ceiling.
    pub fn with_buffer_capacity(mut self, buffer_capacity: usize) -> Self {
        self.buffer_capacity = clamped_capacity(buffer_capacity);
        self
    }

    /// Set the deadline one flush may spend delivering a batch.
    ///
    /// The deadline bounds the caller, not the collector: an export that
    /// outlives it is abandoned. A zero deadline abandons every export, which
    /// fails closed (telemetry stops being delivered; mail is unaffected).
    pub fn with_flush_deadline(mut self, flush_deadline: Duration) -> Self {
        self.flush_deadline = flush_deadline;
        self
    }
}

/// Fail closed: never construct a capacity above the crate ceiling.
fn clamped_capacity(buffer_capacity: usize) -> usize {
    buffer_capacity.min(MAX_BUFFER_CAPACITY)
}

impl Default for TelemetryConfig {
    /// Telemetry is off by default.
    fn default() -> Self {
        TelemetryConfig {
            enabled: false,
            buffer_capacity: DEFAULT_BUFFER_CAPACITY,
            flush_deadline: DEFAULT_FLUSH_DEADLINE,
        }
    }
}
