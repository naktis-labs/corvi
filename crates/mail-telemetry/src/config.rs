//! Telemetry configuration.
//!
//! Telemetry is an optional operational feature (ADR-0001 sections 8 and 9),
//! so it is off unless an operator turns it on.

/// The default number of events kept in memory.
pub const DEFAULT_BUFFER_CAPACITY: usize = 256;

/// How telemetry behaves for one gateway instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TelemetryConfig {
    enabled: bool,
    buffer_capacity: usize,
}

impl TelemetryConfig {
    /// Configuration with telemetry switched on.
    pub fn opt_in(buffer_capacity: usize) -> Self {
        TelemetryConfig {
            enabled: true,
            buffer_capacity,
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

    /// Set whether telemetry is enabled.
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Set how many events are kept in memory.
    pub fn with_buffer_capacity(mut self, buffer_capacity: usize) -> Self {
        self.buffer_capacity = buffer_capacity;
        self
    }
}

impl Default for TelemetryConfig {
    /// Telemetry is off by default.
    fn default() -> Self {
        TelemetryConfig {
            enabled: false,
            buffer_capacity: DEFAULT_BUFFER_CAPACITY,
        }
    }
}
