//! The bounded event buffer.
//!
//! The buffer has a fixed capacity. When it is full the oldest event is
//! dropped, deterministically and visibly, so a telemetry fault can never
//! turn into unbounded memory use in the gateway.

use crate::event::TelemetryEvent;

/// A queue of events with a fixed capacity.
#[derive(Debug)]
pub struct BoundedEventBuffer {
    events: Vec<TelemetryEvent>,
    capacity: usize,
    dropped: u64,
}

impl BoundedEventBuffer {
    /// An empty buffer with room for `capacity` events.
    pub fn with_capacity(capacity: usize) -> Self {
        BoundedEventBuffer {
            events: Vec::new(),
            capacity,
            dropped: 0,
        }
    }

    /// The fixed capacity of the buffer.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// How many events are buffered.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// How many events were dropped because the buffer was full.
    pub fn dropped_count(&self) -> u64 {
        self.dropped
    }

    /// Add an event.
    ///
    /// When the buffer is full the oldest event is dropped to make room.
    pub fn push(&mut self, event: TelemetryEvent) {
        if self.capacity == 0 {
            self.dropped += 1;
            return;
        }
        if self.events.len() == self.capacity {
            self.events.remove(0);
            self.dropped += 1;
        }
        self.events.push(event);
    }

    /// The buffered events, oldest first.
    pub fn events(&self) -> &[TelemetryEvent] {
        &self.events
    }

    /// Take every buffered event, oldest first.
    pub fn take_batch(&mut self) -> Vec<TelemetryEvent> {
        std::mem::take(&mut self.events)
    }

    /// Put a batch back at the front of the buffer, oldest first.
    ///
    /// A batch that could not be delivered stays queued for the next attempt.
    /// The buffer keeps its capacity, so a permanently failing backend cannot
    /// grow memory.
    pub fn restore(&mut self, batch: Vec<TelemetryEvent>) {
        let mut restored = batch;
        restored.append(&mut self.events);
        self.events = restored;
    }
}
