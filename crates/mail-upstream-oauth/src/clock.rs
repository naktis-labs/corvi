//! The clock the flows read.
//!
//! Every deadline in this crate — a transaction expiry, a handoff expiry, a
//! refresh deadline — is compared against a clock the caller supplies. That
//! keeps the tests deterministic without the production code reaching for a
//! global, and it makes the expiry rules something a test can state
//! exactly.

use std::fmt;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// The source of the current time, in seconds since the epoch.
pub trait Clock: fmt::Debug {
    /// The current time.
    fn now(&self) -> u64;
}

/// The clock of the machine.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or_default()
    }
}

/// A clock that only moves when a test moves it.
#[derive(Debug)]
pub struct FixedClock {
    now: Mutex<u64>,
}

impl FixedClock {
    /// A clock at the given time.
    pub fn new(now: u64) -> Self {
        Self {
            now: Mutex::new(now),
        }
    }

    /// Move the clock forward.
    pub fn advance(&self, seconds: u64) {
        let mut now = self.now.lock().expect("the clock lock is poisoned");
        *now += seconds;
    }

    /// Move the clock to a time.
    pub fn set(&self, seconds: u64) {
        let mut now = self.now.lock().expect("the clock lock is poisoned");
        *now = seconds;
    }
}

impl Clock for FixedClock {
    fn now(&self) -> u64 {
        *self.now.lock().expect("the clock lock is poisoned")
    }
}
