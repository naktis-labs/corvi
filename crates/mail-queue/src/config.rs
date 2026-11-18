//! Which optional durable features a deployment switches on.
//!
//! ADR-0010 makes the durable queue, durable tasks and persistent
//! synchronization *explicit feature-dependent commitments* rather than
//! mandatory background infrastructure. This module is where that choice is
//! expressed, and it is deliberately lopsided: **everything is off unless
//! the deployment asks for it**.
//!
//! Two rules follow from that and are enforced here rather than by
//! convention:
//!
//! 1. A disabled feature is **reported**, never ignored. An operation on a
//!    disabled feature fails with [`crate::QueueError::FeatureDisabled`], so
//!    a caller cannot mistake "nothing happened" for "the work was
//!    scheduled".
//! 2. The cache retention window is **bounded**. A cache that keeps mail
//!    content forever is not an opt-in cache, it is a second copy of the
//!    mailbox, so a retention window outside the bound is refused rather
//!    than clamped into something the caller did not ask for.

use crate::error::{QueueError, QueueResult};

/// One optional durable feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Feature {
    /// The durable submission queue.
    DurableQueue,
    /// Durable tasks.
    DurableTasks,
    /// Persistent mailbox synchronization.
    PersistentSync,
    /// The encrypted content cache.
    EncryptedCache,
}

impl Feature {
    /// The name of the feature, as the configuration spells it.
    pub fn as_str(&self) -> &'static str {
        match self {
            Feature::DurableQueue => "durableQueue",
            Feature::DurableTasks => "durableTasks",
            Feature::PersistentSync => "persistentSync",
            Feature::EncryptedCache => "encryptedCache",
        }
    }
}

/// Which optional durable features are enabled.
///
/// The default is the one ADR-0010 asks for: nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct QueueFeatures {
    /// The durable submission queue is enabled.
    pub durable_queue: bool,
    /// Durable tasks are enabled.
    pub durable_tasks: bool,
    /// Persistent mailbox synchronization is enabled.
    pub persistent_sync: bool,
    /// The encrypted content cache is enabled.
    pub encrypted_cache: bool,
}

impl QueueFeatures {
    /// No optional feature is enabled.
    pub const fn none() -> Self {
        Self {
            durable_queue: false,
            durable_tasks: false,
            persistent_sync: false,
            encrypted_cache: false,
        }
    }

    /// Every optional feature is enabled.
    ///
    /// This is a convenience for a deployment that has deliberately opted
    /// in; it is never the default.
    pub const fn all() -> Self {
        Self {
            durable_queue: true,
            durable_tasks: true,
            persistent_sync: true,
            encrypted_cache: true,
        }
    }

    /// Switch the durable queue on or off.
    pub fn with_durable_queue(mut self, enabled: bool) -> Self {
        self.durable_queue = enabled;
        self
    }

    /// Switch durable tasks on or off.
    pub fn with_durable_tasks(mut self, enabled: bool) -> Self {
        self.durable_tasks = enabled;
        self
    }

    /// Switch persistent synchronization on or off.
    pub fn with_persistent_sync(mut self, enabled: bool) -> Self {
        self.persistent_sync = enabled;
        self
    }

    /// Switch the encrypted content cache on or off.
    pub fn with_encrypted_cache(mut self, enabled: bool) -> Self {
        self.encrypted_cache = enabled;
        self
    }

    /// Whether one feature is enabled.
    pub fn is_enabled(&self, feature: Feature) -> bool {
        match feature {
            Feature::DurableQueue => self.durable_queue,
            Feature::DurableTasks => self.durable_tasks,
            Feature::PersistentSync => self.persistent_sync,
            Feature::EncryptedCache => self.encrypted_cache,
        }
    }
}

/// The policy of the optional encrypted content cache.
///
/// The cache holds message content that the provider's mailbox is the source
/// of truth for. ADR-0010 section 5 allows such a copy only when the
/// deployment opts in, encrypts it, and bounds how long it is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CachePolicy {
    enabled: bool,
    retention_seconds: u64,
}

impl CachePolicy {
    /// The longest retention window the cache accepts, in seconds.
    ///
    /// A week is long enough for an offline cache to be useful and short
    /// enough that a forgotten cache is not an unbounded second copy of the
    /// mailbox.
    pub const MAX_RETENTION_SECONDS: u64 = 7 * 24 * 60 * 60;

    /// The cache is off.
    pub const fn disabled() -> Self {
        Self {
            enabled: false,
            retention_seconds: 0,
        }
    }

    /// The cache is on, keeping content for the given window.
    ///
    /// A window of zero is refused because it would expire the content it
    /// stores, and a window beyond [`Self::MAX_RETENTION_SECONDS`] is
    /// refused because the bound is a decision, not a suggestion.
    pub fn enabled(retention_seconds: u64) -> QueueResult<Self> {
        if retention_seconds == 0 {
            return Err(QueueError::Invalid(
                "the cache retention window must be positive".to_owned(),
            ));
        }
        if retention_seconds > Self::MAX_RETENTION_SECONDS {
            return Err(QueueError::Invalid(format!(
                "the cache retention window of {retention_seconds} seconds is longer than the \
                 maximum of {} seconds",
                Self::MAX_RETENTION_SECONDS
            )));
        }
        Ok(Self {
            enabled: true,
            retention_seconds,
        })
    }

    /// Whether the cache is on.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// How long the cache keeps content.
    pub fn retention_seconds(&self) -> u64 {
        self.retention_seconds
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_feature_is_off_by_default() {
        let features = QueueFeatures::default();
        assert!(!features.durable_queue);
        assert!(!features.durable_tasks);
        assert!(!features.persistent_sync);
        assert!(!features.encrypted_cache);
        for feature in [
            Feature::DurableQueue,
            Feature::DurableTasks,
            Feature::PersistentSync,
            Feature::EncryptedCache,
        ] {
            assert!(!features.is_enabled(feature));
        }
    }

    #[test]
    fn a_retention_window_beyond_the_bound_is_refused() {
        let error = CachePolicy::enabled(CachePolicy::MAX_RETENTION_SECONDS + 1).unwrap_err();
        assert!(matches!(error, QueueError::Invalid(_)));
    }

    #[test]
    fn a_zero_retention_window_is_refused() {
        assert!(CachePolicy::enabled(0).is_err());
    }

    #[test]
    fn the_disabled_cache_keeps_no_window() {
        let policy = CachePolicy::disabled();
        assert!(!policy.is_enabled());
        assert_eq!(policy.retention_seconds(), 0);
    }
}
