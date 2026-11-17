//! Explicit reload of a configuration snapshot.
//!
//! Reload is deliberate, never implicit: the gateway re-reads its
//! configuration file only when it is asked to, and only accepts the result
//! when the file is a complete, valid replacement. A reload that fails leaves
//! the previously activated generation in service.
//!
//! The design spec fixes the trigger as SIGHUP. Signal delivery is left to
//! the process that owns the store; this module provides the reload action
//! itself, so the behaviour can be tested without raising a signal.

use std::fmt;
use std::path::{Path, PathBuf};

use crate::SnapshotStore;

/// Why a reload attempt failed.
#[derive(Debug)]
pub enum ReloadError {
    /// The configuration file could not be read.
    Read(std::io::Error),
    /// The configuration file was not valid YAML.
    Parse(serde_yaml::Error),
    /// The candidate was not valid, or was not newer than the active one.
    Activate(crate::ActivationError),
}

impl fmt::Display for ReloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReloadError::Read(error) => write!(f, "configuration file could not be read: {error}"),
            ReloadError::Parse(error) => write!(f, "configuration file is not valid YAML: {error}"),
            ReloadError::Activate(error) => write!(f, "configuration file was rejected: {error}"),
        }
    }
}

impl std::error::Error for ReloadError {}

/// Reloads a store from a configuration file.
///
/// The reloader owns no state beyond the path it reads, so the same instance
/// can be used repeatedly: each call re-reads the file from disk.
#[derive(Debug)]
pub struct Reloader {
    path: PathBuf,
}

impl Reloader {
    /// Reference the configuration file to reload from.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The referenced path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reload the store from the configuration file.
    ///
    /// Returns `true` when a new generation was activated and `false` when
    /// the file was already active, which happens when a reload is requested
    /// before the file changed.
    pub fn reload(&self, store: &SnapshotStore) -> Result<bool, ReloadError> {
        let candidate = crate::Snapshot::from_file(&self.path)?;
        match store.activate(candidate) {
            Ok(()) => Ok(true),
            Err(crate::ActivationError::StaleGeneration) => Ok(false),
            Err(error) => Err(ReloadError::Activate(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reload_reports_the_reason_it_refused_a_candidate() {
        let error = ReloadError::Activate(crate::ActivationError::StaleGeneration);
        assert!(error.to_string().contains("rejected"));
    }
}
