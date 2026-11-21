//! Why a storage operation failed.
//!
//! The variants are deliberately few, because a caller of a store needs to
//! know three things: whether the thing it asked for is there, whether the
//! answer is "not now" (a conflict it may retry) or "never" (a rejection),
//! and whether the failure is a broken deployment rather than a bad
//! request. Nothing here carries a secret, a payload or a mail content.

use std::fmt;

/// Why a storage operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageError {
    /// The record does not exist.
    NotFound(String),
    /// The record exists and conflicts with the request.
    ///
    /// The important case is an idempotency key reused with a different
    /// payload: the reservation is kept, and the caller is told that the
    /// key is taken rather than that the request was invalid.
    Conflict(String),
    /// The request is not valid.
    Invalid(String),
    /// The deployment asked for something this build does not implement.
    Unsupported(String),
    /// The key could not decrypt the envelope.
    ///
    /// The wrong key fails closed: the value is not returned, not partially
    /// returned, and not reported as absent, because absent and unreadable
    /// are different answers.
    KeyMismatch,
    /// The storage backend failed.
    Backend(String),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageError::NotFound(what) => write!(f, "{what} does not exist"),
            StorageError::Conflict(reason) => write!(f, "the request conflicts: {reason}"),
            StorageError::Invalid(reason) => write!(f, "the request is not valid: {reason}"),
            StorageError::Unsupported(reason) => write!(f, "not supported: {reason}"),
            StorageError::KeyMismatch => write!(f, "the key does not decrypt this secret"),
            StorageError::Backend(reason) => write!(f, "the storage backend failed: {reason}"),
        }
    }
}

impl std::error::Error for StorageError {}

impl From<rusqlite::Error> for StorageError {
    fn from(error: rusqlite::Error) -> Self {
        match error {
            rusqlite::Error::QueryReturnedNoRows => StorageError::NotFound("the record".to_owned()),
            other => StorageError::Backend(other.to_string()),
        }
    }
}

impl From<std::io::Error> for StorageError {
    fn from(error: std::io::Error) -> Self {
        StorageError::Backend(error.to_string())
    }
}

/// The result of a storage operation.
pub type StorageResult<T> = Result<T, StorageError>;
