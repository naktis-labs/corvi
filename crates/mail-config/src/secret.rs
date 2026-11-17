//! Reading operator-protected secret files.
//!
//! Corvi never stores a secret value in configuration. The snapshot holds a
//! reference to a file the operator controls, and the value is read from that
//! file at the moment it is needed. A reference is only honoured when the
//! target is a regular file that only its owner can read, so a world-readable
//! file is a configuration error rather than a silently accepted secret.
//!
//! See ADR-0014 and the upstream-secret custody rules in the design spec:
//! references are permitted in snapshots, values never are.

use std::fmt;
use std::fs;
use std::io;
use std::path::Path;

/// A secret value held in memory.
///
/// The value is deliberately opaque in diagnostics: `Debug` and `Display` show
/// that a secret is present without revealing it, so a secret cannot leak
/// through a log line or a panic message.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretValue(String);

impl SecretValue {
    /// Wrap an already-loaded value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the value for use in a comparison or an upstream request.
    ///
    /// The name is a reminder that the result must not be logged.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Whether the value is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretValue(<redacted>)")
    }
}

impl fmt::Display for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Why a protected secret file was refused.
#[derive(Debug)]
pub enum SecretError {
    /// The reference was not an absolute path.
    NotAbsolute,
    /// The reference did not point at a regular file.
    NotRegularFile,
    /// The file was readable by users other than its owner.
    TooPermissive(u32),
    /// The file was owned by a different user than the process.
    WrongOwner {
        /// The effective user id of the running process.
        expected: u32,
        /// The owner of the secret file.
        actual: u32,
    },
    /// The file could not be read.
    Io(io::Error),
}

impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretError::NotAbsolute => f.write_str("secret reference must be an absolute path"),
            SecretError::NotRegularFile => {
                f.write_str("secret reference must point at a regular file")
            }
            SecretError::TooPermissive(mode) => write!(
                f,
                "secret file mode {mode:o} grants access beyond its owner"
            ),
            SecretError::WrongOwner { expected, actual } => write!(
                f,
                "secret file is owned by uid {actual}, expected {expected}"
            ),
            SecretError::Io(error) => write!(f, "secret file could not be read: {error}"),
        }
    }
}

impl std::error::Error for SecretError {}

/// Read a protected secret file.
///
/// The file must be a regular file whose mode grants no access to group or
/// other, and whose owner is the user the process runs as. A trailing newline
/// is stripped, because secret files produced by `echo` and by Kubernetes
/// secret projection both end with one.
pub fn read_secret_file(path: &Path) -> Result<SecretValue, SecretError> {
    if !path.is_absolute() {
        return Err(SecretError::NotAbsolute);
    }
    let metadata = fs::metadata(path).map_err(SecretError::Io)?;
    if !metadata.is_file() {
        return Err(SecretError::NotRegularFile);
    }
    check_permissions(&metadata)?;
    check_owner(&metadata)?;
    let contents = fs::read_to_string(path).map_err(SecretError::Io)?;
    // Exactly one trailing newline is stripped, because that is what a
    // secret file written by `echo` or by a secret projection carries. A
    // value that legitimately ends in further newlines keeps them.
    let trimmed = match contents.strip_suffix('\n') {
        Some(rest) => rest.strip_suffix('\r').unwrap_or(rest),
        None => contents.as_str(),
    };
    Ok(SecretValue::new(trimmed))
}

#[cfg(unix)]
fn check_permissions(metadata: &fs::Metadata) -> Result<(), SecretError> {
    use std::os::unix::fs::MetadataExt;

    let mode = metadata.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(SecretError::TooPermissive(mode));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_permissions(_metadata: &fs::Metadata) -> Result<(), SecretError> {
    Ok(())
}

#[cfg(unix)]
fn check_owner(metadata: &fs::Metadata) -> Result<(), SecretError> {
    use std::os::unix::fs::MetadataExt;

    let Some(expected) = effective_uid() else {
        return Ok(());
    };
    let actual = metadata.uid();
    if actual != expected {
        return Err(SecretError::WrongOwner { expected, actual });
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_owner(_metadata: &fs::Metadata) -> Result<(), SecretError> {
    Ok(())
}

/// The effective user id of this process.
///
/// On Linux the value is read from `/proc/self/status`, which needs no unsafe
/// code. On other platforms the owner check is skipped rather than guessed.
#[cfg(target_os = "linux")]
fn effective_uid() -> Option<u32> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest.split_whitespace().nth(1)?.parse().ok();
        }
    }
    None
}

#[cfg(not(target_os = "linux"))]
fn effective_uid() -> Option<u32> {
    None
}

/// Compare two secrets without leaking their contents through timing.
///
/// The comparison runs over the whole length of both inputs so that a
/// mismatch at an early byte does not return faster than a mismatch at a late
/// byte.
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        difference |= a ^ b;
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_and_display_do_not_reveal_the_value() {
        let value = SecretValue::new("hunter2");
        assert_eq!(format!("{value:?}"), "SecretValue(<redacted>)");
        assert_eq!(format!("{value}"), "<redacted>");
        assert_eq!(value.expose(), "hunter2");
    }

    #[test]
    fn constant_time_eq_matches_equal_and_rejects_unequal() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"secreT"));
        assert!(!constant_time_eq(b"secret", b"secret-longer"));
        assert!(constant_time_eq(b"", b""));
    }
}
