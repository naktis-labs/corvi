//! The revocation ledger: the facts of a revocation, kept outside the
//! database.
//!
//! ADR-0010 section 7 asks that revoked credentials are not silently
//! resurrected by a restore, and that a deployment keeps an explicit
//! revocation/freshness recovery procedure. The database records a
//! revocation like any other state, so a backup taken before a revocation
//! would, if it were restored, bring a revoked grant back as if it were
//! still consented — and the database itself has no way to know that it is
//! stale.
//!
//! The ledger is the answer. It is a file next to the database that holds
//! every revocation the deployment has made, appended and flushed **before**
//! the database is changed. Every database records how far it has caught up
//! with the ledger. A restore is only authorized from a backup whose
//! watermark matches the ledger, so a backup that predates a revocation —
//! or one whose ledger is missing, truncated or foreign — is refused rather
//! than installed.
//!
//! The ledger has to be kept with the same care as the wrapping key: a
//! database backup without its ledger cannot be proven fresh, and a restore
//! of one is refused.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{StorageError, StorageResult};

/// One revocation, as the ledger records it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerEntry {
    /// The position of the entry in the ledger, starting at one.
    pub sequence: u64,
    /// The identifier of the revoked thing.
    pub subject: String,
    /// What kind of thing it was: a grant, a refresh family or a token.
    pub kind: String,
    /// When it was revoked.
    pub at: u64,
}

/// The append-only ledger of the revocations of a database.
#[derive(Debug)]
pub struct RevocationLedger {
    path: PathBuf,
}

impl RevocationLedger {
    /// Open the ledger at a path, creating an empty one when it is not there.
    pub fn open(path: impl AsRef<Path>) -> StorageResult<Self> {
        let path = path.as_ref().to_path_buf();
        if path.exists() {
            crate::secret::check_protected_file(&path)?;
        } else {
            crate::secret::write_owner_only(&path, b"")?;
            crate::secret::sync_directory(path.parent().unwrap_or(Path::new(".")))?;
        }
        Ok(Self { path })
    }

    /// Open a ledger that has to be there already.
    ///
    /// A missing ledger means the freshness of a backup cannot be
    /// established at all, so a restore that needs one is refused instead of
    /// opening an empty ledger that would agree with anything.
    pub fn open_existing(path: impl AsRef<Path>) -> StorageResult<Self> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(StorageError::Unsupported(format!(
                "the revocation ledger {} does not exist; the freshness of a backup cannot be \
                 established without it",
                path.display()
            )));
        }
        Self::open(path)
    }

    /// The path of the ledger.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append a revocation and return it with its sequence.
    ///
    /// The entry is flushed to the disk before the caller continues, so a
    /// crash after a database change cannot lose the fact that it was
    /// revoked.
    pub fn append(&self, subject: &str, kind: &str, at: u64) -> StorageResult<LedgerEntry> {
        let entry = LedgerEntry {
            sequence: self.head()? + 1,
            subject: subject.to_owned(),
            kind: kind.to_owned(),
            at,
        };
        let line = serde_json::to_string(&entry).map_err(|error| {
            StorageError::Backend(format!("the ledger is not writable: {error}"))
        })?;
        crate::secret::append_owner_only(&self.path, format!("{line}\n").as_bytes())?;
        crate::secret::sync_directory(self.path.parent().unwrap_or(Path::new(".")))?;
        Ok(entry)
    }

    /// The entries of the ledger, in the order they were recorded.
    pub fn entries(&self) -> StorageResult<Vec<LedgerEntry>> {
        let text = std::fs::read_to_string(&self.path)?;
        let mut entries = Vec::new();
        for (number, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let entry: LedgerEntry = serde_json::from_str(line).map_err(|error| {
                StorageError::Invalid(format!(
                    "the line {} of the revocation ledger is not readable: {error}",
                    number + 1
                ))
            })?;
            if entry.sequence != entries.len() as u64 + 1 {
                return Err(StorageError::Invalid(
                    "the revocation ledger is not in sequence".to_owned(),
                ));
            }
            entries.push(entry);
        }
        Ok(entries)
    }

    /// The highest sequence the ledger holds.
    pub fn head(&self) -> StorageResult<u64> {
        Ok(self
            .entries()?
            .last()
            .map(|entry| entry.sequence)
            .unwrap_or(0))
    }
}

/// The path of the revocation ledger of a database.
pub fn ledger_path(database: &Path) -> PathBuf {
    let mut name = database
        .file_name()
        .map(|name| name.to_os_string())
        .unwrap_or_default();
    name.push(".revocations");
    database.with_file_name(name)
}

/// Install a ledger at another path.
///
/// The copy is written to a name that does not exist yet, with owner-only
/// permissions, flushed, and renamed over the destination. A reader of the
/// destination sees either the old ledger or the new one, never a partial
/// file.
pub fn install_ledger(source: &Path, destination: &Path) -> StorageResult<()> {
    if let Some(parent) = destination.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let temporary = destination.with_extension("ledger-install");
    let _ = std::fs::remove_file(&temporary);
    if let Err(error) = crate::secret::copy_owner_only(source, &temporary) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    std::fs::rename(&temporary, destination)?;
    crate::secret::sync_directory(destination.parent().unwrap_or(Path::new(".")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn directory(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("corvi-ledger-{name}"));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("the directory can be created");
        path
    }

    #[test]
    fn an_entry_is_recorded_once_and_in_sequence() {
        let path = directory("sequence").join("state.sqlite.revocations");
        let ledger = RevocationLedger::open(&path).expect("the ledger opens");
        assert_eq!(ledger.head().expect("the head"), 0);
        let first = ledger
            .append("grant-1", "grant", 200)
            .expect("the entry is appended");
        assert_eq!(first.sequence, 1);
        let second = ledger
            .append("family-1", "refreshFamily", 300)
            .expect("the entry is appended");
        assert_eq!(second.sequence, 2);
        assert_eq!(ledger.head().expect("the head"), 2);
        let entries = ledger.entries().expect("the entries");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].subject, "grant-1");
        assert_eq!(entries[1].kind, "refreshFamily");
    }

    #[test]
    fn the_entries_survive_a_reopen() {
        let path = directory("reopen").join("state.sqlite.revocations");
        {
            let ledger = RevocationLedger::open(&path).expect("the ledger opens");
            ledger.append("grant-1", "grant", 200).expect("appended");
        }
        let ledger = RevocationLedger::open(&path).expect("the ledger opens");
        assert_eq!(ledger.head().expect("the head"), 1);
    }

    #[test]
    fn a_missing_ledger_is_not_created_for_a_restore() {
        let path = directory("missing").join("state.sqlite.revocations");
        let error = RevocationLedger::open_existing(&path)
            .expect_err("a ledger that is not there cannot authorize a restore");
        assert!(
            matches!(error, StorageError::Unsupported(_)),
            "unexpected error: {error:?}"
        );
        assert!(!path.exists(), "the missing ledger was created");
    }

    #[test]
    fn the_file_is_readable_by_its_owner_alone() {
        let path = directory("protected").join("state.sqlite.revocations");
        let ledger = RevocationLedger::open(&path).expect("the ledger opens");
        ledger.append("grant-1", "grant", 200).expect("appended");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path)
                .expect("the file is there")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "the ledger is readable by other users");
        }
    }
}
