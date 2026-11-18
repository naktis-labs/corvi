//! The SQLite backend: protected persistence for one instance.
//!
//! ADR-0010 section 2 describes what a SQLite deployment looks like: WAL
//! mode, a busy timeout, bounded connections, transactional migrations, one
//! process writer, a configured `synchronous` policy, integrity checks and
//! checkpointing, with the database, WAL and SHM files protected by
//! filesystem permissions.
//!
//! Two deployments are refused rather than half-supported:
//!
//! - **A network share.** SQLite's locking is not reliable over NFS, CIFS
//!   or a similar filesystem, so a database file that lives on one is
//!   refused at startup instead of corrupting itself later.
//! - **A second writer.** SQLite is a single-writer database, so the
//!   store takes an exclusive writer lock next to the database file. The
//!   lock is a database of its own, held with an exclusive transaction, so
//!   the operating system releases it when the writer dies: a second
//!   process is told that the database belongs to another writer, and a
//!   writer that crashed leaves nothing for an operator to clean up.
//!
//! Next to the database the store keeps a **revocation ledger**: the file
//! that holds the revocations the deployment made, written before the
//! database is changed. It is what makes a restore checkable — a backup
//! that predates a revocation, or one whose ledger is missing, is refused
//! rather than installed. See [`crate::revocation`].
//!
//! The store holds no inbound mail: the schema has no table for it.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use rusqlite::{Connection, OptionalExtension, params};

use crate::audit::{AuditEvent, AuditStore};
use crate::error::{StorageError, StorageResult};
use crate::grants::{
    AccessToken, AuthCode, Grant, GrantStore, OAuthClient, RefreshFamily, Revocation,
    RevocationKind,
};
use crate::mailbox::{Checkpoint, MailboxStateStore, OpaqueId, OpaqueKind, WorkerLease};
use crate::migration;
use crate::provider::{
    ConnectionStatus, ProviderConnection, ProviderConnectionStore, RefreshState,
};
use crate::revocation::{RevocationLedger, install_ledger, ledger_path};
use crate::submission::{IdempotencyReservation, Submission, SubmissionState, SubmissionStore};
use crate::task::{Task, TaskState, TaskStore};

/// The default busy timeout, in milliseconds.
pub const DEFAULT_BUSY_TIMEOUT_MS: u64 = 5_000;

/// A store backed by a SQLite database.
#[derive(Debug)]
pub struct SqliteStore {
    connection: Mutex<Connection>,
    path: PathBuf,
    _writer_lock: WriterLock,
    /// The ledger of the revocations of this database, when it has one.
    ///
    /// A database in memory has no ledger: there is nothing to restore, so
    /// there is nothing a stale copy could bring back.
    ledger: Option<RevocationLedger>,
}

impl SqliteStore {
    /// Open or create the database at a path.
    ///
    /// The database file, its WAL file and its shared-memory file are
    /// created with owner-only permissions, so no other user on the machine
    /// can read the state.
    pub fn open(path: impl AsRef<Path>) -> StorageResult<Self> {
        let path = path.as_ref().to_path_buf();
        reject_network_share(&path)?;
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        let writer_lock = WriterLock::acquire(&path)?;
        // The database file is created before SQLite opens it, with
        // owner-only permissions, so it is never readable by another user —
        // not even for the moment between the creation and the first
        // `chmod`.
        crate::secret::create_owner_only(&path)?;
        let connection = Connection::open(&path)?;
        protect(&path)?;
        let mut store = Self {
            connection: Mutex::new(connection),
            path: path.clone(),
            _writer_lock: writer_lock,
            ledger: None,
        };
        store.configure()?;
        protect(&path)?;
        store.migrate()?;
        store.open_ledger()?;
        store.catch_up_revocations()?;
        Ok(store)
    }

    /// Open a database that lives only in memory.
    ///
    /// It is used by the conformance suite to exercise the same code paths
    /// as the file backend, and by a deployment that explicitly wants no
    /// durability at all.
    pub fn open_in_memory() -> StorageResult<Self> {
        let connection = Connection::open_in_memory()?;
        let store = Self {
            connection: Mutex::new(connection),
            path: PathBuf::from(":memory:"),
            _writer_lock: WriterLock::none(),
            ledger: None,
        };
        store.configure()?;
        store.migrate()?;
        Ok(store)
    }

    /// The path of the database.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The path of the revocation ledger of this database, when it has one.
    ///
    /// The ledger is kept next to the database and holds every revocation
    /// the deployment made. It is what makes a restore checkable, so it
    /// belongs in the backup of a deployment as much as the database does.
    pub fn revocation_ledger_path(&self) -> Option<&Path> {
        self.ledger.as_ref().map(RevocationLedger::path)
    }

    /// Apply the connection settings ADR-0010 asks for.
    fn configure(&self) -> StorageResult<()> {
        let connection = self.lock()?;
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA synchronous=FULL;
                 PRAGMA foreign_keys=ON;
                 PRAGMA temp_store=MEMORY;",
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        connection
            .busy_timeout(std::time::Duration::from_millis(DEFAULT_BUSY_TIMEOUT_MS))
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(())
    }

    /// Bring the schema up to date.
    fn migrate(&self) -> StorageResult<()> {
        let mut connection = self.lock()?;
        migration::apply(&mut connection).map(|_| ())
    }

    /// The schema version of the database.
    pub fn schema_version(&self) -> StorageResult<u32> {
        let connection = self.lock()?;
        migration::schema_version(&connection)
    }

    /// Check the integrity of the database.
    pub fn integrity_check(&self) -> StorageResult<String> {
        let connection = self.lock()?;
        let result: String = connection
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(result)
    }

    /// Checkpoint the write-ahead log into the database file.
    pub fn checkpoint(&self) -> StorageResult<()> {
        let connection = self.lock()?;
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(())
    }

    /// Take a backup of the database.
    ///
    /// The backup is a snapshot that SQLite writes itself, so it holds the
    /// state of the write-ahead log as well and is consistent even while a
    /// writer is running. A copy of the database file alone is **not** a
    /// backup: it may leave out what is only in the log, and a restore of
    /// it is refused by the revocation ledger.
    ///
    /// The revocation ledger is copied next to the snapshot, under the name
    /// the ledger of a database at that path would have. A backup and its
    /// ledger belong together: a restore is only authorized from a backup
    /// whose ledger is the one the deployment keeps.
    ///
    /// The snapshot is written into a directory that only its owner can
    /// enter, because SQLite creates the file with the permissions of the
    /// process. The directory is removed again once the snapshot is in
    /// place.
    pub fn backup_to(&self, destination: impl AsRef<Path>) -> StorageResult<()> {
        let destination = destination.as_ref();
        if let Some(parent) = destination.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        // SQLite refuses to write over an existing file, so the snapshot is
        // written under a name of its own and renamed into place.
        let staging = crate::secret::temporary_path(destination, "backup");
        let _ = std::fs::remove_file(&staging);
        let _ = std::fs::remove_dir_all(&staging);
        crate::secret::create_private_directory(&staging)?;
        let temporary = staging.join("backup.sqlite");
        let result = (|| -> StorageResult<()> {
            let connection = self.lock()?;
            connection
                .execute(
                    "VACUUM INTO ?1",
                    params![temporary.to_string_lossy().as_ref()],
                )
                .map_err(|error| {
                    StorageError::Backend(format!("the backup could not be written: {error}"))
                })?;
            drop(connection);
            protect(&temporary)?;
            std::fs::rename(&temporary, destination)?;
            crate::secret::sync_directory(destination.parent().unwrap_or(Path::new(".")))?;
            Ok(())
        })();
        let _ = std::fs::remove_dir_all(&staging);
        result?;
        // The ledger of the deployment belongs in the backup as much as the
        // database does.
        if let Some(ledger) = &self.ledger {
            install_ledger(ledger.path(), &ledger_path(destination))?;
        }
        Ok(())
    }

    /// Restore a backup, refusing one that is stale relative to the ledger.
    ///
    /// The `ledger` is the revocation ledger of the deployment the backup
    /// belongs to. A restore is authorized only when the backup holds
    /// exactly the revocations the ledger holds: a backup that predates a
    /// revocation would bring a revoked credential back, and a ledger that
    /// is missing or belongs to another deployment cannot say which of the
    /// two it is. Both are refused.
    ///
    /// The destination is replaced as a whole, and it may not be in use: the
    /// restore takes the writer lock of the destination, so a store that is
    /// open there is refused rather than overwritten.
    pub fn restore_from(
        backup: impl AsRef<Path>,
        destination: impl AsRef<Path>,
        ledger: impl AsRef<Path>,
    ) -> StorageResult<()> {
        let backup = backup.as_ref();
        let destination = destination.as_ref();
        let ledger = RevocationLedger::open_existing(ledger)?;
        let entries = ledger.entries()?;
        let head = entries.last().map(|entry| entry.sequence).unwrap_or(0);
        let connection =
            Connection::open_with_flags(backup, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .map_err(|error| {
                    StorageError::Invalid(format!(
                        "the backup {} cannot be read: {error}",
                        backup.display()
                    ))
                })?;
        let watermark: u64 = connection
            .query_row(
                "SELECT watermark FROM revocation_state WHERE id = 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map(|watermark| watermark as u64)
            .map_err(|error| {
                StorageError::Invalid(format!(
                    "the backup {} does not record its revocation state: {error}",
                    backup.display()
                ))
            })?;
        if watermark != head {
            return Err(StorageError::Conflict(format!(
                "the backup {} holds the revocations up to sequence {watermark} but the ledger \
                 holds {head}; restoring it could bring a revoked credential back",
                backup.display()
            )));
        }
        for entry in &entries {
            let known: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM revocations WHERE subject = ?1 AND kind = ?2 AND at >= ?3",
                    params![entry.subject, entry.kind, entry.at as i64],
                    |row| row.get(0),
                )
                .map_err(|error| {
                    StorageError::Invalid(format!(
                        "the backup {} cannot be read: {error}",
                        backup.display()
                    ))
                })?;
            if known == 0 {
                return Err(StorageError::Conflict(format!(
                    "the backup {} does not hold the revocation of {}",
                    backup.display(),
                    entry.subject
                )));
            }
        }
        drop(connection);
        // The destination may not be in use.
        let _lock = WriterLock::acquire(destination)?;
        // The destination carries its own ledger. It may not be ahead of the
        // ledger the backup was checked against: those revocations would be
        // lost by the restore, so the restore is refused instead.
        let destination_ledger = ledger_path(destination);
        if destination_ledger != ledger.path() {
            if destination_ledger.exists() {
                let existing = RevocationLedger::open(&destination_ledger)?;
                let existing_entries = existing.entries()?;
                let existing_head = existing_entries
                    .last()
                    .map(|entry| entry.sequence)
                    .unwrap_or(0);
                if existing_head > head {
                    return Err(StorageError::Conflict(format!(
                        "the ledger {} holds revocations up to sequence {existing_head} but the \
                         backup holds {head}; restoring it would lose revocations",
                        destination_ledger.display()
                    )));
                }
                // Length is not agreement. A ledger of the same length
                // whose entries are not the ones the restore installs has
                // diverged: it holds revocations of its own that the
                // restore would silently replace with the backup's
                // ledger. The restore is refused rather than performing
                // that substitution.
                for entry in &existing_entries {
                    let agrees = entries
                        .iter()
                        .find(|candidate| candidate.sequence == entry.sequence)
                        .is_some_and(|candidate| {
                            candidate.subject == entry.subject
                                && candidate.kind == entry.kind
                                && candidate.at == entry.at
                        });
                    if !agrees {
                        return Err(StorageError::Conflict(format!(
                            "the ledger {} holds the revocation of {} at sequence {}, which the \
                             ledger of the backup does not; restoring it would lose revocations",
                            destination_ledger.display(),
                            entry.subject,
                            entry.sequence
                        )));
                    }
                }
            }
            // The restored database is installed together with the ledger it
            // was verified against, so the pair is never inconsistent.
            install_ledger(ledger.path(), &destination_ledger)?;
        }
        install_file(backup, destination)?;
        Ok(())
    }

    /// Open the revocation ledger of this database.
    ///
    /// The ledger is the authority on which credentials are revoked, so a
    /// database that records revocations cannot be opened without it: the
    /// ledger was lost or truncated, and the freshness of the database
    /// cannot be proven. A database that has never recorded a revocation
    /// gets an empty ledger.
    fn open_ledger(&mut self) -> StorageResult<()> {
        let path = ledger_path(&self.path);
        let watermark = self.revocation_watermark()?;
        if !path.exists() && watermark > 0 {
            return Err(StorageError::Conflict(format!(
                "the revocation ledger {} is missing but the database records {watermark} \
                 revocations; the freshness of this database cannot be proven",
                path.display()
            )));
        }
        self.ledger = Some(RevocationLedger::open(&path)?);
        Ok(())
    }

    /// How many revocations this database has recorded.
    fn revocation_watermark(&self) -> StorageResult<u64> {
        let connection = self.lock()?;
        let watermark: i64 = connection
            .query_row(
                "SELECT watermark FROM revocation_state WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(watermark as u64)
    }

    /// Bring the revocations of the database up to the ledger.
    ///
    /// The ledger is written before the database is changed, so a crash in
    /// between leaves the database *behind* the ledger. This applies what
    /// the ledger knows and the database does not.
    fn catch_up_revocations(&self) -> StorageResult<()> {
        let Some(ledger) = &self.ledger else {
            return Ok(());
        };
        let entries = ledger.entries()?;
        let head = entries.last().map(|entry| entry.sequence).unwrap_or(0);
        let watermark = self.revocation_watermark()?;
        // The ledger is written first, so the database is never ahead of it.
        // A database that is ahead means the ledger lost entries — it was
        // truncated, or an old copy of it was put back — and the revocations
        // it holds can no longer be proven: fail closed instead of carrying
        // on with a ledger that is missing the truth.
        if watermark > head {
            return Err(StorageError::Conflict(format!(
                "the revocation ledger {} holds {head} revocations but the database records \
                 {watermark}; the ledger was lost or truncated, so the freshness of this \
                 database cannot be proven",
                ledger.path().display()
            )));
        }
        if entries.is_empty() {
            return Ok(());
        }
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        let watermark: u64 = transaction
            .query_row(
                "SELECT watermark FROM revocation_state WHERE id = 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map(|watermark| watermark as u64)
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        for entry in entries.iter().filter(|entry| entry.sequence > watermark) {
            transaction
                .execute(
                    "INSERT OR REPLACE INTO revocations (subject, kind, at) VALUES (?1, ?2, ?3)",
                    params![entry.subject, entry.kind, entry.at as i64],
                )
                .map_err(|error| StorageError::Backend(error.to_string()))?;
            // The row the revocation is about is brought along, so the
            // database itself says what the ledger says: a token of a
            // revoked grant is refused even if the lookup does not read the
            // ledger.
            let applied = match entry.kind.as_str() {
                kind if kind == RevocationKind::Grant.as_str() => transaction.execute(
                    "UPDATE grants SET revoked_at = ?2 WHERE grant_id = ?1 AND revoked_at IS NULL",
                    params![entry.subject, entry.at as i64],
                ),
                kind if kind == RevocationKind::RefreshFamily.as_str() => transaction.execute(
                    "UPDATE refresh_families SET revoked_at = ?2 WHERE family_id = ?1 AND \
                     revoked_at IS NULL",
                    params![entry.subject, entry.at as i64],
                ),
                kind if kind == RevocationKind::AccessToken.as_str() => transaction.execute(
                    "UPDATE access_tokens SET revoked_at = ?2 WHERE token_hash = ?1 AND \
                     revoked_at IS NULL",
                    params![entry.subject, entry.at as i64],
                ),
                _ => Ok(0),
            }
            .map_err(|error| StorageError::Backend(error.to_string()))?;
            let _ = applied;
        }
        if head > watermark {
            transaction
                .execute(
                    "UPDATE revocation_state SET watermark = ?1 WHERE id = 1 AND watermark < ?1",
                    params![head as i64],
                )
                .map_err(|error| StorageError::Backend(error.to_string()))?;
        }
        transaction
            .commit()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(())
    }

    /// Record a revocation in the ledger and in the open transaction.
    ///
    /// The ledger is written first, so that a failure after it leaves the
    /// database behind the ledger rather than ahead of it. A database that
    /// is behind cannot be restored over a fresh one; a database that is
    /// ahead could be, and that is the direction that is dangerous.
    fn record_revocation(
        &self,
        transaction: &rusqlite::Transaction<'_>,
        subject: &str,
        kind: &str,
        at: u64,
    ) -> StorageResult<()> {
        if let Some(ledger) = &self.ledger {
            let entry = ledger.append(subject, kind, at)?;
            transaction
                .execute(
                    "UPDATE revocation_state SET watermark = ?2 WHERE id = 1 AND watermark < ?2",
                    params![entry.sequence as i64, entry.sequence as i64],
                )
                .map_err(|error| StorageError::Backend(error.to_string()))?;
        }
        transaction
            .execute(
                "INSERT OR REPLACE INTO revocations (subject, kind, at) VALUES (?1, ?2, ?3)",
                params![subject, kind, at as i64],
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(())
    }

    /// The connection, locked.
    fn lock(&self) -> StorageResult<MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| StorageError::Backend("the database lock was poisoned".to_owned()))
    }
}

/// The exclusive writer lock of a database file.
///
/// The lock is a database of its own, held open with an exclusive
/// transaction. The operating system releases that lock when the process
/// dies, so:
///
/// - a second writer is refused, in this process and in another one, and
/// - a writer that crashed leaves nothing to clean up: the next writer
///   takes the lock over without a stale process-id check, and without the
///   race that a check-then-replace file lock has.
#[derive(Debug)]
struct WriterLock {
    /// The lock database. It is held for as long as the store lives.
    _database: Option<Mutex<Connection>>,
}

impl WriterLock {
    /// Take the writer lock next to a database.
    fn acquire(database: &Path) -> StorageResult<Self> {
        let path = lock_path(database);
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        let connection = open_lock_database(&path)?;
        // The refusal is immediate: a second writer is told at once instead
        // of waiting for a lock that will not be released.
        connection
            .busy_timeout(std::time::Duration::ZERO)
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        connection
            .execute_batch("BEGIN EXCLUSIVE")
            .map_err(|error| {
                if is_locked(&error) {
                    StorageError::Conflict(format!(
                        "the database {} is already open for writing; SQLite is a single-writer \
                         database",
                        database.display()
                    ))
                } else {
                    StorageError::Backend(error.to_string())
                }
            })?;
        // The owner is recorded for the operator's benefit. It is written
        // inside the exclusive transaction, so it cannot be written by a
        // writer that does not hold the lock.
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS lock_owner (
                     id  INTEGER PRIMARY KEY CHECK (id = 1),
                     pid INTEGER NOT NULL
                 );",
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        connection
            .execute(
                "INSERT OR REPLACE INTO lock_owner (id, pid) VALUES (1, ?1)",
                params![i64::from(std::process::id())],
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        protect(&path)?;
        Ok(Self {
            _database: Some(Mutex::new(connection)),
        })
    }

    /// A lock that holds nothing.
    fn none() -> Self {
        Self { _database: None }
    }
}

/// Open the lock database of a writer lock.
///
/// A file that holds something else — the process-id file of an older build,
/// for example — cannot hold the lock of this build, so it is replaced
/// rather than obeyed. The check reads the file header and takes no lock,
/// so a lock that somebody else holds is never mistaken for a foreign
/// file.
fn open_lock_database(path: &Path) -> StorageResult<Connection> {
    if path.exists()
        && std::fs::metadata(path)
            .map(|metadata| metadata.len())
            .unwrap_or(0)
            > 0
        && !has_sqlite_header(path)
    {
        std::fs::remove_file(path)?;
    }
    // The lock database is created before SQLite opens it, so it is never
    // readable by another user.
    crate::secret::create_owner_only(path)?;
    Ok(Connection::open(path)?)
}

/// Whether a file starts with the header of a SQLite database.
fn has_sqlite_header(path: &Path) -> bool {
    use std::io::Read;
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    let mut header = [0_u8; 16];
    match file.read_exact(&mut header) {
        Ok(()) => &header == b"SQLite format 3\0",
        // An empty file is a database that has not been written yet.
        Err(_) => false,
    }
}

/// Whether an error says that the database is locked by somebody else.
fn is_locked(error: &rusqlite::Error) -> bool {
    let text = error.to_string();
    text.contains("database is locked") || text.contains("database table is locked")
}

/// The path of the writer lock of a database.
fn lock_path(database: &Path) -> PathBuf {
    let mut name = database
        .file_name()
        .map(|name| name.to_os_string())
        .unwrap_or_default();
    name.push(".writer.lock");
    database.with_file_name(name)
}

/// Put a file in place atomically.
///
/// The copy is written to a name that does not exist yet, with owner-only
/// permissions, flushed, and renamed over the destination. A reader of the
/// destination sees either the old file or the new one, never a partial
/// file.
///
/// The write-ahead log of the database that was there belongs to that
/// database. Left in place, SQLite would replay it over the file that was
/// just installed, and the restore would put back the state of the old
/// database instead of the state of the backup — silently, and with an
/// intact database file. The log is removed under the writer lock, so no
/// other writer can be using it.
fn install_file(source: &Path, destination: &Path) -> StorageResult<()> {
    let temporary = crate::secret::temporary_path(destination, "restore");
    let _ = std::fs::remove_file(&temporary);
    if let Err(error) = crate::secret::copy_owner_only(source, &temporary) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    remove_log_files(destination)?;
    std::fs::rename(&temporary, destination)?;
    crate::secret::sync_directory(destination.parent().unwrap_or(Path::new(".")))?;
    Ok(())
}

/// Remove the write-ahead log and the shared-memory file of a database.
fn remove_log_files(database: &Path) -> StorageResult<()> {
    if let Some(name) = database.file_name() {
        for suffix in ["-wal", "-shm"] {
            let mut extended = name.to_os_string();
            extended.push(suffix);
            let _ = std::fs::remove_file(database.with_file_name(extended));
        }
    }
    Ok(())
}

/// The filesystems a SQLite database must not live on.
const NETWORK_FILESYSTEMS: &[&str] = &[
    "nfs",
    "nfs4",
    "cifs",
    "smbfs",
    "smb3",
    "afs",
    "9p",
    "ceph",
    "glusterfs",
    "fuse.sshfs",
    "fuse.rclone",
    "virtiofs",
];

/// Refuse a database that lives on a network share.
///
/// SQLite's locking relies on byte-range locks that a network filesystem
/// does not implement reliably, so a database on one can be corrupted by
/// two writers that both believe they hold the lock.
fn reject_network_share(path: &Path) -> StorageResult<()> {
    let Ok(mounts) = std::fs::read_to_string("/proc/mounts") else {
        return Ok(());
    };
    let absolute = std::fs::canonicalize(path.parent().unwrap_or(Path::new("/")))
        .unwrap_or_else(|_| path.to_path_buf());
    let mut best: Option<(usize, String)> = None;
    for line in mounts.lines() {
        let mut fields = line.split_whitespace();
        let _device = fields.next();
        let Some(mount_point) = fields.next() else {
            continue;
        };
        let Some(filesystem) = fields.next() else {
            continue;
        };
        if !absolute.starts_with(mount_point) {
            continue;
        }
        let length = mount_point.len();
        if best.as_ref().is_none_or(|(best, _)| length > *best) {
            best = Some((length, filesystem.to_owned()));
        }
    }
    let Some((_, filesystem)) = best else {
        return Ok(());
    };
    if NETWORK_FILESYSTEMS.contains(&filesystem.as_str()) {
        return Err(StorageError::Unsupported(format!(
            "the database would live on the {filesystem} filesystem; SQLite must not be \
             shared over a network filesystem"
        )));
    }
    Ok(())
}

/// Give a file owner-only permissions.
///
/// The write-ahead log and the shared-memory file of a database are named
/// after the database file itself, so they are protected with it.
fn protect(path: &Path) -> StorageResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut candidates = vec![path.to_path_buf()];
        if let Some(name) = path.file_name() {
            for suffix in ["-wal", "-shm"] {
                let mut extended = name.to_os_string();
                extended.push(suffix);
                candidates.push(path.with_file_name(extended));
            }
        }
        for candidate in candidates {
            if candidate.exists() {
                std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(0o600))?;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// Serialize a list of strings.
fn encode_list(values: &[String]) -> String {
    values.join("\u{1f}")
}

/// Parse a list of strings.
fn decode_list(value: &str) -> Vec<String> {
    if value.is_empty() {
        return Vec::new();
    }
    value.split('\u{1f}').map(str::to_owned).collect()
}

/// Whether an error is a uniqueness or not-null violation.
///
/// A violation is a conflict with the state that is already stored, not a
/// broken backend, so it is reported as one.
fn is_constraint_violation(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(failure, _)
            if failure.code == rusqlite::ErrorCode::ConstraintViolation
    )
}

impl GrantStore for SqliteStore {
    fn put_client(&self, client: &OAuthClient) -> StorageResult<()> {
        let connection = self.lock()?;
        connection
            .execute(
                "INSERT INTO oauth_clients (client_id, name, redirect_uris, secret_hash, confidential)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(client_id) DO UPDATE SET
                     name = excluded.name,
                     redirect_uris = excluded.redirect_uris,
                     secret_hash = excluded.secret_hash,
                     confidential = excluded.confidential",
                params![
                    client.client_id,
                    client.name,
                    encode_list(&client.redirect_uris),
                    client.secret_hash,
                    i64::from(client.confidential),
                ],
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(())
    }

    fn get_client(&self, client_id: &str) -> StorageResult<Option<OAuthClient>> {
        let connection = self.lock()?;
        let client = connection
            .query_row(
                "SELECT client_id, name, redirect_uris, secret_hash, confidential
                 FROM oauth_clients WHERE client_id = ?1",
                params![client_id],
                |row| {
                    let redirect_uris: String = row.get(2)?;
                    let confidential: i64 = row.get(4)?;
                    Ok(OAuthClient {
                        client_id: row.get(0)?,
                        name: row.get(1)?,
                        redirect_uris: decode_list(&redirect_uris),
                        secret_hash: row.get(3)?,
                        confidential: confidential != 0,
                    })
                },
            )
            .optional()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(client)
    }

    fn put_grant(&self, grant: &Grant) -> StorageResult<()> {
        self.catch_up_revocations()?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        // Whether the grant was already revoked decides whether the
        // revocation this record carries is a fact or a repetition of one.
        let was_revoked: Option<Option<i64>> = transaction
            .query_row(
                "SELECT revoked_at FROM grants WHERE grant_id = ?1",
                params![grant.grant_id],
                |row| row.get::<_, Option<i64>>(0),
            )
            .optional()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        transaction
            .execute(
                "INSERT INTO grants (grant_id, client_id, principal, identity, scopes, revision, created_at, revoked_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(grant_id) DO UPDATE SET
                     client_id = excluded.client_id,
                     principal = excluded.principal,
                     identity = excluded.identity,
                     scopes = excluded.scopes,
                     revision = MAX(grants.revision, excluded.revision),
                     created_at = excluded.created_at,
                     revoked_at = COALESCE(grants.revoked_at, excluded.revoked_at)",
                params![
                    grant.grant_id,
                    grant.client_id,
                    grant.principal,
                    grant.identity,
                    encode_list(&grant.scopes),
                    grant.revision as i64,
                    grant.created_at as i64,
                    grant.revoked_at.map(|at| at as i64),
                ],
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        // A record that arrives already revoked is a revocation like any
        // other: it goes into the ledger, so a restore of a backup that
        // predates this write cannot bring the grant back as if it were
        // still consented. The ledger is written before the transaction
        // commits, so a crash in between leaves the database *behind* the
        // ledger, which is the safe direction.
        if was_revoked.flatten().is_none() {
            if let Some(revoked_at) = grant.revoked_at {
                self.record_revocation(
                    &transaction,
                    &grant.grant_id,
                    RevocationKind::Grant.as_str(),
                    revoked_at,
                )?;
            }
        }
        transaction
            .commit()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(())
    }

    fn get_grant(&self, grant_id: &str) -> StorageResult<Option<Grant>> {
        let connection = self.lock()?;
        let grant = connection
            .query_row(
                "SELECT grant_id, client_id, principal, identity, scopes, revision, created_at, revoked_at
                 FROM grants WHERE grant_id = ?1",
                params![grant_id],
                |row| {
                    let scopes: String = row.get(4)?;
                    Ok(Grant {
                        grant_id: row.get(0)?,
                        client_id: row.get(1)?,
                        principal: row.get(2)?,
                        identity: row.get(3)?,
                        scopes: decode_list(&scopes),
                        revision: row.get::<_, i64>(5)? as u64,
                        created_at: row.get::<_, i64>(6)? as u64,
                        revoked_at: row.get::<_, Option<i64>>(7)?.map(|at| at as u64),
                    })
                },
            )
            .optional()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(grant)
    }

    fn list_grants(&self, principal: &str) -> StorageResult<Vec<Grant>> {
        let connection = self.lock()?;
        let mut statement = connection
            .prepare(
                "SELECT grant_id, client_id, principal, identity, scopes, revision, created_at, revoked_at
                 FROM grants WHERE principal = ?1 ORDER BY grant_id",
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        let grants = statement
            .query_map(params![principal], |row| {
                let scopes: String = row.get(4)?;
                Ok(Grant {
                    grant_id: row.get(0)?,
                    client_id: row.get(1)?,
                    principal: row.get(2)?,
                    identity: row.get(3)?,
                    scopes: decode_list(&scopes),
                    revision: row.get::<_, i64>(5)? as u64,
                    created_at: row.get::<_, i64>(6)? as u64,
                    revoked_at: row.get::<_, Option<i64>>(7)?.map(|at| at as u64),
                })
            })
            .map_err(|error| StorageError::Backend(error.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(grants)
    }

    fn revoke_grant(&self, grant_id: &str, at: u64) -> StorageResult<bool> {
        self.catch_up_revocations()?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        let changed = transaction
            .execute(
                "UPDATE grants SET revoked_at = ?2 WHERE grant_id = ?1 AND revoked_at IS NULL",
                params![grant_id, at as i64],
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        if changed > 0 {
            self.record_revocation(&transaction, grant_id, RevocationKind::Grant.as_str(), at)?;
        }
        transaction
            .commit()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(changed > 0)
    }

    fn put_auth_code(&self, code: &AuthCode) -> StorageResult<()> {
        let connection = self.lock()?;
        connection
            .execute(
                "INSERT INTO auth_codes (code_hash, client_id, redirect_uri, principal, scopes, expires_at, used_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(code_hash) DO UPDATE SET
                     client_id = excluded.client_id,
                     redirect_uri = excluded.redirect_uri,
                     principal = excluded.principal,
                     scopes = excluded.scopes,
                     expires_at = excluded.expires_at,
                     used_at = excluded.used_at",
                params![
                    code.code_hash,
                    code.client_id,
                    code.redirect_uri,
                    code.principal,
                    encode_list(&code.scopes),
                    code.expires_at as i64,
                    code.used_at.map(|at| at as i64),
                ],
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(())
    }

    fn exchange_auth_code(&self, code_hash: &str, now: u64) -> StorageResult<AuthCode> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        let code = transaction
            .query_row(
                "SELECT code_hash, client_id, redirect_uri, principal, scopes, expires_at, used_at
                 FROM auth_codes WHERE code_hash = ?1",
                params![code_hash],
                |row| {
                    let scopes: String = row.get(4)?;
                    Ok(AuthCode {
                        code_hash: row.get(0)?,
                        client_id: row.get(1)?,
                        redirect_uri: row.get(2)?,
                        principal: row.get(3)?,
                        scopes: decode_list(&scopes),
                        expires_at: row.get::<_, i64>(5)? as u64,
                        used_at: row.get::<_, Option<i64>>(6)?.map(|at| at as u64),
                    })
                },
            )
            .optional()
            .map_err(|error| StorageError::Backend(error.to_string()))?
            .ok_or_else(|| StorageError::NotFound("the authorization code".to_owned()))?;
        if code.used_at.is_some() {
            return Err(StorageError::Conflict(
                "the authorization code was already exchanged".to_owned(),
            ));
        }
        if code.expires_at <= now {
            return Err(StorageError::Conflict(
                "the authorization code has expired".to_owned(),
            ));
        }
        transaction
            .execute(
                "UPDATE auth_codes SET used_at = ?2 WHERE code_hash = ?1 AND used_at IS NULL",
                params![code_hash, now as i64],
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        transaction
            .commit()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(AuthCode {
            used_at: Some(now),
            ..code
        })
    }

    fn exchange_bound_auth_code(
        &self,
        code_hash: &str,
        client_id: &str,
        redirect_uri: &str,
        now: u64,
    ) -> StorageResult<AuthCode> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        let code = transaction
            .query_row(
                "SELECT code_hash, client_id, redirect_uri, principal, scopes, expires_at, used_at
                 FROM auth_codes WHERE code_hash = ?1",
                params![code_hash],
                |row| {
                    let scopes: String = row.get(4)?;
                    Ok(AuthCode {
                        code_hash: row.get(0)?,
                        client_id: row.get(1)?,
                        redirect_uri: row.get(2)?,
                        principal: row.get(3)?,
                        scopes: decode_list(&scopes),
                        expires_at: row.get::<_, i64>(5)? as u64,
                        used_at: row.get::<_, Option<i64>>(6)?.map(|at| at as u64),
                    })
                },
            )
            .optional()
            .map_err(|error| StorageError::Backend(error.to_string()))?
            .ok_or_else(|| StorageError::NotFound("the authorization code".to_owned()))?;
        if code.client_id != client_id || code.redirect_uri != redirect_uri {
            return Err(StorageError::Conflict(
                "authorization code binding mismatch".to_owned(),
            ));
        }
        if code.used_at.is_some() {
            return Err(StorageError::Conflict(
                "the authorization code was already exchanged".to_owned(),
            ));
        }
        if code.expires_at <= now {
            return Err(StorageError::Conflict(
                "the authorization code has expired".to_owned(),
            ));
        }
        transaction
            .execute(
                "UPDATE auth_codes SET used_at = ?2 WHERE code_hash = ?1 AND used_at IS NULL",
                params![code_hash, now as i64],
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        transaction
            .commit()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(AuthCode {
            used_at: Some(now),
            ..code
        })
    }

    fn put_access_token(&self, token: &AccessToken) -> StorageResult<()> {
        self.catch_up_revocations()?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        // Whether the token was already revoked decides whether a new
        // revocation is a fact or a repetition of one.
        let was_revoked: Option<Option<i64>> = transaction
            .query_row(
                "SELECT revoked_at FROM access_tokens WHERE token_hash = ?1",
                params![token.token_hash],
                |row| row.get::<_, Option<i64>>(0),
            )
            .optional()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        transaction
            .execute(
                "INSERT INTO access_tokens (token_hash, grant_id, principal, scopes, expires_at, revoked_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(token_hash) DO UPDATE SET
                     revoked_at = COALESCE(access_tokens.revoked_at, excluded.revoked_at)",
                params![
                    token.token_hash,
                    token.grant_id,
                    token.principal,
                    encode_list(&token.scopes),
                    token.expires_at as i64,
                    token.revoked_at.map(|at| at as i64),
                ],
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        // A revoked token is a fact, not a state: it is written down where a
        // restore of this database cannot make it disappear. The ledger is
        // written before the transaction commits, so a crash in between
        // leaves the database *behind* the ledger, which is the safe
        // direction: a database that is behind is corrected on the next
        // open, a database that is ahead could be restored over a fresh one.
        if was_revoked.flatten().is_none() {
            if let Some(revoked_at) = token.revoked_at {
                self.record_revocation(
                    &transaction,
                    &token.token_hash,
                    RevocationKind::AccessToken.as_str(),
                    revoked_at,
                )?;
            }
        }
        transaction
            .commit()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(())
    }

    fn lookup_access_token(
        &self,
        token_hash: &str,
        now: u64,
    ) -> StorageResult<Option<AccessToken>> {
        let connection = self.lock()?;
        let token = connection
            .query_row(
                "SELECT token_hash, grant_id, principal, scopes, expires_at, revoked_at
                 FROM access_tokens WHERE token_hash = ?1",
                params![token_hash],
                |row| {
                    let scopes: String = row.get(3)?;
                    Ok(AccessToken {
                        token_hash: row.get(0)?,
                        grant_id: row.get(1)?,
                        principal: row.get(2)?,
                        scopes: decode_list(&scopes),
                        expires_at: row.get::<_, i64>(4)? as u64,
                        revoked_at: row.get::<_, Option<i64>>(5)?.map(|at| at as u64),
                    })
                },
            )
            .optional()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        let Some(token) = token else {
            return Ok(None);
        };
        if token.revoked_at.is_some() || token.expires_at <= now {
            return Ok(None);
        }
        // The grant of the token decides as well: a token of a revoked
        // grant is not a token, and neither is a token whose grant row is
        // gone. A missing grant cannot be told apart from a grant this
        // database never held, so the lookup fails closed rather than
        // letting a token outlive the record of what authorized it.
        let grant_revoked = connection
            .query_row(
                "SELECT revoked_at FROM grants WHERE grant_id = ?1",
                params![token.grant_id],
                |row| row.get::<_, Option<i64>>(0),
            )
            .optional()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        if grant_revoked.is_none() || grant_revoked.flatten().is_some() {
            return Ok(None);
        }
        drop(connection);
        // The ledger is the authority outside the database: a revocation it
        // holds is a revocation, even when the database does not know of it
        // yet.
        if let Some(ledger) = &self.ledger {
            for entry in ledger.entries()? {
                let same_grant =
                    entry.subject == token.grant_id && entry.kind == RevocationKind::Grant.as_str();
                let same_token = entry.subject == token_hash
                    && entry.kind == RevocationKind::AccessToken.as_str();
                if same_grant || same_token {
                    return Ok(None);
                }
            }
        }
        Ok(Some(token))
    }

    fn put_refresh_family(&self, family: &RefreshFamily) -> StorageResult<()> {
        self.catch_up_revocations()?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        let was_revoked: Option<Option<i64>> = transaction
            .query_row(
                "SELECT revoked_at FROM refresh_families WHERE family_id = ?1",
                params![family.family_id],
                |row| row.get::<_, Option<i64>>(0),
            )
            .optional()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        transaction
            .execute(
                "INSERT INTO refresh_families (family_id, grant_id, generation, current_token_hash, rotated_at, revoked_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(family_id) DO UPDATE SET
                     grant_id = excluded.grant_id,
                     generation = MAX(refresh_families.generation, excluded.generation),
                     current_token_hash = excluded.current_token_hash,
                     rotated_at = excluded.rotated_at,
                     revoked_at = COALESCE(refresh_families.revoked_at, excluded.revoked_at)",
                params![
                    family.family_id,
                    family.grant_id,
                    family.generation as i64,
                    family.current_token_hash,
                    family.rotated_at as i64,
                    family.revoked_at.map(|at| at as i64),
                ],
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        // As with a grant: a record that arrives already revoked is a
        // revocation, and it is written down where a restore cannot make
        // it disappear.
        if was_revoked.flatten().is_none() {
            if let Some(revoked_at) = family.revoked_at {
                self.record_revocation(
                    &transaction,
                    &family.family_id,
                    RevocationKind::RefreshFamily.as_str(),
                    revoked_at,
                )?;
            }
        }
        transaction
            .commit()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(())
    }

    fn rotate_refresh(
        &self,
        family_id: &str,
        expected_generation: u64,
        new_token_hash: &str,
        now: u64,
    ) -> StorageResult<RefreshFamily> {
        // The ledger is the authority outside the database: a family that
        // the ledger holds as revoked is revoked, even when the database
        // has not caught up with it yet.
        self.catch_up_revocations()?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        let changed = transaction
            .execute(
                "UPDATE refresh_families
                 SET generation = ?3, current_token_hash = ?4, rotated_at = ?5
                 WHERE family_id = ?1 AND generation = ?2 AND revoked_at IS NULL",
                params![
                    family_id,
                    expected_generation as i64,
                    expected_generation as i64 + 1,
                    new_token_hash,
                    now as i64
                ],
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        if changed == 0 {
            return Err(StorageError::Conflict(
                "the refresh family moved on before this rotation".to_owned(),
            ));
        }
        let family = transaction
            .query_row(
                "SELECT family_id, grant_id, generation, current_token_hash, rotated_at, revoked_at
                 FROM refresh_families WHERE family_id = ?1",
                params![family_id],
                |row| {
                    Ok(RefreshFamily {
                        family_id: row.get(0)?,
                        grant_id: row.get(1)?,
                        generation: row.get::<_, i64>(2)? as u64,
                        current_token_hash: row.get(3)?,
                        rotated_at: row.get::<_, i64>(4)? as u64,
                        revoked_at: row.get::<_, Option<i64>>(5)?.map(|at| at as u64),
                    })
                },
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        transaction
            .commit()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(family)
    }

    fn revoke_refresh_family(&self, family_id: &str, at: u64) -> StorageResult<bool> {
        self.catch_up_revocations()?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        let changed = transaction
            .execute(
                "UPDATE refresh_families SET revoked_at = ?2 WHERE family_id = ?1 AND revoked_at IS NULL",
                params![family_id, at as i64],
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        if changed > 0 {
            self.record_revocation(
                &transaction,
                family_id,
                RevocationKind::RefreshFamily.as_str(),
                at,
            )?;
        }
        transaction
            .commit()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(changed > 0)
    }

    fn revoked_after(&self, at: u64) -> StorageResult<Vec<Revocation>> {
        let connection = self.lock()?;
        let mut statement = connection
            .prepare("SELECT subject, kind, at FROM revocations WHERE at > ?1 ORDER BY at, subject")
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        let revocations = statement
            .query_map(params![at as i64], |row| {
                let kind: String = row.get(1)?;
                Ok(Revocation {
                    subject: row.get(0)?,
                    kind: match kind.as_str() {
                        "grant" => RevocationKind::Grant,
                        "refreshFamily" => RevocationKind::RefreshFamily,
                        _ => RevocationKind::AccessToken,
                    },
                    at: row.get::<_, i64>(2)? as u64,
                })
            })
            .map_err(|error| StorageError::Backend(error.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(revocations)
    }
}

impl ProviderConnectionStore for SqliteStore {
    fn put_connection(&self, connection: &ProviderConnection) -> StorageResult<()> {
        let guard = self.lock()?;
        guard
            .execute(
                "INSERT INTO provider_connections
                     (connection_id, provider, account_ref, identity, capabilities, status, generation, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(connection_id) DO UPDATE SET
                     provider = excluded.provider,
                     account_ref = excluded.account_ref,
                     identity = excluded.identity,
                     capabilities = excluded.capabilities,
                     status = excluded.status,
                     generation = excluded.generation,
                     updated_at = excluded.updated_at",
                params![
                    connection.connection_id,
                    connection.provider,
                    connection.account_ref,
                    connection.identity,
                    encode_list(&connection.capabilities),
                    connection.status.as_str(),
                    connection.generation as i64,
                    connection.updated_at as i64,
                ],
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(())
    }

    fn get_connection(&self, connection_id: &str) -> StorageResult<Option<ProviderConnection>> {
        let guard = self.lock()?;
        let connection = guard
            .query_row(
                "SELECT connection_id, provider, account_ref, identity, capabilities, status, generation, updated_at
                 FROM provider_connections WHERE connection_id = ?1",
                params![connection_id],
                |row| {
                    let capabilities: String = row.get(4)?;
                    let status: String = row.get(5)?;
                    Ok(ProviderConnection {
                        connection_id: row.get(0)?,
                        provider: row.get(1)?,
                        account_ref: row.get(2)?,
                        identity: row.get(3)?,
                        capabilities: decode_list(&capabilities),
                        status: ConnectionStatus::parse(&status)
                            .unwrap_or(ConnectionStatus::Degraded),
                        generation: row.get::<_, i64>(6)? as u64,
                        updated_at: row.get::<_, i64>(7)? as u64,
                    })
                },
            )
            .optional()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(connection)
    }

    fn list_connections(&self, identity: &str) -> StorageResult<Vec<ProviderConnection>> {
        let guard = self.lock()?;
        let mut statement = guard
            .prepare(
                "SELECT connection_id, provider, account_ref, identity, capabilities, status, generation, updated_at
                 FROM provider_connections WHERE identity = ?1 ORDER BY connection_id",
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        let connections = statement
            .query_map(params![identity], |row| {
                let capabilities: String = row.get(4)?;
                let status: String = row.get(5)?;
                Ok(ProviderConnection {
                    connection_id: row.get(0)?,
                    provider: row.get(1)?,
                    account_ref: row.get(2)?,
                    identity: row.get(3)?,
                    capabilities: decode_list(&capabilities),
                    status: ConnectionStatus::parse(&status).unwrap_or(ConnectionStatus::Degraded),
                    generation: row.get::<_, i64>(6)? as u64,
                    updated_at: row.get::<_, i64>(7)? as u64,
                })
            })
            .map_err(|error| StorageError::Backend(error.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(connections)
    }

    fn put_refresh_state(&self, state: &RefreshState) -> StorageResult<()> {
        let guard = self.lock()?;
        guard
            .execute(
                "INSERT INTO provider_refresh_state
                     (connection_id, generation, secret_ref, expires_at, needs_reauthorization)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(connection_id) DO UPDATE SET
                     generation = excluded.generation,
                     secret_ref = excluded.secret_ref,
                     expires_at = excluded.expires_at,
                     needs_reauthorization = excluded.needs_reauthorization",
                params![
                    state.connection_id,
                    state.generation as i64,
                    state.secret_ref,
                    state.expires_at as i64,
                    i64::from(state.needs_reauthorization),
                ],
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(())
    }

    fn get_refresh_state(&self, connection_id: &str) -> StorageResult<Option<RefreshState>> {
        let guard = self.lock()?;
        let state = guard
            .query_row(
                "SELECT connection_id, generation, secret_ref, expires_at, needs_reauthorization
                 FROM provider_refresh_state WHERE connection_id = ?1",
                params![connection_id],
                |row| {
                    let needs: i64 = row.get(4)?;
                    Ok(RefreshState {
                        connection_id: row.get(0)?,
                        generation: row.get::<_, i64>(1)? as u64,
                        secret_ref: row.get(2)?,
                        expires_at: row.get::<_, i64>(3)? as u64,
                        needs_reauthorization: needs != 0,
                    })
                },
            )
            .optional()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(state)
    }

    fn claim_refresh(
        &self,
        connection_id: &str,
        generation: u64,
        owner: &str,
    ) -> StorageResult<bool> {
        let mut guard = self.lock()?;
        let transaction = guard
            .transaction()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        let current = transaction
            .query_row(
                "SELECT generation FROM provider_connections WHERE connection_id = ?1",
                params![connection_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        let Some(current) = current else {
            return Ok(false);
        };
        if current as u64 != generation {
            return Ok(false);
        }
        // A claim is bound to the generation it was taken at. A claim of an
        // earlier generation is stale, because the credential moved on, and
        // it does not stop the owner of the current generation from
        // claiming.
        let existing = transaction
            .query_row(
                "SELECT owner, generation FROM refresh_claims WHERE connection_id = ?1",
                params![connection_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        if let Some((_claim_owner, claim_generation)) = existing {
            if claim_generation as u64 == generation {
                // Even the same owner may have another refresh in flight.
                return Ok(false);
            }
            if claim_generation as u64 > generation {
                return Ok(false);
            }
        }
        transaction
            .execute(
                "INSERT INTO refresh_claims (connection_id, owner, claimed_at, generation)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(connection_id) DO UPDATE SET
                     owner = excluded.owner,
                     generation = excluded.generation",
                params![connection_id, owner, 0_i64, generation as i64],
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        transaction
            .commit()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(true)
    }

    /// Claim the right to refresh a connection, with a clock.
    ///
    /// A claim is not automatically taken over: the original worker may
    /// still be performing an irreversible external refresh.
    fn claim_refresh_at(
        &self,
        connection_id: &str,
        generation: u64,
        owner: &str,
        now: u64,
        _ttl: u64,
    ) -> StorageResult<bool> {
        let mut guard = self.lock()?;
        let transaction = guard
            .transaction()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        let current = transaction
            .query_row(
                "SELECT generation FROM provider_connections WHERE connection_id = ?1",
                params![connection_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        let Some(current) = current else {
            return Ok(false);
        };
        if current as u64 != generation {
            return Ok(false);
        }
        // A claim is bound to the generation it was taken at. A claim of an
        // earlier generation is stale, because the credential moved on, and
        // it does not stop the owner of the current generation from
        // claiming.
        let existing = transaction
            .query_row(
                "SELECT owner, generation, claimed_at FROM refresh_claims WHERE connection_id = ?1",
                params![connection_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        if let Some((_claim_owner, claim_generation, _claimed_at)) = existing {
            if claim_generation as u64 == generation {
                // Neither expiry nor an owner name proves the rotation has stopped.
                return Ok(false);
            }
            if claim_generation as u64 > generation {
                return Ok(false);
            }
        }
        transaction
            .execute(
                "INSERT INTO refresh_claims (connection_id, owner, claimed_at, generation)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(connection_id) DO UPDATE SET
                     owner = excluded.owner,
                     claimed_at = excluded.claimed_at,
                     generation = excluded.generation",
                params![connection_id, owner, now as i64, generation as i64],
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        transaction
            .commit()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(true)
    }

    fn complete_refresh(
        &self,
        connection_id: &str,
        generation: u64,
        owner: &str,
        secret_ref: &str,
        expires_at: u64,
        now: u64,
    ) -> StorageResult<bool> {
        let mut guard = self.lock()?;
        let transaction = guard
            .transaction()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        // The owner must hold the claim of this very generation. A claim of
        // another generation belongs to a credential that has moved on.
        let claim_generation = transaction
            .query_row(
                "SELECT generation FROM refresh_claims WHERE connection_id = ?1 AND owner = ?2",
                params![connection_id, owner],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        let Some(claim_generation) = claim_generation else {
            return Ok(false);
        };
        if claim_generation as u64 != generation {
            return Ok(false);
        }
        let changed = transaction
            .execute(
                "UPDATE provider_connections
                 SET generation = ?2, status = ?3, updated_at = ?4
                 WHERE connection_id = ?1 AND generation = ?5",
                params![
                    connection_id,
                    generation as i64 + 1,
                    ConnectionStatus::Active.as_str(),
                    now as i64,
                    generation as i64,
                ],
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        if changed == 0 {
            return Ok(false);
        }
        transaction
            .execute(
                "INSERT INTO provider_refresh_state
                     (connection_id, generation, secret_ref, expires_at, needs_reauthorization)
                 VALUES (?1, ?2, ?3, ?4, 0)
                 ON CONFLICT(connection_id) DO UPDATE SET
                     generation = excluded.generation,
                     secret_ref = excluded.secret_ref,
                     expires_at = excluded.expires_at,
                     needs_reauthorization = 0",
                params![
                    connection_id,
                    generation as i64 + 1,
                    secret_ref,
                    expires_at as i64
                ],
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        transaction
            .execute(
                "DELETE FROM refresh_claims WHERE connection_id = ?1",
                params![connection_id],
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        transaction
            .commit()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(true)
    }

    fn mark_needs_reauthorization(&self, connection_id: &str, now: u64) -> StorageResult<bool> {
        let mut guard = self.lock()?;
        let transaction = guard
            .transaction()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        let changed = transaction
            .execute(
                "UPDATE provider_connections SET status = ?2, updated_at = ?3
                 WHERE connection_id = ?1",
                params![
                    connection_id,
                    ConnectionStatus::NeedsReauthorization.as_str(),
                    now as i64
                ],
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        transaction
            .execute(
                "UPDATE provider_refresh_state SET needs_reauthorization = 1 WHERE connection_id = ?1",
                params![connection_id],
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        transaction
            .execute(
                "DELETE FROM refresh_claims WHERE connection_id = ?1",
                params![connection_id],
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        transaction
            .commit()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(changed > 0)
    }

    fn disconnect(&self, connection_id: &str, now: u64) -> StorageResult<bool> {
        let mut guard = self.lock()?;
        let transaction = guard
            .transaction()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        let changed = transaction
            .execute(
                "UPDATE provider_connections SET status = ?2, updated_at = ?3
                 WHERE connection_id = ?1",
                params![
                    connection_id,
                    ConnectionStatus::Disconnected.as_str(),
                    now as i64
                ],
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        transaction
            .execute(
                "DELETE FROM provider_refresh_state WHERE connection_id = ?1",
                params![connection_id],
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        transaction
            .execute(
                "DELETE FROM refresh_claims WHERE connection_id = ?1",
                params![connection_id],
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        transaction
            .commit()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(changed > 0)
    }
}

impl MailboxStateStore for SqliteStore {
    fn put_checkpoint(&self, checkpoint: &Checkpoint) -> StorageResult<()> {
        let guard = self.lock()?;
        guard
            .execute(
                "INSERT INTO checkpoints (identity, mailbox, upstream_cursor, generation, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(identity, mailbox) DO UPDATE SET
                     upstream_cursor = excluded.upstream_cursor,
                     generation = excluded.generation,
                     updated_at = excluded.updated_at",
                params![
                    checkpoint.identity,
                    checkpoint.mailbox,
                    checkpoint.upstream_cursor,
                    checkpoint.generation as i64,
                    checkpoint.updated_at as i64,
                ],
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(())
    }

    fn get_checkpoint(&self, identity: &str, mailbox: &str) -> StorageResult<Option<Checkpoint>> {
        let guard = self.lock()?;
        let checkpoint = guard
            .query_row(
                "SELECT identity, mailbox, upstream_cursor, generation, updated_at
                 FROM checkpoints WHERE identity = ?1 AND mailbox = ?2",
                params![identity, mailbox],
                |row| {
                    Ok(Checkpoint {
                        identity: row.get(0)?,
                        mailbox: row.get(1)?,
                        upstream_cursor: row.get(2)?,
                        generation: row.get::<_, i64>(3)? as u64,
                        updated_at: row.get::<_, i64>(4)? as u64,
                    })
                },
            )
            .optional()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(checkpoint)
    }

    fn put_opaque_id(&self, mapping: &OpaqueId) -> StorageResult<()> {
        let guard = self.lock()?;
        guard
            .execute(
                "INSERT INTO opaque_ids (identity, kind, public_id, upstream_id)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(identity, kind, public_id) DO UPDATE SET
                     upstream_id = excluded.upstream_id",
                params![
                    mapping.identity,
                    mapping.kind.as_str(),
                    mapping.public_id,
                    mapping.upstream_id,
                ],
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(())
    }

    fn lookup_opaque_id(
        &self,
        identity: &str,
        kind: OpaqueKind,
        public_id: &str,
    ) -> StorageResult<Option<String>> {
        let guard = self.lock()?;
        let upstream = guard
            .query_row(
                "SELECT upstream_id FROM opaque_ids
                 WHERE identity = ?1 AND kind = ?2 AND public_id = ?3",
                params![identity, kind.as_str(), public_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(upstream)
    }

    fn lookup_public_id(
        &self,
        identity: &str,
        kind: OpaqueKind,
        upstream_id: &str,
    ) -> StorageResult<Option<String>> {
        let guard = self.lock()?;
        let public_id = guard
            .query_row(
                "SELECT public_id FROM opaque_ids
                 WHERE identity = ?1 AND kind = ?2 AND upstream_id = ?3
                 ORDER BY public_id LIMIT 1",
                params![identity, kind.as_str(), upstream_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(public_id)
    }

    fn acquire_lease(
        &self,
        name: &str,
        owner: &str,
        now: u64,
        ttl: u64,
    ) -> StorageResult<WorkerLease> {
        let mut guard = self.lock()?;
        let transaction = guard
            .transaction()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        let previous = transaction
            .query_row(
                "SELECT fencing_token FROM leases WHERE name = ?1",
                params![name],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        let fencing_token = previous.unwrap_or(0) as u64 + 1;
        transaction
            .execute(
                "INSERT INTO leases (name, owner, fencing_token, expires_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(name) DO UPDATE SET
                     owner = excluded.owner,
                     fencing_token = excluded.fencing_token,
                     expires_at = excluded.expires_at",
                params![name, owner, fencing_token as i64, (now + ttl) as i64],
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        transaction
            .commit()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(WorkerLease {
            name: name.to_owned(),
            owner: owner.to_owned(),
            fencing_token,
            expires_at: now + ttl,
        })
    }

    fn renew_lease(
        &self,
        name: &str,
        owner: &str,
        fencing_token: u64,
        now: u64,
        ttl: u64,
    ) -> StorageResult<bool> {
        let guard = self.lock()?;
        let changed = guard
            .execute(
                "UPDATE leases SET expires_at = ?4
                 WHERE name = ?1 AND owner = ?2 AND fencing_token = ?3",
                params![name, owner, fencing_token as i64, (now + ttl) as i64],
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(changed > 0)
    }

    fn release_lease(&self, name: &str, fencing_token: u64) -> StorageResult<bool> {
        let guard = self.lock()?;
        let changed = guard
            .execute(
                "DELETE FROM leases WHERE name = ?1 AND fencing_token = ?2",
                params![name, fencing_token as i64],
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(changed > 0)
    }
}

impl SubmissionStore for SqliteStore {
    fn reserve_submission(
        &self,
        reservation: &IdempotencyReservation,
        submission: &Submission,
    ) -> StorageResult<Submission> {
        if submission.id != reservation.submission_id
            || submission.principal != reservation.principal
            || submission.identity != reservation.identity
            || submission.client_id != reservation.client_id
            || submission.idempotency_key.as_deref() != Some(reservation.key.as_str())
            // The reservation records the payload digest as a plain string,
            // so a keyed submission without a payload is recorded there as
            // the empty string. The submission records the absence of a
            // payload as NULL. The two spellings mean the same intent, and
            // anything else — a reservation that names a payload the
            // submission does not carry, or the reverse — is refused.
            || submission.payload_digest.as_deref().unwrap_or_default() != reservation.payload_digest
        {
            return Err(StorageError::Invalid(
                "the reservation and submission intent do not match".to_owned(),
            ));
        }
        let scope = crate::submission::idempotency_scope(
            &reservation.principal,
            &reservation.client_id,
            &reservation.identity,
            &reservation.key,
        );
        let mut guard = self.lock()?;
        let transaction = guard
            .transaction()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        // The key and the intent are one unit: either both are written or
        // neither is. The key is written first so that a competing writer
        // loses the race on the key rather than on the intent.
        let reserved = match transaction.execute(
            "INSERT INTO idempotency (scope, key, principal, identity, client_id, payload_digest, submission_id, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![scope, reservation.key, reservation.principal, reservation.identity, reservation.client_id,
                    reservation.payload_digest, reservation.submission_id, reservation.created_at as i64,
                    reservation.expires_at.max(reservation.created_at.saturating_add(crate::submission::IDEMPOTENCY_RETENTION_SECONDS)) as i64],
        ) {
            Ok(_) => true,
            Err(error) if is_constraint_violation(&error) => false,
            Err(error) => return Err(StorageError::Backend(error.to_string())),
        };
        if !reserved {
            // The key is already taken. The same payload is a replay of the
            // same intent; a different payload is a conflict.
            let existing = transaction
                .query_row(
                    "SELECT payload_digest, submission_id FROM idempotency WHERE scope = ?1",
                    params![scope],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()
                .map_err(|error| StorageError::Backend(error.to_string()))?;
            let Some((digest, id)) = existing else {
                return Err(StorageError::Conflict(
                    "the idempotency key was reserved by another writer".to_owned(),
                ));
            };
            if digest != reservation.payload_digest {
                return Err(StorageError::Conflict(
                    "the idempotency key was already used with a different payload".to_owned(),
                ));
            }
            let existing_submission = transaction.query_row(
                "SELECT id, principal, identity, client_id, idempotency_key, payload_digest, state,
                        upstream_protocol, attempts, lease_owner, lease_expires_at, fencing_token,
                        created_at, updated_at, failure_code FROM submissions WHERE id = ?1",
                params![id], read_submission,
            ).optional().map_err(|error| StorageError::Backend(error.to_string()))?
                .ok_or_else(|| StorageError::Unsupported("idempotency record has no submission intent; refusing replay".to_owned()))?;
            transaction
                .commit()
                .map_err(|error| StorageError::Backend(error.to_string()))?;
            return Ok(existing_submission);
        }
        // The intent is written in the same transaction as the key. A failure
        // here rolls the key back, so no key survives without an intent.
        transaction
            .execute(
                "INSERT INTO submissions
                 (id, principal, identity, client_id, idempotency_key, payload_digest, state,
                  upstream_protocol, attempts, lease_owner, lease_expires_at, fencing_token,
                  created_at, updated_at, failure_code)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                params![
                    submission.id,
                    submission.principal,
                    submission.identity,
                    submission.client_id,
                    submission.idempotency_key,
                    submission.payload_digest,
                    submission.state.as_str(),
                    submission.upstream_protocol,
                    submission.attempts as i64,
                    submission.lease_owner,
                    submission.lease_expires_at.map(|at| at as i64),
                    submission.fencing_token as i64,
                    submission.created_at as i64,
                    submission.updated_at as i64,
                    submission.failure_code,
                ],
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        transaction
            .commit()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(submission.clone())
    }

    fn lookup_idempotency(
        &self,
        principal: &str,
        client_id: &str,
        identity: &str,
        key: &str,
        now: u64,
    ) -> StorageResult<Option<IdempotencyReservation>> {
        let guard = self.lock()?;
        let reservation = guard
            .query_row(
                "SELECT key, principal, identity, client_id, payload_digest, submission_id, created_at, expires_at
                 FROM idempotency WHERE scope = ?1",
                params![crate::submission::idempotency_scope(
                    principal,
                    client_id,
                    identity,
                    key
                )],
                |row| {
                    Ok(IdempotencyReservation {
                        key: row.get(0)?,
                        principal: row.get(1)?,
                        identity: row.get(2)?,
                        client_id: row.get(3)?,
                        payload_digest: row.get(4)?,
                        submission_id: row.get(5)?,
                        created_at: row.get::<_, i64>(6)? as u64,
                        expires_at: row.get::<_, i64>(7)? as u64,
                    })
                },
            )
            .optional()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(reservation.filter(|reservation| reservation.expires_at > now))
    }

    fn put_submission(&self, submission: &Submission) -> StorageResult<()> {
        if submission.idempotency_key.is_some() {
            return Err(StorageError::Invalid(
                "a submission with an idempotency key is created by the atomic reservation path, \
                 which writes the key and the intent together"
                    .to_owned(),
            ));
        }
        let guard = self.lock()?;
        guard
            .execute(
                "INSERT INTO submissions
                     (id, principal, identity, client_id, idempotency_key, payload_digest, state,
                      upstream_protocol, attempts, lease_owner, lease_expires_at, fencing_token,
                      created_at, updated_at, failure_code)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                params![
                    submission.id,
                    submission.principal,
                    submission.identity,
                    submission.client_id,
                    submission.idempotency_key,
                    submission.payload_digest,
                    submission.state.as_str(),
                    submission.upstream_protocol,
                    submission.attempts as i64,
                    submission.lease_owner,
                    submission.lease_expires_at.map(|at| at as i64),
                    submission.fencing_token as i64,
                    submission.created_at as i64,
                    submission.updated_at as i64,
                    submission.failure_code,
                ],
            )
            .map_err(|error| {
                if is_constraint_violation(&error) {
                    StorageError::Conflict(format!(
                        "the submission {} already exists",
                        submission.id
                    ))
                } else {
                    StorageError::Backend(error.to_string())
                }
            })?;
        Ok(())
    }

    fn get_submission(&self, id: &str) -> StorageResult<Option<Submission>> {
        let guard = self.lock()?;
        let submission = guard
            .query_row(
                "SELECT id, principal, identity, client_id, idempotency_key, payload_digest, state,
                        upstream_protocol, attempts, lease_owner, lease_expires_at, fencing_token,
                        created_at, updated_at, failure_code
                 FROM submissions WHERE id = ?1",
                params![id],
                read_submission,
            )
            .optional()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(submission)
    }

    fn transition(
        &self,
        id: &str,
        state: SubmissionState,
        now: u64,
        failure_code: Option<String>,
    ) -> StorageResult<Submission> {
        let guard = self.lock()?;
        let current = guard
            .query_row(
                "SELECT state FROM submissions WHERE id = ?1",
                params![id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| StorageError::Backend(error.to_string()))?
            .ok_or_else(|| StorageError::NotFound(format!("the submission {id}")))?;
        let current = SubmissionState::parse(&current).unwrap_or(SubmissionState::Failed);
        if !current.may_move_to(state) {
            return Err(StorageError::Conflict(
                "the submission state cannot move backwards".to_owned(),
            ));
        }
        let changed = guard
            .execute(
                "UPDATE submissions SET state = ?2, updated_at = ?3, failure_code = ?4 WHERE id = ?1",
                params![id, state.as_str(), now as i64, failure_code],
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        if changed == 0 {
            return Err(StorageError::NotFound(format!("the submission {id}")));
        }
        drop(guard);
        let submission = self.get_submission(id)?;
        submission.ok_or_else(|| StorageError::NotFound(format!("the submission {id}")))
    }

    fn list_unknown(&self) -> StorageResult<Vec<Submission>> {
        let guard = self.lock()?;
        let mut statement = guard
            .prepare(
                "SELECT id, principal, identity, client_id, idempotency_key, payload_digest, state,
                        upstream_protocol, attempts, lease_owner, lease_expires_at, fencing_token,
                        created_at, updated_at, failure_code
                 FROM submissions WHERE state = ?1 ORDER BY created_at, id",
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        let submissions = statement
            .query_map(params![SubmissionState::Unknown.as_str()], read_submission)
            .map_err(|error| StorageError::Backend(error.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(submissions)
    }

    fn list_by_identity(&self, identity: &str) -> StorageResult<Vec<Submission>> {
        let guard = self.lock()?;
        let mut statement = guard
            .prepare(
                "SELECT id, principal, identity, client_id, idempotency_key, payload_digest, state,
                        upstream_protocol, attempts, lease_owner, lease_expires_at, fencing_token,
                        created_at, updated_at, failure_code
                 FROM submissions WHERE identity = ?1 ORDER BY created_at, id",
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        let submissions = statement
            .query_map(params![identity], read_submission)
            .map_err(|error| StorageError::Backend(error.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(submissions)
    }

    fn claim_next(&self, owner: &str, now: u64, ttl: u64) -> StorageResult<Option<Submission>> {
        let mut guard = self.lock()?;
        let transaction = guard
            .transaction()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        let candidate = transaction
            .query_row(
                "SELECT id, fencing_token FROM submissions
                 WHERE state = ?1
                   AND (lease_owner IS NULL OR lease_expires_at IS NULL OR lease_expires_at <= ?2)
                 ORDER BY created_at, id LIMIT 1",
                params![SubmissionState::Reserved.as_str(), now as i64],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        let Some((id, fencing_token)) = candidate else {
            return Ok(None);
        };
        let fencing_token = fencing_token as u64 + 1;
        transaction
            .execute(
                "UPDATE submissions
                 SET lease_owner = ?2, lease_expires_at = ?3, fencing_token = ?4, updated_at = ?5
                 WHERE id = ?1",
                params![
                    id,
                    owner,
                    (now + ttl) as i64,
                    fencing_token as i64,
                    now as i64
                ],
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        transaction
            .commit()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        drop(guard);
        self.get_submission(&id)
    }

    /// Renew the claim of a submission under its fencing token.
    ///
    /// The renewal extends the claim's expiry without changing its owner
    /// or its fencing token, so a worker that is still working keeps the
    /// item while a worker whose token is stale is refused.
    fn renew_claim(&self, id: &str, fencing_token: u64, now: u64, ttl: u64) -> StorageResult<bool> {
        let guard = self.lock()?;
        let changed = guard
            .execute(
                "UPDATE submissions
                 SET lease_expires_at = ?3, updated_at = ?4
                 WHERE id = ?1 AND fencing_token = ?2",
                params![id, fencing_token as i64, (now + ttl) as i64, now as i64],
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(changed > 0)
    }

    /// Move a claimed submission to a new state under its fencing token.
    ///
    /// The write carries the token the claim was taken with, so a worker
    /// whose claim was taken over cannot mark the item as dispatched: the
    /// row no longer matches its token, and the write is refused.
    fn transition_claimed(
        &self,
        id: &str,
        fencing_token: u64,
        state: SubmissionState,
        now: u64,
        failure_code: Option<String>,
    ) -> StorageResult<Submission> {
        let mut guard = self.lock()?;
        let transaction = guard
            .transaction()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        let current = transaction
            .query_row(
                "SELECT state FROM submissions WHERE id = ?1",
                params![id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| StorageError::Backend(error.to_string()))?
            .ok_or_else(|| StorageError::NotFound(format!("the submission {id}")))?;
        let current = SubmissionState::parse(&current).unwrap_or(SubmissionState::Failed);
        // The state machine is monotonic here exactly as it is for the
        // unfenced transition.
        if !current.may_move_to(state) {
            return Err(StorageError::Conflict(
                "the submission state cannot move backwards".to_owned(),
            ));
        }
        let changed = transaction
            .execute(
                "UPDATE submissions
                 SET state = ?2, updated_at = ?3, failure_code = ?4
                 WHERE id = ?1 AND fencing_token = ?5",
                params![
                    id,
                    state.as_str(),
                    now as i64,
                    failure_code,
                    fencing_token as i64
                ],
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        if changed == 0 {
            return Err(StorageError::Conflict(
                "the claim was taken over by another worker".to_owned(),
            ));
        }
        transaction
            .commit()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        drop(guard);
        let submission = self.get_submission(id)?;
        submission.ok_or_else(|| StorageError::NotFound(format!("the submission {id}")))
    }

    fn release_claim(
        &self,
        id: &str,
        fencing_token: u64,
        state: SubmissionState,
        now: u64,
        failure_code: Option<String>,
    ) -> StorageResult<Submission> {
        let mut guard = self.lock()?;
        let transaction = guard
            .transaction()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        let current = transaction
            .query_row(
                "SELECT state FROM submissions WHERE id = ?1",
                params![id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| StorageError::Backend(error.to_string()))?
            .ok_or_else(|| StorageError::NotFound(format!("the submission {id}")))?;
        let current = SubmissionState::parse(&current).unwrap_or(SubmissionState::Failed);
        // The states are monotonic here as well: a worker that reports an
        // outcome may not reopen a finished submission, may not turn an
        // uncertain send into something else, and may not put a submission
        // that was already sent back into the queue.
        if !current.may_move_to(state) {
            return Err(StorageError::Conflict(
                "the submission state cannot move backwards".to_owned(),
            ));
        }
        let changed = transaction
            .execute(
                "UPDATE submissions
                 SET state = ?2, lease_owner = NULL, lease_expires_at = NULL, updated_at = ?3,
                     failure_code = ?4, fencing_token = ?6
                 WHERE id = ?1 AND fencing_token = ?5",
                params![
                    id,
                    state.as_str(),
                    now as i64,
                    failure_code,
                    fencing_token as i64,
                    fencing_token as i64 + 1
                ],
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        if changed == 0 {
            return Err(StorageError::Conflict(
                "the claim was taken over by another worker".to_owned(),
            ));
        }
        transaction
            .commit()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        drop(guard);
        let submission = self.get_submission(id)?;
        submission.ok_or_else(|| StorageError::NotFound(format!("the submission {id}")))
    }

    fn purge_expired_idempotency(&self, now: u64) -> StorageResult<usize> {
        let guard = self.lock()?;
        let removed = guard
            .execute(
                "DELETE FROM idempotency WHERE expires_at <= ?1",
                params![now as i64],
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(removed)
    }
}

/// Read a submission row.
fn read_submission(row: &rusqlite::Row<'_>) -> rusqlite::Result<Submission> {
    let state: String = row.get(6)?;
    Ok(Submission {
        id: row.get(0)?,
        principal: row.get(1)?,
        identity: row.get(2)?,
        client_id: row.get(3)?,
        idempotency_key: row.get(4)?,
        payload_digest: row.get(5)?,
        state: SubmissionState::parse(&state).unwrap_or(SubmissionState::Failed),
        upstream_protocol: row.get(7)?,
        attempts: row.get::<_, i64>(8)? as u32,
        lease_owner: row.get(9)?,
        lease_expires_at: row.get::<_, Option<i64>>(10)?.map(|at| at as u64),
        fencing_token: row.get::<_, i64>(11)? as u64,
        created_at: row.get::<_, i64>(12)? as u64,
        updated_at: row.get::<_, i64>(13)? as u64,
        failure_code: row.get(14)?,
    })
}

impl TaskStore for SqliteStore {
    fn put_task(&self, task: &Task) -> StorageResult<()> {
        let guard = self.lock()?;
        guard
            .execute(
                "INSERT INTO tasks (task_id, principal, identity, owner, state, progress, result_ref, fencing_token, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                 ON CONFLICT(task_id) DO UPDATE SET
                     principal = excluded.principal,
                     identity = excluded.identity,
                     owner = excluded.owner,
                     state = excluded.state,
                     progress = excluded.progress,
                     result_ref = excluded.result_ref,
                     fencing_token = excluded.fencing_token,
                     updated_at = excluded.updated_at",
                params![
                    task.task_id,
                    task.principal,
                    task.identity,
                    task.owner,
                    task.state.as_str(),
                    task.progress,
                    task.result_ref,
                    task.fencing_token as i64,
                    task.created_at as i64,
                    task.updated_at as i64,
                ],
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(())
    }

    fn get_task(&self, task_id: &str) -> StorageResult<Option<Task>> {
        let guard = self.lock()?;
        let task = guard
            .query_row(
                "SELECT task_id, principal, identity, owner, state, progress, result_ref, fencing_token, created_at, updated_at
                 FROM tasks WHERE task_id = ?1",
                params![task_id],
                read_task,
            )
            .optional()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(task)
    }

    fn claim_task(&self, task_id: &str, owner: &str, now: u64) -> StorageResult<Task> {
        let mut guard = self.lock()?;
        let transaction = guard
            .transaction()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        let current = transaction
            .query_row(
                "SELECT fencing_token, state FROM tasks WHERE task_id = ?1",
                params![task_id],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(|error| StorageError::Backend(error.to_string()))?
            .ok_or_else(|| StorageError::NotFound(format!("the task {task_id}")))?;
        let state = TaskState::parse(&current.1).unwrap_or(TaskState::Pending);
        if state.is_terminal() {
            return Err(StorageError::Conflict(format!(
                "the task {task_id} already finished"
            )));
        }
        let fencing_token = current.0 as u64 + 1;
        transaction
            .execute(
                "UPDATE tasks SET owner = ?2, state = ?3, fencing_token = ?4, updated_at = ?5
                 WHERE task_id = ?1",
                params![
                    task_id,
                    owner,
                    TaskState::Running.as_str(),
                    fencing_token as i64,
                    now as i64
                ],
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        transaction
            .commit()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        drop(guard);
        let task = self.get_task(task_id)?;
        task.ok_or_else(|| StorageError::NotFound(format!("the task {task_id}")))
    }

    fn set_progress(
        &self,
        task_id: &str,
        owner: &str,
        fencing_token: u64,
        progress: &str,
        now: u64,
    ) -> StorageResult<bool> {
        let guard = self.lock()?;
        let changed = guard
            .execute(
                "UPDATE tasks SET progress = ?4, updated_at = ?5
                 WHERE task_id = ?1 AND owner = ?2 AND fencing_token = ?3",
                params![task_id, owner, fencing_token as i64, progress, now as i64],
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(changed > 0)
    }

    fn complete_task(
        &self,
        task_id: &str,
        owner: &str,
        fencing_token: u64,
        result_ref: &str,
        now: u64,
    ) -> StorageResult<bool> {
        let guard = self.lock()?;
        let changed = guard
            .execute(
                "UPDATE tasks SET state = ?4, result_ref = ?5, updated_at = ?6
                 WHERE task_id = ?1 AND owner = ?2 AND fencing_token = ?3",
                params![
                    task_id,
                    owner,
                    fencing_token as i64,
                    TaskState::Completed.as_str(),
                    result_ref,
                    now as i64
                ],
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(changed > 0)
    }

    fn fail_task(
        &self,
        task_id: &str,
        owner: &str,
        fencing_token: u64,
        now: u64,
    ) -> StorageResult<bool> {
        let guard = self.lock()?;
        let changed = guard
            .execute(
                "UPDATE tasks SET state = ?4, updated_at = ?5
                 WHERE task_id = ?1 AND owner = ?2 AND fencing_token = ?3",
                params![
                    task_id,
                    owner,
                    fencing_token as i64,
                    TaskState::Failed.as_str(),
                    now as i64
                ],
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(changed > 0)
    }

    fn cancel_task(&self, task_id: &str, now: u64) -> StorageResult<bool> {
        let guard = self.lock()?;
        let changed = guard
            .execute(
                "UPDATE tasks SET state = ?2, updated_at = ?3 WHERE task_id = ?1",
                params![task_id, TaskState::Cancelled.as_str(), now as i64],
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(changed > 0)
    }

    fn list_tasks(&self, state: Option<TaskState>) -> StorageResult<Vec<Task>> {
        let guard = self.lock()?;
        let mut statement = guard
            .prepare(
                "SELECT task_id, principal, identity, owner, state, progress, result_ref, fencing_token, created_at, updated_at
                 FROM tasks ORDER BY created_at, task_id",
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        let tasks = statement
            .query_map([], read_task)
            .map_err(|error| StorageError::Backend(error.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(match state {
            Some(state) => tasks
                .into_iter()
                .filter(|task| task.state == state)
                .collect(),
            None => tasks,
        })
    }
}

/// Read a task row.
fn read_task(row: &rusqlite::Row<'_>) -> rusqlite::Result<Task> {
    let state: String = row.get(4)?;
    Ok(Task {
        task_id: row.get(0)?,
        principal: row.get(1)?,
        identity: row.get(2)?,
        owner: row.get(3)?,
        state: TaskState::parse(&state).unwrap_or(TaskState::Pending),
        progress: row.get(5)?,
        result_ref: row.get(6)?,
        fencing_token: row.get::<_, i64>(7)? as u64,
        created_at: row.get::<_, i64>(8)? as u64,
        updated_at: row.get::<_, i64>(9)? as u64,
    })
}

impl AuditStore for SqliteStore {
    fn append(&self, event: &AuditEvent) -> StorageResult<()> {
        let guard = self.lock()?;
        guard
            .execute(
                "INSERT INTO audit_events (at, actor, action, subject, outcome)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    event.at as i64,
                    event.actor,
                    event.action,
                    event.subject,
                    event.outcome
                ],
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(())
    }

    fn list(&self, since: u64, limit: u32) -> StorageResult<Vec<AuditEvent>> {
        let guard = self.lock()?;
        let mut statement = guard
            .prepare(
                "SELECT at, actor, action, subject, outcome FROM audit_events
                 WHERE at >= ?1 ORDER BY at, id LIMIT ?2",
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        let events = statement
            .query_map(params![since as i64, limit as i64], |row| {
                Ok(AuditEvent {
                    at: row.get::<_, i64>(0)? as u64,
                    actor: row.get(1)?,
                    action: row.get(2)?,
                    subject: row.get(3)?,
                    outcome: row.get(4)?,
                })
            })
            .map_err(|error| StorageError::Backend(error.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(events)
    }

    fn prune(&self, before: u64) -> StorageResult<usize> {
        let guard = self.lock()?;
        let removed = guard
            .execute(
                "DELETE FROM audit_events WHERE at < ?1",
                params![before as i64],
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        Ok(removed)
    }
}
