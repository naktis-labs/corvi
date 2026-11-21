//! Opening the storage of a deployment.
//!
//! The configuration says which backends a deployment uses; this module
//! turns that into the objects the rest of the system uses. It is also
//! where a backend that this build does not implement is refused: a
//! configuration that asks for PostgreSQL is told that PostgreSQL is not
//! implemented, rather than being accepted and quietly running on
//! something else.

use std::path::Path;

use crate::blob::EncryptedDirectoryBlobStore;
use crate::config::{BlobBackend, SecretBackend, StateBackend, StorageConfig};
use crate::crypto::SecretResolver;
use crate::error::{StorageError, StorageResult};
use crate::secret::EncryptedFileSecretStore;
use crate::sqlite::SqliteStore;

/// The storage of a deployment.
#[derive(Debug)]
pub struct Storage {
    store: SqliteStore,
    secrets: Option<EncryptedFileSecretStore>,
    blobs: Option<EncryptedDirectoryBlobStore>,
}

impl Storage {
    /// Open the storage a configuration describes.
    pub fn open(config: &StorageConfig) -> StorageResult<Self> {
        config.validate()?;
        let store = match config.state.backend {
            StateBackend::Ephemeral => SqliteStore::open_in_memory()?,
            StateBackend::Sqlite => {
                let sqlite = config.state.sqlite.as_ref().ok_or_else(|| {
                    StorageError::Invalid("the sqlite backend has no path".to_owned())
                })?;
                SqliteStore::open(Path::new(&sqlite.path))?
            }
            StateBackend::Postgres => {
                return Err(StorageError::Unsupported(
                    "the PostgreSQL backend is not implemented in this build; the SQLite backend \
                     is single-instance and the ephemeral backend is not durable"
                        .to_owned(),
                ));
            }
        };
        let secrets = match config.secrets.backend {
            SecretBackend::EncryptedFile => {
                let settings = config.secrets.encrypted_file.as_ref().ok_or_else(|| {
                    StorageError::Invalid("the encryptedFile backend has no path".to_owned())
                })?;
                let key = read_protected_key(&settings.wrapping_key_ref)?;
                Some(EncryptedFileSecretStore::open(
                    Path::new(&settings.path),
                    &key,
                    "k1",
                )?)
            }
            SecretBackend::External | SecretBackend::KubernetesSecret => {
                return Err(StorageError::Unsupported(
                    "this build implements only the encryptedFile secret backend".to_owned(),
                ));
            }
        };
        let blobs = match config.blobs.backend {
            BlobBackend::Disabled => None,
            BlobBackend::EncryptedDirectory => {
                let settings = config.blobs.encrypted_directory.as_ref().ok_or_else(|| {
                    StorageError::Invalid("the encryptedDirectory backend has no path".to_owned())
                })?;
                let key = read_protected_key(&settings.wrapping_key_ref)?;
                Some(EncryptedDirectoryBlobStore::open(
                    Path::new(&settings.path),
                    &key,
                )?)
            }
            BlobBackend::S3 => {
                return Err(StorageError::Unsupported(
                    "this build implements only the encryptedDirectory blob backend".to_owned(),
                ));
            }
        };
        Ok(Self {
            store,
            secrets,
            blobs,
        })
    }

    /// The transactional store.
    pub fn store(&self) -> &SqliteStore {
        &self.store
    }

    /// The secret store, when the deployment has one.
    pub fn secrets(&self) -> Option<&EncryptedFileSecretStore> {
        self.secrets.as_ref()
    }

    /// The blob store, when the deployment has one.
    pub fn blobs(&self) -> Option<&EncryptedDirectoryBlobStore> {
        self.blobs.as_ref()
    }
}

/// Read a wrapping key and refuse one that other users can read.
///
/// The key file must be owner-only. A key that the users of the machine
/// can read is not a protected key, and a deployment that points at one
/// is told so instead of being trusted.
fn read_protected_key(reference: &str) -> StorageResult<Vec<u8>> {
    if let Some(path) = reference.strip_prefix("secret://file/") {
        crate::secret::check_protected_file(Path::new(path))?;
        return std::fs::read(path).map_err(|error| {
            StorageError::Invalid(format!("the wrapping key cannot be read: {error}"))
        });
    }
    crate::crypto::LocalSecretResolver.resolve(reference)
}
