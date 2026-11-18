//! The blob store: opaque, encrypted objects with a staged write.
//!
//! ADR-0010 section 5 and section 6 describe the shape of a blob store:
//! keys are opaque and namespaced per account, the objects are encrypted,
//! and a write that has to cross a store boundary uses "staged writes,
//! durable intent/outbox and recoverable compensation" rather than a
//! transaction that spans two systems.
//!
//! The staged write is the important part. A payload that has been written
//! but not yet committed is *pending*: it may still belong to a submission
//! that has not been acknowledged. The cleanup therefore never removes a
//! staged object that a pending submission still refers to, and it removes
//! the staged objects that nothing refers to. A crashed write leaves a
//! recoverable record rather than a half-written object.
//!
//! There is deliberately no way to ask this store for inbound mail: the
//! provider's mailbox is the source of truth for incoming mail, and the
//! baseline persists no inbound raw mail at all.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::crypto::{Cipher, derive_key, random_bytes};
use crate::error::{StorageError, StorageResult};

/// A reference to a stored object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobRef {
    /// The account the object belongs to.
    pub account: String,
    /// The opaque key of the object.
    pub key: String,
    /// The version of the object.
    pub version: u32,
}

/// A staged object that has not been committed yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedBlob {
    /// The identifier of the staged write.
    pub staged_id: String,
    /// The account the object belongs to.
    pub account: String,
    /// The opaque key of the object.
    pub key: String,
    /// When the staged write may be removed.
    pub expires_at: u64,
}

/// A blob that a pending submission still refers to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingBlob {
    /// The account the object belongs to.
    pub account: String,
    /// The opaque key of the object.
    pub key: String,
}

/// What a cleanup removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BlobCleanup {
    /// The staged writes that expired and that nothing referred to.
    pub expired_staged: usize,
    /// The committed objects that expired.
    pub expired_objects: usize,
}

/// The blob store.
pub trait BlobStore {
    /// Stage a write.
    fn stage(
        &self,
        account: &str,
        key: &str,
        bytes: &[u8],
        now: u64,
        ttl: u64,
    ) -> StorageResult<StagedBlob>;
    /// Commit a staged write.
    fn commit(&self, staged: &StagedBlob) -> StorageResult<BlobRef>;
    /// Read an object.
    fn get(&self, account: &str, key: &str) -> StorageResult<Option<Vec<u8>>>;
    /// Forget an object.
    fn delete(&self, account: &str, key: &str) -> StorageResult<bool>;
    /// Remove what expired and what nothing refers to.
    ///
    /// The pending list holds the blobs that a submission in flight still
    /// needs, so a cleanup cannot take the payload away from a send that
    /// has not been acknowledged yet.
    fn cleanup(&self, now: u64, pending: &[PendingBlob]) -> StorageResult<BlobCleanup>;
}

/// The metadata of a stored object.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Metadata {
    account: String,
    key: String,
    version: u32,
    expires_at: u64,
    salt: String,
    nonce: String,
}

/// The metadata of a staged write.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StagedMetadata {
    account: String,
    key: String,
    expires_at: u64,
    salt: String,
    nonce: String,
}

/// A blob store backed by an encrypted directory.
#[derive(Debug)]
pub struct EncryptedDirectoryBlobStore {
    root: PathBuf,
    wrapping_key: Vec<u8>,
}

impl EncryptedDirectoryBlobStore {
    /// Open a blob store at a directory, creating it if it does not exist.
    ///
    /// The directories of the store are created so that only their owner
    /// can enter them, and the files in them are owner-only: an object is
    /// the payload of a submission, encrypted but still worth keeping out
    /// of reach of the other users of the machine.
    pub fn open(root: impl AsRef<Path>, wrapping_key: &[u8]) -> StorageResult<Self> {
        let root = root.as_ref().to_path_buf();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            for directory in [root.join("objects"), root.join("staging")] {
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(&directory)?;
            }
        }
        #[cfg(not(unix))]
        {
            std::fs::create_dir_all(root.join("objects"))?;
            std::fs::create_dir_all(root.join("staging"))?;
        }
        Ok(Self {
            root,
            wrapping_key: wrapping_key.to_vec(),
        })
    }

    /// The directory of the store.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The file name of an object.
    fn object_path(&self, account: &str, key: &str) -> PathBuf {
        self.root
            .join("objects")
            .join(format!("{}.blob", digest_of(account, key)))
    }

    /// The metadata file of an object.
    fn object_metadata_path(&self, account: &str, key: &str) -> PathBuf {
        self.root
            .join("objects")
            .join(format!("{}.json", digest_of(account, key)))
    }

    /// The file of a staged write.
    fn staged_path(&self, staged_id: &str) -> PathBuf {
        self.root.join("staging").join(format!("{staged_id}.blob"))
    }

    /// The metadata file of a staged write.
    fn staged_metadata_path(&self, staged_id: &str) -> PathBuf {
        self.root.join("staging").join(format!("{staged_id}.json"))
    }

    /// Encrypt a payload with a fresh salt and nonce.
    fn seal(&self, bytes: &[u8]) -> StorageResult<(String, String, Vec<u8>)> {
        let salt = random_bytes(16)?;
        let key = derive_key(&self.wrapping_key, &salt, b"corvi-blob/v1")?;
        let cipher = Cipher::new(&key)?;
        let (nonce, ciphertext) = cipher.seal(bytes, b"corvi-blob/v1")?;
        Ok((hex::encode(salt), hex::encode(nonce), ciphertext))
    }

    /// Decrypt a payload.
    fn open_bytes(&self, salt: &str, nonce: &str, ciphertext: &[u8]) -> StorageResult<Vec<u8>> {
        let salt = hex::decode(salt)
            .map_err(|_| StorageError::Invalid("the blob metadata is corrupt".to_owned()))?;
        let nonce = hex::decode(nonce)
            .map_err(|_| StorageError::Invalid("the blob metadata is corrupt".to_owned()))?;
        let key = derive_key(&self.wrapping_key, &salt, b"corvi-blob/v1")?;
        let cipher = Cipher::new(&key)?;
        cipher.open(&nonce, ciphertext, b"corvi-blob/v1")
    }
}

impl BlobStore for EncryptedDirectoryBlobStore {
    fn stage(
        &self,
        account: &str,
        key: &str,
        bytes: &[u8],
        now: u64,
        ttl: u64,
    ) -> StorageResult<StagedBlob> {
        let staged_id = hex::encode(random_bytes(16)?);
        let (salt, nonce, ciphertext) = self.seal(bytes)?;
        crate::secret::write_atomic_owner_only(&self.staged_path(&staged_id), &ciphertext)?;
        let metadata = StagedMetadata {
            account: account.to_owned(),
            key: key.to_owned(),
            expires_at: now + ttl,
            salt,
            nonce,
        };
        let bytes = serde_json::to_vec(&metadata).map_err(|error| {
            StorageError::Backend(format!("the metadata is not writable: {error}"))
        })?;
        crate::secret::write_atomic_owner_only(&self.staged_metadata_path(&staged_id), &bytes)?;
        Ok(StagedBlob {
            staged_id,
            account: account.to_owned(),
            key: key.to_owned(),
            expires_at: metadata.expires_at,
        })
    }

    fn commit(&self, staged: &StagedBlob) -> StorageResult<BlobRef> {
        let metadata_path = self.staged_metadata_path(&staged.staged_id);
        let raw = std::fs::read(&metadata_path).map_err(|_| {
            StorageError::NotFound(format!("the staged write {}", staged.staged_id))
        })?;
        let metadata: StagedMetadata = serde_json::from_slice(&raw).map_err(|error| {
            StorageError::Invalid(format!("the staged metadata is corrupt: {error}"))
        })?;
        let sealed = std::fs::read(self.staged_path(&staged.staged_id))?;
        // The staged file holds the encrypted payload; it is decrypted with
        // the staged metadata's key and re-encrypted under the committed
        // object's own salt.
        let plaintext = self.open_bytes(&metadata.salt, &metadata.nonce, &sealed)?;
        let version = self
            .read_metadata(&staged.account, &staged.key)?
            .map_or(1, |existing| existing.version + 1);
        let (salt, nonce, ciphertext) = self.seal(&plaintext)?;
        let stored = Metadata {
            account: staged.account.clone(),
            key: staged.key.clone(),
            version,
            expires_at: metadata.expires_at,
            salt,
            nonce,
        };
        self.write_object(&staged.account, &staged.key, &stored, &ciphertext)?;
        let _ = std::fs::remove_file(self.staged_path(&staged.staged_id));
        let _ = std::fs::remove_file(&metadata_path);
        Ok(BlobRef {
            account: staged.account.clone(),
            key: staged.key.clone(),
            version,
        })
    }

    fn get(&self, account: &str, key: &str) -> StorageResult<Option<Vec<u8>>> {
        let Some(metadata) = self.read_metadata(account, key)? else {
            return Ok(None);
        };
        let path = self.object_path(account, key);
        if !path.exists() {
            return Ok(None);
        }
        let ciphertext = std::fs::read(path)?;
        Ok(Some(self.open_bytes(
            &metadata.salt,
            &metadata.nonce,
            &ciphertext,
        )?))
    }

    fn delete(&self, account: &str, key: &str) -> StorageResult<bool> {
        let path = self.object_path(account, key);
        if !path.exists() {
            return Ok(false);
        }
        std::fs::remove_file(path)?;
        let _ = std::fs::remove_file(self.object_metadata_path(account, key));
        Ok(true)
    }

    fn cleanup(&self, now: u64, pending: &[PendingBlob]) -> StorageResult<BlobCleanup> {
        let mut cleanup = BlobCleanup::default();
        let staging = self.root.join("staging");
        if staging.is_dir() {
            for entry in std::fs::read_dir(&staging)? {
                let entry = entry?;
                let path = entry.path();
                if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
                    continue;
                }
                let raw = std::fs::read(&path)?;
                let metadata: StagedMetadata = match serde_json::from_slice(&raw) {
                    Ok(metadata) => metadata,
                    Err(_) => continue,
                };
                if metadata.expires_at > now {
                    continue;
                }
                let still_pending = pending
                    .iter()
                    .any(|blob| blob.account == metadata.account && blob.key == metadata.key);
                if still_pending {
                    continue;
                }
                let staged_id = path
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .unwrap_or_default()
                    .to_owned();
                let _ = std::fs::remove_file(self.staged_path(&staged_id));
                let _ = std::fs::remove_file(&path);
                cleanup.expired_staged += 1;
            }
        }
        let objects = self.root.join("objects");
        if objects.is_dir() {
            for entry in std::fs::read_dir(&objects)? {
                let entry = entry?;
                let path = entry.path();
                if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
                    continue;
                }
                let raw = std::fs::read(&path)?;
                let metadata: Metadata = match serde_json::from_slice(&raw) {
                    Ok(metadata) => metadata,
                    Err(_) => continue,
                };
                if metadata.expires_at <= now {
                    let _ =
                        std::fs::remove_file(self.object_path(&metadata.account, &metadata.key));
                    let _ = std::fs::remove_file(&path);
                    cleanup.expired_objects += 1;
                }
            }
        }
        Ok(cleanup)
    }
}

impl EncryptedDirectoryBlobStore {
    /// Read the metadata of an object.
    fn read_metadata(&self, account: &str, key: &str) -> StorageResult<Option<Metadata>> {
        let path = self.object_metadata_path(account, key);
        if !path.exists() {
            return Ok(None);
        }
        let raw = std::fs::read(path)?;
        let metadata: Metadata = serde_json::from_slice(&raw).map_err(|error| {
            StorageError::Invalid(format!("the blob metadata is corrupt: {error}"))
        })?;
        if metadata.account != account || metadata.key != key {
            return Ok(None);
        }
        Ok(Some(metadata))
    }

    /// Write an object and its metadata.
    fn write_object(
        &self,
        account: &str,
        key: &str,
        metadata: &Metadata,
        ciphertext: &[u8],
    ) -> StorageResult<()> {
        let path = self.object_path(account, key);
        crate::secret::write_atomic_owner_only(&path, ciphertext)?;
        let metadata_path = self.object_metadata_path(account, key);
        let bytes = serde_json::to_vec(metadata).map_err(|error| {
            StorageError::Backend(format!("the metadata is not writable: {error}"))
        })?;
        crate::secret::write_atomic_owner_only(&metadata_path, &bytes)?;
        Ok(())
    }
}

/// The file name of an object, derived from its account and key.
///
/// The name is derived rather than taken from the key, so a key can never
/// escape the directory it belongs to.
fn digest_of(account: &str, key: &str) -> String {
    let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
    sha2::Digest::update(&mut hasher, account.as_bytes());
    sha2::Digest::update(&mut hasher, [0x1f]);
    sha2::Digest::update(&mut hasher, key.as_bytes());
    hex::encode(sha2::Digest::finalize(hasher))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A store in a temporary directory.
    fn store(name: &str) -> EncryptedDirectoryBlobStore {
        let directory = std::env::temp_dir().join(format!("corvi-blob-{name}"));
        let _ = std::fs::remove_dir_all(&directory);
        EncryptedDirectoryBlobStore::open(directory, b"a wrapping key long enough").unwrap()
    }

    #[test]
    fn a_staged_object_becomes_readable_after_a_commit() {
        let store = store("commit");
        let staged = store
            .stage("acct", "key-1", b"the payload", 100, 60)
            .unwrap();
        assert!(store.get("acct", "key-1").unwrap().is_none());
        store.commit(&staged).unwrap();
        assert_eq!(store.get("acct", "key-1").unwrap().unwrap(), b"the payload");
    }

    #[test]
    fn the_object_is_encrypted_on_disk() {
        let store = store("encrypted");
        let staged = store
            .stage("acct", "key-1", b"the payload", 100, 60)
            .unwrap();
        store.commit(&staged).unwrap();
        let path = store.object_path("acct", "key-1");
        let bytes = std::fs::read(path).unwrap();
        assert!(!bytes.windows(10).any(|window| window == b"the payload"));
    }

    #[test]
    fn a_pending_staged_write_survives_a_cleanup() {
        let store = store("pending");
        let staged = store
            .stage("acct", "key-1", b"the payload", 100, 60)
            .unwrap();
        let pending = vec![PendingBlob {
            account: "acct".to_owned(),
            key: "key-1".to_owned(),
        }];
        let cleanup = store.cleanup(1_000, &pending).unwrap();
        assert_eq!(cleanup.expired_staged, 0);
        assert!(store.staged_path(&staged.staged_id).exists());
    }

    #[test]
    fn an_unreferenced_staged_write_is_removed() {
        let store = store("orphan");
        let staged = store
            .stage("acct", "key-1", b"the payload", 100, 60)
            .unwrap();
        let cleanup = store.cleanup(1_000, &[]).unwrap();
        assert_eq!(cleanup.expired_staged, 1);
        assert!(!store.staged_path(&staged.staged_id).exists());
    }

    #[test]
    fn the_object_and_its_directory_are_owner_only() {
        let store = store("owner-only");
        let staged = store
            .stage("acct", "key-1", b"the payload", 100, 60)
            .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // The staged write is on disk before the commit, and it is as
            // protected as the object it becomes.
            let staged_file = store.staged_path(&staged.staged_id);
            let mode = std::fs::metadata(&staged_file)
                .expect("the staged file is there")
                .permissions()
                .mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "the staged file is readable by other users"
            );
        }
        store.commit(&staged).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let path = store.object_path("acct", "key-1");
            let mode = std::fs::metadata(&path)
                .expect("the object is there")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "the object is readable by other users");
            for directory in [store.root().join("objects"), store.root().join("staging")] {
                let mode = std::fs::metadata(&directory)
                    .expect("the directory is there")
                    .permissions()
                    .mode();
                assert_eq!(
                    mode & 0o777,
                    0o700,
                    "the directory {} is readable by other users",
                    directory.display()
                );
                // Nothing is left behind that another user could read.
                for entry in std::fs::read_dir(&directory).expect("the directory is there") {
                    let entry = entry.expect("the entry is there");
                    let mode = entry
                        .metadata()
                        .expect("the entry is there")
                        .permissions()
                        .mode();
                    assert_eq!(
                        mode & 0o077,
                        0,
                        "the file {} is readable by other users",
                        entry.path().display()
                    );
                }
            }
        }
    }
}
