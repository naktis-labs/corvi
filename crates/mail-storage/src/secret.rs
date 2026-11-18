//! The secret store: custody of the values that must not be readable.
//!
//! ADR-0010 section 4 separates "DB read access" from "secret decryption
//! authority". A relational table may hold a reference to a secret; only
//! the secret store may turn that reference back into a value.
//!
//! The standalone implementation is an encrypted file. The file holds
//! encrypted envelopes and nothing else: no plaintext, no recoverable
//! token, no key material. The wrapping key lives in a **separate** file
//! with its own protection, and the store refuses to use a wrapping key
//! that other users on the machine can read.
//!
//! Every envelope is bound to its context — the provider, the connection,
//! the kind of secret, the owner, the name, the key id and the version —
//! so a secret copied into another connection does not decrypt there. A
//! wrong key, a modified envelope and a mismatched context all fail the
//! same way: closed, and visibly so, rather than "not found".

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

pub use crate::crypto::{LocalSecretResolver, SecretAad, SecretResolver};

use crate::crypto::{Cipher, derive_key, random_bytes};
use crate::error::{StorageError, StorageResult};

/// The version of the on-disk format.
pub const FORMAT_VERSION: u32 = 1;

/// The information the store needs about the key that opened it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRef {
    /// The owner of the secret.
    pub owner: String,
    /// The name of the secret within the owner's namespace.
    pub name: String,
    /// The key that encrypted the envelope.
    pub key_id: String,
    /// The version of the secret.
    pub version: u32,
}

/// The secret store.
pub trait SecretStore {
    /// Store a value, replacing an earlier value with the same name.
    fn put(
        &self,
        owner: &str,
        name: &str,
        plaintext: &[u8],
        aad: &SecretAad,
    ) -> StorageResult<SecretRef>;
    /// Read a value.
    fn get(&self, reference: &SecretRef, aad: &SecretAad) -> StorageResult<Option<Vec<u8>>>;
    /// Replace a value with a new one, increasing its version.
    fn rotate(
        &self,
        reference: &SecretRef,
        plaintext: &[u8],
        aad: &SecretAad,
    ) -> StorageResult<SecretRef>;
    /// Forget a value.
    fn delete(&self, reference: &SecretRef) -> StorageResult<bool>;
    /// List the references of one owner.
    fn list(&self, owner: &str) -> StorageResult<Vec<SecretRef>>;
}

/// One stored envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Envelope {
    owner: String,
    name: String,
    key_id: String,
    version: u32,
    nonce: String,
    ciphertext: String,
    created_at: u64,
}

/// The on-disk document.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Document {
    version: u32,
    salt: String,
    key_id: String,
    secrets: Vec<Envelope>,
}

/// A secret store backed by an encrypted file.
#[derive(Debug)]
pub struct EncryptedFileSecretStore {
    path: PathBuf,
    key_id: String,
    wrapping_key: Vec<u8>,
    /// The counter that makes the name of a temporary file unique, so two
    /// writes of one store cannot take each other's file.
    temporary: AtomicU64,
}

impl EncryptedFileSecretStore {
    /// Open or create a store at a path.
    ///
    /// The file is created with owner-only permissions, its directory is
    /// created so that only its owner can enter it, and the wrapping key is
    /// held in memory for the lifetime of the store. A directory that other
    /// users may write to is refused, because they could replace the secret
    /// file with one of their own.
    pub fn open(path: impl AsRef<Path>, wrapping_key: &[u8], key_id: &str) -> StorageResult<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            protect_directory(parent)?;
        }
        let store = Self {
            path,
            key_id: key_id.to_owned(),
            wrapping_key: wrapping_key.to_vec(),
            temporary: AtomicU64::new(0),
        };
        if !store.path.exists() {
            store.write(&Document {
                version: FORMAT_VERSION,
                salt: hex::encode(random_bytes(16)?),
                key_id: key_id.to_owned(),
                secrets: Vec::new(),
            })?;
        } else {
            check_protected_file(&store.path)?;
        }
        Ok(store)
    }

    /// Open a store whose wrapping key lives in a separate file.
    ///
    /// The key file must not be readable by anyone but its owner. A key
    /// that other users on the machine can read is not a protected key, and
    /// the store refuses to pretend otherwise.
    pub fn open_with_key_file(
        path: impl AsRef<Path>,
        key_file: impl AsRef<Path>,
        key_id: &str,
    ) -> StorageResult<Self> {
        let key_file = key_file.as_ref();
        check_protected_file(key_file)?;
        let key = std::fs::read(key_file)?;
        Self::open(path, &key, key_id)
    }

    /// Open a store whose wrapping key a resolver provides.
    pub fn open_with_resolver(
        path: impl AsRef<Path>,
        resolver: &dyn SecretResolver,
        key_reference: &str,
        key_id: &str,
    ) -> StorageResult<Self> {
        let key = resolver.resolve(key_reference)?;
        Self::open(path, &key, key_id)
    }

    /// The path of the store file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The key id in force.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Read the document.
    fn read(&self) -> StorageResult<Document> {
        let text = std::fs::read_to_string(&self.path)?;
        let document: Document = serde_json::from_str(&text).map_err(|error| {
            StorageError::Invalid(format!("the secret file is not readable: {error}"))
        })?;
        if document.version > FORMAT_VERSION {
            return Err(StorageError::Unsupported(format!(
                "the secret file has version {} but this build understands {FORMAT_VERSION}",
                document.version
            )));
        }
        Ok(document)
    }

    /// Write the document, atomically.
    ///
    /// The document goes to a temporary file next to the store: created
    /// owner-only before the first byte is written, flushed to the disk,
    /// and then renamed over the store, and the directory is flushed with
    /// it. A reader therefore sees the old document or the new one, never a
    /// half-written one; a crash does not leave a truncated secret; and no
    /// other user on the machine can read the secret while it is written.
    fn write(&self, document: &Document) -> StorageResult<()> {
        let text = serde_json::to_string_pretty(document).map_err(|error| {
            StorageError::Backend(format!("the secret file is not writable: {error}"))
        })?;
        let temporary = self.temporary_path();
        let outcome = write_owner_only(&temporary, text.as_bytes());
        if let Err(error) = outcome {
            // A half-written file is not a secret store. It is removed, so
            // nothing partial is left behind.
            let _ = std::fs::remove_file(&temporary);
            return Err(error);
        }
        std::fs::rename(&temporary, &self.path)?;
        sync_directory(self.path.parent().unwrap_or(Path::new(".")))?;
        Ok(())
    }

    /// The path of the file the next write goes to.
    ///
    /// The name is unique to this process and to this write, so a write
    /// cannot take the file of another one, and a file that a crashed write
    /// left behind is not mistaken for the current one.
    fn temporary_path(&self) -> PathBuf {
        let round = self.temporary.fetch_add(1, Ordering::Relaxed);
        let mut name = self
            .path
            .file_name()
            .map(|name| name.to_os_string())
            .unwrap_or_default();
        name.push(format!(".{}.{}.tmp", std::process::id(), round));
        self.path.with_file_name(name)
    }

    /// The cipher for the document.
    fn cipher(&self, document: &Document) -> StorageResult<Cipher> {
        let salt = hex::decode(&document.salt)
            .map_err(|_| StorageError::Invalid("the secret file is corrupt".to_owned()))?;
        let key = derive_key(&self.wrapping_key, &salt, b"corvi-secret-store/v1")?;
        Cipher::new(&key)
    }

    /// Re-encrypt every envelope under a new wrapping key.
    ///
    /// The rewrap needs the old and the new context, because an envelope
    /// is bound to the key that encrypted it. A rewrap that cannot read an
    /// envelope fails and changes nothing.
    pub fn rewrap(
        &self,
        new_key: &[u8],
        new_key_id: &str,
        aad_for: &dyn Fn(&str, &str) -> SecretAad,
    ) -> StorageResult<usize> {
        let mut document = self.read()?;
        let cipher = self.cipher(&document)?;
        let salt_bytes = random_bytes(16)?;
        let salt = hex::encode(&salt_bytes);
        let new_cipher = Cipher::new(&derive_key(new_key, &salt_bytes, b"corvi-secret-store/v1")?)?;
        let mut rewrapped = Vec::with_capacity(document.secrets.len());
        for envelope in &document.secrets {
            let aad = aad_for(&envelope.owner, &envelope.name);
            let nonce = hex::decode(&envelope.nonce)
                .map_err(|_| StorageError::Invalid("the secret file is corrupt".to_owned()))?;
            let ciphertext = hex::decode(&envelope.ciphertext)
                .map_err(|_| StorageError::Invalid("the secret file is corrupt".to_owned()))?;
            let plaintext = cipher.open(
                &nonce,
                &ciphertext,
                &aad.to_bytes(&envelope.name, &envelope.key_id, envelope.version),
            )?;
            let (new_nonce, new_ciphertext) = new_cipher.seal(
                &plaintext,
                &aad.to_bytes(&envelope.name, new_key_id, envelope.version),
            )?;
            rewrapped.push(Envelope {
                owner: envelope.owner.clone(),
                name: envelope.name.clone(),
                key_id: new_key_id.to_owned(),
                version: envelope.version,
                nonce: hex::encode(new_nonce),
                ciphertext: hex::encode(new_ciphertext),
                created_at: envelope.created_at,
            });
        }
        document.salt = salt;
        document.key_id = new_key_id.to_owned();
        document.secrets = rewrapped;
        self.write(&document)?;
        Ok(document.secrets.len())
    }

    /// The entries of the document, keyed by owner and name.
    fn index(document: &Document) -> BTreeMap<(String, String), Envelope> {
        document
            .secrets
            .iter()
            .map(|envelope| {
                (
                    (envelope.owner.clone(), envelope.name.clone()),
                    envelope.clone(),
                )
            })
            .collect()
    }
}

impl SecretStore for EncryptedFileSecretStore {
    fn put(
        &self,
        owner: &str,
        name: &str,
        plaintext: &[u8],
        aad: &SecretAad,
    ) -> StorageResult<SecretRef> {
        let mut document = self.read()?;
        let cipher = self.cipher(&document)?;
        let version = Self::index(&document)
            .get(&(owner.to_owned(), name.to_owned()))
            .map_or(1, |envelope| envelope.version + 1);
        let (nonce, ciphertext) =
            cipher.seal(plaintext, &aad.to_bytes(name, &self.key_id, version))?;
        let envelope = Envelope {
            owner: owner.to_owned(),
            name: name.to_owned(),
            key_id: self.key_id.clone(),
            version,
            nonce: hex::encode(nonce),
            ciphertext: hex::encode(ciphertext),
            created_at: 0,
        };
        document.secrets.retain(|existing| {
            !(existing.owner == envelope.owner && existing.name == envelope.name)
        });
        document.secrets.push(envelope);
        self.write(&document)?;
        Ok(SecretRef {
            owner: owner.to_owned(),
            name: name.to_owned(),
            key_id: self.key_id.clone(),
            version,
        })
    }

    fn get(&self, reference: &SecretRef, aad: &SecretAad) -> StorageResult<Option<Vec<u8>>> {
        let document = self.read()?;
        let index = Self::index(&document);
        let Some(envelope) = index.get(&(reference.owner.clone(), reference.name.clone())) else {
            return Ok(None);
        };
        if envelope.key_id != reference.key_id || envelope.version != reference.version {
            return Ok(None);
        }
        let cipher = self.cipher(&document)?;
        let nonce = hex::decode(&envelope.nonce)
            .map_err(|_| StorageError::Invalid("the secret file is corrupt".to_owned()))?;
        let ciphertext = hex::decode(&envelope.ciphertext)
            .map_err(|_| StorageError::Invalid("the secret file is corrupt".to_owned()))?;
        let plaintext = cipher.open(
            &nonce,
            &ciphertext,
            &aad.to_bytes(&envelope.name, &envelope.key_id, envelope.version),
        )?;
        Ok(Some(plaintext))
    }

    fn rotate(
        &self,
        reference: &SecretRef,
        plaintext: &[u8],
        aad: &SecretAad,
    ) -> StorageResult<SecretRef> {
        self.put(&reference.owner, &reference.name, plaintext, aad)
    }

    fn delete(&self, reference: &SecretRef) -> StorageResult<bool> {
        let mut document = self.read()?;
        let before = document.secrets.len();
        document.secrets.retain(|envelope| {
            !(envelope.owner == reference.owner
                && envelope.name == reference.name
                && envelope.version == reference.version)
        });
        let removed = document.secrets.len() != before;
        if removed {
            self.write(&document)?;
        }
        Ok(removed)
    }

    fn list(&self, owner: &str) -> StorageResult<Vec<SecretRef>> {
        let document = self.read()?;
        Ok(document
            .secrets
            .iter()
            .filter(|envelope| envelope.owner == owner)
            .map(|envelope| SecretRef {
                owner: envelope.owner.clone(),
                name: envelope.name.clone(),
                key_id: envelope.key_id.clone(),
                version: envelope.version,
            })
            .collect())
    }
}

/// Refuse a file that other users on the machine can read.
pub fn check_protected_file(path: &Path) -> StorageResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(path)?;
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(StorageError::Invalid(format!(
                "the file {} is readable by other users; a protected file must not be",
                path.display()
            )));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// Make the directory that holds a protected file owner-only.
///
/// A directory other users may write to lets them replace the protected
/// file with one of their own, so a store that finds itself in one is
/// refused instead of trusted.
fn protect_directory(directory: &Path) -> StorageResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        if !directory.exists() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(directory)?;
        }
        let mode = std::fs::metadata(directory)?.permissions().mode();
        if mode & 0o700 != 0o700 {
            return Err(StorageError::Invalid(format!(
                "the directory {} cannot be entered by its owner",
                directory.display()
            )));
        }
        if mode & 0o022 != 0 {
            return Err(StorageError::Invalid(format!(
                "the directory {} may be written by other users; a secret store must not live \
                 in one",
                directory.display()
            )));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = directory;
    }
    Ok(())
}

/// Write a file that holds a secret value, owner-only from the first byte.
pub(crate) fn write_owner_only(path: &Path, bytes: &[u8]) -> StorageResult<()> {
    use std::io::Write;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    Ok(())
}

/// Create a directory that only its owner can enter.
pub(crate) fn create_private_directory(path: &Path) -> StorageResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(path)?;
    }
    Ok(())
}

/// A temporary name next to a file, for a write that is renamed into place.
///
/// The name carries the label, so it never collides with the file it
/// replaces: `with_extension` would turn `backup.sqlite` into `backup`,
/// which is a different file the caller may care about.
pub(crate) fn temporary_path(path: &Path, label: &str) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|name| name.to_os_string())
        .unwrap_or_default();
    name.push(format!(".{label}.tmp"));
    path.with_file_name(name)
}

/// Write a file atomically, with owner-only permissions from the first byte.
///
/// The bytes are written to a name that does not exist yet, flushed, and
/// renamed over the destination. A reader of the destination sees either
/// the old file or the new one, never a partial file, and never a file
/// other users on the machine may read.
pub(crate) fn write_atomic_owner_only(path: &Path, bytes: &[u8]) -> StorageResult<()> {
    use std::io::Write;
    let temporary = temporary_path(path, "write");
    let _ = std::fs::remove_file(&temporary);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    if let Err(error) = std::fs::rename(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error.into());
    }
    sync_directory(path.parent().unwrap_or(Path::new(".")))?;
    Ok(())
}

/// Create a file with owner-only permissions when it is not there yet.
///
/// A file that is already there is left alone: the caller wants the file to
/// exist with owner-only permissions, not to be replaced.
pub(crate) fn create_owner_only(path: &Path) -> StorageResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
        {
            Ok(file) => {
                file.sync_all()?;
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
    #[cfg(not(unix))]
    {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
        {
            Ok(file) => {
                file.sync_all()?;
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

/// Copy a file into a new owner-only file, and flush it.
///
/// The copy is written to a name that does not exist yet, with owner-only
/// permissions from the first byte, so a reader never sees a partial file
/// and never sees a file other users may read.
pub(crate) fn copy_owner_only(source: &Path, destination: &Path) -> StorageResult<()> {
    use std::io::Read;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(destination)?;
        let mut input = std::fs::File::open(source)?;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = input.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            std::io::Write::write_all(&mut file, &buffer[..read])?;
        }
        file.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = source;
        std::fs::copy(source, destination)?;
    }
    Ok(())
}

/// Append to a file that holds protected material, and flush it.
pub(crate) fn append_owner_only(path: &Path, bytes: &[u8]) -> StorageResult<()> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new().append(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

/// Flush a directory, so that a rename in it is durable across a crash.
pub(crate) fn sync_directory(directory: &Path) -> StorageResult<()> {
    #[cfg(unix)]
    {
        std::fs::File::open(directory)?.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = directory;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A context to bind an envelope to.
    fn aad() -> SecretAad {
        SecretAad {
            provider: "fastmail".to_owned(),
            connection: "conn-1".to_owned(),
            kind: "refreshToken".to_owned(),
            owner: "identity-1".to_owned(),
        }
    }

    #[test]
    fn a_secret_round_trips() {
        let directory = std::env::temp_dir().join(format!(
            "corvi-secret-{}",
            hex::encode(random_bytes(8).unwrap())
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("secrets.enc");
        let store =
            EncryptedFileSecretStore::open(&path, b"a wrapping key long enough", "k1").unwrap();
        let reference = store
            .put("identity-1", "refresh", b"the token", &aad())
            .unwrap();
        let value = store.get(&reference, &aad()).unwrap().unwrap();
        assert_eq!(value, b"the token");
    }

    #[test]
    fn the_file_holds_no_plaintext() {
        let directory = std::env::temp_dir().join(format!(
            "corvi-secret-{}",
            hex::encode(random_bytes(8).unwrap())
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("secrets.enc");
        let store =
            EncryptedFileSecretStore::open(&path, b"a wrapping key long enough", "k1").unwrap();
        store
            .put("identity-1", "refresh", b"the token", &aad())
            .unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("the token"));
    }

    #[test]
    fn the_file_and_its_directory_are_owner_only() {
        let directory = std::env::temp_dir().join(format!(
            "corvi-secret-{}",
            hex::encode(random_bytes(8).unwrap())
        ));
        let path = directory.join("secrets.enc");
        // The store creates the directory itself, so it is the store's
        // permissions that are checked.
        let store =
            EncryptedFileSecretStore::open(&path, b"a wrapping key long enough", "k1").unwrap();
        store
            .put("identity-1", "refresh", b"the token", &aad())
            .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let file = std::fs::metadata(&path).expect("the file is there");
            assert_eq!(
                file.permissions().mode() & 0o777,
                0o600,
                "the secret file is readable by other users"
            );
            let directory = std::fs::metadata(&directory).expect("the directory is there");
            assert_eq!(
                directory.permissions().mode() & 0o777,
                0o700,
                "the directory of the secret file is readable by other users"
            );
        }
    }

    #[test]
    fn a_replacement_never_shows_a_partial_file() {
        let directory = std::env::temp_dir().join(format!(
            "corvi-secret-{}",
            hex::encode(random_bytes(8).unwrap())
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("secrets.enc");
        let store =
            EncryptedFileSecretStore::open(&path, b"a wrapping key long enough", "k1").unwrap();
        store
            .put("identity-1", "refresh", b"the token", &aad())
            .unwrap();
        // A reader watches the file while the writer replaces it. Every
        // observation has to be a whole document, and every file the writer
        // leaves behind has to be readable by its owner alone.
        let writer = std::thread::spawn({
            move || {
                for round in 0..100 {
                    let payload = vec![b'x'; 4_096 + round];
                    store
                        .put("identity-1", "refresh", &payload, &aad())
                        .unwrap();
                }
            }
        });
        let mut observations = 0_usize;
        while !writer.is_finished() {
            let text = std::fs::read_to_string(&path).expect("the file is there");
            let document: serde_json::Value =
                serde_json::from_str(&text).expect("the file is a whole document");
            assert!(document.get("secrets").is_some(), "the document is whole");
            for entry in std::fs::read_dir(&directory).expect("the directory is there") {
                let entry = entry.expect("the entry is there");
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    // A file may have been renamed away between the listing
                    // and this read; that is not a loose permission.
                    if let Ok(metadata) = entry.metadata() {
                        let mode = metadata.permissions().mode();
                        assert_eq!(
                            mode & 0o077,
                            0,
                            "the file {} is readable by other users",
                            entry.path().display()
                        );
                    }
                }
            }
            observations += 1;
        }
        writer.join().expect("the writer ends");
        assert!(observations > 0, "the reader observed nothing");
    }

    #[test]
    fn a_failed_replacement_leaves_no_secret_material_behind() {
        let directory = std::env::temp_dir().join(format!(
            "corvi-secret-{}",
            hex::encode(random_bytes(8).unwrap())
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("secrets.enc");
        let store =
            EncryptedFileSecretStore::open(&path, b"a wrapping key long enough", "k1").unwrap();
        store
            .put("identity-1", "refresh", b"the token", &aad())
            .unwrap();
        // The store cannot be written any more: its place is taken by a
        // directory, so the write cannot finish.
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        let error = store
            .put("identity-1", "refresh", b"another token", &aad())
            .expect_err("the write fails");
        assert!(matches!(error, StorageError::Backend(_)), "{error:?}");
        // Nothing that holds the secret is left behind.
        let mut entries: Vec<String> = std::fs::read_dir(&directory)
            .expect("the directory is there")
            .map(|entry| {
                entry
                    .expect("the entry is there")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        entries.sort();
        assert_eq!(
            entries,
            vec!["secrets.enc".to_owned()],
            "the failed write left a file behind: {entries:?}"
        );
    }

    #[test]
    fn a_writable_directory_is_refused() {
        let directory = std::env::temp_dir().join(format!(
            "corvi-secret-{}",
            hex::encode(random_bytes(8).unwrap())
        ));
        std::fs::create_dir_all(&directory).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o777)).unwrap();
        }
        let path = directory.join("secrets.enc");
        let error = EncryptedFileSecretStore::open(&path, b"a wrapping key long enough", "k1")
            .expect_err("a directory other users may write to is refused");
        assert!(matches!(error, StorageError::Invalid(_)), "{error:?}");
    }

    #[test]
    fn the_wrong_key_fails_closed() {
        let directory = std::env::temp_dir().join(format!(
            "corvi-secret-{}",
            hex::encode(random_bytes(8).unwrap())
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("secrets.enc");
        let store =
            EncryptedFileSecretStore::open(&path, b"a wrapping key long enough", "k1").unwrap();
        let reference = store
            .put("identity-1", "refresh", b"the token", &aad())
            .unwrap();
        let other =
            EncryptedFileSecretStore::open(&path, b"a different wrapping key", "k1").unwrap();
        assert_eq!(
            other.get(&reference, &aad()),
            Err(StorageError::KeyMismatch)
        );
    }

    #[test]
    fn another_connection_cannot_read_the_secret() {
        let directory = std::env::temp_dir().join(format!(
            "corvi-secret-{}",
            hex::encode(random_bytes(8).unwrap())
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("secrets.enc");
        let store =
            EncryptedFileSecretStore::open(&path, b"a wrapping key long enough", "k1").unwrap();
        let reference = store
            .put("identity-1", "refresh", b"the token", &aad())
            .unwrap();
        let elsewhere = SecretAad {
            connection: "conn-2".to_owned(),
            ..aad()
        };
        assert_eq!(
            store.get(&reference, &elsewhere),
            Err(StorageError::KeyMismatch)
        );
    }

    #[test]
    fn a_key_held_in_its_own_protected_file_opens_the_store() {
        let directory = std::env::temp_dir().join(format!(
            "corvi-secret-{}",
            hex::encode(random_bytes(8).unwrap())
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let key_file = directory.join("wrapping.key");
        std::fs::write(&key_file, b"a wrapping key long enough").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let store = EncryptedFileSecretStore::open_with_key_file(
            directory.join("secrets.enc"),
            &key_file,
            "k1",
        )
        .unwrap();
        let reference = store
            .put("identity-1", "refresh", b"the token", &aad())
            .unwrap();
        assert_eq!(
            store.get(&reference, &aad()).unwrap().unwrap(),
            b"the token"
        );
    }

    #[test]
    fn a_key_file_that_other_users_can_read_is_refused() {
        let directory = std::env::temp_dir().join(format!(
            "corvi-secret-{}",
            hex::encode(random_bytes(8).unwrap())
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let key_file = directory.join("wrapping.key");
        std::fs::write(&key_file, b"a wrapping key long enough").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        let error = EncryptedFileSecretStore::open_with_key_file(
            directory.join("secrets.enc"),
            &key_file,
            "k1",
        )
        .expect_err("a key that other users can read is refused");
        assert!(matches!(error, StorageError::Invalid(_)), "{error:?}");
    }
}
