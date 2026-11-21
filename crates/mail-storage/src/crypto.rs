//! The cryptography the secret and blob custody boundaries use.
//!
//! ADR-0010 requires that secret envelopes are authenticated and bound to
//! their context, that the wrapping key is held separately from the data
//! it protects, and that a wrong key fails closed. This module is the small
//! amount of cryptography that needs:
//!
//! - **ChaCha20-Poly1305** for the envelopes, because it is
//!   authenticated: a modified envelope is rejected rather than decrypted.
//! - **HKDF-SHA256** to derive a per-store data key from the wrapping key
//!   and a random salt, so the wrapping key itself never encrypts
//!   anything and the same key under two stores produces two keys.
//! - **Associated data** that binds every envelope to its owner, name, key
//!   id, version and purpose. A secret copied from one connection into
//!   another therefore fails to decrypt rather than decrypting into the
//!   wrong place.
//!
//! Everything here is deliberately small and boring. There is no key
//! stretching, no password derivation and no key recovery: the wrapping
//! key comes from a separate, protected file or secret service, and the
//! exact profile is a deployment decision that ADR-0010 leaves open.

use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use ring::hkdf::{HKDF_SHA256, Salt};
use ring::rand::{SecureRandom, SystemRandom};

use crate::error::{StorageError, StorageResult};

/// The length of the derived data key.
pub const KEY_LENGTH: usize = 32;

/// The length of a nonce.
pub const NONCE_LENGTH: usize = 12;

/// Fill a buffer with random bytes.
pub fn random_bytes(length: usize) -> StorageResult<Vec<u8>> {
    let mut bytes = vec![0u8; length];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| StorageError::Backend("the random source failed".to_owned()))?;
    Ok(bytes)
}

/// Derive a data key from a wrapping key and a salt.
///
/// The wrapping key is never used to encrypt directly, so a store file
/// does not depend on the exact wrapping key being reused elsewhere.
pub fn derive_key(wrapping_key: &[u8], salt: &[u8], info: &[u8]) -> StorageResult<Vec<u8>> {
    if wrapping_key.len() < 16 {
        return Err(StorageError::Invalid(
            "the wrapping key is too short to be a key".to_owned(),
        ));
    }
    let salt = Salt::new(HKDF_SHA256, salt);
    let prk = salt.extract(wrapping_key);
    let info_slice = [info];
    let okm = prk
        .expand(&info_slice, ring::hkdf::HKDF_SHA256)
        .map_err(|_| StorageError::Backend("the key derivation failed".to_owned()))?;
    let mut key = vec![0u8; KEY_LENGTH];
    okm.fill(&mut key)
        .map_err(|_| StorageError::Backend("the key derivation failed".to_owned()))?;
    Ok(key)
}

/// An authenticated cipher for one store.
#[derive(Debug)]
pub struct Cipher {
    key: LessSafeKey,
}

impl Cipher {
    /// A cipher over the given data key.
    pub fn new(key: &[u8]) -> StorageResult<Self> {
        let unbound = UnboundKey::new(&CHACHA20_POLY1305, key)
            .map_err(|_| StorageError::Invalid("the data key is not usable".to_owned()))?;
        Ok(Self {
            key: LessSafeKey::new(unbound),
        })
    }

    /// Encrypt a value, returning the nonce and the ciphertext.
    pub fn seal(&self, plaintext: &[u8], aad: &[u8]) -> StorageResult<(Vec<u8>, Vec<u8>)> {
        let nonce_bytes = random_bytes(NONCE_LENGTH)?;
        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
            .map_err(|_| StorageError::Backend("the random source failed".to_owned()))?;
        let mut buffer = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(nonce, Aad::from(aad), &mut buffer)
            .map_err(|_| StorageError::Backend("the encryption failed".to_owned()))?;
        Ok((nonce_bytes, buffer))
    }

    /// Decrypt a value.
    ///
    /// A wrong key, a modified ciphertext and a mismatched associated data
    /// all fail the same way: [`StorageError::KeyMismatch`]. The value is
    /// not returned, and the failure is not reported as "absent", because
    /// absent and unreadable are different answers.
    pub fn open(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> StorageResult<Vec<u8>> {
        if nonce.len() != NONCE_LENGTH {
            return Err(StorageError::KeyMismatch);
        }
        let nonce =
            Nonce::try_assume_unique_for_key(nonce).map_err(|_| StorageError::KeyMismatch)?;
        let mut buffer = ciphertext.to_vec();
        let plaintext = self
            .key
            .open_in_place(nonce, Aad::from(aad), &mut buffer)
            .map_err(|_| StorageError::KeyMismatch)?;
        Ok(plaintext.to_vec())
    }
}

/// The associated data of one envelope.
///
/// The fields are the ones ADR-0010 names: the provider, the connection,
/// the kind of secret, the version and the owner. Binding them means a
/// secret moved to another connection does not decrypt there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretAad {
    /// The provider the secret belongs to.
    pub provider: String,
    /// The connection the secret belongs to.
    pub connection: String,
    /// The kind of the secret.
    pub kind: String,
    /// The owner of the secret.
    pub owner: String,
}

impl SecretAad {
    /// The canonical byte string the envelope is bound to.
    pub fn to_bytes(&self, name: &str, key_id: &str, version: u32) -> Vec<u8> {
        format!(
            "corvi-secret/v1\nprovider={}\nconnection={}\nkind={}\nowner={}\nname={}\nkey_id={}\nversion={}",
            self.provider, self.connection, self.kind, self.owner, name, key_id, version
        )
        .into_bytes()
    }
}

/// A resolver for secret references.
///
/// The configuration only ever holds a reference, never a value, so the
/// deployment decides where the key material actually comes from.
pub trait SecretResolver: std::fmt::Debug {
    /// Resolve a reference to the bytes it names.
    fn resolve(&self, reference: &str) -> StorageResult<Vec<u8>>;
}

/// A resolver that reads a local file or an environment variable.
///
/// The `secret://` prefix is a promise about *where* the value comes from,
/// not a format: `secret://file/<path>` reads a file and
/// `secret://env/<NAME>` reads an environment variable. A deployment that
/// uses another source implements [`SecretResolver`] instead.
#[derive(Debug, Clone, Copy, Default)]
pub struct LocalSecretResolver;

impl SecretResolver for LocalSecretResolver {
    fn resolve(&self, reference: &str) -> StorageResult<Vec<u8>> {
        let Some(rest) = reference.strip_prefix("secret://") else {
            return Err(StorageError::Invalid(format!(
                "the reference {reference} is not a secret:// reference"
            )));
        };
        if let Some(path) = rest.strip_prefix("file/") {
            return std::fs::read(path).map_err(|error| {
                StorageError::Invalid(format!("the referenced file cannot be read: {error}"))
            });
        }
        if let Some(name) = rest.strip_prefix("env/") {
            return std::env::var(name)
                .map(String::into_bytes)
                .map_err(|error| {
                    StorageError::Invalid(format!("the referenced variable is not set: {error}"))
                });
        }
        Err(StorageError::Invalid(format!(
            "the reference {reference} names no known source"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sealed_value_opens_with_the_same_key() {
        let key = derive_key(b"a wrapping key that is long enough", b"salt", b"info").unwrap();
        let cipher = Cipher::new(&key).unwrap();
        let (nonce, ciphertext) = cipher.seal(b"a secret", b"aad").unwrap();
        let opened = cipher.open(&nonce, &ciphertext, b"aad").unwrap();
        assert_eq!(opened, b"a secret");
    }

    #[test]
    fn a_wrong_key_fails_closed() {
        let key = derive_key(b"a wrapping key that is long enough", b"salt", b"info").unwrap();
        let other = derive_key(b"a different wrapping key!!", b"salt", b"info").unwrap();
        let cipher = Cipher::new(&key).unwrap();
        let other_cipher = Cipher::new(&other).unwrap();
        let (nonce, ciphertext) = cipher.seal(b"a secret", b"aad").unwrap();
        assert_eq!(
            other_cipher.open(&nonce, &ciphertext, b"aad"),
            Err(StorageError::KeyMismatch)
        );
    }

    #[test]
    fn a_mismatched_associated_data_fails_closed() {
        let key = derive_key(b"a wrapping key that is long enough", b"salt", b"info").unwrap();
        let cipher = Cipher::new(&key).unwrap();
        let (nonce, ciphertext) = cipher.seal(b"a secret", b"aad").unwrap();
        assert_eq!(
            cipher.open(&nonce, &ciphertext, b"other"),
            Err(StorageError::KeyMismatch)
        );
    }

    #[test]
    fn a_modified_ciphertext_fails_closed() {
        let key = derive_key(b"a wrapping key that is long enough", b"salt", b"info").unwrap();
        let cipher = Cipher::new(&key).unwrap();
        let (nonce, mut ciphertext) = cipher.seal(b"a secret", b"aad").unwrap();
        ciphertext[0] ^= 0xff;
        assert_eq!(
            cipher.open(&nonce, &ciphertext, b"aad"),
            Err(StorageError::KeyMismatch)
        );
    }
}
