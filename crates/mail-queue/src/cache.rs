//! The optional encrypted cache of message content.
//!
//! ADR-0010 section 5 is explicit: "Default: do not persist inbound raw
//! MIME or attachments." A deployment that wants an offline copy opts in,
//! and the opt-in carries its own encryption and retention contract.
//!
//! This module is that opt-in, and it is small on purpose:
//!
//! - The content is stored through the existing encrypted blob store, which
//!   holds its wrapping key separately from the data it protects. No second
//!   cryptography and no second key custody boundary is introduced here.
//! - The retention window is bounded by [`CachePolicy`], and the entry
//!   expires with it, so a cache cannot become an unbounded second copy of
//!   the mailbox.
//! - Nothing is stored unless the policy says the cache is on. A disabled
//!   cache refuses the write instead of quietly keeping nothing, so a
//!   caller can tell "not cached" from "not allowed to cache".
//!
//! The cache holds what the provider's mailbox is the source of truth for,
//! so it is an internal store: it is written by the synchronization engine
//! and read by the data plane, never by a client-facing endpoint that has
//! not re-authorized the read.

use std::fmt;

use mail_storage::{BlobCleanup, BlobStore};

use crate::config::{CachePolicy, Feature};
use crate::error::{QueueError, QueueResult};
use crate::payload::{account_of, cache_key_for_message};

/// The largest cached content the cache accepts, in bytes.
///
/// The bound keeps a single oversized message from filling the store, and it
/// is a refusal rather than a truncation: a truncated cache entry would be
/// a message that is neither absent nor complete.
pub const MAX_CACHED_CONTENT_BYTES: u64 = 4 * 1024 * 1024;

/// One cached entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheEntry {
    /// The identity the content belongs to.
    pub identity: String,
    /// The opaque identifier of the message.
    pub message_id: String,
    /// The blob account the content is kept under.
    pub account: String,
    /// The blob key the content is kept under.
    pub key: String,
    /// When the entry expires.
    pub expires_at: u64,
}

/// A store of cached message content.
pub trait ContentCache: fmt::Debug {
    /// Whether the cache is switched on.
    fn is_enabled(&self) -> bool;

    /// Cache the content of one message.
    fn store(
        &self,
        identity: &str,
        message_id: &str,
        content: &[u8],
        now: u64,
    ) -> QueueResult<CacheEntry>;

    /// Read the cached content of one message.
    fn load(&self, identity: &str, message_id: &str) -> QueueResult<Option<Vec<u8>>>;

    /// Remove the entries that expired, and report how many were removed.
    fn purge_expired(&self, now: u64) -> QueueResult<usize>;
}

/// A content cache backed by the encrypted blob store.
pub struct EncryptedContentCache<B: BlobStore> {
    blobs: B,
    policy: CachePolicy,
}

impl<B: BlobStore> fmt::Debug for EncryptedContentCache<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedContentCache")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl<B: BlobStore> EncryptedContentCache<B> {
    /// Build a cache over a blob store, with a retention policy.
    pub fn new(blobs: B, policy: CachePolicy) -> Self {
        Self { blobs, policy }
    }

    /// The policy behind this cache.
    pub fn policy(&self) -> &CachePolicy {
        &self.policy
    }

    /// The blob store behind this cache.
    pub fn blobs(&self) -> &B {
        &self.blobs
    }
}

impl<B: BlobStore> ContentCache for EncryptedContentCache<B> {
    fn is_enabled(&self) -> bool {
        self.policy.is_enabled()
    }

    fn store(
        &self,
        identity: &str,
        message_id: &str,
        content: &[u8],
        now: u64,
    ) -> QueueResult<CacheEntry> {
        if !self.policy.is_enabled() {
            return Err(QueueError::FeatureDisabled(Feature::EncryptedCache));
        }
        if content.len() as u64 > MAX_CACHED_CONTENT_BYTES {
            return Err(QueueError::PayloadTooLarge {
                limit: MAX_CACHED_CONTENT_BYTES,
            });
        }
        let account = account_of(identity);
        let key = cache_key_for_message(message_id);
        let staged = self.blobs.stage(
            &account,
            &key,
            content,
            now,
            self.policy.retention_seconds(),
        )?;
        self.blobs.commit(&staged)?;
        Ok(CacheEntry {
            identity: identity.to_owned(),
            message_id: message_id.to_owned(),
            account,
            key,
            expires_at: now + self.policy.retention_seconds(),
        })
    }

    fn load(&self, identity: &str, message_id: &str) -> QueueResult<Option<Vec<u8>>> {
        if !self.policy.is_enabled() {
            return Err(QueueError::FeatureDisabled(Feature::EncryptedCache));
        }
        Ok(self
            .blobs
            .get(&account_of(identity), &cache_key_for_message(message_id))?)
    }

    fn purge_expired(&self, now: u64) -> QueueResult<usize> {
        if !self.policy.is_enabled() {
            return Err(QueueError::FeatureDisabled(Feature::EncryptedCache));
        }
        let BlobCleanup {
            expired_objects, ..
        } = self.blobs.cleanup(now, &[])?;
        Ok(expired_objects)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mail_storage::EncryptedDirectoryBlobStore;

    fn cache(name: &str, retention: u64) -> EncryptedContentCache<EncryptedDirectoryBlobStore> {
        let directory = std::env::temp_dir().join(format!("corvi-queue-cache-{name}"));
        let _ = std::fs::remove_dir_all(&directory);
        let blobs =
            EncryptedDirectoryBlobStore::open(directory, b"a wrapping key long enough").unwrap();
        EncryptedContentCache::new(blobs, CachePolicy::enabled(retention).unwrap())
    }

    #[test]
    fn a_disabled_cache_refuses_to_store() {
        let directory = std::env::temp_dir().join("corvi-queue-cache-disabled");
        let _ = std::fs::remove_dir_all(&directory);
        let blobs =
            EncryptedDirectoryBlobStore::open(directory, b"a wrapping key long enough").unwrap();
        let cache = EncryptedContentCache::new(blobs, CachePolicy::disabled());
        let error = cache
            .store("acct", "message-1", b"the body", 100)
            .unwrap_err();
        assert_eq!(error, QueueError::FeatureDisabled(Feature::EncryptedCache));
    }

    #[test]
    fn an_expired_entry_is_removed() {
        let cache = cache("expiry", 60);
        cache.store("acct", "message-1", b"the body", 100).unwrap();
        assert_eq!(cache.purge_expired(150).unwrap(), 0);
        assert_eq!(cache.purge_expired(200).unwrap(), 1);
        assert_eq!(cache.load("acct", "message-1").unwrap(), None);
    }
}
