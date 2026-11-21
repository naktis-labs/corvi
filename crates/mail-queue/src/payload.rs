//! The payload of a queued item.
//!
//! A queued submission may carry a body and attachments. ADR-0010 section 6
//! puts those bytes in the encrypted blob store, and this module is the
//! queue's use of it — the queue never keeps mail bytes of its own and never
//! writes a file of its own.
//!
//! The lifecycle is the one ADR-0010 section 6 describes for a write that
//! crosses a store boundary: a **staged** write first, then the commit,
//! then the garbage collection of the orphans a crash leaves behind. The
//! staged write exists so that a half-written payload is never visible as a
//! complete one; the commit moves it into the object store; and a payload
//! that nothing refers to any more is removed rather than left behind.
//!
//! Every payload is addressed by a key the queue derives from the item it
//! belongs to, so a worker that comes back after a restart can find the
//! payload of the item it recovered without a second index of its own.

use std::fmt;

use mail_storage::{BlobCleanup, BlobRef, BlobStore, PendingBlob};

use crate::error::QueueResult;

/// The blob account of an identity.
///
/// The blob store namespaces objects per account, and the identity is the
/// unit the disclosure policy is scoped to, so the identity is the account.
pub fn account_of(identity: &str) -> String {
    identity.to_owned()
}

/// The blob key of the payload of one queued submission.
pub fn payload_key_for_submission(submission_id: &str) -> String {
    format!("queue/submission/{submission_id}")
}

/// The blob key of one cached message.
pub fn cache_key_for_message(message_id: &str) -> String {
    format!("queue/cache/{message_id}")
}

/// The store that holds queued payloads.
pub trait PayloadStore: fmt::Debug {
    /// Store the payload of an item.
    ///
    /// The write is staged and committed, so a payload is either absent or
    /// complete. It is encrypted by the blob store, which holds the
    /// wrapping key separately from the data it protects.
    fn stage(&self, account: &str, key: &str, bytes: &[u8], now: u64, ttl: u64) -> QueueResult<()>;

    /// Read the payload of an item.
    fn read(&self, account: &str, key: &str) -> QueueResult<Option<Vec<u8>>>;

    /// Remove the payload of an item.
    ///
    /// This is what a completed, failed or abandoned item calls, so the
    /// bytes of a finished item do not stay behind.
    fn discard(&self, account: &str, key: &str) -> QueueResult<()>;

    /// Remove what expired and what nothing refers to.
    fn cleanup(&self, now: u64, pending: &[PendingBlob]) -> QueueResult<BlobCleanup>;
}

/// A payload store backed by the encrypted blob store.
pub struct BlobPayloadStore<B: BlobStore> {
    blobs: B,
}

impl<B: BlobStore> fmt::Debug for BlobPayloadStore<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlobPayloadStore").finish_non_exhaustive()
    }
}

impl<B: BlobStore> BlobPayloadStore<B> {
    /// Build a payload store over a blob store.
    pub fn new(blobs: B) -> Self {
        Self { blobs }
    }

    /// The blob store behind this payload store.
    pub fn blobs(&self) -> &B {
        &self.blobs
    }
}

impl<B: BlobStore> PayloadStore for BlobPayloadStore<B> {
    fn stage(&self, account: &str, key: &str, bytes: &[u8], now: u64, ttl: u64) -> QueueResult<()> {
        let staged = self.blobs.stage(account, key, bytes, now, ttl)?;
        // The commit consumes the staged write, so nothing is left half
        // written and nothing is left over in the staging area.
        let committed: BlobRef = self.blobs.commit(&staged)?;
        debug_assert_eq!(committed.key, key);
        Ok(())
    }

    fn read(&self, account: &str, key: &str) -> QueueResult<Option<Vec<u8>>> {
        Ok(self.blobs.get(account, key)?)
    }

    fn discard(&self, account: &str, key: &str) -> QueueResult<()> {
        // A payload that is not there any more is not an error: the item it
        // belonged to may have been cleaned up twice.
        let _ = self.blobs.delete(account, key)?;
        Ok(())
    }

    fn cleanup(&self, now: u64, pending: &[PendingBlob]) -> QueueResult<BlobCleanup> {
        Ok(self.blobs.cleanup(now, pending)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mail_storage::EncryptedDirectoryBlobStore;

    fn store(name: &str) -> BlobPayloadStore<EncryptedDirectoryBlobStore> {
        let directory = std::env::temp_dir().join(format!("corvi-queue-payload-{name}"));
        let _ = std::fs::remove_dir_all(&directory);
        BlobPayloadStore::new(
            EncryptedDirectoryBlobStore::open(directory, b"a wrapping key long enough").unwrap(),
        )
    }

    #[test]
    fn a_staged_payload_can_be_read_and_discarded() {
        let payloads = store("roundtrip");
        payloads
            .stage("acct", "queue/submission/a", b"the payload", 100, 60)
            .unwrap();
        assert_eq!(
            payloads.read("acct", "queue/submission/a").unwrap(),
            Some(b"the payload".to_vec())
        );
        payloads.discard("acct", "queue/submission/a").unwrap();
        assert_eq!(payloads.read("acct", "queue/submission/a").unwrap(), None);
    }

    #[test]
    fn discarding_a_payload_that_is_not_there_is_not_an_error() {
        let payloads = store("missing");
        assert!(payloads.discard("acct", "queue/submission/a").is_ok());
    }
}
