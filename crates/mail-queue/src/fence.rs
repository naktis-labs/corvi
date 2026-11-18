//! Fenced ownership of a unit of work.
//!
//! ADR-0010 section 6 requires queue workers to use "transactionally claimed
//! jobs and leases with fencing/version counters". The lease itself lives in
//! the storage layer ([`mail_storage::MailboxStateStore`]); this module is
//! the queue's use of it.
//!
//! The rule the fence enforces is narrow and absolute: **a worker whose
//! fence token is stale must not perform the work**. A worker that was
//! paused long enough to lose its lease comes back believing it still owns
//! the item, and every write it attempts is refused. The owner is the
//! token, not the name: acquiring a lease again fences the previous owner
//! off, and the previous owner's next write fails even though it still
//! holds the same name.
//!
//! The token is monotonically increasing per lease name, so a token that was
//! ever issued is never issued again.

use mail_storage::MailboxStateStore;

use crate::error::{QueueError, QueueResult};

/// The lease name of one queued submission.
pub fn lease_name_for_submission(submission_id: &str) -> String {
    format!("queue/submission/{submission_id}")
}

/// The lease name of one synchronized mailbox.
pub fn lease_name_for_sync(identity: &str, mailbox: &str) -> String {
    format!("queue/sync/{identity}/{mailbox}")
}

/// A held, fenced lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FencedLease {
    name: String,
    owner: String,
    fencing_token: u64,
    expires_at: u64,
}

impl FencedLease {
    /// Acquire a lease, fencing off any earlier owner.
    ///
    /// The returned lease carries the new fencing token. The earlier
    /// owner's token is stale from this moment on, whatever it believes.
    pub fn acquire(
        store: &dyn MailboxStateStore,
        name: &str,
        owner: &str,
        now: u64,
        ttl: u64,
    ) -> QueueResult<Self> {
        let lease = store.acquire_lease(name, owner, now, ttl)?;
        Ok(Self {
            name: lease.name,
            owner: lease.owner,
            fencing_token: lease.fencing_token,
            expires_at: lease.expires_at,
        })
    }

    /// The name of the leased resource.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The owner that holds the lease.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// The fencing token of this acquisition.
    ///
    /// It increases on every acquisition and is never reused.
    pub fn fencing_token(&self) -> u64 {
        self.fencing_token
    }

    /// When the lease expires.
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Renew the lease, and fail when the fence is stale.
    ///
    /// A renewal that does not match the stored owner and token means the
    /// lease was taken over, so the caller must not continue.
    pub fn renew(&self, store: &dyn MailboxStateStore, now: u64, ttl: u64) -> QueueResult<()> {
        if now >= self.expires_at {
            return Err(QueueError::StaleFence(format!(
                "the lease {} expired before the work was finished",
                self.name
            )));
        }
        let renewed = store.renew_lease(&self.name, &self.owner, self.fencing_token, now, ttl)?;
        if !renewed {
            return Err(QueueError::StaleFence(format!(
                "the lease {} was taken over by another worker",
                self.name
            )));
        }
        Ok(())
    }

    /// Assert that this lease is still the current one.
    ///
    /// This is the check a worker makes before it performs work: it renews
    /// the lease, and a refusal means the work belongs to somebody else now.
    pub fn assert_current(
        &self,
        store: &dyn MailboxStateStore,
        now: u64,
        ttl: u64,
    ) -> QueueResult<()> {
        self.renew(store, now, ttl)
    }

    /// Release the lease, and fail when the fence is stale.
    pub fn release(&self, store: &dyn MailboxStateStore) -> QueueResult<()> {
        let released = store.release_lease(&self.name, self.fencing_token)?;
        if !released {
            return Err(QueueError::StaleFence(format!(
                "the lease {} was taken over by another worker",
                self.name
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mail_storage::SqliteStore;

    #[test]
    fn a_taken_over_lease_fences_the_previous_owner_off() {
        let store = SqliteStore::open_in_memory().unwrap();
        let first =
            FencedLease::acquire(&store, "queue/submission/a", "worker-one", 100, 60).unwrap();
        let second =
            FencedLease::acquire(&store, "queue/submission/a", "worker-two", 110, 60).unwrap();
        assert!(second.fencing_token() > first.fencing_token());
        let error = first.assert_current(&store, 120, 60).unwrap_err();
        assert!(matches!(error, QueueError::StaleFence(_)));
        assert!(second.assert_current(&store, 120, 60).is_ok());
    }

    #[test]
    fn an_expired_lease_may_not_perform_work() {
        let store = SqliteStore::open_in_memory().unwrap();
        let lease =
            FencedLease::acquire(&store, "queue/submission/a", "worker-one", 100, 60).unwrap();
        let error = lease.assert_current(&store, 200, 60).unwrap_err();
        assert!(matches!(error, QueueError::StaleFence(_)));
    }
}
