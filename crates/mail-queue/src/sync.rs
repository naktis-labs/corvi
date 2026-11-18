//! Filtered synchronization: what changed, and what may be said about it.
//!
//! ADR-0003 section 6 lists the surfaces a hidden message may not leak
//! through, and the first two are the event stream and the notifications:
//! "Events/notifications — filter before publication or subscription
//! delivery". This module is that filter on the synchronization path.
//!
//! The rule is simple and absolute: **a change to a message the disclosure
//! policy hides produces no event and no notification.** Not a redacted
//! event, not an event without a body, not an event a subscriber can count:
//! no event at all, because an event that mentions a message at all tells
//! the subscriber that the message exists.
//!
//! The synchronization loop itself is not here. This module is the part of
//! it that decides, and the seams are named: a [`ChangeSource`] reports
//! what changed, a [`DisclosureGate`] decides what may be said about a
//! message, an [`EventSink`] receives the events and a [`Notifier`] receives
//! the notifications. The IMAP and JMAP adapters, the timer that calls
//! [`SyncEngine::sync_once`] and the delivery of a notification are the
//! caller's, and none of them exists in this crate.

use std::fmt;

use mail_core::{
    ChangeKind, ChangeSet, MailboxRef, MessageId, NormalizedMessage, TransportError,
    UntrustedMessage,
};
use mail_policy::{FilterPolicy, Visibility};
use mail_storage::{Checkpoint, MailboxStateStore, OpaqueId, OpaqueKind};

use crate::cache::ContentCache;
use crate::config::{Feature, QueueFeatures};
use crate::error::{QueueError, QueueResult};
use crate::fence::{FencedLease, lease_name_for_sync};

/// What the disclosure policy says about a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disclosure {
    /// The message may be mentioned.
    Visible,
    /// The message must not be mentioned at all.
    Hidden,
}

/// The gate that decides whether a message may be mentioned.
pub trait DisclosureGate: fmt::Debug {
    /// Decide one message.
    fn disclosure(&self, message: &NormalizedMessage) -> Disclosure;
}

/// A gate backed by a filter policy.
///
/// The policy is the caller's active configuration snapshot. The queue
/// evaluates it locally and never asks the control plane, because ADR-0003
/// section 7 requires the data plane to keep filtering while the control
/// plane and the provider plugins are offline.
#[derive(Debug)]
pub struct PolicyGate<'a> {
    policy: &'a FilterPolicy,
}

impl<'a> PolicyGate<'a> {
    /// Build a gate over a policy.
    pub fn new(policy: &'a FilterPolicy) -> Self {
        Self { policy }
    }
}

impl DisclosureGate for PolicyGate<'_> {
    fn disclosure(&self, message: &NormalizedMessage) -> Disclosure {
        match self.policy.evaluate(message).visibility {
            Visibility::Hide => Disclosure::Hidden,
            Visibility::Show | Visibility::Redact => Disclosure::Visible,
        }
    }
}

/// A source of changes in a mailbox.
///
/// This is the seam where the IMAP or JMAP transport attaches.
pub trait ChangeSource: fmt::Debug {
    /// Report the changes since a cursor.
    fn changes_since(
        &mut self,
        mailbox: &MailboxRef,
        cursor: Option<&str>,
    ) -> Result<ChangeSet, TransportError>;

    /// Read one message.
    fn message(
        &mut self,
        mailbox: &MailboxRef,
        id: &MessageId,
    ) -> Result<UntrustedMessage, TransportError>;
}

/// A change that may be disclosed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncEvent {
    /// The identity the change belongs to.
    pub identity: String,
    /// The mailbox the change belongs to.
    pub mailbox: String,
    /// The opaque identifier of the message.
    ///
    /// The event carries the opaque identifier and never the upstream one,
    /// so an event cannot be used to address an upstream object directly.
    pub message_id: String,
    /// What happened to the message.
    pub kind: ChangeKind,
    /// When the change was observed.
    pub observed_at: u64,
}

/// The receiver of the change events.
pub trait EventSink: fmt::Debug {
    /// Publish one event.
    fn publish(&mut self, event: &SyncEvent) -> QueueResult<()>;
}

/// The receiver of the change notifications.
pub trait Notifier: fmt::Debug {
    /// Notify about one event.
    fn notify(&mut self, event: &SyncEvent) -> QueueResult<()>;
}

/// What one synchronization pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncRun {
    /// The changes the source reported.
    pub observed: usize,
    /// The changes that were published.
    pub published: usize,
    /// The changes that were suppressed because the policy hides them.
    pub suppressed: usize,
    /// The messages that were cached.
    pub cached: usize,
    /// The cursor the pass ended at.
    pub cursor: Option<String>,
}

/// One synchronization request.
#[derive(Debug, Clone, Copy)]
pub struct SyncRequest<'a> {
    /// The identity to synchronize.
    pub identity: &'a str,
    /// The mailbox to synchronize.
    pub mailbox: &'a MailboxRef,
    /// The worker that performs the pass.
    pub owner: &'a str,
    /// The moment the pass starts.
    pub now: u64,
    /// How long the worker's lease lasts.
    pub ttl: u64,
}

/// The filtered synchronization engine.
pub struct SyncEngine<'a> {
    features: QueueFeatures,
    mailbox: &'a dyn MailboxStateStore,
    cache: &'a dyn ContentCache,
}

impl fmt::Debug for SyncEngine<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SyncEngine")
            .field("features", &self.features)
            .field("cache_enabled", &self.cache.is_enabled())
            .finish_non_exhaustive()
    }
}

impl<'a> SyncEngine<'a> {
    /// Build a synchronization engine.
    pub fn new(
        features: QueueFeatures,
        mailbox: &'a dyn MailboxStateStore,
        cache: &'a dyn ContentCache,
    ) -> Self {
        Self {
            features,
            mailbox,
            cache,
        }
    }

    /// Which optional features are enabled.
    pub fn features(&self) -> &QueueFeatures {
        &self.features
    }

    /// Run one synchronization pass.
    ///
    /// The pass is fenced: it takes a lease over the mailbox, and a worker
    /// whose lease was taken over stops rather than writing a checkpoint
    /// over the new owner's.
    ///
    /// A message the policy hides is not mentioned: it produces no event,
    /// no notification and no cache entry. The pass still advances the
    /// checkpoint, because the change was seen — it simply may not be
    /// disclosed.
    pub fn sync_once(
        &self,
        request: SyncRequest<'_>,
        source: &mut dyn ChangeSource,
        gate: &dyn DisclosureGate,
        events: &mut dyn EventSink,
        notifications: &mut dyn Notifier,
    ) -> QueueResult<SyncRun> {
        if !self.features.is_enabled(Feature::PersistentSync) {
            return Err(QueueError::FeatureDisabled(Feature::PersistentSync));
        }
        let lease = FencedLease::acquire(
            self.mailbox,
            &lease_name_for_sync(request.identity, request.mailbox.as_str()),
            request.owner,
            request.now,
            request.ttl,
        )?;
        lease.assert_current(self.mailbox, request.now, request.ttl)?;
        let checkpoint = self
            .mailbox
            .get_checkpoint(request.identity, request.mailbox.as_str())?;
        let cursor = checkpoint.as_ref().map(|c| c.upstream_cursor.clone());
        let generation = checkpoint.as_ref().map_or(0, |c| c.generation);
        let changes = source
            .changes_since(request.mailbox, cursor.as_deref())
            .map_err(|error| QueueError::Upstream(error.to_string()))?;
        let mut run = SyncRun {
            observed: changes.changes.len(),
            ..SyncRun::default()
        };
        for change in &changes.changes {
            let message = source
                .message(request.mailbox, &change.id)
                .map_err(|error| QueueError::Upstream(error.to_string()))?;
            let normalized = message.into_normalized();
            if gate.disclosure(&normalized) == Disclosure::Hidden {
                // The message must not be mentioned at all: no event, no
                // notification, no cached copy.
                run.suppressed += 1;
                continue;
            }
            let event = SyncEvent {
                identity: request.identity.to_owned(),
                mailbox: request.mailbox.as_str().to_owned(),
                message_id: self.public_id(request.identity, &change.id)?,
                kind: change.kind,
                observed_at: request.now,
            };
            events.publish(&event)?;
            notifications.notify(&event)?;
            run.published += 1;
            if self.cache.is_enabled() {
                let content = serde_json::to_vec(&normalized).map_err(|error| {
                    QueueError::Invalid(format!("the message is not serializable: {error}"))
                })?;
                self.cache
                    .store(request.identity, &event.message_id, &content, request.now)?;
                run.cached += 1;
            }
        }
        // The checkpoint is only moved forward by the worker that holds the
        // fence, and only when the checkpoint is still the one this pass
        // started from.
        if let Some(next) = &changes.next_cursor {
            let current = self
                .mailbox
                .get_checkpoint(request.identity, request.mailbox.as_str())?;
            let current_generation = current.as_ref().map_or(0, |c| c.generation);
            if current_generation != generation {
                return Err(QueueError::StaleFence(format!(
                    "the checkpoint of {} moved while the pass was running",
                    request.mailbox.as_str()
                )));
            }
            self.mailbox.put_checkpoint(&Checkpoint {
                identity: request.identity.to_owned(),
                mailbox: request.mailbox.as_str().to_owned(),
                upstream_cursor: next.token.clone(),
                generation: generation + 1,
                updated_at: request.now,
            })?;
            run.cursor = Some(next.token.clone());
        } else {
            run.cursor = cursor;
        }
        Ok(run)
    }

    /// The opaque identifier of a message.
    ///
    /// The upstream identifier never leaves the data plane, so the event
    /// carries an opaque identifier that the mailbox state store maps back
    /// to the upstream one for the identity that owns it.
    fn public_id(&self, identity: &str, upstream_id: &MessageId) -> QueueResult<String> {
        let public_id = hex::encode(mail_storage::crypto::random_bytes(16)?);
        self.mailbox.put_opaque_id(&OpaqueId {
            identity: identity.to_owned(),
            kind: OpaqueKind::Message,
            public_id: public_id.clone(),
            upstream_id: upstream_id.as_str().to_owned(),
        })?;
        Ok(public_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::EncryptedContentCache;
    use crate::config::CachePolicy;
    use mail_policy::{
        BooleanOp, DefaultVisibility, OnIndeterminate, Predicate, Rendering, Rule, RuleEffect,
        SubjectField, TextMatch, TextPredicate,
    };
    use mail_storage::{EncryptedDirectoryBlobStore, SqliteStore};

    #[derive(Debug)]
    struct ScriptedSource {
        changes: Vec<mail_core::Change>,
        messages: Vec<UntrustedMessage>,
    }

    impl ChangeSource for ScriptedSource {
        fn changes_since(
            &mut self,
            _mailbox: &MailboxRef,
            _cursor: Option<&str>,
        ) -> Result<ChangeSet, TransportError> {
            Ok(ChangeSet {
                changes: self.changes.clone(),
                next_cursor: Some(mail_core::ChangeCursor {
                    token: "cursor-2".to_owned(),
                }),
            })
        }

        fn message(
            &mut self,
            _mailbox: &MailboxRef,
            id: &MessageId,
        ) -> Result<UntrustedMessage, TransportError> {
            self.messages
                .iter()
                .find(|message| &message.id == id)
                .cloned()
                .ok_or(TransportError::NotFound)
        }
    }

    #[derive(Debug, Default)]
    struct RecordingSink {
        events: Vec<SyncEvent>,
    }

    impl EventSink for RecordingSink {
        fn publish(&mut self, event: &SyncEvent) -> QueueResult<()> {
            self.events.push(event.clone());
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct RecordingNotifier {
        events: Vec<SyncEvent>,
    }

    impl Notifier for RecordingNotifier {
        fn notify(&mut self, event: &SyncEvent) -> QueueResult<()> {
            self.events.push(event.clone());
            Ok(())
        }
    }

    fn hiding_policy() -> FilterPolicy {
        FilterPolicy {
            id: "hide-secret".to_owned(),
            default_visibility: DefaultVisibility::Show,
            on_indeterminate: OnIndeterminate::Hide,
            rendering: Rendering::default(),
            rules: vec![Rule {
                id: "hide-secret".to_owned(),
                predicate: Predicate::Boolean {
                    op: BooleanOp::All,
                    operands: vec![Predicate::Text(TextPredicate {
                        field: SubjectField::Subject,
                        comparison: TextMatch::Contains,
                        value: "secret".to_owned(),
                        case_insensitive: true,
                    })],
                },
                effect: RuleEffect::Visibility {
                    value: Visibility::Hide,
                },
            }],
        }
    }

    fn message(id: &str, subject: &str, body: &str) -> UntrustedMessage {
        UntrustedMessage {
            id: MessageId::new(id),
            mailbox: MailboxRef::new("INBOX"),
            from: None,
            reply_to: Vec::new(),
            to: Vec::new(),
            cc: Vec::new(),
            subject: Some(subject.to_owned()),
            text_body: Some(body.to_owned()),
            html_body: None,
            attachments: Vec::new(),
            flags: Vec::new(),
            date: None,
            provenance: Default::default(),
        }
    }

    fn cache(name: &str, enabled: bool) -> EncryptedContentCache<EncryptedDirectoryBlobStore> {
        let directory = std::env::temp_dir().join(format!("corvi-queue-sync-{name}"));
        let _ = std::fs::remove_dir_all(&directory);
        let blobs =
            EncryptedDirectoryBlobStore::open(directory, b"a wrapping key long enough").unwrap();
        let policy = if enabled {
            CachePolicy::enabled(600).unwrap()
        } else {
            CachePolicy::disabled()
        };
        EncryptedContentCache::new(blobs, policy)
    }

    #[test]
    fn a_hidden_change_produces_no_event_and_no_notification() {
        let store = SqliteStore::open_in_memory().unwrap();
        let cache = cache("hidden", false);
        let engine = SyncEngine::new(
            QueueFeatures::none().with_persistent_sync(true),
            &store,
            &cache,
        );
        let policy = hiding_policy();
        let gate = PolicyGate::new(&policy);
        let mut source = ScriptedSource {
            changes: vec![mail_core::Change {
                id: MessageId::new("m-1"),
                kind: ChangeKind::Added,
            }],
            messages: vec![message("m-1", "a secret subject", "the body")],
        };
        let mut events = RecordingSink::default();
        let mut notifications = RecordingNotifier::default();
        let run = engine
            .sync_once(
                SyncRequest {
                    identity: "alice@example.test",
                    mailbox: &MailboxRef::new("INBOX"),
                    owner: "worker",
                    now: 100,
                    ttl: 60,
                },
                &mut source,
                &gate,
                &mut events,
                &mut notifications,
            )
            .unwrap();
        assert_eq!(run.observed, 1);
        assert_eq!(run.suppressed, 1);
        assert_eq!(run.published, 0);
        assert!(events.events.is_empty());
        assert!(notifications.events.is_empty());
    }

    #[test]
    fn a_visible_change_is_published_and_notified() {
        let store = SqliteStore::open_in_memory().unwrap();
        let cache = cache("visible", false);
        let engine = SyncEngine::new(
            QueueFeatures::none().with_persistent_sync(true),
            &store,
            &cache,
        );
        let policy = hiding_policy();
        let gate = PolicyGate::new(&policy);
        let mut source = ScriptedSource {
            changes: vec![mail_core::Change {
                id: MessageId::new("m-2"),
                kind: ChangeKind::Added,
            }],
            messages: vec![message("m-2", "an ordinary subject", "the body")],
        };
        let mut events = RecordingSink::default();
        let mut notifications = RecordingNotifier::default();
        let run = engine
            .sync_once(
                SyncRequest {
                    identity: "alice@example.test",
                    mailbox: &MailboxRef::new("INBOX"),
                    owner: "worker",
                    now: 100,
                    ttl: 60,
                },
                &mut source,
                &gate,
                &mut events,
                &mut notifications,
            )
            .unwrap();
        assert_eq!(run.published, 1);
        assert_eq!(events.events.len(), 1);
        assert_eq!(notifications.events.len(), 1);
        assert_eq!(events.events[0].kind, ChangeKind::Added);
        assert_ne!(events.events[0].message_id, "m-2");
    }

    #[test]
    fn a_disabled_engine_refuses_to_synchronize() {
        let store = SqliteStore::open_in_memory().unwrap();
        let cache = cache("disabled", false);
        let engine = SyncEngine::new(QueueFeatures::none(), &store, &cache);
        let policy = hiding_policy();
        let gate = PolicyGate::new(&policy);
        let mut source = ScriptedSource {
            changes: Vec::new(),
            messages: Vec::new(),
        };
        let mut events = RecordingSink::default();
        let mut notifications = RecordingNotifier::default();
        let error = engine
            .sync_once(
                SyncRequest {
                    identity: "alice@example.test",
                    mailbox: &MailboxRef::new("INBOX"),
                    owner: "worker",
                    now: 100,
                    ttl: 60,
                },
                &mut source,
                &gate,
                &mut events,
                &mut notifications,
            )
            .unwrap_err();
        assert_eq!(error, QueueError::FeatureDisabled(Feature::PersistentSync));
    }
}
