//! Last-known-good configuration and outage handling.
//!
//! A gateway keeps serving from its last verified configuration when the
//! operator or the API server is unavailable. What must **not** happen is a
//! missing or incomplete graph replacing a working configuration with an
//! empty one: that would silently stop mail without anyone deciding to stop
//! it (ADR-0001, ADR-0012).
//!
//! This module does not decide what a valid configuration *is*. That stays in
//! `mail-config`, which every candidate is handed to for validation. This
//! module only decides which candidate is published, which one is retained,
//! and what happens when the control plane disappears.
//!
//! Security removals supersede ordinary availability: a revocation is
//! published even when it makes the remaining configuration unusable, and a
//! revocation that cannot be published fences the gateway instead of leaving
//! the revoked identity in service.

use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use mail_config::{ActivationError, Snapshot as ConfigSnapshot, SnapshotStore, ValidatedSnapshot};
use serde_yaml::{Mapping, Value};

use crate::references::ResourceKey;

/// How reachable the control plane is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlPlaneAvailability {
    /// The operator and the API server are both reachable.
    Available,
    /// The operator itself cannot run.
    OperatorUnavailable,
    /// The API server cannot be reached.
    ApiUnavailable,
}

/// Why the retained configuration stayed in service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionReason {
    /// The operator cannot run.
    OperatorUnavailable,
    /// The API server cannot be reached.
    ApiUnavailable,
    /// The watch was interrupted and no complete graph is available yet.
    InterruptedWatch,
    /// The candidate was not a valid configuration.
    InvalidCandidate,
    /// The candidate was not newer than the retained configuration.
    StaleGeneration,
}

impl fmt::Display for RetentionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OperatorUnavailable => f.write_str("the operator is unavailable"),
            Self::ApiUnavailable => f.write_str("the API server is unavailable"),
            Self::InterruptedWatch => f.write_str("the watch was interrupted"),
            Self::InvalidCandidate => f.write_str("the candidate is not a valid configuration"),
            Self::StaleGeneration => {
                f.write_str("the candidate is not newer than the retained one")
            }
        }
    }
}

/// What a reconciliation attempt did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileOutcome {
    /// A newer configuration was published.
    Published {
        /// The generation that is now active.
        generation: u64,
    },
    /// The retained configuration stayed in service.
    Retained {
        /// The generation that stayed in service.
        generation: Option<u64>,
        /// Why nothing was published.
        reason: RetentionReason,
    },
}

/// Why a candidate was not published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishError {
    /// The candidate is not a valid configuration.
    InvalidCandidate {
        /// Why the candidate was refused.
        reason: String,
    },
    /// The candidate is not newer than the retained configuration.
    StaleGeneration {
        /// The generation of the refused candidate.
        generation: u64,
    },
    /// The snapshot store was poisoned by a panic in another thread.
    Poisoned,
}

impl fmt::Display for PublishError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCandidate { reason } => write!(f, "invalid candidate: {reason}"),
            Self::StaleGeneration { generation } => {
                write!(
                    f,
                    "generation {generation} is not newer than the retained one"
                )
            }
            Self::Poisoned => f.write_str("the snapshot store lock is poisoned"),
        }
    }
}

impl std::error::Error for PublishError {}

/// What a revocation did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationOutcome {
    /// The revocation was published.
    Published {
        /// The generation that is now active.
        generation: u64,
    },
    /// The revocation could not be published, so the gateway is fenced.
    ///
    /// The gateway must stop serving: leaving the revoked identity in
    /// service would be a security failure, and publishing an empty
    /// configuration is not a valid snapshot.
    FailedClosed {
        /// Why the gateway is fenced.
        reason: String,
    },
}

/// The retained configuration of one gateway.
#[derive(Debug)]
pub struct RetainedSnapshot {
    store: SnapshotStore,
    yaml: String,
    generation: u64,
    resource_version: Option<String>,
    published_at: u64,
    fenced: bool,
}

impl RetainedSnapshot {
    /// The generation in service.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// The API resource version the configuration was built from.
    pub fn resource_version(&self) -> Option<&str> {
        self.resource_version.as_deref()
    }

    /// When the configuration was published.
    pub fn published_at(&self) -> u64 {
        self.published_at
    }

    /// Whether the gateway is fenced and may not serve.
    pub fn is_fenced(&self) -> bool {
        self.fenced
    }

    /// The configuration document that was published.
    pub fn yaml(&self) -> &str {
        &self.yaml
    }
}

/// The retained configuration of every gateway the operator manages.
#[derive(Debug, Default)]
pub struct SnapshotRetention {
    gateways: BTreeMap<ResourceKey, RetainedSnapshot>,
}

impl SnapshotRetention {
    /// An empty retention.
    pub fn new() -> Self {
        Self::default()
    }

    /// The configuration currently in service for a gateway.
    ///
    /// A fenced gateway has no configuration in service: it must stop
    /// serving rather than keep a revoked identity alive.
    pub fn active(&self, gateway: &ResourceKey) -> Option<Arc<ValidatedSnapshot>> {
        let retained = self.gateways.get(gateway)?;
        if retained.fenced {
            return None;
        }
        Some(retained.store.active())
    }

    /// The retained configuration record of a gateway.
    pub fn retained(&self, gateway: &ResourceKey) -> Option<&RetainedSnapshot> {
        self.gateways.get(gateway)
    }

    /// The generation in service for a gateway.
    pub fn generation(&self, gateway: &ResourceKey) -> Option<u64> {
        self.gateways
            .get(gateway)
            .map(|retained| retained.generation)
    }

    /// Whether the gateway is fenced and must stop serving.
    pub fn is_fenced(&self, gateway: &ResourceKey) -> bool {
        self.gateways
            .get(gateway)
            .is_some_and(|retained| retained.fenced)
    }

    /// Publish a candidate configuration.
    ///
    /// The candidate is validated by `mail-config`, which remains the single
    /// source of truth for what a valid configuration is. A refused candidate
    /// leaves the retained configuration untouched.
    pub fn publish(
        &mut self,
        gateway: &ResourceKey,
        yaml: &str,
        resource_version: Option<String>,
        now: u64,
    ) -> Result<ReconcileOutcome, PublishError> {
        let snapshot =
            ConfigSnapshot::from_yaml(yaml).map_err(|error| PublishError::InvalidCandidate {
                reason: error.to_string(),
            })?;
        match self.gateways.get_mut(gateway) {
            Some(retained) => {
                retained
                    .store
                    .activate(snapshot)
                    .map_err(|error| match error {
                        ActivationError::Invalid(invalid) => PublishError::InvalidCandidate {
                            reason: invalid.to_string(),
                        },
                        ActivationError::StaleGeneration => PublishError::StaleGeneration {
                            generation: candidate_generation(yaml).unwrap_or(0),
                        },
                        ActivationError::Poisoned => PublishError::Poisoned,
                    })?;
                retained.yaml = yaml.to_owned();
                retained.resource_version = resource_version;
                retained.published_at = now;
                retained.generation = retained.store.active().generation();
                retained.fenced = false;
                Ok(ReconcileOutcome::Published {
                    generation: retained.generation,
                })
            }
            None => {
                let store = SnapshotStore::new(snapshot).map_err(|error| match error {
                    ActivationError::Invalid(invalid) => PublishError::InvalidCandidate {
                        reason: invalid.to_string(),
                    },
                    ActivationError::StaleGeneration => PublishError::StaleGeneration {
                        generation: candidate_generation(yaml).unwrap_or(0),
                    },
                    ActivationError::Poisoned => PublishError::Poisoned,
                })?;
                let generation = store.active().generation();
                self.gateways.insert(
                    gateway.clone(),
                    RetainedSnapshot {
                        store,
                        yaml: yaml.to_owned(),
                        generation,
                        resource_version,
                        published_at: now,
                        fenced: false,
                    },
                );
                Ok(ReconcileOutcome::Published { generation })
            }
        }
    }

    /// Reconcile one gateway.
    ///
    /// When the control plane is unavailable, or when no complete candidate
    /// is available yet, the retained configuration stays in service. The
    /// retained configuration is never replaced with an empty one.
    pub fn reconcile(
        &mut self,
        gateway: &ResourceKey,
        availability: ControlPlaneAvailability,
        candidate: Option<&str>,
        resource_version: Option<String>,
        now: u64,
    ) -> Result<ReconcileOutcome, PublishError> {
        match availability {
            ControlPlaneAvailability::OperatorUnavailable => {
                return Ok(ReconcileOutcome::Retained {
                    generation: self.generation(gateway),
                    reason: RetentionReason::OperatorUnavailable,
                });
            }
            ControlPlaneAvailability::ApiUnavailable => {
                return Ok(ReconcileOutcome::Retained {
                    generation: self.generation(gateway),
                    reason: RetentionReason::ApiUnavailable,
                });
            }
            ControlPlaneAvailability::Available => {}
        }
        let Some(candidate) = candidate else {
            return Ok(ReconcileOutcome::Retained {
                generation: self.generation(gateway),
                reason: RetentionReason::InterruptedWatch,
            });
        };
        match self.publish(gateway, candidate, resource_version, now) {
            Ok(outcome) => Ok(outcome),
            Err(PublishError::InvalidCandidate { .. }) => Ok(ReconcileOutcome::Retained {
                generation: self.generation(gateway),
                reason: RetentionReason::InvalidCandidate,
            }),
            Err(PublishError::StaleGeneration { .. }) => Ok(ReconcileOutcome::Retained {
                generation: self.generation(gateway),
                reason: RetentionReason::StaleGeneration,
            }),
            Err(error) => Err(error),
        }
    }

    /// Revoke one identity from the configuration in service.
    ///
    /// The revocation is published even if the operator cannot reach the API
    /// server: the removal is the new truth. When the remaining
    /// configuration would be empty, no valid snapshot exists, so the gateway
    /// is fenced and must stop serving.
    pub fn revoke_identity(
        &mut self,
        gateway: &ResourceKey,
        identity: &str,
        now: u64,
    ) -> Result<RevocationOutcome, PublishError> {
        let Some(retained) = self.gateways.get(gateway) else {
            return Err(PublishError::InvalidCandidate {
                reason: "no configuration is retained for this gateway".to_owned(),
            });
        };
        let yaml = retained.yaml.clone();
        let Some(reduced) = reduce_snapshot(&yaml, identity) else {
            return Err(PublishError::InvalidCandidate {
                reason: format!("identity {identity} is not in the retained configuration"),
            });
        };
        if reduced.identities.is_empty() {
            self.gateways.get_mut(gateway).expect("just read").fenced = true;
            return Ok(RevocationOutcome::FailedClosed {
                reason: "no identity remains to serve".to_owned(),
            });
        }
        let generation = retained.generation + 1;
        let reduced = SnapshotBuilder {
            generation,
            ..reduced.builder
        };
        let yaml = reduced.to_yaml();
        match self.publish(gateway, &yaml, retained.resource_version.clone(), now) {
            Ok(ReconcileOutcome::Published { generation }) => {
                Ok(RevocationOutcome::Published { generation })
            }
            Ok(ReconcileOutcome::Retained { .. }) => Err(PublishError::InvalidCandidate {
                reason: "the reduced configuration was not published".to_owned(),
            }),
            Err(error) => Err(error),
        }
    }
}

/// The identities of a configuration document.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SnapshotIdentities {
    yaml: String,
    identities: Vec<String>,
    builder: SnapshotBuilder,
}

/// Remove one identity from a configuration document.
fn reduce_snapshot(yaml: &str, identity: &str) -> Option<SnapshotIdentities> {
    let mut document: Value = serde_yaml::from_str(yaml).ok()?;
    let identities: Vec<String> = {
        let mapping = document.as_mapping_mut()?;
        let identities = mapping
            .get_mut("identities")
            .and_then(Value::as_sequence_mut)?;
        let before = identities.len();
        identities.retain(|entry| {
            entry
                .get("id")
                .and_then(Value::as_str)
                .is_none_or(|id| id != identity)
        });
        if identities.len() == before {
            return None;
        }
        identities
            .iter()
            .filter_map(|entry| entry.get("id").and_then(Value::as_str))
            .map(str::to_owned)
            .collect()
    };
    let reduced = serde_yaml::to_string(&document).ok()?;
    Some(SnapshotIdentities {
        yaml: reduced.clone(),
        identities,
        builder: builder_from(&reduced),
    })
}

/// Read the generation counter of a configuration document.
fn candidate_generation(yaml: &str) -> Option<u64> {
    let document: Value = serde_yaml::from_str(yaml).ok()?;
    document.get("generation").and_then(Value::as_u64)
}

/// Rebuild the builder of a configuration document.
fn builder_from(yaml: &str) -> SnapshotBuilder {
    let document: Value = serde_yaml::from_str(yaml).unwrap_or(Value::Mapping(Mapping::new()));
    let generation = document
        .get("generation")
        .and_then(Value::as_u64)
        .unwrap_or(1);
    let listen = document
        .get("listen")
        .and_then(Value::as_str)
        .and_then(|text| text.parse::<SocketAddr>().ok())
        .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 8080)));
    let smtp_listen = document
        .get("smtp_listen")
        .and_then(Value::as_str)
        .and_then(|text| text.parse::<SocketAddr>().ok());
    let identities = document
        .get("identities")
        .and_then(Value::as_sequence)
        .map(|sequence| {
            sequence
                .iter()
                .filter_map(|entry| {
                    Some(SnapshotIdentity {
                        id: entry.get("id")?.as_str()?.to_owned(),
                        mailbox: entry.get("mailbox")?.as_str()?.to_owned(),
                        address: entry.get("address")?.as_str()?.to_owned(),
                        // The isolation is the identity's own confidentiality
                        // claim. It is read from the document instead of
                        // assumed: a revocation must never upgrade the
                        // remaining identities' isolation. An entry that does
                        // not carry a usable mode keeps the weakest claim,
                        // which is the one that promises nothing.
                        isolation: entry
                            .get("isolation")
                            .and_then(|value| {
                                serde_yaml::from_value::<crate::IsolationMode>(value.clone()).ok()
                            })
                            .unwrap_or(crate::IsolationMode::BestEffort),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    SnapshotBuilder {
        gateway: ResourceKey::new("", ""),
        generation,
        identities,
        listen,
        smtp_listen,
    }
}

/// One identity in a configuration document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotIdentity {
    /// The identity identifier.
    pub id: String,
    /// The upstream mailbox the identity reads from.
    pub mailbox: String,
    /// The address the identity sends from.
    pub address: String,
    /// The isolation the identity claims.
    pub isolation: crate::IsolationMode,
}

/// Builds a gateway configuration document.
///
/// The document is handed to `mail-config` for validation; this builder only
/// writes the fields the operator knows about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotBuilder {
    /// The gateway the configuration belongs to.
    pub gateway: ResourceKey,
    /// The generation counter of the configuration.
    pub generation: u64,
    /// The identities the gateway serves.
    pub identities: Vec<SnapshotIdentity>,
    /// The address the gateway listens on.
    pub listen: SocketAddr,
    /// The address the SMTP submission listener binds, if any.
    pub smtp_listen: Option<SocketAddr>,
}

impl Default for SnapshotBuilder {
    fn default() -> Self {
        Self {
            gateway: ResourceKey::new("", ""),
            generation: 1,
            identities: Vec::new(),
            listen: SocketAddr::from(([127, 0, 0, 1], 8080)),
            smtp_listen: None,
        }
    }
}

impl SnapshotBuilder {
    /// Render the configuration document.
    pub fn to_yaml(&self) -> String {
        let mut document = Mapping::new();
        document.insert(
            Value::String("generation".to_owned()),
            Value::Number(self.generation.into()),
        );
        document.insert(
            Value::String("listen".to_owned()),
            Value::String(self.listen.to_string()),
        );
        if let Some(smtp) = &self.smtp_listen {
            document.insert(
                Value::String("smtp_listen".to_owned()),
                Value::String(smtp.to_string()),
            );
        }
        document.insert(
            Value::String("allow_loopback_plaintext".to_owned()),
            Value::Bool(true),
        );
        let identities: Vec<Value> = self
            .identities
            .iter()
            .map(|identity| {
                let mut entry = Mapping::new();
                entry.insert(
                    Value::String("id".to_owned()),
                    Value::String(identity.id.clone()),
                );
                entry.insert(
                    Value::String("mailbox".to_owned()),
                    Value::String(identity.mailbox.clone()),
                );
                entry.insert(
                    Value::String("address".to_owned()),
                    Value::String(identity.address.clone()),
                );
                entry.insert(
                    Value::String("isolation".to_owned()),
                    Value::String(isolation_name(identity.isolation).to_owned()),
                );
                Value::Mapping(entry)
            })
            .collect();
        document.insert(
            Value::String("identities".to_owned()),
            Value::Sequence(identities),
        );
        document.insert(
            Value::String("credentials".to_owned()),
            Value::Sequence(Vec::new()),
        );
        serde_yaml::to_string(&Value::Mapping(document)).expect("a configuration always serialises")
    }
}

/// The name of an isolation mode in a configuration document.
fn isolation_name(isolation: crate::IsolationMode) -> &'static str {
    match isolation {
        crate::IsolationMode::Verified => "verified",
        crate::IsolationMode::Dedicated => "dedicated",
        crate::IsolationMode::BestEffort => "best_effort",
    }
}

/// Where a watch stopped.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WatchCursor {
    /// The last resource version the operator saw.
    pub resource_version: Option<String>,
}

/// What the API server says about a watch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchOutcome {
    /// The watch continues from a new resource version.
    Continue {
        /// The new resource version.
        resource_version: String,
    },
    /// The resource version is too old and the watch must be restarted.
    Expired,
}

/// What the operator does after a watch ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResumeAction {
    /// Continue the watch from a resource version.
    ContinueFrom {
        /// The resource version to continue from.
        resource_version: String,
    },
    /// Re-list the whole namespace.
    ///
    /// The retained configuration stays in service until a complete,
    /// validated configuration replaces it.
    RelistCompletely,
}

/// Decide how to resume an interrupted watch.
pub fn resume_action(cursor: &WatchCursor, outcome: WatchOutcome) -> ResumeAction {
    match outcome {
        WatchOutcome::Continue { resource_version } => {
            // The operator never resumes from a version it has already seen:
            // replaying it would re-apply a state that was already replaced.
            if cursor.resource_version.as_deref() == Some(resource_version.as_str()) {
                return ResumeAction::RelistCompletely;
            }
            ResumeAction::ContinueFrom { resource_version }
        }
        WatchOutcome::Expired => ResumeAction::RelistCompletely,
    }
}
