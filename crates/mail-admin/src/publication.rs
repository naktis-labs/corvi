//! Configuration snapshot publication between the control plane and the data
//! plane.
//!
//! This is deliberately **not** the provider plugin surface. ADR-0001 places
//! provider plugins in third-party OCI images and keeps configuration
//! publication in the control plane, so a provider plugin can never publish
//! configuration and the two surfaces have separate packages on the wire
//! (`corvi.config.v1` and `corvi.provider.v1`).
//!
//! A publication is a three-step handshake: the control plane offers a
//! candidate together with the digest it computed, the store verifies that
//! digest against the candidate bytes and holds the candidate aside, and the
//! acknowledgement confirms the generation and digest. Only then does the
//! candidate become the active snapshot. The last acknowledged snapshot
//! survives a control-plane outage, so a failed publication never takes the
//! data plane's configuration away.

use crate::{MAX_SNAPSHOT_BYTES, PROTOCOL_VERSION, ProviderError};
use sha2::{Digest, Sha256};

/// A configuration snapshot candidate offered for publication.
///
/// The payload is the complete configuration document, and it is validated
/// before it can be offered at all: an empty or partial document never
/// reaches the publication channel, so there is only one snapshot lifecycle
/// and it is the validating one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    generation: u64,
    version: u32,
    payload: Vec<u8>,
}

impl Snapshot {
    /// Build a snapshot candidate from the bytes of a configuration document.
    ///
    /// The document is validated with the same validator the data plane
    /// applies when it activates a snapshot, so an incomplete document is
    /// refused here rather than after it has been published.
    pub fn new(generation: u64, version: u32, payload: Vec<u8>) -> Result<Self, ProviderError> {
        if generation == 0 {
            return Err(ProviderError::InvalidSnapshot);
        }
        if payload.len() > MAX_SNAPSHOT_BYTES {
            return Err(ProviderError::SnapshotTooLarge);
        }
        if version != PROTOCOL_VERSION {
            return Err(ProviderError::IncompatibleVersion);
        }
        validate_document(generation, &payload)?;
        Ok(Self {
            generation,
            version,
            payload,
        })
    }

    /// The generation this candidate would activate as.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// The contract version of the candidate.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// The configuration document bytes.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// The digest the publisher states and the acknowledgement echoes.
    pub fn digest(&self) -> String {
        digest_of(&self.payload)
    }
}

/// The digest of a configuration document: lowercase hex SHA-256.
///
/// The publication channel carries this value between the control plane and
/// the store, so it has to detect corruption rather than merely distinguish
/// documents. A 64-bit non-cryptographic digest would not.
pub fn digest_of(payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(payload);
    hex::encode(hasher.finalize())
}

/// Validate a configuration document against the data plane's own validator.
///
/// The document is the provider-neutral snapshot defined by `mail-config`. A
/// document that is empty, malformed, partial or that carries another
/// generation is refused.
fn validate_document(generation: u64, payload: &[u8]) -> Result<(), ProviderError> {
    let text = std::str::from_utf8(payload).map_err(|_| ProviderError::InvalidSnapshot)?;
    let candidate =
        mail_config::Snapshot::from_yaml(text).map_err(|_| ProviderError::InvalidSnapshot)?;
    let store =
        mail_config::SnapshotStore::new(candidate).map_err(|_| ProviderError::InvalidSnapshot)?;
    let document_generation = store.active().generation();
    if document_generation != generation {
        return Err(ProviderError::GenerationMismatch {
            published: generation,
            document: document_generation,
        });
    }
    Ok(())
}

/// The acknowledgement of a published snapshot.
///
/// The acknowledgement names the generation and the digest of the candidate
/// that was published. Anything else is refused, and the candidate stays
/// pending rather than being activated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ack {
    pub generation: u64,
    pub digest: String,
}

/// The publication handshake of the control-plane configuration service.
///
/// The store holds at most one pending candidate and the last acknowledged
/// snapshot. It never activates a candidate that was not acknowledged, and a
/// publication failure leaves the acknowledged snapshot in service.
#[derive(Debug, Default)]
pub struct SnapshotStore {
    pending: Option<(Snapshot, String)>,
    active: Option<Snapshot>,
}

impl SnapshotStore {
    /// A store with no snapshot in service.
    pub fn new() -> Self {
        Self::default()
    }

    /// Offer a candidate for publication.
    ///
    /// The publisher states the digest it computed over the document bytes.
    /// The store recomputes the digest and refuses a mismatch instead of
    /// publishing a candidate whose acknowledgement the publisher could not
    /// produce. The returned digest is the one the acknowledgement must
    /// carry.
    pub fn publish(
        &mut self,
        snapshot: Snapshot,
        publisher_digest: &str,
    ) -> Result<String, ProviderError> {
        if self
            .active
            .as_ref()
            .is_some_and(|active| snapshot.generation <= active.generation)
            || self
                .pending
                .as_ref()
                .is_some_and(|(pending, _)| snapshot.generation <= pending.generation)
        {
            return Err(ProviderError::StaleGeneration);
        }
        let digest = snapshot.digest();
        if publisher_digest != digest {
            return Err(ProviderError::DigestMismatch);
        }
        self.pending = Some((snapshot, digest.clone()));
        Ok(digest)
    }

    /// Acknowledge a published candidate.
    ///
    /// The candidate becomes the active snapshot only when the generation and
    /// the digest match the pending publication.
    pub fn acknowledge(&mut self, ack: Ack) -> Result<(), ProviderError> {
        let (snapshot, digest) = self.pending.take().ok_or(ProviderError::AckMismatch)?;
        if ack.generation != snapshot.generation || ack.digest != digest {
            self.pending = Some((snapshot, digest));
            return Err(ProviderError::AckMismatch);
        }
        self.active = Some(snapshot);
        Ok(())
    }

    /// A control-plane outage leaves the acknowledged immutable snapshot active.
    pub fn control_plane_outage(&mut self) {
        self.pending = None;
    }

    /// The snapshot currently in service.
    pub fn active(&self) -> Option<&Snapshot> {
        self.active.as_ref()
    }
}
