use mail_admin::{
    Ack, MAX_SNAPSHOT_BYTES, PROTOCOL_VERSION, ProviderError, Snapshot, SnapshotStore,
    publication::digest_of,
};

/// A complete configuration document, in the shape the data plane validates.
const DOCUMENT: &str = "generation: 1\nlisten: 127.0.0.1:8080\nallow_loopback_plaintext: true\nidentities:\n  - id: alice\n    mailbox: account-a\n    address: alice@example.test\n    isolation: dedicated\n";

/// A document that parses but is not a complete snapshot: no identities.
const PARTIAL: &str =
    "generation: 1\nlisten: 127.0.0.1:8080\nallow_loopback_plaintext: true\nidentities: []\n";

fn document() -> Vec<u8> {
    DOCUMENT.as_bytes().to_vec()
}

#[test]
fn snapshot_publication_is_bounded_versioned_and_requires_matching_ack() {
    let mut store = SnapshotStore::new();
    let snapshot = Snapshot::new(1, PROTOCOL_VERSION, document()).unwrap();
    let digest = store.publish(snapshot.clone(), &snapshot.digest()).unwrap();
    assert_eq!(
        store.acknowledge(Ack {
            generation: 1,
            digest: "wrong".into()
        }),
        Err(ProviderError::AckMismatch)
    );
    store
        .acknowledge(Ack {
            generation: 1,
            digest: digest.clone(),
        })
        .unwrap();
    assert_eq!(store.active().unwrap(), &snapshot);
    assert!(Snapshot::new(2, PROTOCOL_VERSION, vec![0; MAX_SNAPSHOT_BYTES + 1]).is_err());
}

#[test]
fn a_publisher_digest_that_does_not_match_the_bytes_is_refused() {
    let mut store = SnapshotStore::new();
    let snapshot = Snapshot::new(1, PROTOCOL_VERSION, document()).unwrap();
    assert_eq!(
        store.publish(snapshot.clone(), "0000"),
        Err(ProviderError::DigestMismatch)
    );
    // Nothing was published, so nothing can be acknowledged into service.
    assert_eq!(
        store.acknowledge(Ack {
            generation: 1,
            digest: snapshot.digest(),
        }),
        Err(ProviderError::AckMismatch)
    );
    assert!(store.active().is_none());
}

#[test]
fn the_digest_is_the_published_sha256_of_the_document() {
    // The SHA-256 of "abc" is a fixed value in FIPS 180-4. A digest that
    // matches it is the one a conforming publisher computes.
    assert_eq!(
        digest_of(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    let digest = digest_of(&document());
    assert_eq!(digest.len(), 64);
    assert!(
        digest
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    );
    assert_ne!(digest, digest_of(b"other"));
}

#[test]
fn an_empty_snapshot_is_refused() {
    assert_eq!(
        Snapshot::new(1, PROTOCOL_VERSION, Vec::new()),
        Err(ProviderError::InvalidSnapshot)
    );
}

#[test]
fn a_partial_snapshot_is_refused() {
    assert_eq!(
        Snapshot::new(1, PROTOCOL_VERSION, PARTIAL.as_bytes().to_vec()),
        Err(ProviderError::InvalidSnapshot)
    );
}

#[test]
fn a_malformed_snapshot_is_refused() {
    assert_eq!(
        Snapshot::new(1, PROTOCOL_VERSION, b"not a snapshot".to_vec()),
        Err(ProviderError::InvalidSnapshot)
    );
}

#[test]
fn a_snapshot_whose_document_carries_another_generation_is_refused() {
    assert_eq!(
        Snapshot::new(7, PROTOCOL_VERSION, document()),
        Err(ProviderError::GenerationMismatch {
            published: 7,
            document: 1,
        })
    );
}

#[test]
fn a_zero_generation_is_refused() {
    assert_eq!(
        Snapshot::new(0, PROTOCOL_VERSION, document()),
        Err(ProviderError::InvalidSnapshot)
    );
}

#[test]
fn an_incompatible_version_is_refused() {
    assert_eq!(
        Snapshot::new(1, PROTOCOL_VERSION + 1, document()),
        Err(ProviderError::IncompatibleVersion)
    );
}

#[test]
fn outage_retains_last_acknowledged_snapshot() {
    let mut store = SnapshotStore::new();
    let first = Snapshot::new(1, PROTOCOL_VERSION, document()).unwrap();
    let digest = store.publish(first.clone(), &first.digest()).unwrap();
    store
        .acknowledge(Ack {
            generation: 1,
            digest,
        })
        .unwrap();
    let second = Snapshot::new(2, PROTOCOL_VERSION, b"generation: 2\nlisten: 127.0.0.1:8080\nallow_loopback_plaintext: true\nidentities:\n  - id: alice\n    mailbox: account-a\n    address: alice@example.test\n    isolation: dedicated\n".to_vec()).unwrap();
    assert!(store.publish(second.clone(), &second.digest()).is_ok());
    store.control_plane_outage();
    assert_eq!(store.active(), Some(&first));
}

#[test]
fn a_stale_generation_is_refused() {
    let mut store = SnapshotStore::new();
    let first = Snapshot::new(1, PROTOCOL_VERSION, document()).unwrap();
    store.publish(first.clone(), &first.digest()).unwrap();
    assert_eq!(
        store.publish(first.clone(), &first.digest()),
        Err(ProviderError::StaleGeneration)
    );
}
