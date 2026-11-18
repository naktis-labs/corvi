use mail_admin::publication::Ack;
use mail_admin::{
    AuthenticatedPeer, BoundedPayload, Capabilities, Deadline, MAX_EXECUTE_PAYLOAD_BYTES,
    Operation, PROTOCOL_VERSION, ProtocolSelection, ProviderError, ProviderStatus, ReadProtocol,
    SecretRef, SubmissionProtocol,
};
use std::time::Duration;

#[test]
fn read_and_submission_protocols_are_independent() {
    let selection = ProtocolSelection::new("jmap", "smtp").unwrap();
    assert_eq!(selection.read(), ReadProtocol::Jmap);
    assert_eq!(selection.submission(), SubmissionProtocol::Smtp);
    assert_eq!(selection.wire(), ("jmap", "smtp"));
}

#[test]
fn the_read_dimension_accepts_only_imap_and_jmap() {
    assert_eq!(
        ProtocolSelection::new("smtp", "smtp"),
        Err(ProviderError::InvalidProtocolSelection)
    );
    assert_eq!(
        ProtocolSelection::new("disabled", "smtp"),
        Err(ProviderError::InvalidProtocolSelection)
    );
}

#[test]
fn the_submission_dimension_accepts_only_smtp_jmap_and_disabled() {
    assert_eq!(
        ProtocolSelection::new("imap", "imap"),
        Err(ProviderError::InvalidProtocolSelection)
    );
    let disabled = ProtocolSelection::new("imap", "disabled").unwrap();
    assert_eq!(disabled.submission(), SubmissionProtocol::Disabled);
}

#[test]
fn unsupported_operations_are_typed_and_never_implied() {
    let caps = Capabilities::new([]);
    assert_eq!(
        caps.require(Operation::ListDomains),
        Err(ProviderError::Unsupported(Operation::ListDomains))
    );
}

#[test]
fn destructive_operations_are_not_in_the_advertised_vocabulary() {
    // The contract has no delete operation at all, so no capability set can
    // imply support for one and no wire name can name one.
    assert!(
        !Operation::ALL
            .iter()
            .any(|operation| operation.as_wire().starts_with("delete_"))
    );
    assert!(matches!(
        Operation::from_wire("delete_domain"),
        Err(ProviderError::UnsupportedOperation { .. })
    ));
    assert!(matches!(
        Operation::from_wire("delete_mailbox"),
        Err(ProviderError::UnsupportedOperation { .. })
    ));
}

#[test]
fn operation_names_round_trip_through_the_wire_form() {
    for operation in Operation::ALL {
        assert_eq!(Operation::from_wire(operation.as_wire()), Ok(operation));
    }
    assert!(matches!(
        Operation::from_wire("list_nothing"),
        Err(ProviderError::UnsupportedOperation { .. })
    ));
}

#[test]
fn capabilities_carry_the_protocol_dimensions() {
    let caps = Capabilities::new([Operation::ListDomains])
        .with_protocols([ReadProtocol::Imap], [SubmissionProtocol::Smtp]);
    assert!(caps.supports_read(ReadProtocol::Imap));
    assert!(!caps.supports_read(ReadProtocol::Jmap));
    assert_eq!(
        caps.require_read(ReadProtocol::Jmap),
        Err(ProviderError::ProtocolNotAdvertised {
            protocol: "jmap".into()
        })
    );
    assert!(caps.supports_submission(SubmissionProtocol::Smtp));
    assert!(!caps.supports_submission(SubmissionProtocol::Jmap));
}

#[test]
fn disabling_submission_is_always_permitted() {
    let caps = Capabilities::new([Operation::ListDomains]);
    assert!(caps.supports_submission(SubmissionProtocol::Disabled));
    assert_eq!(
        caps.require_submission(SubmissionProtocol::Disabled),
        Ok(())
    );
}

#[test]
fn capabilities_round_trip_through_the_wire_form() {
    let caps = Capabilities::new([Operation::ListDomains, Operation::GetUsage])
        .with_protocols([ReadProtocol::Jmap], [SubmissionProtocol::Jmap]);
    let parsed = Capabilities::from_wire(
        &caps.wire_operations(),
        &caps.wire_read_protocols(),
        &caps.wire_submission_protocols(),
    )
    .unwrap();
    assert_eq!(parsed, caps);
    assert_eq!(parsed.wire_operations(), vec!["list_domains", "get_usage"]);
}

#[test]
fn an_unknown_advertised_capability_is_refused() {
    assert!(matches!(
        Capabilities::from_wire(&["teleport_domain"], &[], &[]),
        Err(ProviderError::UnsupportedOperation { .. })
    ));
    assert!(matches!(
        Capabilities::from_wire(&[], &["pop3"], &[]),
        Err(ProviderError::InvalidCapability { .. })
    ));
    assert!(matches!(
        Capabilities::from_wire(&[], &[], &["disabled"]),
        Err(ProviderError::InvalidCapability { .. })
    ));
}

#[test]
fn secret_references_are_opaque_untrusted_identifiers() {
    assert_eq!(
        SecretRef::new("namespace/name").unwrap().as_str(),
        "namespace/name"
    );
    assert!(SecretRef::new("https://attacker.invalid/token").is_err());
}

#[test]
fn secret_references_reject_dot_segments() {
    assert_eq!(
        SecretRef::new("../name"),
        Err(ProviderError::InvalidSecretRef)
    );
    assert_eq!(
        SecretRef::new("ns/.."),
        Err(ProviderError::InvalidSecretRef)
    );
    assert_eq!(SecretRef::new("."), Err(ProviderError::InvalidSecretRef));
    assert_eq!(SecretRef::new("ns/."), Err(ProviderError::InvalidSecretRef));
    assert_eq!(
        SecretRef::new("ns/name/extra"),
        Err(ProviderError::InvalidSecretRef)
    );
}

#[test]
fn request_payloads_are_bounded() {
    let payload = BoundedPayload::new(vec![0; MAX_EXECUTE_PAYLOAD_BYTES]).unwrap();
    assert_eq!(payload.len(), MAX_EXECUTE_PAYLOAD_BYTES);
    assert!(BoundedPayload::new(vec![0; MAX_EXECUTE_PAYLOAD_BYTES + 1]).is_err());
}

#[test]
fn the_status_vocabulary_is_closed() {
    for status in ProviderStatus::ALL {
        assert_eq!(ProviderStatus::from_wire(status.as_wire()), Ok(status));
    }
    assert!(matches!(
        ProviderStatus::from_wire("probably_fine"),
        Err(ProviderError::InvalidStatus { .. })
    ));
}

#[test]
fn rpc_peer_identity_and_contract_version_are_authenticated() {
    let peer = AuthenticatedPeer {
        identity: "spiffe://corvi/operator".into(),
        contract_version: PROTOCOL_VERSION,
    };
    assert!(
        peer.validate("spiffe://corvi/operator", PROTOCOL_VERSION)
            .is_ok()
    );
    assert!(
        peer.validate("spiffe://corvi/other", PROTOCOL_VERSION)
            .is_err()
    );
    assert!(
        peer.validate("spiffe://corvi/operator", PROTOCOL_VERSION + 1)
            .is_err()
    );
}

#[test]
fn an_identity_mismatch_is_a_peer_error_not_a_snapshot_error() {
    let peer = AuthenticatedPeer {
        identity: "spiffe://corvi/other".into(),
        contract_version: PROTOCOL_VERSION,
    };
    let error = peer
        .validate("spiffe://corvi/operator", PROTOCOL_VERSION)
        .expect_err("a mismatched peer must be refused");
    assert_eq!(
        error,
        ProviderError::PeerMismatch {
            expected: "spiffe://corvi/operator".into(),
            actual: "spiffe://corvi/other".into(),
        }
    );
    assert!(
        !matches!(error, ProviderError::InvalidSnapshot),
        "a caller that retries an invalid snapshot would loop forever"
    );
    assert!(!error.is_retryable());
}

#[test]
fn every_provider_call_carries_a_deadline() {
    let deadline = Deadline::after(Duration::from_secs(30));
    assert!(!deadline.expired());
    assert!(deadline.remaining().is_some());
    let expired = Deadline::after(Duration::ZERO);
    assert!(expired.expired());
    assert_eq!(expired.remaining(), None);
}

#[test]
fn a_deadline_beyond_the_clock_horizon_saturates_instead_of_panicking() {
    // A caller that computes a deadline from a malformed or absurd budget
    // must get the farthest representable deadline, not a panic on the
    // request path.
    let deadline = Deadline::after(Duration::MAX);
    assert!(!deadline.expired());
    assert!(deadline.remaining().is_some());
}

#[test]
fn incompatible_contract_versions_are_rejected() {
    assert_eq!(
        mail_admin::publication::Snapshot::new(1, PROTOCOL_VERSION + 1, b"document".to_vec()),
        Err(ProviderError::IncompatibleVersion)
    );
}

#[test]
fn an_acknowledgement_without_a_publication_is_refused() {
    let mut store = mail_admin::publication::SnapshotStore::new();
    assert_eq!(
        store.acknowledge(Ack {
            generation: 1,
            digest: "whatever".into(),
        }),
        Err(ProviderError::AckMismatch)
    );
}
