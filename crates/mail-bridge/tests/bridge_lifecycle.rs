//! Bridge lifecycle: readiness before publication, failure isolation and the
//! independence of already installed bridges (ADR-0006 sections 4 and 7).

use mail_bridge::descriptor::{BridgeDescriptor, BridgeProtocol, Placement, SecretClass};
use mail_bridge::lifecycle::{
    AuthenticatedCapabilities, BridgeEndpoint, BridgeSupervisor, EndpointAddress, LifecycleError,
    MailboxStatus,
};
use mail_bridge::trust::{InstallPolicy, authorize};
use serde_json::json;

const DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";

fn descriptor_json() -> serde_json::Value {
    json!({
        "apiVersion": "corvi.naktis.eu/v1alpha1",
        "kind": "ProviderTransportDependency",
        "transport": {
            "topology": "localBridge",
            "protocols": ["imap", "smtp"],
            "runtime": {
                "mode": "managed",
                "image": format!("ghcr.io/naktis-labs/corvi-proton-bridge@sha256:{DIGEST}"),
                "placement": "colocatedNetworkNamespace",
                "state": { "persistent": true, "accountScope": "perPhysicalMailbox" },
                "endpoint": {
                    "exposure": "loopbackOnly",
                    "imap": { "host": "127.0.0.1", "port": 1143 },
                    "smtp": { "host": "127.0.0.1", "port": 1025 }
                },
                "readiness": { "type": "protocolHandshake" }
            },
            "onboarding": { "method": "interactiveOrPreprovisioned", "automationSupported": "unknown" },
            "secretInputs": [ { "name": "accountSession", "class": "bridgeSession" } ],
            "tls": { "peerVerification": "pinnedCertificateOrTrustedCA" }
        }
    })
}

fn approved() -> mail_bridge::trust::ApprovedBridge {
    let descriptor = BridgeDescriptor::from_json(&descriptor_json()).expect("a valid descriptor");
    let policy = InstallPolicy {
        allowed_repositories: vec!["ghcr.io/naktis-labs/corvi-proton-bridge".to_string()],
        allowed_digests: Vec::new(),
        allowed_secret_classes: vec![SecretClass::BridgeSession],
        allowed_placements: vec![Placement::ColocatedNetworkNamespace],
        max_secret_inputs: 2,
    };
    authorize(&descriptor, &policy).expect("the descriptor is approved")
}

fn capabilities(digest: &str) -> AuthenticatedCapabilities {
    AuthenticatedCapabilities {
        image_digest: format!("sha256:{digest}"),
        runtime_id: "corvi-proton-bridge".to_string(),
        protocol_version: "corvi.bridge.v1".to_string(),
    }
}

fn endpoint() -> BridgeEndpoint {
    BridgeEndpoint {
        imap: Some(EndpointAddress {
            host: "127.0.0.1".to_string(),
            port: 1143,
        }),
        smtp: Some(EndpointAddress {
            host: "127.0.0.1".to_string(),
            port: 1025,
        }),
        tls_peer: "spiffe://corvi/bridge/proton".to_string(),
    }
}

#[test]
fn an_endpoint_may_not_be_published_before_the_bridge_is_ready() {
    let mut supervisor = BridgeSupervisor::new();
    let approved = approved();
    let bridge = supervisor
        .provision_managed("proton-personal", &approved, &capabilities(DIGEST))
        .expect("the bridge is provisioned");

    let error = supervisor
        .publish(&bridge)
        .expect_err("publication waits for readiness");
    assert!(
        matches!(error, LifecycleError::NotReady),
        "unexpected error: {error:?}"
    );

    assert!(supervisor.snapshot().endpoints.is_empty());

    supervisor
        .mark_ready(&bridge, endpoint())
        .expect("the bridge reports ready");

    let published = supervisor.publish(&bridge).expect("publication succeeds");
    assert_eq!(published.bridge_id, bridge);
    assert_eq!(supervisor.snapshot().endpoints.len(), 1);
}

#[test]
fn a_managed_bridge_is_only_provisioned_from_an_agreeing_digest() {
    let mut supervisor = BridgeSupervisor::new();
    let approved = approved();

    let error = supervisor
        .provision_managed(
            "proton-personal",
            &approved,
            &capabilities("2222222222222222222222222222222222222222222222222222222222222222"),
        )
        .expect_err("the authenticated capabilities must agree with the approved digest");
    assert!(
        matches!(error, LifecycleError::CapabilityMismatch { .. }),
        "unexpected error: {error:?}"
    );
}

#[test]
fn a_failing_bridge_only_affects_its_own_mailboxes() {
    let mut supervisor = BridgeSupervisor::new();
    let approved = approved();
    let failing = supervisor
        .provision_managed("proton-personal", &approved, &capabilities(DIGEST))
        .expect("the bridge is provisioned");
    let healthy = supervisor
        .provision_managed("proton-work", &approved, &capabilities(DIGEST))
        .expect("the bridge is provisioned");
    supervisor
        .mark_ready(&failing, endpoint())
        .expect("the bridge reports ready");
    supervisor
        .mark_ready(&healthy, endpoint())
        .expect("the bridge reports ready");

    supervisor
        .attach_mailbox("proton-personal", &failing)
        .expect("the mailbox is attached");
    supervisor
        .attach_mailbox("proton-work", &healthy)
        .expect("the mailbox is attached");

    supervisor.mark_failed(&failing, "the bridge exited");

    assert!(matches!(
        supervisor.mailbox_status("proton-personal"),
        MailboxStatus::BridgeUnavailable { .. }
    ));
    assert_eq!(
        supervisor.mailbox_status("proton-work"),
        MailboxStatus::Ready
    );
    assert_eq!(
        supervisor.mailbox_status("a-direct-mailbox"),
        MailboxStatus::Ready
    );
    assert_eq!(
        supervisor.mailbox_status("proton-work"),
        MailboxStatus::Ready,
        "an unrelated mailbox keeps working"
    );
}

#[test]
fn an_existing_bridge_is_neither_adopted_nor_reconfigured() {
    let mut supervisor = BridgeSupervisor::new();
    let existing = supervisor
        .attach_existing(
            "proton-personal",
            endpoint(),
            vec![BridgeProtocol::Imap, BridgeProtocol::Smtp],
        )
        .expect("the existing bridge is configured");

    // Corvi publishes the administrator configured endpoint as it is.
    let published = supervisor
        .publish(&existing)
        .expect("the endpoint is published");
    assert_eq!(published.endpoint.imap.as_ref().map(|a| a.port), Some(1143));

    // A managed bridge may not take over the same name.
    let error = supervisor
        .provision_managed("proton-personal", &approved(), &capabilities(DIGEST))
        .expect_err("an existing bridge is not adopted");
    assert!(
        matches!(error, LifecycleError::AlreadyExists),
        "unexpected error: {error:?}"
    );

    // Corvi never rewrites the endpoint of an existing bridge.
    assert!(
        supervisor
            .mark_ready(
                &existing,
                BridgeEndpoint {
                    imap: Some(EndpointAddress {
                        host: "0.0.0.0".to_string(),
                        port: 1
                    }),
                    smtp: None,
                    tls_peer: "changed".to_string(),
                }
            )
            .is_err()
    );
    let published = supervisor
        .publish(&existing)
        .expect("the endpoint is published");
    assert_eq!(published.endpoint.imap.as_ref().map(|a| a.port), Some(1143));
}

#[test]
fn a_mailbox_may_only_be_attached_once() {
    let mut supervisor = BridgeSupervisor::new();
    let bridge = supervisor
        .attach_existing("proton-personal", endpoint(), vec![BridgeProtocol::Imap])
        .expect("the existing bridge is configured");

    supervisor
        .attach_mailbox("proton-personal", &bridge)
        .expect("the mailbox is attached");

    let error = supervisor
        .attach_mailbox("proton-personal", &bridge)
        .expect_err("a mailbox is attached once");
    assert!(
        matches!(error, LifecycleError::MailboxAlreadyAttached),
        "unexpected error: {error:?}"
    );
}

#[test]
fn an_unknown_bridge_is_refused() {
    let supervisor = BridgeSupervisor::new();
    let unknown = mail_bridge::lifecycle::BridgeId::new("nope");

    let error = supervisor
        .publish(&unknown)
        .expect_err("an unknown bridge has no endpoint");
    assert!(
        matches!(error, LifecycleError::UnknownBridge),
        "unexpected error: {error:?}"
    );
}

#[test]
fn the_snapshot_contains_only_ready_bridges() {
    let mut supervisor = BridgeSupervisor::new();
    let approved = approved();
    let ready = supervisor
        .provision_managed("proton-personal", &approved, &capabilities(DIGEST))
        .expect("the bridge is provisioned");
    let pending = supervisor
        .provision_managed("proton-work", &approved, &capabilities(DIGEST))
        .expect("the bridge is provisioned");
    supervisor
        .mark_ready(&ready, endpoint())
        .expect("the bridge reports ready");

    let snapshot = supervisor.snapshot();
    assert_eq!(snapshot.endpoints.len(), 1);
    assert_eq!(snapshot.endpoints[0].bridge_id, ready);
    assert_ne!(snapshot.endpoints[0].bridge_id, pending);
}
