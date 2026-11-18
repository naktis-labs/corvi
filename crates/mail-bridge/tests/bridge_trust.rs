//! The bridge install policy and the mandatory rootless profile
//! (ADR-0006 sections 2, 3 and 4).
//!
//! A bridge descriptor - and any OCI annotation that hints at one - is
//! untrusted external data. It may *request* an image, a runtime and secret
//! bindings; only the administrator install policy may authorize them.

use std::collections::BTreeMap;

use mail_bridge::descriptor::{
    BridgeDescriptor, BridgeMode, BridgeProtocol, DescriptorError, EndpointExposure, Placement,
    SecretClass, SecurityRequirements,
};
use mail_bridge::profile::{ProfileError, validate_requirements};
use mail_bridge::trust::{ApprovedBridge, InstallPolicy, TrustError, authorize};
use serde_json::json;

fn descriptor_json() -> serde_json::Value {
    json!({
        "apiVersion": "corvi.naktis.eu/v1alpha1",
        "kind": "ProviderTransportDependency",
        "transport": {
            "topology": "localBridge",
            "protocols": ["imap", "smtp"],
            "runtime": {
                "mode": "managed",
                "image": "ghcr.io/naktis-labs/corvi-proton-bridge@sha256:1111111111111111111111111111111111111111111111111111111111111111",
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

fn policy() -> InstallPolicy {
    InstallPolicy {
        allowed_repositories: vec!["ghcr.io/naktis-labs/corvi-proton-bridge".to_string()],
        allowed_digests: Vec::new(),
        allowed_secret_classes: vec![SecretClass::BridgeSession],
        allowed_placements: vec![Placement::ColocatedNetworkNamespace],
        max_secret_inputs: 2,
    }
}

#[test]
fn a_descriptor_matching_the_install_policy_is_approved() {
    let descriptor = BridgeDescriptor::from_json(&descriptor_json()).expect("a valid descriptor");

    let approved = authorize(&descriptor, &policy()).expect("the descriptor is approved");

    assert_eq!(
        approved
            .image
            .as_ref()
            .expect("a managed bridge has an approved image")
            .repository(),
        "ghcr.io/naktis-labs/corvi-proton-bridge"
    );
    assert_eq!(approved.secret_inputs.len(), 1);
    assert_eq!(
        approved.protocols,
        vec![BridgeProtocol::Imap, BridgeProtocol::Smtp]
    );
}

#[test]
fn an_image_outside_the_allowlist_is_refused() {
    let mut value = descriptor_json();
    value["transport"]["runtime"]["image"] = json!(
        "ghcr.io/attacker/corvi-bridge@sha256:2222222222222222222222222222222222222222222222222222222222222222"
    );
    let descriptor = BridgeDescriptor::from_json(&value).expect("a valid descriptor");

    let error =
        authorize(&descriptor, &policy()).expect_err("an image outside the allowlist is refused");
    assert!(
        matches!(error, TrustError::RepositoryNotAllowed(_)),
        "unexpected error: {error:?}"
    );
}

#[test]
fn a_mutable_image_reference_is_refused() {
    let mut value = descriptor_json();
    value["transport"]["runtime"]["image"] =
        json!("ghcr.io/naktis-labs/corvi-proton-bridge:latest");
    let descriptor = BridgeDescriptor::from_json(&value).expect("a valid descriptor");

    let error =
        authorize(&descriptor, &policy()).expect_err("a mutable tag is never an approved image");
    assert!(
        matches!(error, TrustError::ImageNotDigestPinned),
        "unexpected error: {error:?}"
    );
}

#[test]
fn a_secret_class_outside_the_allowlist_is_refused() {
    let mut value = descriptor_json();
    value["transport"]["secretInputs"] = json!([
        { "name": "accountSession", "class": "bridgeSession" },
        { "name": "providerAdmin", "class": "keyring" }
    ]);
    let descriptor = BridgeDescriptor::from_json(&value).expect("a valid descriptor");

    let error = authorize(&descriptor, &policy())
        .expect_err("a secret class outside the allowlist is refused");
    assert!(
        matches!(
            error,
            TrustError::SecretClassNotAllowed(SecretClass::Keyring)
        ),
        "unexpected error: {error:?}"
    );
}

#[test]
fn too_many_secret_inputs_are_refused() {
    let mut value = descriptor_json();
    value["transport"]["secretInputs"] = json!([
        { "name": "accountSession", "class": "bridgeSession" },
        { "name": "accountSession2", "class": "bridgeSession" },
        { "name": "accountSession3", "class": "bridgeSession" }
    ]);
    let descriptor = BridgeDescriptor::from_json(&value).expect("a valid descriptor");

    let error =
        authorize(&descriptor, &policy()).expect_err("the number of secret inputs is bounded");
    assert!(
        matches!(error, TrustError::TooManySecretInputs { .. }),
        "unexpected error: {error:?}"
    );
}

#[test]
fn an_empty_install_policy_refuses_every_request() {
    let descriptor = BridgeDescriptor::from_json(&descriptor_json()).expect("a valid descriptor");

    let error = authorize(&descriptor, &InstallPolicy::deny_all())
        .expect_err("an empty allowlist authorizes nothing");
    assert!(
        matches!(error, TrustError::RepositoryNotAllowed(_)),
        "unexpected error: {error:?}"
    );
}

#[test]
fn an_oci_hint_never_authorizes_a_bridge() {
    let mut annotations = BTreeMap::new();
    annotations.insert(
        "eu.naktis.corvi.provider.metadata-version".to_string(),
        "v1".to_string(),
    );
    annotations.insert(
        "eu.naktis.corvi.provider.transport-topology".to_string(),
        "local-bridge".to_string(),
    );
    annotations.insert(
        "eu.naktis.corvi.provider.bridge-mode".to_string(),
        "required".to_string(),
    );
    annotations.insert(
        "eu.naktis.corvi.provider.bridge-image".to_string(),
        "ghcr.io/naktis-labs/corvi-proton-bridge@sha256:3333333333333333333333333333333333333333333333333333333333333333"
            .to_string(),
    );

    let hint = mail_bridge::descriptor::OciBridgeHint::from_annotations(&annotations);
    assert!(hint.requests_a_bridge());
    assert!(hint.suggested_image.is_some());

    // The hint is discovery data. It is not an input to the install policy and
    // it authorizes nothing on its own.
    let descriptor = BridgeDescriptor::from_json(&descriptor_json()).expect("a valid descriptor");
    let error = authorize(&descriptor, &InstallPolicy::deny_all())
        .expect_err("a hint never authorizes an image");
    assert!(
        matches!(error, TrustError::RepositoryNotAllowed(_)),
        "unexpected error: {error:?}"
    );
}

#[test]
fn a_runtime_that_requires_root_is_rejected() {
    let mut value = descriptor_json();
    value["transport"]["runtime"]["security"] = json!({ "requiresRoot": true });
    let descriptor = BridgeDescriptor::from_json(&value).expect("a valid descriptor");

    let error = authorize(&descriptor, &policy()).expect_err("a root-required runtime is rejected");
    assert!(
        matches!(error, TrustError::Profile(ProfileError::RootRequired)),
        "unexpected error: {error:?}"
    );
}

#[test]
fn a_privileged_runtime_is_rejected() {
    let mut value = descriptor_json();
    value["transport"]["runtime"]["security"] = json!({ "privileged": true });
    let descriptor = BridgeDescriptor::from_json(&value).expect("a valid descriptor");

    let error = authorize(&descriptor, &policy()).expect_err("a privileged runtime is rejected");
    assert!(
        matches!(
            error,
            TrustError::Profile(ProfileError::PrivilegedRequested)
        ),
        "unexpected error: {error:?}"
    );
}

#[test]
fn a_runtime_that_needs_capabilities_is_rejected() {
    let mut value = descriptor_json();
    value["transport"]["runtime"]["security"] = json!({
        "requiredCapabilities": ["NET_BIND_SERVICE"]
    });
    let descriptor = BridgeDescriptor::from_json(&value).expect("a valid descriptor");

    let error = authorize(&descriptor, &policy())
        .expect_err("a runtime that needs capabilities is rejected");
    assert!(
        matches!(
            error,
            TrustError::Profile(ProfileError::CapabilitiesRequired(_))
        ),
        "unexpected error: {error:?}"
    );
}

#[test]
fn a_writable_root_filesystem_is_rejected() {
    let mut value = descriptor_json();
    value["transport"]["runtime"]["security"] = json!({ "readOnlyRootFilesystem": false });
    let descriptor = BridgeDescriptor::from_json(&value).expect("a valid descriptor");

    let error =
        authorize(&descriptor, &policy()).expect_err("a writable root filesystem is rejected");
    assert!(
        matches!(
            error,
            TrustError::Profile(ProfileError::WritableRootFilesystem)
        ),
        "unexpected error: {error:?}"
    );
}

#[test]
fn a_non_default_seccomp_profile_is_rejected() {
    let mut value = descriptor_json();
    value["transport"]["runtime"]["security"] = json!({ "seccompProfile": "Unconfined" });
    let descriptor = BridgeDescriptor::from_json(&value).expect("a valid descriptor");

    let error =
        authorize(&descriptor, &policy()).expect_err("a non default seccomp profile is rejected");
    assert!(
        matches!(
            error,
            TrustError::Profile(ProfileError::NonDefaultSeccomp(_))
        ),
        "unexpected error: {error:?}"
    );
}

#[test]
fn the_enforced_profile_is_rootless() {
    let enforced = mail_bridge::profile::EnforcedProfile::mandatory_rootless();

    assert!(enforced.run_as_user > 0);
    assert!(enforced.drop_all_capabilities);
    assert!(!enforced.allow_privilege_escalation);
    assert!(enforced.read_only_root_filesystem);
    assert_eq!(enforced.seccomp_profile, "RuntimeDefault");
    assert!(!enforced.api_token_mounted);
}

#[test]
fn a_rootless_runtime_is_accepted() {
    let mut value = descriptor_json();
    value["transport"]["runtime"]["security"] = json!({
        "requiresRoot": false,
        "privileged": false,
        "requiredCapabilities": [],
        "readOnlyRootFilesystem": true,
        "seccompProfile": "RuntimeDefault"
    });
    let descriptor = BridgeDescriptor::from_json(&value).expect("a valid descriptor");

    authorize(&descriptor, &policy()).expect("a rootless runtime is accepted");
}

#[test]
fn a_request_for_system_paths_is_refused() {
    for path in ["/", "/etc", "/var/run"] {
        let mut value = descriptor_json();
        value["transport"]["runtime"]["security"] = json!({ "writablePaths": [path] });
        let descriptor = BridgeDescriptor::from_json(&value).expect("a valid descriptor");

        let error = authorize(&descriptor, &policy())
            .expect_err("a system path is never the necessary writable state");
        assert!(
            matches!(
                error,
                TrustError::Profile(ProfileError::WritablePathNotAllowed(_))
            ),
            "unexpected error for {path}: {error:?}"
        );
    }
}

#[test]
fn a_request_for_a_socket_path_is_refused() {
    let mut value = descriptor_json();
    value["transport"]["runtime"]["security"] =
        json!({ "writablePaths": ["/var/run/corvi/bridge.sock"] });
    let descriptor = BridgeDescriptor::from_json(&value).expect("a valid descriptor");

    let error = authorize(&descriptor, &policy())
        .expect_err("a runtime socket path is never writable state");
    assert!(
        matches!(
            error,
            TrustError::Profile(ProfileError::WritablePathNotAllowed(_))
        ),
        "unexpected error: {error:?}"
    );
}

#[test]
fn a_traversal_writable_path_is_refused() {
    let mut value = descriptor_json();
    value["transport"]["runtime"]["security"] =
        json!({ "writablePaths": ["/var/lib/corvi/../etc"] });
    let descriptor = BridgeDescriptor::from_json(&value).expect("a valid descriptor");

    let error = authorize(&descriptor, &policy()).expect_err("a traversal path is refused");
    assert!(
        matches!(
            error,
            TrustError::Profile(ProfileError::WritablePathNotAllowed(_))
        ),
        "unexpected error: {error:?}"
    );
}

#[test]
fn a_narrow_writable_state_path_is_approved_and_carried() {
    let mut value = descriptor_json();
    value["transport"]["runtime"]["security"] =
        json!({ "writablePaths": ["/var/lib/corvi/session"] });
    let descriptor = BridgeDescriptor::from_json(&value).expect("a valid descriptor");

    let approved = authorize(&descriptor, &policy()).expect("the narrow state path is approved");

    assert_eq!(
        approved.writable_paths,
        vec!["/var/lib/corvi/session".to_string()],
        "the approval states which writable paths were approved"
    );
}

#[test]
fn an_unknown_security_key_is_a_parse_error() {
    let mut value = descriptor_json();
    value["transport"]["runtime"]["security"] =
        json!({ "requiredCapabilites": ["NET_BIND_SERVICE"] });

    let error = BridgeDescriptor::from_json(&value)
        .expect_err("a typoed security key is refused, never silently ignored");

    assert!(
        matches!(error, DescriptorError::Parse(_)),
        "unexpected error: {error:?}"
    );
}

#[test]
fn an_existing_bridge_may_not_request_an_image() {
    let mut value = descriptor_json();
    value["transport"]["runtime"]["mode"] = json!("existing");
    let descriptor = BridgeDescriptor::from_json(&value).expect("a valid descriptor");

    let error = authorize(&descriptor, &policy())
        .expect_err("an existing bridge is not provisioned by Corvi");
    assert!(
        matches!(error, TrustError::ExistingBridgeMustNotRequestAnImage),
        "unexpected error: {error:?}"
    );
}

#[test]
fn a_managed_bridge_without_an_image_is_refused() {
    let mut value = descriptor_json();
    value["transport"]["runtime"]
        .as_object_mut()
        .expect("the runtime is an object")
        .remove("image");
    let descriptor = BridgeDescriptor::from_json(&value).expect("a valid descriptor");

    let error =
        authorize(&descriptor, &policy()).expect_err("a managed bridge needs an approved image");
    assert!(
        matches!(error, TrustError::ManagedBridgeWithoutImage),
        "unexpected error: {error:?}"
    );
}

#[test]
fn an_unknown_descriptor_version_is_refused() {
    let mut value = descriptor_json();
    value["apiVersion"] = json!("corvi.naktis.eu/v2");
    let error = BridgeDescriptor::from_json(&value).expect_err("an unknown version is refused");
    assert!(
        matches!(error, DescriptorError::UnsupportedApiVersion(_)),
        "unexpected error: {error:?}"
    );
}

#[test]
fn an_exposure_outside_the_policy_is_refused() {
    let descriptor = BridgeDescriptor::from_json(&descriptor_json()).expect("a valid descriptor");
    let mut strict = policy();
    strict.allowed_placements = vec![Placement::ExternalTrustedEndpoint];

    let error = authorize(&descriptor, &strict).expect_err("the placement must be allowlisted");
    assert!(
        matches!(error, TrustError::PlacementNotAllowed(_)),
        "unexpected error: {error:?}"
    );
}

#[test]
fn a_network_exposed_endpoint_is_refused_by_the_default_policy() {
    let mut value = descriptor_json();
    value["transport"]["runtime"]["endpoint"]["exposure"] = json!("authenticatedNetwork");
    let descriptor = BridgeDescriptor::from_json(&value).expect("a valid descriptor");

    let error = authorize(&descriptor, &policy())
        .expect_err("a network exposed endpoint needs an explicit approval");
    assert!(
        matches!(error, TrustError::EndpointExposureNotAllowed(_)),
        "unexpected error: {error:?}"
    );
}

#[test]
fn the_approved_bridge_keeps_the_requested_protocols_and_placement() {
    let descriptor = BridgeDescriptor::from_json(&descriptor_json()).expect("a valid descriptor");

    let approved: ApprovedBridge = authorize(&descriptor, &policy()).expect("approved");

    assert_eq!(approved.placement, Placement::ColocatedNetworkNamespace);
    assert_eq!(approved.exposure, EndpointExposure::LoopbackOnly);
    assert_eq!(approved.mode, BridgeMode::Managed);
    let requirements = SecurityRequirements::default();
    assert!(validate_requirements(&requirements).is_ok());
}
