//! OCI policy artifact validation (ADR-0004 sections 4.4 and 4.5).
//!
//! Media-type metadata is never proof of trust: the module bytes are parsed
//! and validated, the imports are checked against an explicit allowlist, the
//! Corvi annotations may describe a module but never grant capabilities, and
//! the recorded manifest digest must match the bytes it pins.

use mail_policy_engine::oci::annotations::{AnnotationError, PolicyAnnotations};
use mail_policy_engine::oci::artifact::{ArtifactError, LayerBlob, validate_native_wasm_artifact};
use mail_policy_engine::oci::digest::{digest_of, sha256_hex};
use mail_policy_engine::oci::manifest::{
    OCI_GZIP_LAYER_MEDIA_TYPE, OCI_IMAGE_CONFIG_MEDIA_TYPE, OCI_MANIFEST_MEDIA_TYPE,
    OCI_TAR_LAYER_MEDIA_TYPE, WASM_CONFIG_MEDIA_TYPE, WASM_LAYER_MEDIA_TYPE,
};
use mail_policy_engine::oci::wasm::{AbiExpectation, AllowedImport, CapabilityAllowlist};
use serde_json::json;
use sha2::{Digest, Sha256};
use wasm_encoder::{
    CodeSection, EntityType, ExportKind, ExportSection, Function, FunctionSection, ImportSection,
    Instruction, Module, TypeSection, ValType,
};

/// A module that exports the Corvi entry point and imports nothing.
fn policy_module() -> Vec<u8> {
    let mut module = Module::new();
    let mut types = TypeSection::new();
    types.ty().function([], []);
    module.section(&types);
    let mut functions = FunctionSection::new();
    functions.function(0);
    module.section(&functions);
    let mut exports = ExportSection::new();
    exports.export("evaluate", ExportKind::Func, 0);
    module.section(&exports);
    let mut code = CodeSection::new();
    let mut function = Function::new(std::iter::empty::<(u32, ValType)>());
    function.instruction(&Instruction::End);
    code.function(&function);
    module.section(&code);
    module.finish()
}

/// A module that imports a host function and still exports the entry point.
fn module_importing(module: &str, name: &str) -> Vec<u8> {
    let mut built = Module::new();
    let mut types = TypeSection::new();
    types.ty().function([], []);
    built.section(&types);
    let mut imports = ImportSection::new();
    imports.import(module, name, EntityType::Function(0));
    built.section(&imports);
    let mut functions = FunctionSection::new();
    // The imported function occupies index 0, so the local function is index 1.
    functions.function(0);
    built.section(&functions);
    let mut exports = ExportSection::new();
    exports.export("evaluate", ExportKind::Func, 1);
    built.section(&exports);
    let mut code = CodeSection::new();
    let mut function = Function::new(std::iter::empty::<(u32, ValType)>());
    function.instruction(&Instruction::End);
    code.function(&function);
    built.section(&code);
    built.finish()
}

fn manifest_bytes(
    config_media_type: &str,
    config_digest: &str,
    config_size: usize,
    layers: serde_json::Value,
    annotations: serde_json::Value,
) -> Vec<u8> {
    let manifest = json!({
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST_MEDIA_TYPE,
        "config": {
            "mediaType": config_media_type,
            "digest": config_digest,
            "size": config_size,
        },
        "layers": layers,
        "annotations": annotations,
    });
    serde_json::to_vec(&manifest).expect("the manifest is serializable")
}

fn wasm_manifest(module: &[u8], annotations: serde_json::Value) -> Vec<u8> {
    let config = b"{}";
    manifest_bytes(
        WASM_CONFIG_MEDIA_TYPE,
        &digest_of(config),
        config.len(),
        json!([{
            "mediaType": WASM_LAYER_MEDIA_TYPE,
            "digest": digest_of(module),
            "size": module.len(),
        }]),
        annotations,
    )
}

fn layers_of(module: &[u8]) -> Vec<LayerBlob> {
    vec![LayerBlob {
        digest: digest_of(module),
        bytes: module.to_vec(),
    }]
}

fn allowlist() -> CapabilityAllowlist {
    CapabilityAllowlist::deny_all()
}

fn abi() -> AbiExpectation {
    AbiExpectation::corvi_policy_v1()
}

fn validate(
    manifest: &[u8],
    layers: Vec<LayerBlob>,
    allowlist: &CapabilityAllowlist,
) -> Result<(), ArtifactError> {
    let digest = digest_of(manifest);
    validate_native_wasm_artifact(manifest, &digest, &layers, allowlist, &abi()).map(|_| ())
}

#[test]
fn a_valid_native_wasm_artifact_is_accepted() {
    let module = policy_module();
    let manifest = wasm_manifest(&module, json!({}));

    validate(&manifest, layers_of(&module), &allowlist()).expect("the artifact is valid");
}

#[test]
fn an_unsupported_manifest_media_type_is_rejected() {
    let module = policy_module();
    let config = b"{}";
    let manifest = serde_json::to_vec(&json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": WASM_CONFIG_MEDIA_TYPE,
            "digest": digest_of(config),
            "size": config.len(),
        },
        "layers": [{
            "mediaType": WASM_LAYER_MEDIA_TYPE,
            "digest": digest_of(&module),
            "size": module.len(),
        }],
        "annotations": {},
    }))
    .expect("the manifest is serializable");

    let error = validate(&manifest, layers_of(&module), &allowlist())
        .expect_err("only the OCI image manifest is supported");
    assert!(
        matches!(error, ArtifactError::UnsupportedManifestMediaType(_)),
        "unexpected error: {error:?}"
    );
}

#[test]
fn an_unsupported_config_media_type_is_rejected() {
    let module = policy_module();
    let config = b"{}";
    let manifest = manifest_bytes(
        "application/vnd.example.config.v1+json",
        &digest_of(config),
        config.len(),
        json!([{
            "mediaType": WASM_LAYER_MEDIA_TYPE,
            "digest": digest_of(&module),
            "size": module.len(),
        }]),
        json!({}),
    );

    let error = validate(&manifest, layers_of(&module), &allowlist())
        .expect_err("only the Wasm config media type is supported");
    assert!(
        matches!(error, ArtifactError::UnsupportedConfigMediaType(_)),
        "unexpected error: {error:?}"
    );
}

#[test]
fn a_container_image_is_not_accepted_as_a_policy_module() {
    let module = policy_module();
    let config = b"{}";
    let manifest = manifest_bytes(
        OCI_IMAGE_CONFIG_MEDIA_TYPE,
        &digest_of(config),
        config.len(),
        json!([{
            "mediaType": OCI_GZIP_LAYER_MEDIA_TYPE,
            "digest": digest_of(&module),
            "size": module.len(),
        }]),
        json!({}),
    );

    let error = validate(&manifest, layers_of(&module), &allowlist())
        .expect_err("a container filesystem is not a policy module");
    assert!(
        matches!(
            error,
            ArtifactError::ContainerFilesystemPresentedAsPolicyModule
        ),
        "unexpected error: {error:?}"
    );
}

#[test]
fn a_container_filesystem_layer_is_not_accepted_as_a_policy_module() {
    let module = policy_module();
    let config = b"{}";
    let manifest = manifest_bytes(
        WASM_CONFIG_MEDIA_TYPE,
        &digest_of(config),
        config.len(),
        json!([{
            "mediaType": OCI_TAR_LAYER_MEDIA_TYPE,
            "digest": digest_of(&module),
            "size": module.len(),
        }]),
        json!({}),
    );

    let error = validate(&manifest, layers_of(&module), &allowlist())
        .expect_err("a container filesystem is not a policy module");
    assert!(
        matches!(
            error,
            ArtifactError::ContainerFilesystemPresentedAsPolicyModule
        ),
        "unexpected error: {error:?}"
    );
}

#[test]
fn several_module_layers_are_ambiguous_and_rejected() {
    let module = policy_module();
    let config = b"{}";
    let manifest = manifest_bytes(
        WASM_CONFIG_MEDIA_TYPE,
        &digest_of(config),
        config.len(),
        json!([
            {
                "mediaType": WASM_LAYER_MEDIA_TYPE,
                "digest": digest_of(&module),
                "size": module.len(),
            },
            {
                "mediaType": WASM_LAYER_MEDIA_TYPE,
                "digest": digest_of(&module),
                "size": module.len(),
            },
        ]),
        json!({}),
    );

    let error = validate(&manifest, layers_of(&module), &allowlist())
        .expect_err("an ambiguous module layer set is rejected");
    assert!(
        matches!(error, ArtifactError::AmbiguousModuleLayers { .. }),
        "unexpected error: {error:?}"
    );
}

#[test]
fn a_missing_module_layer_is_rejected() {
    let config = b"{}";
    let manifest = manifest_bytes(
        WASM_CONFIG_MEDIA_TYPE,
        &digest_of(config),
        config.len(),
        json!([]),
        json!({}),
    );

    let error = validate(&manifest, vec![], &allowlist())
        .expect_err("a policy artifact without a module layer is rejected");
    assert!(
        matches!(error, ArtifactError::MissingModuleLayer),
        "unexpected error: {error:?}"
    );
}

#[test]
fn an_unsupported_layer_media_type_is_rejected() {
    let module = policy_module();
    let config = b"{}";
    let manifest = manifest_bytes(
        WASM_CONFIG_MEDIA_TYPE,
        &digest_of(config),
        config.len(),
        json!([{
            "mediaType": "application/vnd.example.layer.v1+json",
            "digest": digest_of(&module),
            "size": module.len(),
        }]),
        json!({}),
    );

    let error = validate(&manifest, layers_of(&module), &allowlist())
        .expect_err("only the application/wasm layer media type is supported");
    assert!(
        matches!(error, ArtifactError::UnsupportedLayerMediaType(_)),
        "unexpected error: {error:?}"
    );
}

#[test]
fn a_corrupt_module_is_rejected_even_though_the_media_type_says_wasm() {
    let module = b"this is not a wasm module".to_vec();
    let manifest = wasm_manifest(&module, json!({}));

    let error = validate(&manifest, layers_of(&module), &allowlist())
        .expect_err("the module bytes must parse");
    assert!(
        matches!(error, ArtifactError::InvalidModule(_)),
        "unexpected error: {error:?}"
    );
}

#[test]
fn a_module_importing_a_host_function_is_rejected() {
    let module = module_importing("wasi_snapshot_preview1", "fd_write");
    let manifest = wasm_manifest(&module, json!({}));

    let error = validate(&manifest, layers_of(&module), &allowlist())
        .expect_err("an unallowlisted host import is rejected");
    assert!(
        matches!(error, ArtifactError::ForbiddenImport { .. }),
        "unexpected error: {error:?}"
    );
}

#[test]
fn an_allowlisted_import_is_accepted() {
    let module = module_importing("corvi:policy/host@0.1.0", "now");
    let manifest = wasm_manifest(&module, json!({}));
    let allowlist = CapabilityAllowlist::with(vec![AllowedImport {
        module: "corvi:policy/host@0.1.0".to_string(),
        name: "now".to_string(),
    }]);

    validate(&manifest, layers_of(&module), &allowlist)
        .expect("the allowlist is the only grant path");
}

#[test]
fn a_module_without_the_expected_entry_point_is_rejected() {
    let module = module_importing("corvi:policy/host@0.1.0", "now");
    let manifest = wasm_manifest(&module, json!({}));
    let allowlist = CapabilityAllowlist::with(vec![AllowedImport {
        module: "corvi:policy/host@0.1.0".to_string(),
        name: "now".to_string(),
    }]);

    let digest = digest_of(&manifest);
    let error = validate_native_wasm_artifact(
        &manifest,
        &digest,
        &layers_of(&module),
        &allowlist,
        &AbiExpectation::with_entry_point_exports(vec!["corvi:policy/evaluate".to_string()]),
    )
    .expect_err("the ABI entry point must be exported");
    assert!(
        matches!(error, ArtifactError::MissingEntryPoint { .. }),
        "unexpected error: {error:?}"
    );
}

#[test]
fn an_annotation_claiming_extra_capabilities_is_rejected() {
    let module = policy_module();
    let manifest = wasm_manifest(
        &module,
        json!({
            "eu.naktis.corvi.policy.abi": "corvi-policy-v1",
            "eu.naktis.corvi.policy.capabilities": "wasi:filesystem,wasi:network",
        }),
    );

    let error = validate(&manifest, layers_of(&module), &allowlist())
        .expect_err("annotations never grant capabilities");
    assert!(
        matches!(
            error,
            ArtifactError::Annotation(AnnotationError::CapabilitiesNotGrantable(_))
        ),
        "unexpected error: {error:?}"
    );
}

#[test]
fn an_annotation_never_grants_a_forbidden_import() {
    let module = module_importing("wasi_snapshot_preview1", "fd_write");
    let manifest = wasm_manifest(
        &module,
        json!({
            "eu.naktis.corvi.policy.capabilities": "wasi:filesystem",
        }),
    );

    let error = validate(&manifest, layers_of(&module), &allowlist())
        .expect_err("annotations never grant capabilities");
    assert!(
        matches!(error, ArtifactError::ForbiddenImport { .. }),
        "unexpected error: {error:?}"
    );
}

#[test]
fn corvi_annotations_describe_a_module() {
    let annotations = PolicyAnnotations::parse(
        &serde_json::from_value(json!({
            "eu.naktis.corvi.policy.abi": "corvi-policy-v1",
            "eu.naktis.corvi.policy.input-schema": "corvi-policy-input-v1",
            "eu.naktis.corvi.policy.display-name": "Privacy policy",
            "eu.naktis.corvi.policy.provenance": "ci-build-42",
            "org.opencontainers.image.source": "https://example.invalid/policy",
        }))
        .expect("the annotations are a map"),
    )
    .expect("the annotations describe a module");

    assert_eq!(annotations.abi.as_deref(), Some("corvi-policy-v1"));
    assert_eq!(
        annotations.input_schema.as_deref(),
        Some("corvi-policy-input-v1")
    );
    assert_eq!(annotations.display_name.as_deref(), Some("Privacy policy"));
    assert_eq!(annotations.provenance.as_deref(), Some("ci-build-42"));
}

#[test]
fn a_manifest_digest_that_does_not_match_the_bytes_is_rejected() {
    let module = policy_module();
    let manifest = wasm_manifest(
        &module,
        json!({ "eu.naktis.corvi.policy.display-name": "demo" }),
    );
    let mut tampered = manifest.clone();
    let position = tampered
        .windows(4)
        .position(|window| window == b"demo")
        .expect("the display name is present");
    tampered[position] = b'D';

    let error = validate_native_wasm_artifact(
        &tampered,
        &digest_of(&manifest),
        &layers_of(&module),
        &allowlist(),
        &abi(),
    )
    .expect_err("the digest pins the manifest bytes");
    assert!(
        matches!(error, ArtifactError::ManifestDigestMismatch { .. }),
        "unexpected error: {error:?}"
    );
}

#[test]
fn a_layer_that_does_not_match_its_digest_is_rejected() {
    let module = policy_module();
    let manifest = wasm_manifest(&module, json!({}));
    let digest = digest_of(&manifest);

    let error = validate_native_wasm_artifact(
        &manifest,
        &digest,
        &[LayerBlob {
            digest: digest_of(&module),
            bytes: b"tampered".to_vec(),
        }],
        &allowlist(),
        &abi(),
    )
    .expect_err("the layer digest pins the module bytes");
    assert!(
        matches!(error, ArtifactError::LayerDigestMismatch { .. }),
        "unexpected error: {error:?}"
    );
}

#[test]
fn the_digest_helper_matches_sha256() {
    assert_eq!(
        digest_of(b"corvi"),
        format!("sha256:{:x}", Sha256::digest(b"corvi"))
    );
    assert_eq!(
        sha256_hex(b"corvi"),
        format!("{:x}", Sha256::digest(b"corvi"))
    );
}
