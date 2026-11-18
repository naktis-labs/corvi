//! The paired release artifacts (ADR-0004 section 4.4.1).
//!
//! Every released policy is published twice from the same compiled module:
//! the native Wasm OCI variant and the image-volume OCI variant. The module
//! bytes must be identical; the immutable manifest digests must differ.

use mail_policy_engine::oci::artifact::{
    ArtifactError, LayerBlob, validate_native_wasm_artifact, validate_volume_artifact,
};
use mail_policy_engine::oci::build::{BuildError, PolicyMetadata, build_release_variants};
use mail_policy_engine::oci::digest::{digest_of, sha256_hex};
use mail_policy_engine::oci::manifest::{
    OCI_IMAGE_CONFIG_MEDIA_TYPE, OCI_MANIFEST_MEDIA_TYPE, OCI_TAR_LAYER_MEDIA_TYPE,
    WASM_LAYER_MEDIA_TYPE,
};
use mail_policy_engine::oci::tar::{self, TarEntry, read_entries};
use mail_policy_engine::oci::wasm::{AbiExpectation, CapabilityAllowlist};
use wasm_encoder::{
    CodeSection, EntityType, ExportKind, ExportSection, Function, FunctionSection, ImportSection,
    Instruction, Module, TypeSection, ValType,
};

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

fn metadata(module: &[u8]) -> PolicyMetadata {
    PolicyMetadata::for_module(
        module,
        "corvi-policy-v1",
        "corvi-policy-input-v1",
        "Privacy policy",
    )
}

/// Package `module` into an image-volume artifact: a hand-built tar layer
/// with the module and its metadata, and a matching manifest.
fn volume_variant(module: &[u8]) -> (Vec<u8>, String, Vec<LayerBlob>) {
    let metadata = metadata(module);
    let archive = tar::write_entries(&[
        TarEntry {
            path: "policy.wasm".to_string(),
            mode: 0o644,
            data: module.to_vec(),
        },
        TarEntry {
            path: "policy.json".to_string(),
            mode: 0o644,
            data: metadata.to_json_bytes(),
        },
    ])
    .expect("the archive writes");
    let layer = LayerBlob::new(archive);
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST_MEDIA_TYPE,
        "config": {
            "mediaType": OCI_IMAGE_CONFIG_MEDIA_TYPE,
            "digest": format!("sha256:{}", "0".repeat(64)),
            "size": 2,
        },
        "layers": [{
            "mediaType": OCI_TAR_LAYER_MEDIA_TYPE,
            "digest": layer.digest,
            "size": layer.size(),
        }],
    });
    let manifest_bytes = serde_json::to_vec(&manifest).expect("the manifest serialises");
    let digest = digest_of(&manifest_bytes);
    (manifest_bytes, digest, vec![layer])
}

/// A structurally valid module that imports a host function the allowlist
/// does not name.
fn module_with_forbidden_import() -> Vec<u8> {
    let mut module = Module::new();
    let mut types = TypeSection::new();
    types.ty().function([], []);
    module.section(&types);
    let mut imports = ImportSection::new();
    imports.import(
        "wasi_snapshot_preview1",
        "fd_write",
        EntityType::Function(0),
    );
    module.section(&imports);
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

/// A structurally valid module that exports none of the ABI entry points.
fn module_without_entry_point() -> Vec<u8> {
    let mut module = Module::new();
    let mut types = TypeSection::new();
    types.ty().function([], []);
    module.section(&types);
    let mut functions = FunctionSection::new();
    functions.function(0);
    module.section(&functions);
    let mut exports = ExportSection::new();
    exports.export("decide", ExportKind::Func, 0);
    module.section(&exports);
    let mut code = CodeSection::new();
    let mut function = Function::new(std::iter::empty::<(u32, ValType)>());
    function.instruction(&Instruction::End);
    code.function(&function);
    module.section(&code);
    module.finish()
}

#[test]
fn both_variants_contain_identical_module_bytes() {
    let module = policy_module();
    let variants = build_release_variants(&module, &metadata(&module)).expect("the variants build");

    let wasm_layer = variants
        .wasm
        .layer(WASM_LAYER_MEDIA_TYPE)
        .expect("the native variant has one Wasm layer");
    assert_eq!(wasm_layer.bytes, module);

    let volume_layer = variants
        .volume
        .layers
        .first()
        .expect("the volume variant has one filesystem layer");
    let entries = read_entries(&volume_layer.bytes).expect("the volume layer is a tar archive");
    let packaged = entries
        .iter()
        .find(|entry| entry.path == "policy.wasm")
        .expect("the volume variant packages the module");
    assert_eq!(packaged.data, module);
}

#[test]
fn the_variants_have_distinct_manifest_digests() {
    let module = policy_module();
    let variants = build_release_variants(&module, &metadata(&module)).expect("the variants build");

    assert_ne!(
        variants.wasm.manifest_digest,
        variants.volume.manifest_digest
    );
    assert_eq!(
        variants.wasm.manifest_digest,
        digest_of(&variants.wasm.manifest_bytes)
    );
    assert_eq!(
        variants.volume.manifest_digest,
        digest_of(&variants.volume.manifest_bytes)
    );
}

#[test]
fn the_wasm_variant_validates_as_a_native_policy_artifact() {
    let module = policy_module();
    let variants = build_release_variants(&module, &metadata(&module)).expect("the variants build");

    let artifact = validate_native_wasm_artifact(
        &variants.wasm.manifest_bytes,
        &variants.wasm.manifest_digest,
        &variants.wasm.layers,
        &CapabilityAllowlist::deny_all(),
        &AbiExpectation::corvi_policy_v1(),
    )
    .expect("the native variant validates");

    assert_eq!(artifact.module, module);
    assert_eq!(artifact.module_sha256, sha256_hex(&module));
    assert_eq!(artifact.annotations.abi.as_deref(), Some("corvi-policy-v1"));
}

#[test]
fn the_volume_variant_validates_as_a_read_only_data_filesystem() {
    let module = policy_module();
    let variants = build_release_variants(&module, &metadata(&module)).expect("the variants build");

    let artifact = validate_volume_artifact(
        &variants.volume.manifest_bytes,
        &variants.volume.manifest_digest,
        &variants.volume.layers,
        Some(&sha256_hex(&module)),
        &CapabilityAllowlist::deny_all(),
        &AbiExpectation::corvi_policy_v1(),
    )
    .expect("the volume variant validates");

    assert_eq!(artifact.module, module);
    assert_eq!(artifact.module_sha256, sha256_hex(&module));
}

#[test]
fn the_volume_variant_validates_the_module_like_the_native_variant() {
    let module = policy_module();
    let (manifest, digest, layers) = volume_variant(&module);

    let artifact = validate_volume_artifact(
        &manifest,
        &digest,
        &layers,
        None,
        &CapabilityAllowlist::deny_all(),
        &AbiExpectation::corvi_policy_v1(),
    )
    .expect("a valid module passes the volume path");

    assert_eq!(artifact.module, module);
    assert_eq!(artifact.module_sha256, sha256_hex(&module));
}

#[test]
fn the_volume_variant_rejects_a_module_with_a_forbidden_import() {
    let module = module_with_forbidden_import();
    let (manifest, digest, layers) = volume_variant(&module);

    let error = validate_volume_artifact(
        &manifest,
        &digest,
        &layers,
        None,
        &CapabilityAllowlist::deny_all(),
        &AbiExpectation::corvi_policy_v1(),
    )
    .expect_err("the volume path enforces the import allowlist");

    match error {
        ArtifactError::ForbiddenImport { module, name } => {
            assert_eq!(module, "wasi_snapshot_preview1");
            assert_eq!(name, "fd_write");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn the_volume_variant_rejects_a_module_without_the_entry_point() {
    let module = module_without_entry_point();
    let (manifest, digest, layers) = volume_variant(&module);

    let error = validate_volume_artifact(
        &manifest,
        &digest,
        &layers,
        None,
        &CapabilityAllowlist::deny_all(),
        &AbiExpectation::corvi_policy_v1(),
    )
    .expect_err("the volume path requires the ABI entry point");

    assert!(
        matches!(error, ArtifactError::MissingEntryPoint { .. }),
        "unexpected error: {error:?}"
    );
}

#[test]
fn the_volume_variant_rejects_a_module_that_is_not_wasm() {
    let module = b"not a wasm module".to_vec();
    let (manifest, digest, layers) = volume_variant(&module);

    let error = validate_volume_artifact(
        &manifest,
        &digest,
        &layers,
        None,
        &CapabilityAllowlist::deny_all(),
        &AbiExpectation::corvi_policy_v1(),
    )
    .expect_err("the volume path only accepts WebAssembly modules");

    assert!(
        matches!(error, ArtifactError::InvalidModule(_)),
        "unexpected error: {error:?}"
    );
}

#[test]
fn the_volume_variant_contains_no_shell_or_extra_executable() {
    let module = policy_module();
    let variants = build_release_variants(&module, &metadata(&module)).expect("the variants build");
    let volume_layer = variants.volume.layers.first().expect("one layer");
    let entries = read_entries(&volume_layer.bytes).expect("the volume layer is a tar archive");

    let mut paths: Vec<&str> = entries.iter().map(|entry| entry.path.as_str()).collect();
    paths.sort_unstable();
    assert_eq!(paths, ["policy.json", "policy.wasm"]);
    for entry in &entries {
        assert_eq!(
            entry.mode & 0o111,
            0,
            "{} must not be executable",
            entry.path
        );
    }
}

#[test]
fn a_builder_refuses_a_module_that_does_not_match_the_metadata_digest() {
    let module = policy_module();
    let mut metadata = metadata(&module);
    metadata.module_sha256 = sha256_hex(b"a different module");

    let error = build_release_variants(&module, &metadata)
        .expect_err("the release gate compares the module digest");
    assert!(
        matches!(error, BuildError::ModuleDigestMismatch { .. }),
        "unexpected error: {error:?}"
    );
}

#[test]
fn a_builder_refuses_a_module_that_is_not_valid_wasm() {
    let module = b"not a wasm module".to_vec();
    let metadata = metadata(&module);

    let error = build_release_variants(&module, &metadata)
        .expect_err("the release gate validates the module");
    assert!(
        matches!(error, BuildError::InvalidModule(_)),
        "unexpected error: {error:?}"
    );
}

#[test]
fn the_volume_variant_is_refused_when_the_expected_module_digest_differs() {
    let module = policy_module();
    let variants = build_release_variants(&module, &metadata(&module)).expect("the variants build");

    let error = validate_volume_artifact(
        &variants.volume.manifest_bytes,
        &variants.volume.manifest_digest,
        &variants.volume.layers,
        Some(&sha256_hex(b"a different module")),
        &CapabilityAllowlist::deny_all(),
        &AbiExpectation::corvi_policy_v1(),
    )
    .expect_err("the volume mount is verified against the release digest");

    assert!(
        matches!(error, ArtifactError::ModuleDigestMismatch { .. }),
        "unexpected error: {error:?}"
    );
}

#[test]
fn the_volume_variant_layers_are_the_ones_that_were_packaged() {
    let module = policy_module();
    let variants = build_release_variants(&module, &metadata(&module)).expect("the variants build");

    let layer: &LayerBlob = variants.volume.layers.first().expect("one layer");
    assert_eq!(layer.digest, digest_of(&layer.bytes));

    let manifest: serde_json::Value =
        serde_json::from_slice(&variants.volume.manifest_bytes).expect("a valid manifest");
    let descriptor = &manifest["layers"][0];
    assert_eq!(descriptor["digest"], serde_json::json!(layer.digest));
    assert_eq!(descriptor["size"], serde_json::json!(layer.bytes.len()));
}
