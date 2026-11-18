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
use mail_policy_engine::oci::manifest::WASM_LAYER_MEDIA_TYPE;
use mail_policy_engine::oci::tar::read_entries;
use mail_policy_engine::oci::wasm::{AbiExpectation, CapabilityAllowlist};
use wasm_encoder::{
    CodeSection, ExportKind, ExportSection, Function, FunctionSection, Instruction, Module,
    TypeSection, ValType,
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
    )
    .expect("the volume variant validates");

    assert_eq!(artifact.module, module);
    assert_eq!(artifact.module_sha256, sha256_hex(&module));
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
