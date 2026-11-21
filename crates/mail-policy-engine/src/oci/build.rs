//! The paired release builder.
//!
//! ADR-0004 section 4.4.1 requires every released policy to be published
//! twice from the *same* compiled module: a native Wasm OCI variant and an
//! image-volume OCI variant. The two manifests describe different artifacts,
//! so their immutable digests differ; the module bytes inside them are
//! identical, and the builder refuses to produce a pair whose metadata does
//! not describe the module it was given.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::oci::annotations::{
    ABI_ANNOTATION, DISPLAY_NAME_ANNOTATION, INPUT_SCHEMA_ANNOTATION, PROVENANCE_ANNOTATION,
};
use crate::oci::artifact::{LayerBlob, POLICY_METADATA_FILE, POLICY_MODULE_FILE};
use crate::oci::digest::{digest_of, sha256_hex};
use crate::oci::manifest::{
    Descriptor, OCI_IMAGE_CONFIG_MEDIA_TYPE, OCI_MANIFEST_MEDIA_TYPE, OCI_TAR_LAYER_MEDIA_TYPE,
    OciManifest, WASM_CONFIG_MEDIA_TYPE, WASM_LAYER_MEDIA_TYPE,
};
use crate::oci::tar::{self, TarEntry};
use crate::oci::wasm::validate_module;

/// The metadata that describes a policy module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyMetadata {
    /// The policy ABI the module implements.
    pub abi: String,
    /// The input schema version the module expects.
    #[serde(rename = "inputSchema")]
    pub input_schema: String,
    /// The human readable name of the policy.
    #[serde(rename = "displayName")]
    pub display_name: String,
    /// The SHA-256 of the module bytes, in hexadecimal.
    #[serde(rename = "moduleSha256")]
    pub module_sha256: String,
    /// The size of the module in bytes.
    #[serde(rename = "moduleSize")]
    pub module_size: u64,
    /// The build provenance of the module.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<String>,
}

impl PolicyMetadata {
    /// Metadata that describes the given module.
    pub fn for_module(module: &[u8], abi: &str, input_schema: &str, display_name: &str) -> Self {
        Self {
            abi: abi.to_string(),
            input_schema: input_schema.to_string(),
            display_name: display_name.to_string(),
            module_sha256: sha256_hex(module),
            module_size: module.len() as u64,
            provenance: None,
        }
    }

    /// The metadata as the JSON document that is packaged in the volume.
    pub fn to_json_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_else(|_| Vec::new())
    }

    /// Read metadata from the JSON document that is packaged in the volume.
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, BuildError> {
        serde_json::from_slice(bytes).map_err(|error| BuildError::Metadata(error.to_string()))
    }

    /// The Corvi annotations that describe the module.
    pub fn annotations(&self) -> BTreeMap<String, String> {
        let mut annotations = BTreeMap::new();
        annotations.insert(ABI_ANNOTATION.to_string(), self.abi.clone());
        annotations.insert(
            INPUT_SCHEMA_ANNOTATION.to_string(),
            self.input_schema.clone(),
        );
        annotations.insert(
            DISPLAY_NAME_ANNOTATION.to_string(),
            self.display_name.clone(),
        );
        if let Some(provenance) = &self.provenance {
            annotations.insert(PROVENANCE_ANNOTATION.to_string(), provenance.clone());
        }
        annotations
    }
}

/// One built OCI artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciArtifact {
    /// The manifest bytes.
    pub manifest_bytes: Vec<u8>,
    /// The digest of the manifest bytes.
    pub manifest_digest: String,
    /// The configuration blob bytes.
    pub config_bytes: Vec<u8>,
    /// The layer blobs.
    pub layers: Vec<LayerBlob>,
}

impl OciArtifact {
    /// The layer blob with the given media type.
    pub fn layer(&self, media_type: &str) -> Option<&LayerBlob> {
        let manifest: OciManifest = serde_json::from_slice(&self.manifest_bytes).ok()?;
        let descriptor = manifest
            .layers
            .iter()
            .find(|descriptor| descriptor.media_type == media_type)?;
        self.layers
            .iter()
            .find(|blob| blob.digest == descriptor.digest)
    }
}

/// The two variants of one release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseVariants {
    /// The native Wasm OCI variant.
    pub wasm: OciArtifact,
    /// The image-volume OCI variant.
    pub volume: OciArtifact,
}

/// Why a release could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildError {
    /// The module is not a valid WebAssembly module.
    InvalidModule(String),
    /// The metadata describes a different module.
    ModuleDigestMismatch {
        /// The digest the metadata records.
        expected: String,
        /// The digest of the module bytes.
        actual: String,
    },
    /// The metadata records a different module size.
    ModuleSizeMismatch {
        /// The size the metadata records.
        expected: u64,
        /// The size of the module bytes.
        actual: u64,
    },
    /// The metadata document could not be read or written.
    Metadata(String),
    /// The data filesystem could not be written.
    Archive(String),
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BuildError::InvalidModule(reason) => {
                write!(formatter, "the module is not valid: {reason}")
            }
            BuildError::ModuleDigestMismatch { expected, actual } => write!(
                formatter,
                "the metadata records the module digest {expected}, the module hashes to {actual}"
            ),
            BuildError::ModuleSizeMismatch { expected, actual } => write!(
                formatter,
                "the metadata records {expected} module bytes, the module has {actual}"
            ),
            BuildError::Metadata(reason) => {
                write!(formatter, "the policy metadata is not usable: {reason}")
            }
            BuildError::Archive(reason) => {
                write!(
                    formatter,
                    "the data filesystem could not be written: {reason}"
                )
            }
        }
    }
}

impl std::error::Error for BuildError {}

/// Build both release variants from one compiled module.
///
/// The module is compiled once and packaged twice. The builder refuses a
/// module that does not match its metadata, so a release can never pair a
/// stale digest with fresh bytes.
pub fn build_release_variants(
    module: &[u8],
    metadata: &PolicyMetadata,
) -> Result<ReleaseVariants, BuildError> {
    validate_module(module).map_err(|error| BuildError::InvalidModule(error.to_string()))?;

    let module_sha256 = sha256_hex(module);
    if metadata.module_sha256 != module_sha256 {
        return Err(BuildError::ModuleDigestMismatch {
            expected: metadata.module_sha256.clone(),
            actual: module_sha256,
        });
    }
    if metadata.module_size != module.len() as u64 {
        return Err(BuildError::ModuleSizeMismatch {
            expected: metadata.module_size,
            actual: module.len() as u64,
        });
    }

    let annotations = metadata.annotations();

    // The native variant: an OCI image manifest whose config is the Wasm
    // artifact configuration and whose single layer is the module.
    let wasm_config = serde_json::to_vec(&json!({
        "abi": metadata.abi,
        "inputSchema": metadata.input_schema,
        "displayName": metadata.display_name,
        "moduleSha256": metadata.module_sha256,
    }))
    .map_err(|error| BuildError::Metadata(error.to_string()))?;
    let module_layer = LayerBlob::new(module.to_vec());
    let wasm_manifest = OciManifest {
        schema_version: 2,
        media_type: OCI_MANIFEST_MEDIA_TYPE.to_string(),
        config: Descriptor {
            media_type: WASM_CONFIG_MEDIA_TYPE.to_string(),
            digest: digest_of(&wasm_config),
            size: wasm_config.len() as i64,
            annotations: None,
        },
        layers: vec![Descriptor {
            media_type: WASM_LAYER_MEDIA_TYPE.to_string(),
            digest: module_layer.digest.clone(),
            size: module_layer.size(),
            annotations: None,
        }],
        annotations: annotations.clone(),
    };
    let wasm_manifest_bytes = serde_json::to_vec(&wasm_manifest)
        .map_err(|error| BuildError::Metadata(error.to_string()))?;

    // The volume variant: a read-only data filesystem with the module and its
    // metadata, and no shell and no auxiliary executable.
    let archive = tar::write_entries(&[
        TarEntry {
            path: POLICY_MODULE_FILE.to_string(),
            mode: 0o644,
            data: module.to_vec(),
        },
        TarEntry {
            path: POLICY_METADATA_FILE.to_string(),
            mode: 0o644,
            data: metadata.to_json_bytes(),
        },
    ])
    .map_err(|error| BuildError::Archive(error.to_string()))?;
    let volume_layer = LayerBlob::new(archive);
    let volume_config = serde_json::to_vec(&json!({
        "architecture": "wasm",
        "os": "wasip1",
        "config": {},
        "rootfs": {
            "type": "layers",
            "diff_ids": [volume_layer.digest.clone()],
        },
    }))
    .map_err(|error| BuildError::Metadata(error.to_string()))?;
    let volume_manifest = OciManifest {
        schema_version: 2,
        media_type: OCI_MANIFEST_MEDIA_TYPE.to_string(),
        config: Descriptor {
            media_type: OCI_IMAGE_CONFIG_MEDIA_TYPE.to_string(),
            digest: digest_of(&volume_config),
            size: volume_config.len() as i64,
            annotations: None,
        },
        layers: vec![Descriptor {
            media_type: OCI_TAR_LAYER_MEDIA_TYPE.to_string(),
            digest: volume_layer.digest.clone(),
            size: volume_layer.size(),
            annotations: None,
        }],
        annotations,
    };
    let volume_manifest_bytes = serde_json::to_vec(&volume_manifest)
        .map_err(|error| BuildError::Metadata(error.to_string()))?;

    Ok(ReleaseVariants {
        wasm: OciArtifact {
            manifest_digest: digest_of(&wasm_manifest_bytes),
            manifest_bytes: wasm_manifest_bytes,
            config_bytes: wasm_config,
            layers: vec![module_layer],
        },
        volume: OciArtifact {
            manifest_digest: digest_of(&volume_manifest_bytes),
            manifest_bytes: volume_manifest_bytes,
            config_bytes: volume_config,
            layers: vec![volume_layer],
        },
    })
}
