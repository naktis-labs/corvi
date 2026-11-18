//! Validation of OCI policy artifacts.
//!
//! Two layouts are accepted, and nothing else:
//!
//! * the **native Wasm variant**: an OCI image manifest with an
//!   `application/vnd.wasm.config.v0+json` config and exactly one
//!   `application/wasm` layer;
//! * the **image-volume variant**: an OCI image manifest with a standard image
//!   config and exactly one uncompressed tar layer holding the module and its
//!   metadata.
//!
//! A platform specific container filesystem presented as a policy module is
//! rejected: it is a different artifact class, and running it is not what a
//! policy module means.

use std::fmt;

use crate::oci::annotations::{AnnotationError, PolicyAnnotations};
use crate::oci::build::PolicyMetadata;
use crate::oci::digest::{digest_of, sha256_hex};
use crate::oci::manifest::{
    OCI_GZIP_LAYER_MEDIA_TYPE, OCI_IMAGE_CONFIG_MEDIA_TYPE, OCI_MANIFEST_MEDIA_TYPE,
    OCI_TAR_LAYER_MEDIA_TYPE, OciManifest, WASM_CONFIG_MEDIA_TYPE, WASM_LAYER_MEDIA_TYPE,
};
use crate::oci::tar;
use crate::oci::wasm::{
    AbiExpectation, CapabilityAllowlist, ImportKind, WasmError, inspect, validate_module,
};

/// The file name of the module inside an image-volume variant.
pub const POLICY_MODULE_FILE: &str = "policy.wasm";

/// The file name of the metadata inside an image-volume variant.
pub const POLICY_METADATA_FILE: &str = "policy.json";

/// A layer blob and the digest that pins it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayerBlob {
    /// The digest of the blob.
    pub digest: String,
    /// The bytes of the blob.
    pub bytes: Vec<u8>,
}

impl LayerBlob {
    /// A blob with its computed digest.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            digest: digest_of(&bytes),
            bytes,
        }
    }

    /// The size of the blob in bytes.
    pub fn size(&self) -> i64 {
        self.bytes.len() as i64
    }
}

/// A validated native Wasm policy artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedArtifact {
    /// The manifest of the artifact.
    pub manifest: OciManifest,
    /// The digest of the manifest.
    pub manifest_digest: String,
    /// The module bytes.
    pub module: Vec<u8>,
    /// The SHA-256 of the module bytes.
    pub module_sha256: String,
    /// The Corvi annotations of the manifest.
    pub annotations: PolicyAnnotations,
}

/// A validated image-volume policy artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedVolumeArtifact {
    /// The manifest of the artifact.
    pub manifest: OciManifest,
    /// The digest of the manifest.
    pub manifest_digest: String,
    /// The module bytes.
    pub module: Vec<u8>,
    /// The SHA-256 of the module bytes.
    pub module_sha256: String,
    /// The metadata of the artifact.
    pub metadata: PolicyMetadata,
}

/// A module that passed artifact validation and may be handed to a host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedPolicyModule {
    /// The module bytes.
    pub bytes: Vec<u8>,
    /// The digest of the manifest the module came from.
    pub manifest_digest: String,
    /// The SHA-256 of the module bytes.
    pub module_sha256: String,
    /// The policy ABI the module implements.
    pub abi: String,
}

impl PreparedPolicyModule {
    /// A prepared module.
    pub fn new(
        bytes: Vec<u8>,
        manifest_digest: String,
        module_sha256: String,
        abi: String,
    ) -> Self {
        Self {
            bytes,
            manifest_digest,
            module_sha256,
            abi,
        }
    }
}

/// Why an artifact was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactError {
    /// The manifest is not readable JSON.
    ManifestParse(String),
    /// The manifest bytes do not match the recorded digest.
    ManifestDigestMismatch {
        /// The recorded digest.
        expected: String,
        /// The digest of the bytes that were supplied.
        actual: String,
    },
    /// The manifest media type is not supported.
    UnsupportedManifestMediaType(String),
    /// The manifest schema version is not supported.
    UnsupportedManifestSchemaVersion(i64),
    /// The config media type is not supported.
    UnsupportedConfigMediaType(String),
    /// The layer media type is not supported.
    UnsupportedLayerMediaType(String),
    /// The artifact has no module layer.
    MissingModuleLayer,
    /// The artifact has more than one candidate module layer.
    AmbiguousModuleLayers {
        /// How many layers the manifest declares.
        count: usize,
    },
    /// A container filesystem was presented as a policy module.
    ContainerFilesystemPresentedAsPolicyModule,
    /// The layer blob was not supplied.
    LayerMissing {
        /// The digest of the missing blob.
        digest: String,
    },
    /// The layer bytes do not match their digest.
    LayerDigestMismatch {
        /// The recorded digest.
        expected: String,
        /// The digest of the bytes that were supplied.
        actual: String,
    },
    /// The layer size does not match the descriptor.
    LayerSizeMismatch {
        /// The recorded size.
        expected: i64,
        /// The size of the bytes that were supplied.
        actual: i64,
    },
    /// The module is not a valid WebAssembly module.
    InvalidModule(String),
    /// The module imports something the allowlist does not permit.
    ForbiddenImport {
        /// The module the import comes from.
        module: String,
        /// The imported name.
        name: String,
    },
    /// The module does not export the expected entry point.
    MissingEntryPoint {
        /// The acceptable export names.
        expected: Vec<String>,
    },
    /// An annotation was refused.
    Annotation(AnnotationError),
    /// The module bytes do not match the expected digest.
    ModuleDigestMismatch {
        /// The expected digest.
        expected: String,
        /// The digest of the module bytes.
        actual: String,
    },
    /// The content of an image-volume variant is not a policy data filesystem.
    VolumeContent(String),
}

impl fmt::Display for ArtifactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArtifactError::ManifestParse(reason) => {
                write!(formatter, "the manifest does not parse: {reason}")
            }
            ArtifactError::ManifestDigestMismatch { expected, actual } => write!(
                formatter,
                "the manifest digest {expected} does not match the bytes, which hash to {actual}"
            ),
            ArtifactError::UnsupportedManifestMediaType(media_type) => {
                write!(formatter, "unsupported manifest media type {media_type}")
            }
            ArtifactError::UnsupportedManifestSchemaVersion(version) => {
                write!(formatter, "unsupported manifest schema version {version}")
            }
            ArtifactError::UnsupportedConfigMediaType(media_type) => {
                write!(formatter, "unsupported config media type {media_type}")
            }
            ArtifactError::UnsupportedLayerMediaType(media_type) => {
                write!(formatter, "unsupported layer media type {media_type}")
            }
            ArtifactError::MissingModuleLayer => {
                write!(formatter, "the artifact has no module layer")
            }
            ArtifactError::AmbiguousModuleLayers { count } => write!(
                formatter,
                "the artifact declares {count} layers, a policy module has exactly one"
            ),
            ArtifactError::ContainerFilesystemPresentedAsPolicyModule => write!(
                formatter,
                "a container filesystem was presented as a policy module"
            ),
            ArtifactError::LayerMissing { digest } => {
                write!(formatter, "the layer {digest} was not supplied")
            }
            ArtifactError::LayerDigestMismatch { expected, actual } => write!(
                formatter,
                "the layer digest {expected} does not match the bytes, which hash to {actual}"
            ),
            ArtifactError::LayerSizeMismatch { expected, actual } => write!(
                formatter,
                "the layer size {expected} does not match the {actual} bytes that were supplied"
            ),
            ArtifactError::InvalidModule(reason) => {
                write!(formatter, "the module is not usable: {reason}")
            }
            ArtifactError::ForbiddenImport { module, name } => write!(
                formatter,
                "the module imports {module}.{name}, which the allowlist does not permit"
            ),
            ArtifactError::MissingEntryPoint { expected } => write!(
                formatter,
                "the module exports none of the expected entry points {expected:?}"
            ),
            ArtifactError::Annotation(error) => write!(formatter, "{error}"),
            ArtifactError::ModuleDigestMismatch { expected, actual } => write!(
                formatter,
                "the module digest {expected} does not match the bytes, which hash to {actual}"
            ),
            ArtifactError::VolumeContent(reason) => {
                write!(
                    formatter,
                    "the volume variant is not a policy data filesystem: {reason}"
                )
            }
        }
    }
}

impl std::error::Error for ArtifactError {}

impl From<WasmError> for ArtifactError {
    fn from(error: WasmError) -> Self {
        ArtifactError::InvalidModule(error.to_string())
    }
}

/// Validate a native Wasm policy artifact.
///
/// The recorded manifest digest is checked against the manifest bytes before
/// anything else is read, because the digest pins both the module content and
/// the metadata.
pub fn validate_native_wasm_artifact(
    manifest_bytes: &[u8],
    recorded_manifest_digest: &str,
    layers: &[LayerBlob],
    allowlist: &CapabilityAllowlist,
    abi: &AbiExpectation,
) -> Result<ValidatedArtifact, ArtifactError> {
    let manifest_digest = digest_of(manifest_bytes);
    if manifest_digest != recorded_manifest_digest {
        return Err(ArtifactError::ManifestDigestMismatch {
            expected: recorded_manifest_digest.to_string(),
            actual: manifest_digest,
        });
    }

    let manifest: OciManifest = serde_json::from_slice(manifest_bytes)
        .map_err(|error| ArtifactError::ManifestParse(error.to_string()))?;

    if manifest.schema_version != 2 {
        return Err(ArtifactError::UnsupportedManifestSchemaVersion(
            manifest.schema_version,
        ));
    }
    if manifest.media_type != OCI_MANIFEST_MEDIA_TYPE {
        return Err(ArtifactError::UnsupportedManifestMediaType(
            manifest.media_type.clone(),
        ));
    }
    if manifest.config.media_type == OCI_IMAGE_CONFIG_MEDIA_TYPE {
        return Err(ArtifactError::ContainerFilesystemPresentedAsPolicyModule);
    }
    if manifest.config.media_type != WASM_CONFIG_MEDIA_TYPE {
        return Err(ArtifactError::UnsupportedConfigMediaType(
            manifest.config.media_type.clone(),
        ));
    }

    if manifest.layers.is_empty() {
        return Err(ArtifactError::MissingModuleLayer);
    }
    if manifest.layers.len() > 1 {
        return Err(ArtifactError::AmbiguousModuleLayers {
            count: manifest.layers.len(),
        });
    }

    let descriptor = &manifest.layers[0];
    if descriptor.media_type == OCI_TAR_LAYER_MEDIA_TYPE
        || descriptor.media_type == OCI_GZIP_LAYER_MEDIA_TYPE
    {
        return Err(ArtifactError::ContainerFilesystemPresentedAsPolicyModule);
    }
    if descriptor.media_type != WASM_LAYER_MEDIA_TYPE {
        return Err(ArtifactError::UnsupportedLayerMediaType(
            descriptor.media_type.clone(),
        ));
    }

    let blob = layers
        .iter()
        .find(|blob| blob.digest == descriptor.digest)
        .ok_or_else(|| ArtifactError::LayerMissing {
            digest: descriptor.digest.clone(),
        })?;

    let actual_layer_digest = digest_of(&blob.bytes);
    if actual_layer_digest != descriptor.digest {
        return Err(ArtifactError::LayerDigestMismatch {
            expected: descriptor.digest.clone(),
            actual: actual_layer_digest,
        });
    }
    if blob.size() != descriptor.size {
        return Err(ArtifactError::LayerSizeMismatch {
            expected: descriptor.size,
            actual: blob.size(),
        });
    }

    let facts = inspect(&blob.bytes)?;
    validate_module(&blob.bytes)?;
    validate_module_policy(&facts, allowlist, abi)?;

    let annotations =
        PolicyAnnotations::parse(&manifest.annotations).map_err(ArtifactError::Annotation)?;

    Ok(ValidatedArtifact {
        manifest,
        manifest_digest,
        module: blob.bytes.clone(),
        module_sha256: sha256_hex(&blob.bytes),
        annotations,
    })
}

/// Check a module's imports and entry point against the local allowlist and
/// the expected ABI.
///
/// Both artifact paths run the same check: media types and digests alone are
/// never proof that the packaged module may run (ADR-0004 section 4.4).
fn validate_module_policy(
    facts: &crate::oci::wasm::ModuleFacts,
    allowlist: &CapabilityAllowlist,
    abi: &AbiExpectation,
) -> Result<(), ArtifactError> {
    for import in &facts.imports {
        if import.kind != ImportKind::Function {
            return Err(ArtifactError::ForbiddenImport {
                module: import.module.clone(),
                name: import.name.clone(),
            });
        }
        if !allowlist.permits(&import.module, &import.name) {
            return Err(ArtifactError::ForbiddenImport {
                module: import.module.clone(),
                name: import.name.clone(),
            });
        }
    }

    if !abi
        .entry_point_exports()
        .iter()
        .any(|expected| facts.exports.iter().any(|export| export == expected))
    {
        return Err(ArtifactError::MissingEntryPoint {
            expected: abi.entry_point_exports().to_vec(),
        });
    }

    Ok(())
}

/// Validate an image-volume policy artifact.
///
/// The volume is a read-only data filesystem: it holds the module and its
/// metadata, and nothing else. The module is verified against the digest that
/// the release metadata records.
pub fn validate_volume_artifact(
    manifest_bytes: &[u8],
    recorded_manifest_digest: &str,
    layers: &[LayerBlob],
    expected_module_sha256: Option<&str>,
    allowlist: &CapabilityAllowlist,
    abi: &AbiExpectation,
) -> Result<ValidatedVolumeArtifact, ArtifactError> {
    let manifest_digest = digest_of(manifest_bytes);
    if manifest_digest != recorded_manifest_digest {
        return Err(ArtifactError::ManifestDigestMismatch {
            expected: recorded_manifest_digest.to_string(),
            actual: manifest_digest,
        });
    }

    let manifest: OciManifest = serde_json::from_slice(manifest_bytes)
        .map_err(|error| ArtifactError::ManifestParse(error.to_string()))?;

    if manifest.schema_version != 2 {
        return Err(ArtifactError::UnsupportedManifestSchemaVersion(
            manifest.schema_version,
        ));
    }
    if manifest.media_type != OCI_MANIFEST_MEDIA_TYPE {
        return Err(ArtifactError::UnsupportedManifestMediaType(
            manifest.media_type.clone(),
        ));
    }
    if manifest.config.media_type != OCI_IMAGE_CONFIG_MEDIA_TYPE {
        return Err(ArtifactError::UnsupportedConfigMediaType(
            manifest.config.media_type.clone(),
        ));
    }

    if manifest.layers.is_empty() {
        return Err(ArtifactError::MissingModuleLayer);
    }
    if manifest.layers.len() > 1 {
        return Err(ArtifactError::AmbiguousModuleLayers {
            count: manifest.layers.len(),
        });
    }

    let descriptor = &manifest.layers[0];
    if descriptor.media_type != OCI_TAR_LAYER_MEDIA_TYPE {
        return Err(ArtifactError::UnsupportedLayerMediaType(
            descriptor.media_type.clone(),
        ));
    }

    let blob = layers
        .iter()
        .find(|blob| blob.digest == descriptor.digest)
        .ok_or_else(|| ArtifactError::LayerMissing {
            digest: descriptor.digest.clone(),
        })?;

    let actual_layer_digest = digest_of(&blob.bytes);
    if actual_layer_digest != descriptor.digest {
        return Err(ArtifactError::LayerDigestMismatch {
            expected: descriptor.digest.clone(),
            actual: actual_layer_digest,
        });
    }
    if blob.size() != descriptor.size {
        return Err(ArtifactError::LayerSizeMismatch {
            expected: descriptor.size,
            actual: blob.size(),
        });
    }

    let entries = tar::read_entries(&blob.bytes)
        .map_err(|error| ArtifactError::VolumeContent(error.to_string()))?;

    if entries.len() != 2 {
        return Err(ArtifactError::VolumeContent(format!(
            "the volume holds {} files, a policy data filesystem holds exactly the module and its metadata",
            entries.len()
        )));
    }

    for entry in &entries {
        if entry.mode & 0o111 != 0 {
            return Err(ArtifactError::VolumeContent(format!(
                "{} is executable, a policy data filesystem has no executables",
                entry.path
            )));
        }
        if entry.path != POLICY_MODULE_FILE && entry.path != POLICY_METADATA_FILE {
            return Err(ArtifactError::VolumeContent(format!(
                "{} is not part of a policy data filesystem",
                entry.path
            )));
        }
    }

    let module_entry = entries
        .iter()
        .find(|entry| entry.path == POLICY_MODULE_FILE)
        .ok_or_else(|| ArtifactError::VolumeContent(format!("{POLICY_MODULE_FILE} is missing")))?;
    let metadata_entry = entries
        .iter()
        .find(|entry| entry.path == POLICY_METADATA_FILE)
        .ok_or_else(|| {
            ArtifactError::VolumeContent(format!("{POLICY_METADATA_FILE} is missing"))
        })?;

    let metadata = PolicyMetadata::from_json_bytes(&metadata_entry.data)
        .map_err(|error| ArtifactError::VolumeContent(error.to_string()))?;

    let module_sha256 = sha256_hex(&module_entry.data);
    if metadata.module_sha256 != module_sha256 {
        return Err(ArtifactError::ModuleDigestMismatch {
            expected: metadata.module_sha256.clone(),
            actual: module_sha256,
        });
    }
    if metadata.module_size != module_entry.data.len() as u64 {
        return Err(ArtifactError::VolumeContent(format!(
            "the metadata records {} module bytes, the volume holds {}",
            metadata.module_size,
            module_entry.data.len()
        )));
    }
    if let Some(expected) = expected_module_sha256 {
        if expected != module_sha256 {
            return Err(ArtifactError::ModuleDigestMismatch {
                expected: expected.to_string(),
                actual: module_sha256,
            });
        }
    }

    // The volume path runs the same module validation as the native path: a
    // data filesystem that carries the module is still handing the bytes to a
    // host, so the import allowlist and the ABI entry point are checked here
    // and not only at the native seam.
    let facts = inspect(&module_entry.data)?;
    validate_module(&module_entry.data)?;
    validate_module_policy(&facts, allowlist, abi)?;

    Ok(ValidatedVolumeArtifact {
        manifest,
        manifest_digest,
        module: module_entry.data.clone(),
        module_sha256,
        metadata,
    })
}
