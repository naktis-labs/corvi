//! The OCI image manifest and its descriptors.
//!
//! ADR-0004 section 4.4 uses the CNCF Wasm OCI artifact layout: an
//! `application/vnd.oci.image.manifest.v1+json` manifest whose config is an
//! `application/vnd.wasm.config.v0+json` descriptor and whose single layer
//! is an `application/wasm` blob.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The OCI image manifest media type.
pub const OCI_MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";

/// The Wasm artifact configuration media type.
pub const WASM_CONFIG_MEDIA_TYPE: &str = "application/vnd.wasm.config.v0+json";

/// The Wasm module layer media type.
pub const WASM_LAYER_MEDIA_TYPE: &str = "application/wasm";

/// The standard OCI image configuration media type.
pub const OCI_IMAGE_CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.image.config.v1+json";

/// The uncompressed tar layer media type used by the image-volume variant.
pub const OCI_TAR_LAYER_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar";

/// The gzip compressed tar layer media type.
pub const OCI_GZIP_LAYER_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar+gzip";

/// A content descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Descriptor {
    /// The media type of the referenced content.
    #[serde(rename = "mediaType")]
    pub media_type: String,
    /// The digest of the referenced content.
    pub digest: String,
    /// The size of the referenced content in bytes.
    pub size: i64,
    /// Optional annotations for the referenced content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<BTreeMap<String, String>>,
}

/// An OCI image manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciManifest {
    /// The manifest schema version.
    #[serde(rename = "schemaVersion")]
    pub schema_version: i64,
    /// The media type of the manifest.
    #[serde(rename = "mediaType")]
    pub media_type: String,
    /// The descriptor of the configuration blob.
    pub config: Descriptor,
    /// The descriptors of the layer blobs.
    #[serde(default)]
    pub layers: Vec<Descriptor>,
    /// The annotations of the manifest.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}
