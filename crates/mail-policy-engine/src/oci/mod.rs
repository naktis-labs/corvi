//! OCI packaging for Corvi policy modules.
//!
//! ADR-0004 section 4.4 describes the two release variants of a policy
//! artifact, and this module implements the parts of that description which
//! can be checked without a registry:
//!
//! * [`manifest`] — the OCI image manifest and its descriptors.
//! * [`annotations`] — the Corvi policy annotations. They may describe a
//!   module; they may never grant a capability.
//! * [`wasm`] — module inspection with `wasmparser` and the import allowlist.
//! * [`tar`] — the minimal read-only tar writer and reader used by the
//!   image-volume variant.
//! * [`artifact`] — validation of both variants, including digest pinning.
//! * [`build`] — the paired release builder.
//!
//! No registry client is implemented here: an artifact is validated from the
//! bytes a caller already fetched, and the caller is responsible for the
//! transport and for the publisher trust policy.

pub mod annotations;
pub mod artifact;
pub mod build;
pub mod digest;
pub mod manifest;
pub mod tar;
pub mod wasm;

pub use artifact::{
    ArtifactError, LayerBlob, PreparedPolicyModule, ValidatedArtifact, ValidatedVolumeArtifact,
    validate_native_wasm_artifact, validate_volume_artifact,
};
pub use build::{BuildError, OciArtifact, PolicyMetadata, ReleaseVariants, build_release_variants};
