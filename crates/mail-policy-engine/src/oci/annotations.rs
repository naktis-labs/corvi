//! The Corvi policy annotations.
//!
//! ADR-0004 section 4.4 allows annotations to describe a policy module: its
//! ABI, its input schema version, its display name and its build provenance.
//! The same section states that annotations cannot grant host capabilities.
//!
//! This module therefore refuses any annotation in the Corvi policy namespace
//! that tries to claim capabilities: capabilities are granted by the local
//! import allowlist and by nothing else. The refusal is an error rather than a
//! silent ignore, because an artifact that claims a capability it does not
//! have is not describing itself honestly.

use std::collections::BTreeMap;
use std::fmt;

/// The namespace of the Corvi policy annotations.
pub const CORVI_POLICY_ANNOTATION_PREFIX: &str = "eu.naktis.corvi.policy.";

/// The annotation naming the policy ABI.
pub const ABI_ANNOTATION: &str = "eu.naktis.corvi.policy.abi";

/// The annotation naming the input schema version.
pub const INPUT_SCHEMA_ANNOTATION: &str = "eu.naktis.corvi.policy.input-schema";

/// The annotation naming the human readable name of the policy.
pub const DISPLAY_NAME_ANNOTATION: &str = "eu.naktis.corvi.policy.display-name";

/// The annotation naming the build provenance of the policy.
pub const PROVENANCE_ANNOTATION: &str = "eu.naktis.corvi.policy.provenance";

/// The longest annotation value this module accepts.
pub const MAX_ANNOTATION_VALUE_LENGTH: usize = 512;

/// The Corvi annotations of a policy artifact.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyAnnotations {
    /// The policy ABI the module implements.
    pub abi: Option<String>,
    /// The input schema version the module expects.
    pub input_schema: Option<String>,
    /// The human readable name of the policy.
    pub display_name: Option<String>,
    /// The build provenance of the module.
    pub provenance: Option<String>,
}

/// Why an annotation was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnnotationError {
    /// An annotation tried to grant a host capability.
    ///
    /// Capabilities are granted by the import allowlist, never by metadata.
    CapabilitiesNotGrantable(String),
    /// An annotation value is empty or too long.
    InvalidValue {
        /// The annotation key.
        key: String,
        /// Why the value was refused.
        reason: String,
    },
}

impl fmt::Display for AnnotationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AnnotationError::CapabilitiesNotGrantable(key) => write!(
                formatter,
                "the annotation {key} tries to grant a capability, which annotations never do"
            ),
            AnnotationError::InvalidValue { key, reason } => {
                write!(formatter, "the annotation {key} is invalid: {reason}")
            }
        }
    }
}

impl std::error::Error for AnnotationError {}

impl PolicyAnnotations {
    /// Parse the Corvi annotations of a manifest.
    ///
    /// Unknown annotations are ignored: OCI annotations are an open namespace.
    /// An annotation that claims a capability is refused.
    pub fn parse(annotations: &BTreeMap<String, String>) -> Result<Self, AnnotationError> {
        let mut parsed = PolicyAnnotations::default();

        for (key, value) in annotations {
            if key.starts_with(CORVI_POLICY_ANNOTATION_PREFIX)
                && key[CORVI_POLICY_ANNOTATION_PREFIX.len()..].contains("capabilit")
            {
                return Err(AnnotationError::CapabilitiesNotGrantable(key.clone()));
            }

            let target = match key.as_str() {
                ABI_ANNOTATION => &mut parsed.abi,
                INPUT_SCHEMA_ANNOTATION => &mut parsed.input_schema,
                DISPLAY_NAME_ANNOTATION => &mut parsed.display_name,
                PROVENANCE_ANNOTATION => &mut parsed.provenance,
                _ => continue,
            };

            if value.trim().is_empty() {
                return Err(AnnotationError::InvalidValue {
                    key: key.clone(),
                    reason: "the value is empty".to_string(),
                });
            }
            if value.len() > MAX_ANNOTATION_VALUE_LENGTH {
                return Err(AnnotationError::InvalidValue {
                    key: key.clone(),
                    reason: format!("the value is longer than {MAX_ANNOTATION_VALUE_LENGTH} bytes"),
                });
            }
            *target = Some(value.clone());
        }

        Ok(parsed)
    }
}
