//! The Secret policy: which annotations a published Secret may carry.
//!
//! A user-defined annotation can invoke a Secret-copying or reloading
//! controller, so an annotation is a way to hand a credential to something
//! else. ADR-0014 section 1 therefore requires an explicit allow-policy
//! rather than an open field.
//!
//! The policy is also the single place that knows which annotations are
//! reserved. Corvi's own `corvi.naktis.eu/*` annotations are the
//! controller's, and the Kubernetes service-account token annotation would
//! turn the Secret into a token request, so both are refused whatever the
//! allow-list says.
//!
//! Cross-namespace propagation is prevented structurally rather than by
//! policy: a Secret is always written in the namespace of the credential
//! that owns it.

use std::collections::{BTreeMap, BTreeSet};

use crate::publisher::PublishError;

/// Annotation prefixes that may never be written to a published Secret.
pub const RESERVED_ANNOTATION_PREFIXES: &[&str] =
    &["corvi.naktis.eu/", "kubernetes.io/service-account-token"];

/// Which annotations a publisher may write.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SecretPolicy {
    allowed_prefixes: Vec<String>,
    allowed_keys: BTreeSet<String>,
}

impl SecretPolicy {
    /// A policy that approves no annotation at all.
    ///
    /// This is the default: an annotation is a request to move a credential
    /// somewhere else, so it has to be named before it is allowed.
    pub fn deny_all() -> Self {
        Self::default()
    }

    /// Approve every annotation with a prefix.
    pub fn allow_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.allowed_prefixes.push(prefix.into());
        self
    }

    /// Approve one annotation.
    pub fn allow_key(mut self, key: impl Into<String>) -> Self {
        self.allowed_keys.insert(key.into());
        self
    }

    /// Whether one annotation may be written.
    pub fn is_allowed(&self, key: &str) -> bool {
        if RESERVED_ANNOTATION_PREFIXES
            .iter()
            .any(|prefix| key.starts_with(prefix))
        {
            return false;
        }
        if self.allowed_keys.contains(key) {
            return true;
        }
        self.allowed_prefixes
            .iter()
            .any(|prefix| key.starts_with(prefix.as_str()))
    }

    /// Check a whole set of annotations.
    pub fn check(&self, annotations: &BTreeMap<String, String>) -> Result<(), PublishError> {
        for key in annotations.keys() {
            if !self.is_allowed(key) {
                return Err(PublishError::UnsafeAnnotation { key: key.clone() });
            }
        }
        Ok(())
    }
}
