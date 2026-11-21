//! The disclosure policies the gateway applies, and how they bind to identities.
//!
//! ADR-0003 assigns filter policies to identities, and ADR-0005 makes the
//! policy revision part of what a cursor is bound to. The policies therefore
//! live in their own configuration document rather than inside the credential
//! snapshot: the snapshot holds who may act, the policy document holds what
//! they may see.
//!
//! An identity with no policy binding is **fail closed**: nothing is
//! disclosed for it. A gateway that forgot to configure a policy must not
//! fall back to showing everything.

use std::collections::{BTreeMap, BTreeSet};

use mail_core::IdentityId;
use mail_policy::FilterPolicy;
use serde::Deserialize;

/// The policy configuration document.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    /// The policy revision.
    ///
    /// Cursors and approvals are bound to this number, so activating a new
    /// generation invalidates the ones issued under the old one.
    #[serde(default = "default_generation")]
    pub generation: u64,
    /// The available policies.
    #[serde(default)]
    pub policies: Vec<FilterPolicy>,
    /// Which policy applies to which identity.
    #[serde(default)]
    pub bindings: BTreeMap<String, String>,
    /// Identities that may send without an interactive approval.
    ///
    /// This is the "explicitly authorized unattended automation" exception
    /// `docs/spec/mcp.md` section 4 describes. It never bypasses the action,
    /// identity or recipient checks; it only removes the approval round trip.
    #[serde(default)]
    pub unattended_send: BTreeSet<String>,
}

fn default_generation() -> u64 {
    1
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            generation: default_generation(),
            policies: Vec::new(),
            bindings: BTreeMap::new(),
            unattended_send: BTreeSet::new(),
        }
    }
}

/// The policies in force, with the bindings that select them.
#[derive(Debug, Clone)]
pub struct PolicyStore {
    config: PolicyConfig,
    policies: BTreeMap<String, FilterPolicy>,
}

impl PolicyStore {
    /// Build a store from a parsed configuration.
    pub fn new(config: PolicyConfig) -> Result<Self, PolicyError> {
        let mut policies = BTreeMap::new();
        for policy in &config.policies {
            if policies.insert(policy.id.clone(), policy.clone()).is_some() {
                return Err(PolicyError::DuplicatePolicy(policy.id.clone()));
            }
        }
        for (identity, policy) in &config.bindings {
            if !policies.contains_key(policy) {
                return Err(PolicyError::UnknownPolicy {
                    identity: identity.clone(),
                    policy: policy.clone(),
                });
            }
        }
        Ok(Self { config, policies })
    }

    /// Parse a policy configuration document.
    pub fn from_yaml(text: &str) -> Result<Self, PolicyConfigError> {
        let config = serde_yaml::from_str(text).map_err(PolicyConfigError::Parse)?;
        Ok(Self::new(config)?)
    }

    /// The policy revision.
    pub fn generation(&self) -> u64 {
        self.config.generation
    }

    /// The policy that applies to an identity, if one is configured.
    pub fn policy_for(&self, identity: &IdentityId) -> Option<&FilterPolicy> {
        let policy_id = self.config.bindings.get(identity.as_str())?;
        self.policies.get(policy_id)
    }

    /// Whether an identity may send without an interactive approval.
    pub fn allows_unattended_send(&self, identity: &IdentityId) -> bool {
        self.config.unattended_send.contains(identity.as_str())
    }

    /// The configured policy identifiers.
    pub fn policy_ids(&self) -> impl Iterator<Item = &str> {
        self.policies.keys().map(String::as_str)
    }
}

/// Why a policy configuration was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// Two policies share an identifier.
    DuplicatePolicy(String),
    /// A binding names a policy that does not exist.
    UnknownPolicy {
        /// The identity the binding names.
        identity: String,
        /// The policy the binding names.
        policy: String,
    },
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyError::DuplicatePolicy(id) => write!(f, "duplicate policy '{id}'"),
            PolicyError::UnknownPolicy { identity, policy } => {
                write!(f, "identity '{identity}' binds unknown policy '{policy}'")
            }
        }
    }
}

impl std::error::Error for PolicyError {}

/// Why a policy document could not be read.
#[derive(Debug)]
pub enum PolicyConfigError {
    /// The document is not valid YAML or does not match the schema.
    Parse(serde_yaml::Error),
    /// The document parsed but is not usable.
    Invalid(PolicyError),
}

impl std::fmt::Display for PolicyConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyConfigError::Parse(error) => write!(f, "policy configuration: {error}"),
            PolicyConfigError::Invalid(error) => write!(f, "policy configuration: {error}"),
        }
    }
}

impl std::error::Error for PolicyConfigError {}

impl From<PolicyError> for PolicyConfigError {
    fn from(error: PolicyError) -> Self {
        PolicyConfigError::Invalid(error)
    }
}
