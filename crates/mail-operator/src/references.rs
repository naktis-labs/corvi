//! The reference contract of ADR-0013.
//!
//! Every Corvi mail resource points at its parent with a **singular,
//! strongly typed, same-namespace** reference. Two of those references are
//! required (`Mailbox.spec.providerRef`, `MailIdentity.spec.mailboxRef`) and
//! one is optional (`MailProvider.spec.gatewayRef`).
//!
//! The rules this module encodes:
//!
//! * A required reference that is absent is an error, never a fallback.
//! * A specified reference that cannot be resolved is an error, never a
//!   fallback to some other object.
//! * There is **no default gateway**: an omitted `gatewayRef` leaves the
//!   provider unbound, and an unbound provider contributes no identities to
//!   any gateway.
//! * A reference never crosses a namespace boundary.
//! * The chain is logical. It is not a Kubernetes `ownerReference`, so nothing
//!   is garbage collected through it.

use std::fmt;

use crate::model::{LocalRef, ObjectMeta, ResourceKind};

/// A namespace-qualified resource name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResourceKey {
    /// The namespace the object lives in.
    pub namespace: String,
    /// The object name.
    pub name: String,
}

impl ResourceKey {
    /// Build a key.
    pub fn new(namespace: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            name: name.into(),
        }
    }
}

impl fmt::Display for ResourceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.namespace, self.name)
    }
}

/// Why a reference could not be resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReferenceError {
    /// A required parent reference is absent.
    MissingRequiredReference {
        /// The kind that carries the reference.
        kind: ResourceKind,
        /// The field that must be set.
        field: &'static str,
    },
    /// A reference is not a usable object name.
    MalformedReference {
        /// The kind that carries the reference.
        kind: ResourceKind,
        /// The field that carries the reference.
        field: &'static str,
        /// Why the reference is malformed.
        reason: &'static str,
    },
    /// A reference points at another namespace.
    CrossNamespaceReference {
        /// The kind that carries the reference.
        kind: ResourceKind,
        /// The field that carries the reference.
        field: &'static str,
        /// The namespace the reference asked for.
        referenced: String,
        /// The namespace the reference must stay in.
        owner: String,
    },
    /// A specified reference points at an object that does not exist.
    DanglingReference {
        /// The kind that carries the reference.
        kind: ResourceKind,
        /// The field that carries the reference.
        field: &'static str,
        /// The object that could not be found.
        target: ResourceKey,
        /// The kind the reference must point at.
        expected: ResourceKind,
    },
    /// A reference points at an object of the wrong kind.
    KindMismatch {
        /// The kind that carries the reference.
        kind: ResourceKind,
        /// The field that carries the reference.
        field: &'static str,
        /// The object the reference points at.
        target: ResourceKey,
        /// The kind the reference must point at.
        expected: ResourceKind,
    },
    /// The object that was asked for is not in the graph.
    UnknownResource {
        /// The kind that was asked for.
        kind: ResourceKind,
        /// The object that is missing.
        target: ResourceKey,
    },
    /// A mailbox names a provider that serves no mailbox of its own.
    ManagementOnlyProvider {
        /// The management-only provider.
        provider: ResourceKey,
    },
    /// A management-only provider is bound to a gateway.
    ManagementOnlyProviderBound {
        /// The management-only provider.
        provider: ResourceKey,
    },
    /// A provider is suspended.
    SuspendedProvider {
        /// The suspended provider.
        provider: ResourceKey,
    },
    /// A gateway is suspended.
    SuspendedGateway {
        /// The suspended gateway.
        gateway: ResourceKey,
    },
    /// An identity cannot be published because it is incomplete.
    IncompleteIdentity {
        /// The incomplete identity.
        identity: ResourceKey,
        /// Why the identity cannot be published.
        reason: &'static str,
    },
    /// A provider that must be bound to a gateway is not.
    UnboundProvider {
        /// The unbound provider.
        provider: ResourceKey,
    },
}

impl fmt::Display for ReferenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingRequiredReference { kind, field } => {
                write!(f, "{kind} requires {field}")
            }
            Self::MalformedReference {
                kind,
                field,
                reason,
            } => {
                write!(f, "{kind} {field} is malformed: {reason}")
            }
            Self::CrossNamespaceReference {
                kind,
                field,
                referenced,
                owner,
            } => write!(
                f,
                "{kind} {field} may not leave namespace {owner} for {referenced}"
            ),
            Self::DanglingReference {
                kind,
                field,
                target,
                expected,
            } => write!(
                f,
                "{kind} {field} points at {target}, which is not an existing {expected}"
            ),
            Self::KindMismatch {
                kind,
                field,
                target,
                expected,
            } => write!(
                f,
                "{kind} {field} points at {target}, which is not a {expected}"
            ),
            Self::UnknownResource { kind, target } => {
                write!(f, "no {kind} named {target} exists")
            }
            Self::ManagementOnlyProvider { provider } => write!(
                f,
                "provider {provider} administers other providers and owns no mailbox"
            ),
            Self::ManagementOnlyProviderBound { provider } => write!(
                f,
                "provider {provider} administers other providers and may not be bound to a gateway"
            ),
            Self::SuspendedProvider { provider } => write!(f, "provider {provider} is suspended"),
            Self::SuspendedGateway { gateway } => write!(f, "gateway {gateway} is suspended"),
            Self::IncompleteIdentity { identity, reason } => {
                write!(f, "identity {identity} cannot be published: {reason}")
            }
            Self::UnboundProvider { provider } => write!(
                f,
                "provider {provider} is not bound to a gateway and cannot serve mail"
            ),
        }
    }
}

impl std::error::Error for ReferenceError {}

/// Whether a value is a usable Kubernetes object name.
///
/// The rule is the DNS-1123 label rule the reference schemas use.
pub fn is_valid_object_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && value.ends_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Validate one reference against the object that carries it.
///
/// The returned key is the object the reference points at, in the owner's own
/// namespace.
pub fn validate_local_ref(
    owner: &ObjectMeta,
    kind: ResourceKind,
    field: &'static str,
    reference: &LocalRef,
) -> Result<ResourceKey, ReferenceError> {
    if reference.name.trim().is_empty() {
        return Err(ReferenceError::MalformedReference {
            kind,
            field,
            reason: "the name is empty",
        });
    }
    if !is_valid_object_name(&reference.name) {
        return Err(ReferenceError::MalformedReference {
            kind,
            field,
            reason: "the name is not a valid Kubernetes object name",
        });
    }
    if let Some(namespace) = &reference.namespace
        && namespace != &owner.namespace
    {
        return Err(ReferenceError::CrossNamespaceReference {
            kind,
            field,
            referenced: namespace.clone(),
            owner: owner.namespace.clone(),
        });
    }
    Ok(ResourceKey::new(
        owner.namespace.clone(),
        reference.name.clone(),
    ))
}
