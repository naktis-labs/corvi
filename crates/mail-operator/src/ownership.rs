//! The mail-resource ownership graph.
//!
//! ADR-0013 gives every mail resource exactly one parent: an identity belongs
//! to a mailbox, a mailbox belongs to a provider, and a provider may be bound
//! to one gateway. The gateway holds **no** inverse list of children, so the
//! effective identity set of a gateway is derived by following the chain
//! outwards from the gateway's bound providers.
//!
//! This module holds that graph and the decisions taken on it.

use std::collections::BTreeMap;
use std::fmt;

use crate::model::{CorviGateway, MailIdentity, MailProvider, Mailbox, ProviderRole, ResourceKind};
use crate::references::{ReferenceError, ResourceKey, validate_local_ref};

/// Why a resource could not be added to the graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphError {
    /// Two resources claimed the same namespace and name.
    DuplicateResource {
        /// The kind of the duplicated resource.
        kind: ResourceKind,
        /// The key that was claimed twice.
        key: ResourceKey,
    },
}

impl fmt::Display for GraphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateResource { kind, key } => {
                write!(f, "two {kind} resources claim {key}")
            }
        }
    }
}

impl std::error::Error for GraphError {}

/// How a provider is attached to the runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderBinding {
    /// The provider names exactly one gateway.
    Bound {
        /// The gateway the provider is bound to.
        gateway: ResourceKey,
    },
    /// The provider names no gateway.
    ///
    /// An unbound provider is administered normally, and none of its
    /// mailboxes or identities are served by any gateway. There is no default
    /// gateway: an unbound provider stays unbound.
    Unbound,
}

/// A mailbox with its resolved parent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedMailbox {
    /// The mailbox itself.
    pub mailbox: ResourceKey,
    /// The provider the mailbox belongs to.
    pub provider: ResourceKey,
    /// How the provider is attached to the runtime.
    pub binding: ProviderBinding,
}

/// An identity with its resolved parent chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedIdentity {
    /// The identity itself.
    pub identity: ResourceKey,
    /// The mailbox the identity belongs to.
    pub mailbox: ResourceKey,
    /// The provider the mailbox belongs to.
    pub provider: ResourceKey,
    /// How the provider is attached to the runtime.
    pub binding: ProviderBinding,
    /// The address the identity sends from.
    pub address: String,
}

/// The effective view of one gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayView {
    /// The gateway the view belongs to.
    pub gateway: ResourceKey,
    /// Whether the gateway is paused.
    pub suspended: bool,
    /// The providers explicitly bound to this gateway.
    pub providers: Vec<ResourceKey>,
    /// The identities this gateway serves.
    pub identities: Vec<ResolvedIdentity>,
    /// The problems found while resolving the graph.
    ///
    /// A problem removes the affected subtree from the effective set; it never
    /// removes it silently.
    pub problems: Vec<ReferenceError>,
}

/// The set of resources the operator watches.
#[derive(Debug, Clone, Default)]
pub struct ResourceGraph {
    gateways: BTreeMap<ResourceKey, CorviGateway>,
    providers: BTreeMap<ResourceKey, MailProvider>,
    mailboxes: BTreeMap<ResourceKey, Mailbox>,
    identities: BTreeMap<ResourceKey, MailIdentity>,
}

impl ResourceGraph {
    /// An empty graph.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a gateway.
    pub fn insert_gateway(&mut self, gateway: CorviGateway) -> Result<(), GraphError> {
        let key = ResourceKey::new(&gateway.metadata.namespace, &gateway.metadata.name);
        if self.gateways.contains_key(&key) {
            return Err(GraphError::DuplicateResource {
                kind: ResourceKind::CorviGateway,
                key,
            });
        }
        self.gateways.insert(key, gateway);
        Ok(())
    }

    /// Add a provider.
    pub fn insert_provider(&mut self, provider: MailProvider) -> Result<(), GraphError> {
        let key = ResourceKey::new(&provider.metadata.namespace, &provider.metadata.name);
        if self.providers.contains_key(&key) {
            return Err(GraphError::DuplicateResource {
                kind: ResourceKind::MailProvider,
                key,
            });
        }
        self.providers.insert(key, provider);
        Ok(())
    }

    /// Add a mailbox.
    pub fn insert_mailbox(&mut self, mailbox: Mailbox) -> Result<(), GraphError> {
        let key = ResourceKey::new(&mailbox.metadata.namespace, &mailbox.metadata.name);
        if self.mailboxes.contains_key(&key) {
            return Err(GraphError::DuplicateResource {
                kind: ResourceKind::Mailbox,
                key,
            });
        }
        self.mailboxes.insert(key, mailbox);
        Ok(())
    }

    /// Add an identity.
    pub fn insert_identity(&mut self, identity: MailIdentity) -> Result<(), GraphError> {
        let key = ResourceKey::new(&identity.metadata.namespace, &identity.metadata.name);
        if self.identities.contains_key(&key) {
            return Err(GraphError::DuplicateResource {
                kind: ResourceKind::MailIdentity,
                key,
            });
        }
        self.identities.insert(key, identity);
        Ok(())
    }

    /// The gateway with this key, if it exists.
    pub fn gateway(&self, key: &ResourceKey) -> Option<&CorviGateway> {
        self.gateways.get(key)
    }

    /// The provider with this key, if it exists.
    pub fn provider(&self, key: &ResourceKey) -> Option<&MailProvider> {
        self.providers.get(key)
    }

    /// The mailbox with this key, if it exists.
    pub fn mailbox(&self, key: &ResourceKey) -> Option<&Mailbox> {
        self.mailboxes.get(key)
    }

    /// The identity with this key, if it exists.
    pub fn identity(&self, key: &ResourceKey) -> Option<&MailIdentity> {
        self.identities.get(key)
    }

    /// Every provider in the graph.
    pub fn providers(&self) -> impl Iterator<Item = &MailProvider> {
        self.providers.values()
    }

    /// Every identity in the graph.
    pub fn identities(&self) -> impl Iterator<Item = &MailIdentity> {
        self.identities.values()
    }

    /// Resolve how a provider is attached to the runtime.
    ///
    /// An omitted `spec.gatewayRef` leaves the provider **unbound**. There is
    /// no default gateway: an unbound provider is never attached to an
    /// implicit one, and a specified reference that does not resolve is an
    /// error rather than a fallback to some other gateway.
    pub fn resolve_provider_binding(
        &self,
        provider: &ResourceKey,
    ) -> Result<ProviderBinding, ReferenceError> {
        let provider = self
            .providers
            .get(provider)
            .ok_or(ReferenceError::UnknownResource {
                kind: ResourceKind::MailProvider,
                target: provider.clone(),
            })?;
        self.provider_binding_of(provider)
    }

    /// Resolve a mailbox and its parent provider.
    pub fn resolve_mailbox(
        &self,
        mailbox: &ResourceKey,
    ) -> Result<ResolvedMailbox, ReferenceError> {
        let object = self
            .mailboxes
            .get(mailbox)
            .ok_or(ReferenceError::UnknownResource {
                kind: ResourceKind::Mailbox,
                target: mailbox.clone(),
            })?;
        self.resolve_mailbox_from(object)
    }

    /// Resolve an identity and its whole parent chain.
    pub fn resolve_identity(
        &self,
        identity: &ResourceKey,
    ) -> Result<ResolvedIdentity, ReferenceError> {
        let object = self
            .identities
            .get(identity)
            .ok_or(ReferenceError::UnknownResource {
                kind: ResourceKind::MailIdentity,
                target: identity.clone(),
            })?;
        let Some(reference) = &object.spec.mailbox_ref else {
            return Err(ReferenceError::MissingRequiredReference {
                kind: ResourceKind::MailIdentity,
                field: "spec.mailboxRef",
            });
        };
        let target = validate_local_ref(
            &object.metadata,
            ResourceKind::MailIdentity,
            "spec.mailboxRef",
            reference,
        )?;
        let mailbox = self.resolve_mailbox_from(self.mailboxes.get(&target).ok_or(
            ReferenceError::DanglingReference {
                kind: ResourceKind::MailIdentity,
                field: "spec.mailboxRef",
                target: target.clone(),
                expected: ResourceKind::Mailbox,
            },
        )?)?;
        let Some(address) = object.spec.address.clone() else {
            return Err(ReferenceError::IncompleteIdentity {
                identity: identity.clone(),
                reason: "it has no address",
            });
        };
        Ok(ResolvedIdentity {
            identity: identity.clone(),
            mailbox: mailbox.mailbox,
            provider: mailbox.provider,
            binding: mailbox.binding,
            address,
        })
    }

    /// The effective view of one gateway.
    ///
    /// The gateway holds no inverse list of children: the effective set is
    /// derived by following the reference chain outwards from the providers
    /// that name this gateway explicitly.
    pub fn gateway_view(&self, gateway: &ResourceKey) -> GatewayView {
        let mut view = GatewayView {
            gateway: gateway.clone(),
            suspended: false,
            providers: Vec::new(),
            identities: Vec::new(),
            problems: Vec::new(),
        };
        let Some(gateway_object) = self.gateways.get(gateway) else {
            view.problems.push(ReferenceError::UnknownResource {
                kind: ResourceKind::CorviGateway,
                target: gateway.clone(),
            });
            return view;
        };
        view.suspended = gateway_object.spec.suspended;
        for (provider_key, provider) in &self.providers {
            let Ok(ProviderBinding::Bound { gateway: bound }) = self.provider_binding_of(provider)
            else {
                continue;
            };
            if &bound == gateway {
                view.providers.push(provider_key.clone());
            }
        }
        for identity_key in self.identities.keys() {
            // Only this gateway's own namespace is its business. An identity
            // in another namespace can never be bound here (references are
            // same-namespace by contract), and reporting its resolution
            // failures would disclose another namespace's resource keys.
            if identity_key.namespace != gateway.namespace {
                continue;
            }
            match self.resolve_identity(identity_key) {
                Ok(resolved) => {
                    if let ProviderBinding::Bound { gateway: bound } = &resolved.binding
                        && bound == gateway
                    {
                        view.identities.push(resolved);
                    }
                }
                Err(error) => view.problems.push(error),
            }
        }
        view
    }

    /// Resolve the binding of one provider object.
    fn provider_binding_of(
        &self,
        provider: &MailProvider,
    ) -> Result<ProviderBinding, ReferenceError> {
        let Some(reference) = &provider.spec.gateway_ref else {
            return Ok(ProviderBinding::Unbound);
        };
        if provider.spec.role == ProviderRole::ManagementOnly {
            return Err(ReferenceError::ManagementOnlyProviderBound {
                provider: ResourceKey::new(&provider.metadata.namespace, &provider.metadata.name),
            });
        }
        if provider.spec.suspended {
            return Err(ReferenceError::SuspendedProvider {
                provider: ResourceKey::new(&provider.metadata.namespace, &provider.metadata.name),
            });
        }
        let target = validate_local_ref(
            &provider.metadata,
            ResourceKind::MailProvider,
            "spec.gatewayRef",
            reference,
        )?;
        let Some(gateway) = self.gateways.get(&target) else {
            return Err(ReferenceError::DanglingReference {
                kind: ResourceKind::MailProvider,
                field: "spec.gatewayRef",
                target,
                expected: ResourceKind::CorviGateway,
            });
        };
        if gateway.spec.suspended {
            return Err(ReferenceError::SuspendedGateway { gateway: target });
        }
        Ok(ProviderBinding::Bound { gateway: target })
    }

    /// Resolve the parent of a mailbox.
    fn resolve_mailbox_from(&self, mailbox: &Mailbox) -> Result<ResolvedMailbox, ReferenceError> {
        let Some(reference) = &mailbox.spec.provider_ref else {
            return Err(ReferenceError::MissingRequiredReference {
                kind: ResourceKind::Mailbox,
                field: "spec.providerRef",
            });
        };
        let target = validate_local_ref(
            &mailbox.metadata,
            ResourceKind::Mailbox,
            "spec.providerRef",
            reference,
        )?;
        let provider = self
            .providers
            .get(&target)
            .ok_or(ReferenceError::DanglingReference {
                kind: ResourceKind::Mailbox,
                field: "spec.providerRef",
                target: target.clone(),
                expected: ResourceKind::MailProvider,
            })?;
        if provider.spec.role == ProviderRole::ManagementOnly {
            return Err(ReferenceError::ManagementOnlyProvider {
                provider: target.clone(),
            });
        }
        if provider.spec.suspended {
            return Err(ReferenceError::SuspendedProvider {
                provider: target.clone(),
            });
        }
        let binding = self.provider_binding_of(provider)?;
        Ok(ResolvedMailbox {
            mailbox: ResourceKey::new(&mailbox.metadata.namespace, &mailbox.metadata.name),
            provider: target,
            binding,
        })
    }
}

// ---------------------------------------------------------------------------
// Behaviour 2: a management-only provider owns no mailbox.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Behaviour 3: suspension.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Behaviour 4: one owner, revocation before reparenting, no cascade deletion.
// ---------------------------------------------------------------------------

/// Who owns a gateway workload.
///
/// One workload has exactly one field manager. A Helm release and the
/// operator may never manage the same Deployment or Service, and the operator
/// never adopts a Helm-owned workload implicitly (ADR-0012).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkloadOwnership {
    /// A Helm release manages the workload.
    HelmDirect,
    /// The Corvi operator manages the workload.
    OperatorManaged,
}

impl WorkloadOwnership {
    /// The name of the owner.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HelmDirect => "helmDirect",
            Self::OperatorManaged => "operatorManaged",
        }
    }
}

/// What the operator found when it looked for an existing gateway workload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExistingWorkload {
    /// The workload name.
    pub name: String,
    /// The workload namespace.
    pub namespace: String,
    /// The recorded owner.
    pub owner: WorkloadOwnership,
    /// The recorded field manager, when one is known.
    pub managed_by: Option<String>,
}

/// Why ownership could not be decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnershipError {
    /// The workload exists and belongs to another manager.
    OwnershipConflict {
        /// The workload that is already owned.
        workload: String,
        /// Its current owner.
        owner: WorkloadOwnership,
    },
    /// The gateway is suspended, so the operator adopts nothing.
    SuspendedGateway {
        /// The suspended gateway.
        gateway: ResourceKey,
    },
}

impl fmt::Display for OwnershipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OwnershipConflict { workload, owner } => write!(
                f,
                "workload {workload} is owned by {} and is not adopted",
                owner.as_str()
            ),
            Self::SuspendedGateway { gateway } => {
                write!(f, "gateway {gateway} is suspended and adopts nothing")
            }
        }
    }
}

impl std::error::Error for OwnershipError {}

/// Decide who owns a gateway workload.
///
/// The operator creates a workload it does not find, keeps a workload it
/// already owns, and refuses to take over one a Helm release owns unless a
/// migration is explicitly requested. Labels never establish ownership: a
/// label is writable by anyone who may edit the object, so it cannot be the
/// evidence of a cutover.
pub fn decide_ownership(
    gateway: &CorviGateway,
    existing: Option<&ExistingWorkload>,
    migrate: bool,
) -> Result<WorkloadOwnership, OwnershipError> {
    if gateway.spec.suspended {
        return Err(OwnershipError::SuspendedGateway {
            gateway: ResourceKey::new(&gateway.metadata.namespace, &gateway.metadata.name),
        });
    }
    let Some(existing) = existing else {
        return Ok(WorkloadOwnership::OperatorManaged);
    };
    match existing.owner {
        WorkloadOwnership::OperatorManaged => Ok(WorkloadOwnership::OperatorManaged),
        WorkloadOwnership::HelmDirect if migrate => Ok(WorkloadOwnership::OperatorManaged),
        WorkloadOwnership::HelmDirect => Err(OwnershipError::OwnershipConflict {
            workload: format!("{}/{}", existing.namespace, existing.name),
            owner: WorkloadOwnership::HelmDirect,
        }),
    }
}

/// One step of an ownership transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitionStep {
    /// Revoke an identity's effective access from a gateway.
    RevokeGatewayAccess {
        /// The gateway that loses the access.
        gateway: ResourceKey,
        /// The identity that loses the access.
        identity: ResourceKey,
    },
    /// Drop the state that was derived from the old configuration.
    InvalidateDerivedState {
        /// The identity whose derived state is dropped.
        identity: ResourceKey,
    },
    /// Publish an identity's effective access on a gateway.
    PublishGatewayAccess {
        /// The gateway that gains the access.
        gateway: ResourceKey,
        /// The identity that gains the access.
        identity: ResourceKey,
    },
}

/// Why a transition is not safe to execute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReparentingError {
    /// The plan would make an identity visible on two gateways at once.
    OverlappingAccess {
        /// The identity that would overlap.
        identity: ResourceKey,
    },
    /// The plan publishes access it never revoked.
    MissingRevocation {
        /// The identity that was published without a revocation.
        identity: ResourceKey,
    },
    /// The plan moves an identity onto the gateway it already had.
    SameGateway {
        /// The gateway that appears on both sides.
        gateway: ResourceKey,
    },
}

impl fmt::Display for ReparentingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OverlappingAccess { identity } => write!(
                f,
                "identity {identity} would be visible on two gateways at once"
            ),
            Self::MissingRevocation { identity } => write!(
                f,
                "identity {identity} is published without revoking the old gateway"
            ),
            Self::SameGateway { gateway } => {
                write!(f, "gateway {gateway} is both the source and the target")
            }
        }
    }
}

impl std::error::Error for ReparentingError {}

/// The ordered steps that move identities between gateways.
///
/// Reparenting is authorization-sensitive: the old gateway loses access
/// **before** the new gateway gains it, so an identity is never visible
/// through two gateways at once. A plan that *attaches* an identity that had
/// no gateway records no source: there is no earlier access to revoke.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReparentPlan {
    source: Option<ResourceKey>,
    target: Option<ResourceKey>,
    steps: Vec<TransitionStep>,
}

impl ReparentPlan {
    /// Build the plan that moves `identities` from `source` to `target`.
    pub fn build(
        source: ResourceKey,
        target: Option<ResourceKey>,
        identities: &[ResourceKey],
    ) -> Self {
        let mut steps = Vec::new();
        for identity in identities {
            steps.push(TransitionStep::RevokeGatewayAccess {
                gateway: source.clone(),
                identity: identity.clone(),
            });
            steps.push(TransitionStep::InvalidateDerivedState {
                identity: identity.clone(),
            });
            if let Some(target) = &target {
                steps.push(TransitionStep::PublishGatewayAccess {
                    gateway: target.clone(),
                    identity: identity.clone(),
                });
            }
        }
        Self {
            source: Some(source),
            target,
            steps,
        }
    }

    /// Build the plan that publishes identities that had no gateway.
    ///
    /// An attach is not a move: the identities were never served by a
    /// gateway, so there is no source to record and no access to revoke
    /// before publishing.
    pub fn attach(target: ResourceKey, identities: &[ResourceKey]) -> Self {
        let mut steps = Vec::new();
        for identity in identities {
            steps.push(TransitionStep::InvalidateDerivedState {
                identity: identity.clone(),
            });
            steps.push(TransitionStep::PublishGatewayAccess {
                gateway: target.clone(),
                identity: identity.clone(),
            });
        }
        Self {
            source: None,
            target: Some(target),
            steps,
        }
    }

    /// Build a plan from explicit steps.
    pub fn from_steps(
        source: Option<ResourceKey>,
        target: Option<ResourceKey>,
        steps: Vec<TransitionStep>,
    ) -> Self {
        Self {
            source,
            target,
            steps,
        }
    }

    /// The gateway that loses the access, if the identities had one.
    pub fn source(&self) -> Option<&ResourceKey> {
        self.source.as_ref()
    }

    /// The gateway that gains the access, if any.
    pub fn target(&self) -> &Option<ResourceKey> {
        &self.target
    }

    /// The ordered steps.
    pub fn steps(&self) -> &[TransitionStep] {
        &self.steps
    }

    /// Check that the plan never overlaps access.
    pub fn validate(&self) -> Result<(), ReparentingError> {
        if let (Some(source), Some(target)) = (&self.source, &self.target)
            && source == target
        {
            return Err(ReparentingError::SameGateway {
                gateway: source.clone(),
            });
        }
        for (index, step) in self.steps.iter().enumerate() {
            let TransitionStep::PublishGatewayAccess { gateway, identity } = step else {
                continue;
            };
            if Some(gateway) == self.source.as_ref() {
                return Err(ReparentingError::OverlappingAccess {
                    identity: identity.clone(),
                });
            }
            // An attach publishes access the identity never had: no earlier
            // gateway exists, so no revocation can or must precede it.
            let Some(source) = &self.source else {
                continue;
            };
            let revoke = self.steps.iter().position(|earlier| {
                matches!(
                    earlier,
                    TransitionStep::RevokeGatewayAccess { gateway: old, identity: same }
                        if old == source && same == identity
                )
            });
            match revoke {
                Some(revoke) if revoke < index => {}
                Some(_) => {
                    return Err(ReparentingError::OverlappingAccess {
                        identity: identity.clone(),
                    });
                }
                None => {
                    return Err(ReparentingError::MissingRevocation {
                        identity: identity.clone(),
                    });
                }
            }
        }
        Ok(())
    }
}

/// Find the identities whose effective gateway changed between two graphs.
pub fn detect_reparenting(previous: &ResourceGraph, current: &ResourceGraph) -> Vec<ReparentPlan> {
    let mut plans = Vec::new();
    for identity in current.identities() {
        let key = ResourceKey::new(&identity.metadata.namespace, &identity.metadata.name);
        let before = effective_gateway(previous, &key);
        let after = effective_gateway(current, &key);
        if before == after {
            continue;
        }
        let plan = match (before, after) {
            (Some(source), Some(target)) => ReparentPlan::build(source, Some(target), &[key]),
            (Some(source), None) => ReparentPlan::build(source, None, &[key]),
            (None, Some(target)) => ReparentPlan::attach(target, &[key]),
            (None, None) => continue,
        };
        plans.push(plan);
    }
    // A deleted identity is absent from `current`, so the loop above never
    // sees it. The deletion is still a reparenting transition: the gateway
    // that served the identity must lose the access, even though no identity
    // object remains to resolve.
    for identity in previous.identities() {
        let key = ResourceKey::new(&identity.metadata.namespace, &identity.metadata.name);
        if current.identity(&key).is_some() {
            continue;
        }
        if let Some(source) = effective_gateway(previous, &key) {
            plans.push(ReparentPlan::build(source, None, &[key]));
        }
    }
    plans
}

/// The gateway that currently serves an identity.
fn effective_gateway(graph: &ResourceGraph, identity: &ResourceKey) -> Option<ResourceKey> {
    let resolved = graph.resolve_identity(identity).ok()?;
    match resolved.binding {
        ProviderBinding::Bound { gateway } => Some(gateway),
        ProviderBinding::Unbound => None,
    }
}

/// A deletion the operator was asked to perform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletionRequest {
    /// The Kubernetes kind to delete.
    pub kind: String,
    /// The object name.
    pub name: String,
    /// The object namespace.
    pub namespace: String,
}

/// Why a deletion was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeletionError {
    /// The resource may never be deleted as a side effect of a Corvi change.
    ProtectedResource {
        /// The kind that was refused.
        kind: String,
        /// The object that was refused.
        name: String,
    },
    /// Resources still depend on the object being deleted.
    DependentsRemain {
        /// The dependents that must be detached or migrated first.
        dependents: Vec<ResourceKey>,
    },
}

impl fmt::Display for DeletionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProtectedResource { kind, name } => write!(
                f,
                "{kind} {name} is protected and is never deleted by the operator"
            ),
            Self::DependentsRemain { dependents } => {
                write!(f, "{} dependents must be detached first", dependents.len())
            }
        }
    }
}

impl std::error::Error for DeletionError {}

/// The kinds the operator may delete.
///
/// Everything else is protected: upstream mail accounts, the mail resource
/// CRDs, OAuth grants, Secrets and PVCs are never removed as a side effect of
/// a Corvi change (ADR-0012, ADR-0013).
const DELETABLE_KINDS: &[&str] = &[
    "Deployment",
    "StatefulSet",
    "Service",
    "ConfigMap",
    "Job",
    "Lease",
];

/// Check a set of deletions and keep only the operator's own children.
pub fn plan_deletion(requests: &[DeletionRequest]) -> Result<Vec<DeletionRequest>, DeletionError> {
    let mut plan = Vec::with_capacity(requests.len());
    for request in requests {
        if !DELETABLE_KINDS.contains(&request.kind.as_str()) {
            return Err(DeletionError::ProtectedResource {
                kind: request.kind.clone(),
                name: request.name.clone(),
            });
        }
        plan.push(request.clone());
    }
    Ok(plan)
}

/// The deletion of one gateway and the dependents that still point at it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayDeletionPlan {
    requests: Vec<DeletionRequest>,
    dependents: Vec<ResourceKey>,
}

impl GatewayDeletionPlan {
    /// Build the plan.
    pub fn new(requests: Vec<DeletionRequest>, dependents: Vec<ResourceKey>) -> Self {
        Self {
            requests,
            dependents,
        }
    }

    /// The deletions the plan would perform.
    pub fn requests(&self) -> &[DeletionRequest] {
        &self.requests
    }

    /// The dependents that still point at the gateway.
    pub fn dependents(&self) -> &[ResourceKey] {
        &self.dependents
    }

    /// Check that the gateway may be removed.
    pub fn validate(&self) -> Result<(), DeletionError> {
        if !self.dependents.is_empty() {
            return Err(DeletionError::DependentsRemain {
                dependents: self.dependents.clone(),
            });
        }
        plan_deletion(&self.requests)?;
        Ok(())
    }
}
