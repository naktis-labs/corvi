//! The Corvi Kubernetes operator's decision logic.
//!
//! This crate holds the parts of the operator that can be decided without a
//! cluster: the directional reference contract of ADR-0013, the ownership and
//! reparenting rules of ADR-0012/ADR-0013, the hardened workload profile of
//! ADR-0011 and the last-known-good snapshot retention of ADR-0001/ADR-0012.
//!
//! # What this crate is not
//!
//! There is no Kubernetes client here, and nothing in this crate talks to an
//! API server, a CNI or an admission webhook. It renders the shapes a
//! reconciler *would* submit and validates them; it does not submit them, and
//! it does not enforce a network policy or run an admission server. The
//! rendered objects are therefore **proposals**, and the enforcement boundary
//! for a deployed cluster is an independently installed admission policy and
//! network policy, not this code.
//!
//! # Configuration validation
//!
//! Gateway configuration snapshots are validated by `mail-config`, which
//! remains the single source of truth for what a valid snapshot is. This crate
//! only *builds* candidates and *retains* the last known good one.

pub mod model;
pub mod ownership;
pub mod references;
pub mod retention;
pub mod workload;

/// The isolation mode an identity may claim.
pub use mail_core::IsolationMode;

pub use model::{
    API_GROUP, API_GROUP_VERSION, API_VERSION, Authorization, AuthorizationMode, CorviGateway,
    GatewaySpec, Listener, Listeners, LocalRef, MailIdentity, MailIdentitySpec, MailProvider,
    MailProviderSpec, Mailbox, MailboxSpec, ObjectMeta, ParseError, ProviderRole, ResourceKind,
    ResourceRequirements, StateBackend, StateSpec, parse_gateway, parse_identity, parse_mailbox,
    parse_provider,
};
pub use ownership::{
    DeletionError, DeletionRequest, ExistingWorkload, GatewayDeletionPlan, GatewayView, GraphError,
    OwnershipError, ProviderBinding, ReparentPlan, ReparentingError, ResolvedIdentity,
    ResolvedMailbox, ResourceGraph, TransitionStep, WorkloadOwnership, decide_ownership,
    detect_reparenting, plan_deletion,
};
pub use references::{ReferenceError, ResourceKey};
