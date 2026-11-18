//! Continuous revalidation of an issued credential.
//!
//! A webhook cannot enforce an invariant when the objects it depends on
//! change later (ADR-0014 section 2). A gateway may be suspended, a
//! mailbox may be reparented, a provider may lose the capability a
//! credential depends on, and none of those touch the credential itself.
//!
//! So a credential is re-evaluated against the current graph whenever it is
//! reconciled, issued, rotated or published. The decision is one of three:
//!
//! * **Keep** — the credential still holds exactly the authority it was
//!   issued with, against exactly the parents it was issued from.
//! * **Revoke** — the authority is gone. The published output has to be
//!   withdrawn.
//! * **Withhold** — the graph could not be resolved, because a dependency
//!   was unreachable or a capability status was stale. The output is
//!   withheld until the graph can be resolved again.
//!
//! Revalidation never converts a credential. A scoped credential whose
//! provider lost its gateway does not become a provider-native credential;
//! it fails `GatewayRequiredForScopedCredential`. A provider-native
//! credential whose provider gained a gateway does not become a scoped
//! credential; it fails `MissingGatewayPermissions`. Either way the
//! credential has to be authorized again, explicitly, by a human.

use crate::admission::{ChainSnapshot, ConnectionAuthority, ParentStatusReader, resolve_graph};
use crate::model::{MailCredential, TargetRef};
use crate::reasons::Reason;

/// What an issued credential is recorded to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedCredential {
    /// The UID of the credential.
    pub credential_uid: String,
    /// The revision that was issued.
    pub revision: String,
    /// The authority the credential was issued with.
    pub authority: ConnectionAuthority,
    /// The target the credential was issued for.
    pub target: TargetRef,
    /// The parents the authority was derived from.
    pub chain: ChainSnapshot,
    /// The Secret the credential published to.
    pub secret_name: String,
}

impl IssuedCredential {
    /// Record an issued credential against the graph it was issued from.
    pub fn record(
        credential: &MailCredential,
        authority: ConnectionAuthority,
        chain: ChainSnapshot,
        revision: impl Into<String>,
        secret_name: impl Into<String>,
    ) -> Self {
        Self {
            credential_uid: credential.uid().to_string(),
            revision: revision.into(),
            authority,
            target: credential.spec().target_ref().clone(),
            chain,
            secret_name: secret_name.into(),
        }
    }
}

/// The decision of a revalidation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevalidationDecision {
    /// The credential still holds its authority.
    Keep,
    /// The authority is gone and the output has to be withdrawn.
    Revoke {
        /// Why the authority is gone.
        reason: Reason,
        /// A message that names the condition.
        message: String,
    },
    /// The graph could not be resolved, so the output has to be withheld.
    Withhold {
        /// Why the graph could not be resolved.
        reason: Reason,
        /// A message that names the condition.
        message: String,
    },
}

impl RevalidationDecision {
    /// Whether the credential may keep its published output.
    pub fn is_kept(&self) -> bool {
        matches!(self, Self::Keep)
    }

    /// The reason of a decision that is not `Keep`.
    pub fn reason(&self) -> Option<Reason> {
        match self {
            Self::Keep => None,
            Self::Revoke { reason, .. } | Self::Withhold { reason, .. } => Some(*reason),
        }
    }
}

/// Revalidate an issued credential against the current graph.
///
/// The decision never converts the credential and never widens it. It only
/// says whether the authority that was issued still holds.
pub fn revalidate(
    issued: &IssuedCredential,
    credential: &MailCredential,
    reader: &dyn ParentStatusReader,
) -> RevalidationDecision {
    let graph = match resolve_graph(credential, reader) {
        Ok(graph) => graph,
        Err(denial) => {
            let reason = denial.reason();
            let message = denial.message().to_string();
            return match reason {
                // A graph that could not be read is not a graph that lost
                // its authority. The output is withheld until the graph can
                // be resolved again.
                Reason::StaleCapabilityStatus | Reason::DependencyUnavailable => {
                    RevalidationDecision::Withhold { reason, message }
                }
                _ => RevalidationDecision::Revoke { reason, message },
            };
        }
    };

    let was = &issued.authority;
    let now = &graph.authority;
    if was.mode != now.mode
        || was.credential_type != now.credential_type
        || was.granularity != now.granularity
        || was.permissions != now.permissions
        || was.identity_name != now.identity_name
        || was.mailbox_name != now.mailbox_name
    {
        return RevalidationDecision::Revoke {
            reason: Reason::ParentChanged,
            message: "the credential no longer holds the authority it was issued with".to_string(),
        };
    }

    if graph.chain != issued.chain {
        return RevalidationDecision::Revoke {
            reason: Reason::ParentChanged,
            message: "a parent resource changed after the credential was issued".to_string(),
        };
    }

    RevalidationDecision::Keep
}
