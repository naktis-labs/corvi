//! The authority behind a queued item.
//!
//! An item that waits in a queue may have been queued under an authority
//! that has since been revoked or narrowed. ADR-0010 and ADR-0009 both
//! insist that an operation is authorized *at the moment it happens*, not
//! when it was requested, so the queue asks the authority again before it
//! performs the work.
//!
//! The authority itself is **not owned by the queue**. Grants, consents and
//! revocations belong to the OAuth authorization service, and the operator's
//! published policy belongs to the control plane; the queue only refers to
//! them through the [`Authority`] trait. That is the whole point of the
//! trait: the queue can be given a fresh answer without being able to
//! manufacture one.

use std::fmt;

use mail_core::{Action, IdentityId, ScopedGrants};

/// The question the queue asks before it performs an item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationRequest {
    /// The principal the item belongs to.
    pub principal: String,
    /// The identity the item acts on.
    pub identity: String,
    /// The action the item performs.
    pub action: Action,
    /// The item the question is about, when there is one.
    pub subject: Option<String>,
}

/// The answer to an [`AuthorizationRequest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationOutcome {
    /// The item may proceed.
    ///
    /// The generation is the revision of the grant the answer was taken
    /// from, so a caller can tell a fresh authorization from one that has
    /// been in place since the item was queued. The queue records no
    /// generation of its own at enqueue time, so this generation is
    /// reported to the caller and compared against nothing; see
    /// [`crate::queue::ExecutionOutcome::Accepted`] for the precise
    /// consequence of that.
    Permitted {
        /// The revision of the grant that permits the action.
        grant_generation: u64,
    },
    /// The item must not proceed.
    Refused {
        /// Why it was refused, without naming the grant.
        reason: String,
    },
}

/// Something that can say whether an action is still permitted.
pub trait Authority: fmt::Debug {
    /// Decide one request.
    ///
    /// The answer must reflect the authority as it is *now*. A queue that
    /// asked later and got an older answer would be exactly the stale
    /// authority the refusal exists to prevent.
    fn authorize(&self, request: &AuthorizationRequest) -> AuthorizationOutcome;
}

/// An authority backed by the current grant set of one principal.
///
/// The grant set is a snapshot the caller supplies. The queue never writes
/// to it, so the OAuth authorization service stays the only owner of grants
/// and revocations.
#[derive(Debug, Clone)]
pub struct GrantAuthority {
    grants: ScopedGrants,
    generation: u64,
}

impl GrantAuthority {
    /// Build an authority from a grant set and the revision it was taken at.
    pub fn new(grants: ScopedGrants, generation: u64) -> Self {
        Self { grants, generation }
    }

    /// The grant set behind this authority.
    pub fn grants(&self) -> &ScopedGrants {
        &self.grants
    }
}

impl Authority for GrantAuthority {
    fn authorize(&self, request: &AuthorizationRequest) -> AuthorizationOutcome {
        let identity = IdentityId::new(request.identity.clone());
        match self.grants.decide(&identity, request.action) {
            mail_core::GrantDecision::Granted => AuthorizationOutcome::Permitted {
                grant_generation: self.generation,
            },
            mail_core::GrantDecision::ActionDenied => AuthorizationOutcome::Refused {
                reason: format!(
                    "the principal may not {} for this identity any more",
                    request.action.as_str()
                ),
            },
            mail_core::GrantDecision::UnknownIdentity => AuthorizationOutcome::Refused {
                reason: "the principal holds no grant for this identity".to_owned(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mail_core::IdentityGrant;

    fn request(action: Action) -> AuthorizationRequest {
        AuthorizationRequest {
            principal: "alice".to_owned(),
            identity: "alice@example.test".to_owned(),
            action,
            subject: Some("submission-1".to_owned()),
        }
    }

    #[test]
    fn a_granted_action_is_permitted() {
        let grants = ScopedGrants::new([IdentityGrant::new(
            IdentityId::new("alice@example.test"),
            [Action::Send],
        )]);
        let authority = GrantAuthority::new(grants, 7);
        assert_eq!(
            authority.authorize(&request(Action::Send)),
            AuthorizationOutcome::Permitted {
                grant_generation: 7
            }
        );
    }

    #[test]
    fn a_revoked_action_is_refused() {
        let authority = GrantAuthority::new(ScopedGrants::default(), 1);
        assert!(matches!(
            authority.authorize(&request(Action::Send)),
            AuthorizationOutcome::Refused { .. }
        ));
    }
}
