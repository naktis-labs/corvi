//! Identity-specific action grants, without cross-identity permission union.
//!
//! A grant names one identity and the actions that may be performed on it.
//! Grants never union across identities: a principal that may read the
//! mailbox behind one identity gains nothing on another, even when both
//! identities live in the same upstream mailbox.

use std::collections::{BTreeMap, BTreeSet};

use crate::{Action, IdentityId};

/// Actions associated with one identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityGrant {
    identity: IdentityId,
    actions: BTreeSet<Action>,
}

impl IdentityGrant {
    /// Construct a grant for exactly one identity.
    pub fn new(identity: IdentityId, actions: impl IntoIterator<Item = Action>) -> Self {
        Self {
            identity,
            actions: actions.into_iter().collect(),
        }
    }

    /// The identity this grant applies to.
    pub fn identity(&self) -> &IdentityId {
        &self.identity
    }

    /// The actions granted for this identity.
    pub fn actions(&self) -> &BTreeSet<Action> {
        &self.actions
    }
}

/// The outcome of checking one action against a grant set.
///
/// ADR-0009 requires the API to distinguish two denials that look alike from
/// the outside: a known identity the principal may act on but not with this
/// action is a genuine authorization failure, while an identity the principal
/// has no membership in must not be distinguishable from one that does not
/// exist. A bare boolean cannot carry that difference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantDecision {
    /// The action is granted for the selected identity.
    Granted,
    /// The identity is within the principal's grant set, but this action is
    /// not granted for it.
    ActionDenied,
    /// The identity is not in the principal's grant set at all.
    UnknownIdentity,
}

impl GrantDecision {
    /// Whether the action is permitted.
    pub fn is_granted(self) -> bool {
        matches!(self, GrantDecision::Granted)
    }
}

/// Identity-scoped grants for one authenticated principal.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopedGrants {
    grants: BTreeMap<IdentityId, BTreeSet<Action>>,
}

impl ScopedGrants {
    /// Collect grants.
    ///
    /// Repeated entries for the same identity contribute their actions to
    /// that identity only, and never to any other identity. The actions of
    /// one identity are the union of the entries naming it; use
    /// [`ScopedGrants::narrowed`] when a grant must be reduced rather than
    /// widened.
    pub fn new(grants: impl IntoIterator<Item = IdentityGrant>) -> Self {
        let mut result = Self::default();
        for grant in grants {
            result
                .grants
                .entry(grant.identity)
                .or_default()
                .extend(grant.actions);
        }
        result
    }

    /// Check an action only against the explicitly selected identity.
    pub fn permits(&self, identity: &IdentityId, action: Action) -> bool {
        self.decide(identity, action).is_granted()
    }

    /// Decide an action against the explicitly selected identity.
    ///
    /// An action is granted only when it is granted directly and every
    /// prerequisite it carries is granted as well. Subscribing to filtered
    /// inbox changes therefore requires the ability to list the inbox, which
    /// is the dependency the contracts state.
    pub fn decide(&self, identity: &IdentityId, action: Action) -> GrantDecision {
        let Some(actions) = self.grants.get(identity) else {
            return GrantDecision::UnknownIdentity;
        };
        if !actions.contains(&action) {
            return GrantDecision::ActionDenied;
        }
        let prerequisites_met = action
            .prerequisites()
            .iter()
            .all(|prerequisite| actions.contains(prerequisite));
        if prerequisites_met {
            GrantDecision::Granted
        } else {
            GrantDecision::ActionDenied
        }
    }

    /// Whether the principal holds any grant for this identity.
    pub fn contains_identity(&self, identity: &IdentityId) -> bool {
        self.grants.contains_key(identity)
    }

    /// The identities this principal holds a grant for.
    pub fn identities(&self) -> impl Iterator<Item = &IdentityId> {
        self.grants.keys()
    }

    /// The actions granted for one identity.
    pub fn actions_for(&self, identity: &IdentityId) -> Option<&BTreeSet<Action>> {
        self.grants.get(identity)
    }

    /// Reduce the actions granted for one identity.
    ///
    /// The result keeps only the actions that were granted before **and** are
    /// allowed now, so a narrowing cannot be expressed as a widening and a
    /// revoked action cannot come back by rebuilding the grant set from
    /// overlapping entries.
    pub fn narrowed(
        &self,
        identity: &IdentityId,
        allowed: impl IntoIterator<Item = Action>,
    ) -> Self {
        let mut result = self.clone();
        if let Some(actions) = result.grants.get_mut(identity) {
            let allowed: BTreeSet<Action> = allowed.into_iter().collect();
            actions.retain(|action| allowed.contains(action));
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(name: &str) -> IdentityId {
        IdentityId::new(name)
    }

    #[test]
    fn an_empty_grant_set_denies_everything() {
        let grants = ScopedGrants::default();
        assert_eq!(
            grants.decide(&id("alice"), Action::Read),
            GrantDecision::UnknownIdentity
        );
        assert!(!grants.permits(&id("alice"), Action::Read));
        assert_eq!(grants.identities().count(), 0);
    }

    #[test]
    fn repeated_entries_for_one_identity_do_not_widen_the_others() {
        let grants = ScopedGrants::new([
            IdentityGrant::new(id("alice"), [Action::Read]),
            IdentityGrant::new(id("alice"), [Action::Send]),
            IdentityGrant::new(id("bob"), [Action::Read]),
        ]);
        assert!(grants.permits(&id("alice"), Action::Read));
        assert!(grants.permits(&id("alice"), Action::Send));
        assert!(grants.permits(&id("bob"), Action::Read));
        assert!(!grants.permits(&id("bob"), Action::Send));
    }

    #[test]
    fn a_known_identity_without_the_action_is_distinguishable() {
        let grants = ScopedGrants::new([IdentityGrant::new(id("alice"), [Action::Read])]);
        assert_eq!(
            grants.decide(&id("alice"), Action::Send),
            GrantDecision::ActionDenied
        );
        assert_eq!(
            grants.decide(&id("carol"), Action::Read),
            GrantDecision::UnknownIdentity
        );
        assert!(grants.contains_identity(&id("alice")));
        assert!(!grants.contains_identity(&id("carol")));
    }

    #[test]
    fn subscribing_without_listing_is_denied() {
        let grants = ScopedGrants::new([IdentityGrant::new(id("alice"), [Action::Subscribe])]);
        assert_eq!(
            grants.decide(&id("alice"), Action::Subscribe),
            GrantDecision::ActionDenied
        );
        let both = ScopedGrants::new([IdentityGrant::new(
            id("alice"),
            [Action::List, Action::Subscribe],
        )]);
        assert!(both.permits(&id("alice"), Action::Subscribe));
    }

    #[test]
    fn narrowing_removes_actions_and_cannot_widen() {
        let grants = ScopedGrants::new([IdentityGrant::new(
            id("alice"),
            [Action::List, Action::Read, Action::Send],
        )]);
        let narrowed = grants.narrowed(&id("alice"), [Action::List, Action::Read]);
        assert!(narrowed.permits(&id("alice"), Action::Read));
        assert!(!narrowed.permits(&id("alice"), Action::Send));
        assert_eq!(narrowed.actions_for(&id("alice")).unwrap().len(), 2);
        assert!(grants.permits(&id("alice"), Action::Send));
    }

    #[test]
    fn granted_identities_and_actions_can_be_enumerated() {
        let grants = ScopedGrants::new([
            IdentityGrant::new(id("alice"), [Action::List, Action::Read]),
            IdentityGrant::new(id("bob"), [Action::Send]),
        ]);
        let identities: Vec<&str> = grants.identities().map(|i| i.as_str()).collect();
        assert_eq!(identities, vec!["alice", "bob"]);
        let actions = grants.actions_for(&id("alice")).unwrap();
        assert!(actions.contains(&Action::List));
        assert!(actions.contains(&Action::Read));
        assert!(!actions.contains(&Action::Send));
    }

    #[test]
    fn grants_compare_by_content() {
        let a = ScopedGrants::new([IdentityGrant::new(id("alice"), [Action::Read])]);
        let b = ScopedGrants::new([IdentityGrant::new(id("alice"), [Action::Read])]);
        let c = ScopedGrants::new([IdentityGrant::new(id("alice"), [Action::Send])]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
