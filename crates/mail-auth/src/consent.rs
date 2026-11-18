//! Consent, per-identity grants and `corvi_mail` authorization details.
//!
//! ADR-0009's authorization model is an intersection, never a union:
//!
//! ```text
//! requested actions  ∩  what the principal's identity actually allows
//! ```
//!
//! A request for a scope the identity does not allow is **refused**, not
//! silently narrowed: a client that asks for `mail:messages:send` on an
//! identity that allows only reading must be told no, so it cannot mistake
//! silence for a send permission it does not have.
//!
//! Grants are per identity and never merge across identities. One identity
//! with `[read]` and another with `[send]` is two grants, not one grant
//! with `[read, send]`.

use mail_core::Action;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::str::FromStr;

use crate::error::AuthError;

/// The type name of Corvi's custom authorization detail.
pub const CORVI_MAIL_TYPE: &str = "corvi_mail";

/// The constraints a consent may carry.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Constraints {
    /// The recipient domains a send may use.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recipient_domains: Vec<String>,
    /// Whether a send needs no runtime confirmation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unattended_send: Option<bool>,
    /// How many messages an hour a send may use.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_messages_per_hour: Option<u64>,
}

/// A `corvi_mail` authorization detail a client requested.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationDetail {
    /// The identity the detail is about.
    pub identity_id: String,
    /// The actions requested for that identity.
    #[serde(with = "action_list")]
    pub actions: Vec<Action>,
    /// The constraints requested for that identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constraints: Option<Constraints>,
}

/// The actions of one detail, as wire names.
mod action_list {
    use mail_core::Action;
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serialize actions as their wire names.
    pub fn serialize<S: Serializer>(actions: &[Action], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(actions.iter().map(|action| action.as_str()))
    }

    /// Parse actions from their wire names.
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<Action>, D::Error> {
        let names = Vec::<String>::deserialize(deserializer)?;
        names
            .iter()
            .map(|name| name.parse::<Action>().map_err(D::Error::custom))
            .collect()
    }
}

/// What one identity of one principal allows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityAllowance {
    /// The identity the allowance is about.
    pub identity_id: String,
    /// The actions the identity allows.
    pub actions: Vec<Action>,
}

/// The identities and actions a principal may grant at all.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Allowances {
    allowances: Vec<IdentityAllowance>,
}

impl Allowances {
    /// Collect allowances.
    pub fn new(allowances: impl IntoIterator<Item = IdentityAllowance>) -> Self {
        Self {
            allowances: allowances.into_iter().collect(),
        }
    }

    /// The allowance of one identity.
    pub fn for_identity(&self, identity_id: &str) -> Option<&IdentityAllowance> {
        self.allowances
            .iter()
            .find(|allowance| allowance.identity_id == identity_id)
    }

    /// Every allowance.
    pub fn all(&self) -> &[IdentityAllowance] {
        &self.allowances
    }
}

/// One consented grant: one identity, its actions, its constraints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentGrant {
    /// The identity the consent is about.
    pub identity_id: String,
    /// The actions the consent grants.
    pub actions: Vec<Action>,
    /// The constraints the consent carries.
    pub constraints: Option<Constraints>,
}

/// Resolve the flat scopes an authorization request may carry.
///
/// A scope outside the allowed set is refused. An empty request is refused:
/// an authorization that grants nothing is not an authorization.
pub fn resolve_requested_scopes(
    requested: &[String],
    allowed: &[Action],
) -> Result<Vec<Action>, AuthError> {
    if requested.is_empty() {
        return Err(AuthError::InvalidScope(
            "the request carries no scope".to_owned(),
        ));
    }
    let mut resolved = Vec::new();
    for name in requested {
        let action = Action::from_str(name).map_err(|_| {
            AuthError::InvalidScope(format!("the scope {name:?} is not a mail action"))
        })?;
        if !allowed.contains(&action) {
            return Err(AuthError::InvalidScope(format!(
                "the scope {name:?} is not allowed for this request"
            )));
        }
        if !resolved.contains(&action) {
            resolved.push(action);
        }
    }
    Ok(resolved)
}

/// Resolve a consent for a request that carries `corvi_mail` details.
///
/// Every requested identity and action must be within the allowance, and
/// the consent may only select identities the request named. The result is
/// one grant per consented identity, never a merged grant.
pub fn resolve_consent(
    allowance: &Allowances,
    requested: &[AuthorizationDetail],
    consented_identities: &[String],
) -> Result<Vec<ConsentGrant>, AuthError> {
    check_details_against_allowance(allowance, requested)?;
    if consented_identities.is_empty() {
        return Err(AuthError::InvalidScope(
            "the consent selected no identity".to_owned(),
        ));
    }
    let mut grants = Vec::new();
    for identity_id in consented_identities {
        let detail = requested
            .iter()
            .find(|detail| &detail.identity_id == identity_id)
            .ok_or_else(|| {
                AuthError::InvalidScope(
                    "the consent selected an identity the request did not ask for".to_owned(),
                )
            })?;
        if grants
            .iter()
            .any(|grant: &ConsentGrant| grant.identity_id == *identity_id)
        {
            return Err(AuthError::InvalidScope(
                "the consent selected an identity twice".to_owned(),
            ));
        }
        grants.push(ConsentGrant {
            identity_id: identity_id.clone(),
            actions: detail.actions.clone(),
            constraints: detail.constraints.clone(),
        });
    }
    Ok(grants)
}

/// Resolve a consent for a request that carries only flat scopes.
///
/// The consent selects the identities; the granted actions of one identity
/// are the requested scopes that identity actually allows. A requested
/// scope the identity does not allow refuses the request.
pub fn resolve_flat_consent(
    allowance: &Allowances,
    requested_scopes: &[Action],
    consented_identities: &[String],
) -> Result<Vec<ConsentGrant>, AuthError> {
    if consented_identities.is_empty() {
        return Err(AuthError::InvalidScope(
            "the consent selected no identity".to_owned(),
        ));
    }
    if requested_scopes.is_empty() {
        return Err(AuthError::InvalidScope(
            "the request carries no scope".to_owned(),
        ));
    }
    let mut grants = Vec::new();
    for identity_id in consented_identities {
        let allowed = allowance
            .for_identity(identity_id)
            .ok_or_else(|| {
                AuthError::InvalidScope(
                    "the identity is not one this principal may grant".to_owned(),
                )
            })?
            .actions
            .clone();
        let mut actions = Vec::new();
        for action in requested_scopes {
            if !allowed.contains(action) {
                return Err(AuthError::InvalidScope(format!(
                    "the scope {} is not allowed for this identity",
                    action.as_str()
                )));
            }
            actions.push(*action);
        }
        grants.push(ConsentGrant {
            identity_id: identity_id.clone(),
            actions,
            constraints: None,
        });
    }
    Ok(grants)
}

/// Check the requested details against the allowance.
fn check_details_against_allowance(
    allowance: &Allowances,
    requested: &[AuthorizationDetail],
) -> Result<(), AuthError> {
    if requested.is_empty() {
        return Err(AuthError::InvalidScope(
            "the request carries no authorization details".to_owned(),
        ));
    }
    for detail in requested {
        let allowed = allowance
            .for_identity(&detail.identity_id)
            .ok_or_else(|| {
                AuthError::InvalidScope(
                    "the identity is not one this principal may grant".to_owned(),
                )
            })?
            .actions
            .clone();
        for action in &detail.actions {
            if !allowed.contains(action) {
                return Err(AuthError::InvalidScope(format!(
                    "the scope {} is not allowed for this identity",
                    action.as_str()
                )));
            }
        }
        if let Some(constraints) = &detail.constraints {
            if constraints.unattended_send == Some(true) {
                return Err(AuthError::InvalidScope(
                    "a request cannot approve an unattended send; only a separately \
                     designated server policy may"
                        .to_owned(),
                ));
            }
        }
    }
    Ok(())
}

/// Serialize the consented grants as `corvi_mail` authorization details.
///
/// The shape is the scoped shape the contract declares: a `type`, an
/// `identityId`, an `actions` array and, when present, `constraints`. One
/// detail per identity; grants are never merged.
pub fn authorization_details(grants: &[ConsentGrant]) -> Vec<serde_json::Value> {
    grants
        .iter()
        .map(|grant| {
            let mut detail = json!({
                "type": CORVI_MAIL_TYPE,
                "identityId": grant.identity_id,
                "actions": grant
                    .actions
                    .iter()
                    .map(|action| action.as_str())
                    .collect::<Vec<_>>(),
            });
            if let Some(constraints) = &grant.constraints {
                detail["constraints"] =
                    serde_json::to_value(constraints).unwrap_or(serde_json::Value::Null);
            }
            detail
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowance(identity: &str, actions: &[Action]) -> IdentityAllowance {
        IdentityAllowance {
            identity_id: identity.to_owned(),
            actions: actions.to_vec(),
        }
    }

    fn detail(identity: &str, actions: &[Action]) -> AuthorizationDetail {
        AuthorizationDetail {
            identity_id: identity.to_owned(),
            actions: actions.to_vec(),
            constraints: None,
        }
    }

    #[test]
    fn a_scope_outside_the_allowed_set_is_refused() {
        let allowed = [Action::List, Action::Read];
        let requested = vec![
            "mail:messages:read".to_owned(),
            "mail:messages:send".to_owned(),
        ];
        assert!(matches!(
            resolve_requested_scopes(&requested, &allowed),
            Err(AuthError::InvalidScope(_))
        ));
    }

    #[test]
    fn an_unknown_scope_is_refused() {
        let allowed = [Action::List];
        let requested = vec!["mail:everything".to_owned()];
        assert!(matches!(
            resolve_requested_scopes(&requested, &allowed),
            Err(AuthError::InvalidScope(_))
        ));
    }

    #[test]
    fn an_empty_scope_request_is_refused() {
        let allowed = [Action::List];
        assert!(matches!(
            resolve_requested_scopes(&[], &allowed),
            Err(AuthError::InvalidScope(_))
        ));
    }

    #[test]
    fn the_granted_scopes_are_the_intersection() {
        let allowed = [Action::List, Action::Read, Action::Send];
        let requested = vec![
            "mail:messages:list".to_owned(),
            "mail:messages:read".to_owned(),
        ];
        let granted =
            resolve_requested_scopes(&requested, &allowed).expect("the request is allowed");
        assert_eq!(granted, vec![Action::List, Action::Read]);
    }

    #[test]
    fn an_action_outside_the_identity_allowance_is_refused() {
        let allowance = Allowances::new([allowance("identity-a", &[Action::List, Action::Read])]);
        let requested = [detail("identity-a", &[Action::List, Action::Send])];
        assert!(matches!(
            resolve_consent(&allowance, &requested, &["identity-a".to_owned()]),
            Err(AuthError::InvalidScope(_))
        ));
    }

    #[test]
    fn an_identity_outside_the_allowance_is_refused() {
        let allowance = Allowances::new([allowance("identity-a", &[Action::List])]);
        let requested = [detail("identity-b", &[Action::List])];
        assert!(matches!(
            resolve_consent(&allowance, &requested, &["identity-b".to_owned()]),
            Err(AuthError::InvalidScope(_))
        ));
    }

    #[test]
    fn consent_never_widens_the_allowance() {
        let allowance = Allowances::new([allowance(
            "identity-a",
            &[Action::List, Action::Read, Action::Search],
        )]);
        let requested = [detail("identity-a", &[Action::List, Action::Read])];
        let grants = resolve_consent(&allowance, &requested, &["identity-a".to_owned()])
            .expect("the consent resolves");
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].identity_id, "identity-a");
        assert_eq!(grants[0].actions, vec![Action::List, Action::Read]);
        assert!(!grants[0].actions.contains(&Action::Search));
    }

    #[test]
    fn grants_are_never_merged_across_identities() {
        let allowance = Allowances::new([
            allowance("identity-a", &[Action::List, Action::Read]),
            allowance("identity-b", &[Action::Send]),
        ]);
        let requested = [
            detail("identity-a", &[Action::List, Action::Read]),
            detail("identity-b", &[Action::Send]),
        ];
        let grants = resolve_consent(
            &allowance,
            &requested,
            &["identity-a".to_owned(), "identity-b".to_owned()],
        )
        .expect("the consent resolves");
        assert_eq!(grants.len(), 2);
        assert_eq!(grants[0].identity_id, "identity-a");
        assert_eq!(grants[0].actions, vec![Action::List, Action::Read]);
        assert_eq!(grants[1].identity_id, "identity-b");
        assert_eq!(grants[1].actions, vec![Action::Send]);
        // Neither grant carries the other identity's action.
        assert!(!grants[0].actions.contains(&Action::Send));
        assert!(!grants[1].actions.contains(&Action::Read));
    }

    #[test]
    fn a_consent_may_not_select_an_identity_the_request_did_not_ask_for() {
        let allowance = Allowances::new([allowance("identity-a", &[Action::List])]);
        let requested = [detail("identity-a", &[Action::List])];
        assert!(matches!(
            resolve_consent(&allowance, &requested, &["identity-b".to_owned()]),
            Err(AuthError::InvalidScope(_))
        ));
    }

    #[test]
    fn a_flat_consent_is_the_intersection_of_scopes_and_identity() {
        let allowance = Allowances::new([
            allowance("identity-a", &[Action::List, Action::Read]),
            allowance("identity-b", &[Action::Send]),
        ]);
        let scopes = [Action::List, Action::Read];
        let grants = resolve_flat_consent(&allowance, &scopes, &["identity-a".to_owned()])
            .expect("the consent resolves");
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].actions, vec![Action::List, Action::Read]);

        // The same scopes for the other identity are refused: it allows
        // sending, not reading.
        assert!(matches!(
            resolve_flat_consent(&allowance, &scopes, &["identity-b".to_owned()]),
            Err(AuthError::InvalidScope(_))
        ));
    }

    #[test]
    fn a_flat_consent_selecting_an_unknown_identity_is_refused() {
        let allowance = Allowances::new([allowance("identity-a", &[Action::List])]);
        assert!(matches!(
            resolve_flat_consent(&allowance, &[Action::List], &["identity-z".to_owned()]),
            Err(AuthError::InvalidScope(_))
        ));
    }

    #[test]
    fn a_request_without_details_grants_nothing() {
        let allowance = Allowances::new([allowance("identity-a", &[Action::List])]);
        assert!(matches!(
            resolve_consent(&allowance, &[], &["identity-a".to_owned()]),
            Err(AuthError::InvalidScope(_))
        ));
    }

    #[test]
    fn the_authorization_details_are_one_scoped_object_per_identity() {
        let grants = vec![
            ConsentGrant {
                identity_id: "identity-a".to_owned(),
                actions: vec![Action::List, Action::Read],
                constraints: None,
            },
            ConsentGrant {
                identity_id: "identity-b".to_owned(),
                actions: vec![Action::Send],
                constraints: Some(Constraints {
                    recipient_domains: vec!["alerts.example.com".to_owned()],
                    unattended_send: Some(false),
                    max_messages_per_hour: Some(60),
                }),
            },
        ];
        let details = authorization_details(&grants);
        assert_eq!(details.len(), 2);
        assert_eq!(details[0]["type"], "corvi_mail");
        assert_eq!(details[0]["identityId"], "identity-a");
        assert_eq!(
            details[0]["actions"],
            serde_json::json!(["mail:messages:list", "mail:messages:read"])
        );
        assert_eq!(details[1]["identityId"], "identity-b");
        assert_eq!(
            details[1]["actions"],
            serde_json::json!(["mail:messages:send"])
        );
        assert_eq!(
            details[1]["constraints"]["recipientDomains"],
            serde_json::json!(["alerts.example.com"])
        );
        assert_eq!(details[1]["constraints"]["unattendedSend"], false);
    }

    #[test]
    fn an_unattended_send_cannot_be_self_approved_by_a_request() {
        // The contract fixes `unattendedSend` to `false` in a client-supplied
        // detail; only a separately designated, server-approved policy may
        // bypass the per-send confirmation, so a request that asks for it is
        // refused rather than copied into the consent.
        let requested: AuthorizationDetail = serde_json::from_value(serde_json::json!({
            "identityId": "identity-a",
            "actions": ["mail:messages:send"],
            "constraints": {"unattendedSend": true}
        }))
        .expect("the detail parses");
        let allowance = Allowances::new([allowance("identity-a", &[Action::Send])]);
        assert!(matches!(
            resolve_consent(&allowance, &[requested], &["identity-a".to_owned()]),
            Err(AuthError::InvalidScope(_))
        ));
    }
}
