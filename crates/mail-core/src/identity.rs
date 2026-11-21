//! Mail identities and the isolation guarantees they can claim.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::message::NormalizedMessage;

/// Stable identifier of a virtual mail identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IdentityId(String);

impl IdentityId {
    /// Create an identity id.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Borrow the identifier as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for IdentityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Returned when an identity id is empty or contains control characters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseIdentityIdError {
    input: String,
}

impl fmt::Display for ParseIdentityIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid identity id: {:?}", self.input)
    }
}

impl std::error::Error for ParseIdentityIdError {}

impl FromStr for IdentityId {
    type Err = ParseIdentityIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let valid = !s.is_empty()
            && s.len() <= 253
            && !s.chars().any(|c| c.is_control() || c.is_whitespace());
        if valid {
            Ok(Self(s.to_owned()))
        } else {
            Err(ParseIdentityIdError {
                input: s.to_owned(),
            })
        }
    }
}

/// How strongly an identity's message scope can be proven.
///
/// A single upstream mailbox holding several aliases does **not** by itself
/// prove which identity a message belongs to. The isolation mode records how
/// much evidence Corvi has, and `verified` fails closed when that evidence
/// is missing rather than silently degrading.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolationMode {
    /// Scope is proven by trusted provider envelope-recipient metadata or
    /// server-side routing. Without that evidence the message is not visible.
    Verified,
    /// The identity owns a dedicated physical mailbox, so every message in it
    /// belongs to the identity.
    Dedicated,
    /// Scope is inferred from message-authored headers. This is explicitly
    /// **not** a confidentiality guarantee.
    BestEffort,
}

impl IsolationMode {
    /// Whether this mode claims confidentiality.
    ///
    /// `BestEffort` never does, and the distinction must survive all the way
    /// to what a client is told.
    pub fn claims_confidentiality(self) -> bool {
        matches!(self, IsolationMode::Verified | IsolationMode::Dedicated)
    }
}

/// A virtual mail identity: a sender persona and a filtered view of a
/// physical upstream mailbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailIdentity {
    /// Stable identifier used by REST, MCP and credential references.
    pub id: IdentityId,
    /// The physical upstream mailbox this identity draws from.
    pub mailbox: crate::message::MailboxRef,
    /// The address this identity sends from.
    pub address: String,
    /// Additional addresses that resolve to this identity.
    #[serde(default)]
    pub aliases: Vec<String>,
    /// Human-readable name for the identity.
    #[serde(default)]
    pub display_name: Option<String>,
    /// The isolation guarantee this identity can claim.
    pub isolation: IsolationMode,
}

impl MailIdentity {
    /// Whether `address` is this identity's address or one of its aliases.
    ///
    /// Comparison is exact and case-insensitive on the local part, which is
    /// the practical behaviour for address matching. It deliberately does not
    /// attempt full RFC 5321 normalization.
    pub fn matches_address(&self, address: &str) -> bool {
        let candidate = address.trim();
        self.address.eq_ignore_ascii_case(candidate)
            || self
                .aliases
                .iter()
                .any(|alias| alias.eq_ignore_ascii_case(candidate))
    }

    /// Whether a message belongs to this identity.
    ///
    /// The evidence required depends on the isolation mode, and a mode that
    /// cannot be satisfied denies the message rather than accepting it:
    ///
    /// - `verified` requires provider-recorded delivery metadata naming this
    ///   identity. A message-authored header is not that evidence, so a
    ///   transport that cannot record it makes the message invisible.
    /// - `dedicated` requires the message to live in the identity's own
    ///   physical mailbox.
    /// - `best_effort` accepts any message that names the identity among its
    ///   visible addresses, and claims no confidentiality.
    pub fn owns_message(&self, message: &NormalizedMessage) -> bool {
        match self.isolation {
            IsolationMode::Verified => message
                .trusted_recipient()
                .is_some_and(|recipient| self.matches_address(&recipient.address)),
            IsolationMode::Dedicated => message.mailbox == self.mailbox,
            IsolationMode::BestEffort => message
                .visible_addresses()
                .any(|address| self.matches_address(&address.address)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::MailboxRef;

    fn identity() -> MailIdentity {
        MailIdentity {
            id: IdentityId::new("service"),
            mailbox: MailboxRef::new("grafana"),
            address: "noreply@example.com".to_owned(),
            aliases: vec!["alerts@example.com".to_owned()],
            display_name: None,
            isolation: IsolationMode::BestEffort,
        }
    }

    #[test]
    fn matches_own_address_and_aliases() {
        let identity = identity();
        assert!(identity.matches_address("noreply@example.com"));
        assert!(identity.matches_address("NoReply@Example.com"));
        assert!(identity.matches_address("alerts@example.com"));
        assert!(!identity.matches_address("other@example.com"));
        assert!(!identity.matches_address("noreply@example.com.evil.test"));
    }

    #[test]
    fn best_effort_never_claims_confidentiality() {
        assert!(!IsolationMode::BestEffort.claims_confidentiality());
        assert!(IsolationMode::Verified.claims_confidentiality());
        assert!(IsolationMode::Dedicated.claims_confidentiality());
    }

    #[test]
    fn identity_ids_reject_blank_and_control_characters() {
        assert!(IdentityId::from_str("ok-id").is_ok());
        assert!(IdentityId::from_str("").is_err());
        assert!(IdentityId::from_str("has space").is_err());
        assert!(IdentityId::from_str("has\nnewline").is_err());
    }

    /// The wire spelling of the isolation modes is part of the configuration
    /// contract: the operator's CRD fixtures and the documentation both use
    /// `best_effort`, and a mode that cannot be read back is a mode that
    /// silently fails closed.
    #[test]
    fn the_isolation_modes_have_a_stable_wire_spelling() {
        for (mode, wire) in [
            (IsolationMode::Verified, "\"verified\""),
            (IsolationMode::Dedicated, "\"dedicated\""),
            (IsolationMode::BestEffort, "\"best_effort\""),
        ] {
            assert_eq!(
                serde_json::to_string(&mode).unwrap(),
                wire,
                "the wire spelling of {mode:?} changed"
            );
            assert_eq!(
                serde_json::from_str::<IsolationMode>(wire).unwrap(),
                mode,
                "the wire spelling of {mode:?} does not read back"
            );
        }
    }
}
