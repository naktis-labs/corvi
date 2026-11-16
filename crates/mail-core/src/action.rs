//! Permission-scoped operations a principal may attempt against an identity.

use std::fmt;
use std::str::FromStr;

/// An operation that can be granted to a principal for a specific identity.
///
/// Actions are the first of the three independent authorization gates in
/// ADR-0003: operation authorization, identity scope, then disclosure
/// filtering. A grant for one action never implies another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Action {
    /// Discover the identities this principal may act on.
    ListIdentities,
    /// List messages visible to the principal.
    List,
    /// Read one message body.
    Read,
    /// Search visible messages.
    Search,
    /// List attachment metadata for a visible message.
    ListAttachments,
    /// Download attachment bytes for a visible message.
    ReadAttachment,
    /// Send mail from an authorized identity.
    Send,
    /// Subscribe to visible-mail change notifications.
    Subscribe,
}

impl Action {
    /// Every action Corvi defines.
    pub const ALL: [Action; 8] = [
        Action::ListIdentities,
        Action::List,
        Action::Read,
        Action::Search,
        Action::ListAttachments,
        Action::ReadAttachment,
        Action::Send,
        Action::Subscribe,
    ];

    /// The wire representation used by REST and MCP contracts.
    pub fn as_str(self) -> &'static str {
        match self {
            Action::ListIdentities => "mail:identities:list",
            Action::List => "mail:messages:list",
            Action::Read => "mail:messages:read",
            Action::Search => "mail:messages:search",
            Action::ListAttachments => "mail:messages:attachments:list",
            Action::ReadAttachment => "mail:messages:attachments:read",
            Action::Send => "mail:messages:send",
            Action::Subscribe => "mail:messages:subscribe",
        }
    }

    /// Whether this action can disclose message content to the caller.
    ///
    /// Actions that read mail must pass through disclosure filtering; actions
    /// that do not (listing identities, sending) must not be filtered as if
    /// they were.
    pub fn reads_mail(self) -> bool {
        matches!(
            self,
            Action::List
                | Action::Read
                | Action::Search
                | Action::ListAttachments
                | Action::ReadAttachment
                | Action::Subscribe
        )
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Returned when a string does not name a known action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseActionError {
    input: String,
}

impl ParseActionError {
    /// The rejected input.
    pub fn input(&self) -> &str {
        &self.input
    }
}

impl fmt::Display for ParseActionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown mail action: {:?}", self.input)
    }
}

impl std::error::Error for ParseActionError {}

impl FromStr for Action {
    type Err = ParseActionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Action::ALL
            .into_iter()
            .find(|action| action.as_str() == s)
            .ok_or_else(|| ParseActionError {
                input: s.to_owned(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_its_wire_name() {
        for action in Action::ALL {
            assert_eq!(Action::from_str(action.as_str()), Ok(action));
        }
    }

    #[test]
    fn rejects_unknown_actions() {
        assert!(Action::from_str("mail:everything").is_err());
        assert!(Action::from_str("").is_err());
    }

    #[test]
    fn only_read_actions_disclose_mail() {
        assert!(Action::Read.reads_mail());
        assert!(Action::ListAttachments.reads_mail());
        assert!(!Action::Send.reads_mail());
        assert!(!Action::ListIdentities.reads_mail());
    }
}
