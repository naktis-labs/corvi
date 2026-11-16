//! Typed disclosure decisions.
//!
//! ADR-0003 section 2.3 requires a *typed* decision rather than a boolean,
//! because the four outcomes differ in what the caller may learn:
//!
//! - `hide` removes the message's existence entirely.
//! - `show` exposes the permitted fields.
//! - `redact` exposes a projection with field-level redactions applied.
//! - `strip` removes capabilities (remote content, attachments, links).
//!
//! `hide` always wins. There is no `stopProcessing` or `allowOverrideDeny`.

use mail_core::Class;
use serde::{Deserialize, Serialize};

/// The visibility decision for a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    /// The message must not be visible at all.
    Hide,
    /// The message is visible, subject to accumulated restrictions.
    Show,
    /// The message is visible with field-level redactions applied.
    Redact,
}

impl Visibility {
    /// Whether this decision permits any disclosure.
    pub fn permits_disclosure(self) -> bool {
        !matches!(self, Visibility::Hide)
    }
}

/// The default visibility of a policy that matches nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultVisibility {
    /// Nothing is visible unless a rule allows it.
    Hide,
    /// Everything is visible unless a rule denies it.
    Show,
}

impl DefaultVisibility {
    /// The visibility that applies when no rule matched.
    pub fn visibility(self) -> Visibility {
        match self {
            DefaultVisibility::Hide => Visibility::Hide,
            DefaultVisibility::Show => Visibility::Show,
        }
    }
}

/// What to do when a rule's condition cannot be evaluated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnIndeterminate {
    /// Treat the message as if it matched the rule.
    Hide,
    /// Treat the message as if it did not match the rule.
    Show,
}

impl Default for OnIndeterminate {
    /// `hide` is the secure default (ADR-0003 section 2.3).
    fn default() -> Self {
        OnIndeterminate::Hide
    }
}

/// A field that may be redacted from a message projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactableField {
    /// The message subject.
    Subject,
    /// The plain-text body.
    BodyText,
    /// The HTML body.
    BodyHtml,
    /// The sender address.
    SenderAddress,
    /// Recipient addresses.
    RecipientAddress,
    /// Link destinations.
    LinkTarget,
    /// Attachment filenames.
    AttachmentFilename,
}

impl RedactableField {
    /// The dotted path used in policy documents.
    pub fn path(self) -> &'static str {
        match self {
            RedactableField::Subject => "subject",
            RedactableField::BodyText => "body.text",
            RedactableField::BodyHtml => "body.html",
            RedactableField::SenderAddress => "address.sender",
            RedactableField::RecipientAddress => "address.recipient",
            RedactableField::LinkTarget => "link.target",
            RedactableField::AttachmentFilename => "attachment.filename",
        }
    }
}

/// A redaction rule: replace matching content in one field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Redaction {
    /// The field the rule applies to.
    pub field: RedactableField,
    /// The pattern to match.
    pub pattern: String,
    /// The replacement text.
    pub replacement: String,
}

/// Rendering restrictions applied to a visible message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HtmlRendering {
    /// Do not expose HTML at all.
    Deny,
    /// Expose sanitized HTML.
    Sanitized,
}

/// How remote content in HTML is treated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteContent {
    /// Leave remote references in place.
    Allow,
    /// Remove references to remote resources.
    Strip,
}

/// Whether attachments may be listed or downloaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttachmentAccess {
    /// Attachments are neither listed nor downloadable.
    Deny,
    /// Attachment metadata may be listed.
    Metadata,
    /// Attachment metadata and bytes are available.
    Full,
}

/// Whether link destinations are exposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalLinkPolicy {
    /// Links are exposed as-is.
    Allow,
    /// Links are exposed but their destinations are sanitized.
    Sanitize,
    /// Links are removed entirely.
    Deny,
}

/// Accumulated output restrictions.
///
/// Restrictions compose conservatively: the most restrictive value of each
/// kind wins, so two applicable filters can only ever narrow what is
/// disclosed, never widen it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Rendering {
    /// How HTML may be rendered.
    pub html: HtmlRendering,
    /// How remote content is treated.
    pub remote_content: RemoteContent,
    /// Whether attachments are accessible.
    pub attachments: AttachmentAccess,
    /// Whether link destinations are exposed.
    pub external_links: ExternalLinkPolicy,
}

impl Default for Rendering {
    fn default() -> Self {
        Self {
            html: HtmlRendering::Sanitized,
            remote_content: RemoteContent::Strip,
            attachments: AttachmentAccess::Deny,
            external_links: ExternalLinkPolicy::Sanitize,
        }
    }
}

impl Rendering {
    /// Combine two sets of restrictions, keeping the more restrictive of each.
    ///
    /// Each dimension has a fixed order of restrictiveness, so the merge is a
    /// per-dimension maximum on that order. Two applicable filters can
    /// therefore only narrow what is disclosed, never widen it.
    pub fn most_restrictive(self, other: Rendering) -> Rendering {
        Rendering {
            html: stricter(self.html, other.html, |v| match v {
                HtmlRendering::Sanitized => 0,
                HtmlRendering::Deny => 1,
            }),
            remote_content: stricter(self.remote_content, other.remote_content, |v| match v {
                RemoteContent::Allow => 0,
                RemoteContent::Strip => 1,
            }),
            attachments: stricter(self.attachments, other.attachments, |v| match v {
                AttachmentAccess::Full => 0,
                AttachmentAccess::Metadata => 1,
                AttachmentAccess::Deny => 2,
            }),
            external_links: stricter(self.external_links, other.external_links, |v| match v {
                ExternalLinkPolicy::Allow => 0,
                ExternalLinkPolicy::Sanitize => 1,
                ExternalLinkPolicy::Deny => 2,
            }),
        }
    }
}

/// Return whichever of two values is more restrictive, by rank.
fn stricter<T: Copy>(a: T, b: T, rank: impl Fn(T) -> u8) -> T {
    if rank(a) >= rank(b) { a } else { b }
}

/// A rule that matched a message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchedRule {
    /// The rule's identifier, for audit and diagnostics.
    pub id: String,
}

/// The outcome of evaluating every applicable filter against one message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    /// The effective visibility.
    pub visibility: Visibility,
    /// The redactions that apply, in the order they were added.
    pub redactions: Vec<Redaction>,
    /// The accumulated rendering restrictions.
    pub rendering: Rendering,
    /// The rules that matched.
    pub matched_rules: Vec<MatchedRule>,
    /// Whether any applicable rule could not be evaluated.
    ///
    /// When true, the decision already reflects `on_indeterminate`.
    pub indeterminate: bool,
}

impl Decision {
    /// Whether the message may be disclosed at all.
    pub fn permits_disclosure(&self) -> bool {
        self.visibility.permits_disclosure()
    }
}

/// The classification classes that make a message sensitive.
pub fn is_sensitive_class(class: Class) -> bool {
    matches!(
        class,
        Class::AuthOtp
            | Class::AuthPasswordReset
            | Class::AuthLoginLink
            | Class::AuthMfa
            | Class::FinancialAccountIdentifier
            | Class::CredentialSecret
            | Class::PersonalIdentityDocument
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hide_always_wins_over_other_visibility() {
        assert!(!Visibility::Hide.permits_disclosure());
        assert!(Visibility::Show.permits_disclosure());
        assert!(Visibility::Redact.permits_disclosure());
    }

    #[test]
    fn rendering_restrictions_only_narrow() {
        let strict = Rendering {
            html: HtmlRendering::Deny,
            remote_content: RemoteContent::Strip,
            attachments: AttachmentAccess::Deny,
            external_links: ExternalLinkPolicy::Deny,
        };
        let loose = Rendering::default();
        assert_eq!(strict.most_restrictive(loose), strict);
        assert_eq!(loose.most_restrictive(strict), strict);
    }

    #[test]
    fn attachment_access_combines_conservatively() {
        let metadata = Rendering {
            attachments: AttachmentAccess::Metadata,
            ..Rendering::default()
        };
        let full = Rendering {
            attachments: AttachmentAccess::Full,
            ..Rendering::default()
        };
        assert_eq!(
            metadata.most_restrictive(full).attachments,
            AttachmentAccess::Metadata
        );
        assert_eq!(
            full.most_restrictive(metadata).attachments,
            AttachmentAccess::Metadata
        );
    }

    #[test]
    fn indeterminate_defaults_to_hide() {
        assert_eq!(OnIndeterminate::default(), OnIndeterminate::Hide);
    }
}
