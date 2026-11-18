//! The typed decision and obligation contract.
//!
//! ADR-0004 requires that every policy engine - built-in, sandboxed Wasm or a
//! remote gRPC PDP - answers with the same conceptual result: an effect plus a
//! bounded list of typed obligations. Three properties of this module are
//! load bearing:
//!
//! * A decision is **typed**, not a boolean. `ALLOW`, `DENY` and
//!   `INDETERMINATE` are distinct, and `INDETERMINATE` fails closed.
//! * Obligations are **typed and bounded**. An unknown obligation kind, a
//!   redaction without a field path or a field path outside the allowlist is
//!   an *error*: the decision is rejected, not repaired. A valid `ALLOW` with
//!   malformed obligations is an error, never permission to ignore them.
//! * An engine may only **narrow** a locally computed decision. The local
//!   decision is the outer boundary; an engine can add obligations and turn an
//!   allow into a deny, but it can never lift a local deny or drop a local
//!   restriction.
//!
//! The request type is deliberately narrow. It carries the authenticated
//! principal, the requested action, opaque resource and identity references,
//! bounded classifications and explicitly allowlisted attributes. It has no
//! field for a provider administrative secret and no field for a message body:
//! the engine never sees raw mail, and a remote engine never sees provider
//! credentials.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

/// The effect of a policy evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    /// The engine permits the requested action, subject to its obligations.
    Allow,
    /// The engine refuses the requested action.
    Deny,
    /// The engine could not reach a decision.
    ///
    /// This is never permissive: an indeterminate result fails closed.
    Indeterminate,
}

impl Effect {
    /// The wire name of the effect.
    pub fn as_wire(self) -> &'static str {
        match self {
            Effect::Allow => "allow",
            Effect::Deny => "deny",
            Effect::Indeterminate => "indeterminate",
        }
    }

    /// Parse an effect from its wire name.
    pub fn from_wire(name: &str) -> Option<Self> {
        match name {
            "allow" => Some(Effect::Allow),
            "deny" => Some(Effect::Deny),
            "indeterminate" => Some(Effect::Indeterminate),
            _ => None,
        }
    }

    /// Whether the effect permits the requested action on its own.
    pub fn is_permissive(self) -> bool {
        matches!(self, Effect::Allow)
    }
}

/// The kinds of obligation an engine may return.
///
/// An engine may only ever ask for *more* restriction, so this list is closed:
/// every kind names a restriction that Corvi's own projection applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObligationKind {
    /// Hide the message entirely.
    HideMessage,
    /// Redact one field of the message.
    RedactField,
    /// Deny access to attachments.
    DenyAttachments,
    /// Sanitize the HTML body.
    SanitizeHtml,
    /// Remove external links.
    RemoveExternalLinks,
}

impl ObligationKind {
    /// The wire name of the obligation kind.
    pub fn as_wire(self) -> &'static str {
        match self {
            ObligationKind::HideMessage => "hide_message",
            ObligationKind::RedactField => "redact_field",
            ObligationKind::DenyAttachments => "deny_attachments",
            ObligationKind::SanitizeHtml => "sanitize_html",
            ObligationKind::RemoveExternalLinks => "remove_external_links",
        }
    }

    /// Parse an obligation kind from its wire name.
    ///
    /// An unknown name yields `None`: an unknown obligation is never silently
    /// ignored, it fails the whole decision closed.
    pub fn from_wire(name: &str) -> Option<Self> {
        match name {
            "hide_message" => Some(ObligationKind::HideMessage),
            "redact_field" => Some(ObligationKind::RedactField),
            "deny_attachments" => Some(ObligationKind::DenyAttachments),
            "sanitize_html" => Some(ObligationKind::SanitizeHtml),
            "remove_external_links" => Some(ObligationKind::RemoveExternalLinks),
            _ => None,
        }
    }

    /// Whether this obligation names a field.
    pub fn takes_field(self) -> bool {
        matches!(self, ObligationKind::RedactField)
    }
}

/// The fields a policy may ask Corvi to redact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactableField {
    /// The message subject.
    Subject,
    /// The plain text body.
    BodyText,
    /// The HTML body.
    BodyHtml,
    /// The sender address.
    SenderAddress,
    /// The recipient addresses.
    RecipientAddress,
    /// The link destinations.
    LinkTarget,
    /// The attachment file names.
    AttachmentFilename,
}

impl RedactableField {
    /// The dotted path of the field in a message projection.
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

    /// The field for a dotted path.
    pub fn from_path(path: &str) -> Option<Self> {
        match path {
            "subject" => Some(RedactableField::Subject),
            "body.text" => Some(RedactableField::BodyText),
            "body.html" => Some(RedactableField::BodyHtml),
            "address.sender" => Some(RedactableField::SenderAddress),
            "address.recipient" => Some(RedactableField::RecipientAddress),
            "link.target" => Some(RedactableField::LinkTarget),
            "attachment.filename" => Some(RedactableField::AttachmentFilename),
            _ => None,
        }
    }
}

/// A typed restriction an engine asks Corvi to apply.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Obligation {
    /// The kind of restriction.
    pub kind: ObligationKind,
    /// The field path, for [`ObligationKind::RedactField`] only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field_path: Option<String>,
}

impl Obligation {
    /// An obligation that does not name a field.
    pub fn simple(kind: ObligationKind) -> Self {
        Self {
            kind,
            field_path: None,
        }
    }

    /// A redaction obligation for one allowlisted field.
    pub fn redact(field: RedactableField) -> Self {
        Self {
            kind: ObligationKind::RedactField,
            field_path: Some(field.path().to_string()),
        }
    }

    /// Whether the obligation is well formed.
    pub fn is_well_formed(&self) -> bool {
        match self.kind {
            ObligationKind::RedactField => self
                .field_path
                .as_deref()
                .and_then(RedactableField::from_path)
                .is_some(),
            _ => self.field_path.is_none(),
        }
    }
}

/// An obligation as it arrives from an engine, before validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireObligation {
    /// The wire name of the obligation kind.
    pub kind: String,
    /// The field path, when the obligation names one.
    #[serde(default)]
    pub field_path: Option<String>,
}

/// A decision as it arrives from an engine, before validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireDecision {
    /// The wire name of the effect.
    pub effect: String,
    /// The obligations the engine asks for.
    #[serde(default)]
    pub obligations: Vec<WireObligation>,
}

impl WireDecision {
    /// Validate the decision and its obligations.
    ///
    /// Every failure is an error. A decision is never repaired by dropping the
    /// obligations it could not be understood.
    pub fn validate(&self) -> Result<PolicyDecision, DecisionError> {
        let effect = Effect::from_wire(&self.effect)
            .ok_or_else(|| DecisionError::UnknownEffect(self.effect.clone()))?;

        let mut obligations = Vec::with_capacity(self.obligations.len());
        for wire in &self.obligations {
            let kind = ObligationKind::from_wire(&wire.kind)
                .ok_or_else(|| DecisionError::UnknownObligation(wire.kind.clone()))?;
            let obligation = Obligation {
                kind,
                field_path: wire.field_path.clone(),
            };
            if !obligation.is_well_formed() {
                return Err(DecisionError::MalformedObligation {
                    kind,
                    reason: match (
                        obligation.kind.takes_field(),
                        obligation.field_path.as_deref(),
                    ) {
                        (true, None) => {
                            "a redact_field obligation must name an allowlisted field".to_string()
                        }
                        (true, Some(path)) => {
                            format!("{path} is not an allowlisted redactable field")
                        }
                        (false, Some(_)) => {
                            "only a redact_field obligation may name a field".to_string()
                        }
                        (false, None) => "the obligation is not well formed".to_string(),
                    },
                });
            }
            obligations.push(obligation);
        }

        Ok(PolicyDecision {
            effect,
            obligations,
        })
    }
}

/// A validated decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDecision {
    /// The effect of the evaluation.
    pub effect: Effect,
    /// The typed obligations the engine asks for.
    pub obligations: Vec<Obligation>,
}

/// Why a decision could not be accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecisionError {
    /// The effect name is not one of the known effects.
    UnknownEffect(String),
    /// The obligation kind is not one of the known kinds.
    UnknownObligation(String),
    /// The obligation is known but not well formed.
    MalformedObligation {
        /// The obligation kind.
        kind: ObligationKind,
        /// Why the obligation was rejected.
        reason: String,
    },
    /// The decision carries more obligations than the engine limit allows.
    TooManyObligations {
        /// How many obligations were returned.
        count: usize,
        /// The limit that was exceeded.
        limit: usize,
    },
}

impl fmt::Display for DecisionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecisionError::UnknownEffect(effect) => {
                write!(formatter, "unknown policy effect {effect}")
            }
            DecisionError::UnknownObligation(kind) => {
                write!(formatter, "unknown policy obligation {kind}")
            }
            DecisionError::MalformedObligation { kind, reason } => {
                write!(
                    formatter,
                    "malformed {} obligation: {reason}",
                    kind.as_wire()
                )
            }
            DecisionError::TooManyObligations { count, limit } => {
                write!(
                    formatter,
                    "the decision carries {count} obligations, the limit is {limit}"
                )
            }
        }
    }
}

impl std::error::Error for DecisionError {}

/// A decision computed locally, before any engine is consulted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalDecision {
    /// The locally computed effect.
    pub effect: Effect,
    /// The locally computed obligations.
    pub obligations: Vec<Obligation>,
}

impl LocalDecision {
    /// A local decision that permits the action.
    pub fn allow(obligations: Vec<Obligation>) -> Self {
        Self {
            effect: Effect::Allow,
            obligations,
        }
    }

    /// A local decision that refuses the action.
    pub fn deny(obligations: Vec<Obligation>) -> Self {
        Self {
            effect: Effect::Deny,
            obligations,
        }
    }

    /// Whether the local decision permits the action.
    pub fn permits(&self) -> bool {
        self.effect.is_permissive()
    }
}

/// Combine a local decision with an engine decision.
///
/// The engine may only restrict:
///
/// * a local `DENY` stays a `DENY`, whatever the engine says;
/// * an engine `DENY` denies;
/// * an engine `INDETERMINATE` denies, because an unusable engine is not a
///   permission;
/// * an engine `ALLOW` keeps the local effect and unions the obligations, so
///   no local restriction is ever dropped.
pub fn restrict(local: &LocalDecision, engine: &PolicyDecision) -> LocalDecision {
    let mut obligations: BTreeSet<Obligation> = local.obligations.iter().cloned().collect();
    obligations.extend(engine.obligations.iter().cloned());

    let effect = match (local.effect, engine.effect) {
        (Effect::Allow, Effect::Allow) => Effect::Allow,
        _ => Effect::Deny,
    };

    LocalDecision {
        effect,
        obligations: obligations.into_iter().collect(),
    }
}

/// The attributes a policy engine may receive.
///
/// Attribute names are chosen by the local administrator; anything else is
/// refused rather than released.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributePolicy {
    allowed: BTreeSet<String>,
    max_value_length: usize,
}

impl AttributePolicy {
    /// A policy that releases no attributes at all.
    pub fn deny_all() -> Self {
        Self {
            allowed: BTreeSet::new(),
            max_value_length: 0,
        }
    }

    /// A policy that releases the named attributes.
    pub fn new<I, S>(allowed: I, max_value_length: usize) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            allowed: allowed.into_iter().map(Into::into).collect(),
            max_value_length,
        }
    }

    /// Whether an attribute name may be released.
    pub fn permits(&self, name: &str) -> bool {
        self.allowed.contains(name)
    }

    /// The maximum length of an attribute value.
    pub fn max_value_length(&self) -> usize {
        self.max_value_length
    }
}

/// Why a request could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestError {
    /// The attribute is not on the allowlist.
    AttributeNotAllowed(String),
    /// The attribute value is longer than the limit.
    AttributeValueTooLong {
        /// The attribute name.
        name: String,
        /// The length of the value.
        length: usize,
        /// The limit that was exceeded.
        limit: usize,
    },
}

impl fmt::Display for RequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RequestError::AttributeNotAllowed(name) => {
                write!(formatter, "the attribute {name} is not allowlisted")
            }
            RequestError::AttributeValueTooLong {
                name,
                length,
                limit,
            } => write!(
                formatter,
                "the attribute {name} is {length} bytes long, the limit is {limit}"
            ),
        }
    }
}

impl std::error::Error for RequestError {}

/// The request an engine is asked to decide.
///
/// The type has no field for a provider administrative secret and no field for
/// a message body. The engine learns what it needs to decide and nothing else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRequest {
    /// The authenticated principal. This is Corvi's own identity, never one
    /// supplied by the caller of a remote engine.
    pub principal_id: String,
    /// The credential scope the principal holds.
    pub credential_scope_id: String,
    /// The requested action.
    pub action: String,
    /// An opaque reference to the requested resource.
    pub resource_id: String,
    /// The identity the request is made in.
    pub identity_id: String,
    /// The configuration revision the decision applies to.
    pub configuration_revision: String,
    /// The bounded classifications of the resource.
    pub classifications: Vec<String>,
    /// The explicitly allowlisted attributes of the resource.
    pub attributes: BTreeMap<String, String>,
}

impl PolicyRequest {
    /// A request without classifications or attributes.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        principal_id: &str,
        credential_scope_id: &str,
        action: &str,
        resource_id: &str,
        identity_id: &str,
        configuration_revision: &str,
    ) -> Self {
        Self {
            principal_id: principal_id.to_string(),
            credential_scope_id: credential_scope_id.to_string(),
            action: action.to_string(),
            resource_id: resource_id.to_string(),
            identity_id: identity_id.to_string(),
            configuration_revision: configuration_revision.to_string(),
            classifications: Vec::new(),
            attributes: BTreeMap::new(),
        }
    }

    /// Add an allowlisted attribute to the request.
    ///
    /// An attribute that is not on the allowlist, or whose value is too long,
    /// is refused: the request is built without it rather than with a value
    /// the administrator never approved.
    pub fn set_attribute(
        &mut self,
        policy: &AttributePolicy,
        name: &str,
        value: &str,
    ) -> Result<(), RequestError> {
        if !policy.permits(name) {
            return Err(RequestError::AttributeNotAllowed(name.to_string()));
        }
        if value.len() > policy.max_value_length() {
            return Err(RequestError::AttributeValueTooLong {
                name: name.to_string(),
                length: value.len(),
                limit: policy.max_value_length(),
            });
        }
        self.attributes.insert(name.to_string(), value.to_string());
        Ok(())
    }
}
