//! The MailCredential resource model: one CRD, one protocol shape, one target.
//!
//! ADR-0014 defines exactly one credential custom resource. This module is
//! its typed shape: the protocol a credential speaks, the single target it
//! is bound to, the optional Corvi permission list that distinguishes a
//! scoped credential from a provider-native one, and the optional Secret
//! template.
//!
//! Three rules shape the parser.
//!
//! 1. **One protocol shape.** A credential speaks one protocol. A document
//!    that declares two shapes is refused instead of being resolved to the
//!    first one that happens to parse, because a credential with an
//!    ambiguous authority is a credential with an unknown authority.
//! 2. **Presence is meaning.** An absent `permissions` field asks for
//!    provider-native authority; a present one — even an empty list — asks
//!    for Corvi-scoped authority. That difference is a statement of intent,
//!    not a default value, so the parser keeps it.
//! 3. **Nothing is inferred.** An explicit `null`, an unknown protocol and
//!    an unknown field are errors. A credential is never repaired into a
//!    shape it did not ask for.

use std::collections::BTreeMap;
use std::fmt;

use serde_yaml::{Mapping, Value};

/// The largest number of annotations a Secret template may request.
pub const MAX_SECRET_ANNOTATIONS: usize = 32;

/// The largest length of one Secret template annotation value.
pub const MAX_ANNOTATION_VALUE_LENGTH: usize = 4096;

/// The largest length of one Secret template annotation key.
pub const MAX_ANNOTATION_KEY_LENGTH: usize = 253;

/// The protocol a credential connects with.
///
/// The set is closed. An IMAP endpoint or a JMAP HTTP session does not imply
/// an MCP or REST credential (ADR-0014 section 3), so there is no fallback
/// between protocols and no "any" variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProtocolType {
    /// Submission over SMTP.
    Smtp,
    /// A provider's or the gateway's HTTPS REST endpoint.
    Rest,
    /// A provider's or the gateway's HTTPS MCP endpoint.
    Mcp,
}

impl ProtocolType {
    /// The protocol a credential uses when it declares none.
    pub const DEFAULT: Self = Self::Smtp;

    /// Every protocol in the vocabulary.
    pub const ALL: [Self; 3] = [Self::Smtp, Self::Rest, Self::Mcp];

    /// The wire name of the protocol.
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::Smtp => "smtp",
            Self::Rest => "rest",
            Self::Mcp => "mcp",
        }
    }

    /// Parse a protocol name.
    ///
    /// Only the three names in the vocabulary are accepted. An unknown name
    /// is not "probably SMTP".
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "smtp" => Some(Self::Smtp),
            "rest" => Some(Self::Rest),
            "mcp" => Some(Self::Mcp),
            _ => None,
        }
    }
}

impl fmt::Display for ProtocolType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_wire())
    }
}

/// The kind of resource a credential targets.
///
/// A credential names exactly one target of one kind, in its own namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TargetKind {
    /// A `MailIdentity`: a sender inside a mailbox.
    MailIdentity,
    /// A `Mailbox`: a physical mailbox owned by a provider.
    Mailbox,
}

impl TargetKind {
    /// The wire name of the target kind.
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::MailIdentity => "MailIdentity",
            Self::Mailbox => "Mailbox",
        }
    }

    /// Parse a target kind name.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "MailIdentity" => Some(Self::MailIdentity),
            "Mailbox" => Some(Self::Mailbox),
            _ => None,
        }
    }
}

impl fmt::Display for TargetKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_wire())
    }
}

/// One Corvi mail action a scoped credential may request.
///
/// The list is the closed set ADR-0014 fixes. A permission outside it is
/// refused rather than carried, because a permission nobody evaluates is a
/// permission nobody denies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Permission {
    /// `mail:identities:list`.
    IdentitiesList,
    /// `mail:messages:list`.
    MessagesList,
    /// `mail:messages:search`.
    MessagesSearch,
    /// `mail:messages:read`.
    MessagesRead,
    /// `mail:attachments:read`.
    AttachmentsRead,
    /// `mail:messages:send`.
    MessagesSend,
    /// `mail:submissions:read`.
    SubmissionsRead,
    /// `mail:messages:subscribe`.
    MessagesSubscribe,
}

impl Permission {
    /// Every action in the vocabulary.
    pub const ALL: [Self; 8] = [
        Self::IdentitiesList,
        Self::MessagesList,
        Self::MessagesSearch,
        Self::MessagesRead,
        Self::AttachmentsRead,
        Self::MessagesSend,
        Self::SubmissionsRead,
        Self::MessagesSubscribe,
    ];

    /// The wire name of the action.
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::IdentitiesList => "mail:identities:list",
            Self::MessagesList => "mail:messages:list",
            Self::MessagesSearch => "mail:messages:search",
            Self::MessagesRead => "mail:messages:read",
            Self::AttachmentsRead => "mail:attachments:read",
            Self::MessagesSend => "mail:messages:send",
            Self::SubmissionsRead => "mail:submissions:read",
            Self::MessagesSubscribe => "mail:messages:subscribe",
        }
    }

    /// Parse an action name.
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|action| action.as_wire() == value)
    }
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_wire())
    }
}

/// The single same-namespace resource a credential is bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetRef {
    kind: TargetKind,
    name: String,
}

impl TargetRef {
    /// Bind a credential to a target.
    pub fn new(kind: TargetKind, name: impl Into<String>) -> Self {
        Self {
            kind,
            name: name.into(),
        }
    }

    /// The kind of the target.
    pub fn kind(&self) -> TargetKind {
        self.kind
    }

    /// The name of the target.
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// The metadata a credential may request for its Secret.
///
/// Only a name and annotations are accepted. A caller cannot ask for Secret
/// data, a Secret type, immutability, labels, owner references or another
/// namespace: those are the publisher's decisions, not the caller's.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SecretTemplateMetadata {
    name: Option<String>,
    annotations: BTreeMap<String, String>,
}

impl SecretTemplateMetadata {
    /// The requested Secret name, if the credential names one.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// The requested Secret annotations.
    pub fn annotations(&self) -> &BTreeMap<String, String> {
        &self.annotations
    }
}

/// The optional Secret template of a credential.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SecretTemplate {
    metadata: SecretTemplateMetadata,
}

impl SecretTemplate {
    /// The requested Secret metadata.
    pub fn metadata(&self) -> &SecretTemplateMetadata {
        &self.metadata
    }
}

/// Which authority a credential asks for.
///
/// The answer comes from the credential's own document, never from the
/// resource graph: a scoped credential stays scoped and a native credential
/// stays native, whatever the graph looks like later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestedAuthority {
    /// Corvi-scoped authority, expressed as Corvi permissions.
    Scoped,
    /// Provider-native authority, issued by the provider itself.
    Native,
}

/// Why a credential document was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpecError {
    /// The document is not a mapping, or a field has the wrong shape.
    MalformedDocument(String),
    /// The document has no `spec` mapping.
    MissingSpec,
    /// The document carries a field the contract does not define.
    UnknownField {
        /// The offending field, with its path.
        field: String,
    },
    /// A field is explicitly null.
    ///
    /// An explicit null is not an absent field: it is a statement that the
    /// author wanted a value there, and guessing one would silently widen
    /// or narrow the credential.
    ExplicitNull {
        /// The offending field, with its path.
        field: String,
    },
    /// The requested protocol is not in the vocabulary.
    UnsupportedProtocolType {
        /// The rejected value.
        value: String,
    },
    /// The document declares more than one protocol shape.
    MultipleProtocolShapes {
        /// Every declaration that was found.
        declared: Vec<String>,
    },
    /// The document uses the legacy `shape` field.
    ///
    /// A single legacy declaration is refused rather than interpreted: the
    /// legacy field has no defined semantics, and interpreting it would be
    /// inventing one.
    LegacyShapeField {
        /// The rejected declaration.
        value: String,
    },
    /// The target kind is not in the vocabulary.
    InvalidTargetKind {
        /// The rejected value.
        value: String,
    },
    /// A name is not a valid DNS-1123 label.
    InvalidName {
        /// The field the name came from.
        field: String,
        /// The rejected value.
        value: String,
    },
    /// A requested action is not in the vocabulary.
    UnknownPermission {
        /// The rejected value.
        value: String,
    },
    /// The same action was requested twice.
    DuplicatePermission {
        /// The repeated value.
        value: String,
    },
    /// An annotation is malformed or out of bounds.
    InvalidAnnotation {
        /// The offending key.
        key: String,
        /// Why it was refused.
        reason: String,
    },
    /// The template requests more annotations than the contract allows.
    TooManyAnnotations {
        /// How many were requested.
        count: usize,
    },
}

impl fmt::Display for SpecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedDocument(reason) => write!(f, "malformed credential document: {reason}"),
            Self::MissingSpec => f.write_str("the credential document has no spec"),
            Self::UnknownField { field } => write!(f, "unknown field {field}"),
            Self::ExplicitNull { field } => write!(f, "field {field} is explicitly null"),
            Self::UnsupportedProtocolType { value } => {
                write!(f, "unsupported credential protocol {value}")
            }
            Self::MultipleProtocolShapes { declared } => {
                write!(
                    f,
                    "a credential declares one protocol shape, found {declared:?}"
                )
            }
            Self::LegacyShapeField { value } => {
                write!(f, "the legacy shape field is not interpreted: {value}")
            }
            Self::InvalidTargetKind { value } => write!(f, "unsupported target kind {value}"),
            Self::InvalidName { field, value } => {
                write!(f, "{field} is not a valid DNS-1123 label: {value}")
            }
            Self::UnknownPermission { value } => write!(f, "unknown mail action {value}"),
            Self::DuplicatePermission { value } => {
                write!(f, "mail action {value} is requested twice")
            }
            Self::InvalidAnnotation { key, reason } => {
                write!(f, "annotation {key} is refused: {reason}")
            }
            Self::TooManyAnnotations { count } => {
                write!(
                    f,
                    "a Secret template may request at most {MAX_SECRET_ANNOTATIONS} annotations, found {count}"
                )
            }
        }
    }
}

impl std::error::Error for SpecError {}

/// The validated specification of one MailCredential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailCredentialSpec {
    credential_type: ProtocolType,
    target_ref: TargetRef,
    permissions: Option<Vec<Permission>>,
    secret_template: Option<SecretTemplate>,
}

impl MailCredentialSpec {
    /// Parse and validate a credential specification document.
    pub fn parse(document: &str) -> Result<Self, SpecError> {
        let value: Value = serde_yaml::from_str(document)
            .map_err(|error| SpecError::MalformedDocument(error.to_string()))?;
        Self::from_value(&value)
    }

    /// Validate a credential specification that has already been decoded.
    pub fn from_value(value: &Value) -> Result<Self, SpecError> {
        let spec = value.as_mapping().ok_or_else(|| {
            SpecError::MalformedDocument("the spec must be a mapping".to_string())
        })?;

        for key in spec.keys() {
            let name = key.as_str().ok_or_else(|| {
                SpecError::MalformedDocument("field names must be strings".to_string())
            })?;
            if !SPEC_FIELDS.contains(&name) {
                return Err(SpecError::UnknownField {
                    field: format!("spec.{name}"),
                });
            }
        }

        let credential_type = declared_protocol(spec)?;
        let target_value = spec.get("targetRef").ok_or_else(|| {
            SpecError::MalformedDocument("spec.targetRef is required".to_string())
        })?;
        let target_ref = parse_target_ref(target_value)?;
        let permissions = parse_permissions(spec.get("permissions"))?;
        let secret_template = parse_secret_template(spec.get("secretTemplate"))?;

        Ok(Self {
            credential_type,
            target_ref,
            permissions,
            secret_template,
        })
    }

    /// The protocol the credential speaks.
    pub fn credential_type(&self) -> ProtocolType {
        self.credential_type
    }

    /// The single target the credential is bound to.
    pub fn target_ref(&self) -> &TargetRef {
        &self.target_ref
    }

    /// The requested Corvi permissions, if the credential asks for any.
    ///
    /// `Some` and empty are different answers: an empty list still asks for
    /// Corvi-scoped authority and is refused later for having no actions.
    pub fn permissions(&self) -> Option<&[Permission]> {
        self.permissions.as_deref()
    }

    /// The requested Secret template, if the credential names one.
    pub fn secret_template(&self) -> Option<&SecretTemplate> {
        self.secret_template.as_ref()
    }

    /// The authority the credential asks for.
    pub fn requested_authority(&self) -> RequestedAuthority {
        if self.permissions.is_some() {
            RequestedAuthority::Scoped
        } else {
            RequestedAuthority::Native
        }
    }

    /// The Secret name this credential publishes to.
    ///
    /// A credential that names its own Secret uses that name. Otherwise the
    /// name is derived from the credential's own name and UID, so it is
    /// stable across restarts and different for two credentials that share a
    /// name.
    pub fn secret_name(&self, credential_name: &str, uid: &str) -> String {
        match self
            .secret_template
            .as_ref()
            .and_then(|template| template.metadata().name())
        {
            Some(name) => name.to_string(),
            None => default_secret_name(credential_name, uid),
        }
    }
}

/// The fields a credential specification may carry.
const SPEC_FIELDS: [&str; 5] = [
    "type",
    "targetRef",
    "permissions",
    "secretTemplate",
    "shape",
];

/// Collect the protocol declarations of a specification.
///
/// The canonical declaration is `spec.type`. The legacy `spec.shape` field
/// is recognised only so that it can be refused: it has no defined
/// semantics, and a document that carries both a canonical type and a
/// legacy shape declares two protocol shapes at once.
fn declared_protocol(spec: &Mapping) -> Result<ProtocolType, SpecError> {
    let mut declarations: Vec<String> = Vec::new();
    let mut protocol = ProtocolType::DEFAULT;

    if let Some(value) = spec.get("type") {
        if value.is_null() {
            return Err(SpecError::ExplicitNull {
                field: "spec.type".to_string(),
            });
        }
        let text = value.as_str().ok_or_else(|| {
            SpecError::MalformedDocument("spec.type must be a string".to_string())
        })?;
        protocol = ProtocolType::parse(text).ok_or_else(|| SpecError::UnsupportedProtocolType {
            value: text.to_string(),
        })?;
        declarations.push(format!("type:{}", protocol.as_wire()));
    }

    if let Some(value) = spec.get("shape") {
        match value {
            Value::String(text) => declarations.push(format!("shape:{text}")),
            Value::Sequence(items) => {
                for item in items {
                    let text = item.as_str().ok_or_else(|| {
                        SpecError::MalformedDocument(
                            "spec.shape entries must be strings".to_string(),
                        )
                    })?;
                    declarations.push(format!("shape:{text}"));
                }
            }
            Value::Null => {
                return Err(SpecError::ExplicitNull {
                    field: "spec.shape".to_string(),
                });
            }
            _ => {
                return Err(SpecError::MalformedDocument(
                    "spec.shape must be a string or a list of strings".to_string(),
                ));
            }
        }
    }

    match declarations.len() {
        0 => Ok(ProtocolType::DEFAULT),
        1 if spec.get("shape").is_some() => Err(SpecError::LegacyShapeField {
            value: declarations[0].clone(),
        }),
        1 => Ok(protocol),
        _ => Err(SpecError::MultipleProtocolShapes {
            declared: declarations,
        }),
    }
}

/// Parse the single target reference of a credential.
fn parse_target_ref(value: &Value) -> Result<TargetRef, SpecError> {
    let target = value.as_mapping().ok_or_else(|| {
        SpecError::MalformedDocument("spec.targetRef must be a mapping".to_string())
    })?;
    for key in target.keys() {
        let name = key.as_str().ok_or_else(|| {
            SpecError::MalformedDocument("field names must be strings".to_string())
        })?;
        if !matches!(name, "kind" | "name") {
            return Err(SpecError::UnknownField {
                field: format!("spec.targetRef.{name}"),
            });
        }
    }

    let kind_value = target.get("kind").ok_or_else(|| {
        SpecError::MalformedDocument("spec.targetRef.kind is required".to_string())
    })?;
    if kind_value.is_null() {
        return Err(SpecError::ExplicitNull {
            field: "spec.targetRef.kind".to_string(),
        });
    }
    let kind_text = kind_value.as_str().ok_or_else(|| {
        SpecError::MalformedDocument("spec.targetRef.kind must be a string".to_string())
    })?;
    let kind = TargetKind::parse(kind_text).ok_or_else(|| SpecError::InvalidTargetKind {
        value: kind_text.to_string(),
    })?;

    let name_value = target.get("name").ok_or_else(|| {
        SpecError::MalformedDocument("spec.targetRef.name is required".to_string())
    })?;
    if name_value.is_null() {
        return Err(SpecError::ExplicitNull {
            field: "spec.targetRef.name".to_string(),
        });
    }
    let name = name_value.as_str().ok_or_else(|| {
        SpecError::MalformedDocument("spec.targetRef.name must be a string".to_string())
    })?;
    if !is_dns_label(name) {
        return Err(SpecError::InvalidName {
            field: "spec.targetRef.name".to_string(),
            value: name.to_string(),
        });
    }

    Ok(TargetRef {
        kind,
        name: name.to_string(),
    })
}

/// Parse the optional permission list of a credential.
fn parse_permissions(value: Option<&Value>) -> Result<Option<Vec<Permission>>, SpecError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Err(SpecError::ExplicitNull {
            field: "spec.permissions".to_string(),
        });
    }
    let items = value.as_sequence().ok_or_else(|| {
        SpecError::MalformedDocument("spec.permissions must be a list".to_string())
    })?;

    let mut permissions: Vec<Permission> = Vec::with_capacity(items.len());
    for item in items {
        let text = item.as_str().ok_or_else(|| {
            SpecError::MalformedDocument("spec.permissions entries must be strings".to_string())
        })?;
        let permission = Permission::parse(text).ok_or_else(|| SpecError::UnknownPermission {
            value: text.to_string(),
        })?;
        if permissions.contains(&permission) {
            return Err(SpecError::DuplicatePermission {
                value: text.to_string(),
            });
        }
        permissions.push(permission);
    }
    Ok(Some(permissions))
}

/// Parse the optional Secret template of a credential.
fn parse_secret_template(value: Option<&Value>) -> Result<Option<SecretTemplate>, SpecError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Err(SpecError::ExplicitNull {
            field: "spec.secretTemplate".to_string(),
        });
    }
    let template = value.as_mapping().ok_or_else(|| {
        SpecError::MalformedDocument("spec.secretTemplate must be a mapping".to_string())
    })?;
    for key in template.keys() {
        let name = key.as_str().ok_or_else(|| {
            SpecError::MalformedDocument("field names must be strings".to_string())
        })?;
        if name != "metadata" {
            return Err(SpecError::UnknownField {
                field: format!("spec.secretTemplate.{name}"),
            });
        }
    }

    let metadata_value = template.get("metadata").ok_or_else(|| {
        SpecError::MalformedDocument("spec.secretTemplate.metadata is required".to_string())
    })?;
    if metadata_value.is_null() {
        return Err(SpecError::ExplicitNull {
            field: "spec.secretTemplate.metadata".to_string(),
        });
    }
    let metadata = metadata_value.as_mapping().ok_or_else(|| {
        SpecError::MalformedDocument("spec.secretTemplate.metadata must be a mapping".to_string())
    })?;
    for key in metadata.keys() {
        let name = key.as_str().ok_or_else(|| {
            SpecError::MalformedDocument("field names must be strings".to_string())
        })?;
        if !matches!(name, "name" | "annotations") {
            return Err(SpecError::UnknownField {
                field: format!("spec.secretTemplate.metadata.{name}"),
            });
        }
    }

    let name = match metadata.get("name") {
        None => None,
        Some(value) if value.is_null() => {
            return Err(SpecError::ExplicitNull {
                field: "spec.secretTemplate.metadata.name".to_string(),
            });
        }
        Some(value) => {
            let text = value.as_str().ok_or_else(|| {
                SpecError::MalformedDocument(
                    "spec.secretTemplate.metadata.name must be a string".to_string(),
                )
            })?;
            if !is_dns_label(text) {
                return Err(SpecError::InvalidName {
                    field: "spec.secretTemplate.metadata.name".to_string(),
                    value: text.to_string(),
                });
            }
            Some(text.to_string())
        }
    };

    let annotations = match metadata.get("annotations") {
        None => BTreeMap::new(),
        Some(value) if value.is_null() => {
            return Err(SpecError::ExplicitNull {
                field: "spec.secretTemplate.metadata.annotations".to_string(),
            });
        }
        Some(value) => {
            let entries = value.as_mapping().ok_or_else(|| {
                SpecError::MalformedDocument(
                    "spec.secretTemplate.metadata.annotations must be a mapping".to_string(),
                )
            })?;
            if entries.len() > MAX_SECRET_ANNOTATIONS {
                return Err(SpecError::TooManyAnnotations {
                    count: entries.len(),
                });
            }
            let mut annotations: BTreeMap<String, String> = BTreeMap::new();
            for (key, value) in entries {
                let key_text = key.as_str().ok_or_else(|| {
                    SpecError::MalformedDocument("annotation names must be strings".to_string())
                })?;
                if key_text.len() > MAX_ANNOTATION_KEY_LENGTH {
                    return Err(SpecError::InvalidAnnotation {
                        key: key_text.to_string(),
                        reason: format!(
                            "a key may hold at most {MAX_ANNOTATION_KEY_LENGTH} characters"
                        ),
                    });
                }
                let value_text = value.as_str().ok_or_else(|| {
                    SpecError::MalformedDocument("annotation values must be strings".to_string())
                })?;
                if value_text.len() > MAX_ANNOTATION_VALUE_LENGTH {
                    return Err(SpecError::InvalidAnnotation {
                        key: key_text.to_string(),
                        reason: format!(
                            "a value may hold at most {MAX_ANNOTATION_VALUE_LENGTH} characters"
                        ),
                    });
                }
                annotations.insert(key_text.to_string(), value_text.to_string());
            }
            annotations
        }
    };

    Ok(Some(SecretTemplate {
        metadata: SecretTemplateMetadata { name, annotations },
    }))
}

/// Whether a name is a DNS-1123 label.
fn is_dns_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && value.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && value.ends_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
}

/// The deterministic Secret name of a credential that does not name one.
///
/// The name is derived from the credential's own name and a slice of its
/// UID, so two credentials that share a name still get different Secrets and
/// one credential keeps the same Secret across restarts.
pub fn default_secret_name(credential_name: &str, uid: &str) -> String {
    let suffix: String = uid
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(8)
        .collect();
    let suffix = if suffix.is_empty() {
        "credential".to_string()
    } else {
        suffix
    };

    let keep = 63usize.saturating_sub(suffix.len() + 1);
    let mut base: String = credential_name.chars().take(keep).collect();
    while base.ends_with('-') {
        base.pop();
    }
    if base.is_empty() {
        base = "mail-credential".to_string();
    }
    format!("{base}-{suffix}")
}

/// One MailCredential resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailCredential {
    name: String,
    namespace: String,
    uid: String,
    generation: u64,
    spec: MailCredentialSpec,
}

impl MailCredential {
    /// Describe one credential resource.
    pub fn new(
        name: impl Into<String>,
        namespace: impl Into<String>,
        uid: impl Into<String>,
        generation: u64,
        spec: MailCredentialSpec,
    ) -> Self {
        Self {
            name: name.into(),
            namespace: namespace.into(),
            uid: uid.into(),
            generation,
            spec,
        }
    }

    /// The name of the credential.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The namespace the credential lives in.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// The UID of the credential.
    ///
    /// The UID is what owns the published Secret, so it is what a publisher
    /// checks before it replaces one.
    pub fn uid(&self) -> &str {
        &self.uid
    }

    /// The generation of the credential.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// The validated specification of the credential.
    pub fn spec(&self) -> &MailCredentialSpec {
        &self.spec
    }
}
