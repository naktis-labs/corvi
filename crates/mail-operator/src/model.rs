//! The CRD-shaped resource model the operator reads.
//!
//! Four namespaced kinds make up the mail-resource graph of ADR-0013:
//! `CorviGateway`, `MailProvider`, `Mailbox` and `MailIdentity`. Their
//! directional reference contract is written down in
//! `api/mail-resource-ownership.schema.json`; this module is the typed Rust
//! view of that contract plus the handful of extra fields the operator needs
//! to render a hardened workload.
//!
//! The model is deliberately **closed**. Every spec denies unknown fields and
//! every manifest is scanned for PodSpec-shaped keys, so a `CorviGateway`
//! cannot smuggle a container, a volume, a `securityContext` or an
//! `ownerReferences` list past the operator. The security profile is applied
//! by the operator, never requested by the user (ADR-0011, ADR-0012).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize, de::DeserializeOwned};

use mail_core::IsolationMode;

/// The API group every Corvi resource belongs to.
pub const API_GROUP: &str = "corvi.naktis.eu";

/// The API version this operator understands.
pub const API_VERSION: &str = "v1alpha1";

/// The `group/version` string of every Corvi resource.
pub const API_GROUP_VERSION: &str = "corvi.naktis.eu/v1alpha1";

/// The kinds of Corvi resource the operator reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ResourceKind {
    /// A Corvi gateway runtime instance.
    #[serde(rename = "CorviGateway")]
    CorviGateway,
    /// An upstream provider integration.
    #[serde(rename = "MailProvider")]
    MailProvider,
    /// One physical upstream mailbox.
    #[serde(rename = "Mailbox")]
    Mailbox,
    /// A sender persona over a mailbox.
    #[serde(rename = "MailIdentity")]
    MailIdentity,
}

impl ResourceKind {
    /// The Kubernetes `kind` string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CorviGateway => "CorviGateway",
            Self::MailProvider => "MailProvider",
            Self::Mailbox => "Mailbox",
            Self::MailIdentity => "MailIdentity",
        }
    }

    /// The Kubernetes resource plural.
    pub fn plural(self) -> &'static str {
        match self {
            Self::CorviGateway => "corvigateways",
            Self::MailProvider => "mailproviders",
            Self::Mailbox => "mailboxes",
            Self::MailIdentity => "mailidentities",
        }
    }
}

impl fmt::Display for ResourceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The metadata the operator reads from a Corvi resource.
///
/// Kubernetes defines many more metadata fields. They are accepted and
/// ignored rather than rejected, because a real API server always sends them,
/// but `ownerReferences` is rejected outright: the operator sets its own
/// owner references and must never copy user-supplied ones onto a managed
/// object (ADR-0012).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectMeta {
    /// The object name.
    pub name: String,
    /// The namespace the object lives in.
    pub namespace: String,
    /// The stable object UID, used to key published snapshots.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    /// The observed generation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<i64>,
    /// Object labels.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    /// Object annotations.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

impl ObjectMeta {
    /// Build metadata for a resource in `namespace`.
    pub fn new(namespace: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            namespace: namespace.into(),
            uid: None,
            generation: None,
            labels: BTreeMap::new(),
            annotations: BTreeMap::new(),
        }
    }

    /// Attach a UID.
    pub fn with_uid(mut self, uid: impl Into<String>) -> Self {
        self.uid = Some(uid.into());
        self
    }

    /// Attach a generation.
    pub fn with_generation(mut self, generation: i64) -> Self {
        self.generation = Some(generation);
        self
    }
}

/// A same-namespace reference to another Corvi resource.
///
/// The reference is *logical*, not a Kubernetes `ownerReference`: nothing is
/// garbage collected through it (ADR-0013).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalRef {
    /// The referenced object name.
    pub name: String,
    /// The referenced namespace.
    ///
    /// A reference is same-namespace by contract. The field exists only so a
    /// cross-namespace attempt is reported as one, instead of as an unknown
    /// field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

impl LocalRef {
    /// Reference `name` in the owner's own namespace.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            namespace: None,
        }
    }
}

/// What a `MailProvider` is for.
///
/// ADR-0013 calls an **unbound** provider (one without `spec.gatewayRef`)
/// management-only: it is administered normally but none of its mailboxes are
/// served by a gateway. That is a *binding* state, not a role, and it is
/// modelled by the absence of `spec.gatewayRef`.
///
/// This enum models the different thing the brief calls a management-only
/// provider: an integration that administers other provider accounts and
/// serves no mailbox of its own. Such a provider may not own a mailbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ProviderRole {
    /// The provider owns mailboxes and may be bound to a gateway.
    #[serde(rename = "serving")]
    #[default]
    Serving,
    /// The provider only administers other providers and owns no mailbox.
    #[serde(rename = "managementOnly")]
    ManagementOnly,
}

/// The spec of a `MailProvider`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MailProviderSpec {
    /// The optional, singular gateway this provider is bound to.
    ///
    /// Omission means "unbound": the provider is administered, and none of
    /// its mailboxes are served by any gateway. There is no default gateway,
    /// so an omitted reference is never resolved to some implicit one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_ref: Option<LocalRef>,
    /// Whether provider administration is paused.
    #[serde(default)]
    pub suspended: bool,
    /// What the provider is for.
    #[serde(default)]
    pub role: ProviderRole,
}

/// An upstream provider integration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailProvider {
    /// Object metadata.
    pub metadata: ObjectMeta,
    /// The provider spec.
    pub spec: MailProviderSpec,
}

/// The spec of a `Mailbox`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MailboxSpec {
    /// The required parent provider.
    ///
    /// A mailbox always belongs to exactly one provider, so this reference is
    /// required and is never resolved to a fallback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_ref: Option<LocalRef>,
}

/// One physical upstream mailbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mailbox {
    /// Object metadata.
    pub metadata: ObjectMeta,
    /// The mailbox spec.
    pub spec: MailboxSpec,
}

/// The spec of a `MailIdentity`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MailIdentitySpec {
    /// The required parent mailbox.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mailbox_ref: Option<LocalRef>,
    /// The address the identity sends from.
    ///
    /// The reference contract of ADR-0013 does not fix the address fields;
    /// they are required here only because an identity without an address
    /// cannot be published into a configuration snapshot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// The isolation the identity can claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub isolation: Option<IsolationMode>,
}

/// A sender persona over a mailbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailIdentity {
    /// Object metadata.
    pub metadata: ObjectMeta,
    /// The identity spec.
    pub spec: MailIdentitySpec,
}

/// A listener the gateway publishes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Listener {
    /// Whether the listener is published.
    pub enabled: bool,
}

/// The listeners a gateway publishes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Listeners {
    /// The HTTP listener, serving REST and MCP.
    pub http: Listener,
    /// The SMTP AUTH submission listener.
    pub smtp_submission: Listener,
}

/// How the gateway authorizes requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthorizationMode {
    /// An external resource server authorizes requests.
    #[serde(rename = "external")]
    External,
    /// The gateway runs an embedded issuer.
    #[serde(rename = "embedded")]
    Embedded,
}

/// The gateway's authorization configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Authorization {
    /// The authorization mode.
    pub mode: AuthorizationMode,
    /// The approved resource-server configuration Secret.
    pub config_secret_ref: LocalRef,
}

/// Where a gateway keeps its state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StateBackend {
    /// No durable state.
    #[serde(rename = "ephemeral")]
    Ephemeral,
    /// A single-writer SQLite volume.
    #[serde(rename = "sqlite")]
    Sqlite,
    /// An external PostgreSQL server.
    #[serde(rename = "postgres")]
    Postgres,
}

/// The gateway's state configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StateSpec {
    /// The state backend.
    pub backend: StateBackend,
    /// The pre-created claim holding SQLite state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub existing_claim_name: Option<String>,
    /// The Secret holding the PostgreSQL connection descriptor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_secret_ref: Option<LocalRef>,
}

/// A container resource list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceList {
    /// The CPU request or limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu: Option<String>,
    /// The memory request or limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<String>,
    /// The ephemeral-storage request or limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(rename = "ephemeral-storage")]
    pub ephemeral_storage: Option<String>,
}

/// The resources a gateway requests and limits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceRequirements {
    /// The requested resources.
    pub requests: ResourceList,
    /// The limited resources.
    pub limits: ResourceList,
}

/// A `CorviGateway` instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorviGateway {
    /// Object metadata.
    pub metadata: ObjectMeta,
    /// The gateway spec.
    pub spec: GatewaySpec,
}

/// The spec of a `CorviGateway`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GatewaySpec {
    /// How many replicas the gateway runs.
    #[serde(default = "default_replicas")]
    pub replicas: u32,
    /// Whether mail serving is paused.
    #[serde(default)]
    pub suspended: bool,
    /// The published listeners.
    pub listeners: Listeners,
    /// The authorization configuration.
    pub authorization: Authorization,
    /// The state configuration.
    pub state: StateSpec,
    /// The resource requests and limits.
    pub resources: ResourceRequirements,
}

/// The default replica count.
fn default_replicas() -> u32 {
    1
}

/// Why a manifest could not be read as a Corvi resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The document is not valid YAML, or does not match the typed shape.
    Yaml(String),
    /// The document declares another API version.
    UnsupportedApiVersion {
        /// The version found in the document.
        found: String,
    },
    /// The document declares another kind.
    UnexpectedKind {
        /// The kind this parser expects.
        expected: ResourceKind,
        /// The kind found in the document.
        found: String,
    },
    /// The document carries a PodSpec-shaped field.
    ///
    /// The security profile of a Corvi workload is chosen by the operator, not
    /// by the document, so a PodSpec fragment in a Corvi resource is refused
    /// instead of being ignored.
    PodSpecInjection {
        /// The path of the offending field.
        path: String,
    },
    /// The document carries user-supplied owner references.
    OwnerReferenceInjection,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Yaml(message) => write!(f, "invalid resource document: {message}"),
            Self::UnsupportedApiVersion { found } => {
                write!(
                    f,
                    "unsupported apiVersion {found}, expected {API_GROUP_VERSION}"
                )
            }
            Self::UnexpectedKind { expected, found } => {
                write!(f, "unexpected kind {found}, expected {expected}")
            }
            Self::PodSpecInjection { path } => write!(
                f,
                "spec.{path} is a PodSpec field and may not be set on a Corvi resource"
            ),
            Self::OwnerReferenceInjection => {
                f.write_str("metadata.ownerReferences may not be set on a Corvi resource")
            }
        }
    }
}

impl std::error::Error for ParseError {}

/// PodSpec-shaped field names that may not appear in a Corvi resource.
///
/// `resources` is deliberately absent: a gateway requests and limits CPU and
/// memory through `spec.resources`, which is a resource *request*, not a
/// container definition.
const POD_SPEC_FIELDS: &[&str] = &[
    "affinity",
    "automountServiceAccountToken",
    "args",
    "command",
    "containers",
    "dnsConfig",
    "dnsPolicy",
    "enableServiceLinks",
    "env",
    "envFrom",
    "ephemeralContainers",
    "ephemeralVolumeSources",
    "hostAliases",
    "hostIPC",
    "hostNetwork",
    "hostPID",
    "hostPath",
    "hostPort",
    "hostUsers",
    "image",
    "imagePullPolicy",
    "initContainers",
    "lifecycle",
    "nodeSelector",
    "overhead",
    "podTemplate",
    "priorityClassName",
    "procMount",
    "readinessGates",
    "runtimeClassName",
    "schedulerName",
    "seccompProfile",
    "securityContext",
    "serviceAccount",
    "serviceAccountName",
    "setHostnameAsFQDN",
    "shareProcessNamespace",
    "sidecars",
    "subdomain",
    "sysctls",
    "template",
    "terminationGracePeriodSeconds",
    "tolerations",
    "topologySpreadConstraints",
    "volumeMounts",
    "volumes",
];

/// Parse a `CorviGateway` manifest.
pub fn parse_gateway(input: &str) -> Result<CorviGateway, ParseError> {
    parse_resource(input, ResourceKind::CorviGateway)
}

/// Parse a `MailProvider` manifest.
pub fn parse_provider(input: &str) -> Result<MailProvider, ParseError> {
    parse_resource(input, ResourceKind::MailProvider)
}

/// Parse a `Mailbox` manifest.
pub fn parse_mailbox(input: &str) -> Result<Mailbox, ParseError> {
    parse_resource(input, ResourceKind::Mailbox)
}

/// Parse a `MailIdentity` manifest.
pub fn parse_identity(input: &str) -> Result<MailIdentity, ParseError> {
    parse_resource(input, ResourceKind::MailIdentity)
}

/// Parse one Corvi manifest into its typed shape.
fn parse_resource<T: DeserializeOwned>(input: &str, kind: ResourceKind) -> Result<T, ParseError> {
    let document: serde_yaml::Value =
        serde_yaml::from_str(input).map_err(|error| ParseError::Yaml(error.to_string()))?;
    check_api_version(&document)?;
    check_kind(&document, kind)?;
    check_no_owner_references(&document)?;
    check_no_pod_spec(&document)?;
    serde_yaml::from_value(document).map_err(|error| ParseError::Yaml(error.to_string()))
}

/// Check the declared API version.
fn check_api_version(document: &serde_yaml::Value) -> Result<(), ParseError> {
    let found = document
        .get("apiVersion")
        .and_then(serde_yaml::Value::as_str)
        .unwrap_or_default();
    if found != API_GROUP_VERSION {
        return Err(ParseError::UnsupportedApiVersion {
            found: found.to_owned(),
        });
    }
    Ok(())
}

/// Check the declared kind.
fn check_kind(document: &serde_yaml::Value, kind: ResourceKind) -> Result<(), ParseError> {
    let found = document
        .get("kind")
        .and_then(serde_yaml::Value::as_str)
        .unwrap_or_default();
    if found != kind.as_str() {
        return Err(ParseError::UnexpectedKind {
            expected: kind,
            found: found.to_owned(),
        });
    }
    Ok(())
}

/// Refuse user-supplied owner references.
fn check_no_owner_references(document: &serde_yaml::Value) -> Result<(), ParseError> {
    let present = document
        .get("metadata")
        .and_then(|metadata| metadata.get("ownerReferences"))
        .is_some();
    if present {
        return Err(ParseError::OwnerReferenceInjection);
    }
    Ok(())
}

/// Refuse PodSpec-shaped fields anywhere below `spec`.
fn check_no_pod_spec(document: &serde_yaml::Value) -> Result<(), ParseError> {
    let Some(spec) = document.get("spec") else {
        return Ok(());
    };
    let mut path = Vec::new();
    find_pod_spec_field(spec, &mut path)
}

/// Search a value tree for a forbidden field name.
fn find_pod_spec_field(
    value: &serde_yaml::Value,
    path: &mut Vec<String>,
) -> Result<(), ParseError> {
    match value {
        serde_yaml::Value::Mapping(mapping) => {
            for (key, child) in mapping {
                let Some(name) = key.as_str() else {
                    continue;
                };
                if POD_SPEC_FIELDS.contains(&name) {
                    let mut full = path.clone();
                    full.push(name.to_owned());
                    return Err(ParseError::PodSpecInjection {
                        path: full.join("."),
                    });
                }
                path.push(name.to_owned());
                let found = find_pod_spec_field(child, path);
                path.pop();
                found?;
            }
            Ok(())
        }
        serde_yaml::Value::Sequence(sequence) => {
            for child in sequence {
                find_pod_spec_field(child, path)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}
