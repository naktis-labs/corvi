//! The typed bridge dependency descriptor.
//!
//! ADR-0006 section 3 describes a bridge dependency as a typed descriptor that
//! a provider plugin may request. The descriptor is *untrusted external data*:
//! it says what a bridge would need, never what it is allowed to do.
//!
//! The JSON shape follows the provisional schema in
//! `api/provider-transport-bridge.schema.json`. The `security` block inside
//! the runtime is an addition of this implementation: it records what the
//! descriptor *asks* for, so that a request for root or for privileged
//! capabilities can be rejected instead of silently downgrading the profile.

use std::collections::BTreeMap;
use std::fmt;

use serde::de::Error as _;
use serde::{Deserialize, Serialize};

/// The API version of the descriptor.
pub const DESCRIPTOR_API_VERSION: &str = "corvi.naktis.eu/v1alpha1";

/// The kind of the descriptor.
pub const DESCRIPTOR_KIND: &str = "ProviderTransportDependency";

/// The transport topology of a bridge backed mailbox.
pub const LOCAL_BRIDGE_TOPOLOGY: &str = "localBridge";

/// The annotation that names the metadata version of a provider plugin.
pub const PROVIDER_METADATA_VERSION_ANNOTATION: &str = "eu.naktis.corvi.provider.metadata-version";

/// The annotation that names the transport topology of a provider plugin.
pub const PROVIDER_TRANSPORT_TOPOLOGY_ANNOTATION: &str =
    "eu.naktis.corvi.provider.transport-topology";

/// The annotation that names the bridge mode of a provider plugin.
pub const PROVIDER_BRIDGE_MODE_ANNOTATION: &str = "eu.naktis.corvi.provider.bridge-mode";

/// The annotation that names the discovery protocol of a provider plugin.
pub const PROVIDER_DISCOVERY_PROTOCOL_ANNOTATION: &str =
    "eu.naktis.corvi.provider.discovery-protocol";

/// The annotation that hints at a bridge image.
///
/// A hint is discovery data. It never authorizes an image.
pub const PROVIDER_BRIDGE_IMAGE_ANNOTATION: &str = "eu.naktis.corvi.provider.bridge-image";

/// How a bridge is operated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum BridgeMode {
    /// A bridge that is installed and operated independently.
    Existing,
    /// A bridge that Corvi provisions from an approved digest.
    Managed,
}

/// The protocols a bridge serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum BridgeProtocol {
    /// IMAP.
    Imap,
    /// SMTP.
    Smtp,
}

/// Where a managed bridge runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Placement {
    /// In the network namespace of the gateway that connects to it.
    ColocatedNetworkNamespace,
    /// At a separately trusted endpoint.
    ExternalTrustedEndpoint,
}

/// How many accounts one bridge instance serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AccountScope {
    /// One account per instance.
    PerPhysicalMailbox,
    /// Several accounts in one instance.
    SharedMultiAccount,
}

/// How the endpoint of a bridge is reachable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EndpointExposure {
    /// Only on the loopback interface of its consumer.
    LoopbackOnly,
    /// On an authenticated network.
    AuthenticatedNetwork,
}

/// How a bridge reports that it is usable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ReadinessCheck {
    /// A protocol handshake against the bridge.
    ProtocolHandshake,
    /// A health probe.
    HealthProbe,
    /// A manual confirmation.
    Manual,
}

/// The class of a secret the bridge needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SecretClass {
    /// The upstream account session state.
    BridgeSession,
    /// The upstream account credentials.
    BridgeAccount,
    /// The credentials the bridge serves IMAP with.
    #[serde(rename = "bridgeIMAP")]
    BridgeImap,
    /// The credentials the bridge serves SMTP with.
    #[serde(rename = "bridgeSMTP")]
    BridgeSmtp,
    /// A certificate.
    Certificate,
    /// Keyring material.
    Keyring,
}

/// How the peer certificate of a bridge is verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TlsPeerVerification {
    /// A pinned certificate or a trusted local CA.
    #[serde(rename = "pinnedCertificateOrTrustedCA")]
    PinnedCertificateOrTrustedCa,
    /// A trusted CA.
    #[serde(rename = "trustedCA")]
    TrustedCa,
    /// A pinned certificate.
    #[serde(rename = "pinnedCertificate")]
    PinnedCertificate,
}

/// How the upstream account is enrolled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum OnboardingMethod {
    /// Interactive or preprovisioned enrollment.
    InteractiveOrPreprovisioned,
    /// Interactive enrollment only.
    InteractiveOnly,
    /// Preprovisioned enrollment only.
    Preprovisioned,
}

/// Whether the bridge can be enrolled automatically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AutomationSupport {
    /// The descriptor does not say.
    #[default]
    Unknown,
    /// Automatic enrollment is supported.
    Supported,
    /// Automatic enrollment is not supported.
    Unsupported,
}

/// Deserialize the automation support, which is a boolean or the word
/// `unknown`.
fn deserialize_automation_support<'de, D>(deserializer: D) -> Result<AutomationSupport, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Raw {
        Flag(bool),
        Text(String),
    }

    match Raw::deserialize(deserializer)? {
        Raw::Flag(true) => Ok(AutomationSupport::Supported),
        Raw::Flag(false) => Ok(AutomationSupport::Unsupported),
        Raw::Text(text) if text == "unknown" => Ok(AutomationSupport::Unknown),
        Raw::Text(text) => Err(D::Error::custom(format!(
            "unknown automation support {text}"
        ))),
    }
}

/// A hint about the port a bridge serves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortHint {
    /// The host the bridge is expected on.
    pub host: String,
    /// The port, when it is known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// The name of the port reference, when the port is resolved later.
    #[serde(rename = "portRef", default, skip_serializing_if = "Option::is_none")]
    pub port_ref: Option<String>,
}

/// The security a bridge runtime asks for.
///
/// A descriptor may only ask for a profile that is at least as strict as the
/// mandatory rootless profile. Every field here is a *request*; the enforced
/// profile is decided locally. Unknown keys are refused: a typoed request is
/// a change of meaning, not an empty default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecurityRequirements {
    /// Whether the runtime insists on running as root.
    #[serde(default)]
    pub requires_root: bool,
    /// Whether the runtime insists on running privileged.
    #[serde(default)]
    pub privileged: bool,
    /// The Linux capabilities the runtime insists on.
    #[serde(default)]
    pub required_capabilities: Vec<String>,
    /// Whether the runtime insists on a writable root filesystem.
    #[serde(default = "default_read_only_root_filesystem")]
    pub read_only_root_filesystem: bool,
    /// The seccomp profile the runtime insists on.
    #[serde(default)]
    pub seccomp_profile: Option<String>,
    /// The paths the runtime insists on writing to.
    #[serde(default)]
    pub writable_paths: Vec<String>,
}

fn default_read_only_root_filesystem() -> bool {
    true
}

impl Default for SecurityRequirements {
    fn default() -> Self {
        Self {
            requires_root: false,
            privileged: false,
            required_capabilities: Vec::new(),
            read_only_root_filesystem: true,
            seccomp_profile: None,
            writable_paths: Vec::new(),
        }
    }
}

/// A secret the bridge asks for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretInput {
    /// The name of the secret binding.
    pub name: String,
    /// The class of the secret.
    pub class: SecretClass,
}

/// A digest pinned OCI image reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageReference {
    repository: String,
    digest: String,
}

impl ImageReference {
    /// Parse a digest pinned image reference.
    ///
    /// A mutable tag is refused: production references are digest pinned.
    pub fn parse(reference: &str) -> Result<Self, DescriptorError> {
        let (repository, digest) = reference
            .split_once('@')
            .ok_or(DescriptorError::ImageNotDigestPinned)?;
        if repository.is_empty() {
            return Err(DescriptorError::InvalidImageReference(
                reference.to_string(),
            ));
        }
        let hex = digest
            .strip_prefix("sha256:")
            .ok_or(DescriptorError::ImageNotDigestPinned)?;
        if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(DescriptorError::InvalidImageReference(
                reference.to_string(),
            ));
        }
        Ok(Self {
            repository: repository.to_string(),
            digest: digest.to_string(),
        })
    }

    /// The repository of the reference.
    pub fn repository(&self) -> &str {
        &self.repository
    }

    /// The digest of the reference.
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

/// The runtime a bridge descriptor asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeDescriptor {
    /// How the bridge is operated.
    pub mode: BridgeMode,
    /// The image the descriptor asks for, as written.
    pub image: Option<String>,
    /// Where the bridge runs.
    pub placement: Placement,
    /// Whether the bridge keeps state across restarts.
    pub persistent_state: bool,
    /// How many accounts one instance serves.
    pub account_scope: AccountScope,
    /// How the endpoint is reachable.
    pub exposure: EndpointExposure,
    /// The IMAP endpoint hint.
    pub imap: Option<PortHint>,
    /// The SMTP endpoint hint.
    pub smtp: Option<PortHint>,
    /// How the bridge reports readiness.
    pub readiness: ReadinessCheck,
    /// The security the runtime asks for.
    pub security: SecurityRequirements,
}

/// How the upstream account is enrolled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnboardingDescriptor {
    /// The enrollment method.
    pub method: OnboardingMethod,
    /// Whether enrollment can be automated.
    pub automation_support: AutomationSupport,
}

/// How the peer certificate of the bridge is verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsDescriptor {
    /// The peer verification mode.
    pub peer_verification: TlsPeerVerification,
}

/// A typed bridge dependency descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeDescriptor {
    /// The API version of the descriptor.
    pub api_version: String,
    /// The kind of the descriptor.
    pub kind: String,
    /// The transport topology.
    pub topology: String,
    /// The protocols the bridge serves.
    pub protocols: Vec<BridgeProtocol>,
    /// The runtime the bridge needs.
    pub runtime: RuntimeDescriptor,
    /// How the upstream account is enrolled.
    pub onboarding: OnboardingDescriptor,
    /// The secrets the bridge asks for.
    pub secret_inputs: Vec<SecretInput>,
    /// How the peer certificate is verified.
    pub tls: TlsDescriptor,
}

/// Why a descriptor was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DescriptorError {
    /// The descriptor is not readable.
    Parse(String),
    /// The API version is not supported.
    UnsupportedApiVersion(String),
    /// The kind is not supported.
    UnsupportedKind(String),
    /// The transport topology is not supported.
    UnsupportedTopology(String),
    /// The image reference is not digest pinned.
    ImageNotDigestPinned,
    /// The image reference is malformed.
    InvalidImageReference(String),
    /// A field is missing.
    MissingField(String),
}

impl fmt::Display for DescriptorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DescriptorError::Parse(reason) => {
                write!(formatter, "the descriptor does not parse: {reason}")
            }
            DescriptorError::UnsupportedApiVersion(version) => {
                write!(formatter, "unsupported descriptor version {version}")
            }
            DescriptorError::UnsupportedKind(kind) => {
                write!(formatter, "unsupported descriptor kind {kind}")
            }
            DescriptorError::UnsupportedTopology(topology) => {
                write!(formatter, "unsupported transport topology {topology}")
            }
            DescriptorError::ImageNotDigestPinned => {
                write!(formatter, "the image reference is not digest pinned")
            }
            DescriptorError::InvalidImageReference(reference) => {
                write!(formatter, "the image reference {reference} is malformed")
            }
            DescriptorError::MissingField(field) => {
                write!(formatter, "the descriptor is missing {field}")
            }
        }
    }
}

impl std::error::Error for DescriptorError {}

/// The raw shape of a descriptor document.
#[derive(Debug, Deserialize)]
struct RawDescriptor {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kind: String,
    transport: RawTransport,
}

/// The raw transport block.
#[derive(Debug, Deserialize)]
struct RawTransport {
    topology: String,
    protocols: Vec<BridgeProtocol>,
    runtime: RawRuntime,
    onboarding: RawOnboarding,
    #[serde(rename = "secretInputs", default)]
    secret_inputs: Vec<SecretInput>,
    tls: RawTls,
}

/// The raw runtime block.
#[derive(Debug, Deserialize)]
struct RawRuntime {
    mode: BridgeMode,
    #[serde(default)]
    image: Option<String>,
    placement: Placement,
    state: RawState,
    endpoint: RawEndpoint,
    readiness: RawReadiness,
    #[serde(default)]
    security: Option<SecurityRequirements>,
}

/// The raw state block.
#[derive(Debug, Deserialize)]
struct RawState {
    #[serde(default)]
    persistent: bool,
    #[serde(rename = "accountScope")]
    account_scope: AccountScope,
}

/// The raw endpoint block.
#[derive(Debug, Deserialize)]
struct RawEndpoint {
    exposure: EndpointExposure,
    #[serde(default)]
    imap: Option<PortHint>,
    #[serde(default)]
    smtp: Option<PortHint>,
}

/// The raw readiness block.
#[derive(Debug, Deserialize)]
struct RawReadiness {
    #[serde(rename = "type")]
    readiness: ReadinessCheck,
}

/// The raw onboarding block.
#[derive(Debug, Deserialize)]
struct RawOnboarding {
    method: OnboardingMethod,
    #[serde(
        rename = "automationSupported",
        default,
        deserialize_with = "deserialize_automation_support"
    )]
    automation_support: AutomationSupport,
}

/// The raw TLS block.
#[derive(Debug, Deserialize)]
struct RawTls {
    #[serde(rename = "peerVerification")]
    peer_verification: TlsPeerVerification,
}

impl BridgeDescriptor {
    /// Read a descriptor from its JSON document.
    pub fn from_json(value: &serde_json::Value) -> Result<Self, DescriptorError> {
        let raw: RawDescriptor = serde_json::from_value(value.clone())
            .map_err(|error| DescriptorError::Parse(error.to_string()))?;

        if raw.api_version != DESCRIPTOR_API_VERSION {
            return Err(DescriptorError::UnsupportedApiVersion(raw.api_version));
        }
        if raw.kind != DESCRIPTOR_KIND {
            return Err(DescriptorError::UnsupportedKind(raw.kind));
        }
        if raw.transport.topology != LOCAL_BRIDGE_TOPOLOGY {
            return Err(DescriptorError::UnsupportedTopology(raw.transport.topology));
        }
        if raw.transport.protocols.is_empty() {
            return Err(DescriptorError::MissingField("protocols".to_string()));
        }

        Ok(BridgeDescriptor {
            api_version: raw.api_version,
            kind: raw.kind,
            topology: raw.transport.topology,
            protocols: raw.transport.protocols,
            runtime: RuntimeDescriptor {
                mode: raw.transport.runtime.mode,
                image: raw.transport.runtime.image,
                placement: raw.transport.runtime.placement,
                persistent_state: raw.transport.runtime.state.persistent,
                account_scope: raw.transport.runtime.state.account_scope,
                exposure: raw.transport.runtime.endpoint.exposure,
                imap: raw.transport.runtime.endpoint.imap,
                smtp: raw.transport.runtime.endpoint.smtp,
                readiness: raw.transport.runtime.readiness.readiness,
                security: raw.transport.runtime.security.unwrap_or_default(),
            },
            onboarding: OnboardingDescriptor {
                method: raw.transport.onboarding.method,
                automation_support: raw.transport.onboarding.automation_support,
            },
            secret_inputs: raw.transport.secret_inputs,
            tls: TlsDescriptor {
                peer_verification: raw.transport.tls.peer_verification,
            },
        })
    }
}

/// The OCI annotations of a provider plugin that hint at a bridge.
///
/// These are discovery data. They say *that* a plugin needs an ancillary
/// bridge; they never say which image may run, which runtime is acceptable or
/// which secrets may be bound.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OciBridgeHint {
    /// The metadata version of the plugin.
    pub metadata_version: Option<String>,
    /// The transport topology the plugin advertises.
    pub transport_topology: Option<String>,
    /// The bridge mode the plugin advertises.
    pub bridge_mode: Option<String>,
    /// The discovery protocol the plugin speaks.
    pub discovery_protocol: Option<String>,
    /// An image the plugin suggests.
    pub suggested_image: Option<String>,
}

impl OciBridgeHint {
    /// Read the hint from the annotations of a provider plugin manifest.
    pub fn from_annotations(annotations: &BTreeMap<String, String>) -> Self {
        Self {
            metadata_version: annotations
                .get(PROVIDER_METADATA_VERSION_ANNOTATION)
                .cloned(),
            transport_topology: annotations
                .get(PROVIDER_TRANSPORT_TOPOLOGY_ANNOTATION)
                .cloned(),
            bridge_mode: annotations.get(PROVIDER_BRIDGE_MODE_ANNOTATION).cloned(),
            discovery_protocol: annotations
                .get(PROVIDER_DISCOVERY_PROTOCOL_ANNOTATION)
                .cloned(),
            suggested_image: annotations.get(PROVIDER_BRIDGE_IMAGE_ANNOTATION).cloned(),
        }
    }

    /// Whether the hint says that the plugin needs a bridge.
    pub fn requests_a_bridge(&self) -> bool {
        self.bridge_mode.as_deref() == Some("required")
            || self.transport_topology.as_deref() == Some("local-bridge")
    }
}
