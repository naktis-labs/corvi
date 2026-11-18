//! The hardened workload profile of ADR-0011 and the workload model of
//! ADR-0012.
//!
//! The operator renders a gateway workload and validates it against the
//! mandatory security profile. The profile is **not** configurable through
//! the `CorviGateway` resource: the CRD exposes product intent, never a
//! PodSpec, so a user cannot ask for a privileged container, a writable root
//! filesystem, an added capability, a host namespace or a mounted Kubernetes
//! API token.
//!
//! Two boundaries are deliberately outside this crate:
//!
//! * the admission policy that checks generated Pods, and
//! * the network policy that denies traffic by default.
//!
//! Both must be installed by an independently trusted control. The operator
//! *expects* them, reports their absence, and never creates an unrestricted
//! substitute: its own validation is not a security boundary.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::model::{
    AuthorizationMode, CorviGateway, ResourceRequirements, StateBackend, StateSpec,
};

/// The unprivileged UID and GID every Corvi container runs as.
pub const NON_ROOT_UID: i64 = 65532;

/// The kind of workload the operator reconciles a gateway into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkloadKind {
    /// A Deployment, for stateless gateways.
    Deployment,
    /// A StatefulSet, for single-writer SQLite gateways.
    StatefulSet,
}

impl WorkloadKind {
    /// The Kubernetes kind.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deployment => "Deployment",
            Self::StatefulSet => "StatefulSet",
        }
    }
}

/// Where a security policy came from.
///
/// Only a policy installed by an independent control is a boundary. A policy
/// the operator generated from its own configuration is not: it would be
/// written by the same component whose output it is supposed to constrain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum PolicySource {
    /// Installed by an independent, privileged control.
    #[serde(rename = "independentlyInstalled")]
    IndependentlyInstalled,
    /// Derived from the operator's own configuration.
    ///
    /// This is the default because an unknown origin is never trusted.
    #[serde(rename = "operatorDerived")]
    #[default]
    OperatorDerived,
}

/// Which kind of policy an expectation names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyKind {
    /// A validating admission policy for generated workloads.
    #[serde(rename = "admission")]
    Admission,
    /// A NetworkPolicy.
    #[serde(rename = "network")]
    Network,
}

/// A policy the operator expects to find, installed by someone else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyExpectation {
    /// The name of the expected policy.
    pub name: String,
    /// Which kind of policy is expected.
    pub kind: PolicyKind,
    /// Where the policy must come from.
    #[serde(default)]
    pub source: PolicySource,
}

/// The operator-approved profile used to render workloads.
///
/// The image, the service accounts and the ports are chosen here, at
/// operator or chart level. A `CorviGateway` instance cannot point at an
/// arbitrary image or borrow another component's service account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorProfile {
    /// The digest-pinned gateway image.
    pub gateway_image: String,
    /// The operator's own service account.
    pub operator_service_account: String,
    /// The gateway's service account, which carries no API token.
    pub gateway_service_account: String,
    /// The unprivileged HTTP port.
    pub http_port: u16,
    /// The unprivileged SMTP submission port.
    pub smtp_submission_port: u16,
    /// The admission policy the operator expects.
    pub admission_policy: PolicyExpectation,
    /// The network policy the operator expects.
    pub network_policy: PolicyExpectation,
}

/// Why a workload could not be rendered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenderError {
    /// A SQLite gateway was asked for more than one writer.
    SqliteReplicaLimit {
        /// The requested replica count.
        replicas: u32,
    },
    /// An embedded issuer was asked for without durable state.
    EphemeralEmbeddedIssuer,
    /// The image is not pinned to an immutable digest.
    UnpinnedImage {
        /// The image that was rejected.
        image: String,
    },
    /// The gateway would run with the operator's service account.
    ServiceAccountIsolation {
        /// The service account that may not be shared.
        service_account: String,
    },
    /// A listener was asked for a privileged port.
    PrivilegedPort {
        /// The port that was rejected.
        port: u16,
    },
    /// The state configuration is inconsistent.
    InvalidState {
        /// Why the state configuration is rejected.
        reason: String,
    },
}

impl fmt::Display for RenderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SqliteReplicaLimit { replicas } => write!(
                f,
                "a SQLite gateway has a single writer and may not run {replicas} replicas"
            ),
            Self::EphemeralEmbeddedIssuer => {
                f.write_str("an embedded OAuth issuer requires durable state")
            }
            Self::UnpinnedImage { image } => {
                write!(f, "image {image} is not pinned to an immutable digest")
            }
            Self::ServiceAccountIsolation { service_account } => write!(
                f,
                "the gateway may not use the operator's service account {service_account}"
            ),
            Self::PrivilegedPort { port } => {
                write!(f, "port {port} is privileged and may not be published")
            }
            Self::InvalidState { reason } => write!(f, "invalid state configuration: {reason}"),
        }
    }
}

impl std::error::Error for RenderError {}

/// Why a rendered workload is not acceptable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkloadViolation {
    /// A container runs as root.
    RootUser {
        /// The offending container.
        container: String,
    },
    /// A container is privileged.
    PrivilegedContainer {
        /// The offending container.
        container: String,
    },
    /// A container may escalate privileges.
    PrivilegeEscalation {
        /// The offending container.
        container: String,
    },
    /// A container has a writable root filesystem.
    MutableRootFilesystem {
        /// The offending container.
        container: String,
    },
    /// A container does not drop every capability.
    MissingCapabilityDrop {
        /// The offending container.
        container: String,
    },
    /// A container adds a capability.
    AddedCapability {
        /// The offending container.
        container: String,
        /// The capability that was added.
        capability: String,
    },
    /// A container has no effective runtime-default seccomp profile.
    MissingSeccomp {
        /// The offending container.
        container: String,
    },
    /// The pod mounts the default service account token.
    ServiceAccountTokenMounted,
    /// The pod publishes service links.
    ServiceLinksEnabled,
    /// The pod shares a host namespace.
    HostNamespaceShared {
        /// The namespace that was shared.
        namespace: String,
    },
    /// The pod uses the operator's service account.
    OperatorServiceAccountReused {
        /// The service account that may not be shared.
        service_account: String,
    },
    /// The container image is not digest-pinned.
    UnpinnedImage {
        /// The image that was rejected.
        image: String,
    },
    /// The workload publishes a privileged port.
    PrivilegedPort {
        /// The port that was rejected.
        port: u16,
    },
    /// A volume mounts a host path.
    HostPathVolume {
        /// The offending volume.
        volume: String,
    },
    /// The admission policy is not independently installed.
    AdmissionPolicyNotIndependent {
        /// The expected policy.
        name: String,
    },
    /// The network policy is not independently installed.
    NetworkPolicyNotIndependent {
        /// The expected policy.
        name: String,
    },
    /// A policy is expected to come from an independent control.
    PolicyNotIndependentlyTrusted {
        /// The expected policy.
        name: String,
    },
    /// The network policy allows unrestricted egress.
    UnrestrictedEgress {
        /// The offending CIDR.
        cidr: String,
    },
    /// The network policy addresses only one address family.
    MissingAddressFamily {
        /// The family that is missing.
        family: IpFamily,
    },
    /// The network policy does not deny by default.
    IncompletePolicyTypes {
        /// The policy that is not default-deny.
        name: String,
    },
}

impl fmt::Display for WorkloadViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RootUser { container } => write!(f, "container {container} runs as root"),
            Self::PrivilegedContainer { container } => {
                write!(f, "container {container} is privileged")
            }
            Self::PrivilegeEscalation { container } => {
                write!(f, "container {container} may escalate privileges")
            }
            Self::MutableRootFilesystem { container } => {
                write!(f, "container {container} has a writable root filesystem")
            }
            Self::MissingCapabilityDrop { container } => {
                write!(f, "container {container} does not drop every capability")
            }
            Self::AddedCapability {
                container,
                capability,
            } => write!(f, "container {container} adds capability {capability}"),
            Self::MissingSeccomp { container } => {
                write!(
                    f,
                    "container {container} has no runtime-default seccomp profile"
                )
            }
            Self::ServiceAccountTokenMounted => {
                f.write_str("the pod mounts the default service account token")
            }
            Self::ServiceLinksEnabled => f.write_str("the pod publishes service links"),
            Self::HostNamespaceShared { namespace } => {
                write!(f, "the pod shares the {namespace} namespace")
            }
            Self::OperatorServiceAccountReused { service_account } => write!(
                f,
                "the gateway uses the operator's service account {service_account}"
            ),
            Self::UnpinnedImage { image } => {
                write!(f, "image {image} is not pinned to an immutable digest")
            }
            Self::PrivilegedPort { port } => {
                write!(f, "port {port} is privileged and may not be published")
            }
            Self::HostPathVolume { volume } => write!(f, "volume {volume} mounts a host path"),
            Self::AdmissionPolicyNotIndependent { name } => {
                write!(f, "admission policy {name} is not independently installed")
            }
            Self::NetworkPolicyNotIndependent { name } => {
                write!(f, "network policy {name} is not independently installed")
            }
            Self::PolicyNotIndependentlyTrusted { name } => {
                write!(f, "policy {name} is not independently trusted")
            }
            Self::UnrestrictedEgress { cidr } => {
                write!(f, "egress to {cidr} is unrestricted")
            }
            Self::MissingAddressFamily { family } => {
                write!(f, "the network policy does not address {family}")
            }
            Self::IncompletePolicyTypes { name } => {
                write!(f, "network policy {name} does not deny by default")
            }
        }
    }
}

impl std::error::Error for WorkloadViolation {}

/// An IP address family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum IpFamily {
    /// IPv4.
    #[serde(rename = "IPv4")]
    V4,
    /// IPv6.
    #[serde(rename = "IPv6")]
    V6,
}

impl fmt::Display for IpFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4 => f.write_str("IPv4"),
            Self::V6 => f.write_str("IPv6"),
        }
    }
}

/// The address family of a CIDR block.
pub fn ip_family(cidr: &str) -> Option<IpFamily> {
    let address = cidr.split('/').next()?;
    if address.contains(':') {
        Some(IpFamily::V6)
    } else if address.contains('.') {
        Some(IpFamily::V4)
    } else {
        None
    }
}

/// A label selector.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LabelSelector {
    /// The labels the selector matches.
    #[serde(default)]
    pub match_labels: BTreeMap<String, String>,
}

/// An owner reference the operator sets on its own objects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnerReference {
    /// The owner's API version.
    pub api_version: String,
    /// The owner's kind.
    pub kind: String,
    /// The owner's name.
    pub name: String,
    /// The owner's UID.
    pub uid: String,
    /// Whether this owner manages the object.
    pub controller: bool,
    /// Whether the owner's deletion waits for this object.
    pub block_owner_deletion: bool,
}

/// The metadata of a rendered object.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadMetadata {
    /// The object name.
    pub name: String,
    /// The object namespace.
    pub namespace: String,
    /// The object labels.
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    /// The object annotations.
    #[serde(default)]
    pub annotations: BTreeMap<String, String>,
    /// The owner references the operator set.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owner_references: Vec<OwnerReference>,
}

/// A seccomp profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SeccompProfile {
    /// The profile type.
    pub kind: String,
}

impl SeccompProfile {
    /// The runtime-default profile.
    pub fn runtime_default() -> Self {
        Self {
            kind: "RuntimeDefault".to_owned(),
        }
    }
}

/// The pod-level security context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PodSecurityContext {
    /// Whether the pod must run as a non-root user.
    pub run_as_non_root: bool,
    /// The numeric user.
    pub run_as_user: i64,
    /// The numeric group.
    pub run_as_group: i64,
    /// The seccomp profile.
    pub seccomp_profile: SeccompProfile,
}

/// The Linux capabilities of a container.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Capabilities {
    /// The capabilities that are dropped.
    #[serde(default)]
    pub drop: Vec<String>,
    /// The capabilities that are added.
    #[serde(default)]
    pub add: Vec<String>,
}

/// The container-level security context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContainerSecurityContext {
    /// Whether privilege escalation is allowed.
    pub allow_privilege_escalation: bool,
    /// Whether the container is privileged.
    pub privileged: bool,
    /// Whether the root filesystem is read-only.
    pub read_only_root_filesystem: bool,
    /// Whether the container must run as a non-root user.
    pub run_as_non_root: bool,
    /// The numeric user.
    pub run_as_user: i64,
    /// The numeric group.
    pub run_as_group: i64,
    /// The Linux capabilities.
    pub capabilities: Capabilities,
    /// The seccomp profile.
    pub seccomp_profile: SeccompProfile,
    /// The proc mount.
    pub proc_mount: String,
}

/// A container port.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContainerPort {
    /// The port name.
    pub name: String,
    /// The port number.
    pub container_port: u16,
    /// The protocol.
    pub protocol: String,
}

/// A volume mount.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VolumeMount {
    /// The mounted volume.
    pub name: String,
    /// The mount path.
    pub mount_path: String,
    /// Whether the mount is read-only.
    pub read_only: bool,
}

/// The source of a volume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum VolumeSource {
    /// A bounded scratch directory.
    EmptyDir {
        /// The backing medium.
        medium: String,
        /// The size limit.
        size_limit: String,
    },
    /// An operator-owned configuration object.
    ConfigMap {
        /// The ConfigMap name.
        name: String,
    },
    /// A pre-created claim, which the operator references but never owns.
    PersistentVolumeClaim {
        /// The claim name.
        claim_name: String,
        /// Whether the claim is read-only.
        read_only: bool,
    },
    /// A pre-created Secret, mounted read-only.
    Secret {
        /// The Secret name.
        secret_name: String,
        /// The file mode.
        default_mode: u32,
    },
}

/// A pod volume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Volume {
    /// The volume name.
    pub name: String,
    /// The volume source.
    pub source: VolumeSource,
}

/// A container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Container {
    /// The container name.
    pub name: String,
    /// The container image.
    pub image: String,
    /// The image pull policy.
    pub image_pull_policy: String,
    /// The entrypoint.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub command: Vec<String>,
    /// The arguments.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    /// The published ports.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<ContainerPort>,
    /// The container security context.
    pub security_context: ContainerSecurityContext,
    /// The requested and limited resources.
    pub resources: ResourceRequirements,
    /// The volume mounts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub volume_mounts: Vec<VolumeMount>,
}

/// The pod specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PodSpec {
    /// The service account the pod runs as.
    pub service_account_name: String,
    /// Whether the default service account token is mounted.
    pub automount_service_account_token: bool,
    /// Whether service links are published.
    pub enable_service_links: bool,
    /// Whether the pod uses the host network.
    pub host_network: bool,
    /// Whether the pod shares the host PID namespace.
    pub host_pid: bool,
    /// Whether the pod shares the host IPC namespace.
    pub host_ipc: bool,
    /// The pod security context.
    pub security_context: PodSecurityContext,
    /// The init containers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub init_containers: Vec<Container>,
    /// The containers.
    pub containers: Vec<Container>,
    /// The volumes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub volumes: Vec<Volume>,
}

/// The pod template.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PodTemplate {
    /// The template metadata.
    pub metadata: WorkloadMetadata,
    /// The pod specification.
    pub spec: PodSpec,
}

/// A rollout strategy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateStrategy {
    /// The strategy type.
    pub kind: String,
}

/// The spec of a Deployment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentSpec {
    /// The replica count.
    pub replicas: u32,
    /// The label selector.
    pub selector: LabelSelector,
    /// The rollout strategy.
    pub strategy: UpdateStrategy,
    /// The pod template.
    pub template: PodTemplate,
}

/// A gateway Deployment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Deployment {
    /// The API version.
    pub api_version: String,
    /// The kind.
    pub kind: String,
    /// The object metadata.
    pub metadata: WorkloadMetadata,
    /// The workload spec.
    pub spec: DeploymentSpec,
}

/// The spec of a StatefulSet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatefulSetSpec {
    /// The replica count.
    pub replicas: u32,
    /// The label selector.
    pub selector: LabelSelector,
    /// The name of the governing Service.
    pub service_name: String,
    /// The rollout strategy.
    pub update_strategy: UpdateStrategy,
    /// The pod template.
    pub template: PodTemplate,
}

/// A gateway StatefulSet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatefulSet {
    /// The API version.
    pub api_version: String,
    /// The kind.
    pub kind: String,
    /// The object metadata.
    pub metadata: WorkloadMetadata,
    /// The workload spec.
    pub spec: StatefulSetSpec,
}

/// A rendered gateway workload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Workload {
    /// A Deployment.
    Deployment(Deployment),
    /// A StatefulSet.
    StatefulSet(StatefulSet),
}

impl Workload {
    /// The Kubernetes kind.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Deployment(_) => "Deployment",
            Self::StatefulSet(_) => "StatefulSet",
        }
    }

    /// The object name.
    pub fn name(&self) -> &str {
        match self {
            Self::Deployment(deployment) => &deployment.metadata.name,
            Self::StatefulSet(stateful_set) => &stateful_set.metadata.name,
        }
    }

    /// The object namespace.
    pub fn namespace(&self) -> &str {
        match self {
            Self::Deployment(deployment) => &deployment.metadata.namespace,
            Self::StatefulSet(stateful_set) => &stateful_set.metadata.namespace,
        }
    }

    /// The pod specification.
    pub fn pod_spec(&self) -> &PodSpec {
        match self {
            Self::Deployment(deployment) => &deployment.spec.template.spec,
            Self::StatefulSet(stateful_set) => &stateful_set.spec.template.spec,
        }
    }

    /// The pod specification, mutably.
    pub fn pod_spec_mut(&mut self) -> &mut PodSpec {
        match self {
            Self::Deployment(deployment) => &mut deployment.spec.template.spec,
            Self::StatefulSet(stateful_set) => &mut stateful_set.spec.template.spec,
        }
    }

    /// Render the workload as YAML.
    pub fn to_yaml(&self) -> String {
        match self {
            Self::Deployment(deployment) => {
                serde_yaml::to_string(deployment).expect("a workload always serialises")
            }
            Self::StatefulSet(stateful_set) => {
                serde_yaml::to_string(stateful_set).expect("a workload always serialises")
            }
        }
    }
}

/// The metadata of an observed policy.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyMetadata {
    /// The policy name.
    pub name: String,
    /// The policy namespace.
    pub namespace: String,
    /// The policy annotations.
    #[serde(default)]
    pub annotations: BTreeMap<String, String>,
}

/// An observed admission policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdmissionPolicy {
    /// The policy name.
    pub name: String,
    /// Where the policy came from.
    #[serde(default)]
    pub source: PolicySource,
}

/// A CIDR block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpBlock {
    /// The CIDR.
    pub cidr: String,
    /// The excluded addresses.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub except: Vec<String>,
}

/// A network policy peer.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkPolicyPeer {
    /// The address block.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_block: Option<IpBlock>,
    /// The pod selector.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pod_selector: Option<LabelSelector>,
    /// The namespace selector.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace_selector: Option<LabelSelector>,
}

/// A network policy port.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkPolicyPort {
    /// The protocol.
    pub protocol: String,
    /// The port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

/// An ingress rule.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkPolicyIngressRule {
    /// The allowed sources.
    #[serde(default)]
    pub from: Vec<NetworkPolicyPeer>,
    /// The allowed ports.
    #[serde(default)]
    pub ports: Vec<NetworkPolicyPort>,
}

/// An egress rule.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkPolicyEgressRule {
    /// The allowed destinations.
    #[serde(default)]
    pub to: Vec<NetworkPolicyPeer>,
    /// The allowed ports.
    #[serde(default)]
    pub ports: Vec<NetworkPolicyPort>,
}

/// The spec of a NetworkPolicy.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkPolicySpec {
    /// The pods the policy selects.
    pub pod_selector: LabelSelector,
    /// The policy types.
    #[serde(default)]
    pub policy_types: Vec<PolicyType>,
    /// The ingress rules.
    #[serde(default)]
    pub ingress: Vec<NetworkPolicyIngressRule>,
    /// The egress rules.
    #[serde(default)]
    pub egress: Vec<NetworkPolicyEgressRule>,
}

/// The traffic a policy covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyType {
    /// Ingress traffic.
    #[serde(rename = "Ingress")]
    Ingress,
    /// Egress traffic.
    #[serde(rename = "Egress")]
    Egress,
}

/// An observed NetworkPolicy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkPolicy {
    /// The API version.
    pub api_version: String,
    /// The kind.
    pub kind: String,
    /// Where the policy came from.
    pub source: PolicySource,
    /// The policy metadata.
    pub metadata: PolicyMetadata,
    /// The policy spec.
    pub spec: NetworkPolicySpec,
}

impl<'de> Deserialize<'de> for NetworkPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Raw {
            api_version: String,
            kind: String,
            metadata: PolicyMetadata,
            spec: NetworkPolicySpec,
        }
        let raw = Raw::deserialize(deserializer)?;
        Ok(Self {
            source: policy_source(&raw.metadata),
            api_version: raw.api_version,
            kind: raw.kind,
            metadata: raw.metadata,
            spec: raw.spec,
        })
    }
}

/// Where an observed object's policy came from.
///
/// The operator stamps everything it creates with
/// `app.kubernetes.io/managed-by: corvi-operator`, so an object carrying that
/// marker is the operator's own work and is never an independent boundary.
/// An unknown manager is also refused: an unattributed policy is not evidence
/// of an independent control.
fn policy_source(metadata: &PolicyMetadata) -> PolicySource {
    match metadata
        .annotations
        .get("app.kubernetes.io/managed-by")
        .map(String::as_str)
    {
        Some("gitops") | Some("helm") => PolicySource::IndependentlyInstalled,
        _ => PolicySource::OperatorDerived,
    }
}

/// The security policies the operator found.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ObservedPolicies {
    /// The observed admission policy, if any.
    pub admission: Option<AdmissionPolicy>,
    /// The observed network policies.
    pub network: Vec<NetworkPolicy>,
}

/// Render the hardened workload of one gateway.
pub fn render_gateway_workload(
    gateway: &CorviGateway,
    profile: &OperatorProfile,
) -> Result<Workload, RenderError> {
    validate_state(&gateway.spec.state)?;
    if gateway.spec.state.backend == StateBackend::Sqlite && gateway.spec.replicas > 1 {
        return Err(RenderError::SqliteReplicaLimit {
            replicas: gateway.spec.replicas,
        });
    }
    if gateway.spec.authorization.mode == AuthorizationMode::Embedded
        && gateway.spec.state.backend == StateBackend::Ephemeral
    {
        return Err(RenderError::EphemeralEmbeddedIssuer);
    }
    if !is_digest_pinned(&profile.gateway_image) {
        return Err(RenderError::UnpinnedImage {
            image: profile.gateway_image.clone(),
        });
    }
    if profile.gateway_service_account == profile.operator_service_account {
        return Err(RenderError::ServiceAccountIsolation {
            service_account: profile.gateway_service_account.clone(),
        });
    }
    if profile.http_port < 1024 || profile.smtp_submission_port < 1024 {
        return Err(RenderError::PrivilegedPort {
            port: profile.http_port.min(profile.smtp_submission_port),
        });
    }

    let name = format!("corvi-gateway-{}", gateway.metadata.name);
    let mut labels = BTreeMap::new();
    labels.insert(
        "app.kubernetes.io/name".to_owned(),
        "corvi-gateway".to_owned(),
    );
    labels.insert(
        "app.kubernetes.io/instance".to_owned(),
        gateway.metadata.name.clone(),
    );
    labels.insert(
        "app.kubernetes.io/managed-by".to_owned(),
        "corvi-operator".to_owned(),
    );
    labels.insert(
        "app.kubernetes.io/component".to_owned(),
        "gateway".to_owned(),
    );
    labels.insert(
        "corvi.naktis.eu/gateway".to_owned(),
        gateway.metadata.name.clone(),
    );

    let mut owner_references = Vec::new();
    if let Some(uid) = &gateway.metadata.uid {
        owner_references.push(OwnerReference {
            api_version: crate::model::API_GROUP_VERSION.to_owned(),
            kind: crate::model::ResourceKind::CorviGateway.as_str().to_owned(),
            name: gateway.metadata.name.clone(),
            uid: uid.clone(),
            controller: true,
            block_owner_deletion: true,
        });
    }

    let mut volumes = vec![
        Volume {
            name: "config".to_owned(),
            source: VolumeSource::ConfigMap {
                name: format!("{name}-config"),
            },
        },
        Volume {
            name: "tmp".to_owned(),
            source: VolumeSource::EmptyDir {
                medium: "Memory".to_owned(),
                size_limit: "32Mi".to_owned(),
            },
        },
    ];
    if let Some(claim) = &gateway.spec.state.existing_claim_name {
        volumes.push(Volume {
            name: "state".to_owned(),
            source: VolumeSource::PersistentVolumeClaim {
                claim_name: claim.clone(),
                read_only: false,
            },
        });
    }

    let mut ports = vec![ContainerPort {
        name: "http".to_owned(),
        container_port: profile.http_port,
        protocol: "TCP".to_owned(),
    }];
    if gateway.spec.listeners.smtp_submission.enabled {
        ports.push(ContainerPort {
            name: "smtp-submission".to_owned(),
            container_port: profile.smtp_submission_port,
            protocol: "TCP".to_owned(),
        });
    }

    let container = Container {
        name: "gateway".to_owned(),
        image: profile.gateway_image.clone(),
        image_pull_policy: "IfNotPresent".to_owned(),
        command: Vec::new(),
        args: Vec::new(),
        ports,
        security_context: hardened_container_security_context(),
        resources: gateway.spec.resources.clone(),
        volume_mounts: vec![
            VolumeMount {
                name: "config".to_owned(),
                mount_path: "/etc/corvi".to_owned(),
                read_only: true,
            },
            VolumeMount {
                name: "tmp".to_owned(),
                mount_path: "/tmp".to_owned(),
                read_only: false,
            },
        ],
    };

    let pod = PodSpec {
        service_account_name: profile.gateway_service_account.clone(),
        automount_service_account_token: false,
        enable_service_links: false,
        host_network: false,
        host_pid: false,
        host_ipc: false,
        security_context: hardened_pod_security_context(),
        init_containers: Vec::new(),
        containers: vec![container],
        volumes,
    };

    let template = PodTemplate {
        metadata: WorkloadMetadata {
            name: String::new(),
            namespace: gateway.metadata.namespace.clone(),
            labels: labels.clone(),
            annotations: BTreeMap::new(),
            owner_references: Vec::new(),
        },
        spec: pod,
    };

    let metadata = WorkloadMetadata {
        name: name.clone(),
        namespace: gateway.metadata.namespace.clone(),
        labels,
        annotations: BTreeMap::new(),
        owner_references,
    };

    let selector = LabelSelector {
        match_labels: [(
            "app.kubernetes.io/name".to_owned(),
            "corvi-gateway".to_owned(),
        )]
        .into_iter()
        .collect(),
    };

    let kind = match gateway.spec.state.backend {
        StateBackend::Sqlite => WorkloadKind::StatefulSet,
        _ => WorkloadKind::Deployment,
    };

    Ok(match kind {
        WorkloadKind::Deployment => Workload::Deployment(Deployment {
            api_version: "apps/v1".to_owned(),
            kind: "Deployment".to_owned(),
            metadata,
            spec: DeploymentSpec {
                replicas: gateway.spec.replicas,
                selector,
                strategy: UpdateStrategy {
                    kind: "RollingUpdate".to_owned(),
                },
                template,
            },
        }),
        WorkloadKind::StatefulSet => Workload::StatefulSet(StatefulSet {
            api_version: "apps/v1".to_owned(),
            kind: "StatefulSet".to_owned(),
            metadata,
            spec: StatefulSetSpec {
                replicas: gateway.spec.replicas,
                selector,
                service_name: name,
                update_strategy: UpdateStrategy {
                    kind: "RollingUpdate".to_owned(),
                },
                template,
            },
        }),
    })
}

/// Check a rendered workload against the mandatory security profile.
pub fn validate_workload(
    workload: &Workload,
    profile: &OperatorProfile,
) -> Result<(), WorkloadViolation> {
    validate_pod_spec(workload.pod_spec(), profile)
}

/// Check a pod specification against the mandatory security profile.
pub fn validate_pod_spec(
    pod: &PodSpec,
    profile: &OperatorProfile,
) -> Result<(), WorkloadViolation> {
    if !pod.security_context.run_as_non_root
        || pod.security_context.run_as_user == 0
        || pod.security_context.run_as_group == 0
    {
        return Err(WorkloadViolation::RootUser {
            container: "pod".to_owned(),
        });
    }
    if pod.security_context.seccomp_profile.kind != "RuntimeDefault" {
        return Err(WorkloadViolation::MissingSeccomp {
            container: "pod".to_owned(),
        });
    }
    if pod.automount_service_account_token {
        return Err(WorkloadViolation::ServiceAccountTokenMounted);
    }
    if pod.enable_service_links {
        return Err(WorkloadViolation::ServiceLinksEnabled);
    }
    if pod.host_network {
        return Err(WorkloadViolation::HostNamespaceShared {
            namespace: "network".to_owned(),
        });
    }
    if pod.host_pid {
        return Err(WorkloadViolation::HostNamespaceShared {
            namespace: "PID".to_owned(),
        });
    }
    if pod.host_ipc {
        return Err(WorkloadViolation::HostNamespaceShared {
            namespace: "IPC".to_owned(),
        });
    }
    if pod.service_account_name == profile.operator_service_account {
        return Err(WorkloadViolation::OperatorServiceAccountReused {
            service_account: pod.service_account_name.clone(),
        });
    }
    for volume in &pod.volumes {
        if let VolumeSource::PersistentVolumeClaim { claim_name, .. } = &volume.source {
            if claim_name.is_empty() {
                return Err(WorkloadViolation::HostPathVolume {
                    volume: volume.name.clone(),
                });
            }
        }
    }
    for container in pod.init_containers.iter().chain(pod.containers.iter()) {
        validate_container(container)?;
    }
    Ok(())
}

/// Check one container against the mandatory security profile.
fn validate_container(container: &Container) -> Result<(), WorkloadViolation> {
    let name = container.name.clone();
    if container.security_context.privileged {
        return Err(WorkloadViolation::PrivilegedContainer { container: name });
    }
    if container.security_context.allow_privilege_escalation {
        return Err(WorkloadViolation::PrivilegeEscalation { container: name });
    }
    if !container.security_context.read_only_root_filesystem {
        return Err(WorkloadViolation::MutableRootFilesystem { container: name });
    }
    if !container.security_context.run_as_non_root
        || container.security_context.run_as_user == 0
        || container.security_context.run_as_group == 0
    {
        return Err(WorkloadViolation::RootUser { container: name });
    }
    if !container
        .security_context
        .capabilities
        .drop
        .iter()
        .any(|capability| capability == "ALL")
    {
        return Err(WorkloadViolation::MissingCapabilityDrop { container: name });
    }
    if let Some(capability) = container.security_context.capabilities.add.first() {
        return Err(WorkloadViolation::AddedCapability {
            container: name,
            capability: capability.clone(),
        });
    }
    if container.security_context.seccomp_profile.kind != "RuntimeDefault" {
        return Err(WorkloadViolation::MissingSeccomp { container: name });
    }
    if !is_digest_pinned(&container.image) {
        return Err(WorkloadViolation::UnpinnedImage {
            image: container.image.clone(),
        });
    }
    for port in &container.ports {
        if port.container_port < 1024 {
            return Err(WorkloadViolation::PrivilegedPort {
                port: port.container_port,
            });
        }
    }
    Ok(())
}

/// The mandatory pod-level security context.
fn hardened_pod_security_context() -> PodSecurityContext {
    PodSecurityContext {
        run_as_non_root: true,
        run_as_user: NON_ROOT_UID,
        run_as_group: NON_ROOT_UID,
        seccomp_profile: SeccompProfile::runtime_default(),
    }
}

/// The mandatory container-level security context.
fn hardened_container_security_context() -> ContainerSecurityContext {
    ContainerSecurityContext {
        allow_privilege_escalation: false,
        privileged: false,
        read_only_root_filesystem: true,
        run_as_non_root: true,
        run_as_user: NON_ROOT_UID,
        run_as_group: NON_ROOT_UID,
        capabilities: Capabilities {
            drop: vec!["ALL".to_owned()],
            add: Vec::new(),
        },
        seccomp_profile: SeccompProfile::runtime_default(),
        proc_mount: "Default".to_owned(),
    }
}

/// Check the state configuration of a gateway.
fn validate_state(state: &StateSpec) -> Result<(), RenderError> {
    match state.backend {
        StateBackend::Sqlite => {
            if state.existing_claim_name.is_none() {
                return Err(RenderError::InvalidState {
                    reason: "a SQLite gateway needs an existing claim".to_owned(),
                });
            }
            if state.connection_secret_ref.is_some() {
                return Err(RenderError::InvalidState {
                    reason: "a SQLite gateway may not use a connection Secret".to_owned(),
                });
            }
        }
        StateBackend::Postgres => {
            if state.connection_secret_ref.is_none() {
                return Err(RenderError::InvalidState {
                    reason: "a PostgreSQL gateway needs a connection Secret".to_owned(),
                });
            }
            if state.existing_claim_name.is_some() {
                return Err(RenderError::InvalidState {
                    reason: "a PostgreSQL gateway may not use an existing claim".to_owned(),
                });
            }
        }
        StateBackend::Ephemeral => {
            if state.existing_claim_name.is_some() || state.connection_secret_ref.is_some() {
                return Err(RenderError::InvalidState {
                    reason: "an ephemeral gateway has no durable state".to_owned(),
                });
            }
        }
    }
    Ok(())
}

/// Whether an image is pinned to an immutable digest.
fn is_digest_pinned(image: &str) -> bool {
    let Some((_, digest)) = image.split_once('@') else {
        return false;
    };
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit())
}

/// Check that an expected policy is installed by an independent control.
pub fn check_policy_trust(
    expected: &PolicyExpectation,
    observed: &ObservedPolicies,
) -> Result<(), WorkloadViolation> {
    if expected.source != PolicySource::IndependentlyInstalled {
        return Err(WorkloadViolation::PolicyNotIndependentlyTrusted {
            name: expected.name.clone(),
        });
    }
    match expected.kind {
        PolicyKind::Admission => {
            let found = observed
                .admission
                .as_ref()
                .filter(|policy| policy.name == expected.name);
            match found {
                Some(policy) if policy.source == PolicySource::IndependentlyInstalled => Ok(()),
                _ => Err(WorkloadViolation::AdmissionPolicyNotIndependent {
                    name: expected.name.clone(),
                }),
            }
        }
        PolicyKind::Network => {
            let found = observed
                .network
                .iter()
                .find(|policy| policy.metadata.name == expected.name);
            match found {
                Some(policy) if policy.source == PolicySource::IndependentlyInstalled => Ok(()),
                _ => Err(WorkloadViolation::NetworkPolicyNotIndependent {
                    name: expected.name.clone(),
                }),
            }
        }
    }
}

/// Check that a NetworkPolicy denies by default and addresses both address
/// families.
pub fn validate_network_policy(policy: &NetworkPolicy) -> Result<(), WorkloadViolation> {
    if !policy.spec.policy_types.contains(&PolicyType::Ingress)
        || !policy.spec.policy_types.contains(&PolicyType::Egress)
    {
        return Err(WorkloadViolation::IncompletePolicyTypes {
            name: policy.metadata.name.clone(),
        });
    }
    for rule in &policy.spec.egress {
        for peer in &rule.to {
            let Some(block) = &peer.ip_block else {
                continue;
            };
            if block.cidr == "0.0.0.0/0" || block.cidr == "::/0" {
                return Err(WorkloadViolation::UnrestrictedEgress {
                    cidr: block.cidr.clone(),
                });
            }
        }
    }
    let families: std::collections::BTreeSet<IpFamily> = policy
        .spec
        .egress
        .iter()
        .flat_map(|rule| rule.to.iter())
        .filter_map(|peer| peer.ip_block.as_ref())
        .filter_map(|block| ip_family(&block.cidr))
        .collect();
    for family in [IpFamily::V4, IpFamily::V6] {
        if !families.contains(&family) {
            return Err(WorkloadViolation::MissingAddressFamily { family });
        }
    }
    Ok(())
}
