//! Cross-resource admission for MailCredential resources.
//!
//! ADR-0014 section 2 makes admission a **cross-resource** decision: the
//! webhook has to resolve the target chain, the provider and the gateway
//! before it can say whether the credential is admissible. It also makes
//! admission **fail closed**: if a referenced resource or its capability
//! status cannot be read reliably, the request is refused rather than
//! admitted on a guess.
//!
//! Two properties are structural here rather than promised in prose.
//!
//! * **Admission reads and never writes.** The decision is a function of
//!   the credential and the current status of its parents. The reader trait
//!   exposes only reads, and no part of this module can issue a token,
//!   write a Secret or mutate a resource.
//! * **Admission is not an enduring grant.** A parent may change after the
//!   decision. [`crate::revalidate`] re-runs the same resolution against
//!   the current graph, and the publisher refuses to publish a credential
//!   whose authority no longer holds.
//!
//! A dry-run request is evaluated exactly like any other request. There is
//! nothing to skip, because evaluation has no side effect.

use std::fmt;

use crate::model::{
    MailCredential, Permission, ProtocolType, RequestedAuthority, TargetKind, TargetRef,
};
use crate::reasons::Reason;

/// A same-namespace reference to another Corvi resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalRef {
    /// The referenced name.
    pub name: String,
}

impl LocalRef {
    /// Reference a resource by name.
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }

    /// The referenced name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// How a connection reaches TLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    /// The connection starts in plaintext and is upgraded with STARTTLS.
    StartTls,
    /// The connection is TLS from the first byte.
    Implicit,
}

impl TlsMode {
    /// The wire name of the TLS mode.
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::StartTls => "starttls",
            Self::Implicit => "implicit",
        }
    }
}

/// How an SMTP client authenticates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpAuthMechanism {
    /// `PLAIN`.
    Plain,
    /// `LOGIN`.
    Login,
}

impl SmtpAuthMechanism {
    /// The wire name of the mechanism.
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::Plain => "PLAIN",
            Self::Login => "LOGIN",
        }
    }
}

/// The observed, non-secret facts of one SMTP route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmtpRoute {
    /// The observed host.
    pub host: String,
    /// The observed port.
    pub port: u16,
    /// The observed TLS mode.
    pub tls_mode: TlsMode,
    /// The observed server name.
    pub server_name: String,
    /// The observed authentication mechanism.
    pub auth_mechanism: SmtpAuthMechanism,
}

impl SmtpRoute {
    /// The observed host.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The observed port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The observed TLS mode.
    pub fn tls_mode(&self) -> TlsMode {
        self.tls_mode
    }

    /// The observed server name.
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    /// The observed authentication mechanism.
    pub fn auth_mechanism(&self) -> SmtpAuthMechanism {
        self.auth_mechanism
    }
}

/// One endpoint that a controller actually observed.
///
/// An endpoint is only usable when it was observed and verified. A
/// fabricated `.svc` name is not an endpoint, and this type carries no way
/// to express one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedEndpoint {
    /// The protocol the endpoint serves.
    pub protocol: ProtocolType,
    /// The endpoint URL.
    pub url: String,
    /// Whether the endpoint was verified when it was observed.
    pub verified: bool,
}

impl ObservedEndpoint {
    /// Describe an observed endpoint.
    pub fn new(protocol: ProtocolType, url: impl Into<String>, verified: bool) -> Self {
        Self {
            protocol,
            url: url.into(),
            verified,
        }
    }

    /// The protocol the endpoint serves.
    pub fn protocol(&self) -> ProtocolType {
        self.protocol
    }

    /// The endpoint URL.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Whether the endpoint was verified when it was observed.
    pub fn verified(&self) -> bool {
        self.verified
    }
}

/// The authority a credential carries once it is issued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionMode {
    /// The credential is served by a Corvi gateway.
    Gateway,
    /// The credential is issued by the provider itself.
    ProviderDirect,
}

impl ConnectionMode {
    /// The wire name of the connection mode.
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::Gateway => "gateway",
            Self::ProviderDirect => "providerDirect",
        }
    }
}

/// The scope of the authority a credential carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialGranularity {
    /// Corvi-scoped authority over one identity.
    CorviIdentity,
    /// Provider-native authority over one identity.
    ProviderIdentity,
    /// Provider-native authority over a whole physical mailbox.
    ProviderMailbox,
}

impl CredentialGranularity {
    /// The wire name of the granularity.
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::CorviIdentity => "corviIdentity",
            Self::ProviderIdentity => "providerIdentity",
            Self::ProviderMailbox => "providerMailbox",
        }
    }
}

/// What a provider says it can issue.
///
/// Capability status is management data, never authorization by itself: it
/// says which application credentials the provider is able to hand out, not
/// that the caller may have one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderCapabilities {
    /// Whether the provider supports application credentials at all.
    pub supported: bool,
    /// The protocols the provider issues application credentials for.
    pub types: Vec<ProtocolType>,
    /// The granularities the provider isolates.
    pub granularities: Vec<CredentialGranularity>,
    /// Whether the provider can revoke one credential on its own.
    pub revoke_supported: bool,
}

impl ProviderCapabilities {
    /// Describe what a provider can issue.
    pub fn new(
        supported: bool,
        types: Vec<ProtocolType>,
        granularities: Vec<CredentialGranularity>,
        revoke_supported: bool,
    ) -> Self {
        Self {
            supported,
            types,
            granularities,
            revoke_supported,
        }
    }

    /// Whether the provider supports application credentials at all.
    pub fn supported(&self) -> bool {
        self.supported
    }

    /// The protocols the provider issues application credentials for.
    pub fn types(&self) -> &[ProtocolType] {
        &self.types
    }

    /// The granularities the provider isolates.
    pub fn granularities(&self) -> &[CredentialGranularity] {
        &self.granularities
    }

    /// Whether the provider can revoke one credential on its own.
    pub fn revoke_supported(&self) -> bool {
        self.revoke_supported
    }
}

/// The current status of a `MailProvider`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderStatus {
    /// The provider name.
    pub name: String,
    /// The provider namespace.
    pub namespace: String,
    /// The provider UID.
    pub uid: String,
    /// The generation of the provider spec.
    pub generation: u64,
    /// The generation the status was observed for.
    pub observed_generation: u64,
    /// The gateway this provider is attached to, if any.
    pub gateway_ref: Option<LocalRef>,
    /// Whether the provider is suspended.
    pub suspended: bool,
    /// What the provider can issue.
    pub capabilities: ProviderCapabilities,
    /// The generation the capability status was observed for.
    pub capabilities_observed_generation: u64,
    /// The endpoints the provider advertises for direct connections.
    pub direct_endpoints: Vec<ObservedEndpoint>,
    /// The observed SMTP route of the provider.
    pub smtp_route: Option<SmtpRoute>,
}

impl ProviderStatus {
    /// The provider name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The provider namespace.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// The provider UID.
    pub fn uid(&self) -> &str {
        &self.uid
    }

    /// The generation of the provider spec.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// The generation the status was observed for.
    pub fn observed_generation(&self) -> u64 {
        self.observed_generation
    }

    /// The gateway this provider is attached to, if any.
    pub fn gateway_ref(&self) -> Option<&LocalRef> {
        self.gateway_ref.as_ref()
    }

    /// Whether the provider is suspended.
    pub fn suspended(&self) -> bool {
        self.suspended
    }

    /// What the provider can issue.
    pub fn capabilities(&self) -> &ProviderCapabilities {
        &self.capabilities
    }

    /// The generation the capability status was observed for.
    pub fn capabilities_observed_generation(&self) -> u64 {
        self.capabilities_observed_generation
    }

    /// The endpoints the provider advertises for direct connections.
    pub fn direct_endpoints(&self) -> &[ObservedEndpoint] {
        &self.direct_endpoints
    }

    /// The observed SMTP route of the provider.
    pub fn smtp_route(&self) -> Option<&SmtpRoute> {
        self.smtp_route.as_ref()
    }
}

/// The current status of a `Mailbox`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxStatus {
    /// The mailbox name.
    pub name: String,
    /// The mailbox namespace.
    pub namespace: String,
    /// The mailbox UID.
    pub uid: String,
    /// The generation of the mailbox spec.
    pub generation: u64,
    /// The generation the status was observed for.
    pub observed_generation: u64,
    /// The provider this mailbox belongs to.
    pub provider_ref: LocalRef,
    /// Whether the mailbox is suspended.
    pub suspended: bool,
    /// The address of the mailbox, when it is known.
    pub address: Option<String>,
}

impl MailboxStatus {
    /// The mailbox name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The mailbox namespace.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// The mailbox UID.
    pub fn uid(&self) -> &str {
        &self.uid
    }

    /// The generation of the mailbox spec.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// The generation the status was observed for.
    pub fn observed_generation(&self) -> u64 {
        self.observed_generation
    }

    /// The provider this mailbox belongs to.
    pub fn provider_ref(&self) -> &LocalRef {
        &self.provider_ref
    }

    /// Whether the mailbox is suspended.
    pub fn suspended(&self) -> bool {
        self.suspended
    }

    /// The address of the mailbox, when it is known.
    pub fn address(&self) -> Option<&str> {
        self.address.as_deref()
    }
}

/// The current status of a `MailIdentity`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityStatus {
    /// The identity name.
    pub name: String,
    /// The identity namespace.
    pub namespace: String,
    /// The identity UID.
    pub uid: String,
    /// The generation of the identity spec.
    pub generation: u64,
    /// The generation the status was observed for.
    pub observed_generation: u64,
    /// The mailbox this identity belongs to.
    pub mailbox_ref: LocalRef,
    /// Whether the identity address is verified.
    pub verified: bool,
    /// Whether the identity is suspended.
    pub suspended: bool,
    /// The address of the identity, when it is known.
    pub address: Option<String>,
}

impl IdentityStatus {
    /// The identity name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The identity namespace.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// The identity UID.
    pub fn uid(&self) -> &str {
        &self.uid
    }

    /// The generation of the identity spec.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// The generation the status was observed for.
    pub fn observed_generation(&self) -> u64 {
        self.observed_generation
    }

    /// The mailbox this identity belongs to.
    pub fn mailbox_ref(&self) -> &LocalRef {
        &self.mailbox_ref
    }

    /// Whether the identity address is verified.
    pub fn verified(&self) -> bool {
        self.verified
    }

    /// Whether the identity is suspended.
    pub fn suspended(&self) -> bool {
        self.suspended
    }

    /// The address of the identity, when it is known.
    pub fn address(&self) -> Option<&str> {
        self.address.as_deref()
    }
}

/// The current status of a `CorviGateway`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayStatus {
    /// The gateway name.
    pub name: String,
    /// The gateway namespace.
    pub namespace: String,
    /// The gateway UID.
    pub uid: String,
    /// The generation of the gateway spec.
    pub generation: u64,
    /// The generation the status was observed for.
    pub observed_generation: u64,
    /// Whether the gateway is ready to serve.
    pub ready: bool,
    /// Whether the gateway is suspended.
    pub suspended: bool,
    /// The protocols the gateway serves.
    pub supported_types: Vec<ProtocolType>,
    /// The endpoints the gateway actually exposed.
    pub endpoints: Vec<ObservedEndpoint>,
    /// The observed SMTP route of the gateway.
    pub smtp_route: Option<SmtpRoute>,
}

impl GatewayStatus {
    /// The gateway name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The gateway namespace.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// The gateway UID.
    pub fn uid(&self) -> &str {
        &self.uid
    }

    /// The generation of the gateway spec.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// The generation the status was observed for.
    pub fn observed_generation(&self) -> u64 {
        self.observed_generation
    }

    /// Whether the gateway is ready to serve.
    pub fn ready(&self) -> bool {
        self.ready
    }

    /// Whether the gateway is suspended.
    pub fn suspended(&self) -> bool {
        self.suspended
    }

    /// The protocols the gateway serves.
    pub fn supported_types(&self) -> &[ProtocolType] {
        &self.supported_types
    }

    /// The endpoints the gateway actually exposed.
    pub fn endpoints(&self) -> &[ObservedEndpoint] {
        &self.endpoints
    }

    /// The observed SMTP route of the gateway.
    pub fn smtp_route(&self) -> Option<&SmtpRoute> {
        self.smtp_route.as_ref()
    }
}

/// Why a referenced resource could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusReadError {
    /// The resource does not exist.
    NotFound,
    /// The dependency could not be reached.
    Unavailable,
    /// The reader was not allowed to read the resource.
    Forbidden,
}

impl fmt::Display for StatusReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("not found"),
            Self::Unavailable => f.write_str("unavailable"),
            Self::Forbidden => f.write_str("forbidden"),
        }
    }
}

impl std::error::Error for StatusReadError {}

/// Reads the current status of the resources a credential refers to.
///
/// The trait is read-only by construction: it has no method that mutates a
/// resource, creates a Secret or issues a credential. A real implementation
/// reads the Kubernetes API with a read-only ServiceAccount; a test
/// implementation answers from a fixture.
pub trait ParentStatusReader {
    /// Read the current status of a provider.
    fn provider(&self, namespace: &str, name: &str) -> Result<ProviderStatus, StatusReadError>;

    /// Read the current status of a mailbox.
    fn mailbox(&self, namespace: &str, name: &str) -> Result<MailboxStatus, StatusReadError>;

    /// Read the current status of an identity.
    fn identity(&self, namespace: &str, name: &str) -> Result<IdentityStatus, StatusReadError>;

    /// Read the current status of a gateway.
    fn gateway(&self, namespace: &str, name: &str) -> Result<GatewayStatus, StatusReadError>;
}

/// The authority a credential carries, once its graph has been resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionAuthority {
    /// The route the credential is served over.
    pub mode: ConnectionMode,
    /// The protocol the credential speaks.
    pub credential_type: ProtocolType,
    /// The scope of the authority.
    pub granularity: CredentialGranularity,
    /// The provider the credential was issued against.
    pub provider_name: String,
    /// The identity the credential is bound to, if any.
    pub identity_name: Option<String>,
    /// The mailbox the credential is bound to, if any.
    pub mailbox_name: Option<String>,
    /// The Corvi permissions the credential carries.
    ///
    /// A provider-native credential carries none: it is not a Corvi grant.
    pub permissions: Vec<Permission>,
}

impl ConnectionAuthority {
    /// The route the credential is served over.
    pub fn mode(&self) -> ConnectionMode {
        self.mode
    }

    /// The protocol the credential speaks.
    pub fn credential_type(&self) -> ProtocolType {
        self.credential_type
    }

    /// The scope of the authority.
    pub fn granularity(&self) -> CredentialGranularity {
        self.granularity
    }

    /// The provider the credential was issued against.
    pub fn provider_name(&self) -> &str {
        &self.provider_name
    }

    /// The identity the credential is bound to, if any.
    pub fn identity_name(&self) -> Option<&str> {
        self.identity_name.as_deref()
    }

    /// The mailbox the credential is bound to, if any.
    pub fn mailbox_name(&self) -> Option<&str> {
        self.mailbox_name.as_deref()
    }

    /// The Corvi permissions the credential carries.
    pub fn permissions(&self) -> &[Permission] {
        &self.permissions
    }
}

/// A snapshot of the parents a credential was resolved against.
///
/// The snapshot is what makes a later revalidation meaningful: it records
/// which parents, at which generation, carried the authority when the
/// credential was issued.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainSnapshot {
    /// The UID of the provider.
    pub provider_uid: String,
    /// The generation of the provider.
    pub provider_generation: u64,
    /// The UID of the mailbox.
    pub mailbox_uid: String,
    /// The generation of the mailbox.
    pub mailbox_generation: u64,
    /// The UID of the identity, when the credential targets one.
    pub identity_uid: Option<String>,
    /// The generation of the identity, when the credential targets one.
    pub identity_generation: Option<u64>,
    /// The UID of the gateway, when the provider is attached to one.
    pub gateway_uid: Option<String>,
    /// The generation of the gateway, when the provider is attached to one.
    pub gateway_generation: Option<u64>,
}

/// The graph a credential resolves against, with the authority it yields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedGraph {
    /// The authority the credential holds.
    pub authority: ConnectionAuthority,
    /// The parents the authority was derived from.
    pub chain: ChainSnapshot,
}

/// A refusal, with a reason and a message that names no secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denial {
    /// The reason the request was refused.
    pub reason: Reason,
    /// The message that explains the refusal.
    ///
    /// The message names a condition. It never contains a token, a
    /// password, an endpoint that embeds credentials or mailbox content.
    pub message: String,
}

impl Denial {
    /// Refuse a request.
    pub fn new(reason: Reason, message: impl Into<String>) -> Self {
        Self {
            reason,
            message: message.into(),
        }
    }

    /// The reason the request was refused.
    pub fn reason(&self) -> Reason {
        self.reason
    }

    /// The message that explains the refusal.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for Denial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.reason, self.message)
    }
}

impl std::error::Error for Denial {}

/// What admission is being asked about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionOperation {
    /// A credential is being created.
    Create,
    /// A credential is being updated.
    Update,
}

/// One admission request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionRequest {
    credential: MailCredential,
    operation: AdmissionOperation,
    dry_run: bool,
}

impl AdmissionRequest {
    /// Describe an admission request.
    pub fn new(credential: MailCredential, operation: AdmissionOperation, dry_run: bool) -> Self {
        Self {
            credential,
            operation,
            dry_run,
        }
    }

    /// The credential the request is about.
    pub fn credential(&self) -> &MailCredential {
        &self.credential
    }

    /// The operation being admitted.
    pub fn operation(&self) -> AdmissionOperation {
        self.operation
    }

    /// Whether the request is a Kubernetes dry-run.
    pub fn dry_run(&self) -> bool {
        self.dry_run
    }
}

/// The outcome of an admitted request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionOutcome {
    /// The authority the credential would carry.
    pub authority: ConnectionAuthority,
}

/// The decision of an admission request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionDecision {
    /// The credential is admissible.
    Allowed(AdmissionOutcome),
    /// The credential is refused.
    Denied(Denial),
}

impl AdmissionDecision {
    /// Whether the credential was admitted.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed(_))
    }

    /// The authority of an admitted credential.
    pub fn authority(&self) -> Option<&ConnectionAuthority> {
        match self {
            Self::Allowed(outcome) => Some(&outcome.authority),
            Self::Denied(_) => None,
        }
    }

    /// The refusal of a denied credential.
    pub fn denial(&self) -> Option<&Denial> {
        match self {
            Self::Allowed(_) => None,
            Self::Denied(denial) => Some(denial),
        }
    }
}

/// Decide one admission request.
///
/// The decision reads the current status of every referenced resource and
/// returns. It issues nothing, writes nothing and mutates nothing, so a
/// dry-run request is answered exactly like a real one.
pub fn admit(
    request: &AdmissionRequest,
    reader: &dyn ParentStatusReader,
    policy: &crate::policy::SecretPolicy,
) -> AdmissionDecision {
    let graph = match resolve_graph(request.credential(), reader) {
        Ok(graph) => graph,
        Err(denial) => return AdmissionDecision::Denied(denial),
    };

    // A Secret name may be claimed by another producer, and an annotation
    // may hand a credential to a reloader that copies it elsewhere. Both
    // are refused before the credential is admitted.
    if let Some(template) = request.credential().spec().secret_template()
        && let Err(error) = policy.check(template.metadata().annotations())
    {
        return AdmissionDecision::Denied(Denial::new(
            Reason::UnsafeSecretAnnotation,
            error.message().to_string(),
        ));
    }

    AdmissionDecision::Allowed(AdmissionOutcome {
        authority: graph.authority,
    })
}

/// Resolve the authority a credential would carry, or refuse it.
///
/// This is the shared core of admission and continuous revalidation. Both
/// ask the same question — *given the graph as it is right now, does this
/// credential still hold the authority it asks for?* — and both must answer
/// it the same way, or a credential could be admitted by one and revoked by
/// the other for contradictory reasons.
pub fn resolve_authority(
    credential: &MailCredential,
    reader: &dyn ParentStatusReader,
) -> Result<ConnectionAuthority, Denial> {
    resolve_graph(credential, reader).map(|graph| graph.authority)
}

/// Resolve the whole graph a credential refers to, or refuse it.
pub fn resolve_graph(
    credential: &MailCredential,
    reader: &dyn ParentStatusReader,
) -> Result<ResolvedGraph, Denial> {
    let namespace = credential.namespace();
    let spec = credential.spec();
    let target = spec.target_ref();

    let (identity, mailbox) = match target.kind() {
        TargetKind::MailIdentity => {
            let identity = read_identity(reader, namespace, target.name())?;
            check_freshness(
                identity.observed_generation,
                identity.generation,
                "MailIdentity",
                &identity.name,
            )?;
            if identity.suspended {
                return Err(Denial::new(
                    Reason::TargetSuspended,
                    "the target identity is suspended",
                ));
            }
            let mailbox = read_mailbox(reader, namespace, identity.mailbox_ref.name())?;
            check_freshness(
                mailbox.observed_generation,
                mailbox.generation,
                "Mailbox",
                &mailbox.name,
            )?;
            if mailbox.suspended {
                return Err(Denial::new(
                    Reason::TargetSuspended,
                    "the mailbox of the target identity is suspended",
                ));
            }
            (Some(identity), mailbox)
        }
        TargetKind::Mailbox => {
            let mailbox = read_mailbox(reader, namespace, target.name())?;
            check_freshness(
                mailbox.observed_generation,
                mailbox.generation,
                "Mailbox",
                &mailbox.name,
            )?;
            if mailbox.suspended {
                return Err(Denial::new(
                    Reason::TargetSuspended,
                    "the target mailbox is suspended",
                ));
            }
            (None, mailbox)
        }
    };

    let provider = read_provider(reader, namespace, mailbox.provider_ref.name())?;
    check_freshness(
        provider.observed_generation,
        provider.generation,
        "MailProvider",
        &provider.name,
    )?;
    check_freshness(
        provider.capabilities_observed_generation,
        provider.generation,
        "provider capability status",
        &provider.name,
    )?;
    if provider.suspended {
        return Err(Denial::new(
            Reason::TargetSuspended,
            "the provider of the target is suspended",
        ));
    }

    let credential_type = spec.credential_type();
    let requested = spec.requested_authority();

    let (authority, gateway) = match provider.gateway_ref.as_ref() {
        Some(gateway_ref) => {
            // A bound provider serves Corvi-scoped credentials only. An
            // explicit gateway reference is never treated as absent, so a
            // credential cannot escape the gateway by naming a gateway that
            // does not exist.
            //
            // The target kind is checked first: gateway policy is
            // identity-based, so a mailbox target is refused whatever the
            // credential asks for.
            if target.kind() != TargetKind::MailIdentity {
                return Err(Denial::new(
                    Reason::GatewayRequiresMailIdentity,
                    "gateway policy is identity-based, so a mailbox target is refused",
                ));
            }
            if requested == RequestedAuthority::Native {
                return Err(Denial::new(
                    Reason::MissingGatewayPermissions,
                    "a gateway-bound provider requires explicit Corvi permissions",
                ));
            }
            let permissions = spec.permissions().unwrap_or_default();
            if permissions.is_empty() {
                return Err(Denial::new(
                    Reason::MissingGatewayPermissions,
                    "a gateway-bound credential requires a nonempty permission list",
                ));
            }

            let gateway = read_gateway(reader, namespace, &gateway_ref.name)?;
            check_freshness(
                gateway.observed_generation,
                gateway.generation,
                "CorviGateway",
                &gateway.name,
            )?;
            if gateway.suspended || !gateway.ready {
                return Err(Denial::new(
                    Reason::GatewayUnavailable,
                    "the bound gateway is suspended or not ready",
                ));
            }
            if !gateway.supported_types.contains(&credential_type) {
                return Err(Denial::new(
                    Reason::UnsupportedCredentialType,
                    "the bound gateway does not serve this protocol",
                ));
            }

            (
                ConnectionAuthority {
                    mode: ConnectionMode::Gateway,
                    credential_type,
                    granularity: CredentialGranularity::CorviIdentity,
                    provider_name: provider.name.clone(),
                    identity_name: identity.as_ref().map(|identity| identity.name.clone()),
                    mailbox_name: None,
                    permissions: permissions.to_vec(),
                },
                Some(gateway),
            )
        }
        None => {
            // An unbound provider issues native credentials only. Any
            // presence of permissions asks for Corvi-scoped authority, which
            // is exactly what an unbound provider cannot provide.
            if requested == RequestedAuthority::Scoped {
                return Err(Denial::new(
                    Reason::GatewayRequiredForScopedCredential,
                    "a scoped credential requires a gateway-bound provider",
                ));
            }

            let capabilities = &provider.capabilities;
            if !capabilities.supported || !capabilities.revoke_supported {
                return Err(Denial::new(
                    Reason::UnsupportedCredentialIssuance,
                    "the provider cannot issue independently revocable application credentials",
                ));
            }
            if !capabilities.types.contains(&credential_type) {
                return Err(Denial::new(
                    Reason::UnsupportedCredentialType,
                    "the provider does not issue application credentials for this protocol",
                ));
            }

            let granularity = match target.kind() {
                TargetKind::MailIdentity => CredentialGranularity::ProviderIdentity,
                TargetKind::Mailbox => CredentialGranularity::ProviderMailbox,
            };
            if !capabilities.granularities.contains(&granularity) {
                return Err(Denial::new(
                    Reason::UnsupportedCredentialGranularity,
                    "the provider cannot isolate this target for application credentials",
                ));
            }
            if let Some(identity) = &identity
                && !identity.verified
            {
                return Err(Denial::new(
                    Reason::IdentityNotVerified,
                    "the target identity is not verified",
                ));
            }
            let has_endpoint = provider
                .direct_endpoints
                .iter()
                .any(|endpoint| endpoint.protocol == credential_type && endpoint.verified);
            if !has_endpoint {
                return Err(Denial::new(
                    Reason::UnsupportedCredentialType,
                    "the provider advertises no verified endpoint for this protocol",
                ));
            }

            (
                ConnectionAuthority {
                    mode: ConnectionMode::ProviderDirect,
                    credential_type,
                    granularity,
                    provider_name: provider.name.clone(),
                    identity_name: identity.as_ref().map(|identity| identity.name.clone()),
                    mailbox_name: Some(mailbox.name.clone()),
                    permissions: Vec::new(),
                },
                None,
            )
        }
    };

    Ok(ResolvedGraph {
        authority,
        chain: ChainSnapshot {
            provider_uid: provider.uid.clone(),
            provider_generation: provider.generation,
            mailbox_uid: mailbox.uid.clone(),
            mailbox_generation: mailbox.generation,
            identity_uid: identity.as_ref().map(|identity| identity.uid.clone()),
            identity_generation: identity.as_ref().map(|identity| identity.generation),
            gateway_uid: gateway.as_ref().map(|gateway| gateway.uid.clone()),
            gateway_generation: gateway.as_ref().map(|gateway| gateway.generation),
        },
    })
}

/// Read an identity, mapping a read failure onto a refusal.
fn read_identity(
    reader: &dyn ParentStatusReader,
    namespace: &str,
    name: &str,
) -> Result<IdentityStatus, Denial> {
    let identity = reader
        .identity(namespace, name)
        .map_err(|error| match error {
            StatusReadError::NotFound => Denial::new(
                Reason::InvalidTargetRef,
                format!("the target identity {name} does not exist"),
            ),
            StatusReadError::Unavailable => Denial::new(
                Reason::DependencyUnavailable,
                "the identity status could not be read",
            ),
            StatusReadError::Forbidden => Denial::new(
                Reason::DependencyUnavailable,
                "the identity status could not be read",
            ),
        })?;
    check_namespace(&identity.namespace, namespace, "MailIdentity")?;
    Ok(identity)
}

/// Read a mailbox, mapping a read failure onto a refusal.
fn read_mailbox(
    reader: &dyn ParentStatusReader,
    namespace: &str,
    name: &str,
) -> Result<MailboxStatus, Denial> {
    let mailbox = reader
        .mailbox(namespace, name)
        .map_err(|error| match error {
            StatusReadError::NotFound => Denial::new(
                Reason::InvalidTargetRef,
                format!("the mailbox {name} does not exist"),
            ),
            StatusReadError::Unavailable => Denial::new(
                Reason::DependencyUnavailable,
                "the mailbox status could not be read",
            ),
            StatusReadError::Forbidden => Denial::new(
                Reason::DependencyUnavailable,
                "the mailbox status could not be read",
            ),
        })?;
    check_namespace(&mailbox.namespace, namespace, "Mailbox")?;
    Ok(mailbox)
}

/// Read a provider, mapping a read failure onto a refusal.
fn read_provider(
    reader: &dyn ParentStatusReader,
    namespace: &str,
    name: &str,
) -> Result<ProviderStatus, Denial> {
    let provider = reader
        .provider(namespace, name)
        .map_err(|error| match error {
            StatusReadError::NotFound => Denial::new(
                Reason::InvalidTargetRef,
                format!("the provider {name} does not exist"),
            ),
            StatusReadError::Unavailable => Denial::new(
                Reason::DependencyUnavailable,
                "the provider status could not be read",
            ),
            StatusReadError::Forbidden => Denial::new(
                Reason::DependencyUnavailable,
                "the provider status could not be read",
            ),
        })?;
    check_namespace(&provider.namespace, namespace, "MailProvider")?;
    Ok(provider)
}

/// Read a gateway, mapping a read failure onto a refusal.
fn read_gateway(
    reader: &dyn ParentStatusReader,
    namespace: &str,
    name: &str,
) -> Result<GatewayStatus, Denial> {
    let gateway = reader
        .gateway(namespace, name)
        .map_err(|error| match error {
            StatusReadError::NotFound => Denial::new(
                Reason::InvalidGatewayRef,
                format!("the gateway {name} does not exist"),
            ),
            StatusReadError::Unavailable => Denial::new(
                Reason::DependencyUnavailable,
                "the gateway status could not be read",
            ),
            StatusReadError::Forbidden => Denial::new(
                Reason::DependencyUnavailable,
                "the gateway status could not be read",
            ),
        })?;
    check_namespace(&gateway.namespace, namespace, "CorviGateway")?;
    Ok(gateway)
}

/// Refuse a resource that lives in another namespace.
fn check_namespace(actual: &str, expected: &str, kind: &str) -> Result<(), Denial> {
    if actual == expected {
        return Ok(());
    }
    Err(Denial::new(
        Reason::CrossNamespaceReference,
        format!("the referenced {kind} is in another namespace"),
    ))
}

/// Refuse a status that is not fresh for the resource it describes.
///
/// A capability status that was observed for an older generation describes a
/// resource that no longer exists. Admitting against it would decide on
/// facts the cluster has already moved past.
fn check_freshness(
    observed_generation: u64,
    generation: u64,
    kind: &str,
    name: &str,
) -> Result<(), Denial> {
    if observed_generation == generation {
        return Ok(());
    }
    Err(Denial::new(
        Reason::StaleCapabilityStatus,
        format!("the status of {kind} {name} is not fresh for the current generation"),
    ))
}

/// The target of a credential, for a caller that needs to name it.
pub fn target_of(credential: &MailCredential) -> &TargetRef {
    credential.spec().target_ref()
}
