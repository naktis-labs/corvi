//! MailCredential admission, continuous revalidation and connection Secrets.
//!
//! ADR-0014 defines one credential custom resource and two components that
//! touch it: a read-only validating admission webhook, and a separately
//! authorized publisher that writes the connection Secret. This crate is
//! the decision logic of both.
//!
//! The crate contains **no cluster client and no webhook server**. It has
//! no network access and no Kubernetes dependency, so everything it decides
//! is decided here and tested here. The two places where a real deployment
//! attaches are named seams:
//!
//! * [`admission::ParentStatusReader`] — reads the current status of the
//!   `MailIdentity`, `Mailbox`, `MailProvider` and `CorviGateway` a
//!   credential refers to. A real implementation talks to the Kubernetes
//!   API with a read-only ServiceAccount; it may not write anything.
//! * [`publisher::SecretStore`] — reads and writes the generated Secret. A
//!   real implementation talks to the Kubernetes API with the publisher's
//!   own narrowly scoped ServiceAccount.
//!
//! The rules the logic enforces follow from the ADR.
//!
//! 1. **One protocol shape.** SMTP is the default; a credential that
//!    declares two shapes is refused.
//! 2. **Scoped means gateway and identity.** A credential that asks for
//!    Corvi permissions needs a gateway-bound provider and an identity
//!    target. A provider-native credential omits permissions and needs a
//!    verified identity or a whole-mailbox granularity the provider really
//!    isolates.
//! 3. **Fail closed.** A stale capability status, an unreachable dependency
//!    or a missing parent refuses the request.
//! 4. **Revalidate continuously.** A parent that changes or is suspended
//!    revokes the credential's authority; the published output is withdrawn
//!    before any replacement becomes available.
//! 5. **Never convert.** A scoped credential does not become a native one,
//!    and a native one does not become a scoped one.
//! 6. **Separate the roles.** Admission never issues anything. The
//!    publisher needs its own authorization to write a Secret.
//! 7. **Publish flat and exactly.** One protocol per Secret, flat keys,
//!    approved annotations, observed endpoints, whole-map replacement, and
//!    never a foreign Secret.

pub mod admission;
pub mod model;
pub mod policy;
pub mod publisher;
pub mod reasons;
pub mod revalidate;
pub mod testing;

pub use admission::{
    AdmissionDecision, AdmissionOperation, AdmissionOutcome, AdmissionRequest, ChainSnapshot,
    ConnectionAuthority, ConnectionMode, CredentialGranularity, Denial, GatewayStatus,
    IdentityStatus, LocalRef, MailboxStatus, ObservedEndpoint, ParentStatusReader,
    ProviderCapabilities, ProviderStatus, ResolvedGraph, SmtpAuthMechanism, SmtpRoute,
    StatusReadError, TlsMode, admit, resolve_authority, resolve_graph,
};
pub use model::{
    MailCredential, MailCredentialSpec, Permission, ProtocolType, RequestedAuthority,
    SecretTemplate, SecretTemplateMetadata, SpecError, TargetKind, TargetRef, default_secret_name,
};
pub use policy::SecretPolicy;
pub use publisher::{
    FORBIDDEN_SECRET_KEYS, IssuedMaterial, ObservedRoute, PublishError, PublishOutcome,
    PublishRequest, PublisherGrant, RevocationOutcome, RevocationRequest, SecretObject,
    SecretPublisher, SecretStore, SecretStoreError, assert_no_forbidden_material,
    build_secret_data,
};
pub use reasons::Reason;
pub use revalidate::{IssuedCredential, RevalidationDecision, revalidate};
