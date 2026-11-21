//! Publishing the connection Secret of a MailCredential.
//!
//! The publisher is a **separate trust role** from admission (ADR-0014
//! section 6). Admission reads the resource graph and decides; it has no
//! permission to create, update or read a Secret, and it never issues a
//! credential. The publisher holds its own authorization — a
//! [`PublisherGrant`] — and refuses to write anything without it. A
//! credential that admission approved is therefore not, by itself, a
//! credential that may be published.
//!
//! The published Secret follows the flat-key contract of
//! `api/generated-connection-secret.schema.json`:
//!
//! * one protocol shape per Secret, with exactly the keys of that protocol;
//! * only approved annotations, and no reserved ones;
//! * the endpoints that were actually observed, never a fabricated name;
//! * the whole `data` map replaced, never merged, so a rotated credential
//!   cannot leave a stale key behind.
//!
//! Three things are never written: a provider administration token, an
//! issuer or signing key, and a gateway or plugin API token. The material
//! types make most of them inexpressible, and [`assert_no_forbidden_material`]
//! refuses the rest by name.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::admission::{
    ConnectionAuthority, ConnectionMode, CredentialGranularity, ObservedEndpoint, SmtpRoute,
};
use crate::model::ProtocolType;
use crate::policy::SecretPolicy;
use crate::reasons::Reason;
use crate::revalidate::RevalidationDecision;

/// Keys a published Secret may never carry.
///
/// The list names the credentials that belong to Corvi's own provider
/// management or to the control plane's internal plumbing. A connection
/// Secret is handed to an application, so it must never hand out the means
/// to administer the provider, to sign on behalf of Corvi or to call the
/// gateway's or a plugin's private API.
pub const FORBIDDEN_SECRET_KEYS: &[&str] = &[
    "PROVIDER_ADMIN_TOKEN",
    "PROVIDER_ADMIN_PASSWORD",
    "PROVIDER_ADMIN_USERNAME",
    "PROVIDER_ADMIN_API_KEY",
    "PROVIDER_ADMIN_SECRET",
    "PROVIDER_TOKEN",
    "PROVIDER_API_KEY",
    "PROVIDER_API_TOKEN",
    "GATEWAY_API_TOKEN",
    "GATEWAY_TOKEN",
    "GATEWAY_ADMIN_TOKEN",
    "PLUGIN_API_TOKEN",
    "PLUGIN_TOKEN",
    "PLUGIN_ADMIN_TOKEN",
    "OAUTH_REFRESH_TOKEN",
    "OAUTH_ACCESS_TOKEN",
    "REFRESH_TOKEN",
    "ACCESS_TOKEN",
    "ISSUER_KEY",
    "ISSUER_PRIVATE_KEY",
    "SIGNING_KEY",
    "SIGNING_PRIVATE_KEY",
    "SECRET_BROKER_TOKEN",
    "SECRET_BROKER_CREDENTIAL",
];

/// Why a publication was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishError {
    /// The publisher is not authorized to write in this namespace.
    NotAuthorized,
    /// The requested annotation is not approved.
    UnsafeAnnotation {
        /// The offending annotation key.
        key: String,
    },
    /// The Secret name is taken by another owner, or changed underneath the
    /// publisher between the read and the write.
    SecretNameConflict {
        /// The contested Secret name.
        name: String,
    },
    /// The issued material does not match the declared protocol.
    MaterialMismatch {
        /// The authentication type the protocol needs.
        expected: &'static str,
    },
    /// No observed endpoint serves the declared protocol.
    NoObservedEndpoint {
        /// The protocol without an endpoint.
        protocol: ProtocolType,
    },
    /// The observed endpoint was not verified.
    UnverifiedEndpoint {
        /// The protocol whose endpoint was refused.
        protocol: ProtocolType,
    },
    /// A connection fact the protocol requires is missing.
    MissingRouteFact {
        /// The missing field.
        field: String,
    },
    /// The Secret would carry material it must never carry.
    ForbiddenMaterial {
        /// The offending key.
        key: String,
    },
    /// The authority of the credential changed before publication.
    AuthorityChanged {
        /// Why the authority changed.
        reason: Reason,
    },
    /// The Secret store refused or failed the write.
    Store(SecretStoreError),
}

impl PublishError {
    /// A message that names the condition without naming a secret.
    pub fn message(&self) -> String {
        match self {
            Self::NotAuthorized => "the publisher is not authorized for this namespace".to_string(),
            Self::UnsafeAnnotation { key } => {
                format!("the annotation {key} is not approved for a published Secret")
            }
            Self::SecretNameConflict { name } => {
                format!("the Secret {name} is owned by another producer")
            }
            Self::MaterialMismatch { expected } => {
                format!("the issued material does not match the {expected} authentication type")
            }
            Self::NoObservedEndpoint { protocol } => {
                format!("no observed endpoint serves {protocol}")
            }
            Self::UnverifiedEndpoint { protocol } => {
                format!("the observed endpoint for {protocol} was not verified")
            }
            Self::MissingRouteFact { field } => {
                format!("the observed route does not carry {field}")
            }
            Self::ForbiddenMaterial { key } => {
                format!("the key {key} may never be published")
            }
            Self::AuthorityChanged { reason } => {
                format!("the authority of the credential changed: {reason}")
            }
            Self::Store(error) => format!("the Secret store refused the write: {error}"),
        }
    }
}

impl fmt::Display for PublishError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for PublishError {}

impl From<SecretStoreError> for PublishError {
    fn from(error: SecretStoreError) -> Self {
        Self::Store(error)
    }
}

/// Why a Secret store refused a write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretStoreError {
    /// The Secret already exists.
    AlreadyExists,
    /// The Secret changed since it was read.
    Conflict,
    /// The store could not be reached.
    Unavailable,
    /// The store refused the call.
    Forbidden,
}

impl fmt::Display for SecretStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyExists => f.write_str("already exists"),
            Self::Conflict => f.write_str("conflict"),
            Self::Unavailable => f.write_str("unavailable"),
            Self::Forbidden => f.write_str("forbidden"),
        }
    }
}

impl std::error::Error for SecretStoreError {}

/// One Kubernetes Secret, in the shape the publisher needs.
///
/// The publisher works with decoded UTF-8 values, because that is what the
/// flat-key contract describes; a real client encodes them. A published
/// Secret is always `type: Opaque`, and the publisher adopts only a Secret
/// whose owner is the credential that asks for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretObject {
    /// The namespace the Secret lives in.
    pub namespace: String,
    /// The Secret name.
    pub name: String,
    /// The UID the cluster assigned to the Secret.
    pub uid: String,
    /// The resource version of the Secret.
    pub resource_version: String,
    /// The complete data map of the Secret.
    pub data: BTreeMap<String, String>,
    /// The annotations of the Secret.
    pub annotations: BTreeMap<String, String>,
    /// The UID of the owner that may replace this Secret.
    pub owner_uid: Option<String>,
}

/// The Secret store the publisher writes through.
///
/// The trait is the seam where a real Kubernetes client attaches. Its shape
/// carries the two rules that make concurrent publication safe: creation
/// only succeeds when the name is free, and replacement only succeeds when
/// the Secret still has the version the publisher read.
pub trait SecretStore {
    /// Read the current Secret, if there is one.
    fn get(&self, namespace: &str, name: &str) -> Result<Option<SecretObject>, SecretStoreError>;

    /// Create a Secret only when the name is free.
    fn create_if_absent(&self, secret: &SecretObject) -> Result<SecretObject, SecretStoreError>;

    /// Replace the whole data map of a Secret that still has the expected
    /// resource version.
    fn replace_if_version_matches(
        &self,
        secret: &SecretObject,
        expected_resource_version: &str,
    ) -> Result<SecretObject, SecretStoreError>;

    /// Delete a Secret that still has the expected resource version.
    fn delete_if_version_matches(
        &self,
        namespace: &str,
        name: &str,
        expected_resource_version: &str,
    ) -> Result<(), SecretStoreError>;
}

/// The issuer's own authority to publish.
///
/// The grant is deliberately independent of admission: it says which
/// namespaces this publisher may write in, and nothing about which
/// credentials are admissible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublisherGrant {
    namespaces: BTreeSet<String>,
}

impl PublisherGrant {
    /// Grant a publisher the right to write in one namespace.
    pub fn for_namespace(namespace: impl Into<String>) -> Self {
        let mut namespaces = BTreeSet::new();
        namespaces.insert(namespace.into());
        Self { namespaces }
    }

    /// The namespaces this publisher may write in.
    pub fn namespaces(&self) -> &BTreeSet<String> {
        &self.namespaces
    }

    /// Check the grant against a namespace.
    pub fn authorize(&self, namespace: &str) -> Result<(), PublishError> {
        if self.namespaces.contains(namespace) {
            return Ok(());
        }
        Err(PublishError::NotAuthorized)
    }
}

/// The credential material the issuer handed over.
///
/// The variants are the only shapes a published Secret may take, so a
/// provider administration token or an issuer key has no way to reach the
/// output at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssuedMaterial {
    /// A Corvi OAuth client credential for a gateway-scoped connection.
    OAuth2Client {
        /// The token endpoint of the gateway's authorization server.
        token_url: String,
        /// The client identifier.
        client_id: String,
        /// The client secret.
        client_secret: String,
        /// The Corvi mail-resource audience.
        resource: String,
        /// The Corvi action scopes.
        scopes: Vec<String>,
    },
    /// A provider application password for SMTP submission.
    SmtpPassword {
        /// The user name the provider issued.
        username: String,
        /// The application password.
        password: String,
    },
    /// An independent provider application bearer token.
    BearerToken {
        /// The application token.
        token: String,
    },
}

/// The connection facts that were actually observed.
///
/// Nothing here is secret, and nothing here may be invented: the endpoint
/// list holds the URLs a controller saw, and the SMTP route holds the
/// submission service the provider or gateway advertised.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ObservedRoute {
    /// The endpoints that were observed.
    pub endpoints: Vec<ObservedEndpoint>,
    /// The observed SMTP route, when the protocol is SMTP.
    pub smtp: Option<SmtpRoute>,
    /// The sender address, when it is known.
    pub from_address: Option<String>,
    /// The envelope sender, when it is authorized and known.
    pub envelope_from: Option<String>,
    /// The PEM of a configured private certificate authority.
    pub tls_ca_pem: Option<String>,
}

/// One publication request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishRequest {
    /// The namespace the Secret is written in.
    pub namespace: String,
    /// The name of the credential that owns the Secret.
    pub credential_name: String,
    /// The UID of the credential that owns the Secret.
    pub credential_uid: String,
    /// The Secret name.
    pub secret_name: String,
    /// Whether this is a dry run.
    pub dry_run: bool,
    /// The revision of the credential being published.
    pub revision: String,
    /// The authority the credential holds.
    pub authority: ConnectionAuthority,
    /// The material the issuer handed over.
    pub material: IssuedMaterial,
    /// The observed connection facts.
    pub observed: ObservedRoute,
    /// The annotations the credential requested.
    pub annotations: BTreeMap<String, String>,
}

impl PublishRequest {
    /// Describe a publication request.
    pub fn new(
        namespace: impl Into<String>,
        credential_name: impl Into<String>,
        credential_uid: impl Into<String>,
        secret_name: impl Into<String>,
        authority: ConnectionAuthority,
        material: IssuedMaterial,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            credential_name: credential_name.into(),
            credential_uid: credential_uid.into(),
            secret_name: secret_name.into(),
            dry_run: false,
            revision: "1".to_string(),
            authority,
            material,
            observed: ObservedRoute::default(),
            annotations: BTreeMap::new(),
        }
    }
}

/// What a publication did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishOutcome {
    /// The name of the Secret.
    pub secret_name: String,
    /// The revision that was published.
    pub revision: String,
    /// Whether the Secret was created.
    pub created: bool,
    /// Whether the Secret was replaced.
    pub updated: bool,
    /// Whether nothing was written because this was a dry run.
    pub dry_run: bool,
}

/// One revocation request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationRequest {
    /// The namespace the Secret lives in.
    pub namespace: String,
    /// The UID of the credential that owns the Secret.
    pub credential_uid: String,
    /// The Secret name.
    pub secret_name: String,
    /// Whether the issuer confirmed the upstream revocation.
    pub upstream_revoked: bool,
}

/// What a revocation did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationOutcome {
    /// The Secret was removed and the upstream revocation was confirmed.
    Revoked,
    /// The Secret was removed, but the upstream revocation could not be
    /// confirmed. The output is gone; the credential may still exist
    /// upstream, so the caller has to report it.
    OutputWithdrawn,
    /// There was no Secret to withdraw.
    NothingToWithdraw,
}

/// The publisher of connection Secrets.
pub struct SecretPublisher<'a> {
    store: &'a dyn SecretStore,
    grant: &'a PublisherGrant,
    policy: &'a SecretPolicy,
}

impl fmt::Debug for SecretPublisher<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretPublisher")
            .field("grant", &self.grant)
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl<'a> SecretPublisher<'a> {
    /// Build a publisher from its store, its own grant and the Secret
    /// policy it enforces.
    pub fn new(
        store: &'a dyn SecretStore,
        grant: &'a PublisherGrant,
        policy: &'a SecretPolicy,
    ) -> Self {
        Self {
            store,
            grant,
            policy,
        }
    }

    /// Publish the connection Secret of one credential.
    ///
    /// The publisher checks its own authorization first, then builds the
    /// complete data map, then refuses to touch a Secret that another owner
    /// holds. A Secret is created only when its name is free, and replaced
    /// only when it still has the version the publisher read, so two
    /// publishers racing for one name cannot corrupt it: the loser fails
    /// closed instead of clobbering the winner.
    ///
    /// The caller is expected to have revalidated the credential against
    /// the current graph first; [`SecretPublisher::publish_after_revalidation`]
    /// is the entry point that enforces that.
    pub fn publish(&self, request: &PublishRequest) -> Result<PublishOutcome, PublishError> {
        self.grant.authorize(&request.namespace)?;

        let data = build_secret_data(request)?;
        self.policy.check(&request.annotations)?;
        assert_no_forbidden_material(&data)?;

        let desired = SecretObject {
            namespace: request.namespace.clone(),
            name: request.secret_name.clone(),
            uid: String::new(),
            resource_version: String::new(),
            data,
            annotations: request.annotations.clone(),
            owner_uid: Some(request.credential_uid.clone()),
        };

        let existing = self.store.get(&request.namespace, &request.secret_name)?;
        match existing {
            None => {
                if request.dry_run {
                    return Ok(PublishOutcome {
                        secret_name: request.secret_name.clone(),
                        revision: request.revision.clone(),
                        created: false,
                        updated: false,
                        dry_run: true,
                    });
                }
                match self.store.create_if_absent(&desired) {
                    Ok(_) => Ok(PublishOutcome {
                        secret_name: request.secret_name.clone(),
                        revision: request.revision.clone(),
                        created: true,
                        updated: false,
                        dry_run: false,
                    }),
                    Err(SecretStoreError::AlreadyExists) => Err(PublishError::SecretNameConflict {
                        name: request.secret_name.clone(),
                    }),
                    Err(error) => Err(PublishError::Store(error)),
                }
            }
            Some(existing) => {
                // A Secret that another producer owns is never adopted and
                // never overwritten, not even when the name was requested
                // explicitly.
                if existing.owner_uid.as_deref() != Some(request.credential_uid.as_str()) {
                    return Err(PublishError::SecretNameConflict {
                        name: request.secret_name.clone(),
                    });
                }
                if request.dry_run {
                    return Ok(PublishOutcome {
                        secret_name: request.secret_name.clone(),
                        revision: request.revision.clone(),
                        created: false,
                        updated: false,
                        dry_run: true,
                    });
                }
                let mut replacement = desired;
                replacement.uid = existing.uid.clone();
                replacement.resource_version = existing.resource_version.clone();
                match self
                    .store
                    .replace_if_version_matches(&replacement, &existing.resource_version)
                {
                    Ok(_) => Ok(PublishOutcome {
                        secret_name: request.secret_name.clone(),
                        revision: request.revision.clone(),
                        created: false,
                        updated: true,
                        dry_run: false,
                    }),
                    Err(SecretStoreError::Conflict) => Err(PublishError::SecretNameConflict {
                        name: request.secret_name.clone(),
                    }),
                    Err(error) => Err(PublishError::Store(error)),
                }
            }
        }
    }

    /// Publish the connection Secret of a credential that still holds its
    /// authority.
    ///
    /// This is the entry point a reconciler uses: it revalidates against
    /// the current graph first, and refuses to write anything when the
    /// credential was revoked or when the graph could not be resolved.
    /// Publication never repairs a credential by converting it.
    pub fn publish_after_revalidation(
        &self,
        request: &PublishRequest,
        decision: &RevalidationDecision,
    ) -> Result<PublishOutcome, PublishError> {
        match decision {
            RevalidationDecision::Keep => self.publish(request),
            RevalidationDecision::Revoke { reason, .. }
            | RevalidationDecision::Withhold { reason, .. } => {
                Err(PublishError::AuthorityChanged { reason: *reason })
            }
        }
    }

    /// Withdraw the connection Secret of a revoked credential.
    ///
    /// The Secret is removed before anything else may replace it, so a
    /// revoked credential never leaves usable credentials behind. A Secret
    /// that another producer owns is left alone.
    pub fn revoke(&self, request: &RevocationRequest) -> Result<RevocationOutcome, PublishError> {
        self.grant.authorize(&request.namespace)?;

        let existing = self.store.get(&request.namespace, &request.secret_name)?;
        let Some(existing) = existing else {
            return Ok(RevocationOutcome::NothingToWithdraw);
        };
        if existing.owner_uid.as_deref() != Some(request.credential_uid.as_str()) {
            return Err(PublishError::SecretNameConflict {
                name: request.secret_name.clone(),
            });
        }
        self.store.delete_if_version_matches(
            &request.namespace,
            &request.secret_name,
            &existing.resource_version,
        )?;
        if request.upstream_revoked {
            return Ok(RevocationOutcome::Revoked);
        }
        Ok(RevocationOutcome::OutputWithdrawn)
    }
}

/// Build the complete data map of a connection Secret.
///
/// The map holds exactly the keys of the declared protocol and nothing else:
/// a gateway MCP credential carries the OAuth keys and the MCP URL, a
/// provider-native SMTP credential carries the SMTP keys, and neither
/// carries the other's.
pub fn build_secret_data(
    request: &PublishRequest,
) -> Result<BTreeMap<String, String>, PublishError> {
    let authority = &request.authority;
    let mut data: BTreeMap<String, String> = BTreeMap::new();

    data.insert(
        "CONNECTION_TYPE".to_string(),
        authority.credential_type.as_wire().to_string(),
    );
    data.insert(
        "CONNECTION_MODE".to_string(),
        authority.mode.as_wire().to_string(),
    );
    data.insert(
        "CREDENTIAL_GRANULARITY".to_string(),
        authority.granularity.as_wire().to_string(),
    );
    data.insert("PROVIDER_NAME".to_string(), authority.provider_name.clone());
    data.insert("CREDENTIAL_REVISION".to_string(), request.revision.clone());

    match authority.granularity {
        CredentialGranularity::CorviIdentity | CredentialGranularity::ProviderIdentity => {
            let identity = authority.identity_name.as_deref().ok_or_else(|| {
                PublishError::MissingRouteFact {
                    field: "IDENTITY_NAME".to_string(),
                }
            })?;
            data.insert("IDENTITY_NAME".to_string(), identity.to_string());
        }
        CredentialGranularity::ProviderMailbox => {
            let mailbox = authority.mailbox_name.as_deref().ok_or_else(|| {
                PublishError::MissingRouteFact {
                    field: "MAILBOX_NAME".to_string(),
                }
            })?;
            data.insert("MAILBOX_NAME".to_string(), mailbox.to_string());
        }
    }

    match (authority.mode, authority.credential_type) {
        (ConnectionMode::Gateway, ProtocolType::Mcp)
        | (ConnectionMode::Gateway, ProtocolType::Rest) => {
            let IssuedMaterial::OAuth2Client {
                token_url,
                client_id,
                client_secret,
                resource,
                scopes,
            } = &request.material
            else {
                return Err(PublishError::MaterialMismatch {
                    expected: "oauth2_client_credentials",
                });
            };
            data.insert(
                endpoint_key(authority.credential_type).to_string(),
                select_endpoint(&request.observed.endpoints, authority.credential_type)?,
            );
            data.insert("OAUTH_TOKEN_URL".to_string(), token_url.clone());
            data.insert("OAUTH_CLIENT_ID".to_string(), client_id.clone());
            data.insert("OAUTH_CLIENT_SECRET".to_string(), client_secret.clone());
            data.insert("OAUTH_RESOURCE".to_string(), resource.clone());
            data.insert("OAUTH_SCOPES".to_string(), scopes.join(" "));
            data.insert(
                "AUTH_TYPE".to_string(),
                "oauth2_client_credentials".to_string(),
            );
        }
        (ConnectionMode::ProviderDirect, ProtocolType::Mcp)
        | (ConnectionMode::ProviderDirect, ProtocolType::Rest) => {
            let IssuedMaterial::BearerToken { token } = &request.material else {
                return Err(PublishError::MaterialMismatch {
                    expected: "bearer_token",
                });
            };
            data.insert(
                endpoint_key(authority.credential_type).to_string(),
                select_endpoint(&request.observed.endpoints, authority.credential_type)?,
            );
            data.insert("API_TOKEN".to_string(), token.clone());
            data.insert("AUTH_TYPE".to_string(), "bearer_token".to_string());
        }
        (_, ProtocolType::Smtp) => {
            let IssuedMaterial::SmtpPassword { username, password } = &request.material else {
                return Err(PublishError::MaterialMismatch {
                    expected: "smtp_password",
                });
            };
            let route = request
                .observed
                .smtp
                .as_ref()
                .ok_or(PublishError::NoObservedEndpoint {
                    protocol: ProtocolType::Smtp,
                })?;
            let from_address = request.observed.from_address.as_deref().ok_or_else(|| {
                PublishError::MissingRouteFact {
                    field: "SMTP_FROM_ADDRESS".to_string(),
                }
            })?;
            data.insert("SMTP_HOST".to_string(), route.host.clone());
            data.insert("SMTP_PORT".to_string(), route.port.to_string());
            data.insert(
                "SMTP_TLS_MODE".to_string(),
                route.tls_mode.as_wire().to_string(),
            );
            data.insert("SMTP_SERVER_NAME".to_string(), route.server_name.clone());
            data.insert(
                "SMTP_AUTH_MECHANISM".to_string(),
                route.auth_mechanism.as_wire().to_string(),
            );
            data.insert("SMTP_USERNAME".to_string(), username.clone());
            data.insert("SMTP_PASSWORD".to_string(), password.clone());
            data.insert("SMTP_FROM_ADDRESS".to_string(), from_address.to_string());
            if let Some(envelope) = &request.observed.envelope_from {
                data.insert("SMTP_ENVELOPE_FROM".to_string(), envelope.clone());
            }
            data.insert("AUTH_TYPE".to_string(), "smtp_password".to_string());
        }
    }

    if let Some(ca_pem) = &request.observed.tls_ca_pem {
        data.insert("TLS_CA_PEM".to_string(), ca_pem.clone());
    }

    Ok(data)
}

/// The Secret key that holds the endpoint of a protocol.
fn endpoint_key(protocol: ProtocolType) -> &'static str {
    match protocol {
        ProtocolType::Mcp => "MCP_URL",
        ProtocolType::Rest => "REST_URL",
        ProtocolType::Smtp => "SMTP_HOST",
    }
}

/// The observed endpoint that serves a protocol.
///
/// The endpoint is used exactly as it was observed. An endpoint that was
/// not verified, or that is not HTTPS for a web protocol, is refused
/// instead of being published.
fn select_endpoint(
    endpoints: &[ObservedEndpoint],
    protocol: ProtocolType,
) -> Result<String, PublishError> {
    let endpoint = endpoints
        .iter()
        .find(|endpoint| endpoint.protocol == protocol)
        .ok_or(PublishError::NoObservedEndpoint { protocol })?;
    if !endpoint.verified {
        return Err(PublishError::UnverifiedEndpoint { protocol });
    }
    if matches!(protocol, ProtocolType::Mcp | ProtocolType::Rest)
        && !endpoint.url.starts_with("https://")
    {
        return Err(PublishError::UnverifiedEndpoint { protocol });
    }
    Ok(endpoint.url.clone())
}

/// Refuse a Secret that carries material it must never carry.
///
/// The material types already make most of these inexpressible; this check
/// is the second line, in case a future key is added without thinking about
/// what it exposes.
pub fn assert_no_forbidden_material(data: &BTreeMap<String, String>) -> Result<(), PublishError> {
    for key in data.keys() {
        if is_forbidden_key(key) {
            return Err(PublishError::ForbiddenMaterial { key: key.clone() });
        }
    }
    Ok(())
}

/// Whether a Secret key names material that must never be published.
fn is_forbidden_key(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    FORBIDDEN_SECRET_KEYS
        .iter()
        .any(|forbidden| *forbidden == upper)
        || upper.contains("ADMIN")
        || upper.contains("REFRESH")
        || upper.contains("PRIVATE_KEY")
}
