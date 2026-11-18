//! The provider profile: everything a deployment must know before it can
//! onboard an upstream account.
//!
//! ADR-0008 section 1 is blunt about this: "every upstream provider and
//! transport declares and validates its **actual** supported onboarding
//! methods", and "a provider's lack of public client registration or device
//! grant MUST be surfaced as a deployment constraint rather than hidden
//! behind an allegedly generic OAuth button".
//!
//! So the profile is a first-class object, not a bag of configuration. It
//! answers the questions the onboarding flow has to ask before it starts:
//!
//! - which endpoints exist and are they HTTPS,
//! - which client type the provider expects and whether it issues a secret,
//! - which redirect URIs were actually registered,
//! - which upstream scopes the provider really offers,
//! - whether the provider offers a device grant at all,
//! - how the upstream account is verified afterwards.
//!
//! The profile mirrors `api/upstream-oauth.schema.json`, and the example
//! descriptors in `api/upstream-oauth/examples/` are the ones this crate
//! ships. They are **deployment templates, not verified provider facts**: the
//! endpoints and scope strings must be confirmed against the provider's own
//! documentation before a deployment enables them. This crate performs no
//! network calls and verifies nothing against a live provider.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::callback::is_loopback_uri;
use crate::error::UpstreamOAuthError;

/// The descriptor version this build understands.
pub const API_VERSION: &str = "corvi.naktis.eu/v1alpha1";

/// The descriptor kind this build understands.
pub const KIND: &str = "UpstreamOAuthProvider";

/// The example descriptors that ship with the repository.
///
/// The identifiers are the provider names; the documents are the
/// descriptors under `api/upstream-oauth/examples/`.
const EXAMPLE_DESCRIPTORS: &[(&str, &str)] = &[
    (
        "gmail",
        include_str!("../../../api/upstream-oauth/examples/gmail.json"),
    ),
    (
        "microsoft365",
        include_str!("../../../api/upstream-oauth/examples/microsoft365.json"),
    ),
    (
        "fastmail",
        include_str!("../../../api/upstream-oauth/examples/fastmail.json"),
    ),
];

/// How the client is authenticated at the token endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ClientType {
    /// A client that cannot keep a secret.
    Public,
    /// A client that authenticates with a secret or a certificate.
    Confidential,
}

impl ClientType {
    /// The name of the client type.
    pub fn as_str(&self) -> &'static str {
        match self {
            ClientType::Public => "public",
            ClientType::Confidential => "confidential",
        }
    }
}

/// How the client was registered with the provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RegistrationMode {
    /// The client identifier and the callback were registered by hand.
    PreRegistered,
    /// The client is identified by a client-id metadata document.
    ClientIdMetadata,
    /// The client was registered dynamically.
    Dynamic,
    /// The provider treats the client as a native open client.
    NativeOpenClient,
}

impl RegistrationMode {
    /// The name of the registration mode.
    pub fn as_str(&self) -> &'static str {
        match self {
            RegistrationMode::PreRegistered => "preRegistered",
            RegistrationMode::ClientIdMetadata => "clientIdMetadata",
            RegistrationMode::Dynamic => "dynamic",
            RegistrationMode::NativeOpenClient => "nativeOpenClient",
        }
    }
}

/// The PKCE method a client uses.
///
/// RFC 9700 requires S256 for every authorization code client, so this
/// build has no other method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PkceMethod {
    /// The SHA-256 challenge method.
    #[serde(rename = "S256")]
    S256,
}

/// The registration of the client with the provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientRegistration {
    /// The registered client identifier or client metadata URL.
    pub client_id: String,
    /// Whether the client can keep a secret.
    #[serde(rename = "type")]
    pub client_type: ClientType,
    /// How the client was registered.
    pub registration: RegistrationMode,
    /// A reference to the client secret. Never the secret itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret_ref: Option<String>,
    /// The exact callbacks that were registered with the provider.
    pub redirect_uris: Vec<String>,
    /// The PKCE method.
    pub pkce: PkceMethod,
}

impl ClientRegistration {
    /// Whether the provider expects a client secret from this client.
    pub fn issues_client_secret(&self) -> bool {
        self.client_type == ClientType::Confidential
    }
}

/// The endpoints of the provider's authorization server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderEndpoints {
    /// The authorization endpoint.
    pub authorization: String,
    /// The token endpoint.
    pub token: String,
    /// The device authorization endpoint, when the provider has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_authorization: Option<String>,
    /// The revocation endpoint, when the provider advertises one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation: Option<String>,
    /// The dynamic client registration endpoint, when the provider has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration: Option<String>,
}

/// The upstream scope strings the provider really offers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderScopes {
    /// The scopes that let Corvi read mail.
    pub read: Vec<String>,
    /// The scopes that let Corvi submit mail.
    pub send: Vec<String>,
    /// The scopes that ask for offline access.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offline: Option<Vec<String>>,
    /// The scopes that let Corvi administer the upstream account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub management: Option<Vec<String>>,
}

impl ProviderScopes {
    /// Every scope string the provider offers.
    pub fn all(&self) -> Vec<String> {
        let mut scopes = Vec::new();
        scopes.extend(self.read.iter().cloned());
        scopes.extend(self.send.iter().cloned());
        scopes.extend(self.offline.iter().flatten().cloned());
        scopes.extend(self.management.iter().flatten().cloned());
        scopes.sort();
        scopes.dedup();
        scopes
    }

    /// The scopes that belong to one capability.
    pub fn for_capability(&self, capability: crate::scope::Capability) -> Vec<String> {
        use crate::scope::Capability;
        match capability {
            Capability::Read => self.read.clone(),
            Capability::Send => self.send.clone(),
            Capability::Offline => self.offline.clone().unwrap_or_default(),
            Capability::Management => self.management.clone().unwrap_or_default(),
        }
    }
}

/// Whether the provider supports refresh at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RefreshSupport {
    /// The provider says whether it supports refresh.
    Known(bool),
    /// The provider does not say.
    Unknown,
}

impl RefreshSupport {
    /// Whether refresh is known to work.
    pub fn is_supported(&self) -> bool {
        matches!(self, RefreshSupport::Known(true))
    }
}

/// How several replicas share one refresh credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RefreshStrategy {
    /// One instance owns the credential.
    SingleOwner,
    /// A coordinated broker owns it.
    CoordinatedBroker,
}

impl RefreshStrategy {
    /// The name of the strategy.
    pub fn as_str(&self) -> &'static str {
        match self {
            RefreshStrategy::SingleOwner => "singleOwner",
            RefreshStrategy::CoordinatedBroker => "coordinatedBroker",
        }
    }
}

/// The refresh behaviour of a provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RefreshProfile {
    /// Whether the provider supports refresh.
    pub supported: RefreshSupport,
    /// The scope that asks for offline access.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offline_scope: Option<String>,
    /// Whether the provider rotates the refresh token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation_expected: Option<bool>,
    /// How several replicas share the credential.
    pub strategy: RefreshStrategy,
}

impl RefreshProfile {
    /// Whether a rotated refresh token is expected.
    pub fn expects_rotation(&self) -> bool {
        self.rotation_expected.unwrap_or(false)
    }
}

/// The interactive flows a provider offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum OnboardingFlow {
    /// The authorization code flow with PKCE.
    AuthorizationCodePkce,
    /// The device authorization grant.
    DeviceAuthorization,
}

impl OnboardingFlow {
    /// The name of the flow.
    pub fn as_str(&self) -> &'static str {
        match self {
            OnboardingFlow::AuthorizationCodePkce => "authorizationCodePkce",
            OnboardingFlow::DeviceAuthorization => "deviceAuthorization",
        }
    }
}

/// The mechanisms an upstream token may be presented with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TransportMechanism {
    /// A bearer token on the JMAP API.
    JmapBearer,
    /// SASL OAUTHBEARER over IMAP.
    ImapOauthBearer,
    /// SASL XOAUTH2 over IMAP.
    ImapXoauth2,
    /// SASL OAUTHBEARER over SMTP.
    SmtpOauthBearer,
    /// SASL XOAUTH2 over SMTP.
    SmtpXoauth2,
}

impl TransportMechanism {
    /// The name of the mechanism.
    pub fn as_str(&self) -> &'static str {
        match self {
            TransportMechanism::JmapBearer => "jmapBearer",
            TransportMechanism::ImapOauthBearer => "imapOauthBearer",
            TransportMechanism::ImapXoauth2 => "imapXoauth2",
            TransportMechanism::SmtpOauthBearer => "smtpOauthBearer",
            TransportMechanism::SmtpXoauth2 => "smtpXoauth2",
        }
    }
}

/// How the upstream account is verified after the callback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AccountVerification {
    /// The JMAP session lists the account.
    JmapSession,
    /// An IMAP authentication probe names the account.
    ImapAuthenticationProbe,
    /// An SMTP authentication probe names the account.
    SmtpAuthenticationProbe,
    /// A provider account API names the account.
    ProviderAccountApi,
}

impl AccountVerification {
    /// The name of the verification strategy.
    pub fn as_str(&self) -> &'static str {
        match self {
            AccountVerification::JmapSession => "jmapSession",
            AccountVerification::ImapAuthenticationProbe => "imapAuthenticationProbe",
            AccountVerification::SmtpAuthenticationProbe => "smtpAuthenticationProbe",
            AccountVerification::ProviderAccountApi => "providerAccountApi",
        }
    }
}

/// The descriptor of one provider.
///
/// The shape is the one `api/upstream-oauth.schema.json` defines, so a
/// deployment can publish its provider descriptors with the same document
/// the crate reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderProfile {
    /// The descriptor version.
    #[serde(default = "default_api_version")]
    pub api_version: String,
    /// The descriptor kind.
    #[serde(default = "default_kind")]
    pub kind: String,
    /// The provider identifier.
    pub provider_id: String,
    /// The configured authorization server issuer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// A trusted discovery document.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery_url: Option<String>,
    /// The client registration.
    pub client: ClientRegistration,
    /// The provider endpoints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoints: Option<ProviderEndpoints>,
    /// The interactive flows the provider offers.
    pub flows: Vec<OnboardingFlow>,
    /// The upstream scope strings.
    pub scopes: ProviderScopes,
    /// The transport mechanisms the upstream token may be used with.
    pub transport_mechanisms: Vec<TransportMechanism>,
    /// The refresh behaviour.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh: Option<RefreshProfile>,
    /// The account verification strategy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_verification: Option<AccountVerification>,
    /// The safe status of the connection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_status: Option<crate::error::ConnectionStatus>,
}

/// The default descriptor version.
fn default_api_version() -> String {
    API_VERSION.to_owned()
}

/// The default descriptor kind.
fn default_kind() -> String {
    KIND.to_owned()
}

impl ProviderProfile {
    /// Whether the provider offers a flow.
    pub fn supports_flow(&self, flow: OnboardingFlow) -> bool {
        self.flows.contains(&flow)
    }

    /// Whether the provider offers the device authorization grant.
    ///
    /// A provider that does not advertise it must never have it offered to
    /// an operator, because an operator who is told a device flow exists
    /// will design a deployment around it.
    pub fn device_flow_supported(&self) -> bool {
        self.supports_flow(OnboardingFlow::DeviceAuthorization)
            && self
                .endpoints
                .as_ref()
                .is_some_and(|endpoints| endpoints.device_authorization.is_some())
    }

    /// Whether the provider issues a client secret for this client.
    pub fn requires_client_secret(&self) -> bool {
        self.client.issues_client_secret()
    }

    /// The flows this profile advertises.
    ///
    /// A flow is advertised only when the provider offers it *and* the
    /// endpoint it needs is configured.
    pub fn advertised_flows(&self) -> Vec<OnboardingFlow> {
        let mut flows = Vec::new();
        for flow in &self.flows {
            match flow {
                OnboardingFlow::AuthorizationCodePkce => {
                    if self
                        .endpoints
                        .as_ref()
                        .is_some_and(|e| !e.authorization.is_empty() && !e.token.is_empty())
                    {
                        flows.push(*flow);
                    }
                }
                OnboardingFlow::DeviceAuthorization => {
                    if self.device_flow_supported() {
                        flows.push(*flow);
                    }
                }
            }
        }
        flows
    }

    /// The capabilities an authorized management surface may show.
    pub fn capabilities(&self) -> AuthCapabilities {
        AuthCapabilities {
            provider: self.provider_id.clone(),
            flows: self.advertised_flows(),
            scopes: self.scopes.clone(),
            transport_mechanisms: self.transport_mechanisms.clone(),
            client_type: self.client.client_type,
            registration: self.client.registration,
            issues_client_secret: self.requires_client_secret(),
            refresh_supported: self
                .refresh
                .as_ref()
                .is_some_and(|refresh| refresh.supported.is_supported()),
            account_verification: self.account_verification,
        }
    }

    /// Check that the deployment configured this provider well enough to
    /// onboard it.
    ///
    /// Every failure is an explicit [`UpstreamOAuthError::UnsupportedRegistration`]
    /// with the constraint that is unmet. Nothing here falls back to a
    /// generic error, and nothing here silently repairs the configuration.
    pub fn validate(&self) -> Result<(), UpstreamOAuthError> {
        let unsupported = |reason: &str| UpstreamOAuthError::UnsupportedRegistration {
            provider: self.provider_id.clone(),
            reason: reason.to_owned(),
        };
        if self.api_version != API_VERSION {
            return Err(unsupported(
                "the descriptor version is not understood by this build",
            ));
        }
        if self.kind != KIND {
            return Err(unsupported(
                "the descriptor kind is not understood by this build",
            ));
        }
        if self.provider_id.trim().is_empty() {
            return Err(unsupported("the provider identifier is empty"));
        }
        if self.client.client_id.trim().is_empty() {
            return Err(unsupported("no client identifier is configured"));
        }
        match self.client.client_type {
            ClientType::Public => {
                if self.client.client_secret_ref.is_some() {
                    return Err(unsupported(
                        "a public client must not be configured with a client secret",
                    ));
                }
            }
            ClientType::Confidential => {
                if self.client.client_secret_ref.is_none() {
                    return Err(unsupported(
                        "the provider issues a client secret and none is configured",
                    ));
                }
            }
        }
        if self.client.redirect_uris.is_empty() {
            return Err(unsupported("no callback is configured"));
        }
        for uri in &self.client.redirect_uris {
            if !is_https(uri) && !is_loopback_uri(uri) {
                return Err(unsupported(
                    "a callback must be https, or http on the loopback interface",
                ));
            }
        }
        if self.flows.is_empty() {
            return Err(unsupported("the provider offers no interactive flow"));
        }
        match &self.issuer {
            None => return Err(unsupported("no issuer is configured")),
            Some(issuer) if !is_https(issuer) => {
                return Err(unsupported("the issuer must be https"));
            }
            Some(_) => {}
        }
        let Some(endpoints) = &self.endpoints else {
            return Err(unsupported("no endpoints are configured"));
        };
        if !is_https(&endpoints.authorization) || !is_https(&endpoints.token) {
            return Err(unsupported(
                "the authorization and token endpoints must be https",
            ));
        }
        if let Some(device) = &endpoints.device_authorization
            && !is_https(device)
        {
            return Err(unsupported(
                "the device authorization endpoint must be https",
            ));
        }
        if self.scopes.read.is_empty() && self.scopes.send.is_empty() {
            return Err(unsupported("the provider offers no mail scope"));
        }
        if self.transport_mechanisms.is_empty() {
            return Err(unsupported("the provider offers no transport mechanism"));
        }
        Ok(())
    }
}

/// Whether a URI is an HTTPS URI.
fn is_https(uri: &str) -> bool {
    uri.starts_with("https://")
}

/// What an authorized management surface may show about a provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthCapabilities {
    /// The provider identifier.
    pub provider: String,
    /// The flows the provider actually offers.
    pub flows: Vec<OnboardingFlow>,
    /// The upstream scope strings.
    pub scopes: ProviderScopes,
    /// The transport mechanisms.
    pub transport_mechanisms: Vec<TransportMechanism>,
    /// The client type.
    pub client_type: ClientType,
    /// The registration mode.
    pub registration: RegistrationMode,
    /// Whether the provider issues a client secret.
    pub issues_client_secret: bool,
    /// Whether refresh is supported.
    pub refresh_supported: bool,
    /// The account verification strategy.
    pub account_verification: Option<AccountVerification>,
}

/// The providers a deployment can onboard.
///
/// The registry is the only place that decides whether a provider exists.
/// A provider that is not in it is refused with an explicit
/// [`UpstreamOAuthError::UnsupportedProvider`], never with a generic
/// failure from somewhere deeper in the flow.
#[derive(Debug, Clone, Default)]
pub struct ProviderRegistry {
    profiles: BTreeMap<String, ProviderProfile>,
}

impl ProviderRegistry {
    /// A registry without providers.
    pub fn new() -> Self {
        Self::default()
    }

    /// The registry of the example descriptors in the repository.
    ///
    /// The examples are deployment templates. Their endpoints and scope
    /// strings are placeholders that a deployment confirms against the
    /// provider's documentation before it enables them.
    pub fn builtin() -> Self {
        let mut registry = Self::new();
        for (provider, document) in EXAMPLE_DESCRIPTORS {
            let profile: ProviderProfile = serde_json::from_str(document).unwrap_or_else(|error| {
                panic!("the example descriptor for {provider} does not parse: {error}")
            });
            registry
                .profiles
                .insert(profile.provider_id.clone(), profile);
        }
        registry
    }

    /// Add a provider.
    ///
    /// The profile is stored even when it is not fully configured: a
    /// deployment must be able to load a half-finished descriptor and get
    /// an explicit "unsupportedRegistration" when it tries to use it,
    /// rather than a load failure it cannot act on.
    pub fn insert(&mut self, profile: ProviderProfile) {
        self.profiles.insert(profile.provider_id.clone(), profile);
    }

    /// Look up a provider.
    pub fn get(&self, provider: &str) -> Option<&ProviderProfile> {
        self.profiles.get(provider)
    }

    /// Look up a provider and check that it is configured well enough.
    pub fn get_validated(&self, provider: &str) -> Result<&ProviderProfile, UpstreamOAuthError> {
        let profile =
            self.profiles
                .get(provider)
                .ok_or_else(|| UpstreamOAuthError::UnsupportedProvider {
                    provider: provider.to_owned(),
                    reason: "this deployment has no profile for it".to_owned(),
                })?;
        profile.validate()?;
        Ok(profile)
    }

    /// The identifiers of the known providers.
    pub fn provider_ids(&self) -> Vec<&str> {
        self.profiles.keys().map(String::as_str).collect()
    }

    /// The number of known providers.
    pub fn len(&self) -> usize {
        self.profiles.len()
    }

    /// Whether the registry knows no provider.
    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }
}
