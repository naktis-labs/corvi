//! Why a credential was refused, in the words a status condition may use.
//!
//! ADR-0014 section 5.7 fixes the reason vocabulary that a `MailCredential`
//! status may carry. The names here are those names, so a reason printed by
//! the admission webhook, the revalidator and the publisher is the same
//! string in all three places.
//!
//! A reason never carries a secret, a token, an endpoint that contains
//! credentials or mailbox content. It names a condition, not a value.

use std::fmt;

/// The reason a credential request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Reason {
    /// The document declares more than one protocol shape.
    MultipleProtocolShapes,
    /// The document uses the legacy `shape` field, which is not interpreted.
    LegacyShapeField,
    /// The requested protocol is not in the vocabulary.
    UnsupportedProtocolType,
    /// The referenced target, or one of its parents, does not exist.
    InvalidTargetRef,
    /// A referenced resource lives in another namespace.
    CrossNamespaceReference,
    /// The capability status of a referenced resource is not fresh.
    StaleCapabilityStatus,
    /// A dependency could not be read.
    DependencyUnavailable,
    /// A scoped credential was requested from a provider with no gateway.
    GatewayRequiredForScopedCredential,
    /// A gateway-bound credential did not request Corvi permissions.
    MissingGatewayPermissions,
    /// A gateway-bound credential targeted a mailbox instead of an identity.
    GatewayRequiresMailIdentity,
    /// The bound gateway is suspended or not ready.
    GatewayUnavailable,
    /// The provider names a gateway that does not exist.
    InvalidGatewayRef,
    /// The provider cannot issue independently revocable application credentials.
    UnsupportedCredentialIssuance,
    /// The provider or gateway does not serve the requested protocol.
    UnsupportedCredentialType,
    /// The provider cannot isolate the requested target.
    UnsupportedCredentialGranularity,
    /// The target identity is not verified.
    IdentityNotVerified,
    /// A referenced resource is suspended.
    TargetSuspended,
    /// The requested Secret annotation is not approved.
    UnsafeSecretAnnotation,
    /// A parent resource changed after the credential was admitted.
    ParentChanged,
    /// The Secret name is taken by another owner.
    SecretNameConflict,
    /// A migration between two routes has not completed.
    MigrationPending,
    /// Upstream revocation could not be confirmed.
    CredentialRevocationUnconfirmed,
    /// The publisher is not authorized to publish this credential.
    PublisherNotAuthorized,
}

impl Reason {
    /// The wire name of the reason.
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::MultipleProtocolShapes => "MultipleProtocolShapes",
            Self::LegacyShapeField => "LegacyShapeField",
            Self::UnsupportedProtocolType => "UnsupportedProtocolType",
            Self::InvalidTargetRef => "InvalidTargetRef",
            Self::CrossNamespaceReference => "CrossNamespaceReference",
            Self::StaleCapabilityStatus => "StaleCapabilityStatus",
            Self::DependencyUnavailable => "DependencyUnavailable",
            Self::GatewayRequiredForScopedCredential => "GatewayRequiredForScopedCredential",
            Self::MissingGatewayPermissions => "MissingGatewayPermissions",
            Self::GatewayRequiresMailIdentity => "GatewayRequiresMailIdentity",
            Self::GatewayUnavailable => "GatewayUnavailable",
            Self::InvalidGatewayRef => "InvalidGatewayRef",
            Self::UnsupportedCredentialIssuance => "UnsupportedCredentialIssuance",
            Self::UnsupportedCredentialType => "UnsupportedCredentialType",
            Self::UnsupportedCredentialGranularity => "UnsupportedCredentialGranularity",
            Self::IdentityNotVerified => "IdentityNotVerified",
            Self::TargetSuspended => "TargetSuspended",
            Self::UnsafeSecretAnnotation => "UnsafeSecretAnnotation",
            Self::ParentChanged => "ParentChanged",
            Self::SecretNameConflict => "SecretNameConflict",
            Self::MigrationPending => "MigrationPending",
            Self::CredentialRevocationUnconfirmed => "CredentialRevocationUnconfirmed",
            Self::PublisherNotAuthorized => "PublisherNotAuthorized",
        }
    }
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_wire())
    }
}
