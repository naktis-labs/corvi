//! The administrator install policy.
//!
//! ADR-0006 section 2 is explicit that OCI metadata is a hint for the
//! deployment controller and never a source of authorization, credentials or
//! executable behaviour. The controller must apply an explicit install policy:
//! an approved repository or digest, an allowed platform, bounded resources,
//! an allowed network, a Pod security policy and consent to every requested
//! secret.
//!
//! [`authorize`] is that decision. It takes the untrusted descriptor and the
//! local policy and returns an [`ApprovedBridge`] - or refuses. There is no
//! path from an annotation or a descriptor to an approved image that does not
//! pass through this function.

use std::fmt;

use crate::descriptor::{
    BridgeDescriptor, BridgeMode, BridgeProtocol, EndpointExposure, ImageReference, Placement,
    SecretClass,
};
use crate::profile::{ProfileError, validate_requirements};

/// What a local administrator allows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallPolicy {
    /// The repositories a bridge image may come from.
    pub allowed_repositories: Vec<String>,
    /// The digests that are approved regardless of their repository.
    pub allowed_digests: Vec<String>,
    /// The secret classes that may be bound.
    pub allowed_secret_classes: Vec<SecretClass>,
    /// The placements that are allowed.
    pub allowed_placements: Vec<Placement>,
    /// The largest number of secret bindings a descriptor may request.
    pub max_secret_inputs: usize,
}

impl InstallPolicy {
    /// A policy that authorizes nothing.
    pub fn deny_all() -> Self {
        Self {
            allowed_repositories: Vec::new(),
            allowed_digests: Vec::new(),
            allowed_secret_classes: Vec::new(),
            allowed_placements: Vec::new(),
            max_secret_inputs: 0,
        }
    }

    /// Whether a repository is allowed.
    pub fn allows_repository(&self, repository: &str) -> bool {
        self.allowed_repositories
            .iter()
            .any(|allowed| allowed == repository)
    }

    /// Whether a digest is allowed.
    pub fn allows_digest(&self, digest: &str) -> bool {
        self.allowed_digests.iter().any(|allowed| allowed == digest)
    }

    /// Whether a secret class may be bound.
    pub fn allows_secret_class(&self, class: SecretClass) -> bool {
        self.allowed_secret_classes.contains(&class)
    }

    /// Whether a placement is allowed.
    pub fn allows_placement(&self, placement: Placement) -> bool {
        self.allowed_placements.contains(&placement)
    }
}

/// A bridge that the local policy approved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedBridge {
    /// How the bridge is operated.
    pub mode: BridgeMode,
    /// The approved image, for a managed bridge.
    pub image: Option<ImageReference>,
    /// The protocols the bridge serves.
    pub protocols: Vec<BridgeProtocol>,
    /// Where the bridge runs.
    pub placement: Placement,
    /// How the endpoint is reachable.
    pub exposure: EndpointExposure,
    /// The approved secret bindings.
    pub secret_inputs: Vec<crate::descriptor::SecretInput>,
}

/// Why a descriptor was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustError {
    /// The image reference is not digest pinned.
    ImageNotDigestPinned,
    /// The image repository is not on the allowlist.
    RepositoryNotAllowed(String),
    /// The secret class is not on the allowlist.
    SecretClassNotAllowed(SecretClass),
    /// The descriptor requests more secret bindings than allowed.
    TooManySecretInputs {
        /// How many bindings were requested.
        count: usize,
        /// The limit.
        limit: usize,
    },
    /// The placement is not on the allowlist.
    PlacementNotAllowed(Placement),
    /// The endpoint exposure is not allowed.
    EndpointExposureNotAllowed(EndpointExposure),
    /// A managed bridge has no image.
    ManagedBridgeWithoutImage,
    /// An existing bridge asks Corvi to run an image.
    ExistingBridgeMustNotRequestAnImage,
    /// The runtime asks for a weaker security profile.
    Profile(ProfileError),
}

impl fmt::Display for TrustError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrustError::ImageNotDigestPinned => {
                write!(formatter, "the image reference is not digest pinned")
            }
            TrustError::RepositoryNotAllowed(repository) => {
                write!(formatter, "the repository {repository} is not allowlisted")
            }
            TrustError::SecretClassNotAllowed(class) => {
                write!(formatter, "the secret class {class:?} is not allowlisted")
            }
            TrustError::TooManySecretInputs { count, limit } => write!(
                formatter,
                "the descriptor requests {count} secret bindings, the limit is {limit}"
            ),
            TrustError::PlacementNotAllowed(placement) => {
                write!(formatter, "the placement {placement:?} is not allowlisted")
            }
            TrustError::EndpointExposureNotAllowed(exposure) => write!(
                formatter,
                "the endpoint exposure {exposure:?} is not allowlisted"
            ),
            TrustError::ManagedBridgeWithoutImage => {
                write!(formatter, "a managed bridge has no approved image")
            }
            TrustError::ExistingBridgeMustNotRequestAnImage => write!(
                formatter,
                "an existing bridge is not provisioned by Corvi and may not request an image"
            ),
            TrustError::Profile(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for TrustError {}

/// Decide whether a descriptor may be provisioned.
///
/// Every reference in the descriptor is a request. This function is the only
/// place where a request becomes an approval, and it refuses anything the
/// local policy does not name.
pub fn authorize(
    descriptor: &BridgeDescriptor,
    policy: &InstallPolicy,
) -> Result<ApprovedBridge, TrustError> {
    // The image is the thing that would run, so it is decided first. An
    // existing bridge is never provisioned by Corvi and may not ask for one.
    let image = match descriptor.runtime.mode {
        BridgeMode::Managed => {
            let reference = descriptor
                .runtime
                .image
                .as_deref()
                .ok_or(TrustError::ManagedBridgeWithoutImage)?;
            let image =
                ImageReference::parse(reference).map_err(|_| TrustError::ImageNotDigestPinned)?;

            // A reference is approved when the administrator named its digest
            // or named the repository it comes from. Nothing else approves it.
            if !policy.allows_digest(image.digest())
                && !policy.allows_repository(image.repository())
            {
                return Err(TrustError::RepositoryNotAllowed(
                    image.repository().to_string(),
                ));
            }
            Some(image)
        }
        BridgeMode::Existing => {
            if descriptor.runtime.image.is_some() {
                return Err(TrustError::ExistingBridgeMustNotRequestAnImage);
            }
            None
        }
    };

    if descriptor.secret_inputs.len() > policy.max_secret_inputs {
        return Err(TrustError::TooManySecretInputs {
            count: descriptor.secret_inputs.len(),
            limit: policy.max_secret_inputs,
        });
    }

    for input in &descriptor.secret_inputs {
        if !policy.allows_secret_class(input.class) {
            return Err(TrustError::SecretClassNotAllowed(input.class));
        }
    }

    if !policy.allows_placement(descriptor.runtime.placement) {
        return Err(TrustError::PlacementNotAllowed(
            descriptor.runtime.placement,
        ));
    }

    // A bridge endpoint that is exposed beyond the loopback interface is an
    // explicit decision, never a default.
    if descriptor.runtime.exposure != EndpointExposure::LoopbackOnly {
        return Err(TrustError::EndpointExposureNotAllowed(
            descriptor.runtime.exposure,
        ));
    }

    validate_requirements(&descriptor.runtime.security).map_err(TrustError::Profile)?;

    Ok(ApprovedBridge {
        mode: descriptor.runtime.mode,
        image,
        protocols: descriptor.protocols.clone(),
        placement: descriptor.runtime.placement,
        exposure: descriptor.runtime.exposure,
        secret_inputs: descriptor.secret_inputs.clone(),
    })
}
