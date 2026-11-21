//! The mandatory rootless profile.
//!
//! ADR-0006 section 3 requires every operator managed bridge to run as an
//! explicitly non-root user with all capabilities dropped, privilege
//! escalation disabled, a read-only root filesystem, the default seccomp
//! profile and no Kubernetes API token. It also requires that unsupported
//! images are rejected rather than run with weaker settings.
//!
//! This module holds both halves of that rule: the profile Corvi enforces,
//! and the check that refuses a runtime which asks for something weaker.

use std::fmt;

use crate::descriptor::SecurityRequirements;

/// The seccomp profile a managed bridge runs with.
pub const SECCOMP_PROFILE: &str = "RuntimeDefault";

/// The user and group a managed bridge runs as.
pub const NON_ROOT_UID: u32 = 65532;

/// The security profile Corvi enforces for a managed bridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnforcedProfile {
    /// The numeric user the bridge runs as.
    pub run_as_user: u32,
    /// The numeric group the bridge runs as.
    pub run_as_group: u32,
    /// Whether all Linux capabilities are dropped.
    pub drop_all_capabilities: bool,
    /// Whether privilege escalation is disabled.
    pub allow_privilege_escalation: bool,
    /// Whether the root filesystem is read-only.
    pub read_only_root_filesystem: bool,
    /// The seccomp profile.
    pub seccomp_profile: String,
    /// Whether a Kubernetes API token is mounted.
    pub api_token_mounted: bool,
}

impl EnforcedProfile {
    /// The mandatory rootless profile.
    pub fn mandatory_rootless() -> Self {
        Self {
            run_as_user: NON_ROOT_UID,
            run_as_group: NON_ROOT_UID,
            drop_all_capabilities: true,
            allow_privilege_escalation: false,
            read_only_root_filesystem: true,
            seccomp_profile: SECCOMP_PROFILE.to_string(),
            api_token_mounted: false,
        }
    }
}

/// Why a runtime was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileError {
    /// The runtime insists on running as root.
    RootRequired,
    /// The runtime insists on running privileged.
    PrivilegedRequested,
    /// The runtime insists on Linux capabilities.
    CapabilitiesRequired(Vec<String>),
    /// The runtime insists on a writable root filesystem.
    WritableRootFilesystem,
    /// The runtime insists on a seccomp profile other than the default.
    NonDefaultSeccomp(Option<String>),
    /// The runtime insists on a Kubernetes API token.
    ApiTokenRequired,
    /// The runtime insists on writing outside the bridge's writable state.
    WritablePathNotAllowed(String),
}

/// The paths a managed bridge may ask to write to.
///
/// ADR-0006 section 3 grants "only the necessary writable state". The
/// allowlist is deliberately small: the bridge's own state directory, which
/// the operator mounts for it.
const ALLOWED_WRITABLE_PATHS: &[&str] = &["/var/lib/corvi"];

/// The system roots a writable path may never touch, even by accident.
///
/// These are refused before the allowlist is consulted, so a later change to
/// the allowlist cannot silently admit a runtime socket directory or a system
/// root.
const FORBIDDEN_WRITABLE_PREFIXES: &[&str] = &[
    "/etc", "/proc", "/sys", "/dev", "/run", "/var/run", "/usr", "/bin", "/sbin", "/lib", "/boot",
    "/root", "/home",
];

/// Whether a requested writable path is inside the bridge's own state.
///
/// A path is refused unless it is exactly an allowlisted directory or below
/// one, is absolute, carries no `..` component, and names no runtime socket.
fn writable_path_allowed(path: &str) -> bool {
    if !path.starts_with('/') || path == "/" {
        return false;
    }
    if path.split('/').any(|component| component == "..") {
        return false;
    }
    if path.ends_with(".sock") || path.contains(".sock/") {
        return false;
    }
    let touches_system_root = FORBIDDEN_WRITABLE_PREFIXES
        .iter()
        .any(|prefix| path == *prefix || path.starts_with(&format!("{prefix}/")));
    if touches_system_root {
        return false;
    }
    ALLOWED_WRITABLE_PATHS
        .iter()
        .any(|allowed| path == *allowed || path.starts_with(&format!("{allowed}/")))
}

impl fmt::Display for ProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProfileError::RootRequired => {
                write!(formatter, "the runtime requires root")
            }
            ProfileError::PrivilegedRequested => {
                write!(formatter, "the runtime requires a privileged container")
            }
            ProfileError::CapabilitiesRequired(capabilities) => write!(
                formatter,
                "the runtime requires the capabilities {capabilities:?}"
            ),
            ProfileError::WritableRootFilesystem => {
                write!(formatter, "the runtime requires a writable root filesystem")
            }
            ProfileError::NonDefaultSeccomp(profile) => write!(
                formatter,
                "the runtime requires the seccomp profile {profile:?} instead of {SECCOMP_PROFILE}"
            ),
            ProfileError::ApiTokenRequired => {
                write!(formatter, "the runtime requires a Kubernetes API token")
            }
            ProfileError::WritablePathNotAllowed(path) => write!(
                formatter,
                "the runtime requires a writable path {path:?}, which the mandatory profile does not allow"
            ),
        }
    }
}

impl std::error::Error for ProfileError {}

/// Check that a runtime asks for nothing weaker than the mandatory profile.
///
/// A descriptor may only make the profile stricter. A request for root, for
/// privileged execution or for capabilities is refused: the answer is never to
/// weaken the profile.
pub fn validate_requirements(requirements: &SecurityRequirements) -> Result<(), ProfileError> {
    if requirements.requires_root {
        return Err(ProfileError::RootRequired);
    }
    if requirements.privileged {
        return Err(ProfileError::PrivilegedRequested);
    }
    if !requirements.required_capabilities.is_empty() {
        return Err(ProfileError::CapabilitiesRequired(
            requirements.required_capabilities.clone(),
        ));
    }
    if !requirements.read_only_root_filesystem {
        return Err(ProfileError::WritableRootFilesystem);
    }
    match requirements.seccomp_profile.as_deref() {
        None | Some(SECCOMP_PROFILE) => {}
        Some(profile) => return Err(ProfileError::NonDefaultSeccomp(Some(profile.to_string()))),
    }
    for path in &requirements.writable_paths {
        if !writable_path_allowed(path) {
            return Err(ProfileError::WritablePathNotAllowed(path.clone()));
        }
    }

    Ok(())
}
