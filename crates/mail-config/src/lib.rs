//! Standalone configuration snapshots: validation, atomic activation, reload.
//!
//! A snapshot is the complete, versioned description of one gateway
//! deployment. It is parsed from local YAML, validated as a whole, and
//! activated atomically: a candidate either replaces the active snapshot
//! completely or is rejected while the previous generation stays in service.
//!
//! Two rules from the design spec shape this module. First, a snapshot holds
//! **references** to operator-protected secret files, never secret values, so
//! a configuration file can be read, diffed and logged without leaking
//! anything. Second, every identity-scoped decision is made against an
//! explicitly selected identity, so a credential that may act on several
//! identities never gains the union of their permissions.

use std::{
    collections::{HashMap, HashSet},
    fmt,
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
    sync::{Arc, RwLock},
};

use mail_core::{Action, IdentityGrant, IdentityId, MailIdentity, ScopedGrants};
use serde::Deserialize;

pub mod reload;
pub mod secret;

pub use reload::{ReloadError, Reloader};
pub use secret::{SecretError, SecretValue, read_secret_file};

/// Why a snapshot candidate was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// The generation counter was zero, so the snapshot could not be ordered.
    ZeroGeneration,
    /// The listener was not a loopback address, or plaintext was not
    /// explicitly enabled for it.
    InsecureListener,
    /// The snapshot declared no identities.
    NoIdentities,
    /// An identity was malformed or bound to nothing.
    ///
    /// A control character in an address or mailbox is refused here rather
    /// than trimmed: an address reaches SMTP header construction and a
    /// mailbox reaches IMAP command construction, so a newline in either is
    /// an injection vector.
    InvalidIdentityBinding,
    /// Two identities shared one identifier.
    DuplicateIdentity,
    /// Two identities claimed the same address or alias.
    ///
    /// Which of them owns a message addressed there would be undefined, and
    /// identity isolation is a confidentiality boundary, so an ambiguous
    /// binding is refused rather than resolved arbitrarily.
    DuplicateAddress,
    /// A credential had an empty or duplicated identifier.
    DuplicateCredential,
    /// A grant referred to an identity the snapshot does not define.
    UnknownIdentity,
    /// A grant named an action Corvi does not define.
    UnknownAction,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::ZeroGeneration => f.write_str("generation must be greater than zero"),
            ValidationError::InsecureListener => {
                f.write_str("listener must be loopback and plaintext must be explicitly enabled")
            }
            ValidationError::NoIdentities => f.write_str("no identities configured"),
            ValidationError::InvalidIdentityBinding => f.write_str("invalid identity binding"),
            ValidationError::DuplicateIdentity => f.write_str("duplicate identity identifier"),
            ValidationError::DuplicateAddress => {
                f.write_str("two identities claim the same address or alias")
            }
            ValidationError::DuplicateCredential => f.write_str("duplicate credential identifier"),
            ValidationError::UnknownIdentity => {
                f.write_str("grant references an identity the snapshot does not define")
            }
            ValidationError::UnknownAction => f.write_str("grant names an unknown mail action"),
        }
    }
}

impl std::error::Error for ValidationError {}

/// Why an activation attempt failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActivationError {
    /// The candidate was not valid, so the active snapshot was untouched.
    Invalid(ValidationError),
    /// The candidate was not newer than the active snapshot.
    StaleGeneration,
    /// The store's lock was poisoned by a panic in another thread.
    Poisoned,
}

impl fmt::Display for ActivationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ActivationError::Invalid(error) => write!(f, "{error}"),
            ActivationError::StaleGeneration => f.write_str("stale generation"),
            ActivationError::Poisoned => f.write_str("snapshot store lock poisoned"),
        }
    }
}

impl std::error::Error for ActivationError {}

/// A reference to an operator-protected secret file.
///
/// Corvi never accepts a secret value in configuration: the snapshot holds a
/// path, and the value is read from a file the operator controls. An inline
/// value is rejected while deserializing, so a misconfigured file never
/// becomes a snapshot that carries a secret value in memory.
#[derive(Debug, Clone)]
pub struct SecretRef {
    secret: String,
}

impl SecretRef {
    /// The referenced path.
    ///
    /// The only way to construct a `SecretRef` is to deserialize one, and
    /// deserialization rejects anything that is not an absolute `file://`
    /// reference, so the path is always present.
    pub fn path(&self) -> &Path {
        Path::new(
            self.secret
                .strip_prefix("file://")
                .expect("secret reference validated on construction"),
        )
    }
}

impl<'de> Deserialize<'de> for SecretRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            secret: String,
        }

        let raw = Raw::deserialize(deserializer)?;
        let is_file_reference = raw
            .secret
            .strip_prefix("file://")
            .is_some_and(|path| path.len() > 1 && path.starts_with('/'));
        if !is_file_reference {
            return Err(serde::de::Error::custom(
                "secret must be an absolute file:// reference, not an inline value",
            ));
        }
        Ok(SecretRef { secret: raw.secret })
    }
}

/// Actions granted for one identity by one credential.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantConfig {
    identity: String,
    actions: Vec<String>,
}

/// A client credential and the identities it may act on.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialConfig {
    id: String,
    token: SecretRef,
    #[serde(default)]
    expires_at: Option<u64>,
    #[serde(default)]
    grants: Vec<GrantConfig>,
}

/// An untrusted, complete configuration candidate.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    generation: u64,
    listen: SocketAddr,
    allow_loopback_plaintext: bool,
    identities: Vec<MailIdentity>,
    #[serde(default)]
    credentials: Vec<CredentialConfig>,
}

/// A client credential resolved against the active snapshot.
#[derive(Debug)]
pub struct Credential {
    id: String,
    token: SecretRef,
    expires_at: Option<u64>,
    grants: ScopedGrants,
}

impl Credential {
    /// The credential identifier.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Where the credential's secret value lives.
    pub fn token(&self) -> &SecretRef {
        &self.token
    }

    /// Whether the credential is expired at `now` (seconds since the epoch).
    pub fn is_expired(&self, now: u64) -> bool {
        self.expires_at.is_some_and(|expiry| now >= expiry)
    }

    /// The identity-scoped grants this credential carries.
    pub fn grants(&self) -> &ScopedGrants {
        &self.grants
    }

    /// Check a presented secret against the referenced file.
    ///
    /// The comparison is constant time, and a file that cannot be read is a
    /// failure rather than a permissive answer: an unreadable credential
    /// denies access, it never grants it.
    pub fn authenticate(&self, presented: &str) -> Result<bool, SecretError> {
        let stored = read_secret_file(self.token.path())?;
        Ok(secret::constant_time_eq(
            stored.expose().as_bytes(),
            presented.as_bytes(),
        ))
    }
}

/// A candidate that passed local validation.
#[derive(Debug)]
pub struct ValidatedSnapshot {
    snapshot: Snapshot,
    credentials: Vec<Credential>,
}

impl ValidatedSnapshot {
    /// Snapshot generation used to prevent rollback.
    pub fn generation(&self) -> u64 {
        self.snapshot.generation
    }

    /// The validated identities.
    pub fn identities(&self) -> &[MailIdentity] {
        &self.snapshot.identities
    }

    /// The address the gateway listens on.
    pub fn listen(&self) -> SocketAddr {
        self.snapshot.listen
    }

    /// Look up a client credential by identifier.
    pub fn credential(&self, id: &str) -> Option<&Credential> {
        self.credentials.iter().find(|c| c.id == id)
    }

    /// Look up one identity by identifier.
    pub fn identity(&self, id: &IdentityId) -> Option<&MailIdentity> {
        self.snapshot.identities.iter().find(|i| &i.id == id)
    }
}

/// Why an authorized request was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthzError {
    /// The credential is not present in the active snapshot.
    UnknownCredential,
    /// The credential's expiry has passed.
    Expired,
    /// The selected identity is not defined by the active snapshot.
    UnknownIdentity,
    /// The presented secret did not match the credential's secret file, or
    /// the secret file could not be read.
    ///
    /// An unreadable secret file denies access rather than granting it, so
    /// an unreadable credential and a wrong credential are indistinguishable
    /// to the caller.
    InvalidCredential,
    /// The credential does not grant this action on the selected identity.
    NotGranted,
}

impl fmt::Display for AuthzError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthzError::UnknownCredential => f.write_str("unknown credential"),
            AuthzError::Expired => f.write_str("credential expired"),
            AuthzError::UnknownIdentity => f.write_str("unknown identity"),
            AuthzError::InvalidCredential => f.write_str("credential was not authenticated"),
            AuthzError::NotGranted => f.write_str("action not granted for this identity"),
        }
    }
}

impl std::error::Error for AuthzError {}

impl Snapshot {
    /// Parse configuration without activating it.
    pub fn from_yaml(input: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(input)
    }

    /// Parse and validate a snapshot read from a file.
    pub fn from_file(path: &Path) -> Result<Self, ReloadError> {
        let text = std::fs::read_to_string(path).map_err(ReloadError::Read)?;
        Snapshot::from_yaml(&text).map_err(ReloadError::Parse)
    }

    fn validate(self) -> Result<ValidatedSnapshot, ValidationError> {
        if self.generation == 0 {
            return Err(ValidationError::ZeroGeneration);
        }
        if !self.allow_loopback_plaintext || !self.listen.ip().is_loopback() {
            return Err(ValidationError::InsecureListener);
        }
        if self.identities.is_empty() {
            return Err(ValidationError::NoIdentities);
        }
        let mut seen = HashSet::new();
        let mut claimed: HashMap<String, IdentityId> = HashMap::new();
        for identity in &self.identities {
            if IdentityId::from_str(identity.id.as_str()).is_err()
                || identity.mailbox.as_str().trim().is_empty()
                || identity.address.trim().is_empty()
                || has_control_character(identity.mailbox.as_str())
                || has_control_character(&identity.address)
            {
                return Err(ValidationError::InvalidIdentityBinding);
            }
            if !seen.insert(identity.id.clone()) {
                return Err(ValidationError::DuplicateIdentity);
            }
            for address in std::iter::once(&identity.address).chain(identity.aliases.iter()) {
                if has_control_character(address) {
                    return Err(ValidationError::InvalidIdentityBinding);
                }
                let key = address.trim().to_ascii_lowercase();
                if key.is_empty() {
                    continue;
                }
                match claimed.insert(key, identity.id.clone()) {
                    Some(owner) if owner != identity.id => {
                        // Two identities claim one address, so which of them
                        // owns a message addressed there is undefined.
                        return Err(ValidationError::DuplicateAddress);
                    }
                    Some(_) => {}
                    None => {}
                }
            }
        }
        let mut credential_ids = HashSet::new();
        let mut credentials = Vec::with_capacity(self.credentials.len());
        for config in &self.credentials {
            if config.id.trim().is_empty() {
                return Err(ValidationError::DuplicateCredential);
            }
            if !credential_ids.insert(config.id.clone()) {
                return Err(ValidationError::DuplicateCredential);
            }
            let mut grants = Vec::with_capacity(config.grants.len());
            for grant in &config.grants {
                let identity = IdentityId::from_str(&grant.identity)
                    .map_err(|_| ValidationError::UnknownIdentity)?;
                if !seen.contains(&identity) {
                    return Err(ValidationError::UnknownIdentity);
                }
                let mut actions = Vec::with_capacity(grant.actions.len());
                for action in &grant.actions {
                    actions.push(
                        Action::from_str(action).map_err(|_| ValidationError::UnknownAction)?,
                    );
                }
                grants.push(IdentityGrant::new(identity, actions));
            }
            credentials.push(Credential {
                id: config.id.clone(),
                token: config.token.clone(),
                expires_at: config.expires_at,
                grants: ScopedGrants::new(grants),
            });
        }
        Ok(ValidatedSnapshot {
            snapshot: self,
            credentials,
        })
    }
}

/// Atomically swaps validated configurations in memory.
#[derive(Debug)]
pub struct SnapshotStore {
    active: RwLock<Arc<ValidatedSnapshot>>,
}

impl SnapshotStore {
    /// Validate the initial candidate before accepting requests.
    pub fn new(snapshot: Snapshot) -> Result<Self, ActivationError> {
        let validated = snapshot.validate().map_err(ActivationError::Invalid)?;
        Ok(Self {
            active: RwLock::new(Arc::new(validated)),
        })
    }

    /// Validate and replace the active snapshot only with a newer generation.
    pub fn activate(&self, snapshot: Snapshot) -> Result<(), ActivationError> {
        let candidate = Arc::new(snapshot.validate().map_err(ActivationError::Invalid)?);
        let mut active = self.active.write().map_err(|_| ActivationError::Poisoned)?;
        if candidate.generation() <= active.generation() {
            return Err(ActivationError::StaleGeneration);
        }
        *active = candidate;
        Ok(())
    }

    /// Obtain the active immutable configuration.
    pub fn active(&self) -> Arc<ValidatedSnapshot> {
        self.active
            .read()
            .expect("snapshot store lock poisoned")
            .clone()
    }

    /// Reload the snapshot from a file, keeping the last known good one on
    /// failure.
    ///
    /// This is the action a SIGHUP triggers. The file is read and validated as
    /// a complete replacement; if anything about it is wrong, the previously
    /// activated generation stays in service untouched.
    ///
    /// Returns `true` when a new generation was activated and `false` when
    /// the file was already active, which is what a SIGHUP after an edit that
    /// changed nothing produces. A stale or invalid file is an error, because
    /// an unchanged file is not wrong.
    pub fn reload_from_path(&self, path: &Path) -> Result<bool, ReloadError> {
        let snapshot = Snapshot::from_file(path)?;
        match self.activate(snapshot) {
            Ok(()) => Ok(true),
            Err(ActivationError::StaleGeneration) => Ok(false),
            Err(error) => Err(ReloadError::Activate(error)),
        }
    }

    /// Authenticate a credential and authorize one action against one
    /// explicitly selected identity.
    ///
    /// The presented secret is verified against the credential's secret file
    /// before any grant is consulted, so this method cannot be used to
    /// authorize a principal that was never authenticated. A secret file that
    /// cannot be read denies access rather than granting it.
    ///
    /// The credential's grants are consulted for the selected identity only.
    /// A credential that may act on several identities therefore gains no
    /// permission that any single one of them lacks.
    pub fn authorize(
        &self,
        credential_id: &str,
        presented_secret: &str,
        identity: &IdentityId,
        action: Action,
        now: u64,
    ) -> Result<(), AuthzError> {
        let active = self.active();
        let credential = active
            .credential(credential_id)
            .ok_or(AuthzError::UnknownCredential)?;
        if credential.is_expired(now) {
            return Err(AuthzError::Expired);
        }
        match credential.authenticate(presented_secret) {
            Ok(true) => {}
            Ok(false) | Err(_) => return Err(AuthzError::InvalidCredential),
        }
        if active.identity(identity).is_none() {
            return Err(AuthzError::UnknownIdentity);
        }
        if !credential.grants().permits(identity, action) {
            return Err(AuthzError::NotGranted);
        }
        Ok(())
    }
}

/// Whether a value carries a control character.
///
/// An address reaches SMTP header construction and a mailbox reaches IMAP
/// command construction, so a newline in either is an injection vector rather
/// than a cosmetic problem.
fn has_control_character(value: &str) -> bool {
    value.chars().any(|c| c.is_control())
}

/// Where a reloaded snapshot is read from.
#[derive(Debug, Clone)]
pub struct SnapshotSource {
    path: PathBuf,
}

impl SnapshotSource {
    /// Reference a configuration file.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The referenced path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}
