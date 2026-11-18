//! The provider connection store: the data plane's own record of how it
//! talks to a provider.
//!
//! ADR-0010 is explicit that this is **not** a provider-management
//! registry. The operator's desired state is a Kubernetes CRD; this store
//! holds the transactional facts of a running connection: which account a
//! connection serves, which capabilities it has, whether it needs
//! reauthorization, and the generation of its refresh credential.
//!
//! The refresh credential itself is not here. It is a secret, so it lives in
//! the [`crate::secret`] custody boundary, and this store holds only the
//! reference to it and the generation that says which one is current.
//!
//! The refresh rotation is single-owner: a worker claims the connection at
//! a generation, and only a claim at the current generation may commit the
//! new credential. Two replicas therefore cannot both refresh, and a crash
//! leaves the connection marked as needing reauthorization rather than
//! silently rotating twice.

use crate::error::{StorageError, StorageResult};

/// Historical refresh-claim interval, retained for API compatibility.
/// Expiry does not authorize takeover of an ambiguous external refresh.
pub const REFRESH_CLAIM_TTL_SECONDS: u64 = 15 * 60;

/// How healthy a connection is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionStatus {
    /// The connection works.
    Active,
    /// The connection works but something is wrong.
    Degraded,
    /// The credential must be reauthorized.
    NeedsReauthorization,
    /// The provider is disconnected.
    Disconnected,
}

impl ConnectionStatus {
    /// The name of the status.
    pub fn as_str(&self) -> &'static str {
        match self {
            ConnectionStatus::Active => "active",
            ConnectionStatus::Degraded => "degraded",
            ConnectionStatus::NeedsReauthorization => "needsReauthorization",
            ConnectionStatus::Disconnected => "disconnected",
        }
    }

    /// Parse a status name.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(ConnectionStatus::Active),
            "degraded" => Some(ConnectionStatus::Degraded),
            "needsReauthorization" => Some(ConnectionStatus::NeedsReauthorization),
            "disconnected" => Some(ConnectionStatus::Disconnected),
            _ => None,
        }
    }
}

/// One provider connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderConnection {
    /// The connection identifier.
    pub connection_id: String,
    /// The provider the connection serves.
    pub provider: String,
    /// The provider-side account the connection reaches.
    pub account_ref: String,
    /// The Corvi identity the connection serves.
    pub identity: String,
    /// The capabilities the connection offers.
    pub capabilities: Vec<String>,
    /// How healthy the connection is.
    pub status: ConnectionStatus,
    /// The generation of the connection's credential.
    pub generation: u64,
    /// When the connection last changed.
    pub updated_at: u64,
}

/// The state of a connection's refresh credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshState {
    /// The connection the credential belongs to.
    pub connection_id: String,
    /// The generation the credential belongs to.
    pub generation: u64,
    /// The reference to the credential in the secret store.
    pub secret_ref: String,
    /// When the credential expires.
    pub expires_at: u64,
    /// Whether the credential must be reauthorized.
    pub needs_reauthorization: bool,
}

/// The provider connection store.
pub trait ProviderConnectionStore {
    /// Store a connection.
    fn put_connection(&self, connection: &ProviderConnection) -> StorageResult<()>;
    /// Look up a connection.
    fn get_connection(&self, connection_id: &str) -> StorageResult<Option<ProviderConnection>>;
    /// List the connections that serve one identity.
    fn list_connections(&self, identity: &str) -> StorageResult<Vec<ProviderConnection>>;
    /// Store the refresh state of a connection.
    fn put_refresh_state(&self, state: &RefreshState) -> StorageResult<()>;
    /// Look up the refresh state of a connection.
    fn get_refresh_state(&self, connection_id: &str) -> StorageResult<Option<RefreshState>>;
    /// Claim the right to refresh a connection.
    ///
    /// The claim succeeds only when the connection is at the expected
    /// generation and no other owner holds the claim of that generation, so
    /// a refresh happens once. A claim of an older generation is stale — the
    /// credential moved on — and does not stop the owner of the current
    /// generation from claiming. An existing claim refuses all subsequent
    /// claims, including those with the same owner name.
    fn claim_refresh(
        &self,
        connection_id: &str,
        generation: u64,
        owner: &str,
    ) -> StorageResult<bool>;
    /// Claim the right to refresh, recording when the claim was acquired.
    ///
    /// The TTL is retained for compatibility but cannot authorize takeover:
    /// a slow worker may still be rotating the credential at the provider.
    /// An abandoned claim requires explicit recovery or reauthorization.
    ///
    /// The default delegates to [`Self::claim_refresh`], which carries no
    /// time: a store that does not implement the clock keeps its own
    /// behavior.
    fn claim_refresh_at(
        &self,
        connection_id: &str,
        generation: u64,
        owner: &str,
        _now: u64,
        _ttl: u64,
    ) -> StorageResult<bool> {
        self.claim_refresh(connection_id, generation, owner)
    }
    /// Commit a refreshed credential.
    ///
    /// The commit succeeds only when the supplied owner still holds the
    /// claim of the generation being committed and the connection is still
    /// at that generation. A worker that holds a claim of an older
    /// generation is stale and cannot commit.
    fn complete_refresh(
        &self,
        connection_id: &str,
        generation: u64,
        owner: &str,
        secret_ref: &str,
        expires_at: u64,
        now: u64,
    ) -> StorageResult<bool>;
    /// Mark a connection as needing reauthorization.
    fn mark_needs_reauthorization(&self, connection_id: &str, now: u64) -> StorageResult<bool>;
    /// Disconnect a connection.
    ///
    /// Disconnecting invalidates the credential, the cached content, the
    /// sync state and the background jobs of that connection.
    fn disconnect(&self, connection_id: &str, now: u64) -> StorageResult<bool>;

    /// Vouch for the durability of this store's records.
    ///
    /// Delivery coordination a restart forgets cannot protect a credential,
    /// so a store that does not vouch is refused before delivery touches
    /// anything. The default refuses: an unknown store must prove it is
    /// durable, not be believed.
    fn vouches_durability(&self) -> bool {
        false
    }

    /// Claim the right to deliver the credential of one connection.
    ///
    /// The claim is one conditional `INSERT` in durable state: the first
    /// caller holds it, and every other caller is told whether a delivery
    /// is in flight or the credential was already delivered. The claim
    /// survives a restart. A delivery that fails releases it; an abandoned
    /// one requires explicit recovery or reauthorization.
    fn claim_delivery(
        &self,
        _connection_id: &str,
        _owner: &str,
        _now: u64,
    ) -> StorageResult<DeliveryClaim> {
        Err(StorageError::Unsupported(
            "durable delivery claims are unsupported".to_owned(),
        ))
    }

    /// Complete a held delivery claim, permanently.
    ///
    /// The completion succeeds only for the caller that holds the claim,
    /// so a delivered credential is recorded exactly once.
    fn complete_delivery(
        &self,
        _connection_id: &str,
        _owner: &str,
        _now: u64,
    ) -> StorageResult<()> {
        Err(StorageError::Unsupported(
            "durable delivery claims are unsupported".to_owned(),
        ))
    }

    /// Release a held delivery claim after a failed delivery attempt.
    ///
    /// The release succeeds only for the caller that holds the claim, so a
    /// failed delivery never frees the connection for a delivery it did
    /// not make.
    fn release_delivery(&self, _connection_id: &str, _owner: &str) -> StorageResult<()> {
        Err(StorageError::Unsupported(
            "durable delivery claims are unsupported".to_owned(),
        ))
    }

    /// Read the state of a connection's delivery record, without touching it.
    ///
    /// `None` means the connection was never delivered through the durable
    /// path. Recovery reads this to report an in-flight delivery honestly.
    fn delivery_claim_state(&self, _connection_id: &str) -> StorageResult<Option<DeliveryClaim>> {
        Err(StorageError::Unsupported(
            "durable delivery claims are unsupported".to_owned(),
        ))
    }

    /// Read the owner of a connection's outstanding refresh claim, without
    /// touching it.
    ///
    /// `None` means no refresh claim is held. Recovery reads this to
    /// report an in-flight or abandoned rotation honestly; taking or
    /// releasing the claim from recovery would mutate a connection that
    /// may still be in flight.
    fn refresh_claim_owner(&self, _connection_id: &str) -> StorageResult<Option<String>> {
        Err(StorageError::Unsupported(
            "refresh claim reads are unsupported".to_owned(),
        ))
    }
}

/// What a durable delivery claim answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryClaim {
    /// The caller now holds the connection's delivery claim.
    Won,
    /// Another delivery holds the claim and has not finished.
    InProgress,
    /// The credential of the connection was already delivered.
    Delivered,
}
