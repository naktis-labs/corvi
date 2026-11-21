//! The one-time authorization transaction.
//!
//! ADR-0008 section 2.A step 2 says that Corvi "generates one-time
//! unguessable `state`, fresh PKCE `code_verifier`/`S256` challenge and
//! optionally OIDC `nonce`, binds them to the authenticated onboarding
//! principal, provider issuer, intended local account, client ID, exact
//! redirect URI, scope request and short expiry. Securely persist this
//! transaction before redirecting."
//!
//! So the transaction is the unit of binding: everything the callback is
//! checked against lives in it, and the transaction is consumed exactly
//! once. A second callback with the same state finds nothing, which is
//! what makes a replayed callback harmless.
//!
//! The transaction holds the code verifier, so it is a secret. The
//! in-memory store keeps it in the process; the encrypted store keeps it
//! in the secret store, where it belongs in a deployment that survives a
//! restart.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use mail_storage::crypto::{Cipher, derive_key};
use mail_storage::sqlite::SqliteStore;
use std::sync::Mutex;

#[cfg(test)]
mod debug_redaction {
    //! A store that is printed must not print the one-time capabilities it
    //! keeps.

    use super::*;

    fn transaction(state: &str) -> OnboardingTransaction {
        OnboardingTransaction {
            transaction_id: "txn-1".to_owned(),
            connection_id: "conn-1".to_owned(),
            provider: "gmail".to_owned(),
            issuer: "https://provider.example".to_owned(),
            client_id: "the-client".to_owned(),
            redirect_uri: "http://127.0.0.1:8400/callback".to_owned(),
            code_verifier: "the-code-verifier-SECRET".to_owned(),
            code_challenge: "the-challenge".to_owned(),
            state: state.to_owned(),
            nonce: "the-nonce".to_owned(),
            scopes: Vec::new(),
            capabilities: Vec::new(),
            expected_account: "acct-1".to_owned(),
            identity: "identity-1".to_owned(),
            principal: "owner-1".to_owned(),
            principal_roles: Vec::new(),
            issued_at: 0,
            expires_at: 600,
        }
    }

    #[test]
    fn the_memory_store_prints_no_state_and_no_verifier() {
        let store = MemoryTransactionStore::new();
        store
            .insert(&transaction("the-one-time-state-SECRET"))
            .expect("the transaction is stored");
        let printed = format!("{store:?}");
        for secret in ["the-one-time-state-SECRET", "the-code-verifier-SECRET"] {
            assert!(!printed.contains(secret), "leaked {secret}: {printed}");
        }
    }
}

use serde::{Deserialize, Serialize};

use crate::error::UpstreamOAuthError;
use crate::scope::Capability;

/// The longest lifetime of an authorization transaction.
pub const MAX_TRANSACTION_TTL_SECONDS: u64 = 900;

/// The secret-store namespace the encrypted store writes to.
pub const TRANSACTION_STORE_OWNER: &str = "upstream-oauth-transaction";

/// A pending upstream authorization.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnboardingTransaction {
    /// The identifier of the transaction, for audit and logs.
    pub transaction_id: String,
    /// The connection this transaction will create.
    pub connection_id: String,
    /// The provider the transaction is for.
    pub provider: String,
    /// The issuer the transaction is bound to.
    pub issuer: String,
    /// The client the transaction is bound to.
    pub client_id: String,
    /// The exact callback the transaction is bound to.
    pub redirect_uri: String,
    /// The PKCE verifier. A secret until the token exchange.
    pub code_verifier: String,
    /// The S256 challenge of the verifier.
    pub code_challenge: String,
    /// The one-time state the callback must present.
    pub state: String,
    /// The nonce, when the provider uses one.
    pub nonce: String,
    /// The scope strings that were requested.
    pub scopes: Vec<String>,
    /// The capabilities that were requested.
    pub capabilities: Vec<Capability>,
    /// The upstream account the operator expects.
    pub expected_account: String,
    /// The Corvi identity the connection will serve.
    pub identity: String,
    /// The principal that started the onboarding.
    pub principal: String,
    /// The roles the principal held when it started the onboarding.
    pub principal_roles: Vec<crate::onboarding::OnboardingRole>,
    /// When the transaction was created.
    pub issued_at: u64,
    /// When the transaction stops being usable.
    pub expires_at: u64,
}

impl fmt::Debug for OnboardingTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OnboardingTransaction")
            .field("transaction_id", &self.transaction_id)
            .field("provider", &self.provider)
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .field("code_verifier", &"[redacted]")
            .field("code_challenge", &self.code_challenge)
            .field("state", &"[redacted]")
            .field("nonce", &"[redacted]")
            .field("scopes", &self.scopes)
            .field("capabilities", &self.capabilities)
            .field("expected_account", &self.expected_account)
            .field("identity", &self.identity)
            .field("principal", &self.principal)
            .field("principal_roles", &self.principal_roles)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl OnboardingTransaction {
    /// Whether the transaction is past its expiry.
    pub fn is_expired(&self, now: u64) -> bool {
        self.expires_at <= now
    }
}

/// Where the pending authorizations live.
///
/// The store is single use: [`TransactionStore::take`] hands a transaction
/// over at most once. An implementation that cannot promise that is not a
/// transaction store, because a replayed callback would then be able to
/// exchange a second code.
pub trait TransactionStore: fmt::Debug {
    /// Keep a transaction.
    fn insert(&self, transaction: &OnboardingTransaction) -> Result<(), UpstreamOAuthError>;
    /// Consume the transaction behind a state.
    ///
    /// The second call with the same state finds nothing.
    fn take(&self, state: &str) -> Result<Option<OnboardingTransaction>, UpstreamOAuthError>;
}

/// A store that keeps the transactions in memory.
///
/// A printed store names neither the states nor the transactions it keeps:
/// the state is the one-time binder of a callback, and the transaction
/// holds the verifier.
#[derive(Default)]
pub struct MemoryTransactionStore {
    transactions: Mutex<BTreeMap<String, OnboardingTransaction>>,
}

impl fmt::Debug for MemoryTransactionStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let pending = self
            .transactions
            .lock()
            .map(|transactions| transactions.len())
            .unwrap_or_default();
        f.debug_struct("MemoryTransactionStore")
            .field("pending", &pending)
            .finish_non_exhaustive()
    }
}

impl MemoryTransactionStore {
    /// A store without transactions.
    pub fn new() -> Self {
        Self::default()
    }
}

impl TransactionStore for MemoryTransactionStore {
    fn insert(&self, transaction: &OnboardingTransaction) -> Result<(), UpstreamOAuthError> {
        let mut transactions =
            self.transactions
                .lock()
                .map_err(|_| UpstreamOAuthError::Storage {
                    reason: "the transaction store lock is poisoned".to_owned(),
                })?;
        transactions.insert(transaction.state.clone(), transaction.clone());
        Ok(())
    }

    fn take(&self, state: &str) -> Result<Option<OnboardingTransaction>, UpstreamOAuthError> {
        let mut transactions =
            self.transactions
                .lock()
                .map_err(|_| UpstreamOAuthError::Storage {
                    reason: "the transaction store lock is poisoned".to_owned(),
                })?;
        Ok(transactions.remove(state))
    }
}

/// The stored form of a transaction, with its one-time marker.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredTransaction {
    transaction: OnboardingTransaction,
    consumed: bool,
}

/// A store that keeps the transactions in the secret store.
///
/// The verifier is encrypted, but the underlying secret store has no atomic
/// consume operation. Taking a transaction therefore fails closed without
/// modifying it until durable single-use consumption is available.
pub struct EncryptedTransactionStore {
    sqlite: Arc<SqliteStore>,
}

impl fmt::Debug for EncryptedTransactionStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedTransactionStore")
            .finish_non_exhaustive()
    }
}

impl EncryptedTransactionStore {
    /// A store that consumes atomically in the given SQLite database.
    ///
    /// The store vouches for durability itself: an in-memory database is
    /// refused, because a transaction that a restart forgets would redeem
    /// twice.
    pub fn over(sqlite: Arc<SqliteStore>) -> Result<Self, UpstreamOAuthError> {
        sqlite
            .vouches_durability()
            .then_some(())
            .ok_or_else(|| UpstreamOAuthError::Storage {
                reason: "the transaction store must be durable".to_owned(),
            })?;
        Ok(Self { sqlite })
    }

    /// The context an envelope is bound to.
    ///
    /// The context is fixed rather than taken from the transaction, because
    /// the envelope has to be readable before its contents are known. It
    /// still binds the envelope to its state, so a transaction cannot be
    /// moved to another state and read there.
    fn aad(state: &str) -> mail_storage::SecretAad {
        mail_storage::SecretAad {
            provider: "upstream-oauth".to_owned(),
            connection: state.to_owned(),
            kind: "onboardingTransaction".to_owned(),
            owner: "onboarding".to_owned(),
        }
    }
}

impl TransactionStore for EncryptedTransactionStore {
    fn insert(&self, transaction: &OnboardingTransaction) -> Result<(), UpstreamOAuthError> {
        let plaintext = serde_json::to_vec(&StoredTransaction {
            transaction: transaction.clone(),
            consumed: false,
        })
        .map_err(|_| UpstreamOAuthError::Storage {
            reason: "the transaction cannot be encoded".to_owned(),
        })?;
        let key = derive_key(
            TRANSACTION_WRAPPING_KEY,
            &salt(&transaction.state),
            &info(&transaction.state),
        )?;
        let (nonce, ciphertext) = Cipher::new(&key)?.seal(
            &plaintext,
            &Self::aad(&transaction.state).to_bytes(&transaction.state, "k1", 1),
        )?;
        self.sqlite
            .put_onboarding_transaction(&transaction.state, &nonce, &ciphertext)
            .map_err(|error| UpstreamOAuthError::Storage {
                reason: error.to_string(),
            })?;
        Ok(())
    }

    fn take(&self, state: &str) -> Result<Option<OnboardingTransaction>, UpstreamOAuthError> {
        let key = derive_key(TRANSACTION_WRAPPING_KEY, &salt(state), &info(state))?;
        self.sqlite
            .consume_onboarding_transaction(state)
            .map_err(|error| UpstreamOAuthError::Storage {
                reason: error.to_string(),
            })?
            .map(|(nonce, ciphertext)| {
                let plaintext = Cipher::new(&key)?.open(
                    &nonce,
                    &ciphertext,
                    &Self::aad(state).to_bytes(state, "k1", 1),
                )?;
                let document: StoredTransaction =
                    serde_json::from_slice(&plaintext).map_err(|_| {
                        UpstreamOAuthError::Storage {
                            reason: "the stored transaction is not readable".to_owned(),
                        }
                    })?;
                Ok(document.transaction)
            })
            .transpose()
    }
}

/// The wrapping key of the transaction envelopes.
const TRANSACTION_WRAPPING_KEY: &[u8] = b"onboarding-transaction-wrapping-key";

/// The derivation salt of one state's key.
fn salt(state: &str) -> Vec<u8> {
    format!("corvi-onboarding-transaction/{state}").into_bytes()
}

/// The derivation info of one state's key.
fn info(state: &str) -> Vec<u8> {
    format!("corvi-onboarding-transaction-key/{state}").into_bytes()
}

#[cfg(test)]
mod encrypted_fail_closed_tests {
    use super::*;
    #[test]
    fn in_memory_store_is_refused_at_construction() {
        let sqlite = Arc::new(SqliteStore::open_in_memory().unwrap());
        assert!(EncryptedTransactionStore::over(sqlite).is_err());
    }
}
