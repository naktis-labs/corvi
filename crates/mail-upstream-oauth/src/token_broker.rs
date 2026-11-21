//! The data plane's token broker: the only place a provider credential is
//! stored, rotated and replaced.
//!
//! ADR-0008 section 4 sets the rules this module implements:
//!
//! - "Encrypt access **and refresh** tokens at rest with an explicit
//!   encryption/key-management strategy" — the credential goes into the
//!   secret store, so it is encrypted and it is recoverable.
//! - "Proactively refresh upstream access tokens with bound refresh state,
//!   single-flight/concurrency-safe rotation and atomic persistence
//!   **before** treating the new token as active."
//! - "On `invalid_grant`, denied refresh, revoked grant, account mismatch,
//!   scope loss or missing credential, mark the connection
//!   `needsReauthorization` and fail dependent upstream operations
//!   **closed**."
//!
//! The rotation is a compare-and-swap on the generation: a worker claims
//! the connection at the current generation, and only a claim at that
//! generation may commit the new credential. Two replicas therefore cannot
//! both refresh, and a refresh that is interrupted leaves the connection
//! marked as needing reauthorization rather than silently reusing a token
//! the provider has already invalidated.

use std::sync::Arc;

use mail_storage::crypto::random_bytes;
use mail_storage::{
    ConnectionStatus, DeliveryClaim, ProviderConnection, ProviderConnectionStore, RefreshState,
    SecretAad, SecretRef, SecretStore,
};

use crate::clock::Clock;
use crate::error::UpstreamOAuthError;
use crate::flow::{RefreshExchange, refresh_access_token};
use crate::onboarding::{
    ClientSecretResolver, DeliveryEscrow, DeliveryReceipt, EscrowedCredential, OnboardingAction,
    OnboardingAuthorizer, OnboardingPrincipal, ScopedSecretDelivery,
};
use crate::profile::ProviderRegistry;
use crate::scope::Capability;
use crate::transport::OAuthTransport;

/// The secret store namespace the refresh credentials live in.
pub const REFRESH_SECRET_OWNER: &str = "provider-connection";

/// The kind of the credential, as it is bound into the envelope.
pub const REFRESH_SECRET_KIND: &str = "refreshToken";

/// The context a refresh credential is bound to.
///
/// The envelope is bound to the provider, the connection, the kind and the
/// identity, so a credential copied into another connection does not
/// decrypt there.
pub fn refresh_secret_aad(provider: &str, connection_id: &str, identity: &str) -> SecretAad {
    SecretAad {
        provider: provider.to_owned(),
        connection: connection_id.to_owned(),
        kind: REFRESH_SECRET_KIND.to_owned(),
        owner: identity.to_owned(),
    }
}

/// How a refresh credential is named in the refresh state.
fn secret_ref_string(reference: &SecretRef) -> String {
    format!(
        "{}/{}@{}",
        reference.owner, reference.name, reference.version
    )
}

/// The version a stored credential had when it was committed.
fn committed_version(secret_ref: &str) -> Option<u32> {
    secret_ref
        .rsplit_once('@')
        .and_then(|(_, version)| version.parse().ok())
}

/// What a rotation did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotationOutcome {
    /// The new credential is active.
    Committed {
        /// The new generation of the credential.
        generation: u64,
        /// The reference of the new credential.
        secret_ref: String,
        /// When the access token expires.
        expires_at: Option<u64>,
    },
    /// Another worker owns the rotation, or the generation already moved.
    AlreadyRotated {
        /// The generation the worker saw.
        generation: u64,
    },
}

/// What a recovery check found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryOutcome {
    /// The credential is intact and usable.
    Recoverable {
        /// The generation of the credential.
        generation: u64,
        /// The reference of the credential.
        secret_ref: String,
    },
    /// The credential cannot be recovered and must be reauthorized.
    NeedsReauthorization {
        /// Why it cannot be recovered.
        reason: String,
    },
    /// The connection has no refresh credential at all.
    NoCredential,
}

/// The data plane's token broker.
pub struct TokenBroker {
    connections: Arc<dyn ProviderConnectionStore>,
    secrets: Arc<dyn SecretStore>,
    transport: Arc<dyn OAuthTransport>,
    registry: Arc<ProviderRegistry>,
    authorizer: Arc<dyn OnboardingAuthorizer>,
    client_secrets: Arc<dyn ClientSecretResolver>,
    escrow: Arc<DeliveryEscrow>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for TokenBroker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenBroker").finish_non_exhaustive()
    }
}

impl TokenBroker {
    /// A broker with the given collaborators.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        connections: Arc<dyn ProviderConnectionStore>,
        secrets: Arc<dyn SecretStore>,
        transport: Arc<dyn OAuthTransport>,
        registry: Arc<ProviderRegistry>,
        authorizer: Arc<dyn OnboardingAuthorizer>,
        client_secrets: Arc<dyn ClientSecretResolver>,
        escrow: Arc<DeliveryEscrow>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            connections,
            secrets,
            transport,
            registry,
            authorizer,
            client_secrets,
            escrow,
            clock,
        }
    }

    /// Deliver the credential behind a ticket into the secret store.
    ///
    /// The delivery is durable and exactly once per connection: a claim in
    /// the connection store — one conditional `INSERT` — is held from
    /// before the first write to the permanent delivery record, so two
    /// escrows, two handles or two restarts naming one connection cannot
    /// both write a secret. The connection store must vouch for its own
    /// durability; an in-memory store is refused.
    ///
    /// The write order keeps the credential recoverable on any failure:
    /// the secret is written first, then the refresh state that names it,
    /// then the connection, and the ticket is claimed only after the
    /// delivery record is permanent. A delivery that fails releases its
    /// claim and leaves the ticket unclaimed, so it can be retried; an
    /// abandoned claim requires explicit recovery or reauthorization.
    pub fn deliver(
        &self,
        ticket: &str,
        principal: &OnboardingPrincipal,
    ) -> Result<DeliveryReceipt, UpstreamOAuthError> {
        self.authorizer
            .authorize(principal, OnboardingAction::DeliverScopedSecret)?;
        let now = self.clock.now();
        if !self.connections.vouches_durability() {
            return Err(UpstreamOAuthError::Storage {
                reason: "delivery requires a durable connection store".to_owned(),
            });
        }
        // The credential is read without taking it out: the escrow copy is
        // only claimed once the credential is durable elsewhere, so a
        // delivery that fails before the claim leaves the ticket valid for
        // a retry.
        let Some(credential) = self.escrow.peek(ticket, now)? else {
            return Err(UpstreamOAuthError::InvalidRequest {
                reason: "the delivery ticket is unknown or expired".to_owned(),
            });
        };
        // Exactly one delivery of a connection may write: the claim is the
        // database's decision, not this broker's. The claim's owner is
        // random so that only the delivery that won it may release or
        // complete it.
        let owner = match random_bytes(16) {
            Ok(bytes) => format!("delivery-{}", hex::encode(bytes)),
            Err(error) => {
                return Err(UpstreamOAuthError::Storage {
                    reason: error.to_string(),
                });
            }
        };
        match self
            .connections
            .claim_delivery(&credential.connection_id, &owner, now)
            .map_err(|error| UpstreamOAuthError::Storage {
                reason: error.to_string(),
            })? {
            DeliveryClaim::Won => {}
            DeliveryClaim::InProgress => {
                return Err(UpstreamOAuthError::Storage {
                    reason: "another delivery of this connection is in progress".to_owned(),
                });
            }
            DeliveryClaim::Delivered => {
                return Err(UpstreamOAuthError::Storage {
                    reason: "the credential of this connection was already delivered".to_owned(),
                });
            }
        }
        // From here every failure releases the claim, so the ticket stays
        // recoverable and unclaimed and the connection stays deliverable.
        let receipt = match self.write_credential(&credential, now) {
            Ok(receipt) => receipt,
            Err(error) => {
                let _ = self
                    .connections
                    .release_delivery(&credential.connection_id, &owner);
                return Err(error);
            }
        };
        // The delivery record is permanent before the escrow copy is
        // consumed: from here a second delivery of the connection is
        // refused whatever happens to this process.
        self.connections
            .complete_delivery(&credential.connection_id, &owner, now)
            .map_err(|error| UpstreamOAuthError::Storage {
                reason: error.to_string(),
            })?;
        // The credential is durable and recorded; the escrow copy has no
        // remaining role. A ticket that expired while it was being
        // delivered simply stays behind unread.
        let _ = self.escrow.claim(ticket, now)?;
        Ok(receipt)
    }

    /// Write an escrowed credential into durable storage.
    ///
    /// The order is the recovery story: the secret first — it becomes the
    /// only durable copy of the refresh token while the escrow still holds
    /// its copy — then the refresh state that names it, and the connection
    /// last. An `Active` connection therefore always has a refresh state,
    /// whatever fails or crashes in between.
    fn write_credential(
        &self,
        credential: &EscrowedCredential,
        _now: u64,
    ) -> Result<DeliveryReceipt, UpstreamOAuthError> {
        let Some(refresh_token) = &credential.tokens.refresh_token else {
            return Err(UpstreamOAuthError::Storage {
                reason: "the escrowed credential carries no refresh token".to_owned(),
            });
        };
        let aad = refresh_secret_aad(
            &credential.provider,
            &credential.connection_id,
            &credential.identity,
        );
        let reference = self
            .secrets
            .put(
                REFRESH_SECRET_OWNER,
                &credential.connection_id,
                refresh_token.as_bytes(),
                &aad,
            )
            .map_err(|error| UpstreamOAuthError::Storage {
                reason: error.to_string(),
            })?;
        // A redelivery over an existing row keeps its generation, so the
        // refresh state names the generation the connection is at.
        let generation = self
            .connections
            .get_connection(&credential.connection_id)
            .map_err(|error| UpstreamOAuthError::Storage {
                reason: error.to_string(),
            })?
            .map(|connection| connection.generation)
            .unwrap_or(0);
        self.connections
            .put_refresh_state(&RefreshState {
                connection_id: credential.connection_id.clone(),
                generation,
                secret_ref: secret_ref_string(&reference),
                expires_at: credential.tokens.expires_at.unwrap_or(0),
                needs_reauthorization: false,
            })
            .map_err(|error| UpstreamOAuthError::Storage {
                reason: error.to_string(),
            })?;
        self.connections
            .put_connection(&ProviderConnection {
                connection_id: credential.connection_id.clone(),
                provider: credential.provider.clone(),
                account_ref: credential.expected_account.clone(),
                identity: credential.identity.clone(),
                capabilities: capability_names(&credential.capabilities),
                status: ConnectionStatus::Active,
                generation,
                updated_at: _now,
            })
            .map_err(|error| UpstreamOAuthError::Storage {
                reason: error.to_string(),
            })?;
        Ok(DeliveryReceipt {
            connection_id: credential.connection_id.clone(),
            provider: credential.provider.clone(),
            secret_ref: secret_ref_string(&reference),
            expires_at: credential.tokens.expires_at,
            generation,
        })
    }

    /// Rotate the refresh credential of a connection.
    ///
    /// The rotation is a compare-and-swap on the generation. A worker that
    /// cannot claim the current generation does not talk to the provider at
    /// all, so two workers never exchange the same credential.
    pub fn rotate(
        &self,
        connection_id: &str,
        owner: &str,
    ) -> Result<RotationOutcome, UpstreamOAuthError> {
        let now = self.clock.now();
        let Some(state) = self
            .connections
            .get_refresh_state(connection_id)
            .map_err(|error| UpstreamOAuthError::Storage {
                reason: error.to_string(),
            })?
        else {
            return Err(UpstreamOAuthError::NeedsReauthorization {
                connection_id: connection_id.to_owned(),
                reason: "the connection has no refresh credential".to_owned(),
            });
        };
        if state.needs_reauthorization {
            return Err(UpstreamOAuthError::NeedsReauthorization {
                connection_id: connection_id.to_owned(),
                reason: "the connection is already marked as needing reauthorization".to_owned(),
            });
        }
        let Some(connection) = self
            .connections
            .get_connection(connection_id)
            .map_err(|error| UpstreamOAuthError::Storage {
                reason: error.to_string(),
            })?
        else {
            return Err(UpstreamOAuthError::NeedsReauthorization {
                connection_id: connection_id.to_owned(),
                reason: "the connection is unknown".to_owned(),
            });
        };

        let claimed = self
            .connections
            .claim_refresh(connection_id, state.generation, owner)
            .map_err(|error| UpstreamOAuthError::Storage {
                reason: error.to_string(),
            })?;
        if !claimed {
            return Ok(RotationOutcome::AlreadyRotated {
                generation: state.generation,
            });
        }

        let Some(reference) = self.stored_reference(connection_id)? else {
            self.mark_needs_reauthorization(connection_id, now)?;
            return Err(UpstreamOAuthError::NeedsReauthorization {
                connection_id: connection_id.to_owned(),
                reason: "the refresh credential is missing".to_owned(),
            });
        };
        if let Some(committed) = committed_version(&state.secret_ref)
            && reference.version > committed
        {
            self.mark_needs_reauthorization(connection_id, now)?;
            return Err(UpstreamOAuthError::NeedsReauthorization {
                connection_id: connection_id.to_owned(),
                reason: "a rotation was interrupted before it was committed".to_owned(),
            });
        }

        let aad = refresh_secret_aad(
            &connection.provider,
            &connection.connection_id,
            &connection.identity,
        );
        let Some(plaintext) =
            self.secrets
                .get(&reference, &aad)
                .map_err(|error| UpstreamOAuthError::Storage {
                    reason: error.to_string(),
                })?
        else {
            self.mark_needs_reauthorization(connection_id, now)?;
            return Err(UpstreamOAuthError::NeedsReauthorization {
                connection_id: connection_id.to_owned(),
                reason: "the refresh credential cannot be read".to_owned(),
            });
        };
        let refresh_token =
            String::from_utf8(plaintext).map_err(|_| UpstreamOAuthError::NeedsReauthorization {
                connection_id: connection_id.to_owned(),
                reason: "the refresh credential is not text".to_owned(),
            })?;

        let profile = self.registry.get_validated(&connection.provider)?;
        let endpoints = profile.endpoints.clone().ok_or_else(|| {
            UpstreamOAuthError::UnsupportedRegistration {
                provider: connection.provider.clone(),
                reason: "no endpoints are configured".to_owned(),
            }
        })?;
        let client_secret = self.client_secret(profile)?;
        let tokens = match refresh_access_token(
            self.transport.as_ref(),
            &RefreshExchange {
                token_endpoint: endpoints.token.clone(),
                client_id: profile.client.client_id.clone(),
                client_secret,
                refresh_token,
                scopes: Vec::new(),
            },
            now,
        ) {
            Ok(tokens) => tokens,
            Err(UpstreamOAuthError::InvalidGrant { .. }) => {
                self.mark_needs_reauthorization(connection_id, now)?;
                return Err(UpstreamOAuthError::NeedsReauthorization {
                    connection_id: connection_id.to_owned(),
                    reason: "the provider refused the refresh credential".to_owned(),
                });
            }
            Err(other) => return Err(other),
        };

        let secret_ref_text = match &tokens.refresh_token {
            Some(new_refresh_token) => {
                let reference = self
                    .secrets
                    .put(
                        REFRESH_SECRET_OWNER,
                        connection_id,
                        new_refresh_token.as_bytes(),
                        &aad,
                    )
                    .map_err(|error| UpstreamOAuthError::Storage {
                        reason: error.to_string(),
                    })?;
                secret_ref_string(&reference)
            }
            None => {
                if profile
                    .refresh
                    .as_ref()
                    .is_some_and(|refresh| refresh.expects_rotation())
                {
                    self.mark_needs_reauthorization(connection_id, now)?;
                    return Err(UpstreamOAuthError::NeedsReauthorization {
                        connection_id: connection_id.to_owned(),
                        reason: "the provider rotated the credential away".to_owned(),
                    });
                }
                state.secret_ref.clone()
            }
        };

        let expires_at = tokens.expires_at.unwrap_or_default();
        let committed = self
            .connections
            .complete_refresh(
                connection_id,
                state.generation,
                owner,
                &secret_ref_text,
                expires_at,
                now,
            )
            .map_err(|error| UpstreamOAuthError::Storage {
                reason: error.to_string(),
            })?;
        if !committed {
            self.mark_needs_reauthorization(connection_id, now)?;
            return Err(UpstreamOAuthError::NeedsReauthorization {
                connection_id: connection_id.to_owned(),
                reason: "the rotation could not be committed".to_owned(),
            });
        }

        Ok(RotationOutcome::Committed {
            generation: state.generation + 1,
            secret_ref: secret_ref_text,
            expires_at: tokens.expires_at,
        })
    }

    /// Recovery cannot establish exclusivity with an active or abandoned refresh.
    /// Refuse to assert recoverability without mutating the connection or claim.
    /// Report the recovery state of a connection honestly.
    ///
    /// Recovery reads state and changes nothing: a connection that may
    /// still be in flight — a delivery or a refresh claim that is held —
    /// is reported as requiring reconciliation or reauthorization, and the
    /// claim is left exactly as it was. An ambiguous provider outcome is
    /// never reported as recoverable: a rotation that may have happened is
    /// visible here as the refresh claim its worker still holds.
    ///
    /// The store must vouch for its own durability; an in-memory store is
    /// refused, because recovery over records a restart forgets would be a
    /// guess.
    pub fn recover(&self, connection_id: &str) -> Result<RecoveryOutcome, UpstreamOAuthError> {
        if !self.connections.vouches_durability() {
            return Err(UpstreamOAuthError::Storage {
                reason: "recovery requires a durable connection store".to_owned(),
            });
        }
        // An outstanding delivery claim: the delivery may still be writing,
        // so nothing about this connection may be touched.
        if let Some(DeliveryClaim::InProgress) = self
            .connections
            .delivery_claim_state(connection_id)
            .map_err(|error| UpstreamOAuthError::Storage {
                reason: error.to_string(),
            })?
        {
            return Ok(RecoveryOutcome::NeedsReauthorization {
                reason: "a delivery of this connection is in flight; the outstanding claim must \
                 be reconciled or the connection reauthorized"
                    .to_owned(),
            });
        }
        // An outstanding refresh claim: the rotation may still be running,
        // or it died after the provider saw its request. Either way the
        // credential is in question and the claim stays.
        if self
            .connections
            .refresh_claim_owner(connection_id)
            .map_err(|error| UpstreamOAuthError::Storage {
                reason: error.to_string(),
            })?
            .is_some()
        {
            return Ok(RecoveryOutcome::NeedsReauthorization {
                reason: "a refresh of this connection is in flight; refresh recovery requires \
                 atomic coordination — reconciliation or reauthorization is required"
                    .to_owned(),
            });
        }
        let state = self
            .connections
            .get_refresh_state(connection_id)
            .map_err(|error| UpstreamOAuthError::Storage {
                reason: error.to_string(),
            })?;
        let Some(state) = state else {
            let known = self
                .connections
                .get_connection(connection_id)
                .map_err(|error| UpstreamOAuthError::Storage {
                    reason: error.to_string(),
                })?
                .is_some();
            return Ok(if known {
                RecoveryOutcome::NeedsReauthorization {
                    reason: "the connection has no refresh state".to_owned(),
                }
            } else {
                RecoveryOutcome::NoCredential
            });
        };
        if state.needs_reauthorization {
            return Ok(RecoveryOutcome::NeedsReauthorization {
                reason: "the connection is already marked as needing reauthorization".to_owned(),
            });
        }
        let connection = self
            .connections
            .get_connection(connection_id)
            .map_err(|error| UpstreamOAuthError::Storage {
                reason: error.to_string(),
            })?;
        if let Some(connection) = connection {
            match connection.status {
                ConnectionStatus::NeedsReauthorization | ConnectionStatus::Disconnected => {
                    return Ok(RecoveryOutcome::NeedsReauthorization {
                        reason: format!("the connection is {}", connection.status.as_str()),
                    });
                }
                ConnectionStatus::Active | ConnectionStatus::Degraded => {}
            }
        }
        // A credential in the store that the refresh state does not name is
        // an interrupted rotation: the provider may have seen it, so the
        // credential in use is in question.
        if let Some(reference) = self.stored_reference(connection_id)?
            && let Some(committed) = committed_version(&state.secret_ref)
        {
            if reference.version > committed {
                return Ok(RecoveryOutcome::NeedsReauthorization {
                    reason: "a rotation was interrupted before it was committed; refresh \
                     recovery requires atomic coordination — reconciliation or reauthorization \
                     is required"
                        .to_owned(),
                });
            }
            if reference.version < committed {
                return Ok(RecoveryOutcome::NeedsReauthorization {
                    reason: "the committed credential is missing from the secret store".to_owned(),
                });
            }
        }
        Ok(RecoveryOutcome::Recoverable {
            generation: state.generation,
            secret_ref: state.secret_ref.clone(),
        })
    }

    /// The stored credential of a connection, if there is one.
    fn stored_reference(
        &self,
        connection_id: &str,
    ) -> Result<Option<SecretRef>, UpstreamOAuthError> {
        let references = self.secrets.list(REFRESH_SECRET_OWNER).map_err(|error| {
            UpstreamOAuthError::Storage {
                reason: error.to_string(),
            }
        })?;
        Ok(references
            .into_iter()
            .find(|reference| reference.name == connection_id))
    }

    /// Mark a connection as needing reauthorization.
    fn mark_needs_reauthorization(
        &self,
        connection_id: &str,
        now: u64,
    ) -> Result<(), UpstreamOAuthError> {
        self.connections
            .mark_needs_reauthorization(connection_id, now)
            .map_err(|error| UpstreamOAuthError::Storage {
                reason: error.to_string(),
            })?;
        Ok(())
    }

    /// The client secret of a confidential client, when it has one.
    fn client_secret(
        &self,
        profile: &crate::profile::ProviderProfile,
    ) -> Result<Option<String>, UpstreamOAuthError> {
        let Some(reference) = &profile.client.client_secret_ref else {
            return Ok(None);
        };
        match self.client_secrets.resolve(reference) {
            Ok(secret) => Ok(Some(secret)),
            Err(_) => Err(UpstreamOAuthError::UnsupportedRegistration {
                provider: profile.provider_id.clone(),
                reason: "the configured client secret cannot be read".to_owned(),
            }),
        }
    }
}

impl ScopedSecretDelivery for TokenBroker {
    fn deliver(
        &self,
        ticket: &str,
        principal: &OnboardingPrincipal,
    ) -> Result<DeliveryReceipt, UpstreamOAuthError> {
        TokenBroker::deliver(self, ticket, principal)
    }
}

/// The capabilities a connection records.
pub fn capability_names(capabilities: &[Capability]) -> Vec<String> {
    capabilities
        .iter()
        .map(|capability| capability.as_str().to_owned())
        .collect()
}
