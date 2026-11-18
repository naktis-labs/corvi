//! Interactive upstream provider OAuth: onboarding, handoff and refresh.
//!
//! ADR-0008 describes what this crate is for: a user or an authorized
//! administrator chooses a provider and an account, consents **at the
//! provider's own authorization server**, and Corvi exchanges the result
//! into a protected upstream connection. The user never pastes a password
//! and never hands Corvi a provider token it made itself.
//!
//! The crate is the **protocol and policy** half of that. It knows:
//!
//! - what a provider supports, and refuses a provider it does not know
//!   with an explicit status instead of a generic error
//!   ([`profile`], [`scope`], [`callback`]);
//! - how an authorization code flow with PKCE is built and finished, and
//!   how a device grant is polled ([`flow`], [`pkce`]);
//! - how a transaction binds the principal, the issuer, the client, the
//!   callback, the scopes and the expected account, and how it is consumed
//!   exactly once ([`transaction`]);
//! - how a companion CLI hands a credential to a remote controller without
//!   putting it in a URL, a log or a clipboard ([`handoff`]);
//! - who may onboard an account and who may take the credential into the
//!   secret store — two separate authorizations, never one ([`onboarding`],
//!   [`token_broker`]);
//! - how a refresh credential is encrypted at rest, rotated atomically and
//!   turned into `needsReauthorization` when it cannot be recovered
//!   ([`token_broker`]);
//! - what a reconnection may not change ([`reconnect`]).
//!
//! What this crate is **not**:
//!
//! - It performs **no network I/O**. The transport is a seam
//!   ([`transport`]); the fixture in [`testing`] answers instead of a
//!   provider. There is no TLS stack and no HTTP client here, so no
//!   interoperability with a real provider is claimed.
//! - It is **not** Corvi's own OAuth server. That is ADR-0009 and a
//!   different crate. A provider token is never accepted as a Corvi token.
//! - It does **not** implement the device grant against a live provider,
//!   nor any IMAP or SMTP probe: the device flow and the account
//!   validation are seams that a deployment fills in.
//!
//! The crate holds no credential of its own. Provider credentials live in
//! the secret store of [`mail_storage`], and the refresh rotation uses the
//! provider connection store of the same crate, so there is one refresh
//! state and one source of truth.

pub mod callback;
pub mod clock;
pub mod error;
pub mod flow;
pub mod handoff;
pub mod onboarding;
pub mod pkce;
pub mod profile;
pub mod reconnect;
pub mod scope;
pub mod testing;
pub mod token_broker;
pub mod transaction;
pub mod transport;

pub use error::{ConnectionStatus, HandoffFailure, UpstreamOAuthError};
pub use flow::{DevicePoll, ProviderTokens};
pub use handoff::{
    HandoffEnvelope, HandoffLifetime, HandoffPayload, OneTimeUseGuard,
    SingleProcessOneTimeUseGuard, issue_handoff, redeem_handoff,
};
pub use onboarding::{
    AccountValidator, AuthorizationStart, CallbackRequest, ClientSecretResolver, DeliveryEscrow,
    DeliveryReceipt, OnboardingAction, OnboardingAuthorizer, OnboardingOutcome,
    OnboardingPrincipal, OnboardingRequest, OnboardingRole, OnboardingService, RoleAuthorizer,
    ScopedSecretDelivery, SessionAccountValidator, UpstreamAccount,
};
pub use profile::{
    AuthCapabilities, ClientType, ProviderProfile, ProviderRegistry, RegistrationMode,
};
pub use reconnect::{ReconnectRefusal, ReconnectRequest, evaluate_reconnect};
pub use scope::{Capability, ScopeRequest};
pub use token_broker::{RecoveryOutcome, RotationOutcome, TokenBroker};
pub use transaction::{OnboardingTransaction, TransactionStore};
