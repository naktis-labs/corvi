//! Corvi's OAuth authorization server and its protected-resource checks.
//!
//! ADR-0009 asks for a complete standards-based OAuth 2.0 authorization
//! flow for Corvi's own clients, with per-identity consent, refresh and
//! revocation, and with a hard separation between three token domains:
//!
//! - **Corvi client-facing tokens** authorize a client to act on specific
//!   mail identities and actions. This crate mints and validates them.
//! - **Upstream provider tokens** connect Corvi to a mail provider. This
//!   crate never accepts one as a Corvi token, and never mints one.
//! - **Management credentials** belong to another audience entirely.
//!
//! The crate holds protocol logic only. There is no HTTP server here: the
//! transport seam is a trait, and the endpoints below are the shapes an
//! HTTP layer would map onto. Nothing in this crate claims to be a running
//! endpoint, an interoperable provider integration or a consent screen.

pub mod cimd;
pub mod client;
pub mod config;
pub mod consent;
pub mod discovery;
pub mod error;
pub mod issuer;
pub mod pkce;
pub mod registry;
pub mod resource;
pub mod store;
pub mod testing;
pub mod tokens;
