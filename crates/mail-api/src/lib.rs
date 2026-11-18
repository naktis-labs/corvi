//! Corvi's standalone mail gateway.
//!
//! This crate holds one service pipeline and the two protocol adapters that
//! drive it:
//!
//! ```text
//! authenticate -> select identity -> authorize action -> validate
//! provenance -> filter/project -> serve or submit
//! ```
//!
//! The pipeline lives in [`service`]; the REST adapter ([`rest`]) and the MCP
//! adapter ([`mcp`]) are projections over it and contain no business rules of
//! their own. ADR-0005 requires both protocol surfaces to behave identically,
//! and ADR-0003 section 7 requires every disclosure to pass the local policy
//! engine before a byte reaches a caller.
//!
//! Nothing here talks to a provider directly: the gateway reaches mail
//! through the provider-neutral [`upstream::Upstream`] seam, so the policy and
//! authorization gates are the same whether the mail arrived over IMAP, JMAP
//! or a fixture.
//!
//! See ADR-0005 (public mail API), ADR-0003 (filtering and disclosure) and
//! ADR-0015 (workspace layout and the data-plane boundary).

pub mod approval;
pub mod cursor;
pub mod fixture;
pub mod jmap_upstream;
pub mod mcp;
pub mod policy;
pub mod problem;
pub mod rest;
pub mod schema;
pub mod service;
pub mod smtp;
pub mod submission;
pub mod testing;
pub mod time;
pub mod upstream;
pub mod view;

pub use problem::{ErrorCode, Problem};
pub use service::{Caller, Gateway, GatewayBuilder};
pub use upstream::{Upstream, UpstreamError};
