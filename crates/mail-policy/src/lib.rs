//! Corvi's disclosure filter engine.
//!
//! This crate implements the disclosure gate described in ADR-0003: it turns
//! a normalized message plus the applicable filter policies into a typed
//! decision, and turns that decision into the only message projection a
//! scoped caller is allowed to see.
//!
//! The engine is deliberately free of I/O. It has no Kubernetes client, no
//! provider plugin and no network calls, because ADR-0003 section 7 requires
//! the data plane to evaluate policy locally from its active configuration
//! snapshot even while the control plane and provider plugins are offline.
//!
//! ```text
//! let decision = policy.evaluate(&message);
//! if decision.permits_disclosure() {
//!     let projection = apply_redactions(&message, &decision);
//!     // serve the projection, never the original
//! }
//! ```

pub mod classify;
pub mod decision;
pub mod engine;
pub mod html;
pub mod pattern;
pub mod rule;

pub use decision::{
    AttachmentAccess, Decision, DefaultVisibility, ExternalLinkPolicy, HtmlRendering, MatchedRule,
    OnIndeterminate, RedactableField, Redaction, RemoteContent, Rendering, Visibility,
};
pub use engine::{FilterPolicy, MatchOutcome, RedactedMessage, apply_redactions};
pub use rule::{BooleanOp, Predicate, Rule, RuleEffect, SubjectField, TextMatch, TextPredicate};
