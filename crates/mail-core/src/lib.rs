//! Provider-neutral mail types for Corvi.
//!
//! Every upstream adapter (IMAP, SMTP, JMAP) projects into the types in this
//! crate. Nothing here carries provider-specific assumptions, and nothing here
//! talks to a network.
//!
//! The distinction that matters most is between **visible headers** and
//! **trusted delivery metadata**. A `To` header is authored by whoever sent
//! the message; an original envelope recipient recorded by the upstream
//! provider is not. Only the latter can support `verified` identity isolation
//! (ADR-0001 section 4.2, ADR-0003 section 2.1).
//!
//! See ADR-0001 (system architecture) and ADR-0003 (filtering and disclosure
//! policies).

pub mod action;
pub mod classification;
pub mod identity;
pub mod message;

pub use action::{Action, ParseActionError};
pub use classification::{Class, Classification, Confidence, Evidence};
pub use identity::{IdentityId, IsolationMode, MailIdentity, ParseIdentityIdError};
pub use message::{
    Address, AttachmentMeta, Link, MailboxRef, MessageId, NormalizedMessage, Provenance,
    TrustedRecipient,
};
