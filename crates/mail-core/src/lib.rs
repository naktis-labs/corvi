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
pub mod grant;
pub mod identity;
pub mod message;
pub mod mime;
pub mod testing;
pub mod transport;

pub use action::{Action, ParseActionError};
pub use classification::{Class, Classification, Confidence, Evidence};
pub use grant::{GrantDecision, IdentityGrant, ScopedGrants};
pub use identity::{IdentityId, IsolationMode, MailIdentity, ParseIdentityIdError};
pub use message::{
    Address, AttachmentMeta, Link, MailboxRef, MessageId, NormalizedMessage, Provenance,
    TrustedRecipient,
};
pub use mime::{MimeError, MimeLimits, MimeNode};
pub use transport::{
    BlobContent, BlobReader, BlobRequest, ByteStream, Change, ChangeCursor, ChangeKind, ChangeSet,
    ListQuery, MailChangeTracker, MailReader, MailSubmitter, MessagePage, OutgoingMessage,
    SubmissionReceipt, TransportError, TransportLimits, UntrustedMessage,
};
