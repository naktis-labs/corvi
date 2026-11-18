//! Corvi's native JMAP client.
//!
//! ADR-0007 makes JMAP a first-class upstream transport, alongside IMAP and
//! SMTP, rather than a proxy to them. This crate is that transport: it
//! speaks RFC 8620 and RFC 8621 and produces the same untrusted, normalized
//! message model the other adapters produce, so the identity and disclosure
//! policies applied to a message never depend on which protocol delivered
//! it.
//!
//! Four capabilities are implemented, matching `mail-core`'s transport
//! interfaces:
//!
//! - [`reader::JmapReader`] reads mail (`Email/query`, `Email/get`,
//!   `Mailbox/get`) and downloads blobs.
//! - [`reader::JmapChangeTracker`] reports changes (`Email/queryChanges`).
//! - [`submission::JmapSubmitter`] submits mail (`Identity/get`,
//!   `Email/set`, `EmailSubmission/set`).
//! - [`client::JmapClient`] discovers the session and sends method calls.
//!
//! Four rules hold throughout:
//!
//! 1. **Upstream identifiers never become public identifiers.** A JMAP
//!    `accountId`, `Email.id`, `Mailbox.id` or `Identity.id` stays inside the
//!    transport.
//! 2. **Every URL is untrusted.** The session object is written by the
//!    upstream server, so its API, download and event URLs are checked
//!    against the deployment's egress policy before they are used, and every
//!    redirect is checked again ([`trust`]).
//! 3. **There is no protocol fallback.** A JMAP failure is a JMAP failure.
//!    The adapter never silently switches to IMAP or SMTP, because a
//!    fallback would send under a different envelope, from a different
//!    identity, without the checks that just failed.
//! 4. **An ambiguous outcome stays ambiguous.** A submission that was
//!    issued and whose answer was lost is reported as unknown, never as a
//!    failure that invites a retry.
//!
//! See ADR-0007 (native JMAP transport), ADR-0003 (filtering and disclosure)
//! and ADR-0015 (workspace layout).

pub mod client;
pub mod error;
pub mod protocol;
pub mod reader;
pub mod session;
pub mod submission;
pub mod testing;
pub mod transport;
pub mod trust;

pub use client::{Credential, JmapClient};
pub use error::JmapError;
pub use protocol::{JmapRequest, JmapResponse, MethodCall, MethodOutcome};
pub use reader::{JmapChangeTracker, JmapReader};
pub use session::{AccountSelector, CORE, MAIL, SUBMISSION, Session};
pub use submission::JmapSubmitter;
pub use transport::{HttpRequest, HttpResponse, HttpTransport, TransportLimits};
pub use trust::{EgressPolicy, HostResolver, Origin, StaticResolver, SystemResolver, TrustError};
