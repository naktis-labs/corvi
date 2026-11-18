//! Local transport bridges for Corvi.
//!
//! ADR-0006 makes a local transport bridge a first-class, optional provider
//! transport dependency. This crate holds the parts of that contract which are
//! policy, not plumbing:
//!
//! * [`descriptor`] — the typed bridge dependency descriptor and the OCI
//!   annotations that only ever *hint* at a bridge requirement.
//! * [`trust`] — the administrator install policy: an image, runtime or secret
//!   reference inside a descriptor is a request, never a permission.
//! * [`profile`] — the mandatory rootless profile. A runtime that requires root
//!   or privileged capabilities is rejected, never weakened.
//! * [`lifecycle`] — bridge readiness, publication into the gateway
//!   configuration snapshot and failure isolation between mailboxes.
//!
//! No container runtime, Kubernetes client or bridge process is started here:
//! the crate decides *what may run* and *when an endpoint may be published*,
//! and leaves provisioning to a later task.

pub mod descriptor;
pub mod lifecycle;
pub mod profile;
pub mod trust;
