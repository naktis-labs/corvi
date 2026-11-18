//! Optional policy decision engines for Corvi.
//!
//! ADR-0004 makes policy evaluation pluggable: a built-in local evaluator stays
//! the default, while sandboxed WebAssembly modules and external gRPC PDPs may
//! only *restrict* what the local evaluator already decided. This crate holds
//! the parts of that contract which can be implemented honestly:
//!
//! * [`contract`] — the typed decision and obligation vocabulary, the
//!   data-minimised request type and the restriction invariant.
//! * [`engine`] — the sandbox seam: a [`engine::ModuleHost`] trait, a
//!   fail-closed default host and the evaluation contract (timeouts, traps,
//!   invalid obligations).
//! * [`oci`] — OCI policy artifact validation (native Wasm layout, dual
//!   `-wasm`/`-volume` release variants, digest pinning, import allowlisting).
//!
//! What this crate deliberately does **not** contain: a WebAssembly runtime, a
//! gRPC PDP transport or a registry client. Those need a runtime and a network
//! that this build does not have, so the corresponding seams fail closed with
//! an explicit status instead of pretending to work.

pub mod contract;
pub mod engine;
pub mod oci;
