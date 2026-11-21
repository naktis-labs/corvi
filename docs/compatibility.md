# Corvi compatibility

- **Status:** Implemented scope, stated as of the current worktree
- **Date:** 2026-11-18
- **Scope:** What Corvi interoperates with today, what is exercised by tests, and what is deliberately not connected to anything
- **Related:** [ADR-0001](adr/0001-corvi-system-architecture.md), [ADR-0005](adr/0005-public-mail-api.md), [ADR-0007](adr/0007-native-jmap-transport.md), [Capabilities](capabilities.md), [Operations](operations.md)

This document is deliberately narrow. It says what was **run**, against **what**, and what was **not** run. A capability that has a type, a schema and a test but has never spoken to a remote peer is *implemented logic*, not *verified interoperability*, and it is listed in the second table rather than the first.

## Verified interoperability

| Surface | What it speaks | How it was verified |
| --- | --- | --- |
| Public REST API | HTTP/1.1 JSON, the seven operations of [`api/openapi.yaml`](../api/openapi.yaml) | `crates/mail-api/tests/contract.rs` validates live responses against the OpenAPI schemas; `scripts/smoke_gateway.py` drives a running process over loopback HTTP |
| Public MCP API | JSON-RPC over HTTP, MCP protocol revision `2026-07-28`, seven tools and five resources | `crates/mail-api/tests/mcp.rs`, `crates/mail-api/tests/contract.rs`, and the MCP half of `scripts/smoke_gateway.py`, including the multi-round-trip send approval |
| SMTP AUTH submission listener | SMTP with the AUTH exchange, on a loopback listener | `crates/mail-api/tests/smtp.rs` and `crates/mail-smtp/tests/smtp_submission.rs` |
| Configuration | YAML snapshot and policy documents validated before the listener opens | `crates/mail-config/tests/snapshots.rs`; `--check` in `scripts/smoke_gateway.py` |
| Durable state | SQLite through `rusqlite` | `crates/mail-storage/tests/conformance.rs`, 65 tests over the whole storage surface |
| Provider and configuration contracts | protobuf definitions in `api/provider/v1/` and `api/config/v1/` | `crates/mail-admin/tests/proto_contract.rs` binds the Rust vocabulary to the wire strings; there is no gRPC server and no wire peer |

The **standalone gateway** is the only executable that runs today: `cargo run --bin corvi-gateway` serves REST, MCP and (optionally) SMTP AUTH from one process, against a local snapshot and a local fixture mailbox. The smoke test exercises that process end to end over loopback.

## Implemented logic that has never met a remote peer

These are complete, tested implementations of a protocol's rules, driven by fixtures and transport doubles. None of them has been run against a live server, so no interoperability claim is made for them.

| Area | What is implemented | What is missing for real use |
| --- | --- | --- |
| IMAP upstream ([`crates/mail-imap`](../crates/mail-imap)) | IMAP session, listing, fetch, search and append over `mail-core`'s transport interface | A live IMAP server, TLS negotiation against a real server, and a real provider's folder semantics |
| SMTP upstream ([`crates/mail-smtp`](../crates/mail-smtp)) | SMTP submission, including the AUTH exchange and the response classification | A live SMTP relay and the delivery behaviour of real MTAs |
| Native JMAP ([`crates/mail-jmap`](../crates/mail-jmap)) | Session discovery and validation, account and capability selection, `Mailbox/get`, `Email/query`, `Email/get`, bounded blob download, `Email/queryChanges`, `Identity/get`, `Email/set`, `EmailSubmission/set` | A live JMAP server over HTTPS. **Fastmail interop has not been tested**; the client is written against the protocol, not against a recorded Fastmail session |
| Corvi OAuth issuer ([`crates/mail-auth`](../crates/mail-auth)) | Discovery documents, authorization code with PKCE S256, consent narrowing, `corvi_mail` authorization details, token issuance, refresh rotation with reuse detection, CIMD fetch restrictions, DCR disabled by default | An HTTP endpoint. The protocol logic is transport-agnostic; there is no listener, no consent UI and no real CIMD fetch |
| Upstream provider onboarding ([`crates/mail-upstream-oauth`](../crates/mail-upstream-oauth)) | Provider registration profiles, scope and callback allowlists, PKCE/state binding, encrypted handoff, exactly-once credential delivery, and refresh rotation logic | Guarantees hold per database file (SQLite single-writer); a crash mid-delivery or mid-rotation requires reauthorization, not a silent retry; no live provider HTTP calls or real device flow |
| Provider management ([`crates/provider-migadu`](../crates/provider-migadu), [`crates/mail-admin`](../crates/mail-admin)) | Typed protocol selection, capability advertisement, snapshot publication with a SHA-256 digest, typed failure classes with a deadline | The Migadu API itself, an authenticated gRPC service, mTLS and an OCI plugin runtime |
| Policy engines ([`crates/mail-policy-engine`](../crates/mail-policy-engine)) | OCI artifact validation, `wasmparser`-based module validation, capability allowlisting, the decision and obligations contract, the two-variant release invariant | A WASM runtime. `wasmtime` is not available in this environment, so the host side fails closed with an explicit unsupported status |
| Operator and admission ([`crates/mail-operator`](../crates/mail-operator), [`crates/mail-credential`](../crates/mail-credential)) | The ownership graph, reference resolution, workload rendering and validation, the admission decision, revalidation and Secret publication | A Kubernetes API server. There is no cluster client, no admission webhook server and no real Secret write |
| Local transport bridges ([`crates/mail-bridge`](../crates/mail-bridge)) | Descriptor validation, the administrator install policy, readiness-before-publication, per-mailbox failure isolation, the rootless profile | A container runtime and a real bridge process |

## Deliberately unavailable

These are refused by the code rather than emulated. A caller that reaches for them gets an explicit error.

- **PostgreSQL and high availability.** The PostgreSQL backend is refused at validation and at open (`StorageError::Unsupported`); `multi_replica` is refused for every backend. Transactional leases, refresh rotation across replicas and queue ownership across replicas are **not implemented**. A single SQLite writer is the only supported durable topology.
- **Real metrics export.** The telemetry model, the bounded buffer and the exporter seam exist ([`crates/mail-telemetry`](../crates/mail-telemetry)), but there is no exporter, no scrape endpoint and no metrics backend.
- **Dynamic client registration** is disabled by default and refuses unless explicitly enabled.
- **Release publication.** No licence has been chosen, no crate is published and no tag exists. `scripts/release_gates.py` runs gates; it is not a release authorization (ADR-0001 section 14).

## Compatibility notes for clients

- The MCP endpoint answers only protocol revision `2026-07-28`. Any other revision is refused with the supported list, not with an empty success.
- Attachments are limited to 2 MiB per message (`MCP_ATTACHMENT_LIMIT` in `crates/mail-api/src/mcp.rs`).
- The REST surface and the MCP surface enforce the same authorization: a token that may read one identity may not read another, and permissions never union across identities.
- A hidden message is indistinguishable from a message that does not exist: it is absent from listings, from searches and from direct reads.
- The idempotency key of the standalone gateway is **in memory only** (`idempotencyDurable` is `false` in the status projection). A restart forgets the replay table; a concurrent duplicate is suppressed only within one process.
