# Corvi capabilities: proposed versus implemented

- **Status:** Implemented scope, stated as of the current worktree
- **Date:** 2026-11-18
- **Scope:** Which capabilities the ADRs propose, which of them the code implements, and what the evidence for each claim is
- **Related:** [Compatibility](compatibility.md), [Operations](operations.md), [ADR-0001](adr/0001-corvi-system-architecture.md)

The ADRs describe a product. This document separates three states that are easy to blur together:

- **Implemented and exercised.** The behaviour exists and a test fails if it breaks.
- **Implemented as logic.** The rules are complete and tested against fixtures, but the component has never met a remote peer, a cluster or a runtime.
- **Not implemented.** The capability is absent, and the code refuses to pretend otherwise.

Nothing in the third state is emulated. Where a proposal cannot be implemented honestly in this environment, the API refuses rather than returns a plausible answer.

## Data plane

| Capability | State | Evidence |
| --- | --- | --- |
| Per-identity, per-permission authorization | Implemented and exercised | `crates/mail-api/tests/security.rs`; permissions never union across identities |
| Disclosure filtering with typed decisions | Implemented and exercised | `crates/mail-policy/tests/disclosure.rs` (the ADR-0003 section 10 suite) |
| Hidden messages indistinguishable from absent ones | Implemented and exercised | `crates/mail-api/tests/security.rs` |
| REST surface matching the checked OpenAPI document | Implemented and exercised | `crates/mail-api/tests/contract.rs`; `scripts/smoke_gateway.py` |
| MCP surface matching the checked tool and resource catalogues | Implemented and exercised | `crates/mail-api/tests/mcp.rs`, `crates/mail-api/tests/contract.rs` |
| Multi-round-trip send approval over MCP | Implemented and exercised | `crates/mail-api/tests/mcp.rs`; the smoke test drives it end to end |
| SMTP AUTH submission listener | Implemented and exercised | `crates/mail-api/tests/smtp.rs`, `crates/mail-smtp/tests/smtp_submission.rs` |
| MIME projection of upstream mail | Implemented and exercised | `crates/mail-imap`, `crates/mail-smtp`, `crates/mail-jmap` |
| IMAP upstream client | Implemented as logic | `crates/mail-imap/tests/imap_session.rs`; no live server |
| SMTP upstream client | Implemented as logic | `crates/mail-smtp/tests/smtp_submission.rs`; no live relay |
| Native JMAP upstream | Implemented as logic | `crates/mail-jmap/tests/conformance.rs` (57 tests); **Fastmail interop untested** |
| JMAP session URLs treated as instructions, not facts | Implemented and exercised | `crates/mail-jmap/src/trust.rs`; scheme, origin allowlist, redirect targets and private-address refusal are checked |
| A definite upstream refusal distinguished from an unknown outcome | Implemented and exercised | `crates/mail-jmap/src/client.rs`; `crates/mail-api` releases the idempotency key only on a definite refusal |
| In-process idempotency: one delivery for concurrent duplicates | Implemented and exercised | `crates/mail-api/tests/operations.rs`; 50 barrier-started rounds, each asserting exactly one delivery |
| Durable, cross-process idempotency | **Not implemented** | The replay table is in memory; `idempotencyDurable` is `false` |
| Upstream identifiers never reaching the caller | Implemented and exercised | `crates/mail-api/tests/jmap.rs` |
| Native JMAP transport as a first-class protocol, not a proxy to IMAP | Implemented as logic | `crates/mail-jmap` implements the JMAP methods directly |

## Identity, storage and secrets

| Capability | State | Evidence |
| --- | --- | --- |
| SQLite durable state with atomic reservation | Implemented and exercised | `crates/mail-storage/tests/conformance.rs` |
| Atomic idempotency-plus-submission reservation | Implemented and exercised | `crates/mail-storage`; the reservation and the submission are one transaction |
| Single-writer exclusion, including after a stale PID file | Implemented and exercised | `crates/mail-storage` |
| Revocation-safe restore | Implemented and exercised | `crates/mail-storage`; an append-only revocation ledger plus a database watermark makes "cannot prove freshness" an explicit refusal |
| Refresh-claim ownership bound to owner and rotation generation | Implemented and exercised | `crates/mail-storage`; two workers cannot both rotate a token |
| Encrypted secret files with restrictive permissions and atomic replacement | Implemented and exercised | `crates/mail-storage/src/secret.rs` |
| PostgreSQL backend | **Not implemented, explicitly refused** | `StorageError::Unsupported` at validation and at open; no emulation by SQLite |
| High availability, cross-replica leases, cross-replica queue ownership | **Not implemented** | `multi_replica` is refused for every backend |
| Secure erasure; KMS-backed key custody | **Not implemented** | The key resolver is a local prototype; the revocation ledger has no compaction and grows without bound |
| Crash durability under power loss | **Not implemented** | The tests prove recovery after a process kill, not after a power cut |

## OAuth and provider onboarding

| Capability | State | Evidence |
| --- | --- | --- |
| Authorization code flow with PKCE S256, exact redirect and issuer binding | Implemented as logic | `crates/mail-auth` (106 tests); no HTTP endpoint exists |
| Consent narrowing to the intersection of requested and allowed scopes | Implemented as logic | `crates/mail-auth` |
| `corvi_mail` authorization details, one per identity, never merged | Implemented as logic | `crates/mail-auth`; the wire shape is checked by `api/oauth/corvi-authorization-details.schema.json` |
| Refresh rotation with reuse detection and family revocation | Implemented as logic | `crates/mail-auth` |
| A provider token never accepted as a Corvi token | Implemented as logic | `crates/mail-auth` |
| OAuth tokens refused at the SMTP submission interface | Implemented as logic | `crates/mail-auth`; no separately implemented SMTP mode permits them yet |
| CIMD metadata restrictions: HTTPS only, no private address, no cross-origin redirect, bounded age | Implemented as logic | `crates/mail-auth`; the fetch is behind a trait and no network call was made |
| Dynamic client registration disabled by default | Implemented as logic | `crates/mail-auth` |
| The built-in issuer refuses to start without persistent storage | Implemented as logic | `crates/mail-auth` |
| External-issuer-only mode without the built-in issuer | Implemented as logic | `crates/mail-auth` |
| Upstream provider onboarding: registration profiles, scope and callback allowlists, account validation | Implemented as logic | `crates/mail-upstream-oauth`; onboarding transactions are encrypted at rest and consumed atomically (exactly once) through SQLite |
| One-time encrypted authenticated handoff, replay and tamper resistant | Implemented as logic | `crates/mail-upstream-oauth`; redemption requires a durable one-time-use guard backed by SQLite and releases a payload exactly once across handles and restarts; a tampered envelope burns nothing |
| Provider refresh tokens encrypted at rest and rotated as a compare-and-swap | Implemented as logic | `crates/mail-upstream-oauth`; recovery is a pure diagnostic — coherent state is recoverable, outstanding or ambiguous states require reconciliation or reauthorization and are never mutated by recovery |
| Scoped secret delivery | Implemented as logic | `crates/mail-upstream-oauth`; delivery is exactly-once per connection through a durable claim — two escrows cannot both deliver, a failed write leaves the ticket recoverable, and a crash in-flight requires reauthorization rather than a silent retry |
| Live provider onboarding and device flow | **Not implemented** | No provider HTTP client is available offline; the device flow is advertised only for providers that support it |

## Control plane

| Capability | State | Evidence |
| --- | --- | --- |
| Ownership graph with required, singular and optional references | Implemented as logic | `crates/mail-operator` (80 tests); the rendered fixtures in `deploy/operator/` are compared against the renderer |
| No default gateway: an omitted or dangling reference is an error | Implemented as logic | `crates/mail-operator` |
| A management-only provider cannot own a mailbox | Implemented as logic | `crates/mail-operator` |
| Suspension invalidates dependents and stops reconciliation | Implemented as logic | `crates/mail-operator` |
| Reparenting revokes the old access before publishing the new one, and never cascade-deletes | Implemented as logic | `crates/mail-operator` |
| Workload rendering with the mandatory hardening profile | Implemented as logic | `crates/mail-operator`; non-root, read-only root, no added capabilities, seccomp, no default service-account token |
| SQLite gateways limited to one replica | Implemented as logic | `crates/mail-operator` |
| Last-known-good configuration retained when the operator or API is unavailable | Implemented as logic | `crates/mail-operator` |
| A Kubernetes controller, an admission webhook server, real Secret writes, enforced network policy | **Not implemented** | There is no cluster client in the workspace; the decision logic and the rendered fixtures are what exist |
| Credential admission: one protocol shape, scoped or native, non-empty permissions, fail-closed and side-effect-free | Implemented as logic | `crates/mail-credential` (61 tests) |
| Continuous revalidation when a parent changes or is suspended | Implemented as logic | `crates/mail-credential` |
| Secret publication with flat protocol keys, approved annotations and atomic replacement | Implemented as logic | `crates/mail-credential` |
| A foreign Secret is never overwritten; a name race fails closed | Implemented as logic | `crates/mail-credential` |
| No provider token, issuer key or plugin API token in a published Secret | Implemented and exercised | `crates/mail-credential` |
| Provider capability advertisement bound to the protobuf vocabulary | Implemented and exercised | `crates/mail-admin` (38 tests), `crates/provider-migadu` |
| Snapshot publication separated from the provider surface, with a SHA-256 digest | Implemented as logic | `crates/mail-admin`; `api/config/v1/config.proto` is a separate trust domain |
| A gRPC provider service with mTLS | **Not implemented** | The `.proto` files are contracts; there is no server, no transport and no plugin runtime |
| The Migadu API itself | **Not implemented** | The adapter's types and failures exist; no request has been sent to Migadu |

## Extensibility and operations

| Capability | State | Evidence |
| --- | --- | --- |
| OCI policy artifact validation: media types, one Wasm layer, digest pinned | Implemented as logic | `crates/mail-policy-engine` |
| Wasm module validation with `wasmparser` | Implemented as logic | `crates/mail-policy-engine`; a module that imports outside the allowlisted ABI is refused |
| A policy engine may only narrow a local decision | Implemented and exercised | `crates/mail-policy-engine` |
| An ALLOW with malformed obligations is an error, not permission | Implemented and exercised | `crates/mail-policy-engine` |
| The `-wasm` and `-volume` release variants share module bytes but not manifest digests | Implemented and exercised | `crates/mail-policy-engine` |
| Real Wasm execution, a gRPC PDP, a container runtime | **Not implemented** | The sandbox host fails closed with an explicit unsupported status; `wasmtime` and `tonic` are unavailable |
| Bridge readiness precedes publication; an OCI hint authorizes nothing | Implemented and exercised | `crates/mail-bridge` (27 tests) |
| A bridge failure affects only its own mailboxes | Implemented and exercised | `crates/mail-bridge` |
| A runtime requiring root or privileged capabilities is rejected | Implemented and exercised | `crates/mail-bridge` |
| A real bridge process | **Not implemented** | No container runtime is available |
| Opt-in durable queue, Tasks and filtered synchronization | Implemented as logic | `crates/mail-queue`; off by default, no inbound raw mail stored by default. Fenced state transitions cannot fence an external send after dispatch; unknown outcomes must not be blindly retried |
| Hidden-change suppression in synchronization | Implemented and exercised | `crates/mail-queue` |
| Bounded, opt-in, privacy-preserving telemetry that never breaks mail | Implemented as logic | `crates/mail-telemetry` (32 tests) |
| A metrics exporter | **Not implemented** | The exporter seam exists; no backend and no scrape endpoint |
| Release gates that report failures and skips separately | Implemented and exercised | `scripts/release_gates.py` |
| Licence, publication, release tags | **Not an owner decision yet** | ADR-0001 section 14; `publish = false` in every manifest |

## How to read this table

"Implemented as logic" is not a weaker claim of correctness; it is a narrower claim of **reach**. The rules are complete and tested. What is missing is a peer to talk to. Where a peer was unavailable, the code refuses rather than guesses, and the refusal is itself tested.
