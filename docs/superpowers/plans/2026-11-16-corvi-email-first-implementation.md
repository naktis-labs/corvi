# Corvi Email-First Implementation Plan

> **For agentic workers:** Use `superpowers:executing-plans` and execute the gates in order. ADRs and checked-in schemas govern over this roadmap; do not silently weaken a security requirement.

**Goal:** Deliver a standalone policy-enforcing mail gateway, then optional OAuth, storage and Kubernetes capabilities, without making optional infrastructure a dependency of basic mail access.

**Architecture:** Extend the existing `mail-core` and I/O-free `mail-policy` crates. Implement IMAP/SMTP and JMAP behind common untrusted mail DTOs; all REST, MCP and SMTP submission paths share identity authorization and disclosure enforcement. Add issuer, provider management and operator as separate authority domains.

**Tech Stack:** Existing Rust workspace, edition 2024, MSRV 1.85, Cargo lockfile; further libraries chosen at implementation and pinned. Use verified TLS, SQLite for single-instance durable state, PostgreSQL for HA, and Kubernetes CRDs for operator state.

**Spec:** `docs/superpowers/specs/2026-11-16-corvi-email-first-design.md`; ADR-0001 through ADR-0015 and the checked-in `api/` schemas are authoritative, with proposed contracts treated as unimplemented.

## Global Constraints

- Preserve `publish = false` and the unset license. Do not create a LICENSE or select one without the owner's decision; no release claiming a chosen license.
- `mail-core` and `mail-policy` already exist. Extend their actual APIs and tests; preserve policy I/O and dependency boundaries enforced by `scripts/check_crate_boundaries.py`.
- ADR-0015 records that GitHub workflow changes require separate permission. Run local checks; do not assume a workflow exists or bypass that boundary.
- Minimal standalone with external client credentials needs no Kubernetes, provider plugin, control plane, external database or telemetry service. Built-in OAuth issuer, durable queue and Tasks require persistent storage.
- Identity grants intersect scope, client, audience, consent, policy and provenance; grants never union across identities. Deny indeterminate security decisions.
- REST `/v1` and MCP `2026-07-28` implement the checked-in seven operations; no extra mutation or thread-browsing endpoint. MRTR applies to MCP send unless a separately authorized unattended grant exists.
- Read (`imap`/`jmap`) and submission (`smtp`/`jmap`/`disabled`) are independent. JMAP is native and never silently falls back. Validate untrusted discovery URLs and never disclose upstream identifiers or tokens.
- All managed workloads, including init containers and bridges, run non-root, with no added capabilities, read-only root, no privilege escalation and RuntimeDefault seccomp. Reject incompatible managed images; no API token by default.
- Existing ADR-0008 through ADR-0015 numbers are occupied. Any new ADR uses the next available number after checking the repository at execution time.

## Review Focus

1. Rebinding an identity or revoking consent must remove old access before new access; test snapshots, caches, subscriptions, Tasks and credentials.
2. Hostile upstream OAuth/JMAP/CIMD URLs, redirects, DNS answers and issuer/account mismatches must not cause SSRF, credential leakage or fallback.
3. A crash during token rotation, queue submission or reparenting must not resurrect grants or duplicate an ambiguous send.
4. Hidden-only mail changes, search results and upstream IDs must not leak through REST/MCP, cache, telemetry or events.
5. Untrusted Kubernetes resources, plugin descriptors and credential templates must not escalate workload, Secret or API authority.

## Task 0: Establish the existing baseline

**Files:** `Cargo.toml`, `Cargo.lock`, `crates/mail-core/`, `crates/mail-policy/`, `scripts/check_crate_boundaries.py`, `scripts/check_doc_links.py`.

- [ ] Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace --all-targets`, `python3 scripts/check_crate_boundaries.py`, and `python3 scripts/check_doc_links.py`; record actual failures before changing code.
- [ ] Inventory existing exports, tests and missing functionality against ADR-0015; retain implemented types and policy semantics rather than recreating them.
- [ ] Add source-contract tests for OpenAPI and every checked-in JSON Schema, including ADR-0007–0014; validate schema syntax and examples without claiming runtime implementation.
- [ ] Re-run the local gate. Commit only changes made for this task; do not add a license or unauthorized workflow.

## Task 1: Configuration and identity boundaries

**Files:** extend `crates/mail-core/`; create `crates/mail-config/` and focused snapshot/auth tests.

- [ ] Test complete versioned snapshots, scoped secret references, last-known-good atomic activation, SIGHUP reload, expiration, revocation and identity/action non-union across multiple mailboxes.
- [ ] Implement validated local YAML and atomic snapshot activation; reject plaintext upstream secrets, invalid bindings and non-loopback plaintext listeners. Preserve the existing `MailIdentity`, `IdentityId`, `Action` and provenance types.
- [ ] Implement externally managed credential validation and explicit identity selection; enforce grant intersection on each call. Run focused tests and the Task 0 gate; commit.

## Task 2: Safe IMAP/SMTP and disclosure foundations

**Files:** extend `crates/mail-policy/src/` and `crates/mail-policy/tests/disclosure.rs`; create `crates/mail-imap/`, `crates/mail-smtp/` and transport fixture tests.

- [ ] Add failing tests for verified TLS, explicit direct/existing-bridge endpoints, time/size bounds, UIDVALIDITY, provenance, sender/envelope enforcement and malformed MIME.
- [ ] Define provider-neutral reader, submitter, change tracker and blob-reader interfaces using `mail-core::NormalizedMessage`; upstream DTOs remain untrusted until policy evaluates them.
- [ ] Replace the existing string-level HTML sanitizer with a parser-based sanitizer, with adversarial malformed HTML, encoded URLs, remote content and secret-link tests; preserve original mail and `RedactedMessage` projection semantics.
- [ ] Complete IMAP/SMTP adapters, fail-closed provenance and policy projection tests. Run `cargo test -p mail-policy` and transport suites plus boundary checks; commit.

## Task 3: Standalone REST/MCP gateway

**Files:** create `crates/mail-api/`, gateway executable/config examples and contract tests; reference `api/openapi.yaml`, `api/mcp-tools.json`, `api/mcp-resources.json`, `docs/spec/mcp.md`.

- [ ] Add failing tests for the seven operations, exact identity selection, distinct per-identity grants, literal search of safe projections, hidden-message side channels, attachment authorization, opaque scoped cursors and typed errors.
- [ ] Implement a single service pipeline: authenticate, select identity, authorize action, validate provenance, filter/project, then serve or submit. Map REST, MCP and SMTP AUTH to it, with verified TLS and no provider RPC per request.
- [ ] Test MCP discovery/headers, resources and reauthorization, private caching, MRTR approval/replay, idempotency, no side effect before approval and `unknown` on ambiguous send. Do not advertise Tasks without durable storage.
- [ ] Write `skills/corvi-mcp/SKILL.md` and examples against the implemented seven tools, resource schemas and passing fixtures; do not imply that skill text grants authorization.
- [ ] Smoke-test a single process with local config, no external services and the checked-in protocol schemas. Run workspace and security gates; commit.

## Task 4: Native JMAP

**Files:** create `crates/mail-jmap/`, JMAP fixtures and conformance tests; reference `docs/adr/0007-native-jmap-transport.md` and `api/mail-transport.schema.json`.

- [ ] Test session HTTPS trust, DNS/redirect/egress restrictions, account selection, core/mail/submission capabilities, token revocation and independent read/submission selection. Explicitly test no protocol fallback.
- [ ] Implement bounded session discovery, JMAP query/get, blob reads, state changes and polling against the shared interfaces. Search only authorized projections; invalidate stale cursors and suppress hidden-only events.
- [ ] Implement validated `Identity/get`, controlled `Email/set` and `EmailSubmission/set`; keep upstream IDs private, preserve `unknown` on ambiguous completion and never blindly retry or switch to SMTP.
- [ ] Run mixed IMAP/JMAP identity, cross-principal, wrong account/identity, missing scope, malicious URL and standalone/no-plugin tests. Test Fastmail interoperability with separately authorized least-privilege read/send credentials when available; report live-test availability rather than inventing evidence. Commit.

## Task 5: Durable state and secret custody

**Files:** create `crates/mail-storage/` with storage conformance tests; reference `docs/adr/0010-storage-and-durability.md` and `api/storage.schema.json`.

- [ ] Define separate grant, provider-connection, mailbox-state, submission, task, audit, secret and optional blob store boundaries; never create operator management SQL as a second source of truth.
- [ ] Test ephemeral feature rejection, SQLite WAL crash recovery/permissions/single writer, migrations, separately protected keys, wrong-key failure, revocation-safe restore, 24-hour idempotency where promised and unknown-send recovery.
- [ ] Implement protected SQLite persistence for one instance; implement PostgreSQL transactional leases, refresh rotation and queue ownership for HA behind explicit configuration. Reject SQLite multi-writer/network-share deployments.
- [ ] Test no default inbound raw-mail persistence, opt-in encrypted/retained caches, reauthorization and staged blob cleanup; run backend conformance and restart tests. Commit.

## Task 6: Corvi OAuth authorization and grants

**Files:** create `crates/mail-auth/`, issuer/resource-server tests; reference `docs/adr/0009-corvi-oauth-and-identity-grants.md` and `api/corvi-oauth.schema.json`.

- [ ] Test protected-resource and AS discovery, Authorization Code + PKCE S256, exact redirect/issuer binding, consent, `corvi_mail` authorization details, per-identity scope intersection and confidential administrator-provisioned client credentials.
- [ ] Test CIMD metadata SSRF/redirect/freshness restrictions; keep DCR disabled by default. Reject provider tokens as Corvi tokens, wrong audience/issuer and OAuth tokens at SMTP unless a separately implemented SMTP mode permits them.
- [ ] Implement persistent grants, short-lived tokens, refresh rotation/reuse-family revocation and bounded grant freshness using Task 5; reject enabling the issuer without persistent storage. Support external-issuer-only mode without mandatory built-in issuer.
- [ ] Test consent narrowing/revocation across restart, subscriptions, Tasks and MRTR; run OAuth and standalone dependency gates. Commit.

## Task 7: Interactive upstream OAuth

**Files:** create provider onboarding/token broker modules and tests; reference `docs/adr/0008-interactive-upstream-oauth.md` and `api/upstream-oauth.schema.json`.

- [ ] Test provider-specific registration, scopes, callback restrictions, PKCE/state/issuer binding, account validation, one-time encrypted authenticated remote CLI handoff and replay resistance. Device flow is advertised only where supported.
- [ ] Implement privileged onboarding and separate scoped secret delivery; encrypt recoverable provider refresh tokens, atomically rotate them and surface `needsReauthorization` on unrecoverable crash windows.
- [ ] Test that reconnect cannot silently change mailbox owner, widen grants or log credentials, and that unsupported registration constraints are explicit. Run focused tests and commit.

## Task 8: Provider and control-plane contracts

**Files:** create `crates/mail-admin/`, provider protobuf/contracts and `crates/provider-migadu/` consistent with ADR-0015.

- [ ] Test capability discovery, independent protocol selections, typed unsupported operations, untrusted secret references, snapshot publication/acknowledgment and outage retention.
- [ ] Implement authenticated bounded versioned provider contracts and the capability-gated Migadu adapter; no provider administration or plugin call in the mail request path. Never invent destructive operations or trusted recipient provenance.
- [ ] Run compatibility, outage, standalone-boundary and provider fixture tests; commit.

## Task 9: Managed bridges and policy engines

**Files:** bridge and provider SDK modules, optional policy-engine crates, WIT and OCI release tooling; reference ADR-0004 and ADR-0006.

- [ ] Test that OCI hints never authorize image/runtime/secrets, approved digest and authenticated capabilities agree, bridge readiness precedes publication, and failure affects only attached mailboxes. Existing bridges remain independently configured.
- [ ] Implement managed bridge lifecycle under the mandatory rootless profile; reject root-required or privileged images rather than weakening security.
- [ ] Implement optional sandboxed WASM and mTLS gRPC policy engines that can only restrict local decisions; test timeout, traps and invalid obligations. Verify `-wasm` and `-volume` OCI variants contain identical module bytes but use distinct immutable manifest digests.
- [ ] Run bridge, policy failure, artifact and standalone dependency gates; commit.

## Task 10: Kubernetes ownership and hardened deployment

**Files:** create `crates/mail-operator/`, CRDs, controller tests and deploy fixtures; reference ADR-0011, ADR-0012, ADR-0013, `api/corvi-gateway.schema.json` and `api/mail-resource-ownership.schema.json`.

- [ ] Test required same-namespace `Mailbox.providerRef` and `MailIdentity.mailboxRef`, optional singular `MailProvider.gatewayRef`, no default gateway, invalid explicit refs, management-only providers and suspension.
- [ ] Implement `CorviGateway` workload reconciliation with one owner, no automatic Helm adoption, atomic bounded snapshots and old-access revocation before reparenting. Do not cascade-delete upstream mail, CRDs, grants, Secrets or PVCs.
- [ ] Render and validate gateway, operator, init, plugin and bridge workloads for non-root, read-only root, no capabilities, seccomp and no default token. Isolate operator service account, enforce independently trusted admission/network policy including IPv4/IPv6, and reject arbitrary PodSpec injection.
- [ ] Test SQLite replica restrictions, operator/API outage and last-known-good snapshots, Helm/operator ownership conflicts and recovery after interrupted watches. Commit.

## Task 11: MailCredential admission and connection Secrets

**Files:** implement one `MailCredential` CRD, read-only admission webhook, issuer/reconciler and separate publisher; reference ADR-0014 and `api/generated-connection-secret.schema.json`.

- [ ] Test SMTP default and exactly one protocol shape; scoped nonempty permissions require a bound gateway and identity, while native provider issuance omits permissions and requires verified identity/mailbox granularity.
- [ ] Implement fail-closed, side-effect-free cross-resource admission using fresh capability status; continuously revalidate and revoke on parent or gateway changes. Never auto-convert scoped credentials into native credentials or vice versa.
- [ ] Implement separately authorized Secret publisher with flat protocol-specific keys, safe approved annotations, exact observed endpoints and atomic data replacement. Reject foreign Secret ownership and avoid provider tokens or issuer keys.
- [ ] Test webhook outage/dry-run, stale capabilities, Secret name races, role boundaries, rotation, revocation and no gateway/plugin API token. Commit.

## Task 12: Optional operational features and release gates

**Files:** storage, gateway, observability, operator and release documentation.

- [ ] Implement opt-in durable queue, Tasks and filtered synchronization with reauthorization, fenced ownership, restart recovery and hidden-change suppression; default to no inbound raw-mail storage.
- [ ] Add bounded privacy-preserving telemetry and prove collection failures do not break mail; no raw bodies, credentials, provider URLs or high-cardinality private labels.
- [ ] Run full workspace checks, schema and public API conformance, OAuth, transport, rootless workload, ownership/rebinding, secret custody, crash/recovery and standalone outage gates. Document untested live provider integrations and proposed versus implemented capabilities.
- [ ] Produce compatibility and operations documentation. License and publication remain blocked on the explicit owner decision; do not invent a release authorization or tag before that decision.

## Execution Protocol

For each task write the relevant failing tests first, verify the failure, implement, run focused and workspace checks, and commit only that task's changes. If a task depends on a later feature, test its interface with bounded fixtures and defer end-to-end verification until both are implemented; never claim an unavailable integration passed. Keep decisions within the ADRs and preserve the last-known-good standalone path.
