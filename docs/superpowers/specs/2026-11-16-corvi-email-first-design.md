# Corvi Email-First Autonomous Implementation Design

**Contract sources:** ADR-0001 through ADR-0015
(`docs/adr/0001-corvi-system-architecture.md` through
`docs/adr/0015-rust-workspace-and-policy-engine.md`), `api/openapi.yaml`,
`api/mcp-tools.json`, `api/mcp-resources.json`, `api/mail-transport.schema.json`,
and `docs/spec/mcp.md`.

## Intent

Build Corvi as an email-first, provider-neutral mail access broker whose
smallest useful deployment is one standalone gateway process with a local
configuration file and upstream IMAP/SMTP credentials or a native JMAP token.
Applications and agents
receive scoped, revocable access rather than upstream mailbox credentials, and
the gateway enforces identity boundaries and disclosure filtering locally.

The implementation is staged so every phase produces a testable system without
making the control plane, Kubernetes, provider plugins, external policy engines,
an external database, or an observability collector a hidden runtime dependency.

## Goals

- Deliver the ADR-0001 minimal standalone gateway acceptance target first.
- Keep action authorization, identity/provenance boundaries, and disclosure
  filtering as separate gates.
- Make all client-visible projections safe across list, get, search, counts,
  threads, attachments, mutations, events, caches, and exports.
- Implement the proposed shared `/v1` REST and MCP `2026-07-28` contract from
  ADR-0005, with one application service and protocol adapters that cannot
  bypass authorization or filtering.
- Support one credential spanning multiple explicitly granted identities,
  including different physical mailboxes/providers, without unioning grants.
- Provide native JMAP as an optional in-process upstream transport alongside
  IMAP/SMTP, without changing the provider-neutral REST/MCP contract.
- Preserve last-known-good configuration and fail closed on malformed or
  indeterminate security decisions.
- Add optional control-plane, provider, policy-engine, and Kubernetes features
  only through versioned contracts and without putting them on the mail hot path.
- Make the required security and availability invariants executable in CI.

## Non-goals

- SMS, Matrix, Discord, cross-channel routing, or cross-protocol CRDs.
- A public MX server or downstream IMAP server.
- Message flags/move/delete/draft APIs, REST event streams, and cross-identity
  search in the public v1 contract.
- Provider administration in the standalone gateway.
- Treating JMAP as an IMAP/SMTP bridge, provider-management API, or permission
  to expose upstream JMAP identifiers.
- Mandatory Kubernetes, operator, plugin, gRPC PDP, WASM module, database,
  collector, cert-manager, trust-manager, or ServiceMonitor.
- Claiming verified alias isolation from ordinary To/Cc headers.
- Treating heuristic classifiers as proof that a message contains no secret.

## Anti-goals

- Do not query a provider plugin, operator, Kubernetes API, registry, or control
  plane for each mail request.
- Do not let an external policy engine enlarge local credential or identity
  scope, bypass mandatory local filtering, or return rewritten mail content.
- Do not put plaintext credentials, raw message bodies, tokens, or private
  labels in snapshots, logs, metrics, traces, or remote PDP requests.
- Do not silently downgrade verified isolation, TLS, policy safety, or a failed
  required dependency into a permissive mode.

## Settled autonomous decisions

These decisions resolve questions that would otherwise block implementation:

1. **Release shape:** the first release is the standalone email gateway. Later
   subsystems are separate vertical slices, each gated by the baseline tests.
2. **Language/runtime:** use a pinned stable Rust toolchain and a Cargo
   workspace. Use Tokio for async execution, rustls for TLS, serde-based typed
   configuration, Axum for REST, and tonic/prost for later versioned gRPC.
3. **Configuration:** implement local YAML first. Parse and validate a complete
   provider-neutral snapshot, atomically activate it, persist the last-known-good
   revision, and reject malformed/stale/unauthorized replacements without
   disturbing the active revision. Snapshot fields contain credential
   references, never plaintext secrets.
4. **Authorization boundary:** use a transport-neutral internal model of
   principal, credential, action, resource, identity, scope, and request
   context, while keeping IMAP/MIME/sender rules in mail-specific modules.
5. **Isolation:** `verified` requires an explicitly trusted provenance source;
   ordinary generic IMAP has no such source and must fail closed for verified
   policies. `bestEffort` is explicit and non-security-grade. `dedicated` is the
   high-assurance fallback.
6. **Filtering:** implement ADR-0003’s local deterministic evaluator first.
   Applicable filters intersect; hide wins; restrictions accumulate; malformed,
   unavailable, truncated, encrypted, or over-budget inputs become
   indeterminate and use the policy’s `onIndeterminate`, defaulting to hide.
7. **State:** the minimum synchronous path is single-process and in-memory.
   Durable queues, indexes, synchronization checkpoints, and multi-replica
   coordination are opt-in later features, not prerequisites for the gateway.
8. **External policy engines:** built-in policy evaluation remains sufficient
   for standalone operation. WASM and remote gRPC PDPs are optional engines
   behind one internal `PolicyDecisionEngine` interface and cannot bypass local
   enforcement. Missing/invalid/timeout/unknown-obligation results deny or hide.
9. **WASM distribution:** a policy release is compiled once and published as
   separate `-wasm` native OCI and `-volume` image-volume artifacts containing
   identical bytes, each referenced by its own immutable digest. No policy OCI
   artifact is run as a container.
10. **Public API contract:** implement ADR-0005’s proposed OpenAPI 3.1 `/v1`
     REST contract and the MCP `2026-07-28` Streamable HTTP contract. The first
     seven operations are identity discovery, list, literal search, read,
     attachment fetch, text-only send, and submission status. Every operation
     except identity discovery requires one explicit `identityId`; no public
     v1 flags/mutation or conversation-browsing endpoint is invented.
11. **MCP safety:** use a stateless modern adapter with `server/discover`,
     required protocol/method headers, strict schemas, private/no-store cache
     hints, read-only context resources, filtered visible-mail revision
     subscriptions, and MRTR confirmation for send unless an explicit bounded
     unattended grant exists. Tasks are advertised only with healthy durable
     task storage and are not required by standalone mode.
12. **Identity grants:** model credentials as an identity-to-grants map. The
     selected identity, principal, credential, policy generation, cursors,
     attachment handles, submissions, MRTR state, tasks, and subscriptions are
     all bound to one identity; grants never union across identities.
13. **Transport topology:** model `direct`, `existingBridge`, and
     `managedBridge` explicitly. Existing bridges may be used in standalone
     mode; managed bridges require administrator-approved, digest-pinned runtime
     policy, validated OCI hints, authenticated plugin discovery, readiness,
     trusted endpoints, and distinct bridge state/secrets.
14. **Namespace:** use `corvi.naktis.eu`/`mail.corvi.naktis.eu` for Corvi API
     groups and `eu.naktis.corvi.*` for reverse-DNS OCI annotation keys.
15. **Provenance and API status:** use versioned `v1alpha1` internal/config,
     CRD, and bridge schemas while the ADRs remain proposed. Treat the public
     `/v1` and MCP catalogues as conformance contracts, not proof that the API
     is already stable.
16. **Project governance:** preserve the existing Rust 2024 workspace and MSRV
      1.85. The license remains undecided and `publish = false`; do not create
      a LICENSE or publish crates until the owner makes that decision. Follow
      ADR-0015 for local checks and the GitHub workflow permission boundary.
17. **Transport dimensions:** separate read protocol (`imap`/`jmap`), submission
      protocol (`smtp`/`jmap`/`disabled`), and IMAP/SMTP deployment topology
      (`direct`/`existingBridge`/`managedBridge`). JMAP is native HTTPS, not a
      bridge. The public API and policy pipeline are identical for all choices.
18. **Native JMAP:** implement an optional in-process RFC 8620/8621 client with
      explicit HTTPS Session URL, trusted credential reference, account selector,
      capability validation, bounded JSON/method batching, and safe blob URLs.
      Fastmail is the first interoperability target, but no provider-specific
      admin API is implied.
19. **Protocol safety:** there is no implicit JMAP-to-IMAP/SMTP fallback;
      never silently downgrade after authentication, policy, TLS, account, or
      submission failure. Any explicit fallback policy requires a separate
      reviewed contract and full authorization/snapshot reevaluation; the
      default schema permits none.


## Main-branch reconciliation: ADR-0008 through ADR-0015

The repository already contains `mail-core`, `mail-policy`, their disclosure
tests, workspace metadata and local boundary/documentation checks. Extend them;
do not re-bootstrap or duplicate those crates. ADR-0015 is accepted; ADR-0008
through ADR-0014 describe proposed, not yet implemented, contracts.

- Upstream OAuth onboarding and Corvi's own authorization server are distinct
  trust domains. Provider tokens never authenticate Corvi clients. Onboarding
  uses provider-supported authorization code/PKCE and a protected token
  handoff, validates the actual upstream account and never silently rebinds grants.
- The optional Corvi authorization server implements authorization code with
  PKCE, consent, per-identity `corvi_mail` authorization details, registered
  confidential client credentials, metadata/CIMD, refresh rotation and
  revocation; external-issuer resource-server-only operation remains possible.
- Ephemeral standalone operation with externally managed credentials requires
  no database. Enabling the integrated issuer, durable queue or Tasks requires
  durable state: protected single-instance SQLite or PostgreSQL for HA.
  Kubernetes remains authoritative for operator management; no operator SQL
  shadow store. Upstream tokens require separately protected secret custody.
- All managed containers, including init containers, plugins and bridges, run
  non-root with dropped capabilities, read-only root filesystems, RuntimeDefault
  seccomp and no privilege escalation. Workloads receive no Kubernetes API
  token by default; a separate, restricted operator/publisher is authorized.
- `CorviGateway` has one workload owner. A provider's `gatewayRef` is optional;
  `Mailbox.providerRef` and `MailIdentity.mailboxRef` are required and
  same-namespace. Rebinding revokes old access before activating new access;
  deletion never cascades into customer mail, grants, Secrets or PVCs.
- One `MailCredential` resource selects one SMTP/REST/MCP output shape. Scoped
  permissions require an attached gateway and identity; native credentials omit
  permissions and require verified provider granularity. Read-only fail-closed
  admission is followed by continuous issuer revalidation and a separately
  authorized publisher producing flat Secret keys without overwriting foreign
  Secrets. No automatic conversion between scoped and provider-native modes.

## Approaches considered

### Big-bang implementation

Implement the gateway, policy engines, control plane, Migadu plugin, operator,
WASM packaging, and HA state together. Rejected because the contracts are
explicitly provisional and this would increase coupling and make failures in
optional infrastructure affect the core mail path.

### Standalone-first vertical slices (selected)

Bootstrap a Rust workspace, implement configuration/authentication/transport,
then policy-safe projections and the local API, and verify the standalone
acceptance target. Add control-plane/plugin contracts, optional policy engines,
operator, and scale features only after each preceding boundary is tested.
Selected because it directly follows ADR-0001’s implementation sequence and
keeps the minimum deployment useful throughout.

### Contract-only design freeze

Write all protobuf, CRD, WIT, and public API specifications before any running
gateway exists. Rejected as the sole strategy because provenance, filtering,
cache, and failure semantics need executable fixtures; contracts should be
derived and tested against the standalone behavior rather than guessed in
isolation.

## Implementation boundaries

The repository will become a Cargo workspace with focused crates/modules:

- `crates/mail-core`: existing provider-neutral actions, identities, normalized
  messages, classifications, and trusted provenance types.
- `crates/mail-config`: planned YAML loading, secret references, validation, atomic
  activation, generation/staleness checks, and last-known-good persistence.
- `crates/mail-policy`: existing I/O-free disclosure evaluator, classifiers,
  typed decisions, and projections. Replace its provisional string sanitizer
  with a parser-based implementation before exposing untrusted HTML.
- `crates/mail-imap`, `crates/mail-smtp`, and `crates/mail-jmap`: planned
  upstream adapters using provider-neutral reader, submitter, change-tracker,
  and blob-reader boundaries; JMAP and bridges remain optional.
- `crates/mail-api` and the gateway executable: REST/MCP listeners and the
  shared request pipeline; `crates/mail-smtp` owns SMTP submission.
- `api/`, `docs/spec/mcp.md`: machine-readable OpenAPI/MCP tool/resource
  contracts and protocol conformance fixtures.
- `api/mail-transport.schema.json`: provider-neutral read/submission protocol
  and bridge-topology descriptor.
- `skills/corvi-mcp/`: versioned agent-facing skill generated and reviewed only
  against the implemented MCP server and passing fixtures.
- `crates/mail-admin` and planned provider contracts: versioned control-plane,
  provider, and bridge interfaces, kept out of the core hot path.
- `operator/`, policy package tooling, and deployment manifests only after the
  standalone and contract test gates pass.

Exact third-party crate versions are implementation details resolved while
bootstrapping and committed in `Cargo.lock`; no dependency is allowed to make
optional components mandatory for the standalone binary.

## Autonomous completion rule

An implementation worker may make ordinary library and test-structure choices
without asking for clarification. If a choice would alter an ADR invariant,
minimum deployment, authority boundary, data disclosure, or compatibility
promise, the worker must choose the stricter behavior, add a focused test, and
record the choice in the relevant follow-up ADR instead of weakening the
invariant or stopping for a question.

## Builder-check resolutions

The following implementation questions were material enough to resolve before
planning:

- **Plan scope:** this is one staged roadmap for the complete ADR direction,
  but each slice has its own executable acceptance gate. The first gate is the
  standalone gateway; later slices must not be started by making the first gate
  depend on them.
- **First runnable operations:** the standalone gateway implements ADR-0005’s
  seven operations: list identities, list visible messages, literal search,
  filtered read, independently authorized attachment fetch, text-only send, and
  submission status. Message mutations, conversation browsing, events, exports,
  durable queues, persistent indexes, and Tasks are later/optional slices.
- **Standalone authentication:** REST and MCP use opaque bearer tokens whose
  token ID and Argon2id verifier are stored in the local snapshot. SMTP AUTH
  uses a separate username plus Argon2id password verifier. Both resolve to the
  same principal/credential/identity/action policy model. Tokens are scoped,
  expire explicitly, and are revoked by generation update; no upstream
  IMAP/SMTP password is ever issued to a client.
- **Baseline mail state:** the first slice queries direct or explicitly
  configured existing-bridge IMAP live and keeps only bounded request-local
  normalized messages/projections. It has no persistent index, synchronization
  worker, durable task store, or external database. Opaque cursors carry only
  internal scan state and policy/configuration fingerprints; raw UIDs are never
  returned. Direct-relay idempotency cannot survive process restart unless a
  durable store is explicitly enabled, and the response reports that capability.
- **Public client contract:** implement `/v1/identities`, `/v1/messages`,
  `/v1/messages/search`, `/v1/messages/{messageId}`,
  `/v1/messages/{messageId}/attachments/{attachmentId}`,
  `/v1/messages/send`, and `/v1/submissions/{submissionId}` from
  `api/openapi.yaml`, plus exactly the seven MCP tools in `api/mcp-tools.json`.
  Use `application/problem+json`, stable error codes, identity-bound cursors,
  default page size 25/max 100, 15-minute cursor expiry, and no total counts.
- **MCP protocol contract:** target revision `2026-07-28` over stateless
  Streamable HTTP; require version/method headers and matching request metadata,
  reject old handshake assumptions, validate structured/text results from the
  same sanitized DTO, and expose only the catalogued context resources. MRTR is
  required for interactive send, subscriptions emit only caller-visible
  revisions, and Tasks are opt-in only with durable storage.
- **Listener TLS and reload:** the gateway can terminate listener TLS itself
  with rustls certificate/key files; deployment behind another terminator is
  allowed but not required. A non-loopback public listener without configured
  TLS fails startup, while an explicitly labeled loopback development listener
  may use plaintext. Configuration reload is explicit via SIGHUP (and a CLI
  `config check` command for preflight), validates a complete replacement, and
  atomically retains the prior generation on failure.
- **Positive allowlists:** a `show` rule is an eligibility grant only when the
  policy uses `defaultVisibility: hide`; it remains inside the authenticated
  identity boundary and never overrides a matching hide, redaction, or strip
  restriction from another applicable policy.
- **Upstream secret custody:** the standalone slice accepts only references to
  operator-protected files (0600, correct owner, no inline secret values) and
  permits only validated references in snapshots, never secret values, and
  excludes sensitive references from logs. Encrypted-at-rest secret
  storage, emergency revocation distribution, and secret handoff from a
  provider are later control-plane slices, never reasons to put plaintext in
  the data-plane snapshot.
- **Bridge custody and lifecycle:** an existing local bridge uses explicit
  verified endpoints and pinned/trusted TLS in standalone mode. A managed bridge
  is never started from OCI annotations alone; administrator policy approves the
  digest, runtime, placement, state, network, and secret bindings, then the
  plugin’s authenticated capabilities and bridge readiness must agree before
  transport publication. Unknown/headless/enrollment limitations surface as
  status, not as direct-transport fallback.
- **JMAP transport and custody:** JMAP session/account/capability discovery is
  validated before activation; session-advertised API, upload, download and
  EventSource URLs are restricted to approved HTTPS origins/egress and never
  expose bearer tokens. JMAP account/Email/Thread/Identity/state IDs remain
  internal. JMAP submission uses validated `Identity/get`, `Email/set` and
  `EmailSubmission/set`; uncertain outcomes are `unknown` and never trigger
  automatic SMTP fallback.
