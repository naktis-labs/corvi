# ADR-0010: Storage, durability and secret custody

- **Status:** Proposed (no storage implementation yet)
- **Date:** 2026-11-16
- **Scope:** Standalone/clustered Corvi storage for configuration, OAuth, provider secrets, mail synchronization, optional queues and indexes
- **Related:** [ADR-0001](0001-corvi-system-architecture.md), [ADR-0003](0003-mail-filtering-and-disclosure-policies.md), [ADR-0005](0005-public-mail-api.md), [ADR-0007](0007-native-jmap-transport.md), [ADR-0008](0008-interactive-upstream-oauth.md), [ADR-0009](0009-corvi-oauth-and-identity-grants.md)
- **Proposed configuration schema:** [`api/storage.schema.json`](../../api/storage.schema.json)

## Decision

Corvi shall support **SQLite (embedded standalone)** and **PostgreSQL (external/multi-replica)** as alternative relational state backends, with separate abstractions for **secret custody**, **configuration snapshots** and **optional large-object storage**. The provider's IMAP/JMAP mailbox remains the **source of truth for incoming mail**, not Corvi's database.

**No external database is required for minimal standalone**, configured with a local file, direct IMAP/SMTP or native JMAP access, direct submission and an externally managed/verified client credential. Once the **integrated Corvi OAuth authorization server** is enabled, a durable token/grant/revocation store becomes mandatory: **SQLite on a protected persistent volume is sufficient for one instance**. A fully durable queue, crash-safe idempotency, resumable tasks, and persistent synchronization/indexing also require an enabled durable store.

For **HA/multiple active Corvi instances**, use **PostgreSQL as the shared authoritative transactional database**. SQLite remains a local, single-writer database, not a distributed lock coordinator; never share one SQLite WAL database over a generic RWX/NFS PVC among multiple Corvi Pods.

Storage is divided by security and ownership boundaries: data-plane state is owned by the data plane, provider admin state by the optional control plane, and credentials are never exposed to mail-facing clients or provider plugins solely because they can read database records.

## 1. Storage domains

| Domain | Examples | Authority and recommended storage |
| --- | --- | --- |
| **Desired configuration** | MailProvider/Identity/Policy resources, deployment settings, secret *references* | GitOps/CRDs or YAML; input to validated immutable snapshots; no raw secret values |
| **Active configuration** | Last-known-good, validated generation; feature flags; permission references | Atomic snapshot file or protected local state plus in-memory active revision; no unrestricted provider secrets |
| **OAuth/identity state** | Clients, consented per-identity grants, issuer/subject mapping, auth codes, token hashes, refresh families, revocations, session metadata | Transactional SQLite or PostgreSQL; required for integrated Corvi AS |
| **Provider connection state** | Upstream account binding, capability/scopes, token expiry, revocation/reauthorization status, refresh leases | Relational metadata plus encrypted secret store; never ordinary config/CRD status |
| **Message sync state** | IMAP UIDVALIDITY/UID, JMAP account state tokens, checkpoint generations, worker leases, opaque ID mappings | Durable DB **when persistent sync or stable mapping is enabled**; otherwise transient bounded reconciliation |
| **Outbound state** | Idempotency keys, canonical payload digest, submission record, durable queue item, retry attempts, outcome and reconciliation hints | Durable DB and optional encrypted payload blob; owned by data plane |
| **MCP Task and event state** | Task ownership/state/result reference/cancellation, optional event replay/outbox | Durable DB for enabled Tasks; subscriptions alone are best-effort and need no durable history |
| **Visible index/cache** | Authorized sanitized projections, policy revision, filtered search entries | Optional DB index/cache or specialized index; always scoped to principal/identity/policy |
| **Blob storage** | Large queued bodies and optional authorized attachment cache | Optional encrypted local directory or S3-compatible object store; no default remote copy of inbound email |
| **Audit** | Authorization/client grant changes, provider connection updates, send outcomes | Bounded, access-controlled relational audit records or dedicated observability sink, with no content or secret values |

Secret values do **not** belong in GitOps, Kubernetes CRD `spec`/`status`, normal configuration snapshots, JWT claims, plaintext database columns, telemetry, search indexes, or agent-readable MCP resources.

## 2. Backend and deployment modes

| Mode | State | Guarantees |
| --- | --- | --- |
| `ephemeral` | In memory / optional atomic configuration file | Minimal gateway; **no integrated OAuth issuer**, durable queue, guaranteed restart-safe idempotency or durable Tasks |
| `sqlite` | SQLite file on protected local persistent filesystem | Single-instance integrated OAuth, local provider connection metadata, optional durable queue/sync/tasks |
| `postgres` | PostgreSQL over verified TLS | Shared state, multi-replica grants/refresh, queue ownership, sync leases and HA |

SQLite defaults: WAL mode, busy timeout and bounded connections, transactional migrations, one-process writer ownership, configured `synchronous` policy according to durability requirements, integrity checks and checkpointing. Protect file, WAL and SHM files with filesystem permissions; don't copy just the `.db` file while WAL writers are active. Local filesystem or single-instance persistent PVC only. After a crash, restore/reconcile queued sends and refresh families before resuming operations.

PostgreSQL defaults: dedicated role/schema/database permissions per **data-plane** and **control-plane** concern (prefer separate databases or schemas when credentials and trust boundaries differ), TLS certificate/peer verification, bounded pools, schema migration coordination, atomic compare-and-swap/transactional updates, leases/fencing for singleton work, and explicit degraded-mode behavior when DB connectivity is lost. Do not assume PostgreSQL row-level security replaces Corvi per-identity policy enforcement.

**Do not add Redis as a requirement.** An optional cache/pubsub adapter may accelerate multi-replica invalidation/fanout, but PostgreSQL remains authoritative. A cache hit cannot replace token revocation, current policy, OAuth grant, or message disclosure verification.

## 3. Rust storage interfaces and migrations

Define small domain-focused stores instead of a universal `Database` trait with backend-specific SQL exposed to business logic:

- `GrantStore`: OAuth clients/consent/grant revisions, auth-code single-use exchange, opaque access-token lookup, rotating refresh families, revocation and owner review.
- `ProviderConnectionStore`: upstream account metadata, scopes, credential references, refresh rotation ownership and connection state.
- `MailboxStateStore`: IMAP/JMAP sync cursors, opaque ID lookup, identity-safe checkpoint state and fenced worker ownership.
- `SubmissionStore`: idempotency and submission state machine, transactional queue/claim/update, retries and cleanup.
- `TaskStore`: durable task ownership, progress, cancellation and result handles.
- `AuditStore`: bounded events and access-control review, not mail content.
- `SecretStore`: independent keyed, authenticated secret read/write/rotate/delete operations with audit and scoped caller identity.
- `BlobStore`: optional encrypted opaque object put/get/delete with TTL, size and account binding.

Keep SQL migrations **versioned per backend**, with compatible semantic behavior and conformance tests for SQLite and PostgreSQL. Prefer a constrained query/model layer that can implement both backends, but require explicit implementations for row locking, refresh rotation and work claiming where SQLite and PostgreSQL differ. Avoid a distributed transaction across relational DB and secret/object store: use staged writes, durable intent/outbox and recoverable compensation.

Migration safety: transactional migration when supported, `schema_version` and feature-gate checks, pre-upgrade backup, no automatic destructive downgrade, rollback strategy and explicit refusal when a newer incompatible schema is present.

## 4. Token and secret custody

**Separate DB read access from secret decryption authority.** Relational tables store **references**, safe connection metadata and encrypted envelopes only where a dedicated store cannot be used. Sensitive values include:

- **Upstream OAuth** access/refresh tokens, provider session credentials, IMAP/SMTP app passwords and bridge-generated credentials (ADR-0008).
- **Corvi OAuth** client secrets, signing keys, browser session secrets and other AS key material (ADR-0009).
- Inter-component mTLS private keys, envelope-wrapping keys and optional encrypted blob keys.

Proposed implementations:

1. **Standalone:** local encrypted secret vault backed by protected files and an independent wrapping key obtained from operator-supplied file/OS secret/keyring/passphrase mechanism. Never store the decrypting master key in the **same database backup or plain config file** as the encrypted tokens. The exact crypto/KDF profile and secure unlocking UX need implementation-level review.
2. **Kubernetes:** use approved Kubernetes Secrets via mounted volumes, external secrets providers/KMS, or a dedicated encrypted token-vault service; applications should access only the references needed. Kubernetes Secrets are **not encrypted end-to-end by default merely because they use the Secret API**; require configured at-rest encryption, RBAC and audit policy.
3. **PostgreSQL-encrypted-envelope option:** acceptable only if envelope encryption uses a **separately managed** wrapping key. Do not use database-only password encryption or rely on TLS-at-rest claims to protect from a DB dump.

Bind encrypted secret envelopes with associated data (provider/connection/secret type/version/owner); support key IDs, versioned rewrap, least-privilege access, rollback/recovery, and explicit rotation/revoke. Do not log plaintext tokens, OAuth authorization codes, key material, password reset links or the entire URI if it may contain secrets.

For OAuth access tokens stored as **verifiers**, keep keyed hashes or high-entropy token hashes, not recoverable bearer token strings. Provider OAuth **access/refresh** tokens must be recoverable by the authorized outgoing transport or token broker, and therefore require encryption and strict secret custody. Refresh rotation is an atomic state transition with single-owner semantics: after a provider rotates a refresh token, commit the new encrypted credential and generation before announcing it current; handle crash windows with explicit `needsReauthorization` where recovery is impossible.

## 5. Mail content, indexing and privacy

**Default: do not persist inbound raw MIME or attachments.** Fetch directly from IMAP/JMAP when needed; allow bounded, memory-only transit buffers. A user enabling offline cache, search indexing, attachment cache, classification history or queue attachment support must opt into the relevant storage and retention settings, including encryption and deletion policy.

- **Filtering happens before publication** to any client-visible table, search index, notification or embedding store; client-facing indexes contain only allowed sanitized projections, scoped by principal/credential, `MailIdentity`, rule/policy revision and visibility evidence.
- Never use a single global "sanitized message" cache as permission to expose a message to every principal. An identity-specific view can differ even for the same source message. Cache policy must account for changed grant, content classifications, secret handling and source deletion.
- If internal **unfiltered** upstream metadata/raw content must be stored for sync/classification, isolate it in a separately permissioned/encrypted internal store with explicit consent and retention. It cannot be queried directly by public REST/MCP endpoints or used to form unfiltered hit counts, snippets, event timestamps, thread memberships or storage metrics.
- Bounded encrypted queued outgoing payloads can persist temporarily when durable submission is enabled; keep until terminal state + configured retention, then securely expire both database records and blobs, including stale multipart uploads.
- Search index design is optional: SQLite FTS5 for a local prototype or PostgreSQL full-text search for server mode could be evaluated, but neither automatically satisfies the disclosure semantics. An indexing/search backend must have a per-identity policy gate and no hidden-message side channels.
- Blob keys are opaque and namespaced per account/identity/record, bounded by quotas and TTLs. Avoid returning raw S3 URLs or unscoped presigned URLs for restricted content. Any attachment read must reauthorize through Corvi, regardless of physical blob location.

## 6. Idempotency, queue ownership and crash safety

An outgoing send record has a canonical payload digest, requester principal, client, Corvi `MailIdentity`, idempotency key, policy/grant generation, selected upstream submission protocol, state and timestamps. Enforce a **unique key on the appropriate principal/client/identity/idempotency scope**; reject reuse with a different payload.

- Persist the intent and idempotency reservation **transactionally before** a queued submission is acknowledged; reserve at-most-one *Corvi intent* per key. Do not claim exactly-once upstream email delivery because SMTP/JMAP acceptance can be ambiguous after network loss.
- Use monotonic states with explicit `unknown` after an uncertain send; never blindly resend after `EmailSubmission/set` or SMTP DATA without reconciliation.
- Queue workers use transactionally claimed jobs and leases with fencing/version counters. In SQLite mode a single active worker process coordinates locally; in PostgreSQL mode use transactional row claims (e.g. `FOR UPDATE SKIP LOCKED`) and retry-safe status transitions.
- Any DB-to-blob operation requiring cross-store consistency uses durable intent, staged blob creation and garbage collection of orphans. A durable task/result handle is persisted **before** MCP returns `resultType: task`.
- The direct-relay stateless mode must report the absence of restart-safe idempotency/queue guarantees rather than imply a receipt survives a crash.

## 7. Backups, deletion, observability and retention

- **Backup:** SQLite online backup API or a consistent quiesced snapshot including WAL state; PostgreSQL coordinated backups/PITR. Test restore with migrations, encryption key availability and token family validity, not just database file readability.
- **Key recovery:** Back up wrapping keys and recovery material **separately**, under separate protections, or clearly document that backups will be unusable without keys. Revoked/deleted credentials must not silently be resurrected by a restore; maintain an explicit revocation/freshness recovery procedure.
- **Deletion:** Disconnecting a provider invalidates its credential, cached content, sync state and associated background jobs. Removing a `MailIdentity` invalidates derived cursors/projections and consent grants; do not delete shared physical mailbox state that belongs to other identities.
- **Retention:** configurable, shortest reasonable default for sensitive data; proposals: auth codes/transactions minutes, access tokens until expiry + minimal anti-replay window, pending queue until finalized, submission idempotency **at least 24 hours where promised**, optional message caches TTL-based, audit events policy-based and non-content-bearing. Never treat DB TTL cleanup as a substitute for immediate authorization checks.
- **Audit/metrics:** include database/secret-store health, migration revision, cache staleness, queue depth, refresh failure, expiring leases, backup age and storage capacity. **No message subjects, sender addresses, raw grant tokens, mail body content or detailed provider-account labels in metrics.**
- **Performance:** configure pool/connection caps for low-resource standalone and multi-tenant workloads; bound disk budgets, object sizes, indexing costs, concurrency and garbage collection.

## 8. Suggested configuration (illustrative)

```yaml
apiVersion: corvi.naktis.eu/v1alpha1
kind: CorviStorage
state:
  backend: sqlite
  sqlite:
    path: /var/lib/corvi/state.sqlite
secrets:
  backend: encryptedFile
  encryptedFile:
    path: /var/lib/corvi/secrets.enc
    wrappingKeyRef: secret://local/corvi-storage-key
blobs:
  backend: disabled
features:
  integratedOAuthIssuer: true
  durableSubmission: false
  durableTasks: false
  persistentMailboxSync: false
  persistInboundMail: false
```

For Kubernetes HA: set `state.backend: postgres` with a **credential reference**, configure the external/wrapped secret store separately, and use a database reachable by all gateway replicas. Do not mount the same SQLite file into multiple active replicas.

**Do not copy the literal `secret://` syntax into a production config without the corresponding trusted secret-reference resolver.** Illustrative paths and resource names in this ADR are not published configuration fields.

## 9. Acceptance tests

1. Minimal standalone gateway with `ephemeral` state and external identity credential requires no DB or external services; integrated Corvi OAuth issuer, durable Tasks or durable queue cannot be enabled without persistent storage.
2. `sqlite` mode survives restart with client grants, refresh families, revoked tokens, upstream connection state and idempotent queued submissions intact, including WAL checkpoint/crash tests.
3. `postgres` mode coordinates multiple replicas' issuer state, refresh rotation, queue claims and JMAP/IMAP sync ownership with no duplicate token refresh or queue ownership.
4. A DB dump, ordinary config snapshot, CRD dump or S3 object listing does **not** disclose upstream OAuth refresh tokens or provider passwords without separately protected key material.
5. Wrong/missing wrapping key fails closed; key rotation, schema migration, backup and restore are tested; old revoked grants cannot be silently revived.
6. Sensitive message classifications, hidden-only changes, per-client filtered search, count/thread/attachment paths and new policy generations do not leak through shared indexes, object URLs or caches.
7. Default mode stores no inbound raw mail. Opt-in stored mail is encrypted, bounded, tied to consent/retention and erased/inaccessible after account unlink or identity revocation as appropriate.
8. Direct-relay mode explicitly reports non-durable replay limits; durable queue mode reserves idempotency and payload before acknowledgments and preserves `unknown` results through crashes.
9. SQLite network-share/multi-writer setups are rejected, and PostgreSQL loses freshness fail-closed for authorizations needing up-to-date grants.
10. Blob upload failures leave recoverable pending records; orphan/blob TTL cleanup does not remove still-pending authorized submissions.
11. Secrets, PII and raw mail cannot appear in status/telemetry, normal error payloads or public MCP context resources.

## Consequences

The common storage interface enables a small standalone Corvi with embedded SQLite and a safe migration path to PostgreSQL HA. Secret custody stays separate from relational authorization/operational records. Durable OAuth, queues, synchronization and Tasks become **explicit feature-dependent commitments**, not mandatory background infrastructure for basic mail access.

---
This ADR records a proposed storage contract, not implemented database migrations or a released storage configuration format.
