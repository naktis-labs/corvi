# ADR-0005: Shared public mail API contract for REST and MCP

- **Status:** Proposed (implementation contract, subject to conformance testing)
- **Date:** 2026-11-16
- **Related:** [ADR-0001: System architecture](0001-corvi-system-architecture.md), [ADR-0002: Product goals](0002-product-goals-and-messaging-extensibility.md), [ADR-0003: Filtering and disclosure](0003-mail-filtering-and-disclosure-policies.md), [ADR-0004: Policy engines](0004-pluggable-grpc-policy-engines.md)
- **Machine-readable REST specification:** [`api/openapi.yaml`](../../api/openapi.yaml)
- **MCP interface specification:** [`docs/spec/mcp.md`](../spec/mcp.md)

## Context

Corvi must give agents and applications controlled access to the user's mail, and independently manage mail resources for self-hosted services. The previous ADRs specify boundaries but not the actual public client contract. Without one semantic contract, a REST or MCP client may observe different message filtering, sender enforcement, idempotency or error handling.

This ADR specifies the **data-plane public mail API only**. It does **not** authorize administrative resource provisioning through the personal-mail MCP server. A separate administrative API specification is required for mail-provider and Kubernetes control-plane operations.

## Decision

**One application service, multiple protocol adapters.** A single Rust application layer owns the mail operations, and the REST, MCP and SMTP-submission adapters call it. Public adapters must never access raw upstream IMAP state, bypass identity membership, invoke provider management during a mail operation, or independently implement a weaker disclosure policy.

The contract below is a **v1 MVP baseline**, not a claim that endpoints are already implemented. New capabilities require explicit schema and permission additions.

### Operations

| Shared operation | REST interface | MCP tool | Permission |
| --- | --- | --- | --- |
| List accessible identities | `GET /v1/identities` | `mail_list_identities` | `mail:identities:list` |
| List visible messages | `GET /v1/messages` | `mail_list` | `mail:messages:list` |
| Search visible messages | `POST /v1/messages/search` | `mail_search` | `mail:messages:search` |
| Read filtered message | `GET /v1/messages/{messageId}` | `mail_get` | `mail:messages:read` |
| Read permitted attachment | `GET /v1/messages/{messageId}/attachments/{attachmentId}` | `mail_get_attachment` | `mail:attachments:read` |
| Submit outgoing mail | `POST /v1/messages/send` | `mail_send` | `mail:messages:send` |
| Retrieve send status | `GET /v1/submissions/{submissionId}` | `mail_get_send_status` | `mail:submissions:read` |

Reading, searching and listing are separately grantable; a credential need not have all three. A credential with send permission does not gain read permission, and a provisioning/control-plane credential does not gain either by default. List identities exposes only identities the authenticated principal can operate on, without disclosing which other identities exist.

**Explicit identity selection:** Every operation other than listing identities supplies an `identityId`. A gateway-issued opaque message ID alone never grants access. Both identity and message-level eligibility must be checked at every call, even when the caller guesses an existing ID. No implicit global mailbox selection.

## 1. Resource model

### MailIdentityView

A safe client-visible identity includes `id`, `address`, optional `displayName`, and capability booleans or action names for the current caller. It never includes upstream IMAP/SMTP credentials, management secrets, other aliases, or raw provider identifiers.

### MailMessageSummary

A filtered summary contains a gateway-issued opaque `id`, `identityId`, optional `conversationId`, `receivedAt`, and **only permitted** fields such as subject, sender, snippet and read-state. Omit fields that the disclosure projection disallows. Do not indicate that an omitted field was hidden for a specific reason.

### MailMessage

A full message adds safe `to`, `cc`, `replyTo`, sanitized `textBody` and optional `htmlBody`, plus only permitted attachment descriptors. Raw MIME, unredacted HTML and unapproved URL destinations are **not** part of v1. `Message-ID` headers are untrusted metadata, not the gateway's primary ID.

### Conversation identity

`conversationId` is an opaque, best-effort grouping handle. Thread grouping must not reveal hidden messages or implicitly authorize fetching them. v1 has no `GET /conversations` endpoint; any later endpoint must use the same filtering contract.

### Attachment descriptor

An attachment descriptor provides a gateway-issued opaque attachment ID, a sanitized filename, content type and bounded size when permitted. Attachment metadata and content have independent authorization checks. REST streams permitted bytes; initial MCP tool output is base64 with an explicit **2 MiB** size cap. For larger permitted content, an authorized REST client may stream bytes; MCP must return a non-leaking `ATTACHMENT_TOO_LARGE` error rather than an unprotected URL or unrestricted raw MIME resource.

### Outgoing submission

`Submission` uses a generated opaque ID and one of `queued`, `submitted`, `failed` or `unknown` statuses. `unknown` represents ambiguous upstream outcomes (for example a network disconnect after SMTP DATA); it must not trigger unsafe automatic re-sends. `submitted` means accepted by the upstream SMTP server, **not delivered to the final recipient**.

## 2. Authorization and filtering

All operations use, in order:

1. Authenticate the caller and validate token issuer/audience/expiry, active credential and bound identities.
2. Authorize the requested action under `MailPolicy`.
3. Verify mailbox/identity membership and trusted original-recipient provenance where configured as `verified`.
4. Evaluate `MailFilterPolicy`, including classification and optional local WASM/remote PDP obligations.
5. Construct and return **only the permitted projection**. Reauthorize on attachment reads and send-status lookups.

A `hide` decision makes a message indistinguishable from nonexistent mail: direct fetch yields **404**, and search/list/counts, thread grouping, identifiers, snippets, attachments and notifications contain no traces of it. Denials of an *action* on a known authorized identity can be **403**; an inaccessible/hidden message ID must not become an enumeration oracle. Corvi must not return a distinguished `filtered: true` marker for hidden mail.

A response may omit/redact fields of an otherwise visible message. Corvi must never return raw MIME, raw HTML, pre-filtered snippets, unscoped attachment links or filtered-out messages to MCP, REST, a response cache, logs or events.

Policies and capability lists are authorization-dependent. Mark REST private content **`Cache-Control: private, no-store`**; MCP cacheable lists default to `ttlMs: 0`, `cacheScope: private`, unless a rigorously safe shorter-lived policy is established. Changes to identity/filter policy immediately invalidate applicable cursors and projections once the local policy generation is activated.

## 3. Identity, message ID and cursor semantics

- IDs are opaque and generated by Corvi, not raw IMAP UIDs or sequential database keys. Persist a mapping to upstream mailbox/folder/UIDVALIDITY/UID. Message IDs should remain stable when Corvi can reliably track a move, but **clients must tolerate changed IDs** across uncertain IMAP moves, UIDVALIDITY resets or resynchronization.
- `identityId` must be supplied explicitly for reads, searches, attachment fetches, sends and submission-status reads. All IDs are untrusted inputs and revalidated against the caller.
- Message lists are sorted newest first by `receivedAt`, then a stable opaque tie-breaker. Search semantics for `query` are **case-insensitive literal text matching** over the caller's permitted normalized subject/text projection in v1. Advanced search syntax, ranking and index consistency are deferred. Search never uses hidden text to produce a visible hit.
- Paginate with an opaque `nextCursor`. A cursor is bound to principal/credential scope, identity, requested operation, query/filter parameters, active authorization and filter revision, and server-side mailbox snapshot/high-water mark where available. It must be integrity protected and unguessable.
- Default page size **25**, maximum **100**, and cursor expiry **15 minutes**. An expired, invalid, or policy-stale cursor returns `CURSOR_INVALID` or `CURSOR_STALE` without leaking source offsets or hidden counts.
- Do not return upstream counts or `totalHits`. `nextCursor` describes only remaining *visible* items. If an expensive filter scan has not completed, the gateway must not guess visibility or expose unprocessed metadata; it may return a retryable `FILTER_UNAVAILABLE` instead.

v1 list/search consistency is **best-effort against the upstream mailbox**, not a transactional snapshot. Duplicate or missing entries are possible when messages change concurrently; clients deduplicate by opaque ID and restart pagination after stale-cursor errors. The gateway must not allow such inconsistency to reveal hidden messages.

## 4. Sending and idempotency

v1 supports composing **plain-text mail** from an authorized identity (`to`, optional `cc`/`bcc`, `subject`, `textBody`). Arbitrary raw MIME, user-supplied From/envelope sender, HTML composition and outgoing attachments are deferred pending separate input validation and upload specifications.

Corvi derives header From and SMTP envelope sender from the authorized `MailIdentity`. It validates permitted recipients and destination domains, and applies any explicitly configured outgoing policy before upstream submission. Client-supplied messages or quoted text are untrusted and must not cause the server to fetch hidden content.

- **REST** sends require an `Idempotency-Key` header (opaque 1–128 printable characters).
- **MCP** `mail_send` requires an `idempotencyKey` tool argument; the client or host should generate a stable unique key for a single user-intended send.
- The same key, principal/identity and exact canonical request must return the same submission rather than sending twice, within a documented retention period (**at least 24 hours**). Reusing a key with a different payload returns `IDEMPOTENCY_CONFLICT`.
- Retain idempotency state durably when Corvi promises durable queueing. In direct-relay/no-database mode, guaranteed replay protection **cannot survive a process restart** unless durable idempotency storage is configured; expose this deployment capability and do not claim stronger semantics. The caller must be told whether retry safety survives restarts.
- Direct relay reports `submitted` only after the upstream SMTP server accepts the message; a configured durable queue reports `queued` only after persistence. Ambiguous outcomes are `unknown` and require reconciliation rather than blind retransmission.

For REST, `200` indicates an existing/replayed or immediately submitted receipt, while `202` indicates queued/accepted-for-processing; the documented response schema is the same. MCP returns the same structured `Submission` status, never a stronger delivery guarantee.

**Agent confirmation:** `mail_send` is a side-effecting operation; user-facing hosts and the companion MCP skill must require review/confirmation unless the user deliberately configured an unattended automation policy with bounded identities/recipients. Server-side authorization is required in either case. A model-generated claim of approval is not a substitute for actual host/user authorization.

## 5. REST contract

The machine-readable source of truth is [`api/openapi.yaml`](../../api/openapi.yaml), using **OpenAPI 3.1** and JSON Schema 2020-12.

- Prefix `/v1`; all JSON uses UTF-8; TLS is required on network-facing listeners or a trusted terminating proxy.
- OAuth2/OIDC-issued and Corvi service bearer tokens are accepted only when explicitly configured; validate issuer, token audience for Corvi, expiry, authorized identity binding and action scopes on every request. Never accept provider or OAuth authorization-server credentials as Corvi mail API tokens.
- Errors use `application/problem+json` with a **stable `code`**, request `traceId`, generic `detail`, and appropriate HTTP status; never include subjects, OTPs, raw URLs or policy internals.
- Include limits and `429` rate limiting; reject oversized bodies before expensive parsing.
- Use `401` for unauthenticated, `403` for forbidden authorized actions, `404` for absent/hidden resources, `409` for stale cursor/idempotency conflicts, `422` for invalid requested send/recipient, and `503` for dependent upstream/policy unavailability.
- Reads must not mark messages read. Flags/move/delete/draft APIs and event subscriptions are **not in v1**; add them only with new permissions and filtering tests.
- Provide an explicitly documented capability/reporting mechanism later if an installation supports queued delivery, indexing, or stronger idempotency. Do not infer these from a generic success status.

## 6. MCP contract

The human-reviewed source of truth is [`docs/spec/mcp.md`](../spec/mcp.md); it must be validated against a concrete test server and the same service DTOs as OpenAPI.

- Target **MCP protocol revision `2026-07-28`**, using Streamable HTTP `POST /mcp` (and optional trusted stdio). The modern revision is stateless, with `server/discover`, per-request protocol metadata, required version/method HTTP headers, and required `resultType` in results.
- Initial tools are exactly the seven operations listed above. Each exposes strict `inputSchema`, `outputSchema`, and structured content; do not invent additional tools without documenting permissions and security tests.
- In MCP, `tools/list` and `tools/call` are **not permission grants**. Tool discovery may vary with the authenticated user but is never a substitute for per-call permission checks. Use private/no-cache lists by default.
- Do **not** use MCP resources as a second route to raw messages or attachments in v1. Resources, prompts, subscriptions and task extensions are intentionally deferred until their disclosure/authorization behavior is specified.
- Support for older `2025-11-25` handshake-based clients is a **future compatibility choice**; it is not implied by serving the modern protocol. If added, test both eras with distinct lifecycle/transport expectations.

The MCP specification sources used for these protocol-level decisions are the published [2026-07-28 specification announcement](https://blog.modelcontextprotocol.io/posts/2026-07-28/) and [2026-07-28 changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog).

## 7. Control-plane and operational boundaries

The public `/v1` and `/mcp` endpoints never expose mail-provider domain, mailbox, alias or plugin-management operations. A separate authenticated administrative API, possibly on a separate listener, will be specified independently. SMTP AUTH submission calls the same action/identity policy layer; it is not mapped into arbitrary MCP tool calls.

Rate limiting, tracing, error details and audit records must be partitioned by principal/identity without including private mail content or individual addresses as metric labels. Corvi's one-container standalone mode remains supported.

## 8. Conformance and release gates

Before considering this API stable, require contract tests that exercise **each operation through REST and MCP using the same fixtures**, including:

1. Same visible messages, redacted fields and attachment availability for the same principal/identity/policy across both transports.
2. Hidden message IDs return non-disclosing 404 or equivalent MCP tool error, including after guessing a valid ID from another identity.
3. No hidden data in search, counts, pagination cursors, snippets, thread metadata or attachment access; no scan-on-list bypass.
4. Tool discovery and cached results cannot expose capabilities/data from another principal.
5. Filter/policy/credential rotation invalidates data projections and cursors; stale tokens fail closed.
6. Sending enforces From, envelope sender and recipient policies, with identical idempotency behavior across transports.
7. Unknown SMTP outcomes are not reported as successful final delivery; process-restart replay limitations are documented and tested.
8. OAuth resource-server metadata, audience validation, invalid Origin/Host, absent or mismatched MCP headers, unsupported MCP protocol version and overly large requests are handled safely.
9. Generated REST clients pass OpenAPI validation; MCP tool input/output schemas pass JSON Schema checks and current protocol conformance suites.
10. Data-plane operations succeed without a control plane, operator, provider-management RPC or optional external policy engine unless configured to require it.

## 9. Skill deliverable

An agent-oriented `SKILL.md` and accompanying examples remain a **required deliverable** alongside the MCP implementation. It must describe accurate server discovery, authentication, identity selection, tool arguments, permitted read/search behavior, privacy restrictions, redaction semantics, safe sending and idempotent retries. It must be generated/reviewed against the **actual** MCP tool catalog and conformance fixtures, not speculative capabilities. Publishing the spec does not mean the skill or the server is implemented.

## Open questions

- Whether v1 should additionally provide a separate REST `GET /v1/identities/{id}` or mailbox/folder discovery surface.
- How to support HTML/outgoing attachments safely without broadening the initial send model.
- Whether to introduce explicit mailbox synchronization cursors and event streams.
- Exact form of scopes/resource indicator metadata and a multi-issuer trust configuration.
- Search indexing strategy, backfill limits, and query semantics beyond literal visible text.
- Deployment-capability reporting and exact persistence requirements for direct-relay idempotency.
- MCP Rust SDK support and optional legacy-version compatibility plan.

## Consequences

Corvi gains a single, testable mail-facing contract with explicit safety and interoperability requirements. REST and MCP are just adapters. Protocol evolution cannot silently bypass action authorization, trusted recipient isolation, disclosure filtering or send controls.
