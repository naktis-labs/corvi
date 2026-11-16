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

### Multi-mailbox and multi-identity credentials (required in v1)

**A single MCP client authenticated by one access token MUST be able to use multiple explicitly granted `MailIdentity` resources, including identities backed by different physical `Mailbox` instances or upstream providers.** The same capability applies to REST. Requiring one token, connection, or MCP server process per mailbox/identity is expressly **not** part of Corvi's design.

- A validated credential maps to a **set of identity-scoped grants**, conceptually `{ identityId -> allowedActions, mailPolicy, mailFilterPolicy }`. The set may contain any number of permitted identities within deployment limits; authorization is the **intersection** of token/credential maxima, server-side grants, current identity membership, and applicable action/disclosure policy. A token containing broad scope names without identity bindings cannot enumerate or act on every mailbox.
- Distinct identities may map to **the same physical mailbox** (aliases with provenance constraints) or to **different mailboxes, accounts, or providers**. The data plane resolves the selected identity to its configured upstream mailbox and transport using trusted local configuration; client-supplied `identityId` is an untrusted selector, never an upstream mailbox path, credential or provider ID.
- `mail_list_identities` / `GET /v1/identities` returns **all identities granted to that caller that are allowed to be discovered**, each with its **own effective action set**. A client may list/search/read using identity A, then send using identity B with **the same access token and MCP connection**, without new authorization or separate MCP sessions.
- **Each mail operation targets exactly one explicit `identityId`** in v1. There is no `allMailboxes`, implicit default identity, or cross-identity search/list endpoint. An agent can issue multiple separately authorized operations and combine only the results it is itself allowed to see.
- Grants and disclosure policy are evaluated **for the selected identity** on every call. The union of a token's identities must **not** union their permissions: `mail:messages:read` on identity A and `mail:messages:send` on identity B does not grant read on B or send on A. A credential cannot access another mailbox by passing its message ID with a different `identityId`.
- Cursor tokens, message projections, attachment handles, send idempotency keys, MRTR `requestState`, Tasks handles, and subscription resource revisions/notifications are scoped to the **specific selected identity**, principal, credential and policy generation. Reuse across identity boundaries is denied without revealing whether the target resource exists.
- For resource subscriptions, a single authenticated `subscriptions/listen` request may list **multiple permitted** `corvi:///identities/{identityId}/visible-mail` URIs, with an acknowledged authorized subset. No change event is emitted for a nonpermitted identity or for hidden-only changes.
- Credential revocation, per-identity grant changes, and identity removal invalidate only the relevant authorizations and dependent state according to the configured revocation guarantees; they must never silently expand another identity's visibility.

**Non-goal:** A token with permission to manage mail-provider resources or a broadly named OAuth scope does not automatically get personal message access. Identity grants always remain explicit and enforceable.

## 1. Resource model

### MailIdentityView

A safe client-visible identity includes `id`, `address`, optional `displayName`, and action names **effective for that particular identity and caller**. It never includes upstream IMAP/SMTP credentials, management secrets, other aliases, or raw provider identifiers.

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

1. Authenticate the caller and validate token issuer/audience/expiry, active credential and the selected identity's explicit grant (which may be one of many identity grants on the same credential).
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

**Agent confirmation:** Interactive MCP `mail_send` requires **MRTR form elicitation**, with a signed expiring `requestState` bound to the exact payload, principal, identity and idempotency key. On resume Corvi revalidates policy, identity, approval and replay protection before contacting SMTP. Only an explicitly scoped unattended-send grant may bypass this step. A model-generated claim of approval is not authorization; non-MRTR clients fail closed with `CONFIRMATION_REQUIRED`. REST sends retain their separate authorization/approval workflow.

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
- Initial mail tools remain exactly the seven operations listed above. Each exposes strict `inputSchema`, `outputSchema`, and structured content. **MRTR, subscriptions and Tasks are MCP protocol mechanisms, not additional mail tools.**
- In MCP, `tools/list` and `tools/call` are **not permission grants**. Tool discovery may vary with the authenticated user but is never a substitute for per-call permission checks. Use private/no-cache lists by default.
- Support **read-only MCP context resources** for server overview, caller-discoverable identities, safe policy guidance and per-identity effective permissions, plus the existing scoped `corvi:///identities/{identityId}/visible-mail` revision resource. `resources/list` enumerates only permitted concrete URIs, `resources/read` returns bounded filtered `application/json` text, and `subscriptions/listen` emits `notifications/resources/updated` only when that caller's permitted view changes. The separate `mail:messages:subscribe` grant is required alongside list permission for visible-mail revision resources. Raw message resources, policy matcher dumps, prompts and sampling remain deferred. See [the machine-readable resource catalogue](../../api/mcp-resources.json).
- Support **MRTR** for sending confirmation and the official opt-in **Tasks extension** (`io.modelcontextprotocol/tasks`), initially for long-running `mail_search` with durable task storage. See [MCP spec](../spec/mcp.md) for full lifecycle and safeguards.
- Support for older `2025-11-25` handshake-based clients is a **future compatibility choice**; it is not implied by serving the modern protocol. If added, test both eras with distinct lifecycle/transport expectations.

The MCP specification sources used for these protocol-level decisions are the published [2026-07-28 specification announcement](https://blog.modelcontextprotocol.io/posts/2026-07-28/) and [2026-07-28 changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog).

## 7. MCP read-only context resources

The MCP server supports **host-selected, read-only resource context**, but never exposes a raw message or attachment via a resource URI. This provides a discoverable representation for clients that prefer loading context without tool calls. The stable design catalogue and validation schemas are in [`api/mcp-resources.json`](../../api/mcp-resources.json).

| URI | Intent | Grant boundary |
| --- | --- | --- |
| `corvi:///context/overview` | Public mail gateway capabilities and high-level privacy constraints, without mail content | Any authenticated Corvi mail data-plane caller |
| `corvi:///context/identities` | All caller-discoverable identities with their **individual** permitted actions | `mail:identities:list`, filtered per identity |
| `corvi:///context/policy-summary` | Safe behavioral guidance, redaction/hidden-result caveats and send approval expectations | Authenticated Corvi caller; no private filter logic |
| `corvi:///identities/{identityId}/context` | Authorized identity metadata, effective permissions and non-sensitive usage/isolation context | Caller may discover that specific identity |
| `corvi:///identities/{identityId}/visible-mail` | Opaque current revision for the caller-visible inbox, not mail data | Selected identity's `mail:messages:list` + `mail:messages:subscribe` |

These resources are **projections of the same effective authorization state** as `mail_list_identities`, not independent privilege grants. A token with identities across different physical mailboxes can discover multiple concrete resource URIs in **one** `resources/list` response. Switching between them requires no token change. The context identity list must exactly match the discoverable identity set and permissions from the corresponding tool/REST operation.

The server must return `ttlMs: 0`, `cacheScope: "private"` for `resources/list` and `resources/read`, and reauthorize each resource URI on every read and subscription event. Context changes can trigger `notifications/resources/updated`, and changes to the caller-visible resource list can trigger `notifications/resources/list_changed`. No notification may expose identity grants from another caller, or signal hidden-only mail changes. Expose concrete authorized URIs through `resources/list`; an unrestricted template-enumeration API is not part of v1.

The `policy-summary` resource is deliberately **high-level guidance**. It must not reveal private matching rules, classifier details, hidden message evidence, provider/SMTP/IMAP credentials, raw message indexes or internal administrative settings. `resources/read` cannot become a second path to unsanitized data. See [MCP server spec](../spec/mcp.md) for wire behavior.

## 8. MCP interactive and asynchronous facilities

**MRTR:** `mail_send` returns `resultType: "input_required"` with a form `elicitation/create` request for approval. The resumed `tools/call` must provide an affirmative `inputResponses` and an authenticated, expiring `requestState`. Corvi must reauthorize and verify the exact outgoing message before sending. No SMTP side effects occur before approval.

**Subscriptions:** For callers with both `mail:messages:list` and `mail:messages:subscribe`, a `corvi:///identities/{identityId}/visible-mail` resource reports only a per-caller opaque visible-state revision. `subscriptions/listen` acknowledges permitted URIs and sends `notifications/resources/updated` for changes **visible after filtering**. Hidden-only mailbox activity must not generate observable notifications. Streams are best-effort and not a replay log; reconnecting clients refetch their permitted view.

**Tasks:** When the optional durable data-plane task backend is available, Corvi advertises `io.modelcontextprotocol/tasks`. A task-capable `mail_search` call can return `resultType: "task"` only after a retrievable task has been persisted. Clients use `tasks/get`, `tasks/update`, `tasks/cancel`; authorized clients can subscribe to `notifications/tasks` through `subscriptions/listen` with task IDs. Recheck identity, scopes and filtering on task polling, result reads and notifications. Tasks are not mandatory for standalone deployments. Other operations (e.g. sync/classification) can be added as future task-eligible tools only after explicit authorization design.

These features **do not change** the shared REST application service or expose any provider-management controls. They must never bypass message isolation or policy decisions.

## 9. Control-plane and operational boundaries

The public `/v1` and `/mcp` endpoints never expose mail-provider domain, mailbox, alias or plugin-management operations. A separate authenticated administrative API, possibly on a separate listener, will be specified independently. SMTP AUTH submission calls the same action/identity policy layer; it is not mapped into arbitrary MCP tool calls.

Rate limiting, tracing, error details and audit records must be partitioned by principal/identity without including private mail content or individual addresses as metric labels. Corvi's one-container standalone mode remains supported.

## 10. Conformance and release gates

Before considering this API stable, require contract tests that exercise **each operation through REST and MCP using the same fixtures**, including:

1. Same visible messages, redacted fields and attachment availability for the same principal/identity/policy across both transports.
14. One token grants at least two identities backed by different physical mailboxes/providers with different action/disclosure policies; one MCP client can switch between them and use each without reconnecting or changing tokens.
15. A read grant for identity A plus a send grant for identity B never permits reading B or sending A; identity A's message IDs, cursors, attachment IDs, send receipts, subscriptions and Tasks do not become accessible under B.
16. Listing identities returns the caller-visible set with **per-identity** permissions, not the intersection or union of all identities' actions. A single listen stream can include multiple authorized identities and must ignore ungranted or hidden-only updates.
17. Resource context and `mail_list_identities` agree exactly on discoverable identities and effective per-identity permissions, including distinct physical mailbox backends. Guessed/revoked context URIs remain non-enumerating and cannot reveal hidden content or private policy internals.
18. Resource list/read responses have private, immediately stale cache hints; resource change/list-changed notifications reflect only caller-visible state, never hidden-only incoming mail or grants of other principals.
2. Hidden message IDs return non-disclosing 404 or equivalent MCP tool error, including after guessing a valid ID from another identity.
3. No hidden data in search, counts, pagination cursors, snippets, thread metadata or attachment access; no scan-on-list bypass.
4. Tool discovery and cached results cannot expose capabilities/data from another principal.
5. Filter/policy/credential rotation invalidates data projections and cursors; stale tokens fail closed.
6. Sending enforces From, envelope sender and recipient policies, with identical idempotency behavior across transports.
7. Unknown SMTP outcomes are not reported as successful final delivery; process-restart replay limitations are documented and tested.
8. OAuth resource-server metadata, audience validation, invalid Origin/Host, absent or mismatched MCP headers, unsupported MCP protocol version and overly large requests are handled safely.
9. Generated REST clients pass OpenAPI validation; MCP tool input/output schemas pass JSON Schema checks and current protocol conformance suites.
11. MRTR denied, replayed, tampered, modified-message or stale-policy send confirmations never contact SMTP; explicit unattended automation still respects send rules.
12. Hidden-only incoming mail changes do not trigger resource change notifications, and revoked/expired subscriptions stop delivering events.
13. Task handles are durably persisted before return; task IDs are identity-bound, task results re-filter on access, and cancellation is cooperative.
10. Data-plane operations succeed without a control plane, operator, provider-management RPC or optional external policy engine unless configured to require it.

## 11. Skill deliverable

An agent-oriented `SKILL.md` and accompanying examples remain a **required deliverable** alongside the MCP implementation. It must describe accurate server discovery, authentication, identity selection, **loading safe context resources without invoking tools**, tool arguments, permitted read/search behavior, privacy restrictions, redaction semantics, MRTR approval, scoped inbox-change subscriptions, task polling/cancellation, safe sending and idempotent retries. It must be generated/reviewed against the **actual** MCP tool catalog and conformance fixtures, not speculative capabilities. Publishing the spec does not mean the skill or the server is implemented.

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
