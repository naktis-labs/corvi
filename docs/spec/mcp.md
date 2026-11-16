# Corvi MCP server specification (proposed v1)

- **Status:** Proposed, **not implemented**
- **Date:** 2026-11-16
- **MCP protocol target:** `2026-07-28`
- **Additional v1 capabilities:** MRTR elicitation, scoped resource subscriptions, optional Tasks extension
- **Shared API decision:** [ADR-0005](../adr/0005-public-mail-api.md)
- **Machine-readable MCP tool schemas:** [`api/mcp-tools.json`](../../api/mcp-tools.json)
- **REST peer contract:** [`api/openapi.yaml`](../../api/openapi.yaml)

This specification describes the **personal-mail data-plane MCP server**, not the Kubernetes/operator/provider-administration API. The MCP endpoint cannot create domains, aliases, physical mailboxes or provider credentials. Such functionality belongs to a separately authenticated control-plane interface.

## 1. Protocol, discovery and transport

### Target release and lifecycle

Corvi targets the published **MCP 2026-07-28** revision.

- HTTP endpoint: `POST /mcp` using MCP Streamable HTTP and JSON-RPC.
- Modern protocol core is **stateless**: no `initialize` handshake, no required `Mcp-Session-Id`, and no implicit session affinity. Do not copy old `2025-11-25` lifecycle examples into the modern adapter.
- Corvi implements `server/discover` to advertise server identity, supported protocol versions and capabilities.
- Every request carries the **protocol version and client capabilities in `params._meta`**; client software identity is advisory and **not an authentication principal**.
- Every modern HTTP request carries `MCP-Protocol-Version: 2026-07-28`; the body metadata must agree with it.
- Include `Mcp-Method` and, when applicable, `Mcp-Name` headers as required by the transport. The request headers must match the method/tool body.
- Successful results include `resultType: "complete"`. An unsupported protocol version produces the standard MCP `UnsupportedProtocolVersionError`, with supported versions listed, not a successful empty result.
- Support `tools/list` and `tools/call`, MRTR for send approval, narrowly scoped `resources/list`/`resources/read` + `subscriptions/listen` for caller-visible inbox change notices, and the optional Tasks extension when backed by durable state. Raw message resources, prompts, model sampling and unrestricted server-initiated elicitation remain excluded.
- An optional **stdio** adapter may be offered for local, trusted hosts; it must use the same policy engine and tools, and must not implicitly become administrator-privileged.
- `2025-11-25` and other legacy handshake-era compatibility is **deferred**. If enabled, implement the old lifecycle deliberately and test a separate protocol adapter. Do not advertise an unsupported revision.

### Request example

```http
POST /mcp HTTP/1.1
Authorization: Bearer <corvi-scoped-access-token>
Content-Type: application/json
Accept: application/json, text/event-stream
MCP-Protocol-Version: 2026-07-28
Mcp-Method: tools/call
Mcp-Name: mail_search
```

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "mail_search",
    "arguments": {
      "identityId": "identity_opaque_example",
      "query": "invoice",
      "limit": 25
    },
    "_meta": {
      "io.modelcontextprotocol/protocolVersion": "2026-07-28",
      "io.modelcontextprotocol/clientCapabilities": {},
      "io.modelcontextprotocol/clientInfo": {
        "name": "corvi-example-client",
        "version": "0.1.0"
      }
    }
  }
}
```

These placeholders do not describe a deployed endpoint or credentials.

### HTTP security

Reject mismatched `Host`, unexpected browser `Origin`, unsupported media types, oversized requests, invalid protocol/version headers and unauthenticated calls before invoking a mail operation. Restrict allowed hosts/origins in configuration, particularly when accessed through a reverse proxy, to protect against DNS rebinding and cross-site abuse. Protect network-facing endpoints with TLS or a trusted enforcing TLS terminator.

Remote MCP authentication follows MCP OAuth protected-resource guidance. Publish protected resource metadata, identify permitted authorization servers, and validate issuer, **audience/resource binding**, signature (or introspection), expiration, and Corvi-specific identity/action grants. Access tokens must be issued for Corvi, not simply accepted because another service trusts the same OIDC provider. Support issuer-approved scopes and credentials only where configured. Client-declared software identity from `_meta` never substitutes for these checks.

### Output, caching and privacy

For protocol `2026-07-28`, list results include `ttlMs` and `cacheScope`; start with **`ttlMs: 0`, `cacheScope: "private"`** for `tools/list`. Permission-dependent tool visibility must not be cached across principals. Deterministic tool ordering is preferred.

Successful calls return typed `structuredContent` matching the tool's declared `outputSchema`. Also include a JSON text representation in `content` for clients that only expose text results. **Both representations must be generated from the same sanitized result** and neither may contain unfiltered or unauthenticated mail. Because duplicate content increases exposure and token volume, keep results bounded.

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "resultType": "complete",
    "content": [{"type": "text", "text": "{\"items\":[]}"}],
    "structuredContent": {"items": []},
    "isError": false
  }
}
```

The example shows a tool result, not a `tools/list` response. Empty items do not imply no messages exist upstream; they represent an authorized, filtered view.

## 2. Tool catalogue

The **exact proposed seven tools** and machine-readable input/output JSON Schemas are in [`api/mcp-tools.json`](../../api/mcp-tools.json). These tools are a projection over the **same Rust application services** used by REST.

| Tool | Purpose | Permission | REST equivalent |
| --- | --- | --- | --- |
| `mail_list_identities` | Discover only caller-permitted identities | `mail:identities:list` | `GET /v1/identities` |
| `mail_list` | List visible message summaries, newest first | `mail:messages:list` | `GET /v1/messages` |
| `mail_search` | Literal search over permitted subject/text | `mail:messages:search` | `POST /v1/messages/search` |
| `mail_get` | Retrieve a sanitized message projection | `mail:messages:read` | `GET /v1/messages/{messageId}` |
| `mail_get_attachment` | Fetch an allowed attachment as bounded base64 | `mail:attachments:read` | `GET /v1/messages/{messageId}/attachments/{attachmentId}` |
| `mail_send` | Send text-only mail using an authorized identity | `mail:messages:send` | `POST /v1/messages/send` |
| `mail_get_send_status` | Get an authorized outgoing submission | `mail:submissions:read` | `GET /v1/submissions/{submissionId}` |

**Tool discovery is not authorization.** Tool descriptions and annotations (including `readOnlyHint`) are advisory to clients; Corvi evaluates grants, resource membership, filtering and rate limits on every call. The list of tools may be restricted by principal permissions, but a leaked or cached tool definition does not confer access.

All input schemas reject unknown fields. Every mail operation other than `mail_list_identities` requires an explicit `identityId`. A guessed `messageId` or `submissionId` never grants access. Do not add tools that accept upstream IMAP credentials or bypass the Corvi action model.

## 3. Input/output semantics

### `mail_list_identities`

- **Input:** `{}` (no arguments).
- **Output:** `{ "items": [IdentityView, ...] }`.
- Identity entries expose only address/display name, opaque ID and the calling principal's permitted actions. Do not return upstream credentials, hidden aliases or provider administration endpoints.

### `mail_list`

- **Input:** Required `identityId`; optional `limit` (default 25, maximum 100), `cursor`.
- **Output:** `{ "items": [MessageSummary, ...], "nextCursor"?: string }`.
- Sorted by descending received timestamp. No upstream counts, hidden IDs, raw IMAP UIDs, offsets or unfiltered message subjects.

### `mail_search`

- **Input:** Required `identityId`, `query` (1–512 characters); optional `limit`, `cursor`.
- **Output:** Same page schema as `mail_list`.
- In v1, `query` is a **case-insensitive literal substring** over permitted normalized subject/plain-text content. No implicit regular expressions, arbitrary server-side IMAP search syntax, search operators or hidden-body matching.
- A listing or search must complete required message classification before exposing metadata. When the engine cannot safely determine eligibility, hide or fail according to the active policy rather than return an optimistic unfiltered result.

### `mail_get`

- **Input:** Required `identityId`, `messageId`.
- **Output:** `MailMessage`, containing only approved fields, sanitized bodies and permitted attachment descriptors.
- Does **not** mark the message read. Raw MIME is not exposed. A hidden or inaccessible message is treated as not found, without explaining which policy denied it.

### `mail_get_attachment`

- **Input:** Required `identityId`, `messageId`, `attachmentId`.
- **Output:** `{ "id", "fileName", "contentType", "sizeBytes", "dataBase64" }`.
- Maximum decoded content: **2 MiB**. Content is returned only after independent attachment authorization and message-filter re-evaluation. Larger attachments yield `ATTACHMENT_TOO_LARGE`; an authorized REST client may use the streaming attachment endpoint, but MCP never returns public bearer URLs or private raw MIME as an escape hatch.
- Even permitted attachment bytes may contain untrusted or adversarial content. Tool descriptions must not direct an agent to obey instructions inside messages or attachments.

### `mail_send`

- **Input:** Required `identityId`, `to` (nonempty array of email address objects), `subject`, `textBody`, `idempotencyKey`. Optional `cc`, `bcc`.
- **Output:** `Submission` with opaque ID, identity, `queued | submitted | failed | unknown`, timestamps, and `idempotencyDurable`.
- The agent cannot set From, SMTP envelope sender, raw MIME, HTML or arbitrary outgoing attachments in v1. Corvi derives the sender from the authorized identity and validates recipients and send policies.
- A stable idempotency key is generated for one user-intended send, reused only for exact retries. The same key and different payload yields `IDEMPOTENCY_CONFLICT`.
- `submitted` means upstream SMTP accepted it, not that a recipient opened or received it. `unknown` means downstream ambiguity and **must not be automatically resent**.
- This tool is **side-effecting**. Corvi requires the MRTR confirmation flow in §4 unless an explicitly bounded unattended-send grant applies; neither tool annotations nor model text are proof of authorization.

### `mail_get_send_status`

- **Input:** Required `identityId`, `submissionId`.
- **Output:** Same `Submission` schema, reauthorized for the caller.
- Do not return other identities' submissions or arbitrary upstream SMTP recipient details.

## 4. Multi Round-Trip Requests (MRTR): interactive send approval

Corvi uses **MCP 2026-07-28 MRTR** for `mail_send` confirmation. The **default is to require approval**, except when a separately configured, narrowly scoped unattended automation grant explicitly authorizes the send.

1. Validate `mail_send` arguments, sender identity, recipients, action permissions, policy and idempotency key, **without initiating SMTP delivery**.
2. Return an `InputRequiredResult` with `resultType: "input_required"`, an `inputRequests.confirm_send` **`elicitation/create` form**, and an opaque `requestState`. The prompt shows the actual authorized From and recipient addresses, subject, and a safe preview (or digest) of the exact outgoing body.
3. Seal `requestState` using authenticated encryption or a verified MAC. Bind it to the principal/credential, identity, tool, canonical payload hash, idempotency key, policy generation, expiry and one-time nonce. Never treat client-echoed state as trusted.
4. A compliant client obtains a user's response, then **reissues the same `tools/call`** with a new JSON-RPC request ID, the original arguments, `inputResponses.confirm_send`, and byte-identical `requestState`.
5. Require affirmative form input (a validated boolean, not arbitrary conversational text). Revalidate state, payload, permissions, identity, policy generation, nonce and expiry, then apply idempotency before any SMTP action. Declined, altered, expired, tampered or replayed confirmations fail without sending.
6. If the host cannot fulfill form elicitation, return a sanitized `CONFIRMATION_REQUIRED` tool error instead of silently sending. An explicitly authorized unattended automation grant may send without MRTR, but may not bypass server-side action, sender or recipient policy.

Example `InputRequiredResult` (schema shape must be tested against MCP 2026-07-28):

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "resultType": "input_required",
    "inputRequests": {
      "confirm_send": {
        "method": "elicitation/create",
        "params": {
          "mode": "form",
          "message": "Send from agent@example.com to recipient@example.org? Subject: Report",
          "requestedSchema": {
            "type": "object",
            "properties": { "approved": { "type": "boolean" } },
            "required": ["approved"]
          }
        }
      }
    },
    "requestState": "<opaque-expiring-bound-state>"
  }
}
```

MRTR provides a host-mediated approval UI, **not cryptographic proof of human consent** from an untrusted client. The server must enforce unattended-use boundaries, audit decisions, and prevent duplicate sending independently. If a future tool needs both MRTR and Tasks, complete approval **before** materializing a task.

## 5. Filtered subscriptions for incoming mail and task status

Support MCP `subscriptions/listen` over a long-lived **Streamable HTTP POST response**, not legacy `resources/subscribe` or a separate GET stream. To support new-mail notifications using **standard MCP resource updates**, introduce exactly one resource kind:

```text
corvi:///identities/{identityId}/visible-mail
```

- `resources/list` exposes only these resource URIs for identities where the principal has **both** `mail:messages:list` and `mail:messages:subscribe`. `resources/read` returns only `identityId` and an opaque, policy-and-principal-scoped `revision` marker. It does not expose message bodies, IDs, senders, subjects, counts, attachment URLs or raw MIME.
- Clients use `subscriptions/listen` with `notifications.resourceSubscriptions` containing explicitly authorized resource URIs. The first notification is `notifications/subscriptions/acknowledged` identifying the honored subset.
- When the **caller-visible sanitized projection** changes, emit `notifications/resources/updated` for that URI, with the standard subscription metadata; clients refetch through `mail_list` or `mail_search`. Hidden mail arrivals, deletions, reclassifications or other invisible changes must **not** change the revision or trigger notifications. If classification is indeterminate, fail closed.
- On listen, resource read **and before each delivery**, enforce authentication, token lifetime, identity grants, current policy and visibility; terminate or suppress revoked streams. Disallow cross-identity subscriptions and unauthorized task IDs.
- Notifications are **best-effort change hints**, not durable message delivery, replay or a history. They can be coalesced or lost on disconnect; clients refetch after initial subscription and reconnection. Bound stream count, heartbeat, writes and per-principal resource URI lists. In a multi-replica gateway, enable event subscriptions only if correctly scoped fan-out is available; the core read/send path never depends on the optional event bus.
- No general-purpose raw-message MCP resources are added. The resource exists only to support safe `notifications/resources/updated` signaling.

Example `subscriptions/listen` request (with normal version metadata and HTTP headers):

```json
{
  "jsonrpc": "2.0",
  "id": "listen-1",
  "method": "subscriptions/listen",
  "params": {
    "notifications": {
      "resourceSubscriptions": [
        "corvi:///identities/identity_opaque/visible-mail"
      ]
    },
    "_meta": {
      "io.modelcontextprotocol/protocolVersion": "2026-07-28",
      "io.modelcontextprotocol/clientCapabilities": {}
    }
  }
}
```

The same listen stream may receive **Tasks extension** status notifications: the client requests `notifications.taskIds` and, when authorized, receives `notifications/tasks`, which can contain a filtered completed task result. Task subscriptions require per-request `io.modelcontextprotocol/tasks` extension opt-in and task ownership validation. Task statuses may alternatively be polled.

## 6. Tasks extension for long-running operations

Support the **official optional extension** `io.modelcontextprotocol/tasks`. Initially **`mail_search` is the only task-eligible tool**; add task-backed synchronization or bulk classification only after specifying their separate operations, quotas and permissions. Protocol methods are **`tasks/get`, `tasks/update`, `tasks/cancel`**, not extra mail tools.

- The client advertises `io.modelcontextprotocol/tasks: {}` in its per-request `_meta.io.modelcontextprotocol/clientCapabilities.extensions`. Advertise the matching server extension capability in `server/discover` **only when durable task storage is configured and healthy**.
- The server may complete `mail_search` normally or return `CreateTaskResult` with `resultType: "task"`, an opaque unpredictable `taskId`, initial `status`, timestamps, `ttlMs`, and `pollIntervalMs`. **Persist the task durably and make it retrievable before returning the handle.**
- Subsequent `tasks/get` retrieves `working`, `input_required`, `completed`, `failed`, or `cancelled` state. On every call, revalidate the authenticated principal, identity and **current** grants/classification/filter policy; no stored search result or task ID bypasses reauthorization. Invalidate/re-filter results on policy changes, or deny.
- `tasks/update` handles responses to outstanding `inputRequests` when a task is in `input_required`; the initial search task does not ordinarily elicit user input. `tasks/cancel` is cooperative and **does not guarantee cancellation**, particularly for any future action with side effects.
- The client can request `notifications/tasks` through `subscriptions/listen` by passing `taskIds`. Reauthorize each notification and its possible completed result; do not leak private search results via task status. The stream is optional; `tasks/get` polling always remains available while the task exists.
- Over Streamable HTTP, `tasks/get`, `tasks/update` and `tasks/cancel` set `Mcp-Method` to the method and `Mcp-Name` to `params.taskId` as specified by the extension.
- Never return `resultType: "task"` to a client that has not opted into Tasks. If an operation strictly requires Tasks support, return MCP `-32021` (Missing Required Client Capability). Synchronous operations still work without extension support.
- The minimal standalone Corvi gateway can omit durable task support entirely, remaining single-container with no mandatory task database. Optional task storage is **data-plane operational state**, never an operator/control-plane dependency.
- Bound per-principal task counts, CPU/scan time, TTL, polling, memory, stored result sizes and cancellation behavior. Task status and audit output must not contain unfiltered mail.

For `mail_search`, the eventual completed tool result uses the **same JSON Schema, identity, search/filter/pagination and disclosure semantics** as synchronous `mail_search`. Cancellation must not mark messages read or mutate upstream mail.

## 7. Cursors, consistency and error mapping

### Cursors

The paging cursor has a **15-minute expiry** and is cryptographically bound to caller grants, identity, operation, search query, policy revision and a safe mailbox iteration position. On policy change or expiration, return a sanitized `CURSOR_STALE` or `CURSOR_INVALID`; restart search/list from the beginning. Do not emit total hit counts or encode privileged upstream IDs in cursor bytes.

The upstream IMAP mailbox is not a transactional snapshot. Concurrency can create duplicates or gaps; callers must deduplicate by Corvi-issued opaque ID and tolerate changed IDs on untrackable upstream moves or UIDVALIDITY changes. None of these conditions may reveal hidden message content.

### Error surfaces

Separate **MCP protocol errors** (invalid JSON-RPC framing, unsupported protocol version or method, malformed MCP headers) from **tool invocation errors**. A valid tool call that is denied or cannot complete returns a sanitized `CallToolResult` with `isError: true` and a stable, non-sensitive error code; protocol errors use standard JSON-RPC errors.

Proposed tool-visible codes include:

| Code | Meaning |
| --- | --- |
| `NOT_FOUND` | Resource absent, hidden, or outside the authorized identity |
| `FORBIDDEN` | Caller lacks a particular requested operation on an accessible identity |
| `INVALID_INPUT` | Invalid arguments or unsupported send composition |
| `CURSOR_INVALID` | Expired or malformed cursor |
| `CURSOR_STALE` | Caller/filter/snapshot change invalidated cursor |
| `FILTER_UNAVAILABLE` | Eligibility could not be decided safely |
| `UPSTREAM_UNAVAILABLE` | Required upstream operation unavailable |
| `RATE_LIMITED` | Caller exceeded operation budget |
| `ATTACHMENT_TOO_LARGE` | Allowed attachment exceeds MCP byte limit |
| `IDEMPOTENCY_CONFLICT` | Key reused with a different intended message |
| `SEND_OUTCOME_UNKNOWN` | SMTP outcome ambiguous; check submission, do not blindly retry |

Error messages never return message subject, sender, matched security rule, OTP, reset URL, hidden identity, raw upstream UID or provider credentials. Do not distinguish hidden messages from nonexistent messages in either JSON-RPC codes or human-readable text.

## 8. Mandatory filtering invariants

The public MCP adapter must call the same application service and policy pipeline as REST. In particular:

1. Authenticate and validate token/credential scope and requested action.
2. Resolve the authorized `MailIdentity` and verify trusted original-recipient provenance where required.
3. Evaluate required content classifications and all applicable filter policies and obligations.
4. Build a caller-scoped safe projection **before** list/search/snippet/body/attachment output.
5. Reauthorize separate attachment and submission-status requests; never treat a previously issued opaque ID as a bearer capability.
6. Redact or hide consistently across body, HTML, links, thread metadata, search and results. Filter failures fail closed.
7. Do not let tool discovery, resource links, prompt content, cache hints or SDK conveniences bypass any earlier gate.

A filtered-out message cannot be inferred from search hit counts, thread placeholders, "missing" list offsets or success/error distinctions. A visible but redacted message does not gain a hidden raw-text alternative.

## 9. Conformance and implementation guidance

- Validate `api/mcp-tools.json` against MCP's contemporary tool schema, and test example `tools/call` and responses against a current protocol fixture harness. The manifest is a **source document**, not a complete `tools/list` JSON-RPC message.
- Keep input/output schema and permission mappings in sync with `api/openapi.yaml`. Both protocol adapters should call one Rust service, not maintain duplicate business logic.
- Test modern `server/discover`, per-request version metadata, `Mcp-Method`/`Mcp-Name`/version-header validation, origin/host security, the lack of session assumptions and proper result `resultType`.
- Test `tools/list` with two different principals, cached tool metadata, credentials revoked between calls and public/private cache hints.
- Test the same full fixture corpus through MCP and REST for hidden IDs, redaction, metadata/snippet leaks, count-free pagination, big attachments and stale cursors.
- Test sends with approved sender identity, disallowed recipient, duplicate idempotency key, altered request under same key, queued delivery, unknown SMTP acceptance, and direct-relay process restart.
- Never send user email bodies to remote MCP hosts, LLM providers or logs **except through the user's intended, explicitly authorized tool invocation**. Tool return content can be passed by clients to models; policies should default to narrower exposure for agent principals.
- No data-plane operation should depend on the provider-management gRPC service or Kubernetes operator; optional external PDPs may be separately required by explicitly configured policies.

## 10. Agent skill (future deliverable)

The MCP implementation must ship with a documented, versioned agent skill at a planned location such as `skills/corvi-mcp/SKILL.md`, with examples for configuring the MCP endpoint, discovering authorized identities, reading/searching safely, interpreting hidden/redacted results, **fulfilling MRTR approvals**, **subscribing to visible-mail resource changes**, **polling and cancelling Tasks**, generating and retrying idempotency keys, and avoiding prompt injection from mail content.

**Do not publish a skill describing tools as implemented until the server exists and fixtures pass.** The skill must be treated as guidance, not a substitute for any server-side authorization.

## 11. Normative MCP references

- [MCP 2026-07-28 announcement](https://blog.modelcontextprotocol.io/posts/2026-07-28/)
- [MCP protocol 2026-07-28 changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog)
- [MCP 2026-07-28 Streamable HTTP transport](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http)
- [MCP 2026-07-28 version negotiation](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning)
- [MCP 2026-07-28 MRTR and stateless core](https://blog.modelcontextprotocol.io/posts/2026-07-28/)
- [Official MCP Tasks extension](https://tasks.extensions.modelcontextprotocol.io/specification/2026-07-28/tasks)
- [MCP subscriptions SDK guidance](https://ruby.sdk.modelcontextprotocol.io/server/subscriptions/)

Protocol-specific claims above apply to the pinned MCP revision, not automatically to older MCP hosts or future drafts.
