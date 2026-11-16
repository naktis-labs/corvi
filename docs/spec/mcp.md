# Corvi MCP server specification (proposed v1)

- **Status:** Proposed, **not implemented**
- **Date:** 2026-11-16
- **MCP protocol target:** `2026-07-28`
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
- Support `tools/list` and `tools/call`. v1 does not expose resources, prompts, tasks, dynamic sampling, server-initiated elicitation, or an event subscription API.
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
- This tool is **side-effecting**. Clients should request user confirmation unless an explicit unattended send policy applies. The server enforces the policy regardless of agent text; a prompt claiming approval is not authorization.

### `mail_get_send_status`

- **Input:** Required `identityId`, `submissionId`.
- **Output:** Same `Submission` schema, reauthorized for the caller.
- Do not return other identities' submissions or arbitrary upstream SMTP recipient details.

## 4. Cursors, consistency and error mapping

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

## 5. Mandatory filtering invariants

The public MCP adapter must call the same application service and policy pipeline as REST. In particular:

1. Authenticate and validate token/credential scope and requested action.
2. Resolve the authorized `MailIdentity` and verify trusted original-recipient provenance where required.
3. Evaluate required content classifications and all applicable filter policies and obligations.
4. Build a caller-scoped safe projection **before** list/search/snippet/body/attachment output.
5. Reauthorize separate attachment and submission-status requests; never treat a previously issued opaque ID as a bearer capability.
6. Redact or hide consistently across body, HTML, links, thread metadata, search and results. Filter failures fail closed.
7. Do not let tool discovery, resource links, prompt content, cache hints or SDK conveniences bypass any earlier gate.

A filtered-out message cannot be inferred from search hit counts, thread placeholders, "missing" list offsets or success/error distinctions. A visible but redacted message does not gain a hidden raw-text alternative.

## 6. Conformance and implementation guidance

- Validate `api/mcp-tools.json` against MCP's contemporary tool schema, and test example `tools/call` and responses against a current protocol fixture harness. The manifest is a **source document**, not a complete `tools/list` JSON-RPC message.
- Keep input/output schema and permission mappings in sync with `api/openapi.yaml`. Both protocol adapters should call one Rust service, not maintain duplicate business logic.
- Test modern `server/discover`, per-request version metadata, `Mcp-Method`/`Mcp-Name`/version-header validation, origin/host security, the lack of session assumptions and proper result `resultType`.
- Test `tools/list` with two different principals, cached tool metadata, credentials revoked between calls and public/private cache hints.
- Test the same full fixture corpus through MCP and REST for hidden IDs, redaction, metadata/snippet leaks, count-free pagination, big attachments and stale cursors.
- Test sends with approved sender identity, disallowed recipient, duplicate idempotency key, altered request under same key, queued delivery, unknown SMTP acceptance, and direct-relay process restart.
- Never send user email bodies to remote MCP hosts, LLM providers or logs **except through the user's intended, explicitly authorized tool invocation**. Tool return content can be passed by clients to models; policies should default to narrower exposure for agent principals.
- No data-plane operation should depend on the provider-management gRPC service or Kubernetes operator; optional external PDPs may be separately required by explicitly configured policies.

## 7. Agent skill (future deliverable)

The MCP implementation must ship with a documented, versioned agent skill at a planned location such as `skills/corvi-mcp/SKILL.md`, with examples for configuring the MCP endpoint, discovering authorized identities, reading/searching safely, interpreting hidden/redacted results, confirming sends, generating and retrying idempotency keys, and avoiding prompt injection from mail content.

**Do not publish a skill describing tools as implemented until the server exists and fixtures pass.** The skill must be treated as guidance, not a substitute for any server-side authorization.

## 8. Normative MCP references

- [MCP 2026-07-28 announcement](https://blog.modelcontextprotocol.io/posts/2026-07-28/)
- [MCP protocol 2026-07-28 changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog)
- [MCP 2026-07-28 Streamable HTTP transport](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http)
- [MCP 2026-07-28 version negotiation](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning)

Protocol-specific claims above apply to the pinned MCP revision, not automatically to older MCP hosts or future drafts.
