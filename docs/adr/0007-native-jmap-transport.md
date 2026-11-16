# ADR-0007: Native JMAP transport for mail access and submission

- **Status:** Proposed
- **Date:** 2026-11-16
- **Scope:** First-class, in-process JMAP client in the Corvi data plane, alongside generic IMAP/SMTP
- **Related:** [ADR-0001](0001-corvi-system-architecture.md), [ADR-0003](0003-mail-filtering-and-disclosure-policies.md), [ADR-0005](0005-public-mail-api.md), [ADR-0006](0006-local-transport-bridges.md)
- **Proposed configuration schema:** [`api/mail-transport.schema.json`](../../api/mail-transport.schema.json)

## Context and decision

[JMAP core (RFC 8620)](https://www.rfc-editor.org/rfc/rfc8620) and [JMAP Mail (RFC 8621)](https://www.rfc-editor.org/rfc/rfc8621) provide native JSON/HTTPS access to mail, synchronization, submission, blobs and change notifications. [Fastmail](https://www.fastmail.com/dev/) is an initial interoperability target: it supports JMAP mail and submission, in addition to IMAP and SMTP. Its session discovery endpoint is `https://api.fastmail.com/jmap/session`.

**Corvi SHALL implement native JMAP as an optional first-class transport within the Rust gateway**, not a JMAP-to-IMAP proxy, a compulsory OCI provider plugin, or an external sidecar. JMAP and IMAP/SMTP are alternative **upstream** protocol adapters behind the same provider-neutral, policy-enforcing mail application services. The current REST API, MCP tools/resources and downstream SMTP AUTH submission listener remain provider-neutral.

**Native JMAP is an architectural requirement, not yet an implemented library or Fastmail integration.** The minimal standalone IMAP/SMTP deployment remains possible without JMAP, Kubernetes, a control plane or plugins. A standalone gateway configured for JMAP likewise requires only its own JMAP client/configuration/secret provider, not an external JMAP daemon.

## 1. Protocol and topology are different dimensions

Do not conflate:

1. **Read/access protocol:** `imap` or `jmap`.
2. **Submission protocol:** `smtp`, `jmap`, or `disabled`. Each may have a separate upstream credential and a different effective capability.
3. **Physical deployment topology:** direct endpoints, existing IMAP/SMTP bridge, or approved managed IMAP/SMTP bridge as defined in ADR-0006.

Examples:

| Mailbox read | Outgoing send | Deployment | Example |
| --- | --- | --- | --- |
| IMAP | SMTP | direct | Generic standard mail provider |
| IMAP | SMTP | existing/managed bridge | Proton Mail Bridge |
| JMAP | JMAP | direct | Fastmail with mail and submission scopes |
| JMAP | SMTP | direct | Provider with JMAP mail but only SMTP submission |
| JMAP | disabled | direct | Deliberately read-only JMAP account |

JMAP itself is not a "bridge": `https` session/API endpoints are native upstream transport. Existing bridge topology remains a property of IMAP/SMTP endpoints. Where a provider supports both, protocol selection is explicit and deterministic (e.g. `read.protocol: jmap`). An `auto` mode, if added, must use capability discovery and configured preference with a recorded chosen protocol. **Never silently downgrade from JMAP to IMAP/SMTP on authentication, policy, TLS, account mismatch or authorization failures.** Fallback to a separately configured transport requires an explicit policy and full reevaluation of identity/recipient security and snapshot state.

Provider-specific administrative functionality is separate from transport. Fastmail's JMAP Masked Email extension may later be exposed through a narrow provider-management capability, **not** by equating JMAP `Mailbox/set` (folders/labels) with provisioning physical service mailboxes or domains.

## 2. Native Rust transport interfaces

Extend the internal provider-neutral data-plane contract with distinct `MailReader`, `MailSubmitter`, `MailChangeTracker` and `BlobReader` capabilities, implemented by native IMAP/SMTP and native JMAP adapters. The names are provisional; the key requirement is that adapters produce **common, untrusted upstream DTOs** to which the *same* server-side identity and disclosure policies are applied.

- `JmapReader`: session discovery, scoped account selection, `Mailbox/get`, `Email/query`, `Email/get`, `Email/changes`, `Email/queryChanges`, `Thread/get` when required, and bounded download of blobs/attachments.
- `JmapSubmitter`: authorized `Identity/get`, `Email/set` for creating a controlled draft/message, then `EmailSubmission/set` for submission, with careful handling of the optional cleanup/filing steps. Do not accept an arbitrary JMAP `Identity` or draft `Email` ID from an MCP/REST caller.
- `JmapChangeTracker`: use the account's JMAP state tokens, `Email/changes` and `Email/queryChanges` where valid; optionally leverage session `eventSourceUrl` push as an **internal hint** to resync. Corvi's MCP subscription surface must emit only changes to caller-visible projections **after** authorization and filtering, never raw JMAP push events.
- `JmapBlobReader`: guarded, size-limited, authenticated JMAP `downloadUrl` access for permitted attachments. Reauthorize message and blob at retrieval; never return JMAP blob IDs, unaudited upstream URLs or bearer tokens to a mail API client.

The JMAP client handles `using` capability lists, method-call IDs/batching/back-references, account IDs, conditional updates, `notFound`/method errors, RFC 8620 limits and concurrency; none of these internal protocol details becomes a public identity or message ID.

The existing SMTP AUTH listener can call the same authorized `MailSubmitter` service whether the upstream submission transport is SMTP or JMAP. **SMTP at the client-facing edge must not imply SMTP on the upstream side.**

## 3. Session discovery, account selection and credentials

Proposed standalone configuration example (the schema is a **design contract**, not implemented configuration):

```yaml
apiVersion: corvi.naktis.eu/v1alpha1
kind: MailboxTransport
read:
  protocol: jmap
  sessionUrl: https://api.fastmail.com/jmap/session
  account:
    mode: primaryForCapability
    capability: urn:ietf:params:jmap:mail
  authentication: apiToken
  credentialRef: secret://fastmail/jmap
submission:
  protocol: jmap
  sessionSource: reuseRead
  account:
    mode: primaryForCapability
    capability: urn:ietf:params:jmap:submission
  identitySelection:
    selection: byExactEmail
```

The `secret://fastmail/jmap` reference is illustrative; Corvi must resolve it through configured trusted secret backends. The upstream token must include submission permissions for the `submission: jmap` variant; otherwise configure `submission: disabled` or a separately provisioned SMTP sender. JMAP's `accountId` and sender `Identity.id` are validated from the authenticated session and never inferred from a requested Corvi `identityId`.

A normalized JMAP transport descriptor supplies:

- A configured, HTTPS JMAP Session URL, or an explicitly enabled RFC 8620 `/.well-known/jmap` discovery origin; **do not assume** every provider uses Fastmail's URL.
- A trusted upstream credential reference: an **interactive, explicitly consented OAuth 2.0 provider connection** with secure refresh, or a manually supplied provider API token where needed. These credentials remain separate from Corvi client-facing bearer tokens and provider-admin API secrets. [ADR-0008](0008-interactive-upstream-oauth.md) specifies browser/CLI OAuth onboarding, client registration, credential custody and reauthorization.
- An explicit JMAP **account selector**, either `primaryForCapability` or `accountId` (for shared/multi-account providers). Select accounts only from the authenticated Session object's `accounts` and `accountCapabilities`.
- Optional independently selected JMAP submission account and outbound JMAP `Identity` mapping for each Corvi `MailIdentity`, with validated sending addresses and policy. A Corvi `Mailbox` is an **account/mail-store binding**, not a JMAP `Mailbox` folder.

Validate the Session object's `capabilities`, `accounts`, `primaryAccounts`, `accountCapabilities`, `apiUrl`, `downloadUrl`, `uploadUrl` and `eventSourceUrl`. JMAP Mail requires `urn:ietf:params:jmap:core` and `urn:ietf:params:jmap:mail`; native submission separately requires `urn:ietf:params:jmap:submission`, appropriate account capability and at least one validated upstream sending Identity. Don't enable `mail_send` on the strength of mail-read access alone.

**Fastmail:** Prefer interactive OAuth where the deployment has a **supported client registration/redirect mode**, and keep manually generated JMAP API tokens available as fallback. Native/loopback and hosted HTTPS redirect registrations are **not interchangeable** (see [ADR-0008](0008-interactive-upstream-oauth.md)). Upstream scopes include `urn:ietf:params:jmap:core`, `urn:ietf:params:jmap:mail` and optionally `urn:ietf:params:jmap:submission`. Upstream scopes authorize Corvi's backend access **only**; Corvi still issues/checks its own per-client, per-`MailIdentity` grants. Do not repurpose Fastmail's own MCP endpoint or its MCP tokens as Corvi's JMAP transport credentials. See [Fastmail developer API](https://www.fastmail.com/dev/) and [Fastmail API-token documentation](https://www.fastmail.help/hc/en-us/articles/5254602856719-API-tokens).

**SSRF/TLS:** Treat discovery documents, templates, server-directed API/blob/push URLs and redirects as **untrusted URL inputs**. Validate the allowed HTTPS origins, certificate identities, URL schemes, ports, DNS resolution, redirect targets and deployment egress policy for *every* endpoint, including downloads and EventSource reconnects. Never follow arbitrary `file:`, `http:`, localhost/private-network, cloud metadata or Unix-socket destinations supplied by upstream discovery unless an administrator explicitly allows an appropriate local trust boundary. Never disable TLS verification; do not log bearer secrets or query strings containing credentials. Refresh upstream OAuth credentials through approved flows, atomically rotate references and fail closed on revoked/expired credentials.

## 4. Mail identities, policy and message mapping

Maintain Corvi's distinction between **physical account access** (`Mailbox`) and **virtual per-client sender/view** (`MailIdentity`). Multiple Corvi identities may map to one JMAP account or several different JMAP accounts, with one Corvi MCP token able to use only the individually granted identities.

- JMAP `accountId`, `Email.id`, `Thread.id`, `Mailbox.id` and `Identity.id` are upstream identifiers and **must never** become authorization credentials or unchecked public IDs. Corvi generates opaque message, conversation, attachment and submission IDs and binds them to its own mailbox/account/identity/policy context. JMAP Email IDs are stable within an account across folder changes, but Corvi must handle deletion, reimport and migration/rebinding.
- JMAP `mailboxIds` denotes folder/label membership, not a different user's physical mailbox and not trusted evidence of a message's original SMTP envelope recipient. RFC 8621 message `to`, `cc`, `bcc`, `deliveredTo`-like headers/keyword metadata are **not automatically proof** of verified alias isolation; keep ADR-0001 verified/dedicated/bestEffort rules and fail closed without trusted provider provenance.
- `Email/query` may be used for **internal candidate discovery and pagination**, but upstream total counts, search snippets, JMAP Thread membership, matched keywords or raw results must not leak through Corvi. Exact Corvi `mail_search` semantics require searching the **permitted normalized projection**. Filtering must be applied before showing result IDs, snippets, counts, thread info or change events; if upstream search cannot safely generate a complete superset of results after filtering/redaction, use an authorized filtered index or bounded safe scan instead of claiming exact results.
- Fetch only needed JMAP properties and blobs; classify before releasing metadata. Treat mail and HTML as untrusted input (including prompt injection); sanitization, attachment permissions and sensitive-message hiding apply identically to IMAP.
- The same `MailFilterPolicy` and policy-engine obligations apply before REST/MCP `mail_list`, `mail_search`, `mail_get`, attachment streaming, change resources, Task results and send-status results.
- Preserve **no implicit cross-account search** in v1: each public operation targets one explicit `identityId`, whether its backing transport is IMAP or JMAP.

## 5. JMAP submission and ambiguous outcomes

Build controlled MIME/email content from the authorized Corvi `MailIdentity` and a sanitized v1 plain-text send request. Validate the selected upstream JMAP `Identity` and From address, recipients, account submission capabilities, envelope sender and recipient list **before** creating/submitting an Email. `Email/set` may create a draft, but **`EmailSubmission/set` is the send operation**; a created draft alone is not a successful submission.

- The existing Corvi idempotency key is bound to the principal, Corvi identity and canonical message. JMAP method-call IDs, creation IDs and state tokens are **not** durable exactly-once delivery guarantees. Persist intent/receipt through Corvi's transactional submission store when durable idempotency is promised (ADR-0010), and reconcile state before repeating a call with ambiguous outcome.
- Network interruption after an `EmailSubmission/set` may leave the result `unknown`. Do not automatically submit a second Email, retry blindly, or report delivered. A successful upstream EmailSubmission response means **upstream accepted for processing**, not remote recipient delivery.
- A JMAP mail read token does not grant JMAP submission. Refresh-token rotation, revoked grants and insufficient scope trigger `needsReauthorization` and fail closed rather than falling back to a less secure credential. In `read: jmap`/`submission: smtp` mode use a **separately configured** SMTP credential with independent sender validation, never automatic fallback from failing JMAP submission.
- If mailbox filing/cleanup fails after a successful submission, report the correct submission status and a separate cleanup diagnostic. Do not resend.
- Outgoing SMTP AUTH compatibility must apply the same identity, recipient, SMTP envelope, MRTR/approval (where relevant to MCP) and application policy as REST/MCP; a JMAP upstream must not bypass these rules.

No claims of atomic send+file, exactly-once delivery or automatic ambiguous-outcome reconciliation until a concrete provider implementation and failure tests demonstrate them.

## 6. Synchronization, change streams and state

Use JMAP's account-local `state` tokens for incremental reconciliation. Persist checkpoints through the selected data-plane state store (SQLite standalone / PostgreSQL HA when enabled; [ADR-0010](0010-storage-and-durability.md)), not the provider plugin or public MCP resources. State and search-query positions belong to **upstream account synchronization**, not to the public Corvi cursor; the latter remains opaque, per-caller/identity/policy-scoped and has its own expiry.

- Handle `cannotCalculateChanges`, invalid state tokens, account permission changes, too-many-changes and JMAP capability loss with **bounded full resynchronization**, safe cursor invalidation and no stale privileged result reuse.
- JMAP EventSource and RFC 8620 push reduce latency but are optional optimizations for the first implementation. Reconnection and polling must be supported. Subscribe only to authenticated, explicitly authorized upstream accounts and validate any server-provided push destination.
- JMAP push notifications describe **upstream state**, not client visibility. The gateway re-runs the relevant classification/disclosure rules and emits MCP `notifications/resources/updated` **only** when a caller-visible state changes. Hidden-only JMAP updates cannot increment visible-mail revision tokens, generate client change notifications or reveal raw provider counts.
- In multi-replica operation, coordinate sync workers, deduplicate updates and honor JMAP per-account concurrency and request limits. A standalone gateway may operate without an external DB and fall back to bounded polling/refresh.

## 7. Provider discovery, configuration and CRD boundaries

The provider plugin's `GetCapabilities` and `ResolveMailbox` are extended to **select mail access/submission protocols independently**. The supported transport families include `imap`, `smtp`, `jmap`; protocol support is not the same as provider-management support or deployment topology.

- For a **generic JMAP provider**, a configured Session URL/account/credential enables the **built-in JMAP client** directly without any OCI plugin, controller, gRPC provider resolution or Kubernetes. Fastmail may be configured this way.
- A provider-specific OCI plugin may optionally discover/reconcile upstream credentials or expose Fastmail-specific **masked-email administration**, but the gateway's JMAP protocol implementation remains in-process and provider-neutral.
- `MailProvider`/Mailbox schema and immutable transport snapshots must include protocol discrimination, session URL, account selector, optional submission Identity mapping, TLS policy, credential references and negotiated capability status.
- OCI bridge metadata/bridge dependency descriptors from ADR-0006 apply **only when IMAP/SMTP actually requires a local bridge**. JMAP requires no local bridge unless a future provider independently mandates a documented special runtime.
- An unknown JMAP capability, unsupported account selection, absent submission scope, invalid session URL or unexpected downgrade blocks only the affected mailbox/operation with an explicit status, not a blind IMAP fallback or disclosure-policy relaxation.

Initial capability status values should differentiate `UnsupportedTransport`, `CapabilityMissing`, `NeedsAuthorization`, `AccountSelectionInvalid`, `SubmissionUnavailable`, `SyncStateInvalid` and `UpstreamUnavailable`; these may be mapped to existing generic client-safe errors without disclosing backend secrets.

## 8. Implementation sequence and acceptance tests

1. Add a **generic normalized transport schema** (see accompanying JSON Schema) and Rust `MailReader`/`MailSubmitter` boundaries, preserving the existing minimal IMAP/SMTP use case.
2. Implement RFC 8620 Session discovery, account and capability validation, HTTPS URL trust checks, request batching/limits, token-auth transport and bounded JSON parsing.
3. Implement JMAP `Email/query`, `Email/get`, `Mailbox/get`, blob reads, filtered list/search and attachment access over the **same** policy pipeline as IMAP.
4. Implement `Email/set` + `Identity/get` + `EmailSubmission/set` with idempotency, sender constraints and unknown-outcome reconciliation; integrate with REST/MCP/SMTP AUTH submission adapters.
5. Add `Email/changes`/`Email/queryChanges`, polling and optional EventSource-to-safe-MCP-subscription change propagation.
6. Test Fastmail with both least-privilege JMAP token fallback **and interactive provider OAuth** (reading and sending separately); add supported native/hosted redirect variants, refresh and reconsent tests under ADR-0008. Provider-specific administrative extensions remain separate independently tested capabilities.

**Required conformance cases:** one MCP credential accessing an IMAP identity and a Fastmail/JMAP identity with separate permissions; wrong accountId/Identity ID selection; missing submission scope; verified alias isolation without trusted provenance; hidden-message search/count/thread/attachment leak attempts; state invalidation and JMAP resync; cross-principal cache leakage; malicious Session-discovered blob/push URL; revoked upstream token; ambiguous EmailSubmission completion; duplicate idempotency key; no SMTP fallback on JMAP failure; intact standalone functionality without plugins/operator.

## References

- [RFC 8620: JMAP core](https://www.rfc-editor.org/rfc/rfc8620)
- [RFC 8621: JMAP Mail and Submission](https://www.rfc-editor.org/rfc/rfc8621)
- [Fastmail developer API, OAuth and Masked Email](https://www.fastmail.com/dev/)
- [Fastmail API tokens](https://www.fastmail.help/hc/en-us/articles/5254602856719-API-tokens)

## Consequences

Native JMAP becomes a first-class, provider-neutral **upstream** transport, enabling efficient access to Fastmail and other RFC-compatible providers without IMAP translation. This adds HTTP/JSON sync, account-scoped identity mapping, session URL trust and submission-state complexity. It does **not** broaden any Corvi client privilege or promise that Fastmail exposes arbitrary physical mailbox/domain provisioning over its public JMAP API.
