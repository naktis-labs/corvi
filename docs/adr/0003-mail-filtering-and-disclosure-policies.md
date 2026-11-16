# ADR-0003: Mail filtering and disclosure policies

- **Status:** Proposed (detailed policy semantics; schema illustrative)
- **Date:** 2026-11-15
- **Related:** [ADR-0001: Corvi system architecture](0001-corvi-system-architecture.md), [ADR-0002: Product goals and future messaging extensibility](0002-product-goals-and-messaging-extensibility.md)
- **Scope:** Data-plane message eligibility, content filtering, disclosure transformations, attachments, search/indexing and policy testability

## Context and problem

Corvi's personal-access goal is to allow agents and self-hosted applications to work with **the user's own mail** without receiving unrestricted upstream credentials or visibility into unrelated or sensitive messages.

ADR-0001 states that the gateway must hide or redact sensitive content, but does not specify actual rules, matching behavior, combination semantics, error handling, or the API surfaces those decisions protect. A policy system that hides OTPs in `GET /messages/:id` but leaks them through search snippets, thread context, attachments, counts, event payloads or logs is not secure.

This ADR establishes an explicit, locally enforced filtering model. It is **separate from provider administration** and must function when the control plane and provider plugins are offline.

## Decision: three independent authorization gates

For any mail operation, Corvi enforces three gates in sequence:

1. **Operation authorization (`MailPolicy`):** Is this authenticated principal/credential allowed to perform this action (list, read, search, send, delete, fetch attachment, mutate flags, etc.) against this identity?
2. **Mailbox/identity boundary (`MailIdentity`):** Is this upstream message provably within the virtual identity's authorized mailbox/address scope? Trusted original-recipient evidence is required when the identity is configured for `verified` isolation. `bestEffort` never claims confidentiality.
3. **Disclosure filtering (`MailFilterPolicy`):** Even if the message is inside the identity's scope, may the principal learn that it exists or see any part of its metadata, body, attachment, or derived output?

A positive result at a later gate **cannot override** denial at an earlier gate. Granting `mail:read` never overrides recipient isolation. A content filter cannot grant access to another identity, and an allow rule cannot make an otherwise unauthorized message visible.

Sending and provider administration remain different authority domains. This ADR governs **disclosure of mail data**; it does not authorize management API writes or broaden SMTP sender permissions.

**Optional external policy evaluation:** See [ADR-0004: Pluggable gRPC policy decision engines](0004-pluggable-grpc-policy-engines.md). An external policy decision point may restrict disclosure or return typed obligations, but Corvi must still locally enforce identity limits, mandatory sensitive-content filtering and sanitization.

## 1. Explicit resource boundary

Keep `MailPolicy` as the action-level policy. Introduce an optional, reusable `MailFilterPolicy` (name provisional) for message-level exposure rules, referenced by `MailPolicy` or assigned to a specific `MailIdentity`.

- **`MailPolicy`:** principal/action/resource grants, plus references to disclosure filters.
- **`MailIdentity`:** upstream mailbox, sender/recipient identity and original-recipient trust/isolation mode.
- **`MailFilterPolicy`:** classification, selectors, visibility decisions, redaction and output transformations.
- **`MailCredential`:** scoped auth material referencing identities and action policy.

Multiple applicable filters **intersect** in the security sense: the most restrictive visibility decision wins and redactions/stripping accumulate. A permissive filter never cancels a denial from another applicable filter. Configurations must identify exactly which filter policies apply to a given credential and identity.

Filters operate on Corvi's normalized message representation, not untrusted raw header text alone. Original upstream bytes, if retained, remain in a privileged store inaccessible to scoped clients.

## 2. Policy evaluation contract

### 2.1 Evaluation inputs

Every filter decision evaluates against a bounded, explicit context:

- Authenticated principal ID, credential ID, allowed `MailIdentity`, action, effective configuration generation.
- Upstream mailbox/message reference and trusted routing provenance (if available).
- Normalized sender, reply-to and recipient fields; distinguish untrusted visible headers from trusted delivery metadata.
- Date, folder/flags, subject and normalized MIME parts.
- Parsed plain-text and sanitized HTML representations; extracted link destinations (including query parameters); attachment type, filename, size and optional scanned content.
- Classification results, including a distinct `unknown` / `indeterminate` state.

A rule is not permitted to infer verified recipient identity from `To` or `Cc`. A missing trusted field must not silently become a match based on an untrusted equivalent.

### 2.2 Supported matcher families

Initially support an auditable declarative subset:

| Matcher | Examples | Caveats |
| --- | --- | --- |
| Trusted identity/provenance | mailbox ID, verified envelope recipient, delivery route | Trust level carried with data |
| Header metadata | sender address/domain, subject, reply-to, normalized visible recipients | Message-authored fields are untrusted |
| Temporal/state | received date, age, folder, flags | Do not leak hidden state via metadata |
| MIME metadata | content type, attachment filename/type/size | Declared MIME types can be forged |
| Parsed content | text/HTML text, URLs, patterns in subject/body | Decode before matching; bound work |
| Classification | authentication OTP, reset link, login link, financial secrets, custom classes | Classifiers have false positives/negatives |
| Boolean composition | `all`, `any`, `not` | Typed and validated; bounded nesting |

Select exact address/domain matching by normalized mailbox/domain semantics, not naive substring checks. Use bounded non-backtracking regular expressions where allowed. Avoid arbitrary policy scripts, remote HTTP lookups, agent-generated decisions, and unconstrained user-supplied code in the mail request path.

Subject/body/URL classification can be heuristic and is **not a cryptographic confidentiality guarantee**. For strict security, prefer trusted routing, known sender restrictions, and conservative deny rules in addition to classifiers.

### 2.3 Decisions and conflict resolution

The filter engine produces a **typed disclosure decision**, not just a boolean:

- **`hide`:** Do not expose the message's existence. No message ID, count, snippet, search result, thread placeholder, event, attachment, or aggregate derived from that message to this principal.
- **`show`:** Expose only the fields and content still permitted by all effective restrictions.
- **`redact`:** Expose a permitted projection with field-level redactions. Redaction may cover subject, body, link targets, address fields, attachment metadata and attachment content access; a response must never expose the original MIME bytes through another endpoint.
- **`strip`/restriction:** Remove HTML remote content, disallow attachments, suppress links or restrict to a sanitized plain-text representation.

**`hide` wins over `show` and `redact`.** Independently matched redactions and restrictions compose conservatively. There is no `stopProcessing` or `allowOverrideDeny` option.

For an explicit policy, `defaultVisibility` is either `hide` or `show`. Newly created, unreferenced or malformed policies grant nothing; only a successful action/identity grant plus an explicitly bound filter can expose mail. A client-facing personal-mail grant should prefer `hide` by default or opt explicitly into `show` after inspection of the policy. `defaultVisibility: show` is a conscious "allow except these categories" choice, not a global authorization bypass.

**Indeterminate decisions** (unparseable MIME, timeout, truncated content, classifier errors, unknown attachment content, inaccessible encrypted content) are distinct from a clean non-match. Each policy must define `onIndeterminate`, with `hide` as the secure default. Security-sensitive rules must not treat a classification failure as "not sensitive."

The engine should return an internal reason code and matched rule IDs for diagnostics, but only an appropriately sanitized result is exposed to scoped callers. Rule matching does not change the upstream message, mark it read, move it, or delete it.

## 3. Illustrative filtering policy

The exact CRD fields are provisional; this shows intended behavior rather than a committed Kubernetes API. The same normalized model must be usable from a standalone configuration file.

```yaml
apiVersion: mail.corvi.naktis.eu/v1alpha1
kind: MailFilterPolicy
metadata:
  name: agent-safe-inbox
spec:
  defaultVisibility: show  # Explicitly opt into "show unless denied"
  onIndeterminate: hide

  rendering:
    html: sanitized
    remoteContent: strip
    attachments: deny
    externalLinks: sanitize

  rules:
    - name: hide-authentication
      when:
        classificationAny:
          - auth.otp
          - auth.password_reset
          - auth.login_link
          - auth.mfa
      then:
        visibility: hide

    - name: hide-banking
      when:
        senderDomains:
          - bank.example
      then:
        visibility: hide

    - name: redact-billing-reference
      when:
        senderDomains:
          - invoices.example
      then:
        redact:
          - field: body.text
            pattern: '\bINV-[0-9]{8}\b'
            replacement: "[REDACTED-REFERENCE]"
```

Example association to an action policy:

```yaml
apiVersion: mail.corvi.naktis.eu/v1alpha1
kind: MailPolicy
metadata:
  name: agent-mail-read
spec:
  actions:
    - mail:list
    - mail:read
    - mail:search
  identityRefs:
    - agent-inbox
  filterPolicyRefs:
    - agent-safe-inbox
```

For example, an AI agent authenticated under this policy cannot see authentication emails or banking mail at all, receives sanitized message representations without attachments, and sees a redacted invoice reference in matching billing messages. **This is best-effort content classification**, not a guarantee that every possible OTP or secret will be recognized. Strong security may require a much narrower allowlist.

An alternative high-assurance policy can use `defaultVisibility: hide` with an explicit, narrow allowed-subset mechanism. In that model, an allowlist grants eligibility **only within** the authenticated identity and only if no applicable rule denies visibility. The exact syntax for positive allow selectors should be specified in the schema ADR.

## 4. Sensitive-content classification

Start with deterministic classifiers for common authentication content:

- `auth.otp`: likely one-time code in surrounding authentication context, not every arbitrary 4–8 digit number.
- `auth.password_reset`: password-reset/recovery intent and links.
- `auth.login_link`: magic links and sign-in confirmation flows.
- `auth.mfa`: second-factor or security approval messages.

Optional classifiers may include `financial.account_identifier`, `credential.secret`, `personal.identity_document` and user-defined rules. Their behavior, confidence/uncertainty, cost and false-negative limitations must be documented.

Scanning includes **subject, decoded plain-text MIME parts, normalized HTML text and actual link destinations**. Links can contain authentication tokens in query strings or paths. Charset/transfer decoding, Unicode normalization and nested multipart processing should precede detection.

Do not treat a probabilistic classifier as the sole hard gate for particularly sensitive mail. Unknown or encrypted payloads may need to be hidden by policy because their contents cannot be inspected. A safe implementation defines resource limits for body size, attachment inspection depth, MIME nesting, decompression and execution time, and routes exceeded limits to `indeterminate`, not `allow`.

Rules intended to redact a specific field must either prove **all exposed representations** of the sensitive value are sanitized or suppress those representations entirely. For authentication content, prefer `hide` over partial redaction.

## 5. Representation and attachment restrictions

Filtering must control more than the plain text body:

- **Metadata:** Subject, sender, participants, threading metadata and flags can be sensitive.
- **HTML:** Sanitize unsafe markup and strip remote resources (images, CSS imports, tracking pixels, forms and scripts); safe rendering must not fetch remote content on behalf of the agent.
- **URLs:** Suppress or sanitize login/reset links and token-bearing URLs; apply policies to URL targets as well as visible anchor text.
- **Attachments:** Independently authorize listing attachment metadata, downloading bytes, inline images and derived previews. MIME type claims are untrusted. Denied attachments must not be available from raw MIME or signed URLs.
- **Previews:** Snippets, summaries, cached previews and any embeddings must be derived only from the principal's permitted representation.
- **Replies:** Do not insert quoted hidden or redacted original content into reply drafts or conversation context.

A "quarantine" disposition, if later supported, means **local restricted visibility** unless a separately authorized upstream mailbox move is explicitly requested. Filtering itself never changes the user's upstream mail state.

If a field cannot be safely transformed, remove or hide the field; if that makes safe disclosure impossible, hide the message.

## 6. Mandatory enforcement surface

The same decision must be enforced on **every** route by which a client could infer or access mail:

| Surface | Requirement |
| --- | --- |
| List/get | Exclude hidden messages before pagination; never return placeholder IDs |
| Search | Match and rank only permitted projections, including mandatory post-filtering of upstream IMAP **or JMAP** search candidates; use filtered indexing/safe scans where upstream search is not a complete superset |
| Counts | Compute unread/total counts from visible messages only; no upstream raw count leakage |
| Threads | Include only visible messages; do not reveal missing hidden members |
| Attachments/raw source | Re-authorize every fetch; deny raw MIME/part URLs that bypass redaction |
| Mutation | Prevent actions on hidden messages and restrict permitted actions on visible ones |
| Events/notifications | Filter before publication or subscription delivery |
| Cached snippets/indexes | Index derived permitted projections, with policy/identity isolation |
| Exports/bulk APIs | Apply the same filters as single-message reads |
| Logs/traces/metrics | No sensitive message data, matched text, original URLs or unbounded private labels |

Search and pagination must not expose hidden-result counts, unfiltered offsets, source UIDs, or cursors that encode privileged information. Query execution may internally use broad upstream search for efficiency, but observable results must be filtered. Explicitly test response metadata and inference channels.

## 7. Execution model and cache safety

The data plane evaluates policy locally using the active, validated configuration snapshot. The control plane defines/publishes policy but never evaluates each mail request. External provider plugins are not called to decide whether a message is safe.

Recommended pipeline:

1. Authenticate the caller, authorize action and resolve the allowed `MailIdentity`.
2. Establish message membership using the identity's configured trusted provenance/isolation mode.
3. Fetch only the upstream fields needed to evaluate filters; decode/parse/scan within resource budgets.
4. Combine every applicable filter deterministically and build a permitted message projection.
5. Serve, search, count, index, notify, or render **only that projection**.
6. Audit the decision using non-sensitive rule identifiers and action metadata.

A metadata-only list cannot optimistically expose headers for a message whose eligibility depends on body content. Use a classification cache or scan-on-demand; if scanning is unavailable, follow `onIndeterminate`.

Any cached projection or precomputed index must be partitioned by the effective principal/identity and policy fingerprint or equivalent non-bypassable access context. Cache keys should account for **message revision, classifier version, filter policy generation, identity isolation evidence and effective grants**. Invalidate or recompute on policy/revocation changes and upstream message updates. Do not expose a globally indexed unredacted snippet to a scoped client.

Implement message-level decisions consistently for streamed and paginated responses. Filtering must never create an untrusted asynchronous "unfiltered first, sanitize later" window.

## 8. Performance and failure policy

Filtering costs can be significant, particularly for search/counts over large mailboxes. Prefer incremental scan caches and bounded background indexing where enabled; do not require an external database in the minimal single-process gateway.

- Bound regex complexity, MIME nesting, attachment inspection, CPU/time/memory use, and concurrency.
- Fail safely when upstream fetch, MIME parsing or classification fails.
- Support rate limiting and backpressure to prevent a client from forcing expensive unlimited mailbox rescans.
- Do not mark messages read as a side effect of scanning unless separately authorized and explicitly requested.
- Preserve the underlying mailbox bytes; policy changes must not destroy the original message.
- Make policy rollout atomic across configuration generations and track applied generations per replica.
- If a classifier version changes, previously cached decisions must be revalidated before disclosure.

The provider and operator can be entirely unavailable while the data plane continues evaluating its current policy snapshot.

## 9. Auditability, debugging, and privacy

Provide a **local privileged policy simulator** to test a policy against fixture messages or authorized samples without sending them to a third-party service. It should explain which rules matched, which conditions were indeterminate, and the resulting sanitized projection.

Audit events should include action, hashed or internal principal/identity IDs, policy generation, decision category and stable rule identifiers. Message subject/body, codes, tokens, raw URLs and sensitive matched values are forbidden in default logs and telemetry.

Publish aggregate counters/latency for policy evaluations, redaction/hide decisions and classifier failures, with bounded labels. Do not publish per-mailbox/message identifiers as metric labels.

Administrators may opt into controlled local debugging of private data, but that requires explicit elevated authorization and safe retention behavior.

## 10. Tests required before releasing scoped reading

1. **Authorization precedence:** Filters never grant missing actions or cross-identity access; deny wins across multiple policies.
2. **Alias isolation:** `verified` fails closed without trusted original-recipient provenance; `bestEffort` is labeled as such.
3. **OTP/reset cases:** Subject-only code, HTML-only code, token in hidden link href, nested MIME, quoted-printable/base64, and password-reset URL.
4. **Classifiers:** False-positive fixtures (invoices with six-digit numbers), negative fixtures, Unicode/charset variants and documented false-negative limitations.
5. **Indeterminate:** Truncated or malformed MIME, oversized body, encrypted attachment, classifier timeout, fetch error and corrupted cache all follow failure policy.
6. **Redaction completeness:** No alternative raw MIME, HTML, attachment, inline preview, reply quotation or search snippet leaks the original.
7. **Search and counts:** Search, cursor pagination, unread counts, threads and notifications cannot reveal hidden messages.
8. **Policy changes:** Cache/index invalidation and revocation prevent stale filtered content from leaking after changes.
9. **Mutation safety:** Hidden message IDs cannot be used to set flags/delete/move without the necessary authorization; hidden mail remains unchanged upstream.
10. **Control-plane outage:** Current snapshot continues enforcing all filters even without the operator, plugins or control plane.
11. **Fuzz/property tests:** MIME parsers, regex/Unicode boundaries, nested attachments, HTML sanitization, and side-channel-sensitive pagination.
12. **Principal separation:** Two agents sharing a physical mailbox can receive different safe projections of the same upstream message without cross-contamination.

## 11. Open questions

- Exact protobuf/YAML/CRD rule schema, versioning, matcher nesting and positive allowlist syntax.
- Standard library and configuration for deterministic classifiers, classification confidence and optional local model-based classification.
- Whether policy-specific index material is persisted, encrypted or computed on demand.
- Search/count query guarantees and upper bounds for large mailboxes when full scanning has not completed.
- Privileged policy preview UX and controlled disclosure of debug reasons.
- Streaming partial content while eligibility evaluation requires scanning the full message.
- Multi-replica cache invalidation and compatibility with policy/configuration snapshot rollouts.

## Consequences

This model lets Corvi implement useful real filtering rules for personal mail, including hiding OTPs, excluding selected senders, redacting structured content and stripping attachments, **without confusing filtering with authorization or provider provisioning**.

It also makes the limitations visible: heuristic content detection cannot certify the absence of secrets, and a shared IMAP **or JMAP account** cannot provide strict per-alias confidentiality without trustworthy recipient provenance.

The initial implementation remains mail-only and standalone-capable. This ADR records the intended semantics; it does not claim that the proposed CRD or classifiers already exist.
