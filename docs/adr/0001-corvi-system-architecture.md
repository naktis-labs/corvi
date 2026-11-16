# ADR-0001: Corvi system architecture

- **Status:** Accepted as initial architecture direction; API and CRD schemas remain provisional
- **Date:** 2026-11-15
- **Project:** Corvi (Naktis Labs)
- **Scope:** Standalone mail gateway, optional control plane and Kubernetes operator, provider plugin ecosystem, identity and policy enforcement, telemetry
- **Decision owners:** Project maintainers

## Context

Corvi is an open-source, provider-agnostic mail gateway and management platform. Its initial integration target is Migadu, but it must work with an ordinary existing IMAP/SMTP mailbox without a provider management API, Kubernetes, or any extra container.

The motivating use cases include:

1. Exposing mail operations to applications and AI agents through REST and MCP, with legacy SMTP submission.
2. Giving individual applications narrowly scoped, independently revocable mail identities and credentials.
3. Hiding or redacting sensitive messages, such as one-time codes and password-reset links, from untrusted clients.
4. Sharing one physical mailbox across addresses or aliases without leaking mail between virtual identities, subject to provable isolation guarantees.
5. GitOps-managing provider resources (domains, mailboxes, aliases, forwarding, rewrites and policies), initially replacing ad hoc Migadu/Terraform management.
6. Monitoring provider usage, quotas and health through provider plugins.
7. Remaining useful as a small, self-hosted program even when the control plane is not installed.

The central design constraint is **strict data-plane/control-plane separation**. Neither mail delivery nor mail reads may depend on a Kubernetes operator, Kubernetes admission webhook, or provider-management RPC being reachable.

## Decision summary

Corvi consists of independently deployable components:

- **Data plane:** The standalone mail gateway. Serves REST, MCP, and SMTP submission; authenticates, authorizes, filters, reads IMAP, submits SMTP, and owns optional operational state.
- **Control plane:** Resolves provider settings, reconciles supported upstream resources, issues and rotates gateway configuration/credentials, and publishes versioned configuration snapshots. Optional for standalone deployments.
- **Kubernetes operator:** Optional adapter from CRDs/GitOps to the control plane, managing plugin lifecycle and workload resources. It is never on a live mail-request path.
- **Provider plugins:** Optional, OCI-packaged, provider-specific gRPC services. They resolve per-mailbox IMAP/SMTP transport configuration, may administer upstream resources, and may export upstream provider metrics. They do not require Kubernetes privileges.
- **Built-in generic transport:** IMAP and SMTP clients compiled into the gateway. Their configuration can be supplied directly, with **no provider container, gRPC RPC, operator, or control-plane service**.

No component may silently add a hard dependency on another optional component.

## 1. Component boundaries

### 1.1 Data plane

The data plane implements:

- REST and MCP mail APIs; SMTP AUTH submission for legacy applications.
- Authentication and per-request authorization against the active local policy snapshot.
- Virtual mail identities, mailbox/alias scoping, sender validation, content filtering, and attachment safeguards.
- Provider-neutral IMAP readers and SMTP clients with TLS enabled by default.
- Optional mailbox synchronization, indexing, events, durable outbound queue, and operational audit state.
- An independently operated telemetry endpoint/export pipeline.
- A configuration-consumption interface, never an operator-specific webhook.

The gateway **does not import Kubernetes APIs**, call provider management APIs in message-processing code, or require live plugin resolution when reading or sending mail.

Corvi **does not expose downstream IMAP**. IMAP is an upstream protocol used by the data plane. SMTP is exposed only as a client submission/compatibility interface; it is not intended to be a general-purpose public MX server.

### 1.2 Control plane

The control plane implements:

- Provider discovery, administrative reconciliation, and per-mailbox transport resolution.
- Validation and normalization of plugin responses into provider-neutral configuration.
- Issuance, configuration, and revocation of scoped gateway credentials.
- Publication and rollback of complete, versioned configuration snapshots.
- Reconciliation status, drift detection, provider-level usage and health coordination.

Provider reconciliation and transport resolution are control-plane work; the data plane receives fully resolved endpoints and trusted credential references.

The control plane can be run without a data plane. This supports management-only installations, including managing Migadu domains and aliases without enabling mail access.

### 1.3 Optional Kubernetes operator

The operator:

- Watches CRDs and converts desired state into control-plane operations.
- Deploys and supervises OCI provider-plugin Deployments/Services, including discovery, readiness, configuration and lifecycle.
- Generates or publishes normalized gateway configuration, and reports rollout status.
- Configures mTLS certificate volumes and optional monitoring resources.

It must **not** be called synchronously to authorize a message or supply an IMAP/SMTP endpoint during a mail request. Kubernetes admission webhooks, if introduced, are limited to Kubernetes resource admission and never participate in gateway traffic. Prefer OpenAPI schema and CEL validation where practical.

### 1.4 Provider plugin model

External plugins are OCI images running gRPC servers. The **image** is the only mandatory plugin-specific deployment field; credentials and configuration are optional and provider-dependent. The operator deploys the plugin rather than requiring a separate user-managed HelmRelease.

Plugins advertise capabilities. Three independently usable capability families are defined:

1. **Discovery:** Protocol/capability negotiation, supported resource types, configuration schema and telemetry groups.
2. **Transport resolution:** Return mailbox-specific IMAP and SMTP connection details, supported auth methods, and controlled secret references.
3. **Provider management:** Inspect/apply/delete the upstream resources the provider actually supports; return reconciled state and errors.

Provider management is optional. A transport-only external plugin is valid. A management-only plugin is also valid if transport is not needed. For an external managed provider (such as Migadu), the plugin provides the IMAP/SMTP configuration; the gateway should not hard-code provider hostnames or protocol quirks.

The built-in **generic IMAP/SMTP** implementation is not an OCI plugin or another container. It uses direct configuration and in-process Rust calls, and can run without gRPC.

Provider implementations must not depend on the Kubernetes API or assume they are deployed in a cluster. External providers may be used by a standalone control plane through a configured gRPC endpoint.

## 2. Provider RPC contract

Use Protocol Buffers and gRPC, with versioned packages, such as:

- **corvi.provider.v1.ProviderDiscovery:** GetCapabilities.
- **corvi.provider.v1.TransportResolver:** ResolveMailbox.
- **corvi.provider.v1.ProviderManagement:** GetResource, ApplyResource, DeleteResource.
- **corvi.config.v1.ConfigurationService:** Publish/validate/acknowledge configuration snapshots between control and data planes, if a push interface is enabled.

Provider operations are control-plane RPCs. **No provider RPC is required in the data-plane hot path.** The standalone data plane can load the same normalized schema directly from a file.

Transport resolution returns separate IMAP and SMTP endpoints, TLS modes, authentication mechanisms/usernames, and trusted references to credentials. It can include a revision/expiry so the control plane can refresh the result. IMAP and SMTP may have different credentials or endpoints.

Plugin-supplied secret identifiers are untrusted input. They must be mapped through a control-plane-owned allowlist and never treated as arbitrary Kubernetes Secret names, paths, or requests for secret access. Never return plaintext credentials in transport descriptors. Upstream credential provisioning, where a provider API can generate a secret only once, requires a dedicated narrow secret-handoff flow.

Plugin gRPC must use deadlines, bounded request/response sizes, health/readiness probes, structured status errors, retry guidance, semantic version negotiation, and capability-level authorization. gRPC does **not** replace the REST/MCP/SMTP mail-facing interfaces.

## 3. Config delivery, lifecycle and failure behavior

Configuration is expressed as a **provider-neutral versioned snapshot** containing mailbox transport settings, virtual identities, policies, credential verifiers/references, and relevant feature settings.

- Validate a complete snapshot before activation.
- Atomically replace the active snapshot; persist the last known good revision.
- Reject partial, malformed, stale, or unauthorized snapshots without disrupting the active one.
- Report per-replica applied generation and partial rollout status; do not report cluster-wide success prematurely.
- Support rollback and an explicit maximum-staleness policy for security-sensitive credentials.
- Support a standalone YAML/file configuration path without requiring gRPC.
- Do not embed plaintext secrets in ordinary snapshot/log/telemetry payloads.

**Failure invariant:** Existing authorized mail access continues if the operator, provider plugin, Kubernetes API, or control plane becomes unavailable, subject to configured expiry/staleness limits. A failed plugin refresh never downgrades IMAP/SMTP security or silently relaxes policy.

Revocation is only immediately effective on replicas that have received the new configuration (or a separately authenticated emergency revocation update). Short-lived credentials and revocation propagation monitoring mitigate that unavoidable offline tradeoff. Critical authorization should be rechecked when queued operations execute, not just when first accepted.

## 4. Mail identities and security

### 4.1 Separation of physical mailbox and virtual identity

A physical **Mailbox** represents upstream message storage/access. A **MailIdentity** represents an authorized address, sender persona, and restricted logical view over a mailbox.

A MailIdentity specifies:

- Physical mailbox reference and permitted inbound addresses/routing.
- Inbound provenance/isolation policy.
- Permitted From and SMTP envelope-sender identities.
- The policies and credentials that may act on its behalf.

A **MailCredential** references **one or more explicitly permitted identities**, each with its own applicable action grants and policies. This includes identities on **distinct physical mailboxes and upstream providers**, all usable by **one MCP/REST access token** without reconnecting or authenticating separately per mailbox. Requests explicitly select an `identityId`, and Corvi resolves its backing mailbox from trusted configuration; permissions and disclosure policies are never unioned across identities. A credential granting read on identity A and send on identity B does not grant send on A or read on B. Credentials can be per-app/per-agent, read-only, send-only, or restricted to specified actions per identity. REST/MCP bearer credentials and SMTP AUTH credentials may have different issuance and verification mechanisms, but resolve to the same policy enforcement model. Default deny applies everywhere.

### 4.2 Provable alias isolation

A single upstream IMAP mailbox containing messages for multiple aliases is **not sufficient evidence of original SMTP envelope recipient**. To/Cc headers can differ from delivery recipients (BCC, forwarding, lists, rewrites and forged headers).

Define explicit isolation modes:

- **verified:** Only if trusted provider-supplied envelope-recipient metadata or trusted server-side routing proves which identity may see a message. Fail closed when evidence is unavailable.
- **bestEffort:** Header/rule-based filtering with an explicit **non-security-grade** warning; never present as strict confidentiality.
- **dedicated:** A physically separate upstream mailbox or equivalent trusted delivery boundary per identity.

Require verified provenance for strong multi-tenant guarantees; never silently downgrade verified to bestEffort. Isolation must apply to reads, search, pagination, counts, threads, unread metadata, event streams, attachment URLs, sent-mail access and indexes. Cross-identity information leaks through counts or search timing are in scope.

Outbound SMTP submission must authenticate a credential and enforce both From headers and SMTP MAIL FROM/envelope sender. Server-side policy determines whether identity delegation or alternate senders are permitted.

### 4.3 Sensitive mail, content and attachment handling

**Detailed filtering semantics:** See [ADR-0003: Mail filtering and disclosure policies](0003-mail-filtering-and-disclosure-policies.md) for matcher types, rule evaluation, conflict precedence, failure behavior, redaction and API-wide disclosure protections.

Policies support action-level permissions (list/read/search/send/flags/delete/attachments, etc.) and content handling policies including denial, redaction, and optional quarantine of messages containing OTPs, account recovery links, credentials and other sensitive content.

Security-sensitive filtering occurs **before** messages enter client-visible caches, indexes, snippets, search results, embeddings or notifications. Treat email content, links, and attachments as untrusted; never allow instructions inside messages to modify authorization or tool behavior. Strip/block remote HTML content and unsafe attachment types by policy. Redact secrets in traces/logs and protect signed attachment URLs.

Provider forwarding, rewriting, catchalls, delegation and other upstream delivery changes can bypass isolation and therefore require separate high-privilege administrative permissions and auditing.

### 4.4 Trust boundaries

- The data plane gets upstream mail credentials, but not provider administrative credentials.
- The control plane may get provider admin credentials but must not gain unbounded access to message content.
- External provider plugins run with minimal filesystem, network and Kubernetes permissions; restrict egress to their intended provider endpoints where practicable.
- OCI images should be digest-pinned, scanned, and deployable with restrictive security contexts.
- Split administrative APIs from public mail APIs; protect internal configuration publication with strong authentication and independent authorization.
- Log privileged mutations and revocations; avoid storing full message bodies or secrets in administrative audit logs.

## 5. Mail APIs and operational semantics

### 5.1 Client APIs

Expose provider-neutral REST and MCP operations for mail listing, reading, searching, threading, structured metadata, attachments, sending and supported mutations. Use stable gateway-visible message identifiers and cursor-based pagination instead of leaking raw IMAP concepts.

**Public API specification:** [ADR-0005](0005-public-mail-api.md), [OpenAPI 3.1](../../api/openapi.yaml) and the [MCP 2026-07-28 contract](../spec/mcp.md) define the proposed initial subset. In v1, conversation/thread grouping may be represented by an opaque ID, but separate conversation browsing, message mutations and event streaming remain deferred until their permission and filtering semantics are specified.

SMTP submission is a legacy compatibility listener with per-identity SMTP AUTH and strict server-side sender enforcement. It is not a second authorization system.

For application integrations, optionally support SSE/webhook notifications and MCP-compatible notifications for message-received, message-changed and delivery-status events. Public application webhooks are distinct from Kubernetes admission webhooks and from internal gRPC.

### 5.2 SMTP delivery

Support independently selectable modes:

- **Direct relay (minimum deployment):** Relay to upstream SMTP and acknowledge successful acceptance only after upstream acceptance. No durable local queue is mandatory.
- **Durable queued submission (optional):** Persist before acknowledging receipt, retry safely with backoff, track delivery state, and keep the queue in the data plane.

Once Corvi accepts responsibility for a queued message, it must retain sufficient durable state to retry or surface failure. REST/MCP sends should support idempotency keys and explicit queued/submitted/failed/unknown statuses. Exactly-once delivery cannot be guaranteed in the presence of ambiguous upstream SMTP outcomes.

### 5.3 IMAP and message state

Implement upstream IMAP connection pooling and incremental synchronization where enabled. Identify upstream messages by account + folder + UIDVALIDITY + UID, not by untrusted Message-ID headers. Use IDLE and CONDSTORE/QRESYNC when advertised, with polling/fallback reconciliation.

Multiple data-plane replicas may serve reads, but synchronization ownership/checkpoints should be coordinated (leases/fencing), preventing concurrent writers from corrupting state. Event and index semantics must honor isolation and deletions/moves/expunges.

### 5.4 State ownership

Separate three categories:

1. **Desired state:** GitOps/standalone files and control-plane reconciliation.
2. **Active configuration:** Immutable versioned snapshots consumed and persisted by the data plane.
3. **Operational message state:** Queues, mailbox checkpoints, indexes, idempotency records and relevant delivery/audit events, owned by the data plane.

A durable database/queue is optional for the single-process synchronous path. It may become required for explicitly enabled queued delivery, indexing or multi-replica coordination. The control plane never owns the SMTP queue.

## 6. Declarative management and CRDs

The optional operator exposes these provisional API concepts, with names and field shapes subject to review:

| Resource | Purpose |
| --- | --- |
| **MailProvider** | Provider instance, built-in transport settings or OCI plugin image, admin configuration, credentials, capability status |
| **MailDomain** | Upstream domain lifecycle and provider reference |
| **MailDomainPolicy** | Spam, catchall, quota defaults, protocol/security controls and other supported domain settings |
| **Mailbox** | Physical upstream mailbox, provider reference, lifecycle and credential bindings |
| **MailAlias** | Alias and internal destination mapping, potentially multiple destinations |
| **MailForwarding** | External forwarding and its confirmation/expiration policy |
| **MailRewrite** | Ordered/pattern-based address rewrite rules |
| **MailIdentity** | Virtual view and sender identity over a mailbox |
| **MailPolicy** | Action-level grants and references to applicable disclosure filters; never broadens identity scope |
| **MailFilterPolicy** | Declarative message visibility, classification, redaction, attachment and rendering restrictions (see ADR-0003) |
| **MailCredential** | Scoped gateway authentication material, issuance/revocation lifecycle |

**Mailbox lifecycle** must distinguish provider-managed creation/reconciliation from **External** existing mailboxes that Corvi merely accesses.

For **MailProvider**:

- A built-in generic provider requires no OCI image, no plugin Deployment and no provider management access; its IMAP/SMTP connection parameters come from user configuration.
- An external provider requires its OCI image, and may supply resolved transport settings, management capabilities and exporter metrics.
- If provider administration is enabled but the gateway is disabled, the operator still reconciles domains/mailboxes/aliases/etc.
- If only transport is configured, Corvi must not attempt provider administration.

CRDs must not copy provider API objects wholesale. Generic resource schemas should represent common semantics, with an explicit namespaced provider-specific extension/config section where unavoidable. Status must distinguish unsupported capability, not configured, validation failure, provider outage and actual drift. Do not attempt destructive reconciliation for API operations a provider does not support.

### 6.1 Migadu initial adapter

The Migadu plugin is the initial external provider implementation. Its planned administrative and telemetry surface includes, **subject to API capability detection and validation**:

- Domains: list/get/create/update, configuration, spam/catchall/defaults, DNS record guidance and activation/diagnostic status, usage where exposed.
- Mailboxes: lifecycle, passwords/secret rotation, usage, per-mailbox limits, delegations, protocol access and expiration where available.
- Aliases and external forwardings: destinations, confirmation and expiration semantics.
- Sender identities: create/update/list as supported by the upstream API.
- Address rewrites: pattern/local-part rule, ordering and destinations.
- Upstream usage/quota measurements and domain/mailbox health.

Do not invent unimplemented Migadu delete endpoints, account-plan quota endpoints, or trusted original-recipient metadata. Supported operations and the difference between measured usage and configured limits must be made explicit by capability discovery and documentation.

The initial adapter should remove the need to maintain a separate Terraform workflow for supported Migadu resources.

## 7. Transport security and certificate lifecycle

**TLS is mandatory for all inter-component gRPC. Use mTLS for authenticated control-plane RPC connections.** This includes operator/controller ↔ external provider and control plane ↔ data-plane configuration publication. Validate certificate chain **and authorized workload identity** (DNS SAN and/or configured URI/SPIFFE-like identity). Never downgrade to plaintext on errors.

Upstream IMAP/SMTP uses verified TLS by default (implicit TLS or STARTTLS as applicable) and must not silently fall back to cleartext. Public REST/MCP/SMTP listeners must support proper TLS termination.

In Kubernetes, integrate opportunistically with **cert-manager**:

1. Prefer the **cert-manager CSI driver** for per-Pod ephemeral certificates when available and usable.
2. Fall back to a cert-manager **Certificate** resource and Secret-mounted certificate/key when CSI is unavailable.
3. Allow explicitly supplied certificate/key/CA files for standalone or custom PKI deployments.
4. If no selected certificate source is ready, hold the affected internal RPC listener unready rather than starting insecurely.

The operator manages CSI volume attributes, Certificate resources, pod mounts, issuer references and rotation/reload behavior; plugin images only consume certificate paths. CSI capability selection happens during reconciliation, not while handling requests. If certificate provisioning later fails, retain valid credentials when possible and report degradation rather than switching to plaintext.

**Do not depend on trust-manager.** Distribute a separately configured trusted CA bundle using mounted files or operator-managed ConfigMaps. Never implicitly trust a CA merely because it appears in an issued leaf certificate bundle. Support CA overlap during rotation.

Kubernetes admission webhooks, if ever necessary, require normal HTTPS and CA injection; they do not gate mail request processing.

## 8. Observability and upstream-provider exporters

Use OpenTelemetry instrumentation, with independent Prometheus pull and/or OTLP push support. Every component and provider plugin can export its **own internal health/latency** as well as relevant **upstream provider state**.

### 8.1 Instrumentation

Standardize bounded labels and metric families for:

- Provider gRPC operations, latencies, errors, retries, rate limits, readiness and successful reconciliation.
- Gateway HTTP/MCP/SMTP request volume/latency, authorization denials, upstream IMAP/SMTP failures and queue/synchronization health.
- Configuration generation, last successful publication, rollout success, staleness and per-replica readiness.

Use standard OpenTelemetry RPC semantic conventions where possible, rather than duplicating standard gRPC metrics. Propagate W3C trace context through provider gRPC; create spans for resource reconciliation and upstream provider HTTP calls. Never capture tokens, message bodies, authentication headers or mail contents in telemetry.

### 8.2 Plugin-as-exporter capability

Each provider plugin may additionally collect upstream API usage, quota, and health observations. Capability discovery declares supported telemetry groups such as domain_usage, mailbox_usage, mailbox_limits, domain_health and account_usage.

For Migadu, examples include incoming/outgoing usage, domain/mailbox storage consumption, configured limits, send/receive availability, DNS readiness and throttling/quotas **where the API really exposes them**. Account-plan-wide quota must not be synthesized from unrelated mailbox limits; missing values are unsupported, not zero. Clearly describe units, measurement intervals and gauge/counter semantics.

Standardize portable metrics under corvi_provider_* (or a documented stable equivalent), with provider-specific metric families permitted for unmatched fields. Domain/address labels and per-mailbox collection should be configurable and privacy-conscious; never label with tokens, arbitrary error strings or message IDs.

### 8.3 Collection and export lifecycle

- Poll provider APIs on configured schedules, with jitter, caching, backoff, API rate-limit compliance and Retry-After handling.
- **Never call an upstream provider API in response to a Prometheus scrape.** Scrapes read cached samples.
- Export scrape/collection success, last successful collection timestamp, and observation age per group.
- Avoid duplicate upstream polling across plugin replicas by selecting a single collection owner or using coordinated state, without giving plugins Kubernetes permissions.
- Keep telemetry failures independent of gRPC provisioning and the mail data plane.
- Do not define a GetMetrics provider RPC. Metrics have their own Prometheus/OTLP protocols.

The operator can opportunistically create a ServiceMonitor when that CRD is available, but must also support standard Prometheus scrape configuration and native OTLP endpoints. Prometheus Operator, a collector and ServiceMonitor are never required. Expose scrape endpoints with appropriately restricted access; use TLS/mTLS for cross-boundary scraping or OTLP as configured. The existing certificate-provisioning strategy applies, with no trust-manager dependency.

## 9. Deployment modes

| Mode | Data plane | Control plane | External plugin | Operator |
| --- | --- | --- | --- | --- |
| **Minimal standalone gateway** | Yes | No | No | No |
| **Standalone gateway with managed external provider** | Yes | Optional standalone controller | Optional | No |
| **Management-only** | No | Yes | As required | Optional |
| **Full Kubernetes/GitOps** | Yes | Yes | As required | Yes |

The acceptance target for **minimal standalone** is a single gateway process/container with a local configuration file and upstream IMAP/SMTP credentials. REST, MCP and authenticated SMTP submission work without Kubernetes, provider plugins, an external database, an OTel Collector or Prometheus.

Kubernetes deployments independently scale gateway, controller/operator and provider plugins. NetworkPolicies, ServiceAccounts and runtime credentials must reinforce the control/data plane division. Existing mail operations must remain available during operator/provider/collector outages, within explicit snapshot and credential expiry policies.

## 10. Rejected approaches

- **Operator webhook on the data-path:** rejected; creates availability coupling to Kubernetes infrastructure.
- **Mandatory OCI plugin for generic IMAP/SMTP:** rejected; unnecessary process/container for the basic use case.
- **Gateway querying provider RPC for each mail operation:** rejected; transport resolution belongs to configuration/control plane.
- **REST webhooks as provider plugin protocol:** rejected in favor of versioned protobuf/gRPC.
- **Provider-specific mail transport built into the gateway:** rejected; upstream variations belong to provider resolver or generic config.
- **Mandatory cert-manager, trust-manager, ServiceMonitor or collector for standalone use:** rejected; infrastructure integrations must remain optional.
- **Filtering shared mailboxes only by To/Cc while claiming strict isolation:** rejected; recipient provenance must be established by a trusted source.
- **Exposing raw upstream mail/admin credentials to apps and agents:** rejected; credentials must be scoped and independently revocable.

## 11. Consequences and trade-offs

The strict boundary improves resilience, auditability, least privilege and portability, at the cost of designing a robust configuration snapshot schema and reliable revocation propagation.

Provider plugins increase interoperability but introduce an untrusted executable supply chain and separate compatibility/versioning concerns. They must be sandboxed and capability-tested.

Verified alias isolation is not achievable for all arbitrary IMAP inboxes without a trusted delivery provenance signal; some installations must use dedicated mailboxes or explicitly accept bestEffort behavior.

Queuing, indexing, synchronization and HA create operational state, even though the minimum implementation stays lightweight. These are feature-specific complexity costs, not implicit mandatory infrastructure.

## 12. Implementation sequence

1. **Foundations:** Repository structure, provider-neutral config model, policy engine, built-in IMAP/SMTP transport, single-process REST/MCP/SMTP listeners.
   - Specify REST and MCP public contracts and ship a maintained **agent-facing MCP skill** (`SKILL.md`, examples and usage/safety guidance) once the MCP tools are implemented; test the skill against the actual server rather than documenting speculative tool names.
2. **Identity and safety:** Credentials, MailIdentity/MailPolicy, sender enforcement, confidential-message filtering, strict isolation capability classification.
3. **Control plane and protobuf:** Provider discovery, transport resolver, management API, immutable config snapshots and rollout acknowledgment.
4. **Migadu plugin:** Implement only documented/supported management operations, transport resolution and upstream usage/health exporter.
5. **Kubernetes operator:** CRDs, provider Deployment lifecycle, cert-manager CSI/Certificate negotiation, GitOps reconciliation and status.
6. **Scale/operability:** Durable optional queue, IMAP synchronization, events/indexes, multi-replica coordination, telemetry/alerts.

## 13. Architectural invariants to test in CI

- A standalone gateway starts with no Kubernetes, provider plugin, gRPC control service, external database or collector.
- Dependency checks prohibit data-plane imports of Kubernetes, operator or provider-management modules.
- Data-plane mail requests still succeed after the control plane and provider plugin are stopped, within explicit validity constraints.
- Rejected config snapshots preserve the previous valid generation; partial rollouts are reported.
- gRPC without valid TLS and authorized peer identity fails closed; no protocol downgrade is possible.
- External provider plugin crashes do not interrupt existing gateway mail sessions.
- Cross-identity reads, searches, counts, threads, attachments and events do not leak hidden messages.
- Verified alias isolation rejects messages lacking trusted recipient provenance; it never silently becomes bestEffort.
- SMTP AUTH cannot impersonate unauthorized header From or envelope senders.
- Sensitive message content cannot reach client-visible indexes or notifications before policy enforcement.
- Queued SMTP acknowledgment requires persistence; direct-relay acknowledgment requires upstream acceptance.
- Mailbox synchronization handles UIDVALIDITY changes, moves, deletes and concurrent workers.
- Scraping metrics never triggers upstream API calls; metrics/OTLP outages do not block provisioning or mail operations.
- Provider usage metrics report unavailable quotas as unsupported, not fabricated.
- Kubernetes CSI/Certificate fallback does not introduce trust-manager or certificate downgrade dependencies.

## 14. Open design questions

These are deliberately left for follow-up ADRs rather than assumed settled:

- Exact protobuf messages, schema compatibility/version migration and per-capability error models.
- Snapshot persistence and transport (file, pushed gRPC, or another authenticated publication channel); reload atomicity across large fleets.
- Credential custody, encrypted secret-at-rest implementation, rotation and emergency revocation distribution.
- Provider extension fields and admission/defaulting strategy in CRDs.
- Exact trusted recipient provenance mechanisms achievable with Migadu; criteria for verified isolation.
- State backend for optional queue/index/synchronizer and cross-replica ownership.
- Event delivery contract and retention semantics.
- Telemetry naming stability, collector ownership in HA, privacy policy and alert thresholds.
- License, threat-model review, support/versioning matrix, release packaging and public API stability policy.

---

This ADR records agreed architectural direction, not a claim that all features are implemented. Schemas and example component names are illustrative until corresponding code and API specifications land.
