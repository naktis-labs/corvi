# ADR-0001: Corvi system architecture

- **Status:** Accepted as initial architecture direction; API and CRD schemas remain provisional
- **Date:** 2026-11-15
- **Project:** Corvi (Naktis Labs)
- **Scope:** Standalone mail gateway, optional control plane and Kubernetes operator, provider plugin ecosystem, identity and policy enforcement, telemetry
- **Decision owners:** Project maintainers

## Context

Corvi is an open-source, provider-agnostic mail gateway and management platform. Its initial provider-management target is Migadu, but it must work with an ordinary IMAP/SMTP mailbox without a provider management API, Kubernetes, or any extra container. **Native JMAP** is a second first-class upstream mail access and submission protocol, initially validated against Fastmail; see [ADR-0007](0007-native-jmap-transport.md).

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

- **Data plane:** The standalone mail gateway. Serves REST, MCP, and SMTP submission; authenticates, authorizes, filters, reads using native IMAP or JMAP, submits upstream via SMTP or JMAP, and owns optional operational state.
- **Control plane:** Resolves provider settings, reconciles supported upstream resources, **supports privileged interactive provider OAuth connection onboarding**, issues/rotates gateway configuration and credentials, and publishes versioned snapshots. In Kubernetes mode it persists management state **only via CRDs, status, Secrets references and Leases**, with **no control-plane database**. Optional for standalone deployments; a local CLI may complete an upstream OAuth grant when no controller is running.
- **Kubernetes operator:** Optional adapter from CRDs/GitOps to the control plane, managing plugin lifecycle and, when opted in through a **CorviGateway** deployment CRD, gateway runtime workloads. The gateway can also remain directly owned by its app-template Helm chart without the operator. See [ADR-0012](0012-corvi-gateway-deployment-crd.md). The operator is never on a live mail-request path.
- **Provider plugins:** Optional, OCI-packaged, provider-specific gRPC services. They resolve per-mailbox IMAP/SMTP or JMAP transport configuration, may administer upstream resources, and may export upstream provider metrics. They do not require Kubernetes privileges. **Bridge-backed providers** (e.g. Proton Mail via a local bridge) are explicitly supported through OCI metadata hints, verified capability discovery and optional bridge lifecycle management; see [ADR-0006](0006-local-transport-bridges.md).
- **Built-in generic transports:** IMAP, SMTP and JMAP clients compiled into the gateway. Their configuration can be supplied directly, with **no provider container, gRPC RPC, operator, or control-plane service**.

No component may silently add a hard dependency on another optional component.

## 1. Component boundaries

### 1.1 Data plane

The data plane implements:

- REST and MCP mail APIs; SMTP AUTH submission for legacy applications.
- Authentication and per-request authorization against the active local policy snapshot. **Corvi is an OAuth protected resource server** for REST/MCP and may also host an optional OAuth authorization server; all identity grants are owned and enforced by Corvi, even when login is federated through an external OIDC provider (ADR-0009).
- Virtual mail identities, mailbox/alias scoping, sender validation, content filtering, and attachment safeguards.
- Provider-neutral IMAP/JMAP readers and SMTP/JMAP submitters with verified TLS and common access/filtering rules.
- Optional mailbox synchronization, indexing, events, durable outbound queue, and operational audit state.
- An independently operated telemetry endpoint/export pipeline.
- A configuration-consumption interface, never an operator-specific webhook.

The gateway **does not import Kubernetes APIs**, call provider management APIs in message-processing code, or require live plugin resolution when reading or sending mail.

Corvi **does not expose downstream IMAP or JMAP**. Both are upstream protocols used by the data plane. SMTP is exposed only as a client submission/compatibility interface; it is not intended to be a general-purpose public MX server.

### 1.2 Control plane

The control plane implements:

- Provider discovery, administrative reconciliation, and per-mailbox transport resolution.
- Validation and normalization of plugin responses into provider-neutral configuration.
- Issuance, configuration, and revocation of scoped gateway credentials.
- **Corvi-facing OAuth authorization:** interactive client authorization/consent (Authorization Code + PKCE), limited service principals (Client Credentials), client registration (CIMD and preregistration), per-MailIdentity grants, refresh/revocation and trusted external OIDC federation, without mixing provider OAuth tokens (ADR-0009).
- **Provider-side interactive OAuth onboarding** through an authorized administrative flow, with PKCE, provider consent, protected upstream token handoff/refresh and explicit account binding. Client→Corvi authorization is separate; see [ADR-0008](0008-interactive-upstream-oauth.md).
- Publication and rollback of complete, versioned configuration snapshots.
- Reconciliation status, drift detection, provider-level usage and health coordination.

Provider reconciliation and transport resolution are control-plane work; the data plane receives fully resolved endpoints and trusted credential references. **Kubernetes CRD spec/status is authoritative for provider-management state**, not an SQL registry or synchronized database copy. Corvi's integrated OAuth issuer may share an executable with a control-plane component, but its transactional OAuth grants/token families use the **separate OAuth state store**, not Kubernetes reconciliation state (ADR-0010).

The control plane can be run without a data plane. This supports management-only installations, including managing Migadu domains and aliases without enabling mail access.

### 1.3 Optional Kubernetes operator

The operator (deployed using the [hardened bjw-s app-template chart model](0011-hardened-helm-deployment.md)):

- Watches CRDs and converts desired state into control-plane operations. Uses the Kubernetes API directly for provider management persistence, `status.conditions` and `observedGeneration` for status, `resourceVersion` for optimistic updates, finalizers for cleanup, and `Lease` objects for leader election; **no operator SQL database**.
- Optionally reconciles namespaced **CorviGateway** CRDs into hardened gateway Deployments/StatefulSets and ClusterIP Services, only when the gateway is not Helm-managed (ADR-0012).
- Deploys and supervises OCI provider-plugin Deployments/Services, including discovery, readiness, configuration and lifecycle. It enforces **the same non-root, capability-free, no-privilege-escalation, read-only-root, RuntimeDefault-seccomp and no-default-service-account-token policy** for dynamically generated plugin and managed bridge Pods as Helm uses for static Pods. Incompatible managed images fail reconciliation (ADR-0011).
- Generates or publishes normalized gateway configuration, and reports rollout status.
- Configures mTLS certificate volumes and optional monitoring resources.

It must **not** be called synchronously to authorize a message or supply an IMAP/SMTP/JMAP endpoint during a mail request. Kubernetes admission webhooks, if introduced, are limited to Kubernetes resource admission and never participate in gateway traffic. Prefer OpenAPI schema and CEL validation where practical.

### 1.4 Provider plugin model

External plugins are OCI images running gRPC servers. The **image** is the only mandatory plugin-specific deployment field; credentials and configuration are optional and provider-dependent. The operator deploys the plugin rather than requiring a separate user-managed HelmRelease.

Plugins advertise capabilities. Three independently usable capability families are defined. **Upstream protocol** (IMAP, SMTP, or JMAP) and **transport topology** (direct, or existing/managed bridge for IMAP/SMTP) are separate dimensions. Read and submission protocols are chosen independently. OCI image metadata can offer pre-deployment hints, but cannot automatically authorize arbitrary containers/secrets.

1. **Discovery:** Protocol/capability negotiation, supported resource types, configuration schema and telemetry groups.
2. **Transport resolution:** Return independent upstream read/submission protocol selections and mailbox-specific IMAP/SMTP endpoints or JMAP Session URL/account/capability descriptors, verified bridge readiness where needed, and controlled secret references.
3. **Provider management:** Inspect/apply/delete the upstream resources the provider actually supports; return reconciled state and errors.

Provider management is optional. A transport-only external plugin is valid. A management-only plugin is also valid if transport is not needed. When the provider supports **independent application credential issuance**, discovery must declare the exact `appCredentials.types` (`mcp`, `rest`, `smtp`) and native `appCredentials.granularities` (`providerIdentity`, `providerMailbox`), including revocation support. Capability advertising alone does not prove safe issuance; token creation and credential handoff remain verified, privileged control-plane operations (ADR-0014). For an external managed provider (such as Migadu), the plugin provides the IMAP/SMTP configuration; the gateway should not hard-code provider hostnames or protocol quirks.

The built-in **generic IMAP/SMTP and native JMAP** implementations are not OCI plugins or additional containers. They use direct configuration and in-process Rust calls, and can run without gRPC.

Provider implementations must not depend on the Kubernetes API or assume they are deployed in a cluster. External providers may be used by a standalone control plane through a configured gRPC endpoint.

## 2. Provider RPC contract

Use Protocol Buffers and gRPC, with versioned packages, such as:

- **corvi.provider.v1.ProviderDiscovery:** GetCapabilities.
- **corvi.provider.v1.TransportResolver:** ResolveMailbox.
- **corvi.provider.v1.ProviderManagement:** GetResource, ApplyResource, DeleteResource.
- **corvi.config.v1.ConfigurationService:** Publish/validate/acknowledge configuration snapshots between control and data planes, if a push interface is enabled.

Provider operations are control-plane RPCs. **No provider RPC is required in the data-plane hot path.** The standalone data plane can load the same normalized schema directly from a file.

Transport resolution returns independently selected read and submission transports, their endpoints, TLS modes, account bindings, authentication mechanisms and trusted credential references. JMAP includes HTTPS Session discovery, account capability validation and optional sender Identity binding. It can include a revision/expiry so the control plane can refresh the result. IMAP and SMTP may have different credentials or endpoints. **Some providers require a local proxy/bridge**; discover its requirement from typed OCI metadata hints plus authenticated `GetCapabilities`, then publish validated local transport settings only after bridge initialization. The bridge is a lifecycle dependency, not a provider RPC on the data-plane request path. [ADR-0006](0006-local-transport-bridges.md) specifies deployment and trust requirements.

Plugin-supplied secret identifiers are untrusted input. They must be mapped through a control-plane-owned allowlist and never treated as arbitrary Kubernetes Secret names, paths, or requests for secret access. Never return plaintext credentials in transport descriptors. Upstream credential provisioning, where a provider API can generate a secret only once, requires a dedicated narrow secret-handoff flow. Credential-producing resources can publish same-namespace **generated app-credential Secrets** with custom name/annotations and complete protocol-specific connection settings; the credential must be issued for the actual gateway/direct target, never copied from provider admin material. See [ADR-0014](0014-generated-app-credentials-and-connection-secrets.md).

Plugin gRPC must use deadlines, bounded request/response sizes, health/readiness probes, structured status errors, retry guidance, semantic version negotiation, and capability-level authorization. gRPC does **not** replace the REST/MCP/SMTP mail-facing interfaces.

## 3. Config delivery, lifecycle and failure behavior

Configuration is expressed as a **provider-neutral versioned snapshot** containing mailbox transport settings, virtual identities, policies, credential verifiers/references, and relevant feature settings. In operator mode the snapshot is derived through **`MailIdentity.spec.mailboxRef → Mailbox.spec.providerRef → MailProvider.spec.gatewayRef? → CorviGateway`**; `gatewayRef` is optional, and providers without it are managed but **not exposed by any gateway**. No gateway-side identity list or implicit cross-gateway access exists. Missing or migrating parent edges fail closed (ADR-0013).

- Validate a complete snapshot before activation.
- Atomically replace the active snapshot; persist the last known good revision.
- Reject partial, malformed, stale, or unauthorized snapshots without disrupting the active one.
- Report per-replica applied generation and partial rollout status; do not report cluster-wide success prematurely.
- Support rollback and an explicit maximum-staleness policy for security-sensitive credentials.
- Support a standalone YAML/file configuration path without requiring gRPC.
- Do not embed plaintext secrets in ordinary snapshot/log/telemetry payloads.

**Failure invariant:** Existing authorized mail access continues if the operator, provider plugin, Kubernetes API, or control plane becomes unavailable, subject to configured expiry/staleness limits. A failed plugin refresh never downgrades IMAP/SMTP/JMAP security, silently changes protocols or relaxes policy.

Revocation is only immediately effective on replicas that have received the new configuration (or a separately authenticated emergency revocation update). Short-lived credentials and revocation propagation monitoring mitigate that unavoidable offline tradeoff. Critical authorization should be rechecked when queued operations execute, not just when first accepted.

## 4. Mail identities and security

### 4.1 Separation of physical mailbox and virtual identity

A physical **Mailbox** represents upstream message storage/access. A **MailIdentity** represents an authorized address, sender persona, and restricted logical view over a mailbox. In Kubernetes, **`MailIdentity.spec.mailboxRef` selects its single parent Mailbox, `Mailbox.spec.providerRef` selects its single MailProvider, and `MailProvider.spec.gatewayRef` optionally selects its single CorviGateway**. Mailbox and identity parent refs are required, provider gatewayRef is optional; any specified reference is typed and same-namespace. The operator derives the gateway's identities by following only explicitly bound providers, rather than storing inverse lists on CorviGateway ([ADR-0013](0013-mail-resource-ownership-graph.md)). These are logical parent links, never Kubernetes ownerReferences that cascade-delete upstream accounts.

A MailIdentity specifies:

- Physical mailbox reference and permitted inbound addresses/routing.
- Inbound provenance/isolation policy.
- Permitted From and SMTP envelope-sender identities.
- The policies and credentials that may act on its behalf.

**Generated `MailCredential` resources have one typed `targetRef` (`MailIdentity` or `Mailbox`) and one `mcp`/`rest`/`smtp` Secret type (default `smtp`). A validation webhook enforces that gateway-scoped credentials target a `MailIdentity` with permissions, while unbound provider-native requests omit permissions and use the provider's verified native identity or mailbox granularity** (ADR-0014). Separately, an **interactive Corvi OAuth grant** may authorize **one or more explicitly permitted identities**, each with its own action grants and policies. An OAuth grant is **bound to an authenticated principal, specific OAuth client, Corvi mail-resource audience, current grant revision and individually consented identity/action sets**. OAuth scopes alone cannot authorize an identity; only the intersection of token claims, approved grant and current MailPolicy can authorize a call. (See ADR-0009.) This includes identities on **distinct physical mailboxes and upstream providers associated with the same Corvi gateway/audience**, all usable by **one MCP/REST access token** without reconnecting or authenticating separately per mailbox. An identity owned by a different gateway/resource audience is **not** implicitly included in that access token. Requests explicitly select an `identityId`, and Corvi resolves its backing mailbox from trusted configuration; permissions and disclosure policies are never unioned across identities. An OAuth grant granting read on identity A and send on identity B does not grant send on A or read on B. Credentials can be per-app/per-agent, read-only, send-only, or restricted to specified actions per identity. REST/MCP bearer credentials and SMTP AUTH credentials may have different issuance and verification mechanisms, but resolve to the same policy enforcement model. Default deny applies everywhere.

### 4.2 Provable alias isolation

A single upstream IMAP mailbox containing messages for multiple aliases is **not sufficient evidence of original SMTP envelope recipient**. To/Cc headers can differ from delivery recipients (BCC, forwarding, lists, rewrites and forged headers).

Define explicit isolation modes:

- **verified:** Only if trusted provider-supplied envelope-recipient metadata or trusted server-side routing proves which identity may see a message. Fail closed when evidence is unavailable.
- **bestEffort:** Header/rule-based filtering with an explicit **non-security-grade** warning; never present as strict confidentiality.
- **dedicated:** A physically separate upstream mailbox or equivalent trusted delivery boundary per identity.

Require verified provenance for strong multi-tenant guarantees; never silently downgrade verified to bestEffort. Isolation must apply to reads, search, pagination, counts, threads, unread metadata, event streams, attachment URLs, sent-mail access and indexes. Cross-identity information leaks through counts or search timing are in scope.

Outbound submission must authenticate a credential and enforce both From headers and SMTP/JMAP envelope sender, as well as validated upstream JMAP Identity binding where applicable. Server-side policy determines whether identity delegation or alternate senders are permitted.

### 4.3 Sensitive mail, content and attachment handling

**Detailed filtering semantics:** See [ADR-0003: Mail filtering and disclosure policies](0003-mail-filtering-and-disclosure-policies.md) for matcher types, rule evaluation, conflict precedence, failure behavior, redaction and API-wide disclosure protections.

Policies support action-level permissions (list/read/search/send/flags/delete/attachments, etc.) and content handling policies including denial, redaction, and optional quarantine of messages containing OTPs, account recovery links, credentials and other sensitive content.

Security-sensitive filtering occurs **before** messages enter client-visible caches, indexes, snippets, search results, embeddings or notifications. Treat email content, links, and attachments as untrusted; never allow instructions inside messages to modify authorization or tool behavior. Strip/block remote HTML content and unsafe attachment types by policy. Redact secrets in traces/logs and protect signed attachment URLs.

Provider forwarding, rewriting, catchalls, delegation and other upstream delivery changes can bypass isolation and therefore require separate high-privilege administrative permissions and auditing.

### 4.4 Trust boundaries

- The data plane gets upstream mail credentials, including securely stored/provider-refreshed OAuth access tokens where enabled, but not provider administrative credentials. A provider OAuth token is never a Corvi client token; see [ADR-0008](0008-interactive-upstream-oauth.md).
- The control plane may get provider admin credentials and temporary provider OAuth **onboarding** tokens for a strictly authorized account-connection flow, but must not gain unbounded access to message content. Ordinary configuration snapshots must not contain raw OAuth access or refresh tokens.
- External provider plugins **must run as numeric non-root with all capabilities dropped, privilege escalation prohibited, RuntimeDefault seccomp and read-only image root** in Kubernetes; restrict egress, writable mounts, and secret access to intended provider endpoints. Provider plugins, bridges, gateway, OAuth service and maintenance Jobs have **no Kubernetes API token by default**; only the dedicated namespaced operator SA gets explicit RBAC (ADR-0011).
- OCI images should be digest-pinned, scanned, and deployable with restrictive security contexts.
- Split administrative APIs from public mail APIs; protect internal configuration publication with strong authentication and independent authorization. Separate **mail-resource** and **administration** OAuth audiences: a mail OAuth token cannot manage upstream provider OAuth grants, provider mailboxes or administrative secrets. See [ADR-0009](0009-corvi-oauth-and-identity-grants.md).
- Log privileged mutations and revocations; avoid storing full message bodies or secrets in administrative audit logs. Generated app-token Secrets must not leak into CRD status, annotations, ConfigMaps, public MCP resources or Helm values; Secret writers have isolated, namespaced RBAC and independent admission rules for creation (ADR-0014).

## 5. Mail APIs and operational semantics

### 5.1 Client APIs

Expose provider-neutral REST and MCP operations for mail listing, reading, searching, threading, structured metadata, attachments, sending and supported mutations. Use stable gateway-visible message identifiers and cursor-based pagination instead of leaking raw IMAP or JMAP identifiers.

**Public API specification:** [ADR-0005](0005-public-mail-api.md), [OpenAPI 3.1](../../api/openapi.yaml) and the [MCP 2026-07-28 contract](../spec/mcp.md) define the proposed initial subset. The MCP server additionally exposes bounded, caller-authorized **read-only context resources** (server overview, authorized identities, safe policy guidance, and per-identity context) plus visible-mail revision resources. These are not new routes to raw email or administrative data. In v1, conversation/thread grouping may be represented by an opaque ID, but separate conversation browsing, message mutations and event streaming remain deferred until their permission and filtering semantics are specified.

SMTP submission is a legacy compatibility listener with per-identity SMTP AUTH and strict server-side sender enforcement. It is not a second authorization system; it may submit upstream via SMTP **or JMAP**.

For application integrations, optionally support SSE/webhook notifications and MCP-compatible notifications for message-received, message-changed and delivery-status events. Public application webhooks are distinct from Kubernetes admission webhooks and from internal gRPC.

### 5.2 Upstream submission and delivery

Select upstream SMTP, JMAP, or disabled submission independently of the read protocol. JMAP submission uses authorized `Identity/get`, `Email/set` and `EmailSubmission/set`; the public REST/MCP contract stays unchanged. Modes below apply to both upstream protocols:


- **Direct submission (minimum deployment):** Submit upstream to SMTP or JMAP and acknowledge successful acceptance only after upstream acceptance. No durable local queue is mandatory.
- **Durable queued submission (optional):** Persist before acknowledging receipt, retry safely with backoff, track delivery state, and keep the queue in the data plane.

Once Corvi accepts responsibility for a queued message, it must retain sufficient durable state to retry or surface failure. REST/MCP sends should support idempotency keys and explicit queued/submitted/failed/unknown statuses. Exactly-once delivery cannot be guaranteed in the presence of ambiguous SMTP **or JMAP** outcomes. JMAP creation IDs are not durable Corvi idempotency keys; uncertain JMAP sends must never trigger automatic SMTP fallback.

### 5.3 IMAP/JMAP and message state

Implement upstream IMAP connection pooling and incremental synchronization where enabled. Identify upstream messages by account + folder + UIDVALIDITY + UID, not by untrusted Message-ID headers. Use IDLE and CONDSTORE/QRESYNC when advertised, with polling/fallback reconciliation.

For native JMAP, use authenticated RFC 8620 Session and account selection, JMAP `Email/query`, `Email/get`, `Email/changes`/`Email/queryChanges` and bounded blobs. JMAP account/Email/Thread/state identifiers stay internal; all public metadata/search/events are filtered first. JMAP `Mailbox` means a folder/label, not a physical Corvi Mailbox. See [ADR-0007](0007-native-jmap-transport.md).

Multiple data-plane replicas may serve reads, but synchronization ownership/checkpoints should be coordinated (leases/fencing), preventing concurrent writers from corrupting state. Event and index semantics must honor isolation and deletions/moves/expunges.

### 5.4 State ownership

**Storage backend choice:** The **Kubernetes control plane uses Kubernetes itself (CRDs/status/Leases and approved Secret references), without SQLite/PostgreSQL**. [ADR-0010](0010-storage-and-durability.md) separately specifies `ephemeral` for the minimal mail gateway, **SQLite** on local persistent storage for standalone OAuth/queue/sync/tasks, and **PostgreSQL** for multi-replica OAuth/data-plane operational coordination. Secret custody (upstream OAuth refresh, provider passwords, signing keys) is a separate encrypted store; optional object storage and cached inbound mail are opt-in, with filtering and retention safeguards.

Separate three categories:

1. **Desired state:** Kubernetes CRDs and status for operator deployments, or GitOps/standalone files for non-Kubernetes deployments; **no separate control-plane SQL store**.
2. **Active configuration:** Immutable versioned snapshots consumed and persisted by the data plane.
3. **Operational message state:** Queues, mailbox checkpoints, indexes, idempotency records and relevant delivery/audit events, owned by the data plane.

A durable database/queue is optional for the single-process synchronous path. It becomes required for the integrated OAuth issuer, durable tasks/queue, or persistent synchronization; **SQLite embedded mode is enough for one standalone instance**, while multi-replica coordination requires PostgreSQL (ADR-0010). The control plane never owns the outbound SMTP/JMAP submission queue.

## 6. Declarative management and CRDs

The optional operator exposes these provisional API concepts, with names and field shapes subject to review:

| Resource | Purpose |
| --- | --- |
| **CorviGateway** | Optional namespaced gateway runtime instance: replicas, listeners, authorization/state references, resource limits and optional temporary suspension. Its provider/mailbox/identity descendants are **derived, not listed** (ADR-0012/0013) |
| **MailProvider** | **Optional `spec.gatewayRef.name` → CorviGateway** (omitted = provider administration only, no mail-serving gateway), plus built-in IMAP/SMTP/JMAP transport settings or OCI plugin image, optional managed/existing bridge, admin configuration and capability status |
| **MailDomain** | Upstream domain lifecycle and provider reference |
| **MailDomainPolicy** | Spam, catchall, quota defaults, protocol/security controls and other supported domain settings |
| **Mailbox** | **Required `spec.providerRef.name` → MailProvider**, physical upstream mailbox and lifecycle/credential bindings |
| **MailAlias** | Alias and internal destination mapping, potentially multiple destinations |
| **MailForwarding** | External forwarding and its confirmation/expiration policy |
| **MailRewrite** | Ordered/pattern-based address rewrite rules |
| **MailIdentity** | **Required `spec.mailboxRef.name` → Mailbox**, virtual filtered view and sender identity |
| **MailPolicy** | Action-level grants and references to applicable disclosure filters; never broadens identity scope |
| **MailFilterPolicy** | Declarative message visibility, classification, redaction, attachment and rendering restrictions (see ADR-0003) |
| **MailCredential** | **Single credential CRD**, with `targetRef.kind: MailIdentity|Mailbox`, optional `type: smtp|rest|mcp` (defaults to `smtp`) and optional `permissions`. Admission webhook validates the referenced parent graph: bound gateway requires MailIdentity + nonempty permissions and issues Corvi-scoped credentials; unbound provider requires absent permissions and verified native provider identity/mailbox credential support. Issuer revalidates when references change (ADR-0014) |

**Reference hierarchy:** `MailIdentity.spec.mailboxRef` and `Mailbox.spec.providerRef` are **required**; `MailProvider.spec.gatewayRef` is **optional**. When present, gatewayRef is the **only authoritative gateway attachment** for that provider and its descendants. Unbound providers remain available for provider management, but their mailboxes and identities are not served by any gateway; omission is **not** a missing-parent error. All specified references are singular and same-namespace, and the gateway holds **no** inverse child lists. An explicit nonexistent/cross-namespace gatewayRef is invalid and fails closed. The operator reconciles old and new attachments safely; initial binding/reattachment requires appropriate grant revalidation, never automatic privilege expansion ([ADR-0013](0013-mail-resource-ownership-graph.md)). See [ADR-0013](0013-mail-resource-ownership-graph.md), [proposed reference schema](../../api/mail-resource-ownership.schema.json) and [linked example](../../deploy/examples/mail-resource-chain.example.yaml).

**Application credential Secret publication:** The **single** `MailCredential` kind supports `spec.secretTemplate.metadata.name` and custom annotations. It declares one `targetRef`, optional `type: smtp|rest|mcp` (defaults to `smtp`), and optional `permissions`. A **namespaced, read-only validating admission webhook** checks the current target → provider → gateway chain and provider native token type/granularity. When provider is bound, it requires `MailIdentity` + nonempty permissions and produces Corvi-scoped credentials. When provider is **unbound**, it **rejects any `permissions` with `GatewayRequiredForScopedCredential`**; otherwise it can issue verified provider-native per-identity or whole-mailbox credentials for the requested target. The reconciler continuously rechecks referenced resources and capabilities after admission, revoking unsafe outputs. Each output Secret contains only individual, one-type `Secret.data` keys with verified endpoint, TLS/auth, no `connection.json`/`credentials.json` or implicit gateway bypass. Webhook does **not** write Secrets or call the token issuer; a distinct publisher does so with scoped RBAC (ADR-0014, [schema](../../api/generated-connection-secret.schema.json)).

**Mailbox lifecycle** must distinguish provider-managed creation/reconciliation from **External** existing mailboxes that Corvi merely accesses. `MailProvider` and `Mailbox` may refer to a separately permissioned `ProviderConnection` (or equivalent) holding upstream OAuth account binding and protected secret references. Provider OAuth access does not grant clients access to any Corvi identity.

For **MailProvider**:

- A built-in generic provider requires no OCI image, no plugin Deployment and no provider management access; its IMAP/SMTP **or native JMAP** transport settings come from user configuration and the proposed [transport schema](../../api/mail-transport.schema.json). It may use upstream OAuth through an explicitly configured account and **standalone local CLI-assisted login**, without a required provider OCI plugin; provider-specific OAuth client registration constraints still apply.
- An external provider requires its OCI image, and may supply resolved transport settings, management capabilities and exporter metrics. Provider images may declare a **local bridge dependency** via OCI annotations/typed descriptor; the controller verifies metadata against trusted gRPC discovery and administrator-approved image/runtime policy before deploying a bridge.
- **Provider-management-only is the default for an unbound provider:** omit `MailProvider.spec.gatewayRef`, requiring no CorviGateway resource, Pod, mail Service or SQL database. Provider administration can still reconcile domains/mailboxes/aliases/etc. `CorviGateway.spec.suspended: true` is a distinct temporary mail-serving pause for providers already bound to that gateway (ADR-0013).
- If only transport is configured, Corvi must not attempt provider administration.
- Provider-managed app token issuance is **capability-gated per type and native scope**. A provider may issue app credentials restricted to a specific identity or only to a whole physical mailbox; the webhook and issuer must advertise/verify this boundary. A **gatewayless `MailCredential` with `targetRef.kind: MailIdentity` but no `permissions`** fails if only mailbox-wide tokens are supported. Missing provider issuance, real MCP/REST/SMTP endpoint, or safe app-token handoff reports `UnsupportedCredentialIssuance`, `UnsupportedCredentialType` or `UnsupportedCredentialGranularity` rather than publishing a fake or elevated token (ADR-0014).

**Gateway ownership:** Helm-direct and CorviGateway operator-managed workloads are separate deployment choices. Standalone/Helm-direct configurations use the same logical chain without requiring a Kubernetes CRD; a **specified** provider `gatewayRef` in operator mode must resolve to a real namespaced CorviGateway, never silently adopt a Helm-owned Deployment. Never have both controllers mutate one Deployment/StatefulSet, Service or configuration; never auto-adopt Helm-managed objects. CorviGateway must not expose raw PodSpecs, arbitrary images, elevated security contexts or Kubernetes API token configuration. The operator reconciles it under ADR-0011 security invariants and never becomes a synchronous mail dependency ([ADR-0012](0012-corvi-gateway-deployment-crd.md)).

CRDs must not copy provider API objects wholesale. Generic resource schemas should represent common semantics, with an explicit namespaced provider-specific extension/config section where unavoidable. Status must distinguish unsupported capability, not configured, validation failure, provider outage and actual drift. Do not attempt destructive reconciliation for API operations a provider does not support.

### 6.1 Migadu initial adapter

The Migadu plugin is the initial external provider-management implementation. **Native Fastmail JMAP** is an independent mail protocol interoperability target, not evidence of a general Fastmail domain/mailbox provisioning API. Its planned administrative and telemetry surface includes, **subject to API capability detection and validation**:

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

Upstream IMAP/SMTP requires verified TLS (implicit TLS or STARTTLS as applicable); JMAP requires HTTPS with verified TLS and controlled session-discovered endpoints. Neither transport may silently fall back to cleartext. Public REST/MCP/SMTP listeners must support proper TLS termination.

In Kubernetes, integrate opportunistically with **cert-manager**:

1. Prefer the **cert-manager CSI driver** for per-Pod ephemeral certificates when available and usable.
2. Fall back to a cert-manager **Certificate** resource and Secret-mounted certificate/key when CSI is unavailable.
3. Allow explicitly supplied certificate/key/CA files for standalone or custom PKI deployments.
4. If no selected certificate source is ready, hold the affected internal RPC listener unready rather than starting insecurely.

The operator manages CSI volume attributes, Certificate resources, pod mounts, issuer references and rotation/reload behavior; plugin images only consume certificate paths. CSI capability selection happens during reconciliation, not while handling requests. If certificate provisioning later fails, retain valid credentials when possible and report degradation rather than switching to plaintext.

**Do not depend on trust-manager.** Distribute a separately configured trusted CA bundle using mounted files or operator-managed ConfigMaps. Never implicitly trust a CA merely because it appears in an issued leaf certificate bundle. Support CA overlap during rotation.

The **`MailCredential` validating admission webhook** requires normal HTTPS, trusted CA injection and explicit fail-closed CREATE/UPDATE registration. It validates provider/gateway relationships and capability status but never issues tokens, touches Secrets, or gates live mail request processing; issuance and parent-change revalidation belong to the reconciler (ADR-0014).

## 8. Observability and upstream-provider exporters

Use OpenTelemetry instrumentation, with independent Prometheus pull and/or OTLP push support. Every component and provider plugin can export its **own internal health/latency** as well as relevant **upstream provider state**.

### 8.1 Instrumentation

Standardize bounded labels and metric families for:

- Provider gRPC operations, latencies, errors, retries, rate limits, readiness and successful reconciliation.
- Gateway HTTP/MCP/SMTP request volume/latency, authorization denials, upstream IMAP/SMTP/JMAP failures and queue/synchronization health.
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

The acceptance target for **minimal standalone** is a single gateway process/container with a local configuration file and upstream IMAP/SMTP credentials. The same process can optionally use native JMAP with an authorized HTTPS Session URL and token, without a mandatory plugin, controller or Kubernetes. REST, MCP and authenticated SMTP submission work without Kubernetes, provider plugins, an external database, an OTel Collector or Prometheus. A bridge-dependent provider can also be accessed as **an existing locally available IMAP/SMTP bridge** using explicit verified configuration; automatically managing a bridge is optional and never a prerequisite for generic IMAP/SMTP users.

Kubernetes deployments independently scale gateway, controller/operator and provider plugins. NetworkPolicies, ServiceAccounts and runtime credentials must reinforce the control/data plane division. Existing mail operations must remain available during operator/provider/collector outages, within explicit snapshot and credential expiry policies.

## 10. Rejected approaches

- **Operator webhook on the data-path:** rejected; creates availability coupling to Kubernetes infrastructure.
- **Mandatory OCI plugin for generic IMAP/SMTP or standards-based JMAP:** rejected; unnecessary process/container for the built-in transport clients.
- **Gateway querying provider RPC for each mail operation:** rejected; transport resolution belongs to configuration/control plane. Native JMAP is an in-process standard protocol client and does not require a provider RPC in the mail hot path.
- **REST webhooks as provider plugin protocol:** rejected in favor of versioned protobuf/gRPC.
- **Provider-specific mail transport built into the gateway:** rejected; upstream variations belong to provider resolver or generic config.
- **Mandatory cert-manager, trust-manager, ServiceMonitor or collector for standalone use:** rejected; infrastructure integrations must remain optional.
- **Filtering shared mailboxes only by To/Cc while claiming strict isolation:** rejected; recipient provenance must be established by a trusted source.
- **Exposing raw upstream mail/admin credentials to apps and agents:** rejected; credentials must be scoped and independently revocable.

## 11. Consequences and trade-offs

The strict boundary improves resilience, auditability, least privilege and portability, at the cost of designing a robust configuration snapshot schema and reliable revocation propagation.

Provider plugins increase interoperability but introduce an untrusted executable supply chain and separate compatibility/versioning concerns. Native JMAP adds HTTP/JSON session, account and token lifecycle, synchronization, endpoint trust and submission state complexity; it is not a provider plugin. They must be sandboxed and capability-tested. Bridge-backed providers add local application state, account enrollment, key/certificate management, and colocated network topology; OCI metadata only suggests prerequisites and never grants runtime or secret privileges.

Verified alias isolation is not achievable for all arbitrary IMAP inboxes without a trusted delivery provenance signal; some installations must use dedicated mailboxes or explicitly accept bestEffort behavior.

Queuing, indexing, synchronization and HA create operational state, even though the minimum implementation stays lightweight. These are feature-specific complexity costs, not implicit mandatory infrastructure.

## 12. Implementation sequence

1. **Foundations:** Repository structure, provider-neutral config model, policy engine, built-in IMAP/SMTP transport, single-process REST/MCP/SMTP listeners.
   - Specify REST and MCP public contracts and ship a maintained **agent-facing MCP skill** (`SKILL.md`, examples and usage/safety guidance) once the MCP tools are implemented; test the skill against the actual server rather than documenting speculative tool names.
2. **Identity and safety:** Credentials, MailIdentity/MailPolicy, sender enforcement, confidential-message filtering, strict isolation capability classification. Implement Corvi OAuth identity grants and login/consent/token flows (ADR-0009); the issuer can be embedded or federate with a trusted external OIDC login.
3. **Native JMAP:** Implement RFC 8620 Session/capability discovery, JMAP mail reader, attachment reader, filtered synchronization and JMAP submission. Test Fastmail and mixed IMAP/JMAP identities without extending public REST/MCP methods (ADR-0007).
   - **Provider OAuth:** Implement interactive Authorization Code + PKCE, safe local/hosted callbacks and provider-specific registration, encrypted token custody and refresh; then connect JMAP and IMAP/SMTP OAuth mechanisms (ADR-0008).
4. **Control plane and protobuf:** Provider discovery, transport resolver, management API, immutable config snapshots and rollout acknowledgment.
5. **Migadu plugin:** Implement only documented/supported management operations, transport resolution and upstream usage/health exporter.
   - **Bridge compatibility path:** Add the typed provider topology/OCI metadata and local-bridge resolver contract, then test an existing bridge before implementing optional managed-bridge lifecycle or a Proton adapter (see ADR-0006).
6. **Kubernetes operator:** CRDs, optional CorviGateway Deployment/StatefulSet reconciliation, provider Deployment lifecycle, cert-manager CSI/Certificate negotiation, GitOps reconciliation and status.
7. **Scale/operability:** Durable optional queue, IMAP synchronization, events/indexes, multi-replica coordination, telemetry/alerts.

## 13. Architectural invariants to test in CI

- A Kubernetes operator-only management deployment uses **CRDs/status/Secrets/Leases with no separate database**; its reconciler restart recovers from Kubernetes API state. Helm uses [ADR-0011](0011-hardened-helm-deployment.md) rootless, readonly, no-capabilities, RuntimeDefault and narrow token/RBAC defaults.
- A standalone gateway starts with no Kubernetes, provider plugin, gRPC control service, external database or collector. **Enabling Corvi's local OAuth issuer requires persistent grant/refresh/revocation state**, satisfied by embedded SQLite without any external database; a minimal preconfigured-resource-server deployment does not require an integrated issuer.
- Dependency checks prohibit data-plane imports of Kubernetes, operator or provider-management modules.
- The graph `MailIdentity.spec.mailboxRef → Mailbox.spec.providerRef → MailProvider.spec.gatewayRef? → CorviGateway` requires mailbox/provider refs, while gatewayRef is optional. Unbound providers reconcile administrative resources without any gateway; bound providers resolve to exactly one gateway. No inverse identity list or implicit sharing; reparenting/detaching revokes old access and attachment requires verified grants (ADR-0013).
- A CorviGateway-owned workload and a Helm-owned gateway workload can coexist in a cluster but may **never share workload ownership**. Operator-generated gateways use a no-token ServiceAccount and the same rootless, no-capabilities, read-only-root security policy (ADR-0012).
- Data-plane mail requests still succeed after the control plane and provider plugin are stopped, within explicit validity constraints.
- Rejected config snapshots preserve the previous valid generation; partial rollouts are reported.
- gRPC without valid TLS and authorized peer identity fails closed; no protocol downgrade is possible.
- External provider plugin crashes do not interrupt existing gateway mail sessions. A **local transport bridge outage**, unlike a plugin outage, may interrupt the mailboxes that depend on that bridge; unrelated mailboxes remain available.
- Cross-identity reads, searches, counts, threads, attachments and events do not leak hidden messages.
- Verified alias isolation rejects messages lacking trusted recipient provenance; it never silently becomes bestEffort.
- SMTP AUTH cannot impersonate unauthorized header From or envelope senders.
- Sensitive message content cannot reach client-visible indexes or notifications before policy enforcement.
- Queued SMTP acknowledgment requires persistence; direct-relay acknowledgment requires upstream acceptance.
- Mailbox synchronization handles IMAP UIDVALIDITY changes and JMAP state invalidation, moves, deletes and concurrent workers.
- Native JMAP transports work with no controller/plugin/Kubernetes, validate Session URLs/account capabilities, use the same disclosure filters as IMAP, and never automatically fall back to SMTP after ambiguous JMAP sends.
- Scraping metrics never triggers upstream API calls; metrics/OTLP outages do not block provisioning or mail operations.
- Provider usage metrics report unavailable quotas as unsupported, not fabricated.
- The integrated OAuth issuer, durable queue and Tasks reject ephemeral-only storage; SQLite is local/single-instance, while active/active replicas require PostgreSQL. Raw upstream mail never enters a client-visible index or shared cache before identity/disclosure filtering (ADR-0010).
- OCI provider bridge requirements cannot deploy untrusted containers or request arbitrary secrets; bridge capability discovery is validated against administrator-approved **rootless/restricted** runtime profiles (ADR-0011).
- Existing local bridges work without Kubernetes; loopback-only bridges are not silently exposed as routable Services; bridge secret/state and TLS identity remain isolated.
- Kubernetes CSI/Certificate fallback does not introduce trust-manager or certificate downgrade dependencies.

## 14. Open design questions

These are deliberately left for follow-up ADRs rather than assumed settled:

- Exact protobuf messages, schema compatibility/version migration and per-capability error models.
- Snapshot persistence and transport (file, pushed gRPC, or another authenticated publication channel); reload atomicity across large fleets.
- Credential custody, encrypted secret-at-rest implementation, rotation and emergency revocation distribution. Corvi's own OAuth issuer/RAR grant store, CIMD, client consent, refresh-token rotation, external OIDC federation and access-token revocation are specified in [ADR-0009](0009-corvi-oauth-and-identity-grants.md), separate from upstream provider OAuth in ADR-0008. **Provider OAuth browser/CLI consent, PKCE, issuer/redirect safeguards, token refresh/rotation and independent client/connection revocation** follow [ADR-0008](0008-interactive-upstream-oauth.md).
- Provider extension fields and admission/defaulting strategy in CRDs.
- Exact trusted recipient provenance mechanisms achievable with Migadu; criteria for verified isolation.
- State backend for optional queue/index/synchronizer and cross-replica ownership: **SQLite standalone and PostgreSQL HA**, domain-focused state stores and encrypted secret custody are established in [ADR-0010](0010-storage-and-durability.md); exact migrations and driver versions are implementation concerns.
- Event delivery contract and retention semantics.
- Telemetry naming stability, collector ownership in HA, privacy policy and alert thresholds.
- License, threat-model review, support/versioning matrix, release packaging and public API stability policy.

---

This ADR records agreed architectural direction, not a claim that all features are implemented. Schemas and example component names are illustrative until corresponding code and API specifications land.
