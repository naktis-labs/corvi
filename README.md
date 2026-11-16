# Corvi

**Provider-agnostic, policy-driven mail access and infrastructure management.**

Corvi is a planned open-source mail gateway and management platform from Naktis Labs. It has two complementary goals: **scoped access to the user's own email** for applications and AI agents, without handing out unrestricted mailbox credentials; and **declarative provisioning and management of automated mailboxes** for self-hosted services. These roles remain independently deployable. REST/MCP mail access and authenticated SMTP submission are separate from provider administration.

## Goals

1. **Scoped personal mail access:** Expose existing mail safely to agents and applications through REST/MCP with fine-grained identities, authorization, and disclosure filtering. A single MCP/REST token may authorize multiple identities across different physical mailboxes/providers, each with independent permissions; operations explicitly select one identity.
2. **Automated service mailbox management:** Provision and reconcile mailboxes, aliases, routing, sender identities and service credentials for self-hosted infrastructure.
3. **Agent-facing MCP skill:** Write and maintain a distributable agent skill (`SKILL.md` and supporting examples) that teaches clients how to connect to Corvi's MCP server, discover permitted tools/identities, search/read safely, send with appropriate confirmation, handle filtered/unavailable results, and avoid assuming inaccessible mail does not exist. The skill must describe actual implemented behavior, never expand credential scope, and ship alongside the MCP API documentation.

## Architecture

The key boundaries are:

- **Standalone data plane:** A gateway with built-in **IMAP/SMTP and native JMAP clients**, mail identities, content policies and scoped credentials. A minimal deployment needs only a process/container and configuration file.
- **Optional control plane:** Provider configuration discovery, resource reconciliation, credential management and versioned configuration delivery. It is not in the message-processing path.
- **Optional Kubernetes operator:** GitOps/CRD reconciliation and optional OCI provider plugin deployments, using Kubernetes CRD `spec`/`status`, Secret references and Leases as its sole persistent management state. **No operator PostgreSQL/SQLite database**. Kubernetes deployment is built around the pinned bjw-s `app-template` chart with rootless, read-only, no-capabilities workloads and least-privilege component RBAC (ADR-0011).
- **Provider plugins:** gRPC services for provider-specific transport resolution, administrative operations and upstream provider usage/health metrics. Migadu is the initial target.
- **Bridge-backed providers:** Optional local IMAP/SMTP bridge runtimes for providers such as Proton Mail. OCI plugin metadata provides deployment hints, authenticated discovery validates bridge requirements, and the operator can manage a trusted bridge or connect to an existing local one.
- **Native JMAP:** Direct RFC 8620/8621 HTTPS access to mail, synchronization, blobs and email submission through the in-process Rust gateway, with Fastmail as the first interoperability target. JMAP does **not** require a bridge, proxy or provider plugin.
- **Interactive upstream OAuth:** Connect supported mail providers through their browser consent screen using Authorization Code + PKCE; support registered hosted callbacks, local CLI-assisted loopback login and provider-supported device grants, with encrypted refresh tokens and separate Corvi client credentials. Provider-specific OAuth registration restrictions remain explicit.
- **Corvi client OAuth:** A built-in optional OAuth issuer and/or trusted external OIDC integration protects Corvi REST/MCP with consented **per-identity, per-action grants**, short-lived revocable tokens, Authorization Code + PKCE, and restricted Client Credentials for agents/services. Includes MCP CIMD support, step-up, and a standalone issuer without mandatory Kubernetes.
- **Storage:** Kubernetes-native CRDs/status/Secrets/Leases for the **control plane**, separately from optional SQLite for standalone **data-plane/OAuth** state or PostgreSQL for multi-replica transactional durability, with independent encrypted secret custody and opt-in encrypted blobs. Incoming mail stays at its upstream provider by default; running the integrated OAuth issuer requires persistent grant/revocation state.
- **Observability:** OpenTelemetry and Prometheus/OTLP, with provider plugins acting as exporters. TLS/mTLS is mandatory for internal gRPC, and Kubernetes may opportunistically use cert-manager's CSI driver.

**Namespace convention:** Corvi-owned API groups and metadata use the `naktis.eu` domain, generally under `corvi.naktis.eu` (for example, `mail.corvi.naktis.eu`). OCI reverse-DNS annotation keys use `eu.naktis.corvi.*`. Third-party registry hosts and documentation URLs retain their original domains.

## Design decisions

Read **[ADR-0001: Corvi system architecture](docs/adr/0001-corvi-system-architecture.md)** for the complete architectural decision, threat boundaries, identity and alias isolation requirements, data-plane behavior, provider resource model, certificate strategy, and phased implementation plan.

**[ADR-0002: Product goals and future messaging extensibility](docs/adr/0002-product-goals-and-messaging-extensibility.md)** records a possible future extension of scoped personal access to SMS, Matrix, Discord and other authorized messaging systems. This is deliberately **deferred**: the current implementation remains email-first, and automated mailbox management remains an email-focused concern.

**[ADR-0003: Mail filtering and disclosure policies](docs/adr/0003-mail-filtering-and-disclosure-policies.md)** defines concrete personal-mail filtering rules, sensitive-message detection, redaction, hide decisions, attachment restrictions, fail-closed behavior and enforcement across all read/search/event surfaces.

**[ADR-0004: Pluggable policy evaluation with WASM and gRPC](docs/adr/0004-pluggable-grpc-policy-engines.md)** proposes sandboxed in-process WASM with **two OCI release variants** per policy: native WASM OCI (`-wasm`) for Corvi's embedded resolver, and Kubernetes image-volume-compatible OCI (`-volume`) for mounted policy files. Both variants contain identical WASM bytes and are pinned by their respective digests. External gRPC engines such as Cerbos remain optional, and the built-in evaluator is sufficient for standalone use.

**[ADR-0005: Shared public mail API contract](docs/adr/0005-public-mail-api.md)** establishes consistent client-facing authorization, filtering, pagination, sending and idempotency semantics across REST and MCP.

**[ADR-0006: Provider-managed local mail transport bridges](docs/adr/0006-local-transport-bridges.md)** specifies direct versus existing/managed bridge topology, OCI metadata-assisted discovery, validated runtime provisioning, local endpoint/TLS security and Proton Mail Bridge compatibility constraints. A [proposed JSON Schema](api/provider-transport-bridge.schema.json) describes typed bridge prerequisites.

**[ADR-0007: Native JMAP mail transport](docs/adr/0007-native-jmap-transport.md)** adds provider-neutral JMAP reading, searching, synchronization and `EmailSubmission` sending alongside IMAP/SMTP, while preserving identity grants and disclosure filtering. The [transport JSON Schema](api/mail-transport.schema.json) models separate read/submission protocols and prohibits implicit protocol fallback.

**[ADR-0008: Interactive upstream provider OAuth](docs/adr/0008-interactive-upstream-oauth.md)** defines browser/CLI provider consent, PKCE/issuer/redirect protections, token storage and refresh, upstream account binding and the separation from client-facing Corvi OAuth. A [proposed provider OAuth descriptor schema](api/upstream-oauth.schema.json) specifies enrollment capability discovery, client registration and supported protocol mechanisms.

**[ADR-0009: Corvi client OAuth and identity grants](docs/adr/0009-corvi-oauth-and-identity-grants.md)** establishes OAuth authorization-server/resource-server behavior, independent external OIDC login, per-MailIdentity consent through OAuth RAR, trusted client registration, machine credentials, refresh and revocation. The [proposed OAuth issuer/grant schema](api/corvi-oauth.schema.json) documents the design separately from provider OAuth in ADR-0008.

**[ADR-0010: Storage and durability](docs/adr/0010-storage-and-durability.md)** establishes **Kubernetes as the control plane's source of truth**, with no operator database; SQLite and PostgreSQL are reserved for transactional OAuth/data-plane state, alongside independent secret custody, optional encrypted blobs and policy-safe mail caching. The [proposed storage schema](api/storage.schema.json) specifies backend choices and prevents durability-dependent features from using ephemeral state.

**[ADR-0011: Hardened Kubernetes Helm design](docs/adr/0011-hardened-helm-deployment.md)** specifies a bjw-s `app-template` v5 packaging model, strict non-root UID/GID, `capabilities.drop: [ALL]`, `RuntimeDefault` seccomp, read-only root FS, no privilege escalation, default-deny networking, digest-pinned images and scoped Kubernetes API credentials **only for controllers that need them**. Illustrative [gateway](deploy/helm/app-template-gateway.values.yaml) and [operator](deploy/helm/app-template-operator.values.yaml) values are design examples, **not deployable releases**.

## Proposed public API specifications

- **[OpenAPI 3.1 REST contract](api/openapi.yaml):** Versioned `/v1` endpoints, JSON schemas, permission annotations and error responses.
- **[MCP 2026-07-28 specification](docs/spec/mcp.md):** Transport, OAuth resource-server behavior, tool mappings, filtering, **MRTR approval for sending**, **scoped inbox-change subscriptions**, **read-only context resources**, **opt-in durable Tasks**, and conformance rules.
- **[Machine-readable MCP tool catalogue](api/mcp-tools.json):** Seven proposed tools with JSON Schema input/output definitions.
- **[Machine-readable MCP resource catalogue](api/mcp-resources.json):** Read-only server context, authorized identities, safe policy guidance, per-identity context, and filtered inbox-change resources, with JSON Schemas and permission requirements.

All public API specifications are **proposed, not implemented**. The agent-facing MCP `SKILL.md` is a planned deliverable that will be maintained alongside the implemented tool contract.

> **Project status:** Architecture stage. The ADR describes intended behavior and does not imply completed implementations.

The license, stable API contracts and development workflow will be established as the implementation progresses.
