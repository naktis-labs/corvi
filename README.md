# Corvi

**Provider-agnostic, policy-driven mail access and infrastructure management.**

Corvi is a planned open-source mail gateway and management platform from Naktis Labs. It has two complementary goals: **scoped access to the user's own email** for applications and AI agents, without handing out unrestricted mailbox credentials; and **declarative provisioning and management of automated mailboxes** for self-hosted services. These roles remain independently deployable. REST/MCP mail access and authenticated SMTP submission are separate from provider administration.

## Architecture

The key boundaries are:

- **Standalone data plane:** A gateway with built-in IMAP/SMTP clients, mail identities, content policies and scoped credentials. A minimal deployment needs only a process/container and configuration file.
- **Optional control plane:** Provider configuration discovery, resource reconciliation, credential management and versioned configuration delivery. It is not in the message-processing path.
- **Optional Kubernetes operator:** GitOps/CRD reconciliation and optional OCI provider plugin deployments.
- **Provider plugins:** gRPC services for provider-specific transport resolution, administrative operations and upstream provider usage/health metrics. Migadu is the initial target.
- **Observability:** OpenTelemetry and Prometheus/OTLP, with provider plugins acting as exporters. TLS/mTLS is mandatory for internal gRPC, and Kubernetes may opportunistically use cert-manager's CSI driver.

## Design decisions

Read **[ADR-0001: Corvi system architecture](docs/adr/0001-corvi-system-architecture.md)** for the complete architectural decision, threat boundaries, identity and alias isolation requirements, data-plane behavior, provider resource model, certificate strategy, and phased implementation plan.

**[ADR-0002: Product goals and future messaging extensibility](docs/adr/0002-product-goals-and-messaging-extensibility.md)** records a possible future extension of scoped personal access to SMS, Matrix, Discord and other authorized messaging systems. This is deliberately **deferred**: the current implementation remains email-first, and automated mailbox management remains an email-focused concern.

**[ADR-0003: Mail filtering and disclosure policies](docs/adr/0003-mail-filtering-and-disclosure-policies.md)** defines concrete personal-mail filtering rules, sensitive-message detection, redaction, hide decisions, attachment restrictions, fail-closed behavior and enforcement across all read/search/event surfaces.

**[ADR-0004: Pluggable policy evaluation with WASM and gRPC](docs/adr/0004-pluggable-grpc-policy-engines.md)** proposes sandboxed in-process WASM as the preferred extension mechanism, with optional gRPC authorization engines such as Cerbos. The built-in policy engine remains sufficient for a standalone gateway.

> **Project status:** Architecture stage. The ADR describes intended behavior and does not imply completed implementations.

The license, stable API contracts and development workflow will be established as the implementation progresses.
