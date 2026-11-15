# Corvi

**Provider-agnostic, policy-driven mail access and infrastructure management.**

Corvi is a planned open-source mail gateway and management platform from Naktis Labs. It is designed to let applications and AI agents use mail through scoped REST/MCP APIs and authenticated SMTP submission, while keeping upstream IMAP/SMTP connectivity and provider administration independent.

## Architecture

The key boundaries are:

- **Standalone data plane:** A gateway with built-in IMAP/SMTP clients, mail identities, content policies and scoped credentials. A minimal deployment needs only a process/container and configuration file.
- **Optional control plane:** Provider configuration discovery, resource reconciliation, credential management and versioned configuration delivery. It is not in the message-processing path.
- **Optional Kubernetes operator:** GitOps/CRD reconciliation and optional OCI provider plugin deployments.
- **Provider plugins:** gRPC services for provider-specific transport resolution, administrative operations and upstream provider usage/health metrics. Migadu is the initial target.
- **Observability:** OpenTelemetry and Prometheus/OTLP, with provider plugins acting as exporters. TLS/mTLS is mandatory for internal gRPC, and Kubernetes may opportunistically use cert-manager's CSI driver.

## Design decisions

Read **[ADR-0001: Corvi system architecture](docs/adr/0001-corvi-system-architecture.md)** for the complete architectural decision, threat boundaries, identity and alias isolation requirements, data-plane behavior, provider resource model, certificate strategy, and phased implementation plan.

> **Project status:** Architecture stage. The ADR describes intended behavior and does not imply completed implementations.

The license, stable API contracts and development workflow will be established as the implementation progresses.
