# ADR-0002: Product goals and future messaging extensibility

- **Status:** Proposed (future extensibility); current scope remains email-first
- **Date:** 2026-11-15
- **Related:** [ADR-0001: Corvi system architecture](0001-corvi-system-architecture.md)

## Context

Corvi currently targets email, with a standalone IMAP/SMTP gateway, scoped REST/MCP access, an optional control plane and Kubernetes operator, and provider-specific gRPC plugins for administrative operations, transport resolution, and metrics.

We may eventually extend scoped access beyond email to personally owned or authorized communications carried through SMS, Matrix, Discord, or other messaging systems. That prospect should inform foundational interfaces, but **must not increase the implementation scope or minimum deployment requirements for the initial email release**.

Two different user needs motivate Corvi, and the distinction should remain explicit.

## Product goals

### Goal A: Scoped access to personal communications

The **read/access** side exists to grant applications and agents narrowly scoped access to **the user's own messages**, rather than handing them full account credentials.

Examples include allowing an agent to read one email alias, a selected conversation, or a designated message subset while refusing access to authentication messages, unrelated correspondence, attachments, or other private content.

This goal is about privacy, consent, policy enforcement, auditable access, and revocation.

Future connectors may support SMS, Matrix, Discord, and other systems **only where a legitimate, authorized integration supports the requested access**. This is not an authorization to circumvent provider restrictions, obtain unrestricted access to personal accounts, or claim per-message guarantees that the upstream platform cannot deliver.

### Goal B: Declarative automated mailbox management

The **infrastructure-management/write** side exists primarily to simplify provisioning and operating email resources for **self-hosted services**.

Examples include declaratively creating a mailbox or alias for Grafana, setting the permitted sender identity for a service, configuring forwarding/rewrite rules, rotating credentials, and reconciling mail-provider state through GitOps.

It is not primarily a general-purpose mechanism for administering Matrix homeservers, Discord servers, or phone-number fleets. Those systems have different administrative semantics, and no cross-protocol management parity is promised.

### A third, distinct action: Sending

**Sending a message** is neither the same permission as **reading messages** nor the same permission as **administering provider infrastructure**.

Clients may receive dedicated send privileges under specific identities and recipient policies. A service provisioned by the control plane does not automatically gain access to personal mail, and a personal-mail reader does not automatically gain provider administrative privileges.

## Decision direction

1. **Ship email first.** Implement the architecture in ADR-0001 without SMS, Matrix or Discord connectors, cross-channel routing, or cross-protocol CRDs.
2. **Maintain independently deployable concerns.** Personal-message access belongs to the data plane; automated mailbox/provider provisioning belongs to the control plane; neither requires the other in a minimal deployment.
3. **Design the authorization core to be transport-neutral where useful.** Model a principal, action, resource, identity, scope, and request context without assuming that every permission is intrinsically an IMAP permission. Preserve mail-specific types for email-specific behavior.
4. **Keep native protocol semantics.** Do not force rooms, channels, SMS conversations, BCC, email aliases, attachments, message edits, reactions and encryption state into a lossy universal mailbox model.
5. **Preserve actual upstream access constraints.** A connector must only claim capabilities and access/isolation guarantees it can enforce with trusted information from the underlying platform.
6. **Reserve, but do not implement, a future connector interface.** A potential `corvi.connector.v1` gRPC namespace would handle live message transport/synchronization and is distinct from `corvi.provider.v1`, which handles control-plane provider discovery, resolution and administration. The namespace is a design placeholder, not a committed protocol.
7. **Do not introduce new hard runtime dependencies.** The one-container generic IMAP/SMTP gateway, plugin-free path, and strict data/control-plane separation remain architectural invariants.

## Conceptual boundaries

| Concern | Current email implementation | Possible future extension |
| --- | --- | --- |
| Scoped reading/search | Personal mailbox via IMAP, REST/MCP access policies | Authorized SMS, Matrix, Discord sources |
| Sending | Identity-scoped SMTP submission or REST/MCP send | Capability-scoped channel sends |
| Provisioning | Mail domains, managed mailboxes, aliases, forwarding, rewrites | Not assumed for other protocols |
| Upstream provider administration | Optional provider gRPC plugins, initially Migadu | Only if justified by an actual use case |
| Policy/credential system | Shared scoped access model | Reuse where semantics truly match |
| Telemetry | Gateway + provider exporters | Connector-specific health and delivery telemetry |

A future **messaging connector** would be a data-plane integration, and could require a persistent connection, webhook ingress, synchronization state, or device/key management. A **provider-management plugin** is a control-plane integration. They can both use gRPC if out of process, but must not share privileges or create a hot-path dependency on the control plane.

For example, a Matrix connector may require locally protected encryption keys and a synchronization cursor; a Discord connector may be constrained to a bot's actual channel permissions and message-content access; and SMS may require a paired-device bridge or provider service with authenticated inbound delivery. None of these details should contaminate the initial IMAP/SMTP implementation.

## Security consequences

- Access grants must be scoped to resources actually proven accessible by the connector.
- Content-based rules, sender/recipient filters and event notifications must not leak excluded messages, counts, attachments or conversational metadata.
- Cross-channel forwarding/summarization must be a separate explicitly authorized operation, with source read and destination send permissions, not an implicit entitlement.
- Provider administration credentials, personal account access credentials and end-user access tokens remain separate.
- A newly provisioned automated mailbox is not automatically readable by an agent; a personal mailbox being readable by an agent does not confer the ability to provision or delete provider resources.
- Do not imply that a third-party bot API can access the user's entire personal message history.

## Non-goals for the initial release

- An omnichannel inbox or unified history of all personal communications.
- Generic SMS, Discord or Matrix connectors.
- Cross-channel message forwarding, synchronization or search.
- Cross-protocol provisioning CRDs.
- A universal transport protocol or lossless conversion between unrelated message formats.

## Revisit criteria

Revisit this ADR after the email MVP demonstrates:

1. Correct and auditable scoped personal mail access, including strict limits on alias isolation claims.
2. Working declarative mail-resource management for at least one provider.
3. Reliable standalone gateway behavior without an operator or extra plugin container.
4. A reusable principal/action/resource policy model that does not prevent later channel-specific adapters.

A subsequent ADR should specify one concrete additional messaging system, its authorization model, its state and encryption requirements, and whether a separate connector process is justified.

## Consequences

Corvi remains a **secure personal-message access broker and declarative mail infrastructure management platform**, with email as its present domain. Future messaging support is a possible extension of the access-broker role, not a commitment to make every protocol administrable or to rebuild the gateway around a universal message format.

This ADR records product intent and a compatibility direction, not a mandate to implement non-email messaging now.
