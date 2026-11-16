# ADR-0013: Directional mail-resource ownership with optional gateway attachment

- **Status:** Proposed, architectural requirement; CRDs and controllers are not implemented
- **Date:** 2026-11-16
- **Scope:** Parent references and safe resolution of Corvi's Kubernetes mail resources
- **Related:** [ADR-0001](0001-corvi-system-architecture.md), [ADR-0005](0005-public-mail-api.md), [ADR-0009](0009-corvi-oauth-and-identity-grants.md), [ADR-0010](0010-storage-and-durability.md), [ADR-0012](0012-corvi-gateway-deployment-crd.md)
- **Design contracts:** [Reference JSON Schema](../../api/mail-resource-ownership.schema.json), [full-chain example](../../deploy/examples/mail-resource-chain.example.yaml)

## Decision

**Mail resources use one typed, directional ownership chain, with optional provider attachment to a gateway**:

```text
MailIdentity.spec.mailboxRef.name
         → Mailbox.metadata.name
Mailbox.spec.providerRef.name
         → MailProvider.metadata.name
MailProvider.spec.gatewayRef.name (OPTIONAL)
         → CorviGateway.metadata.name (only when bound)
```

The gateway **does not** contain `mailIdentityRefs`, `mailboxRefs` or `providerRefs` that mirror inverse ownership. Every mailbox belongs to one provider and every identity belongs to one mailbox. A provider may be **unbound** (no gatewayRef), in which case it remains fully manageable through the control plane but **none of its mailboxes or identities are served by any Corvi gateway**. A bound provider refers to **exactly one** gateway; a gateway may host many providers. These are logical associations, **not Kubernetes garbage-collection `ownerReferences`**.

**`Mailbox.spec.providerRef` and `MailIdentity.spec.mailboxRef` are required**; **`MailProvider.spec.gatewayRef` is optional**. When provided, each reference is singular, strongly typed and same-namespace. Reject malformed/empty refs, multiple gateway assignments, wrong-kind refs, cross-namespace refs and nonexistent *specified* parents. **Omitted gatewayRef is a valid, intentional management-only state, not an invalid reference.** An explicitly specified gatewayRef that cannot resolve is an error and must never silently fall back to another gateway. There is no wildcard, label-selector attachment, default gateway or automatic cross-gateway adoption.

This design applies to Kubernetes operator-managed resources. Standalone or `helmDirect` Corvi without CRDs uses the **same logical optional provider → gateway, required mailbox → provider and identity → mailbox model in trusted local configuration**, without a Kubernetes API client. A specified namespaced CRD `gatewayRef` must resolve to an actual operator-managed `CorviGateway`; a Helm-only runtime must not be silently adopted. Providers may stay unbound indefinitely while the operator reconciles their domain/mailbox/alias administration.

## 1. Resource roles and scope

| Kind | Parent field | May have multiple children | Stored ownership |
| --- | --- | --- | --- |
| `CorviGateway` | none | `MailProvider` | Gateway runtime / routing / resource limits / authorization config |
| `MailProvider` | **optional** `spec.gatewayRef.name` | `Mailbox` and provider-managed domains/aliases | Provider management, upstream transport and plugin settings; unbound provider is management-only |
| `Mailbox` | **required** `spec.providerRef.name` | `MailIdentity` | One physical upstream mailbox/account and credential/transport bindings |
| `MailIdentity` | **required** `spec.mailboxRef.name` | none in this graph | Sender persona / filtered mailbox view and policies |

`MailAlias`, `MailDomain`, forwarding and rewriting objects may reference provider/mailbox resources as appropriate, but **must not bypass** the authoritative path for identity-to-gateway resolution. A `MailCredential` or OAuth grant may authorize **several** `MailIdentity` resources; that is a different **authorization association**, not a competing parent ownership edge.

**Do not put provider lists on the gateway.** Reversing the edge to `CorviGateway.spec.providerRefs[]` would allow two gateways to claim the same provider and require a separate many-to-many ownership, credential isolation, conflict, sync and administrative-authority design. For v1alpha1, the single optional `MailProvider.spec.gatewayRef` chooses an unambiguous **zero-or-one** gateway: **no sharing of one MailProvider CRD across independent gateways**. If HA is needed, scale one logical CorviGateway using its replicas; a future explicit per-gateway binding resource could model multi-gateway attachment with separate authorization/state, but is out of scope.

The chain is **not** permission inheritance. A gateway containing a provider does not grant every client every provider/mailbox/identity. Authorization remains the intersection of caller token/grant/action, identity policy, disclosure filtering and the resolved current gateway. A credential listing identities across providers **within the same Corvi mail-resource audience** can continue to use one token. An identity on *another* gateway cannot be accessed merely by reusing a token with a different issuer/audience/resource configuration; explicit cross-gateway authorization is required (ADR-0005/0009).

## 2. Resolution, watch indexes and configuration publication

The operator maintains reverse indexes from the child references, for efficient reconciliation:

```text
CorviGateway(primary)
 ├─ MailProvider(fastmail)   spec.gatewayRef: primary
 │   ├─ Mailbox(personal)    spec.providerRef: fastmail
 │   │   └─ MailIdentity(me) spec.mailboxRef: personal
 │   └─ Mailbox(alerts)      spec.providerRef: fastmail
 └─ MailProvider(migadu)     spec.gatewayRef: primary
     └─ Mailbox(service)     spec.providerRef: migadu
         └─ MailIdentity(noreply) spec.mailboxRef: service
```

For gateway `G`, its **effective identities** are the `MailIdentity` children whose `mailboxRef` resolves to a `Mailbox` whose `providerRef` resolves to a `MailProvider` with an **explicit, valid** `gatewayRef` pointing to `G` in the same namespace. A provider **without** `gatewayRef` contributes **zero** identities to every gateway. The gateway does not list, select or grant them individually.

The gateway configuration publisher:

1. Reads a coherent, bounded set of resources and verifies every parent edge and status/enablement. Use owner namespace as a strict boundary and re-list on missed watch/resync.
2. Resolves provider authentication/transport settings, mailbox binding, identity isolation and applicable policies **only for bound providers**. Independently reconcile unbound providers' supported upstream administration without instantiating a CorviGateway, mail Pod, runtime token or mail-facing Service. `spec.suspended: true` remains a separate optional *maintenance pause* for gateways that are bound, not a prerequisite for management-only providers.
3. Builds the next **complete**, validated, immutable, versioned per-gateway snapshot, keyed by stable object UID and generation. Do not publish a partially resolved graph or use an incomplete old cache as evidence of ownership.
4. On a missing **required** parent, invalid **specified** gatewayRef, cross-gateway mismatch, revoked permission or changed provider binding, **fail closed for affected mail identities**, report bounded `Resolved=False`/`InvalidReference` conditions and ensure an old gateway cannot indefinitely serve newly unauthorized identities. An **intentionally omitted** gatewayRef reports a distinct healthy provider-management state such as `GatewayBound=False` (`reason: Unbound`) and `MailServing=False`, **not** `InvalidReference`. Last-known-good availability is subject to strict revocation/freshness deadlines; security removals supersede ordinary availability.
5. After validation, atomically activate the snapshot on the correct gateway; data-plane REST/MCP/SMTP does not call the Kubernetes API or provider plugin on each mail request.

Do **not** copy provider admin credentials, upstream OAuth refresh tokens, raw message data or unfiltered mailbox contents into snapshots, CRD status or Kubernetes labels/annotations.

The operator's namespace-scoped Role already requires read/watch for `corvigateways`, `mailproviders`, `mailboxes`, `mailidentities`; no new cluster-wide RBAC is necessary. It needs no permission to create or mutate ServiceAccounts. Updates to child references trigger reconciliation of **both old and new gateways**, not merely the currently selected parent.

## 3. Moving, deleting and suspending resources

**Binding, detachment and reparenting are authorization-sensitive state transitions**, not benign field updates. For a new/removed/changed `MailProvider.spec.gatewayRef`, changed `Mailbox.spec.providerRef` or changed `MailIdentity.spec.mailboxRef`:

- Validate any specified new parent exists, is same-namespace and supports required transport/capabilities. **Detachment** (remove gatewayRef) is valid and leaves the provider's admin reconciliation and mailbox CRDs intact, but immediately removes that provider's mail-facing identities from the old gateway. **Initial binding** is an explicit operator/GitOps action; no auto-attachment.
- Mark the affected subtree as transitioning; **revoke its effective visibility/sending permissions from the old gateway before activating them on the new gateway**, with an auditable handover and no overlap. When the operator cannot safely coordinate or confirm expiry/revocation, hold the subtree unavailable rather than briefly serving it from both.
- Invalidate scoped message ID mappings, cursors, subscriptions, search/cache entries, queues/tasks and authorization projections that are bound to the old identity/mailbox/provider/gateway configuration. Preserve only deliberately migratable durable data after explicit validation.
- On binding/detachment, **revoke and invalidate old generated app credentials and their Secret keys**. **Do not auto-convert** a Corvi-scoped `MailCredential` to a direct provider token when gatewayRef is removed: it must fail `GatewayRequiredForScopedCredential`. A separate, explicitly authorized `ProviderAppCredential` may request only the provider's native identity/mailbox issuance granularity while unbound. Conversely, after binding, provider-native direct credentials must be revoked before gateway policy becomes authoritative; failure blocks safe cutover. Bound but suspended gateways do not authorize direct fallback (ADR-0014).
- Recheck per-client OAuth grants and mail-resource audience. Existing grants **never expand automatically** across gateways, or upon *first attachment/reattachment* of a previously unbound provider; require explicit owner/admin-approved activation and fresh or explicitly revalidated grant binding to the gateway audience/graph generation. If issuer/resource binding changes, require re-consent or appropriately scoped token reissuance.
- Publish `Resolved`, `Migrating`/readiness and reasoned failure conditions in status; never leak credentials or private mail details in status.

**Deletion must not cascade through this graph via Kubernetes ownerReferences.** A CorviGateway with attached providers cannot be deleted without first detaching or moving them (and removing its effective mail access), or explicitly approved handling of the dependents. A MailProvider may be deleted/retained according to provider lifecycle policy only after handling its mailboxes. Prefer finalizer/reference-integrity validation that holds parent deletion until children are deliberately migrated, detached through an explicit supported operation, or deliberately deleted by an authorized administrator. Never automatically delete physical upstream mailboxes, other providers, mail contents, OAuth grants, secret vault records, PVCs or customer domains as a side effect of deleting a CorviGateway.

**Management-only deployments:** **Omit `MailProvider.spec.gatewayRef`**. The operator reconciles provider domains/mailboxes/aliases with no CorviGateway CRD, gateway Pod, mail Service, SQLite, PostgreSQL or mail-serving configuration. A resource that independently issues a **provider-native app token** may still publish a [complete direct-provider connection Secret](0014-generated-app-credentials-and-connection-secrets.md), but only if the provider supports safe app credentials and no MailIdentity filtering would be bypassed. If a gateway already has providers, `CorviGateway.spec.suspended: true` remains a distinct operational *pause* that disables mail serving while retaining gateway attachment. Operators should prefer unbound providers for ongoing management-only usage and suspension only for temporary gateway downtime.

## 4. Minimal YAML example

```yaml
apiVersion: corvi.naktis.eu/v1alpha1
kind: MailProvider
metadata:
  name: fastmail
  namespace: corvi-system
spec:
  gatewayRef:
    name: primary
---
apiVersion: corvi.naktis.eu/v1alpha1
kind: Mailbox
metadata:
  name: personal
  namespace: corvi-system
spec:
  providerRef:
    name: fastmail
---
apiVersion: corvi.naktis.eu/v1alpha1
kind: MailIdentity
metadata:
  name: me
  namespace: corvi-system
spec:
  mailboxRef:
    name: personal
```

The example illustrates the **optional gateway association and required lower parent references**. Omitting `gatewayRef` from the example MailProvider makes it management-only; adding a valid `gatewayRef` opts it into that gateway's runtime. It is not a complete released provider/mailbox/identity CRD contract: provider transport settings, mailbox connection credentials and identity address/policy fields will be added through separate typed schemas and reconciliation.

## 5. Acceptance tests

1. Zero or more MailProviders can refer to one gateway, and **each MailProvider has at most one `gatewayRef`**; multiple Mailboxes can refer to one provider and multiple MailIdentities to one Mailbox. The gateway contains **no inverse provider lists**.
2. Missing **required** parent, wrong kind/group, wrong namespace, invalid **provided** gatewayRef, or deleting a bound gateway makes affected identities unavailable. Omitting gatewayRef is valid, never selects a default gateway and never leaks mail through a stale cache.
3. Provider management works with **no `gatewayRef` and no CorviGateway resource at all**, without deploying a mail gateway Pod. A suspended bound gateway also serves no mail.
4. Adding, removing or changing gatewayRef, or reparenting a mailbox/identity, triggers graph reconciliation and cannot expose an identity through both gateways, resurrect an old token grant or auto-authorize a previously unbound provider.
5. A token with distinct action grants to two identities under different providers but **the same gateway resource audience** may work through one REST/MCP server; identities on another gateway do not become visible from it.
6. The operator cannot accidentally remove upstream provider accounts, physical mailboxes, or Secrets through Kubernetes garbage collection of the parent CRD.
7. Complete snapshot generation is atomic and bounded; revoked/reparented identity never survives beyond configured security-critical staleness, including after operator crash/restart.
8. The operator needs no extra secret/RBAC permissions just to follow references. Gateway remains rootless and carries no Kubernetes API token.

## Consequences

Two required parent references plus an **optional, singular provider→gateway reference** avoid drift between gateway lists and resource ownership while supporting management-only providers with no gateway CRD. Shared providers across independent gateway resources are explicitly **not** supported in v1alpha1; replicas on one gateway provide HA without ownership ambiguity. It makes controlled reparenting/deletion and authorization-aware snapshot invalidation mandatory. CRDs, controller code and migration tools remain implementation work.

---
This ADR specifies a reference contract; it is not a deployed controller or generated Kubernetes CRD.
