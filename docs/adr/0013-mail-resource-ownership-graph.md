# ADR-0013: Directional MailIdentity → Mailbox → MailProvider → CorviGateway references

- **Status:** Proposed, architectural requirement; CRDs and controllers are not implemented
- **Date:** 2026-11-16
- **Scope:** Parent references and safe resolution of Corvi's Kubernetes mail resources
- **Related:** [ADR-0001](0001-corvi-system-architecture.md), [ADR-0005](0005-public-mail-api.md), [ADR-0009](0009-corvi-oauth-and-identity-grants.md), [ADR-0010](0010-storage-and-durability.md), [ADR-0012](0012-corvi-gateway-deployment-crd.md)
- **Design contracts:** [Reference JSON Schema](../../api/mail-resource-ownership.schema.json), [full-chain example](../../deploy/examples/mail-resource-chain.example.yaml)

## Decision

**Mail resources follow exactly one typed, directional parent-reference chain**:

```text
MailIdentity.spec.mailboxRef.name
         → Mailbox.metadata.name
Mailbox.spec.providerRef.name
         → MailProvider.metadata.name
MailProvider.spec.gatewayRef.name
         → CorviGateway.metadata.name
```

The gateway **does not** contain `mailIdentityRefs`, `mailboxRefs` or `providerRefs` that mirror inverse ownership. The reference is stored at the **child**, making each provider belong to one gateway, each mailbox to one provider and each mail identity to one mailbox. Each parent may have many children. This is a **logical association / runtime configuration ownership** graph, **not a Kubernetes garbage-collection `ownerReferences` chain**.

All references are **required, singular, strongly typed, same-namespace local name references** in Kubernetes v1alpha1. Reject missing, empty, multiple, malformed or cross-namespace references; there is no wildcard, label-selector attachment, implicit default gateway or automatic cross-gateway adoption. The referenced parent must exist and have the expected resource kind/API group.

This design applies to Kubernetes operator-managed resources. Standalone or `helmDirect` Corvi without CRDs uses the **same logical provider → gateway, mailbox → provider, identity → mailbox model in its trusted local configuration**, without a mandatory Kubernetes API client. Namespaced CRD references specifically target an existing `CorviGateway` object in operator-managed mode. A Helm-only runtime must not be silently adopted by a `MailProvider.spec.gatewayRef`; explicit migration is required.

## 1. Resource roles and scope

| Kind | Required parent field | May have multiple children | Stored ownership |
| --- | --- | --- | --- |
| `CorviGateway` | none | `MailProvider` | Gateway runtime / routing / resource limits / authorization config |
| `MailProvider` | `spec.gatewayRef.name` | `Mailbox` and provider-managed domains/aliases | Upstream transport, provider plugin, management configuration and capabilities |
| `Mailbox` | `spec.providerRef.name` | `MailIdentity` | One physical upstream mailbox/account and credential/transport bindings |
| `MailIdentity` | `spec.mailboxRef.name` | none in this graph | One sender persona / virtual filtered mailbox view and applicable policies |

`MailAlias`, `MailDomain`, forwarding and rewriting objects may reference provider/mailbox resources as appropriate, but **must not bypass** the authoritative path for identity-to-gateway resolution. A `MailCredential` or OAuth grant may authorize **several** `MailIdentity` resources; that is a different **authorization association**, not a competing parent ownership edge.

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

For gateway `G`, its **effective identities** are the `MailIdentity` children whose `mailboxRef` resolves to a `Mailbox` whose `providerRef` resolves to a `MailProvider` whose `gatewayRef` resolves **to G in the same namespace**. A gateway does not list, select or grant them individually.

The gateway configuration publisher:

1. Reads a coherent, bounded set of resources and verifies every parent edge and status/enablement. Use owner namespace as a strict boundary and re-list on missed watch/resync.
2. Resolves provider authentication/transport settings, mailbox binding, identity isolation and applicable policies. Distinguish a provider's management-only capability from its mail-transport capability; **management still works with a suspended gateway**.
3. Builds the next **complete**, validated, immutable, versioned per-gateway snapshot, keyed by stable object UID and generation. Do not publish a partially resolved graph or use an incomplete old cache as evidence of ownership.
4. On a missing/invalid parent, cross-gateway mismatch, revoked permission, or provider binding change, **fail closed for affected mail identities**, report bounded `Resolved=False`/`InvalidReference` conditions, and ensure the old gateway cannot indefinitely continue serving newly unauthorized identities. Last-known-good availability is subject to explicit revocation/freshness deadlines; security removals supersede ordinary availability.
5. After validation, atomically activate the snapshot on the correct gateway; data-plane REST/MCP/SMTP does not call the Kubernetes API or provider plugin on each mail request.

Do **not** copy provider admin credentials, upstream OAuth refresh tokens, raw message data or unfiltered mailbox contents into snapshots, CRD status or Kubernetes labels/annotations.

The operator's namespace-scoped Role already requires read/watch for `corvigateways`, `mailproviders`, `mailboxes`, `mailidentities`; no new cluster-wide RBAC is necessary. It needs no permission to create or mutate ServiceAccounts. Updates to child references trigger reconciliation of **both old and new gateways**, not merely the currently selected parent.

## 3. Moving, deleting and suspending resources

**Reparenting is an authorization-sensitive migration**, not a benign field update. For a changed `MailProvider.spec.gatewayRef`, `Mailbox.spec.providerRef` or `MailIdentity.spec.mailboxRef`:

- Validate that the new parent exists, is same-namespace and supports the required transport/capabilities.
- Mark the affected subtree as transitioning; **revoke its effective visibility/sending permissions from the old gateway before activating them on the new gateway**, with an auditable handover and no overlap. When the operator cannot safely coordinate or confirm expiry/revocation, hold the subtree unavailable rather than briefly serving it from both.
- Invalidate scoped message ID mappings, cursors, subscriptions, search/cache entries, queues/tasks and authorization projections that are bound to the old identity/mailbox/provider/gateway configuration. Preserve only deliberately migratable durable data after explicit validation.
- Recheck per-client OAuth grants and mail-resource audience. Existing grants **never expand automatically** across gateways or to unrelated mailbox contents. If issuer/resource binding changes, re-consent or reissue appropriately scoped tokens.
- Publish `Resolved`, `Migrating`/readiness and reasoned failure conditions in status; never leak credentials or private mail details in status.

**Deletion must not cascade through this graph via Kubernetes ownerReferences.** Prefer finalizer/reference-integrity validation that denies or holds deletion of a parent with dependent children until they are deliberately migrated, detached through an explicit supported operation, or deleted by an authorized administrator. Never automatically delete physical upstream mailboxes, other providers, mail contents, OAuth grants, secret vault records, PVCs or customer domains as a side effect of deleting a CorviGateway.

**Management-only deployments:** A `CorviGateway` with `spec.suspended: true` is a **logical parent resource** but runs no gateway mail Pods or published mail Service. Providers can remain bound and provider-management reconciliation can continue. Mail reads/sends from its identities are unavailable. This preserves operator-only upstream domain/mailbox administration without requiring SQLite/PostgreSQL or a live data plane. In `helmDirect` mode, an equivalent explicit local logical gateway binding can exist without Kubernetes CRDs.

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

The example illustrates **required reference fields only**. It is not a complete released provider/mailbox/identity CRD contract: provider transport settings, mailbox connection credentials and identity address/policy fields will be added through separate typed schemas and reconciliation.

## 5. Acceptance tests

1. Multiple MailProviders can reference one CorviGateway, multiple Mailboxes can reference one provider and multiple MailIdentities can reference one Mailbox; the gateway contains **no inverse reference lists**.
2. Missing parent, wrong kind/group, wrong namespace, invalid reference syntax, or deleting parent makes affected identity unavailable without exposing an unrelated mailbox or treating stale caches as authorization.
3. Provider plugin management-only functions can reconcile under `CorviGateway.spec.suspended: true` without deploying a mail gateway Pod.
4. Changing any of three parent refs triggers both old and new graph reconciliation and cannot expose an identity under both gateways or silently transfer its client access grant.
5. A token with distinct action grants to two identities under different providers but **the same gateway resource audience** may work through one REST/MCP server; identities on another gateway do not become visible from it.
6. The operator cannot accidentally remove upstream provider accounts, physical mailboxes, or Secrets through Kubernetes garbage collection of the parent CRD.
7. Complete snapshot generation is atomic and bounded; revoked/reparented identity never survives beyond configured security-critical staleness, including after operator crash/restart.
8. The operator needs no extra secret/RBAC permissions just to follow references. Gateway remains rootless and carries no Kubernetes API token.

## Consequences

A single authoritative parent reference per resource avoids drift between gateway lists and resource ownership, makes the effective runtime scope derivable and simplifies GitOps. It makes controlled reparenting/deletion and authorization-aware snapshot invalidation mandatory. CRDs, controller code and migration tools remain implementation work.

---
This ADR specifies a reference contract; it is not a deployed controller or generated Kubernetes CRD.
