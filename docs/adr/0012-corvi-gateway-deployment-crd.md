# ADR-0012: CorviGateway deployment CRD and ownership model

- **Status:** Proposed; not an implemented CRD/controller
- **Date:** 2026-11-16
- **Scope:** Declarative deployment and lifecycle of Corvi gateway instances in Kubernetes
- **Related:** [ADR-0001](0001-corvi-system-architecture.md), [ADR-0005](0005-public-mail-api.md), [ADR-0009](0009-corvi-oauth-and-identity-grants.md), [ADR-0010](0010-storage-and-durability.md), [ADR-0011](0011-hardened-helm-deployment.md), [ADR-0013](0013-mail-resource-ownership-graph.md)
- **Proposed model:** [CorviGateway JSON Schema](../../api/corvi-gateway.schema.json), [example resource](../../deploy/examples/corvi-gateway.example.yaml)

## Decision

Add an **optional, namespaced `CorviGateway` CRD** (`corvigateways.corvi.naktis.eu`, `apiVersion: corvi.naktis.eu/v1alpha1`, `kind: CorviGateway`) that declaratively requests one separately addressable Corvi gateway runtime instance. The Corvi Kubernetes operator reconciles it into a hardened **Deployment or StatefulSet**, stable ClusterIP Service, validated configuration snapshot and bounded rollout/status metadata.

**This is not `Gateway` from the Kubernetes Gateway API** (`gateway.networking.k8s.io`). CorviGateway represents a Corvi *application server*, not a load-balancer/listener/ingress gateway. Existing Gateway API `Gateway`, `HTTPRoute` and, when explicitly supported, `TCPRoute` resources belong to their respective networking controllers and may route to the Service generated for CorviGateway. The Corvi operator must not create or administer GatewayClass/Gateway by default.

The CRD is **an alternative to Helm-owned gateway workloads**, not an added mandatory dependency. Two deployment modes remain:

| Mode | Gateway workload owner | Control-plane dependency | Primary use |
| --- | --- | --- | --- |
| **`helmDirect`** | bjw-s `app-template` Helm release manages Deployment/StatefulSet, Service and config mounts | No Corvi operator or CRD required | Minimal standalone-on-Kubernetes installation |
| **`operatorManaged`** | Corvi operator reconciles `CorviGateway` to the same class of hardened Kubernetes resources | Operator+CRD required only for changes/reconciliation; gateway continues from last known-good snapshot during outage | Multi-instance GitOps, provider-integrated deployment and lifecycle |

**One workload has exactly one field manager/owner.** Never use `app-template` to create a gateway Deployment/Service which an operator subsequently owns or patches. A GitOps/Helm installer deploying the operator, CRDs, and `CorviGateway` resource is not simultaneously the workload owner. Migrating from Helm-owned to operator-owned requires a deliberate cutover with resource naming/selector stability and a tested no-duplicate-instance strategy; **do not automatically adopt an existing Helm workload**. Deleting a CRD instance must not automatically delete protected Secrets, upstream mailboxes, consent grants or persistent PVCs.

## 1. Resource boundary and minimal spec

The CRD expresses **safe product-level intent**, not the arbitrary Kubernetes PodSpec. Suggested fields:

```yaml
apiVersion: corvi.naktis.eu/v1alpha1
kind: CorviGateway
metadata:
  name: primary
  namespace: corvi-system
spec:
  replicas: 2
  suspended: false
  listeners:
    http:
      enabled: true
    smtpSubmission:
      enabled: false
  authorization:
    mode: external # or embedded
    configSecretRef:
      name: corvi-resource-server
  state:
    backend: postgres # ephemeral | sqlite | postgres
    connectionSecretRef:
      name: corvi-runtime-db
  resources:
    requests:
      cpu: 100m
      memory: 128Mi
    limits:
      memory: 512Mi
```

A one-instance `sqlite` gateway may use `state.backend: sqlite` with `existingClaimName` and `replicas: 1`; the operator then uses a safe **single-writer StatefulSet** or equivalent controller with explicit ownership/fencing and rollout semantics. `replicas > 1` with SQLite is forbidden. `postgres` uses a secret-backed connection descriptor and may scale independently. `ephemeral` is allowed only for features not requiring durable state. An **embedded Corvi OAuth issuer** requires durable state; do not allow `authorization.mode: embedded` plus ephemeral state. Full feature/cross-field validation is required in CEL/admission and reconciler code.

**The gateway has no `mailIdentityRefs` selector.** Ownership is directed from children to parents: `MailIdentity.spec.mailboxRef` → `Mailbox.spec.providerRef` → `MailProvider.spec.gatewayRef` → this `CorviGateway`. The operator derives the effective identity set by walking the reverse index of these **single required, typed, same-namespace references** and validating the entire chain, not by maintaining inverse lists or label selectors. See [ADR-0013](0013-mail-resource-ownership-graph.md). A reference is not an OAuth grant: per-client Corvi identity permissions, sender restrictions, disclosure policies and resource audience remain mandatory.

**`spec.suspended: true`** retains CorviGateway as a logical provider parent for operator-only **management** deployments but suppresses gateway mail Pods and Services. Provider administration may continue; mail reads/sends are unavailable. A gateway can have many providers, a provider many mailboxes, and a mailbox many identities, but a child has exactly one parent. Do not automatically reparent children when a gateway is suspended.

`authorization.configSecretRef` selects an approved **resource-server** auth configuration, not a plaintext bearer token in CRD status. The operator should preferably publish only validated config and read-only secret references/mounts; it does not need to read Corvi OAuth signing keys or upstream provider tokens. When using the embedded issuer, grant/token state remains SQLite/PostgreSQL (ADR-0009/0010), not in the `CorviGateway` object.

`listeners` choose which runtime listeners to publish via the ClusterIP Service. **Pod ports are fixed and unprivileged**, e.g. 8080 HTTP/MCP and 2525 SMTP AUTH; a CRD cannot enable public MX port 25, host ports, node ports, host networking or arbitrary listeners. Gateway API `HTTPRoute` for REST/MCP is a separate object that targets the generated Service; TCP/SMTP publication must use an explicitly approved route/Service layer, not a privileged Corvi Pod.

### Security invariants are not user-editable CRD fields

The CRD **does not expose** inverse provider/mailbox/identity reference lists, `podTemplate`, `securityContext`, `serviceAccountName`, host volumes, `hostNetwork`, arbitrary init/sidecars, commands, env vars, Linux capability additions, tolerations that bypass admission, raw image tags, unconstrained NetworkPolicy rules or user-provided container privileges.

The operator always sets:

- Rootless numeric UID/GID (default 65532), `runAsNonRoot: true`, `allowPrivilegeEscalation: false`, `privileged: false`, `capabilities.drop: [ALL]` **with no additions**, `seccompProfile: RuntimeDefault`, and `readOnlyRootFilesystem: true` for every container/init container.
- `automountServiceAccountToken: false`, a pre-provisioned **no-RBAC** gateway ServiceAccount (approved by operator namespace installation), no host paths/namespace access, no unsafe sysctls or host ports; only approved, read-only Secret projections and bounded scratch/PVC mounts.
- Image from a **signed, digest-pinned, operator-approved Corvi gateway release**, selected at operator/chart level. A `CorviGateway` instance cannot point to an arbitrary image or plugin.
- Safe resource floors/ceilings with configured `resources` requested/limited; reject attempts to bypass resource quotas, privileged storage or secret allowlists.
- Default-deny ingress/egress NetworkPolicies installed by independently trusted GitOps/Helm/network policy controls; the operator may report missing policies but **must not** silently create an unrestricted egress exemption.

Restricted Pod Security Admission and an independent validating admission policy must check generated workloads. Kubernetes RBAC allowing Deployment creation cannot constrain the PodSpec by itself; do not rely on the operator's own validation as the only security boundary.

## 2. Reconciliation and child resource ownership

For each accepted `CorviGateway`:

1. Validate spec, namespace ownership, **the child→parent graph** (`MailProvider.gatewayRef`, `Mailbox.providerRef`, `MailIdentity.mailboxRef`), secret/claim references, deployment-mode conflict, storage/replica constraints, quotas and operator-approved image.
2. Reverse-index **only providers whose `gatewayRef` points to this gateway**, then their mailboxes and identities; validate each same-namespace parent reference and applicable transport/OAuth policy before publishing a **complete versioned, bounded, immutable configuration snapshot**. A missing parent, cross-gateway/misbound identity or changing parent must fail closed and trigger reconciliation of **both old and new gateways**, with old visibility revoked before new activation (ADR-0013). Never publish raw provider tokens or secret material.
3. For an unsuspended gateway, reconcile workload resources with stable labels, selectors and **ownerReferences** (for created Deployment/StatefulSet, ClusterIP Service and operator-owned nonsecret ConfigMaps). Use server-side apply field ownership and conflicts as **errors**, not forced takeover of Helm-owned objects.
4. Inject approved ServiceAccount and read-only Secret/CSI mounts with correct rootless file permissions. Prepare resource-specific network policy and external routes **through an independently installed, restricted GitOps/admission policy**.
5. Roll out on validated config generation or approved image-digest changes; preserve last-known-good active gateway config and availability on invalid desired state **only within security-sensitive revocation/staleness bounds**. When `spec.suspended` becomes true, stop gateway mail workloads and external mail exposure without deleting provider/mailbox/identity CRDs. For stateful SQLite, enforce single writer/no simultaneous pod handover; use appropriate rollout strategy and fencing.
6. Observe workload readiness and configuration generation; publish **sanitized conditions and references** to `status`, never secrets, access tokens, mailbox subjects, provider account details or sensitive configuration.

Workload names should derive deterministically from resource namespace/name, e.g. `corvi-gateway-primary`; selectors and owner references stay stable across reconciliation. Ensure the operator cannot create resources with arbitrary user-defined ownerRefs that would cross a namespace or impersonate unrelated owners. Deleting a `CorviGateway` must first resolve or explicitly block remaining `MailProvider.spec.gatewayRef` dependents and must **never garbage-collect provider/mailbox/identity CRDs via Kubernetes ownerReferences**. It may remove its managed **workload** children after safe finalizer cleanup, but never delete externally owned PVCs, auth grants, Kubernetes Secrets, provider accounts, or mail resource CRDs as a side effect. Always define explicit retention and safe cleanup semantics.

`status` should include:
- `observedGeneration`, `conditions` (`Accepted`, `Resolved`, `Ready`, `Progressing`, `Degraded`), `desiredReplicas`, `readyReplicas`, `replicas`, `configurationRevision`, `workloadKind`, `serviceName` and limited diagnostic reason/message.
- Distinguish `InvalidSpec`, `MissingParent`, `InvalidReference`, `CrossGatewayMismatch`, `MigrationPending`, `SecretUnavailable`, `StorageUnavailable`, `ConfigPublishFailed`, `OwnershipConflict`, `SecurityPolicyDenied` and `RolloutFailed`. Keep messages safe for users who can read namespaced CRD status.
- Enable Kubernetes CRD **`status` subresource** and optional **`scale` subresource** mapping `spec.replicas` to `status.replicas`/selector, subject to storage constraints. A `kubectl scale` may update `spec.replicas`, but cannot bypass validation forbidding `sqlite` multi-replica.

Gateway availability must not depend on a live operator reconciliation RPC or live Kubernetes API call. If the operator stops, Kubernetes-managed Pods keep serving from the last verified configuration as long as configured credentials/policies remain valid; security-sensitive revocation freshness remains explicitly bounded (ADR-0001/0009).

## 3. Chart relationship and supported modes

**bjw-s `app-template` remains the deployment base for the operator and standalone Helm-managed gateway**, with the same hardened Pod/container semantics. In operator-managed mode, Kubernetes resources are created directly by the operator; it is not necessary or desirable to run Helm as a subprocess per `CorviGateway` or to create a second Helm release for every instance. The operator's PodSpec builder follows and tests the **same profile** used by `app-template`.

A user may install the `corvi-operator` app-template chart and separately apply `CorviGateway` objects via GitOps. A user who wants no operator installs `corvi-gateway` app-template release directly. In hybrid installations, some gateways may be Helm-managed and others operator-managed, but **no two systems may manage the same named workload or Service**. Avoid automatically treating any existing Deployment called `corvi-gateway-*` as adoptable; require explicit metadata and a migration procedure.

The CRD installation is a **separate privileged bootstrap/GitOps step** from operator runtime. Kubernetes RBAC requires namespaced `get/list/watch` of `corvigateways`, `patch/update` of `corvigateways/status`, `patch/update` of `corvigateways/finalizers` when used; plus bounded access to managed `deployments`, `statefulsets`, `services`, and approved `configmaps`. Do not give the operator ClusterRoleBinding, generic ServiceAccount create/update, Secrets list/watch, or a token for the gateway Pods. Existing Services/HTTPRoutes/Gateway API Gateways owned by Helm/GitOps are **not automatically adopted**.

**Do not confuse `CorviGateway` with `MailProvider`:** a `MailProvider` describes the upstream provider integration and its administrative/transport capabilities; a `CorviGateway` describes one instance of Corvi's own mail API process. Many upstream `MailIdentity` resources can be served by one CorviGateway **only when their required parent references resolve through `Mailbox` and `MailProvider` to that gateway**. No direct gateway identity selector exists; this relationship remains separate from per-client OAuth grants (ADR-0013).

## 4. Implementation sequence and tests

1. Define a structural CRD with OpenAPI v3 schema, CEL cross-field invariants, `status`/`scale` subresources and a namespaced resource scope, with conversion/versioning plan. The linked JSON Schema is a *design model*, not itself the generated Kubernetes CRD manifest.
2. Implement controller reconciliation with stable resource names/labels/ownerRefs, separate release-owned ServiceAccount, immutable config snapshot publication, constrained workloads and safe status.
3. Add `corvigateways` and required child resources to the namespaced operator RBAC, and no additional Kubernetes privileges to gateway/auth/provider workloads.
4. Add negative CI/integration fixtures for arbitrary PodSpec injection, image escalation, Secret reference abuse, **missing parent, cross-namespace refs, mistaken gateway attachment, stale reverse indexes, unsafe parent rebind, overlapping OAuth grants**, duplicate Helm ownership, missing/expired config, rootful/mutable images, wrong security contexts, SQLite scale >1, unsigned plugin pods, and operator restart/API loss.
5. Verify Deployment/StatefulSet rollouts, no duplicate SQLite writer, deterministic status and safe finalizer deletion. Validate both standalone-Helm and operator-CRD modes with the same rootless/security admission policies.
6. Document an explicit opt-in migration path between Helm-owned and operator-owned workloads with no concurrent double ownership and no accidental credential/PVC loss.
7. Verify `spec.suspended: true` retains provider-management bindings without serving mail, and that changed `gatewayRef` causes old gateway permissions to be invalidated before the new gateway is activated.

## References

- [Kubernetes custom resource definition and subresources](https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definitions/)
- [Kubernetes Gateway API resource model](https://kubernetes.io/docs/concepts/services-networking/gateway/)
- [Kubernetes RBAC guidance](https://kubernetes.io/docs/concepts/security/rbac-good-practices/)
- [ADR-0011: Helm deployment and Kubernetes hardening](0011-hardened-helm-deployment.md)
- [ADR-0013: Mail resource reference ownership](0013-mail-resource-ownership-graph.md)

## Consequences

A dedicated CRD lets GitOps declaratively manage **multiple Corvi gateway deployments** without writing independent Helm releases per instance, while preserving standalone app-template deployment and strict separation of control-plane and data-plane authority. The effective identity set is **derived** through provider → gateway, mailbox → provider and identity → mailbox references, with no duplicated child list. It also adds a reconciliation controller, CRD lifecycle/versioning and an important risk of ownership conflicts. No gateway is deployed or modified by this ADR alone.

---
This ADR is an architectural design; neither a production CRD/controller nor runnable Corvi images exist yet.
