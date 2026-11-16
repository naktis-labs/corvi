# ADR-0011: Helm deployment with bjw-s app-template and restricted Kubernetes security

- **Status:** Proposed; no Corvi release images or production chart are published
- **Date:** 2026-11-16
- **Scope:** Hardened default deployment of Corvi gateway, Kubernetes operator, OAuth authorization service, provider plugins and optional supporting workloads
- **Related:** [ADR-0001](0001-corvi-system-architecture.md), [ADR-0004](0004-pluggable-grpc-policy-engines.md), [ADR-0006](0006-local-transport-bridges.md), [ADR-0008](0008-interactive-upstream-oauth.md), [ADR-0009](0009-corvi-oauth-and-identity-grants.md), [ADR-0010](0010-storage-and-durability.md)
- **Values examples:** [gateway](../../deploy/helm/app-template/gateway.values.example.yaml), [operator](../../deploy/helm/app-template/operator.values.example.yaml), [deployment guide](../../deploy/helm/app-template/README.md)

## Decision

Corvi's Kubernetes deployment will **build on the [bjw-s-labs app-template Helm chart](https://bjw-s-labs.github.io/helm-charts/docs/app-template/)**, pinning a tested **5.x** release (examples use **5.2.1**, verified against the 2026-11 chart reference) and its chart artifact digest wherever the deployment tooling supports digest verification. `app-template` supplies ordinary workloads, ServiceAccounts, network policies and namespaced RBAC. A thin Corvi-specific Helm wrapper or supplemental bootstrap manifests supply Corvi CRDs, schema validation and specialized RBAC where the upstream chart is insufficient. **Do not maintain a fork** or hide a second broad-privilege chart under Corvi.

**Every Corvi-provided container**, including init containers, migration Jobs, OAuth/token broker processes, provider plugin servers, policy engines, collectors and bridge runtimes, must be **rootless, `capabilities.drop: [ALL]`, `allowPrivilegeEscalation: false`, `seccompProfile.type: RuntimeDefault` and `readOnlyRootFilesystem: true`**. These are **hard security invariants**, not tuning flags. If a third-party provider bridge cannot run in this profile, it is *unsupported for in-cluster managed deployment* until an independently reviewed restricted adapter exists. It may be connected as an explicitly approved external bridge outside Corvi's chart; do not weaken chart defaults.

**No Kubernetes ServiceAccount token is mounted on Pods that do not access the Kubernetes API.** The Kubernetes **operator** normally needs a scoped token for CRD watch/reconcile and managed plugin lifecycle; every other workload gets `automountServiceAccountToken: false`, including gateway REST/MCP/SMTP, built-in Corvi AS and provider-specific gRPC adapter Pods. If a dedicated OAuth token broker/secret reconciler truly needs Kubernetes Secret API access, it is a separate, explicitly enabled workload and tightly scoped ServiceAccount, not a reason to grant the gateway permission.

## 1. Packaging and ownership

Prefer two installable app-template-based releases in Kubernetes:

1. **`corvi-operator`**: optional, Kubernetes-dependent; one or leader-elected replicas watch namespaced Corvi CRDs, reconcile provider adapters/bridge workloads and publish approved configuration. **Kubernetes CRD `spec`/`status`/Secrets/Leases remain the sole operator database** (ADR-0010).
2. **`corvi-gateway`**: standalone-capable data plane, independently scalable; serves REST, MCP, SMTP AUTH and native upstream JMAP/IMAP/SMTP. It may connect to an OAuth AS and transactional SQLite/PostgreSQL state but **never needs a Kubernetes API client**.
3. **Optional `corvi-auth`**: when the Corvi OAuth issuer runs independently, deploy as a separate release/Pod with limited storage and secrets; no Kubernetes API access. It can also run in the gateway process for small deployments without changing role separation.
4. **Optional supporting workloads:** provider gRPC plugins (deployed/updated by operator with approved OCI digests), local bridge (only if compatible with all restrictions), token broker/secret controller if necessary, policy PDP, one-shot migrations. Each gets its own trust boundary, labels, network policies and secrets.

An installed chart must support **gateway-only**, **operator-only**, **gateway+auth**, and independent/fully managed deployments; no implicit auto-installation of all components or provider plugins. App-template's chart `controllers` are for workload objects only; install versioned **Corvi CRDs separately** in a bootstrap/chart phase with cluster-admin privileges belonging to the installer, not the operator. Avoid Helm uninstall automatically deleting CRDs and their data. Kubernetes Roles and service accounts are namespace-scoped by default; any cluster-wide watch/CRD install is an explicit alternative deployment/permission profile.

Operator-created provider workloads **inherit the same security invariants** via a validated restricted PodSpec builder and admission checks. `app-template` values do not automatically secure Pods created later by an operator. OCI registry annotations/third-party plugin descriptors are untrusted: they cannot choose privileged `securityContext`, a new SA, arbitrary `hostPath`, an API token, network access, or extra Secrets.

## 2. Mandatory pod and container security profile

**Pod defaults** (`defaultPodOptions` in app-template):

- `runAsNonRoot: true`, default `runAsUser: 65532`, `runAsGroup: 65532`, `seccompProfile.type: RuntimeDefault`; images must actually run as this UID or a reviewed nonzero UID, without relying on root entrypoints.
- `automountServiceAccountToken: false` globally. Only the operator controller overrides it to `true`, using its own ServiceAccount.
- `hostNetwork: false`, `hostPID: false`, `hostIPC: false`, `shareProcessNamespace: false`, `enableServiceLinks: false`.
- Prefer `appArmorProfile.type: RuntimeDefault` on supported clusters. Optional stronger `Localhost` profiles require node support and testing. Do not set `seccompProfile: Unconfined`.
- Use the Kubernetes **Restricted Pod Security Standard**, with an externally managed namespace configured to enforce/audit/warn `restricted`. PSS alone does **not** enforce a read-only root filesystem, network policy, Secret RBAC or image digests, so use additional admission/CI controls.

**Container defaults** (`controllers.<controllerName>.defaultContainerOptions.securityContext`, applied to init containers with `applyDefaultContainerOptionsToInitContainers: true`):

```yaml
securityContext:
  allowPrivilegeEscalation: false
  privileged: false
  readOnlyRootFilesystem: true
  runAsNonRoot: true
  capabilities:
    drop: [ALL]
    add: [] # explicitly no capabilities may be re-added
```

No `CAP_NET_BIND_SERVICE`: Corvi listens on **unprivileged ports**, e.g. HTTP/MCP `8080`, control-plane gRPC `9090`, and SMTP submission `2525`, with Service/HTTPRoute/Gateway listeners exposing public `443`/`587` if configured. No `hostPort`, `hostNetwork`, `SYS_ADMIN`, setuid entrypoints, privileged root init container, chmod/chown init fixes or host filesystem mounts.

If an app requires writable paths, mount **targeted, bounded `emptyDir`** at `/tmp`/`/run/corvi` and persistent PVCs only at explicit data paths; `readOnlyRootFilesystem` remains `true`. Use `medium: Memory` only for small scratch with `sizeLimit` and memory-accounting budget; ensure process runtime, SQLite WAL/SHM, XDG directories, temp files, certificate rotation and plugin scratch directories work without writes to the image root. App images should include a nonroot `USER 65532:65532` and a usable `HOME`/XDG path. Filesystem group ownership can use `fsGroup: 65532` when compatible with mounted PVCs/Secrets, but group-readable mounts and supplemental groups must be minimal; do not widen every Pod to access unrelated volumes.

Every init/sidecar/Ephemeral Container must meet the same security constraints; use a separate approved build-time step for file ownership instead of privileged init. Do not use the Kubernetes ephemeral debug container feature to evade policy; audit/deny production debug injections unless explicitly approved.

## 3. Least-privilege ServiceAccounts and RBAC

| Component | Kubernetes API token | Suggested SA | Kubernetes Role |
| --- | --- | --- | --- |
| Gateway (REST/MCP/SMTP) | **None** | Dedicated non-privileged SA or `default` with automount false | **None** |
| Corvi OAuth AS | **None** | Separate no-privilege SA | **None** |
| Generic IMAP/JMAP transport / sync worker | **None** | No-privilege SA | **None** |
| Provider OCI gRPC adapter | **None** | Per-provider no-privilege SA | **None** |
| Local bridge / WASM policy runtime / external PDP | **None** | Per-workload no-privilege SA | **None** |
| Metrics, migration, cleanup or indexing Job | **None** unless an exact Kubernetes operation is required | Dedicated no-privilege SA | **None** |
| Operator/controller | **Yes** (only reconciler Pod) | `corvi-operator` | Namespace-scoped minimum CRD/status/finalizer, Lease and managed workloads |
| Optional dedicated Secret/token broker | **Only if explicitly configured to use K8s Secrets API** | `corvi-secret-broker` | `get` on named Secrets; narrowly limited `update/patch` only on approved existing names when rotation truly requires it |

Operator RBAC initially includes namespaced `get,list,watch` on the exact installed Corvi CRD plural resources; `patch,update` on `<plural>/status` and separately `<plural>/finalizers` as needed; `get,list,watch,create,patch,update,delete` on **Deployments/Services/ConfigMaps** *only when it actually manages them* and ownership validation is enforced; `get/create/update` on an approved `Lease` as leader election requires. Prefer named resource restrictions for sensitive reads and narrow managed-configuration writes.

**Not allowed by default:** `ClusterRoleBinding`, `cluster-admin`, verbs `*`, resources `*`, `secrets list/watch`, `secrets create/delete`, `serviceaccounts/token`, `pods/exec`, `pods/attach`, `pods/portforward`, `nodes`, `namespaces`, `rbac.authorization.k8s.io` modifications, `certificatesigningrequests` or `admissionregistration` mutations. `resourceNames` constrains `get/update/patch` on known Secret names; do not assume it constrains arbitrary `create` requests. If managed plugin lifecycle requires workload `create/update` in a namespace, its power to deploy Pods is itself a sensitive boundary: validate immutable image digests and workload service account/security/network placement, and use validating admission policies independent of the operator for enforcement. A Kubernetes Role alone cannot constrain a permitted Deployment's PodSpec.

Multi-namespace or cluster-scoped resources require a separately enabled and documented ClusterRole/ClusterRoleBinding with narrowly listed resources and verbs, installed by a suitably privileged Helm/CRD bootstrap identity, **never implicitly**. Operator credentials do not grant provider OAuth, Corvi MailCredential or mail content read.

## 4. Secret separation and mounted credentials

- Provider management API secrets are mounted **only** into the operator/provider-adapter that requires them. The data plane must not receive provider administrator keys; the operator must not receive mail contents or OAuth AS signing keys.
- Gateway receives only approved upstream IMAP/JMAP/SMTP data-plane credentials and Corvi mail authorization verification material. `corvi-auth` receives its own signing key, OAuth client credentials and transactional DB credentials, not provider admin tokens.
- Token broker, if deployed, has isolated key custody and a narrowly authenticated protocol; no broad `get/list secrets` on the entire namespace. Avoid placing unrelated workloads in a shared Pod where projected secrets become reachable.
- Prefer read-only CSI or Secret projections with explicit file modes, mounted read-only, rather than plaintext secrets in environment variables/Helm values. Avoid leaking Secret material via Helm release history, ConfigMaps, command-line arguments, `/proc`, traces, logs, annotations or Kubernetes status.
- `imagePullSecrets` are consumed by the kubelet: they do **not** justify giving application Pods Kubernetes API tokens. Private image pulls and registry auth are not Kubernetes API RBAC grants to the running process.
- TLS trust bundles are explicitly supplied; cert-manager CSI may mount managed certs without granting the application a general Kubernetes API client. Cross-service gRPC requires mTLS and verification of **authorized peer identity**, not just a trusted certificate chain.

## 5. Network exposure, default-deny and egress policies

- **Ingress default-deny** and **egress default-deny** on namespaces/Pools where the CNI enforces NetworkPolicy; allow only declared connectivity by component.
- Gateway inbound: Gateway API/ingress-controller namespace to HTTP/MCP, an approved authenticated SMTP submission source to the configured unprivileged port; internal control-plane configuration publishing over mTLS; metrics from explicitly allowed monitoring agents. Do not expose internal gRPC, admin, debug, metrics or health listeners to the Internet.
- Gateway outbound: DNS resolver, **approved provider IMAP/SMTP/JMAP endpoints**, remote PDP when configured, optional internal OAuth/JWKS/introspection, token broker, database, object store and OTLP collector according to enabled features. Restrict cloud metadata endpoints, RFC1918/private/loopback destinations as appropriate, and enforce IPv4/**IPv6** egress symmetry; DNS-name/FQDN policies require a CNI with explicit support, because native Kubernetes NetworkPolicy uses IPBlock/pod/namespace selectors, not hostnames.
- Operator outbound: Kubernetes API server, authenticated gRPC provider adapters, approved OCI registries and upstream **provider administration** APIs, and DNS; no unrestricted gateway/mail-message access.
- Auth issuer outbound: configured OIDC IdP and OAuth discovery/metadata endpoints, DB/token broker (if needed), and DNS. Separate ingress for browser auth callbacks/consent, not a cluster-wide unauthenticated admin listener.
- Plugin outbound: only its declared management APIs and required private control-plane gRPC; no arbitrary Pod/cluster network, AWS/GCP metadata, local Kubernetes API or other providers.
- Bridges: isolate provider session/decryption state, preferably sidecar/network namespace shared only with the connecting gateway where loopback-only requirements mandate it; **never** make a loopback-only bridge globally reachable by a Service. Bridge must still meet the rootless, capability-free, read-only-root restrictions.
- Namespace Selector rules must not trust arbitrary attacker-set labels in shared namespaces; where appropriate use dedicated namespaces and admission-protected workload labels. Default deny is ineffective without a working CNI implementing policies, so CI/integration tests must verify actual traffic, including IPv6.

## 6. Workload lifecycle and operational hardening

- **Build supply chain:** run CI to generate reproducible minimal rootless images with a nonzero `USER`, SBOM and signed provenance where available; pin immutable image **digests** and Helm dependency versions; scan dependencies/images and record policy exceptions with expiry. Do not deploy mutable `latest` tags. Mirror external OCI provider images only under digest/signature allowlists.
- **No writable image root:** provide only named scratch directories and named PVCs; bound `ephemeral-storage` and memory usage; avoid shell-reliant entrypoints and package-manager operations on start. Ensure rootless TLS file, cert-manager CSI, Unix socket and SQLite access with tests.
- **Resource requests and limits:** conservative CPU/memory requests, memory and `ephemeral-storage` limits; avoid CPU hard limits where latency-sensitive and avoid turning a rootless migration into a DoS via unrestricted resources. Apply namespace `LimitRange` and `ResourceQuota` where appropriate.
- **Probes:** configure startup/readiness/liveness on **nonprivileged localhost ports**, ensure readiness tests authorization/config readiness, not upstream provider availability for unrelated mailboxes. Liveness must not crash loop on temporary provider/DB outages. Shutdown drains subscriptions/sends and respects queue/idempotency state.
- **Availability:** PDB and topology spread for stateful, horizontally scaled gateway/auth deployments where safe; one writer or fenced leases for SQLite/sync and OAuth token refresh; avoid PDB/deployment replicas that imply unsupported HA semantics.
- **Storage:** PVs are writable only by the correct rootless UID/GID; provision SQLite as local single-instance RWO, PostgreSQL for HA; do not mount unrelated provider keys into gateway. Sensitive scratch should avoid shared or host-accessible volumes.
- **Pod security:** no hostPath, host devices, host namespace access, privileged container, hostPorts, host PID/IPC/network, unsafe sysctls, host process mounting or unrestricted user namespaces. **Do not make arbitrary PodSecurity exceptions in values**. If user namespaces (`hostUsers: false`) are explicitly supported by the cluster, validate PVC and CSI behavior before enabling.
- **Chart lifecycle:** install/update CRDs separately with a versioned compatibility matrix, apply namespace PSS enforcement intentionally, preserve PVCs/Secrets by retention policy, block accidental deletion of grants or bridge state, rotate signing keys/certs with overlap, and report incompatible migrations before rollout.
- **Health and telemetry:** no token/mail subject/address as metric labels; require authenticated private admin/metrics endpoints, sanitize errors, and log only safe provenance/authorization decisions.
- **Policy-as-code:** use `helm template` and JSON Schema + `kubeconform`, Pod Security Admission `restricted`, Kyverno/Gatekeeper/ValidatingAdmissionPolicy as available, and `kubectl auth can-i` checks for each SA. CI inspects every rendered container/init container and managed provider PodSpec; reject security-context relaxations even if chart `values` schema allows them.

## 7. App-template v5 example and constraints

The [gateway values example](../../deploy/helm/app-template/gateway.values.example.yaml) uses **`defaultPodOptions`** at chart root and **per-controller `defaultContainerOptions`** to cover containers and init containers (set `applyDefaultContainerOptionsToInitContainers: true`). Each controller has its own values; there is no global `controllers.defaultContainerOptions` key. The [operator example](../../deploy/helm/app-template/operator.values.example.yaml) overrides only `controllers.operator.pod.automountServiceAccountToken: true` and selects the chart-generated `ServiceAccount` via `controllers.operator.serviceAccount.identifier`. It uses app-template's `serviceAccount` and `rbac.roles`/`rbac.bindings` for minimal namespaced RoleBindings.

The values examples are **design fixtures**: no Corvi image release is published; `repository` and `tag` are placeholders which cannot be deployed as-is. Exact `app-template` 5.2.1 rendering must be pinned and validated before calling them a release. Every future change to `defaultPodOptions`, `defaultContainerOptions`, chart major version or plugin PodSpec builder is subject to hardening review and rendered-manifest tests. Only `corvi-operator` may have a Kubernetes API token in the default install.

Proposed chart wrapper layout, if/when implementation begins:

```text
charts/corvi-gateway/
  Chart.yaml                  # app-template pinned dependency
  values.yaml                 # secure defaults, disabled optional features
  values.schema.json          # reject unsafe overrides / incompatible features
  templates/                  # only Corvi-specific policy/validation resources
charts/corvi-operator/
  Chart.yaml                  # app-template pinned dependency
  values.yaml                 # secure defaults, scoped API access
  values.schema.json
charts/corvi-crds/
  crds/                       # versioned bootstrap; separate lifecycle
```

`app-template` is a workload base, **not** a justification to duplicate Corvi CRD permissions or grant Helm installation rights to the application ServiceAccount. A thin wrapper may pass values through a pinned dependency; an alternative is a chart-provided values profile installed directly against pinned `app-template`. In either case secure defaults are immutable in CI/admission and incompatible overrides cause installation failure.

## 8. Acceptance criteria

1. Rendered **every** application, init, migration, plugin and bridge container runs non-root with `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, `privileged: false`, `capabilities.drop: [ALL]`, **no added Linux capabilities**, and pod/runtime seccomp `RuntimeDefault`. No root/chown init exception.
2. All generated gateway/auth/provider adapter/bridge/PDP/metrics Pods have `automountServiceAccountToken: false` and no projected Kubernetes API token. The operator alone mounts a token by default. No automatic static long-lived SA tokens.
3. The operator SA's namespace Role can only touch documented namespaced CRDs/status/finalizers, selected leases and directly managed workloads. No wildcard verbs/resources, `cluster-admin`, forbidden subresources, Secret list/watch, or token-minting permissions.
4. Restricted Pod Security Admission (including any managed provider Pods) and extra read-only-root/no-capability admission policy pass; unsafe OCI plugin manifests or broad RBAC/secret references are rejected.
5. Namespace ingress/egress default-deny plus required DNS, Kubernetes API, upstream, DB and monitoring flows work without blanket `0.0.0.0/0`/`::/0` or public metadata access, under a CNI with actual policy enforcement.
6. Rootless operation succeeds with read-only images, bounded emptyDir/PVC mounts, certificate/key read permissions and unprivileged SMTP listener; no SETUID/root privileges or host mounts.
7. The gateway remains available for existing authorized operations when operator/Kubernetes API is temporarily down, subject to existing snapshot freshness/expiry policy, and does not gain API credentials.
8. Operator-only install uses Kubernetes CRD spec/status/Secrets/Leases for persistence with no SQLite/PostgreSQL requirement. Gateway-only chart needs no operator API permissions.
9. Missing/invalid image digest, unsigned/unapproved plugin, mutable chart major change, invalid security override, PodSpec template escape, and ambiguous secret access all fail CI/admission before production.
10. No public ingress/admin/metrics/health path unintentionally allows unauthenticated mail/provider/OAuth management data, and no secret appears in Helm values, release history, Pod env, log or chart notes.

## References

- [bjw-s-labs app-template reference (v5)](https://bjw-s-labs.github.io/helm-charts/docs/app-template/)
- [app-template defaultPodOptions](https://bjw-s-labs.github.io/helm-charts/docs/app-template/reference/defaultpodoptions/)
- [app-template defaultContainerOptions](https://bjw-s-labs.github.io/helm-charts/docs/app-template/reference/controllers/defaultcontaineroptions/)
- [app-template ServiceAccounts](https://bjw-s-labs.github.io/helm-charts/docs/app-template/reference/serviceaccount/)
- [app-template Roles and RoleBindings](https://bjw-s-labs.github.io/helm-charts/docs/app-template/reference/rbac/)
- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Kubernetes good practices for RBAC](https://kubernetes.io/docs/concepts/security/rbac-good-practices/)
- [Kubernetes NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [OWASP Kubernetes Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html)

## Consequences

The operator can reconcile providers through Kubernetes without an extra database while the gateway remains **rootless, capability-free, read-only, and free of Kubernetes API credentials**. The design adds CI/admission policy, explicitly approved provider-plugin boundaries and CNI/Secret-store integration requirements. Functionality requiring privileged upstream bridge runtimes is **not supported in the hardened in-cluster profile**; manage a verified external bridge instead.

---
This document records a proposed Helm design and hardening contract, not a functioning released chart.
