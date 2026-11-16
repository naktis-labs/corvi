# ADR-0011: Hardened Helm deployments with bjw-s app-template

- **Status:** Proposed (design, not a released chart)
- **Date:** 2026-11-16
- **Scope:** Kubernetes packaging for Corvi gateway, OAuth service, provider-management operator, plugin workloads, bridges and maintenance Jobs
- **Related:** [ADR-0001](0001-corvi-system-architecture.md), [ADR-0004](0004-pluggable-grpc-policy-engines.md), [ADR-0006](0006-local-transport-bridges.md), [ADR-0008](0008-interactive-upstream-oauth.md), [ADR-0009](0009-corvi-oauth-and-identity-grants.md), [ADR-0010](0010-storage-and-durability.md)
- **Illustrative app-template values:** [gateway](../../deploy/helm/app-template-gateway.values.yaml), [operator](../../deploy/helm/app-template-operator.values.yaml)
- **Supplemental deployment guide:** [chart usage and validation](../../deploy/helm/app-template/README.md), [default-deny/DNS NetworkPolicy fixture](../../deploy/helm/app-template/networkpolicy.example.yaml)

## Decision

Build the initial Kubernetes deployment around **bjw-s-labs `app-template` v5**, pinned and tested (initial design baseline **5.3.0**, released October 2026), rather than building a second generic Deployment/Service/PVC templating framework. Its Common Library already models controllers, containers, Services, HTTPRoutes, persistence, ServiceAccounts, RBAC, NetworkPolicies and `rawResources`. Only Corvi-specific lifecycle/admission behavior requires additional templates/code.

**Every Corvi-owned container MUST be rootless with no Linux capabilities, no privilege escalation, explicit runtime-default seccomp and a read-only image root filesystem.** This covers main containers, sidecars, init containers, migration Jobs, plugin-runtime containers and **operator-created managed bridges**. A third-party image that cannot meet this profile is **unsupported as a managed workload** rather than a reason to weaken deployment defaults. An existing independently operated bridge may remain usable outside the managed-Pod deployment, with explicit trust/security warnings (ADR-0006).

The **operator needs Kubernetes API access**, but gateway, OAuth web/token service, provider plugin, bridge and normal maintenance workers **do not get an API token by default**. Only components with a demonstrated API operation receive a dedicated ServiceAccount, narrow role and token projection. A component sharing a Pod with the operator also shares that Pod's mounted token; therefore **do not co-locate the operator with untrusted provider plugins or bridge containers**.

## 1. Chart packaging and release boundary

Suggested source layout, to be implemented after the ADR:

```text
charts/
  corvi/                      # Packaging/chart composition or release profiles
  corvi-crds/                 # Independently versioned CRD lifecycle
deploy/helm/
  app-template-gateway.values.yaml   # Design example; not deployable
  app-template-operator.values.yaml  # Design example; not deployable
```

**Release profiles** (each independently enableable, preferably separate Helm releases/app-template instances for smallest blast radius):

| Profile | Controller | Kubernetes API token | Persistence/owner |
| --- | --- | --- | --- |
| `gateway` | Deployment or StatefulSet (when local SQLite) | **No** | Validated active snapshot, data-plane SQLite/PVC or external PostgreSQL |
| `oauth` | Optional Deployment, possibly same Rust binary but separate listener/Pod | **No** | OAuth SQLite/PVC or PostgreSQL, independent token/grant domain |
| `operator` | Deployment with a dedicated SA | **Yes, strictly scoped** | **Kubernetes CRDs/status/Leases; no operator database** |
| `provider-plugin` | Operator-managed digest-pinned Deployment/Job | **No** | Explicit provider-admin secret refs only; no arbitrary Kubernetes rights |
| `bridge` | Opt-in operator-managed rootless sidecar or carefully isolated Pod | **No** | Dedicated per-account persistent state and generated local credentials |
| `migrations` | Optional Job, separately authorized DB credentials | **No** | Transactional schema migrations; no Kubernetes RBAC |
| `policy-wasm` | In-process runtime; **not** a separate Pod for OCI-WASM images | **No** | Verified, digest-pinned WASM module/image volume |
| `external-pdp` | Optional separately deployed component | **No** unless its own documented feature requires it | mTLS, narrowly scoped metadata; never mail-body-by-default |

Use **one chosen source for generated Kubernetes objects**: bjw-s app-template for ordinary workload resources, with Corvi-specific Helm templates or a small pre-install/bootstrap chart **only for CRDs/admission policies and resources not adequately represented by the library**. Avoid duplicated Deployments between chart and operator. The operator controls plugin/bridge Pods at runtime from validated CRDs; Helm doesn't maintain every dynamic provider instance.

- **CRDs:** install/update separately (dedicated `corvi-crds` release or GitOps-controlled CRD bundle). Helm `crds/` files are not a complete CRD upgrade/uninstall strategy. Preserve conversion/version-skew tests; uninstalling workloads must not silently delete providers, mail identities or secrets.
- **Chart dependency:** pin app-template to an exact tested version/OCI digest where tool support permits; use Renovate and compatibility CI before bumps. v5 chart requires Kubernetes >=1.31 and Helm >=3.18 according to its release notes; verify the chart's exact requirements during packaging.
- **Profiles:** `gateway-only`, `operator-only`, `gateway+OAuth`, `full managed` and `existingBridge`. Disabling optional components creates **no RBAC or dangling service accounts** for them.
- **Values:** use bjw-s keys such as `controllers`, `defaultPodOptions`, `controllers.*.defaultContainerOptions`, `serviceAccount`, `rbac`, `service`, `route`, `persistence`, `networkpolicies` and `rawResources`; chart-specific higher-level values must render these without exposing a bypass for mandatory hardening.
- **Dangerous defaults are not overridable by ordinary values**: any `extraContainers`, custom templates, init containers, operator-generated Pods or raw manifests require the same admission profile, with CI validation and explicit operator/admin review.

## 2. Mandatory Pod and container security profile

**Pod-level** (all Linux Corvi workloads):

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 65532
  runAsGroup: 65532
  seccompProfile:
    type: RuntimeDefault
automountServiceAccountToken: false
enableServiceLinks: false
hostNetwork: false
hostPID: false
hostIPC: false
```

**Each container and init container** (explicit or inherited from tested app-template `defaultContainerOptions`):

```yaml
securityContext:
  allowPrivilegeEscalation: false
  privileged: false
  readOnlyRootFilesystem: true
  runAsNonRoot: true
  runAsUser: 65532
  runAsGroup: 65532
  capabilities:
    drop: ["ALL"]
  seccompProfile:
    type: RuntimeDefault
  procMount: Default
```

- **No `capabilities.add` at all**, including `NET_BIND_SERVICE`. Bind HTTP/MCP/OAuth/SMTP submission listeners to **unprivileged ports** (e.g. 8080, 8081, 8587/8465) and map external 80/443/587/465 at Service, Gateway API, proxy or load-balancer level. No `hostPort`, privileged `hostNetwork`, host-mounted sockets or direct `hostPath`.
- **No root-based `chown`/install/permissions init containers**. Build official images with a matching numeric user/group, writable *mounted* paths and statically linked/appropriately packaged binaries, and test filesystem ownership. Use a minimal/distroless production image; no package manager, interactive shell or bundled credential files required at runtime.
- The filesystem root stays read-only. Mount only explicitly required `emptyDir` volumes for `/tmp` and runtime scratch (size-limited, optionally Memory-backed), and dedicated writable PVCs for SQLite or bridge session state. Provider secret and certificate mounts are **read-only** with `defaultMode: 0400`/appropriate ownership. Avoid mount of the entire Kubernetes Secret directory where only a key is needed.
- App-template v5 `controllers.*.defaultContainerOptions` normally applies to **both init and regular containers**, but per-container values can **overwrite entire securityContext maps**. Every rendered container is validated; never assume a default inherited when a third-party values fragment overrides it.
- `fsGroup`, `fsGroupChangePolicy` and CSI `fsGroup` support are **opt-in only for volumes that genuinely require them**. Don't use `fsGroup: 0` to solve permissions. For shared storage, prefer CSI-native permission support or compatible rootless pre-provisioning, not a privileged fixer.
- Consider `appArmorProfile: RuntimeDefault` on compatible nodes; reject `Unconfined` where enforceable. Configure SELinux profiles/nodes, user namespaces (`hostUsers: false` where supported), and seccomp `Localhost` profiles as **optional stronger hardening**, never relaxing the required `RuntimeDefault` baseline.
- Disallow `procMount: Unmasked`, `hostUsers: true` exceptions, `shareProcessNamespace` by default, host devices, privileged sysctls, `hostPath`, writable host socket mounts, and unsafe volume mount propagation. No Docker socket, CRI socket or Kubelet credentials.
- Assign bounded requests/limits for memory and ephemeral storage and reasonable CPU requests, configurable per workload. Avoid arbitrary huge defaults on small clusters. Memory `limits` need not equal `requests`; CPU limits may be optional to avoid throttling, subject to namespace policy.
- Run lifecycle health probes on private, unauthenticated-but-non-sensitive ports/paths that do not expose mail or secret data. Separate readiness from liveness; tolerate provider/IdP/controller outages without crash loops that turn transient errors into wider incidents.

**Pod Security Admission:** namespace(s) labeled `pod-security.kubernetes.io/enforce: restricted` (also `audit` and `warn`). Restricted PSS does **not** itself require `readOnlyRootFilesystem`, so enforce **all** of Corvi's stronger rules in chart/schema/CI and, where deployed, native ValidatingAdmissionPolicy/Gatekeeper/Kyverno. Validate security contexts for operator-created Pods, not merely chart-rendered Deployments.

## 3. Service accounts, tokens and RBAC

**Default deny by omission:** every controller uses a distinct ServiceAccount (or an explicitly selected, unprivileged default account) with `automountServiceAccountToken: false` **at both Pod and ServiceAccount level** where possible. `serviceAccount.staticToken: false`; never create a legacy long-lived SA token. app-template v5 defaults to per-release unprivileged SA and disabled automount, but **write the settings explicitly** and verify rendered output.

| Workload | SA/token | RBAC |
| --- | --- | --- |
| Gateway (REST/MCP/SMTP) | Dedicated `corvi-gateway`, **no token** | None |
| OAuth AS/broker | Dedicated `corvi-oauth`, **no token** | None |
| Operator/provider reconciler | Dedicated `corvi-operator`, **token required** | Scoped CRD read/watch/update status/finalizer, approved generated object lifecycle and Lease |
| Provider plugin (including Migadu) | Per-plugin unprivileged SA, **no token** | None; gRPC+mTLS access to control plane is not Kubernetes RBAC |
| Managed local bridge | Per-account unprivileged SA, **no token** | None |
| WASM policy loader | Shares gateway process; **no token** | OCI module retrieval uses registry credentials, not K8s bearer token |
| Migration/backup worker | Dedicated no-token SA | No K8s RBAC; dedicated DB/secret credentials as appropriate |
| Secret/cert controller | **External operator's own SA** | Don't add external controller rights to Corvi's operator |
| Optional programmatic Secret rotator | Dedicated restricted SA **only if really needed** | Explicit named Secret `get`/`update` where supported, never namespace-wide listing by default |

Operator RBAC design:
- **Namespaced controller mode is preferred.** Namespaced `Role` / `RoleBinding` for allowed CRD resources, `status` and `finalizers` subresources; `get,list,watch` for intended kinds; `create,patch,update,delete` only for needed managed Deployments/Jobs/Services/ConfigMaps; `leases` `get,create,update,patch` in a designated election namespace; Secrets **only named, minimal get permissions** or indirect reference to externally mounted Secrets. Some Kubernetes RBAC operations (e.g. `create`, `list`, `watch`) cannot be limited by `resourceNames` as a general strategy; combine namespace isolation and admission policy. Do not grant `list secrets` casually.
- **Cluster-scope watch is an explicit alternate install mode**, with a narrowly scoped ClusterRole/ClusterRoleBinding only for CRDs/resources needing cluster-wide watch. CRD installation/upgrade, Namespace changes, RBAC role creation, impersonation, CSR approval and admission policy installation belong to **separate installer/GitOps permissions**, not the runtime operator.
- No `cluster-admin`, wildcard `apiGroups/resources/verbs`, `escalate`/`bind`/`impersonate`, arbitrary Secrets enumerate, `pods/exec`, `pods/attach`, `pods/portforward`, `serviceaccounts/token`, node/proxy, workload privilege changes or webhooks in the runtime Role.
- **Token mount:** set `defaultPodOptions.automountServiceAccountToken: false` globally. Operator-only Pod uses `controllers.operator.pod.automountServiceAccountToken: true` **or**, preferably, a separate projected `serviceAccountToken` volume with short expiration and an API-server audience, with the default mount still disabled. Use a bounded TTL and validate it works for the controller's client implementation; do not configure both automatic and projected mounts.
- Don't mount operator API tokens in provider-plugin, bridge or mail-gateway Pods. If an operator needs Kubernetes Secrets, grant the operator SA appropriately and avoid sending its service account token through plugin gRPC. Do not let plugins request arbitrary RBAC, ServiceAccounts or Pod spec modifications through metadata.

## 4. Network and entry-point isolation

- **Default-deny ingress and egress NetworkPolicies** on each component; allow only the exact required peer/port/protocol combinations. NetworkPolicy enforcement depends on the cluster's CNI; verify actual enforced behavior, and use Cilium policies/FQDN/egress gateway where appropriate for stable provider DNS allowlists. Standard Kubernetes NetworkPolicy is L3/L4 and has **no native FQDN selector**.
- Gateway ingress: from chosen Gateway API proxy/ingress controller namespaces to HTTP REST/MCP, and optionally from approved SMTP client networks to the submission Service. Do **not** publish inbound MX port 25. No NodePort/LoadBalancer by default; internal ClusterIP services.
- OAuth ingress: TLS-terminated, verified `/oauth/*` endpoints with separate allowed hostname/route and strict redirect/origin policy. Administrative onboarding and callback routes must not share unrestricted exposure with public mail APIs.
- Operator/provider gRPC: private ClusterIP, verified mTLS (cert-manager CSI when supported, Certificate+Secret fallback). Operator-to-Kubernetes API TCP 443/6443 egress only as actually configured. Avoid mTLS assumptions for HTTP external providers; validate appropriate HTTPS CA and pinned provider URL trust.
- Upstream network: allow gateway to configured JMAP HTTPS / IMAP TLS / SMTP TLS and selected PostgreSQL/secret broker/OTLP endpoints. Operator/plugin egress is restricted to approved provider management, OCI registry, approved secret services and Kubernetes API as required. Bridges need only their configured upstream provider endpoints and local transport.
- **DNS**: permit actual CoreDNS/kube-dns UDP/TCP 53 endpoints, allowing dual-stack IPv4/IPv6 when used. Do not conflate `::/0` or `0.0.0.0/0` with restricted egress; explicitly model proxy/FQDN enforcement or approved IP ranges.
- **Managed bridge loopback**: same Pod / network namespace when the bridge only listens on localhost. NetworkPolicy **does not isolate containers in one Pod**; local bridge TCP listeners are reachable by all containers sharing the Pod and any injected sidecars. Don't inject untrusted extra containers into the bridge Pod; keep per-account state and exposure isolated.
- Gateway API `HTTPRoute` recommended for HTTPS mail/OAuth routing, with dedicated host/path mapping; TLS secrets live in Gateway controller's trust domain, and `ReferenceGrant` only when a cross-namespace reference is approved. No unrestricted `allowCrossNamespace`. Use NetworkPolicy to restrict direct Pod reachability and avoid a route that bypasses Corvi authorization.
- Admin APIs private by default (not automatically on an HTTPRoute); secure auth, ingress restrictions and mTLS/authorization as applicable. Metrics/OTLP ports private; no external scrape API that leaks mailbox or tenant identifiers.

## 5. Images, plugins and OCI-WASM supply chain

- Pin all Corvi container images **by immutable digest** in production; publish signed SBOM/provenance and scan for CVEs, malformed layers and embedded credentials. Restrict trusted registries, signatures and build identities using admission policy. Chart dependency pinning and container image digest pinning are separate controls.
- Build Rust binaries to execute as numeric UID/GID `65532` (or a documented other nonzero UID matching volumes) and **never** rely on running an entrypoint root to drop privileges after startup. Multi-arch images should support required platforms and not require a writable home or `/etc`.
- Plugins are untrusted OCI-sourced workloads. The operator enforces digest/signature policy and a **closed Pod security profile**: no privilege, no added capabilities, non-root numeric UID, root FS read-only, seccomp, separate no-token SA, only approved volumes/env/network/Secret refs, bounded resources, port allowlists and no arbitrary init/sidecars. A plugin's OCI annotations/discovery do not bypass these checks.
- If `app-template` launches static plugin replicas, apply the same security profile there; for dynamic plugins/bridges, the operator's pod-builder/admission checks are the enforcement boundary.
- OCI-WASM policy modules are **data artifacts executed under Wasmtime in the gateway process** (ADR-0004), not an extra Kubernetes runtime with extra privileges. Use digest verification and sandbox Wasmtime imports, memory/fuel/epoch limits and deny network/FS access by default. Kubernetes OCI image-volume availability is version/feature-gated; verify support and keep alternate OCI-WASM delivery.
- Sidecars (observability, cert refresh, bridge) are **never automatically trusted** by Pod co-location. Set each container's explicit securityContext and minimal mounts and process credentials. Prefer log-to-stdout and existing OTLP rather than broad log/host collectors.

## 6. Secret handling, writable volumes and lifecycle

- `Secret` and cert/key volumes mount **read-only** at component-specific paths. Prefer external secret management/KMS with at-rest encryption, restrict operator's Secret RBAC, and avoid Helm `secrets:` values containing literal OAuth/SMTP/password/key material or chart-rendered Secret objects with plaintext values.
- Standalone SQLite when inside Kubernetes requires an explicitly single-writer PVC, compatible owner/group permissions, backup and failure policy. PostgreSQL in HA is outside the operator persistence domain (ADR-0010). The **operator itself requires neither SQLite nor PostgreSQL**.
- Use `emptyDir` (bounded, optionally `medium: Memory`) for `/tmp`/runtime scratch only when needed. All other filesystem paths are read-only; never permit a Pod to write to the image root. Bridge runtime account/session directories and OAuth state use separate account-scoped PVCs/Secrets.
- Do **not** automatically deploy database migrations as a privileged `helm hook` with broad cluster rights. Run migrations as rootless Jobs with narrow **DB** credentials and no Kubernetes API token, backed by checksum/version gating and retry-safe schema locks.
- Avoid destructive post-delete hooks, surprise deletion of PVCs or provider CRDs, blind replacement of bridge state, and unbounded init loops. `preStop`, graceful termination, terminationGracePeriodSeconds, PDBs, readiness gates and anti-affinity should protect the queue and OAuth token writer from unsafe rolling updates.
- Allow image pull secrets **for fetching images**, but the Pod should not receive an API token or other Kubernetes RBAC privileges for pulling a private OCI image.
- Certificates: mTLS between operator/plugins and config publisher; prefer cert-manager CSI if present, fallback to mounted Certificate Secret, and supply CA bundle separately. Key files are read-only, scoped per workload and rotated without temporary plaintext fallback.

## 7. Multi-instance behavior and operator outage

- Gateway does **not** call Kubernetes API or require its bearer token to serve existing authorized reads/submissions. Active configuration is versioned and last-known-good; a controller outage does not drop functioning sessions until explicit staleness/expiry limits.
- Operator-only deployment is a no-database Kubernetes reconciler with optional leader election and sanitized CRD status. It must recover via watch/list after restart and use `status.observedGeneration`, finalizers and optimistic conflict retries.
- `oauth` and gateway can be deployed separately but still use an appropriate transactional SQLite/PostgreSQL state backend when their enabled features require durability. Their DB credentials are not Kubernetes API permissions.
- Provider plugin failures don't imply gateway outage; a **bridge outage** affects only attached mailbox transports, without weakening gateway isolation.
- Token broker/secret integration should not entail mounting a Kubernetes API service-account token into every gateway just to retrieve a Secret. Use operator/secret-controller projection or narrowly brokered delivery.

## 8. Acceptance tests and release gates

1. Render gateway, OAuth, operator, provider-plugin, bridge and migration Jobs. **Every Linux container/init container** has `runAsNonRoot=true`, UID/GID nonzero, `allowPrivilegeEscalation=false`, `privileged=false`, `readOnlyRootFilesystem=true`, `capabilities.drop` containing `ALL`, no `capabilities.add`, and effective `RuntimeDefault` seccomp.
2. No generated workload mounts an SA token except explicitly authorized API-using controllers. Verify no legacy static token Secret, no `cluster-admin` binding and separate scoped Role/RoleBinding. Use `kubectl auth can-i --as=system:serviceaccount:...` negative/positive tests for each component.
3. Validate the **operator-created** plugin and managed bridge Pod manifests against the **same policy**, including negative tests for untrusted OCI metadata asking for root, hostPath, extra capabilities, API token, root-run init or oversized resources. Reconcile should reject these requirements rather than silently weaken defaults.
4. Chart rendering under Kubernetes `restricted` PSS and policy-engine rules passes for every profile and optional init/Job; `helm template`, `helm lint`, app-template schema validation, `kubeconform`, `kubectl --dry-run=server`, and policy-as-code tests run in CI.
5. No network route bypasses Corvi auth; default-deny ingress/egress plus DNS/upstream provider/DB/HTTPS/mTLS exceptions are minimized and tested for **both IPv4 and IPv6**.
6. Read-only image root + bounded writable mounts work on fresh PVCs without privileged `chmod`/`chown` Jobs. Volume owner differences lead to early actionable failure, not a root-init fallback.
7. Operator-only Kubernetes profile starts with **no PostgreSQL/SQLite/Redis**, no data plane and no secret exposure through CRD status; lost Kubernetes API suspends reconcile without requiring gateway token access.
8. Standalone gateway in Kubernetes starts with **no Kubernetes token**; native IMAP/JMAP upstream access, optional SMTP AUTH and client-facing OAuth protection function with required configured secrets and verified TLS.
9. Optional embedded OAuth issuer, queue, Tasks and JMAP/IMAP checkpoints use configured state with SQLite single-owner or PostgreSQL HA as appropriate, never the operator's CRD status store.
10. Image/supply-chain tests reject mutable `latest`, untrusted plugin digest, malformed signature, unsupported non-root image and missing SBOM per published release gate.
11. Chart upgrade/rollback and CRD conversion are tested independently; no surprise credential/PVC deletion, accidental privileged new hook or restart of active bridge accounts.
12. Admission policies and deployment scans refuse securityContext override via values, `rawResources`, arbitrary sidecars and unmanaged operator-generated workloads.

## References

- [bjw-s-labs app-template](https://bjw-s-labs.github.io/helm-charts/docs/app-template/)
- [bjw-s-labs app-template v5 default Pod options](https://bjw-s-labs.github.io/helm-charts/docs/app-template/reference/defaultpodoptions/)
- [bjw-s-labs app-template default container options](https://bjw-s-labs.github.io/helm-charts/docs/app-template/howto/default-container-options/)
- [bjw-s-labs v4 → v5 migration](https://bjw-s-labs.github.io/helm-charts/docs/app-template/upgrades/4-to-5/)
- [Kubernetes Restricted Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Kubernetes security context](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Kubernetes RBAC reference](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Kubernetes ServiceAccount token projection](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/)

## Consequences

bjw-s app-template supplies the standardized Kubernetes resource rendering, while Corvi enforces a **closed, rootless, no-capabilities, no-default-token execution profile** across both statically rendered and dynamically operator-managed workloads. The trade-off is rejecting incompatible third-party plugin/bridge images and keeping explicit dedicated permissions, networks, volumes and credentials for each component. Operator management state remains Kubernetes-native, independent of optional SQLite/PostgreSQL data-plane and OAuth state.

---
This ADR defines the chart and security contract; it does **not** claim a usable released Helm chart, CRD installer or audited Kubernetes manifests exist yet.
