# Corvi Helm deployment design based on bjw-s app-template

**Design fixtures only, not a released or deployable Corvi chart.** The application images, health endpoints, runtime env/config contract, CRD groups, CRD plural names and admission policies are not implemented/finalized. The examples must not be installed without that implementation and validation.

Read [ADR-0011: Helm chart and Kubernetes hardening](../../../docs/adr/0011-hardened-helm-deployment.md) and [ADR-0010: Kubernetes-native control-plane storage](../../../docs/adr/0010-storage-and-durability.md).

## Profiles

| File | Workload | Kubernetes token | Permissions |
| --- | --- | --- | --- |
| [`app-template-gateway.values.yaml`](../app-template-gateway.values.yaml) | Provider-neutral REST/MCP/SMTP gateway, optionally native IMAP/JMAP | **No** | No Kubernetes Role |
| [`app-template-operator.values.yaml`](../app-template-operator.values.yaml) | Kubernetes CRD controller and approved OCI provider plugin manager | **Yes** | Namespaced Role only; read CRDs, patch status/finalizers, manage limited workloads, Lease |
| [`networkpolicy.example.yaml`](networkpolicy.example.yaml) | Default-deny and bounded DNS egress for Corvi namespace | N/A | Independently add explicitly approved per-component network flows |

A gateway can alternatively be created by the operator from a namespaced [`CorviGateway` resource](../../examples/corvi-gateway.example.yaml), documented in [ADR-0012](../../../docs/adr/0012-corvi-gateway-deployment-crd.md). In that mode, **do not install a Helm-direct app-template gateway release owning the same Deployment/Service**. Helm still installs the operator (and separate CRD bootstrap), while the operator builds equally hardened gateway PodSpecs directly rather than spawning Helm per CRD.

Independent Corvi OAuth issuer, provider adapters, WASM/PDP and bridge runtime use the **same container/pod hardening profile** as gateway with separate namespace/ServiceAccounts/network and Secret references. They are not automatically enabled by the operator release. Only the operator normally needs the Kubernetes API.

## Chart base

Pin the OCI chart and render its values from the corresponding example. Reference pinned design release: **bjw-s-labs/app-template 5.3.0**, from `oci://ghcr.io/bjw-s-labs/helm/app-template`. Newer compatible versions may be evaluated with rendered-manifest testing and explicit bump. Production Helm dependencies and images must be pinned and provenance-verified; this design example intentionally does not invent an available Corvi image digest.

After real release images and health paths exist, render and inspect:

```sh
helm template corvi-gateway \
  oci://ghcr.io/bjw-s-labs/helm/app-template \
  --version 5.3.0 \
  --namespace corvi-system \
  -f deploy/helm/app-template-gateway.values.yaml > /tmp/corvi-gateway.yaml

helm template corvi-operator \
  oci://ghcr.io/bjw-s-labs/helm/app-template \
  --version 5.3.0 \
  --namespace corvi-system \
  -f deploy/helm/app-template-operator.values.yaml > /tmp/corvi-operator.yaml
```

These commands are **future CI targets**, not a claim they currently pass or that the example workloads boot.

The chart values use `defaultPodOptions` at the chart root, **per-controller** `defaultContainerOptions`, `serviceAccount` and `rbac.roles`/`rbac.bindings`. `applyDefaultContainerOptionsToInitContainers` is explicit. **Do not assume values defaulting is an enforcement mechanism:** a chart upgrade or controller/container override could weaken it. Examine the complete final rendered PodSpecs and run independent admission checks.

## Hardening invariants

Every rendered Pod and init/ephemeral/regular container must satisfy:

```yaml
spec:
  automountServiceAccountToken: false # true only for operator Pod
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    runAsGroup: 65532
    seccompProfile: {type: RuntimeDefault}
  containers:
    - name: example
      securityContext:
        privileged: false
        runAsNonRoot: true
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: [ALL]
          add: []
```

No root init Jobs, `chown` hacks, added Linux capabilities, hostNetwork/hostPID/hostIPC/hostPorts, hostPath, insecure sysctls, privileged containers or host devices. Rootless ports (HTTP 8080, SMTP 2525, internal gRPC 9090) can be exposed via Services/Gateway API while the process binds only unprivileged ports.

Provide bounded scratch via `emptyDir`; for SQLite/PVC mount use an explicitly tested UID/GID/fsGroup access strategy. Never flip `readOnlyRootFilesystem` to false to make a third-party plugin/bridge work. If an external bridge is incompatible, declare managed in-cluster bridge unsupported for that provider.

Images, optional read-only policy WASM image volumes, Secrets and CRDs are separate from runtime Kubernetes API credentials. `imagePullSecrets` do not require an API token in the app container.

## RBAC and CRD lifecycle

Install versioned Corvi CRDs independently via a bootstrap chart or GitOps manifests using the **installer's** privileged identity. Do **not** give Corvi's operator permission to install its own CRDs, write RBAC/ClusterRoleBindings or access arbitrary Secrets. Operator namespaces must be explicit.

The operator Role example includes `corvigateways` with namespaced `get/list/watch` and scoped `status`/`finalizers` writes, plus the ability to reconcile Deployments/StatefulSets. The CRD and workload implementation are not yet released. The operator Role example contains **provisional CRD plural names and API groups** and must be reconciled with real generated manifests before use. The RoleBinding's `subjects[].namespace` must match the release namespace. Narrow or remove plugin Deployment/Service/ConfigMap permissions in read-only configurations. For `secrets`, prefer projected read-only named Secrets; a broker that truly performs dynamic rotation needs its own scoped SA/Role. **No wildcard resources/verbs or Secrets list/watch.**

RBAC allowing `deployments create` is a privileged workflow: Kubernetes RBAC cannot constrain the Pod template. An independent validating policy must reject arbitrary ServiceAccounts, token automounts, elevated Pod security, image/registry changes, volume mounts and unknown secrets from operator-created plugin Deployments.

## NetworkPolicy

Apply [`networkpolicy.example.yaml`](networkpolicy.example.yaml) as a **baseline only**: namespace default-deny plus a gateway/operator DNS egress exception. The example intentionally provides **no general Internet egress** and does not attempt to guess your CNI labels, public provider IPs or Gateway Controller Pod selectors.

Provide *separate per-component rules* with constrained ingress and egress for exactly the configured services: gateway ingress from Gateway API or SMTP clients; gateway egress to mail providers, auth broker/AS, DB, PDP and DNS; operator egress to Kubernetes API, management endpoints/registries and DNS. Account for dual-stack IPv4/IPv6, egress DNS/FQDN limitations of native NetworkPolicy, and real network policy enforcement by the selected CNI. Do not disable policies to fix DNS or bridge connectivity.

Enforce `pod-security.kubernetes.io/enforce: restricted` on the namespace, together with audit/warn labels where applicable. This **namespace** and any cluster-wide admission setup are out of scope of an application chart's ServiceAccount. Native Restricted PSS does not enforce read-only root filesystems, secret-scoping or signed images, so an additional admission policy is required.

## Release gates

- `helm template` and schema-validate all profiles on the pinned chart version, Kubernetes manifests and relevant versioned CRDs.
- Test Pod Security restricted compatibility and explicit `readOnlyRootFilesystem: true`, `capabilities.drop: [ALL]`, **no added caps**, non-root, `RuntimeDefault`, `allowPrivilegeEscalation: false` for all regular, init, ephemeral and operator-created provider Pods.
- Audit `serviceAccountName`, token automount and projected tokens: operator only by default; no long-lived SA token Secrets.
- Verify `kubectl auth can-i` for forbidden actions under each SA, including all Secrets, RBAC mutation, token creation, Pod exec, node and namespace access. Confirm Role namespace and no wildcard authorization.
- Test operator-created Deployment/StatefulSet admission independently, image signatures and pinned digests, invalid Secrets/Pod templates, NetworkPolicy/IPv6 and no unapproved internet egress. Test that a CorviGateway never adopts a Helm-owned resource or allows unsafe security overrides.
- Check rootless startup, ephemeral scratch, SQLite/PVC permissions, cert-manager CSI, graceful shutdown and no accidental sensitive exposure through logs/metrics/Helm history.
- Re-run on all chart/CRD/Kubernetes version upgrades, fail closed on incompatible deployment constraints.

This guide describes intent and reproducible test inputs. It does **not** assert a released, tested Helm chart or a deployed Corvi Kubernetes workload.
