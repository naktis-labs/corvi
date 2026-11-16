# Hardened Helm deployment design (not released)

These files are **bjw-s-labs app-template v5.3.0 values examples** for a future Corvi Kubernetes packaging effort. They are not a complete chart and cannot be deployed as-is: images and digest placeholders, CRDs, generated workloads, health probes, application configuration and installation-specific network allowlists remain to be implemented.

- [ADR-0011: Hardened Helm design](../../docs/adr/0011-hardened-helm-deployment.md) is the normative architectural/security contract.
- [Gateway app-template values](app-template-gateway.values.yaml): rootless, read-only, no Kubernetes API token or RBAC, bounded resources and tmpfs scratch.
- [Operator app-template values](app-template-operator.values.yaml): same rootless hardening, **only** this controller opts into Kubernetes API token mounting, dedicated service account and a **namespaced** Role/RoleBinding. The final list of CRD resource plurals, namespaced resources and allowed verbs must be generated from actual implemented reconciliation code, not assumed from the example.

The design pins **app-template v5.3.0** (see [official chart reference](https://bjw-s-labs.github.io/helm-charts/docs/app-template/)) and specifies separate releases for the gateway, operator and optional OAuth issuer. Production must pin real **container image digests**, verify OCI signatures and pass a rendered-manifest policy check before installing.

## Network isolation is mandatory

Before enabling a release, provision Kubernetes **Pod Security Admission Restricted** labels on its namespace and enforce both default-deny **ingress and egress** policies (with the cluster's actual CNI and dual-stack addressing). Add separately reviewed minimal exceptions for:

- Inbound Gateway API/ingress-controller peers to gateway HTTP/MCP, and optional approved SMTP submission clients; no public MX listener.
- Inbound OAuth users through an HTTPS Gateway/ingress, plus tightly constrained callback/management access.
- Cluster DNS (UDP/TCP 53 to real kube-dns/CoreDNS endpoints), approved upstream JMAP/IMAP/SMTP/provider HTTPS endpoints, optional PostgreSQL, approved mTLS plugin/bridge interfaces, and observability endpoints.
- Operator Kubernetes API, approved provider-admin API and OCI registry egress. Ordinary gateway/worker/plugin Pods **must not** gain Kubernetes API egress just because the operator has it.

Standard Kubernetes NetworkPolicy has no provider-hostname selector. Configure approved IP ranges, explicit egress proxy, or CNI-specific FQDN policy where appropriate; never use `0.0.0.0/0` or `::/0` as a disguised allowlist. A default-deny policy without the explicit allowlist will block the service (securely, but not usefully).

## Packaging and rendering gates

1. Install CRDs **separately** from ordinary workload releases; avoid Helm hooks that run privileged or delete persistent resources. Prefer operator-only and gateway-only deployment profiles.
2. Use the app-template `controllers`, `serviceAccount`, `rbac`, `networkpolicies`, `persistence`, `service` and optionally `route` keys instead of hand-writing normal workloads. Apply every security context to both init and regular containers and generated provider/bridge workloads.
3. Verify the pinned chart against its upstream values schema; run `helm lint` and `helm template` for all profiles, `kubeconform`, namespace Restricted PSS checks, and server-side dry-run against supported Kubernetes releases.
4. Fail CI for `runAsUser: 0`, `capabilities.add`, privilege escalation, writable root, missing `RuntimeDefault`, writable hostPath, host networking, unbounded or unauthorized writable mounts, unapproved Services, image tags without digest pinning, or unexpected automatic Kubernetes API token mounts. Fail on wildcard ClusterRoles/RoleBindings, secret enumeration and access to other service accounts.
5. Test **operator-created** plugin/bridge Pod manifests as well as chart-rendered manifests. Kubernetes RBAC `deployments.create` is powerful; pair it with admission validation of Pod specs and approved ServiceAccount names.
6. Verify read-only-root startup, rootless PVC access, TLS/mTLS and secret injection, token issuance/revocation, startup/readiness/liveness behavior, IPv4+IPv6 NetworkPolicy enforcement and complete restore/rollback paths in an isolated test cluster.

**A released Helm chart and production-grade security attestation are implementation deliverables, not existing functionality.**
