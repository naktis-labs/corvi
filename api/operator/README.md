# Corvi operator API fixtures

The Corvi Kubernetes **reconciler exists** (`crates/corvi-operator`): it
watches `CorviGateway` resources, resolves them through the decision logic in
`crates/mail-operator`, applies the rendered workload with server-side apply
and writes the gateway's status. Against a real API server (kwok, v1.36.1) it
has been shown to create a hardened Deployment, a ClusterIP Service and status
conditions, and to refuse a Helm-owned workload without touching it.

The operator's **admission webhook and its network policy are still not
implemented**, and no controller runs anywhere yet: nothing in this
repository deploys the reconciler, and the cluster evidence is object-level
only (no nodes exist, so no pod ever ran).

What exists:

* `crates/mail-operator` — the decision logic: reference resolution
  (ADR-0013), ownership, suspension, reparenting and cascade-delete guards
  (ADR-0012/ADR-0013), the hardened workload profile (ADR-0011) and
  last-known-good snapshot retention.
* `crates/mail-operator/tests/fixtures.rs` — parses and validates the files in
  this directory.
* `deploy/operator/` — the workload shapes the renderer would submit, plus the
  independently installed policy fixture.
* `api/operator/crds/` — **structural CRD manifests with OpenAPI v3 and CEL
  invariants**, generated from the checked-in JSON Schemas by
  `scripts/generate_crds.py`. They are derived, never hand-written, and the
  release gate fails when the checked-in files drift from the generated
  output. The API server accepts all four of them; see
  [docs/cluster-validation.md](../../docs/cluster-validation.md) for what that
  did and did not prove.

What does **not** exist: a reconciler loop, an admission webhook server, a
network policy controller, any Kubernetes RBAC enforcement, and any workload
that the operator would submit. The CRDs alone decide the local syntax; the
cross-resource rules below remain the reconciler's job. ADR-0012 §4 item 1
(the structural CRD) is now satisfied for the schema, and the deployment
hardening gates remain future work. The enforcement boundary for a deployed
cluster is an independently installed admission policy and network policy —
not this crate.

## Fixtures

Valid CRD-shaped instances:

| File | What it shows |
| --- | --- |
| `gateway-primary.yaml` | A `CorviGateway` with ephemeral state, one replica. |
| `gateway-sqlite.yaml` | A single-writer SQLite `CorviGateway` (one replica, pre-created claim). |
| `provider-chain.yaml` | The ADR-0013 chain: gateway ← provider ← mailbox ← identity, including an unbound provider. |

Invalid instances, each of which the operator rejects:

| File | Rejected because |
| --- | --- |
| `invalid-dangling-gateway-ref.yaml` | `gatewayRef` names a gateway that does not exist. |
| `invalid-missing-provider-ref.yaml` | `Mailbox.spec.providerRef` is required. |
| `invalid-missing-mailbox-ref.yaml` | `MailIdentity.spec.mailboxRef` is required. |
| `invalid-cross-namespace-ref.yaml` | A reference may not leave its namespace. |
| `invalid-management-only-mailbox.yaml` | A provider that administers other providers and serves no mailbox of its own may not own a mailbox. |
| `invalid-suspended-provider.yaml` | A suspended provider invalidates its dependents. |
| `invalid-podspec-injection.yaml` | A PodSpec fragment in a `CorviGateway` is refused. |
| `invalid-owner-reference-injection.yaml` | User-supplied `ownerReferences` are refused. |
| `invalid-sqlite-two-replicas.yaml` | SQLite has one writer; more than one replica is refused. |
| `invalid-ephemeral-embedded-issuer.yaml` | An embedded OAuth issuer needs durable state. |

## One reinterpretation

The task brief describes a *management-only provider* as one that
"administers other providers and serves no mailbox itself" and forbids it from
owning mailboxes. ADR-0013 uses "management-only" for a different thing: a
provider with **no `gatewayRef`**, which still owns mailboxes that are simply
not served by any gateway.

Both are modelled. A provider with no `gatewayRef` is *unbound* (valid, owns
mailboxes, contributes no identities to any gateway). A provider with
`spec.role: managementOnly` is the brief's management-only provider: it may
own no mailbox and may not be bound to a gateway. The reference contract of
`api/mail-resource-ownership.schema.json` is otherwise unchanged.

## Live cluster validation

Cluster validation is skipped by default. Set `CORVI_CLUSTER_VALIDATION=1`
for `scripts/validate_cluster.sh` or the release gates only after checking
`kubectl config current-context`: it installs or updates cluster-scoped CRDs
and creates the `corvi-system` namespace if absent. Use a disposable test
cluster; see [cluster validation](../../docs/cluster-validation.md).
