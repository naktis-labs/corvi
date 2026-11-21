# Cluster validation of the operator resources

This document records what a **real Kubernetes API server** was asked to
accept, what it accepted, what it refused, and — just as important — what no
cluster checked at all.

The resources are derived from the checked-in JSON Schemas by
[scripts/generate_crds.py](../scripts/generate_crds.py); the manifests live in
[api/operator/crds/](../api/operator/crds/) and the fixtures live in
[api/operator/fixtures/](../api/operator/fixtures/).

## The cluster

The validation ran against a [kwok](https://github.com/kubernetes-sigs/kwok)
*binary* runtime cluster. It runs a real control plane and no workload
runtime at all:

| Component | Version |
| --- | --- |
| `kwokctl` / `kwok` | v0.8.0 |
| `kube-apiserver` | v1.36.1 |
| `etcd` | bundled with the kwok control plane |
| `kubectl` (client) | v1.37.2 |

```bash
# create: a real API server, a real etcd, a real admission chain
kwokctl create cluster --name corvi --runtime binary

# the kubeconfig is written to ~/.kube/config
kubectl cluster-info
kubectl get ns

# destroy: remove the control plane and its state
kwokctl delete cluster --name corvi
```

The `binary` runtime needs **no container runtime** (no containerd, no CRI-O,
no Docker) and it needs **no nodes**: `kubectl get nodes` returns *No
resources found*. kwok can simulate nodes, but this cluster has none, so no
Pod is ever created, scheduled or run. That is exactly what the schema
validation needs and exactly what it cannot tell us about workloads.

## What was validated

| Manifest | Command | Result |
| --- | --- | --- |
| `api/operator/crds/corvi-corvigateway.yaml` | `kubectl apply -f api/operator/crds/` | installed, no warning |
| `api/operator/crds/corvi-mailprovider.yaml` | `kubectl apply -f api/operator/crds/` | installed, no warning |
| `api/operator/crds/corvi-mailbox.yaml` | `kubectl apply -f api/operator/crds/` | installed, no warning |
| `api/operator/crds/corvi-mailidentity.yaml` | `kubectl apply -f api/operator/crds/` | installed, no warning |
| every fixture in `api/operator/fixtures/` | `kubectl apply --dry-run=server -f <file>` | see the table below |

The API server is the oracle for the structural schema: it rejected the
drafts that used `const`, `if`/`then`/`else`, `propertyNames`,
`dependentRequired` and `unevaluatedProperties` (strict decoding of the CRD
object reports them as unknown fields), it rejected `additionalProperties`
next to `properties`, and it accepted the generated manifests as they stand.

`kubectl explain corvigateway.spec.state` renders the installed schema, which
is a second, independent check that the schema is the structural one the API
server stores rather than the JSON Schema the file was written from.

### Fixtures: the API server against the operator's semantics

The API server can only decide what the CRD schema expresses. Everything else
is the operator's reconciler, which does not exist yet. The three valid
fixtures are **accepted**; the invalid ones split in two.

| Fixture | API server | Why |
| --- | --- | --- |
| `gateway-primary.yaml` | accepted | schema-level valid |
| `gateway-sqlite.yaml` | accepted | schema-level valid |
| `provider-chain.yaml` | accepted | schema-level valid |
| `invalid-cross-namespace-ref.yaml` | **rejected** | `spec.gatewayRef.namespace` is not a field of the local-reference schema (`strict decoding error: unknown field`) |
| `invalid-dangling-gateway-ref.yaml` | accepted | schema-level valid, **rejected by the operator's semantic validation** (the named gateway does not exist) |
| `invalid-ephemeral-embedded-issuer.yaml` | **rejected** | the CEL rule from `spec.allOf[1]`: an embedded issuer needs durable state |
| `invalid-management-only-mailbox.yaml` | accepted | schema-level valid, **rejected by the operator's semantic validation** (a management-only provider may not own a mailbox) |
| `invalid-missing-mailbox-ref.yaml` | **rejected** | `spec.mailboxRef: Required value` |
| `invalid-missing-provider-ref.yaml` | **rejected** | `spec.providerRef: Required value` |
| `invalid-owner-reference-injection.yaml` | accepted | schema-level valid, **rejected by the operator's semantic validation** (the operator sets its own owner references) |
| `invalid-podspec-injection.yaml` | **rejected** | `spec.template` is not a field of the gateway spec, and `spec.listeners`, `spec.authorization` and `spec.state` are required |
| `invalid-sqlite-two-replicas.yaml` | **rejected** | the CEL rule from `spec.allOf[0]`: SQLite has one writer, so `replicas` must be 1 |
| `invalid-suspended-provider.yaml` | accepted | schema-level valid, **rejected by the operator's semantic validation** (a suspended provider invalidates its dependents) |

Two of the schema-level rejections depend on the API server's **strict field
validation**, which is kubectl's default (`fieldValidation=Strict`):

* `invalid-cross-namespace-ref.yaml` is rejected because the API server
  refuses the unknown field. With `--validate=false` the same object is
  **accepted** and the unknown field is silently pruned. The cross-namespace
  *meaning* of the fixture is still the operator's semantic check; the schema
  only says that a local reference has no `namespace` field.
* `invalid-podspec-injection.yaml` is rejected either way: with
  `--validate=false` the unknown `spec.template` is pruned, but the missing
  required fields are still refused.

`scripts/validate_cluster.sh` runs exactly this classification and fails if
a fixture reaches a different outcome than the one recorded here.

## What was not validated

Nothing outside the table above was sent to the API server. In particular:

* `api/credential/mail-credential.crd.yaml` — a separate, hand-written
  manifest. It is not generated by `scripts/generate_crds.py`, and this work
  neither installed nor validated it; see that file's own header for what it
  claims.
* `deploy/examples/*.yaml` — design examples whose own headers say not to
  apply them.
* `deploy/operator/**`, `deploy/helm/**`, `deploy/credential/**` — workload,
  Helm and RBAC shapes. They are not custom resources and were not submitted.
* Every Rust crate. No crate was modified and no crate was exercised against
  the cluster.

## Limitations

The cluster is a control plane with no workload runtime. The following are
**not** validated by anything in this repository:

* **No Pod runs.** There are no nodes, no scheduler placement and no kubelet.
* **No scheduler execution.** The scheduler binary is running, but with no
  nodes it never schedules anything, and no Pod was ever created.
* **No CNI and no network policy enforcement.** No pod network exists.
* **No controller of ours is deployed.** The Corvi operator, its reconciler,
  its admission webhook and its network-policy controller do not exist in this
  repository. The `CorviGateway` status stays empty; the scale subresource is
  declared but nothing writes `.status.replicas`.
* **No RBAC for the operator.** The API server runs with `Node,RBAC`
  authorization, but this work did not install or exercise a Corvi Role or
  RoleBinding; the checks above ran as the cluster administrator.
* **No admission webhook.** The semantic rejections in the table above are
  what `crates/mail-operator` decides in its own tests, not what a live
  webhook decided here.
* **No owner-reference guard at the API level.** The CRD schema does not
  constrain `metadata`; a user-supplied `ownerReference` is accepted by the
  API server and refused by the operator. A CEL rule cannot close this gap:
  the API server does not expose `metadata` to a root validation rule.
* **No storage, no OAuth and no transport.** A real gateway was never
  reconciled, so nothing proved that a SQLite claim, an embedded issuer or an
  upstream OAuth grant works at runtime.
* **One API server version.** Everything above was observed on Kubernetes
  v1.36.1 only.

## Reproducing this

```bash
# 1. a cluster (no container runtime, no nodes)
kwokctl create cluster --name corvi --runtime binary

# 2. generate the manifests from the checked-in JSON Schemas
python3 scripts/generate_crds.py

# 3. install them and check the fixtures against the API server
CORVI_CLUSTER_VALIDATION=1 bash scripts/validate_cluster.sh

# 4. destroy the cluster
kwokctl delete cluster --name corvi
```

**Caution:** opt-in installs or updates cluster-scoped CRDs and creates the
`corvi-system` namespace if absent on the current Kubernetes context. Verify
`kubectl config current-context` points to a disposable test cluster first.
The release gates skip cluster validation by default; set
`CORVI_CLUSTER_VALIDATION=1` when invoking the gates to opt in to these writes.

The generation step needs no cluster and is checked by the release gates
(`python3 scripts/release_gates.py --fast`). The cluster step is separate and
reports **skipped**, never passed, without opt-in or when no API server is reachable.
