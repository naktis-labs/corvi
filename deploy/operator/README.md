# Corvi operator deployment fixtures

These are the shapes the operator's renderer **would** submit, checked in so
they can be reviewed and diffed. They are not applied by anything here: there
is no cluster in this repository, no Kubernetes client in the crate and no
admission webhook or network policy controller is implemented.

| File | What it is |
| --- | --- |
| `rendered/corvi-gateway-primary.yaml` | The rendered Deployment of `api/operator/fixtures/gateway-primary.yaml`. |
| `rendered/corvi-gateway-sqlite.yaml` | The rendered single-writer StatefulSet of `api/operator/fixtures/gateway-sqlite.yaml`. |
| `policy/corvi-gateway-default-deny.networkpolicy.yaml` | The default-deny NetworkPolicy, installed **independently** of the operator. |
| `policy/corvi-operator.rbac.yaml` | The operator's own identity and Role, namespaced and deliberately narrower than the gateway's. |

`crates/mail-operator/tests/fixtures.rs` re-renders the API fixtures and
compares them with `rendered/`, so a renderer change that changes the shipped
shape fails the test instead of drifting silently.

## What the rendered workload proves

Every container and init container is rootless (UID/GID 65532,
`runAsNonRoot: true`), drops all capabilities and adds none, runs with an
effective `RuntimeDefault` seccomp profile, mounts a read-only root
filesystem and cannot escalate privileges. The pod mounts no Kubernetes API
token, publishes no service links and shares no host namespace. The gateway
uses its own service account, `corvi-gateway`, which carries no RBAC role; the
operator uses `corvi-operator`, which is the only component with a token.

SQLite is a single writer: the renderer refuses a replica count above one and
reconciles SQLite into a StatefulSet with one replica over a pre-created claim
that it references but never owns, creates or deletes.

## What is deliberately outside this crate

The NetworkPolicy and the admission policy are installed by an independent
control (`app.kubernetes.io/managed-by: gitops`). The operator expects them,
reports their absence, and is not allowed to create an unrestricted
substitute: a policy derived from the operator's own configuration would be
written by the component whose output it constrains. Enforcement depends on
the cluster's CNI and is **not verified here**; the `IPv4`/`IPv6` DNS egress
entries in the policy fixture are documentation addresses that a real cluster
must replace with its own verified resolver addresses.
