# The MailCredential contract

These files record the shape of the one credential custom resource and the
vocabulary of its refusals. They are design fixtures: nothing here installs
a CRD, registers a webhook or writes a Secret.

- [`mail-credential.crd.yaml`](mail-credential.crd.yaml) — the structural
  OpenAPI v3 shape of `MailCredential`, with `spec.type` defaulted to
  `smtp`. It decides local syntax only.
- [`admission-reasons.json`](admission-reasons.json) — the reason codes a
  refusal may carry, and which component raises each one.

The decision logic lives in
[`crates/mail-credential`](../../crates/mail-credential/src/lib.rs); the
design rationale is
[ADR-0014](../../docs/adr/0014-generated-app-credentials-and-connection-secrets.md)
and the flat-key output contract is
[`generated-connection-secret.schema.json`](../generated-connection-secret.schema.json).

## What the schema decides, and what it cannot

The CRD schema decides what one object says: the protocol vocabulary, the
single typed target, the action vocabulary, the Secret template metadata and
the `smtp` default. It cannot decide what the object means, because that
depends on other objects:

| Question | Decided by |
| --- | --- |
| Does a scoped credential have a bound gateway and a bound identity? | webhook, then the issuer again |
| Can this provider really isolate this identity or mailbox? | webhook, against fresh capability status |
| Is the capability status still fresh for the current generation? | webhook and revalidator |
| May this publisher write this Secret? | the publisher's own grant |
| Does the Secret still belong to this credential? | the publisher, at write time |

## The two seams

The crate has no Kubernetes client and no network. Two traits are where a
real deployment attaches:

- `admission::ParentStatusReader` — reads the current status of the
  referenced `MailIdentity`, `Mailbox`, `MailProvider` and `CorviGateway`.
  A real implementation uses a ServiceAccount with `get` on those four
  resources and nothing else.
- `publisher::SecretStore` — reads and writes the generated Secret. A real
  implementation uses the publisher's own ServiceAccount, whose Secret
  permissions are bounded to the generated objects.

The webhook server, the admission registration, the CA bundle and the
publisher's controller loop are **not** implemented here. They are named in
[ADR-0014 section 6](../../docs/adr/0014-generated-app-credentials-and-connection-secrets.md)
and in
[`deploy/credential`](../../deploy/credential/README.md).
