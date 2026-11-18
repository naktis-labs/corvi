# The credential roles

ADR-0014 section 6 makes the validating admission webhook and the Secret
publisher **separate trust roles**. This directory holds the role
boundary; the decision logic behind both roles is
[`crates/mail-credential`](../../crates/mail-credential/src/lib.rs).

## What each role may do

| | Validator | Publisher |
| --- | --- | --- |
| Read parents and their status | `get` | `get`, `list`, `watch` |
| Read the credential | no | `get`, `list`, `watch` |
| Write the credential status | no | `mailcredentials/status` only |
| Write Secrets | **no, in any verb** | `get`, `create`, `update`, `patch`, `delete` |
| Issue a credential | no | no; the issuer hands over material |
| Admit a request | yes | no |

[`credential-roles.yaml`](credential-roles.yaml) is the design fixture for
both roles. It is not applied by any release step, and neither role may
carry a blanket `list`/`watch` on Secrets: the publisher works on the
generated objects only, and Kubernetes cannot restrict `create` by
`resourceNames`, so the publisher verifies the owner UID of every Secret it
touches and fails closed with `SecretNameConflict` rather than adopt or
overwrite a Secret it does not own.

## What is not here

The admission **registration** is a privileged bootstrap/GitOps action:

- the `ValidatingWebhookConfiguration`, with `sideEffects: None`,
  `failurePolicy: Fail`, `matchPolicy: Equivalent` and a constrained
  timeout, is in
  [`../examples/mailcredential-validating-webhook.example.yaml`](../examples/mailcredential-validating-webhook.example.yaml);
- the HTTPS Service, the separately managed serving certificate and the
  injected CA bundle are provisioned by the trusted release, never by the
  Corvi operator Role;
- the webhook Pod is rootless, with a read-only root filesystem, all
  capabilities dropped and a projected API token for its `get` rights only.

The webhook **server**, the issuer and the publisher's controller loop are
not implemented in this task. The crate implements the decisions those
components make; the components themselves are named in
[ADR-0014](../../docs/adr/0014-generated-app-credentials-and-connection-secrets.md).

## Normal Pods

The gateway, the OAuth runtime, the plugin and the bridge Pods keep no
Kubernetes API token at all. They receive their connection material from
the generated Secret, never from the API server.
