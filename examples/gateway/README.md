# Corvi gateway example

A runnable configuration for the standalone gateway: one credential
snapshot, one disclosure policy document and one fixture mailbox. Nothing
here talks to a provider, so the example runs with no external service.

## Files

| File | What it is |
| --- | --- |
| [`snapshot.yaml`](snapshot.yaml) | Identities, credentials, grants and listeners |
| [`policies.yaml`](policies.yaml) | The disclosure policies and the identity bindings |
| [`mailbox.json`](mailbox.json) | A fixture mailbox the gateway serves |

## Run it

Create the secret file the snapshot names. It must be a regular file that
only its owner may read; a file that is readable by others is refused, and
an unreadable secret denies access rather than granting it.

```console
$ install -m 0600 /dev/null /tmp/corvi-demo-token
$ printf '%s\n' 'replace-me' > /tmp/corvi-demo-token
```

Check the configuration without listening:

```console
$ cargo run --bin corvi-gateway -- \
    --config examples/gateway/snapshot.yaml \
    --policies examples/gateway/policies.yaml \
    --upstream examples/gateway/mailbox.json \
    --check
configuration is valid: listen 127.0.0.1:8080, 2 identities, 1 policies
```

Then serve it:

```console
$ cargo run --bin corvi-gateway -- \
    --config examples/gateway/snapshot.yaml \
    --policies examples/gateway/policies.yaml \
    --upstream examples/gateway/mailbox.json
corvi-gateway accepts SMTP AUTH submissions on 127.0.0.1:2525
corvi-gateway is listening on 127.0.0.1:8080
```

Call it:

```console
$ curl -s -H 'Authorization: Bearer replace-me' \
    http://127.0.0.1:8080/v1/identities
```

The scripted version of all of this — including the MCP approval round trip
— is [`scripts/smoke_gateway.py`](../../scripts/smoke_gateway.py):

```console
$ cargo build --bin corvi-gateway
$ python3 scripts/smoke_gateway.py
```

## What the example demonstrates

- **Two identities, one credential.** The `agent` credential may read
  `personal` and may send as `work`. It may not send as `personal` and may
  not read `work`: permissions never union across identities.
- **A hidden message.** `m-2` carries a one-time code, the policy hides it,
  and the gateway answers `NOT_FOUND` for it exactly as it does for a
  message that does not exist.
- **A policy revision.** The `generation` in `policies.yaml` is part of what
  a cursor and an approval are bound to, so changing the rules invalidates
  the ones issued under the old revision.
- **A loopback-only listener.** The gateway does not terminate TLS, so both
  listeners must be loopback addresses and the snapshot must say
  `allow_loopback_plaintext: true`. See ADR-0006, which is not implemented.

## What the example is not

The fixture mailbox is a test backend. It is not a mail store, it never
talks to a network, and a deployment that points a gateway at it serves
fixture mail only. Live IMAP, SMTP and JMAP upstream transports are not
implemented in this slice.
