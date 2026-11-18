# Upstream OAuth provider descriptors

This directory holds the **provider descriptors** the `mail-upstream-oauth`
crate reads. The schema is [`../upstream-oauth.schema.json`](../upstream-oauth.schema.json);
the descriptor kind is `UpstreamOAuthProvider` and the API version is
`corvi.naktis.eu/v1alpha1`.

```
examples/gmail.json          a public client, IMAP and SMTP over XOAUTH2
examples/microsoft365.json   a public client, delegated IMAP and SMTP scopes
examples/fastmail.json       a confidential client, JMAP, no device grant
```

## What a descriptor is

A descriptor is **deployment configuration, not provider fact**. It states
what a deployment registered with a provider and which endpoints it trusts:

- the client identifier and whether the client is public or confidential,
- the exact callback URIs that were registered,
- the endpoints of the provider's authorization server,
- the provider's own scope strings, separated into read, send, offline and
  management,
- the transport mechanisms an upstream token may be presented with,
- the refresh behaviour and the account verification strategy.

The crate refuses a descriptor it cannot use, and says which constraint is
unmet: an unknown provider, a provider with no configured callback, a
confidential client without a configured client secret, a missing issuer, a
non-HTTPS endpoint. The refusal is an `unsupportedRegistration` status, not
a generic error.

## The examples are placeholders

The endpoints, client identifiers and scope strings in `examples/` are
**placeholders**. They are shaped like the values a deployment would write,
and they are the fixtures the crate's own tests run against, but this
repository does not verify them against a live provider and does not claim
that they are current. A deployment replaces them with the values from the
provider's own documentation before it enables the provider.

Two of them are deliberate:

- `fastmail.json` lists **no device flow**. A provider that does not
  advertise a device grant must never have one offered, so the descriptor
  does not list it and the crate does not advertise it. Its client is
  confidential, because a provider that issues a client secret needs one
  configured.
- `gmail.json` and `microsoft365.json` use a **loopback callback**
  (`http://127.0.0.1:8400/...`). Only the loopback interface may use HTTP;
  every other callback has to be HTTPS. The port in the example is the one
  a deployment registers with its provider.

## Secrets

A descriptor never holds a secret. A confidential client names a
`clientSecretRef`, which is a reference to where the secret is kept, not the
secret itself.
