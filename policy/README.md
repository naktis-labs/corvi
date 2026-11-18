# Corvi policy artifacts

This directory holds the versioned interfaces and the release layout of a
Corvi policy module.

| Path | What it is |
| --- | --- |
| `wit/corvi-policy.wit` | The `corvi:policy@0.1.0` WIT package: the ABI a policy module implements. |
| `../api/policy-engine/v1/policy_engine.proto` | The engine-neutral contract for an optional external policy decision point. |

## The two release variants

ADR-0004 section 4.4.1 requires every released policy to be published twice
from **one** compiled module, under format-suffixed tags of the same OCI
repository:

| Variant | Tag | Layout |
| --- | --- | --- |
| Native Wasm OCI | `v1.2.3-wasm` | OCI image manifest, `application/vnd.wasm.config.v0+json` config, one `application/wasm` layer. |
| Image-volume OCI | `v1.2.3-volume` | OCI image manifest, standard image config, one tar layer with `/policy.wasm` and `/policy.json`. |

Both variants carry identical module bytes and have distinct immutable manifest
digests, because they describe different artifacts. The builder that produces
the pair is `mail_policy_engine::oci::build::build_release_variants`, and the
tests in `crates/mail-policy-engine/tests/release_variants.rs` prove the
equality of the module bytes, the inequality of the manifest digests and the
absence of any shell or auxiliary executable in the volume variant.

Production configuration references the digests, never the tags:

```text
ghcr.io/naktis-labs/corvi-policy-privacy@sha256:<native-manifest-digest>
ghcr.io/naktis-labs/corvi-policy-privacy@sha256:<volume-manifest-digest>
```

## What is not implemented yet

No registry client, no WebAssembly runtime and no gRPC transport are part of
this repository state. The artifact validator works on bytes a caller already
fetched, and the policy host is a trait whose default implementation reports
that no runtime is available. See the crate documentation of
`mail-policy-engine` for the exact seams a later task plugs into.
