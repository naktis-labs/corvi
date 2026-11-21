# The Corvi policy engine contract

`v1/policy_engine.proto` is the engine-neutral contract for an optional
external policy decision point (ADR-0004 section 2).

It is a **contract document**. No transport is implemented in this repository
state: the gRPC client and server need a protobuf toolchain and a TLS stack
that are not part of this build, and ADR-0004 makes an external PDP an
explicitly opted-in data-plane dependency rather than a mandatory one.

The typed Rust counterpart of the same contract - the decision vocabulary, the
obligation validation and the request type that carries no secret and no
message body - lives in `crates/mail-policy-engine/src/contract.rs`, and the
sandbox seam it is evaluated through lives in
`crates/mail-policy-engine/src/engine.rs`.

## Invariants the contract encodes

* The request has no field for a provider administrative secret and no field
  for a message body. Only allowlisted attributes and classifications travel.
* The response carries an effect and typed obligations, never a rewritten
  message body.
* An unknown effect or an unknown obligation kind is an error. A valid
  `ALLOW` with malformed obligations is an error, not permission to ignore
  them.
* An external engine may only narrow a locally computed decision.
