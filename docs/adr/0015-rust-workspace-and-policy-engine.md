# ADR-0015: Rust workspace layout and the policy engine boundary

- **Status:** Accepted for the initial implementation; the crate layout will evolve as later phases land
- **Date:** 2026-11-16
- **Scope:** Repository structure, crate boundaries and the dependency rule that keeps the data plane independent of the control plane
- **Related:** [ADR-0001](0001-corvi-system-architecture.md), [ADR-0003](0003-mail-filtering-and-disclosure-policies.md), [ADR-0004](0004-pluggable-grpc-policy-engines.md), [ADR-0010](0010-storage-and-durability.md)
- **Implementation:** `crates/mail-core`, `crates/mail-policy`, [ADR-0003 section 10 test suite](../../crates/mail-policy/tests/disclosure.rs)

## Context

The design phase produced 14 ADRs, 11 JSON Schemas and a set of deployment examples, but no code. ADR-0001 section 12 sequences the work: foundations first (provider-neutral config model, policy engine, built-in IMAP/SMTP transport, single-process REST/MCP/SMTP listeners), then identity and safety, then native JMAP, then the control plane and protobuf, then the Migadu plugin, then the Kubernetes operator.

The first implementation step is the one ADR-0001 section 13 lists as a CI invariant: *"Dependency checks prohibit data-plane imports of Kubernetes, operator or provider-management modules."* A crate layout is the cheapest way to make that invariant structural rather than aspirational, because a data-plane crate that cannot see the operator's types cannot import them.

ADR-0003 additionally requires the filter engine to be free of I/O: the data plane evaluates policy locally from its active configuration snapshot while the control plane and provider plugins are offline.

## Decision

### Workspace layout

Corvi is a Cargo workspace. Crate names are short and role-specific, and the role is visible in the name:

```text
crates/
  mail-core/      Provider-neutral types: identities, actions, normalized messages
  mail-policy/    The disclosure filter engine (ADR-0003)
  mail-imap/      IMAP upstream client
  mail-smtp/      SMTP upstream client and submission listener
  mail-jmap/      Native JMAP client (ADR-0007)
  mail-api/       REST and MCP public surface (ADR-0005)
  mail-admin/     Provider administration interface
  mail-operator/  Kubernetes reconciler
  provider-migadu/ Migadu management adapter
```

`mail-core` and `mail-policy` are implemented now. The remaining crates follow the phase order in ADR-0001 section 12.

**`corvi-operator` is the reconciler binary of phase 6.** When the Kubernetes phase landed, the decision logic stayed in `mail-operator` (pure, dependency-light, cluster-free) and the API-server layer moved into a new control-plane crate `corvi-operator`, which depends on `kube`, `tokio` and `mail-operator` and is the only crate allowed a Kubernetes client. This is the layout evolution the ADR's status anticipated: the data plane still cannot see either crate.

### Crate rules

**`mail-core` holds provider-neutral types only.** No transport, no network, no Kubernetes. It defines the normalized message model that every upstream adapter projects into, and it is where the distinction between message-authored headers and trusted delivery metadata is encoded.

That distinction is carried in the type system rather than in documentation. `NormalizedMessage` has a `provenance` field holding the provider-recorded original envelope recipient, and no field for `To`/`Delivered-To` headers is treated as trusted. A rule that wants trusted routing provenance has exactly one place to look, and the values there came from the provider rather than from the sender.

**`mail-policy` depends only on `mail-core` and free of I/O.** It has no Kubernetes client, no provider plugin client, no HTTP client and no database. This is what makes ADR-0003 section 7's "the provider and operator can be entirely unavailable while the data plane continues evaluating its current policy snapshot" a structural property rather than a runtime hope: the engine has no way to call out.

**Data-plane crates never depend on the operator or on provider-management crates.** The dependency direction is one-way: `mail-operator` and `provider-migadu` may depend on `mail-core`; `mail-core` and `mail-policy` may not depend on them. ADR-0001 section 13 makes this a CI check.

**`mail-operator` may depend on the data plane's types, but the data plane never depends on the operator.** The operator publishes configuration; it does not sit in the request path.

### The filter engine's typed decisions

ADR-0003 section 2.3 requires a typed decision rather than a boolean. The engine produces a `Decision` carrying a `Visibility` (`hide`, `show`, `redact`), accumulated `Redaction`s, a merged `Rendering` restriction set and the identifiers of the rules that matched.

Two composition rules govern it:

- **`hide` wins.** Once any applicable rule hides a message, no later rule can make it visible. There is no `stopProcessing` and no `allowOverrideDeny`.
- **Restrictions only narrow.** Two applicable filters merge by taking the more restrictive value of each rendering dimension. A permissive filter cannot cancel a denial from another filter.

### Indeterminate is not clean

ADR-0003 section 2.3 requires that an indeterminate result is distinct from a clean non-match, and section 8 requires that exceeded limits route to indeterminate rather than to allow.

An indeterminate outcome arises when a rule's condition cannot be evaluated: an invalid regular expression, a message too large to scan, or content that cannot be parsed. The policy's `on_indeterminate` decides, and the secure default is `hide`.

The rule's **own effect is not applied** in that case. The condition that would justify the effect is unknown, so applying it would be acting on an unevaluated rule. `on_indeterminate: hide` withdraws the message; `on_indeterminate: show` treats the rule as not having matched. Neither path applies the rule's effect.

### Rule vocabulary

The initial matcher set is the auditable declarative subset ADR-0003 section 2.2 calls for: text predicates over named fields, classification classes, flags, folders, attachment counts, and bounded boolean composition. There is no arbitrary policy script, no remote lookup, no agent-generated decision and no user-supplied code in the mail request path.

Regular expressions are compiled with a bounded pattern length and a bounded program size. The `regex` crate guarantees linear-time matching, so a hostile message cannot make a pattern backtrack exponentially.

### Classification

Classification is heuristic and the implementation says so. The classifiers look for authentication **context** alongside a code, rather than treating any short digit run as a one-time code, because ADR-0003 section 4 names invoice numbers as the false-positive case that must not be classified as a credential.

A message that cannot be scanned at all is **indeterminate**, not clean. `scan_text` returns `None` for an empty or oversized message, and the predicate layer propagates that as an indeterminate outcome rather than as a non-match.

### Output projection

The engine produces a `RedactedMessage` projection, which is the only representation a scoped caller may receive. The original message is never mutated: filtering preserves the underlying mailbox bytes, and a policy change must not destroy the original (ADR-0003 section 8).

Rendering restrictions apply to every channel, not just the body. Denied attachments are removed from the projection entirely; attachment metadata access removes filenames, which are the part most likely to leak a title; remote content is stripped from HTML; and link destinations are reduced to a scheme and host, because a login link carries its token in the query string rather than in the anchor text.

### HTML sanitization

The current sanitizer is a string-level pass that removes script and embedded-object elements, drops event-handler attributes and strips remote references. It is **not** a parser-based sanitizer, and it is marked as such in the source.

A production implementation should parse HTML properly. The boundary is deliberate and temporary: a dependency-free implementation was preferred for the foundations phase so that the engine could be exercised without pulling a parser into the data plane, and the swap point is documented rather than implicit.

## Consequences

The layout costs one crate per role and some duplication of type definitions across the provider boundary. It buys a data plane that cannot accidentally acquire a Kubernetes dependency, and a filter engine that is testable without standing up any infrastructure.

The engine's rules are more verbose than an expression language would be. That is the intended trade: ADR-0003 rules out unconstrained user-supplied code in the mail request path, and a declarative vocabulary is auditable in a way a small expression language is not.

The string-level sanitizer is the weakest part of this implementation. It is bounded and it fails closed on the fields it cannot safely transform, but a parser-based sanitizer should replace it before the engine is exposed to untrusted mail at scale.

## Acceptance criteria

1. `cargo build --workspace` succeeds with `-D warnings`.
2. `cargo clippy --workspace --all-targets` is clean.
3. `cargo test --workspace` passes, including the ADR-0003 section 10 integration suite in `crates/mail-policy/tests/disclosure.rs`.
4. `mail-policy` depends on nothing outside `mail-core`, `regex` and `serde`. This is enforced by `scripts/check_crate_boundaries.py`, which also rejects Kubernetes, operator, provider-management, database and HTTP-client dependencies anywhere in the data plane.
5. `mail-core` exposes no transport, network or Kubernetes type.
6. Internal documentation links resolve (`scripts/check_doc_links.py`).

## The licence is deliberately unset

The workspace sets `publish = false` and names no licence. ADR-0001 section 14 lists the licence as an open question, and it is one that has real consequences: Corvi depends on nothing, so a permissive licence costs nothing, but picking one is m00n's decision and not a detail to be settled by an implementation pass.

There is deliberately **no `LICENSE` file** in the repository, and the crates carry `publish = false`. Both should stay until the licence is chosen.

## CI

The repository has a GitHub Actions workflow that runs formatting, clippy under `-D warnings`, the test suite, a locked build, the crate boundary check and the documentation link check.

The workflow file is **not yet committed**, because the `hati-moonchaser` GitHub App does not hold the `workflows` permission, and GitHub refuses to let a GitHub App create or update `.github/workflows/*`. This is a deliberate grant boundary from the App setup, not an oversight: m00n grants `workflows` only when he wants Hati pushing Actions changes.

Until that permission is granted, the same checks run locally with:

```console
$ cargo fmt --all -- --check
$ cargo clippy --workspace --all-targets -- -D warnings
$ cargo test --workspace --all-targets
$ python3 scripts/check_crate_boundaries.py
$ python3 scripts/check_doc_links.py
```

## References

- [ADR-0001: Corvi system architecture](0001-corvi-system-architecture.md)
- [ADR-0003: Mail filtering and disclosure policies](0003-mail-filtering-and-disclosure-policies.md)
- [ADR-0004: Pluggable policy evaluation with WASM and gRPC](0004-pluggable-grpc-policy-engines.md)

---

This ADR records an implemented layout and set of semantics. The remaining crates in the layout are planned and do not yet exist.
