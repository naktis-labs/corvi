# Corvi operations

- **Status:** Implemented scope, stated as of the current worktree
- **Date:** 2026-11-18
- **Scope:** Running the gateway, running the gates, and the operational limits an operator must know about
- **Related:** [Compatibility](compatibility.md), [Capabilities](capabilities.md), [ADR-0010](adr/0010-storage-and-durability.md), [ADR-0011](adr/0011-hardened-helm-deployment.md)

This document covers the path that works today: one standalone gateway process, one local configuration, local durable state, and the gates that prove the tree is sound. Everything that would require a cluster, a provider account or a network is listed under **Not available in this deployment**.

## Running the standalone gateway

The gateway serves the REST API, the MCP endpoint and, optionally, an SMTP AUTH submission listener from one process. It terminates no TLS: the listener must be a loopback address and `allow_loopback_plaintext` must be true, so the gateway belongs behind a TLS-terminating proxy that is outside this repository.

```console
$ cargo run --bin corvi-gateway -- \
    --config examples/gateway/snapshot.yaml \
    --policies examples/gateway/policies.yaml \
    --upstream examples/gateway/mailbox.json \
    --check
configuration is valid: listen 127.0.0.1:8080, 2 identities, 1 policies
```

Drop `--check` to serve. The example configuration is in [`examples/gateway`](../examples/gateway); its README explains the secret file the snapshot names and the ownership rules that file must satisfy.

Two rules about secrets are worth repeating here because they fail closed and look like a misconfiguration:

- A secret file that is readable by others, or that the process does not own, is **refused**. Create it with `install -m 0600`.
- An unreadable secret **denies access** rather than granting it. A gateway that cannot read its secrets serves nothing to anyone.

## The gates

```console
$ python3 scripts/release_gates.py            # every gate
$ python3 scripts/release_gates.py --fast     # skip the cargo build gates
```

The runner prints one line per gate and a summary that names the gates that **failed** or were **skipped**, so a skipped gate cannot be mistaken for a passed one.

| Gate | What it proves |
| --- | --- |
| workspace format | `cargo fmt --all -- --check` |
| workspace clippy | `cargo clippy --workspace --all-targets -- -D warnings` |
| workspace tests | `cargo test --workspace --all-targets` |
| crate dependency boundaries | The data plane cannot reach the operator, the provider-management crates or a database, except the one documented `mail-storage` waiver |
| source contract schemas | The checked-in JSON Schemas validate. This is a **design** check: it says nothing about runtime behaviour |
| documentation links | Every internal link resolves |
| standalone gateway smoke test | A running process serves the checked REST and MCP surfaces, including the approval round trip |

Two of these need a local virtual environment for the schema libraries:

```console
$ .superpowers/contract-venv/bin/python scripts/check_source_contracts.py
```

The gates are a **quality gate, not a release authorization**. The licence is still an open decision and the crate manifests set `publish = false`. Nothing in this repository creates a release, a tag or a published artifact.

## What the gates do not cover

- No gate talks to a provider, a registry, a cluster or an OAuth endpoint. See [Compatibility](compatibility.md) for the full list of surfaces that have never met a remote peer.
- The schema gate validates design documents, not the code that implements them.
- The smoke test binds a loopback port and uses a fixture mailbox. It proves the process starts, validates its configuration and serves its own contract.

## Durable state

Durable state lives in SQLite through `mail-storage`. The operational rules are strict, and each of them fails closed:

- **One writer.** A second writer is refused, including after a stale PID file from a crashed writer. Do not run two gateway processes against one database file.
- **No high availability.** The PostgreSQL backend is explicitly unavailable rather than emulated, and a multi-replica configuration is refused for every backend.
- **Restore is revocation-safe.** A backup that cannot prove it is newer than the revocation state is refused, and a revoked grant does not come back with a backup. If a restore is refused for freshness, the operator must re-authorize; do not work around it by restoring an older file.
- **The revocation ledger must be backed up with the database.** It is written before the database changes it describes. A database restored without its ledger has lost the evidence that a credential was revoked.
- **Crash durability is proven for a process kill, not for power loss.** The tests kill a process; they do not cut power to a disk.

## Idempotency

The standalone gateway keeps its idempotency replay table in memory. `idempotencyDurable` is `false` in the status projection, and that is the truth: a restart forgets the table, and duplicate suppression holds only within one process.

Within a process the behaviour is:

- Two concurrent sends with the same key deliver the message **once**; the second returns the first submission as a replay.
- The same key with a different envelope is an `IDEMPOTENCY_CONFLICT` and sends nothing.
- A send the upstream **definitely refused** releases the key, so the caller may retry with it.
- A send whose outcome is **unknown** keeps the key claimed, because the message may have been delivered and a retry could deliver it twice.

## Telemetry

Telemetry is off by default and allocates nothing when it is off. When it is on, the buffer is bounded, the label keys come from a fixed allowlist, and an event structurally cannot carry a message body, a credential, a token, a provider URL or a recipient address. A collector that errors, times out or panics never fails the mail operation that produced the event.

There is no exporter. The seam exists so that one can be attached later; nothing scrapes this process today.

## Not available in this deployment

| Capability | Status |
| --- | --- |
| Kubernetes operator, admission webhook, real Secret writes | Decision logic and rendered fixtures only. There is no cluster client in the workspace |
| PostgreSQL, multi-replica, cross-replica leases | Refused explicitly. One SQLite writer is the supported topology |
| Real WASM policy execution | The host side fails closed with an explicit unsupported status; `wasmtime` is not available |
| gRPC provider service, mTLS, OCI plugin runtime | Contract definitions and typed clients only; no server, no transport |
| Live provider APIs (Migadu, IMAP, SMTP, JMAP) | Not exercised. See [Compatibility](compatibility.md) |
| Metrics export | No exporter, no scrape endpoint |
| Licence, publication, release tags | Blocked on the explicit owner decision (ADR-0001 section 14) |

## When something fails

The gateway's rule is to fail closed and to say so:

- An unknown identity is reported as **not found**, never as forbidden, so a caller cannot probe for identities it may not use.
- A hidden message is absent from listings, searches and direct reads alike.
- A missing dependency in the operator's admission path is a refusal, not a permissive default.
- A policy decision that cannot be evaluated routes to the policy's `on_indeterminate`, whose secure default is to hide.
- An upstream call whose outcome cannot be determined is reported as unknown and is never retried automatically.
