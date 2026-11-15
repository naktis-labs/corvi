# ADR-0004: Pluggable policy evaluation with WASM and gRPC

- **Status:** Proposed
- **Date:** 2026-11-15
- **Updated:** 2026-11-16
- **Related:** [ADR-0001: System architecture](0001-corvi-system-architecture.md), [ADR-0003: Mail filtering and disclosure policies](0003-mail-filtering-and-disclosure-policies.md)

## Context

Corvi's mail access broker must enforce action permissions, strong mailbox/identity boundaries, and message-level disclosure filters. ADR-0003 describes a built-in deterministic filter model. Some installations may prefer established authorization policy engines, centralized governance, or reusable Rego/Cerbos rules.

Corvi should support **pluggable policy decision backends** without turning external authorization infrastructure into a mandatory dependency. **Sandboxed in-process WASM is the preferred extensibility mechanism** for self-hosted deployments; gRPC PDPs remain an option for installations with existing centralized authorization systems. The built-in rules engine remains the minimum baseline.

WASM policies run inside the data-plane process through a constrained host ABI. A remote PDP is an explicitly opted-in **data-plane-adjacent authorization dependency**, not a provider-management plugin, Kubernetes admission webhook, or configuration publisher. Both implementations return the same conceptual decisions and obligations.

## Decision

1. Ship a **built-in local policy evaluator** as the default. A standalone gateway requires no additional container, Kubernetes API, gRPC endpoint or WASM module.
2. Define an internal **PolicyDecisionEngine** interface shared by built-in evaluation, optional **in-process sandboxed WASM**, and optional **external gRPC PDPs**. The policy engine must never become a control-plane webhook.
3. Prefer **WASM for user-supplied or custom policy logic**. A sandboxed module consumes bounded, typed, allowlisted input and returns structured decisions and obligations, without requiring a second process or disclosure of mail metadata over a network.
4. Support gRPC adapters for existing engines. **Cerbos** exposes native gRPC resource checks; **OPA's Envoy plugin** implements Envoy `ext_authz` (HTTP-centric), requiring an adapter for mail operations. **OPA/Rego** policies may also be compiled to WASM, subject to OPA's own runtime ABI and built-in function limitations.
5. Keep the Corvi data plane as **Policy Enforcement Point (PEP)**. Neither WASM nor gRPC can enlarge credential scope, fabricate recipient provenance, or suppress mandatory local safety filters.
6. Keep **action authorization** and **message disclosure** logically separate. Evaluators may return bounded typed obligations; the core validates and executes redaction, hiding, attachment restrictions and content sanitization.
7. Fail closed on missing/invalid module, trap, fuel exhaustion, memory violation, unexpected output, timeout, malformed remote response, or missing required PDP. Never silently fall back to a more permissive policy. A local-only policy works independently of all optional engines.

## 1. Evaluation order and trust

```text
Authenticated caller / credential
     |
     v
Local non-overridable token + identity scope
     |
     v
Built-in, WASM or optional gRPC action PDP
     |
     v
Trusted recipient provenance / message membership
     |
     v
Local MIME parsing + classification (bounded)
     |
     v
Built-in, WASM or optional remote disclosure decision
     |
     v
Corvi validates decision and applies local redactions
     |
     v
Safe principal-specific message projection
```

A positive decision only grants access **within the caller's locally validated outer boundary**. Policy engines do not receive provider administrative secrets. Where an engine has its own policy repository, the control plane may provision its configuration independently, but the data plane cannot depend on the operator to evaluate any individual request.

No policy engine may be used as a shortcut around the existing hide/redact/attachment protections in ADR-0003. For example, deciding that `auth.otp` should be hidden still requires trusted local detection and suppression of every presentation surface.

## 2. Proposed remote gRPC contract

Expose a small, engine-neutral gRPC contract for third-party PDP adapters (conceptual protobuf; concrete fields and compatibility rules to be specified before implementation):

```protobuf
syntax = "proto3";
package corvi.policy.v1;

service PolicyDecisionPoint {
  rpc Evaluate(EvaluateRequest) returns (EvaluateResponse);
  rpc EvaluateBatch(EvaluateBatchRequest)
      returns (EvaluateBatchResponse);
}

message EvaluateRequest {
  string request_id = 1;
  string principal_id = 2;
  string credential_scope_id = 3;
  string action = 4;
  string resource_id = 5;
  string identity_id = 6;
  string configuration_revision = 7;

  // Normalized, allowlisted attributes only.
  map<string, string> attributes = 8;
  repeated string classifications = 9;
}

message EvaluateResponse {
  enum Effect {
    EFFECT_UNSPECIFIED = 0;
    ALLOW = 1;
    DENY = 2;
    INDETERMINATE = 3;
  }

  Effect effect = 1;
  repeated DisclosureObligation obligations = 2;
  string policy_revision = 3;
}

message DisclosureObligation {
  enum Kind {
    KIND_UNSPECIFIED = 0;
    HIDE_MESSAGE = 1;
    REDACT_FIELD = 2;
    DENY_ATTACHMENTS = 3;
    SANITIZE_HTML = 4;
    REMOVE_EXTERNAL_LINKS = 5;
  }

  Kind kind = 1;
  string field_path = 2;
}

message EvaluateBatchRequest {
  repeated EvaluateRequest requests = 1;
}

message EvaluateBatchResponse {
  repeated EvaluateResponse responses = 1;
}
```

The schema above is **not finalized**. In particular, production messages should use typed attribute values, authenticated request-context handling, bounded attribute sets, unambiguous batch-item correlation, and versioned policy input contracts. A caller-supplied `principal_id` must never be accepted as authentication.

The PDP returns decisions and typed obligations, **not rewritten message bodies**. Corvi owns the MIME parser, sanitizer, classifier, content redaction, attachment handling, rendering and final enforcement. A valid `ALLOW` with malformed obligations is an error, not permission to ignore them.

## 3. Supported implementation modes

| Mode | Evaluation | Availability impact |
| --- | --- | --- |
| **Built-in** | In-process Corvi policies | No external process |
| **Sandboxed WASM (preferred extension)** | In-process Wasmtime; versioned policy input/output ABI | No additional container or RPC; fail closed on module error |
| **External gRPC PDP** | Corvi-native policy RPC or adapter to existing engines | Explicit per-policy data-plane dependency |
| **Mixed** | Local mandatory restrictions plus optional external grants/denials/obligations | Fail closed for whichever restricted decision cannot be obtained |

The exact mechanism should be configured **per policy or policy group**, so a gateway may use local filtering for most mail and an external PDP for a particular credential or tenant.

```yaml
# Illustrative standalone config, not a finalized schema.
policyEngines:
  builtin:
    type: local

  privacy:
    type: wasm
    module: /etc/corvi/policies/privacy.wasm
    abi: corvi-policy-v1
    limits:
      memoryBytes: 16777216
      fuel: 1000000
      timeout: 50ms
    onError: deny

  corporate:
    type: grpc
    protocol: cerbos
    endpoint: dns:///cerbos:3593
    tls:
      caFile: /etc/corvi/pki/ca.crt
      clientCertificateFile: /etc/corvi/pki/tls.crt
      clientKeyFile: /etc/corvi/pki/tls.key
      expectedServerName: cerbos.internal
    timeout: 250ms
    onError: deny

mailPolicies:
  scoped-read:
    engineRef: privacy
    mandatoryLocalFilters:
      - hide-authentication
```

Any Cerbos-specific adapter must translate Corvi request attributes and actions to Cerbos resource/principal/action types, and translate returned decisions/outputs to the *restricted* Corvi contract. Cerbos outputs may describe obligations, but the adapter must validate them against an allowlisted schema. The same approach applies to OPA and future engines.

## 4. Sandboxed in-process WASM backend

**Preferred extension path:** Embed Wasmtime in the Rust data plane and allow administrator-supplied policy modules to be loaded from a local path or from a control-plane-published, digest-pinned and validated policy bundle. A local file is sufficient for standalone operation; an operator is never required.

### 4.1 Contract and module formats

Prefer a **versioned WIT/WebAssembly Component Model interface** for Corvi-native policy modules. The WIT shape below is illustrative; the exact IDL, error types and versioning need their own API review.

```wit
package corvi:policy@0.1.0;

interface decisions {
  enum effect { allow, deny, indeterminate }
  enum obligation-kind {
    hide-message,
    redact-field,
    deny-attachments,
    sanitize-html,
    remove-external-links
  }

  record obligation {
    kind: obligation-kind,
    field: option<string>,
  }

  record request {
    principal: string,
    action: string,
    resource: string,
    identity: string,
    classifications: list<string>,
  }

  record response {
    effect: effect,
    obligations: list<obligation>,
  }

  evaluate: func(input: request) -> response;
}

world policy {
  export decisions;
}
```

Treat untrusted client attributes as untrusted inputs; authenticated principal/identity and maximum credential scope come from Corvi, not from module-supplied claims. Version every input and output schema. Cap string lengths, list sizes and invocation frequency.

**OPA/Rego WASM is not the same ABI as a Corvi WIT component.** OPA compiled policies use an OPA-specific evaluation and host-builtin interface. Provide an explicit OPA-WASM adapter if supported rather than pretending an OPA bundle can be loaded directly as a Corvi component. OPA's WASM target does not natively support every Rego builtin; fail closed for missing imports unless an intentionally allowed host implementation exists.

### 4.2 Sandbox and resource limits

WASM modules receive **no WASI filesystem, network, sockets, clocks, random source, environment variables or arbitrary host functions by default**. Only deliberately exposed, pure, bounded host functions are permitted. In particular, modules cannot fetch raw mail or call external APIs on their own.

Use separate per-request invocation state, or carefully reset isolated state between calls. Precompile and cache the code where safe, but do not share mutable policy state or secrets across principals. Policy evaluation must be deterministic given the input and policy version, or its non-determinism must be explicitly declared and bounded.

Enforce:

- Wasmtime **fuel** budgets (deterministic instruction budget), **epoch/interruption deadlines**, and **linear-memory/table limits**.
- Per-call wall-clock deadlines, bounded module initialization and output validation.
- Concurrency/backpressure limits so a slow policy cannot exhaust the gateway.
- Digest pinning, signature verification where configured, provenance and local admin authorization for policy installation.
- No in-process native shared libraries as an alternative execution path for untrusted policies.

A trap, invalid return value, exceeded limit, unknown obligation or ABI mismatch results in **indeterminate → deny/hide** for any operation depending on that module, never a permissive fallback.

### 4.3 What WASM may decide

Policy modules produce `ALLOW`, `DENY`, `INDETERMINATE` and a bounded list of typed obligations. They do **not** return rewritten MIME payloads, raw attachment bytes or arbitrary executable transformations. Corvi applies every hide/redact/strip instruction to the final representation and every derived surface.

WASM can implement a custom classification rule over **explicitly permitted and bounded input fields**, but Corvi must parse MIME and control disclosure first. Feeding raw private email bodies to untrusted code is not automatic; explicit local administrator policy must approve the exact input fields. A WASM module itself should not be treated as more trustworthy than a remote PDP solely because it executes locally.

### 4.4 Distribution and reload

In standalone mode, a local module path plus digest and configuration revision is enough. In managed deployments, the control plane may publish policy-module references/assets alongside a validated snapshot. The data plane validates and compiles the new module before atomically activating a policy generation. Retain last-known-good modules only when safe under the configured staleness/revocation policy.

Policy updates require cache invalidation using module digest, policy revision, message/classification version and credential scope. No operator, plugin or remote RPC is required for a WASM policy invocation.

## 5. Data-minimization and message confidentiality

A remote PDP is another recipient of information about personal messages. **Do not transmit raw email bodies, complete MIME payloads, attachments, OTP values, password-reset URLs, access tokens or other sensitive fields by default.**

Instead, Corvi locally derives the minimum necessary information: opaque message/identity reference, requested action, normalized attributes explicitly approved for release, classifications such as `auth.otp` or `auth.password_reset`, and relevant policy revisions.

Even sender, subject, recipient and message existence can be sensitive. Their inclusion must be an explicit, privacy-reviewed policy setting. Avoid unbounded user-controlled labels or echoing private content in gRPC metadata, errors, logs or traces.

If future remote content-inspection engines are required, design a **separate explicit trusted processing contract** with its own opt-in data transfer permissions, transport security, quotas and retention guarantees. A generic authorization PDP is not entitled to raw personal mail simply because it participates in policy evaluation.

## 6. Security, transport and lifecycle

- **mTLS required** for remote gRPC across a network trust boundary, with verified peer identity and explicit service authorization. WASM in-process evaluation does not require gRPC, certificates or a remote policy endpoint.
- For Kubernetes, use operator-managed **cert-manager CSI certificates opportunistically**, falling back to Certificate + Secret; supply CA trust separately. **No trust-manager.**
- Standalone operation uses explicitly supplied certificate/key and CA files. No plaintext gRPC fallback.
- Bound deadlines, batch size, attribute cardinality, request size, concurrency and retries. Do not retry side-effecting operations through a PDP; policy evaluation RPCs should be pure/idempotent.
- Batch checks for list/search workloads to reduce per-message RPC overhead. Cache **decisions** only when safe and revision-scoped: principal, credential scope, action, resource/message revision, classifications, identity/isolation evidence, PDP policy revision and active Corvi config generation.
- Do not cache `ALLOW` across revocation, policy rollout, or identity scope changes. A stale cache must never bypass an expired credential. If PDP freshness cannot be established, fail closed for checks that require it.
- Distinguish `DENY` from `INDETERMINATE` internally; do not leak matched private rule details to scoped clients.
- Keep gRPC PDP configuration independent of provider-plugin gRPC credentials, Services and authorization domains.

**Availability rule:** Configuring an external PDP changes availability for the *specific operations depending on it*: they deny or become unavailable if the PDP cannot be reached, while operations governed purely by local policy continue normally. The blanket "gateway keeps running without the control plane" invariant remains true: a PDP is a deliberately optional, separately identified **data-plane** dependency, not an operator webhook.

## 7. Observability and testability

Instrument evaluation count, decision outcome, duration, batch size, timeout/failure rates, cache hit rates, policy revision mismatches and obligation validation failures. Use bounded labels only; never metric-label individual messages, addresses, token IDs or rule-matched secrets. Preserve W3C trace context when safe; traces must not contain policy input bodies.

Provide a privileged local `corvi policy test` command and fixture suite able to run policy decisions against synthetic messages and compare local/remote results with expected allowed/hide/redacted projections.

Required tests include:

1. A WASM or remote `ALLOW` cannot override a local identity/credential denial or trusted recipient provenance check.
2. A WASM or remote `ALLOW` cannot bypass a mandatory local `hide-authentication` rule.
3. Missing, malformed, timed-out or unauthenticated PDP responses fail closed for dependent operations.
4. Unknown obligations fail closed, not silently ignored.
5. Bulk search, counts, threads, attachments, snippets and event streams honor all effective decisions.
6. Remote requests contain only explicitly allowlisted metadata and classifications, not raw sensitive values.
7. PDP outages never affect operations using only the local policy engine.
8. Certificate rotation and CA overlap do not permit downgrade to plaintext.
9. Cache keys incorporate policy, module digest, and message revisions and are invalidated on revocation and policy changes.
10. WASM modules with infinite loops, excessive memory, invalid imports, forbidden filesystem/network access or malformed obligations fail closed without crashing the gateway.
11. OPA/Rego WASM bundles require their explicit adapter and cannot be loaded as Corvi WIT components by accident.

## Non-goals

- Mandating OPA, Cerbos, Envoy, Kubernetes, WASM modules or another service for standalone Corvi.
- Allowing an arbitrary policy engine to administer the upstream mail provider.
- Treating a network authorization response as sufficient to sanitize email content.
- Adding remote classifiers that receive full mail by default.
- Changing the control-plane/data-plane separation in ADR-0001.

## Open questions

- Whether the public integration interface should offer only Corvi-native gRPC, or also direct protocol-specific Cerbos/Envoy clients.
- Precise typed input, output, obligation and filter-rule schema, including compatibility rules.
- How to express contextual access grants without confusing them with maximum credential scope.
- Versioned WIT policy schema, guest SDKs and acceptable module signing/rollout conventions.
- Exact Wasmtime fuel/memory/time budgets per action and the extent of allowed host functionality.
- OPA-WASM adapter lifecycle and upstream builtins compatibility.
- PDP outage policy for in-flight paginated requests and streaming responses.
- Cache/plan integration for expensive searchable-mail listings and query-based authorization.
- Secure distribution of PDP policy revisions and detection of drift between configured policies and engine state.

## Consequences

Corvi can run custom sandboxed policy code in-process using WASM and integrate with existing gRPC authorization systems, while keeping a minimal single-container IMAP/SMTP deployment. The data plane remains the authority that **enforces** identity isolation and safe content projections. WASM and external PDPs are optional tools for expressing decisions, not a route around the privacy guarantees established by ADR-0003.
