# ADR-0004: Pluggable gRPC policy decision engines

- **Status:** Proposed
- **Date:** 2026-11-15
- **Related:** [ADR-0001: System architecture](0001-corvi-system-architecture.md), [ADR-0003: Mail filtering and disclosure policies](0003-mail-filtering-and-disclosure-policies.md)

## Context

Corvi's mail access broker must enforce action permissions, strong mailbox/identity boundaries, and message-level disclosure filters. ADR-0003 describes a built-in deterministic filter model. Some installations may prefer established authorization policy engines, centralized governance, or reusable Rego/Cerbos rules.

Corvi should support **optional gRPC policy decision points (PDPs)** without turning an external authorization service into a mandatory runtime dependency for the minimal one-process gateway.

An external PDP is a **data-plane-adjacent authorization dependency**, not a provider-management plugin, not a Kubernetes admission webhook, and not part of the control-plane configuration publisher. It can be colocated with the gateway or contacted over authenticated gRPC when explicitly configured.

## Decision

1. Ship a **built-in local policy evaluator** as the default. A standalone gateway requires neither a PDP container nor Kubernetes nor gRPC.
2. Define an optional, provider-neutral **policy decision interface**, with a versioned gRPC transport for remote PDPs.
3. Offer adapters for established engines where useful. **Cerbos** exposes a native gRPC `CheckResources` interface; **OPA's Envoy plugin** implements the Envoy `ext_authz` gRPC protocol (HTTP-centric), so Corvi would need a deliberate translation layer for message-level semantics. OPA can alternatively be evaluated locally from compiled Wasm.
4. The core data plane remains the **Policy Enforcement Point (PEP)**. Every external result is constrained by authenticated principal and credential scope, mailbox/identity membership, and non-overridable security requirements. A PDP can never grant an identity the credential does not have, claim trusted recipient provenance, or bypass mandatory filtering.
5. Keep **action authorization** and **message disclosure** logically separate. External decisions can deny or permit configured actions within a locally established maximum scope, and can emit **typed disclosure obligations**; the core validates and applies obligations locally.
6. Fail closed on timeout, malformed response, unknown obligation, unrecognized engine version, or unavailability for any operation that requires remote evaluation. Never fall back to a permissive policy. A working local-only policy must remain available without a remote service.

## 1. Evaluation order and trust

```text
Authenticated caller / credential
     |
     v
Local non-overridable token + identity scope
     |
     v
Optional local or gRPC action PDP
     |
     v
Trusted recipient provenance / message membership
     |
     v
Local MIME parsing + classification (bounded)
     |
     v
Built-in and optional remote disclosure PDP(s)
     |
     v
Corvi validates decision and applies local redactions
     |
     v
Safe principal-specific message projection
```

A positive decision only grants access **within the caller's locally validated outer boundary**. External policy engines do not see provider administrative secrets. Where an engine has its own policy repository, the control plane may provision its configuration independently, but the data plane cannot depend on the operator to evaluate any individual request.

The remote policy engine must not be used as a shortcut around the existing hide/redact/attachment protections in ADR-0003. For example, deciding that `auth.otp` should be hidden still requires trusted local detection and suppression of every presentation surface.

## 2. Proposed Corvi gRPC contract

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
| **Local compiled policy** | Optional embedded Wasm/equivalent evaluation | Policy module packaged locally; no PDP RPC |
| **External gRPC PDP** | Corvi-native policy RPC or adapter to existing engines | Explicit per-policy data-plane dependency |
| **Mixed** | Local mandatory restrictions plus optional external grants/denials/obligations | Fail closed for whichever restricted decision cannot be obtained |

The exact mechanism should be configured **per policy or policy group**, so a gateway may use local filtering for most mail and an external PDP for a particular credential or tenant.

```yaml
# Illustrative standalone config, not a finalized schema.
policyEngines:
  builtin:
    type: local

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
    engineRef: corporate
    mandatoryLocalFilters:
      - hide-authentication
```

Any Cerbos-specific adapter must translate Corvi request attributes and actions to Cerbos resource/principal/action types, and translate returned decisions/outputs to the *restricted* Corvi contract. Cerbos outputs may describe obligations, but the adapter must validate them against an allowlisted schema. The same approach applies to OPA and future engines.

## 4. Data-minimization and message confidentiality

A remote PDP is another recipient of information about personal messages. **Do not transmit raw email bodies, complete MIME payloads, attachments, OTP values, password-reset URLs, access tokens or other sensitive fields by default.**

Instead, Corvi locally derives the minimum necessary information: opaque message/identity reference, requested action, normalized attributes explicitly approved for release, classifications such as `auth.otp` or `auth.password_reset`, and relevant policy revisions.

Even sender, subject, recipient and message existence can be sensitive. Their inclusion must be an explicit, privacy-reviewed policy setting. Avoid unbounded user-controlled labels or echoing private content in gRPC metadata, errors, logs or traces.

If future remote content-inspection engines are required, design a **separate explicit trusted processing contract** with its own opt-in data transfer permissions, transport security, quotas and retention guarantees. A generic authorization PDP is not entitled to raw personal mail simply because it participates in policy evaluation.

## 5. Security, transport and lifecycle

- **mTLS required** for remote gRPC across a network trust boundary, with verified peer identity and explicit service authorization.
- For Kubernetes, use operator-managed **cert-manager CSI certificates opportunistically**, falling back to Certificate + Secret; supply CA trust separately. **No trust-manager.**
- Standalone operation uses explicitly supplied certificate/key and CA files. No plaintext gRPC fallback.
- Bound deadlines, batch size, attribute cardinality, request size, concurrency and retries. Do not retry side-effecting operations through a PDP; policy evaluation RPCs should be pure/idempotent.
- Batch checks for list/search workloads to reduce per-message RPC overhead. Cache **decisions** only when safe and revision-scoped: principal, credential scope, action, resource/message revision, classifications, identity/isolation evidence, PDP policy revision and active Corvi config generation.
- Do not cache `ALLOW` across revocation, policy rollout, or identity scope changes. A stale cache must never bypass an expired credential. If PDP freshness cannot be established, fail closed for checks that require it.
- Distinguish `DENY` from `INDETERMINATE` internally; do not leak matched private rule details to scoped clients.
- Keep gRPC PDP configuration independent of provider-plugin gRPC credentials, Services and authorization domains.

**Availability rule:** Configuring an external PDP changes availability for the *specific operations depending on it*: they deny or become unavailable if the PDP cannot be reached, while operations governed purely by local policy continue normally. The blanket "gateway keeps running without the control plane" invariant remains true: a PDP is a deliberately optional, separately identified **data-plane** dependency, not an operator webhook.

## 6. Observability and testability

Instrument evaluation count, decision outcome, duration, batch size, timeout/failure rates, cache hit rates, policy revision mismatches and obligation validation failures. Use bounded labels only; never metric-label individual messages, addresses, token IDs or rule-matched secrets. Preserve W3C trace context when safe; traces must not contain policy input bodies.

Provide a privileged local `corvi policy test` command and fixture suite able to run policy decisions against synthetic messages and compare local/remote results with expected allowed/hide/redacted projections.

Required tests include:

1. A remote `ALLOW` cannot override a local identity/credential denial or trusted recipient provenance check.
2. A remote `ALLOW` cannot bypass a mandatory local `hide-authentication` rule.
3. Missing, malformed, timed-out or unauthenticated PDP responses fail closed for dependent operations.
4. Unknown obligations fail closed, not silently ignored.
5. Bulk search, counts, threads, attachments, snippets and event streams honor all effective decisions.
6. Remote requests contain only explicitly allowlisted metadata and classifications, not raw sensitive values.
7. PDP outages never affect operations using only the local policy engine.
8. Certificate rotation and CA overlap do not permit downgrade to plaintext.
9. Cache keys incorporate policy and message revisions and are invalidated on revocation and policy changes.

## Non-goals

- Mandating OPA, Cerbos, Envoy, Kubernetes or another service for standalone Corvi.
- Allowing an arbitrary policy engine to administer the upstream mail provider.
- Treating a network authorization response as sufficient to sanitize email content.
- Adding remote classifiers that receive full mail by default.
- Changing the control-plane/data-plane separation in ADR-0001.

## Open questions

- Whether the public integration interface should offer only Corvi-native gRPC, or also direct protocol-specific Cerbos/Envoy clients.
- Precise typed input, output, obligation and filter-rule schema, including compatibility rules.
- How to express contextual access grants without confusing them with maximum credential scope.
- Supported local compiled engines (Wasm sandboxing, fuel/memory budgets, trusted module loading).
- PDP outage policy for in-flight paginated requests and streaming responses.
- Cache/plan integration for expensive searchable-mail listings and query-based authorization.
- Secure distribution of PDP policy revisions and detection of drift between configured policies and engine state.

## Consequences

Corvi can integrate with existing gRPC authorization systems while keeping a minimal single-container IMAP/SMTP deployment. The data plane remains the authority that **enforces** identity isolation and safe content projections. External PDPs are optional tools for expressing decisions, not a route around the privacy guarantees established by ADR-0003.
