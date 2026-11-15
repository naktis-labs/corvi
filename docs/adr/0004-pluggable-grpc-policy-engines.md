# ADR-0004: Pluggable policy evaluation with WASM and gRPC

- **Status:** Proposed
- **Date:** 2026-11-15
- **Updated:** 2026-11-16
- **Distribution requirement:** Publish every WASM policy version as both native Wasm OCI and Kubernetes image-volume OCI variants, under separate tags.
- **Related:** [ADR-0001: System architecture](0001-corvi-system-architecture.md), [ADR-0003: Mail filtering and disclosure policies](0003-mail-filtering-and-disclosure-policies.md)

## Context

Corvi's mail access broker must enforce action permissions, strong mailbox/identity boundaries, and message-level disclosure filters. ADR-0003 describes a built-in deterministic filter model. Some installations may prefer established authorization policy engines, centralized governance, or reusable Rego/Cerbos rules.

Corvi should support **pluggable policy decision backends** without turning external authorization infrastructure into a mandatory dependency. **Sandboxed in-process WASM is the preferred extensibility mechanism** for self-hosted deployments; gRPC PDPs remain an option for installations with existing centralized authorization systems. The built-in rules engine remains the minimum baseline.

WASM policies run inside the data-plane process through a constrained host ABI. A remote PDP is an explicitly opted-in **data-plane-adjacent authorization dependency**, not a provider-management plugin, Kubernetes admission webhook, or configuration publisher. Both implementations return the same conceptual decisions and obligations.

## Decision

1. Ship a **built-in local policy evaluator** as the default. A standalone gateway requires no additional container, Kubernetes API, gRPC endpoint or WASM module.
2. Define an internal **PolicyDecisionEngine** interface shared by built-in evaluation, optional **in-process sandboxed WASM**, and optional **external gRPC PDPs**. The policy engine must never become a control-plane webhook.
3. Prefer **WASM for user-supplied or custom policy logic**. Distribute executable policy modules as **OCI registry images**, resolve them to immutable digests, and execute the extracted WASM component in-process. A sandboxed module consumes bounded, typed, allowlisted input and returns structured decisions and obligations, without requiring a second process or disclosure of mail metadata over a network.
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
    image: ghcr.io/naktis-labs/corvi-policy-privacy@sha256:<native-wasm-manifest-digest>
    abi: corvi-policy-v1
    registryAuth:
      credentialFile: /run/secrets/registry-auth.json
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

**Preferred extension path:** Embed Wasmtime in the Rust data plane. Administrator-supplied executable policy modules are **packaged and distributed as OCI images from registries**, pinned to digests. The gateway can resolve and cache them itself in standalone mode; an operator is never required. Raw local `.wasm` files may be accepted by an explicitly labeled developer/test command, but are **not the supported deployment format** for installed policy modules.

An OCI-distributed WASM module does **not** imply a separate running Linux container, Pod, OCI runtime or control-plane RPC. An OCI registry transports the package; Wasmtime executes the verified component **inside** Corvi.

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
- OCI manifest digest and optional publisher trust verification **before** execution; do not allow a module to evade sandbox rules by changing packaging format.

A trap, invalid return value, exceeded limit, unknown obligation or ABI mismatch results in **indeterminate → deny/hide** for any operation depending on that module, never a permissive fallback.

### 4.3 What WASM may decide

Policy modules produce `ALLOW`, `DENY`, `INDETERMINATE` and a bounded list of typed obligations. They do **not** return rewritten MIME payloads, raw attachment bytes or arbitrary executable transformations. Corvi applies every hide/redact/strip instruction to the final representation and every derived surface.

WASM can implement a custom classification rule over **explicitly permitted and bounded input fields**, but Corvi must parse MIME and control disclosure first. Feeding raw private email bodies to untrusted code is not automatic; explicit local administrator policy must approve the exact input fields. A WASM module itself should not be treated as more trustworthy than a remote PDP solely because it executes locally.

### 4.4 Dual OCI image packaging and tag convention

**The native WASM OCI variant** uses the CNCF TAG Runtime *Wasm OCI Artifact layout* where compatible: an `application/vnd.oci.image.manifest.v1+json` manifest with `config.mediaType: application/vnd.wasm.config.v0+json` and a single `application/wasm` layer containing the compiled policy component. This is an OCI **image-manifest-based non-container artifact**, not a Linux/amd64 image that kubelet is expected to run as a Deployment.

For the **native variant**, reject unsupported manifest/config/media types, multiple ambiguous module layers, platform-specific container filesystems presented as policy modules, and unsupported imported capabilities. Validate the actual WASM binary and its required WIT ABI; media-type metadata alone is not proof of trust. Corvi-specific annotations may describe the policy ABI, input schema version, display name and build provenance, but **cannot grant additional host capabilities**. The manifest digest pins both module content and its metadata.

The image reference is an **OCI registry address** (e.g. `ghcr.io/naktis-labs/corvi-policy-privacy@sha256:<digest>`). A human-friendly tag may be used to discover an image during development, but production activation resolves and records an immutable digest; mutable tags are not used as cache identity or a policy-evaluation dependency.

The same artifact can be published with OCI-aware tooling such as ORAS, provided it preserves the expected image-manifest and layer media types. Registry compatibility, including registries that reject non-container image manifests, must be tested rather than assumed. These media types follow the current CNCF Wasm OCI layout guidance; if that guidance evolves, a future ADR or compatibility version may migrate the packaging rules.

### 4.4.1 Required paired release artifacts

**Every released Corvi WASM policy is published twice, using separate format-suffixed tags under the same OCI repository.** Both packages derive from the **same compiled WASM module** and implement the same WIT ABI.

| Variant | Version tag | Format | Consumer |
| --- | --- | --- | --- |
| Native WASM OCI | `v1.2.3-wasm` | Native OCI image manifest, `application/vnd.wasm.config.v0+json` config, single `application/wasm` layer | Corvi's OCI resolver |
| Image-volume OCI | `v1.2.3-volume` | Standard OCI container-image manifest and tar filesystem layer with `/policy.wasm` and `/policy.json` | Kubernetes `image` volume |

For example:

```text
ghcr.io/naktis-labs/corvi-policy-privacy:v1.2.3-wasm
ghcr.io/naktis-labs/corvi-policy-privacy:v1.2.3-volume
```

The `-volume` image is a **read-only data filesystem**, not a service or a new container to run. It contains the module and metadata, with no shell or auxiliary executable. The `policy.json` file identifies the policy ABI and common uncompressed WASM SHA-256. Publish a multi-platform image index where required for the supported Kubernetes node platforms, using **identical WASM bytes** in each platform-specific image.

The publish pipeline must **compile the module once** and create both images from the result. Before releasing, extract/check both module byte sequences and fail if their SHA-256 hashes differ or ABI metadata disagrees. Record the version, the **two distinct OCI manifest/index digests**, and the **shared WASM module digest** in signed or attestable release metadata. A matching tag prefix does not prove that two images contain the same code.

Production configuration uses **digest-pinned image references**, rather than tags:

```text
# Corvi-native resolver
ghcr.io/naktis-labs/corvi-policy-privacy@sha256:<native-manifest-digest>

# Kubernetes image volume
ghcr.io/naktis-labs/corvi-policy-privacy@sha256:<volume-manifest-or-index-digest>
```

Corvi must never mix up the two manifest digests. It must verify the actual module's ABI, imports and SHA-256 before running it. Image signatures/publisher trust policies apply to each artifact or a verified release mapping, not only to a version string. OCI distribution, media-type and volume compatibility must be tested on supported registries and runtimes.

### 4.5 Registry access, trust and caching

- Fetch over verified HTTPS, using scoped read-only registry credentials where needed. **Do not assume Kubernetes imagePullSecrets automatically authenticate a process using an OCI registry client.** A standalone gateway receives registry auth as a mounted file or workload identity; an operator may provision a Secret mount or an optional prefetch mechanism.
- Verify content-addressed manifest/layer digests and sizes; enforce byte, layer-count, decompression, redirect and fetch-time limits.
- Allow an explicit per-installation image signature/attestation trust policy (e.g. Sigstore verification); production configurations should be able to **require** verified publisher identity or signed digest before activation. Never infer trust merely from the registry name or the OCI media type.
- In native mode extract only expected module/config blobs into a content-addressed cache. In image-volume mode read only the expected mounted files, verifying the shared WASM digest. Never run an OCI container, execute an image entrypoint, or expose arbitrary file paths to a module.
- Precompile and validate policy components *before* switching active policy revisions, and bind the compiled module to its manifest digest and ABI version.
- If a required policy's pinned image is not cached and its registry is unavailable, **fail closed** for operations requiring that policy. If a validated cached image exists, evaluate it without contacting the registry. The cache must be available across gateway restarts when offline operation is expected.
- Cache and source policy modules independently of the control plane. No remote registry request is made **per mail request**, and registry or publisher outages never affect evaluation of already cached, still-valid modules.
- Snapshot publication and module activation must be coordinated: only activate a new policy generation after its image digest, trusted publisher (when configured), ABI and resource limits have been validated. A previous generation can remain active only within its explicit expiry/revocation rules, never as a permissive fallback after a mandatory security change.

### 4.6 Deployment modes and reload

**Standalone:** A single Corvi container accepts digest-pinned **native `-wasm`** OCI image references in its local configuration, fetches modules using an embedded registry client, and persists a verified cache. No extra registry sidecar, operator or runtime is necessary. For air-gapped deployments, allow explicitly prepopulating the content-addressed cache with the **same digest-verified OCI image**; the policy configuration still references its image digest.

**Operator-managed:** Prefer a Kubernetes `image` volume backed by the **`-volume` variant's own digest**, where the cluster/runtime supports image volumes. The operator mounts the image read-only and provides Corvi the path to `policy.wasm` and `policy.json`, plus the expected WASM SHA-256 from the verified release mapping. Corvi loads the module in-process; it does not execute the image as a container. Kubernetes owns the pull, node cache and `imagePullSecrets`. Changing a pinned digest requires a controlled Pod-template rollout because image-volume contents do not live-update.

```yaml
# Illustrative generated Pod volume:
volumes:
  - name: privacy-policy
    image:
      reference: ghcr.io/naktis-labs/corvi-policy-privacy@sha256:<volume-manifest-or-index-digest>
      pullPolicy: IfNotPresent

# Illustrative gateway configuration with the volume mounted at /run/corvi/policies/privacy:
policyEngines:
  privacy:
    type: wasm
    source:
      type: mounted
      path: /run/corvi/policies/privacy/policy.wasm
      metadataPath: /run/corvi/policies/privacy/policy.json
      expectedModuleSha256: "<shared-wasm-module-sha256>"
    abi: corvi-policy-v1
```

If the cluster does not support this image volume format, an explicit configuration option switches to **Corvi's native `-wasm` OCI pull/cache**, with separately supplied registry credentials. Do not silently fall back after a failed Pod mount or substitute the wrong format's digest. The operator does not participate in policy evaluation. Kubernetes CSI certificates remain for gRPC mTLS, not policy execution.

Cache invalidation uses manifest digest, input schema/ABI, policy revision, message/classification revision and credential scope. A tag move must not silently change running policy behavior. A newly requested digest is validated and atomically activated; a missing/broken image never becomes an empty permit-all policy.

The OCI provider **service** plugin images from ADR-0001 are a different class of deployment: the operator starts those as separate gRPC processes. A Corvi policy OCI **WASM image** is a loadable in-process code artifact, **not** a Deployment.

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
11. OCI policy images with wrong media types, changed tags, incorrect digests, invalid signatures, excessive layers or corrupted cached content are rejected; valid pinned cached modules remain usable offline.
12. Policy rollout never activates a snapshot that refers to a required OCI module which failed fetching or validation.
13. OPA/Rego WASM bundles require their explicit adapter and cannot be loaded as Corvi WIT components by accident.
14. Release CI rejects native/volume image pairs with different WASM content or ABI; the image-volume source validates its mounted WASM hash against the expected release digest.

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
- Versioned WIT policy schema, guest SDKs, signature/attestation trust policy and OCI image publishing toolchain.
- Exact Wasmtime fuel/memory/time budgets per action and the extent of allowed host functionality.
- Registry auth formats, offline OCI cache provisioning, signature verification provider, and admission policy for non-digest-pinned tags.
- Signing and release attestation format tying both OCI image digests to one WASM module digest; supported image-volume runtime/platform matrix.
- OPA-WASM adapter lifecycle and upstream builtins compatibility.
- PDP outage policy for in-flight paginated requests and streaming responses.
- Cache/plan integration for expensive searchable-mail listings and query-based authorization.
- Secure distribution of PDP policy revisions and detection of drift between configured policies and engine state.

## Consequences

Corvi can run sandboxed WASM policy code in-process from either of two separately tagged OCI packages: native WASM OCI or Kubernetes image-volume OCI. It also integrates with external gRPC authorization systems while retaining a minimal single-container IMAP/SMTP deployment. The data plane remains the authority that **enforces** identity isolation and safe content projections. WASM and external PDPs are optional tools for expressing decisions, not a route around the privacy guarantees established by ADR-0003.
