# ADR-0006: Provider-managed local mail transport bridges

- **Status:** Proposed
- **Date:** 2026-11-16
- **Scope:** Mail providers requiring a local application/proxy to expose an IMAP/SMTP-compatible transport
- **Related:** [ADR-0001: Corvi system architecture](0001-corvi-system-architecture.md), [ADR-0005: Public mail API](0005-public-mail-api.md)
- **Example:** Proton Mail with Proton Mail Bridge (a compatibility target, **not** a claim of working headless/Kubernetes support)

## Context

Corvi's gateway uses built-in Rust IMAP and SMTP clients and receives resolved transport settings from trusted configuration. Some providers cannot be accessed using conventional direct network IMAP/SMTP endpoints. Proton Mail Bridge, for example, runs a **local IMAP/SMTP server** and performs Proton Mail encryption/decryption on the client-side host. It normally exposes services only to clients on the same device, needs persistent account/session state, and uses OS keyring-like facilities. A generic direct-provider assumption would make these accounts inaccessible without undocumented sidecars or manual topology work.

**Decision:** Treat a **local transport bridge** as a first-class, optional provider transport dependency, distinct from both (1) the **provider gRPC adapter/plugin** that discovers/configures a service and (2) the Corvi **gateway's own IMAP/SMTP clients**. Bridge-backed transport must not add an obligatory provider-specific mail protocol implementation to the gateway.

## 1. Transport topology classification

Each MailProvider/Mailbox resolution explicitly declares a transport topology:

| Topology | Meaning | Gateway configuration |
| --- | --- | --- |
| `direct` | An upstream IMAP/SMTP server is reachable directly | Verified upstream endpoints and scoped credentials |
| `existingBridge` | A separately installed bridge is already reachable in the gateway's authorized execution/network context | Explicitly configured approved local endpoint(s), bridge identity/certificate and secret references |
| `managedBridge` | A provider OCI plugin declares and a trusted deployment controller provisions a supported bridge runtime | Validated bridge lifecycle/attachment, resulting local endpoint(s) and secret references |

These are deployment/transport choices, **not different mail access APIs**. A bridge-backed physical Mailbox supports the same `MailIdentity`, per-identity permissions, safe message projections, REST/MCP tools, SMTP sender enforcement and isolation rules as a direct mailbox. One client token can span a direct mailbox and bridge-backed mailboxes without knowing the difference; explicit `identityId` still selects a single authorized view.

**Distinction from native JMAP:** This ADR's `direct`/`existingBridge`/`managedBridge` classifications describe **IMAP/SMTP connectivity topologies**. Native JMAP is a separate **upstream protocol** (RFC 8620/8621) implemented in Corvi itself and normally connected directly via authenticated HTTPS, with no bridge dependency. Read and submission protocols are independently selected. See [ADR-0007](0007-native-jmap-transport.md) and [the provider-neutral transport schema](../../api/mail-transport.schema.json); do not attempt to deploy a local bridge simply because the provider advertises JMAP.

Provider plugins can be **transport-only**, and the bridge requirement does **not** imply the provider supports administration of remote domains, mailboxes, aliases or quotas. Unsupported administrative operations must be reported as unsupported.

## 2. OCI metadata-assisted discovery

OCI metadata is a **fast hint for the deployment controller**, not a trusted source of authorization, credentials or executable behavior. Support a versioned Corvi annotation namespace on **provider plugin OCI image manifests** (and the selected platform-specific manifest or index where appropriate); do **not** overload the OCI/Wasm policy module annotations from ADR-0004.

Example proposed plugin annotations:

```yaml
annotations:
  eu.naktis.corvi.provider.metadata-version: "v1"
  eu.naktis.corvi.provider.transport-topology: "local-bridge"
  eu.naktis.corvi.provider.bridge-mode: "required"
  eu.naktis.corvi.provider.discovery-protocol: "corvi.provider.v1"
```

The annotations convey **that** an adapter requires an ancillary bridge, not its unrestricted execution plan. They comply with OCI's ordinary namespaced string-key/string-value annotation format. The canonical Corvi namespace is rooted at `corvi.naktis.eu`, so reverse-DNS OCI annotation keys use the `eu.naktis.corvi.*` prefix. Specific key names and their schemas remain provisional until the implementation contract is published.

Discovery flow:

1. The operator/standalone controller retrieves the **digest-pinned, allowlisted provider plugin image** manifest and selected platform metadata from its registry, verifying content digests and configured publisher signatures/attestations. Manifest annotations and optional OCI config labels can be inspected **before** launching the plugin. Missing/unknown metadata is reported as `discoveryRequired`, not assumed to mean a direct transport.
2. Validate a **versioned, typed bridge dependency descriptor** referenced by the vetted plugin or supplied by an administrator (example below). The descriptor must be bound to the digest of the inspected plugin release or separately verified as a trusted artifact; untrusted plugin data can request, **but cannot authorize**, running another container.
3. Start the plugin through the existing authorized deployment path; call `ProviderDiscovery.GetCapabilities` over authenticated mTLS. Compare the advertised transport type, required bridge runtime, supported auth, initialization/status and constraints with the pre-deployment metadata. Reject unrecognized major versions, contradictory classifications, invalid image references, or unsupported runtime requirements.
4. Resolve the actual bridge endpoints **only after** the trusted bridge is running, authenticated and ready. `TransportResolver.ResolveMailbox` produces normalized IMAP/SMTP descriptors and **trusted, allowlisted** secret references for the gateway's immutable configuration snapshot.
5. The gateway connects to the resolved endpoints directly using its generic clients. There is **no provider/plugin RPC on the data-plane message hot path**. If the bridge itself is down, relevant mailbox operations fail with an upstream/bridge unavailable status; do not imply that stopping the provider controller will stop an already healthy bridge.

The operator may pre-fetch OCI metadata without running the provider plugin, but initial metadata **must not** be relied on as the sole runtime capability negotiation. OCI labels, manifest annotations and descriptor fields are untrusted external data until validated against **local administrator policy**. An OCI manifest digest proves content identity, not permission or publisher authenticity.

## 3. Typed bridge dependency descriptor (proposed)

The provider-plugin capability schema and operator reconciliation model are extended with an **optional bridge dependency**. Provisional example, intentionally independent of Kubernetes Pod types:

```yaml
apiVersion: corvi.naktis.eu/v1alpha1
kind: ProviderTransportDependency
transport:
  topology: localBridge
  protocols: [imap, smtp]
  runtime:
    mode: managed
    image: ghcr.io/naktis-labs/corvi-proton-bridge@sha256:<trusted-digest>
    placement: colocatedNetworkNamespace
    state:
      persistent: true
      accountScope: perPhysicalMailbox
    endpoint:
      exposure: loopbackOnly
      imap: { host: "127.0.0.1", portRef: imap }
      smtp: { host: "127.0.0.1", portRef: smtp }
    readiness: { type: protocolHandshake }
  onboarding:
    method: interactiveOrPreprovisioned
    automationSupported: unknown
  secretInputs:
    - name: accountSession
      class: bridgeSession
  tls:
    peerVerification: pinnedCertificateOrTrustedCA
```

The example image/repository and fields are **illustrative**, not a published official Proton Bridge container or a usable deployment. Do not assume upstream has an official unattended, headless image. The bridge descriptor may be a typed protobuf message from discovery, backed by verified OCI data for pre-run inspection; its final protobuf and CRD schemas are a separate implementation deliverable.

A proposed [JSON Schema for this dependency descriptor](../../api/provider-transport-bridge.schema.json) is included for schema-driven validation and future code generation. It captures required fields and basic managed-vs-existing constraints, but **passing the schema does not authorize runtime execution**, credential access or endpoints; the administrator-approved install and transport trust checks above are still mandatory.

Rules:

- **No arbitrary execution by OCI annotation.** The controller must apply an explicit install policy (approved repository/digest or trusted signature identity, allowed platform and executable, bounded resources, allowed network, Pod security policy and consent to any requested secret). It must not accept unqualified `latest` references or arbitrarily supplied host paths, extra containers, environment variables containing credentials, network exposure, privileged security contexts or extra Kubernetes permissions.
- **Separate credential classes.** Provider administrative API tokens, upstream OAuth access/refresh tokens, upstream account onboarding/session state, bridge-generated IMAP/SMTP credentials, Corvi public API credentials, and gRPC mTLS identities remain distinct. Never embed passwords/session tokens in OCI annotations, image layers, config snapshots, status, logs or metrics.
- **Mandatory managed-Pod hardening.** Every operator-managed bridge **must run as an explicitly non-root numeric UID/GID, with all Linux capabilities dropped, privilege escalation disabled, `seccompProfile: RuntimeDefault`, `readOnlyRootFilesystem: true`, no Kubernetes API token, bounded resources, immutable bridge image digest, and only the necessary writable state and read-only secret mounts**. Reject unsupported images; do not silently run managed bridges as root. An independently operated existing bridge outside Kubernetes has its own documented trust boundary. See [ADR-0011](0011-hardened-helm-deployment.md).
- **No implicit exposure.** A `loopbackOnly` bridge never becomes a routable Kubernetes Service, hostPort, NodePort, ingress or public listener merely because its plugin advertises IMAP/SMTP. Endpoint topology must pass the operator's security policy.
- **State/compatibility.** The descriptor states persistent-state needs, initialization/onboarding mode, platform support, readiness mechanism, credential rotation/recovery capabilities, network placement and per-account concurrency limits. Unsupported requirements fail reconciliation with an actionable status, rather than silently being ignored.
- **Identity isolation.** A bridge may serve multiple physical accounts or addresses, but any mailbox grouping and verified recipient provenance must still satisfy ADR-0001. Bridge-emitted message headers alone are not trusted original-delivery provenance by default.

## 4. Deployment and lifecycle

### Standalone gateway, no Kubernetes

Support either (a) explicit `existingBridge` connection to a verified **locally reachable** IMAP/SMTP bridge, or (b) an **optional** standalone controller/launcher that understands the same validated dependency descriptor and manages the bridge lifecycle. A gateway with only a config file can use the existing bridge with **no provider plugin or operator**, subject to local connectivity and safe TLS configuration.

A local bridge is not mandatory for the generic IMAP/SMTP installation. Standalone mode must never be forced to run Kubernetes or a provider plugin to connect to a pre-existing bridge.

### Kubernetes operator

The operator can provision a digest-pinned bridge runtime when a `MailProvider`/Mailbox explicitly opts into managed bridge deployment and **rootless, capability-free, readonly, RuntimeDefault, API-token-free** trust/admission checks pass (ADR-0011):

- **Preferred for loopback-only bridges:** Run the bridge in the **same Pod/network namespace** as the gateway process that connects to it (sidecar or equivalent colocated runtime). A Kubernetes Service to a separate bridge Pod is **not equivalent to localhost**.
- Use a persistent state volume and tightly scoped secret mounts where supported. Support readiness gates, account enrollment/init Jobs only with explicit user-approved provisioning, bridge health, restart/recovery/backoff and upgrade/rollback.
- Do **not** assume that a per-account or GUI-oriented bridge tolerates one writable instance per gateway replica. Coordinate single-owner accounts and storage, or restrict the supported topology to one gateway replica for that mailbox until a safe, tested multi-instance proxy/transport design exists.
- If a provider bridge supports access across a network, that must be an **explicit alternate topology**, with authenticated, verified and encrypted transport and approved exposure; never rewrite a localhost-only endpoint to a Service DNS name or disable TLS peer checking.
- Operator-managed bridge startup is an **infrastructure lifecycle dependency**. Once a bridge is healthy, controller/plugin/Kubernetes API outages do not automatically block the gateway; a bridge outage **does** block mail operations for mailboxes attached to it. Report bridge health separately from provider plugin/control-plane health.
- Do not expose decrypted bridge message content or keys via a management endpoint; the gateway's message classification/filtering rules apply before client-visible data is emitted.

**Headless compatibility is conditional.** Some bridge products require interactive account login, keyrings or unsupported GUI initialization. Do **not** substitute generic interactive provider OAuth onboarding for bridge enrollment unless the provider officially supports it; [ADR-0008](0008-interactive-upstream-oauth.md) treats bridge enrollment as a distinct capability. Corvi must report `needsEnrollment`, `unsupportedHeadless`, `credentialsUnavailable` or `unhealthyBridge` rather than claiming unattended setup works. Where an upstream product offers no supported container/headless mode, a verified manually managed local bridge is an acceptable compatibility path.

### Resolved transport example

An operator or standalone controller publishes a normal mailbox transport snapshot after bridge initialization; example fields:

```yaml
mailboxes:
  - id: proton-personal
    provider: proton
    transport:
      topology: managedBridge
      bridgeInstance: proton-personal-bridge
      imap:
        host: 127.0.0.1
        port: 1143 # illustration only; resolve from bridge configuration
        tls: starttls
        tlsPeer: pinnedBridgeCertificate
        credentialsRef: secret://proton-bridge/imap
      smtp:
        host: 127.0.0.1
        port: 1025 # illustration only; resolve from bridge configuration
        tls: starttls
        tlsPeer: pinnedBridgeCertificate
        credentialsRef: secret://proton-bridge/smtp
```

The example is **not** an assurance that Proton Bridge binds these ports or supports `STARTTLS` in every build. All endpoint details, authentication and trusted TLS material must come from validated bridge provisioning and transport resolution, not hard-coded gateway defaults.

## 5. Security and privacy

**Using a local decrypting bridge changes the trust boundary:** Corvi and the bridge host/process can handle decrypted email. Provider end-to-end/zero-access encryption **does not extend to the Corvi gateway or its scoped clients**. This must be explicit in docs/configuration UX; bridge keys, session state and local transport connections are high-value secrets.

- Only localhost or explicitly authenticated local IPC endpoints are acceptable by default. For local TLS, pin the bridge-issued server certificate or use a configured trusted local CA; never globally disable certificate verification to make a self-signed bridge work. Require TLS for non-loopback endpoints and reject cleartext fallback. If a product only supports a narrower trust mode, specify and approve a narrowly scoped exception before deployment; **never** make it an implicit global security downgrade.
- Restrict bridge process and volume access to the gateway's authorized network namespace, user/Pod and narrowly scoped mounts. Avoid network policies that expose the plaintext local IMAP/SMTP traffic beyond that boundary.
- A provider plugin or its metadata cannot grant access to credentials/keys outside approved secret bindings. Corvi's client tokens never contain bridge secrets.
- Bridge failure and restart do not invalidate identity/scoping rules or permit connections to an unrelated upstream host. Endpoint changes require trusted, atomic config snapshot publication.
- Mail sent via a bridge still passes server-side identity, header From, SMTP envelope sender and recipient policy checks. Do not allow bridge alias behavior to bypass Corvi's `MailIdentity` restrictions.
- Never expose bridge connection credentials, decrypted mail content, account identifiers, keyring material or raw error strings in Kubernetes status, diagnostics or metrics. Mask/hash labels where appropriate.

## 6. Discovery and capability/schema implications

Extend `ProviderDiscovery.GetCapabilities` with a **transport topology capability** and optional bridge dependency descriptor. Extend `TransportResolver.ResolveMailbox` with a validated `topology` and `bridgeInstance`/readiness provenance reference in addition to the existing IMAP/SMTP endpoints.

The operator/standalone controller must be able to compare:

- OCI annotation/descriptor version and selected image digest;
- provider plugin gRPC capability version and bridge requirements;
- operator-approved runtime/profile/trust policy;
- actual bridge readiness, certificate identity, local endpoint addresses and generated credential bindings.

The `MailProvider` CRD needs an **optional** `spec.transportBridge` block for deployment mode (`existing` vs `managed`), approved image digest when managed, trusted init/session state reference, placement policy and secrets, and status conditions (e.g. `BridgeRequired`, `BridgeReady`, `NeedsEnrollment`, `UnsupportedRuntime`, `TransportUnavailable`). `Mailbox` may reference a per-mailbox bridge instance. The provider can advertise a requirement, but the user's **administrator-controlled configuration decides whether to install or attach** the bridge.

Unknown OCI metadata, unsupported descriptor versions, missing mandatory bridge prerequisites or an invalid/trust-mismatched runtime MUST fail the affected provider reconciliation **without silently assuming direct IMAP/SMTP access**. A plugin lacking a bridge dependency is not presumed direct merely because annotations were stripped.

## 7. Tests and acceptance criteria

1. **Generic IMAP/SMTP** still works without OCI plugins, bridges, a controller or Kubernetes.
2. **Existing local bridge** works in standalone mode using verified local endpoints without any provider admin plugin or special gateway protocol client.
3. **Managed bridge** plugin OCI metadata is discoverable before deployment, but images/processes are created only when explicitly authorized by an install/trust policy.
4. Plugin `GetCapabilities` and OCI metadata agree on required bridge topology. Missing/contradictory/unknown discovery information cannot cause unsafe auto-deployment or insecure fallback.
5. The provider transport resolver supplies actual bridged IMAP/SMTP host, ports, TLS peer identity, credential references and bridge readiness; no provider RPC is needed on every message.
6. Loopback-only bridges run in the same network namespace as their consumer, never exposed through a routable Service by default.
7. Bridge state survives permitted restarts; an unsupported concurrent replica configuration is rejected or restricted rather than causing multiple session writers.
8. Bridge outage affects only dependent mailboxes; control-plane/plugin outages alone do not break a still-running bridge.
9. TLS/certificate verification and secret scope remain enforced even when a bridge uses a local self-signed certificate.
10. No permission crossover or message leakage when the **same Corvi token** accesses multiple direct and bridge-backed `MailIdentity` values with different policies.
11. Proton-style manual/keyring onboarding, unsupported containerization or headless-mode limitations are surfaced explicitly and never misrepresented as automatic setup.
12. Classification/redaction, original-recipient provenance, send authorization and no-raw-MIME rules remain consistent across direct and bridged transports.

## 8. References

- [Proton: Why you need Proton Mail Bridge](https://proton.me/support/why-you-need-bridge)
- [Proton: Bridge for Linux](https://proton.me/support/bridge-for-linux)
- [Proton Mail Bridge source](https://github.com/ProtonMail/proton-bridge)
- [OCI image-spec annotations](https://specs.opencontainers.org/image-spec/annotations/?v=v1.1.0)

## Consequences

This makes bridge-dependent providers first-class **without** changing Corvi's provider-neutral mail data plane. The trade-off is explicitly managed proxy state, startup/onboarding dependencies, deployment placement and secrets. OCI metadata enables pre-deployment hints; authenticated gRPC discovery and trusted admin policy determine the actual runtime and endpoints. Supporting an existing bridge does not require Kubernetes or a new controller process.

---
This ADR defines proposed behavior; it does not assert the existence of a functional Proton bridge adapter, official headless image or supported Kubernetes deployment.
