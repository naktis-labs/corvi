# ADR-0014: App-credential Secret publication and resolved connection bundles

- **Status:** Proposed, not implemented
- **Date:** 2026-11-16
- **Scope:** Credential-producing Kubernetes resources, custom generated Secret names/annotations, portable protocol-specific connection material
- **Related:** [ADR-0001](0001-corvi-system-architecture.md), [ADR-0005](0005-public-mail-api.md), [ADR-0008](0008-interactive-upstream-oauth.md), [ADR-0009](0009-corvi-oauth-and-identity-grants.md), [ADR-0010](0010-storage-and-durability.md), [ADR-0011](0011-hardened-helm-deployment.md), [ADR-0013](0013-mail-resource-ownership-graph.md)
- **Design schema:** [Connection Secret schema](../../api/generated-connection-secret.schema.json)
- **Example:** [Credential-to-Secret examples](../../deploy/examples/generated-connection-secrets.example.yaml)

## Decision

**Any Corvi resource that *issues* an app token or application credential SHALL support an operator-controlled Kubernetes Secret output with a user-chosen name and custom annotations.** The output MUST be **directly usable**: it contains protocol endpoints, transport/TLS details, the correct credential and authentication mechanism, and effective capabilities for the specific target and routing mode, instead of only an opaque token with no connection information.

Use a common optional resource field:

```yaml
spec:
  secretTemplate:
    metadata:
      name: notifications-mail
      annotations:
        reloader.stakater.com/match: "true"
```

`secretTemplate.metadata.name` may be omitted: the reconciler deterministically generates a DNS-compliant name scoped to the credential resource. `metadata.annotations` is an arbitrary string map **subject to security/admission policy**, with bounded size and reserved `corvi.naktis.eu/*` controller annotations disallowed in user input. The user **cannot** set `Secret.data`, `type`, `ownerReferences`, `immutable`, `namespace`, service-account-token annotations or controller-owned identity/rotation metadata through this template. A Secret is always created in the producing resource's namespace, never an arbitrary destination namespace.

In v1alpha1 the contract applies to **`MailCredential` (gateway-issued app credentials)** and to **provider-backed app-token/credential issuance resources** where the provider management API advertises this capability (e.g., a dedicated mailbox app-credential resource or explicitly modeled mailbox app-token subresource). Do not assume every `Mailbox` or `MailProvider` can issue tokens. The *same Secret template and connection document schema* is reused by every supported credential producer. Where a single `MailCredential` requests portable auto routing, **direct mode is restricted to a single identity/physical mailbox with a demonstrably equivalent upstream permission boundary**; multi-identity gateway OAuth grants must not be silently translated into a broad upstream app password.

`MailCredential` remains a Corvi grant/credential resource, **not** the provider's OAuth refresh-token vault. If a provider-management app-token resource is implemented separately, it may reuse the publication contract without reclassifying an upstream app password as a Corvi OAuth access token. Both paths use the same secure Secret output abstraction but keep independent credential issuance/authorization.

## 1. Routing and target resolution

**`connection.strategy: auto` is the normal and preferred behavior.** Determine the active connection target from the authoritative graph `MailIdentity.mailboxRef → Mailbox.providerRef → MailProvider.gatewayRef?` (ADR-0013):

| Provider/gateway state | Issued credential and published endpoints |
| --- | --- |
| Provider **has no** `spec.gatewayRef` | **Direct provider** connection only when the provider can issue an independent app-scoped credential and publish validated IMAP/SMTP/JMAP or provider-supported protocol endpoints |
| Provider has a valid `gatewayRef` and gateway mail service is **enabled** | **Corvi gateway** connection: Corvi-audience, scoped, per-identity OAuth Client Credentials (when supported) for REST/MCP and/or separately issued SMTP AUTH credential, with externally reachable Corvi endpoints |
| Provider has `gatewayRef` but gateway is **suspended, not Ready, missing or unresolved** | **Unavailable/Pending**. Do **not** switch to direct provider access, export provider refresh tokens, or issue an unscoped app password as fallback |
| Explicit `gatewayRef` changes, appears or disappears | **Security-sensitive routing change**: revoke/deactivate old published capability before reissuing an appropriately scoped credential for the new target and updating the Secret |

A `CorviGateway.spec.suspended: true` is an intentional mail-serving pause, **not** permission to bypass gateway policy. The user may deliberately detach `MailProvider.spec.gatewayRef` to enter direct mode, but this is an audited change and requires grant/policy revalidation. Do not publish an inaccessible `*.svc` address as the only endpoint for an app expected to run outside the cluster; gateway publication metadata must specify a verified **client-reachable** URL/hostname and scheme, separately from the internal Service address. Use only configured/observed Gateway API routing/approved service exposure; don't fabricate a DNS name from an ingress class or merely from `metadata.name`.

**No automatic privilege expansion:** Corvi might hide messages and limit sending by virtual `MailIdentity`; a provider app password often covers the **entire physical Mailbox**. Direct mode MUST prove the provider-issued token enforces the same read/sender/recipient restrictions or a specifically approved, independently isolated physical mailbox. If this cannot be guaranteed, mark `UnsupportedIsolation` and **do not generate the direct Secret**. An app token for one MailIdentity cannot turn into a broadly usable raw mailbox password because a gateway was detached. Do not transform Corvi client bearer tokens into upstream provider tokens or expose Corvi's internally held upstream OAuth refresh tokens.

Provider capabilities and exact protocol auth (IMAP/SMTP app password, OAuth SASL, JMAP Bearer, etc.) are independently verified. For providers with **no supported token-issuance API**, report `UnsupportedCapability` rather than generating an invalid credential or reusing the provider-admin credential. Read/send may require **separate** credentials, protocols, scopes and endpoints; never pretend a provider-issued token is valid for an unsupported service. Similarly, Corvi REST/MCP OAuth credentials are **not** SMTP AUTH credentials unless a dedicated SMTP OAuth profile is explicitly implemented.

## 2. Secret content and a canonical portable contract

The generated Kubernetes Secret is `type: Opaque` and MUST contain **`data["connection.json"]`**, UTF-8 JSON in a Secret data key, encoding a versioned connection document, e.g.:

```json
{
  "version": "corvi.naktis.eu/connection/v1",
  "mode": "gateway",
  "revision": "example-revision",
  "grants": [
    {
      "identity": {"id": "notifications", "address": "alerts@example.test"},
      "actions": ["mail:messages:send"]
    }
  ],
  "services": {
    "rest": {"url": "https://mail.example.test/v1"},
    "mcp": {"url": "https://mail.example.test/mcp"}
  },
  "auth": {
    "oauth": {
      "type": "oauth2_client_credentials",
      "tokenUrl": "https://auth.example.test/oauth/token",
      "clientId": "example-client",
      "clientSecret": "<secret-in-kubernetes-secret-only>",
      "resource": "https://mail.example.test",
      "scopes": ["mail:messages:send"]
    }
  }
}
```

**Illustrative endpoints and placeholder values only**, not deployed Corvi hostnames. In direct mode the document instead carries only supported `imap`, `smtp` and/or `jmap` services, with verified hostnames, ports, TLS modes, SNI/certificate trust requirements, upstream username/account selector, and **service-specific** `app_password`/`api_token` (or provider-supported self-contained OAuth client credentials). Where JMAP is supported, include its Session URL and authenticated JMAP account selection, not a fictional SMTP endpoint. Include provider endpoint provenance/transport generation and optional expiry/rotation timestamps as appropriate. Never serialize a token that has already expired or cannot be renewed safely.

A gateway connection may grant **multiple identities**, and the bundle must keep `grants[]` separate by identity, **not union actions** across mailboxes. Provider-direct connections advertise **exactly one** approved identity and its scoped `capabilities`. The current server-side grant still wins if permissions are later reduced. For direct IMAP/SMTP/JMAP, the actual app credential must be provider-issued and valid for the listed service (not a Corvi token).

The document must be self-contained for a client capable of the listed protocol. Required information per case:

| Connection | Mandatory fields when applicable |
| --- | --- |
| Gateway REST/MCP | externally reachable `services.rest.url`, `services.mcp.url` only if enabled; exact OAuth `tokenUrl` (and issuer/discovery URI if needed), `clientId`, protected client credential/approved auth method, `resource` audience, scopes and **per-identity `grants[]` with independent action sets** |
| Gateway SMTP AUTH | hostname/port, STARTTLS or implicit TLS, trusted server name, **distinct** SMTP username/password or explicitly supported Corvi SASL token profile; sender address and allowed actions |
| Direct IMAP | verified host/port/TLS/serverName, username/mailbox identifier and app-token authentication mechanism |
| Direct SMTP | verified host/port/TLS/serverName, username and app-token authentication mechanism, sender/envelope restrictions |
| Direct JMAP | HTTPS Session URL and account selection, bearer/API token and relevant JMAP read/submission capability, verified HTTPS trust |
| Any connection | schema version, `mode`, identity/address association, action capabilities, generated credential revision; no unadvertised protocols |

**Use `Secret.data`, not plaintext GitOps `stringData` values** for reconciled output. `connection.json` is itself **sensitive** even though the Kubernetes API base64-encodes it. The operator may optionally publish **stable convenience data keys** (e.g. `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `IMAP_HOST`, `IMAP_USERNAME`, `IMAP_PASSWORD`, `CORVI_API_URL`, `CORVI_MCP_URL`, `OAUTH_TOKEN_URL`, `OAUTH_CLIENT_ID`, `OAUTH_CLIENT_SECRET`) for compatible consumers; never populate keys for unsupported protocols, and treat any duplicated credentials as secrets. **Canonical `connection.json` remains the source of truth**, and convenience key names are versioned. Clients that need only one key can mount it with `secretKeyRef`, and full clients can mount the connection document without visiting a separate config resource.

Never place passwords, bearer tokens, refresh tokens, authorization codes, password-bearing URLs, or secret JSON in annotations, labels, owner references, CRD spec/status, ConfigMaps, Helm values, admission error messages, events, diffs or audit traces. A Secret may include harmless routing/status annotations such as version and owner UID, but not credentials.

## 3. Lifecycle, rotation and collision safety

- **Ownership:** Generated Secret `metadata.namespace` equals the issuing resource namespace; deterministic default name, or explicit `secretTemplate.metadata.name`. Add immutable controller ownership labels/annotations and an ownerReference **only to the exact token-producing resource**, never its parent provider, mailbox, identity or gateway. Credentials and their Secrets have lifecycle relationships, but deleting a gateway must not cascade-delete independently issued provider credentials.
- **No takeover:** An existing Secret with the chosen name is **not** automatically adopted or overwritten, even if its labels look similar. Only mutate a Secret already proven to belong to this exact credential UID using its ownerReference and verified controller metadata. Otherwise `SecretNameConflict` and no credential disclosure. A Secret controlled by another manager or user remains untouched.
- **Name/annotation changes:** Reconcile desired metadata with Kubernetes optimistic concurrency and server-side apply. Preserve **operator-owned** Secret keys/labels, reject user annotation keys reserved by `corvi.naktis.eu/`, service-account-token annotations and security-sensitive third-party annotation controllers where policy forbids them. Changing Secret name requires a controlled **reissue/cutover** and cleanup/revocation; never leave the old Secret as a valid unnoticed credential.
- **First issuance:** Generate/obtain an app credential only once per intended grant/target revision and stage it securely. Never generate a second one merely because a Secret `create`/update had a conflict or an operator restarted. Use a durable protected issuance journal/secret custody mechanism and idempotency/lookup where the provider supports it. For providers that reveal token material only once, first persist it in a protected handoff staging store and only then publish the Secret. If publication fails, report and retry safely; never leak the only token in logs or CRD status.
- **Rotation:** Resolve current target/capabilities and form the **complete** Secret contents for that target. Atomic Kubernetes Secret update of `data` replaces old protocol keys (rather than merge), increments an opaque connection revision, and notifies consumers via ordinary Kubernetes change semantics. Old credential revocation and Secret publication must follow a **fail-closed transition protocol** with no old gateway/direct bypass; manage cache/propagation delays and don't claim instant container-env reload. If a consumer reads Secret keys via environment variables, it must restart to see updates; projected volume refresh is eventual and applications must reload.
- **Detachment/rebinding:** Before switching gateway/direct or moving providers, withdraw old routing and tokens from the effective authorization/snapshots. **Do not silently preserve upstream token material** in a gateway Secret or publish gateway credentials in direct provider mode. A previously consented gateway OAuth grant is not authority for a provider-wide app token. If safe rotation/revocation cannot be proven, mark `MigrationPending` / `ReauthorizationRequired` and keep Secret unready/unavailable, rather than publishing a misleading connection.
- **Deletion:** On credential resource deletion, revoke its issued app token **when the issuer supports revocation**, clear the generated Secret after safe finalizer processing, and retain unrelated provider resources, existing mailbox contents, user-created Secrets and OAuth grants belonging to other credentials. Report provider-side revoke failure without claiming external revocation succeeded.
- **Status:** `status.secretRef.name` (safe, no value), `status.connectionMode` (`Gateway`, `ProviderDirect`, `Unavailable`), `status.credentialRevision`, `status.observedGeneration`, `status.conditions` (`Ready`, `Issued`, `Published`, `RotationPending`) with safe reasons (`UnsupportedCapability`, `UnsupportedIsolation`, `SecretNameConflict`, `EndpointUnavailable`, `GatewaySuspended`, `ReauthorizationRequired`, etc.). Status must not contain token hashes, raw endpoints with userinfo, or secret contents.

**Annotations can trigger external Secret copying/sync controllers.** The requested custom annotations are not inherently safe: user/config policy must allow the intended keys/values, enforce namespace controls and block accidental cross-namespace credential replication (or require a separate privileged approval). Provide an explicit allowed-annotation policy; do not assume that arbitrary annotations are passive metadata.

## 4. Kubernetes RBAC, Secret publisher and control-plane boundaries

The mail gateway, OAuth resource server, provider gRPC plugin, bridge and mail client Pods **retain `automountServiceAccountToken: false` and no Kubernetes Secret API rights**. A credential producer that must write generated Secrets needs API permissions, so use a **dedicated `corvi-credential-publisher` controller or an explicitly enabled, scoped role on the operator**. The default operator Role may remain Secret-write-free when no generated Secrets are requested.

- Read/watch token-producing CRDs and necessary non-secret parent references. For generated Secrets, use `get`, `create`, `patch`, `update`, `delete` as needed, **no `list/watch secrets` by default**. `create` cannot be limited by Kubernetes RBAC `resourceNames`; `delete` can be narrowed to known names only when feasible. Avoid wildcard resources, token creation, RBAC mutation and cross-namespace Secret writes. Isolate publisher namespaces or use an independently administered validating admission policy that verifies the controller identity, generated Secret naming/owner UID and allowed data/annotations. RBAC alone cannot force `Secret.create` to target a matching resource.
- Keep token-issuing RPCs authenticated and narrowly authorized. Provider plugins return one-time secret material through a bounded, mTLS protected **secret-handoff** channel, never standard `TransportResolver` responses. For Corvi OAuth Client Credentials, issuer registers an explicitly scoped confidential client and the publisher receives only the specific client credential needed for this generated Secret, not its token-signing key or unrelated refresh tokens.
- The publisher temporarily handles sensitive app credential material and is therefore a higher-trust workload. Rootless UID/GID, drop `ALL` capabilities, `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, `RuntimeDefault` seccomp, bounded memory and network egress, and one scoped API token. Protect against log/trace/export leaks and prevent reading arbitrary upstream mail or OAuth signing keys. Do not mount the operator's broader API token into the plugin.
- Kubernetes **control plane uses CRDs and Secret objects**, not an added PostgreSQL/Redis database for generated Secret status. A recoverable staging mechanism for one-time issued token material may be an encrypted existing Secret/approved external vault plus an idempotent issuance record, but must not be embedded in resource status or shared broadly. Retain Kubernetes at-rest encryption, etcd audit/backup security and scoped Secret consumers.

## 5. Acceptance tests

1. A `MailCredential` (or supported provider app-token resource) with `secretTemplate.metadata.name` and custom safe annotations produces a same-namespace, owned Secret; missing name produces a stable deterministic name. Invalid/unsafe annotation policy is rejected.
2. The decoded `connection.json` has every endpoint, port, TLS requirement, username/account selector, credential, authentication mode, effective action and grant/audience detail needed for **each actually supported** published protocol. Unusable/made-up endpoints and unsupported service entries are absent.
3. An attached, ready gateway produces Corvi REST/MCP credentials and endpoints, not exposed upstream provider OAuth refresh tokens or unfiltered IMAP password. A provider with no gatewayRef produces provider-direct credentials and verified direct endpoints **only if supported**.
4. An attached but suspended/unready/nonexistent gateway never falls back to direct provider credentials. Omitted gatewayRef is **direct mode**, not an invalid parent; explicit invalid gatewayRef is not direct mode.
5. Direct mode for a virtual/filter-restricted identity, provider without app-token issuance, or unsupported authentication mechanism fails closed with a precise reason rather than exporting a broad mailbox password or pretending the token can authenticate through OAuth.
6. A multi-identity `MailCredential` works with an authorized gateway and matching audience; it cannot automatically produce a direct provider credential spanning unrelated mailboxes/providers.
7. Renaming an output Secret, reparenting a mailbox, changing gatewayRef, rotating tokens or changing endpoint URLs cannot leak stale credentials, retain obsolete protocol keys or expand OAuth grants without explicit authorization.
8. Resource status/metadata/CRDs, Helm history, logs/events/metrics, and gateway snapshots expose **zero** plaintext credential material, even for one-time provider tokens.
9. An existing unrelated Secret with the requested name is not adopted/overwritten. Reconciler restart after a one-time token issue but before Secret publication recovers safely or fails closed without losing or logging the token.
10. Secret publication functionality does not require adding API tokens or Secret RBAC to mail gateways, OAuth runtime, provider plugins or bridge Pods; only a narrowly scoped publisher/operator identity has bounded Secret write authority.
11. Kubernetes Secret volume/env consumers can reconstruct usable settings from a single Secret. Updating projected Secret data or restarting env-based consumers follows documented Kubernetes semantics.
12. Deleting a gateway or unbinding a provider never unintentionally deletes unrelated upstream resources, owner OAuth grants or provider admin credentials. Credential deletion handles app-token revoke and its own generated Secret.

## Consequences

Portable app credentials become directly consumable from **one generated Kubernetes Secret** in either Corvi-gateway or direct-provider mode, with customizable metadata, and without coupling the control plane to a live gateway. This adds a security-sensitive credential-publication controller, provider-capability negotiation, endpoint-validation and no-bypass migration discipline. **The CRD/resource schema and controller are proposals; none of the Secret issuance/publishing flows is implemented yet.**
