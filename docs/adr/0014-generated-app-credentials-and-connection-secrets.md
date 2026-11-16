# ADR-0014: Typed app credentials and flat-key connection Secrets

- **Status:** Proposed; credential CRDs, issuer integration, Secret publisher and controllers are not implemented
- **Date:** 2026-11-16
- **Scope:** App-credential resources, provider-native issuance, custom Secret names/annotations, explicit MCP/REST/SMTP connection shapes
- **Related:** [ADR-0001](0001-corvi-system-architecture.md), [ADR-0005](0005-public-mail-api.md), [ADR-0008](0008-interactive-upstream-oauth.md), [ADR-0009](0009-corvi-oauth-and-identity-grants.md), [ADR-0010](0010-storage-and-durability.md), [ADR-0011](0011-hardened-helm-deployment.md), [ADR-0013](0013-mail-resource-ownership-graph.md)
- **Design schema:** [Typed credential and Secret-key contract](../../api/generated-connection-secret.schema.json)
- **Examples:** [Credential producers](../../deploy/examples/generated-connection-secrets.example.yaml), [decoded gateway Secret keys](../../api/examples/gateway-connection.example.json), [decoded provider-direct Secret keys](../../api/examples/provider-direct-connection.example.json)

## Decision

Every Corvi resource that **issues an application token or password** supports `spec.secretTemplate.metadata.name` and `spec.secretTemplate.metadata.annotations`. The reconciled Kubernetes `Secret` is `Opaque`, in the same namespace, and has **individually addressable, flat `data` keys** containing *everything needed to connect and authenticate* using **one explicitly declared connection shape**: `mcp`, `rest`, or `smtp`.

**There is no `credentials.json`, `connection.json`, embedded JSON, secret-bundle file, or mandatory connection descriptor key.** No app needs to parse JSON to use the Secret: consumers use `secretKeyRef`, mounted individual keys, or `envFrom` where appropriately trusted. The operator writes encoded values into Kubernetes `Secret.data`; a Secret's base64 is **not encryption**. CRD `spec` and `status` contain *only references and non-sensitive readiness metadata*, never token contents.

**Gateway-scoped and direct-provider credentials are different authority models:**

- **`MailCredential`** issues **Corvi policy-scoped** credentials, bound to exactly one `MailIdentity` and an action set. It **REQUIRES** a valid `MailProvider.spec.gatewayRef` pointing to an active CorviGateway, even if the provider supports direct app passwords. **When gatewayRef is absent, explicitly reject issuance** with `GatewayRequiredForScopedCredential`; do not generate a Secret or try the provider directly. When the gateway is bound but suspended/unready, keep issuance unavailable; **no direct fallback**.
- **`ProviderAppCredential`** requests **provider-native**, independent app-token issuance for a `Mailbox` or (only when supported) a `MailIdentity`. It is valid **only when the provider has no gatewayRef**, and it publishes the provider's verified direct endpoint/auth details. It has no Corvi `permissions`, `identityRefs`, `scopes` or virtual-identity filtering semantics. For a provider with a gatewayRef, reject with `GatewayBoundUseMailCredential`; never leak a direct credential that bypasses the gateway. These kinds may share one Secret-output implementation, but **must not silently convert between issuance modes**.

The implied routing rule is therefore: **bound provider → Corvi gateway credential and endpoint; unbound provider → independently issued provider-native app credential and endpoint, but never a Corvi-scoped credential.** A provider management resource may exist without either credential producer. Attachment, detachment or changes of target require explicit issuance/re-authorization and revocation, not opportunistic privilege expansion.

## 1. Declarative resource shapes

```yaml
apiVersion: corvi.naktis.eu/v1alpha1
kind: MailCredential
metadata:
  name: notifications-mcp
  namespace: corvi-system
spec:
  shape: mcp                   # explicitly one of: mcp | rest | smtp
  identityRef:
    name: notifications
  permissions:                 # Corvi grant, enforced by bound gateway
    - mail:messages:list
    - mail:messages:send
  secretTemplate:
    metadata:
      name: notifications-mcp-connection
      annotations:
        example.com/application: notifications
```

```yaml
apiVersion: corvi.naktis.eu/v1alpha1
kind: ProviderAppCredential
metadata:
  name: alerts-direct-smtp
  namespace: corvi-system
spec:
  shape: smtp
  targetRef:
    kind: Mailbox             # OR MailIdentity, if provider explicitly supports it
    name: alerts
  secretTemplate:
    metadata:
      name: alerts-direct-smtp
      annotations:
        example.com/application: alerts
```

Both kinds expose **exactly one shape**, and each resource generates **exactly one Secret**. For MCP + REST + SMTP output, create separately authorized credential resources/Secrets; a gateway OAuth client MAY internally reuse a grant only if the issuer explicitly supports it, but generated outputs still have one deterministic shape. A single generated app Secret is bound to one identity/mailbox and cannot flatten multiple identity-specific policies into an ambiguous list. Corvi's **interactive** OAuth grants may still span several identities (ADR-0009); that is a separate authorization flow.

The `secretTemplate` is optional. Without an explicit name, derive a deterministic DNS-safe Secret name from the issuing resource (and avoid cross-kind collisions). Only `metadata.name` and `metadata.annotations` are user-configurable in this template; keys/values have bounded lengths and an independently reviewed annotation allow-policy. The Secret's namespace is always the producer namespace. Reject attempts to control `Secret.data`, `stringData`, `type`, `immutable`, `ownerReferences`, `namespace`, labels used for controller authorization, service-account-token annotations or reserved `corvi.naktis.eu/*` metadata. User annotations can cause third-party controllers to replicate Secrets; prohibit unsafe replication/cross-namespace sync without explicit administrative authorization.

## 2. Provider capability and credential granularity

The provider's **actual API/protocol capabilities** determine whether direct application credentials can be issued and how narrowly the provider itself enforces them:

| Provider capability | Requested `ProviderAppCredential.targetRef` | Result |
| --- | --- | --- |
| Native **per-identity** app tokens | `kind: MailIdentity` | Supported only when the provider guarantees the token cannot access sibling identities or additional mailbox contents; advertise `providerIdentity` granularity |
| Native **per-mailbox** app tokens | `kind: Mailbox` | Supported; advertise `providerMailbox` granularity and the **entire physical mailbox** authority |
| Provider only supports mailbox-wide tokens | `kind: MailIdentity` | **Reject `UnsupportedCredentialGranularity`**; never represent mailbox-wide access as identity-scoped |
| Provider has no independent app-credential issuance API | Either kind | **Reject `UnsupportedCredentialIssuance`**; don't reuse admin passwords, upstream OAuth refresh/access tokens or create fictional tokens |
| Provider supports issuance but not requested shape `mcp`/`rest`/`smtp` | Either kind | **Reject `UnsupportedCredentialShape`**; don't mislabel IMAP/JMAP/management APIs as REST/MCP |

Provider plugins should advertise typed capabilities `appCredentials.shapes[]` and `appCredentials.granularities[]` (e.g., `providerIdentity`, `providerMailbox`), plus per-shape authentication and revocation support. Discovery hints are **not authorization**: the issuer must verify provider support, identity/mailbox ownership, acceptable sender/read boundaries, credential independence and the actual returned transport endpoint before publication. Upstream provider credentials are never Corvi-scoped credentials. In particular, a provider-wide management API token cannot be relabeled as an app token and sent to an application.

One provider may support both granularities or only one. Do not pretend that arbitrary virtual identity filtering, attachment redaction or recipient/send policies can be enforced by a direct mailbox-wide credential. If the requested target implies restrictions the provider cannot enforce, reject; a caller that explicitly targets an entire `Mailbox` is requesting that provider-native mailbox authority, subject to independent administrative approval, not a Corvi MailIdentity scope.

**Direct provider `mcp` or `rest` requires a real corresponding provider endpoint and independently issued app auth for that service.** SMTP direct mode requires a verified SMTP submission endpoint. A JMAP HTTPS Session API is **not automatically REST-shaped**, an IMAP endpoint is not REST/MCP, and a provider's administrator API must not become an application mail credential. Additional protocol shapes (e.g. `imap`, `jmap`) require a future explicit versioned extension rather than guessing.

## 3. Required flat Secret keys

All keys are **individual UTF-8 string values in `Secret.data`**. No nested serialized objects, arrays, blobs, credentials.json or connection.json. The exact allowed/required key sets are described in the [JSON Schema design contract](../../api/generated-connection-secret.schema.json); the following table is normative for v1alpha1.

| Output shape | Mandatory connection/auth keys |
| --- | --- |
| **All** | `CONNECTION_SHAPE` (`mcp`/`rest`/`smtp`), `CONNECTION_MODE` (`gateway`/`providerDirect`), `AUTH_TYPE`, `CREDENTIAL_GRANULARITY` (`corviIdentity`/`providerIdentity`/`providerMailbox`), `PROVIDER_NAME`, `CREDENTIAL_REVISION`, and **`IDENTITY_NAME`** or **`MAILBOX_NAME`** according to granularity |
| **MCP** | `MCP_URL` (actual HTTPS Streamable HTTP MCP endpoint), plus the applicable auth keys below |
| **REST** | `REST_URL` (actual HTTPS API base URL), plus the applicable auth keys below |
| **Gateway MCP/REST OAuth client credentials** | `OAUTH_TOKEN_URL`, `OAUTH_CLIENT_ID`, `OAUTH_CLIENT_SECRET`, `OAUTH_RESOURCE`, `OAUTH_SCOPES` (space-separated), `AUTH_TYPE=oauth2_client_credentials` |
| **Provider-direct MCP/REST bearer app token** | `API_TOKEN`, `AUTH_TYPE=bearer_token`, and a provider-verified `MCP_URL` or `REST_URL` respectively |
| **SMTP** | `SMTP_HOST`, `SMTP_PORT`, `SMTP_TLS_MODE` (`starttls`/`implicit`), `SMTP_SERVER_NAME`, `SMTP_AUTH_MECHANISM`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM_ADDRESS`, `AUTH_TYPE=smtp_password` |

For SMTP, `SMTP_ENVELOPE_FROM` is optional if the approved envelope address differs; the producer must verify sender restrictions with the actual gateway/provider and must not advertise forbidden From identities. Publish additional CA/trust material as a separately named key only when the endpoint uses an explicitly configured private trust root; never silently weaken TLS verification. For gateway OAuth, `OAUTH_RESOURCE` must be the exact Corvi mail-resource audience and `OAUTH_SCOPES` reflects the requested action classes; the server's grant, policy and identity binding remain authoritative, not the Secret text. Direct-provider REST/MCP static bearer tokens and SMTP app passwords are **different authentication mechanisms** and must not be interchanged.

**No unused protocol keys:** an MCP-shaped Secret does not contain `REST_URL`, SMTP credentials or hidden provider tokens; REST similarly contains no MCP/SMTP keys; SMTP contains no OAuth client secret or HTTP URL. Generated Secret keys are a versioned API; unknown/unsupported auth combinations fail publication rather than guessing. A Secret is useful to a client without additional provider-management API calls.

Examples of **decoded individual `data` values** are in the [gateway](../../api/examples/gateway-connection.example.json) and [provider direct](../../api/examples/provider-direct-connection.example.json) fixtures. These JSON files are *test fixtures documenting key/value maps*, **not files placed inside Kubernetes Secrets**. Actual generated Secrets contain the individually named keys, not a JSON-valued key.

## 4. Issuance, attachment and lifecycle

1. Resolve the producer's identity/mailbox and provider chain using authoritative same-namespace CRDs and validate provider capability, requested shape, target, grant and endpoint. `MailCredential` with **no gatewayRef must fail** `GatewayRequiredForScopedCredential` even if direct SMTP app tokens exist. `ProviderAppCredential` with a bound gateway must fail `GatewayBoundUseMailCredential`, including when the gateway is suspended or not Ready.
2. Validate exact gateway/client-reachable endpoint from approved published routes, never invent a DNS hostname or export an in-cluster `.svc` name as the only externally usable URL. Direct endpoints come from verified transport/provider data and must match the requested shape and TLS/auth profile. Don't copy provider admin token or internally held upstream OAuth access/refresh token.
3. Obtain the app token through the appropriate **independent authority**: Corvi OAuth issuer/SMTP credential service for scoped gateway access, or provider-supported app-credential administration API for direct native access. Fail if issuer lacks the required granularity, shape, secure token handoff or one-time issuance semantics.
4. Stage one-time token material securely and idempotently before publication (approved protected Secret/vault handoff; never store it in CRD status, logs or GitOps). Publish the **entire shape-specific flat key map atomically** with `Secret.data`; replace old keys rather than merge them. Mark `Ready` only after successful publication and usable validated endpoint data.
5. On Secret name/annotation changes, rotate/reissue safely. An existing Secret not provably owned by the exact producing object UID is **never adopted/overwritten** (`SecretNameConflict`). Use optimistic resourceVersion checks, bounded retries and consistent Secret ownerReferences to **only the credential-producing CRD**, not to gateway/provider/mailbox/identity resources.
6. For any provider `gatewayRef` bind, detach, change, mailbox/identity reparenting or shape/target revision, **withdraw/revoke the old credential and old route before publishing the new one**. Reauthorization or explicit human-approved conversion is mandatory when moving between Corvi scope and provider-native mailbox authority. **Never automatically convert scoped credentials into direct ones.** If upstream revocation cannot be confirmed, block migration/issuance and report `MigrationPending` or `CredentialRevocationUnconfirmed`; retain no old Secret that could still bypass new gateway policies. Secret deletion alone is not provider-side token revocation.
7. Reconcile statuses without secrets: `status.secretRef.name`, `status.connectionMode`, `status.shape`, `status.granularity`, `status.credentialRevision`, `status.observedGeneration` and bounded `Ready`/`Issued`/`Published`/`RotationPending` conditions with safe reasons (`GatewayRequiredForScopedCredential`, `GatewayBoundUseMailCredential`, `GatewayUnavailable`, `UnsupportedCredentialGranularity`, `UnsupportedCredentialShape`, `UnsupportedCredentialIssuance`, `EndpointUnavailable`, `SecretNameConflict`, `MigrationPending`). No raw credential, secrets, message data, hashed token material or password-bearing URL in status.

Secret volumes eventually update but clients must reload them; environment variables from Secrets do **not** hot-reload. Never suggest instant revocation across unobserved client workloads. The gateway continues enforcing current per-identity grants even when a previously copied Secret is stale. Provider-native tokens require actual upstream revocation, so revocation capability and failure behavior must be visible in sanitized conditions.

## 5. Security and Kubernetes RBAC

The mail gateway, OAuth resource server, provider gRPC plugin and bridges **remain rootless, read-only-root and without Kubernetes API tokens or Secret read/write API permissions** (ADR-0011). A dedicated `corvi-credential-publisher` controller or explicitly enabled, separately permissioned operator component may issue and write Secrets.

- Use namespace-scoped `get/create/update/patch/delete` only as needed for generated Secrets, **without blanket `list/watch secrets`**; narrow subject/namespace and enforce an independent admission policy for allowed generated Secret name, owner UID, annotations and data keys. Kubernetes RBAC alone cannot constrain a Secret `create` verb to arbitrary per-resource names. Without issuing credentials, the operator can remain Secret-write-free.
- Provider plugins hand off one-time native app credentials only through mutually authenticated, bounded **secret-handoff** methods, never via ordinary transport resolver RPC or logs. Corvi issuer does not hand its signing key or unrelated refresh tokens to the publisher.
- The publisher needs a narrowly scoped API token and remains subject to UID/GID nonroot, `allowPrivilegeEscalation=false`, `capabilities.drop=[ALL]`, `readOnlyRootFilesystem=true`, `seccompProfile=RuntimeDefault`, constrained egress and short-lived projected Kubernetes API credentials. No provider/plugin Pod gains an API token merely to write the generated Secret.
- CRD management state uses **Kubernetes CRDs/Secrets/Leases, no SQL or Redis**. One-time credential staging uses an approved encrypted Secret/vault and safe issuance record; never use CRD status as a secret store. Kubernetes at-rest encryption and backup/audit restrictions are still required.

## 6. Acceptance tests

1. Every app-credential-producing CRD supports `secretTemplate.metadata.name` and custom policy-approved annotations, deterministic omitted-name default and same-namespace publication. A foreign Secret name conflict never causes takeover.
2. There is **no `credentials.json`, `connection.json` or other serialized credential document inside any generated Secret**. All published `Secret.data` entries are flat UTF-8 strings with precisely the required shape-specific keys and no keys from a different protocol.
3. Each credential explicitly declares `shape: mcp|rest|smtp`; exactly one set of endpoint/auth keys appears. Gateway MCP/REST uses Corvi-scoped OAuth; SMTP has verified host/port/TLS/user/password; direct MCP/REST/SMTP requires real provider-side support.
4. `MailCredential` targeting an identity whose provider has **no gatewayRef** is rejected with **`GatewayRequiredForScopedCredential`** and publishes no usable Secret. An invalid/suspended gateway does not cause direct fallback.
5. `ProviderAppCredential` targeting a gateway-bound provider is rejected, never bypasses gateway authorization, and cannot reuse upstream administration or provider OAuth refresh credentials.
6. Provider with per-identity native issuance can fulfill an explicit `MailIdentity` target. A provider supporting **only mailbox-wide** tokens can fulfill an explicit `Mailbox` target but must reject identity target as `UnsupportedCredentialGranularity`. Neither is described as Corvi policy-scoped.
7. Binding or detaching a provider never automatically converts a scoped gateway credential to a provider mailbox password; revoke the old token before a replacement is published. Unsafe or unverifiable transitions report blocked status.
8. Every generated Secret includes verified usable connection details, exact authentication type, grant/authority granularity and revision. No invented public DNS, implicit JMAP→REST mapping or deprecated SMTP TLS downgrade.
9. Deleting credentials cleans up only their own Secrets and revokes the issued app token where supported. Parent provider/gateway deletion never garbage-collects unrelated producer resources or upstream mailboxes.
10. Publisher permissions and admission prevent unauthorized cross-namespace Secret publication, annotation-triggered unsafe replication and secret leakage. No added Secret API token in ordinary gateway or plugin Pods.

## Consequences

Corvi has two explicit application-credential security domains and one reusable flat-key Secret output contract, with safe default-deny routing. Consumers need only specific Kubernetes Secret keys. The trade-off is extra credential resources when an app needs multiple protocols and strict refusal of implicit mode changes. The design does not claim any actual Kubernetes CRD/controller exists.
