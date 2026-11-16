# ADR-0014: One MailCredential CRD, webhook validation and flat-key Secrets

- **Status:** Proposed; CRD, admission webhook, issuer, Secret publisher and controllers are not implemented
- **Date:** 2026-11-16
- **Scope:** Single application-credential custom resource, gateway/provider-specific validation, provider-native issuance, custom Secret name/annotations and explicit MCP/REST/SMTP connections
- **Related:** [ADR-0001](0001-corvi-system-architecture.md), [ADR-0005](0005-public-mail-api.md), [ADR-0008](0008-interactive-upstream-oauth.md), [ADR-0009](0009-corvi-oauth-and-identity-grants.md), [ADR-0010](0010-storage-and-durability.md), [ADR-0011](0011-hardened-helm-deployment.md), [ADR-0013](0013-mail-resource-ownership-graph.md)
- **Design schema:** [MailCredential and flat Secret key contract](../../api/generated-connection-secret.schema.json)
- **Examples:** [Same-CRD credential resources](../../deploy/examples/generated-connection-secrets.example.yaml), [webhook + read-only RBAC fixture](../../deploy/examples/mailcredential-validating-webhook.example.yaml), [gateway MCP key/value fixture](../../api/examples/gateway-connection.example.json), [direct provider SMTP key/value fixture](../../api/examples/provider-direct-connection.example.json)

## Decision

Use **one namespaced `MailCredential` CRD**, with **one validating admission webhook** for its semantic invariants. **Do not create a separate provider-app credential CRD or a second credential type.** The effective credential authority and connection route are **derived from the existing MailIdentity → Mailbox → MailProvider → optional CorviGateway reference graph** (ADR-0013), not from two competing CRDs or a user-controlled `mode` selector.

Every `MailCredential` declares:
- `spec.type: smtp | rest | mcp` (optional; defaults to `smtp`), **exactly one protocol type**, one generated Secret.
- `spec.targetRef: {kind: MailIdentity | Mailbox, name: ...}`, **exactly one** same-namespace target.
- Optional `spec.permissions` (nonempty, unique Corvi mail actions) **only** for a **gateway-attached MailIdentity**. Presence of `permissions` expressly requests **Corvi-scoped authority**. Native direct-provider credentials **must omit `permissions`**, including the empty list; they are not Corvi-scoped.
- Optional `spec.secretTemplate.metadata.name` and `.annotations`, with custom name, custom safe annotations and a deterministic default name when omitted.

The **validating webhook** inspects those fields and the resolved, typed resource chain before admitting CREATE/UPDATE. The **reconciler also repeats the checks before issuance/renewal/Secret publication**, because referenced Mailbox, MailIdentity, MailProvider, CorviGateway and provider capabilities can change *without* updating the MailCredential and can change after admission. A webhook **does not issue tokens, write Secrets, call providers, mutate resources, or run on mail requests**. Admission approval is not an enduring credential grant.

### One resource, two validated modes

| Target's provider | `targetRef.kind` | `permissions` | Effective result |
| --- | --- | --- | --- |
| Bound to an active, valid CorviGateway | `MailIdentity` | **Required nonempty** action list | **Gateway mode**: Corvi-scoped, per-identity credentials for selected `mcp`, `rest` or `smtp` |
| Bound to CorviGateway | `Mailbox` | Any | **Reject `GatewayRequiresMailIdentity`**: gateway policy is identity-based |
| Bound to CorviGateway | `MailIdentity` | Omitted | **Reject `MissingGatewayPermissions`** |
| Bound but suspended/unready/missing gateway | `MailIdentity` | Nonempty | Refuse issuance/mark pending (`GatewayUnavailable` or `InvalidGatewayRef`), **never fall back to direct** |
| **Unbound** (no `MailProvider.spec.gatewayRef`) | `Mailbox` | **Omitted** | **Direct provider mode**: issue native **whole-mailbox** credential only if provider supports that type and granularity |
| **Unbound** | `MailIdentity` | **Omitted** | **Direct provider mode**: issue native **per-identity** credential only if provider actually isolates that identity |
| **Unbound** | Either | **Present** (even `[]`) | **Reject `GatewayRequiredForScopedCredential`**: no Corvi-scoped credentials without a gateway |
| **Unbound** | Either | Omitted, but no native app-token API / requested type / granularity | **Reject `UnsupportedCredentialIssuance`, `UnsupportedCredentialType`, `UnsupportedCredentialGranularity` or `UnsupportedIsolation`** |

A valid **provider-native** credential is *not* a Corvi OAuth or MailPolicy grant. Provider implementations decide whether they issue independently revocable credentials per physical mailbox or per virtual/sender identity, and which protocols they actually support; the webhook does not assume per-identity isolation from an email address alone. It rejects requests for a virtual `MailIdentity` if the provider's token would expose the entire underlying Mailbox. Explicit `Mailbox` targets request mailbox authority, require appropriate administrative authorization, and never falsely advertise identity-scoped permissions.

The **routing rule** is: attached provider → Corvi gateway endpoint/credential; unbound provider → supported native provider endpoint/credential **only when no Corvi `permissions` were requested**. An explicit, invalid `gatewayRef` is not unbound. A suspended bound gateway is not permission to bypass it. Transitioning between states requires revocation/reissue and explicit reauthorization, never silent conversion or privilege expansion.

## 1. One CRD with conditionally validated specs

Gateway-scoped example:

```yaml
apiVersion: corvi.naktis.eu/v1alpha1
kind: MailCredential
metadata:
  name: personal-mcp
  namespace: corvi-system
spec:
  type: mcp
  targetRef:
    kind: MailIdentity
    name: me
  permissions:
    - mail:messages:list
    - mail:messages:read
  secretTemplate:
    metadata:
      name: personal-mcp-app
      annotations:
        example.com/application: mail-agent
```

Provider-native, **mailbox-wide**, direct SMTP example using the **same kind**:

```yaml
apiVersion: corvi.naktis.eu/v1alpha1
kind: MailCredential
metadata:
  name: direct-alerts
  namespace: corvi-system
spec:
  # type omitted: defaults to smtp
  targetRef:
    kind: Mailbox
    name: unserved-mailbox
  # No permissions: provider-native authority, NOT a Corvi scoped credential.
  secretTemplate:
    metadata:
      name: direct-alerts-smtp
      annotations:
        example.com/application: alerts
```

A provider advertising **verified native per-identity issuance** can also accept `targetRef.kind: MailIdentity` with `permissions` **omitted**, but must enforce the exact physical isolation of that identity. A provider only issuing whole-mailbox credentials must reject that request: `UnsupportedCredentialGranularity`.

Corvi's **interactive** OAuth grants may still authorize several identities under one grant (ADR-0009). **Generated MailCredential resources are deliberately one-target, one-type** to keep their Secret consumers, authority boundaries and revocation understandable.

### Secret template

`secretTemplate` is optional. If `secretTemplate.metadata.name` is absent, derive a stable, DNS-compliant name from `MailCredential` name/UID (and a collision-resistant scheme); Secret always stays in the resource namespace. Accept only `metadata.name` and policy-approved `metadata.annotations`. Reject arbitrary Secret `data`, `stringData`, `type`, `immutable`, `ownerReferences`, namespace, controller-owned labels, reserved `corvi.naktis.eu/*` annotations and service-account-token annotations.

User-defined annotations may invoke Secret-copying/reloader controllers. The webhook must check an explicit allow-policy, length bounds and any restrictions on cross-namespace propagation. A custom Secret name cannot claim an existing Secret owned by another producer: admission can preflight names, but the publisher must independently verify ownership/resourceVersion at create/update and fail `SecretNameConflict` rather than overwrite.

## 2. Admission webhook contract

Install one narrowly scoped `ValidatingWebhookConfiguration` (privileged bootstrap/GitOps step, **not** by the runtime operator Role) targeting:

- `apiGroups: [corvi.naktis.eu]`, `apiVersions: [v1alpha1]`, `resources: [mailcredentials]`, `operations: [CREATE, UPDATE]`.
- AdmissionReview v1, HTTPS Service with separately managed serving certificate and injected CA bundle; `sideEffects: None`, `failurePolicy: Fail`, `matchPolicy: Equivalent`, constrained timeout and namespace/object selectors **only if they cannot allow unvalidated credentials to bypass the webhook**. Keep the scope namespace-appropriate.
- ServiceAccount with **only the necessary namespaced `get`** rights for referenced MailIdentity, Mailbox, MailProvider and CorviGateway, and trusted read access to **bounded, nonsecret provider capability status**. It cannot create/update Secrets, issue tokens, change other CRDs, read provider admin passwords or execute Pod commands.

On MailCredential CREATE/UPDATE, the webhook:

1. Performs field-level/schema validation: one supported `type` (default `smtp`), typed one-name targetRef, unique nonempty action list when present, allowed Secret annotations/name, no secret literals, no unsupported arbitrary object fields. CRD OpenAPI/CEL can catch local syntax; the webhook is required for **cross-resource** checks.
2. Resolves exact same-namespace target chain: `MailIdentity → Mailbox → MailProvider` for identity targets; `Mailbox → MailProvider` for mailbox targets; and `MailProvider.gatewayRef?` to CorviGateway when present. No default gateway, cross-namespace reference, missing or wrong-kind parent. Require authorizations for requested management/issuance scope in addition to admission: a Secret-readable namespace must not itself confer provider-admin token issuance.
3. For **bound** provider: accept **only MailIdentity with nonempty permissions**, subject to selected gateway capabilities, policies and route/issuer configuration. If the gateway is temporarily not Ready, preserve the desired object but keep issuance pending; do not turn it into a provider-native credential. Reject invalid gatewayRef rather than treating it as absent.
4. For **unbound** provider: **reject any presence of permissions with `GatewayRequiredForScopedCredential`**, then check the provider's **verified, current `appCredentials.types[]` and `appCredentials.granularities[]`**, actual ability to issue separately revocable client credentials, sender/reader isolation and approved provider endpoint. Reject MailIdentity target when only mailbox-wide issuance is possible, and reject unsupported MCP/REST/SMTP types rather than guessing IMAP/JMAP/API equivalence.
5. Return precise admission denial reasons without revealing endpoints containing secrets, token values, mailbox content, upstream admin account details or OAuth grants. If referenced resources/capabilities cannot be read reliably, **fail closed** and allow a retry after discovery/reconciliation. An unavailable webhook must not silently admit insecure resources.

Admission **must not** call an upstream provider's `CreateAppToken`, revoke credentials, write a generated Secret, create an OAuth client or make any mutation. Kubernetes API dry-run must be safe. It should avoid synchronous calls to external provider gRPC/API and validate against reconciled capability status **only if fresh for the target generation**. Provider-side issuance still rechecks capabilities at issue time.

**A webhook cannot enforce invariants when its referenced objects change later.** In addition to CREATE/UPDATE validation, the operator re-evaluates every `MailCredential` on the relevant `MailProvider.gatewayRef`, `Mailbox.providerRef`, `MailIdentity.mailboxRef`, gateway suspension/route, provider capability and relevant policy changes. Validating related parent-resource updates can reject unsafe instant transitions, but is not a substitute for **reconciler revocation/fencing**, particularly while the webhook is unavailable or resources are changed outside the normal admission path. Design bounded revocation freshness and block insecure issuance when the new graph cannot be resolved. **No admission webhook is on the mail data path.**

When implemented, the structural CRD OpenAPI schema MUST default `spec.type` to `smtp`, allowing Kubernetes to apply that default before the validating admission webhook runs. The design JSON Schema records the same default but is not itself an installed CRD. No mutating admission webhook is required. Explicit `null`, unknown types and legacy `shape` fields are rejected, not silently interpreted.

## 3. Provider capabilities and direct credential granularity

Providers advertise and the control plane verifies `appCredentials.types[]` (`mcp`, `rest`, `smtp`), `appCredentials.granularities[]` (`providerIdentity`, `providerMailbox`), supported authentication profile and independent revocation behavior. Existence of an IMAP endpoint or JMAP HTTP Session does **not** imply provider-native REST/MCP. An upstream provider admin API key is never an application mail credential. Direct SMTP needs verified submission endpoint and independent app password; direct MCP/REST needs a real corresponding app endpoint and per-app bearer authentication.

Native provider-issued tokens must not be confused with Corvi scoped grants:
- **`providerIdentity`**: only when upstream authorization truly limits token access to that identity/sender and selected mailbox messages. Target `MailIdentity` with no Corvi permissions.
- **`providerMailbox`**: the entire physical mailbox according to provider-native permissions. Target `Mailbox` with no Corvi permissions. Do **not** masquerade this as virtual per-identity isolation.
- **Unsupported**: no independent token API, unsafe isolation, unknown server identity/CA, unsupported type/auth or unreliable revocation behavior. Do not generate output or export the provider-admin account password, internally held upstream OAuth access/refresh tokens, signing keys or secret broker credentials.

Provider capability status is declarative management data, never authorization by itself. Credentials are independently issued through a protected provider-management secret handoff; the webhook is not that issuer.

## 4. Flat-key Secret output

The publisher creates **`type: Opaque` with individual UTF-8 values under `Secret.data`**. No `credentials.json`, `connection.json`, JSON credential bundle or other serialized secret file. Each `MailCredential` produces exactly **one** of these types:

| Type | Mandatory data keys |
| --- | --- |
| **All** | `CONNECTION_TYPE` (`mcp`/`rest`/`smtp`), `CONNECTION_MODE` (`gateway`/`providerDirect`), `AUTH_TYPE`, `CREDENTIAL_GRANULARITY` (`corviIdentity`, `providerIdentity`, `providerMailbox`), `PROVIDER_NAME`, `CREDENTIAL_REVISION`, plus appropriate `IDENTITY_NAME` or `MAILBOX_NAME` |
| **MCP** | `MCP_URL` (verified HTTPS Streamable HTTP endpoint) and exactly the applicable auth keys |
| **REST** | `REST_URL` (verified HTTPS endpoint) and exactly the applicable auth keys |
| **Gateway MCP/REST** | `OAUTH_TOKEN_URL`, `OAUTH_CLIENT_ID`, `OAUTH_CLIENT_SECRET`, `OAUTH_RESOURCE`, `OAUTH_SCOPES` (space-delimited); `AUTH_TYPE=oauth2_client_credentials` |
| **Direct provider MCP/REST** | `API_TOKEN` and `AUTH_TYPE=bearer_token`; real provider-supported endpoint/auth required |
| **SMTP** | `SMTP_HOST`, `SMTP_PORT`, `SMTP_TLS_MODE` (`starttls`/`implicit`), `SMTP_SERVER_NAME`, `SMTP_AUTH_MECHANISM`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM_ADDRESS`; `AUTH_TYPE=smtp_password` |

`SMTP_ENVELOPE_FROM` is optional only when authorized and appropriate; `TLS_CA_PEM` is an optional separately named key for configured private CA trust, never a TLS-verification bypass. Only include keys for the **declared** type, never unrelated protocol credentials. A Secret may contain verified route/identity metadata but **never** provider admin tokens or internal OAuth refresh/access tokens copied from Corvi's provider connection. `OAUTH_RESOURCE` is the exact Corvi mail-resource audience, not a provider API audience. Actual grant/policy decisions remain server-side.

[Gateway MCP](../../api/examples/gateway-connection.example.json) and [provider SMTP](../../api/examples/provider-direct-connection.example.json) examples are **decoded key/value test fixtures**, not files placed into Kubernetes Secrets. Full protocol type variants live in the [schema](../../api/generated-connection-secret.schema.json).

## 5. Reconciliation, Secret ownership and safe transitions

1. **Revalidate** all webhook rules at each reconciliation/issuance/rotation, including chain UIDs and generations, provider `gatewayRef`, recipient target kind, token granularity, active publisher route, effective permissions, current provider capabilities and Secret ownership. A resource admitted months ago does not override newly changed policy or parent references.
2. Publish only after obtaining/verifying the appropriate token: Corvi OAuth client/SMTP credential for bound gateway scoped access or independent provider-native app token for unbound provider. Use idempotent issuance, protected one-time staging, bounded mTLS secret handoff; never issue in the webhook. Unknown provider capabilities or unsafe state report `UnsupportedCredentialGranularity`/`UnsupportedCredentialType`/`IssuerUnavailable` without token exposure.
3. Validate a real reachable route and exact protocol auth before publication. Gateway exposure must be from approved observed endpoints, not fabricated `.svc` names. Direct endpoints must match the advertised provider service/protocol. Generate the complete expected flat key map and atomically **replace**, never merge, `Secret.data`.
4. Manage Secret names and annotations with resourceVersion checks and verified owner UID (ownerReference only to the `MailCredential`, never the provider/mailbox/gateway). Never adopt or overwrite an unrelated Secret, even on custom-name collision. `SecretNameConflict` fails safely; no cross-namespace targets. Do not allow consumer annotations that replicate tokens to untrusted namespaces.
5. On bind/detach, mailbox or identity reparenting, gateway suspension, permission/grant changes, native capability loss or requested type/target changes, **revoke old authority and invalidate the prior connection Secret before any replacement becomes available**. A `MailCredential` with previously scoped `permissions` cannot silently turn into a mailbox-wide provider password: with the gateway removed it now **fails `GatewayRequiredForScopedCredential`**. Creating a **new or explicitly amended** unscoped `MailCredential` is a separately authorized request, never an automatic permission expansion.
6. If upstream revocation or safe cutover cannot be verified, report `MigrationPending`/`CredentialRevocationUnconfirmed`, withdraw outputs as required to prevent unintended continued use, and block publication; deleting a Secret alone is not upstream revocation. Secret volumes update eventually, Secret-backed environment variables require Pod restart, and copied provider-native tokens remain valid until upstream revoked/expired.
7. Sanitized status may contain `status.secretRef.name`, `status.connectionMode`, `status.type`, `status.granularity`, `status.credentialRevision`, `observedGeneration` and bounded `Ready`/`Issued`/`Published`/`RotationPending` conditions with reasons such as `GatewayRequiredForScopedCredential`, `MissingGatewayPermissions`, `GatewayRequiresMailIdentity`, `GatewayUnavailable`, `UnsupportedCredentialGranularity`, `UnsupportedCredentialType`, `SecretNameConflict` and `MigrationPending`. No raw token, token hash, private mail, password-bearing URL or secret contents in status, logs, events, ConfigMaps or Helm values.

A `MailCredential` without `permissions` is only **eligible for native direct issuance while unbound**. It never gains Corvi OAuth scope automatically when its provider becomes bound; webhook validation on the associated parent change and issuer reconciliation keep it unavailable until the requested form is explicitly authorized.

## 6. Security, deployment and RBAC

The webhook and Secret publisher are **separate trust roles**. A read-only admission webhook (with short-lived API credentials) validates the resource graph; a privileged-in-scope Secret publisher (with its own narrowly scoped ServiceAccount) creates/revokes credential and writes Secret keys. Neither is on mail's request path; normal gateway, OAuth runtime, plugin and bridge Pods **get no Kubernetes API token or Secret-write RBAC**.

- Webhook: namespaced `get` on `mailidentities`, `mailboxes`, `mailproviders`, `corvigateways` plus approved provider capability status; cannot write any Kubernetes objects or read arbitrary Secrets. Admission registration and CA injection are separately bootstrapped by trusted GitOps/cert-manager, **never authorized by the runtime operator Role**.
- Publisher: namespaced `get/create/update/patch/delete` on exact generated Secret objects where feasible (no blanket `list/watch secrets`), read/watch MailCredential and relevant parent resource status, update `mailcredentials/status` and `mailcredentials/finalizers` as required. Kubernetes `create secrets` cannot be restricted by RBAC `resourceNames`; independent admission verifies issuer identity, UID and metadata/key ownership. Do not grant operator plugin ServiceAccounts creation rights.
- Both Pods use UID/GID nonroot, `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, `readOnlyRootFilesystem: true`, `seccompProfile: RuntimeDefault`, tight egress and bounded resources. Use separate projected API tokens for the workloads that actually need them. No database/Redis for operator credential metadata; encrypted Kubernetes Secrets or approved vault for one-time protected issuance material.

The optional webhook, publisher, and their RBAC/install wiring are **future implementation work**. Operator-only provider administration with no credential CRDs is otherwise unchanged.

## 7. Acceptance tests

1. **Exactly one MailCredential CRD.** Repository, RBAC, resource examples and schema contain no second credential API kind or CRD.
2. Admission CREATE/UPDATE for bound MailIdentity + nonempty permissions succeeds only for verified gateway/type; bound Mailbox is denied; missing gateway permissions denied.
3. Admission **rejects gatewayless `permissions`** with `GatewayRequiredForScopedCredential`, including empty-list presence. For an unbound Mailbox or properly isolated MailIdentity **without permissions**, admission permits only provider-native supported type and exact native granularity.
4. A provider exposing only whole-mailbox app tokens rejects identity target as `UnsupportedCredentialGranularity`. Provider without independent app-token issuance or actual requested MCP/REST/SMTP endpoint fails closed.
5. Changed MailProvider/ Mailbox/ MailIdentity / CorviGateway refs, capabilities or status **after admission** trigger revalidation and revoke or withhold unsafe output; no two gateways nor direct-provider route serve the same credential authority during migration.
6. Admission dry-run makes no external token, Secret, account or other mutation. Webhook outage or stale ref/capability status fails closed for new/updated MailCredential resources; live mail continues without webhook.
7. Every Secret has user-specified or deterministic name and safe annotations, never overwrites foreign Secret UID, and contains only one `mcp`/`rest`/`smtp` set of **flat individual keys** with complete auth/TLS/endpoint info. **No `credentials.json`/`connection.json` generated.**
8. Gateway and provider native tokens remain distinct; provider mailbox-wide token is not labeled identity-scoped and existing gateway grants never expand automatically on attachment/detachment.
9. Separate publisher role has bounded Secret-write permissions. The admission webhook is read-only and cannot issue credentials; gateway/bridge/plugin pods retain no Kubernetes API tokens.

## Consequences

A **single MailCredential CRD** serves both deployment cases without duplicate CRD lifecycle, while a validating webhook can enforce conditional cross-resource constraints at creation/update time. The **issuer/reconciler must also enforce them continuously**; the admission webhook is not a security boundary for later parent changes by itself. Secret outputs remain flat, complete and explicitly protocol-typed. No component in this ADR is yet deployed or implemented.
