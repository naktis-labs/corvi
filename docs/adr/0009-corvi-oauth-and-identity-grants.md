# ADR-0009: Corvi OAuth authorization and identity-scoped grants

- **Status:** Proposed; authentication/authorization implementation is pending
- **Date:** 2026-11-16
- **Scope:** Authorization of clients to Corvi's REST, MCP, and eligible SMTP AUTH submission interfaces; separate administrative identities
- **Related:** [ADR-0001](0001-corvi-system-architecture.md), [ADR-0003](0003-mail-filtering-and-disclosure-policies.md), [ADR-0005](0005-public-mail-api.md), [ADR-0008](0008-interactive-upstream-oauth.md), [MCP spec](../spec/mcp.md)
- **Contract:** [`api/corvi-oauth.schema.json`](../../api/corvi-oauth.schema.json)

## Decision and trust boundaries

**Corvi SHALL support a complete standards-based OAuth 2.0 authorization flow for its own clients**, not merely check arbitrary third-party bearer tokens. Support interactive authorization and per-client consent, non-interactive machine credentials, granular per-`MailIdentity` grants, refresh/revocation, OAuth discovery and MCP compatibility. **Clients can authorize access to several identities and mailboxes with one Corvi access token**, each with different granted actions.

Corvi shall support two deployment patterns using the same **Corvi-owned authorization-grant engine**:

1. **Built-in/standalone Corvi authorization server (AS):** optional first-party OAuth authorization/token/discovery service for a self-contained installation, using durable or securely configured single-instance grant/token state. The owner signs in with a configured trusted local authentication mechanism or a federated identity provider. Do not invent an ad hoc password database or make the gateway's mail endpoints responsible for authenticating user passwords.
2. **External identity provider (IdP) / authorization-server integration:** support OpenID Connect federation for the Corvi consent/authorization UI (e.g. Kanidm) and/or direct validation of external **Corvi-audience** access tokens from explicitly trusted OAuth issuers. Direct external validation is suitable only when Corvi can reliably bind the authenticated subject/client to **Corvi-controlled identity/action grants**. Where the upstream AS cannot express/grant per-mailbox consent, use the built-in Corvi **authorization broker** to mint Corvi-restricted tokens after upstream OIDC sign-in and local consent.

**Kubernetes operators store provider-management desired/status state only in Kubernetes CRDs and Secrets references, with no SQL database.** Corvi's OAuth authorization server is **logically distinct from the provider-management reconciler**: consent grants, authorization codes, opaque token hashes, refresh families and revocation history require transactional SQLite (standalone issuer) or PostgreSQL (multi-replica issuer), even if both components share a binary or Pod (ADR-0010).

A standalone installation needs no mandatory Kubernetes, external Keycloak/IdP or separate microservice. The built-in AS, grant store and resource server may live in one Corvi process, with separate logical endpoints, keys and access controls. Multi-replica issuer deployments require shared durable authorization state, refresh-token concurrency control, revocation propagation and stable signing keys. Read-only resource-server verification can run on many replicas.

**Separate three token/credential trust domains:**

- **Corvi client-facing** access/refresh tokens: allow a client to use specific Corvi mail identities/actions through REST/MCP; never grant a direct provider credential.
- **Upstream mail provider** OAuth access/refresh tokens: connect Corvi *to* Fastmail/Gmail/Microsoft JMAP/IMAP/SMTP and remain only in provider-connection custody (ADR-0008).
- **Provider administration and Corvi management** credentials: belong to distinct management audiences, principals and policies. A mail API token cannot list provider secrets, manage OAuth connections or administer physical mailboxes.

## 1. OAuth roles and endpoints

Corvi's REST `/v1/*` and HTTP MCP `/mcp` are **protected OAuth resource-server** endpoints. A local Corvi AS (when configured) has **separate OAuth endpoints**. It is legitimate for the two roles to reside in the same process but their scopes, audiences, handlers, error behavior and secrets must remain distinct.

| Surface | Role | Proposed endpoint / capability |
| --- | --- | --- |
| REST and MCP | Resource server | `/v1/*`, `/mcp` |
| Resource metadata | RFC 9728 discovery | `/.well-known/oauth-protected-resource` for the configured resource URI, plus RFC-defined path-qualified form if needed |
| OAuth AS metadata | RFC 8414 discovery | `/.well-known/oauth-authorization-server` at the issuer's correct well-known path |
| User authorization | AS only | `/oauth/authorize` (browser login + client consent) |
| Token grant/refresh | AS only | `/oauth/token` |
| Token revocation | AS only | `/oauth/revoke` (RFC 7009) |
| Opaque token introspection | AS only, privileged | `/oauth/introspect` (RFC 7662); not public mail functionality |
| Keys for JWT mode | AS only | `/oauth/jwks.json`, if signed access tokens are enabled |
| Device flow | Optional AS feature | `/oauth/device_authorization` (RFC 8628) |
| PAR | Optional security hardening | `/oauth/par` (RFC 9126), useful for large RAR requests |
| Approvals and grant review | Authenticated owner/admin UI | `/account/authorized-apps` and internal grant-management operations, not public mail tools |

All concrete paths are provisional except the standards-based well-known path rules. **Hostnames and resource indicators are deployment-configured**, not hardcoded to a single production domain. Illustrative deployment: mail resource `https://mail.corvi.naktis.eu`, AS issuer `https://auth.corvi.naktis.eu`. For resource `https://mail.corvi.naktis.eu/mcp`, publish the RFC 9728 path-qualified metadata where required; do not assume a root well-known document is always sufficient.

The resource metadata advertises only **configured trusted authorization server issuers** and a canonical resource identifier. A 401 challenges the client with `WWW-Authenticate: Bearer resource_metadata="..."` and appropriate scopes. MCP 2026-07-28 discovers the AS through protected-resource metadata, **not** by trusting arbitrary HTTP redirects to an issuer chosen by an attacker.

## 2. OAuth grants and client enrollment

| OAuth grant | Status | Intended use |
| --- | --- | --- |
| **Authorization Code + PKCE S256** | Required | Interactive desktop, web and MCP application authorization |
| **Refresh Token** | Required for eligible interactive clients | Preserve consented access without repeated login; rotate tokens and detect replay |
| **Client Credentials** | Required | Admin-provisioned, independently revocable automation/service principals; no user impersonation |
| **Device Authorization** (RFC 8628) | Optional, advertised only when implemented | Headless/terminal clients, interactive owner approval on separate device |
| **Token Exchange** (RFC 8693) | Future opt-in | Explicitly trusted delegation; never general third-party token pass-through |
| **Implicit / ROPC / unbounded password tokens** | Forbidden | No bearer token in URL fragments, no client access to owner's password |

**Public clients** (native app, CLI, MCP host) use PKCE S256, one-time authorization code, exact redirect URI checking, per-transaction state, issuer `iss` response (RFC 9207) and supported loopback/deep-link redirect policies. Browser-only apps use current OAuth browser-app security guidance. **Confidential clients** additionally authenticate to the token endpoint using their configured method (`private_key_jwt`/mTLS or a securely stored client secret); all authorization-code flows use PKCE.

**MCP client registration precedence:** support **Client ID Metadata Documents (CIMD)** in the embedded Corvi AS, according to MCP 2026-07-28. Treat the HTTPS client metadata URL as a client identifier only after fetching/validating the document: HTTPS with allowed host/port, SSRF and DNS/redirect protection, exact `client_id`, permitted `redirect_uris`, trusted metadata freshness, verified client binding, size/timeout limits and a policy controlling unregistered clients. Pre-registered clients remain supported. **Dynamic Client Registration (DCR, RFC 7591) is deprecated** in MCP 2026-07-28; leave it disabled by default and optionally enable a rate-limited legacy compatibility mode, never an unauthenticated arbitrary-secret-issuing endpoint.

For **client credentials**, require explicit administrator registration of service principals and an approved identity/action allowlist. Confidential client authentication is mandatory. A `client_id` or `scope` string alone is not permission to access mail. Refresh tokens are not issued by default for `client_credentials`; a service requests another short-lived access token through authenticated client credentials.

## 3. Core authorization model: resource, scope, identity and consent

**Scopes specify the requested action class; per-identity grants specify where those actions are valid.** The issuer and resource server MUST evaluate the intersection, never the union, of:

```text
authenticated principal + OAuth client identity
  ∩ consented authorization grant (owner, client, identity IDs, actions, bounds)
  ∩ issued access token scope/details/audience/expiry
  ∩ current server-side MailCredential/MailIdentity membership and MailPolicy
  ∩ current MailFilterPolicy and message recipient-provenance restrictions
  ∩ operation-specific constraints (send recipients, approval, attachment, task, stream)
```

Grant identity values are **opaque Corvi `identityId` values**, resolved against owner/admin-visible MailIdentity instances; they are not email address strings, provider IDs, JMAP account IDs, or arbitrary selectors. One grant can contain *multiple* identity entries, each with *its own* action set and optional restrictions. There is no implicit wildcard identity and no cross-identity search. A client with permission to read `identity-a` and send `identity-b` cannot read `identity-b` or send `identity-a`.

### Action scope registry

Canonical resource-facing scopes match the **existing** v1 permission vocabulary:

| Scope | Operation |
| --- | --- |
| `mail:identities:list` | Discover only caller-visible granted identities |
| `mail:messages:list` | List visible mail for selected identity |
| `mail:messages:search` | Search the caller-visible projection |
| `mail:messages:read` | Get sanitized message |
| `mail:attachments:read` | Get authorized attachment |
| `mail:messages:send` | Submit message from authorized sender |
| `mail:submissions:read` | Check authorized send status |
| `mail:messages:subscribe` | Receive filtered visible-mail change hints **with** list permission |

Use least-privilege `scopes_supported` discovery rather than encouraging every client to request all scopes. If an application requests a new action or identity, perform **OAuth step-up** with a fresh, narrowly constrained consent decision, rather than silently widening existing grants. Denying a step-up does not revoke an unrelated previously consented grant.

### Rich Authorization Requests (RAR, RFC 9396)

Support **OAuth `authorization_details`** with a custom, versioned `type` **`corvi_mail`**, documented in [`api/corvi-oauth.schema.json`](../../api/corvi-oauth.schema.json). Corvi's consent and token code MUST preserve the *effective* per-identity choices. Example request:

```json
{
  "authorization_details": [
    {
      "type": "corvi_mail",
      "identityId": "identity-a",
      "actions": ["mail:messages:list", "mail:messages:read"]
    },
    {
      "type": "corvi_mail",
      "identityId": "identity-b",
      "actions": ["mail:messages:send"],
      "constraints": {
        "recipientDomains": ["alerts.example.com"],
        "unattendedSend": false
      }
    }
  ]
}
```

This is a **Corvi-defined RAR detail type**, not a claim that `corvi_mail` or `identityId` are standard OAuth fields. In an actual authorization request the JSON array is serialized as the standard `authorization_details` parameter, alongside `resource` (RFC 8707) and whichever action scopes are used. RAR `actions` must correspond to the granted scopes and Corvi policies, never override them. The AS may grant a proper subset and MUST show that exact subset to the user. Consent can include an expiry and constraints, but never grants administrator/root access. The token response conveys granted `authorization_details` as RFC 9396 requires when supported.

**No broad auth-through-scope bypass:** If an external OAuth issuer cannot represent RAR, Corvi may use a locally owned, server-side OAuth authorization grant keyed by (`issuer`, subject, client, audience, grant ID) plus token scopes. A token's `mail:messages:read` scope **without a matching identity binding** authorizes no mailbox. Never treat an OAuth token as proof of user consent to an arbitrary set of mailboxes.

### Consent UI and grant lifecycle

The account owner sees the **verified client name and identity**, each selected address/identity, read/list/search/attachment/send capabilities separately, recipient restrictions, whether sending will require runtime confirmation, and the grant's expiry. Avoid deceptive aggregated `Full mailbox access` consent that obscures identity-specific permissions. Distinguish client identity from an unverified display name and do not use client metadata as a trusted principal.

An owner can list active apps/clients and per-identity grants, reduce permissions, revoke one identity, revoke a single client, or revoke all client sessions/tokens. User-delegated grants cannot grant more than the user currently controls; service-account grants require an administrator and cannot inherit broad user visibility by default.

The consent grant's **allowlist** remains an upper bound. Policies changing underneath may *reduce* effective access immediately; expansions to a new identity or action require explicit new consent or separate administrator-issued service grant. `mail:messages:send` consent **does not remove** the MCP MRTR runtime confirmation requirement: only a separately designated, limited, server-approved `unattendedSend` capability plus applicable policy may bypass per-send confirmation. REST and SMTP AUTH retain their independent sending protections.

## 4. Access token and audience contract

Clients request access for a specific **Corvi protected resource identifier**, e.g. `resource=https://mail.corvi.naktis.eu` (RFC 8707). The same mail-resource audience may protect REST and MCP under one trusted deployment; the **administration API uses a separate audience** and cannot accept mail bearer tokens.

Recommended initial **opaque short-lived access tokens** with server-side reference/introspection and revocation, rather than huge self-contained JWTs containing every mailbox grant. Opaque tokens simplify immediate identity-grant revocation, privacy and constrained token size. An optional signed JWT access-token profile may be added when needed for multi-replica/high-throughput deployments; use RFC 9068 (`typ=at+jwt`, signature, `iss`, `aud`, `sub`, `client_id`, `iat`, `exp`, scope and immutable grant reference, and `jti`) with key rotation/JWKS and **online revocation or bounded policy-freshness checks** for high-risk operations. Do not put provider secrets, private filter rules, or full mailbox inventories in JWTs.

Required validation before any REST/MCP operation:

1. Verify token format/MAC or signature, trusted `iss`, exact expected `aud`/resource, `exp`/`nbf` where supplied, revocation status and authenticated client/sender-binding if configured.
2. Resolve the **authenticated principal and OAuth client**; ensure the client is permitted to represent this principal and the grant has not been revoked. Reject unknown user account, deleted principal, changed authorization server, disabled client or wrong audience.
3. Resolve current consented identity/action grant and its revision; check `identityId` and required scope/action **for this specific identity**. Check Corvi's active configuration, disclosure policy and message provenance, even if token claims say `allow`.
4. Recheck at pagination, attachments, Tasks polling/results, MRTR resume, SMTP send, and before each long-lived MCP subscription notification. Revoked grants may not remain active just because a stream was established before revocation.
5. No token passthrough to IMAP/SMTP/JMAP upstreams or administrative provider gRPC. Never treat upstream tokens, login ID tokens, session cookies, expired refresh tokens or authorization codes as API access tokens.

For `resources/list`, authorization controls which concrete resource URIs are advertised, and `resources/read` enforces matching identity grants. Tool discovery and cacheable metadata do not grant permission.

## 5. Token renewal, storage, revocation and availability

- **Access token lifetime:** configurable, default short (proposed 15 minutes); refresh tokens have bounded absolute/sliding lifetime with **rotation, reuse detection and family revocation**. Do not return refresh tokens in resource-server responses, logs, trace data or MCP content. A refresh cannot expand the original consented identity/action set and must fail closed if the principal/client/grant has been revoked or reduced.
- **Authorization codes:** one-use, short-lived, bound to issuer, client, redirect URI, PKCE challenge, authenticated owner, requested resource, scopes, RAR and exact grant consent. Deny code substitution and issuer mix-up.
- **Token storage:** hashed opaque access/refresh tokens at rest in the transactional grant store (SQLite standalone, PostgreSQL multi-replica) and protected grant/refresh family state and revocation records; encrypt secret keys and private client credentials using configured secure storage. Browser-based AS login uses secure session cookies with `HttpOnly`, `Secure`, `SameSite` appropriate to the flow, CSRF protection and session invalidation. Prevent cross-user consent CSRF and open redirects.
- **Revocation:** RFC 7009 for refresh/access token revocation; owner/admin grant revocation propagates to all tokens derived from it. If remote replicas temporarily cannot access the revocation/grant state, use a strict maximum cache staleness and fail closed where freshness is required. Never claim instant cross-replica revocation unless the installation actually provides it.
- **Client authentication:** support securely stored `client_secret_basic` where needed and prefer `private_key_jwt` or mTLS for privileged automation. Keep confidential client secrets issuer-specific. DPoP (RFC 9449) or mTLS sender-constrained access tokens are optional hardening where clients and deployment can support them, not assumptions about all MCP clients.
- **Resource access headers:** missing/invalid token => HTTP 401 with RFC 6750 `WWW-Authenticate` and RFC 9728 `resource_metadata`; valid token but missing scope => HTTP 403 `insufficient_scope` with the required scope and an OAuth **step-up path** as supported by the client. For missing identity membership, avoid enumeration: inaccessible/hidden content returns a non-disclosing 404 while genuine known-identity action denial may return 403.
- **Audit:** record owner/client/grant changes, requested and granted scopes/identity IDs, issuance/refresh/step-up/revocation and denied privileged sends; do not log token values, mail bodies, OTPs or private policy matcher details.
- **Standalone:** a single Corvi process can serve issuer + protected resource with local encrypted persistent state (embedded **SQLite** plus separately protected secret-key custody, per [ADR-0010](0010-storage-and-durability.md)) and trusted owner login. Persistent issuance/refresh/grant state is **required if OAuth AS is enabled**, even when the underlying mail transport otherwise requires no DB. In-memory-only ephemeral AS mode must not promise durable refresh or revocation after restart. External-issuer-only resource-server deployments may run without built-in AS state, but still need reliable Corvi identity-grant resolution.

## 6. SMTP AUTH interaction

SMTP AUTH remains a separately authenticated client-submission protocol using scoped `MailCredential` material. An OAuth bearer token for HTTP REST/MCP **does not automatically work as a SMTP password**.

Optionally, support SMTP SASL `OAUTHBEARER` with an explicitly enabled **Corvi SMTP audience**, a transport-approved token profile, independent `mail:messages:send` grants and sender restrictions. Only advertise OAuth SASL if fully implemented and validated. Existing SMTP app/credential authentication remains supported. Public mail issuance, web consent and OAuth token endpoints are not exposed as raw SMTP commands.

The upstream submission may still use SMTP or JMAP, each with **separate upstream credentials** (ADR-0007/0008).

## 7. External OIDC federation and multiple trusted issuers

Existing IdPs like Kanidm can provide user authentication through OIDC. In brokered mode, the user authenticates with the external IdP; the Corvi AS establishes a secured owner session, displays **Corvi-specific identity grants**, and mints access tokens for the Corvi mail-resource audience.

In direct external-AS mode, accept only **preconfigured trusted** issuers with a validated Corvi audience, exact issuer binding, enabled OAuth client identity (where available) and server-side Corvi grant mapping; **never accept an arbitrary OIDC ID token** or an access token originally intended for the upstream IdP's own APIs. External `groups` or roles may influence an admin-controlled grant policy but cannot directly expand access to all Corvi mail identities. Resolve stable subject IDs by the pair (`iss`, `sub`), not email address alone. If fine-grained consent cannot be enforced externally, brokered authorization is preferred.

MCP protected-resource metadata may advertise multiple trusted AS issuer URLs when explicitly configured. Clients choose one using the MCP protocol's discovery and issuer binding, with no credentials reused across issuers. The authorization server for a selected request must be consistently bound to the `iss` response, stored client credentials, token `iss`, consent and grant reference.

## 8. Tests and release gates

1. A new MCP client can discover Corvi's RFC 9728 protected-resource metadata and the AS's RFC 8414 metadata, use CIMD or a registered client, complete Authorization Code + PKCE, consent to selected identity/action combinations, and receive a Corvi-audience access token.
2. A single token authorizes read on identity A (Fastmail/JMAP) and send on identity B (Migadu/SMTP) but cannot read B, send A, access identity C, or use an account's provider OAuth token as a Corvi bearer.
3. A client requesting only `mail:messages:list` cannot read contents, obtain attachments or send mail. An OAuth scope alone with no authorized identity yields no mailbox access.
4. Scope **step-up** for a new action/identity requires new owner consent; failed/declined step-up preserves existing grants but cannot widen them.
5. Consent revocation, client disablement, identity deletion, policy narrowing and JWT/opaque-token replay all fail closed for every public mail access, including MCP subscriptions, Tasks and MRTR confirmations.
6. Client Credentials is accepted only for administrator-provisioned confidential service clients with permitted identity/action sets; it never impersonates an owner by default or bypasses send approval merely because a machine issued the token.
7. Test CIMD SSRF restrictions, client metadata origin/redirect binding, unknown or stale client metadata, wrong owner, PKCE failure, wrong redirect, arbitrary issuer mix-up, forged authorization details and consent CSRF.
8. DCR, if enabled for legacy MCP, must enforce client metadata validation, rate limits and no unauthorized privileges. An issuer must not leak a confidential client secret to an unknown public client.
9. Refresh rotation, old-token reuse detection, grant narrowing and revocation persist over process restart; multi-replica stale/grant caches cannot outlive configured maximum freshness.
10. JWT mode, if enabled, rejects wrong `typ`, signature/algorithm, `aud`, `iss`, `exp`, inactive grant, missing `client_id`, untrusted key and excessive/stale grant claims.
11. REST/MCP mail-resource tokens cannot authenticate to admin management APIs, provider onboarding callbacks, upstream JMAP/IMAP, other OAuth issuers or the SMTP AUTH listener unless separately explicitly scoped for an implemented SMTP OAuth mode.
12. External OIDC authentication does not silently mint broad mail tokens; group membership and displayed email addresses cannot substitute for owner/client/identity consent.
13. The standalone configuration supports owner interactive login, encrypted persistent refresh/revocation state and no mandatory external IdP/Kubernetes; turning off the built-in AS leaves an external resource-server trust mode possible.
14. Errors, logs, consent UI, MCP context resources, JWTs and audit records never reveal provider secrets, raw mail, PKCE code verifier, authorization code or refresh-token material.

## References

- [MCP 2026-07-28 Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
- [MCP 2026-07-28 release changes](https://blog.modelcontextprotocol.io/posts/2026-07-28/)
- [RFC 9700 OAuth Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700)
- [RFC 9396 Rich Authorization Requests](https://www.rfc-editor.org/rfc/rfc9396)
- [RFC 8707 Resource Indicators](https://www.rfc-editor.org/rfc/rfc8707)
- [RFC 9728 Protected Resource Metadata](https://www.rfc-editor.org/rfc/rfc9728)
- [RFC 8414 Authorization Server Metadata](https://www.rfc-editor.org/rfc/rfc8414)
- [RFC 9068 JWT Access Token Profile](https://www.rfc-editor.org/rfc/rfc9068)
- [RFC 7009 Token Revocation](https://www.rfc-editor.org/rfc/rfc7009)
- [RFC 7662 Token Introspection](https://www.rfc-editor.org/rfc/rfc7662)
- [RFC 8628 Device Authorization](https://www.rfc-editor.org/rfc/rfc8628)
- [RFC 9207 Authorization Server Issuer Identification](https://www.rfc-editor.org/rfc/rfc9207)

## Consequences

Corvi becomes both a reliable OAuth-protected mail resource server and, optionally, an OAuth authorization service with its own **per-app, per-mail-identity consent**. The design favors an integrated grant evaluator and optional federation over putting every mailbox permission in external IdP groups or long-lived JWT claims. It adds durable AS token/grant state where enabled but never creates a mandatory control-plane dependency for the minimal IMAP/SMTP/JMAP gateway.

---
This ADR is an implementation proposal, not a deployed issuer or live OAuth endpoint.
