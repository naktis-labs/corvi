# ADR-0008: Interactive OAuth onboarding for upstream mail providers

- **Status:** Proposed (not implemented)
- **Date:** 2026-11-16
- **Scope:** User-authorized OAuth connections from Corvi to upstream mail accounts, including JMAP, IMAP and SMTP
- **Related:** [ADR-0001](0001-corvi-system-architecture.md), [ADR-0005](0005-public-mail-api.md), [ADR-0006](0006-local-transport-bridges.md), [ADR-0007](0007-native-jmap-transport.md)
- **Machine-readable provider connection descriptor:** [`api/upstream-oauth.schema.json`](../../api/upstream-oauth.schema.json)

## Decision

**Corvi SHALL support interactive OAuth 2.0 authorization against mail providers that offer it** as a first-class way to connect upstream accounts. A user or authorized administrator chooses a provider/account, explicitly consents at the **provider's own authorization server**, and Corvi exchanges the resulting authorization code and stores a protected upstream connection. The user must not have to paste account passwords or manually create provider API tokens when a supported provider OAuth integration is available.

Interactive **upstream provider OAuth** is a **separate trust domain** from client→Corvi OAuth/OIDC, Corvi service tokens, SMTP AUTH credentials, MCP authorization, and provider-management administrator credentials. Corvi's **own OAuth authorization server, client consent and per-identity grants** are specified separately in [ADR-0009](0009-corvi-oauth-and-identity-grants.md). A provider's access/refresh token is **never** accepted as a Corvi public API token, sent to an MCP/REST client or agent, copied into tool results, or used as a broad client authorization grant. Provider consent establishes what *Corvi* can access upstream; Corvi's `MailCredential`, `MailIdentity`, `MailPolicy` and `MailFilterPolicy` independently decide what each agent/application may see or do.

The **gateway's public seven REST operations and seven MCP mail tools do not change**. Client-facing OAuth authorization and the provider-onboarding browser consent endpoint may be hosted in one binary but maintain separate issuer/account bindings, credentials, resource audiences and permissions (ADR-0009). Upstream connection administration belongs to an authenticated, separately authorized management/onboarding interface. A standalone CLI/UI may expose the same connection workflow locally without requiring Kubernetes or an always-on controller.

## 1. Provider authentication capabilities and fallback

Every upstream provider/transport declares and validates its **actual** supported onboarding methods:

| Method | Availability / purpose |
| --- | --- |
| `oauthAuthorizationCode` | Preferred interactive browser flow with **PKCE S256** (RFC 7636, RFC 9700) when provider supports it |
| `oauthDeviceCode` | Optional device authorization grant (RFC 8628) **only if advertised by the provider**; ideal for headless/server environments |
| `oauthNativeLoopback` | Local companion CLI/browser flow with loopback redirect **only if registered/permitted by the provider** |
| `apiToken` | Explicitly supplied JMAP/provider API token for non-OAuth setups or providers without supported interactive registration |
| `appPassword` / `password` | Scoped IMAP/SMTP app password as a fallback when provider OAuth is unavailable or unsupported, never the user's primary password by default |
| `bridgeEnrollment` | Provider-specific local bridge account/session enrollment, e.g. Proton Mail Bridge; **not interchangeable with OAuth** unless officially supported |

`oauthNativeLoopback` is a deployment variant of **authorization code + PKCE**, not an independent OAuth grant. Legacy implicit grant, resource-owner password credentials (ROPC), arbitrary code/token pasting and OAuth tokens in callback query arguments are **not supported**. Do not downgrade silently from a failing OAuth flow to a password, token or bridge session.

Provider-specific capabilities must include registered/granted client type, redirect URI restrictions, upstream scopes, refresh/offline permission requirements, and transport authentication mechanisms. A provider's lack of public client registration or device grant MUST be surfaced as a deployment constraint rather than hidden behind an allegedly generic OAuth button.

## 2. Interactive authorization flows

### A. Hosted browser callback: standalone web/controller or Kubernetes

1. An authenticated **Corvi account owner or provider-connection administrator** initiates `Connect Mail Account` through a privileged control-plane/onboarding API. They choose provider, intended upstream account(s), requested read/send capability set and a **known allowed callback origin**.
2. Corvi loads trusted issuer/client metadata and pre-registered redirect URI(s), generates one-time unguessable `state`, fresh PKCE `code_verifier`/`S256` challenge and optionally OIDC `nonce`, binds them to the authenticated onboarding principal, provider issuer, intended local account, client ID, exact redirect URI, scope request and short expiry. Securely persist this transaction before redirecting.
3. Corvi returns the provider authorization URL to the authenticated browser. The user signs in **at the mail provider** and explicitly approves the requested scopes. Corvi never collects upstream account passwords.
4. The provider redirects to a **fixed, explicitly registered HTTPS callback**, e.g. `https://auth.corvi.naktis.eu/oauth/upstream/callback/fastmail` **as an illustrative deployment hostname, not a required public service**. The callback verifies the transaction, CSRF binding/`state`, issuer mix-up protection, exact redirect URI/client ID, one-time code, and error/result. It must not rely solely on an untrusted browser-supplied `provider` argument.
5. Corvi exchanges the code **server-side** with PKCE at the trusted provider token endpoint using the correct public/confidential-client authentication, checks response scope/resource constraints and securely stores encrypted token material. Neither authorization codes nor tokens appear in browser HTML, redirect URLs, logs, metrics or public API replies.
6. Corvi validates upstream account identity and actual protocol permissions (JMAP Session `accounts`/`accountCapabilities`, IMAP/SMTP SASL token acceptance or provider-specific authorized-account probe). It then creates/updates a **provider connection** with status and secret references, and binds it to the intended physical `Mailbox` only after explicit identity/account confirmation and authorization.
7. Corvi returns a safe status (e.g. `connected`, `needsConsent`, `scopeInsufficient`) to the **authorized management UI**, never a token. Other agents cannot discover the account merely because it was connected.

**Fastmail constraint:** Its published docs distinguish native clients with loopback/private-use redirect URIs from clients with a **public HTTPS redirect**, which require prior registration with Fastmail. Do **not** assume an arbitrary self-hosted `https://auth.corvi.naktis.eu/...` callback will be accepted without registration. Provider registration details and redirect values must be configured ahead of time. Fastmail can also support its documented public-client metadata/profile options where applicable.

### B. Local companion CLI: standalone/headless-remote-friendly

Use an administrator-invoked **local** `corvi provider login <provider>` command or companion helper that can (when supported) register/use a native OAuth client and bind a loopback listener to `127.0.0.1`/`[::1]` on the user's machine, launch the browser, and complete authorization code + PKCE locally.

For a remote Corvi gateway, a `localhost` redirect refers to the **computer running the browser/CLI, not the remote server or its Kubernetes Pod**. A separately authenticated, one-time short-lived **connection-import/authorization handoff** is therefore required to deliver credentials securely to the controller/data-plane secret store; the transport must be encrypted, authenticated, recipient-bound and resistant to replay. Never put provider access/refresh tokens in shell command arguments, clipboard content, agent prompts, WebSocket/HTTP URL fragments or ordinary logs. Do not expose an unauthenticated `/oauth/import` endpoint, nor tunnel a localhost callback through a public proxy without proper host/callback validation.

The CLI helper authenticates to Corvi's **administrative/onboarding** interface for this handoff, not through a mailbox-scoped MCP bearer token. If a provider's native public-client scheme cannot be safely used for server-side token storage/refresh or remote import, disable this mode for that provider and document the supported alternative.

### C. Device authorization: provider-specific optional flow

If the provider publishes a device authorization endpoint/grant, let the admin initiate a short-lived device flow with `verification_uri`, `user_code` and permitted polling interval. The provider authenticates the user in a separate browser, while the authenticated Corvi controller polls according to RFC 8628 (`authorization_pending`, `slow_down`, `expired_token`, denial). Protect device-code storage and revalidate the initiating Corvi admin when finalizing account binding. **Do not claim Fastmail supports device grant without provider evidence.**

## 3. OAuth discovery, registration and security boundaries

Use an explicit provider profile, optionally populated from trusted authorization-server metadata (RFC 8414), as the source of:

- Authorization, token, revocation, introspection (if any), device and registration endpoints; issuer and supported grant types.
- Public/confidential client type, pre-registered client ID and authenticated confidential-client secret/certificate references, allowable redirect URIs and client registration mode (`preRegistered`, `clientIdMetadata`, `dynamic`, `nativeOpenClient`).
- Supported upstream permission bundles: e.g. `jmapMailRead`, `jmapSubmission`, `imapRead`, `smtpSend`; exact upstream OAuth scope strings and provider-specific authentication mechanisms.
- Required offline access/refresh behavior, token endpoint authentication method, requested resource indicators where applicable, token renewal constraints, and account identity verification strategy.

**Security requirements**:

- Implement RFC 9700 OAuth security best current practice: **PKCE S256 for all authorization code clients**, unguessable one-time state bound to the initiating Corvi administrator/browser session, exact redirect URI matching and issuer/mix-up protections (RFC 9207 `iss` or otherwise provider-bound redirect URI/endpoint). Do not accept credentials from an arbitrary discovered authorization endpoint.
- Approved provider/issuer/redirect allowlists; HTTPS issuer/authorization/token/resource URLs; DNS/redirect/SSRF protection, including any discovery/reconnect URLs. Only explicitly permitted loopback callbacks may use HTTP. Verify certificates; no blanket `insecure_skip_verify`.
- Confidential client credentials are managed secrets. A provider-supplied image/OCI metadata can **advertise** OAuth capabilities but may not authorize registering a new OAuth client, creating public callbacks, broadening scopes, invoking arbitrary external URLs, or accessing stored tokens. Verify gRPC capability discovery and administrator policy first.
- Avoid asking for more provider scopes than the intended transport/actions need; show read/send differences in consent UI. Do not assume the provider scopes equal Corvi action grants or that consent alone permits any Corvi agent to act.
- Bind onboarding to a privileged Corvi owner/administrator. The actual authorized **upstream account** must be validated after token exchange to prevent binding an attacker's account or a different provider account under a requested Corvi identity. Treat provider profile, authenticated principal, provider subject/account and local mailbox mapping as separate identifiers.
- Reconnect/re-consent must not silently reassign existing Corvi `MailIdentity` grants or expand agent access to new physical mailboxes; changes to upstream account owner, issuer or privilege require an explicit review.

## 4. Credentials, refresh, revocation and storage

Each connection stores metadata separately from a **provider credential secret**. [ADR-0010](0010-storage-and-durability.md) defines SQLite/PostgreSQL metadata persistence and an independent, encrypted `SecretStore` for provider access/refresh tokens, with a wrapping key outside ordinary database backups. The normal metadata includes `connectionId`, provider ID, transport/account binding, upstream account identifier (where safe), granted scopes and capability flags, opaque secret reference, expiry, refresh status, last validation time and generation.

- Encrypt access **and refresh** tokens at rest with an explicit encryption/key-management strategy; require protected file permissions in standalone mode and a configured Kubernetes Secret/KMS/external secret backend in clustered mode. In-memory access is restricted to the mail data plane (or a dedicated token broker) for upstream use. **Never store tokens in GitOps manifests, ordinary config snapshots, CRDs/status, OCI annotations, database debug logs, traces, Prometheus labels, MCP resources or agent-readable config.**
- The controller/onboarding component may receive the initial OAuth tokens when completing the grant, but must hand them off through a **separate scoped, authenticated secret-delivery interface** to the data-plane token store/broker. No provider admin token or personal mail body access is implied. Do not put raw provider refresh tokens into the ordinary non-secret snapshot publication channel.
- Proactively refresh upstream access tokens with bound refresh state, single-flight/concurrency-safe rotation and atomic persistence **before** treating the new token as active. Support refresh token rotation, revocation and replacement, clock skew, transient backoff and retries. Do not simultaneously refresh with the same rotated token from several replicas.
- Multi-replica installations require a single refresh owner or coordinated token broker/lease + atomic versioning, with cache invalidation. PostgreSQL is the authoritative state/lease backend for HA, while standalone mode may use embedded SQLite (ADR-0010). A local standalone process may refresh without an external service.
- On `invalid_grant`, denied refresh, revoked grant, account mismatch, scope loss or missing credential, mark the connection `needsReauthorization` and fail dependent upstream operations **closed**. Surface only non-sensitive status to authorized admins; do not automatically fall back to an earlier password or broaden privileges.
- Revocation/disconnect: remove Corvi's binding, invalidate cached upstream access tokens, revoke with the provider endpoint if advertised, securely delete local secret state and cancel affected long-running operations. Provider-side revoke is best-effort and not guaranteed by local deletion; report that distinction.
- Corvi client token revocation is **independent**: revoking an agent's `MailCredential` does not revoke the upstream account, while disconnecting an upstream account makes dependent operations unavailable even if their local identity grants still exist.

## 5. OAuth token use by protocol

| Transport | Upstream token use | Additional requirements |
| --- | --- | --- |
| JMAP read | `Authorization: Bearer <upstream-access-token>` on the HTTPS JMAP Session/API and approved blob endpoints | Verify Session accounts/capabilities, trusted URLs and account selection |
| JMAP send | Separate/combined upstream scope authorizing submission, plus sender `Identity` validation | A mail-read scope alone is not permission to send |
| IMAP | SASL `OAUTHBEARER` (RFC 7628) or provider-supported `XOAUTH2` | Must verify advertised/known mechanism, token audience, TLS and username/account mapping |
| SMTP | SASL `OAUTHBEARER` or provider-supported `XOAUTH2` | Separate send scope and envelope From/recipient policy enforced by Corvi |
| Bridge-backed IMAP/SMTP | Usually **bridge-local credentials**, with independent upstream account session management | Do not substitute a provider OAuth token for bridge credentials absent explicit bridge support |

Fastmail supports OAuth for its documented protocols and JMAP Authorization Code flows, with provider-specific registration restrictions. Gmail supports OAuth2/XOAUTH2 for IMAP/SMTP; its broad `https://mail.google.com/` scope and application verification requirements must be considered, not hidden behind generic scopes. Microsoft 365 supports OAuth delegated IMAP and SMTP authentication with their **distinct** Outlook resource scopes and can offer authorization-code or supported device grant. No provider is presumed to support all OAuth grant types, token refresh, every scope or native JMAP.

## 6. Administrative onboarding endpoints (provisional, not in public OpenAPI v1)

Keep account connection operations in a separate **provider-onboarding/admin** API surface, never in the personal mail `/v1/messages` REST API or MCP `mail_*` catalogue. Illustrative endpoint names below are **not** implemented routes or final contracts:

| Action | Illustrative management operation | Permission |
| --- | --- | --- |
| Discover OAuth support | `GET /admin/v1/providers/{providerId}/auth-capabilities` | `provider:connections:inspect` |
| Start interactive consent | `POST /admin/v1/provider-connections/oauth/start` | `provider:connections:create` |
| OAuth callback | `GET /oauth/upstream/callback/{providerId}` | One-time state, exact provider/client binding; **not** a standalone unauthenticated admin action |
| Inspect connection status | `GET /admin/v1/provider-connections/{connectionId}` | `provider:connections:inspect` with connection ownership |
| Reauthorize / disconnect | `POST .../reauthorize`, `DELETE .../{connectionId}` | `provider:connections:manage` with ownership |

A user allowed to read an already connected mailbox is **not automatically** allowed to initiate provider OAuth, inspect provider scopes/identities, reconnect an account or extract tokens. Do not accidentally expose OAuth onboarding through the public MCP mail server or the agent skill as a mailbox access shortcut.

## 7. Examples and provider registration notes

**Fastmail**: configured native JMAP `read: jmap` / `submission: jmap` with a browser-based OAuth grant, separately requested JMAP mail/submission scopes, secure token storage and account validation. Its currently documented native/loopback registration behavior differs from a hosted HTTPS redirect. The exact client registration mode must be selected to match the actual deployment; Fastmail's official OAuth documentation must be used and verified before enabling a hosted callback.

**Gmail**: `read: imap` / `submission: smtp` with an appropriately registered Google OAuth client. Use provider-supported SASL XOAUTH2 with access tokens; validate Google's scope/verification and offline-access behavior. A Google/Gmail mail account cannot be connected by presenting a Google ID token to Corvi's API.

**Microsoft 365 / Outlook**: `read: imap` / `submission: smtp` with Microsoft Entra delegated OAuth and independently requested `IMAP.AccessAsUser.All` and `SMTP.Send` scopes. Tenant/admin consent, mailbox protocol settings and SMTP AUTH policy can restrict actual availability; don't assume granted OAuth scopes override provider-side mail configuration.

**Proton Bridge**: use the supported bridge enrollment/session and local credentials route from ADR-0006. Only implement interactive OAuth for Proton bridge enrollment if a supported official interface is documented and tested.

## 8. Release gates and tests

1. Local/hosted Authorization Code + PKCE works, rejects state/code replay, unsolicited callback, wrong browser/admin, cross-issuer response, wrong redirect/client ID, missing PKCE and malicious token URL.
2. Provider capability discovery correctly distinguishes supported/unsupported grant types, registration modes, offline access and independently needed read/send scopes.
3. One Corvi client can read from a Fastmail/JMAP account and an IMAP/XOAUTH2 account, each connected through OAuth but exposed under independent Corvi identity grants.
4. An agent's Corvi token **cannot** call provider-management OAuth onboarding endpoints, retrieve a provider access token, use callback state, or broaden any identity grant.
5. Native/loopback redirect callback works on the **local CLI machine** and can securely hand off an approved connection to a remote standalone/controller deployment without exposing tokens in URL/history or to an unauthenticated import route.
6. Device-code mode is enabled only for a provider advertising RFC 8628 support; error/polling handling respects rate limits.
7. Refresh token rotation/atomicity and concurrent replicas cannot lose or reuse a rotated token or cause credential disclosure.
8. Upstream `invalid_grant`, authorization scope loss, provider revoke, account change or expired credentials fail closed and prompt authorized operator reauthorization.
9. An upstream connection may serve multiple Corvi identities, but connecting/remapping/reconnecting never silently changes existing identity grants or revives a revoked client credential.
10. Auth logs, MCP tool results/context resources, OpenAPI error bodies, provider status, CRD snapshots, telemetry and debug traces never include authorization code, access/refresh tokens, provider session cookies or client secrets.
11. Disconnect removes the protected upstream binding, attempts provider revocation where supported, invalidates affected cache/sync and independently preserves revocation of Corvi client access.
12. Generic app password and existing bridge configurations remain supported; OAuth support does not require Kubernetes, an external database or provider plugin for a standalone gateway.

## References

- [ADR-0009: Corvi client OAuth authorization and grants](0009-corvi-oauth-and-identity-grants.md)
- [RFC 9700: OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700)
- [RFC 7636: Proof Key for Code Exchange](https://www.rfc-editor.org/rfc/rfc7636)
- [RFC 8628: Device Authorization Grant](https://www.rfc-editor.org/rfc/rfc8628)
- [RFC 8414: Authorization Server Metadata](https://www.rfc-editor.org/rfc/rfc8414)
- [RFC 9207: OAuth 2.0 Authorization Server Issuer Identification](https://www.rfc-editor.org/rfc/rfc9207)
- [Fastmail API and OAuth](https://www.fastmail.com/dev/)
- [Google Gmail IMAP/SMTP OAuth2](https://developers.google.com/workspace/gmail/imap/xoauth2-protocol)
- [Microsoft OAuth for IMAP/SMTP](https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth)

## Consequences

Interactive provider consent improves onboarding and replaces manual long-lived credentials where the provider supports it. It adds a security-sensitive OAuth redirect/token lifecycle with account binding, encrypted refresh state and provider-specific registration constraints. **It does not turn Corvi into an upstream authorization server**, make provider credentials visible to agents, or weaken the standalone, policy-scoped data-plane design.
