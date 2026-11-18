//! The authorization code flow, the consent it produces and the tokens it
//! issues.
//!
//! These are the tests of the protocol itself: they drive the issuer the
//! way an HTTP layer would, and they check the refusals the ADR asks for.

use mail_auth::client::{ClientRegistration, ClientType};
use mail_auth::config::{AuthConfig, GrantType, PkceMethod};
use mail_auth::consent::{Allowances, AuthorizationDetail, IdentityAllowance};
use mail_auth::error::AuthError;
use mail_auth::issuer::{AuthorizationRequest, Issuer, RevocationRequest, TokenRequest};
use mail_auth::pkce::s256_challenge;
use mail_auth::resource::ResourceServer;
use mail_auth::store::GrantState;
use mail_auth::testing::MemoryGrantState;

use mail_core::Action;
use mail_storage::grants::AccessToken;

const KEY: &[u8] = b"a deployment key that is long enough to be a key";
const ADMIN_SECRET: &str = "the administrator secret";
/// The hash of `ADMIN_SECRET` under `KEY`, as the deployment keeps it.
const ADMIN_HASH: &str = "d829e7cf5fc69172ec502f235ac08b6c3e3f43c49b355f33010650e74f52eb4b";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const NOW: u64 = 1_700_000_000;

/// The fixture of a running issuer.
struct Fixture {
    config: AuthConfig,
    state: MemoryGrantState,
}

impl Fixture {
    /// Build the fixture and provision the clients.
    fn new() -> Self {
        let fixture = Self {
            config: config(),
            state: MemoryGrantState::durable(),
        };
        let mut issuer = fixture.issuer();
        issuer
            .clients()
            .provision(
                registration("public-client", ClientType::Public),
                ADMIN_SECRET,
            )
            .expect("the public client is provisioned");
        issuer
            .clients()
            .provision(
                registration("confidential-client", ClientType::Confidential),
                ADMIN_SECRET,
            )
            .expect("the confidential client is provisioned");
        fixture
    }

    /// An issuer over the same state.
    fn issuer(&self) -> Issuer<'_> {
        let mut issuer = Issuer::new(&self.config, &self.state, KEY, Some(ADMIN_HASH))
            .expect("the issuer starts");
        issuer
            .clients()
            .provision(
                registration("public-client", ClientType::Public),
                ADMIN_SECRET,
            )
            .expect("the public client is provisioned");
        issuer
            .clients()
            .provision(
                registration("confidential-client", ClientType::Confidential),
                ADMIN_SECRET,
            )
            .expect("the confidential client is provisioned");
        issuer
    }
}

/// A configuration with one public and one confidential client.
fn config() -> AuthConfig {
    let mut config =
        AuthConfig::integrated("https://auth.corvi.example", "https://mail.corvi.example");
    config.client_registration.client_id_metadata_documents = true;
    config
}

/// The allowances of the owner: read on one identity, send on the other.
fn allowances() -> Allowances {
    Allowances::new([
        IdentityAllowance {
            identity_id: "identity-a".to_owned(),
            actions: vec![Action::List, Action::Read],
        },
        IdentityAllowance {
            identity_id: "identity-b".to_owned(),
            actions: vec![Action::Send],
        },
    ])
}

fn registration(client_id: &str, client_type: ClientType) -> ClientRegistration {
    ClientRegistration {
        client_id: client_id.to_owned(),
        name: format!("the {client_id} client"),
        client_type,
        redirect_uris: vec!["https://client.example/callback".to_owned()],
        grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
        allowed_actions: vec![Action::List, Action::Read, Action::Send],
        allowed_identity_ids: vec!["identity-a".to_owned(), "identity-b".to_owned()],
        secret: match client_type {
            ClientType::Public => None,
            ClientType::Confidential => Some("the client secret".to_owned()),
        },
    }
}

/// A fixture with both clients provisioned.
fn fixture() -> Fixture {
    Fixture::new()
}

/// An authorization request that asks for read on one identity and send on
/// the other.
fn request() -> AuthorizationRequest {
    AuthorizationRequest {
        issuer: "https://auth.corvi.example".to_owned(),
        client_id: "public-client".to_owned(),
        redirect_uri: "https://client.example/callback".to_owned(),
        response_type: "code".to_owned(),
        scope: vec![
            "mail:messages:list".to_owned(),
            "mail:messages:read".to_owned(),
        ],
        state: Some("the state".to_owned()),
        code_challenge: s256_challenge(VERIFIER),
        code_challenge_method: "S256".to_owned(),
        resource: Some("https://mail.corvi.example".to_owned()),
        authorization_details: Vec::new(),
    }
}

/// The token request that exchanges a code.
fn token_request(code: &str, verifier: &str) -> TokenRequest {
    TokenRequest {
        grant_type: "authorization_code".to_owned(),
        client_id: "public-client".to_owned(),
        client_secret: None,
        code: Some(code.to_owned()),
        code_verifier: Some(verifier.to_owned()),
        redirect_uri: Some("https://client.example/callback".to_owned()),
        refresh_token: None,
        resource: Some("https://mail.corvi.example".to_owned()),
    }
}

/// Authorize and exchange, and return the token response.
fn complete_flow(fixture: &Fixture) -> mail_auth::issuer::TokenResponse {
    let authorized = fixture
        .issuer()
        .authorize(
            &request(),
            "owner-1",
            &allowances(),
            &["identity-a".to_owned()],
            NOW,
        )
        .expect("the authorization succeeds");
    fixture
        .issuer()
        .token(&token_request(&authorized.code, VERIFIER), NOW)
        .expect("the exchange succeeds")
}

#[test]
fn the_authorization_code_flow_issues_a_token() {
    let fixture = fixture();
    let response = complete_flow(&fixture);
    assert!(response.access_token.starts_with("cat1."));
    assert_eq!(response.token_type, "Bearer");
    assert_eq!(
        response.expires_in,
        fixture.config.access_token_lifetime_seconds
    );
    assert!(response.refresh_token.is_some());
    assert_eq!(response.issuer, "https://auth.corvi.example");
    assert_eq!(response.scope, "mail:messages:list mail:messages:read");
}

#[test]
fn the_state_comes_back_unchanged() {
    let fixture = fixture();
    let authorized = fixture
        .issuer()
        .authorize(
            &request(),
            "owner-1",
            &allowances(),
            &["identity-a".to_owned()],
            NOW,
        )
        .expect("the authorization succeeds");
    assert_eq!(authorized.state, Some("the state".to_owned()));
}

#[test]
fn the_plain_code_challenge_method_is_refused() {
    let fixture = fixture();
    let mut request = request();
    request.code_challenge_method = "plain".to_owned();
    request.code_challenge = VERIFIER.to_owned();
    assert!(matches!(
        fixture.issuer().authorize(
            &request,
            "owner-1",
            &allowances(),
            &["identity-a".to_owned()],
            NOW
        ),
        Err(AuthError::UnsupportedPkceMethod(_))
    ));
}

#[test]
fn an_unknown_code_challenge_method_is_refused() {
    let fixture = fixture();
    let mut request = request();
    request.code_challenge_method = "S512".to_owned();
    assert!(matches!(
        fixture.issuer().authorize(
            &request,
            "owner-1",
            &allowances(),
            &["identity-a".to_owned()],
            NOW
        ),
        Err(AuthError::InvalidPkce(_))
    ));
}

#[test]
fn a_malformed_code_challenge_is_refused() {
    let fixture = fixture();
    let mut request = request();
    request.code_challenge = "not a challenge".to_owned();
    assert!(matches!(
        fixture.issuer().authorize(
            &request,
            "owner-1",
            &allowances(),
            &["identity-a".to_owned()],
            NOW
        ),
        Err(AuthError::InvalidPkce(_))
    ));
}

#[test]
fn an_unregistered_redirect_uri_is_refused() {
    let fixture = fixture();
    for redirect_uri in [
        "https://client.example/callback/extra",
        "https://client.example/other",
        "https://attacker.example/callback",
    ] {
        let mut request = request();
        request.redirect_uri = redirect_uri.to_owned();
        assert!(
            matches!(
                fixture.issuer().authorize(
                    &request,
                    "owner-1",
                    &allowances(),
                    &["identity-a".to_owned()],
                    NOW
                ),
                Err(AuthError::InvalidRedirectUri(_))
            ),
            "the redirect uri {redirect_uri:?} should have been refused"
        );
    }
}

#[test]
fn a_request_bound_to_another_issuer_is_refused() {
    let fixture = fixture();
    let mut request = request();
    request.issuer = "https://attacker.example".to_owned();
    assert!(matches!(
        fixture.issuer().authorize(
            &request,
            "owner-1",
            &allowances(),
            &["identity-a".to_owned()],
            NOW
        ),
        Err(AuthError::IssuerMismatch(_))
    ));
}

#[test]
fn an_authorization_code_is_exchanged_exactly_once() {
    let fixture = fixture();
    let authorized = fixture
        .issuer()
        .authorize(
            &request(),
            "owner-1",
            &allowances(),
            &["identity-a".to_owned()],
            NOW,
        )
        .expect("the authorization succeeds");
    fixture
        .issuer()
        .token(&token_request(&authorized.code, VERIFIER), NOW)
        .expect("the first exchange succeeds");
    assert!(matches!(
        fixture
            .issuer()
            .token(&token_request(&authorized.code, VERIFIER), NOW),
        Err(AuthError::InvalidGrant(_))
    ));
}

#[test]
fn a_replayed_code_with_another_verifier_is_refused() {
    let fixture = fixture();
    let authorized = fixture
        .issuer()
        .authorize(
            &request(),
            "owner-1",
            &allowances(),
            &["identity-a".to_owned()],
            NOW,
        )
        .expect("the authorization succeeds");
    fixture
        .issuer()
        .token(&token_request(&authorized.code, VERIFIER), NOW)
        .expect("the first exchange succeeds");
    let other_verifier = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    assert!(matches!(
        fixture
            .issuer()
            .token(&token_request(&authorized.code, other_verifier), NOW),
        Err(AuthError::InvalidGrant(_))
    ));
}

#[test]
fn a_wrong_code_verifier_is_refused() {
    let fixture = fixture();
    let authorized = fixture
        .issuer()
        .authorize(
            &request(),
            "owner-1",
            &allowances(),
            &["identity-a".to_owned()],
            NOW,
        )
        .expect("the authorization succeeds");
    assert!(matches!(
        fixture.issuer().token(
            &token_request(
                &authorized.code,
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            ),
            NOW
        ),
        Err(AuthError::InvalidPkce(_))
    ));
}

#[test]
fn a_code_is_bound_to_the_redirect_uri_it_was_issued_for() {
    let fixture = fixture();
    let authorized = fixture
        .issuer()
        .authorize(
            &request(),
            "owner-1",
            &allowances(),
            &["identity-a".to_owned()],
            NOW,
        )
        .expect("the authorization succeeds");
    let mut exchange = token_request(&authorized.code, VERIFIER);
    exchange.redirect_uri = Some("https://client.example/other".to_owned());
    assert!(matches!(
        fixture.issuer().token(&exchange, NOW),
        Err(AuthError::InvalidRedirectUri(_))
    ));
}

#[test]
fn a_scope_outside_the_identity_allowance_is_refused() {
    let fixture = fixture();
    let mut request = request();
    request.scope = vec!["mail:messages:send".to_owned()];
    assert!(matches!(
        fixture.issuer().authorize(
            &request,
            "owner-1",
            &allowances(),
            &["identity-a".to_owned()],
            NOW
        ),
        Err(AuthError::InvalidScope(_))
    ));
}

#[test]
fn the_authorization_details_are_one_per_identity_and_never_merged() {
    let fixture = fixture();
    let mut request = request();
    request.scope = vec![
        "mail:messages:list".to_owned(),
        "mail:messages:read".to_owned(),
        "mail:messages:send".to_owned(),
    ];
    request.authorization_details = vec![
        AuthorizationDetail {
            identity_id: "identity-a".to_owned(),
            actions: vec![Action::List, Action::Read],
            constraints: None,
        },
        AuthorizationDetail {
            identity_id: "identity-b".to_owned(),
            actions: vec![Action::Send],
            constraints: None,
        },
    ];
    let authorized = fixture
        .issuer()
        .authorize(
            &request,
            "owner-1",
            &allowances(),
            &["identity-a".to_owned(), "identity-b".to_owned()],
            NOW,
        )
        .expect("the authorization succeeds");
    assert_eq!(authorized.grant_ids.len(), 2);
    let response = fixture
        .issuer()
        .token(&token_request(&authorized.code, VERIFIER), NOW)
        .expect("the exchange succeeds");
    assert_eq!(response.authorization_details.len(), 2);
    let first = &response.authorization_details[0];
    let second = &response.authorization_details[1];
    assert_eq!(first["type"], "corvi_mail");
    assert_eq!(first["identityId"], "identity-a");
    assert_eq!(
        first["actions"],
        serde_json::json!(["mail:messages:list", "mail:messages:read"])
    );
    assert_eq!(second["identityId"], "identity-b");
    assert_eq!(second["actions"], serde_json::json!(["mail:messages:send"]));
    assert!(
        !first["actions"]
            .as_array()
            .expect("the actions are listed")
            .contains(&serde_json::json!("mail:messages:send"))
    );
}

#[test]
fn a_public_client_may_not_present_a_secret_at_the_token_endpoint() {
    let fixture = fixture();
    let authorized = fixture
        .issuer()
        .authorize(
            &request(),
            "owner-1",
            &allowances(),
            &["identity-a".to_owned()],
            NOW,
        )
        .expect("the authorization succeeds");
    let mut exchange = token_request(&authorized.code, VERIFIER);
    exchange.client_secret = Some("a secret".to_owned());
    assert!(matches!(
        fixture.issuer().token(&exchange, NOW),
        Err(AuthError::InvalidClient(_))
    ));
}

#[test]
fn a_confidential_client_must_present_its_secret() {
    let fixture = fixture();
    let mut request = request();
    request.client_id = "confidential-client".to_owned();
    let authorized = fixture
        .issuer()
        .authorize(
            &request,
            "owner-1",
            &allowances(),
            &["identity-a".to_owned()],
            NOW,
        )
        .expect("the authorization succeeds");
    let mut exchange = token_request(&authorized.code, VERIFIER);
    exchange.client_id = "confidential-client".to_owned();
    assert!(matches!(
        fixture.issuer().token(&exchange, NOW),
        Err(AuthError::InvalidClient(_))
    ));
    exchange.client_secret = Some("the wrong secret".to_owned());
    assert!(matches!(
        fixture.issuer().token(&exchange, NOW),
        Err(AuthError::InvalidClient(_))
    ));
    exchange.client_secret = Some("the client secret".to_owned());
    assert!(fixture.issuer().token(&exchange, NOW).is_ok());
}

#[test]
fn a_refresh_token_rotates_and_the_old_one_is_refused() {
    let fixture = fixture();
    let response = complete_flow(&fixture);
    let refresh_token = response.refresh_token.expect("a refresh token is issued");
    let mut refresh = TokenRequest {
        grant_type: "refresh_token".to_owned(),
        client_id: "public-client".to_owned(),
        client_secret: None,
        code: None,
        code_verifier: None,
        redirect_uri: None,
        refresh_token: Some(refresh_token.clone()),
        resource: Some("https://mail.corvi.example".to_owned()),
    };
    let refreshed = fixture
        .issuer()
        .token(&refresh, NOW + 10)
        .expect("the refresh succeeds");
    let rotated = refreshed
        .refresh_token
        .expect("the refresh rotates the token");
    assert_ne!(rotated, refresh_token);

    // The old token is a replay: it is refused.
    refresh.refresh_token = Some(refresh_token.clone());
    assert!(matches!(
        fixture.issuer().token(&refresh, NOW + 20),
        Err(AuthError::InvalidGrant(_))
    ));
}

#[test]
fn a_replayed_refresh_token_revokes_the_whole_family() {
    let fixture = fixture();
    let response = complete_flow(&fixture);
    let refresh_token = response.refresh_token.expect("a refresh token is issued");
    let access_token = response.access_token.clone();
    let mut refresh = TokenRequest {
        grant_type: "refresh_token".to_owned(),
        client_id: "public-client".to_owned(),
        client_secret: None,
        code: None,
        code_verifier: None,
        redirect_uri: None,
        refresh_token: Some(refresh_token.clone()),
        resource: Some("https://mail.corvi.example".to_owned()),
    };
    fixture
        .issuer()
        .token(&refresh, NOW + 10)
        .expect("the refresh succeeds");
    refresh.refresh_token = Some(refresh_token);
    assert!(matches!(
        fixture.issuer().token(&refresh, NOW + 20),
        Err(AuthError::InvalidGrant(_))
    ));

    // The family is revoked, so the access token minted from it is refused
    // as well.
    let resource = ResourceServer::new(&fixture.config, &fixture.state, KEY);
    assert!(matches!(
        resource.authorize(&access_token, "https://mail.corvi.example", NOW + 30),
        Err(AuthError::InvalidToken(_))
    ));
}

#[test]
fn a_revoked_grant_survives_a_restart() {
    let fixture = fixture();
    let response = complete_flow(&fixture);
    let grant_id = fixture
        .state
        .list_grants("owner-1")
        .expect("the grants are listed")
        .first()
        .expect("the grant is there")
        .grant_id
        .clone();
    fixture
        .state
        .revoke_grant(&grant_id, NOW + 10)
        .expect("the grant is revoked");

    // A restarted issuer reads the same records.
    let restarted = fixture.state.reopen();
    let grant = restarted
        .get_grant(&grant_id)
        .expect("the grant is there")
        .expect("the grant is there");
    assert!(grant.revoked_at.is_some());

    let resource = ResourceServer::new(&fixture.config, &restarted, KEY);
    assert!(matches!(
        resource.authorize(
            &response.access_token,
            "https://mail.corvi.example",
            NOW + 20
        ),
        Err(AuthError::InvalidToken(_))
    ));
}

#[test]
fn a_narrowed_consent_takes_effect_on_the_next_token_request() {
    let fixture = fixture();
    let response = complete_flow(&fixture);
    let mut grant = fixture
        .state
        .list_grants("owner-1")
        .expect("the grants are listed")
        .first()
        .expect("the grant is there")
        .clone();
    // The owner reduces the grant to listing only.
    grant.scopes = vec!["mail:messages:list".to_owned()];
    grant.revision = 2;
    fixture
        .state
        .put_grant(&grant)
        .expect("the narrowed grant is stored");

    let refresh = TokenRequest {
        grant_type: "refresh_token".to_owned(),
        client_id: "public-client".to_owned(),
        client_secret: None,
        code: None,
        code_verifier: None,
        redirect_uri: None,
        refresh_token: response.refresh_token.clone(),
        resource: Some("https://mail.corvi.example".to_owned()),
    };
    let refreshed = fixture
        .issuer()
        .token(&refresh, NOW + 10)
        .expect("the refresh succeeds");
    assert_eq!(refreshed.scope, "mail:messages:list");

    // The token minted before the narrowing no longer carries the read
    // action for that identity.
    let resource = ResourceServer::new(&fixture.config, &fixture.state, KEY);
    let authorization = resource
        .authorize(
            &response.access_token,
            "https://mail.corvi.example",
            NOW + 20,
        )
        .expect("the token still works");
    let identity = authorization
        .identities
        .first()
        .expect("the identity is there");
    assert_eq!(identity.actions, vec![Action::List]);
}

#[test]
fn a_token_of_another_issuer_is_refused() {
    let fixture = fixture();
    let response = complete_flow(&fixture);
    let other = ResourceServer::new(
        &fixture.config,
        &fixture.state,
        b"another deployment key that is long enough",
    );
    assert!(matches!(
        other.authorize(&response.access_token, "https://mail.corvi.example", NOW),
        Err(AuthError::InvalidToken(_))
    ));
}

#[test]
fn a_token_that_names_another_issuer_is_refused() {
    let fixture = fixture();
    let response = complete_flow(&fixture);
    // The token is a good token in every respect but one: it is in the
    // store, it names the grants of the owner and it is addressed to the
    // mail resource. Only the issuer is another one.
    let good = mail_auth::tokens::parse_access_token(KEY, &response.access_token)
        .expect("the token parses");
    let claims = mail_auth::tokens::AccessTokenClaims {
        issuer: "https://attacker.example".to_owned(),
        ..good.clone()
    };
    let token = mail_auth::tokens::mint_access_token(KEY, &claims).expect("the token mints");
    fixture
        .state
        .put_access_token(&AccessToken {
            token_hash: mail_auth::tokens::token_hash(&token),
            grant_id: claims.grant_ids.first().cloned().unwrap_or_default(),
            principal: claims.subject.clone(),
            scopes: claims.scopes.clone(),
            expires_at: claims.expires_at,
            revoked_at: None,
        })
        .expect("the token is in the store");

    // The binding is the issuer, not only the signature: the signature is
    // this deployment's own.
    let resource = ResourceServer::new(&fixture.config, &fixture.state, KEY);
    let error = resource
        .authorize(&token, "https://mail.corvi.example", NOW)
        .expect_err("a token of another issuer must be refused");
    assert!(matches!(&error, AuthError::InvalidToken(_)));
    assert!(
        error.to_string().contains("another issuer"),
        "the refusal should name the issuer: {error}"
    );
}

#[test]
fn a_token_of_another_audience_is_refused() {
    let fixture = fixture();
    let response = complete_flow(&fixture);
    let resource = ResourceServer::new(&fixture.config, &fixture.state, KEY);
    assert!(matches!(
        resource.authorize(&response.access_token, "https://admin.corvi.example", NOW),
        Err(AuthError::InvalidToken(_))
    ));
}

#[test]
fn a_provider_token_is_never_a_corvi_token() {
    let fixture = fixture();
    let resource = ResourceServer::new(&fixture.config, &fixture.state, KEY);
    for token in [
        "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJwcm92aWRlciJ9.c2lnbmF0dXJl",
        "ya29.a0AfH6SMBprovider",
        "Bearer provider-token",
        "",
    ] {
        assert!(
            matches!(
                resource.authorize(token, "https://mail.corvi.example", NOW),
                Err(AuthError::InvalidToken(_))
            ),
            "the provider token {token:?} should have been refused"
        );
    }
}

#[test]
fn an_oauth_token_does_not_authenticate_an_smtp_submission() {
    let fixture = fixture();
    let response = complete_flow(&fixture);
    let resource = ResourceServer::new(&fixture.config, &fixture.state, KEY);
    assert!(!resource.accepts_oauth_at_smtp());
    let error = resource
        .authorize_smtp_oauth(&response.access_token)
        .expect_err("an OAuth bearer must not authenticate an SMTP submission");
    assert!(error.to_string().contains("SMTP"));
}

#[test]
fn an_issuer_without_persistent_state_refuses_to_start() {
    let config = config();
    let state = MemoryGrantState::ephemeral();
    assert!(matches!(
        Issuer::new(&config, &state, KEY, Some(ADMIN_HASH)),
        Err(AuthError::Deployment(_))
    ));
}

#[test]
fn an_external_issuer_only_deployment_needs_no_built_in_issuer() {
    let config = AuthConfig::external_resource_server(
        "https://mail.corvi.example",
        &["https://idp.corvi.example".to_owned()],
    );
    let state = MemoryGrantState::ephemeral();
    // The resource server of an external-issuer-only deployment runs on the
    // external issuer's tokens, so it needs no built-in issuer at all.
    let resource = ResourceServer::new(&config, &state, KEY);
    assert!(matches!(
        resource.authorize("a token", "https://mail.corvi.example", NOW),
        Err(AuthError::InvalidToken(_))
    ));
}

#[test]
fn a_revoked_access_token_is_refused() {
    let fixture = fixture();
    let response = complete_flow(&fixture);
    let resource = ResourceServer::new(&fixture.config, &fixture.state, KEY);
    fixture
        .issuer()
        .revoke(
            &RevocationRequest {
                client_id: "public-client".to_owned(),
                client_secret: None,
                token: response.access_token.clone(),
            },
            NOW + 10,
        )
        .expect("the token is revoked");
    assert!(matches!(
        resource.authorize(
            &response.access_token,
            "https://mail.corvi.example",
            NOW + 20
        ),
        Err(AuthError::InvalidToken(_))
    ));
}

#[test]
fn the_pkce_method_of_the_configuration_is_s256() {
    let config = config();
    assert_eq!(config.pkce_methods, vec![PkceMethod::S256]);
}
