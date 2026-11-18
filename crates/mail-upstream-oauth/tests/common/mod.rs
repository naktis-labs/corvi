#![allow(dead_code)]

//! The pieces the behavior tests share.

use std::sync::Arc;

use mail_storage::{EncryptedFileSecretStore, SqliteStore};
use mail_upstream_oauth::clock::FixedClock;
use mail_upstream_oauth::onboarding::{
    CallbackRequest, DeliveryEscrow, OnboardingPrincipal, OnboardingRequest, OnboardingRole,
    OnboardingService, RoleAuthorizer, SessionAccountValidator,
};
use mail_upstream_oauth::profile::ProviderRegistry;
use mail_upstream_oauth::scope::Capability;
use mail_upstream_oauth::testing::{FixtureTransport, MapClientSecrets, token_response};
use mail_upstream_oauth::transaction::MemoryTransactionStore;
use mail_upstream_oauth::transport::HttpMethod;
use mail_upstream_oauth::transport::OAuthResponse;

/// A fixed point in time the tests reason about.
pub const NOW: u64 = 1_800_000_000;

/// The JMAP session URL the account probe reads.
pub const SESSION_URL: &str = "https://mail.example.test/jmap/session";

/// The callback the gmail example registers.
pub const GMAIL_REDIRECT: &str = "http://127.0.0.1:8400/oauth/upstream/callback/gmail";

/// The upstream account the tests expect.
pub const ACCOUNT: &str = "acct-1";

/// The refresh token the gmail fixture issues first.
pub const FIRST_REFRESH_TOKEN: &str = "rt-first-credential";

/// The access token the gmail fixture issues.
pub const ACCESS_TOKEN: &str = "at-first-credential";

/// The client secret of the fastmail example.
pub const FASTMAIL_CLIENT_SECRET: &str = "fastmail-confidential-secret-1234567890";

/// A principal that may onboard accounts.
pub fn admin() -> OnboardingPrincipal {
    OnboardingPrincipal::new("admin-1", vec![OnboardingRole::ProviderOnboardingAdmin])
}

/// A principal that may only read a mailbox.
pub fn reader() -> OnboardingPrincipal {
    OnboardingPrincipal::new("reader-1", vec![OnboardingRole::MailboxReader])
}

/// A principal that may only take credentials into the data plane.
pub fn broker() -> OnboardingPrincipal {
    OnboardingPrincipal::new("broker-1", vec![OnboardingRole::DataPlaneTokenBroker])
}

/// The routes the gmail fixture answers.
fn gmail_routes() -> FixtureTransport {
    FixtureTransport::new()
        .route_form(
            HttpMethod::Post,
            "https://oauth2.googleapis.com/token",
            "grant_type=authorization_code",
            OAuthResponse::json(
                200,
                &token_response(
                    ACCESS_TOKEN,
                    Some(FIRST_REFRESH_TOKEN),
                    Some(3600),
                    Some("https://mail.google.com/"),
                ),
            ),
        )
        .route_form(
            HttpMethod::Post,
            "https://oauth2.googleapis.com/token",
            "grant_type=refresh_token",
            OAuthResponse::json(
                200,
                &token_response(
                    "at-second-credential",
                    Some("rt-second-credential"),
                    Some(3600),
                    Some("https://mail.google.com/"),
                ),
            ),
        )
        .route(
            HttpMethod::Get,
            SESSION_URL,
            OAuthResponse::json(
                200,
                &serde_json::json!({ "accounts": { ACCOUNT.to_string(): { "name": "me" } } }),
            ),
        )
}

/// A transport that answers the gmail token endpoint and the session.
pub fn gmail_transport() -> Arc<FixtureTransport> {
    Arc::new(gmail_routes())
}

/// A transport whose routes are changed first.
pub fn gmail_transport_with(
    change: impl FnOnce(FixtureTransport) -> FixtureTransport,
) -> Arc<FixtureTransport> {
    Arc::new(change(gmail_routes()))
}

/// An onboarding service over the gmail example.
pub fn gmail_service(
    transport: Arc<FixtureTransport>,
    clock: Arc<FixedClock>,
) -> (OnboardingService, Arc<DeliveryEscrow>) {
    let registry = Arc::new(ProviderRegistry::builtin());
    let transactions = Arc::new(MemoryTransactionStore::new());
    let validator = Arc::new(SessionAccountValidator::new(
        transport.clone(),
        SESSION_URL.to_owned(),
    ));
    let authorizer = Arc::new(RoleAuthorizer);
    let client_secrets = Arc::new(MapClientSecrets::new().with(
        "secret://provider/fastmail-client-secret",
        FASTMAIL_CLIENT_SECRET,
    ));
    let escrow = Arc::new(DeliveryEscrow::new());
    let service = OnboardingService::new(
        registry,
        transactions,
        transport,
        authorizer,
        validator,
        client_secrets,
        escrow.clone(),
        clock,
    );
    (service, escrow)
}

/// An onboarding request for the gmail example.
pub fn gmail_request() -> OnboardingRequest {
    OnboardingRequest {
        provider: "gmail".to_owned(),
        principal: admin(),
        identity: "identity-1".to_owned(),
        expected_account: ACCOUNT.to_owned(),
        capabilities: vec![Capability::Read, Capability::Send],
        extra_scopes: Vec::new(),
        redirect_uri: GMAIL_REDIRECT.to_owned(),
        ttl_seconds: 300,
    }
}

/// Start an onboarding and build the callback the provider would send.
pub fn authorize(service: &OnboardingService) -> CallbackRequest {
    let start = service
        .start(&gmail_request())
        .expect("the onboarding starts");
    let state = query(&start.authorization_url, "state");
    CallbackRequest {
        provider: Some("gmail".to_owned()),
        state,
        code: Some("auth-code-1".to_owned()),
        error: None,
        issuer: None,
        redirect_uri: Some(GMAIL_REDIRECT.to_owned()),
        client_id: Some("gmail-example-client-id.apps.googleusercontent.com".to_owned()),
    }
}

/// The value of one query parameter of a URL.
pub fn query(url: &str, name: &str) -> String {
    let prefix = format!("{name}=");
    url.split('?')
        .nth(1)
        .and_then(|rest| {
            rest.split('&')
                .find(|pair| pair.starts_with(&prefix))
                .map(|pair| pair[prefix.len()..].to_owned())
        })
        .unwrap_or_default()
}

/// An encrypted secret store at a unique path.
///
/// The directory is not created here: the secret store creates the
/// directories it lives in with owner-only permissions, and a directory
/// made with the default umask would be refused.
pub fn secret_store(name: &str) -> (EncryptedFileSecretStore, std::path::PathBuf) {
    let directory =
        std::env::temp_dir().join(format!("corvi-upstream-oauth-{name}-{}", unique_suffix()));
    let path = directory.join("secrets.enc");
    let store = EncryptedFileSecretStore::open(&path, b"a wrapping key long enough", "k1")
        .expect("the secret store opens");
    (store, path)
}

/// An in-memory transactional store.
pub fn connection_store() -> Arc<SqliteStore> {
    Arc::new(SqliteStore::open_in_memory().expect("the store opens"))
}

/// A file-backed connection store: its records survive a restart.
pub fn durable_connection_store() -> Arc<SqliteStore> {
    Arc::new(
        SqliteStore::open(
            std::env::temp_dir().join(format!("corvi-connections-{}", unique_suffix())),
        )
        .expect("the store opens"),
    )
}

/// Random suffix for a test directory.
///
/// The suffix is unique per call inside this process, and unique per
/// process across runs: two tests that start within the same nanosecond
/// must not race on one secret-store directory.
fn unique_suffix() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static CALLS: AtomicU64 = AtomicU64::new(0);
    let call = CALLS.fetch_add(1, Ordering::Relaxed);
    let started = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or_default();
    format!("{}-{call}-{started}", std::process::id())
}

/// The random suffix for a test path, exported for the delivery tests.
pub fn unique_suffix_pub() -> String {
    unique_suffix()
}
