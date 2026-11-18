//! Provider registration, scopes, callbacks and the explicit refusals
//! ADR-0008 section 1 requires.

mod common;

use std::sync::Arc;

use mail_upstream_oauth::callback::{check_callback, is_loopback_uri};
use mail_upstream_oauth::clock::FixedClock;
use mail_upstream_oauth::error::UpstreamOAuthError;
use mail_upstream_oauth::profile::{ClientType, OnboardingFlow, ProviderRegistry};
use mail_upstream_oauth::scope::Capability;

use common::*;

#[test]
fn an_unknown_provider_is_refused_explicitly() {
    let clock = Arc::new(FixedClock::new(NOW));
    let (service, _escrow) = gmail_service(gmail_transport(), clock);
    let error = service
        .capabilities("proton-bridge", &admin())
        .expect_err("an unknown provider is refused");
    match &error {
        UpstreamOAuthError::UnsupportedProvider { provider, reason } => {
            assert_eq!(provider, "proton-bridge");
            assert!(reason.contains("no profile"), "{reason}");
        }
        other => panic!("expected UnsupportedProvider, got {other:?}"),
    }
    assert_eq!(error.status().as_str(), "unsupportedRegistration");
}

#[test]
fn each_provider_declares_its_registration() {
    let registry = ProviderRegistry::builtin();

    let gmail = registry.get("gmail").expect("gmail is known");
    assert_eq!(gmail.client.client_type, ClientType::Public);
    assert!(!gmail.requires_client_secret());
    assert!(gmail.device_flow_supported());
    assert_eq!(gmail.scopes.read, vec!["https://mail.google.com/"]);
    assert_eq!(gmail.scopes.send, vec!["https://mail.google.com/"]);
    assert!(
        gmail
            .transport_mechanisms
            .contains(&mail_upstream_oauth::profile::TransportMechanism::ImapXoauth2)
    );

    let m365 = registry.get("microsoft365").expect("microsoft365 is known");
    assert_eq!(m365.client.client_type, ClientType::Public);
    assert!(m365.device_flow_supported());
    assert_ne!(m365.scopes.read, m365.scopes.send);
    assert_eq!(
        m365.scopes.send,
        vec!["https://outlook.office365.com/SMTP.Send"]
    );
    assert!(m365.scopes.offline.is_some());

    let fastmail = registry.get("fastmail").expect("fastmail is known");
    assert_eq!(fastmail.client.client_type, ClientType::Confidential);
    assert!(fastmail.requires_client_secret());
    assert!(!fastmail.device_flow_supported());
    assert_eq!(
        fastmail.transport_mechanisms,
        vec![mail_upstream_oauth::profile::TransportMechanism::JmapBearer]
    );
}

#[test]
fn the_device_flow_is_advertised_only_where_supported() {
    let registry = ProviderRegistry::builtin();
    let fastmail = registry.get("fastmail").expect("fastmail is known");
    let capabilities = fastmail.capabilities();
    assert!(
        !capabilities
            .flows
            .contains(&OnboardingFlow::DeviceAuthorization),
        "a provider without a device grant must not advertise one"
    );
    assert!(
        capabilities
            .flows
            .contains(&OnboardingFlow::AuthorizationCodePkce)
    );

    // A provider that lists the flow but has no device endpoint advertises
    // nothing, because an operator who is told a device flow exists will
    // design a deployment around it.
    let mut without_endpoint = fastmail.clone();
    without_endpoint.provider_id = "fastmail-claiming".to_owned();
    without_endpoint
        .flows
        .push(OnboardingFlow::DeviceAuthorization);
    assert!(!without_endpoint.device_flow_supported());
    assert!(
        !without_endpoint
            .advertised_flows()
            .contains(&OnboardingFlow::DeviceAuthorization)
    );
}

#[test]
fn a_device_flow_is_never_started_without_an_endpoint() {
    let clock = Arc::new(FixedClock::new(NOW));
    let transport = gmail_transport();
    let (service, _escrow) = gmail_service(transport.clone(), clock);
    // The gmail profile has a device endpoint, so it advertises one; the
    // fastmail profile does not, so asking for its capabilities never
    // mentions the flow even though the registry knows the provider.
    let capabilities = service
        .capabilities("fastmail", &admin())
        .expect("fastmail is known");
    assert!(
        !capabilities
            .flows
            .contains(&OnboardingFlow::DeviceAuthorization)
    );
}

#[test]
fn a_scope_the_provider_does_not_offer_is_refused() {
    let registry = ProviderRegistry::builtin();
    let gmail = registry.get("gmail").expect("gmail is known");

    let error = mail_upstream_oauth::scope::resolve_scopes(
        gmail,
        &mail_upstream_oauth::scope::ScopeRequest::new(vec![
            Capability::Read,
            Capability::Management,
        ]),
    )
    .expect_err("gmail offers no management scope");
    match &error {
        UpstreamOAuthError::UnsupportedScope { provider, scope } => {
            assert_eq!(provider, "gmail");
            assert_eq!(scope, "management");
        }
        other => panic!("expected UnsupportedScope, got {other:?}"),
    }
    assert_eq!(error.status().as_str(), "scopeInsufficient");

    let error = mail_upstream_oauth::scope::resolve_scopes(
        gmail,
        &mail_upstream_oauth::scope::ScopeRequest::new(vec![Capability::Read]).with_scopes(vec![
            "https://www.googleapis.test/auth/drive.readonly".to_owned(),
        ]),
    )
    .expect_err("a drive scope is not a mail scope");
    assert!(matches!(error, UpstreamOAuthError::UnsupportedScope { .. }));
}

#[test]
fn the_requested_scopes_are_the_providers_own() {
    let registry = ProviderRegistry::builtin();
    let gmail = registry.get("gmail").expect("gmail is known");
    let resolved = mail_upstream_oauth::scope::resolve_scopes(
        gmail,
        &mail_upstream_oauth::scope::ScopeRequest::new(vec![Capability::Read, Capability::Send]),
    )
    .expect("gmail offers read and send");
    assert_eq!(resolved.scopes, vec!["https://mail.google.com/"]);
    assert_eq!(
        resolved.capabilities,
        vec![Capability::Read, Capability::Send]
    );
}

#[test]
fn a_callback_that_is_not_registered_is_refused() {
    let registry = ProviderRegistry::builtin();
    let gmail = registry.get("gmail").expect("gmail is known");

    let error = check_callback(gmail, "https://evil.example/oauth/callback")
        .expect_err("an unregistered callback is refused");
    assert!(matches!(
        error,
        UpstreamOAuthError::CallbackNotAllowed { .. }
    ));
    assert_eq!(error.status().as_str(), "unsupportedRegistration");

    let error = check_callback(gmail, "http://10.0.0.5:8400/oauth/upstream/callback/gmail")
        .expect_err("an http callback off the loopback interface is refused");
    assert!(matches!(
        error,
        UpstreamOAuthError::CallbackNotAllowed { .. }
    ));

    check_callback(gmail, GMAIL_REDIRECT).expect("the registered loopback callback is allowed");

    let fastmail = registry.get("fastmail").expect("fastmail is known");
    check_callback(
        fastmail,
        "https://auth.corvi.example/oauth/upstream/callback/fastmail",
    )
    .expect("the registered https callback is allowed");
    let error = check_callback(fastmail, GMAIL_REDIRECT)
        .expect_err("another provider's callback is not this provider's");
    assert!(matches!(
        error,
        UpstreamOAuthError::CallbackNotAllowed { .. }
    ));
}

#[test]
fn only_the_loopback_interface_may_use_http() {
    assert!(is_loopback_uri("http://127.0.0.1:8400/callback"));
    assert!(is_loopback_uri("http://[::1]:8400/callback"));
    assert!(!is_loopback_uri("http://localhost:8400/callback"));
    assert!(!is_loopback_uri("https://127.0.0.1/callback"));
    assert!(!is_loopback_uri("http://example.test/callback"));
}

#[test]
fn an_unconfigured_provider_says_what_is_missing() {
    let registry = ProviderRegistry::builtin();
    let fastmail = registry.get("fastmail").expect("fastmail is known").clone();

    let mut without_callback = fastmail.clone();
    without_callback.client.redirect_uris.clear();
    let error = without_callback
        .validate()
        .expect_err("a provider without a callback cannot onboard");
    match &error {
        UpstreamOAuthError::UnsupportedRegistration { provider, reason } => {
            assert_eq!(provider, "fastmail");
            assert!(reason.contains("no callback"), "{reason}");
        }
        other => panic!("expected UnsupportedRegistration, got {other:?}"),
    }

    let mut without_secret = fastmail.clone();
    without_secret.client.client_secret_ref = None;
    let error = without_secret
        .validate()
        .expect_err("a confidential client needs its secret");
    match &error {
        UpstreamOAuthError::UnsupportedRegistration { reason, .. } => {
            assert!(reason.contains("client secret"), "{reason}");
        }
        other => panic!("expected UnsupportedRegistration, got {other:?}"),
    }

    let mut over_secret = registry.get("gmail").expect("gmail is known").clone();
    over_secret.client.client_secret_ref = Some("secret://provider/leak".to_owned());
    let error = over_secret
        .validate()
        .expect_err("a public client must not carry a secret");
    assert!(matches!(
        error,
        UpstreamOAuthError::UnsupportedRegistration { .. }
    ));

    let mut without_issuer = fastmail.clone();
    without_issuer.issuer = None;
    let error = without_issuer
        .validate()
        .expect_err("a provider without an issuer cannot be bound");
    match &error {
        UpstreamOAuthError::UnsupportedRegistration { reason, .. } => {
            assert!(reason.contains("issuer"), "{reason}");
        }
        other => panic!("expected UnsupportedRegistration, got {other:?}"),
    }
}

#[test]
fn an_unconfigured_provider_is_refused_before_anything_is_sent() {
    let clock = Arc::new(FixedClock::new(NOW));
    let transport = gmail_transport();
    let registry = ProviderRegistry::builtin();
    let mut broken = registry.get("gmail").expect("gmail is known").clone();
    broken.client.redirect_uris.clear();
    let mut registry = ProviderRegistry::new();
    registry.insert(broken);

    let transactions = Arc::new(mail_upstream_oauth::transaction::MemoryTransactionStore::new());
    let validator = Arc::new(
        mail_upstream_oauth::onboarding::SessionAccountValidator::new(
            transport.clone(),
            SESSION_URL.to_owned(),
        ),
    );
    let service = mail_upstream_oauth::onboarding::OnboardingService::new(
        Arc::new(registry),
        transactions,
        transport.clone(),
        Arc::new(mail_upstream_oauth::onboarding::RoleAuthorizer),
        validator,
        Arc::new(mail_upstream_oauth::testing::MapClientSecrets::new()),
        Arc::new(mail_upstream_oauth::onboarding::DeliveryEscrow::new()),
        clock,
    );
    let error = service
        .start(&gmail_request())
        .expect_err("an unconfigured provider cannot onboard");
    assert!(matches!(
        error,
        UpstreamOAuthError::UnsupportedRegistration { .. }
    ));
    assert_eq!(
        transport.request_count(),
        0,
        "nothing was sent to the provider"
    );
}

#[test]
fn a_provider_without_the_authorization_code_flow_says_so() {
    let registry = ProviderRegistry::builtin();
    let mut no_flow = registry.get("gmail").expect("gmail is known").clone();
    no_flow.provider_id = "no-flow".to_owned();
    no_flow.flows.clear();
    let error = no_flow
        .validate()
        .expect_err("a provider without flows cannot onboard");
    match &error {
        UpstreamOAuthError::UnsupportedRegistration { reason, .. } => {
            assert!(reason.contains("interactive flow"), "{reason}");
        }
        other => panic!("expected UnsupportedRegistration, got {other:?}"),
    }
}
