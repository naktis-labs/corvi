//! Admission decisions for MailCredential resources.

use mail_credential::admission::{
    AdmissionDecision, AdmissionOperation, AdmissionRequest, ConnectionMode, CredentialGranularity,
    GatewayStatus, ParentStatusReader,
};
use mail_credential::model::{
    MailCredential, MailCredentialSpec, Permission, ProtocolType, RequestedAuthority, SpecError,
};
use mail_credential::policy::SecretPolicy;
use mail_credential::reasons::Reason;
use mail_credential::testing::{
    FIXTURE_NAMESPACE, FakeGraph, gateway, identity, mailbox, provider_bound, provider_unbound,
};

const SCOPED_MCP: &str = "type: mcp\ntargetRef:\n  kind: MailIdentity\n  name: me\npermissions:\n  - mail:messages:list\n  - mail:messages:read\n";

const NATIVE_SMTP: &str = "targetRef:\n  kind: Mailbox\n  name: unserved-mailbox\n";

fn spec(document: &str) -> MailCredentialSpec {
    MailCredentialSpec::parse(document).expect("the fixture spec is valid")
}

fn credential(document: &str) -> MailCredential {
    MailCredential::new(
        "me-mcp",
        FIXTURE_NAMESPACE,
        "credential-uid",
        1,
        spec(document),
    )
}

fn request(document: &str) -> AdmissionRequest {
    AdmissionRequest::new(credential(document), AdmissionOperation::Create, false)
}

fn policy() -> SecretPolicy {
    SecretPolicy::deny_all()
}

/// A provider that is attached to a gateway, with the identity it serves.
fn bound_graph() -> FakeGraph {
    FakeGraph::new()
        .with_provider(provider_bound("fastmail", "primary"))
        .with_mailbox(mailbox("personal", "fastmail"))
        .with_identity(identity("me", "personal"))
        .with_gateway(gateway("primary"))
}

/// A provider that is not attached to a gateway.
fn direct_graph() -> FakeGraph {
    FakeGraph::new()
        .with_provider(provider_unbound("administration-only"))
        .with_mailbox(mailbox("personal", "administration-only"))
        .with_mailbox(mailbox("unserved-mailbox", "administration-only"))
        .with_identity(identity("me", "personal"))
        .with_identity(identity("unserved", "unserved-mailbox"))
}

fn reason_of(decision: &AdmissionDecision) -> Reason {
    decision.denial().expect("the request was refused").reason()
}

#[test]
fn smtp_is_the_default_protocol_of_a_credential() {
    let graph = direct_graph();
    let decision = mail_credential::admission::admit(&request(NATIVE_SMTP), &graph, &policy());

    assert!(decision.is_allowed(), "{decision:?}");
    let authority = decision
        .authority()
        .expect("an admitted credential has an authority");
    assert_eq!(authority.credential_type(), ProtocolType::Smtp);
    assert_eq!(authority.mode(), ConnectionMode::ProviderDirect);
    assert_eq!(
        authority.granularity(),
        CredentialGranularity::ProviderMailbox
    );
    assert_eq!(authority.mailbox_name(), Some("unserved-mailbox"));
    assert_eq!(authority.identity_name(), None);
}

#[test]
fn a_credential_that_declares_two_protocol_shapes_is_refused() {
    let error = MailCredentialSpec::parse(
        "type: smtp\nshape: providerDirect\ntargetRef:\n  kind: MailIdentity\n  name: me\n",
    )
    .expect_err("two shapes are refused");
    assert_eq!(
        error,
        SpecError::MultipleProtocolShapes {
            declared: vec!["type:smtp".to_string(), "shape:providerDirect".to_string()],
        }
    );

    let error = MailCredentialSpec::parse(
        "shape:\n  - providerDirect\n  - native\ntargetRef:\n  kind: MailIdentity\n  name: me\n",
    )
    .expect_err("two native shapes are refused");
    assert!(matches!(error, SpecError::MultipleProtocolShapes { .. }));
}

#[test]
fn a_single_legacy_shape_is_refused_rather_than_interpreted() {
    let error =
        MailCredentialSpec::parse("shape: smtp\ntargetRef:\n  kind: MailIdentity\n  name: me\n")
            .expect_err("the legacy field is refused");
    assert!(matches!(error, SpecError::LegacyShapeField { .. }));
}

#[test]
fn a_scoped_credential_requires_a_bound_gateway() {
    let graph = direct_graph();
    let decision = mail_credential::admission::admit(&request(SCOPED_MCP), &graph, &policy());

    assert_eq!(
        reason_of(&decision),
        Reason::GatewayRequiredForScopedCredential
    );
}

#[test]
fn a_scoped_credential_requires_an_identity_target() {
    let graph = bound_graph();
    let decision = mail_credential::admission::admit(
        &request(
            "type: smtp\ntargetRef:\n  kind: Mailbox\n  name: personal\npermissions:\n  - mail:messages:send\n",
        ),
        &graph,
        &policy(),
    );

    assert_eq!(reason_of(&decision), Reason::GatewayRequiresMailIdentity);
}

#[test]
fn a_gateway_bound_credential_requires_a_nonempty_permission_list() {
    let graph = bound_graph();

    let omitted = mail_credential::admission::admit(
        &request("type: mcp\ntargetRef:\n  kind: MailIdentity\n  name: me\n"),
        &graph,
        &policy(),
    );
    assert_eq!(reason_of(&omitted), Reason::MissingGatewayPermissions);

    let empty = mail_credential::admission::admit(
        &request("type: mcp\ntargetRef:\n  kind: MailIdentity\n  name: me\npermissions: []\n"),
        &graph,
        &policy(),
    );
    assert_eq!(reason_of(&empty), Reason::MissingGatewayPermissions);
}

#[test]
fn an_omitted_permission_list_asks_for_provider_native_authority() {
    assert_eq!(
        spec("targetRef:\n  kind: Mailbox\n  name: unserved-mailbox\n").requested_authority(),
        RequestedAuthority::Native
    );
    assert_eq!(
        spec(SCOPED_MCP).requested_authority(),
        RequestedAuthority::Scoped
    );
}

#[test]
fn a_scoped_credential_on_a_bound_provider_carries_its_permissions() {
    let graph = bound_graph();
    let decision = mail_credential::admission::admit(&request(SCOPED_MCP), &graph, &policy());

    assert!(decision.is_allowed(), "{decision:?}");
    let authority = decision
        .authority()
        .expect("an admitted credential has an authority");
    assert_eq!(authority.mode(), ConnectionMode::Gateway);
    assert_eq!(
        authority.granularity(),
        CredentialGranularity::CorviIdentity
    );
    assert_eq!(authority.identity_name(), Some("me"));
    assert_eq!(authority.mailbox_name(), None);
    assert_eq!(
        authority.permissions(),
        [Permission::MessagesList, Permission::MessagesRead]
    );
}

#[test]
fn a_native_credential_needs_the_granularity_the_provider_isolates() {
    let mut provider = provider_unbound("administration-only");
    provider.capabilities.granularities = vec![CredentialGranularity::ProviderMailbox];
    let graph = FakeGraph::new()
        .with_provider(provider)
        .with_mailbox(mailbox("personal", "administration-only"))
        .with_identity(identity("me", "personal"));

    let decision = mail_credential::admission::admit(
        &request("type: smtp\ntargetRef:\n  kind: MailIdentity\n  name: me\n"),
        &graph,
        &policy(),
    );

    assert_eq!(
        reason_of(&decision),
        Reason::UnsupportedCredentialGranularity
    );
}

#[test]
fn a_native_credential_needs_a_verified_identity() {
    let mut unverfied = identity("me", "personal");
    unverfied.verified = false;
    let graph = FakeGraph::new()
        .with_provider(provider_unbound("administration-only"))
        .with_mailbox(mailbox("personal", "administration-only"))
        .with_identity(unverfied);

    let decision = mail_credential::admission::admit(
        &request("type: smtp\ntargetRef:\n  kind: MailIdentity\n  name: me\n"),
        &graph,
        &policy(),
    );

    assert_eq!(reason_of(&decision), Reason::IdentityNotVerified);
}

#[test]
fn a_provider_that_cannot_issue_revocable_credentials_is_refused() {
    let mut provider = provider_unbound("administration-only");
    provider.capabilities.revoke_supported = false;
    let graph = FakeGraph::new()
        .with_provider(provider)
        .with_mailbox(mailbox("unserved-mailbox", "administration-only"));

    let decision = mail_credential::admission::admit(&request(NATIVE_SMTP), &graph, &policy());

    assert_eq!(reason_of(&decision), Reason::UnsupportedCredentialIssuance);
}

#[test]
fn a_provider_that_does_not_serve_the_protocol_is_refused() {
    let mut provider = provider_unbound("administration-only");
    provider.capabilities.types = vec![ProtocolType::Rest];
    let graph = FakeGraph::new()
        .with_provider(provider)
        .with_mailbox(mailbox("unserved-mailbox", "administration-only"));

    let decision = mail_credential::admission::admit(&request(NATIVE_SMTP), &graph, &policy());

    assert_eq!(reason_of(&decision), Reason::UnsupportedCredentialType);
}

#[test]
fn admission_fails_closed_when_a_dependency_cannot_be_read() {
    let mut graph = bound_graph();
    graph.set_unavailable(true);

    let decision = mail_credential::admission::admit(&request(SCOPED_MCP), &graph, &policy());

    assert_eq!(reason_of(&decision), Reason::DependencyUnavailable);
}

#[test]
fn admission_fails_closed_on_a_stale_capability_status() {
    let mut provider = provider_bound("fastmail", "primary");
    provider.generation = 2;
    let graph = FakeGraph::new()
        .with_provider(provider)
        .with_mailbox(mailbox("personal", "fastmail"))
        .with_identity(identity("me", "personal"))
        .with_gateway(gateway("primary"));

    let decision = mail_credential::admission::admit(&request(SCOPED_MCP), &graph, &policy());

    assert_eq!(reason_of(&decision), Reason::StaleCapabilityStatus);
}

#[test]
fn a_stale_capability_status_is_refused_even_when_the_status_is_fresh() {
    let mut provider = provider_bound("fastmail", "primary");
    provider.capabilities_observed_generation = 0;
    let graph = FakeGraph::new()
        .with_provider(provider)
        .with_mailbox(mailbox("personal", "fastmail"))
        .with_identity(identity("me", "personal"))
        .with_gateway(gateway("primary"));

    let decision = mail_credential::admission::admit(&request(SCOPED_MCP), &graph, &policy());

    assert_eq!(reason_of(&decision), Reason::StaleCapabilityStatus);
}

#[test]
fn an_explicit_gateway_reference_is_not_treated_as_unbound() {
    // The provider names a gateway that does not exist. That is an invalid
    // reference, not an unbound provider, so the request is refused instead
    // of falling back to a native credential.
    let graph = FakeGraph::new()
        .with_provider(provider_bound("fastmail", "missing-gateway"))
        .with_mailbox(mailbox("personal", "fastmail"))
        .with_identity(identity("me", "personal"));

    let decision = mail_credential::admission::admit(&request(SCOPED_MCP), &graph, &policy());

    assert_eq!(reason_of(&decision), Reason::InvalidGatewayRef);
}

#[test]
fn a_suspended_or_unready_gateway_is_refused() {
    let mut suspended = gateway("primary");
    suspended.suspended = true;
    let graph = FakeGraph::new()
        .with_provider(provider_bound("fastmail", "primary"))
        .with_mailbox(mailbox("personal", "fastmail"))
        .with_identity(identity("me", "personal"))
        .with_gateway(suspended);

    let decision = mail_credential::admission::admit(&request(SCOPED_MCP), &graph, &policy());
    assert_eq!(reason_of(&decision), Reason::GatewayUnavailable);

    let mut unready = gateway("primary");
    unready.ready = false;
    let graph = FakeGraph::new()
        .with_provider(provider_bound("fastmail", "primary"))
        .with_mailbox(mailbox("personal", "fastmail"))
        .with_identity(identity("me", "personal"))
        .with_gateway(unready);

    let decision = mail_credential::admission::admit(&request(SCOPED_MCP), &graph, &policy());
    assert_eq!(reason_of(&decision), Reason::GatewayUnavailable);
}

#[test]
fn a_missing_target_is_refused() {
    let graph = FakeGraph::new().with_provider(provider_bound("fastmail", "primary"));
    let decision = mail_credential::admission::admit(&request(SCOPED_MCP), &graph, &policy());

    assert_eq!(reason_of(&decision), Reason::InvalidTargetRef);
}

#[test]
fn a_target_in_another_namespace_is_refused() {
    let mut elsewhere = identity("me", "personal");
    elsewhere.namespace = "other-namespace".to_string();
    let graph = FakeGraph::new()
        .with_provider(provider_bound("fastmail", "primary"))
        .with_mailbox(mailbox("personal", "fastmail"))
        .with_identity(elsewhere)
        .with_gateway(gateway("primary"));

    let decision = mail_credential::admission::admit(&request(SCOPED_MCP), &graph, &policy());

    assert_eq!(reason_of(&decision), Reason::CrossNamespaceReference);
}

#[test]
fn admission_is_side_effect_free_and_answers_a_dry_run_request() {
    let graph = bound_graph();
    let dry_run = AdmissionRequest::new(credential(SCOPED_MCP), AdmissionOperation::Create, true);

    let dry_decision = mail_credential::admission::admit(&dry_run, &graph, &policy());
    let dry_calls = graph.calls();
    assert!(dry_decision.is_allowed(), "{dry_decision:?}");

    let wet_decision = mail_credential::admission::admit(&request(SCOPED_MCP), &graph, &policy());
    let wet_calls = graph.calls();

    // A dry run is evaluated, not skipped: it reads exactly what a real
    // request reads and reaches the same decision.
    assert_eq!(dry_calls.len(), 4);
    assert_eq!(wet_calls.len(), dry_calls.len() * 2);
    assert_eq!(wet_calls[dry_calls.len()..], dry_calls[..]);
    assert_eq!(dry_decision, wet_decision);
}

#[test]
fn admission_only_reads_the_parents_it_needs() {
    let graph = bound_graph();
    let decision = mail_credential::admission::admit(&request(SCOPED_MCP), &graph, &policy());
    assert!(decision.is_allowed(), "{decision:?}");

    let calls = graph.calls();
    assert!(
        calls.contains(&mail_credential::testing::GraphCall::Identity(
            "me".to_string()
        ))
    );
    assert!(
        calls.contains(&mail_credential::testing::GraphCall::Mailbox(
            "personal".to_string()
        ))
    );
    assert!(
        calls.contains(&mail_credential::testing::GraphCall::Provider(
            "fastmail".to_string()
        ))
    );
    assert!(
        calls.contains(&mail_credential::testing::GraphCall::Gateway(
            "primary".to_string()
        ))
    );
    // The publisher never runs on the admission path.
    assert_eq!(calls.len(), 4);
}

#[test]
fn an_unapproved_secret_annotation_is_refused() {
    let graph = bound_graph();
    let document = "type: mcp\ntargetRef:\n  kind: MailIdentity\n  name: me\npermissions:\n  - mail:messages:read\nsecretTemplate:\n  metadata:\n    name: me-mcp-app\n    annotations:\n      example.com/application: mail-agent\n";

    let decision = mail_credential::admission::admit(&request(document), &graph, &policy());
    assert_eq!(reason_of(&decision), Reason::UnsafeSecretAnnotation);

    let approving = SecretPolicy::deny_all().allow_prefix("example.com/");
    let decision = mail_credential::admission::admit(&request(document), &graph, &approving);
    assert!(decision.is_allowed(), "{decision:?}");
}

#[test]
fn a_reserved_secret_annotation_is_refused_even_by_an_approving_policy() {
    let graph = bound_graph();
    let document = "type: mcp\ntargetRef:\n  kind: MailIdentity\n  name: me\npermissions:\n  - mail:messages:read\nsecretTemplate:\n  metadata:\n    annotations:\n      corvi.naktis.eu/owner: corvi\n";
    let approving = SecretPolicy::deny_all().allow_prefix("corvi.naktis.eu/");

    let decision = mail_credential::admission::admit(&request(document), &graph, &approving);

    assert_eq!(reason_of(&decision), Reason::UnsafeSecretAnnotation);
}

#[test]
fn a_gateway_that_does_not_serve_the_protocol_is_refused() {
    let mut narrow = gateway("primary");
    narrow.supported_types = vec![ProtocolType::Smtp];
    let graph = FakeGraph::new()
        .with_provider(provider_bound("fastmail", "primary"))
        .with_mailbox(mailbox("personal", "fastmail"))
        .with_identity(identity("me", "personal"))
        .with_gateway(narrow);

    let decision = mail_credential::admission::admit(&request(SCOPED_MCP), &graph, &policy());

    assert_eq!(reason_of(&decision), Reason::UnsupportedCredentialType);
}

#[test]
fn an_explicit_null_is_refused_rather_than_defaulted() {
    let error =
        MailCredentialSpec::parse("type: null\ntargetRef:\n  kind: MailIdentity\n  name: me\n")
            .expect_err("an explicit null is refused");
    assert_eq!(
        error,
        SpecError::ExplicitNull {
            field: "spec.type".to_string()
        }
    );

    let error = MailCredentialSpec::parse(
        "targetRef:\n  kind: MailIdentity\n  name: me\npermissions: null\n",
    )
    .expect_err("an explicit null is refused");
    assert_eq!(
        error,
        SpecError::ExplicitNull {
            field: "spec.permissions".to_string()
        }
    );
}

#[test]
fn an_unknown_field_is_refused() {
    let error = MailCredentialSpec::parse(
        "type: smtp\nshape: smtp\ntargetRef:\n  kind: MailIdentity\n  name: me\nproviderAdmin: true\n",
    )
    .expect_err("an unknown field is refused");
    assert_eq!(
        error,
        SpecError::UnknownField {
            field: "spec.providerAdmin".to_string()
        }
    );

    let error = MailCredentialSpec::parse(
        "type: smtp\ntargetRef:\n  kind: MailIdentity\n  name: me\nsecretTemplate:\n  metadata:\n    name: app\n  data:\n    token: hunter2\n",
    )
    .expect_err("a Secret template may not carry data");
    assert_eq!(
        error,
        SpecError::UnknownField {
            field: "spec.secretTemplate.data".to_string()
        }
    );
}

#[test]
fn an_unknown_or_repeated_action_is_refused() {
    let error = MailCredentialSpec::parse(
        "type: smtp\ntargetRef:\n  kind: MailIdentity\n  name: me\npermissions:\n  - mail:messages:teleport\n",
    )
    .expect_err("an unknown action is refused");
    assert_eq!(
        error,
        SpecError::UnknownPermission {
            value: "mail:messages:teleport".to_string()
        }
    );

    let error = MailCredentialSpec::parse(
        "type: smtp\ntargetRef:\n  kind: MailIdentity\n  name: me\npermissions:\n  - mail:messages:read\n  - mail:messages:read\n",
    )
    .expect_err("a repeated action is refused");
    assert_eq!(
        error,
        SpecError::DuplicatePermission {
            value: "mail:messages:read".to_string()
        }
    );
}

#[test]
fn a_secret_template_may_only_name_a_name_and_annotations() {
    let parsed = spec(
        "type: smtp\ntargetRef:\n  kind: MailIdentity\n  name: me\nsecretTemplate:\n  metadata:\n    name: me-app\n    annotations:\n      example.com/application: mail-agent\n",
    );
    let template = parsed.secret_template().expect("a template was requested");
    assert_eq!(template.metadata().name(), Some("me-app"));
    assert_eq!(
        template.metadata().annotations()["example.com/application"],
        "mail-agent"
    );

    let error = MailCredentialSpec::parse(
        "type: smtp\ntargetRef:\n  kind: MailIdentity\n  name: me\nsecretTemplate:\n  metadata:\n    name: Not A Name\n",
    )
    .expect_err("an invalid Secret name is refused");
    assert!(matches!(error, SpecError::InvalidName { .. }));
}

#[test]
fn the_reader_is_the_only_way_admission_touches_the_cluster() {
    // A reader that answers nothing fails the request closed rather than
    // admitting it on the strength of the credential document alone.
    struct Silent;
    impl ParentStatusReader for Silent {
        fn provider(
            &self,
            _namespace: &str,
            _name: &str,
        ) -> Result<
            mail_credential::admission::ProviderStatus,
            mail_credential::admission::StatusReadError,
        > {
            Err(mail_credential::admission::StatusReadError::Unavailable)
        }
        fn mailbox(
            &self,
            _namespace: &str,
            _name: &str,
        ) -> Result<
            mail_credential::admission::MailboxStatus,
            mail_credential::admission::StatusReadError,
        > {
            Err(mail_credential::admission::StatusReadError::Unavailable)
        }
        fn identity(
            &self,
            _namespace: &str,
            _name: &str,
        ) -> Result<
            mail_credential::admission::IdentityStatus,
            mail_credential::admission::StatusReadError,
        > {
            Err(mail_credential::admission::StatusReadError::Unavailable)
        }
        fn gateway(
            &self,
            _namespace: &str,
            _name: &str,
        ) -> Result<GatewayStatus, mail_credential::admission::StatusReadError> {
            Err(mail_credential::admission::StatusReadError::Unavailable)
        }
    }

    let decision = mail_credential::admission::admit(&request(SCOPED_MCP), &Silent, &policy());
    assert_eq!(reason_of(&decision), Reason::DependencyUnavailable);
}
