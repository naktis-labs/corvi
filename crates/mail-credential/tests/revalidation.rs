//! Continuous revalidation of an issued credential.

use mail_credential::admission::resolve_graph;
use mail_credential::model::MailCredential;
use mail_credential::reasons::Reason;
use mail_credential::revalidate::{IssuedCredential, RevalidationDecision, revalidate};
use mail_credential::testing::{
    FIXTURE_NAMESPACE, FakeGraph, gateway, identity, mailbox, provider_bound, provider_unbound,
};

const SCOPED_MCP: &str = "type: mcp\ntargetRef:\n  kind: MailIdentity\n  name: me\npermissions:\n  - mail:messages:read\n";

const NATIVE_SMTP: &str = "type: smtp\ntargetRef:\n  kind: MailIdentity\n  name: me\n";

fn credential(document: &str) -> MailCredential {
    let spec = mail_credential::model::MailCredentialSpec::parse(document).expect("valid spec");
    MailCredential::new("me-mcp", FIXTURE_NAMESPACE, "credential-uid", 1, spec)
}

fn bound_graph() -> FakeGraph {
    FakeGraph::new()
        .with_provider(provider_bound("fastmail", "primary"))
        .with_mailbox(mailbox("personal", "fastmail"))
        .with_identity(identity("me", "personal"))
        .with_gateway(gateway("primary"))
}

fn direct_graph() -> FakeGraph {
    FakeGraph::new()
        .with_provider(provider_unbound("administration-only"))
        .with_mailbox(mailbox("personal", "administration-only"))
        .with_identity(identity("me", "personal"))
}

fn issued(credential: &MailCredential, graph: &FakeGraph) -> IssuedCredential {
    let resolved = resolve_graph(credential, graph).expect("the fixture resolves");
    IssuedCredential::record(
        credential,
        resolved.authority,
        resolved.chain,
        "revision-42",
        "me-mcp-app",
    )
}

#[test]
fn an_unchanged_graph_keeps_the_credential() {
    let graph = bound_graph();
    let credential = credential(SCOPED_MCP);
    let issued = issued(&credential, &graph);

    assert_eq!(
        revalidate(&issued, &credential, &graph),
        RevalidationDecision::Keep
    );
}

#[test]
fn a_suspended_gateway_revokes_the_credential() {
    let mut graph = bound_graph();
    let credential = credential(SCOPED_MCP);
    let issued = issued(&credential, &graph);

    graph.gateways_mut("primary").suspended = true;
    let decision = revalidate(&issued, &credential, &graph);

    assert_eq!(decision.reason(), Some(Reason::GatewayUnavailable));
    assert!(matches!(decision, RevalidationDecision::Revoke { .. }));
}

#[test]
fn a_suspended_identity_revokes_the_credential() {
    let mut graph = bound_graph();
    let credential = credential(SCOPED_MCP);
    let issued = issued(&credential, &graph);

    graph.identities_mut("me").suspended = true;
    let decision = revalidate(&issued, &credential, &graph);

    assert_eq!(decision.reason(), Some(Reason::TargetSuspended));
}

#[test]
fn a_changed_parent_revokes_the_credential() {
    let mut graph = bound_graph();
    let credential = credential(SCOPED_MCP);
    let issued = issued(&credential, &graph);

    // The provider changed and the controller reconciled it, so the status
    // is fresh again but the chain is not the one the credential was
    // issued against.
    let provider = graph.providers_mut("fastmail");
    provider.generation = 2;
    provider.observed_generation = 2;
    provider.capabilities_observed_generation = 2;

    let decision = revalidate(&issued, &credential, &graph);

    assert_eq!(decision.reason(), Some(Reason::ParentChanged));
}

#[test]
fn a_scoped_credential_is_never_converted_into_a_native_credential() {
    let mut graph = bound_graph();
    let credential = credential(SCOPED_MCP);
    let issued = issued(&credential, &graph);

    // The provider is detached from its gateway. The credential does not
    // become a provider-native credential; it loses its authority.
    graph.providers_mut("fastmail").gateway_ref = None;

    let decision = revalidate(&issued, &credential, &graph);

    assert_eq!(
        decision.reason(),
        Some(Reason::GatewayRequiredForScopedCredential)
    );
    assert!(matches!(decision, RevalidationDecision::Revoke { .. }));
}

#[test]
fn a_native_credential_is_never_converted_into_a_gateway_credential() {
    let mut graph = direct_graph();
    let credential = credential(NATIVE_SMTP);
    let issued = issued(&credential, &graph);

    // The provider is attached to a gateway. The credential does not gain
    // Corvi scope; it has to be authorized again.
    graph.providers_mut("administration-only").gateway_ref =
        Some(mail_credential::admission::LocalRef::new("primary"));

    let decision = revalidate(&issued, &credential, &graph);

    assert_eq!(decision.reason(), Some(Reason::MissingGatewayPermissions));
    assert!(matches!(decision, RevalidationDecision::Revoke { .. }));
}

#[test]
fn a_changed_mailbox_revokes_the_credential() {
    let mut graph = bound_graph();
    let credential = credential(SCOPED_MCP);
    let issued = issued(&credential, &graph);

    // The mailbox was reparented: its generation moved on and the
    // controller reconciled it.
    let mailbox = graph.mailboxes_mut("personal");
    mailbox.generation = 2;
    mailbox.observed_generation = 2;

    let decision = revalidate(&issued, &credential, &graph);

    assert_eq!(decision.reason(), Some(Reason::ParentChanged));
}

#[test]
fn a_suspended_mailbox_revokes_the_credential() {
    let mut graph = bound_graph();
    let credential = credential(SCOPED_MCP);
    let issued = issued(&credential, &graph);

    graph.mailboxes_mut("personal").suspended = true;

    let decision = revalidate(&issued, &credential, &graph);

    assert_eq!(decision.reason(), Some(Reason::TargetSuspended));
}

#[test]
fn a_changed_gateway_revokes_the_credential() {
    let mut graph = bound_graph();
    let credential = credential(SCOPED_MCP);
    let issued = issued(&credential, &graph);

    let gateway = graph.gateways_mut("primary");
    gateway.generation = 2;
    gateway.observed_generation = 2;

    let decision = revalidate(&issued, &credential, &graph);

    assert_eq!(decision.reason(), Some(Reason::ParentChanged));
}

#[test]
fn an_unreachable_dependency_withholds_the_output() {
    let mut graph = bound_graph();
    let credential = credential(SCOPED_MCP);
    let issued = issued(&credential, &graph);

    graph.set_unavailable(true);
    let decision = revalidate(&issued, &credential, &graph);

    assert_eq!(decision.reason(), Some(Reason::DependencyUnavailable));
    assert!(matches!(decision, RevalidationDecision::Withhold { .. }));
}

#[test]
fn a_stale_capability_status_withholds_the_output() {
    let mut graph = bound_graph();
    let credential = credential(SCOPED_MCP);
    let issued = issued(&credential, &graph);

    graph
        .providers_mut("fastmail")
        .capabilities_observed_generation = 0;
    let decision = revalidate(&issued, &credential, &graph);

    assert_eq!(decision.reason(), Some(Reason::StaleCapabilityStatus));
    assert!(matches!(decision, RevalidationDecision::Withhold { .. }));
}

#[test]
fn a_lost_capability_revokes_the_credential() {
    let mut graph = direct_graph();
    let credential = credential(NATIVE_SMTP);
    let issued = issued(&credential, &graph);

    graph
        .providers_mut("administration-only")
        .capabilities
        .granularities = vec![mail_credential::admission::CredentialGranularity::ProviderMailbox];

    let decision = revalidate(&issued, &credential, &graph);

    assert_eq!(
        decision.reason(),
        Some(Reason::UnsupportedCredentialGranularity)
    );
}
