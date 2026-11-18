use std::cell::Cell;

use mail_admin::{
    Capabilities, Deadline, Operation, ProviderError, ProviderStatus, ReadProtocol,
    SubmissionProtocol,
};
use provider_migadu::{CallFailure, Migadu, MigaduError, MigaduResponse, Request};
use std::time::Duration;

fn capabilities() -> Capabilities {
    Capabilities::new([Operation::ListDomains, Operation::GetUsage])
        .with_protocols([ReadProtocol::Imap], [SubmissionProtocol::Smtp])
}

fn deadline() -> Deadline {
    Deadline::after(Duration::from_secs(30))
}

#[test]
fn capability_fixture_gates_operations() {
    let client = Migadu::new(capabilities());
    assert!(
        client
            .execute(Request::ListDomains, deadline(), |_, _| Ok(
                MigaduResponse::Empty
            ))
            .is_ok()
    );
    let error = client
        .execute(Request::GetHealth, deadline(), |_, _| {
            Ok(MigaduResponse::Empty)
        })
        .expect_err("an unadvertised operation must be refused");
    assert_eq!(
        error,
        MigaduError::Contract(ProviderError::Unsupported(Operation::GetHealth))
    );
}

#[test]
fn protocol_selection_is_gated_on_the_advertised_capabilities() {
    let client = Migadu::new(capabilities());
    let selection = client.protocol_selection("imap", "smtp").unwrap();
    assert_eq!(selection.read(), ReadProtocol::Imap);
    assert_eq!(selection.submission(), SubmissionProtocol::Smtp);
    // The provider does not advertise JMAP, so a JMAP read cannot be selected.
    assert_eq!(
        client.protocol_selection("jmap", "smtp"),
        Err(ProviderError::ProtocolNotAdvertised {
            protocol: "jmap".into()
        })
    );
    // Disabling submission needs no provider capability.
    assert!(client.protocol_selection("imap", "disabled").is_ok());
}

#[test]
fn a_delete_request_is_refused_with_a_typed_unsupported_error() {
    let client = Migadu::new(capabilities());
    let called = Cell::new(false);
    let error = client
        .execute(
            Request::DeleteDomain("example.test".into()),
            deadline(),
            |_, _| {
                called.set(true);
                Ok(MigaduResponse::Empty)
            },
        )
        .expect_err("a destructive request must never be dispatched");
    assert_eq!(
        error,
        MigaduError::Contract(ProviderError::UnsupportedOperation {
            name: "delete_domain".into(),
        })
    );
    assert!(
        !called.get(),
        "the provider must not be called for a delete"
    );
}

#[test]
fn a_wire_operation_outside_the_allowlist_is_refused() {
    let client = Migadu::new(capabilities());
    assert_eq!(
        client.resolve_operation("delete_mailbox"),
        Err(MigaduError::Contract(ProviderError::UnsupportedOperation {
            name: "delete_mailbox".into(),
        }))
    );
    assert_eq!(
        client.resolve_operation("list_domains"),
        Ok(Operation::ListDomains)
    );
    assert_eq!(
        client.resolve_operation("get_health"),
        Err(MigaduError::Contract(ProviderError::Unsupported(
            Operation::GetHealth
        )))
    );
}

#[test]
fn provider_failures_are_typed() {
    let client = Migadu::new(capabilities());
    let cases = [
        (CallFailure::NotConfigured, ProviderStatus::NotConfigured),
        (
            CallFailure::ValidationFailed,
            ProviderStatus::ValidationFailed,
        ),
        (CallFailure::ProviderOutage, ProviderStatus::ProviderOutage),
        (CallFailure::Drift, ProviderStatus::Drift),
    ];
    for (failure, status) in cases {
        let error = client
            .execute(
                Request::ListDomains,
                deadline(),
                |_, _| Err(failure.clone()),
            )
            .expect_err("the provider call failed");
        assert_eq!(error, MigaduError::Status(status));
    }
}

#[test]
fn a_call_is_not_made_after_the_deadline_passed() {
    let client = Migadu::new(capabilities());
    let called = Cell::new(false);
    let error = client
        .execute(
            Request::ListDomains,
            Deadline::after(Duration::ZERO),
            |_, _| {
                called.set(true);
                Ok(MigaduResponse::Empty)
            },
        )
        .expect_err("an expired deadline must stop the call");
    assert_eq!(error, MigaduError::DeadlineExceeded);
    assert!(!called.get(), "no call may start after the deadline");
}

#[test]
fn the_call_receives_the_deadline_it_must_run_within() {
    let client = Migadu::new(capabilities());
    let expected = deadline();
    let seen = client
        .execute(Request::ListDomains, expected, |_, call_deadline| {
            assert_eq!(call_deadline, expected);
            assert!(!call_deadline.expired());
            Ok(MigaduResponse::Empty)
        })
        .unwrap();
    assert_eq!(seen, MigaduResponse::Empty);
}

#[test]
fn a_deadline_reported_by_the_boundary_is_typed() {
    let client = Migadu::new(capabilities());
    let error = client
        .execute(Request::ListDomains, deadline(), |_, _| {
            Err(CallFailure::DeadlineExceeded)
        })
        .expect_err("the call outlived its deadline");
    assert_eq!(error, MigaduError::DeadlineExceeded);
}

#[test]
fn outage_does_not_synthesize_unsupported_usage_or_recipient_provenance() {
    let client = Migadu::new(capabilities());
    let result = client.execute(
        Request::GetUsage {
            domain: None,
            mailbox: None,
        },
        deadline(),
        |_, _| Err(CallFailure::ProviderOutage),
    );
    assert!(result.is_err());
    assert!(MigaduResponse::Empty.trusted_recipient().is_none());
}
