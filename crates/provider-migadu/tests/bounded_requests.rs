//! The adapter enforces the contract's payload bound itself.
//!
//! The proto gives `ExecuteRequest.bounded_payload` at most 1 MiB, and
//! `mail_admin::BoundedPayload` enforces it on the type a caller constructs.
//! The adapter does not trust where a `Request` came from: an oversized
//! configuration is refused at the boundary, before the provider closure is
//! called at all.

use std::cell::Cell;

use mail_admin::{
    Capabilities, Deadline, MAX_EXECUTE_PAYLOAD_BYTES, Operation, ProviderError, ReadProtocol,
    SubmissionProtocol,
};
use provider_migadu::{Migadu, MigaduError, MigaduResponse, Request};
use std::time::Duration;

fn capabilities() -> Capabilities {
    Capabilities::new([
        Operation::ListDomains,
        Operation::UpdateDomain,
        Operation::UpdateMailbox,
    ])
    .with_protocols([ReadProtocol::Imap], [SubmissionProtocol::Smtp])
}

fn deadline() -> Deadline {
    Deadline::after(Duration::from_secs(30))
}

#[test]
fn an_oversized_request_config_is_refused_before_the_provider_is_called() {
    let client = Migadu::new(capabilities());
    let called = Cell::new(false);
    let oversized = vec![0u8; MAX_EXECUTE_PAYLOAD_BYTES + 1];

    let error = client
        .execute(
            Request::UpdateDomain {
                name: "example.test".into(),
                config: oversized,
            },
            deadline(),
            |_, _| {
                called.set(true);
                Ok(MigaduResponse::Empty)
            },
        )
        .expect_err("a request past the contract limit must be refused");

    assert_eq!(error, MigaduError::Contract(ProviderError::PayloadTooLarge));
    assert!(
        !called.get(),
        "an oversized request must never reach the provider"
    );
}

#[test]
fn an_oversized_mailbox_config_is_refused_before_the_provider_is_called() {
    let client = Migadu::new(capabilities());
    let called = Cell::new(false);
    let oversized = vec![0u8; MAX_EXECUTE_PAYLOAD_BYTES + 1];

    let error = client
        .execute(
            Request::UpdateMailbox {
                domain: "example.test".into(),
                local_part: "alice".into(),
                config: oversized,
            },
            deadline(),
            |_, _| {
                called.set(true);
                Ok(MigaduResponse::Empty)
            },
        )
        .expect_err("a request past the contract limit must be refused");

    assert_eq!(error, MigaduError::Contract(ProviderError::PayloadTooLarge));
    assert!(!called.get());
}

#[test]
fn a_config_at_the_exact_limit_still_reaches_the_provider() {
    let client = Migadu::new(capabilities());
    let called = Cell::new(false);
    let at_limit = vec![0u8; MAX_EXECUTE_PAYLOAD_BYTES];

    let response = client
        .execute(
            Request::UpdateDomain {
                name: "example.test".into(),
                config: at_limit,
            },
            deadline(),
            |_, _| {
                called.set(true);
                Ok(MigaduResponse::Empty)
            },
        )
        .expect("a request at the contract limit is allowed");

    assert_eq!(response, MigaduResponse::Empty);
    assert!(called.get());
}
