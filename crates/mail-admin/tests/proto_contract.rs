//! The wire contract and the Rust vocabulary must agree.
//!
//! The `.proto` files are the contract. These tests bind the Rust types to
//! them: an operation, protocol or status name that exists on one side and
//! not the other is a contract defect, not a documentation nit.

use mail_admin::{
    MAX_EXECUTE_PAYLOAD_BYTES, MAX_SNAPSHOT_BYTES, Operation, ProviderStatus, ReadProtocol,
    SubmissionProtocol,
};

const PROVIDER_PROTO: &str = include_str!("../../../api/provider/v1/provider.proto");
const CONFIG_PROTO: &str = include_str!("../../../api/config/v1/config.proto");

/// Read the names listed under an "Allowlisted ..." heading.
fn allowlist(proto: &str, heading: &str) -> Vec<String> {
    let marker = format!("// {heading}:");
    let mut names = Vec::new();
    let mut collecting = false;
    for line in proto.lines() {
        if !collecting {
            if line.trim() == marker {
                collecting = true;
            }
            continue;
        }
        match line.strip_prefix("//   ") {
            Some(name) => names.push(name.trim().to_string()),
            None => break,
        }
    }
    names
}

#[test]
fn the_proto_operation_allowlist_matches_the_rust_vocabulary() {
    let declared = allowlist(PROVIDER_PROTO, "Allowlisted operations");
    let rust: Vec<String> = Operation::ALL
        .iter()
        .map(|operation| operation.as_wire().to_string())
        .collect();
    assert_eq!(
        declared.to_vec(),
        rust,
        "the proto operation allowlist and the Rust vocabulary must be the same set"
    );
}

#[test]
fn the_proto_does_not_allowlist_a_destructive_operation() {
    let declared = allowlist(PROVIDER_PROTO, "Allowlisted operations");
    assert!(
        !declared.iter().any(|name| name.starts_with("delete_")),
        "a destructive operation must never be dispatchable"
    );
}

#[test]
fn the_proto_protocol_allowlists_match_the_rust_vocabulary() {
    assert_eq!(
        allowlist(PROVIDER_PROTO, "Allowlisted read protocols"),
        ReadProtocol::ALL
            .iter()
            .map(|protocol| protocol.as_wire().to_string())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        allowlist(PROVIDER_PROTO, "Allowlisted submission protocols"),
        SubmissionProtocol::ADVERTISABLE
            .iter()
            .map(|protocol| protocol.as_wire().to_string())
            .collect::<Vec<_>>()
    );
}

#[test]
fn the_proto_status_allowlist_matches_the_rust_vocabulary() {
    assert_eq!(
        allowlist(PROVIDER_PROTO, "Allowlisted statuses"),
        ProviderStatus::ALL
            .iter()
            .map(|status| status.as_wire().to_string())
            .collect::<Vec<_>>()
    );
}

#[test]
fn the_proto_states_the_message_limit_the_rust_types_enforce() {
    assert_eq!(MAX_EXECUTE_PAYLOAD_BYTES, 1_048_576);
    assert_eq!(MAX_SNAPSHOT_BYTES, 1_048_576);
    // The limit is bound to the field the contract actually bounds, not to a
    // number that may appear anywhere in the file: the comment on the bounded
    // field must state exactly what the Rust type enforces.
    assert_eq!(
        declared_byte_limit(PROVIDER_PROTO, "message ExecuteRequest", "bounded_payload"),
        MAX_EXECUTE_PAYLOAD_BYTES,
        "the ExecuteRequest field comment and the Rust limit must agree"
    );
    assert_eq!(
        declared_byte_limit(PROVIDER_PROTO, "message ExecuteResponse", "bounded_payload"),
        MAX_EXECUTE_PAYLOAD_BYTES,
        "the ExecuteResponse field comment and the Rust limit must agree"
    );
    assert_eq!(
        declared_byte_limit(
            CONFIG_PROTO,
            "message PublishSnapshotRequest",
            "bounded_snapshot"
        ),
        MAX_SNAPSHOT_BYTES,
        "the PublishSnapshotRequest field comment and the Rust limit must agree"
    );
}

/// The byte limit stated in the comment directly above a field, in bytes.
///
/// Fails the test rather than returning a default when the comment is
/// missing or no longer states a byte count: a silent drift from the contract
/// is exactly what these tests exist to catch.
fn declared_byte_limit(proto: &str, message: &str, field: &str) -> usize {
    let lines: Vec<&str> = proto.lines().collect();
    let start = lines
        .iter()
        .position(|line| line.starts_with(message))
        .unwrap_or_else(|| {
            panic!(
                "{proto_name} has no {message}",
                proto_name = if proto.contains("corvi.provider.v1") {
                    "provider.proto"
                } else {
                    "config.proto"
                }
            )
        });
    let block_end = lines[start..]
        .iter()
        .position(|line| *line == "}")
        .expect("the message block is closed");
    let block = &lines[start..start + block_end];
    let field_line = block
        .iter()
        .position(|line| line.contains(field) && line.contains(" bytes "))
        .unwrap_or_else(|| panic!("{message} does not declare a bytes field named {field}"));

    // The limit lives in the `//` comment block immediately above the field.
    let mut comment = String::new();
    for line in block[..field_line].iter().rev() {
        match line.trim_start().strip_prefix("//") {
            Some(text) => comment.insert_str(0, text),
            None => break,
        }
    }
    let bytes_unit = comment
        .find(" bytes)")
        .unwrap_or_else(|| panic!("the comment on {field} does not state a byte limit"));
    let digits: String = comment[..bytes_unit]
        .chars()
        .rev()
        .take_while(|character| character.is_ascii_digit())
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    digits
        .parse::<usize>()
        .unwrap_or_else(|_| panic!("the comment on {field} states no byte count: {comment:?}"))
}

#[test]
fn configuration_publication_is_not_part_of_the_provider_surface() {
    assert!(PROVIDER_PROTO.contains("package corvi.provider.v1;"));
    assert!(!PROVIDER_PROTO.contains("Snapshot"));
    assert!(CONFIG_PROTO.contains("package corvi.config.v1;"));
    assert!(CONFIG_PROTO.contains("service ConfigurationService"));
    assert!(!CONFIG_PROTO.contains("ProviderAdmin"));
}

#[test]
fn the_configuration_service_states_the_digest_algorithm() {
    assert!(CONFIG_PROTO.contains("lowercase hex SHA-256"));
    assert!(CONFIG_PROTO.contains("digest"));
}

#[test]
fn the_provider_service_states_the_deadline_rule() {
    assert!(PROVIDER_PROTO.contains("deadline"));
}
