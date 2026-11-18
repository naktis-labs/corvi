//! The JMAP upstream inside the gateway pipeline.
//!
//! ADR-0007 section 8 asks for "one MCP credential accessing an IMAP
//! identity and a Fastmail/JMAP identity with separate permissions". These
//! tests hold the gateway to that: one credential holds two identities, one
//! of them is served over JMAP and the other over the local fixture, and
//! neither identity's mail reaches the other.

mod common;

use std::collections::HashMap;
use std::sync::Arc;

use mail_api::fixture::FixtureUpstream;
use mail_api::jmap_upstream::JmapUpstream;
use mail_api::policy::PolicyStore;
use mail_api::service::{Gateway, GatewayBuilder, ListRequest};
use mail_api::testing::{DEFAULT_FIXTURE, PERMISSIVE_POLICIES, TestDirectory};
use mail_config::{Snapshot, SnapshotStore};
use mail_core::IdentityId;
use mail_jmap::client::JmapClient;
use mail_jmap::testing::FixtureTransport;
use mail_jmap::trust::{EgressPolicy, Origin, StaticResolver};
use serde_json::{Value, json};

const SESSION: &str = include_str!("../../mail-jmap/tests/fixtures/session.json");
const QUERY: &str = include_str!("../../mail-jmap/tests/fixtures/query.json");
const EMAILS: &str = include_str!("../../mail-jmap/tests/fixtures/emails.json");

/// Wrap a fixture in the JMAP response envelope.
fn envelope(method: &str, call_id: &str, arguments: Value) -> Value {
    json!({"methodResponses": [[method, arguments, call_id]]})
}

/// The upstream the JMAP identity reads from.
fn jmap_transport() -> FixtureTransport {
    FixtureTransport::new()
        .on_get(
            "/jmap/session",
            serde_json::from_str(SESSION).expect("a valid session"),
        )
        .on_post_body(
            "/jmap/api",
            "\"Mailbox/get\"",
            envelope(
                "Mailbox/get",
                "m0",
                json!({
                    "accountId": "acct-personal",
                    "list": [
                        {"id": "mbx-work", "name": "WORK", "role": "other"},
                        {"id": "mbx-inbox", "name": "INBOX", "role": "inbox"}
                    ],
                    "notFound": []
                }),
            ),
        )
        .on_post_body(
            "/jmap/api",
            "\"Email/query\"",
            envelope(
                "Email/query",
                "m0",
                serde_json::from_str(QUERY).expect("valid"),
            ),
        )
        .on_post_body(
            "/jmap/api",
            "\"Email/get\"",
            envelope(
                "Email/get",
                "m1",
                serde_json::from_str(EMAILS).expect("valid"),
            ),
        )
}

/// A JMAP client that talks to the fixture upstream.
fn jmap_client() -> JmapClient {
    let policy = EgressPolicy::new(vec![
        Origin::parse("https://api.example.com").expect("a valid origin"),
    ]);
    let resolver = StaticResolver::new().with_host(
        "api.example.com",
        vec!["93.184.216.34".parse().expect("an address")],
    );
    let mut client = JmapClient::new(Box::new(jmap_transport()), policy)
        .with_resolver(Box::new(resolver))
        .with_credential(mail_jmap::Credential::bearer("upstream-token"));
    client
        .discover("https://api.example.com/jmap/session")
        .expect("the session is discovered");
    client
}

/// The actions the test credentials hold.
const ACTION_NAMES: [&str; 8] = [
    "mail:identities:list",
    "mail:messages:list",
    "mail:messages:read",
    "mail:messages:search",
    "mail:attachments:read",
    "mail:messages:send",
    "mail:submissions:read",
    "mail:messages:subscribe",
];

/// The granted actions, one per line.
fn actions(indent: &str) -> String {
    ACTION_NAMES
        .iter()
        .map(|action| format!("{indent}- {action}\n"))
        .collect()
}

/// A snapshot with two identities and two credentials.
fn snapshot(agent_secret: &std::path::Path, reader_secret: &std::path::Path) -> String {
    format!(
        "generation: 1\n\
         listen: \"127.0.0.1:0\"\n\
         allow_loopback_plaintext: true\n\
         identities:\n  \
         - id: personal\n    \
         mailbox: INBOX\n    \
         address: me@example.com\n    \
         isolation: verified\n  \
         - id: work\n    \
         mailbox: WORK\n    \
         address: me@work.example\n    \
         isolation: dedicated\n\
         credentials:\n  \
         - id: agent\n    \
         token:\n      \
         secret: \"file://{agent_secret}\"\n    \
         grants:\n      \
         - identity: personal\n        \
         actions:\n{personal}      \
         - identity: work\n        \
         actions:\n{work}  \
         - id: reader\n    \
         token:\n      \
         secret: \"file://{reader_secret}\"\n    \
         grants:\n      \
         - identity: personal\n        \
         actions:\n{personal}",
        agent_secret = agent_secret.display(),
        reader_secret = reader_secret.display(),
        personal = actions("          "),
        work = actions("          "),
    )
}

/// A gateway whose `work` identity is served over JMAP.
fn environment(name: &str) -> (Gateway, TestDirectory) {
    let directory = TestDirectory::new(name);
    let agent_secret = directory.write_secret("agent.token", "test-token");
    let reader_secret = directory.write_secret("reader.token", "reader-token");
    let document = snapshot(&agent_secret, &reader_secret);
    let config = Arc::new(
        SnapshotStore::new(Snapshot::from_yaml(&document).expect("the snapshot is valid"))
            .expect("the snapshot validates"),
    );
    let policies =
        Arc::new(PolicyStore::from_yaml(PERMISSIVE_POLICIES).expect("the policies are valid"));
    let fixture =
        Arc::new(FixtureUpstream::from_json(DEFAULT_FIXTURE).expect("the fixture is valid"));
    let mut accounts = HashMap::new();
    accounts.insert("work".to_owned(), "acct-personal".to_owned());
    let upstream = Arc::new(JmapUpstream::new(jmap_client(), accounts).with_remaining(fixture));
    let gateway = GatewayBuilder::new(config, policies, upstream).build();
    (gateway, directory)
}

#[test]
fn one_credential_serves_an_imap_identity_and_a_jmap_identity() {
    let (gateway, _directory) = environment("jmap-mixed");
    let caller = gateway
        .authenticate("test-token")
        .expect("the credential authenticates");

    let personal = gateway
        .list_messages(
            &caller,
            &ListRequest {
                identity: IdentityId::new("personal"),
                limit: 10,
                cursor: None,
            },
        )
        .expect("the local identity lists");
    let work = gateway
        .list_messages(
            &caller,
            &ListRequest {
                identity: IdentityId::new("work"),
                limit: 10,
                cursor: None,
            },
        )
        .expect("the JMAP identity lists");

    // The local identity keeps its own mail.
    assert!(personal.items.iter().any(|item| item.id == "m-1"));
    // The JMAP identity is served over JMAP.
    assert_eq!(work.items.len(), 1);
    assert_eq!(work.items[0].subject.as_deref(), Some("Invoice 2026"));
}

#[test]
fn the_jmap_upstream_identifiers_never_reach_the_caller() {
    let (gateway, _directory) = environment("jmap-ids");
    let caller = gateway
        .authenticate("test-token")
        .expect("the credential authenticates");
    let work = gateway
        .list_messages(
            &caller,
            &ListRequest {
                identity: IdentityId::new("work"),
                limit: 10,
                cursor: None,
            },
        )
        .expect("the JMAP identity lists");

    let id = &work.items[0].id;
    assert!(id.starts_with("msg_"), "the identifier is opaque: {id}");
    assert!(!id.contains("M-email-1"));
    let encoded = serde_json::to_string(&work.items).expect("the listing is JSON");
    assert!(!encoded.contains("M-email-1"));
    assert!(!encoded.contains("acct-personal"));
}

#[test]
fn a_credential_without_the_jmap_grant_sees_nothing_of_it() {
    let (gateway, _directory) = environment("jmap-cross-principal");
    let reader = gateway
        .authenticate("reader-token")
        .expect("the credential authenticates");
    // The `reader` credential holds a grant on `personal` only, so the
    // `work` identity is outside its grant set and must be indistinguishable
    // from one that does not exist.
    let granted = gateway
        .list_identities(&reader)
        .expect("the identities list");
    assert_eq!(granted.items.len(), 1);
    assert_eq!(granted.items[0].id, "personal");

    let error = gateway
        .list_messages(
            &reader,
            &ListRequest {
                identity: IdentityId::new("work"),
                limit: 10,
                cursor: None,
            },
        )
        .expect_err("the identity is not granted");
    assert_eq!(error.error_code(), "NOT_FOUND");
}
