//! Helpers for exercising the gateway without a deployment.
//!
//! The helpers build a real configuration, real secret files and a real
//! gateway, so a test exercises the same code a deployment runs. The only
//! thing a test replaces is the upstream, which is a fixture file.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use mail_config::{Snapshot, SnapshotStore};

use crate::fixture::{FixtureFile, FixtureUpstream};
use crate::policy::{PolicyConfig, PolicyStore};
use crate::service::{Caller, Clock, FixedClock, Gateway, GatewayBuilder};

/// A temporary directory that holds a test's configuration.
#[derive(Debug)]
pub struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    /// Create a directory for a test.
    pub fn new(name: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("corvi-{name}-{}", crate::time::random_id_of(8)));
        fs::create_dir_all(&path).expect("the test directory can be created");
        Self { path }
    }

    /// The directory's path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Write a secret file that only its owner may read.
    pub fn write_secret(&self, name: &str, value: &str) -> PathBuf {
        let path = self.path.join(name);
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path).expect("the secret file can be created");
        file.write_all(value.as_bytes())
            .expect("the secret file can be written");
        file.write_all(b"\n")
            .expect("the secret file can be written");
        path
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// A gateway and everything a test needs to drive it.
#[derive(Debug)]
pub struct TestEnvironment {
    /// The directory holding the configuration.
    pub directory: TestDirectory,
    /// The gateway under test.
    pub gateway: Gateway,
    /// The fixture upstream the gateway reads.
    pub upstream: Arc<FixtureUpstream>,
    /// The token the test presents.
    pub token: String,
}

impl TestEnvironment {
    /// Build an environment with one credential and one secret file.
    ///
    /// The secret file is written with owner-only permissions, exactly as a
    /// deployment must write it, so the test exercises the same secret
    /// handling a deployment does.
    pub fn build(
        name: &str,
        grants: &str,
        policies_yaml: &str,
        fixture_json: &str,
        clock: Option<Arc<dyn Clock>>,
    ) -> Self {
        let directory = TestDirectory::new(name);
        let secret = directory.write_secret("agent.token", "test-token");
        let snapshot_yaml = snapshot_document(&secret, grants);
        Self::from_documents(
            directory,
            &snapshot_yaml,
            policies_yaml,
            fixture_json,
            clock,
        )
    }

    /// Build an environment from full documents.
    pub fn from_documents(
        directory: TestDirectory,
        snapshot_yaml: &str,
        policies_yaml: &str,
        fixture_json: &str,
        clock: Option<Arc<dyn Clock>>,
    ) -> Self {
        let snapshot = Snapshot::from_yaml(snapshot_yaml).expect("the snapshot document is valid");
        let config = Arc::new(SnapshotStore::new(snapshot).expect("the snapshot validates"));
        let policies =
            Arc::new(PolicyStore::from_yaml(policies_yaml).expect("the policy document is valid"));
        let upstream = Arc::new(
            FixtureUpstream::from_json(fixture_json).expect("the fixture document is valid"),
        );
        let mut builder = GatewayBuilder::new(config, policies, upstream.clone());
        if let Some(clock) = clock {
            builder = builder.clock(clock);
        }
        Self {
            directory,
            gateway: builder.build(),
            upstream,
            token: "test-token".to_owned(),
        }
    }

    /// Authenticate the environment's token.
    pub fn caller(&self) -> Caller {
        self.gateway
            .authenticate(&self.token)
            .expect("the test token authenticates")
    }
}

/// A clock a test can move forward.
#[derive(Debug)]
pub struct TestClock {
    now: std::sync::atomic::AtomicU64,
}

impl TestClock {
    /// Create a clock that reports `epoch_seconds`.
    pub fn new(epoch_seconds: u64) -> Arc<Self> {
        Arc::new(Self {
            now: std::sync::atomic::AtomicU64::new(epoch_seconds),
        })
    }

    /// Move the clock forward.
    pub fn advance(&self, seconds: u64) {
        self.now
            .fetch_add(seconds, std::sync::atomic::Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now(&self) -> u64 {
        self.now.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// A policy document that shows everything, with attachments downloadable.
pub const PERMISSIVE_POLICIES: &str = "\
generation: 1
policies:
  - id: default
    default_visibility: show
    on_indeterminate: hide
    rendering:
      html: sanitized
      remote_content: strip
      attachments: full
      external_links: sanitize
    rules: []
bindings:
  personal: default
  work: default
";

/// A snapshot document with one identity and one credential.
///
/// `grants` is the YAML list of granted actions for the `personal` identity.
pub fn snapshot_document(secret_path: &Path, grants: &str) -> String {
    format!(
        "generation: 1\n\
         listen: \"127.0.0.1:0\"\n\
         allow_loopback_plaintext: true\n\
         identities:\n  \
         - id: personal\n    \
         mailbox: INBOX\n    \
         address: me@example.com\n    \
         display_name: Me\n    \
         isolation: verified\n  \
         - id: work\n    \
         mailbox: WORK\n    \
         address: me@work.example\n    \
         isolation: dedicated\n\
         credentials:\n  \
         - id: agent\n    \
         token:\n      \
         secret: \"file://{secret}\"\n    \
         grants:\n      \
         - identity: personal\n        \
         actions:\n{grants}",
        secret = secret_path.display()
    )
}

/// A fixture document with one visible message and one hidden message.
pub const DEFAULT_FIXTURE: &str = r#"{
  "messages": [
    {
      "id": "m-1",
      "mailbox": "INBOX",
      "from": {"address": "sender@example.com", "displayName": "Sender"},
      "to": [{"address": "me@example.com"}],
      "subject": "Invoice 2026",
      "textBody": "Please pay the invoice of 42 euros.",
      "date": "2026-01-02T10:00:00Z",
      "flags": ["seen"],
      "trustedRecipient": "me@example.com",
      "attachments": [
        {"id": "a-1", "filename": "invoice.txt", "contentType": "text/plain", "base64": "aW52b2ljZQ=="}
      ]
    },
    {
      "id": "m-2",
      "mailbox": "INBOX",
      "from": {"address": "secret@example.com"},
      "to": [{"address": "me@example.com"}],
      "subject": "Your one-time code",
      "textBody": "Code 123456",
      "date": "2026-01-01T10:00:00Z",
      "trustedRecipient": "me@example.com"
    }
  ]
}"#;

/// A policy document that hides any message whose subject mentions a code.
pub const HIDING_POLICIES: &str = "\
generation: 1
policies:
  - id: default
    default_visibility: show
    on_indeterminate: hide
    rendering:
      html: sanitized
      remote_content: strip
      attachments: full
      external_links: sanitize
    rules:
      - id: hide-codes
        when: !text
          field: subject
          match: contains
          value: one-time
        then: !visibility
          value: hide
bindings:
  personal: default
  work: default
";

/// Build a policy store from a document.
pub fn policy_store(document: &str) -> Arc<PolicyStore> {
    Arc::new(PolicyStore::from_yaml(document).expect("the policy document is valid"))
}

/// Build a policy configuration from a document.
pub fn policy_config(document: &str) -> PolicyConfig {
    serde_yaml::from_str(document).expect("the policy document is valid")
}

/// A clock that never moves.
pub fn fixed_clock(epoch_seconds: u64) -> Arc<dyn Clock> {
    Arc::new(FixedClock::new(epoch_seconds))
}

/// A fixture document parsed from JSON.
pub fn fixture_file(document: &str) -> FixtureFile {
    serde_json::from_str(document).expect("the fixture document is valid")
}
