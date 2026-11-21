//! The schema migrations.
//!
//! ADR-0010 section 3 requires versioned migrations, a `schema_version`, a
//! refusal to run against a newer incompatible schema, and no automatic
//! destructive downgrade. The migrations here are additive: each one creates
//! tables and indexes and changes nothing that exists.
//!
//! The schema deliberately has **no table for inbound mail**. The
//! provider's mailbox is the source of truth for incoming mail, and the
//! baseline persists no raw MIME and no attachment of an incoming message.
//! The only payload column in the whole schema is the encrypted blob
//! store, which is not part of the relational schema at all.

use rusqlite::Connection;

use crate::error::{StorageError, StorageResult};

/// The schema version this build understands.
pub const SCHEMA_VERSION: u32 = 6;

/// One migration.
#[derive(Debug, Clone, Copy)]
pub struct Migration {
    /// The version the migration brings the schema to.
    pub version: u32,
    /// The name of the migration.
    pub name: &'static str,
    /// The statements of the migration.
    pub sql: &'static str,
}

/// The migrations, in order.
pub fn migrations() -> &'static [Migration] {
    &[
        Migration {
            version: 1,
            name: "initial",
            sql: r#"
CREATE TABLE oauth_clients (
    client_id     TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    redirect_uris TEXT NOT NULL,
    secret_hash   TEXT,
    confidential  INTEGER NOT NULL
);

CREATE TABLE grants (
    grant_id   TEXT PRIMARY KEY,
    client_id  TEXT NOT NULL,
    principal  TEXT NOT NULL,
    identity   TEXT NOT NULL,
    scopes     TEXT NOT NULL,
    revision   INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    revoked_at INTEGER
);
CREATE INDEX grants_principal ON grants(principal);

CREATE TABLE auth_codes (
    code_hash   TEXT PRIMARY KEY,
    client_id   TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    principal   TEXT NOT NULL,
    scopes      TEXT NOT NULL,
    expires_at  INTEGER NOT NULL,
    used_at     INTEGER
);

CREATE TABLE access_tokens (
    token_hash TEXT PRIMARY KEY,
    grant_id   TEXT NOT NULL,
    principal  TEXT NOT NULL,
    scopes     TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER
);

CREATE TABLE refresh_families (
    family_id         TEXT PRIMARY KEY,
    grant_id          TEXT NOT NULL,
    generation        INTEGER NOT NULL,
    current_token_hash TEXT NOT NULL,
    rotated_at        INTEGER NOT NULL,
    revoked_at        INTEGER
);

CREATE TABLE revocations (
    subject TEXT NOT NULL,
    kind    TEXT NOT NULL,
    at      INTEGER NOT NULL,
    PRIMARY KEY (subject, kind)
);

CREATE TABLE provider_connections (
    connection_id TEXT PRIMARY KEY,
    provider      TEXT NOT NULL,
    account_ref   TEXT NOT NULL,
    identity      TEXT NOT NULL,
    capabilities  TEXT NOT NULL,
    status        TEXT NOT NULL,
    generation    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
);
CREATE INDEX provider_connections_identity ON provider_connections(identity);

CREATE TABLE provider_refresh_state (
    connection_id         TEXT PRIMARY KEY,
    generation            INTEGER NOT NULL,
    secret_ref            TEXT NOT NULL,
    expires_at            INTEGER NOT NULL,
    needs_reauthorization INTEGER NOT NULL
);

CREATE TABLE refresh_claims (
    connection_id TEXT PRIMARY KEY,
    owner         TEXT NOT NULL,
    claimed_at    INTEGER NOT NULL
);

CREATE TABLE checkpoints (
    identity        TEXT NOT NULL,
    mailbox         TEXT NOT NULL,
    upstream_cursor TEXT NOT NULL,
    generation      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    PRIMARY KEY (identity, mailbox)
);

CREATE TABLE opaque_ids (
    identity    TEXT NOT NULL,
    kind        TEXT NOT NULL,
    public_id   TEXT NOT NULL,
    upstream_id TEXT NOT NULL,
    PRIMARY KEY (identity, kind, public_id)
);

CREATE TABLE leases (
    name          TEXT PRIMARY KEY,
    owner         TEXT NOT NULL,
    fencing_token INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL
);

CREATE TABLE submissions (
    id               TEXT PRIMARY KEY,
    principal        TEXT NOT NULL,
    identity         TEXT NOT NULL,
    client_id        TEXT NOT NULL,
    idempotency_key  TEXT,
    payload_digest   TEXT,
    state            TEXT NOT NULL,
    upstream_protocol TEXT,
    attempts         INTEGER NOT NULL,
    lease_owner      TEXT,
    lease_expires_at INTEGER,
    fencing_token    INTEGER NOT NULL,
    created_at       INTEGER NOT NULL,
    updated_at       INTEGER NOT NULL,
    failure_code     TEXT
);
CREATE INDEX submissions_identity ON submissions(identity);
CREATE INDEX submissions_state ON submissions(state);

CREATE TABLE idempotency (
    scope         TEXT PRIMARY KEY,
    key           TEXT NOT NULL,
    principal     TEXT NOT NULL,
    identity      TEXT NOT NULL,
    client_id     TEXT NOT NULL,
    payload_digest TEXT NOT NULL,
    submission_id TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL
);
CREATE INDEX idempotency_expiry ON idempotency(expires_at);

CREATE TABLE tasks (
    task_id       TEXT PRIMARY KEY,
    principal     TEXT NOT NULL,
    identity      TEXT NOT NULL,
    owner         TEXT,
    state         TEXT NOT NULL,
    progress      TEXT,
    result_ref    TEXT,
    fencing_token INTEGER NOT NULL,
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
);

CREATE TABLE audit_events (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    at      INTEGER NOT NULL,
    actor   TEXT NOT NULL,
    action  TEXT NOT NULL,
    subject TEXT NOT NULL,
    outcome TEXT NOT NULL
);
CREATE INDEX audit_events_at ON audit_events(at);
"#,
        },
        Migration {
            version: 2,
            name: "refresh-claim-generation",
            sql: r#"
-- The claim of a refresh is bound to the generation it was taken at, so a
-- worker that held an older claim cannot commit against a newer credential
-- and a stale claim does not block the owner of the current generation.
ALTER TABLE refresh_claims ADD COLUMN generation INTEGER NOT NULL DEFAULT 0;
"#,
        },
        Migration {
            version: 3,
            name: "revocation-state",
            sql: r#"
-- How far this database has caught up with the revocation ledger that
-- lives next to it. A restore is only allowed from a backup whose watermark
-- matches the ledger, so a backup that predates a revocation cannot install
-- a revoked grant.
CREATE TABLE revocation_state (
    id        INTEGER PRIMARY KEY CHECK (id = 1),
    watermark INTEGER NOT NULL
);
INSERT INTO revocation_state (id, watermark) VALUES (1, 0);
"#,
        },
        Migration {
            version: 4,
            name: "onboarding-transactions",
            sql: r#"
-- One encrypted onboarding transaction per state, consumed at most once.
-- The whole transaction (including its one-time marker) lives in one row,
-- so consumption is a single conditional UPDATE.
CREATE TABLE onboarding_transactions (
    state          TEXT PRIMARY KEY,
    envelope       BLOB NOT NULL,
    consumed       INTEGER NOT NULL DEFAULT 0
);
"#,
        },
        Migration {
            version: 5,
            name: "one-time-use-guards",
            sql: r#"
-- Durable one-time-use identifiers: guards over this table consume an
-- identifier with one conditional INSERT, so at most one caller is told
-- the identifier was fresh, and the record survives a restart.
CREATE TABLE one_time_use_guards (
    identifier     TEXT PRIMARY KEY,
    used_at        INTEGER NOT NULL
);
"#,
        },
        Migration {
            version: 6,
            name: "connection-deliveries",
            sql: r#"
-- The durable delivery record of one connection. At most one delivery
-- claim exists per connection, and a completed delivery is permanent, so
-- two deliveries of one connection cannot both write a secret.
CREATE TABLE connection_deliveries (
    connection_id  TEXT PRIMARY KEY,
    owner          TEXT NOT NULL,
    state          TEXT NOT NULL,
    updated_at     INTEGER NOT NULL
);
"#,
        },
    ]
}

/// Apply the migrations that are missing.
///
/// A database whose schema is newer than this build is refused: running an
/// old binary against a newer schema is how a migration is corrupted.
pub fn apply(connection: &mut Connection) -> StorageResult<u32> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version    INTEGER PRIMARY KEY,
            name       TEXT NOT NULL,
            applied_at INTEGER NOT NULL
        );",
    )?;
    let current: i64 = connection
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
            [],
            |row| row.get(0),
        )
        .map_err(|error| StorageError::Backend(error.to_string()))?;
    if current > i64::from(SCHEMA_VERSION) {
        return Err(StorageError::Unsupported(format!(
            "the database schema is version {current} but this build understands {SCHEMA_VERSION}"
        )));
    }
    for migration in migrations() {
        if i64::from(migration.version) <= current {
            continue;
        }
        let transaction = connection
            .transaction()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        transaction.execute_batch(migration.sql).map_err(|error| {
            StorageError::Backend(format!("the migration {} failed: {error}", migration.name))
        })?;
        transaction
            .execute(
                "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?1, ?2, ?3)",
                rusqlite::params![i64::from(migration.version), migration.name, 0_i64],
            )
            .map_err(|error| StorageError::Backend(error.to_string()))?;
        transaction
            .commit()
            .map_err(|error| StorageError::Backend(error.to_string()))?;
    }
    Ok(SCHEMA_VERSION)
}

/// The schema version of a database.
pub fn schema_version(connection: &Connection) -> StorageResult<u32> {
    let version: i64 = connection
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
            [],
            |row| row.get(0),
        )
        .map_err(|error| StorageError::Backend(error.to_string()))?;
    Ok(version as u32)
}
