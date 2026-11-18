//! The storage configuration, and the rules that decide what a deployment
//! may ask for.
//!
//! [`api/storage.schema.json`](../../../api/storage.schema.json) is the
//! contract: it says which backends exist, which feature flags require
//! which backend, and which combinations are impossible. This module reads
//! the same document and enforces the same rules, so a configuration that
//! passes here is one the schema would accept.
//!
//! Two rules are worth stating on their own, because they are the ones a
//! deployment usually gets wrong:
//!
//! 1. **A durable feature needs a durable backend.** An integrated OAuth
//!    issuer, a durable submission queue, durable tasks or persistent
//!    mailbox synchronization cannot run on ephemeral state, because their
//!    whole promise is that the answer survives a restart. Asking for one
//!    on ephemeral state is refused rather than silently degraded.
//! 2. **No PostgreSQL backend is implemented.** ADR-0010 assigns HA
//!    deployments — transactional leases, refresh rotation and queue
//!    ownership across replicas — to PostgreSQL. This build has no such
//!    backend, so a configuration that asks for `postgres`, or for
//!    `multiReplica`, is refused rather than run on SQLite or in memory.
//!    The [`PostgresConfig`] type exists only to read the shape of the
//!    schema's document; it never stands for a working backend.
//!
//! The `persistInboundMail` flag is accepted only with the value `false`.
//! Inbound raw mail is not persisted by default, and the baseline schema
//! has no way to opt in, because an opt-in needs its own encryption,
//! consent and retention contract.

use serde::{Deserialize, Serialize};

use crate::error::{StorageError, StorageResult};

/// The API version the configuration declares.
pub const API_VERSION: &str = "corvi.naktis.eu/v1alpha1";

/// The kind the configuration declares.
pub const KIND: &str = "CorviStorage";

/// The storage configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StorageConfig {
    /// The API version.
    pub api_version: String,
    /// The kind.
    pub kind: String,
    /// The management storage, which is separate from the data plane's.
    #[serde(default)]
    pub control_plane: Option<ControlPlaneConfig>,
    /// The transactional state of the data plane and the OAuth issuer.
    pub state: StateConfig,
    /// Where secrets are kept.
    pub secrets: SecretStoreConfig,
    /// Where large objects are kept.
    pub blobs: BlobStoreConfig,
    /// Which durable features are enabled.
    pub features: Features,
}

/// The management storage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ControlPlaneConfig {
    /// Which management backend is used.
    pub backend: ControlPlaneBackend,
    /// The Kubernetes management settings.
    #[serde(default)]
    pub kubernetes: Option<ControlPlaneKubernetes>,
    /// The standalone file settings.
    #[serde(default)]
    pub standalone_file: Option<ControlPlaneFile>,
}

/// The management backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ControlPlaneBackend {
    /// Kubernetes CRDs and Secrets.
    Kubernetes,
    /// A local YAML file.
    StandaloneFile,
    /// No management state.
    Disabled,
}

/// The Kubernetes management settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ControlPlaneKubernetes {
    /// The namespace that holds the Corvi resources.
    pub namespace: String,
    /// The lease the operator leader election uses.
    #[serde(default)]
    pub leader_election_lease_name: Option<String>,
}

/// The standalone management file settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ControlPlaneFile {
    /// The path of the file.
    pub path: String,
}

/// The transactional state configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StateConfig {
    /// Which backend holds the state.
    pub backend: StateBackend,
    /// The SQLite settings.
    #[serde(default)]
    pub sqlite: Option<SqliteConfig>,
    /// The PostgreSQL settings.
    #[serde(default)]
    pub postgres: Option<PostgresConfig>,
}

/// The transactional state backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum StateBackend {
    /// In memory, without durability.
    Ephemeral,
    /// A local SQLite file.
    Sqlite,
    /// An external PostgreSQL server. **Not implemented in this build**: a
    /// configuration that asks for it is refused.
    Postgres,
}

/// The SQLite settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SqliteConfig {
    /// The path of the database file.
    pub path: String,
    /// Whether write-ahead logging is on.
    #[serde(default)]
    pub wal: Option<bool>,
    /// How long a writer waits for the lock.
    #[serde(default)]
    pub busy_timeout_ms: Option<u64>,
}

/// The PostgreSQL settings.
///
/// This type only reads the shape of the schema's `postgres` document so
/// that a configuration can be parsed and reported. **No PostgreSQL backend
/// exists in this build**: a configuration that uses it is refused, and
/// nothing in this type stands for a working connection, lease or rotation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PostgresConfig {
    /// A secret reference to the connection string, never the string itself.
    pub dsn_ref: String,
    /// The TLS mode; only full verification is allowed.
    pub tls_mode: String,
    /// The size of the connection pool.
    #[serde(default)]
    pub pool_size: Option<u32>,
    /// The schema the tables live in.
    #[serde(default)]
    pub schema: Option<String>,
}

/// Where secrets are kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretStoreConfig {
    /// Which secret backend is used.
    pub backend: SecretBackend,
    /// The encrypted-file settings.
    #[serde(default)]
    pub encrypted_file: Option<EncryptedFileConfig>,
    /// The external secret store settings.
    #[serde(default)]
    pub external: Option<ExternalSecretConfig>,
    /// The Kubernetes Secret settings.
    #[serde(default)]
    pub kubernetes_secret: Option<KubernetesSecretConfig>,
}

/// The secret backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SecretBackend {
    /// A local file encrypted with a separately held key.
    EncryptedFile,
    /// An external secret service.
    External,
    /// Kubernetes Secrets.
    KubernetesSecret,
}

/// The encrypted-file secret store settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EncryptedFileConfig {
    /// The path of the encrypted file.
    pub path: String,
    /// A secret reference to the wrapping key.
    pub wrapping_key_ref: String,
}

/// The external secret store settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExternalSecretConfig {
    /// The driver that talks to the service.
    pub driver: String,
    /// A secret reference to the endpoint.
    pub endpoint_ref: String,
    /// A secret reference to the credentials.
    #[serde(default)]
    pub credentials_ref: Option<String>,
}

/// The Kubernetes Secret settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KubernetesSecretConfig {
    /// The namespace that holds the Secrets.
    pub namespace: String,
    /// Where the Secrets are mounted.
    pub mount_path: String,
}

/// Where large objects are kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BlobStoreConfig {
    /// Which blob backend is used.
    pub backend: BlobBackend,
    /// The encrypted-directory settings.
    #[serde(default)]
    pub encrypted_directory: Option<EncryptedDirectoryConfig>,
    /// The S3 settings.
    #[serde(default)]
    pub s3: Option<S3Config>,
}

/// The blob backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum BlobBackend {
    /// No blob store.
    Disabled,
    /// A local encrypted directory.
    EncryptedDirectory,
    /// An S3-compatible object store.
    S3,
}

/// The encrypted-directory blob store settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EncryptedDirectoryConfig {
    /// The path of the directory.
    pub path: String,
    /// A secret reference to the wrapping key.
    pub wrapping_key_ref: String,
}

/// The S3 blob store settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct S3Config {
    /// The endpoint, which must be HTTPS.
    pub endpoint: String,
    /// The bucket.
    pub bucket: String,
    /// A secret reference to the credentials.
    pub credentials_ref: String,
    /// A secret reference to the encryption key.
    pub encryption_key_ref: String,
    /// The key prefix.
    #[serde(default)]
    pub prefix: Option<String>,
}

/// Which durable features are enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Features {
    /// The integrated Corvi OAuth issuer is enabled.
    pub integrated_o_auth_issuer: bool,
    /// Durable submission is enabled.
    pub durable_submission: bool,
    /// Durable tasks are enabled.
    pub durable_tasks: bool,
    /// Persistent mailbox synchronization is enabled.
    pub persistent_mailbox_sync: bool,
    /// Inbound raw mail is persisted.
    pub persist_inbound_mail: bool,
    /// Several active replicas serve the data plane.
    pub multi_replica: bool,
    /// A search index is enabled.
    #[serde(default)]
    pub search_index: bool,
}

impl StorageConfig {
    /// Read a configuration from YAML.
    pub fn from_yaml(document: &str) -> StorageResult<Self> {
        let config: Self = serde_yaml::from_str(document).map_err(|error| {
            StorageError::Invalid(format!("the configuration is not valid: {error}"))
        })?;
        config.validate()?;
        Ok(config)
    }

    /// Read a configuration from JSON.
    pub fn from_json(document: &str) -> StorageResult<Self> {
        let config: Self = serde_json::from_str(document).map_err(|error| {
            StorageError::Invalid(format!("the configuration is not valid: {error}"))
        })?;
        config.validate()?;
        Ok(config)
    }

    /// Whether a feature needs a durable backend.
    fn needs_durable_state(&self) -> bool {
        self.features.integrated_o_auth_issuer
            || self.features.durable_submission
            || self.features.durable_tasks
            || self.features.persistent_mailbox_sync
    }

    /// Check the configuration against the rules of the schema.
    pub fn validate(&self) -> StorageResult<()> {
        if self.api_version != API_VERSION {
            return Err(StorageError::Invalid(format!(
                "the API version is {} but this build understands {API_VERSION}",
                self.api_version
            )));
        }
        if self.kind != KIND {
            return Err(StorageError::Invalid(format!(
                "the kind is {} but this build understands {KIND}",
                self.kind
            )));
        }
        if self.features.persist_inbound_mail {
            return Err(StorageError::Invalid(
                "inbound raw mail is not persisted: the baseline has no opt-in, because one \
                 needs its own encryption, consent and retention contract"
                    .to_owned(),
            ));
        }
        if self.features.multi_replica {
            return Err(StorageError::Unsupported(
                "several active replicas need the PostgreSQL backend for transactional leases, \
                 refresh rotation and queue ownership, and this build has no PostgreSQL backend; \
                 SQLite is a single-writer database on a local filesystem and ephemeral state is \
                 in memory"
                    .to_owned(),
            ));
        }
        match self.state.backend {
            StateBackend::Ephemeral => {
                if self.state.sqlite.is_some() || self.state.postgres.is_some() {
                    return Err(StorageError::Invalid(
                        "the ephemeral backend takes no sqlite or postgres settings".to_owned(),
                    ));
                }
                if self.needs_durable_state() {
                    return Err(StorageError::Invalid(
                        "a durable feature cannot run on ephemeral state: enable the sqlite or \
                         postgres backend"
                            .to_owned(),
                    ));
                }
            }
            StateBackend::Sqlite => {
                if self.state.sqlite.is_none() {
                    return Err(StorageError::Invalid(
                        "the sqlite backend requires the sqlite settings".to_owned(),
                    ));
                }
                if self.state.postgres.is_some() {
                    return Err(StorageError::Invalid(
                        "the sqlite backend takes no postgres settings".to_owned(),
                    ));
                }
            }
            StateBackend::Postgres => {
                return Err(StorageError::Unsupported(
                    "the PostgreSQL backend is not implemented in this build: a configuration \
                     that asks for it is refused instead of running its state on SQLite or in \
                     memory, and no transactional lease, refresh rotation or queue ownership \
                     exists for several replicas"
                        .to_owned(),
                ));
            }
        }
        match self.secrets.backend {
            SecretBackend::EncryptedFile => {
                if self.secrets.encrypted_file.is_none() {
                    return Err(StorageError::Invalid(
                        "the encryptedFile backend requires the encryptedFile settings".to_owned(),
                    ));
                }
                if self.secrets.external.is_some() || self.secrets.kubernetes_secret.is_some() {
                    return Err(StorageError::Invalid(
                        "the encryptedFile backend takes no external or kubernetesSecret settings"
                            .to_owned(),
                    ));
                }
            }
            SecretBackend::External => {
                if self.secrets.external.is_none() {
                    return Err(StorageError::Invalid(
                        "the external backend requires the external settings".to_owned(),
                    ));
                }
                if self.secrets.encrypted_file.is_some() || self.secrets.kubernetes_secret.is_some()
                {
                    return Err(StorageError::Invalid(
                        "the external backend takes no encryptedFile or kubernetesSecret settings"
                            .to_owned(),
                    ));
                }
            }
            SecretBackend::KubernetesSecret => {
                if self.secrets.kubernetes_secret.is_none() {
                    return Err(StorageError::Invalid(
                        "the kubernetesSecret backend requires the kubernetesSecret settings"
                            .to_owned(),
                    ));
                }
                if self.secrets.encrypted_file.is_some() || self.secrets.external.is_some() {
                    return Err(StorageError::Invalid(
                        "the kubernetesSecret backend takes no encryptedFile or external settings"
                            .to_owned(),
                    ));
                }
            }
        }
        match self.blobs.backend {
            BlobBackend::Disabled => {
                if self.blobs.encrypted_directory.is_some() || self.blobs.s3.is_some() {
                    return Err(StorageError::Invalid(
                        "the disabled blob backend takes no other settings".to_owned(),
                    ));
                }
            }
            BlobBackend::EncryptedDirectory => {
                if self.blobs.encrypted_directory.is_none() {
                    return Err(StorageError::Invalid(
                        "the encryptedDirectory backend requires the encryptedDirectory settings"
                            .to_owned(),
                    ));
                }
                if self.blobs.s3.is_some() {
                    return Err(StorageError::Invalid(
                        "the encryptedDirectory backend takes no s3 settings".to_owned(),
                    ));
                }
            }
            BlobBackend::S3 => {
                if self.blobs.s3.is_none() {
                    return Err(StorageError::Invalid(
                        "the s3 backend requires the s3 settings".to_owned(),
                    ));
                }
                if self.blobs.encrypted_directory.is_some() {
                    return Err(StorageError::Invalid(
                        "the s3 backend takes no encryptedDirectory settings".to_owned(),
                    ));
                }
                if let Some(s3) = &self.blobs.s3
                    && !s3.endpoint.starts_with("https://")
                {
                    return Err(StorageError::Invalid(
                        "the s3 endpoint must be https".to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A configuration that is valid.
    fn config() -> StorageConfig {
        StorageConfig {
            api_version: API_VERSION.to_owned(),
            kind: KIND.to_owned(),
            control_plane: Some(ControlPlaneConfig {
                backend: ControlPlaneBackend::StandaloneFile,
                kubernetes: None,
                standalone_file: Some(ControlPlaneFile {
                    path: "/etc/corvi/providers.yaml".to_owned(),
                }),
            }),
            state: StateConfig {
                backend: StateBackend::Sqlite,
                sqlite: Some(SqliteConfig {
                    path: "/var/lib/corvi/state.sqlite".to_owned(),
                    wal: Some(true),
                    busy_timeout_ms: Some(5_000),
                }),
                postgres: None,
            },
            secrets: SecretStoreConfig {
                backend: SecretBackend::EncryptedFile,
                encrypted_file: Some(EncryptedFileConfig {
                    path: "/var/lib/corvi/secrets.enc".to_owned(),
                    wrapping_key_ref: "secret://local/corvi-storage-key".to_owned(),
                }),
                external: None,
                kubernetes_secret: None,
            },
            blobs: BlobStoreConfig {
                backend: BlobBackend::Disabled,
                encrypted_directory: None,
                s3: None,
            },
            features: Features {
                integrated_o_auth_issuer: false,
                durable_submission: true,
                durable_tasks: false,
                persistent_mailbox_sync: false,
                persist_inbound_mail: false,
                multi_replica: false,
                search_index: false,
            },
        }
    }

    #[test]
    fn a_valid_configuration_is_accepted() {
        assert!(config().validate().is_ok());
    }

    #[test]
    fn a_durable_feature_on_ephemeral_state_is_refused() {
        let mut config = config();
        config.state = StateConfig {
            backend: StateBackend::Ephemeral,
            sqlite: None,
            postgres: None,
        };
        let error = config.validate().expect_err("durable state is required");
        assert!(matches!(error, StorageError::Invalid(_)));
    }

    #[test]
    fn a_postgres_configuration_is_refused() {
        let mut config = config();
        config.state = StateConfig {
            backend: StateBackend::Postgres,
            sqlite: None,
            postgres: Some(PostgresConfig {
                dsn_ref: "secret://local/corvi-postgres-dsn".to_owned(),
                tls_mode: "verify-full".to_owned(),
                pool_size: Some(8),
                schema: Some("corvi".to_owned()),
            }),
        };
        let error = config
            .validate()
            .expect_err("the PostgreSQL backend is not implemented");
        assert!(
            matches!(error, StorageError::Unsupported(_)),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn several_replicas_are_refused_in_every_backend() {
        for backend in [
            StateBackend::Ephemeral,
            StateBackend::Sqlite,
            StateBackend::Postgres,
        ] {
            let mut config = config();
            config.state.backend = backend;
            config.state.postgres = None;
            config.state.sqlite = if backend == StateBackend::Sqlite {
                Some(SqliteConfig {
                    path: "/var/lib/corvi/state.sqlite".to_owned(),
                    wal: Some(true),
                    busy_timeout_ms: Some(5_000),
                })
            } else {
                None
            };
            if backend == StateBackend::Postgres {
                config.state.postgres = Some(PostgresConfig {
                    dsn_ref: "secret://local/corvi-postgres-dsn".to_owned(),
                    tls_mode: "verify-full".to_owned(),
                    pool_size: Some(8),
                    schema: Some("corvi".to_owned()),
                });
            }
            config.features.multi_replica = true;
            let error = config
                .validate()
                .expect_err("several active replicas are not supported");
            assert!(
                matches!(error, StorageError::Unsupported(_)),
                "unexpected error for {backend:?}: {error:?}"
            );
        }
    }

    #[test]
    fn persisting_inbound_mail_is_refused() {
        let mut config = config();
        config.features.persist_inbound_mail = true;
        assert!(config.validate().is_err());
    }

    #[test]
    fn the_document_of_the_schema_is_accepted() {
        let document = "\
apiVersion: corvi.naktis.eu/v1alpha1
kind: CorviStorage
state:
  backend: sqlite
  sqlite:
    path: /var/lib/corvi/state.sqlite
secrets:
  backend: encryptedFile
  encryptedFile:
    path: /var/lib/corvi/secrets.enc
    wrappingKeyRef: secret://local/corvi-storage-key
blobs:
  backend: disabled
features:
  integratedOAuthIssuer: false
  durableSubmission: true
  durableTasks: false
  persistentMailboxSync: false
  persistInboundMail: false
  multiReplica: false
";
        let config = StorageConfig::from_yaml(document).expect("the document is valid");
        assert_eq!(config.state.backend, StateBackend::Sqlite);
        assert_eq!(config.secrets.backend, SecretBackend::EncryptedFile);
    }
}
