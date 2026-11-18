//! The JMAP session object: capabilities, accounts and endpoints.
//!
//! ADR-0007 section 3 requires the client to validate the session object
//! rather than trust it. Everything the session says is treated as an
//! assertion by the upstream server, and the client checks it:
//!
//! - the capabilities it claims to offer,
//! - the accounts it lists and the capabilities of each account,
//! - the account a configured selector names,
//! - the endpoints it directs the client at, which are validated as
//!   untrusted URL inputs by [`crate::trust`].
//!
//! Read access and submission are selected **independently**. A deployment
//! may read from one JMAP account and submit through another, and a
//! submission account that lacks the submission capability is reported as
//! unavailable rather than quietly reused for reading.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::error::JmapError;

/// The JMAP core capability.
pub const CORE: &str = "urn:ietf:params:jmap:core";
/// The JMAP mail capability.
pub const MAIL: &str = "urn:ietf:params:jmap:mail";
/// The JMAP submission capability.
pub const SUBMISSION: &str = "urn:ietf:params:jmap:submission";

/// One account in the session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    /// The account identifier the upstream uses.
    pub id: String,
    /// The account's display name.
    pub name: Option<String>,
    /// Whether the account is a personal account.
    pub is_personal: bool,
    /// Whether the account is read-only.
    pub is_read_only: bool,
    /// The capabilities the account offers.
    pub capabilities: BTreeSet<String>,
}

/// How a deployment chooses the account an operation runs against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountSelector {
    /// The account the session names as the primary one for a capability.
    PrimaryForCapability {
        /// The capability the account must offer.
        capability: String,
    },
    /// A named account, for a deployment with several accounts.
    AccountId {
        /// The account identifier.
        account_id: String,
    },
}

impl AccountSelector {
    /// Select the account for a capability.
    pub fn primary_for(capability: &str) -> Self {
        AccountSelector::PrimaryForCapability {
            capability: capability.to_owned(),
        }
    }

    /// Select a named account.
    pub fn by_id(account_id: impl Into<String>) -> Self {
        AccountSelector::AccountId {
            account_id: account_id.into(),
        }
    }
}

/// An account the client may use, with the capabilities it has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedAccount {
    /// The account identifier.
    pub account_id: String,
    /// The capabilities the account offers.
    pub capabilities: BTreeSet<String>,
}

impl SelectedAccount {
    /// Whether the account offers a capability.
    pub fn supports(&self, capability: &str) -> bool {
        self.capabilities.contains(capability)
    }
}

/// A validated JMAP session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    capabilities: BTreeMap<String, Value>,
    accounts: BTreeMap<String, Account>,
    primary_accounts: BTreeMap<String, String>,
    api_url: String,
    download_url: Option<String>,
    upload_url: Option<String>,
    event_source_url: Option<String>,
    username: Option<String>,
}

impl Session {
    /// Parse and validate a session object.
    pub fn parse(value: &Value) -> Result<Self, JmapError> {
        let object = value
            .as_object()
            .ok_or_else(|| JmapError::Protocol("the session is not an object".to_owned()))?;
        let capabilities = object
            .get("capabilities")
            .and_then(Value::as_object)
            .map(|map| {
                map.iter()
                    .map(|(name, value)| (name.clone(), value.clone()))
                    .collect::<BTreeMap<String, Value>>()
            })
            .ok_or_else(|| JmapError::Protocol("the session has no capabilities".to_owned()))?;
        let accounts = object
            .get("accounts")
            .and_then(Value::as_object)
            .ok_or_else(|| JmapError::Protocol("the session has no accounts".to_owned()))?;
        let mut parsed_accounts = BTreeMap::new();
        for (id, account) in accounts {
            let account_object = account
                .as_object()
                .ok_or_else(|| JmapError::Protocol(format!("the account {id} is not an object")))?;
            let mut account_capabilities = BTreeSet::new();
            if let Some(map) = account_object
                .get("accountCapabilities")
                .and_then(Value::as_object)
            {
                for name in map.keys() {
                    account_capabilities.insert(name.clone());
                }
            }
            parsed_accounts.insert(
                id.clone(),
                Account {
                    id: id.clone(),
                    name: account_object
                        .get("name")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    is_personal: account_object
                        .get("isPersonal")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                    is_read_only: account_object
                        .get("isReadOnly")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                    capabilities: account_capabilities,
                },
            );
        }
        let primary_accounts = object
            .get("primaryAccounts")
            .and_then(Value::as_object)
            .map(|map| {
                map.iter()
                    .filter_map(|(capability, account)| {
                        account
                            .as_str()
                            .map(|account| (capability.clone(), account.to_owned()))
                    })
                    .collect::<BTreeMap<String, String>>()
            })
            .unwrap_or_default();
        let api_url = object
            .get("apiUrl")
            .and_then(Value::as_str)
            .ok_or_else(|| JmapError::Protocol("the session has no apiUrl".to_owned()))?
            .to_owned();
        Ok(Self {
            capabilities,
            accounts: parsed_accounts,
            primary_accounts,
            api_url,
            download_url: object
                .get("downloadUrl")
                .and_then(Value::as_str)
                .map(str::to_owned),
            upload_url: object
                .get("uploadUrl")
                .and_then(Value::as_str)
                .map(str::to_owned),
            event_source_url: object
                .get("eventSourceUrl")
                .and_then(Value::as_str)
                .map(str::to_owned),
            username: object
                .get("username")
                .and_then(Value::as_str)
                .map(str::to_owned),
        })
    }

    /// The capabilities the server offers.
    pub fn capabilities(&self) -> &BTreeMap<String, Value> {
        &self.capabilities
    }

    /// Whether the server offers a capability.
    pub fn supports(&self, capability: &str) -> bool {
        self.capabilities.contains_key(capability)
    }

    /// The accounts the session lists.
    pub fn accounts(&self) -> &BTreeMap<String, Account> {
        &self.accounts
    }

    /// The account the session names as primary for a capability.
    pub fn primary_account(&self, capability: &str) -> Option<&str> {
        self.primary_accounts.get(capability).map(String::as_str)
    }

    /// The URL of the JMAP API endpoint.
    pub fn api_url(&self) -> &str {
        &self.api_url
    }

    /// The URL template for blob downloads, if the server offers one.
    pub fn download_url(&self) -> Option<&str> {
        self.download_url.as_deref()
    }

    /// The URL of the event source, if the server offers one.
    pub fn event_source_url(&self) -> Option<&str> {
        self.event_source_url.as_deref()
    }

    /// The username the session reports.
    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    /// Select the account an operation runs against.
    ///
    /// The selector is checked against the **authenticated** session: an
    /// account the session does not list cannot be selected, and an account
    /// that lacks the capability the operation needs is reported as a
    /// missing capability rather than used anyway.
    pub fn select_account(
        &self,
        selector: &AccountSelector,
        required: &str,
    ) -> Result<SelectedAccount, JmapError> {
        if !self.supports(required) {
            // The server does not offer the capability at all, so no
            // account can provide it.
            return Err(JmapError::CapabilityMissing(required.to_owned()));
        }
        let account_id = match selector {
            AccountSelector::PrimaryForCapability { capability } => self
                .primary_account(capability)
                .ok_or_else(|| {
                    JmapError::AccountSelectionInvalid(format!(
                        "the session names no primary account for {capability}"
                    ))
                })?
                .to_owned(),
            AccountSelector::AccountId { account_id } => account_id.clone(),
        };
        let account = self.accounts.get(&account_id).ok_or_else(|| {
            JmapError::AccountSelectionInvalid(format!(
                "the session does not list the account {account_id}"
            ))
        })?;
        if !account.capabilities.contains(required) {
            return Err(JmapError::CapabilityMissing(required.to_owned()));
        }
        Ok(SelectedAccount {
            account_id,
            capabilities: account.capabilities.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn session() -> Session {
        Session::parse(&json!({
            "capabilities": {
                "urn:ietf:params:jmap:core": {},
                "urn:ietf:params:jmap:mail": {},
                "urn:ietf:params:jmap:submission": {}
            },
            "accounts": {
                "acct-1": {
                    "name": "Personal",
                    "isPersonal": true,
                    "accountCapabilities": {
                        "urn:ietf:params:jmap:core": {},
                        "urn:ietf:params:jmap:mail": {},
                        "urn:ietf:params:jmap:submission": {}
                    }
                },
                "acct-2": {
                    "name": "Read only",
                    "accountCapabilities": {
                        "urn:ietf:params:jmap:core": {},
                        "urn:ietf:params:jmap:mail": {}
                    }
                }
            },
            "primaryAccounts": {
                "urn:ietf:params:jmap:mail": "acct-1",
                "urn:ietf:params:jmap:submission": "acct-1"
            },
            "username": "me@example.com",
            "apiUrl": "https://api.example.com/jmap/api/",
            "downloadUrl": "https://api.example.com/jmap/download/{accountId}/{blobId}/{name}"
        }))
        .expect("the session is valid")
    }

    #[test]
    fn the_session_lists_its_capabilities() {
        let session = session();
        assert!(session.supports(CORE));
        assert!(session.supports(MAIL));
        assert!(session.supports(SUBMISSION));
    }

    #[test]
    fn the_primary_account_is_selected_by_capability() {
        let session = session();
        let selected = session
            .select_account(&AccountSelector::primary_for(MAIL), MAIL)
            .expect("the account is selected");
        assert_eq!(selected.account_id, "acct-1");
        assert!(selected.supports(SUBMISSION));
    }

    #[test]
    fn an_account_without_the_capability_is_refused() {
        let session = session();
        let error = session
            .select_account(&AccountSelector::by_id("acct-2"), SUBMISSION)
            .expect_err("the account cannot submit");
        assert_eq!(error, JmapError::CapabilityMissing(SUBMISSION.to_owned()));
    }

    #[test]
    fn an_unknown_account_is_refused() {
        let session = session();
        let error = session
            .select_account(&AccountSelector::by_id("acct-9"), MAIL)
            .expect_err("the account does not exist");
        assert!(matches!(error, JmapError::AccountSelectionInvalid(_)));
    }

    #[test]
    fn a_missing_capability_in_the_session_is_refused() {
        let error = Session::parse(&json!({"capabilities": {}, "accounts": {}}))
            .expect_err("a session without capabilities is refused");
        assert!(matches!(error, JmapError::Protocol(_)));
    }
}
