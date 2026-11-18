//! Submitting mail over JMAP.
//!
//! ADR-0007 section 5 is precise about what a submission is:
//!
//! - `Email/set` may create a draft, but **`EmailSubmission/set` is the send
//!   operation**. A created draft alone is not a successful submission.
//! - The upstream sending identity is validated from the session, never from
//!   the caller's request: a caller may not name a JMAP `Identity`.
//! - An outcome that cannot be determined is reported as unknown. The client
//!   does not submit a second email, does not retry blindly, and does not
//!   switch to SMTP.
//!
//! The last point is why this adapter has no second path. A JMAP upstream
//! that fails is a failed JMAP upstream: falling back to another transport
//! would send the message under a different envelope, from a different
//! identity, without the checks that just failed.

use serde_json::{Value, json};

use mail_core::{MailSubmitter, OutgoingMessage, SubmissionReceipt, TransportError};

use crate::client::JmapClient;
use crate::error::JmapError;
use crate::protocol::{JmapRequest, MethodCall};
use crate::session::{CORE, MAIL, SUBMISSION};
use crate::transport::TransportLimits;

/// Submit one message through a JMAP account.
///
/// The `sender` is the address of the authorized Corvi identity. It must be
/// the envelope sender of the message, and the upstream account must offer a
/// sending identity with exactly that address.
pub fn submit_message(
    client: &mut JmapClient,
    account_id: &str,
    sender: &str,
    message: &OutgoingMessage,
) -> Result<SubmissionReceipt, JmapError> {
    if !message.sender.eq_ignore_ascii_case(sender) {
        return Err(JmapError::Rejected(
            "the envelope sender is not the authorized identity".to_owned(),
        ));
    }
    let identity_id = resolve_identity(client, account_id, sender)?;
    let recipients: Vec<Value> = message
        .recipients
        .iter()
        .map(|recipient| json!({"email": recipient}))
        .collect();
    let create = json!({
        "from": [{"email": message.sender}],
        "to": recipients,
        "subject": message.subject,
        "textBody": message.body,
    });
    let create_request = JmapRequest::new(vec![CORE.to_owned(), MAIL.to_owned()]).with(
        MethodCall::new(
            "Email/set",
            json!({"accountId": account_id, "create": {"draft": create}}),
        )
        .with_id("m0"),
    );
    let create_response = client.call(&create_request)?;
    let created = create_response.ok("m0")?;
    if let Some(reason) = creation_failure(created) {
        return Err(JmapError::Rejected(format!(
            "the upstream refused to create the message: {reason}"
        )));
    }
    let email_id = created
        .get("created")
        .and_then(|created| created.get("draft"))
        .and_then(|entry| entry.get("id"))
        .and_then(Value::as_str)
        .ok_or_else(|| JmapError::Protocol("the upstream created no message".to_owned()))?
        .to_owned();
    let envelope = json!({
        "mailFrom": {"email": message.sender},
        "rcptTo": message
            .recipients
            .iter()
            .map(|recipient| json!({"email": recipient}))
            .collect::<Vec<Value>>(),
    });
    let submit_request = JmapRequest::new(vec![
        CORE.to_owned(),
        MAIL.to_owned(),
        SUBMISSION.to_owned(),
    ])
    .with(
        MethodCall::new(
            "EmailSubmission/set",
            json!({
                "accountId": account_id,
                "create": {
                    "send": {
                        "emailId": email_id,
                        "identityId": identity_id,
                        "envelope": envelope,
                    }
                }
            }),
        )
        .with_id("m0"),
    );
    // The submission is the moment the message leaves. A transport failure
    // from here on is ambiguous, not a failure: the upstream may have
    // accepted the message and lost the answer.
    let response = match client.call(&submit_request) {
        Ok(response) => response,
        Err(JmapError::UpstreamUnavailable(reason)) => {
            return Err(JmapError::Ambiguous(reason));
        }
        Err(error) => return Err(error),
    };
    let result = response.ok("m0")?;
    if let Some(reason) = creation_failure(result) {
        return Err(JmapError::Rejected(format!(
            "the upstream refused the submission: {reason}"
        )));
    }
    let submission_id = result
        .get("created")
        .and_then(|created| created.get("send"))
        .and_then(|entry| entry.get("id"))
        .and_then(Value::as_str)
        .ok_or_else(|| JmapError::Protocol("the upstream created no submission".to_owned()))?
        .to_owned();
    Ok(SubmissionReceipt {
        id: submission_id,
        accepted: true,
        rejection: None,
    })
}

/// The upstream sending identity that may send as an address.
///
/// The identity is selected by its email address, so a caller cannot submit
/// as an identity the Corvi identity does not own.
fn resolve_identity(
    client: &mut JmapClient,
    account_id: &str,
    sender: &str,
) -> Result<String, JmapError> {
    let request = JmapRequest::new(vec![
        CORE.to_owned(),
        MAIL.to_owned(),
        SUBMISSION.to_owned(),
    ])
    .with(MethodCall::new("Identity/get", json!({"accountId": account_id})).with_id("m0"));
    let response = client.call(&request)?;
    let list = response
        .ok("m0")?
        .get("list")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for entry in list {
        let email = entry
            .get("email")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if email.eq_ignore_ascii_case(sender) {
            if let Some(id) = entry.get("id").and_then(Value::as_str) {
                return Ok(id.to_owned());
            }
        }
    }
    Err(JmapError::SubmissionUnavailable(format!(
        "the account has no sending identity for {sender}"
    )))
}

/// The reason a creation failed, if one did.
fn creation_failure(result: &Value) -> Option<String> {
    let not_created = result.get("notCreated")?.as_object()?;
    let entry = not_created.values().next()?;
    entry
        .get("type")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| Some("rejected".to_owned()))
}

/// A submitter that sends through one JMAP account.
#[derive(Debug)]
pub struct JmapSubmitter {
    client: JmapClient,
    account_id: String,
    sender: String,
    limits: TransportLimits,
}

impl JmapSubmitter {
    /// A submitter for one account and one envelope sender.
    ///
    /// The sender is the address of the Corvi identity, and the client
    /// checks that the upstream account has an identity with exactly that
    /// address before it sends anything.
    pub fn new(
        client: JmapClient,
        account_id: impl Into<String>,
        sender: impl Into<String>,
    ) -> Self {
        Self {
            client,
            account_id: account_id.into(),
            sender: sender.into(),
            limits: TransportLimits::default(),
        }
    }

    /// Apply transport limits.
    pub fn with_limits(mut self, limits: TransportLimits) -> Self {
        self.limits = limits;
        self
    }

    /// The client the submitter speaks through.
    pub fn client_mut(&mut self) -> &mut JmapClient {
        &mut self.client
    }

    /// The account the submitter sends through.
    pub fn account_id(&self) -> &str {
        &self.account_id
    }
}

impl MailSubmitter for JmapSubmitter {
    fn submit(&mut self, message: &OutgoingMessage) -> Result<SubmissionReceipt, TransportError> {
        submit_message(&mut self.client, &self.account_id, &self.sender, message)
            .map_err(TransportError::from)
    }
}
