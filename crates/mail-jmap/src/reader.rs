//! Reading mail over JMAP.
//!
//! ADR-0007 section 4 is explicit about what a JMAP read may and may not
//! leak: upstream counts, snippets, thread membership and raw results stay
//! inside the transport, and every message is filtered before a caller sees
//! it. This module therefore returns **untrusted** messages in
//! `mail-core`'s shape and decides nothing about visibility.
//!
//! One rule is worth stating on its own: a JMAP read never establishes
//! trusted provenance. The `To` header of a message is written by the
//! sender, so it cannot justify `verified` isolation. The messages this
//! module produces therefore carry no provenance, and an identity in
//! `verified` mode fails closed — exactly as it does for any transport that
//! cannot distinguish provider-recorded delivery metadata from
//! message-authored headers.
//!
//! The operations are free functions over a client, so a deployment that
//! serves several identities from one upstream connection can share it. The
//! [`JmapReader`], [`JmapChangeTracker`] and [`BlobReader`] wrappers own a
//! client and implement `mail-core`'s transport traits.

use serde_json::{Value, json};

use mail_core::{
    Address, AttachmentMeta, BlobContent, BlobReader, BlobRequest, Change, ChangeCursor,
    ChangeKind, ChangeSet, ListQuery, MailChangeTracker, MailReader, MailboxRef, MessageId,
    MessagePage, TransportError, UntrustedMessage,
};

use crate::client::JmapClient;
use crate::error::JmapError;
use crate::protocol::{JmapRequest, MethodCall};
use crate::session::{CORE, MAIL};
use crate::transport::TransportLimits;

/// The properties the client asks for.
///
/// Only the properties the projection needs are requested, and the bodies
/// are fetched as values so the client never has to parse raw MIME.
fn properties() -> Vec<&'static str> {
    vec![
        "id",
        "mailboxIds",
        "from",
        "to",
        "cc",
        "replyTo",
        "subject",
        "receivedAt",
        "keywords",
        "threadId",
        "attachments",
    ]
}

/// Whether the upstream says the message is in the mailbox.
///
/// The upstream's answer is not trusted to have filtered the query. A
/// message the upstream places in another mailbox is not a message of the
/// requested mailbox, so it is not disclosed.
fn in_mailbox(email: &Value, mailbox_id: &str) -> bool {
    email
        .get("mailboxIds")
        .and_then(Value::as_object)
        .and_then(|ids| ids.get(mailbox_id))
        .and_then(Value::as_bool)
        == Some(true)
}

/// Read a page of messages from one mailbox.
pub fn list_messages(
    client: &mut JmapClient,
    account_id: &str,
    mailbox: &MailboxRef,
    query: &ListQuery,
    limits: &TransportLimits,
) -> Result<MessagePage, JmapError> {
    let limit = query.limit.min(limits.max_page_size).max(1);
    let position = match query.cursor.as_deref() {
        None => 0,
        Some(cursor) => cursor
            .parse::<usize>()
            .map_err(|_| JmapError::Protocol("the upstream position is not a number".to_owned()))?,
    };
    let Some(mailbox_id) = resolve_mailbox(client, account_id, mailbox)? else {
        return Ok(MessagePage {
            messages: Vec::new(),
            next_cursor: None,
        });
    };
    // The query asks for candidates only: no total count, no snippets and no
    // thread information, because none of those may leave the transport.
    let query_request = JmapRequest::new(vec![CORE.to_owned(), MAIL.to_owned()]).with(
        MethodCall::new(
            "Email/query",
            json!({
                "accountId": account_id,
                "filter": {"inMailbox": mailbox_id},
                "limit": limit,
                "position": position,
                "calculateTotal": false,
            }),
        )
        .with_id("m0"),
    );
    let query_response = client.call(&query_request)?;
    let ids: Vec<String> = query_response
        .ok("m0")?
        .get("ids")
        .and_then(Value::as_array)
        .map(|ids| {
            ids.iter()
                .filter_map(|id| id.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    if ids.is_empty() {
        return Ok(MessagePage {
            messages: Vec::new(),
            next_cursor: None,
        });
    }
    let get_request = JmapRequest::new(vec![CORE.to_owned(), MAIL.to_owned()]).with(
        MethodCall::new(
            "Email/get",
            json!({
                "accountId": account_id,
                "ids": ids,
                "properties": properties(),
                "bodyProperties": ["textBody", "htmlBody"],
                "fetchTextBodyValues": true,
                "fetchAllBodyValues": true,
            }),
        )
        .with_id("m1"),
    );
    let get_response = client.call(&get_request)?;
    let list: Vec<Value> = get_response
        .ok("m1")?
        .get("list")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let messages: Vec<UntrustedMessage> = list
        .iter()
        .filter(|email| in_mailbox(email, &mailbox_id))
        .map(|email| to_untrusted(email, mailbox))
        .collect();
    // The cursor counts the messages the upstream answered with, not the
    // messages that survived the containment check: a filtered message must
    // not end the page early.
    let next_cursor = if (list.len() as u32) < limit {
        None
    } else {
        Some((position + list.len()).to_string())
    };
    Ok(MessagePage {
        messages,
        next_cursor,
    })
}

/// Read one message.
pub fn get_message(
    client: &mut JmapClient,
    account_id: &str,
    mailbox: &MailboxRef,
    id: &MessageId,
) -> Result<UntrustedMessage, JmapError> {
    let mailbox_id = resolve_mailbox(client, account_id, mailbox)?.ok_or(JmapError::NotFound)?;
    let request = JmapRequest::new(vec![CORE.to_owned(), MAIL.to_owned()]).with(
        MethodCall::new(
            "Email/get",
            json!({
                "accountId": account_id,
                "ids": [id.as_str()],
                "properties": properties(),
                "bodyProperties": ["textBody", "htmlBody"],
                "fetchTextBodyValues": true,
                "fetchAllBodyValues": true,
            }),
        )
        .with_id("m0"),
    );
    let response = client.call(&request)?;
    let list = response
        .ok("m0")?
        .get("list")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    list.iter()
        .find(|email| {
            email.get("id").and_then(Value::as_str) == Some(id.as_str())
                && in_mailbox(email, &mailbox_id)
        })
        .map(|email| to_untrusted(email, mailbox))
        .ok_or(JmapError::NotFound)
}

#[cfg(test)]
mod download_template_tests {
    use super::*;

    #[test]
    fn template_components_are_encoded_and_unknown_placeholders_rejected() {
        let expanded = expand_download_template(
            "https://example.test/{accountId}/{blobId}/{name}",
            "a/b",
            "x?y",
        )
        .expect("known placeholders expand safely");
        assert!(expanded.contains("a%2Fb"));
        assert!(expanded.contains("x%3Fy"));
        assert!(
            expand_download_template("https://example.test/{accountId}/{blobId}/{evil}", "a", "b")
                .is_err()
        );
    }

    #[test]
    fn template_segments_are_percent_encoded_for_a_path() {
        let expanded = expand_download_template(
            "https://example.test/{accountId}/{blobId}/{name}",
            "account one",
            "..",
        )
        .expect("known placeholders expand safely");
        // A space is a space in a path, not a form field.
        assert!(
            expanded.contains("account%20one"),
            "the space is percent encoded: {expanded}"
        );
        assert!(
            !expanded.contains(' '),
            "no raw space reaches the URL: {expanded}"
        );
        // A dot segment would walk out of the blob path.
        assert!(
            expanded.contains("%2E%2E"),
            "a dot segment is encoded: {expanded}"
        );
        assert!(
            !expanded.contains("/.."),
            "the blob path cannot be walked: {expanded}"
        );
    }
}

fn expand_download_template(
    template: &str,
    account_id: &str,
    blob_id: &str,
) -> Result<String, JmapError> {
    if !template.contains("{accountId}")
        || !template.contains("{blobId}")
        || template.matches('{').count() != template.matches('}').count()
        || template
            .replace("{accountId}", "")
            .replace("{blobId}", "")
            .replace("{name}", "")
            .contains(['{', '}'])
    {
        return Err(JmapError::Protocol(
            "the download URL template is malformed".to_owned(),
        ));
    }
    let account = encode_path_segment(account_id);
    let blob = encode_path_segment(blob_id);
    Ok(template
        .replace("{accountId}", &account)
        .replace("{blobId}", &blob)
        .replace("{name}", "blob"))
}

/// Percent-encode one path segment.
///
/// The placeholders are path segments, not form fields: a space is `%20` and
/// not `+`, and a segment that is only dots is encoded so that it cannot be
/// read as a path traversal when the URL is normalized.
fn encode_path_segment(segment: &str) -> String {
    let mut encoded = String::with_capacity(segment.len());
    for byte in segment.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'~' => {
                encoded.push(*byte as char);
            }
            b'.' => encoded.push('.'),
            other => {
                encoded.push('%');
                encoded.push_str(&format!("{other:02X}"));
            }
        }
    }
    if segment == "." || segment == ".." {
        return encoded.replace('.', "%2E");
    }
    encoded
}

/// Download the bytes of one blob.
pub fn read_blob(
    client: &mut JmapClient,
    account_id: &str,
    request: &BlobRequest,
    limits: &TransportLimits,
) -> Result<BlobContent, JmapError> {
    let template = client
        .session()
        .and_then(|session| session.download_url().map(str::to_owned))
        .ok_or_else(|| JmapError::Protocol("the session offers no download URL".to_owned()))?;
    let url = expand_download_template(&template, account_id, &request.blob_id)?;
    let response = client.download(&url)?;
    if response.body.len() as u64 > limits.max_blob_bytes {
        return Err(JmapError::TooLarge {
            limit: limits.max_blob_bytes,
        });
    }
    let content_type = response.header("content-type").map(str::to_owned);
    Ok(BlobContent {
        bytes: response.body,
        content_type,
    })
}

/// Report the changes in one mailbox since a state token.
pub fn changes_since(
    client: &mut JmapClient,
    account_id: &str,
    mailbox: &MailboxRef,
    cursor: Option<&ChangeCursor>,
    limits: &TransportLimits,
) -> Result<ChangeSet, JmapError> {
    let Some(mailbox_id) = resolve_mailbox(client, account_id, mailbox)? else {
        return Ok(ChangeSet {
            changes: Vec::new(),
            next_cursor: None,
        });
    };
    let mut arguments = json!({
        "accountId": account_id,
        "filter": {"inMailbox": mailbox_id},
        "maxChanges": limits.max_page_size,
    });
    if let Some(cursor) = cursor {
        arguments["sinceState"] = Value::String(cursor.token.clone());
    }
    let request = JmapRequest::new(vec![CORE.to_owned(), MAIL.to_owned()])
        .with(MethodCall::new("Email/queryChanges", arguments).with_id("m0"));
    let response = client.call(&request)?;
    let value = response.ok("m0")?;
    if value
        .get("canCalculateChanges")
        .and_then(Value::as_bool)
        .is_some_and(|can| !can)
    {
        // The upstream cannot compute the difference, so the caller has to
        // resynchronize from scratch. Reporting a stale cursor would hide
        // the change instead.
        return Err(JmapError::SyncStateInvalid(
            "the upstream cannot calculate the changes".to_owned(),
        ));
    }
    let mut changes = Vec::new();
    for (key, kind) in [
        ("created", ChangeKind::Added),
        ("updated", ChangeKind::Modified),
        ("destroyed", ChangeKind::Removed),
    ] {
        if let Some(ids) = value.get(key).and_then(Value::as_array) {
            for id in ids.iter().filter_map(Value::as_str) {
                changes.push(Change {
                    id: MessageId::new(id),
                    kind,
                });
            }
        }
    }
    let next_cursor = value
        .get("newState")
        .and_then(Value::as_str)
        .map(|state| ChangeCursor {
            token: state.to_owned(),
        });
    Ok(ChangeSet {
        changes,
        next_cursor,
    })
}

/// Find the JMAP mailbox that corresponds to a Corvi mailbox reference.
///
/// The reference is a folder name, because a Corvi `Mailbox` is a binding to
/// a physical mailbox and not a JMAP folder. When the upstream has no folder
/// with that name, the reader reports no messages rather than reading a
/// different folder.
pub fn resolve_mailbox(
    client: &mut JmapClient,
    account_id: &str,
    mailbox: &MailboxRef,
) -> Result<Option<String>, JmapError> {
    let request = JmapRequest::new(vec![CORE.to_owned(), MAIL.to_owned()])
        .with(MethodCall::new("Mailbox/get", json!({"accountId": account_id})).with_id("m0"));
    let response = client.call(&request)?;
    let list = response
        .ok("m0")?
        .get("list")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let wanted = mailbox.as_str();
    for entry in list {
        let name = entry
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let role = entry
            .get("role")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let matches_name = name.eq_ignore_ascii_case(wanted);
        let matches_role = wanted.eq_ignore_ascii_case("inbox") && role == "inbox";
        if matches_name || matches_role {
            if let Some(id) = entry.get("id").and_then(Value::as_str) {
                return Ok(Some(id.to_owned()));
            }
        }
    }
    Ok(None)
}

/// A reader over one JMAP account.
#[derive(Debug)]
pub struct JmapReader {
    client: JmapClient,
    account_id: String,
    limits: TransportLimits,
}

impl JmapReader {
    /// A reader for one account.
    pub fn new(client: JmapClient, account_id: impl Into<String>) -> Self {
        Self {
            client,
            account_id: account_id.into(),
            limits: TransportLimits::default(),
        }
    }

    /// Apply transport limits.
    pub fn with_limits(mut self, limits: TransportLimits) -> Self {
        self.limits = limits;
        self
    }

    /// The client the reader speaks through.
    pub fn client(&self) -> &JmapClient {
        &self.client
    }

    /// The client the reader speaks through.
    pub fn client_mut(&mut self) -> &mut JmapClient {
        &mut self.client
    }

    /// The account the reader reads.
    pub fn account_id(&self) -> &str {
        &self.account_id
    }
}

impl MailReader for JmapReader {
    fn list(
        &mut self,
        mailbox: &MailboxRef,
        query: &ListQuery,
    ) -> Result<MessagePage, TransportError> {
        list_messages(
            &mut self.client,
            &self.account_id,
            mailbox,
            query,
            &self.limits,
        )
        .map_err(TransportError::from)
    }

    fn get(
        &mut self,
        mailbox: &MailboxRef,
        id: &MessageId,
    ) -> Result<UntrustedMessage, TransportError> {
        get_message(&mut self.client, &self.account_id, mailbox, id).map_err(TransportError::from)
    }
}

impl BlobReader for JmapReader {
    fn read_blob(&mut self, request: &BlobRequest) -> Result<BlobContent, TransportError> {
        read_blob(&mut self.client, &self.account_id, request, &self.limits)
            .map_err(TransportError::from)
    }
}

/// A tracker of changes in one JMAP mailbox.
#[derive(Debug)]
pub struct JmapChangeTracker {
    client: JmapClient,
    account_id: String,
    limits: TransportLimits,
}

impl JmapChangeTracker {
    /// A tracker for one account.
    pub fn new(client: JmapClient, account_id: impl Into<String>) -> Self {
        Self {
            client,
            account_id: account_id.into(),
            limits: TransportLimits::default(),
        }
    }

    /// Apply transport limits.
    pub fn with_limits(mut self, limits: TransportLimits) -> Self {
        self.limits = limits;
        self
    }

    /// The client the tracker speaks through.
    pub fn client_mut(&mut self) -> &mut JmapClient {
        &mut self.client
    }
}

impl MailChangeTracker for JmapChangeTracker {
    fn changes_since(
        &mut self,
        mailbox: &MailboxRef,
        cursor: Option<&ChangeCursor>,
    ) -> Result<ChangeSet, TransportError> {
        changes_since(
            &mut self.client,
            &self.account_id,
            mailbox,
            cursor,
            &self.limits,
        )
        .map_err(TransportError::from)
    }
}

/// Convert one JMAP email into the untrusted message the filters read.
fn to_untrusted(email: &Value, mailbox: &MailboxRef) -> UntrustedMessage {
    let id = email
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let body_values = email.get("bodyValues").and_then(Value::as_object);
    let text_body = body_values
        .and_then(|values| values.get("textBody"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let html_body = body_values
        .and_then(|values| values.get("htmlBody"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let attachments = email
        .get("attachments")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .map(|attachment| AttachmentMeta {
                    id: attachment
                        .get("blobId")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                    filename: attachment
                        .get("name")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    content_type: attachment
                        .get("type")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    size: attachment.get("size").and_then(Value::as_u64).unwrap_or(0),
                    inline: attachment
                        .get("isInline")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                })
                .collect()
        })
        .unwrap_or_default();
    UntrustedMessage {
        id: MessageId::new(id),
        mailbox: mailbox.clone(),
        from: first_address(email.get("from")),
        reply_to: addresses(email.get("replyTo")),
        to: addresses(email.get("to")),
        cc: addresses(email.get("cc")),
        subject: email
            .get("subject")
            .and_then(Value::as_str)
            .map(str::to_owned),
        text_body,
        html_body,
        attachments,
        // A JMAP read carries no trusted delivery evidence: the `to` header
        // is written by the sender. Leaving the provenance empty keeps a
        // `verified` identity fail-closed.
        provenance: mail_core::Provenance::default(),
        flags: email
            .get("keywords")
            .and_then(Value::as_array)
            .map(|list| {
                list.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
        date: email
            .get("receivedAt")
            .and_then(Value::as_str)
            .map(str::to_owned),
    }
}

/// The addresses of one JMAP address list.
fn addresses(value: Option<&Value>) -> Vec<Address> {
    value
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(|entry| {
                    let address = entry.get("email").and_then(Value::as_str)?;
                    Some(Address {
                        address: address.to_owned(),
                        display_name: entry.get("name").and_then(Value::as_str).map(str::to_owned),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The first address of a JMAP address list.
fn first_address(value: Option<&Value>) -> Option<Address> {
    addresses(value).into_iter().next()
}
