//! The JMAP request and response shapes.
//!
//! ADR-0007 section 2 requires the client to handle "using capability lists,
//! method-call IDs/batching/back-references, account IDs, conditional
//! updates, `notFound`/method errors, RFC 8620 limits and concurrency",
//! while keeping "none of these internal protocol details" visible as a
//! public identity or message id. This module holds the wire shapes; they
//! never leave the transport.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::error::JmapError;

/// One method call within a request.
#[derive(Debug, Clone, PartialEq)]
pub struct MethodCall {
    /// The method name, for example `Email/get`.
    pub name: String,
    /// The method arguments.
    pub arguments: Value,
    /// The identifier of this call within the request.
    pub method_id: String,
    /// The identifier of a call this one refers to.
    pub back_reference: Option<String>,
}

impl MethodCall {
    /// A method call with the given arguments.
    pub fn new(name: impl Into<String>, arguments: Value) -> Self {
        Self {
            name: name.into(),
            arguments,
            method_id: "c0".to_owned(),
            back_reference: None,
        }
    }

    /// Set the identifier of this call.
    pub fn with_id(mut self, method_id: impl Into<String>) -> Self {
        self.method_id = method_id.into();
        self
    }

    /// Refer to another call in the same request.
    pub fn referring_to(mut self, method_id: impl Into<String>) -> Self {
        self.back_reference = Some(method_id.into());
        self
    }

    /// The wire form of the call.
    fn to_json(&self) -> Value {
        let mut array = vec![Value::String(self.name.clone()), self.arguments.clone()];
        if let Some(back_reference) = &self.back_reference {
            array.push(Value::String(format!("#{back_reference}")));
        }
        array.push(Value::String(self.method_id.clone()));
        Value::Array(array)
    }
}

/// A JMAP request.
#[derive(Debug, Clone, PartialEq)]
pub struct JmapRequest {
    /// The capabilities the request uses.
    pub using: Vec<String>,
    /// The method calls in the request.
    pub method_calls: Vec<MethodCall>,
}

impl JmapRequest {
    /// A request that uses the given capabilities.
    pub fn new(using: Vec<String>) -> Self {
        Self {
            using,
            method_calls: Vec::new(),
        }
    }

    /// Add a method call.
    pub fn with(mut self, call: MethodCall) -> Self {
        self.method_calls.push(call);
        self
    }

    /// The wire form of the request.
    pub fn to_json(&self) -> Value {
        let mut object = Map::new();
        object.insert(
            "using".to_owned(),
            Value::Array(
                self.using
                    .iter()
                    .map(|capability| Value::String(capability.clone()))
                    .collect(),
            ),
        );
        object.insert(
            "methodCalls".to_owned(),
            Value::Array(self.method_calls.iter().map(MethodCall::to_json).collect()),
        );
        Value::Object(object)
    }
}

/// What one method call answered.
#[derive(Debug, Clone, PartialEq)]
pub enum MethodOutcome {
    /// The call succeeded.
    Ok(Value),
    /// The requested object does not exist.
    NotFound,
    /// The call failed.
    Error {
        /// The error type the upstream reported.
        kind: String,
        /// The error description, if the upstream gave one.
        description: Option<String>,
    },
}

/// A JMAP response.
#[derive(Debug, Clone, PartialEq)]
pub struct JmapResponse {
    /// The outcome of every method call, in the order the upstream answered.
    pub outcomes: Vec<(String, MethodOutcome, String)>,
    /// The identifiers the upstream created, keyed by creation id.
    pub created_ids: BTreeMap<String, Value>,
    /// The session state the upstream reported.
    pub session_state: Option<String>,
}

impl JmapResponse {
    /// Parse a response body.
    pub fn parse(bytes: &[u8]) -> Result<Self, JmapError> {
        let value: Value = serde_json::from_slice(bytes)
            .map_err(|error| JmapError::Protocol(format!("the response is not JSON: {error}")))?;
        let object = value
            .as_object()
            .ok_or_else(|| JmapError::Protocol("the response is not an object".to_owned()))?;
        let responses = object
            .get("methodResponses")
            .and_then(Value::as_array)
            .ok_or_else(|| JmapError::Protocol("the response has no methodResponses".to_owned()))?;
        let mut outcomes = Vec::new();
        for response in responses {
            let array = response.as_array().ok_or_else(|| {
                JmapError::Protocol("a method response is not an array".to_owned())
            })?;
            if array.len() < 2 {
                return Err(JmapError::Protocol(
                    "a method response is too short".to_owned(),
                ));
            }
            let name = array[0]
                .as_str()
                .ok_or_else(|| JmapError::Protocol("a method name is not a string".to_owned()))?
                .to_owned();
            let method_id = array
                .get(2)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let outcome = if name == "error" {
                let arguments = array[1].as_object().ok_or_else(|| {
                    JmapError::Protocol("a method error is not an object".to_owned())
                })?;
                MethodOutcome::Error {
                    kind: arguments
                        .get("type")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown")
                        .to_owned(),
                    description: arguments
                        .get("description")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                }
            } else {
                MethodOutcome::Ok(array[1].clone())
            };
            outcomes.push((name, outcome, method_id));
        }
        let created_ids = object
            .get("createdIds")
            .and_then(Value::as_object)
            .map(|map| {
                map.iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect()
            })
            .unwrap_or_default();
        Ok(Self {
            outcomes,
            created_ids,
            session_state: object
                .get("sessionState")
                .and_then(Value::as_str)
                .map(str::to_owned),
        })
    }

    /// The outcome of one call.
    pub fn outcome(&self, method_id: &str) -> Option<&MethodOutcome> {
        self.outcomes
            .iter()
            .find(|(_, _, id)| id == method_id)
            .map(|(_, outcome, _)| outcome)
    }

    /// The result of one call, or an error describing what went wrong.
    pub fn ok(&self, method_id: &str) -> Result<&Value, JmapError> {
        match self.outcome(method_id) {
            Some(MethodOutcome::Ok(value)) => Ok(value),
            Some(MethodOutcome::NotFound) => Err(JmapError::NotFound),
            Some(MethodOutcome::Error { kind, description }) => Err(JmapError::Rejected(
                description.clone().unwrap_or_else(|| kind.clone()),
            )),
            None => Err(JmapError::Protocol(format!(
                "the response has no answer for the call {method_id}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_request_carries_its_capabilities_and_calls() {
        let request = JmapRequest::new(vec!["urn:ietf:params:jmap:core".to_owned()])
            .with(MethodCall::new("Email/get", json!({"accountId": "a"})));
        let value = request.to_json();
        assert_eq!(value["using"][0], "urn:ietf:params:jmap:core");
        assert_eq!(value["methodCalls"][0][0], "Email/get");
        assert_eq!(value["methodCalls"][0][2], "c0");
    }

    #[test]
    fn a_back_reference_is_rendered() {
        let request = JmapRequest::new(vec!["urn:ietf:params:jmap:core".to_owned()])
            .with(MethodCall::new("Email/get", json!({})).with_id("m0"))
            .with(
                MethodCall::new("Email/query", json!({}))
                    .with_id("m1")
                    .referring_to("m0"),
            );
        let value = request.to_json();
        assert_eq!(value["methodCalls"][1][2], "#m0");
        assert_eq!(value["methodCalls"][1][3], "m1");
    }

    #[test]
    fn a_response_is_parsed() {
        let response = JmapResponse::parse(
            br#"{"methodResponses":[["Email/get",{"list":[]},"m0"]],"createdIds":{"c0":{"id":"M1"}}}"#,
        )
        .expect("the response parses");
        assert_eq!(
            response.outcome("m0"),
            Some(&MethodOutcome::Ok(json!({"list": []})))
        );
        assert_eq!(response.created_ids["c0"]["id"], "M1");
    }

    #[test]
    fn a_method_error_is_parsed() {
        let response = JmapResponse::parse(
            br#"{"methodResponses":[["error",{"type":"unknownCapability"},"m0"]]}"#,
        )
        .expect("the response parses");
        assert!(matches!(
            response.outcome("m0"),
            Some(MethodOutcome::Error { kind, .. }) if kind == "unknownCapability"
        ));
        assert!(matches!(response.ok("m0"), Err(JmapError::Rejected(_))));
    }

    #[test]
    fn a_missing_answer_is_a_protocol_error() {
        let response =
            JmapResponse::parse(br#"{"methodResponses":[]}"#).expect("the response parses");
        assert!(matches!(response.ok("m0"), Err(JmapError::Protocol(_))));
    }
}
