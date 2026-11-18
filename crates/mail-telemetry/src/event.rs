//! The telemetry event model.
//!
//! The model is deliberately closed. An event carries a metric name from a
//! fixed allowlist, a numeric or bucketed value and at most one value per
//! allowlisted label key. There is no free-form string anywhere in the event:
//! no body, no credential, no token, no upstream endpoint and no recipient
//! address can be attached, because there is no field that could carry one.
//!
//! This is the structural half of ADR-0001 section 8.1 ("never capture tokens,
//! message bodies, authentication headers or mail contents in telemetry") and
//! ADR-0003 section 6 ("no sensitive message data ... or unbounded private
//! labels").

use serde::Serialize;

/// A metric family.
///
/// The set is fixed: a caller cannot invent a metric name, so the exported
/// metric families stay bounded and stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub enum MetricName {
    /// Gateway request volume.
    #[serde(rename = "corvi_gateway_requests_total")]
    GatewayRequests,
    /// Gateway request latency, bucketed.
    #[serde(rename = "corvi_gateway_request_duration")]
    GatewayRequestLatency,
    /// Requests denied by the authorization layer.
    #[serde(rename = "corvi_authorization_denials_total")]
    AuthorizationDenials,
    /// Upstream transport failures.
    #[serde(rename = "corvi_upstream_failures_total")]
    UpstreamFailures,
    /// Upstream transport latency, bucketed.
    #[serde(rename = "corvi_upstream_duration")]
    UpstreamLatency,
    /// Depth of the durable submission queue.
    #[serde(rename = "corvi_queue_depth")]
    QueueDepth,
    /// Telemetry collection failures.
    #[serde(rename = "corvi_telemetry_collection_failures_total")]
    TelemetryCollectionFailures,
}

impl MetricName {
    /// Every metric name in the allowlist.
    pub const ALL: [MetricName; 7] = [
        MetricName::GatewayRequests,
        MetricName::GatewayRequestLatency,
        MetricName::AuthorizationDenials,
        MetricName::UpstreamFailures,
        MetricName::UpstreamLatency,
        MetricName::QueueDepth,
        MetricName::TelemetryCollectionFailures,
    ];

    /// The exported wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            MetricName::GatewayRequests => "corvi_gateway_requests_total",
            MetricName::GatewayRequestLatency => "corvi_gateway_request_duration",
            MetricName::AuthorizationDenials => "corvi_authorization_denials_total",
            MetricName::UpstreamFailures => "corvi_upstream_failures_total",
            MetricName::UpstreamLatency => "corvi_upstream_duration",
            MetricName::QueueDepth => "corvi_queue_depth",
            MetricName::TelemetryCollectionFailures => "corvi_telemetry_collection_failures_total",
        }
    }

    /// Look a metric name up on the allowlist.
    ///
    /// Anything that is not on the list has no name, so an unknown or private
    /// metric cannot be recorded.
    pub fn parse(name: &str) -> Option<MetricName> {
        MetricName::ALL
            .into_iter()
            .find(|candidate| candidate.as_str() == name)
    }
}

/// Whether an operation succeeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The operation completed.
    Success,
    /// The operation failed.
    Failure,
    /// The operation was denied by policy.
    Denied,
    /// The operation ran out of time.
    Timeout,
}

impl Outcome {
    /// Every outcome value.
    pub const ALL: [Outcome; 4] = [
        Outcome::Success,
        Outcome::Failure,
        Outcome::Denied,
        Outcome::Timeout,
    ];

    /// The exported wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Success => "success",
            Outcome::Failure => "failure",
            Outcome::Denied => "denied",
            Outcome::Timeout => "timeout",
        }
    }
}

/// The protocol a request arrived on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    /// The REST API.
    Http,
    /// The MCP server.
    Mcp,
    /// SMTP submission.
    Smtp,
    /// Upstream IMAP.
    Imap,
    /// Upstream JMAP.
    Jmap,
    /// An internal RPC.
    Grpc,
    /// Not protocol specific.
    Internal,
}

impl Protocol {
    /// Every protocol value.
    pub const ALL: [Protocol; 7] = [
        Protocol::Http,
        Protocol::Mcp,
        Protocol::Smtp,
        Protocol::Imap,
        Protocol::Jmap,
        Protocol::Grpc,
        Protocol::Internal,
    ];

    /// The exported wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Http => "http",
            Protocol::Mcp => "mcp",
            Protocol::Smtp => "smtp",
            Protocol::Imap => "imap",
            Protocol::Jmap => "jmap",
            Protocol::Grpc => "grpc",
            Protocol::Internal => "internal",
        }
    }
}

/// Which way a message or request travelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// Towards the gateway.
    Inbound,
    /// Away from the gateway.
    Outbound,
    /// Inside the gateway.
    Internal,
}

impl Direction {
    /// Every direction value.
    pub const ALL: [Direction; 3] = [Direction::Inbound, Direction::Outbound, Direction::Internal];

    /// The exported wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::Inbound => "inbound",
            Direction::Outbound => "outbound",
            Direction::Internal => "internal",
        }
    }
}

/// Which part of the gateway produced an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Component {
    /// The gateway as a whole.
    Gateway,
    /// The REST and MCP APIs.
    Api,
    /// The SMTP listener.
    Smtp,
    /// The IMAP client.
    Imap,
    /// The JMAP client.
    Jmap,
    /// The policy engine.
    Policy,
    /// Operational storage.
    Storage,
    /// The telemetry subsystem.
    Telemetry,
}

impl Component {
    /// Every component value.
    pub const ALL: [Component; 8] = [
        Component::Gateway,
        Component::Api,
        Component::Smtp,
        Component::Imap,
        Component::Jmap,
        Component::Policy,
        Component::Storage,
        Component::Telemetry,
    ];

    /// The exported wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Component::Gateway => "gateway",
            Component::Api => "api",
            Component::Smtp => "smtp",
            Component::Imap => "imap",
            Component::Jmap => "jmap",
            Component::Policy => "policy",
            Component::Storage => "storage",
            Component::Telemetry => "telemetry",
        }
    }
}

/// A bounded class of failure.
///
/// An upstream error is classified into one of these before it is recorded.
/// The upstream text itself is never kept, because it may contain an address
/// or an endpoint (ADR-0001 section 8.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureClass {
    /// Authentication or authorization failed.
    Auth,
    /// The operation ran out of time.
    Timeout,
    /// The upstream provider failed.
    Upstream,
    /// A policy denied the operation.
    Policy,
    /// The configuration is invalid or missing.
    Config,
    /// The upstream rate limited the request.
    RateLimited,
    /// An internal error.
    Internal,
}

impl FailureClass {
    /// Every failure class.
    pub const ALL: [FailureClass; 7] = [
        FailureClass::Auth,
        FailureClass::Timeout,
        FailureClass::Upstream,
        FailureClass::Policy,
        FailureClass::Config,
        FailureClass::RateLimited,
        FailureClass::Internal,
    ];

    /// The exported wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            FailureClass::Auth => "auth",
            FailureClass::Timeout => "timeout",
            FailureClass::Upstream => "upstream",
            FailureClass::Policy => "policy",
            FailureClass::Config => "config",
            FailureClass::RateLimited => "rate_limited",
            FailureClass::Internal => "internal",
        }
    }

    /// Classify a free-form upstream message into a bounded class.
    ///
    /// The message is read and discarded: only the class is kept, so an
    /// address, a URL or a token inside the upstream text can never reach an
    /// exported event.
    pub fn from_upstream_message(message: &str) -> FailureClass {
        let lowered = message.to_lowercase();

        if lowered.contains("timeout") || lowered.contains("timed out") {
            FailureClass::Timeout
        } else if lowered.contains("rate limit")
            || lowered.contains("too many requests")
            || lowered.contains("throttl")
        {
            FailureClass::RateLimited
        } else if lowered.contains("auth")
            || lowered.contains("credential")
            || lowered.contains("password")
            || lowered.contains("login")
            || lowered.contains("unauthorized")
            || lowered.contains("forbidden")
        {
            FailureClass::Auth
        } else if lowered.contains("policy")
            || lowered.contains("denied")
            || lowered.contains("not allowed")
            || lowered.contains("blocked")
        {
            FailureClass::Policy
        } else if lowered.contains("config") || lowered.contains("invalid setting") {
            FailureClass::Config
        } else {
            FailureClass::Upstream
        }
    }
}

/// A latency bucket.
///
/// Exact timings are not published; a bounded bucket is. This keeps the
/// exported values inside a fixed set and avoids turning latency into a
/// side channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub enum DurationBucket {
    /// Under ten milliseconds.
    #[serde(rename = "under_10_ms")]
    Under10Ms,
    /// Under one hundred milliseconds.
    #[serde(rename = "under_100_ms")]
    Under100Ms,
    /// Under one second.
    #[serde(rename = "under_1_s")]
    Under1S,
    /// Under ten seconds.
    #[serde(rename = "under_10_s")]
    Under10S,
    /// Ten seconds or more.
    #[serde(rename = "over_10_s")]
    Over10S,
}

impl DurationBucket {
    /// Every duration bucket.
    pub const ALL: [DurationBucket; 5] = [
        DurationBucket::Under10Ms,
        DurationBucket::Under100Ms,
        DurationBucket::Under1S,
        DurationBucket::Under10S,
        DurationBucket::Over10S,
    ];

    /// The exported wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            DurationBucket::Under10Ms => "under_10_ms",
            DurationBucket::Under100Ms => "under_100_ms",
            DurationBucket::Under1S => "under_1_s",
            DurationBucket::Under10S => "under_10_s",
            DurationBucket::Over10S => "over_10_s",
        }
    }

    /// Bucket a duration in milliseconds.
    pub fn from_millis(millis: u64) -> DurationBucket {
        match millis {
            0..=9 => DurationBucket::Under10Ms,
            10..=99 => DurationBucket::Under100Ms,
            100..=999 => DurationBucket::Under1S,
            1_000..=9_999 => DurationBucket::Under10S,
            _ => DurationBucket::Over10S,
        }
    }
}

/// The value of an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventValue {
    /// A counter increment.
    Count(u64),
    /// A bucketed latency.
    Duration(DurationBucket),
    /// A point-in-time observation.
    Gauge(u64),
}

/// A label key.
///
/// The set is fixed and every key is low cardinality by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum LabelKey {
    /// Whether the operation succeeded.
    Outcome,
    /// Which protocol was used.
    Protocol,
    /// Which way the request travelled.
    Direction,
    /// Which part of the gateway was involved.
    Component,
    /// Which class of failure occurred.
    Failure,
}

impl LabelKey {
    /// Every label key in the allowlist.
    pub const ALL: [LabelKey; 5] = [
        LabelKey::Outcome,
        LabelKey::Protocol,
        LabelKey::Direction,
        LabelKey::Component,
        LabelKey::Failure,
    ];

    /// The exported wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            LabelKey::Outcome => "outcome",
            LabelKey::Protocol => "protocol",
            LabelKey::Direction => "direction",
            LabelKey::Component => "component",
            LabelKey::Failure => "failure",
        }
    }

    /// Look a label key up on the allowlist.
    ///
    /// A key that is not on the list has no key, so a private or
    /// high-cardinality label cannot be introduced by name.
    pub fn parse(key: &str) -> Option<LabelKey> {
        LabelKey::ALL
            .into_iter()
            .find(|candidate| candidate.as_str() == key)
    }
}

/// A label value.
///
/// The value type is bound to its key, so a value can never be filed under a
/// key it does not describe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelValue {
    /// A success or failure outcome.
    Outcome(Outcome),
    /// A protocol.
    Protocol(Protocol),
    /// A direction.
    Direction(Direction),
    /// A component.
    Component(Component),
    /// A failure class.
    Failure(FailureClass),
}

/// Why a label was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelError {
    /// The key is not on the allowlist.
    ///
    /// The refused key is deliberately not echoed back: it may itself be a
    /// private value that a caller tried to smuggle into a metric.
    DisallowedKey,
    /// The value does not belong to the key.
    MismatchedValue,
}

/// The labels of an event.
///
/// At most one value is kept per allowlisted key, so the number of labels is
/// bounded by the size of the allowlist.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct LabelSet {
    #[serde(skip_serializing_if = "Option::is_none")]
    outcome: Option<Outcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<Protocol>,
    #[serde(skip_serializing_if = "Option::is_none")]
    direction: Option<Direction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    component: Option<Component>,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure: Option<FailureClass>,
}

impl LabelSet {
    /// An empty label set.
    pub fn new() -> Self {
        LabelSet::default()
    }

    /// Record a label.
    ///
    /// A key that already carries a value is replaced, so the set never grows
    /// beyond the allowlist.
    pub fn insert(&mut self, key: LabelKey, value: LabelValue) -> Result<(), LabelError> {
        match (key, value) {
            (LabelKey::Outcome, LabelValue::Outcome(outcome)) => self.outcome = Some(outcome),
            (LabelKey::Protocol, LabelValue::Protocol(protocol)) => self.protocol = Some(protocol),
            (LabelKey::Direction, LabelValue::Direction(direction)) => {
                self.direction = Some(direction);
            }
            (LabelKey::Component, LabelValue::Component(component)) => {
                self.component = Some(component);
            }
            (LabelKey::Failure, LabelValue::Failure(failure)) => self.failure = Some(failure),
            _ => return Err(LabelError::MismatchedValue),
        }
        Ok(())
    }

    /// Record a label under a key named at runtime.
    ///
    /// The key is checked against the allowlist and refused if it is not on
    /// it. This is the entry point a caller uses when the key comes from
    /// configuration rather than from code.
    pub fn insert_key(&mut self, key: &str, value: LabelValue) -> Result<(), LabelError> {
        match LabelKey::parse(key) {
            Some(parsed) => self.insert(parsed, value),
            None => Err(LabelError::DisallowedKey),
        }
    }

    /// The value recorded for a key.
    pub fn get(&self, key: LabelKey) -> Option<LabelValue> {
        match key {
            LabelKey::Outcome => self.outcome.map(LabelValue::Outcome),
            LabelKey::Protocol => self.protocol.map(LabelValue::Protocol),
            LabelKey::Direction => self.direction.map(LabelValue::Direction),
            LabelKey::Component => self.component.map(LabelValue::Component),
            LabelKey::Failure => self.failure.map(LabelValue::Failure),
        }
    }

    /// How many labels are set.
    pub fn len(&self) -> usize {
        self.outcome.is_some() as usize
            + self.protocol.is_some() as usize
            + self.direction.is_some() as usize
            + self.component.is_some() as usize
            + self.failure.is_some() as usize
    }

    /// Whether no label is set.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A telemetry event.
///
/// Every field is closed: a metric name from the allowlist, a numeric or
/// bucketed value and a bounded label set. There is no field for a message,
/// a credential or an endpoint, so those cannot be attached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TelemetryEvent {
    name: MetricName,
    value: EventValue,
    labels: LabelSet,
}

impl TelemetryEvent {
    /// A new event.
    pub fn new(name: MetricName, value: EventValue) -> Self {
        TelemetryEvent {
            name,
            value,
            labels: LabelSet::new(),
        }
    }

    /// Record a label on this event.
    pub fn set_label(&mut self, key: LabelKey, value: LabelValue) -> Result<(), LabelError> {
        self.labels.insert(key, value)
    }

    /// Record a label under a key named at runtime.
    ///
    /// A key that is not on the allowlist is refused.
    pub fn set_label_key(&mut self, key: &str, value: LabelValue) -> Result<(), LabelError> {
        self.labels.insert_key(key, value)
    }

    /// The metric family.
    pub fn name(&self) -> MetricName {
        self.name
    }

    /// The value of the event.
    pub fn value(&self) -> &EventValue {
        &self.value
    }

    /// The labels of the event.
    pub fn labels(&self) -> &LabelSet {
        &self.labels
    }

    /// The value recorded for a label key.
    pub fn label(&self, key: LabelKey) -> Option<LabelValue> {
        self.labels.get(key)
    }
}
