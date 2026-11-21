//! Gateway status objects the operator writes to the CRD's status subresource.
//!
//! The shape is fixed by `api/corvi-gateway.schema.json`'s `status` document:
//! the CRD is generated from it, so a field this module does not produce is
//! pruned by the API server and a condition reason longer than the schema
//! bound is refused.

use serde::Serialize;

/// A condition on a `CorviGateway`, in the CRD's vocabulary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Condition {
    /// One of the condition types the schema allows.
    #[serde(rename = "type")]
    pub kind: ConditionKind,
    /// `"True"`, `"False"` or `"Unknown"`.
    pub status: ConditionStatus,
    /// A bounded, schema-conforming reason.
    pub reason: String,
    /// A bounded human-readable message.
    pub message: String,
    /// The generation this condition was evaluated against.
    pub observed_generation: i64,
    /// RFC 3339 UTC timestamp of the last transition.
    pub last_transition_time: String,
}

/// The condition types the `CorviGateway` schema allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ConditionKind {
    /// The spec was accepted and the workload could be built.
    Accepted,
    /// The ownership graph resolved for this gateway.
    Resolved,
    /// The workload is observed ready.
    Ready,
    /// The workload is being reconciled.
    Progressing,
    /// The reconciliation could not proceed.
    Degraded,
}

impl ConditionKind {
    /// The wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "Accepted",
            Self::Resolved => "Resolved",
            Self::Ready => "Ready",
            Self::Progressing => "Progressing",
            Self::Degraded => "Degraded",
        }
    }
}

/// The three-valued condition status the schema allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ConditionStatus {
    /// The condition holds.
    True,
    /// The condition does not hold.
    False,
    /// The condition cannot be observed yet.
    Unknown,
}

impl ConditionStatus {
    /// The wire name the schema requires.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::True => "True",
            Self::False => "False",
            Self::Unknown => "Unknown",
        }
    }
}

/// The status document the operator writes to a `CorviGateway`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GatewayStatus {
    /// The gateway generation this status reflects.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
    /// The observed replica count of the workload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replicas: Option<i64>,
    /// The replica count the gateway spec asks for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desired_replicas: Option<i64>,
    /// The observed ready replica count.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ready_replicas: Option<i64>,
    /// The workload kind the operator manages for this gateway.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workload_kind: Option<String>,
    /// The Service the operator manages for this gateway.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_name: Option<String>,
    /// The bounded condition set.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
}

impl GatewayStatus {
    /// Set the observed generation.
    #[must_use]
    pub fn with_generation(mut self, generation: i64) -> Self {
        self.observed_generation = Some(generation);
        self
    }

    /// Record the desired replica count.
    #[must_use]
    pub fn with_desired_replicas(mut self, replicas: i64) -> Self {
        self.desired_replicas = Some(replicas);
        self
    }

    /// Record observed replica counts read from the workload.
    #[must_use]
    pub fn with_observed_replicas(mut self, replicas: Option<i64>, ready: Option<i64>) -> Self {
        self.replicas = replicas;
        self.ready_replicas = ready;
        self
    }

    /// Record the workload kind.
    #[must_use]
    pub fn with_workload_kind(mut self, kind: impl Into<String>) -> Self {
        self.workload_kind = Some(kind.into());
        self
    }

    /// Record the managed Service name.
    #[must_use]
    pub fn with_service(mut self, name: impl Into<String>) -> Self {
        self.service_name = Some(name.into());
        self
    }

    /// Append a condition.
    #[must_use]
    pub fn with_condition(mut self, condition: Condition) -> Self {
        self.conditions.push(condition);
        self
    }
}

/// Build a condition stamped at `now_unix`.
#[must_use]
pub fn condition(
    kind: ConditionKind,
    holds: ConditionStatus,
    reason: &str,
    message: &str,
    generation: i64,
    now_unix: i64,
) -> Condition {
    Condition {
        kind,
        status: holds,
        reason: reason.to_owned(),
        message: message.to_owned(),
        observed_generation: generation,
        last_transition_time: rfc3339(now_unix),
    }
}

/// Render a Unix timestamp as an RFC 3339 UTC timestamp.
///
/// The workspace depends on nothing, so the civil-from-days conversion is
/// written here rather than pulled in from a date crate.
#[must_use]
pub fn rfc3339(unix_seconds: i64) -> String {
    let days = unix_seconds.div_euclid(86_400);
    let seconds_of_day = unix_seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3600;
    let minute = (seconds_of_day % 3600) / 60;
    let second = seconds_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Convert a count of days since 1970-01-01 to a civil UTC date.
///
/// Howard Hinnant's `civil_from_days` algorithm; valid for the full range
/// Kubernetes timestamps can name.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_timestamps_render_as_utc() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_000_000_000), "2001-09-09T01:46:40Z");
        assert_eq!(rfc3339(1_763_000_000), "2025-11-13T02:13:20Z");
        // Leap year: 2024-02-29T12:00:00Z is 1709208000.
        assert_eq!(rfc3339(1_709_208_000), "2024-02-29T12:00:00Z");
    }
}
