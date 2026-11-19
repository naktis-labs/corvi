//! The Corvi Kubernetes operator: it watches `CorviGateway` resources and
//! reconciles them into the hardened workloads [`mail_operator`] renders.
//!
//! # Division of responsibility
//!
//! [`mail_operator`] owns every decision that can be made without a cluster:
//! the ownership and reparenting rules of ADR-0012/ADR-0013, the hardened
//! workload profile of ADR-0011 and the workload rendering itself. This crate
//! is the thin layer that connects those decisions to a real API server: it
//! reads resources, hands them to the decision logic, applies the result with
//! server-side apply, and writes the status the CRD schema allows.
//!
//! # What the reconciler refuses
//!
//! * A workload that exists and is owned by someone else (for example a Helm
//!   release) is never adopted or modified (ADR-0011 section 8.14).
//! * A spec that fails `mail-operator`'s validation is never applied; an
//!   existing operator-owned workload is left untouched and the failure is
//!   reported on the gateway's status.
//! * A suspended gateway never runs mail: its workload is scaled to zero.
//!
//! The reconciler never creates or mutates ServiceAccounts, never cascades
//! into upstream mail objects, Secrets, PVCs or CRDs, and never carries more
//! RBAC than `deploy/operator/policy/corvi-operator.rbac.yaml` grants.

pub mod kube;
pub mod status;

use mail_operator::model::CorviGateway;
use mail_operator::model::ParseError;
use mail_operator::workload::Workload;
use status::{ConditionKind, ConditionStatus, GatewayStatus, condition};

/// A bounded API-server failure.
///
/// The message is produced by this crate, never copied from a provider or a
/// user-controlled field, and it names no resource content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiFailure(pub String);

impl std::fmt::Display for ApiFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ApiFailure {}

/// The API surface a reconciler needs from the cluster.
///
/// Implemented against `kube` in [`self::kube`] and against an in-memory
/// fake in the tests, so the reconciliation rules are testable without a
/// cluster.
pub trait ClusterApi {
    /// Read a `CorviGateway` as its JSON manifest.
    fn get_gateway(
        &self,
        namespace: &str,
        name: &str,
    ) -> impl std::future::Future<Output = Result<Option<serde_json::Value>, ApiFailure>> + Send;

    /// Read the gateway workload of `kind` ("Deployment" or "StatefulSet").
    fn get_workload(
        &self,
        namespace: &str,
        kind: &str,
        name: &str,
    ) -> impl std::future::Future<Output = Result<Option<serde_json::Value>, ApiFailure>> + Send;

    /// Server-side apply a workload manifest.
    fn apply_workload(
        &self,
        namespace: &str,
        kind: &str,
        manifest: serde_json::Value,
        field_manager: &str,
    ) -> impl std::future::Future<Output = Result<(), ApiFailure>> + Send;

    /// Server-side apply a Service manifest.
    fn apply_service(
        &self,
        namespace: &str,
        manifest: serde_json::Value,
        field_manager: &str,
    ) -> impl std::future::Future<Output = Result<(), ApiFailure>> + Send;

    /// Merge-patch the gateway's status subresource.
    fn patch_status(
        &self,
        namespace: &str,
        name: &str,
        patch: serde_json::Value,
    ) -> impl std::future::Future<Output = Result<(), ApiFailure>> + Send;
}

/// What one pass of reconciliation decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileOutcome {
    /// The workload and Service were applied.
    Applied {
        /// The workload kind that was applied.
        workload_kind: String,
        /// The workload name that was applied.
        workload_name: String,
        /// The Service that was applied, when a listener is published.
        service: Option<String>,
        /// The status that was written.
        status: GatewayStatus,
    },
    /// The gateway is suspended: no mail-serving replicas.
    Suspended {
        /// The status that was written.
        status: GatewayStatus,
    },
    /// The reconciler refused to act; nothing was changed.
    Refused {
        /// Why it refused.
        reason: Refusal,
        /// The status that was written.
        status: GatewayStatus,
    },
    /// The gateway does not exist (it was deleted between watch and read).
    Gone,
}

/// Why a reconciliation refused to change anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The live object is not a valid Corvi resource.
    InvalidSpec {
        /// The bounded parse failure.
        detail: String,
    },
    /// The workload exists and is owned by someone else.
    OwnershipConflict {
        /// The workload that is already owned.
        workload: String,
    },
    /// The hardened profile refused to render or validate the workload.
    RenderRefused {
        /// The bounded refusal.
        detail: String,
    },
}

/// An unrecoverable reconciliation failure (the API surface failed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileError {
    /// The API call failed; the reconciliation is retried.
    Api(ApiFailure),
}

impl std::fmt::Display for ReconcileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Api(failure) => write!(f, "API call failed: {failure}"),
        }
    }
}

impl std::error::Error for ReconcileError {}

/// The field manager every server-side apply carries.
pub const FIELD_MANAGER: &str = "corvi-operator";

/// The label the operator sets on everything it manages.
pub const MANAGED_BY_LABEL: &str = "app.kubernetes.io/managed-by";

/// The operator's value for [`MANAGED_BY_LABEL`].
pub const MANAGED_BY_VALUE: &str = "corvi-operator";

/// Reconcile one gateway to its workload.
///
/// `now_unix` stamps condition transition times; the caller supplies the
/// clock so the rules are testable without one.
pub async fn reconcile_gateway<A: ClusterApi>(
    api: &A,
    namespace: &str,
    name: &str,
    profile: &mail_operator::workload::OperatorProfile,
    now_unix: i64,
) -> Result<ReconcileOutcome, ReconcileError> {
    let Some(raw) = api
        .get_gateway(namespace, name)
        .await
        .map_err(ReconcileError::Api)?
    else {
        return Ok(ReconcileOutcome::Gone);
    };

    // The live object goes through the same parser as a submitted manifest, so
    // every refusal in mail-operator's model applies here too.
    let gateway: CorviGateway = match parse_gateway(&raw) {
        Ok(gateway) => gateway,
        Err(error) => {
            let detail = bounded(error.to_string());
            let generation = generation_of(&raw);
            let status = GatewayStatus::default()
                .with_generation(generation)
                .with_condition(condition(
                    ConditionKind::Accepted,
                    ConditionStatus::False,
                    "SpecInvalid",
                    &format!("the live object is not a valid CorviGateway: {detail}"),
                    generation,
                    now_unix,
                ))
                .with_condition(condition(
                    ConditionKind::Resolved,
                    ConditionStatus::False,
                    "InvalidReference",
                    "the resource could not be parsed; nothing was changed",
                    generation,
                    now_unix,
                ));
            let patch = serde_json::to_value(&status).map_err(|_| {
                ReconcileError::Api(ApiFailure("status could not be encoded".into()))
            })?;
            api.patch_status(namespace, name, serde_json::json!({ "status": patch }))
                .await
                .map_err(ReconcileError::Api)?;
            return Ok(ReconcileOutcome::Refused {
                reason: Refusal::InvalidSpec { detail },
                status,
            });
        }
    };

    let generation = gateway.metadata.generation.unwrap_or(0);
    let suspended = gateway.spec.suspended;
    let desired = if suspended { 0 } else { gateway.spec.replicas };

    // Render the workload for the *effective* spec: a suspended gateway is
    // reconciled to zero replicas rather than to a stale workload.
    let mut effective = gateway.clone();
    if suspended {
        effective.spec.replicas = 0;
    }
    let rendered = {
        match mail_operator::workload::render_gateway_workload(&effective, profile) {
            Ok(workload) => match mail_operator::workload::validate_workload(&workload, profile) {
                Ok(()) => Ok(workload),
                Err(error) => Err(bounded(error.to_string())),
            },
            Err(error) => Err(bounded(error.to_string())),
        }
    };
    let rendered = match rendered {
        Ok(workload) => workload,
        Err(detail) => {
            let status = GatewayStatus::default()
                .with_generation(generation)
                .with_desired_replicas(i64::from(gateway.spec.replicas))
                .with_condition(condition(
                    ConditionKind::Accepted,
                    ConditionStatus::False,
                    "SpecInvalid",
                    &format!("the hardened profile refused this spec: {detail}"),
                    generation,
                    now_unix,
                ))
                .with_condition(condition(
                    ConditionKind::Resolved,
                    ConditionStatus::False,
                    "RenderRefused",
                    "no workload was changed; the retained configuration stays in service",
                    generation,
                    now_unix,
                ));
            return write_refusal(
                api,
                namespace,
                name,
                Refusal::RenderRefused { detail },
                status,
            )
            .await;
        }
    };

    let workload_kind = rendered.kind().to_owned();
    let workload_name = rendered.name().to_owned();

    // The adoption guard: a workload that exists and is owned by someone else
    // is never modified (ADR-0011 section 8.14).
    let existing = api
        .get_workload(namespace, rendered.kind(), rendered.name())
        .await
        .map_err(ReconcileError::Api)?;
    if let Some(live) = &existing {
        if ownership_of(live) == WorkloadOwner::Other {
            let status = GatewayStatus::default()
                .with_generation(generation)
                .with_condition(condition(
                    ConditionKind::Degraded,
                    ConditionStatus::True,
                    "OwnershipConflict",
                    &format!(
                        "{workload_kind}/{workload_name} exists and is not owned by the operator"
                    ),
                    generation,
                    now_unix,
                ))
                .with_condition(condition(
                    ConditionKind::Resolved,
                    ConditionStatus::False,
                    "OwnershipConflict",
                    "a Helm-owned workload is never adopted (ADR-0011 section 8.14)",
                    generation,
                    now_unix,
                ));
            return write_refusal(
                api,
                namespace,
                name,
                Refusal::OwnershipConflict {
                    workload: format!("{workload_kind}/{workload_name}"),
                },
                status,
            )
            .await;
        }
    }

    let manifest = workload_manifest(&rendered)
        .map_err(|_| ReconcileError::Api(ApiFailure("workload could not be encoded".into())))?;
    api.apply_workload(namespace, rendered.kind(), manifest, FIELD_MANAGER)
        .await
        .map_err(ReconcileError::Api)?;

    let service_name = format!("corvi-gateway-{name}");
    let service = service_manifest(&rendered, &gateway, profile, &service_name);
    let mut applied_service = None;
    if let Some(service) = service {
        let manifest = serde_json::to_value(&service)
            .map_err(|_| ReconcileError::Api(ApiFailure("service could not be encoded".into())))?;
        api.apply_service(namespace, manifest, FIELD_MANAGER)
            .await
            .map_err(ReconcileError::Api)?;
        applied_service = Some(service_name.clone());
    }

    let observed = observed_replicas(existing.as_ref());
    let mut status = GatewayStatus::default()
        .with_generation(generation)
        .with_desired_replicas(i64::from(desired))
        .with_observed_replicas(observed.replicas, observed.ready)
        .with_workload_kind(workload_kind.clone())
        .with_condition(condition(
            ConditionKind::Accepted,
            ConditionStatus::True,
            "SpecValidated",
            "the spec passed the hardened workload profile",
            generation,
            now_unix,
        ));
    if let Some(service) = &applied_service {
        status = status.with_service(service.clone());
    }

    let outcome = if suspended {
        status = status.with_condition(condition(
            ConditionKind::Resolved,
            ConditionStatus::True,
            "Suspended",
            "the gateway is suspended; the workload is scaled to zero",
            generation,
            now_unix,
        ));
        ReconcileOutcome::Suspended {
            status: status.clone(),
        }
    } else {
        let (ready_status, ready_reason) = readiness(&observed, i64::from(desired));
        status = status.with_condition(condition(
            ConditionKind::Resolved,
            ConditionStatus::True,
            "WorkloadApplied",
            &format!("{workload_kind}/{workload_name} applied"),
            generation,
            now_unix,
        ));
        status = status.with_condition(condition(
            ConditionKind::Ready,
            ready_status,
            ready_reason,
            "readiness is observed from the workload, never assumed",
            generation,
            now_unix,
        ));
        ReconcileOutcome::Applied {
            workload_kind,
            workload_name,
            service: applied_service,
            status: status.clone(),
        }
    };

    let patch = serde_json::to_value(&status)
        .map_err(|_| ReconcileError::Api(ApiFailure("status could not be encoded".into())))?;
    api.patch_status(namespace, name, serde_json::json!({ "status": patch }))
        .await
        .map_err(ReconcileError::Api)?;
    Ok(outcome)
}

async fn write_refusal<A: ClusterApi>(
    api: &A,
    namespace: &str,
    name: &str,
    reason: Refusal,
    status: GatewayStatus,
) -> Result<ReconcileOutcome, ReconcileError> {
    let patch = serde_json::to_value(&status)
        .map_err(|_| ReconcileError::Api(ApiFailure("status could not be encoded".into())))?;
    api.patch_status(namespace, name, serde_json::json!({ "status": patch }))
        .await
        .map_err(ReconcileError::Api)?;
    Ok(ReconcileOutcome::Refused { reason, status })
}

/// Whose workload the live object is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkloadOwner {
    /// This operator manages it.
    Operator,
    /// Someone else does; never touched.
    Other,
}

/// Decide ownership from the live object. The rule fails closed: an explicit
/// `managed-by` label that is not this operator's makes the object foreign
/// even if it carries the gateway as controller owner — a stolen label with a
/// kept owner reference is exactly what a hostile or buggy adoption looks
/// like. An object with no `managed-by` label is the operator's only when the
/// gateway is its controller owner. An unlabeled object created by `kubectl`
/// is therefore never adopted: ADR-0011 section 8.14 gives the operator one
/// owner, and silently taking over a foreign Deployment is the opposite of
/// that.
fn ownership_of(live: &serde_json::Value) -> WorkloadOwner {
    let metadata = &live["metadata"];
    let managed_by = metadata["labels"][MANAGED_BY_LABEL].as_str();
    if let Some(managed_by) = managed_by {
        return if managed_by == MANAGED_BY_VALUE {
            WorkloadOwner::Operator
        } else {
            WorkloadOwner::Other
        };
    }
    if let Some(references) = metadata["ownerReferences"].as_array() {
        for reference in references {
            let controller = reference["controller"].as_bool().unwrap_or(false);
            if controller && reference["kind"].as_str() == Some("CorviGateway") {
                return WorkloadOwner::Operator;
            }
        }
    }
    WorkloadOwner::Other
}

/// The replica counts the live workload reports, if any.
struct ObservedReplicas {
    replicas: Option<i64>,
    ready: Option<i64>,
}

impl ObservedReplicas {
    const NONE: Self = Self {
        replicas: None,
        ready: None,
    };
}

fn observed_replicas(live: Option<&serde_json::Value>) -> ObservedReplicas {
    let Some(status) = live.map(|object| &object["status"]) else {
        return ObservedReplicas::NONE;
    };
    ObservedReplicas {
        replicas: status["replicas"].as_i64(),
        ready: status["readyReplicas"].as_i64(),
    }
}

/// Readiness is observed, never assumed: without workload status the
/// condition is `Unknown`.
fn readiness(observed: &ObservedReplicas, desired: i64) -> (ConditionStatus, &'static str) {
    match observed.ready {
        Some(ready) if ready >= desired && desired > 0 => {
            (ConditionStatus::True, "AtDesiredReplicas")
        }
        Some(_) => (ConditionStatus::False, "ReplicasNotReady"),
        None => (ConditionStatus::Unknown, "AwaitingWorkloadStatus"),
    }
}

/// Encode a rendered workload as its Kubernetes manifest.
fn workload_manifest(workload: &Workload) -> Result<serde_json::Value, serde_json::Error> {
    match workload {
        Workload::Deployment(deployment) => serde_json::to_value(deployment),
        Workload::StatefulSet(stateful_set) => serde_json::to_value(stateful_set),
    }
}

/// Build the Service the gateway's listeners ask for.
///
/// The rendered workload names no Service, because the workload profile and
/// the entry points are different concerns; the Service is the operator's own
/// bounded object: ClusterIP, the workload's selector, only the enabled
/// listeners, and no external exposure (that belongs to a Gateway API or a
/// proxy, not to the operator).
fn service_manifest(
    workload: &Workload,
    gateway: &CorviGateway,
    profile: &mail_operator::workload::OperatorProfile,
    name: &str,
) -> Option<serde_json::Value> {
    let mut ports = Vec::new();
    if gateway.spec.listeners.http.enabled {
        ports.push(serde_json::json!({
            "name": "http",
            "port": profile.http_port,
            "targetPort": profile.http_port,
            "protocol": "TCP",
        }));
    }
    if gateway.spec.listeners.smtp_submission.enabled {
        ports.push(serde_json::json!({
            "name": "smtp-submission",
            "port": profile.smtp_submission_port,
            "targetPort": profile.smtp_submission_port,
            "protocol": "TCP",
        }));
    }
    if ports.is_empty() {
        return None;
    }
    let selector = match workload {
        Workload::Deployment(deployment) => &deployment.spec.selector.match_labels,
        Workload::StatefulSet(stateful_set) => &stateful_set.spec.selector.match_labels,
    };
    Some(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": name,
            "namespace": gateway.metadata.namespace,
            "labels": *selector,
            "ownerReferences": owner_references(gateway),
        },
        "spec": {
            "type": "ClusterIP",
            "selector": selector,
            "ports": ports,
        },
    }))
}

/// The owner references the operator sets, keyed to the live object's UID.
fn owner_references(gateway: &CorviGateway) -> serde_json::Value {
    let Some(uid) = &gateway.metadata.uid else {
        // Without a UID the API server cannot key garbage collection; the
        // caller parsed a live object, so this cannot happen on the real
        // path, and an object without an owner reference is safer than a
        // fabricated one.
        return serde_json::json!([]);
    };
    serde_json::json!([{
        "apiVersion": mail_operator::model::API_GROUP_VERSION,
        "kind": mail_operator::model::ResourceKind::CorviGateway.as_str(),
        "name": gateway.metadata.name,
        "uid": uid,
        "controller": true,
        "blockOwnerDeletion": true,
    }])
}

/// Parse a live gateway object through the CRD-derived model.
fn parse_gateway(raw: &serde_json::Value) -> Result<CorviGateway, ParseError> {
    let yaml = serde_yaml::to_string(raw).map_err(|error| ParseError::Yaml(error.to_string()))?;
    mail_operator::parse_gateway(&yaml)
}

/// The generation of a live object, before it has been parsed.
fn generation_of(raw: &serde_json::Value) -> i64 {
    raw["metadata"]["generation"].as_i64().unwrap_or(0)
}

/// Bound a message so a refusal cannot carry unbounded text into status.
pub(crate) fn bounded(message: String) -> String {
    const MAX: usize = 1024;
    if message.len() <= MAX {
        return message;
    }
    let mut cut = MAX;
    while !message.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}...", &message[..cut])
}
