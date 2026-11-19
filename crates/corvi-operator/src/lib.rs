//! The Corvi Kubernetes operator: it reconciles `CorviGateway` resources
//! into the hardened workloads [`mail_operator`] renders.
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
//! * A workload or Service that exists and is owned by someone else (for
//!   example a Helm release) is never adopted or modified (ADR-0011 section
//!   8.14). An explicit `managed-by` label that is not this operator's makes
//!   an object foreign even when the gateway is its controller owner, and an
//!   object with no `managed-by` label at all is foreign too: the trust
//!   anchor is the namespace's RBAC, not a forgeable label.
//! * A spec that fails `mail-operator`'s validation is never applied; an
//!   existing operator-owned workload is left untouched and the failure is
//!   reported on the gateway's status.
//! * Server-side apply runs without `.force()`: an apply conflict is an
//!   error, never a silent field steal (ADR-0012 section 3). The same rule
//!   covers the operator's own objects: if a foreign actor edits a field the
//!   operator applies, the apply conflicts and the drift is reported as
//!   `Degraded/ApplyFailed` on the gateway's status instead of being forced
//!   back — repairing it is a deliberate human decision, not an automatic
//!   takeover.
//! * A suspended gateway never runs mail — including on refusal paths, where
//!   the operator-owned workload is scaled to zero before the refusal is
//!   reported (ADR-0013 section 3).
//!
//! # What this reconciler deliberately does not do yet
//!
//! The rendered workload mounts a configuration snapshot from a ConfigMap
//! (ADR-0012 section 3). Building that snapshot from the resolved ownership
//! graph is the remaining piece of the phase, so every applied outcome also
//! carries a `Degraded` condition with reason `SnapshotNotPublished`: the
//! workload objects exist and are correct, but no pod of theirs can start
//! until the snapshot pipeline lands. This is reported rather than hidden.

pub mod kube;
pub mod status;

use mail_operator::model::CorviGateway;
use mail_operator::model::ParseError;
use mail_operator::workload::Workload;
use status::{ConditionKind, ConditionStatus, GatewayStatus, condition};

/// A bounded API-server failure.
///
/// The message is produced by this crate and bounded in length; it may quote
/// Kubernetes API validation text, so it must never be treated as free of
/// resource content.
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
/// Implemented against `kube` in [`kube`] and against an in-memory fake in
/// the tests, so the reconciliation rules are testable without a cluster.
/// Adapters are namespaced at construction: every `namespace` argument names
/// the adapter's own scope, and an adapter must never act outside it.
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

    /// Read the gateway's managed Service.
    ///
    /// Adapters are scoped at construction: the kube adapter is namespaced
    /// when it is built and every call lands inside that namespace, so the
    /// argument names the same namespace to the fake and to the real client.
    fn get_service(
        &self,
        namespace: &str,
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

    /// Delete a workload this operator owns.
    fn delete_workload(
        &self,
        namespace: &str,
        kind: &str,
        name: &str,
    ) -> impl std::future::Future<Output = Result<(), ApiFailure>> + Send;

    /// Scale a workload to zero replicas.
    ///
    /// This is deliberately *not* server-side apply: the operator's field
    /// manager owns the whole applied workload, and an apply that omits
    /// `spec.template` and `spec.selector` would delete them (SSA removes
    /// fields its manager previously owned), invalidating the object. A
    /// JSON merge patch changes the one field that "suspended" means and
    /// leaves the rest of the workload exactly as it was applied.
    fn scale_workload(
        &self,
        namespace: &str,
        kind: &str,
        name: &str,
    ) -> impl std::future::Future<Output = Result<(), ApiFailure>> + Send;

    /// Delete a Service this operator owns.
    fn delete_service(
        &self,
        namespace: &str,
        name: &str,
    ) -> impl std::future::Future<Output = Result<(), ApiFailure>> + Send;

    /// Apply the gateway's status subresource with server-side apply, so
    /// fields this operator previously owned and no longer reports are
    /// removed instead of lingering.
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
    /// The reconciler refused to reconcile the spec. The spec was not
    /// reconciled, but the pass may still have scaled down a suspended
    /// gateway's operator-owned workload before refusing, and a Service
    /// ownership refusal follows a workload apply.
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
    /// A workload or Service exists and is owned by someone else.
    OwnershipConflict {
        /// The object that is already owned.
        object: String,
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

/// The condition reason that names the not-yet-implemented snapshot pipeline.
pub const SNAPSHOT_PENDING_REASON: &str = "SnapshotNotPublished";

/// Reconcile one gateway to its workload.
///
/// `now_unix` stamps condition transition times; the caller supplies the
/// clock so the rules are testable without one. A condition whose content is
/// unchanged keeps its previous `lastTransitionTime`.
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

    // Suspension is honoured before anything else, straight from the raw
    // object: even a spec that can no longer be parsed must not keep mail
    // flowing (ADR-0013 section 3).
    let raw_suspended = raw["spec"]["suspended"].as_bool().unwrap_or(false);

    // The live object goes through the same parser as a submitted manifest, so
    // every refusal in mail-operator's model applies here too.
    let gateway: CorviGateway = match parse_gateway(&raw) {
        Ok(gateway) => gateway,
        Err(error) => {
            let detail = bounded(error.to_string());
            let generation = generation_of(&raw);
            let mut status = GatewayStatus::default()
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
            if raw_suspended {
                let scaled =
                    scale_operator_owned_to_zero(api, namespace, name, uid_of(&raw)).await?;
                status = status.with_condition(condition(
                    ConditionKind::Degraded,
                    ConditionStatus::True,
                    "Suspended",
                    if scaled {
                        "the spec is invalid and the gateway is suspended: the operator-owned \
                         workload was scaled to zero"
                    } else {
                        "the spec is invalid and the gateway is suspended: no operator-owned \
                         workload was found to scale down"
                    },
                    generation,
                    now_unix,
                ));
            }
            return write_status(api, namespace, name, raw, status.clone())
                .await
                .map(|_| ReconcileOutcome::Refused {
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
            let mut status = GatewayStatus::default()
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
            if suspended {
                let scaled =
                    scale_operator_owned_to_zero(api, namespace, name, uid_of(&raw)).await?;
                status = status.with_condition(condition(
                    ConditionKind::Degraded,
                    ConditionStatus::True,
                    "Suspended",
                    if scaled {
                        "the gateway is suspended: the operator-owned workload was scaled to zero"
                    } else {
                        "the gateway is suspended: no operator-owned workload was found"
                    },
                    generation,
                    now_unix,
                ));
            }
            return write_status(api, namespace, name, raw, status.clone())
                .await
                .map(|_| ReconcileOutcome::Refused {
                    reason: Refusal::RenderRefused { detail },
                    status,
                });
        }
    };

    let workload_kind = rendered.kind().to_owned();
    let workload_name = rendered.name().to_owned();

    // The adoption guard: an object that exists and is owned by someone else
    // is never modified (ADR-0011 section 8.14).
    let existing = api
        .get_workload(namespace, rendered.kind(), rendered.name())
        .await
        .map_err(ReconcileError::Api)?;
    if let Some(live) = &existing {
        if !is_operator_owned(
            live,
            &gateway.metadata.name,
            gateway.metadata.uid.as_deref(),
        ) {
            let status = GatewayStatus::default()
                .with_generation(generation)
                .with_condition(condition(
                    ConditionKind::Degraded,
                    ConditionStatus::True,
                    "OwnershipConflict",
                    &format!(
                        "{workload_kind}/{workload_name} exists and is not owned by the operator; \
                         a foreign object may still be serving"
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
            return write_status(api, namespace, name, raw, status.clone())
                .await
                .map(|_| ReconcileOutcome::Refused {
                    reason: Refusal::OwnershipConflict {
                        object: format!("{workload_kind}/{workload_name}"),
                    },
                    status,
                });
        }
    }

    let manifest = workload_manifest(&rendered)
        .map_err(|_| ReconcileError::Api(ApiFailure("workload could not be encoded".into())))?;
    if let Err(error) = api
        .apply_workload(namespace, rendered.kind(), manifest, FIELD_MANAGER)
        .await
    {
        return degrade_and_fail(api, namespace, name, raw, generation, now_unix, &error).await;
    }

    // A backend change flips the workload kind; the previous operator-owned
    // workload of the other kind would keep its pod-template labels and keep
    // receiving the Service's traffic, so it is deleted once the new kind is
    // in place.
    let other_kind = if workload_kind == "Deployment" {
        "StatefulSet"
    } else {
        "Deployment"
    };
    let stale = api
        .get_workload(namespace, other_kind, &workload_name)
        .await
        .map_err(ReconcileError::Api)?;
    if let Some(stale) = stale {
        if is_operator_owned(
            &stale,
            &gateway.metadata.name,
            gateway.metadata.uid.as_deref(),
        ) {
            api.delete_workload(namespace, other_kind, &workload_name)
                .await
                .map_err(ReconcileError::Api)?;
        }
    }

    let service_name = format!("corvi-gateway-{name}");
    let service = service_manifest(&rendered, &gateway, profile, &service_name);
    let mut applied_service = None;
    match service {
        Some(service) => {
            // The Service is guarded like the workload: a foreign object with
            // this deterministic name is never adopted.
            let existing_service = api
                .get_service(namespace, &service_name)
                .await
                .map_err(ReconcileError::Api)?;
            if let Some(live) = &existing_service {
                if !is_operator_owned(
                    live,
                    &gateway.metadata.name,
                    gateway.metadata.uid.as_deref(),
                ) {
                    let status = GatewayStatus::default()
                        .with_generation(generation)
                        .with_condition(condition(
                            ConditionKind::Degraded,
                            ConditionStatus::True,
                            "OwnershipConflict",
                            &format!(
                                "Service/{service_name} exists and is not owned by the operator"
                            ),
                            generation,
                            now_unix,
                        ))
                        .with_condition(condition(
                            ConditionKind::Resolved,
                            ConditionStatus::False,
                            "OwnershipConflict",
                            "a Helm-owned Service is never adopted (ADR-0011 section 8.14)",
                            generation,
                            now_unix,
                        ));
                    return write_status(api, namespace, name, raw, status.clone())
                        .await
                        .map(|_| ReconcileOutcome::Refused {
                            reason: Refusal::OwnershipConflict {
                                object: format!("Service/{service_name}"),
                            },
                            status,
                        });
                }
            }
            let manifest = serde_json::to_value(&service).map_err(|_| {
                ReconcileError::Api(ApiFailure("service could not be encoded".into()))
            })?;
            if let Err(error) = api.apply_service(namespace, manifest, FIELD_MANAGER).await {
                return degrade_and_fail(api, namespace, name, raw, generation, now_unix, &error)
                    .await;
            }
            applied_service = Some(service_name.clone());
        }
        None => {
            // No listener is published: an operator-owned Service from an
            // earlier generation would keep routing disabled ports, so it is
            // removed.
            let existing_service = api
                .get_service(namespace, &service_name)
                .await
                .map_err(ReconcileError::Api)?;
            if let Some(live) = existing_service {
                if is_operator_owned(
                    &live,
                    &gateway.metadata.name,
                    gateway.metadata.uid.as_deref(),
                ) {
                    api.delete_service(namespace, &service_name)
                        .await
                        .map_err(ReconcileError::Api)?;
                }
            }
        }
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

    if suspended {
        status = status.with_condition(condition(
            ConditionKind::Resolved,
            ConditionStatus::True,
            "Suspended",
            "the gateway is suspended; the workload is scaled to zero",
            generation,
            now_unix,
        ));
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
    }

    // The snapshot pipeline (ADR-0012 section 3) is the remaining piece of
    // the phase: until it exists, the applied workload's pods cannot start,
    // and the status says so instead of implying readiness is reachable.
    status = status.with_condition(condition(
        ConditionKind::Degraded,
        ConditionStatus::True,
        SNAPSHOT_PENDING_REASON,
        "the configuration snapshot (ADR-0012 section 3) is not published yet; \
         the workload mounts a ConfigMap nothing creates, so no pod can start",
        generation,
        now_unix,
    ));

    let status = carry_transition_times(&raw, status);
    let outcome = if suspended {
        ReconcileOutcome::Suspended {
            status: status.clone(),
        }
    } else {
        ReconcileOutcome::Applied {
            workload_kind,
            workload_name,
            service: applied_service,
            status: status.clone(),
        }
    };
    write_status(api, namespace, name, raw, status).await?;
    Ok(outcome)
}

/// Scale any operator-owned workload of either kind to zero.
///
/// Used on refusal paths for a suspended gateway, where the spec may be too
/// broken to name its own workload kind. Returns whether anything was
/// scaled.
async fn scale_operator_owned_to_zero<A: ClusterApi>(
    api: &A,
    namespace: &str,
    name: &str,
    gateway_uid: Option<&str>,
) -> Result<bool, ReconcileError> {
    let workload_name = format!("corvi-gateway-{name}");
    let mut scaled = false;
    for kind in ["Deployment", "StatefulSet"] {
        let existing = api
            .get_workload(namespace, kind, &workload_name)
            .await
            .map_err(ReconcileError::Api)?;
        let Some(live) = existing else {
            continue;
        };
        if !is_operator_owned(&live, name, gateway_uid) {
            continue;
        }
        api.scale_workload(namespace, kind, &workload_name)
            .await
            .map_err(ReconcileError::Api)?;
        scaled = true;
    }
    Ok(scaled)
}

/// Best-effort degraded status before surfacing an API failure.
async fn degrade_and_fail<A: ClusterApi>(
    api: &A,
    namespace: &str,
    name: &str,
    raw: serde_json::Value,
    generation: i64,
    now_unix: i64,
    failure: &ApiFailure,
) -> Result<ReconcileOutcome, ReconcileError> {
    let status = GatewayStatus::default()
        .with_generation(generation)
        .with_condition(condition(
            ConditionKind::Degraded,
            ConditionStatus::True,
            "ApplyFailed",
            &format!("a mutation failed and the status may lag: {}", failure.0),
            generation,
            now_unix,
        ));
    let _ = write_status(api, namespace, name, raw, status).await;
    Err(ReconcileError::Api(failure.clone()))
}

/// Write the status, stamping unchanged conditions with their previous
/// transition times so an unchanged reconciliation does not churn the
/// resource.
async fn write_status<A: ClusterApi>(
    api: &A,
    namespace: &str,
    name: &str,
    raw: serde_json::Value,
    mut status: GatewayStatus,
) -> Result<(), ReconcileError> {
    status = carry_transition_times(&raw, status);
    let patch = serde_json::json!({
        "apiVersion": mail_operator::model::API_GROUP_VERSION,
        "kind": mail_operator::model::ResourceKind::CorviGateway.as_str(),
        "metadata": { "name": name },
        "status": serde_json::to_value(&status)
            .map_err(|_| ReconcileError::Api(ApiFailure("status could not be encoded".into())))?,
    });
    api.patch_status(namespace, name, patch)
        .await
        .map_err(ReconcileError::Api)
}

/// Keep the previous `lastTransitionTime` for every condition whose content
/// is unchanged; a condition that did not change did not transition.
fn carry_transition_times(raw: &serde_json::Value, mut status: GatewayStatus) -> GatewayStatus {
    let Some(previous) = raw["status"]["conditions"].as_array() else {
        return status;
    };
    for condition in &mut status.conditions {
        if let Some(old) = previous
            .iter()
            .find(|old| old["type"] == serde_json::json!(condition.kind.as_str()))
        {
            let unchanged = old["status"] == serde_json::json!(condition.status.as_str())
                && old["reason"] == serde_json::json!(condition.reason)
                && old["message"] == serde_json::json!(condition.message)
                && old["observedGeneration"] == serde_json::json!(condition.observed_generation);
            if unchanged {
                if let Some(time) = old["lastTransitionTime"].as_str() {
                    condition.last_transition_time = time.to_owned();
                }
            }
        }
    }
    status
}

/// Whose object the live one is. The rule fails closed: an explicit
/// `managed-by` label that is not this operator's makes the object foreign
/// even if it carries the gateway as controller owner — a stolen label with a
/// kept owner reference is exactly what a hostile or buggy adoption looks
/// like. An object with no `managed-by` label is the operator's only when the
/// reconciled gateway is its controller owner by name. An unlabeled object
/// created by `kubectl` is therefore never adopted: ADR-0011 section 8.14
/// gives the operator one owner, and silently taking over a foreign object is
/// the opposite of that. The label itself is forgeable by anyone with patch
/// RBAC in the namespace; the real boundary is that RBAC, not this check.
fn is_operator_owned(
    live: &serde_json::Value,
    gateway_name: &str,
    gateway_uid: Option<&str>,
) -> bool {
    let metadata = &live["metadata"];
    let managed_by = metadata["labels"][MANAGED_BY_LABEL].as_str();
    if let Some(managed_by) = managed_by {
        return managed_by == MANAGED_BY_VALUE;
    }
    if let Some(references) = metadata["ownerReferences"].as_array() {
        for reference in references {
            let controller = reference["controller"].as_bool().unwrap_or(false);
            let named = reference["name"].as_str() == Some(gateway_name);
            // Both sides must carry a UID and they must match; a reference
            // without one is never proof of ownership (fail closed).
            let same_uid = match (gateway_uid, reference["uid"].as_str()) {
                (Some(ours), Some(theirs)) => ours == theirs,
                _ => false,
            };
            if controller && named && same_uid && reference["kind"].as_str() == Some("CorviGateway")
            {
                return true;
            }
        }
    }
    false
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
            "labels": selector,
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

/// The UID of a live object, before it has been parsed.
fn uid_of(raw: &serde_json::Value) -> Option<&str> {
    raw["metadata"]["uid"].as_str()
}

/// The generation of a live object, before it has been parsed.
fn generation_of(raw: &serde_json::Value) -> i64 {
    raw["metadata"]["generation"].as_i64().unwrap_or(0)
}

/// Bound a message so a refusal cannot carry unbounded text into status; the
/// appended marker keeps the total inside the CRD's 1024-character bound.
pub fn bounded(message: String) -> String {
    const MAX: usize = 1024;
    const MARKER: usize = 3; // "..."
    if message.chars().count() <= MAX {
        return message;
    }
    let mut end = 0;
    for (kept_index, (index, character)) in message.char_indices().enumerate() {
        if kept_index == MAX - MARKER {
            break;
        }
        end = index + character.len_utf8();
    }
    format!("{}...", &message[..end])
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
/// condition is `Unknown`. A converged zero-replica gateway is ready.
fn readiness(observed: &ObservedReplicas, desired: i64) -> (ConditionStatus, &'static str) {
    match observed.ready {
        Some(ready) if ready >= desired => (ConditionStatus::True, "AtDesiredReplicas"),
        Some(_) => (ConditionStatus::False, "ReplicasNotReady"),
        None => (ConditionStatus::Unknown, "AwaitingWorkloadStatus"),
    }
}
