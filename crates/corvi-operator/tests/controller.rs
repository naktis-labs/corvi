//! The reconciliation rules, tested against an in-memory API.
//!
//! These tests exercise the exact paths a real cluster takes: the fixtures
//! under `api/operator/fixtures/` are the same documents the cluster
//! validation applies, and the workload manifests asserted here are the ones
//! `mail-operator` renders.

use std::collections::BTreeMap;
use std::sync::Mutex;

use corvi_operator::status::ConditionKind;
use corvi_operator::{
    ClusterApi, FIELD_MANAGER, MANAGED_BY_LABEL, MANAGED_BY_VALUE, ReconcileError,
    ReconcileOutcome, Refusal, reconcile_gateway,
};
use mail_operator::workload::{OperatorProfile, PolicyExpectation};

const NOW: i64 = 1_763_000_000;

/// The operator-approved profile, identical to mail-operator's fixtures.
fn profile() -> OperatorProfile {
    OperatorProfile {
        gateway_image: "ghcr.io/naktis-labs/corvi-gateway@sha256:".to_owned() + &"a".repeat(64),
        operator_service_account: "corvi-operator".to_owned(),
        gateway_service_account: "corvi-gateway".to_owned(),
        http_port: 8080,
        smtp_submission_port: 2525,
        admission_policy: admission_policy(),
        network_policy: network_policy(),
    }
}

/// The default policy expectations used by mail-operator's own fixtures.
fn admission_policy() -> PolicyExpectation {
    PolicyExpectation {
        name: "corvi-restricted-workload".to_owned(),
        kind: mail_operator::workload::PolicyKind::Admission,
        source: mail_operator::workload::PolicySource::IndependentlyInstalled,
    }
}

fn network_policy() -> PolicyExpectation {
    PolicyExpectation {
        name: "corvi-gateway-default-deny".to_owned(),
        kind: mail_operator::workload::PolicyKind::Network,
        source: mail_operator::workload::PolicySource::IndependentlyInstalled,
    }
}

/// An in-memory API with the same observable behaviour as the real one.
#[derive(Default)]
struct FakeApi {
    gateways: Mutex<BTreeMap<String, serde_json::Value>>,
    workloads: Mutex<BTreeMap<String, serde_json::Value>>,
    services: Mutex<BTreeMap<String, serde_json::Value>>,
    status_patches: Mutex<Vec<serde_json::Value>>,
}

impl FakeApi {
    fn with_gateway(name: &str, manifest: serde_json::Value) -> Self {
        let api = Self::default();
        api.gateways
            .lock()
            .unwrap()
            .insert(name.to_owned(), manifest);
        api
    }

    fn with_workload_from(self, kind: &str, name: &str, manifest: serde_json::Value) -> Self {
        self.workloads
            .lock()
            .unwrap()
            .insert(format!("{kind}/{name}"), manifest);
        self
    }

    fn workload(&self, kind: &str, name: &str) -> Option<serde_json::Value> {
        self.workloads
            .lock()
            .unwrap()
            .get(&format!("{kind}/{name}"))
            .cloned()
    }

    fn service(&self, name: &str) -> Option<serde_json::Value> {
        self.services.lock().unwrap().get(name).cloned()
    }
}

impl ClusterApi for FakeApi {
    async fn get_gateway(
        &self,
        _namespace: &str,
        name: &str,
    ) -> Result<Option<serde_json::Value>, corvi_operator::ApiFailure> {
        Ok(self.gateways.lock().unwrap().get(name).cloned())
    }

    async fn get_workload(
        &self,
        _namespace: &str,
        kind: &str,
        name: &str,
    ) -> Result<Option<serde_json::Value>, corvi_operator::ApiFailure> {
        Ok(self.workload(kind, name))
    }

    async fn apply_workload(
        &self,
        _namespace: &str,
        kind: &str,
        manifest: serde_json::Value,
        _field_manager: &str,
    ) -> Result<(), corvi_operator::ApiFailure> {
        let name = manifest["metadata"]["name"].as_str().unwrap().to_owned();
        self.workloads
            .lock()
            .unwrap()
            .insert(format!("{kind}/{name}"), manifest);
        Ok(())
    }

    async fn apply_service(
        &self,
        _namespace: &str,
        manifest: serde_json::Value,
        _field_manager: &str,
    ) -> Result<(), corvi_operator::ApiFailure> {
        let name = manifest["metadata"]["name"].as_str().unwrap().to_owned();
        self.services.lock().unwrap().insert(name, manifest);
        Ok(())
    }

    async fn patch_status(
        &self,
        _namespace: &str,
        _name: &str,
        patch: serde_json::Value,
    ) -> Result<(), corvi_operator::ApiFailure> {
        self.status_patches.lock().unwrap().push(patch);
        Ok(())
    }
}

/// Read a checked-in operator fixture as its JSON manifest.
fn fixture(name: &str) -> serde_json::Value {
    let path = format!(
        "{}/../../api/operator/fixtures/{name}.yaml",
        env!("CARGO_MANIFEST_DIR")
    );
    let document = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("fixture {name} could not be read: {error}"));
    serde_yaml::from_str(&document).expect("a fixture is a YAML document")
}

/// Load a fixture and index it by the resource's own `metadata.name`,
/// exactly as the API server would.
fn gateway_fixture(file: &str) -> (FakeApi, String) {
    let manifest = fixture(file);
    let name = manifest["metadata"]["name"]
        .as_str()
        .expect("a fixture names its resource")
        .to_owned();
    (FakeApi::with_gateway(&name, manifest), name)
}

fn status_json(status: &corvi_operator::status::GatewayStatus) -> serde_json::Value {
    serde_json::to_value(status).expect("a status always serialises")
}

fn condition_of(status: &serde_json::Value, kind: ConditionKind) -> serde_json::Value {
    status["conditions"]
        .as_array()
        .expect("conditions were written")
        .iter()
        .find(|condition| condition["type"].as_str() == Some(kind.as_str()))
        .cloned()
        .unwrap_or_else(|| panic!("condition {} was written", kind.as_str()))
}

#[tokio::test]
async fn a_valid_gateway_is_reconciled_to_a_hardened_workload() {
    let (api, name) = gateway_fixture("gateway-primary");
    let outcome = reconcile_gateway(&api, "corvi-system", &name, &profile(), NOW)
        .await
        .expect("reconciliation succeeds");
    let ReconcileOutcome::Applied {
        workload_kind,
        workload_name,
        service,
        status,
    } = outcome
    else {
        panic!("expected an applied workload, got {outcome:?}");
    };
    let status = status_json(&status);
    assert_eq!(workload_kind, "Deployment");
    assert_eq!(workload_name, "corvi-gateway-primary");
    assert_eq!(service.as_deref(), Some("corvi-gateway-primary"));

    let live = api.workload(&workload_kind, &workload_name).unwrap();
    // The hardened profile, applied to the live object, not just rendered.
    let pod = &live["spec"]["template"]["spec"];
    assert_eq!(pod["automountServiceAccountToken"], false);
    assert_eq!(pod["securityContext"]["runAsNonRoot"], true);
    assert_eq!(pod["securityContext"]["runAsUser"], 65532);
    assert_eq!(pod["serviceAccountName"], "corvi-gateway");
    assert_eq!(
        live["metadata"]["labels"][MANAGED_BY_LABEL],
        MANAGED_BY_VALUE
    );
    assert_eq!(live["spec"]["replicas"], 1);

    // The workload is owned by the gateway it was rendered from.
    assert_eq!(
        live["metadata"]["ownerReferences"][0]["kind"].as_str(),
        Some("CorviGateway")
    );

    // The status is written with the schema's fields.
    assert_eq!(
        condition_of(&status, ConditionKind::Accepted)["status"],
        "True"
    );
    assert_eq!(
        condition_of(&status, ConditionKind::Resolved)["reason"],
        "WorkloadApplied"
    );
    assert_eq!(status["workloadKind"], "Deployment");
    assert_eq!(status["serviceName"], "corvi-gateway-primary");
    assert_eq!(status["desiredReplicas"], 1);
}

#[tokio::test]
async fn the_service_carries_only_the_enabled_listeners() {
    let (api, name) = gateway_fixture("gateway-primary");
    reconcile_gateway(&api, "corvi-system", &name, &profile(), NOW)
        .await
        .unwrap();
    let service = api.service("corvi-gateway-primary").unwrap();
    let ports: Vec<&str> = service["spec"]["ports"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|port| port["name"].as_str())
        .collect();
    assert_eq!(
        ports,
        vec!["http", "smtp-submission"],
        "both listeners are enabled"
    );
    assert_eq!(service["spec"]["type"], "ClusterIP");
    // The Service is owned by the gateway so garbage collection follows it.
    assert_eq!(
        service["metadata"]["ownerReferences"][0]["uid"],
        fixture("gateway-primary")["metadata"]["uid"]
    );
}

#[tokio::test]
async fn a_suspended_gateway_reconciles_to_zero_replicas() {
    let (api, name) = gateway_fixture("gateway-primary");
    let mut suspended = fixture("gateway-primary");
    suspended["spec"]["suspended"] = serde_json::json!(true);
    api.gateways.lock().unwrap().insert(name.clone(), suspended);

    let outcome = reconcile_gateway(&api, "corvi-system", &name, &profile(), NOW)
        .await
        .unwrap();
    let ReconcileOutcome::Suspended { status } = outcome else {
        panic!("expected a suspended outcome, got {outcome:?}");
    };
    let status = status_json(&status);
    assert_eq!(
        condition_of(&status, ConditionKind::Resolved)["reason"],
        "Suspended"
    );
    let live = api.workload("Deployment", "corvi-gateway-primary").unwrap();
    assert_eq!(
        live["spec"]["replicas"], 0,
        "suspended means no mail-serving replicas"
    );
    assert_eq!(status["desiredReplicas"], 0);
}

#[tokio::test]
async fn a_helm_owned_workload_is_never_adopted() {
    // The operator-created workload already exists, owned by a Helm release.
    let (api, _) = gateway_fixture("gateway-primary");
    let foreign = serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "StatefulSet",
        "metadata": {
            "name": "corvi-gateway-primary",
            "namespace": "corvi-system",
            "labels": { MANAGED_BY_LABEL: "Helm" },
        },
        "spec": { "replicas": 3 },
    });
    let api = FakeApi::with_workload_from(api, "Deployment", "corvi-gateway-primary", foreign);

    let outcome = reconcile_gateway(&api, "corvi-system", "primary", &profile(), NOW)
        .await
        .unwrap();
    let ReconcileOutcome::Refused { reason, status } = outcome else {
        panic!("expected a refusal, got {outcome:?}");
    };
    let status = status_json(&status);
    assert_eq!(
        reason,
        Refusal::OwnershipConflict {
            workload: "Deployment/corvi-gateway-primary".to_owned(),
        }
    );
    assert_eq!(
        condition_of(&status, ConditionKind::Resolved)["reason"],
        "OwnershipConflict"
    );
    // The foreign workload is untouched.
    let live = api.workload("Deployment", "corvi-gateway-primary").unwrap();
    assert_eq!(live["spec"]["replicas"], 3);
}

#[tokio::test]
async fn an_unlabeled_workload_is_not_adopted_either() {
    // An object with no managed-by label and no controller owner is not the
    // operator's, even though it carries its name: adopting foreign objects
    // is the failure mode ADR-0011 section 8.14 forbids.
    let (api, _) = gateway_fixture("gateway-primary");
    let plain = serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "StatefulSet",
        "metadata": { "name": "corvi-gateway-primary", "namespace": "corvi-system" },
        "spec": { "replicas": 2 },
    });
    let api = FakeApi::with_workload_from(api, "Deployment", "corvi-gateway-primary", plain);
    let outcome = reconcile_gateway(&api, "corvi-system", "primary", &profile(), NOW)
        .await
        .unwrap();
    assert!(matches!(outcome, ReconcileOutcome::Refused { .. }));
    let live = api.workload("Deployment", "corvi-gateway-primary").unwrap();
    assert_eq!(live["spec"]["replicas"], 2, "nothing was changed");
}

#[tokio::test]
async fn a_stolen_label_with_a_kept_owner_reference_is_still_foreign() {
    // The hostile case: someone stole the managed-by label but the gateway
    // controller owner reference survived. The explicit foreign label wins;
    // the object is never touched.
    let (api, name) = gateway_fixture("gateway-primary");
    let hostile = serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": "corvi-gateway-primary",
            "namespace": "corvi-system",
            "labels": { MANAGED_BY_LABEL: "Helm" },
            "ownerReferences": [{
                "apiVersion": "corvi.naktis.eu/v1alpha1",
                "kind": "CorviGateway",
                "name": name,
                "uid": "00000000-0000-0000-0000-000000000001",
                "controller": true,
                "blockOwnerDeletion": true,
            }],
        },
        "spec": { "replicas": 5 },
    });
    let api = FakeApi::with_workload_from(api, "Deployment", "corvi-gateway-primary", hostile);
    let outcome = reconcile_gateway(&api, "corvi-system", &name, &profile(), NOW)
        .await
        .unwrap();
    assert!(matches!(outcome, ReconcileOutcome::Refused { .. }));
    let live = api.workload("Deployment", "corvi-gateway-primary").unwrap();
    assert_eq!(live["spec"]["replicas"], 5, "nothing was changed");
}

#[tokio::test]
async fn an_operator_owned_workload_is_updated_in_place() {
    let (api, _) = gateway_fixture("gateway-primary");
    let owned = serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "StatefulSet",
        "metadata": {
            "name": "corvi-gateway-primary",
            "namespace": "corvi-system",
            "labels": { MANAGED_BY_LABEL: MANAGED_BY_VALUE },
        },
        "status": { "replicas": 1, "readyReplicas": 1 },
        "spec": { "replicas": 1 },
    });
    let api = FakeApi::with_workload_from(api, "Deployment", "corvi-gateway-primary", owned);

    let outcome = reconcile_gateway(&api, "corvi-system", "primary", &profile(), NOW)
        .await
        .unwrap();
    let ReconcileOutcome::Applied { status, .. } = outcome else {
        panic!("expected an applied workload, got {outcome:?}");
    };
    let status = status_json(&status);
    assert_eq!(
        condition_of(&status, ConditionKind::Ready)["status"],
        "True"
    );
    assert_eq!(
        condition_of(&status, ConditionKind::Ready)["reason"],
        "AtDesiredReplicas"
    );
    assert_eq!(status["readyReplicas"], 1);
}

#[tokio::test]
async fn an_invalid_spec_is_reported_and_changes_nothing() {
    for file in [
        "invalid-podspec-injection",
        "invalid-owner-reference-injection",
    ] {
        let (api, name) = gateway_fixture(file);
        let outcome = reconcile_gateway(&api, "corvi-system", &name, &profile(), NOW)
            .await
            .unwrap();
        let ReconcileOutcome::Refused { reason, status } = outcome else {
            panic!("expected a refusal for {name}, got {outcome:?}");
        };
        let status = status_json(&status);
        let Refusal::InvalidSpec { detail } = reason else {
            panic!("expected an invalid-spec refusal for {name}, got {reason:?}");
        };
        assert!(!detail.is_empty());
        assert_eq!(
            condition_of(&status, ConditionKind::Resolved)["reason"],
            "InvalidReference"
        );
        // No workload was created for an invalid spec.
        assert!(
            api.workload("Deployment", &format!("corvi-gateway-{name}"))
                .is_none()
        );
        assert!(
            api.workload("StatefulSet", &format!("corvi-gateway-{name}"))
                .is_none()
        );
    }
}

#[tokio::test]
async fn a_spec_the_hardened_profile_refuses_changes_nothing() {
    let (api, name) = gateway_fixture("invalid-sqlite-two-replicas");
    let outcome = reconcile_gateway(&api, "corvi-system", &name, &profile(), NOW)
        .await
        .unwrap();
    let ReconcileOutcome::Refused { reason, status } = outcome else {
        panic!("expected a refusal, got {outcome:?}");
    };
    let status = status_json(&status);
    let Refusal::RenderRefused { detail } = reason else {
        panic!("expected a render refusal, got {reason:?}");
    };
    assert!(
        detail.contains("replica"),
        "the replica limit is named: {detail}"
    );
    assert_eq!(
        condition_of(&status, ConditionKind::Accepted)["status"],
        "False"
    );
    assert_eq!(
        condition_of(&status, ConditionKind::Resolved)["reason"],
        "RenderRefused"
    );
}

#[tokio::test]
async fn a_gateway_without_listeners_gets_no_service() {
    let (api, name) = gateway_fixture("gateway-primary");
    let mut no_listeners = fixture("gateway-primary");
    no_listeners["spec"]["listeners"] = serde_json::json!({
        "http": { "enabled": false },
        "smtpSubmission": { "enabled": false },
    });
    api.gateways
        .lock()
        .unwrap()
        .insert(name.clone(), no_listeners);

    let outcome = reconcile_gateway(&api, "corvi-system", &name, &profile(), NOW)
        .await
        .unwrap();
    let ReconcileOutcome::Applied {
        service, status, ..
    } = outcome
    else {
        panic!("expected an applied workload, got {outcome:?}");
    };
    let status = status_json(&status);
    assert_eq!(service, None);
    assert!(api.service("corvi-gateway-primary").is_none());
    assert_eq!(status["serviceName"], serde_json::Value::Null);
}

#[tokio::test]
async fn a_missing_gateway_is_a_no_op() {
    let api = FakeApi::default();
    let outcome = reconcile_gateway(&api, "corvi-system", "primary", &profile(), NOW)
        .await
        .unwrap();
    assert_eq!(outcome, ReconcileOutcome::Gone);
    assert!(api.status_patches.lock().unwrap().is_empty());
}

#[tokio::test]
async fn an_api_failure_surfaces_as_a_reconcile_error() {
    struct Broken;
    impl ClusterApi for Broken {
        async fn get_gateway(
            &self,
            _namespace: &str,
            _name: &str,
        ) -> Result<Option<serde_json::Value>, corvi_operator::ApiFailure> {
            Err(corvi_operator::ApiFailure("unreachable".into()))
        }
        async fn get_workload(
            &self,
            _namespace: &str,
            _kind: &str,
            _name: &str,
        ) -> Result<Option<serde_json::Value>, corvi_operator::ApiFailure> {
            unreachable!()
        }
        async fn apply_workload(
            &self,
            _namespace: &str,
            _kind: &str,
            _manifest: serde_json::Value,
            _field_manager: &str,
        ) -> Result<(), corvi_operator::ApiFailure> {
            unreachable!()
        }
        async fn apply_service(
            &self,
            _namespace: &str,
            _manifest: serde_json::Value,
            _field_manager: &str,
        ) -> Result<(), corvi_operator::ApiFailure> {
            unreachable!()
        }
        async fn patch_status(
            &self,
            _namespace: &str,
            _name: &str,
            _patch: serde_json::Value,
        ) -> Result<(), corvi_operator::ApiFailure> {
            unreachable!()
        }
    }
    let error = reconcile_gateway(&Broken, "corvi-system", "primary", &profile(), NOW).await;
    assert!(matches!(error, Err(ReconcileError::Api(_))));
}

/// The field manager and label vocabulary are stable API.
#[test]
fn the_operator_owns_a_stable_label_vocabulary() {
    assert_eq!(FIELD_MANAGER, "corvi-operator");
    assert_eq!(MANAGED_BY_VALUE, "corvi-operator");
}
