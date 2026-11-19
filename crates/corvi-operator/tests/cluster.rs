//! The reconciler against a real API server.
//!
//! This test is **opt-in**: it creates and deletes cluster resources in the
//! current kubeconfig's cluster. Run it with
//!
//! ```console
//! $ CORVI_OPERATOR_CLUSTER=1 cargo test -p corvi-operator --test cluster
//! ```
//!
//! It verifies what no in-memory fake can: that the reconciler's manifests
//! are accepted by a real API server, that the cluster's own controllers
//! react to them, and that the status subresource accepts the conditions.

use corvi_operator::kube::{API_GROUP, API_VERSION, OperatorClient};
use corvi_operator::{ReconcileOutcome, reconcile_gateway};
use kube::api::{Api, DynamicObject, GroupVersionKind, Patch, PatchParams};

/// Skip unless explicitly opted in.
fn opted_in() -> bool {
    std::env::var("CORVI_OPERATOR_CLUSTER").is_ok_and(|value| value == "1")
}

fn profile() -> mail_operator::workload::OperatorProfile {
    mail_operator::workload::OperatorProfile {
        gateway_image: "ghcr.io/naktis-labs/corvi-gateway@sha256:".to_owned() + &"a".repeat(64),
        operator_service_account: "corvi-operator".to_owned(),
        gateway_service_account: "corvi-gateway".to_owned(),
        http_port: 8080,
        smtp_submission_port: 2525,
        admission_policy: PolicyExpectation {
            name: "corvi-restricted-workload".to_owned(),
            kind: PolicyKind::Admission,
            source: PolicySource::IndependentlyInstalled,
        },
        network_policy: PolicyExpectation {
            name: "corvi-gateway-default-deny".to_owned(),
            kind: PolicyKind::Network,
            source: PolicySource::IndependentlyInstalled,
        },
    }
}

use mail_operator::workload::{PolicyExpectation, PolicyKind, PolicySource};

fn fixture(name: &str) -> serde_json::Value {
    let path = format!(
        "{}/../../api/operator/fixtures/{name}.yaml",
        env!("CARGO_MANIFEST_DIR")
    );
    let document = std::fs::read_to_string(&path).expect("the fixture exists");
    serde_yaml::from_str(&document).expect("a fixture is a YAML document")
}

fn gateway_api(client: &kube::Client, namespace: &str) -> Api<DynamicObject> {
    let gvk = GroupVersionKind::gvk(API_GROUP, API_VERSION, "CorviGateway");
    let resource = kube::api::ApiResource::from_gvk_with_plural(&gvk, "corvigateways");
    Api::namespaced_with(client.clone(), namespace, &resource)
}

fn workload_api(client: &kube::Client, namespace: &str, kind: &str) -> Api<DynamicObject> {
    let gvk = GroupVersionKind::gvk("apps", "v1", kind);
    let plural = if kind == "Deployment" {
        "deployments"
    } else {
        "statefulsets"
    };
    let resource = kube::api::ApiResource::from_gvk_with_plural(&gvk, plural);
    Api::namespaced_with(client.clone(), namespace, &resource)
}

/// Apply a manifest under a test field manager.
async fn apply(api: &Api<DynamicObject>, manifest: &serde_json::Value) {
    let name = manifest["metadata"]["name"].as_str().unwrap();
    let params = PatchParams::apply("corvi-operator-integration-test").force();
    api.patch(name, &params, &Patch::Apply(manifest))
        .await
        .expect("the test manifest applies");
}

#[tokio::test]
async fn the_reconciler_drives_a_real_api_server() {
    if !opted_in() {
        eprintln!("skipping: set CORVI_OPERATOR_CLUSTER=1 to run against a real cluster");
        return;
    }
    let namespace = std::env::var("CORVI_NAMESPACE").unwrap_or_else(|_| "corvi-system".to_owned());
    let operator = OperatorClient::connect(&namespace)
        .await
        .expect("a reachable cluster");

    // The CRDs must be installed first; scripts/validate_cluster.sh does that.
    let gateways = gateway_api(operator.kube(), &namespace);
    // The fixture carries a fabricated UID for design fixtures; a live
    // object gets its UID from the API server, so it is stripped here and
    // the reconciler reads the real one back.
    let mut gateway = fixture("gateway-primary");
    gateway["metadata"]["uid"] = serde_json::Value::Null;
    gateway["metadata"]["generation"] = serde_json::Value::Null;
    apply(&gateways, &gateway).await;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| i64::try_from(since.as_secs()).unwrap_or(0))
        .unwrap_or(0);
    let outcome = reconcile_gateway(&operator, &namespace, "primary", &profile(), now)
        .await
        .expect("the reconciliation succeeds");

    let ReconcileOutcome::Applied { workload_kind, .. } = &outcome else {
        panic!("expected an applied workload, got {outcome:?}");
    };
    assert_eq!(workload_kind, "Deployment");

    // The API server accepted the manifest and the cluster's own controllers
    // materialised the pod template from it.
    let workloads = workload_api(operator.kube(), &namespace, "Deployment");
    let live = workloads
        .get("corvi-gateway-primary")
        .await
        .expect("the workload was applied");
    let pod = &live.data["spec"]["template"]["spec"];
    assert_eq!(pod["automountServiceAccountToken"], false);
    assert_eq!(pod["securityContext"]["runAsNonRoot"], true);
    assert_eq!(pod["securityContext"]["runAsUser"], 65532);
    assert_eq!(pod["serviceAccountName"], "corvi-gateway");

    // The Service exists and is ClusterIP.
    let services_gvk = GroupVersionKind::gvk("", "v1", "Service");
    let services_resource = kube::api::ApiResource::from_gvk_with_plural(&services_gvk, "services");
    let services: Api<DynamicObject> =
        Api::namespaced_with(operator.kube().clone(), &namespace, &services_resource);
    let service = services
        .get("corvi-gateway-primary")
        .await
        .expect("the service was applied");
    assert_eq!(service.data["spec"]["type"], "ClusterIP");

    // The status subresource accepted the conditions.
    let stored = gateways.get("primary").await.expect("the gateway exists");
    let conditions = stored.data["status"]["conditions"]
        .as_array()
        .expect("the status was written");
    let resolved = conditions
        .iter()
        .find(|condition| condition["type"] == "Resolved")
        .expect("a Resolved condition");
    assert_eq!(resolved["status"], "True");

    // A foreign workload is refused, and the refusal is on the status.
    let foreign = serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": "corvi-gateway-primary",
            "namespace": &namespace,
            "labels": { "app.kubernetes.io/managed-by": "Helm" },
        },
        "spec": { "replicas": 3 },
    });
    apply(&workloads, &foreign).await;
    let outcome = reconcile_gateway(&operator, &namespace, "primary", &profile(), now)
        .await
        .expect("the reconciliation completes");
    assert!(matches!(outcome, ReconcileOutcome::Refused { .. }));
    let stored = gateways.get("primary").await.unwrap();
    let conditions = stored.data["status"]["conditions"].as_array().unwrap();
    assert!(
        conditions
            .iter()
            .any(|condition| condition["reason"] == "OwnershipConflict"),
        "the ownership conflict is reported on the status"
    );

    // Cleanup: remove what this test created, nothing else.
    let _ = workloads
        .delete("corvi-gateway-primary", &Default::default())
        .await;
    let _ = services
        .delete("corvi-gateway-primary", &Default::default())
        .await;
    let _ = gateways.delete("primary", &Default::default()).await;
}
