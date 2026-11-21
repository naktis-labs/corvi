//! The `kube` adapter: it implements [`ClusterApi`] against a real API
//! server and keeps every kube type out of the reconciliation rules.
//!
//! Objects travel through the dynamic API, because the CRD types are
//! *derived* (see `scripts/generate_crds.py`): hand-deriving a second set of
//! Rust types would be a second source of truth. The reconciler reads the
//! JSON manifest and parses it through `mail_operator`'s model instead.

use crate::ApiFailure;
use crate::ClusterApi;
use kube::Client;
use kube::api::Api;
use kube::api::ApiResource;
use kube::api::DeleteParams;
use kube::api::DynamicObject;
use kube::api::GroupVersionKind;
use kube::api::ListParams;
use kube::api::Patch;
use kube::api::PatchParams;

/// The Corvi API group.
pub const API_GROUP: &str = "corvi.naktis.eu";
/// The served version.
pub const API_VERSION: &str = "v1alpha1";

/// A connected, namespaced client for the resources the operator manages.
#[derive(Clone)]
pub struct OperatorClient {
    client: Client,
    namespace: String,
    gateways: Api<DynamicObject>,
    workloads: std::collections::HashMap<&'static str, Api<DynamicObject>>,
    services: Api<DynamicObject>,
}

impl std::fmt::Debug for OperatorClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OperatorClient")
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}

impl OperatorClient {
    /// Connect with the ambient kubeconfig and scope every API to `namespace`.
    ///
    /// # Errors
    ///
    /// The kubeconfig could not be loaded or the cluster is unreachable.
    pub async fn connect(namespace: impl Into<String>) -> Result<Self, ApiFailure> {
        // Exactly one TLS provider is selected, deterministically, before any
        // connection is made; the workspace already depends on `ring`.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = Client::try_default()
            .await
            .map_err(|error| ApiFailure(format!("no usable kubeconfig: {error}")))?;
        Ok(Self::with_client(client, namespace))
    }

    /// Scope every API to `namespace` using an existing client.
    #[must_use]
    pub fn with_client(client: Client, namespace: impl Into<String>) -> Self {
        let namespace = namespace.into();
        let gateways = dynamic_api(&client, &namespace, "CorviGateway", "corvigateways");
        let mut workloads = std::collections::HashMap::new();
        workloads.insert(
            "Deployment",
            dynamic_api(&client, &namespace, "Deployment", "deployments"),
        );
        workloads.insert(
            "StatefulSet",
            dynamic_api(&client, &namespace, "StatefulSet", "statefulsets"),
        );
        let services = dynamic_api(&client, &namespace, "Service", "services");
        Self {
            client,
            namespace,
            gateways,
            workloads,
            services,
        }
    }

    /// The namespace this client is scoped to.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// The underlying client, for the watch loop.
    #[must_use]
    pub fn kube(&self) -> &Client {
        &self.client
    }

    /// The gateway API handle.
    #[must_use]
    pub fn gateways(&self) -> &Api<DynamicObject> {
        &self.gateways
    }
}

fn dynamic_api(
    client: &Client,
    namespace: &str,
    kind: &'static str,
    plural: &'static str,
) -> Api<DynamicObject> {
    let gvk = GroupVersionKind::gvk(group_of(kind), version_of(kind), kind);
    let api_resource = ApiResource::from_gvk_with_plural(&gvk, plural);
    Api::namespaced_with(client.clone(), namespace, &api_resource)
}

// Deployments, StatefulSets and Services live in their own groups; only the
// Corvi CRDs are in the Corvi group. `GroupVersionKind::gvk` names them here
// so a kind never silently resolves against the wrong group.
fn group_of(kind: &str) -> &'static str {
    match kind {
        "Deployment" | "StatefulSet" => "apps",
        "Service" => "",
        _ => API_GROUP,
    }
}

fn version_of(kind: &str) -> &'static str {
    match kind {
        "Deployment" | "StatefulSet" | "Service" => "v1",
        _ => API_VERSION,
    }
}

impl ClusterApi for OperatorClient {
    async fn get_gateway(
        &self,
        _namespace: &str,
        name: &str,
    ) -> Result<Option<serde_json::Value>, ApiFailure> {
        match self.gateways.get_opt(name).await {
            Ok(Some(object)) => to_value(&object),
            Ok(None) => Ok(None),
            Err(error) => Err(bounded_api_failure("reading the gateway", &error)),
        }
    }

    async fn get_workload(
        &self,
        _namespace: &str,
        kind: &str,
        name: &str,
    ) -> Result<Option<serde_json::Value>, ApiFailure> {
        let Some(api) = self.workloads.get(kind) else {
            return Err(ApiFailure(format!("unsupported workload kind {kind}")));
        };
        match api.get_opt(name).await {
            Ok(Some(object)) => to_value(&object),
            Ok(None) => Ok(None),
            Err(error) => Err(bounded_api_failure("reading the workload", &error)),
        }
    }

    async fn apply_workload(
        &self,
        _namespace: &str,
        kind: &str,
        manifest: serde_json::Value,
        field_manager: &str,
    ) -> Result<(), ApiFailure> {
        let Some(api) = self.workloads.get(kind) else {
            return Err(ApiFailure(format!("unsupported workload kind {kind}")));
        };
        apply(api, manifest, field_manager).await
    }

    async fn apply_service(
        &self,
        _namespace: &str,
        manifest: serde_json::Value,
        field_manager: &str,
    ) -> Result<(), ApiFailure> {
        apply(&self.services, manifest, field_manager).await
    }

    async fn scale_workload(
        &self,
        _namespace: &str,
        kind: &str,
        name: &str,
    ) -> Result<(), ApiFailure> {
        let Some(api) = self.workloads.get(kind) else {
            return Err(ApiFailure(format!("unsupported workload kind {kind}")));
        };
        // A plain JSON merge patch: only the replica count changes, and the
        // fields the operator's apply manager owns stay owned and intact.
        // See the trait method's documentation for why this is not apply.
        let patch = serde_json::json!({ "spec": { "replicas": 0 } });
        api.patch(name, &PatchParams::default(), &Patch::Merge(&patch))
            .await
            .map_err(|error| bounded_api_failure("scaling the suspended workload", &error))?;
        Ok(())
    }

    async fn get_service(
        &self,
        _namespace: &str,
        name: &str,
    ) -> Result<Option<serde_json::Value>, ApiFailure> {
        match self.services.get_opt(name).await {
            Ok(Some(object)) => to_value(&object),
            Ok(None) => Ok(None),
            Err(error) => Err(bounded_api_failure("reading the service", &error)),
        }
    }

    async fn delete_workload(
        &self,
        _namespace: &str,
        kind: &str,
        name: &str,
    ) -> Result<(), ApiFailure> {
        let Some(api) = self.workloads.get(kind) else {
            return Err(ApiFailure(format!("unsupported workload kind {kind}")));
        };
        api.delete(name, &DeleteParams::default())
            .await
            .map_err(|error| bounded_api_failure("deleting the stale workload", &error))?;
        Ok(())
    }

    async fn delete_service(&self, _namespace: &str, name: &str) -> Result<(), ApiFailure> {
        self.services
            .delete(name, &DeleteParams::default())
            .await
            .map_err(|error| bounded_api_failure("deleting the stale service", &error))?;
        Ok(())
    }

    async fn patch_status(
        &self,
        _namespace: &str,
        name: &str,
        patch: serde_json::Value,
    ) -> Result<(), ApiFailure> {
        let params = PatchParams::apply(crate::FIELD_MANAGER);
        self.gateways
            .patch_status(name, &params, &Patch::Apply(&patch))
            .await
            .map_err(|error| bounded_api_failure("writing the gateway status", &error))?;
        Ok(())
    }
}

async fn apply(
    api: &Api<DynamicObject>,
    manifest: serde_json::Value,
    field_manager: &str,
) -> Result<(), ApiFailure> {
    let name = manifest["metadata"]["name"]
        .as_str()
        .ok_or_else(|| ApiFailure("the manifest names no object".into()))?
        .to_owned();
    let params = PatchParams::apply(field_manager);
    api.patch(&name, &params, &Patch::Apply(&manifest))
        .await
        .map_err(|error| bounded_api_failure("applying the object", &error))?;
    Ok(())
}

fn to_value(object: &DynamicObject) -> Result<Option<serde_json::Value>, ApiFailure> {
    serde_json::to_value(object)
        .map(Some)
        .map_err(|error| ApiFailure(format!("the live object could not be encoded: {error}")))
}

/// A bounded failure message: kube errors can quote object bodies, so only
/// the error's own chain summary travels.
fn bounded_api_failure(context: &str, error: &kube::Error) -> ApiFailure {
    ApiFailure(crate::bounded(format!("{context}: {error}")))
}

/// List the gateway names in the namespace, for the resync pass.
///
/// # Errors
///
/// The API call failed.
pub async fn list_gateway_names(api: &Api<DynamicObject>) -> Result<Vec<String>, ApiFailure> {
    let list = api
        .list(&ListParams::default())
        .await
        .map_err(|error| bounded_api_failure("listing gateways", &error))?;
    Ok(list
        .items
        .iter()
        .filter_map(|object| object.metadata.name.clone())
        .collect())
}
