//! Behaviours 5 and 6: the hardened workload profile, the independently
//! trusted policies and the SQLite replica restriction.

mod common;

use common::{gateway, gateway_with, profile};
use mail_operator::model::{AuthorizationMode, ParseError, StateBackend, parse_gateway};
use mail_operator::workload::{
    AdmissionPolicy, IpBlock, IpFamily, NetworkPolicy, NetworkPolicyEgressRule, NetworkPolicyPeer,
    NetworkPolicyPort, ObservedPolicies, PolicyExpectation, PolicySource, PolicyType, RenderError,
    VolumeSource, Workload, WorkloadViolation, render_gateway_workload, validate_network_policy,
    validate_workload,
};

fn policy_with_dns(families: &[IpFamily]) -> NetworkPolicy {
    let mut egress = Vec::new();
    for family in families {
        let cidr = match family {
            IpFamily::V4 => "192.0.2.53/32",
            IpFamily::V6 => "2001:db8::53/128",
        };
        egress.push(NetworkPolicyEgressRule {
            to: vec![NetworkPolicyPeer {
                ip_block: Some(IpBlock {
                    cidr: cidr.to_owned(),
                    except: Vec::new(),
                }),
                pod_selector: None,
                namespace_selector: None,
            }],
            ports: vec![
                NetworkPolicyPort {
                    protocol: "UDP".to_owned(),
                    port: Some(53),
                },
                NetworkPolicyPort {
                    protocol: "TCP".to_owned(),
                    port: Some(53),
                },
            ],
        });
    }
    NetworkPolicy {
        api_version: "networking.k8s.io/v1".to_owned(),
        kind: "NetworkPolicy".to_owned(),
        source: PolicySource::IndependentlyInstalled,
        metadata: mail_operator::workload::PolicyMetadata {
            name: "corvi-gateway-default-deny".to_owned(),
            namespace: common::NS.to_owned(),
            annotations: Default::default(),
        },
        spec: mail_operator::workload::NetworkPolicySpec {
            pod_selector: mail_operator::workload::LabelSelector {
                match_labels: [(
                    "app.kubernetes.io/name".to_owned(),
                    "corvi-gateway".to_owned(),
                )]
                .into_iter()
                .collect(),
            },
            policy_types: vec![PolicyType::Ingress, PolicyType::Egress],
            ingress: Vec::new(),
            egress,
        },
    }
}

#[test]
fn a_rendered_gateway_workload_is_rootless_and_read_only() {
    let workload = render_gateway_workload(&gateway(), &profile()).expect("the gateway renders");

    assert_eq!(workload.kind(), "Deployment");
    let pod = workload.pod_spec();
    assert!(pod.security_context.run_as_non_root);
    assert_eq!(pod.security_context.run_as_user, 65532);
    assert_eq!(pod.security_context.run_as_group, 65532);
    assert_eq!(pod.security_context.seccomp_profile.kind, "RuntimeDefault");
    assert!(!pod.host_network);
    assert!(!pod.host_pid);
    assert!(!pod.host_ipc);

    let container = &pod.containers[0];
    assert!(container.security_context.run_as_non_root);
    assert!(!container.security_context.privileged);
    assert!(!container.security_context.allow_privilege_escalation);
    assert!(container.security_context.read_only_root_filesystem);
    assert_eq!(container.security_context.capabilities.drop, vec!["ALL"]);
    assert!(
        container.security_context.capabilities.add.is_empty(),
        "no capability may be added"
    );
    assert_eq!(
        container.security_context.seccomp_profile.kind,
        "RuntimeDefault"
    );
}

#[test]
fn a_rendered_gateway_workload_mounts_no_service_account_token() {
    let workload = render_gateway_workload(&gateway(), &profile()).expect("the gateway renders");

    let pod = workload.pod_spec();
    assert!(!pod.automount_service_account_token);
    assert!(!pod.enable_service_links);
    assert_eq!(pod.service_account_name, "corvi-gateway");
    assert_ne!(
        pod.service_account_name, "corvi-operator",
        "the gateway must not use the operator's service account"
    );
}

#[test]
fn the_operator_and_the_gateway_may_not_share_a_service_account() {
    let mut profile = profile();
    profile.gateway_service_account = "corvi-operator".to_owned();

    let error = render_gateway_workload(&gateway(), &profile)
        .expect_err("the operator's service account is not the gateway's");

    assert_eq!(
        error,
        RenderError::ServiceAccountIsolation {
            service_account: "corvi-operator".to_owned(),
        }
    );
}

#[test]
fn a_workload_that_adds_a_capability_is_rejected() {
    let mut workload =
        render_gateway_workload(&gateway(), &profile()).expect("the gateway renders");
    workload.pod_spec_mut().containers[0]
        .security_context
        .capabilities
        .add
        .push("NET_BIND_SERVICE".to_owned());

    let error =
        validate_workload(&workload, &profile()).expect_err("added capabilities are refused");

    assert_eq!(
        error,
        WorkloadViolation::AddedCapability {
            container: "gateway".to_owned(),
            capability: "NET_BIND_SERVICE".to_owned(),
        }
    );
}

#[test]
fn a_workload_that_runs_as_root_is_rejected() {
    let mut workload =
        render_gateway_workload(&gateway(), &profile()).expect("the gateway renders");
    workload.pod_spec_mut().containers[0]
        .security_context
        .run_as_user = 0;
    workload.pod_spec_mut().containers[0]
        .security_context
        .run_as_non_root = false;

    let error = validate_workload(&workload, &profile()).expect_err("root is refused");

    assert_eq!(
        error,
        WorkloadViolation::RootUser {
            container: "gateway".to_owned(),
        }
    );
}

#[test]
fn a_workload_with_a_mutable_root_filesystem_is_rejected() {
    let mut workload =
        render_gateway_workload(&gateway(), &profile()).expect("the gateway renders");
    workload.pod_spec_mut().containers[0]
        .security_context
        .read_only_root_filesystem = false;

    let error = validate_workload(&workload, &profile()).expect_err("a writable root is refused");

    assert_eq!(
        error,
        WorkloadViolation::MutableRootFilesystem {
            container: "gateway".to_owned(),
        }
    );
}

#[test]
fn a_workload_without_a_seccomp_profile_is_rejected() {
    let mut workload =
        render_gateway_workload(&gateway(), &profile()).expect("the gateway renders");
    workload.pod_spec_mut().containers[0]
        .security_context
        .seccomp_profile
        .kind = "Unconfined".to_owned();

    let error =
        validate_workload(&workload, &profile()).expect_err("an unconfined workload is refused");

    assert_eq!(
        error,
        WorkloadViolation::MissingSeccomp {
            container: "gateway".to_owned(),
        }
    );
}

#[test]
fn a_workload_that_mounts_the_default_token_is_rejected() {
    let mut workload =
        render_gateway_workload(&gateway(), &profile()).expect("the gateway renders");
    workload.pod_spec_mut().automount_service_account_token = true;

    let error = validate_workload(&workload, &profile()).expect_err("a mounted token is refused");

    assert_eq!(error, WorkloadViolation::ServiceAccountTokenMounted);
}

#[test]
fn a_gateway_may_not_smuggle_a_podspec_into_its_resource() {
    let document = r#"
apiVersion: corvi.naktis.eu/v1alpha1
kind: CorviGateway
metadata:
  name: primary
  namespace: corvi-system
spec:
  replicas: 1
  template:
    spec:
      containers:
        - name: backdoor
          image: evil:latest
"#;

    let error = parse_gateway(document).expect_err("a PodSpec may not be injected");

    match error {
        ParseError::PodSpecInjection { path } => {
            assert!(
                path.contains("template"),
                "the path must name the field: {path}"
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn a_sqlite_gateway_is_limited_to_one_replica() {
    let gateway = gateway_with(2, StateBackend::Sqlite, AuthorizationMode::External);

    let error = render_gateway_workload(&gateway, &profile())
        .expect_err("SQLite cannot be scaled beyond one writer");

    assert_eq!(error, RenderError::SqliteReplicaLimit { replicas: 2 });
}

#[test]
fn a_sqlite_gateway_renders_a_single_writer_stateful_set() {
    let gateway = gateway_with(1, StateBackend::Sqlite, AuthorizationMode::External);

    let workload = render_gateway_workload(&gateway, &profile()).expect("the gateway renders");

    assert_eq!(workload.kind(), "StatefulSet");
    assert_eq!(workload.pod_spec().containers[0].ports.len(), 2);
}

#[test]
fn an_embedded_issuer_requires_durable_state() {
    let gateway = gateway_with(1, StateBackend::Ephemeral, AuthorizationMode::Embedded);

    let error = render_gateway_workload(&gateway, &profile())
        .expect_err("an embedded issuer needs durable state");

    assert_eq!(error, RenderError::EphemeralEmbeddedIssuer);
}

#[test]
fn an_operator_derived_admission_policy_is_not_trusted() {
    let expected = PolicyExpectation {
        name: "corvi-restricted-workload".to_owned(),
        kind: mail_operator::workload::PolicyKind::Admission,
        source: PolicySource::IndependentlyInstalled,
    };
    let observed = ObservedPolicies {
        admission: Some(AdmissionPolicy {
            name: "corvi-restricted-workload".to_owned(),
            namespace: common::NS.to_owned(),
            source: PolicySource::OperatorDerived,
        }),
        network: vec![policy_with_dns(&[IpFamily::V4, IpFamily::V6])],
    };

    let error = mail_operator::workload::check_policy_trust(&expected, &observed, common::NS)
        .expect_err("the operator's own policy is not a boundary");

    assert_eq!(
        error,
        WorkloadViolation::AdmissionPolicyNotIndependent {
            name: "corvi-restricted-workload".to_owned(),
        }
    );
}

#[test]
fn a_missing_network_policy_is_reported_and_never_replaced() {
    let expected = PolicyExpectation {
        name: "corvi-gateway-default-deny".to_owned(),
        kind: mail_operator::workload::PolicyKind::Network,
        source: PolicySource::IndependentlyInstalled,
    };
    let observed = ObservedPolicies {
        admission: Some(AdmissionPolicy {
            name: "corvi-restricted-workload".to_owned(),
            namespace: common::NS.to_owned(),
            source: PolicySource::IndependentlyInstalled,
        }),
        network: Vec::new(),
    };

    let error = mail_operator::workload::check_policy_trust(&expected, &observed, common::NS)
        .expect_err("a missing default-deny policy is reported");

    assert_eq!(
        error,
        WorkloadViolation::NetworkPolicyNotIndependent {
            name: "corvi-gateway-default-deny".to_owned(),
        }
    );
}

#[test]
fn the_network_policy_must_address_both_ipv4_and_ipv6() {
    let policy = policy_with_dns(&[IpFamily::V4]);

    let error = validate_network_policy(&policy).expect_err("a single-stack policy is refused");

    assert_eq!(
        error,
        WorkloadViolation::MissingAddressFamily {
            family: IpFamily::V6,
        }
    );
}

#[test]
fn a_dual_stack_network_policy_is_accepted() {
    let policy = policy_with_dns(&[IpFamily::V4, IpFamily::V6]);

    validate_network_policy(&policy).expect("a dual-stack policy is accepted");
}

#[test]
fn the_network_policy_must_not_allow_unrestricted_egress() {
    let mut policy = policy_with_dns(&[IpFamily::V4, IpFamily::V6]);
    policy.spec.egress[0].to[0].ip_block = Some(IpBlock {
        cidr: "0.0.0.0/0".to_owned(),
        except: Vec::new(),
    });

    let error = validate_network_policy(&policy).expect_err("unrestricted egress is refused");

    assert_eq!(
        error,
        WorkloadViolation::UnrestrictedEgress {
            cidr: "0.0.0.0/0".to_owned(),
        }
    );
}

#[test]
fn a_rendered_workload_passes_its_own_validation() {
    let workload = render_gateway_workload(&gateway(), &profile()).expect("the gateway renders");

    validate_workload(&workload, &profile()).expect("the rendered workload is hardened");
}

#[test]
fn a_same_named_policy_in_another_namespace_is_not_trusted() {
    let expected = PolicyExpectation {
        name: "corvi-gateway-default-deny".to_owned(),
        kind: mail_operator::workload::PolicyKind::Network,
        source: PolicySource::IndependentlyInstalled,
    };
    let mut policy = policy_with_dns(&[IpFamily::V4, IpFamily::V6]);
    policy.metadata.namespace = "somewhere-else".to_owned();
    let observed = ObservedPolicies {
        admission: None,
        network: vec![policy],
    };

    let error = mail_operator::workload::check_policy_trust(&expected, &observed, common::NS)
        .expect_err("a same-named policy in another namespace enforces nothing here");

    assert_eq!(
        error,
        WorkloadViolation::NetworkPolicyNotIndependent {
            name: "corvi-gateway-default-deny".to_owned(),
        }
    );
}

#[test]
fn a_same_named_admission_policy_in_another_namespace_is_not_trusted() {
    let expected = PolicyExpectation {
        name: "corvi-restricted-workload".to_owned(),
        kind: mail_operator::workload::PolicyKind::Admission,
        source: PolicySource::IndependentlyInstalled,
    };
    let observed = ObservedPolicies {
        admission: Some(AdmissionPolicy {
            name: "corvi-restricted-workload".to_owned(),
            namespace: "somewhere-else".to_owned(),
            source: PolicySource::IndependentlyInstalled,
        }),
        network: Vec::new(),
    };

    let error = mail_operator::workload::check_policy_trust(&expected, &observed, common::NS)
        .expect_err("a same-named admission policy in another namespace is not a boundary");

    assert_eq!(
        error,
        WorkloadViolation::AdmissionPolicyNotIndependent {
            name: "corvi-restricted-workload".to_owned(),
        }
    );
}

#[test]
fn a_policy_in_the_workloads_namespace_is_trusted() {
    let expected = PolicyExpectation {
        name: "corvi-gateway-default-deny".to_owned(),
        kind: mail_operator::workload::PolicyKind::Network,
        source: PolicySource::IndependentlyInstalled,
    };
    let observed = ObservedPolicies {
        admission: Some(AdmissionPolicy {
            name: "corvi-restricted-workload".to_owned(),
            namespace: common::NS.to_owned(),
            source: PolicySource::IndependentlyInstalled,
        }),
        network: vec![policy_with_dns(&[IpFamily::V4, IpFamily::V6])],
    };

    mail_operator::workload::check_policy_trust(&expected, &observed, common::NS)
        .expect("a policy in the workload's namespace satisfies the expectation");
}

#[test]
fn a_sqlite_gateway_mounts_its_state_volume_at_a_durable_path() {
    let gateway = gateway_with(1, StateBackend::Sqlite, AuthorizationMode::External);

    let workload = render_gateway_workload(&gateway, &profile()).expect("the gateway renders");

    let pod = workload.pod_spec();
    let mounts = &pod.containers[0].volume_mounts;
    for volume in &pod.volumes {
        assert!(
            mounts.iter().any(|mount| mount.name == volume.name),
            "volume {} is declared but never mounted: {mounts:?}",
            volume.name
        );
    }
    let state = mounts
        .iter()
        .find(|mount| mount.name == "state")
        .expect("the SQLite gateway mounts its state volume");
    assert_eq!(
        state.mount_path, "/var/lib/corvi",
        "SQLite state needs a dedicated durable path, not the read-only root or /tmp"
    );
    assert!(!state.read_only, "SQLite state must be writable");
}

#[test]
fn the_authorization_secret_is_rendered_as_a_mounted_volume() {
    let workload = render_gateway_workload(&gateway(), &profile()).expect("the gateway renders");

    let pod = workload.pod_spec();
    let volume = pod
        .volumes
        .iter()
        .find(|volume| volume.name == "auth")
        .expect("the authorization secret is rendered as a volume");
    match &volume.source {
        VolumeSource::Secret { secret_name, .. } => {
            assert_eq!(secret_name, "corvi-resource-server");
        }
        other => panic!("unexpected volume source {other:?}"),
    }

    let mount = pod.containers[0]
        .volume_mounts
        .iter()
        .find(|mount| mount.name == "auth")
        .expect("the authorization secret is mounted");
    assert!(mount.read_only, "a secret is never mounted writable");
}

#[test]
fn the_rendered_workload_names_the_gateway_deterministically() {
    let workload = render_gateway_workload(&gateway(), &profile()).expect("the gateway renders");

    assert_eq!(workload.name(), "corvi-gateway-primary");
    assert_eq!(workload.namespace(), common::NS);
    match &workload {
        Workload::Deployment(deployment) => {
            assert_eq!(deployment.api_version, "apps/v1");
            assert_eq!(deployment.kind, "Deployment");
        }
        Workload::StatefulSet(stateful_set) => {
            assert_eq!(stateful_set.api_version, "apps/v1");
            assert_eq!(stateful_set.kind, "StatefulSet");
        }
    }
}

#[test]
fn serialized_pod_uses_kubernetes_security_field_names() {
    let workload = render_gateway_workload(&gateway(), &profile()).unwrap();
    let yaml: serde_yaml::Value = serde_yaml::from_str(&workload.to_yaml()).unwrap();
    let pod = &yaml["spec"]["template"]["spec"];
    assert_eq!(pod["hostPID"].as_bool(), Some(false));
    assert_eq!(pod["hostIPC"].as_bool(), Some(false));
    assert!(pod.get("hostPid").is_none());
    assert!(pod.get("hostIpc").is_none());
    for security in [
        &pod["securityContext"],
        &pod["containers"][0]["securityContext"],
    ] {
        assert_eq!(
            security["seccompProfile"]["type"].as_str(),
            Some("RuntimeDefault")
        );
        assert!(security["seccompProfile"].get("kind").is_none());
    }
}

#[test]
fn sqlite_gateway_selectors_match_only_their_own_templates() {
    let first = gateway_with(1, StateBackend::Sqlite, AuthorizationMode::External);
    let mut second = first.clone();
    second.metadata.name = "secondary".to_owned();
    let first = render_gateway_workload(&first, &profile()).unwrap();
    let second = render_gateway_workload(&second, &profile()).unwrap();
    let (Workload::StatefulSet(first), Workload::StatefulSet(second)) = (first, second) else {
        panic!("expected StatefulSets")
    };
    let matches = |selector: &mail_operator::workload::LabelSelector,
                   labels: &std::collections::BTreeMap<String, String>| {
        selector
            .match_labels
            .iter()
            .all(|(key, value)| labels.get(key) == Some(value))
    };
    assert!(matches(
        &first.spec.selector,
        &first.spec.template.metadata.labels
    ));
    assert!(matches(
        &second.spec.selector,
        &second.spec.template.metadata.labels
    ));
    assert!(!matches(
        &first.spec.selector,
        &second.spec.template.metadata.labels
    ));
    assert!(!matches(
        &second.spec.selector,
        &first.spec.template.metadata.labels
    ));
}

#[test]
fn rendered_rollout_strategies_use_kubernetes_type_field() {
    for (gateway, field) in [
        (gateway(), "strategy"),
        (
            gateway_with(1, StateBackend::Sqlite, AuthorizationMode::External),
            "updateStrategy",
        ),
    ] {
        let workload = render_gateway_workload(&gateway, &profile()).unwrap();
        let yaml: serde_yaml::Value = serde_yaml::from_str(&workload.to_yaml()).unwrap();
        let strategy = &yaml["spec"][field];
        assert_eq!(strategy["type"].as_str(), Some("RollingUpdate"), "{field}");
        assert!(strategy.get("kind").is_none(), "{field}");
    }
}
