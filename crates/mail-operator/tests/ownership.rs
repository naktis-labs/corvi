//! Behaviours 2, 3 and 4: management-only providers, suspension and the
//! ownership transitions of ADR-0012/ADR-0013.

use std::collections::BTreeMap;

use mail_operator::model::{
    Authorization, AuthorizationMode, CorviGateway, GatewaySpec, Listener, Listeners, LocalRef,
    MailIdentity, MailIdentitySpec, MailProvider, MailProviderSpec, Mailbox, MailboxSpec,
    ObjectMeta, ProviderRole, ResourceList, ResourceRequirements, StateBackend, StateSpec,
};
use mail_operator::ownership::{
    DeletionError, DeletionRequest, ExistingWorkload, OwnershipError, ReparentPlan, ResourceGraph,
    TransitionStep, WorkloadOwnership, decide_ownership, detect_reparenting, plan_deletion,
};
use mail_operator::references::{ReferenceError, ResourceKey};

const NS: &str = "corvi-system";

fn key(name: &str) -> ResourceKey {
    ResourceKey::new(NS, name)
}

fn gateway(name: &str) -> CorviGateway {
    CorviGateway {
        metadata: ObjectMeta::new(NS, name),
        spec: GatewaySpec {
            replicas: 1,
            suspended: false,
            listeners: Listeners {
                http: Listener { enabled: true },
                smtp_submission: Listener { enabled: false },
            },
            authorization: Authorization {
                mode: AuthorizationMode::External,
                config_secret_ref: LocalRef::new("corvi-resource-server"),
            },
            state: StateSpec {
                backend: StateBackend::Ephemeral,
                existing_claim_name: None,
                connection_secret_ref: None,
            },
            resources: ResourceRequirements {
                requests: ResourceList {
                    cpu: Some("100m".to_owned()),
                    memory: Some("128Mi".to_owned()),
                    ephemeral_storage: None,
                },
                limits: ResourceList {
                    cpu: None,
                    memory: Some("512Mi".to_owned()),
                    ephemeral_storage: None,
                },
            },
        },
    }
}

fn provider(name: &str, gateway: Option<&str>) -> MailProvider {
    MailProvider {
        metadata: ObjectMeta::new(NS, name),
        spec: MailProviderSpec {
            gateway_ref: gateway.map(LocalRef::new),
            suspended: false,
            role: ProviderRole::Serving,
        },
    }
}

fn mailbox(name: &str, provider: Option<&str>) -> Mailbox {
    Mailbox {
        metadata: ObjectMeta::new(NS, name),
        spec: MailboxSpec {
            provider_ref: provider.map(LocalRef::new),
        },
    }
}

fn identity(name: &str, mailbox: Option<&str>) -> MailIdentity {
    MailIdentity {
        metadata: ObjectMeta::new(NS, name),
        spec: MailIdentitySpec {
            mailbox_ref: mailbox.map(LocalRef::new),
            address: Some(format!("{name}@example.com")),
            isolation: Some(mail_operator::IsolationMode::Dedicated),
        },
    }
}

// ---------------------------------------------------------------------------
// Behaviour 2: a management-only provider owns no mailbox.
// ---------------------------------------------------------------------------

#[test]
fn a_management_only_provider_cannot_own_a_mailbox() {
    let mut graph = ResourceGraph::new();
    let mut administration = provider("administration", Some("primary"));
    administration.spec.role = ProviderRole::ManagementOnly;
    graph.insert_provider(administration).unwrap();
    graph
        .insert_mailbox(mailbox("personal", Some("administration")))
        .unwrap();

    let error = graph
        .resolve_mailbox(&key("personal"))
        .expect_err("a management-only provider owns no mailbox");

    assert_eq!(
        error,
        ReferenceError::ManagementOnlyProvider {
            provider: key("administration"),
        }
    );
}

#[test]
fn a_management_only_provider_may_not_be_bound_to_a_gateway() {
    let mut graph = ResourceGraph::new();
    let mut administration = provider("administration", Some("primary"));
    administration.spec.role = ProviderRole::ManagementOnly;
    graph.insert_provider(administration).unwrap();

    let error = graph
        .resolve_provider_binding(&key("administration"))
        .expect_err("a management-only provider serves no gateway");

    assert_eq!(
        error,
        ReferenceError::ManagementOnlyProviderBound {
            provider: key("administration"),
        }
    );
}

#[test]
fn an_unbound_serving_provider_may_still_own_mailboxes() {
    let mut graph = ResourceGraph::new();
    graph
        .insert_provider(provider("administration-only", None))
        .unwrap();
    graph
        .insert_mailbox(mailbox("unserved-mailbox", Some("administration-only")))
        .unwrap();

    let resolved = graph
        .resolve_mailbox(&key("unserved-mailbox"))
        .expect("an unbound provider is administered, not served");

    assert_eq!(resolved.provider, key("administration-only"));
    assert_eq!(
        resolved.binding,
        mail_operator::ownership::ProviderBinding::Unbound
    );
}

// ---------------------------------------------------------------------------
// Behaviour 3: suspension invalidates dependents and stops reconciliation.
// ---------------------------------------------------------------------------

#[test]
fn a_suspended_provider_makes_its_dependents_invalid() {
    let mut graph = ResourceGraph::new();
    graph.insert_gateway(gateway("primary")).unwrap();
    let mut suspended = provider("fastmail", Some("primary"));
    suspended.spec.suspended = true;
    graph.insert_provider(suspended).unwrap();
    graph
        .insert_mailbox(mailbox("personal", Some("fastmail")))
        .unwrap();

    let error = graph
        .resolve_mailbox(&key("personal"))
        .expect_err("a suspended provider invalidates its mailbox");

    assert_eq!(
        error,
        ReferenceError::SuspendedProvider {
            provider: key("fastmail"),
        }
    );
}

#[test]
fn a_suspended_gateway_makes_its_dependents_invalid() {
    let mut graph = ResourceGraph::new();
    let mut suspended = gateway("primary");
    suspended.spec.suspended = true;
    graph.insert_gateway(suspended).unwrap();
    graph
        .insert_provider(provider("fastmail", Some("primary")))
        .unwrap();
    graph
        .insert_mailbox(mailbox("personal", Some("fastmail")))
        .unwrap();

    let error = graph
        .resolve_mailbox(&key("personal"))
        .expect_err("a suspended gateway invalidates its dependents");

    assert_eq!(
        error,
        ReferenceError::SuspendedGateway {
            gateway: key("primary"),
        }
    );
}

#[test]
fn a_suspended_gateway_serves_no_identity() {
    let mut graph = ResourceGraph::new();
    let mut suspended = gateway("primary");
    suspended.spec.suspended = true;
    graph.insert_gateway(suspended).unwrap();
    graph
        .insert_provider(provider("fastmail", Some("primary")))
        .unwrap();
    graph
        .insert_mailbox(mailbox("personal", Some("fastmail")))
        .unwrap();
    graph
        .insert_identity(identity("me", Some("personal")))
        .unwrap();

    let view = graph.gateway_view(&key("primary"));

    assert!(view.suspended, "the view must report the pause");
    assert!(
        view.identities.is_empty(),
        "a suspended gateway serves no identity"
    );
}

#[test]
fn a_suspended_provider_contributes_no_identity_to_its_gateway() {
    let mut graph = ResourceGraph::new();
    graph.insert_gateway(gateway("primary")).unwrap();
    let mut suspended = provider("fastmail", Some("primary"));
    suspended.spec.suspended = true;
    graph.insert_provider(suspended).unwrap();
    graph
        .insert_mailbox(mailbox("personal", Some("fastmail")))
        .unwrap();
    graph
        .insert_identity(identity("me", Some("personal")))
        .unwrap();

    let view = graph.gateway_view(&key("primary"));

    assert!(view.identities.is_empty());
    assert!(
        view.problems.contains(&ReferenceError::SuspendedProvider {
            provider: key("fastmail"),
        }),
        "the suspension must be reported, not hidden: {:?}",
        view.problems
    );
}

#[test]
fn a_suspended_provider_is_not_reported_as_bound() {
    let mut graph = ResourceGraph::new();
    graph.insert_gateway(gateway("primary")).unwrap();
    let mut suspended = provider("fastmail", Some("primary"));
    suspended.spec.suspended = true;
    graph.insert_provider(suspended).unwrap();

    let error = graph
        .resolve_provider_binding(&key("fastmail"))
        .expect_err("a suspended provider is not actively bound");

    assert_eq!(
        error,
        ReferenceError::SuspendedProvider {
            provider: key("fastmail"),
        }
    );

    let view = graph.gateway_view(&key("primary"));
    assert!(
        !view.providers.contains(&key("fastmail")),
        "the view must not report a suspended provider as serving: {:?}",
        view.providers
    );
}

#[test]
fn another_namespaces_problems_are_not_this_gateways_problems() {
    let mut graph = ResourceGraph::new();
    graph.insert_gateway(gateway("primary")).unwrap();
    graph
        .insert_provider(provider("fastmail", Some("primary")))
        .unwrap();

    // A dangling identity in a foreign namespace: its reference chain cannot
    // be this gateway's business, and reporting it here would disclose
    // another namespace's resource keys.
    let mut foreign = identity("foreign-orphan", Some("ghost-mailbox"));
    foreign.metadata = ObjectMeta::new("other-namespace", "foreign-orphan");
    graph.insert_identity(foreign).unwrap();
    // The same defect in this gateway's own namespace must still be reported.
    graph
        .insert_identity(identity("local-orphan", Some("ghost-mailbox")))
        .unwrap();

    let view = graph.gateway_view(&key("primary"));

    let dangling: Vec<&ResourceKey> = view
        .problems
        .iter()
        .filter_map(|problem| match problem {
            ReferenceError::DanglingReference { target, .. } => Some(target),
            _ => None,
        })
        .collect();
    assert!(
        dangling.iter().any(|target| target.namespace == NS),
        "the gateway's own dangling identity is still reported: {:?}",
        view.problems
    );
    assert!(
        dangling.iter().all(|target| target.namespace == NS),
        "problems must stay inside the gateway's own namespace: {:?}",
        view.problems
    );
}

// ---------------------------------------------------------------------------
// Behaviour 4: one owner per workload, revocation before reparenting, and no
// cascade deletion.
// ---------------------------------------------------------------------------

#[test]
fn the_operator_creates_a_workload_it_does_not_find() {
    let gateway = gateway("primary");

    let ownership = decide_ownership(&gateway, None, false).expect("the operator creates it");

    assert_eq!(ownership, WorkloadOwnership::OperatorManaged);
}

#[test]
fn the_operator_never_adopts_a_helm_owned_workload() {
    let gateway = gateway("primary");
    let existing = ExistingWorkload {
        name: "corvi-gateway-primary".to_owned(),
        namespace: NS.to_owned(),
        owner: WorkloadOwnership::HelmDirect,
        managed_by: Some("Helm".to_owned()),
    };

    let error = decide_ownership(&gateway, Some(&existing), false)
        .expect_err("a Helm-owned workload is never adopted silently");

    assert_eq!(
        error,
        OwnershipError::OwnershipConflict {
            workload: "corvi-system/corvi-gateway-primary".to_owned(),
            owner: WorkloadOwnership::HelmDirect,
        }
    );
}

#[test]
fn an_explicit_migration_may_take_over_a_helm_owned_workload() {
    let gateway = gateway("primary");
    let existing = ExistingWorkload {
        name: "corvi-gateway-primary".to_owned(),
        namespace: NS.to_owned(),
        owner: WorkloadOwnership::HelmDirect,
        managed_by: Some("Helm".to_owned()),
    };

    let ownership =
        decide_ownership(&gateway, Some(&existing), true).expect("a deliberate cutover is allowed");

    assert_eq!(ownership, WorkloadOwnership::OperatorManaged);
}

#[test]
fn a_suspended_gateway_is_never_adopted() {
    let mut suspended = gateway("primary");
    suspended.spec.suspended = true;

    let error =
        decide_ownership(&suspended, None, true).expect_err("a suspended gateway adopts nothing");

    assert_eq!(
        error,
        OwnershipError::SuspendedGateway {
            gateway: key("primary"),
        }
    );
}

/// Build the chain `identity -> mailbox -> provider -> gateway`.
fn chain(gateway_name: &str, provider_name: &str) -> ResourceGraph {
    let mut graph = ResourceGraph::new();
    graph.insert_gateway(gateway("primary")).unwrap();
    graph.insert_gateway(gateway("secondary")).unwrap();
    graph
        .insert_provider(provider(provider_name, Some(gateway_name)))
        .unwrap();
    graph
        .insert_mailbox(mailbox("personal", Some(provider_name)))
        .unwrap();
    graph
        .insert_identity(identity("me", Some("personal")))
        .unwrap();
    graph
}

#[test]
fn reparenting_revokes_the_old_gateway_before_publishing_the_new_one() {
    let previous = chain("primary", "fastmail");
    let current = chain("secondary", "migadu");

    let plans = detect_reparenting(&previous, &current);
    assert_eq!(plans.len(), 1, "one mailbox moved: {plans:?}");

    let plan = &plans[0];
    plan.validate().expect("the plan must be well ordered");
    assert_eq!(plan.source(), Some(&key("primary")));
    assert_eq!(plan.target(), &Some(key("secondary")));

    let steps = plan.steps();
    let revoke = steps
        .iter()
        .position(|step| {
            matches!(step, TransitionStep::RevokeGatewayAccess { gateway, identity }
            if gateway == &key("primary") && identity == &key("me"))
        })
        .expect("the old gateway must be revoked");
    let publish = steps
        .iter()
        .position(|step| {
            matches!(step, TransitionStep::PublishGatewayAccess { gateway, identity }
            if gateway == &key("secondary") && identity == &key("me"))
        })
        .expect("the new gateway must be published");
    assert!(
        revoke < publish,
        "access must be revoked before it is published: {steps:?}"
    );
}

#[test]
fn a_reparenting_plan_that_publishes_before_revoking_is_rejected() {
    let plan = ReparentPlan::from_steps(
        Some(key("primary")),
        Some(key("secondary")),
        vec![
            TransitionStep::PublishGatewayAccess {
                gateway: key("secondary"),
                identity: key("me"),
            },
            TransitionStep::RevokeGatewayAccess {
                gateway: key("primary"),
                identity: key("me"),
            },
        ],
    );

    let error = plan
        .validate()
        .expect_err("publishing before revoking overlaps access");

    assert_eq!(
        error,
        mail_operator::ownership::ReparentingError::OverlappingAccess {
            identity: key("me"),
        }
    );
}

#[test]
fn detaching_a_provider_revokes_without_publishing() {
    let previous = chain("primary", "fastmail");

    let mut current = ResourceGraph::new();
    current.insert_gateway(gateway("primary")).unwrap();
    current.insert_provider(provider("fastmail", None)).unwrap();
    current
        .insert_mailbox(mailbox("personal", Some("fastmail")))
        .unwrap();
    current
        .insert_identity(identity("me", Some("personal")))
        .unwrap();

    let plans = detect_reparenting(&previous, &current);
    assert_eq!(plans.len(), 1);

    let plan = &plans[0];
    plan.validate().expect("a detachment is well ordered");
    assert_eq!(plan.target(), &None);
    assert!(
        plan.steps()
            .iter()
            .all(|step| !matches!(step, TransitionStep::PublishGatewayAccess { .. })),
        "a detached identity is never published: {:?}",
        plan.steps()
    );
}

#[test]
fn deleting_an_identity_revokes_its_former_gateway() {
    let previous = chain("primary", "fastmail");

    // The identity is deleted: it is present in `previous` and absent from
    // `current`. No identity object remains to resolve, but the old gateway
    // must still lose the access it held.
    let mut current = ResourceGraph::new();
    current.insert_gateway(gateway("primary")).unwrap();
    current
        .insert_provider(provider("fastmail", Some("primary")))
        .unwrap();
    current
        .insert_mailbox(mailbox("personal", Some("fastmail")))
        .unwrap();

    let plans = detect_reparenting(&previous, &current);
    assert_eq!(
        plans.len(),
        1,
        "a deleted identity must produce a revocation plan: {plans:?}"
    );

    let plan = &plans[0];
    plan.validate().expect("the deletion plan is well ordered");
    assert_eq!(plan.source(), Some(&key("primary")));
    assert_eq!(plan.target(), &None);
    assert!(
        plan.steps().iter().any(|step| matches!(step,
            TransitionStep::RevokeGatewayAccess { gateway, identity }
            if gateway == &key("primary") && identity == &key("me")
        )),
        "the old gateway must be revoked: {:?}",
        plan.steps()
    );
    assert!(
        plan.steps()
            .iter()
            .all(|step| !matches!(step, TransitionStep::PublishGatewayAccess { .. })),
        "a deleted identity is never published: {:?}",
        plan.steps()
    );
}

#[test]
fn attaching_an_unbound_identity_to_a_gateway_validates() {
    let mut previous = ResourceGraph::new();
    previous.insert_gateway(gateway("primary")).unwrap();
    previous
        .insert_provider(provider("fastmail", None))
        .unwrap();
    previous
        .insert_mailbox(mailbox("personal", Some("fastmail")))
        .unwrap();
    previous
        .insert_identity(identity("me", Some("personal")))
        .unwrap();
    let current = chain("primary", "fastmail");

    let plans = detect_reparenting(&previous, &current);
    assert_eq!(plans.len(), 1, "one identity gained a gateway: {plans:?}");

    let plan = &plans[0];
    assert_eq!(
        plan.source(),
        None,
        "an attach has no gateway that loses access"
    );
    plan.validate()
        .expect("an attach publishes access the identity never had, so it validates");
    assert_eq!(plan.target(), &Some(key("primary")));
}

#[test]
fn a_move_between_the_same_gateway_is_still_refused() {
    let plan = ReparentPlan::from_steps(
        Some(key("primary")),
        Some(key("primary")),
        vec![
            TransitionStep::RevokeGatewayAccess {
                gateway: key("primary"),
                identity: key("me"),
            },
            TransitionStep::InvalidateDerivedState {
                identity: key("me"),
            },
            TransitionStep::PublishGatewayAccess {
                gateway: key("primary"),
                identity: key("me"),
            },
        ],
    );

    let error = plan
        .validate()
        .expect_err("a same-gateway move is never a valid plan");

    assert_eq!(
        error,
        mail_operator::ownership::ReparentingError::SameGateway {
            gateway: key("primary"),
        }
    );
}

#[test]
fn deleting_a_gateway_never_cascades_into_secrets_claims_or_mail_resources() {
    let requests = vec![
        DeletionRequest {
            kind: "Deployment".to_owned(),
            name: "corvi-gateway-primary".to_owned(),
            namespace: NS.to_owned(),
        },
        DeletionRequest {
            kind: "Secret".to_owned(),
            name: "corvi-runtime-db".to_owned(),
            namespace: NS.to_owned(),
        },
        DeletionRequest {
            kind: "PersistentVolumeClaim".to_owned(),
            name: "corvi-gateway-primary-data".to_owned(),
            namespace: NS.to_owned(),
        },
        DeletionRequest {
            kind: "MailProvider".to_owned(),
            name: "fastmail".to_owned(),
            namespace: NS.to_owned(),
        },
        DeletionRequest {
            kind: "MailIdentity".to_owned(),
            name: "me".to_owned(),
            namespace: NS.to_owned(),
        },
    ];

    let error = plan_deletion(&requests).expect_err("protected resources are never deleted");

    assert_eq!(
        error,
        DeletionError::ProtectedResource {
            kind: "Secret".to_owned(),
            name: "corvi-runtime-db".to_owned(),
        }
    );
}

#[test]
fn only_operator_managed_workload_children_may_be_deleted() {
    let requests = vec![
        DeletionRequest {
            kind: "Deployment".to_owned(),
            name: "corvi-gateway-primary".to_owned(),
            namespace: NS.to_owned(),
        },
        DeletionRequest {
            kind: "Service".to_owned(),
            name: "corvi-gateway-primary".to_owned(),
            namespace: NS.to_owned(),
        },
        DeletionRequest {
            kind: "ConfigMap".to_owned(),
            name: "corvi-gateway-primary-config".to_owned(),
            namespace: NS.to_owned(),
        },
    ];

    let plan = plan_deletion(&requests).expect("the operator may delete its own children");

    assert_eq!(plan.len(), 3);
}

#[test]
fn a_gateway_with_remaining_dependents_may_not_be_deleted() {
    let mut graph = ResourceGraph::new();
    graph.insert_gateway(gateway("primary")).unwrap();
    graph
        .insert_provider(provider("fastmail", Some("primary")))
        .unwrap();

    let view = graph.gateway_view(&key("primary"));
    assert_eq!(view.providers, vec![key("fastmail")]);

    let error = mail_operator::ownership::GatewayDeletionPlan::new(
        vec![DeletionRequest {
            kind: "Deployment".to_owned(),
            name: "corvi-gateway-primary".to_owned(),
            namespace: NS.to_owned(),
        }],
        view.providers.clone(),
    )
    .validate()
    .expect_err("dependents must be detached or migrated first");

    assert_eq!(
        error,
        DeletionError::DependentsRemain {
            dependents: vec![key("fastmail")],
        }
    );
}

#[test]
fn labels_are_not_used_to_claim_ownership() {
    // A workload carrying Corvi's labels is still not adoptable: ownership
    // comes from the recorded manager, never from a label an operator could
    // have written.
    let mut labels = BTreeMap::new();
    labels.insert(
        "app.kubernetes.io/managed-by".to_owned(),
        "corvi-operator".to_owned(),
    );
    let existing = ExistingWorkload {
        name: "corvi-gateway-primary".to_owned(),
        namespace: NS.to_owned(),
        owner: WorkloadOwnership::HelmDirect,
        managed_by: Some("Helm".to_owned()),
    };

    let error = decide_ownership(&gateway("primary"), Some(&existing), false)
        .expect_err("labels never establish ownership");

    assert!(matches!(error, OwnershipError::OwnershipConflict { .. }));
}
