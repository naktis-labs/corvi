//! Behaviour 7: operator and API outage, last-known-good snapshots and
//! recovery after an interrupted watch.

mod common;

use common::key;
use mail_operator::IsolationMode;
use mail_operator::retention::{
    ControlPlaneAvailability, PublishError, ReconcileOutcome, ResumeAction, RevocationOutcome,
    SnapshotBuilder, SnapshotIdentity, SnapshotRetention, WatchCursor, WatchOutcome, resume_action,
};

fn snapshot_yaml(generation: u64, identities: &[(&str, &str)]) -> String {
    let builder = SnapshotBuilder {
        gateway: key("primary"),
        generation,
        identities: identities
            .iter()
            .map(|(id, mailbox)| SnapshotIdentity {
                id: (*id).to_owned(),
                mailbox: (*mailbox).to_owned(),
                address: format!("{id}@example.com"),
                isolation: IsolationMode::Dedicated,
            })
            .collect(),
        ..SnapshotBuilder::default()
    };
    builder.to_yaml()
}

#[test]
fn a_valid_candidate_becomes_the_last_known_good_snapshot() {
    let mut retention = SnapshotRetention::new();

    let outcome = retention
        .publish(
            &key("primary"),
            &snapshot_yaml(1, &[("me", "personal")]),
            None,
            10,
        )
        .expect("a valid snapshot is published");

    assert_eq!(outcome, ReconcileOutcome::Published { generation: 1 });
    let active = retention
        .active(&key("primary"))
        .expect("the published snapshot is retained");
    assert_eq!(active.generation(), 1);
    assert_eq!(active.identities().len(), 1);
}

#[test]
fn an_invalid_candidate_keeps_the_last_known_good_snapshot() {
    let mut retention = SnapshotRetention::new();
    retention
        .publish(
            &key("primary"),
            &snapshot_yaml(1, &[("me", "personal")]),
            None,
            10,
        )
        .expect("a valid snapshot is published");

    let error = retention
        .publish(&key("primary"), "generation: 0\n", None, 20)
        .expect_err("an invalid candidate is refused");

    assert!(matches!(error, PublishError::InvalidCandidate { .. }));
    let active = retention
        .active(&key("primary"))
        .expect("the last known good snapshot is retained");
    assert_eq!(active.generation(), 1);
    assert_eq!(active.identities().len(), 1);
}

#[test]
fn an_api_outage_keeps_the_last_known_good_snapshot() {
    let mut retention = SnapshotRetention::new();
    retention
        .publish(
            &key("primary"),
            &snapshot_yaml(1, &[("me", "personal")]),
            None,
            10,
        )
        .expect("a valid snapshot is published");

    let outcome = retention
        .reconcile(
            &key("primary"),
            ControlPlaneAvailability::ApiUnavailable,
            Some(&snapshot_yaml(2, &[("me", "personal")])),
            None,
            20,
        )
        .expect("an outage is not an error");

    assert_eq!(
        outcome,
        ReconcileOutcome::Retained {
            generation: Some(1),
            reason: mail_operator::retention::RetentionReason::ApiUnavailable,
        }
    );
    let active = retention
        .active(&key("primary"))
        .expect("the last known good snapshot is retained");
    assert_eq!(active.generation(), 1);
    assert_eq!(active.identities().len(), 1);
}

#[test]
fn an_operator_outage_keeps_the_last_known_good_snapshot() {
    let mut retention = SnapshotRetention::new();
    retention
        .publish(
            &key("primary"),
            &snapshot_yaml(1, &[("me", "personal")]),
            None,
            10,
        )
        .expect("a valid snapshot is published");

    let outcome = retention
        .reconcile(
            &key("primary"),
            ControlPlaneAvailability::OperatorUnavailable,
            None,
            None,
            20,
        )
        .expect("an outage is not an error");

    assert_eq!(
        outcome,
        ReconcileOutcome::Retained {
            generation: Some(1),
            reason: mail_operator::retention::RetentionReason::OperatorUnavailable,
        }
    );
    assert_eq!(
        retention
            .active(&key("primary"))
            .expect("the last known good snapshot is retained")
            .identities()
            .len(),
        1
    );
}

#[test]
fn an_empty_candidate_never_replaces_a_retained_snapshot() {
    let mut retention = SnapshotRetention::new();
    retention
        .publish(
            &key("primary"),
            &snapshot_yaml(1, &[("me", "personal")]),
            None,
            10,
        )
        .expect("a valid snapshot is published");

    let outcome = retention
        .reconcile(
            &key("primary"),
            ControlPlaneAvailability::Available,
            Some(""),
            None,
            20,
        )
        .expect("an empty candidate is refused, not published");

    assert_eq!(
        outcome,
        ReconcileOutcome::Retained {
            generation: Some(1),
            reason: mail_operator::retention::RetentionReason::InvalidCandidate,
        }
    );
    assert_eq!(
        retention
            .active(&key("primary"))
            .expect("the last known good snapshot is retained")
            .identities()
            .len(),
        1
    );
}

#[test]
fn an_interrupted_watch_resumes_from_its_cursor() {
    let cursor = WatchCursor {
        resource_version: Some("4711".to_owned()),
    };

    let action = resume_action(
        &cursor,
        WatchOutcome::Continue {
            resource_version: "4712".to_owned(),
        },
    );

    assert_eq!(
        action,
        ResumeAction::ContinueFrom {
            resource_version: "4712".to_owned()
        }
    );
}

#[test]
fn a_watch_that_replays_a_seen_version_forces_a_full_relist() {
    let cursor = WatchCursor {
        resource_version: Some("4711".to_owned()),
    };

    let action = resume_action(
        &cursor,
        WatchOutcome::Continue {
            resource_version: "4711".to_owned(),
        },
    );

    assert_eq!(action, ResumeAction::RelistCompletely);
}

#[test]
fn an_expired_watch_forces_a_full_relist_without_losing_state() {
    let mut retention = SnapshotRetention::new();
    retention
        .publish(
            &key("primary"),
            &snapshot_yaml(1, &[("me", "personal")]),
            None,
            10,
        )
        .expect("a valid snapshot is published");

    let cursor = WatchCursor {
        resource_version: Some("4711".to_owned()),
    };
    let action = resume_action(&cursor, WatchOutcome::Expired);
    assert_eq!(action, ResumeAction::RelistCompletely);

    // The re-list has not produced a complete graph yet, so the retained
    // configuration keeps serving.
    let outcome = retention
        .reconcile(
            &key("primary"),
            ControlPlaneAvailability::Available,
            None,
            None,
            20,
        )
        .expect("an interrupted watch is not an error");

    assert_eq!(
        outcome,
        ReconcileOutcome::Retained {
            generation: Some(1),
            reason: mail_operator::retention::RetentionReason::InterruptedWatch,
        }
    );
    assert_eq!(
        retention
            .active(&key("primary"))
            .expect("the retained snapshot survives the interruption")
            .identities()
            .len(),
        1
    );
}

#[test]
fn a_revoked_identity_is_removed_from_the_retained_snapshot() {
    let mut retention = SnapshotRetention::new();
    retention
        .publish(
            &key("primary"),
            &snapshot_yaml(1, &[("me", "personal"), ("noreply", "service")]),
            None,
            10,
        )
        .expect("a valid snapshot is published");

    let outcome = retention
        .revoke_identity(&key("primary"), "me", 20)
        .expect("the revocation is published");

    assert_eq!(outcome, RevocationOutcome::Published { generation: 2 });
    let active = retention
        .active(&key("primary"))
        .expect("the revocation is retained");
    assert_eq!(active.generation(), 2);
    assert_eq!(active.identities().len(), 1);
    assert_eq!(active.identities()[0].id.as_str(), "noreply");
}

#[test]
fn revoking_the_last_identity_fails_closed() {
    let mut retention = SnapshotRetention::new();
    retention
        .publish(
            &key("primary"),
            &snapshot_yaml(1, &[("me", "personal")]),
            None,
            10,
        )
        .expect("a valid snapshot is published");

    let outcome = retention
        .revoke_identity(&key("primary"), "me", 20)
        .expect("the revocation is handled");

    assert_eq!(
        outcome,
        RevocationOutcome::FailedClosed {
            reason: "no identity remains to serve".to_owned()
        }
    );
}

#[test]
fn a_stale_candidate_never_replaces_a_newer_snapshot() {
    let mut retention = SnapshotRetention::new();
    retention
        .publish(
            &key("primary"),
            &snapshot_yaml(5, &[("me", "personal")]),
            None,
            10,
        )
        .expect("a valid snapshot is published");

    let error = retention
        .publish(
            &key("primary"),
            &snapshot_yaml(4, &[("me", "personal")]),
            None,
            20,
        )
        .expect_err("a rollback is refused");

    assert_eq!(error, PublishError::StaleGeneration { generation: 4 });
    assert_eq!(
        retention
            .active(&key("primary"))
            .expect("the newer snapshot is retained")
            .generation(),
        5
    );
}
