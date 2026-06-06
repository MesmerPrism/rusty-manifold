use super::*;

#[test]
fn clock_snapshot_authority_review_accepts_next_tick() {
    let snapshot = authority_snapshot();
    let request = clock_snapshot_change_request();
    let review = snapshot
        .review_clock_snapshot_change(
            request,
            command_review_clock(),
            vec![id(
                "evidence.clock_snapshot_authority.request.synthetic_tick",
            )],
        )
        .unwrap();

    assert_eq!(
        review.outcome,
        ManifoldClockSnapshotAuthorityReviewOutcome::ClockSnapshotAccepted
    );
    assert_eq!(review.accepted.as_ref().unwrap().sequence, 43);
    assert_eq!(
        review.accepted.as_ref().unwrap().health,
        ClockHealth::Degraded
    );
    assert_eq!(review.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn clock_snapshot_authority_application_advances_snapshot() {
    let snapshot = authority_snapshot();
    let review = snapshot
        .review_clock_snapshot_change(
            clock_snapshot_change_request(),
            command_review_clock(),
            vec![id(
                "evidence.clock_snapshot_authority.request.synthetic_tick",
            )],
        )
        .unwrap();
    let application = snapshot
        .apply_clock_snapshot_authority_review(review)
        .unwrap();

    assert_eq!(
        application.outcome,
        ManifoldClockSnapshotAuthorityApplicationOutcome::ClockSnapshotApplied
    );
    assert!(application.rejection.is_none());
    let applied = application.applied_snapshot.as_ref().unwrap();
    assert_eq!(applied.authority_revision, Revision::new(2).unwrap());
    assert_eq!(applied.clock_snapshot.sequence, 43);
    assert_eq!(
        applied.clock_snapshot.clock_epoch_id,
        snapshot.clock_snapshot.clock_epoch_id
    );
    assert_eq!(applied.clock_snapshot.health, ClockHealth::Degraded);
    assert_eq!(application.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn clock_snapshot_authority_application_rejects_rejected_review() {
    let snapshot = authority_snapshot();
    let mut request = clock_snapshot_change_request();
    request.request_id = id("request.clock.stale_revision");
    request.expected_authority_revision = Revision::new(2).unwrap();
    let review = snapshot
        .review_clock_snapshot_change(
            request,
            command_review_clock(),
            vec![id(
                "evidence.clock_snapshot_authority.request.stale_revision",
            )],
        )
        .unwrap();
    let application = snapshot
        .apply_clock_snapshot_authority_review(review)
        .unwrap();

    assert_eq!(
        application.outcome,
        ManifoldClockSnapshotAuthorityApplicationOutcome::ClockSnapshotApplicationRejected
    );
    assert!(application.applied_snapshot.is_none());
    assert_eq!(
        application
            .rejection
            .as_ref()
            .unwrap()
            .rejection_code
            .as_str(),
        "review_rejected"
    );
    assert_eq!(application.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn clock_snapshot_authority_review_rejects_sequence_gap() {
    let snapshot = authority_snapshot();
    let mut request = clock_snapshot_change_request();
    request.request_id = id("request.clock.sequence_gap");
    request.proposed_snapshot.sequence = 44;
    let review = snapshot
        .review_clock_snapshot_change(
            request,
            command_review_clock(),
            vec![id("evidence.clock_snapshot_authority.request.sequence_gap")],
        )
        .unwrap();

    assert_eq!(
        review.outcome,
        ManifoldClockSnapshotAuthorityReviewOutcome::ClockSnapshotRejected
    );
    assert_eq!(
        review.rejection.as_ref().unwrap().rejection_code.as_str(),
        "clock_sequence_mismatch"
    );
    assert_eq!(review.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn clock_snapshot_authority_review_rejects_monotonic_regression() {
    let snapshot = authority_snapshot();
    let mut request = clock_snapshot_change_request();
    request.request_id = id("request.clock.monotonic_regression");
    request.proposed_snapshot.monotonic_elapsed_ns = snapshot.clock_snapshot.monotonic_elapsed_ns;
    let review = snapshot
        .review_clock_snapshot_change(
            request,
            command_review_clock(),
            vec![id(
                "evidence.clock_snapshot_authority.request.monotonic_regression",
            )],
        )
        .unwrap();

    assert_eq!(
        review.outcome,
        ManifoldClockSnapshotAuthorityReviewOutcome::ClockSnapshotRejected
    );
    assert_eq!(
        review.rejection.as_ref().unwrap().rejection_code.as_str(),
        "monotonic_time_regression"
    );
    assert_eq!(review.validate_against_snapshot(&snapshot), Ok(()));
}
