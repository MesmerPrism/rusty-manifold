use super::*;

#[test]
fn authority_expiry_sweep_application_removes_expired_state() {
    let snapshot = stream_authority_snapshot();
    let subscription_review = snapshot
        .review_stream_subscription(
            stream_subscription_request(),
            command_review_clock(),
            vec![id(
                "evidence.stream_subscription_authority.request.synthetic_wave_ui",
            )],
        )
        .unwrap();
    let subscription_application = snapshot
        .apply_stream_subscription_authority_review(subscription_review)
        .unwrap();
    let active_snapshot = subscription_application.applied_snapshot.unwrap();
    let mut expired_clock = command_review_clock();
    expired_clock.sequence = 44;
    expired_clock.monotonic_elapsed_ns = 3_334_567_990;
    expired_clock.wall_unix_ms = 1_765_000_030_200;
    let request = ManifoldAuthorityExpirySweepRequest {
        schema_id: authority_expiry_sweep_request_schema_id(),
        request_id: id("request.expiry_sweep.synthetic"),
        requester_id: id("authority.synthetic"),
        expected_authority_revision: active_snapshot.authority_revision,
        expected_registry_revision: active_snapshot.stream_registry.registry_revision,
        sweep_reason: id("maintenance.ttl_expired"),
        requested_at_ms: 1_765_000_030_200,
    };

    let review = active_snapshot
        .review_authority_expiry_sweep(
            request,
            expired_clock,
            vec![id("evidence.expiry_sweep.synthetic")],
        )
        .unwrap();

    assert_eq!(
        review.outcome,
        ManifoldAuthorityExpirySweepAuthorityReviewOutcome::ExpiredStateAccepted
    );
    assert_eq!(
        review.expired_leases.len(),
        active_snapshot.active_leases.len()
    );
    assert_eq!(
        review.expired_stream_subscriptions.len(),
        active_snapshot.active_stream_subscriptions.len()
    );
    assert_eq!(review.validate_against_snapshot(&active_snapshot), Ok(()));

    let application = active_snapshot
        .apply_authority_expiry_sweep_review(review)
        .unwrap();

    assert_eq!(
        application.outcome,
        ManifoldAuthorityExpirySweepAuthorityApplicationOutcome::ExpiredStateApplied
    );
    assert!(application.rejection.is_none());
    let applied = application.applied_snapshot.as_ref().unwrap();
    assert_eq!(applied.authority_revision, Revision::new(3).unwrap());
    assert!(applied.active_leases.is_empty());
    assert!(applied.active_stream_subscriptions.is_empty());
    assert_eq!(
        application.validate_against_snapshot(&active_snapshot),
        Ok(())
    );
}
