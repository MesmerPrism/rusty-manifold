use super::*;

#[test]
fn stream_registry_authority_review_accepts_metadata_change() {
    let snapshot = stream_authority_snapshot();
    let request = stream_registry_change_request();
    let review = snapshot
        .review_stream_registry_change(
            request,
            command_review_clock(),
            vec![id(
                "evidence.stream_registry_authority.request.synthetic_wave_subscription",
            )],
        )
        .unwrap();

    assert_eq!(
        review.outcome,
        ManifoldStreamRegistryAuthorityReviewOutcome::RegistryAccepted
    );
    assert_eq!(
        review
            .accepted
            .as_ref()
            .unwrap()
            .streams
            .first()
            .unwrap()
            .subscription
            .max_subscribers,
        Some(4)
    );
    assert_eq!(review.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn stream_registry_authority_review_rejects_active_stream_removal() {
    let snapshot = stream_authority_snapshot();
    let mut request = stream_registry_change_request();
    request.request_id = id("request.stream_registry.remove_active_wave");
    request.diff.changed_streams.clear();
    request.diff.removed_streams = vec![synthetic_stream(8)];
    let review = snapshot
        .review_stream_registry_change(
            request,
            command_review_clock(),
            vec![id(
                "evidence.stream_registry_authority.request.remove_active_wave",
            )],
        )
        .unwrap();

    assert_eq!(
        review.outcome,
        ManifoldStreamRegistryAuthorityReviewOutcome::RegistryRejected
    );
    assert_eq!(
        review.rejection.as_ref().unwrap().rejection_code.as_str(),
        "active_stream_conflict"
    );
    assert_eq!(review.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn stream_registry_authority_application_advances_snapshot() {
    let snapshot = stream_authority_snapshot();
    let review = snapshot
        .review_stream_registry_change(
            stream_registry_change_request(),
            command_review_clock(),
            vec![id(
                "evidence.stream_registry_authority.request.synthetic_wave_subscription",
            )],
        )
        .unwrap();
    let application = snapshot
        .apply_stream_registry_authority_review(review)
        .unwrap();

    assert_eq!(
        application.outcome,
        ManifoldStreamRegistryAuthorityApplicationOutcome::RegistrySnapshotApplied
    );
    assert!(application.rejection.is_none());
    let applied = application.applied_snapshot.as_ref().unwrap();
    assert_eq!(applied.authority_revision, Revision::new(2).unwrap());
    assert_eq!(
        applied.stream_registry.registry_revision,
        Revision::new(2).unwrap()
    );
    assert_eq!(
        applied.stream_registry.streams[0]
            .subscription
            .max_subscribers,
        Some(4)
    );
    assert_eq!(application.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn stream_registry_authority_application_rejects_rejected_review() {
    let snapshot = stream_authority_snapshot();
    let mut request = stream_registry_change_request();
    request.request_id = id("request.stream_registry.stale_revision");
    request.expected_authority_revision = Revision::new(2).unwrap();
    let review = snapshot
        .review_stream_registry_change(
            request,
            command_review_clock(),
            vec![id(
                "evidence.stream_registry_authority.request.stale_revision",
            )],
        )
        .unwrap();
    let application = snapshot
        .apply_stream_registry_authority_review(review)
        .unwrap();

    assert_eq!(
        application.outcome,
        ManifoldStreamRegistryAuthorityApplicationOutcome::RegistryApplicationRejected
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
fn stream_subscription_authority_review_accepts_ui_subscriber() {
    let snapshot = stream_authority_snapshot();
    let request = stream_subscription_request();
    let review = snapshot
        .review_stream_subscription(
            request,
            command_review_clock(),
            vec![id(
                "evidence.stream_subscription_authority.request.synthetic_wave_ui",
            )],
        )
        .unwrap();

    assert_eq!(
        review.outcome,
        ManifoldStreamSubscriptionAuthorityReviewOutcome::SubscriptionAccepted
    );
    let accepted = review.accepted.as_ref().unwrap();
    assert_eq!(accepted.stream_id, id("stream.synthetic_wave"));
    assert_eq!(accepted.transport_id, id("transport.in_process"));
    assert_eq!(accepted.accepted_authority_revision, Revision::INITIAL);
    assert_eq!(review.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn stream_subscription_authority_review_rejects_stale_registry() {
    let snapshot = stream_authority_snapshot();
    let mut request = stream_subscription_request();
    request.request_id = id("request.stream_subscription.stale_registry");
    request.expected_registry_revision = Revision::new(2).unwrap();
    let review = snapshot
        .review_stream_subscription(
            request,
            command_review_clock(),
            vec![id(
                "evidence.stream_subscription_authority.request.stale_registry",
            )],
        )
        .unwrap();

    assert_eq!(
        review.outcome,
        ManifoldStreamSubscriptionAuthorityReviewOutcome::SubscriptionRejected
    );
    assert_eq!(
        review.rejection.as_ref().unwrap().rejection_code.as_str(),
        "registry_revision_mismatch"
    );
    assert_eq!(review.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn stream_subscription_authority_review_rejects_subscriber_limit() {
    let mut snapshot = stream_authority_snapshot();
    snapshot.stream_registry.streams[0]
        .subscription
        .max_subscribers = Some(1);
    let review = snapshot
        .review_stream_subscription(
            stream_subscription_request(),
            command_review_clock(),
            vec![id(
                "evidence.stream_subscription_authority.request.synthetic_wave_ui",
            )],
        )
        .unwrap();
    let first_subscription = review.accepted.clone().unwrap();
    snapshot
        .active_stream_subscriptions
        .push(first_subscription);
    let mut second_request = stream_subscription_request();
    second_request.request_id = id("request.stream_subscription.second_ui");
    second_request.subscriber_id = id("subscriber.ui.second_dashboard");
    let review = snapshot
        .review_stream_subscription(
            second_request,
            command_review_clock(),
            vec![id(
                "evidence.stream_subscription_authority.request.second_ui",
            )],
        )
        .unwrap();

    assert_eq!(
        review.outcome,
        ManifoldStreamSubscriptionAuthorityReviewOutcome::SubscriptionRejected
    );
    assert_eq!(
        review.rejection.as_ref().unwrap().rejection_code.as_str(),
        "subscriber_limit_reached"
    );
    assert_eq!(review.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn stream_subscription_authority_application_appends_subscription() {
    let snapshot = stream_authority_snapshot();
    let review = snapshot
        .review_stream_subscription(
            stream_subscription_request(),
            command_review_clock(),
            vec![id(
                "evidence.stream_subscription_authority.request.synthetic_wave_ui",
            )],
        )
        .unwrap();
    let application = snapshot
        .apply_stream_subscription_authority_review(review)
        .unwrap();

    assert_eq!(
        application.outcome,
        ManifoldStreamSubscriptionAuthorityApplicationOutcome::SubscriptionApplied
    );
    assert!(application.rejection.is_none());
    let applied = application.applied_snapshot.as_ref().unwrap();
    assert_eq!(applied.authority_revision, Revision::new(2).unwrap());
    assert_eq!(applied.active_stream_subscriptions.len(), 1);
    assert_eq!(application.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn stream_subscription_release_application_removes_subscription() {
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
    let subscription = active_snapshot.active_stream_subscriptions[0].clone();
    let release_request = ManifoldStreamSubscriptionReleaseRequest {
        schema_id: stream_subscription_release_request_schema_id(),
        request_id: id("request.stream_subscription_release.synthetic_wave_ui"),
        subscription_id: subscription.subscription_id.clone(),
        subscriber_id: subscription.subscriber_id.clone(),
        expected_authority_revision: active_snapshot.authority_revision,
        expected_registry_revision: active_snapshot.stream_registry.registry_revision,
        stream_id: subscription.stream_id.clone(),
        release_reason: id("subscriber.closed"),
        requested_at_ms: 1_765_000_000_200,
    };
    let release_review = active_snapshot
        .review_stream_subscription_release(
            release_request,
            command_review_clock(),
            vec![id(
                "evidence.stream_subscription_release_authority.request.synthetic_wave_ui",
            )],
        )
        .unwrap();

    assert_eq!(
        release_review.outcome,
        ManifoldStreamSubscriptionReleaseAuthorityReviewOutcome::SubscriptionReleased
    );
    assert_eq!(release_review.released.as_ref(), Some(&subscription));
    assert_eq!(
        release_review.validate_against_snapshot(&active_snapshot),
        Ok(())
    );

    let release_application = active_snapshot
        .apply_stream_subscription_release_authority_review(release_review)
        .unwrap();

    assert_eq!(
        release_application.outcome,
        ManifoldStreamSubscriptionReleaseAuthorityApplicationOutcome::SubscriptionReleaseApplied
    );
    assert!(release_application.rejection.is_none());
    let applied = release_application.applied_snapshot.as_ref().unwrap();
    assert_eq!(applied.authority_revision, Revision::new(3).unwrap());
    assert!(applied.active_stream_subscriptions.is_empty());
    assert_eq!(
        release_application.validate_against_snapshot(&active_snapshot),
        Ok(())
    );
}

#[test]
fn stream_subscription_renewal_application_replaces_subscription() {
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
    let subscription = active_snapshot.active_stream_subscriptions[0].clone();
    let old_expires_at_ms = subscription.expires_at_ms;
    let renewal_request = ManifoldStreamSubscriptionRenewalRequest {
        schema_id: stream_subscription_renewal_request_schema_id(),
        request_id: id("request.stream_subscription_renewal.synthetic_wave_ui"),
        subscription_id: subscription.subscription_id.clone(),
        subscriber_id: subscription.subscriber_id.clone(),
        expected_authority_revision: active_snapshot.authority_revision,
        expected_registry_revision: active_snapshot.stream_registry.registry_revision,
        stream_id: subscription.stream_id.clone(),
        transport_id: subscription.transport_id.clone(),
        requested_ttl_ms: 60_000,
        renewal_reason: id("subscriber.needs_more_time"),
        requested_at_ms: 1_765_000_000_200,
    };
    let renewal_review = active_snapshot
        .review_stream_subscription_renewal(
            renewal_request,
            command_review_clock(),
            vec![id(
                "evidence.stream_subscription_renewal_authority.request.synthetic_wave_ui",
            )],
        )
        .unwrap();

    assert_eq!(
        renewal_review.outcome,
        ManifoldStreamSubscriptionRenewalAuthorityReviewOutcome::SubscriptionRenewed
    );
    let renewed = renewal_review.renewed.as_ref().unwrap();
    assert_eq!(renewed.subscription_id, subscription.subscription_id);
    assert!(renewed.expires_at_ms > old_expires_at_ms);
    assert_eq!(
        renewal_review.validate_against_snapshot(&active_snapshot),
        Ok(())
    );

    let renewal_application = active_snapshot
        .apply_stream_subscription_renewal_authority_review(renewal_review)
        .unwrap();

    assert_eq!(
        renewal_application.outcome,
        ManifoldStreamSubscriptionRenewalAuthorityApplicationOutcome::SubscriptionRenewalApplied
    );
    assert!(renewal_application.rejection.is_none());
    let applied = renewal_application.applied_snapshot.as_ref().unwrap();
    assert_eq!(applied.authority_revision, Revision::new(3).unwrap());
    assert_eq!(
        applied.active_stream_subscriptions.len(),
        active_snapshot.active_stream_subscriptions.len()
    );
    let renewed_subscription = applied
        .active_stream_subscriptions
        .iter()
        .find(|active| active.subscription_id == subscription.subscription_id)
        .unwrap();
    assert!(renewed_subscription.expires_at_ms > old_expires_at_ms);
    assert_eq!(
        renewed_subscription.accepted_authority_revision,
        Revision::new(2).unwrap()
    );
    assert_eq!(
        renewal_application.validate_against_snapshot(&active_snapshot),
        Ok(())
    );
}
