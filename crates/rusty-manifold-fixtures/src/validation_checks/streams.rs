use super::*;

pub(super) fn push_stream_checks(checks: &mut Vec<ValidationCheckReport>, fixtures: &FixtureSet) {
    push_result(
        checks,
        "validation.check.stream_registry_diff_fixture",
        if fixtures.stream_registry_change_request.diff == fixtures.stream_registry_diff {
            Ok(())
        } else {
            Err(
                "stream registry change request does not embed the standalone diff fixture"
                    .to_owned(),
            )
        },
        "stream registry change request embeds the standalone diff fixture",
    );

    push_result(
        checks,
        "validation.check.stream_registry_lease_fixture",
        if fixtures.stream_registry_lease.scope.as_str() == "manifold.stream_registry"
            && fixtures.stream_registry_lease.holder_id
                == fixtures.stream_registry_change_request.holder_id
            && fixtures.stream_registry_change_request.lease_id.as_ref()
                == Some(&fixtures.stream_registry_lease.lease_id)
        {
            Ok(())
        } else {
            Err(
                "stream registry lease fixture does not authorize the registry change request"
                    .to_owned(),
            )
        },
        "stream registry lease fixture authorizes the accepted registry request",
    );

    push_result(
        checks,
        "validation.check.stream_registry_authority_audit_event",
        fixtures
            .stream_registry_authority_audit_event
            .validate_against_snapshot(&fixtures.authority_snapshot),
        "stream registry authority audit event matches the accepted request, lease, clock, and snapshot",
    );

    push_result(
        checks,
        "validation.check.stream_registry_rejection_fixture",
        if fixtures.stream_registry_rejection.rejection_code.as_str() == "stale_revision"
            && fixtures.stream_registry_rejection.retryable
            && fixtures
                .stream_registry_rejection
                .current_authority_revision
                == Revision::INITIAL
            && fixtures.stream_registry_rejection.current_registry_revision == Revision::INITIAL
        {
            Ok(())
        } else {
            Err("standalone stream registry rejection fixture is not the expected stale-revision rejection"
                .to_owned())
        },
        "standalone stream registry rejection fixture is a stale-revision rejection",
    );

    push_result(
        checks,
        "validation.check.stream_registry_authority_review_accepted",
        stream_registry_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.stream_registry_change_request,
            &fixtures.command_review_clock,
            &fixtures.accepted_stream_registry_review,
        ),
        "stream registry authority evaluator deterministically accepts a lease-scoped metadata change",
    );

    push_result(
        checks,
        "validation.check.stream_registry_authority_review_expired_lease",
        stream_registry_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.stream_registry_change_request,
            &fixtures.expired_command_review_clock,
            &fixtures.expired_lease_stream_registry_review,
        ),
        "stream registry authority evaluator deterministically rejects leases expired at the review clock",
    );

    push_result(
        checks,
        "validation.check.stream_registry_authority_review_stale_revision",
        stream_registry_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.stale_stream_registry_request,
            &fixtures.command_review_clock,
            &fixtures.stale_stream_registry_review,
        ),
        "stream registry authority evaluator deterministically rejects stale authority revisions",
    );

    push_result(
        checks,
        "validation.check.stream_registry_authority_review_missing_lease",
        stream_registry_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.missing_lease_stream_registry_request,
            &fixtures.command_review_clock,
            &fixtures.missing_lease_stream_registry_review,
        ),
        "stream registry authority evaluator deterministically rejects missing registry leases",
    );

    push_result(
        checks,
        "validation.check.stream_registry_authority_review_active_stream_conflict",
        stream_registry_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.active_stream_registry_request,
            &fixtures.command_review_clock,
            &fixtures.active_stream_registry_review,
        ),
        "stream registry authority evaluator deterministically rejects active-stream removals",
    );

    push_result(
        checks,
        "validation.check.stream_registry_authority_review_active_subscription_transport_conflict",
        stream_registry_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.remove_active_transport_stream_registry_request,
            &fixtures.command_review_clock,
            &fixtures.remove_active_transport_stream_registry_review,
        ),
        "stream registry authority evaluator deterministically rejects removing transport offers used by active subscriptions",
    );

    push_result(
        checks,
        "validation.check.stream_registry_authority_review_active_subscription_ui_policy_conflict",
        stream_registry_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.disable_active_ui_stream_registry_request,
            &fixtures.command_review_clock,
            &fixtures.disable_active_ui_stream_registry_review,
        ),
        "stream registry authority evaluator deterministically rejects disabling UI subscriptions while UI subscriptions are active",
    );

    push_result(
        checks,
        "validation.check.stream_registry_authority_review_active_subscription_limit_conflict",
        stream_registry_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.lower_active_subscriber_limit_stream_registry_request,
            &fixtures.command_review_clock,
            &fixtures.lower_active_subscriber_limit_stream_registry_review,
        ),
        "stream registry authority evaluator deterministically rejects subscriber limits below active subscriptions",
    );

    push_result(
        checks,
        "validation.check.stream_registry_authority_review_unknown_module",
        stream_registry_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.unknown_module_stream_registry_request,
            &fixtures.command_review_clock,
            &fixtures.unknown_module_stream_registry_review,
        ),
        "stream registry authority evaluator deterministically rejects unknown source modules",
    );

    push_result(
        checks,
        "validation.check.stream_registry_authority_review_unknown_endpoint",
        stream_registry_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.unknown_endpoint_stream_registry_request,
            &fixtures.command_review_clock,
            &fixtures.unknown_endpoint_stream_registry_review,
        ),
        "stream registry authority evaluator deterministically rejects unknown transport endpoints",
    );

    push_result(
        checks,
        "validation.check.stream_registry_authority_application_rejection_fixture",
        if fixtures
            .stream_registry_application_rejection
            .rejection_code
            .as_str()
            == "review_rejected"
            && fixtures
                .stream_registry_application_rejection
                .current_authority_revision
                == Revision::INITIAL
        {
            Ok(())
        } else {
            Err("standalone stream registry application rejection fixture is not the expected review-rejected rejection"
                .to_owned())
        },
        "standalone stream registry application rejection fixture is a review-rejected rejection",
    );

    push_result(
        checks,
        "validation.check.stream_registry_authority_application_accepted",
        stream_registry_application_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.accepted_stream_registry_review,
            &fixtures.accepted_stream_registry_application,
        ),
        "stream registry authority application deterministically advances accepted registry state",
    );

    push_result(
        checks,
        "validation.check.stream_registry_authority_application_rejected",
        stream_registry_application_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.stale_stream_registry_review,
            &fixtures.rejected_stream_registry_application,
        ),
        "stream registry authority application deterministically rejects rejected registry reviews",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_authority_snapshot",
        fixtures
            .stream_subscription_authority_snapshot
            .validate_authority_links(),
        "stream subscription authority snapshot carries subscribe capability and valid stream links",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_fixture",
        if fixtures
            .accepted_stream_subscription_review
            .accepted
            .as_ref()
            == Some(&fixtures.stream_subscription)
        {
            Ok(())
        } else {
            Err(
                "standalone stream subscription fixture does not match the accepted review"
                    .to_owned(),
            )
        },
        "standalone stream subscription fixture matches the accepted review state",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_rejection_fixture",
        if fixtures
            .stream_subscription_rejection
            .rejection_code
            .as_str()
            == "stale_revision"
            && fixtures.stream_subscription_rejection.retryable
            && fixtures
                .stream_subscription_rejection
                .current_authority_revision
                == Revision::INITIAL
            && fixtures
                .stream_subscription_rejection
                .current_registry_revision
                == Revision::INITIAL
        {
            Ok(())
        } else {
            Err("standalone stream subscription rejection fixture is not the expected stale-revision rejection"
                .to_owned())
        },
        "standalone stream subscription rejection fixture is a stale-revision rejection",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_authority_audit_event",
        fixtures
            .stream_subscription_authority_audit_event
            .validate_against_snapshot(&fixtures.stream_subscription_authority_snapshot),
        "stream subscription authority audit event matches the accepted request, clock, and snapshot",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_authority_review_accepted",
        stream_subscription_review_matches_fixture(
            &fixtures.stream_subscription_authority_snapshot,
            &fixtures.stream_subscription_request,
            &fixtures.command_review_clock,
            &fixtures.accepted_stream_subscription_review,
        ),
        "stream subscription authority evaluator deterministically accepts a UI subscriber for an advertised transport",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_authority_review_zero_ttl",
        stream_subscription_review_matches_fixture(
            &fixtures.stream_subscription_authority_snapshot,
            &fixtures.zero_ttl_stream_subscription_request,
            &fixtures.command_review_clock,
            &fixtures.zero_ttl_stream_subscription_review,
        ),
        "stream subscription authority evaluator deterministically rejects zero-duration subscriptions",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_authority_review_missing_capability",
        stream_subscription_review_matches_fixture(
            &fixtures.stream_subscription_authority_snapshot,
            &fixtures.missing_capability_stream_subscription_request,
            &fixtures.command_review_clock,
            &fixtures.missing_capability_stream_subscription_review,
        ),
        "stream subscription authority evaluator deterministically rejects unadvertised subscribe capabilities",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_authority_review_stale_revision",
        stream_subscription_review_matches_fixture(
            &fixtures.stream_subscription_authority_snapshot,
            &fixtures.stale_stream_subscription_request,
            &fixtures.command_review_clock,
            &fixtures.stale_stream_subscription_review,
        ),
        "stream subscription authority evaluator deterministically rejects stale authority revisions",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_authority_review_stale_registry",
        stream_subscription_review_matches_fixture(
            &fixtures.stream_subscription_authority_snapshot,
            &fixtures.stale_registry_stream_subscription_request,
            &fixtures.command_review_clock,
            &fixtures.stale_registry_stream_subscription_review,
        ),
        "stream subscription authority evaluator deterministically rejects stale registry revisions",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_authority_review_unknown_stream",
        stream_subscription_review_matches_fixture(
            &fixtures.stream_subscription_authority_snapshot,
            &fixtures.unknown_stream_subscription_request,
            &fixtures.command_review_clock,
            &fixtures.unknown_stream_subscription_review,
        ),
        "stream subscription authority evaluator deterministically rejects unknown streams",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_authority_review_unknown_transport",
        stream_subscription_review_matches_fixture(
            &fixtures.stream_subscription_authority_snapshot,
            &fixtures.unknown_transport_stream_subscription_request,
            &fixtures.command_review_clock,
            &fixtures.unknown_transport_stream_subscription_review,
        ),
        "stream subscription authority evaluator deterministically rejects unknown transport offers",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_authority_review_subscriber_limit",
        stream_subscription_review_matches_fixture(
            &fixtures.subscriber_limit_stream_subscription_authority_snapshot,
            &fixtures.subscriber_limit_stream_subscription_request,
            &fixtures.command_review_clock,
            &fixtures.subscriber_limit_stream_subscription_review,
        ),
        "stream subscription authority evaluator deterministically rejects subscriptions beyond the stream subscriber limit",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_authority_review_ui_disabled",
        stream_subscription_review_matches_fixture(
            &fixtures.ui_disabled_stream_subscription_authority_snapshot,
            &fixtures.ui_disabled_stream_subscription_request,
            &fixtures.command_review_clock,
            &fixtures.ui_disabled_stream_subscription_review,
        ),
        "stream subscription authority evaluator deterministically rejects UI subscribers when stream policy disables UI subscriptions",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_authority_application_rejection_fixture",
        if fixtures
            .stream_subscription_application_rejection
            .rejection_code
            .as_str()
            == "review_rejected"
            && fixtures
                .stream_subscription_application_rejection
                .current_authority_revision
                == Revision::INITIAL
        {
            Ok(())
        } else {
            Err("standalone stream subscription application rejection fixture is not the expected review-rejected rejection"
                .to_owned())
        },
        "standalone stream subscription application rejection fixture is a review-rejected rejection",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_authority_application_accepted",
        stream_subscription_application_matches_fixture(
            &fixtures.stream_subscription_authority_snapshot,
            &fixtures.accepted_stream_subscription_review,
            &fixtures.accepted_stream_subscription_application,
        ),
        "stream subscription authority application deterministically appends accepted subscription state",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_authority_application_rejected",
        stream_subscription_application_matches_fixture(
            &fixtures.stream_subscription_authority_snapshot,
            &fixtures.stale_stream_subscription_review,
            &fixtures.rejected_stream_subscription_application,
        ),
        "stream subscription authority application deterministically rejects rejected subscription reviews",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_release_authority_snapshot",
        fixtures
            .stream_subscription_active_authority_snapshot
            .validate_authority_links(),
        "stream subscription release authority snapshot has one accepted active subscription",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_release_request_fixture",
        if fixtures
            .stream_subscription_active_authority_snapshot
            .active_stream_subscriptions
            .iter()
            .any(|subscription| {
                subscription.subscription_id
                    == fixtures.stream_subscription_release_request.subscription_id
                    && subscription.subscriber_id
                        == fixtures.stream_subscription_release_request.subscriber_id
                    && subscription.stream_id
                        == fixtures.stream_subscription_release_request.stream_id
            })
            && fixtures
                .stream_subscription_release_request
                .expected_authority_revision
                == fixtures
                    .stream_subscription_active_authority_snapshot
                    .authority_revision
            && fixtures
                .stream_subscription_release_request
                .expected_registry_revision
                == fixtures
                    .stream_subscription_active_authority_snapshot
                    .stream_registry
                    .registry_revision
        {
            Ok(())
        } else {
            Err("stream subscription release request does not target the active subscription snapshot"
                .to_owned())
        },
        "stream subscription release request targets the accepted active subscription",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_release_rejection_fixture",
        if fixtures
            .stream_subscription_release_rejection
            .rejection_code
            .as_str()
            == "stale_revision"
            && fixtures.stream_subscription_release_rejection.retryable
            && fixtures
                .stream_subscription_release_rejection
                .current_authority_revision
                == Revision::new(2).expect("revision literal is valid")
        {
            Ok(())
        } else {
            Err("standalone stream subscription release rejection fixture is not the expected stale-revision rejection"
                .to_owned())
        },
        "standalone stream subscription release rejection fixture is a stale-revision rejection",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_release_authority_audit_event",
        fixtures
            .stream_subscription_release_authority_audit_event
            .validate_against_snapshot(&fixtures.stream_subscription_active_authority_snapshot),
        "stream subscription release authority audit event matches the accepted request, clock, and active snapshot",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_release_authority_review_accepted",
        stream_subscription_release_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.stream_subscription_release_request,
            &fixtures.command_review_clock,
            &fixtures.accepted_stream_subscription_release_review,
        ),
        "stream subscription release authority evaluator deterministically accepts active subscription release",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_release_authority_review_expired_subscription",
        stream_subscription_release_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.stream_subscription_release_request,
            &fixtures.expired_command_review_clock,
            &fixtures.expired_stream_subscription_release_review,
        ),
        "stream subscription release authority evaluator deterministically rejects subscriptions expired at the review clock",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_release_authority_review_stale_revision",
        stream_subscription_release_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.stale_stream_subscription_release_request,
            &fixtures.command_review_clock,
            &fixtures.stale_stream_subscription_release_review,
        ),
        "stream subscription release authority evaluator deterministically rejects stale authority revisions",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_release_authority_review_stale_registry",
        stream_subscription_release_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.stale_registry_stream_subscription_release_request,
            &fixtures.command_review_clock,
            &fixtures.stale_registry_stream_subscription_release_review,
        ),
        "stream subscription release authority evaluator deterministically rejects stale stream registries",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_release_authority_review_unknown_subscription",
        stream_subscription_release_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.unknown_stream_subscription_release_request,
            &fixtures.command_review_clock,
            &fixtures.unknown_stream_subscription_release_review,
        ),
        "stream subscription release authority evaluator deterministically rejects unknown subscriptions",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_release_authority_review_subscriber_mismatch",
        stream_subscription_release_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.subscriber_mismatch_stream_subscription_release_request,
            &fixtures.command_review_clock,
            &fixtures.subscriber_mismatch_stream_subscription_release_review,
        ),
        "stream subscription release authority evaluator deterministically rejects subscriber mismatches",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_release_authority_review_stream_mismatch",
        stream_subscription_release_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.stream_mismatch_stream_subscription_release_request,
            &fixtures.command_review_clock,
            &fixtures.stream_mismatch_stream_subscription_release_review,
        ),
        "stream subscription release authority evaluator deterministically rejects stream mismatches",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_release_authority_application_rejection_fixture",
        if fixtures
            .stream_subscription_release_application_rejection
            .rejection_code
            .as_str()
            == "review_rejected"
            && fixtures
                .stream_subscription_release_application_rejection
                .current_authority_revision
                == Revision::new(2).expect("revision literal is valid")
        {
            Ok(())
        } else {
            Err("standalone stream subscription release application rejection fixture is not the expected review-rejected rejection"
                .to_owned())
        },
        "standalone stream subscription release application rejection fixture is a review-rejected rejection",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_release_authority_application_accepted",
        stream_subscription_release_application_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.accepted_stream_subscription_release_review,
            &fixtures.accepted_stream_subscription_release_application,
        ),
        "stream subscription release authority application deterministically removes accepted active subscription state",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_release_authority_application_rejected",
        stream_subscription_release_application_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.stale_stream_subscription_release_review,
            &fixtures.rejected_stream_subscription_release_application,
        ),
        "stream subscription release authority application deterministically rejects rejected release reviews",
    );

    let stream_subscription_renewal_expected_expires_at_ms =
        u64::try_from(fixtures.command_review_clock.wall_unix_ms)
            .unwrap_or_default()
            .saturating_add(
                fixtures
                    .stream_subscription_renewal_request
                    .requested_ttl_ms,
            );
    push_result(
        checks,
        "validation.check.stream_subscription_renewal_request_fixture",
        match fixtures
            .stream_subscription_active_authority_snapshot
            .active_stream_subscriptions
            .iter()
            .find(|subscription| {
                subscription.subscription_id
                    == fixtures.stream_subscription_renewal_request.subscription_id
                    && subscription.subscriber_id
                        == fixtures.stream_subscription_renewal_request.subscriber_id
                    && subscription.stream_id
                        == fixtures.stream_subscription_renewal_request.stream_id
                    && subscription.transport_id
                        == fixtures.stream_subscription_renewal_request.transport_id
            }) {
            Some(subscription)
                if fixtures
                    .stream_subscription_renewal_request
                    .expected_authority_revision
                    == fixtures
                        .stream_subscription_active_authority_snapshot
                        .authority_revision
                    && fixtures
                        .stream_subscription_renewal_request
                        .expected_registry_revision
                        == fixtures
                            .stream_subscription_active_authority_snapshot
                            .stream_registry
                            .registry_revision
                    && fixtures.stream_subscription_renewal_request.requested_ttl_ms > 0
                    && stream_subscription_renewal_expected_expires_at_ms
                        > subscription.expires_at_ms =>
            {
                Ok(())
            }
            _ => Err(
                "stream subscription renewal request does not extend the active subscription snapshot"
                    .to_owned(),
            ),
        },
        "stream subscription renewal request targets and extends the accepted active subscription",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_renewal_rejection_fixture",
        if fixtures
            .stream_subscription_renewal_rejection
            .rejection_code
            .as_str()
            == "stale_revision"
            && fixtures.stream_subscription_renewal_rejection.retryable
            && fixtures
                .stream_subscription_renewal_rejection
                .current_authority_revision
                == Revision::new(2).expect("revision literal is valid")
            && fixtures
                .stream_subscription_renewal_rejection
                .current_registry_revision
                == Revision::INITIAL
            && fixtures
                .stream_subscription_renewal_rejection
                .active_subscriber_count
                == u32::try_from(
                    fixtures
                        .stream_subscription_active_authority_snapshot
                        .active_stream_subscriptions
                        .len(),
                )
                .expect("fixture active subscription count fits in u32")
            && fixtures
                .stream_subscription_renewal_rejection
                .current_expires_at_ms
                .is_none()
        {
            Ok(())
        } else {
            Err("standalone stream subscription renewal rejection fixture is not the expected stale-revision rejection"
                .to_owned())
        },
        "standalone stream subscription renewal rejection fixture is a stale-revision rejection",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_renewal_authority_audit_event",
        fixtures
            .stream_subscription_renewal_authority_audit_event
            .validate_against_snapshot(&fixtures.stream_subscription_active_authority_snapshot),
        "stream subscription renewal authority audit event matches the accepted request, clock, and active snapshot",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_renewal_authority_review_accepted",
        stream_subscription_renewal_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.stream_subscription_renewal_request,
            &fixtures.command_review_clock,
            &fixtures.accepted_stream_subscription_renewal_review,
        ),
        "stream subscription renewal authority evaluator deterministically accepts active subscription renewal",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_renewal_authority_review_stale_revision",
        stream_subscription_renewal_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.stale_stream_subscription_renewal_request,
            &fixtures.command_review_clock,
            &fixtures.stale_stream_subscription_renewal_review,
        ),
        "stream subscription renewal authority evaluator deterministically rejects stale authority revisions",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_renewal_authority_review_stale_registry",
        stream_subscription_renewal_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.stale_registry_stream_subscription_renewal_request,
            &fixtures.command_review_clock,
            &fixtures.stale_registry_stream_subscription_renewal_review,
        ),
        "stream subscription renewal authority evaluator deterministically rejects stale stream registries",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_renewal_authority_review_unknown_subscription",
        stream_subscription_renewal_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.unknown_stream_subscription_renewal_request,
            &fixtures.command_review_clock,
            &fixtures.unknown_stream_subscription_renewal_review,
        ),
        "stream subscription renewal authority evaluator deterministically rejects unknown subscriptions",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_renewal_authority_review_subscriber_mismatch",
        stream_subscription_renewal_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.subscriber_mismatch_stream_subscription_renewal_request,
            &fixtures.command_review_clock,
            &fixtures.subscriber_mismatch_stream_subscription_renewal_review,
        ),
        "stream subscription renewal authority evaluator deterministically rejects subscriber mismatches",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_renewal_authority_review_stream_mismatch",
        stream_subscription_renewal_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.stream_mismatch_stream_subscription_renewal_request,
            &fixtures.command_review_clock,
            &fixtures.stream_mismatch_stream_subscription_renewal_review,
        ),
        "stream subscription renewal authority evaluator deterministically rejects stream mismatches",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_renewal_authority_review_transport_mismatch",
        stream_subscription_renewal_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.transport_mismatch_stream_subscription_renewal_request,
            &fixtures.command_review_clock,
            &fixtures.transport_mismatch_stream_subscription_renewal_review,
        ),
        "stream subscription renewal authority evaluator deterministically rejects transport mismatches",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_renewal_authority_review_zero_ttl",
        stream_subscription_renewal_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.zero_ttl_stream_subscription_renewal_request,
            &fixtures.command_review_clock,
            &fixtures.zero_ttl_stream_subscription_renewal_review,
        ),
        "stream subscription renewal authority evaluator deterministically rejects zero-duration renewals",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_renewal_authority_review_non_extending",
        stream_subscription_renewal_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.non_extending_stream_subscription_renewal_request,
            &fixtures.command_review_clock,
            &fixtures.non_extending_stream_subscription_renewal_review,
        ),
        "stream subscription renewal authority evaluator deterministically rejects non-extending renewals",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_renewal_authority_review_expired_subscription",
        stream_subscription_renewal_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.stream_subscription_renewal_request,
            &fixtures.expired_command_review_clock,
            &fixtures.expired_stream_subscription_renewal_review,
        ),
        "stream subscription renewal authority evaluator deterministically rejects subscriptions expired at the review clock",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_renewal_authority_application_rejection_fixture",
        if fixtures
            .stream_subscription_renewal_application_rejection
            .rejection_code
            .as_str()
            == "review_rejected"
            && fixtures
                .stream_subscription_renewal_application_rejection
                .current_authority_revision
                == Revision::new(2).expect("revision literal is valid")
        {
            Ok(())
        } else {
            Err("standalone stream subscription renewal application rejection fixture is not the expected review-rejected rejection"
                .to_owned())
        },
        "standalone stream subscription renewal application rejection fixture is a review-rejected rejection",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_renewal_authority_application_accepted",
        stream_subscription_renewal_application_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.accepted_stream_subscription_renewal_review,
            &fixtures.accepted_stream_subscription_renewal_application,
        ),
        "stream subscription renewal authority application deterministically replaces accepted active subscription state",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_renewal_authority_application_rejected",
        stream_subscription_renewal_application_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.stale_stream_subscription_renewal_review,
            &fixtures.rejected_stream_subscription_renewal_application,
        ),
        "stream subscription renewal authority application deterministically rejects rejected renewal reviews",
    );
}

pub(super) fn push_damaged_stream_checks(
    repo_root: &Path,
    checks: &mut Vec<ValidationCheckReport>,
    fixtures: &FixtureSet,
    module_ids: &[DottedId],
) -> Result<(), CliError> {
    push_damaged(
        checks,
        "validation.check.damaged_unknown_stream_module",
        expected_rejection(repo_root, "fixtures/damaged/unknown-module-link.json")?,
        fixtures
            .damaged_unknown_stream_module
            .validate_source_modules(module_ids)
            .map_err(|error| error.rejection_code().to_owned()),
        "stream registry referencing an unknown module is rejected",
    );

    Ok(())
}
