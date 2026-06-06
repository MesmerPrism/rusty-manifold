use super::*;

pub(super) fn push_expiry_checks(checks: &mut Vec<ValidationCheckReport>, fixtures: &FixtureSet) {
    let expired_lease_count = fixtures
        .stream_subscription_active_authority_snapshot
        .active_leases
        .iter()
        .filter(|lease| {
            u64::try_from(fixtures.expired_command_review_clock.wall_unix_ms).unwrap_or_default()
                >= lease.expires_at_ms
        })
        .count();
    let expired_subscription_count = fixtures
        .stream_subscription_active_authority_snapshot
        .active_stream_subscriptions
        .iter()
        .filter(|subscription| {
            u64::try_from(fixtures.expired_command_review_clock.wall_unix_ms).unwrap_or_default()
                >= subscription.expires_at_ms
        })
        .count();

    push_result(
        checks,
        "validation.check.authority_expiry_sweep_request_fixture",
        if fixtures
            .authority_expiry_sweep_request
            .expected_authority_revision
            == fixtures
                .stream_subscription_active_authority_snapshot
                .authority_revision
            && fixtures
                .authority_expiry_sweep_request
                .expected_registry_revision
                == fixtures
                    .stream_subscription_active_authority_snapshot
                    .stream_registry
                    .registry_revision
            && expired_lease_count > 0
            && expired_subscription_count > 0
        {
            Ok(())
        } else {
            Err("authority expiry sweep request does not target the active authority snapshot with expired state"
                .to_owned())
        },
        "authority expiry sweep request targets active accepted state with expired leases and subscriptions",
    );

    push_result(
        checks,
        "validation.check.authority_expiry_sweep_rejection_fixture",
        if fixtures
            .authority_expiry_sweep_rejection
            .rejection_code
            .as_str()
            == "stale_revision"
            && fixtures.authority_expiry_sweep_rejection.retryable
            && fixtures
                .authority_expiry_sweep_rejection
                .current_authority_revision
                == fixtures
                    .stream_subscription_active_authority_snapshot
                    .authority_revision
            && fixtures
                .authority_expiry_sweep_rejection
                .current_registry_revision
                == fixtures
                    .stream_subscription_active_authority_snapshot
                    .stream_registry
                    .registry_revision
            && fixtures
                .authority_expiry_sweep_rejection
                .expired_lease_count
                == expired_lease_count
            && fixtures
                .authority_expiry_sweep_rejection
                .expired_subscription_count
                == expired_subscription_count
        {
            Ok(())
        } else {
            Err("standalone authority expiry sweep rejection fixture is not the expected stale-revision rejection"
                .to_owned())
        },
        "standalone authority expiry sweep rejection fixture is a stale-revision rejection",
    );

    push_result(
        checks,
        "validation.check.authority_expiry_sweep_authority_audit_event",
        fixtures
            .authority_expiry_sweep_authority_audit_event
            .validate_against_snapshot(&fixtures.stream_subscription_active_authority_snapshot),
        "authority expiry sweep audit event matches the accepted request, clock, and active snapshot",
    );

    push_result(
        checks,
        "validation.check.authority_expiry_sweep_authority_review_accepted",
        authority_expiry_sweep_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.authority_expiry_sweep_request,
            &fixtures.expired_command_review_clock,
            &fixtures.accepted_authority_expiry_sweep_review,
        ),
        "authority expiry sweep evaluator deterministically accepts expired active leases and stream subscriptions",
    );

    push_result(
        checks,
        "validation.check.authority_expiry_sweep_authority_review_stale_revision",
        authority_expiry_sweep_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.stale_authority_expiry_sweep_request,
            &fixtures.expired_command_review_clock,
            &fixtures.stale_authority_expiry_sweep_review,
        ),
        "authority expiry sweep evaluator deterministically rejects stale authority revisions",
    );

    push_result(
        checks,
        "validation.check.authority_expiry_sweep_authority_review_registry_mismatch",
        authority_expiry_sweep_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.registry_mismatch_authority_expiry_sweep_request,
            &fixtures.expired_command_review_clock,
            &fixtures.registry_mismatch_authority_expiry_sweep_review,
        ),
        "authority expiry sweep evaluator deterministically rejects stale registry revisions",
    );

    push_result(
        checks,
        "validation.check.authority_expiry_sweep_authority_review_no_expired",
        authority_expiry_sweep_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.authority_expiry_sweep_request,
            &fixtures.command_review_clock,
            &fixtures.no_expired_authority_expiry_sweep_review,
        ),
        "authority expiry sweep evaluator deterministically rejects sweeps with no expired active state",
    );

    push_result(
        checks,
        "validation.check.authority_expiry_sweep_authority_application_rejection_fixture",
        if fixtures
            .authority_expiry_sweep_application_rejection
            .rejection_code
            .as_str()
            == "review_rejected"
            && fixtures
                .authority_expiry_sweep_application_rejection
                .current_authority_revision
                == fixtures
                    .stream_subscription_active_authority_snapshot
                    .authority_revision
        {
            Ok(())
        } else {
            Err("standalone authority expiry sweep application rejection fixture is not the expected review-rejected rejection"
                .to_owned())
        },
        "standalone authority expiry sweep application rejection fixture is a review-rejected rejection",
    );

    push_result(
        checks,
        "validation.check.authority_expiry_sweep_authority_application_accepted",
        authority_expiry_sweep_application_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.accepted_authority_expiry_sweep_review,
            &fixtures.accepted_authority_expiry_sweep_application,
        ),
        "authority expiry sweep application deterministically removes expired accepted state",
    );

    push_result(
        checks,
        "validation.check.authority_expiry_sweep_authority_application_rejected",
        authority_expiry_sweep_application_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.stale_authority_expiry_sweep_review,
            &fixtures.rejected_authority_expiry_sweep_application,
        ),
        "authority expiry sweep application deterministically rejects rejected sweep reviews",
    );
}
