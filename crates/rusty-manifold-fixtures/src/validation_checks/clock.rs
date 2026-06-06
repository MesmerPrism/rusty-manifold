use super::*;

pub(super) fn push_clock_checks(checks: &mut Vec<ValidationCheckReport>, fixtures: &FixtureSet) {
    push_result(
        checks,
        "validation.check.clock_lease_fixture",
        if fixtures.clock_lease.scope.as_str() == "manifold.clock"
            && fixtures.clock_lease.holder_id == fixtures.clock_change_request.holder_id
            && fixtures.clock_change_request.lease_id.as_ref()
                == Some(&fixtures.clock_lease.lease_id)
        {
            Ok(())
        } else {
            Err("clock lease fixture does not authorize the clock request".to_owned())
        },
        "clock lease fixture authorizes the accepted clock request",
    );

    push_result(
        checks,
        "validation.check.clock_authority_audit_event",
        fixtures
            .clock_authority_audit_event
            .validate_against_snapshot(&fixtures.authority_snapshot),
        "clock authority audit event matches the accepted request, lease, clock, and snapshot",
    );

    push_result(
        checks,
        "validation.check.clock_rejection_fixture",
        if fixtures.clock_rejection.rejection_code.as_str() == "stale_revision"
            && fixtures.clock_rejection.retryable
            && fixtures.clock_rejection.current_authority_revision == Revision::INITIAL
            && fixtures.clock_rejection.current_clock_sequence == 42
        {
            Ok(())
        } else {
            Err(
                "standalone clock rejection fixture is not the expected stale-revision rejection"
                    .to_owned(),
            )
        },
        "standalone clock rejection fixture is a stale-revision rejection",
    );

    push_result(
        checks,
        "validation.check.clock_authority_review_accepted",
        clock_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.clock_change_request,
            &fixtures.command_review_clock,
            &fixtures.accepted_clock_review,
        ),
        "clock authority evaluator deterministically accepts a lease-scoped clock tick",
    );

    push_result(
        checks,
        "validation.check.clock_authority_review_expired_lease",
        clock_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.clock_change_request,
            &fixtures.expired_command_review_clock,
            &fixtures.expired_lease_clock_review,
        ),
        "clock authority evaluator deterministically rejects leases expired at the review clock",
    );

    push_result(
        checks,
        "validation.check.clock_authority_review_stale_revision",
        clock_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.stale_clock_request,
            &fixtures.command_review_clock,
            &fixtures.stale_clock_review,
        ),
        "clock authority evaluator deterministically rejects stale authority revisions",
    );

    push_result(
        checks,
        "validation.check.clock_authority_review_missing_lease",
        clock_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.missing_lease_clock_request,
            &fixtures.command_review_clock,
            &fixtures.missing_lease_clock_review,
        ),
        "clock authority evaluator deterministically rejects missing clock leases",
    );

    push_result(
        checks,
        "validation.check.clock_authority_review_domain_mismatch",
        clock_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.domain_mismatch_clock_request,
            &fixtures.command_review_clock,
            &fixtures.domain_mismatch_clock_review,
        ),
        "clock authority evaluator deterministically rejects clock-domain mismatches",
    );

    push_result(
        checks,
        "validation.check.clock_authority_review_sequence_gap",
        clock_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.sequence_gap_clock_request,
            &fixtures.command_review_clock,
            &fixtures.sequence_gap_clock_review,
        ),
        "clock authority evaluator deterministically rejects skipped clock sequences",
    );

    push_result(
        checks,
        "validation.check.clock_authority_review_monotonic_regression",
        clock_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.monotonic_regression_clock_request,
            &fixtures.command_review_clock,
            &fixtures.monotonic_regression_clock_review,
        ),
        "clock authority evaluator deterministically rejects monotonic time regressions",
    );

    push_result(
        checks,
        "validation.check.clock_authority_application_rejection_fixture",
        if fixtures.clock_application_rejection.rejection_code.as_str() == "review_rejected"
            && fixtures
                .clock_application_rejection
                .current_authority_revision
                == Revision::INITIAL
        {
            Ok(())
        } else {
            Err("standalone clock application rejection fixture is not the expected review-rejected rejection"
                .to_owned())
        },
        "standalone clock application rejection fixture is a review-rejected rejection",
    );

    push_result(
        checks,
        "validation.check.clock_authority_application_accepted",
        clock_application_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.accepted_clock_review,
            &fixtures.accepted_clock_application,
        ),
        "clock authority application deterministically advances accepted clock state",
    );

    push_result(
        checks,
        "validation.check.clock_authority_application_rejected",
        clock_application_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.stale_clock_review,
            &fixtures.rejected_clock_application,
        ),
        "clock authority application deterministically rejects rejected clock reviews",
    );
}
