use super::*;

pub(super) fn push_module_runtime_checks(
    checks: &mut Vec<ValidationCheckReport>,
    fixtures: &FixtureSet,
) {
    push_result(
        checks,
        "validation.check.module_runtime_state_request_fixture",
        if fixtures.module_runtime_state_change_request.proposed_state
            == fixtures.next_provider_runtime
        {
            Ok(())
        } else {
            Err(
                "module runtime-state change request does not embed the v2 provider state fixture"
                    .to_owned(),
            )
        },
        "module runtime-state change request embeds the accepted provider runtime-state fixture",
    );

    push_result(
        checks,
        "validation.check.module_runtime_state_authority_audit_event",
        fixtures
            .module_runtime_state_authority_audit_event
            .validate_against_snapshot(&fixtures.authority_snapshot),
        "module runtime-state authority audit event matches the accepted request, lease, clock, and snapshot",
    );

    push_result(
        checks,
        "validation.check.module_runtime_state_rejection_fixture",
        if fixtures
            .module_runtime_state_rejection
            .rejection_code
            .as_str()
            == "stale_revision"
            && fixtures.module_runtime_state_rejection.retryable
            && fixtures
                .module_runtime_state_rejection
                .current_authority_revision
                == Revision::INITIAL
            && fixtures
                .module_runtime_state_rejection
                .current_runtime_revision
                == Some(Revision::INITIAL)
        {
            Ok(())
        } else {
            Err("standalone module runtime-state rejection fixture is not the expected stale-revision rejection"
                .to_owned())
        },
        "standalone module runtime-state rejection fixture is a stale-revision rejection",
    );

    push_result(
        checks,
        "validation.check.module_runtime_state_authority_review_accepted",
        module_runtime_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.module_runtime_state_change_request,
            &fixtures.command_review_clock,
            &fixtures.accepted_module_runtime_review,
        ),
        "module runtime-state authority evaluator deterministically accepts a lease-scoped stop transition",
    );

    push_result(
        checks,
        "validation.check.module_runtime_state_authority_review_expired_lease",
        module_runtime_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.module_runtime_state_change_request,
            &fixtures.expired_command_review_clock,
            &fixtures.expired_lease_module_runtime_review,
        ),
        "module runtime-state authority evaluator deterministically rejects leases expired at the review clock",
    );

    push_result(
        checks,
        "validation.check.module_runtime_state_authority_review_stale_revision",
        module_runtime_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.stale_module_runtime_request,
            &fixtures.command_review_clock,
            &fixtures.stale_module_runtime_review,
        ),
        "module runtime-state authority evaluator deterministically rejects stale authority revisions",
    );

    push_result(
        checks,
        "validation.check.module_runtime_state_authority_review_missing_lease",
        module_runtime_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.missing_lease_module_runtime_request,
            &fixtures.command_review_clock,
            &fixtures.missing_lease_module_runtime_review,
        ),
        "module runtime-state authority evaluator deterministically rejects missing module leases",
    );

    push_result(
        checks,
        "validation.check.module_runtime_state_authority_review_unknown_stream",
        module_runtime_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.unknown_stream_module_runtime_request,
            &fixtures.command_review_clock,
            &fixtures.unknown_stream_module_runtime_review,
        ),
        "module runtime-state authority evaluator deterministically rejects unknown active streams",
    );

    push_result(
        checks,
        "validation.check.module_runtime_state_authority_review_missing_backend",
        module_runtime_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.missing_backend_module_runtime_request,
            &fixtures.command_review_clock,
            &fixtures.missing_backend_module_runtime_review,
        ),
        "module runtime-state authority evaluator deterministically rejects unsupported backends",
    );

    push_result(
        checks,
        "validation.check.module_runtime_state_authority_application_rejection_fixture",
        if fixtures
            .module_runtime_application_rejection
            .rejection_code
            .as_str()
            == "review_rejected"
            && fixtures
                .module_runtime_application_rejection
                .current_authority_revision
                == Revision::INITIAL
        {
            Ok(())
        } else {
            Err("standalone module runtime-state application rejection fixture is not the expected review-rejected rejection"
                .to_owned())
        },
        "standalone module runtime-state application rejection fixture is a review-rejected rejection",
    );

    push_result(
        checks,
        "validation.check.module_runtime_state_authority_application_accepted",
        module_runtime_application_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.accepted_module_runtime_review,
            &fixtures.accepted_module_runtime_application,
        ),
        "module runtime-state authority application deterministically advances accepted runtime state",
    );

    push_result(
        checks,
        "validation.check.module_runtime_state_authority_application_rejected",
        module_runtime_application_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.stale_module_runtime_review,
            &fixtures.rejected_module_runtime_application,
        ),
        "module runtime-state authority application deterministically rejects rejected runtime-state reviews",
    );
}
