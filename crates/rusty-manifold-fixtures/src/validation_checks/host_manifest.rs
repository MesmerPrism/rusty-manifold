use super::*;

pub(super) fn push_host_manifest_checks(
    checks: &mut Vec<ValidationCheckReport>,
    fixtures: &FixtureSet,
) {
    push_result(
        checks,
        "validation.check.host_manifest_lease_fixture",
        if fixtures.host_manifest_lease.scope.as_str() == "manifold.host_manifest"
            && fixtures.host_manifest_lease.holder_id
                == fixtures.host_manifest_change_request.holder_id
            && fixtures.host_manifest_change_request.lease_id.as_ref()
                == Some(&fixtures.host_manifest_lease.lease_id)
        {
            Ok(())
        } else {
            Err(
                "host manifest lease fixture does not authorize the host manifest request"
                    .to_owned(),
            )
        },
        "host manifest lease fixture authorizes the accepted host manifest request",
    );

    push_result(
        checks,
        "validation.check.host_manifest_authority_audit_event",
        fixtures
            .host_manifest_authority_audit_event
            .validate_against_snapshot(&fixtures.authority_snapshot),
        "host manifest authority audit event matches the accepted request, lease, clock, and snapshot",
    );

    push_result(
        checks,
        "validation.check.host_manifest_rejection_fixture",
        if fixtures.host_manifest_rejection.rejection_code.as_str() == "stale_revision"
            && fixtures.host_manifest_rejection.retryable
            && fixtures.host_manifest_rejection.current_authority_revision == Revision::INITIAL
        {
            Ok(())
        } else {
            Err(
                "standalone host manifest rejection fixture is not the expected stale-revision rejection"
                    .to_owned(),
            )
        },
        "standalone host manifest rejection fixture is a stale-revision rejection",
    );

    push_result(
        checks,
        "validation.check.host_manifest_authority_review_accepted",
        host_manifest_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.host_manifest_change_request,
            &fixtures.command_review_clock,
            &fixtures.accepted_host_manifest_review,
        ),
        "host manifest authority evaluator deterministically accepts a lease-scoped permission change",
    );

    push_result(
        checks,
        "validation.check.host_manifest_authority_review_expired_lease",
        host_manifest_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.host_manifest_change_request,
            &fixtures.expired_command_review_clock,
            &fixtures.expired_lease_host_manifest_review,
        ),
        "host manifest authority evaluator deterministically rejects leases expired at the review clock",
    );

    push_result(
        checks,
        "validation.check.host_manifest_authority_review_stale_revision",
        host_manifest_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.stale_host_manifest_request,
            &fixtures.command_review_clock,
            &fixtures.stale_host_manifest_review,
        ),
        "host manifest authority evaluator deterministically rejects stale authority revisions",
    );

    push_result(
        checks,
        "validation.check.host_manifest_authority_review_missing_authority_role",
        host_manifest_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.missing_authority_role_host_manifest_request,
            &fixtures.command_review_clock,
            &fixtures.missing_authority_role_host_manifest_review,
        ),
        "host manifest authority evaluator deterministically rejects missing authority roles",
    );

    push_result(
        checks,
        "validation.check.host_manifest_authority_review_endpoint_mismatch",
        host_manifest_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.endpoint_mismatch_host_manifest_request,
            &fixtures.command_review_clock,
            &fixtures.endpoint_mismatch_host_manifest_review,
        ),
        "host manifest authority evaluator deterministically rejects unsafe endpoint pairings",
    );

    push_result(
        checks,
        "validation.check.host_manifest_authority_review_remove_capability",
        host_manifest_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.remove_capability_host_manifest_request,
            &fixtures.command_review_clock,
            &fixtures.remove_capability_host_manifest_review,
        ),
        "host manifest authority evaluator deterministically rejects capability removal while active leases or commands use it",
    );

    push_result(
        checks,
        "validation.check.host_manifest_authority_review_remove_backend",
        host_manifest_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.remove_backend_host_manifest_request,
            &fixtures.command_review_clock,
            &fixtures.remove_backend_host_manifest_review,
        ),
        "host manifest authority evaluator deterministically rejects backend removal while active modules use it",
    );

    push_result(
        checks,
        "validation.check.host_manifest_authority_application_rejection_fixture",
        if fixtures
            .host_manifest_application_rejection
            .rejection_code
            .as_str()
            == "review_rejected"
            && fixtures
                .host_manifest_application_rejection
                .current_authority_revision
                == Revision::INITIAL
        {
            Ok(())
        } else {
            Err("standalone host manifest application rejection fixture is not the expected review-rejected rejection"
                .to_owned())
        },
        "standalone host manifest application rejection fixture is a review-rejected rejection",
    );

    push_result(
        checks,
        "validation.check.host_manifest_authority_application_accepted",
        host_manifest_application_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.accepted_host_manifest_review,
            &fixtures.accepted_host_manifest_application,
        ),
        "host manifest authority application deterministically advances accepted host state",
    );

    push_result(
        checks,
        "validation.check.host_manifest_authority_application_rejected",
        host_manifest_application_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.stale_host_manifest_review,
            &fixtures.rejected_host_manifest_application,
        ),
        "host manifest authority application deterministically rejects rejected host manifest reviews",
    );
}
