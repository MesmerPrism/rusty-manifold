use super::*;

pub(super) fn push_lease_checks(checks: &mut Vec<ValidationCheckReport>, fixtures: &FixtureSet) {
    push_result(
        checks,
        "validation.check.lease_authority_audit_event",
        fixtures
            .lease_authority_audit_event
            .validate_against_snapshot(&fixtures.authority_snapshot),
        "lease authority audit event matches the accepted request, lease, clock, and snapshot",
    );

    push_result(
        checks,
        "validation.check.lease_authority_rejection_fixture",
        if fixtures.lease_rejection.rejection_code.as_str() == "stale_revision"
            && fixtures.lease_rejection.retryable
            && fixtures.lease_rejection.current_revision == Revision::INITIAL
            && fixtures.lease_rejection.conflicting_lease_id.is_none()
        {
            Ok(())
        } else {
            Err(
                "standalone lease rejection fixture is not the expected stale-revision rejection"
                    .to_owned(),
            )
        },
        "standalone lease rejection fixture is a non-conflict stale-revision rejection",
    );

    push_result(
        checks,
        "validation.check.lease_authority_review_accepted",
        lease_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.lease_request,
            &fixtures.command_review_clock,
            &fixtures.accepted_lease_review,
        ),
        "lease authority evaluator deterministically accepts an available graph lease",
    );

    push_result(
        checks,
        "validation.check.lease_authority_review_stale_revision",
        lease_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.stale_lease_request,
            &fixtures.command_review_clock,
            &fixtures.stale_revision_lease_review,
        ),
        "lease authority evaluator deterministically rejects stale lease revisions",
    );

    push_result(
        checks,
        "validation.check.lease_authority_review_zero_ttl",
        lease_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.zero_ttl_lease_request,
            &fixtures.command_review_clock,
            &fixtures.zero_ttl_lease_review,
        ),
        "lease authority evaluator deterministically rejects zero-duration leases",
    );

    push_result(
        checks,
        "validation.check.lease_authority_review_missing_capability",
        lease_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.missing_capability_lease_request,
            &fixtures.command_review_clock,
            &fixtures.missing_capability_lease_review,
        ),
        "lease authority evaluator deterministically rejects unadvertised capabilities",
    );

    push_result(
        checks,
        "validation.check.lease_authority_review_busy_scope",
        lease_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.busy_scope_lease_request,
            &fixtures.command_review_clock,
            &fixtures.busy_scope_lease_review,
        ),
        "lease authority evaluator deterministically rejects active-lease scope conflicts",
    );

    push_result(
        checks,
        "validation.check.lease_authority_application_rejection_fixture",
        if fixtures.lease_application_rejection.rejection_code.as_str() == "review_rejected"
            && fixtures
                .lease_application_rejection
                .current_authority_revision
                == Revision::INITIAL
        {
            Ok(())
        } else {
            Err("standalone lease application rejection fixture is not the expected review-rejected rejection"
                .to_owned())
        },
        "standalone lease application rejection fixture is a review-rejected rejection",
    );

    push_result(
        checks,
        "validation.check.lease_authority_application_accepted",
        lease_application_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.accepted_lease_review,
            &fixtures.accepted_lease_application,
        ),
        "lease authority application deterministically advances accepted lease state",
    );

    push_result(
        checks,
        "validation.check.lease_authority_application_rejected",
        lease_application_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.stale_revision_lease_review,
            &fixtures.rejected_lease_application,
        ),
        "lease authority application deterministically rejects rejected lease reviews",
    );

    let lease_release_authority_revision = Revision::new(2).expect("revision literal is valid");
    push_result(
        checks,
        "validation.check.lease_release_authority_snapshot",
        fixtures
            .lease_active_authority_snapshot
            .validate_authority_links(),
        "lease release authority snapshot has the accepted active lease from lease application",
    );

    push_result(
        checks,
        "validation.check.lease_release_request_fixture",
        if fixtures
            .lease_active_authority_snapshot
            .active_leases
            .iter()
            .any(|lease| {
                lease.lease_id == fixtures.lease_release_request.lease_id
                    && lease.holder_id == fixtures.lease_release_request.holder_id
                    && lease.scope == fixtures.lease_release_request.scope
            })
            && fixtures.lease_release_request.expected_authority_revision
                == fixtures.lease_active_authority_snapshot.authority_revision
        {
            Ok(())
        } else {
            Err("lease release request does not target the active lease snapshot".to_owned())
        },
        "lease release request targets an accepted active lease",
    );

    push_result(
        checks,
        "validation.check.lease_release_rejection_fixture",
        if fixtures.lease_release_rejection.rejection_code.as_str() == "stale_revision"
            && fixtures.lease_release_rejection.retryable
            && fixtures.lease_release_rejection.current_revision == lease_release_authority_revision
            && fixtures.lease_release_rejection.active_lease_count
                == fixtures.lease_active_authority_snapshot.active_leases.len()
        {
            Ok(())
        } else {
            Err("standalone lease release rejection fixture is not the expected stale-revision rejection".to_owned())
        },
        "standalone lease release rejection fixture is a stale-revision rejection",
    );

    push_result(
        checks,
        "validation.check.lease_release_authority_audit_event",
        fixtures
            .lease_release_authority_audit_event
            .validate_against_snapshot(&fixtures.lease_active_authority_snapshot),
        "lease release authority audit event matches the accepted request, clock, and active snapshot",
    );

    push_result(
        checks,
        "validation.check.lease_release_authority_review_accepted",
        lease_release_review_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.lease_release_request,
            &fixtures.command_review_clock,
            &fixtures.accepted_lease_release_review,
        ),
        "lease release authority evaluator deterministically accepts active lease release",
    );

    push_result(
        checks,
        "validation.check.lease_release_authority_review_expired_lease",
        lease_release_review_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.lease_release_request,
            &fixtures.expired_command_review_clock,
            &fixtures.expired_lease_release_review,
        ),
        "lease release authority evaluator deterministically rejects leases expired at the review clock",
    );

    push_result(
        checks,
        "validation.check.lease_release_authority_review_stale_revision",
        lease_release_review_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.stale_lease_release_request,
            &fixtures.command_review_clock,
            &fixtures.stale_lease_release_review,
        ),
        "lease release authority evaluator deterministically rejects stale authority revisions",
    );

    push_result(
        checks,
        "validation.check.lease_release_authority_review_unknown_lease",
        lease_release_review_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.unknown_lease_release_request,
            &fixtures.command_review_clock,
            &fixtures.unknown_lease_release_review,
        ),
        "lease release authority evaluator deterministically rejects unknown leases",
    );

    push_result(
        checks,
        "validation.check.lease_release_authority_review_holder_mismatch",
        lease_release_review_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.holder_mismatch_lease_release_request,
            &fixtures.command_review_clock,
            &fixtures.holder_mismatch_lease_release_review,
        ),
        "lease release authority evaluator deterministically rejects holder mismatches",
    );

    push_result(
        checks,
        "validation.check.lease_release_authority_review_scope_mismatch",
        lease_release_review_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.scope_mismatch_lease_release_request,
            &fixtures.command_review_clock,
            &fixtures.scope_mismatch_lease_release_review,
        ),
        "lease release authority evaluator deterministically rejects scope mismatches",
    );

    push_result(
        checks,
        "validation.check.lease_release_authority_application_rejection_fixture",
        if fixtures
            .lease_release_application_rejection
            .rejection_code
            .as_str()
            == "review_rejected"
            && fixtures
                .lease_release_application_rejection
                .current_authority_revision
                == lease_release_authority_revision
        {
            Ok(())
        } else {
            Err("standalone lease release application rejection fixture is not the expected review-rejected rejection"
                .to_owned())
        },
        "standalone lease release application rejection fixture is a review-rejected rejection",
    );

    push_result(
        checks,
        "validation.check.lease_release_authority_application_accepted",
        lease_release_application_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.accepted_lease_release_review,
            &fixtures.accepted_lease_release_application,
        ),
        "lease release authority application deterministically removes accepted active lease state",
    );

    push_result(
        checks,
        "validation.check.lease_release_authority_application_rejected",
        lease_release_application_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.stale_lease_release_review,
            &fixtures.rejected_lease_release_application,
        ),
        "lease release authority application deterministically rejects rejected release reviews",
    );

    let lease_renewal_expected_expires_at_ms =
        u64::try_from(fixtures.command_review_clock.wall_unix_ms)
            .unwrap_or_default()
            .saturating_add(fixtures.lease_renewal_request.requested_ttl_ms);
    push_result(
        checks,
        "validation.check.lease_renewal_request_fixture",
        match fixtures
            .lease_active_authority_snapshot
            .active_leases
            .iter()
            .find(|lease| {
                lease.lease_id == fixtures.lease_renewal_request.lease_id
                    && lease.holder_id == fixtures.lease_renewal_request.holder_id
                    && lease.scope == fixtures.lease_renewal_request.scope
            }) {
            Some(lease)
                if fixtures.lease_renewal_request.expected_authority_revision
                    == fixtures.lease_active_authority_snapshot.authority_revision
                    && fixtures.lease_renewal_request.requested_ttl_ms > 0
                    && lease_renewal_expected_expires_at_ms > lease.expires_at_ms =>
            {
                Ok(())
            }
            _ => Err("lease renewal request does not extend the active lease snapshot".to_owned()),
        },
        "lease renewal request targets and extends an accepted active lease",
    );

    push_result(
        checks,
        "validation.check.lease_renewal_rejection_fixture",
        if fixtures.lease_renewal_rejection.rejection_code.as_str() == "stale_revision"
            && fixtures.lease_renewal_rejection.retryable
            && fixtures.lease_renewal_rejection.current_revision == lease_release_authority_revision
            && fixtures.lease_renewal_rejection.active_lease_count
                == fixtures.lease_active_authority_snapshot.active_leases.len()
            && fixtures
                .lease_renewal_rejection
                .current_expires_at_ms
                .is_none()
        {
            Ok(())
        } else {
            Err("standalone lease renewal rejection fixture is not the expected stale-revision rejection".to_owned())
        },
        "standalone lease renewal rejection fixture is a stale-revision rejection",
    );

    push_result(
        checks,
        "validation.check.lease_renewal_authority_audit_event",
        fixtures
            .lease_renewal_authority_audit_event
            .validate_against_snapshot(&fixtures.lease_active_authority_snapshot),
        "lease renewal authority audit event matches the accepted request, clock, and active snapshot",
    );

    push_result(
        checks,
        "validation.check.lease_renewal_authority_review_accepted",
        lease_renewal_review_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.lease_renewal_request,
            &fixtures.command_review_clock,
            &fixtures.accepted_lease_renewal_review,
        ),
        "lease renewal authority evaluator deterministically accepts active lease renewal",
    );

    push_result(
        checks,
        "validation.check.lease_renewal_authority_review_stale_revision",
        lease_renewal_review_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.stale_lease_renewal_request,
            &fixtures.command_review_clock,
            &fixtures.stale_lease_renewal_review,
        ),
        "lease renewal authority evaluator deterministically rejects stale authority revisions",
    );

    push_result(
        checks,
        "validation.check.lease_renewal_authority_review_unknown_lease",
        lease_renewal_review_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.unknown_lease_renewal_request,
            &fixtures.command_review_clock,
            &fixtures.unknown_lease_renewal_review,
        ),
        "lease renewal authority evaluator deterministically rejects unknown leases",
    );

    push_result(
        checks,
        "validation.check.lease_renewal_authority_review_holder_mismatch",
        lease_renewal_review_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.holder_mismatch_lease_renewal_request,
            &fixtures.command_review_clock,
            &fixtures.holder_mismatch_lease_renewal_review,
        ),
        "lease renewal authority evaluator deterministically rejects holder mismatches",
    );

    push_result(
        checks,
        "validation.check.lease_renewal_authority_review_scope_mismatch",
        lease_renewal_review_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.scope_mismatch_lease_renewal_request,
            &fixtures.command_review_clock,
            &fixtures.scope_mismatch_lease_renewal_review,
        ),
        "lease renewal authority evaluator deterministically rejects scope mismatches",
    );

    push_result(
        checks,
        "validation.check.lease_renewal_authority_review_zero_ttl",
        lease_renewal_review_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.zero_ttl_lease_renewal_request,
            &fixtures.command_review_clock,
            &fixtures.zero_ttl_lease_renewal_review,
        ),
        "lease renewal authority evaluator deterministically rejects zero-duration renewals",
    );

    push_result(
        checks,
        "validation.check.lease_renewal_authority_review_non_extending",
        lease_renewal_review_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.non_extending_lease_renewal_request,
            &fixtures.command_review_clock,
            &fixtures.non_extending_lease_renewal_review,
        ),
        "lease renewal authority evaluator deterministically rejects non-extending renewals",
    );

    push_result(
        checks,
        "validation.check.lease_renewal_authority_review_expired_lease",
        lease_renewal_review_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.lease_renewal_request,
            &fixtures.expired_command_review_clock,
            &fixtures.expired_lease_renewal_review,
        ),
        "lease renewal authority evaluator deterministically rejects leases expired at the review clock",
    );

    push_result(
        checks,
        "validation.check.lease_renewal_authority_application_rejection_fixture",
        if fixtures
            .lease_renewal_application_rejection
            .rejection_code
            .as_str()
            == "review_rejected"
            && fixtures
                .lease_renewal_application_rejection
                .current_authority_revision
                == lease_release_authority_revision
        {
            Ok(())
        } else {
            Err("standalone lease renewal application rejection fixture is not the expected review-rejected rejection"
                .to_owned())
        },
        "standalone lease renewal application rejection fixture is a review-rejected rejection",
    );

    push_result(
        checks,
        "validation.check.lease_renewal_authority_application_accepted",
        lease_renewal_application_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.accepted_lease_renewal_review,
            &fixtures.accepted_lease_renewal_application,
        ),
        "lease renewal authority application deterministically replaces accepted active lease state",
    );

    push_result(
        checks,
        "validation.check.lease_renewal_authority_application_rejected",
        lease_renewal_application_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.stale_lease_renewal_review,
            &fixtures.rejected_lease_renewal_application,
        ),
        "lease renewal authority application deterministically rejects rejected renewal reviews",
    );
}
