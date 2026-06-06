use super::*;

pub(super) fn push_command_checks(checks: &mut Vec<ValidationCheckReport>, fixtures: &FixtureSet) {
    push_result(
        checks,
        "validation.check.command_accept",
        fixtures.valid_envelope.validate_request(
            &fixtures.command_descriptor,
            Revision::INITIAL,
            Some(&fixtures.control_lease),
        ),
        "command envelope matches descriptor, revision, holder, and lease",
    );

    push_result(
        checks,
        "validation.check.authority_snapshot_links",
        fixtures.authority_snapshot.validate_authority_links(),
        "authority snapshot aligns host, clock, stream registry, module runtime, commands, and leases",
    );

    push_result(
        checks,
        "validation.check.command_authority_audit_event",
        fixtures
            .command_authority_audit_event
            .validate_against_snapshot(&fixtures.authority_snapshot),
        "command authority audit event matches the accepted envelope, ack, lease, clock, and snapshot",
    );

    push_result(
        checks,
        "validation.check.command_authority_review_accepted",
        command_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.valid_envelope,
            &fixtures.command_review_clock,
            &fixtures.accepted_command_review,
        ),
        "command authority evaluator deterministically accepts a valid leased command",
    );

    push_result(
        checks,
        "validation.check.command_authority_review_stale_revision",
        command_review_matches_fixture(
            &fixtures.authority_snapshot_v2,
            &fixtures.damaged_stale_command,
            &fixtures.command_review_clock,
            &fixtures.stale_revision_command_review,
        ),
        "command authority evaluator deterministically rejects stale command revisions",
    );

    push_result(
        checks,
        "validation.check.command_authority_review_expired_lease",
        command_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.valid_envelope,
            &fixtures.expired_command_review_clock,
            &fixtures.expired_lease_command_review,
        ),
        "command authority evaluator deterministically rejects leases expired at the review clock",
    );

    push_result(
        checks,
        "validation.check.command_authority_review_missing_lease",
        command_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.damaged_missing_lease_command,
            &fixtures.command_review_clock,
            &fixtures.missing_lease_command_review,
        ),
        "command authority evaluator deterministically rejects commands missing a required lease",
    );

    push_result(
        checks,
        "validation.check.command_authority_review_unknown_command",
        command_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.unknown_command_review_envelope,
            &fixtures.command_review_clock,
            &fixtures.unknown_command_review,
        ),
        "command authority evaluator deterministically rejects commands absent from the authority snapshot",
    );

    push_result(
        checks,
        "validation.check.command_authority_review_unknown_lease",
        command_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.unknown_lease_review_envelope,
            &fixtures.command_review_clock,
            &fixtures.unknown_lease_command_review,
        ),
        "command authority evaluator deterministically rejects commands carrying an unknown lease",
    );

    push_result(
        checks,
        "validation.check.command_authority_review_capability_mismatch",
        command_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.capability_mismatch_review_envelope,
            &fixtures.command_review_clock,
            &fixtures.capability_mismatch_command_review,
        ),
        "command authority evaluator deterministically rejects capability mismatches",
    );

    push_result(
        checks,
        "validation.check.command_dispatch_rejection_fixture",
        if fixtures.command_dispatch_rejection.rejection_code.as_str() == "review_rejected"
            && fixtures.command_dispatch_rejection.retryable
            && fixtures
                .command_dispatch_rejection
                .current_authority_revision
                == Revision::INITIAL
        {
            Ok(())
        } else {
            Err("standalone command dispatch rejection fixture is not the expected review-rejected rejection".to_owned())
        },
        "standalone command dispatch rejection fixture is a review-rejected rejection",
    );

    push_result(
        checks,
        "validation.check.command_dispatch_receipt_ready",
        command_dispatch_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.accepted_command_review,
            &fixtures.accepted_command_dispatch,
        ),
        "command dispatch receipt deterministically prepares an accepted review without executing it",
    );

    push_result(
        checks,
        "validation.check.command_dispatch_receipt_rejected",
        command_dispatch_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.missing_lease_command_review,
            &fixtures.rejected_command_dispatch,
        ),
        "command dispatch receipt deterministically rejects rejected command reviews",
    );

    push_result(
        checks,
        "validation.check.command_dispatch_rejects_snapshot_revision_mismatch",
        command_dispatch_rejects_snapshot_revision_mismatch(
            &fixtures.authority_snapshot_v2,
            &fixtures.accepted_command_review,
        ),
        "command dispatch preparation rejects command reviews from a different authority snapshot revision",
    );

    push_result(
        checks,
        "validation.check.command_dispatch_receipt_rejects_request_lineage_mismatch",
        command_dispatch_receipt_rejects_request_lineage_mismatch(
            &fixtures.authority_snapshot,
            &fixtures.accepted_command_dispatch,
        ),
        "command dispatch receipt validation rejects top-level request ids that diverge from the embedded review",
    );
}

pub(super) fn push_damaged_command_checks(
    repo_root: &Path,
    checks: &mut Vec<ValidationCheckReport>,
    fixtures: &FixtureSet,
) -> Result<(), CliError> {
    push_damaged(
        checks,
        "validation.check.damaged_stale_revision",
        expected_rejection(repo_root, "fixtures/damaged/stale-revision-command.json")?,
        fixtures
            .damaged_stale_command
            .validate_request(
                &fixtures.command_descriptor,
                Revision::new(2).expect("literal is non-zero"),
                Some(&fixtures.control_lease),
            )
            .map_err(|error| error.rejection_code().to_owned()),
        "stale command revision is rejected",
    );

    push_damaged(
        checks,
        "validation.check.damaged_missing_lease",
        expected_rejection(
            repo_root,
            "fixtures/damaged/missing-lease-scope-command.json",
        )?,
        fixtures
            .damaged_missing_lease_command
            .validate_request(&fixtures.command_descriptor, Revision::INITIAL, None)
            .map_err(|error| error.rejection_code().to_owned()),
        "command requiring a lease is rejected when the lease is missing",
    );

    push_damaged(
        checks,
        "validation.check.damaged_authority_audit_unknown_command",
        expected_rejection(
            repo_root,
            "fixtures/damaged/authority-audit-unknown-command.json",
        )?,
        fixtures
            .damaged_command_authority_audit_event
            .validate_against_snapshot(&fixtures.authority_snapshot)
            .map_err(|error| error.rejection_code().to_owned()),
        "command authority audit event cannot accept a command absent from the authority model",
    );

    let bad_timestamp_path = repo_root.join("fixtures/damaged/bad-timestamp-domain.json");
    let bad_timestamp = read_model::<ManifoldStreamManifest>(&bad_timestamp_path);
    push_deserialize_rejection(
        checks,
        "validation.check.damaged_bad_timestamp_domain",
        expected_rejection(repo_root, "fixtures/damaged/bad-timestamp-domain.json")?,
        bad_timestamp,
        "invalid timestamp-domain id is rejected during deserialization",
    );

    Ok(())
}
