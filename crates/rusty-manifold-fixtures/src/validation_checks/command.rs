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

    push_result(
        checks,
        "validation.check.remote_camera_authority_snapshot_links",
        fixtures
            .remote_camera_authority_snapshot
            .validate_authority_links(),
        "remote-camera authority snapshot aligns host capabilities, command descriptors, and active session lease",
    );

    push_result(
        checks,
        "validation.check.remote_camera_command_reviews_match_evaluator",
        remote_camera_command_reviews_match_evaluator(fixtures),
        "remote-camera receiver, sender, status, and stop reviews are deterministic authority decisions",
    );

    push_result(
        checks,
        "validation.check.remote_camera_command_dispatches_match_evaluator",
        remote_camera_command_dispatches_match_evaluator(fixtures),
        "remote-camera command dispatch receipts are deterministic source-only handoffs",
    );

    push_result(
        checks,
        "validation.check.remote_camera_receiver_first_sequence",
        remote_camera_receiver_first_sequence(fixtures),
        "remote-camera dispatch fixtures preserve receiver-first startup, status readback, and immediate stop order",
    );
}

fn remote_camera_command_reviews_match_evaluator(fixtures: &FixtureSet) -> Result<(), String> {
    for review in &fixtures.remote_camera_command_reviews {
        command_review_matches_fixture(
            &fixtures.remote_camera_authority_snapshot,
            &review.audit_event.envelope,
            &review.audit_event.recorded_clock,
            review,
        )?;

        if review.outcome != ManifoldCommandAuthorityReviewOutcome::CommandAccepted {
            return Err(format!(
                "remote-camera review {} was not accepted",
                review.review_id
            ));
        }
    }

    Ok(())
}

fn remote_camera_command_dispatches_match_evaluator(fixtures: &FixtureSet) -> Result<(), String> {
    if fixtures.remote_camera_command_reviews.len()
        != fixtures.remote_camera_command_dispatches.len()
    {
        return Err("remote-camera review/dispatch fixture count mismatch".to_owned());
    }

    for (review, dispatch) in fixtures
        .remote_camera_command_reviews
        .iter()
        .zip(fixtures.remote_camera_command_dispatches.iter())
    {
        command_dispatch_matches_fixture(
            &fixtures.remote_camera_authority_snapshot,
            review,
            dispatch,
        )?;

        if dispatch.outcome != ManifoldCommandDispatchReceiptOutcome::CommandDispatchReady {
            return Err(format!(
                "remote-camera dispatch {} was not ready",
                dispatch.dispatch_id
            ));
        }
    }

    Ok(())
}

fn remote_camera_receiver_first_sequence(fixtures: &FixtureSet) -> Result<(), String> {
    let expected_command_ids = [
        "command.remote_camera.start_receiver",
        "command.remote_camera.start_sender",
        "command.remote_camera.get_status",
        "command.remote_camera.stop",
    ];
    let mut previous_accepted_at_ms = 0;

    for (expected_command_id, dispatch) in expected_command_ids
        .iter()
        .zip(fixtures.remote_camera_command_dispatches.iter())
    {
        if dispatch.command_id.as_str() != *expected_command_id {
            return Err(format!(
                "expected remote-camera dispatch command {expected_command_id}, got {}",
                dispatch.command_id
            ));
        }

        let ack = dispatch
            .ack
            .as_ref()
            .ok_or_else(|| format!("dispatch {} is missing ack", dispatch.dispatch_id))?;
        if ack.accepted_at_ms <= previous_accepted_at_ms {
            return Err(format!(
                "dispatch {} did not advance accepted_at_ms",
                dispatch.dispatch_id
            ));
        }
        previous_accepted_at_ms = ack.accepted_at_ms;
    }

    let start_receiver = fixtures
        .remote_camera_command_dispatches
        .first()
        .expect("remote-camera dispatch sequence is non-empty");
    if start_receiver
        .ack
        .as_ref()
        .and_then(|ack| ack.lease_id.as_ref())
        .is_none()
    {
        return Err(
            "remote-camera start_receiver dispatch must carry the session lease".to_owned(),
        );
    }

    let start_sender = &fixtures.remote_camera_command_dispatches[1];
    if start_sender
        .ack
        .as_ref()
        .and_then(|ack| ack.lease_id.as_ref())
        .is_none()
    {
        return Err("remote-camera start_sender dispatch must carry the session lease".to_owned());
    }

    let stop = fixtures
        .remote_camera_command_dispatches
        .last()
        .expect("remote-camera dispatch sequence is non-empty");
    if stop
        .ack
        .as_ref()
        .and_then(|ack| ack.lease_id.as_ref())
        .is_some()
    {
        return Err("remote-camera stop dispatch must remain lease-free".to_owned());
    }

    Ok(())
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
