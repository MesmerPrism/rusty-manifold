use super::*;

#[test]
fn command_envelope_accepts_matching_descriptor_revision_and_lease() {
    let result = command_envelope().validate_request(
        &command_descriptor(),
        Revision::INITIAL,
        Some(&active_lease()),
    );

    assert_eq!(result, Ok(()));
}

#[test]
fn command_envelope_rejects_stale_revision() {
    let current_revision = Revision::new(2).unwrap();
    let error = command_envelope()
        .validate_request(
            &command_descriptor(),
            current_revision,
            Some(&active_lease()),
        )
        .unwrap_err();

    assert_eq!(error.kind(), CommandValidationErrorKind::StaleRevision);
    assert_eq!(error.rejection_code(), "stale_revision");
}

#[test]
fn command_envelope_rejects_missing_required_lease() {
    let error = command_envelope()
        .validate_request(&command_descriptor(), Revision::INITIAL, None)
        .unwrap_err();

    assert_eq!(error.kind(), CommandValidationErrorKind::MissingLease);
    assert_eq!(error.rejection_code(), "missing_lease");
}

#[test]
fn authority_snapshot_validates_command_stream_host_clock_and_leases() {
    let snapshot = authority_snapshot();

    assert_eq!(snapshot.validate_authority_links(), Ok(()));
}

#[test]
fn command_authority_audit_event_validates_accepted_command() {
    let snapshot = authority_snapshot();
    let event = accepted_command_audit_event();

    assert_eq!(event.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn command_authority_review_accepts_valid_command() {
    let snapshot = authority_snapshot();
    let envelope = command_envelope();
    let review = snapshot
        .review_command(
            envelope,
            command_review_clock(),
            vec![id(
                "evidence.command_authority.request.start.synthetic_wave",
            )],
        )
        .unwrap();

    assert_eq!(
        review.outcome,
        ManifoldCommandAuthorityReviewOutcome::CommandAccepted
    );
    assert!(review.accepted.is_some());
    assert!(review.rejection.is_none());
    assert_eq!(review.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn command_authority_audit_event_rejects_skipped_acceptance_revision() {
    let snapshot = authority_snapshot();
    let mut event = accepted_command_audit_event();
    event
        .accepted
        .as_mut()
        .expect("accepted fixture is present")
        .accepted_revision = Revision::new(3).unwrap();

    let error = event.validate_against_snapshot(&snapshot).unwrap_err();

    assert_eq!(error.rejection_code(), "acceptance_revision_mismatch");
}

#[test]
fn command_dispatch_receipt_prepares_accepted_review() {
    let snapshot = authority_snapshot();
    let review = snapshot
        .review_command(
            command_envelope(),
            command_review_clock(),
            vec![id(
                "evidence.command_authority.request.start.synthetic_wave",
            )],
        )
        .unwrap();
    let receipt = snapshot.prepare_command_dispatch(review.clone()).unwrap();

    assert_eq!(
        receipt.outcome,
        ManifoldCommandDispatchReceiptOutcome::CommandDispatchReady
    );
    assert_eq!(receipt.ack, review.accepted);
    assert!(receipt.rejection.is_none());
    assert_eq!(receipt.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn command_dispatch_receipt_rejects_review_from_different_authority_revision() {
    let snapshot = authority_snapshot();
    let review = snapshot
        .review_command(
            command_envelope(),
            command_review_clock(),
            vec![id(
                "evidence.command_authority.request.start.synthetic_wave",
            )],
        )
        .unwrap();
    let mut next_snapshot = snapshot.clone();
    next_snapshot.authority_revision = Revision::new(2).unwrap();

    let error = next_snapshot.prepare_command_dispatch(review).unwrap_err();

    assert_eq!(error.rejection_code(), "authority_revision_mismatch");
}

#[test]
fn command_dispatch_receipt_rejects_receipt_review_request_mismatch() {
    let snapshot = authority_snapshot();
    let review = snapshot
        .review_command(
            command_envelope(),
            command_review_clock(),
            vec![id(
                "evidence.command_authority.request.start.synthetic_wave",
            )],
        )
        .unwrap();
    let mut receipt = snapshot.prepare_command_dispatch(review).unwrap();
    receipt.request_id = id("request.command_dispatch.lineage_mismatch");

    let error = receipt.validate_against_snapshot(&snapshot).unwrap_err();

    assert_eq!(error.rejection_code(), "request_id_mismatch");
}

#[test]
fn command_authority_audit_event_rejects_unknown_command() {
    let snapshot = authority_snapshot();
    let mut event = accepted_command_audit_event();
    event.envelope.command_id = id("command.module.not_registered");

    let error = event.validate_against_snapshot(&snapshot).unwrap_err();

    assert_eq!(error.rejection_code(), "unknown_command");
}

#[test]
fn command_authority_review_rejects_missing_lease() {
    let snapshot = authority_snapshot();
    let mut envelope = command_envelope();
    envelope.request_id = id("request.missing_lease.synthetic_wave");
    envelope.lease_id = None;
    let review = snapshot
        .review_command(
            envelope,
            command_review_clock(),
            vec![id(
                "evidence.command_authority.request.missing_lease.synthetic_wave",
            )],
        )
        .unwrap();

    assert_eq!(
        review.outcome,
        ManifoldCommandAuthorityReviewOutcome::CommandRejected
    );
    assert_eq!(
        review.rejection.as_ref().unwrap().rejection_code.as_str(),
        "missing_lease"
    );
    assert_eq!(review.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn command_dispatch_receipt_rejects_rejected_review() {
    let snapshot = authority_snapshot();
    let mut envelope = command_envelope();
    envelope.request_id = id("request.missing_lease.synthetic_wave");
    envelope.lease_id = None;
    let review = snapshot
        .review_command(
            envelope,
            command_review_clock(),
            vec![id(
                "evidence.command_authority.request.missing_lease.synthetic_wave",
            )],
        )
        .unwrap();
    let receipt = snapshot.prepare_command_dispatch(review).unwrap();

    assert_eq!(
        receipt.outcome,
        ManifoldCommandDispatchReceiptOutcome::CommandDispatchRejected
    );
    assert!(receipt.ack.is_none());
    assert_eq!(
        receipt
            .rejection
            .as_ref()
            .expect("dispatch rejection is present")
            .rejection_code
            .as_str(),
        "review_rejected"
    );
    assert_eq!(receipt.validate_against_snapshot(&snapshot), Ok(()));
}
