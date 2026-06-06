use super::*;

pub(super) fn review_shell_handoff(
    repo_root: &Path,
    handoff_path: &Path,
) -> Result<ManifoldShellHandoffReviewReceipt, CliError> {
    let fixtures = FixtureSet::load(repo_root)?;
    let handoff = read_model::<ManifoldShellHandoffManifest>(handoff_path)?;
    let endpoint_ids = fixtures.endpoint_ids();
    let receipt = handoff.review_receipt(
        &fixtures.valid_registry,
        &fixtures.package_manifest.exports.commands,
        &endpoint_ids,
        std::slice::from_ref(&fixtures.host_run_slot.slot_id),
    );
    receipt.validate_against_handoff(&handoff)?;
    Ok(receipt)
}

pub(super) fn review_command(
    repo_root: &Path,
    snapshot_path: &Path,
    envelope_path: &Path,
    clock_path: &Path,
) -> Result<ManifoldCommandAuthorityReview, CliError> {
    let snapshot =
        read_model::<ManifoldAuthoritySnapshot>(resolve_input_path(repo_root, snapshot_path))?;
    let envelope =
        read_model::<ManifoldCommandEnvelope>(resolve_input_path(repo_root, envelope_path))?;
    let clock = read_model::<ManifoldClockSnapshot>(resolve_input_path(repo_root, clock_path))?;
    let evidence_ref = command_review_evidence_ref(&envelope);
    let review = snapshot.review_command(envelope, clock, vec![evidence_ref])?;
    review.validate_against_snapshot(&snapshot)?;
    Ok(review)
}

pub(super) fn command_review_evidence_ref(envelope: &ManifoldCommandEnvelope) -> DottedId {
    DottedId::new(format!(
        "evidence.command_authority.{}",
        envelope.request_id.as_str()
    ))
    .expect("derived command-review evidence id is valid")
}

pub(super) fn command_review_matches_fixture(
    snapshot: &ManifoldAuthoritySnapshot,
    envelope: &ManifoldCommandEnvelope,
    clock: &ManifoldClockSnapshot,
    expected: &ManifoldCommandAuthorityReview,
) -> Result<(), String> {
    let generated = snapshot
        .review_command(
            envelope.clone(),
            clock.clone(),
            vec![command_review_evidence_ref(envelope)],
        )
        .map_err(|error| error.to_string())?;
    generated
        .validate_against_snapshot(snapshot)
        .map_err(|error| error.to_string())?;

    if &generated == expected {
        Ok(())
    } else {
        Err(format!(
            "command authority review fixture mismatch for {}",
            envelope.request_id
        ))
    }
}

pub(super) fn prepare_command_dispatch(
    repo_root: &Path,
    snapshot_path: &Path,
    review_path: &Path,
) -> Result<ManifoldCommandDispatchReceipt, CliError> {
    let snapshot =
        read_model::<ManifoldAuthoritySnapshot>(resolve_input_path(repo_root, snapshot_path))?;
    let review =
        read_model::<ManifoldCommandAuthorityReview>(resolve_input_path(repo_root, review_path))?;
    let receipt = snapshot.prepare_command_dispatch(review)?;
    receipt.validate_against_snapshot(&snapshot)?;
    Ok(receipt)
}

pub(super) fn command_dispatch_matches_fixture(
    snapshot: &ManifoldAuthoritySnapshot,
    review: &ManifoldCommandAuthorityReview,
    expected: &ManifoldCommandDispatchReceipt,
) -> Result<(), String> {
    let generated = snapshot
        .prepare_command_dispatch(review.clone())
        .map_err(|error| error.to_string())?;
    generated
        .validate_against_snapshot(snapshot)
        .map_err(|error| error.to_string())?;

    if &generated == expected {
        Ok(())
    } else {
        Err(format!(
            "command dispatch receipt fixture mismatch for {}",
            review.review_id
        ))
    }
}

pub(super) fn command_dispatch_rejects_snapshot_revision_mismatch(
    snapshot: &ManifoldAuthoritySnapshot,
    review: &ManifoldCommandAuthorityReview,
) -> Result<(), String> {
    match snapshot.prepare_command_dispatch(review.clone()) {
        Ok(receipt) => Err(format!(
            "command dispatch unexpectedly accepted mismatched review {} as {}",
            review.review_id, receipt.dispatch_id
        )),
        Err(error) if error.rejection_code() == "authority_revision_mismatch" => Ok(()),
        Err(error) => Err(format!(
            "expected authority_revision_mismatch, got {}",
            error.rejection_code()
        )),
    }
}

pub(super) fn command_dispatch_receipt_rejects_request_lineage_mismatch(
    snapshot: &ManifoldAuthoritySnapshot,
    receipt: &ManifoldCommandDispatchReceipt,
) -> Result<(), String> {
    let mut damaged = receipt.clone();
    damaged.request_id = DottedId::new("request.command_dispatch.lineage_mismatch")
        .expect("literal request id is valid");

    match damaged.validate_against_snapshot(snapshot) {
        Ok(()) => Err(format!(
            "damaged command dispatch receipt {} unexpectedly validated",
            damaged.dispatch_id
        )),
        Err(error) if error.rejection_code() == "request_id_mismatch" => Ok(()),
        Err(error) => Err(format!(
            "expected request_id_mismatch, got {}",
            error.rejection_code()
        )),
    }
}

pub(super) fn review_lease(
    repo_root: &Path,
    snapshot_path: &Path,
    request_path: &Path,
    clock_path: &Path,
) -> Result<ManifoldControlLeaseAuthorityReview, CliError> {
    let snapshot =
        read_model::<ManifoldAuthoritySnapshot>(resolve_input_path(repo_root, snapshot_path))?;
    let request =
        read_model::<ManifoldControlLeaseRequest>(resolve_input_path(repo_root, request_path))?;
    let clock = read_model::<ManifoldClockSnapshot>(resolve_input_path(repo_root, clock_path))?;
    let evidence_ref = lease_review_evidence_ref(&request);
    let review = snapshot.review_lease_request(request, clock, vec![evidence_ref])?;
    review.validate_against_snapshot(&snapshot)?;
    Ok(review)
}

pub(super) fn lease_review_evidence_ref(request: &ManifoldControlLeaseRequest) -> DottedId {
    DottedId::new(format!(
        "evidence.lease_authority.{}",
        request.request_id.as_str()
    ))
    .expect("derived lease-review evidence id is valid")
}

pub(super) fn lease_review_matches_fixture(
    snapshot: &ManifoldAuthoritySnapshot,
    request: &ManifoldControlLeaseRequest,
    clock: &ManifoldClockSnapshot,
    expected: &ManifoldControlLeaseAuthorityReview,
) -> Result<(), String> {
    let generated = snapshot
        .review_lease_request(
            request.clone(),
            clock.clone(),
            vec![lease_review_evidence_ref(request)],
        )
        .map_err(|error| error.to_string())?;
    generated
        .validate_against_snapshot(snapshot)
        .map_err(|error| error.to_string())?;

    if &generated == expected {
        Ok(())
    } else {
        Err(format!(
            "lease authority review fixture mismatch for {}",
            request.request_id
        ))
    }
}

pub(super) fn apply_lease_review(
    repo_root: &Path,
    snapshot_path: &Path,
    review_path: &Path,
) -> Result<ManifoldControlLeaseAuthorityApplication, CliError> {
    let snapshot =
        read_model::<ManifoldAuthoritySnapshot>(resolve_input_path(repo_root, snapshot_path))?;
    let review = read_model::<ManifoldControlLeaseAuthorityReview>(resolve_input_path(
        repo_root,
        review_path,
    ))?;
    let application = snapshot.apply_control_lease_authority_review(review)?;
    application.validate_against_snapshot(&snapshot)?;
    Ok(application)
}

pub(super) fn lease_application_matches_fixture(
    snapshot: &ManifoldAuthoritySnapshot,
    review: &ManifoldControlLeaseAuthorityReview,
    expected: &ManifoldControlLeaseAuthorityApplication,
) -> Result<(), String> {
    let generated = snapshot
        .apply_control_lease_authority_review(review.clone())
        .map_err(|error| error.to_string())?;
    generated
        .validate_against_snapshot(snapshot)
        .map_err(|error| error.to_string())?;

    if &generated == expected {
        Ok(())
    } else {
        Err(format!(
            "lease authority application fixture mismatch for {}",
            review.review_id
        ))
    }
}

pub(super) fn review_lease_release(
    repo_root: &Path,
    snapshot_path: &Path,
    request_path: &Path,
    clock_path: &Path,
) -> Result<ManifoldControlLeaseReleaseAuthorityReview, CliError> {
    let snapshot =
        read_model::<ManifoldAuthoritySnapshot>(resolve_input_path(repo_root, snapshot_path))?;
    let request = read_model::<ManifoldControlLeaseReleaseRequest>(resolve_input_path(
        repo_root,
        request_path,
    ))?;
    let clock = read_model::<ManifoldClockSnapshot>(resolve_input_path(repo_root, clock_path))?;
    let evidence_ref = lease_release_review_evidence_ref(&request);
    let review = snapshot.review_control_lease_release(request, clock, vec![evidence_ref])?;
    review.validate_against_snapshot(&snapshot)?;
    Ok(review)
}

pub(super) fn lease_release_review_evidence_ref(
    request: &ManifoldControlLeaseReleaseRequest,
) -> DottedId {
    DottedId::new(format!(
        "evidence.lease_release_authority.{}",
        request.request_id.as_str()
    ))
    .expect("derived lease-release-review evidence id is valid")
}

pub(super) fn lease_release_review_matches_fixture(
    snapshot: &ManifoldAuthoritySnapshot,
    request: &ManifoldControlLeaseReleaseRequest,
    clock: &ManifoldClockSnapshot,
    expected: &ManifoldControlLeaseReleaseAuthorityReview,
) -> Result<(), String> {
    let generated = snapshot
        .review_control_lease_release(
            request.clone(),
            clock.clone(),
            vec![lease_release_review_evidence_ref(request)],
        )
        .map_err(|error| error.to_string())?;
    generated
        .validate_against_snapshot(snapshot)
        .map_err(|error| error.to_string())?;

    if &generated == expected {
        Ok(())
    } else {
        Err(format!(
            "lease release authority review fixture mismatch for {}",
            request.request_id
        ))
    }
}

pub(super) fn apply_lease_release_review(
    repo_root: &Path,
    snapshot_path: &Path,
    review_path: &Path,
) -> Result<ManifoldControlLeaseReleaseAuthorityApplication, CliError> {
    let snapshot =
        read_model::<ManifoldAuthoritySnapshot>(resolve_input_path(repo_root, snapshot_path))?;
    let review = read_model::<ManifoldControlLeaseReleaseAuthorityReview>(resolve_input_path(
        repo_root,
        review_path,
    ))?;
    let application = snapshot.apply_control_lease_release_authority_review(review)?;
    application.validate_against_snapshot(&snapshot)?;
    Ok(application)
}

pub(super) fn lease_release_application_matches_fixture(
    snapshot: &ManifoldAuthoritySnapshot,
    review: &ManifoldControlLeaseReleaseAuthorityReview,
    expected: &ManifoldControlLeaseReleaseAuthorityApplication,
) -> Result<(), String> {
    let generated = snapshot
        .apply_control_lease_release_authority_review(review.clone())
        .map_err(|error| error.to_string())?;
    generated
        .validate_against_snapshot(snapshot)
        .map_err(|error| error.to_string())?;

    if &generated == expected {
        Ok(())
    } else {
        Err(format!(
            "lease release authority application fixture mismatch for {}",
            review.review_id
        ))
    }
}

pub(super) fn review_lease_renewal(
    repo_root: &Path,
    snapshot_path: &Path,
    request_path: &Path,
    clock_path: &Path,
) -> Result<ManifoldControlLeaseRenewalAuthorityReview, CliError> {
    let snapshot =
        read_model::<ManifoldAuthoritySnapshot>(resolve_input_path(repo_root, snapshot_path))?;
    let request = read_model::<ManifoldControlLeaseRenewalRequest>(resolve_input_path(
        repo_root,
        request_path,
    ))?;
    let clock = read_model::<ManifoldClockSnapshot>(resolve_input_path(repo_root, clock_path))?;
    let evidence_ref = lease_renewal_review_evidence_ref(&request);
    let review = snapshot.review_control_lease_renewal(request, clock, vec![evidence_ref])?;
    review.validate_against_snapshot(&snapshot)?;
    Ok(review)
}

pub(super) fn lease_renewal_review_evidence_ref(
    request: &ManifoldControlLeaseRenewalRequest,
) -> DottedId {
    DottedId::new(format!(
        "evidence.lease_renewal_authority.{}",
        request.request_id.as_str()
    ))
    .expect("derived lease-renewal-review evidence id is valid")
}

pub(super) fn lease_renewal_review_matches_fixture(
    snapshot: &ManifoldAuthoritySnapshot,
    request: &ManifoldControlLeaseRenewalRequest,
    clock: &ManifoldClockSnapshot,
    expected: &ManifoldControlLeaseRenewalAuthorityReview,
) -> Result<(), String> {
    let generated = snapshot
        .review_control_lease_renewal(
            request.clone(),
            clock.clone(),
            vec![lease_renewal_review_evidence_ref(request)],
        )
        .map_err(|error| error.to_string())?;
    generated
        .validate_against_snapshot(snapshot)
        .map_err(|error| error.to_string())?;

    if &generated == expected {
        Ok(())
    } else {
        Err(format!(
            "lease renewal authority review fixture mismatch for {}",
            request.request_id
        ))
    }
}

pub(super) fn apply_lease_renewal_review(
    repo_root: &Path,
    snapshot_path: &Path,
    review_path: &Path,
) -> Result<ManifoldControlLeaseRenewalAuthorityApplication, CliError> {
    let snapshot =
        read_model::<ManifoldAuthoritySnapshot>(resolve_input_path(repo_root, snapshot_path))?;
    let review = read_model::<ManifoldControlLeaseRenewalAuthorityReview>(resolve_input_path(
        repo_root,
        review_path,
    ))?;
    let application = snapshot.apply_control_lease_renewal_authority_review(review)?;
    application.validate_against_snapshot(&snapshot)?;
    Ok(application)
}

pub(super) fn lease_renewal_application_matches_fixture(
    snapshot: &ManifoldAuthoritySnapshot,
    review: &ManifoldControlLeaseRenewalAuthorityReview,
    expected: &ManifoldControlLeaseRenewalAuthorityApplication,
) -> Result<(), String> {
    let generated = snapshot
        .apply_control_lease_renewal_authority_review(review.clone())
        .map_err(|error| error.to_string())?;
    generated
        .validate_against_snapshot(snapshot)
        .map_err(|error| error.to_string())?;

    if &generated == expected {
        Ok(())
    } else {
        Err(format!(
            "lease renewal authority application fixture mismatch for {}",
            review.review_id
        ))
    }
}

pub(super) fn review_stream_registry(
    repo_root: &Path,
    snapshot_path: &Path,
    request_path: &Path,
    clock_path: &Path,
) -> Result<ManifoldStreamRegistryAuthorityReview, CliError> {
    let snapshot =
        read_model::<ManifoldAuthoritySnapshot>(resolve_input_path(repo_root, snapshot_path))?;
    let request = read_model::<ManifoldStreamRegistryChangeRequest>(resolve_input_path(
        repo_root,
        request_path,
    ))?;
    let clock = read_model::<ManifoldClockSnapshot>(resolve_input_path(repo_root, clock_path))?;
    let evidence_ref = stream_registry_review_evidence_ref(&request);
    let review = snapshot.review_stream_registry_change(request, clock, vec![evidence_ref])?;
    review.validate_against_snapshot(&snapshot)?;
    Ok(review)
}

pub(super) fn stream_registry_review_evidence_ref(
    request: &ManifoldStreamRegistryChangeRequest,
) -> DottedId {
    DottedId::new(format!(
        "evidence.stream_registry_authority.{}",
        request.request_id.as_str()
    ))
    .expect("derived stream-registry-review evidence id is valid")
}

pub(super) fn stream_registry_review_matches_fixture(
    snapshot: &ManifoldAuthoritySnapshot,
    request: &ManifoldStreamRegistryChangeRequest,
    clock: &ManifoldClockSnapshot,
    expected: &ManifoldStreamRegistryAuthorityReview,
) -> Result<(), String> {
    let generated = snapshot
        .review_stream_registry_change(
            request.clone(),
            clock.clone(),
            vec![stream_registry_review_evidence_ref(request)],
        )
        .map_err(|error| error.to_string())?;
    generated
        .validate_against_snapshot(snapshot)
        .map_err(|error| error.to_string())?;

    if &generated == expected {
        Ok(())
    } else {
        Err(format!(
            "stream-registry authority review fixture mismatch for {}",
            request.request_id
        ))
    }
}

pub(super) fn apply_stream_registry_review(
    repo_root: &Path,
    snapshot_path: &Path,
    review_path: &Path,
) -> Result<ManifoldStreamRegistryAuthorityApplication, CliError> {
    let snapshot =
        read_model::<ManifoldAuthoritySnapshot>(resolve_input_path(repo_root, snapshot_path))?;
    let review = read_model::<ManifoldStreamRegistryAuthorityReview>(resolve_input_path(
        repo_root,
        review_path,
    ))?;
    let application = snapshot.apply_stream_registry_authority_review(review)?;
    Ok(application)
}

pub(super) fn stream_registry_application_matches_fixture(
    snapshot: &ManifoldAuthoritySnapshot,
    review: &ManifoldStreamRegistryAuthorityReview,
    expected: &ManifoldStreamRegistryAuthorityApplication,
) -> Result<(), String> {
    let generated = snapshot
        .apply_stream_registry_authority_review(review.clone())
        .map_err(|error| error.to_string())?;
    generated
        .validate_against_snapshot(snapshot)
        .map_err(|error| error.to_string())?;

    if &generated == expected {
        Ok(())
    } else {
        Err(format!(
            "stream registry authority application fixture mismatch for {}",
            review.review_id
        ))
    }
}

pub(super) fn review_stream_subscription(
    repo_root: &Path,
    snapshot_path: &Path,
    request_path: &Path,
    clock_path: &Path,
) -> Result<ManifoldStreamSubscriptionAuthorityReview, CliError> {
    let snapshot =
        read_model::<ManifoldAuthoritySnapshot>(resolve_input_path(repo_root, snapshot_path))?;
    let request = read_model::<ManifoldStreamSubscriptionRequest>(resolve_input_path(
        repo_root,
        request_path,
    ))?;
    let clock = read_model::<ManifoldClockSnapshot>(resolve_input_path(repo_root, clock_path))?;
    let evidence_ref = stream_subscription_review_evidence_ref(&request);
    let review = snapshot.review_stream_subscription(request, clock, vec![evidence_ref])?;
    review.validate_against_snapshot(&snapshot)?;
    Ok(review)
}

pub(super) fn stream_subscription_review_evidence_ref(
    request: &ManifoldStreamSubscriptionRequest,
) -> DottedId {
    DottedId::new(format!(
        "evidence.stream_subscription_authority.{}",
        request.request_id.as_str()
    ))
    .expect("derived stream-subscription-review evidence id is valid")
}

pub(super) fn stream_subscription_review_matches_fixture(
    snapshot: &ManifoldAuthoritySnapshot,
    request: &ManifoldStreamSubscriptionRequest,
    clock: &ManifoldClockSnapshot,
    expected: &ManifoldStreamSubscriptionAuthorityReview,
) -> Result<(), String> {
    let generated = snapshot
        .review_stream_subscription(
            request.clone(),
            clock.clone(),
            vec![stream_subscription_review_evidence_ref(request)],
        )
        .map_err(|error| error.to_string())?;
    generated
        .validate_against_snapshot(snapshot)
        .map_err(|error| error.to_string())?;

    if &generated == expected {
        Ok(())
    } else {
        Err(format!(
            "stream subscription authority review fixture mismatch for {}",
            request.request_id
        ))
    }
}

pub(super) fn apply_stream_subscription_review(
    repo_root: &Path,
    snapshot_path: &Path,
    review_path: &Path,
) -> Result<ManifoldStreamSubscriptionAuthorityApplication, CliError> {
    let snapshot =
        read_model::<ManifoldAuthoritySnapshot>(resolve_input_path(repo_root, snapshot_path))?;
    let review = read_model::<ManifoldStreamSubscriptionAuthorityReview>(resolve_input_path(
        repo_root,
        review_path,
    ))?;
    let application = snapshot.apply_stream_subscription_authority_review(review)?;
    application.validate_against_snapshot(&snapshot)?;
    Ok(application)
}

pub(super) fn stream_subscription_application_matches_fixture(
    snapshot: &ManifoldAuthoritySnapshot,
    review: &ManifoldStreamSubscriptionAuthorityReview,
    expected: &ManifoldStreamSubscriptionAuthorityApplication,
) -> Result<(), String> {
    let generated = snapshot
        .apply_stream_subscription_authority_review(review.clone())
        .map_err(|error| error.to_string())?;
    generated
        .validate_against_snapshot(snapshot)
        .map_err(|error| error.to_string())?;

    if &generated == expected {
        Ok(())
    } else {
        Err(format!(
            "stream subscription authority application fixture mismatch for {}",
            review.review_id
        ))
    }
}

pub(super) fn review_stream_subscription_release(
    repo_root: &Path,
    snapshot_path: &Path,
    request_path: &Path,
    clock_path: &Path,
) -> Result<ManifoldStreamSubscriptionReleaseAuthorityReview, CliError> {
    let snapshot =
        read_model::<ManifoldAuthoritySnapshot>(resolve_input_path(repo_root, snapshot_path))?;
    let request = read_model::<ManifoldStreamSubscriptionReleaseRequest>(resolve_input_path(
        repo_root,
        request_path,
    ))?;
    let clock = read_model::<ManifoldClockSnapshot>(resolve_input_path(repo_root, clock_path))?;
    let evidence_ref = stream_subscription_release_review_evidence_ref(&request);
    let review = snapshot.review_stream_subscription_release(request, clock, vec![evidence_ref])?;
    review.validate_against_snapshot(&snapshot)?;
    Ok(review)
}

pub(super) fn stream_subscription_release_review_evidence_ref(
    request: &ManifoldStreamSubscriptionReleaseRequest,
) -> DottedId {
    DottedId::new(format!(
        "evidence.stream_subscription_release_authority.{}",
        request.request_id.as_str()
    ))
    .expect("derived stream-subscription-release-review evidence id is valid")
}

pub(super) fn stream_subscription_release_review_matches_fixture(
    snapshot: &ManifoldAuthoritySnapshot,
    request: &ManifoldStreamSubscriptionReleaseRequest,
    clock: &ManifoldClockSnapshot,
    expected: &ManifoldStreamSubscriptionReleaseAuthorityReview,
) -> Result<(), String> {
    let generated = snapshot
        .review_stream_subscription_release(
            request.clone(),
            clock.clone(),
            vec![stream_subscription_release_review_evidence_ref(request)],
        )
        .map_err(|error| error.to_string())?;
    generated
        .validate_against_snapshot(snapshot)
        .map_err(|error| error.to_string())?;

    if &generated == expected {
        Ok(())
    } else {
        Err(format!(
            "stream subscription release authority review fixture mismatch for {}",
            request.request_id
        ))
    }
}

pub(super) fn apply_stream_subscription_release_review(
    repo_root: &Path,
    snapshot_path: &Path,
    review_path: &Path,
) -> Result<ManifoldStreamSubscriptionReleaseAuthorityApplication, CliError> {
    let snapshot =
        read_model::<ManifoldAuthoritySnapshot>(resolve_input_path(repo_root, snapshot_path))?;
    let review = read_model::<ManifoldStreamSubscriptionReleaseAuthorityReview>(
        resolve_input_path(repo_root, review_path),
    )?;
    let application = snapshot.apply_stream_subscription_release_authority_review(review)?;
    application.validate_against_snapshot(&snapshot)?;
    Ok(application)
}

pub(super) fn stream_subscription_release_application_matches_fixture(
    snapshot: &ManifoldAuthoritySnapshot,
    review: &ManifoldStreamSubscriptionReleaseAuthorityReview,
    expected: &ManifoldStreamSubscriptionReleaseAuthorityApplication,
) -> Result<(), String> {
    let generated = snapshot
        .apply_stream_subscription_release_authority_review(review.clone())
        .map_err(|error| error.to_string())?;
    generated
        .validate_against_snapshot(snapshot)
        .map_err(|error| error.to_string())?;

    if &generated == expected {
        Ok(())
    } else {
        Err(format!(
            "stream subscription release authority application fixture mismatch for {}",
            review.review_id
        ))
    }
}

pub(super) fn review_stream_subscription_renewal(
    repo_root: &Path,
    snapshot_path: &Path,
    request_path: &Path,
    clock_path: &Path,
) -> Result<ManifoldStreamSubscriptionRenewalAuthorityReview, CliError> {
    let snapshot =
        read_model::<ManifoldAuthoritySnapshot>(resolve_input_path(repo_root, snapshot_path))?;
    let request = read_model::<ManifoldStreamSubscriptionRenewalRequest>(resolve_input_path(
        repo_root,
        request_path,
    ))?;
    let clock = read_model::<ManifoldClockSnapshot>(resolve_input_path(repo_root, clock_path))?;
    let evidence_ref = stream_subscription_renewal_review_evidence_ref(&request);
    let review = snapshot.review_stream_subscription_renewal(request, clock, vec![evidence_ref])?;
    review.validate_against_snapshot(&snapshot)?;
    Ok(review)
}

pub(super) fn stream_subscription_renewal_review_evidence_ref(
    request: &ManifoldStreamSubscriptionRenewalRequest,
) -> DottedId {
    DottedId::new(format!(
        "evidence.stream_subscription_renewal_authority.{}",
        request.request_id.as_str()
    ))
    .expect("derived stream-subscription-renewal-review evidence id is valid")
}

pub(super) fn stream_subscription_renewal_review_matches_fixture(
    snapshot: &ManifoldAuthoritySnapshot,
    request: &ManifoldStreamSubscriptionRenewalRequest,
    clock: &ManifoldClockSnapshot,
    expected: &ManifoldStreamSubscriptionRenewalAuthorityReview,
) -> Result<(), String> {
    let generated = snapshot
        .review_stream_subscription_renewal(
            request.clone(),
            clock.clone(),
            vec![stream_subscription_renewal_review_evidence_ref(request)],
        )
        .map_err(|error| error.to_string())?;
    generated
        .validate_against_snapshot(snapshot)
        .map_err(|error| error.to_string())?;

    if &generated == expected {
        Ok(())
    } else {
        Err(format!(
            "stream subscription renewal authority review fixture mismatch for {}",
            request.request_id
        ))
    }
}

pub(super) fn apply_stream_subscription_renewal_review(
    repo_root: &Path,
    snapshot_path: &Path,
    review_path: &Path,
) -> Result<ManifoldStreamSubscriptionRenewalAuthorityApplication, CliError> {
    let snapshot =
        read_model::<ManifoldAuthoritySnapshot>(resolve_input_path(repo_root, snapshot_path))?;
    let review = read_model::<ManifoldStreamSubscriptionRenewalAuthorityReview>(
        resolve_input_path(repo_root, review_path),
    )?;
    let application = snapshot.apply_stream_subscription_renewal_authority_review(review)?;
    application.validate_against_snapshot(&snapshot)?;
    Ok(application)
}

pub(super) fn stream_subscription_renewal_application_matches_fixture(
    snapshot: &ManifoldAuthoritySnapshot,
    review: &ManifoldStreamSubscriptionRenewalAuthorityReview,
    expected: &ManifoldStreamSubscriptionRenewalAuthorityApplication,
) -> Result<(), String> {
    let generated = snapshot
        .apply_stream_subscription_renewal_authority_review(review.clone())
        .map_err(|error| error.to_string())?;
    generated
        .validate_against_snapshot(snapshot)
        .map_err(|error| error.to_string())?;

    if &generated == expected {
        Ok(())
    } else {
        Err(format!(
            "stream subscription renewal authority application fixture mismatch for {}",
            review.review_id
        ))
    }
}

pub(super) fn review_authority_expiry_sweep(
    repo_root: &Path,
    snapshot_path: &Path,
    request_path: &Path,
    clock_path: &Path,
) -> Result<ManifoldAuthorityExpirySweepAuthorityReview, CliError> {
    let snapshot =
        read_model::<ManifoldAuthoritySnapshot>(resolve_input_path(repo_root, snapshot_path))?;
    let request = read_model::<ManifoldAuthorityExpirySweepRequest>(resolve_input_path(
        repo_root,
        request_path,
    ))?;
    let clock = read_model::<ManifoldClockSnapshot>(resolve_input_path(repo_root, clock_path))?;
    let evidence_ref = authority_expiry_sweep_review_evidence_ref(&request);
    let review = snapshot.review_authority_expiry_sweep(request, clock, vec![evidence_ref])?;
    review.validate_against_snapshot(&snapshot)?;
    Ok(review)
}

pub(super) fn authority_expiry_sweep_review_evidence_ref(
    request: &ManifoldAuthorityExpirySweepRequest,
) -> DottedId {
    DottedId::new(format!(
        "evidence.expiry_sweep_authority.{}",
        request.request_id.as_str()
    ))
    .expect("derived authority-expiry-sweep-review evidence id is valid")
}

pub(super) fn authority_expiry_sweep_review_matches_fixture(
    snapshot: &ManifoldAuthoritySnapshot,
    request: &ManifoldAuthorityExpirySweepRequest,
    clock: &ManifoldClockSnapshot,
    expected: &ManifoldAuthorityExpirySweepAuthorityReview,
) -> Result<(), String> {
    let generated = snapshot
        .review_authority_expiry_sweep(
            request.clone(),
            clock.clone(),
            vec![authority_expiry_sweep_review_evidence_ref(request)],
        )
        .map_err(|error| error.to_string())?;
    generated
        .validate_against_snapshot(snapshot)
        .map_err(|error| error.to_string())?;

    if &generated == expected {
        Ok(())
    } else {
        Err(format!(
            "authority expiry sweep review fixture mismatch for {}",
            request.request_id
        ))
    }
}

pub(super) fn apply_authority_expiry_sweep_review(
    repo_root: &Path,
    snapshot_path: &Path,
    review_path: &Path,
) -> Result<ManifoldAuthorityExpirySweepAuthorityApplication, CliError> {
    let snapshot =
        read_model::<ManifoldAuthoritySnapshot>(resolve_input_path(repo_root, snapshot_path))?;
    let review = read_model::<ManifoldAuthorityExpirySweepAuthorityReview>(resolve_input_path(
        repo_root,
        review_path,
    ))?;
    let application = snapshot.apply_authority_expiry_sweep_review(review)?;
    application.validate_against_snapshot(&snapshot)?;
    Ok(application)
}

pub(super) fn authority_expiry_sweep_application_matches_fixture(
    snapshot: &ManifoldAuthoritySnapshot,
    review: &ManifoldAuthorityExpirySweepAuthorityReview,
    expected: &ManifoldAuthorityExpirySweepAuthorityApplication,
) -> Result<(), String> {
    let generated = snapshot
        .apply_authority_expiry_sweep_review(review.clone())
        .map_err(|error| error.to_string())?;
    generated
        .validate_against_snapshot(snapshot)
        .map_err(|error| error.to_string())?;

    if &generated == expected {
        Ok(())
    } else {
        Err(format!(
            "authority expiry sweep application fixture mismatch for {}",
            review.review_id
        ))
    }
}

pub(super) fn review_module_runtime(
    repo_root: &Path,
    snapshot_path: &Path,
    request_path: &Path,
    clock_path: &Path,
) -> Result<ManifoldModuleRuntimeStateAuthorityReview, CliError> {
    let snapshot =
        read_model::<ManifoldAuthoritySnapshot>(resolve_input_path(repo_root, snapshot_path))?;
    let request = read_model::<ManifoldModuleRuntimeStateChangeRequest>(resolve_input_path(
        repo_root,
        request_path,
    ))?;
    let clock = read_model::<ManifoldClockSnapshot>(resolve_input_path(repo_root, clock_path))?;
    let evidence_ref = module_runtime_review_evidence_ref(&request);
    let review = snapshot.review_module_runtime_state_change(request, clock, vec![evidence_ref])?;
    review.validate_against_snapshot(&snapshot)?;
    Ok(review)
}

pub(super) fn apply_module_runtime_review(
    repo_root: &Path,
    snapshot_path: &Path,
    review_path: &Path,
) -> Result<ManifoldModuleRuntimeStateAuthorityApplication, CliError> {
    let snapshot =
        read_model::<ManifoldAuthoritySnapshot>(resolve_input_path(repo_root, snapshot_path))?;
    let review = read_model::<ManifoldModuleRuntimeStateAuthorityReview>(resolve_input_path(
        repo_root,
        review_path,
    ))?;
    let application = snapshot.apply_module_runtime_state_authority_review(review)?;
    application.validate_against_snapshot(&snapshot)?;
    Ok(application)
}

pub(super) fn module_runtime_review_evidence_ref(
    request: &ManifoldModuleRuntimeStateChangeRequest,
) -> DottedId {
    DottedId::new(format!(
        "evidence.module_runtime_state_authority.{}",
        request.request_id.as_str()
    ))
    .expect("derived module-runtime-state-review evidence id is valid")
}

pub(super) fn module_runtime_review_matches_fixture(
    snapshot: &ManifoldAuthoritySnapshot,
    request: &ManifoldModuleRuntimeStateChangeRequest,
    clock: &ManifoldClockSnapshot,
    expected: &ManifoldModuleRuntimeStateAuthorityReview,
) -> Result<(), String> {
    let generated = snapshot
        .review_module_runtime_state_change(
            request.clone(),
            clock.clone(),
            vec![module_runtime_review_evidence_ref(request)],
        )
        .map_err(|error| error.to_string())?;
    generated
        .validate_against_snapshot(snapshot)
        .map_err(|error| error.to_string())?;

    if &generated == expected {
        Ok(())
    } else {
        Err(format!(
            "module runtime-state authority review fixture mismatch for {}",
            request.request_id
        ))
    }
}

pub(super) fn module_runtime_application_matches_fixture(
    snapshot: &ManifoldAuthoritySnapshot,
    review: &ManifoldModuleRuntimeStateAuthorityReview,
    expected: &ManifoldModuleRuntimeStateAuthorityApplication,
) -> Result<(), String> {
    let generated = snapshot
        .apply_module_runtime_state_authority_review(review.clone())
        .map_err(|error| error.to_string())?;
    generated
        .validate_against_snapshot(snapshot)
        .map_err(|error| error.to_string())?;

    if &generated == expected {
        Ok(())
    } else {
        Err(format!(
            "module runtime-state authority application fixture mismatch for {}",
            review.review_id
        ))
    }
}

pub(super) fn review_host_manifest(
    repo_root: &Path,
    snapshot_path: &Path,
    request_path: &Path,
    clock_path: &Path,
) -> Result<ManifoldHostManifestAuthorityReview, CliError> {
    let snapshot =
        read_model::<ManifoldAuthoritySnapshot>(resolve_input_path(repo_root, snapshot_path))?;
    let request = read_model::<ManifoldHostManifestChangeRequest>(resolve_input_path(
        repo_root,
        request_path,
    ))?;
    let clock = read_model::<ManifoldClockSnapshot>(resolve_input_path(repo_root, clock_path))?;
    let evidence_ref = host_manifest_review_evidence_ref(&request);
    let review = snapshot.review_host_manifest_change(request, clock, vec![evidence_ref])?;
    review.validate_against_snapshot(&snapshot)?;
    Ok(review)
}

pub(super) fn host_manifest_review_evidence_ref(
    request: &ManifoldHostManifestChangeRequest,
) -> DottedId {
    DottedId::new(format!(
        "evidence.host_manifest_authority.{}",
        request.request_id.as_str()
    ))
    .expect("derived host-manifest-review evidence id is valid")
}

pub(super) fn host_manifest_review_matches_fixture(
    snapshot: &ManifoldAuthoritySnapshot,
    request: &ManifoldHostManifestChangeRequest,
    clock: &ManifoldClockSnapshot,
    expected: &ManifoldHostManifestAuthorityReview,
) -> Result<(), String> {
    let generated = snapshot
        .review_host_manifest_change(
            request.clone(),
            clock.clone(),
            vec![host_manifest_review_evidence_ref(request)],
        )
        .map_err(|error| error.to_string())?;
    generated
        .validate_against_snapshot(snapshot)
        .map_err(|error| error.to_string())?;

    if &generated == expected {
        Ok(())
    } else {
        Err(format!(
            "host manifest authority review fixture mismatch for {}",
            request.request_id
        ))
    }
}

pub(super) fn apply_host_manifest_review(
    repo_root: &Path,
    snapshot_path: &Path,
    review_path: &Path,
) -> Result<ManifoldHostManifestAuthorityApplication, CliError> {
    let snapshot =
        read_model::<ManifoldAuthoritySnapshot>(resolve_input_path(repo_root, snapshot_path))?;
    let review = read_model::<ManifoldHostManifestAuthorityReview>(resolve_input_path(
        repo_root,
        review_path,
    ))?;
    let application = snapshot.apply_host_manifest_authority_review(review)?;
    application.validate_against_snapshot(&snapshot)?;
    Ok(application)
}

pub(super) fn host_manifest_application_matches_fixture(
    snapshot: &ManifoldAuthoritySnapshot,
    review: &ManifoldHostManifestAuthorityReview,
    expected: &ManifoldHostManifestAuthorityApplication,
) -> Result<(), String> {
    let generated = snapshot
        .apply_host_manifest_authority_review(review.clone())
        .map_err(|error| error.to_string())?;
    generated
        .validate_against_snapshot(snapshot)
        .map_err(|error| error.to_string())?;

    if &generated == expected {
        Ok(())
    } else {
        Err(format!(
            "host manifest authority application fixture mismatch for {}",
            review.review_id
        ))
    }
}

pub(super) fn review_clock(
    repo_root: &Path,
    snapshot_path: &Path,
    request_path: &Path,
    clock_path: &Path,
) -> Result<ManifoldClockSnapshotAuthorityReview, CliError> {
    let snapshot =
        read_model::<ManifoldAuthoritySnapshot>(resolve_input_path(repo_root, snapshot_path))?;
    let request = read_model::<ManifoldClockSnapshotChangeRequest>(resolve_input_path(
        repo_root,
        request_path,
    ))?;
    let clock = read_model::<ManifoldClockSnapshot>(resolve_input_path(repo_root, clock_path))?;
    let evidence_ref = clock_review_evidence_ref(&request);
    let review = snapshot.review_clock_snapshot_change(request, clock, vec![evidence_ref])?;
    review.validate_against_snapshot(&snapshot)?;
    Ok(review)
}

pub(super) fn clock_review_evidence_ref(request: &ManifoldClockSnapshotChangeRequest) -> DottedId {
    DottedId::new(format!(
        "evidence.clock_snapshot_authority.{}",
        request.request_id.as_str()
    ))
    .expect("derived clock-review evidence id is valid")
}

pub(super) fn clock_review_matches_fixture(
    snapshot: &ManifoldAuthoritySnapshot,
    request: &ManifoldClockSnapshotChangeRequest,
    clock: &ManifoldClockSnapshot,
    expected: &ManifoldClockSnapshotAuthorityReview,
) -> Result<(), String> {
    let generated = snapshot
        .review_clock_snapshot_change(
            request.clone(),
            clock.clone(),
            vec![clock_review_evidence_ref(request)],
        )
        .map_err(|error| error.to_string())?;
    generated
        .validate_against_snapshot(snapshot)
        .map_err(|error| error.to_string())?;

    if &generated == expected {
        Ok(())
    } else {
        Err(format!(
            "clock snapshot authority review fixture mismatch for {}",
            request.request_id
        ))
    }
}

pub(super) fn apply_clock_review(
    repo_root: &Path,
    snapshot_path: &Path,
    review_path: &Path,
) -> Result<ManifoldClockSnapshotAuthorityApplication, CliError> {
    let snapshot =
        read_model::<ManifoldAuthoritySnapshot>(resolve_input_path(repo_root, snapshot_path))?;
    let review = read_model::<ManifoldClockSnapshotAuthorityReview>(resolve_input_path(
        repo_root,
        review_path,
    ))?;
    let application = snapshot.apply_clock_snapshot_authority_review(review)?;
    application.validate_against_snapshot(&snapshot)?;
    Ok(application)
}

pub(super) fn clock_application_matches_fixture(
    snapshot: &ManifoldAuthoritySnapshot,
    review: &ManifoldClockSnapshotAuthorityReview,
    expected: &ManifoldClockSnapshotAuthorityApplication,
) -> Result<(), String> {
    let generated = snapshot
        .apply_clock_snapshot_authority_review(review.clone())
        .map_err(|error| error.to_string())?;
    generated
        .validate_against_snapshot(snapshot)
        .map_err(|error| error.to_string())?;

    if &generated == expected {
        Ok(())
    } else {
        Err(format!(
            "clock snapshot authority application fixture mismatch for {}",
            review.review_id
        ))
    }
}
