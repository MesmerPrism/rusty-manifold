use super::*;

#[test]
fn lease_authority_review_accepts_available_scope() {
    let snapshot = authority_snapshot();
    let request = lease_request();
    let review = snapshot
        .review_lease_request(
            request,
            command_review_clock(),
            vec![id("evidence.lease_authority.request.synthetic_lease_1")],
        )
        .unwrap();

    assert_eq!(
        review.outcome,
        ManifoldControlLeaseAuthorityReviewOutcome::LeaseAccepted
    );
    assert!(review.accepted.is_some());
    assert!(review.rejection.is_none());
    assert_eq!(review.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn lease_authority_application_advances_snapshot() {
    let snapshot = authority_snapshot();
    let review = snapshot
        .review_lease_request(
            lease_request(),
            command_review_clock(),
            vec![id("evidence.lease_authority.request.synthetic_lease_1")],
        )
        .unwrap();
    let application = snapshot
        .apply_control_lease_authority_review(review)
        .unwrap();

    assert_eq!(
        application.outcome,
        ManifoldControlLeaseAuthorityApplicationOutcome::LeaseApplied
    );
    assert!(application.rejection.is_none());
    let applied = application.applied_snapshot.as_ref().unwrap();
    assert_eq!(applied.authority_revision, Revision::new(2).unwrap());
    assert_eq!(
        applied.active_leases.len(),
        snapshot.active_leases.len() + 1
    );
    let accepted_lease = applied.active_leases.last().unwrap();
    assert_eq!(accepted_lease.lease_id.as_str(), "lease.synthetic_lease_1");
    assert_eq!(accepted_lease.scope.as_str(), "manifold.graph");
    assert_eq!(accepted_lease.granted_revision, Revision::INITIAL);
    assert_eq!(application.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn lease_authority_application_rejects_rejected_review() {
    let snapshot = authority_snapshot();
    let mut request = lease_request();
    request.request_id = id("request.lease.stale_graph");
    request.expected_revision = Revision::new(2).unwrap();
    let review = snapshot
        .review_lease_request(
            request,
            command_review_clock(),
            vec![id("evidence.lease_authority.request.lease.stale_graph")],
        )
        .unwrap();
    let application = snapshot
        .apply_control_lease_authority_review(review)
        .unwrap();

    assert_eq!(
        application.outcome,
        ManifoldControlLeaseAuthorityApplicationOutcome::LeaseApplicationRejected
    );
    assert!(application.applied_snapshot.is_none());
    assert_eq!(
        application
            .rejection
            .as_ref()
            .unwrap()
            .rejection_code
            .as_str(),
        "review_rejected"
    );
    assert_eq!(application.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn lease_release_authority_application_removes_active_lease() {
    let snapshot = authority_snapshot();
    let lease_review = snapshot
        .review_lease_request(
            lease_request(),
            command_review_clock(),
            vec![id("evidence.lease_authority.request.synthetic_lease_1")],
        )
        .unwrap();
    let lease_application = snapshot
        .apply_control_lease_authority_review(lease_review)
        .unwrap();
    let active_snapshot = lease_application.applied_snapshot.unwrap();
    let lease = active_snapshot.active_leases.last().unwrap().clone();
    let release_request = ManifoldControlLeaseReleaseRequest {
        schema_id: control_lease_release_request_schema_id(),
        request_id: id("request.lease_release.synthetic_lease_1"),
        lease_id: lease.lease_id.clone(),
        holder_id: lease.holder_id.clone(),
        expected_authority_revision: active_snapshot.authority_revision,
        scope: lease.scope.clone(),
        release_reason: id("holder.done"),
        requested_at_ms: 1_765_000_000_200,
    };
    let release_review = active_snapshot
        .review_control_lease_release(
            release_request,
            command_review_clock(),
            vec![id(
                "evidence.lease_release_authority.request.synthetic_lease_1",
            )],
        )
        .unwrap();

    assert_eq!(
        release_review.outcome,
        ManifoldControlLeaseReleaseAuthorityReviewOutcome::LeaseReleased
    );
    assert_eq!(release_review.released.as_ref(), Some(&lease));
    assert_eq!(
        release_review.validate_against_snapshot(&active_snapshot),
        Ok(())
    );

    let release_application = active_snapshot
        .apply_control_lease_release_authority_review(release_review)
        .unwrap();

    assert_eq!(
        release_application.outcome,
        ManifoldControlLeaseReleaseAuthorityApplicationOutcome::LeaseReleaseApplied
    );
    assert!(release_application.rejection.is_none());
    let applied = release_application.applied_snapshot.as_ref().unwrap();
    assert_eq!(applied.authority_revision, Revision::new(3).unwrap());
    assert_eq!(
        applied.active_leases.len(),
        active_snapshot.active_leases.len() - 1
    );
    assert!(!applied
        .active_leases
        .iter()
        .any(|active| active.lease_id == lease.lease_id));
    assert_eq!(
        release_application.validate_against_snapshot(&active_snapshot),
        Ok(())
    );
}

#[test]
fn lease_renewal_authority_application_replaces_active_lease() {
    let snapshot = authority_snapshot();
    let lease_review = snapshot
        .review_lease_request(
            lease_request(),
            command_review_clock(),
            vec![id("evidence.lease_authority.request.synthetic_lease_1")],
        )
        .unwrap();
    let lease_application = snapshot
        .apply_control_lease_authority_review(lease_review)
        .unwrap();
    let active_snapshot = lease_application.applied_snapshot.unwrap();
    let lease = active_snapshot.active_leases.last().unwrap().clone();
    let old_expires_at_ms = lease.expires_at_ms;
    let renewal_request = ManifoldControlLeaseRenewalRequest {
        schema_id: control_lease_renewal_request_schema_id(),
        request_id: id("request.lease_renewal.synthetic_lease_1"),
        lease_id: lease.lease_id.clone(),
        holder_id: lease.holder_id.clone(),
        expected_authority_revision: active_snapshot.authority_revision,
        scope: lease.scope.clone(),
        requested_ttl_ms: 60_000,
        renewal_reason: id("holder.needs_more_time"),
        requested_at_ms: 1_765_000_000_200,
    };
    let renewal_review = active_snapshot
        .review_control_lease_renewal(
            renewal_request,
            command_review_clock(),
            vec![id(
                "evidence.lease_renewal_authority.request.synthetic_lease_1",
            )],
        )
        .unwrap();

    assert_eq!(
        renewal_review.outcome,
        ManifoldControlLeaseRenewalAuthorityReviewOutcome::LeaseRenewed
    );
    let renewed = renewal_review.renewed.as_ref().unwrap();
    assert_eq!(renewed.lease_id, lease.lease_id);
    assert!(renewed.expires_at_ms > old_expires_at_ms);
    assert_eq!(
        renewal_review.validate_against_snapshot(&active_snapshot),
        Ok(())
    );

    let renewal_application = active_snapshot
        .apply_control_lease_renewal_authority_review(renewal_review)
        .unwrap();

    assert_eq!(
        renewal_application.outcome,
        ManifoldControlLeaseRenewalAuthorityApplicationOutcome::LeaseRenewalApplied
    );
    assert!(renewal_application.rejection.is_none());
    let applied = renewal_application.applied_snapshot.as_ref().unwrap();
    assert_eq!(applied.authority_revision, Revision::new(3).unwrap());
    assert_eq!(
        applied.active_leases.len(),
        active_snapshot.active_leases.len()
    );
    let renewed_lease = applied
        .active_leases
        .iter()
        .find(|active| active.lease_id == lease.lease_id)
        .unwrap();
    assert!(renewed_lease.expires_at_ms > old_expires_at_ms);
    assert_eq!(renewed_lease.granted_revision, Revision::new(2).unwrap());
    assert_eq!(
        renewal_application.validate_against_snapshot(&active_snapshot),
        Ok(())
    );
}

#[test]
fn lease_authority_review_rejects_busy_scope() {
    let snapshot = authority_snapshot();
    let mut request = lease_request();
    request.request_id = id("request.lease.busy_module");
    request.holder_id = id("holder.other_agent");
    request.scope = id("module.synthetic_wave_provider");
    request.required_capability = id("manifold.module.control");
    let review = snapshot
        .review_lease_request(
            request,
            command_review_clock(),
            vec![id("evidence.lease_authority.request.lease.busy_module")],
        )
        .unwrap();

    assert_eq!(
        review.outcome,
        ManifoldControlLeaseAuthorityReviewOutcome::LeaseRejected
    );
    assert_eq!(
        review.rejection.as_ref().unwrap().rejection_code.as_str(),
        "lease_scope_busy"
    );
    assert_eq!(
        review
            .rejection
            .as_ref()
            .unwrap()
            .conflicting_lease_id
            .as_ref()
            .unwrap()
            .as_str(),
        "lease.synthetic_module"
    );
    assert_eq!(review.validate_against_snapshot(&snapshot), Ok(()));
}
