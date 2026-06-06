use super::*;

#[test]
fn host_manifest_authority_review_accepts_permission_change() {
    let snapshot = authority_snapshot();
    let request = host_manifest_change_request();
    let review = snapshot
        .review_host_manifest_change(
            request,
            command_review_clock(),
            vec![id(
                "evidence.host_manifest_authority.request.synthetic_permissions",
            )],
        )
        .unwrap();

    assert_eq!(
        review.outcome,
        ManifoldHostManifestAuthorityReviewOutcome::HostManifestAccepted
    );
    assert_eq!(
        review.accepted.as_ref().unwrap().permissions,
        vec![id("permission.synthetic_diagnostics")]
    );
    assert_eq!(review.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn host_manifest_authority_review_rejects_missing_authority_role() {
    let snapshot = authority_snapshot();
    let mut request = host_manifest_change_request();
    request.request_id = id("request.host_manifest.missing_authority_role");
    request.proposed_manifest.authority_role = AuthorityRole::None;
    let review = snapshot
        .review_host_manifest_change(
            request,
            command_review_clock(),
            vec![id(
                "evidence.host_manifest_authority.request.missing_authority_role",
            )],
        )
        .unwrap();

    assert_eq!(
        review.outcome,
        ManifoldHostManifestAuthorityReviewOutcome::HostManifestRejected
    );
    assert_eq!(
        review.rejection.as_ref().unwrap().rejection_code.as_str(),
        "missing_authority_role"
    );
    assert_eq!(review.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn host_manifest_authority_review_rejects_backend_in_use_removal() {
    let snapshot = authority_snapshot();
    let mut request = host_manifest_change_request();
    request.request_id = id("request.host_manifest.remove_backend");
    request.proposed_manifest.supported_backends.clear();
    let review = snapshot
        .review_host_manifest_change(
            request,
            command_review_clock(),
            vec![id(
                "evidence.host_manifest_authority.request.remove_backend",
            )],
        )
        .unwrap();

    assert_eq!(
        review.outcome,
        ManifoldHostManifestAuthorityReviewOutcome::HostManifestRejected
    );
    assert_eq!(
        review.rejection.as_ref().unwrap().rejection_code.as_str(),
        "backend_in_use"
    );
    assert_eq!(review.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn host_manifest_authority_application_advances_snapshot() {
    let snapshot = authority_snapshot();
    let review = snapshot
        .review_host_manifest_change(
            host_manifest_change_request(),
            command_review_clock(),
            vec![id(
                "evidence.host_manifest_authority.request.synthetic_permissions",
            )],
        )
        .unwrap();
    let application = snapshot
        .apply_host_manifest_authority_review(review)
        .unwrap();

    assert_eq!(
        application.outcome,
        ManifoldHostManifestAuthorityApplicationOutcome::HostManifestApplied
    );
    assert!(application.rejection.is_none());
    let applied = application.applied_snapshot.as_ref().unwrap();
    assert_eq!(applied.authority_revision, Revision::new(2).unwrap());
    assert_eq!(
        applied.host_manifest.permissions,
        vec![id("permission.synthetic_diagnostics")]
    );
    assert_eq!(application.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn host_manifest_authority_application_rejects_rejected_review() {
    let snapshot = authority_snapshot();
    let mut request = host_manifest_change_request();
    request.request_id = id("request.host_manifest.stale_revision");
    request.expected_authority_revision = Revision::new(2).unwrap();
    let review = snapshot
        .review_host_manifest_change(
            request,
            command_review_clock(),
            vec![id(
                "evidence.host_manifest_authority.request.stale_revision",
            )],
        )
        .unwrap();
    let application = snapshot
        .apply_host_manifest_authority_review(review)
        .unwrap();

    assert_eq!(
        application.outcome,
        ManifoldHostManifestAuthorityApplicationOutcome::HostManifestApplicationRejected
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
