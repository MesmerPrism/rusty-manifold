use super::*;

#[test]
fn module_runtime_state_authority_review_accepts_stop_transition() {
    let snapshot = stream_authority_snapshot();
    let request = module_runtime_state_change_request();
    let review = snapshot
        .review_module_runtime_state_change(
            request,
            command_review_clock(),
            vec![id(
                "evidence.module_runtime_state_authority.request.stop.synthetic_wave_provider",
            )],
        )
        .unwrap();

    assert_eq!(
        review.outcome,
        ManifoldModuleRuntimeStateAuthorityReviewOutcome::RuntimeStateAccepted
    );
    assert_eq!(
        review.accepted.as_ref().unwrap().lifecycle,
        ModuleLifecycleState::Stopped
    );
    assert_eq!(
        review.transition.as_ref().unwrap().deactivated_streams,
        vec![id("stream.synthetic_wave")]
    );
    assert_eq!(review.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn module_runtime_state_authority_review_rejects_unknown_stream() {
    let snapshot = stream_authority_snapshot();
    let mut request = module_runtime_state_change_request();
    request.request_id = id("request.module_runtime.unknown_stream");
    request.proposed_state.lifecycle = ModuleLifecycleState::Running;
    request.proposed_state.active_streams = vec![id("stream.not_registered")];
    let review = snapshot
        .review_module_runtime_state_change(
            request,
            command_review_clock(),
            vec![id(
                "evidence.module_runtime_state_authority.request.unknown_stream",
            )],
        )
        .unwrap();

    assert_eq!(
        review.outcome,
        ManifoldModuleRuntimeStateAuthorityReviewOutcome::RuntimeStateRejected
    );
    assert_eq!(
        review.rejection.as_ref().unwrap().rejection_code.as_str(),
        "unknown_stream"
    );
    assert_eq!(review.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn module_runtime_state_authority_application_advances_snapshot() {
    let snapshot = stream_authority_snapshot();
    let review = snapshot
        .review_module_runtime_state_change(
            module_runtime_state_change_request(),
            command_review_clock(),
            vec![id(
                "evidence.module_runtime_state_authority.request.stop.synthetic_wave_provider",
            )],
        )
        .unwrap();
    let application = snapshot
        .apply_module_runtime_state_authority_review(review)
        .unwrap();

    assert_eq!(
        application.outcome,
        ManifoldModuleRuntimeStateAuthorityApplicationOutcome::RuntimeStateApplied
    );
    assert!(application.rejection.is_none());
    let applied = application.applied_snapshot.as_ref().unwrap();
    assert_eq!(applied.authority_revision, Revision::new(2).unwrap());
    let runtime_state = applied
        .module_runtime_state(&id("module.synthetic_wave_provider"))
        .unwrap();
    assert_eq!(runtime_state.lifecycle, ModuleLifecycleState::Stopped);
    assert_eq!(runtime_state.runtime_revision, Revision::new(2).unwrap());
    assert!(runtime_state.active_streams.is_empty());
    assert_eq!(application.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn module_runtime_state_authority_application_rejects_rejected_review() {
    let snapshot = stream_authority_snapshot();
    let mut request = module_runtime_state_change_request();
    request.request_id = id("request.module_runtime.stale_revision");
    request.expected_authority_revision = Revision::new(2).unwrap();
    let review = snapshot
        .review_module_runtime_state_change(
            request,
            command_review_clock(),
            vec![id(
                "evidence.module_runtime_state_authority.request.stale_revision",
            )],
        )
        .unwrap();
    let application = snapshot
        .apply_module_runtime_state_authority_review(review)
        .unwrap();

    assert_eq!(
        application.outcome,
        ManifoldModuleRuntimeStateAuthorityApplicationOutcome::RuntimeStateApplicationRejected
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
