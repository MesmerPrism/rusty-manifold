use super::*;

pub(super) fn shell_handoff_review_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.shell.handoff_review_receipt.v1")
        .expect("schema literal is valid")
}

pub(super) fn shell_handoff_review_id(handoff_id: &DottedId) -> DottedId {
    DottedId::new(format!("shell_handoff_review.{}", handoff_id.as_str()))
        .expect("derived review id is valid")
}

pub(super) fn manifold_authority_id() -> DottedId {
    DottedId::new("authority.manifold").expect("authority id literal is valid")
}

pub(super) fn shell_handoff_review_check(
    check_id: &str,
    condition: bool,
    pass_evidence: &str,
    fail_evidence: &str,
    issue_code: &str,
) -> ValidationCheck {
    ValidationCheck {
        check_id: DottedId::new(check_id).expect("check id literal is valid"),
        status: if condition {
            ValidationStatus::Pass
        } else {
            ValidationStatus::Fail
        },
        evidence: if condition {
            pass_evidence.to_owned()
        } else {
            fail_evidence.to_owned()
        },
        issue_codes: if condition {
            Vec::new()
        } else {
            vec![DottedId::new(issue_code).expect("issue code literal is valid")]
        },
    }
}

pub(super) fn shell_handoff_review_issue(issue_code: DottedId) -> ManifoldIssue {
    ManifoldIssue {
        message: format!("shell handoff review failed {issue_code}"),
        issue_code,
        severity: IssueSeverity::Error,
    }
}

pub(super) fn host_manifest_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.host.manifest.v1").expect("schema literal is valid")
}

pub(super) fn host_manifest_change_request_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.host.manifest_change_request.v1")
        .expect("schema literal is valid")
}

pub(super) fn host_manifest_rejection_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.host.manifest_rejection.v1").expect("schema literal is valid")
}

pub(super) fn clock_snapshot_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.clock.snapshot.v1").expect("schema literal is valid")
}

pub(super) fn clock_snapshot_change_request_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.clock.snapshot_change_request.v1")
        .expect("schema literal is valid")
}

pub(super) fn clock_snapshot_rejection_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.clock.snapshot_rejection.v1").expect("schema literal is valid")
}

pub(super) fn stream_registry_snapshot_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.stream.registry_snapshot.v1").expect("schema literal is valid")
}

pub(super) fn module_runtime_state_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.module.runtime_state.v1").expect("schema literal is valid")
}

pub(super) fn module_runtime_state_change_request_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.module.runtime_state_change_request.v1")
        .expect("schema literal is valid")
}

pub(super) fn module_runtime_state_rejection_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.module.runtime_state_rejection.v1")
        .expect("schema literal is valid")
}

pub(super) fn stream_registry_diff_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.stream.registry_diff.v1").expect("schema literal is valid")
}

pub(super) fn stream_registry_change_request_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.stream.registry_change_request.v1")
        .expect("schema literal is valid")
}

pub(super) fn stream_registry_rejection_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.stream.registry_rejection.v1").expect("schema literal is valid")
}

pub(super) fn stream_subscription_request_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.stream.subscription_request.v1").expect("schema literal is valid")
}

pub(super) fn stream_subscription_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.stream.subscription.v1").expect("schema literal is valid")
}

pub(super) fn stream_subscription_rejection_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.stream.subscription_rejection.v1")
        .expect("schema literal is valid")
}

pub(super) fn stream_subscription_release_request_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.stream.subscription_release_request.v1")
        .expect("schema literal is valid")
}

pub(super) fn stream_subscription_release_rejection_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.stream.subscription_release_rejection.v1")
        .expect("schema literal is valid")
}

pub(super) fn stream_subscription_renewal_request_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.stream.subscription_renewal_request.v1")
        .expect("schema literal is valid")
}

pub(super) fn stream_subscription_renewal_rejection_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.stream.subscription_renewal_rejection.v1")
        .expect("schema literal is valid")
}

pub(super) fn command_ack_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.command.ack.v1").expect("schema literal is valid")
}

pub(super) fn command_rejection_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.command.rejection.v1").expect("schema literal is valid")
}

pub(super) fn control_lease_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.command.control_lease.v1").expect("schema literal is valid")
}

pub(super) fn control_lease_rejection_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.command.lease_rejection.v1").expect("schema literal is valid")
}

pub(super) fn control_lease_release_request_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.command.lease_release_request.v1")
        .expect("schema literal is valid")
}

pub(super) fn control_lease_release_rejection_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.command.lease_release_rejection.v1")
        .expect("schema literal is valid")
}

pub(super) fn control_lease_renewal_request_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.command.lease_renewal_request.v1")
        .expect("schema literal is valid")
}

pub(super) fn control_lease_renewal_rejection_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.command.lease_renewal_rejection.v1")
        .expect("schema literal is valid")
}

pub(super) fn authority_expiry_sweep_request_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.authority.expiry_sweep_request.v1")
        .expect("schema literal is valid")
}

pub(super) fn authority_expiry_sweep_rejection_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.authority.expiry_sweep_rejection.v1")
        .expect("schema literal is valid")
}

pub(super) fn command_authority_audit_event_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.authority.command_audit_event.v1")
        .expect("schema literal is valid")
}

pub(super) fn command_authority_review_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.authority.command_review.v1").expect("schema literal is valid")
}

pub(super) fn command_dispatch_rejection_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.authority.command_dispatch_rejection.v1")
        .expect("schema literal is valid")
}

pub(super) fn command_dispatch_receipt_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.authority.command_dispatch_receipt.v1")
        .expect("schema literal is valid")
}

pub(super) fn control_lease_authority_audit_event_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.authority.lease_audit_event.v1").expect("schema literal is valid")
}

pub(super) fn control_lease_authority_review_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.authority.lease_review.v1").expect("schema literal is valid")
}

pub(super) fn control_lease_authority_application_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.authority.lease_application.v1").expect("schema literal is valid")
}

pub(super) fn control_lease_release_authority_audit_event_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.authority.lease_release_audit_event.v1")
        .expect("schema literal is valid")
}

pub(super) fn control_lease_release_authority_review_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.authority.lease_release_review.v1")
        .expect("schema literal is valid")
}

pub(super) fn control_lease_release_authority_application_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.authority.lease_release_application.v1")
        .expect("schema literal is valid")
}

pub(super) fn control_lease_renewal_authority_audit_event_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.authority.lease_renewal_audit_event.v1")
        .expect("schema literal is valid")
}

pub(super) fn control_lease_renewal_authority_review_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.authority.lease_renewal_review.v1")
        .expect("schema literal is valid")
}

pub(super) fn control_lease_renewal_authority_application_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.authority.lease_renewal_application.v1")
        .expect("schema literal is valid")
}

pub(super) fn stream_registry_authority_audit_event_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.authority.stream_registry_audit_event.v1")
        .expect("schema literal is valid")
}

pub(super) fn stream_registry_authority_review_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.authority.stream_registry_review.v1")
        .expect("schema literal is valid")
}

pub(super) fn stream_registry_authority_application_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.authority.stream_registry_application.v1")
        .expect("schema literal is valid")
}

pub(super) fn stream_subscription_authority_audit_event_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.authority.stream_subscription_audit_event.v1")
        .expect("schema literal is valid")
}

pub(super) fn stream_subscription_authority_review_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.authority.stream_subscription_review.v1")
        .expect("schema literal is valid")
}

pub(super) fn stream_subscription_authority_application_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.authority.stream_subscription_application.v1")
        .expect("schema literal is valid")
}

pub(super) fn stream_subscription_release_authority_audit_event_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.authority.stream_subscription_release_audit_event.v1")
        .expect("schema literal is valid")
}

pub(super) fn stream_subscription_release_authority_review_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.authority.stream_subscription_release_review.v1")
        .expect("schema literal is valid")
}

pub(super) fn stream_subscription_release_authority_application_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.authority.stream_subscription_release_application.v1")
        .expect("schema literal is valid")
}

pub(super) fn stream_subscription_renewal_authority_audit_event_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.authority.stream_subscription_renewal_audit_event.v1")
        .expect("schema literal is valid")
}

pub(super) fn stream_subscription_renewal_authority_review_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.authority.stream_subscription_renewal_review.v1")
        .expect("schema literal is valid")
}

pub(super) fn stream_subscription_renewal_authority_application_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.authority.stream_subscription_renewal_application.v1")
        .expect("schema literal is valid")
}

pub(super) fn authority_expiry_sweep_authority_audit_event_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.authority.expiry_sweep_audit_event.v1")
        .expect("schema literal is valid")
}

pub(super) fn authority_expiry_sweep_authority_review_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.authority.expiry_sweep_review.v1")
        .expect("schema literal is valid")
}

pub(super) fn authority_expiry_sweep_authority_application_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.authority.expiry_sweep_application.v1")
        .expect("schema literal is valid")
}

pub(super) fn authority_snapshot_application_rejection_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.authority.snapshot_application_rejection.v1")
        .expect("schema literal is valid")
}

pub(super) fn module_runtime_state_authority_audit_event_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.authority.module_runtime_state_audit_event.v1")
        .expect("schema literal is valid")
}

pub(super) fn module_runtime_state_authority_review_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.authority.module_runtime_state_review.v1")
        .expect("schema literal is valid")
}

pub(super) fn module_runtime_state_authority_application_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.authority.module_runtime_state_application.v1")
        .expect("schema literal is valid")
}

pub(super) fn host_manifest_authority_audit_event_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.authority.host_manifest_audit_event.v1")
        .expect("schema literal is valid")
}

pub(super) fn host_manifest_authority_review_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.authority.host_manifest_review.v1")
        .expect("schema literal is valid")
}

pub(super) fn host_manifest_authority_application_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.authority.host_manifest_application.v1")
        .expect("schema literal is valid")
}

pub(super) fn clock_snapshot_authority_audit_event_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.authority.clock_snapshot_audit_event.v1")
        .expect("schema literal is valid")
}

pub(super) fn clock_snapshot_authority_review_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.authority.clock_snapshot_review.v1")
        .expect("schema literal is valid")
}

pub(super) fn clock_snapshot_authority_application_schema_id() -> SchemaId {
    SchemaId::new("rusty.manifold.authority.clock_snapshot_application.v1")
        .expect("schema literal is valid")
}

pub(super) fn command_authority_review_id(request_id: &DottedId) -> DottedId {
    DottedId::new(format!("command_review.{}", request_id.as_str()))
        .expect("derived command review id is valid")
}

pub(super) fn command_dispatch_receipt_id(review_id: &DottedId) -> DottedId {
    DottedId::new(format!("command_dispatch.{}", review_id.as_str()))
        .expect("derived command dispatch id is valid")
}

pub(super) fn control_lease_authority_review_id(request_id: &DottedId) -> DottedId {
    DottedId::new(format!("lease_review.{}", request_id.as_str()))
        .expect("derived lease review id is valid")
}

pub(super) fn control_lease_authority_application_id(review_id: &DottedId) -> DottedId {
    DottedId::new(format!("lease_application.{}", review_id.as_str()))
        .expect("derived lease application id is valid")
}

pub(super) fn control_lease_release_authority_review_id(request_id: &DottedId) -> DottedId {
    DottedId::new(format!("lease_release_review.{}", request_id.as_str()))
        .expect("derived lease release review id is valid")
}

pub(super) fn control_lease_release_authority_application_id(review_id: &DottedId) -> DottedId {
    DottedId::new(format!("lease_release_application.{}", review_id.as_str()))
        .expect("derived lease release application id is valid")
}

pub(super) fn control_lease_renewal_authority_review_id(request_id: &DottedId) -> DottedId {
    DottedId::new(format!("lease_renewal_review.{}", request_id.as_str()))
        .expect("derived lease renewal review id is valid")
}

pub(super) fn control_lease_renewal_authority_application_id(review_id: &DottedId) -> DottedId {
    DottedId::new(format!("lease_renewal_application.{}", review_id.as_str()))
        .expect("derived lease renewal application id is valid")
}

pub(super) fn stream_registry_authority_review_id(request_id: &DottedId) -> DottedId {
    DottedId::new(format!("stream_registry_review.{}", request_id.as_str()))
        .expect("derived stream-registry review id is valid")
}

pub(super) fn stream_registry_authority_application_id(review_id: &DottedId) -> DottedId {
    DottedId::new(format!(
        "stream_registry_application.{}",
        review_id.as_str()
    ))
    .expect("derived stream-registry application id is valid")
}

pub(super) fn stream_subscription_authority_review_id(request_id: &DottedId) -> DottedId {
    DottedId::new(format!(
        "stream_subscription_review.{}",
        request_id.as_str()
    ))
    .expect("derived stream subscription review id is valid")
}

pub(super) fn stream_subscription_authority_application_id(review_id: &DottedId) -> DottedId {
    DottedId::new(format!(
        "stream_subscription_application.{}",
        review_id.as_str()
    ))
    .expect("derived stream subscription application id is valid")
}

pub(super) fn stream_subscription_release_authority_review_id(request_id: &DottedId) -> DottedId {
    DottedId::new(format!(
        "stream_subscription_release_review.{}",
        request_id.as_str()
    ))
    .expect("derived stream subscription release review id is valid")
}

pub(super) fn stream_subscription_release_authority_application_id(
    review_id: &DottedId,
) -> DottedId {
    DottedId::new(format!(
        "stream_subscription_release_application.{}",
        review_id.as_str()
    ))
    .expect("derived stream subscription release application id is valid")
}

pub(super) fn stream_subscription_renewal_authority_review_id(request_id: &DottedId) -> DottedId {
    DottedId::new(format!(
        "stream_subscription_renewal_review.{}",
        request_id.as_str()
    ))
    .expect("derived stream subscription renewal review id is valid")
}

pub(super) fn stream_subscription_renewal_authority_application_id(
    review_id: &DottedId,
) -> DottedId {
    DottedId::new(format!(
        "stream_subscription_renewal_application.{}",
        review_id.as_str()
    ))
    .expect("derived stream subscription renewal application id is valid")
}

pub(super) fn authority_expiry_sweep_authority_review_id(request_id: &DottedId) -> DottedId {
    DottedId::new(format!("expiry_sweep_review.{}", request_id.as_str()))
        .expect("derived authority expiry sweep review id is valid")
}

pub(super) fn authority_expiry_sweep_authority_application_id(review_id: &DottedId) -> DottedId {
    DottedId::new(format!("expiry_sweep_application.{}", review_id.as_str()))
        .expect("derived authority expiry sweep application id is valid")
}

pub(super) fn module_runtime_state_authority_review_id(request_id: &DottedId) -> DottedId {
    DottedId::new(format!(
        "module_runtime_state_review.{}",
        request_id.as_str()
    ))
    .expect("derived module runtime-state review id is valid")
}

pub(super) fn module_runtime_state_authority_application_id(review_id: &DottedId) -> DottedId {
    DottedId::new(format!(
        "module_runtime_state_application.{}",
        review_id.as_str()
    ))
    .expect("derived module runtime-state application id is valid")
}

pub(super) fn host_manifest_authority_review_id(request_id: &DottedId) -> DottedId {
    DottedId::new(format!("host_manifest_review.{}", request_id.as_str()))
        .expect("derived host manifest review id is valid")
}

pub(super) fn host_manifest_authority_application_id(review_id: &DottedId) -> DottedId {
    DottedId::new(format!("host_manifest_application.{}", review_id.as_str()))
        .expect("derived host manifest application id is valid")
}

pub(super) fn clock_snapshot_authority_review_id(request_id: &DottedId) -> DottedId {
    DottedId::new(format!("clock_snapshot_review.{}", request_id.as_str()))
        .expect("derived clock snapshot review id is valid")
}

pub(super) fn clock_snapshot_authority_application_id(review_id: &DottedId) -> DottedId {
    DottedId::new(format!("clock_snapshot_application.{}", review_id.as_str()))
        .expect("derived clock snapshot application id is valid")
}

pub(super) fn control_lease_id(request_id: &DottedId) -> DottedId {
    let suffix = request_id
        .as_str()
        .strip_prefix("request.")
        .unwrap_or_else(|| request_id.as_str());
    DottedId::new(format!("lease.{}", suffix)).expect("derived lease id is valid")
}

pub(super) fn stream_subscription_id(request_id: &DottedId) -> DottedId {
    let suffix = request_id
        .as_str()
        .strip_prefix("request.")
        .unwrap_or_else(|| request_id.as_str());
    DottedId::new(format!("subscription.{}", suffix)).expect("derived subscription id is valid")
}

pub(super) fn registry_lease_scope() -> DottedId {
    DottedId::new("manifold.stream_registry").expect("registry lease scope is valid")
}

pub(super) fn host_manifest_lease_scope() -> DottedId {
    DottedId::new("manifold.host_manifest").expect("host-manifest lease scope is valid")
}

pub(super) fn clock_snapshot_lease_scope() -> DottedId {
    DottedId::new("manifold.clock").expect("clock lease scope is valid")
}

pub(super) fn command_authority_audit_event_id(
    request_id: &DottedId,
    outcome: ManifoldCommandAuthorityReviewOutcome,
) -> DottedId {
    let suffix = match outcome {
        ManifoldCommandAuthorityReviewOutcome::CommandAccepted => "accepted",
        ManifoldCommandAuthorityReviewOutcome::CommandRejected => "rejected",
    };
    DottedId::new(format!("audit.command.{}.{}", request_id.as_str(), suffix))
        .expect("derived command audit event id is valid")
}

pub(super) fn control_lease_authority_audit_event_id(
    request_id: &DottedId,
    outcome: ManifoldControlLeaseAuthorityReviewOutcome,
) -> DottedId {
    let suffix = match outcome {
        ManifoldControlLeaseAuthorityReviewOutcome::LeaseAccepted => "accepted",
        ManifoldControlLeaseAuthorityReviewOutcome::LeaseRejected => "rejected",
    };
    DottedId::new(format!("audit.lease.{}.{}", request_id.as_str(), suffix))
        .expect("derived lease audit event id is valid")
}

pub(super) fn control_lease_release_authority_audit_event_id(
    request_id: &DottedId,
    outcome: ManifoldControlLeaseReleaseAuthorityReviewOutcome,
) -> DottedId {
    let suffix = match outcome {
        ManifoldControlLeaseReleaseAuthorityReviewOutcome::LeaseReleased => "released",
        ManifoldControlLeaseReleaseAuthorityReviewOutcome::LeaseReleaseRejected => "rejected",
    };
    DottedId::new(format!(
        "audit.lease_release.{}.{}",
        request_id.as_str(),
        suffix
    ))
    .expect("derived lease release audit event id is valid")
}

pub(super) fn control_lease_renewal_authority_audit_event_id(
    request_id: &DottedId,
    outcome: ManifoldControlLeaseRenewalAuthorityReviewOutcome,
) -> DottedId {
    let suffix = match outcome {
        ManifoldControlLeaseRenewalAuthorityReviewOutcome::LeaseRenewed => "renewed",
        ManifoldControlLeaseRenewalAuthorityReviewOutcome::LeaseRenewalRejected => "rejected",
    };
    DottedId::new(format!(
        "audit.lease_renewal.{}.{}",
        request_id.as_str(),
        suffix
    ))
    .expect("derived lease renewal audit event id is valid")
}

pub(super) fn stream_registry_authority_audit_event_id(
    request_id: &DottedId,
    outcome: ManifoldStreamRegistryAuthorityReviewOutcome,
) -> DottedId {
    let suffix = match outcome {
        ManifoldStreamRegistryAuthorityReviewOutcome::RegistryAccepted => "accepted",
        ManifoldStreamRegistryAuthorityReviewOutcome::RegistryRejected => "rejected",
    };
    DottedId::new(format!(
        "audit.stream_registry.{}.{}",
        request_id.as_str(),
        suffix
    ))
    .expect("derived stream-registry audit event id is valid")
}

pub(super) fn stream_subscription_authority_audit_event_id(
    request_id: &DottedId,
    outcome: ManifoldStreamSubscriptionAuthorityReviewOutcome,
) -> DottedId {
    let suffix = match outcome {
        ManifoldStreamSubscriptionAuthorityReviewOutcome::SubscriptionAccepted => "accepted",
        ManifoldStreamSubscriptionAuthorityReviewOutcome::SubscriptionRejected => "rejected",
    };
    DottedId::new(format!(
        "audit.stream_subscription.{}.{}",
        request_id.as_str(),
        suffix
    ))
    .expect("derived stream subscription audit event id is valid")
}

pub(super) fn stream_subscription_release_authority_audit_event_id(
    request_id: &DottedId,
    outcome: ManifoldStreamSubscriptionReleaseAuthorityReviewOutcome,
) -> DottedId {
    let suffix = match outcome {
        ManifoldStreamSubscriptionReleaseAuthorityReviewOutcome::SubscriptionReleased => "released",
        ManifoldStreamSubscriptionReleaseAuthorityReviewOutcome::SubscriptionReleaseRejected => {
            "rejected"
        }
    };
    DottedId::new(format!(
        "audit.stream_subscription_release.{}.{}",
        request_id.as_str(),
        suffix
    ))
    .expect("derived stream subscription release audit event id is valid")
}

pub(super) fn stream_subscription_renewal_authority_audit_event_id(
    request_id: &DottedId,
    outcome: ManifoldStreamSubscriptionRenewalAuthorityReviewOutcome,
) -> DottedId {
    let suffix = match outcome {
        ManifoldStreamSubscriptionRenewalAuthorityReviewOutcome::SubscriptionRenewed => "renewed",
        ManifoldStreamSubscriptionRenewalAuthorityReviewOutcome::SubscriptionRenewalRejected => {
            "rejected"
        }
    };
    DottedId::new(format!(
        "audit.stream_subscription_renewal.{}.{}",
        request_id.as_str(),
        suffix
    ))
    .expect("derived stream subscription renewal audit event id is valid")
}

pub(super) fn authority_expiry_sweep_authority_audit_event_id(
    request_id: &DottedId,
    outcome: ManifoldAuthorityExpirySweepAuthorityReviewOutcome,
) -> DottedId {
    let suffix = match outcome {
        ManifoldAuthorityExpirySweepAuthorityReviewOutcome::ExpiredStateAccepted => "accepted",
        ManifoldAuthorityExpirySweepAuthorityReviewOutcome::ExpirySweepRejected => "rejected",
    };
    DottedId::new(format!(
        "audit.expiry_sweep.{}.{}",
        request_id.as_str(),
        suffix
    ))
    .expect("derived authority expiry sweep audit event id is valid")
}

pub(super) fn module_runtime_state_authority_audit_event_id(
    request_id: &DottedId,
    outcome: ManifoldModuleRuntimeStateAuthorityReviewOutcome,
) -> DottedId {
    let suffix = match outcome {
        ManifoldModuleRuntimeStateAuthorityReviewOutcome::RuntimeStateAccepted => "accepted",
        ManifoldModuleRuntimeStateAuthorityReviewOutcome::RuntimeStateRejected => "rejected",
    };
    DottedId::new(format!(
        "audit.module_runtime_state.{}.{}",
        request_id.as_str(),
        suffix
    ))
    .expect("derived module runtime-state audit event id is valid")
}

pub(super) fn host_manifest_authority_audit_event_id(
    request_id: &DottedId,
    outcome: ManifoldHostManifestAuthorityReviewOutcome,
) -> DottedId {
    let suffix = match outcome {
        ManifoldHostManifestAuthorityReviewOutcome::HostManifestAccepted => "accepted",
        ManifoldHostManifestAuthorityReviewOutcome::HostManifestRejected => "rejected",
    };
    DottedId::new(format!(
        "audit.host_manifest.{}.{}",
        request_id.as_str(),
        suffix
    ))
    .expect("derived host manifest audit event id is valid")
}

pub(super) fn clock_snapshot_authority_audit_event_id(
    request_id: &DottedId,
    outcome: ManifoldClockSnapshotAuthorityReviewOutcome,
) -> DottedId {
    let suffix = match outcome {
        ManifoldClockSnapshotAuthorityReviewOutcome::ClockSnapshotAccepted => "accepted",
        ManifoldClockSnapshotAuthorityReviewOutcome::ClockSnapshotRejected => "rejected",
    };
    DottedId::new(format!(
        "audit.clock_snapshot.{}.{}",
        request_id.as_str(),
        suffix
    ))
    .expect("derived clock snapshot audit event id is valid")
}
