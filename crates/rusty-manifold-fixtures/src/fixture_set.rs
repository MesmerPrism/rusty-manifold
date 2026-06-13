use super::*;

#[derive(Debug)]
pub(super) struct FixtureSet {
    pub(super) package_manifest: ManifoldPackageManifest,
    pub(super) valid_graph: ManifoldGraphManifest,
    pub(super) module_manifests: Vec<ManifoldModuleManifest>,
    pub(super) next_provider_runtime: ManifoldModuleRuntimeState,
    pub(super) valid_registry: ManifoldStreamRegistrySnapshot,
    pub(super) stream_registry_diff: ManifoldStreamRegistryDiff,
    pub(super) command_descriptor: ManifoldCommandDescriptor,
    pub(super) valid_envelope: ManifoldCommandEnvelope,
    pub(super) lease_request: ManifoldControlLeaseRequest,
    pub(super) control_lease: ManifoldControlLease,
    pub(super) authority_snapshot: ManifoldAuthoritySnapshot,
    pub(super) authority_snapshot_v2: ManifoldAuthoritySnapshot,
    pub(super) command_review_clock: ManifoldClockSnapshot,
    pub(super) expired_command_review_clock: ManifoldClockSnapshot,
    pub(super) command_authority_audit_event: ManifoldCommandAuthorityAuditEvent,
    pub(super) accepted_command_review: ManifoldCommandAuthorityReview,
    pub(super) stale_revision_command_review: ManifoldCommandAuthorityReview,
    pub(super) expired_lease_command_review: ManifoldCommandAuthorityReview,
    pub(super) missing_lease_command_review: ManifoldCommandAuthorityReview,
    pub(super) unknown_command_review_envelope: ManifoldCommandEnvelope,
    pub(super) unknown_command_review: ManifoldCommandAuthorityReview,
    pub(super) unknown_lease_review_envelope: ManifoldCommandEnvelope,
    pub(super) unknown_lease_command_review: ManifoldCommandAuthorityReview,
    pub(super) capability_mismatch_review_envelope: ManifoldCommandEnvelope,
    pub(super) capability_mismatch_command_review: ManifoldCommandAuthorityReview,
    pub(super) command_dispatch_rejection: ManifoldCommandDispatchRejection,
    pub(super) accepted_command_dispatch: Box<ManifoldCommandDispatchReceipt>,
    pub(super) rejected_command_dispatch: Box<ManifoldCommandDispatchReceipt>,
    pub(super) remote_camera_authority_snapshot: ManifoldAuthoritySnapshot,
    pub(super) remote_camera_command_reviews: Vec<ManifoldCommandAuthorityReview>,
    pub(super) remote_camera_command_dispatches: Vec<Box<ManifoldCommandDispatchReceipt>>,
    pub(super) lease_rejection: ManifoldControlLeaseRejection,
    pub(super) lease_authority_audit_event: ManifoldControlLeaseAuthorityAuditEvent,
    pub(super) accepted_lease_review: ManifoldControlLeaseAuthorityReview,
    pub(super) stale_lease_request: ManifoldControlLeaseRequest,
    pub(super) stale_revision_lease_review: ManifoldControlLeaseAuthorityReview,
    pub(super) zero_ttl_lease_request: ManifoldControlLeaseRequest,
    pub(super) zero_ttl_lease_review: ManifoldControlLeaseAuthorityReview,
    pub(super) missing_capability_lease_request: ManifoldControlLeaseRequest,
    pub(super) missing_capability_lease_review: ManifoldControlLeaseAuthorityReview,
    pub(super) busy_scope_lease_request: ManifoldControlLeaseRequest,
    pub(super) busy_scope_lease_review: ManifoldControlLeaseAuthorityReview,
    pub(super) accepted_lease_application: Box<ManifoldControlLeaseAuthorityApplication>,
    pub(super) rejected_lease_application: Box<ManifoldControlLeaseAuthorityApplication>,
    pub(super) lease_application_rejection: ManifoldAuthoritySnapshotApplicationRejection,
    pub(super) lease_active_authority_snapshot: ManifoldAuthoritySnapshot,
    pub(super) lease_release_request: ManifoldControlLeaseReleaseRequest,
    pub(super) lease_release_rejection: ManifoldControlLeaseReleaseRejection,
    pub(super) lease_release_authority_audit_event: ManifoldControlLeaseReleaseAuthorityAuditEvent,
    pub(super) accepted_lease_release_review: ManifoldControlLeaseReleaseAuthorityReview,
    pub(super) expired_lease_release_review: ManifoldControlLeaseReleaseAuthorityReview,
    pub(super) stale_lease_release_request: ManifoldControlLeaseReleaseRequest,
    pub(super) stale_lease_release_review: ManifoldControlLeaseReleaseAuthorityReview,
    pub(super) unknown_lease_release_request: ManifoldControlLeaseReleaseRequest,
    pub(super) unknown_lease_release_review: ManifoldControlLeaseReleaseAuthorityReview,
    pub(super) holder_mismatch_lease_release_request: ManifoldControlLeaseReleaseRequest,
    pub(super) holder_mismatch_lease_release_review: ManifoldControlLeaseReleaseAuthorityReview,
    pub(super) scope_mismatch_lease_release_request: ManifoldControlLeaseReleaseRequest,
    pub(super) scope_mismatch_lease_release_review: ManifoldControlLeaseReleaseAuthorityReview,
    pub(super) accepted_lease_release_application:
        Box<ManifoldControlLeaseReleaseAuthorityApplication>,
    pub(super) rejected_lease_release_application:
        Box<ManifoldControlLeaseReleaseAuthorityApplication>,
    pub(super) lease_release_application_rejection: ManifoldAuthoritySnapshotApplicationRejection,
    pub(super) lease_renewal_request: ManifoldControlLeaseRenewalRequest,
    pub(super) lease_renewal_rejection: ManifoldControlLeaseRenewalRejection,
    pub(super) lease_renewal_authority_audit_event: ManifoldControlLeaseRenewalAuthorityAuditEvent,
    pub(super) accepted_lease_renewal_review: ManifoldControlLeaseRenewalAuthorityReview,
    pub(super) stale_lease_renewal_request: ManifoldControlLeaseRenewalRequest,
    pub(super) stale_lease_renewal_review: ManifoldControlLeaseRenewalAuthorityReview,
    pub(super) unknown_lease_renewal_request: ManifoldControlLeaseRenewalRequest,
    pub(super) unknown_lease_renewal_review: ManifoldControlLeaseRenewalAuthorityReview,
    pub(super) holder_mismatch_lease_renewal_request: ManifoldControlLeaseRenewalRequest,
    pub(super) holder_mismatch_lease_renewal_review: ManifoldControlLeaseRenewalAuthorityReview,
    pub(super) scope_mismatch_lease_renewal_request: ManifoldControlLeaseRenewalRequest,
    pub(super) scope_mismatch_lease_renewal_review: ManifoldControlLeaseRenewalAuthorityReview,
    pub(super) zero_ttl_lease_renewal_request: ManifoldControlLeaseRenewalRequest,
    pub(super) zero_ttl_lease_renewal_review: ManifoldControlLeaseRenewalAuthorityReview,
    pub(super) non_extending_lease_renewal_request: ManifoldControlLeaseRenewalRequest,
    pub(super) non_extending_lease_renewal_review: ManifoldControlLeaseRenewalAuthorityReview,
    pub(super) expired_lease_renewal_review: ManifoldControlLeaseRenewalAuthorityReview,
    pub(super) accepted_lease_renewal_application:
        Box<ManifoldControlLeaseRenewalAuthorityApplication>,
    pub(super) rejected_lease_renewal_application:
        Box<ManifoldControlLeaseRenewalAuthorityApplication>,
    pub(super) lease_renewal_application_rejection: ManifoldAuthoritySnapshotApplicationRejection,
    pub(super) stream_registry_lease: ManifoldControlLease,
    pub(super) stream_registry_change_request: ManifoldStreamRegistryChangeRequest,
    pub(super) stream_registry_rejection: ManifoldStreamRegistryRejection,
    pub(super) stream_registry_authority_audit_event: ManifoldStreamRegistryAuthorityAuditEvent,
    pub(super) accepted_stream_registry_review: ManifoldStreamRegistryAuthorityReview,
    pub(super) expired_lease_stream_registry_review: ManifoldStreamRegistryAuthorityReview,
    pub(super) stale_stream_registry_request: ManifoldStreamRegistryChangeRequest,
    pub(super) stale_stream_registry_review: ManifoldStreamRegistryAuthorityReview,
    pub(super) missing_lease_stream_registry_request: ManifoldStreamRegistryChangeRequest,
    pub(super) missing_lease_stream_registry_review: ManifoldStreamRegistryAuthorityReview,
    pub(super) active_stream_registry_request: ManifoldStreamRegistryChangeRequest,
    pub(super) active_stream_registry_review: ManifoldStreamRegistryAuthorityReview,
    pub(super) remove_active_transport_stream_registry_request: ManifoldStreamRegistryChangeRequest,
    pub(super) remove_active_transport_stream_registry_review:
        ManifoldStreamRegistryAuthorityReview,
    pub(super) disable_active_ui_stream_registry_request: ManifoldStreamRegistryChangeRequest,
    pub(super) disable_active_ui_stream_registry_review: ManifoldStreamRegistryAuthorityReview,
    pub(super) lower_active_subscriber_limit_stream_registry_request:
        ManifoldStreamRegistryChangeRequest,
    pub(super) lower_active_subscriber_limit_stream_registry_review:
        ManifoldStreamRegistryAuthorityReview,
    pub(super) unknown_module_stream_registry_request: ManifoldStreamRegistryChangeRequest,
    pub(super) unknown_module_stream_registry_review: ManifoldStreamRegistryAuthorityReview,
    pub(super) unknown_endpoint_stream_registry_request: ManifoldStreamRegistryChangeRequest,
    pub(super) unknown_endpoint_stream_registry_review: ManifoldStreamRegistryAuthorityReview,
    pub(super) accepted_stream_registry_application:
        Box<ManifoldStreamRegistryAuthorityApplication>,
    pub(super) rejected_stream_registry_application:
        Box<ManifoldStreamRegistryAuthorityApplication>,
    pub(super) stream_registry_application_rejection: ManifoldAuthoritySnapshotApplicationRejection,
    pub(super) stream_subscription_authority_snapshot: ManifoldAuthoritySnapshot,
    pub(super) stream_subscription_request: ManifoldStreamSubscriptionRequest,
    pub(super) stream_subscription: ManifoldStreamSubscription,
    pub(super) stream_subscription_rejection: ManifoldStreamSubscriptionRejection,
    pub(super) stream_subscription_authority_audit_event:
        ManifoldStreamSubscriptionAuthorityAuditEvent,
    pub(super) accepted_stream_subscription_review: ManifoldStreamSubscriptionAuthorityReview,
    pub(super) zero_ttl_stream_subscription_request: ManifoldStreamSubscriptionRequest,
    pub(super) zero_ttl_stream_subscription_review: ManifoldStreamSubscriptionAuthorityReview,
    pub(super) missing_capability_stream_subscription_request: ManifoldStreamSubscriptionRequest,
    pub(super) missing_capability_stream_subscription_review:
        ManifoldStreamSubscriptionAuthorityReview,
    pub(super) stale_stream_subscription_request: ManifoldStreamSubscriptionRequest,
    pub(super) stale_stream_subscription_review: ManifoldStreamSubscriptionAuthorityReview,
    pub(super) stale_registry_stream_subscription_request: ManifoldStreamSubscriptionRequest,
    pub(super) stale_registry_stream_subscription_review: ManifoldStreamSubscriptionAuthorityReview,
    pub(super) unknown_stream_subscription_request: ManifoldStreamSubscriptionRequest,
    pub(super) unknown_stream_subscription_review: ManifoldStreamSubscriptionAuthorityReview,
    pub(super) unknown_transport_stream_subscription_request: ManifoldStreamSubscriptionRequest,
    pub(super) unknown_transport_stream_subscription_review:
        ManifoldStreamSubscriptionAuthorityReview,
    pub(super) subscriber_limit_stream_subscription_authority_snapshot: ManifoldAuthoritySnapshot,
    pub(super) subscriber_limit_stream_subscription_request: ManifoldStreamSubscriptionRequest,
    pub(super) subscriber_limit_stream_subscription_review:
        ManifoldStreamSubscriptionAuthorityReview,
    pub(super) ui_disabled_stream_subscription_authority_snapshot: ManifoldAuthoritySnapshot,
    pub(super) ui_disabled_stream_subscription_request: ManifoldStreamSubscriptionRequest,
    pub(super) ui_disabled_stream_subscription_review: ManifoldStreamSubscriptionAuthorityReview,
    pub(super) accepted_stream_subscription_application:
        Box<ManifoldStreamSubscriptionAuthorityApplication>,
    pub(super) rejected_stream_subscription_application:
        Box<ManifoldStreamSubscriptionAuthorityApplication>,
    pub(super) stream_subscription_application_rejection:
        ManifoldAuthoritySnapshotApplicationRejection,
    pub(super) stream_subscription_active_authority_snapshot: ManifoldAuthoritySnapshot,
    pub(super) stream_subscription_release_request: ManifoldStreamSubscriptionReleaseRequest,
    pub(super) stream_subscription_release_rejection: ManifoldStreamSubscriptionReleaseRejection,
    pub(super) stream_subscription_release_authority_audit_event:
        ManifoldStreamSubscriptionReleaseAuthorityAuditEvent,
    pub(super) accepted_stream_subscription_release_review:
        ManifoldStreamSubscriptionReleaseAuthorityReview,
    pub(super) expired_stream_subscription_release_review:
        ManifoldStreamSubscriptionReleaseAuthorityReview,
    pub(super) stale_stream_subscription_release_request: ManifoldStreamSubscriptionReleaseRequest,
    pub(super) stale_stream_subscription_release_review:
        ManifoldStreamSubscriptionReleaseAuthorityReview,
    pub(super) stale_registry_stream_subscription_release_request:
        ManifoldStreamSubscriptionReleaseRequest,
    pub(super) stale_registry_stream_subscription_release_review:
        ManifoldStreamSubscriptionReleaseAuthorityReview,
    pub(super) unknown_stream_subscription_release_request:
        ManifoldStreamSubscriptionReleaseRequest,
    pub(super) unknown_stream_subscription_release_review:
        ManifoldStreamSubscriptionReleaseAuthorityReview,
    pub(super) subscriber_mismatch_stream_subscription_release_request:
        ManifoldStreamSubscriptionReleaseRequest,
    pub(super) subscriber_mismatch_stream_subscription_release_review:
        ManifoldStreamSubscriptionReleaseAuthorityReview,
    pub(super) stream_mismatch_stream_subscription_release_request:
        ManifoldStreamSubscriptionReleaseRequest,
    pub(super) stream_mismatch_stream_subscription_release_review:
        ManifoldStreamSubscriptionReleaseAuthorityReview,
    pub(super) accepted_stream_subscription_release_application:
        Box<ManifoldStreamSubscriptionReleaseAuthorityApplication>,
    pub(super) rejected_stream_subscription_release_application:
        Box<ManifoldStreamSubscriptionReleaseAuthorityApplication>,
    pub(super) stream_subscription_release_application_rejection:
        ManifoldAuthoritySnapshotApplicationRejection,
    pub(super) stream_subscription_renewal_request: ManifoldStreamSubscriptionRenewalRequest,
    pub(super) stream_subscription_renewal_rejection: ManifoldStreamSubscriptionRenewalRejection,
    pub(super) stream_subscription_renewal_authority_audit_event:
        ManifoldStreamSubscriptionRenewalAuthorityAuditEvent,
    pub(super) accepted_stream_subscription_renewal_review:
        ManifoldStreamSubscriptionRenewalAuthorityReview,
    pub(super) stale_stream_subscription_renewal_request: ManifoldStreamSubscriptionRenewalRequest,
    pub(super) stale_stream_subscription_renewal_review:
        ManifoldStreamSubscriptionRenewalAuthorityReview,
    pub(super) stale_registry_stream_subscription_renewal_request:
        ManifoldStreamSubscriptionRenewalRequest,
    pub(super) stale_registry_stream_subscription_renewal_review:
        ManifoldStreamSubscriptionRenewalAuthorityReview,
    pub(super) unknown_stream_subscription_renewal_request:
        ManifoldStreamSubscriptionRenewalRequest,
    pub(super) unknown_stream_subscription_renewal_review:
        ManifoldStreamSubscriptionRenewalAuthorityReview,
    pub(super) subscriber_mismatch_stream_subscription_renewal_request:
        ManifoldStreamSubscriptionRenewalRequest,
    pub(super) subscriber_mismatch_stream_subscription_renewal_review:
        ManifoldStreamSubscriptionRenewalAuthorityReview,
    pub(super) stream_mismatch_stream_subscription_renewal_request:
        ManifoldStreamSubscriptionRenewalRequest,
    pub(super) stream_mismatch_stream_subscription_renewal_review:
        ManifoldStreamSubscriptionRenewalAuthorityReview,
    pub(super) transport_mismatch_stream_subscription_renewal_request:
        ManifoldStreamSubscriptionRenewalRequest,
    pub(super) transport_mismatch_stream_subscription_renewal_review:
        ManifoldStreamSubscriptionRenewalAuthorityReview,
    pub(super) zero_ttl_stream_subscription_renewal_request:
        ManifoldStreamSubscriptionRenewalRequest,
    pub(super) zero_ttl_stream_subscription_renewal_review:
        ManifoldStreamSubscriptionRenewalAuthorityReview,
    pub(super) non_extending_stream_subscription_renewal_request:
        ManifoldStreamSubscriptionRenewalRequest,
    pub(super) non_extending_stream_subscription_renewal_review:
        ManifoldStreamSubscriptionRenewalAuthorityReview,
    pub(super) expired_stream_subscription_renewal_review:
        ManifoldStreamSubscriptionRenewalAuthorityReview,
    pub(super) accepted_stream_subscription_renewal_application:
        Box<ManifoldStreamSubscriptionRenewalAuthorityApplication>,
    pub(super) rejected_stream_subscription_renewal_application:
        Box<ManifoldStreamSubscriptionRenewalAuthorityApplication>,
    pub(super) stream_subscription_renewal_application_rejection:
        ManifoldAuthoritySnapshotApplicationRejection,
    pub(super) authority_expiry_sweep_request: ManifoldAuthorityExpirySweepRequest,
    pub(super) authority_expiry_sweep_rejection: ManifoldAuthorityExpirySweepRejection,
    pub(super) authority_expiry_sweep_authority_audit_event:
        ManifoldAuthorityExpirySweepAuthorityAuditEvent,
    pub(super) accepted_authority_expiry_sweep_review: ManifoldAuthorityExpirySweepAuthorityReview,
    pub(super) stale_authority_expiry_sweep_request: ManifoldAuthorityExpirySweepRequest,
    pub(super) stale_authority_expiry_sweep_review: ManifoldAuthorityExpirySweepAuthorityReview,
    pub(super) registry_mismatch_authority_expiry_sweep_request:
        ManifoldAuthorityExpirySweepRequest,
    pub(super) registry_mismatch_authority_expiry_sweep_review:
        ManifoldAuthorityExpirySweepAuthorityReview,
    pub(super) no_expired_authority_expiry_sweep_review:
        ManifoldAuthorityExpirySweepAuthorityReview,
    pub(super) accepted_authority_expiry_sweep_application:
        Box<ManifoldAuthorityExpirySweepAuthorityApplication>,
    pub(super) rejected_authority_expiry_sweep_application:
        Box<ManifoldAuthorityExpirySweepAuthorityApplication>,
    pub(super) authority_expiry_sweep_application_rejection:
        ManifoldAuthoritySnapshotApplicationRejection,
    pub(super) module_runtime_state_change_request: ManifoldModuleRuntimeStateChangeRequest,
    pub(super) module_runtime_state_rejection: ManifoldModuleRuntimeStateRejection,
    pub(super) module_runtime_state_authority_audit_event:
        ManifoldModuleRuntimeStateAuthorityAuditEvent,
    pub(super) accepted_module_runtime_review: ManifoldModuleRuntimeStateAuthorityReview,
    pub(super) expired_lease_module_runtime_review: ManifoldModuleRuntimeStateAuthorityReview,
    pub(super) stale_module_runtime_request: ManifoldModuleRuntimeStateChangeRequest,
    pub(super) stale_module_runtime_review: ManifoldModuleRuntimeStateAuthorityReview,
    pub(super) missing_lease_module_runtime_request: ManifoldModuleRuntimeStateChangeRequest,
    pub(super) missing_lease_module_runtime_review: ManifoldModuleRuntimeStateAuthorityReview,
    pub(super) unknown_stream_module_runtime_request: ManifoldModuleRuntimeStateChangeRequest,
    pub(super) unknown_stream_module_runtime_review: ManifoldModuleRuntimeStateAuthorityReview,
    pub(super) missing_backend_module_runtime_request: ManifoldModuleRuntimeStateChangeRequest,
    pub(super) missing_backend_module_runtime_review: ManifoldModuleRuntimeStateAuthorityReview,
    pub(super) accepted_module_runtime_application:
        Box<ManifoldModuleRuntimeStateAuthorityApplication>,
    pub(super) rejected_module_runtime_application:
        Box<ManifoldModuleRuntimeStateAuthorityApplication>,
    pub(super) module_runtime_application_rejection: ManifoldAuthoritySnapshotApplicationRejection,
    pub(super) host_manifest_lease: ManifoldControlLease,
    pub(super) host_manifest_change_request: ManifoldHostManifestChangeRequest,
    pub(super) host_manifest_rejection: ManifoldHostManifestRejection,
    pub(super) host_manifest_authority_audit_event: ManifoldHostManifestAuthorityAuditEvent,
    pub(super) accepted_host_manifest_review: ManifoldHostManifestAuthorityReview,
    pub(super) expired_lease_host_manifest_review: ManifoldHostManifestAuthorityReview,
    pub(super) stale_host_manifest_request: ManifoldHostManifestChangeRequest,
    pub(super) stale_host_manifest_review: ManifoldHostManifestAuthorityReview,
    pub(super) missing_authority_role_host_manifest_request: ManifoldHostManifestChangeRequest,
    pub(super) missing_authority_role_host_manifest_review: ManifoldHostManifestAuthorityReview,
    pub(super) endpoint_mismatch_host_manifest_request: ManifoldHostManifestChangeRequest,
    pub(super) endpoint_mismatch_host_manifest_review: ManifoldHostManifestAuthorityReview,
    pub(super) remove_capability_host_manifest_request: ManifoldHostManifestChangeRequest,
    pub(super) remove_capability_host_manifest_review: ManifoldHostManifestAuthorityReview,
    pub(super) remove_backend_host_manifest_request: ManifoldHostManifestChangeRequest,
    pub(super) remove_backend_host_manifest_review: ManifoldHostManifestAuthorityReview,
    pub(super) accepted_host_manifest_application: Box<ManifoldHostManifestAuthorityApplication>,
    pub(super) rejected_host_manifest_application: Box<ManifoldHostManifestAuthorityApplication>,
    pub(super) host_manifest_application_rejection: ManifoldAuthoritySnapshotApplicationRejection,
    pub(super) clock_lease: ManifoldControlLease,
    pub(super) clock_change_request: ManifoldClockSnapshotChangeRequest,
    pub(super) clock_rejection: ManifoldClockSnapshotRejection,
    pub(super) clock_authority_audit_event: ManifoldClockSnapshotAuthorityAuditEvent,
    pub(super) accepted_clock_review: ManifoldClockSnapshotAuthorityReview,
    pub(super) expired_lease_clock_review: ManifoldClockSnapshotAuthorityReview,
    pub(super) stale_clock_request: ManifoldClockSnapshotChangeRequest,
    pub(super) stale_clock_review: ManifoldClockSnapshotAuthorityReview,
    pub(super) missing_lease_clock_request: ManifoldClockSnapshotChangeRequest,
    pub(super) missing_lease_clock_review: ManifoldClockSnapshotAuthorityReview,
    pub(super) domain_mismatch_clock_request: ManifoldClockSnapshotChangeRequest,
    pub(super) domain_mismatch_clock_review: ManifoldClockSnapshotAuthorityReview,
    pub(super) sequence_gap_clock_request: ManifoldClockSnapshotChangeRequest,
    pub(super) sequence_gap_clock_review: ManifoldClockSnapshotAuthorityReview,
    pub(super) monotonic_regression_clock_request: ManifoldClockSnapshotChangeRequest,
    pub(super) monotonic_regression_clock_review: ManifoldClockSnapshotAuthorityReview,
    pub(super) accepted_clock_application: Box<ManifoldClockSnapshotAuthorityApplication>,
    pub(super) rejected_clock_application: Box<ManifoldClockSnapshotAuthorityApplication>,
    pub(super) clock_application_rejection: ManifoldAuthoritySnapshotApplicationRejection,
    pub(super) valid_host: ManifoldHostManifest,
    pub(super) deployment_manifest: ManifoldDeploymentManifest,
    pub(super) deployment_selection: ManifoldDeploymentSelectionSnapshot,
    pub(super) damaged_endpoint_host: ManifoldHostManifest,
    pub(super) damaged_stale_command: ManifoldCommandEnvelope,
    pub(super) damaged_missing_lease_command: ManifoldCommandEnvelope,
    pub(super) damaged_command_authority_audit_event: ManifoldCommandAuthorityAuditEvent,
    pub(super) damaged_unknown_stream_module: ManifoldStreamRegistrySnapshot,
    pub(super) damaged_unknown_graph_module: ManifoldGraphManifest,
    pub(super) damaged_unknown_graph_node: ManifoldGraphManifest,
    pub(super) damaged_unavailable_deployment: ManifoldDeploymentManifest,
    pub(super) platform_hosts: Vec<ManifoldHostManifest>,
    pub(super) host_run_profiles: Vec<ManifoldHostRunInstallLaunchProfile>,
    pub(super) host_run_slot: ManifoldHostRunValidationSlot,
    pub(super) host_run_bundle: ManifoldHostRunBundle,
    pub(super) host_run_command: ManifoldHostRunCommandEnvelope,
    pub(super) host_run_evidence: ManifoldHostRunEvidence,
    pub(super) shell_handoff: ManifoldShellHandoffManifest,
    pub(super) shell_handoff_review: ManifoldShellHandoffReviewReceipt,
    pub(super) damaged_shell_handoff: ManifoldShellHandoffManifest,
    pub(super) damaged_shell_handoff_review: ManifoldShellHandoffReviewReceipt,
}

impl FixtureSet {
    pub(super) fn load(repo_root: &Path) -> Result<Self, CliError> {
        let package_manifest =
            read_model(repo_root.join("fixtures/package/synthetic-package.json"))?;
        let valid_graph =
            read_model(repo_root.join("fixtures/graph/synthetic-wave-pipeline.json"))?;
        read_model::<ManifoldGraphManifest>(
            repo_root.join("fixtures/graph/synthetic-wave-pipeline-v2.json"),
        )?;
        let provider_manifest =
            read_model(repo_root.join("fixtures/module/synthetic-wave-provider.json"))?;
        let processor_manifest =
            read_model(repo_root.join("fixtures/module/synthetic-wave-processor.json"))?;
        read_model::<ManifoldModuleRuntimeState>(
            repo_root.join("fixtures/module/synthetic-wave-runtime-state.json"),
        )?;
        read_model::<ManifoldModuleRuntimeState>(
            repo_root.join("fixtures/module/synthetic-processor-runtime-state.json"),
        )?;
        let next_provider_runtime =
            read_model(repo_root.join("fixtures/module/synthetic-wave-runtime-state-v2.json"))?;

        read_model::<ManifoldStreamManifest>(
            repo_root.join("fixtures/stream/synthetic-wave-stream.json"),
        )?;
        read_model::<ManifoldStreamManifest>(
            repo_root.join("fixtures/stream/synthetic-rms-stream.json"),
        )?;

        let valid_registry =
            read_model(repo_root.join("fixtures/stream/synthetic-stream-registry.json"))?;
        read_model::<ManifoldStreamRegistrySnapshot>(
            repo_root.join("fixtures/stream/synthetic-stream-registry-v2.json"),
        )?;
        let stream_registry_diff =
            read_model(repo_root.join("fixtures/stream/synthetic-stream-registry-diff.json"))?;
        let command_descriptor =
            read_model(repo_root.join("fixtures/command/synthetic-command-descriptor.json"))?;
        let valid_envelope =
            read_model(repo_root.join("fixtures/command/synthetic-command-envelope.json"))?;
        read_model::<ManifoldCommandAck>(
            repo_root.join("fixtures/command/synthetic-command-ack.json"),
        )?;
        read_model::<ManifoldCommandRejection>(
            repo_root.join("fixtures/command/synthetic-command-rejection.json"),
        )?;
        let lease_request =
            read_model(repo_root.join("fixtures/command/synthetic-lease-request.json"))?;
        let control_lease =
            read_model(repo_root.join("fixtures/command/synthetic-control-lease.json"))?;
        let authority_snapshot =
            read_model(repo_root.join("fixtures/authority/synthetic-authority-snapshot.json"))?;
        let authority_snapshot_v2 =
            read_model(repo_root.join("fixtures/authority/synthetic-authority-snapshot-v2.json"))?;
        let command_review_clock =
            read_model(repo_root.join("fixtures/clock/synthetic-command-review-clock.json"))?;
        let expired_command_review_clock = read_model(
            repo_root.join("fixtures/clock/synthetic-expired-command-review-clock.json"),
        )?;
        let command_authority_audit_event =
            read_model(repo_root.join("fixtures/audit/synthetic-command-accepted-event.json"))?;
        let accepted_command_review = read_model(
            repo_root.join("fixtures/authority-review/synthetic-command-accepted-review.json"),
        )?;
        let stale_revision_command_review = read_model(
            repo_root
                .join("fixtures/authority-review/synthetic-command-stale-revision-review.json"),
        )?;
        let expired_lease_command_review = read_model(
            repo_root.join("fixtures/authority-review/synthetic-command-expired-lease-review.json"),
        )?;
        let missing_lease_command_review = read_model(
            repo_root.join("fixtures/authority-review/synthetic-command-missing-lease-review.json"),
        )?;
        let unknown_command_review_envelope =
            read_model(repo_root.join("fixtures/damaged/authority-review-unknown-command.json"))?;
        let unknown_command_review = read_model(
            repo_root
                .join("fixtures/authority-review/synthetic-command-unknown-command-review.json"),
        )?;
        let unknown_lease_review_envelope = read_model(
            repo_root.join("fixtures/damaged/authority-review-unknown-lease-command.json"),
        )?;
        let unknown_lease_command_review = read_model(
            repo_root.join("fixtures/authority-review/synthetic-command-unknown-lease-review.json"),
        )?;
        let capability_mismatch_review_envelope = read_model(
            repo_root.join("fixtures/damaged/authority-review-capability-mismatch-command.json"),
        )?;
        let capability_mismatch_command_review =
            read_model(repo_root.join(
                "fixtures/authority-review/synthetic-command-capability-mismatch-review.json",
            ))?;
        let command_dispatch_rejection = read_model(
            repo_root.join("fixtures/command-dispatch/synthetic-command-dispatch-rejection.json"),
        )?;
        let accepted_command_dispatch: Box<ManifoldCommandDispatchReceipt> = read_model(
            repo_root
                .join("fixtures/command-dispatch/synthetic-command-dispatch-ready-receipt.json"),
        )?;
        let rejected_command_dispatch: Box<ManifoldCommandDispatchReceipt> = read_model(
            repo_root
                .join("fixtures/command-dispatch/synthetic-command-dispatch-rejected-receipt.json"),
        )?;
        let remote_camera_authority_snapshot = read_model(
            repo_root.join("fixtures/authority/remote-camera-q2q-authority-snapshot.json"),
        )?;
        let remote_camera_command_reviews = vec![
            read_model(
                repo_root
                    .join("fixtures/authority-review/remote-camera-q2q-start-receiver-review.json"),
            )?,
            read_model(
                repo_root
                    .join("fixtures/authority-review/remote-camera-q2q-start-sender-review.json"),
            )?,
            read_model(
                repo_root
                    .join("fixtures/authority-review/remote-camera-q2q-get-status-review.json"),
            )?,
            read_model(
                repo_root.join("fixtures/authority-review/remote-camera-q2q-stop-review.json"),
            )?,
        ];
        let remote_camera_command_dispatches = vec![
            read_model(repo_root.join(
                "fixtures/command-dispatch/remote-camera-q2q-start-receiver-dispatch-receipt.json",
            ))?,
            read_model(repo_root.join(
                "fixtures/command-dispatch/remote-camera-q2q-start-sender-dispatch-receipt.json",
            ))?,
            read_model(repo_root.join(
                "fixtures/command-dispatch/remote-camera-q2q-get-status-dispatch-receipt.json",
            ))?,
            read_model(
                repo_root
                    .join("fixtures/command-dispatch/remote-camera-q2q-stop-dispatch-receipt.json"),
            )?,
        ];
        let lease_rejection =
            read_model(repo_root.join("fixtures/command/synthetic-lease-rejection.json"))?;
        let lease_authority_audit_event =
            read_model(repo_root.join("fixtures/audit/synthetic-lease-accepted-event.json"))?;
        let accepted_lease_review = read_model(
            repo_root.join("fixtures/lease-review/synthetic-lease-accepted-review.json"),
        )?;
        let stale_lease_request =
            read_model(repo_root.join("fixtures/damaged/lease-request-stale-revision.json"))?;
        let stale_revision_lease_review = read_model(
            repo_root.join("fixtures/lease-review/synthetic-lease-stale-revision-review.json"),
        )?;
        let zero_ttl_lease_request =
            read_model(repo_root.join("fixtures/damaged/lease-request-zero-ttl.json"))?;
        let zero_ttl_lease_review = read_model(
            repo_root.join("fixtures/lease-review/synthetic-lease-zero-ttl-review.json"),
        )?;
        let missing_capability_lease_request =
            read_model(repo_root.join("fixtures/damaged/lease-request-missing-capability.json"))?;
        let missing_capability_lease_review = read_model(
            repo_root.join("fixtures/lease-review/synthetic-lease-missing-capability-review.json"),
        )?;
        let busy_scope_lease_request =
            read_model(repo_root.join("fixtures/damaged/lease-request-busy-scope.json"))?;
        let busy_scope_lease_review = read_model(
            repo_root.join("fixtures/lease-review/synthetic-lease-busy-scope-review.json"),
        )?;
        let accepted_lease_application: Box<ManifoldControlLeaseAuthorityApplication> = read_model(
            repo_root
                .join("fixtures/authority-application/synthetic-lease-accepted-application.json"),
        )?;
        let rejected_lease_application: Box<ManifoldControlLeaseAuthorityApplication> = read_model(
            repo_root
                .join("fixtures/authority-application/synthetic-lease-rejected-application.json"),
        )?;
        let lease_application_rejection = read_model(
            repo_root
                .join("fixtures/authority-application/synthetic-lease-application-rejection.json"),
        )?;
        let lease_active_authority_snapshot = read_model(
            repo_root.join("fixtures/authority/synthetic-lease-active-authority-snapshot.json"),
        )?;
        let lease_release_request =
            read_model(repo_root.join("fixtures/command/synthetic-lease-release-request.json"))?;
        let lease_release_rejection =
            read_model(repo_root.join("fixtures/command/synthetic-lease-release-rejection.json"))?;
        let lease_release_authority_audit_event = read_model(
            repo_root.join("fixtures/audit/synthetic-lease-release-accepted-event.json"),
        )?;
        let accepted_lease_release_review = read_model(
            repo_root
                .join("fixtures/lease-release-review/synthetic-lease-release-accepted-review.json"),
        )?;
        let expired_lease_release_review = read_model(repo_root.join(
            "fixtures/lease-release-review/synthetic-lease-release-expired-lease-review.json",
        ))?;
        let stale_lease_release_request = read_model(
            repo_root.join("fixtures/damaged/lease-release-request-stale-revision.json"),
        )?;
        let stale_lease_release_review = read_model(repo_root.join(
            "fixtures/lease-release-review/synthetic-lease-release-stale-revision-review.json",
        ))?;
        let unknown_lease_release_request = read_model(
            repo_root.join("fixtures/damaged/lease-release-request-unknown-lease.json"),
        )?;
        let unknown_lease_release_review = read_model(repo_root.join(
            "fixtures/lease-release-review/synthetic-lease-release-unknown-lease-review.json",
        ))?;
        let holder_mismatch_lease_release_request = read_model(
            repo_root.join("fixtures/damaged/lease-release-request-holder-mismatch.json"),
        )?;
        let holder_mismatch_lease_release_review = read_model(repo_root.join(
            "fixtures/lease-release-review/synthetic-lease-release-holder-mismatch-review.json",
        ))?;
        let scope_mismatch_lease_release_request = read_model(
            repo_root.join("fixtures/damaged/lease-release-request-scope-mismatch.json"),
        )?;
        let scope_mismatch_lease_release_review = read_model(repo_root.join(
            "fixtures/lease-release-review/synthetic-lease-release-scope-mismatch-review.json",
        ))?;
        let accepted_lease_release_application: Box<
            ManifoldControlLeaseReleaseAuthorityApplication,
        > = read_model(repo_root.join(
            "fixtures/authority-application/synthetic-lease-release-accepted-application.json",
        ))?;
        let rejected_lease_release_application: Box<
            ManifoldControlLeaseReleaseAuthorityApplication,
        > = read_model(repo_root.join(
            "fixtures/authority-application/synthetic-lease-release-rejected-application.json",
        ))?;
        let lease_release_application_rejection = read_model(repo_root.join(
            "fixtures/authority-application/synthetic-lease-release-application-rejection.json",
        ))?;
        let lease_renewal_request =
            read_model(repo_root.join("fixtures/command/synthetic-lease-renewal-request.json"))?;
        let lease_renewal_rejection =
            read_model(repo_root.join("fixtures/command/synthetic-lease-renewal-rejection.json"))?;
        let lease_renewal_authority_audit_event = read_model(
            repo_root.join("fixtures/audit/synthetic-lease-renewal-accepted-event.json"),
        )?;
        let accepted_lease_renewal_review = read_model(
            repo_root
                .join("fixtures/lease-renewal-review/synthetic-lease-renewal-accepted-review.json"),
        )?;
        let stale_lease_renewal_request = read_model(
            repo_root.join("fixtures/damaged/lease-renewal-request-stale-revision.json"),
        )?;
        let stale_lease_renewal_review = read_model(repo_root.join(
            "fixtures/lease-renewal-review/synthetic-lease-renewal-stale-revision-review.json",
        ))?;
        let unknown_lease_renewal_request = read_model(
            repo_root.join("fixtures/damaged/lease-renewal-request-unknown-lease.json"),
        )?;
        let unknown_lease_renewal_review = read_model(repo_root.join(
            "fixtures/lease-renewal-review/synthetic-lease-renewal-unknown-lease-review.json",
        ))?;
        let holder_mismatch_lease_renewal_request = read_model(
            repo_root.join("fixtures/damaged/lease-renewal-request-holder-mismatch.json"),
        )?;
        let holder_mismatch_lease_renewal_review = read_model(repo_root.join(
            "fixtures/lease-renewal-review/synthetic-lease-renewal-holder-mismatch-review.json",
        ))?;
        let scope_mismatch_lease_renewal_request = read_model(
            repo_root.join("fixtures/damaged/lease-renewal-request-scope-mismatch.json"),
        )?;
        let scope_mismatch_lease_renewal_review = read_model(repo_root.join(
            "fixtures/lease-renewal-review/synthetic-lease-renewal-scope-mismatch-review.json",
        ))?;
        let zero_ttl_lease_renewal_request =
            read_model(repo_root.join("fixtures/damaged/lease-renewal-request-zero-ttl.json"))?;
        let zero_ttl_lease_renewal_review = read_model(
            repo_root
                .join("fixtures/lease-renewal-review/synthetic-lease-renewal-zero-ttl-review.json"),
        )?;
        let non_extending_lease_renewal_request = read_model(
            repo_root.join("fixtures/damaged/lease-renewal-request-non-extending.json"),
        )?;
        let non_extending_lease_renewal_review = read_model(repo_root.join(
            "fixtures/lease-renewal-review/synthetic-lease-renewal-non-extending-review.json",
        ))?;
        let expired_lease_renewal_review = read_model(repo_root.join(
            "fixtures/lease-renewal-review/synthetic-lease-renewal-expired-lease-review.json",
        ))?;
        let accepted_lease_renewal_application: Box<
            ManifoldControlLeaseRenewalAuthorityApplication,
        > = read_model(repo_root.join(
            "fixtures/authority-application/synthetic-lease-renewal-accepted-application.json",
        ))?;
        let rejected_lease_renewal_application: Box<
            ManifoldControlLeaseRenewalAuthorityApplication,
        > = read_model(repo_root.join(
            "fixtures/authority-application/synthetic-lease-renewal-rejected-application.json",
        ))?;
        let lease_renewal_application_rejection = read_model(repo_root.join(
            "fixtures/authority-application/synthetic-lease-renewal-application-rejection.json",
        ))?;
        let stream_registry_lease =
            read_model(repo_root.join("fixtures/command/synthetic-stream-registry-lease.json"))?;
        let stream_registry_change_request = read_model(
            repo_root.join("fixtures/stream/synthetic-stream-registry-change-request.json"),
        )?;
        let stream_registry_rejection =
            read_model(repo_root.join("fixtures/stream/synthetic-stream-registry-rejection.json"))?;
        let stream_registry_authority_audit_event = read_model(
            repo_root.join("fixtures/audit/synthetic-stream-registry-accepted-event.json"),
        )?;
        let accepted_stream_registry_review = read_model(repo_root.join(
            "fixtures/stream-registry-review/synthetic-stream-registry-accepted-review.json",
        ))?;
        let expired_lease_stream_registry_review = read_model(repo_root.join(
            "fixtures/stream-registry-review/synthetic-stream-registry-expired-lease-review.json",
        ))?;
        let stale_stream_registry_request = read_model(
            repo_root.join("fixtures/damaged/stream-registry-request-stale-revision.json"),
        )?;
        let stale_stream_registry_review = read_model(repo_root.join(
            "fixtures/stream-registry-review/synthetic-stream-registry-stale-revision-review.json",
        ))?;
        let missing_lease_stream_registry_request = read_model(
            repo_root.join("fixtures/damaged/stream-registry-request-missing-lease.json"),
        )?;
        let missing_lease_stream_registry_review = read_model(repo_root.join(
            "fixtures/stream-registry-review/synthetic-stream-registry-missing-lease-review.json",
        ))?;
        let active_stream_registry_request = read_model(
            repo_root.join("fixtures/damaged/stream-registry-request-remove-active-stream.json"),
        )?;
        let active_stream_registry_review = read_model(repo_root.join(
            "fixtures/stream-registry-review/synthetic-stream-registry-active-stream-review.json",
        ))?;
        let remove_active_transport_stream_registry_request = read_model(
            repo_root.join("fixtures/damaged/stream-registry-request-remove-active-transport.json"),
        )?;
        let remove_active_transport_stream_registry_review = read_model(repo_root.join(
            "fixtures/stream-registry-review/synthetic-stream-registry-remove-active-transport-review.json",
        ))?;
        let disable_active_ui_stream_registry_request = read_model(repo_root.join(
            "fixtures/damaged/stream-registry-request-disable-active-ui-subscriptions.json",
        ))?;
        let disable_active_ui_stream_registry_review = read_model(repo_root.join(
            "fixtures/stream-registry-review/synthetic-stream-registry-disable-active-ui-subscriptions-review.json",
        ))?;
        let lower_active_subscriber_limit_stream_registry_request =
            read_model(repo_root.join(
                "fixtures/damaged/stream-registry-request-lower-active-subscriber-limit.json",
            ))?;
        let lower_active_subscriber_limit_stream_registry_review = read_model(repo_root.join(
            "fixtures/stream-registry-review/synthetic-stream-registry-lower-active-subscriber-limit-review.json",
        ))?;
        let unknown_module_stream_registry_request = read_model(
            repo_root.join("fixtures/damaged/stream-registry-request-unknown-module.json"),
        )?;
        let unknown_module_stream_registry_review = read_model(repo_root.join(
            "fixtures/stream-registry-review/synthetic-stream-registry-unknown-module-review.json",
        ))?;
        let unknown_endpoint_stream_registry_request = read_model(
            repo_root.join("fixtures/damaged/stream-registry-request-unknown-endpoint.json"),
        )?;
        let unknown_endpoint_stream_registry_review = read_model(
            repo_root.join(
                "fixtures/stream-registry-review/synthetic-stream-registry-unknown-endpoint-review.json",
            ),
        )?;
        let accepted_stream_registry_application: Box<ManifoldStreamRegistryAuthorityApplication> = read_model(repo_root.join(
            "fixtures/authority-application/synthetic-stream-registry-accepted-application.json",
        ))?;
        let rejected_stream_registry_application: Box<ManifoldStreamRegistryAuthorityApplication> = read_model(repo_root.join(
            "fixtures/authority-application/synthetic-stream-registry-rejected-application.json",
        ))?;
        let stream_registry_application_rejection = read_model(repo_root.join(
            "fixtures/authority-application/synthetic-stream-registry-application-rejection.json",
        ))?;
        let stream_subscription_authority_snapshot = read_model(
            repo_root
                .join("fixtures/authority/synthetic-stream-subscription-authority-snapshot.json"),
        )?;
        let stream_subscription_request = read_model(
            repo_root
                .join("fixtures/stream-subscription/synthetic-stream-subscription-request.json"),
        )?;
        let stream_subscription = read_model(
            repo_root.join("fixtures/stream-subscription/synthetic-stream-subscription.json"),
        )?;
        let stream_subscription_rejection = read_model(
            repo_root
                .join("fixtures/stream-subscription/synthetic-stream-subscription-rejection.json"),
        )?;
        let stream_subscription_authority_audit_event = read_model(
            repo_root.join("fixtures/audit/synthetic-stream-subscription-accepted-event.json"),
        )?;
        let accepted_stream_subscription_review = read_model(repo_root.join(
            "fixtures/stream-subscription-review/synthetic-stream-subscription-accepted-review.json",
        ))?;
        let zero_ttl_stream_subscription_request = read_model(
            repo_root.join("fixtures/damaged/stream-subscription-request-zero-ttl.json"),
        )?;
        let zero_ttl_stream_subscription_review = read_model(repo_root.join(
            "fixtures/stream-subscription-review/synthetic-stream-subscription-zero-ttl-review.json",
        ))?;
        let missing_capability_stream_subscription_request = read_model(
            repo_root.join("fixtures/damaged/stream-subscription-request-missing-capability.json"),
        )?;
        let missing_capability_stream_subscription_review = read_model(repo_root.join(
            "fixtures/stream-subscription-review/synthetic-stream-subscription-missing-capability-review.json",
        ))?;
        let stale_stream_subscription_request = read_model(
            repo_root.join("fixtures/damaged/stream-subscription-request-stale-revision.json"),
        )?;
        let stale_stream_subscription_review = read_model(repo_root.join(
            "fixtures/stream-subscription-review/synthetic-stream-subscription-stale-revision-review.json",
        ))?;
        let stale_registry_stream_subscription_request = read_model(
            repo_root.join("fixtures/damaged/stream-subscription-request-stale-registry.json"),
        )?;
        let stale_registry_stream_subscription_review = read_model(repo_root.join(
            "fixtures/stream-subscription-review/synthetic-stream-subscription-stale-registry-review.json",
        ))?;
        let unknown_stream_subscription_request = read_model(
            repo_root.join("fixtures/damaged/stream-subscription-request-unknown-stream.json"),
        )?;
        let unknown_stream_subscription_review = read_model(repo_root.join(
            "fixtures/stream-subscription-review/synthetic-stream-subscription-unknown-stream-review.json",
        ))?;
        let unknown_transport_stream_subscription_request = read_model(
            repo_root.join("fixtures/damaged/stream-subscription-request-unknown-transport.json"),
        )?;
        let unknown_transport_stream_subscription_review = read_model(repo_root.join(
            "fixtures/stream-subscription-review/synthetic-stream-subscription-unknown-transport-review.json",
        ))?;
        let subscriber_limit_stream_subscription_authority_snapshot = read_model(repo_root.join(
            "fixtures/authority/synthetic-stream-subscription-limit-authority-snapshot.json",
        ))?;
        let subscriber_limit_stream_subscription_request = read_model(
            repo_root.join("fixtures/damaged/stream-subscription-request-subscriber-limit.json"),
        )?;
        let subscriber_limit_stream_subscription_review = read_model(repo_root.join(
            "fixtures/stream-subscription-review/synthetic-stream-subscription-subscriber-limit-review.json",
        ))?;
        let ui_disabled_stream_subscription_authority_snapshot = read_model(repo_root.join(
            "fixtures/authority/synthetic-stream-subscription-ui-disabled-authority-snapshot.json",
        ))?;
        let ui_disabled_stream_subscription_request = read_model(
            repo_root.join("fixtures/damaged/stream-subscription-request-ui-disabled.json"),
        )?;
        let ui_disabled_stream_subscription_review = read_model(repo_root.join(
            "fixtures/stream-subscription-review/synthetic-stream-subscription-ui-disabled-review.json",
        ))?;
        let accepted_stream_subscription_application: Box<
            ManifoldStreamSubscriptionAuthorityApplication,
        > = read_model(repo_root.join(
            "fixtures/authority-application/synthetic-stream-subscription-accepted-application.json",
        ))?;
        let rejected_stream_subscription_application: Box<
            ManifoldStreamSubscriptionAuthorityApplication,
        > = read_model(repo_root.join(
            "fixtures/authority-application/synthetic-stream-subscription-rejected-application.json",
        ))?;
        let stream_subscription_application_rejection = read_model(repo_root.join(
            "fixtures/authority-application/synthetic-stream-subscription-application-rejection.json",
        ))?;
        let stream_subscription_active_authority_snapshot = read_model(repo_root.join(
            "fixtures/authority/synthetic-stream-subscription-active-authority-snapshot.json",
        ))?;
        let stream_subscription_release_request = read_model(repo_root.join(
            "fixtures/stream-subscription/synthetic-stream-subscription-release-request.json",
        ))?;
        let stream_subscription_release_rejection = read_model(repo_root.join(
            "fixtures/stream-subscription/synthetic-stream-subscription-release-rejection.json",
        ))?;
        let stream_subscription_release_authority_audit_event = read_model(
            repo_root
                .join("fixtures/audit/synthetic-stream-subscription-release-accepted-event.json"),
        )?;
        let accepted_stream_subscription_release_review = read_model(repo_root.join(
            "fixtures/stream-subscription-release-review/synthetic-stream-subscription-release-accepted-review.json",
        ))?;
        let expired_stream_subscription_release_review = read_model(repo_root.join(
            "fixtures/stream-subscription-release-review/synthetic-stream-subscription-release-expired-subscription-review.json",
        ))?;
        let stale_stream_subscription_release_request = read_model(
            repo_root
                .join("fixtures/damaged/stream-subscription-release-request-stale-revision.json"),
        )?;
        let stale_stream_subscription_release_review = read_model(repo_root.join(
            "fixtures/stream-subscription-release-review/synthetic-stream-subscription-release-stale-revision-review.json",
        ))?;
        let stale_registry_stream_subscription_release_request = read_model(
            repo_root
                .join("fixtures/damaged/stream-subscription-release-request-stale-registry.json"),
        )?;
        let stale_registry_stream_subscription_release_review = read_model(repo_root.join(
            "fixtures/stream-subscription-release-review/synthetic-stream-subscription-release-stale-registry-review.json",
        ))?;
        let unknown_stream_subscription_release_request = read_model(repo_root.join(
            "fixtures/damaged/stream-subscription-release-request-unknown-subscription.json",
        ))?;
        let unknown_stream_subscription_release_review = read_model(repo_root.join(
            "fixtures/stream-subscription-release-review/synthetic-stream-subscription-release-unknown-subscription-review.json",
        ))?;
        let subscriber_mismatch_stream_subscription_release_request = read_model(repo_root.join(
            "fixtures/damaged/stream-subscription-release-request-subscriber-mismatch.json",
        ))?;
        let subscriber_mismatch_stream_subscription_release_review = read_model(repo_root.join(
            "fixtures/stream-subscription-release-review/synthetic-stream-subscription-release-subscriber-mismatch-review.json",
        ))?;
        let stream_mismatch_stream_subscription_release_request = read_model(
            repo_root
                .join("fixtures/damaged/stream-subscription-release-request-stream-mismatch.json"),
        )?;
        let stream_mismatch_stream_subscription_release_review = read_model(repo_root.join(
            "fixtures/stream-subscription-release-review/synthetic-stream-subscription-release-stream-mismatch-review.json",
        ))?;
        let accepted_stream_subscription_release_application: Box<
            ManifoldStreamSubscriptionReleaseAuthorityApplication,
        > = read_model(repo_root.join(
            "fixtures/authority-application/synthetic-stream-subscription-release-accepted-application.json",
        ))?;
        let rejected_stream_subscription_release_application: Box<
            ManifoldStreamSubscriptionReleaseAuthorityApplication,
        > = read_model(repo_root.join(
            "fixtures/authority-application/synthetic-stream-subscription-release-rejected-application.json",
        ))?;
        let stream_subscription_release_application_rejection = read_model(repo_root.join(
            "fixtures/authority-application/synthetic-stream-subscription-release-application-rejection.json",
        ))?;
        let stream_subscription_renewal_request = read_model(repo_root.join(
            "fixtures/stream-subscription/synthetic-stream-subscription-renewal-request.json",
        ))?;
        let stream_subscription_renewal_rejection = read_model(repo_root.join(
            "fixtures/stream-subscription/synthetic-stream-subscription-renewal-rejection.json",
        ))?;
        let stream_subscription_renewal_authority_audit_event = read_model(
            repo_root
                .join("fixtures/audit/synthetic-stream-subscription-renewal-accepted-event.json"),
        )?;
        let accepted_stream_subscription_renewal_review = read_model(repo_root.join(
            "fixtures/stream-subscription-renewal-review/synthetic-stream-subscription-renewal-accepted-review.json",
        ))?;
        let stale_stream_subscription_renewal_request = read_model(
            repo_root
                .join("fixtures/damaged/stream-subscription-renewal-request-stale-revision.json"),
        )?;
        let stale_stream_subscription_renewal_review = read_model(repo_root.join(
            "fixtures/stream-subscription-renewal-review/synthetic-stream-subscription-renewal-stale-revision-review.json",
        ))?;
        let stale_registry_stream_subscription_renewal_request = read_model(
            repo_root
                .join("fixtures/damaged/stream-subscription-renewal-request-stale-registry.json"),
        )?;
        let stale_registry_stream_subscription_renewal_review = read_model(repo_root.join(
            "fixtures/stream-subscription-renewal-review/synthetic-stream-subscription-renewal-stale-registry-review.json",
        ))?;
        let unknown_stream_subscription_renewal_request = read_model(repo_root.join(
            "fixtures/damaged/stream-subscription-renewal-request-unknown-subscription.json",
        ))?;
        let unknown_stream_subscription_renewal_review = read_model(repo_root.join(
            "fixtures/stream-subscription-renewal-review/synthetic-stream-subscription-renewal-unknown-subscription-review.json",
        ))?;
        let subscriber_mismatch_stream_subscription_renewal_request = read_model(repo_root.join(
            "fixtures/damaged/stream-subscription-renewal-request-subscriber-mismatch.json",
        ))?;
        let subscriber_mismatch_stream_subscription_renewal_review = read_model(repo_root.join(
            "fixtures/stream-subscription-renewal-review/synthetic-stream-subscription-renewal-subscriber-mismatch-review.json",
        ))?;
        let stream_mismatch_stream_subscription_renewal_request = read_model(
            repo_root
                .join("fixtures/damaged/stream-subscription-renewal-request-stream-mismatch.json"),
        )?;
        let stream_mismatch_stream_subscription_renewal_review = read_model(repo_root.join(
            "fixtures/stream-subscription-renewal-review/synthetic-stream-subscription-renewal-stream-mismatch-review.json",
        ))?;
        let transport_mismatch_stream_subscription_renewal_request =
            read_model(repo_root.join(
                "fixtures/damaged/stream-subscription-renewal-request-transport-mismatch.json",
            ))?;
        let transport_mismatch_stream_subscription_renewal_review = read_model(repo_root.join(
            "fixtures/stream-subscription-renewal-review/synthetic-stream-subscription-renewal-transport-mismatch-review.json",
        ))?;
        let zero_ttl_stream_subscription_renewal_request = read_model(
            repo_root.join("fixtures/damaged/stream-subscription-renewal-request-zero-ttl.json"),
        )?;
        let zero_ttl_stream_subscription_renewal_review = read_model(repo_root.join(
            "fixtures/stream-subscription-renewal-review/synthetic-stream-subscription-renewal-zero-ttl-review.json",
        ))?;
        let non_extending_stream_subscription_renewal_request = read_model(
            repo_root
                .join("fixtures/damaged/stream-subscription-renewal-request-non-extending.json"),
        )?;
        let non_extending_stream_subscription_renewal_review = read_model(repo_root.join(
            "fixtures/stream-subscription-renewal-review/synthetic-stream-subscription-renewal-non-extending-review.json",
        ))?;
        let expired_stream_subscription_renewal_review = read_model(repo_root.join(
            "fixtures/stream-subscription-renewal-review/synthetic-stream-subscription-renewal-expired-subscription-review.json",
        ))?;
        let accepted_stream_subscription_renewal_application: Box<
            ManifoldStreamSubscriptionRenewalAuthorityApplication,
        > = read_model(repo_root.join(
            "fixtures/authority-application/synthetic-stream-subscription-renewal-accepted-application.json",
        ))?;
        let rejected_stream_subscription_renewal_application: Box<
            ManifoldStreamSubscriptionRenewalAuthorityApplication,
        > = read_model(repo_root.join(
            "fixtures/authority-application/synthetic-stream-subscription-renewal-rejected-application.json",
        ))?;
        let stream_subscription_renewal_application_rejection = read_model(repo_root.join(
            "fixtures/authority-application/synthetic-stream-subscription-renewal-application-rejection.json",
        ))?;
        let authority_expiry_sweep_request = read_model(
            repo_root
                .join("fixtures/authority-expiry/synthetic-authority-expiry-sweep-request.json"),
        )?;
        let authority_expiry_sweep_rejection = read_model(
            repo_root
                .join("fixtures/authority-expiry/synthetic-authority-expiry-sweep-rejection.json"),
        )?;
        let authority_expiry_sweep_authority_audit_event = read_model(
            repo_root.join("fixtures/audit/synthetic-authority-expiry-sweep-accepted-event.json"),
        )?;
        let accepted_authority_expiry_sweep_review = read_model(
            repo_root.join("fixtures/authority-expiry-review/synthetic-authority-expiry-sweep-accepted-review.json"),
        )?;
        let stale_authority_expiry_sweep_request = read_model(
            repo_root.join("fixtures/damaged/authority-expiry-sweep-request-stale-revision.json"),
        )?;
        let stale_authority_expiry_sweep_review = read_model(
            repo_root.join("fixtures/authority-expiry-review/synthetic-authority-expiry-sweep-stale-revision-review.json"),
        )?;
        let registry_mismatch_authority_expiry_sweep_request = read_model(
            repo_root
                .join("fixtures/damaged/authority-expiry-sweep-request-registry-mismatch.json"),
        )?;
        let registry_mismatch_authority_expiry_sweep_review = read_model(
            repo_root.join("fixtures/authority-expiry-review/synthetic-authority-expiry-sweep-registry-mismatch-review.json"),
        )?;
        let no_expired_authority_expiry_sweep_review = read_model(
            repo_root.join("fixtures/authority-expiry-review/synthetic-authority-expiry-sweep-no-expired-review.json"),
        )?;
        let accepted_authority_expiry_sweep_application: Box<
            ManifoldAuthorityExpirySweepAuthorityApplication,
        > = read_model(repo_root.join(
            "fixtures/authority-application/synthetic-authority-expiry-sweep-accepted-application.json",
        ))?;
        let rejected_authority_expiry_sweep_application: Box<
            ManifoldAuthorityExpirySweepAuthorityApplication,
        > = read_model(repo_root.join(
            "fixtures/authority-application/synthetic-authority-expiry-sweep-rejected-application.json",
        ))?;
        let authority_expiry_sweep_application_rejection = read_model(repo_root.join(
            "fixtures/authority-application/synthetic-authority-expiry-sweep-application-rejection.json",
        ))?;
        let module_runtime_state_change_request = read_model(
            repo_root.join("fixtures/module/synthetic-runtime-state-change-request.json"),
        )?;
        let module_runtime_state_rejection =
            read_model(repo_root.join("fixtures/module/synthetic-runtime-state-rejection.json"))?;
        let module_runtime_state_authority_audit_event = read_model(
            repo_root.join("fixtures/audit/synthetic-module-runtime-state-accepted-event.json"),
        )?;
        let accepted_module_runtime_review =
            read_model(repo_root.join(
                "fixtures/module-runtime-review/synthetic-module-runtime-accepted-review.json",
            ))?;
        let expired_lease_module_runtime_review = read_model(repo_root.join(
            "fixtures/module-runtime-review/synthetic-module-runtime-expired-lease-review.json",
        ))?;
        let stale_module_runtime_request = read_model(
            repo_root.join("fixtures/damaged/module-runtime-request-stale-revision.json"),
        )?;
        let stale_module_runtime_review = read_model(repo_root.join(
            "fixtures/module-runtime-review/synthetic-module-runtime-stale-revision-review.json",
        ))?;
        let missing_lease_module_runtime_request = read_model(
            repo_root.join("fixtures/damaged/module-runtime-request-missing-lease.json"),
        )?;
        let missing_lease_module_runtime_review = read_model(repo_root.join(
            "fixtures/module-runtime-review/synthetic-module-runtime-missing-lease-review.json",
        ))?;
        let unknown_stream_module_runtime_request = read_model(
            repo_root.join("fixtures/damaged/module-runtime-request-unknown-stream.json"),
        )?;
        let unknown_stream_module_runtime_review = read_model(repo_root.join(
            "fixtures/module-runtime-review/synthetic-module-runtime-unknown-stream-review.json",
        ))?;
        let missing_backend_module_runtime_request = read_model(
            repo_root.join("fixtures/damaged/module-runtime-request-missing-backend.json"),
        )?;
        let missing_backend_module_runtime_review = read_model(repo_root.join(
            "fixtures/module-runtime-review/synthetic-module-runtime-missing-backend-review.json",
        ))?;
        let accepted_module_runtime_application: Box<
            ManifoldModuleRuntimeStateAuthorityApplication,
        > = read_model(repo_root.join(
            "fixtures/authority-application/synthetic-module-runtime-accepted-application.json",
        ))?;
        let rejected_module_runtime_application: Box<
            ManifoldModuleRuntimeStateAuthorityApplication,
        > = read_model(repo_root.join(
            "fixtures/authority-application/synthetic-module-runtime-rejected-application.json",
        ))?;
        let module_runtime_application_rejection = read_model(repo_root.join(
            "fixtures/authority-application/synthetic-module-runtime-application-rejection.json",
        ))?;
        let host_manifest_lease =
            read_model(repo_root.join("fixtures/command/synthetic-host-manifest-lease.json"))?;
        let host_manifest_change_request = read_model(
            repo_root.join("fixtures/host/synthetic-host-manifest-change-request.json"),
        )?;
        let host_manifest_rejection =
            read_model(repo_root.join("fixtures/host/synthetic-host-manifest-rejection.json"))?;
        let host_manifest_authority_audit_event = read_model(
            repo_root.join("fixtures/audit/synthetic-host-manifest-accepted-event.json"),
        )?;
        let accepted_host_manifest_review = read_model(
            repo_root
                .join("fixtures/host-manifest-review/synthetic-host-manifest-accepted-review.json"),
        )?;
        let expired_lease_host_manifest_review = read_model(repo_root.join(
            "fixtures/host-manifest-review/synthetic-host-manifest-expired-lease-review.json",
        ))?;
        let stale_host_manifest_request = read_model(
            repo_root.join("fixtures/damaged/host-manifest-request-stale-revision.json"),
        )?;
        let stale_host_manifest_review = read_model(repo_root.join(
            "fixtures/host-manifest-review/synthetic-host-manifest-stale-revision-review.json",
        ))?;
        let missing_authority_role_host_manifest_request = read_model(
            repo_root.join("fixtures/damaged/host-manifest-request-missing-authority-role.json"),
        )?;
        let missing_authority_role_host_manifest_review = read_model(repo_root.join(
            "fixtures/host-manifest-review/synthetic-host-manifest-missing-authority-role-review.json",
        ))?;
        let endpoint_mismatch_host_manifest_request = read_model(
            repo_root.join("fixtures/damaged/host-manifest-request-endpoint-mismatch.json"),
        )?;
        let endpoint_mismatch_host_manifest_review = read_model(repo_root.join(
            "fixtures/host-manifest-review/synthetic-host-manifest-endpoint-mismatch-review.json",
        ))?;
        let remove_capability_host_manifest_request = read_model(
            repo_root.join("fixtures/damaged/host-manifest-request-remove-capability.json"),
        )?;
        let remove_capability_host_manifest_review = read_model(repo_root.join(
            "fixtures/host-manifest-review/synthetic-host-manifest-remove-capability-review.json",
        ))?;
        let remove_backend_host_manifest_request = read_model(
            repo_root.join("fixtures/damaged/host-manifest-request-remove-backend.json"),
        )?;
        let remove_backend_host_manifest_review = read_model(repo_root.join(
            "fixtures/host-manifest-review/synthetic-host-manifest-remove-backend-review.json",
        ))?;
        let accepted_host_manifest_application: Box<ManifoldHostManifestAuthorityApplication> =
            read_model(repo_root.join(
                "fixtures/authority-application/synthetic-host-manifest-accepted-application.json",
            ))?;
        let rejected_host_manifest_application: Box<ManifoldHostManifestAuthorityApplication> =
            read_model(repo_root.join(
                "fixtures/authority-application/synthetic-host-manifest-rejected-application.json",
            ))?;
        let host_manifest_application_rejection = read_model(repo_root.join(
            "fixtures/authority-application/synthetic-host-manifest-application-rejection.json",
        ))?;
        let clock_lease =
            read_model(repo_root.join("fixtures/command/synthetic-clock-lease.json"))?;
        let clock_change_request =
            read_model(repo_root.join("fixtures/clock/synthetic-clock-change-request.json"))?;
        let clock_rejection =
            read_model(repo_root.join("fixtures/clock/synthetic-clock-rejection.json"))?;
        let clock_authority_audit_event =
            read_model(repo_root.join("fixtures/audit/synthetic-clock-accepted-event.json"))?;
        let accepted_clock_review = read_model(
            repo_root.join("fixtures/clock-review/synthetic-clock-accepted-review.json"),
        )?;
        let expired_lease_clock_review = read_model(
            repo_root.join("fixtures/clock-review/synthetic-clock-expired-lease-review.json"),
        )?;
        let stale_clock_request =
            read_model(repo_root.join("fixtures/damaged/clock-request-stale-revision.json"))?;
        let stale_clock_review = read_model(
            repo_root.join("fixtures/clock-review/synthetic-clock-stale-revision-review.json"),
        )?;
        let missing_lease_clock_request =
            read_model(repo_root.join("fixtures/damaged/clock-request-missing-lease.json"))?;
        let missing_lease_clock_review = read_model(
            repo_root.join("fixtures/clock-review/synthetic-clock-missing-lease-review.json"),
        )?;
        let domain_mismatch_clock_request =
            read_model(repo_root.join("fixtures/damaged/clock-request-domain-mismatch.json"))?;
        let domain_mismatch_clock_review = read_model(
            repo_root.join("fixtures/clock-review/synthetic-clock-domain-mismatch-review.json"),
        )?;
        let sequence_gap_clock_request =
            read_model(repo_root.join("fixtures/damaged/clock-request-sequence-gap.json"))?;
        let sequence_gap_clock_review = read_model(
            repo_root.join("fixtures/clock-review/synthetic-clock-sequence-gap-review.json"),
        )?;
        let monotonic_regression_clock_request =
            read_model(repo_root.join("fixtures/damaged/clock-request-monotonic-regression.json"))?;
        let monotonic_regression_clock_review = read_model(
            repo_root
                .join("fixtures/clock-review/synthetic-clock-monotonic-regression-review.json"),
        )?;
        let accepted_clock_application: Box<ManifoldClockSnapshotAuthorityApplication> =
            read_model(
                repo_root.join(
                    "fixtures/authority-application/synthetic-clock-accepted-application.json",
                ),
            )?;
        let rejected_clock_application: Box<ManifoldClockSnapshotAuthorityApplication> =
            read_model(
                repo_root.join(
                    "fixtures/authority-application/synthetic-clock-rejected-application.json",
                ),
            )?;
        let clock_application_rejection = read_model(
            repo_root
                .join("fixtures/authority-application/synthetic-clock-application-rejection.json"),
        )?;
        let valid_host = read_model(repo_root.join("fixtures/host/synthetic-host.json"))?;
        let desktop_host = read_model(repo_root.join("fixtures/host/desktop-local.json"))?;
        let mobile_host = read_model(repo_root.join("fixtures/host/mobile-device.json"))?;
        let headset_host = read_model(repo_root.join("fixtures/host/headset-device.json"))?;
        let deployment_manifest =
            read_model(repo_root.join("fixtures/deployment/synthetic-deployment.json"))?;
        let deployment_selection =
            read_model(repo_root.join("fixtures/deployment/synthetic-selection.json"))?;
        read_model::<ManifoldClockSnapshot>(
            repo_root.join("fixtures/clock/synthetic-clock-snapshot.json"),
        )?;
        read_model::<ManifoldValidationScorecard>(
            repo_root.join("fixtures/validation/synthetic-scorecard.json"),
        )?;
        let host_run_desktop_profile =
            read_model(repo_root.join("fixtures/host-run/install-profile-desktop.json"))?;
        let host_run_mobile_profile =
            read_model(repo_root.join("fixtures/host-run/install-profile-mobile.json"))?;
        let host_run_headset_profile =
            read_model(repo_root.join("fixtures/host-run/install-profile-headset.json"))?;
        let host_run_slot = read_model(repo_root.join("fixtures/host-run/slot-live-smoke.json"))?;
        let host_run_bundle =
            read_model(repo_root.join("fixtures/host-run/run-bundle-live-smoke.json"))?;
        let host_run_command =
            read_model(repo_root.join("fixtures/host-run/command-envelope-run-live.json"))?;
        let host_run_evidence =
            read_model(repo_root.join("fixtures/host-run/run-evidence-live-smoke.json"))?;
        let shell_handoff =
            read_model(repo_root.join("fixtures/shell-handoff/synthetic-loopback-shell.json"))?;
        let shell_handoff_review = read_model(
            repo_root.join("fixtures/shell-handoff/synthetic-loopback-shell-review.json"),
        )?;

        let damaged_endpoint_host =
            read_model(repo_root.join("fixtures/damaged/invalid-endpoint-security.json"))?;
        let damaged_stale_command =
            read_model(repo_root.join("fixtures/damaged/stale-revision-command.json"))?;
        let damaged_missing_lease_command =
            read_model(repo_root.join("fixtures/damaged/missing-lease-scope-command.json"))?;
        let damaged_command_authority_audit_event =
            read_model(repo_root.join("fixtures/damaged/authority-audit-unknown-command.json"))?;
        let damaged_unknown_stream_module =
            read_model(repo_root.join("fixtures/damaged/unknown-module-link.json"))?;
        let damaged_unknown_graph_module =
            read_model(repo_root.join("fixtures/damaged/unknown-graph-module-link.json"))?;
        let damaged_unknown_graph_node =
            read_model(repo_root.join("fixtures/damaged/unknown-graph-node-link.json"))?;
        let damaged_unavailable_deployment =
            read_model(repo_root.join("fixtures/damaged/unavailable-deployment-backend.json"))?;
        let damaged_shell_handoff =
            read_model(repo_root.join("fixtures/damaged/shell-handoff-missing-stream.json"))?;
        let damaged_shell_handoff_review = read_model(
            repo_root.join("fixtures/damaged/shell-handoff-review-runtime-started.json"),
        )?;

        Ok(Self {
            package_manifest,
            valid_graph,
            module_manifests: vec![provider_manifest, processor_manifest],
            next_provider_runtime,
            valid_registry,
            stream_registry_diff,
            command_descriptor,
            valid_envelope,
            lease_request,
            control_lease,
            authority_snapshot,
            authority_snapshot_v2,
            command_review_clock,
            expired_command_review_clock,
            command_authority_audit_event,
            accepted_command_review,
            stale_revision_command_review,
            expired_lease_command_review,
            missing_lease_command_review,
            unknown_command_review_envelope,
            unknown_command_review,
            unknown_lease_review_envelope,
            unknown_lease_command_review,
            capability_mismatch_review_envelope,
            capability_mismatch_command_review,
            command_dispatch_rejection,
            accepted_command_dispatch,
            rejected_command_dispatch,
            remote_camera_authority_snapshot,
            remote_camera_command_reviews,
            remote_camera_command_dispatches,
            lease_rejection,
            lease_authority_audit_event,
            accepted_lease_review,
            stale_lease_request,
            stale_revision_lease_review,
            zero_ttl_lease_request,
            zero_ttl_lease_review,
            missing_capability_lease_request,
            missing_capability_lease_review,
            busy_scope_lease_request,
            busy_scope_lease_review,
            accepted_lease_application,
            rejected_lease_application,
            lease_application_rejection,
            lease_active_authority_snapshot,
            lease_release_request,
            lease_release_rejection,
            lease_release_authority_audit_event,
            accepted_lease_release_review,
            expired_lease_release_review,
            stale_lease_release_request,
            stale_lease_release_review,
            unknown_lease_release_request,
            unknown_lease_release_review,
            holder_mismatch_lease_release_request,
            holder_mismatch_lease_release_review,
            scope_mismatch_lease_release_request,
            scope_mismatch_lease_release_review,
            accepted_lease_release_application,
            rejected_lease_release_application,
            lease_release_application_rejection,
            lease_renewal_request,
            lease_renewal_rejection,
            lease_renewal_authority_audit_event,
            accepted_lease_renewal_review,
            stale_lease_renewal_request,
            stale_lease_renewal_review,
            unknown_lease_renewal_request,
            unknown_lease_renewal_review,
            holder_mismatch_lease_renewal_request,
            holder_mismatch_lease_renewal_review,
            scope_mismatch_lease_renewal_request,
            scope_mismatch_lease_renewal_review,
            zero_ttl_lease_renewal_request,
            zero_ttl_lease_renewal_review,
            non_extending_lease_renewal_request,
            non_extending_lease_renewal_review,
            expired_lease_renewal_review,
            accepted_lease_renewal_application,
            rejected_lease_renewal_application,
            lease_renewal_application_rejection,
            stream_registry_lease,
            stream_registry_change_request,
            stream_registry_rejection,
            stream_registry_authority_audit_event,
            accepted_stream_registry_review,
            expired_lease_stream_registry_review,
            stale_stream_registry_request,
            stale_stream_registry_review,
            missing_lease_stream_registry_request,
            missing_lease_stream_registry_review,
            active_stream_registry_request,
            active_stream_registry_review,
            remove_active_transport_stream_registry_request,
            remove_active_transport_stream_registry_review,
            disable_active_ui_stream_registry_request,
            disable_active_ui_stream_registry_review,
            lower_active_subscriber_limit_stream_registry_request,
            lower_active_subscriber_limit_stream_registry_review,
            unknown_module_stream_registry_request,
            unknown_module_stream_registry_review,
            unknown_endpoint_stream_registry_request,
            unknown_endpoint_stream_registry_review,
            accepted_stream_registry_application,
            rejected_stream_registry_application,
            stream_registry_application_rejection,
            stream_subscription_authority_snapshot,
            stream_subscription_request,
            stream_subscription,
            stream_subscription_rejection,
            stream_subscription_authority_audit_event,
            accepted_stream_subscription_review,
            zero_ttl_stream_subscription_request,
            zero_ttl_stream_subscription_review,
            missing_capability_stream_subscription_request,
            missing_capability_stream_subscription_review,
            stale_stream_subscription_request,
            stale_stream_subscription_review,
            stale_registry_stream_subscription_request,
            stale_registry_stream_subscription_review,
            unknown_stream_subscription_request,
            unknown_stream_subscription_review,
            unknown_transport_stream_subscription_request,
            unknown_transport_stream_subscription_review,
            subscriber_limit_stream_subscription_authority_snapshot,
            subscriber_limit_stream_subscription_request,
            subscriber_limit_stream_subscription_review,
            ui_disabled_stream_subscription_authority_snapshot,
            ui_disabled_stream_subscription_request,
            ui_disabled_stream_subscription_review,
            accepted_stream_subscription_application,
            rejected_stream_subscription_application,
            stream_subscription_application_rejection,
            stream_subscription_active_authority_snapshot,
            stream_subscription_release_request,
            stream_subscription_release_rejection,
            stream_subscription_release_authority_audit_event,
            accepted_stream_subscription_release_review,
            expired_stream_subscription_release_review,
            stale_stream_subscription_release_request,
            stale_stream_subscription_release_review,
            stale_registry_stream_subscription_release_request,
            stale_registry_stream_subscription_release_review,
            unknown_stream_subscription_release_request,
            unknown_stream_subscription_release_review,
            subscriber_mismatch_stream_subscription_release_request,
            subscriber_mismatch_stream_subscription_release_review,
            stream_mismatch_stream_subscription_release_request,
            stream_mismatch_stream_subscription_release_review,
            accepted_stream_subscription_release_application,
            rejected_stream_subscription_release_application,
            stream_subscription_release_application_rejection,
            stream_subscription_renewal_request,
            stream_subscription_renewal_rejection,
            stream_subscription_renewal_authority_audit_event,
            accepted_stream_subscription_renewal_review,
            stale_stream_subscription_renewal_request,
            stale_stream_subscription_renewal_review,
            stale_registry_stream_subscription_renewal_request,
            stale_registry_stream_subscription_renewal_review,
            unknown_stream_subscription_renewal_request,
            unknown_stream_subscription_renewal_review,
            subscriber_mismatch_stream_subscription_renewal_request,
            subscriber_mismatch_stream_subscription_renewal_review,
            stream_mismatch_stream_subscription_renewal_request,
            stream_mismatch_stream_subscription_renewal_review,
            transport_mismatch_stream_subscription_renewal_request,
            transport_mismatch_stream_subscription_renewal_review,
            zero_ttl_stream_subscription_renewal_request,
            zero_ttl_stream_subscription_renewal_review,
            non_extending_stream_subscription_renewal_request,
            non_extending_stream_subscription_renewal_review,
            expired_stream_subscription_renewal_review,
            accepted_stream_subscription_renewal_application,
            rejected_stream_subscription_renewal_application,
            stream_subscription_renewal_application_rejection,
            authority_expiry_sweep_request,
            authority_expiry_sweep_rejection,
            authority_expiry_sweep_authority_audit_event,
            accepted_authority_expiry_sweep_review,
            stale_authority_expiry_sweep_request,
            stale_authority_expiry_sweep_review,
            registry_mismatch_authority_expiry_sweep_request,
            registry_mismatch_authority_expiry_sweep_review,
            no_expired_authority_expiry_sweep_review,
            accepted_authority_expiry_sweep_application,
            rejected_authority_expiry_sweep_application,
            authority_expiry_sweep_application_rejection,
            module_runtime_state_change_request,
            module_runtime_state_rejection,
            module_runtime_state_authority_audit_event,
            accepted_module_runtime_review,
            expired_lease_module_runtime_review,
            stale_module_runtime_request,
            stale_module_runtime_review,
            missing_lease_module_runtime_request,
            missing_lease_module_runtime_review,
            unknown_stream_module_runtime_request,
            unknown_stream_module_runtime_review,
            missing_backend_module_runtime_request,
            missing_backend_module_runtime_review,
            accepted_module_runtime_application,
            rejected_module_runtime_application,
            module_runtime_application_rejection,
            host_manifest_lease,
            host_manifest_change_request,
            host_manifest_rejection,
            host_manifest_authority_audit_event,
            accepted_host_manifest_review,
            expired_lease_host_manifest_review,
            stale_host_manifest_request,
            stale_host_manifest_review,
            missing_authority_role_host_manifest_request,
            missing_authority_role_host_manifest_review,
            endpoint_mismatch_host_manifest_request,
            endpoint_mismatch_host_manifest_review,
            remove_capability_host_manifest_request,
            remove_capability_host_manifest_review,
            remove_backend_host_manifest_request,
            remove_backend_host_manifest_review,
            accepted_host_manifest_application,
            rejected_host_manifest_application,
            host_manifest_application_rejection,
            clock_lease,
            clock_change_request,
            clock_rejection,
            clock_authority_audit_event,
            accepted_clock_review,
            expired_lease_clock_review,
            stale_clock_request,
            stale_clock_review,
            missing_lease_clock_request,
            missing_lease_clock_review,
            domain_mismatch_clock_request,
            domain_mismatch_clock_review,
            sequence_gap_clock_request,
            sequence_gap_clock_review,
            monotonic_regression_clock_request,
            monotonic_regression_clock_review,
            accepted_clock_application,
            rejected_clock_application,
            clock_application_rejection,
            valid_host,
            deployment_manifest,
            deployment_selection,
            damaged_endpoint_host,
            damaged_stale_command,
            damaged_missing_lease_command,
            damaged_command_authority_audit_event,
            damaged_unknown_stream_module,
            damaged_unknown_graph_module,
            damaged_unknown_graph_node,
            damaged_unavailable_deployment,
            platform_hosts: vec![desktop_host, mobile_host, headset_host],
            host_run_profiles: vec![
                host_run_desktop_profile,
                host_run_mobile_profile,
                host_run_headset_profile,
            ],
            host_run_slot,
            host_run_bundle,
            host_run_command,
            host_run_evidence,
            shell_handoff,
            shell_handoff_review,
            damaged_shell_handoff,
            damaged_shell_handoff_review,
        })
    }

    pub(super) fn endpoint_ids(&self) -> Vec<DottedId> {
        std::iter::once(&self.valid_host)
            .chain(self.platform_hosts.iter())
            .flat_map(|host| {
                host.endpoints
                    .iter()
                    .map(|endpoint| endpoint.endpoint_id.clone())
            })
            .collect()
    }
}
