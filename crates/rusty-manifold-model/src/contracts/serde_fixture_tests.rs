use super::*;
use serde::de::DeserializeOwned;

fn fixture<T: DeserializeOwned>(json: &str) -> T {
    serde_json::from_str(json).unwrap()
}

#[test]
fn valid_fixtures_deserialize_into_contract_models() {
    fixture::<ManifoldPackageManifest>(include_str!(
        "../../../../fixtures/package/synthetic-package.json"
    ));
    fixture::<ManifoldGraphManifest>(include_str!(
        "../../../../fixtures/graph/synthetic-wave-pipeline.json"
    ));
    fixture::<ManifoldGraphExecutionReport>(include_str!(
        "../../../../fixtures/graph/synthetic-graph-execution-report.json"
    ));
    fixture::<ManifoldModuleManifest>(include_str!(
        "../../../../fixtures/module/synthetic-wave-provider.json"
    ));
    fixture::<ManifoldModuleManifest>(include_str!(
        "../../../../fixtures/module/synthetic-wave-processor.json"
    ));
    fixture::<ManifoldModuleRuntimeState>(include_str!(
        "../../../../fixtures/module/synthetic-wave-runtime-state.json"
    ));
    fixture::<ManifoldModuleRuntimeState>(include_str!(
        "../../../../fixtures/module/synthetic-processor-runtime-state.json"
    ));
    fixture::<ManifoldModuleRuntimeState>(include_str!(
        "../../../../fixtures/module/synthetic-wave-runtime-state-v2.json"
    ));
    fixture::<ManifoldModuleRuntimeTransition>(include_str!(
        "../../../../fixtures/module/synthetic-runtime-state-transition.json"
    ));
    fixture::<ManifoldModuleRuntimeStateChangeRequest>(include_str!(
        "../../../../fixtures/module/synthetic-runtime-state-change-request.json"
    ));
    fixture::<ManifoldModuleRuntimeStateChangeRequest>(include_str!(
        "../../../../fixtures/damaged/module-runtime-request-stale-revision.json"
    ));
    fixture::<ManifoldModuleRuntimeStateChangeRequest>(include_str!(
        "../../../../fixtures/damaged/module-runtime-request-missing-lease.json"
    ));
    fixture::<ManifoldModuleRuntimeStateChangeRequest>(include_str!(
        "../../../../fixtures/damaged/module-runtime-request-unknown-stream.json"
    ));
    fixture::<ManifoldModuleRuntimeStateChangeRequest>(include_str!(
        "../../../../fixtures/damaged/module-runtime-request-missing-backend.json"
    ));
    fixture::<ManifoldModuleRuntimeStateRejection>(include_str!(
        "../../../../fixtures/module/synthetic-runtime-state-rejection.json"
    ));
    fixture::<ManifoldStreamManifest>(include_str!(
        "../../../../fixtures/stream/synthetic-wave-stream.json"
    ));
    fixture::<ManifoldStreamManifest>(include_str!(
        "../../../../fixtures/stream/synthetic-rms-stream.json"
    ));
    fixture::<ManifoldStreamRegistrySnapshot>(include_str!(
        "../../../../fixtures/stream/synthetic-stream-registry.json"
    ));
    fixture::<ManifoldStreamRegistryDiff>(include_str!(
        "../../../../fixtures/stream/synthetic-stream-registry-diff.json"
    ));
    fixture::<ManifoldStreamRegistryChangeRequest>(include_str!(
        "../../../../fixtures/stream/synthetic-stream-registry-change-request.json"
    ));
    fixture::<ManifoldStreamRegistryChangeRequest>(include_str!(
        "../../../../fixtures/damaged/stream-registry-request-stale-revision.json"
    ));
    fixture::<ManifoldStreamRegistryChangeRequest>(include_str!(
        "../../../../fixtures/damaged/stream-registry-request-missing-lease.json"
    ));
    fixture::<ManifoldStreamRegistryChangeRequest>(include_str!(
        "../../../../fixtures/damaged/stream-registry-request-remove-active-stream.json"
    ));
    fixture::<ManifoldStreamRegistryChangeRequest>(include_str!(
        "../../../../fixtures/damaged/stream-registry-request-unknown-module.json"
    ));
    fixture::<ManifoldStreamRegistryChangeRequest>(include_str!(
        "../../../../fixtures/damaged/stream-registry-request-unknown-endpoint.json"
    ));
    fixture::<ManifoldStreamRegistryRejection>(include_str!(
        "../../../../fixtures/stream/synthetic-stream-registry-rejection.json"
    ));
    fixture::<ManifoldSyntheticScalarOscillatorProfile>(include_str!(
        "../../../../fixtures/synthetic/synthetic-scalar-oscillator-profile.json"
    ));
    fixture::<ManifoldStreamSubscriptionRequest>(include_str!(
        "../../../../fixtures/stream-subscription/synthetic-stream-subscription-request.json"
    ));
    fixture::<ManifoldStreamSubscriptionRequest>(include_str!(
        "../../../../fixtures/damaged/stream-subscription-request-zero-ttl.json"
    ));
    fixture::<ManifoldStreamSubscriptionRequest>(include_str!(
        "../../../../fixtures/damaged/stream-subscription-request-missing-capability.json"
    ));
    fixture::<ManifoldStreamSubscriptionRequest>(include_str!(
        "../../../../fixtures/damaged/stream-subscription-request-stale-revision.json"
    ));
    fixture::<ManifoldStreamSubscriptionRequest>(include_str!(
        "../../../../fixtures/damaged/stream-subscription-request-stale-registry.json"
    ));
    fixture::<ManifoldStreamSubscriptionRequest>(include_str!(
        "../../../../fixtures/damaged/stream-subscription-request-unknown-stream.json"
    ));
    fixture::<ManifoldStreamSubscriptionRequest>(include_str!(
        "../../../../fixtures/damaged/stream-subscription-request-unknown-transport.json"
    ));
    fixture::<ManifoldStreamSubscriptionRequest>(include_str!(
        "../../../../fixtures/damaged/stream-subscription-request-subscriber-limit.json"
    ));
    fixture::<ManifoldStreamSubscriptionRequest>(include_str!(
        "../../../../fixtures/damaged/stream-subscription-request-ui-disabled.json"
    ));
    fixture::<ManifoldStreamSubscription>(include_str!(
        "../../../../fixtures/stream-subscription/synthetic-stream-subscription.json"
    ));
    fixture::<ManifoldStreamSubscriptionRejection>(include_str!(
        "../../../../fixtures/stream-subscription/synthetic-stream-subscription-rejection.json"
    ));
    fixture::<ManifoldStreamSubscriptionRenewalRequest>(include_str!(
            "../../../../fixtures/stream-subscription/synthetic-stream-subscription-renewal-request.json"
        ));
    fixture::<ManifoldStreamSubscriptionRenewalRequest>(include_str!(
        "../../../../fixtures/damaged/stream-subscription-renewal-request-stale-revision.json"
    ));
    fixture::<ManifoldStreamSubscriptionRenewalRequest>(include_str!(
        "../../../../fixtures/damaged/stream-subscription-renewal-request-stale-registry.json"
    ));
    fixture::<ManifoldStreamSubscriptionRenewalRequest>(include_str!(
            "../../../../fixtures/damaged/stream-subscription-renewal-request-unknown-subscription.json"
        ));
    fixture::<ManifoldStreamSubscriptionRenewalRequest>(include_str!(
        "../../../../fixtures/damaged/stream-subscription-renewal-request-subscriber-mismatch.json"
    ));
    fixture::<ManifoldStreamSubscriptionRenewalRequest>(include_str!(
        "../../../../fixtures/damaged/stream-subscription-renewal-request-stream-mismatch.json"
    ));
    fixture::<ManifoldStreamSubscriptionRenewalRequest>(include_str!(
        "../../../../fixtures/damaged/stream-subscription-renewal-request-transport-mismatch.json"
    ));
    fixture::<ManifoldStreamSubscriptionRenewalRequest>(include_str!(
        "../../../../fixtures/damaged/stream-subscription-renewal-request-zero-ttl.json"
    ));
    fixture::<ManifoldStreamSubscriptionRenewalRequest>(include_str!(
        "../../../../fixtures/damaged/stream-subscription-renewal-request-non-extending.json"
    ));
    fixture::<ManifoldStreamSubscriptionRenewalRejection>(include_str!(
            "../../../../fixtures/stream-subscription/synthetic-stream-subscription-renewal-rejection.json"
        ));
    fixture::<ManifoldCommandDescriptor>(include_str!(
        "../../../../fixtures/command/synthetic-command-descriptor.json"
    ));
    fixture::<ManifoldCommandDescriptor>(include_str!(
        "../../../../fixtures/command/remote-camera-start-receiver-descriptor.json"
    ));
    fixture::<ManifoldCommandDescriptor>(include_str!(
        "../../../../fixtures/command/remote-camera-start-sender-descriptor.json"
    ));
    fixture::<ManifoldCommandDescriptor>(include_str!(
        "../../../../fixtures/command/remote-camera-get-status-descriptor.json"
    ));
    fixture::<ManifoldCommandDescriptor>(include_str!(
        "../../../../fixtures/command/remote-camera-stop-descriptor.json"
    ));
    fixture::<ManifoldCommandEnvelope>(include_str!(
        "../../../../fixtures/command/synthetic-command-envelope.json"
    ));
    fixture::<ManifoldCommandEnvelope>(include_str!(
        "../../../../fixtures/command/remote-camera-start-receiver-envelope.json"
    ));
    fixture::<ManifoldCommandEnvelope>(include_str!(
        "../../../../fixtures/command/remote-camera-start-sender-envelope.json"
    ));
    fixture::<ManifoldCommandEnvelope>(include_str!(
        "../../../../fixtures/command/remote-camera-get-status-envelope.json"
    ));
    fixture::<ManifoldCommandEnvelope>(include_str!(
        "../../../../fixtures/command/remote-camera-stop-envelope.json"
    ));
    fixture::<ManifoldClockSnapshot>(include_str!(
        "../../../../fixtures/clock/remote-camera-start-receiver-review-clock.json"
    ));
    fixture::<ManifoldClockSnapshot>(include_str!(
        "../../../../fixtures/clock/remote-camera-start-sender-review-clock.json"
    ));
    fixture::<ManifoldClockSnapshot>(include_str!(
        "../../../../fixtures/clock/remote-camera-get-status-review-clock.json"
    ));
    fixture::<ManifoldClockSnapshot>(include_str!(
        "../../../../fixtures/clock/remote-camera-stop-review-clock.json"
    ));
    fixture::<ManifoldCommandAck>(include_str!(
        "../../../../fixtures/command/synthetic-command-ack.json"
    ));
    fixture::<ManifoldCommandRejection>(include_str!(
        "../../../../fixtures/command/synthetic-command-rejection.json"
    ));
    fixture::<ManifoldControlLeaseRequest>(include_str!(
        "../../../../fixtures/command/synthetic-lease-request.json"
    ));
    fixture::<ManifoldControlLeaseRequest>(include_str!(
        "../../../../fixtures/damaged/lease-request-stale-revision.json"
    ));
    fixture::<ManifoldControlLeaseRequest>(include_str!(
        "../../../../fixtures/damaged/lease-request-zero-ttl.json"
    ));
    fixture::<ManifoldControlLeaseRequest>(include_str!(
        "../../../../fixtures/damaged/lease-request-missing-capability.json"
    ));
    fixture::<ManifoldControlLeaseRequest>(include_str!(
        "../../../../fixtures/damaged/lease-request-busy-scope.json"
    ));
    fixture::<ManifoldControlLease>(include_str!(
        "../../../../fixtures/command/synthetic-control-lease.json"
    ));
    fixture::<ManifoldControlLease>(include_str!(
        "../../../../fixtures/command/synthetic-stream-registry-lease.json"
    ));
    fixture::<ManifoldControlLease>(include_str!(
        "../../../../fixtures/command/synthetic-host-manifest-lease.json"
    ));
    fixture::<ManifoldControlLease>(include_str!(
        "../../../../fixtures/command/synthetic-clock-lease.json"
    ));
    fixture::<ManifoldControlLeaseRejection>(include_str!(
        "../../../../fixtures/command/synthetic-lease-rejection.json"
    ));
    fixture::<ManifoldControlLeaseReleaseRequest>(include_str!(
        "../../../../fixtures/command/synthetic-lease-release-request.json"
    ));
    fixture::<ManifoldControlLeaseReleaseRequest>(include_str!(
        "../../../../fixtures/damaged/lease-release-request-stale-revision.json"
    ));
    fixture::<ManifoldControlLeaseReleaseRequest>(include_str!(
        "../../../../fixtures/damaged/lease-release-request-unknown-lease.json"
    ));
    fixture::<ManifoldControlLeaseReleaseRequest>(include_str!(
        "../../../../fixtures/damaged/lease-release-request-holder-mismatch.json"
    ));
    fixture::<ManifoldControlLeaseReleaseRequest>(include_str!(
        "../../../../fixtures/damaged/lease-release-request-scope-mismatch.json"
    ));
    fixture::<ManifoldControlLeaseReleaseRejection>(include_str!(
        "../../../../fixtures/command/synthetic-lease-release-rejection.json"
    ));
    fixture::<ManifoldControlLeaseRenewalRequest>(include_str!(
        "../../../../fixtures/command/synthetic-lease-renewal-request.json"
    ));
    fixture::<ManifoldControlLeaseRenewalRequest>(include_str!(
        "../../../../fixtures/damaged/lease-renewal-request-stale-revision.json"
    ));
    fixture::<ManifoldControlLeaseRenewalRequest>(include_str!(
        "../../../../fixtures/damaged/lease-renewal-request-unknown-lease.json"
    ));
    fixture::<ManifoldControlLeaseRenewalRequest>(include_str!(
        "../../../../fixtures/damaged/lease-renewal-request-holder-mismatch.json"
    ));
    fixture::<ManifoldControlLeaseRenewalRequest>(include_str!(
        "../../../../fixtures/damaged/lease-renewal-request-scope-mismatch.json"
    ));
    fixture::<ManifoldControlLeaseRenewalRequest>(include_str!(
        "../../../../fixtures/damaged/lease-renewal-request-zero-ttl.json"
    ));
    fixture::<ManifoldControlLeaseRenewalRequest>(include_str!(
        "../../../../fixtures/damaged/lease-renewal-request-non-extending.json"
    ));
    fixture::<ManifoldControlLeaseRenewalRejection>(include_str!(
        "../../../../fixtures/command/synthetic-lease-renewal-rejection.json"
    ));
    fixture::<ManifoldAuthoritySnapshot>(include_str!(
        "../../../../fixtures/authority/synthetic-authority-snapshot.json"
    ));
    fixture::<ManifoldAuthoritySnapshot>(include_str!(
        "../../../../fixtures/authority/synthetic-authority-snapshot-v2.json"
    ));
    fixture::<ManifoldAuthoritySnapshot>(include_str!(
        "../../../../fixtures/authority/synthetic-lease-active-authority-snapshot.json"
    ));
    fixture::<ManifoldAuthoritySnapshot>(include_str!(
        "../../../../fixtures/authority/synthetic-stream-subscription-authority-snapshot.json"
    ));
    fixture::<ManifoldAuthoritySnapshot>(include_str!(
            "../../../../fixtures/authority/synthetic-stream-subscription-active-authority-snapshot.json"
        ));
    fixture::<ManifoldAuthoritySnapshot>(include_str!(
            "../../../../fixtures/authority/synthetic-stream-subscription-limit-authority-snapshot.json"
        ));
    fixture::<ManifoldAuthoritySnapshot>(include_str!(
        "../../../../fixtures/authority/synthetic-stream-subscription-ui-disabled-authority-snapshot.json"
    ));
    fixture::<ManifoldAuthoritySnapshot>(include_str!(
        "../../../../fixtures/authority/remote-camera-q2q-authority-snapshot.json"
    ));
    fixture::<ManifoldCommandAuthorityAuditEvent>(include_str!(
        "../../../../fixtures/audit/synthetic-command-accepted-event.json"
    ));
    fixture::<ManifoldControlLeaseAuthorityAuditEvent>(include_str!(
        "../../../../fixtures/audit/synthetic-lease-accepted-event.json"
    ));
    fixture::<ManifoldControlLeaseReleaseAuthorityAuditEvent>(include_str!(
        "../../../../fixtures/audit/synthetic-lease-release-accepted-event.json"
    ));
    fixture::<ManifoldControlLeaseRenewalAuthorityAuditEvent>(include_str!(
        "../../../../fixtures/audit/synthetic-lease-renewal-accepted-event.json"
    ));
    fixture::<ManifoldStreamRegistryAuthorityAuditEvent>(include_str!(
        "../../../../fixtures/audit/synthetic-stream-registry-accepted-event.json"
    ));
    fixture::<ManifoldStreamSubscriptionAuthorityAuditEvent>(include_str!(
        "../../../../fixtures/audit/synthetic-stream-subscription-accepted-event.json"
    ));
    fixture::<ManifoldStreamSubscriptionRenewalAuthorityAuditEvent>(include_str!(
        "../../../../fixtures/audit/synthetic-stream-subscription-renewal-accepted-event.json"
    ));
    fixture::<ManifoldModuleRuntimeStateAuthorityAuditEvent>(include_str!(
        "../../../../fixtures/audit/synthetic-module-runtime-state-accepted-event.json"
    ));
    fixture::<ManifoldHostManifestAuthorityAuditEvent>(include_str!(
        "../../../../fixtures/audit/synthetic-host-manifest-accepted-event.json"
    ));
    fixture::<ManifoldClockSnapshotAuthorityAuditEvent>(include_str!(
        "../../../../fixtures/audit/synthetic-clock-accepted-event.json"
    ));
    fixture::<ManifoldCommandAuthorityReview>(include_str!(
        "../../../../fixtures/authority-review/synthetic-command-accepted-review.json"
    ));
    fixture::<ManifoldCommandAuthorityReview>(include_str!(
        "../../../../fixtures/authority-review/synthetic-command-stale-revision-review.json"
    ));
    fixture::<ManifoldCommandAuthorityReview>(include_str!(
        "../../../../fixtures/authority-review/synthetic-command-expired-lease-review.json"
    ));
    fixture::<ManifoldCommandAuthorityReview>(include_str!(
        "../../../../fixtures/authority-review/synthetic-command-missing-lease-review.json"
    ));
    fixture::<ManifoldCommandAuthorityReview>(include_str!(
        "../../../../fixtures/authority-review/synthetic-command-unknown-command-review.json"
    ));
    fixture::<ManifoldCommandAuthorityReview>(include_str!(
        "../../../../fixtures/authority-review/synthetic-command-unknown-lease-review.json"
    ));
    fixture::<ManifoldCommandAuthorityReview>(include_str!(
        "../../../../fixtures/authority-review/synthetic-command-capability-mismatch-review.json"
    ));
    fixture::<ManifoldCommandAuthorityReview>(include_str!(
        "../../../../fixtures/authority-review/remote-camera-q2q-start-receiver-review.json"
    ));
    fixture::<ManifoldCommandAuthorityReview>(include_str!(
        "../../../../fixtures/authority-review/remote-camera-q2q-start-sender-review.json"
    ));
    fixture::<ManifoldCommandAuthorityReview>(include_str!(
        "../../../../fixtures/authority-review/remote-camera-q2q-get-status-review.json"
    ));
    fixture::<ManifoldCommandAuthorityReview>(include_str!(
        "../../../../fixtures/authority-review/remote-camera-q2q-stop-review.json"
    ));
    fixture::<ManifoldCommandDispatchRejection>(include_str!(
        "../../../../fixtures/command-dispatch/synthetic-command-dispatch-rejection.json"
    ));
    fixture::<ManifoldCommandDispatchReceipt>(include_str!(
        "../../../../fixtures/command-dispatch/synthetic-command-dispatch-ready-receipt.json"
    ));
    fixture::<ManifoldCommandDispatchReceipt>(include_str!(
        "../../../../fixtures/command-dispatch/synthetic-command-dispatch-rejected-receipt.json"
    ));
    fixture::<ManifoldCommandDispatchReceipt>(include_str!(
        "../../../../fixtures/command-dispatch/remote-camera-q2q-start-receiver-dispatch-receipt.json"
    ));
    fixture::<ManifoldCommandDispatchReceipt>(include_str!(
        "../../../../fixtures/command-dispatch/remote-camera-q2q-start-sender-dispatch-receipt.json"
    ));
    fixture::<ManifoldCommandDispatchReceipt>(include_str!(
        "../../../../fixtures/command-dispatch/remote-camera-q2q-get-status-dispatch-receipt.json"
    ));
    fixture::<ManifoldCommandDispatchReceipt>(include_str!(
        "../../../../fixtures/command-dispatch/remote-camera-q2q-stop-dispatch-receipt.json"
    ));
    fixture::<ManifoldControlLeaseAuthorityReview>(include_str!(
        "../../../../fixtures/lease-review/synthetic-lease-accepted-review.json"
    ));
    fixture::<ManifoldControlLeaseAuthorityReview>(include_str!(
        "../../../../fixtures/lease-review/synthetic-lease-stale-revision-review.json"
    ));
    fixture::<ManifoldControlLeaseAuthorityReview>(include_str!(
        "../../../../fixtures/lease-review/synthetic-lease-zero-ttl-review.json"
    ));
    fixture::<ManifoldControlLeaseAuthorityReview>(include_str!(
        "../../../../fixtures/lease-review/synthetic-lease-missing-capability-review.json"
    ));
    fixture::<ManifoldControlLeaseAuthorityReview>(include_str!(
        "../../../../fixtures/lease-review/synthetic-lease-busy-scope-review.json"
    ));
    fixture::<ManifoldControlLeaseAuthorityApplication>(include_str!(
        "../../../../fixtures/authority-application/synthetic-lease-accepted-application.json"
    ));
    fixture::<ManifoldControlLeaseAuthorityApplication>(include_str!(
        "../../../../fixtures/authority-application/synthetic-lease-rejected-application.json"
    ));
    fixture::<ManifoldAuthoritySnapshotApplicationRejection>(include_str!(
        "../../../../fixtures/authority-application/synthetic-lease-application-rejection.json"
    ));
    fixture::<ManifoldControlLeaseReleaseAuthorityReview>(include_str!(
        "../../../../fixtures/lease-release-review/synthetic-lease-release-accepted-review.json"
    ));
    fixture::<ManifoldControlLeaseReleaseAuthorityReview>(include_str!(
            "../../../../fixtures/lease-release-review/synthetic-lease-release-expired-lease-review.json"
        ));
    fixture::<ManifoldControlLeaseReleaseAuthorityReview>(include_str!(
            "../../../../fixtures/lease-release-review/synthetic-lease-release-stale-revision-review.json"
        ));
    fixture::<ManifoldControlLeaseReleaseAuthorityReview>(include_str!(
            "../../../../fixtures/lease-release-review/synthetic-lease-release-unknown-lease-review.json"
        ));
    fixture::<ManifoldControlLeaseReleaseAuthorityReview>(include_str!(
            "../../../../fixtures/lease-release-review/synthetic-lease-release-holder-mismatch-review.json"
        ));
    fixture::<ManifoldControlLeaseReleaseAuthorityReview>(include_str!(
            "../../../../fixtures/lease-release-review/synthetic-lease-release-scope-mismatch-review.json"
        ));
    fixture::<ManifoldControlLeaseReleaseAuthorityApplication>(include_str!(
            "../../../../fixtures/authority-application/synthetic-lease-release-accepted-application.json"
        ));
    fixture::<ManifoldControlLeaseReleaseAuthorityApplication>(include_str!(
            "../../../../fixtures/authority-application/synthetic-lease-release-rejected-application.json"
        ));
    fixture::<ManifoldAuthoritySnapshotApplicationRejection>(include_str!(
            "../../../../fixtures/authority-application/synthetic-lease-release-application-rejection.json"
        ));
    fixture::<ManifoldControlLeaseRenewalAuthorityReview>(include_str!(
        "../../../../fixtures/lease-renewal-review/synthetic-lease-renewal-accepted-review.json"
    ));
    fixture::<ManifoldControlLeaseRenewalAuthorityReview>(include_str!(
            "../../../../fixtures/lease-renewal-review/synthetic-lease-renewal-stale-revision-review.json"
        ));
    fixture::<ManifoldControlLeaseRenewalAuthorityReview>(include_str!(
            "../../../../fixtures/lease-renewal-review/synthetic-lease-renewal-unknown-lease-review.json"
        ));
    fixture::<ManifoldControlLeaseRenewalAuthorityReview>(include_str!(
            "../../../../fixtures/lease-renewal-review/synthetic-lease-renewal-holder-mismatch-review.json"
        ));
    fixture::<ManifoldControlLeaseRenewalAuthorityReview>(include_str!(
            "../../../../fixtures/lease-renewal-review/synthetic-lease-renewal-scope-mismatch-review.json"
        ));
    fixture::<ManifoldControlLeaseRenewalAuthorityReview>(include_str!(
        "../../../../fixtures/lease-renewal-review/synthetic-lease-renewal-zero-ttl-review.json"
    ));
    fixture::<ManifoldControlLeaseRenewalAuthorityReview>(include_str!(
            "../../../../fixtures/lease-renewal-review/synthetic-lease-renewal-non-extending-review.json"
        ));
    fixture::<ManifoldControlLeaseRenewalAuthorityReview>(include_str!(
            "../../../../fixtures/lease-renewal-review/synthetic-lease-renewal-expired-lease-review.json"
        ));
    fixture::<ManifoldControlLeaseRenewalAuthorityApplication>(include_str!(
            "../../../../fixtures/authority-application/synthetic-lease-renewal-accepted-application.json"
        ));
    fixture::<ManifoldControlLeaseRenewalAuthorityApplication>(include_str!(
            "../../../../fixtures/authority-application/synthetic-lease-renewal-rejected-application.json"
        ));
    fixture::<ManifoldAuthoritySnapshotApplicationRejection>(include_str!(
            "../../../../fixtures/authority-application/synthetic-lease-renewal-application-rejection.json"
        ));
    fixture::<ManifoldStreamRegistryAuthorityReview>(include_str!(
            "../../../../fixtures/stream-registry-review/synthetic-stream-registry-accepted-review.json"
        ));
    fixture::<ManifoldStreamRegistryAuthorityReview>(include_str!(
            "../../../../fixtures/stream-registry-review/synthetic-stream-registry-expired-lease-review.json"
        ));
    fixture::<ManifoldStreamRegistryAuthorityReview>(include_str!(
            "../../../../fixtures/stream-registry-review/synthetic-stream-registry-stale-revision-review.json"
        ));
    fixture::<ManifoldStreamRegistryAuthorityReview>(include_str!(
            "../../../../fixtures/stream-registry-review/synthetic-stream-registry-missing-lease-review.json"
        ));
    fixture::<ManifoldStreamRegistryAuthorityReview>(include_str!(
            "../../../../fixtures/stream-registry-review/synthetic-stream-registry-active-stream-review.json"
        ));
    fixture::<ManifoldStreamRegistryAuthorityReview>(include_str!(
            "../../../../fixtures/stream-registry-review/synthetic-stream-registry-remove-active-transport-review.json"
        ));
    fixture::<ManifoldStreamRegistryAuthorityReview>(include_str!(
            "../../../../fixtures/stream-registry-review/synthetic-stream-registry-disable-active-ui-subscriptions-review.json"
        ));
    fixture::<ManifoldStreamRegistryAuthorityReview>(include_str!(
            "../../../../fixtures/stream-registry-review/synthetic-stream-registry-lower-active-subscriber-limit-review.json"
        ));
    fixture::<ManifoldStreamRegistryAuthorityReview>(include_str!(
            "../../../../fixtures/stream-registry-review/synthetic-stream-registry-unknown-module-review.json"
        ));
    fixture::<ManifoldStreamRegistryAuthorityReview>(include_str!(
            "../../../../fixtures/stream-registry-review/synthetic-stream-registry-unknown-endpoint-review.json"
        ));
    fixture::<ManifoldStreamRegistryAuthorityApplication>(include_str!(
            "../../../../fixtures/authority-application/synthetic-stream-registry-accepted-application.json"
        ));
    fixture::<ManifoldStreamRegistryAuthorityApplication>(include_str!(
            "../../../../fixtures/authority-application/synthetic-stream-registry-rejected-application.json"
        ));
    fixture::<ManifoldAuthoritySnapshotApplicationRejection>(include_str!(
            "../../../../fixtures/authority-application/synthetic-stream-registry-application-rejection.json"
        ));
    fixture::<ManifoldStreamSubscriptionAuthorityReview>(include_str!(
            "../../../../fixtures/stream-subscription-review/synthetic-stream-subscription-accepted-review.json"
        ));
    fixture::<ManifoldStreamSubscriptionAuthorityReview>(include_str!(
            "../../../../fixtures/stream-subscription-review/synthetic-stream-subscription-zero-ttl-review.json"
        ));
    fixture::<ManifoldStreamSubscriptionAuthorityReview>(include_str!(
            "../../../../fixtures/stream-subscription-review/synthetic-stream-subscription-missing-capability-review.json"
        ));
    fixture::<ManifoldStreamSubscriptionAuthorityReview>(include_str!(
            "../../../../fixtures/stream-subscription-review/synthetic-stream-subscription-stale-revision-review.json"
        ));
    fixture::<ManifoldStreamSubscriptionAuthorityReview>(include_str!(
            "../../../../fixtures/stream-subscription-review/synthetic-stream-subscription-stale-registry-review.json"
        ));
    fixture::<ManifoldStreamSubscriptionAuthorityReview>(include_str!(
            "../../../../fixtures/stream-subscription-review/synthetic-stream-subscription-unknown-stream-review.json"
        ));
    fixture::<ManifoldStreamSubscriptionAuthorityReview>(include_str!(
            "../../../../fixtures/stream-subscription-review/synthetic-stream-subscription-unknown-transport-review.json"
        ));
    fixture::<ManifoldStreamSubscriptionAuthorityReview>(include_str!(
            "../../../../fixtures/stream-subscription-review/synthetic-stream-subscription-subscriber-limit-review.json"
        ));
    fixture::<ManifoldStreamSubscriptionAuthorityReview>(include_str!(
            "../../../../fixtures/stream-subscription-review/synthetic-stream-subscription-ui-disabled-review.json"
        ));
    fixture::<ManifoldStreamSubscriptionAuthorityApplication>(include_str!(
            "../../../../fixtures/authority-application/synthetic-stream-subscription-accepted-application.json"
        ));
    fixture::<ManifoldStreamSubscriptionAuthorityApplication>(include_str!(
            "../../../../fixtures/authority-application/synthetic-stream-subscription-rejected-application.json"
        ));
    fixture::<ManifoldAuthoritySnapshotApplicationRejection>(include_str!(
            "../../../../fixtures/authority-application/synthetic-stream-subscription-application-rejection.json"
        ));
    fixture::<ManifoldStreamSubscriptionReleaseAuthorityReview>(include_str!(
            "../../../../fixtures/stream-subscription-release-review/synthetic-stream-subscription-release-accepted-review.json"
        ));
    fixture::<ManifoldStreamSubscriptionReleaseAuthorityReview>(include_str!(
            "../../../../fixtures/stream-subscription-release-review/synthetic-stream-subscription-release-expired-subscription-review.json"
        ));
    fixture::<ManifoldStreamSubscriptionReleaseAuthorityReview>(include_str!(
            "../../../../fixtures/stream-subscription-release-review/synthetic-stream-subscription-release-stale-revision-review.json"
        ));
    fixture::<ManifoldStreamSubscriptionReleaseAuthorityReview>(include_str!(
            "../../../../fixtures/stream-subscription-release-review/synthetic-stream-subscription-release-stale-registry-review.json"
        ));
    fixture::<ManifoldStreamSubscriptionReleaseAuthorityReview>(include_str!(
            "../../../../fixtures/stream-subscription-release-review/synthetic-stream-subscription-release-unknown-subscription-review.json"
        ));
    fixture::<ManifoldStreamSubscriptionReleaseAuthorityReview>(include_str!(
            "../../../../fixtures/stream-subscription-release-review/synthetic-stream-subscription-release-subscriber-mismatch-review.json"
        ));
    fixture::<ManifoldStreamSubscriptionReleaseAuthorityReview>(include_str!(
            "../../../../fixtures/stream-subscription-release-review/synthetic-stream-subscription-release-stream-mismatch-review.json"
        ));
    fixture::<ManifoldStreamSubscriptionReleaseAuthorityApplication>(include_str!(
            "../../../../fixtures/authority-application/synthetic-stream-subscription-release-accepted-application.json"
        ));
    fixture::<ManifoldStreamSubscriptionReleaseAuthorityApplication>(include_str!(
            "../../../../fixtures/authority-application/synthetic-stream-subscription-release-rejected-application.json"
        ));
    fixture::<ManifoldAuthoritySnapshotApplicationRejection>(include_str!(
            "../../../../fixtures/authority-application/synthetic-stream-subscription-release-application-rejection.json"
        ));
    fixture::<ManifoldStreamSubscriptionRenewalAuthorityReview>(include_str!(
            "../../../../fixtures/stream-subscription-renewal-review/synthetic-stream-subscription-renewal-accepted-review.json"
        ));
    fixture::<ManifoldStreamSubscriptionRenewalAuthorityReview>(include_str!(
            "../../../../fixtures/stream-subscription-renewal-review/synthetic-stream-subscription-renewal-stale-revision-review.json"
        ));
    fixture::<ManifoldStreamSubscriptionRenewalAuthorityReview>(include_str!(
            "../../../../fixtures/stream-subscription-renewal-review/synthetic-stream-subscription-renewal-stale-registry-review.json"
        ));
    fixture::<ManifoldStreamSubscriptionRenewalAuthorityReview>(include_str!(
            "../../../../fixtures/stream-subscription-renewal-review/synthetic-stream-subscription-renewal-unknown-subscription-review.json"
        ));
    fixture::<ManifoldStreamSubscriptionRenewalAuthorityReview>(include_str!(
            "../../../../fixtures/stream-subscription-renewal-review/synthetic-stream-subscription-renewal-subscriber-mismatch-review.json"
        ));
    fixture::<ManifoldStreamSubscriptionRenewalAuthorityReview>(include_str!(
            "../../../../fixtures/stream-subscription-renewal-review/synthetic-stream-subscription-renewal-stream-mismatch-review.json"
        ));
    fixture::<ManifoldStreamSubscriptionRenewalAuthorityReview>(include_str!(
            "../../../../fixtures/stream-subscription-renewal-review/synthetic-stream-subscription-renewal-transport-mismatch-review.json"
        ));
    fixture::<ManifoldStreamSubscriptionRenewalAuthorityReview>(include_str!(
            "../../../../fixtures/stream-subscription-renewal-review/synthetic-stream-subscription-renewal-zero-ttl-review.json"
        ));
    fixture::<ManifoldStreamSubscriptionRenewalAuthorityReview>(include_str!(
            "../../../../fixtures/stream-subscription-renewal-review/synthetic-stream-subscription-renewal-non-extending-review.json"
        ));
    fixture::<ManifoldStreamSubscriptionRenewalAuthorityReview>(include_str!(
            "../../../../fixtures/stream-subscription-renewal-review/synthetic-stream-subscription-renewal-expired-subscription-review.json"
        ));
    fixture::<ManifoldStreamSubscriptionRenewalAuthorityApplication>(include_str!(
            "../../../../fixtures/authority-application/synthetic-stream-subscription-renewal-accepted-application.json"
        ));
    fixture::<ManifoldStreamSubscriptionRenewalAuthorityApplication>(include_str!(
            "../../../../fixtures/authority-application/synthetic-stream-subscription-renewal-rejected-application.json"
        ));
    fixture::<ManifoldAuthoritySnapshotApplicationRejection>(include_str!(
            "../../../../fixtures/authority-application/synthetic-stream-subscription-renewal-application-rejection.json"
        ));
    fixture::<ManifoldAuthorityExpirySweepRequest>(include_str!(
        "../../../../fixtures/authority-expiry/synthetic-authority-expiry-sweep-request.json"
    ));
    fixture::<ManifoldAuthorityExpirySweepRequest>(include_str!(
        "../../../../fixtures/damaged/authority-expiry-sweep-request-stale-revision.json"
    ));
    fixture::<ManifoldAuthorityExpirySweepRequest>(include_str!(
        "../../../../fixtures/damaged/authority-expiry-sweep-request-registry-mismatch.json"
    ));
    fixture::<ManifoldAuthorityExpirySweepRejection>(include_str!(
        "../../../../fixtures/authority-expiry/synthetic-authority-expiry-sweep-rejection.json"
    ));
    fixture::<ManifoldAuthorityExpirySweepAuthorityAuditEvent>(include_str!(
        "../../../../fixtures/audit/synthetic-authority-expiry-sweep-accepted-event.json"
    ));
    fixture::<ManifoldAuthorityExpirySweepAuthorityReview>(include_str!(
            "../../../../fixtures/authority-expiry-review/synthetic-authority-expiry-sweep-accepted-review.json"
        ));
    fixture::<ManifoldAuthorityExpirySweepAuthorityReview>(include_str!(
            "../../../../fixtures/authority-expiry-review/synthetic-authority-expiry-sweep-stale-revision-review.json"
        ));
    fixture::<ManifoldAuthorityExpirySweepAuthorityReview>(include_str!(
            "../../../../fixtures/authority-expiry-review/synthetic-authority-expiry-sweep-registry-mismatch-review.json"
        ));
    fixture::<ManifoldAuthorityExpirySweepAuthorityReview>(include_str!(
            "../../../../fixtures/authority-expiry-review/synthetic-authority-expiry-sweep-no-expired-review.json"
        ));
    fixture::<ManifoldAuthorityExpirySweepAuthorityApplication>(include_str!(
            "../../../../fixtures/authority-application/synthetic-authority-expiry-sweep-accepted-application.json"
        ));
    fixture::<ManifoldAuthorityExpirySweepAuthorityApplication>(include_str!(
            "../../../../fixtures/authority-application/synthetic-authority-expiry-sweep-rejected-application.json"
        ));
    fixture::<ManifoldAuthoritySnapshotApplicationRejection>(include_str!(
            "../../../../fixtures/authority-application/synthetic-authority-expiry-sweep-application-rejection.json"
        ));
    fixture::<ManifoldModuleRuntimeStateAuthorityReview>(include_str!(
        "../../../../fixtures/module-runtime-review/synthetic-module-runtime-accepted-review.json"
    ));
    fixture::<ManifoldModuleRuntimeStateAuthorityReview>(include_str!(
            "../../../../fixtures/module-runtime-review/synthetic-module-runtime-expired-lease-review.json"
        ));
    fixture::<ManifoldModuleRuntimeStateAuthorityReview>(include_str!(
            "../../../../fixtures/module-runtime-review/synthetic-module-runtime-stale-revision-review.json"
        ));
    fixture::<ManifoldModuleRuntimeStateAuthorityReview>(include_str!(
            "../../../../fixtures/module-runtime-review/synthetic-module-runtime-missing-lease-review.json"
        ));
    fixture::<ManifoldModuleRuntimeStateAuthorityReview>(include_str!(
            "../../../../fixtures/module-runtime-review/synthetic-module-runtime-unknown-stream-review.json"
        ));
    fixture::<ManifoldModuleRuntimeStateAuthorityReview>(include_str!(
            "../../../../fixtures/module-runtime-review/synthetic-module-runtime-missing-backend-review.json"
        ));
    fixture::<ManifoldModuleRuntimeStateAuthorityApplication>(include_str!(
            "../../../../fixtures/authority-application/synthetic-module-runtime-accepted-application.json"
        ));
    fixture::<ManifoldModuleRuntimeStateAuthorityApplication>(include_str!(
            "../../../../fixtures/authority-application/synthetic-module-runtime-rejected-application.json"
        ));
    fixture::<ManifoldAuthoritySnapshotApplicationRejection>(include_str!(
            "../../../../fixtures/authority-application/synthetic-module-runtime-application-rejection.json"
        ));
    fixture::<ManifoldHostManifestChangeRequest>(include_str!(
        "../../../../fixtures/host/synthetic-host-manifest-change-request.json"
    ));
    fixture::<ManifoldHostManifestChangeRequest>(include_str!(
        "../../../../fixtures/damaged/host-manifest-request-stale-revision.json"
    ));
    fixture::<ManifoldHostManifestChangeRequest>(include_str!(
        "../../../../fixtures/damaged/host-manifest-request-missing-authority-role.json"
    ));
    fixture::<ManifoldHostManifestChangeRequest>(include_str!(
        "../../../../fixtures/damaged/host-manifest-request-endpoint-mismatch.json"
    ));
    fixture::<ManifoldHostManifestChangeRequest>(include_str!(
        "../../../../fixtures/damaged/host-manifest-request-remove-capability.json"
    ));
    fixture::<ManifoldHostManifestChangeRequest>(include_str!(
        "../../../../fixtures/damaged/host-manifest-request-remove-backend.json"
    ));
    fixture::<ManifoldHostManifestRejection>(include_str!(
        "../../../../fixtures/host/synthetic-host-manifest-rejection.json"
    ));
    fixture::<ManifoldHostManifestAuthorityReview>(include_str!(
        "../../../../fixtures/host-manifest-review/synthetic-host-manifest-accepted-review.json"
    ));
    fixture::<ManifoldHostManifestAuthorityReview>(include_str!(
            "../../../../fixtures/host-manifest-review/synthetic-host-manifest-expired-lease-review.json"
        ));
    fixture::<ManifoldHostManifestAuthorityReview>(include_str!(
            "../../../../fixtures/host-manifest-review/synthetic-host-manifest-stale-revision-review.json"
        ));
    fixture::<ManifoldHostManifestAuthorityReview>(include_str!(
            "../../../../fixtures/host-manifest-review/synthetic-host-manifest-missing-authority-role-review.json"
        ));
    fixture::<ManifoldHostManifestAuthorityReview>(include_str!(
            "../../../../fixtures/host-manifest-review/synthetic-host-manifest-endpoint-mismatch-review.json"
        ));
    fixture::<ManifoldHostManifestAuthorityReview>(include_str!(
            "../../../../fixtures/host-manifest-review/synthetic-host-manifest-remove-capability-review.json"
        ));
    fixture::<ManifoldHostManifestAuthorityReview>(include_str!(
            "../../../../fixtures/host-manifest-review/synthetic-host-manifest-remove-backend-review.json"
        ));
    fixture::<ManifoldHostManifestAuthorityApplication>(include_str!(
            "../../../../fixtures/authority-application/synthetic-host-manifest-accepted-application.json"
        ));
    fixture::<ManifoldHostManifestAuthorityApplication>(include_str!(
            "../../../../fixtures/authority-application/synthetic-host-manifest-rejected-application.json"
        ));
    fixture::<ManifoldAuthoritySnapshotApplicationRejection>(include_str!(
            "../../../../fixtures/authority-application/synthetic-host-manifest-application-rejection.json"
        ));
    fixture::<ManifoldClockSnapshotChangeRequest>(include_str!(
        "../../../../fixtures/clock/synthetic-clock-change-request.json"
    ));
    fixture::<ManifoldClockSnapshotChangeRequest>(include_str!(
        "../../../../fixtures/damaged/clock-request-stale-revision.json"
    ));
    fixture::<ManifoldClockSnapshotChangeRequest>(include_str!(
        "../../../../fixtures/damaged/clock-request-missing-lease.json"
    ));
    fixture::<ManifoldClockSnapshotChangeRequest>(include_str!(
        "../../../../fixtures/damaged/clock-request-domain-mismatch.json"
    ));
    fixture::<ManifoldClockSnapshotChangeRequest>(include_str!(
        "../../../../fixtures/damaged/clock-request-sequence-gap.json"
    ));
    fixture::<ManifoldClockSnapshotChangeRequest>(include_str!(
        "../../../../fixtures/damaged/clock-request-monotonic-regression.json"
    ));
    fixture::<ManifoldClockSnapshotRejection>(include_str!(
        "../../../../fixtures/clock/synthetic-clock-rejection.json"
    ));
    fixture::<ManifoldClockSnapshotAuthorityReview>(include_str!(
        "../../../../fixtures/clock-review/synthetic-clock-accepted-review.json"
    ));
    fixture::<ManifoldClockSnapshotAuthorityReview>(include_str!(
        "../../../../fixtures/clock-review/synthetic-clock-expired-lease-review.json"
    ));
    fixture::<ManifoldClockSnapshotAuthorityReview>(include_str!(
        "../../../../fixtures/clock-review/synthetic-clock-stale-revision-review.json"
    ));
    fixture::<ManifoldClockSnapshotAuthorityReview>(include_str!(
        "../../../../fixtures/clock-review/synthetic-clock-missing-lease-review.json"
    ));
    fixture::<ManifoldClockSnapshotAuthorityReview>(include_str!(
        "../../../../fixtures/clock-review/synthetic-clock-domain-mismatch-review.json"
    ));
    fixture::<ManifoldClockSnapshotAuthorityReview>(include_str!(
        "../../../../fixtures/clock-review/synthetic-clock-sequence-gap-review.json"
    ));
    fixture::<ManifoldClockSnapshotAuthorityReview>(include_str!(
        "../../../../fixtures/clock-review/synthetic-clock-monotonic-regression-review.json"
    ));
    fixture::<ManifoldClockSnapshotAuthorityApplication>(include_str!(
        "../../../../fixtures/authority-application/synthetic-clock-accepted-application.json"
    ));
    fixture::<ManifoldClockSnapshotAuthorityApplication>(include_str!(
        "../../../../fixtures/authority-application/synthetic-clock-rejected-application.json"
    ));
    fixture::<ManifoldAuthoritySnapshotApplicationRejection>(include_str!(
        "../../../../fixtures/authority-application/synthetic-clock-application-rejection.json"
    ));
    fixture::<ManifoldHostManifest>(include_str!(
        "../../../../fixtures/host/synthetic-host.json"
    ));
    fixture::<ManifoldHostManifest>(include_str!("../../../../fixtures/host/desktop-local.json"));
    fixture::<ManifoldHostManifest>(include_str!("../../../../fixtures/host/mobile-device.json"));
    fixture::<ManifoldHostManifest>(include_str!(
        "../../../../fixtures/host/headset-device.json"
    ));
    fixture::<ManifoldDeploymentManifest>(include_str!(
        "../../../../fixtures/deployment/synthetic-deployment.json"
    ));
    fixture::<ManifoldClockSnapshot>(include_str!(
        "../../../../fixtures/clock/synthetic-clock-snapshot.json"
    ));
    fixture::<ManifoldClockSnapshot>(include_str!(
        "../../../../fixtures/clock/synthetic-command-review-clock.json"
    ));
    fixture::<ManifoldClockSnapshot>(include_str!(
        "../../../../fixtures/clock/synthetic-expired-command-review-clock.json"
    ));
    fixture::<ManifoldValidationScorecard>(include_str!(
        "../../../../fixtures/validation/synthetic-scorecard.json"
    ));
    fixture::<ManifoldHostRunInstallLaunchProfile>(include_str!(
        "../../../../fixtures/host-run/install-profile-desktop.json"
    ));
    fixture::<ManifoldHostRunInstallLaunchProfile>(include_str!(
        "../../../../fixtures/host-run/install-profile-mobile.json"
    ));
    fixture::<ManifoldHostRunInstallLaunchProfile>(include_str!(
        "../../../../fixtures/host-run/install-profile-headset.json"
    ));
    fixture::<ManifoldHostRunValidationSlot>(include_str!(
        "../../../../fixtures/host-run/slot-live-smoke.json"
    ));
    fixture::<ManifoldHostRunBundle>(include_str!(
        "../../../../fixtures/host-run/run-bundle-live-smoke.json"
    ));
    fixture::<ManifoldHostRunCommandEnvelope>(include_str!(
        "../../../../fixtures/host-run/command-envelope-run-live.json"
    ));
    fixture::<ManifoldHostRunEvidence>(include_str!(
        "../../../../fixtures/host-run/run-evidence-live-smoke.json"
    ));
    fixture::<ManifoldBridgeRouteDescriptor>(include_str!(
        "../../../../fixtures/bridge-route/command-websocket-applied-route.json"
    ));
    fixture::<ManifoldBridgeRouteEvidence>(include_str!(
        "../../../../fixtures/bridge-route/command-websocket-applied-evidence.json"
    ));
    fixture::<ManifoldBridgeRouteDescriptor>(include_str!(
        "../../../../fixtures/bridge-route/marker-lsl-timestamped-route.json"
    ));
    fixture::<ManifoldBridgeRouteDescriptor>(include_str!(
        "../../../../fixtures/bridge-route/stream-lsl-clock-roundtrip-route.json"
    ));
    fixture::<ManifoldBridgeRouteDescriptor>(include_str!(
        "../../../../fixtures/bridge-route/telemetry-udp-best-effort-route.json"
    ));
    fixture::<ManifoldBridgeRouteDescriptor>(include_str!(
        "../../../../fixtures/bridge-route/stream-websocket-ordered-route.json"
    ));
    fixture::<ManifoldBridgeRouteDescriptor>(include_str!(
        "../../../../fixtures/bridge-route/stream-osc-udp-route.json"
    ));
    fixture::<ManifoldBridgeRouteDescriptor>(include_str!(
        "../../../../fixtures/bridge-route/stream-bluetooth-rfcomm-route.json"
    ));
    fixture::<ManifoldBridgeRouteDescriptor>(include_str!(
        "../../../../fixtures/bridge-route/stream-bluetooth-gatt-notify-route.json"
    ));
    fixture::<ManifoldBridgeRouteDescriptor>(include_str!(
        "../../../../fixtures/bridge-route/device-adb-transport-route.json"
    ));
    fixture::<ManifoldBridgeRouteDescriptor>(include_str!(
        "../../../../fixtures/bridge-route/media-h264-data-plane-route.json"
    ));
    fixture::<ManifoldBridgeRouteDescriptor>(include_str!(
        "../../../../fixtures/bridge-route/stream-zeromq-pubsub-route.json"
    ));
    fixture::<ManifoldBridgeRouteEvidence>(include_str!(
        "../../../../fixtures/bridge-route/stream-lsl-clock-roundtrip-evidence.json"
    ));
    fixture::<ManifoldBridgeRouteEvidence>(include_str!(
        "../../../../fixtures/bridge-route/stream-zeromq-pubsub-evidence.json"
    ));
    fixture::<ManifoldBridgeRouteEvidence>(include_str!(
        "../../../../fixtures/damaged/bridge-route-command-transport-only-evidence.json"
    ));
    fixture::<ManifoldBridgeRouteDescriptor>(include_str!(
        "../../../../fixtures/damaged/bridge-route-lsl-missing-profile.json"
    ));
    fixture::<ManifoldBridgeRouteDescriptor>(include_str!(
        "../../../../fixtures/damaged/bridge-route-zeromq-missing-profile.json"
    ));
    fixture::<ManifoldBridgeRouteDescriptor>(include_str!(
        "../../../../fixtures/damaged/bridge-route-missing-conditions.json"
    ));
    fixture::<ManifoldBridgeRouteDescriptor>(include_str!(
        "../../../../fixtures/damaged/bridge-route-invalid-timing.json"
    ));
    fixture::<ManifoldShellHandoffManifest>(include_str!(
        "../../../../fixtures/shell-handoff/synthetic-loopback-shell.json"
    ));
    fixture::<ManifoldShellHandoffReviewReceipt>(include_str!(
        "../../../../fixtures/shell-handoff/synthetic-loopback-shell-review.json"
    ));
}

#[test]
fn damaged_endpoint_security_fixture_has_expected_rejection() {
    let manifest = fixture::<ManifoldHostManifest>(include_str!(
        "../../../../fixtures/damaged/invalid-endpoint-security.json"
    ));
    let error = manifest.validate_endpoint_security().unwrap_err();

    assert_eq!(error.rejection_code(), "endpoint_security_mismatch");
}

#[test]
fn damaged_stale_revision_fixture_rejects_against_current_revision() {
    let descriptor = fixture::<ManifoldCommandDescriptor>(include_str!(
        "../../../../fixtures/command/synthetic-command-descriptor.json"
    ));
    let envelope = fixture::<ManifoldCommandEnvelope>(include_str!(
        "../../../../fixtures/damaged/stale-revision-command.json"
    ));
    let lease = fixture::<ManifoldControlLease>(include_str!(
        "../../../../fixtures/command/synthetic-control-lease.json"
    ));
    let current_revision = Revision::new(2).unwrap();
    let error = envelope
        .validate_request(&descriptor, current_revision, Some(&lease))
        .unwrap_err();

    assert_eq!(error.rejection_code(), "stale_revision");
}

#[test]
fn damaged_missing_lease_fixture_rejects_required_lease() {
    let descriptor = fixture::<ManifoldCommandDescriptor>(include_str!(
        "../../../../fixtures/command/synthetic-command-descriptor.json"
    ));
    let envelope = fixture::<ManifoldCommandEnvelope>(include_str!(
        "../../../../fixtures/damaged/missing-lease-scope-command.json"
    ));
    let error = envelope
        .validate_request(&descriptor, Revision::INITIAL, None)
        .unwrap_err();

    assert_eq!(error.rejection_code(), "missing_lease");
}

#[test]
fn remote_camera_command_fixtures_match_descriptors() {
    let lease = ManifoldControlLease {
        schema_id: SchemaId::new("rusty.manifold.command.control_lease.v1").unwrap(),
        lease_id: DottedId::new("lease.remote_camera.q2q_two_way_lan_smoke").unwrap(),
        holder_id: DottedId::new("holder.remote_camera.quest_a").unwrap(),
        scope: DottedId::new("session.remote_camera.q2q_two_way_lan_smoke").unwrap(),
        state: LeaseState::Active,
        granted_revision: Revision::INITIAL,
        expires_at_ms: 1765000030000,
        required_capability: DottedId::new("manifold.remote_camera.control").unwrap(),
    };
    let leased_pairs = [
        (
            fixture::<ManifoldCommandDescriptor>(include_str!(
                "../../../../fixtures/command/remote-camera-start-receiver-descriptor.json"
            )),
            fixture::<ManifoldCommandEnvelope>(include_str!(
                "../../../../fixtures/command/remote-camera-start-receiver-envelope.json"
            )),
        ),
        (
            fixture::<ManifoldCommandDescriptor>(include_str!(
                "../../../../fixtures/command/remote-camera-start-sender-descriptor.json"
            )),
            fixture::<ManifoldCommandEnvelope>(include_str!(
                "../../../../fixtures/command/remote-camera-start-sender-envelope.json"
            )),
        ),
    ];
    for (descriptor, envelope) in leased_pairs {
        assert_eq!(
            envelope.validate_request(&descriptor, Revision::INITIAL, Some(&lease)),
            Ok(())
        );
    }

    let lease_free_pairs = [
        (
            fixture::<ManifoldCommandDescriptor>(include_str!(
                "../../../../fixtures/command/remote-camera-get-status-descriptor.json"
            )),
            fixture::<ManifoldCommandEnvelope>(include_str!(
                "../../../../fixtures/command/remote-camera-get-status-envelope.json"
            )),
        ),
        (
            fixture::<ManifoldCommandDescriptor>(include_str!(
                "../../../../fixtures/command/remote-camera-stop-descriptor.json"
            )),
            fixture::<ManifoldCommandEnvelope>(include_str!(
                "../../../../fixtures/command/remote-camera-stop-envelope.json"
            )),
        ),
    ];
    for (descriptor, envelope) in lease_free_pairs {
        assert_eq!(
            envelope.validate_request(&descriptor, Revision::INITIAL, None),
            Ok(())
        );
    }
}

#[test]
fn valid_authority_audit_fixture_matches_snapshot() {
    let snapshot = fixture::<ManifoldAuthoritySnapshot>(include_str!(
        "../../../../fixtures/authority/synthetic-authority-snapshot.json"
    ));
    let event = fixture::<ManifoldCommandAuthorityAuditEvent>(include_str!(
        "../../../../fixtures/audit/synthetic-command-accepted-event.json"
    ));

    assert_eq!(snapshot.validate_authority_links(), Ok(()));
    assert_eq!(event.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn valid_authority_review_fixture_matches_evaluator() {
    let snapshot = fixture::<ManifoldAuthoritySnapshot>(include_str!(
        "../../../../fixtures/authority/synthetic-authority-snapshot.json"
    ));
    let envelope = fixture::<ManifoldCommandEnvelope>(include_str!(
        "../../../../fixtures/command/synthetic-command-envelope.json"
    ));
    let clock = fixture::<ManifoldClockSnapshot>(include_str!(
        "../../../../fixtures/clock/synthetic-command-review-clock.json"
    ));
    let expected = fixture::<ManifoldCommandAuthorityReview>(include_str!(
        "../../../../fixtures/authority-review/synthetic-command-accepted-review.json"
    ));
    let generated = snapshot
        .review_command(
            envelope,
            clock,
            vec![DottedId::new("evidence.command_authority.request.start.synthetic_wave").unwrap()],
        )
        .unwrap();

    assert_eq!(generated, expected);
    assert_eq!(expected.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn valid_command_dispatch_receipt_fixtures_match_evaluator() {
    let snapshot = fixture::<ManifoldAuthoritySnapshot>(include_str!(
        "../../../../fixtures/authority/synthetic-authority-snapshot.json"
    ));
    let accepted_review = fixture::<ManifoldCommandAuthorityReview>(include_str!(
        "../../../../fixtures/authority-review/synthetic-command-accepted-review.json"
    ));
    let rejected_review = fixture::<ManifoldCommandAuthorityReview>(include_str!(
        "../../../../fixtures/authority-review/synthetic-command-missing-lease-review.json"
    ));
    let expected_ready = fixture::<ManifoldCommandDispatchReceipt>(include_str!(
        "../../../../fixtures/command-dispatch/synthetic-command-dispatch-ready-receipt.json"
    ));
    let expected_rejected = fixture::<ManifoldCommandDispatchReceipt>(include_str!(
        "../../../../fixtures/command-dispatch/synthetic-command-dispatch-rejected-receipt.json"
    ));

    let generated_ready = snapshot.prepare_command_dispatch(accepted_review).unwrap();
    let generated_rejected = snapshot.prepare_command_dispatch(rejected_review).unwrap();

    assert_eq!(generated_ready, expected_ready);
    assert_eq!(generated_rejected, expected_rejected);
    assert_eq!(expected_ready.validate_against_snapshot(&snapshot), Ok(()));
    assert_eq!(
        expected_rejected.validate_against_snapshot(&snapshot),
        Ok(())
    );
}

#[test]
fn valid_remote_camera_command_sequence_fixtures_match_evaluator() {
    let snapshot = fixture::<ManifoldAuthoritySnapshot>(include_str!(
        "../../../../fixtures/authority/remote-camera-q2q-authority-snapshot.json"
    ));
    let reviews = [
        fixture::<ManifoldCommandAuthorityReview>(include_str!(
            "../../../../fixtures/authority-review/remote-camera-q2q-start-receiver-review.json"
        )),
        fixture::<ManifoldCommandAuthorityReview>(include_str!(
            "../../../../fixtures/authority-review/remote-camera-q2q-start-sender-review.json"
        )),
        fixture::<ManifoldCommandAuthorityReview>(include_str!(
            "../../../../fixtures/authority-review/remote-camera-q2q-get-status-review.json"
        )),
        fixture::<ManifoldCommandAuthorityReview>(include_str!(
            "../../../../fixtures/authority-review/remote-camera-q2q-stop-review.json"
        )),
    ];
    let dispatches = [
        fixture::<ManifoldCommandDispatchReceipt>(include_str!(
            "../../../../fixtures/command-dispatch/remote-camera-q2q-start-receiver-dispatch-receipt.json"
        )),
        fixture::<ManifoldCommandDispatchReceipt>(include_str!(
            "../../../../fixtures/command-dispatch/remote-camera-q2q-start-sender-dispatch-receipt.json"
        )),
        fixture::<ManifoldCommandDispatchReceipt>(include_str!(
            "../../../../fixtures/command-dispatch/remote-camera-q2q-get-status-dispatch-receipt.json"
        )),
        fixture::<ManifoldCommandDispatchReceipt>(include_str!(
            "../../../../fixtures/command-dispatch/remote-camera-q2q-stop-dispatch-receipt.json"
        )),
    ];
    let expected_commands = [
        "command.remote_camera.start_receiver",
        "command.remote_camera.start_sender",
        "command.remote_camera.get_status",
        "command.remote_camera.stop",
    ];

    assert_eq!(snapshot.validate_authority_links(), Ok(()));
    let mut previous_accepted_at_ms = 0;
    for ((review, dispatch), expected_command) in reviews
        .iter()
        .zip(dispatches.iter())
        .zip(expected_commands.iter())
    {
        let generated_review = snapshot
            .review_command(
                review.audit_event.envelope.clone(),
                review.audit_event.recorded_clock.clone(),
                review.audit_event.evidence_refs.clone(),
            )
            .unwrap();
        let generated_dispatch = snapshot
            .prepare_command_dispatch(generated_review.clone())
            .unwrap();

        assert_eq!(&generated_review, review);
        assert_eq!(&generated_dispatch, dispatch);
        assert_eq!(
            dispatch.outcome,
            ManifoldCommandDispatchReceiptOutcome::CommandDispatchReady
        );
        assert_eq!(dispatch.command_id.as_str(), *expected_command);

        let accepted_at_ms = dispatch.ack.as_ref().unwrap().accepted_at_ms;
        assert!(accepted_at_ms > previous_accepted_at_ms);
        previous_accepted_at_ms = accepted_at_ms;
    }

    assert!(dispatches[0].ack.as_ref().unwrap().lease_id.is_some());
    assert!(dispatches[1].ack.as_ref().unwrap().lease_id.is_some());
    assert!(dispatches[2].ack.as_ref().unwrap().lease_id.is_none());
    assert!(dispatches[3].ack.as_ref().unwrap().lease_id.is_none());
}

#[test]
fn damaged_authority_audit_fixture_rejects_unknown_command() {
    let snapshot = fixture::<ManifoldAuthoritySnapshot>(include_str!(
        "../../../../fixtures/authority/synthetic-authority-snapshot.json"
    ));
    let event = fixture::<ManifoldCommandAuthorityAuditEvent>(include_str!(
        "../../../../fixtures/damaged/authority-audit-unknown-command.json"
    ));
    let error = event.validate_against_snapshot(&snapshot).unwrap_err();

    assert_eq!(error.rejection_code(), "unknown_command");
}

#[test]
fn valid_lease_authority_audit_fixture_matches_snapshot() {
    let snapshot = fixture::<ManifoldAuthoritySnapshot>(include_str!(
        "../../../../fixtures/authority/synthetic-authority-snapshot.json"
    ));
    let event = fixture::<ManifoldControlLeaseAuthorityAuditEvent>(include_str!(
        "../../../../fixtures/audit/synthetic-lease-accepted-event.json"
    ));

    assert_eq!(snapshot.validate_authority_links(), Ok(()));
    assert_eq!(event.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn valid_lease_authority_review_fixture_matches_evaluator() {
    let snapshot = fixture::<ManifoldAuthoritySnapshot>(include_str!(
        "../../../../fixtures/authority/synthetic-authority-snapshot.json"
    ));
    let request = fixture::<ManifoldControlLeaseRequest>(include_str!(
        "../../../../fixtures/command/synthetic-lease-request.json"
    ));
    let clock = fixture::<ManifoldClockSnapshot>(include_str!(
        "../../../../fixtures/clock/synthetic-command-review-clock.json"
    ));
    let expected = fixture::<ManifoldControlLeaseAuthorityReview>(include_str!(
        "../../../../fixtures/lease-review/synthetic-lease-accepted-review.json"
    ));
    let generated = snapshot
        .review_lease_request(
            request,
            clock,
            vec![DottedId::new("evidence.lease_authority.request.synthetic_lease_1").unwrap()],
        )
        .unwrap();

    assert_eq!(generated, expected);
    assert_eq!(expected.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn valid_lease_authority_application_fixture_matches_evaluator() {
    let snapshot = fixture::<ManifoldAuthoritySnapshot>(include_str!(
        "../../../../fixtures/authority/synthetic-authority-snapshot.json"
    ));
    let review = fixture::<ManifoldControlLeaseAuthorityReview>(include_str!(
        "../../../../fixtures/lease-review/synthetic-lease-accepted-review.json"
    ));
    let expected = fixture::<ManifoldControlLeaseAuthorityApplication>(include_str!(
        "../../../../fixtures/authority-application/synthetic-lease-accepted-application.json"
    ));
    let generated = snapshot
        .apply_control_lease_authority_review(review)
        .unwrap();

    assert_eq!(generated, expected);
    assert_eq!(expected.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn valid_lease_release_authority_audit_fixture_matches_snapshot() {
    let snapshot = fixture::<ManifoldAuthoritySnapshot>(include_str!(
        "../../../../fixtures/authority/synthetic-lease-active-authority-snapshot.json"
    ));
    let event = fixture::<ManifoldControlLeaseReleaseAuthorityAuditEvent>(include_str!(
        "../../../../fixtures/audit/synthetic-lease-release-accepted-event.json"
    ));

    assert_eq!(snapshot.validate_authority_links(), Ok(()));
    assert_eq!(event.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn valid_lease_release_authority_review_fixture_matches_evaluator() {
    let snapshot = fixture::<ManifoldAuthoritySnapshot>(include_str!(
        "../../../../fixtures/authority/synthetic-lease-active-authority-snapshot.json"
    ));
    let request = fixture::<ManifoldControlLeaseReleaseRequest>(include_str!(
        "../../../../fixtures/command/synthetic-lease-release-request.json"
    ));
    let clock = fixture::<ManifoldClockSnapshot>(include_str!(
        "../../../../fixtures/clock/synthetic-command-review-clock.json"
    ));
    let expected = fixture::<ManifoldControlLeaseReleaseAuthorityReview>(include_str!(
        "../../../../fixtures/lease-release-review/synthetic-lease-release-accepted-review.json"
    ));
    let generated = snapshot
        .review_control_lease_release(
            request,
            clock,
            vec![DottedId::new(
                "evidence.lease_release_authority.request.lease_release.synthetic_lease_1",
            )
            .unwrap()],
        )
        .unwrap();

    assert_eq!(generated, expected);
    assert_eq!(expected.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn valid_lease_release_authority_application_fixture_matches_evaluator() {
    let snapshot = fixture::<ManifoldAuthoritySnapshot>(include_str!(
        "../../../../fixtures/authority/synthetic-lease-active-authority-snapshot.json"
    ));
    let review = fixture::<ManifoldControlLeaseReleaseAuthorityReview>(include_str!(
        "../../../../fixtures/lease-release-review/synthetic-lease-release-accepted-review.json"
    ));
    let expected = fixture::<ManifoldControlLeaseReleaseAuthorityApplication>(include_str!(
            "../../../../fixtures/authority-application/synthetic-lease-release-accepted-application.json"
        ));
    let generated = snapshot
        .apply_control_lease_release_authority_review(review)
        .unwrap();

    assert_eq!(generated, expected);
    assert_eq!(expected.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn valid_lease_renewal_authority_audit_fixture_matches_snapshot() {
    let snapshot = fixture::<ManifoldAuthoritySnapshot>(include_str!(
        "../../../../fixtures/authority/synthetic-lease-active-authority-snapshot.json"
    ));
    let event = fixture::<ManifoldControlLeaseRenewalAuthorityAuditEvent>(include_str!(
        "../../../../fixtures/audit/synthetic-lease-renewal-accepted-event.json"
    ));

    assert_eq!(snapshot.validate_authority_links(), Ok(()));
    assert_eq!(event.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn valid_lease_renewal_authority_review_fixture_matches_evaluator() {
    let snapshot = fixture::<ManifoldAuthoritySnapshot>(include_str!(
        "../../../../fixtures/authority/synthetic-lease-active-authority-snapshot.json"
    ));
    let request = fixture::<ManifoldControlLeaseRenewalRequest>(include_str!(
        "../../../../fixtures/command/synthetic-lease-renewal-request.json"
    ));
    let clock = fixture::<ManifoldClockSnapshot>(include_str!(
        "../../../../fixtures/clock/synthetic-command-review-clock.json"
    ));
    let expected = fixture::<ManifoldControlLeaseRenewalAuthorityReview>(include_str!(
        "../../../../fixtures/lease-renewal-review/synthetic-lease-renewal-accepted-review.json"
    ));
    let generated = snapshot
        .review_control_lease_renewal(
            request,
            clock,
            vec![DottedId::new(
                "evidence.lease_renewal_authority.request.lease_renewal.synthetic_lease_1",
            )
            .unwrap()],
        )
        .unwrap();

    assert_eq!(generated, expected);
    assert_eq!(expected.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn valid_lease_renewal_authority_application_fixture_matches_evaluator() {
    let snapshot = fixture::<ManifoldAuthoritySnapshot>(include_str!(
        "../../../../fixtures/authority/synthetic-lease-active-authority-snapshot.json"
    ));
    let review = fixture::<ManifoldControlLeaseRenewalAuthorityReview>(include_str!(
        "../../../../fixtures/lease-renewal-review/synthetic-lease-renewal-accepted-review.json"
    ));
    let expected = fixture::<ManifoldControlLeaseRenewalAuthorityApplication>(include_str!(
            "../../../../fixtures/authority-application/synthetic-lease-renewal-accepted-application.json"
        ));
    let generated = snapshot
        .apply_control_lease_renewal_authority_review(review)
        .unwrap();

    assert_eq!(generated, expected);
    assert_eq!(expected.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn valid_stream_registry_authority_audit_fixture_matches_snapshot() {
    let snapshot = fixture::<ManifoldAuthoritySnapshot>(include_str!(
        "../../../../fixtures/authority/synthetic-authority-snapshot.json"
    ));
    let event = fixture::<ManifoldStreamRegistryAuthorityAuditEvent>(include_str!(
        "../../../../fixtures/audit/synthetic-stream-registry-accepted-event.json"
    ));

    assert_eq!(snapshot.validate_authority_links(), Ok(()));
    assert_eq!(event.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn valid_stream_registry_authority_review_fixture_matches_evaluator() {
    let snapshot = fixture::<ManifoldAuthoritySnapshot>(include_str!(
        "../../../../fixtures/authority/synthetic-authority-snapshot.json"
    ));
    let request = fixture::<ManifoldStreamRegistryChangeRequest>(include_str!(
        "../../../../fixtures/stream/synthetic-stream-registry-change-request.json"
    ));
    let clock = fixture::<ManifoldClockSnapshot>(include_str!(
        "../../../../fixtures/clock/synthetic-command-review-clock.json"
    ));
    let expected = fixture::<ManifoldStreamRegistryAuthorityReview>(include_str!(
            "../../../../fixtures/stream-registry-review/synthetic-stream-registry-accepted-review.json"
        ));
    let generated = snapshot
            .review_stream_registry_change(
                request,
                clock,
                vec![DottedId::new(
                    "evidence.stream_registry_authority.request.stream_registry.synthetic_wave_subscription",
                )
                .unwrap()],
            )
            .unwrap();

    assert_eq!(generated, expected);
    assert_eq!(expected.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn valid_stream_registry_authority_application_fixture_matches_evaluator() {
    let snapshot = fixture::<ManifoldAuthoritySnapshot>(include_str!(
        "../../../../fixtures/authority/synthetic-authority-snapshot.json"
    ));
    let review = fixture::<ManifoldStreamRegistryAuthorityReview>(include_str!(
            "../../../../fixtures/stream-registry-review/synthetic-stream-registry-accepted-review.json"
        ));
    let expected = fixture::<ManifoldStreamRegistryAuthorityApplication>(include_str!(
            "../../../../fixtures/authority-application/synthetic-stream-registry-accepted-application.json"
        ));
    let generated = snapshot
        .apply_stream_registry_authority_review(review)
        .unwrap();

    assert_eq!(generated, expected);
    assert_eq!(expected.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn valid_stream_subscription_renewal_authority_audit_fixture_matches_snapshot() {
    let snapshot = fixture::<ManifoldAuthoritySnapshot>(include_str!(
            "../../../../fixtures/authority/synthetic-stream-subscription-active-authority-snapshot.json"
        ));
    let event = fixture::<ManifoldStreamSubscriptionRenewalAuthorityAuditEvent>(include_str!(
        "../../../../fixtures/audit/synthetic-stream-subscription-renewal-accepted-event.json"
    ));

    assert_eq!(snapshot.validate_authority_links(), Ok(()));
    assert_eq!(event.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn valid_stream_subscription_renewal_authority_review_fixture_matches_evaluator() {
    let snapshot = fixture::<ManifoldAuthoritySnapshot>(include_str!(
            "../../../../fixtures/authority/synthetic-stream-subscription-active-authority-snapshot.json"
        ));
    let request = fixture::<ManifoldStreamSubscriptionRenewalRequest>(include_str!(
            "../../../../fixtures/stream-subscription/synthetic-stream-subscription-renewal-request.json"
        ));
    let clock = fixture::<ManifoldClockSnapshot>(include_str!(
        "../../../../fixtures/clock/synthetic-command-review-clock.json"
    ));
    let expected = fixture::<ManifoldStreamSubscriptionRenewalAuthorityReview>(include_str!(
            "../../../../fixtures/stream-subscription-renewal-review/synthetic-stream-subscription-renewal-accepted-review.json"
        ));
    let generated = snapshot
            .review_stream_subscription_renewal(
                request,
                clock,
                vec![DottedId::new(
                    "evidence.stream_subscription_renewal_authority.request.stream_subscription_renewal.synthetic_wave_ui",
                )
                .unwrap()],
            )
            .unwrap();

    assert_eq!(generated, expected);
    assert_eq!(expected.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn valid_stream_subscription_renewal_authority_application_fixture_matches_evaluator() {
    let snapshot = fixture::<ManifoldAuthoritySnapshot>(include_str!(
            "../../../../fixtures/authority/synthetic-stream-subscription-active-authority-snapshot.json"
        ));
    let review = fixture::<ManifoldStreamSubscriptionRenewalAuthorityReview>(include_str!(
            "../../../../fixtures/stream-subscription-renewal-review/synthetic-stream-subscription-renewal-accepted-review.json"
        ));
    let expected =
            fixture::<ManifoldStreamSubscriptionRenewalAuthorityApplication>(include_str!(
                "../../../../fixtures/authority-application/synthetic-stream-subscription-renewal-accepted-application.json"
            ));
    let generated = snapshot
        .apply_stream_subscription_renewal_authority_review(review)
        .unwrap();

    assert_eq!(generated, expected);
    assert_eq!(expected.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn valid_authority_expiry_sweep_authority_audit_fixture_matches_snapshot() {
    let snapshot = fixture::<ManifoldAuthoritySnapshot>(include_str!(
            "../../../../fixtures/authority/synthetic-stream-subscription-active-authority-snapshot.json"
        ));
    let event = fixture::<ManifoldAuthorityExpirySweepAuthorityAuditEvent>(include_str!(
        "../../../../fixtures/audit/synthetic-authority-expiry-sweep-accepted-event.json"
    ));

    assert_eq!(snapshot.validate_authority_links(), Ok(()));
    assert_eq!(event.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn valid_authority_expiry_sweep_authority_review_fixture_matches_evaluator() {
    let snapshot = fixture::<ManifoldAuthoritySnapshot>(include_str!(
            "../../../../fixtures/authority/synthetic-stream-subscription-active-authority-snapshot.json"
        ));
    let request = fixture::<ManifoldAuthorityExpirySweepRequest>(include_str!(
        "../../../../fixtures/authority-expiry/synthetic-authority-expiry-sweep-request.json"
    ));
    let clock = fixture::<ManifoldClockSnapshot>(include_str!(
        "../../../../fixtures/clock/synthetic-expired-command-review-clock.json"
    ));
    let expected = fixture::<ManifoldAuthorityExpirySweepAuthorityReview>(include_str!(
            "../../../../fixtures/authority-expiry-review/synthetic-authority-expiry-sweep-accepted-review.json"
        ));
    let generated = snapshot
        .review_authority_expiry_sweep(
            request,
            clock,
            vec![
                DottedId::new("evidence.expiry_sweep_authority.request.expiry_sweep.synthetic")
                    .unwrap(),
            ],
        )
        .unwrap();

    assert_eq!(generated, expected);
    assert_eq!(expected.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn valid_authority_expiry_sweep_authority_application_fixture_matches_evaluator() {
    let snapshot = fixture::<ManifoldAuthoritySnapshot>(include_str!(
            "../../../../fixtures/authority/synthetic-stream-subscription-active-authority-snapshot.json"
        ));
    let accepted_review = fixture::<ManifoldAuthorityExpirySweepAuthorityReview>(include_str!(
            "../../../../fixtures/authority-expiry-review/synthetic-authority-expiry-sweep-accepted-review.json"
        ));
    let rejected_review = fixture::<ManifoldAuthorityExpirySweepAuthorityReview>(include_str!(
            "../../../../fixtures/authority-expiry-review/synthetic-authority-expiry-sweep-stale-revision-review.json"
        ));
    let expected_accepted =
            fixture::<ManifoldAuthorityExpirySweepAuthorityApplication>(include_str!(
                "../../../../fixtures/authority-application/synthetic-authority-expiry-sweep-accepted-application.json"
            ));
    let expected_rejected =
            fixture::<ManifoldAuthorityExpirySweepAuthorityApplication>(include_str!(
                "../../../../fixtures/authority-application/synthetic-authority-expiry-sweep-rejected-application.json"
            ));
    let generated_accepted = snapshot
        .apply_authority_expiry_sweep_review(accepted_review)
        .unwrap();
    let generated_rejected = snapshot
        .apply_authority_expiry_sweep_review(rejected_review)
        .unwrap();

    assert_eq!(generated_accepted, expected_accepted);
    assert_eq!(generated_rejected, expected_rejected);
    assert_eq!(
        expected_accepted.validate_against_snapshot(&snapshot),
        Ok(())
    );
    assert_eq!(
        expected_rejected.validate_against_snapshot(&snapshot),
        Ok(())
    );
}

#[test]
fn valid_module_runtime_state_authority_audit_fixture_matches_snapshot() {
    let snapshot = fixture::<ManifoldAuthoritySnapshot>(include_str!(
        "../../../../fixtures/authority/synthetic-authority-snapshot.json"
    ));
    let event = fixture::<ManifoldModuleRuntimeStateAuthorityAuditEvent>(include_str!(
        "../../../../fixtures/audit/synthetic-module-runtime-state-accepted-event.json"
    ));

    assert_eq!(snapshot.validate_authority_links(), Ok(()));
    assert_eq!(event.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn valid_module_runtime_state_authority_review_fixture_matches_evaluator() {
    let snapshot = fixture::<ManifoldAuthoritySnapshot>(include_str!(
        "../../../../fixtures/authority/synthetic-authority-snapshot.json"
    ));
    let request = fixture::<ManifoldModuleRuntimeStateChangeRequest>(include_str!(
        "../../../../fixtures/module/synthetic-runtime-state-change-request.json"
    ));
    let clock = fixture::<ManifoldClockSnapshot>(include_str!(
        "../../../../fixtures/clock/synthetic-command-review-clock.json"
    ));
    let expected = fixture::<ManifoldModuleRuntimeStateAuthorityReview>(include_str!(
        "../../../../fixtures/module-runtime-review/synthetic-module-runtime-accepted-review.json"
    ));
    let generated = snapshot
            .review_module_runtime_state_change(
                request,
                clock,
                vec![DottedId::new(
                    "evidence.module_runtime_state_authority.request.module_runtime.stop.synthetic_wave_provider",
                )
                .unwrap()],
            )
            .unwrap();

    assert_eq!(generated, expected);
    assert_eq!(expected.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn valid_module_runtime_state_authority_application_fixture_matches_evaluator() {
    let snapshot = fixture::<ManifoldAuthoritySnapshot>(include_str!(
        "../../../../fixtures/authority/synthetic-authority-snapshot.json"
    ));
    let review = fixture::<ManifoldModuleRuntimeStateAuthorityReview>(include_str!(
        "../../../../fixtures/module-runtime-review/synthetic-module-runtime-accepted-review.json"
    ));
    let expected = fixture::<ManifoldModuleRuntimeStateAuthorityApplication>(include_str!(
            "../../../../fixtures/authority-application/synthetic-module-runtime-accepted-application.json"
        ));
    let generated = snapshot
        .apply_module_runtime_state_authority_review(review)
        .unwrap();

    assert_eq!(generated, expected);
    assert_eq!(expected.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn valid_host_manifest_authority_review_fixture_matches_evaluator() {
    let snapshot = fixture::<ManifoldAuthoritySnapshot>(include_str!(
        "../../../../fixtures/authority/synthetic-authority-snapshot.json"
    ));
    let request = fixture::<ManifoldHostManifestChangeRequest>(include_str!(
        "../../../../fixtures/host/synthetic-host-manifest-change-request.json"
    ));
    let clock = fixture::<ManifoldClockSnapshot>(include_str!(
        "../../../../fixtures/clock/synthetic-command-review-clock.json"
    ));
    let expected = fixture::<ManifoldHostManifestAuthorityReview>(include_str!(
        "../../../../fixtures/host-manifest-review/synthetic-host-manifest-accepted-review.json"
    ));
    let generated = snapshot
        .review_host_manifest_change(
            request,
            clock,
            vec![DottedId::new(
                "evidence.host_manifest_authority.request.host_manifest.synthetic_permissions",
            )
            .unwrap()],
        )
        .unwrap();

    assert_eq!(generated, expected);
    assert_eq!(expected.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn valid_host_manifest_authority_application_fixture_matches_evaluator() {
    let snapshot = fixture::<ManifoldAuthoritySnapshot>(include_str!(
        "../../../../fixtures/authority/synthetic-authority-snapshot.json"
    ));
    let review = fixture::<ManifoldHostManifestAuthorityReview>(include_str!(
        "../../../../fixtures/host-manifest-review/synthetic-host-manifest-accepted-review.json"
    ));
    let expected = fixture::<ManifoldHostManifestAuthorityApplication>(include_str!(
            "../../../../fixtures/authority-application/synthetic-host-manifest-accepted-application.json"
        ));
    let generated = snapshot
        .apply_host_manifest_authority_review(review)
        .unwrap();

    assert_eq!(generated, expected);
    assert_eq!(expected.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn valid_clock_snapshot_authority_review_fixture_matches_evaluator() {
    let snapshot = fixture::<ManifoldAuthoritySnapshot>(include_str!(
        "../../../../fixtures/authority/synthetic-authority-snapshot.json"
    ));
    let request = fixture::<ManifoldClockSnapshotChangeRequest>(include_str!(
        "../../../../fixtures/clock/synthetic-clock-change-request.json"
    ));
    let clock = fixture::<ManifoldClockSnapshot>(include_str!(
        "../../../../fixtures/clock/synthetic-command-review-clock.json"
    ));
    let expected = fixture::<ManifoldClockSnapshotAuthorityReview>(include_str!(
        "../../../../fixtures/clock-review/synthetic-clock-accepted-review.json"
    ));
    let generated = snapshot
        .review_clock_snapshot_change(
            request,
            clock,
            vec![
                DottedId::new("evidence.clock_snapshot_authority.request.clock.synthetic_tick")
                    .unwrap(),
            ],
        )
        .unwrap();

    assert_eq!(generated, expected);
    assert_eq!(expected.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn valid_clock_snapshot_authority_application_fixture_matches_evaluator() {
    let snapshot = fixture::<ManifoldAuthoritySnapshot>(include_str!(
        "../../../../fixtures/authority/synthetic-authority-snapshot.json"
    ));
    let review = fixture::<ManifoldClockSnapshotAuthorityReview>(include_str!(
        "../../../../fixtures/clock-review/synthetic-clock-accepted-review.json"
    ));
    let expected = fixture::<ManifoldClockSnapshotAuthorityApplication>(include_str!(
        "../../../../fixtures/authority-application/synthetic-clock-accepted-application.json"
    ));
    let generated = snapshot
        .apply_clock_snapshot_authority_review(review)
        .unwrap();

    assert_eq!(generated, expected);
    assert_eq!(expected.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn damaged_bad_timestamp_domain_fixture_rejects_invalid_id() {
    let result = serde_json::from_str::<ManifoldStreamManifest>(include_str!(
        "../../../../fixtures/damaged/bad-timestamp-domain.json"
    ));

    assert!(result.is_err());
}

#[test]
fn damaged_unknown_module_link_fixture_rejects_registry_topology() {
    let snapshot = fixture::<ManifoldStreamRegistrySnapshot>(include_str!(
        "../../../../fixtures/damaged/unknown-module-link.json"
    ));
    let error = snapshot
        .validate_source_modules(&[DottedId::new("module.synthetic_wave_provider").unwrap()])
        .unwrap_err();

    assert_eq!(error.rejection_code(), "unknown_module_link");
}

#[test]
fn damaged_shell_handoff_fixture_rejects_missing_stream() {
    let handoff = fixture::<ManifoldShellHandoffManifest>(include_str!(
        "../../../../fixtures/damaged/shell-handoff-missing-stream.json"
    ));
    let registry = fixture::<ManifoldStreamRegistrySnapshot>(include_str!(
        "../../../../fixtures/stream/synthetic-stream-registry.json"
    ));
    let error = handoff
        .validate_links(
            &registry,
            &[
                DottedId::new("command.module.start").unwrap(),
                DottedId::new("command.module.stop").unwrap(),
            ],
            &[DottedId::new("endpoint.headset_loopback").unwrap()],
            &[DottedId::new("host_run.slot.synthetic_smoke").unwrap()],
        )
        .unwrap_err();

    assert_eq!(error.rejection_code(), "unknown_stream");
}

#[test]
fn valid_shell_handoff_review_fixture_matches_handoff() {
    let handoff = fixture::<ManifoldShellHandoffManifest>(include_str!(
        "../../../../fixtures/shell-handoff/synthetic-loopback-shell.json"
    ));
    let receipt = fixture::<ManifoldShellHandoffReviewReceipt>(include_str!(
        "../../../../fixtures/shell-handoff/synthetic-loopback-shell-review.json"
    ));

    assert_eq!(receipt.validate_against_handoff(&handoff), Ok(()));
}

#[test]
fn damaged_shell_handoff_review_fixture_rejects_runtime_started() {
    let handoff = fixture::<ManifoldShellHandoffManifest>(include_str!(
        "../../../../fixtures/shell-handoff/synthetic-loopback-shell.json"
    ));
    let receipt = fixture::<ManifoldShellHandoffReviewReceipt>(include_str!(
        "../../../../fixtures/damaged/shell-handoff-review-runtime-started.json"
    ));
    let error = receipt.validate_against_handoff(&handoff).unwrap_err();

    assert_eq!(error.rejection_code(), "runtime_started");
}
