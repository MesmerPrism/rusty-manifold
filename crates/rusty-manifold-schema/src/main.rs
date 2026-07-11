//! Deterministic schema catalog export CLI.

use std::env;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde::Serialize;

fn main() -> ExitCode {
    match run(env::args().skip(1).collect()) {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Vec<String>) -> Result<String, CliError> {
    let options = Options::parse(args)?;
    let catalog = SchemaCatalog::current();
    let output = serde_json::to_string_pretty(&catalog).map_err(CliError::Serialize)?;
    let schema_path = options.repo_root.join("schemas/catalog.json");

    if options.check {
        let existing = fs::read_to_string(&schema_path).map_err(|source| CliError::Io {
            path: schema_path.clone(),
            source,
        })?;
        if existing.trim_end() == output.trim_end() {
            Ok("schema catalog matches".to_owned())
        } else {
            Err(CliError::CatalogMismatch {
                schema_path,
                output,
            })
        }
    } else {
        fs::write(&schema_path, format!("{output}\n")).map_err(|source| CliError::Io {
            path: schema_path.clone(),
            source,
        })?;
        Ok(format!("wrote {}", schema_path.display()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Options {
    repo_root: PathBuf,
    check: bool,
}

impl Options {
    fn parse(args: Vec<String>) -> Result<Self, CliError> {
        let mut args = args.into_iter();
        let Some(command) = args.next() else {
            return Err(CliError::Usage(usage()));
        };
        if command != "export" {
            return Err(CliError::Usage(usage()));
        }

        let mut repo_root = default_repo_root();
        let mut check = false;
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--check" => check = true,
                "--repo-root" => {
                    let Some(value) = args.next() else {
                        return Err(CliError::Usage("--repo-root requires a value".to_owned()));
                    };
                    repo_root = PathBuf::from(value);
                }
                "-h" | "--help" => return Err(CliError::Usage(usage())),
                other => return Err(CliError::UnknownOption(other.to_owned())),
            }
        }

        Ok(Self { repo_root, check })
    }
}

#[derive(Serialize)]
struct SchemaCatalog {
    #[serde(rename = "$schema")]
    schema_id: &'static str,
    version: u32,
    entries: Vec<SchemaEntry>,
}

impl SchemaCatalog {
    fn current() -> Self {
        Self {
            schema_id: "rusty.manifold.schema.catalog.v1",
            version: 1,
            entries: schema_entries(),
        }
    }
}

fn schema_entries() -> Vec<SchemaEntry> {
    let mut entries = Vec::new();
    entries.extend(package_and_graph_entries());
    entries.extend(module_and_stream_entries());
    entries.extend(command_entries());
    entries.extend(coordination_entries());
    entries.extend(peer_entries());
    entries.extend(runtime_host_entries());
    entries.extend(authority_entries());
    entries.extend(bridge_route_entries());
    entries.extend(host_and_deployment_entries());
    entries.extend(verification_entries());
    entries
}

fn runtime_host_entries() -> Vec<SchemaEntry> {
    vec![
        entry(
            "rusty.manifold.runtime_host.snapshot.v1",
            "ManifoldRuntimeHostSnapshot",
            &[
                "fixtures/runtime-host/synthetic-runtime-host-snapshot.json",
                "fixtures/runtime-host/synthetic-runtime-host-restarted-snapshot.json",
            ],
        ),
        entry(
            "rusty.manifold.runtime_host.command_request.v1",
            "ManifoldRuntimeCommandRequest",
            &[
                "fixtures/runtime-host/synthetic-runtime-command-request.json",
                "fixtures/damaged/runtime-host-unknown-command.json",
                "fixtures/damaged/runtime-host-missing-lease.json",
                "fixtures/damaged/runtime-host-expired-lease.json",
            ],
        ),
        entry(
            "rusty.manifold.runtime_host.dispatch_receipt.v1",
            "ManifoldRuntimeDispatchReceipt",
            &["fixtures/runtime-host/synthetic-runtime-dispatch-receipt.json"],
        ),
        entry(
            "rusty.manifold.runtime_host.application_receipt.v1",
            "ManifoldRuntimeApplicationReceipt",
            &["fixtures/runtime-host/synthetic-runtime-application-receipt.json"],
        ),
        entry(
            "rusty.manifold.runtime_host.lease_expiry_receipt.v1",
            "ManifoldRuntimeLeaseExpiryReceipt",
            &["fixtures/runtime-host/synthetic-runtime-lease-expiry-receipt.json"],
        ),
        entry(
            "rusty.manifold.runtime_host.audit_event.v1",
            "ManifoldRuntimeAuditEvent",
            &["fixtures/runtime-host/synthetic-runtime-audit-event.json"],
        ),
    ]
}

fn peer_entries() -> Vec<SchemaEntry> {
    vec![
        entry(
            "rusty.manifold.peer.identity.v1",
            "ManifoldPeerIdentity",
            &["fixtures/peer/synthetic-peer-identity.json"],
        ),
        entry(
            "rusty.manifold.peer.status.v1",
            "ManifoldPeerStatus",
            &["fixtures/peer/synthetic-peer-status.json"],
        ),
        entry(
            "rusty.manifold.peer.status_proposal.v1",
            "ManifoldPeerStatusProposal",
            &["fixtures/peer/synthetic-peer-proposal.json"],
        ),
        entry(
            "rusty.manifold.peer.accepted_state.v1",
            "ManifoldAcceptedPeerState",
            &["fixtures/peer/synthetic-peer-accepted-state.json"],
        ),
        entry(
            "rusty.manifold.peer.review_case.v1",
            "ManifoldPeerReviewCase",
            &[
                "fixtures/peer-review/synthetic-peer-accepted-review.json",
                "fixtures/damaged/peer-status-stale-authority.json",
                "fixtures/damaged/peer-status-replayed-proposal.json",
                "fixtures/damaged/peer-status-untrusted-identity.json",
                "fixtures/damaged/peer-status-stale-observation.json",
                "fixtures/damaged/peer-status-high-rate-payload.json",
                "fixtures/damaged/peer-status-advisory-command.json",
                "fixtures/damaged/peer-status-role-escalation.json",
                "fixtures/damaged/peer-status-stale-status-revision.json",
            ],
        ),
        entry(
            "rusty.manifold.peer.decision.v1",
            "ManifoldPeerDecision",
            &["fixtures/peer/synthetic-peer-decision.json"],
        ),
        entry(
            "rusty.manifold.peer.rejection.v1",
            "ManifoldPeerRejection",
            &["fixtures/peer/synthetic-peer-rejection.json"],
        ),
        entry(
            "rusty.manifold.peer.audit_event.v1",
            "ManifoldPeerAuditEvent",
            &["fixtures/peer/synthetic-peer-audit-event.json"],
        ),
        entry(
            "rusty.manifold.peer.application_receipt.v1",
            "ManifoldPeerApplicationReceipt",
            &["fixtures/peer/synthetic-peer-application-receipt.json"],
        ),
    ]
}

fn package_and_graph_entries() -> Vec<SchemaEntry> {
    vec![
        entry(
            "rusty.manifold.package.manifest.v1",
            "ManifoldPackageManifest",
            &["fixtures/package/synthetic-package.json"],
        ),
        entry(
            "rusty.manifold.graph.manifest.v1",
            "ManifoldGraphManifest",
            &[
                "fixtures/graph/synthetic-wave-pipeline.json",
                "fixtures/graph/synthetic-wave-pipeline-v2.json",
            ],
        ),
        entry(
            "rusty.manifold.graph.diff.v1",
            "ManifoldGraphDiff",
            &["fixtures/diff/synthetic-contract-diff.json"],
        ),
        entry(
            "rusty.manifold.graph.execution_report.v1",
            "ManifoldGraphExecutionReport",
            &["fixtures/graph/synthetic-graph-execution-report.json"],
        ),
    ]
}

fn module_and_stream_entries() -> Vec<SchemaEntry> {
    vec![
        entry(
            "rusty.manifold.module.manifest.v1",
            "ManifoldModuleManifest",
            &[
                "fixtures/module/synthetic-wave-provider.json",
                "fixtures/module/synthetic-wave-processor.json",
            ],
        ),
        entry(
            "rusty.manifold.module.runtime_state.v1",
            "ManifoldModuleRuntimeState",
            &[
                "fixtures/module/synthetic-wave-runtime-state.json",
                "fixtures/module/synthetic-processor-runtime-state.json",
                "fixtures/module/synthetic-wave-runtime-state-v2.json",
            ],
        ),
        entry(
            "rusty.manifold.module.runtime_transition.v1",
            "ManifoldModuleRuntimeTransition",
            &[
                "fixtures/diff/synthetic-contract-diff.json",
                "fixtures/module/synthetic-runtime-state-transition.json",
            ],
        ),
        entry(
            "rusty.manifold.module.runtime_state_change_request.v1",
            "ManifoldModuleRuntimeStateChangeRequest",
            &[
                "fixtures/module/synthetic-runtime-state-change-request.json",
                "fixtures/damaged/module-runtime-request-stale-revision.json",
                "fixtures/damaged/module-runtime-request-missing-lease.json",
                "fixtures/damaged/module-runtime-request-unknown-stream.json",
                "fixtures/damaged/module-runtime-request-missing-backend.json",
            ],
        ),
        entry(
            "rusty.manifold.module.runtime_state_rejection.v1",
            "ManifoldModuleRuntimeStateRejection",
            &["fixtures/module/synthetic-runtime-state-rejection.json"],
        ),
        entry(
            "rusty.manifold.stream.manifest.v1",
            "ManifoldStreamManifest",
            &[
                "fixtures/stream/synthetic-wave-stream.json",
                "fixtures/stream/synthetic-rms-stream.json",
            ],
        ),
        entry(
            "rusty.manifold.stream.registry_snapshot.v1",
            "ManifoldStreamRegistrySnapshot",
            &[
                "fixtures/stream/synthetic-stream-registry.json",
                "fixtures/stream/synthetic-stream-registry-v2.json",
            ],
        ),
        entry(
            "rusty.manifold.stream.registry_diff.v1",
            "ManifoldStreamRegistryDiff",
            &[
                "fixtures/diff/synthetic-contract-diff.json",
                "fixtures/stream/synthetic-stream-registry-diff.json",
            ],
        ),
        entry(
            "rusty.manifold.stream.registry_change_request.v1",
            "ManifoldStreamRegistryChangeRequest",
            &[
                "fixtures/stream/synthetic-stream-registry-change-request.json",
                "fixtures/damaged/stream-registry-request-stale-revision.json",
                "fixtures/damaged/stream-registry-request-missing-lease.json",
                "fixtures/damaged/stream-registry-request-remove-active-stream.json",
                "fixtures/damaged/stream-registry-request-remove-active-transport.json",
                "fixtures/damaged/stream-registry-request-disable-active-ui-subscriptions.json",
                "fixtures/damaged/stream-registry-request-lower-active-subscriber-limit.json",
                "fixtures/damaged/stream-registry-request-unknown-module.json",
                "fixtures/damaged/stream-registry-request-unknown-endpoint.json",
            ],
        ),
        entry(
            "rusty.manifold.stream.registry_rejection.v1",
            "ManifoldStreamRegistryRejection",
            &["fixtures/stream/synthetic-stream-registry-rejection.json"],
        ),
        entry(
            "rusty.manifold.synthetic.scalar_oscillator_profile.v1",
            "ManifoldSyntheticScalarOscillatorProfile",
            &["fixtures/synthetic/synthetic-scalar-oscillator-profile.json"],
        ),
        entry(
            "rusty.manifold.sample.scalar_f32.v1",
            "ManifoldScalarF32Sample",
            &["fixtures/synthetic/synthetic-scalar-oscillator-samples.jsonl"],
        ),
        entry(
            "rusty.manifold.stream.subscription_request.v1",
            "ManifoldStreamSubscriptionRequest",
            &[
                "fixtures/stream-subscription/synthetic-stream-subscription-request.json",
                "fixtures/damaged/stream-subscription-request-zero-ttl.json",
                "fixtures/damaged/stream-subscription-request-missing-capability.json",
                "fixtures/damaged/stream-subscription-request-stale-revision.json",
                "fixtures/damaged/stream-subscription-request-stale-registry.json",
                "fixtures/damaged/stream-subscription-request-unknown-stream.json",
                "fixtures/damaged/stream-subscription-request-unknown-transport.json",
                "fixtures/damaged/stream-subscription-request-subscriber-limit.json",
                "fixtures/damaged/stream-subscription-request-ui-disabled.json",
            ],
        ),
        entry(
            "rusty.manifold.stream.subscription.v1",
            "ManifoldStreamSubscription",
            &["fixtures/stream-subscription/synthetic-stream-subscription.json"],
        ),
        entry(
            "rusty.manifold.stream.subscription_rejection.v1",
            "ManifoldStreamSubscriptionRejection",
            &["fixtures/stream-subscription/synthetic-stream-subscription-rejection.json"],
        ),
        entry(
            "rusty.manifold.stream.subscription_release_request.v1",
            "ManifoldStreamSubscriptionReleaseRequest",
            &[
                "fixtures/stream-subscription/synthetic-stream-subscription-release-request.json",
                "fixtures/damaged/stream-subscription-release-request-stale-revision.json",
                "fixtures/damaged/stream-subscription-release-request-stale-registry.json",
                "fixtures/damaged/stream-subscription-release-request-unknown-subscription.json",
                "fixtures/damaged/stream-subscription-release-request-subscriber-mismatch.json",
                "fixtures/damaged/stream-subscription-release-request-stream-mismatch.json",
            ],
        ),
        entry(
            "rusty.manifold.stream.subscription_release_rejection.v1",
            "ManifoldStreamSubscriptionReleaseRejection",
            &["fixtures/stream-subscription/synthetic-stream-subscription-release-rejection.json"],
        ),
        entry(
            "rusty.manifold.stream.subscription_renewal_request.v1",
            "ManifoldStreamSubscriptionRenewalRequest",
            &[
                "fixtures/stream-subscription/synthetic-stream-subscription-renewal-request.json",
                "fixtures/damaged/stream-subscription-renewal-request-stale-revision.json",
                "fixtures/damaged/stream-subscription-renewal-request-stale-registry.json",
                "fixtures/damaged/stream-subscription-renewal-request-unknown-subscription.json",
                "fixtures/damaged/stream-subscription-renewal-request-subscriber-mismatch.json",
                "fixtures/damaged/stream-subscription-renewal-request-stream-mismatch.json",
                "fixtures/damaged/stream-subscription-renewal-request-transport-mismatch.json",
                "fixtures/damaged/stream-subscription-renewal-request-zero-ttl.json",
                "fixtures/damaged/stream-subscription-renewal-request-non-extending.json",
            ],
        ),
        entry(
            "rusty.manifold.stream.subscription_renewal_rejection.v1",
            "ManifoldStreamSubscriptionRenewalRejection",
            &["fixtures/stream-subscription/synthetic-stream-subscription-renewal-rejection.json"],
        ),
    ]
}

fn command_entries() -> Vec<SchemaEntry> {
    vec![
        entry(
            "rusty.manifold.command.descriptor.v1",
            "ManifoldCommandDescriptor",
            &[
                "fixtures/command/synthetic-command-descriptor.json",
                "fixtures/command/remote-camera-start-receiver-descriptor.json",
                "fixtures/command/remote-camera-start-sender-descriptor.json",
                "fixtures/command/remote-camera-get-status-descriptor.json",
                "fixtures/command/remote-camera-stop-descriptor.json",
            ],
        ),
        entry(
            "rusty.manifold.command.envelope.v1",
            "ManifoldCommandEnvelope",
            &[
                "fixtures/command/synthetic-command-envelope.json",
                "fixtures/command/remote-camera-start-receiver-envelope.json",
                "fixtures/command/remote-camera-start-sender-envelope.json",
                "fixtures/command/remote-camera-get-status-envelope.json",
                "fixtures/command/remote-camera-stop-envelope.json",
                "fixtures/damaged/stale-revision-command.json",
                "fixtures/damaged/missing-lease-scope-command.json",
                "fixtures/damaged/authority-review-unknown-command.json",
                "fixtures/damaged/authority-review-unknown-lease-command.json",
                "fixtures/damaged/authority-review-capability-mismatch-command.json",
            ],
        ),
        entry(
            "rusty.manifold.command.ack.v1",
            "ManifoldCommandAck",
            &["fixtures/command/synthetic-command-ack.json"],
        ),
        entry(
            "rusty.manifold.command.rejection.v1",
            "ManifoldCommandRejection",
            &["fixtures/command/synthetic-command-rejection.json"],
        ),
        entry(
            "rusty.manifold.command.lease_request.v1",
            "ManifoldControlLeaseRequest",
            &[
                "fixtures/command/synthetic-lease-request.json",
                "fixtures/damaged/lease-request-stale-revision.json",
                "fixtures/damaged/lease-request-zero-ttl.json",
                "fixtures/damaged/lease-request-missing-capability.json",
                "fixtures/damaged/lease-request-busy-scope.json",
            ],
        ),
        entry(
            "rusty.manifold.command.control_lease.v1",
            "ManifoldControlLease",
            &[
                "fixtures/command/synthetic-control-lease.json",
                "fixtures/command/synthetic-stream-registry-lease.json",
                "fixtures/command/synthetic-host-manifest-lease.json",
                "fixtures/command/synthetic-clock-lease.json",
            ],
        ),
        entry(
            "rusty.manifold.command.lease_rejection.v1",
            "ManifoldControlLeaseRejection",
            &["fixtures/command/synthetic-lease-rejection.json"],
        ),
        entry(
            "rusty.manifold.command.lease_release_request.v1",
            "ManifoldControlLeaseReleaseRequest",
            &[
                "fixtures/command/synthetic-lease-release-request.json",
                "fixtures/damaged/lease-release-request-stale-revision.json",
                "fixtures/damaged/lease-release-request-unknown-lease.json",
                "fixtures/damaged/lease-release-request-holder-mismatch.json",
                "fixtures/damaged/lease-release-request-scope-mismatch.json",
            ],
        ),
        entry(
            "rusty.manifold.command.lease_release_rejection.v1",
            "ManifoldControlLeaseReleaseRejection",
            &["fixtures/command/synthetic-lease-release-rejection.json"],
        ),
        entry(
            "rusty.manifold.command.lease_renewal_request.v1",
            "ManifoldControlLeaseRenewalRequest",
            &[
                "fixtures/command/synthetic-lease-renewal-request.json",
                "fixtures/damaged/lease-renewal-request-stale-revision.json",
                "fixtures/damaged/lease-renewal-request-unknown-lease.json",
                "fixtures/damaged/lease-renewal-request-holder-mismatch.json",
                "fixtures/damaged/lease-renewal-request-scope-mismatch.json",
                "fixtures/damaged/lease-renewal-request-zero-ttl.json",
                "fixtures/damaged/lease-renewal-request-non-extending.json",
            ],
        ),
        entry(
            "rusty.manifold.command.lease_renewal_rejection.v1",
            "ManifoldControlLeaseRenewalRejection",
            &["fixtures/command/synthetic-lease-renewal-rejection.json"],
        ),
    ]
}

fn coordination_entries() -> Vec<SchemaEntry> {
    vec![
        entry(
            "rusty.manifold.coordination.session_plan.v1",
            "ManifoldCoordinationSessionPlan",
            &[
                "fixtures/coordination/remote-camera-q2q-lan-plan.json",
                "fixtures/coordination/remote-camera-quest-phone-lan-plan.json",
                "fixtures/coordination/remote-camera-remote-relay-two-way-plan.json",
            ],
        ),
        entry(
            "rusty.manifold.coordination.message_log.v1",
            "ManifoldCoordinationMessageLog",
            &[
                "fixtures/coordination/remote-camera-q2q-lan-messages.json",
                "fixtures/coordination/remote-camera-quest-phone-lan-messages.json",
                "fixtures/coordination/remote-camera-remote-relay-two-way-messages.json",
            ],
        ),
        entry(
            "rusty.manifold.coordination.message.v1",
            "ManifoldCoordinationMessage",
            &[
                "fixtures/coordination/remote-camera-q2q-lan-messages.json",
                "fixtures/coordination/remote-camera-quest-phone-lan-messages.json",
                "fixtures/coordination/remote-camera-remote-relay-two-way-messages.json",
            ],
        ),
        entry(
            "rusty.manifold.coordination.scorecard.v1",
            "ManifoldCoordinationScorecard",
            &[
                "fixtures/coordination/remote-camera-q2q-lan-scorecard.json",
                "fixtures/coordination/remote-camera-quest-phone-lan-scorecard.json",
                "fixtures/coordination/remote-camera-remote-relay-two-way-scorecard.json",
            ],
        ),
    ]
}

fn authority_entries() -> Vec<SchemaEntry> {
    vec![
        entry(
            "rusty.manifold.authority.snapshot.v1",
            "ManifoldAuthoritySnapshot",
            &[
                "fixtures/authority/synthetic-authority-snapshot.json",
                "fixtures/authority/synthetic-authority-snapshot-v2.json",
                "fixtures/authority/synthetic-lease-active-authority-snapshot.json",
                "fixtures/authority/synthetic-stream-subscription-authority-snapshot.json",
                "fixtures/authority/synthetic-stream-subscription-active-authority-snapshot.json",
                "fixtures/authority/synthetic-stream-subscription-limit-authority-snapshot.json",
                "fixtures/authority/synthetic-stream-subscription-ui-disabled-authority-snapshot.json",
                "fixtures/authority/remote-camera-q2q-authority-snapshot.json",
            ],
        ),
        entry(
            "rusty.manifold.authority.expiry_sweep_request.v1",
            "ManifoldAuthorityExpirySweepRequest",
            &[
                "fixtures/authority-expiry/synthetic-authority-expiry-sweep-request.json",
                "fixtures/damaged/authority-expiry-sweep-request-stale-revision.json",
                "fixtures/damaged/authority-expiry-sweep-request-registry-mismatch.json",
            ],
        ),
        entry(
            "rusty.manifold.authority.expiry_sweep_rejection.v1",
            "ManifoldAuthorityExpirySweepRejection",
            &["fixtures/authority-expiry/synthetic-authority-expiry-sweep-rejection.json"],
        ),
        entry(
            "rusty.manifold.authority.command_audit_event.v1",
            "ManifoldCommandAuthorityAuditEvent",
            &[
                "fixtures/audit/synthetic-command-accepted-event.json",
                "fixtures/damaged/authority-audit-unknown-command.json",
            ],
        ),
        entry(
            "rusty.manifold.authority.lease_audit_event.v1",
            "ManifoldControlLeaseAuthorityAuditEvent",
            &["fixtures/audit/synthetic-lease-accepted-event.json"],
        ),
        entry(
            "rusty.manifold.authority.lease_release_audit_event.v1",
            "ManifoldControlLeaseReleaseAuthorityAuditEvent",
            &["fixtures/audit/synthetic-lease-release-accepted-event.json"],
        ),
        entry(
            "rusty.manifold.authority.lease_renewal_audit_event.v1",
            "ManifoldControlLeaseRenewalAuthorityAuditEvent",
            &["fixtures/audit/synthetic-lease-renewal-accepted-event.json"],
        ),
        entry(
            "rusty.manifold.authority.stream_registry_audit_event.v1",
            "ManifoldStreamRegistryAuthorityAuditEvent",
            &["fixtures/audit/synthetic-stream-registry-accepted-event.json"],
        ),
        entry(
            "rusty.manifold.authority.stream_subscription_audit_event.v1",
            "ManifoldStreamSubscriptionAuthorityAuditEvent",
            &["fixtures/audit/synthetic-stream-subscription-accepted-event.json"],
        ),
        entry(
            "rusty.manifold.authority.stream_subscription_release_audit_event.v1",
            "ManifoldStreamSubscriptionReleaseAuthorityAuditEvent",
            &["fixtures/audit/synthetic-stream-subscription-release-accepted-event.json"],
        ),
        entry(
            "rusty.manifold.authority.stream_subscription_renewal_audit_event.v1",
            "ManifoldStreamSubscriptionRenewalAuthorityAuditEvent",
            &["fixtures/audit/synthetic-stream-subscription-renewal-accepted-event.json"],
        ),
        entry(
            "rusty.manifold.authority.expiry_sweep_audit_event.v1",
            "ManifoldAuthorityExpirySweepAuthorityAuditEvent",
            &["fixtures/audit/synthetic-authority-expiry-sweep-accepted-event.json"],
        ),
        entry(
            "rusty.manifold.authority.module_runtime_state_audit_event.v1",
            "ManifoldModuleRuntimeStateAuthorityAuditEvent",
            &["fixtures/audit/synthetic-module-runtime-state-accepted-event.json"],
        ),
        entry(
            "rusty.manifold.authority.host_manifest_audit_event.v1",
            "ManifoldHostManifestAuthorityAuditEvent",
            &["fixtures/audit/synthetic-host-manifest-accepted-event.json"],
        ),
        entry(
            "rusty.manifold.authority.clock_snapshot_audit_event.v1",
            "ManifoldClockSnapshotAuthorityAuditEvent",
            &["fixtures/audit/synthetic-clock-accepted-event.json"],
        ),
        entry(
            "rusty.manifold.authority.command_review.v1",
            "ManifoldCommandAuthorityReview",
            &[
                "fixtures/authority-review/synthetic-command-accepted-review.json",
                "fixtures/authority-review/synthetic-command-stale-revision-review.json",
                "fixtures/authority-review/synthetic-command-expired-lease-review.json",
                "fixtures/authority-review/synthetic-command-missing-lease-review.json",
                "fixtures/authority-review/synthetic-command-unknown-command-review.json",
                "fixtures/authority-review/synthetic-command-unknown-lease-review.json",
                "fixtures/authority-review/synthetic-command-capability-mismatch-review.json",
                "fixtures/authority-review/remote-camera-q2q-start-receiver-review.json",
                "fixtures/authority-review/remote-camera-q2q-start-sender-review.json",
                "fixtures/authority-review/remote-camera-q2q-get-status-review.json",
                "fixtures/authority-review/remote-camera-q2q-stop-review.json",
            ],
        ),
        entry(
            "rusty.manifold.authority.command_dispatch_rejection.v1",
            "ManifoldCommandDispatchRejection",
            &["fixtures/command-dispatch/synthetic-command-dispatch-rejection.json"],
        ),
        entry(
            "rusty.manifold.authority.command_dispatch_receipt.v1",
            "ManifoldCommandDispatchReceipt",
            &[
                "fixtures/command-dispatch/synthetic-command-dispatch-ready-receipt.json",
                "fixtures/command-dispatch/synthetic-command-dispatch-rejected-receipt.json",
                "fixtures/command-dispatch/remote-camera-q2q-start-receiver-dispatch-receipt.json",
                "fixtures/command-dispatch/remote-camera-q2q-start-sender-dispatch-receipt.json",
                "fixtures/command-dispatch/remote-camera-q2q-get-status-dispatch-receipt.json",
                "fixtures/command-dispatch/remote-camera-q2q-stop-dispatch-receipt.json",
            ],
        ),
        entry(
            "rusty.manifold.authority.lease_review.v1",
            "ManifoldControlLeaseAuthorityReview",
            &[
                "fixtures/lease-review/synthetic-lease-accepted-review.json",
                "fixtures/lease-review/synthetic-lease-stale-revision-review.json",
                "fixtures/lease-review/synthetic-lease-zero-ttl-review.json",
                "fixtures/lease-review/synthetic-lease-missing-capability-review.json",
                "fixtures/lease-review/synthetic-lease-busy-scope-review.json",
            ],
        ),
        entry(
            "rusty.manifold.authority.lease_application.v1",
            "ManifoldControlLeaseAuthorityApplication",
            &[
                "fixtures/authority-application/synthetic-lease-accepted-application.json",
                "fixtures/authority-application/synthetic-lease-rejected-application.json",
            ],
        ),
        entry(
            "rusty.manifold.authority.lease_release_review.v1",
            "ManifoldControlLeaseReleaseAuthorityReview",
            &[
                "fixtures/lease-release-review/synthetic-lease-release-accepted-review.json",
                "fixtures/lease-release-review/synthetic-lease-release-expired-lease-review.json",
                "fixtures/lease-release-review/synthetic-lease-release-stale-revision-review.json",
                "fixtures/lease-release-review/synthetic-lease-release-unknown-lease-review.json",
                "fixtures/lease-release-review/synthetic-lease-release-holder-mismatch-review.json",
                "fixtures/lease-release-review/synthetic-lease-release-scope-mismatch-review.json",
            ],
        ),
        entry(
            "rusty.manifold.authority.lease_release_application.v1",
            "ManifoldControlLeaseReleaseAuthorityApplication",
            &[
                "fixtures/authority-application/synthetic-lease-release-accepted-application.json",
                "fixtures/authority-application/synthetic-lease-release-rejected-application.json",
            ],
        ),
        entry(
            "rusty.manifold.authority.lease_renewal_review.v1",
            "ManifoldControlLeaseRenewalAuthorityReview",
            &[
                "fixtures/lease-renewal-review/synthetic-lease-renewal-accepted-review.json",
                "fixtures/lease-renewal-review/synthetic-lease-renewal-stale-revision-review.json",
                "fixtures/lease-renewal-review/synthetic-lease-renewal-unknown-lease-review.json",
                "fixtures/lease-renewal-review/synthetic-lease-renewal-holder-mismatch-review.json",
                "fixtures/lease-renewal-review/synthetic-lease-renewal-scope-mismatch-review.json",
                "fixtures/lease-renewal-review/synthetic-lease-renewal-zero-ttl-review.json",
                "fixtures/lease-renewal-review/synthetic-lease-renewal-non-extending-review.json",
                "fixtures/lease-renewal-review/synthetic-lease-renewal-expired-lease-review.json",
            ],
        ),
        entry(
            "rusty.manifold.authority.lease_renewal_application.v1",
            "ManifoldControlLeaseRenewalAuthorityApplication",
            &[
                "fixtures/authority-application/synthetic-lease-renewal-accepted-application.json",
                "fixtures/authority-application/synthetic-lease-renewal-rejected-application.json",
            ],
        ),
        entry(
            "rusty.manifold.authority.stream_registry_review.v1",
            "ManifoldStreamRegistryAuthorityReview",
            &[
                "fixtures/stream-registry-review/synthetic-stream-registry-accepted-review.json",
                "fixtures/stream-registry-review/synthetic-stream-registry-expired-lease-review.json",
                "fixtures/stream-registry-review/synthetic-stream-registry-stale-revision-review.json",
                "fixtures/stream-registry-review/synthetic-stream-registry-missing-lease-review.json",
                "fixtures/stream-registry-review/synthetic-stream-registry-active-stream-review.json",
                "fixtures/stream-registry-review/synthetic-stream-registry-remove-active-transport-review.json",
                "fixtures/stream-registry-review/synthetic-stream-registry-disable-active-ui-subscriptions-review.json",
                "fixtures/stream-registry-review/synthetic-stream-registry-lower-active-subscriber-limit-review.json",
                "fixtures/stream-registry-review/synthetic-stream-registry-unknown-module-review.json",
                "fixtures/stream-registry-review/synthetic-stream-registry-unknown-endpoint-review.json",
            ],
        ),
        entry(
            "rusty.manifold.authority.stream_registry_application.v1",
            "ManifoldStreamRegistryAuthorityApplication",
            &[
                "fixtures/authority-application/synthetic-stream-registry-accepted-application.json",
                "fixtures/authority-application/synthetic-stream-registry-rejected-application.json",
            ],
        ),
        entry(
            "rusty.manifold.authority.stream_subscription_review.v1",
            "ManifoldStreamSubscriptionAuthorityReview",
            &[
                "fixtures/stream-subscription-review/synthetic-stream-subscription-accepted-review.json",
                "fixtures/stream-subscription-review/synthetic-stream-subscription-zero-ttl-review.json",
                "fixtures/stream-subscription-review/synthetic-stream-subscription-missing-capability-review.json",
                "fixtures/stream-subscription-review/synthetic-stream-subscription-stale-revision-review.json",
                "fixtures/stream-subscription-review/synthetic-stream-subscription-stale-registry-review.json",
                "fixtures/stream-subscription-review/synthetic-stream-subscription-unknown-stream-review.json",
                "fixtures/stream-subscription-review/synthetic-stream-subscription-unknown-transport-review.json",
                "fixtures/stream-subscription-review/synthetic-stream-subscription-subscriber-limit-review.json",
                "fixtures/stream-subscription-review/synthetic-stream-subscription-ui-disabled-review.json",
            ],
        ),
        entry(
            "rusty.manifold.authority.stream_subscription_application.v1",
            "ManifoldStreamSubscriptionAuthorityApplication",
            &[
                "fixtures/authority-application/synthetic-stream-subscription-accepted-application.json",
                "fixtures/authority-application/synthetic-stream-subscription-rejected-application.json",
            ],
        ),
        entry(
            "rusty.manifold.authority.stream_subscription_release_review.v1",
            "ManifoldStreamSubscriptionReleaseAuthorityReview",
            &[
                "fixtures/stream-subscription-release-review/synthetic-stream-subscription-release-accepted-review.json",
                "fixtures/stream-subscription-release-review/synthetic-stream-subscription-release-expired-subscription-review.json",
                "fixtures/stream-subscription-release-review/synthetic-stream-subscription-release-stale-revision-review.json",
                "fixtures/stream-subscription-release-review/synthetic-stream-subscription-release-stale-registry-review.json",
                "fixtures/stream-subscription-release-review/synthetic-stream-subscription-release-unknown-subscription-review.json",
                "fixtures/stream-subscription-release-review/synthetic-stream-subscription-release-subscriber-mismatch-review.json",
                "fixtures/stream-subscription-release-review/synthetic-stream-subscription-release-stream-mismatch-review.json",
            ],
        ),
        entry(
            "rusty.manifold.authority.stream_subscription_release_application.v1",
            "ManifoldStreamSubscriptionReleaseAuthorityApplication",
            &[
                "fixtures/authority-application/synthetic-stream-subscription-release-accepted-application.json",
                "fixtures/authority-application/synthetic-stream-subscription-release-rejected-application.json",
            ],
        ),
        entry(
            "rusty.manifold.authority.stream_subscription_renewal_review.v1",
            "ManifoldStreamSubscriptionRenewalAuthorityReview",
            &[
                "fixtures/stream-subscription-renewal-review/synthetic-stream-subscription-renewal-accepted-review.json",
                "fixtures/stream-subscription-renewal-review/synthetic-stream-subscription-renewal-stale-revision-review.json",
                "fixtures/stream-subscription-renewal-review/synthetic-stream-subscription-renewal-stale-registry-review.json",
                "fixtures/stream-subscription-renewal-review/synthetic-stream-subscription-renewal-unknown-subscription-review.json",
                "fixtures/stream-subscription-renewal-review/synthetic-stream-subscription-renewal-subscriber-mismatch-review.json",
                "fixtures/stream-subscription-renewal-review/synthetic-stream-subscription-renewal-stream-mismatch-review.json",
                "fixtures/stream-subscription-renewal-review/synthetic-stream-subscription-renewal-transport-mismatch-review.json",
                "fixtures/stream-subscription-renewal-review/synthetic-stream-subscription-renewal-zero-ttl-review.json",
                "fixtures/stream-subscription-renewal-review/synthetic-stream-subscription-renewal-non-extending-review.json",
                "fixtures/stream-subscription-renewal-review/synthetic-stream-subscription-renewal-expired-subscription-review.json",
            ],
        ),
        entry(
            "rusty.manifold.authority.stream_subscription_renewal_application.v1",
            "ManifoldStreamSubscriptionRenewalAuthorityApplication",
            &[
                "fixtures/authority-application/synthetic-stream-subscription-renewal-accepted-application.json",
                "fixtures/authority-application/synthetic-stream-subscription-renewal-rejected-application.json",
            ],
        ),
        entry(
            "rusty.manifold.authority.expiry_sweep_review.v1",
            "ManifoldAuthorityExpirySweepAuthorityReview",
            &[
                "fixtures/authority-expiry-review/synthetic-authority-expiry-sweep-accepted-review.json",
                "fixtures/authority-expiry-review/synthetic-authority-expiry-sweep-stale-revision-review.json",
                "fixtures/authority-expiry-review/synthetic-authority-expiry-sweep-registry-mismatch-review.json",
                "fixtures/authority-expiry-review/synthetic-authority-expiry-sweep-no-expired-review.json",
            ],
        ),
        entry(
            "rusty.manifold.authority.expiry_sweep_application.v1",
            "ManifoldAuthorityExpirySweepAuthorityApplication",
            &[
                "fixtures/authority-application/synthetic-authority-expiry-sweep-accepted-application.json",
                "fixtures/authority-application/synthetic-authority-expiry-sweep-rejected-application.json",
            ],
        ),
        entry(
            "rusty.manifold.authority.snapshot_application_rejection.v1",
            "ManifoldAuthoritySnapshotApplicationRejection",
            &[
                "fixtures/authority-application/synthetic-stream-registry-application-rejection.json",
                "fixtures/authority-application/synthetic-stream-subscription-application-rejection.json",
                "fixtures/authority-application/synthetic-stream-subscription-release-application-rejection.json",
                "fixtures/authority-application/synthetic-stream-subscription-renewal-application-rejection.json",
                "fixtures/authority-application/synthetic-module-runtime-application-rejection.json",
                "fixtures/authority-application/synthetic-host-manifest-application-rejection.json",
                "fixtures/authority-application/synthetic-clock-application-rejection.json",
                "fixtures/authority-application/synthetic-lease-application-rejection.json",
                "fixtures/authority-application/synthetic-lease-release-application-rejection.json",
                "fixtures/authority-application/synthetic-lease-renewal-application-rejection.json",
                "fixtures/authority-application/synthetic-authority-expiry-sweep-application-rejection.json",
            ],
        ),
        entry(
            "rusty.manifold.authority.module_runtime_state_review.v1",
            "ManifoldModuleRuntimeStateAuthorityReview",
            &[
                "fixtures/module-runtime-review/synthetic-module-runtime-accepted-review.json",
                "fixtures/module-runtime-review/synthetic-module-runtime-expired-lease-review.json",
                "fixtures/module-runtime-review/synthetic-module-runtime-stale-revision-review.json",
                "fixtures/module-runtime-review/synthetic-module-runtime-missing-lease-review.json",
                "fixtures/module-runtime-review/synthetic-module-runtime-unknown-stream-review.json",
                "fixtures/module-runtime-review/synthetic-module-runtime-missing-backend-review.json",
            ],
        ),
        entry(
            "rusty.manifold.authority.module_runtime_state_application.v1",
            "ManifoldModuleRuntimeStateAuthorityApplication",
            &[
                "fixtures/authority-application/synthetic-module-runtime-accepted-application.json",
                "fixtures/authority-application/synthetic-module-runtime-rejected-application.json",
            ],
        ),
        entry(
            "rusty.manifold.authority.host_manifest_review.v1",
            "ManifoldHostManifestAuthorityReview",
            &[
                "fixtures/host-manifest-review/synthetic-host-manifest-accepted-review.json",
                "fixtures/host-manifest-review/synthetic-host-manifest-expired-lease-review.json",
                "fixtures/host-manifest-review/synthetic-host-manifest-stale-revision-review.json",
                "fixtures/host-manifest-review/synthetic-host-manifest-missing-authority-role-review.json",
                "fixtures/host-manifest-review/synthetic-host-manifest-endpoint-mismatch-review.json",
                "fixtures/host-manifest-review/synthetic-host-manifest-remove-capability-review.json",
                "fixtures/host-manifest-review/synthetic-host-manifest-remove-backend-review.json",
            ],
        ),
        entry(
            "rusty.manifold.authority.host_manifest_application.v1",
            "ManifoldHostManifestAuthorityApplication",
            &[
                "fixtures/authority-application/synthetic-host-manifest-accepted-application.json",
                "fixtures/authority-application/synthetic-host-manifest-rejected-application.json",
            ],
        ),
        entry(
            "rusty.manifold.authority.clock_snapshot_review.v1",
            "ManifoldClockSnapshotAuthorityReview",
            &[
                "fixtures/clock-review/synthetic-clock-accepted-review.json",
                "fixtures/clock-review/synthetic-clock-expired-lease-review.json",
                "fixtures/clock-review/synthetic-clock-stale-revision-review.json",
                "fixtures/clock-review/synthetic-clock-missing-lease-review.json",
                "fixtures/clock-review/synthetic-clock-domain-mismatch-review.json",
                "fixtures/clock-review/synthetic-clock-sequence-gap-review.json",
                "fixtures/clock-review/synthetic-clock-monotonic-regression-review.json",
            ],
        ),
        entry(
            "rusty.manifold.authority.clock_snapshot_application.v1",
            "ManifoldClockSnapshotAuthorityApplication",
            &[
                "fixtures/authority-application/synthetic-clock-accepted-application.json",
                "fixtures/authority-application/synthetic-clock-rejected-application.json",
            ],
        ),
    ]
}

fn bridge_route_entries() -> Vec<SchemaEntry> {
    vec![
        entry(
            "rusty.manifold.bridge.route_descriptor.v1",
            "ManifoldBridgeRouteDescriptor",
            &[
                "fixtures/bridge-route/command-websocket-applied-route.json",
                "fixtures/bridge-route/marker-lsl-timestamped-route.json",
                "fixtures/bridge-route/stream-lsl-clock-roundtrip-route.json",
                "fixtures/bridge-route/telemetry-udp-best-effort-route.json",
                "fixtures/bridge-route/stream-websocket-ordered-route.json",
                "fixtures/bridge-route/stream-osc-udp-route.json",
                "fixtures/bridge-route/stream-bluetooth-rfcomm-route.json",
                "fixtures/bridge-route/stream-bluetooth-gatt-notify-route.json",
                "fixtures/bridge-route/device-adb-transport-route.json",
                "fixtures/bridge-route/media-h264-data-plane-route.json",
                "fixtures/bridge-route/stream-zeromq-pubsub-route.json",
                "fixtures/damaged/bridge-route-lsl-missing-profile.json",
                "fixtures/damaged/bridge-route-zeromq-missing-profile.json",
                "fixtures/damaged/bridge-route-missing-conditions.json",
                "fixtures/damaged/bridge-route-invalid-timing.json",
            ],
        ),
        entry(
            "rusty.manifold.bridge.route_evidence.v1",
            "ManifoldBridgeRouteEvidence",
            &[
                "fixtures/bridge-route/command-websocket-applied-evidence.json",
                "fixtures/bridge-route/stream-websocket-ordered-evidence.json",
                "fixtures/bridge-route/stream-lsl-clock-roundtrip-evidence.json",
                "fixtures/bridge-route/stream-zeromq-pubsub-evidence.json",
                "fixtures/damaged/bridge-route-command-transport-only-evidence.json",
            ],
        ),
    ]
}

fn host_and_deployment_entries() -> Vec<SchemaEntry> {
    vec![
        entry(
            "rusty.manifold.host.manifest.v1",
            "ManifoldHostManifest",
            &[
                "fixtures/host/synthetic-host.json",
                "fixtures/host/desktop-local.json",
                "fixtures/host/mobile-device.json",
                "fixtures/host/headset-device.json",
            ],
        ),
        entry(
            "rusty.manifold.host.manifest_change_request.v1",
            "ManifoldHostManifestChangeRequest",
            &[
                "fixtures/host/synthetic-host-manifest-change-request.json",
                "fixtures/damaged/host-manifest-request-stale-revision.json",
                "fixtures/damaged/host-manifest-request-missing-authority-role.json",
                "fixtures/damaged/host-manifest-request-endpoint-mismatch.json",
                "fixtures/damaged/host-manifest-request-remove-capability.json",
                "fixtures/damaged/host-manifest-request-remove-backend.json",
            ],
        ),
        entry(
            "rusty.manifold.host.manifest_rejection.v1",
            "ManifoldHostManifestRejection",
            &["fixtures/host/synthetic-host-manifest-rejection.json"],
        ),
        entry(
            "rusty.manifold.deployment.manifest.v1",
            "ManifoldDeploymentManifest",
            &[
                "fixtures/deployment/synthetic-deployment.json",
                "fixtures/damaged/unavailable-deployment-backend.json",
            ],
        ),
        entry(
            "rusty.manifold.deployment.selection_snapshot.v1",
            "ManifoldDeploymentSelectionSnapshot",
            &["fixtures/deployment/synthetic-selection.json"],
        ),
    ]
}

fn verification_entries() -> Vec<SchemaEntry> {
    vec![
        entry(
            "rusty.manifold.clock.snapshot.v1",
            "ManifoldClockSnapshot",
            &[
                "fixtures/clock/synthetic-clock-snapshot.json",
                "fixtures/clock/synthetic-command-review-clock.json",
                "fixtures/clock/synthetic-expired-command-review-clock.json",
                "fixtures/clock/remote-camera-start-receiver-review-clock.json",
                "fixtures/clock/remote-camera-start-sender-review-clock.json",
                "fixtures/clock/remote-camera-get-status-review-clock.json",
                "fixtures/clock/remote-camera-stop-review-clock.json",
            ],
        ),
        entry(
            "rusty.manifold.clock.snapshot_change_request.v1",
            "ManifoldClockSnapshotChangeRequest",
            &[
                "fixtures/clock/synthetic-clock-change-request.json",
                "fixtures/damaged/clock-request-stale-revision.json",
                "fixtures/damaged/clock-request-missing-lease.json",
                "fixtures/damaged/clock-request-domain-mismatch.json",
                "fixtures/damaged/clock-request-sequence-gap.json",
                "fixtures/damaged/clock-request-monotonic-regression.json",
            ],
        ),
        entry(
            "rusty.manifold.clock.snapshot_rejection.v1",
            "ManifoldClockSnapshotRejection",
            &["fixtures/clock/synthetic-clock-rejection.json"],
        ),
        entry(
            "rusty.manifold.validation.scorecard.v1",
            "ManifoldValidationScorecard",
            &["fixtures/validation/synthetic-scorecard.json"],
        ),
        entry(
            "rusty.manifold.simulator.snapshot.v1",
            "SimulatorSnapshot",
            &["fixtures/simulator/synthetic-topology-summary.json"],
        ),
        entry(
            "rusty.manifold.diff.snapshot.v1",
            "FixtureDiffSnapshot",
            &["fixtures/diff/synthetic-contract-diff.json"],
        ),
        entry(
            "rusty.manifold.host_run.install_launch_profile.v1",
            "ManifoldHostRunInstallLaunchProfile",
            &[
                "fixtures/host-run/install-profile-desktop.json",
                "fixtures/host-run/install-profile-mobile.json",
                "fixtures/host-run/install-profile-headset.json",
            ],
        ),
        entry(
            "rusty.manifold.host_run.validation_slot.v1",
            "ManifoldHostRunValidationSlot",
            &["fixtures/host-run/slot-live-smoke.json"],
        ),
        entry(
            "rusty.manifold.host_run.run_bundle.v1",
            "ManifoldHostRunBundle",
            &["fixtures/host-run/run-bundle-live-smoke.json"],
        ),
        entry(
            "rusty.manifold.host_run.command_envelope.v1",
            "ManifoldHostRunCommandEnvelope",
            &["fixtures/host-run/command-envelope-run-live.json"],
        ),
        entry(
            "rusty.manifold.host_run.run_evidence.v1",
            "ManifoldHostRunEvidence",
            &["fixtures/host-run/run-evidence-live-smoke.json"],
        ),
        entry(
            "rusty.manifold.shell.handoff.v1",
            "ManifoldShellHandoffManifest",
            &[
                "fixtures/shell-handoff/synthetic-loopback-shell.json",
                "fixtures/damaged/shell-handoff-missing-stream.json",
            ],
        ),
        entry(
            "rusty.manifold.shell.handoff_review_receipt.v1",
            "ManifoldShellHandoffReviewReceipt",
            &[
                "fixtures/shell-handoff/synthetic-loopback-shell-review.json",
                "fixtures/damaged/shell-handoff-review-runtime-started.json",
            ],
        ),
    ]
}

#[derive(Serialize)]
struct SchemaEntry {
    schema_id: &'static str,
    rust_type: &'static str,
    fixture_paths: Vec<&'static str>,
}

fn entry(
    schema_id: &'static str,
    rust_type: &'static str,
    fixture_paths: &[&'static str],
) -> SchemaEntry {
    SchemaEntry {
        schema_id,
        rust_type,
        fixture_paths: fixture_paths.to_vec(),
    }
}

fn default_repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn usage() -> String {
    "usage: rusty-manifold-schema export [--check] [--repo-root <path>]".to_owned()
}

#[derive(Debug)]
enum CliError {
    Usage(String),
    UnknownOption(String),
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Serialize(serde_json::Error),
    CatalogMismatch {
        schema_path: PathBuf,
        output: String,
    },
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(message) => formatter.write_str(message),
            Self::UnknownOption(option) => write!(formatter, "unknown option: {option}"),
            Self::Io { path, source } => write!(formatter, "{}: {source}", path.display()),
            Self::Serialize(source) => write!(formatter, "failed to serialize catalog: {source}"),
            Self::CatalogMismatch {
                schema_path,
                output,
            } => write!(
                formatter,
                "schema catalog does not match {}\n{output}",
                schema_path.display()
            ),
        }
    }
}

impl std::error::Error for CliError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_export_is_deterministic() {
        let catalog = SchemaCatalog::current();
        let output = serde_json::to_string_pretty(&catalog).unwrap();
        let expected =
            fs::read_to_string(default_repo_root().join("schemas/catalog.json")).unwrap();

        assert_eq!(expected.trim_end(), output.trim_end());
    }
}
