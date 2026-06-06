//! Fixture validation and source-only simulation CLI.

use std::env;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use rusty_manifold_model::{
    DottedId, ManifoldAuthorityExpirySweepAuthorityApplication,
    ManifoldAuthorityExpirySweepAuthorityAuditEvent, ManifoldAuthorityExpirySweepAuthorityReview,
    ManifoldAuthorityExpirySweepRejection, ManifoldAuthorityExpirySweepRequest,
    ManifoldAuthoritySnapshot, ManifoldAuthoritySnapshotApplicationRejection,
    ManifoldClockSnapshot, ManifoldClockSnapshotAuthorityApplication,
    ManifoldClockSnapshotAuthorityAuditEvent, ManifoldClockSnapshotAuthorityReview,
    ManifoldClockSnapshotChangeRequest, ManifoldClockSnapshotRejection, ManifoldCommandAck,
    ManifoldCommandAuthorityAuditEvent, ManifoldCommandAuthorityReview, ManifoldCommandDescriptor,
    ManifoldCommandDispatchReceipt, ManifoldCommandDispatchRejection, ManifoldCommandEnvelope,
    ManifoldCommandRejection, ManifoldControlLease, ManifoldControlLeaseAuthorityApplication,
    ManifoldControlLeaseAuthorityAuditEvent, ManifoldControlLeaseAuthorityReview,
    ManifoldControlLeaseRejection, ManifoldControlLeaseReleaseAuthorityApplication,
    ManifoldControlLeaseReleaseAuthorityAuditEvent, ManifoldControlLeaseReleaseAuthorityReview,
    ManifoldControlLeaseReleaseRejection, ManifoldControlLeaseReleaseRequest,
    ManifoldControlLeaseRenewalAuthorityApplication,
    ManifoldControlLeaseRenewalAuthorityAuditEvent, ManifoldControlLeaseRenewalAuthorityReview,
    ManifoldControlLeaseRenewalRejection, ManifoldControlLeaseRenewalRequest,
    ManifoldControlLeaseRequest, ManifoldDeploymentManifest, ManifoldDeploymentSelectionSnapshot,
    ManifoldGraphDiff, ManifoldGraphManifest, ManifoldHostManifest,
    ManifoldHostManifestAuthorityApplication, ManifoldHostManifestAuthorityAuditEvent,
    ManifoldHostManifestAuthorityReview, ManifoldHostManifestChangeRequest,
    ManifoldHostManifestRejection, ManifoldHostRunBundle, ManifoldHostRunCommandEnvelope,
    ManifoldHostRunEvidence, ManifoldHostRunInstallLaunchProfile, ManifoldHostRunValidationSlot,
    ManifoldModuleManifest, ManifoldModuleRuntimeState,
    ManifoldModuleRuntimeStateAuthorityApplication, ManifoldModuleRuntimeStateAuthorityAuditEvent,
    ManifoldModuleRuntimeStateAuthorityReview, ManifoldModuleRuntimeStateChangeRequest,
    ManifoldModuleRuntimeStateRejection, ManifoldModuleRuntimeTransition, ManifoldPackageManifest,
    ManifoldShellHandoffManifest, ManifoldShellHandoffReviewReceipt, ManifoldStreamManifest,
    ManifoldStreamRegistryAuthorityApplication, ManifoldStreamRegistryAuthorityAuditEvent,
    ManifoldStreamRegistryAuthorityReview, ManifoldStreamRegistryChangeRequest,
    ManifoldStreamRegistryDiff, ManifoldStreamRegistryRejection, ManifoldStreamRegistrySnapshot,
    ManifoldStreamSubscription, ManifoldStreamSubscriptionAuthorityApplication,
    ManifoldStreamSubscriptionAuthorityAuditEvent, ManifoldStreamSubscriptionAuthorityReview,
    ManifoldStreamSubscriptionRejection, ManifoldStreamSubscriptionReleaseAuthorityApplication,
    ManifoldStreamSubscriptionReleaseAuthorityAuditEvent,
    ManifoldStreamSubscriptionReleaseAuthorityReview, ManifoldStreamSubscriptionReleaseRejection,
    ManifoldStreamSubscriptionReleaseRequest,
    ManifoldStreamSubscriptionRenewalAuthorityApplication,
    ManifoldStreamSubscriptionRenewalAuthorityAuditEvent,
    ManifoldStreamSubscriptionRenewalAuthorityReview, ManifoldStreamSubscriptionRenewalRejection,
    ManifoldStreamSubscriptionRenewalRequest, ManifoldStreamSubscriptionRequest,
    ManifoldValidationScorecard, Revision,
};
use serde::de::DeserializeOwned;
use serde::Serialize;

fn main() -> ExitCode {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let result = std::thread::Builder::new()
        .name("rusty-manifold-fixtures".to_owned())
        // Fixture validation intentionally loads deeply nested authority receipts.
        .stack_size(16 * 1024 * 1024)
        .spawn(move || run(args))
        .expect("fixture worker should spawn")
        .join()
        .expect("fixture worker should not panic");

    match result {
        Ok(output) => {
            if !output.is_empty() {
                println!("{output}");
            }
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
    match options.command {
        Command::Validate => {
            let report = validate_repo(&options.repo_root)?;
            let status = report.status.clone();
            let output = to_pretty_json(&report)?;
            if status == "pass" {
                Ok(output)
            } else {
                Err(CliError::ValidationFailed(output))
            }
        }
        Command::Simulate { check } => {
            let snapshot = simulate_synthetic_topology(&options.repo_root)?;
            let output = to_pretty_json(&snapshot)?;
            if check {
                let expected_path = options
                    .repo_root
                    .join("fixtures/simulator/synthetic-topology-summary.json");
                let expected = read_text(&expected_path)?;
                if expected.trim_end() == output.trim_end() {
                    Ok("simulator snapshot matches fixture".to_owned())
                } else {
                    Err(CliError::SnapshotMismatch {
                        expected_path,
                        output,
                    })
                }
            } else {
                Ok(output)
            }
        }
        Command::Diff { check } => {
            let snapshot = diff_synthetic_contracts(&options.repo_root)?;
            let output = to_pretty_json(&snapshot)?;
            if check {
                let expected_path = options
                    .repo_root
                    .join("fixtures/diff/synthetic-contract-diff.json");
                let expected = read_text(&expected_path)?;
                if expected.trim_end() == output.trim_end() {
                    Ok("contract diff snapshot matches fixture".to_owned())
                } else {
                    Err(CliError::SnapshotMismatch {
                        expected_path,
                        output,
                    })
                }
            } else {
                Ok(output)
            }
        }
        Command::ReviewShellHandoff { handoff, output } => {
            let Some(handoff_path) = handoff else {
                return Err(CliError::Usage(
                    "review-shell-handoff requires --handoff <path>".to_owned(),
                ));
            };
            let receipt = review_shell_handoff(&options.repo_root, &handoff_path)?;
            let status = receipt.status;
            let serialized = to_pretty_json(&receipt)?;
            if let Some(output_path) = output {
                write_text(&output_path, &serialized)?;
            }
            if status == rusty_manifold_model::ValidationStatus::Pass {
                Ok(serialized)
            } else {
                Err(CliError::ValidationFailed(serialized))
            }
        }
        Command::ReviewCommand {
            snapshot,
            envelope,
            clock,
            output,
        } => {
            let Some(snapshot_path) = snapshot else {
                return Err(CliError::Usage(
                    "review-command requires --snapshot <path>".to_owned(),
                ));
            };
            let Some(envelope_path) = envelope else {
                return Err(CliError::Usage(
                    "review-command requires --envelope <path>".to_owned(),
                ));
            };
            let Some(clock_path) = clock else {
                return Err(CliError::Usage(
                    "review-command requires --clock <path>".to_owned(),
                ));
            };
            let review = review_command(
                &options.repo_root,
                &snapshot_path,
                &envelope_path,
                &clock_path,
            )?;
            let serialized = to_pretty_json(&review)?;
            if let Some(output_path) = output {
                write_text(&output_path, &serialized)?;
            }
            Ok(serialized)
        }
        Command::PrepareCommandDispatch {
            snapshot,
            review,
            output,
        } => {
            let Some(snapshot_path) = snapshot else {
                return Err(CliError::Usage(
                    "prepare-command-dispatch requires --snapshot <path>".to_owned(),
                ));
            };
            let Some(review_path) = review else {
                return Err(CliError::Usage(
                    "prepare-command-dispatch requires --review <path>".to_owned(),
                ));
            };
            let receipt =
                prepare_command_dispatch(&options.repo_root, &snapshot_path, &review_path)?;
            let serialized = to_pretty_json(&receipt)?;
            if let Some(output_path) = output {
                write_text(&output_path, &serialized)?;
            }
            Ok(serialized)
        }
        Command::ReviewLease {
            snapshot,
            request,
            clock,
            output,
        } => {
            let Some(snapshot_path) = snapshot else {
                return Err(CliError::Usage(
                    "review-lease requires --snapshot <path>".to_owned(),
                ));
            };
            let Some(request_path) = request else {
                return Err(CliError::Usage(
                    "review-lease requires --request <path>".to_owned(),
                ));
            };
            let Some(clock_path) = clock else {
                return Err(CliError::Usage(
                    "review-lease requires --clock <path>".to_owned(),
                ));
            };
            let review = review_lease(
                &options.repo_root,
                &snapshot_path,
                &request_path,
                &clock_path,
            )?;
            let serialized = to_pretty_json(&review)?;
            if let Some(output_path) = output {
                write_text(&output_path, &serialized)?;
            }
            Ok(serialized)
        }
        Command::ApplyLeaseReview {
            snapshot,
            review,
            output,
        } => {
            let Some(snapshot_path) = snapshot else {
                return Err(CliError::Usage(
                    "apply-lease-review requires --snapshot <path>".to_owned(),
                ));
            };
            let Some(review_path) = review else {
                return Err(CliError::Usage(
                    "apply-lease-review requires --review <path>".to_owned(),
                ));
            };
            let application = apply_lease_review(&options.repo_root, &snapshot_path, &review_path)?;
            let serialized = to_pretty_json(&application)?;
            if let Some(output_path) = output {
                write_text(&output_path, &serialized)?;
            }
            Ok(serialized)
        }
        Command::ReviewLeaseRelease {
            snapshot,
            request,
            clock,
            output,
        } => {
            let Some(snapshot_path) = snapshot else {
                return Err(CliError::Usage(
                    "review-lease-release requires --snapshot <path>".to_owned(),
                ));
            };
            let Some(request_path) = request else {
                return Err(CliError::Usage(
                    "review-lease-release requires --request <path>".to_owned(),
                ));
            };
            let Some(clock_path) = clock else {
                return Err(CliError::Usage(
                    "review-lease-release requires --clock <path>".to_owned(),
                ));
            };
            let review = review_lease_release(
                &options.repo_root,
                &snapshot_path,
                &request_path,
                &clock_path,
            )?;
            let serialized = to_pretty_json(&review)?;
            if let Some(output_path) = output {
                write_text(&output_path, &serialized)?;
            }
            Ok(serialized)
        }
        Command::ApplyLeaseReleaseReview {
            snapshot,
            review,
            output,
        } => {
            let Some(snapshot_path) = snapshot else {
                return Err(CliError::Usage(
                    "apply-lease-release-review requires --snapshot <path>".to_owned(),
                ));
            };
            let Some(review_path) = review else {
                return Err(CliError::Usage(
                    "apply-lease-release-review requires --review <path>".to_owned(),
                ));
            };
            let application =
                apply_lease_release_review(&options.repo_root, &snapshot_path, &review_path)?;
            let serialized = to_pretty_json(&application)?;
            if let Some(output_path) = output {
                write_text(&output_path, &serialized)?;
            }
            Ok(serialized)
        }
        Command::ReviewLeaseRenewal {
            snapshot,
            request,
            clock,
            output,
        } => {
            let Some(snapshot_path) = snapshot else {
                return Err(CliError::Usage(
                    "review-lease-renewal requires --snapshot <path>".to_owned(),
                ));
            };
            let Some(request_path) = request else {
                return Err(CliError::Usage(
                    "review-lease-renewal requires --request <path>".to_owned(),
                ));
            };
            let Some(clock_path) = clock else {
                return Err(CliError::Usage(
                    "review-lease-renewal requires --clock <path>".to_owned(),
                ));
            };
            let review = review_lease_renewal(
                &options.repo_root,
                &snapshot_path,
                &request_path,
                &clock_path,
            )?;
            let serialized = to_pretty_json(&review)?;
            if let Some(output_path) = output {
                write_text(&output_path, &serialized)?;
            }
            Ok(serialized)
        }
        Command::ApplyLeaseRenewalReview {
            snapshot,
            review,
            output,
        } => {
            let Some(snapshot_path) = snapshot else {
                return Err(CliError::Usage(
                    "apply-lease-renewal-review requires --snapshot <path>".to_owned(),
                ));
            };
            let Some(review_path) = review else {
                return Err(CliError::Usage(
                    "apply-lease-renewal-review requires --review <path>".to_owned(),
                ));
            };
            let application =
                apply_lease_renewal_review(&options.repo_root, &snapshot_path, &review_path)?;
            let serialized = to_pretty_json(&application)?;
            if let Some(output_path) = output {
                write_text(&output_path, &serialized)?;
            }
            Ok(serialized)
        }
        Command::ReviewStreamRegistry {
            snapshot,
            request,
            clock,
            output,
        } => {
            let Some(snapshot_path) = snapshot else {
                return Err(CliError::Usage(
                    "review-stream-registry requires --snapshot <path>".to_owned(),
                ));
            };
            let Some(request_path) = request else {
                return Err(CliError::Usage(
                    "review-stream-registry requires --request <path>".to_owned(),
                ));
            };
            let Some(clock_path) = clock else {
                return Err(CliError::Usage(
                    "review-stream-registry requires --clock <path>".to_owned(),
                ));
            };
            let review = review_stream_registry(
                &options.repo_root,
                &snapshot_path,
                &request_path,
                &clock_path,
            )?;
            let serialized = to_pretty_json(&review)?;
            if let Some(output_path) = output {
                write_text(&output_path, &serialized)?;
            }
            Ok(serialized)
        }
        Command::ApplyStreamRegistryReview {
            snapshot,
            review,
            output,
        } => {
            let Some(snapshot_path) = snapshot else {
                return Err(CliError::Usage(
                    "apply-stream-registry-review requires --snapshot <path>".to_owned(),
                ));
            };
            let Some(review_path) = review else {
                return Err(CliError::Usage(
                    "apply-stream-registry-review requires --review <path>".to_owned(),
                ));
            };
            let application =
                apply_stream_registry_review(&options.repo_root, &snapshot_path, &review_path)?;
            let serialized = to_pretty_json(&application)?;
            if let Some(output_path) = output {
                write_text(&output_path, &serialized)?;
            }
            Ok(serialized)
        }
        Command::ReviewStreamSubscription {
            snapshot,
            request,
            clock,
            output,
        } => {
            let Some(snapshot_path) = snapshot else {
                return Err(CliError::Usage(
                    "review-stream-subscription requires --snapshot <path>".to_owned(),
                ));
            };
            let Some(request_path) = request else {
                return Err(CliError::Usage(
                    "review-stream-subscription requires --request <path>".to_owned(),
                ));
            };
            let Some(clock_path) = clock else {
                return Err(CliError::Usage(
                    "review-stream-subscription requires --clock <path>".to_owned(),
                ));
            };
            let review = review_stream_subscription(
                &options.repo_root,
                &snapshot_path,
                &request_path,
                &clock_path,
            )?;
            let serialized = to_pretty_json(&review)?;
            if let Some(output_path) = output {
                write_text(&output_path, &serialized)?;
            }
            Ok(serialized)
        }
        Command::ApplyStreamSubscriptionReview {
            snapshot,
            review,
            output,
        } => {
            let Some(snapshot_path) = snapshot else {
                return Err(CliError::Usage(
                    "apply-stream-subscription-review requires --snapshot <path>".to_owned(),
                ));
            };
            let Some(review_path) = review else {
                return Err(CliError::Usage(
                    "apply-stream-subscription-review requires --review <path>".to_owned(),
                ));
            };
            let application =
                apply_stream_subscription_review(&options.repo_root, &snapshot_path, &review_path)?;
            let serialized = to_pretty_json(&application)?;
            if let Some(output_path) = output {
                write_text(&output_path, &serialized)?;
            }
            Ok(serialized)
        }
        Command::ReviewStreamSubscriptionRelease {
            snapshot,
            request,
            clock,
            output,
        } => {
            let Some(snapshot_path) = snapshot else {
                return Err(CliError::Usage(
                    "review-stream-subscription-release requires --snapshot <path>".to_owned(),
                ));
            };
            let Some(request_path) = request else {
                return Err(CliError::Usage(
                    "review-stream-subscription-release requires --request <path>".to_owned(),
                ));
            };
            let Some(clock_path) = clock else {
                return Err(CliError::Usage(
                    "review-stream-subscription-release requires --clock <path>".to_owned(),
                ));
            };
            let review = review_stream_subscription_release(
                &options.repo_root,
                &snapshot_path,
                &request_path,
                &clock_path,
            )?;
            let serialized = to_pretty_json(&review)?;
            if let Some(output_path) = output {
                write_text(&output_path, &serialized)?;
            }
            Ok(serialized)
        }
        Command::ApplyStreamSubscriptionReleaseReview {
            snapshot,
            review,
            output,
        } => {
            let Some(snapshot_path) = snapshot else {
                return Err(CliError::Usage(
                    "apply-stream-subscription-release-review requires --snapshot <path>"
                        .to_owned(),
                ));
            };
            let Some(review_path) = review else {
                return Err(CliError::Usage(
                    "apply-stream-subscription-release-review requires --review <path>".to_owned(),
                ));
            };
            let application = apply_stream_subscription_release_review(
                &options.repo_root,
                &snapshot_path,
                &review_path,
            )?;
            let serialized = to_pretty_json(&application)?;
            if let Some(output_path) = output {
                write_text(&output_path, &serialized)?;
            }
            Ok(serialized)
        }
        Command::ReviewStreamSubscriptionRenewal {
            snapshot,
            request,
            clock,
            output,
        } => {
            let Some(snapshot_path) = snapshot else {
                return Err(CliError::Usage(
                    "review-stream-subscription-renewal requires --snapshot <path>".to_owned(),
                ));
            };
            let Some(request_path) = request else {
                return Err(CliError::Usage(
                    "review-stream-subscription-renewal requires --request <path>".to_owned(),
                ));
            };
            let Some(clock_path) = clock else {
                return Err(CliError::Usage(
                    "review-stream-subscription-renewal requires --clock <path>".to_owned(),
                ));
            };
            let review = review_stream_subscription_renewal(
                &options.repo_root,
                &snapshot_path,
                &request_path,
                &clock_path,
            )?;
            let serialized = to_pretty_json(&review)?;
            if let Some(output_path) = output {
                write_text(&output_path, &serialized)?;
            }
            Ok(serialized)
        }
        Command::ApplyStreamSubscriptionRenewalReview {
            snapshot,
            review,
            output,
        } => {
            let Some(snapshot_path) = snapshot else {
                return Err(CliError::Usage(
                    "apply-stream-subscription-renewal-review requires --snapshot <path>"
                        .to_owned(),
                ));
            };
            let Some(review_path) = review else {
                return Err(CliError::Usage(
                    "apply-stream-subscription-renewal-review requires --review <path>".to_owned(),
                ));
            };
            let application = apply_stream_subscription_renewal_review(
                &options.repo_root,
                &snapshot_path,
                &review_path,
            )?;
            let serialized = to_pretty_json(&application)?;
            if let Some(output_path) = output {
                write_text(&output_path, &serialized)?;
            }
            Ok(serialized)
        }
        Command::ReviewAuthorityExpirySweep {
            snapshot,
            request,
            clock,
            output,
        } => {
            let Some(snapshot_path) = snapshot else {
                return Err(CliError::Usage(
                    "review-authority-expiry-sweep requires --snapshot <path>".to_owned(),
                ));
            };
            let Some(request_path) = request else {
                return Err(CliError::Usage(
                    "review-authority-expiry-sweep requires --request <path>".to_owned(),
                ));
            };
            let Some(clock_path) = clock else {
                return Err(CliError::Usage(
                    "review-authority-expiry-sweep requires --clock <path>".to_owned(),
                ));
            };
            let review = review_authority_expiry_sweep(
                &options.repo_root,
                &snapshot_path,
                &request_path,
                &clock_path,
            )?;
            let serialized = to_pretty_json(&review)?;
            if let Some(output_path) = output {
                write_text(&output_path, &serialized)?;
            }
            Ok(serialized)
        }
        Command::ApplyAuthorityExpirySweepReview {
            snapshot,
            review,
            output,
        } => {
            let Some(snapshot_path) = snapshot else {
                return Err(CliError::Usage(
                    "apply-authority-expiry-sweep-review requires --snapshot <path>".to_owned(),
                ));
            };
            let Some(review_path) = review else {
                return Err(CliError::Usage(
                    "apply-authority-expiry-sweep-review requires --review <path>".to_owned(),
                ));
            };
            let application = apply_authority_expiry_sweep_review(
                &options.repo_root,
                &snapshot_path,
                &review_path,
            )?;
            let serialized = to_pretty_json(&application)?;
            if let Some(output_path) = output {
                write_text(&output_path, &serialized)?;
            }
            Ok(serialized)
        }
        Command::ReviewModuleRuntime {
            snapshot,
            request,
            clock,
            output,
        } => {
            let Some(snapshot_path) = snapshot else {
                return Err(CliError::Usage(
                    "review-module-runtime requires --snapshot <path>".to_owned(),
                ));
            };
            let Some(request_path) = request else {
                return Err(CliError::Usage(
                    "review-module-runtime requires --request <path>".to_owned(),
                ));
            };
            let Some(clock_path) = clock else {
                return Err(CliError::Usage(
                    "review-module-runtime requires --clock <path>".to_owned(),
                ));
            };
            let review = review_module_runtime(
                &options.repo_root,
                &snapshot_path,
                &request_path,
                &clock_path,
            )?;
            let serialized = to_pretty_json(&review)?;
            if let Some(output_path) = output {
                write_text(&output_path, &serialized)?;
            }
            Ok(serialized)
        }
        Command::ApplyModuleRuntimeReview {
            snapshot,
            review,
            output,
        } => {
            let Some(snapshot_path) = snapshot else {
                return Err(CliError::Usage(
                    "apply-module-runtime-review requires --snapshot <path>".to_owned(),
                ));
            };
            let Some(review_path) = review else {
                return Err(CliError::Usage(
                    "apply-module-runtime-review requires --review <path>".to_owned(),
                ));
            };
            let application =
                apply_module_runtime_review(&options.repo_root, &snapshot_path, &review_path)?;
            let serialized = to_pretty_json(&application)?;
            if let Some(output_path) = output {
                write_text(&output_path, &serialized)?;
            }
            Ok(serialized)
        }
        Command::ReviewHostManifest {
            snapshot,
            request,
            clock,
            output,
        } => {
            let Some(snapshot_path) = snapshot else {
                return Err(CliError::Usage(
                    "review-host-manifest requires --snapshot <path>".to_owned(),
                ));
            };
            let Some(request_path) = request else {
                return Err(CliError::Usage(
                    "review-host-manifest requires --request <path>".to_owned(),
                ));
            };
            let Some(clock_path) = clock else {
                return Err(CliError::Usage(
                    "review-host-manifest requires --clock <path>".to_owned(),
                ));
            };
            let review = review_host_manifest(
                &options.repo_root,
                &snapshot_path,
                &request_path,
                &clock_path,
            )?;
            let serialized = to_pretty_json(&review)?;
            if let Some(output_path) = output {
                write_text(&output_path, &serialized)?;
            }
            Ok(serialized)
        }
        Command::ApplyHostManifestReview {
            snapshot,
            review,
            output,
        } => {
            let Some(snapshot_path) = snapshot else {
                return Err(CliError::Usage(
                    "apply-host-manifest-review requires --snapshot <path>".to_owned(),
                ));
            };
            let Some(review_path) = review else {
                return Err(CliError::Usage(
                    "apply-host-manifest-review requires --review <path>".to_owned(),
                ));
            };
            let application =
                apply_host_manifest_review(&options.repo_root, &snapshot_path, &review_path)?;
            let serialized = to_pretty_json(&application)?;
            if let Some(output_path) = output {
                write_text(&output_path, &serialized)?;
            }
            Ok(serialized)
        }
        Command::ReviewClock {
            snapshot,
            request,
            clock,
            output,
        } => {
            let Some(snapshot_path) = snapshot else {
                return Err(CliError::Usage(
                    "review-clock requires --snapshot <path>".to_owned(),
                ));
            };
            let Some(request_path) = request else {
                return Err(CliError::Usage(
                    "review-clock requires --request <path>".to_owned(),
                ));
            };
            let Some(clock_path) = clock else {
                return Err(CliError::Usage(
                    "review-clock requires --clock <path>".to_owned(),
                ));
            };
            let review = review_clock(
                &options.repo_root,
                &snapshot_path,
                &request_path,
                &clock_path,
            )?;
            let serialized = to_pretty_json(&review)?;
            if let Some(output_path) = output {
                write_text(&output_path, &serialized)?;
            }
            Ok(serialized)
        }
        Command::ApplyClockReview {
            snapshot,
            review,
            output,
        } => {
            let Some(snapshot_path) = snapshot else {
                return Err(CliError::Usage(
                    "apply-clock-review requires --snapshot <path>".to_owned(),
                ));
            };
            let Some(review_path) = review else {
                return Err(CliError::Usage(
                    "apply-clock-review requires --review <path>".to_owned(),
                ));
            };
            let application = apply_clock_review(&options.repo_root, &snapshot_path, &review_path)?;
            let serialized = to_pretty_json(&application)?;
            if let Some(output_path) = output {
                write_text(&output_path, &serialized)?;
            }
            Ok(serialized)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Options {
    command: Command,
    repo_root: PathBuf,
}

impl Options {
    fn parse(args: Vec<String>) -> Result<Self, CliError> {
        let mut args = args.into_iter();
        let Some(command_text) = args.next() else {
            return Err(CliError::Usage(usage()));
        };

        let command = match command_text.as_str() {
            "validate" => Command::Validate,
            "simulate" => Command::Simulate { check: false },
            "diff" => Command::Diff { check: false },
            "review-shell-handoff" => Command::ReviewShellHandoff {
                handoff: None,
                output: None,
            },
            "review-command" => Command::ReviewCommand {
                snapshot: None,
                envelope: None,
                clock: None,
                output: None,
            },
            "prepare-command-dispatch" => Command::PrepareCommandDispatch {
                snapshot: None,
                review: None,
                output: None,
            },
            "review-lease" => Command::ReviewLease {
                snapshot: None,
                request: None,
                clock: None,
                output: None,
            },
            "apply-lease-review" => Command::ApplyLeaseReview {
                snapshot: None,
                review: None,
                output: None,
            },
            "review-lease-release" => Command::ReviewLeaseRelease {
                snapshot: None,
                request: None,
                clock: None,
                output: None,
            },
            "apply-lease-release-review" => Command::ApplyLeaseReleaseReview {
                snapshot: None,
                review: None,
                output: None,
            },
            "review-lease-renewal" => Command::ReviewLeaseRenewal {
                snapshot: None,
                request: None,
                clock: None,
                output: None,
            },
            "apply-lease-renewal-review" => Command::ApplyLeaseRenewalReview {
                snapshot: None,
                review: None,
                output: None,
            },
            "review-stream-registry" => Command::ReviewStreamRegistry {
                snapshot: None,
                request: None,
                clock: None,
                output: None,
            },
            "apply-stream-registry-review" => Command::ApplyStreamRegistryReview {
                snapshot: None,
                review: None,
                output: None,
            },
            "review-stream-subscription" => Command::ReviewStreamSubscription {
                snapshot: None,
                request: None,
                clock: None,
                output: None,
            },
            "apply-stream-subscription-review" => Command::ApplyStreamSubscriptionReview {
                snapshot: None,
                review: None,
                output: None,
            },
            "review-stream-subscription-release" => Command::ReviewStreamSubscriptionRelease {
                snapshot: None,
                request: None,
                clock: None,
                output: None,
            },
            "apply-stream-subscription-release-review" => {
                Command::ApplyStreamSubscriptionReleaseReview {
                    snapshot: None,
                    review: None,
                    output: None,
                }
            }
            "review-stream-subscription-renewal" => Command::ReviewStreamSubscriptionRenewal {
                snapshot: None,
                request: None,
                clock: None,
                output: None,
            },
            "apply-stream-subscription-renewal-review" => {
                Command::ApplyStreamSubscriptionRenewalReview {
                    snapshot: None,
                    review: None,
                    output: None,
                }
            }
            "review-authority-expiry-sweep" => Command::ReviewAuthorityExpirySweep {
                snapshot: None,
                request: None,
                clock: None,
                output: None,
            },
            "apply-authority-expiry-sweep-review" => Command::ApplyAuthorityExpirySweepReview {
                snapshot: None,
                review: None,
                output: None,
            },
            "review-module-runtime" => Command::ReviewModuleRuntime {
                snapshot: None,
                request: None,
                clock: None,
                output: None,
            },
            "apply-module-runtime-review" => Command::ApplyModuleRuntimeReview {
                snapshot: None,
                review: None,
                output: None,
            },
            "review-host-manifest" => Command::ReviewHostManifest {
                snapshot: None,
                request: None,
                clock: None,
                output: None,
            },
            "apply-host-manifest-review" => Command::ApplyHostManifestReview {
                snapshot: None,
                review: None,
                output: None,
            },
            "review-clock" => Command::ReviewClock {
                snapshot: None,
                request: None,
                clock: None,
                output: None,
            },
            "apply-clock-review" => Command::ApplyClockReview {
                snapshot: None,
                review: None,
                output: None,
            },
            "-h" | "--help" | "help" => return Err(CliError::Usage(usage())),
            other => return Err(CliError::UnknownCommand(other.to_owned())),
        };

        let mut repo_root = default_repo_root();
        let mut command = command;

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--repo-root" => {
                    let Some(value) = args.next() else {
                        return Err(CliError::Usage("--repo-root requires a value".to_owned()));
                    };
                    repo_root = PathBuf::from(value);
                }
                "--check" => match &mut command {
                    Command::Simulate { check } | Command::Diff { check } => *check = true,
                    Command::Validate
                    | Command::ReviewShellHandoff { .. }
                    | Command::ReviewCommand { .. }
                    | Command::PrepareCommandDispatch { .. }
                    | Command::ReviewLease { .. }
                    | Command::ApplyLeaseReview { .. }
                    | Command::ReviewLeaseRelease { .. }
                    | Command::ApplyLeaseReleaseReview { .. }
                    | Command::ReviewLeaseRenewal { .. }
                    | Command::ApplyLeaseRenewalReview { .. }
                    | Command::ReviewStreamRegistry { .. }
                    | Command::ApplyStreamRegistryReview { .. }
                    | Command::ReviewStreamSubscription { .. }
                    | Command::ApplyStreamSubscriptionReview { .. }
                    | Command::ReviewStreamSubscriptionRelease { .. }
                    | Command::ApplyStreamSubscriptionReleaseReview { .. }
                    | Command::ReviewStreamSubscriptionRenewal { .. }
                    | Command::ApplyStreamSubscriptionRenewalReview { .. }
                    | Command::ReviewAuthorityExpirySweep { .. }
                    | Command::ApplyAuthorityExpirySweepReview { .. }
                    | Command::ReviewModuleRuntime { .. }
                    | Command::ApplyModuleRuntimeReview { .. }
                    | Command::ReviewHostManifest { .. }
                    | Command::ApplyHostManifestReview { .. }
                    | Command::ReviewClock { .. }
                    | Command::ApplyClockReview { .. } => {
                        return Err(CliError::Usage(
                            "--check is only valid for simulate or diff".to_owned(),
                        ));
                    }
                },
                "--handoff" => {
                    let Some(value) = args.next() else {
                        return Err(CliError::Usage("--handoff requires a value".to_owned()));
                    };
                    match &mut command {
                        Command::ReviewShellHandoff { handoff, .. } => {
                            *handoff = Some(PathBuf::from(value));
                        }
                        Command::Validate
                        | Command::Simulate { .. }
                        | Command::Diff { .. }
                        | Command::ReviewCommand { .. }
                        | Command::PrepareCommandDispatch { .. }
                        | Command::ReviewLease { .. }
                        | Command::ApplyLeaseReview { .. }
                        | Command::ReviewLeaseRelease { .. }
                        | Command::ApplyLeaseReleaseReview { .. }
                        | Command::ReviewLeaseRenewal { .. }
                        | Command::ApplyLeaseRenewalReview { .. }
                        | Command::ReviewStreamRegistry { .. }
                        | Command::ApplyStreamRegistryReview { .. }
                        | Command::ReviewStreamSubscription { .. }
                        | Command::ApplyStreamSubscriptionReview { .. }
                        | Command::ReviewStreamSubscriptionRelease { .. }
                        | Command::ApplyStreamSubscriptionReleaseReview { .. }
                        | Command::ReviewStreamSubscriptionRenewal { .. }
                        | Command::ApplyStreamSubscriptionRenewalReview { .. }
                        | Command::ReviewAuthorityExpirySweep { .. }
                        | Command::ApplyAuthorityExpirySweepReview { .. }
                        | Command::ReviewModuleRuntime { .. }
                        | Command::ApplyModuleRuntimeReview { .. }
                        | Command::ReviewHostManifest { .. }
                        | Command::ApplyHostManifestReview { .. }
                        | Command::ReviewClock { .. }
                        | Command::ApplyClockReview { .. } => {
                            return Err(CliError::Usage(
                                "--handoff is only valid for review-shell-handoff".to_owned(),
                            ))
                        }
                    }
                }
                "--snapshot" => {
                    let Some(value) = args.next() else {
                        return Err(CliError::Usage("--snapshot requires a value".to_owned()));
                    };
                    match &mut command {
                        Command::ReviewCommand { snapshot, .. }
                        | Command::PrepareCommandDispatch { snapshot, .. }
                        | Command::ReviewLease { snapshot, .. }
                        | Command::ApplyLeaseReview { snapshot, .. }
                        | Command::ReviewLeaseRelease { snapshot, .. }
                        | Command::ApplyLeaseReleaseReview { snapshot, .. }
                        | Command::ReviewLeaseRenewal { snapshot, .. }
                        | Command::ApplyLeaseRenewalReview { snapshot, .. }
                        | Command::ReviewStreamRegistry { snapshot, .. }
                        | Command::ApplyStreamRegistryReview { snapshot, .. }
                        | Command::ReviewStreamSubscription { snapshot, .. }
                        | Command::ApplyStreamSubscriptionReview { snapshot, .. }
                        | Command::ReviewStreamSubscriptionRelease { snapshot, .. }
                        | Command::ApplyStreamSubscriptionReleaseReview { snapshot, .. }
                        | Command::ReviewStreamSubscriptionRenewal { snapshot, .. }
                        | Command::ApplyStreamSubscriptionRenewalReview { snapshot, .. }
                        | Command::ReviewAuthorityExpirySweep { snapshot, .. }
                        | Command::ApplyAuthorityExpirySweepReview { snapshot, .. }
                        | Command::ReviewModuleRuntime { snapshot, .. }
                        | Command::ApplyModuleRuntimeReview { snapshot, .. }
                        | Command::ReviewHostManifest { snapshot, .. }
                        | Command::ApplyHostManifestReview { snapshot, .. }
                        | Command::ReviewClock { snapshot, .. }
                        | Command::ApplyClockReview { snapshot, .. } => {
                            *snapshot = Some(PathBuf::from(value));
                        }
                        Command::Validate
                        | Command::Simulate { .. }
                        | Command::Diff { .. }
                        | Command::ReviewShellHandoff { .. } => {
                            return Err(CliError::Usage(
                                "--snapshot is only valid for review-command, prepare-command-dispatch, review-lease, apply-lease-review, review-lease-release, apply-lease-release-review, review-lease-renewal, apply-lease-renewal-review, review-stream-registry, apply-stream-registry-review, review-stream-subscription, apply-stream-subscription-review, review-stream-subscription-release, apply-stream-subscription-release-review, review-stream-subscription-renewal, apply-stream-subscription-renewal-review, review-authority-expiry-sweep, apply-authority-expiry-sweep-review, review-module-runtime, apply-module-runtime-review, review-host-manifest, apply-host-manifest-review, review-clock, or apply-clock-review"
                                    .to_owned(),
                            ))
                        }
                    }
                }
                "--envelope" => {
                    let Some(value) = args.next() else {
                        return Err(CliError::Usage("--envelope requires a value".to_owned()));
                    };
                    match &mut command {
                        Command::ReviewCommand { envelope, .. } => {
                            *envelope = Some(PathBuf::from(value));
                        }
                        Command::Validate
                        | Command::Simulate { .. }
                        | Command::Diff { .. }
                        | Command::ReviewShellHandoff { .. }
                        | Command::ReviewLease { .. }
                        | Command::PrepareCommandDispatch { .. }
                        | Command::ApplyLeaseReview { .. }
                        | Command::ReviewLeaseRelease { .. }
                        | Command::ApplyLeaseReleaseReview { .. }
                        | Command::ReviewLeaseRenewal { .. }
                        | Command::ApplyLeaseRenewalReview { .. }
                        | Command::ReviewStreamRegistry { .. }
                        | Command::ApplyStreamRegistryReview { .. }
                        | Command::ReviewStreamSubscription { .. }
                        | Command::ApplyStreamSubscriptionReview { .. }
                        | Command::ReviewStreamSubscriptionRelease { .. }
                        | Command::ApplyStreamSubscriptionReleaseReview { .. }
                        | Command::ReviewStreamSubscriptionRenewal { .. }
                        | Command::ApplyStreamSubscriptionRenewalReview { .. }
                        | Command::ReviewAuthorityExpirySweep { .. }
                        | Command::ApplyAuthorityExpirySweepReview { .. }
                        | Command::ReviewModuleRuntime { .. }
                        | Command::ApplyModuleRuntimeReview { .. }
                        | Command::ReviewHostManifest { .. }
                        | Command::ApplyHostManifestReview { .. }
                        | Command::ReviewClock { .. }
                        | Command::ApplyClockReview { .. } => {
                            return Err(CliError::Usage(
                                "--envelope is only valid for review-command".to_owned(),
                            ))
                        }
                    }
                }
                "--request" => {
                    let Some(value) = args.next() else {
                        return Err(CliError::Usage("--request requires a value".to_owned()));
                    };
                    match &mut command {
                        Command::ReviewLease { request, .. }
                        | Command::ReviewLeaseRelease { request, .. }
                        | Command::ReviewLeaseRenewal { request, .. }
                        | Command::ReviewStreamRegistry { request, .. }
                        | Command::ReviewStreamSubscription { request, .. }
                        | Command::ReviewStreamSubscriptionRelease { request, .. }
                        | Command::ReviewStreamSubscriptionRenewal { request, .. }
                        | Command::ReviewAuthorityExpirySweep { request, .. }
                        | Command::ReviewModuleRuntime { request, .. }
                        | Command::ReviewHostManifest { request, .. }
                        | Command::ReviewClock { request, .. } => {
                            *request = Some(PathBuf::from(value));
                        }
                        Command::Validate
                        | Command::Simulate { .. }
                        | Command::Diff { .. }
                        | Command::ReviewShellHandoff { .. }
                        | Command::ReviewCommand { .. }
                        | Command::PrepareCommandDispatch { .. }
                        | Command::ApplyLeaseReview { .. }
                        | Command::ApplyLeaseReleaseReview { .. }
                        | Command::ApplyLeaseRenewalReview { .. }
                        | Command::ApplyStreamRegistryReview { .. }
                        | Command::ApplyStreamSubscriptionReview { .. } => return Err(CliError::Usage(
                            "--request is only valid for review-lease, review-lease-release, review-lease-renewal, review-stream-registry, review-stream-subscription, review-stream-subscription-release, review-stream-subscription-renewal, review-authority-expiry-sweep, review-module-runtime, review-host-manifest, or review-clock"
                                .to_owned(),
                        )),
                        Command::ApplyStreamSubscriptionReleaseReview { .. }
                        | Command::ApplyStreamSubscriptionRenewalReview { .. }
                        | Command::ApplyAuthorityExpirySweepReview { .. }
                        | Command::ApplyModuleRuntimeReview { .. }
                        | Command::ApplyHostManifestReview { .. }
                        | Command::ApplyClockReview { .. } => {
                            return Err(CliError::Usage(
                                "--request is only valid for review-lease, review-lease-release, review-lease-renewal, review-stream-registry, review-stream-subscription, review-stream-subscription-release, review-stream-subscription-renewal, review-authority-expiry-sweep, review-module-runtime, review-host-manifest, or review-clock"
                                    .to_owned(),
                            ))
                        }
                    }
                }
                "--review" => {
                    let Some(value) = args.next() else {
                        return Err(CliError::Usage("--review requires a value".to_owned()));
                    };
                    match &mut command {
                        Command::PrepareCommandDispatch { review, .. }
                        | Command::ApplyLeaseReview { review, .. }
                        | Command::ApplyLeaseReleaseReview { review, .. }
                        | Command::ApplyLeaseRenewalReview { review, .. }
                        | Command::ApplyStreamRegistryReview { review, .. }
                        | Command::ApplyStreamSubscriptionReview { review, .. }
                        | Command::ApplyStreamSubscriptionReleaseReview { review, .. }
                        | Command::ApplyStreamSubscriptionRenewalReview { review, .. }
                        | Command::ApplyAuthorityExpirySweepReview { review, .. }
                        | Command::ApplyModuleRuntimeReview { review, .. }
                        | Command::ApplyHostManifestReview { review, .. }
                        | Command::ApplyClockReview { review, .. } => {
                            *review = Some(PathBuf::from(value));
                        }
                        Command::Validate
                        | Command::Simulate { .. }
                        | Command::Diff { .. }
                        | Command::ReviewShellHandoff { .. }
                        | Command::ReviewCommand { .. }
                        | Command::ReviewLease { .. }
                        | Command::ReviewLeaseRelease { .. }
                        | Command::ReviewLeaseRenewal { .. }
                        | Command::ReviewStreamRegistry { .. }
                        | Command::ReviewStreamSubscription { .. }
                        | Command::ReviewStreamSubscriptionRelease { .. }
                        | Command::ReviewStreamSubscriptionRenewal { .. }
                        | Command::ReviewAuthorityExpirySweep { .. }
                        | Command::ReviewModuleRuntime { .. }
                        | Command::ReviewHostManifest { .. }
                        | Command::ReviewClock { .. } => {
                            return Err(CliError::Usage(
                                "--review is only valid for prepare-command-dispatch, apply-lease-review, apply-lease-release-review, apply-lease-renewal-review, apply-stream-registry-review, apply-stream-subscription-review, apply-stream-subscription-release-review, apply-stream-subscription-renewal-review, apply-authority-expiry-sweep-review, apply-module-runtime-review, apply-host-manifest-review, or apply-clock-review"
                                    .to_owned(),
                            ));
                        }
                    }
                }
                "--clock" => {
                    let Some(value) = args.next() else {
                        return Err(CliError::Usage("--clock requires a value".to_owned()));
                    };
                    match &mut command {
                        Command::ReviewCommand { clock, .. }
                        | Command::ReviewLease { clock, .. }
                        | Command::ReviewLeaseRelease { clock, .. }
                        | Command::ReviewLeaseRenewal { clock, .. }
                        | Command::ReviewStreamRegistry { clock, .. }
                        | Command::ReviewStreamSubscription { clock, .. }
                        | Command::ReviewStreamSubscriptionRelease { clock, .. }
                        | Command::ReviewStreamSubscriptionRenewal { clock, .. }
                        | Command::ReviewAuthorityExpirySweep { clock, .. }
                        | Command::ReviewModuleRuntime { clock, .. }
                        | Command::ReviewHostManifest { clock, .. }
                        | Command::ReviewClock { clock, .. } => {
                            *clock = Some(PathBuf::from(value));
                        }
                        Command::Validate
                        | Command::Simulate { .. }
                        | Command::Diff { .. }
                        | Command::ReviewShellHandoff { .. }
                        | Command::PrepareCommandDispatch { .. }
                        | Command::ApplyLeaseReview { .. }
                        | Command::ApplyLeaseReleaseReview { .. }
                        | Command::ApplyLeaseRenewalReview { .. }
                        | Command::ApplyStreamRegistryReview { .. }
                        | Command::ApplyStreamSubscriptionReview { .. }
                        | Command::ApplyStreamSubscriptionReleaseReview { .. }
                        | Command::ApplyStreamSubscriptionRenewalReview { .. }
                        | Command::ApplyAuthorityExpirySweepReview { .. }
                        | Command::ApplyModuleRuntimeReview { .. }
                        | Command::ApplyHostManifestReview { .. }
                        | Command::ApplyClockReview { .. } => {
                            return Err(CliError::Usage(
                                "--clock is only valid for review-command, review-lease, review-lease-release, review-lease-renewal, review-stream-registry, review-stream-subscription, review-stream-subscription-release, review-stream-subscription-renewal, review-authority-expiry-sweep, review-module-runtime, review-host-manifest, or review-clock"
                                    .to_owned(),
                            ))
                        }
                    }
                }
                "--output" => {
                    let Some(value) = args.next() else {
                        return Err(CliError::Usage("--output requires a value".to_owned()));
                    };
                    match &mut command {
                        Command::ReviewShellHandoff { output, .. } => {
                            *output = Some(PathBuf::from(value));
                        }
                        Command::ReviewCommand { output, .. } => {
                            *output = Some(PathBuf::from(value));
                        }
                        Command::PrepareCommandDispatch { output, .. } => {
                            *output = Some(PathBuf::from(value));
                        }
                        Command::ReviewLease { output, .. } => {
                            *output = Some(PathBuf::from(value));
                        }
                        Command::ApplyLeaseReview { output, .. } => {
                            *output = Some(PathBuf::from(value));
                        }
                        Command::ReviewLeaseRelease { output, .. } => {
                            *output = Some(PathBuf::from(value));
                        }
                        Command::ApplyLeaseReleaseReview { output, .. } => {
                            *output = Some(PathBuf::from(value));
                        }
                        Command::ReviewLeaseRenewal { output, .. } => {
                            *output = Some(PathBuf::from(value));
                        }
                        Command::ApplyLeaseRenewalReview { output, .. } => {
                            *output = Some(PathBuf::from(value));
                        }
                        Command::ReviewStreamRegistry { output, .. } => {
                            *output = Some(PathBuf::from(value));
                        }
                        Command::ApplyStreamRegistryReview { output, .. } => {
                            *output = Some(PathBuf::from(value));
                        }
                        Command::ReviewStreamSubscription { output, .. } => {
                            *output = Some(PathBuf::from(value));
                        }
                        Command::ApplyStreamSubscriptionReview { output, .. } => {
                            *output = Some(PathBuf::from(value));
                        }
                        Command::ReviewStreamSubscriptionRelease { output, .. } => {
                            *output = Some(PathBuf::from(value));
                        }
                        Command::ApplyStreamSubscriptionReleaseReview { output, .. } => {
                            *output = Some(PathBuf::from(value));
                        }
                        Command::ReviewStreamSubscriptionRenewal { output, .. } => {
                            *output = Some(PathBuf::from(value));
                        }
                        Command::ApplyStreamSubscriptionRenewalReview { output, .. } => {
                            *output = Some(PathBuf::from(value));
                        }
                        Command::ReviewAuthorityExpirySweep { output, .. } => {
                            *output = Some(PathBuf::from(value));
                        }
                        Command::ApplyAuthorityExpirySweepReview { output, .. } => {
                            *output = Some(PathBuf::from(value));
                        }
                        Command::ReviewModuleRuntime { output, .. } => {
                            *output = Some(PathBuf::from(value));
                        }
                        Command::ApplyModuleRuntimeReview { output, .. } => {
                            *output = Some(PathBuf::from(value));
                        }
                        Command::ReviewHostManifest { output, .. } => {
                            *output = Some(PathBuf::from(value));
                        }
                        Command::ApplyHostManifestReview { output, .. } => {
                            *output = Some(PathBuf::from(value));
                        }
                        Command::ReviewClock { output, .. } => {
                            *output = Some(PathBuf::from(value));
                        }
                        Command::ApplyClockReview { output, .. } => {
                            *output = Some(PathBuf::from(value));
                        }
                        Command::Validate | Command::Simulate { .. } | Command::Diff { .. } => {
                            return Err(CliError::Usage(
                                "--output is only valid for review-shell-handoff, review-command, prepare-command-dispatch, review-lease, apply-lease-review, review-lease-release, apply-lease-release-review, review-lease-renewal, apply-lease-renewal-review, review-stream-registry, apply-stream-registry-review, review-stream-subscription, apply-stream-subscription-review, review-stream-subscription-release, apply-stream-subscription-release-review, review-stream-subscription-renewal, apply-stream-subscription-renewal-review, review-authority-expiry-sweep, apply-authority-expiry-sweep-review, review-module-runtime, apply-module-runtime-review, review-host-manifest, apply-host-manifest-review, review-clock, or apply-clock-review"
                                    .to_owned(),
                            ));
                        }
                    }
                }
                "-h" | "--help" => return Err(CliError::Usage(usage())),
                other => return Err(CliError::UnknownOption(other.to_owned())),
            }
        }

        Ok(Self { command, repo_root })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Command {
    Validate,
    Simulate {
        check: bool,
    },
    Diff {
        check: bool,
    },
    ReviewShellHandoff {
        handoff: Option<PathBuf>,
        output: Option<PathBuf>,
    },
    ReviewCommand {
        snapshot: Option<PathBuf>,
        envelope: Option<PathBuf>,
        clock: Option<PathBuf>,
        output: Option<PathBuf>,
    },
    PrepareCommandDispatch {
        snapshot: Option<PathBuf>,
        review: Option<PathBuf>,
        output: Option<PathBuf>,
    },
    ReviewLease {
        snapshot: Option<PathBuf>,
        request: Option<PathBuf>,
        clock: Option<PathBuf>,
        output: Option<PathBuf>,
    },
    ApplyLeaseReview {
        snapshot: Option<PathBuf>,
        review: Option<PathBuf>,
        output: Option<PathBuf>,
    },
    ReviewLeaseRelease {
        snapshot: Option<PathBuf>,
        request: Option<PathBuf>,
        clock: Option<PathBuf>,
        output: Option<PathBuf>,
    },
    ApplyLeaseReleaseReview {
        snapshot: Option<PathBuf>,
        review: Option<PathBuf>,
        output: Option<PathBuf>,
    },
    ReviewLeaseRenewal {
        snapshot: Option<PathBuf>,
        request: Option<PathBuf>,
        clock: Option<PathBuf>,
        output: Option<PathBuf>,
    },
    ApplyLeaseRenewalReview {
        snapshot: Option<PathBuf>,
        review: Option<PathBuf>,
        output: Option<PathBuf>,
    },
    ReviewStreamRegistry {
        snapshot: Option<PathBuf>,
        request: Option<PathBuf>,
        clock: Option<PathBuf>,
        output: Option<PathBuf>,
    },
    ApplyStreamRegistryReview {
        snapshot: Option<PathBuf>,
        review: Option<PathBuf>,
        output: Option<PathBuf>,
    },
    ReviewStreamSubscription {
        snapshot: Option<PathBuf>,
        request: Option<PathBuf>,
        clock: Option<PathBuf>,
        output: Option<PathBuf>,
    },
    ApplyStreamSubscriptionReview {
        snapshot: Option<PathBuf>,
        review: Option<PathBuf>,
        output: Option<PathBuf>,
    },
    ReviewStreamSubscriptionRelease {
        snapshot: Option<PathBuf>,
        request: Option<PathBuf>,
        clock: Option<PathBuf>,
        output: Option<PathBuf>,
    },
    ApplyStreamSubscriptionReleaseReview {
        snapshot: Option<PathBuf>,
        review: Option<PathBuf>,
        output: Option<PathBuf>,
    },
    ReviewStreamSubscriptionRenewal {
        snapshot: Option<PathBuf>,
        request: Option<PathBuf>,
        clock: Option<PathBuf>,
        output: Option<PathBuf>,
    },
    ApplyStreamSubscriptionRenewalReview {
        snapshot: Option<PathBuf>,
        review: Option<PathBuf>,
        output: Option<PathBuf>,
    },
    ReviewAuthorityExpirySweep {
        snapshot: Option<PathBuf>,
        request: Option<PathBuf>,
        clock: Option<PathBuf>,
        output: Option<PathBuf>,
    },
    ApplyAuthorityExpirySweepReview {
        snapshot: Option<PathBuf>,
        review: Option<PathBuf>,
        output: Option<PathBuf>,
    },
    ReviewModuleRuntime {
        snapshot: Option<PathBuf>,
        request: Option<PathBuf>,
        clock: Option<PathBuf>,
        output: Option<PathBuf>,
    },
    ApplyModuleRuntimeReview {
        snapshot: Option<PathBuf>,
        review: Option<PathBuf>,
        output: Option<PathBuf>,
    },
    ReviewHostManifest {
        snapshot: Option<PathBuf>,
        request: Option<PathBuf>,
        clock: Option<PathBuf>,
        output: Option<PathBuf>,
    },
    ApplyHostManifestReview {
        snapshot: Option<PathBuf>,
        review: Option<PathBuf>,
        output: Option<PathBuf>,
    },
    ReviewClock {
        snapshot: Option<PathBuf>,
        request: Option<PathBuf>,
        clock: Option<PathBuf>,
        output: Option<PathBuf>,
    },
    ApplyClockReview {
        snapshot: Option<PathBuf>,
        review: Option<PathBuf>,
        output: Option<PathBuf>,
    },
}

fn validate_repo(repo_root: &Path) -> Result<ValidationReport, CliError> {
    let fixtures = FixtureSet::load(repo_root)?;
    let mut checks = Vec::new();
    let module_ids = fixtures
        .module_manifests
        .iter()
        .map(|module| module.module_id.clone())
        .collect::<Vec<_>>();
    let endpoint_ids = fixtures.endpoint_ids();

    push_valid_checks(&mut checks, &fixtures, &module_ids, &endpoint_ids);
    push_damaged_checks(
        repo_root,
        &mut checks,
        &fixtures,
        &module_ids,
        &endpoint_ids,
    )?;

    let failed = checks.iter().any(|check| check.status == "fail");
    Ok(ValidationReport {
        schema_id: "rusty.manifold.validation.fixture_report.v1".to_owned(),
        status: if failed { "fail" } else { "pass" }.to_owned(),
        checks,
    })
}

fn push_valid_checks(
    checks: &mut Vec<ValidationCheckReport>,
    fixtures: &FixtureSet,
    module_ids: &[DottedId],
    endpoint_ids: &[DottedId],
) {
    checks.push(pass(
        "validation.check.valid_fixture_deserialize",
        "valid fixtures deserialize into typed contract models",
    ));

    push_result(
        checks,
        "validation.check.host_endpoint_security",
        fixtures.valid_host.validate_endpoint_security(),
        "valid host endpoint visibility and security pairing accepted",
    );

    for host in &fixtures.platform_hosts {
        let check_id = format!("validation.check.{}_endpoint_security", host.host_id);
        push_result(
            checks,
            &check_id,
            host.validate_endpoint_security(),
            "platform host endpoint visibility and security pairing accepted",
        );
    }

    push_result(
        checks,
        "validation.check.graph_links",
        fixtures.valid_graph.validate_links(module_ids),
        "graph nodes and edges reference known modules and graph nodes",
    );

    push_result(
        checks,
        "validation.check.stream_registry_links",
        fixtures.valid_registry.validate_source_modules(module_ids),
        "stream registry source modules are known",
    );

    push_result(
        checks,
        "validation.check.stream_registry_transport_endpoints",
        fixtures
            .valid_registry
            .validate_transport_endpoints(endpoint_ids),
        "endpoint-bound stream transport offers reference advertised host endpoints",
    );

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
        "validation.check.lease_authority_audit_event",
        fixtures
            .lease_authority_audit_event
            .validate_against_snapshot(&fixtures.authority_snapshot),
        "lease authority audit event matches the accepted request, lease, clock, and snapshot",
    );

    push_result(
        checks,
        "validation.check.lease_authority_rejection_fixture",
        if fixtures.lease_rejection.rejection_code.as_str() == "stale_revision"
            && fixtures.lease_rejection.retryable
            && fixtures.lease_rejection.current_revision == Revision::INITIAL
            && fixtures.lease_rejection.conflicting_lease_id.is_none()
        {
            Ok(())
        } else {
            Err(
                "standalone lease rejection fixture is not the expected stale-revision rejection"
                    .to_owned(),
            )
        },
        "standalone lease rejection fixture is a non-conflict stale-revision rejection",
    );

    push_result(
        checks,
        "validation.check.lease_authority_review_accepted",
        lease_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.lease_request,
            &fixtures.command_review_clock,
            &fixtures.accepted_lease_review,
        ),
        "lease authority evaluator deterministically accepts an available graph lease",
    );

    push_result(
        checks,
        "validation.check.lease_authority_review_stale_revision",
        lease_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.stale_lease_request,
            &fixtures.command_review_clock,
            &fixtures.stale_revision_lease_review,
        ),
        "lease authority evaluator deterministically rejects stale lease revisions",
    );

    push_result(
        checks,
        "validation.check.lease_authority_review_zero_ttl",
        lease_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.zero_ttl_lease_request,
            &fixtures.command_review_clock,
            &fixtures.zero_ttl_lease_review,
        ),
        "lease authority evaluator deterministically rejects zero-duration leases",
    );

    push_result(
        checks,
        "validation.check.lease_authority_review_missing_capability",
        lease_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.missing_capability_lease_request,
            &fixtures.command_review_clock,
            &fixtures.missing_capability_lease_review,
        ),
        "lease authority evaluator deterministically rejects unadvertised capabilities",
    );

    push_result(
        checks,
        "validation.check.lease_authority_review_busy_scope",
        lease_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.busy_scope_lease_request,
            &fixtures.command_review_clock,
            &fixtures.busy_scope_lease_review,
        ),
        "lease authority evaluator deterministically rejects active-lease scope conflicts",
    );

    push_result(
        checks,
        "validation.check.lease_authority_application_rejection_fixture",
        if fixtures.lease_application_rejection.rejection_code.as_str() == "review_rejected"
            && fixtures
                .lease_application_rejection
                .current_authority_revision
                == Revision::INITIAL
        {
            Ok(())
        } else {
            Err("standalone lease application rejection fixture is not the expected review-rejected rejection"
                .to_owned())
        },
        "standalone lease application rejection fixture is a review-rejected rejection",
    );

    push_result(
        checks,
        "validation.check.lease_authority_application_accepted",
        lease_application_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.accepted_lease_review,
            &fixtures.accepted_lease_application,
        ),
        "lease authority application deterministically advances accepted lease state",
    );

    push_result(
        checks,
        "validation.check.lease_authority_application_rejected",
        lease_application_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.stale_revision_lease_review,
            &fixtures.rejected_lease_application,
        ),
        "lease authority application deterministically rejects rejected lease reviews",
    );

    let lease_release_authority_revision = Revision::new(2).expect("revision literal is valid");
    push_result(
        checks,
        "validation.check.lease_release_authority_snapshot",
        fixtures
            .lease_active_authority_snapshot
            .validate_authority_links(),
        "lease release authority snapshot has the accepted active lease from lease application",
    );

    push_result(
        checks,
        "validation.check.lease_release_request_fixture",
        if fixtures
            .lease_active_authority_snapshot
            .active_leases
            .iter()
            .any(|lease| {
                lease.lease_id == fixtures.lease_release_request.lease_id
                    && lease.holder_id == fixtures.lease_release_request.holder_id
                    && lease.scope == fixtures.lease_release_request.scope
            })
            && fixtures.lease_release_request.expected_authority_revision
                == fixtures.lease_active_authority_snapshot.authority_revision
        {
            Ok(())
        } else {
            Err("lease release request does not target the active lease snapshot".to_owned())
        },
        "lease release request targets an accepted active lease",
    );

    push_result(
        checks,
        "validation.check.lease_release_rejection_fixture",
        if fixtures.lease_release_rejection.rejection_code.as_str() == "stale_revision"
            && fixtures.lease_release_rejection.retryable
            && fixtures.lease_release_rejection.current_revision == lease_release_authority_revision
            && fixtures.lease_release_rejection.active_lease_count
                == fixtures.lease_active_authority_snapshot.active_leases.len()
        {
            Ok(())
        } else {
            Err("standalone lease release rejection fixture is not the expected stale-revision rejection".to_owned())
        },
        "standalone lease release rejection fixture is a stale-revision rejection",
    );

    push_result(
        checks,
        "validation.check.lease_release_authority_audit_event",
        fixtures
            .lease_release_authority_audit_event
            .validate_against_snapshot(&fixtures.lease_active_authority_snapshot),
        "lease release authority audit event matches the accepted request, clock, and active snapshot",
    );

    push_result(
        checks,
        "validation.check.lease_release_authority_review_accepted",
        lease_release_review_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.lease_release_request,
            &fixtures.command_review_clock,
            &fixtures.accepted_lease_release_review,
        ),
        "lease release authority evaluator deterministically accepts active lease release",
    );

    push_result(
        checks,
        "validation.check.lease_release_authority_review_expired_lease",
        lease_release_review_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.lease_release_request,
            &fixtures.expired_command_review_clock,
            &fixtures.expired_lease_release_review,
        ),
        "lease release authority evaluator deterministically rejects leases expired at the review clock",
    );

    push_result(
        checks,
        "validation.check.lease_release_authority_review_stale_revision",
        lease_release_review_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.stale_lease_release_request,
            &fixtures.command_review_clock,
            &fixtures.stale_lease_release_review,
        ),
        "lease release authority evaluator deterministically rejects stale authority revisions",
    );

    push_result(
        checks,
        "validation.check.lease_release_authority_review_unknown_lease",
        lease_release_review_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.unknown_lease_release_request,
            &fixtures.command_review_clock,
            &fixtures.unknown_lease_release_review,
        ),
        "lease release authority evaluator deterministically rejects unknown leases",
    );

    push_result(
        checks,
        "validation.check.lease_release_authority_review_holder_mismatch",
        lease_release_review_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.holder_mismatch_lease_release_request,
            &fixtures.command_review_clock,
            &fixtures.holder_mismatch_lease_release_review,
        ),
        "lease release authority evaluator deterministically rejects holder mismatches",
    );

    push_result(
        checks,
        "validation.check.lease_release_authority_review_scope_mismatch",
        lease_release_review_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.scope_mismatch_lease_release_request,
            &fixtures.command_review_clock,
            &fixtures.scope_mismatch_lease_release_review,
        ),
        "lease release authority evaluator deterministically rejects scope mismatches",
    );

    push_result(
        checks,
        "validation.check.lease_release_authority_application_rejection_fixture",
        if fixtures
            .lease_release_application_rejection
            .rejection_code
            .as_str()
            == "review_rejected"
            && fixtures
                .lease_release_application_rejection
                .current_authority_revision
                == lease_release_authority_revision
        {
            Ok(())
        } else {
            Err("standalone lease release application rejection fixture is not the expected review-rejected rejection"
                .to_owned())
        },
        "standalone lease release application rejection fixture is a review-rejected rejection",
    );

    push_result(
        checks,
        "validation.check.lease_release_authority_application_accepted",
        lease_release_application_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.accepted_lease_release_review,
            &fixtures.accepted_lease_release_application,
        ),
        "lease release authority application deterministically removes accepted active lease state",
    );

    push_result(
        checks,
        "validation.check.lease_release_authority_application_rejected",
        lease_release_application_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.stale_lease_release_review,
            &fixtures.rejected_lease_release_application,
        ),
        "lease release authority application deterministically rejects rejected release reviews",
    );

    let lease_renewal_expected_expires_at_ms =
        u64::try_from(fixtures.command_review_clock.wall_unix_ms)
            .unwrap_or_default()
            .saturating_add(fixtures.lease_renewal_request.requested_ttl_ms);
    push_result(
        checks,
        "validation.check.lease_renewal_request_fixture",
        match fixtures
            .lease_active_authority_snapshot
            .active_leases
            .iter()
            .find(|lease| {
                lease.lease_id == fixtures.lease_renewal_request.lease_id
                    && lease.holder_id == fixtures.lease_renewal_request.holder_id
                    && lease.scope == fixtures.lease_renewal_request.scope
            }) {
            Some(lease)
                if fixtures.lease_renewal_request.expected_authority_revision
                    == fixtures.lease_active_authority_snapshot.authority_revision
                    && fixtures.lease_renewal_request.requested_ttl_ms > 0
                    && lease_renewal_expected_expires_at_ms > lease.expires_at_ms =>
            {
                Ok(())
            }
            _ => Err("lease renewal request does not extend the active lease snapshot".to_owned()),
        },
        "lease renewal request targets and extends an accepted active lease",
    );

    push_result(
        checks,
        "validation.check.lease_renewal_rejection_fixture",
        if fixtures.lease_renewal_rejection.rejection_code.as_str() == "stale_revision"
            && fixtures.lease_renewal_rejection.retryable
            && fixtures.lease_renewal_rejection.current_revision == lease_release_authority_revision
            && fixtures.lease_renewal_rejection.active_lease_count
                == fixtures.lease_active_authority_snapshot.active_leases.len()
            && fixtures
                .lease_renewal_rejection
                .current_expires_at_ms
                .is_none()
        {
            Ok(())
        } else {
            Err("standalone lease renewal rejection fixture is not the expected stale-revision rejection".to_owned())
        },
        "standalone lease renewal rejection fixture is a stale-revision rejection",
    );

    push_result(
        checks,
        "validation.check.lease_renewal_authority_audit_event",
        fixtures
            .lease_renewal_authority_audit_event
            .validate_against_snapshot(&fixtures.lease_active_authority_snapshot),
        "lease renewal authority audit event matches the accepted request, clock, and active snapshot",
    );

    push_result(
        checks,
        "validation.check.lease_renewal_authority_review_accepted",
        lease_renewal_review_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.lease_renewal_request,
            &fixtures.command_review_clock,
            &fixtures.accepted_lease_renewal_review,
        ),
        "lease renewal authority evaluator deterministically accepts active lease renewal",
    );

    push_result(
        checks,
        "validation.check.lease_renewal_authority_review_stale_revision",
        lease_renewal_review_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.stale_lease_renewal_request,
            &fixtures.command_review_clock,
            &fixtures.stale_lease_renewal_review,
        ),
        "lease renewal authority evaluator deterministically rejects stale authority revisions",
    );

    push_result(
        checks,
        "validation.check.lease_renewal_authority_review_unknown_lease",
        lease_renewal_review_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.unknown_lease_renewal_request,
            &fixtures.command_review_clock,
            &fixtures.unknown_lease_renewal_review,
        ),
        "lease renewal authority evaluator deterministically rejects unknown leases",
    );

    push_result(
        checks,
        "validation.check.lease_renewal_authority_review_holder_mismatch",
        lease_renewal_review_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.holder_mismatch_lease_renewal_request,
            &fixtures.command_review_clock,
            &fixtures.holder_mismatch_lease_renewal_review,
        ),
        "lease renewal authority evaluator deterministically rejects holder mismatches",
    );

    push_result(
        checks,
        "validation.check.lease_renewal_authority_review_scope_mismatch",
        lease_renewal_review_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.scope_mismatch_lease_renewal_request,
            &fixtures.command_review_clock,
            &fixtures.scope_mismatch_lease_renewal_review,
        ),
        "lease renewal authority evaluator deterministically rejects scope mismatches",
    );

    push_result(
        checks,
        "validation.check.lease_renewal_authority_review_zero_ttl",
        lease_renewal_review_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.zero_ttl_lease_renewal_request,
            &fixtures.command_review_clock,
            &fixtures.zero_ttl_lease_renewal_review,
        ),
        "lease renewal authority evaluator deterministically rejects zero-duration renewals",
    );

    push_result(
        checks,
        "validation.check.lease_renewal_authority_review_non_extending",
        lease_renewal_review_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.non_extending_lease_renewal_request,
            &fixtures.command_review_clock,
            &fixtures.non_extending_lease_renewal_review,
        ),
        "lease renewal authority evaluator deterministically rejects non-extending renewals",
    );

    push_result(
        checks,
        "validation.check.lease_renewal_authority_review_expired_lease",
        lease_renewal_review_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.lease_renewal_request,
            &fixtures.expired_command_review_clock,
            &fixtures.expired_lease_renewal_review,
        ),
        "lease renewal authority evaluator deterministically rejects leases expired at the review clock",
    );

    push_result(
        checks,
        "validation.check.lease_renewal_authority_application_rejection_fixture",
        if fixtures
            .lease_renewal_application_rejection
            .rejection_code
            .as_str()
            == "review_rejected"
            && fixtures
                .lease_renewal_application_rejection
                .current_authority_revision
                == lease_release_authority_revision
        {
            Ok(())
        } else {
            Err("standalone lease renewal application rejection fixture is not the expected review-rejected rejection"
                .to_owned())
        },
        "standalone lease renewal application rejection fixture is a review-rejected rejection",
    );

    push_result(
        checks,
        "validation.check.lease_renewal_authority_application_accepted",
        lease_renewal_application_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.accepted_lease_renewal_review,
            &fixtures.accepted_lease_renewal_application,
        ),
        "lease renewal authority application deterministically replaces accepted active lease state",
    );

    push_result(
        checks,
        "validation.check.lease_renewal_authority_application_rejected",
        lease_renewal_application_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.stale_lease_renewal_review,
            &fixtures.rejected_lease_renewal_application,
        ),
        "lease renewal authority application deterministically rejects rejected renewal reviews",
    );

    push_result(
        checks,
        "validation.check.stream_registry_diff_fixture",
        if fixtures.stream_registry_change_request.diff == fixtures.stream_registry_diff {
            Ok(())
        } else {
            Err(
                "stream registry change request does not embed the standalone diff fixture"
                    .to_owned(),
            )
        },
        "stream registry change request embeds the standalone diff fixture",
    );

    push_result(
        checks,
        "validation.check.stream_registry_lease_fixture",
        if fixtures.stream_registry_lease.scope.as_str() == "manifold.stream_registry"
            && fixtures.stream_registry_lease.holder_id
                == fixtures.stream_registry_change_request.holder_id
            && fixtures.stream_registry_change_request.lease_id.as_ref()
                == Some(&fixtures.stream_registry_lease.lease_id)
        {
            Ok(())
        } else {
            Err(
                "stream registry lease fixture does not authorize the registry change request"
                    .to_owned(),
            )
        },
        "stream registry lease fixture authorizes the accepted registry request",
    );

    push_result(
        checks,
        "validation.check.stream_registry_authority_audit_event",
        fixtures
            .stream_registry_authority_audit_event
            .validate_against_snapshot(&fixtures.authority_snapshot),
        "stream registry authority audit event matches the accepted request, lease, clock, and snapshot",
    );

    push_result(
        checks,
        "validation.check.stream_registry_rejection_fixture",
        if fixtures.stream_registry_rejection.rejection_code.as_str() == "stale_revision"
            && fixtures.stream_registry_rejection.retryable
            && fixtures
                .stream_registry_rejection
                .current_authority_revision
                == Revision::INITIAL
            && fixtures.stream_registry_rejection.current_registry_revision == Revision::INITIAL
        {
            Ok(())
        } else {
            Err("standalone stream registry rejection fixture is not the expected stale-revision rejection"
                .to_owned())
        },
        "standalone stream registry rejection fixture is a stale-revision rejection",
    );

    push_result(
        checks,
        "validation.check.stream_registry_authority_review_accepted",
        stream_registry_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.stream_registry_change_request,
            &fixtures.command_review_clock,
            &fixtures.accepted_stream_registry_review,
        ),
        "stream registry authority evaluator deterministically accepts a lease-scoped metadata change",
    );

    push_result(
        checks,
        "validation.check.stream_registry_authority_review_expired_lease",
        stream_registry_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.stream_registry_change_request,
            &fixtures.expired_command_review_clock,
            &fixtures.expired_lease_stream_registry_review,
        ),
        "stream registry authority evaluator deterministically rejects leases expired at the review clock",
    );

    push_result(
        checks,
        "validation.check.stream_registry_authority_review_stale_revision",
        stream_registry_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.stale_stream_registry_request,
            &fixtures.command_review_clock,
            &fixtures.stale_stream_registry_review,
        ),
        "stream registry authority evaluator deterministically rejects stale authority revisions",
    );

    push_result(
        checks,
        "validation.check.stream_registry_authority_review_missing_lease",
        stream_registry_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.missing_lease_stream_registry_request,
            &fixtures.command_review_clock,
            &fixtures.missing_lease_stream_registry_review,
        ),
        "stream registry authority evaluator deterministically rejects missing registry leases",
    );

    push_result(
        checks,
        "validation.check.stream_registry_authority_review_active_stream_conflict",
        stream_registry_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.active_stream_registry_request,
            &fixtures.command_review_clock,
            &fixtures.active_stream_registry_review,
        ),
        "stream registry authority evaluator deterministically rejects active-stream removals",
    );

    push_result(
        checks,
        "validation.check.stream_registry_authority_review_unknown_module",
        stream_registry_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.unknown_module_stream_registry_request,
            &fixtures.command_review_clock,
            &fixtures.unknown_module_stream_registry_review,
        ),
        "stream registry authority evaluator deterministically rejects unknown source modules",
    );

    push_result(
        checks,
        "validation.check.stream_registry_authority_review_unknown_endpoint",
        stream_registry_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.unknown_endpoint_stream_registry_request,
            &fixtures.command_review_clock,
            &fixtures.unknown_endpoint_stream_registry_review,
        ),
        "stream registry authority evaluator deterministically rejects unknown transport endpoints",
    );

    push_result(
        checks,
        "validation.check.stream_registry_authority_application_rejection_fixture",
        if fixtures
            .stream_registry_application_rejection
            .rejection_code
            .as_str()
            == "review_rejected"
            && fixtures
                .stream_registry_application_rejection
                .current_authority_revision
                == Revision::INITIAL
        {
            Ok(())
        } else {
            Err("standalone stream registry application rejection fixture is not the expected review-rejected rejection"
                .to_owned())
        },
        "standalone stream registry application rejection fixture is a review-rejected rejection",
    );

    push_result(
        checks,
        "validation.check.stream_registry_authority_application_accepted",
        stream_registry_application_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.accepted_stream_registry_review,
            &fixtures.accepted_stream_registry_application,
        ),
        "stream registry authority application deterministically advances accepted registry state",
    );

    push_result(
        checks,
        "validation.check.stream_registry_authority_application_rejected",
        stream_registry_application_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.stale_stream_registry_review,
            &fixtures.rejected_stream_registry_application,
        ),
        "stream registry authority application deterministically rejects rejected registry reviews",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_authority_snapshot",
        fixtures
            .stream_subscription_authority_snapshot
            .validate_authority_links(),
        "stream subscription authority snapshot carries subscribe capability and valid stream links",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_fixture",
        if fixtures
            .accepted_stream_subscription_review
            .accepted
            .as_ref()
            == Some(&fixtures.stream_subscription)
        {
            Ok(())
        } else {
            Err(
                "standalone stream subscription fixture does not match the accepted review"
                    .to_owned(),
            )
        },
        "standalone stream subscription fixture matches the accepted review state",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_rejection_fixture",
        if fixtures
            .stream_subscription_rejection
            .rejection_code
            .as_str()
            == "stale_revision"
            && fixtures.stream_subscription_rejection.retryable
            && fixtures
                .stream_subscription_rejection
                .current_authority_revision
                == Revision::INITIAL
            && fixtures
                .stream_subscription_rejection
                .current_registry_revision
                == Revision::INITIAL
        {
            Ok(())
        } else {
            Err("standalone stream subscription rejection fixture is not the expected stale-revision rejection"
                .to_owned())
        },
        "standalone stream subscription rejection fixture is a stale-revision rejection",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_authority_audit_event",
        fixtures
            .stream_subscription_authority_audit_event
            .validate_against_snapshot(&fixtures.stream_subscription_authority_snapshot),
        "stream subscription authority audit event matches the accepted request, clock, and snapshot",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_authority_review_accepted",
        stream_subscription_review_matches_fixture(
            &fixtures.stream_subscription_authority_snapshot,
            &fixtures.stream_subscription_request,
            &fixtures.command_review_clock,
            &fixtures.accepted_stream_subscription_review,
        ),
        "stream subscription authority evaluator deterministically accepts a UI subscriber for an advertised transport",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_authority_review_zero_ttl",
        stream_subscription_review_matches_fixture(
            &fixtures.stream_subscription_authority_snapshot,
            &fixtures.zero_ttl_stream_subscription_request,
            &fixtures.command_review_clock,
            &fixtures.zero_ttl_stream_subscription_review,
        ),
        "stream subscription authority evaluator deterministically rejects zero-duration subscriptions",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_authority_review_missing_capability",
        stream_subscription_review_matches_fixture(
            &fixtures.stream_subscription_authority_snapshot,
            &fixtures.missing_capability_stream_subscription_request,
            &fixtures.command_review_clock,
            &fixtures.missing_capability_stream_subscription_review,
        ),
        "stream subscription authority evaluator deterministically rejects unadvertised subscribe capabilities",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_authority_review_stale_revision",
        stream_subscription_review_matches_fixture(
            &fixtures.stream_subscription_authority_snapshot,
            &fixtures.stale_stream_subscription_request,
            &fixtures.command_review_clock,
            &fixtures.stale_stream_subscription_review,
        ),
        "stream subscription authority evaluator deterministically rejects stale authority revisions",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_authority_review_stale_registry",
        stream_subscription_review_matches_fixture(
            &fixtures.stream_subscription_authority_snapshot,
            &fixtures.stale_registry_stream_subscription_request,
            &fixtures.command_review_clock,
            &fixtures.stale_registry_stream_subscription_review,
        ),
        "stream subscription authority evaluator deterministically rejects stale registry revisions",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_authority_review_unknown_stream",
        stream_subscription_review_matches_fixture(
            &fixtures.stream_subscription_authority_snapshot,
            &fixtures.unknown_stream_subscription_request,
            &fixtures.command_review_clock,
            &fixtures.unknown_stream_subscription_review,
        ),
        "stream subscription authority evaluator deterministically rejects unknown streams",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_authority_review_unknown_transport",
        stream_subscription_review_matches_fixture(
            &fixtures.stream_subscription_authority_snapshot,
            &fixtures.unknown_transport_stream_subscription_request,
            &fixtures.command_review_clock,
            &fixtures.unknown_transport_stream_subscription_review,
        ),
        "stream subscription authority evaluator deterministically rejects unknown transport offers",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_authority_review_subscriber_limit",
        stream_subscription_review_matches_fixture(
            &fixtures.subscriber_limit_stream_subscription_authority_snapshot,
            &fixtures.subscriber_limit_stream_subscription_request,
            &fixtures.command_review_clock,
            &fixtures.subscriber_limit_stream_subscription_review,
        ),
        "stream subscription authority evaluator deterministically rejects subscriptions beyond the stream subscriber limit",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_authority_review_ui_disabled",
        stream_subscription_review_matches_fixture(
            &fixtures.ui_disabled_stream_subscription_authority_snapshot,
            &fixtures.ui_disabled_stream_subscription_request,
            &fixtures.command_review_clock,
            &fixtures.ui_disabled_stream_subscription_review,
        ),
        "stream subscription authority evaluator deterministically rejects UI subscribers when stream policy disables UI subscriptions",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_authority_application_rejection_fixture",
        if fixtures
            .stream_subscription_application_rejection
            .rejection_code
            .as_str()
            == "review_rejected"
            && fixtures
                .stream_subscription_application_rejection
                .current_authority_revision
                == Revision::INITIAL
        {
            Ok(())
        } else {
            Err("standalone stream subscription application rejection fixture is not the expected review-rejected rejection"
                .to_owned())
        },
        "standalone stream subscription application rejection fixture is a review-rejected rejection",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_authority_application_accepted",
        stream_subscription_application_matches_fixture(
            &fixtures.stream_subscription_authority_snapshot,
            &fixtures.accepted_stream_subscription_review,
            &fixtures.accepted_stream_subscription_application,
        ),
        "stream subscription authority application deterministically appends accepted subscription state",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_authority_application_rejected",
        stream_subscription_application_matches_fixture(
            &fixtures.stream_subscription_authority_snapshot,
            &fixtures.stale_stream_subscription_review,
            &fixtures.rejected_stream_subscription_application,
        ),
        "stream subscription authority application deterministically rejects rejected subscription reviews",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_release_authority_snapshot",
        fixtures
            .stream_subscription_active_authority_snapshot
            .validate_authority_links(),
        "stream subscription release authority snapshot has one accepted active subscription",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_release_request_fixture",
        if fixtures
            .stream_subscription_active_authority_snapshot
            .active_stream_subscriptions
            .iter()
            .any(|subscription| {
                subscription.subscription_id
                    == fixtures.stream_subscription_release_request.subscription_id
                    && subscription.subscriber_id
                        == fixtures.stream_subscription_release_request.subscriber_id
                    && subscription.stream_id
                        == fixtures.stream_subscription_release_request.stream_id
            })
            && fixtures
                .stream_subscription_release_request
                .expected_authority_revision
                == fixtures
                    .stream_subscription_active_authority_snapshot
                    .authority_revision
            && fixtures
                .stream_subscription_release_request
                .expected_registry_revision
                == fixtures
                    .stream_subscription_active_authority_snapshot
                    .stream_registry
                    .registry_revision
        {
            Ok(())
        } else {
            Err("stream subscription release request does not target the active subscription snapshot"
                .to_owned())
        },
        "stream subscription release request targets the accepted active subscription",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_release_rejection_fixture",
        if fixtures
            .stream_subscription_release_rejection
            .rejection_code
            .as_str()
            == "stale_revision"
            && fixtures.stream_subscription_release_rejection.retryable
            && fixtures
                .stream_subscription_release_rejection
                .current_authority_revision
                == Revision::new(2).expect("revision literal is valid")
        {
            Ok(())
        } else {
            Err("standalone stream subscription release rejection fixture is not the expected stale-revision rejection"
                .to_owned())
        },
        "standalone stream subscription release rejection fixture is a stale-revision rejection",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_release_authority_audit_event",
        fixtures
            .stream_subscription_release_authority_audit_event
            .validate_against_snapshot(&fixtures.stream_subscription_active_authority_snapshot),
        "stream subscription release authority audit event matches the accepted request, clock, and active snapshot",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_release_authority_review_accepted",
        stream_subscription_release_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.stream_subscription_release_request,
            &fixtures.command_review_clock,
            &fixtures.accepted_stream_subscription_release_review,
        ),
        "stream subscription release authority evaluator deterministically accepts active subscription release",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_release_authority_review_expired_subscription",
        stream_subscription_release_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.stream_subscription_release_request,
            &fixtures.expired_command_review_clock,
            &fixtures.expired_stream_subscription_release_review,
        ),
        "stream subscription release authority evaluator deterministically rejects subscriptions expired at the review clock",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_release_authority_review_stale_revision",
        stream_subscription_release_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.stale_stream_subscription_release_request,
            &fixtures.command_review_clock,
            &fixtures.stale_stream_subscription_release_review,
        ),
        "stream subscription release authority evaluator deterministically rejects stale authority revisions",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_release_authority_review_stale_registry",
        stream_subscription_release_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.stale_registry_stream_subscription_release_request,
            &fixtures.command_review_clock,
            &fixtures.stale_registry_stream_subscription_release_review,
        ),
        "stream subscription release authority evaluator deterministically rejects stale stream registries",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_release_authority_review_unknown_subscription",
        stream_subscription_release_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.unknown_stream_subscription_release_request,
            &fixtures.command_review_clock,
            &fixtures.unknown_stream_subscription_release_review,
        ),
        "stream subscription release authority evaluator deterministically rejects unknown subscriptions",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_release_authority_review_subscriber_mismatch",
        stream_subscription_release_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.subscriber_mismatch_stream_subscription_release_request,
            &fixtures.command_review_clock,
            &fixtures.subscriber_mismatch_stream_subscription_release_review,
        ),
        "stream subscription release authority evaluator deterministically rejects subscriber mismatches",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_release_authority_review_stream_mismatch",
        stream_subscription_release_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.stream_mismatch_stream_subscription_release_request,
            &fixtures.command_review_clock,
            &fixtures.stream_mismatch_stream_subscription_release_review,
        ),
        "stream subscription release authority evaluator deterministically rejects stream mismatches",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_release_authority_application_rejection_fixture",
        if fixtures
            .stream_subscription_release_application_rejection
            .rejection_code
            .as_str()
            == "review_rejected"
            && fixtures
                .stream_subscription_release_application_rejection
                .current_authority_revision
                == Revision::new(2).expect("revision literal is valid")
        {
            Ok(())
        } else {
            Err("standalone stream subscription release application rejection fixture is not the expected review-rejected rejection"
                .to_owned())
        },
        "standalone stream subscription release application rejection fixture is a review-rejected rejection",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_release_authority_application_accepted",
        stream_subscription_release_application_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.accepted_stream_subscription_release_review,
            &fixtures.accepted_stream_subscription_release_application,
        ),
        "stream subscription release authority application deterministically removes accepted active subscription state",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_release_authority_application_rejected",
        stream_subscription_release_application_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.stale_stream_subscription_release_review,
            &fixtures.rejected_stream_subscription_release_application,
        ),
        "stream subscription release authority application deterministically rejects rejected release reviews",
    );

    let stream_subscription_renewal_expected_expires_at_ms =
        u64::try_from(fixtures.command_review_clock.wall_unix_ms)
            .unwrap_or_default()
            .saturating_add(
                fixtures
                    .stream_subscription_renewal_request
                    .requested_ttl_ms,
            );
    push_result(
        checks,
        "validation.check.stream_subscription_renewal_request_fixture",
        match fixtures
            .stream_subscription_active_authority_snapshot
            .active_stream_subscriptions
            .iter()
            .find(|subscription| {
                subscription.subscription_id
                    == fixtures.stream_subscription_renewal_request.subscription_id
                    && subscription.subscriber_id
                        == fixtures.stream_subscription_renewal_request.subscriber_id
                    && subscription.stream_id
                        == fixtures.stream_subscription_renewal_request.stream_id
                    && subscription.transport_id
                        == fixtures.stream_subscription_renewal_request.transport_id
            }) {
            Some(subscription)
                if fixtures
                    .stream_subscription_renewal_request
                    .expected_authority_revision
                    == fixtures
                        .stream_subscription_active_authority_snapshot
                        .authority_revision
                    && fixtures
                        .stream_subscription_renewal_request
                        .expected_registry_revision
                        == fixtures
                            .stream_subscription_active_authority_snapshot
                            .stream_registry
                            .registry_revision
                    && fixtures.stream_subscription_renewal_request.requested_ttl_ms > 0
                    && stream_subscription_renewal_expected_expires_at_ms
                        > subscription.expires_at_ms =>
            {
                Ok(())
            }
            _ => Err(
                "stream subscription renewal request does not extend the active subscription snapshot"
                    .to_owned(),
            ),
        },
        "stream subscription renewal request targets and extends the accepted active subscription",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_renewal_rejection_fixture",
        if fixtures
            .stream_subscription_renewal_rejection
            .rejection_code
            .as_str()
            == "stale_revision"
            && fixtures.stream_subscription_renewal_rejection.retryable
            && fixtures
                .stream_subscription_renewal_rejection
                .current_authority_revision
                == Revision::new(2).expect("revision literal is valid")
            && fixtures
                .stream_subscription_renewal_rejection
                .current_registry_revision
                == Revision::INITIAL
            && fixtures
                .stream_subscription_renewal_rejection
                .active_subscriber_count
                == u32::try_from(
                    fixtures
                        .stream_subscription_active_authority_snapshot
                        .active_stream_subscriptions
                        .len(),
                )
                .expect("fixture active subscription count fits in u32")
            && fixtures
                .stream_subscription_renewal_rejection
                .current_expires_at_ms
                .is_none()
        {
            Ok(())
        } else {
            Err("standalone stream subscription renewal rejection fixture is not the expected stale-revision rejection"
                .to_owned())
        },
        "standalone stream subscription renewal rejection fixture is a stale-revision rejection",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_renewal_authority_audit_event",
        fixtures
            .stream_subscription_renewal_authority_audit_event
            .validate_against_snapshot(&fixtures.stream_subscription_active_authority_snapshot),
        "stream subscription renewal authority audit event matches the accepted request, clock, and active snapshot",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_renewal_authority_review_accepted",
        stream_subscription_renewal_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.stream_subscription_renewal_request,
            &fixtures.command_review_clock,
            &fixtures.accepted_stream_subscription_renewal_review,
        ),
        "stream subscription renewal authority evaluator deterministically accepts active subscription renewal",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_renewal_authority_review_stale_revision",
        stream_subscription_renewal_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.stale_stream_subscription_renewal_request,
            &fixtures.command_review_clock,
            &fixtures.stale_stream_subscription_renewal_review,
        ),
        "stream subscription renewal authority evaluator deterministically rejects stale authority revisions",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_renewal_authority_review_stale_registry",
        stream_subscription_renewal_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.stale_registry_stream_subscription_renewal_request,
            &fixtures.command_review_clock,
            &fixtures.stale_registry_stream_subscription_renewal_review,
        ),
        "stream subscription renewal authority evaluator deterministically rejects stale stream registries",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_renewal_authority_review_unknown_subscription",
        stream_subscription_renewal_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.unknown_stream_subscription_renewal_request,
            &fixtures.command_review_clock,
            &fixtures.unknown_stream_subscription_renewal_review,
        ),
        "stream subscription renewal authority evaluator deterministically rejects unknown subscriptions",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_renewal_authority_review_subscriber_mismatch",
        stream_subscription_renewal_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.subscriber_mismatch_stream_subscription_renewal_request,
            &fixtures.command_review_clock,
            &fixtures.subscriber_mismatch_stream_subscription_renewal_review,
        ),
        "stream subscription renewal authority evaluator deterministically rejects subscriber mismatches",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_renewal_authority_review_stream_mismatch",
        stream_subscription_renewal_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.stream_mismatch_stream_subscription_renewal_request,
            &fixtures.command_review_clock,
            &fixtures.stream_mismatch_stream_subscription_renewal_review,
        ),
        "stream subscription renewal authority evaluator deterministically rejects stream mismatches",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_renewal_authority_review_transport_mismatch",
        stream_subscription_renewal_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.transport_mismatch_stream_subscription_renewal_request,
            &fixtures.command_review_clock,
            &fixtures.transport_mismatch_stream_subscription_renewal_review,
        ),
        "stream subscription renewal authority evaluator deterministically rejects transport mismatches",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_renewal_authority_review_zero_ttl",
        stream_subscription_renewal_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.zero_ttl_stream_subscription_renewal_request,
            &fixtures.command_review_clock,
            &fixtures.zero_ttl_stream_subscription_renewal_review,
        ),
        "stream subscription renewal authority evaluator deterministically rejects zero-duration renewals",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_renewal_authority_review_non_extending",
        stream_subscription_renewal_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.non_extending_stream_subscription_renewal_request,
            &fixtures.command_review_clock,
            &fixtures.non_extending_stream_subscription_renewal_review,
        ),
        "stream subscription renewal authority evaluator deterministically rejects non-extending renewals",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_renewal_authority_review_expired_subscription",
        stream_subscription_renewal_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.stream_subscription_renewal_request,
            &fixtures.expired_command_review_clock,
            &fixtures.expired_stream_subscription_renewal_review,
        ),
        "stream subscription renewal authority evaluator deterministically rejects subscriptions expired at the review clock",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_renewal_authority_application_rejection_fixture",
        if fixtures
            .stream_subscription_renewal_application_rejection
            .rejection_code
            .as_str()
            == "review_rejected"
            && fixtures
                .stream_subscription_renewal_application_rejection
                .current_authority_revision
                == Revision::new(2).expect("revision literal is valid")
        {
            Ok(())
        } else {
            Err("standalone stream subscription renewal application rejection fixture is not the expected review-rejected rejection"
                .to_owned())
        },
        "standalone stream subscription renewal application rejection fixture is a review-rejected rejection",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_renewal_authority_application_accepted",
        stream_subscription_renewal_application_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.accepted_stream_subscription_renewal_review,
            &fixtures.accepted_stream_subscription_renewal_application,
        ),
        "stream subscription renewal authority application deterministically replaces accepted active subscription state",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_renewal_authority_application_rejected",
        stream_subscription_renewal_application_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.stale_stream_subscription_renewal_review,
            &fixtures.rejected_stream_subscription_renewal_application,
        ),
        "stream subscription renewal authority application deterministically rejects rejected renewal reviews",
    );

    let expired_lease_count = fixtures
        .stream_subscription_active_authority_snapshot
        .active_leases
        .iter()
        .filter(|lease| {
            u64::try_from(fixtures.expired_command_review_clock.wall_unix_ms).unwrap_or_default()
                >= lease.expires_at_ms
        })
        .count();
    let expired_subscription_count = fixtures
        .stream_subscription_active_authority_snapshot
        .active_stream_subscriptions
        .iter()
        .filter(|subscription| {
            u64::try_from(fixtures.expired_command_review_clock.wall_unix_ms).unwrap_or_default()
                >= subscription.expires_at_ms
        })
        .count();
    push_result(
        checks,
        "validation.check.authority_expiry_sweep_request_fixture",
        if fixtures
            .authority_expiry_sweep_request
            .expected_authority_revision
            == fixtures
                .stream_subscription_active_authority_snapshot
                .authority_revision
            && fixtures
                .authority_expiry_sweep_request
                .expected_registry_revision
                == fixtures
                    .stream_subscription_active_authority_snapshot
                    .stream_registry
                    .registry_revision
            && expired_lease_count > 0
            && expired_subscription_count > 0
        {
            Ok(())
        } else {
            Err("authority expiry sweep request does not target the active authority snapshot with expired state"
                .to_owned())
        },
        "authority expiry sweep request targets active accepted state with expired leases and subscriptions",
    );

    push_result(
        checks,
        "validation.check.authority_expiry_sweep_rejection_fixture",
        if fixtures
            .authority_expiry_sweep_rejection
            .rejection_code
            .as_str()
            == "stale_revision"
            && fixtures.authority_expiry_sweep_rejection.retryable
            && fixtures
                .authority_expiry_sweep_rejection
                .current_authority_revision
                == fixtures
                    .stream_subscription_active_authority_snapshot
                    .authority_revision
            && fixtures
                .authority_expiry_sweep_rejection
                .current_registry_revision
                == fixtures
                    .stream_subscription_active_authority_snapshot
                    .stream_registry
                    .registry_revision
            && fixtures
                .authority_expiry_sweep_rejection
                .expired_lease_count
                == expired_lease_count
            && fixtures
                .authority_expiry_sweep_rejection
                .expired_subscription_count
                == expired_subscription_count
        {
            Ok(())
        } else {
            Err("standalone authority expiry sweep rejection fixture is not the expected stale-revision rejection"
                .to_owned())
        },
        "standalone authority expiry sweep rejection fixture is a stale-revision rejection",
    );

    push_result(
        checks,
        "validation.check.authority_expiry_sweep_authority_audit_event",
        fixtures
            .authority_expiry_sweep_authority_audit_event
            .validate_against_snapshot(&fixtures.stream_subscription_active_authority_snapshot),
        "authority expiry sweep audit event matches the accepted request, clock, and active snapshot",
    );

    push_result(
        checks,
        "validation.check.authority_expiry_sweep_authority_review_accepted",
        authority_expiry_sweep_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.authority_expiry_sweep_request,
            &fixtures.expired_command_review_clock,
            &fixtures.accepted_authority_expiry_sweep_review,
        ),
        "authority expiry sweep evaluator deterministically accepts expired active leases and stream subscriptions",
    );

    push_result(
        checks,
        "validation.check.authority_expiry_sweep_authority_review_stale_revision",
        authority_expiry_sweep_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.stale_authority_expiry_sweep_request,
            &fixtures.expired_command_review_clock,
            &fixtures.stale_authority_expiry_sweep_review,
        ),
        "authority expiry sweep evaluator deterministically rejects stale authority revisions",
    );

    push_result(
        checks,
        "validation.check.authority_expiry_sweep_authority_review_registry_mismatch",
        authority_expiry_sweep_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.registry_mismatch_authority_expiry_sweep_request,
            &fixtures.expired_command_review_clock,
            &fixtures.registry_mismatch_authority_expiry_sweep_review,
        ),
        "authority expiry sweep evaluator deterministically rejects stale registry revisions",
    );

    push_result(
        checks,
        "validation.check.authority_expiry_sweep_authority_review_no_expired",
        authority_expiry_sweep_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.authority_expiry_sweep_request,
            &fixtures.command_review_clock,
            &fixtures.no_expired_authority_expiry_sweep_review,
        ),
        "authority expiry sweep evaluator deterministically rejects sweeps with no expired active state",
    );

    push_result(
        checks,
        "validation.check.authority_expiry_sweep_authority_application_rejection_fixture",
        if fixtures
            .authority_expiry_sweep_application_rejection
            .rejection_code
            .as_str()
            == "review_rejected"
            && fixtures
                .authority_expiry_sweep_application_rejection
                .current_authority_revision
                == fixtures
                    .stream_subscription_active_authority_snapshot
                    .authority_revision
        {
            Ok(())
        } else {
            Err("standalone authority expiry sweep application rejection fixture is not the expected review-rejected rejection"
                .to_owned())
        },
        "standalone authority expiry sweep application rejection fixture is a review-rejected rejection",
    );

    push_result(
        checks,
        "validation.check.authority_expiry_sweep_authority_application_accepted",
        authority_expiry_sweep_application_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.accepted_authority_expiry_sweep_review,
            &fixtures.accepted_authority_expiry_sweep_application,
        ),
        "authority expiry sweep application deterministically removes expired accepted state",
    );

    push_result(
        checks,
        "validation.check.authority_expiry_sweep_authority_application_rejected",
        authority_expiry_sweep_application_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.stale_authority_expiry_sweep_review,
            &fixtures.rejected_authority_expiry_sweep_application,
        ),
        "authority expiry sweep application deterministically rejects rejected sweep reviews",
    );

    push_result(
        checks,
        "validation.check.module_runtime_state_request_fixture",
        if fixtures.module_runtime_state_change_request.proposed_state
            == fixtures.next_provider_runtime
        {
            Ok(())
        } else {
            Err(
                "module runtime-state change request does not embed the v2 provider state fixture"
                    .to_owned(),
            )
        },
        "module runtime-state change request embeds the accepted provider runtime-state fixture",
    );

    push_result(
        checks,
        "validation.check.module_runtime_state_authority_audit_event",
        fixtures
            .module_runtime_state_authority_audit_event
            .validate_against_snapshot(&fixtures.authority_snapshot),
        "module runtime-state authority audit event matches the accepted request, lease, clock, and snapshot",
    );

    push_result(
        checks,
        "validation.check.module_runtime_state_rejection_fixture",
        if fixtures
            .module_runtime_state_rejection
            .rejection_code
            .as_str()
            == "stale_revision"
            && fixtures.module_runtime_state_rejection.retryable
            && fixtures
                .module_runtime_state_rejection
                .current_authority_revision
                == Revision::INITIAL
            && fixtures
                .module_runtime_state_rejection
                .current_runtime_revision
                == Some(Revision::INITIAL)
        {
            Ok(())
        } else {
            Err("standalone module runtime-state rejection fixture is not the expected stale-revision rejection"
                .to_owned())
        },
        "standalone module runtime-state rejection fixture is a stale-revision rejection",
    );

    push_result(
        checks,
        "validation.check.module_runtime_state_authority_review_accepted",
        module_runtime_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.module_runtime_state_change_request,
            &fixtures.command_review_clock,
            &fixtures.accepted_module_runtime_review,
        ),
        "module runtime-state authority evaluator deterministically accepts a lease-scoped stop transition",
    );

    push_result(
        checks,
        "validation.check.module_runtime_state_authority_review_expired_lease",
        module_runtime_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.module_runtime_state_change_request,
            &fixtures.expired_command_review_clock,
            &fixtures.expired_lease_module_runtime_review,
        ),
        "module runtime-state authority evaluator deterministically rejects leases expired at the review clock",
    );

    push_result(
        checks,
        "validation.check.module_runtime_state_authority_review_stale_revision",
        module_runtime_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.stale_module_runtime_request,
            &fixtures.command_review_clock,
            &fixtures.stale_module_runtime_review,
        ),
        "module runtime-state authority evaluator deterministically rejects stale authority revisions",
    );

    push_result(
        checks,
        "validation.check.module_runtime_state_authority_review_missing_lease",
        module_runtime_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.missing_lease_module_runtime_request,
            &fixtures.command_review_clock,
            &fixtures.missing_lease_module_runtime_review,
        ),
        "module runtime-state authority evaluator deterministically rejects missing module leases",
    );

    push_result(
        checks,
        "validation.check.module_runtime_state_authority_review_unknown_stream",
        module_runtime_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.unknown_stream_module_runtime_request,
            &fixtures.command_review_clock,
            &fixtures.unknown_stream_module_runtime_review,
        ),
        "module runtime-state authority evaluator deterministically rejects unknown active streams",
    );

    push_result(
        checks,
        "validation.check.module_runtime_state_authority_review_missing_backend",
        module_runtime_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.missing_backend_module_runtime_request,
            &fixtures.command_review_clock,
            &fixtures.missing_backend_module_runtime_review,
        ),
        "module runtime-state authority evaluator deterministically rejects unsupported backends",
    );

    push_result(
        checks,
        "validation.check.module_runtime_state_authority_application_rejection_fixture",
        if fixtures
            .module_runtime_application_rejection
            .rejection_code
            .as_str()
            == "review_rejected"
            && fixtures
                .module_runtime_application_rejection
                .current_authority_revision
                == Revision::INITIAL
        {
            Ok(())
        } else {
            Err("standalone module runtime-state application rejection fixture is not the expected review-rejected rejection"
                .to_owned())
        },
        "standalone module runtime-state application rejection fixture is a review-rejected rejection",
    );

    push_result(
        checks,
        "validation.check.module_runtime_state_authority_application_accepted",
        module_runtime_application_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.accepted_module_runtime_review,
            &fixtures.accepted_module_runtime_application,
        ),
        "module runtime-state authority application deterministically advances accepted runtime state",
    );

    push_result(
        checks,
        "validation.check.module_runtime_state_authority_application_rejected",
        module_runtime_application_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.stale_module_runtime_review,
            &fixtures.rejected_module_runtime_application,
        ),
        "module runtime-state authority application deterministically rejects rejected runtime-state reviews",
    );

    push_result(
        checks,
        "validation.check.host_manifest_lease_fixture",
        if fixtures.host_manifest_lease.scope.as_str() == "manifold.host_manifest"
            && fixtures.host_manifest_lease.holder_id
                == fixtures.host_manifest_change_request.holder_id
            && fixtures.host_manifest_change_request.lease_id.as_ref()
                == Some(&fixtures.host_manifest_lease.lease_id)
        {
            Ok(())
        } else {
            Err(
                "host manifest lease fixture does not authorize the host manifest request"
                    .to_owned(),
            )
        },
        "host manifest lease fixture authorizes the accepted host manifest request",
    );

    push_result(
        checks,
        "validation.check.host_manifest_authority_audit_event",
        fixtures
            .host_manifest_authority_audit_event
            .validate_against_snapshot(&fixtures.authority_snapshot),
        "host manifest authority audit event matches the accepted request, lease, clock, and snapshot",
    );

    push_result(
        checks,
        "validation.check.host_manifest_rejection_fixture",
        if fixtures.host_manifest_rejection.rejection_code.as_str() == "stale_revision"
            && fixtures.host_manifest_rejection.retryable
            && fixtures.host_manifest_rejection.current_authority_revision == Revision::INITIAL
        {
            Ok(())
        } else {
            Err(
                "standalone host manifest rejection fixture is not the expected stale-revision rejection"
                    .to_owned(),
            )
        },
        "standalone host manifest rejection fixture is a stale-revision rejection",
    );

    push_result(
        checks,
        "validation.check.host_manifest_authority_review_accepted",
        host_manifest_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.host_manifest_change_request,
            &fixtures.command_review_clock,
            &fixtures.accepted_host_manifest_review,
        ),
        "host manifest authority evaluator deterministically accepts a lease-scoped permission change",
    );

    push_result(
        checks,
        "validation.check.host_manifest_authority_review_expired_lease",
        host_manifest_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.host_manifest_change_request,
            &fixtures.expired_command_review_clock,
            &fixtures.expired_lease_host_manifest_review,
        ),
        "host manifest authority evaluator deterministically rejects leases expired at the review clock",
    );

    push_result(
        checks,
        "validation.check.host_manifest_authority_review_stale_revision",
        host_manifest_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.stale_host_manifest_request,
            &fixtures.command_review_clock,
            &fixtures.stale_host_manifest_review,
        ),
        "host manifest authority evaluator deterministically rejects stale authority revisions",
    );

    push_result(
        checks,
        "validation.check.host_manifest_authority_review_missing_authority_role",
        host_manifest_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.missing_authority_role_host_manifest_request,
            &fixtures.command_review_clock,
            &fixtures.missing_authority_role_host_manifest_review,
        ),
        "host manifest authority evaluator deterministically rejects missing authority roles",
    );

    push_result(
        checks,
        "validation.check.host_manifest_authority_review_endpoint_mismatch",
        host_manifest_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.endpoint_mismatch_host_manifest_request,
            &fixtures.command_review_clock,
            &fixtures.endpoint_mismatch_host_manifest_review,
        ),
        "host manifest authority evaluator deterministically rejects unsafe endpoint pairings",
    );

    push_result(
        checks,
        "validation.check.host_manifest_authority_review_remove_capability",
        host_manifest_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.remove_capability_host_manifest_request,
            &fixtures.command_review_clock,
            &fixtures.remove_capability_host_manifest_review,
        ),
        "host manifest authority evaluator deterministically rejects capability removal while active leases or commands use it",
    );

    push_result(
        checks,
        "validation.check.host_manifest_authority_review_remove_backend",
        host_manifest_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.remove_backend_host_manifest_request,
            &fixtures.command_review_clock,
            &fixtures.remove_backend_host_manifest_review,
        ),
        "host manifest authority evaluator deterministically rejects backend removal while active modules use it",
    );

    push_result(
        checks,
        "validation.check.host_manifest_authority_application_rejection_fixture",
        if fixtures
            .host_manifest_application_rejection
            .rejection_code
            .as_str()
            == "review_rejected"
            && fixtures
                .host_manifest_application_rejection
                .current_authority_revision
                == Revision::INITIAL
        {
            Ok(())
        } else {
            Err("standalone host manifest application rejection fixture is not the expected review-rejected rejection"
                .to_owned())
        },
        "standalone host manifest application rejection fixture is a review-rejected rejection",
    );

    push_result(
        checks,
        "validation.check.host_manifest_authority_application_accepted",
        host_manifest_application_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.accepted_host_manifest_review,
            &fixtures.accepted_host_manifest_application,
        ),
        "host manifest authority application deterministically advances accepted host state",
    );

    push_result(
        checks,
        "validation.check.host_manifest_authority_application_rejected",
        host_manifest_application_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.stale_host_manifest_review,
            &fixtures.rejected_host_manifest_application,
        ),
        "host manifest authority application deterministically rejects rejected host manifest reviews",
    );

    push_result(
        checks,
        "validation.check.clock_lease_fixture",
        if fixtures.clock_lease.scope.as_str() == "manifold.clock"
            && fixtures.clock_lease.holder_id == fixtures.clock_change_request.holder_id
            && fixtures.clock_change_request.lease_id.as_ref()
                == Some(&fixtures.clock_lease.lease_id)
        {
            Ok(())
        } else {
            Err("clock lease fixture does not authorize the clock request".to_owned())
        },
        "clock lease fixture authorizes the accepted clock request",
    );

    push_result(
        checks,
        "validation.check.clock_authority_audit_event",
        fixtures
            .clock_authority_audit_event
            .validate_against_snapshot(&fixtures.authority_snapshot),
        "clock authority audit event matches the accepted request, lease, clock, and snapshot",
    );

    push_result(
        checks,
        "validation.check.clock_rejection_fixture",
        if fixtures.clock_rejection.rejection_code.as_str() == "stale_revision"
            && fixtures.clock_rejection.retryable
            && fixtures.clock_rejection.current_authority_revision == Revision::INITIAL
            && fixtures.clock_rejection.current_clock_sequence == 42
        {
            Ok(())
        } else {
            Err(
                "standalone clock rejection fixture is not the expected stale-revision rejection"
                    .to_owned(),
            )
        },
        "standalone clock rejection fixture is a stale-revision rejection",
    );

    push_result(
        checks,
        "validation.check.clock_authority_review_accepted",
        clock_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.clock_change_request,
            &fixtures.command_review_clock,
            &fixtures.accepted_clock_review,
        ),
        "clock authority evaluator deterministically accepts a lease-scoped clock tick",
    );

    push_result(
        checks,
        "validation.check.clock_authority_review_expired_lease",
        clock_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.clock_change_request,
            &fixtures.expired_command_review_clock,
            &fixtures.expired_lease_clock_review,
        ),
        "clock authority evaluator deterministically rejects leases expired at the review clock",
    );

    push_result(
        checks,
        "validation.check.clock_authority_review_stale_revision",
        clock_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.stale_clock_request,
            &fixtures.command_review_clock,
            &fixtures.stale_clock_review,
        ),
        "clock authority evaluator deterministically rejects stale authority revisions",
    );

    push_result(
        checks,
        "validation.check.clock_authority_review_missing_lease",
        clock_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.missing_lease_clock_request,
            &fixtures.command_review_clock,
            &fixtures.missing_lease_clock_review,
        ),
        "clock authority evaluator deterministically rejects missing clock leases",
    );

    push_result(
        checks,
        "validation.check.clock_authority_review_domain_mismatch",
        clock_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.domain_mismatch_clock_request,
            &fixtures.command_review_clock,
            &fixtures.domain_mismatch_clock_review,
        ),
        "clock authority evaluator deterministically rejects clock-domain mismatches",
    );

    push_result(
        checks,
        "validation.check.clock_authority_review_sequence_gap",
        clock_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.sequence_gap_clock_request,
            &fixtures.command_review_clock,
            &fixtures.sequence_gap_clock_review,
        ),
        "clock authority evaluator deterministically rejects skipped clock sequences",
    );

    push_result(
        checks,
        "validation.check.clock_authority_review_monotonic_regression",
        clock_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.monotonic_regression_clock_request,
            &fixtures.command_review_clock,
            &fixtures.monotonic_regression_clock_review,
        ),
        "clock authority evaluator deterministically rejects monotonic time regressions",
    );

    push_result(
        checks,
        "validation.check.clock_authority_application_rejection_fixture",
        if fixtures.clock_application_rejection.rejection_code.as_str() == "review_rejected"
            && fixtures
                .clock_application_rejection
                .current_authority_revision
                == Revision::INITIAL
        {
            Ok(())
        } else {
            Err("standalone clock application rejection fixture is not the expected review-rejected rejection"
                .to_owned())
        },
        "standalone clock application rejection fixture is a review-rejected rejection",
    );

    push_result(
        checks,
        "validation.check.clock_authority_application_accepted",
        clock_application_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.accepted_clock_review,
            &fixtures.accepted_clock_application,
        ),
        "clock authority application deterministically advances accepted clock state",
    );

    push_result(
        checks,
        "validation.check.clock_authority_application_rejected",
        clock_application_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.stale_clock_review,
            &fixtures.rejected_clock_application,
        ),
        "clock authority application deterministically rejects rejected clock reviews",
    );

    let selection_result = match fixtures.deployment_manifest.selection_snapshot(
        &fixtures.package_manifest,
        &fixtures.module_manifests,
        &fixtures.valid_host,
    ) {
        Ok(snapshot) if snapshot == fixtures.deployment_selection => Ok(()),
        Ok(_) => Err("deployment selection snapshot mismatch".to_owned()),
        Err(error) => Err(error.to_string()),
    };
    push_result(
        checks,
        "validation.check.deployment_selection",
        selection_result,
        "deployment selection resolves package, modules, host, endpoint, and backends",
    );

    let host_run_result = if !fixtures
        .host_run_profiles
        .iter()
        .any(|profile| profile.host_profile == fixtures.host_run_bundle.target_host_profile)
    {
        Err("host-run bundle target host profile missing".to_owned())
    } else if fixtures.host_run_bundle.validation_slot_id != fixtures.host_run_slot.slot_id
        || fixtures.host_run_command.validation_slot_id != fixtures.host_run_slot.slot_id
        || fixtures.host_run_evidence.validation_slot_id != fixtures.host_run_slot.slot_id
    {
        Err("host-run slot ids do not align".to_owned())
    } else if fixtures.host_run_evidence.bundle_id != fixtures.host_run_bundle.bundle_id {
        Err("host-run evidence does not reference the run bundle".to_owned())
    } else if fixtures.host_run_evidence.status != rusty_manifold_model::ValidationStatus::Pass {
        Err("host-run evidence fixture did not pass".to_owned())
    } else {
        Ok(())
    };
    push_result(
        checks,
        "validation.check.host_run_bundle_links",
        host_run_result,
        "host-run bundle, command envelope, validation slot, profiles, and evidence align",
    );

    push_result(
        checks,
        "validation.check.shell_handoff_links",
        fixtures.shell_handoff.validate_links(
            &fixtures.valid_registry,
            &fixtures.package_manifest.exports.commands,
            endpoint_ids,
            std::slice::from_ref(&fixtures.host_run_slot.slot_id),
        ),
        "shell handoff streams, commands, endpoint, and validation slot resolve",
    );

    push_result(
        checks,
        "validation.check.shell_handoff_review_receipt",
        fixtures
            .shell_handoff_review
            .validate_against_handoff(&fixtures.shell_handoff),
        "shell handoff review receipt matches the handoff and stays review-only",
    );
}

fn push_damaged_checks(
    repo_root: &Path,
    checks: &mut Vec<ValidationCheckReport>,
    fixtures: &FixtureSet,
    module_ids: &[DottedId],
    endpoint_ids: &[DottedId],
) -> Result<(), CliError> {
    push_damaged(
        checks,
        "validation.check.damaged_endpoint_security",
        expected_rejection(repo_root, "fixtures/damaged/invalid-endpoint-security.json")?,
        fixtures
            .damaged_endpoint_host
            .validate_endpoint_security()
            .map_err(|error| error.rejection_code().to_owned()),
        "public relay endpoint without security policy is rejected",
    );

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

    push_damaged(
        checks,
        "validation.check.damaged_unknown_stream_module",
        expected_rejection(repo_root, "fixtures/damaged/unknown-module-link.json")?,
        fixtures
            .damaged_unknown_stream_module
            .validate_source_modules(module_ids)
            .map_err(|error| error.rejection_code().to_owned()),
        "stream registry referencing an unknown module is rejected",
    );

    push_damaged(
        checks,
        "validation.check.damaged_shell_handoff_missing_stream",
        expected_rejection(
            repo_root,
            "fixtures/damaged/shell-handoff-missing-stream.json",
        )?,
        fixtures
            .damaged_shell_handoff
            .validate_links(
                &fixtures.valid_registry,
                &fixtures.package_manifest.exports.commands,
                endpoint_ids,
                std::slice::from_ref(&fixtures.host_run_slot.slot_id),
            )
            .map_err(|error| error.rejection_code().to_owned()),
        "shell handoff referencing an unknown stream is rejected",
    );

    push_damaged(
        checks,
        "validation.check.damaged_shell_handoff_review_runtime_started",
        expected_rejection(
            repo_root,
            "fixtures/damaged/shell-handoff-review-runtime-started.json",
        )?,
        fixtures
            .damaged_shell_handoff_review
            .validate_against_handoff(&fixtures.shell_handoff)
            .map_err(|error| error.rejection_code().to_owned()),
        "shell handoff review receipt claiming runtime work is rejected",
    );

    push_damaged(
        checks,
        "validation.check.damaged_unknown_graph_module",
        expected_rejection(repo_root, "fixtures/damaged/unknown-graph-module-link.json")?,
        fixtures
            .damaged_unknown_graph_module
            .validate_links(module_ids)
            .map_err(|error| error.rejection_code().to_owned()),
        "graph node referencing an unknown module is rejected",
    );

    push_damaged(
        checks,
        "validation.check.damaged_unknown_graph_node",
        expected_rejection(repo_root, "fixtures/damaged/unknown-graph-node-link.json")?,
        fixtures
            .damaged_unknown_graph_node
            .validate_links(module_ids)
            .map_err(|error| error.rejection_code().to_owned()),
        "graph edge referencing an unknown node is rejected",
    );

    push_damaged(
        checks,
        "validation.check.damaged_unavailable_deployment_backend",
        expected_rejection(
            repo_root,
            "fixtures/damaged/unavailable-deployment-backend.json",
        )?,
        fixtures
            .damaged_unavailable_deployment
            .validate_selection(
                &fixtures.package_manifest,
                &fixtures.module_manifests,
                &fixtures.valid_host,
            )
            .map_err(|error| error.rejection_code().to_owned()),
        "deployment selecting an unavailable backend is rejected",
    );

    Ok(())
}

fn simulate_synthetic_topology(repo_root: &Path) -> Result<SimulatorSnapshot, CliError> {
    let package_manifest = read_model::<ManifoldPackageManifest>(
        repo_root.join("fixtures/package/synthetic-package.json"),
    )?;
    let provider_manifest = read_model::<ManifoldModuleManifest>(
        repo_root.join("fixtures/module/synthetic-wave-provider.json"),
    )?;
    let processor_manifest = read_model::<ManifoldModuleManifest>(
        repo_root.join("fixtures/module/synthetic-wave-processor.json"),
    )?;
    let module_manifests = vec![provider_manifest, processor_manifest];
    let provider_runtime = read_model::<ManifoldModuleRuntimeState>(
        repo_root.join("fixtures/module/synthetic-wave-runtime-state.json"),
    )?;
    let processor_runtime = read_model::<ManifoldModuleRuntimeState>(
        repo_root.join("fixtures/module/synthetic-processor-runtime-state.json"),
    )?;
    let module_runtime_states = vec![provider_runtime, processor_runtime];
    let valid_host =
        read_model::<ManifoldHostManifest>(repo_root.join("fixtures/host/synthetic-host.json"))?;
    let valid_graph = read_model::<ManifoldGraphManifest>(
        repo_root.join("fixtures/graph/synthetic-wave-pipeline.json"),
    )?;
    let valid_registry = read_model::<ManifoldStreamRegistrySnapshot>(
        repo_root.join("fixtures/stream/synthetic-stream-registry.json"),
    )?;
    let command_descriptor = read_model::<ManifoldCommandDescriptor>(
        repo_root.join("fixtures/command/synthetic-command-descriptor.json"),
    )?;
    let valid_envelope = read_model::<ManifoldCommandEnvelope>(
        repo_root.join("fixtures/command/synthetic-command-envelope.json"),
    )?;
    let valid_ack = read_model::<ManifoldCommandAck>(
        repo_root.join("fixtures/command/synthetic-command-ack.json"),
    )?;
    let control_lease = read_model::<ManifoldControlLease>(
        repo_root.join("fixtures/command/synthetic-control-lease.json"),
    )?;
    let damaged_stale_command = read_model::<ManifoldCommandEnvelope>(
        repo_root.join("fixtures/damaged/stale-revision-command.json"),
    )?;
    let module_ids = module_manifests
        .iter()
        .map(|module| module.module_id.clone())
        .collect::<Vec<_>>();

    valid_host.validate_endpoint_security()?;
    valid_graph.validate_links(&module_ids)?;
    valid_registry.validate_source_modules(&module_ids)?;
    valid_envelope.validate_request(
        &command_descriptor,
        Revision::INITIAL,
        Some(&control_lease),
    )?;

    let stale_rejection = damaged_stale_command
        .validate_request(
            &command_descriptor,
            Revision::new(2).expect("literal is non-zero"),
            Some(&control_lease),
        )
        .expect_err("stale command fixture must reject");

    Ok(SimulatorSnapshot {
        schema_id: "rusty.manifold.simulator.snapshot.v1".to_owned(),
        simulation_id: "simulation.synthetic_wave_pipeline".to_owned(),
        host_id: valid_host.host_id.to_string(),
        package_id: package_manifest.package_id.to_string(),
        graph_id: valid_graph.graph_id.to_string(),
        graph_revision: valid_graph.graph_revision.get(),
        module_states: module_runtime_states
            .iter()
            .map(|state| ModuleStateSummary {
                module_id: state.module_id.to_string(),
                lifecycle: to_json_string(&state.lifecycle),
                health: to_json_string(&state.health),
                selected_backend: state
                    .selected_backend
                    .as_ref()
                    .map(std::string::ToString::to_string),
            })
            .collect(),
        stream_registry_revision: valid_registry.registry_revision.get(),
        streams: valid_registry
            .streams
            .iter()
            .map(|stream| stream.stream_id.to_string())
            .collect(),
        accepted_commands: vec![CommandAcceptanceSummary {
            request_id: valid_ack.request_id.to_string(),
            command_id: valid_envelope.command_id.to_string(),
            accepted_revision: valid_ack.accepted_revision.get(),
        }],
        rejected_commands: vec![CommandRejectionSummary {
            request_id: damaged_stale_command.request_id.to_string(),
            command_id: damaged_stale_command.command_id.to_string(),
            rejection_code: stale_rejection.rejection_code().to_owned(),
        }],
        scorecard: ScorecardSummary {
            scorecard_id: "scorecard.synthetic_simulator_pass".to_owned(),
            status: "pass".to_owned(),
            checks: vec![
                "validation.check.host_endpoint_security".to_owned(),
                "validation.check.graph_links".to_owned(),
                "validation.check.stream_registry_links".to_owned(),
                "validation.check.command_accept".to_owned(),
                "validation.check.stale_reject".to_owned(),
            ],
        },
    })
}

fn diff_synthetic_contracts(repo_root: &Path) -> Result<FixtureDiffSnapshot, CliError> {
    let package_manifest = read_model::<ManifoldPackageManifest>(
        repo_root.join("fixtures/package/synthetic-package.json"),
    )?;
    let provider_manifest = read_model::<ManifoldModuleManifest>(
        repo_root.join("fixtures/module/synthetic-wave-provider.json"),
    )?;
    let processor_manifest = read_model::<ManifoldModuleManifest>(
        repo_root.join("fixtures/module/synthetic-wave-processor.json"),
    )?;
    let module_manifests = vec![provider_manifest, processor_manifest];
    let provider_runtime = read_model::<ManifoldModuleRuntimeState>(
        repo_root.join("fixtures/module/synthetic-wave-runtime-state.json"),
    )?;
    let next_provider_runtime = read_model::<ManifoldModuleRuntimeState>(
        repo_root.join("fixtures/module/synthetic-wave-runtime-state-v2.json"),
    )?;
    let valid_graph = read_model::<ManifoldGraphManifest>(
        repo_root.join("fixtures/graph/synthetic-wave-pipeline.json"),
    )?;
    let next_graph = read_model::<ManifoldGraphManifest>(
        repo_root.join("fixtures/graph/synthetic-wave-pipeline-v2.json"),
    )?;
    let valid_registry = read_model::<ManifoldStreamRegistrySnapshot>(
        repo_root.join("fixtures/stream/synthetic-stream-registry.json"),
    )?;
    let next_registry = read_model::<ManifoldStreamRegistrySnapshot>(
        repo_root.join("fixtures/stream/synthetic-stream-registry-v2.json"),
    )?;
    let valid_host =
        read_model::<ManifoldHostManifest>(repo_root.join("fixtures/host/synthetic-host.json"))?;
    let deployment_manifest = read_model::<ManifoldDeploymentManifest>(
        repo_root.join("fixtures/deployment/synthetic-deployment.json"),
    )?;
    let deployment_selection = deployment_manifest.selection_snapshot(
        &package_manifest,
        &module_manifests,
        &valid_host,
    )?;

    Ok(FixtureDiffSnapshot {
        schema_id: "rusty.manifold.diff.snapshot.v1".to_owned(),
        graph_diff: next_graph.diff_from(&valid_graph),
        stream_registry_diff: next_registry.diff_from(&valid_registry),
        runtime_transition: next_provider_runtime.transition_from(&provider_runtime),
        deployment_selection,
    })
}

fn review_shell_handoff(
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

fn review_command(
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

fn command_review_evidence_ref(envelope: &ManifoldCommandEnvelope) -> DottedId {
    DottedId::new(format!(
        "evidence.command_authority.{}",
        envelope.request_id.as_str()
    ))
    .expect("derived command-review evidence id is valid")
}

fn command_review_matches_fixture(
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

fn prepare_command_dispatch(
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

fn command_dispatch_matches_fixture(
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

fn review_lease(
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

fn lease_review_evidence_ref(request: &ManifoldControlLeaseRequest) -> DottedId {
    DottedId::new(format!(
        "evidence.lease_authority.{}",
        request.request_id.as_str()
    ))
    .expect("derived lease-review evidence id is valid")
}

fn lease_review_matches_fixture(
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

fn apply_lease_review(
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

fn lease_application_matches_fixture(
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

fn review_lease_release(
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

fn lease_release_review_evidence_ref(request: &ManifoldControlLeaseReleaseRequest) -> DottedId {
    DottedId::new(format!(
        "evidence.lease_release_authority.{}",
        request.request_id.as_str()
    ))
    .expect("derived lease-release-review evidence id is valid")
}

fn lease_release_review_matches_fixture(
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

fn apply_lease_release_review(
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

fn lease_release_application_matches_fixture(
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

fn review_lease_renewal(
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

fn lease_renewal_review_evidence_ref(request: &ManifoldControlLeaseRenewalRequest) -> DottedId {
    DottedId::new(format!(
        "evidence.lease_renewal_authority.{}",
        request.request_id.as_str()
    ))
    .expect("derived lease-renewal-review evidence id is valid")
}

fn lease_renewal_review_matches_fixture(
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

fn apply_lease_renewal_review(
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

fn lease_renewal_application_matches_fixture(
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

fn review_stream_registry(
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

fn stream_registry_review_evidence_ref(request: &ManifoldStreamRegistryChangeRequest) -> DottedId {
    DottedId::new(format!(
        "evidence.stream_registry_authority.{}",
        request.request_id.as_str()
    ))
    .expect("derived stream-registry-review evidence id is valid")
}

fn stream_registry_review_matches_fixture(
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

fn apply_stream_registry_review(
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

fn stream_registry_application_matches_fixture(
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

fn review_stream_subscription(
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

fn stream_subscription_review_evidence_ref(
    request: &ManifoldStreamSubscriptionRequest,
) -> DottedId {
    DottedId::new(format!(
        "evidence.stream_subscription_authority.{}",
        request.request_id.as_str()
    ))
    .expect("derived stream-subscription-review evidence id is valid")
}

fn stream_subscription_review_matches_fixture(
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

fn apply_stream_subscription_review(
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

fn stream_subscription_application_matches_fixture(
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

fn review_stream_subscription_release(
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

fn stream_subscription_release_review_evidence_ref(
    request: &ManifoldStreamSubscriptionReleaseRequest,
) -> DottedId {
    DottedId::new(format!(
        "evidence.stream_subscription_release_authority.{}",
        request.request_id.as_str()
    ))
    .expect("derived stream-subscription-release-review evidence id is valid")
}

fn stream_subscription_release_review_matches_fixture(
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

fn apply_stream_subscription_release_review(
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

fn stream_subscription_release_application_matches_fixture(
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

fn review_stream_subscription_renewal(
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

fn stream_subscription_renewal_review_evidence_ref(
    request: &ManifoldStreamSubscriptionRenewalRequest,
) -> DottedId {
    DottedId::new(format!(
        "evidence.stream_subscription_renewal_authority.{}",
        request.request_id.as_str()
    ))
    .expect("derived stream-subscription-renewal-review evidence id is valid")
}

fn stream_subscription_renewal_review_matches_fixture(
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

fn apply_stream_subscription_renewal_review(
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

fn stream_subscription_renewal_application_matches_fixture(
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

fn review_authority_expiry_sweep(
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

fn authority_expiry_sweep_review_evidence_ref(
    request: &ManifoldAuthorityExpirySweepRequest,
) -> DottedId {
    DottedId::new(format!(
        "evidence.expiry_sweep_authority.{}",
        request.request_id.as_str()
    ))
    .expect("derived authority-expiry-sweep-review evidence id is valid")
}

fn authority_expiry_sweep_review_matches_fixture(
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

fn apply_authority_expiry_sweep_review(
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

fn authority_expiry_sweep_application_matches_fixture(
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

fn review_module_runtime(
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

fn apply_module_runtime_review(
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

fn module_runtime_review_evidence_ref(
    request: &ManifoldModuleRuntimeStateChangeRequest,
) -> DottedId {
    DottedId::new(format!(
        "evidence.module_runtime_state_authority.{}",
        request.request_id.as_str()
    ))
    .expect("derived module-runtime-state-review evidence id is valid")
}

fn module_runtime_review_matches_fixture(
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

fn module_runtime_application_matches_fixture(
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

fn review_host_manifest(
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

fn host_manifest_review_evidence_ref(request: &ManifoldHostManifestChangeRequest) -> DottedId {
    DottedId::new(format!(
        "evidence.host_manifest_authority.{}",
        request.request_id.as_str()
    ))
    .expect("derived host-manifest-review evidence id is valid")
}

fn host_manifest_review_matches_fixture(
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

fn apply_host_manifest_review(
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

fn host_manifest_application_matches_fixture(
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

fn review_clock(
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

fn clock_review_evidence_ref(request: &ManifoldClockSnapshotChangeRequest) -> DottedId {
    DottedId::new(format!(
        "evidence.clock_snapshot_authority.{}",
        request.request_id.as_str()
    ))
    .expect("derived clock-review evidence id is valid")
}

fn clock_review_matches_fixture(
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

fn apply_clock_review(
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

fn clock_application_matches_fixture(
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

fn resolve_input_path(repo_root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        repo_root.join(path)
    }
}

#[derive(Debug)]
struct FixtureSet {
    package_manifest: ManifoldPackageManifest,
    valid_graph: ManifoldGraphManifest,
    module_manifests: Vec<ManifoldModuleManifest>,
    next_provider_runtime: ManifoldModuleRuntimeState,
    valid_registry: ManifoldStreamRegistrySnapshot,
    stream_registry_diff: ManifoldStreamRegistryDiff,
    command_descriptor: ManifoldCommandDescriptor,
    valid_envelope: ManifoldCommandEnvelope,
    lease_request: ManifoldControlLeaseRequest,
    control_lease: ManifoldControlLease,
    authority_snapshot: ManifoldAuthoritySnapshot,
    authority_snapshot_v2: ManifoldAuthoritySnapshot,
    command_review_clock: ManifoldClockSnapshot,
    expired_command_review_clock: ManifoldClockSnapshot,
    command_authority_audit_event: ManifoldCommandAuthorityAuditEvent,
    accepted_command_review: ManifoldCommandAuthorityReview,
    stale_revision_command_review: ManifoldCommandAuthorityReview,
    expired_lease_command_review: ManifoldCommandAuthorityReview,
    missing_lease_command_review: ManifoldCommandAuthorityReview,
    unknown_command_review_envelope: ManifoldCommandEnvelope,
    unknown_command_review: ManifoldCommandAuthorityReview,
    unknown_lease_review_envelope: ManifoldCommandEnvelope,
    unknown_lease_command_review: ManifoldCommandAuthorityReview,
    capability_mismatch_review_envelope: ManifoldCommandEnvelope,
    capability_mismatch_command_review: ManifoldCommandAuthorityReview,
    command_dispatch_rejection: ManifoldCommandDispatchRejection,
    accepted_command_dispatch: Box<ManifoldCommandDispatchReceipt>,
    rejected_command_dispatch: Box<ManifoldCommandDispatchReceipt>,
    lease_rejection: ManifoldControlLeaseRejection,
    lease_authority_audit_event: ManifoldControlLeaseAuthorityAuditEvent,
    accepted_lease_review: ManifoldControlLeaseAuthorityReview,
    stale_lease_request: ManifoldControlLeaseRequest,
    stale_revision_lease_review: ManifoldControlLeaseAuthorityReview,
    zero_ttl_lease_request: ManifoldControlLeaseRequest,
    zero_ttl_lease_review: ManifoldControlLeaseAuthorityReview,
    missing_capability_lease_request: ManifoldControlLeaseRequest,
    missing_capability_lease_review: ManifoldControlLeaseAuthorityReview,
    busy_scope_lease_request: ManifoldControlLeaseRequest,
    busy_scope_lease_review: ManifoldControlLeaseAuthorityReview,
    accepted_lease_application: Box<ManifoldControlLeaseAuthorityApplication>,
    rejected_lease_application: Box<ManifoldControlLeaseAuthorityApplication>,
    lease_application_rejection: ManifoldAuthoritySnapshotApplicationRejection,
    lease_active_authority_snapshot: ManifoldAuthoritySnapshot,
    lease_release_request: ManifoldControlLeaseReleaseRequest,
    lease_release_rejection: ManifoldControlLeaseReleaseRejection,
    lease_release_authority_audit_event: ManifoldControlLeaseReleaseAuthorityAuditEvent,
    accepted_lease_release_review: ManifoldControlLeaseReleaseAuthorityReview,
    expired_lease_release_review: ManifoldControlLeaseReleaseAuthorityReview,
    stale_lease_release_request: ManifoldControlLeaseReleaseRequest,
    stale_lease_release_review: ManifoldControlLeaseReleaseAuthorityReview,
    unknown_lease_release_request: ManifoldControlLeaseReleaseRequest,
    unknown_lease_release_review: ManifoldControlLeaseReleaseAuthorityReview,
    holder_mismatch_lease_release_request: ManifoldControlLeaseReleaseRequest,
    holder_mismatch_lease_release_review: ManifoldControlLeaseReleaseAuthorityReview,
    scope_mismatch_lease_release_request: ManifoldControlLeaseReleaseRequest,
    scope_mismatch_lease_release_review: ManifoldControlLeaseReleaseAuthorityReview,
    accepted_lease_release_application: Box<ManifoldControlLeaseReleaseAuthorityApplication>,
    rejected_lease_release_application: Box<ManifoldControlLeaseReleaseAuthorityApplication>,
    lease_release_application_rejection: ManifoldAuthoritySnapshotApplicationRejection,
    lease_renewal_request: ManifoldControlLeaseRenewalRequest,
    lease_renewal_rejection: ManifoldControlLeaseRenewalRejection,
    lease_renewal_authority_audit_event: ManifoldControlLeaseRenewalAuthorityAuditEvent,
    accepted_lease_renewal_review: ManifoldControlLeaseRenewalAuthorityReview,
    stale_lease_renewal_request: ManifoldControlLeaseRenewalRequest,
    stale_lease_renewal_review: ManifoldControlLeaseRenewalAuthorityReview,
    unknown_lease_renewal_request: ManifoldControlLeaseRenewalRequest,
    unknown_lease_renewal_review: ManifoldControlLeaseRenewalAuthorityReview,
    holder_mismatch_lease_renewal_request: ManifoldControlLeaseRenewalRequest,
    holder_mismatch_lease_renewal_review: ManifoldControlLeaseRenewalAuthorityReview,
    scope_mismatch_lease_renewal_request: ManifoldControlLeaseRenewalRequest,
    scope_mismatch_lease_renewal_review: ManifoldControlLeaseRenewalAuthorityReview,
    zero_ttl_lease_renewal_request: ManifoldControlLeaseRenewalRequest,
    zero_ttl_lease_renewal_review: ManifoldControlLeaseRenewalAuthorityReview,
    non_extending_lease_renewal_request: ManifoldControlLeaseRenewalRequest,
    non_extending_lease_renewal_review: ManifoldControlLeaseRenewalAuthorityReview,
    expired_lease_renewal_review: ManifoldControlLeaseRenewalAuthorityReview,
    accepted_lease_renewal_application: Box<ManifoldControlLeaseRenewalAuthorityApplication>,
    rejected_lease_renewal_application: Box<ManifoldControlLeaseRenewalAuthorityApplication>,
    lease_renewal_application_rejection: ManifoldAuthoritySnapshotApplicationRejection,
    stream_registry_lease: ManifoldControlLease,
    stream_registry_change_request: ManifoldStreamRegistryChangeRequest,
    stream_registry_rejection: ManifoldStreamRegistryRejection,
    stream_registry_authority_audit_event: ManifoldStreamRegistryAuthorityAuditEvent,
    accepted_stream_registry_review: ManifoldStreamRegistryAuthorityReview,
    expired_lease_stream_registry_review: ManifoldStreamRegistryAuthorityReview,
    stale_stream_registry_request: ManifoldStreamRegistryChangeRequest,
    stale_stream_registry_review: ManifoldStreamRegistryAuthorityReview,
    missing_lease_stream_registry_request: ManifoldStreamRegistryChangeRequest,
    missing_lease_stream_registry_review: ManifoldStreamRegistryAuthorityReview,
    active_stream_registry_request: ManifoldStreamRegistryChangeRequest,
    active_stream_registry_review: ManifoldStreamRegistryAuthorityReview,
    unknown_module_stream_registry_request: ManifoldStreamRegistryChangeRequest,
    unknown_module_stream_registry_review: ManifoldStreamRegistryAuthorityReview,
    unknown_endpoint_stream_registry_request: ManifoldStreamRegistryChangeRequest,
    unknown_endpoint_stream_registry_review: ManifoldStreamRegistryAuthorityReview,
    accepted_stream_registry_application: Box<ManifoldStreamRegistryAuthorityApplication>,
    rejected_stream_registry_application: Box<ManifoldStreamRegistryAuthorityApplication>,
    stream_registry_application_rejection: ManifoldAuthoritySnapshotApplicationRejection,
    stream_subscription_authority_snapshot: ManifoldAuthoritySnapshot,
    stream_subscription_request: ManifoldStreamSubscriptionRequest,
    stream_subscription: ManifoldStreamSubscription,
    stream_subscription_rejection: ManifoldStreamSubscriptionRejection,
    stream_subscription_authority_audit_event: ManifoldStreamSubscriptionAuthorityAuditEvent,
    accepted_stream_subscription_review: ManifoldStreamSubscriptionAuthorityReview,
    zero_ttl_stream_subscription_request: ManifoldStreamSubscriptionRequest,
    zero_ttl_stream_subscription_review: ManifoldStreamSubscriptionAuthorityReview,
    missing_capability_stream_subscription_request: ManifoldStreamSubscriptionRequest,
    missing_capability_stream_subscription_review: ManifoldStreamSubscriptionAuthorityReview,
    stale_stream_subscription_request: ManifoldStreamSubscriptionRequest,
    stale_stream_subscription_review: ManifoldStreamSubscriptionAuthorityReview,
    stale_registry_stream_subscription_request: ManifoldStreamSubscriptionRequest,
    stale_registry_stream_subscription_review: ManifoldStreamSubscriptionAuthorityReview,
    unknown_stream_subscription_request: ManifoldStreamSubscriptionRequest,
    unknown_stream_subscription_review: ManifoldStreamSubscriptionAuthorityReview,
    unknown_transport_stream_subscription_request: ManifoldStreamSubscriptionRequest,
    unknown_transport_stream_subscription_review: ManifoldStreamSubscriptionAuthorityReview,
    subscriber_limit_stream_subscription_authority_snapshot: ManifoldAuthoritySnapshot,
    subscriber_limit_stream_subscription_request: ManifoldStreamSubscriptionRequest,
    subscriber_limit_stream_subscription_review: ManifoldStreamSubscriptionAuthorityReview,
    ui_disabled_stream_subscription_authority_snapshot: ManifoldAuthoritySnapshot,
    ui_disabled_stream_subscription_request: ManifoldStreamSubscriptionRequest,
    ui_disabled_stream_subscription_review: ManifoldStreamSubscriptionAuthorityReview,
    accepted_stream_subscription_application: Box<ManifoldStreamSubscriptionAuthorityApplication>,
    rejected_stream_subscription_application: Box<ManifoldStreamSubscriptionAuthorityApplication>,
    stream_subscription_application_rejection: ManifoldAuthoritySnapshotApplicationRejection,
    stream_subscription_active_authority_snapshot: ManifoldAuthoritySnapshot,
    stream_subscription_release_request: ManifoldStreamSubscriptionReleaseRequest,
    stream_subscription_release_rejection: ManifoldStreamSubscriptionReleaseRejection,
    stream_subscription_release_authority_audit_event:
        ManifoldStreamSubscriptionReleaseAuthorityAuditEvent,
    accepted_stream_subscription_release_review: ManifoldStreamSubscriptionReleaseAuthorityReview,
    expired_stream_subscription_release_review: ManifoldStreamSubscriptionReleaseAuthorityReview,
    stale_stream_subscription_release_request: ManifoldStreamSubscriptionReleaseRequest,
    stale_stream_subscription_release_review: ManifoldStreamSubscriptionReleaseAuthorityReview,
    stale_registry_stream_subscription_release_request: ManifoldStreamSubscriptionReleaseRequest,
    stale_registry_stream_subscription_release_review:
        ManifoldStreamSubscriptionReleaseAuthorityReview,
    unknown_stream_subscription_release_request: ManifoldStreamSubscriptionReleaseRequest,
    unknown_stream_subscription_release_review: ManifoldStreamSubscriptionReleaseAuthorityReview,
    subscriber_mismatch_stream_subscription_release_request:
        ManifoldStreamSubscriptionReleaseRequest,
    subscriber_mismatch_stream_subscription_release_review:
        ManifoldStreamSubscriptionReleaseAuthorityReview,
    stream_mismatch_stream_subscription_release_request: ManifoldStreamSubscriptionReleaseRequest,
    stream_mismatch_stream_subscription_release_review:
        ManifoldStreamSubscriptionReleaseAuthorityReview,
    accepted_stream_subscription_release_application:
        Box<ManifoldStreamSubscriptionReleaseAuthorityApplication>,
    rejected_stream_subscription_release_application:
        Box<ManifoldStreamSubscriptionReleaseAuthorityApplication>,
    stream_subscription_release_application_rejection:
        ManifoldAuthoritySnapshotApplicationRejection,
    stream_subscription_renewal_request: ManifoldStreamSubscriptionRenewalRequest,
    stream_subscription_renewal_rejection: ManifoldStreamSubscriptionRenewalRejection,
    stream_subscription_renewal_authority_audit_event:
        ManifoldStreamSubscriptionRenewalAuthorityAuditEvent,
    accepted_stream_subscription_renewal_review: ManifoldStreamSubscriptionRenewalAuthorityReview,
    stale_stream_subscription_renewal_request: ManifoldStreamSubscriptionRenewalRequest,
    stale_stream_subscription_renewal_review: ManifoldStreamSubscriptionRenewalAuthorityReview,
    stale_registry_stream_subscription_renewal_request: ManifoldStreamSubscriptionRenewalRequest,
    stale_registry_stream_subscription_renewal_review:
        ManifoldStreamSubscriptionRenewalAuthorityReview,
    unknown_stream_subscription_renewal_request: ManifoldStreamSubscriptionRenewalRequest,
    unknown_stream_subscription_renewal_review: ManifoldStreamSubscriptionRenewalAuthorityReview,
    subscriber_mismatch_stream_subscription_renewal_request:
        ManifoldStreamSubscriptionRenewalRequest,
    subscriber_mismatch_stream_subscription_renewal_review:
        ManifoldStreamSubscriptionRenewalAuthorityReview,
    stream_mismatch_stream_subscription_renewal_request: ManifoldStreamSubscriptionRenewalRequest,
    stream_mismatch_stream_subscription_renewal_review:
        ManifoldStreamSubscriptionRenewalAuthorityReview,
    transport_mismatch_stream_subscription_renewal_request:
        ManifoldStreamSubscriptionRenewalRequest,
    transport_mismatch_stream_subscription_renewal_review:
        ManifoldStreamSubscriptionRenewalAuthorityReview,
    zero_ttl_stream_subscription_renewal_request: ManifoldStreamSubscriptionRenewalRequest,
    zero_ttl_stream_subscription_renewal_review: ManifoldStreamSubscriptionRenewalAuthorityReview,
    non_extending_stream_subscription_renewal_request: ManifoldStreamSubscriptionRenewalRequest,
    non_extending_stream_subscription_renewal_review:
        ManifoldStreamSubscriptionRenewalAuthorityReview,
    expired_stream_subscription_renewal_review: ManifoldStreamSubscriptionRenewalAuthorityReview,
    accepted_stream_subscription_renewal_application:
        Box<ManifoldStreamSubscriptionRenewalAuthorityApplication>,
    rejected_stream_subscription_renewal_application:
        Box<ManifoldStreamSubscriptionRenewalAuthorityApplication>,
    stream_subscription_renewal_application_rejection:
        ManifoldAuthoritySnapshotApplicationRejection,
    authority_expiry_sweep_request: ManifoldAuthorityExpirySweepRequest,
    authority_expiry_sweep_rejection: ManifoldAuthorityExpirySweepRejection,
    authority_expiry_sweep_authority_audit_event: ManifoldAuthorityExpirySweepAuthorityAuditEvent,
    accepted_authority_expiry_sweep_review: ManifoldAuthorityExpirySweepAuthorityReview,
    stale_authority_expiry_sweep_request: ManifoldAuthorityExpirySweepRequest,
    stale_authority_expiry_sweep_review: ManifoldAuthorityExpirySweepAuthorityReview,
    registry_mismatch_authority_expiry_sweep_request: ManifoldAuthorityExpirySweepRequest,
    registry_mismatch_authority_expiry_sweep_review: ManifoldAuthorityExpirySweepAuthorityReview,
    no_expired_authority_expiry_sweep_review: ManifoldAuthorityExpirySweepAuthorityReview,
    accepted_authority_expiry_sweep_application:
        Box<ManifoldAuthorityExpirySweepAuthorityApplication>,
    rejected_authority_expiry_sweep_application:
        Box<ManifoldAuthorityExpirySweepAuthorityApplication>,
    authority_expiry_sweep_application_rejection: ManifoldAuthoritySnapshotApplicationRejection,
    module_runtime_state_change_request: ManifoldModuleRuntimeStateChangeRequest,
    module_runtime_state_rejection: ManifoldModuleRuntimeStateRejection,
    module_runtime_state_authority_audit_event: ManifoldModuleRuntimeStateAuthorityAuditEvent,
    accepted_module_runtime_review: ManifoldModuleRuntimeStateAuthorityReview,
    expired_lease_module_runtime_review: ManifoldModuleRuntimeStateAuthorityReview,
    stale_module_runtime_request: ManifoldModuleRuntimeStateChangeRequest,
    stale_module_runtime_review: ManifoldModuleRuntimeStateAuthorityReview,
    missing_lease_module_runtime_request: ManifoldModuleRuntimeStateChangeRequest,
    missing_lease_module_runtime_review: ManifoldModuleRuntimeStateAuthorityReview,
    unknown_stream_module_runtime_request: ManifoldModuleRuntimeStateChangeRequest,
    unknown_stream_module_runtime_review: ManifoldModuleRuntimeStateAuthorityReview,
    missing_backend_module_runtime_request: ManifoldModuleRuntimeStateChangeRequest,
    missing_backend_module_runtime_review: ManifoldModuleRuntimeStateAuthorityReview,
    accepted_module_runtime_application: Box<ManifoldModuleRuntimeStateAuthorityApplication>,
    rejected_module_runtime_application: Box<ManifoldModuleRuntimeStateAuthorityApplication>,
    module_runtime_application_rejection: ManifoldAuthoritySnapshotApplicationRejection,
    host_manifest_lease: ManifoldControlLease,
    host_manifest_change_request: ManifoldHostManifestChangeRequest,
    host_manifest_rejection: ManifoldHostManifestRejection,
    host_manifest_authority_audit_event: ManifoldHostManifestAuthorityAuditEvent,
    accepted_host_manifest_review: ManifoldHostManifestAuthorityReview,
    expired_lease_host_manifest_review: ManifoldHostManifestAuthorityReview,
    stale_host_manifest_request: ManifoldHostManifestChangeRequest,
    stale_host_manifest_review: ManifoldHostManifestAuthorityReview,
    missing_authority_role_host_manifest_request: ManifoldHostManifestChangeRequest,
    missing_authority_role_host_manifest_review: ManifoldHostManifestAuthorityReview,
    endpoint_mismatch_host_manifest_request: ManifoldHostManifestChangeRequest,
    endpoint_mismatch_host_manifest_review: ManifoldHostManifestAuthorityReview,
    remove_capability_host_manifest_request: ManifoldHostManifestChangeRequest,
    remove_capability_host_manifest_review: ManifoldHostManifestAuthorityReview,
    remove_backend_host_manifest_request: ManifoldHostManifestChangeRequest,
    remove_backend_host_manifest_review: ManifoldHostManifestAuthorityReview,
    accepted_host_manifest_application: Box<ManifoldHostManifestAuthorityApplication>,
    rejected_host_manifest_application: Box<ManifoldHostManifestAuthorityApplication>,
    host_manifest_application_rejection: ManifoldAuthoritySnapshotApplicationRejection,
    clock_lease: ManifoldControlLease,
    clock_change_request: ManifoldClockSnapshotChangeRequest,
    clock_rejection: ManifoldClockSnapshotRejection,
    clock_authority_audit_event: ManifoldClockSnapshotAuthorityAuditEvent,
    accepted_clock_review: ManifoldClockSnapshotAuthorityReview,
    expired_lease_clock_review: ManifoldClockSnapshotAuthorityReview,
    stale_clock_request: ManifoldClockSnapshotChangeRequest,
    stale_clock_review: ManifoldClockSnapshotAuthorityReview,
    missing_lease_clock_request: ManifoldClockSnapshotChangeRequest,
    missing_lease_clock_review: ManifoldClockSnapshotAuthorityReview,
    domain_mismatch_clock_request: ManifoldClockSnapshotChangeRequest,
    domain_mismatch_clock_review: ManifoldClockSnapshotAuthorityReview,
    sequence_gap_clock_request: ManifoldClockSnapshotChangeRequest,
    sequence_gap_clock_review: ManifoldClockSnapshotAuthorityReview,
    monotonic_regression_clock_request: ManifoldClockSnapshotChangeRequest,
    monotonic_regression_clock_review: ManifoldClockSnapshotAuthorityReview,
    accepted_clock_application: Box<ManifoldClockSnapshotAuthorityApplication>,
    rejected_clock_application: Box<ManifoldClockSnapshotAuthorityApplication>,
    clock_application_rejection: ManifoldAuthoritySnapshotApplicationRejection,
    valid_host: ManifoldHostManifest,
    deployment_manifest: ManifoldDeploymentManifest,
    deployment_selection: ManifoldDeploymentSelectionSnapshot,
    damaged_endpoint_host: ManifoldHostManifest,
    damaged_stale_command: ManifoldCommandEnvelope,
    damaged_missing_lease_command: ManifoldCommandEnvelope,
    damaged_command_authority_audit_event: ManifoldCommandAuthorityAuditEvent,
    damaged_unknown_stream_module: ManifoldStreamRegistrySnapshot,
    damaged_unknown_graph_module: ManifoldGraphManifest,
    damaged_unknown_graph_node: ManifoldGraphManifest,
    damaged_unavailable_deployment: ManifoldDeploymentManifest,
    platform_hosts: Vec<ManifoldHostManifest>,
    host_run_profiles: Vec<ManifoldHostRunInstallLaunchProfile>,
    host_run_slot: ManifoldHostRunValidationSlot,
    host_run_bundle: ManifoldHostRunBundle,
    host_run_command: ManifoldHostRunCommandEnvelope,
    host_run_evidence: ManifoldHostRunEvidence,
    shell_handoff: ManifoldShellHandoffManifest,
    shell_handoff_review: ManifoldShellHandoffReviewReceipt,
    damaged_shell_handoff: ManifoldShellHandoffManifest,
    damaged_shell_handoff_review: ManifoldShellHandoffReviewReceipt,
}

impl FixtureSet {
    fn load(repo_root: &Path) -> Result<Self, CliError> {
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

    fn endpoint_ids(&self) -> Vec<DottedId> {
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

#[derive(Serialize)]
struct FixtureDiffSnapshot {
    #[serde(rename = "$schema")]
    schema_id: String,
    graph_diff: ManifoldGraphDiff,
    stream_registry_diff: ManifoldStreamRegistryDiff,
    runtime_transition: ManifoldModuleRuntimeTransition,
    deployment_selection: ManifoldDeploymentSelectionSnapshot,
}

#[derive(Serialize)]
struct ValidationReport {
    #[serde(rename = "$schema")]
    schema_id: String,
    status: String,
    checks: Vec<ValidationCheckReport>,
}

#[derive(Serialize)]
struct ValidationCheckReport {
    check_id: String,
    status: String,
    evidence: String,
    rejection_code: Option<String>,
}

#[derive(Serialize)]
struct SimulatorSnapshot {
    #[serde(rename = "$schema")]
    schema_id: String,
    simulation_id: String,
    host_id: String,
    package_id: String,
    graph_id: String,
    graph_revision: u64,
    module_states: Vec<ModuleStateSummary>,
    stream_registry_revision: u64,
    streams: Vec<String>,
    accepted_commands: Vec<CommandAcceptanceSummary>,
    rejected_commands: Vec<CommandRejectionSummary>,
    scorecard: ScorecardSummary,
}

#[derive(Serialize)]
struct ModuleStateSummary {
    module_id: String,
    lifecycle: String,
    health: String,
    selected_backend: Option<String>,
}

#[derive(Serialize)]
struct CommandAcceptanceSummary {
    request_id: String,
    command_id: String,
    accepted_revision: u64,
}

#[derive(Serialize)]
struct CommandRejectionSummary {
    request_id: String,
    command_id: String,
    rejection_code: String,
}

#[derive(Serialize)]
struct ScorecardSummary {
    scorecard_id: String,
    status: String,
    checks: Vec<String>,
}

fn push_result<T, E>(
    checks: &mut Vec<ValidationCheckReport>,
    check_id: &str,
    result: Result<T, E>,
    evidence: &str,
) where
    E: fmt::Display,
{
    match result {
        Ok(_) => checks.push(pass(check_id, evidence)),
        Err(error) => checks.push(fail(check_id, error.to_string(), None)),
    }
}

fn push_damaged<T>(
    checks: &mut Vec<ValidationCheckReport>,
    check_id: &str,
    expected_rejection: String,
    result: Result<T, String>,
    evidence: &str,
) {
    match result {
        Ok(_) => checks.push(fail(
            check_id,
            format!("damaged input was accepted; expected {expected_rejection}"),
            Some(expected_rejection),
        )),
        Err(rejection_code) if rejection_code == expected_rejection => {
            checks.push(pass_with_rejection(check_id, evidence, rejection_code));
        }
        Err(rejection_code) => checks.push(fail(
            check_id,
            format!("expected {expected_rejection}, got {rejection_code}"),
            Some(rejection_code),
        )),
    }
}

fn push_deserialize_rejection<T>(
    checks: &mut Vec<ValidationCheckReport>,
    check_id: &str,
    expected_rejection: String,
    result: Result<T, CliError>,
    evidence: &str,
) {
    match result {
        Ok(_) => checks.push(fail(
            check_id,
            format!("damaged input was accepted; expected {expected_rejection}"),
            Some(expected_rejection),
        )),
        Err(CliError::Json { .. }) if expected_rejection == "invalid_dotted_id" => {
            checks.push(pass_with_rejection(check_id, evidence, expected_rejection));
        }
        Err(error) => checks.push(fail(check_id, error.to_string(), Some(expected_rejection))),
    }
}

fn pass(check_id: &str, evidence: &str) -> ValidationCheckReport {
    ValidationCheckReport {
        check_id: check_id.to_owned(),
        status: "pass".to_owned(),
        evidence: evidence.to_owned(),
        rejection_code: None,
    }
}

fn pass_with_rejection(
    check_id: &str,
    evidence: &str,
    rejection_code: String,
) -> ValidationCheckReport {
    ValidationCheckReport {
        check_id: check_id.to_owned(),
        status: "pass".to_owned(),
        evidence: evidence.to_owned(),
        rejection_code: Some(rejection_code),
    }
}

fn fail(check_id: &str, evidence: String, rejection_code: Option<String>) -> ValidationCheckReport {
    ValidationCheckReport {
        check_id: check_id.to_owned(),
        status: "fail".to_owned(),
        evidence,
        rejection_code,
    }
}

fn read_model<T>(path: impl AsRef<Path>) -> Result<T, CliError>
where
    T: DeserializeOwned,
{
    let path = path.as_ref();
    let text = read_text(path)?;
    serde_json::from_str(&text).map_err(|source| CliError::Json {
        path: path.to_path_buf(),
        source,
    })
}

fn read_text(path: &Path) -> Result<String, CliError> {
    fs::read_to_string(path).map_err(|source| CliError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn write_text(path: &Path, text: &str) -> Result<(), CliError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|source| CliError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let mut text = text.to_owned();
    text.push('\n');
    fs::write(path, text).map_err(|source| CliError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn expected_rejection(repo_root: &Path, relative_path: &str) -> Result<String, CliError> {
    let path = repo_root.join(relative_path);
    let text = read_text(&path)?;
    let value: serde_json::Value =
        serde_json::from_str(&text).map_err(|source| CliError::Json {
            path: path.clone(),
            source,
        })?;
    value
        .get("expected_rejection")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or(CliError::MissingExpectedRejection { path })
}

fn to_pretty_json<T>(value: &T) -> Result<String, CliError>
where
    T: Serialize,
{
    serde_json::to_string_pretty(value).map_err(CliError::Serialize)
}

fn to_json_string<T>(value: &T) -> String
where
    T: Serialize,
{
    serde_json::to_value(value)
        .expect("model enum serialization should not fail")
        .as_str()
        .expect("model enum serializes as a string")
        .to_owned()
}

fn default_repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn usage() -> String {
    "usage: rusty-manifold-fixtures <validate|simulate|diff|review-shell-handoff|review-command|prepare-command-dispatch|review-lease|apply-lease-review|review-lease-release|apply-lease-release-review|review-lease-renewal|apply-lease-renewal-review|review-stream-registry|apply-stream-registry-review|review-stream-subscription|apply-stream-subscription-review|review-stream-subscription-release|apply-stream-subscription-release-review|review-stream-subscription-renewal|apply-stream-subscription-renewal-review|review-authority-expiry-sweep|apply-authority-expiry-sweep-review|review-module-runtime|apply-module-runtime-review|review-host-manifest|apply-host-manifest-review|review-clock|apply-clock-review> [--repo-root <path>] [--check] [--handoff <path>] [--snapshot <path>] [--envelope <path>] [--request <path>] [--review <path>] [--clock <path>] [--output <path>]"
        .to_owned()
}

#[derive(Debug)]
enum CliError {
    Usage(String),
    UnknownCommand(String),
    UnknownOption(String),
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Json {
        path: PathBuf,
        source: serde_json::Error,
    },
    Serialize(serde_json::Error),
    MissingExpectedRejection {
        path: PathBuf,
    },
    ValidationFailed(String),
    SnapshotMismatch {
        expected_path: PathBuf,
        output: String,
    },
    EndpointSecurity(rusty_manifold_model::EndpointSecurityError),
    CommandValidation(rusty_manifold_model::CommandValidationError),
    DeploymentSelection(rusty_manifold_model::DeploymentSelectionError),
    GraphValidation(rusty_manifold_model::GraphValidationError),
    StreamRegistryValidation(rusty_manifold_model::StreamRegistryValidationError),
    ShellHandoffReviewReceiptValidation(
        rusty_manifold_model::ShellHandoffReviewReceiptValidationError,
    ),
    CommandAuthorityValidation(rusty_manifold_model::ManifoldAuthorityValidationError),
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(message) => formatter.write_str(message),
            Self::UnknownCommand(command) => write!(formatter, "unknown command: {command}"),
            Self::UnknownOption(option) => write!(formatter, "unknown option: {option}"),
            Self::Io { path, source } => write!(formatter, "{}: {source}", path.display()),
            Self::Json { path, source } => write!(formatter, "{}: {source}", path.display()),
            Self::Serialize(source) => write!(formatter, "failed to serialize output: {source}"),
            Self::MissingExpectedRejection { path } => {
                write!(formatter, "{}: missing expected_rejection", path.display())
            }
            Self::ValidationFailed(report) => {
                write!(formatter, "fixture validation failed:\n{report}")
            }
            Self::SnapshotMismatch {
                expected_path,
                output,
            } => write!(
                formatter,
                "simulator snapshot does not match {}\n{output}",
                expected_path.display()
            ),
            Self::EndpointSecurity(source) => write!(formatter, "{source}"),
            Self::CommandValidation(source) => write!(formatter, "{source}"),
            Self::DeploymentSelection(source) => write!(formatter, "{source}"),
            Self::GraphValidation(source) => write!(formatter, "{source}"),
            Self::StreamRegistryValidation(source) => write!(formatter, "{source}"),
            Self::ShellHandoffReviewReceiptValidation(source) => write!(formatter, "{source}"),
            Self::CommandAuthorityValidation(source) => write!(formatter, "{source}"),
        }
    }
}

impl std::error::Error for CliError {}

impl From<rusty_manifold_model::EndpointSecurityError> for CliError {
    fn from(source: rusty_manifold_model::EndpointSecurityError) -> Self {
        Self::EndpointSecurity(source)
    }
}

impl From<rusty_manifold_model::CommandValidationError> for CliError {
    fn from(source: rusty_manifold_model::CommandValidationError) -> Self {
        Self::CommandValidation(source)
    }
}

impl From<rusty_manifold_model::DeploymentSelectionError> for CliError {
    fn from(source: rusty_manifold_model::DeploymentSelectionError) -> Self {
        Self::DeploymentSelection(source)
    }
}

impl From<rusty_manifold_model::GraphValidationError> for CliError {
    fn from(source: rusty_manifold_model::GraphValidationError) -> Self {
        Self::GraphValidation(source)
    }
}

impl From<rusty_manifold_model::StreamRegistryValidationError> for CliError {
    fn from(source: rusty_manifold_model::StreamRegistryValidationError) -> Self {
        Self::StreamRegistryValidation(source)
    }
}

impl From<rusty_manifold_model::ShellHandoffReviewReceiptValidationError> for CliError {
    fn from(source: rusty_manifold_model::ShellHandoffReviewReceiptValidationError) -> Self {
        Self::ShellHandoffReviewReceiptValidation(source)
    }
}

impl From<rusty_manifold_model::ManifoldAuthorityValidationError> for CliError {
    fn from(source: rusty_manifold_model::ManifoldAuthorityValidationError) -> Self {
        Self::CommandAuthorityValidation(source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_passes_for_repo_fixtures() {
        let report = validate_repo(&default_repo_root()).unwrap();

        assert_eq!(report.status, "pass");
        assert!(report.checks.len() >= 10);
    }

    #[test]
    fn simulation_snapshot_is_deterministic() {
        let snapshot = simulate_synthetic_topology(&default_repo_root()).unwrap();
        let output = to_pretty_json(&snapshot).unwrap();
        let expected = read_text(
            &default_repo_root().join("fixtures/simulator/synthetic-topology-summary.json"),
        )
        .unwrap();

        assert_eq!(expected.trim_end(), output.trim_end());
    }

    #[test]
    fn diff_snapshot_is_deterministic() {
        let snapshot = diff_synthetic_contracts(&default_repo_root()).unwrap();
        let output = to_pretty_json(&snapshot).unwrap();
        let expected =
            read_text(&default_repo_root().join("fixtures/diff/synthetic-contract-diff.json"))
                .unwrap();

        assert_eq!(expected.trim_end(), output.trim_end());
    }

    #[test]
    fn shell_handoff_review_receipt_is_generated_from_handoff() {
        let handoff_path =
            default_repo_root().join("fixtures/shell-handoff/synthetic-loopback-shell.json");

        let receipt = review_shell_handoff(&default_repo_root(), &handoff_path).unwrap();

        assert_eq!(receipt.status, rusty_manifold_model::ValidationStatus::Pass);
        assert_eq!(
            receipt.handoff_id.to_string(),
            "shell_handoff.synthetic_wave.loopback"
        );
        assert!(!receipt.runtime_execution_performed);
        assert!(!receipt.launch_started);
        assert!(!receipt.command_session_started);
    }

    #[test]
    fn shell_handoff_review_command_writes_receipt() {
        let output_path = default_repo_root().join("target/test-shell-handoff-review.json");
        let _ = fs::remove_file(&output_path);

        let output = run(vec![
            "review-shell-handoff".to_string(),
            "--handoff".to_string(),
            default_repo_root()
                .join("fixtures/shell-handoff/synthetic-loopback-shell.json")
                .display()
                .to_string(),
            "--output".to_string(),
            output_path.display().to_string(),
        ])
        .unwrap();

        assert!(output.contains("\"$schema\": \"rusty.manifold.shell.handoff_review_receipt.v1\""));
        assert!(output_path.is_file());
        let written = read_text(&output_path).unwrap();
        assert_eq!(written.trim_end(), output.trim_end());
    }

    #[test]
    fn command_authority_review_command_matches_fixture() {
        let output = run(vec![
            "review-command".to_string(),
            "--snapshot".to_string(),
            "fixtures/authority/synthetic-authority-snapshot.json".to_string(),
            "--envelope".to_string(),
            "fixtures/command/synthetic-command-envelope.json".to_string(),
            "--clock".to_string(),
            "fixtures/clock/synthetic-command-review-clock.json".to_string(),
        ])
        .unwrap();
        let expected = read_text(
            &default_repo_root()
                .join("fixtures/authority-review/synthetic-command-accepted-review.json"),
        )
        .unwrap();

        assert!(output.contains("\"$schema\": \"rusty.manifold.authority.command_review.v1\""));
        assert_eq!(expected.trim_end(), output.trim_end());
    }

    #[test]
    fn command_dispatch_receipt_command_matches_fixture() {
        let output = run(vec![
            "prepare-command-dispatch".to_string(),
            "--snapshot".to_string(),
            "fixtures/authority/synthetic-authority-snapshot.json".to_string(),
            "--review".to_string(),
            "fixtures/authority-review/synthetic-command-accepted-review.json".to_string(),
        ])
        .unwrap();
        let expected = read_text(
            &default_repo_root()
                .join("fixtures/command-dispatch/synthetic-command-dispatch-ready-receipt.json"),
        )
        .unwrap();

        assert!(output
            .contains("\"$schema\": \"rusty.manifold.authority.command_dispatch_receipt.v1\""));
        assert_eq!(expected.trim_end(), output.trim_end());
    }

    #[test]
    fn lease_authority_review_command_matches_fixture() {
        let output = run(vec![
            "review-lease".to_string(),
            "--snapshot".to_string(),
            "fixtures/authority/synthetic-authority-snapshot.json".to_string(),
            "--request".to_string(),
            "fixtures/command/synthetic-lease-request.json".to_string(),
            "--clock".to_string(),
            "fixtures/clock/synthetic-command-review-clock.json".to_string(),
        ])
        .unwrap();
        let expected = read_text(
            &default_repo_root().join("fixtures/lease-review/synthetic-lease-accepted-review.json"),
        )
        .unwrap();

        assert!(output.contains("\"$schema\": \"rusty.manifold.authority.lease_review.v1\""));
        assert_eq!(expected.trim_end(), output.trim_end());
    }

    #[test]
    fn lease_authority_application_command_matches_fixture() {
        let output = run(vec![
            "apply-lease-review".to_string(),
            "--snapshot".to_string(),
            "fixtures/authority/synthetic-authority-snapshot.json".to_string(),
            "--review".to_string(),
            "fixtures/lease-review/synthetic-lease-accepted-review.json".to_string(),
        ])
        .unwrap();
        let expected = read_text(
            &default_repo_root()
                .join("fixtures/authority-application/synthetic-lease-accepted-application.json"),
        )
        .unwrap();

        assert!(output.contains("\"$schema\": \"rusty.manifold.authority.lease_application.v1\""));
        assert_eq!(expected.trim_end(), output.trim_end());
    }

    #[test]
    fn lease_release_authority_review_command_matches_fixture() {
        let output = run(vec![
            "review-lease-release".to_string(),
            "--snapshot".to_string(),
            "fixtures/authority/synthetic-lease-active-authority-snapshot.json".to_string(),
            "--request".to_string(),
            "fixtures/command/synthetic-lease-release-request.json".to_string(),
            "--clock".to_string(),
            "fixtures/clock/synthetic-command-review-clock.json".to_string(),
        ])
        .unwrap();
        let expected = read_text(
            &default_repo_root()
                .join("fixtures/lease-release-review/synthetic-lease-release-accepted-review.json"),
        )
        .unwrap();

        assert!(
            output.contains("\"$schema\": \"rusty.manifold.authority.lease_release_review.v1\"")
        );
        assert_eq!(expected.trim_end(), output.trim_end());
    }

    #[test]
    fn lease_release_authority_application_command_matches_fixture() {
        let output = run(vec![
            "apply-lease-release-review".to_string(),
            "--snapshot".to_string(),
            "fixtures/authority/synthetic-lease-active-authority-snapshot.json".to_string(),
            "--review".to_string(),
            "fixtures/lease-release-review/synthetic-lease-release-accepted-review.json"
                .to_string(),
        ])
        .unwrap();
        let expected = read_text(&default_repo_root().join(
            "fixtures/authority-application/synthetic-lease-release-accepted-application.json",
        ))
        .unwrap();

        assert!(output
            .contains("\"$schema\": \"rusty.manifold.authority.lease_release_application.v1\""));
        assert_eq!(expected.trim_end(), output.trim_end());
    }

    #[test]
    fn lease_renewal_authority_review_command_matches_fixture() {
        let output = run(vec![
            "review-lease-renewal".to_string(),
            "--snapshot".to_string(),
            "fixtures/authority/synthetic-lease-active-authority-snapshot.json".to_string(),
            "--request".to_string(),
            "fixtures/command/synthetic-lease-renewal-request.json".to_string(),
            "--clock".to_string(),
            "fixtures/clock/synthetic-command-review-clock.json".to_string(),
        ])
        .unwrap();
        let expected = read_text(
            &default_repo_root()
                .join("fixtures/lease-renewal-review/synthetic-lease-renewal-accepted-review.json"),
        )
        .unwrap();

        assert!(
            output.contains("\"$schema\": \"rusty.manifold.authority.lease_renewal_review.v1\"")
        );
        assert_eq!(expected.trim_end(), output.trim_end());
    }

    #[test]
    fn lease_renewal_authority_application_command_matches_fixture() {
        let output = run(vec![
            "apply-lease-renewal-review".to_string(),
            "--snapshot".to_string(),
            "fixtures/authority/synthetic-lease-active-authority-snapshot.json".to_string(),
            "--review".to_string(),
            "fixtures/lease-renewal-review/synthetic-lease-renewal-accepted-review.json"
                .to_string(),
        ])
        .unwrap();
        let expected = read_text(&default_repo_root().join(
            "fixtures/authority-application/synthetic-lease-renewal-accepted-application.json",
        ))
        .unwrap();

        assert!(output
            .contains("\"$schema\": \"rusty.manifold.authority.lease_renewal_application.v1\""));
        assert_eq!(expected.trim_end(), output.trim_end());
    }

    #[test]
    fn stream_registry_authority_review_command_matches_fixture() {
        let output = run(vec![
            "review-stream-registry".to_string(),
            "--snapshot".to_string(),
            "fixtures/authority/synthetic-authority-snapshot.json".to_string(),
            "--request".to_string(),
            "fixtures/stream/synthetic-stream-registry-change-request.json".to_string(),
            "--clock".to_string(),
            "fixtures/clock/synthetic-command-review-clock.json".to_string(),
        ])
        .unwrap();
        let expected = read_text(&default_repo_root().join(
            "fixtures/stream-registry-review/synthetic-stream-registry-accepted-review.json",
        ))
        .unwrap();

        assert!(
            output.contains("\"$schema\": \"rusty.manifold.authority.stream_registry_review.v1\"")
        );
        assert_eq!(expected.trim_end(), output.trim_end());
    }

    #[test]
    fn stream_registry_authority_application_command_matches_fixture() {
        let output = run(vec![
            "apply-stream-registry-review".to_string(),
            "--snapshot".to_string(),
            "fixtures/authority/synthetic-authority-snapshot.json".to_string(),
            "--review".to_string(),
            "fixtures/stream-registry-review/synthetic-stream-registry-accepted-review.json"
                .to_string(),
        ])
        .unwrap();
        let expected = read_text(&default_repo_root().join(
            "fixtures/authority-application/synthetic-stream-registry-accepted-application.json",
        ))
        .unwrap();

        assert!(output
            .contains("\"$schema\": \"rusty.manifold.authority.stream_registry_application.v1\""));
        assert_eq!(expected.trim_end(), output.trim_end());
    }

    #[test]
    fn stream_subscription_authority_review_command_matches_fixture() {
        let output = run(vec![
            "review-stream-subscription".to_string(),
            "--snapshot".to_string(),
            "fixtures/authority/synthetic-stream-subscription-authority-snapshot.json".to_string(),
            "--request".to_string(),
            "fixtures/stream-subscription/synthetic-stream-subscription-request.json".to_string(),
            "--clock".to_string(),
            "fixtures/clock/synthetic-command-review-clock.json".to_string(),
        ])
        .unwrap();
        let expected = read_text(&default_repo_root().join(
            "fixtures/stream-subscription-review/synthetic-stream-subscription-accepted-review.json",
        ))
        .unwrap();

        assert!(output
            .contains("\"$schema\": \"rusty.manifold.authority.stream_subscription_review.v1\""));
        assert_eq!(expected.trim_end(), output.trim_end());
    }

    #[test]
    fn stream_subscription_authority_application_command_matches_fixture() {
        let output = run(vec![
            "apply-stream-subscription-review".to_string(),
            "--snapshot".to_string(),
            "fixtures/authority/synthetic-stream-subscription-authority-snapshot.json".to_string(),
            "--review".to_string(),
            "fixtures/stream-subscription-review/synthetic-stream-subscription-accepted-review.json"
                .to_string(),
        ])
        .unwrap();
        let expected = read_text(&default_repo_root().join(
            "fixtures/authority-application/synthetic-stream-subscription-accepted-application.json",
        ))
        .unwrap();

        assert!(output.contains(
            "\"$schema\": \"rusty.manifold.authority.stream_subscription_application.v1\""
        ));
        assert_eq!(expected.trim_end(), output.trim_end());
    }

    #[test]
    fn stream_subscription_release_authority_review_command_matches_fixture() {
        let output = run(vec![
            "review-stream-subscription-release".to_string(),
            "--snapshot".to_string(),
            "fixtures/authority/synthetic-stream-subscription-active-authority-snapshot.json"
                .to_string(),
            "--request".to_string(),
            "fixtures/stream-subscription/synthetic-stream-subscription-release-request.json"
                .to_string(),
            "--clock".to_string(),
            "fixtures/clock/synthetic-command-review-clock.json".to_string(),
        ])
        .unwrap();
        let expected = read_text(&default_repo_root().join(
            "fixtures/stream-subscription-release-review/synthetic-stream-subscription-release-accepted-review.json",
        ))
        .unwrap();

        assert!(output.contains(
            "\"$schema\": \"rusty.manifold.authority.stream_subscription_release_review.v1\""
        ));
        assert_eq!(expected.trim_end(), output.trim_end());
    }

    #[test]
    fn stream_subscription_release_authority_application_command_matches_fixture() {
        let output = run(vec![
            "apply-stream-subscription-release-review".to_string(),
            "--snapshot".to_string(),
            "fixtures/authority/synthetic-stream-subscription-active-authority-snapshot.json"
                .to_string(),
            "--review".to_string(),
            "fixtures/stream-subscription-release-review/synthetic-stream-subscription-release-accepted-review.json"
                .to_string(),
        ])
        .unwrap();
        let expected = read_text(&default_repo_root().join(
            "fixtures/authority-application/synthetic-stream-subscription-release-accepted-application.json",
        ))
        .unwrap();

        assert!(output.contains(
            "\"$schema\": \"rusty.manifold.authority.stream_subscription_release_application.v1\""
        ));
        assert_eq!(expected.trim_end(), output.trim_end());
    }

    #[test]
    fn stream_subscription_renewal_authority_review_command_matches_fixture() {
        let output = run(vec![
            "review-stream-subscription-renewal".to_string(),
            "--snapshot".to_string(),
            "fixtures/authority/synthetic-stream-subscription-active-authority-snapshot.json"
                .to_string(),
            "--request".to_string(),
            "fixtures/stream-subscription/synthetic-stream-subscription-renewal-request.json"
                .to_string(),
            "--clock".to_string(),
            "fixtures/clock/synthetic-command-review-clock.json".to_string(),
        ])
        .unwrap();
        let expected = read_text(&default_repo_root().join(
            "fixtures/stream-subscription-renewal-review/synthetic-stream-subscription-renewal-accepted-review.json",
        ))
        .unwrap();

        assert!(output.contains(
            "\"$schema\": \"rusty.manifold.authority.stream_subscription_renewal_review.v1\""
        ));
        assert_eq!(expected.trim_end(), output.trim_end());
    }

    #[test]
    fn stream_subscription_renewal_authority_application_command_matches_fixture() {
        let output = run(vec![
            "apply-stream-subscription-renewal-review".to_string(),
            "--snapshot".to_string(),
            "fixtures/authority/synthetic-stream-subscription-active-authority-snapshot.json"
                .to_string(),
            "--review".to_string(),
            "fixtures/stream-subscription-renewal-review/synthetic-stream-subscription-renewal-accepted-review.json"
                .to_string(),
        ])
        .unwrap();
        let expected = read_text(&default_repo_root().join(
            "fixtures/authority-application/synthetic-stream-subscription-renewal-accepted-application.json",
        ))
        .unwrap();

        assert!(output.contains(
            "\"$schema\": \"rusty.manifold.authority.stream_subscription_renewal_application.v1\""
        ));
        assert_eq!(expected.trim_end(), output.trim_end());
    }

    #[test]
    fn authority_expiry_sweep_authority_review_command_matches_fixture() {
        let output = run(vec![
            "review-authority-expiry-sweep".to_string(),
            "--snapshot".to_string(),
            "fixtures/authority/synthetic-stream-subscription-active-authority-snapshot.json"
                .to_string(),
            "--request".to_string(),
            "fixtures/authority-expiry/synthetic-authority-expiry-sweep-request.json".to_string(),
            "--clock".to_string(),
            "fixtures/clock/synthetic-expired-command-review-clock.json".to_string(),
        ])
        .unwrap();
        let expected = read_text(&default_repo_root().join(
            "fixtures/authority-expiry-review/synthetic-authority-expiry-sweep-accepted-review.json",
        ))
        .unwrap();

        assert!(output.contains("\"$schema\": \"rusty.manifold.authority.expiry_sweep_review.v1\""));
        assert_eq!(expected.trim_end(), output.trim_end());
    }

    #[test]
    fn authority_expiry_sweep_authority_application_command_matches_fixture() {
        let output = run(vec![
            "apply-authority-expiry-sweep-review".to_string(),
            "--snapshot".to_string(),
            "fixtures/authority/synthetic-stream-subscription-active-authority-snapshot.json"
                .to_string(),
            "--review".to_string(),
            "fixtures/authority-expiry-review/synthetic-authority-expiry-sweep-accepted-review.json"
                .to_string(),
        ])
        .unwrap();
        let expected = read_text(&default_repo_root().join(
            "fixtures/authority-application/synthetic-authority-expiry-sweep-accepted-application.json",
        ))
        .unwrap();

        assert!(output
            .contains("\"$schema\": \"rusty.manifold.authority.expiry_sweep_application.v1\""));
        assert_eq!(expected.trim_end(), output.trim_end());
    }

    #[test]
    fn module_runtime_state_authority_review_command_matches_fixture() {
        let output = run(vec![
            "review-module-runtime".to_string(),
            "--snapshot".to_string(),
            "fixtures/authority/synthetic-authority-snapshot.json".to_string(),
            "--request".to_string(),
            "fixtures/module/synthetic-runtime-state-change-request.json".to_string(),
            "--clock".to_string(),
            "fixtures/clock/synthetic-command-review-clock.json".to_string(),
        ])
        .unwrap();
        let expected =
            read_text(&default_repo_root().join(
                "fixtures/module-runtime-review/synthetic-module-runtime-accepted-review.json",
            ))
            .unwrap();

        assert!(output
            .contains("\"$schema\": \"rusty.manifold.authority.module_runtime_state_review.v1\""));
        assert_eq!(expected.trim_end(), output.trim_end());
    }

    #[test]
    fn module_runtime_state_authority_application_command_matches_fixture() {
        let output = run(vec![
            "apply-module-runtime-review".to_string(),
            "--snapshot".to_string(),
            "fixtures/authority/synthetic-authority-snapshot.json".to_string(),
            "--review".to_string(),
            "fixtures/module-runtime-review/synthetic-module-runtime-accepted-review.json"
                .to_string(),
        ])
        .unwrap();
        let expected = read_text(&default_repo_root().join(
            "fixtures/authority-application/synthetic-module-runtime-accepted-application.json",
        ))
        .unwrap();

        assert!(output.contains(
            "\"$schema\": \"rusty.manifold.authority.module_runtime_state_application.v1\""
        ));
        assert_eq!(expected.trim_end(), output.trim_end());
    }

    #[test]
    fn host_manifest_authority_review_command_matches_fixture() {
        let output = run(vec![
            "review-host-manifest".to_string(),
            "--snapshot".to_string(),
            "fixtures/authority/synthetic-authority-snapshot.json".to_string(),
            "--request".to_string(),
            "fixtures/host/synthetic-host-manifest-change-request.json".to_string(),
            "--clock".to_string(),
            "fixtures/clock/synthetic-command-review-clock.json".to_string(),
        ])
        .unwrap();
        let expected = read_text(
            &default_repo_root()
                .join("fixtures/host-manifest-review/synthetic-host-manifest-accepted-review.json"),
        )
        .unwrap();

        assert!(
            output.contains("\"$schema\": \"rusty.manifold.authority.host_manifest_review.v1\"")
        );
        assert_eq!(expected.trim_end(), output.trim_end());
    }

    #[test]
    fn host_manifest_authority_application_command_matches_fixture() {
        let output = run(vec![
            "apply-host-manifest-review".to_string(),
            "--snapshot".to_string(),
            "fixtures/authority/synthetic-authority-snapshot.json".to_string(),
            "--review".to_string(),
            "fixtures/host-manifest-review/synthetic-host-manifest-accepted-review.json"
                .to_string(),
        ])
        .unwrap();
        let expected = read_text(&default_repo_root().join(
            "fixtures/authority-application/synthetic-host-manifest-accepted-application.json",
        ))
        .unwrap();

        assert!(output
            .contains("\"$schema\": \"rusty.manifold.authority.host_manifest_application.v1\""));
        assert_eq!(expected.trim_end(), output.trim_end());
    }

    #[test]
    fn clock_authority_review_command_matches_fixture() {
        let output = run(vec![
            "review-clock".to_string(),
            "--snapshot".to_string(),
            "fixtures/authority/synthetic-authority-snapshot.json".to_string(),
            "--request".to_string(),
            "fixtures/clock/synthetic-clock-change-request.json".to_string(),
            "--clock".to_string(),
            "fixtures/clock/synthetic-command-review-clock.json".to_string(),
        ])
        .unwrap();
        let expected = read_text(
            &default_repo_root().join("fixtures/clock-review/synthetic-clock-accepted-review.json"),
        )
        .unwrap();

        assert!(
            output.contains("\"$schema\": \"rusty.manifold.authority.clock_snapshot_review.v1\"")
        );
        assert_eq!(expected.trim_end(), output.trim_end());
    }

    #[test]
    fn clock_authority_application_command_matches_fixture() {
        let output = run(vec![
            "apply-clock-review".to_string(),
            "--snapshot".to_string(),
            "fixtures/authority/synthetic-authority-snapshot.json".to_string(),
            "--review".to_string(),
            "fixtures/clock-review/synthetic-clock-accepted-review.json".to_string(),
        ])
        .unwrap();
        let expected = read_text(
            &default_repo_root()
                .join("fixtures/authority-application/synthetic-clock-accepted-application.json"),
        )
        .unwrap();

        assert!(output
            .contains("\"$schema\": \"rusty.manifold.authority.clock_snapshot_application.v1\""));
        assert_eq!(expected.trim_end(), output.trim_end());
    }
}
