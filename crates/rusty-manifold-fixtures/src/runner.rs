use std::path::PathBuf;
use std::time::Duration;

use super::authority_commands::*;
use super::cli::{Command, Options};
use super::{
    default_repo_root, diff_synthetic_contracts, emit_synthetic_scalar_samples,
    publish_synthetic_scalar_profile, read_text, resolve_input_path, simulate_coordination_session,
    simulate_synthetic_topology, to_json_lines, to_pretty_json, validate_repo, write_text,
    CliError, SyntheticScalarPublishConfig,
};

pub(super) fn run(args: Vec<String>) -> Result<String, CliError> {
    if args.first().map(String::as_str) == Some("simulate-coordination") {
        return run_simulate_coordination(args.into_iter().skip(1).collect());
    }
    if args.first().map(String::as_str) == Some("emit-synthetic-scalar") {
        return run_emit_synthetic_scalar(args.into_iter().skip(1).collect());
    }
    if args.first().map(String::as_str) == Some("publish-synthetic-scalar") {
        return run_publish_synthetic_scalar(args.into_iter().skip(1).collect());
    }

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

fn run_simulate_coordination(args: Vec<String>) -> Result<String, CliError> {
    let options = CoordinationSimulationOptions::parse(args)?;
    let plan_path = options.plan.ok_or_else(|| {
        CliError::Usage("simulate-coordination requires --plan <path>".to_owned())
    })?;
    let messages_path = options.messages.ok_or_else(|| {
        CliError::Usage("simulate-coordination requires --messages <path>".to_owned())
    })?;
    let scorecard = simulate_coordination_session(&options.repo_root, &plan_path, &messages_path)?;
    let serialized = to_pretty_json(&scorecard)?;

    if let Some(output_path) = options.output {
        write_text(&output_path, &serialized)?;
    }

    if options.check {
        let expected_path = options.expected.ok_or_else(|| {
            CliError::Usage("simulate-coordination --check requires --expected <path>".to_owned())
        })?;
        let resolved_expected = resolve_input_path(&options.repo_root, &expected_path);
        let expected = read_text(&resolved_expected)?;
        if expected.trim_end() == serialized.trim_end() {
            Ok("coordination scorecard matches fixture".to_owned())
        } else {
            Err(CliError::SnapshotMismatch {
                expected_path: resolved_expected,
                output: serialized,
            })
        }
    } else {
        Ok(serialized)
    }
}

fn run_emit_synthetic_scalar(args: Vec<String>) -> Result<String, CliError> {
    let options = SyntheticScalarOptions::parse(args)?;
    let samples = emit_synthetic_scalar_samples(&options.repo_root, &options.profile)?;
    let serialized = to_json_lines(&samples)?;

    if let Some(output_path) = options.output {
        write_text(&output_path, &serialized)?;
    }

    if options.check {
        let expected_path = options.expected.ok_or_else(|| {
            CliError::Usage("emit-synthetic-scalar --check requires --expected <path>".to_owned())
        })?;
        let resolved_expected = resolve_input_path(&options.repo_root, &expected_path);
        let expected = read_text(&resolved_expected)?;
        if expected.trim_end() == serialized.trim_end() {
            Ok("synthetic scalar samples match fixture".to_owned())
        } else {
            Err(CliError::SnapshotMismatch {
                expected_path: resolved_expected,
                output: serialized,
            })
        }
    } else {
        Ok(serialized)
    }
}

fn run_publish_synthetic_scalar(args: Vec<String>) -> Result<String, CliError> {
    let options = SyntheticScalarPublishOptions::parse(args)?;
    let sample_count = options.sample_count.unwrap_or_else(|| {
        options
            .repeat
            .saturating_mul(options.profile_sample_count_hint.unwrap_or(5))
    });
    let config = SyntheticScalarPublishConfig {
        broker_host: options.broker_host,
        broker_port: options.broker_port,
        broker_path: options.broker_path,
        sample_interval: options.sample_interval,
    };
    let report = publish_synthetic_scalar_profile(
        &options.repo_root,
        &options.profile,
        sample_count.max(1),
        &config,
    )?;
    to_pretty_json(&report)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CoordinationSimulationOptions {
    repo_root: PathBuf,
    plan: Option<PathBuf>,
    messages: Option<PathBuf>,
    expected: Option<PathBuf>,
    output: Option<PathBuf>,
    check: bool,
}

impl CoordinationSimulationOptions {
    fn parse(args: Vec<String>) -> Result<Self, CliError> {
        let mut args = args.into_iter();
        let mut options = Self {
            repo_root: default_repo_root(),
            plan: None,
            messages: None,
            expected: None,
            output: None,
            check: false,
        };

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--repo-root" => {
                    options.repo_root = PathBuf::from(next_value(&mut args, "--repo-root")?);
                }
                "--plan" => {
                    options.plan = Some(PathBuf::from(next_value(&mut args, "--plan")?));
                }
                "--messages" => {
                    options.messages = Some(PathBuf::from(next_value(&mut args, "--messages")?));
                }
                "--expected" => {
                    options.expected = Some(PathBuf::from(next_value(&mut args, "--expected")?));
                }
                "--output" => {
                    options.output = Some(PathBuf::from(next_value(&mut args, "--output")?));
                }
                "--check" => {
                    options.check = true;
                }
                "-h" | "--help" => return Err(CliError::Usage(coordination_usage())),
                other => return Err(CliError::UnknownOption(other.to_owned())),
            }
        }

        Ok(options)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SyntheticScalarOptions {
    repo_root: PathBuf,
    profile: PathBuf,
    expected: Option<PathBuf>,
    output: Option<PathBuf>,
    check: bool,
}

#[derive(Clone, Debug, PartialEq)]
struct SyntheticScalarPublishOptions {
    repo_root: PathBuf,
    profile: PathBuf,
    broker_host: String,
    broker_port: u16,
    broker_path: String,
    sample_count: Option<u32>,
    profile_sample_count_hint: Option<u32>,
    repeat: u32,
    sample_interval: Option<Duration>,
}

impl SyntheticScalarPublishOptions {
    fn parse(args: Vec<String>) -> Result<Self, CliError> {
        let mut args = args.into_iter();
        let mut options = Self {
            repo_root: default_repo_root(),
            profile: PathBuf::from("fixtures/synthetic/synthetic-scalar-oscillator-profile.json"),
            broker_host: "127.0.0.1".to_owned(),
            broker_port: 8765,
            broker_path: "/manifold/v1/events".to_owned(),
            sample_count: None,
            profile_sample_count_hint: Some(5),
            repeat: 1,
            sample_interval: None,
        };
        let mut explicit_interval = false;
        let mut no_sleep = false;

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--repo-root" => {
                    options.repo_root = PathBuf::from(next_value(&mut args, "--repo-root")?);
                }
                "--profile" => {
                    options.profile = PathBuf::from(next_value(&mut args, "--profile")?);
                }
                "--broker-host" | "--host" => {
                    options.broker_host = next_value(&mut args, "--broker-host")?;
                }
                "--broker-port" | "--port" => {
                    let value = next_value(&mut args, "--broker-port")?;
                    options.broker_port = value.parse::<u16>().map_err(|_| {
                        CliError::Usage(format!("--broker-port must be 1..65535, got {value}"))
                    })?;
                }
                "--broker-path" | "--path" => {
                    options.broker_path = next_value(&mut args, "--broker-path")?;
                }
                "--sample-count" => {
                    let value = next_value(&mut args, "--sample-count")?;
                    options.sample_count = Some(parse_positive_u32("--sample-count", &value)?);
                }
                "--repeat" => {
                    let value = next_value(&mut args, "--repeat")?;
                    options.repeat = parse_positive_u32("--repeat", &value)?;
                }
                "--interval-ms" => {
                    let value = next_value(&mut args, "--interval-ms")?;
                    let interval_ms = parse_nonnegative_u64("--interval-ms", &value)?;
                    options.sample_interval = Some(Duration::from_millis(interval_ms));
                    explicit_interval = true;
                }
                "--no-sleep" => {
                    options.sample_interval = Some(Duration::ZERO);
                    no_sleep = true;
                }
                "-h" | "--help" => {
                    return Err(CliError::Usage(synthetic_scalar_publish_usage()));
                }
                other => return Err(CliError::UnknownOption(other.to_owned())),
            }
        }

        let profile = super::read_model::<super::ManifoldSyntheticScalarOscillatorProfile>(
            super::resolve_input_path(&options.repo_root, &options.profile),
        )?;
        profile.validate().map_err(CliError::from)?;
        options.profile_sample_count_hint = Some(profile.sample_count);
        if !explicit_interval && !no_sleep {
            let interval_ms = (1000.0_f32 / profile.sample_rate_hz).round().max(1.0) as u64;
            options.sample_interval = Some(Duration::from_millis(interval_ms));
        }

        Ok(options)
    }
}

impl SyntheticScalarOptions {
    fn parse(args: Vec<String>) -> Result<Self, CliError> {
        let mut args = args.into_iter();
        let mut options = Self {
            repo_root: default_repo_root(),
            profile: PathBuf::from("fixtures/synthetic/synthetic-scalar-oscillator-profile.json"),
            expected: None,
            output: None,
            check: false,
        };

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--repo-root" => {
                    options.repo_root = PathBuf::from(next_value(&mut args, "--repo-root")?);
                }
                "--profile" => {
                    options.profile = PathBuf::from(next_value(&mut args, "--profile")?);
                }
                "--expected" => {
                    options.expected = Some(PathBuf::from(next_value(&mut args, "--expected")?));
                }
                "--output" => {
                    options.output = Some(PathBuf::from(next_value(&mut args, "--output")?));
                }
                "--check" => {
                    options.check = true;
                }
                "-h" | "--help" => return Err(CliError::Usage(synthetic_scalar_usage())),
                other => return Err(CliError::UnknownOption(other.to_owned())),
            }
        }

        Ok(options)
    }
}

fn next_value(args: &mut impl Iterator<Item = String>, option: &str) -> Result<String, CliError> {
    args.next()
        .ok_or_else(|| CliError::Usage(format!("{option} requires a value")))
}

fn parse_positive_u32(option: &str, value: &str) -> Result<u32, CliError> {
    value
        .parse::<u32>()
        .ok()
        .filter(|parsed| *parsed > 0)
        .ok_or_else(|| CliError::Usage(format!("{option} must be a positive integer, got {value}")))
}

fn parse_nonnegative_u64(option: &str, value: &str) -> Result<u64, CliError> {
    value.parse::<u64>().map_err(|_| {
        CliError::Usage(format!(
            "{option} must be a non-negative integer number of milliseconds, got {value}"
        ))
    })
}

fn coordination_usage() -> String {
    "usage: rusty-manifold-fixtures simulate-coordination --plan <path> --messages <path> [--repo-root <path>] [--check --expected <path>] [--output <path>]"
        .to_owned()
}

fn synthetic_scalar_usage() -> String {
    "usage: rusty-manifold-fixtures emit-synthetic-scalar [--profile <path>] [--repo-root <path>] [--check --expected <path>] [--output <path>]"
        .to_owned()
}

fn synthetic_scalar_publish_usage() -> String {
    "usage: rusty-manifold-fixtures publish-synthetic-scalar [--profile <path>] [--repo-root <path>] [--broker-host <host>] [--broker-port <port>] [--broker-path <path>] [--sample-count <n>|--repeat <n>] [--interval-ms <ms>|--no-sleep]"
        .to_owned()
}
