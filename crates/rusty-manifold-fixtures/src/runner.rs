use std::path::PathBuf;

use super::authority_commands::*;
use super::cli::{Command, Options};
use super::{
    default_repo_root, diff_synthetic_contracts, read_text, resolve_input_path,
    simulate_coordination_session, simulate_synthetic_topology, to_pretty_json, validate_repo,
    write_text, CliError,
};

pub(super) fn run(args: Vec<String>) -> Result<String, CliError> {
    if args.first().map(String::as_str) == Some("simulate-coordination") {
        return run_simulate_coordination(args.into_iter().skip(1).collect());
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

fn next_value(args: &mut impl Iterator<Item = String>, option: &str) -> Result<String, CliError> {
    args.next()
        .ok_or_else(|| CliError::Usage(format!("{option} requires a value")))
}

fn coordination_usage() -> String {
    "usage: rusty-manifold-fixtures simulate-coordination --plan <path> --messages <path> [--repo-root <path>] [--check --expected <path>] [--output <path>]"
        .to_owned()
}
