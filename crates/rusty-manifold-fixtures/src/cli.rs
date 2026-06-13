use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Options {
    pub(super) command: Command,
    pub(super) repo_root: PathBuf,
}

impl Options {
    pub(super) fn parse(args: Vec<String>) -> Result<Self, CliError> {
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
pub(super) enum Command {
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

fn usage() -> String {
    "usage: rusty-manifold-fixtures <validate|simulate|diff|simulate-coordination|review-shell-handoff|review-command|prepare-command-dispatch|review-lease|apply-lease-review|review-lease-release|apply-lease-release-review|review-lease-renewal|apply-lease-renewal-review|review-stream-registry|apply-stream-registry-review|review-stream-subscription|apply-stream-subscription-review|review-stream-subscription-release|apply-stream-subscription-release-review|review-stream-subscription-renewal|apply-stream-subscription-renewal-review|review-authority-expiry-sweep|apply-authority-expiry-sweep-review|review-module-runtime|apply-module-runtime-review|review-host-manifest|apply-host-manifest-review|review-clock|apply-clock-review> [--repo-root <path>] [--check] [--handoff <path>] [--snapshot <path>] [--envelope <path>] [--request <path>] [--review <path>] [--clock <path>] [--plan <path>] [--messages <path>] [--expected <path>] [--output <path>]"
        .to_owned()
}
