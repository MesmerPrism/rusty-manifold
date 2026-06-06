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

mod authority_commands;
mod cli;
mod fixture_set;
mod runner;
mod validation_checks;

use self::authority_commands::*;
use self::fixture_set::FixtureSet;
use self::runner::run;
use self::validation_checks::*;

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

fn resolve_input_path(repo_root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        repo_root.join(path)
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
#[path = "main_tests.rs"]
mod tests;
