//! Fixture validation and source-only simulation CLI.

use std::env;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use rusty_manifold_model::{
    DottedId, ManifoldClockSnapshot, ManifoldCommandAck, ManifoldCommandDescriptor,
    ManifoldCommandEnvelope, ManifoldCommandRejection, ManifoldControlLease,
    ManifoldControlLeaseRequest, ManifoldDeploymentManifest, ManifoldGraphManifest,
    ManifoldHostManifest, ManifoldModuleManifest, ManifoldModuleRuntimeState,
    ManifoldPackageManifest, ManifoldStreamManifest, ManifoldStreamRegistrySnapshot,
    ManifoldValidationScorecard, Revision,
};
use serde::de::DeserializeOwned;
use serde::Serialize;

fn main() -> ExitCode {
    match run(env::args().skip(1).collect()) {
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
                    Command::Simulate { check } => *check = true,
                    Command::Validate => {
                        return Err(CliError::Usage(
                            "--check is only valid for simulate".to_owned(),
                        ));
                    }
                },
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
    Simulate { check: bool },
}

fn validate_repo(repo_root: &Path) -> Result<ValidationReport, CliError> {
    let fixtures = FixtureSet::load(repo_root)?;
    let mut checks = Vec::new();
    let module_ids = fixtures
        .module_manifests
        .iter()
        .map(|module| module.module_id.clone())
        .collect::<Vec<_>>();

    push_valid_checks(&mut checks, &fixtures, &module_ids);
    push_damaged_checks(repo_root, &mut checks, &fixtures, &module_ids)?;

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
        "validation.check.command_accept",
        fixtures.valid_envelope.validate_request(
            &fixtures.command_descriptor,
            Revision::INITIAL,
            Some(&fixtures.control_lease),
        ),
        "command envelope matches descriptor, revision, holder, and lease",
    );
}

fn push_damaged_checks(
    repo_root: &Path,
    checks: &mut Vec<ValidationCheckReport>,
    fixtures: &FixtureSet,
    module_ids: &[DottedId],
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

    Ok(())
}

fn simulate_synthetic_topology(repo_root: &Path) -> Result<SimulatorSnapshot, CliError> {
    let fixtures = FixtureSet::load(repo_root)?;
    let module_ids = fixtures
        .module_manifests
        .iter()
        .map(|module| module.module_id.clone())
        .collect::<Vec<_>>();

    fixtures.valid_host.validate_endpoint_security()?;
    fixtures.valid_graph.validate_links(&module_ids)?;
    fixtures
        .valid_registry
        .validate_source_modules(&module_ids)?;
    fixtures.valid_envelope.validate_request(
        &fixtures.command_descriptor,
        Revision::INITIAL,
        Some(&fixtures.control_lease),
    )?;

    let stale_rejection = fixtures
        .damaged_stale_command
        .validate_request(
            &fixtures.command_descriptor,
            Revision::new(2).expect("literal is non-zero"),
            Some(&fixtures.control_lease),
        )
        .expect_err("stale command fixture must reject");

    Ok(SimulatorSnapshot {
        schema_id: "rusty.manifold.simulator.snapshot.v1".to_owned(),
        simulation_id: "simulation.synthetic_wave_pipeline".to_owned(),
        host_id: fixtures.valid_host.host_id.to_string(),
        package_id: fixtures.package_manifest.package_id.to_string(),
        graph_id: fixtures.valid_graph.graph_id.to_string(),
        graph_revision: fixtures.valid_graph.graph_revision.get(),
        module_states: fixtures
            .module_runtime_states
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
        stream_registry_revision: fixtures.valid_registry.registry_revision.get(),
        streams: fixtures
            .valid_registry
            .streams
            .iter()
            .map(|stream| stream.stream_id.to_string())
            .collect(),
        accepted_commands: vec![CommandAcceptanceSummary {
            request_id: fixtures.valid_ack.request_id.to_string(),
            command_id: fixtures.valid_envelope.command_id.to_string(),
            accepted_revision: fixtures.valid_ack.accepted_revision.get(),
        }],
        rejected_commands: vec![CommandRejectionSummary {
            request_id: fixtures.damaged_stale_command.request_id.to_string(),
            command_id: fixtures.damaged_stale_command.command_id.to_string(),
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

#[derive(Debug)]
struct FixtureSet {
    package_manifest: ManifoldPackageManifest,
    valid_graph: ManifoldGraphManifest,
    module_manifests: Vec<ManifoldModuleManifest>,
    module_runtime_states: Vec<ManifoldModuleRuntimeState>,
    valid_registry: ManifoldStreamRegistrySnapshot,
    command_descriptor: ManifoldCommandDescriptor,
    valid_envelope: ManifoldCommandEnvelope,
    valid_ack: ManifoldCommandAck,
    control_lease: ManifoldControlLease,
    valid_host: ManifoldHostManifest,
    damaged_endpoint_host: ManifoldHostManifest,
    damaged_stale_command: ManifoldCommandEnvelope,
    damaged_missing_lease_command: ManifoldCommandEnvelope,
    damaged_unknown_stream_module: ManifoldStreamRegistrySnapshot,
    damaged_unknown_graph_module: ManifoldGraphManifest,
    damaged_unknown_graph_node: ManifoldGraphManifest,
    platform_hosts: Vec<ManifoldHostManifest>,
}

impl FixtureSet {
    fn load(repo_root: &Path) -> Result<Self, CliError> {
        let package_manifest =
            read_model(repo_root.join("fixtures/package/synthetic-package.json"))?;
        let valid_graph =
            read_model(repo_root.join("fixtures/graph/synthetic-wave-pipeline.json"))?;
        let provider_manifest =
            read_model(repo_root.join("fixtures/module/synthetic-wave-provider.json"))?;
        let processor_manifest =
            read_model(repo_root.join("fixtures/module/synthetic-wave-processor.json"))?;
        let provider_runtime =
            read_model(repo_root.join("fixtures/module/synthetic-wave-runtime-state.json"))?;
        let processor_runtime =
            read_model(repo_root.join("fixtures/module/synthetic-processor-runtime-state.json"))?;

        read_model::<ManifoldStreamManifest>(
            repo_root.join("fixtures/stream/synthetic-wave-stream.json"),
        )?;
        read_model::<ManifoldStreamManifest>(
            repo_root.join("fixtures/stream/synthetic-rms-stream.json"),
        )?;

        let valid_registry =
            read_model(repo_root.join("fixtures/stream/synthetic-stream-registry.json"))?;
        let command_descriptor =
            read_model(repo_root.join("fixtures/command/synthetic-command-descriptor.json"))?;
        let valid_envelope =
            read_model(repo_root.join("fixtures/command/synthetic-command-envelope.json"))?;
        let valid_ack = read_model(repo_root.join("fixtures/command/synthetic-command-ack.json"))?;
        read_model::<ManifoldCommandRejection>(
            repo_root.join("fixtures/command/synthetic-command-rejection.json"),
        )?;
        read_model::<ManifoldControlLeaseRequest>(
            repo_root.join("fixtures/command/synthetic-lease-request.json"),
        )?;
        let control_lease =
            read_model(repo_root.join("fixtures/command/synthetic-control-lease.json"))?;
        let valid_host = read_model(repo_root.join("fixtures/host/synthetic-host.json"))?;
        let desktop_host = read_model(repo_root.join("fixtures/host/desktop-local.json"))?;
        let mobile_host = read_model(repo_root.join("fixtures/host/mobile-device.json"))?;
        let headset_host = read_model(repo_root.join("fixtures/host/headset-device.json"))?;
        read_model::<ManifoldDeploymentManifest>(
            repo_root.join("fixtures/deployment/synthetic-deployment.json"),
        )?;
        read_model::<ManifoldClockSnapshot>(
            repo_root.join("fixtures/clock/synthetic-clock-snapshot.json"),
        )?;
        read_model::<ManifoldValidationScorecard>(
            repo_root.join("fixtures/validation/synthetic-scorecard.json"),
        )?;

        let damaged_endpoint_host =
            read_model(repo_root.join("fixtures/damaged/invalid-endpoint-security.json"))?;
        let damaged_stale_command =
            read_model(repo_root.join("fixtures/damaged/stale-revision-command.json"))?;
        let damaged_missing_lease_command =
            read_model(repo_root.join("fixtures/damaged/missing-lease-scope-command.json"))?;
        let damaged_unknown_stream_module =
            read_model(repo_root.join("fixtures/damaged/unknown-module-link.json"))?;
        let damaged_unknown_graph_module =
            read_model(repo_root.join("fixtures/damaged/unknown-graph-module-link.json"))?;
        let damaged_unknown_graph_node =
            read_model(repo_root.join("fixtures/damaged/unknown-graph-node-link.json"))?;

        Ok(Self {
            package_manifest,
            valid_graph,
            module_manifests: vec![provider_manifest, processor_manifest],
            module_runtime_states: vec![provider_runtime, processor_runtime],
            valid_registry,
            command_descriptor,
            valid_envelope,
            valid_ack,
            control_lease,
            valid_host,
            damaged_endpoint_host,
            damaged_stale_command,
            damaged_missing_lease_command,
            damaged_unknown_stream_module,
            damaged_unknown_graph_module,
            damaged_unknown_graph_node,
            platform_hosts: vec![desktop_host, mobile_host, headset_host],
        })
    }
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
    "usage: rusty-manifold-fixtures <validate|simulate> [--repo-root <path>] [--check]".to_owned()
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
    GraphValidation(rusty_manifold_model::GraphValidationError),
    StreamRegistryValidation(rusty_manifold_model::StreamRegistryValidationError),
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
            Self::GraphValidation(source) => write!(formatter, "{source}"),
            Self::StreamRegistryValidation(source) => write!(formatter, "{source}"),
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
}
