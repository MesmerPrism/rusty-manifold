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
    entries.extend(host_and_deployment_entries());
    entries.extend(verification_entries());
    entries
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
            &["fixtures/diff/synthetic-contract-diff.json"],
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
            &["fixtures/diff/synthetic-contract-diff.json"],
        ),
    ]
}

fn command_entries() -> Vec<SchemaEntry> {
    vec![
        entry(
            "rusty.manifold.command.descriptor.v1",
            "ManifoldCommandDescriptor",
            &["fixtures/command/synthetic-command-descriptor.json"],
        ),
        entry(
            "rusty.manifold.command.envelope.v1",
            "ManifoldCommandEnvelope",
            &["fixtures/command/synthetic-command-envelope.json"],
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
            &["fixtures/command/synthetic-lease-request.json"],
        ),
        entry(
            "rusty.manifold.command.control_lease.v1",
            "ManifoldControlLease",
            &["fixtures/command/synthetic-control-lease.json"],
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
            &["fixtures/clock/synthetic-clock-snapshot.json"],
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
            "rusty.manifold.hostess.install_launch_profile.v1",
            "ManifoldHostessInstallLaunchProfile",
            &[
                "fixtures/hostess/install-profile-desktop.json",
                "fixtures/hostess/install-profile-mobile.json",
                "fixtures/hostess/install-profile-headset.json",
            ],
        ),
        entry(
            "rusty.manifold.hostess.validation_slot.v1",
            "ManifoldHostessValidationSlot",
            &["fixtures/hostess/slot-live-smoke.json"],
        ),
        entry(
            "rusty.manifold.hostess.run_bundle.v1",
            "ManifoldHostessRunBundle",
            &["fixtures/hostess/run-bundle-live-smoke.json"],
        ),
        entry(
            "rusty.manifold.hostess.command_envelope.v1",
            "ManifoldHostessCommandEnvelope",
            &["fixtures/hostess/command-envelope-run-live.json"],
        ),
        entry(
            "rusty.manifold.hostess.run_evidence.v1",
            "ManifoldHostessRunEvidence",
            &["fixtures/hostess/run-evidence-live-smoke.json"],
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
