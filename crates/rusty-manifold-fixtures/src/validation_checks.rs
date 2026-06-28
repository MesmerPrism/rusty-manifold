use super::*;

mod clock;
mod command;
mod coordination;
mod expiry;
mod host_manifest;
mod leases;
mod module_runtime;
mod streams;
mod synthetic;

use self::clock::push_clock_checks;
use self::command::{push_command_checks, push_damaged_command_checks};
use self::coordination::push_coordination_checks;
use self::expiry::push_expiry_checks;
use self::host_manifest::push_host_manifest_checks;
use self::leases::push_lease_checks;
use self::module_runtime::push_module_runtime_checks;
use self::streams::{push_damaged_stream_checks, push_stream_checks};
use self::synthetic::push_synthetic_checks;

pub(super) fn validate_repo(repo_root: &Path) -> Result<ValidationReport, CliError> {
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
    push_coordination_checks(repo_root, &mut checks)?;
    push_synthetic_checks(repo_root, &mut checks)?;

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

    push_command_checks(checks, fixtures);

    push_lease_checks(checks, fixtures);

    push_stream_checks(checks, fixtures);

    push_expiry_checks(checks, fixtures);

    push_module_runtime_checks(checks, fixtures);

    push_host_manifest_checks(checks, fixtures);

    push_clock_checks(checks, fixtures);

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

    let bridge_route_result = fixtures
        .bridge_route_descriptors
        .iter()
        .try_for_each(ManifoldBridgeRouteDescriptor::validate_shape)
        .map_err(|error| error.to_string())
        .and_then(|()| {
            let Some(route) = fixtures
                .bridge_route_descriptors
                .iter()
                .find(|route| route.route_id == fixtures.bridge_route_evidence.route_id)
            else {
                return Err(format!(
                    "bridge route {} missing from descriptor fixtures",
                    fixtures.bridge_route_evidence.route_id
                ));
            };
            route
                .validate_evidence_summary(&fixtures.bridge_route_evidence)
                .map_err(|error| error.to_string())
        });
    push_result(
        checks,
        "validation.check.bridge_route_evidence",
        bridge_route_result,
        "bridge-route descriptors validate and applied WebSocket command evidence satisfies required runtime stages",
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

    push_damaged_command_checks(repo_root, checks, fixtures)?;

    push_damaged_stream_checks(repo_root, checks, fixtures, module_ids)?;

    push_damaged(
        checks,
        "validation.check.damaged_bridge_route_transport_only_evidence",
        expected_rejection(
            repo_root,
            "fixtures/damaged/bridge-route-command-transport-only-evidence.json",
        )?,
        fixtures
            .bridge_route_descriptors
            .iter()
            .find(|route| route.route_id == fixtures.damaged_bridge_route_evidence.route_id)
            .ok_or_else(|| "route_mismatch".to_owned())
            .and_then(|route| {
                route
                    .validate_evidence_summary(&fixtures.damaged_bridge_route_evidence)
                    .map_err(|error| error.rejection_code().to_owned())
            }),
        "transport-only evidence is rejected for a route that requires runtime acceptance and applied evidence",
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

#[derive(Serialize)]
pub(super) struct ValidationReport {
    #[serde(rename = "$schema")]
    pub(super) schema_id: String,
    pub(super) status: String,
    pub(super) checks: Vec<ValidationCheckReport>,
}

#[derive(Serialize)]
pub(super) struct ValidationCheckReport {
    pub(super) check_id: String,
    pub(super) status: String,
    pub(super) evidence: String,
    pub(super) rejection_code: Option<String>,
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
