//! Deterministic generic and Runtime Host control-lease revocation fixtures.

use rusty_manifold_model::{
    DottedId, ManifoldAuthoritySnapshot, ManifoldControlLeaseRevocationAuthorityApplication,
    ManifoldControlLeaseRevocationRequest, SchemaId,
};
use rusty_manifold_runtime_host::{
    ManifoldRuntimeControlLeaseAdoptionRequest, ManifoldRuntimeControlLeaseAuthorityApplication,
    ManifoldRuntimeDerivativeLeaseBinding, ManifoldRuntimeDerivativeLeaseRevocationRequest,
    ManifoldRuntimeHost, ManifoldRuntimeLease, ManifoldRuntimeUpstreamRevocationProof,
    HOST_CONTROL_LEASE_ADOPTION_REQUEST_SCHEMA, HOST_DERIVATIVE_LEASE_BINDING_SCHEMA,
    HOST_DERIVATIVE_LEASE_REVOCATION_REQUEST_SCHEMA,
};
use serde::Serialize;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let repo_root = parse_repo_root(env::args().skip(1).collect())?;
    export_fixtures(&repo_root)
}

fn parse_repo_root(args: Vec<String>) -> Result<PathBuf, String> {
    let mut args = args.into_iter();
    let Some(flag) = args.next() else {
        return Err(
            "usage: export_control_lease_revocation_fixtures --repo-root <directory>".to_owned(),
        );
    };
    let Some(value) = args.next() else {
        return Err("--repo-root requires a value".to_owned());
    };
    if flag != "--repo-root" || args.next().is_some() {
        return Err(
            "usage: export_control_lease_revocation_fixtures --repo-root <directory>".to_owned(),
        );
    }
    Ok(PathBuf::from(value))
}

fn export_fixtures(repo_root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    export_runtime_host_v3_migration_fixture(repo_root)?;
    let prior: ManifoldAuthoritySnapshot =
        read_json(&repo_root.join("fixtures/authority/synthetic-authority-snapshot.json"))?;
    let target = prior
        .active_leases
        .first()
        .ok_or("authority fixture must contain one active lease")?
        .clone();

    let accepted_request = revocation_request(
        &prior,
        "request.synthetic.lease_revocation.accepted",
        prior.authority_id.clone(),
        &target.lease_id,
        &target.scope,
    );
    let accepted_review = prior.review_control_lease_revocation(
        accepted_request.clone(),
        prior.clock_snapshot.clone(),
        vec![id("evidence.synthetic.lease_revocation.accepted")],
    )?;
    let accepted_application =
        prior.apply_control_lease_revocation_authority_review(accepted_review.clone())?;
    let accepted_snapshot = accepted_application
        .applied_snapshot
        .as_ref()
        .ok_or("accepted revocation must include its applied snapshot")?;

    write_json(
        &repo_root.join("fixtures/command/synthetic-lease-revocation-request.json"),
        &accepted_request,
    )?;
    write_json(
        &repo_root.join("fixtures/audit/synthetic-lease-revocation-accepted-event.json"),
        &accepted_review.audit_event,
    )?;
    write_json(
        &repo_root.join(
            "fixtures/lease-revocation-review/synthetic-lease-revocation-accepted-review.json",
        ),
        &accepted_review,
    )?;
    write_json(
        &repo_root.join(
            "fixtures/authority-application/synthetic-lease-revocation-accepted-application.json",
        ),
        &accepted_application,
    )?;
    write_json(
        &repo_root.join("fixtures/authority/synthetic-lease-revocation-tombstone.json"),
        accepted_application
            .tombstone
            .as_ref()
            .ok_or("accepted revocation must include its terminal tombstone")?,
    )?;
    write_json(
        &repo_root.join("fixtures/authority/synthetic-authority-revoked-lease-snapshot.json"),
        accepted_snapshot,
    )?;

    let rejected_request = revocation_request(
        &prior,
        "request.synthetic.lease_revocation.authority_mismatch",
        id("authority.substituted"),
        &target.lease_id,
        &target.scope,
    );
    let rejected_review = prior.review_control_lease_revocation(
        rejected_request.clone(),
        prior.clock_snapshot.clone(),
        vec![id("evidence.synthetic.lease_revocation.rejected")],
    )?;
    let rejected_application =
        prior.apply_control_lease_revocation_authority_review(rejected_review.clone())?;
    write_json(
        &repo_root.join("fixtures/damaged/lease-revocation-request-authority-mismatch.json"),
        &rejected_request,
    )?;
    write_json(
        &repo_root.join("fixtures/command/synthetic-lease-revocation-rejection.json"),
        rejected_review
            .rejection
            .as_ref()
            .ok_or("rejected revocation review must include a rejection")?,
    )?;
    write_json(
        &repo_root.join("fixtures/audit/synthetic-lease-revocation-rejected-event.json"),
        &rejected_review.audit_event,
    )?;
    write_json(
        &repo_root.join(
            "fixtures/lease-revocation-review/synthetic-lease-revocation-rejected-review.json",
        ),
        &rejected_review,
    )?;
    write_json(
        &repo_root.join(
            "fixtures/authority-application/synthetic-lease-revocation-rejected-application.json",
        ),
        &rejected_application,
    )?;
    write_json(
        &repo_root.join(
            "fixtures/authority-application/synthetic-lease-revocation-application-rejection.json",
        ),
        rejected_application
            .rejection
            .as_ref()
            .ok_or("rejected revocation application must include its rejection")?,
    )?;

    export_runtime_host_fixtures(repo_root, &prior, &target, accepted_application)
}

fn export_runtime_host_v3_migration_fixture(
    repo_root: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let broker_v4: serde_json::Value =
        read_json(&repo_root.join("fixtures/broker-adapter/runtime-evidence-v4.json"))?;
    let legacy_host = broker_v4
        .get("host_snapshot")
        .ok_or("released Broker v4 fixture must contain its Runtime Host snapshot")?;
    let legacy_host_json = serde_json::to_string(legacy_host)?;
    let (_, receipt) = ManifoldRuntimeHost::restart_from_json_with_migration(&legacy_host_json)?;
    if !receipt.migrated
        || receipt.source_schema_id.as_str() != "rusty.manifold.runtime_host.snapshot.v3"
    {
        return Err("released Runtime Host v3 fixture must migrate explicitly to current".into());
    }
    write_json(
        &repo_root
            .join("fixtures/runtime-host/synthetic-runtime-host-v3-to-v4-migration-receipt.json"),
        &receipt,
    )
}

fn export_runtime_host_fixtures(
    repo_root: &Path,
    prior: &ManifoldAuthoritySnapshot,
    target: &rusty_manifold_model::ManifoldControlLease,
    accepted_application: ManifoldControlLeaseRevocationAuthorityApplication,
) -> Result<(), Box<dyn std::error::Error>> {
    let legacy_host_json = fs::read_to_string(
        repo_root.join("fixtures/runtime-host/synthetic-runtime-host-snapshot.json"),
    )?;
    let mut host_snapshot = ManifoldRuntimeHost::restart_from_json(&legacy_host_json)?
        .snapshot()
        .clone();
    host_snapshot.leases = vec![ManifoldRuntimeLease {
        lease_id: target.lease_id.clone(),
        scope: target.scope.clone(),
        holder_id: target.holder_id.clone(),
        expires_at_ms: target.expires_at_ms,
        derivative_binding: None,
    }];

    let host = ManifoldRuntimeHost::from_snapshot(host_snapshot.clone())?;
    let accepted_request = ManifoldRuntimeControlLeaseAdoptionRequest {
        schema_id: schema(HOST_CONTROL_LEASE_ADOPTION_REQUEST_SCHEMA),
        adoption_id: id("adoption.runtime.lease_revocation.accepted"),
        expected_host_authority_revision: host.snapshot().authority_revision,
        prior_authority_snapshot: prior.clone(),
        application: ManifoldRuntimeControlLeaseAuthorityApplication::Revocation(Box::new(
            accepted_application.clone(),
        )),
    };
    let mut accepted_host = host.clone();
    let accepted_receipt = accepted_host.apply_control_lease_adoption(&accepted_request);
    if !accepted_receipt.applied {
        return Err("Runtime Host must adopt the valid revocation fixture".into());
    }
    write_json(
        &repo_root
            .join("fixtures/runtime-host/synthetic-control-lease-revocation-adoption-request.json"),
        &accepted_request,
    )?;
    write_json(
        &repo_root
            .join("fixtures/runtime-host/synthetic-control-lease-revocation-adoption-receipt.json"),
        &accepted_receipt,
    )?;
    write_json(
        &repo_root
            .join("fixtures/runtime-host/synthetic-control-lease-revocation-applied-snapshot.json"),
        accepted_host.snapshot(),
    )?;
    export_derivative_runtime_host_fixtures(repo_root, &prior, &accepted_application)?;

    let mut damaged_application = accepted_application;
    damaged_application.authority_id = id("authority.substituted");
    let damaged_request = ManifoldRuntimeControlLeaseAdoptionRequest {
        schema_id: schema(HOST_CONTROL_LEASE_ADOPTION_REQUEST_SCHEMA),
        adoption_id: id("adoption.runtime.lease_revocation.damaged"),
        expected_host_authority_revision: host_snapshot.authority_revision,
        prior_authority_snapshot: prior.clone(),
        application: ManifoldRuntimeControlLeaseAuthorityApplication::Revocation(Box::new(
            damaged_application,
        )),
    };
    let mut rejected_host = ManifoldRuntimeHost::from_snapshot(host_snapshot)?;
    let rejected_receipt = rejected_host.apply_control_lease_adoption(&damaged_request);
    if rejected_receipt.applied {
        return Err("Runtime Host must reject the damaged revocation fixture".into());
    }
    write_json(
        &repo_root
            .join("fixtures/damaged/runtime-host-control-lease-revocation-adoption-request.json"),
        &damaged_request,
    )?;
    write_json(
        &repo_root.join(
            "fixtures/runtime-host/synthetic-control-lease-revocation-adoption-rejected-receipt.json",
        ),
        &rejected_receipt,
    )
}

fn export_derivative_runtime_host_fixtures(
    repo_root: &Path,
    upstream_prior_authority_snapshot: &ManifoldAuthoritySnapshot,
    upstream_application: &ManifoldControlLeaseRevocationAuthorityApplication,
) -> Result<(), Box<dyn std::error::Error>> {
    let legacy_host_json = fs::read_to_string(
        repo_root.join("fixtures/runtime-host/synthetic-runtime-host-snapshot.json"),
    )?;
    let mut initial_snapshot = ManifoldRuntimeHost::restart_from_json(&legacy_host_json)?
        .snapshot()
        .clone();
    let provider_epoch_id = id("provider_epoch.synthetic.upstream");
    for lease in &mut initial_snapshot.leases {
        lease.derivative_binding = Some(ManifoldRuntimeDerivativeLeaseBinding {
            schema_id: schema(HOST_DERIVATIVE_LEASE_BINDING_SCHEMA),
            binding_id: id(&format!("binding.derivative.{}", lease.lease_id)),
            provider_epoch_id: provider_epoch_id.clone(),
            upstream_control_lease_id: upstream_application.lease_id.clone(),
            source_authorization_id: id(&format!("authorization.derivative.{}", lease.lease_id)),
        });
    }

    let mut accepted_host = ManifoldRuntimeHost::from_snapshot(initial_snapshot.clone())?;
    let upstream_revocation_proof =
        ManifoldRuntimeUpstreamRevocationProof::from_accepted_application(
            provider_epoch_id,
            upstream_prior_authority_snapshot.clone(),
            upstream_application.clone(),
        )?;
    let accepted_request = ManifoldRuntimeDerivativeLeaseRevocationRequest {
        schema_id: schema(HOST_DERIVATIVE_LEASE_REVOCATION_REQUEST_SCHEMA),
        revocation_id: id("revocation.runtime.derivative.accepted"),
        convergence_id: id("convergence.runtime.derivative.accepted"),
        expected_host_authority_revision: accepted_host.snapshot().authority_revision,
        upstream_revocation_proof: upstream_revocation_proof.clone(),
        exact_leases: accepted_host.snapshot().leases.clone(),
    };
    let accepted_receipt = accepted_host.apply_derivative_lease_revocation(&accepted_request);
    if !accepted_receipt.applied {
        return Err("Runtime Host must apply the exact derivative revocation fixture".into());
    }
    accepted_receipt.validate_against_snapshot(accepted_host.snapshot())?;
    let accepted_audit = accepted_host
        .snapshot()
        .audit_events
        .last()
        .ok_or("accepted derivative revocation must append audit")?;
    let accepted_binding = accepted_audit
        .derivative_lease_revocation
        .as_ref()
        .ok_or("accepted derivative revocation audit must retain its exact input")?;
    write_json(
        &repo_root.join("fixtures/runtime-host/synthetic-derivative-lease-revocation-request.json"),
        &accepted_request,
    )?;
    write_json(
        &repo_root.join("fixtures/runtime-host/synthetic-derivative-lease-revocation-receipt.json"),
        &accepted_receipt,
    )?;
    write_json(
        &repo_root
            .join("fixtures/runtime-host/synthetic-derivative-lease-revocation-audit-binding.json"),
        accepted_binding,
    )?;
    write_json(
        &repo_root
            .join("fixtures/runtime-host/synthetic-derivative-lease-revocation-audit-event.json"),
        accepted_audit,
    )?;
    write_json(
        &repo_root.join(
            "fixtures/runtime-host/synthetic-derivative-lease-revocation-applied-snapshot.json",
        ),
        accepted_host.snapshot(),
    )?;

    let mut substituted_lease = initial_snapshot
        .leases
        .first()
        .ok_or("Runtime Host fixture must contain one derivative lease")?
        .clone();
    substituted_lease
        .derivative_binding
        .as_mut()
        .ok_or("Runtime Host fixture derivative lease must retain binding")?
        .upstream_control_lease_id = id("lease.outer.substituted");
    let rejected_request = ManifoldRuntimeDerivativeLeaseRevocationRequest {
        schema_id: schema(HOST_DERIVATIVE_LEASE_REVOCATION_REQUEST_SCHEMA),
        revocation_id: id("revocation.runtime.derivative.substituted"),
        convergence_id: id("convergence.runtime.derivative.substituted"),
        expected_host_authority_revision: initial_snapshot.authority_revision,
        upstream_revocation_proof,
        exact_leases: vec![substituted_lease],
    };
    let mut rejected_host = ManifoldRuntimeHost::from_snapshot(initial_snapshot)?;
    let rejected_receipt = rejected_host.apply_derivative_lease_revocation(&rejected_request);
    if rejected_receipt.applied {
        return Err("Runtime Host must reject substituted derivative lease evidence".into());
    }
    rejected_receipt.validate_against_snapshot(rejected_host.snapshot())?;
    let rejected_audit = rejected_host
        .snapshot()
        .audit_events
        .last()
        .ok_or("rejected derivative revocation must append audit")?;
    write_json(
        &repo_root.join(
            "fixtures/damaged/runtime-host-derivative-lease-revocation-substituted-request.json",
        ),
        &rejected_request,
    )?;
    write_json(
        &repo_root.join(
            "fixtures/runtime-host/synthetic-derivative-lease-revocation-rejected-receipt.json",
        ),
        &rejected_receipt,
    )?;
    write_json(
        &repo_root.join(
            "fixtures/runtime-host/synthetic-derivative-lease-revocation-rejected-audit-event.json",
        ),
        rejected_audit,
    )
}

fn revocation_request(
    prior: &ManifoldAuthoritySnapshot,
    request_id: &str,
    authority_id: DottedId,
    lease_id: &DottedId,
    scope: &DottedId,
) -> ManifoldControlLeaseRevocationRequest {
    ManifoldControlLeaseRevocationRequest {
        schema_id: schema("rusty.manifold.command.lease_revocation_request.v1"),
        request_id: id(request_id),
        authority_id,
        lease_id: lease_id.clone(),
        expected_authority_revision: prior.authority_revision,
        scope: scope.clone(),
        revocation_reason: id("reason.security.policy_revocation"),
        requested_at_ms: u64::try_from(prior.clock_snapshot.wall_unix_ms)
            .expect("fixture wall time is non-negative"),
    }
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, Box<dyn std::error::Error>> {
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, format!("{}\n", serde_json::to_string_pretty(value)?))?;
    Ok(())
}

fn id(value: &str) -> DottedId {
    DottedId::new(value).expect("static id")
}

fn schema(value: &str) -> SchemaId {
    SchemaId::new(value).expect("static schema")
}
