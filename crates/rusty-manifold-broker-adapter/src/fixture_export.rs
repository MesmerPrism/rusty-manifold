//! Deterministic standalone/embedded adapter parity fixture export.

use crate::{
    packaged_product_lock_sha256, ManifoldBrokerAdapter, ManifoldBrokerAdapterConfig,
    ManifoldBrokerAdapterMode, ManifoldBrokerControlLeaseAuthority,
    ManifoldBrokerControlLeaseSource, ManifoldBrokerRuntime, ManifoldBrokerRuntimeLeaseProjector,
    BROKER_ADAPTER_CONFIG_SCHEMA, BROKER_CONTROL_LEASE_SOURCE_SCHEMA, RUNTIME_HOST_AUTHORITY_OWNER,
};
use rusty_manifold_admission::{ManifoldAdmissionSnapshot, ADMISSION_SNAPSHOT_SCHEMA};
use rusty_manifold_broker_product::{
    resolve_broker_product, ManifoldBrokerFeature, ManifoldBrokerProductLock,
    ManifoldBrokerProductSpec, BROKER_PRODUCT_SPEC_SCHEMA,
};
use rusty_manifold_model::{
    DottedId, ManifoldAuthoritySnapshot, ManifoldClockSnapshot,
    ManifoldControlLeaseAuthorityApplication, ManifoldControlLeaseRequest, Revision, SafetyClass,
    SchemaId,
};
use rusty_manifold_runtime_host::{
    ManifoldRuntimeCommandRequest, ManifoldRuntimeLease, HOST_COMMAND_REQUEST_SCHEMA,
};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};

/// Writes the fixed synthetic Broker adapter fixture set.
///
/// This feature-gated helper deliberately exposes no arbitrary adapter mutation
/// surface. Production consumers must enter through `ManifoldBrokerRuntime`.
///
/// # Errors
///
/// Returns an error when a synthetic contract cannot be constructed or a
/// fixture cannot be serialized or written.
pub fn export_broker_adapter_fixtures(out: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(out)?;
    for mode in [
        ManifoldBrokerAdapterMode::Standalone,
        ManifoldBrokerAdapterMode::Embedded,
    ] {
        export_mode(out, &mode)?;
    }
    export_lease_projection(out)?;
    export_runtime_evidence(out)?;
    Ok(())
}

fn export_mode(
    out: &Path,
    mode: &ManifoldBrokerAdapterMode,
) -> Result<(), Box<dyn std::error::Error>> {
    let name = match mode {
        ManifoldBrokerAdapterMode::Standalone => "standalone",
        ManifoldBrokerAdapterMode::Embedded => "embedded",
    };
    let lock = product_lock(mode);
    let packaged_lock = packaged_lock_bytes(&lock);
    let config = config(mode.clone(), &lock);
    write_json(out.join(format!("{name}-config.json")), &config)?;
    write_json(out.join(format!("{name}-product-lock.json")), &lock)?;

    let lease_authority = lease_authority()?;
    let mut applied = ManifoldBrokerAdapter::new(config.clone(), &packaged_lock, &lease_authority)?;
    write_json(
        out.join(format!("{name}-applied.json")),
        &applied.handle_command(
            &request(
                "request.broker.applied",
                "command.media.session.start",
                Some("lease.media.session.client"),
            ),
            2_000,
        ),
    )?;

    let mut unknown = ManifoldBrokerAdapter::new(config.clone(), &packaged_lock, &lease_authority)?;
    write_json(
        out.join(format!("{name}-unknown-rejected.json")),
        &unknown.handle_command(
            &request("request.broker.unknown", "command.unknown", None),
            2_000,
        ),
    )?;

    let mut unleased = ManifoldBrokerAdapter::new(config, &packaged_lock, &lease_authority)?;
    write_json(
        out.join(format!("{name}-unleased-rejected.json")),
        &unleased.handle_command(
            &request(
                "request.broker.unleased",
                "command.media.session.start",
                None,
            ),
            2_000,
        ),
    )?;
    Ok(())
}

fn export_lease_projection(out: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let prior_snapshot: ManifoldAuthoritySnapshot = serde_json::from_str(include_str!(
        "../../../fixtures/authority/synthetic-authority-snapshot.json"
    ))?;
    let application: ManifoldControlLeaseAuthorityApplication =
        serde_json::from_str(include_str!(
            "../../../fixtures/authority-application/synthetic-lease-accepted-application.json"
        ))?;
    let projection_clock: ManifoldClockSnapshot = serde_json::from_str(include_str!(
        "../../../fixtures/clock/synthetic-command-review-clock.json"
    ))?;
    let current_snapshot = application
        .applied_snapshot
        .clone()
        .ok_or("accepted lease fixture must include an applied snapshot")?;
    let projection = ManifoldBrokerRuntimeLeaseProjector::from_retained_authority_state(
        &current_snapshot,
        &projection_clock,
    )?
    .project(&prior_snapshot, &application)?;
    write_json(
        out.join("runtime-lease-projection.json"),
        projection.receipt(),
    )
}

fn export_runtime_evidence(out: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let lock = product_lock(&ManifoldBrokerAdapterMode::Standalone);
    let packaged_lock = packaged_lock_bytes(&lock);
    let config = config(ManifoldBrokerAdapterMode::Standalone, &lock);
    let initial_authority = lease_authority()?;
    let adapter = ManifoldBrokerAdapter::new(config.clone(), &packaged_lock, &initial_authority)?;
    let admission = ManifoldAdmissionSnapshot {
        schema_id: schema(ADMISSION_SNAPSHOT_SCHEMA),
        authority_id: id("authority.admission.broker.fixture"),
        authority_revision: Revision::INITIAL,
        grants: Vec::new(),
        active_tokens: Vec::new(),
        revoked_token_ids: Vec::new(),
        consumed_request_ids: Vec::new(),
        consumed_use_request_ids: Vec::new(),
        reviewed_sweep_ids: Vec::new(),
        audit_events: Vec::new(),
        max_token_ttl_ms: 30_000,
    };
    let runtime = ManifoldBrokerRuntime::new(
        id("provider_epoch.broker.fixture"),
        adapter,
        initial_authority,
        admission,
    )?;
    let current_evidence = runtime.evidence();

    // Keep the released v4 bytes immutable: they are the exact migration
    // input whose byte digest is bound by the v4-to-v5 receipt.
    let legacy_v4_json = include_str!("../../../fixtures/broker-adapter/runtime-evidence-v4.json");
    let revocation_migration_authority = lease_authority()?;
    let revocation_migration_adapter = ManifoldBrokerAdapter::new(
        config.clone(),
        &packaged_lock,
        &revocation_migration_authority,
    )?;
    let (migrated_runtime, revocation_migration_receipt) =
        ManifoldBrokerRuntime::migrate_v4_evidence_json(
            revocation_migration_adapter,
            legacy_v4_json,
        )?;
    let migrated_evidence = migrated_runtime.evidence();
    if migrated_evidence != current_evidence {
        return Err("fresh v5 evidence must equal the decision-free v4 migration result".into());
    }
    write_json(out.join("runtime-evidence-v5.json"), &migrated_evidence)?;
    write_json(
        out.join("runtime-evidence-v4-revocation-migration-receipt.json"),
        &revocation_migration_receipt,
    )?;

    // Released v2/v3/v4 fixture bytes are immutable migration inputs. Only
    // current evidence and migration receipts may be regenerated here.
    let legacy_v2_json = include_str!("../../../fixtures/broker-adapter/runtime-evidence-v2.json");
    let migration_authority = lease_authority()?;
    let migration_adapter =
        ManifoldBrokerAdapter::new(config, &packaged_lock, &migration_authority)?;
    let (_, migration_receipt) = ManifoldBrokerRuntime::from_legacy_v2_evidence_json(
        migration_adapter,
        migration_authority,
        legacy_v2_json,
    )?;
    write_json(
        out.join("runtime-evidence-v2-authority-migration-receipt.json"),
        &migration_receipt,
    )
}

fn product_lock(mode: &ManifoldBrokerAdapterMode) -> ManifoldBrokerProductLock {
    resolve_broker_product(&ManifoldBrokerProductSpec {
        schema_id: schema(BROKER_PRODUCT_SPEC_SCHEMA),
        product_id: id("broker.camera.parity"),
        standalone_enabled: *mode == ManifoldBrokerAdapterMode::Standalone,
        embedded_enabled: *mode == ManifoldBrokerAdapterMode::Embedded,
        requested_features: vec![ManifoldBrokerFeature::CameraMedia],
    })
    .expect("fixture product must resolve")
}

fn packaged_lock_bytes(lock: &ManifoldBrokerProductLock) -> Vec<u8> {
    format!(
        "{}\n",
        serde_json::to_string_pretty(lock).expect("serialize packaged product lock")
    )
    .into_bytes()
}

fn config(
    mode: ManifoldBrokerAdapterMode,
    lock: &ManifoldBrokerProductLock,
) -> ManifoldBrokerAdapterConfig {
    ManifoldBrokerAdapterConfig {
        schema_id: schema(BROKER_ADAPTER_CONFIG_SCHEMA),
        adapter_id: id(match mode {
            ManifoldBrokerAdapterMode::Standalone => "adapter.broker.standalone",
            ManifoldBrokerAdapterMode::Embedded => "adapter.broker.embedded",
        }),
        mode,
        product_lock_id: lock.lock_id.clone(),
        product_lock_fingerprint: lock.spec_fingerprint.clone(),
        product_lock_sha256: packaged_product_lock_sha256(
            format!(
                "{}\n",
                serde_json::to_string_pretty(lock).expect("serialize lock")
            )
            .as_bytes(),
        ),
        authority_host_id: id("host.broker.parity"),
        authority_owner_id: id(RUNTIME_HOST_AUTHORITY_OWNER),
    }
}

fn lease() -> ManifoldRuntimeLease {
    ManifoldRuntimeLease {
        lease_id: id("lease.media.session.client"),
        scope: id("lease.media.session"),
        holder_id: id("client.parity"),
        expires_at_ms: 60_000,
        derivative_binding: None,
    }
}

fn lease_authority() -> Result<ManifoldBrokerControlLeaseAuthority, Box<dyn std::error::Error>> {
    let mut prior: ManifoldAuthoritySnapshot = serde_json::from_str(include_str!(
        "../../../fixtures/authority/synthetic-authority-snapshot.json"
    ))?;
    let clock: ManifoldClockSnapshot = serde_json::from_str(include_str!(
        "../../../fixtures/clock/synthetic-command-review-clock.json"
    ))?;
    let projected = lease();
    let capability = id("capability.broker.fixture");
    prior.host_manifest.capabilities.push(capability.clone());
    let suffix = projected
        .lease_id
        .as_str()
        .strip_prefix("lease.")
        .ok_or("fixture lease id must start with lease.")?;
    let review = prior.review_lease_request(
        ManifoldControlLeaseRequest {
            schema_id: schema("rusty.manifold.command.lease_request.v1"),
            request_id: id(&format!("request.{suffix}")),
            holder_id: projected.holder_id,
            scope: projected.scope,
            expected_revision: prior.authority_revision,
            requested_ttl_ms: 30_000,
            required_capability: capability,
            safety_class: SafetyClass::BoundedMutation,
        },
        clock.clone(),
        vec![id("evidence.broker.fixture.lease")],
    )?;
    let application = prior.apply_control_lease_authority_review(review)?;
    let current = application
        .applied_snapshot
        .clone()
        .ok_or("fixture lease application must apply")?;
    Ok(
        ManifoldBrokerControlLeaseAuthority::from_caller_attested_retained_authority_state(
            current,
            clock,
            vec![ManifoldBrokerControlLeaseSource {
                schema_id: schema(BROKER_CONTROL_LEASE_SOURCE_SCHEMA),
                prior_authority_snapshot: prior,
                application,
            }],
        )?,
    )
}

fn request(
    request_id: &str,
    command_id: &str,
    lease_id: Option<&str>,
) -> ManifoldRuntimeCommandRequest {
    ManifoldRuntimeCommandRequest {
        schema_id: schema(HOST_COMMAND_REQUEST_SCHEMA),
        request_id: id(request_id),
        expected_authority_revision: Revision::new(1).expect("revision"),
        requester_id: id("client.parity"),
        command_id: id(command_id),
        lease_id: lease_id.map(id),
        params_digest: None,
        issued_at_ms: 1_000,
        expires_at_ms: 10_000,
    }
}

fn write_json(path: PathBuf, value: &impl Serialize) -> Result<(), Box<dyn std::error::Error>> {
    fs::write(path, format!("{}\n", serde_json::to_string_pretty(value)?))?;
    Ok(())
}

fn id(value: &str) -> DottedId {
    DottedId::new(value).expect("static id")
}

fn schema(value: &str) -> SchemaId {
    SchemaId::new(value).expect("static schema")
}
