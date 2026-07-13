//! Exports deterministic standalone/embedded adapter parity fixtures.

use rusty_manifold_broker_adapter::{
    packaged_product_lock_sha256, ManifoldBrokerAdapter, ManifoldBrokerAdapterConfig,
    ManifoldBrokerAdapterMode, BROKER_ADAPTER_CONFIG_SCHEMA, RUNTIME_HOST_AUTHORITY_OWNER,
};
use rusty_manifold_broker_product::{
    resolve_broker_product, ManifoldBrokerFeature, ManifoldBrokerProductLock,
    ManifoldBrokerProductSpec, BROKER_PRODUCT_SPEC_SCHEMA,
};
use rusty_manifold_model::{DottedId, Revision, SchemaId};
use rusty_manifold_runtime_host::{
    ManifoldRuntimeCommandRequest, ManifoldRuntimeLease, HOST_COMMAND_REQUEST_SCHEMA,
};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out = output_dir()?;
    fs::create_dir_all(&out)?;
    for mode in [
        ManifoldBrokerAdapterMode::Standalone,
        ManifoldBrokerAdapterMode::Embedded,
    ] {
        export_mode(&out, mode)?;
    }
    println!("wrote {}", out.display());
    Ok(())
}

fn output_dir() -> Result<PathBuf, String> {
    let mut args = std::env::args().skip(1);
    match (args.next().as_deref(), args.next(), args.next()) {
        (Some("--out"), Some(path), None) => Ok(PathBuf::from(path)),
        _ => Err("usage: export_broker_adapter_fixtures --out <directory>".to_owned()),
    }
}

fn export_mode(
    out: &Path,
    mode: ManifoldBrokerAdapterMode,
) -> Result<(), Box<dyn std::error::Error>> {
    let name = match mode {
        ManifoldBrokerAdapterMode::Standalone => "standalone",
        ManifoldBrokerAdapterMode::Embedded => "embedded",
    };
    let lock = product_lock(mode.clone());
    let packaged_lock = packaged_lock_bytes(&lock);
    let config = config(mode.clone(), &lock);
    write_json(out.join(format!("{name}-config.json")), &config)?;
    write_json(out.join(format!("{name}-product-lock.json")), &lock)?;

    let mut applied = ManifoldBrokerAdapter::new(config.clone(), &packaged_lock, vec![lease()])?;
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

    let mut unknown = ManifoldBrokerAdapter::new(config.clone(), &packaged_lock, vec![lease()])?;
    write_json(
        out.join(format!("{name}-unknown-rejected.json")),
        &unknown.handle_command(
            &request("request.broker.unknown", "command.unknown", None),
            2_000,
        ),
    )?;

    let mut unleased = ManifoldBrokerAdapter::new(config, &packaged_lock, vec![lease()])?;
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

fn product_lock(mode: ManifoldBrokerAdapterMode) -> ManifoldBrokerProductLock {
    resolve_broker_product(&ManifoldBrokerProductSpec {
        schema_id: schema(BROKER_PRODUCT_SPEC_SCHEMA),
        product_id: id("broker.camera.parity"),
        standalone_enabled: mode == ManifoldBrokerAdapterMode::Standalone,
        embedded_enabled: mode == ManifoldBrokerAdapterMode::Embedded,
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
    }
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
