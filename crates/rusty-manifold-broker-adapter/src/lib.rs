//! Standalone and embedded broker adapters over one Manifold Runtime Host.

mod runtime;

pub use runtime::*;

use rusty_manifold_broker_product::{ManifoldBrokerProductLock, BROKER_PRODUCT_LOCK_SCHEMA};
use rusty_manifold_model::{DottedId, Revision, SchemaId};
use rusty_manifold_runtime_host::{
    ManifoldRuntimeApplicationReceipt, ManifoldRuntimeCommandDescriptor,
    ManifoldRuntimeCommandRequest, ManifoldRuntimeDispatchOutcome, ManifoldRuntimeDispatchReceipt,
    ManifoldRuntimeHost, ManifoldRuntimeHostError, ManifoldRuntimeHostSnapshot,
    ManifoldRuntimeLease, ManifoldRuntimeRejectionReason, ManifoldRuntimeTypedParamsDigest,
    HOST_APPLICATION_RECEIPT_SCHEMA, HOST_DISPATCH_RECEIPT_SCHEMA, HOST_SNAPSHOT_SCHEMA,
    LEGACY_HOST_APPLICATION_RECEIPT_V1_SCHEMA, LEGACY_HOST_DISPATCH_RECEIPT_V1_SCHEMA,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;

/// Legacy broker adapter config schema accepted only by migration.
pub const LEGACY_BROKER_ADAPTER_CONFIG_V1_SCHEMA: &str = "rusty.manifold.broker.adapter_config.v1";
/// Broker adapter configuration schema with exact packaged-lock bytes bound.
pub const BROKER_ADAPTER_CONFIG_SCHEMA: &str = "rusty.manifold.broker.adapter_config.v2";
/// Legacy broker adapter receipt schema accepted only by migration.
pub const LEGACY_BROKER_ADAPTER_RECEIPT_V1_SCHEMA: &str =
    "rusty.manifold.broker.adapter_receipt.v1";
/// Broker adapter receipt schema with exact packaged-lock and host provenance.
pub const BROKER_ADAPTER_RECEIPT_SCHEMA: &str = "rusty.manifold.broker.adapter_receipt.v2";
/// Broker adapter v1-to-v2 migration receipt schema.
pub const BROKER_ADAPTER_MIGRATION_RECEIPT_SCHEMA: &str =
    "rusty.manifold.broker.adapter_migration_receipt.v1";
/// Sole accepted-state and command-decision owner.
pub const RUNTIME_HOST_AUTHORITY_OWNER: &str = "module.runtime.host";

/// Computes the exact SHA-256 binding for caller-supplied packaged lock bytes.
/// This is distinct from the lock's semantic `spec_fingerprint`.
#[must_use]
pub fn packaged_product_lock_sha256(packaged_lock_bytes: &[u8]) -> String {
    let digest = Sha256::digest(packaged_lock_bytes);
    let mut encoded = String::with_capacity(71);
    encoded.push_str("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("String writes cannot fail");
    }
    encoded
}

/// Broker process placement. Placement never changes command authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldBrokerAdapterMode {
    /// Dedicated background process/application.
    Standalone,
    /// Same-process adapter hosted by another application.
    Embedded,
}

/// Truthful non-authoritative role of the process adapter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldBrokerAdapterRole {
    /// Socket/process adapter around the Runtime Host.
    ProcessTransportAdapter,
    /// In-process adapter around the Runtime Host.
    InProcessAdapter,
}

/// Immutable adapter binding to one accepted product lock and Runtime Host.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerAdapterConfig {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Stable adapter identity.
    pub adapter_id: DottedId,
    /// Process placement.
    pub mode: ManifoldBrokerAdapterMode,
    /// Exact accepted product lock identity.
    pub product_lock_id: DottedId,
    /// Exact accepted product-lock fingerprint.
    pub product_lock_fingerprint: String,
    /// SHA-256 of the exact packaged accepted-lock bytes.
    pub product_lock_sha256: String,
    /// Stable Runtime Host identity.
    pub authority_host_id: DottedId,
    /// Must remain `module.runtime.host`.
    pub authority_owner_id: DottedId,
}

/// Adapter-level receipt that preserves the underlying host receipts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerAdapterReceipt {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Stable adapter identity.
    pub adapter_id: DottedId,
    /// Process placement.
    pub mode: ManifoldBrokerAdapterMode,
    /// Truthful non-authoritative adapter role.
    pub adapter_role: ManifoldBrokerAdapterRole,
    /// Exact accepted product lock identity.
    pub product_lock_id: DottedId,
    /// Exact accepted product-lock fingerprint.
    pub product_lock_fingerprint: String,
    /// SHA-256 of the exact packaged accepted-lock bytes.
    pub product_lock_sha256: String,
    /// Runtime Host identity that owns accepted state.
    pub authority_host_id: DottedId,
    /// Runtime Host module that owns the decision.
    pub authority_owner_id: DottedId,
    /// Host review receipt.
    pub dispatch: ManifoldRuntimeDispatchReceipt,
    /// Host application/rejection receipt.
    pub application: ManifoldRuntimeApplicationReceipt,
}

/// Broker adapter artifact migrated from a released v1 shape.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldBrokerAdapterMigrationArtifact {
    /// Immutable adapter config.
    Config,
    /// Adapter review/application receipt.
    Receipt,
    /// Adapter plus durable Runtime Host restart.
    Restart,
}

/// Explicit evidence for a broker adapter v1-to-v2 migration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerAdapterMigrationReceipt {
    /// Receipt schema.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Migrated artifact family.
    pub artifact: ManifoldBrokerAdapterMigrationArtifact,
    /// Source schema ids consumed by the migration.
    pub source_schema_ids: Vec<SchemaId>,
    /// Resulting schema ids emitted by the migration.
    pub resulting_schema_ids: Vec<SchemaId>,
    /// Exact adapter identity.
    pub adapter_id: DottedId,
    /// Exact Runtime Host identity.
    pub authority_host_id: DottedId,
    /// SHA-256 of the exact packaged product-lock bytes supplied to migration.
    pub product_lock_sha256: String,
    /// Whether a legacy Runtime Host snapshot was migrated with the adapter.
    pub runtime_host_snapshot_migrated: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct LegacyBrokerAdapterConfigV1 {
    #[serde(rename = "$schema")]
    schema_id: SchemaId,
    adapter_id: DottedId,
    mode: ManifoldBrokerAdapterMode,
    product_lock_id: DottedId,
    product_lock_fingerprint: String,
    authority_host_id: DottedId,
    authority_owner_id: DottedId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct LegacyRuntimeDispatchReceiptV1 {
    #[serde(rename = "$schema")]
    schema_id: SchemaId,
    dispatch_id: DottedId,
    request_id: DottedId,
    command_id: DottedId,
    #[serde(default)]
    params_digest: Option<ManifoldRuntimeTypedParamsDigest>,
    reviewed_authority_revision: Revision,
    outcome: ManifoldRuntimeDispatchOutcome,
    rejection_reason: Option<ManifoldRuntimeRejectionReason>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct LegacyRuntimeApplicationReceiptV1 {
    #[serde(rename = "$schema")]
    schema_id: SchemaId,
    receipt_id: DottedId,
    dispatch_id: DottedId,
    request_id: DottedId,
    #[serde(default)]
    params_digest: Option<ManifoldRuntimeTypedParamsDigest>,
    applied: bool,
    prior_authority_revision: Revision,
    resulting_authority_revision: Revision,
    rejection_reason: Option<ManifoldRuntimeRejectionReason>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct LegacyBrokerAdapterReceiptV1 {
    #[serde(rename = "$schema")]
    schema_id: SchemaId,
    adapter_id: DottedId,
    mode: ManifoldBrokerAdapterMode,
    adapter_role: ManifoldBrokerAdapterRole,
    product_lock_id: DottedId,
    product_lock_fingerprint: String,
    authority_host_id: DottedId,
    authority_owner_id: DottedId,
    dispatch: LegacyRuntimeDispatchReceiptV1,
    application: LegacyRuntimeApplicationReceiptV1,
}

/// Shared adapter implementation. Mode changes placement labels only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldBrokerAdapter {
    config: ManifoldBrokerAdapterConfig,
    product_lock: ManifoldBrokerProductLock,
    host: ManifoldRuntimeHost,
}

/// Migrates a released v1 adapter config using the exact packaged product-lock
/// bytes. The semantic FNV fingerprint remains distinct from the exact SHA-256.
///
/// # Errors
///
/// Returns an error when the legacy config, packaged lock, placement, owner,
/// or lock identity does not form a closed adapter binding.
pub fn migrate_legacy_broker_adapter_config(
    legacy_json: &str,
    packaged_product_lock_bytes: &[u8],
) -> Result<
    (
        ManifoldBrokerAdapterConfig,
        ManifoldBrokerAdapterMigrationReceipt,
    ),
    ManifoldBrokerAdapterError,
> {
    let legacy: LegacyBrokerAdapterConfigV1 = serde_json::from_str(legacy_json)
        .map_err(ManifoldBrokerAdapterError::DeserializeLegacyArtifact)?;
    let product_lock = decode_packaged_product_lock(packaged_product_lock_bytes)?;
    validate_legacy_adapter_binding(
        &legacy.schema_id,
        &legacy.mode,
        &legacy.product_lock_id,
        &legacy.product_lock_fingerprint,
        &legacy.authority_owner_id,
        &product_lock,
    )?;
    let config = ManifoldBrokerAdapterConfig {
        schema_id: schema_id(BROKER_ADAPTER_CONFIG_SCHEMA),
        adapter_id: legacy.adapter_id,
        mode: legacy.mode,
        product_lock_id: legacy.product_lock_id,
        product_lock_fingerprint: legacy.product_lock_fingerprint,
        product_lock_sha256: packaged_product_lock_sha256(packaged_product_lock_bytes),
        authority_host_id: legacy.authority_host_id,
        authority_owner_id: legacy.authority_owner_id,
    };
    validate_config_lock(&config, &product_lock, packaged_product_lock_bytes)?;
    let receipt = broker_adapter_migration_receipt(
        ManifoldBrokerAdapterMigrationArtifact::Config,
        vec![schema_id(LEGACY_BROKER_ADAPTER_CONFIG_V1_SCHEMA)],
        vec![config.schema_id.clone()],
        &config.adapter_id,
        &config.authority_host_id,
        &config.product_lock_sha256,
        false,
    );
    Ok((config, receipt))
}

/// Migrates a released v1 adapter receipt into the v2 exact-lock/host-bound
/// evidence shape. This is evidence conversion only; it never applies state.
///
/// # Errors
///
/// Returns an error when legacy receipt closure or exact packaged-lock
/// provenance cannot be validated.
pub fn migrate_legacy_broker_adapter_receipt(
    legacy_json: &str,
    packaged_product_lock_bytes: &[u8],
) -> Result<
    (
        ManifoldBrokerAdapterReceipt,
        ManifoldBrokerAdapterMigrationReceipt,
    ),
    ManifoldBrokerAdapterError,
> {
    let legacy: LegacyBrokerAdapterReceiptV1 = serde_json::from_str(legacy_json)
        .map_err(ManifoldBrokerAdapterError::DeserializeLegacyArtifact)?;
    let product_lock = decode_packaged_product_lock(packaged_product_lock_bytes)?;
    validate_legacy_adapter_binding(
        &legacy.schema_id,
        &legacy.mode,
        &legacy.product_lock_id,
        &legacy.product_lock_fingerprint,
        &legacy.authority_owner_id,
        &product_lock,
    )?;
    if legacy.schema_id.as_str() != LEGACY_BROKER_ADAPTER_RECEIPT_V1_SCHEMA
        || legacy.dispatch.schema_id.as_str() != LEGACY_HOST_DISPATCH_RECEIPT_V1_SCHEMA
        || legacy.application.schema_id.as_str() != LEGACY_HOST_APPLICATION_RECEIPT_V1_SCHEMA
        || legacy.adapter_role != role_for_mode(&legacy.mode)
        || legacy.dispatch.request_id != legacy.application.request_id
        || legacy.dispatch.dispatch_id != legacy.application.dispatch_id
        || legacy.dispatch.params_digest != legacy.application.params_digest
        || legacy.dispatch.reviewed_authority_revision
            != legacy.application.prior_authority_revision
        || (legacy.dispatch.outcome == ManifoldRuntimeDispatchOutcome::Ready)
            != legacy.dispatch.rejection_reason.is_none()
        || legacy.application.applied != legacy.application.rejection_reason.is_none()
        || (legacy.application.applied
            && legacy.application.prior_authority_revision.next()
                != Some(legacy.application.resulting_authority_revision))
        || (!legacy.application.applied
            && legacy.application.prior_authority_revision
                != legacy.application.resulting_authority_revision)
    {
        return Err(ManifoldBrokerAdapterError::InvalidLegacyArtifact);
    }
    let exact_sha256 = packaged_product_lock_sha256(packaged_product_lock_bytes);
    let dispatch = ManifoldRuntimeDispatchReceipt {
        schema_id: schema_id(HOST_DISPATCH_RECEIPT_SCHEMA),
        authority_host_id: legacy.authority_host_id.clone(),
        dispatch_id: legacy.dispatch.dispatch_id,
        request_id: legacy.dispatch.request_id,
        command_id: legacy.dispatch.command_id,
        params_digest: legacy.dispatch.params_digest,
        reviewed_authority_revision: legacy.dispatch.reviewed_authority_revision,
        outcome: legacy.dispatch.outcome,
        rejection_reason: legacy.dispatch.rejection_reason,
    };
    let application = ManifoldRuntimeApplicationReceipt {
        schema_id: schema_id(HOST_APPLICATION_RECEIPT_SCHEMA),
        authority_host_id: legacy.authority_host_id.clone(),
        receipt_id: legacy.application.receipt_id,
        dispatch_id: legacy.application.dispatch_id,
        request_id: legacy.application.request_id,
        params_digest: legacy.application.params_digest,
        applied: legacy.application.applied,
        prior_authority_revision: legacy.application.prior_authority_revision,
        resulting_authority_revision: legacy.application.resulting_authority_revision,
        rejection_reason: legacy.application.rejection_reason,
    };
    let migrated = ManifoldBrokerAdapterReceipt {
        schema_id: schema_id(BROKER_ADAPTER_RECEIPT_SCHEMA),
        adapter_id: legacy.adapter_id,
        mode: legacy.mode,
        adapter_role: legacy.adapter_role,
        product_lock_id: legacy.product_lock_id,
        product_lock_fingerprint: legacy.product_lock_fingerprint,
        product_lock_sha256: exact_sha256.clone(),
        authority_host_id: legacy.authority_host_id,
        authority_owner_id: legacy.authority_owner_id,
        dispatch,
        application,
    };
    let receipt = broker_adapter_migration_receipt(
        ManifoldBrokerAdapterMigrationArtifact::Receipt,
        vec![
            schema_id(LEGACY_BROKER_ADAPTER_RECEIPT_V1_SCHEMA),
            schema_id(LEGACY_HOST_DISPATCH_RECEIPT_V1_SCHEMA),
            schema_id(LEGACY_HOST_APPLICATION_RECEIPT_V1_SCHEMA),
        ],
        vec![
            migrated.schema_id.clone(),
            migrated.dispatch.schema_id.clone(),
            migrated.application.schema_id.clone(),
        ],
        &migrated.adapter_id,
        &migrated.authority_host_id,
        &exact_sha256,
        false,
    );
    Ok((migrated, receipt))
}

impl ManifoldBrokerAdapter {
    /// Returns the immutable adapter/product provenance binding.
    #[must_use]
    pub const fn config(&self) -> &ManifoldBrokerAdapterConfig {
        &self.config
    }

    /// Creates a new host whose command registry is derived exactly from the lock.
    pub fn new(
        config: ManifoldBrokerAdapterConfig,
        packaged_product_lock_bytes: &[u8],
        leases: Vec<ManifoldRuntimeLease>,
    ) -> Result<Self, ManifoldBrokerAdapterError> {
        let product_lock = decode_packaged_product_lock(packaged_product_lock_bytes)?;
        validate_config_lock(&config, &product_lock, packaged_product_lock_bytes)?;
        let snapshot = snapshot_from_lock(&config, &product_lock, leases)?;
        let host = ManifoldRuntimeHost::from_snapshot(snapshot)
            .map_err(ManifoldBrokerAdapterError::RuntimeHost)?;
        Ok(Self {
            config,
            product_lock,
            host,
        })
    }

    /// Restarts an adapter from a durable Runtime Host snapshot and revalidates lock parity.
    pub fn restart_from_json(
        config: ManifoldBrokerAdapterConfig,
        packaged_product_lock_bytes: &[u8],
        snapshot_json: &str,
    ) -> Result<Self, ManifoldBrokerAdapterError> {
        let product_lock = decode_packaged_product_lock(packaged_product_lock_bytes)?;
        validate_config_lock(&config, &product_lock, packaged_product_lock_bytes)?;
        let host = ManifoldRuntimeHost::restart_from_json(snapshot_json)
            .map_err(ManifoldBrokerAdapterError::RuntimeHost)?;
        validate_host_binding(&config, &product_lock, host.snapshot())?;
        Ok(Self {
            config,
            product_lock,
            host,
        })
    }

    /// Migrates a v1 config and v1/v2 Runtime Host snapshot using the exact
    /// packaged product-lock bytes, then restarts the adapter.
    ///
    /// # Errors
    ///
    /// Returns an error when config, packaged bytes, Runtime Host lineage, or
    /// resulting adapter closure fails validation.
    pub fn restart_from_legacy_json(
        legacy_config_json: &str,
        packaged_product_lock_bytes: &[u8],
        snapshot_json: &str,
    ) -> Result<(Self, ManifoldBrokerAdapterMigrationReceipt), ManifoldBrokerAdapterError> {
        let (config, _) =
            migrate_legacy_broker_adapter_config(legacy_config_json, packaged_product_lock_bytes)?;
        let product_lock = decode_packaged_product_lock(packaged_product_lock_bytes)?;
        validate_config_lock(&config, &product_lock, packaged_product_lock_bytes)?;
        let (host, host_receipt) =
            ManifoldRuntimeHost::restart_from_json_with_migration(snapshot_json)
                .map_err(ManifoldBrokerAdapterError::RuntimeHost)?;
        validate_host_binding(&config, &product_lock, host.snapshot())?;
        let receipt = broker_adapter_migration_receipt(
            ManifoldBrokerAdapterMigrationArtifact::Restart,
            vec![
                schema_id(LEGACY_BROKER_ADAPTER_CONFIG_V1_SCHEMA),
                host_receipt.source_schema_id,
            ],
            vec![config.schema_id.clone(), host.snapshot().schema_id.clone()],
            &config.adapter_id,
            &config.authority_host_id,
            &config.product_lock_sha256,
            host_receipt.migrated,
        );
        Ok((
            Self {
                config,
                product_lock,
                host,
            },
            receipt,
        ))
    }

    /// Reviews then applies through the sole Runtime Host path.
    pub fn handle_command(
        &mut self,
        request: &ManifoldRuntimeCommandRequest,
        now_ms: u64,
    ) -> ManifoldBrokerAdapterReceipt {
        let dispatch = self.host.review_command(request, now_ms);
        let application = self.host.apply_dispatch(request, &dispatch, now_ms);
        ManifoldBrokerAdapterReceipt {
            schema_id: schema_id(BROKER_ADAPTER_RECEIPT_SCHEMA),
            adapter_id: self.config.adapter_id.clone(),
            mode: self.config.mode.clone(),
            adapter_role: role_for_mode(&self.config.mode),
            product_lock_id: self.product_lock.lock_id.clone(),
            product_lock_fingerprint: self.product_lock.spec_fingerprint.clone(),
            product_lock_sha256: self.config.product_lock_sha256.clone(),
            authority_host_id: self.config.authority_host_id.clone(),
            authority_owner_id: self.config.authority_owner_id.clone(),
            dispatch,
            application,
        }
    }

    /// Returns accepted Runtime Host state.
    #[must_use]
    pub const fn host_snapshot(&self) -> &ManifoldRuntimeHostSnapshot {
        self.host.snapshot()
    }

    /// Serializes durable Runtime Host state for process restart.
    pub fn snapshot_json(&self) -> Result<String, ManifoldBrokerAdapterError> {
        self.host
            .snapshot_json()
            .map_err(ManifoldBrokerAdapterError::RuntimeHost)
    }
}

fn snapshot_from_lock(
    config: &ManifoldBrokerAdapterConfig,
    lock: &ManifoldBrokerProductLock,
    leases: Vec<ManifoldRuntimeLease>,
) -> Result<ManifoldRuntimeHostSnapshot, ManifoldBrokerAdapterError> {
    let commands = lock
        .command_ids
        .iter()
        .map(|command_id| ManifoldRuntimeCommandDescriptor {
            command_id: command_id.clone(),
            required_lease_scope: lease_scope_for_command(command_id),
        })
        .collect();
    let snapshot = ManifoldRuntimeHostSnapshot {
        schema_id: schema_id(HOST_SNAPSHOT_SCHEMA),
        host_id: config.authority_host_id.clone(),
        authority_revision: Revision::new(1).expect("initial revision is valid"),
        commands,
        leases,
        applied_request_ids: Vec::new(),
        reviewed_sweep_ids: Vec::new(),
        audit_events: Vec::new(),
    };
    validate_host_binding(config, lock, &snapshot)?;
    Ok(snapshot)
}

fn validate_config_lock(
    config: &ManifoldBrokerAdapterConfig,
    lock: &ManifoldBrokerProductLock,
    packaged_product_lock_bytes: &[u8],
) -> Result<(), ManifoldBrokerAdapterError> {
    if config.schema_id.as_str() != BROKER_ADAPTER_CONFIG_SCHEMA
        || lock.schema_id.as_str() != BROKER_PRODUCT_LOCK_SCHEMA
    {
        return Err(ManifoldBrokerAdapterError::SchemaMismatch);
    }
    let expected_mode = if lock.standalone_enabled && !lock.embedded_enabled {
        ManifoldBrokerAdapterMode::Standalone
    } else if lock.embedded_enabled && !lock.standalone_enabled {
        ManifoldBrokerAdapterMode::Embedded
    } else {
        return Err(ManifoldBrokerAdapterError::InvalidProductMode);
    };
    if config.mode != expected_mode {
        return Err(ManifoldBrokerAdapterError::ModeMismatch);
    }
    if config.product_lock_id != lock.lock_id
        || config.product_lock_fingerprint != lock.spec_fingerprint
        || !valid_sha256(&config.product_lock_sha256)
        || config.product_lock_sha256 != packaged_product_lock_sha256(packaged_product_lock_bytes)
    {
        return Err(ManifoldBrokerAdapterError::ProductLockMismatch);
    }
    if config.authority_owner_id.as_str() != RUNTIME_HOST_AUTHORITY_OWNER {
        return Err(ManifoldBrokerAdapterError::AuthorityOwnerMismatch);
    }
    Ok(())
}

fn decode_packaged_product_lock(
    packaged_product_lock_bytes: &[u8],
) -> Result<ManifoldBrokerProductLock, ManifoldBrokerAdapterError> {
    serde_json::from_slice(packaged_product_lock_bytes)
        .map_err(ManifoldBrokerAdapterError::DeserializePackagedProductLock)
}

fn validate_legacy_adapter_binding(
    schema_id: &SchemaId,
    mode: &ManifoldBrokerAdapterMode,
    product_lock_id: &DottedId,
    product_lock_fingerprint: &str,
    authority_owner_id: &DottedId,
    lock: &ManifoldBrokerProductLock,
) -> Result<(), ManifoldBrokerAdapterError> {
    if schema_id.as_str() != LEGACY_BROKER_ADAPTER_CONFIG_V1_SCHEMA
        && schema_id.as_str() != LEGACY_BROKER_ADAPTER_RECEIPT_V1_SCHEMA
    {
        return Err(ManifoldBrokerAdapterError::SchemaMismatch);
    }
    let expected_mode = if lock.standalone_enabled && !lock.embedded_enabled {
        ManifoldBrokerAdapterMode::Standalone
    } else if lock.embedded_enabled && !lock.standalone_enabled {
        ManifoldBrokerAdapterMode::Embedded
    } else {
        return Err(ManifoldBrokerAdapterError::InvalidProductMode);
    };
    if mode != &expected_mode {
        return Err(ManifoldBrokerAdapterError::ModeMismatch);
    }
    if product_lock_id != &lock.lock_id || product_lock_fingerprint != lock.spec_fingerprint {
        return Err(ManifoldBrokerAdapterError::ProductLockMismatch);
    }
    if authority_owner_id.as_str() != RUNTIME_HOST_AUTHORITY_OWNER {
        return Err(ManifoldBrokerAdapterError::AuthorityOwnerMismatch);
    }
    Ok(())
}

fn broker_adapter_migration_receipt(
    artifact: ManifoldBrokerAdapterMigrationArtifact,
    source_schema_ids: Vec<SchemaId>,
    resulting_schema_ids: Vec<SchemaId>,
    adapter_id: &DottedId,
    authority_host_id: &DottedId,
    product_lock_sha256: &str,
    runtime_host_snapshot_migrated: bool,
) -> ManifoldBrokerAdapterMigrationReceipt {
    ManifoldBrokerAdapterMigrationReceipt {
        schema_id: schema_id(BROKER_ADAPTER_MIGRATION_RECEIPT_SCHEMA),
        artifact,
        source_schema_ids,
        resulting_schema_ids,
        adapter_id: adapter_id.clone(),
        authority_host_id: authority_host_id.clone(),
        product_lock_sha256: product_lock_sha256.to_owned(),
        runtime_host_snapshot_migrated,
    }
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_host_binding(
    config: &ManifoldBrokerAdapterConfig,
    lock: &ManifoldBrokerProductLock,
    snapshot: &ManifoldRuntimeHostSnapshot,
) -> Result<(), ManifoldBrokerAdapterError> {
    if snapshot.host_id != config.authority_host_id {
        return Err(ManifoldBrokerAdapterError::AuthorityHostMismatch);
    }
    let locked = lock.command_ids.iter().collect::<BTreeSet<_>>();
    let registered = snapshot
        .commands
        .iter()
        .map(|command| &command.command_id)
        .collect::<BTreeSet<_>>();
    if locked != registered || registered.len() != snapshot.commands.len() {
        return Err(ManifoldBrokerAdapterError::CommandRegistryMismatch);
    }
    for command in &snapshot.commands {
        if command.required_lease_scope != lease_scope_for_command(&command.command_id) {
            return Err(ManifoldBrokerAdapterError::LeasePolicyMismatch);
        }
    }
    Ok(())
}

fn lease_scope_for_command(command_id: &DottedId) -> Option<DottedId> {
    let value = command_id.as_str();
    let scope = if value.starts_with("command.media.session.") {
        Some("lease.media.session")
    } else if value.starts_with("command.topology.p2p.") {
        Some("lease.topology.p2p")
    } else if value.starts_with("command.rendezvous.ble.") {
        Some("lease.rendezvous.ble")
    } else {
        None
    };
    scope.map(|value| DottedId::new(value).expect("static lease scope is valid"))
}

const fn role_for_mode(mode: &ManifoldBrokerAdapterMode) -> ManifoldBrokerAdapterRole {
    match mode {
        ManifoldBrokerAdapterMode::Standalone => ManifoldBrokerAdapterRole::ProcessTransportAdapter,
        ManifoldBrokerAdapterMode::Embedded => ManifoldBrokerAdapterRole::InProcessAdapter,
    }
}

fn schema_id(value: &str) -> SchemaId {
    SchemaId::new(value).expect("static schema id is valid")
}

/// Adapter construction failure. Command rejections remain typed host receipts.
#[derive(Debug)]
pub enum ManifoldBrokerAdapterError {
    /// Exact packaged product-lock JSON could not be decoded.
    DeserializePackagedProductLock(serde_json::Error),
    /// Legacy adapter config/receipt JSON could not be decoded.
    DeserializeLegacyArtifact(serde_json::Error),
    /// Legacy config/receipt closure was internally inconsistent.
    InvalidLegacyArtifact,
    /// Config or lock schema mismatch.
    SchemaMismatch,
    /// Product lock did not select exactly one mode.
    InvalidProductMode,
    /// Adapter mode differs from its lock.
    ModeMismatch,
    /// Lock identity or fingerprint differs.
    ProductLockMismatch,
    /// Adapter claimed authority outside the Runtime Host.
    AuthorityOwnerMismatch,
    /// Runtime Host identity differs from config.
    AuthorityHostMismatch,
    /// Runtime Host command registry differs from the product lock.
    CommandRegistryMismatch,
    /// Runtime Host lease policy differs from the shared adapter policy.
    LeasePolicyMismatch,
    /// Runtime Host snapshot failure.
    RuntimeHost(ManifoldRuntimeHostError),
}

impl fmt::Display for ManifoldBrokerAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeserializePackagedProductLock(error) => {
                write!(
                    formatter,
                    "packaged broker product lock decode failed: {error}"
                )
            }
            Self::DeserializeLegacyArtifact(error) => {
                write!(
                    formatter,
                    "legacy broker adapter artifact decode failed: {error}"
                )
            }
            Self::InvalidLegacyArtifact => {
                write!(formatter, "legacy broker adapter artifact is inconsistent")
            }
            Self::SchemaMismatch => write!(formatter, "broker adapter schema mismatch"),
            Self::InvalidProductMode => write!(formatter, "broker product mode is not exclusive"),
            Self::ModeMismatch => write!(formatter, "broker adapter mode differs from lock"),
            Self::ProductLockMismatch => write!(formatter, "broker adapter lock binding mismatch"),
            Self::AuthorityOwnerMismatch => write!(formatter, "broker adapter claimed authority"),
            Self::AuthorityHostMismatch => write!(formatter, "runtime host identity mismatch"),
            Self::CommandRegistryMismatch => {
                write!(formatter, "runtime host command registry mismatch")
            }
            Self::LeasePolicyMismatch => write!(formatter, "runtime host lease policy mismatch"),
            Self::RuntimeHost(error) => write!(formatter, "runtime host error: {error}"),
        }
    }
}

impl std::error::Error for ManifoldBrokerAdapterError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::DeserializePackagedProductLock(error)
            | Self::DeserializeLegacyArtifact(error) => Some(error),
            Self::RuntimeHost(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusty_manifold_broker_product::{
        resolve_broker_product, ManifoldBrokerFeature, ManifoldBrokerProductSpec,
        BROKER_PRODUCT_SPEC_SCHEMA,
    };
    use rusty_manifold_runtime_host::{
        ManifoldRuntimeDispatchOutcome, ManifoldRuntimeRejectionReason, HOST_COMMAND_REQUEST_SCHEMA,
    };

    fn id(value: &str) -> DottedId {
        DottedId::new(value).expect("test id")
    }

    fn lock(mode: ManifoldBrokerAdapterMode) -> ManifoldBrokerProductLock {
        resolve_broker_product(&ManifoldBrokerProductSpec {
            schema_id: schema_id(BROKER_PRODUCT_SPEC_SCHEMA),
            product_id: id("broker.camera.parity"),
            standalone_enabled: mode == ManifoldBrokerAdapterMode::Standalone,
            embedded_enabled: mode == ManifoldBrokerAdapterMode::Embedded,
            requested_features: vec![ManifoldBrokerFeature::CameraMedia],
        })
        .expect("product lock")
    }

    fn config(
        mode: ManifoldBrokerAdapterMode,
        lock: &ManifoldBrokerProductLock,
    ) -> ManifoldBrokerAdapterConfig {
        ManifoldBrokerAdapterConfig {
            schema_id: schema_id(BROKER_ADAPTER_CONFIG_SCHEMA),
            adapter_id: id(match mode {
                ManifoldBrokerAdapterMode::Standalone => "adapter.broker.standalone",
                ManifoldBrokerAdapterMode::Embedded => "adapter.broker.embedded",
            }),
            mode,
            product_lock_id: lock.lock_id.clone(),
            product_lock_fingerprint: lock.spec_fingerprint.clone(),
            product_lock_sha256: packaged_product_lock_sha256(
                &serde_json::to_vec(lock).expect("serialize lock"),
            ),
            authority_host_id: id("host.broker.parity"),
            authority_owner_id: id(RUNTIME_HOST_AUTHORITY_OWNER),
        }
    }

    fn lock_bytes(lock: &ManifoldBrokerProductLock) -> Vec<u8> {
        serde_json::to_vec(lock).expect("serialize packaged lock")
    }

    fn lease() -> ManifoldRuntimeLease {
        ManifoldRuntimeLease {
            lease_id: id("lease.media.session.client"),
            scope: id("lease.media.session"),
            holder_id: id("client.parity"),
            expires_at_ms: 60_000,
        }
    }

    fn request(command_id: &str, lease_id: Option<&str>) -> ManifoldRuntimeCommandRequest {
        ManifoldRuntimeCommandRequest {
            schema_id: schema_id(HOST_COMMAND_REQUEST_SCHEMA),
            request_id: id("request.broker.parity"),
            expected_authority_revision: Revision::new(1).expect("revision"),
            requester_id: id("client.parity"),
            command_id: id(command_id),
            lease_id: lease_id.map(id),
            params_digest: None,
            issued_at_ms: 1_000,
            expires_at_ms: 10_000,
        }
    }

    fn pair() -> (ManifoldBrokerAdapter, ManifoldBrokerAdapter) {
        let standalone_lock = lock(ManifoldBrokerAdapterMode::Standalone);
        let embedded_lock = lock(ManifoldBrokerAdapterMode::Embedded);
        let standalone_bytes = lock_bytes(&standalone_lock);
        let embedded_bytes = lock_bytes(&embedded_lock);
        let standalone = ManifoldBrokerAdapter::new(
            config(ManifoldBrokerAdapterMode::Standalone, &standalone_lock),
            &standalone_bytes,
            vec![lease()],
        )
        .expect("standalone");
        let embedded = ManifoldBrokerAdapter::new(
            config(ManifoldBrokerAdapterMode::Embedded, &embedded_lock),
            &embedded_bytes,
            vec![lease()],
        )
        .expect("embedded");
        (standalone, embedded)
    }

    #[test]
    fn standalone_and_embedded_apply_through_identical_host_decisions() {
        let (mut standalone, mut embedded) = pair();
        let request = request(
            "command.media.session.start",
            Some("lease.media.session.client"),
        );
        let standalone_receipt = standalone.handle_command(&request, 2_000);
        let embedded_receipt = embedded.handle_command(&request, 2_000);
        assert_eq!(standalone_receipt.dispatch, embedded_receipt.dispatch);
        assert_eq!(standalone_receipt.application, embedded_receipt.application);
        assert!(standalone_receipt.application.applied);
        assert_eq!(standalone.host_snapshot().authority_revision.get(), 2);
        assert_eq!(embedded.host_snapshot().authority_revision.get(), 2);
        assert_eq!(
            standalone_receipt.authority_owner_id.as_str(),
            RUNTIME_HOST_AUTHORITY_OWNER
        );
        assert_eq!(
            embedded_receipt.authority_owner_id.as_str(),
            RUNTIME_HOST_AUTHORITY_OWNER
        );
    }

    #[test]
    fn unknown_and_unleased_commands_reject_without_state_advance_in_both_modes() {
        for mut adapter in [pair().0, pair().1] {
            let unknown = adapter.handle_command(&request("command.unknown", None), 2_000);
            assert_eq!(
                unknown.dispatch.outcome,
                ManifoldRuntimeDispatchOutcome::Rejected
            );
            assert_eq!(
                unknown.application.rejection_reason,
                Some(ManifoldRuntimeRejectionReason::UnknownCommand)
            );
            assert_eq!(adapter.host_snapshot().authority_revision.get(), 1);
        }
        for mut adapter in [pair().0, pair().1] {
            let unleased =
                adapter.handle_command(&request("command.media.session.start", None), 2_000);
            assert_eq!(
                unleased.application.rejection_reason,
                Some(ManifoldRuntimeRejectionReason::MissingLease)
            );
            assert_eq!(adapter.host_snapshot().authority_revision.get(), 1);
        }
    }

    #[test]
    fn adapter_mode_lock_and_authority_labels_fail_closed() {
        let standalone_lock = lock(ManifoldBrokerAdapterMode::Standalone);
        let standalone_bytes = lock_bytes(&standalone_lock);
        let mut mismatched = config(ManifoldBrokerAdapterMode::Standalone, &standalone_lock);
        mismatched.mode = ManifoldBrokerAdapterMode::Embedded;
        assert!(matches!(
            ManifoldBrokerAdapter::new(mismatched, &standalone_bytes, Vec::new()),
            Err(ManifoldBrokerAdapterError::ModeMismatch)
        ));
        let mut authority = config(ManifoldBrokerAdapterMode::Standalone, &standalone_lock);
        authority.authority_owner_id = id("adapter.claims.authority");
        assert!(matches!(
            ManifoldBrokerAdapter::new(authority, &standalone_bytes, Vec::new()),
            Err(ManifoldBrokerAdapterError::AuthorityOwnerMismatch)
        ));

        let standalone_lock = lock(ManifoldBrokerAdapterMode::Standalone);
        let standalone_bytes = lock_bytes(&standalone_lock);
        let mut malformed_sha = config(ManifoldBrokerAdapterMode::Standalone, &standalone_lock);
        malformed_sha.product_lock_sha256 = "sha256:not-a-packaged-lock-digest".to_owned();
        assert!(matches!(
            ManifoldBrokerAdapter::new(malformed_sha, &standalone_bytes, Vec::new()),
            Err(ManifoldBrokerAdapterError::ProductLockMismatch)
        ));
    }

    #[test]
    fn restart_revalidates_exact_lock_registry_and_preserves_replay_state() {
        let (mut standalone, _) = pair();
        let request = request(
            "command.media.session.start",
            Some("lease.media.session.client"),
        );
        let receipt = standalone.handle_command(&request, 2_000);
        assert!(receipt.application.applied);
        let json = standalone.snapshot_json().expect("snapshot");
        let lock = lock(ManifoldBrokerAdapterMode::Standalone);
        let packaged_lock = lock_bytes(&lock);
        let restarted = ManifoldBrokerAdapter::restart_from_json(
            config(ManifoldBrokerAdapterMode::Standalone, &lock),
            &packaged_lock,
            &json,
        )
        .expect("restart");
        assert_eq!(restarted.host_snapshot().authority_revision.get(), 2);
        assert_eq!(
            restarted.host_snapshot().applied_request_ids,
            vec![request.request_id]
        );
    }

    #[test]
    fn committed_adapter_receipts_preserve_host_decision_parity() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("fixtures/broker-adapter");
        for suffix in ["applied", "unknown-rejected", "unleased-rejected"] {
            let standalone: ManifoldBrokerAdapterReceipt = serde_json::from_str(
                &std::fs::read_to_string(root.join(format!("standalone-{suffix}.json")))
                    .expect("standalone fixture"),
            )
            .expect("standalone receipt");
            let embedded: ManifoldBrokerAdapterReceipt = serde_json::from_str(
                &std::fs::read_to_string(root.join(format!("embedded-{suffix}.json")))
                    .expect("embedded fixture"),
            )
            .expect("embedded receipt");
            assert_eq!(standalone.dispatch, embedded.dispatch, "{suffix}");
            assert_eq!(standalone.application, embedded.application, "{suffix}");
            assert_eq!(standalone.authority_owner_id, embedded.authority_owner_id);
            assert_eq!(
                standalone.authority_owner_id.as_str(),
                RUNTIME_HOST_AUTHORITY_OWNER
            );
        }
    }

    #[test]
    fn legacy_v1_config_receipt_and_restart_migrate_with_exact_packaged_bytes() {
        let lock_bytes = include_bytes!(
            "../../../fixtures/broker-adapter/legacy-v1-standalone-product-lock.json"
        );
        let config_json =
            include_str!("../../../fixtures/broker-adapter/legacy-v1-standalone-config.json");
        let receipt_json =
            include_str!("../../../fixtures/broker-adapter/legacy-v1-standalone-applied.json");
        let snapshot_json = include_str!(
            "../../../fixtures/broker-adapter/legacy-v1-standalone-runtime-host-snapshot.json"
        );
        let exact_sha = packaged_product_lock_sha256(lock_bytes);

        let (config, config_receipt) =
            migrate_legacy_broker_adapter_config(config_json, lock_bytes)
                .expect("legacy config migration");
        assert_eq!(config.schema_id.as_str(), BROKER_ADAPTER_CONFIG_SCHEMA);
        assert_eq!(config.product_lock_sha256, exact_sha);
        assert_eq!(
            config_receipt.artifact,
            ManifoldBrokerAdapterMigrationArtifact::Config
        );
        assert!(!config_receipt.runtime_host_snapshot_migrated);

        let (receipt, evidence_receipt) =
            migrate_legacy_broker_adapter_receipt(receipt_json, lock_bytes)
                .expect("legacy receipt migration");
        assert_eq!(receipt.schema_id.as_str(), BROKER_ADAPTER_RECEIPT_SCHEMA);
        assert_eq!(receipt.product_lock_sha256, exact_sha);
        assert_eq!(
            receipt.dispatch.authority_host_id,
            receipt.authority_host_id
        );
        assert_eq!(
            receipt.application.authority_host_id,
            receipt.authority_host_id
        );
        assert_eq!(
            evidence_receipt.artifact,
            ManifoldBrokerAdapterMigrationArtifact::Receipt
        );

        let (adapter, restart_receipt) =
            ManifoldBrokerAdapter::restart_from_legacy_json(config_json, lock_bytes, snapshot_json)
                .expect("legacy adapter restart");
        assert_eq!(adapter.config().product_lock_sha256, exact_sha);
        assert_eq!(
            adapter.host_snapshot().schema_id.as_str(),
            HOST_SNAPSHOT_SCHEMA
        );
        assert_eq!(
            restart_receipt.artifact,
            ManifoldBrokerAdapterMigrationArtifact::Restart
        );
        assert!(restart_receipt.runtime_host_snapshot_migrated);

        let damaged = config_json.replace("fnv1a64-ad70739bf6657364", "fnv1a64-0000000000000000");
        assert!(migrate_legacy_broker_adapter_config(&damaged, lock_bytes).is_err());
        let damaged = receipt_json.replacen(
            "\"dispatch_id\": \"dispatch.runtime.request.broker.applied\"",
            "\"dispatch_id\": \"dispatch.runtime.forged\"",
            1,
        );
        assert!(migrate_legacy_broker_adapter_receipt(&damaged, lock_bytes).is_err());
    }
}
