//! Standalone and embedded broker adapters over one Manifold Runtime Host.

use rusty_manifold_broker_product::{ManifoldBrokerProductLock, BROKER_PRODUCT_LOCK_SCHEMA};
use rusty_manifold_model::{DottedId, Revision, SchemaId};
use rusty_manifold_runtime_host::{
    ManifoldRuntimeApplicationReceipt, ManifoldRuntimeCommandDescriptor,
    ManifoldRuntimeCommandRequest, ManifoldRuntimeDispatchReceipt, ManifoldRuntimeHost,
    ManifoldRuntimeHostError, ManifoldRuntimeHostSnapshot, ManifoldRuntimeLease,
    HOST_SNAPSHOT_SCHEMA,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

/// Broker adapter configuration schema.
pub const BROKER_ADAPTER_CONFIG_SCHEMA: &str = "rusty.manifold.broker.adapter_config.v1";
/// Broker adapter receipt schema.
pub const BROKER_ADAPTER_RECEIPT_SCHEMA: &str = "rusty.manifold.broker.adapter_receipt.v1";
/// Sole accepted-state and command-decision owner.
pub const RUNTIME_HOST_AUTHORITY_OWNER: &str = "module.runtime.host";

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
    /// Runtime Host identity that owns accepted state.
    pub authority_host_id: DottedId,
    /// Runtime Host module that owns the decision.
    pub authority_owner_id: DottedId,
    /// Host review receipt.
    pub dispatch: ManifoldRuntimeDispatchReceipt,
    /// Host application/rejection receipt.
    pub application: ManifoldRuntimeApplicationReceipt,
}

/// Shared adapter implementation. Mode changes placement labels only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldBrokerAdapter {
    config: ManifoldBrokerAdapterConfig,
    product_lock: ManifoldBrokerProductLock,
    host: ManifoldRuntimeHost,
}

impl ManifoldBrokerAdapter {
    /// Creates a new host whose command registry is derived exactly from the lock.
    pub fn new(
        config: ManifoldBrokerAdapterConfig,
        product_lock: ManifoldBrokerProductLock,
        leases: Vec<ManifoldRuntimeLease>,
    ) -> Result<Self, ManifoldBrokerAdapterError> {
        validate_config_lock(&config, &product_lock)?;
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
        product_lock: ManifoldBrokerProductLock,
        snapshot_json: &str,
    ) -> Result<Self, ManifoldBrokerAdapterError> {
        validate_config_lock(&config, &product_lock)?;
        let host = ManifoldRuntimeHost::restart_from_json(snapshot_json)
            .map_err(ManifoldBrokerAdapterError::RuntimeHost)?;
        validate_host_binding(&config, &product_lock, host.snapshot())?;
        Ok(Self {
            config,
            product_lock,
            host,
        })
    }

    /// Reviews then applies through the sole Runtime Host path.
    pub fn handle_command(
        &mut self,
        request: &ManifoldRuntimeCommandRequest,
        now_ms: u64,
    ) -> ManifoldBrokerAdapterReceipt {
        let dispatch = self.host.review_command(request, now_ms);
        let application = self.host.apply_dispatch(request, &dispatch);
        ManifoldBrokerAdapterReceipt {
            schema_id: schema_id(BROKER_ADAPTER_RECEIPT_SCHEMA),
            adapter_id: self.config.adapter_id.clone(),
            mode: self.config.mode.clone(),
            adapter_role: role_for_mode(&self.config.mode),
            product_lock_id: self.product_lock.lock_id.clone(),
            product_lock_fingerprint: self.product_lock.spec_fingerprint.clone(),
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
        audit_events: Vec::new(),
    };
    validate_host_binding(config, lock, &snapshot)?;
    Ok(snapshot)
}

fn validate_config_lock(
    config: &ManifoldBrokerAdapterConfig,
    lock: &ManifoldBrokerProductLock,
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
    {
        return Err(ManifoldBrokerAdapterError::ProductLockMismatch);
    }
    if config.authority_owner_id.as_str() != RUNTIME_HOST_AUTHORITY_OWNER {
        return Err(ManifoldBrokerAdapterError::AuthorityOwnerMismatch);
    }
    Ok(())
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

impl std::error::Error for ManifoldBrokerAdapterError {}

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

    fn request(command_id: &str, lease_id: Option<&str>) -> ManifoldRuntimeCommandRequest {
        ManifoldRuntimeCommandRequest {
            schema_id: schema_id(HOST_COMMAND_REQUEST_SCHEMA),
            request_id: id("request.broker.parity"),
            expected_authority_revision: Revision::new(1).expect("revision"),
            requester_id: id("client.parity"),
            command_id: id(command_id),
            lease_id: lease_id.map(id),
            issued_at_ms: 1_000,
            expires_at_ms: 10_000,
        }
    }

    fn pair() -> (ManifoldBrokerAdapter, ManifoldBrokerAdapter) {
        let standalone_lock = lock(ManifoldBrokerAdapterMode::Standalone);
        let embedded_lock = lock(ManifoldBrokerAdapterMode::Embedded);
        let standalone = ManifoldBrokerAdapter::new(
            config(ManifoldBrokerAdapterMode::Standalone, &standalone_lock),
            standalone_lock,
            vec![lease()],
        )
        .expect("standalone");
        let embedded = ManifoldBrokerAdapter::new(
            config(ManifoldBrokerAdapterMode::Embedded, &embedded_lock),
            embedded_lock,
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
        let mut mismatched = config(ManifoldBrokerAdapterMode::Standalone, &standalone_lock);
        mismatched.mode = ManifoldBrokerAdapterMode::Embedded;
        assert!(matches!(
            ManifoldBrokerAdapter::new(mismatched, standalone_lock.clone(), Vec::new()),
            Err(ManifoldBrokerAdapterError::ModeMismatch)
        ));
        let mut authority = config(ManifoldBrokerAdapterMode::Standalone, &standalone_lock);
        authority.authority_owner_id = id("adapter.claims.authority");
        assert!(matches!(
            ManifoldBrokerAdapter::new(authority, standalone_lock, Vec::new()),
            Err(ManifoldBrokerAdapterError::AuthorityOwnerMismatch)
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
        let restarted = ManifoldBrokerAdapter::restart_from_json(
            config(ManifoldBrokerAdapterMode::Standalone, &lock),
            lock,
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
}
