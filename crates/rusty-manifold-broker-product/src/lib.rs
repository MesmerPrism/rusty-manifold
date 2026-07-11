//! Exact, deterministic broker product specifications and locks.

use rusty_manifold_model::{DottedId, SchemaId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Broker product specification schema.
pub const BROKER_PRODUCT_SPEC_SCHEMA: &str = "rusty.manifold.broker.product_spec.v1";
/// Broker product lock schema.
pub const BROKER_PRODUCT_LOCK_SCHEMA: &str = "rusty.manifold.broker.product_lock.v1";

/// Optional broker feature families.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldBrokerFeature {
    /// Camera/media session descriptors.
    CameraMedia,
    /// Direct peer-to-peer topology descriptors.
    DirectP2p,
    /// Authenticated BLE rendezvous descriptors.
    BleRendezvous,
}

/// Platform-neutral permission capabilities resolved by Manifold.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldBrokerPermission {
    /// Network client/server access.
    Internet,
    /// Camera capture.
    Camera,
    /// Nearby Wi-Fi discovery/group operations.
    NearbyWifiDevices,
    /// Wi-Fi state mutation.
    ChangeWifiState,
    /// Wi-Fi state observation.
    AccessWifiState,
    /// BLE scanning.
    BluetoothScan,
    /// BLE connection/GATT use.
    BluetoothConnect,
    /// BLE advertising.
    BluetoothAdvertise,
}

/// Requested broker product composition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerProductSpec {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Stable product identity.
    pub product_id: DottedId,
    /// Standalone background product selection.
    pub standalone_enabled: bool,
    /// Embedded in-process product selection.
    pub embedded_enabled: bool,
    /// Explicit optional feature families.
    pub requested_features: Vec<ManifoldBrokerFeature>,
}

/// Fully resolved immutable product closure.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerProductLock {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Stable lock identity.
    pub lock_id: DottedId,
    /// Product identity.
    pub product_id: DottedId,
    /// Exactly-one standalone selection.
    pub standalone_enabled: bool,
    /// Exactly-one embedded selection.
    pub embedded_enabled: bool,
    /// Sorted feature closure.
    pub features: Vec<ManifoldBrokerFeature>,
    /// Sorted command closure.
    pub command_ids: Vec<DottedId>,
    /// Sorted stream closure.
    pub stream_ids: Vec<DottedId>,
    /// Sorted module closure.
    pub module_ids: Vec<DottedId>,
    /// Sorted permission closure.
    pub permissions: Vec<ManifoldBrokerPermission>,
    /// Deterministic fingerprint of the selected spec and closure.
    pub spec_fingerprint: String,
}

/// Product resolution failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManifoldBrokerProductError {
    /// Specification schema is wrong.
    SchemaMismatch,
    /// Standalone and embedded must be exactly-one.
    InvalidRuntimeMode,
    /// Feature list contains duplicates.
    DuplicateFeature,
    /// Lock differs from a fresh exact resolution.
    StaleOrExpandedLock,
}

/// Resolves one product spec into an exact deterministic lock.
pub fn resolve_broker_product(
    spec: &ManifoldBrokerProductSpec,
) -> Result<ManifoldBrokerProductLock, ManifoldBrokerProductError> {
    if spec.schema_id.as_str() != BROKER_PRODUCT_SPEC_SCHEMA {
        return Err(ManifoldBrokerProductError::SchemaMismatch);
    }
    if spec.standalone_enabled == spec.embedded_enabled {
        return Err(ManifoldBrokerProductError::InvalidRuntimeMode);
    }
    let feature_set = spec
        .requested_features
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if feature_set.len() != spec.requested_features.len() {
        return Err(ManifoldBrokerProductError::DuplicateFeature);
    }

    let mut commands = ids(["command.peer.status.get", "command.session.list"]);
    let mut streams = ids(["stream.peer.status"]);
    let mut modules = ids(["module.runtime.host"]);
    let mut permissions = BTreeSet::from([ManifoldBrokerPermission::Internet]);

    for feature in &feature_set {
        match feature {
            ManifoldBrokerFeature::CameraMedia => {
                commands.extend(ids([
                    "command.media.session.start",
                    "command.media.session.stop",
                ]));
                streams.extend(ids(["stream.media.video"]));
                modules.extend(ids(["module.media.camera"]));
                permissions.insert(ManifoldBrokerPermission::Camera);
            }
            ManifoldBrokerFeature::DirectP2p => {
                commands.extend(ids([
                    "command.topology.p2p.open",
                    "command.topology.p2p.close",
                ]));
                streams.extend(ids(["stream.topology.status"]));
                modules.extend(ids(["module.transport.direct_p2p"]));
                permissions.extend([
                    ManifoldBrokerPermission::NearbyWifiDevices,
                    ManifoldBrokerPermission::ChangeWifiState,
                    ManifoldBrokerPermission::AccessWifiState,
                ]);
            }
            ManifoldBrokerFeature::BleRendezvous => {
                commands.extend(ids([
                    "command.rendezvous.ble.start",
                    "command.rendezvous.ble.stop",
                ]));
                streams.extend(ids(["stream.rendezvous.status"]));
                modules.extend(ids(["module.rendezvous.ble"]));
                permissions.extend([
                    ManifoldBrokerPermission::BluetoothScan,
                    ManifoldBrokerPermission::BluetoothConnect,
                    ManifoldBrokerPermission::BluetoothAdvertise,
                ]);
            }
        }
    }

    let features = feature_set.into_iter().collect::<Vec<_>>();
    let command_ids = commands.into_iter().collect::<Vec<_>>();
    let stream_ids = streams.into_iter().collect::<Vec<_>>();
    let module_ids = modules.into_iter().collect::<Vec<_>>();
    let permissions = permissions.into_iter().collect::<Vec<_>>();
    let fingerprint = fingerprint(
        spec,
        &features,
        &command_ids,
        &stream_ids,
        &module_ids,
        &permissions,
    );
    Ok(ManifoldBrokerProductLock {
        schema_id: SchemaId::new(BROKER_PRODUCT_LOCK_SCHEMA).expect("schema"),
        lock_id: DottedId::new(format!("lock.{}", spec.product_id.as_str())).expect("lock id"),
        product_id: spec.product_id.clone(),
        standalone_enabled: spec.standalone_enabled,
        embedded_enabled: spec.embedded_enabled,
        features,
        command_ids,
        stream_ids,
        module_ids,
        permissions,
        spec_fingerprint: fingerprint,
    })
}

/// Rejects stale, expanded, or otherwise non-exact locks.
pub fn validate_broker_product_lock(
    spec: &ManifoldBrokerProductSpec,
    lock: &ManifoldBrokerProductLock,
) -> Result<(), ManifoldBrokerProductError> {
    let expected = resolve_broker_product(spec)?;
    if lock == &expected {
        Ok(())
    } else {
        Err(ManifoldBrokerProductError::StaleOrExpandedLock)
    }
}

fn ids<const N: usize>(values: [&str; N]) -> BTreeSet<DottedId> {
    values
        .into_iter()
        .map(|value| DottedId::new(value).expect("static id"))
        .collect()
}

fn fingerprint(
    spec: &ManifoldBrokerProductSpec,
    features: &[ManifoldBrokerFeature],
    commands: &[DottedId],
    streams: &[DottedId],
    modules: &[DottedId],
    permissions: &[ManifoldBrokerPermission],
) -> String {
    let canonical = format!(
        "{}|{}|{}|{:?}|{:?}|{:?}|{:?}|{:?}",
        spec.product_id,
        spec.standalone_enabled,
        spec.embedded_enabled,
        features,
        commands,
        streams,
        modules,
        permissions
    );
    let hash = canonical
        .bytes()
        .fold(0xcbf2_9ce4_8422_2325_u64, |value, byte| {
            (value ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
        });
    format!("fnv1a64-{hash:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(name: &str) -> ManifoldBrokerProductSpec {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(format!("fixtures/broker-product/{name}.json"));
        serde_json::from_str(&std::fs::read_to_string(root).expect("fixture")).expect("spec")
    }

    #[test]
    fn base_is_camera_p2p_and_ble_free() {
        let lock = resolve_broker_product(&spec("base-standalone")).expect("lock");
        assert_eq!(lock.permissions, vec![ManifoldBrokerPermission::Internet]);
        assert_eq!(
            lock.module_ids,
            ids(["module.runtime.host"]).into_iter().collect::<Vec<_>>()
        );
    }

    #[test]
    fn optional_profiles_resolve_independently_and_exactly() {
        let camera = resolve_broker_product(&spec("camera-embedded")).expect("camera");
        assert!(camera
            .permissions
            .contains(&ManifoldBrokerPermission::Camera));
        assert!(!camera
            .permissions
            .contains(&ManifoldBrokerPermission::NearbyWifiDevices));
        assert!(!camera
            .permissions
            .contains(&ManifoldBrokerPermission::BluetoothScan));
        let p2p = resolve_broker_product(&spec("direct-p2p-standalone")).expect("p2p");
        assert!(p2p
            .permissions
            .contains(&ManifoldBrokerPermission::NearbyWifiDevices));
        assert!(!p2p.permissions.contains(&ManifoldBrokerPermission::Camera));
        let ble = resolve_broker_product(&spec("ble-embedded")).expect("ble");
        assert!(ble
            .permissions
            .contains(&ManifoldBrokerPermission::BluetoothAdvertise));
        assert!(!ble.permissions.contains(&ManifoldBrokerPermission::Camera));
    }

    #[test]
    fn runtime_mode_duplicates_and_stale_or_union_locks_fail_closed() {
        for name in ["invalid-both-modes", "invalid-no-mode"] {
            assert_eq!(
                resolve_broker_product(&spec(name)),
                Err(ManifoldBrokerProductError::InvalidRuntimeMode)
            );
        }
        let base = spec("base-standalone");
        let mut lock = resolve_broker_product(&base).expect("lock");
        lock.permissions.push(ManifoldBrokerPermission::Camera);
        assert_eq!(
            validate_broker_product_lock(&base, &lock),
            Err(ManifoldBrokerProductError::StaleOrExpandedLock)
        );
        let mut changed = base.clone();
        changed
            .requested_features
            .push(ManifoldBrokerFeature::CameraMedia);
        let original = resolve_broker_product(&base).expect("lock");
        assert_eq!(
            validate_broker_product_lock(&changed, &original),
            Err(ManifoldBrokerProductError::StaleOrExpandedLock)
        );
    }

    #[test]
    fn committed_locks_match_fresh_resolution() {
        for name in [
            "base-standalone",
            "camera-embedded",
            "direct-p2p-standalone",
            "ble-embedded",
        ] {
            let product = spec(name);
            let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join(format!("fixtures/broker-product/{name}.lock.json"));
            let lock: ManifoldBrokerProductLock =
                serde_json::from_str(&std::fs::read_to_string(root).expect("lock fixture"))
                    .expect("lock");
            assert_eq!(
                validate_broker_product_lock(&product, &lock),
                Ok(()),
                "{name}"
            );
        }
    }
}
