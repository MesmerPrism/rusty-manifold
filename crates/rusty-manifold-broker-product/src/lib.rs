//! Exact, deterministic broker product specifications and locks.

use rusty_manifold_model::{DottedId, SchemaId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Broker product specification schema.
pub const BROKER_PRODUCT_SPEC_SCHEMA: &str = "rusty.manifold.broker.product_spec.v1";
/// Broker product lock schema.
pub const BROKER_PRODUCT_LOCK_SCHEMA: &str = "rusty.manifold.broker.product_lock.v1";

const QCL100_LEGACY_CAMERA_P2P_PRODUCT_ID: &str = "broker.legacy_camera_p2p.standalone";
const QCL100_REMOTE_CAMERA_COMMANDS: [&str; 4] = [
    "command.remote_camera.get_status",
    "command.remote_camera.start_receiver",
    "command.remote_camera.start_sender",
    "command.remote_camera.stop",
];

/// Optional broker feature families.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldBrokerFeature {
    /// Durable standalone Connection Hub authority with LAN/WebSocket control
    /// adapters but no BLE, P2P, camera, or media-plane authority.
    ConnectionHub,
    /// Generic media-session descriptors without capture-device authority.
    MediaSession,
    /// Camera capture adapter layered over generic media sessions.
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
    /// User-visible background-service notification surface.
    UserNotifications,
    /// Long-lived background execution surface.
    BackgroundService,
    /// Background data synchronization surface.
    BackgroundDataSync,
    /// Background camera capture surface.
    BackgroundCamera,
    /// Camera capture.
    Camera,
    /// Network-state observation.
    NetworkStateObservation,
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
///
/// # Errors
///
/// Rejects an unsupported schema, a zero-or-two runtime-mode selection, or a
/// duplicate requested feature.
///
/// # Panics
///
/// Panics only if this crate's static schema or derived lock-id literals stop
/// satisfying their own identifier grammar.
pub fn resolve_broker_product(
    spec: &ManifoldBrokerProductSpec,
) -> Result<ManifoldBrokerProductLock, ManifoldBrokerProductError> {
    if spec.schema_id.as_str() != BROKER_PRODUCT_SPEC_SCHEMA {
        return Err(ManifoldBrokerProductError::SchemaMismatch);
    }
    if spec.standalone_enabled == spec.embedded_enabled {
        return Err(ManifoldBrokerProductError::InvalidRuntimeMode);
    }
    let requested_feature_set = spec
        .requested_features
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if requested_feature_set.len() != spec.requested_features.len() {
        return Err(ManifoldBrokerProductError::DuplicateFeature);
    }
    let mut feature_set = requested_feature_set;
    if feature_set.contains(&ManifoldBrokerFeature::CameraMedia) {
        feature_set.insert(ManifoldBrokerFeature::MediaSession);
    }

    let (commands, streams, modules, permissions) = resolve_feature_closure(spec, &feature_set);

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
///
/// # Errors
///
/// Returns the underlying specification error or
/// [`ManifoldBrokerProductError::StaleOrExpandedLock`] when any lock field
/// differs from a fresh exact resolution.
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

fn resolve_feature_closure(
    spec: &ManifoldBrokerProductSpec,
    feature_set: &BTreeSet<ManifoldBrokerFeature>,
) -> (
    BTreeSet<DottedId>,
    BTreeSet<DottedId>,
    BTreeSet<DottedId>,
    BTreeSet<ManifoldBrokerPermission>,
) {
    let mut commands = ids(["command.peer.status.get", "command.session.list"]);
    let mut streams = ids(["stream.peer.status"]);
    let mut modules = ids(["module.runtime.host"]);
    let mut permissions = BTreeSet::from([ManifoldBrokerPermission::Internet]);
    if spec.standalone_enabled {
        permissions.extend([
            ManifoldBrokerPermission::UserNotifications,
            ManifoldBrokerPermission::BackgroundService,
            ManifoldBrokerPermission::BackgroundDataSync,
        ]);
    }
    for feature in feature_set {
        match feature {
            ManifoldBrokerFeature::ConnectionHub => {
                commands.extend(ids([
                    "command.connection_hub.status.get",
                    "command.connection_hub.controller.trust",
                    "command.connection_hub.controller.forget",
                    "command.connection_hub.session.open",
                    "command.connection_hub.session.revoke",
                    "command.connection_hub.provider.register",
                    "command.connection_hub.provider.unregister",
                    "command.connection_hub.surface.register",
                    "command.connection_hub.surface.unregister",
                    "command.connection_hub.surface_lease.acquire",
                    "command.connection_hub.surface_lease.release",
                    "command.connection_hub.surface_command.authorize",
                    "command.connection_hub.transport.replace",
                    "command.connection_hub.expire",
                    "command.connection_hub.surface.list",
                ]));
                streams.extend(ids(["stream.connection_hub.status"]));
                modules.extend(ids([
                    "module.connection_hub.authority",
                    "module.transport.websocket",
                ]));
                permissions.insert(ManifoldBrokerPermission::NetworkStateObservation);
            }
            ManifoldBrokerFeature::MediaSession => {
                commands.extend(ids([
                    "command.media.session.start",
                    "command.media.session.stop",
                ]));
                streams.extend(ids(["stream.media.video"]));
                modules.extend(ids(["module.media.session"]));
            }
            ManifoldBrokerFeature::CameraMedia => {
                modules.extend(ids(["module.media.camera"]));
                permissions.insert(ManifoldBrokerPermission::Camera);
                if spec.standalone_enabled {
                    permissions.insert(ManifoldBrokerPermission::BackgroundCamera);
                }
            }
            ManifoldBrokerFeature::DirectP2p => {
                commands.extend(ids([
                    "command.topology.p2p.open",
                    "command.topology.p2p.close",
                ]));
                streams.extend(ids(["stream.topology.status"]));
                modules.extend(ids(["module.transport.direct_p2p"]));
                permissions.extend([
                    ManifoldBrokerPermission::NetworkStateObservation,
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
    if is_qcl100_legacy_camera_p2p_product(spec, feature_set) {
        commands.extend(ids(QCL100_REMOTE_CAMERA_COMMANDS));
    }
    (commands, streams, modules, permissions)
}

fn is_qcl100_legacy_camera_p2p_product(
    spec: &ManifoldBrokerProductSpec,
    feature_set: &BTreeSet<ManifoldBrokerFeature>,
) -> bool {
    spec.product_id.as_str() == QCL100_LEGACY_CAMERA_P2P_PRODUCT_ID
        && spec.standalone_enabled
        && !spec.embedded_enabled
        && feature_set.len() == 3
        && feature_set.contains(&ManifoldBrokerFeature::MediaSession)
        && feature_set.contains(&ManifoldBrokerFeature::CameraMedia)
        && feature_set.contains(&ManifoldBrokerFeature::DirectP2p)
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
        assert_eq!(
            lock.permissions,
            vec![
                ManifoldBrokerPermission::Internet,
                ManifoldBrokerPermission::UserNotifications,
                ManifoldBrokerPermission::BackgroundService,
                ManifoldBrokerPermission::BackgroundDataSync,
            ]
        );
        assert_eq!(
            lock.module_ids,
            ids(["module.runtime.host"]).into_iter().collect::<Vec<_>>()
        );
    }

    #[test]
    fn generic_media_session_has_no_camera_or_peer_transport_permissions() {
        let media = resolve_broker_product(&spec("media-session-standalone")).expect("media");
        assert!(media
            .features
            .contains(&ManifoldBrokerFeature::MediaSession));
        assert!(!media.features.contains(&ManifoldBrokerFeature::CameraMedia));
        assert!(media
            .module_ids
            .contains(&DottedId::new("module.media.session").expect("id")));
        assert!(!media
            .permissions
            .contains(&ManifoldBrokerPermission::Camera));
        assert!(!media
            .permissions
            .contains(&ManifoldBrokerPermission::NearbyWifiDevices));
        assert!(!media
            .permissions
            .contains(&ManifoldBrokerPermission::BluetoothScan));
    }

    #[test]
    fn optional_profiles_resolve_independently_and_exactly() {
        let hub = resolve_broker_product(&spec("connection-hub-standalone")).expect("hub");
        assert!(hub.features.contains(&ManifoldBrokerFeature::ConnectionHub));
        assert!(hub
            .module_ids
            .contains(&DottedId::new("module.connection_hub.authority").expect("id")));
        assert!(hub
            .permissions
            .contains(&ManifoldBrokerPermission::NetworkStateObservation));
        assert!(!hub.permissions.contains(&ManifoldBrokerPermission::Camera));
        assert!(!hub
            .permissions
            .contains(&ManifoldBrokerPermission::NearbyWifiDevices));
        assert!(!hub
            .permissions
            .contains(&ManifoldBrokerPermission::BluetoothScan));
        let camera = resolve_broker_product(&spec("camera-embedded")).expect("camera");
        assert!(camera
            .features
            .contains(&ManifoldBrokerFeature::MediaSession));
        assert!(camera
            .features
            .contains(&ManifoldBrokerFeature::CameraMedia));
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
        let mut duplicate = base;
        duplicate.requested_features = vec![
            ManifoldBrokerFeature::MediaSession,
            ManifoldBrokerFeature::MediaSession,
        ];
        assert_eq!(
            resolve_broker_product(&duplicate),
            Err(ManifoldBrokerProductError::DuplicateFeature)
        );
    }

    #[test]
    fn qcl100_legacy_camera_p2p_has_exact_remote_camera_delta() {
        let legacy_spec = spec("legacy-camera-p2p-standalone");
        let legacy = resolve_broker_product(&legacy_spec).expect("legacy lock");
        assert_eq!(
            legacy.command_ids,
            ids([
                "command.media.session.start",
                "command.media.session.stop",
                "command.peer.status.get",
                "command.remote_camera.get_status",
                "command.remote_camera.start_receiver",
                "command.remote_camera.start_sender",
                "command.remote_camera.stop",
                "command.session.list",
                "command.topology.p2p.close",
                "command.topology.p2p.open",
            ])
            .into_iter()
            .collect::<Vec<_>>()
        );
        assert_eq!(
            legacy.features,
            vec![
                ManifoldBrokerFeature::MediaSession,
                ManifoldBrokerFeature::CameraMedia,
                ManifoldBrokerFeature::DirectP2p,
            ]
        );
        assert_eq!(
            legacy.module_ids,
            ids([
                "module.media.camera",
                "module.media.session",
                "module.runtime.host",
                "module.transport.direct_p2p",
            ])
            .into_iter()
            .collect::<Vec<_>>()
        );
        assert_eq!(
            legacy.stream_ids,
            ids([
                "stream.media.video",
                "stream.peer.status",
                "stream.topology.status",
            ])
            .into_iter()
            .collect::<Vec<_>>()
        );
        assert_eq!(
            legacy.permissions,
            vec![
                ManifoldBrokerPermission::Internet,
                ManifoldBrokerPermission::UserNotifications,
                ManifoldBrokerPermission::BackgroundService,
                ManifoldBrokerPermission::BackgroundDataSync,
                ManifoldBrokerPermission::BackgroundCamera,
                ManifoldBrokerPermission::Camera,
                ManifoldBrokerPermission::NetworkStateObservation,
                ManifoldBrokerPermission::NearbyWifiDevices,
                ManifoldBrokerPermission::ChangeWifiState,
                ManifoldBrokerPermission::AccessWifiState,
            ]
        );

        let mut stale = legacy;
        stale
            .command_ids
            .retain(|command| command.as_str() != "command.remote_camera.get_status");
        assert_eq!(
            validate_broker_product_lock(&legacy_spec, &stale),
            Err(ManifoldBrokerProductError::StaleOrExpandedLock)
        );
    }

    #[test]
    fn qcl100_remote_camera_commands_do_not_widen_other_products() {
        let mut legacy_camera_only = spec("legacy-camera-p2p-standalone");
        legacy_camera_only.requested_features = vec![ManifoldBrokerFeature::CameraMedia];
        let mut legacy_p2p_only = spec("legacy-camera-p2p-standalone");
        legacy_p2p_only.requested_features = vec![ManifoldBrokerFeature::DirectP2p];
        let mut legacy_embedded = spec("legacy-camera-p2p-standalone");
        legacy_embedded.standalone_enabled = false;
        legacy_embedded.embedded_enabled = true;

        for (name, product) in [
            ("media-session-standalone", spec("media-session-standalone")),
            ("camera-embedded", spec("camera-embedded")),
            ("direct-p2p-standalone", spec("direct-p2p-standalone")),
            ("legacy-camera-only", legacy_camera_only),
            ("legacy-p2p-only", legacy_p2p_only),
            ("legacy-embedded", legacy_embedded),
        ] {
            let lock = resolve_broker_product(&product).expect("other product lock");
            for command in QCL100_REMOTE_CAMERA_COMMANDS {
                assert!(
                    !lock
                        .command_ids
                        .contains(&DottedId::new(command).expect("static command")),
                    "{name} unexpectedly contains {command}"
                );
            }
        }
    }

    #[test]
    fn committed_locks_match_fresh_resolution() {
        for name in [
            "base-standalone",
            "connection-hub-standalone",
            "media-session-standalone",
            "media-session-embedded",
            "camera-embedded",
            "direct-p2p-standalone",
            "ble-embedded",
            "legacy-camera-p2p-standalone",
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
