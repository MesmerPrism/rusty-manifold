//! PMB V3 placement adapters over the sole shared Runtime Host.
#![allow(missing_docs)]
#![allow(dead_code)]

use crate::{
    packaged_product_lock_sha256, ManifoldBrokerControlLeaseAuthority, RUNTIME_HOST_AUTHORITY_OWNER,
};
use rusty_manifold_broker_product::pmb_v2::{
    pmb_product_spec, validate_pmb_product_lock_v2, ManifoldBrokerPlacement,
    ManifoldBrokerProductLockV2,
};
use rusty_manifold_model::{DottedId, Revision, SchemaId};
use rusty_manifold_runtime_host::{
    ManifoldRuntimeApplicationReceipt, ManifoldRuntimeCommandDescriptor,
    ManifoldRuntimeCommandRequest, ManifoldRuntimeDispatchReceipt, ManifoldRuntimeHost,
    ManifoldRuntimeHostError, ManifoldRuntimeHostSnapshot, HOST_SNAPSHOT_SCHEMA,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const PMB_ADAPTER_CONFIG_V3_SCHEMA: &str = "rusty.manifold.broker.adapter_config.v3";
pub const PMB_ADAPTER_RECEIPT_V3_SCHEMA: &str = "rusty.manifold.broker.adapter_receipt.v3";
pub const PMB_NEUTRAL_INGRESS_SCHEMA: &str = "rusty.manifold.broker.pmb_neutral_ingress.v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerAdapterConfigV3 {
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    pub adapter_id: DottedId,
    pub selected_placement: ManifoldBrokerPlacement,
    pub product_lock_id: DottedId,
    pub product_lock_fingerprint: String,
    pub product_lock_sha256: String,
    pub authority_host_id: DottedId,
    pub authority_owner_id: DottedId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerAdapterReceiptV3 {
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    pub adapter_id: DottedId,
    pub selected_placement: ManifoldBrokerPlacement,
    pub product_lock_id: DottedId,
    pub product_lock_fingerprint: String,
    pub product_lock_sha256: String,
    pub authority_host_id: DottedId,
    pub authority_owner_id: DottedId,
    pub dispatch: ManifoldRuntimeDispatchReceipt,
    pub application: ManifoldRuntimeApplicationReceipt,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerNeutralIngressV1 {
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    pub ingress_id: DottedId,
    pub descriptor_id: DottedId,
    pub resolved_descriptor_fingerprint: String,
    pub stream_id: DottedId,
    pub source_module_id: DottedId,
}

#[derive(Debug)]
pub enum ManifoldPmbAdapterError {
    Decode(serde_json::Error),
    InvalidLock,
    ConfigMismatch,
    AuthoritySubstitution,
    RegistryMismatch,
    LeaseMismatch,
    RuntimeHost(ManifoldRuntimeHostError),
    /// The original snapshot is retained verbatim as non-mutating evidence.
    RestartRejected {
        prior_snapshot: ManifoldRuntimeHostSnapshot,
    },
}

pub struct ManifoldPmbPlacementAdapter {
    config: ManifoldBrokerAdapterConfigV3,
    lock: ManifoldBrokerProductLockV2,
    host: ManifoldRuntimeHost,
}

/// Exact generated fixture bytes from the generic V3 construction path.
/// This surface is available only to the fixture-validation binary.
#[cfg(feature = "fixture-export")]
pub struct ManifoldPmbV3FixtureBytes {
    pub standalone_config: Vec<u8>,
    pub standalone_receipt: Vec<u8>,
    pub embedded_config: Vec<u8>,
    pub embedded_receipt: Vec<u8>,
}

impl ManifoldBrokerNeutralIngressV1 {
    pub fn validate(
        &self,
        lock: &ManifoldBrokerProductLockV2,
        active_owner_ids: &BTreeSet<DottedId>,
    ) -> Result<(), ManifoldPmbAdapterError> {
        if self.schema_id.as_str() != PMB_NEUTRAL_INGRESS_SCHEMA
            || self.resolved_descriptor_fingerprint != lock.resolved_descriptor_fingerprint
            || active_owner_ids.contains(&self.source_module_id)
        {
            return Err(ManifoldPmbAdapterError::InvalidLock);
        }
        let descriptor = lock
            .descriptors
            .iter()
            .find(|descriptor| descriptor.descriptor_id == self.descriptor_id)
            .ok_or(ManifoldPmbAdapterError::InvalidLock)?;
        if !lock.stream_ids.contains(&self.stream_id)
            || !descriptor.stream_bindings.iter().any(|binding| {
                binding.stream_id == self.stream_id
                    && binding.source_module_id == self.source_module_id
            })
        {
            return Err(ManifoldPmbAdapterError::InvalidLock);
        }
        Ok(())
    }
}

impl ManifoldPmbPlacementAdapter {
    pub fn new(
        config: ManifoldBrokerAdapterConfigV3,
        lock_bytes: &[u8],
        leases: &ManifoldBrokerControlLeaseAuthority,
    ) -> Result<Self, ManifoldPmbAdapterError> {
        let lock: ManifoldBrokerProductLockV2 =
            serde_json::from_slice(lock_bytes).map_err(ManifoldPmbAdapterError::Decode)?;
        validate_pmb_product_lock_v2(&pmb_product_spec(), &lock)
            .map_err(|_| ManifoldPmbAdapterError::InvalidLock)?;
        validate_config(&config, &lock, lock_bytes)?;
        let host = ManifoldRuntimeHost::from_snapshot(ManifoldRuntimeHostSnapshot {
            schema_id: schema(HOST_SNAPSHOT_SCHEMA),
            host_id: config.authority_host_id.clone(),
            authority_revision: Revision::new(1).expect("initial revision"),
            commands: lock
                .command_bindings
                .iter()
                .map(|binding| ManifoldRuntimeCommandDescriptor {
                    command_id: binding.command_id.clone(),
                    required_lease_scope: binding.required_lease_scope.clone(),
                })
                .collect(),
            leases: leases.runtime_leases().to_vec(),
            applied_request_ids: Vec::new(),
            reviewed_sweep_ids: Vec::new(),
            reviewed_control_lease_adoption_ids: Vec::new(),
            reviewed_derivative_lease_revocation_ids: Vec::new(),
            audit_events: Vec::new(),
        })
        .map_err(ManifoldPmbAdapterError::RuntimeHost)?;
        leases
            .validate_host_snapshot(host.snapshot())
            .map_err(|_| ManifoldPmbAdapterError::LeaseMismatch)?;
        Ok(Self { config, lock, host })
    }

    pub(crate) fn handle_command(
        &mut self,
        request: &ManifoldRuntimeCommandRequest,
        now_ms: u64,
    ) -> ManifoldBrokerAdapterReceiptV3 {
        let dispatch = self.host.review_command(request, now_ms);
        let application = self.host.apply_dispatch(request, &dispatch, now_ms);
        ManifoldBrokerAdapterReceiptV3 {
            schema_id: schema(PMB_ADAPTER_RECEIPT_V3_SCHEMA),
            adapter_id: self.config.adapter_id.clone(),
            selected_placement: self.config.selected_placement.clone(),
            product_lock_id: self.lock.lock_id.clone(),
            product_lock_fingerprint: self.lock.spec_fingerprint.clone(),
            product_lock_sha256: self.config.product_lock_sha256.clone(),
            authority_host_id: self.config.authority_host_id.clone(),
            authority_owner_id: self.config.authority_owner_id.clone(),
            dispatch,
            application,
        }
    }
    pub fn snapshot_json(&self) -> Result<String, ManifoldPmbAdapterError> {
        self.host
            .snapshot_json()
            .map_err(ManifoldPmbAdapterError::RuntimeHost)
    }
    /// Restores only after revalidating the lock/config/host registry bindings.
    /// Any failure returns the untouched caller snapshot as evidence.
    pub fn restart_from_snapshot(
        config: ManifoldBrokerAdapterConfigV3,
        lock_bytes: &[u8],
        snapshot: ManifoldRuntimeHostSnapshot,
        leases: &ManifoldBrokerControlLeaseAuthority,
    ) -> Result<Self, ManifoldPmbAdapterError> {
        let prior_snapshot = snapshot.clone();
        let lock: ManifoldBrokerProductLockV2 =
            serde_json::from_slice(lock_bytes).map_err(ManifoldPmbAdapterError::Decode)?;
        if validate_pmb_product_lock_v2(&pmb_product_spec(), &lock).is_err()
            || validate_config(&config, &lock, lock_bytes).is_err()
            || snapshot.host_id != config.authority_host_id
            || !registry_matches_lock(&snapshot, &lock)
            || leases.validate_host_snapshot(&snapshot).is_err()
        {
            return Err(ManifoldPmbAdapterError::RestartRejected { prior_snapshot });
        }
        let host = ManifoldRuntimeHost::from_snapshot(snapshot)
            .map_err(|_| ManifoldPmbAdapterError::RestartRejected { prior_snapshot })?;
        Ok(Self { config, lock, host })
    }
}

/// Constructs the one-placement adapter config from exact accepted V2 bytes.
pub fn pmb_adapter_config_v3(
    placement: ManifoldBrokerPlacement,
    lock_bytes: &[u8],
) -> Result<ManifoldBrokerAdapterConfigV3, ManifoldPmbAdapterError> {
    let lock: ManifoldBrokerProductLockV2 =
        serde_json::from_slice(lock_bytes).map_err(ManifoldPmbAdapterError::Decode)?;
    validate_pmb_product_lock_v2(&pmb_product_spec(), &lock)
        .map_err(|_| ManifoldPmbAdapterError::InvalidLock)?;
    if !lock.permitted_placements.contains(&placement) {
        return Err(ManifoldPmbAdapterError::ConfigMismatch);
    }
    Ok(ManifoldBrokerAdapterConfigV3 {
        schema_id: schema(PMB_ADAPTER_CONFIG_V3_SCHEMA),
        adapter_id: id(match placement {
            ManifoldBrokerPlacement::Embedded => "adapter.pmb.embedded",
            ManifoldBrokerPlacement::Standalone => "adapter.pmb.standalone",
        }),
        selected_placement: placement,
        product_lock_id: lock.lock_id,
        product_lock_fingerprint: lock.spec_fingerprint,
        product_lock_sha256: packaged_product_lock_sha256(lock_bytes),
        authority_host_id: id("host.pmb.parity"),
        authority_owner_id: id(RUNTIME_HOST_AUTHORITY_OWNER),
    })
}

#[cfg(feature = "fixture-export")]
pub fn generate_pmb_v3_fixture_bytes(
    lock_bytes: &[u8],
) -> Result<ManifoldPmbV3FixtureBytes, ManifoldPmbAdapterError> {
    use crate::{ManifoldBrokerControlLeaseSource, BROKER_CONTROL_LEASE_SOURCE_SCHEMA};
    use rusty_manifold_model::{
        ManifoldAuthoritySnapshot, ManifoldClockSnapshot, ManifoldControlLeaseRequest, SafetyClass,
    };
    use rusty_manifold_runtime_host::HOST_COMMAND_REQUEST_SCHEMA;

    let mut prior: ManifoldAuthoritySnapshot = serde_json::from_str(include_str!(
        "../../../fixtures/authority/synthetic-authority-snapshot.json"
    ))
    .expect("committed authority fixture");
    let clock: ManifoldClockSnapshot = serde_json::from_str(include_str!(
        "../../../fixtures/clock/synthetic-command-review-clock.json"
    ))
    .expect("committed clock fixture");
    prior
        .host_manifest
        .capabilities
        .push(id("capability.pmb.control"));
    let review = prior
        .review_lease_request(
            ManifoldControlLeaseRequest {
                schema_id: schema("rusty.manifold.command.lease_request.v1"),
                request_id: id("request.pmb.lease"),
                holder_id: id("client.pmb"),
                scope: id("module.breath.projected_motion"),
                expected_revision: prior.authority_revision,
                requested_ttl_ms: 30_000,
                required_capability: id("capability.pmb.control"),
                safety_class: SafetyClass::BoundedMutation,
            },
            clock.clone(),
            vec![id("evidence.pmb.lease")],
        )
        .expect("fixture lease review");
    let application = prior
        .apply_control_lease_authority_review(review)
        .expect("fixture lease application");
    let authority =
        ManifoldBrokerControlLeaseAuthority::from_caller_attested_retained_authority_state(
            application
                .applied_snapshot
                .clone()
                .expect("fixture lease produces snapshot"),
            clock,
            vec![ManifoldBrokerControlLeaseSource {
                schema_id: schema(BROKER_CONTROL_LEASE_SOURCE_SCHEMA),
                prior_authority_snapshot: prior,
                application,
            }],
        )
        .expect("fixture lease authority");
    let request = ManifoldRuntimeCommandRequest {
        schema_id: schema(HOST_COMMAND_REQUEST_SCHEMA),
        request_id: id("request.pmb.status"),
        expected_authority_revision: Revision::new(1).expect("literal revision"),
        requester_id: id("client.pmb"),
        command_id: id("command.breath.status"),
        lease_id: None,
        params_digest: None,
        issued_at_ms: 1_000,
        expires_at_ms: 10_000,
    };
    let standalone_config = pmb_adapter_config_v3(ManifoldBrokerPlacement::Standalone, lock_bytes)?;
    let embedded_config = pmb_adapter_config_v3(ManifoldBrokerPlacement::Embedded, lock_bytes)?;
    let standalone_receipt =
        ManifoldPmbPlacementAdapter::new(standalone_config.clone(), lock_bytes, &authority)?
            .handle_command(&request, 2_000);
    let embedded_receipt =
        ManifoldPmbPlacementAdapter::new(embedded_config.clone(), lock_bytes, &authority)?
            .handle_command(&request, 2_000);
    Ok(ManifoldPmbV3FixtureBytes {
        standalone_config: canonical_fixture_json(&standalone_config),
        standalone_receipt: canonical_fixture_json(&standalone_receipt),
        embedded_config: canonical_fixture_json(&embedded_config),
        embedded_receipt: canonical_fixture_json(&embedded_receipt),
    })
}

#[cfg(feature = "fixture-export")]
fn canonical_fixture_json<T: Serialize>(value: &T) -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(value).expect("fixture value serializes");
    bytes.push(b'\n');
    bytes
}

fn validate_config(
    config: &ManifoldBrokerAdapterConfigV3,
    lock: &ManifoldBrokerProductLockV2,
    bytes: &[u8],
) -> Result<(), ManifoldPmbAdapterError> {
    if config.schema_id.as_str() != PMB_ADAPTER_CONFIG_V3_SCHEMA {
        return Err(ManifoldPmbAdapterError::ConfigMismatch);
    }
    if !lock
        .permitted_placements
        .contains(&config.selected_placement)
    {
        return Err(ManifoldPmbAdapterError::ConfigMismatch);
    }
    if config.product_lock_id != lock.lock_id
        || config.product_lock_fingerprint != lock.spec_fingerprint
        || config.product_lock_sha256 != packaged_product_lock_sha256(bytes)
    {
        return Err(ManifoldPmbAdapterError::ConfigMismatch);
    }
    if config.authority_owner_id.as_str() != RUNTIME_HOST_AUTHORITY_OWNER {
        return Err(ManifoldPmbAdapterError::AuthoritySubstitution);
    }
    let expected = lock
        .command_ids
        .iter()
        .map(|value| value.as_str())
        .collect::<BTreeSet<_>>();
    if expected.len() != 5 || expected.iter().any(|id| !id.starts_with("command.breath.")) {
        return Err(ManifoldPmbAdapterError::RegistryMismatch);
    }
    Ok(())
}
fn registry_matches_lock(
    snapshot: &ManifoldRuntimeHostSnapshot,
    lock: &ManifoldBrokerProductLockV2,
) -> bool {
    snapshot
        .commands
        .iter()
        .map(|command| &command.command_id)
        .collect::<BTreeSet<_>>()
        == lock.command_ids.iter().collect::<BTreeSet<_>>()
        && snapshot.commands.iter().all(|command| {
            lock.command_bindings
                .iter()
                .find(|binding| binding.command_id == command.command_id)
                .is_some_and(|binding| command.required_lease_scope == binding.required_lease_scope)
        })
}
fn id(value: &str) -> DottedId {
    DottedId::new(value).expect("static id")
}
fn schema(value: &str) -> SchemaId {
    SchemaId::new(value).expect("static schema")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ManifoldBrokerControlLeaseAuthority, ManifoldBrokerControlLeaseSource};
    use rusty_manifold_broker_product::pmb_v2::resolve_pmb_product_v2;
    use rusty_manifold_model::{
        ManifoldAuthoritySnapshot, ManifoldClockSnapshot, ManifoldControlLeaseRequest, SafetyClass,
    };
    use rusty_manifold_runtime_host::{
        ManifoldRuntimeDispatchOutcome, ManifoldRuntimeRejectionReason, HOST_COMMAND_REQUEST_SCHEMA,
    };

    fn authority(with_lease: bool) -> ManifoldBrokerControlLeaseAuthority {
        let mut prior: ManifoldAuthoritySnapshot = serde_json::from_str(include_str!(
            "../../../fixtures/authority/synthetic-authority-snapshot.json"
        ))
        .expect("authority");
        let clock: ManifoldClockSnapshot = serde_json::from_str(include_str!(
            "../../../fixtures/clock/synthetic-command-review-clock.json"
        ))
        .expect("clock");
        if !with_lease {
            return ManifoldBrokerControlLeaseAuthority::from_caller_attested_retained_authority_state(prior, clock, Vec::new()).expect("authority");
        }
        prior
            .host_manifest
            .capabilities
            .push(id("capability.pmb.control"));
        let review = prior
            .review_lease_request(
                ManifoldControlLeaseRequest {
                    schema_id: schema("rusty.manifold.command.lease_request.v1"),
                    request_id: id("request.pmb.lease"),
                    holder_id: id("client.pmb"),
                    scope: id("module.breath.projected_motion"),
                    expected_revision: prior.authority_revision,
                    requested_ttl_ms: 30_000,
                    required_capability: id("capability.pmb.control"),
                    safety_class: SafetyClass::BoundedMutation,
                },
                clock.clone(),
                vec![id("evidence.pmb.lease")],
            )
            .expect("review");
        let application = prior
            .apply_control_lease_authority_review(review)
            .expect("application");
        let current = application.applied_snapshot.clone().expect("current");
        ManifoldBrokerControlLeaseAuthority::from_caller_attested_retained_authority_state(
            current,
            clock,
            vec![ManifoldBrokerControlLeaseSource {
                schema_id: schema(crate::BROKER_CONTROL_LEASE_SOURCE_SCHEMA),
                prior_authority_snapshot: prior,
                application,
            }],
        )
        .expect("authority")
    }
    fn config(placement: ManifoldBrokerPlacement, bytes: &[u8]) -> ManifoldBrokerAdapterConfigV3 {
        let lock: ManifoldBrokerProductLockV2 = serde_json::from_slice(bytes).expect("lock");
        ManifoldBrokerAdapterConfigV3 {
            schema_id: schema(PMB_ADAPTER_CONFIG_V3_SCHEMA),
            adapter_id: id(match placement {
                ManifoldBrokerPlacement::Embedded => "adapter.pmb.embedded",
                ManifoldBrokerPlacement::Standalone => "adapter.pmb.standalone",
            }),
            selected_placement: placement,
            product_lock_id: lock.lock_id,
            product_lock_fingerprint: lock.spec_fingerprint,
            product_lock_sha256: packaged_product_lock_sha256(bytes),
            authority_host_id: id("host.pmb.parity"),
            authority_owner_id: id(RUNTIME_HOST_AUTHORITY_OWNER),
        }
    }
    fn request(
        id_value: &str,
        command: &str,
        lease: Option<&str>,
        revision: u64,
        expires_at_ms: u64,
    ) -> ManifoldRuntimeCommandRequest {
        ManifoldRuntimeCommandRequest {
            schema_id: schema(HOST_COMMAND_REQUEST_SCHEMA),
            request_id: id(id_value),
            expected_authority_revision: Revision::new(revision).expect("revision"),
            requester_id: id("client.pmb"),
            command_id: id(command),
            lease_id: lease.map(id),
            params_digest: None,
            issued_at_ms: 1_000,
            expires_at_ms,
        }
    }
    #[test]
    fn same_bytes_drive_both_placements_with_host_parity() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let bytes = std::fs::read(root.join("fixtures/broker-product/pmb-v2-product-lock.json"))
            .expect("committed package bytes");
        let authority = authority(true);
        let mut standalone = ManifoldPmbPlacementAdapter::new(
            config(ManifoldBrokerPlacement::Standalone, &bytes),
            &bytes,
            &authority,
        )
        .expect("standalone");
        let mut embedded = ManifoldPmbPlacementAdapter::new(
            config(ManifoldBrokerPlacement::Embedded, &bytes),
            &bytes,
            &authority,
        )
        .expect("embedded");
        let accepted = request(
            "request.pmb.apply",
            "command.breath.configure",
            Some("lease.pmb.lease"),
            1,
            10_000,
        );
        let a = standalone.handle_command(&accepted, 2_000);
        let b = embedded.handle_command(&accepted, 2_000);
        assert_eq!(a.product_lock_sha256, b.product_lock_sha256);
        assert_eq!(a.dispatch, b.dispatch);
        assert_eq!(a.application, b.application);
        assert!(a.application.applied);
        let snapshot = standalone.host.snapshot().clone();
        let restarted = ManifoldPmbPlacementAdapter::restart_from_snapshot(
            config(ManifoldBrokerPlacement::Standalone, &bytes),
            &bytes,
            snapshot.clone(),
            &authority,
        )
        .expect("same lock/config/host restart");
        assert_eq!(restarted.host.snapshot(), &snapshot);
        let mut changed_host = config(ManifoldBrokerPlacement::Standalone, &bytes);
        changed_host.authority_host_id = id("host.pmb.substituted");
        assert!(matches!(
            ManifoldPmbPlacementAdapter::restart_from_snapshot(changed_host, &bytes, snapshot.clone(), &authority),
            Err(ManifoldPmbAdapterError::RestartRejected { prior_snapshot }) if prior_snapshot == snapshot
        ));
        for (id_value, command, lease, revision, expires_at, reason) in [
            (
                "request.pmb.unknown",
                "command.unknown",
                None,
                2,
                10_000,
                ManifoldRuntimeRejectionReason::UnknownCommand,
            ),
            (
                "request.pmb.unleased",
                "command.breath.set_profile",
                None,
                2,
                10_000,
                ManifoldRuntimeRejectionReason::MissingLease,
            ),
            (
                "request.pmb.expired",
                "command.breath.status",
                None,
                2,
                1_000,
                ManifoldRuntimeRejectionReason::ExpiredRequest,
            ),
        ] {
            let r = request(id_value, command, lease, revision, expires_at);
            let a = standalone.handle_command(&r, 2_000);
            let b = embedded.handle_command(&r, 2_000);
            assert_eq!(a.dispatch, b.dispatch);
            assert_eq!(a.application, b.application);
            assert_eq!(a.application.rejection_reason, Some(reason));
        }
        let replay = standalone.handle_command(&accepted, 2_000);
        assert_eq!(
            replay.application.rejection_reason,
            Some(ManifoldRuntimeRejectionReason::StaleAuthorityRevision)
        );
        let stale = embedded.handle_command(
            &request(
                "request.pmb.stale",
                "command.breath.status",
                None,
                1,
                10_000,
            ),
            2_000,
        );
        assert_eq!(
            stale.dispatch.outcome,
            ManifoldRuntimeDispatchOutcome::Rejected
        );
        assert_eq!(
            stale.application.rejection_reason,
            Some(ManifoldRuntimeRejectionReason::StaleAuthorityRevision)
        );
    }
    #[test]
    fn ingress_and_config_damage_fail_closed() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let lock = resolve_pmb_product_v2(&pmb_product_spec()).expect("lock");
        let valid: ManifoldBrokerNeutralIngressV1 = serde_json::from_str(
            &std::fs::read_to_string(
                root.join("fixtures/broker-adapter/pmb-neutral-vector3-ingress.json"),
            )
            .expect("valid ingress fixture"),
        )
        .expect("valid fixture JSON");
        assert!(valid.validate(&lock, &BTreeSet::new()).is_ok());
        let damaged: ManifoldBrokerNeutralIngressV1 = serde_json::from_str(
            &std::fs::read_to_string(
                root.join("fixtures/damaged/pmb-neutral-ingress-unadmitted-stream.json"),
            )
            .expect("damaged ingress fixture"),
        )
        .expect("damaged fixture JSON");
        assert!(damaged.validate(&lock, &BTreeSet::new()).is_err());
        let mut duplicate_owner = BTreeSet::new();
        duplicate_owner.insert(valid.source_module_id.clone());
        assert!(valid.validate(&lock, &duplicate_owner).is_err());
        let bytes = serde_json::to_vec(&lock).expect("bytes");
        let mut bad = config(ManifoldBrokerPlacement::Standalone, &bytes);
        bad.authority_owner_id = id("adapter.authority");
        assert!(ManifoldPmbPlacementAdapter::new(bad, &bytes, &authority(false)).is_err());
        let mut absent = config(ManifoldBrokerPlacement::Standalone, &bytes);
        absent.selected_placement = ManifoldBrokerPlacement::Standalone;
        let mut embedded_only = lock.clone();
        embedded_only.permitted_placements = vec![ManifoldBrokerPlacement::Embedded];
        let embedded_bytes = serde_json::to_vec(&embedded_only).unwrap();
        assert!(
            ManifoldPmbPlacementAdapter::new(absent, &embedded_bytes, &authority(false)).is_err()
        );
        let standalone_fixture: ManifoldBrokerAdapterConfigV3 = serde_json::from_str(
            &std::fs::read_to_string(
                root.join("fixtures/broker-adapter/pmb-v3-standalone-config.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            standalone_fixture.selected_placement,
            ManifoldBrokerPlacement::Standalone
        );
        let _: ManifoldBrokerAdapterReceiptV3 = serde_json::from_str(
            &std::fs::read_to_string(
                root.join("fixtures/broker-adapter/pmb-v3-standalone-receipt.json"),
            )
            .unwrap(),
        )
        .unwrap();
        for name in [
            "pmb-v3-placement-missing.json",
            "pmb-v3-placement-duplicate.json",
            "pmb-v3-placement-legacy-empty.json",
            "pmb-v3-placement-legacy-multiple.json",
            "pmb-v3-placement-singular-plus-plural.json",
        ] {
            let raw = std::fs::read_to_string(root.join("fixtures/damaged").join(name)).unwrap();
            assert!(
                serde_json::from_str::<ManifoldBrokerAdapterConfigV3>(&raw).is_err(),
                "{name}"
            );
        }
        let unknown_placement =
            std::fs::read_to_string(root.join("fixtures/damaged/pmb-v3-placement-unknown.json"))
                .unwrap();
        let unknown_placement_error =
            serde_json::from_str::<ManifoldBrokerAdapterConfigV3>(&unknown_placement)
                .expect_err("non-permitted selected_placement must fail before normalization");
        assert!(unknown_placement_error.is_data());
        assert!(unknown_placement_error
            .to_string()
            .contains("unknown variant `sidecar`"));

        let unknown_authority = std::fs::read_to_string(
            root.join("fixtures/damaged/pmb-v3-placement-unknown-authority.json"),
        )
        .unwrap();
        let unknown_authority_error =
            serde_json::from_str::<ManifoldBrokerAdapterConfigV3>(&unknown_authority)
                .expect_err("unknown placement authority must fail before normalization");
        assert!(unknown_authority_error.is_data());
        assert!(unknown_authority_error
            .to_string()
            .contains("unknown field `placement_authority`"));
    }
}
