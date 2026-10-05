//! Actual retained Peer lineage joined to borrowed Broker Pending authority.
//! No terminal effect, snapshot field, or normal lease is synthesized here.

use super::*;
use rusty_manifold_broker_adapter::{
    ManifoldBrokerCleanupBinding, ManifoldBrokerCleanupDeploymentInputs,
    ManifoldBrokerCleanupExpectedRegistration, ManifoldBrokerCleanupPendingCapability,
    ManifoldBrokerCleanupRegistration,
};
use rusty_manifold_model::{ManifoldClockSnapshot, ManifoldMediaRouteLegDescriptor};

/// Independently retained deployment expectation for one original effect target.
/// It describes expected ownership, not evidence that effects existed or ceased.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldPeerCleanupEffectExpectation {
    /// Exact original directional resource set and generation.
    pub route_leg: ManifoldMediaRouteLegDescriptor,
    /// Exact original platform runtime specification.
    pub platform_runtime_spec_id: DottedId,
    /// Executor-owner-defined digest of the original resource generation.
    pub effect_target_sha256: String,
}

/// Non-serializable preflight result. It retains both live owner borrows and
/// permits no completion or ordinary dispatch; dropping it changes no state.
#[derive(Debug)]
pub struct ManifoldPeerCleanupPendingPreflight<'peer, 'broker> {
    peer: &'peer ManifoldPeerRuntimeHost,
    pending: ManifoldBrokerCleanupPendingCapability<'broker>,
    observed_clock: ManifoldClockSnapshot,
}
impl ManifoldPeerCleanupPendingPreflight<'_, '_> {
    /// The exact consumed cleanup request identity.
    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.pending.pending().request_id
    }
    /// Current Peer CAS checked at preflight, independent of immutable issue revision.
    #[must_use]
    pub fn peer_authority_revision(&self) -> Revision {
        self.peer.snapshot.pair_media_routes.authority_revision
    }
    /// Current unified Peer event sequence checked at preflight.
    #[must_use]
    pub fn peer_event_sequence(&self) -> u64 {
        self.peer.snapshot.event_sequence
    }
    /// Independent clock at actual preflight, not merely at capability borrow.
    #[must_use]
    pub fn observed_clock(&self) -> &ManifoldClockSnapshot {
        &self.observed_clock
    }
}

impl ManifoldPeerRuntimeHost {
    /// Derive the immutable original route/admission projection from held,
    /// validated Peer state. Caller expectations cannot substitute accepted state.
    /// # Errors
    /// Rejects missing genuine admission/issue lineage or any target/provenance mismatch.
    pub fn derive_retained_cleanup_projection(
        &self,
        binding: &ManifoldBrokerCleanupBinding,
        deployment: &ManifoldBrokerCleanupDeploymentInputs,
        effect: &ManifoldPeerCleanupEffectExpectation,
    ) -> Result<String, ManifoldPeerRuntimeHostError> {
        let (route, admission) = self.cleanup_route_admission(binding, deployment, effect)?;
        let issue = unique_applied_pair_event(
            &self.snapshot,
            &ManifoldPeerRuntimeAuditKind::PairMediaRoute,
            route.request_id(),
        )?;
        // Closed immutable whitelist preserves the transport tag and every
        // original issue field. Future route fields require an explicit decision
        // here instead of silently becoming immutable provenance.
        let mut original_route =
            serde_json::to_value(route).map_err(ManifoldPeerRuntimeHostError::Serialize)?;
        let record = original_route
            .get_mut("record")
            .and_then(serde_json::Value::as_object_mut)
            .ok_or_else(|| invalid_snapshot("cleanup route transport"))?;
        const IMMUTABLE: &[&str] = &[
            "$schema",
            "grant_id",
            "request_id",
            "route_leg",
            "peer_session_id",
            "peer_session_decision_id",
            "transport",
            "signed_topology_evidence",
            "peer_session_authority_revision",
            "peer_session_acceptance_authority_revision",
            "rendezvous_receipt_id",
            "rendezvous_authority_revision",
            "reciprocal_receipt_id",
            "reciprocal_authority_revision",
            "enrollment_authority_revision",
            "source_topology_role",
            "sink_topology_role",
            "media_session_decision_id",
            "media_session_id",
            "media_session_authority_revision",
            "media_acceptance_authority_revision",
            "media_descriptor_canonical_sha256",
            "platform_runtime_spec_id",
            "authority_host_id",
            "authority_provider_epoch_id",
            "authority_client_id",
            "authority_runtime_lease_id",
            "authority_runtime_lease_expires_at_ms",
            "runtime_command_request_id",
            "runtime_command_id",
            "runtime_params_digest",
            "runtime_dispatch_id",
            "runtime_application_receipt_id",
            "runtime_resulting_authority_revision",
            "product_id",
            "feature_lock_id",
            "feature_lock_fingerprint",
            "capability_id",
            "admission_grant_id",
            "valid_from_ms",
            "expires_at_ms",
        ];
        const LIFECYCLE: &[&str] = &[
            "lifecycle_status",
            "cleanup_status",
            "ended_at_ms",
            "ended_by_id",
            "termination_action",
            "termination_runtime_binding",
            "cleanup_receipt_id",
        ];
        if record.keys().any(|field| {
            !IMMUTABLE.contains(&field.as_str()) && !LIFECYCLE.contains(&field.as_str())
        }) {
            return Err(invalid_snapshot(
                "cleanup original projection field is not classified",
            ));
        }
        record.retain(|field, _| IMMUTABLE.contains(&field.as_str()));
        // Retained admission release is mutable cleanup history; original admission is not.
        let mut original_admission =
            serde_json::to_value(admission).map_err(ManifoldPeerRuntimeHostError::Serialize)?;
        let object = original_admission
            .as_object_mut()
            .expect("typed admission object");
        object.remove("released_at_ms");
        object.remove("release_id");
        domain_separated_digest(
            "rusty.manifold.peer.cleanup_original_projection.v1",
            &(
                original_route,
                original_admission,
                issue,
                binding,
                deployment,
                &effect.route_leg,
                &effect.platform_runtime_spec_id,
                &effect.effect_target_sha256,
            ),
        )
    }

    /// Register only the Peer-derived immutable projection before ordinary source start.
    /// Deployment must persist complete Broker V6 and independent anchors before effects.
    /// # Errors
    /// Rejects expired/currentness failures, false Broker lineage or target mismatch.
    pub fn register_pair_route_cleanup_before_start(
        &self,
        broker: &mut ManifoldBrokerRuntime,
        registration_id: DottedId,
        binding: ManifoldBrokerCleanupBinding,
        deployment: &ManifoldBrokerCleanupDeploymentInputs,
        effect: &ManifoldPeerCleanupEffectExpectation,
        clock: ManifoldClockSnapshot,
    ) -> Result<ManifoldBrokerCleanupRegistration, ManifoldPeerRuntimeHostError> {
        let (route, admission) = self.cleanup_route_admission(&binding, deployment, effect)?;
        let now = u64::try_from(clock.wall_unix_ms)
            .map_err(|_| invalid_snapshot("negative cleanup clock"))?;
        if *route.lifecycle_status()
            != rusty_manifold_peer::ManifoldPairMediaRouteLifecycleStatus::Current
            || now >= route.expires_at_ms()
            || now >= admission.runtime_lease.expires_at_ms
            || now
                < self
                    .snapshot
                    .pair_media_routes
                    .last_observed_at_ms
                    .unwrap_or(0)
        {
            return Err(invalid_snapshot(
                "cleanup registration requires current original route",
            ));
        }
        validate_active_broker_admission(&self.snapshot, admission, &broker.evidence())?;
        let projection = self.derive_retained_cleanup_projection(&binding, deployment, effect)?;
        broker
            .register_cleanup_before_start(
                ManifoldBrokerCleanupExpectedRegistration {
                    registration_id,
                    binding,
                    deployment_inputs: deployment.clone(),
                    peer_route_projection_sha256: projection,
                },
                deployment,
                clock,
            )
            .map_err(|e| ManifoldPeerRuntimeHostError::Authority(e.to_string()))
    }

    /// Join exact live consumed Broker Pending to retained Peer provenance and
    /// independently supplied current CAS. This grants no terminal completion.
    /// # Errors
    /// Rejects stale CAS, cross-owner epoch, missing admission, changed original
    /// projection, wrong exact transaction or already completed cleanup.
    pub fn preflight_pair_route_cleanup_pending<'peer, 'broker>(
        &'peer self,
        pending: ManifoldBrokerCleanupPendingCapability<'broker>,
        effect: &ManifoldPeerCleanupEffectExpectation,
        exact_request_id: &str,
        expected_authority_revision: Revision,
        expected_event_sequence: u64,
        observed_clock: ManifoldClockSnapshot,
    ) -> Result<ManifoldPeerCleanupPendingPreflight<'peer, 'broker>, ManifoldPeerRuntimeHostError>
    {
        pending
            .validate_at(&observed_clock)
            .map_err(|e| ManifoldPeerRuntimeHostError::Authority(e.to_string()))?;
        if u64::try_from(observed_clock.wall_unix_ms)
            .map_err(|_| invalid_snapshot("negative preflight clock"))?
            < self
                .snapshot
                .pair_media_routes
                .last_observed_at_ms
                .unwrap_or(0)
        {
            return Err(invalid_snapshot(
                "cleanup preflight predates Peer authority observation",
            ));
        }
        let expected = pending.expected();
        if self.snapshot.pair_media_routes.authority_revision != expected_authority_revision
            || self.snapshot.event_sequence != expected_event_sequence
            || pending.pending().request_id != exact_request_id
            || pending.provider_epoch() != &self.snapshot.provider_epoch_id
        {
            return Err(invalid_snapshot(
                "cleanup Pending transaction or current CAS mismatch",
            ));
        }
        let (route, admission) =
            self.cleanup_route_admission(&expected.binding, &expected.deployment_inputs, effect)?;
        if *route.cleanup_status()
            == rusty_manifold_peer::ManifoldPairMediaRouteCleanupStatus::Completed
            || !pending.retains_admission(&admission.broker_receipt)
            || pending.original_lease().lease_id.as_str() != expected.binding.target.lease_id
            || self.derive_retained_cleanup_projection(
                &expected.binding,
                &expected.deployment_inputs,
                effect,
            )? != expected.peer_route_projection_sha256
        {
            return Err(invalid_snapshot(
                "cleanup Pending retained projection mismatch",
            ));
        }
        Ok(ManifoldPeerCleanupPendingPreflight {
            peer: self,
            pending,
            observed_clock,
        })
    }

    fn cleanup_route_admission<'a>(
        &'a self,
        binding: &ManifoldBrokerCleanupBinding,
        deployment: &ManifoldBrokerCleanupDeploymentInputs,
        effect: &ManifoldPeerCleanupEffectExpectation,
    ) -> Result<
        (
            &'a ManifoldAcceptedPairMediaRouteV2,
            &'a ManifoldPeerRuntimeBrokerLeaseAdmission,
        ),
        ManifoldPeerRuntimeHostError,
    > {
        validate_snapshot(&self.snapshot)?;
        let t = &binding.target;
        let route = self
            .snapshot
            .pair_media_routes
            .routes
            .iter()
            .find(|r| r.grant_id().as_str() == t.route_grant_id)
            .ok_or_else(|| invalid_snapshot("cleanup retained route missing"))?;
        let admissions: Vec<_> = self
            .snapshot
            .broker_lease_admissions
            .iter()
            .filter(|a| &a.runtime_lease.lease_id == route.authority_runtime_lease_id())
            .collect();
        if admissions.len() != 1 {
            return Err(invalid_snapshot("cleanup admission ambiguous or missing"));
        }
        let admission = admissions[0];
        let bounded = admission
            .broker_receipt
            .bounded_use
            .as_ref()
            .ok_or_else(|| invalid_snapshot("cleanup bounded admission missing"))?;
        let adapter = admission
            .broker_receipt
            .adapter_receipt
            .as_ref()
            .ok_or_else(|| invalid_snapshot("cleanup applied Broker adapter missing"))?;
        let outer = broker_outer_lease_id_for_admission(&self.snapshot, admission)
            .ok_or_else(|| invalid_snapshot("cleanup outer lease lineage missing"))?;
        let issue = unique_applied_pair_event(
            &self.snapshot,
            &ManifoldPeerRuntimeAuditKind::PairMediaRoute,
            route.request_id(),
        )?;
        if !broker_lease_admission_is_well_formed(&self.snapshot, admission)
            || route.authority_host_id() != &self.snapshot.media_command_runtime.host_id
            || route.authority_provider_epoch_id() != &self.snapshot.provider_epoch_id
            || admission.broker_receipt.provider_epoch_id != self.snapshot.provider_epoch_id
            || t.authority_host != adapter.authority_host_id.as_str()
            || t.provider_epoch != admission.broker_receipt.provider_epoch_id.as_str()
            || t.lease_id != outer.as_str()
            || t.original_principal != route.authority_client_id().as_str()
            || deployment.original_identity != bounded.identity
            || t.admission_id != bounded.admission_grant_id.as_str()
            || t.client_lock_id != bounded.client_lock_id.as_str()
            || t.client_lock_sha256 != bounded.client_lock_fingerprint
            || t.product_lock_id != adapter.product_lock_id.as_str()
            || t.product_lock_fingerprint != adapter.product_lock_fingerprint
            || t.product_lock_sha256 != adapter.product_lock_sha256
            || t.route_revision != issue.resulting_authority_revision.get()
            || t.platform_runtime != route.platform_runtime_spec_id().as_str()
            || effect.platform_runtime_spec_id != *route.platform_runtime_spec_id()
            || effect.route_leg != *route.route_leg()
            || !valid_sha256(&effect.effect_target_sha256)
            || effect.effect_target_sha256 != t.effect_target_sha256
            || binding.trust != deployment.trust
            || binding.revoker_principal != deployment.revoker_principal
            || t.feature_lock_id != deployment.feature_lock_id
            || t.feature_lock_sha256 != deployment.feature_lock_sha256
        {
            return Err(invalid_snapshot(
                "cleanup original Peer/Broker lineage mismatch",
            ));
        }
        let value = serde_json::to_value(route).map_err(ManifoldPeerRuntimeHostError::Serialize)?;
        let record = &value["record"];
        if record["feature_lock_id"].as_str() != Some(t.feature_lock_id.as_str())
            || record["feature_lock_fingerprint"].as_str() != Some(t.feature_lock_sha256.as_str())
        {
            return Err(invalid_snapshot(
                "cleanup application feature provenance mismatch",
            ));
        }
        Ok((route, admission))
    }
}
