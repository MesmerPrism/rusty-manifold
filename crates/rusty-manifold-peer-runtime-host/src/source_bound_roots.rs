//! Selected actual M owner, same registered Broker, no-live-Peer root recovery.
use super::*;
use rusty_manifold_admission::ManifoldSourceBoundGrantReestablishmentRequest;
use rusty_manifold_broker_adapter::{
    ManifoldSourceBoundRootReestablishmentReceipt, ManifoldSourceBoundRootReestablishmentRequest,
};
use rusty_manifold_model::{
    ManifoldClockSnapshot, ManifoldSourceBoundControlLeaseReestablishmentRequest,
    ManifoldSourceBoundPeerDisposition, ManifoldSourceBoundRootEvidence,
};
use rusty_manifold_peer::{
    fresh_pair_setup_digest, ManifoldFreshPairSetupAuthorization, ManifoldPeerCredentialStatus,
};
/// Deployment Native owner input, not M signature/cleanup authority. Native's
/// private constructor derives these from its real Host/ARM/lifetime/Original;
/// public runtime command takes {} and accepts no supplied witness JSON.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldSourceBoundRootNativeWitness {
    pub request_id: DottedId,
    pub native_setup_request_id: DottedId,
    pub native_phase_id: DottedId,
    pub peer_disposition: ManifoldSourceBoundPeerDisposition,
    pub lifetime_ordinal: u64,
    pub prior_start_sha256: Option<String>,
    pub terminal_stop_sha256: Option<String>,
    pub native_lifecycle_sha256: String,
    pub native_actor_sha256: String,
    pub runtime_configuration_sha256: String,
    pub arm_binding_sha256: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPeerSourceBoundRootReestablishmentReceipt {
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    pub authority: ManifoldSourceBoundRootEvidence,
    pub current_pair: ManifoldPeerSessionCurrentReceiptV2,
    pub broker: ManifoldSourceBoundRootReestablishmentReceipt,
}
fn digest<T: Serialize>(domain: &str, value: &T) -> Result<String, ManifoldPeerRuntimeHostError> {
    fresh_pair_setup_digest(domain, value).map_err(invalid_snapshot)
}
/// Owning cross-language commitment for this new exact full result only.
fn owner_receipt_digest(
    value: &ManifoldPeerSourceBoundRootReestablishmentReceipt,
) -> Result<String, ManifoldPeerRuntimeHostError> {
    use sha2::{Digest, Sha256};
    let bytes = rusty_manifold_peer::fresh_history_canonical(value).map_err(invalid_snapshot)?;
    let mut h = Sha256::new();
    h.update(b"rusty.manifold.peer.source_bound_root_owner_receipt.v1\0");
    h.update(bytes);
    Ok(format!("sha256:{:x}", h.finalize()))
}
impl ManifoldPeerRuntimeHost {
    /// Native invokes only after fixed app storage proves the prior successful
    /// Original's exact outcome is durable. This owner derives all live pins;
    /// neither that custody observation nor a caller Boolean grants authority.
    pub fn checkpoint_dormant_root_history(
        &mut self,
        broker: &mut ManifoldBrokerRuntime,
        now: u64,
    ) -> Result<
        Option<rusty_manifold_broker_adapter::ManifoldBrokerHistoryCheckpoint>,
        ManifoldPeerRuntimeHostError,
    > {
        self.require_actual_fresh_setup_owner()?;
        validate_snapshot(&self.snapshot)?;
        fresh_pair_setup::no_live_graph(&self.snapshot)?;
        if !broker.has_source_bound_root_suffix() {
            return Ok(None);
        }
        self.validate_owned_state_with_live_broker(broker)?;
        let pins = self
            .snapshot
            .broker_lease_admissions
            .iter()
            .map(|a| a.broker_receipt.admission_use_request_id.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let plan = broker
            .plan_dormant_root_history(&pins, now)
            .map_err(ManifoldPeerRuntimeHostError::from)?;
        // Preserve every source required by current M authority graphs before
        // publishing the real generic-owner checkpoint and sealed baseline.
        self.validate_owned_state_with_live_broker(plan.candidate())?;
        broker
            .commit_dormant_root_history(plan)
            .map(Some)
            .map_err(ManifoldPeerRuntimeHostError::from)
    }

    pub fn register_source_bound_root_broker(
        &mut self,
        broker: &mut ManifoldBrokerRuntime,
        grant: DottedId,
        lease: DottedId,
        now: u64,
    ) -> Result<(), ManifoldPeerRuntimeHostError> {
        self.require_actual_fresh_setup_owner()?;
        fresh_pair_setup::no_live_graph(&self.snapshot)?;
        if !self.snapshot.enrollment.credentials.is_empty()
            || !self.snapshot.accepted_peers.peers.is_empty()
        {
            return Err(invalid_snapshot(
                "root source owner registration after enrollment",
            ));
        }
        let owner = self
            .signed_history_owner
            .as_mut()
            .ok_or_else(|| invalid_snapshot("root actual signed owner absent"))?;
        let registration = owner
            .prepare_source_bound_root_registration()
            .map_err(invalid_snapshot)?;
        broker
            .register_source_bound_root_owner(registration.verifier(), grant, lease, now)
            .map_err(ManifoldPeerRuntimeHostError::from)?;
        registration.commit();
        Ok(())
    }
    pub fn reestablish_source_bound_roots(
        &mut self,
        broker: &mut ManifoldBrokerRuntime,
        witness: ManifoldSourceBoundRootNativeWitness,
        fresh: &ManifoldFreshPairSetupReceipt,
        session_id: &DottedId,
        clock: ManifoldClockSnapshot,
        now: u64,
        desired_stop: &std::sync::atomic::AtomicBool,
    ) -> Result<ManifoldPeerSourceBoundRootReestablishmentReceipt, ManifoldPeerRuntimeHostError>
    {
        if desired_stop.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(invalid_snapshot("root actual DesiredStop"));
        }
        self.require_actual_fresh_setup_owner()?;
        validate_snapshot(&self.snapshot)?;
        fresh_pair_setup::no_live_graph(&self.snapshot)?;
        let policy = self
            .selected_fresh_pair_setup_policy()
            .ok_or_else(|| invalid_snapshot("root selected source-bound policy absent"))?
            .clone();
        if policy.authorization != ManifoldFreshPairSetupAuthorization::SourceBound {
            return Err(invalid_snapshot("root source-bound selection"));
        }
        let state = self
            .snapshot
            .fresh_pair_setup
            .as_ref()
            .ok_or_else(|| invalid_snapshot("root fresh source absent"))?;
        if !state.receipts.contains(fresh)
            || fresh.request.context.native_setup_request_id != witness.native_setup_request_id
            || fresh.request.context.native_phase_id != witness.native_phase_id
            || self
                .snapshot
                .trust_policy
                .fresh_setup_local_peer_id
                .as_ref()
                != Some(&fresh.local_peer_id)
            || self
                .snapshot
                .reciprocal_ed25519
                .fresh_setup_fences
                .iter()
                .find(|f| f.peer_ids == fresh.fence.peer_ids)
                != Some(&fresh.fence)
        {
            return Err(invalid_snapshot("root exact actual fresh request/floor"));
        }
        let pair = self.validate_peer_session_v2(session_id, now);
        if !pair.current
            || pair.rejection_reason.is_some()
            || pair.session_id != *session_id
            || pair.peer_ids != fresh.request.context.peer_ids
            || pair.validated_at_ms != now
            || pair.decision_id.is_none()
        {
            return Err(invalid_snapshot("root requires genuine new current pair"));
        }
        let expiry = pair
            .expires_at_ms
            .filter(|e| *e > now)
            .ok_or_else(|| invalid_snapshot("root actual pair expired"))?;
        for expected in &fresh.renewed_credentials {
            if !self.snapshot.enrollment.credentials.iter().any(|c| {
                c == expected
                    && c.status == ManifoldPeerCredentialStatus::Active
                    && c.replaced_by_key_id.is_none()
                    && c.valid_from_ms <= now
                    && c.expires_at_ms > now
            }) {
                return Err(invalid_snapshot(
                    "root current enrolled key differs/revoked/expired",
                ));
            }
        }
        let (grant_id, lease_id) = broker
            .source_bound_root_target()
            .ok_or_else(|| invalid_snapshot("root Broker not initially registered"))?;
        let grant = broker
            .admission_snapshot()
            .grants
            .iter()
            .find(|g| &g.grant_id == grant_id)
            .cloned()
            .ok_or_else(|| invalid_snapshot("root grant absent"))?;
        let lease = broker
            .control_lease_authority_snapshot()
            .active_leases
            .iter()
            .find(|l| &l.lease_id == lease_id)
            .cloned()
            .ok_or_else(|| invalid_snapshot("root lease removed/terminal"))?;
        if grant.revoked || lease.state != rusty_manifold_model::LeaseState::Active {
            return Err(invalid_snapshot("root revoked/terminal"));
        }
        let current_clock = &broker.control_lease_authority_snapshot().clock_snapshot;
        if clock.clock_domain != current_clock.clock_domain
            || clock.clock_epoch_id != current_clock.clock_epoch_id
            || clock.sequence < current_clock.sequence
            || clock.monotonic_elapsed_ns < current_clock.monotonic_elapsed_ns
            || clock.wall_unix_ms < current_clock.wall_unix_ms
            || u64::try_from(clock.wall_unix_ms).ok() != Some(now)
            || clock.read_uncertainty_ns > 10_000_000
            || clock.wall_clock_adjustment_count != current_clock.wall_clock_adjustment_count
            || clock.health != rusty_manifold_model::ClockHealth::Healthy
        {
            return Err(invalid_snapshot("root actual owner clock"));
        }
        let horizon = broker
            .admission_snapshot()
            .root_renewal_horizon_ms(&grant.grant_id);
        let deadline = now
            .checked_add(horizon)
            .ok_or_else(|| invalid_snapshot("root actual deadline overflow"))?
            .min(expiry);
        let sequence = self
            .signed_history_owner
            .as_ref()
            .ok_or_else(|| invalid_snapshot("root actual signed owner absent"))?
            .next_source_bound_root_sequence()
            .map_err(invalid_snapshot)?;
        let authority = ManifoldSourceBoundRootEvidence {
            schema_id: schema("rusty.manifold.authority.source_bound_root.v1"),
            request_id: witness.request_id.clone(),
            sequence,
            peer_host_id: self.snapshot.host_id.clone(),
            provider_epoch_id: self.snapshot.provider_epoch_id.clone(),
            native_setup_request_id: witness.native_setup_request_id,
            native_phase_id: witness.native_phase_id,
            grant_id: grant.grant_id.clone(),
            lease_id: lease.lease_id.clone(),
            peer_disposition: witness.peer_disposition,
            lifetime_ordinal: witness.lifetime_ordinal,
            prior_start_sha256: witness.prior_start_sha256,
            terminal_stop_sha256: witness.terminal_stop_sha256,
            native_lifecycle_sha256: witness.native_lifecycle_sha256,
            native_actor_sha256: witness.native_actor_sha256,
            runtime_configuration_sha256: witness.runtime_configuration_sha256,
            arm_binding_sha256: witness.arm_binding_sha256,
            selected_policy_sha256: digest(
                "rusty.manifold.peer.source_bound_root_policy.v1",
                &policy,
            )?,
            source_peer_snapshot_sha256: crate::fresh_history_source_sha256(&self.snapshot)?,
            fresh_setup_receipt_sha256: digest(
                "rusty.manifold.peer.source_bound_root_fresh_receipt.v1",
                fresh,
            )?,
            current_pair_sha256: digest(
                "rusty.manifold.peer.source_bound_root_current_pair.v1",
                &pair,
            )?,
            current_floor_sha256: digest(
                "rusty.manifold.peer.source_bound_root_floor.v1",
                &fresh.fence,
            )?,
            observed_at_ms: now,
            actual_authority_expires_at_ms: expiry,
        };
        authority.validate_at(now).map_err(invalid_snapshot)?;
        let grant_request = ManifoldSourceBoundGrantReestablishmentRequest {
            schema_id: schema(
                "rusty.manifold.admission.source_bound_grant_reestablishment_request.v1",
            ),
            request_id: broker
                .current_admission_history_request_id(
                    &DottedId::new(format!("{}.grant", witness.request_id))
                        .map_err(|_| invalid_snapshot("root grant identity"))?,
                )
                .map_err(ManifoldPeerRuntimeHostError::from)?,
            expected_authority_revision: broker.admission_snapshot().authority_revision,
            expires_at_ms: if grant.expires_at_ms <= now {
                deadline
            } else {
                grant.expires_at_ms
            },
            prior_grant: grant,
            authority: authority.clone(),
        };
        let lease_request = ManifoldSourceBoundControlLeaseReestablishmentRequest {
            schema_id: schema(
                "rusty.manifold.authority.source_bound_control_lease_reestablishment_request.v1",
            ),
            request_id: broker
                .current_control_history_request_id(
                    &DottedId::new(format!("{}.lease", witness.request_id))
                        .map_err(|_| invalid_snapshot("root lease identity"))?,
                )
                .map_err(ManifoldPeerRuntimeHostError::from)?,
            expected_authority_revision: broker
                .control_lease_authority_snapshot()
                .authority_revision,
            expires_at_ms: if lease.expires_at_ms <= now {
                deadline
            } else {
                lease.expires_at_ms
            },
            prior_lease: lease,
            authority: authority.clone(),
        };
        let request = ManifoldSourceBoundRootReestablishmentRequest {
            schema_id: schema("rusty.manifold.broker.source_bound_root_reestablishment_request.v1"),
            request_id: witness.request_id,
            grant: grant_request,
            lease: lease_request,
        };
        // This exclusive &mut Peer gate retains exact source/key/floor while the
        // borrowed actual signed owner lends its nonserializable permit. No Java,
        // transport or signer callback occurs under these owner borrows.
        let permit = self
            .signed_history_owner
            .as_mut()
            .ok_or_else(|| invalid_snapshot("root signed owner absent"))?
            .borrow_source_bound_root_permit(authority.clone(), now)
            .map_err(invalid_snapshot)?;
        let plan = broker
            .plan_source_bound_root_reestablishment(&permit, &request, clock, now)
            .map_err(ManifoldPeerRuntimeHostError::from)?;
        // Qualify every dynamic result value before publication. Native's
        // final fixed-field projection composes only this canonical receipt
        // and its already-qualified actor/ARM/prior-root data.
        rusty_manifold_peer::fresh_history_canonical(plan.receipt()).map_err(invalid_snapshot)?;
        rusty_manifold_peer::fresh_history_canonical(&authority).map_err(invalid_snapshot)?;
        rusty_manifold_peer::fresh_history_canonical(&pair).map_err(invalid_snapshot)?;
        let verified = broker
            .verify_source_bound_root_reestablishment(&permit, plan, now)
            .map_err(ManifoldPeerRuntimeHostError::from)?;
        // Cancellation is a veto, never an authority grant. This is the
        // commit admission point; later Stop observes an already-entered action.
        if desired_stop.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(invalid_snapshot("root actual DesiredStop before commit"));
        }
        let result = ManifoldPeerSourceBoundRootReestablishmentReceipt {
            schema_id: schema("rusty.manifold.peer.source_bound_root_reestablishment_receipt.v1"),
            authority,
            current_pair: pair,
            broker: verified.receipt_for_enclosing_owner().clone(),
        };
        let receipt_digest = owner_receipt_digest(&result)?;
        let _receipt = verified.commit();
        permit.commit_with_receipt_digest(receipt_digest);
        Ok(result)
    }
}

/// Same actual owner validation across sealed history. This observation is not
/// a portable restore credential or a replay of an unavailable audit prefix.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPeerCurrentRootLineageObservation {
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    pub root_request_id: DottedId,
    pub root_sequence: u64,
    pub root_receipt_sha256: String,
    pub peer_host_id: DottedId,
    pub provider_epoch_id: DottedId,
    pub observed_at_ms: u64,
    pub selected_policy_sha256: String,
    pub source_peer_snapshot_sha256: String,
    pub current_pair: ManifoldPeerSessionCurrentReceiptV2,
    pub current_floor_sha256: String,
    pub grant: rusty_manifold_admission::ManifoldAdmissionGrant,
    pub control_lease: rusty_manifold_model::ManifoldControlLease,
    pub runtime_lease: rusty_manifold_runtime_host::ManifoldRuntimeLease,
    pub broker_checkpoint: Option<rusty_manifold_broker_adapter::ManifoldBrokerHistoryCheckpoint>,
    pub authority_revisions: ManifoldPeerCurrentRootAuthorityRevisions,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPeerCurrentRootAuthorityRevisions {
    pub admission: Revision,
    pub control_lease: Revision,
    pub runtime_host: Revision,
}
impl ManifoldPeerRuntimeHost {
    /// Seed comes from the Native owner's retained actual commit; an identical
    /// caller shape cannot replace this issuer's private latest-result digest.
    /// Terminal evidence custody accepts actual expired authority as history,
    /// never as current media permission. Identity remains actual-owner-only.
    pub fn validate_committed_root_seed_for_custody(
        &self,
        broker: &ManifoldBrokerRuntime,
        seed: &ManifoldPeerSourceBoundRootReestablishmentReceipt,
    ) -> Result<(), ManifoldPeerRuntimeHostError> {
        self.require_actual_fresh_setup_owner()?;
        validate_snapshot(&self.snapshot)?;
        self.validate_owned_state_with_live_broker(broker)?;
        let sha = owner_receipt_digest(seed)?;
        if !self.signed_history_owner.as_ref().is_some_and(|o| {
            o.matches_committed_source_bound_root_receipt(seed.authority.sequence, &sha)
        }) || seed.authority.peer_host_id != self.snapshot.host_id
            || seed.authority.provider_epoch_id != self.snapshot.provider_epoch_id
        {
            return Err(invalid_snapshot(
                "terminal root seed is not actual latest committed result",
            ));
        }
        Ok(())
    }
    pub fn current_root_lineage_observation(
        &self,
        broker: &ManifoldBrokerRuntime,
        seed: &ManifoldPeerSourceBoundRootReestablishmentReceipt,
        session: &DottedId,
        now: u64,
    ) -> Result<ManifoldPeerCurrentRootLineageObservation, ManifoldPeerRuntimeHostError> {
        self.require_actual_fresh_setup_owner()?;
        validate_snapshot(&self.snapshot)?;
        self.validate_owned_state_with_live_broker(broker)?;
        let root_receipt_sha256 = owner_receipt_digest(seed)?;
        if !self.signed_history_owner.as_ref().is_some_and(|o| {
            o.matches_committed_source_bound_root_receipt(
                seed.authority.sequence,
                &root_receipt_sha256,
            )
        }) || seed.authority.peer_host_id != self.snapshot.host_id
            || seed.authority.provider_epoch_id != self.snapshot.provider_epoch_id
        {
            return Err(invalid_snapshot(
                "current root lineage requires latest actual committed seed",
            ));
        }
        let policy = self
            .selected_fresh_pair_setup_policy()
            .ok_or_else(|| invalid_snapshot("current root selected policy absent"))?;
        let selected_policy_sha256 =
            digest("rusty.manifold.peer.source_bound_root_policy.v1", policy)?;
        let pair = self.validate_peer_session_v2(session, now);
        if selected_policy_sha256 != seed.authority.selected_policy_sha256
            || !pair.current
            || pair.rejection_reason.is_some()
            || pair.validated_at_ms != now
            || pair.decision_id.is_none()
            || pair.peer_ids != seed.current_pair.peer_ids
            || pair.expires_at_ms.is_none_or(|e| e <= now)
        {
            return Err(invalid_snapshot(
                "current root source/pair expired or replaced",
            ));
        }
        // A genuine later fresh phase may advance this same owner's floor.
        // Full owner validation, current signed pair and fixed peer identities
        // authenticate that continuation; historical seed floor stays immutable.
        let floor = self
            .snapshot
            .reciprocal_ed25519
            .fresh_setup_fences
            .iter()
            .find(|f| f.peer_ids == pair.peer_ids)
            .ok_or_else(|| invalid_snapshot("current root floor absent"))?;
        let (gid, lid) = broker
            .source_bound_root_target()
            .ok_or_else(|| invalid_snapshot("current root registration absent"))?;
        if gid != &seed.authority.grant_id || lid != &seed.authority.lease_id {
            return Err(invalid_snapshot("current root registered target changed"));
        }
        let grant = broker
            .admission_snapshot()
            .grants
            .iter()
            .find(|g| &g.grant_id == gid)
            .cloned()
            .ok_or_else(|| invalid_snapshot("current root grant removed"))?;
        let control = broker
            .control_lease_authority_snapshot()
            .active_leases
            .iter()
            .find(|l| &l.lease_id == lid)
            .cloned()
            .ok_or_else(|| invalid_snapshot("current root control removed"))?;
        let runtime = broker
            .host_snapshot()
            .leases
            .iter()
            .find(|l| &l.lease_id == lid)
            .cloned()
            .ok_or_else(|| invalid_snapshot("current root runtime removed"))?;
        let mut expected_grant = seed.broker.request.grant.prior_grant.clone();
        expected_grant.expires_at_ms = grant.expires_at_ms;
        let mut expected_control = seed.broker.request.lease.prior_lease.clone();
        expected_control.expires_at_ms = control.expires_at_ms;
        expected_control.granted_revision = control.granted_revision;
        if grant != expected_grant
            || control != expected_control
            || grant.revoked
            || control.state != rusty_manifold_model::LeaseState::Active
            || grant.expires_at_ms <= now
            || control.expires_at_ms <= now
            || runtime.expires_at_ms <= now
            || runtime.lease_id != control.lease_id
            || runtime.holder_id != control.holder_id
            || runtime.scope != control.scope
            || runtime.expires_at_ms != control.expires_at_ms
        {
            return Err(invalid_snapshot(
                "current root scope/revocation/expiry differs",
            ));
        }
        let evidence = broker.evidence();
        Ok(ManifoldPeerCurrentRootLineageObservation {
            schema_id: schema("rusty.manifold.peer.current_root_lineage_observation.v1"),
            root_request_id: seed.authority.request_id.clone(),
            root_sequence: seed.authority.sequence,
            root_receipt_sha256,
            peer_host_id: self.snapshot.host_id.clone(),
            provider_epoch_id: self.snapshot.provider_epoch_id.clone(),
            observed_at_ms: now,
            selected_policy_sha256,
            source_peer_snapshot_sha256: crate::fresh_history_source_sha256(&self.snapshot)?,
            current_pair: pair,
            current_floor_sha256: digest("rusty.manifold.peer.source_bound_root_floor.v1", floor)?,
            grant,
            control_lease: control,
            runtime_lease: runtime,
            broker_checkpoint: evidence.history_checkpoint,
            authority_revisions: ManifoldPeerCurrentRootAuthorityRevisions {
                admission: evidence.admission_snapshot.authority_revision,
                control_lease: evidence
                    .control_lease_authority
                    .current_authority_snapshot
                    .authority_revision,
                runtime_host: evidence.host_snapshot.authority_revision,
            },
        })
    }
}
