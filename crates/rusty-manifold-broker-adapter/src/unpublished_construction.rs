//! Actual uncommitted Broker owners retained BEFORE fallible construction.
//! No Clone/Deserialize/snapshot-to-owner path is provided by this arena.
use super::*;

struct Parts {
    development_lifetime_policy:
        Option<rusty_manifold_admission::ManifoldDevelopmentLifetimePolicy>,
    provider_epoch_id: DottedId,
    adapter: ManifoldBrokerAdapter,
    control_lease_authority: ManifoldBrokerControlLeaseAuthority,
    admission_snapshot: ManifoldAdmissionSnapshot,
}
/// One process-owned constructor attempt. On any refusal its actual components
/// remain here for source observation and explicit enclosing-owner retirement.
pub struct ManifoldBrokerUnpublishedConstruction {
    parts: Option<Parts>,
    runtime: Option<ManifoldBrokerRuntime>,
    attempted: bool,
    validated: bool,
}
impl ManifoldBrokerUnpublishedConstruction {
    /// Retain actual non-clone owners before any constructor validation.
    pub fn new(
        provider_epoch_id: DottedId,
        adapter: ManifoldBrokerAdapter,
        control_lease_authority: ManifoldBrokerControlLeaseAuthority,
        admission_snapshot: ManifoldAdmissionSnapshot,
    ) -> Self {
        Self::new_with_policy_selection(
            provider_epoch_id,
            adapter,
            control_lease_authority,
            admission_snapshot,
            None,
        )
    }

    /// Selects the exact trusted source policy without changing legacy input shapes.
    pub fn new_with_lifetime_policy(
        provider_epoch_id: DottedId,
        adapter: ManifoldBrokerAdapter,
        control_lease_authority: ManifoldBrokerControlLeaseAuthority,
        admission_snapshot: ManifoldAdmissionSnapshot,
        policy: &rusty_manifold_admission::ManifoldDevelopmentLifetimePolicy,
    ) -> Self {
        Self::new_with_policy_selection(
            provider_epoch_id,
            adapter,
            control_lease_authority,
            admission_snapshot,
            Some(policy),
        )
    }

    fn new_with_policy_selection(
        provider_epoch_id: DottedId,
        adapter: ManifoldBrokerAdapter,
        control_lease_authority: ManifoldBrokerControlLeaseAuthority,
        admission_snapshot: ManifoldAdmissionSnapshot,
        policy: Option<&rusty_manifold_admission::ManifoldDevelopmentLifetimePolicy>,
    ) -> Self {
        Self {
            parts: Some(Parts {
                development_lifetime_policy: policy.cloned(),
                provider_epoch_id,
                adapter,
                control_lease_authority,
                admission_snapshot,
            }),
            runtime: None,
            attempted: false,
            validated: false,
        }
    }
    /// Run exactly the ordinary new-constructor predicates on retained parts.
    /// A refusal or unwind never discards the enclosing arena's owned parts.
    pub fn try_construct(&mut self) -> Result<(), ManifoldBrokerRuntimeStateError> {
        if self.attempted {
            return Err(ManifoldBrokerRuntimeStateError::InvalidEvidence(
                "unpublished_constructor_already_attempted",
            ));
        }
        self.attempted = true;
        let parts = self
            .parts
            .as_ref()
            .ok_or(ManifoldBrokerRuntimeStateError::InvalidEvidence(
                "unpublished_constructor_parts_absent",
            ))?;
        if parts
            .control_lease_authority
            .evidence()
            .history_checkpoint
            .is_some()
            || parts.adapter.host_snapshot().history_checkpoint.is_some()
            || parts.admission_snapshot.history_checkpoint.is_some()
        {
            return Err(ManifoldBrokerRuntimeStateError::InvalidEvidence(
                "ongoing_requires_owned_composition_selection",
            ));
        }
        parts
            .control_lease_authority
            .validate_host_snapshot(parts.adapter.host_snapshot())
            .map_err(ManifoldBrokerRuntimeStateError::ControlLeaseAuthority)?;
        let admission_token_history = parts
            .admission_snapshot
            .active_tokens
            .iter()
            .map(|t| (t.token_id.clone(), t.clone()))
            .collect();
        // Cloning input DATA does not clone any live authority. The actual new
        // admission owner is immediately installed in the retained candidate.
        let admission = match &parts.development_lifetime_policy {
            Some(policy) => ManifoldAdmissionAuthority::from_snapshot_with_lifetime_policy(
                parts.admission_snapshot.clone(),
                policy,
            ),
            None => ManifoldAdmissionAuthority::from_snapshot(parts.admission_snapshot.clone()),
        }
        .map_err(ManifoldBrokerRuntimeStateError::Admission)?;
        let parts = self.parts.take().expect("retained real constructor parts");
        self.runtime = Some(ManifoldBrokerRuntime {
            history_checkpoint: None,
            cleanup_registrations: BTreeMap::new(),
            cleanup_clock: None,
            provider_epoch_id: parts.provider_epoch_id,
            adapter: parts.adapter,
            control_lease_authority: parts.control_lease_authority,
            admission,
            pending_bounded_uses: BTreeMap::new(),
            authorized_bounded_uses: BTreeMap::new(),
            admission_token_history,
            invalidated_bounded_use_ids: BTreeSet::new(),
            pending_control_lease_lifecycle_uses: BTreeMap::new(),
            authorized_control_lease_lifecycle_uses: BTreeMap::new(),
            invalidated_control_lease_lifecycle_use_ids: BTreeSet::new(),
            control_lease_revocation_use_invalidations: BTreeMap::new(),
            control_lease_revocation_barriers: BTreeMap::new(),
            control_lease_revocation_recovery_receipts: Vec::new(),
            control_lease_revocation_consumer_acknowledgements: BTreeMap::new(),
            committed_mutation_receipts: Vec::new(),
            committed_capability_use_receipts: Vec::new(),
            compacted_control_lease_request_ids: BTreeSet::new(),
            consumed_bounded_use_ids: BTreeSet::new(),
            control_lease_lifecycle_receipts: Vec::new(),
            source_bound_root_reestablishments: Vec::new(),
        });
        validate_runtime_evidence_size(
            &self
                .runtime
                .as_ref()
                .expect("retained candidate")
                .evidence(),
        )?;
        self.validated = true;
        Ok(())
    }
    /// Borrow the SAME validated constructed owner for its real ongoing/root
    /// joins. The enclosing arena remains responsible if a later join refuses.
    pub fn runtime_mut(
        &mut self,
    ) -> Result<&mut ManifoldBrokerRuntime, ManifoldBrokerRuntimeStateError> {
        if !self.validated {
            return Err(ManifoldBrokerRuntimeStateError::InvalidEvidence(
                "unpublished_constructor_not_ready",
            ));
        }
        self.runtime
            .as_mut()
            .ok_or(ManifoldBrokerRuntimeStateError::InvalidEvidence(
                "unpublished_constructor_owner_absent",
            ))
    }
    /// Move the actual validated owner to the provider; never reconstruct it.
    pub fn take_runtime(
        &mut self,
    ) -> Result<ManifoldBrokerRuntime, ManifoldBrokerRuntimeStateError> {
        if !self.validated {
            return Err(ManifoldBrokerRuntimeStateError::InvalidEvidence(
                "unpublished_constructor_not_ready",
            ));
        }
        self.validated = false;
        self.runtime
            .take()
            .ok_or(ManifoldBrokerRuntimeStateError::InvalidEvidence(
                "unpublished_constructor_owner_absent",
            ))
    }
    /// Exact current owner data for explicit unpublished-construction custody.
    /// This projection is neither a writable restore nor completed cleanup.
    pub fn source_observation(&self) -> Result<serde_json::Value, ManifoldBrokerRuntimeStateError> {
        let parts=self.parts.as_ref().map(|p|serde_json::json!({"provider_epoch_id":p.provider_epoch_id,
            "adapter_config":p.adapter.config(),"host_snapshot":p.adapter.host_snapshot(),
            "control_lease_authority":p.control_lease_authority.evidence(),"admission_snapshot":p.admission_snapshot}));
        Ok(
            serde_json::json!({"$schema":"rusty.manifold.broker.unpublished_construction.v1",
            "attempted":self.attempted,"validated":self.validated,"parts":parts,
            "runtime":self.runtime.as_ref().map(|r|r.evidence()),"writable_restore":"unsupported_preserve_actual_history"}),
        )
    }
    /// Read actual candidate evidence without constructing another owner.
    pub fn runtime_evidence(&self) -> Option<ManifoldBrokerRuntimeEvidence> {
        self.runtime.as_ref().map(|r| r.evidence())
    }
}
