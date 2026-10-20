//! Child of runtime.rs: exact selected-owner staged root transaction.
use super::*;
use rusty_manifold_admission::{
    ManifoldSourceBoundGrantReestablishmentReceipt, ManifoldSourceBoundGrantReestablishmentRequest,
};
use rusty_manifold_model::{
    ManifoldClockSnapshot, ManifoldSourceBoundControlLeaseReestablishmentRequest,
};
use rusty_manifold_runtime_host::{ManifoldSourceBoundRootPermit, ManifoldSourceBoundRootVerifier};
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldSourceBoundRootReestablishmentRequest {
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    pub request_id: DottedId,
    pub grant: ManifoldSourceBoundGrantReestablishmentRequest,
    pub lease: ManifoldSourceBoundControlLeaseReestablishmentRequest,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldSourceBoundRootReestablishmentReceipt {
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    pub request: ManifoldSourceBoundRootReestablishmentRequest,
    pub provider_epoch_id: DottedId,
    pub admission: Option<ManifoldSourceBoundGrantReestablishmentReceipt>,
    pub control_lease_transition: Option<ManifoldBrokerControlLeaseTransition>,
    pub runtime_adoption: Option<ManifoldRuntimeControlLeaseAdoptionReceipt>,
    pub observed_at_ms: u64,
}
#[derive(Debug)]
pub struct ManifoldSourceBoundRootReestablishmentPlan {
    source_sha256: String,
    candidate: ManifoldBrokerRuntime,
    receipt: ManifoldSourceBoundRootReestablishmentReceipt,
}
/// The verified publication keeps both the actual Broker and actual permit
/// borrowed until commit; consuming the issuer sequence in between is illegal.
/// ```compile_fail
/// use rusty_manifold_broker_adapter::{ManifoldBrokerRuntime,ManifoldSourceBoundRootReestablishmentPlan};
/// use rusty_manifold_runtime_host::ManifoldSourceBoundRootPermit;
/// fn consume_before_publish(b:&mut ManifoldBrokerRuntime,p:ManifoldSourceBoundRootPermit<'_>,plan:ManifoldSourceBoundRootReestablishmentPlan){
///     let verified=b.verify_source_bound_root_reestablishment(&p,plan,100).unwrap();
///     p.commit(); // cannot consume while the verified publication borrows p
///     verified.commit();
/// }
/// ```
pub struct ManifoldVerifiedSourceBoundRootReestablishment<'owner, 'permit, 'issuer> {
    owner: &'owner mut ManifoldBrokerRuntime,
    _permit: &'permit ManifoldSourceBoundRootPermit<'issuer>,
    plan: ManifoldSourceBoundRootReestablishmentPlan,
}
fn invalid(message: &'static str) -> ManifoldBrokerRuntimeStateError {
    ManifoldBrokerRuntimeStateError::InvalidEvidence(message)
}
fn hash<T: Serialize>(value: &T) -> Result<String, ManifoldBrokerRuntimeStateError> {
    let mut h = Sha256::new();
    h.update(b"rusty.manifold.broker.source_bound_root_plan.v1\0");
    h.update(serde_json::to_vec(value).map_err(|_| invalid("root encoding"))?);
    Ok(format!("sha256:{:x}", h.finalize()))
}
impl ManifoldBrokerRuntime {
    pub fn source_bound_root_target(&self) -> Option<(&DottedId, &DottedId)> {
        self.admission.source_bound_root_target()
    }
    pub fn register_source_bound_root_owner(
        &mut self,
        verifier: ManifoldSourceBoundRootVerifier,
        grant_id: DottedId,
        lease_id: DottedId,
        now: u64,
    ) -> Result<(), ManifoldBrokerRuntimeStateError> {
        if self.history_checkpoint.is_none() || !self.source_bound_root_reestablishments.is_empty()
        {
            return Err(invalid(
                "root registration requires pristine actual ongoing Broker",
            ));
        }
        let mut staged = self.staged_copy()?;
        staged
            .admission
            .register_source_bound_root_owner(verifier.clone(), grant_id, lease_id.clone(), now)
            .map_err(|_| invalid("root admission registration"))?;
        staged
            .adapter
            .host
            .register_source_bound_root_owner(verifier, lease_id)
            .map_err(|_| invalid("root Host registration"))?;
        *self = staged;
        Ok(())
    }
    pub fn plan_source_bound_root_reestablishment(
        &self,
        permit: &ManifoldSourceBoundRootPermit<'_>,
        request: &ManifoldSourceBoundRootReestablishmentRequest,
        clock: ManifoldClockSnapshot,
        now: u64,
    ) -> Result<ManifoldSourceBoundRootReestablishmentPlan, ManifoldBrokerRuntimeStateError> {
        if self.history_checkpoint.is_none()
            || request.schema_id.as_str()
                != "rusty.manifold.broker.source_bound_root_reestablishment_request.v1"
            || request.request_id != permit.evidence().request_id
            || request.grant.authority != *permit.evidence()
            || request.lease.authority != *permit.evidence()
            || u64::try_from(clock.wall_unix_ms).ok() != Some(now)
            || request.lease.prior_lease.holder_id != request.grant.prior_grant.identity.client_id
            || !request
                .grant
                .prior_grant
                .capabilities
                .contains(&request.lease.prior_lease.required_capability)
            || request.lease.prior_lease.scope.as_str() != "lease.media.session"
            || self.source_bound_root_reestablishments.len() >= MAX_BROKER_CONTROL_LEASE_TRANSITIONS
        {
            return Err(invalid("root actual source/scope/clock/capacity"));
        }
        self.admission
            .validate_source_bound_root_permit(permit, now)
            .map_err(|_| invalid("root actual registered admission owner"))?;
        if self
            .admission_snapshot()
            .grants
            .iter()
            .find(|g| g.grant_id == request.grant.prior_grant.grant_id)
            != Some(&request.grant.prior_grant)
            || self
                .control_lease_authority_snapshot()
                .active_leases
                .iter()
                .find(|l| l.lease_id == request.lease.prior_lease.lease_id)
                != Some(&request.lease.prior_lease)
        {
            return Err(invalid("root component actual preimage"));
        }
        let grant_needed = request.grant.prior_grant.expires_at_ms <= now;
        let lease_needed = request.lease.prior_lease.expires_at_ms <= now;
        if (!grant_needed && !lease_needed)
            || (!grant_needed
                && request.grant.expires_at_ms != request.grant.prior_grant.expires_at_ms)
            || (!lease_needed
                && request.lease.expires_at_ms != request.lease.prior_lease.expires_at_ms)
        {
            return Err(invalid(
                "root retain current components exact/no empty effect",
            ));
        }
        let source_sha256 = hash(&self.evidence())?;
        let mut staged = self.staged_copy()?;
        // Admission verifies the registered actual M issuer. No expired token
        // use is fabricated, and nothing publishes until every owner closes.
        let admission = if grant_needed {
            Some(
                staged
                    .admission
                    .reestablish_source_bound_grant(permit, &request.grant, now)
                    .map_err(|_| invalid("root admission application"))?,
            )
        } else {
            None
        };
        let (transition, runtime_adoption) = if lease_needed {
            let transition = staged
                .control_lease_authority
                .reestablish_source_bound_control_lease(request.lease.clone(), clock)
                .map_err(ManifoldBrokerRuntimeStateError::ControlLeaseAuthority)?;
            let application = match &transition.application {
                ManifoldBrokerControlLeaseTransitionApplication::SourceBoundReestablishment(a) => {
                    a.clone()
                }
                _ => return Err(invalid("root exact lease operation")),
            };
            let suffix = DottedId::new(format!("adoption.{}", application.request.request_id))
                .map_err(|_| invalid("root adoption identity"))?;
            let adoption_request = ManifoldRuntimeControlLeaseAdoptionRequest {
                schema_id: schema_id(
                    "rusty.manifold.runtime_host.control_lease_adoption_request.v3",
                ),
                adoption_id: staged.current_host_history_request_id(&suffix)?,
                expected_host_authority_revision: staged.adapter.host_snapshot().authority_revision,
                prior_authority_snapshot: transition.prior_authority_snapshot.clone(),
                application:
                    ManifoldRuntimeControlLeaseAuthorityApplication::SourceBoundReestablishment(
                        application,
                    ),
            };
            let runtime_adoption = staged
                .adapter
                .host
                .apply_source_bound_control_lease_adoption(permit, &adoption_request, now)
                .map_err(|_| invalid("root Host registered permit/application"))?;
            if !runtime_adoption.applied {
                return Err(invalid("root Host adoption refused"));
            }
            (Some(transition), Some(runtime_adoption))
        } else {
            (None, None)
        };
        staged
            .control_lease_authority
            .validate_host_snapshot(staged.adapter.host_snapshot())
            .map_err(ManifoldBrokerRuntimeStateError::ControlLeaseAuthority)?;
        let receipt = ManifoldSourceBoundRootReestablishmentReceipt {
            schema_id: schema_id(
                "rusty.manifold.broker.source_bound_root_reestablishment_receipt.v1",
            ),
            request: request.clone(),
            provider_epoch_id: self.provider_epoch_id.clone(),
            admission,
            control_lease_transition: transition,
            runtime_adoption,
            observed_at_ms: now,
        };
        staged
            .source_bound_root_reestablishments
            .push(receipt.clone());
        // Re-run full current source composition over the actual candidate,
        // preserving its registered verifier and actual admission/history anchor.
        let evidence = staged.evidence();
        if !source_bound_root_receipts_close(&evidence) {
            return Err(invalid("root receipt owner lineage"));
        }
        let candidate = staged.staged_copy()?;
        Ok(ManifoldSourceBoundRootReestablishmentPlan {
            source_sha256,
            candidate,
            receipt,
        })
    }
    pub fn verify_source_bound_root_reestablishment<'owner, 'permit, 'issuer>(
        &'owner mut self,
        permit: &'permit ManifoldSourceBoundRootPermit<'issuer>,
        plan: ManifoldSourceBoundRootReestablishmentPlan,
        now: u64,
    ) -> Result<
        ManifoldVerifiedSourceBoundRootReestablishment<'owner, 'permit, 'issuer>,
        ManifoldBrokerRuntimeStateError,
    > {
        self.admission
            .validate_source_bound_root_permit(permit, now)
            .map_err(|_| invalid("root final actual admission issuer/sequence"))?;
        self.adapter
            .host
            .validate_source_bound_root_permit(permit, now)
            .map_err(|_| invalid("root final actual Host issuer/sequence"))?;
        if hash(&self.evidence())? != plan.source_sha256
            || plan.receipt.request.grant.authority != *permit.evidence()
        {
            return Err(invalid("root source changed before commit"));
        }
        Ok(ManifoldVerifiedSourceBoundRootReestablishment {
            owner: self,
            _permit: permit,
            plan,
        })
    }
}
impl ManifoldSourceBoundRootReestablishmentPlan {
    pub fn receipt(&self) -> &ManifoldSourceBoundRootReestablishmentReceipt {
        &self.receipt
    }
}
impl ManifoldVerifiedSourceBoundRootReestablishment<'_, '_, '_> {
    pub fn receipt_for_enclosing_owner(&self) -> &ManifoldSourceBoundRootReestablishmentReceipt {
        &self.plan.receipt
    }
    pub fn commit(self) -> ManifoldSourceBoundRootReestablishmentReceipt {
        *self.owner = self.plan.candidate;
        self.plan.receipt
    }
}

fn lease_at_revision<'a>(
    e: &'a ManifoldBrokerControlLeaseAuthorityEvidenceV2,
    revision: Revision,
) -> Option<&'a rusty_manifold_model::ManifoldAuthoritySnapshot> {
    if e.current_authority_snapshot.authority_revision == revision {
        return Some(&e.current_authority_snapshot);
    }
    if e.baseline.current_authority_snapshot.authority_revision == revision {
        return Some(&e.baseline.current_authority_snapshot);
    }
    e.transitions.iter().find_map(|t| {
        if t.prior_authority_snapshot.authority_revision == revision {
            Some(&t.prior_authority_snapshot)
        } else {
            t.application
                .applied_snapshot()
                .filter(|s| s.authority_revision == revision)
        }
    })
}
pub(super) fn source_bound_root_receipts_close(e: &ManifoldBrokerRuntimeEvidence) -> bool {
    if !e.source_bound_root_reestablishments.is_empty() && e.history_checkpoint.is_none() {
        return false;
    }
    let mut ids = BTreeSet::new();
    e.source_bound_root_reestablishments.iter().all(|r| {
        let root = &r.request;
        let now = r.observed_at_ms;
        if r.schema_id.as_str()
            != "rusty.manifold.broker.source_bound_root_reestablishment_receipt.v1"
            || root.schema_id.as_str()
                != "rusty.manifold.broker.source_bound_root_reestablishment_request.v1"
            || r.provider_epoch_id != e.provider_epoch_id
            || !ids.insert(root.request_id.clone())
            || root.request_id != root.grant.authority.request_id
            || root.grant.authority != root.lease.authority
            || root.grant.authority.validate_at(now).is_err()
            || root.lease.prior_lease.holder_id != root.grant.prior_grant.identity.client_id
            || !root
                .grant
                .prior_grant
                .capabilities
                .contains(&root.lease.prior_lease.required_capability)
            || root.lease.prior_lease.scope.as_str() != "lease.media.session"
            || rusty_manifold_admission::source_bound_grant_at_revision(
                &e.admission_snapshot,
                &root.grant.prior_grant.grant_id,
                root.grant.expected_authority_revision,
            )
            .map_or(true, |g| g != root.grant.prior_grant)
            || lease_at_revision(
                &e.control_lease_authority,
                root.lease.expected_authority_revision,
            )
            .and_then(|s| {
                s.active_leases
                    .iter()
                    .find(|l| l.lease_id == root.lease.prior_lease.lease_id)
            }) != Some(&root.lease.prior_lease)
        {
            return false;
        }
        let grant_closes =
            match &r.admission {
                Some(a) => root.grant == a.binding.request
                    && root.grant.prior_grant.expires_at_ms <= now
                    && a.application.applied
                    && a.application.operation
                        == rusty_manifold_admission::ManifoldAdmissionOperation::ReestablishGrant
                    && a.application.request_id == root.grant.request_id
                    && a.binding.observed_at_ms == now
                    && e.admission_snapshot
                        .audit_events
                        .iter()
                        .filter(|event| {
                            event.request_id == root.grant.request_id
                                && event.grant_reestablishment.as_ref() == Some(&a.binding)
                                && event.prior_authority_revision
                                    == a.application.prior_authority_revision
                                && event.resulting_authority_revision
                                    == a.application.resulting_authority_revision
                                && event.applied
                        })
                        .count()
                        == 1,
                None => {
                    root.grant.prior_grant.expires_at_ms > now
                        && !root.grant.prior_grant.revoked
                        && root.grant.expires_at_ms == root.grant.prior_grant.expires_at_ms
                }
            };
        let lease_closes = match (&r.control_lease_transition, &r.runtime_adoption) {
            (Some(t), Some(h)) => {
                let ManifoldBrokerControlLeaseTransitionApplication::SourceBoundReestablishment(a) =
                    &t.application
                else {
                    return false;
                };
                root.lease == a.request
                    && root.lease.prior_lease.expires_at_ms <= now
                    && e.control_lease_authority
                        .transitions
                        .iter()
                        .filter(|v| *v == t)
                        .count()
                        == 1
                    && a.validate_against_snapshot(&t.prior_authority_snapshot)
                        .is_ok()
                    && control_lease_host_adoption_closes(h, t, &e.host_snapshot)
            }
            (None, None) => {
                root.lease.prior_lease.expires_at_ms > now
                    && root.lease.prior_lease.state == rusty_manifold_model::LeaseState::Active
                    && root.lease.expires_at_ms == root.lease.prior_lease.expires_at_ms
            }
            _ => false,
        };
        grant_closes
            && lease_closes
            && (r.admission.is_some() || r.control_lease_transition.is_some())
    }) && e
        .control_lease_authority
        .transitions
        .iter()
        .filter(|t| {
            matches!(
                t.application,
                ManifoldBrokerControlLeaseTransitionApplication::SourceBoundReestablishment(_)
            )
        })
        .all(|t| {
            e.source_bound_root_reestablishments
                .iter()
                .filter(|r| r.control_lease_transition.as_ref() == Some(t))
                .count()
                == 1
        })
}

/// Metadata checkpoint candidate from the actual Broker, retaining exact current
/// M dependency IDs. No new grant/lease/media permission is issued.
pub struct ManifoldDormantRootHistoryPlan {
    source_sha256: String,
    candidate: ManifoldBrokerRuntime,
    checkpoint: ManifoldBrokerHistoryCheckpoint,
}
impl ManifoldDormantRootHistoryPlan {
    pub fn candidate(&self) -> &ManifoldBrokerRuntime {
        &self.candidate
    }
}
impl ManifoldBrokerRuntime {
    pub fn has_source_bound_root_suffix(&self) -> bool {
        !self.source_bound_root_reestablishments.is_empty()
    }
    pub fn plan_dormant_root_history(
        &self,
        pins: &[DottedId],
        now: u64,
    ) -> Result<ManifoldDormantRootHistoryPlan, ManifoldBrokerRuntimeStateError> {
        if self.source_bound_root_target().is_none() || !self.has_source_bound_root_suffix() {
            return Err(invalid(
                "dormant root history has no selected completed suffix",
            ));
        }
        let source_sha256 = hash(&self.evidence())?;
        let mut candidate = self.staged_copy()?;
        let checkpoint = candidate.checkpoint_ongoing_history(pins, now)?;
        Ok(ManifoldDormantRootHistoryPlan {
            source_sha256,
            candidate,
            checkpoint,
        })
    }
    pub fn commit_dormant_root_history(
        &mut self,
        plan: ManifoldDormantRootHistoryPlan,
    ) -> Result<ManifoldBrokerHistoryCheckpoint, ManifoldBrokerRuntimeStateError> {
        if hash(&self.evidence())? != plan.source_sha256 {
            return Err(invalid("dormant root history source changed"));
        }
        *self = plan.candidate;
        Ok(plan.checkpoint)
    }
}

#[cfg(test)]
mod commit_controls {
    use super::*;
    use rusty_manifold_runtime_host::{ManifoldRuntimeLease, ManifoldSourceBoundRootIssuer};
    fn id(s: &str) -> DottedId {
        DottedId::new(s).unwrap()
    }
    fn fixture() -> (
        ManifoldBrokerRuntime,
        ManifoldSourceBoundRootIssuer,
        ManifoldSourceBoundRootReestablishmentRequest,
        ManifoldClockSnapshot,
        u64,
    ) {
        let prior_wall = 1_765_000_000_100u64;
        let mut b = super::super::tests::runtime(
            vec![rusty_manifold_broker_product::ManifoldBrokerFeature::MediaSession],
            vec![id("capability.broker.runtime.test")],
            vec![ManifoldRuntimeLease {
                lease_id: id("lease.root.control"),
                scope: id("lease.media.session"),
                holder_id: id("client.runtime.test"),
                expires_at_ms: prior_wall + 30_000,
                derivative_binding: None,
            }],
            "epoch.root.control",
        );
        b.enable_ongoing_history().unwrap();
        let (mut issuer, verifier) = ManifoldSourceBoundRootIssuer::new_selected_owner();
        b.register_source_bound_root_owner(
            verifier,
            id("grant.runtime.test"),
            id("lease.root.control"),
            prior_wall,
        )
        .unwrap();
        let now = prior_wall + 40_000;
        let sha = format!("sha256:{}", "a1".repeat(32));
        let authority=serde_json::from_value::<rusty_manifold_model::ManifoldSourceBoundRootEvidence>(serde_json::json!({"$schema":"rusty.manifold.authority.source_bound_root.v1",
        "request_id":"request.root.control","sequence":1,"peer_host_id":"host.root.control","provider_epoch_id":"epoch.root.control",
        "native_setup_request_id":"ceremony.duplex.control","native_phase_id":"ceremony.duplex.control-phase","grant_id":"grant.runtime.test","lease_id":"lease.root.control",
        "peer_disposition":"never_started","lifetime_ordinal":0,"prior_start_sha256":null,"terminal_stop_sha256":null,
        "native_lifecycle_sha256":sha,"native_actor_sha256":sha,"runtime_configuration_sha256":sha,"arm_binding_sha256":sha,
        "selected_policy_sha256":sha,"source_peer_snapshot_sha256":sha,"fresh_setup_receipt_sha256":sha,"current_pair_sha256":sha,"current_floor_sha256":sha,
        "observed_at_ms":now,"actual_authority_expires_at_ms":now+10_000})).unwrap();
        let grant = b.admission_snapshot().grants[0].clone();
        let lease = b
            .control_lease_authority_snapshot()
            .active_leases
            .iter()
            .find(|l| l.lease_id == id("lease.root.control"))
            .unwrap()
            .clone();
        let request=ManifoldSourceBoundRootReestablishmentRequest{schema_id:schema_id("rusty.manifold.broker.source_bound_root_reestablishment_request.v1"),request_id:authority.request_id.clone(),
        grant:ManifoldSourceBoundGrantReestablishmentRequest{schema_id:schema_id("rusty.manifold.admission.source_bound_grant_reestablishment_request.v1"),request_id:b.current_admission_history_request_id(&id("request.root.control.grant")).unwrap(),expected_authority_revision:b.admission_snapshot().authority_revision,expires_at_ms:grant.expires_at_ms,prior_grant:grant,authority:authority.clone()},
        lease:ManifoldSourceBoundControlLeaseReestablishmentRequest{schema_id:schema_id("rusty.manifold.authority.source_bound_control_lease_reestablishment_request.v1"),request_id:b.current_control_history_request_id(&id("request.root.control.lease")).unwrap(),expected_authority_revision:b.control_lease_authority_snapshot().authority_revision,expires_at_ms:now+5_000,prior_lease:lease,authority}};
        let mut clock = b.control_lease_authority_snapshot().clock_snapshot.clone();
        clock.sequence += 1;
        clock.wall_unix_ms = now as i64;
        clock.monotonic_elapsed_ns += 40_000_000_000;
        assert_eq!(issuer.next_sequence().unwrap(), 1);
        (b, issuer, request, clock, now)
    }
    #[test]
    fn real_plan_refuses_foreign_issuer_with_identical_serialized_evidence_at_final_boundary() {
        let (mut b, mut owner, request, clock, now) = fixture();
        let before = b.evidence();
        let real = owner
            .borrow_current(request.grant.authority.clone(), now)
            .unwrap();
        let plan = b
            .plan_source_bound_root_reestablishment(&real, &request, clock, now)
            .unwrap();
        drop(real);
        let (mut foreign, _) = ManifoldSourceBoundRootIssuer::new_selected_owner();
        let foreign = foreign
            .borrow_current(request.grant.authority.clone(), now)
            .unwrap();
        assert!(b
            .verify_source_bound_root_reestablishment(&foreign, plan, now)
            .is_err());
        assert_eq!(b.evidence(), before);
    }
    #[test]
    fn same_owner_sequence_is_consumed_only_after_real_plan_commit_then_cannot_be_reborrowed() {
        let (mut b, mut owner, request, clock, now) = fixture();
        let permit = owner
            .borrow_current(request.grant.authority.clone(), now)
            .unwrap();
        let plan = b
            .plan_source_bound_root_reestablishment(&permit, &request, clock, now)
            .unwrap();
        let verified = b
            .verify_source_bound_root_reestablishment(&permit, plan, now)
            .unwrap();
        let result = verified.commit();
        permit.commit();
        assert!(result.control_lease_transition.is_some());
        assert!(owner.borrow_current(request.grant.authority, now).is_err());
    }
}
