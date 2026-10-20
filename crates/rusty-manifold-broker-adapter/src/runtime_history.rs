//! Exclusive Broker composition of live authority history checkpoints.
use super::*;

/// Explicit core projection with live checkpoints. Complete cleanup storage remains separate.
pub const ONGOING_BROKER_RUNTIME_EVIDENCE_SCHEMA: &str =
    "rusty.manifold.broker.runtime_evidence.v7";

/// Latest bounded Broker checkpoint, created only from its actual exclusive owner.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerHistoryCheckpoint {
    /// Storage schema.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Global checkpoint count; zero is prospective policy selection.
    pub checkpoint_sequence: u64,
    /// Monotonic count of consumed one-use decisions checkpointed so far.
    pub consumed_use_count: u64,
    /// Monotonic count of completed command mutation attempts checkpointed so far.
    pub mutation_count: u64,
    /// Monotonic count of lifecycle attempts checkpointed so far.
    pub lifecycle_count: u64,
    /// Exact accepted mutations pinned by still-live downstream lease obligations.
    pub retained_mutations: Vec<ManifoldBrokerMutationReceipt>,
    /// Complete accepted source-evidence commitment; never a restore credential.
    pub source_evidence_sha256: String,
    /// Prior checkpoint commitment, never its recursive body.
    pub prior_checkpoint_sha256: Option<String>,
}

/// Private-field borrowed restore authority from the actual current Broker.
#[derive(Debug)]
pub struct ManifoldBrokerHistoryRestoreAnchor<'owner> {
    owner: &'owner ManifoldBrokerRuntime,
    evidence_sha256: String,
}

/// Immutable checkpoint transaction minted from the actual owner. Its private
/// candidate cannot dispatch, consume uses or supply a replacement live baseline.
#[derive(Debug)]
pub struct ManifoldBrokerHistoryCheckpointPlan {
    source_evidence_sha256: String,
    candidate: ManifoldBrokerRuntime,
    checkpoint: ManifoldBrokerHistoryCheckpoint,
}

/// Exact-current checkpoint plan borrowing the exclusive actual Broker gate.
pub struct ManifoldVerifiedBrokerHistoryCheckpoint<'owner> {
    owner: &'owner mut ManifoldBrokerRuntime,
    plan: ManifoldBrokerHistoryCheckpointPlan,
}
impl ManifoldVerifiedBrokerHistoryCheckpoint<'_> {
    /// Infallible publication after every enclosing plan has been validated.
    pub fn commit(self) -> ManifoldBrokerHistoryCheckpoint {
        *self.owner = self.plan.candidate;
        self.plan.checkpoint
    }
}
impl ManifoldBrokerHistoryCheckpointPlan {
    /// Proposed evidence for enclosing-owner validation; no restore authority.
    pub fn evidence(&self) -> ManifoldBrokerRuntimeEvidence {
        self.candidate.evidence()
    }
    /// Completed-prefix commitment proposed by this exact source plan.
    pub fn checkpoint(&self) -> &ManifoldBrokerHistoryCheckpoint {
        &self.checkpoint
    }
}

fn digest<T: Serialize>(value: &T) -> Result<String, ManifoldBrokerRuntimeStateError> {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"rusty.manifold.broker.ongoing_history.sha256.v1\0");
    hash.update(
        serde_json::to_vec(value)
            .map_err(|_| ManifoldBrokerRuntimeStateError::InvalidEvidence("history_encode"))?,
    );
    Ok(format!("sha256:{:x}", hash.finalize()))
}

pub(super) fn admission_audits(
    snapshot: &ManifoldAdmissionSnapshot,
) -> impl Iterator<Item = &rusty_manifold_admission::ManifoldAdmissionAuditEvent> {
    snapshot.audit_events.iter().chain(
        snapshot
            .history_checkpoint
            .iter()
            .flat_map(|c| c.retained_use_authorizations.iter()),
    )
}
pub(super) fn baseline_token(
    snapshot: &ManifoldAdmissionSnapshot,
    token: &ManifoldAdmissionToken,
) -> bool {
    snapshot.history_checkpoint.as_ref().is_some_and(|c| {
        c.active_tokens.contains(token)
            || c.retained_use_authorizations.iter().any(|e| {
                e.use_authorization
                    .as_ref()
                    .is_some_and(|b| b.token == *token)
            })
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn committed_mutation_suffix_closes(
    checkpoint: Option<&ManifoldBrokerHistoryCheckpoint>,
    receipts: &[ManifoldBrokerMutationReceipt],
    epoch: &DottedId,
    config: &ManifoldBrokerAdapterConfig,
    host: &ManifoldRuntimeHostSnapshot,
    consumed: &BTreeSet<DottedId>,
    authorized: &BTreeMap<DottedId, ManifoldBrokerBoundedUse>,
    admission: &ManifoldAdmissionSnapshot,
    tokens: &BTreeMap<DottedId, ManifoldAdmissionToken>,
) -> bool {
    let Some(c) = checkpoint else {
        return committed_mutation_receipts_close(
            receipts, epoch, config, host, consumed, authorized, admission, tokens,
        );
    };
    if c.schema_id.as_str() != "rusty.manifold.broker.history_checkpoint.v1"
        || (c.checkpoint_sequence > 0) != c.prior_checkpoint_sha256.is_some()
        || !valid_hash(&c.source_evidence_sha256)
        || c.prior_checkpoint_sha256
            .as_ref()
            .is_some_and(|h| !valid_hash(h))
        || c.mutation_count
            .checked_add(c.lifecycle_count)
            .map_or(true, |n| n > c.consumed_use_count)
        || c.mutation_count < c.retained_mutations.len() as u64
        || c.retained_mutations.len() > crate::MAX_BROKER_CONTROL_LEASES
        || c.retained_mutations
            .windows(2)
            .any(|w| w[0].admission_use_request_id >= w[1].admission_use_request_id)
        || c.retained_mutations
            .iter()
            .any(|r| !r.applied || &r.provider_epoch_id != epoch || !receipts.contains(r))
        || admission.history_checkpoint.is_none()
        || host.history_checkpoint.is_none()
    {
        return false;
    }
    let pinned = c
        .retained_mutations
        .iter()
        .map(|r| &r.admission_use_request_id)
        .collect::<BTreeSet<_>>();
    let suffix = receipts
        .iter()
        .filter(|r| !pinned.contains(&r.admission_use_request_id))
        .cloned()
        .collect::<Vec<_>>();
    committed_mutation_receipts_close(
        &suffix, epoch, config, host, consumed, authorized, admission, tokens,
    )
}

fn valid_hash(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn add_count(
    base: u64,
    current: usize,
    retained: usize,
) -> Result<u64, ManifoldBrokerRuntimeStateError> {
    current
        .checked_sub(retained)
        .and_then(|n| u64::try_from(n).ok())
        .and_then(|n| base.checked_add(n))
        .ok_or(ManifoldBrokerRuntimeStateError::InvalidEvidence(
            "history_counter_exhausted",
        ))
}

impl ManifoldBrokerRuntime {
    /// Stages compaction without changing the live owner. This is a checkpoint
    /// plan only, never a command or one-use decision preview/rollback route.
    pub fn plan_ongoing_history_checkpoint(
        &self,
        retained_use_ids: &[DottedId],
        now_ms: u64,
    ) -> Result<ManifoldBrokerHistoryCheckpointPlan, ManifoldBrokerRuntimeStateError> {
        let source_evidence_sha256 = digest(&self.evidence())?;
        let mut candidate = self.staged_copy()?;
        let checkpoint = candidate.checkpoint_ongoing_history(retained_use_ids, now_ms)?;
        Ok(ManifoldBrokerHistoryCheckpointPlan {
            source_evidence_sha256,
            candidate,
            checkpoint,
        })
    }
    /// The caller holds the actual exclusive Broker gate alongside the enclosing
    /// Peer gate. Exact-current validation precedes infallible owner publication.
    pub fn commit_ongoing_history_checkpoint(
        &mut self,
        plan: ManifoldBrokerHistoryCheckpointPlan,
    ) -> Result<ManifoldBrokerHistoryCheckpoint, ManifoldBrokerRuntimeStateError> {
        Ok(self.verify_ongoing_history_checkpoint(plan)?.commit())
    }
    /// Holds the exact current owner exclusively until enclosing publication.
    pub fn verify_ongoing_history_checkpoint(
        &mut self,
        plan: ManifoldBrokerHistoryCheckpointPlan,
    ) -> Result<ManifoldVerifiedBrokerHistoryCheckpoint<'_>, ManifoldBrokerRuntimeStateError> {
        if digest(&self.evidence())? != plan.source_evidence_sha256 {
            return Err(ManifoldBrokerRuntimeStateError::InvalidEvidence(
                "history_checkpoint_plan_stale",
            ));
        }
        Ok(ManifoldVerifiedBrokerHistoryCheckpoint { owner: self, plan })
    }
    /// Selects prospective checkpoints on this exact fresh owner. Existing live
    /// leases, grants, provider epoch, clocks and resource identities are unchanged.
    pub fn enable_ongoing_history(&mut self) -> Result<(), ManifoldBrokerRuntimeStateError> {
        if self.history_checkpoint.is_some() {
            self.staged_copy()?;
            return Ok(());
        }
        if !self.cleanup_registrations.is_empty()
            || !self.pending_bounded_uses.is_empty()
            || !self.pending_control_lease_lifecycle_uses.is_empty()
            || !self.control_lease_revocation_barriers.is_empty()
        {
            return Err(ManifoldBrokerRuntimeStateError::InvalidEvidence(
                "ongoing_initial_owner_obligations",
            ));
        }
        let mut candidate = self.staged_copy()?;
        candidate
            .admission
            .enable_ongoing_history()
            .map_err(ManifoldBrokerRuntimeStateError::Admission)?;
        candidate
            .adapter
            .host
            .enable_ongoing_history()
            .map_err(|_| {
                ManifoldBrokerRuntimeStateError::InvalidEvidence("ongoing_host_selection")
            })?;
        candidate
            .control_lease_authority
            .enable_ongoing_history()
            .map_err(ManifoldBrokerRuntimeStateError::ControlLeaseAuthority)?;
        candidate.history_checkpoint = Some(ManifoldBrokerHistoryCheckpoint {
            schema_id: schema_id("rusty.manifold.broker.history_checkpoint.v1"),
            checkpoint_sequence: 0,
            consumed_use_count: 0,
            mutation_count: 0,
            lifecycle_count: 0,
            retained_mutations: Vec::new(),
            source_evidence_sha256: digest(&self.evidence())?,
            prior_checkpoint_sha256: None,
        });
        candidate.staged_copy()?;
        *self = candidate;
        Ok(())
    }

    /// Qualifies a new admission identity with the actual Admission owner epoch.
    pub fn current_admission_history_request_id(
        &self,
        suffix: &DottedId,
    ) -> Result<DottedId, ManifoldBrokerRuntimeStateError> {
        self.admission
            .current_history_request_id(suffix)
            .map_err(ManifoldBrokerRuntimeStateError::Admission)
    }
    /// Qualifies a new command/adoption identity with the actual Runtime Host epoch.
    pub fn current_host_history_request_id(
        &self,
        suffix: &DottedId,
    ) -> Result<DottedId, ManifoldBrokerRuntimeStateError> {
        self.adapter
            .host
            .current_history_request_id(suffix)
            .map_err(|_| ManifoldBrokerRuntimeStateError::InvalidEvidence("history_host_identity"))
    }
    /// Qualifies a new generic lifecycle identity with its actual owner epoch.
    pub fn current_control_history_request_id(
        &self,
        suffix: &DottedId,
    ) -> Result<DottedId, ManifoldBrokerRuntimeStateError> {
        self.control_lease_authority
            .current_history_request_id(suffix)
            .map_err(ManifoldBrokerRuntimeStateError::ControlLeaseAuthority)
    }
    pub(super) fn control_history_request_matches(&self, id: &DottedId) -> bool {
        self.control_lease_authority
            .evidence()
            .history_checkpoint
            .as_ref()
            .map_or(true, |c| {
                id.as_str()
                    .strip_prefix(&format!("history.{}.", c.request_epoch))
                    .is_some_and(|s| !s.is_empty() && !s.starts_with("history."))
            })
    }

    /// Compacts completed state under this exclusive mutation gate. Caller ids
    /// may select existing accepted live-obligation proofs, never supply bodies.
    /// Pending uses, revocation barriers and cleanup registrations refuse this
    /// supported mode. The embedding must also finish its product adoption.
    pub fn checkpoint_ongoing_history(
        &mut self,
        retained_use_ids: &[DottedId],
        now_ms: u64,
    ) -> Result<ManifoldBrokerHistoryCheckpoint, ManifoldBrokerRuntimeStateError> {
        if !self.pending_bounded_uses.is_empty()
            || !self.pending_control_lease_lifecycle_uses.is_empty()
            || !self.control_lease_revocation_barriers.is_empty()
            || !self.cleanup_registrations.is_empty()
            || retained_use_ids.len() > crate::MAX_BROKER_CONTROL_LEASES
            || retained_use_ids.windows(2).any(|w| w[0] >= w[1])
        {
            return Err(ManifoldBrokerRuntimeStateError::InvalidEvidence(
                "history_unresolved_or_pin_scope",
            ));
        }
        let prior = self.history_checkpoint.as_ref().ok_or(
            ManifoldBrokerRuntimeStateError::InvalidEvidence("ongoing_history_not_selected"),
        )?;
        let retained_mutations = retained_use_ids
            .iter()
            .map(|id| {
                self.committed_mutation_receipts
                    .iter()
                    .find(|r| &r.admission_use_request_id == id && r.applied)
                    .cloned()
                    .ok_or(ManifoldBrokerRuntimeStateError::InvalidEvidence(
                        "history_pin_not_applied",
                    ))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut candidate = self.staged_copy()?;
        let mut checkpoint = ManifoldBrokerHistoryCheckpoint {
            schema_id: schema_id("rusty.manifold.broker.history_checkpoint.v1"),
            checkpoint_sequence: prior.checkpoint_sequence.checked_add(1).ok_or(
                ManifoldBrokerRuntimeStateError::InvalidEvidence("history_sequence_exhausted"),
            )?,
            consumed_use_count: add_count(
                prior.consumed_use_count,
                self.consumed_bounded_use_ids.len(),
                prior.retained_mutations.len(),
            )?,
            mutation_count: add_count(
                prior.mutation_count,
                self.committed_mutation_receipts.len(),
                prior.retained_mutations.len(),
            )?,
            lifecycle_count: add_count(
                prior.lifecycle_count,
                self.control_lease_lifecycle_receipts.len(),
                0,
            )?,
            retained_mutations,
            source_evidence_sha256: digest(&self.evidence())?,
            prior_checkpoint_sha256: Some(digest(prior)?),
        };
        // This is an actual accepted expiry operation, never an implicit TTL
        // extension or deletion of tokens still valid at the supplied owner time.
        let sweep = candidate.current_admission_history_request_id(
            &DottedId::new(format!("sweep.history.{}", checkpoint.checkpoint_sequence))
                .expect("sweep id"),
        )?;
        let _ = candidate.expire_tokens(
            sweep,
            candidate.admission.snapshot().authority_revision,
            now_ms,
        );
        candidate.staged_copy()?;
        checkpoint.source_evidence_sha256 = digest(&candidate.evidence())?;
        candidate
            .admission
            .checkpoint_ongoing_history_with_retained_uses(retained_use_ids)
            .map_err(ManifoldBrokerRuntimeStateError::Admission)?;
        candidate
            .adapter
            .host
            .checkpoint_ongoing_history()
            .map_err(|_| {
                ManifoldBrokerRuntimeStateError::InvalidEvidence("history_host_checkpoint")
            })?;
        candidate
            .control_lease_authority
            .checkpoint_ongoing_history()
            .map_err(ManifoldBrokerRuntimeStateError::ControlLeaseAuthority)?;
        let pins = retained_use_ids.iter().cloned().collect::<BTreeSet<_>>();
        candidate
            .authorized_bounded_uses
            .retain(|id, _| pins.contains(id));
        candidate.consumed_bounded_use_ids = pins;
        candidate.committed_mutation_receipts = checkpoint.retained_mutations.clone();
        candidate.committed_capability_use_receipts.clear();
        candidate.invalidated_bounded_use_ids.clear();
        candidate.authorized_control_lease_lifecycle_uses.clear();
        candidate
            .invalidated_control_lease_lifecycle_use_ids
            .clear();
        candidate.control_lease_lifecycle_receipts.clear();
        // Same actual checkpoint seals completed root suffix bytes into its
        // source commitment; current grant/lease baseline remains exact. The
        // Native Original journal separately retains its completed root outcome.
        candidate.source_bound_root_reestablishments.clear();
        candidate.control_lease_revocation_use_invalidations.clear();
        candidate.control_lease_revocation_recovery_receipts.clear();
        candidate
            .control_lease_revocation_consumer_acknowledgements
            .clear();
        candidate.compacted_control_lease_request_ids.clear();
        let keep_tokens = candidate
            .admission
            .snapshot()
            .active_tokens
            .iter()
            .map(|t| t.token_id.clone())
            .chain(
                candidate
                    .authorized_bounded_uses
                    .values()
                    .map(|u| u.token_id.clone()),
            )
            .collect::<BTreeSet<_>>();
        candidate
            .admission_token_history
            .retain(|id, _| keep_tokens.contains(id));
        candidate.history_checkpoint = Some(checkpoint.clone());
        candidate.staged_copy()?;
        *self = candidate;
        Ok(checkpoint)
    }

    /// Creates a same-process borrowed seal over complete current evidence.
    pub fn seal_ongoing_history(
        &self,
    ) -> Result<ManifoldBrokerHistoryRestoreAnchor<'_>, ManifoldBrokerRuntimeStateError> {
        if self.history_checkpoint.is_none() || !self.cleanup_registrations.is_empty() {
            return Err(ManifoldBrokerRuntimeStateError::InvalidEvidence(
                "ongoing_history_not_selected",
            ));
        }
        self.staged_copy()?;
        Ok(ManifoldBrokerHistoryRestoreAnchor {
            owner: self,
            evidence_sha256: digest(&self.evidence())?,
        })
    }
    /// Verifies a read-only projection; this never constructs another Broker.
    pub fn verify_ongoing_history(
        evidence: &ManifoldBrokerRuntimeEvidence,
        anchor: &ManifoldBrokerHistoryRestoreAnchor<'_>,
    ) -> Result<(), ManifoldBrokerRuntimeStateError> {
        validate_runtime_evidence_size(evidence)?;
        if evidence.history_checkpoint.is_none()
            || digest(evidence)? != anchor.evidence_sha256
            || digest(&anchor.owner.evidence())? != anchor.evidence_sha256
        {
            return Err(ManifoldBrokerRuntimeStateError::InvalidEvidence(
                "ongoing_restore_requires_live_owner",
            ));
        }
        anchor.owner.staged_copy()?;
        Ok(())
    }

    /// Restores only this exact current exclusive owner in place. No public
    /// candidate-copy API may duplicate one provider epoch or roll back uses.
    /// Detached process-death restore requires a separate deployment contract.
    pub fn restore_ongoing_history(
        &mut self,
        evidence: ManifoldBrokerRuntimeEvidence,
    ) -> Result<(), ManifoldBrokerRuntimeStateError> {
        validate_runtime_evidence_size(&evidence)?;
        if self.history_checkpoint.is_none()
            || evidence.history_checkpoint.is_none()
            || digest(&evidence)? != digest(&self.evidence())?
        {
            return Err(ManifoldBrokerRuntimeStateError::InvalidEvidence(
                "ongoing_restore_requires_current_exclusive_owner",
            ));
        }
        let candidate = self.staged_copy()?;
        *self = candidate;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn id(s: &str) -> DottedId {
        DottedId::new(s).unwrap()
    }
    fn owner() -> ManifoldBrokerRuntime {
        let mut owner = super::super::tests::runtime(
            vec![],
            vec![command_capability(&id("command.session.list"))],
            vec![],
            "epoch.ongoing.test",
        );
        owner.enable_ongoing_history().unwrap();
        owner
    }
    fn admit(
        owner: &mut ManifoldBrokerRuntime,
        suffix: &str,
        entropy: u64,
    ) -> (ManifoldBrokerMutationRequest, ManifoldAdmissionUseRequest) {
        let identity = owner.admission_snapshot().grants[0].identity.clone();
        let command_id = id("command.session.list");
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&entropy.to_be_bytes());
        let token = owner
            .issue_token(
                &ManifoldAdmissionRequest {
                    schema_id: schema_id(rusty_manifold_admission::ADMISSION_REQUEST_SCHEMA),
                    request_id: owner
                        .current_admission_history_request_id(&id(&format!(
                            "request.{suffix}.issue"
                        )))
                        .unwrap(),
                    expected_authority_revision: owner.admission_snapshot().authority_revision,
                    identity: identity.clone(),
                    requested_capabilities: vec![command_capability(&command_id)],
                    issued_at_ms: 2000,
                    expires_at_ms: 10_000,
                    requested_token_ttl_ms: 20_000,
                },
                bytes,
                2000,
            )
            .token
            .unwrap();
        let use_request = ManifoldAdmissionUseRequest {
            schema_id: schema_id(rusty_manifold_admission::ADMISSION_USE_REQUEST_SCHEMA),
            request_id: owner
                .current_admission_history_request_id(&id(&format!("request.{suffix}.use")))
                .unwrap(),
            expected_authority_revision: owner.admission_snapshot().authority_revision,
            token_id: token.token_id.clone(),
            identity: identity.clone(),
            capability_id: command_capability(&command_id),
            issued_at_ms: 2000,
            expires_at_ms: 9000,
        };
        let accepted = owner.authorize_use(&use_request, 3000);
        assert!(accepted.applied);
        (
            ManifoldBrokerMutationRequest {
                schema_id: schema_id(BROKER_MUTATION_REQUEST_SCHEMA),
                provider_epoch_id: owner.provider_epoch_id().clone(),
                admission_use_request_id: use_request.request_id.clone(),
                token_id: token.token_id,
                expected_admission_authority_revision: accepted.resulting_authority_revision,
                command: ManifoldRuntimeCommandRequest {
                    schema_id: schema_id(rusty_manifold_runtime_host::HOST_COMMAND_REQUEST_SCHEMA),
                    request_id: owner
                        .current_host_history_request_id(&id(&format!("request.{suffix}.command")))
                        .unwrap(),
                    expected_authority_revision: owner.host_snapshot().authority_revision,
                    requester_id: identity.client_id,
                    command_id,
                    lease_id: None,
                    params_digest: None,
                    issued_at_ms: 2000,
                    expires_at_ms: 9000,
                },
            },
            use_request,
        )
    }
    fn retire_token(
        owner: &mut ManifoldBrokerRuntime,
        request: &ManifoldBrokerMutationRequest,
        suffix: &str,
    ) {
        let revoke = ManifoldAdmissionRevocationRequest {
            schema_id: schema_id(rusty_manifold_admission::ADMISSION_REVOCATION_REQUEST_SCHEMA),
            request_id: owner
                .current_admission_history_request_id(&id(&format!("request.{suffix}.revoke")))
                .unwrap(),
            expected_authority_revision: owner.admission_snapshot().authority_revision,
            token_id: request.token_id.clone(),
            identity: owner.admission_snapshot().grants[0].identity.clone(),
            reason: id("reason.done"),
        };
        assert!(owner.revoke_token(&revoke).applied);
    }
    #[test]
    fn ongoing_broker_checkpoint_plan_is_readonly_and_stale_commit_cannot_replace_current_owner() {
        let mut owner = owner();
        let (request, _) = admit(&mut owner, "plan.first", 90001);
        assert!(
            owner
                .commit_mutation(&request, 4000, |r, _| r.clone())
                .unwrap()
                .applied
        );
        retire_token(&mut owner, &request, "plan.first");
        let source = owner.evidence();
        let discarded = owner.plan_ongoing_history_checkpoint(&[], 4000).unwrap();
        assert_eq!(owner.evidence(), source);
        assert_ne!(discarded.evidence(), source);
        drop(discarded);
        let stale = owner.plan_ongoing_history_checkpoint(&[], 4000).unwrap();
        let (request, _) = admit(&mut owner, "plan.second", 90002);
        assert!(
            owner
                .commit_mutation(&request, 4000, |r, _| r.clone())
                .unwrap()
                .applied
        );
        retire_token(&mut owner, &request, "plan.second");
        let current = owner.evidence();
        assert!(owner.commit_ongoing_history_checkpoint(stale).is_err());
        assert_eq!(owner.evidence(), current);
        let plan = owner.plan_ongoing_history_checkpoint(&[], 4000).unwrap();
        let expected = plan.evidence();
        owner.commit_ongoing_history_checkpoint(plan).unwrap();
        assert_eq!(owner.evidence(), expected);
        assert_eq!(
            owner.evidence().history_checkpoint.unwrap().mutation_count,
            2
        );
    }
    #[test]
    fn ongoing_broker_5000_actual_mutations_retain_original_live_use_and_bound_all_composed_suffixes(
    ) {
        let mut owner = owner();
        let provider = owner.provider_epoch_id().clone();
        let grant = owner.admission_snapshot().grants[0].clone();
        let mut original = None;
        let mut old_nonpin = None;
        let mut old_evidence = None;
        for cycle in 0..5000u64 {
            let suffix = format!("cycle.r{cycle}");
            let (request, use_request) = admit(&mut owner, &suffix, cycle + 1);
            let receipt = owner
                .commit_mutation(&request, 4000, |receipt, _| receipt.clone())
                .unwrap();
            assert!(receipt.applied);
            retire_token(&mut owner, &request, &suffix);
            if original.is_none() {
                original = Some(receipt.clone());
            }
            if cycle == 1 {
                old_nonpin = Some(use_request);
            }
            if cycle % 16 == 15 {
                let pin = original.as_ref().unwrap().admission_use_request_id.clone();
                let before_revision = owner.host_snapshot().authority_revision;
                let checkpoint = owner
                    .checkpoint_ongoing_history(&[pin.clone()], 4000)
                    .unwrap();
                assert_eq!(checkpoint.mutation_count, cycle + 1);
                assert_eq!(checkpoint.consumed_use_count, cycle + 1);
                assert_eq!(owner.provider_epoch_id(), &provider);
                assert_eq!(owner.admission_snapshot().grants[0], grant);
                assert_eq!(owner.host_snapshot().authority_revision, before_revision);
                assert_eq!(
                    owner.evidence().committed_mutation_receipts,
                    vec![original.clone().unwrap()]
                );
                assert!(owner
                    .admission_snapshot()
                    .consumed_use_request_ids
                    .contains(&pin));
                assert!(owner.evidence().consumed_bounded_use_ids.contains(&pin));
                assert!(owner.evidence().pending_bounded_uses.is_empty());
                let evidence = owner.evidence();
                let anchor = owner.seal_ongoing_history().unwrap();
                ManifoldBrokerRuntime::verify_ongoing_history(&evidence, &anchor).unwrap();
                if let Some(old) = old_evidence.take() {
                    assert!(ManifoldBrokerRuntime::verify_ongoing_history(&old, &anchor).is_err());
                }
                let mut damaged = evidence.clone();
                damaged.host_snapshot.authority_revision =
                    damaged.host_snapshot.authority_revision.next().unwrap();
                assert!(ManifoldBrokerRuntime::verify_ongoing_history(&damaged, &anchor).is_err());
                let saved = owner.evidence();
                assert!(owner.restore_ongoing_history(damaged).is_err());
                assert_eq!(owner.evidence(), saved);
                owner.restore_ongoing_history(evidence.clone()).unwrap();
                assert_eq!(owner.evidence(), evidence);
                old_evidence = Some(evidence);
                let mut replay = old_nonpin.clone().unwrap();
                replay.expected_authority_revision = owner.admission_snapshot().authority_revision;
                assert_eq!(
                    owner.authorize_use(&replay, 4000).rejection_reason,
                    Some(ManifoldAdmissionRejectionReason::ReplayedRequest)
                );
            }
            assert!(owner.evidence().committed_mutation_receipts.len() <= 17);
            assert!(owner.evidence().authorized_bounded_uses.len() <= 17);
            assert!(owner.evidence().admission_token_history.len() <= 17);
            assert!(owner.admission_snapshot().audit_events.len() <= 50);
        }
        assert!(serde_json::to_vec(&owner.evidence()).unwrap().len() < 256 * 1024);
        assert_eq!(owner.host_snapshot().authority_revision.get(), 5001);
    }
    #[test]
    fn ongoing_broker_pending_phase_refuses_checkpoint_and_old_command_cannot_reopen() {
        let mut owner = owner();
        let (first, _) = admit(&mut owner, "first", 1);
        assert!(owner
            .commit_mutation(&first, 4000, |r, _| r.applied)
            .unwrap());
        retire_token(&mut owner, &first, "first");
        owner.checkpoint_ongoing_history(&[], 4000).unwrap();
        let (mut pending, _) = admit(&mut owner, "pending", 2);
        let before = owner.evidence();
        assert!(owner.checkpoint_ongoing_history(&[], 4000).is_err());
        assert_eq!(owner.evidence(), before);
        pending.command.request_id = first.command.request_id;
        let revision = owner.host_snapshot().authority_revision;
        let rejected = owner
            .commit_mutation(&pending, 4000, |r, _| r.clone())
            .unwrap();
        assert!(!rejected.applied);
        assert_eq!(
            rejected
                .adapter_receipt
                .unwrap()
                .application
                .rejection_reason,
            Some(rusty_manifold_runtime_host::ManifoldRuntimeRejectionReason::ReplayedRequest)
        );
        assert_eq!(owner.host_snapshot().authority_revision, revision);
        retire_token(&mut owner, &pending, "pending");
        owner.checkpoint_ongoing_history(&[], 4000).unwrap();
        assert!(owner.evidence().pending_bounded_uses.is_empty());
        assert!(add_count(u64::MAX, 1, 0).is_err());
        assert!(add_count(0, 0, 1).is_err());
    }
}
