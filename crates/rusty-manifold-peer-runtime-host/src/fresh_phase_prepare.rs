//! Selected ongoing owner bookkeeping and explicit signed initial preparation.
use super::*;
use rusty_manifold_peer::*;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldFreshPhasePrepareReceipt {
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    pub request: ManifoldFreshPhasePrepareRequest,
    pub local_peer_id: DottedId,
    pub local_request_id: DottedId,
    pub prepare_sequence: u64,
    pub context_sha256: String,
    pub prior_authority_revision: Revision,
    pub resulting_authority_revision: Revision,
    pub enrollments: Vec<ManifoldFreshPrimeEnrollmentEntry>,
    pub applied_at_ms: u64,
}

fn digest<T: Serialize>(domain: &str, value: &T) -> Result<String, ManifoldPeerRuntimeHostError> {
    fresh_pair_setup_digest(domain, value).map_err(invalid_snapshot)
}

/// Pure semantic validation. An authenticated native transport and actual remote
/// owner call are still required; a deserialized receipt is never a write owner.
pub fn validate_fresh_phase_prepare_receipt(
    r: &ManifoldFreshPhasePrepareReceipt,
) -> Result<(), ManifoldPeerRuntimeHostError> {
    verify_fresh_phase_prepare_request(&r.request).map_err(invalid_snapshot)?;
    let c = &r.request.context;
    let view = c
        .views
        .iter()
        .find(|v| v.local_peer_id == r.local_peer_id)
        .ok_or_else(|| invalid_snapshot("prepare receipt local view"))?;
    if r.schema_id.as_str() != "rusty.manifold.peer.fresh_phase_prepare_receipt.v2"
        || view.prior_prepare_sequence.checked_add(1) != Some(r.prepare_sequence)
        || r.context_sha256 != digest("rusty.manifold.peer.fresh_phase_prepare_context.v2", c)?
        || r.applied_at_ms < c.issued_at_ms
        || r.prior_authority_revision != view.enrollment.authority_revision
        || r.enrollments
            .iter()
            .map(|e| e.receipt.peer_id.clone())
            .collect::<Vec<_>>()
            != view
                .unentered_peer_ids
                .iter()
                .cloned()
                .map(Some)
                .collect::<Vec<_>>()
    {
        return Err(invalid_snapshot("prepare receipt identity/context"));
    }
    let expiry = r
        .applied_at_ms
        .checked_add(c.policy.credential_validity_ms)
        .ok_or_else(|| invalid_snapshot("prepare receipt expiry overflow"))?;
    let mut state = view.enrollment.clone();
    for entry in &r.enrollments {
        let ManifoldPeerEnrollmentAction::Enroll { credential } = &entry.request.action else {
            return Err(invalid_snapshot("prepare receipt Enroll"));
        };
        let key = c
            .selection
            .keys
            .iter()
            .find(|k| k.peer_id == credential.peer_id)
            .ok_or_else(|| invalid_snapshot("prepare receipt selected key"))?;
        let (next, receipt) = review_and_apply_peer_enrollment(
            &state,
            &entry.request,
            &[c.selection.operator_id.clone()],
            r.applied_at_ms,
        );
        if entry.schema_id.as_str() != "rusty.manifold.peer.fresh_prime_enrollment_entry.v1"
            || entry.applied_at_ms != r.applied_at_ms
            || entry.request.issued_at_ms != r.applied_at_ms
            || *credential != key.credential(r.applied_at_ms, expiry)
            || !receipt.applied
            || receipt != entry.receipt
            || entry.source_before_sha256
                != digest(
                    "rusty.manifold.peer.fresh_prime_source.v1",
                    &entry.source_before,
                )?
            || entry.source_after_sha256
                != digest(
                    "rusty.manifold.peer.fresh_prime_source.v1",
                    &entry.source_after,
                )?
        {
            return Err(invalid_snapshot("prepare receipt actual new application"));
        }
        state = next;
    }
    if state.authority_revision != r.resulting_authority_revision {
        return Err(invalid_snapshot("prepare receipt resulting revision"));
    }
    Ok(())
}

/// Hash the actual snapshot with accounting removed. This avoids a recursive
/// post-hash; the full source hash in signed views still includes all accounting.
fn enrollment_source_value(
    snapshot: &ManifoldPeerRuntimeHostSnapshot,
) -> Result<serde_json::Value, ManifoldPeerRuntimeHostError> {
    let mut source = snapshot.clone();
    if let Some(state) = source.fresh_pair_setup.as_mut() {
        state.prime_origin = None;
        state.prime_enrollments.clear();
        state.phase_preparations.clear();
        state.archive = None;
    }
    serde_json::to_value(&source).map_err(ManifoldPeerRuntimeHostError::Serialize)
}

pub fn fresh_prime_enrollment_source_sha256(
    snapshot: &ManifoldPeerRuntimeHostSnapshot,
) -> Result<String, ManifoldPeerRuntimeHostError> {
    digest(
        "rusty.manifold.peer.fresh_prime_source.v1",
        &enrollment_source_value(snapshot)?,
    )
}

pub(super) fn selection_valid(policy: &ManifoldPeerRuntimeTrustPolicy) -> bool {
    let Some(s) = &policy.fresh_setup_enrollment_selection else {
        return policy.fresh_setup_policy.is_none();
    };
    policy.fresh_setup_policy.as_ref().is_some_and(|p| {
        fresh_setup_enrollment_selection_is_well_formed(s)
            && policy.trusted_operator_ids == vec![s.operator_id.clone()]
            && s.keys.iter().all(|k| {
                k.trust_domain == p.initial_status.trust_domain
                    && policy.trusted_key_fingerprints.contains(&k.key_fingerprint)
            })
            && policy
                .fresh_setup_local_peer_id
                .as_ref()
                .is_some_and(|id| s.keys.iter().any(|k| &k.peer_id == id))
    })
}

impl ManifoldPeerRuntimeHost {
    pub(super) fn initialize_fresh_prime_origin(
        &mut self,
    ) -> Result<(), ManifoldPeerRuntimeHostError> {
        self.require_actual_fresh_setup_owner()?;
        if self.snapshot.enrollment != ManifoldPeerEnrollmentState::empty() {
            return Err(invalid_snapshot("prime origin not pristine"));
        }
        let origin = ManifoldFreshPrimeOrigin {
            schema_id: schema("rusty.manifold.peer.fresh_prime_origin.v1"),
            source_snapshot_sha256: fresh_prime_enrollment_source_sha256(&self.snapshot)?,
            host_id: self.snapshot.host_id.clone(),
            provider_epoch_id: self.snapshot.provider_epoch_id.clone(),
            enrollment: self.snapshot.enrollment.clone(),
        };
        self.snapshot
            .fresh_pair_setup
            .as_mut()
            .ok_or_else(|| invalid_snapshot("prime state absent"))?
            .prime_origin = Some(origin);
        Ok(())
    }

    /// Full retained actual-writer outcome. None is not an unentered proof.
    pub fn current_fresh_prime_enrollment_receipt(
        &self,
        request_id: &DottedId,
    ) -> Result<Option<ManifoldFreshPrimeEnrollmentEntry>, ManifoldPeerRuntimeHostError> {
        self.require_actual_fresh_setup_owner()?;
        validate_snapshot(&self.snapshot)?;
        Ok(self
            .snapshot
            .fresh_pair_setup
            .as_ref()
            .ok_or_else(|| invalid_snapshot("prime state absent"))?
            .prime_enrollments
            .iter()
            .find(|e| &e.request.request_id == request_id)
            .cloned())
    }

    /// Selected initial Enroll branch only. All fallible mutation/audit/ledger
    /// work happens on the candidate before transferring the real owner.
    pub(super) fn review_fresh_prime_enrollment(
        &mut self,
        request: &ManifoldPeerEnrollmentRequest,
        now: u64,
    ) -> Result<ManifoldPeerEnrollmentReceipt, ManifoldPeerRuntimeHostError> {
        self.require_actual_fresh_setup_owner()?;
        let mut candidate = self.copy_for_transaction();
        let receipt = candidate.stage_fresh_prime_enrollment(request, now)?;
        validate_snapshot(&candidate.snapshot)?;
        self.commit_transaction_candidate(candidate)?;
        Ok(receipt)
    }

    fn stage_fresh_prime_enrollment(
        &mut self,
        request: &ManifoldPeerEnrollmentRequest,
        now: u64,
    ) -> Result<ManifoldPeerEnrollmentReceipt, ManifoldPeerRuntimeHostError> {
        self.ensure_family_enabled(ManifoldPeerRuntimeAuthorityFamily::Enrollment)?;
        self.ensure_history_request(&request.request_id)?;
        self.ensure_event_capacity()?;
        let selection = self
            .snapshot
            .trust_policy
            .fresh_setup_enrollment_selection
            .as_ref()
            .ok_or_else(|| invalid_snapshot("prime enrollment selection absent"))?;
        let ManifoldPeerEnrollmentAction::Enroll { credential } = &request.action else {
            return Err(invalid_snapshot("prime requires new initial Enroll"));
        };
        if request.operator_id != selection.operator_id
            || !selection.keys.iter().any(|k| k.matches(credential))
            || self
                .snapshot
                .enrollment
                .credentials
                .iter()
                .any(|k| k.peer_id == credential.peer_id)
        {
            return Err(invalid_snapshot(
                "prime immutable selected key or existing peer",
            ));
        }
        let source_before = enrollment_source_value(&self.snapshot)?;
        let before = digest("rusty.manifold.peer.fresh_prime_source.v1", &source_before)?;
        let (next, receipt) = review_and_apply_peer_enrollment(
            &self.snapshot.enrollment,
            request,
            &self.snapshot.trust_policy.trusted_operator_ids,
            now,
        );
        self.snapshot.enrollment = next;
        self.record(
            ManifoldPeerRuntimeAuditKind::Enrollment,
            request.request_id.clone(),
            receipt.prior_authority_revision,
            receipt.resulting_authority_revision,
            receipt.applied,
            rejection_code(receipt.rejection_reason.as_ref()),
        )?;
        if receipt.applied {
            let source_after = enrollment_source_value(&self.snapshot)?;
            let after = digest("rusty.manifold.peer.fresh_prime_source.v1", &source_after)?;
            let state = self
                .snapshot
                .fresh_pair_setup
                .as_mut()
                .ok_or_else(|| invalid_snapshot("prime state absent"))?;
            if state.prime_enrollments.len() >= 2 {
                return Err(invalid_snapshot("prime finite selected key set complete"));
            }
            state
                .prime_enrollments
                .push(ManifoldFreshPrimeEnrollmentEntry {
                    schema_id: schema("rusty.manifold.peer.fresh_prime_enrollment_entry.v1"),
                    ordinal: u64::try_from(state.prime_enrollments.len())
                        .map_err(|_| invalid_snapshot("prime ordinal"))?
                        + 1,
                    request: request.clone(),
                    applied_at_ms: now,
                    receipt: receipt.clone(),
                    source_before_sha256: before,
                    source_after_sha256: after,
                    source_before,
                    source_after,
                });
        }
        Ok(receipt)
    }

    pub fn fresh_phase_prepare_view(
        &self,
        unentered_peer_ids: &[DottedId],
        native_operation_sha256: &str,
        native_eligibility_sha256: &str,
        now: u64,
    ) -> Result<ManifoldFreshPhasePrepareView, ManifoldPeerRuntimeHostError> {
        self.require_actual_fresh_setup_owner()?;
        validate_snapshot(&self.snapshot)?;
        super::fresh_pair_setup::no_live_graph(&self.snapshot)?;
        let selection = self
            .snapshot
            .trust_policy
            .fresh_setup_enrollment_selection
            .as_ref()
            .ok_or_else(|| invalid_snapshot("prime selection absent"))?;
        let state = self
            .snapshot
            .fresh_pair_setup
            .as_ref()
            .ok_or_else(|| invalid_snapshot("prime state absent"))?;
        let mut exact_enrollment = ManifoldPeerEnrollmentState::empty();
        for entry in &state.prime_enrollments {
            exact_enrollment = review_and_apply_peer_enrollment(
                &exact_enrollment,
                &entry.request,
                &[selection.operator_id.clone()],
                entry.applied_at_ms,
            )
            .0;
        }
        let missing: Vec<_> = selection
            .keys
            .iter()
            .filter(|k| {
                !self
                    .snapshot
                    .enrollment
                    .credentials
                    .iter()
                    .any(|c| c.peer_id == k.peer_id)
            })
            .map(|k| k.peer_id.clone())
            .collect();
        if exact_enrollment != self.snapshot.enrollment
            || !state.receipts.is_empty()
            || !self
                .snapshot
                .reciprocal_ed25519
                .accepted_receipts
                .is_empty()
            || missing != unentered_peer_ids
            || !fresh_pair_setup_sha256_is_valid(native_operation_sha256)
            || !fresh_pair_setup_sha256_is_valid(native_eligibility_sha256)
        {
            return Err(invalid_snapshot(
                "phase preparation initial missing-set/source boundary",
            ));
        }
        Ok(ManifoldFreshPhasePrepareView {
            schema_id: schema("rusty.manifold.peer.fresh_phase_prepare_view.v1"),
            local_peer_id: self
                .snapshot
                .trust_policy
                .fresh_setup_local_peer_id
                .clone()
                .ok_or_else(|| invalid_snapshot("prime local identity"))?,
            runtime_host_id: self.snapshot.host_id.clone(),
            provider_epoch_id: self.snapshot.provider_epoch_id.clone(),
            trust_policy_id: self.snapshot.trust_policy.policy_id.clone(),
            trust_policy_revision: self.snapshot.trust_policy.revision,
            source_snapshot_sha256: digest(
                "rusty.manifold.peer.fresh_phase_prepare_source.v1",
                &self.snapshot,
            )?,
            origin: state
                .prime_origin
                .clone()
                .ok_or_else(|| invalid_snapshot("prime origin absent"))?,
            enrollment: self.snapshot.enrollment.clone(),
            prime_enrollments: state.prime_enrollments.clone(),
            prior_prepare_sequence: state
                .archive
                .as_ref()
                .map_or(0, |a| a.phase_receipts)
                .checked_add(
                    u64::try_from(state.phase_preparations.len())
                        .map_err(|_| invalid_snapshot("prepare sequence"))?,
                )
                .ok_or_else(|| invalid_snapshot("prepare sequence exhausted"))?,
            unentered_peer_ids: missing,
            native_operation_sha256: native_operation_sha256.into(),
            native_eligibility_sha256: native_eligibility_sha256.into(),
            observed_at_ms: now,
        })
    }

    /// Exact historical result on the actual owner. None grants no replay or
    /// native unentered permission; caller must retain its pending original.
    pub fn current_fresh_phase_prepare_receipt(
        &self,
        request_id: &DottedId,
    ) -> Result<Option<ManifoldFreshPhasePrepareReceipt>, ManifoldPeerRuntimeHostError> {
        self.require_actual_fresh_setup_owner()?;
        validate_snapshot(&self.snapshot)?;
        let state = self
            .snapshot
            .fresh_pair_setup
            .as_ref()
            .ok_or_else(|| invalid_snapshot("phase preparation state absent"))?;
        let found = state
            .phase_preparations
            .iter()
            .find(|r| &r.request.context.request_id == request_id);
        if found.is_none() && state.archive.is_some() {
            return Err(invalid_snapshot("preparation may be durably archived; verified history lookup required, no absence grant"));
        }
        if let Some(receipt) = found {
            validate_fresh_phase_prepare_receipt(receipt)?;
        }
        Ok(found.cloned())
    }

    pub fn apply_fresh_phase_prepare(
        &mut self,
        request: &ManifoldFreshPhasePrepareRequest,
        now: u64,
    ) -> Result<ManifoldFreshPhasePrepareReceipt, ManifoldPeerRuntimeHostError> {
        self.require_actual_fresh_setup_owner()?;
        validate_snapshot(&self.snapshot)?;
        let state = self
            .snapshot
            .fresh_pair_setup
            .as_ref()
            .ok_or_else(|| invalid_snapshot("prime state absent"))?;
        if let Some(old) = state
            .phase_preparations
            .iter()
            .find(|r| r.request.context.request_id == request.context.request_id)
        {
            return if old.request == *request {
                Ok(old.clone())
            } else {
                Err(invalid_snapshot("phase preparation changed retry"))
            };
        }
        verify_fresh_phase_prepare_request(request).map_err(invalid_snapshot)?;
        let c = &request.context;
        if self.selected_fresh_pair_setup_policy() != Some(&c.policy)
            || self
                .snapshot
                .trust_policy
                .fresh_setup_enrollment_selection
                .as_ref()
                != Some(&c.selection)
            || c.issued_at_ms > now
        {
            return Err(invalid_snapshot(
                "phase preparation selected policy or future audit",
            ));
        }
        let local = self
            .snapshot
            .trust_policy
            .fresh_setup_local_peer_id
            .as_ref()
            .ok_or_else(|| invalid_snapshot("prime local identity"))?;
        let view = c
            .views
            .iter()
            .find(|v| &v.local_peer_id == local)
            .ok_or_else(|| invalid_snapshot("phase preparation local view"))?;
        if self.fresh_phase_prepare_view(
            &view.unentered_peer_ids,
            &view.native_operation_sha256,
            &view.native_eligibility_sha256,
            view.observed_at_ms,
        )? != *view
        {
            return Err(invalid_snapshot(
                "phase preparation exact current source changed",
            ));
        }
        let expires = now
            .checked_add(c.policy.credential_validity_ms)
            .ok_or_else(|| invalid_snapshot("phase credential overflow"))?;
        let local_request_id = self.current_runtime_history_request_id(&derived(
            "request.fresh-phase-prepare",
            &c.request_id,
        ))?;
        self.ensure_history_request(&local_request_id)?;
        self.ensure_event_capacity()?;
        let mut candidate = self.copy_for_transaction();
        let prior = self.snapshot.enrollment.authority_revision;
        let first = candidate
            .snapshot
            .fresh_pair_setup
            .as_ref()
            .expect("selected state")
            .prime_enrollments
            .len();
        for key in c
            .selection
            .keys
            .iter()
            .filter(|key| view.unentered_peer_ids.contains(&key.peer_id))
        {
            let request_id = candidate.current_runtime_history_request_id(&derived(
                "request.fresh-phase-enroll",
                &derived(c.request_id.as_str(), &key.peer_id),
            ))?;
            let enrollment = ManifoldPeerEnrollmentRequest {
                schema_id: schema(PEER_ENROLLMENT_REQUEST_SCHEMA),
                request_id,
                expected_authority_revision: candidate.snapshot.enrollment.authority_revision,
                operator_id: c.selection.operator_id.clone(),
                issued_at_ms: now,
                action: ManifoldPeerEnrollmentAction::Enroll {
                    credential: key.credential(now, expires),
                },
            };
            if !candidate
                .stage_fresh_prime_enrollment(&enrollment, now)?
                .applied
            {
                return Err(invalid_snapshot("phase preparation actual Enroll refused"));
            }
        }
        let resulting = candidate.snapshot.enrollment.authority_revision;
        let receipt = ManifoldFreshPhasePrepareReceipt {
            schema_id: schema("rusty.manifold.peer.fresh_phase_prepare_receipt.v2"),
            request: request.clone(),
            local_peer_id: local.clone(),
            local_request_id: local_request_id.clone(),
            prepare_sequence: view
                .prior_prepare_sequence
                .checked_add(1)
                .ok_or_else(|| invalid_snapshot("prepare sequence overflow"))?,
            context_sha256: digest("rusty.manifold.peer.fresh_phase_prepare_context.v2", c)?,
            prior_authority_revision: prior,
            resulting_authority_revision: resulting,
            enrollments: candidate
                .snapshot
                .fresh_pair_setup
                .as_ref()
                .expect("selected state")
                .prime_enrollments[first..]
                .to_vec(),
            applied_at_ms: now,
        };
        candidate
            .snapshot
            .fresh_pair_setup
            .as_mut()
            .expect("selected state")
            .phase_preparations
            .push(receipt.clone());
        // The distinct phase is replay-fenced even on the already-enrolled side.
        candidate.record(
            ManifoldPeerRuntimeAuditKind::FreshPhasePrepare,
            local_request_id,
            prior,
            resulting,
            true,
            None,
        )?;
        validate_snapshot(&candidate.snapshot)?;
        self.commit_transaction_candidate(candidate)?;
        Ok(receipt)
    }
}

pub(super) fn validate(
    snapshot: &ManifoldPeerRuntimeHostSnapshot,
) -> Result<(), ManifoldPeerRuntimeHostError> {
    if !selection_valid(&snapshot.trust_policy) {
        return Err(invalid_snapshot("prime immutable selection"));
    }
    let Some(state) = &snapshot.fresh_pair_setup else {
        return Ok(());
    };
    let origin = state
        .prime_origin
        .as_ref()
        .ok_or_else(|| invalid_snapshot("prime constructor origin absent"))?;
    if origin.schema_id.as_str() != "rusty.manifold.peer.fresh_prime_origin.v1"
        || origin.host_id != snapshot.host_id
        || origin.provider_epoch_id != snapshot.provider_epoch_id
        || origin.enrollment != ManifoldPeerEnrollmentState::empty()
        || !fresh_pair_setup_sha256_is_valid(&origin.source_snapshot_sha256)
        || state.prime_enrollments.len() > 2
    {
        return Err(invalid_snapshot("prime retained origin"));
    }
    let selection = snapshot
        .trust_policy
        .fresh_setup_enrollment_selection
        .as_ref()
        .expect("selection checked");
    let mut enrollment = origin.enrollment.clone();
    let mut peers = BTreeSet::new();
    for (i, entry) in state.prime_enrollments.iter().enumerate() {
        let ManifoldPeerEnrollmentAction::Enroll { credential } = &entry.request.action else {
            return Err(invalid_snapshot("prime entry not Enroll"));
        };
        let (next, receipt) = review_and_apply_peer_enrollment(
            &enrollment,
            &entry.request,
            &[selection.operator_id.clone()],
            entry.applied_at_ms,
        );
        let before: ManifoldPeerRuntimeHostSnapshot =
            serde_json::from_value(entry.source_before.clone())
                .map_err(ManifoldPeerRuntimeHostError::Deserialize)?;
        let after: ManifoldPeerRuntimeHostSnapshot =
            serde_json::from_value(entry.source_after.clone())
                .map_err(ManifoldPeerRuntimeHostError::Deserialize)?;
        let mut expected = before.clone();
        expected.enrollment = next.clone();
        let sequence = before
            .event_sequence
            .checked_add(1)
            .ok_or_else(|| invalid_snapshot("prime source audit overflow"))?;
        expected.event_sequence = sequence;
        expected.audit_events.push(ManifoldPeerRuntimeAuditEvent {
            schema_id: schema(PEER_RUNTIME_HOST_AUDIT_SCHEMA),
            sequence,
            event_id: audit_id(sequence),
            event_kind: ManifoldPeerRuntimeAuditKind::Enrollment,
            source_id: entry.request.request_id.clone(),
            prior_authority_revision: receipt.prior_authority_revision,
            resulting_authority_revision: receipt.resulting_authority_revision,
            applied: true,
            rejection_code: None,
        });
        if entry.schema_id.as_str() != "rusty.manifold.peer.fresh_prime_enrollment_entry.v1"
            || entry.ordinal != u64::try_from(i).unwrap_or(u64::MAX) + 1
            || !receipt.applied
            || receipt != entry.receipt
            || !peers.insert(credential.peer_id.clone())
            || !selection.keys.iter().any(|k| k.matches(credential))
            || before.enrollment != enrollment
            || expected != after
            || before.host_id != snapshot.host_id
            || before.provider_epoch_id != snapshot.provider_epoch_id
            || before.trust_policy != snapshot.trust_policy
            || enrollment_source_value(&before)? != entry.source_before
            || enrollment_source_value(&after)? != entry.source_after
            || entry.source_before_sha256
                != digest(
                    "rusty.manifold.peer.fresh_prime_source.v1",
                    &entry.source_before,
                )?
            || entry.source_after_sha256
                != digest(
                    "rusty.manifold.peer.fresh_prime_source.v1",
                    &entry.source_after,
                )?
            || !fresh_pair_setup_sha256_is_valid(&entry.source_before_sha256)
            || !fresh_pair_setup_sha256_is_valid(&entry.source_after_sha256)
            || snapshot
                .audit_events
                .iter()
                .filter(|e| {
                    e.event_kind == ManifoldPeerRuntimeAuditKind::Enrollment
                        && e.source_id == entry.request.request_id
                        && e.applied
                        && e.prior_authority_revision == receipt.prior_authority_revision
                        && e.resulting_authority_revision == receipt.resulting_authority_revision
                })
                .count()
                != 1
            || !snapshot
                .enrollment
                .applied_request_ids
                .contains(&entry.request.request_id)
        {
            return Err(invalid_snapshot("prime actual-writer ledger drift"));
        }
        enrollment = next;
    }
    let mut phase_ids = BTreeSet::new();
    for (i, r) in state.phase_preparations.iter().enumerate() {
        validate_fresh_phase_prepare_receipt(r)?;
        verify_fresh_phase_prepare_request(&r.request).map_err(invalid_snapshot)?;
        let c = &r.request.context;
        let view = c
            .views
            .iter()
            .find(|v| v.local_peer_id == r.local_peer_id)
            .ok_or_else(|| invalid_snapshot("prepare retained view"))?;
        let mut resulting = view.enrollment.clone();
        let expires = r
            .applied_at_ms
            .checked_add(c.policy.credential_validity_ms)
            .ok_or_else(|| invalid_snapshot("prepare retained expiry overflow"))?;
        for entry in &r.enrollments {
            let ManifoldPeerEnrollmentAction::Enroll { credential } = &entry.request.action else {
                return Err(invalid_snapshot("prepare retained Enroll"));
            };
            let expected_key = selection
                .keys
                .iter()
                .find(|k| k.peer_id == credential.peer_id)
                .ok_or_else(|| invalid_snapshot("prepare retained key"))?;
            if entry.request.issued_at_ms != r.applied_at_ms
                || entry.applied_at_ms != r.applied_at_ms
                || *credential != expected_key.credential(r.applied_at_ms, expires)
            {
                return Err(invalid_snapshot("prepare actual-time credential"));
            }
            let (next, receipt) = review_and_apply_peer_enrollment(
                &resulting,
                &entry.request,
                &[selection.operator_id.clone()],
                entry.applied_at_ms,
            );
            if receipt != entry.receipt || !receipt.applied {
                return Err(invalid_snapshot("prepare retained application"));
            }
            resulting = next;
        }
        if r.schema_id.as_str() != "rusty.manifold.peer.fresh_phase_prepare_receipt.v2"
            || !phase_ids.insert(&c.request_id)
            || r.prepare_sequence
                != state
                    .archive
                    .as_ref()
                    .map_or(0, |a| a.phase_receipts)
                    .checked_add(
                        u64::try_from(i).map_err(|_| invalid_snapshot("prepare retained index"))?,
                    )
                    .and_then(|n| n.checked_add(1))
                    .ok_or_else(|| invalid_snapshot("prepare retained sequence overflow"))?
            || view.prior_prepare_sequence.checked_add(1) != Some(r.prepare_sequence)
            || r.request.context.selection != *selection
            || Some(&c.policy) != snapshot.trust_policy.fresh_setup_policy.as_ref()
            || Some(&r.local_peer_id) != snapshot.trust_policy.fresh_setup_local_peer_id.as_ref()
            || r.context_sha256 != digest("rusty.manifold.peer.fresh_phase_prepare_context.v2", c)?
            || r.applied_at_ms < c.issued_at_ms
            || r.prior_authority_revision != view.enrollment.authority_revision
            || r.resulting_authority_revision != resulting.authority_revision
            || r.enrollments
                .iter()
                .any(|e| !state.prime_enrollments.contains(e))
            || r.enrollments
                .iter()
                .map(|e| e.receipt.peer_id.clone())
                .collect::<Vec<_>>()
                != view
                    .unentered_peer_ids
                    .iter()
                    .cloned()
                    .map(Some)
                    .collect::<Vec<_>>()
            || snapshot
                .audit_events
                .iter()
                .filter(|e| {
                    e.event_kind == ManifoldPeerRuntimeAuditKind::FreshPhasePrepare
                        && e.source_id == r.local_request_id
                        && e.applied
                        && e.prior_authority_revision == r.prior_authority_revision
                        && e.resulting_authority_revision == r.resulting_authority_revision
                })
                .count()
                != 1
        {
            return Err(invalid_snapshot("phase preparation retained receipt drift"));
        }
    }
    for event in snapshot
        .audit_events
        .iter()
        .filter(|e| e.event_kind == ManifoldPeerRuntimeAuditKind::FreshPhasePrepare)
    {
        if !state
            .phase_preparations
            .iter()
            .any(|r| r.local_request_id == event.source_id)
        {
            return Err(invalid_snapshot("prepare receipt omitted"));
        }
    }
    for key in &selection.keys {
        if snapshot
            .enrollment
            .credentials
            .iter()
            .any(|c| c.key_id == key.key_id)
            && !state
                .prime_enrollments
                .iter()
                .any(|e| e.receipt.key_id.as_ref() == Some(&key.key_id))
        {
            return Err(invalid_snapshot("prime actual receipt omitted"));
        }
    }
    Ok(())
}
