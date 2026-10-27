//! Non-cloneable signed gate stays at the actual Peer owner, never in candidates.
use super::*;
use rusty_manifold_peer::ManifoldReciprocalHistoryOwner;

/// Immutable private source evidence. It constructs no reciprocal authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct SignedHistoryCandidate {
    source: ManifoldReciprocalEd25519AuthorityStateV3,
    writable: bool,
}

impl Clone for ManifoldPeerRuntimeHost {
    /// Finite behavior is unchanged. An ongoing signed clone is an observation,
    /// not another accepted writer; its public mutations explicitly refuse.
    fn clone(&self) -> Self {
        let signed_history_candidate = self
            .signed_history_owner
            .as_ref()
            .map(|owner| {
                Box::new(SignedHistoryCandidate {
                    source: owner.state().clone(),
                    writable: false,
                })
            })
            .or_else(|| {
                self.signed_history_candidate.as_ref().map(|source| {
                    Box::new(SignedHistoryCandidate {
                        source: source.source.clone(),
                        writable: false,
                    })
                })
            });
        Self {
            development_lifetime_policy: self.development_lifetime_policy.clone(),
            snapshot: self.snapshot.clone(),
            media_runtime_owner: self.media_runtime_owner.clone(),
            signed_history_owner: None,
            signed_history_candidate,
        }
    }
}

impl ManifoldPeerRuntimeHost {
    /// Qualifies a new signed request/correlation in this actual reciprocal owner.
    pub fn current_signed_history_request_id(
        &self,
        suffix: &DottedId,
    ) -> Result<DottedId, ManifoldPeerRuntimeHostError> {
        if let Some(owner) = &self.signed_history_owner {
            owner.current_request_id(suffix).map_err(invalid_snapshot)
        } else if self
            .snapshot
            .reciprocal_ed25519
            .history_checkpoint
            .is_some()
        {
            Err(invalid_snapshot("signed request needs actual owner"))
        } else {
            Ok(suffix.clone())
        }
    }
    /// Only internal transaction code may stage mutations on immutable evidence.
    pub(super) fn copy_for_transaction(&self) -> Self {
        let mut candidate = self.clone();
        if let Some(source) = &mut candidate.signed_history_candidate {
            source.writable = self.signed_history_owner.is_some()
                || self
                    .signed_history_candidate
                    .as_ref()
                    .is_some_and(|source| source.writable);
        }
        candidate
    }
    fn validate_transaction_candidate(
        &self,
        candidate: &Self,
    ) -> Result<(), ManifoldPeerRuntimeHostError> {
        self.validate_signed_history_owner()?;
        if candidate.signed_history_owner.is_some() {
            return Err(invalid_snapshot("candidate contains another signed owner"));
        }
        if let Some(owner) = &self.signed_history_owner {
            let source = candidate
                .signed_history_candidate
                .as_ref()
                .ok_or_else(|| invalid_snapshot("candidate source absent"))?;
            if !source.writable
                || &source.source != owner.state()
                || &candidate.snapshot.reciprocal_ed25519 != owner.state()
            {
                return Err(invalid_snapshot("candidate changed actual signed owner"));
            }
        } else if self.signed_history_candidate != candidate.signed_history_candidate {
            return Err(invalid_snapshot(
                "nested candidate changed immutable signed source",
            ));
        }
        Ok(())
    }
    /// Last check precedes infallible transfer and publication under the caller's
    /// exclusive &mut Peer gate. No shared owner can change between these steps.
    pub(super) fn commit_transaction_candidate(
        &mut self,
        mut candidate: Self,
    ) -> Result<(), ManifoldPeerRuntimeHostError> {
        self.validate_transaction_candidate(&candidate)?;
        if self.signed_history_owner.is_some() {
            candidate.signed_history_candidate = None;
            candidate.signed_history_owner = self.signed_history_owner.take();
        }
        *self = candidate;
        Ok(())
    }
    pub(super) fn enable_owned_signed_history(
        &mut self,
    ) -> Result<(), ManifoldPeerRuntimeHostError> {
        if self.signed_history_owner.is_some() {
            return self.validate_signed_history_owner();
        }
        if self.signed_history_candidate.is_some()
            || self.snapshot.reciprocal_ed25519
                != ManifoldReciprocalEd25519AuthorityStateV3::empty()
        {
            return Err(invalid_snapshot(
                "signed history selection requires fresh actual owner",
            ));
        }
        let owner = ManifoldReciprocalHistoryOwner::new();
        self.snapshot.reciprocal_ed25519 = owner.state().clone();
        self.signed_history_owner = Some(Box::new(owner));
        Ok(())
    }
    pub(super) fn validate_signed_history_owner(&self) -> Result<(), ManifoldPeerRuntimeHostError> {
        if let Some(owner) = &self.signed_history_owner {
            if self.signed_history_candidate.is_some()
                || owner.state() != &self.snapshot.reciprocal_ed25519
            {
                return Err(invalid_snapshot("actual signed owner differs"));
            }
        } else if let Some(source) = &self.signed_history_candidate {
            if !source.writable || source.source != self.snapshot.reciprocal_ed25519 {
                return Err(invalid_snapshot(
                    "ongoing clone is read-only or signed source changed",
                ));
            }
        } else if self
            .snapshot
            .reciprocal_ed25519
            .history_checkpoint
            .is_some()
        {
            return Err(invalid_snapshot("signed checkpoint has no actual owner"));
        }
        Ok(())
    }
    pub(super) fn review_owned_signed_history(
        &mut self,
        request: &ManifoldReciprocalEd25519ReviewRequestV3,
        now_ms: u64,
    ) -> Result<ManifoldReciprocalEd25519ReceiptV3, ManifoldPeerRuntimeHostError> {
        let ManifoldReciprocalEd25519ReviewRequestV3::CommonLan(request) = request else {
            return Err(invalid_snapshot(
                "ongoing signed history supports common-LAN only",
            ));
        };
        self.validate_signed_history_owner()?;
        let owner = self
            .signed_history_owner
            .as_ref()
            .ok_or_else(|| invalid_snapshot("signed plans require actual owner"))?;
        let plan = owner
            .plan_common_lan_with_lifetime_policy(
                request,
                ManifoldReciprocalEd25519RuntimeContext {
                    runtime_host_id: &self.snapshot.host_id,
                    trust_policy_id: &self.snapshot.trust_policy.policy_id,
                    trust_policy_revision: self.snapshot.trust_policy.revision,
                    peer_authority_revision: self.snapshot.accepted_peers.authority_revision,
                    enrollment: &self.snapshot.enrollment,
                    rendezvous_authority_revision: self.snapshot.rendezvous.authority_revision,
                    peer_session_authority_revision: self.snapshot.peer_sessions.authority_revision,
                    peer_mesh_authority_revision: self.snapshot.peer_mesh.authority_revision,
                    direct_lane_lease_authority_revision: self
                        .snapshot
                        .direct_lane_leases
                        .authority_revision,
                },
                now_ms,
                self.development_lifetime_policy(),
            )
            .map_err(invalid_snapshot)?;
        let receipt = plan.receipt().expect("signed review plan").clone();
        let mut candidate = self.copy_for_transaction();
        candidate.snapshot.reciprocal_ed25519 = plan.state().clone();
        candidate.record(
            ManifoldPeerRuntimeAuditKind::ReciprocalEd25519,
            receipt.request_id.clone(),
            receipt.prior_authority_revision,
            receipt.resulting_authority_revision,
            receipt.accepted,
            rejection_code(receipt.rejection_reason.as_ref()),
        )?;
        validate_snapshot(&candidate.snapshot)?;
        // All fallible validation precedes exact-current commit; moving the actual
        // gate and publishing the candidate afterwards is infallible under &mut.
        self.signed_history_owner
            .as_mut()
            .expect("actual owner retained")
            .commit(plan)
            .map_err(invalid_snapshot)?;
        candidate.signed_history_candidate = None;
        candidate.signed_history_owner = self.signed_history_owner.take();
        *self = candidate;
        Ok(ManifoldReciprocalEd25519ReceiptV3::CommonLan(receipt))
    }
}
