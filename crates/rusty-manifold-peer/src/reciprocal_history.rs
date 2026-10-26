//! Bounded reciprocal history owned by a live, prospective authority object.
use super::*;

/// Explicit common-LAN ongoing state. Finite mixed v3 remains the default.
/// Ongoing storage with explicitly retained pair setup floors.
pub const RECIPROCAL_FRESH_SETUP_HISTORY_STATE_SCHEMA: &str =
    "rusty.manifold.peer.reciprocal_ed25519_state.v6";
pub const RECIPROCAL_HISTORY_STATE_SCHEMA: &str = "rusty.manifold.peer.reciprocal_ed25519_state.v4";

/// Completed signed prefix plus the exact receipts still needed by live children.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldReciprocalHistoryCheckpoint {
    /// Storage schema.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Request and signed correlation namespace for the next bounded suffix.
    pub request_epoch: u64,
    /// Last accepted global revision before the current suffix.
    pub authority_revision: Revision,
    /// Exact accepted receipts still referenced by current owner obligations.
    pub retained_receipt_ids: Vec<DottedId>,
    /// Commitment to the complete actual source, not an authority certificate.
    pub source_state_sha256: String,
    /// Commitment to the preceding checkpoint without recursive history bodies.
    pub prior_checkpoint_sha256: Option<String>,
}

/// Actual non-cloneable signed reciprocal mutation gate. No detached constructor.
/// Deployment still owns exclusive writer custody across processes and storage.
#[derive(Debug, Eq, PartialEq)]
pub struct ManifoldReciprocalHistoryOwner {
    pub(super) state: ManifoldReciprocalEd25519AuthorityStateV3,
    // Proof custody is part of this SAME actual signed mutation owner.
    pub(crate) source_bound_root_issuer:
        Option<rusty_manifold_runtime_host::ManifoldSourceBoundRootIssuer>,
}

/// Read-only transaction plan minted from one exact actual owner. Not transport data.
#[derive(Debug)]
pub struct ManifoldReciprocalHistoryPlan {
    source_state_sha256: String,
    state: ManifoldReciprocalEd25519AuthorityStateV3,
    receipt: Option<ManifoldCommonLanReciprocalEd25519Receipt>,
}

/// Exact-current plan borrowing the one actual mutation gate.
pub struct ManifoldVerifiedReciprocalHistoryPlan<'owner> {
    owner: &'owner mut ManifoldReciprocalHistoryOwner,
    plan: ManifoldReciprocalHistoryPlan,
}
impl ManifoldVerifiedReciprocalHistoryPlan<'_> {
    /// Infallible publication under the retained exclusive owner borrow.
    pub fn commit(self) {
        self.owner.state = self.plan.state;
    }
}
impl ManifoldReciprocalHistoryPlan {
    /// Proposed evidence only; it cannot construct an owner.
    pub fn state(&self) -> &ManifoldReciprocalEd25519AuthorityStateV3 {
        &self.state
    }
    /// Exact reviewed receipt when this plan represents a signed request.
    pub fn receipt(&self) -> Option<&ManifoldCommonLanReciprocalEd25519Receipt> {
        self.receipt.as_ref()
    }
}

fn hash<T: Serialize>(value: &T) -> Result<String, &'static str> {
    let mut digest = Sha256::new();
    digest.update(b"rusty.manifold.peer.reciprocal_history.sha256.v1\0");
    digest.update(serde_json::to_vec(value).map_err(|_| "reciprocal history serialization")?);
    Ok(format!("sha256:{}", encode_lower_hex(&digest.finalize())))
}
fn receipt_parts(receipt: &ManifoldReciprocalEd25519ReceiptV3) -> (&DottedId, Revision, Revision) {
    match receipt {
        ManifoldReciprocalEd25519ReceiptV3::WifiDirect(v) => (
            &v.receipt_id,
            v.prior_authority_revision,
            v.resulting_authority_revision,
        ),
        ManifoldReciprocalEd25519ReceiptV3::CommonLan(v) => (
            &v.receipt_id,
            v.prior_authority_revision,
            v.resulting_authority_revision,
        ),
    }
}
pub(super) fn baseline_revision(state: &ManifoldReciprocalEd25519AuthorityStateV3) -> Revision {
    state
        .history_checkpoint
        .as_ref()
        .map_or(Revision::INITIAL, |c| c.authority_revision)
}
pub(super) fn request_matches(
    state: &ManifoldReciprocalEd25519AuthorityStateV3,
    id: &DottedId,
) -> bool {
    state.history_checkpoint.as_ref().map_or(true, |c| {
        id.as_str()
            .strip_prefix(&format!("history.{}.", c.request_epoch))
            .is_some_and(|suffix| !suffix.is_empty() && !suffix.starts_with("history."))
    })
}
pub(super) fn valid_checkpoint(state: &ManifoldReciprocalEd25519AuthorityStateV3) -> bool {
    state.history_checkpoint.as_ref().map_or_else(
        || {
            state.fresh_setup_fences.is_empty()
                && state.schema_id.as_str() == RECIPROCAL_ED25519_STATE_V3_SCHEMA
        },
        |c| {
            state.schema_id.as_str()
                == (if state.fresh_setup_fences.is_empty() {
                    RECIPROCAL_HISTORY_STATE_SCHEMA
                } else {
                    RECIPROCAL_FRESH_SETUP_HISTORY_STATE_SCHEMA
                })
                && c.schema_id.as_str() == "rusty.manifold.peer.reciprocal_history_checkpoint.v1"
                && c.request_epoch > 0
                && c.authority_revision <= state.authority_revision
                && c.request_epoch <= c.authority_revision.get()
                && (c.request_epoch > 1) == c.prior_checkpoint_sha256.is_some()
                && c.retained_receipt_ids.len() <= 64
                && c.retained_receipt_ids
                    .windows(2)
                    .all(|pair| pair[0] < pair[1])
                && valid_sha256(&c.source_state_sha256)
                && c.prior_checkpoint_sha256
                    .as_ref()
                    .map_or(true, |value| valid_sha256(value))
        },
    )
}
pub(super) fn valid_receipt_count(state: &ManifoldReciprocalEd25519AuthorityStateV3) -> bool {
    let suffix = state
        .authority_revision
        .get()
        .checked_sub(baseline_revision(state).get());
    suffix.and_then(|n| usize::try_from(n).ok()).and_then(|n| {
        n.checked_add(
            state
                .history_checkpoint
                .as_ref()
                .map_or(0, |c| c.retained_receipt_ids.len()),
        )
    }) == Some(state.accepted_receipts.len())
}
pub(super) fn valid_pinned_receipts(state: &ManifoldReciprocalEd25519AuthorityStateV3) -> bool {
    let Some(checkpoint) = &state.history_checkpoint else {
        return true;
    };
    let mut pinned = Vec::new();
    for receipt in &state.accepted_receipts {
        let (id, prior, resulting) = receipt_parts(receipt);
        if resulting <= checkpoint.authority_revision {
            if prior.next() != Some(resulting) {
                return false;
            }
            pinned.push(id.clone());
        } else {
            let ManifoldReciprocalEd25519ReceiptV3::CommonLan(value) = receipt else {
                return false;
            };
            if !request_matches(state, &value.request_id)
                || !request_matches(state, &value.correlation_id)
            {
                return false;
            }
        }
    }
    pinned.sort();
    pinned == checkpoint.retained_receipt_ids
}

impl ManifoldReciprocalHistoryOwner {
    /// Stages a monotonic setup floor on this actual owner, without cloning the gate.
    /// Runtime Host additionally rejoins its whole local preimage and inactive graph.
    pub fn plan_fresh_pair_setup_fence(
        &self,
        request: &crate::ManifoldFreshPairSetupRequest,
        enrollment: &ManifoldPeerEnrollmentState,
        local_peer_id: &DottedId,
        now_ms: u64,
    ) -> Result<ManifoldReciprocalHistoryPlan, &'static str> {
        crate::verify_fresh_pair_setup_request(request)?;
        let c = &request.context;
        let view = c
            .views
            .iter()
            .find(|v| &v.local_peer_id == local_peer_id)
            .ok_or("fresh setup local signed view")?;
        if c.issued_at_ms > now_ms
            || view.enrollment_authority_revision != enrollment.authority_revision
            || view.prior_fence.as_ref()
                != self
                    .state
                    .fresh_setup_fences
                    .iter()
                    .find(|f| f.peer_ids == c.peer_ids)
        {
            return Err("fresh setup owner preimage or future audit time");
        }
        for old in &view.prior_credentials {
            if enrollment
                .credentials
                .iter()
                .find(|k| k.key_id == old.key_id)
                != Some(old)
            {
                return Err("fresh setup actual enrolled key changed");
            }
        }
        let mut state = self.state.clone();
        crate::advance_fresh_pair_setup_fence(
            &mut state.fresh_setup_fences,
            crate::ManifoldPairSetupFence {
                schema_id: schema("rusty.manifold.peer.pair_setup_fence.v1"),
                peer_ids: c.peer_ids.clone(),
                setup_epoch: view
                    .prior_setup_epoch
                    .checked_add(1)
                    .ok_or("fresh setup epoch exhausted")?,
                minimum_enrollment_authority_revision: enrollment
                    .authority_revision
                    .next()
                    .ok_or("fresh setup revision exhausted")?,
                setup_request_id: c.request_id.clone(),
                context_sha256: crate::fresh_pair_setup_digest(
                    "rusty.manifold.peer.fresh_pair_setup_context.v3",
                    c,
                )?,
            },
        )?;
        state.schema_id = schema(RECIPROCAL_FRESH_SETUP_HISTORY_STATE_SCHEMA);
        Ok(ManifoldReciprocalHistoryPlan {
            source_state_sha256: hash(&self.state)?,
            state,
            receipt: None,
        })
    }
    /// Stages signature review without mutating this owner, for enclosing atomic adoption.
    pub fn plan_common_lan(
        &self,
        request: &ManifoldCommonLanReciprocalEd25519ReviewRequest,
        runtime: ManifoldReciprocalEd25519RuntimeContext<'_>,
        now_ms: u64,
    ) -> Result<ManifoldReciprocalHistoryPlan, &'static str> {
        let (state, receipt) = review_and_apply_reciprocal_ed25519_owned(
            &self.state,
            &ManifoldReciprocalEd25519ReviewRequestV3::CommonLan(request.clone()),
            runtime,
            now_ms,
        );
        let ManifoldReciprocalEd25519ReceiptV3::CommonLan(receipt) = receipt else {
            unreachable!()
        };
        Ok(ManifoldReciprocalHistoryPlan {
            source_state_sha256: hash(&self.state)?,
            state,
            receipt: Some(receipt),
        })
    }
    /// Stages a checkpoint only from this actual owner, never from target evidence.
    pub fn plan_checkpoint(
        &self,
        retained: &[DottedId],
    ) -> Result<ManifoldReciprocalHistoryPlan, &'static str> {
        let mut staged = Self {
            state: self.state.clone(),
            source_bound_root_issuer: None,
        };
        staged.checkpoint(retained)?;
        Ok(ManifoldReciprocalHistoryPlan {
            source_state_sha256: hash(&self.state)?,
            state: staged.state,
            receipt: None,
        })
    }
    /// Commits one plan only while the actual source is still byte-equivalent.
    /// Any stale competing plan is denied before mutation.
    pub fn commit(&mut self, plan: ManifoldReciprocalHistoryPlan) -> Result<(), &'static str> {
        self.verify_plan(plan)?.commit();
        Ok(())
    }
    /// Validates the actual source before enclosing atomic publication. This
    /// constructs no second owner and is neither a receipt nor restore credential.
    pub fn verify_plan(
        &mut self,
        plan: ManifoldReciprocalHistoryPlan,
    ) -> Result<ManifoldVerifiedReciprocalHistoryPlan<'_>, &'static str> {
        if hash(&self.state)? != plan.source_state_sha256
            || !reciprocal_ed25519_state_v3_is_well_formed(&plan.state)
        {
            return Err("reciprocal plan source changed");
        }
        Ok(ManifoldVerifiedReciprocalHistoryPlan { owner: self, plan })
    }
    /// Selects ongoing storage only before any accepted reciprocal request.
    pub fn new() -> Self {
        let mut state = ManifoldReciprocalEd25519AuthorityStateV3::empty();
        let source_state_sha256 = hash(&state).expect("typed empty reciprocal state");
        state.schema_id = schema(RECIPROCAL_HISTORY_STATE_SCHEMA);
        state.history_checkpoint = Some(ManifoldReciprocalHistoryCheckpoint {
            schema_id: schema("rusty.manifold.peer.reciprocal_history_checkpoint.v1"),
            request_epoch: 1,
            authority_revision: Revision::INITIAL,
            retained_receipt_ids: Vec::new(),
            source_state_sha256,
            prior_checkpoint_sha256: None,
        });
        Self {
            state,
            source_bound_root_issuer: None,
        }
    }
    /// Read-only projection. It cannot be re-admitted through the finite mutation API.
    pub fn state(&self) -> &ManifoldReciprocalEd25519AuthorityStateV3 {
        &self.state
    }
    /// Namespaces both the outer request and the context correlation signed by both peers.
    pub fn current_request_id(&self, suffix: &DottedId) -> Result<DottedId, &'static str> {
        if suffix.as_str().starts_with("history.") {
            return Err("already qualified reciprocal request");
        }
        DottedId::new(format!(
            "history.{}.{}",
            self.state
                .history_checkpoint
                .as_ref()
                .unwrap()
                .request_epoch,
            suffix
        ))
        .map_err(|_| "reciprocal request identity")
    }
    /// Reviews the original exact signatures, current keys, all revisions and sliding expiry.
    /// Nonces are replay-unique within this explicit authenticated request epoch.
    /// A fresh epoch is signed through correlation plus monotonic reciprocal revision;
    /// nonce generation and signature context bytes are otherwise unchanged.
    pub fn review_common_lan(
        &mut self,
        request: &ManifoldCommonLanReciprocalEd25519ReviewRequest,
        runtime: ManifoldReciprocalEd25519RuntimeContext<'_>,
        now_ms: u64,
    ) -> ManifoldCommonLanReciprocalEd25519Receipt {
        let (state, receipt) = review_and_apply_reciprocal_ed25519_owned(
            &self.state,
            &ManifoldReciprocalEd25519ReviewRequestV3::CommonLan(request.clone()),
            runtime,
            now_ms,
        );
        let ManifoldReciprocalEd25519ReceiptV3::CommonLan(receipt) = receipt else {
            unreachable!()
        };
        if receipt.accepted {
            self.state = state;
        }
        receipt
    }
    /// Pins exact already accepted receipt identities required by the enclosing owner.
    /// No caller receipt body, replacement baseline or deadline is accepted.
    pub fn checkpoint(
        &mut self,
        retained: &[DottedId],
    ) -> Result<ManifoldReciprocalHistoryCheckpoint, &'static str> {
        if !reciprocal_ed25519_state_v3_is_well_formed(&self.state)
            || retained.len() > 64
            || !retained.windows(2).all(|p| p[0] < p[1])
        {
            return Err("reciprocal checkpoint source or pins");
        }
        let prior = self.state.history_checkpoint.as_ref().unwrap();
        if prior.authority_revision == self.state.authority_revision {
            return Err("reciprocal checkpoint requires progress");
        }
        let checkpoint = ManifoldReciprocalHistoryCheckpoint {
            schema_id: prior.schema_id.clone(),
            request_epoch: prior
                .request_epoch
                .checked_add(1)
                .ok_or("reciprocal epoch exhausted")?,
            authority_revision: self.state.authority_revision,
            retained_receipt_ids: retained.to_vec(),
            source_state_sha256: hash(&self.state)?,
            prior_checkpoint_sha256: Some(hash(prior)?),
        };
        let mut state = self.state.clone();
        state
            .accepted_receipts
            .retain(|receipt| retained.contains(receipt_parts(receipt).0));
        if state.accepted_receipts.len() != retained.len() {
            return Err("reciprocal pin absent");
        }
        state.applied_request_ids.clear();
        state.consumed_correlation_ids.clear();
        state.consumed_context_sha256.clear();
        state.consumed_nonce_sha256.clear();
        for receipt in &state.accepted_receipts {
            let (request, correlation, context, nonces) = match receipt {
                ManifoldReciprocalEd25519ReceiptV3::CommonLan(v) => (
                    &v.request_id,
                    &v.correlation_id,
                    &v.context_sha256,
                    &v.device_nonce_sha256,
                ),
                ManifoldReciprocalEd25519ReceiptV3::WifiDirect(_) => {
                    return Err("ongoing history is common-LAN only")
                }
            };
            state.applied_request_ids.push(request.clone());
            state.consumed_correlation_ids.push(correlation.clone());
            state.consumed_context_sha256.push(context.clone());
            state.consumed_nonce_sha256.extend(nonces.iter().cloned());
        }
        state.history_checkpoint = Some(checkpoint.clone());
        if !reciprocal_ed25519_state_v3_is_well_formed(&state) {
            return Err("reciprocal checkpoint target invalid");
        }
        self.state = state;
        Ok(checkpoint)
    }
    /// In-place exact current restore; target bytes alone cannot create another owner.
    pub fn restore_current(
        &mut self,
        state: ManifoldReciprocalEd25519AuthorityStateV3,
    ) -> Result<(), &'static str> {
        if state != self.state || !reciprocal_ed25519_state_v3_is_well_formed(&state) {
            return Err("reciprocal restore requires actual current owner");
        }
        self.state = state;
        Ok(())
    }
}
impl Default for ManifoldReciprocalHistoryOwner {
    fn default() -> Self {
        Self::new()
    }
}
