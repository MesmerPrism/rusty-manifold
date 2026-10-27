//! Atomic same-key setup plus retained invalidation floor. No platform effects.
use super::*;
use rusty_manifold_peer::*;

pub const PEER_FRESH_SETUP_ONGOING_SNAPSHOT_SCHEMA: &str =
    "rusty.manifold.peer.runtime_host.snapshot.v10";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldFreshPairSetupReceipt {
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    pub request_id: DottedId,
    pub local_request_id: DottedId,
    pub context_sha256: String,
    pub request: ManifoldFreshPairSetupRequest,
    pub local_peer_id: DottedId,
    pub prior_authority_revision: Revision,
    pub resulting_authority_revision: Revision,
    pub prior_credentials: Vec<ManifoldPeerCredentialRecord>,
    pub renewed_credentials: Vec<ManifoldPeerCredentialRecord>,
    pub status_receipts: Vec<ManifoldPeerApplicationReceipt>,
    pub renewed_peers: Vec<ManifoldAcceptedPeer>,
    pub fence: ManifoldPairSetupFence,
    pub applied_at_ms: u64,
}

/// Selected fresh history; full bodies transfer only through exact durable owner archive custody.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldFreshPairSetupState {
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    pub receipts: Vec<ManifoldFreshPairSetupReceipt>,
    pub prime_origin: Option<ManifoldFreshPrimeOrigin>,
    pub prime_enrollments: Vec<ManifoldFreshPrimeEnrollmentEntry>,
    pub phase_preparations: Vec<ManifoldFreshPhasePrepareReceipt>,
    pub archive: Option<ManifoldFreshHistoryArchiveCursor>,
}

pub(super) fn empty_state() -> ManifoldFreshPairSetupState {
    ManifoldFreshPairSetupState {
        schema_id: schema("rusty.manifold.peer.fresh_pair_setup_state.v4"),
        receipts: Vec::new(),
        prime_origin: None,
        prime_enrollments: Vec::new(),
        phase_preparations: Vec::new(),
        archive: None,
    }
}

pub(super) fn snapshot_schema(selected: bool, ongoing: bool) -> &'static str {
    match (selected, ongoing) {
        (true, true) => PEER_FRESH_SETUP_ONGOING_SNAPSHOT_SCHEMA,
        // Private pristine construction only; validation refuses exposed finite selection.
        (true, false) => PEER_RUNTIME_HOST_SNAPSHOT_SCHEMA,
        (false, true) => PEER_ONGOING_HISTORY_SNAPSHOT_SCHEMA,
        (false, false) => PEER_RUNTIME_HOST_SNAPSHOT_SCHEMA,
    }
}

fn digest<T: Serialize>(domain: &str, value: &T) -> Result<String, ManifoldPeerRuntimeHostError> {
    fresh_pair_setup_digest(domain, value).map_err(invalid_snapshot)
}

/// Pure graph predicate only. Quest separately joins real pending/active native originals.
pub(super) fn no_live_graph(
    snapshot: &ManifoldPeerRuntimeHostSnapshot,
) -> Result<(), ManifoldPeerRuntimeHostError> {
    if snapshot
        .media_sessions
        .sessions
        .iter()
        .any(|s| s.lifecycle_status == ManifoldMediaSessionLifecycleStatus::Current)
        || snapshot
            .direct_lane_leases
            .leases
            .iter()
            .any(|lease| !lease.revoked)
        || snapshot
            .broker_lease_revocation_convergences
            .iter()
            .any(|c| {
                c.platform_cleanup_pending
                    && !snapshot
                        .broker_lease_revocation_cleanup_completions
                        .iter()
                        .any(|done| done.completed && done.convergence_id == c.convergence_id)
            })
        || snapshot.pair_media_routes.routes.iter().any(|r| {
            *r.lifecycle_status() == ManifoldPairMediaRouteLifecycleStatus::Current
                || *r.cleanup_status() == ManifoldPairMediaRouteCleanupStatus::Pending
        })
    {
        return Err(invalid_snapshot(
            "fresh setup cannot invalidate active media or pending route cleanup",
        ));
    }
    Ok(())
}

impl ManifoldPeerRuntimeHost {
    /// Selects setup only while constructing a pristine actual ongoing-v2 owner.
    /// No snapshot/caller view, existing history, or Broker identity is imported here.
    pub fn new_with_fresh_pair_setup(
        host_id: DottedId,
        trust_policy: ManifoldPeerRuntimeTrustPolicy,
        provider_epoch_id: DottedId,
        media_command_runtime: ManifoldRuntimeHostSnapshot,
    ) -> Result<Self, ManifoldPeerRuntimeHostError> {
        validate_trust_policy(&trust_policy)?;
        if trust_policy.fresh_setup_policy.is_none()
            || trust_policy.fresh_setup_local_peer_id.is_none()
        {
            return Err(invalid_snapshot(
                "fresh constructor requires explicit selected policy and local identity",
            ));
        }
        let mut baseline_policy = trust_policy.clone();
        baseline_policy.fresh_setup_policy = None;
        baseline_policy.fresh_setup_local_peer_id = None;
        baseline_policy.fresh_setup_enrollment_selection = None;
        let mut actual = Self::new(
            host_id,
            baseline_policy,
            provider_epoch_id,
            media_command_runtime,
        )?;
        actual.snapshot.trust_policy = trust_policy;
        actual.snapshot.fresh_pair_setup = Some(empty_state());
        actual.enable_owned_runtime_history()?;
        actual.require_actual_fresh_setup_owner()?;
        validate_snapshot(&actual.snapshot)?;
        Ok(actual)
    }

    pub(super) fn require_actual_fresh_setup_owner(
        &self,
    ) -> Result<(), ManifoldPeerRuntimeHostError> {
        self.validate_signed_history_owner()?;
        if self.signed_history_owner.is_none()
            || self.signed_history_candidate.is_some()
            || !runtime_history::selected(&self.snapshot)
            || self.snapshot.ongoing_media_policy.as_ref()
                != Some(&ManifoldOngoingMediaPolicy::active_checkpoint_v2())
        {
            return Err(invalid_snapshot(
                "fresh setup requires actual non-cloneable ongoing-v2 owner",
            ));
        }
        self.validate_media_runtime_owner()
    }

    pub fn selected_fresh_pair_setup_policy(&self) -> Option<&ManifoldFreshPairSetupPolicy> {
        self.require_actual_fresh_setup_owner().ok()?;
        self.snapshot.trust_policy.fresh_setup_policy.as_ref()
    }

    /// Observation of one exact owner; neither cloning this view nor signing it creates an owner.
    pub fn fresh_pair_setup_view(
        &self,
        local_peer_id: &DottedId,
        peer_ids: &[DottedId],
        native_operation_sha256: &str,
        native_eligibility_sha256: &str,
        now_ms: u64,
    ) -> Result<ManifoldFreshPairSetupPeerView, ManifoldPeerRuntimeHostError> {
        self.require_actual_fresh_setup_owner()?;
        self.ensure_family_enabled(ManifoldPeerRuntimeAuthorityFamily::Enrollment)?;
        self.ensure_family_enabled(ManifoldPeerRuntimeAuthorityFamily::PeerStatus)?;
        no_live_graph(&self.snapshot)?;
        if self.selected_fresh_pair_setup_policy().is_none()
            || self
                .snapshot
                .trust_policy
                .fresh_setup_local_peer_id
                .as_ref()
                != Some(local_peer_id)
            || peer_ids.len() != 2
            || peer_ids[0] >= peer_ids[1]
            || !peer_ids.contains(local_peer_id)
            || !fresh_pair_setup_sha256_is_valid(native_operation_sha256)
            || !fresh_pair_setup_sha256_is_valid(native_eligibility_sha256)
        {
            return Err(invalid_snapshot(
                "fresh setup selected owner or pair binding",
            ));
        }
        let mut credentials = Vec::new();
        let mut peers = Vec::new();
        for peer in peer_ids {
            let records: Vec<_> = self
                .snapshot
                .enrollment
                .credentials
                .iter()
                .filter(|c| &c.peer_id == peer && c.status == ManifoldPeerCredentialStatus::Active)
                .collect();
            if records.len() != 1
                || records[0].replaced_by_key_id.is_some()
                || records[0].valid_from_ms > now_ms
            {
                return Err(invalid_snapshot("fresh setup exact active enrolled key"));
            }
            if let Some(accepted) = self
                .snapshot
                .accepted_peers
                .peers
                .iter()
                .find(|p| &p.identity.peer_id == peer)
            {
                if accepted.status.availability != ManifoldPeerAvailability::Ready
                    || accepted.status.observed_at_ms > now_ms
                {
                    return Err(invalid_snapshot("fresh setup retained identity not ready"));
                }
                peers.push(accepted.clone());
            }
            // Missing initial status stays an absent signed preimage. It is
            // created later only by the real writer from immutable policy.
            credentials.push(records[0].clone());
        }
        let prior_fence = self
            .snapshot
            .reciprocal_ed25519
            .fresh_setup_fences
            .iter()
            .find(|f| f.peer_ids == peer_ids)
            .cloned();
        Ok(ManifoldFreshPairSetupPeerView {
            schema_id: schema("rusty.manifold.peer.fresh_pair_setup_peer_view.v2"),
            local_peer_id: local_peer_id.clone(),
            runtime_host_id: self.snapshot.host_id.clone(),
            provider_epoch_id: self.snapshot.provider_epoch_id.clone(),
            trust_policy_id: self.snapshot.trust_policy.policy_id.clone(),
            trust_policy_revision: self.snapshot.trust_policy.revision,
            source_snapshot_sha256: digest(
                "rusty.manifold.peer.fresh_pair_setup_source.v2",
                &self.snapshot,
            )?,
            enrollment_authority_revision: self.snapshot.enrollment.authority_revision,
            prior_setup_epoch: prior_fence.as_ref().map_or(0, |f| f.setup_epoch),
            prior_fence,
            prior_credentials: credentials,
            accepted_peers: peers,
            native_operation_sha256: native_operation_sha256.to_owned(),
            native_eligibility_sha256: native_eligibility_sha256.to_owned(),
            observed_at_ms: now_ms,
        })
    }

    /// Reads the exact retained local transaction from this actual signed owner.
    ///
    /// `current` names the live owning instance, not current credential validity.
    /// Expired receipts remain historical outcomes. `None` means only that this
    /// fresh transaction ID was not committed here; ordinary prime enrollment
    /// or status effects may already exist. No mutation/replay/restore occurs.
    pub fn current_fresh_pair_setup_receipt(
        &self,
        request_id: &DottedId,
    ) -> Result<Option<ManifoldFreshPairSetupReceipt>, ManifoldPeerRuntimeHostError> {
        self.require_actual_fresh_setup_owner()?;
        if self.selected_fresh_pair_setup_policy().is_none() {
            return Err(invalid_snapshot(
                "fresh setup receipt requires selected actual owner",
            ));
        }
        // Join retained receipt, audit/replay rows and complete floor history.
        // A detached valid-shaped receipt or verification clone is insufficient.
        validate_snapshot(&self.snapshot)?;
        let state = self
            .snapshot
            .fresh_pair_setup
            .as_ref()
            .ok_or_else(|| invalid_snapshot("fresh setup state absent"))?;
        let receipt = state.receipts.iter().find(|r| &r.request_id == request_id);
        if receipt.is_none() && state.archive.is_some() {
            return Err(invalid_snapshot("fresh transaction may be durably archived; verified history lookup required, no absence grant"));
        }
        if let Some(receipt) = receipt {
            validate_fresh_pair_setup_receipt_with_lifetime_policy(
                receipt,
                self.snapshot
                    .trust_policy
                    .development_lifetime_policy
                    .as_ref(),
            )?;
        }
        Ok(receipt.cloned())
    }

    /// Both signatures and exact current local preimage precede every accepted mutation.
    /// Retry only returns the retained original receipt; it cannot renew it or make it current.
    pub fn apply_fresh_pair_setup(
        &mut self,
        request: &ManifoldFreshPairSetupRequest,
        now_ms: u64,
    ) -> Result<ManifoldFreshPairSetupReceipt, ManifoldPeerRuntimeHostError> {
        self.require_actual_fresh_setup_owner()?;
        let policy = self
            .selected_fresh_pair_setup_policy()
            .ok_or_else(|| invalid_snapshot("fresh setup policy absent"))?;
        if policy != &request.context.policy {
            return Err(invalid_snapshot("fresh setup policy differs"));
        }
        let state = self
            .snapshot
            .fresh_pair_setup
            .as_ref()
            .ok_or_else(|| invalid_snapshot("fresh setup state absent"))?;
        if let Some(old) = state
            .receipts
            .iter()
            .find(|r| r.request_id == request.context.request_id)
        {
            return if old.request == *request {
                Ok(old.clone())
            } else {
                Err(invalid_snapshot("fresh setup retry changed bytes"))
            };
        }
        verify_fresh_pair_setup_request(request).map_err(invalid_snapshot)?;
        let c = &request.context;
        if c.issued_at_ms > now_ms {
            return Err(invalid_snapshot("fresh setup future audit time"));
        }
        let credential_expires_at_ms = now_ms
            .checked_add(c.policy.credential_validity_ms)
            .ok_or_else(|| invalid_snapshot("fresh setup credential expiry overflow"))?;
        let local = self
            .snapshot
            .trust_policy
            .fresh_setup_local_peer_id
            .as_ref()
            .ok_or_else(|| invalid_snapshot("fresh setup local owner identity absent"))?;
        let view = c
            .views
            .iter()
            .find(|v| &v.local_peer_id == local)
            .ok_or_else(|| invalid_snapshot("fresh setup local view absent"))?;
        let actual = self.fresh_pair_setup_view(
            local,
            &c.peer_ids,
            &view.native_operation_sha256,
            &view.native_eligibility_sha256,
            view.observed_at_ms,
        )?;
        if actual != *view {
            return Err(invalid_snapshot("fresh setup exact owner preimage changed"));
        }
        self.ensure_event_capacity()?;
        let prior = self.snapshot.enrollment.authority_revision;
        let resulting = prior
            .next()
            .ok_or_else(|| invalid_snapshot("fresh setup enrollment revision exhausted"))?;
        let local_request_id = self.current_runtime_history_request_id(&derived(
            "request.fresh-pair-setup",
            &c.request_id,
        ))?;
        if self
            .snapshot
            .enrollment
            .applied_request_ids
            .contains(&local_request_id)
        {
            return Err(invalid_snapshot("fresh setup unbound request replay"));
        }
        let context_sha256 = digest("rusty.manifold.peer.fresh_pair_setup_context.v3", c)?;
        let fence = ManifoldPairSetupFence {
            schema_id: schema("rusty.manifold.peer.pair_setup_fence.v1"),
            peer_ids: c.peer_ids.clone(),
            setup_epoch: view
                .prior_setup_epoch
                .checked_add(1)
                .ok_or_else(|| invalid_snapshot("fresh setup epoch exhausted"))?,
            minimum_enrollment_authority_revision: resulting,
            setup_request_id: c.request_id.clone(),
            context_sha256: context_sha256.clone(),
        };
        let mut candidate = self.copy_for_transaction();
        let mut renewed = Vec::new();
        for old in &view.prior_credentials {
            let key = candidate
                .snapshot
                .enrollment
                .credentials
                .iter_mut()
                .find(|key| key.key_id == old.key_id)
                .ok_or_else(|| invalid_snapshot("fresh setup current key absent"))?;
            if key != old || credential_expires_at_ms < old.expires_at_ms {
                return Err(invalid_snapshot(
                    "fresh setup key preimage or regressing validity",
                ));
            }
            key.expires_at_ms = credential_expires_at_ms;
            renewed.push(key.clone());
        }
        candidate.snapshot.enrollment.authority_revision = resulting;
        candidate
            .snapshot
            .enrollment
            .applied_request_ids
            .push(local_request_id.clone());
        let mut status_receipts = Vec::new();
        for peer in &c.peer_ids {
            let accepted = fresh_pair_setup_expected_peer(
                view,
                peer,
                &c.policy,
                now_ms,
                credential_expires_at_ms,
                rusty_manifold_admission::ManifoldDevelopmentLifetimePolicy::selected_horizon(
                    self.snapshot
                        .trust_policy
                        .development_lifetime_policy
                        .as_ref(),
                    MAX_PEER_STATUS_TTL_MS,
                ),
            )
            .map_err(invalid_snapshot)?;
            let status = accepted.status;
            let (_, application) = candidate.review_peer_status(
                ManifoldPeerStatusProposal {
                    schema_id: schema(PEER_PROPOSAL_SCHEMA),
                    proposal_id: candidate.current_runtime_history_request_id(&derived(
                        "proposal.fresh-pair-setup",
                        &DottedId::new(format!(
                            "{}.{}",
                            c.request_id.as_str(),
                            accepted.identity.peer_id.as_str()
                        ))
                        .map_err(|_| invalid_snapshot("fresh setup status id"))?,
                    ))?,
                    expected_authority_revision: candidate
                        .snapshot
                        .accepted_peers
                        .authority_revision,
                    proposer_id: candidate.snapshot.trust_policy.trusted_operator_ids[0].clone(),
                    identity: accepted.identity.clone(),
                    status,
                    payload_class: ManifoldPeerPayloadClass::LowRateDescriptor,
                },
                now_ms,
            )?;
            if !application.applied {
                return Err(invalid_snapshot("fresh setup status application refused"));
            }
            status_receipts.push(application);
        }
        let receipt = ManifoldFreshPairSetupReceipt {
            schema_id: schema("rusty.manifold.peer.fresh_pair_setup_receipt.v3"),
            request_id: c.request_id.clone(),
            local_request_id: local_request_id.clone(),
            context_sha256,
            request: request.clone(),
            local_peer_id: local.clone(),
            prior_authority_revision: prior,
            resulting_authority_revision: resulting,
            prior_credentials: view.prior_credentials.clone(),
            renewed_credentials: renewed,
            status_receipts,
            renewed_peers: c
                .peer_ids
                .iter()
                .map(|id| {
                    candidate
                        .snapshot
                        .accepted_peers
                        .peers
                        .iter()
                        .find(|p| &p.identity.peer_id == id)
                        .expect("accepted refreshed peer")
                        .clone()
                })
                .collect(),
            fence: fence.clone(),
            applied_at_ms: now_ms,
        };
        candidate
            .snapshot
            .fresh_pair_setup
            .as_mut()
            .expect("selected state")
            .receipts
            .push(receipt.clone());
        candidate.record(
            ManifoldPeerRuntimeAuditKind::Enrollment,
            local_request_id,
            prior,
            resulting,
            true,
            None,
        )?;
        // Use the one retained actual signed owner. A changed snapshot is never accepted
        // by the ordinary candidate commit path and no clone receives a writable owner.
        {
            let owner = self
                .signed_history_owner
                .as_ref()
                .expect("actual ongoing owner required");
            let plan = owner
                .plan_fresh_pair_setup_fence(request, &self.snapshot.enrollment, local, now_ms)
                .map_err(invalid_snapshot)?;
            candidate.snapshot.reciprocal_ed25519 = plan.state().clone();
            validate_snapshot(&candidate.snapshot)?;
            candidate.validate_media_runtime_owner()?;
            self.signed_history_owner
                .as_mut()
                .expect("actual owner")
                .verify_plan(plan)
                .map_err(invalid_snapshot)?
                .commit();
            candidate.signed_history_candidate = None;
            candidate.signed_history_owner = self.signed_history_owner.take();
            *self = candidate;
        }
        Ok(receipt)
    }
}

pub(super) fn validate(
    snapshot: &ManifoldPeerRuntimeHostSnapshot,
) -> Result<(), ManifoldPeerRuntimeHostError> {
    let selected = snapshot.trust_policy.fresh_setup_policy.as_ref();
    if selected.is_some() != snapshot.trust_policy.fresh_setup_local_peer_id.is_some()
        || selected.is_some() != snapshot.fresh_pair_setup.is_some()
        || selected.is_some_and(|p| !fresh_pair_setup_policy_is_well_formed(p))
        || (selected.is_none() && !snapshot.reciprocal_ed25519.fresh_setup_fences.is_empty())
        || (selected.is_some()
            && (!runtime_history::selected(snapshot)
                || snapshot.ongoing_media_policy.as_ref()
                    != Some(&ManifoldOngoingMediaPolicy::active_checkpoint_v2())))
    {
        return Err(invalid_snapshot("fresh setup policy/state or downgrade"));
    }
    let Some(state) = &snapshot.fresh_pair_setup else {
        return Ok(());
    };
    if state.schema_id.as_str() != "rusty.manifold.peer.fresh_pair_setup_state.v4" {
        return Err(invalid_snapshot("fresh setup state schema"));
    }
    fresh_phase_prepare::validate(snapshot)?;
    fresh_history_archive::validate_archive_cursor(snapshot)?;
    let mut fences = state
        .archive
        .as_ref()
        .map_or_else(Vec::new, |a| a.floor_checkpoint.clone());
    let mut requests = BTreeSet::new();
    let mut local_requests = BTreeSet::new();
    let mut previous_revision = state
        .archive
        .as_ref()
        .map(|a| a.enrollment_authority_revision);
    for r in &state.receipts {
        validate_fresh_pair_setup_receipt_with_lifetime_policy(
            r,
            snapshot.trust_policy.development_lifetime_policy.as_ref(),
        )?;
        let c = &r.request.context;
        let credential_expires_at_ms = r
            .applied_at_ms
            .checked_add(c.policy.credential_validity_ms)
            .ok_or_else(|| invalid_snapshot("fresh setup credential expiry overflow"))?;
        let view = c
            .views
            .iter()
            .find(|v| v.local_peer_id == r.local_peer_id)
            .ok_or_else(|| invalid_snapshot("fresh receipt local view"))?;
        if r.schema_id.as_str() != "rusty.manifold.peer.fresh_pair_setup_receipt.v3"
            || &c.policy != selected.expect("selected policy")
            || Some(&r.local_peer_id) != snapshot.trust_policy.fresh_setup_local_peer_id.as_ref()
            || r.request_id != c.request_id
            || !requests.insert(&r.request_id)
            || !local_requests.insert(&r.local_request_id)
            || !snapshot
                .enrollment
                .applied_request_ids
                .contains(&r.local_request_id)
            || view.runtime_host_id != snapshot.host_id
            || view.trust_policy_id != snapshot.trust_policy.policy_id
            || view.trust_policy_revision != snapshot.trust_policy.revision
            || r.context_sha256 != digest("rusty.manifold.peer.fresh_pair_setup_context.v3", c)?
            || view.enrollment_authority_revision != r.prior_authority_revision
            || r.prior_authority_revision.next() != Some(r.resulting_authority_revision)
            || previous_revision.is_some_and(|prior| prior >= r.resulting_authority_revision)
            || r.resulting_authority_revision > snapshot.enrollment.authority_revision
            || r.applied_at_ms < c.issued_at_ms
            || r.prior_credentials != view.prior_credentials
            || r.renewed_credentials.len() != 2
            || r.status_receipts.len() != 2
            || r.status_receipts.iter().any(|s| !s.applied)
            || snapshot
                .audit_events
                .iter()
                .filter(|e| {
                    e.applied
                        && e.event_kind == ManifoldPeerRuntimeAuditKind::Enrollment
                        && e.source_id == r.local_request_id
                        && e.prior_authority_revision == r.prior_authority_revision
                        && e.resulting_authority_revision == r.resulting_authority_revision
                })
                .count()
                != 1
            || r.fence.peer_ids != c.peer_ids
            || r.fence.minimum_enrollment_authority_revision != r.resulting_authority_revision
            || r.fence.setup_request_id != r.request_id
            || r.fence.context_sha256 != r.context_sha256
            || r.fence.setup_epoch
                != view
                    .prior_setup_epoch
                    .checked_add(1)
                    .ok_or_else(|| invalid_snapshot("fresh setup epoch overflow"))?
            || view.prior_fence.as_ref()
                != fences
                    .iter()
                    .find(|f: &&ManifoldPairSetupFence| f.peer_ids == c.peer_ids)
        {
            return Err(invalid_snapshot("fresh setup retained transaction joins"));
        }
        for (old, new) in r.prior_credentials.iter().zip(&r.renewed_credentials) {
            let mut expected = old.clone();
            expected.expires_at_ms = credential_expires_at_ms;
            if expected != *new || new.expires_at_ms < old.expires_at_ms {
                return Err(invalid_snapshot("fresh setup retained key mutation"));
            }
            let current = snapshot
                .enrollment
                .credentials
                .iter()
                .find(|v| v.key_id == new.key_id)
                .ok_or_else(|| invalid_snapshot("fresh setup retained key history"))?;
            if current.peer_id != new.peer_id
                || current.key_generation != new.key_generation
                || current.public_key_sha256 != new.public_key_sha256
                || current.public_key_hex != new.public_key_hex
            {
                return Err(invalid_snapshot("fresh setup key history changed"));
            }
        }
        advance_fresh_pair_setup_fence(&mut fences, r.fence.clone()).map_err(invalid_snapshot)?;
        previous_revision = Some(r.resulting_authority_revision);
    }
    if fences != snapshot.reciprocal_ed25519.fresh_setup_fences {
        return Err(invalid_snapshot(
            "fresh setup floor history missing or changed",
        ));
    }
    // A retained setup's final key validity must be accounted for by its latest
    // setup or ordinary-refresh preimage chain, including later rotation/revocation.
    for key in &snapshot.enrollment.credentials {
        let mut updates: Vec<_> = state
            .receipts
            .iter()
            .filter_map(|r| {
                r.renewed_credentials
                    .iter()
                    .find(|c| c.key_id == key.key_id)
                    .map(|c| (r.resulting_authority_revision, c))
            })
            .collect();
        if let Some(archive) = &state.archive {
            if let Some(key) = archive
                .credential_checkpoint
                .iter()
                .find(|c| c.key_id == key.key_id)
            {
                updates.push((archive.enrollment_authority_revision, key));
            }
        }
        updates.extend(
            snapshot
                .concurrent_credential_refreshes
                .iter()
                .filter_map(|r| {
                    r.renewed_credentials
                        .iter()
                        .find(|c| c.key_id == key.key_id)
                        .map(|c| (r.resulting_authority_revision, c))
                }),
        );
        updates.sort_by_key(|(revision, _)| *revision);
        if let Some((_, last)) = updates.last() {
            if last.expires_at_ms != key.expires_at_ms {
                return Err(invalid_snapshot(
                    "fresh setup final credential validity unaccounted",
                ));
            }
        }
    }
    for event in snapshot
        .audit_events
        .iter()
        .filter(|e| e.applied && e.event_kind == ManifoldPeerRuntimeAuditKind::Enrollment)
    {
        if event
            .source_id
            .as_str()
            .contains("request.fresh-pair-setup.")
            && !state
                .receipts
                .iter()
                .any(|r| r.local_request_id == event.source_id)
        {
            return Err(invalid_snapshot(
                "fresh setup receipt omitted from retained history",
            ));
        }
    }
    Ok(())
}

/// Typed retained evidence only. The remote transport must still authenticate
/// its exact owner/original, and no receipt constructs a live mutation capability.
pub fn validate_fresh_pair_setup_receipt(
    r: &ManifoldFreshPairSetupReceipt,
) -> Result<(), ManifoldPeerRuntimeHostError> {
    validate_fresh_pair_setup_receipt_with_lifetime_policy(r, None)
}

/// Validates retained evidence under an independently accepted immutable policy.
/// The receipt itself cannot select longer authority or mint a live capability.
pub fn validate_fresh_pair_setup_receipt_with_lifetime_policy(
    r: &ManifoldFreshPairSetupReceipt,
    lifetime_policy: Option<&rusty_manifold_admission::ManifoldDevelopmentLifetimePolicy>,
) -> Result<(), ManifoldPeerRuntimeHostError> {
    verify_fresh_pair_setup_request(&r.request).map_err(invalid_snapshot)?;
    let c = &r.request.context;
    let credential_expires_at_ms = r
        .applied_at_ms
        .checked_add(c.policy.credential_validity_ms)
        .ok_or_else(|| invalid_snapshot("fresh setup credential expiry overflow"))?;
    let view = c
        .views
        .iter()
        .find(|v| v.local_peer_id == r.local_peer_id)
        .ok_or_else(|| invalid_snapshot("fresh receipt local view"))?;
    if r.schema_id.as_str() != "rusty.manifold.peer.fresh_pair_setup_receipt.v3"
        || r.request_id != c.request_id
        || r.prior_authority_revision != view.enrollment_authority_revision
        || r.prior_authority_revision.next() != Some(r.resulting_authority_revision)
        || r.context_sha256 != digest("rusty.manifold.peer.fresh_pair_setup_context.v3", c)?
        || r.prior_credentials != view.prior_credentials
        || r.renewed_credentials.len() != 2
        || r.status_receipts.len() != 2
        || r.renewed_peers.len() != 2
        || r.applied_at_ms < c.issued_at_ms
        || r.fence.peer_ids != c.peer_ids
        || r.fence.setup_request_id != r.request_id
        || r.fence.context_sha256 != r.context_sha256
        || r.fence.minimum_enrollment_authority_revision != r.resulting_authority_revision
        || r.fence.setup_epoch
            != view
                .prior_setup_epoch
                .checked_add(1)
                .ok_or_else(|| invalid_snapshot("fresh receipt epoch overflow"))?
        || !fresh_pair_setup_fence_is_well_formed(&r.fence)
    {
        return Err(invalid_snapshot("fresh setup receipt shape and preimages"));
    }
    let base = derived("request.fresh-pair-setup", &c.request_id);
    if r.local_request_id != base
        && !r
            .local_request_id
            .as_str()
            .strip_prefix("history.")
            .and_then(|s| s.split_once('.'))
            .is_some_and(|(epoch, suffix)| {
                epoch
                    .parse::<u64>()
                    .ok()
                    .is_some_and(|n| n > 0 && n.to_string() == epoch)
                    && suffix == base.as_str()
            })
    {
        return Err(invalid_snapshot(
            "fresh setup receipt local request namespace",
        ));
    }
    for index in 0..2 {
        let old = &r.prior_credentials[index];
        let new = &r.renewed_credentials[index];
        let mut expected = old.clone();
        expected.expires_at_ms = credential_expires_at_ms;
        let expected_peer = fresh_pair_setup_expected_peer(
            view,
            &c.peer_ids[index],
            &c.policy,
            r.applied_at_ms,
            credential_expires_at_ms,
            rusty_manifold_admission::ManifoldDevelopmentLifetimePolicy::selected_horizon(
                lifetime_policy,
                MAX_PEER_STATUS_TTL_MS,
            ),
        )
        .map_err(invalid_snapshot)?;
        let application = &r.status_receipts[index];
        let proposal_suffix = derived(
            "proposal.fresh-pair-setup",
            &DottedId::new(format!(
                "{}.{}",
                c.request_id.as_str(),
                c.peer_ids[index].as_str()
            ))
            .map_err(|_| invalid_snapshot("fresh receipt proposal identity"))?,
        );
        let expected_proposal = if r.local_request_id == base {
            proposal_suffix
        } else {
            let (epoch, _) = r
                .local_request_id
                .as_str()
                .strip_prefix("history.")
                .expect("validated namespace")
                .split_once('.')
                .expect("validated epoch");
            DottedId::new(format!("history.{epoch}.{}", proposal_suffix.as_str()))
                .map_err(|_| invalid_snapshot("fresh receipt status namespace"))?
        };
        if expected != *new
            || new.expires_at_ms < old.expires_at_ms
            || r.renewed_peers[index] != expected_peer
            || application.schema_id.as_str() != PEER_APPLICATION_SCHEMA
            || !application.applied
            || application.receipt_id != derived("receipt.peer", &expected_proposal)
            || application.decision_id != derived("decision.peer", &expected_proposal)
            || application.proposal_id != expected_proposal
            || application.prior_authority_revision.next()
                != Some(application.resulting_authority_revision)
            || (index == 1
                && r.status_receipts[0].resulting_authority_revision
                    != application.prior_authority_revision)
        {
            return Err(invalid_snapshot(
                "fresh setup receipt credential and status transition",
            ));
        }
    }
    Ok(())
}
