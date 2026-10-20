//! Bounded parent audit/replay prefix for the prospective ongoing composition.
use super::*;

/// Explicit ongoing parent storage; finite snapshot v5 remains unchanged.
pub const PEER_ONGOING_HISTORY_SNAPSHOT_SCHEMA: &str =
    "rusty.manifold.peer_runtime_host.snapshot.v6";

/// Commitment to completed parent history and exact still-live source audit IDs.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPeerRuntimeHistoryCheckpoint {
    /// Storage schema.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Namespace of subsequent externally requested parent mutations.
    pub request_epoch: u64,
    /// Global audit high-water sequence at this checkpoint; never reset.
    pub event_sequence: u64,
    /// Accepted pair-route revision at this exact source boundary, never reset.
    pub pair_route_authority_revision: Revision,
    /// Existing accepted audit bodies still required by active obligations.
    pub retained_event_ids: Vec<DottedId>,
    /// Exact complete actual source commitment; not a restore credential.
    pub source_snapshot_sha256: String,
    /// Previous checkpoint commitment without recursive history bodies.
    pub prior_checkpoint_sha256: Option<String>,
    /// Exact fully adopted concurrent checkpoint already composed here.
    pub adopted_media_checkpoint_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fresh_history_archive: Option<ManifoldFreshHistoryParentCheckpoint>,
}

fn hash<T: Serialize>(value: &T) -> Result<String, ManifoldPeerRuntimeHostError> {
    domain_separated_digest("rusty.manifold.peer.runtime_history.sha256.v1", value)
}
pub(super) fn selected(snapshot: &ManifoldPeerRuntimeHostSnapshot) -> bool {
    snapshot.runtime_history_checkpoint.is_some()
}
pub(super) fn base(snapshot: &ManifoldPeerRuntimeHostSnapshot) -> u64 {
    snapshot
        .runtime_history_checkpoint
        .as_ref()
        .map_or(0, |c| c.event_sequence)
}
pub(super) fn request_matches(snapshot: &ManifoldPeerRuntimeHostSnapshot, id: &DottedId) -> bool {
    snapshot
        .runtime_history_checkpoint
        .as_ref()
        .map_or(true, |c| {
            id.as_str()
                .strip_prefix(&format!("history.{}.", c.request_epoch))
                .is_some_and(|suffix| !suffix.is_empty() && !suffix.starts_with("history."))
        })
}
pub(super) fn validate(
    snapshot: &ManifoldPeerRuntimeHostSnapshot,
) -> Result<(), ManifoldPeerRuntimeHostError> {
    let Some(checkpoint) = &snapshot.runtime_history_checkpoint else {
        if snapshot.schema_id.as_str()
            != fresh_pair_setup::snapshot_schema(
                snapshot.trust_policy.fresh_setup_policy.is_some(),
                false,
            )
        {
            return Err(invalid_snapshot("parent history storage policy absent"));
        }
        return Ok(());
    };
    if snapshot.schema_id.as_str()
        != fresh_pair_setup::snapshot_schema(
            snapshot.trust_policy.fresh_setup_policy.is_some(),
            true,
        )
        || snapshot
            .ongoing_media_policy
            .as_ref()
            .map(|p| p.schema_id.as_str())
            != Some("rusty.manifold.peer.ongoing_media_policy.v2")
        || !matches!(
            checkpoint.schema_id.as_str(),
            "rusty.manifold.peer.runtime_history_checkpoint.v1"
                | "rusty.manifold.peer.runtime_history_checkpoint.v2"
        )
        || (checkpoint.schema_id.as_str() == "rusty.manifold.peer.runtime_history_checkpoint.v2")
            != checkpoint.fresh_history_archive.is_some()
        || (checkpoint.fresh_history_archive.is_some()
            && snapshot.trust_policy.fresh_setup_policy.is_none())
        || checkpoint.request_epoch == 0
        || checkpoint.request_epoch.saturating_sub(1) > checkpoint.event_sequence
        || checkpoint.event_sequence > snapshot.event_sequence
        || checkpoint.pair_route_authority_revision > snapshot.pair_media_routes.authority_revision
        || (checkpoint.request_epoch > 1) != checkpoint.prior_checkpoint_sha256.is_some()
        || (checkpoint.schema_id.as_str() == "rusty.manifold.peer.runtime_history_checkpoint.v1"
            && ((checkpoint.request_epoch > 1)
                != checkpoint.adopted_media_checkpoint_sha256.is_some()))
        || !valid_sha256(&checkpoint.source_snapshot_sha256)
        || checkpoint
            .prior_checkpoint_sha256
            .as_ref()
            .is_some_and(|d| !valid_sha256(d))
        || checkpoint
            .adopted_media_checkpoint_sha256
            .as_ref()
            .is_some_and(|d| !valid_sha256(d))
        || checkpoint.retained_event_ids.len() > 256
        || !strictly_sorted_unique(checkpoint.retained_event_ids.iter())
    {
        return Err(invalid_snapshot("parent history checkpoint shape"));
    }
    fresh_history_archive::validate_fresh_parent_checkpoint(snapshot)?;
    Ok(())
}
pub(super) fn valid_audit_count(snapshot: &ManifoldPeerRuntimeHostSnapshot) -> bool {
    let Some(checkpoint) = &snapshot.runtime_history_checkpoint else {
        return snapshot.event_sequence == snapshot.audit_events.len() as u64;
    };
    let mut retained = snapshot
        .audit_events
        .iter()
        .filter(|event| event.sequence <= checkpoint.event_sequence)
        .map(|event| event.event_id.clone())
        .collect::<Vec<_>>();
    retained.sort();
    retained == checkpoint.retained_event_ids
        && snapshot
            .event_sequence
            .checked_sub(checkpoint.event_sequence)
            .and_then(|count| usize::try_from(count).ok())
            .and_then(|count| count.checked_add(retained.len()))
            == Some(snapshot.audit_events.len())
        && snapshot
            .audit_events
            .windows(2)
            .all(|p| p[0].sequence < p[1].sequence)
}

impl ManifoldPeerRuntimeHost {
    pub(super) fn ensure_history_request(
        &self,
        id: &DottedId,
    ) -> Result<(), ManifoldPeerRuntimeHostError> {
        if request_matches(&self.snapshot, id) {
            Ok(())
        } else {
            Err(ManifoldPeerRuntimeHostError::ReplayedMutation(id.clone()))
        }
    }
    /// Namespaces a fresh parent request; retries retain the original exact ID.
    pub fn current_runtime_history_request_id(
        &self,
        suffix: &DottedId,
    ) -> Result<DottedId, ManifoldPeerRuntimeHostError> {
        if suffix.as_str().starts_with("history.") {
            return Err(invalid_snapshot("parent request already qualified"));
        }
        self.snapshot
            .runtime_history_checkpoint
            .as_ref()
            .map_or_else(
                || Ok(suffix.clone()),
                |checkpoint| {
                    DottedId::new(format!("history.{}.{}", checkpoint.request_epoch, suffix))
                        .map_err(|_| invalid_snapshot("parent request identity"))
                },
            )
    }
    // Selected by the full prospective composition only after both owned children
    // have been created fresh; this function admits no detached current baseline.
    pub(super) fn enable_owned_runtime_history(
        &mut self,
    ) -> Result<(), ManifoldPeerRuntimeHostError> {
        if self.snapshot.runtime_history_checkpoint.is_some() {
            return validate(&self.snapshot);
        }
        if self.signed_history_owner.is_some()
            || self.signed_history_candidate.is_some()
            || self.snapshot.event_sequence != 0
            || !self.snapshot.audit_events.is_empty()
            || self.snapshot.reciprocal_ed25519
                != ManifoldReciprocalEd25519AuthorityStateV3::empty()
            || !self.snapshot.broker_lease_admissions.is_empty()
            || !self.snapshot.media_sessions.sessions.is_empty()
            || !self.snapshot.concurrent_media_renewals.is_empty()
        {
            return Err(invalid_snapshot(
                "parent history requires fresh actual owner",
            ));
        }
        let source_snapshot_sha256 = hash(&self.snapshot)?;
        let mut candidate = self.copy_for_transaction();
        candidate.enable_owned_media_runtime_history()?;
        candidate.enable_owned_signed_history()?;
        candidate.snapshot.ongoing_media_policy = Some(ManifoldOngoingMediaPolicy {
            schema_id: schema("rusty.manifold.peer.ongoing_media_policy.v2"),
        });
        candidate.snapshot.schema_id = schema(fresh_pair_setup::snapshot_schema(
            candidate.snapshot.trust_policy.fresh_setup_policy.is_some(),
            true,
        ));
        candidate.snapshot.runtime_history_checkpoint =
            Some(Box::new(ManifoldPeerRuntimeHistoryCheckpoint {
                schema_id: schema("rusty.manifold.peer.runtime_history_checkpoint.v1"),
                request_epoch: 1,
                event_sequence: 0,
                pair_route_authority_revision: self.snapshot.pair_media_routes.authority_revision,
                retained_event_ids: Vec::new(),
                source_snapshot_sha256,
                prior_checkpoint_sha256: None,
                adopted_media_checkpoint_sha256: None,
                fresh_history_archive: None,
            }));
        if candidate.snapshot.trust_policy.fresh_setup_policy.is_some() {
            candidate.initialize_fresh_prime_origin()?;
        }
        validate_snapshot(&candidate.snapshot)?;
        *self = candidate;
        Ok(())
    }

    /// Composes completed parent, signed, command and Broker prefixes under the
    /// actual two exclusive owners. The embedding must first finish product
    /// adoption; this method never starts, stops or replaces platform resources.
    /// Completed command plans are not previews of new one-use decisions.
    pub fn checkpoint_ongoing_runtime_histories(
        &mut self,
        broker: &mut ManifoldBrokerRuntime,
        adopted: &ManifoldConcurrentMediaAuthorityRenewalReceipt,
        now_ms: u64,
    ) -> Result<Option<ManifoldPeerRuntimeHistoryCheckpoint>, ManifoldPeerRuntimeHostError> {
        self.checkpoint_runtime_histories_candidate(
            broker,
            adopted,
            now_ms,
            self.copy_for_transaction(),
        )
    }
    /// Atomically composes media and generic histories from the actual current
    /// Peer/Broker owners after product adoption. No intermediate candidate is
    /// exposed as accepted state and no platform effect runs here.
    pub fn checkpoint_coupled_ongoing_histories(
        &mut self,
        broker: &mut ManifoldBrokerRuntime,
        adopted: &ManifoldConcurrentMediaAuthorityRenewalReceipt,
        now_ms: u64,
    ) -> Result<Option<ManifoldConcurrentMediaCheckpoint>, ManifoldPeerRuntimeHostError> {
        if !selected(&self.snapshot) {
            return Err(invalid_snapshot("v2 history composition not selected"));
        }
        let Some((candidate, checkpoint)) =
            self.prepare_concurrent_media_checkpoint(broker, adopted, now_ms)?
        else {
            return Ok(None);
        };
        self.checkpoint_runtime_histories_candidate(broker, adopted, now_ms, candidate)?;
        Ok(Some(checkpoint))
    }
    fn checkpoint_runtime_histories_candidate(
        &mut self,
        broker: &mut ManifoldBrokerRuntime,
        adopted: &ManifoldConcurrentMediaAuthorityRenewalReceipt,
        now_ms: u64,
        mut candidate: Self,
    ) -> Result<Option<ManifoldPeerRuntimeHistoryCheckpoint>, ManifoldPeerRuntimeHostError> {
        let Some(prior) = &self.snapshot.runtime_history_checkpoint else {
            return Ok(None);
        };
        self.validate_owned_state_with_live_broker(broker)?;
        let media = candidate
            .snapshot
            .concurrent_media_checkpoint
            .as_ref()
            .ok_or_else(|| {
                invalid_snapshot("generic checkpoint needs complete concurrent checkpoint")
            })?;
        if &media.baseline != adopted
            || adopted.expires_at_ms <= now_ms
            || candidate.snapshot.concurrent_media_renewals.last() != Some(adopted)
            || !self
                .snapshot
                .broker_lease_revocation_convergences
                .is_empty()
            || !self
                .snapshot
                .broker_lease_revocation_cleanup_completions
                .is_empty()
            || !self.snapshot.broker_epoch_rollovers.is_empty()
            || !self.snapshot.rendezvous.accepted_receipts.is_empty()
            || !self.snapshot.direct_lane_leases.leases.is_empty()
            || !self.snapshot.peer_mesh.members.is_empty()
        {
            return Err(invalid_snapshot(
                "generic checkpoint unresolved or unsupported owner scope",
            ));
        }
        let media_sha = hash(media)?;
        if prior.adopted_media_checkpoint_sha256.as_ref() == Some(&media_sha) {
            return Ok(None);
        }
        let checkpoint = ManifoldPeerRuntimeHistoryCheckpoint {
            schema_id: schema("rusty.manifold.peer.runtime_history_checkpoint.v1"),
            request_epoch: prior
                .request_epoch
                .checked_add(1)
                .ok_or_else(|| invalid_snapshot("parent history epoch exhausted"))?,
            event_sequence: self.snapshot.event_sequence,
            pair_route_authority_revision: self.snapshot.pair_media_routes.authority_revision,
            retained_event_ids: Vec::new(),
            source_snapshot_sha256: hash(&self.snapshot)?,
            prior_checkpoint_sha256: Some(hash(prior)?),
            adopted_media_checkpoint_sha256: Some(media_sha),
            fresh_history_archive: None,
        };
        // Preserve every source needed by current accepted derivative obligations.
        // The exact source audit bodies remain visible beside the bounded suffix.
        ongoing_media::prune_completed_media_lifetimes(&mut candidate.snapshot, adopted)?;
        let admission_ids = candidate
            .snapshot
            .broker_lease_admissions
            .iter()
            .map(|a| a.broker_receipt.admission_use_request_id.clone())
            .collect::<BTreeSet<_>>();
        let release_ids = candidate
            .snapshot
            .broker_lease_admissions
            .iter()
            .filter_map(|a| a.release_id.clone())
            .collect::<BTreeSet<_>>();
        let mut pair_sources = BTreeSet::new();
        let mut command_sources = BTreeSet::new();
        for route in &candidate.snapshot.pair_media_routes.routes {
            pair_sources.insert(route.request_id().clone());
            if let Some(id) = route.ended_by_id() {
                pair_sources.insert(id.clone());
            }
            match route {
                ManifoldAcceptedPairMediaRouteV2::CommonLan(v) => {
                    command_sources.insert(v.runtime_command_request_id.clone());
                }
                ManifoldAcceptedPairMediaRouteV2::WifiDirect(_) => {
                    return Err(invalid_snapshot("ongoing route scope"))
                }
            }
            if let Some(binding) = route.termination_runtime_binding() {
                command_sources.insert(binding.request_id.clone());
            }
        }
        for receipt in &candidate.snapshot.pair_media_routes.cleanup_receipts {
            pair_sources.insert(receipt.request_id().clone());
            command_sources.insert(receipt.runtime_binding().request_id.clone());
        }
        candidate
            .snapshot
            .pair_media_routes
            .applied_request_ids
            .retain(|id| pair_sources.contains(id));
        let media_sources = candidate
            .snapshot
            .media_sessions
            .sessions
            .iter()
            .flat_map(|media| {
                std::iter::once(media.request_id.clone()).chain(media.ended_by_id.clone())
            })
            .collect::<BTreeSet<_>>();
        candidate
            .snapshot
            .media_sessions
            .applied_request_ids
            .retain(|id| media_sources.contains(id));
        let fresh_sources = candidate
            .snapshot
            .fresh_pair_setup
            .as_ref()
            .map(|s| {
                s.receipts
                    .iter()
                    .map(|r| r.local_request_id.clone())
                    .chain(
                        s.prime_enrollments
                            .iter()
                            .map(|e| e.request.request_id.clone()),
                    )
                    .chain(
                        s.phase_preparations
                            .iter()
                            .map(|r| r.local_request_id.clone()),
                    )
                    .collect::<BTreeSet<_>>()
            })
            .unwrap_or_default();
        candidate.snapshot.audit_events.retain(|event| {
            (matches!(
                event.event_kind,
                ManifoldPeerRuntimeAuditKind::Enrollment
                    | ManifoldPeerRuntimeAuditKind::FreshPhasePrepare
            ) && event.applied
                && fresh_sources.contains(&event.source_id))
                || (event.event_kind == ManifoldPeerRuntimeAuditKind::BrokerLeaseAdmission
                    && event.applied
                    && admission_ids.contains(&event.source_id))
                || (event.event_kind == ManifoldPeerRuntimeAuditKind::BrokerLeaseRelease
                    && release_ids.contains(&event.source_id))
                || (is_pair_media_route_audit_kind(&event.event_kind)
                    && pair_sources.contains(&event.source_id))
        });
        let mut checkpoint = checkpoint;
        checkpoint.retained_event_ids = candidate
            .snapshot
            .audit_events
            .iter()
            .map(|e| e.event_id.clone())
            .collect();
        checkpoint.retained_event_ids.sort();
        candidate
            .snapshot
            .accepted_peers
            .applied_proposal_ids
            .clear();
        let mut enrollment_ids = candidate
            .snapshot
            .concurrent_credential_refreshes
            .iter()
            .map(|r| r.request_id.clone())
            .collect::<BTreeSet<_>>();
        if let Some(fresh) = &candidate.snapshot.fresh_pair_setup {
            enrollment_ids.extend(fresh.receipts.iter().map(|r| r.local_request_id.clone()));
            enrollment_ids.extend(
                fresh
                    .prime_enrollments
                    .iter()
                    .map(|e| e.request.request_id.clone()),
            );
        }
        candidate
            .snapshot
            .enrollment
            .applied_request_ids
            .retain(|id| enrollment_ids.contains(id));
        let mut session_ids = candidate
            .snapshot
            .concurrent_session_renewals
            .iter()
            .map(|r| r.request_id.clone())
            .collect::<BTreeSet<_>>();
        for session in &candidate.snapshot.peer_sessions.sessions {
            match session {
                ManifoldAcceptedPeerSessionV2::CommonLan(v) => {
                    session_ids.insert(v.proposal.proposal_id.clone());
                }
                ManifoldAcceptedPeerSessionV2::WifiDirect(_) => {
                    return Err(invalid_snapshot("generic history common-LAN scope"))
                }
            }
        }
        candidate
            .snapshot
            .peer_sessions
            .applied_proposal_ids
            .retain(|id| session_ids.contains(id));
        let mut reciprocal_ids = candidate
            .snapshot
            .concurrent_session_renewals
            .iter()
            .map(|r| r.reciprocal.receipt_id.clone())
            .collect::<BTreeSet<_>>();
        reciprocal_ids.extend(
            candidate
                .snapshot
                .concurrent_credential_refreshes
                .iter()
                .map(|r| r.reciprocal.receipt_id.clone()),
        );
        for topology in &candidate.snapshot.signed_topology_authorizations {
            match topology {
                ManifoldSignedPeerTopologyAuthorizationV2::CommonLan(v) => {
                    reciprocal_ids.insert(v.reciprocal_receipt_id.clone());
                }
                ManifoldSignedPeerTopologyAuthorizationV2::WifiDirect(_) => {
                    return Err(invalid_snapshot(
                        "generic history common-LAN topology scope",
                    ))
                }
            }
        }
        let signed_plan = self
            .signed_history_owner
            .as_ref()
            .ok_or_else(|| invalid_snapshot("actual signed owner absent"))?
            .plan_checkpoint(&reciprocal_ids.into_iter().collect::<Vec<_>>())
            .map_err(invalid_snapshot)?;
        candidate.snapshot.reciprocal_ed25519 = signed_plan.state().clone();
        let mut command_owner = candidate.media_runtime_copy()?;
        command_owner
            .checkpoint_ongoing_history_retaining(&command_sources.into_iter().collect::<Vec<_>>())
            .map_err(|e| invalid_snapshot(&format!("owned command checkpoint: {e}")))?;
        candidate.retain_media_runtime(command_owner);
        candidate.snapshot.runtime_history_checkpoint = Some(Box::new(checkpoint.clone()));
        let mut retained_uses = candidate
            .snapshot
            .broker_lease_admissions
            .iter()
            .filter(|a| a.released_at_ms.is_none())
            .map(|a| a.broker_receipt.admission_use_request_id.clone())
            .collect::<Vec<_>>();
        retained_uses.sort();
        retained_uses.dedup();
        let broker_plan = broker
            .plan_ongoing_history_checkpoint(&retained_uses, now_ms)
            .map_err(ManifoldPeerRuntimeHostError::from)?;
        validate_snapshot(&candidate.snapshot)?;
        candidate.validate_media_runtime_owner()?;
        validate_live_broker_restoration(&candidate.snapshot, &broker_plan.evidence())?;
        // Both exact-current checks finish before either owner changes. Borrowed
        // verified plans hold the actual gates until infallible publication.
        let broker_commit = broker
            .verify_ongoing_history_checkpoint(broker_plan)
            .map_err(ManifoldPeerRuntimeHostError::from)?;
        let signed_commit = self
            .signed_history_owner
            .as_mut()
            .expect("actual signed owner retained")
            .verify_plan(signed_plan)
            .map_err(invalid_snapshot)?;
        broker_commit.commit();
        signed_commit.commit();
        candidate.signed_history_candidate = None;
        candidate.signed_history_owner = self.signed_history_owner.take();
        *self = candidate;
        Ok(Some(checkpoint))
    }
}
