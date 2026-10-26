//! Bounded live-owner histories; detached checkpoints never admit authority.
use super::*;
use sha2::{Digest, Sha256};

/// Explicit opted-in Runtime Host storage; finite v4 remains unchanged.
pub const ONGOING_HOST_SNAPSHOT_SCHEMA: &str = "rusty.manifold.runtime_host.snapshot.v5";

/// Commitment to a completed audit prefix with monotonic replay namespace.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldRuntimeHistoryCheckpoint {
    /// Storage schema.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Mandatory namespace for subsequent command/adoption/revocation/sweep identities.
    pub request_epoch: u64,
    /// Last global audit sequence included in the checkpoint.
    pub audit_sequence: u64,
    /// Accepted authority revision at that boundary; compaction never resets it.
    pub authority_revision: Revision,
    /// Commitment to the prior checkpoint, without its recursively growing body.
    pub prior_checkpoint_sha256: Option<String>,
    /// Commitment to the exact complete accepted source snapshot.
    pub source_snapshot_sha256: String,
    /// Exact accepted source audit bodies retained for current downstream obligations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retained_event_ids: Vec<DottedId>,
}

/// Borrowed restore authority minted only from the independent current owner.
#[derive(Debug)]
pub struct ManifoldRuntimeHistoryRestoreAnchor<'owner> {
    owner: &'owner ManifoldRuntimeHost,
    snapshot_sha256: String,
}

/// Projection of a derivative lease already accepted by the enclosing owner.
/// Deliberately not deserializable: external transport cannot select this gate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManifoldRuntimeAcceptedDerivativeProjection {
    /// Project one newly admitted upstream-bound derivative.
    Admit(ManifoldRuntimeLease),
    /// Project an accepted deadline extension of the exact current derivative.
    Renew {
        /// Exact derivative currently retained by this owner.
        prior: ManifoldRuntimeLease,
        /// Already accepted replacement with the same lineage and a later deadline.
        renewed: ManifoldRuntimeLease,
    },
    /// Project terminal release of the exact current derivative.
    Release(ManifoldRuntimeLease),
}

fn digest<T: Serialize>(value: &T) -> Result<String, ManifoldRuntimeHostError> {
    let mut hash = Sha256::new();
    hash.update(b"rusty.manifold.runtime_host.ongoing_history.sha256.v1\0");
    hash.update(serde_json::to_vec(value).map_err(ManifoldRuntimeHostError::Serialize)?);
    Ok(format!("sha256:{:x}", hash.finalize()))
}

pub(super) fn audit_base(snapshot: &ManifoldRuntimeHostSnapshot) -> u64 {
    snapshot.history_checkpoint.as_ref().map_or(0, |c| {
        c.audit_sequence
            .saturating_sub(c.retained_event_ids.len() as u64)
    })
}
pub(super) fn audit_capacity_exhausted(snapshot: &ManifoldRuntimeHostSnapshot) -> bool {
    snapshot.audit_events.len() >= MAX_RUNTIME_AUDIT_EVENTS
        || audit_base(snapshot)
            .checked_add(snapshot.audit_events.len() as u64)
            .and_then(|v| v.checked_add(1))
            .is_none()
        || (snapshot.history_checkpoint.is_some() && snapshot.authority_revision.next().is_none())
}
pub(super) fn next_sequence(snapshot: &ManifoldRuntimeHostSnapshot) -> u64 {
    audit_base(snapshot)
        .checked_add(snapshot.audit_events.len() as u64)
        .and_then(|v| v.checked_add(1))
        .expect("audit capacity checked before mutation")
}
pub(super) fn request_matches(snapshot: &ManifoldRuntimeHostSnapshot, id: &DottedId) -> bool {
    snapshot.history_checkpoint.as_ref().map_or(true, |c| {
        id.as_str()
            .strip_prefix(&format!("history.{}.", c.request_epoch))
            .is_some_and(|suffix| !suffix.is_empty() && !suffix.starts_with("history."))
    })
}
pub(super) fn validate_checkpoint(
    snapshot: &ManifoldRuntimeHostSnapshot,
) -> Result<(), ManifoldRuntimeHostError> {
    let Some(c) = &snapshot.history_checkpoint else {
        return if snapshot.schema_id.as_str() == HOST_SNAPSHOT_SCHEMA {
            Ok(())
        } else {
            Err(ManifoldRuntimeHostError::InvalidSnapshot(
                "history_policy_schema",
            ))
        };
    };
    if snapshot.schema_id.as_str() != ONGOING_HOST_SNAPSHOT_SCHEMA
        || !matches!(
            c.schema_id.as_str(),
            "rusty.manifold.runtime_host.history_checkpoint.v1"
                | "rusty.manifold.runtime_host.history_checkpoint.v2"
        )
        || (c.schema_id.as_str() == "rusty.manifold.runtime_host.history_checkpoint.v1"
            && !c.retained_event_ids.is_empty())
        || c.retained_event_ids.len() > 64
        || snapshot
            .audit_events
            .windows(2)
            .any(|p| p[0].sequence >= p[1].sequence)
        || snapshot.audit_events.iter().any(|e| {
            c.retained_event_ids.contains(&e.event_id)
                && e.resulting_authority_revision > c.authority_revision
        })
        || c.retained_event_ids.windows(2).any(|p| p[0] >= p[1])
        || c.audit_sequence < c.retained_event_ids.len() as u64
        || snapshot
            .audit_events
            .iter()
            .filter(|e| e.sequence <= c.audit_sequence)
            .map(|e| e.event_id.clone())
            .collect::<BTreeSet<_>>()
            != c.retained_event_ids
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>()
        || c.request_epoch == 0
        || c.audit_sequence < c.request_epoch.saturating_sub(1)
        || (c.request_epoch > 1) != c.prior_checkpoint_sha256.is_some()
        || c.authority_revision > snapshot.authority_revision
        || !valid_sha256_digest(&c.source_snapshot_sha256)
        || c.prior_checkpoint_sha256
            .as_ref()
            .is_some_and(|h| !valid_sha256_digest(h))
    {
        return Err(ManifoldRuntimeHostError::InvalidSnapshot(
            "history_checkpoint_shape",
        ));
    }
    Ok(())
}

impl ManifoldRuntimeHost {
    /// Projects only an already accepted enclosing-owner derivative decision.
    ///
    /// This trusted composition boundary performs no lease review, issues no
    /// grant and emits no application/effect receipt. The enclosing authority
    /// must validate its actual live source before constructing the typed delta.
    /// It replaces its previous direct accepted lease snapshot projection;
    /// accepted revision/audit remain owned by that enclosing authority.
    /// A whole target snapshot is never accepted here.
    pub fn project_accepted_derivative_lease(
        &mut self,
        expected_revision: Revision,
        projection: &ManifoldRuntimeAcceptedDerivativeProjection,
        now_ms: u64,
    ) -> Result<(), ManifoldRuntimeHostError> {
        if self.snapshot.history_checkpoint.is_none()
            || expected_revision != self.snapshot.authority_revision
        {
            return Err(ManifoldRuntimeHostError::InvalidSnapshot(
                "derivative_projection_owner_or_revision",
            ));
        }
        let mut candidate = self.clone();
        match projection {
            ManifoldRuntimeAcceptedDerivativeProjection::Admit(lease) => {
                if lease.derivative_binding.is_none()
                    || lease.expires_at_ms <= now_ms
                    || candidate
                        .snapshot
                        .leases
                        .iter()
                        .any(|old| old.lease_id == lease.lease_id)
                    || candidate.snapshot.leases.len() >= MAX_RUNTIME_SNAPSHOT_RECORDS
                {
                    return Err(ManifoldRuntimeHostError::InvalidSnapshot(
                        "derivative_projection_admission",
                    ));
                }
                candidate.snapshot.leases.push(lease.clone());
                candidate
                    .snapshot
                    .leases
                    .sort_by(|a, b| a.lease_id.cmp(&b.lease_id));
            }
            ManifoldRuntimeAcceptedDerivativeProjection::Renew { prior, renewed } => {
                if prior.derivative_binding.is_none()
                    || prior.expires_at_ms <= now_ms
                    || renewed.derivative_binding != prior.derivative_binding
                    || renewed.lease_id != prior.lease_id
                    || renewed.holder_id != prior.holder_id
                    || renewed.scope != prior.scope
                    || renewed.expires_at_ms <= prior.expires_at_ms
                    || renewed.expires_at_ms <= now_ms
                {
                    return Err(ManifoldRuntimeHostError::InvalidSnapshot(
                        "derivative_projection_renewal",
                    ));
                }
                let current = candidate
                    .snapshot
                    .leases
                    .iter_mut()
                    .find(|l| l.lease_id == prior.lease_id)
                    .ok_or(ManifoldRuntimeHostError::InvalidSnapshot(
                        "derivative_projection_missing",
                    ))?;
                if current != prior {
                    return Err(ManifoldRuntimeHostError::InvalidSnapshot(
                        "derivative_projection_stale",
                    ));
                }
                *current = renewed.clone();
            }
            ManifoldRuntimeAcceptedDerivativeProjection::Release(prior) => {
                if prior.derivative_binding.is_none() || !candidate.snapshot.leases.contains(prior)
                {
                    return Err(ManifoldRuntimeHostError::InvalidSnapshot(
                        "derivative_projection_release",
                    ));
                }
                candidate
                    .snapshot
                    .leases
                    .retain(|l| l.lease_id != prior.lease_id);
            }
        }
        validate_snapshot(&candidate.snapshot)?;
        *self = candidate;
        Ok(())
    }
    /// Selects prospective ongoing storage on a fresh actual owner. Commands,
    /// existing accepted leases and their deadlines remain unchanged.
    pub fn enable_ongoing_history(&mut self) -> Result<(), ManifoldRuntimeHostError> {
        validate_snapshot(&self.snapshot)?;
        if self.snapshot.history_checkpoint.is_some() {
            return Ok(());
        }
        if self.snapshot.authority_revision != Revision::INITIAL
            || !self.snapshot.audit_events.is_empty()
            || !self.snapshot.applied_request_ids.is_empty()
            || !self.snapshot.reviewed_sweep_ids.is_empty()
            || !self.snapshot.reviewed_control_lease_adoption_ids.is_empty()
            || !self
                .snapshot
                .reviewed_derivative_lease_revocation_ids
                .is_empty()
        {
            return Err(ManifoldRuntimeHostError::InvalidSnapshot(
                "ongoing_history_requires_fresh_owner",
            ));
        }
        let mut candidate = self.clone();
        candidate.snapshot.history_checkpoint = Some(ManifoldRuntimeHistoryCheckpoint {
            schema_id: schema_id("rusty.manifold.runtime_host.history_checkpoint.v1"),
            request_epoch: 1,
            audit_sequence: 0,
            authority_revision: self.snapshot.authority_revision,
            prior_checkpoint_sha256: None,
            source_snapshot_sha256: digest(&self.snapshot)?,
            retained_event_ids: Vec::new(),
        });
        candidate.snapshot.schema_id = schema_id(ONGOING_HOST_SNAPSHOT_SCHEMA);
        validate_snapshot(&candidate.snapshot)?;
        *self = candidate;
        Ok(())
    }
    /// Qualifies a new identity; pending operations must retain their original id.
    pub fn current_history_request_id(
        &self,
        suffix: &DottedId,
    ) -> Result<DottedId, ManifoldRuntimeHostError> {
        if suffix.as_str().starts_with("history.") {
            return Err(ManifoldRuntimeHostError::InvalidSnapshot(
                "history_request_already_qualified",
            ));
        }
        Ok(self.snapshot.history_checkpoint.as_ref().map_or_else(
            || suffix.clone(),
            |c| {
                DottedId::new(format!("history.{}.{}", c.request_epoch, suffix))
                    .expect("qualified id")
            },
        ))
    }
    /// Checkpoints only this actual owner's completed ledger. An embedding
    /// composition must separately close its pending effects before adoption.
    pub fn checkpoint_ongoing_history(
        &mut self,
    ) -> Result<ManifoldRuntimeHistoryCheckpoint, ManifoldRuntimeHostError> {
        self.checkpoint_ongoing_history_retaining(&[])
    }
    /// Retains only exact already accepted audit sources required by the enclosing owner.
    /// No caller-supplied audit body or replacement baseline is accepted.
    pub fn checkpoint_ongoing_history_retaining(
        &mut self,
        source_ids: &[DottedId],
    ) -> Result<ManifoldRuntimeHistoryCheckpoint, ManifoldRuntimeHostError> {
        validate_snapshot(&self.snapshot)?;
        if source_ids.len() > 64
            || source_ids.windows(2).any(|p| p[0] >= p[1])
            || source_ids.iter().any(|id| {
                !self
                    .snapshot
                    .audit_events
                    .iter()
                    .any(|e| &e.source_id == id && e.applied)
            })
        {
            return Err(ManifoldRuntimeHostError::InvalidSnapshot(
                "history_retained_source",
            ));
        }
        let retained_events = self
            .snapshot
            .audit_events
            .iter()
            .filter(|e| source_ids.contains(&e.source_id))
            .cloned()
            .collect::<Vec<_>>();
        if retained_events.len() > 64 {
            return Err(ManifoldRuntimeHostError::InvalidSnapshot(
                "history_retained_capacity",
            ));
        }
        let mut retained_event_ids = retained_events
            .iter()
            .map(|e| e.event_id.clone())
            .collect::<Vec<_>>();
        retained_event_ids.sort();
        let prior = self.snapshot.history_checkpoint.as_ref().ok_or(
            ManifoldRuntimeHostError::InvalidSnapshot("ongoing_history_not_selected"),
        )?;
        if self.snapshot.audit_events.len() == prior.retained_event_ids.len()
            && retained_event_ids == prior.retained_event_ids
        {
            return Ok(prior.clone());
        }
        let checkpoint = ManifoldRuntimeHistoryCheckpoint {
            schema_id: schema_id(if retained_event_ids.is_empty() {
                "rusty.manifold.runtime_host.history_checkpoint.v1"
            } else {
                "rusty.manifold.runtime_host.history_checkpoint.v2"
            }),
            request_epoch: prior.request_epoch.checked_add(1).ok_or(
                ManifoldRuntimeHostError::InvalidSnapshot("history_epoch_exhausted"),
            )?,
            audit_sequence: prior
                .audit_sequence
                .checked_add(
                    (self.snapshot.audit_events.len() - prior.retained_event_ids.len()) as u64,
                )
                .ok_or(ManifoldRuntimeHostError::InvalidSnapshot(
                    "history_sequence_exhausted",
                ))?,
            authority_revision: self.snapshot.authority_revision,
            prior_checkpoint_sha256: Some(digest(prior)?),
            source_snapshot_sha256: digest(&self.snapshot)?,
            retained_event_ids,
        };
        let mut candidate = self.clone();
        candidate.snapshot.history_checkpoint = Some(checkpoint.clone());
        candidate.snapshot.audit_events = retained_events;
        candidate
            .snapshot
            .applied_request_ids
            .retain(|id| source_ids.contains(id));
        candidate
            .snapshot
            .reviewed_sweep_ids
            .retain(|id| source_ids.contains(id));
        candidate
            .snapshot
            .reviewed_control_lease_adoption_ids
            .retain(|id| source_ids.contains(id));
        candidate
            .snapshot
            .reviewed_derivative_lease_revocation_ids
            .retain(|id| source_ids.contains(id));
        validate_snapshot(&candidate.snapshot)?;
        *self = candidate;
        Ok(checkpoint)
    }
    /// Structural validation only: this constructs no authority and admits no baseline.
    pub fn validate_snapshot_shape(
        snapshot: &ManifoldRuntimeHostSnapshot,
    ) -> Result<(), ManifoldRuntimeHostError> {
        validate_snapshot(snapshot)
    }
    /// Validates the actual already owned object.
    pub fn validate_owned_history(&self) -> Result<(), ManifoldRuntimeHostError> {
        validate_snapshot(&self.snapshot)
    }
    /// Seals the exact current owner for same-process restore only.
    pub fn seal_ongoing_history(
        &self,
    ) -> Result<ManifoldRuntimeHistoryRestoreAnchor<'_>, ManifoldRuntimeHostError> {
        if self.snapshot.history_checkpoint.is_none() {
            return Err(ManifoldRuntimeHostError::InvalidSnapshot(
                "ongoing_history_not_selected",
            ));
        }
        validate_snapshot(&self.snapshot)?;
        Ok(ManifoldRuntimeHistoryRestoreAnchor {
            owner: self,
            snapshot_sha256: digest(&self.snapshot)?,
        })
    }
    /// Requires the independent current live owner; target JSON cannot mint this anchor.
    pub fn restore_ongoing_history(
        json: &str,
        anchor: &ManifoldRuntimeHistoryRestoreAnchor<'_>,
    ) -> Result<Self, ManifoldRuntimeHostError> {
        let snapshot: ManifoldRuntimeHostSnapshot =
            serde_json::from_str(json).map_err(ManifoldRuntimeHostError::Deserialize)?;
        if snapshot.history_checkpoint.is_none()
            || digest(&snapshot)? != anchor.snapshot_sha256
            || digest(&anchor.owner.snapshot)? != anchor.snapshot_sha256
        {
            return Err(ManifoldRuntimeHostError::InvalidSnapshot(
                "ongoing_restore_requires_live_owner",
            ));
        }
        validate_snapshot(&snapshot)?;
        Ok(Self {
            snapshot,
            source_bound_root_owner: anchor.owner.source_bound_root_owner.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn id(s: &str) -> DottedId {
        DottedId::new(s).unwrap()
    }
    fn owner() -> ManifoldRuntimeHost {
        let mut owner = ManifoldRuntimeHost::restart_from_json(include_str!(
            "../../../fixtures/runtime-host/synthetic-runtime-host-snapshot.json"
        ))
        .unwrap();
        owner.enable_ongoing_history().unwrap();
        owner
    }
    fn request(owner: &ManifoldRuntimeHost, suffix: &str) -> ManifoldRuntimeCommandRequest {
        let mut request: ManifoldRuntimeCommandRequest = serde_json::from_str(include_str!(
            "../../../fixtures/runtime-host/synthetic-runtime-command-request.json"
        ))
        .unwrap();
        request.request_id = owner.current_history_request_id(&id(suffix)).unwrap();
        request.expected_authority_revision = owner.snapshot.authority_revision;
        request
    }
    #[test]
    fn ongoing_10000_real_commands_keep_current_leases_and_global_revision_with_bounded_replay() {
        let mut owner = owner();
        let leases = owner.snapshot.leases.clone();
        let commands = owner.snapshot.commands.clone();
        let mut first = None;
        let mut old_json: Option<String> = None;
        for cycle in 0..10_000u64 {
            let r = request(&owner, &format!("request.command.r{cycle}"));
            let reviewed = owner.review_command(&r, 2000);
            assert_eq!(reviewed.outcome, ManifoldRuntimeDispatchOutcome::Ready);
            assert!(owner.apply_dispatch(&r, &reviewed, 2000).applied);
            if first.is_none() {
                first = Some(r);
            }
            if cycle % 16 == 15 {
                let revision = owner.snapshot.authority_revision;
                let c = owner.checkpoint_ongoing_history().unwrap();
                assert_eq!(c.audit_sequence, cycle + 1 + cycle / 16);
                assert_eq!(owner.snapshot.authority_revision, revision);
                assert_eq!(owner.snapshot.leases, leases);
                assert_eq!(owner.snapshot.commands, commands);
                assert!(owner.snapshot.audit_events.is_empty());
                assert!(owner.snapshot.applied_request_ids.is_empty());
                let json = owner.snapshot_json().unwrap();
                let anchor = owner.seal_ongoing_history().unwrap();
                assert_eq!(
                    ManifoldRuntimeHost::restore_ongoing_history(&json, &anchor).unwrap(),
                    owner
                );
                assert!(ManifoldRuntimeHost::restart_from_json(&json).is_err());
                if let Some(old) = &old_json {
                    assert!(ManifoldRuntimeHost::restore_ongoing_history(old, &anchor).is_err());
                }
                let mut damage = owner.snapshot.clone();
                damage.leases[0].expires_at_ms += 1;
                assert!(ManifoldRuntimeHost::restore_ongoing_history(
                    &serde_json::to_string(&damage).unwrap(),
                    &anchor
                )
                .is_err());
                old_json = Some(json);
                let mut replay = first.clone().unwrap();
                replay.expected_authority_revision = owner.snapshot.authority_revision;
                assert_eq!(
                    owner.review_command(&replay, 2000).rejection_reason,
                    Some(ManifoldRuntimeRejectionReason::ReplayedRequest)
                );
                // A rejection is recorded, never promoted to an applied command.
                let rejection = owner.review_command(&replay, 2000);
                assert!(!owner.apply_dispatch(&replay, &rejection, 2000).applied);
            }
            assert_eq!(owner.snapshot.leases, leases);
            owner.validate_owned_history().unwrap();
            assert!(owner.snapshot.audit_events.len() <= 17);
        }
        assert_eq!(owner.snapshot.authority_revision.get(), 10_001);
        assert!(owner.snapshot_json().unwrap().len() < 65_536);
    }
    #[test]
    fn ongoing_retained_application_survives_bounded_prefix_and_cannot_authorize_new_work() {
        let mut owner = owner();
        let first = request(&owner, "request.retained");
        let dispatch = owner.review_command(&first, 2000);
        assert!(owner.apply_dispatch(&first, &dispatch, 2000).applied);
        let source = owner.snapshot.audit_events[0].clone();
        for cycle in 0..160u64 {
            let r = request(&owner, &format!("request.current.c{cycle}"));
            let d = owner.review_command(&r, 2000);
            assert!(owner.apply_dispatch(&r, &d, 2000).applied);
            if cycle % 16 == 15 {
                owner
                    .checkpoint_ongoing_history_retaining(&[first.request_id.clone()])
                    .unwrap();
                assert_eq!(owner.snapshot.audit_events, vec![source.clone()]);
                assert_eq!(
                    owner.snapshot.applied_request_ids,
                    vec![first.request_id.clone()]
                );
                assert_eq!(
                    owner
                        .snapshot
                        .history_checkpoint
                        .as_ref()
                        .unwrap()
                        .audit_sequence,
                    cycle + 2
                );
                let mut replay = first.clone();
                replay.expected_authority_revision = owner.snapshot.authority_revision;
                assert_eq!(
                    owner.review_command(&replay, 2000).rejection_reason,
                    Some(ManifoldRuntimeRejectionReason::ReplayedRequest)
                );
                let before = owner.clone();
                assert!(owner
                    .checkpoint_ongoing_history_retaining(&[id("request.foreign")])
                    .is_err());
                assert_eq!(owner, before);
                let anchor = owner.seal_ongoing_history().unwrap();
                let bytes = owner.snapshot_json().unwrap();
                assert_eq!(
                    ManifoldRuntimeHost::restore_ongoing_history(&bytes, &anchor).unwrap(),
                    owner
                );
            }
            assert!(owner.snapshot.audit_events.len() <= 17);
        }
        owner.checkpoint_ongoing_history_retaining(&[]).unwrap();
        assert!(owner.snapshot.audit_events.is_empty());
        assert_eq!(
            owner
                .snapshot
                .history_checkpoint
                .as_ref()
                .unwrap()
                .audit_sequence,
            161
        );
        let mut replay = first.clone();
        replay.expected_authority_revision = owner.snapshot.authority_revision;
        assert_eq!(
            owner.review_command(&replay, 2000).rejection_reason,
            Some(ManifoldRuntimeRejectionReason::ReplayedRequest)
        );
    }

    #[test]
    fn ongoing_epoch_and_global_sequence_overflow_refuse_without_mutation() {
        let mut owner = owner();
        let c = owner.snapshot.history_checkpoint.as_mut().unwrap();
        c.request_epoch = u64::MAX;
        c.audit_sequence = u64::MAX - 1;
        c.prior_checkpoint_sha256 = Some(format!("sha256:{}", "a".repeat(64)));
        let r = request(&owner, "request.last");
        let d = owner.review_command(&r, 2000);
        assert!(owner.apply_dispatch(&r, &d, 2000).applied);
        let saved = owner.clone();
        assert!(owner.checkpoint_ongoing_history().is_err());
        assert_eq!(owner, saved);
        let r = request(&owner, "request.overflow");
        let d = owner.review_command(&r, 2000);
        assert_eq!(
            owner.apply_dispatch(&r, &d, 2000).rejection_reason,
            Some(ManifoldRuntimeRejectionReason::AuthorityCapacityExhausted)
        );
        assert_eq!(owner, saved);
    }

    #[test]
    fn ongoing_accepted_derivative_projection_preserves_owner_and_rejects_stale_or_foreign_delta() {
        let mut owner = owner();
        let initial = owner.snapshot.clone();
        let mut lease = initial.leases[0].clone();
        lease.lease_id = id("lease.accepted.derivative");
        lease.derivative_binding = Some(ManifoldRuntimeDerivativeLeaseBinding {
            schema_id: schema_id(HOST_DERIVATIVE_LEASE_BINDING_SCHEMA),
            binding_id: id("binding.accepted.derivative"),
            provider_epoch_id: id("epoch.provider.accepted"),
            upstream_control_lease_id: id("lease.upstream.accepted"),
            source_authorization_id: id("authorization.accepted.derivative"),
        });
        let revision = owner.snapshot.authority_revision;
        owner
            .project_accepted_derivative_lease(
                revision,
                &ManifoldRuntimeAcceptedDerivativeProjection::Admit(lease.clone()),
                2000,
            )
            .unwrap();
        let mut renewed = lease.clone();
        renewed.expires_at_ms += 1000;
        owner
            .project_accepted_derivative_lease(
                revision,
                &ManifoldRuntimeAcceptedDerivativeProjection::Renew {
                    prior: lease.clone(),
                    renewed: renewed.clone(),
                },
                2000,
            )
            .unwrap();
        let saved = owner.clone();
        for delta in [
            ManifoldRuntimeAcceptedDerivativeProjection::Admit(renewed.clone()),
            ManifoldRuntimeAcceptedDerivativeProjection::Release(lease.clone()),
            ManifoldRuntimeAcceptedDerivativeProjection::Renew {
                prior: lease.clone(),
                renewed: renewed.clone(),
            },
        ] {
            assert!(owner
                .project_accepted_derivative_lease(revision, &delta, 2000)
                .is_err());
            assert_eq!(owner, saved);
        }
        let mut foreign = renewed.clone();
        foreign.expires_at_ms += 1000;
        foreign
            .derivative_binding
            .as_mut()
            .unwrap()
            .provider_epoch_id = id("epoch.foreign");
        assert!(owner
            .project_accepted_derivative_lease(
                revision,
                &ManifoldRuntimeAcceptedDerivativeProjection::Renew {
                    prior: renewed.clone(),
                    renewed: foreign
                },
                2000
            )
            .is_err());
        assert_eq!(owner, saved);
        assert!(owner
            .project_accepted_derivative_lease(
                revision.next().unwrap(),
                &ManifoldRuntimeAcceptedDerivativeProjection::Release(renewed.clone()),
                2000
            )
            .is_err());
        assert_eq!(owner, saved);
        owner
            .project_accepted_derivative_lease(
                revision,
                &ManifoldRuntimeAcceptedDerivativeProjection::Release(renewed),
                2000,
            )
            .unwrap();
        assert_eq!(owner.snapshot, initial);
        // Checkpoint and all counters/commands remain exactly the actual owner baseline.
        assert!(ManifoldRuntimeHost::from_snapshot(owner.snapshot.clone()).is_err());
    }
}
