//! Explicit live-owner continuation of bounded concurrent renewal histories.
//!
//! This first storage version checkpoints concurrent histories only. Generic
//! Broker/admission/audit capacities remain independent, enforced bounds.
use super::*;

/// Prospective owner-selected storage policy; omission retains finite behavior.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldOngoingMediaPolicy {
    /// Closed policy schema, selected by the embedding product owner.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
}

impl ManifoldOngoingMediaPolicy {
    /// Selects owner checkpoints; this never grants or extends media authority.
    #[must_use]
    pub fn active_checkpoint_v1() -> Self {
        Self {
            schema_id: schema("rusty.manifold.peer.ongoing_media_policy.v1"),
        }
    }
    /// Explicit generic history composition. Requires fresh actual signed and
    /// command owners plus an independently selected live Broker history owner.
    #[must_use]
    pub fn active_checkpoint_v2() -> Self {
        Self {
            schema_id: schema("rusty.manifold.peer.ongoing_media_policy.v2"),
        }
    }
}

/// Constant-size commitment to a validated concurrent-history prefix.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldConcurrentMediaCheckpoint {
    /// Storage schema.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Strictly increasing checkpoint ordinal, independent of provider epoch.
    pub checkpoint_sequence: u64,
    /// Total accepted renewals checkpointed, never reset by compaction.
    pub cumulative_renewals: u64,
    /// Digest of the immediately preceding checkpoint.
    pub prior_checkpoint_sha256: Option<String>,
    /// Digest of exact source concurrent histories.
    pub source_history_sha256: String,
    /// Original renewal preserves the issue-time route and derivative ancestry.
    pub original: ManifoldConcurrentMediaAuthorityRenewalReceipt,
    /// Latest fully adopted renewal at this checkpoint.
    pub baseline: ManifoldConcurrentMediaAuthorityRenewalReceipt,
    /// V2 count for the current exact Start/derivative lifetime. The cumulative
    /// count above remains monotonic across every completed media lifetime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_lifetime_renewal_count: Option<u64>,
}

pub(super) fn retained_anchor_count(checkpoint: &ManifoldConcurrentMediaCheckpoint) -> usize {
    if checkpoint.current_lifetime_renewal_count.is_some()
        && checkpoint.original == checkpoint.baseline
    {
        1
    } else {
        2
    }
}

/// Same-process restore authority minted only from the actual live owner.
///
/// It deliberately implements neither Deserialize nor a digest constructor.
/// Persisting/recovering it across process death requires a separately
/// authenticated embedding-owner storage contract; target JSON cannot mint it.
#[derive(Clone, Debug)]
pub struct ManifoldOngoingMediaRestoreAnchor<'owner> {
    owner: &'owner ManifoldPeerRuntimeHost,
    snapshot_sha256: String,
    broker_evidence_sha256: String,
    trust_policy: ManifoldPeerRuntimeTrustPolicy,
    provider_epoch_id: DottedId,
}

fn digest<T: Serialize>(value: &T) -> Result<String, ManifoldPeerRuntimeHostError> {
    domain_separated_digest("rusty.manifold.peer.ongoing_media.sha256.v1", value)
}

pub(super) fn validate_ongoing_media(
    snapshot: &ManifoldPeerRuntimeHostSnapshot,
) -> Result<(), ManifoldPeerRuntimeHostError> {
    if snapshot
        .ongoing_media_policy
        .as_ref()
        .is_some_and(|policy| {
            *policy != ManifoldOngoingMediaPolicy::active_checkpoint_v1()
                && !(runtime_history::selected(snapshot)
                    && policy.schema_id.as_str() == "rusty.manifold.peer.ongoing_media_policy.v2")
        })
        || (snapshot.concurrent_media_checkpoint.is_some()
            && snapshot.ongoing_media_policy.is_none())
    {
        return Err(invalid_snapshot("ongoing media policy"));
    }
    if let Some(checkpoint) = &snapshot.concurrent_media_checkpoint {
        let history = runtime_history::selected(snapshot);
        let count_valid = if history {
            checkpoint.schema_id.as_str() == "rusty.manifold.peer.concurrent_media_checkpoint.v2"
                && checkpoint.checkpoint_sequence > 0
                && checkpoint.checkpoint_sequence <= checkpoint.cumulative_renewals
                && (checkpoint.checkpoint_sequence > 1)
                    == checkpoint.prior_checkpoint_sha256.is_some()
                && checkpoint
                    .current_lifetime_renewal_count
                    .is_some_and(|count| count > 0 && count <= checkpoint.cumulative_renewals)
        } else {
            checkpoint.schema_id.as_str() == "rusty.manifold.peer.concurrent_media_checkpoint.v1"
                && checkpoint.current_lifetime_renewal_count.is_none()
                && valid_checkpoint_sequence(
                    checkpoint.checkpoint_sequence,
                    checkpoint.cumulative_renewals,
                    checkpoint.prior_checkpoint_sha256.is_some(),
                )
        };
        if !count_valid
            || !valid_sha256(&checkpoint.source_history_sha256)
            || checkpoint
                .prior_checkpoint_sha256
                .as_ref()
                .is_some_and(|hash| !valid_sha256(hash))
            || snapshot.concurrent_media_renewals.first() != Some(&checkpoint.original)
            || snapshot
                .concurrent_media_renewals
                .get(retained_anchor_count(checkpoint) - 1)
                != Some(&checkpoint.baseline)
            || checkpoint.original.provider_epoch_id != snapshot.provider_epoch_id
            || checkpoint.baseline.provider_epoch_id != snapshot.provider_epoch_id
            || checkpoint.original.prior_inner_lease.derivative_binding
                != checkpoint.baseline.prior_inner_lease.derivative_binding
            || checkpoint.original.prior_media.decision_id
                != checkpoint.baseline.prior_media.decision_id
        {
            return Err(invalid_snapshot(
                "ongoing media checkpoint shape or lifetime",
            ));
        }
    }
    Ok(())
}

pub(super) fn checkpoint_bridges(
    snapshot: &ManifoldPeerRuntimeHostSnapshot,
    prior: &ManifoldConcurrentMediaAuthorityRenewalReceipt,
    next: &ManifoldConcurrentMediaAuthorityRenewalReceipt,
) -> bool {
    snapshot
        .concurrent_media_checkpoint
        .as_ref()
        .is_some_and(|checkpoint| prior == &checkpoint.original && next == &checkpoint.baseline)
}

impl ManifoldPeerRuntimeHost {
    /// Validates this already owned state without admitting detached snapshot data.
    pub fn validate_owned_state_with_live_broker(
        &self,
        broker: &ManifoldBrokerRuntime,
    ) -> Result<(), ManifoldPeerRuntimeHostError> {
        self.validate_media_runtime_owner()?;
        self.validate_signed_history_owner()?;
        validate_snapshot(&self.snapshot)?;
        validate_live_broker_restoration(&self.snapshot, &broker.evidence())
    }
    /// Selects the prospective policy through the actual live Broker join.
    /// Existing grants, deadlines, resource identities and revisions are unchanged.
    pub fn enable_ongoing_media_continuation(
        &mut self,
        broker: &ManifoldBrokerRuntime,
        policy: ManifoldOngoingMediaPolicy,
    ) -> Result<(), ManifoldPeerRuntimeHostError> {
        self.validate_signed_history_owner()?;
        if policy == ManifoldOngoingMediaPolicy::active_checkpoint_v2() {
            if broker.evidence().history_checkpoint.is_none() {
                return Err(invalid_snapshot(
                    "ongoing v2 requires actual ongoing Broker owner",
                ));
            }
            if self.snapshot.ongoing_media_policy.as_ref() == Some(&policy) {
                return self.validate_owned_state_with_live_broker(broker);
            }
            self.validate_owned_state_with_live_broker(broker)?;
            return self.enable_owned_runtime_history();
        }
        if policy != ManifoldOngoingMediaPolicy::active_checkpoint_v1()
            || self.snapshot.concurrent_media_checkpoint.is_some()
            || (self.snapshot.ongoing_media_policy.is_none()
                && !self.snapshot.concurrent_media_renewals.is_empty())
        {
            return Err(invalid_snapshot("ongoing media policy selection"));
        }
        self.validate_media_runtime_owner()?;
        validate_snapshot(&self.snapshot)?;
        validate_live_broker_restoration(&self.snapshot, &broker.evidence())?;
        self.snapshot.ongoing_media_policy = Some(policy);
        Ok(())
    }

    /// Reports cumulative coupled renewals, including the bounded current suffix.
    #[must_use]
    pub fn cumulative_concurrent_media_renewals(
        &self,
    ) -> Result<u64, ManifoldPeerRuntimeHostError> {
        let (base, suffix) = self.snapshot.concurrent_media_checkpoint.as_ref().map_or(
            (0, self.snapshot.concurrent_media_renewals.len()),
            |checkpoint| {
                (
                    checkpoint.cumulative_renewals,
                    self.snapshot
                        .concurrent_media_renewals
                        .len()
                        .saturating_sub(retained_anchor_count(checkpoint)),
                )
            },
        );
        checked_total(base, suffix)
    }

    /// Actual accepted count for the latest exact Start/derivative lifetime.
    /// The global cumulative count remains independent and never resets on Start.
    pub fn current_lifetime_concurrent_media_renewals(
        &self,
    ) -> Result<u64, ManifoldPeerRuntimeHostError> {
        let latest_media = self
            .snapshot
            .media_sessions
            .sessions
            .iter()
            .max_by_key(|media| media.accepted_at_ms);
        if latest_media.is_some_and(|media| {
            self.snapshot
                .concurrent_media_renewals
                .last()
                .map_or(true, |last| {
                    last.prior_media.decision_id != media.decision_id
                })
        }) {
            return Ok(0);
        }
        if let Some(checkpoint) = &self.snapshot.concurrent_media_checkpoint {
            if let Some(count) = checkpoint.current_lifetime_renewal_count.filter(|_| {
                self.snapshot
                    .concurrent_media_renewals
                    .last()
                    .is_some_and(|last| {
                        last.prior_media.decision_id == checkpoint.original.prior_media.decision_id
                            && last.prior_inner_lease.derivative_binding
                                == checkpoint.original.prior_inner_lease.derivative_binding
                    })
            }) {
                return checked_total(
                    count,
                    self.snapshot
                        .concurrent_media_renewals
                        .len()
                        .saturating_sub(retained_anchor_count(checkpoint)),
                );
            }
        }
        let Some(current) = self.snapshot.concurrent_media_renewals.last() else {
            return Ok(0);
        };
        u64::try_from(
            self.snapshot
                .concurrent_media_renewals
                .iter()
                .filter(|receipt| {
                    receipt.prior_media.decision_id == current.prior_media.decision_id
                        && receipt.prior_inner_lease.derivative_binding
                            == current.prior_inner_lease.derivative_binding
                })
                .count(),
        )
        .map_err(|_| invalid_snapshot("lifetime renewal count exhausted"))
    }

    /// Checkpoints only a complete live same-graph renewal prefix.
    ///
    /// The caller owns the composition gate and must finish product adoption
    /// before calling. No renewal or platform effect is performed here.
    pub fn checkpoint_concurrent_media_history(
        &mut self,
        broker: &ManifoldBrokerRuntime,
        adopted: &ManifoldConcurrentMediaAuthorityRenewalReceipt,
        now_ms: u64,
    ) -> Result<Option<ManifoldConcurrentMediaCheckpoint>, ManifoldPeerRuntimeHostError> {
        if runtime_history::selected(&self.snapshot) {
            return Err(invalid_snapshot(
                "v2 requires composed media and generic checkpoint publication",
            ));
        }
        let Some((candidate, checkpoint)) =
            self.prepare_concurrent_media_checkpoint(broker, adopted, now_ms)?
        else {
            return Ok(None);
        };
        validate_snapshot(&candidate.snapshot)?;
        validate_live_broker_restoration(&candidate.snapshot, &broker.evidence())?;
        self.commit_transaction_candidate(candidate)?;
        Ok(Some(checkpoint))
    }
    // A private candidate is not accepted authority and cannot escape before
    // complete enclosing-owner validation/publication.
    pub(super) fn prepare_concurrent_media_checkpoint(
        &self,
        broker: &ManifoldBrokerRuntime,
        adopted: &ManifoldConcurrentMediaAuthorityRenewalReceipt,
        now_ms: u64,
    ) -> Result<Option<(Self, ManifoldConcurrentMediaCheckpoint)>, ManifoldPeerRuntimeHostError>
    {
        if self.snapshot.ongoing_media_policy.is_none() {
            return Ok(None);
        }
        let history = runtime_history::selected(&self.snapshot);
        if self.snapshot.concurrent_media_renewals.last() != Some(adopted)
            || adopted.expires_at_ms <= now_ms
            || adopted.renewed_media.lifecycle_status
                != ManifoldMediaSessionLifecycleStatus::Current
            || self
                .snapshot
                .media_sessions
                .sessions
                .iter()
                .filter(|media| {
                    media.lifecycle_status == ManifoldMediaSessionLifecycleStatus::Current
                })
                .count()
                != 1
            || self.snapshot.pair_media_routes.routes.iter().any(|route| {
                *route.lifecycle_status()
                    != rusty_manifold_peer::ManifoldPairMediaRouteLifecycleStatus::Current
                    && (!history
                        || *route.cleanup_status()
                            != rusty_manifold_peer::ManifoldPairMediaRouteCleanupStatus::Completed)
            })
        {
            return Err(invalid_snapshot(
                "checkpoint requires complete current live media graph",
            ));
        }
        self.validate_media_runtime_owner()?;
        validate_snapshot(&self.snapshot)?;
        validate_live_broker_restoration(&self.snapshot, &broker.evidence())?;
        if let Some(checkpoint) = &self.snapshot.concurrent_media_checkpoint {
            if &checkpoint.baseline == adopted {
                return Ok(Some((
                    self.copy_for_transaction(),
                    checkpoint.as_ref().clone(),
                )));
            }
        }
        let suffix = self.snapshot.concurrent_media_renewals.len()
            - self
                .snapshot
                .concurrent_media_checkpoint
                .as_ref()
                .map_or(0, |checkpoint| retained_anchor_count(checkpoint));
        let current_original = self
            .snapshot
            .concurrent_media_renewals
            .iter()
            .find(|r| {
                r.prior_media.decision_id == adopted.prior_media.decision_id
                    && r.prior_inner_lease.derivative_binding
                        == adopted.prior_inner_lease.derivative_binding
            })
            .ok_or_else(|| invalid_snapshot("current lifetime original missing"))?
            .clone();
        let changed_lifetime = self
            .snapshot
            .concurrent_media_renewals
            .first()
            .is_some_and(|r| {
                r.prior_media.decision_id != adopted.prior_media.decision_id
                    || r.prior_inner_lease.derivative_binding
                        != adopted.prior_inner_lease.derivative_binding
            });
        if suffix < 16 && !(history && changed_lifetime) {
            return Ok(None);
        }
        let cumulative = self.cumulative_concurrent_media_renewals()?;
        let prior = self.snapshot.concurrent_media_checkpoint.as_ref();
        let lifetime_count = if history {
            Some(if changed_lifetime {
                u64::try_from(
                    self.snapshot
                        .concurrent_media_renewals
                        .iter()
                        .filter(|r| r.prior_media.decision_id == adopted.prior_media.decision_id)
                        .count(),
                )
                .map_err(|_| invalid_snapshot("current lifetime count exhausted"))?
            } else if let Some(prior) = prior {
                checked_total(
                    prior.current_lifetime_renewal_count.ok_or_else(|| {
                        invalid_snapshot("current lifetime checkpoint count missing")
                    })?,
                    suffix,
                )?
            } else {
                cumulative
            })
        } else {
            None
        };
        let checkpoint = ManifoldConcurrentMediaCheckpoint {
            schema_id: schema(if history {
                "rusty.manifold.peer.concurrent_media_checkpoint.v2"
            } else {
                "rusty.manifold.peer.concurrent_media_checkpoint.v1"
            }),
            checkpoint_sequence: prior
                .map_or(Some(1), |value| value.checkpoint_sequence.checked_add(1))
                .ok_or_else(|| invalid_snapshot("checkpoint sequence overflow"))?,
            cumulative_renewals: cumulative,
            prior_checkpoint_sha256: prior.map(digest).transpose()?,
            source_history_sha256: if history {
                digest(&self.snapshot)?
            } else {
                digest(&(
                    &self.snapshot.concurrent_media_renewals,
                    &self.snapshot.concurrent_session_renewals,
                    &self.snapshot.concurrent_credential_refreshes,
                ))?
            },
            original: if history {
                current_original
            } else {
                self.snapshot.concurrent_media_renewals[0].clone()
            },
            baseline: adopted.clone(),
            current_lifetime_renewal_count: lifetime_count,
        };
        let mut candidate = self.copy_for_transaction();
        candidate.snapshot.concurrent_media_renewals =
            vec![checkpoint.original.clone(), adopted.clone()];
        if retained_anchor_count(&checkpoint) == 1 {
            candidate.snapshot.concurrent_media_renewals.truncate(1);
        }
        candidate
            .snapshot
            .concurrent_session_renewals
            .retain(|session| {
                session == &checkpoint.original.paired_session_receipt
                    || session == &adopted.paired_session_receipt
            });
        if let Some(last) = candidate
            .snapshot
            .concurrent_credential_refreshes
            .last()
            .cloned()
        {
            candidate.snapshot.concurrent_credential_refreshes = vec![last];
        }
        // Box is storage only: serialized checkpoint and all signed receipt bytes
        // remain identical. Avoid embedding two large renewal receipts in every
        // Host snapshot and every deserializer's by-value stack frame.
        let stored_checkpoint = Box::new(checkpoint.clone());
        #[cfg(test)]
        {
            let raw = serde_json::to_vec(&checkpoint).expect("actual checkpoint serialization");
            assert_eq!(
                raw,
                serde_json::to_vec(&stored_checkpoint).expect("boxed checkpoint serialization")
            );
            let restored: Box<ManifoldConcurrentMediaCheckpoint> =
                serde_json::from_slice(&raw).expect("same checkpoint roundtrip");
            assert_eq!(*restored, checkpoint);
            assert_eq!(
                rusty_manifold_peer::fresh_history_canonical(&checkpoint)
                    .expect("actual checkpoint canonical bytes"),
                rusty_manifold_peer::fresh_history_canonical(&restored)
                    .expect("boxed checkpoint canonical bytes")
            );
        }
        candidate.snapshot.concurrent_media_checkpoint = Some(stored_checkpoint);
        Ok(Some((candidate, checkpoint)))
    }

    /// Seals the exact current owner state for a same-process restore.
    pub fn seal_ongoing_media_snapshot(
        &self,
        broker: &ManifoldBrokerRuntime,
    ) -> Result<ManifoldOngoingMediaRestoreAnchor<'_>, ManifoldPeerRuntimeHostError> {
        self.validate_signed_history_owner()?;
        if self.snapshot.ongoing_media_policy.is_none() {
            return Err(invalid_snapshot("ongoing snapshot policy absent"));
        }
        self.validate_media_runtime_owner()?;
        validate_snapshot(&self.snapshot)?;
        validate_live_broker_restoration(&self.snapshot, &broker.evidence())?;
        Ok(ManifoldOngoingMediaRestoreAnchor {
            owner: self,
            snapshot_sha256: digest(&self.snapshot)?,
            broker_evidence_sha256: digest(&broker.evidence())?,
            trust_policy: self.snapshot.trust_policy.clone(),
            provider_epoch_id: self.snapshot.provider_epoch_id.clone(),
        })
    }

    /// Restores only byte-equivalent accepted state sealed by a live owner.
    pub fn restore_ongoing_media_snapshot(
        json: &str,
        anchor: &ManifoldOngoingMediaRestoreAnchor<'_>,
        broker: &ManifoldBrokerRuntime,
    ) -> Result<Self, ManifoldPeerRuntimeHostError> {
        let snapshot: ManifoldPeerRuntimeHostSnapshot =
            serde_json::from_str(json).map_err(ManifoldPeerRuntimeHostError::Deserialize)?;
        Self::verify_ongoing_media_snapshot(json, anchor, broker)?;
        if snapshot.ongoing_media_policy.is_none()
            || anchor.owner.signed_history_owner.is_some()
            || snapshot.trust_policy != anchor.trust_policy
            || snapshot.provider_epoch_id != anchor.provider_epoch_id
            || digest(&snapshot)? != anchor.snapshot_sha256
            || digest(anchor.owner.snapshot())? != anchor.snapshot_sha256
            || digest(&broker.evidence())? != anchor.broker_evidence_sha256
        {
            return Err(invalid_snapshot(
                "ongoing restore requires exact independent live-owner seal",
            ));
        }
        validate_snapshot(&snapshot)?;
        validate_live_broker_restoration(&snapshot, &broker.evidence())?;
        Ok(Self {
            snapshot,
            media_runtime_owner: anchor.owner.media_runtime_owner.clone(),
            signed_history_owner: None,
            signed_history_candidate: None,
        })
    }

    /// Checks exact sealed evidence without constructing or cloning a writer.
    pub fn verify_ongoing_media_snapshot(
        json: &str,
        anchor: &ManifoldOngoingMediaRestoreAnchor<'_>,
        broker: &ManifoldBrokerRuntime,
    ) -> Result<(), ManifoldPeerRuntimeHostError> {
        let snapshot: ManifoldPeerRuntimeHostSnapshot =
            serde_json::from_str(json).map_err(ManifoldPeerRuntimeHostError::Deserialize)?;
        anchor.owner.validate_owned_state_with_live_broker(broker)?;
        if snapshot.ongoing_media_policy.is_none()
            || snapshot.trust_policy != anchor.trust_policy
            || snapshot.provider_epoch_id != anchor.provider_epoch_id
            || digest(&snapshot)? != anchor.snapshot_sha256
            || digest(anchor.owner.snapshot())? != anchor.snapshot_sha256
            || digest(&broker.evidence())? != anchor.broker_evidence_sha256
        {
            return Err(invalid_snapshot(
                "ongoing verification requires actual current owner seal",
            ));
        }
        validate_snapshot(&snapshot)?;
        validate_live_broker_restoration(&snapshot, &broker.evidence())
    }

    /// Reconciles exact current bytes in place, preserving the same non-cloneable
    /// signed gate. Detached target bytes cannot replace this actual owner.
    pub fn restore_current_ongoing_media_snapshot(
        &mut self,
        json: &str,
        broker: &ManifoldBrokerRuntime,
    ) -> Result<(), ManifoldPeerRuntimeHostError> {
        let snapshot: ManifoldPeerRuntimeHostSnapshot =
            serde_json::from_str(json).map_err(ManifoldPeerRuntimeHostError::Deserialize)?;
        self.validate_owned_state_with_live_broker(broker)?;
        if self.snapshot != snapshot || self.snapshot.ongoing_media_policy.is_none() {
            return Err(invalid_snapshot(
                "in-place restore requires actual current owner bytes",
            ));
        }
        Ok(())
    }
}

fn checked_total(base: u64, suffix: usize) -> Result<u64, ManifoldPeerRuntimeHostError> {
    u64::try_from(suffix)
        .ok()
        .and_then(|suffix| base.checked_add(suffix))
        .ok_or_else(|| invalid_snapshot("cumulative renewal count exhausted"))
}

// Called only after the complete actual source validates the old→new adoption
// chain. Terminal records disappear only with their accepted Stop, derivative
// release and completed route cleanup, all committed by the source digest.
pub(super) fn prune_completed_media_lifetimes(
    snapshot: &mut ManifoldPeerRuntimeHostSnapshot,
    current: &ManifoldConcurrentMediaAuthorityRenewalReceipt,
) -> Result<(), ManifoldPeerRuntimeHostError> {
    if !snapshot.broker_lease_revocation_convergences.is_empty()
        || !snapshot
            .broker_lease_revocation_cleanup_completions
            .is_empty()
    {
        return Err(invalid_snapshot(
            "retired lifetime still has revocation obligations",
        ));
    }
    let retired = snapshot
        .media_sessions
        .sessions
        .iter()
        .filter(|media| media.decision_id != current.prior_media.decision_id)
        .cloned()
        .collect::<Vec<_>>();
    let mut retired_admissions = BTreeSet::new();
    let mut retired_routes = BTreeSet::new();
    for media in &retired {
        if media.lifecycle_status != ManifoldMediaSessionLifecycleStatus::Stopped
            || media.ended_at_ms.is_none()
            || media.ended_by_id.is_none()
        {
            return Err(invalid_snapshot(
                "retired media lifetime is not exactly stopped",
            ));
        }
        let ended = media.ended_at_ms.unwrap();
        let routes = snapshot
            .pair_media_routes
            .routes
            .iter()
            .filter(|route| route.media_session_decision_id() == &media.decision_id)
            .collect::<Vec<_>>();
        if routes.is_empty()
            || routes.iter().any(|route| {
                *route.lifecycle_status()
                    == rusty_manifold_peer::ManifoldPairMediaRouteLifecycleStatus::Current
                    || *route.cleanup_status()
                        != rusty_manifold_peer::ManifoldPairMediaRouteCleanupStatus::Completed
                    || !snapshot
                        .pair_media_routes
                        .cleanup_receipts
                        .iter()
                        .any(|receipt| {
                            receipt.grant_id() == route.grant_id()
                                && receipt.completed_at_ms() >= ended
                                && receipt.completed_at_ms() < current.prior_media.accepted_at_ms
                        })
            })
        {
            return Err(invalid_snapshot(
                "retired lifetime route cleanup is unresolved",
            ));
        }
        retired_routes.extend(routes.iter().map(|route| route.grant_id().clone()));
        let admissions = snapshot
            .broker_lease_admissions
            .iter()
            .filter(|admission| {
                admission.runtime_lease.lease_id == media.runtime_lease_id
                    && admission.runtime_lease.holder_id == media.runtime_client_id
                    && admission.admitted_at_ms == media.accepted_at_ms
            })
            .collect::<Vec<_>>();
        if admissions.len() != 1
            || admissions.iter().any(|admission| {
                admission.release_id.is_none()
                    || !admission
                        .released_at_ms
                        .is_some_and(|at| at >= ended && at < current.prior_media.accepted_at_ms)
                    || admission.runtime_lease.derivative_binding
                        == current.prior_inner_lease.derivative_binding
            })
        {
            return Err(invalid_snapshot(
                "retired lifetime derivative release is unresolved",
            ));
        }
        retired_admissions.extend(
            admissions
                .iter()
                .map(|admission| admission.broker_receipt.admission_use_request_id.clone()),
        );
    }
    let retired_media = retired
        .iter()
        .map(|media| media.decision_id.clone())
        .collect::<BTreeSet<_>>();
    snapshot
        .media_sessions
        .sessions
        .retain(|media| !retired_media.contains(&media.decision_id));
    snapshot
        .pair_media_routes
        .routes
        .retain(|route| !retired_routes.contains(route.grant_id()));
    snapshot
        .pair_media_routes
        .cleanup_receipts
        .retain(|receipt| !retired_routes.contains(receipt.grant_id()));
    snapshot.broker_lease_admissions.retain(|admission| {
        !retired_admissions.contains(&admission.broker_receipt.admission_use_request_id)
    });
    Ok(())
}

fn valid_checkpoint_sequence(sequence: u64, cumulative: u64, prior_present: bool) -> bool {
    sequence > 0 && sequence.checked_mul(16) == Some(cumulative) && (sequence > 1) == prior_present
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_continuation_count_refuses_overflow() {
        assert_eq!(checked_total(u64::MAX - 1, 1).unwrap(), u64::MAX);
        assert!(checked_total(u64::MAX - 1, 2).is_err());
        assert!(checked_total(u64::MAX, 1).is_err());
    }
    #[test]
    fn actual_checkpoint_sequence_refuses_overflow_and_broken_prefix() {
        assert!(valid_checkpoint_sequence(1, 16, false));
        assert!(valid_checkpoint_sequence(2, 32, true));
        assert!(!valid_checkpoint_sequence(1, 16, true));
        assert!(!valid_checkpoint_sequence(2, 32, false));
        assert!(!valid_checkpoint_sequence(u64::MAX, u64::MAX - 15, true));
        assert!(!valid_checkpoint_sequence(0, 0, false));
    }
}
