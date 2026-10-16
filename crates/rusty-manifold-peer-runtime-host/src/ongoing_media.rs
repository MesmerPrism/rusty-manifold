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
        .is_some_and(|policy| *policy != ManifoldOngoingMediaPolicy::active_checkpoint_v1())
        || (snapshot.concurrent_media_checkpoint.is_some()
            && snapshot.ongoing_media_policy.is_none())
    {
        return Err(invalid_snapshot("ongoing media policy"));
    }
    if let Some(checkpoint) = &snapshot.concurrent_media_checkpoint {
        if checkpoint.schema_id.as_str() != "rusty.manifold.peer.concurrent_media_checkpoint.v1"
            || !valid_checkpoint_sequence(
                checkpoint.checkpoint_sequence,
                checkpoint.cumulative_renewals,
                checkpoint.prior_checkpoint_sha256.is_some(),
            )
            || !valid_sha256(&checkpoint.source_history_sha256)
            || checkpoint
                .prior_checkpoint_sha256
                .as_ref()
                .is_some_and(|hash| !valid_sha256(hash))
            || snapshot.concurrent_media_renewals.first() != Some(&checkpoint.original)
            || snapshot.concurrent_media_renewals.get(1) != Some(&checkpoint.baseline)
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
        if policy != ManifoldOngoingMediaPolicy::active_checkpoint_v1()
            || self.snapshot.concurrent_media_checkpoint.is_some()
            || (self.snapshot.ongoing_media_policy.is_none()
                && !self.snapshot.concurrent_media_renewals.is_empty())
        {
            return Err(invalid_snapshot("ongoing media policy selection"));
        }
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
                        .saturating_sub(2),
                )
            },
        );
        checked_total(base, suffix)
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
        if self.snapshot.ongoing_media_policy.is_none() {
            return Ok(None);
        }
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
            })
        {
            return Err(invalid_snapshot(
                "checkpoint requires complete current live media graph",
            ));
        }
        validate_snapshot(&self.snapshot)?;
        validate_live_broker_restoration(&self.snapshot, &broker.evidence())?;
        if let Some(checkpoint) = &self.snapshot.concurrent_media_checkpoint {
            if &checkpoint.baseline == adopted {
                return Ok(Some(checkpoint.clone()));
            }
        }
        let suffix = self.snapshot.concurrent_media_renewals.len()
            - if self.snapshot.concurrent_media_checkpoint.is_some() {
                2
            } else {
                0
            };
        if suffix < 16 {
            return Ok(None);
        }
        let cumulative = self.cumulative_concurrent_media_renewals()?;
        let prior = self.snapshot.concurrent_media_checkpoint.as_ref();
        let checkpoint = ManifoldConcurrentMediaCheckpoint {
            schema_id: schema("rusty.manifold.peer.concurrent_media_checkpoint.v1"),
            checkpoint_sequence: prior
                .map_or(Some(1), |value| value.checkpoint_sequence.checked_add(1))
                .ok_or_else(|| invalid_snapshot("checkpoint sequence overflow"))?,
            cumulative_renewals: cumulative,
            prior_checkpoint_sha256: prior.map(digest).transpose()?,
            source_history_sha256: digest(&(
                &self.snapshot.concurrent_media_renewals,
                &self.snapshot.concurrent_session_renewals,
                &self.snapshot.concurrent_credential_refreshes,
            ))?,
            original: self.snapshot.concurrent_media_renewals[0].clone(),
            baseline: adopted.clone(),
        };
        let mut candidate = self.clone();
        candidate.snapshot.concurrent_media_renewals =
            vec![checkpoint.original.clone(), adopted.clone()];
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
        candidate.snapshot.concurrent_media_checkpoint = Some(checkpoint.clone());
        validate_snapshot(&candidate.snapshot)?;
        validate_live_broker_restoration(&candidate.snapshot, &broker.evidence())?;
        *self = candidate;
        Ok(Some(checkpoint))
    }

    /// Seals the exact current owner state for a same-process restore.
    pub fn seal_ongoing_media_snapshot(
        &self,
        broker: &ManifoldBrokerRuntime,
    ) -> Result<ManifoldOngoingMediaRestoreAnchor<'_>, ManifoldPeerRuntimeHostError> {
        if self.snapshot.ongoing_media_policy.is_none() {
            return Err(invalid_snapshot("ongoing snapshot policy absent"));
        }
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
        if snapshot.ongoing_media_policy.is_none()
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
        Ok(Self { snapshot })
    }
}

fn checked_total(base: u64, suffix: usize) -> Result<u64, ManifoldPeerRuntimeHostError> {
    u64::try_from(suffix)
        .ok()
        .and_then(|suffix| base.checked_add(suffix))
        .ok_or_else(|| invalid_snapshot("cumulative renewal count exhausted"))
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
