//! Live control-lease baselines admitted only through the actual owning gate.
use super::*;

/// Opted-in live checkpoint evidence; finite v3 is unchanged.
pub const BROKER_CONTROL_LEASE_AUTHORITY_EVIDENCE_V4_SCHEMA: &str =
    "rusty.manifold.broker.control_lease_authority_evidence.v4";

/// Bounded live baseline selected from already accepted owner state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerControlLeaseHistoryCheckpoint {
    /// Storage version.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Epoch required in every subsequent lifecycle request identity.
    pub request_epoch: u64,
    /// Global accepted lifecycle transition sequence; never reset by compaction.
    pub transition_sequence: u64,
    /// Exact currently accepted product leases, including renewed deadlines.
    pub product_leases: Vec<ManifoldControlLease>,
    /// Commitment to the previous checkpoint, without its body.
    pub prior_checkpoint_sha256: Option<String>,
    /// Commitment to complete validated source owner evidence.
    pub source_evidence_sha256: String,
}

/// Restore authority borrowing an independent current live owner.
#[derive(Debug)]
pub struct ManifoldBrokerControlLeaseHistoryRestoreAnchor<'owner> {
    owner: &'owner ManifoldBrokerControlLeaseAuthority,
    evidence_sha256: String,
}

fn digest<T: Serialize>(value: &T) -> Result<String, ManifoldBrokerControlLeaseAuthorityError> {
    use sha2::{Digest, Sha256};
    let bytes = serde_json::to_vec(value)
        .map_err(|_| ManifoldBrokerControlLeaseAuthorityError::TransitionLineage)?;
    let mut hash = Sha256::new();
    hash.update(b"rusty.manifold.broker.control_lease_history.sha256.v1\0");
    hash.update(bytes);
    Ok(format!("sha256:{:x}", hash.finalize()))
}

pub(super) fn transition_base(evidence: &ManifoldBrokerControlLeaseAuthorityEvidenceV2) -> u64 {
    evidence
        .history_checkpoint
        .as_ref()
        .map_or(0, |c| c.transition_sequence)
}

pub(super) fn request_matches(
    evidence: &ManifoldBrokerControlLeaseAuthorityEvidenceV2,
    request_id: &DottedId,
) -> bool {
    evidence.history_checkpoint.as_ref().map_or(true, |c| {
        request_id
            .as_str()
            .strip_prefix(&format!("history.{}.", c.request_epoch))
            .is_some_and(|suffix| !suffix.is_empty() && !suffix.starts_with("history."))
    })
}

type Baseline = (
    ManifoldBrokerControlLeaseAuthorityEvidence,
    BTreeMap<DottedId, ManifoldControlLease>,
    BTreeMap<DottedId, ManifoldBrokerControlLeaseSource>,
);

pub(super) fn validate_live_baseline(
    baseline: ManifoldBrokerControlLeaseAuthorityEvidence,
    checkpoint: &ManifoldBrokerControlLeaseHistoryCheckpoint,
) -> Result<Baseline, ManifoldBrokerControlLeaseAuthorityError> {
    let valid_hash = |h: &str| {
        h.len() == 71
            && h.starts_with("sha256:")
            && h[7..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    if baseline.schema_id.as_str() != BROKER_CONTROL_LEASE_AUTHORITY_EVIDENCE_SCHEMA
        || !baseline.lease_sources.is_empty()
        || checkpoint.schema_id.as_str()
            != "rusty.manifold.broker.control_lease_history_checkpoint.v1"
        || checkpoint.request_epoch == 0
        || checkpoint.transition_sequence < checkpoint.request_epoch.saturating_sub(1)
        || (checkpoint.request_epoch > 1) != checkpoint.prior_checkpoint_sha256.is_some()
        || !valid_hash(&checkpoint.source_evidence_sha256)
        || checkpoint
            .prior_checkpoint_sha256
            .as_ref()
            .is_some_and(|h| !valid_hash(h))
        || checkpoint.product_leases.len() > MAX_BROKER_CONTROL_LEASES
        || checkpoint
            .product_leases
            .windows(2)
            .any(|w| w[0].lease_id >= w[1].lease_id)
        || checkpoint.product_leases.iter().any(|lease| {
            !baseline
                .current_authority_snapshot
                .active_leases
                .contains(lease)
        })
    {
        return Err(ManifoldBrokerControlLeaseAuthorityError::TransitionLineage);
    }
    validate_snapshot_duplicate_ids(&baseline.current_authority_snapshot)?;
    validate_v1_evidence_size(&baseline)?;
    ManifoldBrokerRuntimeLeaseProjector::from_retained_authority_state(
        &baseline.current_authority_snapshot,
        &baseline.current_clock,
    )
    .map_err(ManifoldBrokerControlLeaseAuthorityError::Projection)?;
    let product = checkpoint
        .product_leases
        .iter()
        .map(|lease| (lease.lease_id.clone(), lease.clone()))
        .collect();
    Ok((baseline, product, BTreeMap::new()))
}

impl ManifoldBrokerControlLeaseAuthority {
    /// Selects live checkpoint storage before any chronological lifecycle work.
    /// Existing accepted leases are retained exactly, never reissued or extended.
    pub fn enable_ongoing_history(
        &mut self,
    ) -> Result<(), ManifoldBrokerControlLeaseAuthorityError> {
        if self.evidence.history_checkpoint.is_some() {
            self.copy_from_live_owner()?;
            return Ok(());
        }
        if !self.evidence.transitions.is_empty() {
            return Err(ManifoldBrokerControlLeaseAuthorityError::TransitionLineage);
        }
        Self::from_v2_evidence(self.evidence.clone())?;
        self.install_history_checkpoint(1, 0, None).map(|_| ())
    }

    /// Qualifies only a new lifecycle identity with the actual current epoch.
    pub fn current_history_request_id(
        &self,
        suffix: &DottedId,
    ) -> Result<DottedId, ManifoldBrokerControlLeaseAuthorityError> {
        if suffix.as_str().starts_with("history.") {
            return Err(ManifoldBrokerControlLeaseAuthorityError::TransitionReplay);
        }
        Ok(self.evidence.history_checkpoint.as_ref().map_or_else(
            || suffix.clone(),
            |c| {
                DottedId::new(format!("history.{}.{}", c.request_epoch, suffix))
                    .expect("qualified dotted id")
            },
        ))
    }

    /// Checkpoints actual accepted current leases, without a drained rollover.
    /// The embedding Broker must separately close its pending phase obligations.
    pub fn checkpoint_ongoing_history(
        &mut self,
    ) -> Result<ManifoldBrokerControlLeaseHistoryCheckpoint, ManifoldBrokerControlLeaseAuthorityError>
    {
        self.copy_from_live_owner()?;
        let prior = self
            .evidence
            .history_checkpoint
            .as_ref()
            .ok_or(ManifoldBrokerControlLeaseAuthorityError::SchemaMismatch)?;
        if self.evidence.transitions.is_empty() {
            return Ok(prior.clone());
        }
        let epoch = prior
            .request_epoch
            .checked_add(1)
            .ok_or(ManifoldBrokerControlLeaseAuthorityError::TransitionCapacityExceeded)?;
        let sequence = prior
            .transition_sequence
            .checked_add(self.evidence.transitions.len() as u64)
            .ok_or(ManifoldBrokerControlLeaseAuthorityError::TransitionCapacityExceeded)?;
        self.install_history_checkpoint(epoch, sequence, Some(digest(prior)?))
    }

    fn install_history_checkpoint(
        &mut self,
        request_epoch: u64,
        transition_sequence: u64,
        prior_checkpoint_sha256: Option<String>,
    ) -> Result<ManifoldBrokerControlLeaseHistoryCheckpoint, ManifoldBrokerControlLeaseAuthorityError>
    {
        let product_leases = self
            .runtime_leases
            .iter()
            .map(|lease| {
                self.evidence
                    .current_authority_snapshot
                    .active_leases
                    .iter()
                    .find(|accepted| accepted.lease_id == lease.lease_id)
                    .cloned()
                    .ok_or(ManifoldBrokerControlLeaseAuthorityError::UnrelatedLease)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let checkpoint = ManifoldBrokerControlLeaseHistoryCheckpoint {
            schema_id: schema_id("rusty.manifold.broker.control_lease_history_checkpoint.v1"),
            request_epoch,
            transition_sequence,
            product_leases,
            prior_checkpoint_sha256,
            source_evidence_sha256: digest(&self.evidence)?,
        };
        let mut evidence = self.evidence.clone();
        evidence.schema_id = schema_id(BROKER_CONTROL_LEASE_AUTHORITY_EVIDENCE_V4_SCHEMA);
        evidence.baseline.current_authority_snapshot = evidence.current_authority_snapshot.clone();
        evidence.baseline.current_clock = evidence.current_clock.clone();
        evidence.baseline.lease_sources.clear();
        evidence.transitions.clear();
        evidence.history_checkpoint = Some(checkpoint.clone());
        // This is the only baseline-installation gate. The anchor passed here
        // was computed from this actual validated owner, never target JSON.
        let candidate = Self::from_live_checkpoint_evidence(evidence, Some(&checkpoint))?;
        if candidate.runtime_leases != self.runtime_leases
            || candidate.current_clock() != self.current_clock()
            || candidate.authority_snapshot() != self.authority_snapshot()
        {
            return Err(ManifoldBrokerControlLeaseAuthorityError::TransitionLineage);
        }
        *self = candidate;
        Ok(checkpoint)
    }

    pub(crate) fn copy_from_live_owner(
        &self,
    ) -> Result<Self, ManifoldBrokerControlLeaseAuthorityError> {
        Self::from_live_checkpoint_evidence(
            self.evidence.clone(),
            self.evidence.history_checkpoint.as_ref(),
        )
    }

    /// Seals accepted current state. The private anchor cannot be deserialized.
    pub fn seal_ongoing_history(
        &self,
    ) -> Result<
        ManifoldBrokerControlLeaseHistoryRestoreAnchor<'_>,
        ManifoldBrokerControlLeaseAuthorityError,
    > {
        if self.evidence.history_checkpoint.is_none() {
            return Err(ManifoldBrokerControlLeaseAuthorityError::SchemaMismatch);
        }
        self.copy_from_live_owner()?;
        Ok(ManifoldBrokerControlLeaseHistoryRestoreAnchor {
            owner: self,
            evidence_sha256: digest(&self.evidence)?,
        })
    }

    /// Verifies exact current evidence without constructing a second owner.
    pub fn verify_ongoing_history(
        evidence: &ManifoldBrokerControlLeaseAuthorityEvidenceV2,
        anchor: &ManifoldBrokerControlLeaseHistoryRestoreAnchor<'_>,
    ) -> Result<(), ManifoldBrokerControlLeaseAuthorityError> {
        if evidence.history_checkpoint.is_none()
            || digest(evidence)? != anchor.evidence_sha256
            || digest(&anchor.owner.evidence)? != anchor.evidence_sha256
        {
            return Err(ManifoldBrokerControlLeaseAuthorityError::TransitionLineage);
        }
        anchor.owner.copy_from_live_owner()?;
        Ok(())
    }

    /// Restores only this exact current owner in place; no public clone escapes.
    pub fn restore_ongoing_history(
        &mut self,
        evidence: ManifoldBrokerControlLeaseAuthorityEvidenceV2,
    ) -> Result<(), ManifoldBrokerControlLeaseAuthorityError> {
        if self.evidence.history_checkpoint.is_none()
            || evidence.history_checkpoint.is_none()
            || digest(&evidence)? != digest(&self.evidence)?
        {
            return Err(ManifoldBrokerControlLeaseAuthorityError::TransitionLineage);
        }
        let candidate = self.copy_from_live_owner()?;
        *self = candidate;
        Ok(())
    }
}
