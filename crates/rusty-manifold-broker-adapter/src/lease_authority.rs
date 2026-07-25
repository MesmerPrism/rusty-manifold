//! Broker-owned control-lease authority state and Runtime Host projection closure.

use crate::{
    ManifoldBrokerRuntimeLeaseProjection, ManifoldBrokerRuntimeLeaseProjectionError,
    ManifoldBrokerRuntimeLeaseProjector, MAX_BROKER_RUNTIME_LEASE_CLOCK_UNCERTAINTY_NS,
};
use rusty_manifold_model::{
    ClockHealth, DottedId, LeaseState, ManifoldAuthorityExpirySweepAuthorityApplication,
    ManifoldAuthorityExpirySweepAuthorityApplicationOutcome,
    ManifoldAuthorityExpirySweepAuthorityReviewOutcome, ManifoldAuthorityExpirySweepRequest,
    ManifoldAuthoritySnapshot, ManifoldClockSnapshot, ManifoldControlLease,
    ManifoldControlLeaseAuthorityApplication, ManifoldControlLeaseAuthorityApplicationOutcome,
    ManifoldControlLeaseReleaseAuthorityApplication,
    ManifoldControlLeaseReleaseAuthorityApplicationOutcome, ManifoldControlLeaseReleaseRequest,
    ManifoldControlLeaseRenewalAuthorityApplication,
    ManifoldControlLeaseRenewalAuthorityApplicationOutcome, ManifoldControlLeaseRenewalRequest,
    ManifoldControlLeaseRequest, SchemaId,
};
use rusty_manifold_runtime_host::{ManifoldRuntimeHostSnapshot, ManifoldRuntimeLease};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{self, Write};

/// Durable source-lineage schema for one Broker-owned control lease.
pub const BROKER_CONTROL_LEASE_SOURCE_SCHEMA: &str =
    "rusty.manifold.broker.control_lease_source.v1";
/// Durable synchronized control-lease authority evidence schema.
pub const BROKER_CONTROL_LEASE_AUTHORITY_EVIDENCE_SCHEMA: &str =
    "rusty.manifold.broker.control_lease_authority_evidence.v1";
/// Current durable synchronized control-lease authority evidence schema.
pub const BROKER_CONTROL_LEASE_AUTHORITY_EVIDENCE_V2_SCHEMA: &str =
    "rusty.manifold.broker.control_lease_authority_evidence.v2";
/// Durable chronological Broker control-lease transition schema.
pub const BROKER_CONTROL_LEASE_TRANSITION_SCHEMA: &str =
    "rusty.manifold.broker.control_lease_transition.v1";
/// Maximum projected control leases retained by one Broker product authority.
pub const MAX_BROKER_CONTROL_LEASES: usize = 64;
/// Maximum chronological lifecycle transitions retained by one Broker owner.
pub const MAX_BROKER_CONTROL_LEASE_TRANSITIONS: usize = 4_096;
/// Lifecycle slots reserved for one cleanup per maximum active product lease.
pub const BROKER_CONTROL_LEASE_CLEANUP_TRANSITION_RESERVE: usize = MAX_BROKER_CONTROL_LEASES;
/// Maximum serialized authority snapshot accepted by this Broker boundary.
pub const MAX_BROKER_CONTROL_LEASE_SNAPSHOT_BYTES: usize = 128 * 1024;
/// Maximum serialized exact generic transition retained by the owner ledger.
pub const MAX_BROKER_CONTROL_LEASE_TRANSITION_BYTES: usize = 512 * 1024;
/// Serialized owner-evidence suffix reserved for release/expiry cleanup.
pub const BROKER_CONTROL_LEASE_CLEANUP_EVIDENCE_RESERVE_BYTES: usize =
    MAX_BROKER_CONTROL_LEASES * MAX_BROKER_CONTROL_LEASE_TRANSITION_BYTES;
/// Maximum serialized owner evidence accepted by one Broker runtime.
pub const MAX_BROKER_CONTROL_LEASE_AUTHORITY_EVIDENCE_BYTES: usize = 48 * 1024 * 1024;

/// Exact source lineage required to reproduce one Runtime Host lease projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerControlLeaseSource {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Exact authority state against which the lease application was reviewed.
    pub prior_authority_snapshot: ManifoldAuthoritySnapshot,
    /// Exact accepted control-lease application.
    pub application: ManifoldControlLeaseAuthorityApplication,
}

/// Durable Broker authority state from which Runtime Host leases are reproduced.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerControlLeaseAuthorityEvidence {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Last synchronized retained authority state.
    pub current_authority_snapshot: ManifoldAuthoritySnapshot,
    /// Last synchronized authority-owner clock view.
    pub current_clock: ManifoldClockSnapshot,
    /// Canonically lease-id-ordered source lineage for projected leases.
    pub lease_sources: Vec<ManifoldBrokerControlLeaseSource>,
}

/// Exact generic Manifold application recorded by one Broker lifecycle step.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "application")]
pub enum ManifoldBrokerControlLeaseTransitionApplication {
    /// Generic control-lease issuance review/application.
    Issue(ManifoldControlLeaseAuthorityApplication),
    /// Generic control-lease renewal review/application.
    Renewal(ManifoldControlLeaseRenewalAuthorityApplication),
    /// Generic control-lease holder release review/application.
    Release(ManifoldControlLeaseReleaseAuthorityApplication),
    /// Generic explicit authority expiry review/application.
    Expiry(ManifoldAuthorityExpirySweepAuthorityApplication),
}

/// Broker lifecycle operation kind used for bounded-ledger admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManifoldBrokerControlLeaseTransitionKind {
    Issue,
    Renewal,
    Release,
    Expiry,
}

impl ManifoldBrokerControlLeaseTransitionApplication {
    pub(crate) const fn kind(&self) -> ManifoldBrokerControlLeaseTransitionKind {
        match self {
            Self::Issue(_) => ManifoldBrokerControlLeaseTransitionKind::Issue,
            Self::Renewal(_) => ManifoldBrokerControlLeaseTransitionKind::Renewal,
            Self::Release(_) => ManifoldBrokerControlLeaseTransitionKind::Release,
            Self::Expiry(_) => ManifoldBrokerControlLeaseTransitionKind::Expiry,
        }
    }

    pub(crate) fn request_id(&self) -> &DottedId {
        match self {
            Self::Issue(application) => &application.request_id,
            Self::Renewal(application) => &application.review.audit_event.request.request_id,
            Self::Release(application) => &application.review.audit_event.request.request_id,
            Self::Expiry(application) => &application.request_id,
        }
    }

    fn recorded_clock(&self) -> &ManifoldClockSnapshot {
        match self {
            Self::Issue(application) => &application.review.audit_event.recorded_clock,
            Self::Renewal(application) => &application.review.audit_event.recorded_clock,
            Self::Release(application) => &application.review.audit_event.recorded_clock,
            Self::Expiry(application) => &application.review.audit_event.recorded_clock,
        }
    }

    fn applied_snapshot(&self) -> Option<&ManifoldAuthoritySnapshot> {
        match self {
            Self::Issue(application) => application.applied_snapshot.as_ref(),
            Self::Renewal(application) => application.applied_snapshot.as_ref(),
            Self::Release(application) => application.applied_snapshot.as_ref(),
            Self::Expiry(application) => application.applied_snapshot.as_ref(),
        }
    }

    pub(crate) fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldBrokerControlLeaseAuthorityError> {
        match self {
            Self::Issue(application) => {
                if application.review.audit_event.request.schema_id.as_str()
                    != "rusty.manifold.command.lease_request.v1"
                {
                    return Err(ManifoldBrokerControlLeaseAuthorityError::SchemaMismatch);
                }
                application
                    .validate_against_snapshot(snapshot)
                    .map_err(|_| ManifoldBrokerControlLeaseAuthorityError::TransitionLineage)
            }
            Self::Renewal(application) => application
                .validate_against_snapshot(snapshot)
                .map_err(|_| ManifoldBrokerControlLeaseAuthorityError::TransitionLineage),
            Self::Release(application) => application
                .validate_against_snapshot(snapshot)
                .map_err(|_| ManifoldBrokerControlLeaseAuthorityError::TransitionLineage),
            Self::Expiry(application) => application
                .validate_against_snapshot(snapshot)
                .map_err(|_| ManifoldBrokerControlLeaseAuthorityError::TransitionLineage),
        }
    }
}

/// One exact chronological Broker owner transition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerControlLeaseTransition {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// One-based sequence in this owner evidence lineage.
    pub sequence: u64,
    /// Exact accepted authority state reviewed by the generic application.
    pub prior_authority_snapshot: ManifoldAuthoritySnapshot,
    /// Exact generic issue, renewal, release, or expiry application.
    pub application: ManifoldBrokerControlLeaseTransitionApplication,
}

/// Current durable Broker owner evidence.
///
/// V1 remains the immutable adoption baseline. V2 appends exact chronological
/// generic lifecycle applications and retains the resulting synchronized
/// authority/clock view.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerControlLeaseAuthorityEvidenceV2 {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Immutable v1 adoption baseline.
    pub baseline: ManifoldBrokerControlLeaseAuthorityEvidence,
    /// Resulting accepted authority state after replaying all transitions.
    pub current_authority_snapshot: ManifoldAuthoritySnapshot,
    /// Last synchronized strict owner clock.
    pub current_clock: ManifoldClockSnapshot,
    /// Exact chronological lifecycle transition ledger.
    pub transitions: Vec<ManifoldBrokerControlLeaseTransition>,
}

/// Exclusive synchronized control-lease owner retained by a Broker runtime.
///
/// Construction validates every projected lease against one supplied retained
/// authority/clock view. Fields are private and the type is not cloneable, so
/// normal Broker construction cannot receive ambient Runtime Host leases.
#[derive(Debug)]
pub struct ManifoldBrokerControlLeaseAuthority {
    evidence: ManifoldBrokerControlLeaseAuthorityEvidenceV2,
    runtime_leases: Vec<ManifoldRuntimeLease>,
    projection_receipts: Vec<ManifoldBrokerRuntimeLeaseProjection>,
}

impl ManifoldBrokerControlLeaseAuthority {
    /// Builds one synchronized owner from a caller-attested retained view.
    ///
    /// Unrelated active Manifold leases may remain outside this Broker product,
    /// but every Runtime Host lease produced here must have exact source
    /// lineage and remain current in the supplied authority snapshot.
    ///
    /// # Errors
    ///
    /// Returns a typed error when state, clock, lineage, ordering, capacity, or
    /// one-to-one projected lease closure is invalid.
    pub fn from_caller_attested_retained_authority_state(
        current_authority_snapshot: ManifoldAuthoritySnapshot,
        current_clock: ManifoldClockSnapshot,
        lease_sources: Vec<ManifoldBrokerControlLeaseSource>,
    ) -> Result<Self, ManifoldBrokerControlLeaseAuthorityError> {
        let baseline = ManifoldBrokerControlLeaseAuthorityEvidence {
            schema_id: schema_id(BROKER_CONTROL_LEASE_AUTHORITY_EVIDENCE_SCHEMA),
            current_authority_snapshot: current_authority_snapshot.clone(),
            current_clock: current_clock.clone(),
            lease_sources,
        };
        Self::from_v2_evidence(ManifoldBrokerControlLeaseAuthorityEvidenceV2 {
            schema_id: schema_id(BROKER_CONTROL_LEASE_AUTHORITY_EVIDENCE_V2_SCHEMA),
            baseline,
            current_authority_snapshot,
            current_clock,
            transitions: Vec::new(),
        })
    }

    /// Restores source lineage while requiring a freshly supplied owner view.
    ///
    /// The durable snapshot and clock are rollback anchors only. The supplied
    /// current view must use the same authority and clock lineage without
    /// revision or time regression, and every source lease is reprojected
    /// against that supplied view before any host can be restored.
    ///
    /// # Errors
    ///
    /// Returns a typed error when durable evidence, the fresh owner view, or
    /// the reproduced projection set fails validation.
    pub fn refresh_from_evidence(
        evidence: ManifoldBrokerControlLeaseAuthorityEvidence,
        current_authority_snapshot: ManifoldAuthoritySnapshot,
        current_clock: ManifoldClockSnapshot,
    ) -> Result<Self, ManifoldBrokerControlLeaseAuthorityError> {
        Self::migrate_v1_evidence(evidence, current_authority_snapshot, current_clock)
    }

    /// Migrates immutable v1 adoption evidence into current v2 owner state.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the v1 baseline or supplied exact retained
    /// state/clock fails current owner validation.
    pub fn migrate_v1_evidence(
        evidence: ManifoldBrokerControlLeaseAuthorityEvidence,
        current_authority_snapshot: ManifoldAuthoritySnapshot,
        current_clock: ManifoldClockSnapshot,
    ) -> Result<Self, ManifoldBrokerControlLeaseAuthorityError> {
        Self::refresh_from_v2_evidence(
            ManifoldBrokerControlLeaseAuthorityEvidenceV2 {
                schema_id: schema_id(BROKER_CONTROL_LEASE_AUTHORITY_EVIDENCE_V2_SCHEMA),
                baseline: evidence.clone(),
                current_authority_snapshot: evidence.current_authority_snapshot,
                current_clock: evidence.current_clock,
                transitions: Vec::new(),
            },
            current_authority_snapshot,
            current_clock,
        )
    }

    /// Restores current v2 owner evidence against a fresh caller-attested view.
    ///
    /// The exact baseline and transition prefix are immutable. The supplied
    /// view may include unrelated authority changes, but every product lease
    /// derived by replay must remain byte-identical and current.
    ///
    /// # Errors
    ///
    /// Returns a typed error for evidence, replay, clock, authority, capacity,
    /// or product-lease closure failure.
    pub fn refresh_from_v2_evidence(
        mut evidence: ManifoldBrokerControlLeaseAuthorityEvidenceV2,
        current_authority_snapshot: ManifoldAuthoritySnapshot,
        current_clock: ManifoldClockSnapshot,
    ) -> Result<Self, ManifoldBrokerControlLeaseAuthorityError> {
        let restored = Self::from_v2_evidence(evidence.clone())?;
        validate_clock_advance(restored.current_clock(), &current_clock)?;
        if restored.authority_snapshot() != &current_authority_snapshot {
            return Err(ManifoldBrokerControlLeaseAuthorityError::AuthorityRegression);
        }
        evidence.current_authority_snapshot = current_authority_snapshot;
        evidence.current_clock = current_clock;
        Self::from_v2_evidence(evidence)
    }

    fn from_v2_evidence(
        mut evidence: ManifoldBrokerControlLeaseAuthorityEvidenceV2,
    ) -> Result<Self, ManifoldBrokerControlLeaseAuthorityError> {
        if evidence.schema_id.as_str() != BROKER_CONTROL_LEASE_AUTHORITY_EVIDENCE_V2_SCHEMA {
            return Err(ManifoldBrokerControlLeaseAuthorityError::SchemaMismatch);
        }
        if evidence.transitions.len() > MAX_BROKER_CONTROL_LEASE_TRANSITIONS {
            return Err(ManifoldBrokerControlLeaseAuthorityError::TransitionCapacityExceeded);
        }
        validate_v2_evidence_size(&evidence)?;
        let (baseline, mut product_leases, mut issue_sources) =
            validate_and_canonicalize_baseline(evidence.baseline)?;
        evidence.baseline = baseline;

        let mut rolling_snapshot = evidence.baseline.current_authority_snapshot.clone();
        let mut rolling_clock = evidence.baseline.current_clock.clone();
        let mut request_ids = evidence
            .baseline
            .lease_sources
            .iter()
            .map(|source| source.application.request_id.clone())
            .collect::<BTreeSet<_>>();
        for (index, transition) in evidence.transitions.iter().enumerate() {
            validate_serialized_size(transition, MAX_BROKER_CONTROL_LEASE_TRANSITION_BYTES)?;
            if transition.schema_id.as_str() != BROKER_CONTROL_LEASE_TRANSITION_SCHEMA {
                return Err(ManifoldBrokerControlLeaseAuthorityError::SchemaMismatch);
            }
            if transition.sequence != (index as u64) + 1 {
                return Err(ManifoldBrokerControlLeaseAuthorityError::TransitionLineage);
            }
            if !request_ids.insert(transition.application.request_id().clone()) {
                return Err(ManifoldBrokerControlLeaseAuthorityError::TransitionReplay);
            }
            if transition.prior_authority_snapshot != rolling_snapshot {
                return Err(ManifoldBrokerControlLeaseAuthorityError::TransitionLineage);
            }
            validate_clock_advance(&rolling_clock, transition.application.recorded_clock())?;
            transition
                .application
                .validate_against_snapshot(&transition.prior_authority_snapshot)?;
            apply_transition_to_product_set(transition, &mut product_leases, &mut issue_sources)?;
            if product_leases.len() > MAX_BROKER_CONTROL_LEASES {
                return Err(ManifoldBrokerControlLeaseAuthorityError::CapacityExceeded);
            }
            rolling_snapshot = transition
                .application
                .applied_snapshot()
                .cloned()
                .unwrap_or_else(|| transition.prior_authority_snapshot.clone());
            validate_snapshot_duplicate_ids(&rolling_snapshot)?;
            validate_serialized_size(&rolling_snapshot, MAX_BROKER_CONTROL_LEASE_SNAPSHOT_BYTES)?;
            rolling_clock = transition.application.recorded_clock().clone();
        }

        validate_clock_advance(&rolling_clock, &evidence.current_clock)?;
        if evidence.current_authority_snapshot != rolling_snapshot {
            return Err(ManifoldBrokerControlLeaseAuthorityError::TransitionLineage);
        }
        validate_product_lease_expiry(&product_leases, &evidence.current_clock)?;

        let runtime_leases = product_leases
            .values()
            .map(runtime_lease_from_control_lease)
            .collect::<Vec<_>>();
        let mut projection_receipts = Vec::new();
        for (lease_id, source) in issue_sources {
            let Some(current) = product_leases.get(&lease_id) else {
                continue;
            };
            let Some(issued) = source.application.review.accepted.as_ref() else {
                return Err(ManifoldBrokerControlLeaseAuthorityError::TransitionLineage);
            };
            if current != issued {
                continue;
            }
            let projection = ManifoldBrokerRuntimeLeaseProjector::from_retained_authority_state(
                &evidence.current_authority_snapshot,
                &evidence.current_clock,
            )
            .map_err(ManifoldBrokerControlLeaseAuthorityError::Projection)?
            .project(&source.prior_authority_snapshot, &source.application)
            .map_err(ManifoldBrokerControlLeaseAuthorityError::Projection)?;
            projection_receipts.push(projection.into_receipt());
        }
        projection_receipts.sort_by(|left, right| left.projection_id().cmp(right.projection_id()));
        validate_v2_evidence_size(&evidence)?;

        Ok(Self {
            evidence,
            runtime_leases,
            projection_receipts,
        })
    }

    /// Returns the current retained Manifold authority snapshot.
    #[must_use]
    pub const fn authority_snapshot(&self) -> &ManifoldAuthoritySnapshot {
        &self.evidence.current_authority_snapshot
    }

    /// Returns the current retained authority-owner clock view.
    #[must_use]
    pub const fn current_clock(&self) -> &ManifoldClockSnapshot {
        &self.evidence.current_clock
    }

    /// Returns durable source lineage and current owner-state evidence.
    #[must_use]
    pub fn evidence(&self) -> ManifoldBrokerControlLeaseAuthorityEvidenceV2 {
        self.evidence.clone()
    }

    /// Returns the immutable v1 adoption baseline.
    #[must_use]
    pub const fn baseline_evidence(&self) -> &ManifoldBrokerControlLeaseAuthorityEvidence {
        &self.evidence.baseline
    }

    /// Returns the freshly reproduced projection receipts.
    #[must_use]
    pub fn projection_receipts(&self) -> &[ManifoldBrokerRuntimeLeaseProjection] {
        &self.projection_receipts
    }

    pub(crate) fn runtime_leases(&self) -> &[ManifoldRuntimeLease] {
        &self.runtime_leases
    }

    pub(crate) fn ensure_transition_capacity(
        &self,
        kind: ManifoldBrokerControlLeaseTransitionKind,
    ) -> Result<(), ManifoldBrokerControlLeaseAuthorityError> {
        let limit = transition_capacity_limit(kind);
        if self.evidence.transitions.len() >= limit {
            Err(match kind {
                ManifoldBrokerControlLeaseTransitionKind::Issue
                | ManifoldBrokerControlLeaseTransitionKind::Renewal => {
                    ManifoldBrokerControlLeaseAuthorityError::CleanupCapacityReserved
                }
                ManifoldBrokerControlLeaseTransitionKind::Release
                | ManifoldBrokerControlLeaseTransitionKind::Expiry => {
                    ManifoldBrokerControlLeaseAuthorityError::TransitionCapacityExceeded
                }
            })
        } else if matches!(
            kind,
            ManifoldBrokerControlLeaseTransitionKind::Issue
                | ManifoldBrokerControlLeaseTransitionKind::Renewal
        ) && validate_v2_evidence_size_with_limit(
            &self.evidence,
            MAX_BROKER_CONTROL_LEASE_AUTHORITY_EVIDENCE_BYTES
                .saturating_sub(BROKER_CONTROL_LEASE_CLEANUP_EVIDENCE_RESERVE_BYTES),
        )
        .is_err()
        {
            Err(ManifoldBrokerControlLeaseAuthorityError::CleanupCapacityReserved)
        } else {
            Ok(())
        }
    }

    pub(crate) fn issue_control_lease(
        &mut self,
        request: ManifoldControlLeaseRequest,
        recorded_clock: ManifoldClockSnapshot,
        evidence_refs: Vec<DottedId>,
    ) -> Result<ManifoldBrokerControlLeaseTransition, ManifoldBrokerControlLeaseAuthorityError>
    {
        self.ensure_transition_capacity(ManifoldBrokerControlLeaseTransitionKind::Issue)?;
        self.ensure_request_not_replayed(&request.request_id)?;
        validate_clock_advance(self.current_clock(), &recorded_clock)?;
        if request.schema_id.as_str() != "rusty.manifold.command.lease_request.v1" {
            return Err(ManifoldBrokerControlLeaseAuthorityError::SchemaMismatch);
        }
        let review = self
            .authority_snapshot()
            .review_lease_request(request, recorded_clock.clone(), evidence_refs)
            .map_err(|_| ManifoldBrokerControlLeaseAuthorityError::TransitionLineage)?;
        let application = self
            .authority_snapshot()
            .apply_control_lease_authority_review(review)
            .map_err(|_| ManifoldBrokerControlLeaseAuthorityError::TransitionLineage)?;
        self.apply_transition(
            ManifoldBrokerControlLeaseTransitionApplication::Issue(application),
            recorded_clock,
        )
    }

    pub(crate) fn renew_control_lease(
        &mut self,
        request: ManifoldControlLeaseRenewalRequest,
        recorded_clock: ManifoldClockSnapshot,
        evidence_refs: Vec<DottedId>,
    ) -> Result<ManifoldBrokerControlLeaseTransition, ManifoldBrokerControlLeaseAuthorityError>
    {
        self.ensure_transition_capacity(ManifoldBrokerControlLeaseTransitionKind::Renewal)?;
        self.ensure_request_not_replayed(&request.request_id)?;
        self.ensure_product_lease(&request.lease_id)?;
        validate_clock_advance(self.current_clock(), &recorded_clock)?;
        let review = self
            .authority_snapshot()
            .review_control_lease_renewal(request, recorded_clock.clone(), evidence_refs)
            .map_err(|_| ManifoldBrokerControlLeaseAuthorityError::TransitionLineage)?;
        let application = self
            .authority_snapshot()
            .apply_control_lease_renewal_authority_review(review)
            .map_err(|_| ManifoldBrokerControlLeaseAuthorityError::TransitionLineage)?;
        self.apply_transition(
            ManifoldBrokerControlLeaseTransitionApplication::Renewal(application),
            recorded_clock,
        )
    }

    pub(crate) fn release_control_lease(
        &mut self,
        request: ManifoldControlLeaseReleaseRequest,
        recorded_clock: ManifoldClockSnapshot,
        evidence_refs: Vec<DottedId>,
    ) -> Result<ManifoldBrokerControlLeaseTransition, ManifoldBrokerControlLeaseAuthorityError>
    {
        self.ensure_transition_capacity(ManifoldBrokerControlLeaseTransitionKind::Release)?;
        self.ensure_request_not_replayed(&request.request_id)?;
        self.ensure_product_lease(&request.lease_id)?;
        validate_clock_advance(self.current_clock(), &recorded_clock)?;
        let review = self
            .authority_snapshot()
            .review_control_lease_release(request, recorded_clock.clone(), evidence_refs)
            .map_err(|_| ManifoldBrokerControlLeaseAuthorityError::TransitionLineage)?;
        let application = self
            .authority_snapshot()
            .apply_control_lease_release_authority_review(review)
            .map_err(|_| ManifoldBrokerControlLeaseAuthorityError::TransitionLineage)?;
        self.apply_transition(
            ManifoldBrokerControlLeaseTransitionApplication::Release(application),
            recorded_clock,
        )
    }

    pub(crate) fn expire_control_leases(
        &mut self,
        request: ManifoldAuthorityExpirySweepRequest,
        expected_product_lease_ids: &[DottedId],
        recorded_clock: ManifoldClockSnapshot,
        evidence_refs: Vec<DottedId>,
    ) -> Result<ManifoldBrokerControlLeaseTransition, ManifoldBrokerControlLeaseAuthorityError>
    {
        self.ensure_transition_capacity(ManifoldBrokerControlLeaseTransitionKind::Expiry)?;
        self.ensure_request_not_replayed(&request.request_id)?;
        if expected_product_lease_ids.is_empty()
            || expected_product_lease_ids
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(ManifoldBrokerControlLeaseAuthorityError::UnsupportedExpiryDelta);
        }
        for lease_id in expected_product_lease_ids {
            self.ensure_product_lease(lease_id)?;
        }
        validate_clock_advance(self.current_clock(), &recorded_clock)?;
        let review = self
            .authority_snapshot()
            .review_authority_expiry_sweep(request, recorded_clock.clone(), evidence_refs)
            .map_err(|_| ManifoldBrokerControlLeaseAuthorityError::TransitionLineage)?;
        if review.outcome
            == ManifoldAuthorityExpirySweepAuthorityReviewOutcome::ExpiredStateAccepted
        {
            let mut expired_lease_ids = review
                .expired_leases
                .iter()
                .map(|lease| lease.lease_id.clone())
                .collect::<Vec<_>>();
            expired_lease_ids.sort();
            if !review.expired_stream_subscriptions.is_empty()
                || expired_lease_ids != expected_product_lease_ids
            {
                return Err(ManifoldBrokerControlLeaseAuthorityError::UnsupportedExpiryDelta);
            }
        }
        let application = self
            .authority_snapshot()
            .apply_authority_expiry_sweep_review(review)
            .map_err(|_| ManifoldBrokerControlLeaseAuthorityError::TransitionLineage)?;
        self.apply_transition(
            ManifoldBrokerControlLeaseTransitionApplication::Expiry(application),
            recorded_clock,
        )
    }

    fn apply_transition(
        &mut self,
        application: ManifoldBrokerControlLeaseTransitionApplication,
        current_clock: ManifoldClockSnapshot,
    ) -> Result<ManifoldBrokerControlLeaseTransition, ManifoldBrokerControlLeaseAuthorityError>
    {
        self.ensure_transition_capacity(application.kind())?;
        let transition = ManifoldBrokerControlLeaseTransition {
            schema_id: schema_id(BROKER_CONTROL_LEASE_TRANSITION_SCHEMA),
            sequence: (self.evidence.transitions.len() as u64) + 1,
            prior_authority_snapshot: self.evidence.current_authority_snapshot.clone(),
            application,
        };
        if transition.application.applied_snapshot().is_none() {
            return Ok(transition);
        }
        let mut evidence = self.evidence.clone();
        evidence.current_authority_snapshot = transition
            .application
            .applied_snapshot()
            .cloned()
            .unwrap_or_else(|| transition.prior_authority_snapshot.clone());
        evidence.current_clock = current_clock;
        evidence.transitions.push(transition.clone());
        if matches!(
            transition.application.kind(),
            ManifoldBrokerControlLeaseTransitionKind::Issue
                | ManifoldBrokerControlLeaseTransitionKind::Renewal
        ) && validate_v2_evidence_size_with_limit(
            &evidence,
            MAX_BROKER_CONTROL_LEASE_AUTHORITY_EVIDENCE_BYTES
                .saturating_sub(BROKER_CONTROL_LEASE_CLEANUP_EVIDENCE_RESERVE_BYTES),
        )
        .is_err()
        {
            return Err(ManifoldBrokerControlLeaseAuthorityError::CleanupCapacityReserved);
        }
        let candidate = Self::from_v2_evidence(evidence)?;
        *self = candidate;
        Ok(transition)
    }

    pub(crate) fn ensure_request_not_replayed(
        &self,
        request_id: &DottedId,
    ) -> Result<(), ManifoldBrokerControlLeaseAuthorityError> {
        let baseline_replay = self
            .evidence
            .baseline
            .lease_sources
            .iter()
            .any(|source| &source.application.request_id == request_id);
        let transition_replay = self
            .evidence
            .transitions
            .iter()
            .any(|transition| transition.application.request_id() == request_id);
        if baseline_replay || transition_replay {
            Err(ManifoldBrokerControlLeaseAuthorityError::TransitionReplay)
        } else {
            Ok(())
        }
    }

    fn ensure_product_lease(
        &self,
        lease_id: &DottedId,
    ) -> Result<(), ManifoldBrokerControlLeaseAuthorityError> {
        if self
            .runtime_leases
            .iter()
            .any(|lease| &lease.lease_id == lease_id)
        {
            Ok(())
        } else {
            Err(ManifoldBrokerControlLeaseAuthorityError::UnrelatedLease)
        }
    }

    pub(crate) fn validate_host_snapshot(
        &self,
        snapshot: &ManifoldRuntimeHostSnapshot,
    ) -> Result<(), ManifoldBrokerControlLeaseAuthorityError> {
        let mut host_leases = snapshot.leases.clone();
        host_leases.sort_by(|left, right| left.lease_id.cmp(&right.lease_id));
        if host_leases == self.runtime_leases {
            Ok(())
        } else {
            Err(ManifoldBrokerControlLeaseAuthorityError::HostLeaseSetMismatch)
        }
    }

    pub(crate) fn is_refresh_of(
        &self,
        evidence: &ManifoldBrokerControlLeaseAuthorityEvidenceV2,
    ) -> bool {
        self.evidence.baseline == evidence.baseline
            && self.evidence.transitions == evidence.transitions
            && self.evidence.current_authority_snapshot.authority_id
                == evidence.current_authority_snapshot.authority_id
            && self.evidence.current_authority_snapshot.authority_revision
                >= evidence.current_authority_snapshot.authority_revision
            && self.evidence.current_clock.schema_id == evidence.current_clock.schema_id
            && self.evidence.current_clock.clock_domain == evidence.current_clock.clock_domain
            && self.evidence.current_clock.clock_epoch_id == evidence.current_clock.clock_epoch_id
            && self.evidence.current_clock.sequence >= evidence.current_clock.sequence
            && self.evidence.current_clock.monotonic_elapsed_ns
                >= evidence.current_clock.monotonic_elapsed_ns
            && self.evidence.current_clock.wall_unix_ms >= evidence.current_clock.wall_unix_ms
            && self.evidence.current_clock.wall_clock_adjustment_count
                >= evidence.current_clock.wall_clock_adjustment_count
    }
}

/// Failure to close Broker-owned control-lease state over Runtime Host state.
#[derive(Debug)]
pub enum ManifoldBrokerControlLeaseAuthorityError {
    /// A durable source or authority-evidence schema is unsupported.
    SchemaMismatch,
    /// Retained projected lease capacity was exceeded.
    CapacityExceeded,
    /// Chronological lifecycle ledger capacity was exhausted.
    TransitionCapacityExceeded,
    /// Issue/renew admission reached the cleanup-reserved ledger suffix.
    CleanupCapacityReserved,
    /// Durable source lineage exceeds the serialized evidence budget.
    EvidenceTooLarge,
    /// Two retained source applications derive the same lease identity.
    DuplicateLeaseId,
    /// A lifecycle request identity was already retained.
    TransitionReplay,
    /// A transition application did not continue the exact retained lineage.
    TransitionLineage,
    /// Renewal or release targeted a lease outside this Broker product.
    UnrelatedLease,
    /// Generic expiry selected subscriptions, unrelated leases, or another lease set.
    UnsupportedExpiryDelta,
    /// A retained or supplied clock is not healthy or exceeds uncertainty policy.
    InvalidClock,
    /// A retained product lease is expired at the strict uncertainty-adjusted clock.
    ExpiredLease,
    /// A source lease or owner view failed projection validation.
    Projection(ManifoldBrokerRuntimeLeaseProjectionError),
    /// The refreshed authority identity or revision regressed.
    AuthorityRegression,
    /// The refreshed clock uses a different schema, domain, or epoch.
    ClockLineageMismatch,
    /// The refreshed clock sequence or time regressed.
    ClockRegression,
    /// Runtime Host leases differ from the owner-derived projection set.
    HostLeaseSetMismatch,
}

impl fmt::Display for ManifoldBrokerControlLeaseAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SchemaMismatch => formatter.write_str("control-lease schema mismatch"),
            Self::CapacityExceeded => formatter.write_str("control-lease capacity exceeded"),
            Self::TransitionCapacityExceeded => {
                formatter.write_str("control-lease transition capacity exceeded")
            }
            Self::CleanupCapacityReserved => {
                formatter.write_str("control-lease transition capacity is reserved for cleanup")
            }
            Self::EvidenceTooLarge => {
                formatter.write_str("control-lease authority evidence exceeds byte budget")
            }
            Self::DuplicateLeaseId => formatter.write_str("duplicate projected lease id"),
            Self::TransitionReplay => formatter.write_str("control-lease transition replay"),
            Self::TransitionLineage => {
                formatter.write_str("control-lease transition lineage mismatch")
            }
            Self::UnrelatedLease => {
                formatter.write_str("control-lease transition targets an unrelated lease")
            }
            Self::UnsupportedExpiryDelta => {
                formatter.write_str("control-lease expiry selected an unsupported authority delta")
            }
            Self::InvalidClock => {
                formatter.write_str("control-lease authority clock is not admissible")
            }
            Self::ExpiredLease => formatter.write_str("control-lease product lease is expired"),
            Self::Projection(error) => {
                write!(formatter, "control-lease projection failed: {error}")
            }
            Self::AuthorityRegression => {
                formatter.write_str("control-lease authority identity or revision regressed")
            }
            Self::ClockLineageMismatch => {
                formatter.write_str("control-lease authority clock lineage changed")
            }
            Self::ClockRegression => formatter.write_str("control-lease authority clock regressed"),
            Self::HostLeaseSetMismatch => {
                formatter.write_str("Runtime Host lease set differs from control-lease authority")
            }
        }
    }
}

impl std::error::Error for ManifoldBrokerControlLeaseAuthorityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Projection(error) => Some(error),
            _ => None,
        }
    }
}

fn schema_id(value: &str) -> SchemaId {
    SchemaId::new(value).expect("static schema id is valid")
}

#[allow(clippy::type_complexity)]
fn validate_and_canonicalize_baseline(
    mut evidence: ManifoldBrokerControlLeaseAuthorityEvidence,
) -> Result<
    (
        ManifoldBrokerControlLeaseAuthorityEvidence,
        BTreeMap<DottedId, ManifoldControlLease>,
        BTreeMap<DottedId, ManifoldBrokerControlLeaseSource>,
    ),
    ManifoldBrokerControlLeaseAuthorityError,
> {
    if evidence.schema_id.as_str() != BROKER_CONTROL_LEASE_AUTHORITY_EVIDENCE_SCHEMA {
        return Err(ManifoldBrokerControlLeaseAuthorityError::SchemaMismatch);
    }
    if evidence.lease_sources.len() > MAX_BROKER_CONTROL_LEASES {
        return Err(ManifoldBrokerControlLeaseAuthorityError::CapacityExceeded);
    }
    validate_v1_evidence_size(&evidence)?;
    validate_snapshot_duplicate_ids(&evidence.current_authority_snapshot)?;
    validate_serialized_size(
        &evidence.current_authority_snapshot,
        MAX_BROKER_CONTROL_LEASE_SNAPSHOT_BYTES,
    )?;
    ManifoldBrokerRuntimeLeaseProjector::from_retained_authority_state(
        &evidence.current_authority_snapshot,
        &evidence.current_clock,
    )
    .map_err(ManifoldBrokerControlLeaseAuthorityError::Projection)?;

    let mut projected = std::mem::take(&mut evidence.lease_sources)
        .into_iter()
        .map(|source| {
            if source.schema_id.as_str() != BROKER_CONTROL_LEASE_SOURCE_SCHEMA
                || source
                    .application
                    .review
                    .audit_event
                    .request
                    .schema_id
                    .as_str()
                    != "rusty.manifold.command.lease_request.v1"
            {
                return Err(ManifoldBrokerControlLeaseAuthorityError::SchemaMismatch);
            }
            validate_snapshot_duplicate_ids(&source.prior_authority_snapshot)?;
            validate_serialized_size(
                &source.prior_authority_snapshot,
                MAX_BROKER_CONTROL_LEASE_SNAPSHOT_BYTES,
            )?;
            let projection = ManifoldBrokerRuntimeLeaseProjector::from_retained_authority_state(
                &evidence.current_authority_snapshot,
                &evidence.current_clock,
            )
            .map_err(ManifoldBrokerControlLeaseAuthorityError::Projection)?
            .project(&source.prior_authority_snapshot, &source.application)
            .map_err(ManifoldBrokerControlLeaseAuthorityError::Projection)?;
            let lease = source
                .application
                .review
                .accepted
                .clone()
                .ok_or(ManifoldBrokerControlLeaseAuthorityError::TransitionLineage)?;
            Ok((lease.lease_id.clone(), source, lease, projection))
        })
        .collect::<Result<Vec<_>, _>>()?;
    projected.sort_by(|left, right| left.0.cmp(&right.0));
    if projected.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(ManifoldBrokerControlLeaseAuthorityError::DuplicateLeaseId);
    }
    let mut product_leases = BTreeMap::new();
    let mut issue_sources = BTreeMap::new();
    let mut canonical_sources = Vec::with_capacity(projected.len());
    for (lease_id, source, lease, _) in projected {
        product_leases.insert(lease_id.clone(), lease);
        issue_sources.insert(lease_id, source.clone());
        canonical_sources.push(source);
    }
    evidence.lease_sources = canonical_sources;
    validate_v1_evidence_size(&evidence)?;
    Ok((evidence, product_leases, issue_sources))
}

fn apply_transition_to_product_set(
    transition: &ManifoldBrokerControlLeaseTransition,
    product_leases: &mut BTreeMap<DottedId, ManifoldControlLease>,
    issue_sources: &mut BTreeMap<DottedId, ManifoldBrokerControlLeaseSource>,
) -> Result<(), ManifoldBrokerControlLeaseAuthorityError> {
    match &transition.application {
        ManifoldBrokerControlLeaseTransitionApplication::Issue(application) => {
            if application.outcome == ManifoldControlLeaseAuthorityApplicationOutcome::LeaseApplied
            {
                let lease = application
                    .review
                    .accepted
                    .clone()
                    .ok_or(ManifoldBrokerControlLeaseAuthorityError::TransitionLineage)?;
                if product_leases.contains_key(&lease.lease_id) {
                    return Err(ManifoldBrokerControlLeaseAuthorityError::DuplicateLeaseId);
                }
                let lease_id = lease.lease_id.clone();
                product_leases.insert(lease_id.clone(), lease);
                issue_sources.insert(
                    lease_id,
                    ManifoldBrokerControlLeaseSource {
                        schema_id: schema_id(BROKER_CONTROL_LEASE_SOURCE_SCHEMA),
                        prior_authority_snapshot: transition.prior_authority_snapshot.clone(),
                        application: application.clone(),
                    },
                );
            }
        }
        ManifoldBrokerControlLeaseTransitionApplication::Renewal(application) => {
            let lease_id = &application.lease_id;
            let current = product_leases
                .get(lease_id)
                .cloned()
                .ok_or(ManifoldBrokerControlLeaseAuthorityError::UnrelatedLease)?;
            if application.outcome
                == ManifoldControlLeaseRenewalAuthorityApplicationOutcome::LeaseRenewalApplied
            {
                let renewed = application
                    .review
                    .renewed
                    .clone()
                    .ok_or(ManifoldBrokerControlLeaseAuthorityError::TransitionLineage)?;
                if renewed.lease_id != current.lease_id
                    || renewed.holder_id != current.holder_id
                    || renewed.scope != current.scope
                    || renewed.required_capability != current.required_capability
                    || renewed.state != LeaseState::Active
                    || renewed.expires_at_ms <= current.expires_at_ms
                {
                    return Err(ManifoldBrokerControlLeaseAuthorityError::TransitionLineage);
                }
                product_leases.insert(lease_id.clone(), renewed);
                issue_sources.remove(lease_id);
            }
        }
        ManifoldBrokerControlLeaseTransitionApplication::Release(application) => {
            let lease_id = &application.lease_id;
            if !product_leases.contains_key(lease_id) {
                return Err(ManifoldBrokerControlLeaseAuthorityError::UnrelatedLease);
            }
            if application.outcome
                == ManifoldControlLeaseReleaseAuthorityApplicationOutcome::LeaseReleaseApplied
            {
                product_leases.remove(lease_id);
                issue_sources.remove(lease_id);
            }
        }
        ManifoldBrokerControlLeaseTransitionApplication::Expiry(application) => {
            if !application.review.expired_stream_subscriptions.is_empty()
                || application.review.expired_leases.is_empty()
                || application
                    .review
                    .expired_leases
                    .iter()
                    .any(|lease| !product_leases.contains_key(&lease.lease_id))
            {
                return Err(ManifoldBrokerControlLeaseAuthorityError::UnsupportedExpiryDelta);
            }
            if application.outcome
                == ManifoldAuthorityExpirySweepAuthorityApplicationOutcome::ExpiredStateApplied
            {
                for lease in &application.review.expired_leases {
                    product_leases.remove(&lease.lease_id);
                    issue_sources.remove(&lease.lease_id);
                }
            }
        }
    }
    Ok(())
}

fn validate_snapshot_duplicate_ids(
    snapshot: &ManifoldAuthoritySnapshot,
) -> Result<(), ManifoldBrokerControlLeaseAuthorityError> {
    snapshot
        .validate_authority_links()
        .map_err(|_| ManifoldBrokerControlLeaseAuthorityError::TransitionLineage)?;
    let unique = snapshot
        .active_leases
        .iter()
        .map(|lease| &lease.lease_id)
        .collect::<BTreeSet<_>>();
    if unique.len() == snapshot.active_leases.len() {
        Ok(())
    } else {
        Err(ManifoldBrokerControlLeaseAuthorityError::DuplicateLeaseId)
    }
}

fn validate_clock_advance(
    previous: &ManifoldClockSnapshot,
    current: &ManifoldClockSnapshot,
) -> Result<(), ManifoldBrokerControlLeaseAuthorityError> {
    if current.schema_id != previous.schema_id
        || current.clock_domain != previous.clock_domain
        || current.clock_epoch_id != previous.clock_epoch_id
    {
        return Err(ManifoldBrokerControlLeaseAuthorityError::ClockLineageMismatch);
    }
    if current.health != ClockHealth::Healthy
        || current.read_uncertainty_ns > MAX_BROKER_RUNTIME_LEASE_CLOCK_UNCERTAINTY_NS
        || current.wall_unix_ms < 0
    {
        return Err(ManifoldBrokerControlLeaseAuthorityError::InvalidClock);
    }
    if current.sequence < previous.sequence
        || current.monotonic_elapsed_ns < previous.monotonic_elapsed_ns
        || current.wall_unix_ms < previous.wall_unix_ms
        || current.wall_clock_adjustment_count < previous.wall_clock_adjustment_count
    {
        return Err(ManifoldBrokerControlLeaseAuthorityError::ClockRegression);
    }
    Ok(())
}

fn validate_product_lease_expiry(
    product_leases: &BTreeMap<DottedId, ManifoldControlLease>,
    clock: &ManifoldClockSnapshot,
) -> Result<(), ManifoldBrokerControlLeaseAuthorityError> {
    let wall = u64::try_from(clock.wall_unix_ms)
        .map_err(|_| ManifoldBrokerControlLeaseAuthorityError::InvalidClock)?;
    let uncertainty_ms = clock.read_uncertainty_ns.div_ceil(1_000_000);
    let check_at = wall
        .checked_add(uncertainty_ms)
        .ok_or(ManifoldBrokerControlLeaseAuthorityError::InvalidClock)?;
    if product_leases
        .values()
        .any(|lease| lease.expires_at_ms <= check_at)
    {
        Err(ManifoldBrokerControlLeaseAuthorityError::ExpiredLease)
    } else {
        Ok(())
    }
}

fn runtime_lease_from_control_lease(lease: &ManifoldControlLease) -> ManifoldRuntimeLease {
    ManifoldRuntimeLease {
        lease_id: lease.lease_id.clone(),
        scope: lease.scope.clone(),
        holder_id: lease.holder_id.clone(),
        expires_at_ms: lease.expires_at_ms,
    }
}

const fn transition_capacity_limit(kind: ManifoldBrokerControlLeaseTransitionKind) -> usize {
    match kind {
        ManifoldBrokerControlLeaseTransitionKind::Issue
        | ManifoldBrokerControlLeaseTransitionKind::Renewal => MAX_BROKER_CONTROL_LEASE_TRANSITIONS
            .saturating_sub(BROKER_CONTROL_LEASE_CLEANUP_TRANSITION_RESERVE),
        ManifoldBrokerControlLeaseTransitionKind::Release
        | ManifoldBrokerControlLeaseTransitionKind::Expiry => MAX_BROKER_CONTROL_LEASE_TRANSITIONS,
    }
}

fn validate_v1_evidence_size(
    evidence: &ManifoldBrokerControlLeaseAuthorityEvidence,
) -> Result<(), ManifoldBrokerControlLeaseAuthorityError> {
    let mut writer = LimitedWriter::new(
        MAX_BROKER_CONTROL_LEASE_AUTHORITY_EVIDENCE_BYTES
            .saturating_sub(BROKER_CONTROL_LEASE_CLEANUP_EVIDENCE_RESERVE_BYTES),
    );
    serde_json::to_writer(&mut writer, evidence)
        .map_err(|_| ManifoldBrokerControlLeaseAuthorityError::EvidenceTooLarge)
}

fn validate_v2_evidence_size(
    evidence: &ManifoldBrokerControlLeaseAuthorityEvidenceV2,
) -> Result<(), ManifoldBrokerControlLeaseAuthorityError> {
    validate_v2_evidence_size_with_limit(
        evidence,
        MAX_BROKER_CONTROL_LEASE_AUTHORITY_EVIDENCE_BYTES,
    )
}

fn validate_v2_evidence_size_with_limit(
    evidence: &ManifoldBrokerControlLeaseAuthorityEvidenceV2,
    limit: usize,
) -> Result<(), ManifoldBrokerControlLeaseAuthorityError> {
    let mut writer = LimitedWriter::new(limit);
    serde_json::to_writer(&mut writer, evidence)
        .map_err(|_| ManifoldBrokerControlLeaseAuthorityError::EvidenceTooLarge)
}

fn validate_serialized_size<T: Serialize>(
    value: &T,
    limit: usize,
) -> Result<(), ManifoldBrokerControlLeaseAuthorityError> {
    let mut writer = LimitedWriter::new(limit);
    serde_json::to_writer(&mut writer, value)
        .map_err(|_| ManifoldBrokerControlLeaseAuthorityError::EvidenceTooLarge)
}

struct LimitedWriter {
    written: usize,
    limit: usize,
}

impl LimitedWriter {
    const fn new(limit: usize) -> Self {
        Self { written: 0, limit }
    }
}

impl Write for LimitedWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let remaining = self.limit.saturating_sub(self.written);
        if buffer.len() > remaining {
            return Err(io::Error::other("serialized evidence byte limit exceeded"));
        }
        self.written += buffer.len();
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusty_manifold_model::DottedId;

    fn accepted_source() -> ManifoldBrokerControlLeaseSource {
        ManifoldBrokerControlLeaseSource {
            schema_id: schema_id(BROKER_CONTROL_LEASE_SOURCE_SCHEMA),
            prior_authority_snapshot: serde_json::from_str(include_str!(
                "../../../fixtures/authority/synthetic-authority-snapshot.json"
            ))
            .expect("prior snapshot"),
            application: serde_json::from_str(include_str!(
                "../../../fixtures/authority-application/synthetic-lease-accepted-application.json"
            ))
            .expect("accepted application"),
        }
    }

    fn current_snapshot() -> ManifoldAuthoritySnapshot {
        accepted_source()
            .application
            .applied_snapshot
            .expect("current snapshot")
    }

    fn current_clock() -> ManifoldClockSnapshot {
        serde_json::from_str(include_str!(
            "../../../fixtures/clock/synthetic-command-review-clock.json"
        ))
        .expect("current clock")
    }

    fn advanced_clock(delta_ms: i64) -> ManifoldClockSnapshot {
        let mut clock = current_clock();
        clock.sequence += 1;
        clock.monotonic_elapsed_ns += 1_000_000;
        clock.wall_unix_ms += delta_ms;
        clock
    }

    fn empty_authority() -> ManifoldBrokerControlLeaseAuthority {
        ManifoldBrokerControlLeaseAuthority::from_caller_attested_retained_authority_state(
            accepted_source().prior_authority_snapshot,
            current_clock(),
            Vec::new(),
        )
        .expect("empty product authority")
    }

    #[test]
    fn source_lineage_reproduces_exact_host_lease_set() {
        let authority =
            ManifoldBrokerControlLeaseAuthority::from_caller_attested_retained_authority_state(
                current_snapshot(),
                current_clock(),
                vec![accepted_source()],
            )
            .expect("authority");
        assert_eq!(authority.runtime_leases.len(), 1);
        assert_eq!(
            authority.runtime_leases[0].lease_id,
            DottedId::new("lease.synthetic_lease_1").expect("id")
        );
        assert_eq!(authority.projection_receipts.len(), 1);
    }

    #[test]
    fn refresh_rejects_authority_clock_and_lease_regression() {
        let authority =
            ManifoldBrokerControlLeaseAuthority::from_caller_attested_retained_authority_state(
                current_snapshot(),
                current_clock(),
                vec![accepted_source()],
            )
            .expect("authority");
        let evidence = authority.evidence();

        let mut regressed_snapshot = current_snapshot();
        regressed_snapshot.authority_revision = rusty_manifold_model::Revision::INITIAL;
        assert!(matches!(
            ManifoldBrokerControlLeaseAuthority::refresh_from_v2_evidence(
                evidence.clone(),
                regressed_snapshot,
                current_clock(),
            ),
            Err(ManifoldBrokerControlLeaseAuthorityError::AuthorityRegression)
        ));

        let mut regressed_clock = current_clock();
        regressed_clock.sequence = regressed_clock.sequence.saturating_sub(1);
        assert!(matches!(
            ManifoldBrokerControlLeaseAuthority::refresh_from_v2_evidence(
                evidence.clone(),
                current_snapshot(),
                regressed_clock,
            ),
            Err(ManifoldBrokerControlLeaseAuthorityError::ClockRegression)
        ));

        let mut released = current_snapshot();
        released.authority_revision = rusty_manifold_model::Revision::new(3).expect("revision");
        released
            .active_leases
            .retain(|lease| lease.lease_id.as_str() != "lease.synthetic_lease_1");
        assert!(matches!(
            ManifoldBrokerControlLeaseAuthority::refresh_from_v2_evidence(
                evidence,
                released,
                current_clock(),
            ),
            Err(ManifoldBrokerControlLeaseAuthorityError::AuthorityRegression)
        ));
    }

    #[test]
    fn duplicate_source_and_host_only_lease_fail_closed() {
        assert!(matches!(
            ManifoldBrokerControlLeaseAuthority::from_caller_attested_retained_authority_state(
                current_snapshot(),
                current_clock(),
                vec![accepted_source(), accepted_source()],
            ),
            Err(ManifoldBrokerControlLeaseAuthorityError::DuplicateLeaseId)
        ));

        let authority =
            ManifoldBrokerControlLeaseAuthority::from_caller_attested_retained_authority_state(
                current_snapshot(),
                current_clock(),
                vec![accepted_source()],
            )
            .expect("authority");
        let mut snapshot = ManifoldRuntimeHostSnapshot {
            schema_id: schema_id("rusty.manifold.runtime_host.snapshot.v2"),
            host_id: DottedId::new("host.test").expect("id"),
            authority_revision: rusty_manifold_model::Revision::INITIAL,
            commands: Vec::new(),
            leases: authority.runtime_leases().to_vec(),
            applied_request_ids: Vec::new(),
            reviewed_sweep_ids: Vec::new(),
            reviewed_control_lease_adoption_ids: Vec::new(),
            audit_events: Vec::new(),
        };
        snapshot.leases.push(ManifoldRuntimeLease {
            lease_id: DottedId::new("lease.host_only").expect("id"),
            scope: DottedId::new("scope.host_only").expect("id"),
            holder_id: DottedId::new("holder.host_only").expect("id"),
            expires_at_ms: u64::MAX,
        });
        assert!(matches!(
            authority.validate_host_snapshot(&snapshot),
            Err(ManifoldBrokerControlLeaseAuthorityError::HostLeaseSetMismatch)
        ));
    }

    #[test]
    fn authority_evidence_writer_and_product_lease_count_are_bounded() {
        let mut writer = LimitedWriter::new(4);
        assert!(serde_json::to_writer(&mut writer, "oversized").is_err());

        assert!(matches!(
            ManifoldBrokerControlLeaseAuthority::from_caller_attested_retained_authority_state(
                current_snapshot(),
                current_clock(),
                vec![accepted_source(); MAX_BROKER_CONTROL_LEASES + 1],
            ),
            Err(ManifoldBrokerControlLeaseAuthorityError::CapacityExceeded)
        ));
    }

    #[test]
    fn v2_replay_preserves_one_identity_across_issue_renew_release() {
        let source = accepted_source();
        let issue_request = source.application.review.audit_event.request;
        let mut authority = empty_authority();
        authority
            .issue_control_lease(
                issue_request,
                current_clock(),
                vec![DottedId::new("evidence.issue.product").expect("id")],
            )
            .expect("issue");
        let issued = authority.runtime_leases()[0].clone();

        let renewal_clock = advanced_clock(100);
        authority
            .renew_control_lease(
                ManifoldControlLeaseRenewalRequest {
                    schema_id: schema_id("rusty.manifold.command.lease_renewal_request.v1"),
                    request_id: DottedId::new("request.renew.product").expect("id"),
                    lease_id: issued.lease_id.clone(),
                    holder_id: issued.holder_id.clone(),
                    expected_authority_revision: authority.authority_snapshot().authority_revision,
                    scope: issued.scope.clone(),
                    requested_ttl_ms: 60_000,
                    renewal_reason: DottedId::new("holder.continue").expect("id"),
                    requested_at_ms: u64::try_from(renewal_clock.wall_unix_ms).expect("time"),
                },
                renewal_clock,
                vec![DottedId::new("evidence.renew.product").expect("id")],
            )
            .expect("renew");
        assert_eq!(authority.runtime_leases()[0].lease_id, issued.lease_id);
        assert!(authority.runtime_leases()[0].expires_at_ms > issued.expires_at_ms);

        let release_clock = advanced_clock(200);
        authority
            .release_control_lease(
                ManifoldControlLeaseReleaseRequest {
                    schema_id: schema_id("rusty.manifold.command.lease_release_request.v1"),
                    request_id: DottedId::new("request.release.product").expect("id"),
                    lease_id: issued.lease_id,
                    holder_id: issued.holder_id,
                    expected_authority_revision: authority.authority_snapshot().authority_revision,
                    scope: issued.scope,
                    release_reason: DottedId::new("holder.done").expect("id"),
                    requested_at_ms: u64::try_from(release_clock.wall_unix_ms).expect("time"),
                },
                release_clock,
                vec![DottedId::new("evidence.release.product").expect("id")],
            )
            .expect("release");
        assert!(authority.runtime_leases().is_empty());
        assert_eq!(authority.evidence().transitions.len(), 3);
    }

    #[test]
    fn explicit_expiry_removes_product_and_replay_unrelated_clock_fail_closed() {
        let mut authority =
            ManifoldBrokerControlLeaseAuthority::from_caller_attested_retained_authority_state(
                current_snapshot(),
                current_clock(),
                vec![accepted_source()],
            )
            .expect("authority");
        let lease_id = authority.runtime_leases()[0].lease_id.clone();
        let expiry_clock = advanced_clock(120_000);
        assert!(matches!(
            authority.expire_control_leases(
                ManifoldAuthorityExpirySweepRequest {
                    schema_id: schema_id("rusty.manifold.authority.expiry_sweep_request.v1"),
                    request_id: DottedId::new("request.expiry.product").expect("id"),
                    requester_id: DottedId::new("owner.broker").expect("id"),
                    expected_authority_revision: authority.authority_snapshot().authority_revision,
                    expected_registry_revision: authority
                        .authority_snapshot()
                        .stream_registry
                        .registry_revision,
                    sweep_reason: DottedId::new("clock.expired").expect("id"),
                    requested_at_ms: u64::try_from(expiry_clock.wall_unix_ms).expect("time"),
                },
                &[lease_id.clone()],
                expiry_clock,
                vec![DottedId::new("evidence.expiry.product").expect("id")],
            ),
            Err(ManifoldBrokerControlLeaseAuthorityError::UnsupportedExpiryDelta)
        ));
        assert!(authority
            .runtime_leases()
            .iter()
            .any(|lease| lease.lease_id == lease_id));

        let unrelated = DottedId::new("lease.synthetic_module").expect("id");
        let request = ManifoldControlLeaseRenewalRequest {
            schema_id: schema_id("rusty.manifold.command.lease_renewal_request.v1"),
            request_id: DottedId::new("request.renew.unrelated").expect("id"),
            lease_id: unrelated,
            holder_id: DottedId::new("holder.synthetic_operator").expect("id"),
            expected_authority_revision: authority.authority_snapshot().authority_revision,
            scope: DottedId::new("module.synthetic_wave_provider").expect("id"),
            requested_ttl_ms: 60_000,
            renewal_reason: DottedId::new("holder.continue").expect("id"),
            requested_at_ms: 1,
        };
        let retained_clock = authority.current_clock().clone();
        assert!(matches!(
            authority.renew_control_lease(
                request,
                retained_clock,
                vec![DottedId::new("evidence.unrelated").expect("id")]
            ),
            Err(ManifoldBrokerControlLeaseAuthorityError::UnrelatedLease)
        ));

        let mut unhealthy = authority.current_clock().clone();
        unhealthy.health = ClockHealth::Degraded;
        assert!(matches!(
            validate_clock_advance(authority.current_clock(), &unhealthy),
            Err(ManifoldBrokerControlLeaseAuthorityError::InvalidClock)
        ));
    }

    #[test]
    fn replay_damaged_lineage_and_cleanup_reserve_fail_closed() {
        let source = accepted_source();
        let request = source.application.review.audit_event.request;
        let mut authority = empty_authority();
        let transition = authority
            .issue_control_lease(
                request.clone(),
                current_clock(),
                vec![DottedId::new("evidence.issue.replay").expect("id")],
            )
            .expect("issue");
        assert!(matches!(
            authority.issue_control_lease(
                request,
                current_clock(),
                vec![DottedId::new("evidence.issue.replay").expect("id")]
            ),
            Err(ManifoldBrokerControlLeaseAuthorityError::TransitionReplay)
        ));

        let mut damaged = authority.evidence();
        damaged.transitions[0]
            .prior_authority_snapshot
            .authority_revision = rusty_manifold_model::Revision::new(2).expect("revision");
        assert!(matches!(
            ManifoldBrokerControlLeaseAuthority::from_v2_evidence(damaged),
            Err(ManifoldBrokerControlLeaseAuthorityError::TransitionLineage)
        ));

        assert_eq!(
            transition_capacity_limit(ManifoldBrokerControlLeaseTransitionKind::Renewal),
            MAX_BROKER_CONTROL_LEASE_TRANSITIONS - BROKER_CONTROL_LEASE_CLEANUP_TRANSITION_RESERVE
        );
        assert_eq!(
            transition_capacity_limit(ManifoldBrokerControlLeaseTransitionKind::Release),
            MAX_BROKER_CONTROL_LEASE_TRANSITIONS
        );
        assert_eq!(transition.sequence, 1);
    }
}
