//! Manifold-owned authority for external low-rate stream observations.
//!
//! Producers submit typed proposals. Review is non-mutating. Application
//! revalidates the proposal and decision against current host state, advances
//! authority exactly once, and emits a Manifold-owned receipt.

use rusty_manifold_model::{DottedId, Revision, SchemaId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;

/// Proposal schema.
pub const PROPOSAL_SCHEMA: &str = "rusty.manifold.stream.observation_proposal.v1";
/// Observation metadata schema.
pub const OBSERVATION_SCHEMA: &str = "rusty.manifold.stream.observation.v1";
/// Review policy schema.
pub const POLICY_SCHEMA: &str = "rusty.manifold.stream.observation_review_policy.v1";
/// Review decision schema.
pub const REVIEW_SCHEMA: &str = "rusty.manifold.stream.observation_review.v1";
/// Accepted state schema.
pub const STATE_SCHEMA: &str = "rusty.manifold.stream.observation_accepted_state.v1";
/// Rejection schema.
pub const REJECTION_SCHEMA: &str = "rusty.manifold.stream.observation_rejection.v1";
/// Audit event schema.
pub const AUDIT_SCHEMA: &str = "rusty.manifold.stream.observation_audit_event.v1";
/// Application receipt schema.
pub const RECEIPT_SCHEMA: &str = "rusty.manifold.stream.observation_application_receipt.v1";
/// Host snapshot schema.
pub const SNAPSHOT_SCHEMA: &str = "rusty.manifold.stream.observation_host_snapshot.v1";
/// Conformance case schema.
pub const CONFORMANCE_SCHEMA: &str = "rusty.manifold.stream.observation_conformance_case.v1";

const MAX_TTL_MS: u64 = 300_000;
const MAX_AUDIT_EVENTS: usize = 4096;
const MAX_APPLIED_PROPOSALS: usize = 4096;
const MAX_ACCEPTED_STREAMS: usize = 1024;

/// Bounded low-rate observation metadata. Samples and effect-bearing fields are absent.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldStreamObservation {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Opaque descriptor family.
    pub descriptor_type: DottedId,
    /// Opaque channel format.
    pub channel_format: DottedId,
    /// Declared channel count.
    pub channel_count: u32,
    /// Optional nominal rate in millihertz; zero is not accepted.
    pub nominal_rate_millihz: Option<u64>,
    /// Optional opaque native descriptor digest.
    pub native_descriptor_sha256: Option<String>,
}

/// Typed, non-authoritative proposal from an external producer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldStreamObservationProposal {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Idempotency identity.
    pub proposal_id: DottedId,
    /// Proposing adapter identity.
    pub proposer_id: DottedId,
    /// External source identity, distinct from the proposer.
    pub source_id: DottedId,
    /// Logical stream identity.
    pub stream_id: DottedId,
    /// SHA-256 of canonical observation metadata.
    pub content_sha256: String,
    /// Proposal-envelope observation time.
    pub observed_at_ms: u64,
    /// Proposal-envelope expiry.
    pub expires_at_ms: u64,
    /// Current Manifold revision expected by the proposer.
    pub expected_authority_revision: Revision,
    /// Proposed low-rate metadata.
    pub observation: ManifoldStreamObservation,
}

/// One policy-owned proposer/source/stream binding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldStreamObservationBinding {
    /// Proposer identity.
    pub proposer_id: DottedId,
    /// Source identity.
    pub source_id: DottedId,
    /// Stream identity.
    pub stream_id: DottedId,
}

/// Explicit Manifold review policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldStreamObservationReviewPolicy {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Stable policy identity.
    pub policy_id: DottedId,
    /// Exact allowed bindings.
    pub allowed_bindings: Vec<ManifoldStreamObservationBinding>,
}

/// Review outcome.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldStreamObservationReviewOutcome {
    /// Proposal is eligible for later application.
    Accepted,
    /// Proposal is rejected without mutation.
    Rejected,
}

/// Stable rejection reason.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldStreamObservationRejectionReason {
    /// Schema identity mismatch.
    SchemaMismatch,
    /// Proposal expected a different current revision.
    StaleAuthorityRevision,
    /// Proposal or digest was already applied.
    Replay,
    /// Policy did not authorize the exact identity triple.
    BindingNotAllowed,
    /// Observation content did not match its digest.
    ContentDigestMismatch,
    /// Proposal is future-dated, expired, or has invalid time ordering.
    Expired,
    /// Proposal lifetime exceeds the low-rate bound.
    TtlExceeded,
    /// Observation fields are empty, zero, or malformed.
    InvalidObservation,
    /// Retained state has reached a fail-closed capacity bound.
    CapacityExceeded,
    /// Decision does not bind the exact proposal or review revision.
    DecisionMismatch,
    /// Accepted application was attempted more than once.
    DuplicateApplication,
}

/// Machine-readable rejection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldStreamObservationRejection {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Proposal identity.
    pub proposal_id: DottedId,
    /// Proposal digest.
    pub proposal_sha256: String,
    /// Unchanged authority revision.
    pub authority_revision: Revision,
    /// Stable reason.
    pub reason: ManifoldStreamObservationRejectionReason,
}

/// Non-mutating review decision. It never contains accepted state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldStreamObservationReviewDecision {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Derived decision identity.
    pub decision_id: DottedId,
    /// Exact proposal identity.
    pub proposal_id: DottedId,
    /// Digest of the exact proposal.
    pub proposal_sha256: String,
    /// Policy identity.
    pub policy_id: DottedId,
    /// Digest of the exact reviewed policy.
    pub policy_sha256: String,
    /// Revision reviewed without mutation.
    pub reviewed_authority_revision: Revision,
    /// Review attempt time.
    pub reviewed_at_ms: u64,
    /// Explicit outcome.
    pub outcome: ManifoldStreamObservationReviewOutcome,
    /// Rejection when rejected.
    pub rejection: Option<ManifoldStreamObservationRejection>,
    /// Separate non-mutating review audit event.
    pub audit_event: ManifoldStreamObservationAuditEvent,
}

/// One accepted observation owned by Manifold.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldAcceptedStreamObservation {
    /// Stream identity.
    pub stream_id: DottedId,
    /// Source identity.
    pub source_id: DottedId,
    /// Proposer identity.
    pub proposer_id: DottedId,
    /// Accepted content digest.
    pub content_sha256: String,
    /// Envelope observation time.
    pub observed_at_ms: u64,
    /// Envelope expiry.
    pub expires_at_ms: u64,
    /// Accepted low-rate metadata.
    pub observation: ManifoldStreamObservation,
}

/// Current Manifold-owned accepted state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldStreamObservationAcceptedState {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Current authority revision.
    pub authority_revision: Revision,
    /// Accepted observations, sorted by stream identity.
    pub streams: Vec<ManifoldAcceptedStreamObservation>,
}

/// Audit phase.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldStreamObservationAuditPhase {
    /// Review result.
    Review,
    /// Application result.
    Application,
}

/// Manifold-owned audit event.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldStreamObservationAuditEvent {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Deterministic event identity.
    pub event_id: DottedId,
    /// Event phase.
    pub phase: ManifoldStreamObservationAuditPhase,
    /// Proposal identity.
    pub proposal_id: DottedId,
    /// Exact review decision identity.
    pub decision_id: DottedId,
    /// Proposer identity.
    pub proposer_id: DottedId,
    /// Source identity.
    pub source_id: DottedId,
    /// Stream identity.
    pub stream_id: DottedId,
    /// Accepted observation content digest.
    pub content_sha256: String,
    /// Envelope observation time.
    pub observed_at_ms: u64,
    /// Envelope expiry.
    pub expires_at_ms: u64,
    /// Proposal digest.
    pub proposal_sha256: String,
    /// Exact policy digest bound by review.
    pub reviewed_policy_sha256: String,
    /// Policy digest recomputed for this attempt.
    pub application_policy_sha256: String,
    /// Attempt time.
    pub attempted_at_ms: u64,
    /// Prior authority revision.
    pub prior_authority_revision: Revision,
    /// Resulting revision.
    pub resulting_authority_revision: Revision,
    /// Outcome.
    pub outcome: ManifoldStreamObservationReviewOutcome,
    /// Rejection reason.
    pub rejection_reason: Option<ManifoldStreamObservationRejectionReason>,
}

/// Manifold-owned application receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldStreamObservationApplicationReceipt {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Deterministic receipt identity.
    pub receipt_id: DottedId,
    /// Decision identity.
    pub decision_id: DottedId,
    /// Proposal identity.
    pub proposal_id: DottedId,
    /// Proposer identity.
    pub proposer_id: DottedId,
    /// Source identity.
    pub source_id: DottedId,
    /// Stream identity.
    pub stream_id: DottedId,
    /// Observation content digest.
    pub content_sha256: String,
    /// Envelope observation time.
    pub observed_at_ms: u64,
    /// Envelope expiry.
    pub expires_at_ms: u64,
    /// Proposal digest.
    pub proposal_sha256: String,
    /// Exact policy digest bound by review.
    pub reviewed_policy_sha256: String,
    /// Policy digest recomputed at application.
    pub application_policy_sha256: String,
    /// Application attempt time.
    pub applied_at_ms: u64,
    /// Whether state changed.
    pub applied: bool,
    /// Prior revision.
    pub prior_authority_revision: Revision,
    /// Resulting revision.
    pub resulting_authority_revision: Revision,
    /// Rejection when no state changed.
    pub rejection: Option<ManifoldStreamObservationRejection>,
    /// Application audit event.
    pub audit_event: ManifoldStreamObservationAuditEvent,
}

/// Restartable Runtime Host snapshot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldStreamObservationHostSnapshot {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Accepted state.
    pub accepted_state: ManifoldStreamObservationAcceptedState,
    /// Applied proposal identities.
    pub applied_proposal_ids: Vec<DottedId>,
    /// Applied proposal digests.
    pub applied_proposal_sha256: Vec<String>,
    /// Complete retained audit lineage.
    pub audit_events: Vec<ManifoldStreamObservationAuditEvent>,
}

/// Deterministic conformance input.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldStreamObservationConformanceCase {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Initial host snapshot.
    pub snapshot: ManifoldStreamObservationHostSnapshot,
    /// Review policy.
    pub policy: ManifoldStreamObservationReviewPolicy,
    /// Proposal.
    pub proposal: ManifoldStreamObservationProposal,
    /// Review/application time.
    pub now_ms: u64,
}

/// Deterministic conformance output.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldStreamObservationConformanceResult {
    /// Review decision.
    pub review: ManifoldStreamObservationReviewDecision,
    /// Application receipt.
    pub application: ManifoldStreamObservationApplicationReceipt,
    /// Final host snapshot.
    pub snapshot: ManifoldStreamObservationHostSnapshot,
}

/// Snapshot or conformance failure.
#[derive(Debug)]
pub enum ManifoldStreamObservationError {
    /// JSON encoding or decoding failed.
    Json(serde_json::Error),
    /// Snapshot invariants failed.
    InvalidSnapshot(&'static str),
    /// Conformance case schema is invalid.
    InvalidCase(&'static str),
}

impl fmt::Display for ManifoldStreamObservationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(formatter, "{error}"),
            Self::InvalidSnapshot(reason) => write!(formatter, "invalid snapshot: {reason}"),
            Self::InvalidCase(reason) => write!(formatter, "invalid conformance case: {reason}"),
        }
    }
}

impl std::error::Error for ManifoldStreamObservationError {}

impl From<serde_json::Error> for ManifoldStreamObservationError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

/// Restartable Manifold stream-observation authority host.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamObservationAuthorityHost {
    snapshot: ManifoldStreamObservationHostSnapshot,
}

impl Default for ManifoldStreamObservationAuthorityHost {
    fn default() -> Self {
        Self::new()
    }
}

impl ManifoldStreamObservationAuthorityHost {
    /// Creates an empty authority at revision one.
    #[must_use]
    pub fn new() -> Self {
        Self {
            snapshot: ManifoldStreamObservationHostSnapshot {
                schema_id: schema(SNAPSHOT_SCHEMA),
                accepted_state: ManifoldStreamObservationAcceptedState {
                    schema_id: schema(STATE_SCHEMA),
                    authority_revision: Revision::INITIAL,
                    streams: Vec::new(),
                },
                applied_proposal_ids: Vec::new(),
                applied_proposal_sha256: Vec::new(),
                audit_events: Vec::new(),
            },
        }
    }

    /// Returns the current snapshot.
    #[must_use]
    pub fn snapshot(&self) -> &ManifoldStreamObservationHostSnapshot {
        &self.snapshot
    }

    /// Serializes a stable pretty snapshot.
    ///
    /// # Errors
    ///
    /// Returns JSON serialization errors.
    pub fn snapshot_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.snapshot).map(|mut value| {
            value.push('\n');
            value
        })
    }

    /// Restarts from an exact validated snapshot.
    ///
    /// # Errors
    ///
    /// Rejects malformed JSON or damaged snapshot invariants.
    pub fn restart_from_json(value: &str) -> Result<Self, ManifoldStreamObservationError> {
        let snapshot: ManifoldStreamObservationHostSnapshot = serde_json::from_str(value)?;
        validate_snapshot(&snapshot)?;
        Ok(Self { snapshot })
    }

    /// Reviews without mutating host state.
    #[must_use]
    pub fn review(
        &self,
        policy: &ManifoldStreamObservationReviewPolicy,
        proposal: &ManifoldStreamObservationProposal,
        now_ms: u64,
    ) -> ManifoldStreamObservationReviewDecision {
        let digest = proposal_sha256(proposal);
        let policy_digest = policy_sha256(policy);
        let reason = validate_review(&self.snapshot, policy, proposal, &digest, now_ms).err();
        let outcome = if reason.is_some() {
            ManifoldStreamObservationReviewOutcome::Rejected
        } else {
            ManifoldStreamObservationReviewOutcome::Accepted
        };
        let revision = self.snapshot.accepted_state.authority_revision;
        let identity = [
            proposal.proposal_id.as_str(),
            digest.as_str(),
            policy_digest.as_str(),
            outcome_label(&outcome),
            reason_label(reason.as_ref()),
        ];
        let decision_id = artifact_id(
            "decision.stream-observation",
            &identity,
            revision,
            revision,
            now_ms,
        );
        let audit_event = ManifoldStreamObservationAuditEvent {
            schema_id: schema(AUDIT_SCHEMA),
            event_id: artifact_id(
                "audit.stream-observation.review",
                &identity,
                revision,
                revision,
                now_ms,
            ),
            phase: ManifoldStreamObservationAuditPhase::Review,
            proposal_id: proposal.proposal_id.clone(),
            decision_id: decision_id.clone(),
            proposer_id: proposal.proposer_id.clone(),
            source_id: proposal.source_id.clone(),
            stream_id: proposal.stream_id.clone(),
            content_sha256: proposal.content_sha256.clone(),
            observed_at_ms: proposal.observed_at_ms,
            expires_at_ms: proposal.expires_at_ms,
            proposal_sha256: digest.clone(),
            reviewed_policy_sha256: policy_digest.clone(),
            application_policy_sha256: policy_digest.clone(),
            attempted_at_ms: now_ms,
            prior_authority_revision: revision,
            resulting_authority_revision: revision,
            outcome: outcome.clone(),
            rejection_reason: reason.clone(),
        };
        ManifoldStreamObservationReviewDecision {
            schema_id: schema(REVIEW_SCHEMA),
            decision_id,
            proposal_id: proposal.proposal_id.clone(),
            proposal_sha256: digest.clone(),
            policy_id: policy.policy_id.clone(),
            policy_sha256: policy_digest,
            reviewed_authority_revision: revision,
            reviewed_at_ms: now_ms,
            outcome,
            rejection: reason.map(|reason| rejection(proposal, digest, revision, reason)),
            audit_event,
        }
    }

    /// Applies an accepted review after revalidating current state.
    ///
    /// Rejection never mutates the host.
    ///
    /// # Panics
    ///
    /// Panics only if an internal capacity invariant admits revision overflow.
    /// The preceding fail-closed capacity check makes that state unreachable.
    #[must_use]
    pub fn apply(
        &mut self,
        policy: &ManifoldStreamObservationReviewPolicy,
        proposal: &ManifoldStreamObservationProposal,
        decision: &ManifoldStreamObservationReviewDecision,
        now_ms: u64,
    ) -> ManifoldStreamObservationApplicationReceipt {
        let prior = self.revision();
        let digest = proposal_sha256(proposal);
        let application_policy_digest = policy_sha256(policy);
        let duplicate = self
            .snapshot
            .applied_proposal_ids
            .contains(&proposal.proposal_id)
            || self.snapshot.applied_proposal_sha256.contains(&digest);
        let mut reason =
            duplicate.then_some(ManifoldStreamObservationRejectionReason::DuplicateApplication);
        if reason.is_none() {
            reason = validate_decision(decision, policy, proposal, &digest, prior, now_ms).err();
        }
        if reason.is_none() {
            reason = validate_review(&self.snapshot, policy, proposal, &digest, now_ms).err();
        }
        if reason.is_none() && !self.has_capacity(proposal) {
            reason = Some(ManifoldStreamObservationRejectionReason::CapacityExceeded);
        }
        if let Some(reason) = reason {
            return receipt(
                decision,
                proposal,
                digest,
                application_policy_digest,
                prior,
                prior,
                now_ms,
                Some(reason),
            );
        }

        let resulting = prior
            .next()
            .expect("capacity validation rejects revision overflow");
        let accepted = ManifoldAcceptedStreamObservation {
            stream_id: proposal.stream_id.clone(),
            source_id: proposal.source_id.clone(),
            proposer_id: proposal.proposer_id.clone(),
            content_sha256: proposal.content_sha256.clone(),
            observed_at_ms: proposal.observed_at_ms,
            expires_at_ms: proposal.expires_at_ms,
            observation: proposal.observation.clone(),
        };
        if let Some(current) = self
            .snapshot
            .accepted_state
            .streams
            .iter_mut()
            .find(|current| current.stream_id == accepted.stream_id)
        {
            *current = accepted;
        } else {
            self.snapshot.accepted_state.streams.push(accepted);
            self.snapshot
                .accepted_state
                .streams
                .sort_by(|left, right| left.stream_id.cmp(&right.stream_id));
        }
        self.snapshot.accepted_state.authority_revision = resulting;
        self.snapshot
            .applied_proposal_ids
            .push(proposal.proposal_id.clone());
        self.snapshot.applied_proposal_sha256.push(digest.clone());
        let mut result = receipt(
            decision,
            proposal,
            digest,
            application_policy_digest,
            prior,
            resulting,
            now_ms,
            None,
        );
        self.snapshot.audit_events.push(result.audit_event.clone());
        result.applied = true;
        result
    }

    fn revision(&self) -> Revision {
        self.snapshot.accepted_state.authority_revision
    }

    fn has_capacity(&self, proposal: &ManifoldStreamObservationProposal) -> bool {
        self.revision().next().is_some()
            && self.snapshot.applied_proposal_ids.len() < MAX_APPLIED_PROPOSALS
            && self.snapshot.applied_proposal_sha256.len() < MAX_APPLIED_PROPOSALS
            && self.snapshot.audit_events.len() < MAX_AUDIT_EVENTS
            && (self.snapshot.accepted_state.streams.len() < MAX_ACCEPTED_STREAMS
                || self
                    .snapshot
                    .accepted_state
                    .streams
                    .iter()
                    .any(|stream| stream.stream_id == proposal.stream_id))
    }
}

/// Computes the canonical observation content digest.
#[must_use]
pub fn observation_content_sha256(observation: &ManifoldStreamObservation) -> String {
    sha256_json(observation)
}

/// Computes the exact proposal digest used by review/application.
#[must_use]
pub fn proposal_sha256(proposal: &ManifoldStreamObservationProposal) -> String {
    sha256_json(proposal)
}

/// Computes the digest of the exact review policy.
#[must_use]
pub fn policy_sha256(policy: &ManifoldStreamObservationReviewPolicy) -> String {
    sha256_json(policy)
}

/// Runs one deterministic review/application conformance case.
///
/// # Errors
///
/// Rejects an invalid case schema or any damaged snapshot invariant.
pub fn run_conformance_case(
    case: &ManifoldStreamObservationConformanceCase,
) -> Result<ManifoldStreamObservationConformanceResult, ManifoldStreamObservationError> {
    if case.schema_id.as_str() != CONFORMANCE_SCHEMA {
        return Err(ManifoldStreamObservationError::InvalidCase("schema"));
    }
    let snapshot_json = serde_json::to_string(&case.snapshot)?;
    let mut host = ManifoldStreamObservationAuthorityHost::restart_from_json(&snapshot_json)?;
    let review = host.review(&case.policy, &case.proposal, case.now_ms);
    let application = host.apply(&case.policy, &case.proposal, &review, case.now_ms);
    Ok(ManifoldStreamObservationConformanceResult {
        review,
        application,
        snapshot: host.snapshot().clone(),
    })
}

fn validate_review(
    snapshot: &ManifoldStreamObservationHostSnapshot,
    policy: &ManifoldStreamObservationReviewPolicy,
    proposal: &ManifoldStreamObservationProposal,
    digest: &str,
    now_ms: u64,
) -> Result<(), ManifoldStreamObservationRejectionReason> {
    if snapshot.schema_id.as_str() != SNAPSHOT_SCHEMA
        || snapshot.accepted_state.schema_id.as_str() != STATE_SCHEMA
        || policy.schema_id.as_str() != POLICY_SCHEMA
        || proposal.schema_id.as_str() != PROPOSAL_SCHEMA
        || proposal.observation.schema_id.as_str() != OBSERVATION_SCHEMA
    {
        return Err(ManifoldStreamObservationRejectionReason::SchemaMismatch);
    }
    if proposal.expected_authority_revision != snapshot.accepted_state.authority_revision {
        return Err(ManifoldStreamObservationRejectionReason::StaleAuthorityRevision);
    }
    if snapshot
        .applied_proposal_ids
        .contains(&proposal.proposal_id)
        || snapshot
            .applied_proposal_sha256
            .iter()
            .any(|applied| applied == digest)
    {
        return Err(ManifoldStreamObservationRejectionReason::Replay);
    }
    let binding = ManifoldStreamObservationBinding {
        proposer_id: proposal.proposer_id.clone(),
        source_id: proposal.source_id.clone(),
        stream_id: proposal.stream_id.clone(),
    };
    if !policy.allowed_bindings.contains(&binding) {
        return Err(ManifoldStreamObservationRejectionReason::BindingNotAllowed);
    }
    if !valid_sha256(&proposal.content_sha256)
        || proposal.content_sha256 != observation_content_sha256(&proposal.observation)
    {
        return Err(ManifoldStreamObservationRejectionReason::ContentDigestMismatch);
    }
    if proposal.observed_at_ms > now_ms
        || proposal.expires_at_ms <= now_ms
        || proposal.expires_at_ms <= proposal.observed_at_ms
    {
        return Err(ManifoldStreamObservationRejectionReason::Expired);
    }
    if proposal.expires_at_ms - proposal.observed_at_ms > MAX_TTL_MS {
        return Err(ManifoldStreamObservationRejectionReason::TtlExceeded);
    }
    if proposal.observation.channel_count == 0
        || proposal.observation.nominal_rate_millihz == Some(0)
        || proposal
            .observation
            .native_descriptor_sha256
            .as_ref()
            .is_some_and(|value| !valid_sha256(value))
    {
        return Err(ManifoldStreamObservationRejectionReason::InvalidObservation);
    }
    Ok(())
}

fn validate_decision(
    decision: &ManifoldStreamObservationReviewDecision,
    policy: &ManifoldStreamObservationReviewPolicy,
    proposal: &ManifoldStreamObservationProposal,
    digest: &str,
    revision: Revision,
    now_ms: u64,
) -> Result<(), ManifoldStreamObservationRejectionReason> {
    let policy_digest = policy_sha256(policy);
    let identity = [
        proposal.proposal_id.as_str(),
        digest,
        policy_digest.as_str(),
        outcome_label(&decision.outcome),
        reason_label(decision.rejection.as_ref().map(|value| &value.reason)),
    ];
    if decision.schema_id.as_str() != REVIEW_SCHEMA
        || decision.outcome != ManifoldStreamObservationReviewOutcome::Accepted
        || decision.rejection.is_some()
        || decision.decision_id
            != artifact_id(
                "decision.stream-observation",
                &identity,
                revision,
                revision,
                decision.reviewed_at_ms,
            )
        || decision.proposal_id != proposal.proposal_id
        || decision.proposal_sha256 != digest
        || decision.policy_id != policy.policy_id
        || decision.policy_sha256 != policy_digest
        || decision.reviewed_authority_revision != revision
        || decision.reviewed_at_ms > now_ms
        || decision.audit_event.schema_id.as_str() != AUDIT_SCHEMA
        || decision.audit_event.phase != ManifoldStreamObservationAuditPhase::Review
        || decision.audit_event.proposal_id != proposal.proposal_id
        || decision.audit_event.decision_id != decision.decision_id
        || decision.audit_event.proposer_id != proposal.proposer_id
        || decision.audit_event.source_id != proposal.source_id
        || decision.audit_event.stream_id != proposal.stream_id
        || decision.audit_event.content_sha256 != proposal.content_sha256
        || decision.audit_event.observed_at_ms != proposal.observed_at_ms
        || decision.audit_event.expires_at_ms != proposal.expires_at_ms
        || decision.audit_event.proposal_sha256 != digest
        || decision.audit_event.reviewed_policy_sha256 != policy_digest
        || decision.audit_event.application_policy_sha256 != policy_digest
        || decision.audit_event.attempted_at_ms != decision.reviewed_at_ms
        || decision.audit_event.event_id
            != artifact_id(
                "audit.stream-observation.review",
                &identity,
                revision,
                revision,
                decision.reviewed_at_ms,
            )
        || decision.audit_event.prior_authority_revision != revision
        || decision.audit_event.resulting_authority_revision != revision
        || decision.audit_event.outcome != ManifoldStreamObservationReviewOutcome::Accepted
        || decision.audit_event.rejection_reason.is_some()
    {
        return Err(ManifoldStreamObservationRejectionReason::DecisionMismatch);
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_snapshot(
    snapshot: &ManifoldStreamObservationHostSnapshot,
) -> Result<(), ManifoldStreamObservationError> {
    if snapshot.schema_id.as_str() != SNAPSHOT_SCHEMA
        || snapshot.accepted_state.schema_id.as_str() != STATE_SCHEMA
    {
        return Err(ManifoldStreamObservationError::InvalidSnapshot("schema"));
    }
    if snapshot.applied_proposal_ids.len() != snapshot.applied_proposal_sha256.len()
        || snapshot.applied_proposal_ids.len() > MAX_APPLIED_PROPOSALS
        || snapshot.audit_events.len() > MAX_AUDIT_EVENTS
        || snapshot.accepted_state.streams.len() > MAX_ACCEPTED_STREAMS
    {
        return Err(ManifoldStreamObservationError::InvalidSnapshot("capacity"));
    }
    if !unique(snapshot.applied_proposal_ids.iter().map(DottedId::as_str))
        || !unique(snapshot.applied_proposal_sha256.iter().map(String::as_str))
        || snapshot
            .applied_proposal_sha256
            .iter()
            .any(|digest| !valid_sha256(digest))
    {
        return Err(ManifoldStreamObservationError::InvalidSnapshot(
            "replay set",
        ));
    }
    if !snapshot
        .accepted_state
        .streams
        .windows(2)
        .all(|pair| pair[0].stream_id < pair[1].stream_id)
    {
        return Err(ManifoldStreamObservationError::InvalidSnapshot(
            "stream order",
        ));
    }
    if snapshot.accepted_state.streams.iter().any(|stream| {
        stream.observation.schema_id.as_str() != OBSERVATION_SCHEMA
            || stream.content_sha256 != observation_content_sha256(&stream.observation)
            || stream.expires_at_ms <= stream.observed_at_ms
            || stream.expires_at_ms - stream.observed_at_ms > MAX_TTL_MS
            || stream.observation.channel_count == 0
            || stream.observation.nominal_rate_millihz == Some(0)
            || stream
                .observation
                .native_descriptor_sha256
                .as_ref()
                .is_some_and(|value| !valid_sha256(value))
    }) {
        return Err(ManifoldStreamObservationError::InvalidSnapshot(
            "accepted stream",
        ));
    }
    let expected_revision = 1_u64
        .checked_add(u64::try_from(snapshot.audit_events.len()).unwrap_or(u64::MAX))
        .ok_or(ManifoldStreamObservationError::InvalidSnapshot(
            "revision overflow",
        ))?;
    if snapshot.accepted_state.authority_revision.get() != expected_revision
        || snapshot
            .audit_events
            .iter()
            .enumerate()
            .any(|(index, event)| {
                event.schema_id.as_str() != AUDIT_SCHEMA
                    || event.phase != ManifoldStreamObservationAuditPhase::Application
                    || event.outcome != ManifoldStreamObservationReviewOutcome::Accepted
                    || event.rejection_reason.is_some()
                    || !valid_sha256(&event.content_sha256)
                    || event.expires_at_ms <= event.observed_at_ms
                    || event.expires_at_ms - event.observed_at_ms > MAX_TTL_MS
                    || event.observed_at_ms > event.attempted_at_ms
                    || event.attempted_at_ms >= event.expires_at_ms
                    || !valid_sha256(&event.proposal_sha256)
                    || !valid_sha256(&event.reviewed_policy_sha256)
                    || !valid_sha256(&event.application_policy_sha256)
                    || event.reviewed_policy_sha256 != event.application_policy_sha256
                    || event.event_id != application_event_id(event)
                    || snapshot.applied_proposal_ids.get(index) != Some(&event.proposal_id)
                    || snapshot.applied_proposal_sha256.get(index) != Some(&event.proposal_sha256)
                    || event.prior_authority_revision.get() != index as u64 + 1
                    || event.resulting_authority_revision.get() != index as u64 + 2
            })
    {
        return Err(ManifoldStreamObservationError::InvalidSnapshot(
            "audit lineage",
        ));
    }
    if !unique(
        snapshot
            .audit_events
            .iter()
            .map(|event| event.event_id.as_str()),
    ) {
        return Err(ManifoldStreamObservationError::InvalidSnapshot("audit ids"));
    }
    let accepted_stream_ids: BTreeSet<_> = snapshot
        .accepted_state
        .streams
        .iter()
        .map(|stream| stream.stream_id.as_str())
        .collect();
    let audited_stream_ids: BTreeSet<_> = snapshot
        .audit_events
        .iter()
        .map(|event| event.stream_id.as_str())
        .collect();
    if accepted_stream_ids != audited_stream_ids {
        return Err(ManifoldStreamObservationError::InvalidSnapshot(
            "accepted stream set",
        ));
    }
    if snapshot.accepted_state.streams.iter().any(|stream| {
        snapshot
            .audit_events
            .iter()
            .rev()
            .find(|event| event.stream_id == stream.stream_id)
            .map_or(true, |event| {
                event.source_id != stream.source_id
                    || event.proposer_id != stream.proposer_id
                    || event.content_sha256 != stream.content_sha256
                    || event.observed_at_ms != stream.observed_at_ms
                    || event.expires_at_ms != stream.expires_at_ms
            })
    }) {
        return Err(ManifoldStreamObservationError::InvalidSnapshot(
            "accepted audit correlation",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn receipt(
    decision: &ManifoldStreamObservationReviewDecision,
    proposal: &ManifoldStreamObservationProposal,
    digest: String,
    application_policy_digest: String,
    prior: Revision,
    resulting: Revision,
    applied_at_ms: u64,
    reason: Option<ManifoldStreamObservationRejectionReason>,
) -> ManifoldStreamObservationApplicationReceipt {
    let rejection = reason
        .clone()
        .map(|reason| rejection(proposal, digest.clone(), prior, reason));
    let outcome = if rejection.is_some() {
        ManifoldStreamObservationReviewOutcome::Rejected
    } else {
        ManifoldStreamObservationReviewOutcome::Accepted
    };
    let identity = [
        proposal.proposal_id.as_str(),
        decision.decision_id.as_str(),
        proposal.proposer_id.as_str(),
        proposal.source_id.as_str(),
        proposal.stream_id.as_str(),
        proposal.content_sha256.as_str(),
        &proposal.observed_at_ms.to_string(),
        &proposal.expires_at_ms.to_string(),
        digest.as_str(),
        decision.policy_sha256.as_str(),
        application_policy_digest.as_str(),
        outcome_label(&outcome),
        reason_label(reason.as_ref()),
    ];
    let audit_event = ManifoldStreamObservationAuditEvent {
        schema_id: schema(AUDIT_SCHEMA),
        event_id: artifact_id(
            "audit.stream-observation.application",
            &identity,
            prior,
            resulting,
            applied_at_ms,
        ),
        phase: ManifoldStreamObservationAuditPhase::Application,
        proposal_id: proposal.proposal_id.clone(),
        decision_id: decision.decision_id.clone(),
        proposer_id: proposal.proposer_id.clone(),
        source_id: proposal.source_id.clone(),
        stream_id: proposal.stream_id.clone(),
        content_sha256: proposal.content_sha256.clone(),
        observed_at_ms: proposal.observed_at_ms,
        expires_at_ms: proposal.expires_at_ms,
        proposal_sha256: digest.clone(),
        reviewed_policy_sha256: decision.policy_sha256.clone(),
        application_policy_sha256: application_policy_digest.clone(),
        attempted_at_ms: applied_at_ms,
        prior_authority_revision: prior,
        resulting_authority_revision: resulting,
        outcome,
        rejection_reason: reason,
    };
    ManifoldStreamObservationApplicationReceipt {
        schema_id: schema(RECEIPT_SCHEMA),
        receipt_id: artifact_id(
            "receipt.stream-observation",
            &identity,
            prior,
            resulting,
            applied_at_ms,
        ),
        decision_id: decision.decision_id.clone(),
        proposal_id: proposal.proposal_id.clone(),
        proposer_id: proposal.proposer_id.clone(),
        source_id: proposal.source_id.clone(),
        stream_id: proposal.stream_id.clone(),
        content_sha256: proposal.content_sha256.clone(),
        observed_at_ms: proposal.observed_at_ms,
        expires_at_ms: proposal.expires_at_ms,
        proposal_sha256: digest,
        reviewed_policy_sha256: decision.policy_sha256.clone(),
        application_policy_sha256: application_policy_digest,
        applied_at_ms,
        applied: rejection.is_none(),
        prior_authority_revision: prior,
        resulting_authority_revision: resulting,
        rejection,
        audit_event,
    }
}

fn rejection(
    proposal: &ManifoldStreamObservationProposal,
    digest: String,
    revision: Revision,
    reason: ManifoldStreamObservationRejectionReason,
) -> ManifoldStreamObservationRejection {
    ManifoldStreamObservationRejection {
        schema_id: schema(REJECTION_SCHEMA),
        proposal_id: proposal.proposal_id.clone(),
        proposal_sha256: digest,
        authority_revision: revision,
        reason,
    }
}

fn sha256_json<T: Serialize>(value: &T) -> String {
    let bytes = serde_json::to_vec(value).expect("typed contracts serialize");
    let digest = Sha256::digest(bytes);
    format!("sha256:{}", lower_hex(&digest))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn lower_hex(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(value, "{byte:02x}").expect("writing to String cannot fail");
    }
    value
}

fn unique<'a>(mut values: impl Iterator<Item = &'a str>) -> bool {
    let mut seen = BTreeSet::new();
    values.all(|value| seen.insert(value))
}

fn schema(value: &str) -> SchemaId {
    SchemaId::new(value).expect("constant schema id is valid")
}

fn artifact_id(
    prefix: &str,
    identity: &[&str],
    prior: Revision,
    resulting: Revision,
    attempted_at_ms: u64,
) -> DottedId {
    let stable = format!(
        "{}\u{1f}{}\u{1f}{}\u{1f}{}",
        identity.join("\u{1f}"),
        prior.get(),
        resulting.get(),
        attempted_at_ms
    );
    let digest = lower_hex(&Sha256::digest(stable.as_bytes()));
    DottedId::new(format!("{prefix}.{}", &digest[..24])).expect("derived dotted id is valid")
}

fn application_event_id(event: &ManifoldStreamObservationAuditEvent) -> DottedId {
    let identity = [
        event.proposal_id.as_str(),
        event.decision_id.as_str(),
        event.proposer_id.as_str(),
        event.source_id.as_str(),
        event.stream_id.as_str(),
        event.content_sha256.as_str(),
        &event.observed_at_ms.to_string(),
        &event.expires_at_ms.to_string(),
        event.proposal_sha256.as_str(),
        event.reviewed_policy_sha256.as_str(),
        event.application_policy_sha256.as_str(),
        outcome_label(&event.outcome),
        reason_label(event.rejection_reason.as_ref()),
    ];
    artifact_id(
        "audit.stream-observation.application",
        &identity,
        event.prior_authority_revision,
        event.resulting_authority_revision,
        event.attempted_at_ms,
    )
}

fn outcome_label(outcome: &ManifoldStreamObservationReviewOutcome) -> &'static str {
    match outcome {
        ManifoldStreamObservationReviewOutcome::Accepted => "accepted",
        ManifoldStreamObservationReviewOutcome::Rejected => "rejected",
    }
}

fn reason_label(reason: Option<&ManifoldStreamObservationRejectionReason>) -> &'static str {
    match reason {
        None => "none",
        Some(reason) => match reason {
            ManifoldStreamObservationRejectionReason::SchemaMismatch => "schema-mismatch",
            ManifoldStreamObservationRejectionReason::StaleAuthorityRevision => "stale-revision",
            ManifoldStreamObservationRejectionReason::Replay => "replay",
            ManifoldStreamObservationRejectionReason::BindingNotAllowed => "binding",
            ManifoldStreamObservationRejectionReason::ContentDigestMismatch => "digest",
            ManifoldStreamObservationRejectionReason::Expired => "expired",
            ManifoldStreamObservationRejectionReason::TtlExceeded => "ttl",
            ManifoldStreamObservationRejectionReason::InvalidObservation => "observation",
            ManifoldStreamObservationRejectionReason::CapacityExceeded => "capacity",
            ManifoldStreamObservationRejectionReason::DecisionMismatch => "decision",
            ManifoldStreamObservationRejectionReason::DuplicateApplication => "duplicate",
        },
    }
}

#[cfg(test)]
mod tests;
