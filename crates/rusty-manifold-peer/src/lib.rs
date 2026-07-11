//! Manifold-owned peer identity and accepted low-rate peer-status authority.

mod direct_lane_lease;
mod enrollment;
mod peer_mesh;
mod peer_session;

pub use direct_lane_lease::*;
pub use enrollment::*;
pub use peer_mesh::*;
pub use peer_session::*;

use rusty_manifold_model::{DottedId, Revision, SchemaId};
use serde::{Deserialize, Serialize};

/// Peer identity schema.
pub const PEER_IDENTITY_SCHEMA: &str = "rusty.manifold.peer.identity.v1";
/// Peer status schema.
pub const PEER_STATUS_SCHEMA: &str = "rusty.manifold.peer.status.v1";
/// Peer status proposal schema.
pub const PEER_PROPOSAL_SCHEMA: &str = "rusty.manifold.peer.status_proposal.v1";
/// Accepted peer-state snapshot schema.
pub const PEER_SNAPSHOT_SCHEMA: &str = "rusty.manifold.peer.accepted_state.v1";
/// Peer review case schema used by deterministic fixtures.
pub const PEER_REVIEW_CASE_SCHEMA: &str = "rusty.manifold.peer.review_case.v1";
/// Peer decision schema.
pub const PEER_DECISION_SCHEMA: &str = "rusty.manifold.peer.decision.v1";
/// Peer rejection schema.
pub const PEER_REJECTION_SCHEMA: &str = "rusty.manifold.peer.rejection.v1";
/// Peer audit event schema.
pub const PEER_AUDIT_SCHEMA: &str = "rusty.manifold.peer.audit_event.v1";
/// Peer application receipt schema.
pub const PEER_APPLICATION_SCHEMA: &str = "rusty.manifold.peer.application_receipt.v1";

const MAX_STATUS_TTL_MS: u64 = 300_000;
const MAX_CAPABILITIES: usize = 64;

/// Bounded peer roles that do not grant command authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldPeerRole {
    /// May publish advisory observations.
    Observer,
    /// May participate in authenticated rendezvous.
    Rendezvous,
    /// May consume broker-owned streams after separate admission.
    BrokerConsumer,
}

/// Stable peer identity proposed to Manifold.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPeerIdentity {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Stable peer identifier.
    pub peer_id: DottedId,
    /// Public-key fingerprint identifier; never raw key material.
    pub key_fingerprint: DottedId,
    /// Trust-domain identifier.
    pub trust_domain: DottedId,
    /// Bounded non-command roles.
    pub roles: Vec<ManifoldPeerRole>,
}

/// Low-rate advisory peer status proposed to Manifold.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPeerStatus {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Identity this status describes.
    pub peer_id: DottedId,
    /// Monotonic status revision for this peer.
    pub status_revision: Revision,
    /// Observation time in the proposal time domain.
    pub observed_at_ms: u64,
    /// Expiry time in the same time domain.
    pub expires_at_ms: u64,
    /// Advisory availability class.
    pub availability: ManifoldPeerAvailability,
    /// Bounded capability identifiers, never payloads.
    pub capability_ids: Vec<DottedId>,
}

/// Advisory peer availability.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldPeerAvailability {
    /// Peer was observed ready for separately authorized work.
    Ready,
    /// Peer was observed degraded.
    Degraded,
    /// Peer was observed unavailable.
    Unavailable,
}

/// Payload-plane declaration for a peer proposal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldPeerPayloadClass {
    /// Accepted low-rate descriptor class.
    LowRateDescriptor,
    /// Explicitly rejected high-rate telemetry class.
    HighRateTelemetry,
    /// Explicitly rejected media payload class.
    Media,
}

/// Revisioned peer-status proposal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPeerStatusProposal {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Idempotency identity for this proposal.
    pub proposal_id: DottedId,
    /// Current authority revision expected by the proposer.
    pub expected_authority_revision: Revision,
    /// Identity of the proposing adapter or operator route.
    pub proposer_id: DottedId,
    /// Proposed stable peer identity.
    pub identity: ManifoldPeerIdentity,
    /// Proposed low-rate status.
    pub status: ManifoldPeerStatus,
    /// Declared payload plane.
    pub payload_class: ManifoldPeerPayloadClass,
}

/// Accepted peer state owned by Manifold authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldAcceptedPeerState {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Current Manifold authority revision.
    pub authority_revision: Revision,
    /// Accepted peer records.
    pub peers: Vec<ManifoldAcceptedPeer>,
    /// Applied proposal ids retained for replay rejection.
    pub applied_proposal_ids: Vec<DottedId>,
}

/// Accepted identity plus its latest low-rate status.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldAcceptedPeer {
    /// Accepted identity.
    pub identity: ManifoldPeerIdentity,
    /// Latest accepted status.
    pub status: ManifoldPeerStatus,
}

/// Fixture envelope for deterministic peer review.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPeerReviewCase {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Stable case identifier.
    pub case_id: DottedId,
    /// Current accepted state.
    pub current_state: ManifoldAcceptedPeerState,
    /// Proposed mutation.
    pub proposal: ManifoldPeerStatusProposal,
    /// Trusted public-key fingerprints.
    pub trusted_key_fingerprints: Vec<DottedId>,
    /// Review time.
    pub now_ms: u64,
    /// Expected decision outcome.
    pub expected_outcome: ManifoldPeerDecisionOutcome,
}

/// Deterministic peer decision outcome.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldPeerDecisionOutcome {
    /// Proposal may be applied.
    Accepted,
    /// Proposal must not mutate accepted state.
    Rejected,
}

/// Machine-readable peer rejection reason.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldPeerRejectionReason {
    /// Proposal expected an older or newer authority revision.
    StaleAuthorityRevision,
    /// Proposal id was already applied.
    ReplayedProposal,
    /// Public-key fingerprint is outside the current trust input.
    UntrustedIdentity,
    /// Identity and status refer to different peers.
    PeerIdentityMismatch,
    /// Status revision did not advance.
    StaleStatusRevision,
    /// Observation is from the future or already expired.
    StaleObservation,
    /// Status lifetime exceeds the bounded low-rate policy.
    StatusTtlExceeded,
    /// Existing identity roles were escalated by the proposal.
    RoleEscalation,
    /// Proposal declared high-rate or media payloads.
    HighRatePayload,
    /// Capability descriptor count exceeded its bound.
    CapabilityLimitExceeded,
    /// Schema identity was inconsistent.
    SchemaMismatch,
}

/// Machine-readable rejection that leaves accepted state unchanged.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPeerRejection {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Rejected proposal identity.
    pub proposal_id: DottedId,
    /// Peer identity named by the proposal.
    pub peer_id: DottedId,
    /// Authority revision that performed the review.
    pub authority_revision: Revision,
    /// Stable rejection reason.
    pub reason: ManifoldPeerRejectionReason,
}

/// Review decision plus accepted state or rejection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPeerDecision {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Derived decision identifier.
    pub decision_id: DottedId,
    /// Reviewed proposal identifier.
    pub proposal_id: DottedId,
    /// Outcome.
    pub outcome: ManifoldPeerDecisionOutcome,
    /// Candidate accepted state when accepted.
    pub accepted_state: Option<ManifoldAcceptedPeerState>,
    /// Machine-readable rejection when rejected.
    pub rejection: Option<ManifoldPeerRejection>,
    /// Matching audit event.
    pub audit_event: ManifoldPeerAuditEvent,
}

/// Peer decision audit event.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPeerAuditEvent {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Stable audit event identifier.
    pub event_id: DottedId,
    /// Proposal identity.
    pub proposal_id: DottedId,
    /// Peer identity.
    pub peer_id: DottedId,
    /// Prior authority revision.
    pub prior_authority_revision: Revision,
    /// Resulting authority revision; unchanged for rejection.
    pub resulting_authority_revision: Revision,
    /// Decision outcome.
    pub outcome: ManifoldPeerDecisionOutcome,
    /// Rejection reason when applicable.
    pub rejection_reason: Option<ManifoldPeerRejectionReason>,
}

/// Application receipt proving whether accepted state changed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPeerApplicationReceipt {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Derived receipt identifier.
    pub receipt_id: DottedId,
    /// Decision identifier.
    pub decision_id: DottedId,
    /// Applied proposal identifier.
    pub proposal_id: DottedId,
    /// Whether accepted state changed.
    pub applied: bool,
    /// Prior authority revision.
    pub prior_authority_revision: Revision,
    /// Resulting authority revision.
    pub resulting_authority_revision: Revision,
}

/// Reviews and applies one peer proposal against a current snapshot.
#[must_use]
pub fn review_and_apply_peer_proposal(
    case: &ManifoldPeerReviewCase,
) -> (ManifoldPeerDecision, ManifoldPeerApplicationReceipt) {
    let rejection = validate_case(case).err();
    let prior = case.current_state.authority_revision;
    let accepted_state = rejection.is_none().then(|| apply_proposal(case));
    let resulting = accepted_state
        .as_ref()
        .map_or(prior, |state| state.authority_revision);
    let outcome = if rejection.is_none() {
        ManifoldPeerDecisionOutcome::Accepted
    } else {
        ManifoldPeerDecisionOutcome::Rejected
    };
    let decision_id = derived_id("decision.peer", &case.proposal.proposal_id);
    let audit = ManifoldPeerAuditEvent {
        schema_id: schema_id(PEER_AUDIT_SCHEMA),
        event_id: derived_id("audit.peer", &case.proposal.proposal_id),
        proposal_id: case.proposal.proposal_id.clone(),
        peer_id: case.proposal.identity.peer_id.clone(),
        prior_authority_revision: prior,
        resulting_authority_revision: resulting,
        outcome: outcome.clone(),
        rejection_reason: rejection.clone(),
    };
    let decision = ManifoldPeerDecision {
        schema_id: schema_id(PEER_DECISION_SCHEMA),
        decision_id: decision_id.clone(),
        proposal_id: case.proposal.proposal_id.clone(),
        outcome,
        accepted_state,
        rejection: rejection.map(|reason| ManifoldPeerRejection {
            schema_id: schema_id(PEER_REJECTION_SCHEMA),
            proposal_id: case.proposal.proposal_id.clone(),
            peer_id: case.proposal.identity.peer_id.clone(),
            authority_revision: prior,
            reason,
        }),
        audit_event: audit,
    };
    let receipt = ManifoldPeerApplicationReceipt {
        schema_id: schema_id(PEER_APPLICATION_SCHEMA),
        receipt_id: derived_id("receipt.peer", &case.proposal.proposal_id),
        decision_id,
        proposal_id: case.proposal.proposal_id.clone(),
        applied: decision.outcome == ManifoldPeerDecisionOutcome::Accepted,
        prior_authority_revision: prior,
        resulting_authority_revision: resulting,
    };
    (decision, receipt)
}

fn validate_case(case: &ManifoldPeerReviewCase) -> Result<(), ManifoldPeerRejectionReason> {
    if case.schema_id.as_str() != PEER_REVIEW_CASE_SCHEMA
        || case.current_state.schema_id.as_str() != PEER_SNAPSHOT_SCHEMA
        || case.proposal.schema_id.as_str() != PEER_PROPOSAL_SCHEMA
        || case.proposal.identity.schema_id.as_str() != PEER_IDENTITY_SCHEMA
        || case.proposal.status.schema_id.as_str() != PEER_STATUS_SCHEMA
    {
        return Err(ManifoldPeerRejectionReason::SchemaMismatch);
    }
    if case.proposal.expected_authority_revision != case.current_state.authority_revision {
        return Err(ManifoldPeerRejectionReason::StaleAuthorityRevision);
    }
    if case
        .current_state
        .applied_proposal_ids
        .contains(&case.proposal.proposal_id)
    {
        return Err(ManifoldPeerRejectionReason::ReplayedProposal);
    }
    if !case
        .trusted_key_fingerprints
        .contains(&case.proposal.identity.key_fingerprint)
    {
        return Err(ManifoldPeerRejectionReason::UntrustedIdentity);
    }
    if case.proposal.identity.peer_id != case.proposal.status.peer_id {
        return Err(ManifoldPeerRejectionReason::PeerIdentityMismatch);
    }
    if case.proposal.payload_class != ManifoldPeerPayloadClass::LowRateDescriptor {
        return Err(ManifoldPeerRejectionReason::HighRatePayload);
    }
    if case.proposal.status.capability_ids.len() > MAX_CAPABILITIES {
        return Err(ManifoldPeerRejectionReason::CapabilityLimitExceeded);
    }
    if case.proposal.status.observed_at_ms > case.now_ms
        || case.proposal.status.expires_at_ms <= case.now_ms
    {
        return Err(ManifoldPeerRejectionReason::StaleObservation);
    }
    if case
        .proposal
        .status
        .expires_at_ms
        .saturating_sub(case.proposal.status.observed_at_ms)
        > MAX_STATUS_TTL_MS
    {
        return Err(ManifoldPeerRejectionReason::StatusTtlExceeded);
    }
    if let Some(current) = case
        .current_state
        .peers
        .iter()
        .find(|peer| peer.identity.peer_id == case.proposal.identity.peer_id)
    {
        if case.proposal.status.status_revision <= current.status.status_revision {
            return Err(ManifoldPeerRejectionReason::StaleStatusRevision);
        }
        if case
            .proposal
            .identity
            .roles
            .iter()
            .any(|role| !current.identity.roles.contains(role))
        {
            return Err(ManifoldPeerRejectionReason::RoleEscalation);
        }
    }
    Ok(())
}

fn apply_proposal(case: &ManifoldPeerReviewCase) -> ManifoldAcceptedPeerState {
    let mut state = case.current_state.clone();
    state.authority_revision = state
        .authority_revision
        .next()
        .expect("authority revision must advance");
    let peer = ManifoldAcceptedPeer {
        identity: case.proposal.identity.clone(),
        status: case.proposal.status.clone(),
    };
    if let Some(existing) = state
        .peers
        .iter_mut()
        .find(|existing| existing.identity.peer_id == peer.identity.peer_id)
    {
        *existing = peer;
    } else {
        state.peers.push(peer);
        state
            .peers
            .sort_by(|left, right| left.identity.peer_id.cmp(&right.identity.peer_id));
    }
    state
        .applied_proposal_ids
        .push(case.proposal.proposal_id.clone());
    state
}

fn schema_id(value: &str) -> SchemaId {
    SchemaId::new(value).expect("static schema id must be valid")
}

fn derived_id(prefix: &str, proposal_id: &DottedId) -> DottedId {
    DottedId::new(format!("{prefix}.{}", proposal_id.as_str())).expect("derived id must be valid")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn case(path: &str) -> ManifoldPeerReviewCase {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(path);
        serde_json::from_str(&std::fs::read_to_string(root).expect("fixture must load"))
            .expect("fixture must deserialize")
    }

    #[test]
    fn accepted_case_advances_state_and_emits_audit_and_application_receipt() {
        let case = case("fixtures/peer-review/synthetic-peer-accepted-review.json");
        let (decision, receipt) = review_and_apply_peer_proposal(&case);
        assert_eq!(decision.outcome, ManifoldPeerDecisionOutcome::Accepted);
        assert!(decision.rejection.is_none());
        assert_eq!(
            decision
                .accepted_state
                .as_ref()
                .expect("state")
                .authority_revision
                .get(),
            2
        );
        assert!(receipt.applied);
        assert_eq!(receipt.resulting_authority_revision.get(), 2);
        assert_eq!(
            decision.audit_event.resulting_authority_revision,
            receipt.resulting_authority_revision
        );
    }

    #[test]
    fn damaged_review_cases_reject_without_mutation() {
        for (path, reason) in [
            (
                "fixtures/damaged/peer-status-stale-authority.json",
                ManifoldPeerRejectionReason::StaleAuthorityRevision,
            ),
            (
                "fixtures/damaged/peer-status-replayed-proposal.json",
                ManifoldPeerRejectionReason::ReplayedProposal,
            ),
            (
                "fixtures/damaged/peer-status-untrusted-identity.json",
                ManifoldPeerRejectionReason::UntrustedIdentity,
            ),
            (
                "fixtures/damaged/peer-status-stale-observation.json",
                ManifoldPeerRejectionReason::StaleObservation,
            ),
            (
                "fixtures/damaged/peer-status-high-rate-payload.json",
                ManifoldPeerRejectionReason::HighRatePayload,
            ),
            (
                "fixtures/damaged/peer-status-role-escalation.json",
                ManifoldPeerRejectionReason::RoleEscalation,
            ),
            (
                "fixtures/damaged/peer-status-stale-status-revision.json",
                ManifoldPeerRejectionReason::StaleStatusRevision,
            ),
        ] {
            let case = case(path);
            let (decision, receipt) = review_and_apply_peer_proposal(&case);
            assert_eq!(
                decision.outcome,
                ManifoldPeerDecisionOutcome::Rejected,
                "{path}"
            );
            assert_eq!(
                decision
                    .rejection
                    .as_ref()
                    .map(|value| value.reason.clone()),
                Some(reason),
                "{path}"
            );
            assert!(decision.accepted_state.is_none(), "{path}");
            assert!(!receipt.applied, "{path}");
            assert_eq!(
                receipt.prior_authority_revision, receipt.resulting_authority_revision,
                "{path}"
            );
        }
    }

    #[test]
    fn advisory_command_and_unknown_fields_fail_deserialization() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("fixtures/damaged/peer-status-advisory-command.json");
        let text = std::fs::read_to_string(root).expect("fixture must load");
        assert!(serde_json::from_str::<ManifoldPeerReviewCase>(&text).is_err());
    }

    #[test]
    fn public_peer_fixtures_deserialize_into_each_contract() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        macro_rules! parse {
            ($path:literal, $kind:ty) => {{
                let text = std::fs::read_to_string(root.join($path)).expect("fixture must load");
                serde_json::from_str::<$kind>(&text).expect("fixture must deserialize")
            }};
        }
        let _: ManifoldPeerIdentity = parse!(
            "fixtures/peer/synthetic-peer-identity.json",
            ManifoldPeerIdentity
        );
        let _: ManifoldPeerStatus = parse!(
            "fixtures/peer/synthetic-peer-status.json",
            ManifoldPeerStatus
        );
        let _: ManifoldPeerStatusProposal = parse!(
            "fixtures/peer/synthetic-peer-proposal.json",
            ManifoldPeerStatusProposal
        );
        let _: ManifoldAcceptedPeerState = parse!(
            "fixtures/peer/synthetic-peer-accepted-state.json",
            ManifoldAcceptedPeerState
        );
        let _: ManifoldPeerDecision = parse!(
            "fixtures/peer/synthetic-peer-decision.json",
            ManifoldPeerDecision
        );
        let _: ManifoldPeerRejection = parse!(
            "fixtures/peer/synthetic-peer-rejection.json",
            ManifoldPeerRejection
        );
        let _: ManifoldPeerAuditEvent = parse!(
            "fixtures/peer/synthetic-peer-audit-event.json",
            ManifoldPeerAuditEvent
        );
        let _: ManifoldPeerApplicationReceipt = parse!(
            "fixtures/peer/synthetic-peer-application-receipt.json",
            ManifoldPeerApplicationReceipt
        );
    }
}
