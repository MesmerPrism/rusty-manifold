//! Manifold-owned bounded N-peer membership and route scheduling authority.

use std::collections::{BTreeMap, BTreeSet};

use rusty_manifold_model::{DottedId, Revision, SchemaId};
use serde::{Deserialize, Serialize};

use crate::{
    ManifoldAcceptedPeerState, ManifoldPeerAvailability, ManifoldPeerRole, PEER_SNAPSHOT_SCHEMA,
};

/// N-peer mesh proposal schema.
pub const PEER_MESH_PROPOSAL_SCHEMA: &str = "rusty.manifold.peer.mesh_proposal.v1";
/// N-peer mesh state schema.
pub const PEER_MESH_STATE_SCHEMA: &str = "rusty.manifold.peer.mesh_state.v1";
/// N-peer mesh review schema.
pub const PEER_MESH_REVIEW_SCHEMA: &str = "rusty.manifold.peer.mesh_review.v1";
/// N-peer mesh decision schema.
pub const PEER_MESH_DECISION_SCHEMA: &str = "rusty.manifold.peer.mesh_decision.v1";
/// N-peer mesh audit schema.
pub const PEER_MESH_AUDIT_SCHEMA: &str = "rusty.manifold.peer.mesh_audit_event.v1";
/// N-peer mesh mutation receipt schema.
pub const PEER_MESH_MUTATION_SCHEMA: &str = "rusty.manifold.peer.mesh_mutation_receipt.v1";
/// Direct pairwise data-plane route contract.
pub const DIRECT_P2P_ROUTE_CONTRACT: &str = "rusty.quest.direct_p2p_socket_route.v1";
/// Advisory status-only route contract.
pub const ADVISORY_STATUS_ROUTE_CONTRACT: &str = "rusty.quest.advisory_status_route.v1";

const MIN_MESH_PEERS: usize = 3;
const MAX_MESH_PEERS: usize = 32;
const MAX_ROUTE_CANDIDATES: usize = 256;

/// Route class proposed to the mesh authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldPeerMeshRouteClass {
    /// Authenticated pairwise route eligible for direct media-lane scheduling.
    DirectPairwise,
    /// Low-rate advisory route; never eligible for media.
    AdvisoryStatusOnly,
}

/// Bounded route candidate. It contains no endpoint or payload bytes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPeerMeshRouteCandidate {
    /// Stable candidate id.
    pub candidate_id: DottedId,
    /// First peer endpoint identity.
    pub source_peer_id: DottedId,
    /// Second peer endpoint identity.
    pub target_peer_id: DottedId,
    /// Route class.
    pub route_class: ManifoldPeerMeshRouteClass,
    /// Versioned route contract reference.
    pub route_contract_id: DottedId,
    /// Whether independent authentication evidence admitted this route.
    pub authenticated: bool,
    /// Bounded observed latency used only for deterministic ranking.
    pub observed_latency_ms: u32,
    /// Bounded hop count used after latency.
    pub hop_count: u8,
    /// Expiry of the route observation.
    pub evidence_expires_at_ms: u64,
}

/// Proposed bounded N-peer membership and route-candidate view.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPeerMeshProposal {
    /// Schema id.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Idempotency id.
    pub proposal_id: DottedId,
    /// Mesh id.
    pub mesh_id: DottedId,
    /// Expected mesh authority revision.
    pub expected_authority_revision: Revision,
    /// Trusted adapter/proposer id.
    pub proposer_id: DottedId,
    /// Deterministic leadership epoch.
    pub authority_epoch: u64,
    /// Coordinator; must be the lexicographically first member.
    pub coordinator_peer_id: DottedId,
    /// Unique sorted member ids.
    pub member_peer_ids: Vec<DottedId>,
    /// Bounded route candidates.
    pub route_candidates: Vec<ManifoldPeerMeshRouteCandidate>,
}

/// Accepted member status reference copied from Manifold peer authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldAcceptedMeshMember {
    /// Peer id.
    pub peer_id: DottedId,
    /// Accepted per-peer status revision.
    pub status_revision: Revision,
    /// Status expiry.
    pub expires_at_ms: u64,
}

/// Ranked direct pairwise route selected by Manifold.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPeerMeshSelectedRoute {
    /// Selected candidate id.
    pub candidate_id: DottedId,
    /// Canonical lower peer id.
    pub first_peer_id: DottedId,
    /// Canonical upper peer id.
    pub second_peer_id: DottedId,
    /// Direct route contract.
    pub route_contract_id: DottedId,
    /// Rank latency.
    pub observed_latency_ms: u32,
    /// Rank hop count.
    pub hop_count: u8,
    /// Pairwise direct media lane is allowed after separate session/media admission.
    pub direct_media_lane_eligible: bool,
}

/// Manifold-owned accepted N-peer state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPeerMeshState {
    /// Schema id.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Mesh authority revision.
    pub authority_revision: Revision,
    /// Mesh id when initialized.
    pub mesh_id: Option<DottedId>,
    /// Current leadership epoch.
    pub authority_epoch: u64,
    /// Current deterministic coordinator.
    pub coordinator_peer_id: Option<DottedId>,
    /// Accepted members.
    pub members: Vec<ManifoldAcceptedMeshMember>,
    /// Ranked direct routes forming a connected graph.
    pub selected_routes: Vec<ManifoldPeerMeshSelectedRoute>,
    /// Applied proposals retained for replay rejection.
    pub applied_proposal_ids: Vec<DottedId>,
    /// Explicitly revoked peers retained against resurrection.
    pub revoked_peer_ids: Vec<DottedId>,
}

/// Review input binding accepted peer state to mesh state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPeerMeshReviewCase {
    /// Schema id.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Manifold accepted peer identities/status.
    pub accepted_peers: ManifoldAcceptedPeerState,
    /// Current mesh state.
    pub current_state: ManifoldPeerMeshState,
    /// Candidate mesh view.
    pub proposal: ManifoldPeerMeshProposal,
    /// Trusted proposal adapters.
    pub trusted_proposer_ids: Vec<DottedId>,
    /// Review time.
    pub now_ms: u64,
}

/// Stable mesh rejection reasons.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldPeerMeshRejectionReason {
    /// Schema mismatch.
    SchemaMismatch,
    /// Revision mismatch.
    StaleAuthorityRevision,
    /// Proposal replay.
    ReplayedProposal,
    /// Adapter is not trusted.
    UntrustedProposer,
    /// Membership is outside the bounded N-peer range.
    MemberCount,
    /// Membership is not unique and canonical.
    MemberOrder,
    /// Explicitly revoked member attempted to return.
    RevokedMember,
    /// Member is not accepted for rendezvous.
    MemberNotAccepted,
    /// Proposed member status does not match accepted state.
    MemberStatusMismatch,
    /// Accepted member observation is stale.
    StaleMember,
    /// Coordinator is not the deterministic first member.
    CoordinatorMismatch,
    /// Proposed epoch is older.
    StaleEpoch,
    /// Same epoch names a different authority.
    SplitBrain,
    /// Route identity, endpoints, count, or metric is invalid.
    InvalidRoute,
    /// Route evidence is expired.
    StaleRouteEvidence,
    /// A direct route lacks authentication.
    RouteNotAuthenticated,
    /// Advisory gossip attempted to become a direct/media route.
    MediaGossipForbidden,
    /// Ranked direct routes do not connect all members.
    MeshDisconnected,
}

/// Mesh decision outcome.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldPeerMeshOutcome {
    /// Accepted and applied.
    Accepted,
    /// Rejected without mutation.
    Rejected,
}

/// Audit event for a review.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPeerMeshAuditEvent {
    /// Schema id.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Audit id.
    pub event_id: DottedId,
    /// Proposal id.
    pub proposal_id: DottedId,
    /// Prior revision.
    pub prior_authority_revision: Revision,
    /// Resulting revision.
    pub resulting_authority_revision: Revision,
    /// Outcome.
    pub outcome: ManifoldPeerMeshOutcome,
    /// Rejection reason.
    pub rejection_reason: Option<ManifoldPeerMeshRejectionReason>,
}

/// Review result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPeerMeshDecision {
    /// Schema id.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Decision id.
    pub decision_id: DottedId,
    /// Proposal id.
    pub proposal_id: DottedId,
    /// Outcome.
    pub outcome: ManifoldPeerMeshOutcome,
    /// Whether state changed.
    pub applied: bool,
    /// Rejection reason.
    pub rejection_reason: Option<ManifoldPeerMeshRejectionReason>,
    /// Accepted state when applied.
    pub accepted_state: Option<ManifoldPeerMeshState>,
    /// Audit event.
    pub audit_event: ManifoldPeerMeshAuditEvent,
}

/// Explicit peer revocation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPeerMeshRevocation {
    /// Operation id.
    pub revocation_id: DottedId,
    /// Peer id to revoke.
    pub peer_id: DottedId,
    /// Expected authority revision.
    pub expected_authority_revision: Revision,
}

/// Expiry/revocation mutation receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPeerMeshMutationReceipt {
    /// Schema id.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Operation id.
    pub operation_id: DottedId,
    /// Operation kind.
    pub operation: String,
    /// Whether state changed.
    pub applied: bool,
    /// Removed peers.
    pub removed_peer_ids: Vec<DottedId>,
    /// Prior revision.
    pub prior_authority_revision: Revision,
    /// Resulting revision.
    pub resulting_authority_revision: Revision,
}

/// Review and apply one bounded N-peer proposal.
#[must_use]
pub fn review_and_apply_peer_mesh(case: &ManifoldPeerMeshReviewCase) -> ManifoldPeerMeshDecision {
    let ranked = validate_case(case).and_then(|()| rank_direct_routes(case));
    let rejection = ranked.as_ref().err().cloned();
    let prior = case.current_state.authority_revision;
    let accepted_state = ranked.ok().map(|routes| apply(case, routes));
    let resulting = accepted_state
        .as_ref()
        .map_or(prior, |state| state.authority_revision);
    let outcome = if accepted_state.is_some() {
        ManifoldPeerMeshOutcome::Accepted
    } else {
        ManifoldPeerMeshOutcome::Rejected
    };
    let decision_id = derived("decision.peer-mesh", &case.proposal.proposal_id);
    ManifoldPeerMeshDecision {
        schema_id: schema(PEER_MESH_DECISION_SCHEMA),
        decision_id,
        proposal_id: case.proposal.proposal_id.clone(),
        outcome: outcome.clone(),
        applied: accepted_state.is_some(),
        rejection_reason: rejection.clone(),
        accepted_state,
        audit_event: ManifoldPeerMeshAuditEvent {
            schema_id: schema(PEER_MESH_AUDIT_SCHEMA),
            event_id: derived("audit.peer-mesh", &case.proposal.proposal_id),
            proposal_id: case.proposal.proposal_id.clone(),
            prior_authority_revision: prior,
            resulting_authority_revision: resulting,
            outcome,
            rejection_reason: rejection,
        },
    }
}

/// Remove expired members and all routes involving them.
pub fn expire_peer_mesh_members(
    state: &ManifoldPeerMeshState,
    sweep_id: DottedId,
    now_ms: u64,
) -> Result<(ManifoldPeerMeshState, ManifoldPeerMeshMutationReceipt), String> {
    validate_state_schema(state)?;
    let removed = state
        .members
        .iter()
        .filter(|member| member.expires_at_ms <= now_ms)
        .map(|member| member.peer_id.clone())
        .collect::<Vec<_>>();
    mutate_remove(state, sweep_id, "expire", removed, false)
}

/// Explicitly revoke one member and retain the revocation against resurrection.
pub fn revoke_peer_mesh_member(
    state: &ManifoldPeerMeshState,
    request: &ManifoldPeerMeshRevocation,
) -> Result<(ManifoldPeerMeshState, ManifoldPeerMeshMutationReceipt), String> {
    validate_state_schema(state)?;
    if request.expected_authority_revision != state.authority_revision {
        return Err("peer-mesh revocation authority revision mismatch".to_string());
    }
    if !state
        .members
        .iter()
        .any(|member| member.peer_id == request.peer_id)
    {
        return Err("active mesh member not found".to_string());
    }
    mutate_remove(
        state,
        request.revocation_id.clone(),
        "revoke",
        vec![request.peer_id.clone()],
        true,
    )
}

fn validate_case(case: &ManifoldPeerMeshReviewCase) -> Result<(), ManifoldPeerMeshRejectionReason> {
    let proposal = &case.proposal;
    if case.schema_id.as_str() != PEER_MESH_REVIEW_SCHEMA
        || case.accepted_peers.schema_id.as_str() != PEER_SNAPSHOT_SCHEMA
        || case.current_state.schema_id.as_str() != PEER_MESH_STATE_SCHEMA
        || proposal.schema_id.as_str() != PEER_MESH_PROPOSAL_SCHEMA
    {
        return Err(ManifoldPeerMeshRejectionReason::SchemaMismatch);
    }
    if proposal.expected_authority_revision != case.current_state.authority_revision {
        return Err(ManifoldPeerMeshRejectionReason::StaleAuthorityRevision);
    }
    if case
        .current_state
        .applied_proposal_ids
        .contains(&proposal.proposal_id)
    {
        return Err(ManifoldPeerMeshRejectionReason::ReplayedProposal);
    }
    if !case.trusted_proposer_ids.contains(&proposal.proposer_id) {
        return Err(ManifoldPeerMeshRejectionReason::UntrustedProposer);
    }
    if !(MIN_MESH_PEERS..=MAX_MESH_PEERS).contains(&proposal.member_peer_ids.len()) {
        return Err(ManifoldPeerMeshRejectionReason::MemberCount);
    }
    let sorted_members = proposal
        .member_peer_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if sorted_members != proposal.member_peer_ids {
        return Err(ManifoldPeerMeshRejectionReason::MemberOrder);
    }
    if proposal.coordinator_peer_id != proposal.member_peer_ids[0] {
        return Err(ManifoldPeerMeshRejectionReason::CoordinatorMismatch);
    }
    if proposal.authority_epoch < case.current_state.authority_epoch {
        return Err(ManifoldPeerMeshRejectionReason::StaleEpoch);
    }
    if proposal.authority_epoch == case.current_state.authority_epoch
        && case.current_state.coordinator_peer_id.is_some()
        && case.current_state.coordinator_peer_id.as_ref() != Some(&proposal.coordinator_peer_id)
    {
        return Err(ManifoldPeerMeshRejectionReason::SplitBrain);
    }
    for peer_id in &proposal.member_peer_ids {
        if case.current_state.revoked_peer_ids.contains(peer_id) {
            return Err(ManifoldPeerMeshRejectionReason::RevokedMember);
        }
        let Some(peer) = case
            .accepted_peers
            .peers
            .iter()
            .find(|peer| &peer.identity.peer_id == peer_id)
        else {
            return Err(ManifoldPeerMeshRejectionReason::MemberNotAccepted);
        };
        if !peer.identity.roles.contains(&ManifoldPeerRole::Rendezvous)
            || peer.status.availability == ManifoldPeerAvailability::Unavailable
        {
            return Err(ManifoldPeerMeshRejectionReason::MemberNotAccepted);
        }
        if peer.status.peer_id != *peer_id {
            return Err(ManifoldPeerMeshRejectionReason::MemberStatusMismatch);
        }
        if peer.status.observed_at_ms > case.now_ms || peer.status.expires_at_ms <= case.now_ms {
            return Err(ManifoldPeerMeshRejectionReason::StaleMember);
        }
    }
    if proposal.route_candidates.len() > MAX_ROUTE_CANDIDATES {
        return Err(ManifoldPeerMeshRejectionReason::InvalidRoute);
    }
    let mut route_ids = BTreeSet::new();
    for route in &proposal.route_candidates {
        if !route_ids.insert(route.candidate_id.clone())
            || route.source_peer_id == route.target_peer_id
            || !proposal.member_peer_ids.contains(&route.source_peer_id)
            || !proposal.member_peer_ids.contains(&route.target_peer_id)
            || route.observed_latency_ms == 0
            || route.hop_count == 0
        {
            return Err(ManifoldPeerMeshRejectionReason::InvalidRoute);
        }
        if route.evidence_expires_at_ms <= case.now_ms {
            return Err(ManifoldPeerMeshRejectionReason::StaleRouteEvidence);
        }
        match route.route_class {
            ManifoldPeerMeshRouteClass::DirectPairwise => {
                if route.route_contract_id.as_str() != DIRECT_P2P_ROUTE_CONTRACT {
                    return Err(ManifoldPeerMeshRejectionReason::InvalidRoute);
                }
                if !route.authenticated {
                    return Err(ManifoldPeerMeshRejectionReason::RouteNotAuthenticated);
                }
            }
            ManifoldPeerMeshRouteClass::AdvisoryStatusOnly => {
                if route.route_contract_id.as_str() != ADVISORY_STATUS_ROUTE_CONTRACT
                    || route.authenticated
                {
                    return Err(ManifoldPeerMeshRejectionReason::MediaGossipForbidden);
                }
            }
        }
    }
    Ok(())
}

fn rank_direct_routes(
    case: &ManifoldPeerMeshReviewCase,
) -> Result<Vec<ManifoldPeerMeshSelectedRoute>, ManifoldPeerMeshRejectionReason> {
    let mut pairs: BTreeMap<(DottedId, DottedId), Vec<&ManifoldPeerMeshRouteCandidate>> =
        BTreeMap::new();
    for route in &case.proposal.route_candidates {
        if route.route_class != ManifoldPeerMeshRouteClass::DirectPairwise {
            continue;
        }
        let pair = canonical_pair(&route.source_peer_id, &route.target_peer_id);
        pairs.entry(pair).or_default().push(route);
    }
    let mut selected = Vec::new();
    for ((first, second), mut candidates) in pairs {
        candidates.sort_by(|left, right| {
            (left.observed_latency_ms, left.hop_count, &left.candidate_id).cmp(&(
                right.observed_latency_ms,
                right.hop_count,
                &right.candidate_id,
            ))
        });
        let winner = candidates[0];
        selected.push(ManifoldPeerMeshSelectedRoute {
            candidate_id: winner.candidate_id.clone(),
            first_peer_id: first,
            second_peer_id: second,
            route_contract_id: winner.route_contract_id.clone(),
            observed_latency_ms: winner.observed_latency_ms,
            hop_count: winner.hop_count,
            direct_media_lane_eligible: true,
        });
    }
    selected.sort_by(|left, right| {
        (
            &left.first_peer_id,
            &left.second_peer_id,
            &left.candidate_id,
        )
            .cmp(&(
                &right.first_peer_id,
                &right.second_peer_id,
                &right.candidate_id,
            ))
    });
    if !connected(
        &case.proposal.member_peer_ids,
        &case.proposal.route_candidates,
    ) {
        return Err(ManifoldPeerMeshRejectionReason::MeshDisconnected);
    }
    Ok(selected)
}

fn connected(members: &[DottedId], routes: &[ManifoldPeerMeshRouteCandidate]) -> bool {
    let mut visited = BTreeSet::from([members[0].clone()]);
    loop {
        let before = visited.len();
        for route in routes {
            if visited.contains(&route.source_peer_id) {
                visited.insert(route.target_peer_id.clone());
            }
            if visited.contains(&route.target_peer_id) {
                visited.insert(route.source_peer_id.clone());
            }
        }
        if visited.len() == before {
            break;
        }
    }
    visited.len() == members.len()
}

fn apply(
    case: &ManifoldPeerMeshReviewCase,
    selected_routes: Vec<ManifoldPeerMeshSelectedRoute>,
) -> ManifoldPeerMeshState {
    let mut next = case.current_state.clone();
    next.authority_revision = next
        .authority_revision
        .next()
        .expect("mesh authority revision must advance");
    next.mesh_id = Some(case.proposal.mesh_id.clone());
    next.authority_epoch = case.proposal.authority_epoch;
    next.coordinator_peer_id = Some(case.proposal.coordinator_peer_id.clone());
    next.members = case
        .proposal
        .member_peer_ids
        .iter()
        .map(|peer_id| {
            let peer = case
                .accepted_peers
                .peers
                .iter()
                .find(|peer| &peer.identity.peer_id == peer_id)
                .expect("validated peer must exist");
            ManifoldAcceptedMeshMember {
                peer_id: peer_id.clone(),
                status_revision: peer.status.status_revision,
                expires_at_ms: peer.status.expires_at_ms,
            }
        })
        .collect();
    next.selected_routes = selected_routes;
    next.applied_proposal_ids
        .push(case.proposal.proposal_id.clone());
    next
}

fn mutate_remove(
    state: &ManifoldPeerMeshState,
    operation_id: DottedId,
    operation: &str,
    mut removed: Vec<DottedId>,
    retain_revocation: bool,
) -> Result<(ManifoldPeerMeshState, ManifoldPeerMeshMutationReceipt), String> {
    removed.sort();
    removed.dedup();
    let prior = state.authority_revision;
    let mut next = state.clone();
    let applied = !removed.is_empty();
    if applied {
        next.authority_revision = next
            .authority_revision
            .next()
            .ok_or_else(|| "peer-mesh authority revision overflow".to_string())?;
        next.members
            .retain(|member| !removed.contains(&member.peer_id));
        next.selected_routes.retain(|route| {
            !removed.contains(&route.first_peer_id) && !removed.contains(&route.second_peer_id)
        });
        if retain_revocation {
            next.revoked_peer_ids.extend(removed.clone());
            next.revoked_peer_ids.sort();
            next.revoked_peer_ids.dedup();
        }
    }
    let receipt = ManifoldPeerMeshMutationReceipt {
        schema_id: schema(PEER_MESH_MUTATION_SCHEMA),
        operation_id,
        operation: operation.to_string(),
        applied,
        removed_peer_ids: removed,
        prior_authority_revision: prior,
        resulting_authority_revision: next.authority_revision,
    };
    Ok((next, receipt))
}

fn validate_state_schema(state: &ManifoldPeerMeshState) -> Result<(), String> {
    if state.schema_id.as_str() != PEER_MESH_STATE_SCHEMA {
        return Err("peer-mesh state schema mismatch".to_string());
    }
    Ok(())
}

fn canonical_pair(first: &DottedId, second: &DottedId) -> (DottedId, DottedId) {
    if first <= second {
        (first.clone(), second.clone())
    } else {
        (second.clone(), first.clone())
    }
}

fn schema(value: &str) -> SchemaId {
    SchemaId::new(value).expect("static mesh schema")
}

fn derived(prefix: &str, suffix: &DottedId) -> DottedId {
    DottedId::new(format!("{prefix}.{}", suffix.as_str())).expect("derived mesh id")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ManifoldAcceptedPeer, ManifoldPeerIdentity, ManifoldPeerPayloadClass, ManifoldPeerStatus,
        PEER_IDENTITY_SCHEMA, PEER_STATUS_SCHEMA,
    };

    fn id(value: &str) -> DottedId {
        DottedId::new(value).expect("id")
    }

    fn peer(name: &str, expires_at_ms: u64) -> ManifoldAcceptedPeer {
        let peer_id = id(name);
        ManifoldAcceptedPeer {
            identity: ManifoldPeerIdentity {
                schema_id: schema(PEER_IDENTITY_SCHEMA),
                peer_id: peer_id.clone(),
                key_fingerprint: id(&format!("fingerprint.{name}")),
                trust_domain: id("trust.morphospace.peer"),
                roles: vec![ManifoldPeerRole::Observer, ManifoldPeerRole::Rendezvous],
            },
            status: ManifoldPeerStatus {
                schema_id: schema(PEER_STATUS_SCHEMA),
                peer_id,
                status_revision: Revision::INITIAL,
                observed_at_ms: 1_000,
                expires_at_ms,
                availability: ManifoldPeerAvailability::Ready,
                capability_ids: vec![id("capability.peer.mesh.status")],
            },
        }
    }

    fn route(
        suffix: &str,
        first: &str,
        second: &str,
        latency: u32,
    ) -> ManifoldPeerMeshRouteCandidate {
        ManifoldPeerMeshRouteCandidate {
            candidate_id: id(&format!("route.{suffix}")),
            source_peer_id: id(first),
            target_peer_id: id(second),
            route_class: ManifoldPeerMeshRouteClass::DirectPairwise,
            route_contract_id: id(DIRECT_P2P_ROUTE_CONTRACT),
            authenticated: true,
            observed_latency_ms: latency,
            hop_count: 1,
            evidence_expires_at_ms: 60_000,
        }
    }

    fn review_case() -> ManifoldPeerMeshReviewCase {
        let members = ["peer.alpha", "peer.beta", "peer.gamma"];
        ManifoldPeerMeshReviewCase {
            schema_id: schema(PEER_MESH_REVIEW_SCHEMA),
            accepted_peers: ManifoldAcceptedPeerState {
                schema_id: schema(PEER_SNAPSHOT_SCHEMA),
                authority_revision: Revision::new(4).expect("revision"),
                peers: members.iter().map(|name| peer(name, 61_000)).collect(),
                applied_proposal_ids: Vec::new(),
            },
            current_state: ManifoldPeerMeshState {
                schema_id: schema(PEER_MESH_STATE_SCHEMA),
                authority_revision: Revision::INITIAL,
                mesh_id: None,
                authority_epoch: 0,
                coordinator_peer_id: None,
                members: Vec::new(),
                selected_routes: Vec::new(),
                applied_proposal_ids: Vec::new(),
                revoked_peer_ids: Vec::new(),
            },
            proposal: ManifoldPeerMeshProposal {
                schema_id: schema(PEER_MESH_PROPOSAL_SCHEMA),
                proposal_id: id("proposal.peer-mesh.three.001"),
                mesh_id: id("mesh.quest.low-rate.001"),
                expected_authority_revision: Revision::INITIAL,
                proposer_id: id("adapter.quest.peer-mesh"),
                authority_epoch: 1,
                coordinator_peer_id: id("peer.alpha"),
                member_peer_ids: members.into_iter().map(id).collect(),
                route_candidates: vec![
                    route("alpha-beta.fast", "peer.alpha", "peer.beta", 10),
                    route("alpha-beta.slow", "peer.alpha", "peer.beta", 30),
                    route("beta-gamma", "peer.beta", "peer.gamma", 12),
                    ManifoldPeerMeshRouteCandidate {
                        candidate_id: id("route.advisory.alpha-gamma"),
                        source_peer_id: id("peer.alpha"),
                        target_peer_id: id("peer.gamma"),
                        route_class: ManifoldPeerMeshRouteClass::AdvisoryStatusOnly,
                        route_contract_id: id(ADVISORY_STATUS_ROUTE_CONTRACT),
                        authenticated: false,
                        observed_latency_ms: 2,
                        hop_count: 1,
                        evidence_expires_at_ms: 60_000,
                    },
                ],
            },
            trusted_proposer_ids: vec![id("adapter.quest.peer-mesh")],
            now_ms: 2_000,
        }
    }

    #[test]
    fn three_peers_rank_direct_routes_and_keep_gossip_non_media() {
        let decision = review_and_apply_peer_mesh(&review_case());
        assert_eq!(decision.outcome, ManifoldPeerMeshOutcome::Accepted);
        let state = decision.accepted_state.expect("state");
        assert_eq!(state.members.len(), 3);
        assert_eq!(state.selected_routes.len(), 2);
        assert_eq!(
            state.selected_routes[0].candidate_id,
            id("route.alpha-beta.fast")
        );
        assert!(state
            .selected_routes
            .iter()
            .all(|route| route.direct_media_lane_eligible));
    }

    #[test]
    fn replay_split_brain_disconnect_and_media_gossip_fail_closed() {
        let baseline = review_case();
        let accepted = review_and_apply_peer_mesh(&baseline)
            .accepted_state
            .expect("accepted");

        let mut replay = baseline.clone();
        replay.current_state = accepted.clone();
        replay.proposal.expected_authority_revision = accepted.authority_revision;
        assert_eq!(
            review_and_apply_peer_mesh(&replay).rejection_reason,
            Some(ManifoldPeerMeshRejectionReason::ReplayedProposal)
        );

        let mut split = baseline.clone();
        split.current_state = accepted.clone();
        split.current_state.coordinator_peer_id = Some(id("peer.beta"));
        split.proposal.proposal_id = id("proposal.peer-mesh.split.001");
        split.proposal.expected_authority_revision = accepted.authority_revision;
        assert_eq!(
            review_and_apply_peer_mesh(&split).rejection_reason,
            Some(ManifoldPeerMeshRejectionReason::SplitBrain)
        );

        let mut disconnected = baseline.clone();
        disconnected.proposal.proposal_id = id("proposal.peer-mesh.disconnected.001");
        disconnected
            .proposal
            .route_candidates
            .retain(|route| route.target_peer_id != id("peer.gamma"));
        assert_eq!(
            review_and_apply_peer_mesh(&disconnected).rejection_reason,
            Some(ManifoldPeerMeshRejectionReason::MeshDisconnected)
        );

        let mut media_gossip = baseline;
        media_gossip.proposal.proposal_id = id("proposal.peer-mesh.gossip-media.001");
        let gossip = media_gossip
            .proposal
            .route_candidates
            .iter_mut()
            .find(|route| route.route_class == ManifoldPeerMeshRouteClass::AdvisoryStatusOnly)
            .expect("gossip");
        gossip.route_contract_id = id(DIRECT_P2P_ROUTE_CONTRACT);
        assert_eq!(
            review_and_apply_peer_mesh(&media_gossip).rejection_reason,
            Some(ManifoldPeerMeshRejectionReason::MediaGossipForbidden)
        );
    }

    #[test]
    fn expiry_and_revocation_advance_and_prevent_resurrection() {
        let case = review_case();
        let state = review_and_apply_peer_mesh(&case)
            .accepted_state
            .expect("accepted");
        let (expired, expiry) =
            expire_peer_mesh_members(&state, id("sweep.peer-mesh.expired"), 61_000)
                .expect("expire");
        assert!(expiry.applied);
        assert!(expired.members.is_empty());

        let (revoked, receipt) = revoke_peer_mesh_member(
            &state,
            &ManifoldPeerMeshRevocation {
                revocation_id: id("revoke.peer-mesh.gamma"),
                peer_id: id("peer.gamma"),
                expected_authority_revision: state.authority_revision,
            },
        )
        .expect("revoke");
        assert!(receipt.applied);
        assert!(revoked.revoked_peer_ids.contains(&id("peer.gamma")));
        let mut resurrect = case;
        resurrect.current_state = revoked.clone();
        resurrect.proposal.proposal_id = id("proposal.peer-mesh.resurrect.001");
        resurrect.proposal.expected_authority_revision = revoked.authority_revision;
        assert_eq!(
            review_and_apply_peer_mesh(&resurrect).rejection_reason,
            Some(ManifoldPeerMeshRejectionReason::RevokedMember)
        );
    }

    #[test]
    fn mesh_types_remain_low_rate_and_payload_free() {
        let case = review_case();
        let text = serde_json::to_string(&case).expect("json");
        assert!(!text.contains("payload"));
        assert!(!text.contains("endpoint"));
        assert!(!text.contains("command"));
        let _ = ManifoldPeerPayloadClass::LowRateDescriptor;
    }

    #[test]
    fn committed_three_peer_fixture_and_damage_registry_are_executable() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let case: ManifoldPeerMeshReviewCase = serde_json::from_str(
            &std::fs::read_to_string(root.join("fixtures/peer-mesh/three-peer.pass.json"))
                .expect("fixture"),
        )
        .expect("review fixture");
        assert_eq!(
            review_and_apply_peer_mesh(&case).outcome,
            ManifoldPeerMeshOutcome::Accepted
        );
        let damage: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(root.join("fixtures/damaged/peer-mesh-matrix.json"))
                .expect("damage fixture"),
        )
        .expect("damage json");
        assert_eq!(
            damage["schema"],
            "rusty.manifold.peer.mesh_damage_matrix.v1"
        );
        assert_eq!(damage["cases"].as_array().expect("cases").len(), 6);
    }
}
