//! Manifold peer-session review and topology authorization.

use rusty_manifold_model::{DottedId, Revision, SchemaId};
use serde::{Deserialize, Serialize};

use crate::{ManifoldAcceptedPeerState, ManifoldPeerRole};

/// Peer-session proposal schema.
pub const PEER_SESSION_PROPOSAL_SCHEMA: &str = "rusty.manifold.peer.session_proposal.v1";
/// Peer-session accepted snapshot schema.
pub const PEER_SESSION_SNAPSHOT_SCHEMA: &str = "rusty.manifold.peer.session_state.v1";
/// Peer-session review-case schema.
pub const PEER_SESSION_REVIEW_SCHEMA: &str = "rusty.manifold.peer.session_review.v1";
/// Peer-session decision schema.
pub const PEER_SESSION_DECISION_SCHEMA: &str = "rusty.manifold.peer.session_decision.v1";
/// Peer-session topology authorization schema.
pub const PEER_TOPOLOGY_AUTHORIZATION_SCHEMA: &str =
    "rusty.manifold.peer.topology_authorization.v1";
/// Peer-session revocation request schema.
pub const PEER_SESSION_REVOCATION_SCHEMA: &str = "rusty.manifold.peer.session_revocation.v1";
/// Product Wi-Fi Direct topology contract id.
pub const PRODUCT_WIFI_DIRECT_TOPOLOGY_CONTRACT: &str =
    "rusty.quest.product_wifi_direct_topology.v1";

const MAX_RENDEZVOUS_TTL_MS: u64 = 120_000;
const MAX_SESSION_CAPABILITIES: usize = 16;

/// Authenticated low-rate rendezvous transport.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerRendezvousTransport {
    /// Quest BLE/GATT adapter with authenticated pair evidence.
    BleGattAuthenticated,
}

/// Topology role authorized for a peer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerTopologyRole {
    /// Wi-Fi Direct group owner.
    GroupOwner,
    /// Wi-Fi Direct client.
    Client,
}

/// Adapter-projected authentication evidence; this never contains the secret.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PeerRendezvousAuthenticationEvidence {
    /// Approved adapter identity.
    pub adapter_id: DottedId,
    /// Rendezvous transport.
    pub transport: PeerRendezvousTransport,
    /// Digest of the validated source artifact.
    pub evidence_digest: DottedId,
    /// Whether the adapter verified source authentication.
    pub authenticated: bool,
    /// Total authenticated messages across both roles/phases.
    pub authenticated_messages: u32,
    /// Authentication failures observed in the accepted window.
    pub authentication_failures: u32,
    /// Whether both devices swapped GATT roles.
    pub role_swap_completed: bool,
    /// Reconnect cycles proven across the pair.
    pub reconnects_completed: u32,
    /// Evidence observation time.
    pub observed_at_ms: u64,
    /// Evidence expiry time.
    pub expires_at_ms: u64,
}

/// Authenticated proposal for one bounded peer session.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPeerSessionProposal {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Idempotency identity.
    pub proposal_id: DottedId,
    /// Session identity.
    pub session_id: DottedId,
    /// Current session authority revision expected by the adapter.
    pub expected_authority_revision: Revision,
    /// Stable local/initiating peer.
    pub subject_peer_id: DottedId,
    /// Stable remote peer.
    pub candidate_peer_id: DottedId,
    /// Peer authorized as topology group owner.
    pub group_owner_peer_id: DottedId,
    /// Peer authorized as topology client.
    pub client_peer_id: DottedId,
    /// Requested shared low-rate capability ids.
    pub requested_capability_ids: Vec<DottedId>,
    /// Explicit topology contract.
    pub topology_contract_id: DottedId,
    /// Desired authorization expiry.
    pub expires_at_ms: u64,
    /// Authenticated transport evidence.
    pub authentication: PeerRendezvousAuthenticationEvidence,
}

/// Accepted peer session.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldAcceptedPeerSession {
    /// Applied proposal.
    pub proposal: ManifoldPeerSessionProposal,
    /// Decision that authorized the session.
    pub decision_id: DottedId,
    /// Whether explicit revocation ended the session.
    pub revoked: bool,
}

/// Manifold-owned peer-session snapshot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPeerSessionState {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Current peer-session authority revision.
    pub authority_revision: Revision,
    /// Accepted sessions.
    pub sessions: Vec<ManifoldAcceptedPeerSession>,
    /// Applied proposal identities retained for replay rejection.
    pub applied_proposal_ids: Vec<DottedId>,
    /// Explicitly revoked session identities.
    pub revoked_session_ids: Vec<DottedId>,
}

/// Review envelope binding peer authority and peer-session authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPeerSessionReviewCase {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Current accepted peer identities/status.
    pub accepted_peers: ManifoldAcceptedPeerState,
    /// Current peer-session state.
    pub current_state: ManifoldPeerSessionState,
    /// Proposed session.
    pub proposal: ManifoldPeerSessionProposal,
    /// Adapter identities trusted to project authenticated evidence.
    pub trusted_adapter_ids: Vec<DottedId>,
    /// Review time.
    pub now_ms: u64,
}

/// Peer-session decision outcome.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldPeerSessionOutcome {
    /// Proposal was accepted and applied.
    Accepted,
    /// Proposal was rejected without mutation.
    Rejected,
}

/// Stable peer-session rejection reasons.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldPeerSessionRejectionReason {
    /// Schema mismatch.
    SchemaMismatch,
    /// Expected authority revision mismatched.
    StaleAuthorityRevision,
    /// Proposal was already applied.
    ReplayedProposal,
    /// Session was explicitly revoked.
    RevokedSession,
    /// Evidence adapter is not trusted.
    UntrustedAdapter,
    /// Authentication did not pass.
    AuthenticationFailed,
    /// Role swap or reconnect evidence was incomplete.
    RendezvousLifecycleIncomplete,
    /// Evidence was stale or future-dated.
    StaleRendezvousEvidence,
    /// Requested session exceeded the evidence window.
    SessionOutlivesEvidence,
    /// Subject/candidate identities were invalid.
    InvalidPeerPair,
    /// One peer was not accepted for rendezvous.
    PeerNotAcceptedForRendezvous,
    /// Requested capability was not accepted for both peers.
    CapabilityNotShared,
    /// Media/high-rate capability entered rendezvous.
    HighRateCapability,
    /// Capability list exceeded its bound.
    CapabilityLimitExceeded,
    /// Topology role assignment did not match the pair.
    InvalidTopologyRoles,
    /// Topology contract is unsupported.
    UnsupportedTopologyContract,
    /// Subject attempted to replace an active peer without revocation.
    PeerChangedWithoutRevocation,
}

/// Audit-bearing peer-session decision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPeerSessionDecision {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Stable decision id.
    pub decision_id: DottedId,
    /// Proposal id.
    pub proposal_id: DottedId,
    /// Outcome.
    pub outcome: ManifoldPeerSessionOutcome,
    /// Rejection reason.
    pub rejection_reason: Option<ManifoldPeerSessionRejectionReason>,
    /// Prior revision.
    pub prior_authority_revision: Revision,
    /// Resulting revision; unchanged on rejection.
    pub resulting_authority_revision: Revision,
    /// Whether accepted state changed.
    pub applied: bool,
    /// Candidate next state on acceptance.
    pub accepted_state: Option<ManifoldPeerSessionState>,
}

/// Machine-readable topology authorization consumed by a platform adapter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPeerTopologyAuthorization {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Decision/revocation identity.
    pub decision_id: DottedId,
    /// Session identity.
    pub session_id: DottedId,
    /// Proposal identity.
    pub proposal_id: DottedId,
    /// Current peer-session authority revision.
    pub authority_revision: Revision,
    /// Group-owner peer.
    pub group_owner_peer_id: DottedId,
    /// Client peer.
    pub client_peer_id: DottedId,
    /// Authorized topology contract.
    pub topology_contract_id: DottedId,
    /// Whether topology may start.
    pub authorized: bool,
    /// Authorization observation time.
    pub valid_from_ms: u64,
    /// Authorization expiry.
    pub expires_at_ms: u64,
    /// Denial reason on a non-authorizing receipt.
    pub denial_reason: Option<ManifoldPeerSessionRejectionReason>,
}

/// Explicit peer-session revocation request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPeerSessionRevocation {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Revocation operation id.
    pub revocation_id: DottedId,
    /// Session to revoke.
    pub session_id: DottedId,
    /// Expected authority revision.
    pub expected_authority_revision: Revision,
}

/// Review and apply one authenticated peer-session proposal.
#[must_use]
pub fn review_and_apply_peer_session(
    case: &ManifoldPeerSessionReviewCase,
) -> (
    ManifoldPeerSessionDecision,
    ManifoldPeerTopologyAuthorization,
) {
    let rejection = validate_review(case).err();
    let prior = case.current_state.authority_revision;
    let decision_id = derived("decision.peer-session", &case.proposal.proposal_id);
    let accepted_state = rejection
        .is_none()
        .then(|| apply(case, decision_id.clone()));
    let resulting = accepted_state
        .as_ref()
        .map_or(prior, |state| state.authority_revision);
    let outcome = if rejection.is_none() {
        ManifoldPeerSessionOutcome::Accepted
    } else {
        ManifoldPeerSessionOutcome::Rejected
    };
    let decision = ManifoldPeerSessionDecision {
        schema_id: schema(PEER_SESSION_DECISION_SCHEMA),
        decision_id: decision_id.clone(),
        proposal_id: case.proposal.proposal_id.clone(),
        outcome,
        rejection_reason: rejection.clone(),
        prior_authority_revision: prior,
        resulting_authority_revision: resulting,
        applied: rejection.is_none(),
        accepted_state,
    };
    let authorization = authorization(
        &case.proposal,
        decision_id,
        resulting,
        case.now_ms,
        rejection.is_none(),
        rejection,
    );
    (decision, authorization)
}

/// Explicitly revoke a current peer session and emit a non-authorizing receipt.
pub fn revoke_peer_session(
    state: &ManifoldPeerSessionState,
    request: &ManifoldPeerSessionRevocation,
    now_ms: u64,
) -> Result<(ManifoldPeerSessionState, ManifoldPeerTopologyAuthorization), String> {
    if request.schema_id.as_str() != PEER_SESSION_REVOCATION_SCHEMA {
        return Err("peer-session revocation schema mismatch".to_string());
    }
    if request.expected_authority_revision != state.authority_revision {
        return Err("peer-session revocation authority revision mismatch".to_string());
    }
    let Some(current) = state
        .sessions
        .iter()
        .find(|session| session.proposal.session_id == request.session_id && !session.revoked)
    else {
        return Err("active peer session not found".to_string());
    };
    let mut next = state.clone();
    next.authority_revision = next
        .authority_revision
        .next()
        .ok_or_else(|| "peer-session authority revision overflow".to_string())?;
    for session in &mut next.sessions {
        if session.proposal.session_id == request.session_id {
            session.revoked = true;
        }
    }
    if !next.revoked_session_ids.contains(&request.session_id) {
        next.revoked_session_ids.push(request.session_id.clone());
    }
    let receipt = authorization(
        &current.proposal,
        request.revocation_id.clone(),
        next.authority_revision,
        now_ms,
        false,
        Some(ManifoldPeerSessionRejectionReason::RevokedSession),
    );
    Ok((next, receipt))
}

fn validate_review(
    case: &ManifoldPeerSessionReviewCase,
) -> Result<(), ManifoldPeerSessionRejectionReason> {
    let proposal = &case.proposal;
    if case.schema_id.as_str() != PEER_SESSION_REVIEW_SCHEMA
        || case.current_state.schema_id.as_str() != PEER_SESSION_SNAPSHOT_SCHEMA
        || proposal.schema_id.as_str() != PEER_SESSION_PROPOSAL_SCHEMA
    {
        return Err(ManifoldPeerSessionRejectionReason::SchemaMismatch);
    }
    if proposal.expected_authority_revision != case.current_state.authority_revision {
        return Err(ManifoldPeerSessionRejectionReason::StaleAuthorityRevision);
    }
    if case
        .current_state
        .applied_proposal_ids
        .contains(&proposal.proposal_id)
    {
        return Err(ManifoldPeerSessionRejectionReason::ReplayedProposal);
    }
    if case
        .current_state
        .revoked_session_ids
        .contains(&proposal.session_id)
    {
        return Err(ManifoldPeerSessionRejectionReason::RevokedSession);
    }
    if !case
        .trusted_adapter_ids
        .contains(&proposal.authentication.adapter_id)
    {
        return Err(ManifoldPeerSessionRejectionReason::UntrustedAdapter);
    }
    if !proposal.authentication.authenticated
        || proposal.authentication.authentication_failures != 0
        || proposal.authentication.authenticated_messages < 4
    {
        return Err(ManifoldPeerSessionRejectionReason::AuthenticationFailed);
    }
    if !proposal.authentication.role_swap_completed
        || proposal.authentication.reconnects_completed < 2
    {
        return Err(ManifoldPeerSessionRejectionReason::RendezvousLifecycleIncomplete);
    }
    if proposal.authentication.observed_at_ms > case.now_ms
        || proposal.authentication.expires_at_ms <= case.now_ms
        || proposal
            .authentication
            .expires_at_ms
            .saturating_sub(proposal.authentication.observed_at_ms)
            > MAX_RENDEZVOUS_TTL_MS
    {
        return Err(ManifoldPeerSessionRejectionReason::StaleRendezvousEvidence);
    }
    if proposal.expires_at_ms > proposal.authentication.expires_at_ms
        || proposal.expires_at_ms <= case.now_ms
    {
        return Err(ManifoldPeerSessionRejectionReason::SessionOutlivesEvidence);
    }
    if proposal.subject_peer_id == proposal.candidate_peer_id {
        return Err(ManifoldPeerSessionRejectionReason::InvalidPeerPair);
    }
    let pair = [
        proposal.subject_peer_id.clone(),
        proposal.candidate_peer_id.clone(),
    ];
    if proposal.group_owner_peer_id == proposal.client_peer_id
        || !pair.contains(&proposal.group_owner_peer_id)
        || !pair.contains(&proposal.client_peer_id)
    {
        return Err(ManifoldPeerSessionRejectionReason::InvalidTopologyRoles);
    }
    if proposal.topology_contract_id.as_str() != PRODUCT_WIFI_DIRECT_TOPOLOGY_CONTRACT {
        return Err(ManifoldPeerSessionRejectionReason::UnsupportedTopologyContract);
    }
    if proposal.requested_capability_ids.len() > MAX_SESSION_CAPABILITIES {
        return Err(ManifoldPeerSessionRejectionReason::CapabilityLimitExceeded);
    }
    if proposal.requested_capability_ids.iter().any(|id| {
        let value = id.as_str();
        value.contains("media") || value.contains("stream") || value.contains("high-rate")
    }) {
        return Err(ManifoldPeerSessionRejectionReason::HighRateCapability);
    }
    for peer_id in &pair {
        let Some(peer) = case
            .accepted_peers
            .peers
            .iter()
            .find(|peer| &peer.identity.peer_id == peer_id)
        else {
            return Err(ManifoldPeerSessionRejectionReason::PeerNotAcceptedForRendezvous);
        };
        if !peer.identity.roles.contains(&ManifoldPeerRole::Rendezvous) {
            return Err(ManifoldPeerSessionRejectionReason::PeerNotAcceptedForRendezvous);
        }
        if proposal
            .requested_capability_ids
            .iter()
            .any(|capability| !peer.status.capability_ids.contains(capability))
        {
            return Err(ManifoldPeerSessionRejectionReason::CapabilityNotShared);
        }
    }
    if case.current_state.sessions.iter().any(|session| {
        !session.revoked
            && session.proposal.expires_at_ms > case.now_ms
            && session.proposal.subject_peer_id == proposal.subject_peer_id
            && session.proposal.candidate_peer_id != proposal.candidate_peer_id
    }) {
        return Err(ManifoldPeerSessionRejectionReason::PeerChangedWithoutRevocation);
    }
    Ok(())
}

fn apply(case: &ManifoldPeerSessionReviewCase, decision_id: DottedId) -> ManifoldPeerSessionState {
    let mut state = case.current_state.clone();
    state.authority_revision = state
        .authority_revision
        .next()
        .expect("peer-session authority revision must advance");
    let accepted = ManifoldAcceptedPeerSession {
        proposal: case.proposal.clone(),
        decision_id,
        revoked: false,
    };
    if let Some(existing) = state
        .sessions
        .iter_mut()
        .find(|session| session.proposal.session_id == accepted.proposal.session_id)
    {
        *existing = accepted;
    } else {
        state.sessions.push(accepted);
    }
    state
        .applied_proposal_ids
        .push(case.proposal.proposal_id.clone());
    state
}

fn authorization(
    proposal: &ManifoldPeerSessionProposal,
    decision_id: DottedId,
    authority_revision: Revision,
    now_ms: u64,
    authorized: bool,
    denial_reason: Option<ManifoldPeerSessionRejectionReason>,
) -> ManifoldPeerTopologyAuthorization {
    ManifoldPeerTopologyAuthorization {
        schema_id: schema(PEER_TOPOLOGY_AUTHORIZATION_SCHEMA),
        decision_id,
        session_id: proposal.session_id.clone(),
        proposal_id: proposal.proposal_id.clone(),
        authority_revision,
        group_owner_peer_id: proposal.group_owner_peer_id.clone(),
        client_peer_id: proposal.client_peer_id.clone(),
        topology_contract_id: proposal.topology_contract_id.clone(),
        authorized,
        valid_from_ms: now_ms,
        expires_at_ms: proposal.expires_at_ms,
        denial_reason,
    }
}

fn schema(value: &str) -> SchemaId {
    SchemaId::new(value).expect("static peer-session schema must be valid")
}

fn derived(prefix: &str, suffix: &DottedId) -> DottedId {
    DottedId::new(format!("{prefix}.{}", suffix.as_str()))
        .expect("derived peer-session id must be valid")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn case(path: &str) -> ManifoldPeerSessionReviewCase {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let text = std::fs::read_to_string(root.join(path)).expect("fixture");
        serde_json::from_str(&text).expect("review case")
    }

    #[test]
    fn authenticated_pair_authorizes_topology() {
        let case = case("fixtures/peer-session/authenticated-ble.pass.json");
        let (decision, authorization) = review_and_apply_peer_session(&case);
        assert_eq!(decision.outcome, ManifoldPeerSessionOutcome::Accepted);
        assert!(decision.applied);
        assert!(authorization.authorized);
        assert_eq!(authorization.authority_revision.get(), 2);
    }

    #[test]
    fn damaged_cases_reject_without_revision_advance() {
        for (path, expected) in [
            (
                "fixtures/damaged/peer-session-unauthenticated.json",
                ManifoldPeerSessionRejectionReason::AuthenticationFailed,
            ),
            (
                "fixtures/damaged/peer-session-expired.json",
                ManifoldPeerSessionRejectionReason::StaleRendezvousEvidence,
            ),
            (
                "fixtures/damaged/peer-session-replayed.json",
                ManifoldPeerSessionRejectionReason::ReplayedProposal,
            ),
            (
                "fixtures/damaged/peer-session-peer-changed.json",
                ManifoldPeerSessionRejectionReason::PeerChangedWithoutRevocation,
            ),
            (
                "fixtures/damaged/peer-session-media-capability.json",
                ManifoldPeerSessionRejectionReason::HighRateCapability,
            ),
        ] {
            let case = case(path);
            let (decision, authorization) = review_and_apply_peer_session(&case);
            assert_eq!(decision.rejection_reason, Some(expected), "{path}");
            assert!(!decision.applied, "{path}");
            assert_eq!(
                decision.prior_authority_revision, decision.resulting_authority_revision,
                "{path}"
            );
            assert!(!authorization.authorized, "{path}");
        }
    }

    #[test]
    fn revocation_advances_revision_and_denies_topology() {
        let case = case("fixtures/peer-session/authenticated-ble.pass.json");
        let (decision, _) = review_and_apply_peer_session(&case);
        let state = decision.accepted_state.expect("accepted state");
        let request = ManifoldPeerSessionRevocation {
            schema_id: schema(PEER_SESSION_REVOCATION_SCHEMA),
            revocation_id: DottedId::new("revoke.peer-session.fixture").expect("id"),
            session_id: case.proposal.session_id,
            expected_authority_revision: state.authority_revision,
        };
        let (next, receipt) =
            revoke_peer_session(&state, &request, case.now_ms + 1).expect("revoke");
        assert_eq!(next.authority_revision.get(), 3);
        assert!(!receipt.authorized);
        assert_eq!(
            receipt.denial_reason,
            Some(ManifoldPeerSessionRejectionReason::RevokedSession)
        );
    }
}
