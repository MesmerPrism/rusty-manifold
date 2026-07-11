//! Revisioned direct-lane lease authority derived from accepted mesh state.
//!
//! Route eligibility is advisory until this authority binds an accepted mesh
//! route to a fresh signed peer session and, when requested, an explicit media
//! session reference. No endpoint, socket, codec, or media payload is owned
//! here.

use std::collections::BTreeSet;

use rusty_manifold_model::{DottedId, ManifoldMediaSessionDescriptor, Revision, SchemaId};
use serde::{Deserialize, Serialize};

use crate::{
    validate_current_rendezvous_receipt, ManifoldPeerEnrollmentState, ManifoldPeerMeshState,
    ManifoldPeerSessionState, ManifoldRendezvousAuthorityState,
    ManifoldRendezvousReceiptValidationError, ManifoldSignedPeerTopologyAuthorization,
    DIRECT_P2P_ROUTE_CONTRACT, PEER_MESH_STATE_SCHEMA, PEER_SESSION_PROPOSAL_SCHEMA,
    PEER_SESSION_SNAPSHOT_SCHEMA, PEER_TOPOLOGY_AUTHORIZATION_SCHEMA,
    PRODUCT_WIFI_DIRECT_TOPOLOGY_CONTRACT, SIGNED_PEER_TOPOLOGY_AUTHORIZATION_SCHEMA,
};

/// Direct-lane lease state schema.
pub const DIRECT_LANE_LEASE_STATE_SCHEMA: &str = "rusty.manifold.peer.direct_lane_lease_state.v1";
/// Direct-lane lease request schema.
pub const DIRECT_LANE_LEASE_REQUEST_SCHEMA: &str =
    "rusty.manifold.peer.direct_lane_lease_request.v1";
/// Direct-lane lease record schema.
pub const DIRECT_LANE_LEASE_RECORD_SCHEMA: &str = "rusty.manifold.peer.direct_lane_lease_record.v1";
/// Direct-lane lease receipt schema.
pub const DIRECT_LANE_LEASE_RECEIPT_SCHEMA: &str =
    "rusty.manifold.peer.direct_lane_lease_receipt.v1";
/// Direct-lane lease revocation schema.
pub const DIRECT_LANE_LEASE_REVOCATION_SCHEMA: &str =
    "rusty.manifold.peer.direct_lane_lease_revocation.v1";

const MAX_DIRECT_LANE_LEASE_TTL_MS: u64 = 120_000;

/// Authority scope of a direct-lane lease.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldDirectLaneLeaseScope {
    /// Authorizes the accepted pair/session route only.
    PeerSession,
    /// Also binds an accepted generic media-session reference.
    MediaSession,
}

/// Revisioned request to issue one direct-lane lease.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldDirectLaneLeaseRequest {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Replay-protected request id.
    pub request_id: DottedId,
    /// Expected lease authority revision.
    pub expected_lease_authority_revision: Revision,
    /// Exact mesh authority revision being consumed.
    pub expected_mesh_authority_revision: Revision,
    /// Exact enrollment authority revision being consumed.
    pub expected_enrollment_authority_revision: Revision,
    /// Exact signed-rendezvous authority revision being consumed.
    pub expected_rendezvous_authority_revision: Revision,
    /// Exact peer-session authority revision being consumed.
    pub expected_peer_session_authority_revision: Revision,
    /// Exact media-session authority revision, only for media scope.
    pub expected_media_session_authority_revision: Option<Revision>,
    /// Accepted mesh identity.
    pub mesh_id: DottedId,
    /// Selected route candidate identity.
    pub selected_route_id: DottedId,
    /// Canonical lower peer identity.
    pub first_peer_id: DottedId,
    /// Canonical upper peer identity.
    pub second_peer_id: DottedId,
    /// Accepted peer session identity.
    pub peer_session_id: DottedId,
    /// Optional accepted generic media-session identity.
    pub media_session_id: Option<DottedId>,
    /// Requested authority scope.
    pub scope: ManifoldDirectLaneLeaseScope,
    /// Requested expiry.
    pub expires_at_ms: u64,
}

/// Accepted Manifold direct-lane lease.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldDirectLaneLease {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Stable derived lease identity.
    pub lease_id: DottedId,
    /// Request that created the lease.
    pub request_id: DottedId,
    /// Accepted mesh identity and revision.
    pub mesh_id: DottedId,
    /// Accepted mesh authority revision.
    pub mesh_authority_revision: Revision,
    /// Enrollment authority revision backing the signer keys.
    pub enrollment_authority_revision: Revision,
    /// Selected direct route identity.
    pub selected_route_id: DottedId,
    /// Canonical peer pair.
    pub peer_ids: Vec<DottedId>,
    /// Accepted peer session identity and revision.
    pub peer_session_id: DottedId,
    /// Peer-session authority revision.
    pub peer_session_authority_revision: Revision,
    /// Signed rendezvous receipt that anchored the peer session.
    pub rendezvous_receipt_id: DottedId,
    /// Rendezvous authority revision.
    pub rendezvous_authority_revision: Revision,
    /// Optional accepted generic media-session reference.
    pub media_session_id: Option<DottedId>,
    /// Optional accepted generic media-session authority revision.
    pub media_session_authority_revision: Option<Revision>,
    /// Lease authority scope.
    pub scope: ManifoldDirectLaneLeaseScope,
    /// Lease validity start.
    pub valid_from_ms: u64,
    /// Lease validity end.
    pub expires_at_ms: u64,
    /// Explicit revocation state.
    pub revoked: bool,
}

/// Manifold-owned direct-lane lease state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldDirectLaneLeaseState {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Current lease authority revision.
    pub authority_revision: Revision,
    /// Issued leases, including revoked history.
    pub leases: Vec<ManifoldDirectLaneLease>,
    /// Applied request ids retained for replay rejection.
    pub applied_request_ids: Vec<DottedId>,
}

impl ManifoldDirectLaneLeaseState {
    /// Creates an empty revision-one lease authority.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            schema_id: schema(DIRECT_LANE_LEASE_STATE_SCHEMA),
            authority_revision: Revision::INITIAL,
            leases: Vec::new(),
            applied_request_ids: Vec::new(),
        }
    }
}

/// Current accepted authorities consumed by direct-lane issuance and use.
#[derive(Clone, Copy, Debug)]
pub struct ManifoldDirectLaneLeaseAuthorityContext<'a> {
    /// Current operator-mediated enrollment state.
    pub enrollment: &'a ManifoldPeerEnrollmentState,
    /// Current retained signed-rendezvous state.
    pub rendezvous: &'a ManifoldRendezvousAuthorityState,
    /// Current accepted peer mesh.
    pub mesh: &'a ManifoldPeerMeshState,
    /// Current accepted peer-session state.
    pub peer_sessions: &'a ManifoldPeerSessionState,
    /// Signed topology authorization emitted for the accepted peer session.
    pub topology: &'a ManifoldSignedPeerTopologyAuthorization,
    /// Accepted media descriptor when media scope is requested.
    pub media_session: Option<&'a ManifoldMediaSessionDescriptor>,
}

/// Stable issuance rejection reason.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldDirectLaneLeaseRejectionReason {
    /// Schema mismatch.
    SchemaMismatch,
    /// Lease, mesh, or peer-session revision mismatched.
    StaleAuthorityRevision,
    /// Request id was already applied.
    ReplayedRequest,
    /// Mesh identity or membership was not current.
    InvalidMesh,
    /// Selected route was absent, ineligible, or not direct.
    RouteNotEligible,
    /// Request pair was not canonical or did not match the route/session.
    PeerPairMismatch,
    /// Signed topology authorization was denied, stale, or mismatched.
    TopologyNotAuthorized,
    /// Scope and media-session reference did not form a closed selection.
    ScopeMismatch,
    /// Media scope did not name an exact valid accepted descriptor and revision.
    MediaSessionNotAccepted,
    /// Requested validity was empty, too long, or outlived source authority.
    InvalidExpiry,
    /// An equivalent live lease already exists.
    ActiveLeaseExists,
    /// Authority revision could not advance.
    RevisionExhausted,
    /// Supplied lease state violated identity, replay, or scope invariants.
    InvalidAuthorityState,
}

/// Audit-bearing issuance receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldDirectLaneLeaseReceipt {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Derived receipt id.
    pub receipt_id: DottedId,
    /// Reviewed request id.
    pub request_id: DottedId,
    /// Whether a lease was issued.
    pub applied: bool,
    /// Stable rejection reason.
    pub rejection_reason: Option<ManifoldDirectLaneLeaseRejectionReason>,
    /// Issued lease when applied.
    pub lease: Option<ManifoldDirectLaneLease>,
    /// Prior lease authority revision.
    pub prior_authority_revision: Revision,
    /// Resulting lease authority revision.
    pub resulting_authority_revision: Revision,
}

/// Explicit direct-lane lease revocation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldDirectLaneLeaseRevocation {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Replay-protected revocation identity.
    pub revocation_id: DottedId,
    /// Lease being revoked.
    pub lease_id: DottedId,
    /// Expected lease authority revision.
    pub expected_authority_revision: Revision,
}

/// Issue a real session/media lease from current mesh and signed topology
/// authority. Rejections return an unchanged state plus a typed receipt.
#[must_use]
pub fn review_and_apply_direct_lane_lease(
    state: &ManifoldDirectLaneLeaseState,
    authority: &ManifoldDirectLaneLeaseAuthorityContext<'_>,
    request: &ManifoldDirectLaneLeaseRequest,
    now_ms: u64,
) -> (ManifoldDirectLaneLeaseState, ManifoldDirectLaneLeaseReceipt) {
    let prior = state.authority_revision;
    let rejection = validate_request(state, authority, request, now_ms)
        .err()
        .or_else(|| {
            prior
                .next()
                .is_none()
                .then_some(ManifoldDirectLaneLeaseRejectionReason::RevisionExhausted)
        });
    if let Some(reason) = rejection {
        return (
            state.clone(),
            receipt(request, false, Some(reason), None, prior, prior),
        );
    }

    let resulting_revision = prior.next().unwrap_or(prior);
    let lease = ManifoldDirectLaneLease {
        schema_id: schema(DIRECT_LANE_LEASE_RECORD_SCHEMA),
        lease_id: derived("lease.peer.direct", &request.request_id),
        request_id: request.request_id.clone(),
        mesh_id: request.mesh_id.clone(),
        mesh_authority_revision: request.expected_mesh_authority_revision,
        enrollment_authority_revision: request.expected_enrollment_authority_revision,
        selected_route_id: request.selected_route_id.clone(),
        peer_ids: vec![
            request.first_peer_id.clone(),
            request.second_peer_id.clone(),
        ],
        peer_session_id: request.peer_session_id.clone(),
        peer_session_authority_revision: request.expected_peer_session_authority_revision,
        rendezvous_receipt_id: authority.topology.rendezvous_receipt_id.clone(),
        rendezvous_authority_revision: authority.topology.rendezvous_authority_revision,
        media_session_id: request.media_session_id.clone(),
        media_session_authority_revision: request.expected_media_session_authority_revision,
        scope: request.scope.clone(),
        valid_from_ms: now_ms,
        expires_at_ms: request.expires_at_ms,
        revoked: false,
    };
    let mut next = state.clone();
    next.authority_revision = resulting_revision;
    next.leases.push(lease.clone());
    next.applied_request_ids.push(request.request_id.clone());
    (
        next,
        receipt(request, true, None, Some(lease), prior, resulting_revision),
    )
}

fn validate_request(
    state: &ManifoldDirectLaneLeaseState,
    authority: &ManifoldDirectLaneLeaseAuthorityContext<'_>,
    request: &ManifoldDirectLaneLeaseRequest,
    now_ms: u64,
) -> Result<(), ManifoldDirectLaneLeaseRejectionReason> {
    validate_authority_headers(state, authority, request)?;
    if state.applied_request_ids.contains(&request.request_id) {
        return Err(ManifoldDirectLaneLeaseRejectionReason::ReplayedRequest);
    }
    let member_expiry = validate_mesh_route(authority.mesh, request, now_ms)?;
    let topology_expiry = validate_topology_authority(authority, request, now_ms)?;
    validate_media_scope(authority.media_session, request)?;
    if request.expires_at_ms <= now_ms
        || request.expires_at_ms > topology_expiry
        || request.expires_at_ms > member_expiry
        || request.expires_at_ms.saturating_sub(now_ms) > MAX_DIRECT_LANE_LEASE_TTL_MS
    {
        return Err(ManifoldDirectLaneLeaseRejectionReason::InvalidExpiry);
    }
    if state.leases.iter().any(|lease| {
        !lease.revoked
            && lease.expires_at_ms > now_ms
            && lease.selected_route_id == request.selected_route_id
            && lease.peer_session_id == request.peer_session_id
            && lease.media_session_id == request.media_session_id
    }) {
        return Err(ManifoldDirectLaneLeaseRejectionReason::ActiveLeaseExists);
    }
    Ok(())
}

fn validate_authority_headers(
    state: &ManifoldDirectLaneLeaseState,
    authority: &ManifoldDirectLaneLeaseAuthorityContext<'_>,
    request: &ManifoldDirectLaneLeaseRequest,
) -> Result<(), ManifoldDirectLaneLeaseRejectionReason> {
    let topology = authority.topology;
    if state.schema_id.as_str() != DIRECT_LANE_LEASE_STATE_SCHEMA
        || request.schema_id.as_str() != DIRECT_LANE_LEASE_REQUEST_SCHEMA
        || authority.enrollment.schema_id.as_str() != crate::PEER_ENROLLMENT_STATE_SCHEMA
        || authority.rendezvous.schema_id.as_str() != crate::RENDEZVOUS_AUTHORITY_STATE_SCHEMA
        || authority.mesh.schema_id.as_str() != PEER_MESH_STATE_SCHEMA
        || authority.peer_sessions.schema_id.as_str() != PEER_SESSION_SNAPSHOT_SCHEMA
        || topology.schema_id.as_str() != SIGNED_PEER_TOPOLOGY_AUTHORIZATION_SCHEMA
        || topology.topology_authorization.schema_id.as_str() != PEER_TOPOLOGY_AUTHORIZATION_SCHEMA
    {
        return Err(ManifoldDirectLaneLeaseRejectionReason::SchemaMismatch);
    }
    if !direct_lane_state_is_well_formed(state) {
        return Err(ManifoldDirectLaneLeaseRejectionReason::InvalidAuthorityState);
    }
    if request.expected_lease_authority_revision != state.authority_revision
        || request.expected_enrollment_authority_revision != authority.enrollment.authority_revision
        || request.expected_rendezvous_authority_revision != authority.rendezvous.authority_revision
        || request.expected_mesh_authority_revision != authority.mesh.authority_revision
        || request.expected_peer_session_authority_revision
            != authority.peer_sessions.authority_revision
        || topology.topology_authorization.authority_revision
            != authority.peer_sessions.authority_revision
        || topology.enrollment_authority_revision != authority.enrollment.authority_revision
        || topology.rendezvous_authority_revision != authority.rendezvous.authority_revision
    {
        return Err(ManifoldDirectLaneLeaseRejectionReason::StaleAuthorityRevision);
    }
    Ok(())
}

fn direct_lane_state_is_well_formed(state: &ManifoldDirectLaneLeaseState) -> bool {
    let request_ids = state.applied_request_ids.iter().collect::<BTreeSet<_>>();
    let lease_ids = state
        .leases
        .iter()
        .map(|lease| &lease.lease_id)
        .collect::<BTreeSet<_>>();
    let lease_request_ids = state
        .leases
        .iter()
        .map(|lease| &lease.request_id)
        .collect::<BTreeSet<_>>();
    request_ids.len() == state.applied_request_ids.len()
        && lease_ids.len() == state.leases.len()
        && lease_request_ids.len() == state.leases.len()
        && state.leases.iter().all(|lease| {
            lease.schema_id.as_str() == DIRECT_LANE_LEASE_RECORD_SCHEMA
                && state.applied_request_ids.contains(&lease.request_id)
                && lease.peer_ids.len() == 2
                && lease.peer_ids[0] < lease.peer_ids[1]
                && lease.valid_from_ms < lease.expires_at_ms
                && matches!(
                    (
                        &lease.scope,
                        &lease.media_session_id,
                        lease.media_session_authority_revision
                    ),
                    (ManifoldDirectLaneLeaseScope::PeerSession, None, None)
                        | (ManifoldDirectLaneLeaseScope::MediaSession, Some(_), Some(_))
                )
        })
}

fn validate_mesh_route(
    mesh: &ManifoldPeerMeshState,
    request: &ManifoldDirectLaneLeaseRequest,
    now_ms: u64,
) -> Result<u64, ManifoldDirectLaneLeaseRejectionReason> {
    if request.first_peer_id >= request.second_peer_id {
        return Err(ManifoldDirectLaneLeaseRejectionReason::PeerPairMismatch);
    }
    let member_ids = mesh
        .members
        .iter()
        .map(|member| &member.peer_id)
        .collect::<BTreeSet<_>>();
    let route_ids = mesh
        .selected_routes
        .iter()
        .map(|route| &route.candidate_id)
        .collect::<BTreeSet<_>>();
    let pair_members = mesh
        .members
        .iter()
        .filter(|member| {
            member.peer_id == request.first_peer_id || member.peer_id == request.second_peer_id
        })
        .collect::<Vec<_>>();
    if mesh.mesh_id.as_ref() != Some(&request.mesh_id)
        || mesh.members.len() < 2
        || member_ids.len() != mesh.members.len()
        || route_ids.len() != mesh.selected_routes.len()
        || pair_members.len() != 2
        || pair_members
            .iter()
            .any(|member| member.expires_at_ms <= now_ms)
        || mesh.revoked_peer_ids.contains(&request.first_peer_id)
        || mesh.revoked_peer_ids.contains(&request.second_peer_id)
    {
        return Err(ManifoldDirectLaneLeaseRejectionReason::InvalidMesh);
    }
    let route = mesh
        .selected_routes
        .iter()
        .find(|route| route.candidate_id == request.selected_route_id)
        .ok_or(ManifoldDirectLaneLeaseRejectionReason::RouteNotEligible)?;
    if !route.direct_media_lane_eligible
        || route.route_contract_id.as_str() != DIRECT_P2P_ROUTE_CONTRACT
    {
        return Err(ManifoldDirectLaneLeaseRejectionReason::RouteNotEligible);
    }
    if route.first_peer_id != request.first_peer_id
        || route.second_peer_id != request.second_peer_id
    {
        return Err(ManifoldDirectLaneLeaseRejectionReason::PeerPairMismatch);
    }
    pair_members
        .iter()
        .map(|member| member.expires_at_ms)
        .min()
        .ok_or(ManifoldDirectLaneLeaseRejectionReason::InvalidMesh)
}

fn validate_topology_authority(
    authority: &ManifoldDirectLaneLeaseAuthorityContext<'_>,
    request: &ManifoldDirectLaneLeaseRequest,
    now_ms: u64,
) -> Result<u64, ManifoldDirectLaneLeaseRejectionReason> {
    let topology = authority.topology;
    let authorization = &topology.topology_authorization;
    let mut authorized_pair = vec![
        authorization.group_owner_peer_id.clone(),
        authorization.client_peer_id.clone(),
    ];
    authorized_pair.sort();
    if !authorization.authorized
        || authorization.denial_reason.is_some()
        || authorization.session_id != request.peer_session_id
        || authorized_pair
            != [
                request.first_peer_id.clone(),
                request.second_peer_id.clone(),
            ]
        || authorization.topology_contract_id.as_str() != PRODUCT_WIFI_DIRECT_TOPOLOGY_CONTRACT
        || authorization.valid_from_ms > now_ms
        || authorization.expires_at_ms <= now_ms
    {
        return Err(ManifoldDirectLaneLeaseRejectionReason::TopologyNotAuthorized);
    }
    let accepted_session = authority
        .peer_sessions
        .sessions
        .iter()
        .find(|session| session.proposal.session_id == request.peer_session_id && !session.revoked)
        .ok_or(ManifoldDirectLaneLeaseRejectionReason::TopologyNotAuthorized)?;
    let proposal = &accepted_session.proposal;
    if authority
        .peer_sessions
        .revoked_session_ids
        .contains(&request.peer_session_id)
        || proposal.schema_id.as_str() != PEER_SESSION_PROPOSAL_SCHEMA
        || accepted_session.rendezvous_receipt_id.as_ref() != Some(&topology.rendezvous_receipt_id)
        || accepted_session.decision_id != authorization.decision_id
        || proposal.proposal_id != authorization.proposal_id
        || proposal.group_owner_peer_id != authorization.group_owner_peer_id
        || proposal.client_peer_id != authorization.client_peer_id
        || proposal.topology_contract_id != authorization.topology_contract_id
        || proposal.expires_at_ms <= now_ms
    {
        return Err(ManifoldDirectLaneLeaseRejectionReason::TopologyNotAuthorized);
    }
    let receipt = authority
        .rendezvous
        .accepted_receipts
        .iter()
        .find(|receipt| receipt.receipt_id == topology.rendezvous_receipt_id)
        .ok_or(ManifoldDirectLaneLeaseRejectionReason::TopologyNotAuthorized)?;
    validate_current_rendezvous_receipt(
        authority.rendezvous,
        authority.enrollment,
        receipt,
        &authorization.group_owner_peer_id,
        &authorization.client_peer_id,
        now_ms,
    )
    .map_err(|error| match error {
        ManifoldRendezvousReceiptValidationError::SchemaMismatch => {
            ManifoldDirectLaneLeaseRejectionReason::SchemaMismatch
        }
        ManifoldRendezvousReceiptValidationError::StaleAuthorityRevision => {
            ManifoldDirectLaneLeaseRejectionReason::StaleAuthorityRevision
        }
        ManifoldRendezvousReceiptValidationError::ReceiptNotRetained
        | ManifoldRendezvousReceiptValidationError::InvalidReceipt
        | ManifoldRendezvousReceiptValidationError::CredentialNotCurrent => {
            ManifoldDirectLaneLeaseRejectionReason::TopologyNotAuthorized
        }
    })?;
    if topology.signer_key_ids != receipt.signer_key_ids {
        return Err(ManifoldDirectLaneLeaseRejectionReason::TopologyNotAuthorized);
    }
    Ok(authorization
        .expires_at_ms
        .min(proposal.expires_at_ms)
        .min(receipt.expires_at_ms))
}

fn validate_media_scope(
    media_session: Option<&ManifoldMediaSessionDescriptor>,
    request: &ManifoldDirectLaneLeaseRequest,
) -> Result<(), ManifoldDirectLaneLeaseRejectionReason> {
    match (
        &request.scope,
        &request.media_session_id,
        request.expected_media_session_authority_revision,
        media_session,
    ) {
        (ManifoldDirectLaneLeaseScope::PeerSession, None, None, None) => {}
        (
            ManifoldDirectLaneLeaseScope::MediaSession,
            Some(media_session_id),
            Some(media_revision),
            Some(media_session),
        ) if media_session.validate().is_ok()
            && &media_session.session_id == media_session_id
            && media_session.authority_revision == media_revision
            && media_session.route_ids.contains(&request.selected_route_id) => {}
        (ManifoldDirectLaneLeaseScope::PeerSession, ..)
        | (ManifoldDirectLaneLeaseScope::MediaSession, None, ..)
        | (ManifoldDirectLaneLeaseScope::MediaSession, _, None, _) => {
            return Err(ManifoldDirectLaneLeaseRejectionReason::ScopeMismatch);
        }
        _ => {
            return Err(ManifoldDirectLaneLeaseRejectionReason::MediaSessionNotAccepted);
        }
    }
    Ok(())
}

/// Revalidate one stored lease against current enrollment, rendezvous, mesh,
/// peer-session, topology, and optional media authority before platform use.
///
/// # Errors
///
/// Returns the same typed rejection family used at issuance when the lease is
/// absent, revoked, expired, malformed, or stale against any source authority.
pub fn validate_current_direct_lane_lease(
    state: &ManifoldDirectLaneLeaseState,
    authority: &ManifoldDirectLaneLeaseAuthorityContext<'_>,
    lease_id: &DottedId,
    now_ms: u64,
) -> Result<(), ManifoldDirectLaneLeaseRejectionReason> {
    let lease = state
        .leases
        .iter()
        .find(|lease| &lease.lease_id == lease_id)
        .ok_or(ManifoldDirectLaneLeaseRejectionReason::TopologyNotAuthorized)?;
    if lease.schema_id.as_str() != DIRECT_LANE_LEASE_RECORD_SCHEMA
        || lease.revoked
        || lease.valid_from_ms > now_ms
        || lease.expires_at_ms <= now_ms
        || lease.peer_ids.len() != 2
    {
        return Err(ManifoldDirectLaneLeaseRejectionReason::InvalidExpiry);
    }
    let mut validation_state = state.clone();
    validation_state
        .leases
        .retain(|candidate| candidate.lease_id != *lease_id);
    validation_state
        .applied_request_ids
        .retain(|request_id| request_id != &lease.request_id);
    let request = ManifoldDirectLaneLeaseRequest {
        schema_id: schema(DIRECT_LANE_LEASE_REQUEST_SCHEMA),
        request_id: lease.request_id.clone(),
        expected_lease_authority_revision: state.authority_revision,
        expected_mesh_authority_revision: lease.mesh_authority_revision,
        expected_enrollment_authority_revision: lease.enrollment_authority_revision,
        expected_rendezvous_authority_revision: lease.rendezvous_authority_revision,
        expected_peer_session_authority_revision: lease.peer_session_authority_revision,
        expected_media_session_authority_revision: lease.media_session_authority_revision,
        mesh_id: lease.mesh_id.clone(),
        selected_route_id: lease.selected_route_id.clone(),
        first_peer_id: lease.peer_ids[0].clone(),
        second_peer_id: lease.peer_ids[1].clone(),
        peer_session_id: lease.peer_session_id.clone(),
        media_session_id: lease.media_session_id.clone(),
        scope: lease.scope.clone(),
        expires_at_ms: lease.expires_at_ms,
    };
    validate_request(&validation_state, authority, &request, now_ms)
}

/// Revoke an active direct-lane lease and advance authority revision.
///
/// # Errors
///
/// Returns an error for schema/revision mismatch, a missing active lease, or
/// authority-revision exhaustion.
pub fn revoke_direct_lane_lease(
    state: &ManifoldDirectLaneLeaseState,
    request: &ManifoldDirectLaneLeaseRevocation,
) -> Result<ManifoldDirectLaneLeaseState, String> {
    if state.schema_id.as_str() != DIRECT_LANE_LEASE_STATE_SCHEMA
        || request.schema_id.as_str() != DIRECT_LANE_LEASE_REVOCATION_SCHEMA
    {
        return Err("direct-lane lease schema mismatch".to_owned());
    }
    if !direct_lane_state_is_well_formed(state) {
        return Err("direct-lane lease authority state invalid".to_owned());
    }
    if request.expected_authority_revision != state.authority_revision {
        return Err("direct-lane lease authority revision mismatch".to_owned());
    }
    if state.applied_request_ids.contains(&request.revocation_id) {
        return Err("direct-lane lease revocation replay".to_owned());
    }
    let mut next = state.clone();
    let lease = next
        .leases
        .iter_mut()
        .find(|lease| lease.lease_id == request.lease_id && !lease.revoked)
        .ok_or_else(|| "active direct-lane lease not found".to_owned())?;
    lease.revoked = true;
    next.authority_revision = next
        .authority_revision
        .next()
        .ok_or_else(|| "direct-lane lease authority revision overflow".to_owned())?;
    next.applied_request_ids.push(request.revocation_id.clone());
    Ok(next)
}

/// Consume one replay-protected sweep and mark every expired direct-lane lease
/// revoked. Every accepted sweep advances revision, including a no-op sweep.
///
/// # Errors
///
/// Returns an error for a state-schema mismatch, replayed sweep id, or
/// authority-revision exhaustion.
pub fn expire_direct_lane_leases(
    state: &ManifoldDirectLaneLeaseState,
    sweep_id: DottedId,
    now_ms: u64,
) -> Result<ManifoldDirectLaneLeaseState, String> {
    if state.schema_id.as_str() != DIRECT_LANE_LEASE_STATE_SCHEMA {
        return Err("direct-lane lease state schema mismatch".to_owned());
    }
    if !direct_lane_state_is_well_formed(state) {
        return Err("direct-lane lease authority state invalid".to_owned());
    }
    if state.applied_request_ids.contains(&sweep_id) {
        return Err("direct-lane lease sweep replay".to_owned());
    }
    let mut next = state.clone();
    for lease in &mut next.leases {
        if !lease.revoked && lease.expires_at_ms <= now_ms {
            lease.revoked = true;
        }
    }
    next.authority_revision = next
        .authority_revision
        .next()
        .ok_or_else(|| "direct-lane lease authority revision overflow".to_owned())?;
    next.applied_request_ids.push(sweep_id);
    Ok(next)
}

fn receipt(
    request: &ManifoldDirectLaneLeaseRequest,
    applied: bool,
    rejection_reason: Option<ManifoldDirectLaneLeaseRejectionReason>,
    lease: Option<ManifoldDirectLaneLease>,
    prior_authority_revision: Revision,
    resulting_authority_revision: Revision,
) -> ManifoldDirectLaneLeaseReceipt {
    ManifoldDirectLaneLeaseReceipt {
        schema_id: schema(DIRECT_LANE_LEASE_RECEIPT_SCHEMA),
        receipt_id: derived("receipt.peer.direct", &request.request_id),
        request_id: request.request_id.clone(),
        applied,
        rejection_reason,
        lease,
        prior_authority_revision,
        resulting_authority_revision,
    }
}

fn schema(value: &str) -> SchemaId {
    SchemaId::new(value).expect("static direct-lane lease schema")
}

fn derived(prefix: &str, suffix: &DottedId) -> DottedId {
    DottedId::new(format!("{prefix}.{}", suffix.as_str())).expect("derived direct-lane id")
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::{
        ManifoldAcceptedMeshMember, ManifoldAcceptedPeerSession, ManifoldPeerCredentialAlgorithm,
        ManifoldPeerCredentialRecord, ManifoldPeerCredentialStatus, ManifoldPeerMeshSelectedRoute,
        ManifoldPeerSessionProposal, ManifoldPeerTopologyAuthorization, ManifoldRendezvousReceipt,
        PeerRendezvousAuthenticationEvidence, PeerRendezvousTransport, PEER_CREDENTIAL_SCHEMA,
        PEER_ENROLLMENT_STATE_SCHEMA, RENDEZVOUS_AUTHORITY_STATE_SCHEMA, RENDEZVOUS_RECEIPT_SCHEMA,
    };

    fn id(value: &str) -> DottedId {
        DottedId::new(value).expect("test id")
    }

    struct AuthorityFixture {
        enrollment: ManifoldPeerEnrollmentState,
        rendezvous: ManifoldRendezvousAuthorityState,
        mesh: ManifoldPeerMeshState,
        peer_sessions: ManifoldPeerSessionState,
        topology: ManifoldSignedPeerTopologyAuthorization,
        media_session: ManifoldMediaSessionDescriptor,
    }

    impl AuthorityFixture {
        fn context(&self) -> ManifoldDirectLaneLeaseAuthorityContext<'_> {
            ManifoldDirectLaneLeaseAuthorityContext {
                enrollment: &self.enrollment,
                rendezvous: &self.rendezvous,
                mesh: &self.mesh,
                peer_sessions: &self.peer_sessions,
                topology: &self.topology,
                media_session: Some(&self.media_session),
            }
        }
    }

    fn hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        output
    }

    fn credential(peer_id: &str, key_id: &str, seed: u8) -> ManifoldPeerCredentialRecord {
        let public_key = SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes();
        ManifoldPeerCredentialRecord {
            schema_id: schema(PEER_CREDENTIAL_SCHEMA),
            credential_id: id(&format!("credential.{peer_id}.1")),
            peer_id: id(peer_id),
            trust_domain: id("trust.morphospace.peer"),
            key_id: id(key_id),
            key_generation: 1,
            algorithm: ManifoldPeerCredentialAlgorithm::Ed25519,
            public_key_hex: hex(&public_key),
            public_key_sha256: format!("sha256:{}", hex(&Sha256::digest(public_key))),
            valid_from_ms: 1,
            expires_at_ms: 100_000,
            status: ManifoldPeerCredentialStatus::Active,
            replaced_by_key_id: None,
        }
    }

    fn mesh() -> ManifoldPeerMeshState {
        ManifoldPeerMeshState {
            schema_id: schema(PEER_MESH_STATE_SCHEMA),
            authority_revision: Revision::new(4).expect("revision"),
            mesh_id: Some(id("mesh.quest.product.001")),
            authority_epoch: 3,
            coordinator_peer_id: Some(id("peer.alpha")),
            members: ["peer.alpha", "peer.beta", "peer.gamma"]
                .into_iter()
                .map(|peer_id| ManifoldAcceptedMeshMember {
                    peer_id: id(peer_id),
                    status_revision: Revision::new(2).expect("revision"),
                    expires_at_ms: 90_000,
                })
                .collect(),
            selected_routes: vec![ManifoldPeerMeshSelectedRoute {
                candidate_id: id("route.alpha-beta.direct"),
                first_peer_id: id("peer.alpha"),
                second_peer_id: id("peer.beta"),
                route_contract_id: id(DIRECT_P2P_ROUTE_CONTRACT),
                observed_latency_ms: 12,
                hop_count: 1,
                direct_media_lane_eligible: true,
            }],
            applied_proposal_ids: vec![id("proposal.mesh.quest.001")],
            revoked_peer_ids: Vec::new(),
        }
    }

    fn topology() -> ManifoldSignedPeerTopologyAuthorization {
        ManifoldSignedPeerTopologyAuthorization {
            schema_id: schema(SIGNED_PEER_TOPOLOGY_AUTHORIZATION_SCHEMA),
            topology_authorization: ManifoldPeerTopologyAuthorization {
                schema_id: schema(PEER_TOPOLOGY_AUTHORIZATION_SCHEMA),
                decision_id: id("decision.peer-session.alpha-beta.001"),
                session_id: id("session.peer.alpha-beta.001"),
                proposal_id: id("proposal.peer-session.alpha-beta.001"),
                authority_revision: Revision::new(5).expect("revision"),
                group_owner_peer_id: id("peer.alpha"),
                client_peer_id: id("peer.beta"),
                topology_contract_id: id("rusty.quest.product_wifi_direct_topology.v1"),
                authorized: true,
                valid_from_ms: 2_000,
                expires_at_ms: 60_000,
                denial_reason: None,
            },
            rendezvous_receipt_id: id("receipt.peer.rendezvous.alpha-beta.001"),
            rendezvous_authority_revision: Revision::new(3).expect("revision"),
            enrollment_authority_revision: Revision::new(3).expect("revision"),
            signer_key_ids: vec![id("key.peer.alpha.001"), id("key.peer.beta.001")],
        }
    }

    fn authority_fixture() -> AuthorityFixture {
        let topology = topology();
        let receipt = ManifoldRendezvousReceipt {
            schema_id: schema(RENDEZVOUS_RECEIPT_SCHEMA),
            receipt_id: topology.rendezvous_receipt_id.clone(),
            request_id: id("request.peer.rendezvous.alpha-beta.001"),
            accepted: true,
            rejection_reason: None,
            peer_ids: vec![id("peer.alpha"), id("peer.beta")],
            group_owner_peer_id: Some(id("peer.alpha")),
            client_peer_id: Some(id("peer.beta")),
            signer_key_ids: topology.signer_key_ids.clone(),
            evidence_ids: vec![id("evidence.peer.alpha.001"), id("evidence.peer.beta.001")],
            nonce_sha256: format!("sha256:{}", "a1".repeat(32)),
            coordinator_epoch: 7,
            topology_contract_id: id(PRODUCT_WIFI_DIRECT_TOPOLOGY_CONTRACT),
            enrollment_authority_revision: Revision::new(3).expect("revision"),
            prior_authority_revision: Revision::new(2).expect("revision"),
            resulting_authority_revision: Revision::new(3).expect("revision"),
            expires_at_ms: 60_000,
        };
        let proposal = ManifoldPeerSessionProposal {
            schema_id: schema(PEER_SESSION_PROPOSAL_SCHEMA),
            proposal_id: id("proposal.peer-session.alpha-beta.001"),
            session_id: id("session.peer.alpha-beta.001"),
            expected_authority_revision: Revision::new(4).expect("revision"),
            subject_peer_id: id("peer.alpha"),
            candidate_peer_id: id("peer.beta"),
            group_owner_peer_id: id("peer.alpha"),
            client_peer_id: id("peer.beta"),
            requested_capability_ids: vec![id("capability.peer.presence")],
            topology_contract_id: id(PRODUCT_WIFI_DIRECT_TOPOLOGY_CONTRACT),
            expires_at_ms: 60_000,
            authentication: PeerRendezvousAuthenticationEvidence {
                adapter_id: id("adapter.quest.ble"),
                transport: PeerRendezvousTransport::BleGattAuthenticated,
                evidence_digest: id("digest.rendezvous.alpha-beta.001"),
                authenticated: true,
                authenticated_messages: 4,
                authentication_failures: 0,
                role_swap_completed: true,
                reconnects_completed: 2,
                observed_at_ms: 2_000,
                expires_at_ms: 60_000,
            },
        };
        AuthorityFixture {
            enrollment: ManifoldPeerEnrollmentState {
                schema_id: schema(PEER_ENROLLMENT_STATE_SCHEMA),
                authority_revision: Revision::new(3).expect("revision"),
                credentials: vec![
                    credential("peer.alpha", "key.peer.alpha.001", 7),
                    credential("peer.beta", "key.peer.beta.001", 11),
                ],
                applied_request_ids: Vec::new(),
            },
            rendezvous: ManifoldRendezvousAuthorityState {
                schema_id: schema(RENDEZVOUS_AUTHORITY_STATE_SCHEMA),
                authority_revision: Revision::new(3).expect("revision"),
                applied_request_ids: vec![receipt.request_id.clone()],
                consumed_evidence_ids: receipt.evidence_ids.clone(),
                consumed_nonce_sha256: vec![receipt.nonce_sha256.clone()],
                accepted_receipts: vec![receipt.clone()],
            },
            mesh: mesh(),
            peer_sessions: ManifoldPeerSessionState {
                schema_id: schema(PEER_SESSION_SNAPSHOT_SCHEMA),
                authority_revision: Revision::new(5).expect("revision"),
                sessions: vec![ManifoldAcceptedPeerSession {
                    proposal,
                    decision_id: id("decision.peer-session.alpha-beta.001"),
                    revoked: false,
                    rendezvous_receipt_id: Some(receipt.receipt_id),
                }],
                applied_proposal_ids: vec![id("proposal.peer-session.alpha-beta.001")],
                revoked_session_ids: Vec::new(),
            },
            topology,
            media_session: ManifoldMediaSessionDescriptor {
                schema_id: rusty_manifold_model::SchemaId::new(
                    rusty_manifold_model::MANIFOLD_MEDIA_SESSION_SCHEMA,
                )
                .expect("schema"),
                session_id: id("session.media.quest-pair.001"),
                authority_revision: Revision::new(6).expect("revision"),
                platform_runtime_spec_id: id("runtime.quest.direct-p2p"),
                source_ids: vec![id("source.quest.camera.alpha")],
                processor_ids: vec![id("processor.quest.layout.passthrough")],
                route_ids: vec![id("route.alpha-beta.direct")],
                sink_ids: vec![id("sink.quest.beta")],
                stream_ids: vec![id("stream.quest.camera.alpha-beta")],
                payload_plane: rusty_manifold_model::MANIFOLD_BINARY_MEDIA_PLANE.to_owned(),
                inline_media_payloads_allowed: false,
                remote_camera_compatibility: false,
            },
        }
    }

    fn request() -> ManifoldDirectLaneLeaseRequest {
        ManifoldDirectLaneLeaseRequest {
            schema_id: schema(DIRECT_LANE_LEASE_REQUEST_SCHEMA),
            request_id: id("request.direct-lane.alpha-beta.001"),
            expected_lease_authority_revision: Revision::INITIAL,
            expected_mesh_authority_revision: Revision::new(4).expect("revision"),
            expected_enrollment_authority_revision: Revision::new(3).expect("revision"),
            expected_rendezvous_authority_revision: Revision::new(3).expect("revision"),
            expected_peer_session_authority_revision: Revision::new(5).expect("revision"),
            expected_media_session_authority_revision: Some(Revision::new(6).expect("revision")),
            mesh_id: id("mesh.quest.product.001"),
            selected_route_id: id("route.alpha-beta.direct"),
            first_peer_id: id("peer.alpha"),
            second_peer_id: id("peer.beta"),
            peer_session_id: id("session.peer.alpha-beta.001"),
            media_session_id: Some(id("session.media.quest-pair.001")),
            scope: ManifoldDirectLaneLeaseScope::MediaSession,
            expires_at_ms: 50_000,
        }
    }

    #[test]
    fn eligible_route_becomes_a_revisioned_real_media_lease() {
        let state = ManifoldDirectLaneLeaseState::empty();
        let authority = authority_fixture();
        let (next, receipt) =
            review_and_apply_direct_lane_lease(&state, &authority.context(), &request(), 3_000);
        assert!(receipt.applied);
        assert_eq!(next.authority_revision.get(), 2);
        let lease = receipt.lease.expect("lease");
        assert_eq!(
            lease.media_session_id,
            Some(id("session.media.quest-pair.001"))
        );
        assert_eq!(
            lease.rendezvous_receipt_id,
            id("receipt.peer.rendezvous.alpha-beta.001")
        );
        assert!(!lease.revoked);
    }

    #[test]
    fn eligibility_boolean_never_bypasses_session_scope_or_authority() {
        let baseline = request();
        let authority = authority_fixture();
        let cases = [
            {
                let mut value = baseline.clone();
                value.media_session_id = None;
                (value, ManifoldDirectLaneLeaseRejectionReason::ScopeMismatch)
            },
            {
                let mut value = baseline.clone();
                value.expected_mesh_authority_revision = Revision::new(3).expect("revision");
                (
                    value,
                    ManifoldDirectLaneLeaseRejectionReason::StaleAuthorityRevision,
                )
            },
            {
                let mut value = baseline.clone();
                value.first_peer_id = id("peer.beta");
                value.second_peer_id = id("peer.alpha");
                (
                    value,
                    ManifoldDirectLaneLeaseRejectionReason::PeerPairMismatch,
                )
            },
            {
                let mut value = baseline.clone();
                value.expires_at_ms = 70_000;
                (value, ManifoldDirectLaneLeaseRejectionReason::InvalidExpiry)
            },
        ];
        for (request, expected) in cases {
            let state = ManifoldDirectLaneLeaseState::empty();
            let (unchanged, receipt) =
                review_and_apply_direct_lane_lease(&state, &authority.context(), &request, 3_000);
            assert_eq!(unchanged, state);
            assert_eq!(receipt.rejection_reason, Some(expected));
        }

        let mut ineligible_authority = authority_fixture();
        ineligible_authority.mesh.selected_routes[0].direct_media_lane_eligible = false;
        let (_, receipt) = review_and_apply_direct_lane_lease(
            &ManifoldDirectLaneLeaseState::empty(),
            &ineligible_authority.context(),
            &baseline,
            3_000,
        );
        assert_eq!(
            receipt.rejection_reason,
            Some(ManifoldDirectLaneLeaseRejectionReason::RouteNotEligible)
        );

        let mut denied_authority = authority_fixture();
        denied_authority.topology.topology_authorization.authorized = false;
        let (_, receipt) = review_and_apply_direct_lane_lease(
            &ManifoldDirectLaneLeaseState::empty(),
            &denied_authority.context(),
            &baseline,
            3_000,
        );
        assert_eq!(
            receipt.rejection_reason,
            Some(ManifoldDirectLaneLeaseRejectionReason::TopologyNotAuthorized)
        );
    }

    #[test]
    fn pair_membership_roles_provenance_and_current_keys_fail_closed() {
        let baseline = request();
        let cases = [
            {
                let mut authority = authority_fixture();
                authority
                    .mesh
                    .members
                    .retain(|member| member.peer_id != id("peer.beta"));
                (
                    authority,
                    ManifoldDirectLaneLeaseRejectionReason::InvalidMesh,
                )
            },
            {
                let mut authority = authority_fixture();
                authority.mesh.revoked_peer_ids.push(id("peer.beta"));
                (
                    authority,
                    ManifoldDirectLaneLeaseRejectionReason::InvalidMesh,
                )
            },
            {
                let mut authority = authority_fixture();
                authority.mesh.selected_routes[0].route_contract_id =
                    id("rusty.manifold.peer.advisory_gossip.v1");
                (
                    authority,
                    ManifoldDirectLaneLeaseRejectionReason::RouteNotEligible,
                )
            },
            {
                let mut authority = authority_fixture();
                authority.topology.topology_authorization.valid_from_ms = 4_000;
                (
                    authority,
                    ManifoldDirectLaneLeaseRejectionReason::TopologyNotAuthorized,
                )
            },
            {
                let mut authority = authority_fixture();
                authority.peer_sessions.sessions[0].revoked = true;
                authority
                    .peer_sessions
                    .revoked_session_ids
                    .push(id("session.peer.alpha-beta.001"));
                (
                    authority,
                    ManifoldDirectLaneLeaseRejectionReason::TopologyNotAuthorized,
                )
            },
            {
                let mut authority = authority_fixture();
                authority.rendezvous.accepted_receipts.clear();
                (
                    authority,
                    ManifoldDirectLaneLeaseRejectionReason::TopologyNotAuthorized,
                )
            },
            {
                let mut authority = authority_fixture();
                authority.enrollment.credentials[0].status = ManifoldPeerCredentialStatus::Revoked;
                (
                    authority,
                    ManifoldDirectLaneLeaseRejectionReason::TopologyNotAuthorized,
                )
            },
            {
                let mut authority = authority_fixture();
                authority
                    .topology
                    .topology_authorization
                    .group_owner_peer_id = id("peer.beta");
                authority.topology.topology_authorization.client_peer_id = id("peer.alpha");
                (
                    authority,
                    ManifoldDirectLaneLeaseRejectionReason::TopologyNotAuthorized,
                )
            },
        ];
        for (authority, expected) in cases {
            let state = ManifoldDirectLaneLeaseState::empty();
            let (unchanged, receipt) =
                review_and_apply_direct_lane_lease(&state, &authority.context(), &baseline, 3_000);
            assert_eq!(unchanged, state);
            assert_eq!(receipt.rejection_reason, Some(expected));
        }
    }

    #[test]
    fn unrelated_expired_member_does_not_deny_exact_live_pair() {
        let mut authority = authority_fixture();
        let gamma = authority
            .mesh
            .members
            .iter_mut()
            .find(|member| member.peer_id == id("peer.gamma"))
            .expect("gamma");
        gamma.expires_at_ms = 3_000;
        let (_, receipt) = review_and_apply_direct_lane_lease(
            &ManifoldDirectLaneLeaseState::empty(),
            &authority.context(),
            &request(),
            3_000,
        );
        assert!(receipt.applied);
    }

    #[test]
    fn media_scope_requires_exact_valid_descriptor_revision_and_route() {
        let baseline = request();
        let mut wrong_route = authority_fixture();
        wrong_route.media_session.route_ids = vec![id("route.other.direct")];
        let (_, rejected) = review_and_apply_direct_lane_lease(
            &ManifoldDirectLaneLeaseState::empty(),
            &wrong_route.context(),
            &baseline,
            3_000,
        );
        assert_eq!(
            rejected.rejection_reason,
            Some(ManifoldDirectLaneLeaseRejectionReason::MediaSessionNotAccepted)
        );

        let authority = authority_fixture();
        let mut wrong_revision = baseline.clone();
        wrong_revision.expected_media_session_authority_revision =
            Some(Revision::new(7).expect("revision"));
        let (_, rejected) = review_and_apply_direct_lane_lease(
            &ManifoldDirectLaneLeaseState::empty(),
            &authority.context(),
            &wrong_revision,
            3_000,
        );
        assert_eq!(
            rejected.rejection_reason,
            Some(ManifoldDirectLaneLeaseRejectionReason::MediaSessionNotAccepted)
        );

        let mut peer_only = baseline;
        peer_only.media_session_id = None;
        peer_only.expected_media_session_authority_revision = None;
        peer_only.scope = ManifoldDirectLaneLeaseScope::PeerSession;
        let mut context = authority.context();
        context.media_session = None;
        let (_, accepted) = review_and_apply_direct_lane_lease(
            &ManifoldDirectLaneLeaseState::empty(),
            &context,
            &peer_only,
            3_000,
        );
        assert!(accepted.applied);
    }

    #[test]
    fn replay_duplicate_revoke_and_expiry_are_stateful() {
        let state = ManifoldDirectLaneLeaseState::empty();
        let request = request();
        let authority = authority_fixture();
        let (issued, receipt) =
            review_and_apply_direct_lane_lease(&state, &authority.context(), &request, 3_000);
        let lease_id = receipt.lease.expect("lease").lease_id;
        validate_current_direct_lane_lease(&issued, &authority.context(), &lease_id, 3_100)
            .expect("current lease");

        let mut replay = request.clone();
        replay.expected_lease_authority_revision = issued.authority_revision;
        let (unchanged, replay_receipt) =
            review_and_apply_direct_lane_lease(&issued, &authority.context(), &replay, 3_100);
        assert_eq!(unchanged, issued);
        assert_eq!(
            replay_receipt.rejection_reason,
            Some(ManifoldDirectLaneLeaseRejectionReason::ReplayedRequest)
        );

        let mut duplicate = request;
        duplicate.request_id = id("request.direct-lane.alpha-beta.duplicate");
        duplicate.expected_lease_authority_revision = issued.authority_revision;
        let (_, duplicate_receipt) =
            review_and_apply_direct_lane_lease(&issued, &authority.context(), &duplicate, 3_100);
        assert_eq!(
            duplicate_receipt.rejection_reason,
            Some(ManifoldDirectLaneLeaseRejectionReason::ActiveLeaseExists)
        );

        let revoked = revoke_direct_lane_lease(
            &issued,
            &ManifoldDirectLaneLeaseRevocation {
                schema_id: schema(DIRECT_LANE_LEASE_REVOCATION_SCHEMA),
                revocation_id: id("revoke.direct-lane.alpha-beta.001"),
                lease_id: lease_id.clone(),
                expected_authority_revision: issued.authority_revision,
            },
        )
        .expect("revoke");
        assert!(revoked.leases[0].revoked);
        assert_eq!(revoked.authority_revision.get(), 3);
        assert!(validate_current_direct_lane_lease(
            &revoked,
            &authority.context(),
            &lease_id,
            3_100
        )
        .is_err());

        let (issued_again, second_receipt) = review_and_apply_direct_lane_lease(
            &revoked,
            &authority.context(),
            &ManifoldDirectLaneLeaseRequest {
                request_id: id("request.direct-lane.alpha-beta.002"),
                expected_lease_authority_revision: revoked.authority_revision,
                expires_at_ms: 4_000,
                ..duplicate
            },
            3_500,
        );
        let second_lease_id = second_receipt.lease.expect("second lease").lease_id;
        let replayed_revocation = revoke_direct_lane_lease(
            &issued_again,
            &ManifoldDirectLaneLeaseRevocation {
                schema_id: schema(DIRECT_LANE_LEASE_REVOCATION_SCHEMA),
                revocation_id: id("revoke.direct-lane.alpha-beta.001"),
                lease_id: second_lease_id,
                expected_authority_revision: issued_again.authority_revision,
            },
        );
        assert_eq!(
            replayed_revocation.expect_err("revocation replay must reject"),
            "direct-lane lease revocation replay"
        );
        let expired =
            expire_direct_lane_leases(&issued_again, id("sweep.direct-lane.expired.001"), 4_000)
                .expect("expire");
        assert!(expired.leases.iter().all(|lease| lease.revoked));
        assert_eq!(expired.authority_revision.get(), 5);
    }

    #[test]
    fn no_op_expiry_sweep_is_still_consumed_against_replay() {
        let state = ManifoldDirectLaneLeaseState::empty();
        let sweep_id = id("sweep.direct-lane.no-op.001");
        let swept = expire_direct_lane_leases(&state, sweep_id.clone(), 3_000)
            .expect("accepted no-op sweep");
        assert_eq!(swept.authority_revision.get(), 2);
        assert!(swept.leases.is_empty());
        assert_eq!(
            expire_direct_lane_leases(&swept, sweep_id, 3_100)
                .expect_err("sweep replay must reject"),
            "direct-lane lease sweep replay"
        );
    }

    #[test]
    fn lease_contract_contains_references_not_endpoints_or_payloads() {
        let authority = authority_fixture();
        let (_, receipt) = review_and_apply_direct_lane_lease(
            &ManifoldDirectLaneLeaseState::empty(),
            &authority.context(),
            &request(),
            3_000,
        );
        let text = serde_json::to_string(&receipt).expect("json");
        assert!(!text.contains("endpoint"));
        assert!(!text.contains("socket"));
        assert!(!text.contains("payload"));
        assert!(!text.contains("codec"));
        assert!(!text.contains("gossip"));
    }
}
