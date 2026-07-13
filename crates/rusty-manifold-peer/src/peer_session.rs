//! Manifold peer-session review and topology authorization.

use rusty_manifold_model::{DottedId, Revision, SchemaId};
use serde::{Deserialize, Serialize};

use crate::{
    validate_current_rendezvous_receipt, ManifoldAcceptedPeerState, ManifoldPeerAvailability,
    ManifoldPeerEnrollmentState, ManifoldPeerRole, ManifoldRendezvousAuthorityState,
    ManifoldRendezvousReceipt, ManifoldRendezvousReceiptValidationError,
};

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
/// Signed-rendezvous peer-session review schema.
pub const SIGNED_PEER_SESSION_REVIEW_SCHEMA: &str = "rusty.manifold.peer.signed_session_review.v1";
/// Signed-rendezvous topology authorization schema.
pub const SIGNED_PEER_TOPOLOGY_AUTHORIZATION_SCHEMA: &str =
    "rusty.manifold.peer.signed_topology_authorization.v1";
/// Subject-scoped current peer-session receipt schema.
pub const PEER_SESSION_CURRENT_RECEIPT_SCHEMA: &str =
    "rusty.manifold.peer.session_current_receipt.v1";
/// Product Wi-Fi Direct topology contract id.
pub const PRODUCT_WIFI_DIRECT_TOPOLOGY_CONTRACT: &str =
    "rusty.quest.product_wifi_direct_topology.v1";

const MAX_RENDEZVOUS_TTL_MS: u64 = 120_000;
const MAX_SESSION_CAPABILITIES: usize = 16;

/// Closed low-rate capability class accepted by peer-session authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldPeerSessionLowRateCapability {
    /// Low-rate peer presence/status exchange.
    PeerPresence,
    /// Low-rate N-peer mesh status exchange.
    PeerMeshStatus,
    /// Authenticated BLE rendezvous control.
    RendezvousBle,
    /// Carrier-independent reciprocal Ed25519 rendezvous control.
    RendezvousReciprocalEd25519,
    /// Wi-Fi Direct topology setup control.
    TopologyWifiDirect,
    /// Rust-owned direct P2P route setup control.
    RouteRustDirectP2p,
}

impl ManifoldPeerSessionLowRateCapability {
    fn from_id(value: &DottedId) -> Option<Self> {
        match value.as_str() {
            "capability.peer.presence" => Some(Self::PeerPresence),
            "capability.peer.mesh.status" => Some(Self::PeerMeshStatus),
            "capability.rendezvous.ble" => Some(Self::RendezvousBle),
            "capability.rendezvous.reciprocal-ed25519" => Some(Self::RendezvousReciprocalEd25519),
            "capability.topology.wifi-direct" => Some(Self::TopologyWifiDirect),
            "capability.route.rust-direct-p2p" => Some(Self::RouteRustDirectP2p),
            _ => None,
        }
    }
}

/// Authenticated low-rate rendezvous transport.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerRendezvousTransport {
    /// Quest BLE/GATT adapter with authenticated pair evidence.
    BleGattAuthenticated,
    /// Carrier-independent reciprocal Ed25519 evidence. A platform or operator
    /// transport may relay the already-signed bytes, but it cannot author the
    /// identity, signature, acceptance, topology, or direct-lane lease.
    ReciprocalEd25519,
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
    /// Signed rendezvous receipt that authorized this session. `None` is the
    /// legacy adapter-attestation compatibility path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rendezvous_receipt_id: Option<DottedId>,
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

/// Peer-session review that requires a current Manifold-signed-rendezvous
/// receipt instead of trusting an adapter Boolean as topology authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldSignedPeerSessionReviewCase {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Existing peer/session review inputs.
    pub session_review: ManifoldPeerSessionReviewCase,
    /// Accepted reciprocal-signature receipt.
    pub rendezvous_receipt: ManifoldRendezvousReceipt,
    /// Current enrollment authority whose active keys must match the receipt.
    pub current_enrollment: ManifoldPeerEnrollmentState,
    /// Current rendezvous authority that must retain the exact receipt.
    pub current_rendezvous_state: ManifoldRendezvousAuthorityState,
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
    /// Capability list was empty, duplicated, or not canonically sorted.
    InvalidCapabilitySet,
    /// Topology role assignment did not match the pair.
    InvalidTopologyRoles,
    /// Topology contract is unsupported.
    UnsupportedTopologyContract,
    /// Subject attempted to replace an active peer without revocation.
    PeerChangedWithoutRevocation,
    /// A live session identity was reused for a different pair or contract.
    SessionIdentityCollision,
    /// An accepted peer status was not Ready/current for the session window.
    StalePeerStatus,
    /// The clean product path did not carry an accepted signed-rendezvous receipt.
    SignedRendezvousRequired,
    /// Signed receipt pair, roles, contract, keys, or validity did not match.
    SignedRendezvousMismatch,
    /// Signed receipt was not issued by the current rendezvous authority revision.
    StaleRendezvousAuthority,
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

/// Topology authorization bound to the signed-rendezvous authority revision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldSignedPeerTopologyAuthorization {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Existing session authority receipt.
    pub topology_authorization: ManifoldPeerTopologyAuthorization,
    /// Signed rendezvous receipt reviewed by Manifold.
    pub rendezvous_receipt_id: DottedId,
    /// Rendezvous authority revision that accepted the pair.
    pub rendezvous_authority_revision: Revision,
    /// Enrollment authority revision whose keys signed the pair receipt.
    pub enrollment_authority_revision: Revision,
    /// Enrolled key ids used by the pair.
    pub signer_key_ids: Vec<DottedId>,
}

/// Stable current-peer-session rejection family.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldPeerSessionCurrentRejectionReason {
    /// Session or retained topology was absent.
    NotFound,
    /// Session was explicitly revoked.
    Revoked,
    /// Session/topology validity ended.
    Expired,
    /// One peer status is no longer ready/current.
    PeerNotCurrent,
    /// Reciprocal receipt or signer credentials are no longer current.
    RendezvousNotCurrent,
    /// Retained session/topology/receipt closure disagreed.
    TopologyMismatch,
}

/// Subject-scoped current receipt for low-rate peer-session consumers.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPeerSessionCurrentReceipt {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Exact session subject.
    pub session_id: DottedId,
    /// Whether every current authority check passed.
    pub current: bool,
    /// Stable rejection reason when not current.
    pub rejection_reason: Option<ManifoldPeerSessionCurrentRejectionReason>,
    /// Retained session decision when found.
    pub decision_id: Option<DottedId>,
    /// Exact reciprocal receipt when found.
    pub rendezvous_receipt_id: Option<DottedId>,
    /// Canonical peer pair.
    pub peer_ids: Vec<DottedId>,
    /// Current per-peer status revisions.
    pub peer_status_revisions: Vec<Revision>,
    /// Current signer keys.
    pub signer_key_ids: Vec<DottedId>,
    /// Exact topology contract.
    pub topology_contract_id: Option<DottedId>,
    /// Validation time.
    pub validated_at_ms: u64,
    /// Subject validity end when found.
    pub expires_at_ms: Option<u64>,
}

/// Revalidates one retained peer-session subject against current peer status,
/// credential, reciprocal receipt, revocation, and topology authority.
#[must_use]
pub fn validate_current_peer_session(
    accepted_peers: &ManifoldAcceptedPeerState,
    enrollment: &ManifoldPeerEnrollmentState,
    rendezvous: &ManifoldRendezvousAuthorityState,
    sessions: &ManifoldPeerSessionState,
    topologies: &[ManifoldSignedPeerTopologyAuthorization],
    session_id: &DottedId,
    now_ms: u64,
) -> ManifoldPeerSessionCurrentReceipt {
    let rejected = |reason| ManifoldPeerSessionCurrentReceipt {
        schema_id: schema(PEER_SESSION_CURRENT_RECEIPT_SCHEMA),
        session_id: session_id.clone(),
        current: false,
        rejection_reason: Some(reason),
        decision_id: None,
        rendezvous_receipt_id: None,
        peer_ids: Vec::new(),
        peer_status_revisions: Vec::new(),
        signer_key_ids: Vec::new(),
        topology_contract_id: None,
        validated_at_ms: now_ms,
        expires_at_ms: None,
    };
    let Some(session) = sessions
        .sessions
        .iter()
        .find(|session| &session.proposal.session_id == session_id)
    else {
        return rejected(ManifoldPeerSessionCurrentRejectionReason::NotFound);
    };
    if session.revoked || sessions.revoked_session_ids.contains(session_id) {
        return rejected(ManifoldPeerSessionCurrentRejectionReason::Revoked);
    }
    let Some(receipt_id) = &session.rendezvous_receipt_id else {
        return rejected(ManifoldPeerSessionCurrentRejectionReason::RendezvousNotCurrent);
    };
    let Some(receipt) = rendezvous
        .accepted_receipts
        .iter()
        .find(|receipt| &receipt.receipt_id == receipt_id)
    else {
        return rejected(ManifoldPeerSessionCurrentRejectionReason::RendezvousNotCurrent);
    };
    let Some(topology) = topologies.iter().find(|topology| {
        topology.topology_authorization.session_id == *session_id
            && topology.topology_authorization.decision_id == session.decision_id
    }) else {
        return rejected(ManifoldPeerSessionCurrentRejectionReason::NotFound);
    };
    let proposal = &session.proposal;
    let authorization = &topology.topology_authorization;
    if !authorization.authorized
        || authorization.denial_reason.is_some()
        || authorization.proposal_id != proposal.proposal_id
        || authorization.group_owner_peer_id != proposal.group_owner_peer_id
        || authorization.client_peer_id != proposal.client_peer_id
        || authorization.topology_contract_id != proposal.topology_contract_id
        || topology.rendezvous_receipt_id != *receipt_id
        || topology.signer_key_ids != receipt.signer_key_ids
    {
        return rejected(ManifoldPeerSessionCurrentRejectionReason::TopologyMismatch);
    }
    if authorization.valid_from_ms > now_ms
        || proposal.expires_at_ms <= now_ms
        || authorization.expires_at_ms <= now_ms
    {
        return rejected(ManifoldPeerSessionCurrentRejectionReason::Expired);
    }
    let mut peer_ids = vec![
        proposal.group_owner_peer_id.clone(),
        proposal.client_peer_id.clone(),
    ];
    peer_ids.sort();
    let mut status_revisions = Vec::with_capacity(2);
    for peer_id in &peer_ids {
        let Some(peer) = accepted_peers
            .peers
            .iter()
            .find(|peer| &peer.identity.peer_id == peer_id)
        else {
            return rejected(ManifoldPeerSessionCurrentRejectionReason::PeerNotCurrent);
        };
        if peer.status.availability != ManifoldPeerAvailability::Ready
            || peer.status.observed_at_ms > now_ms
            || peer.status.expires_at_ms <= now_ms
        {
            return rejected(ManifoldPeerSessionCurrentRejectionReason::PeerNotCurrent);
        }
        status_revisions.push(peer.status.status_revision);
    }
    if validate_current_rendezvous_receipt(
        rendezvous,
        enrollment,
        receipt,
        &proposal.group_owner_peer_id,
        &proposal.client_peer_id,
        now_ms,
    )
    .is_err()
    {
        return rejected(ManifoldPeerSessionCurrentRejectionReason::RendezvousNotCurrent);
    }
    ManifoldPeerSessionCurrentReceipt {
        schema_id: schema(PEER_SESSION_CURRENT_RECEIPT_SCHEMA),
        session_id: session_id.clone(),
        current: true,
        rejection_reason: None,
        decision_id: Some(session.decision_id.clone()),
        rendezvous_receipt_id: Some(receipt_id.clone()),
        peer_ids,
        peer_status_revisions: status_revisions,
        signer_key_ids: receipt.signer_key_ids.clone(),
        topology_contract_id: Some(proposal.topology_contract_id.clone()),
        validated_at_ms: now_ms,
        expires_at_ms: Some(
            proposal
                .expires_at_ms
                .min(authorization.expires_at_ms)
                .min(receipt.expires_at_ms),
        ),
    }
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
    review_and_apply_peer_session_with_context(case, false)
}

fn review_and_apply_peer_session_with_context(
    case: &ManifoldPeerSessionReviewCase,
    signed_reciprocal_evidence_validated: bool,
) -> (
    ManifoldPeerSessionDecision,
    ManifoldPeerTopologyAuthorization,
) {
    let rejection = validate_review(case, signed_reciprocal_evidence_validated).err();
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

/// Review and apply a peer session only when it is bound to a fresh accepted
/// reciprocal-signature receipt. This is the clean product path; the older
/// adapter-attestation function remains a compatibility surface.
#[must_use]
pub fn review_and_apply_signed_peer_session(
    case: &ManifoldSignedPeerSessionReviewCase,
) -> (
    ManifoldPeerSessionDecision,
    ManifoldSignedPeerTopologyAuthorization,
) {
    let signed_rejection = validate_signed_session_receipt(case).err();
    let base = &case.session_review;
    if let Some(reason) = signed_rejection {
        let prior = base.current_state.authority_revision;
        let decision_id = derived("decision.peer-session", &base.proposal.proposal_id);
        let decision = ManifoldPeerSessionDecision {
            schema_id: schema(PEER_SESSION_DECISION_SCHEMA),
            decision_id: decision_id.clone(),
            proposal_id: base.proposal.proposal_id.clone(),
            outcome: ManifoldPeerSessionOutcome::Rejected,
            rejection_reason: Some(reason.clone()),
            prior_authority_revision: prior,
            resulting_authority_revision: prior,
            applied: false,
            accepted_state: None,
        };
        return (
            decision,
            ManifoldSignedPeerTopologyAuthorization {
                schema_id: schema(SIGNED_PEER_TOPOLOGY_AUTHORIZATION_SCHEMA),
                topology_authorization: authorization(
                    &base.proposal,
                    decision_id,
                    prior,
                    base.now_ms,
                    false,
                    Some(reason),
                ),
                rendezvous_receipt_id: case.rendezvous_receipt.receipt_id.clone(),
                rendezvous_authority_revision: case.current_rendezvous_state.authority_revision,
                enrollment_authority_revision: case.current_enrollment.authority_revision,
                signer_key_ids: case.rendezvous_receipt.signer_key_ids.clone(),
            },
        );
    }

    let (mut decision, authorization) = review_and_apply_peer_session_with_context(base, true);
    if let Some(state) = &mut decision.accepted_state {
        if let Some(session) = state
            .sessions
            .iter_mut()
            .find(|session| session.proposal.session_id == base.proposal.session_id)
        {
            session.rendezvous_receipt_id = Some(case.rendezvous_receipt.receipt_id.clone());
        }
    }
    (
        decision,
        ManifoldSignedPeerTopologyAuthorization {
            schema_id: schema(SIGNED_PEER_TOPOLOGY_AUTHORIZATION_SCHEMA),
            topology_authorization: authorization,
            rendezvous_receipt_id: case.rendezvous_receipt.receipt_id.clone(),
            rendezvous_authority_revision: case.current_rendezvous_state.authority_revision,
            enrollment_authority_revision: case.current_enrollment.authority_revision,
            signer_key_ids: case.rendezvous_receipt.signer_key_ids.clone(),
        },
    )
}

fn validate_signed_session_receipt(
    case: &ManifoldSignedPeerSessionReviewCase,
) -> Result<(), ManifoldPeerSessionRejectionReason> {
    if case.schema_id.as_str() != SIGNED_PEER_SESSION_REVIEW_SCHEMA {
        return Err(ManifoldPeerSessionRejectionReason::SchemaMismatch);
    }
    let receipt = &case.rendezvous_receipt;
    let proposal = &case.session_review.proposal;
    if !receipt.accepted || receipt.rejection_reason.is_some() {
        return Err(ManifoldPeerSessionRejectionReason::SignedRendezvousRequired);
    }
    validate_current_rendezvous_receipt(
        &case.current_rendezvous_state,
        &case.current_enrollment,
        receipt,
        &proposal.group_owner_peer_id,
        &proposal.client_peer_id,
        case.session_review.now_ms,
    )
    .map_err(|error| match error {
        ManifoldRendezvousReceiptValidationError::SchemaMismatch => {
            ManifoldPeerSessionRejectionReason::SchemaMismatch
        }
        ManifoldRendezvousReceiptValidationError::StaleAuthorityRevision => {
            ManifoldPeerSessionRejectionReason::StaleRendezvousAuthority
        }
        ManifoldRendezvousReceiptValidationError::ReceiptNotRetained
        | ManifoldRendezvousReceiptValidationError::InvalidReceipt
        | ManifoldRendezvousReceiptValidationError::CredentialNotCurrent => {
            ManifoldPeerSessionRejectionReason::SignedRendezvousMismatch
        }
    })?;
    if receipt.topology_contract_id != proposal.topology_contract_id
        || receipt.expires_at_ms < proposal.expires_at_ms
    {
        return Err(ManifoldPeerSessionRejectionReason::SignedRendezvousMismatch);
    }
    Ok(())
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
    signed_reciprocal_evidence_validated: bool,
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
    let minimum_authenticated_messages = match proposal.authentication.transport {
        PeerRendezvousTransport::BleGattAuthenticated => 4,
        PeerRendezvousTransport::ReciprocalEd25519 => 2,
    };
    if !proposal.authentication.authenticated
        || proposal.authentication.authentication_failures != 0
        || proposal.authentication.authenticated_messages < minimum_authenticated_messages
    {
        return Err(ManifoldPeerSessionRejectionReason::AuthenticationFailed);
    }
    match proposal.authentication.transport {
        PeerRendezvousTransport::BleGattAuthenticated => {
            if !proposal.authentication.role_swap_completed
                || proposal.authentication.reconnects_completed < 2
            {
                return Err(ManifoldPeerSessionRejectionReason::RendezvousLifecycleIncomplete);
            }
        }
        PeerRendezvousTransport::ReciprocalEd25519 => {
            if !signed_reciprocal_evidence_validated {
                return Err(ManifoldPeerSessionRejectionReason::SignedRendezvousRequired);
            }
        }
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
    if proposal.requested_capability_ids.is_empty()
        || proposal.requested_capability_ids.len() > MAX_SESSION_CAPABILITIES
    {
        return Err(ManifoldPeerSessionRejectionReason::CapabilityLimitExceeded);
    }
    if proposal
        .requested_capability_ids
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
    {
        return Err(ManifoldPeerSessionRejectionReason::InvalidCapabilitySet);
    }
    if proposal
        .requested_capability_ids
        .iter()
        .any(|capability| ManifoldPeerSessionLowRateCapability::from_id(capability).is_none())
    {
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
        if peer.status.availability != ManifoldPeerAvailability::Ready
            || peer.status.observed_at_ms > case.now_ms
            || peer.status.expires_at_ms <= case.now_ms
            || proposal.expires_at_ms > peer.status.expires_at_ms
        {
            return Err(ManifoldPeerSessionRejectionReason::StalePeerStatus);
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
            && session.proposal.session_id == proposal.session_id
            && (session.proposal.subject_peer_id != proposal.subject_peer_id
                || session.proposal.candidate_peer_id != proposal.candidate_peer_id
                || session.proposal.group_owner_peer_id != proposal.group_owner_peer_id
                || session.proposal.client_peer_id != proposal.client_peer_id
                || session.proposal.topology_contract_id != proposal.topology_contract_id
                || session.proposal.requested_capability_ids != proposal.requested_capability_ids)
    }) {
        return Err(ManifoldPeerSessionRejectionReason::SessionIdentityCollision);
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
        rendezvous_receipt_id: None,
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
    use ed25519_dalek::SigningKey;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::{
        ManifoldPeerCredentialAlgorithm, ManifoldPeerCredentialRecord,
        ManifoldPeerCredentialStatus, ManifoldRendezvousReceipt, PEER_CREDENTIAL_SCHEMA,
        PEER_ENROLLMENT_STATE_SCHEMA, RENDEZVOUS_AUTHORITY_STATE_SCHEMA, RENDEZVOUS_RECEIPT_SCHEMA,
    };

    fn case(path: &str) -> ManifoldPeerSessionReviewCase {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let text = std::fs::read_to_string(root.join(path)).expect("fixture");
        serde_json::from_str(&text).expect("review case")
    }

    fn signed_case() -> ManifoldSignedPeerSessionReviewCase {
        let session_review = case("fixtures/peer-session/authenticated-ble.pass.json");
        let mut peer_ids = vec![
            session_review.proposal.subject_peer_id.clone(),
            session_review.proposal.candidate_peer_id.clone(),
        ];
        peer_ids.sort();
        let enrollment_revision = Revision::new(3).expect("revision");
        let credentials = [
            ("peer.alpha", "key.peer.alpha.001", 7_u8),
            ("peer.beta", "key.peer.beta.001", 11_u8),
        ]
        .into_iter()
        .map(|(peer_id, key_id, seed)| {
            let public_key = SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .to_bytes();
            let public_key_hex = hex(&public_key);
            ManifoldPeerCredentialRecord {
                schema_id: schema(PEER_CREDENTIAL_SCHEMA),
                credential_id: DottedId::new(format!("credential.{peer_id}.1")).expect("id"),
                peer_id: DottedId::new(peer_id).expect("id"),
                trust_domain: DottedId::new("trust.morphospace.peer").expect("id"),
                key_id: DottedId::new(key_id).expect("id"),
                key_generation: 1,
                algorithm: ManifoldPeerCredentialAlgorithm::Ed25519,
                public_key_hex,
                public_key_sha256: format!("sha256:{}", hex(&Sha256::digest(public_key))),
                valid_from_ms: 1,
                expires_at_ms: 100_000,
                status: ManifoldPeerCredentialStatus::Active,
                replaced_by_key_id: None,
            }
        })
        .collect();
        let current_enrollment = ManifoldPeerEnrollmentState {
            schema_id: schema(PEER_ENROLLMENT_STATE_SCHEMA),
            authority_revision: enrollment_revision,
            credentials,
            applied_request_ids: Vec::new(),
        };
        let receipt = ManifoldRendezvousReceipt {
            schema_id: schema(RENDEZVOUS_RECEIPT_SCHEMA),
            receipt_id: DottedId::new("receipt.peer.rendezvous.alpha-beta.001").expect("id"),
            request_id: DottedId::new("request.peer.rendezvous.alpha-beta.001").expect("id"),
            accepted: true,
            rejection_reason: None,
            peer_ids,
            group_owner_peer_id: Some(session_review.proposal.group_owner_peer_id.clone()),
            client_peer_id: Some(session_review.proposal.client_peer_id.clone()),
            signer_key_ids: vec![
                DottedId::new("key.peer.alpha.001").expect("id"),
                DottedId::new("key.peer.beta.001").expect("id"),
            ],
            evidence_ids: vec![
                DottedId::new("evidence.peer.alpha.001").expect("id"),
                DottedId::new("evidence.peer.beta.001").expect("id"),
            ],
            nonce_sha256: format!("sha256:{}", "a1".repeat(32)),
            coordinator_epoch: 7,
            topology_contract_id: session_review.proposal.topology_contract_id.clone(),
            enrollment_authority_revision: enrollment_revision,
            prior_authority_revision: Revision::INITIAL,
            resulting_authority_revision: Revision::new(2).expect("revision"),
            expires_at_ms: session_review.proposal.expires_at_ms,
        };
        let current_rendezvous_state = ManifoldRendezvousAuthorityState {
            schema_id: schema(RENDEZVOUS_AUTHORITY_STATE_SCHEMA),
            authority_revision: Revision::new(2).expect("revision"),
            applied_request_ids: vec![receipt.request_id.clone()],
            consumed_evidence_ids: receipt.evidence_ids.clone(),
            consumed_nonce_sha256: vec![receipt.nonce_sha256.clone()],
            accepted_receipts: vec![receipt.clone()],
        };
        ManifoldSignedPeerSessionReviewCase {
            schema_id: schema(SIGNED_PEER_SESSION_REVIEW_SCHEMA),
            rendezvous_receipt: receipt,
            session_review,
            current_enrollment,
            current_rendezvous_state,
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

    #[test]
    fn authenticated_pair_authorizes_topology() {
        let case = case("fixtures/peer-session/authenticated-ble.pass.json");
        let (decision, authorization) = review_and_apply_peer_session(&case);
        assert_eq!(decision.outcome, ManifoldPeerSessionOutcome::Accepted);
        assert!(decision.applied);
        assert!(authorization.authorized);
        assert_eq!(authorization.authority_revision.get(), 2);
        assert!(decision.accepted_state.as_ref().expect("state").sessions[0]
            .rendezvous_receipt_id
            .is_none());
    }

    #[test]
    fn clean_product_session_requires_and_persists_signed_rendezvous_receipt() {
        let case = signed_case();
        let receipt_id = case.rendezvous_receipt.receipt_id.clone();
        let (decision, authorization) = review_and_apply_signed_peer_session(&case);
        assert!(decision.applied);
        assert!(authorization.topology_authorization.authorized);
        assert_eq!(authorization.rendezvous_receipt_id, receipt_id);
        assert_eq!(
            decision.accepted_state.expect("state").sessions[0].rendezvous_receipt_id,
            Some(receipt_id)
        );
    }

    #[test]
    fn stale_rejected_or_pair_mismatched_signed_receipt_never_authorizes() {
        let mut unrelated_revision = signed_case();
        unrelated_revision
            .current_rendezvous_state
            .authority_revision = Revision::new(3).expect("revision");
        let (decision, authorization) = review_and_apply_signed_peer_session(&unrelated_revision);
        assert!(decision.applied);
        assert!(authorization.topology_authorization.authorized);

        let cases = [
            {
                let mut value = signed_case();
                value.rendezvous_receipt.accepted = false;
                (
                    value,
                    ManifoldPeerSessionRejectionReason::SignedRendezvousRequired,
                )
            },
            {
                let mut value = signed_case();
                value.rendezvous_receipt.peer_ids[1] = DottedId::new("peer.gamma").expect("id");
                (
                    value,
                    ManifoldPeerSessionRejectionReason::SignedRendezvousMismatch,
                )
            },
            {
                let mut value = signed_case();
                std::mem::swap(
                    &mut value.session_review.proposal.group_owner_peer_id,
                    &mut value.session_review.proposal.client_peer_id,
                );
                (
                    value,
                    ManifoldPeerSessionRejectionReason::SignedRendezvousMismatch,
                )
            },
        ];
        for (case, expected) in cases {
            let (decision, authorization) = review_and_apply_signed_peer_session(&case);
            assert_eq!(decision.rejection_reason, Some(expected));
            assert!(!decision.applied);
            assert!(!authorization.topology_authorization.authorized);
            assert_eq!(
                decision.prior_authority_revision,
                decision.resulting_authority_revision
            );
        }
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
    fn peer_status_must_be_ready_current_and_cover_the_session_window() {
        let cases = [
            {
                let mut value = case("fixtures/peer-session/authenticated-ble.pass.json");
                value.accepted_peers.peers[0].status.availability =
                    ManifoldPeerAvailability::Degraded;
                value
            },
            {
                let mut value = case("fixtures/peer-session/authenticated-ble.pass.json");
                value.accepted_peers.peers[0].status.observed_at_ms = value.now_ms + 1;
                value
            },
            {
                let mut value = case("fixtures/peer-session/authenticated-ble.pass.json");
                value.accepted_peers.peers[0].status.expires_at_ms = value.now_ms;
                value
            },
            {
                let mut value = case("fixtures/peer-session/authenticated-ble.pass.json");
                value.accepted_peers.peers[0].status.expires_at_ms =
                    value.proposal.expires_at_ms - 1;
                value
            },
        ];
        for value in cases {
            let (decision, authorization) = review_and_apply_peer_session(&value);
            assert_eq!(
                decision.rejection_reason,
                Some(ManifoldPeerSessionRejectionReason::StalePeerStatus)
            );
            assert!(!authorization.authorized);
        }
    }

    #[test]
    fn capability_set_is_exact_allowlisted_sorted_and_unique() {
        let mut duplicate = case("fixtures/peer-session/authenticated-ble.pass.json");
        duplicate.proposal.requested_capability_ids = vec![
            DottedId::new("capability.rendezvous.ble").expect("id"),
            DottedId::new("capability.rendezvous.ble").expect("id"),
        ];
        let (decision, _) = review_and_apply_peer_session(&duplicate);
        assert_eq!(
            decision.rejection_reason,
            Some(ManifoldPeerSessionRejectionReason::InvalidCapabilitySet)
        );

        let mut unknown = case("fixtures/peer-session/authenticated-ble.pass.json");
        unknown.proposal.requested_capability_ids =
            vec![DottedId::new("capability.media.video").expect("id")];
        let (decision, _) = review_and_apply_peer_session(&unknown);
        assert_eq!(
            decision.rejection_reason,
            Some(ManifoldPeerSessionRejectionReason::HighRateCapability)
        );
    }

    #[test]
    fn live_session_id_cannot_be_substituted_by_another_pair_or_role() {
        let mut value = case("fixtures/peer-session/authenticated-ble.pass.json");
        let mut occupied = value.proposal.clone();
        occupied.proposal_id = DottedId::new("proposal.peer-session.occupied").expect("id");
        occupied.subject_peer_id = DottedId::new("peer.gamma").expect("id");
        occupied.candidate_peer_id = DottedId::new("peer.delta").expect("id");
        occupied.group_owner_peer_id = occupied.subject_peer_id.clone();
        occupied.client_peer_id = occupied.candidate_peer_id.clone();
        value
            .current_state
            .sessions
            .push(ManifoldAcceptedPeerSession {
                proposal: occupied,
                decision_id: DottedId::new("decision.peer-session.occupied").expect("id"),
                revoked: false,
                rendezvous_receipt_id: None,
            });
        let (decision, authorization) = review_and_apply_peer_session(&value);
        assert_eq!(
            decision.rejection_reason,
            Some(ManifoldPeerSessionRejectionReason::SessionIdentityCollision)
        );
        assert!(!authorization.authorized);
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
