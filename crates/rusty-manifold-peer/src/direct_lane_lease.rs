//! Revisioned direct-lane lease authority derived from accepted mesh state.
//!
//! Route eligibility is advisory until this authority binds an accepted mesh
//! route to a fresh signed peer session and, when requested, an explicit media
//! session reference. No endpoint, socket, codec, or media payload is owned
//! here.

use std::collections::BTreeSet;
use std::fmt;

use rusty_manifold_media_session::{
    validate_media_session_acceptance_state, ManifoldMediaSessionAcceptanceState,
    ManifoldMediaSessionLifecycleStatus, MANIFOLD_MEDIA_SESSION_ACCEPTANCE_STATE_SCHEMA,
};
use rusty_manifold_model::{DottedId, Revision, SchemaId};
use rusty_manifold_runtime_host::{
    ManifoldRuntimeApplicationReceipt, ManifoldRuntimeCommandRequest,
    ManifoldRuntimeDispatchOutcome, ManifoldRuntimeDispatchReceipt,
    ManifoldRuntimeTypedParamsDigest, HOST_APPLICATION_RECEIPT_SCHEMA, HOST_COMMAND_REQUEST_SCHEMA,
    HOST_DISPATCH_RECEIPT_SCHEMA, HOST_TYPED_PARAMS_DIGEST_SCHEMA,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    validate_current_rendezvous_receipt, ManifoldAcceptedPeerState, ManifoldPeerAvailability,
    ManifoldPeerEnrollmentState, ManifoldPeerMeshState, ManifoldPeerSessionState,
    ManifoldRendezvousAuthorityState, ManifoldRendezvousReceiptValidationError,
    ManifoldSignedPeerTopologyAuthorization, DIRECT_P2P_ROUTE_CONTRACT, PEER_MESH_STATE_SCHEMA,
    PEER_SESSION_PROPOSAL_SCHEMA, PEER_SESSION_SNAPSHOT_SCHEMA, PEER_TOPOLOGY_AUTHORIZATION_SCHEMA,
    PRODUCT_WIFI_DIRECT_TOPOLOGY_CONTRACT, SIGNED_PEER_TOPOLOGY_AUTHORIZATION_SCHEMA,
};

/// Legacy direct-lane state accepted only by fail-closed migration.
pub const LEGACY_DIRECT_LANE_LEASE_STATE_V1_SCHEMA: &str =
    "rusty.manifold.peer.direct_lane_lease_state.v1";
/// Direct-lane lease state schema with Runtime Host and exact route provenance.
pub const DIRECT_LANE_LEASE_STATE_SCHEMA: &str = "rusty.manifold.peer.direct_lane_lease_state.v2";
/// Direct-lane lease request schema.
pub const DIRECT_LANE_LEASE_REQUEST_SCHEMA: &str =
    "rusty.manifold.peer.direct_lane_lease_request.v2";
/// Direct-lane lease record schema.
/// Legacy direct-lane record schema accepted only by fail-closed migration.
pub const LEGACY_DIRECT_LANE_LEASE_RECORD_V1_SCHEMA: &str =
    "rusty.manifold.peer.direct_lane_lease_record.v1";
/// Direct-lane record schema with Runtime Host and exact route provenance.
pub const DIRECT_LANE_LEASE_RECORD_SCHEMA: &str = "rusty.manifold.peer.direct_lane_lease_record.v2";
/// Direct-lane lease receipt schema.
pub const DIRECT_LANE_LEASE_RECEIPT_SCHEMA: &str =
    "rusty.manifold.peer.direct_lane_lease_receipt.v2";
/// Direct-lane lease revocation schema.
pub const DIRECT_LANE_LEASE_REVOCATION_SCHEMA: &str =
    "rusty.manifold.peer.direct_lane_lease_revocation.v1";
/// Direct-lane use request schema.
pub const DIRECT_LANE_LEASE_USE_REQUEST_SCHEMA: &str =
    "rusty.manifold.peer.direct_lane_lease_use_request.v1";
/// Current direct-lane receipt schema.
pub const DIRECT_LANE_LEASE_CURRENT_RECEIPT_SCHEMA: &str =
    "rusty.manifold.peer.direct_lane_lease_current_receipt.v1";
/// Fail-closed v1 direct-lane state migration receipt schema.
pub const DIRECT_LANE_LEASE_MIGRATION_RECEIPT_SCHEMA: &str =
    "rusty.manifold.peer.direct_lane_lease_migration_receipt.v1";
/// Runtime Host command that admits direct-lane issuance.
pub const DIRECT_LANE_LEASE_ISSUE_COMMAND: &str = "rusty.manifold.peer.direct_lane.issue";
/// Runtime Host command that admits one current-lease use.
pub const DIRECT_LANE_LEASE_USE_COMMAND: &str = "rusty.manifold.peer.direct_lane.use";
/// Runtime Host command that admits holder revocation.
pub const DIRECT_LANE_LEASE_REVOKE_COMMAND: &str = "rusty.manifold.peer.direct_lane.revoke";
/// Typed params contract for issuance commands.
pub const DIRECT_LANE_LEASE_ISSUE_PARAMS_TYPE: &str =
    "rusty.manifold.peer.direct_lane_issue_params.v1";
/// Typed params contract for use commands.
pub const DIRECT_LANE_LEASE_USE_PARAMS_TYPE: &str = "rusty.manifold.peer.direct_lane_use_params.v1";
/// Typed params contract for revoke commands.
pub const DIRECT_LANE_LEASE_REVOKE_PARAMS_TYPE: &str =
    "rusty.manifold.peer.direct_lane_revoke_params.v1";
/// Explicit PeerSession-scope capability.
pub const DIRECT_LANE_PEER_SESSION_CAPABILITY: &str =
    "capability.manifold.direct_lane.peer_session";
/// Explicit MediaSession-scope capability.
pub const DIRECT_LANE_MEDIA_SESSION_CAPABILITY: &str =
    "capability.manifold.direct_lane.media_session";

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

/// Immutable host-owned admission closure for direct-lane operations.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldDirectLaneClientGrant {
    /// Exact Runtime Host that owns admission commands.
    pub runtime_host_id: DottedId,
    /// Exact Runtime Host client.
    pub client_id: DottedId,
    /// Exact Runtime Host lease.
    pub runtime_lease_id: DottedId,
    /// Exact admitted product.
    pub product_id: DottedId,
    /// Exact selected feature lock.
    pub feature_lock_id: DottedId,
    /// Exact feature-lock fingerprint.
    pub feature_lock_fingerprint: String,
    /// Exact PeerSession-scope capability, when admitted.
    pub peer_session_capability_id: Option<DottedId>,
    /// Exact MediaSession-scope capability, when admitted.
    pub media_session_capability_id: Option<DottedId>,
    /// Exact direct-lane admission grant.
    pub admission_grant_id: DottedId,
}

/// Non-serializable Runtime Host proof consumed by direct-lane authority.
#[derive(Clone, Copy, Debug)]
pub struct ManifoldDirectLaneRuntimeCommandContext<'a> {
    /// Runtime Host that owns command state.
    pub runtime_host_id: &'a DottedId,
    /// Exact reviewed command request.
    pub command_request: &'a ManifoldRuntimeCommandRequest,
    /// Exact current-state dispatch.
    pub dispatch: &'a ManifoldRuntimeDispatchReceipt,
    /// Exact applied command receipt.
    pub application: &'a ManifoldRuntimeApplicationReceipt,
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
    /// Exact accepted-peer mutation revision being consumed.
    pub expected_peer_authority_revision: Revision,
    /// Exact mesh authority revision being consumed.
    pub expected_mesh_authority_revision: Revision,
    /// Exact accepted mesh coordinator epoch being consumed.
    pub expected_mesh_authority_epoch: u64,
    /// Exact accepted mesh coordinator peer identity.
    pub expected_mesh_coordinator_peer_id: DottedId,
    /// Exact enrollment authority revision being consumed.
    pub expected_enrollment_authority_revision: Revision,
    /// Exact signed-rendezvous authority revision being consumed.
    pub expected_rendezvous_authority_revision: Revision,
    /// Exact peer-session authority revision being consumed.
    pub expected_peer_session_authority_revision: Revision,
    /// Exact lower-peer status revision copied into the mesh.
    pub first_peer_status_revision: Revision,
    /// Exact upper-peer status revision copied into the mesh.
    pub second_peer_status_revision: Revision,
    /// Exact reciprocal pair receipt selected by the mesh route.
    pub pair_evidence_receipt_id: DottedId,
    /// Exact reciprocal evidence digest selected by the mesh route.
    pub pair_evidence_sha256: String,
    /// Subject-scoped reciprocal authority revision.
    pub pair_authority_revision: Revision,
    /// Pair/topology epoch, independent of the global mesh epoch.
    pub pair_authority_epoch: u64,
    /// Current signer keys for the reciprocal pair evidence.
    pub pair_signer_key_ids: Vec<DottedId>,
    /// Exact media-session authority revision, only for media scope.
    pub expected_media_session_authority_revision: Option<Revision>,
    /// Exact retained media-acceptance authority revision, only for media scope.
    pub expected_media_acceptance_authority_revision: Option<Revision>,
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
    /// Exact retained Manifold media-session decision identity.
    pub media_session_decision_id: Option<DottedId>,
    /// Exact canonical product descriptor digest accepted by Manifold.
    pub media_session_descriptor_canonical_sha256: Option<String>,
    /// Exact accepted provider-process epoch.
    pub media_session_provider_epoch_id: Option<DottedId>,
    /// Exact accepted platform runtime specification.
    pub media_session_platform_runtime_spec_id: Option<DottedId>,
    /// Exact admitted product.
    pub product_id: DottedId,
    /// Exact selected feature lock.
    pub feature_lock_id: DottedId,
    /// Exact feature-lock fingerprint.
    pub feature_lock_fingerprint: String,
    /// Exact admitted capability.
    pub capability_id: DottedId,
    /// Exact admission grant.
    pub admission_grant_id: DottedId,
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
    /// Runtime Host that atomically applied the issue command.
    pub runtime_authority_host_id: DottedId,
    /// Exact admitted Runtime Host client that owns this lease.
    pub holder_client_id: DottedId,
    /// Exact admitted Runtime Host lease held by the client.
    pub holder_runtime_lease_id: DottedId,
    /// Exact admitted product.
    pub product_id: DottedId,
    /// Exact selected feature lock.
    pub feature_lock_id: DottedId,
    /// Exact feature-lock fingerprint.
    pub feature_lock_fingerprint: String,
    /// Exact admitted capability.
    pub capability_id: DottedId,
    /// Exact admission grant.
    pub admission_grant_id: DottedId,
    /// Accepted-peer mutation revision observed at issuance.
    pub peer_authority_revision: Revision,
    /// Accepted mesh identity and revision.
    pub mesh_id: DottedId,
    /// Accepted mesh authority revision.
    pub mesh_authority_revision: Revision,
    /// Accepted mesh coordinator epoch.
    pub mesh_authority_epoch: u64,
    /// Accepted mesh coordinator peer identity.
    pub mesh_coordinator_peer_id: DottedId,
    /// Exact per-peer status revisions consumed at issuance.
    pub peer_status_revisions: Vec<Revision>,
    /// Exact reciprocal pair receipt selected by the mesh route.
    pub pair_evidence_receipt_id: DottedId,
    /// Exact reciprocal evidence digest selected by the mesh route.
    pub pair_evidence_sha256: String,
    /// Subject-scoped reciprocal authority revision.
    pub pair_authority_revision: Revision,
    /// Pair/topology epoch, independent of the global mesh epoch.
    pub pair_authority_epoch: u64,
    /// Current signer keys for the reciprocal pair evidence.
    pub pair_signer_key_ids: Vec<DottedId>,
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
    /// Optional retained media-acceptance authority revision.
    pub media_acceptance_authority_revision: Option<Revision>,
    /// Optional exact retained Manifold media-session decision.
    pub media_session_decision_id: Option<DottedId>,
    /// Optional exact canonical accepted product descriptor digest.
    pub media_session_descriptor_canonical_sha256: Option<String>,
    /// Optional exact accepted provider-process epoch.
    pub media_session_provider_epoch_id: Option<DottedId>,
    /// Optional exact accepted platform runtime specification.
    pub media_session_platform_runtime_spec_id: Option<DottedId>,
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

/// Receipt proving that v1 leases without current Runtime Host, exact pair,
/// product, feature-lock, and admission closure were invalidated on migration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldDirectLaneLeaseMigrationReceipt {
    /// Receipt schema.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Legacy source schema.
    pub source_schema_id: SchemaId,
    /// Resulting fail-closed state schema.
    pub resulting_schema_id: SchemaId,
    /// Preserved authority revision.
    pub authority_revision: Revision,
    /// All legacy lease identities invalidated during migration.
    pub invalidated_lease_ids: Vec<DottedId>,
    /// Legacy issue/revocation/sweep ids retained against replay.
    pub preserved_applied_request_ids: Vec<DottedId>,
    /// Stable reason why no v1 lease was promoted.
    pub invalidation_reason: DottedId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct LegacyDirectLaneLeaseV1 {
    #[serde(rename = "$schema")]
    schema_id: SchemaId,
    lease_id: DottedId,
    request_id: DottedId,
    mesh_id: DottedId,
    mesh_authority_revision: Revision,
    enrollment_authority_revision: Revision,
    selected_route_id: DottedId,
    peer_ids: Vec<DottedId>,
    peer_session_id: DottedId,
    peer_session_authority_revision: Revision,
    rendezvous_receipt_id: DottedId,
    rendezvous_authority_revision: Revision,
    media_session_id: Option<DottedId>,
    media_session_authority_revision: Option<Revision>,
    scope: ManifoldDirectLaneLeaseScope,
    valid_from_ms: u64,
    expires_at_ms: u64,
    revoked: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct LegacyDirectLaneLeaseStateV1 {
    #[serde(rename = "$schema")]
    schema_id: SchemaId,
    authority_revision: Revision,
    leases: Vec<LegacyDirectLaneLeaseV1>,
    applied_request_ids: Vec<DottedId>,
}

/// Migrates released v1 direct-lane state by retaining replay history while
/// invalidating every lease whose required v2 provenance cannot be inferred.
///
/// # Errors
///
/// Returns an error when legacy JSON or structural/replay invariants fail.
pub fn migrate_legacy_direct_lane_lease_state_json(
    json: &str,
) -> Result<
    (
        ManifoldDirectLaneLeaseState,
        ManifoldDirectLaneLeaseMigrationReceipt,
    ),
    ManifoldDirectLaneLeaseMigrationError,
> {
    let legacy: LegacyDirectLaneLeaseStateV1 =
        serde_json::from_str(json).map_err(ManifoldDirectLaneLeaseMigrationError::Deserialize)?;
    validate_legacy_direct_lane_state(&legacy)?;
    let mut invalidated_lease_ids = legacy
        .leases
        .iter()
        .map(|lease| lease.lease_id.clone())
        .collect::<Vec<_>>();
    invalidated_lease_ids.sort();
    let mut applied_request_ids = legacy.applied_request_ids;
    applied_request_ids.sort();
    let state = ManifoldDirectLaneLeaseState {
        schema_id: schema(DIRECT_LANE_LEASE_STATE_SCHEMA),
        authority_revision: legacy.authority_revision,
        leases: Vec::new(),
        applied_request_ids: applied_request_ids.clone(),
    };
    let receipt = ManifoldDirectLaneLeaseMigrationReceipt {
        schema_id: schema(DIRECT_LANE_LEASE_MIGRATION_RECEIPT_SCHEMA),
        source_schema_id: legacy.schema_id,
        resulting_schema_id: state.schema_id.clone(),
        authority_revision: state.authority_revision,
        invalidated_lease_ids,
        preserved_applied_request_ids: applied_request_ids,
        invalidation_reason: DottedId::new("legacy.provenance.insufficient")
            .expect("static migration reason"),
    };
    Ok((state, receipt))
}

fn validate_legacy_direct_lane_state(
    state: &LegacyDirectLaneLeaseStateV1,
) -> Result<(), ManifoldDirectLaneLeaseMigrationError> {
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
    let applied_ids = state.applied_request_ids.iter().collect::<BTreeSet<_>>();
    if state.schema_id.as_str() != LEGACY_DIRECT_LANE_LEASE_STATE_V1_SCHEMA
        || state.leases.len() > 4_096
        || state.applied_request_ids.len() > 4_096
        || lease_ids.len() != state.leases.len()
        || lease_request_ids.len() != state.leases.len()
        || applied_ids.len() != state.applied_request_ids.len()
    {
        return Err(ManifoldDirectLaneLeaseMigrationError::Invalid(
            "schema_capacity_or_identity",
        ));
    }
    if state.leases.iter().any(|lease| {
        let legacy_authority_refs = (
            &lease.mesh_id,
            lease.mesh_authority_revision,
            lease.enrollment_authority_revision,
            &lease.selected_route_id,
            &lease.peer_session_id,
            lease.peer_session_authority_revision,
            &lease.rendezvous_receipt_id,
            lease.rendezvous_authority_revision,
            lease.revoked,
        );
        let _ = legacy_authority_refs;
        lease.schema_id.as_str() != LEGACY_DIRECT_LANE_LEASE_RECORD_V1_SCHEMA
            || lease.lease_id != derived("lease.peer.direct", &lease.request_id)
            || !state.applied_request_ids.contains(&lease.request_id)
            || lease.peer_ids.len() != 2
            || lease.peer_ids[0] >= lease.peer_ids[1]
            || lease.valid_from_ms >= lease.expires_at_ms
            || !matches!(
                (
                    &lease.scope,
                    &lease.media_session_id,
                    lease.media_session_authority_revision,
                ),
                (ManifoldDirectLaneLeaseScope::PeerSession, None, None)
                    | (ManifoldDirectLaneLeaseScope::MediaSession, Some(_), Some(_))
            )
    }) {
        return Err(ManifoldDirectLaneLeaseMigrationError::Invalid(
            "legacy_lease_closure",
        ));
    }
    Ok(())
}

/// Legacy direct-lane migration failure.
#[derive(Debug)]
pub enum ManifoldDirectLaneLeaseMigrationError {
    /// Legacy JSON could not be decoded.
    Deserialize(serde_json::Error),
    /// Legacy state failed structural/replay validation.
    Invalid(&'static str),
}

impl fmt::Display for ManifoldDirectLaneLeaseMigrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Deserialize(error) => {
                write!(formatter, "legacy direct-lane state decode failed: {error}")
            }
            Self::Invalid(reason) => {
                write!(formatter, "legacy direct-lane state invalid: {reason}")
            }
        }
    }
}

impl std::error::Error for ManifoldDirectLaneLeaseMigrationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Deserialize(error) => Some(error),
            Self::Invalid(_) => None,
        }
    }
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
    /// Current accepted peer identity/status authority.
    pub accepted_peers: &'a ManifoldAcceptedPeerState,
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
    /// Current retained Manifold media-session acceptance authority.
    pub media_sessions: &'a ManifoldMediaSessionAcceptanceState,
    /// Host-owned live provider-process epoch.
    pub live_provider_epoch_id: &'a DottedId,
    /// Immutable client/product/feature-lock/capability/grant closures.
    pub client_grants: &'a [ManifoldDirectLaneClientGrant],
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
    /// Runtime client, lease, product, feature lock, capability, or grant was not admitted.
    ClientNotAuthorized,
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

/// Replay-protected request to consume one admitted current lease.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldDirectLaneLeaseUseRequest {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Runtime command/request identity.
    pub request_id: DottedId,
    /// Exact lease authority revision being consumed.
    pub expected_authority_revision: Revision,
    /// Exact direct-lane lease.
    pub lease_id: DottedId,
}

/// Trusted current-state receipt returned only after an applied use command.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldDirectLaneLeaseCurrentReceipt {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Use request that produced this receipt.
    pub request_id: DottedId,
    /// Exact current lease.
    pub lease_id: DottedId,
    /// Exact authenticated Runtime Host client.
    pub holder_client_id: DottedId,
    /// Exact authenticated Runtime Host lease.
    pub holder_runtime_lease_id: DottedId,
    /// Exact product/feature/capability/grant closure.
    pub product_id: DottedId,
    /// Exact selected feature lock.
    pub feature_lock_id: DottedId,
    /// SHA-256 of the exact selected feature-lock bytes.
    pub feature_lock_fingerprint: String,
    /// Exact capability authorized for this lease use.
    pub capability_id: DottedId,
    /// Exact admission grant that authorized this client.
    pub admission_grant_id: DottedId,
    /// Lease authority revision reviewed.
    pub authority_revision: Revision,
    /// Validation time and retained expiry.
    pub validated_at_ms: u64,
    /// Absolute lease expiry.
    pub expires_at_ms: u64,
}

/// Issue a real session/media lease from current mesh and signed topology
/// authority. Rejections return an unchanged state plus a typed receipt.
#[must_use]
pub fn review_and_apply_direct_lane_lease(
    state: &ManifoldDirectLaneLeaseState,
    authority: &ManifoldDirectLaneLeaseAuthorityContext<'_>,
    request: &ManifoldDirectLaneLeaseRequest,
    runtime: ManifoldDirectLaneRuntimeCommandContext<'_>,
    now_ms: u64,
) -> (ManifoldDirectLaneLeaseState, ManifoldDirectLaneLeaseReceipt) {
    let prior = state.authority_revision;
    let rejection = validate_request(state, authority, request, Some(runtime), now_ms)
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
        runtime_authority_host_id: runtime.runtime_host_id.clone(),
        holder_client_id: runtime.command_request.requester_id.clone(),
        holder_runtime_lease_id: runtime
            .command_request
            .lease_id
            .clone()
            .expect("validated direct-lane command lease"),
        product_id: request.product_id.clone(),
        feature_lock_id: request.feature_lock_id.clone(),
        feature_lock_fingerprint: request.feature_lock_fingerprint.clone(),
        capability_id: request.capability_id.clone(),
        admission_grant_id: request.admission_grant_id.clone(),
        peer_authority_revision: request.expected_peer_authority_revision,
        mesh_id: request.mesh_id.clone(),
        mesh_authority_revision: request.expected_mesh_authority_revision,
        mesh_authority_epoch: request.expected_mesh_authority_epoch,
        mesh_coordinator_peer_id: request.expected_mesh_coordinator_peer_id.clone(),
        peer_status_revisions: vec![
            request.first_peer_status_revision,
            request.second_peer_status_revision,
        ],
        pair_evidence_receipt_id: request.pair_evidence_receipt_id.clone(),
        pair_evidence_sha256: request.pair_evidence_sha256.clone(),
        pair_authority_revision: request.pair_authority_revision,
        pair_authority_epoch: request.pair_authority_epoch,
        pair_signer_key_ids: request.pair_signer_key_ids.clone(),
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
        media_acceptance_authority_revision: request.expected_media_acceptance_authority_revision,
        media_session_decision_id: request.media_session_decision_id.clone(),
        media_session_descriptor_canonical_sha256: request
            .media_session_descriptor_canonical_sha256
            .clone(),
        media_session_provider_epoch_id: request.media_session_provider_epoch_id.clone(),
        media_session_platform_runtime_spec_id: request
            .media_session_platform_runtime_spec_id
            .clone(),
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
    runtime: Option<ManifoldDirectLaneRuntimeCommandContext<'_>>,
    now_ms: u64,
) -> Result<(), ManifoldDirectLaneLeaseRejectionReason> {
    validate_authority_headers(state, authority, request)?;
    if state.applied_request_ids.contains(&request.request_id) {
        return Err(ManifoldDirectLaneLeaseRejectionReason::ReplayedRequest);
    }
    if let Some(runtime) = runtime {
        validate_runtime_command(
            runtime,
            DIRECT_LANE_LEASE_ISSUE_COMMAND,
            &direct_lane_lease_issue_params_digest(request)
                .map_err(|_| ManifoldDirectLaneLeaseRejectionReason::ClientNotAuthorized)?,
        )?;
        validate_client_grant(authority.client_grants, request, runtime)?;
    }
    let member_expiry = validate_mesh_route(authority, request, now_ms)?;
    let topology_expiry = validate_topology_authority(authority, request, now_ms)?;
    validate_media_scope(
        authority.media_sessions,
        authority.live_provider_epoch_id,
        request,
        runtime.map(|context| &context.command_request.requester_id),
        now_ms,
    )?;
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
        || authority.accepted_peers.schema_id.as_str() != crate::PEER_SNAPSHOT_SCHEMA
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
        || request.expected_peer_authority_revision != authority.accepted_peers.authority_revision
        || request.expected_enrollment_authority_revision != authority.enrollment.authority_revision
        || request.expected_rendezvous_authority_revision != authority.rendezvous.authority_revision
        || request.expected_mesh_authority_revision != authority.mesh.authority_revision
        || request.expected_peer_session_authority_revision
            != authority.peer_sessions.authority_revision
    {
        return Err(ManifoldDirectLaneLeaseRejectionReason::StaleAuthorityRevision);
    }
    Ok(())
}

/// Validates durable direct-lane identity, replay, scope, and closure invariants.
#[must_use]
pub fn direct_lane_state_is_well_formed(state: &ManifoldDirectLaneLeaseState) -> bool {
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
                && lease.peer_status_revisions.len() == 2
                && lease.mesh_authority_epoch > 0
                && lease.pair_authority_epoch > 0
                && lease.pair_signer_key_ids.len() == 2
                && lease.pair_signer_key_ids[0] < lease.pair_signer_key_ids[1]
                && valid_sha256(&lease.pair_evidence_sha256)
                && !lease.feature_lock_fingerprint.is_empty()
                && lease.valid_from_ms < lease.expires_at_ms
                && matches!(
                    (
                        &lease.scope,
                        &lease.media_session_id,
                        lease.media_session_authority_revision,
                        lease.media_acceptance_authority_revision,
                        &lease.media_session_decision_id,
                        &lease.media_session_descriptor_canonical_sha256,
                        &lease.media_session_provider_epoch_id,
                        &lease.media_session_platform_runtime_spec_id,
                    ),
                    (
                        ManifoldDirectLaneLeaseScope::PeerSession,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None
                    ) | (
                        ManifoldDirectLaneLeaseScope::MediaSession,
                        Some(_),
                        Some(_),
                        Some(_),
                        Some(_),
                        Some(_),
                        Some(_),
                        Some(_)
                    )
                )
        })
}

fn validate_mesh_route(
    authority: &ManifoldDirectLaneLeaseAuthorityContext<'_>,
    request: &ManifoldDirectLaneLeaseRequest,
    now_ms: u64,
) -> Result<u64, ManifoldDirectLaneLeaseRejectionReason> {
    let mesh = authority.mesh;
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
        || mesh.authority_epoch == 0
        || mesh.authority_epoch != request.expected_mesh_authority_epoch
        || mesh.coordinator_peer_id.as_ref() != Some(&request.expected_mesh_coordinator_peer_id)
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
    for (peer_id, expected_status_revision) in [
        (&request.first_peer_id, request.first_peer_status_revision),
        (&request.second_peer_id, request.second_peer_status_revision),
    ] {
        let accepted = authority
            .accepted_peers
            .peers
            .iter()
            .find(|peer| &peer.identity.peer_id == peer_id)
            .ok_or(ManifoldDirectLaneLeaseRejectionReason::InvalidMesh)?;
        let mesh_member = pair_members
            .iter()
            .find(|member| &member.peer_id == peer_id)
            .ok_or(ManifoldDirectLaneLeaseRejectionReason::InvalidMesh)?;
        if accepted.status.status_revision != expected_status_revision
            || mesh_member.status_revision != expected_status_revision
            || accepted.status.availability != ManifoldPeerAvailability::Ready
            || accepted.status.observed_at_ms > now_ms
            || accepted.status.expires_at_ms <= now_ms
            || accepted.status.expires_at_ms != mesh_member.expires_at_ms
        {
            return Err(ManifoldDirectLaneLeaseRejectionReason::InvalidMesh);
        }
    }
    let route = mesh
        .selected_routes
        .iter()
        .find(|route| route.candidate_id == request.selected_route_id)
        .ok_or(ManifoldDirectLaneLeaseRejectionReason::RouteNotEligible)?;
    if !route.direct_media_lane_eligible
        || route.evidence_expires_at_ms <= now_ms
        || route.route_contract_id.as_str() != DIRECT_P2P_ROUTE_CONTRACT
        || route.pair_evidence_receipt_id != request.pair_evidence_receipt_id
        || route.pair_evidence_sha256 != request.pair_evidence_sha256
        || route.pair_authority_revision != request.pair_authority_revision
        || route.pair_authority_epoch != request.pair_authority_epoch
        || route.signer_key_ids != request.pair_signer_key_ids
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
        .map(|member_expiry| member_expiry.min(route.evidence_expires_at_ms))
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
    if topology.signer_key_ids != receipt.signer_key_ids
        || request.pair_evidence_receipt_id != receipt.receipt_id
        || request.pair_evidence_sha256 != receipt.nonce_sha256
        || request.pair_authority_revision != receipt.resulting_authority_revision
        || request.pair_authority_epoch != receipt.coordinator_epoch
        || request.pair_signer_key_ids != receipt.signer_key_ids
    {
        return Err(ManifoldDirectLaneLeaseRejectionReason::TopologyNotAuthorized);
    }
    Ok(authorization
        .expires_at_ms
        .min(proposal.expires_at_ms)
        .min(receipt.expires_at_ms))
}

fn validate_media_scope(
    media_sessions: &ManifoldMediaSessionAcceptanceState,
    live_provider_epoch_id: &DottedId,
    request: &ManifoldDirectLaneLeaseRequest,
    caller: Option<&DottedId>,
    now_ms: u64,
) -> Result<(), ManifoldDirectLaneLeaseRejectionReason> {
    if media_sessions.schema_id.as_str() != MANIFOLD_MEDIA_SESSION_ACCEPTANCE_STATE_SCHEMA {
        return Err(ManifoldDirectLaneLeaseRejectionReason::SchemaMismatch);
    }
    if !validate_media_session_acceptance_state(media_sessions) {
        return Err(ManifoldDirectLaneLeaseRejectionReason::MediaSessionNotAccepted);
    }
    match (
        &request.scope,
        &request.media_session_id,
        request.expected_media_session_authority_revision,
        request.expected_media_acceptance_authority_revision,
        &request.media_session_decision_id,
        &request.media_session_descriptor_canonical_sha256,
        &request.media_session_provider_epoch_id,
        &request.media_session_platform_runtime_spec_id,
    ) {
        (ManifoldDirectLaneLeaseScope::PeerSession, None, None, None, None, None, None, None) => {}
        (
            ManifoldDirectLaneLeaseScope::MediaSession,
            Some(media_session_id),
            Some(session_revision),
            Some(acceptance_revision),
            Some(decision_id),
            Some(descriptor_digest),
            Some(provider_epoch_id),
            Some(runtime_spec_id),
        ) if media_sessions.authority_revision == acceptance_revision
            && media_sessions.sessions.iter().any(|accepted| {
                &accepted.session_id == media_session_id
                    && accepted.session_authority_revision == session_revision
                    && &accepted.decision_id == decision_id
                    && &accepted.product_descriptor_canonical_sha256 == descriptor_digest
                    && &accepted.provider_epoch_id == provider_epoch_id
                    && &accepted.platform_runtime_spec_id == runtime_spec_id
                    && caller.is_none_or(|client_id| &accepted.runtime_client_id == client_id)
                    && accepted.product_id == request.product_id
                    && accepted.feature_lock_id == request.feature_lock_id
                    && accepted.feature_lock_fingerprint == request.feature_lock_fingerprint
                    && accepted.lifecycle_status == ManifoldMediaSessionLifecycleStatus::Current
                    && accepted.provider_epoch_id == *live_provider_epoch_id
                    && accepted.accepted_at_ms <= now_ms
                    && accepted.expires_at_ms > now_ms
                    && accepted
                        .product_binding
                        .descriptor
                        .route_ids
                        .contains(&request.selected_route_id)
            }) => {}
        (ManifoldDirectLaneLeaseScope::PeerSession, ..)
        | (ManifoldDirectLaneLeaseScope::MediaSession, None, ..)
        | (ManifoldDirectLaneLeaseScope::MediaSession, _, None, ..)
        | (ManifoldDirectLaneLeaseScope::MediaSession, _, _, None, ..)
        | (ManifoldDirectLaneLeaseScope::MediaSession, _, _, _, None, ..)
        | (ManifoldDirectLaneLeaseScope::MediaSession, _, _, _, _, None, ..)
        | (ManifoldDirectLaneLeaseScope::MediaSession, _, _, _, _, _, None, _)
        | (ManifoldDirectLaneLeaseScope::MediaSession, _, _, _, _, _, _, None) => {
            return Err(ManifoldDirectLaneLeaseRejectionReason::ScopeMismatch);
        }
        _ => {
            return Err(ManifoldDirectLaneLeaseRejectionReason::MediaSessionNotAccepted);
        }
    }
    Ok(())
}

fn validate_client_grant(
    grants: &[ManifoldDirectLaneClientGrant],
    request: &ManifoldDirectLaneLeaseRequest,
    runtime: ManifoldDirectLaneRuntimeCommandContext<'_>,
) -> Result<(), ManifoldDirectLaneLeaseRejectionReason> {
    let command = runtime.command_request;
    let runtime_lease_id = command
        .lease_id
        .as_ref()
        .ok_or(ManifoldDirectLaneLeaseRejectionReason::ClientNotAuthorized)?;
    let required_capability = match request.scope {
        ManifoldDirectLaneLeaseScope::PeerSession => DIRECT_LANE_PEER_SESSION_CAPABILITY,
        ManifoldDirectLaneLeaseScope::MediaSession => DIRECT_LANE_MEDIA_SESSION_CAPABILITY,
    };
    if grants.iter().any(|grant| {
        grant.runtime_host_id == *runtime.runtime_host_id
            && grant.client_id == command.requester_id
            && &grant.runtime_lease_id == runtime_lease_id
            && grant.product_id == request.product_id
            && grant.feature_lock_id == request.feature_lock_id
            && grant.feature_lock_fingerprint == request.feature_lock_fingerprint
            && request.capability_id.as_str() == required_capability
            && match request.scope {
                ManifoldDirectLaneLeaseScope::PeerSession => {
                    grant.peer_session_capability_id.as_ref() == Some(&request.capability_id)
                }
                ManifoldDirectLaneLeaseScope::MediaSession => {
                    grant.media_session_capability_id.as_ref() == Some(&request.capability_id)
                }
            }
            && grant.admission_grant_id == request.admission_grant_id
    }) {
        Ok(())
    } else {
        Err(ManifoldDirectLaneLeaseRejectionReason::ClientNotAuthorized)
    }
}

fn validate_runtime_command(
    runtime: ManifoldDirectLaneRuntimeCommandContext<'_>,
    expected_command_id: &str,
    expected_params: &ManifoldRuntimeTypedParamsDigest,
) -> Result<(), ManifoldDirectLaneLeaseRejectionReason> {
    let command = runtime.command_request;
    let dispatch = runtime.dispatch;
    let application = runtime.application;
    if command.schema_id.as_str() != HOST_COMMAND_REQUEST_SCHEMA
        || command.command_id.as_str() != expected_command_id
        || command.lease_id.is_none()
        || command.params_digest.as_ref() != Some(expected_params)
        || dispatch.schema_id.as_str() != HOST_DISPATCH_RECEIPT_SCHEMA
        || dispatch.authority_host_id != *runtime.runtime_host_id
        || dispatch.dispatch_id != derived("dispatch.runtime", &command.request_id)
        || dispatch.request_id != command.request_id
        || dispatch.command_id != command.command_id
        || dispatch.params_digest != command.params_digest
        || dispatch.reviewed_authority_revision != command.expected_authority_revision
        || dispatch.outcome != ManifoldRuntimeDispatchOutcome::Ready
        || dispatch.rejection_reason.is_some()
        || application.schema_id.as_str() != HOST_APPLICATION_RECEIPT_SCHEMA
        || application.authority_host_id != *runtime.runtime_host_id
        || application.receipt_id != derived("receipt.runtime", &command.request_id)
        || application.dispatch_id != dispatch.dispatch_id
        || application.request_id != command.request_id
        || application.params_digest != command.params_digest
        || !application.applied
        || application.rejection_reason.is_some()
        || application.prior_authority_revision != dispatch.reviewed_authority_revision
        || application.resulting_authority_revision
            != application
                .prior_authority_revision
                .next()
                .unwrap_or(application.prior_authority_revision)
    {
        return Err(ManifoldDirectLaneLeaseRejectionReason::ClientNotAuthorized);
    }
    Ok(())
}

fn lease_caller_is_granted(
    grants: &[ManifoldDirectLaneClientGrant],
    lease: &ManifoldDirectLaneLease,
) -> bool {
    grants.iter().any(|grant| {
        grant.runtime_host_id == lease.runtime_authority_host_id
            && grant.client_id == lease.holder_client_id
            && grant.runtime_lease_id == lease.holder_runtime_lease_id
            && grant.product_id == lease.product_id
            && grant.feature_lock_id == lease.feature_lock_id
            && grant.feature_lock_fingerprint == lease.feature_lock_fingerprint
            && grant.admission_grant_id == lease.admission_grant_id
            && match lease.scope {
                ManifoldDirectLaneLeaseScope::PeerSession => {
                    grant.peer_session_capability_id.as_ref() == Some(&lease.capability_id)
                        && lease.capability_id.as_str() == DIRECT_LANE_PEER_SESSION_CAPABILITY
                }
                ManifoldDirectLaneLeaseScope::MediaSession => {
                    grant.media_session_capability_id.as_ref() == Some(&lease.capability_id)
                        && lease.capability_id.as_str() == DIRECT_LANE_MEDIA_SESSION_CAPABILITY
                }
            }
    })
}

/// Canonical typed params digest for one direct-lane issue request.
pub fn direct_lane_lease_issue_params_digest(
    request: &ManifoldDirectLaneLeaseRequest,
) -> Result<ManifoldRuntimeTypedParamsDigest, serde_json::Error> {
    direct_lane_typed_params_digest(DIRECT_LANE_LEASE_ISSUE_PARAMS_TYPE, request)
}

/// Canonical typed params digest for one direct-lane use request.
pub fn direct_lane_lease_use_params_digest(
    request: &ManifoldDirectLaneLeaseUseRequest,
) -> Result<ManifoldRuntimeTypedParamsDigest, serde_json::Error> {
    direct_lane_typed_params_digest(DIRECT_LANE_LEASE_USE_PARAMS_TYPE, request)
}

/// Canonical typed params digest for one direct-lane revoke request.
pub fn direct_lane_lease_revoke_params_digest(
    request: &ManifoldDirectLaneLeaseRevocation,
) -> Result<ManifoldRuntimeTypedParamsDigest, serde_json::Error> {
    direct_lane_typed_params_digest(DIRECT_LANE_LEASE_REVOKE_PARAMS_TYPE, request)
}

fn direct_lane_typed_params_digest<T: Serialize>(
    params_type_id: &str,
    value: &T,
) -> Result<ManifoldRuntimeTypedParamsDigest, serde_json::Error> {
    let canonical = serde_json::to_vec(value)?;
    Ok(ManifoldRuntimeTypedParamsDigest {
        schema_id: schema(HOST_TYPED_PARAMS_DIGEST_SCHEMA),
        params_type_id: DottedId::new(params_type_id).expect("static params type"),
        canonical_sha256: format!("sha256:{}", encode_lower_hex(&Sha256::digest(canonical))),
        canonical_size_bytes: u32::try_from(serde_json::to_vec(value)?.len()).unwrap_or(u32::MAX),
    })
}

fn encode_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
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
    request: &ManifoldDirectLaneLeaseUseRequest,
    runtime: ManifoldDirectLaneRuntimeCommandContext<'_>,
    now_ms: u64,
) -> Result<ManifoldDirectLaneLeaseCurrentReceipt, ManifoldDirectLaneLeaseRejectionReason> {
    if request.schema_id.as_str() != DIRECT_LANE_LEASE_USE_REQUEST_SCHEMA
        || request.expected_authority_revision != state.authority_revision
        || runtime.command_request.request_id != request.request_id
    {
        return Err(ManifoldDirectLaneLeaseRejectionReason::StaleAuthorityRevision);
    }
    let params = direct_lane_lease_use_params_digest(request)
        .map_err(|_| ManifoldDirectLaneLeaseRejectionReason::ClientNotAuthorized)?;
    validate_runtime_command(runtime, DIRECT_LANE_LEASE_USE_COMMAND, &params)?;
    let lease = state
        .leases
        .iter()
        .find(|lease| lease.lease_id == request.lease_id)
        .ok_or(ManifoldDirectLaneLeaseRejectionReason::TopologyNotAuthorized)?;
    if lease.schema_id.as_str() != DIRECT_LANE_LEASE_RECORD_SCHEMA
        || lease.revoked
        || lease.valid_from_ms > now_ms
        || lease.expires_at_ms <= now_ms
        || lease.peer_ids.len() != 2
        || lease.peer_status_revisions.len() != 2
    {
        return Err(ManifoldDirectLaneLeaseRejectionReason::InvalidExpiry);
    }
    if lease.runtime_authority_host_id != *runtime.runtime_host_id
        || lease.holder_client_id != runtime.command_request.requester_id
        || runtime.command_request.lease_id.as_ref() != Some(&lease.holder_runtime_lease_id)
        || !lease_caller_is_granted(authority.client_grants, lease)
    {
        return Err(ManifoldDirectLaneLeaseRejectionReason::ClientNotAuthorized);
    }
    let mut validation_state = state.clone();
    validation_state
        .leases
        .retain(|candidate| candidate.lease_id != request.lease_id);
    validation_state
        .applied_request_ids
        .retain(|request_id| request_id != &lease.request_id);
    let request = ManifoldDirectLaneLeaseRequest {
        schema_id: schema(DIRECT_LANE_LEASE_REQUEST_SCHEMA),
        request_id: lease.request_id.clone(),
        expected_lease_authority_revision: state.authority_revision,
        expected_peer_authority_revision: authority.accepted_peers.authority_revision,
        expected_mesh_authority_revision: authority.mesh.authority_revision,
        expected_mesh_authority_epoch: authority.mesh.authority_epoch,
        expected_mesh_coordinator_peer_id: authority
            .mesh
            .coordinator_peer_id
            .clone()
            .ok_or(ManifoldDirectLaneLeaseRejectionReason::InvalidMesh)?,
        expected_enrollment_authority_revision: authority.enrollment.authority_revision,
        expected_rendezvous_authority_revision: authority.rendezvous.authority_revision,
        expected_peer_session_authority_revision: authority.peer_sessions.authority_revision,
        first_peer_status_revision: lease.peer_status_revisions[0],
        second_peer_status_revision: lease.peer_status_revisions[1],
        pair_evidence_receipt_id: lease.pair_evidence_receipt_id.clone(),
        pair_evidence_sha256: lease.pair_evidence_sha256.clone(),
        pair_authority_revision: lease.pair_authority_revision,
        pair_authority_epoch: lease.pair_authority_epoch,
        pair_signer_key_ids: lease.pair_signer_key_ids.clone(),
        expected_media_session_authority_revision: lease.media_session_authority_revision,
        expected_media_acceptance_authority_revision: lease
            .media_acceptance_authority_revision
            .map(|_| authority.media_sessions.authority_revision),
        mesh_id: lease.mesh_id.clone(),
        selected_route_id: lease.selected_route_id.clone(),
        first_peer_id: lease.peer_ids[0].clone(),
        second_peer_id: lease.peer_ids[1].clone(),
        peer_session_id: lease.peer_session_id.clone(),
        media_session_id: lease.media_session_id.clone(),
        media_session_decision_id: lease.media_session_decision_id.clone(),
        media_session_descriptor_canonical_sha256: lease
            .media_session_descriptor_canonical_sha256
            .clone(),
        media_session_provider_epoch_id: lease.media_session_provider_epoch_id.clone(),
        media_session_platform_runtime_spec_id: lease
            .media_session_platform_runtime_spec_id
            .clone(),
        product_id: lease.product_id.clone(),
        feature_lock_id: lease.feature_lock_id.clone(),
        feature_lock_fingerprint: lease.feature_lock_fingerprint.clone(),
        capability_id: lease.capability_id.clone(),
        admission_grant_id: lease.admission_grant_id.clone(),
        scope: lease.scope.clone(),
        expires_at_ms: lease.expires_at_ms,
    };
    validate_request(&validation_state, authority, &request, None, now_ms)?;
    Ok(ManifoldDirectLaneLeaseCurrentReceipt {
        schema_id: schema(DIRECT_LANE_LEASE_CURRENT_RECEIPT_SCHEMA),
        request_id: runtime.command_request.request_id.clone(),
        lease_id: lease.lease_id.clone(),
        holder_client_id: lease.holder_client_id.clone(),
        holder_runtime_lease_id: lease.holder_runtime_lease_id.clone(),
        product_id: lease.product_id.clone(),
        feature_lock_id: lease.feature_lock_id.clone(),
        feature_lock_fingerprint: lease.feature_lock_fingerprint.clone(),
        capability_id: lease.capability_id.clone(),
        admission_grant_id: lease.admission_grant_id.clone(),
        authority_revision: state.authority_revision,
        validated_at_ms: now_ms,
        expires_at_ms: lease.expires_at_ms,
    })
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
    runtime: ManifoldDirectLaneRuntimeCommandContext<'_>,
    client_grants: &[ManifoldDirectLaneClientGrant],
    trusted_revoker_ids: &[DottedId],
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
    let params = direct_lane_lease_revoke_params_digest(request)
        .map_err(|_| "direct-lane revoke typed params invalid".to_owned())?;
    validate_runtime_command(runtime, DIRECT_LANE_LEASE_REVOKE_COMMAND, &params)
        .map_err(|_| "direct-lane revoke Runtime Host command not accepted".to_owned())?;
    if state.applied_request_ids.contains(&request.revocation_id) {
        return Err("direct-lane lease revocation replay".to_owned());
    }
    let mut next = state.clone();
    let lease = next
        .leases
        .iter_mut()
        .find(|lease| lease.lease_id == request.lease_id && !lease.revoked)
        .ok_or_else(|| "active direct-lane lease not found".to_owned())?;
    let holder = lease.runtime_authority_host_id == *runtime.runtime_host_id
        && lease.holder_client_id == runtime.command_request.requester_id
        && runtime.command_request.lease_id.as_ref() == Some(&lease.holder_runtime_lease_id)
        && lease_caller_is_granted(client_grants, lease);
    let operator = trusted_revoker_ids.contains(&runtime.command_request.requester_id);
    if !holder && !operator {
        return Err("direct-lane lease holder mismatch".to_owned());
    }
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

fn valid_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use rusty_manifold_admission::ManifoldClientIdentity;
    use rusty_manifold_media_session::{
        canonical_media_session_sha256, media_session_acceptance_params_digest,
        review_and_apply_media_session_acceptance, ManifoldMediaSessionAcceptanceRequest,
        ManifoldMediaSessionAcceptanceState, ManifoldMediaSessionClientGrant,
        ManifoldMediaSessionProductBinding, ManifoldMediaSessionRuntimeCommandContext,
        MANIFOLD_MEDIA_SESSION_ACCEPTANCE_REQUEST_SCHEMA, MANIFOLD_MEDIA_SESSION_ACCEPT_COMMAND,
        MANIFOLD_MEDIA_SESSION_BINDING_SCHEMA,
    };
    use rusty_manifold_model::ManifoldMediaSessionDescriptor;
    use rusty_manifold_runtime_host::{
        ManifoldRuntimeCommandDescriptor, ManifoldRuntimeCommandRequest, ManifoldRuntimeHost,
        ManifoldRuntimeHostSnapshot, ManifoldRuntimeLease, HOST_COMMAND_REQUEST_SCHEMA,
        HOST_SNAPSHOT_SCHEMA,
    };
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::{
        ManifoldAcceptedMeshMember, ManifoldAcceptedPeer, ManifoldAcceptedPeerSession,
        ManifoldPeerCredentialAlgorithm, ManifoldPeerCredentialRecord,
        ManifoldPeerCredentialStatus, ManifoldPeerIdentity, ManifoldPeerMeshSelectedRoute,
        ManifoldPeerRole, ManifoldPeerSessionProposal, ManifoldPeerStatus,
        ManifoldPeerTopologyAuthorization, ManifoldRendezvousReceipt,
        PeerRendezvousAuthenticationEvidence, PeerRendezvousTransport, PEER_CREDENTIAL_SCHEMA,
        PEER_ENROLLMENT_STATE_SCHEMA, PEER_IDENTITY_SCHEMA, PEER_SNAPSHOT_SCHEMA,
        PEER_STATUS_SCHEMA, RENDEZVOUS_AUTHORITY_STATE_SCHEMA, RENDEZVOUS_RECEIPT_SCHEMA,
    };

    fn id(value: &str) -> DottedId {
        DottedId::new(value).expect("test id")
    }

    struct AuthorityFixture {
        accepted_peers: ManifoldAcceptedPeerState,
        enrollment: ManifoldPeerEnrollmentState,
        rendezvous: ManifoldRendezvousAuthorityState,
        mesh: ManifoldPeerMeshState,
        peer_sessions: ManifoldPeerSessionState,
        topology: ManifoldSignedPeerTopologyAuthorization,
        media_sessions: ManifoldMediaSessionAcceptanceState,
        provider_epoch_id: DottedId,
        direct_lane_client_grants: Vec<ManifoldDirectLaneClientGrant>,
    }

    impl AuthorityFixture {
        fn context(&self) -> ManifoldDirectLaneLeaseAuthorityContext<'_> {
            ManifoldDirectLaneLeaseAuthorityContext {
                accepted_peers: &self.accepted_peers,
                enrollment: &self.enrollment,
                rendezvous: &self.rendezvous,
                mesh: &self.mesh,
                peer_sessions: &self.peer_sessions,
                topology: &self.topology,
                media_sessions: &self.media_sessions,
                live_provider_epoch_id: &self.provider_epoch_id,
                client_grants: &self.direct_lane_client_grants,
            }
        }
    }

    struct DirectProof {
        host_id: DottedId,
        command: ManifoldRuntimeCommandRequest,
        dispatch: ManifoldRuntimeDispatchReceipt,
        application: ManifoldRuntimeApplicationReceipt,
    }

    impl DirectProof {
        fn context(&self) -> ManifoldDirectLaneRuntimeCommandContext<'_> {
            ManifoldDirectLaneRuntimeCommandContext {
                runtime_host_id: &self.host_id,
                command_request: &self.command,
                dispatch: &self.dispatch,
                application: &self.application,
            }
        }
    }

    fn direct_proof(
        request_id: DottedId,
        command_id: &str,
        params_digest: ManifoldRuntimeTypedParamsDigest,
        now_ms: u64,
    ) -> DirectProof {
        let host_id = id("host.runtime.direct-lane-test");
        let client_id = id("client.quest.media-test");
        let lease_id = id("lease.runtime.media-test");
        let scope = id("scope.direct-lane.authority");
        let mut host = ManifoldRuntimeHost::from_snapshot(ManifoldRuntimeHostSnapshot {
            schema_id: schema(HOST_SNAPSHOT_SCHEMA),
            host_id: host_id.clone(),
            authority_revision: Revision::INITIAL,
            commands: vec![ManifoldRuntimeCommandDescriptor {
                command_id: id(command_id),
                required_lease_scope: Some(scope.clone()),
            }],
            leases: vec![ManifoldRuntimeLease {
                lease_id: lease_id.clone(),
                scope,
                holder_id: client_id.clone(),
                expires_at_ms: 100_000,
            }],
            applied_request_ids: Vec::new(),
            reviewed_sweep_ids: Vec::new(),
            audit_events: Vec::new(),
        })
        .expect("direct Runtime Host");
        let command = ManifoldRuntimeCommandRequest {
            schema_id: schema(HOST_COMMAND_REQUEST_SCHEMA),
            request_id,
            expected_authority_revision: Revision::INITIAL,
            requester_id: client_id,
            command_id: id(command_id),
            lease_id: Some(lease_id),
            params_digest: Some(params_digest),
            issued_at_ms: now_ms.saturating_sub(1),
            expires_at_ms: now_ms.saturating_add(1_000),
        };
        let dispatch = host.review_command(&command, now_ms);
        let application = host.apply_dispatch(&command, &dispatch, now_ms);
        DirectProof {
            host_id,
            command,
            dispatch,
            application,
        }
    }

    fn issue(
        state: &ManifoldDirectLaneLeaseState,
        authority: &AuthorityFixture,
        request: &ManifoldDirectLaneLeaseRequest,
        now_ms: u64,
    ) -> (ManifoldDirectLaneLeaseState, ManifoldDirectLaneLeaseReceipt) {
        let proof = direct_proof(
            id(&format!("runtime.{}", request.request_id.as_str())),
            DIRECT_LANE_LEASE_ISSUE_COMMAND,
            direct_lane_lease_issue_params_digest(request).expect("params"),
            now_ms,
        );
        review_and_apply_direct_lane_lease(
            state,
            &authority.context(),
            request,
            proof.context(),
            now_ms,
        )
    }

    fn use_lease(
        state: &ManifoldDirectLaneLeaseState,
        authority: &AuthorityFixture,
        lease_id: DottedId,
        request_id: &str,
        now_ms: u64,
    ) -> Result<ManifoldDirectLaneLeaseCurrentReceipt, ManifoldDirectLaneLeaseRejectionReason> {
        let request = ManifoldDirectLaneLeaseUseRequest {
            schema_id: schema(DIRECT_LANE_LEASE_USE_REQUEST_SCHEMA),
            request_id: id(request_id),
            expected_authority_revision: state.authority_revision,
            lease_id,
        };
        let proof = direct_proof(
            request.request_id.clone(),
            DIRECT_LANE_LEASE_USE_COMMAND,
            direct_lane_lease_use_params_digest(&request).expect("params"),
            now_ms,
        );
        validate_current_direct_lane_lease(
            state,
            &authority.context(),
            &request,
            proof.context(),
            now_ms,
        )
    }

    fn revoke_lease(
        state: &ManifoldDirectLaneLeaseState,
        authority: &AuthorityFixture,
        request: &ManifoldDirectLaneLeaseRevocation,
        now_ms: u64,
    ) -> Result<ManifoldDirectLaneLeaseState, String> {
        let proof = direct_proof(
            request.revocation_id.clone(),
            DIRECT_LANE_LEASE_REVOKE_COMMAND,
            direct_lane_lease_revoke_params_digest(request).expect("params"),
            now_ms,
        );
        revoke_direct_lane_lease(
            state,
            request,
            proof.context(),
            &authority.direct_lane_client_grants,
            &[],
        )
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
                pair_evidence_receipt_id: id("receipt.peer.rendezvous.alpha-beta.001"),
                pair_evidence_sha256: format!("sha256:{}", "a1".repeat(32)),
                pair_authority_revision: Revision::new(3).expect("revision"),
                pair_authority_epoch: 3,
                signer_key_ids: vec![id("key.peer.alpha.001"), id("key.peer.beta.001")],
                evidence_expires_at_ms: 55_000,
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
            coordinator_epoch: 3,
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
        let media_descriptor = ManifoldMediaSessionDescriptor {
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
        };
        let media_binding = ManifoldMediaSessionProductBinding {
            schema_id: MANIFOLD_MEDIA_SESSION_BINDING_SCHEMA.to_owned(),
            descriptor_canonical_sha256: canonical_media_session_sha256(&media_descriptor)
                .expect("digest"),
            descriptor: media_descriptor,
        };
        let provider_epoch_id = id("provider.epoch.quest-pair.001");
        let media_request = ManifoldMediaSessionAcceptanceRequest {
            schema_id: schema(MANIFOLD_MEDIA_SESSION_ACCEPTANCE_REQUEST_SCHEMA),
            request_id: id("request.media-session.quest-pair.001"),
            expected_authority_revision: Revision::INITIAL,
            runtime_command_request_id: id("request.runtime.media-session.quest-pair.001"),
            expected_provider_epoch_id: provider_epoch_id.clone(),
            product_id: id("product.quest.media-test"),
            feature_lock_id: id("lock.quest.media-test"),
            feature_lock_fingerprint: format!("sha256:{}", "ab".repeat(32)),
            capability_id: id("capability.media.session.accept"),
            admission_grant_id: id("grant.quest.media-test"),
            expires_at_ms: 60_000,
            product_binding: media_binding,
        };
        let runtime_host_id = id("host.runtime.media-test");
        let runtime_client_id = id("client.quest.media-test");
        let runtime_lease_id = id("lease.runtime.media-test");
        let runtime_scope = id("scope.media.session.authority");
        let mut runtime = ManifoldRuntimeHost::from_snapshot(ManifoldRuntimeHostSnapshot {
            schema_id: schema(HOST_SNAPSHOT_SCHEMA),
            host_id: runtime_host_id.clone(),
            authority_revision: Revision::INITIAL,
            commands: vec![ManifoldRuntimeCommandDescriptor {
                command_id: id(MANIFOLD_MEDIA_SESSION_ACCEPT_COMMAND),
                required_lease_scope: Some(runtime_scope.clone()),
            }],
            leases: vec![ManifoldRuntimeLease {
                lease_id: runtime_lease_id.clone(),
                scope: runtime_scope,
                holder_id: runtime_client_id.clone(),
                expires_at_ms: 100_000,
            }],
            applied_request_ids: Vec::new(),
            reviewed_sweep_ids: Vec::new(),
            audit_events: Vec::new(),
        })
        .expect("runtime");
        let runtime_request = ManifoldRuntimeCommandRequest {
            schema_id: schema(HOST_COMMAND_REQUEST_SCHEMA),
            request_id: media_request.runtime_command_request_id.clone(),
            expected_authority_revision: Revision::INITIAL,
            requester_id: runtime_client_id.clone(),
            command_id: id(MANIFOLD_MEDIA_SESSION_ACCEPT_COMMAND),
            lease_id: Some(runtime_lease_id.clone()),
            params_digest: Some(
                media_session_acceptance_params_digest(&media_request).expect("params"),
            ),
            issued_at_ms: 1_000,
            expires_at_ms: 10_000,
        };
        let dispatch = runtime.review_command(&runtime_request, 2_000);
        let application = runtime.apply_dispatch(&runtime_request, &dispatch, 2_000);
        let client_grants = vec![ManifoldMediaSessionClientGrant {
            broker_adapter_id: id("adapter.broker.media-test"),
            broker_runtime_host_id: id("host.broker.media-test"),
            broker_product_lock_id: id("lock.broker.media-test"),
            broker_product_lock_fingerprint: "fnv1a64-0011223344556677".to_owned(),
            broker_product_lock_sha256: format!("sha256:{}", "d1".repeat(32)),
            broker_capability_id: id("capability.command.media.session.start"),
            broker_command_id: id("command.media.session.start"),
            broker_runtime_lease_id: id("lease.broker.media-test"),
            broker_client_identity: ManifoldClientIdentity {
                client_id: runtime_client_id.clone(),
                platform_subject: "org.rustyquest.media_test".to_owned(),
                signing_fingerprint: format!("sha256:{}", "a1".repeat(32)),
            },
            broker_client_lock_id: id("lock.client.media-test"),
            broker_client_lock_fingerprint: format!("sha256:{}", "c1".repeat(32)),
            runtime_host_id: runtime_host_id.clone(),
            client_id: runtime_client_id.clone(),
            lease_id: runtime_lease_id,
            product_id: media_request.product_id.clone(),
            feature_lock_id: media_request.feature_lock_id.clone(),
            feature_lock_fingerprint: media_request.feature_lock_fingerprint.clone(),
            capability_id: media_request.capability_id.clone(),
            admission_grant_id: media_request.admission_grant_id.clone(),
            allowed_session_id: media_request.product_binding.descriptor.session_id.clone(),
            allowed_platform_runtime_spec_id: media_request
                .product_binding
                .descriptor
                .platform_runtime_spec_id
                .clone(),
            allowed_descriptor_canonical_sha256: vec![media_request
                .product_binding
                .descriptor_canonical_sha256
                .clone()],
            allowed_resource_ids: {
                let descriptor = &media_request.product_binding.descriptor;
                let mut ids = descriptor
                    .source_ids
                    .iter()
                    .chain(&descriptor.processor_ids)
                    .chain(&descriptor.route_ids)
                    .chain(&descriptor.sink_ids)
                    .chain(&descriptor.stream_ids)
                    .cloned()
                    .collect::<Vec<_>>();
                ids.sort();
                ids
            },
        }];
        let trusted_revokers = Vec::new();
        let (media_sessions, media_receipt) = review_and_apply_media_session_acceptance(
            &ManifoldMediaSessionAcceptanceState::empty(),
            &media_request,
            ManifoldMediaSessionRuntimeCommandContext {
                runtime_host_id: &runtime_host_id,
                live_provider_epoch_id: &provider_epoch_id,
                client_grants: &client_grants,
                trusted_revoker_ids: &trusted_revokers,
                command_request: &runtime_request,
                dispatch: &dispatch,
                application: &application,
            },
            2_000,
        );
        assert!(media_receipt.accepted);
        AuthorityFixture {
            accepted_peers: ManifoldAcceptedPeerState {
                schema_id: schema(PEER_SNAPSHOT_SCHEMA),
                authority_revision: Revision::new(4).expect("revision"),
                peers: ["peer.alpha", "peer.beta", "peer.gamma"]
                    .into_iter()
                    .map(|peer_id| ManifoldAcceptedPeer {
                        identity: ManifoldPeerIdentity {
                            schema_id: schema(PEER_IDENTITY_SCHEMA),
                            peer_id: id(peer_id),
                            key_fingerprint: id(&format!("fingerprint.{peer_id}")),
                            trust_domain: id("trust.morphospace.peer"),
                            roles: vec![ManifoldPeerRole::Rendezvous],
                        },
                        status: ManifoldPeerStatus {
                            schema_id: schema(PEER_STATUS_SCHEMA),
                            peer_id: id(peer_id),
                            status_revision: Revision::new(2).expect("revision"),
                            observed_at_ms: 1_000,
                            expires_at_ms: 90_000,
                            availability: ManifoldPeerAvailability::Ready,
                            capability_ids: vec![id("capability.peer.presence")],
                        },
                    })
                    .collect(),
                applied_proposal_ids: Vec::new(),
            },
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
            media_sessions,
            provider_epoch_id,
            direct_lane_client_grants: vec![ManifoldDirectLaneClientGrant {
                runtime_host_id: id("host.runtime.direct-lane-test"),
                client_id: id("client.quest.media-test"),
                runtime_lease_id: id("lease.runtime.media-test"),
                product_id: id("product.quest.media-test"),
                feature_lock_id: id("lock.quest.media-test"),
                feature_lock_fingerprint: format!("sha256:{}", "ab".repeat(32)),
                peer_session_capability_id: Some(id(DIRECT_LANE_PEER_SESSION_CAPABILITY)),
                media_session_capability_id: Some(id(DIRECT_LANE_MEDIA_SESSION_CAPABILITY)),
                admission_grant_id: id("grant.quest.direct-lane"),
            }],
        }
    }

    fn request() -> ManifoldDirectLaneLeaseRequest {
        ManifoldDirectLaneLeaseRequest {
            schema_id: schema(DIRECT_LANE_LEASE_REQUEST_SCHEMA),
            request_id: id("request.direct-lane.alpha-beta.001"),
            expected_lease_authority_revision: Revision::INITIAL,
            expected_peer_authority_revision: Revision::new(4).expect("revision"),
            expected_mesh_authority_revision: Revision::new(4).expect("revision"),
            expected_mesh_authority_epoch: 3,
            expected_mesh_coordinator_peer_id: id("peer.alpha"),
            expected_enrollment_authority_revision: Revision::new(3).expect("revision"),
            expected_rendezvous_authority_revision: Revision::new(3).expect("revision"),
            expected_peer_session_authority_revision: Revision::new(5).expect("revision"),
            first_peer_status_revision: Revision::new(2).expect("revision"),
            second_peer_status_revision: Revision::new(2).expect("revision"),
            pair_evidence_receipt_id: id("receipt.peer.rendezvous.alpha-beta.001"),
            pair_evidence_sha256: format!("sha256:{}", "a1".repeat(32)),
            pair_authority_revision: Revision::new(3).expect("revision"),
            pair_authority_epoch: 3,
            pair_signer_key_ids: vec![id("key.peer.alpha.001"), id("key.peer.beta.001")],
            expected_media_session_authority_revision: Some(Revision::new(6).expect("revision")),
            expected_media_acceptance_authority_revision: Some(Revision::new(2).expect("revision")),
            mesh_id: id("mesh.quest.product.001"),
            selected_route_id: id("route.alpha-beta.direct"),
            first_peer_id: id("peer.alpha"),
            second_peer_id: id("peer.beta"),
            peer_session_id: id("session.peer.alpha-beta.001"),
            media_session_id: Some(id("session.media.quest-pair.001")),
            media_session_decision_id: Some(id(
                "decision.media-session.request.media-session.quest-pair.001",
            )),
            media_session_descriptor_canonical_sha256: Some(
                authority_fixture().media_sessions.sessions[0]
                    .product_descriptor_canonical_sha256
                    .clone(),
            ),
            media_session_provider_epoch_id: Some(id("provider.epoch.quest-pair.001")),
            media_session_platform_runtime_spec_id: Some(id("runtime.quest.direct-p2p")),
            product_id: id("product.quest.media-test"),
            feature_lock_id: id("lock.quest.media-test"),
            feature_lock_fingerprint: format!("sha256:{}", "ab".repeat(32)),
            capability_id: id(DIRECT_LANE_MEDIA_SESSION_CAPABILITY),
            admission_grant_id: id("grant.quest.direct-lane"),
            scope: ManifoldDirectLaneLeaseScope::MediaSession,
            expires_at_ms: 50_000,
        }
    }

    #[test]
    fn eligible_route_becomes_a_revisioned_real_media_lease() {
        let state = ManifoldDirectLaneLeaseState::empty();
        let authority = authority_fixture();
        let (next, receipt) = issue(&state, &authority, &request(), 3_000);
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
            let (unchanged, receipt) = issue(&state, &authority, &request, 3_000);
            assert_eq!(unchanged, state);
            assert_eq!(receipt.rejection_reason, Some(expected));
        }

        let mut ineligible_authority = authority_fixture();
        ineligible_authority.mesh.selected_routes[0].direct_media_lane_eligible = false;
        let (_, receipt) = issue(
            &ManifoldDirectLaneLeaseState::empty(),
            &ineligible_authority,
            &baseline,
            3_000,
        );
        assert_eq!(
            receipt.rejection_reason,
            Some(ManifoldDirectLaneLeaseRejectionReason::RouteNotEligible)
        );

        let mut denied_authority = authority_fixture();
        denied_authority.topology.topology_authorization.authorized = false;
        let (_, receipt) = issue(
            &ManifoldDirectLaneLeaseState::empty(),
            &denied_authority,
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
                authority.mesh.selected_routes[0].pair_evidence_sha256 =
                    format!("sha256:{}", "00".repeat(32));
                (
                    authority,
                    ManifoldDirectLaneLeaseRejectionReason::RouteNotEligible,
                )
            },
            {
                let mut authority = authority_fixture();
                authority.mesh.selected_routes[0].evidence_expires_at_ms = 3_000;
                (
                    authority,
                    ManifoldDirectLaneLeaseRejectionReason::RouteNotEligible,
                )
            },
            {
                let mut authority = authority_fixture();
                authority.mesh.authority_epoch = 4;
                (
                    authority,
                    ManifoldDirectLaneLeaseRejectionReason::InvalidMesh,
                )
            },
            {
                let mut authority = authority_fixture();
                authority.rendezvous.accepted_receipts[0].coordinator_epoch = 4;
                (
                    authority,
                    ManifoldDirectLaneLeaseRejectionReason::TopologyNotAuthorized,
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
            let (unchanged, receipt) = issue(&state, &authority, &baseline, 3_000);
            assert_eq!(unchanged, state);
            assert_eq!(receipt.rejection_reason, Some(expected));
        }
    }

    #[test]
    fn lease_expiry_is_capped_by_retained_route_evidence() {
        let authority = authority_fixture();
        let mut overlong = request();
        overlong.expires_at_ms = authority.mesh.selected_routes[0].evidence_expires_at_ms + 1;
        let (_, receipt) = issue(
            &ManifoldDirectLaneLeaseState::empty(),
            &authority,
            &overlong,
            3_000,
        );
        assert_eq!(
            receipt.rejection_reason,
            Some(ManifoldDirectLaneLeaseRejectionReason::InvalidExpiry)
        );
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
        let (_, receipt) = issue(
            &ManifoldDirectLaneLeaseState::empty(),
            &authority,
            &request(),
            3_000,
        );
        assert!(receipt.applied);
    }

    #[test]
    fn media_scope_requires_exact_valid_descriptor_revision_and_route() {
        let baseline = request();
        let mut wrong_route = authority_fixture();
        wrong_route.media_sessions.sessions[0]
            .product_binding
            .descriptor
            .route_ids = vec![id("route.other.direct")];
        let (_, rejected) = issue(
            &ManifoldDirectLaneLeaseState::empty(),
            &wrong_route,
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
        let (_, rejected) = issue(
            &ManifoldDirectLaneLeaseState::empty(),
            &authority,
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
        peer_only.expected_media_acceptance_authority_revision = None;
        peer_only.media_session_decision_id = None;
        peer_only.media_session_descriptor_canonical_sha256 = None;
        peer_only.media_session_provider_epoch_id = None;
        peer_only.media_session_platform_runtime_spec_id = None;
        peer_only.scope = ManifoldDirectLaneLeaseScope::PeerSession;
        peer_only.capability_id = id(DIRECT_LANE_PEER_SESSION_CAPABILITY);
        let (_, accepted) = issue(
            &ManifoldDirectLaneLeaseState::empty(),
            &authority,
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
        let (issued, receipt) = issue(&state, &authority, &request, 3_000);
        let lease_id = receipt.lease.expect("lease").lease_id;
        use_lease(
            &issued,
            &authority,
            lease_id.clone(),
            "request.direct-lane.use.001",
            3_100,
        )
        .expect("current lease");

        let mut replay = request.clone();
        replay.expected_lease_authority_revision = issued.authority_revision;
        let (unchanged, replay_receipt) = issue(&issued, &authority, &replay, 3_100);
        assert_eq!(unchanged, issued);
        assert_eq!(
            replay_receipt.rejection_reason,
            Some(ManifoldDirectLaneLeaseRejectionReason::ReplayedRequest)
        );

        let mut duplicate = request.clone();
        duplicate.request_id = id("request.direct-lane.alpha-beta.duplicate");
        duplicate.expected_lease_authority_revision = issued.authority_revision;
        let (_, duplicate_receipt) = issue(&issued, &authority, &duplicate, 3_100);
        assert_eq!(
            duplicate_receipt.rejection_reason,
            Some(ManifoldDirectLaneLeaseRejectionReason::ActiveLeaseExists)
        );

        let revoked = revoke_lease(
            &issued,
            &authority,
            &ManifoldDirectLaneLeaseRevocation {
                schema_id: schema(DIRECT_LANE_LEASE_REVOCATION_SCHEMA),
                revocation_id: id("revoke.direct-lane.alpha-beta.001"),
                lease_id: lease_id.clone(),
                expected_authority_revision: issued.authority_revision,
            },
            3_100,
        )
        .expect("revoke");
        assert!(revoked.leases[0].revoked);
        assert_eq!(revoked.authority_revision.get(), 3);
        assert!(use_lease(
            &revoked,
            &authority,
            lease_id.clone(),
            "request.direct-lane.use.revoked",
            3_100
        )
        .is_err());

        let second_request = ManifoldDirectLaneLeaseRequest {
            request_id: id("request.direct-lane.alpha-beta.002"),
            expected_lease_authority_revision: revoked.authority_revision,
            expires_at_ms: 4_000,
            ..duplicate
        };
        let (issued_again, second_receipt) = issue(&revoked, &authority, &second_request, 3_500);
        let second_lease_id = second_receipt.lease.expect("second lease").lease_id;
        let replayed_revocation = revoke_lease(
            &issued_again,
            &authority,
            &ManifoldDirectLaneLeaseRevocation {
                schema_id: schema(DIRECT_LANE_LEASE_REVOCATION_SCHEMA),
                revocation_id: id("revoke.direct-lane.alpha-beta.001"),
                lease_id: second_lease_id,
                expected_authority_revision: issued_again.authority_revision,
            },
            3_600,
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
        let (_, receipt) = issue(
            &ManifoldDirectLaneLeaseState::empty(),
            &authority,
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

    #[test]
    fn legacy_v1_direct_lane_migration_invalidates_unbound_leases_and_keeps_replay() {
        let json = include_str!("../../../fixtures/peer/legacy-v1-direct-lane-active-state.json");
        let (state, receipt) = migrate_legacy_direct_lane_lease_state_json(json)
            .expect("fail-closed direct-lane migration");
        assert_eq!(state.schema_id.as_str(), DIRECT_LANE_LEASE_STATE_SCHEMA);
        assert_eq!(state.authority_revision.get(), 2);
        assert!(state.leases.is_empty());
        assert_eq!(
            state.applied_request_ids,
            vec![id("request.direct.legacy.001")]
        );
        assert_eq!(
            receipt.invalidated_lease_ids,
            vec![id("lease.peer.direct.request.direct.legacy.001")]
        );
        assert_eq!(
            receipt.invalidation_reason,
            id("legacy.provenance.insufficient")
        );
        assert!(direct_lane_state_is_well_formed(&state));

        let damaged = json.replace(
            "lease.peer.direct.request.direct.legacy.001",
            "lease.peer.direct.forged",
        );
        assert!(migrate_legacy_direct_lane_lease_state_json(&damaged).is_err());
    }
}
