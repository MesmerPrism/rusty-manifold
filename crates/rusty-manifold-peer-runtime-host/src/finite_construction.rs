//! Stable typed finite-policy input; no separate wire or authority owner.
use super::*;

/// Version-frozen explicit fields of the finite peer trust policy.
/// All policy choices are supplied by the caller; construction grants no authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldPeerRuntimeTrustPolicyFieldsV1 {
    /// Schema identifier.
    pub schema_id: SchemaId,
    /// Stable policy identity.
    pub policy_id: DottedId,
    /// Explicit policy revision.
    pub revision: Revision,
    /// Canonical authority-family selection resolved from the product lock.
    pub enabled_authority_families: Vec<ManifoldPeerRuntimeAuthorityFamily>,
    /// Operator identities allowed to enroll/rotate/revoke credentials.
    pub trusted_operator_ids: Vec<DottedId>,
    /// Configured non-enrollment key fingerprints (for example a host peer).
    pub trusted_key_fingerprints: Vec<DottedId>,
    /// Platform adapters allowed to propose peer sessions.
    pub trusted_adapter_ids: Vec<DottedId>,
    /// Adapters allowed to propose bounded mesh state.
    pub trusted_mesh_proposer_ids: Vec<DottedId>,
    /// Immutable client/lease/product/feature-lock/capability/grant closures.
    pub media_client_grants: Vec<ManifoldMediaSessionClientGrant>,
    /// Separate operator identities allowed to revoke media sessions.
    pub trusted_media_revoker_ids: Vec<DottedId>,
    /// Immutable direct-lane client/product/capability/grant closures.
    pub direct_lane_client_grants: Vec<ManifoldDirectLaneClientGrant>,
    /// Separate operator identities allowed to revoke direct-lane leases.
    pub trusted_direct_lane_revoker_ids: Vec<DottedId>,
    /// Exact embedded Runtime Host identity for media lifecycle commands.
    pub media_runtime_host_id: DottedId,
    /// Exact lease scope required by every media lifecycle command.
    pub media_runtime_lease_scope_id: DottedId,
    /// Exact separate lease scope required by direct-lane commands.
    pub direct_lane_runtime_lease_scope_id: DottedId,
}

impl ManifoldPeerRuntimeTrustPolicy {
    /// Preserves every explicit finite policy field without selecting new authority.
    /// The ordinary Peer Runtime Host constructor still validates this data.
    pub fn finite(fields: ManifoldPeerRuntimeTrustPolicyFieldsV1) -> Self {
        Self {
            schema_id: fields.schema_id,
            policy_id: fields.policy_id,
            revision: fields.revision,
            enabled_authority_families: fields.enabled_authority_families,
            trusted_operator_ids: fields.trusted_operator_ids,
            trusted_key_fingerprints: fields.trusted_key_fingerprints,
            trusted_adapter_ids: fields.trusted_adapter_ids,
            trusted_mesh_proposer_ids: fields.trusted_mesh_proposer_ids,
            media_client_grants: fields.media_client_grants,
            trusted_media_revoker_ids: fields.trusted_media_revoker_ids,
            direct_lane_client_grants: fields.direct_lane_client_grants,
            trusted_direct_lane_revoker_ids: fields.trusted_direct_lane_revoker_ids,
            media_runtime_host_id: fields.media_runtime_host_id,
            media_runtime_lease_scope_id: fields.media_runtime_lease_scope_id,
            direct_lane_runtime_lease_scope_id: fields.direct_lane_runtime_lease_scope_id,
            fresh_setup_policy: None,
            fresh_setup_local_peer_id: None,
            fresh_setup_enrollment_selection: None,
        }
    }
}
