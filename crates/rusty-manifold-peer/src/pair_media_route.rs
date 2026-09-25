//! Pairwise directional media route authority independent of N-peer mesh state.

use std::collections::BTreeSet;

use rusty_manifold_media_session::{
    validate_current_media_session, ManifoldMediaSessionAcceptanceState,
    ManifoldMediaSessionClientGrant, ManifoldMediaSessionLifecycleStatus,
};
use rusty_manifold_model::{
    DottedId, ManifoldMediaRouteLegDescriptor, Revision, SchemaId, MANIFOLD_MEDIA_ROUTE_LEG_SCHEMA,
};
use rusty_manifold_runtime_host::{
    ManifoldRuntimeApplicationReceipt, ManifoldRuntimeCommandRequest,
    ManifoldRuntimeDispatchOutcome, ManifoldRuntimeDispatchReceipt, ManifoldRuntimeLease,
    ManifoldRuntimeTypedParamsDigest, HOST_APPLICATION_RECEIPT_SCHEMA, HOST_COMMAND_REQUEST_SCHEMA,
    HOST_DISPATCH_RECEIPT_SCHEMA, HOST_TYPED_PARAMS_DIGEST_SCHEMA,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    validate_current_peer_session, validate_current_peer_session_v2, ManifoldAcceptedPeerState,
    ManifoldCommonLanTransportBinding, ManifoldPeerEnrollmentState,
    ManifoldPeerSessionAuthorityStateV2, ManifoldPeerSessionState,
    ManifoldReciprocalEd25519AuthorityStateV3, ManifoldRendezvousAuthorityState,
    ManifoldSignedPeerTopologyAuthorization, ManifoldSignedPeerTopologyAuthorizationV2,
    PeerTopologyRole,
};

/// Durable pair media route authority-state schema.
pub const PAIR_MEDIA_ROUTE_STATE_SCHEMA: &str = "rusty.manifold.peer.pair_media_route_state.v1";
/// Active mixed route state schema.
pub const PAIR_MEDIA_ROUTE_STATE_V2_SCHEMA: &str = "rusty.manifold.peer.pair_media_route_state.v2";
/// Active mixed issue request schema.
pub const PAIR_MEDIA_ROUTE_REQUEST_V2_SCHEMA: &str =
    "rusty.manifold.peer.pair_media_route_request.v2";
/// Active mixed record schema.
pub const PAIR_MEDIA_ROUTE_RECORD_V2_SCHEMA: &str =
    "rusty.manifold.peer.pair_media_route_record.v2";
/// Active mixed issue receipt schema.
pub const PAIR_MEDIA_ROUTE_RECEIPT_V2_SCHEMA: &str =
    "rusty.manifold.peer.pair_media_route_receipt.v2";
/// Active mixed current receipt schema.
pub const PAIR_MEDIA_ROUTE_CURRENT_RECEIPT_V2_SCHEMA: &str =
    "rusty.manifold.peer.pair_media_route_current_receipt.v2";
/// Active mixed termination request schema.
pub const PAIR_MEDIA_ROUTE_TERMINATION_REQUEST_V2_SCHEMA: &str =
    "rusty.manifold.peer.pair_media_route_termination_request.v2";
/// Active mixed mutation receipt schema.
pub const PAIR_MEDIA_ROUTE_MUTATION_RECEIPT_V2_SCHEMA: &str =
    "rusty.manifold.peer.pair_media_route_mutation_receipt.v2";
/// Active mixed cleanup request schema.
pub const PAIR_MEDIA_ROUTE_CLEANUP_REQUEST_V2_SCHEMA: &str =
    "rusty.manifold.peer.pair_media_route_cleanup_request.v2";
/// Active mixed cleanup receipt schema.
pub const PAIR_MEDIA_ROUTE_CLEANUP_RECEIPT_V2_SCHEMA: &str =
    "rusty.manifold.peer.pair_media_route_cleanup_receipt.v2";
/// Pair media route issue-request schema.
pub const PAIR_MEDIA_ROUTE_REQUEST_SCHEMA: &str = "rusty.manifold.peer.pair_media_route_request.v1";
/// Accepted pair media route-record schema.
pub const PAIR_MEDIA_ROUTE_RECORD_SCHEMA: &str = "rusty.manifold.peer.pair_media_route_record.v1";
/// Pair media route issue-receipt schema.
pub const PAIR_MEDIA_ROUTE_RECEIPT_SCHEMA: &str = "rusty.manifold.peer.pair_media_route_receipt.v1";
/// Pair media route stop/revoke-request schema.
pub const PAIR_MEDIA_ROUTE_TERMINATION_REQUEST_SCHEMA: &str =
    "rusty.manifold.peer.pair_media_route_termination_request.v1";
/// Pair media route mutation-receipt schema.
pub const PAIR_MEDIA_ROUTE_MUTATION_RECEIPT_SCHEMA: &str =
    "rusty.manifold.peer.pair_media_route_mutation_receipt.v1";
/// Pair media route current-validation receipt schema.
pub const PAIR_MEDIA_ROUTE_CURRENT_RECEIPT_SCHEMA: &str =
    "rusty.manifold.peer.pair_media_route_current_receipt.v1";
/// Pair media route cleanup-completion request schema.
pub const PAIR_MEDIA_ROUTE_CLEANUP_REQUEST_SCHEMA: &str =
    "rusty.manifold.peer.pair_media_route_cleanup_request.v1";
/// Pair media route cleanup receipt schema.
pub const PAIR_MEDIA_ROUTE_CLEANUP_RECEIPT_SCHEMA: &str =
    "rusty.manifold.peer.pair_media_route_cleanup_receipt.v1";
/// Runtime Host command for issuing a pair media route.
pub const PAIR_MEDIA_ROUTE_ISSUE_COMMAND: &str = "rusty.manifold.peer.pair_media_route.issue";
/// Runtime Host command for client-requested route stop.
pub const PAIR_MEDIA_ROUTE_STOP_COMMAND: &str = "rusty.manifold.peer.pair_media_route.stop";
/// Runtime Host command for trusted-operator route revocation.
pub const PAIR_MEDIA_ROUTE_REVOKE_COMMAND: &str = "rusty.manifold.peer.pair_media_route.revoke";
/// Runtime Host command for acknowledging deployment cleanup.
pub const PAIR_MEDIA_ROUTE_CLEANUP_COMMAND: &str =
    "rusty.manifold.peer.pair_media_route.cleanup.complete";
/// Typed-parameter identity for route issue.
pub const PAIR_MEDIA_ROUTE_ISSUE_PARAMS_TYPE: &str =
    "rusty.manifold.peer.pair_media_route_issue_params.v1";
/// Typed-parameter identity for route termination.
pub const PAIR_MEDIA_ROUTE_TERMINATION_PARAMS_TYPE: &str =
    "rusty.manifold.peer.pair_media_route_termination_params.v1";
/// Typed-parameter identity for cleanup completion.
pub const PAIR_MEDIA_ROUTE_CLEANUP_PARAMS_TYPE: &str =
    "rusty.manifold.peer.pair_media_route_cleanup_params.v1";
/// Mixed route termination params type.
pub const PAIR_MEDIA_ROUTE_TERMINATION_PARAMS_V2_TYPE: &str =
    "rusty.manifold.peer.pair_media_route_termination_params.v2";
/// Mixed route issue params type.
pub const PAIR_MEDIA_ROUTE_ISSUE_PARAMS_V2_TYPE: &str =
    "rusty.manifold.peer.pair_media_route_issue_params.v2";
/// Mixed route cleanup params type.
pub const PAIR_MEDIA_ROUTE_CLEANUP_PARAMS_V2_TYPE: &str =
    "rusty.manifold.peer.pair_media_route_cleanup_params.v2";
/// Maximum retained route records, including terminal history.
pub const MAX_PAIR_MEDIA_ROUTE_RECORDS: usize = 4_096;
/// Maximum replay-protected mutation request identities.
pub const MAX_PAIR_MEDIA_ROUTE_REQUEST_IDS: usize = 8_192;
const MAX_PAIR_MEDIA_ROUTE_TTL_MS: u64 = 120_000;
// Common-LAN media has a 110-second rendered-frame run plus a bounded
// reconnect/cleanup window. Wi-Fi Direct keeps its existing route ceiling.
const MAX_COMMON_LAN_PAIR_MEDIA_ROUTE_TTL_MS: u64 = 180_000;

fn route_lifetime_is_bounded(expires_at_ms: u64, now_ms: u64, max_ttl_ms: u64) -> bool {
    expires_at_ms > now_ms && expires_at_ms.saturating_sub(now_ms) <= max_ttl_ms
}

/// Lifecycle of a retained directional route grant.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldPairMediaRouteLifecycleStatus {
    /// The grant is eligible for current-state validation.
    Current,
    /// The requesting media client stopped the grant.
    Stopped,
    /// A trusted media operator revoked the grant.
    Revoked,
    /// An expiry sweep terminalized the grant.
    Expired,
    /// A higher leg revision replaced the grant.
    Superseded,
}

/// Deployment cleanup state for a retained route grant.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldPairMediaRouteCleanupStatus {
    /// The current grant has no cleanup obligation yet.
    NotRequired,
    /// The terminal grant still needs deployment cleanup evidence.
    Pending,
    /// A retained cleanup receipt closed the obligation.
    Completed,
}

/// Compact proof that one pair-route mutation was accepted by Runtime Host.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPairMediaRouteRuntimeMutationBinding {
    /// Exact registered Runtime Host command.
    pub command_id: DottedId,
    /// Exact requester whose lease authorized the command.
    pub requester_id: DottedId,
    /// Exact Runtime Host lease presented by the requester.
    pub lease_id: DottedId,
    /// Lease scope retained when Runtime Host accepted the command.
    pub lease_scope_id: DottedId,
    /// Exact host-owned lease record borrowed when the command was accepted.
    pub runtime_lease: ManifoldRuntimeLease,
    /// Replay-protected Runtime Host command request.
    pub request_id: DottedId,
    /// Exact typed parameters accepted with the command.
    pub params_digest: ManifoldRuntimeTypedParamsDigest,
    /// Runtime Host revision after command application.
    pub resulting_authority_revision: Revision,
}

/// CAS-bound request to issue one directional leg.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPairMediaRouteRequest {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Replay-protected issue identity.
    pub request_id: DottedId,
    /// Expected pair-route authority revision.
    pub expected_authority_revision: Revision,
    /// Expected pair-session acceptance-state revision.
    pub expected_peer_session_authority_revision: Revision,
    /// Expected accepted media authority revision.
    pub expected_media_acceptance_authority_revision: Revision,
    /// Exact Runtime Host command request reviewed for this issue.
    pub runtime_command_request_id: DottedId,
    /// Expected expiry of the host-owned Runtime Host lease.
    pub expected_runtime_lease_expires_at_ms: u64,
    /// Current signed pair-session subject.
    pub peer_session_id: DottedId,
    /// Current accepted media decision subject.
    pub media_session_decision_id: DottedId,
    /// Direction and resource subset requested for the grant.
    pub route_leg: ManifoldMediaRouteLegDescriptor,
    /// Exclusive grant deadline.
    pub expires_at_ms: u64,
}

/// Retained accepted route with exact source-authority bindings.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldAcceptedPairMediaRoute {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Stable grant identity derived from the issue request.
    pub grant_id: DottedId,
    /// Issue request identity.
    pub request_id: DottedId,
    /// Accepted directional route-leg descriptor.
    pub route_leg: ManifoldMediaRouteLegDescriptor,
    /// Signed pair-session identity.
    pub peer_session_id: DottedId,
    /// Exact accepted pair-session decision.
    pub peer_session_decision_id: DottedId,
    /// Exact signed topology retained as issuance provenance.
    pub signed_topology_evidence: ManifoldSignedPeerTopologyAuthorization,
    /// Exact signed pair-session subject revision.
    pub peer_session_authority_revision: Revision,
    /// Pair-session acceptance-state revision used by the issue CAS.
    pub peer_session_acceptance_authority_revision: Revision,
    /// Reciprocal rendezvous receipt used by the signed session.
    pub rendezvous_receipt_id: DottedId,
    /// Exact rendezvous authority revision retained by the signed topology.
    pub rendezvous_authority_revision: Revision,
    /// Exact enrollment authority revision retained by the signed topology.
    pub enrollment_authority_revision: Revision,
    /// Signed topology role of the source peer.
    pub source_topology_role: PeerTopologyRole,
    /// Signed topology role of the sink peer.
    pub sink_topology_role: PeerTopologyRole,
    /// Exact accepted media decision.
    pub media_session_decision_id: DottedId,
    /// Media-session subject.
    pub media_session_id: DottedId,
    /// Media descriptor subject revision.
    pub media_session_authority_revision: Revision,
    /// Accepted media-state revision at issue time.
    pub media_acceptance_authority_revision: Revision,
    /// Exact accepted media descriptor digest.
    pub media_descriptor_canonical_sha256: String,
    /// Accepted platform runtime specification.
    pub platform_runtime_spec_id: DottedId,
    /// Actual Manifold command authority host; not a downstream effect provider.
    pub authority_host_id: DottedId,
    /// Host-owned authority provider epoch; not transport execution evidence.
    pub authority_provider_epoch_id: DottedId,
    /// Media requester/client identity; distinct from the authority host.
    pub authority_client_id: DottedId,
    /// Runtime Host lease held by the media client.
    pub authority_runtime_lease_id: DottedId,
    /// Exact lease expiry that capped this grant at issue time.
    pub authority_runtime_lease_expires_at_ms: u64,
    /// Accepted Runtime Host command request identity.
    pub runtime_command_request_id: DottedId,
    /// Exact registered Runtime Host issue command.
    pub runtime_command_id: DottedId,
    /// Typed digest of the issue request.
    pub runtime_params_digest: ManifoldRuntimeTypedParamsDigest,
    /// Accepted Runtime Host dispatch identity.
    pub runtime_dispatch_id: DottedId,
    /// Applied Runtime Host application receipt identity.
    pub runtime_application_receipt_id: DottedId,
    /// Runtime Host revision after issue command application.
    pub runtime_resulting_authority_revision: Revision,
    /// Product bound by the accepted media decision.
    pub product_id: DottedId,
    /// Feature lock bound by the accepted media decision.
    pub feature_lock_id: DottedId,
    /// Exact feature-lock fingerprint.
    pub feature_lock_fingerprint: String,
    /// Media client-grant capability.
    pub capability_id: DottedId,
    /// Media admission grant.
    pub admission_grant_id: DottedId,
    /// Current or terminal route lifecycle.
    pub lifecycle_status: ManifoldPairMediaRouteLifecycleStatus,
    /// Deployment cleanup lifecycle.
    pub cleanup_status: ManifoldPairMediaRouteCleanupStatus,
    /// Acceptance time.
    pub valid_from_ms: u64,
    /// Exclusive route deadline.
    pub expires_at_ms: u64,
    /// Terminalization time, if terminal.
    pub ended_at_ms: Option<u64>,
    /// Mutation that terminalized the route, if terminal.
    pub ended_by_id: Option<DottedId>,
    /// Exact stop or revoke action, when explicitly terminalized.
    pub termination_action: Option<ManifoldPairMediaRouteTerminationAction>,
    /// Runtime Host proof for an explicit stop or revoke.
    pub termination_runtime_binding: Option<ManifoldPairMediaRouteRuntimeMutationBinding>,
    /// Retained cleanup receipt, when completed.
    pub cleanup_receipt_id: Option<DottedId>,
}

/// Bounded durable pair-route authority state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPairMediaRouteState {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Monotonic route authority revision.
    pub authority_revision: Revision,
    /// Last accepted authority clock value.
    pub last_observed_at_ms: Option<u64>,
    /// Current and terminal route records.
    pub routes: Vec<ManifoldAcceptedPairMediaRoute>,
    /// Strict replay guard for all mutations.
    pub applied_request_ids: Vec<DottedId>,
    /// Terminal cleanup receipts.
    pub cleanup_receipts: Vec<ManifoldPairMediaRouteCleanupReceipt>,
}

/// Accepted common-LAN route retaining exact authority and cleanup bindings.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldAcceptedCommonLanPairMediaRoute {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Stable grant.
    pub grant_id: DottedId,
    /// Issue request.
    pub request_id: DottedId,
    /// Directional resource subset.
    pub route_leg: ManifoldMediaRouteLegDescriptor,
    /// Current pair session.
    pub peer_session_id: DottedId,
    /// Session decision.
    pub peer_session_decision_id: DottedId,
    /// Exact signed carrier configuration.
    pub transport: ManifoldCommonLanTransportBinding,
    /// Exact signed topology retained as issuance provenance.
    pub signed_topology_evidence: crate::ManifoldCommonLanSignedPeerTopologyAuthorization,
    /// Session revision.
    pub peer_session_authority_revision: Revision,
    /// Pair-session acceptance-state revision used by the issue CAS.
    pub peer_session_acceptance_authority_revision: Revision,
    /// Reciprocal receipt retained by the signed topology.
    pub reciprocal_receipt_id: DottedId,
    /// Reciprocal authority revision retained by the signed topology.
    pub reciprocal_authority_revision: Revision,
    /// Enrollment authority revision retained by the signed topology.
    pub enrollment_authority_revision: Revision,
    /// Accepted media decision.
    pub media_session_decision_id: DottedId,
    /// Media session.
    pub media_session_id: DottedId,
    /// Media subject revision.
    pub media_session_authority_revision: Revision,
    /// Accepted media revision.
    pub media_acceptance_authority_revision: Revision,
    /// Accepted media descriptor digest.
    pub media_descriptor_canonical_sha256: String,
    /// Exact platform runtime specification.
    pub platform_runtime_spec_id: DottedId,
    /// Authority host.
    pub authority_host_id: DottedId,
    /// Provider epoch.
    pub authority_provider_epoch_id: DottedId,
    /// Original client.
    pub authority_client_id: DottedId,
    /// Original command lease.
    pub authority_runtime_lease_id: DottedId,
    /// Original lease expiry.
    pub authority_runtime_lease_expires_at_ms: u64,
    /// Accepted Runtime Host command request identity.
    pub runtime_command_request_id: DottedId,
    /// Exact registered Runtime Host issue command.
    pub runtime_command_id: DottedId,
    /// Typed digest of the issue request.
    pub runtime_params_digest: ManifoldRuntimeTypedParamsDigest,
    /// Accepted Runtime Host dispatch identity.
    pub runtime_dispatch_id: DottedId,
    /// Applied Runtime Host application receipt identity.
    pub runtime_application_receipt_id: DottedId,
    /// Runtime Host revision after issue command application.
    pub runtime_resulting_authority_revision: Revision,
    /// Product.
    pub product_id: DottedId,
    /// Feature lock.
    pub feature_lock_id: DottedId,
    /// Feature-lock fingerprint.
    pub feature_lock_fingerprint: String,
    /// Capability.
    pub capability_id: DottedId,
    /// Admission grant.
    pub admission_grant_id: DottedId,
    /// Lifecycle.
    pub lifecycle_status: ManifoldPairMediaRouteLifecycleStatus,
    /// Cleanup lifecycle.
    pub cleanup_status: ManifoldPairMediaRouteCleanupStatus,
    /// Start time.
    pub valid_from_ms: u64,
    /// Expiry.
    pub expires_at_ms: u64,
    /// Terminal time.
    pub ended_at_ms: Option<u64>,
    /// Terminal mutation.
    pub ended_by_id: Option<DottedId>,
    /// Explicit terminal action.
    pub termination_action: Option<ManifoldPairMediaRouteTerminationAction>,
    /// Runtime proof for explicit termination.
    pub termination_runtime_binding: Option<ManifoldPairMediaRouteRuntimeMutationBinding>,
    /// Cleanup receipt.
    pub cleanup_receipt_id: Option<DottedId>,
}

/// Closed active route payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "topology_kind",
    content = "record",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ManifoldAcceptedPairMediaRouteV2 {
    /// Exact legacy Wi-Fi route.
    WifiDirect(ManifoldAcceptedPairMediaRoute),
    /// Common-LAN route.
    CommonLan(ManifoldAcceptedCommonLanPairMediaRoute),
}

macro_rules! route_v2_ref {
    ($self:expr, $field:ident) => {
        match $self {
            ManifoldAcceptedPairMediaRouteV2::WifiDirect(value) => &value.$field,
            ManifoldAcceptedPairMediaRouteV2::CommonLan(value) => &value.$field,
        }
    };
}

impl ManifoldAcceptedPairMediaRouteV2 {
    /// Issue request identity.
    #[must_use]
    pub fn request_id(&self) -> &DottedId {
        route_v2_ref!(self, request_id)
    }
    /// Grant identity.
    #[must_use]
    pub fn grant_id(&self) -> &DottedId {
        route_v2_ref!(self, grant_id)
    }
    /// Directional resource leg.
    #[must_use]
    pub fn route_leg(&self) -> &ManifoldMediaRouteLegDescriptor {
        route_v2_ref!(self, route_leg)
    }
    /// Lifecycle status.
    #[must_use]
    pub fn lifecycle_status(&self) -> &ManifoldPairMediaRouteLifecycleStatus {
        route_v2_ref!(self, lifecycle_status)
    }
    /// Cleanup status.
    #[must_use]
    pub fn cleanup_status(&self) -> &ManifoldPairMediaRouteCleanupStatus {
        route_v2_ref!(self, cleanup_status)
    }
    /// Provider epoch retained at issue.
    #[must_use]
    pub fn authority_provider_epoch_id(&self) -> &DottedId {
        route_v2_ref!(self, authority_provider_epoch_id)
    }
    /// Platform runtime retained at issue.
    #[must_use]
    pub fn platform_runtime_spec_id(&self) -> &DottedId {
        route_v2_ref!(self, platform_runtime_spec_id)
    }
    /// Original route client.
    #[must_use]
    pub fn authority_client_id(&self) -> &DottedId {
        route_v2_ref!(self, authority_client_id)
    }
    /// Original command lease.
    #[must_use]
    pub fn authority_runtime_lease_id(&self) -> &DottedId {
        route_v2_ref!(self, authority_runtime_lease_id)
    }
    /// Peer session subject.
    #[must_use]
    pub fn peer_session_id(&self) -> &DottedId {
        route_v2_ref!(self, peer_session_id)
    }
    /// Accepted media decision.
    #[must_use]
    pub fn media_session_decision_id(&self) -> &DottedId {
        route_v2_ref!(self, media_session_decision_id)
    }
    /// Authority host.
    #[must_use]
    pub fn authority_host_id(&self) -> &DottedId {
        route_v2_ref!(self, authority_host_id)
    }
    /// Expiry.
    #[must_use]
    pub fn expires_at_ms(&self) -> u64 {
        *route_v2_ref!(self, expires_at_ms)
    }
    /// Terminal mutation identity.
    #[must_use]
    pub fn ended_by_id(&self) -> Option<&DottedId> {
        route_v2_ref!(self, ended_by_id).as_ref()
    }
    /// Terminal time.
    #[must_use]
    pub fn ended_at_ms(&self) -> Option<u64> {
        *route_v2_ref!(self, ended_at_ms)
    }
    /// Explicit terminal action.
    #[must_use]
    pub fn termination_action(&self) -> Option<&ManifoldPairMediaRouteTerminationAction> {
        route_v2_ref!(self, termination_action).as_ref()
    }
    /// Explicit terminal Runtime Host proof.
    #[must_use]
    pub fn termination_runtime_binding(
        &self,
    ) -> Option<&ManifoldPairMediaRouteRuntimeMutationBinding> {
        route_v2_ref!(self, termination_runtime_binding).as_ref()
    }
}

/// Closed active cleanup receipt payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "topology_kind",
    content = "record",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ManifoldPairMediaRouteCleanupReceiptV2 {
    /// Exact legacy Wi-Fi cleanup receipt.
    WifiDirect(ManifoldPairMediaRouteCleanupReceipt),
    /// Common-LAN cleanup receipt with the same opaque effect evidence.
    CommonLan(ManifoldPairMediaRouteCleanupReceipt),
}

impl ManifoldPairMediaRouteCleanupReceiptV2 {
    /// Cleanup request identity.
    #[must_use]
    pub fn request_id(&self) -> &DottedId {
        match self {
            Self::WifiDirect(v) | Self::CommonLan(v) => &v.request_id,
        }
    }
    /// Cleaned grant identity.
    #[must_use]
    pub fn grant_id(&self) -> &DottedId {
        match self {
            Self::WifiDirect(v) | Self::CommonLan(v) => &v.grant_id,
        }
    }
    /// Runtime binding retained by cleanup.
    #[must_use]
    pub fn runtime_binding(&self) -> &ManifoldPairMediaRouteRuntimeMutationBinding {
        match self {
            Self::WifiDirect(v) | Self::CommonLan(v) => &v.runtime_binding,
        }
    }
    /// Opaque effect receipt identity.
    #[must_use]
    pub fn effect_receipt_id(&self) -> &DottedId {
        match self {
            Self::WifiDirect(v) | Self::CommonLan(v) => &v.effect_receipt_id,
        }
    }
    /// Opaque effect receipt digest.
    #[must_use]
    pub fn effect_receipt_sha256(&self) -> &str {
        match self {
            Self::WifiDirect(v) | Self::CommonLan(v) => &v.effect_receipt_sha256,
        }
    }
    /// Completion time.
    #[must_use]
    pub fn completed_at_ms(&self) -> u64 {
        match self {
            Self::WifiDirect(v) | Self::CommonLan(v) => v.completed_at_ms,
        }
    }
}

/// Active mixed route authority state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPairMediaRouteAuthorityStateV2 {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Shared authority revision.
    pub authority_revision: Revision,
    /// Shared monotonic clock.
    pub last_observed_at_ms: Option<u64>,
    /// Mixed route records.
    pub routes: Vec<ManifoldAcceptedPairMediaRouteV2>,
    /// Shared replay guard.
    pub applied_request_ids: Vec<DottedId>,
    /// Mixed cleanup receipts.
    pub cleanup_receipts: Vec<ManifoldPairMediaRouteCleanupReceiptV2>,
}

/// Common-LAN route issue parameters.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldCommonLanPairMediaRouteRequest {
    /// Existing topology-neutral issue fields.
    pub request: ManifoldPairMediaRouteRequest,
    /// Exact signed transport match.
    pub transport: ManifoldCommonLanTransportBinding,
}

/// Closed mixed route issue request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "topology_kind",
    content = "record",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ManifoldPairMediaRouteRequestV2 {
    /// Existing Wi-Fi issue request.
    WifiDirect(ManifoldPairMediaRouteRequest),
    /// Common-LAN issue request.
    CommonLan(ManifoldCommonLanPairMediaRouteRequest),
}

/// Common-LAN issue receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldCommonLanPairMediaRouteReceipt {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Request identity.
    pub request_id: DottedId,
    /// Rejection reason.
    pub rejection_reason: Option<ManifoldPairMediaRouteRejectionReason>,
    /// Accepted record.
    pub route: Option<ManifoldAcceptedCommonLanPairMediaRoute>,
    /// Prior revision.
    pub prior_authority_revision: Revision,
    /// Resulting revision.
    pub resulting_authority_revision: Revision,
}

/// Closed mixed issue receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "topology_kind",
    content = "record",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ManifoldPairMediaRouteReceiptV2 {
    /// Existing Wi-Fi receipt.
    WifiDirect(ManifoldPairMediaRouteReceipt),
    /// Common-LAN receipt.
    CommonLan(ManifoldCommonLanPairMediaRouteReceipt),
}

/// Current mixed authority dependencies.
#[derive(Clone, Copy, Debug)]
pub struct ManifoldPairMediaRouteAuthorityContextV2<'a> {
    /// Accepted peers.
    pub accepted_peers: &'a ManifoldAcceptedPeerState,
    /// Current enrollment.
    pub enrollment: &'a ManifoldPeerEnrollmentState,
    /// Existing Wi-Fi compatibility rendezvous authority.
    pub rendezvous: &'a ManifoldRendezvousAuthorityState,
    /// Current mixed reciprocal authority.
    pub reciprocal: &'a ManifoldReciprocalEd25519AuthorityStateV3,
    /// Current mixed sessions.
    pub peer_sessions: &'a ManifoldPeerSessionAuthorityStateV2,
    /// Retained mixed topologies.
    pub signed_topologies: &'a [ManifoldSignedPeerTopologyAuthorizationV2],
    /// Accepted media decisions.
    pub media_sessions: &'a ManifoldMediaSessionAcceptanceState,
}

/// Mixed current route receipt used by feature activation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPairMediaRouteCurrentReceiptV2 {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Reviewed grant.
    pub grant_id: DottedId,
    /// Current result.
    pub current: bool,
    /// Rejection reason.
    pub rejection_reason: Option<ManifoldPairMediaRouteRejectionReason>,
    /// Retained route.
    pub route: Option<ManifoldAcceptedPairMediaRouteV2>,
    /// Validation time.
    pub validated_at_ms: u64,
}

impl ManifoldPairMediaRouteAuthorityStateV2 {
    /// Empty active route authority.
    #[must_use]
    pub fn empty() -> Self {
        migrate_pair_media_route_state_v1_to_v2(ManifoldPairMediaRouteState::empty())
    }
}

/// Lossless migration of a legacy Wi-Fi route state.
#[must_use]
pub fn migrate_pair_media_route_state_v1_to_v2(
    legacy: ManifoldPairMediaRouteState,
) -> ManifoldPairMediaRouteAuthorityStateV2 {
    ManifoldPairMediaRouteAuthorityStateV2 {
        schema_id: schema(PAIR_MEDIA_ROUTE_STATE_V2_SCHEMA),
        authority_revision: legacy.authority_revision,
        last_observed_at_ms: legacy.last_observed_at_ms,
        routes: legacy
            .routes
            .into_iter()
            .map(ManifoldAcceptedPairMediaRouteV2::WifiDirect)
            .collect(),
        applied_request_ids: legacy.applied_request_ids,
        cleanup_receipts: legacy
            .cleanup_receipts
            .into_iter()
            .map(ManifoldPairMediaRouteCleanupReceiptV2::WifiDirect)
            .collect(),
    }
}

/// Structural validation for the mixed route container.
#[must_use]
pub fn pair_media_route_state_v2_is_well_formed(
    state: &ManifoldPairMediaRouteAuthorityStateV2,
) -> bool {
    let Some(reserved_mutations) = pair_media_route_reserved_mutations_v2(state) else {
        return false;
    };
    let request_ids = state.applied_request_ids.iter().collect::<BTreeSet<_>>();
    let grant_ids = state
        .routes
        .iter()
        .map(|route| match route {
            ManifoldAcceptedPairMediaRouteV2::WifiDirect(value) => &value.grant_id,
            ManifoldAcceptedPairMediaRouteV2::CommonLan(value) => &value.grant_id,
        })
        .collect::<BTreeSet<_>>();
    let receipt_ids = state
        .cleanup_receipts
        .iter()
        .map(|receipt| match receipt {
            ManifoldPairMediaRouteCleanupReceiptV2::WifiDirect(v)
            | ManifoldPairMediaRouteCleanupReceiptV2::CommonLan(v) => &v.receipt_id,
        })
        .collect::<BTreeSet<_>>();
    let records_are_closed = state.routes.iter().all(|route| {
        state.applied_request_ids.contains(route.request_id())
            && route
                .ended_by_id()
                .map_or(true, |id| state.applied_request_ids.contains(id))
            && state.last_observed_at_ms.is_some_and(|last| {
                (match route {
                    ManifoldAcceptedPairMediaRouteV2::WifiDirect(v) => v.valid_from_ms <= last,
                    ManifoldAcceptedPairMediaRouteV2::CommonLan(v) => v.valid_from_ms <= last,
                }) && route.ended_at_ms().map_or(true, |ended| ended <= last)
            })
            && match route {
                ManifoldAcceptedPairMediaRouteV2::WifiDirect(v) => valid_wifi_route_record_v2(v),
                ManifoldAcceptedPairMediaRouteV2::CommonLan(v) => valid_common_lan_route_record(v),
            }
            && match route {
                ManifoldAcceptedPairMediaRouteV2::WifiDirect(v) => &v.cleanup_receipt_id,
                ManifoldAcceptedPairMediaRouteV2::CommonLan(v) => &v.cleanup_receipt_id,
            }
            .as_ref()
            .map_or(true, |receipt_id| {
                state.cleanup_receipts.iter().any(|tagged| {
                    let receipt = match tagged {
                        ManifoldPairMediaRouteCleanupReceiptV2::WifiDirect(v)
                        | ManifoldPairMediaRouteCleanupReceiptV2::CommonLan(v) => v,
                    };
                    &receipt.receipt_id == receipt_id
                        && &receipt.grant_id == route.grant_id()
                        && receipt.completed_at_ms >= route.ended_at_ms().unwrap_or(0)
                })
            })
    });
    let cleanup_is_closed = state.cleanup_receipts.iter().all(|tagged| {
        let receipt = match tagged {
            ManifoldPairMediaRouteCleanupReceiptV2::WifiDirect(v)
            | ManifoldPairMediaRouteCleanupReceiptV2::CommonLan(v) => v,
        };
        let identity_valid = match tagged {
            ManifoldPairMediaRouteCleanupReceiptV2::WifiDirect(_) => {
                (receipt.schema_id.as_str() == PAIR_MEDIA_ROUTE_CLEANUP_RECEIPT_SCHEMA
                    && receipt.receipt_id
                        == derived("receipt.peer.pair-media-route-cleanup", &receipt.request_id)
                    && valid_runtime_binding(
                        &receipt.runtime_binding,
                        PAIR_MEDIA_ROUTE_CLEANUP_COMMAND,
                        PAIR_MEDIA_ROUTE_CLEANUP_PARAMS_TYPE,
                    ))
                    || (receipt.schema_id.as_str() == PAIR_MEDIA_ROUTE_CLEANUP_RECEIPT_V2_SCHEMA
                        && receipt.receipt_id
                            == derived(
                                "receipt.peer.pair-media-route-cleanup-v2",
                                &receipt.request_id,
                            )
                        && valid_runtime_binding(
                            &receipt.runtime_binding,
                            PAIR_MEDIA_ROUTE_CLEANUP_COMMAND,
                            PAIR_MEDIA_ROUTE_CLEANUP_PARAMS_V2_TYPE,
                        ))
            }
            ManifoldPairMediaRouteCleanupReceiptV2::CommonLan(_) => {
                receipt.schema_id.as_str() == PAIR_MEDIA_ROUTE_CLEANUP_RECEIPT_V2_SCHEMA
                    && receipt.receipt_id
                        == derived(
                            "receipt.peer.pair-media-route-cleanup-v2",
                            &receipt.request_id,
                        )
                    && valid_runtime_binding(
                        &receipt.runtime_binding,
                        PAIR_MEDIA_ROUTE_CLEANUP_COMMAND,
                        PAIR_MEDIA_ROUTE_CLEANUP_PARAMS_V2_TYPE,
                    )
            }
        };
        identity_valid
            && valid_sha256(&receipt.effect_receipt_sha256)
            && state.applied_request_ids.contains(&receipt.request_id)
            && state
                .last_observed_at_ms
                .is_some_and(|last| receipt.completed_at_ms <= last)
            && state.routes.iter().any(|route| {
                route.grant_id() == &receipt.grant_id
                    && *route.cleanup_status() == ManifoldPairMediaRouteCleanupStatus::Completed
            })
    });
    state.schema_id.as_str() == PAIR_MEDIA_ROUTE_STATE_V2_SCHEMA
        && request_ids.len() == state.applied_request_ids.len()
        && grant_ids.len() == state.routes.len()
        && receipt_ids.len() == state.cleanup_receipts.len()
        && state.routes.len() <= MAX_PAIR_MEDIA_ROUTE_RECORDS
        && state.cleanup_receipts.len() <= MAX_PAIR_MEDIA_ROUTE_RECORDS
        && state.applied_request_ids.len() <= MAX_PAIR_MEDIA_ROUTE_REQUEST_IDS
        && records_are_closed
        && cleanup_is_closed
        && state.routes.iter().enumerate().all(|(index, route)| {
            *route.lifecycle_status() != ManifoldPairMediaRouteLifecycleStatus::Current
                || !state.routes[index + 1..].iter().any(|candidate| {
                    *candidate.lifecycle_status() == ManifoldPairMediaRouteLifecycleStatus::Current
                        && candidate.route_leg().leg_id == route.route_leg().leg_id
                })
        })
        && (state.applied_request_ids.is_empty() == state.last_observed_at_ms.is_none())
        && state
            .applied_request_ids
            .len()
            .checked_add(reserved_mutations)
            .is_some_and(|needed| needed <= MAX_PAIR_MEDIA_ROUTE_REQUEST_IDS)
        && u64::try_from(reserved_mutations).is_ok_and(|reserved| {
            state
                .authority_revision
                .get()
                .checked_add(reserved)
                .is_some()
        })
}

impl ManifoldPairMediaRouteState {
    /// Returns the initial empty route authority state.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            schema_id: schema(PAIR_MEDIA_ROUTE_STATE_SCHEMA),
            authority_revision: Revision::INITIAL,
            last_observed_at_ms: None,
            routes: Vec::new(),
            applied_request_ids: Vec::new(),
            cleanup_receipts: Vec::new(),
        }
    }
}

/// Borrowed host-owned Runtime Host evidence for one route mutation.
#[derive(Clone, Copy, Debug)]
pub struct ManifoldPairMediaRouteRuntimeContext<'a> {
    /// Manifold Runtime Host authority identity.
    pub authority_host_id: &'a DottedId,
    /// Current host-owned provider epoch.
    pub live_authority_provider_epoch_id: &'a DottedId,
    /// Immutable accepted media client grants.
    pub media_client_grants: &'a [ManifoldMediaSessionClientGrant],
    /// Trusted media revocation operators.
    pub trusted_media_revoker_ids: &'a [DottedId],
    /// Exact Runtime Host command request.
    pub command_request: &'a ManifoldRuntimeCommandRequest,
    /// Current host-owned lease resolved for the command requester.
    pub runtime_lease: Option<&'a ManifoldRuntimeLease>,
    /// Exact media-command lease scope configured by the owning host.
    pub required_runtime_lease_scope_id: &'a DottedId,
    /// Exact accepted dispatch.
    pub dispatch: &'a ManifoldRuntimeDispatchReceipt,
    /// Exact applied command receipt.
    pub application: &'a ManifoldRuntimeApplicationReceipt,
}

/// Borrowed current peer and accepted-media authority context.
#[derive(Clone, Copy, Debug)]
pub struct ManifoldPairMediaRouteAuthorityContext<'a> {
    /// Current accepted peer status.
    pub accepted_peers: &'a ManifoldAcceptedPeerState,
    /// Current credential enrollment.
    pub enrollment: &'a ManifoldPeerEnrollmentState,
    /// Current reciprocal rendezvous receipts.
    pub rendezvous: &'a ManifoldRendezvousAuthorityState,
    /// Current signed pair sessions.
    pub peer_sessions: &'a ManifoldPeerSessionState,
    /// Host-retained signed topology authorizations.
    pub signed_topologies: &'a [ManifoldSignedPeerTopologyAuthorization],
    /// Current accepted media decisions.
    pub media_sessions: &'a ManifoldMediaSessionAcceptanceState,
}

/// Closed route review and mutation rejection classes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldPairMediaRouteRejectionReason {
    /// A request or retained record uses an unsupported schema.
    SchemaMismatch,
    /// Retained route authority state is internally inconsistent.
    InvalidAuthorityState,
    /// A caller supplied a stale expected authority revision.
    StaleAuthorityRevision,
    /// The mutation identity was already consumed.
    ReplayedRequest,
    /// Authority time moved backwards.
    ClockRegression,
    /// A bounded retained collection reached its limit.
    CapacityExceeded,
    /// The referenced signed pair session is not current.
    PeerSessionNotCurrent,
    /// The referenced accepted media decision is not current.
    MediaSessionNotCurrent,
    /// Source/sink peers do not match the signed topology.
    DirectionMismatch,
    /// Route resources exceed the accepted media descriptor.
    ResourceMismatch,
    /// The leg revision does not advance the subject.
    StaleLegRevision,
    /// Runtime Host command evidence was not accepted and applied.
    RuntimeCommandNotAccepted,
    /// The client or operator lacks the required immutable grant.
    ClientNotAuthorized,
    /// The requested deadline is empty or outside source authority.
    InvalidExpiry,
    /// The route is absent or terminal.
    RouteNotCurrent,
    /// The route has no pending cleanup obligation.
    CleanupNotPending,
    /// Deployment cleanup evidence is malformed.
    CleanupEvidenceInvalid,
    /// The authority revision cannot advance.
    RevisionExhausted,
}

/// Result of reviewing one route issue request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPairMediaRouteReceipt {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Reviewed request identity.
    pub request_id: DottedId,
    /// Whether a route grant was retained.
    pub accepted: bool,
    /// Closed rejection reason when not accepted.
    pub rejection_reason: Option<ManifoldPairMediaRouteRejectionReason>,
    /// Exact accepted route when accepted.
    pub accepted_route: Option<ManifoldAcceptedPairMediaRoute>,
    /// Authority revision before review.
    pub prior_authority_revision: Revision,
    /// Authority revision after review.
    pub resulting_authority_revision: Revision,
}

/// Requested route terminalization action.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldPairMediaRouteTerminationAction {
    /// Client-requested graceful stop.
    Stop,
    /// Trusted-operator administrative revocation.
    Revoke,
}

/// CAS-bound request to stop or revoke a route.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPairMediaRouteTerminationRequest {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Replay-protected mutation identity.
    pub request_id: DottedId,
    /// Expected route authority revision.
    pub expected_authority_revision: Revision,
    /// Exact Runtime Host command request identity.
    pub runtime_command_request_id: DottedId,
    /// Route grant to terminalize.
    pub grant_id: DottedId,
    /// Stop or administrative revoke.
    pub action: ManifoldPairMediaRouteTerminationAction,
}

/// Mixed route termination request with exact retained target binding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPairMediaRouteTerminationRequestV2 {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Replay-protected mutation.
    pub request_id: DottedId,
    /// Expected shared revision.
    pub expected_authority_revision: Revision,
    /// Runtime command request.
    pub runtime_command_request_id: DottedId,
    /// Route grant.
    pub grant_id: DottedId,
    /// Exact retained provider epoch.
    pub expected_authority_provider_epoch_id: DottedId,
    /// Exact retained platform runtime.
    pub expected_platform_runtime_spec_id: DottedId,
    /// Stop or revoke.
    pub action: ManifoldPairMediaRouteTerminationAction,
}

/// Receipt for stop, revoke, or expiry mutation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPairMediaRouteMutationReceipt {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Request or sweep identity.
    pub source_id: DottedId,
    /// Whether authority state changed.
    pub applied: bool,
    /// Closed rejection reason when not applied.
    pub rejection_reason: Option<ManifoldPairMediaRouteRejectionReason>,
    /// Canonical affected grant identities.
    pub affected_grant_ids: Vec<DottedId>,
    /// Authority revision before mutation.
    pub prior_authority_revision: Revision,
    /// Authority revision after mutation.
    pub resulting_authority_revision: Revision,
}

/// Current-state validation receipt for one route grant.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPairMediaRouteCurrentReceipt {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Reviewed grant identity.
    pub grant_id: DottedId,
    /// Whether every retained source authority remains current.
    pub current: bool,
    /// Closed rejection reason when not current.
    pub rejection_reason: Option<ManifoldPairMediaRouteRejectionReason>,
    /// Retained route, if found.
    pub route: Option<ManifoldAcceptedPairMediaRoute>,
    /// Authority time used for validation.
    pub validated_at_ms: u64,
}

/// Request to acknowledge deployment-owned cleanup evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPairMediaRouteCleanupCompletionRequest {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Replay-protected cleanup identity.
    pub request_id: DottedId,
    /// Expected route authority revision.
    pub expected_authority_revision: Revision,
    /// Exact Runtime Host command request identity.
    pub runtime_command_request_id: DottedId,
    /// Terminal grant whose cleanup completed.
    pub grant_id: DottedId,
    /// Deployment-owned effect receipt identity.
    pub effect_receipt_id: DottedId,
    /// SHA-256 of deployment-verified effect evidence.
    pub effect_receipt_sha256: String,
}

/// Mixed cleanup completion with exact retained target binding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPairMediaRouteCleanupCompletionRequestV2 {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Replay-protected cleanup.
    pub request_id: DottedId,
    /// Expected shared revision.
    pub expected_authority_revision: Revision,
    /// Runtime command request.
    pub runtime_command_request_id: DottedId,
    /// Target grant.
    pub grant_id: DottedId,
    /// Exact retained provider epoch.
    pub expected_authority_provider_epoch_id: DottedId,
    /// Exact retained platform runtime.
    pub expected_platform_runtime_spec_id: DottedId,
    /// Effect receipt identity.
    pub effect_receipt_id: DottedId,
    /// Effect receipt digest.
    pub effect_receipt_sha256: String,
}

/// Retained acknowledgement of opaque deployment cleanup evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPairMediaRouteCleanupReceipt {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Derived cleanup receipt identity.
    pub receipt_id: DottedId,
    /// Cleanup request identity.
    pub request_id: DottedId,
    /// Terminal route grant.
    pub grant_id: DottedId,
    /// Deployment-owned effect receipt identity.
    pub effect_receipt_id: DottedId,
    /// SHA-256 of deployment-verified effect evidence.
    pub effect_receipt_sha256: String,
    /// Manifold authority host acknowledging cleanup.
    pub authority_host_id: DottedId,
    /// Host-owned provider epoch acknowledging cleanup.
    pub authority_provider_epoch_id: DottedId,
    /// Runtime Host proof for this cleanup acknowledgement.
    pub runtime_binding: ManifoldPairMediaRouteRuntimeMutationBinding,
    /// Authority time of acknowledgement.
    pub completed_at_ms: u64,
}

/// Reviews and applies one pair route issue using borrowed current authority.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn review_and_apply_pair_media_route_v2(
    state: &ManifoldPairMediaRouteAuthorityStateV2,
    request: &ManifoldPairMediaRouteRequestV2,
    runtime: ManifoldPairMediaRouteRuntimeContext<'_>,
    authority: ManifoldPairMediaRouteAuthorityContextV2<'_>,
    now_ms: u64,
) -> (
    ManifoldPairMediaRouteAuthorityStateV2,
    ManifoldPairMediaRouteReceiptV2,
) {
    match request {
        ManifoldPairMediaRouteRequestV2::WifiDirect(request) => {
            let preflight_rejection = if !pair_media_route_state_v2_is_well_formed(state) {
                Some(ManifoldPairMediaRouteRejectionReason::InvalidAuthorityState)
            } else if state.routes.len() >= MAX_PAIR_MEDIA_ROUTE_RECORDS
                || !issue_preserves_terminal_capacity_v2(state, &request.route_leg.leg_id)
            {
                Some(ManifoldPairMediaRouteRejectionReason::CapacityExceeded)
            } else if !issue_preserves_revision_capacity_v2(state, &request.route_leg.leg_id) {
                Some(ManifoldPairMediaRouteRejectionReason::RevisionExhausted)
            } else if state.routes.iter().any(|route| {
                matches!(route, ManifoldAcceptedPairMediaRouteV2::CommonLan(value)
                    if value.route_leg.leg_id == request.route_leg.leg_id
                        && (value.route_leg.source_peer_id != request.route_leg.source_peer_id
                            || value.route_leg.sink_peer_id != request.route_leg.sink_peer_id
                            || value.authority_client_id != runtime.command_request.requester_id))
            }) {
                Some(ManifoldPairMediaRouteRejectionReason::DirectionMismatch)
            } else if state.routes.iter().any(|route| {
                matches!(route, ManifoldAcceptedPairMediaRouteV2::CommonLan(value)
                    if value.route_leg.leg_id == request.route_leg.leg_id
                        && value.route_leg.leg_revision >= request.route_leg.leg_revision)
            }) {
                Some(ManifoldPairMediaRouteRejectionReason::StaleLegRevision)
            } else {
                None
            };
            if let Some(reason) = preflight_rejection {
                let receipt = route_receipt(
                    request,
                    Some(reason),
                    None,
                    state.authority_revision,
                    state.authority_revision,
                );
                return (
                    state.clone(),
                    ManifoldPairMediaRouteReceiptV2::WifiDirect(receipt),
                );
            }
            let legacy = ManifoldPairMediaRouteState {
                schema_id: schema(PAIR_MEDIA_ROUTE_STATE_SCHEMA),
                authority_revision: state.authority_revision,
                last_observed_at_ms: state.last_observed_at_ms,
                routes: state
                    .routes
                    .iter()
                    .filter_map(|v| match v {
                        ManifoldAcceptedPairMediaRouteV2::WifiDirect(v) => Some(v.clone()),
                        _ => None,
                    })
                    .collect(),
                applied_request_ids: state.applied_request_ids.clone(),
                cleanup_receipts: state
                    .cleanup_receipts
                    .iter()
                    .filter_map(|v| match v {
                        ManifoldPairMediaRouteCleanupReceiptV2::WifiDirect(v) => Some(v.clone()),
                        _ => None,
                    })
                    .collect(),
            };
            let wifi_sessions = crate::wifi_direct_peer_session_projection(authority.peer_sessions);
            let wifi_topologies = authority
                .signed_topologies
                .iter()
                .filter_map(|v| v.as_wifi_direct().cloned())
                .collect::<Vec<_>>();
            let legacy_authority = ManifoldPairMediaRouteAuthorityContext {
                accepted_peers: authority.accepted_peers,
                enrollment: authority.enrollment,
                rendezvous: authority.rendezvous,
                peer_sessions: &wifi_sessions,
                signed_topologies: &wifi_topologies,
                media_sessions: authority.media_sessions,
            };
            let (next_legacy, receipt) = review_and_apply_pair_media_route(
                &legacy,
                legacy_authority,
                request,
                runtime,
                now_ms,
            );
            if !receipt.accepted {
                return (
                    state.clone(),
                    ManifoldPairMediaRouteReceiptV2::WifiDirect(receipt),
                );
            }
            let mut next = state.clone();
            next.authority_revision = next_legacy.authority_revision;
            next.last_observed_at_ms = next_legacy.last_observed_at_ms;
            next.applied_request_ids = next_legacy.applied_request_ids;
            next.routes
                .retain(|route| matches!(route, ManifoldAcceptedPairMediaRouteV2::CommonLan(_)));
            for route in &mut next.routes {
                if let ManifoldAcceptedPairMediaRouteV2::CommonLan(value) = route {
                    if value.route_leg.leg_id == request.route_leg.leg_id
                        && value.lifecycle_status == ManifoldPairMediaRouteLifecycleStatus::Current
                    {
                        value.lifecycle_status = ManifoldPairMediaRouteLifecycleStatus::Superseded;
                        value.cleanup_status = ManifoldPairMediaRouteCleanupStatus::Pending;
                        value.ended_at_ms = Some(now_ms);
                        value.ended_by_id = Some(request.request_id.clone());
                    }
                }
            }
            next.routes.extend(
                next_legacy
                    .routes
                    .into_iter()
                    .map(ManifoldAcceptedPairMediaRouteV2::WifiDirect),
            );
            next.cleanup_receipts.retain(|receipt| {
                matches!(
                    receipt,
                    ManifoldPairMediaRouteCleanupReceiptV2::CommonLan(_)
                )
            });
            next.cleanup_receipts.extend(
                next_legacy
                    .cleanup_receipts
                    .into_iter()
                    .map(ManifoldPairMediaRouteCleanupReceiptV2::WifiDirect),
            );
            (next, ManifoldPairMediaRouteReceiptV2::WifiDirect(receipt))
        }
        ManifoldPairMediaRouteRequestV2::CommonLan(common) => {
            issue_common_lan_route(state, common, runtime, authority, now_ms)
        }
    }
}

#[allow(clippy::too_many_lines)]
fn issue_common_lan_route(
    state: &ManifoldPairMediaRouteAuthorityStateV2,
    common: &ManifoldCommonLanPairMediaRouteRequest,
    runtime: ManifoldPairMediaRouteRuntimeContext<'_>,
    authority: ManifoldPairMediaRouteAuthorityContextV2<'_>,
    now_ms: u64,
) -> (
    ManifoldPairMediaRouteAuthorityStateV2,
    ManifoldPairMediaRouteReceiptV2,
) {
    let request = &common.request;
    let prior = state.authority_revision;
    let rejected = |reason| {
        ManifoldPairMediaRouteReceiptV2::CommonLan(ManifoldCommonLanPairMediaRouteReceipt {
            schema_id: schema(PAIR_MEDIA_ROUTE_RECEIPT_V2_SCHEMA),
            request_id: request.request_id.clone(),
            rejection_reason: Some(reason),
            route: None,
            prior_authority_revision: prior,
            resulting_authority_revision: prior,
        })
    };
    if request.schema_id.as_str() != PAIR_MEDIA_ROUTE_REQUEST_SCHEMA
        || request.route_leg.schema_id.as_str() != MANIFOLD_MEDIA_ROUTE_LEG_SCHEMA
    {
        return (
            state.clone(),
            rejected(ManifoldPairMediaRouteRejectionReason::SchemaMismatch),
        );
    }
    if !pair_media_route_state_v2_is_well_formed(state) {
        return (
            state.clone(),
            rejected(ManifoldPairMediaRouteRejectionReason::InvalidAuthorityState),
        );
    }
    if state.applied_request_ids.contains(&request.request_id) {
        return (
            state.clone(),
            rejected(ManifoldPairMediaRouteRejectionReason::ReplayedRequest),
        );
    }
    if request.expected_authority_revision != prior
        || request.expected_peer_session_authority_revision
            != authority.peer_sessions.authority_revision
        || request.expected_media_acceptance_authority_revision
            != authority.media_sessions.authority_revision
    {
        return (
            state.clone(),
            rejected(ManifoldPairMediaRouteRejectionReason::StaleAuthorityRevision),
        );
    }
    if state.last_observed_at_ms.is_some_and(|last| now_ms < last) {
        return (
            state.clone(),
            rejected(ManifoldPairMediaRouteRejectionReason::ClockRegression),
        );
    }
    if state.routes.len() >= MAX_PAIR_MEDIA_ROUTE_RECORDS
        || !issue_preserves_terminal_capacity_v2(state, &request.route_leg.leg_id)
    {
        return (
            state.clone(),
            rejected(ManifoldPairMediaRouteRejectionReason::CapacityExceeded),
        );
    }
    if request.route_leg.validate().is_err() {
        return (
            state.clone(),
            rejected(ManifoldPairMediaRouteRejectionReason::DirectionMismatch),
        );
    }
    let peer = validate_current_peer_session_v2(
        authority.accepted_peers,
        authority.enrollment,
        authority.reciprocal,
        authority.peer_sessions,
        authority.signed_topologies,
        &request.peer_session_id,
        now_ms,
    );
    let Some(topology) = authority
        .signed_topologies
        .iter()
        .find_map(|value| match value {
            ManifoldSignedPeerTopologyAuthorizationV2::CommonLan(value)
                if value.session_id == request.peer_session_id
                    && peer.decision_id.as_ref() == Some(&value.decision_id)
                    && value.authorized =>
            {
                Some(value)
            }
            _ => None,
        })
    else {
        return (
            state.clone(),
            rejected(ManifoldPairMediaRouteRejectionReason::PeerSessionNotCurrent),
        );
    };
    if !peer.current
        || topology.transport != common.transport
        || topology.valid_from_ms > now_ms
        || topology.expires_at_ms <= now_ms
        || !peer.peer_ids.contains(&request.route_leg.source_peer_id)
        || !peer.peer_ids.contains(&request.route_leg.sink_peer_id)
    {
        return (
            state.clone(),
            rejected(ManifoldPairMediaRouteRejectionReason::PeerSessionNotCurrent),
        );
    }
    let media_current = validate_current_media_session(
        authority.media_sessions,
        &request.media_session_decision_id,
        runtime.live_authority_provider_epoch_id,
        now_ms,
    );
    let Some(media) = media_current.session.filter(|_| media_current.current) else {
        return (
            state.clone(),
            rejected(ManifoldPairMediaRouteRejectionReason::MediaSessionNotCurrent),
        );
    };
    let descriptor = &media.product_binding.descriptor;
    if !descriptor.source_ids.contains(&request.route_leg.source_id)
        || !descriptor.route_ids.contains(&request.route_leg.route_id)
        || !descriptor.sink_ids.contains(&request.route_leg.sink_id)
        || request
            .route_leg
            .processor_ids
            .iter()
            .any(|id| !descriptor.processor_ids.contains(id))
        || request
            .route_leg
            .stream_ids
            .iter()
            .any(|id| !descriptor.stream_ids.contains(id))
    {
        return (
            state.clone(),
            rejected(ManifoldPairMediaRouteRejectionReason::ResourceMismatch),
        );
    }
    if state.routes.iter().any(|route| {
        route.route_leg().leg_id == request.route_leg.leg_id
            && (route.route_leg().source_peer_id != request.route_leg.source_peer_id
                || route.route_leg().sink_peer_id != request.route_leg.sink_peer_id
                || route.authority_client_id() != &runtime.command_request.requester_id)
    }) {
        return (
            state.clone(),
            rejected(ManifoldPairMediaRouteRejectionReason::DirectionMismatch),
        );
    }
    if state.routes.iter().any(|route| {
        route.route_leg().leg_id == request.route_leg.leg_id
            && route.route_leg().leg_revision >= request.route_leg.leg_revision
    }) {
        return (
            state.clone(),
            rejected(ManifoldPairMediaRouteRejectionReason::StaleLegRevision),
        );
    }
    if !route_lifetime_is_bounded(
        request.expires_at_ms,
        now_ms,
        MAX_COMMON_LAN_PAIR_MEDIA_ROUTE_TTL_MS,
    ) || peer
        .expires_at_ms
        .map_or(true, |expiry| request.expires_at_ms > expiry)
        || request.expires_at_ms > media.expires_at_ms
        || request.expires_at_ms > request.expected_runtime_lease_expires_at_ms
    {
        return (
            state.clone(),
            rejected(ManifoldPairMediaRouteRejectionReason::InvalidExpiry),
        );
    }
    if !issue_preserves_revision_capacity_v2(state, &request.route_leg.leg_id) {
        return (
            state.clone(),
            rejected(ManifoldPairMediaRouteRejectionReason::RevisionExhausted),
        );
    }
    let params = typed_digest(PAIR_MEDIA_ROUTE_ISSUE_PARAMS_V2_TYPE, common).ok();
    if validate_runtime(
        runtime,
        &request.runtime_command_request_id,
        PAIR_MEDIA_ROUTE_ISSUE_COMMAND,
        params.as_ref(),
        now_ms,
    )
    .is_err()
    {
        return (
            state.clone(),
            rejected(ManifoldPairMediaRouteRejectionReason::RuntimeCommandNotAccepted),
        );
    }
    let Some(lease_id) = runtime.command_request.lease_id.as_ref() else {
        return (
            state.clone(),
            rejected(ManifoldPairMediaRouteRejectionReason::RuntimeCommandNotAccepted),
        );
    };
    let Some(runtime_lease) = runtime.runtime_lease.filter(|lease| {
        lease.lease_id == *lease_id
            && lease.holder_id == runtime.command_request.requester_id
            && lease.expires_at_ms > now_ms
    }) else {
        return (
            state.clone(),
            rejected(ManifoldPairMediaRouteRejectionReason::RuntimeCommandNotAccepted),
        );
    };
    if media.runtime_authority_host_id != *runtime.authority_host_id
        || media.provider_epoch_id != *runtime.live_authority_provider_epoch_id
        || media.runtime_client_id != runtime.command_request.requester_id
        || media.runtime_lease_id != *lease_id
        || request.expected_runtime_lease_expires_at_ms != runtime_lease.expires_at_ms
    {
        return (
            state.clone(),
            rejected(ManifoldPairMediaRouteRejectionReason::ClientNotAuthorized),
        );
    }
    let mut resources = descriptor
        .source_ids
        .iter()
        .chain(&descriptor.processor_ids)
        .chain(&descriptor.route_ids)
        .chain(&descriptor.sink_ids)
        .chain(&descriptor.stream_ids)
        .cloned()
        .collect::<Vec<_>>();
    resources.sort();
    let Some(grant) = runtime.media_client_grants.iter().find(|grant| {
        grant.runtime_host_id == *runtime.authority_host_id
            && grant.client_id == runtime.command_request.requester_id
            && grant.lease_id == *lease_id
            && grant.product_id == media.product_id
            && grant.feature_lock_id == media.feature_lock_id
            && grant.feature_lock_fingerprint == media.feature_lock_fingerprint
            && grant.capability_id == media.capability_id
            && grant.admission_grant_id == media.admission_grant_id
            && grant.allowed_session_id == media.session_id
            && grant.allowed_platform_runtime_spec_id == media.platform_runtime_spec_id
            && grant
                .allowed_descriptor_canonical_sha256
                .contains(&media.product_descriptor_canonical_sha256)
            && grant.allowed_resource_ids == resources
    }) else {
        return (
            state.clone(),
            rejected(ManifoldPairMediaRouteRejectionReason::ClientNotAuthorized),
        );
    };
    let Some(resulting) = prior.next() else {
        return (
            state.clone(),
            rejected(ManifoldPairMediaRouteRejectionReason::RevisionExhausted),
        );
    };
    let accepted = ManifoldAcceptedCommonLanPairMediaRoute {
        schema_id: schema(PAIR_MEDIA_ROUTE_RECORD_V2_SCHEMA),
        grant_id: derived(
            "grant.peer.common-lan-pair-media-route",
            &request.request_id,
        ),
        request_id: request.request_id.clone(),
        route_leg: request.route_leg.clone(),
        peer_session_id: request.peer_session_id.clone(),
        peer_session_decision_id: peer.decision_id.expect("current peer receipt has decision"),
        transport: common.transport.clone(),
        signed_topology_evidence: topology.clone(),
        peer_session_authority_revision: topology.authority_revision,
        peer_session_acceptance_authority_revision: authority.peer_sessions.authority_revision,
        reciprocal_receipt_id: topology.reciprocal_receipt_id.clone(),
        reciprocal_authority_revision: topology.reciprocal_authority_revision,
        enrollment_authority_revision: topology.enrollment_authority_revision,
        media_session_decision_id: media.decision_id.clone(),
        media_session_id: media.session_id.clone(),
        media_session_authority_revision: media.session_authority_revision,
        media_acceptance_authority_revision: authority.media_sessions.authority_revision,
        media_descriptor_canonical_sha256: media.product_descriptor_canonical_sha256.clone(),
        platform_runtime_spec_id: media.platform_runtime_spec_id.clone(),
        authority_host_id: runtime.authority_host_id.clone(),
        authority_provider_epoch_id: runtime.live_authority_provider_epoch_id.clone(),
        authority_client_id: runtime.command_request.requester_id.clone(),
        authority_runtime_lease_id: lease_id.clone(),
        authority_runtime_lease_expires_at_ms: request.expected_runtime_lease_expires_at_ms,
        runtime_command_request_id: runtime.command_request.request_id.clone(),
        runtime_command_id: runtime.command_request.command_id.clone(),
        runtime_params_digest: params.expect("validated issue digest"),
        runtime_dispatch_id: runtime.dispatch.dispatch_id.clone(),
        runtime_application_receipt_id: runtime.application.receipt_id.clone(),
        runtime_resulting_authority_revision: runtime.application.resulting_authority_revision,
        product_id: media.product_id.clone(),
        feature_lock_id: media.feature_lock_id.clone(),
        feature_lock_fingerprint: media.feature_lock_fingerprint.clone(),
        capability_id: grant.capability_id.clone(),
        admission_grant_id: grant.admission_grant_id.clone(),
        lifecycle_status: ManifoldPairMediaRouteLifecycleStatus::Current,
        cleanup_status: ManifoldPairMediaRouteCleanupStatus::NotRequired,
        valid_from_ms: now_ms,
        expires_at_ms: request.expires_at_ms,
        ended_at_ms: None,
        ended_by_id: None,
        termination_action: None,
        termination_runtime_binding: None,
        cleanup_receipt_id: None,
    };
    let mut next = state.clone();
    for route in &mut next.routes {
        if route.route_leg().leg_id == request.route_leg.leg_id
            && *route.lifecycle_status() == ManifoldPairMediaRouteLifecycleStatus::Current
        {
            match route {
                ManifoldAcceptedPairMediaRouteV2::WifiDirect(value) => {
                    value.lifecycle_status = ManifoldPairMediaRouteLifecycleStatus::Superseded;
                    value.cleanup_status = ManifoldPairMediaRouteCleanupStatus::Pending;
                    value.ended_at_ms = Some(now_ms);
                    value.ended_by_id = Some(request.request_id.clone());
                }
                ManifoldAcceptedPairMediaRouteV2::CommonLan(value) => {
                    value.lifecycle_status = ManifoldPairMediaRouteLifecycleStatus::Superseded;
                    value.cleanup_status = ManifoldPairMediaRouteCleanupStatus::Pending;
                    value.ended_at_ms = Some(now_ms);
                    value.ended_by_id = Some(request.request_id.clone());
                }
            }
        }
    }
    next.authority_revision = resulting;
    next.last_observed_at_ms = Some(now_ms);
    next.applied_request_ids.push(request.request_id.clone());
    next.applied_request_ids.sort();
    next.routes
        .push(ManifoldAcceptedPairMediaRouteV2::CommonLan(
            accepted.clone(),
        ));
    next.routes
        .sort_by(|left, right| left.grant_id().cmp(right.grant_id()));
    let receipt = ManifoldCommonLanPairMediaRouteReceipt {
        schema_id: schema(PAIR_MEDIA_ROUTE_RECEIPT_V2_SCHEMA),
        request_id: request.request_id.clone(),
        rejection_reason: None,
        route: Some(accepted),
        prior_authority_revision: prior,
        resulting_authority_revision: resulting,
    };
    (next, ManifoldPairMediaRouteReceiptV2::CommonLan(receipt))
}

/// Reviews and applies one pair route issue using borrowed current authority.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn review_and_apply_pair_media_route(
    state: &ManifoldPairMediaRouteState,
    authority: ManifoldPairMediaRouteAuthorityContext<'_>,
    request: &ManifoldPairMediaRouteRequest,
    runtime: ManifoldPairMediaRouteRuntimeContext<'_>,
    now_ms: u64,
) -> (ManifoldPairMediaRouteState, ManifoldPairMediaRouteReceipt) {
    let prior = state.authority_revision;
    let validation = validate_issue(state, authority, request, runtime, now_ms);
    let Ok((_peer_receipt, peer, media, topology, grant)) = validation else {
        return (
            state.clone(),
            route_receipt(request, validation.err(), None, prior, prior),
        );
    };
    let Some(resulting) = prior.next() else {
        return (
            state.clone(),
            route_receipt(
                request,
                Some(ManifoldPairMediaRouteRejectionReason::RevisionExhausted),
                None,
                prior,
                prior,
            ),
        );
    };
    let (Some(runtime_lease_id), Some(runtime_params_digest)) = (
        runtime.command_request.lease_id.as_ref(),
        runtime.command_request.params_digest.as_ref(),
    ) else {
        return (
            state.clone(),
            route_receipt(
                request,
                Some(ManifoldPairMediaRouteRejectionReason::RuntimeCommandNotAccepted),
                None,
                prior,
                prior,
            ),
        );
    };
    let mut next = state.clone();
    for route in &mut next.routes {
        if route.route_leg.leg_id == request.route_leg.leg_id
            && route.lifecycle_status == ManifoldPairMediaRouteLifecycleStatus::Current
        {
            route.lifecycle_status = ManifoldPairMediaRouteLifecycleStatus::Superseded;
            route.cleanup_status = ManifoldPairMediaRouteCleanupStatus::Pending;
            route.ended_at_ms = Some(now_ms);
            route.ended_by_id = Some(request.request_id.clone());
        }
    }
    let source_is_owner =
        topology.topology_authorization.group_owner_peer_id == request.route_leg.source_peer_id;
    let accepted = ManifoldAcceptedPairMediaRoute {
        schema_id: schema(PAIR_MEDIA_ROUTE_RECORD_SCHEMA),
        grant_id: derived("grant.peer.pair-media-route", &request.request_id),
        request_id: request.request_id.clone(),
        route_leg: request.route_leg.clone(),
        peer_session_id: request.peer_session_id.clone(),
        peer_session_decision_id: peer.decision_id.clone(),
        signed_topology_evidence: topology.clone(),
        peer_session_authority_revision: topology.topology_authorization.authority_revision,
        peer_session_acceptance_authority_revision: authority.peer_sessions.authority_revision,
        rendezvous_receipt_id: topology.rendezvous_receipt_id.clone(),
        rendezvous_authority_revision: topology.rendezvous_authority_revision,
        enrollment_authority_revision: topology.enrollment_authority_revision,
        source_topology_role: if source_is_owner {
            PeerTopologyRole::GroupOwner
        } else {
            PeerTopologyRole::Client
        },
        sink_topology_role: if source_is_owner {
            PeerTopologyRole::Client
        } else {
            PeerTopologyRole::GroupOwner
        },
        media_session_decision_id: media.decision_id.clone(),
        media_session_id: media.session_id.clone(),
        media_session_authority_revision: media.session_authority_revision,
        media_acceptance_authority_revision: authority.media_sessions.authority_revision,
        media_descriptor_canonical_sha256: media.product_descriptor_canonical_sha256.clone(),
        platform_runtime_spec_id: media.platform_runtime_spec_id.clone(),
        authority_host_id: runtime.authority_host_id.clone(),
        authority_provider_epoch_id: runtime.live_authority_provider_epoch_id.clone(),
        authority_client_id: runtime.command_request.requester_id.clone(),
        authority_runtime_lease_id: runtime_lease_id.clone(),
        authority_runtime_lease_expires_at_ms: request.expected_runtime_lease_expires_at_ms,
        runtime_command_request_id: runtime.command_request.request_id.clone(),
        runtime_command_id: runtime.command_request.command_id.clone(),
        runtime_params_digest: runtime_params_digest.clone(),
        runtime_dispatch_id: runtime.dispatch.dispatch_id.clone(),
        runtime_application_receipt_id: runtime.application.receipt_id.clone(),
        runtime_resulting_authority_revision: runtime.application.resulting_authority_revision,
        product_id: media.product_id.clone(),
        feature_lock_id: media.feature_lock_id.clone(),
        feature_lock_fingerprint: media.feature_lock_fingerprint.clone(),
        capability_id: grant.capability_id.clone(),
        admission_grant_id: grant.admission_grant_id.clone(),
        lifecycle_status: ManifoldPairMediaRouteLifecycleStatus::Current,
        cleanup_status: ManifoldPairMediaRouteCleanupStatus::NotRequired,
        valid_from_ms: now_ms,
        expires_at_ms: request.expires_at_ms,
        ended_at_ms: None,
        ended_by_id: None,
        termination_action: None,
        termination_runtime_binding: None,
        cleanup_receipt_id: None,
    };
    next.authority_revision = resulting;
    next.last_observed_at_ms = Some(now_ms);
    next.routes.push(accepted.clone());
    next.routes.sort_by(|a, b| a.grant_id.cmp(&b.grant_id));
    next.applied_request_ids.push(request.request_id.clone());
    next.applied_request_ids.sort();
    (
        next,
        route_receipt(request, None, Some(accepted), prior, resulting),
    )
}

/// Reviews and applies a client stop or trusted-operator revocation.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn review_and_apply_pair_media_route_termination(
    state: &ManifoldPairMediaRouteState,
    request: &ManifoldPairMediaRouteTerminationRequest,
    runtime: ManifoldPairMediaRouteRuntimeContext<'_>,
    now_ms: u64,
) -> (
    ManifoldPairMediaRouteState,
    ManifoldPairMediaRouteMutationReceipt,
) {
    let prior = state.authority_revision;
    let expected_command = match request.action {
        ManifoldPairMediaRouteTerminationAction::Stop => PAIR_MEDIA_ROUTE_STOP_COMMAND,
        ManifoldPairMediaRouteTerminationAction::Revoke => PAIR_MEDIA_ROUTE_REVOKE_COMMAND,
    };
    let params = pair_media_route_termination_params_digest(request).ok();
    let target = state.routes.iter().find(|r| r.grant_id == request.grant_id);
    let rejection = common_mutation_rejection(
        state,
        request.expected_authority_revision,
        &request.request_id,
        now_ms,
    )
    .or_else(|| {
        (request.schema_id.as_str() != PAIR_MEDIA_ROUTE_TERMINATION_REQUEST_SCHEMA)
            .then_some(ManifoldPairMediaRouteRejectionReason::SchemaMismatch)
    })
    .or_else(|| {
        validate_runtime(
            runtime,
            &request.runtime_command_request_id,
            expected_command,
            params.as_ref(),
            now_ms,
        )
        .err()
    })
    .or_else(|| {
        target
            .filter(|r| {
                r.lifecycle_status == ManifoldPairMediaRouteLifecycleStatus::Current
                    && r.expires_at_ms > now_ms
            })
            .is_none()
            .then_some(ManifoldPairMediaRouteRejectionReason::RouteNotCurrent)
    })
    .or_else(|| {
        target.and_then(|route| match request.action {
            ManifoldPairMediaRouteTerminationAction::Stop
                if runtime.command_request.requester_id != route.authority_client_id
                    || runtime.command_request.lease_id.as_ref()
                        != Some(&route.authority_runtime_lease_id) =>
            {
                Some(ManifoldPairMediaRouteRejectionReason::ClientNotAuthorized)
            }
            ManifoldPairMediaRouteTerminationAction::Revoke
                if !runtime
                    .trusted_media_revoker_ids
                    .contains(&runtime.command_request.requester_id) =>
            {
                Some(ManifoldPairMediaRouteRejectionReason::ClientNotAuthorized)
            }
            _ => None,
        })
    })
    .or_else(|| {
        target.and_then(|route| {
            (*runtime.authority_host_id != route.authority_host_id
                || *runtime.live_authority_provider_epoch_id != route.authority_provider_epoch_id)
                .then_some(ManifoldPairMediaRouteRejectionReason::ClientNotAuthorized)
        })
    })
    .or_else(|| {
        prior
            .next()
            .is_none()
            .then_some(ManifoldPairMediaRouteRejectionReason::RevisionExhausted)
    });
    if let Some(reason) = rejection {
        return (
            state.clone(),
            mutation_receipt(
                request.request_id.clone(),
                Some(reason),
                Vec::new(),
                prior,
                prior,
            ),
        );
    }
    let Some(resulting) = prior.next() else {
        return (
            state.clone(),
            mutation_receipt(
                request.request_id.clone(),
                Some(ManifoldPairMediaRouteRejectionReason::RevisionExhausted),
                Vec::new(),
                prior,
                prior,
            ),
        );
    };
    let mut next = state.clone();
    for route in &mut next.routes {
        if route.grant_id == request.grant_id {
            route.lifecycle_status = match request.action {
                ManifoldPairMediaRouteTerminationAction::Stop => {
                    ManifoldPairMediaRouteLifecycleStatus::Stopped
                }
                ManifoldPairMediaRouteTerminationAction::Revoke => {
                    ManifoldPairMediaRouteLifecycleStatus::Revoked
                }
            };
            route.cleanup_status = ManifoldPairMediaRouteCleanupStatus::Pending;
            route.ended_at_ms = Some(now_ms);
            route.ended_by_id = Some(request.request_id.clone());
            route.termination_action = Some(request.action.clone());
            route.termination_runtime_binding = Some(runtime_binding(runtime));
        }
    }
    next.authority_revision = resulting;
    next.last_observed_at_ms = Some(now_ms);
    next.applied_request_ids.push(request.request_id.clone());
    next.applied_request_ids.sort();
    next.applied_request_ids.sort();
    (
        next.clone(),
        mutation_receipt(
            request.request_id.clone(),
            None,
            vec![request.grant_id.clone()],
            prior,
            next.authority_revision,
        ),
    )
}

/// Terminalizes current routes whose deadlines have passed.
///
/// # Errors
///
/// Returns a closed rejection for stale/replayed sweeps, clock regression,
/// malformed retained state, no due routes, capacity, or revision exhaustion.
pub fn expire_pair_media_routes(
    state: &ManifoldPairMediaRouteState,
    sweep_id: DottedId,
    expected: Revision,
    now_ms: u64,
) -> Result<
    (
        ManifoldPairMediaRouteState,
        ManifoldPairMediaRouteMutationReceipt,
    ),
    ManifoldPairMediaRouteRejectionReason,
> {
    if let Some(reason) = common_mutation_rejection(state, expected, &sweep_id, now_ms) {
        return Err(reason);
    }
    let affected = state
        .routes
        .iter()
        .filter(|r| {
            r.lifecycle_status == ManifoldPairMediaRouteLifecycleStatus::Current
                && r.expires_at_ms <= now_ms
        })
        .map(|r| r.grant_id.clone())
        .collect::<Vec<_>>();
    if affected.is_empty() {
        return Err(ManifoldPairMediaRouteRejectionReason::RouteNotCurrent);
    }
    let resulting = state
        .authority_revision
        .next()
        .ok_or(ManifoldPairMediaRouteRejectionReason::RevisionExhausted)?;
    let mut next = state.clone();
    for route in &mut next.routes {
        if affected.contains(&route.grant_id) {
            route.lifecycle_status = ManifoldPairMediaRouteLifecycleStatus::Expired;
            route.cleanup_status = ManifoldPairMediaRouteCleanupStatus::Pending;
            route.ended_at_ms = Some(now_ms);
            route.ended_by_id = Some(sweep_id.clone());
        }
    }
    next.authority_revision = resulting;
    next.last_observed_at_ms = Some(now_ms);
    next.applied_request_ids.push(sweep_id.clone());
    next.applied_request_ids.sort();
    next.applied_request_ids.sort();
    let receipt = mutation_receipt(
        sweep_id,
        None,
        affected,
        state.authority_revision,
        resulting,
    );
    Ok((next, receipt))
}

/// Rechecks one route against retained signed pair and accepted media state.
#[must_use]
pub fn validate_current_pair_media_route(
    state: &ManifoldPairMediaRouteState,
    authority: ManifoldPairMediaRouteAuthorityContext<'_>,
    grant_id: &DottedId,
    live_epoch: &DottedId,
    now_ms: u64,
) -> ManifoldPairMediaRouteCurrentReceipt {
    let route = state.routes.iter().find(|r| &r.grant_id == grant_id);
    let rejection = if !pair_media_route_state_is_well_formed(state) {
        Some(ManifoldPairMediaRouteRejectionReason::InvalidAuthorityState)
    } else if state.last_observed_at_ms.is_some_and(|last| now_ms < last) {
        Some(ManifoldPairMediaRouteRejectionReason::ClockRegression)
    } else if let Some(route) = route {
        if route.lifecycle_status != ManifoldPairMediaRouteLifecycleStatus::Current
            || route.expires_at_ms <= now_ms
            || &route.authority_provider_epoch_id != live_epoch
        {
            Some(ManifoldPairMediaRouteRejectionReason::RouteNotCurrent)
        } else {
            let peer = validate_current_peer_session(
                authority.accepted_peers,
                authority.enrollment,
                authority.rendezvous,
                authority.peer_sessions,
                authority.signed_topologies,
                &route.peer_session_id,
                now_ms,
            );
            if !peer.current || !route_matches_current_peer(route, authority, &peer) {
                Some(ManifoldPairMediaRouteRejectionReason::PeerSessionNotCurrent)
            } else {
                let media = validate_current_media_session(
                    authority.media_sessions,
                    &route.media_session_decision_id,
                    live_epoch,
                    now_ms,
                );
                if !media.current
                    || media
                        .session
                        .as_ref()
                        .map_or(true, |session| !route_matches_current_media(route, session))
                {
                    Some(ManifoldPairMediaRouteRejectionReason::MediaSessionNotCurrent)
                } else {
                    None
                }
            }
        }
    } else {
        Some(ManifoldPairMediaRouteRejectionReason::RouteNotCurrent)
    };
    ManifoldPairMediaRouteCurrentReceipt {
        schema_id: schema(PAIR_MEDIA_ROUTE_CURRENT_RECEIPT_SCHEMA),
        grant_id: grant_id.clone(),
        current: rejection.is_none(),
        rejection_reason: rejection,
        route: route.cloned(),
        validated_at_ms: now_ms,
    }
}

/// Rechecks one mixed route against current peer/media authority.
#[must_use]
pub fn validate_current_pair_media_route_v2(
    state: &ManifoldPairMediaRouteAuthorityStateV2,
    authority: ManifoldPairMediaRouteAuthorityContextV2<'_>,
    grant_id: &DottedId,
    live_epoch: &DottedId,
    now_ms: u64,
) -> ManifoldPairMediaRouteCurrentReceiptV2 {
    let route = state
        .routes
        .iter()
        .find(|route| route.grant_id() == grant_id);
    let rejection = if !pair_media_route_state_v2_is_well_formed(state) {
        Some(ManifoldPairMediaRouteRejectionReason::InvalidAuthorityState)
    } else if state.last_observed_at_ms.is_some_and(|last| now_ms < last) {
        Some(ManifoldPairMediaRouteRejectionReason::ClockRegression)
    } else if let Some(route) = route {
        if *route.lifecycle_status() != ManifoldPairMediaRouteLifecycleStatus::Current
            || route.expires_at_ms() <= now_ms
            || route.authority_provider_epoch_id() != live_epoch
        {
            Some(ManifoldPairMediaRouteRejectionReason::RouteNotCurrent)
        } else {
            let peer_matches = match route {
                ManifoldAcceptedPairMediaRouteV2::WifiDirect(value) => {
                    let wifi_sessions =
                        crate::wifi_direct_peer_session_projection(authority.peer_sessions);
                    let wifi_topologies = authority
                        .signed_topologies
                        .iter()
                        .filter_map(|candidate| candidate.as_wifi_direct().cloned())
                        .collect::<Vec<_>>();
                    let legacy_authority = ManifoldPairMediaRouteAuthorityContext {
                        accepted_peers: authority.accepted_peers,
                        enrollment: authority.enrollment,
                        rendezvous: authority.rendezvous,
                        peer_sessions: &wifi_sessions,
                        signed_topologies: &wifi_topologies,
                        media_sessions: authority.media_sessions,
                    };
                    let peer = validate_current_peer_session(
                        legacy_authority.accepted_peers,
                        legacy_authority.enrollment,
                        legacy_authority.rendezvous,
                        legacy_authority.peer_sessions,
                        legacy_authority.signed_topologies,
                        &value.peer_session_id,
                        now_ms,
                    );
                    peer.current && route_matches_current_peer(value, legacy_authority, &peer)
                }
                ManifoldAcceptedPairMediaRouteV2::CommonLan(value) => {
                    let peer = validate_current_peer_session_v2(
                        authority.accepted_peers,
                        authority.enrollment,
                        authority.reciprocal,
                        authority.peer_sessions,
                        authority.signed_topologies,
                        &value.peer_session_id,
                        now_ms,
                    );
                    peer.current && route_matches_current_common_lan_peer(value, authority, &peer)
                }
            };
            if !peer_matches {
                Some(ManifoldPairMediaRouteRejectionReason::PeerSessionNotCurrent)
            } else {
                let media = validate_current_media_session(
                    authority.media_sessions,
                    route.media_session_decision_id(),
                    live_epoch,
                    now_ms,
                );
                if media.current
                    && media.session.as_ref().is_some_and(|session| match route {
                        ManifoldAcceptedPairMediaRouteV2::WifiDirect(value) => {
                            route_matches_current_media(value, session)
                        }
                        ManifoldAcceptedPairMediaRouteV2::CommonLan(value) => {
                            route_matches_current_common_lan_media(value, session)
                        }
                    })
                {
                    None
                } else {
                    Some(ManifoldPairMediaRouteRejectionReason::MediaSessionNotCurrent)
                }
            }
        }
    } else {
        Some(ManifoldPairMediaRouteRejectionReason::RouteNotCurrent)
    };
    ManifoldPairMediaRouteCurrentReceiptV2 {
        schema_id: schema(PAIR_MEDIA_ROUTE_CURRENT_RECEIPT_V2_SCHEMA),
        grant_id: grant_id.clone(),
        current: rejection.is_none(),
        rejection_reason: rejection,
        route: route.cloned(),
        validated_at_ms: now_ms,
    }
}

fn route_matches_current_common_lan_peer(
    route: &ManifoldAcceptedCommonLanPairMediaRoute,
    authority: ManifoldPairMediaRouteAuthorityContextV2<'_>,
    receipt: &crate::ManifoldPeerSessionCurrentReceiptV2,
) -> bool {
    let Some(topology) = authority
        .signed_topologies
        .iter()
        .find_map(|candidate| match candidate {
            ManifoldSignedPeerTopologyAuthorizationV2::CommonLan(value)
                if value.session_id == route.peer_session_id
                    && value.decision_id == route.peer_session_decision_id =>
            {
                Some(value)
            }
            _ => None,
        })
    else {
        return false;
    };
    let pair = [&topology.initiator_peer_id, &topology.responder_peer_id];
    topology == &route.signed_topology_evidence
        && topology.authorized
        && topology.transport == route.transport
        && receipt.decision_id.as_ref() == Some(&route.peer_session_decision_id)
        && receipt.peer_ids.len() == 2
        && pair.contains(&&route.route_leg.source_peer_id)
        && pair.contains(&&route.route_leg.sink_peer_id)
        && receipt.peer_ids.contains(&route.route_leg.source_peer_id)
        && receipt.peer_ids.contains(&route.route_leg.sink_peer_id)
        && route.peer_session_authority_revision == topology.authority_revision
        && route.reciprocal_receipt_id == topology.reciprocal_receipt_id
        && route.reciprocal_authority_revision == topology.reciprocal_authority_revision
        && route.enrollment_authority_revision == topology.enrollment_authority_revision
        && route.valid_from_ms >= topology.valid_from_ms
}

fn route_matches_current_common_lan_media(
    route: &ManifoldAcceptedCommonLanPairMediaRoute,
    media: &rusty_manifold_media_session::ManifoldAcceptedMediaSession,
) -> bool {
    let descriptor = &media.product_binding.descriptor;
    media.decision_id == route.media_session_decision_id
        && media.session_id == route.media_session_id
        && media.session_authority_revision == route.media_session_authority_revision
        && media.product_descriptor_canonical_sha256 == route.media_descriptor_canonical_sha256
        && media.platform_runtime_spec_id == route.platform_runtime_spec_id
        && media.runtime_authority_host_id == route.authority_host_id
        && media.provider_epoch_id == route.authority_provider_epoch_id
        && media.runtime_client_id == route.authority_client_id
        && media.runtime_lease_id == route.authority_runtime_lease_id
        && media.product_id == route.product_id
        && media.feature_lock_id == route.feature_lock_id
        && media.feature_lock_fingerprint == route.feature_lock_fingerprint
        && media.capability_id == route.capability_id
        && media.admission_grant_id == route.admission_grant_id
        && route.valid_from_ms >= media.accepted_at_ms
        && descriptor.source_ids.contains(&route.route_leg.source_id)
        && descriptor.route_ids.contains(&route.route_leg.route_id)
        && descriptor.sink_ids.contains(&route.route_leg.sink_id)
        && route
            .route_leg
            .processor_ids
            .iter()
            .all(|id| descriptor.processor_ids.contains(id))
        && route
            .route_leg
            .stream_ids
            .iter()
            .all(|id| descriptor.stream_ids.contains(id))
}

fn route_matches_current_peer(
    route: &ManifoldAcceptedPairMediaRoute,
    authority: ManifoldPairMediaRouteAuthorityContext<'_>,
    receipt: &crate::ManifoldPeerSessionCurrentReceipt,
) -> bool {
    let Some(topology) = authority.signed_topologies.iter().find(|topology| {
        topology.topology_authorization.session_id == route.peer_session_id
            && topology.topology_authorization.decision_id == route.peer_session_decision_id
    }) else {
        return false;
    };
    let source_is_owner =
        topology.topology_authorization.group_owner_peer_id == route.route_leg.source_peer_id;
    topology == &route.signed_topology_evidence
        && receipt.decision_id.as_ref() == Some(&route.peer_session_decision_id)
        && receipt.rendezvous_receipt_id.as_ref() == Some(&route.rendezvous_receipt_id)
        && receipt.peer_ids.len() == 2
        && receipt.peer_ids.contains(&route.route_leg.source_peer_id)
        && receipt.peer_ids.contains(&route.route_leg.sink_peer_id)
        && topology.topology_authorization.authority_revision
            == route.peer_session_authority_revision
        && topology.rendezvous_receipt_id == route.rendezvous_receipt_id
        && topology.rendezvous_authority_revision == route.rendezvous_authority_revision
        && topology.enrollment_authority_revision == route.enrollment_authority_revision
        && route.valid_from_ms >= topology.topology_authorization.valid_from_ms
        && route.route_leg.sink_peer_id
            == if source_is_owner {
                topology.topology_authorization.client_peer_id.clone()
            } else {
                topology.topology_authorization.group_owner_peer_id.clone()
            }
        && source_is_owner == (route.source_topology_role == PeerTopologyRole::GroupOwner)
        && route.source_topology_role != route.sink_topology_role
}

fn route_matches_current_media(
    route: &ManifoldAcceptedPairMediaRoute,
    media: &rusty_manifold_media_session::ManifoldAcceptedMediaSession,
) -> bool {
    let descriptor = &media.product_binding.descriptor;
    media.decision_id == route.media_session_decision_id
        && media.session_id == route.media_session_id
        && media.session_authority_revision == route.media_session_authority_revision
        && media.product_descriptor_canonical_sha256 == route.media_descriptor_canonical_sha256
        && media.platform_runtime_spec_id == route.platform_runtime_spec_id
        && media.runtime_authority_host_id == route.authority_host_id
        && media.provider_epoch_id == route.authority_provider_epoch_id
        && media.runtime_client_id == route.authority_client_id
        && media.runtime_lease_id == route.authority_runtime_lease_id
        && media.product_id == route.product_id
        && media.feature_lock_id == route.feature_lock_id
        && media.feature_lock_fingerprint == route.feature_lock_fingerprint
        && media.capability_id == route.capability_id
        && media.admission_grant_id == route.admission_grant_id
        && route.valid_from_ms >= media.accepted_at_ms
        && descriptor.source_ids.contains(&route.route_leg.source_id)
        && descriptor.route_ids.contains(&route.route_leg.route_id)
        && descriptor.sink_ids.contains(&route.route_leg.sink_id)
        && route
            .route_leg
            .processor_ids
            .iter()
            .all(|id| descriptor.processor_ids.contains(id))
        && route
            .route_leg
            .stream_ids
            .iter()
            .all(|id| descriptor.stream_ids.contains(id))
}

/// Retains an acknowledgement of deployment-owned cleanup evidence.
///
/// # Errors
///
/// Returns a closed rejection for stale/replayed requests, invalid Runtime
/// Host evidence, malformed effect evidence, or a non-pending grant.
pub fn complete_pair_media_route_cleanup(
    state: &ManifoldPairMediaRouteState,
    request: &ManifoldPairMediaRouteCleanupCompletionRequest,
    runtime: ManifoldPairMediaRouteRuntimeContext<'_>,
    now_ms: u64,
) -> Result<
    (
        ManifoldPairMediaRouteState,
        ManifoldPairMediaRouteCleanupReceipt,
    ),
    ManifoldPairMediaRouteRejectionReason,
> {
    if let Some(reason) = common_mutation_rejection(
        state,
        request.expected_authority_revision,
        &request.request_id,
        now_ms,
    ) {
        return Err(reason);
    }
    if request.schema_id.as_str() != PAIR_MEDIA_ROUTE_CLEANUP_REQUEST_SCHEMA {
        return Err(ManifoldPairMediaRouteRejectionReason::SchemaMismatch);
    }
    if state.cleanup_receipts.len() >= MAX_PAIR_MEDIA_ROUTE_RECORDS {
        return Err(ManifoldPairMediaRouteRejectionReason::CapacityExceeded);
    }
    if !valid_sha256(&request.effect_receipt_sha256) {
        return Err(ManifoldPairMediaRouteRejectionReason::CleanupEvidenceInvalid);
    }
    let params = pair_media_route_cleanup_params_digest(request)
        .map_err(|_| ManifoldPairMediaRouteRejectionReason::RuntimeCommandNotAccepted)?;
    validate_runtime(
        runtime,
        &request.runtime_command_request_id,
        PAIR_MEDIA_ROUTE_CLEANUP_COMMAND,
        Some(&params),
        now_ms,
    )?;
    let target = state
        .routes
        .iter()
        .find(|r| r.grant_id == request.grant_id)
        .ok_or(ManifoldPairMediaRouteRejectionReason::RouteNotCurrent)?;
    if target.cleanup_status != ManifoldPairMediaRouteCleanupStatus::Pending {
        return Err(ManifoldPairMediaRouteRejectionReason::CleanupNotPending);
    }
    let requester_is_client = runtime.command_request.requester_id == target.authority_client_id;
    let requester_is_revoker = runtime
        .trusted_media_revoker_ids
        .contains(&runtime.command_request.requester_id);
    if *runtime.authority_host_id != target.authority_host_id
        || (!requester_is_client && !requester_is_revoker)
        || (requester_is_client
            && runtime.command_request.lease_id.as_ref()
                != Some(&target.authority_runtime_lease_id))
        || *runtime.live_authority_provider_epoch_id != target.authority_provider_epoch_id
    {
        return Err(ManifoldPairMediaRouteRejectionReason::ClientNotAuthorized);
    }
    let resulting = state
        .authority_revision
        .next()
        .ok_or(ManifoldPairMediaRouteRejectionReason::RevisionExhausted)?;
    let receipt = ManifoldPairMediaRouteCleanupReceipt {
        schema_id: schema(PAIR_MEDIA_ROUTE_CLEANUP_RECEIPT_SCHEMA),
        receipt_id: derived("receipt.peer.pair-media-route-cleanup", &request.request_id),
        request_id: request.request_id.clone(),
        grant_id: request.grant_id.clone(),
        effect_receipt_id: request.effect_receipt_id.clone(),
        effect_receipt_sha256: request.effect_receipt_sha256.clone(),
        authority_host_id: runtime.authority_host_id.clone(),
        authority_provider_epoch_id: runtime.live_authority_provider_epoch_id.clone(),
        runtime_binding: runtime_binding(runtime),
        completed_at_ms: now_ms,
    };
    let mut next = state.clone();
    for route in &mut next.routes {
        if route.grant_id == request.grant_id {
            route.cleanup_status = ManifoldPairMediaRouteCleanupStatus::Completed;
            route.cleanup_receipt_id = Some(receipt.receipt_id.clone());
        }
    }
    next.authority_revision = resulting;
    next.last_observed_at_ms = Some(now_ms);
    next.applied_request_ids.push(request.request_id.clone());
    next.applied_request_ids.sort();
    next.cleanup_receipts.push(receipt.clone());
    next.cleanup_receipts
        .sort_by(|a, b| a.receipt_id.cmp(&b.receipt_id));
    Ok((next, receipt))
}

/// Applies stop/revoke to either retained topology variant.
#[must_use]
pub fn review_and_apply_pair_media_route_termination_v2(
    state: &ManifoldPairMediaRouteAuthorityStateV2,
    request: &ManifoldPairMediaRouteTerminationRequestV2,
    runtime: ManifoldPairMediaRouteRuntimeContext<'_>,
    now_ms: u64,
) -> (
    ManifoldPairMediaRouteAuthorityStateV2,
    ManifoldPairMediaRouteMutationReceipt,
) {
    let prior = state.authority_revision;
    let mut rejection = (!pair_media_route_state_v2_is_well_formed(state)
        || request.schema_id.as_str() != PAIR_MEDIA_ROUTE_TERMINATION_REQUEST_V2_SCHEMA)
        .then_some(ManifoldPairMediaRouteRejectionReason::InvalidAuthorityState);
    if rejection.is_none()
        && (request.expected_authority_revision != prior
            || state.applied_request_ids.contains(&request.request_id))
    {
        rejection = Some(ManifoldPairMediaRouteRejectionReason::StaleAuthorityRevision);
    }
    if rejection.is_none() && state.last_observed_at_ms.is_some_and(|last| now_ms < last) {
        rejection = Some(ManifoldPairMediaRouteRejectionReason::ClockRegression);
    }
    let target = state
        .routes
        .iter()
        .find(|route| route.grant_id() == &request.grant_id);
    if rejection.is_none()
        && target.map_or(true, |route| {
            route.authority_provider_epoch_id() != &request.expected_authority_provider_epoch_id
                || route.platform_runtime_spec_id() != &request.expected_platform_runtime_spec_id
                || *route.lifecycle_status() != ManifoldPairMediaRouteLifecycleStatus::Current
                || route.expires_at_ms() <= now_ms
        })
    {
        rejection = Some(ManifoldPairMediaRouteRejectionReason::RouteNotCurrent);
    }
    let expected_command = match request.action {
        ManifoldPairMediaRouteTerminationAction::Stop => PAIR_MEDIA_ROUTE_STOP_COMMAND,
        ManifoldPairMediaRouteTerminationAction::Revoke => PAIR_MEDIA_ROUTE_REVOKE_COMMAND,
    };
    let params = typed_digest(PAIR_MEDIA_ROUTE_TERMINATION_PARAMS_V2_TYPE, request).ok();
    if rejection.is_none() {
        rejection = validate_runtime(
            runtime,
            &request.runtime_command_request_id,
            expected_command,
            params.as_ref(),
            now_ms,
        )
        .err();
    }
    if let Some(route) = target {
        let authorized = match request.action {
            ManifoldPairMediaRouteTerminationAction::Stop => {
                runtime.command_request.requester_id == *route.authority_client_id()
                    && runtime.command_request.lease_id.as_ref()
                        == Some(route.authority_runtime_lease_id())
            }
            ManifoldPairMediaRouteTerminationAction::Revoke => runtime
                .trusted_media_revoker_ids
                .contains(&runtime.command_request.requester_id),
        };
        if rejection.is_none() && !authorized {
            rejection = Some(ManifoldPairMediaRouteRejectionReason::ClientNotAuthorized);
        }
    }
    if let Some(reason) = rejection {
        return (
            state.clone(),
            mutation_receipt(
                request.request_id.clone(),
                Some(reason),
                Vec::new(),
                prior,
                prior,
            ),
        );
    }
    let Some(resulting) = prior.next() else {
        return (
            state.clone(),
            mutation_receipt(
                request.request_id.clone(),
                Some(ManifoldPairMediaRouteRejectionReason::RevisionExhausted),
                Vec::new(),
                prior,
                prior,
            ),
        );
    };
    let mut next = state.clone();
    for route in &mut next.routes {
        if route.grant_id() == &request.grant_id {
            let (lifecycle, cleanup, ended_at, ended_by, action, binding) = match route {
                ManifoldAcceptedPairMediaRouteV2::WifiDirect(v) => (
                    &mut v.lifecycle_status,
                    &mut v.cleanup_status,
                    &mut v.ended_at_ms,
                    &mut v.ended_by_id,
                    &mut v.termination_action,
                    &mut v.termination_runtime_binding,
                ),
                ManifoldAcceptedPairMediaRouteV2::CommonLan(v) => (
                    &mut v.lifecycle_status,
                    &mut v.cleanup_status,
                    &mut v.ended_at_ms,
                    &mut v.ended_by_id,
                    &mut v.termination_action,
                    &mut v.termination_runtime_binding,
                ),
            };
            *lifecycle = match request.action {
                ManifoldPairMediaRouteTerminationAction::Stop => {
                    ManifoldPairMediaRouteLifecycleStatus::Stopped
                }
                ManifoldPairMediaRouteTerminationAction::Revoke => {
                    ManifoldPairMediaRouteLifecycleStatus::Revoked
                }
            };
            *cleanup = ManifoldPairMediaRouteCleanupStatus::Pending;
            *ended_at = Some(now_ms);
            *ended_by = Some(request.request_id.clone());
            *action = Some(request.action.clone());
            *binding = Some(runtime_binding(runtime));
        }
    }
    next.authority_revision = resulting;
    next.last_observed_at_ms = Some(now_ms);
    next.applied_request_ids.push(request.request_id.clone());
    (
        next,
        mutation_receipt(
            request.request_id.clone(),
            None,
            vec![request.grant_id.clone()],
            prior,
            resulting,
        ),
    )
}

/// Applies an unchanged V1 Wi-Fi termination command to mixed durable state.
#[must_use]
pub fn review_and_apply_pair_media_route_termination_v1_on_v2(
    state: &ManifoldPairMediaRouteAuthorityStateV2,
    request: &ManifoldPairMediaRouteTerminationRequest,
    runtime: ManifoldPairMediaRouteRuntimeContext<'_>,
    now_ms: u64,
) -> (
    ManifoldPairMediaRouteAuthorityStateV2,
    ManifoldPairMediaRouteMutationReceipt,
) {
    let prior = state.authority_revision;
    let expected_command = match request.action {
        ManifoldPairMediaRouteTerminationAction::Stop => PAIR_MEDIA_ROUTE_STOP_COMMAND,
        ManifoldPairMediaRouteTerminationAction::Revoke => PAIR_MEDIA_ROUTE_REVOKE_COMMAND,
    };
    let target = state.routes.iter().find_map(|route| match route {
        ManifoldAcceptedPairMediaRouteV2::WifiDirect(value)
            if value.grant_id == request.grant_id =>
        {
            Some(value)
        }
        ManifoldAcceptedPairMediaRouteV2::WifiDirect(_)
        | ManifoldAcceptedPairMediaRouteV2::CommonLan(_) => None,
    });
    let rejection = (!pair_media_route_state_v2_is_well_formed(state))
        .then_some(ManifoldPairMediaRouteRejectionReason::InvalidAuthorityState)
        .or_else(|| {
            (state.applied_request_ids.contains(&request.request_id)
                || request.expected_authority_revision != prior)
                .then_some(ManifoldPairMediaRouteRejectionReason::StaleAuthorityRevision)
        })
        .or_else(|| {
            state
                .last_observed_at_ms
                .is_some_and(|last| now_ms < last)
                .then_some(ManifoldPairMediaRouteRejectionReason::ClockRegression)
        })
        .or_else(|| {
            (request.schema_id.as_str() != PAIR_MEDIA_ROUTE_TERMINATION_REQUEST_SCHEMA)
                .then_some(ManifoldPairMediaRouteRejectionReason::SchemaMismatch)
        })
        .or_else(|| {
            let params = pair_media_route_termination_params_digest(request).ok();
            validate_runtime(
                runtime,
                &request.runtime_command_request_id,
                expected_command,
                params.as_ref(),
                now_ms,
            )
            .err()
        })
        .or_else(|| {
            target
                .filter(|route| {
                    route.lifecycle_status == ManifoldPairMediaRouteLifecycleStatus::Current
                        && route.expires_at_ms > now_ms
                })
                .is_none()
                .then_some(ManifoldPairMediaRouteRejectionReason::RouteNotCurrent)
        })
        .or_else(|| {
            target.and_then(|route| {
                let authorized = match request.action {
                    ManifoldPairMediaRouteTerminationAction::Stop => {
                        runtime.command_request.requester_id == route.authority_client_id
                            && runtime.command_request.lease_id.as_ref()
                                == Some(&route.authority_runtime_lease_id)
                    }
                    ManifoldPairMediaRouteTerminationAction::Revoke => runtime
                        .trusted_media_revoker_ids
                        .contains(&runtime.command_request.requester_id),
                };
                (!authorized
                    || *runtime.authority_host_id != route.authority_host_id
                    || *runtime.live_authority_provider_epoch_id
                        != route.authority_provider_epoch_id)
                    .then_some(ManifoldPairMediaRouteRejectionReason::ClientNotAuthorized)
            })
        });
    if let Some(reason) = rejection {
        return (
            state.clone(),
            mutation_receipt(
                request.request_id.clone(),
                Some(reason),
                Vec::new(),
                prior,
                prior,
            ),
        );
    }
    let Some(resulting) = prior.next() else {
        return (
            state.clone(),
            mutation_receipt(
                request.request_id.clone(),
                Some(ManifoldPairMediaRouteRejectionReason::RevisionExhausted),
                Vec::new(),
                prior,
                prior,
            ),
        );
    };
    let mut next = state.clone();
    for route in &mut next.routes {
        if let ManifoldAcceptedPairMediaRouteV2::WifiDirect(value) = route {
            if value.grant_id == request.grant_id {
                value.lifecycle_status = match request.action {
                    ManifoldPairMediaRouteTerminationAction::Stop => {
                        ManifoldPairMediaRouteLifecycleStatus::Stopped
                    }
                    ManifoldPairMediaRouteTerminationAction::Revoke => {
                        ManifoldPairMediaRouteLifecycleStatus::Revoked
                    }
                };
                value.cleanup_status = ManifoldPairMediaRouteCleanupStatus::Pending;
                value.ended_at_ms = Some(now_ms);
                value.ended_by_id = Some(request.request_id.clone());
                value.termination_action = Some(request.action.clone());
                value.termination_runtime_binding = Some(runtime_binding(runtime));
            }
        }
    }
    next.authority_revision = resulting;
    next.last_observed_at_ms = Some(now_ms);
    next.applied_request_ids.push(request.request_id.clone());
    next.applied_request_ids.sort();
    (
        next,
        mutation_receipt(
            request.request_id.clone(),
            None,
            vec![request.grant_id.clone()],
            prior,
            resulting,
        ),
    )
}

/// Expires all due mixed routes in one bounded shared mutation.
pub fn expire_pair_media_routes_v2(
    state: &ManifoldPairMediaRouteAuthorityStateV2,
    sweep_id: DottedId,
    expected: Revision,
    now_ms: u64,
) -> Result<
    (
        ManifoldPairMediaRouteAuthorityStateV2,
        ManifoldPairMediaRouteMutationReceipt,
    ),
    ManifoldPairMediaRouteRejectionReason,
> {
    if !pair_media_route_state_v2_is_well_formed(state)
        || expected != state.authority_revision
        || state.applied_request_ids.contains(&sweep_id)
        || state.last_observed_at_ms.is_some_and(|last| now_ms < last)
    {
        return Err(ManifoldPairMediaRouteRejectionReason::InvalidAuthorityState);
    }
    let affected = state
        .routes
        .iter()
        .filter(|route| {
            *route.lifecycle_status() == ManifoldPairMediaRouteLifecycleStatus::Current
                && route.expires_at_ms() <= now_ms
        })
        .map(|route| route.grant_id().clone())
        .collect::<Vec<_>>();
    if affected.is_empty() {
        return Err(ManifoldPairMediaRouteRejectionReason::RouteNotCurrent);
    }
    let resulting = state
        .authority_revision
        .next()
        .ok_or(ManifoldPairMediaRouteRejectionReason::RevisionExhausted)?;
    let mut next = state.clone();
    for route in &mut next.routes {
        if affected.contains(route.grant_id()) {
            match route {
                ManifoldAcceptedPairMediaRouteV2::WifiDirect(v) => {
                    v.lifecycle_status = ManifoldPairMediaRouteLifecycleStatus::Expired;
                    v.cleanup_status = ManifoldPairMediaRouteCleanupStatus::Pending;
                    v.ended_at_ms = Some(now_ms);
                    v.ended_by_id = Some(sweep_id.clone());
                }
                ManifoldAcceptedPairMediaRouteV2::CommonLan(v) => {
                    v.lifecycle_status = ManifoldPairMediaRouteLifecycleStatus::Expired;
                    v.cleanup_status = ManifoldPairMediaRouteCleanupStatus::Pending;
                    v.ended_at_ms = Some(now_ms);
                    v.ended_by_id = Some(sweep_id.clone());
                }
            }
        }
    }
    next.authority_revision = resulting;
    next.last_observed_at_ms = Some(now_ms);
    next.applied_request_ids.push(sweep_id.clone());
    Ok((
        next,
        mutation_receipt(
            sweep_id,
            None,
            affected,
            state.authority_revision,
            resulting,
        ),
    ))
}

/// Terminalizes current routes whose accepted media source was revoked by a
/// trusted Broker convergence transaction. The Runtime Host must bind
/// `convergence_id` to its retained authenticated convergence receipt/audit.
pub fn revoke_pair_media_routes_for_media_sessions_v2(
    state: &ManifoldPairMediaRouteAuthorityStateV2,
    convergence_id: DottedId,
    expected_authority_revision: Revision,
    revoked_media_decision_ids: &[DottedId],
    now_ms: u64,
) -> Result<
    (
        ManifoldPairMediaRouteAuthorityStateV2,
        ManifoldPairMediaRouteMutationReceipt,
    ),
    ManifoldPairMediaRouteRejectionReason,
> {
    if !pair_media_route_state_v2_is_well_formed(state) {
        return Err(ManifoldPairMediaRouteRejectionReason::InvalidAuthorityState);
    }
    if expected_authority_revision != state.authority_revision {
        return Err(ManifoldPairMediaRouteRejectionReason::StaleAuthorityRevision);
    }
    if state.applied_request_ids.contains(&convergence_id) {
        return Err(ManifoldPairMediaRouteRejectionReason::ReplayedRequest);
    }
    if state.last_observed_at_ms.is_some_and(|last| now_ms < last) {
        return Err(ManifoldPairMediaRouteRejectionReason::ClockRegression);
    }
    let affected = state
        .routes
        .iter()
        .filter(|route| {
            *route.lifecycle_status() == ManifoldPairMediaRouteLifecycleStatus::Current
                && revoked_media_decision_ids.contains(route.media_session_decision_id())
        })
        .map(|route| route.grant_id().clone())
        .collect::<Vec<_>>();
    if affected.is_empty() {
        return Err(ManifoldPairMediaRouteRejectionReason::RouteNotCurrent);
    }
    let resulting = state
        .authority_revision
        .next()
        .ok_or(ManifoldPairMediaRouteRejectionReason::RevisionExhausted)?;
    let mut next = state.clone();
    for route in &mut next.routes {
        if affected.contains(route.grant_id()) {
            match route {
                ManifoldAcceptedPairMediaRouteV2::WifiDirect(value) => {
                    value.lifecycle_status = ManifoldPairMediaRouteLifecycleStatus::Revoked;
                    value.cleanup_status = ManifoldPairMediaRouteCleanupStatus::Pending;
                    value.ended_at_ms = Some(now_ms);
                    value.ended_by_id = Some(convergence_id.clone());
                    value.termination_action = None;
                    value.termination_runtime_binding = None;
                }
                ManifoldAcceptedPairMediaRouteV2::CommonLan(value) => {
                    value.lifecycle_status = ManifoldPairMediaRouteLifecycleStatus::Revoked;
                    value.cleanup_status = ManifoldPairMediaRouteCleanupStatus::Pending;
                    value.ended_at_ms = Some(now_ms);
                    value.ended_by_id = Some(convergence_id.clone());
                    value.termination_action = None;
                    value.termination_runtime_binding = None;
                }
            }
        }
    }
    next.authority_revision = resulting;
    next.last_observed_at_ms = Some(now_ms);
    next.applied_request_ids.push(convergence_id.clone());
    next.applied_request_ids.sort();
    Ok((
        next,
        mutation_receipt(
            convergence_id,
            None,
            affected,
            state.authority_revision,
            resulting,
        ),
    ))
}

/// Completes pending cleanup for either variant using a current client or a fresh trusted revoker.
pub fn complete_pair_media_route_cleanup_v2(
    state: &ManifoldPairMediaRouteAuthorityStateV2,
    request: &ManifoldPairMediaRouteCleanupCompletionRequestV2,
    runtime: ManifoldPairMediaRouteRuntimeContext<'_>,
    now_ms: u64,
) -> Result<
    (
        ManifoldPairMediaRouteAuthorityStateV2,
        ManifoldPairMediaRouteCleanupReceiptV2,
    ),
    ManifoldPairMediaRouteRejectionReason,
> {
    if !pair_media_route_state_v2_is_well_formed(state)
        || request.schema_id.as_str() != PAIR_MEDIA_ROUTE_CLEANUP_REQUEST_V2_SCHEMA
    {
        return Err(ManifoldPairMediaRouteRejectionReason::InvalidAuthorityState);
    }
    if request.expected_authority_revision != state.authority_revision
        || state.applied_request_ids.contains(&request.request_id)
    {
        return Err(ManifoldPairMediaRouteRejectionReason::StaleAuthorityRevision);
    }
    if state.last_observed_at_ms.is_some_and(|last| now_ms < last) {
        return Err(ManifoldPairMediaRouteRejectionReason::ClockRegression);
    }
    if !valid_sha256(&request.effect_receipt_sha256) {
        return Err(ManifoldPairMediaRouteRejectionReason::CleanupEvidenceInvalid);
    }
    let params = typed_digest(PAIR_MEDIA_ROUTE_CLEANUP_PARAMS_V2_TYPE, request)
        .map_err(|_| ManifoldPairMediaRouteRejectionReason::RuntimeCommandNotAccepted)?;
    validate_runtime(
        runtime,
        &request.runtime_command_request_id,
        PAIR_MEDIA_ROUTE_CLEANUP_COMMAND,
        Some(&params),
        now_ms,
    )?;
    let target = state
        .routes
        .iter()
        .find(|route| route.grant_id() == &request.grant_id)
        .ok_or(ManifoldPairMediaRouteRejectionReason::RouteNotCurrent)?;
    if *target.cleanup_status() != ManifoldPairMediaRouteCleanupStatus::Pending {
        return Err(ManifoldPairMediaRouteRejectionReason::CleanupNotPending);
    }
    if target.authority_provider_epoch_id() != &request.expected_authority_provider_epoch_id
        || target.platform_runtime_spec_id() != &request.expected_platform_runtime_spec_id
        || runtime.live_authority_provider_epoch_id != target.authority_provider_epoch_id()
        || runtime.authority_host_id != target.authority_host_id()
    {
        return Err(ManifoldPairMediaRouteRejectionReason::ClientNotAuthorized);
    }
    let requester_is_client = runtime.command_request.requester_id == *target.authority_client_id()
        && runtime.command_request.lease_id.as_ref() == Some(target.authority_runtime_lease_id());
    let requester_is_revoker = runtime
        .trusted_media_revoker_ids
        .contains(&runtime.command_request.requester_id);
    if !requester_is_client && !requester_is_revoker {
        return Err(ManifoldPairMediaRouteRejectionReason::ClientNotAuthorized);
    }
    let resulting = state
        .authority_revision
        .next()
        .ok_or(ManifoldPairMediaRouteRejectionReason::RevisionExhausted)?;
    let receipt = ManifoldPairMediaRouteCleanupReceipt {
        schema_id: schema(PAIR_MEDIA_ROUTE_CLEANUP_RECEIPT_V2_SCHEMA),
        receipt_id: derived(
            "receipt.peer.pair-media-route-cleanup-v2",
            &request.request_id,
        ),
        request_id: request.request_id.clone(),
        grant_id: request.grant_id.clone(),
        effect_receipt_id: request.effect_receipt_id.clone(),
        effect_receipt_sha256: request.effect_receipt_sha256.clone(),
        authority_host_id: runtime.authority_host_id.clone(),
        authority_provider_epoch_id: runtime.live_authority_provider_epoch_id.clone(),
        runtime_binding: runtime_binding(runtime),
        completed_at_ms: now_ms,
    };
    let tagged = match target {
        ManifoldAcceptedPairMediaRouteV2::WifiDirect(_) => {
            ManifoldPairMediaRouteCleanupReceiptV2::WifiDirect(receipt.clone())
        }
        ManifoldAcceptedPairMediaRouteV2::CommonLan(_) => {
            ManifoldPairMediaRouteCleanupReceiptV2::CommonLan(receipt.clone())
        }
    };
    let mut next = state.clone();
    for route in &mut next.routes {
        if route.grant_id() == &request.grant_id {
            match route {
                ManifoldAcceptedPairMediaRouteV2::WifiDirect(v) => {
                    v.cleanup_status = ManifoldPairMediaRouteCleanupStatus::Completed;
                    v.cleanup_receipt_id = Some(receipt.receipt_id.clone());
                }
                ManifoldAcceptedPairMediaRouteV2::CommonLan(v) => {
                    v.cleanup_status = ManifoldPairMediaRouteCleanupStatus::Completed;
                    v.cleanup_receipt_id = Some(receipt.receipt_id.clone());
                }
            }
        }
    }
    next.authority_revision = resulting;
    next.last_observed_at_ms = Some(now_ms);
    next.applied_request_ids.push(request.request_id.clone());
    next.applied_request_ids.sort();
    next.cleanup_receipts.push(tagged.clone());
    next.cleanup_receipts.sort_by(|left, right| {
        let left = match left {
            ManifoldPairMediaRouteCleanupReceiptV2::WifiDirect(v)
            | ManifoldPairMediaRouteCleanupReceiptV2::CommonLan(v) => &v.receipt_id,
        };
        let right = match right {
            ManifoldPairMediaRouteCleanupReceiptV2::WifiDirect(v)
            | ManifoldPairMediaRouteCleanupReceiptV2::CommonLan(v) => &v.receipt_id,
        };
        left.cmp(right)
    });
    Ok((next, tagged))
}

/// Applies an unchanged V1 Wi-Fi cleanup command to mixed durable state.
pub fn complete_pair_media_route_cleanup_v1_on_v2(
    state: &ManifoldPairMediaRouteAuthorityStateV2,
    request: &ManifoldPairMediaRouteCleanupCompletionRequest,
    runtime: ManifoldPairMediaRouteRuntimeContext<'_>,
    now_ms: u64,
) -> Result<
    (
        ManifoldPairMediaRouteAuthorityStateV2,
        ManifoldPairMediaRouteCleanupReceiptV2,
    ),
    ManifoldPairMediaRouteRejectionReason,
> {
    if !pair_media_route_state_v2_is_well_formed(state) {
        return Err(ManifoldPairMediaRouteRejectionReason::InvalidAuthorityState);
    }
    if state.applied_request_ids.contains(&request.request_id)
        || request.expected_authority_revision != state.authority_revision
    {
        return Err(ManifoldPairMediaRouteRejectionReason::StaleAuthorityRevision);
    }
    if state.last_observed_at_ms.is_some_and(|last| now_ms < last) {
        return Err(ManifoldPairMediaRouteRejectionReason::ClockRegression);
    }
    if request.schema_id.as_str() != PAIR_MEDIA_ROUTE_CLEANUP_REQUEST_SCHEMA {
        return Err(ManifoldPairMediaRouteRejectionReason::SchemaMismatch);
    }
    if state.cleanup_receipts.len() >= MAX_PAIR_MEDIA_ROUTE_RECORDS {
        return Err(ManifoldPairMediaRouteRejectionReason::CapacityExceeded);
    }
    if !valid_sha256(&request.effect_receipt_sha256) {
        return Err(ManifoldPairMediaRouteRejectionReason::CleanupEvidenceInvalid);
    }
    let params = pair_media_route_cleanup_params_digest(request)
        .map_err(|_| ManifoldPairMediaRouteRejectionReason::RuntimeCommandNotAccepted)?;
    validate_runtime(
        runtime,
        &request.runtime_command_request_id,
        PAIR_MEDIA_ROUTE_CLEANUP_COMMAND,
        Some(&params),
        now_ms,
    )?;
    let target = state
        .routes
        .iter()
        .find_map(|route| match route {
            ManifoldAcceptedPairMediaRouteV2::WifiDirect(value)
                if value.grant_id == request.grant_id =>
            {
                Some(value)
            }
            ManifoldAcceptedPairMediaRouteV2::WifiDirect(_)
            | ManifoldAcceptedPairMediaRouteV2::CommonLan(_) => None,
        })
        .ok_or(ManifoldPairMediaRouteRejectionReason::RouteNotCurrent)?;
    if target.cleanup_status != ManifoldPairMediaRouteCleanupStatus::Pending {
        return Err(ManifoldPairMediaRouteRejectionReason::CleanupNotPending);
    }
    let requester_is_client = runtime.command_request.requester_id == target.authority_client_id;
    let requester_is_revoker = runtime
        .trusted_media_revoker_ids
        .contains(&runtime.command_request.requester_id);
    if *runtime.authority_host_id != target.authority_host_id
        || (!requester_is_client && !requester_is_revoker)
        || (requester_is_client
            && runtime.command_request.lease_id.as_ref()
                != Some(&target.authority_runtime_lease_id))
        || *runtime.live_authority_provider_epoch_id != target.authority_provider_epoch_id
    {
        return Err(ManifoldPairMediaRouteRejectionReason::ClientNotAuthorized);
    }
    let resulting = state
        .authority_revision
        .next()
        .ok_or(ManifoldPairMediaRouteRejectionReason::RevisionExhausted)?;
    let receipt = ManifoldPairMediaRouteCleanupReceipt {
        schema_id: schema(PAIR_MEDIA_ROUTE_CLEANUP_RECEIPT_SCHEMA),
        receipt_id: derived("receipt.peer.pair-media-route-cleanup", &request.request_id),
        request_id: request.request_id.clone(),
        grant_id: request.grant_id.clone(),
        effect_receipt_id: request.effect_receipt_id.clone(),
        effect_receipt_sha256: request.effect_receipt_sha256.clone(),
        authority_host_id: runtime.authority_host_id.clone(),
        authority_provider_epoch_id: runtime.live_authority_provider_epoch_id.clone(),
        runtime_binding: runtime_binding(runtime),
        completed_at_ms: now_ms,
    };
    let mut next = state.clone();
    for route in &mut next.routes {
        if let ManifoldAcceptedPairMediaRouteV2::WifiDirect(value) = route {
            if value.grant_id == request.grant_id {
                value.cleanup_status = ManifoldPairMediaRouteCleanupStatus::Completed;
                value.cleanup_receipt_id = Some(receipt.receipt_id.clone());
            }
        }
    }
    next.authority_revision = resulting;
    next.last_observed_at_ms = Some(now_ms);
    next.applied_request_ids.push(request.request_id.clone());
    next.applied_request_ids.sort();
    next.cleanup_receipts
        .push(ManifoldPairMediaRouteCleanupReceiptV2::WifiDirect(
            receipt.clone(),
        ));
    next.cleanup_receipts.sort_by(|left, right| {
        let left = match left {
            ManifoldPairMediaRouteCleanupReceiptV2::WifiDirect(value)
            | ManifoldPairMediaRouteCleanupReceiptV2::CommonLan(value) => &value.receipt_id,
        };
        let right = match right {
            ManifoldPairMediaRouteCleanupReceiptV2::WifiDirect(value)
            | ManifoldPairMediaRouteCleanupReceiptV2::CommonLan(value) => &value.receipt_id,
        };
        left.cmp(right)
    });
    Ok((
        next,
        ManifoldPairMediaRouteCleanupReceiptV2::WifiDirect(receipt),
    ))
}

/// Validates durable legacy route state.
#[must_use]
pub fn pair_media_route_state_is_well_formed(state: &ManifoldPairMediaRouteState) -> bool {
    let Some(reserved_mutations) = pair_media_route_reserved_mutations(state) else {
        return false;
    };
    let records_are_closed = state.routes.iter().all(|route| {
        state.applied_request_ids.contains(&route.request_id)
            && route
                .ended_by_id
                .as_ref()
                .map_or(true, |id| state.applied_request_ids.contains(id))
            && state.last_observed_at_ms.is_some_and(|last| {
                route.valid_from_ms <= last && route.ended_at_ms.map_or(true, |ended| ended <= last)
            })
            && match &route.cleanup_receipt_id {
                Some(receipt_id) => state.cleanup_receipts.iter().any(|receipt| {
                    &receipt.receipt_id == receipt_id
                        && receipt.grant_id == route.grant_id
                        && receipt.authority_host_id == route.authority_host_id
                        && receipt.authority_provider_epoch_id == route.authority_provider_epoch_id
                        && route
                            .ended_at_ms
                            .is_some_and(|ended| receipt.completed_at_ms >= ended)
                }),
                None => true,
            }
    });
    let cleanup_is_closed = state.cleanup_receipts.iter().all(|receipt| {
        receipt.schema_id.as_str() == PAIR_MEDIA_ROUTE_CLEANUP_RECEIPT_SCHEMA
            && receipt.receipt_id
                == derived("receipt.peer.pair-media-route-cleanup", &receipt.request_id)
            && valid_sha256(&receipt.effect_receipt_sha256)
            && valid_runtime_binding(
                &receipt.runtime_binding,
                PAIR_MEDIA_ROUTE_CLEANUP_COMMAND,
                PAIR_MEDIA_ROUTE_CLEANUP_PARAMS_TYPE,
            )
            && state.applied_request_ids.contains(&receipt.request_id)
            && state
                .last_observed_at_ms
                .is_some_and(|last| receipt.completed_at_ms <= last)
            && state.routes.iter().any(|route| {
                route.grant_id == receipt.grant_id
                    && route.cleanup_status == ManifoldPairMediaRouteCleanupStatus::Completed
                    && route.cleanup_receipt_id.as_ref() == Some(&receipt.receipt_id)
            })
    });
    state.schema_id.as_str() == PAIR_MEDIA_ROUTE_STATE_SCHEMA
        && state.routes.len() <= MAX_PAIR_MEDIA_ROUTE_RECORDS
        && state.applied_request_ids.len() <= MAX_PAIR_MEDIA_ROUTE_REQUEST_IDS
        && state.cleanup_receipts.len() <= MAX_PAIR_MEDIA_ROUTE_RECORDS
        && state
            .routes
            .windows(2)
            .all(|p| p[0].grant_id < p[1].grant_id)
        && state.applied_request_ids.windows(2).all(|p| p[0] < p[1])
        && state
            .cleanup_receipts
            .windows(2)
            .all(|p| p[0].receipt_id < p[1].receipt_id)
        && state.routes.iter().all(valid_route_record)
        && state.routes.iter().enumerate().all(|(index, route)| {
            route.lifecycle_status != ManifoldPairMediaRouteLifecycleStatus::Current
                || !state.routes[index + 1..].iter().any(|candidate| {
                    candidate.lifecycle_status == ManifoldPairMediaRouteLifecycleStatus::Current
                        && candidate.route_leg.leg_id == route.route_leg.leg_id
                })
        })
        && records_are_closed
        && cleanup_is_closed
        && (state.applied_request_ids.is_empty() == state.last_observed_at_ms.is_none())
        && state
            .applied_request_ids
            .len()
            .checked_add(reserved_mutations)
            .is_some_and(|needed| needed <= MAX_PAIR_MEDIA_ROUTE_REQUEST_IDS)
        && u64::try_from(reserved_mutations).is_ok_and(|reserved| {
            state
                .authority_revision
                .get()
                .checked_add(reserved)
                .is_some()
        })
}

/// Returns the mutations still required to terminate and clean every route.
///
/// A current route reserves one terminal mutation plus one cleanup mutation;
/// a terminal route with pending cleanup reserves the cleanup mutation.
#[must_use]
pub fn pair_media_route_reserved_mutations(state: &ManifoldPairMediaRouteState) -> Option<usize> {
    let current = state
        .routes
        .iter()
        .filter(|route| route.lifecycle_status == ManifoldPairMediaRouteLifecycleStatus::Current)
        .count();
    let pending = state
        .routes
        .iter()
        .filter(|route| route.cleanup_status == ManifoldPairMediaRouteCleanupStatus::Pending)
        .count();
    current.checked_mul(2)?.checked_add(pending)
}

fn pair_media_route_reserved_mutations_v2(
    state: &ManifoldPairMediaRouteAuthorityStateV2,
) -> Option<usize> {
    let current = state
        .routes
        .iter()
        .filter(|route| *route.lifecycle_status() == ManifoldPairMediaRouteLifecycleStatus::Current)
        .count();
    let pending = state
        .routes
        .iter()
        .filter(|route| *route.cleanup_status() == ManifoldPairMediaRouteCleanupStatus::Pending)
        .count();
    current.checked_mul(2)?.checked_add(pending)
}

fn issue_preserves_terminal_capacity_v2(
    state: &ManifoldPairMediaRouteAuthorityStateV2,
    leg_id: &DottedId,
) -> bool {
    let superseded = usize::from(state.routes.iter().any(|route| {
        route.route_leg().leg_id == *leg_id
            && *route.lifecycle_status() == ManifoldPairMediaRouteLifecycleStatus::Current
    }));
    let Some(current) = state
        .routes
        .iter()
        .filter(|route| *route.lifecycle_status() == ManifoldPairMediaRouteLifecycleStatus::Current)
        .count()
        .checked_add(1)
        .and_then(|count| count.checked_sub(superseded))
    else {
        return false;
    };
    let Some(pending) = state
        .routes
        .iter()
        .filter(|route| *route.cleanup_status() == ManifoldPairMediaRouteCleanupStatus::Pending)
        .count()
        .checked_add(superseded)
    else {
        return false;
    };
    state
        .applied_request_ids
        .len()
        .checked_add(1)
        .and_then(|applied| {
            current
                .checked_mul(2)
                .and_then(|reserved| applied.checked_add(reserved))
        })
        .and_then(|needed| needed.checked_add(pending))
        .is_some_and(|needed| needed <= MAX_PAIR_MEDIA_ROUTE_REQUEST_IDS)
}

fn issue_preserves_revision_capacity_v2(
    state: &ManifoldPairMediaRouteAuthorityStateV2,
    leg_id: &DottedId,
) -> bool {
    let superseded = usize::from(state.routes.iter().any(|route| {
        route.route_leg().leg_id == *leg_id
            && *route.lifecycle_status() == ManifoldPairMediaRouteLifecycleStatus::Current
    }));
    let current = state
        .routes
        .iter()
        .filter(|route| *route.lifecycle_status() == ManifoldPairMediaRouteLifecycleStatus::Current)
        .count()
        + 1
        - superseded;
    let pending = state
        .routes
        .iter()
        .filter(|route| *route.cleanup_status() == ManifoldPairMediaRouteCleanupStatus::Pending)
        .count()
        + superseded;
    current
        .checked_mul(2)
        .and_then(|reserved| reserved.checked_add(pending))
        .and_then(|reserved| u64::try_from(reserved).ok())
        .and_then(|reserved| {
            state
                .authority_revision
                .get()
                .checked_add(1)?
                .checked_add(reserved)
        })
        .is_some()
}

fn issue_preserves_terminal_capacity(
    state: &ManifoldPairMediaRouteState,
    leg_id: &DottedId,
) -> bool {
    let superseded = usize::from(state.routes.iter().any(|route| {
        route.route_leg.leg_id == *leg_id
            && route.lifecycle_status == ManifoldPairMediaRouteLifecycleStatus::Current
    }));
    let Some(current) = state
        .routes
        .iter()
        .filter(|route| route.lifecycle_status == ManifoldPairMediaRouteLifecycleStatus::Current)
        .count()
        .checked_add(1)
        .and_then(|count| count.checked_sub(superseded))
    else {
        return false;
    };
    let Some(pending) = state
        .routes
        .iter()
        .filter(|route| route.cleanup_status == ManifoldPairMediaRouteCleanupStatus::Pending)
        .count()
        .checked_add(superseded)
    else {
        return false;
    };
    state
        .applied_request_ids
        .len()
        .checked_add(1)
        .and_then(|applied| {
            current
                .checked_mul(2)
                .and_then(|reserved| applied.checked_add(reserved))
        })
        .and_then(|needed| needed.checked_add(pending))
        .is_some_and(|needed| needed <= MAX_PAIR_MEDIA_ROUTE_REQUEST_IDS)
}

fn issue_preserves_revision_capacity(
    state: &ManifoldPairMediaRouteState,
    leg_id: &DottedId,
) -> bool {
    let superseded = usize::from(state.routes.iter().any(|route| {
        route.route_leg.leg_id == *leg_id
            && route.lifecycle_status == ManifoldPairMediaRouteLifecycleStatus::Current
    }));
    let current = state
        .routes
        .iter()
        .filter(|route| route.lifecycle_status == ManifoldPairMediaRouteLifecycleStatus::Current)
        .count()
        + 1
        - superseded;
    let pending = state
        .routes
        .iter()
        .filter(|route| route.cleanup_status == ManifoldPairMediaRouteCleanupStatus::Pending)
        .count()
        + superseded;
    current
        .checked_mul(2)
        .and_then(|reserved| reserved.checked_add(pending))
        .and_then(|reserved| u64::try_from(reserved).ok())
        .and_then(|reserved| {
            state
                .authority_revision
                .get()
                .checked_add(1)?
                .checked_add(reserved)
        })
        .is_some()
}

#[allow(clippy::too_many_lines)]
fn validate_issue<'a>(
    state: &ManifoldPairMediaRouteState,
    authority: ManifoldPairMediaRouteAuthorityContext<'a>,
    request: &ManifoldPairMediaRouteRequest,
    runtime: ManifoldPairMediaRouteRuntimeContext<'a>,
    now_ms: u64,
) -> Result<
    (
        crate::ManifoldPeerSessionCurrentReceipt,
        &'a crate::ManifoldAcceptedPeerSession,
        &'a rusty_manifold_media_session::ManifoldAcceptedMediaSession,
        &'a ManifoldSignedPeerTopologyAuthorization,
        &'a ManifoldMediaSessionClientGrant,
    ),
    ManifoldPairMediaRouteRejectionReason,
> {
    if request.schema_id.as_str() != PAIR_MEDIA_ROUTE_REQUEST_SCHEMA
        || request.route_leg.schema_id.as_str() != MANIFOLD_MEDIA_ROUTE_LEG_SCHEMA
    {
        return Err(ManifoldPairMediaRouteRejectionReason::SchemaMismatch);
    }
    if !pair_media_route_state_is_well_formed(state) {
        return Err(ManifoldPairMediaRouteRejectionReason::InvalidAuthorityState);
    }
    if state.applied_request_ids.contains(&request.request_id) {
        return Err(ManifoldPairMediaRouteRejectionReason::ReplayedRequest);
    }
    if request.expected_authority_revision != state.authority_revision {
        return Err(ManifoldPairMediaRouteRejectionReason::StaleAuthorityRevision);
    }
    if state.last_observed_at_ms.is_some_and(|last| now_ms < last) {
        return Err(ManifoldPairMediaRouteRejectionReason::ClockRegression);
    }
    if state.routes.len() >= MAX_PAIR_MEDIA_ROUTE_RECORDS
        || !issue_preserves_terminal_capacity(state, &request.route_leg.leg_id)
    {
        return Err(ManifoldPairMediaRouteRejectionReason::CapacityExceeded);
    }
    if request.route_leg.validate().is_err() {
        return Err(ManifoldPairMediaRouteRejectionReason::DirectionMismatch);
    }
    let peer_receipt = validate_current_peer_session(
        authority.accepted_peers,
        authority.enrollment,
        authority.rendezvous,
        authority.peer_sessions,
        authority.signed_topologies,
        &request.peer_session_id,
        now_ms,
    );
    if !peer_receipt.current {
        return Err(ManifoldPairMediaRouteRejectionReason::PeerSessionNotCurrent);
    }
    let peer = authority
        .peer_sessions
        .sessions
        .iter()
        .find(|session| session.proposal.session_id == request.peer_session_id && !session.revoked)
        .ok_or(ManifoldPairMediaRouteRejectionReason::PeerSessionNotCurrent)?;
    if request.expected_peer_session_authority_revision
        != authority.peer_sessions.authority_revision
    {
        return Err(ManifoldPairMediaRouteRejectionReason::StaleAuthorityRevision);
    }
    let topology = authority
        .signed_topologies
        .iter()
        .find(|t| {
            t.topology_authorization.session_id == request.peer_session_id
                && t.topology_authorization.decision_id == peer.decision_id
                && t.topology_authorization.authorized
        })
        .ok_or(ManifoldPairMediaRouteRejectionReason::PeerSessionNotCurrent)?;
    let pair = [
        &topology.topology_authorization.group_owner_peer_id,
        &topology.topology_authorization.client_peer_id,
    ];
    if !pair.contains(&&request.route_leg.source_peer_id)
        || !pair.contains(&&request.route_leg.sink_peer_id)
    {
        return Err(ManifoldPairMediaRouteRejectionReason::DirectionMismatch);
    }
    if request.expected_media_acceptance_authority_revision
        != authority.media_sessions.authority_revision
    {
        return Err(ManifoldPairMediaRouteRejectionReason::StaleAuthorityRevision);
    }
    let media = authority
        .media_sessions
        .sessions
        .iter()
        .find(|m| {
            m.decision_id == request.media_session_decision_id
                && m.lifecycle_status == ManifoldMediaSessionLifecycleStatus::Current
                && m.expires_at_ms > now_ms
        })
        .ok_or(ManifoldPairMediaRouteRejectionReason::MediaSessionNotCurrent)?;
    let descriptor = &media.product_binding.descriptor;
    if !descriptor.source_ids.contains(&request.route_leg.source_id)
        || !descriptor.route_ids.contains(&request.route_leg.route_id)
        || !descriptor.sink_ids.contains(&request.route_leg.sink_id)
        || request
            .route_leg
            .processor_ids
            .iter()
            .any(|id| !descriptor.processor_ids.contains(id))
        || request
            .route_leg
            .stream_ids
            .iter()
            .any(|id| !descriptor.stream_ids.contains(id))
    {
        return Err(ManifoldPairMediaRouteRejectionReason::ResourceMismatch);
    }
    if state.routes.iter().any(|route| {
        route.route_leg.leg_id == request.route_leg.leg_id
            && (route.route_leg.source_peer_id != request.route_leg.source_peer_id
                || route.route_leg.sink_peer_id != request.route_leg.sink_peer_id
                || route.authority_client_id != runtime.command_request.requester_id)
    }) {
        return Err(ManifoldPairMediaRouteRejectionReason::DirectionMismatch);
    }
    if state.routes.iter().any(|r| {
        r.route_leg.leg_id == request.route_leg.leg_id
            && r.route_leg.leg_revision >= request.route_leg.leg_revision
    }) {
        return Err(ManifoldPairMediaRouteRejectionReason::StaleLegRevision);
    }
    if !route_lifetime_is_bounded(request.expires_at_ms, now_ms, MAX_PAIR_MEDIA_ROUTE_TTL_MS)
        || request.expires_at_ms > peer.proposal.expires_at_ms
        || request.expires_at_ms > media.expires_at_ms
        || request.expires_at_ms > request.expected_runtime_lease_expires_at_ms
    {
        return Err(ManifoldPairMediaRouteRejectionReason::InvalidExpiry);
    }
    if !issue_preserves_revision_capacity(state, &request.route_leg.leg_id) {
        return Err(ManifoldPairMediaRouteRejectionReason::RevisionExhausted);
    }
    let params = pair_media_route_issue_params_digest(request)
        .map_err(|_| ManifoldPairMediaRouteRejectionReason::RuntimeCommandNotAccepted)?;
    validate_runtime(
        runtime,
        &request.runtime_command_request_id,
        PAIR_MEDIA_ROUTE_ISSUE_COMMAND,
        Some(&params),
        now_ms,
    )?;
    if media.runtime_authority_host_id != *runtime.authority_host_id
        || media.provider_epoch_id != *runtime.live_authority_provider_epoch_id
        || media.runtime_client_id != runtime.command_request.requester_id
    {
        return Err(ManifoldPairMediaRouteRejectionReason::ClientNotAuthorized);
    }
    let lease = runtime
        .command_request
        .lease_id
        .as_ref()
        .ok_or(ManifoldPairMediaRouteRejectionReason::RuntimeCommandNotAccepted)?;
    let runtime_lease = runtime
        .runtime_lease
        .filter(|runtime_lease| {
            runtime_lease.lease_id == *lease
                && runtime_lease.holder_id == runtime.command_request.requester_id
                && runtime_lease.expires_at_ms > now_ms
        })
        .ok_or(ManifoldPairMediaRouteRejectionReason::RuntimeCommandNotAccepted)?;
    if &media.runtime_lease_id != lease
        || request.expected_runtime_lease_expires_at_ms != runtime_lease.expires_at_ms
    {
        return Err(ManifoldPairMediaRouteRejectionReason::ClientNotAuthorized);
    }
    let mut resources = descriptor
        .source_ids
        .iter()
        .chain(&descriptor.processor_ids)
        .chain(&descriptor.route_ids)
        .chain(&descriptor.sink_ids)
        .chain(&descriptor.stream_ids)
        .cloned()
        .collect::<Vec<_>>();
    resources.sort();
    let grant = runtime
        .media_client_grants
        .iter()
        .find(|g| {
            g.runtime_host_id == *runtime.authority_host_id
                && g.client_id == runtime.command_request.requester_id
                && g.lease_id == *lease
                && g.product_id == media.product_id
                && g.feature_lock_id == media.feature_lock_id
                && g.feature_lock_fingerprint == media.feature_lock_fingerprint
                && g.capability_id == media.capability_id
                && g.admission_grant_id == media.admission_grant_id
                && g.allowed_session_id == media.session_id
                && g.allowed_platform_runtime_spec_id == media.platform_runtime_spec_id
                && g.allowed_descriptor_canonical_sha256
                    .contains(&media.product_descriptor_canonical_sha256)
                && g.allowed_resource_ids == resources
        })
        .ok_or(ManifoldPairMediaRouteRejectionReason::ClientNotAuthorized)?;
    Ok((peer_receipt, peer, media, topology, grant))
}

fn common_mutation_rejection(
    state: &ManifoldPairMediaRouteState,
    expected: Revision,
    id: &DottedId,
    now_ms: u64,
) -> Option<ManifoldPairMediaRouteRejectionReason> {
    if !pair_media_route_state_is_well_formed(state) {
        Some(ManifoldPairMediaRouteRejectionReason::InvalidAuthorityState)
    } else if state.applied_request_ids.contains(id) {
        Some(ManifoldPairMediaRouteRejectionReason::ReplayedRequest)
    } else if expected != state.authority_revision {
        Some(ManifoldPairMediaRouteRejectionReason::StaleAuthorityRevision)
    } else if state.last_observed_at_ms.is_some_and(|last| now_ms < last) {
        Some(ManifoldPairMediaRouteRejectionReason::ClockRegression)
    } else if state.applied_request_ids.len() >= MAX_PAIR_MEDIA_ROUTE_REQUEST_IDS {
        Some(ManifoldPairMediaRouteRejectionReason::CapacityExceeded)
    } else {
        None
    }
}
fn validate_runtime(
    runtime: ManifoldPairMediaRouteRuntimeContext<'_>,
    request_id: &DottedId,
    command: &str,
    params: Option<&ManifoldRuntimeTypedParamsDigest>,
    now_ms: u64,
) -> Result<(), ManifoldPairMediaRouteRejectionReason> {
    let c = runtime.command_request;
    let d = runtime.dispatch;
    let a = runtime.application;
    if c.schema_id.as_str() != HOST_COMMAND_REQUEST_SCHEMA
        || c.request_id != *request_id
        || c.command_id.as_str() != command
        || c.lease_id.is_none()
        || !c
            .lease_id
            .as_ref()
            .zip(runtime.runtime_lease)
            .is_some_and(|(lease_id, lease)| {
                *lease_id == lease.lease_id
                    && c.requester_id == lease.holder_id
                    && lease.scope == *runtime.required_runtime_lease_scope_id
                    && lease.expires_at_ms > now_ms
            })
        || c.params_digest.as_ref() != params
        || d.schema_id.as_str() != HOST_DISPATCH_RECEIPT_SCHEMA
        || d.authority_host_id != *runtime.authority_host_id
        || d.request_id != c.request_id
        || d.command_id != c.command_id
        || d.params_digest != c.params_digest
        || d.outcome != ManifoldRuntimeDispatchOutcome::Ready
        || d.rejection_reason.is_some()
        || a.schema_id.as_str() != HOST_APPLICATION_RECEIPT_SCHEMA
        || a.authority_host_id != *runtime.authority_host_id
        || a.dispatch_id != d.dispatch_id
        || a.request_id != c.request_id
        || a.params_digest != c.params_digest
        || !a.applied
        || a.rejection_reason.is_some()
    {
        Err(ManifoldPairMediaRouteRejectionReason::RuntimeCommandNotAccepted)
    } else {
        Ok(())
    }
}
fn runtime_binding(
    runtime: ManifoldPairMediaRouteRuntimeContext<'_>,
) -> ManifoldPairMediaRouteRuntimeMutationBinding {
    ManifoldPairMediaRouteRuntimeMutationBinding {
        command_id: runtime.command_request.command_id.clone(),
        requester_id: runtime.command_request.requester_id.clone(),
        lease_id: runtime
            .command_request
            .lease_id
            .clone()
            .expect("validated pair mutation has a lease"),
        lease_scope_id: runtime
            .runtime_lease
            .expect("accepted Runtime Host command has a retained lease")
            .scope
            .clone(),
        runtime_lease: runtime
            .runtime_lease
            .expect("accepted Runtime Host command has a retained lease")
            .clone(),
        request_id: runtime.command_request.request_id.clone(),
        params_digest: runtime
            .command_request
            .params_digest
            .clone()
            .expect("validated pair mutation has typed parameters"),
        resulting_authority_revision: runtime.application.resulting_authority_revision,
    }
}
fn valid_runtime_binding(
    binding: &ManifoldPairMediaRouteRuntimeMutationBinding,
    expected_command: &str,
    expected_params_type: &str,
) -> bool {
    binding.command_id.as_str() == expected_command
        && binding.runtime_lease.lease_id == binding.lease_id
        && binding.runtime_lease.holder_id == binding.requester_id
        && binding.runtime_lease.scope == binding.lease_scope_id
        && binding.runtime_lease.derivative_binding.is_none()
        && binding.params_digest.schema_id.as_str() == HOST_TYPED_PARAMS_DIGEST_SCHEMA
        && binding.params_digest.params_type_id.as_str() == expected_params_type
        && valid_sha256(&binding.params_digest.canonical_sha256)
}
fn valid_route_record(r: &ManifoldAcceptedPairMediaRoute) -> bool {
    let terminal = r.lifecycle_status != ManifoldPairMediaRouteLifecycleStatus::Current;
    let cleanup = match r.cleanup_status {
        ManifoldPairMediaRouteCleanupStatus::NotRequired => {
            !terminal && r.cleanup_receipt_id.is_none()
        }
        ManifoldPairMediaRouteCleanupStatus::Pending => terminal && r.cleanup_receipt_id.is_none(),
        ManifoldPairMediaRouteCleanupStatus::Completed => {
            terminal && r.cleanup_receipt_id.is_some()
        }
    };
    let termination_binding = match r.lifecycle_status {
        ManifoldPairMediaRouteLifecycleStatus::Stopped => r
            .termination_action
            .as_ref()
            .zip(r.termination_runtime_binding.as_ref())
            .is_some_and(|(action, binding)| {
                *action == ManifoldPairMediaRouteTerminationAction::Stop
                    && valid_runtime_binding(
                        binding,
                        PAIR_MEDIA_ROUTE_STOP_COMMAND,
                        PAIR_MEDIA_ROUTE_TERMINATION_PARAMS_TYPE,
                    )
            }),
        ManifoldPairMediaRouteLifecycleStatus::Revoked => r
            .termination_action
            .as_ref()
            .zip(r.termination_runtime_binding.as_ref())
            .is_some_and(|(action, binding)| {
                *action == ManifoldPairMediaRouteTerminationAction::Revoke
                    && valid_runtime_binding(
                        binding,
                        PAIR_MEDIA_ROUTE_REVOKE_COMMAND,
                        PAIR_MEDIA_ROUTE_TERMINATION_PARAMS_TYPE,
                    )
            }),
        ManifoldPairMediaRouteLifecycleStatus::Current
        | ManifoldPairMediaRouteLifecycleStatus::Expired
        | ManifoldPairMediaRouteLifecycleStatus::Superseded => {
            r.termination_action.is_none() && r.termination_runtime_binding.is_none()
        }
    };
    r.schema_id.as_str() == PAIR_MEDIA_ROUTE_RECORD_SCHEMA
        && r.grant_id == derived("grant.peer.pair-media-route", &r.request_id)
        && r.route_leg.validate().is_ok()
        && r.source_topology_role != r.sink_topology_role
        && valid_sha256(&r.media_descriptor_canonical_sha256)
        && valid_sha256(&r.feature_lock_fingerprint)
        && r.runtime_params_digest.schema_id.as_str() == HOST_TYPED_PARAMS_DIGEST_SCHEMA
        && r.runtime_params_digest.params_type_id.as_str() == PAIR_MEDIA_ROUTE_ISSUE_PARAMS_TYPE
        && r.runtime_command_id.as_str() == PAIR_MEDIA_ROUTE_ISSUE_COMMAND
        && valid_sha256(&r.runtime_params_digest.canonical_sha256)
        && r.valid_from_ms < r.expires_at_ms
        && r.ended_at_ms.map_or(true, |ended| ended >= r.valid_from_ms)
        && r.expires_at_ms <= r.authority_runtime_lease_expires_at_ms
        && cleanup
        && termination_binding
        && (terminal == (r.ended_at_ms.is_some() && r.ended_by_id.is_some()))
}

fn valid_wifi_route_record_v2(route: &ManifoldAcceptedPairMediaRoute) -> bool {
    if valid_route_record(route) {
        return true;
    }
    if matches!(
        route.lifecycle_status,
        ManifoldPairMediaRouteLifecycleStatus::Stopped
            | ManifoldPairMediaRouteLifecycleStatus::Revoked
    ) && route
        .termination_runtime_binding
        .as_ref()
        .is_some_and(|binding| {
            let command = match route.lifecycle_status {
                ManifoldPairMediaRouteLifecycleStatus::Stopped => PAIR_MEDIA_ROUTE_STOP_COMMAND,
                ManifoldPairMediaRouteLifecycleStatus::Revoked => PAIR_MEDIA_ROUTE_REVOKE_COMMAND,
                ManifoldPairMediaRouteLifecycleStatus::Current
                | ManifoldPairMediaRouteLifecycleStatus::Expired
                | ManifoldPairMediaRouteLifecycleStatus::Superseded => return false,
            };
            valid_runtime_binding(
                binding,
                command,
                PAIR_MEDIA_ROUTE_TERMINATION_PARAMS_V2_TYPE,
            )
        })
    {
        let mut normalized = route.clone();
        normalized
            .termination_runtime_binding
            .as_mut()
            .expect("checked terminal binding")
            .params_digest
            .params_type_id = id(PAIR_MEDIA_ROUTE_TERMINATION_PARAMS_TYPE);
        return valid_route_record(&normalized);
    }
    if route.lifecycle_status != ManifoldPairMediaRouteLifecycleStatus::Revoked
        || route.termination_action.is_some()
        || route.termination_runtime_binding.is_some()
    {
        return false;
    }
    let mut source_revoked = route.clone();
    source_revoked.lifecycle_status = ManifoldPairMediaRouteLifecycleStatus::Expired;
    valid_route_record(&source_revoked)
}

fn valid_common_lan_route_record(r: &ManifoldAcceptedCommonLanPairMediaRoute) -> bool {
    let terminal = r.lifecycle_status != ManifoldPairMediaRouteLifecycleStatus::Current;
    let cleanup = match r.cleanup_status {
        ManifoldPairMediaRouteCleanupStatus::NotRequired => {
            !terminal && r.cleanup_receipt_id.is_none()
        }
        ManifoldPairMediaRouteCleanupStatus::Pending => terminal && r.cleanup_receipt_id.is_none(),
        ManifoldPairMediaRouteCleanupStatus::Completed => {
            terminal && r.cleanup_receipt_id.is_some()
        }
    };
    let termination_binding = match r.lifecycle_status {
        ManifoldPairMediaRouteLifecycleStatus::Stopped => r
            .termination_action
            .as_ref()
            .zip(r.termination_runtime_binding.as_ref())
            .is_some_and(|(action, binding)| {
                *action == ManifoldPairMediaRouteTerminationAction::Stop
                    && valid_runtime_binding(
                        binding,
                        PAIR_MEDIA_ROUTE_STOP_COMMAND,
                        PAIR_MEDIA_ROUTE_TERMINATION_PARAMS_V2_TYPE,
                    )
            }),
        ManifoldPairMediaRouteLifecycleStatus::Revoked => {
            (r.termination_action.is_none() && r.termination_runtime_binding.is_none())
                || r.termination_action
                    .as_ref()
                    .zip(r.termination_runtime_binding.as_ref())
                    .is_some_and(|(action, binding)| {
                        *action == ManifoldPairMediaRouteTerminationAction::Revoke
                            && valid_runtime_binding(
                                binding,
                                PAIR_MEDIA_ROUTE_REVOKE_COMMAND,
                                PAIR_MEDIA_ROUTE_TERMINATION_PARAMS_V2_TYPE,
                            )
                    })
        }
        ManifoldPairMediaRouteLifecycleStatus::Current
        | ManifoldPairMediaRouteLifecycleStatus::Expired
        | ManifoldPairMediaRouteLifecycleStatus::Superseded => {
            r.termination_action.is_none() && r.termination_runtime_binding.is_none()
        }
    };
    r.schema_id.as_str() == PAIR_MEDIA_ROUTE_RECORD_V2_SCHEMA
        && r.grant_id == derived("grant.peer.common-lan-pair-media-route", &r.request_id)
        && r.route_leg.validate().is_ok()
        && r.transport == r.signed_topology_evidence.transport
        && r.peer_session_id == r.signed_topology_evidence.session_id
        && r.peer_session_decision_id == r.signed_topology_evidence.decision_id
        && r.peer_session_authority_revision == r.signed_topology_evidence.authority_revision
        && r.reciprocal_receipt_id == r.signed_topology_evidence.reciprocal_receipt_id
        && r.reciprocal_authority_revision
            == r.signed_topology_evidence.reciprocal_authority_revision
        && r.enrollment_authority_revision
            == r.signed_topology_evidence.enrollment_authority_revision
        && r.signed_topology_evidence.authorized
        && valid_sha256(&r.media_descriptor_canonical_sha256)
        && valid_sha256(&r.feature_lock_fingerprint)
        && r.runtime_params_digest.schema_id.as_str() == HOST_TYPED_PARAMS_DIGEST_SCHEMA
        && r.runtime_params_digest.params_type_id.as_str() == PAIR_MEDIA_ROUTE_ISSUE_PARAMS_V2_TYPE
        && r.runtime_command_id.as_str() == PAIR_MEDIA_ROUTE_ISSUE_COMMAND
        && valid_sha256(&r.runtime_params_digest.canonical_sha256)
        && r.valid_from_ms >= r.signed_topology_evidence.valid_from_ms
        && r.valid_from_ms < r.expires_at_ms
        && r.expires_at_ms <= r.signed_topology_evidence.expires_at_ms
        && r.expires_at_ms <= r.authority_runtime_lease_expires_at_ms
        && r.ended_at_ms.map_or(true, |ended| ended >= r.valid_from_ms)
        && cleanup
        && termination_binding
        && (terminal == (r.ended_at_ms.is_some() && r.ended_by_id.is_some()))
}

fn id(value: &str) -> DottedId {
    DottedId::new(value).expect("static dotted id")
}
fn valid_sha256(v: &str) -> bool {
    v.len() == 71
        && v.starts_with("sha256:")
        && v[7..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
/// Computes the typed Runtime Host parameter digest for route issue.
///
/// # Errors
///
/// Returns an error when canonical request serialization fails.
pub fn pair_media_route_issue_params_digest(
    r: &ManifoldPairMediaRouteRequest,
) -> Result<ManifoldRuntimeTypedParamsDigest, serde_json::Error> {
    typed_digest(PAIR_MEDIA_ROUTE_ISSUE_PARAMS_TYPE, r)
}
/// Computes the typed Runtime Host parameter digest for a common-LAN route issue.
pub fn pair_media_route_issue_params_digest_v2(
    request: &ManifoldCommonLanPairMediaRouteRequest,
) -> Result<ManifoldRuntimeTypedParamsDigest, serde_json::Error> {
    typed_digest(PAIR_MEDIA_ROUTE_ISSUE_PARAMS_V2_TYPE, request)
}
/// Computes the typed Runtime Host parameter digest for route termination.
///
/// # Errors
///
/// Returns an error when canonical request serialization fails.
pub fn pair_media_route_termination_params_digest(
    r: &ManifoldPairMediaRouteTerminationRequest,
) -> Result<ManifoldRuntimeTypedParamsDigest, serde_json::Error> {
    typed_digest(PAIR_MEDIA_ROUTE_TERMINATION_PARAMS_TYPE, r)
}
/// Computes the typed Runtime Host parameter digest for mixed route termination.
pub fn pair_media_route_termination_params_digest_v2(
    request: &ManifoldPairMediaRouteTerminationRequestV2,
) -> Result<ManifoldRuntimeTypedParamsDigest, serde_json::Error> {
    typed_digest(PAIR_MEDIA_ROUTE_TERMINATION_PARAMS_V2_TYPE, request)
}
/// Computes the typed Runtime Host parameter digest for cleanup completion.
///
/// # Errors
///
/// Returns an error when canonical request serialization fails.
pub fn pair_media_route_cleanup_params_digest(
    r: &ManifoldPairMediaRouteCleanupCompletionRequest,
) -> Result<ManifoldRuntimeTypedParamsDigest, serde_json::Error> {
    typed_digest(PAIR_MEDIA_ROUTE_CLEANUP_PARAMS_TYPE, r)
}
/// Computes the typed Runtime Host parameter digest for mixed route cleanup.
pub fn pair_media_route_cleanup_params_digest_v2(
    request: &ManifoldPairMediaRouteCleanupCompletionRequestV2,
) -> Result<ManifoldRuntimeTypedParamsDigest, serde_json::Error> {
    typed_digest(PAIR_MEDIA_ROUTE_CLEANUP_PARAMS_V2_TYPE, request)
}
fn typed_digest<T: Serialize>(
    kind: &str,
    value: &T,
) -> Result<ManifoldRuntimeTypedParamsDigest, serde_json::Error> {
    let bytes = serde_json::to_vec(value)?;
    Ok(ManifoldRuntimeTypedParamsDigest {
        schema_id: schema(HOST_TYPED_PARAMS_DIGEST_SCHEMA),
        params_type_id: DottedId::new(kind).expect("static params id"),
        canonical_sha256: format!("sha256:{}", hex(&Sha256::digest(&bytes))),
        canonical_size_bytes: u32::try_from(bytes.len()).unwrap_or(u32::MAX),
    })
}
fn route_receipt(
    r: &ManifoldPairMediaRouteRequest,
    reason: Option<ManifoldPairMediaRouteRejectionReason>,
    accepted: Option<ManifoldAcceptedPairMediaRoute>,
    prior: Revision,
    resulting: Revision,
) -> ManifoldPairMediaRouteReceipt {
    ManifoldPairMediaRouteReceipt {
        schema_id: schema(PAIR_MEDIA_ROUTE_RECEIPT_SCHEMA),
        request_id: r.request_id.clone(),
        accepted: reason.is_none(),
        rejection_reason: reason,
        accepted_route: accepted,
        prior_authority_revision: prior,
        resulting_authority_revision: resulting,
    }
}
fn mutation_receipt(
    id: DottedId,
    reason: Option<ManifoldPairMediaRouteRejectionReason>,
    affected: Vec<DottedId>,
    prior: Revision,
    resulting: Revision,
) -> ManifoldPairMediaRouteMutationReceipt {
    ManifoldPairMediaRouteMutationReceipt {
        schema_id: schema(PAIR_MEDIA_ROUTE_MUTATION_RECEIPT_SCHEMA),
        source_id: id,
        applied: reason.is_none(),
        rejection_reason: reason,
        affected_grant_ids: affected,
        prior_authority_revision: prior,
        resulting_authority_revision: resulting,
    }
}
fn schema(v: &str) -> SchemaId {
    SchemaId::new(v).expect("static schema")
}
fn derived(prefix: &str, id: &DottedId) -> DottedId {
    DottedId::new(format!("{prefix}.{}", id.as_str())).expect("derived id")
}
fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from(H[usize::from(b >> 4)]));
        s.push(char::from(H[usize::from(b & 15)]));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_lan_route_window_is_bounded_without_extending_wifi_direct() {
        let issued_at_ms = 10_000;
        assert!(route_lifetime_is_bounded(
            issued_at_ms + MAX_COMMON_LAN_PAIR_MEDIA_ROUTE_TTL_MS,
            issued_at_ms,
            MAX_COMMON_LAN_PAIR_MEDIA_ROUTE_TTL_MS,
        ));
        assert!(!route_lifetime_is_bounded(
            issued_at_ms + MAX_COMMON_LAN_PAIR_MEDIA_ROUTE_TTL_MS + 1,
            issued_at_ms,
            MAX_COMMON_LAN_PAIR_MEDIA_ROUTE_TTL_MS,
        ));
        assert!(!route_lifetime_is_bounded(
            issued_at_ms,
            issued_at_ms,
            MAX_COMMON_LAN_PAIR_MEDIA_ROUTE_TTL_MS,
        ));
        assert!(route_lifetime_is_bounded(
            issued_at_ms + MAX_PAIR_MEDIA_ROUTE_TTL_MS,
            issued_at_ms,
            MAX_PAIR_MEDIA_ROUTE_TTL_MS,
        ));
        assert!(!route_lifetime_is_bounded(
            issued_at_ms + MAX_PAIR_MEDIA_ROUTE_TTL_MS + 1,
            issued_at_ms,
            MAX_PAIR_MEDIA_ROUTE_TTL_MS,
        ));
    }

    fn id(value: &str) -> DottedId {
        DottedId::new(value).expect("test id")
    }

    #[test]
    fn runtime_review_rejects_missing_or_mismatched_borrowed_lease() {
        let host_id = id("host.runtime.test");
        let epoch_id = id("epoch.runtime.test");
        let scope_id = id("scope.media.test");
        let request_id = id("request.runtime.test");
        let params = ManifoldRuntimeTypedParamsDigest {
            schema_id: schema(HOST_TYPED_PARAMS_DIGEST_SCHEMA),
            params_type_id: id(PAIR_MEDIA_ROUTE_CLEANUP_PARAMS_TYPE),
            canonical_sha256: format!("sha256:{}", "12".repeat(32)),
            canonical_size_bytes: 12,
        };
        let command = ManifoldRuntimeCommandRequest {
            schema_id: schema(HOST_COMMAND_REQUEST_SCHEMA),
            request_id: request_id.clone(),
            expected_authority_revision: Revision::INITIAL,
            requester_id: id("client.media.test"),
            command_id: id(PAIR_MEDIA_ROUTE_CLEANUP_COMMAND),
            lease_id: Some(id("lease.media.test")),
            params_digest: Some(params.clone()),
            issued_at_ms: 10,
            expires_at_ms: 20,
        };
        let dispatch = ManifoldRuntimeDispatchReceipt {
            schema_id: schema(HOST_DISPATCH_RECEIPT_SCHEMA),
            authority_host_id: host_id.clone(),
            dispatch_id: derived("dispatch.runtime", &request_id),
            request_id: request_id.clone(),
            command_id: command.command_id.clone(),
            params_digest: Some(params.clone()),
            reviewed_authority_revision: Revision::INITIAL,
            outcome: ManifoldRuntimeDispatchOutcome::Ready,
            rejection_reason: None,
        };
        let application = ManifoldRuntimeApplicationReceipt {
            schema_id: schema(HOST_APPLICATION_RECEIPT_SCHEMA),
            authority_host_id: host_id.clone(),
            receipt_id: derived("receipt.runtime", &request_id),
            dispatch_id: dispatch.dispatch_id.clone(),
            request_id: request_id.clone(),
            params_digest: Some(params.clone()),
            applied: true,
            prior_authority_revision: Revision::INITIAL,
            resulting_authority_revision: Revision::new(1).expect("revision"),
            rejection_reason: None,
        };
        let context = |runtime_lease| ManifoldPairMediaRouteRuntimeContext {
            authority_host_id: &host_id,
            live_authority_provider_epoch_id: &epoch_id,
            media_client_grants: &[],
            trusted_media_revoker_ids: &[],
            command_request: &command,
            runtime_lease,
            required_runtime_lease_scope_id: &scope_id,
            dispatch: &dispatch,
            application: &application,
        };
        assert_eq!(
            validate_runtime(
                context(None),
                &request_id,
                PAIR_MEDIA_ROUTE_CLEANUP_COMMAND,
                Some(&params),
                10,
            ),
            Err(ManifoldPairMediaRouteRejectionReason::RuntimeCommandNotAccepted)
        );
        let wrong = ManifoldRuntimeLease {
            lease_id: id("lease.media.wrong"),
            scope: scope_id.clone(),
            holder_id: command.requester_id.clone(),
            expires_at_ms: 20,
            derivative_binding: None,
        };
        assert_eq!(
            validate_runtime(
                context(Some(&wrong)),
                &request_id,
                PAIR_MEDIA_ROUTE_CLEANUP_COMMAND,
                Some(&params),
                10,
            ),
            Err(ManifoldPairMediaRouteRejectionReason::RuntimeCommandNotAccepted)
        );
    }
}
