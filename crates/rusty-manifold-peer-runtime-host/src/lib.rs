//! Compile-time-selected source-only Runtime Host extension for peer authority.
//!
//! `rusty-manifold-peer` remains the pure decision layer. This crate owns the
//! durable composition, current-state routing, restart snapshot, and unified
//! audit sequence. It deliberately contains no sockets, platform APIs,
//! sidecars, codecs, or media payloads.

use std::collections::BTreeSet;
use std::fmt;

use rusty_manifold_broker_adapter::{
    packaged_product_lock_sha256, ManifoldBrokerAdapterMode, ManifoldBrokerAdapterRole,
    ManifoldBrokerControlLeaseLifecycleOperationKind, ManifoldBrokerControlLeaseLifecycleOutcome,
    ManifoldBrokerControlLeaseLifecycleReceipt, ManifoldBrokerControlLeaseRevocationBarrierState,
    ManifoldBrokerControlLeaseRevocationConsumerAcknowledgement,
    ManifoldBrokerControlLeaseRevocationConsumerKind,
    ManifoldBrokerControlLeaseTransitionApplication, ManifoldBrokerMutationReceipt,
    ManifoldBrokerMutationRequest, ManifoldBrokerRuntime,
    ManifoldBrokerRuntimeEpochRolloverReceipt, ManifoldBrokerRuntimeEvidence,
    ManifoldBrokerRuntimeStateError, BROKER_ADAPTER_RECEIPT_SCHEMA, BROKER_BOUNDED_USE_SCHEMA,
    BROKER_CONTROL_LEASE_REVOCATION_CONSUMER_ACKNOWLEDGEMENT_SCHEMA,
    BROKER_MUTATION_RECEIPT_SCHEMA, BROKER_MUTATION_REQUEST_SCHEMA,
    BROKER_RUNTIME_EPOCH_ROLLOVER_RECEIPT_SCHEMA, BROKER_RUNTIME_EVIDENCE_SCHEMA,
    EPOCH_ROLLOVER_RESULT_DIGEST_DOMAIN, EPOCH_ROLLOVER_SOURCE_DIGEST_DOMAIN,
    RUNTIME_HOST_AUTHORITY_OWNER,
};
use rusty_manifold_media_session::{
    expire_media_sessions, review_and_apply_media_session_acceptance,
    review_and_apply_media_session_termination, validate_current_media_session,
    validate_media_session_acceptance_state, ManifoldMediaSessionAcceptanceReceipt,
    ManifoldMediaSessionAcceptanceRequest, ManifoldMediaSessionAcceptanceState,
    ManifoldMediaSessionClientGrant, ManifoldMediaSessionCurrentReceipt,
    ManifoldMediaSessionLifecycleStatus, ManifoldMediaSessionMutationReceipt,
    ManifoldMediaSessionRuntimeCommandContext, ManifoldMediaSessionTerminationRequest,
    MANIFOLD_MEDIA_SESSION_ACCEPTANCE_STATE_SCHEMA, MANIFOLD_MEDIA_SESSION_ACCEPT_COMMAND,
    MANIFOLD_MEDIA_SESSION_REVOKE_COMMAND, MANIFOLD_MEDIA_SESSION_STOP_COMMAND,
};
use rusty_manifold_model::{
    DottedId, ManifoldControlLeaseRevocationAuthorityApplicationOutcome,
    ManifoldControlLeaseRevocationTombstone, Revision, SchemaId,
};
use rusty_manifold_peer::{
    direct_lane_state_is_well_formed, enrollment_state_is_well_formed, expire_direct_lane_leases,
    expire_peer_mesh_members, reciprocal_ed25519_compatibility_receipt,
    review_and_apply_direct_lane_lease, review_and_apply_peer_enrollment,
    review_and_apply_peer_mesh, review_and_apply_peer_proposal,
    review_and_apply_reciprocal_ed25519, review_and_apply_signed_peer_session,
    review_and_apply_signed_rendezvous, revoke_direct_lane_lease, revoke_peer_mesh_member,
    revoke_peer_session, validate_current_direct_lane_lease, validate_current_peer_session,
    validate_current_rendezvous_receipt, ManifoldAcceptedPeerState, ManifoldDirectLaneClientGrant,
    ManifoldDirectLaneLeaseAuthorityContext, ManifoldDirectLaneLeaseCurrentReceipt,
    ManifoldDirectLaneLeaseReceipt, ManifoldDirectLaneLeaseRejectionReason,
    ManifoldDirectLaneLeaseRequest, ManifoldDirectLaneLeaseRevocation,
    ManifoldDirectLaneLeaseState, ManifoldDirectLaneLeaseUseRequest,
    ManifoldDirectLaneRuntimeCommandContext, ManifoldPeerApplicationReceipt, ManifoldPeerDecision,
    ManifoldPeerDecisionOutcome, ManifoldPeerEnrollmentReceipt, ManifoldPeerEnrollmentRequest,
    ManifoldPeerEnrollmentState, ManifoldPeerMeshDecision, ManifoldPeerMeshMutationReceipt,
    ManifoldPeerMeshPairEvidence, ManifoldPeerMeshProposal, ManifoldPeerMeshReviewCase,
    ManifoldPeerMeshRevocation, ManifoldPeerMeshState, ManifoldPeerReviewCase,
    ManifoldPeerSessionCurrentReceipt, ManifoldPeerSessionDecision, ManifoldPeerSessionProposal,
    ManifoldPeerSessionReviewCase, ManifoldPeerSessionRevocation, ManifoldPeerSessionState,
    ManifoldPeerStatusProposal, ManifoldPeerTopologyAuthorization,
    ManifoldReciprocalEd25519AuthorityState, ManifoldReciprocalEd25519Receipt,
    ManifoldReciprocalEd25519ReviewRequest, ManifoldReciprocalEd25519RuntimeContext,
    ManifoldRendezvousAuthorityState, ManifoldRendezvousReceipt, ManifoldRendezvousReviewRequest,
    ManifoldSignedPeerSessionReviewCase, ManifoldSignedPeerTopologyAuthorization,
    DIRECT_LANE_LEASE_ISSUE_COMMAND, DIRECT_LANE_LEASE_REVOKE_COMMAND,
    DIRECT_LANE_LEASE_STATE_SCHEMA, DIRECT_LANE_LEASE_USE_COMMAND, MAX_MESH_PEERS, MIN_MESH_PEERS,
    PEER_CREDENTIAL_SCHEMA, PEER_ENROLLMENT_STATE_SCHEMA, PEER_MESH_STATE_SCHEMA,
    PEER_REVIEW_CASE_SCHEMA, PEER_SESSION_PROPOSAL_SCHEMA, PEER_SESSION_REVIEW_SCHEMA,
    PEER_SESSION_SNAPSHOT_SCHEMA, PEER_SNAPSHOT_SCHEMA, PEER_TOPOLOGY_AUTHORIZATION_SCHEMA,
    RECIPROCAL_ED25519_STATE_SCHEMA, RENDEZVOUS_AUTHORITY_STATE_SCHEMA, RENDEZVOUS_RECEIPT_SCHEMA,
    SIGNED_PEER_SESSION_REVIEW_SCHEMA, SIGNED_PEER_TOPOLOGY_AUTHORIZATION_SCHEMA,
};
use rusty_manifold_runtime_host::{
    ManifoldRuntimeCommandRequest, ManifoldRuntimeDerivativeLeaseBinding,
    ManifoldRuntimeDerivativeLeaseRevocationReceipt,
    ManifoldRuntimeDerivativeLeaseRevocationRequest, ManifoldRuntimeDispatchOutcome,
    ManifoldRuntimeHost, ManifoldRuntimeHostSnapshot, ManifoldRuntimeLease,
    ManifoldRuntimeUpstreamRevocationProof, HOST_APPLICATION_RECEIPT_SCHEMA,
    HOST_COMMAND_REQUEST_SCHEMA, HOST_DERIVATIVE_LEASE_BINDING_SCHEMA,
    HOST_DERIVATIVE_LEASE_REVOCATION_REQUEST_SCHEMA, HOST_DISPATCH_RECEIPT_SCHEMA,
    HOST_SNAPSHOT_SCHEMA,
};
use serde::{Deserialize, Serialize};

/// Released peer Runtime Host snapshot schema retained for explicit migration.
pub const LEGACY_PEER_RUNTIME_HOST_SNAPSHOT_V1_SCHEMA: &str =
    "rusty.manifold.peer.runtime_host.snapshot.v1";
/// Released peer Runtime Host snapshot schema without epoch checkpoints.
pub const LEGACY_PEER_RUNTIME_HOST_SNAPSHOT_V2_SCHEMA: &str =
    "rusty.manifold.peer.runtime_host.snapshot.v2";
/// Durable peer Runtime Host snapshot schema.
pub const PEER_RUNTIME_HOST_SNAPSHOT_SCHEMA: &str = "rusty.manifold.peer.runtime_host.snapshot.v3";
/// Unified peer Runtime Host audit-event schema.
pub const PEER_RUNTIME_HOST_AUDIT_SCHEMA: &str = "rusty.manifold.peer.runtime_host.audit_event.v1";
/// Immutable/revisioned Runtime Host trust-policy schema.
pub const PEER_RUNTIME_HOST_TRUST_POLICY_SCHEMA: &str =
    "rusty.manifold.peer.runtime_host.trust_policy.v1";
/// Retained live-broker-to-inner-lease admission schema.
pub const PEER_RUNTIME_BROKER_LEASE_ADMISSION_SCHEMA: &str =
    "rusty.manifold.peer.runtime_host.broker_lease_admission.v1";
/// Typed result of one live broker-to-inner-media-lease attempt.
pub const PEER_RUNTIME_BROKER_LEASE_ATTEMPT_SCHEMA: &str =
    "rusty.manifold.peer.runtime_host.broker_lease_attempt.v1";
/// Live Broker revocation convergence request schema.
pub const PEER_RUNTIME_BROKER_LEASE_REVOCATION_CONVERGENCE_REQUEST_SCHEMA: &str =
    "rusty.manifold.peer.runtime_host.broker_lease_revocation_convergence_request.v1";
/// Retained cleanup obligation schema for one revoked media decision.
pub const PEER_RUNTIME_MEDIA_CLEANUP_OBLIGATION_SCHEMA: &str =
    "rusty.manifold.peer.runtime_host.media_cleanup_obligation.v1";
/// Durable live Broker revocation convergence receipt schema.
pub const PEER_RUNTIME_BROKER_LEASE_REVOCATION_CONVERGENCE_RECEIPT_SCHEMA: &str =
    "rusty.manifold.peer.runtime_host.broker_lease_revocation_convergence_receipt.v1";
/// Terminal platform-cleanup completion request schema.
pub const PEER_RUNTIME_BROKER_LEASE_REVOCATION_CLEANUP_COMPLETION_REQUEST_SCHEMA: &str =
    "rusty.manifold.peer.runtime_host.broker_lease_revocation_cleanup_completion_request.v1";
/// Durable terminal platform-cleanup completion receipt schema.
pub const PEER_RUNTIME_BROKER_LEASE_REVOCATION_CLEANUP_COMPLETION_RECEIPT_SCHEMA: &str =
    "rusty.manifold.peer.runtime_host.broker_lease_revocation_cleanup_completion_receipt.v1";
/// Peer-owned checkpoint joining one exact drained Broker epoch rollover.
pub const PEER_RUNTIME_BROKER_EPOCH_ROLLOVER_RECEIPT_SCHEMA: &str =
    "rusty.manifold.peer.runtime_host.broker_epoch_rollover_receipt.v1";
/// Explicit peer Runtime Host snapshot migration receipt schema.
pub const PEER_RUNTIME_HOST_SNAPSHOT_MIGRATION_RECEIPT_SCHEMA: &str =
    "rusty.manifold.peer.runtime_host.snapshot_migration_receipt.v1";
const PEER_RUNTIME_CONVERGENCE_RECEIPT_DIGEST_DOMAIN: &str =
    "rusty.manifold.peer.runtime_host.convergence_receipt.sha256.v1";
const PEER_RUNTIME_TERMINAL_CLEANUP_RECEIPT_DIGEST_DOMAIN: &str =
    "rusty.manifold.peer.runtime_host.terminal_cleanup_receipt.sha256.v1";
const PEER_RUNTIME_BROKER_EPOCH_STATE_DIGEST_DOMAIN: &str =
    "rusty.manifold.peer.runtime_host.broker_epoch_state.sha256.v1";
const PEER_RUNTIME_BROKER_EPOCH_AUDIT_DIGEST_DOMAIN: &str =
    "rusty.manifold.peer.runtime_host.broker_epoch_audit_prefix.sha256.v1";

/// Hard cap for lifetime mutation/audit events between explicit operator
/// checkpoints. The host fails closed at this boundary; it never silently
/// drops replay guards or historical authority records.
pub const MAX_PEER_RUNTIME_HOST_EVENTS: usize = 8_192;
/// Hard cap for any single retained authority/replay collection. This leaves
/// headroom for operations that atomically append two evidence/nonce records.
pub const MAX_PEER_RUNTIME_AUTHORITY_RECORDS: usize = 32_768;

/// Immutable authority modules selected by the product feature lock.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldPeerRuntimeAuthorityFamily {
    /// Low-rate peer identity/status authority.
    PeerStatus,
    /// Operator credential enrollment/rotation/revocation.
    Enrollment,
    /// Reciprocal rendezvous and peer-session authority.
    Rendezvous,
    /// Bounded N-peer mesh authority.
    PeerMesh,
    /// Product-bound media-session authority.
    MediaSession,
    /// Authenticated direct-lane issue/use/revoke authority.
    DirectLane,
}

/// Immutable trust roots selected by the embedding product at host creation.
/// Mutation requests may reference these identities but can never supply or
/// widen trust themselves.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPeerRuntimeTrustPolicy {
    /// Schema identifier.
    #[serde(rename = "$schema")]
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

/// Family of pure peer authority invoked by one host operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldPeerRuntimeAuditKind {
    /// Accepted low-rate peer identity/status review.
    PeerStatus,
    /// Operator-mediated credential enrollment, rotation, or revocation.
    Enrollment,
    /// Reciprocal signed rendezvous review.
    SignedRendezvous,
    /// Carrier-independent reciprocal Ed25519 v2 review.
    ReciprocalEd25519,
    /// Signed-rendezvous-bound peer-session review.
    SignedPeerSession,
    /// Explicit peer-session revocation.
    PeerSessionRevocation,
    /// Bounded N-peer mesh review.
    PeerMesh,
    /// Product-bound generic media-session acceptance review.
    MediaSessionAcceptance,
    /// Explicit media-session stop/revoke review.
    MediaSessionTermination,
    /// Explicit media-session expiry sweep.
    MediaSessionExpiry,
    /// Outer broker bounded use minted an inner Runtime Host lease.
    BrokerLeaseAdmission,
    /// Inner Runtime Host lease released after stop/revoke.
    BrokerLeaseRelease,
    /// Live Broker administrative revocation cascaded through peer derivatives.
    BrokerLeaseRevocationConvergence,
    /// Terminal platform cleanup completion for one Broker revocation.
    BrokerLeaseRevocationCleanupCompletion,
    /// Exact drained Broker provider epoch joined and checkpointed.
    BrokerEpochRollover,
    /// Explicit peer-mesh member expiry sweep.
    PeerMeshExpiry,
    /// Explicit peer-mesh member revocation.
    PeerMeshRevocation,
    /// Real direct-lane lease review.
    DirectLaneLease,
    /// Authenticated current direct-lane use.
    DirectLaneUse,
    /// Explicit direct-lane lease expiry sweep.
    DirectLaneLeaseExpiry,
    /// Explicit direct-lane lease revocation.
    DirectLaneLeaseRevocation,
}

/// Append-only audit record spanning all peer authority families.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPeerRuntimeAuditEvent {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Strictly increasing host-local event sequence.
    pub sequence: u64,
    /// Derived event identity.
    pub event_id: DottedId,
    /// Pure authority family invoked.
    pub event_kind: ManifoldPeerRuntimeAuditKind,
    /// Request, proposal, revocation, or sweep identity.
    pub source_id: DottedId,
    /// Authority revision before review/application.
    pub prior_authority_revision: Revision,
    /// Authority revision after review/application.
    pub resulting_authority_revision: Revision,
    /// Whether the underlying accepted authority changed.
    pub applied: bool,
    /// Stable serialized rejection code or mutation error.
    pub rejection_code: Option<String>,
}

/// Durable composition of every source-only peer authority family.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPeerRuntimeHostSnapshot {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Stable host identity selected by the embedding product.
    pub host_id: DottedId,
    /// Immutable/revisioned trust roots selected at host creation.
    pub trust_policy: ManifoldPeerRuntimeTrustPolicy,
    /// Host-owned live provider-process epoch.
    pub provider_epoch_id: DottedId,
    /// Last emitted unified audit sequence.
    pub event_sequence: u64,
    /// Accepted low-rate peer identities/status.
    pub accepted_peers: ManifoldAcceptedPeerState,
    /// Operator-mediated public credential state.
    pub enrollment: ManifoldPeerEnrollmentState,
    /// Accepted signed-rendezvous receipts and replay guards.
    pub rendezvous: ManifoldRendezvousAuthorityState,
    /// Carrier-independent reciprocal Ed25519 v2 receipts and replay guards.
    #[serde(default = "ManifoldReciprocalEd25519AuthorityState::empty")]
    pub reciprocal_ed25519: ManifoldReciprocalEd25519AuthorityState,
    /// Accepted/revoked peer sessions.
    pub peer_sessions: ManifoldPeerSessionState,
    /// Accepted/revoked/expired N-peer mesh state.
    pub peer_mesh: ManifoldPeerMeshState,
    /// Current product-bound media-session decisions retained by Manifold.
    pub media_sessions: ManifoldMediaSessionAcceptanceState,
    /// Embedded Runtime Host state that applies media lifecycle commands.
    pub media_command_runtime: ManifoldRuntimeHostSnapshot,
    /// Broker-admission receipts that minted short-lived inner Runtime Host leases.
    #[serde(default)]
    pub broker_lease_admissions: Vec<ManifoldPeerRuntimeBrokerLeaseAdmission>,
    /// Applied live Broker administrative revocations and derivative cleanup.
    pub broker_lease_revocation_convergences:
        Vec<ManifoldPeerRuntimeBrokerLeaseRevocationConvergenceReceipt>,
    /// Terminal platform cleanup evidence for Broker revocation convergences.
    pub broker_lease_revocation_cleanup_completions:
        Vec<ManifoldPeerRuntimeBrokerLeaseRevocationCleanupCompletionReceipt>,
    /// Ordered peer-owned checkpoints for drained Broker provider epochs.
    pub broker_epoch_rollovers: Vec<ManifoldPeerRuntimeBrokerEpochRolloverReceipt>,
    /// Real direct-lane lease state.
    pub direct_lane_leases: ManifoldDirectLaneLeaseState,
    /// Signed topology receipts retained for current-state revalidation.
    pub signed_topology_authorizations: Vec<ManifoldSignedPeerTopologyAuthorization>,
    /// Append-only cross-authority audit records.
    pub audit_events: Vec<ManifoldPeerRuntimeAuditEvent>,
}

/// Retained broker-to-peer Runtime Host lease mint/release closure.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPeerRuntimeBrokerLeaseAdmission {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Exact outer mutation/admission receipt.
    pub broker_receipt: ManifoldBrokerMutationReceipt,
    /// Exact inner Runtime Host lease minted from it.
    pub runtime_lease: ManifoldRuntimeLease,
    /// Mint time.
    pub admitted_at_ms: u64,
    /// Release time after stop/revoke, when no longer active.
    pub released_at_ms: Option<u64>,
    /// Exact replay-guarded release mutation, when released.
    pub release_id: Option<DottedId>,
}

/// Closed result class for one broker-to-inner-lease attempt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldPeerRuntimeBrokerLeaseAttemptOutcome {
    /// Admission rejected before a bounded use was consumed.
    BrokerAdmissionRejected,
    /// The bounded use was consumed but the outer Runtime Host rejected.
    BrokerCommandRejected,
    /// The outer command applied but a fail-closed peer join rejected.
    PeerLeaseRejected,
    /// Both the outer command and inner lease admission committed.
    LeaseAdmitted,
}

/// Exact split outcome preserving broker consumption even when no inner lease
/// is admitted.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPeerRuntimeBrokerLeaseAttempt {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Closed attempt outcome.
    pub outcome: ManifoldPeerRuntimeBrokerLeaseAttemptOutcome,
    /// Exact live broker receipt.
    pub broker_receipt: ManifoldBrokerMutationReceipt,
    /// Retained lease admission only when the full transaction succeeded.
    pub lease_admission: Option<ManifoldPeerRuntimeBrokerLeaseAdmission>,
    /// Stable peer rejection detail for a fail-closed post-broker join.
    pub peer_rejection_code: Option<String>,
}

/// CAS-bound request to converge one current live Broker revocation.
///
/// The request contains only identities and freshness expectations. It never
/// supplies a lifecycle receipt; the peer host obtains that evidence from the
/// live [`ManifoldBrokerRuntime`] passed to the convergence method.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPeerRuntimeBrokerLeaseRevocationConvergenceRequest {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Replay-protected peer convergence identity.
    pub convergence_id: DottedId,
    /// Exact peer event sequence before this convergence.
    pub expected_peer_event_sequence: u64,
    /// Exact peer provider epoch.
    pub expected_peer_provider_epoch_id: DottedId,
    /// Exact live Broker provider epoch.
    pub expected_broker_provider_epoch_id: DottedId,
    /// Exact retained Broker lifecycle request to join.
    pub broker_lifecycle_request_id: DottedId,
    /// Outer Manifold control lease whose revocation must be current.
    pub outer_control_lease_id: DottedId,
    /// Current Broker control-lease authority revision.
    pub expected_broker_control_lease_authority_revision: Revision,
    /// Current Broker Runtime Host revision.
    pub expected_broker_runtime_host_revision: Revision,
    /// Peer authority clock used for deterministic derivative tombstones.
    pub converged_at_ms: u64,
}

/// Platform cleanup still owed after accepted-state media revocation.
///
/// This record intentionally carries only source-neutral descriptor
/// references. It never claims that a renderer, codec, camera, relay, or
/// transport process has actually released its platform resources.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPeerRuntimeMediaCleanupObligation {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Exact retained media decision that became revoked.
    pub session_decision_id: DottedId,
    /// Generic media-session identity.
    pub session_id: DottedId,
    /// Exact selected platform runtime specification.
    pub platform_runtime_spec_id: DottedId,
    /// Canonical source descriptor references.
    pub source_ids: Vec<DottedId>,
    /// Canonical processor descriptor references.
    pub processor_ids: Vec<DottedId>,
    /// Canonical route descriptor references.
    pub route_ids: Vec<DottedId>,
    /// Canonical sink descriptor references.
    pub sink_ids: Vec<DottedId>,
    /// Canonical stream descriptor references.
    pub stream_ids: Vec<DottedId>,
}

/// Durable proof that one live Broker revocation was joined and cascaded.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPeerRuntimeBrokerLeaseRevocationConvergenceReceipt {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Replay-protected peer convergence identity.
    pub convergence_id: DottedId,
    /// Peer host that applied the derivative cleanup.
    pub peer_host_id: DottedId,
    /// Exact peer provider epoch.
    pub peer_provider_epoch_id: DottedId,
    /// Exact live Broker lifecycle receipt copied from current evidence.
    pub broker_lifecycle_receipt: ManifoldBrokerControlLeaseLifecycleReceipt,
    /// Exact terminal outer-lease tombstone copied from the generic application.
    pub outer_control_lease_tombstone: ManifoldControlLeaseRevocationTombstone,
    /// Exact inner Runtime Host derivative-lease revocation receipt.
    pub inner_runtime_lease_revocation_receipt: ManifoldRuntimeDerivativeLeaseRevocationReceipt,
    /// Peer event sequence before convergence.
    pub prior_peer_event_sequence: u64,
    /// Peer event sequence after convergence.
    pub resulting_peer_event_sequence: u64,
    /// Peer authority time at which derivative tombstones were committed.
    pub converged_at_ms: u64,
    /// Media authority revision before derivative revocation.
    pub prior_media_authority_revision: Revision,
    /// Media authority revision after derivative revocation.
    pub resulting_media_authority_revision: Revision,
    /// Direct-lane authority revision before derivative revocation.
    pub prior_direct_lane_authority_revision: Revision,
    /// Direct-lane authority revision after derivative revocation.
    pub resulting_direct_lane_authority_revision: Revision,
    /// Canonical Broker admission-use ids terminally released by convergence.
    pub affected_broker_admission_use_ids: Vec<DottedId>,
    /// Canonical inner Runtime Host lease ids removed by convergence.
    pub removed_inner_runtime_lease_ids: Vec<DottedId>,
    /// Canonical media decision ids marked revoked.
    pub revoked_media_decision_ids: Vec<DottedId>,
    /// Canonical direct-lane lease ids marked revoked.
    pub revoked_direct_lane_lease_ids: Vec<DottedId>,
    /// Exact source-neutral platform cleanup obligations.
    pub cleanup_obligations: Vec<ManifoldPeerRuntimeMediaCleanupObligation>,
    /// True when platform cleanup evidence was required at convergence time.
    pub platform_cleanup_pending: bool,
    /// True only for an atomically committed convergence.
    pub applied: bool,
}

/// Exact terminal cleanup completion proposed for one retained convergence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPeerRuntimeBrokerLeaseRevocationCleanupCompletionRequest {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Replay-protected completion identity.
    pub completion_id: DottedId,
    /// Exact retained convergence being completed.
    pub convergence_id: DottedId,
    /// Peer event sequence expected by the caller.
    pub expected_peer_event_sequence: u64,
    /// Complete canonical media-decision identities whose cleanup completed.
    pub completed_session_decision_ids: Vec<DottedId>,
    /// SHA-256 of deployment-owner-verified platform cleanup evidence.
    pub platform_cleanup_receipt_sha256: String,
}

/// Durable peer-owned proof that every retained cleanup obligation completed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPeerRuntimeBrokerLeaseRevocationCleanupCompletionReceipt {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Replay-protected completion identity.
    pub completion_id: DottedId,
    /// Exact retained convergence completed by this receipt.
    pub convergence_id: DottedId,
    /// Stable peer Runtime Host identity.
    pub peer_host_id: DottedId,
    /// Exact peer provider epoch.
    pub peer_provider_epoch_id: DottedId,
    /// Event sequence before completion.
    pub prior_peer_event_sequence: u64,
    /// Event sequence after completion.
    pub resulting_peer_event_sequence: u64,
    /// Complete exact cleanup obligations closed by this receipt.
    pub completed_obligations: Vec<ManifoldPeerRuntimeMediaCleanupObligation>,
    /// Deployment-owner-verified platform cleanup evidence digest.
    pub platform_cleanup_receipt_sha256: String,
    /// True only when every retained obligation is closed.
    pub completed: bool,
}

/// Durable peer-owned proof of one exact Broker epoch rollover.
///
/// The nested Broker receipt binds complete source and result evidence. The
/// peer digests bind every retained Broker-derived record from the source epoch
/// plus the complete append-only audit prefix that existed before rollover.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPeerRuntimeBrokerEpochRolloverReceipt {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Replay-protected peer rollover identity.
    pub rollover_id: DottedId,
    /// Stable peer Runtime Host identity.
    pub peer_host_id: DottedId,
    /// Drained peer/Broker provider epoch.
    pub source_provider_epoch_id: DottedId,
    /// Fresh peer/Broker provider epoch.
    pub resulting_provider_epoch_id: DottedId,
    /// Exact Broker rollover checkpoint accepted by this peer.
    pub broker_rollover_receipt: ManifoldBrokerRuntimeEpochRolloverReceipt,
    /// Domain-separated digest of retained source-epoch Broker joins.
    pub checkpointed_peer_broker_state_sha256: String,
    /// Retained Broker admissions belonging to the source epoch.
    pub checkpointed_broker_lease_admission_count: usize,
    /// Retained revocation convergences belonging to the source epoch.
    pub checkpointed_revocation_convergence_count: usize,
    /// Retained cleanup completions belonging to the source epoch.
    pub checkpointed_cleanup_completion_count: usize,
    /// Domain-separated digest of the complete pre-rollover audit prefix.
    pub checkpointed_peer_audit_prefix_sha256: String,
    /// Exact number of audit events in the checkpointed prefix.
    pub checkpointed_peer_audit_event_count: usize,
    /// Peer event sequence before rollover.
    pub prior_peer_event_sequence: u64,
    /// Peer event sequence after rollover.
    pub resulting_peer_event_sequence: u64,
    /// True only for a completely validated and committed rollover.
    pub applied: bool,
}

/// Explicit migration receipt for a released v1 peer snapshot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPeerRuntimeHostSnapshotMigrationReceipt {
    /// Receipt schema.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Source snapshot schema.
    pub source_schema_id: SchemaId,
    /// Current resulting snapshot schema.
    pub resulting_schema_id: SchemaId,
    /// Whether migration changed the persistent shape.
    pub migrated: bool,
    /// Stable peer Runtime Host identity.
    pub host_id: DottedId,
    /// Exact preserved provider epoch.
    pub provider_epoch_id: DottedId,
    /// Exact preserved event sequence.
    pub preserved_event_sequence: u64,
    /// Exact preserved broker admission count.
    pub preserved_broker_lease_admission_count: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyManifoldPeerRuntimeHostSnapshotV1 {
    #[serde(rename = "$schema")]
    schema_id: SchemaId,
    host_id: DottedId,
    trust_policy: ManifoldPeerRuntimeTrustPolicy,
    provider_epoch_id: DottedId,
    event_sequence: u64,
    accepted_peers: ManifoldAcceptedPeerState,
    enrollment: ManifoldPeerEnrollmentState,
    rendezvous: ManifoldRendezvousAuthorityState,
    #[serde(default = "ManifoldReciprocalEd25519AuthorityState::empty")]
    reciprocal_ed25519: ManifoldReciprocalEd25519AuthorityState,
    peer_sessions: ManifoldPeerSessionState,
    peer_mesh: ManifoldPeerMeshState,
    media_sessions: ManifoldMediaSessionAcceptanceState,
    media_command_runtime: ManifoldRuntimeHostSnapshot,
    #[serde(default)]
    broker_lease_admissions: Vec<ManifoldPeerRuntimeBrokerLeaseAdmission>,
    direct_lane_leases: ManifoldDirectLaneLeaseState,
    signed_topology_authorizations: Vec<ManifoldSignedPeerTopologyAuthorization>,
    audit_events: Vec<ManifoldPeerRuntimeAuditEvent>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyManifoldPeerRuntimeHostSnapshotV2 {
    #[serde(rename = "$schema")]
    schema_id: SchemaId,
    host_id: DottedId,
    trust_policy: ManifoldPeerRuntimeTrustPolicy,
    provider_epoch_id: DottedId,
    event_sequence: u64,
    accepted_peers: ManifoldAcceptedPeerState,
    enrollment: ManifoldPeerEnrollmentState,
    rendezvous: ManifoldRendezvousAuthorityState,
    #[serde(default = "ManifoldReciprocalEd25519AuthorityState::empty")]
    reciprocal_ed25519: ManifoldReciprocalEd25519AuthorityState,
    peer_sessions: ManifoldPeerSessionState,
    peer_mesh: ManifoldPeerMeshState,
    media_sessions: ManifoldMediaSessionAcceptanceState,
    media_command_runtime: ManifoldRuntimeHostSnapshot,
    #[serde(default)]
    broker_lease_admissions: Vec<ManifoldPeerRuntimeBrokerLeaseAdmission>,
    broker_lease_revocation_convergences:
        Vec<ManifoldPeerRuntimeBrokerLeaseRevocationConvergenceReceipt>,
    broker_lease_revocation_cleanup_completions:
        Vec<ManifoldPeerRuntimeBrokerLeaseRevocationCleanupCompletionReceipt>,
    direct_lane_leases: ManifoldDirectLaneLeaseState,
    signed_topology_authorizations: Vec<ManifoldSignedPeerTopologyAuthorization>,
    audit_events: Vec<ManifoldPeerRuntimeAuditEvent>,
}

#[derive(Deserialize)]
struct PeerRuntimeHostSnapshotSchemaProbe {
    #[serde(rename = "$schema")]
    schema_id: SchemaId,
}

/// Source-only owner for combined peer authority state and audit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldPeerRuntimeHost {
    snapshot: ManifoldPeerRuntimeHostSnapshot,
}

impl ManifoldPeerRuntimeHost {
    /// Creates an empty revision-one host. Peer status must be accepted before
    /// session or mesh work can advance.
    ///
    /// # Errors
    ///
    /// Returns an invalid-snapshot error if a constructed invariant drifts.
    pub fn new(
        host_id: DottedId,
        trust_policy: ManifoldPeerRuntimeTrustPolicy,
        provider_epoch_id: DottedId,
        media_command_runtime: ManifoldRuntimeHostSnapshot,
    ) -> Result<Self, ManifoldPeerRuntimeHostError> {
        let expected_trust_policy = trust_policy.clone();
        let expected_provider_epoch_id = provider_epoch_id.clone();
        Self::from_snapshot(
            ManifoldPeerRuntimeHostSnapshot {
                schema_id: schema(PEER_RUNTIME_HOST_SNAPSHOT_SCHEMA),
                host_id,
                trust_policy,
                provider_epoch_id,
                event_sequence: 0,
                accepted_peers: ManifoldAcceptedPeerState {
                    schema_id: schema(PEER_SNAPSHOT_SCHEMA),
                    authority_revision: Revision::INITIAL,
                    peers: Vec::new(),
                    applied_proposal_ids: Vec::new(),
                },
                enrollment: ManifoldPeerEnrollmentState::empty(),
                rendezvous: ManifoldRendezvousAuthorityState::empty(),
                reciprocal_ed25519: ManifoldReciprocalEd25519AuthorityState::empty(),
                peer_sessions: ManifoldPeerSessionState {
                    schema_id: schema(PEER_SESSION_SNAPSHOT_SCHEMA),
                    authority_revision: Revision::INITIAL,
                    sessions: Vec::new(),
                    applied_proposal_ids: Vec::new(),
                    revoked_session_ids: Vec::new(),
                },
                peer_mesh: ManifoldPeerMeshState {
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
                media_sessions: ManifoldMediaSessionAcceptanceState::empty(),
                media_command_runtime,
                broker_lease_admissions: Vec::new(),
                broker_lease_revocation_convergences: Vec::new(),
                broker_lease_revocation_cleanup_completions: Vec::new(),
                broker_epoch_rollovers: Vec::new(),
                direct_lane_leases: ManifoldDirectLaneLeaseState::empty(),
                signed_topology_authorizations: Vec::new(),
                audit_events: Vec::new(),
            },
            &expected_trust_policy,
            &expected_provider_epoch_id,
        )
    }

    /// Restores a host from a validated durable snapshot.
    ///
    /// # Errors
    ///
    /// Returns an invalid-snapshot error for schema, identity, replay, audit,
    /// or cross-authority reference damage.
    pub fn from_snapshot(
        snapshot: ManifoldPeerRuntimeHostSnapshot,
        expected_trust_policy: &ManifoldPeerRuntimeTrustPolicy,
        expected_provider_epoch_id: &DottedId,
    ) -> Result<Self, ManifoldPeerRuntimeHostError> {
        if &snapshot.trust_policy != expected_trust_policy {
            return Err(invalid_snapshot("trust policy substitution"));
        }
        if &snapshot.provider_epoch_id != expected_provider_epoch_id {
            return Err(invalid_snapshot("provider epoch substitution"));
        }
        validate_snapshot(&snapshot)?;
        if !snapshot.broker_lease_admissions.is_empty()
            || !snapshot.broker_lease_revocation_convergences.is_empty()
            || !snapshot
                .broker_lease_revocation_cleanup_completions
                .is_empty()
            || !snapshot.broker_epoch_rollovers.is_empty()
        {
            return Err(invalid_snapshot(
                "live Broker join required for broker-derived restoration",
            ));
        }
        Ok(Self { snapshot })
    }

    /// Restores a Broker-derived peer snapshot only after joining current live
    /// Broker authority, Runtime Host, and lifecycle evidence.
    ///
    /// # Errors
    ///
    /// Returns an invalid-snapshot error for normal peer damage or whenever an
    /// active inner admission or retained convergence disagrees with the live
    /// Broker closure.
    pub fn from_snapshot_with_live_broker_runtime(
        snapshot: ManifoldPeerRuntimeHostSnapshot,
        expected_trust_policy: &ManifoldPeerRuntimeTrustPolicy,
        expected_provider_epoch_id: &DottedId,
        broker_runtime: &ManifoldBrokerRuntime,
    ) -> Result<Self, ManifoldPeerRuntimeHostError> {
        if &snapshot.trust_policy != expected_trust_policy {
            return Err(invalid_snapshot("trust policy substitution"));
        }
        if &snapshot.provider_epoch_id != expected_provider_epoch_id {
            return Err(invalid_snapshot("provider epoch substitution"));
        }
        validate_snapshot(&snapshot)?;
        validate_live_broker_restoration(&snapshot, &broker_runtime.evidence())?;
        Ok(Self { snapshot })
    }

    /// Restarts a host from deterministic JSON.
    ///
    /// # Errors
    ///
    /// Returns a deserialize or invalid-snapshot error for damaged state.
    pub fn restart_from_json(
        json: &str,
        expected_trust_policy: &ManifoldPeerRuntimeTrustPolicy,
        expected_provider_epoch_id: &DottedId,
    ) -> Result<Self, ManifoldPeerRuntimeHostError> {
        let (snapshot, _) = decode_peer_runtime_snapshot_with_migration(json)?;
        Self::from_snapshot(snapshot, expected_trust_policy, expected_provider_epoch_id)
    }

    /// Restarts from current or released-v1 JSON and returns explicit migration
    /// evidence. Broker-derived snapshots still require the live-Broker variant.
    ///
    /// # Errors
    ///
    /// Returns a deserialize or invalid-snapshot error for damaged state.
    pub fn restart_from_json_with_migration(
        json: &str,
        expected_trust_policy: &ManifoldPeerRuntimeTrustPolicy,
        expected_provider_epoch_id: &DottedId,
    ) -> Result<(Self, ManifoldPeerRuntimeHostSnapshotMigrationReceipt), ManifoldPeerRuntimeHostError>
    {
        let (snapshot, receipt) = decode_peer_runtime_snapshot_with_migration(json)?;
        let host =
            Self::from_snapshot(snapshot, expected_trust_policy, expected_provider_epoch_id)?;
        Ok((host, receipt))
    }

    /// Restarts current or released-v1 Broker-derived state only after a live
    /// Broker evidence join, returning explicit migration evidence.
    ///
    /// # Errors
    ///
    /// Returns a deserialize or invalid-snapshot error for damaged state,
    /// stale old-peer state, or a live Broker closure mismatch.
    pub fn restart_from_json_with_live_broker_runtime(
        json: &str,
        expected_trust_policy: &ManifoldPeerRuntimeTrustPolicy,
        expected_provider_epoch_id: &DottedId,
        broker_runtime: &ManifoldBrokerRuntime,
    ) -> Result<(Self, ManifoldPeerRuntimeHostSnapshotMigrationReceipt), ManifoldPeerRuntimeHostError>
    {
        let (snapshot, receipt) = decode_peer_runtime_snapshot_with_migration(json)?;
        let host = Self::from_snapshot_with_live_broker_runtime(
            snapshot,
            expected_trust_policy,
            expected_provider_epoch_id,
            broker_runtime,
        )?;
        Ok((host, receipt))
    }

    /// Serializes the complete accepted state and audit history.
    ///
    /// # Errors
    ///
    /// Returns a serialization error if JSON encoding fails.
    pub fn snapshot_json(&self) -> Result<String, ManifoldPeerRuntimeHostError> {
        serde_json::to_string_pretty(&self.snapshot)
            .map_err(ManifoldPeerRuntimeHostError::Serialize)
    }

    /// Returns the durable accepted snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> &ManifoldPeerRuntimeHostSnapshot {
        &self.snapshot
    }

    /// Reviews one low-rate peer status proposal against host-owned state.
    ///
    /// # Errors
    ///
    /// Returns event-sequence exhaustion before invoking the pure authority.
    pub fn review_peer_status(
        &mut self,
        proposal: ManifoldPeerStatusProposal,
        now_ms: u64,
    ) -> Result<(ManifoldPeerDecision, ManifoldPeerApplicationReceipt), ManifoldPeerRuntimeHostError>
    {
        self.ensure_family_enabled(ManifoldPeerRuntimeAuthorityFamily::PeerStatus)?;
        self.ensure_event_capacity()?;
        let mut trusted_key_fingerprints =
            self.snapshot.trust_policy.trusted_key_fingerprints.clone();
        trusted_key_fingerprints.extend(
            self.snapshot
                .enrollment
                .credentials
                .iter()
                .filter(|credential| {
                    credential.status == rusty_manifold_peer::ManifoldPeerCredentialStatus::Active
                        && credential.valid_from_ms <= now_ms
                        && credential.expires_at_ms > now_ms
                })
                .filter_map(|credential| {
                    credential
                        .public_key_sha256
                        .strip_prefix("sha256:")
                        .and_then(|digest| DottedId::new(format!("fingerprint.{digest}")).ok())
                }),
        );
        trusted_key_fingerprints.sort();
        trusted_key_fingerprints.dedup();
        let case = ManifoldPeerReviewCase {
            schema_id: schema(PEER_REVIEW_CASE_SCHEMA),
            case_id: derived("case.peer-runtime", &proposal.proposal_id),
            current_state: self.snapshot.accepted_peers.clone(),
            proposal,
            trusted_key_fingerprints,
            now_ms,
            expected_outcome: ManifoldPeerDecisionOutcome::Accepted,
        };
        let (decision, receipt) = review_and_apply_peer_proposal(&case);
        if let Some(state) = decision.accepted_state.clone() {
            self.snapshot.accepted_peers = state;
        }
        let rejection = decision.rejection.as_ref().map(|value| &value.reason);
        self.record(
            ManifoldPeerRuntimeAuditKind::PeerStatus,
            case.proposal.proposal_id.clone(),
            receipt.prior_authority_revision,
            receipt.resulting_authority_revision,
            receipt.applied,
            rejection_code(rejection),
        )?;
        Ok((decision, receipt))
    }

    /// Reviews an operator enrollment, rotation, or revocation request.
    ///
    /// # Errors
    ///
    /// Returns event-sequence exhaustion before invoking enrollment authority.
    pub fn review_enrollment(
        &mut self,
        request: &ManifoldPeerEnrollmentRequest,
        now_ms: u64,
    ) -> Result<ManifoldPeerEnrollmentReceipt, ManifoldPeerRuntimeHostError> {
        self.ensure_family_enabled(ManifoldPeerRuntimeAuthorityFamily::Enrollment)?;
        self.ensure_event_capacity()?;
        let (next, receipt) = review_and_apply_peer_enrollment(
            &self.snapshot.enrollment,
            request,
            &self.snapshot.trust_policy.trusted_operator_ids,
            now_ms,
        );
        self.snapshot.enrollment = next;
        self.record(
            ManifoldPeerRuntimeAuditKind::Enrollment,
            request.request_id.clone(),
            receipt.prior_authority_revision,
            receipt.resulting_authority_revision,
            receipt.applied,
            rejection_code(receipt.rejection_reason.as_ref()),
        )?;
        Ok(receipt)
    }

    /// Reviews reciprocal signed rendezvous evidence against current keys.
    ///
    /// # Errors
    ///
    /// Returns event-sequence exhaustion before invoking rendezvous authority.
    pub fn review_signed_rendezvous(
        &mut self,
        request: &ManifoldRendezvousReviewRequest,
        now_ms: u64,
    ) -> Result<ManifoldRendezvousReceipt, ManifoldPeerRuntimeHostError> {
        self.ensure_family_enabled(ManifoldPeerRuntimeAuthorityFamily::Rendezvous)?;
        self.ensure_event_capacity()?;
        let (next, receipt) = review_and_apply_signed_rendezvous(
            &self.snapshot.rendezvous,
            &self.snapshot.enrollment,
            request,
            now_ms,
        );
        self.snapshot.rendezvous = next;
        self.record(
            ManifoldPeerRuntimeAuditKind::SignedRendezvous,
            request.request_id.clone(),
            receipt.prior_authority_revision,
            receipt.resulting_authority_revision,
            receipt.accepted,
            rejection_code(receipt.rejection_reason.as_ref()),
        )?;
        Ok(receipt)
    }

    /// Reviews a carrier-independent reciprocal Ed25519 v2 context against
    /// the exact current Runtime Host identity, authority revisions, and
    /// enrolled public keys. Platform/ADB routes may relay already-signed
    /// bytes only; this host remains the acceptance authority.
    ///
    /// # Errors
    ///
    /// Returns event-sequence exhaustion before invoking the pure authority.
    pub fn review_reciprocal_ed25519(
        &mut self,
        request: &ManifoldReciprocalEd25519ReviewRequest,
        now_ms: u64,
    ) -> Result<ManifoldReciprocalEd25519Receipt, ManifoldPeerRuntimeHostError> {
        self.ensure_family_enabled(ManifoldPeerRuntimeAuthorityFamily::Rendezvous)?;
        self.ensure_event_capacity()?;
        let runtime = ManifoldReciprocalEd25519RuntimeContext {
            runtime_host_id: &self.snapshot.host_id,
            trust_policy_id: &self.snapshot.trust_policy.policy_id,
            trust_policy_revision: self.snapshot.trust_policy.revision,
            peer_authority_revision: self.snapshot.accepted_peers.authority_revision,
            enrollment: &self.snapshot.enrollment,
            rendezvous_authority_revision: self.snapshot.rendezvous.authority_revision,
            peer_session_authority_revision: self.snapshot.peer_sessions.authority_revision,
            peer_mesh_authority_revision: self.snapshot.peer_mesh.authority_revision,
            direct_lane_lease_authority_revision: self
                .snapshot
                .direct_lane_leases
                .authority_revision,
        };
        let (next, receipt) = review_and_apply_reciprocal_ed25519(
            &self.snapshot.reciprocal_ed25519,
            request,
            runtime,
            now_ms,
        );
        if receipt.accepted {
            let compatibility = reciprocal_ed25519_compatibility_receipt(&receipt);
            self.snapshot.reciprocal_ed25519 = next;
            self.snapshot.rendezvous.authority_revision =
                receipt.compatibility_resulting_authority_revision;
            self.snapshot
                .rendezvous
                .applied_request_ids
                .push(compatibility.request_id.clone());
            self.snapshot
                .rendezvous
                .consumed_evidence_ids
                .extend(compatibility.evidence_ids.clone());
            self.snapshot
                .rendezvous
                .consumed_nonce_sha256
                .push(compatibility.nonce_sha256.clone());
            self.snapshot
                .rendezvous
                .accepted_receipts
                .push(compatibility);
            self.snapshot
                .rendezvous
                .accepted_receipts
                .sort_by(|left, right| left.receipt_id.cmp(&right.receipt_id));
        }
        self.record(
            ManifoldPeerRuntimeAuditKind::ReciprocalEd25519,
            request.request_id.clone(),
            receipt.prior_authority_revision,
            receipt.resulting_authority_revision,
            receipt.accepted,
            rejection_code(receipt.rejection_reason.as_ref()),
        )?;
        Ok(receipt)
    }

    /// Reviews a peer session against host-owned peer/enrollment/rendezvous
    /// state and retains the signed topology authorization on acceptance.
    ///
    /// # Errors
    ///
    /// Returns event-sequence exhaustion before invoking session authority.
    pub fn review_signed_peer_session(
        &mut self,
        proposal: ManifoldPeerSessionProposal,
        rendezvous_receipt: ManifoldRendezvousReceipt,
        now_ms: u64,
    ) -> Result<
        (
            ManifoldPeerSessionDecision,
            ManifoldSignedPeerTopologyAuthorization,
        ),
        ManifoldPeerRuntimeHostError,
    > {
        self.ensure_family_enabled(ManifoldPeerRuntimeAuthorityFamily::Rendezvous)?;
        self.ensure_event_capacity()?;
        let case = ManifoldSignedPeerSessionReviewCase {
            schema_id: schema(SIGNED_PEER_SESSION_REVIEW_SCHEMA),
            session_review: ManifoldPeerSessionReviewCase {
                schema_id: schema(PEER_SESSION_REVIEW_SCHEMA),
                accepted_peers: self.snapshot.accepted_peers.clone(),
                current_state: self.snapshot.peer_sessions.clone(),
                proposal,
                trusted_adapter_ids: self.snapshot.trust_policy.trusted_adapter_ids.clone(),
                now_ms,
            },
            rendezvous_receipt,
            current_enrollment: self.snapshot.enrollment.clone(),
            current_rendezvous_state: self.snapshot.rendezvous.clone(),
        };
        let (decision, topology) = review_and_apply_signed_peer_session(&case);
        if let Some(state) = decision.accepted_state.clone() {
            self.snapshot.peer_sessions = state;
            self.snapshot
                .signed_topology_authorizations
                .push(topology.clone());
            self.snapshot
                .signed_topology_authorizations
                .sort_by(|left, right| {
                    left.topology_authorization
                        .decision_id
                        .cmp(&right.topology_authorization.decision_id)
                });
        }
        self.record(
            ManifoldPeerRuntimeAuditKind::SignedPeerSession,
            case.session_review.proposal.proposal_id.clone(),
            decision.prior_authority_revision,
            decision.resulting_authority_revision,
            decision.applied,
            rejection_code(decision.rejection_reason.as_ref()),
        )?;
        Ok((decision, topology))
    }

    /// Explicitly revokes one active peer session and invalidates its retained
    /// signed topology authorization.
    ///
    /// # Errors
    ///
    /// Returns a typed host error for replay, stale revision, missing session,
    /// authority failure, or event-sequence exhaustion.
    pub fn revoke_peer_session(
        &mut self,
        request: &ManifoldPeerSessionRevocation,
        now_ms: u64,
    ) -> Result<ManifoldPeerTopologyAuthorization, ManifoldPeerRuntimeHostError> {
        self.ensure_family_enabled(ManifoldPeerRuntimeAuthorityFamily::Rendezvous)?;
        self.ensure_event_capacity()?;
        let prior = self.snapshot.peer_sessions.authority_revision;
        match revoke_peer_session(&self.snapshot.peer_sessions, request, now_ms) {
            Ok((next, topology)) => {
                self.snapshot.peer_sessions = next;
                self.snapshot
                    .signed_topology_authorizations
                    .retain(|value| value.topology_authorization.session_id != request.session_id);
                let resulting = self.snapshot.peer_sessions.authority_revision;
                self.record(
                    ManifoldPeerRuntimeAuditKind::PeerSessionRevocation,
                    request.revocation_id.clone(),
                    prior,
                    resulting,
                    true,
                    None,
                )?;
                Ok(topology)
            }
            Err(reason) => {
                self.record(
                    ManifoldPeerRuntimeAuditKind::PeerSessionRevocation,
                    request.revocation_id.clone(),
                    prior,
                    prior,
                    false,
                    Some(reason.clone()),
                )?;
                Err(ManifoldPeerRuntimeHostError::Authority(reason))
            }
        }
    }

    /// Reviews a bounded N-peer mesh proposal against host-owned peer status.
    ///
    /// # Errors
    ///
    /// Returns event-sequence exhaustion before invoking mesh authority.
    pub fn review_peer_mesh(
        &mut self,
        proposal: ManifoldPeerMeshProposal,
        now_ms: u64,
    ) -> Result<ManifoldPeerMeshDecision, ManifoldPeerRuntimeHostError> {
        self.ensure_family_enabled(ManifoldPeerRuntimeAuthorityFamily::PeerMesh)?;
        self.ensure_event_capacity()?;
        let member_ids = proposal
            .member_peer_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let mut accepted_pair_evidence = self
            .snapshot
            .rendezvous
            .accepted_receipts
            .iter()
            .filter(|receipt| {
                receipt.peer_ids.len() == 2
                    && receipt
                        .peer_ids
                        .iter()
                        .all(|peer_id| member_ids.contains(peer_id))
                    && validate_current_rendezvous_receipt(
                        &self.snapshot.rendezvous,
                        &self.snapshot.enrollment,
                        receipt,
                        &receipt.peer_ids[0],
                        &receipt.peer_ids[1],
                        now_ms,
                    )
                    .is_ok()
            })
            .map(|receipt| ManifoldPeerMeshPairEvidence {
                receipt_id: receipt.receipt_id.clone(),
                peer_ids: receipt.peer_ids.clone(),
                signer_key_ids: receipt.signer_key_ids.clone(),
                evidence_sha256: receipt.nonce_sha256.clone(),
                pair_authority_revision: receipt.resulting_authority_revision,
                pair_authority_epoch: receipt.coordinator_epoch,
                topology_contract_id: receipt.topology_contract_id.clone(),
                expires_at_ms: receipt.expires_at_ms,
            })
            .collect::<Vec<_>>();
        accepted_pair_evidence.sort_by(|left, right| left.receipt_id.cmp(&right.receipt_id));
        let case = ManifoldPeerMeshReviewCase {
            schema_id: schema(rusty_manifold_peer::PEER_MESH_REVIEW_SCHEMA),
            accepted_peers: self.snapshot.accepted_peers.clone(),
            accepted_pair_evidence,
            current_state: self.snapshot.peer_mesh.clone(),
            proposal,
            trusted_proposer_ids: self.snapshot.trust_policy.trusted_mesh_proposer_ids.clone(),
            now_ms,
        };
        let decision = review_and_apply_peer_mesh(&case);
        if let Some(state) = decision.accepted_state.clone() {
            self.snapshot.peer_mesh = state;
        }
        self.record(
            ManifoldPeerRuntimeAuditKind::PeerMesh,
            case.proposal.proposal_id.clone(),
            decision.audit_event.prior_authority_revision,
            decision.audit_event.resulting_authority_revision,
            decision.applied,
            rejection_code(decision.rejection_reason.as_ref()),
        )?;
        Ok(decision)
    }

    /// Reviews and retains one exact product-bound media-session decision.
    /// Static descriptor validation alone is never accepted as runtime
    /// authority; direct leases resolve this retained state internally.
    ///
    /// # Errors
    ///
    /// Returns event-sequence exhaustion before invoking the pure authority.
    pub fn review_media_session_acceptance(
        &mut self,
        request: &ManifoldMediaSessionAcceptanceRequest,
        command_request: &ManifoldRuntimeCommandRequest,
        now_ms: u64,
    ) -> Result<ManifoldMediaSessionAcceptanceReceipt, ManifoldPeerRuntimeHostError> {
        self.ensure_runtime_lease_does_not_require_live_broker(
            command_request.lease_id.as_ref(),
            "media-session acceptance",
        )?;
        self.review_media_session_acceptance_inner(request, command_request, now_ms)
    }

    /// Reviews a media-session acceptance after rejoining any active
    /// Broker-derived Runtime Host lease to the current live Broker evidence.
    ///
    /// # Errors
    ///
    /// Returns a host error when the Broker-derived lease is no longer current
    /// or when normal media-session review fails.
    pub fn review_media_session_acceptance_with_live_broker_runtime(
        &mut self,
        broker_runtime: &ManifoldBrokerRuntime,
        request: &ManifoldMediaSessionAcceptanceRequest,
        command_request: &ManifoldRuntimeCommandRequest,
        now_ms: u64,
    ) -> Result<ManifoldMediaSessionAcceptanceReceipt, ManifoldPeerRuntimeHostError> {
        self.validate_runtime_lease_against_live_broker(
            broker_runtime,
            command_request.lease_id.as_ref(),
        )?;
        self.review_media_session_acceptance_inner(request, command_request, now_ms)
    }

    fn review_media_session_acceptance_inner(
        &mut self,
        request: &ManifoldMediaSessionAcceptanceRequest,
        command_request: &ManifoldRuntimeCommandRequest,
        now_ms: u64,
    ) -> Result<ManifoldMediaSessionAcceptanceReceipt, ManifoldPeerRuntimeHostError> {
        self.ensure_family_enabled(ManifoldPeerRuntimeAuthorityFamily::MediaSession)?;
        self.ensure_event_capacity()?;
        let mut runtime =
            ManifoldRuntimeHost::from_snapshot(self.snapshot.media_command_runtime.clone())
                .map_err(|error| ManifoldPeerRuntimeHostError::Authority(error.to_string()))?;
        let dispatch = runtime.review_command(command_request, now_ms);
        let application = runtime.apply_dispatch(command_request, &dispatch, now_ms);
        self.snapshot.media_command_runtime = runtime.snapshot().clone();
        let context = ManifoldMediaSessionRuntimeCommandContext {
            runtime_host_id: &self.snapshot.media_command_runtime.host_id,
            live_provider_epoch_id: &self.snapshot.provider_epoch_id,
            client_grants: &self.snapshot.trust_policy.media_client_grants,
            trusted_revoker_ids: &self.snapshot.trust_policy.trusted_media_revoker_ids,
            command_request,
            dispatch: &dispatch,
            application: &application,
        };
        let (next, receipt) = review_and_apply_media_session_acceptance(
            &self.snapshot.media_sessions,
            request,
            context,
            now_ms,
        );
        self.snapshot.media_sessions = next;
        self.record(
            ManifoldPeerRuntimeAuditKind::MediaSessionAcceptance,
            request.request_id.clone(),
            receipt.prior_authority_revision,
            receipt.resulting_authority_revision,
            receipt.accepted,
            rejection_code(receipt.rejection_reason.as_ref()),
        )?;
        Ok(receipt)
    }

    /// Consumes one bounded use in the owning live `BrokerRuntime` and, when
    /// accepted by the peer host, mints the corresponding short-lived inner
    /// media Runtime Host lease.
    /// A caller-supplied/deserialized mutation receipt is never accepted as
    /// authority. Preflight rejects before Broker mutation. Once a live Broker
    /// decision is exposed, its one-use consumption commits before peer-host
    /// composition so an error cannot turn the decision into a retry oracle.
    ///
    /// # Errors
    ///
    /// Returns before Broker mutation when family, capacity, replay,
    /// provenance, or current-state preflight rejects. A later composition
    /// error leaves the peer host unchanged but preserves Broker one-use
    /// consumption.
    pub fn apply_broker_media_command_and_admit_runtime_lease(
        &mut self,
        broker_runtime: &mut ManifoldBrokerRuntime,
        request: &ManifoldBrokerMutationRequest,
        now_ms: u64,
    ) -> Result<ManifoldPeerRuntimeBrokerLeaseAttempt, ManifoldPeerRuntimeHostError> {
        let mut next_host = self.clone();
        next_host.ensure_family_enabled(ManifoldPeerRuntimeAuthorityFamily::MediaSession)?;
        next_host.ensure_mutation_source_unused(
            &ManifoldPeerRuntimeAuditKind::BrokerLeaseAdmission,
            &request.admission_use_request_id,
        )?;
        next_host.ensure_event_capacity()?;
        next_host.preflight_broker_media_runtime_lease(broker_runtime, request, now_ms)?;

        let observed = broker_runtime
            .commit_mutation(
                request,
                now_ms,
                |receipt,
                 broker_evidence|
                 -> Result<
                    (
                        ManifoldPeerRuntimeHost,
                        ManifoldPeerRuntimeBrokerLeaseAttempt,
                    ),
                    ManifoldPeerRuntimeHostError,
                > {
                    if !receipt.admission_applied {
                        return Ok((
                        next_host,
                        broker_lease_attempt(
                            ManifoldPeerRuntimeBrokerLeaseAttemptOutcome::BrokerAdmissionRejected,
                            receipt.clone(),
                            None,
                            None,
                        ),
                    ));
                    }
                    if !receipt.applied {
                        let rejection = "outer_broker_command_rejected".to_owned();
                        next_host.record(
                            ManifoldPeerRuntimeAuditKind::BrokerLeaseAdmission,
                            request.admission_use_request_id.clone(),
                            next_host.snapshot.media_command_runtime.authority_revision,
                            next_host.snapshot.media_command_runtime.authority_revision,
                            false,
                            Some(rejection.clone()),
                        )?;
                        validate_snapshot(&next_host.snapshot)?;
                        return Ok((
                            next_host,
                            broker_lease_attempt(
                                ManifoldPeerRuntimeBrokerLeaseAttemptOutcome::BrokerCommandRejected,
                                receipt.clone(),
                                None,
                                Some(rejection),
                            ),
                        ));
                    }

                    let mut admitted_host = next_host.clone();
                    match admitted_host.admit_live_broker_media_receipt(
                        request,
                        receipt,
                        broker_evidence,
                        now_ms,
                    ) {
                        Ok(admission) => {
                            validate_snapshot(&admitted_host.snapshot)?;
                            Ok((
                                admitted_host,
                                broker_lease_attempt(
                                    ManifoldPeerRuntimeBrokerLeaseAttemptOutcome::LeaseAdmitted,
                                    receipt.clone(),
                                    Some(admission),
                                    None,
                                ),
                            ))
                        }
                        Err(error) => {
                            let rejection = error.to_string();
                            next_host.record(
                                ManifoldPeerRuntimeAuditKind::BrokerLeaseAdmission,
                                request.admission_use_request_id.clone(),
                                next_host.snapshot.media_command_runtime.authority_revision,
                                next_host.snapshot.media_command_runtime.authority_revision,
                                false,
                                Some(rejection.clone()),
                            )?;
                            validate_snapshot(&next_host.snapshot)?;
                            Ok((
                                next_host,
                                broker_lease_attempt(
                                    ManifoldPeerRuntimeBrokerLeaseAttemptOutcome::PeerLeaseRejected,
                                    receipt.clone(),
                                    None,
                                    Some(rejection),
                                ),
                            ))
                        }
                    }
                },
            )
            .map_err(ManifoldPeerRuntimeHostError::from)?;
        let (committed_host, attempt) = observed?;
        *self = committed_host;
        Ok(attempt)
    }

    fn preflight_broker_media_runtime_lease(
        &self,
        broker_runtime: &ManifoldBrokerRuntime,
        request: &ManifoldBrokerMutationRequest,
        now_ms: u64,
    ) -> Result<(), ManifoldPeerRuntimeHostError> {
        let evidence = broker_runtime.evidence();
        let config = broker_runtime.adapter_config();
        let bounded_use = evidence
            .pending_bounded_uses
            .iter()
            .find(|use_| use_.admission_use_request_id == request.admission_use_request_id)
            .ok_or_else(|| {
                ManifoldPeerRuntimeHostError::Authority(
                    "broker media preflight lacks a pending bounded use".to_owned(),
                )
            })?;
        let grant = self
            .snapshot
            .trust_policy
            .media_client_grants
            .iter()
            .find(|grant| {
                request.schema_id.as_str() == BROKER_MUTATION_REQUEST_SCHEMA
                    && request.provider_epoch_id == self.snapshot.provider_epoch_id
                    && evidence.provider_epoch_id == request.provider_epoch_id
                    && config.adapter_id == grant.broker_adapter_id
                    && config.authority_host_id == grant.broker_runtime_host_id
                    && config.product_lock_id == grant.broker_product_lock_id
                    && config.product_lock_fingerprint == grant.broker_product_lock_fingerprint
                    && config.product_lock_sha256 == grant.broker_product_lock_sha256
                    && request.token_id == bounded_use.token_id
                    && request.expected_admission_authority_revision
                        == bounded_use.admission_authority_revision
                    && request.command.command_id == grant.broker_command_id
                    && request.command.requester_id == grant.client_id
                    && request.command.lease_id.as_ref() == Some(&grant.broker_runtime_lease_id)
                    && bounded_use.identity == grant.broker_client_identity
                    && bounded_use.admission_grant_id == grant.admission_grant_id
                    && bounded_use.client_lock_id == grant.broker_client_lock_id
                    && bounded_use.client_lock_fingerprint == grant.broker_client_lock_fingerprint
                    && bounded_use.capability_id == grant.broker_capability_id
                    && bounded_use.expires_at_ms > now_ms
            })
            .ok_or_else(|| {
                ManifoldPeerRuntimeHostError::Authority(
                    "broker media preflight provenance does not match a client grant".to_owned(),
                )
            })?;
        if self.snapshot.broker_lease_admissions.len() >= MAX_PEER_RUNTIME_AUTHORITY_RECORDS
            || self
                .snapshot
                .broker_lease_admissions
                .iter()
                .any(|admission| {
                    admission.broker_receipt.admission_use_request_id
                        == request.admission_use_request_id
                })
            || self
                .snapshot
                .media_command_runtime
                .leases
                .iter()
                .any(|lease| lease.lease_id == grant.lease_id)
        {
            return Err(ManifoldPeerRuntimeHostError::Authority(
                "broker media preflight replay/capacity/active-lease conflict".to_owned(),
            ));
        }
        let lease = ManifoldRuntimeLease {
            lease_id: grant.lease_id.clone(),
            scope: self
                .snapshot
                .trust_policy
                .media_runtime_lease_scope_id
                .clone(),
            holder_id: grant.client_id.clone(),
            expires_at_ms: bounded_use
                .expires_at_ms
                .min(now_ms.saturating_add(120_000)),
            derivative_binding: Some(broker_runtime_derivative_binding(
                broker_runtime.provider_epoch_id(),
                request
                    .command
                    .lease_id
                    .as_ref()
                    .expect("validated Broker command lease"),
                &request.admission_use_request_id,
            )),
        };
        let mut runtime_snapshot = self.snapshot.media_command_runtime.clone();
        runtime_snapshot.leases.push(lease);
        runtime_snapshot
            .leases
            .sort_by(|left, right| left.lease_id.cmp(&right.lease_id));
        ManifoldRuntimeHost::from_snapshot(runtime_snapshot)
            .map_err(|error| ManifoldPeerRuntimeHostError::Authority(error.to_string()))?;
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn admit_live_broker_media_receipt(
        &mut self,
        request: &ManifoldBrokerMutationRequest,
        receipt: &ManifoldBrokerMutationReceipt,
        broker_evidence: &ManifoldBrokerRuntimeEvidence,
        now_ms: u64,
    ) -> Result<ManifoldPeerRuntimeBrokerLeaseAdmission, ManifoldPeerRuntimeHostError> {
        let bounded_use = receipt.bounded_use.as_ref().ok_or_else(|| {
            ManifoldPeerRuntimeHostError::Authority(
                "broker mutation lacks consumed bounded-use evidence".to_owned(),
            )
        })?;
        let adapter = receipt.adapter_receipt.as_ref().ok_or_else(|| {
            ManifoldPeerRuntimeHostError::Authority(
                "broker mutation lacks Runtime Host application evidence".to_owned(),
            )
        })?;
        let grant = self
            .snapshot
            .trust_policy
            .media_client_grants
            .iter()
            .find(|grant| {
                request.schema_id.as_str() == BROKER_MUTATION_REQUEST_SCHEMA
                    && receipt.schema_id.as_str() == BROKER_MUTATION_RECEIPT_SCHEMA
                    && broker_evidence.schema_id.as_str() == BROKER_RUNTIME_EVIDENCE_SCHEMA
                    && bounded_use.schema_id.as_str() == BROKER_BOUNDED_USE_SCHEMA
                    && receipt.applied
                    && receipt.admission_applied
                    && receipt.admission_rejection_reason.is_none()
                    && !receipt.local_acceptance_rules
                    && receipt.command_selected
                    && receipt.provider_epoch_id == self.snapshot.provider_epoch_id
                    && request.provider_epoch_id == receipt.provider_epoch_id
                    && broker_evidence.provider_epoch_id == receipt.provider_epoch_id
                    && receipt.admission_use_request_id == request.admission_use_request_id
                    && bounded_use.admission_use_request_id == request.admission_use_request_id
                    && bounded_use.token_id == request.token_id
                    && bounded_use.admission_authority_revision
                        == request.expected_admission_authority_revision
                    && receipt.admission_authority_revision
                        == broker_evidence.admission_snapshot.authority_revision
                    && receipt.authority_owner_id.as_str() == RUNTIME_HOST_AUTHORITY_OWNER
                    && adapter.schema_id.as_str() == BROKER_ADAPTER_RECEIPT_SCHEMA
                    && adapter.adapter_id == grant.broker_adapter_id
                    && matches!(
                        (&adapter.mode, &adapter.adapter_role),
                        (
                            ManifoldBrokerAdapterMode::Standalone,
                            ManifoldBrokerAdapterRole::ProcessTransportAdapter
                        ) | (
                            ManifoldBrokerAdapterMode::Embedded,
                            ManifoldBrokerAdapterRole::InProcessAdapter
                        )
                    )
                    && adapter.authority_owner_id.as_str() == RUNTIME_HOST_AUTHORITY_OWNER
                    && adapter.application.applied
                    && adapter.application.rejection_reason.is_none()
                    && adapter.dispatch.schema_id.as_str() == HOST_DISPATCH_RECEIPT_SCHEMA
                    && adapter.application.schema_id.as_str() == HOST_APPLICATION_RECEIPT_SCHEMA
                    && adapter.authority_host_id == grant.broker_runtime_host_id
                    && adapter.dispatch.authority_host_id == grant.broker_runtime_host_id
                    && adapter.application.authority_host_id == grant.broker_runtime_host_id
                    && adapter.product_lock_id == grant.broker_product_lock_id
                    && adapter.product_lock_fingerprint == grant.broker_product_lock_fingerprint
                    && adapter.product_lock_sha256 == grant.broker_product_lock_sha256
                    && request.command.schema_id.as_str() == HOST_COMMAND_REQUEST_SCHEMA
                    && request.command.command_id == grant.broker_command_id
                    && request.command.lease_id.as_ref() == Some(&grant.broker_runtime_lease_id)
                    && request.command.requester_id == grant.client_id
                    && bounded_use.identity == grant.broker_client_identity
                    && bounded_use.identity.client_id == grant.client_id
                    && bounded_use.admission_grant_id == grant.admission_grant_id
                    && bounded_use.client_lock_id == grant.broker_client_lock_id
                    && bounded_use.client_lock_fingerprint == grant.broker_client_lock_fingerprint
                    && bounded_use.capability_id == grant.broker_capability_id
                    && bounded_use.expires_at_ms > now_ms
                    && adapter.dispatch.request_id == request.command.request_id
                    && adapter.dispatch.command_id == request.command.command_id
                    && adapter.dispatch.params_digest == request.command.params_digest
                    && adapter.dispatch.reviewed_authority_revision
                        == request.command.expected_authority_revision
                    && adapter.dispatch.outcome == ManifoldRuntimeDispatchOutcome::Ready
                    && adapter.dispatch.rejection_reason.is_none()
                    && adapter.application.dispatch_id == adapter.dispatch.dispatch_id
                    && adapter.application.request_id == request.command.request_id
                    && adapter.application.params_digest == request.command.params_digest
                    && adapter.application.prior_authority_revision
                        == adapter.dispatch.reviewed_authority_revision
                    && broker_evidence.host_snapshot.host_id == grant.broker_runtime_host_id
                    && broker_evidence.host_snapshot.authority_revision
                        == adapter.application.resulting_authority_revision
                    && broker_evidence
                        .host_snapshot
                        .applied_request_ids
                        .contains(&request.command.request_id)
                    && broker_evidence
                        .consumed_bounded_use_ids
                        .contains(&request.admission_use_request_id)
                    && !broker_evidence.pending_bounded_uses.iter().any(|use_| {
                        use_.admission_use_request_id == request.admission_use_request_id
                    })
                    && broker_evidence
                        .admission_snapshot
                        .consumed_use_request_ids
                        .contains(&request.admission_use_request_id)
            })
            .ok_or_else(|| {
                ManifoldPeerRuntimeHostError::Authority(
                    "broker bounded use does not match a media client grant".to_owned(),
                )
            })?;
        if self.snapshot.broker_lease_admissions.len() >= MAX_PEER_RUNTIME_AUTHORITY_RECORDS
            || self
                .snapshot
                .broker_lease_admissions
                .iter()
                .any(|admission| {
                    admission.broker_receipt.admission_use_request_id
                        == receipt.admission_use_request_id
                })
            || self
                .snapshot
                .media_command_runtime
                .leases
                .iter()
                .any(|lease| lease.lease_id == grant.lease_id)
        {
            return Err(ManifoldPeerRuntimeHostError::Authority(
                "broker media lease admission replay/capacity conflict".to_owned(),
            ));
        }
        let lease = ManifoldRuntimeLease {
            lease_id: grant.lease_id.clone(),
            scope: self
                .snapshot
                .trust_policy
                .media_runtime_lease_scope_id
                .clone(),
            holder_id: grant.client_id.clone(),
            expires_at_ms: bounded_use
                .expires_at_ms
                .min(now_ms.saturating_add(120_000)),
            derivative_binding: Some(broker_runtime_derivative_binding(
                &receipt.provider_epoch_id,
                request
                    .command
                    .lease_id
                    .as_ref()
                    .expect("validated Broker command lease"),
                &receipt.admission_use_request_id,
            )),
        };
        let mut runtime_snapshot = self.snapshot.media_command_runtime.clone();
        runtime_snapshot.leases.push(lease.clone());
        runtime_snapshot
            .leases
            .sort_by(|left, right| left.lease_id.cmp(&right.lease_id));
        ManifoldRuntimeHost::from_snapshot(runtime_snapshot.clone())
            .map_err(|error| ManifoldPeerRuntimeHostError::Authority(error.to_string()))?;
        self.snapshot.media_command_runtime = runtime_snapshot;
        let admission = ManifoldPeerRuntimeBrokerLeaseAdmission {
            schema_id: schema(PEER_RUNTIME_BROKER_LEASE_ADMISSION_SCHEMA),
            broker_receipt: receipt.clone(),
            runtime_lease: lease.clone(),
            admitted_at_ms: now_ms,
            released_at_ms: None,
            release_id: None,
        };
        self.snapshot
            .broker_lease_admissions
            .push(admission.clone());
        self.record(
            ManifoldPeerRuntimeAuditKind::BrokerLeaseAdmission,
            receipt.admission_use_request_id.clone(),
            self.snapshot.media_command_runtime.authority_revision,
            self.snapshot.media_command_runtime.authority_revision,
            true,
            None,
        )?;
        Ok(admission)
    }

    /// Releases one dynamically admitted inner media lease after every media
    /// subject using it is no longer current.
    ///
    /// # Errors
    ///
    /// Returns a host error for disabled authority, replay/capacity, a missing
    /// or still-used generation, invalid time order, or damaged candidate state.
    pub fn release_media_runtime_lease(
        &mut self,
        lease_id: &DottedId,
        release_id: DottedId,
        now_ms: u64,
    ) -> Result<(), ManifoldPeerRuntimeHostError> {
        self.ensure_runtime_lease_does_not_require_live_broker(
            Some(lease_id),
            "media Runtime Host lease release",
        )?;
        self.release_media_runtime_lease_inner(lease_id, release_id, now_ms)
    }

    /// Releases a dynamically admitted media lease after rejoining it to the
    /// current live Broker authority.
    ///
    /// # Errors
    ///
    /// Returns a host error when the outer Broker lease is no longer current
    /// or when normal release validation fails.
    pub fn release_media_runtime_lease_with_live_broker_runtime(
        &mut self,
        broker_runtime: &ManifoldBrokerRuntime,
        lease_id: &DottedId,
        release_id: DottedId,
        now_ms: u64,
    ) -> Result<(), ManifoldPeerRuntimeHostError> {
        self.validate_runtime_lease_against_live_broker(broker_runtime, Some(lease_id))?;
        self.release_media_runtime_lease_inner(lease_id, release_id, now_ms)
    }

    fn release_media_runtime_lease_inner(
        &mut self,
        lease_id: &DottedId,
        release_id: DottedId,
        now_ms: u64,
    ) -> Result<(), ManifoldPeerRuntimeHostError> {
        self.ensure_family_enabled(ManifoldPeerRuntimeAuthorityFamily::MediaSession)?;
        self.ensure_mutation_source_unused(
            &ManifoldPeerRuntimeAuditKind::BrokerLeaseRelease,
            &release_id,
        )?;
        self.ensure_event_capacity()?;
        let mut next = self.clone();
        if next.snapshot.media_sessions.sessions.iter().any(|session| {
            session.runtime_lease_id == *lease_id
                && session.lifecycle_status
                    == rusty_manifold_media_session::ManifoldMediaSessionLifecycleStatus::Current
        }) {
            return Err(ManifoldPeerRuntimeHostError::Authority(
                "current media session still holds runtime lease".to_owned(),
            ));
        }
        let admission = next
            .snapshot
            .broker_lease_admissions
            .iter_mut()
            .find(|admission| {
                admission.runtime_lease.lease_id == *lease_id && admission.released_at_ms.is_none()
            })
            .ok_or_else(|| {
                ManifoldPeerRuntimeHostError::Authority(
                    "active broker-admitted media lease not found".to_owned(),
                )
            })?;
        if now_ms < admission.admitted_at_ms {
            return Err(ManifoldPeerRuntimeHostError::Authority(
                "broker-admitted media lease release predates admission".to_owned(),
            ));
        }
        admission.released_at_ms = Some(now_ms);
        admission.release_id = Some(release_id.clone());
        let mut runtime_snapshot = next.snapshot.media_command_runtime.clone();
        runtime_snapshot
            .leases
            .retain(|lease| lease.lease_id != *lease_id);
        ManifoldRuntimeHost::from_snapshot(runtime_snapshot.clone())
            .map_err(|error| ManifoldPeerRuntimeHostError::Authority(error.to_string()))?;
        next.snapshot.media_command_runtime = runtime_snapshot;
        next.record(
            ManifoldPeerRuntimeAuditKind::BrokerLeaseRelease,
            release_id,
            next.snapshot.media_command_runtime.authority_revision,
            next.snapshot.media_command_runtime.authority_revision,
            true,
            None,
        )?;
        validate_snapshot(&next.snapshot)?;
        *self = next;
        Ok(())
    }

    /// Joins one applied administrative revocation from current live Broker
    /// evidence and atomically tombstones every matching peer derivative.
    ///
    /// The caller supplies only identities and CAS expectations. The accepted
    /// lifecycle receipt and generic tombstone are read from `broker_runtime`
    /// during this call and copied into the durable peer receipt. Matching
    /// inner Runtime Host leases are removed, current media sessions and direct
    /// lanes are marked revoked, and source-neutral platform cleanup remains an
    /// explicit pending obligation.
    ///
    /// # Errors
    ///
    /// Returns a host error for replay, stale peer or Broker revisions, an
    /// absent/non-revocation Broker receipt, no active matching peer
    /// derivative, revision/capacity exhaustion, or a damaged candidate state.
    #[allow(clippy::too_many_lines)]
    pub fn converge_live_broker_control_lease_revocation(
        &mut self,
        broker_runtime: &ManifoldBrokerRuntime,
        request: &ManifoldPeerRuntimeBrokerLeaseRevocationConvergenceRequest,
    ) -> Result<
        ManifoldPeerRuntimeBrokerLeaseRevocationConvergenceReceipt,
        ManifoldPeerRuntimeHostError,
    > {
        self.ensure_family_enabled(ManifoldPeerRuntimeAuthorityFamily::MediaSession)?;
        self.ensure_event_capacity()?;
        if request.schema_id.as_str()
            != PEER_RUNTIME_BROKER_LEASE_REVOCATION_CONVERGENCE_REQUEST_SCHEMA
        {
            return Err(ManifoldPeerRuntimeHostError::Authority(
                "broker revocation convergence request schema mismatch".to_owned(),
            ));
        }
        if self
            .snapshot
            .broker_lease_revocation_convergences
            .iter()
            .any(|receipt| {
                receipt.convergence_id == request.convergence_id
                    || receipt.broker_lifecycle_receipt.lifecycle_request_id
                        == request.broker_lifecycle_request_id
            })
        {
            return Err(ManifoldPeerRuntimeHostError::ReplayedMutation(
                request.convergence_id.clone(),
            ));
        }
        if request.expected_peer_event_sequence != self.snapshot.event_sequence
            || request.expected_peer_provider_epoch_id != self.snapshot.provider_epoch_id
        {
            return Err(ManifoldPeerRuntimeHostError::Authority(
                "stale peer revocation convergence request".to_owned(),
            ));
        }
        self.ensure_mutation_source_unused(
            &ManifoldPeerRuntimeAuditKind::BrokerLeaseRevocationConvergence,
            &request.convergence_id,
        )?;
        if self.snapshot.broker_lease_revocation_convergences.len()
            >= MAX_PEER_RUNTIME_AUTHORITY_RECORDS
        {
            return Err(ManifoldPeerRuntimeHostError::AuthorityCapacityExhausted);
        }

        let broker_evidence = broker_runtime.evidence();
        let (broker_receipt, application, tombstone) =
            validated_live_broker_revocation(&broker_evidence, request)?;
        if broker_evidence.provider_epoch_id != self.snapshot.provider_epoch_id {
            return Err(ManifoldPeerRuntimeHostError::Authority(
                "peer and Broker provider epochs diverge".to_owned(),
            ));
        }
        let broker_revoked_at_ms =
            u64::try_from(tombstone.recorded_clock.wall_unix_ms).map_err(|_| {
                ManifoldPeerRuntimeHostError::Authority(
                    "Broker revocation clock predates the Unix epoch".to_owned(),
                )
            })?;
        if request.converged_at_ms < broker_revoked_at_ms {
            return Err(ManifoldPeerRuntimeHostError::Authority(
                "peer convergence predates authoritative Broker revocation".to_owned(),
            ));
        }

        let mut next = self.clone();
        let affected_admission_use_ids = next
            .snapshot
            .broker_lease_admissions
            .iter()
            .filter(|admission| {
                admission.released_at_ms.is_none()
                    && admission
                        .runtime_lease
                        .derivative_binding
                        .as_ref()
                        .is_some_and(|binding| {
                            binding.provider_epoch_id == broker_evidence.provider_epoch_id
                                && binding.upstream_control_lease_id
                                    == request.outer_control_lease_id
                        })
            })
            .map(|admission| admission.broker_receipt.admission_use_request_id.clone())
            .collect::<BTreeSet<_>>();
        if affected_admission_use_ids.is_empty() {
            return Err(ManifoldPeerRuntimeHostError::Authority(
                "active peer derivative for revoked Broker lease not found".to_owned(),
            ));
        }

        let removed_inner_runtime_lease_ids = next
            .snapshot
            .broker_lease_admissions
            .iter()
            .filter(|admission| {
                affected_admission_use_ids
                    .contains(&admission.broker_receipt.admission_use_request_id)
            })
            .map(|admission| admission.runtime_lease.lease_id.clone())
            .collect::<BTreeSet<_>>();
        if next
            .snapshot
            .broker_lease_admissions
            .iter()
            .filter(|admission| {
                affected_admission_use_ids
                    .contains(&admission.broker_receipt.admission_use_request_id)
            })
            .any(|admission| request.converged_at_ms < admission.admitted_at_ms)
        {
            return Err(ManifoldPeerRuntimeHostError::Authority(
                "broker revocation convergence predates inner admission".to_owned(),
            ));
        }
        let exact_inner_runtime_leases = next
            .snapshot
            .media_command_runtime
            .leases
            .iter()
            .filter(|lease| removed_inner_runtime_lease_ids.contains(&lease.lease_id))
            .cloned()
            .collect::<Vec<_>>();
        if exact_inner_runtime_leases.len() != removed_inner_runtime_lease_ids.len() {
            return Err(ManifoldPeerRuntimeHostError::Authority(
                "broker revocation derivative lease set is incomplete".to_owned(),
            ));
        }

        let prior_media_authority_revision = next.snapshot.media_sessions.authority_revision;
        let mut revoked_media_decision_ids = Vec::new();
        let mut cleanup_obligations = Vec::new();
        for session in &mut next.snapshot.media_sessions.sessions {
            if removed_inner_runtime_lease_ids.contains(&session.runtime_lease_id)
                && session.lifecycle_status == ManifoldMediaSessionLifecycleStatus::Current
            {
                if request.converged_at_ms < session.accepted_at_ms {
                    return Err(ManifoldPeerRuntimeHostError::Authority(
                        "broker revocation convergence predates media acceptance".to_owned(),
                    ));
                }
                session.lifecycle_status = ManifoldMediaSessionLifecycleStatus::Revoked;
                session.ended_at_ms = Some(request.converged_at_ms);
                session.ended_by_id = Some(request.convergence_id.clone());
                revoked_media_decision_ids.push(session.decision_id.clone());
                let descriptor = &session.product_binding.descriptor;
                cleanup_obligations.push(ManifoldPeerRuntimeMediaCleanupObligation {
                    schema_id: schema(PEER_RUNTIME_MEDIA_CLEANUP_OBLIGATION_SCHEMA),
                    session_decision_id: session.decision_id.clone(),
                    session_id: session.session_id.clone(),
                    platform_runtime_spec_id: session.platform_runtime_spec_id.clone(),
                    source_ids: descriptor.source_ids.clone(),
                    processor_ids: descriptor.processor_ids.clone(),
                    route_ids: descriptor.route_ids.clone(),
                    sink_ids: descriptor.sink_ids.clone(),
                    stream_ids: descriptor.stream_ids.clone(),
                });
            }
        }
        revoked_media_decision_ids.sort();
        cleanup_obligations
            .sort_by(|left, right| left.session_decision_id.cmp(&right.session_decision_id));
        if !revoked_media_decision_ids.is_empty() {
            next.snapshot.media_sessions.authority_revision =
                prior_media_authority_revision.next().ok_or_else(|| {
                    ManifoldPeerRuntimeHostError::Authority(
                        "media authority revision exhausted".to_owned(),
                    )
                })?;
            next.snapshot
                .media_sessions
                .applied_request_ids
                .push(request.convergence_id.clone());
            next.snapshot.media_sessions.applied_request_ids.sort();
        }
        let resulting_media_authority_revision = next.snapshot.media_sessions.authority_revision;

        let prior_direct_lane_authority_revision =
            next.snapshot.direct_lane_leases.authority_revision;
        let mut revoked_direct_lane_lease_ids = Vec::new();
        let mut direct_lane_changed = false;
        for lease in &mut next.snapshot.direct_lane_leases.leases {
            if removed_inner_runtime_lease_ids.contains(&lease.holder_runtime_lease_id)
                || lease
                    .media_session_decision_id
                    .as_ref()
                    .is_some_and(|decision_id| revoked_media_decision_ids.contains(decision_id))
            {
                if request.converged_at_ms < lease.valid_from_ms {
                    return Err(ManifoldPeerRuntimeHostError::Authority(
                        "broker revocation convergence predates direct-lane issuance".to_owned(),
                    ));
                }
                revoked_direct_lane_lease_ids.push(lease.lease_id.clone());
                if !lease.revoked {
                    lease.revoked = true;
                    direct_lane_changed = true;
                }
            }
        }
        revoked_direct_lane_lease_ids.sort();
        if direct_lane_changed {
            next.snapshot.direct_lane_leases.authority_revision =
                prior_direct_lane_authority_revision.next().ok_or_else(|| {
                    ManifoldPeerRuntimeHostError::Authority(
                        "direct-lane authority revision exhausted".to_owned(),
                    )
                })?;
            next.snapshot
                .direct_lane_leases
                .applied_request_ids
                .push(request.convergence_id.clone());
            next.snapshot.direct_lane_leases.applied_request_ids.sort();
        }
        let resulting_direct_lane_authority_revision =
            next.snapshot.direct_lane_leases.authority_revision;

        for admission in &mut next.snapshot.broker_lease_admissions {
            if affected_admission_use_ids
                .contains(&admission.broker_receipt.admission_use_request_id)
            {
                admission.released_at_ms = Some(request.converged_at_ms);
                admission.release_id = Some(request.convergence_id.clone());
            }
        }
        let mut media_command_runtime =
            ManifoldRuntimeHost::from_snapshot(next.snapshot.media_command_runtime.clone())
                .map_err(|error| ManifoldPeerRuntimeHostError::Authority(error.to_string()))?;
        let upstream_transition =
            broker_receipt
                .authority_transition
                .as_ref()
                .ok_or_else(|| {
                    ManifoldPeerRuntimeHostError::Authority(
                        "validated live revocation lost its transition".to_owned(),
                    )
                })?;
        let upstream_revocation_proof =
            ManifoldRuntimeUpstreamRevocationProof::from_accepted_application(
                next.snapshot.provider_epoch_id.clone(),
                upstream_transition.prior_authority_snapshot.clone(),
                application.clone(),
            )
            .map_err(|error| ManifoldPeerRuntimeHostError::Authority(error.to_string()))?;
        let inner_runtime_lease_revocation_receipt = media_command_runtime
            .apply_derivative_lease_revocation(&ManifoldRuntimeDerivativeLeaseRevocationRequest {
                schema_id: schema(HOST_DERIVATIVE_LEASE_REVOCATION_REQUEST_SCHEMA),
                revocation_id: derived("revocation.runtime", &request.convergence_id),
                convergence_id: request.convergence_id.clone(),
                expected_host_authority_revision: next
                    .snapshot
                    .media_command_runtime
                    .authority_revision,
                upstream_revocation_proof,
                exact_leases: exact_inner_runtime_leases,
            });
        if !inner_runtime_lease_revocation_receipt.applied {
            return Err(ManifoldPeerRuntimeHostError::Authority(format!(
                "inner Runtime Host derivative revocation rejected: {:?}",
                inner_runtime_lease_revocation_receipt.rejection_reason
            )));
        }
        inner_runtime_lease_revocation_receipt
            .validate_against_snapshot(media_command_runtime.snapshot())
            .map_err(|error| ManifoldPeerRuntimeHostError::Authority(error.to_string()))?;
        next.snapshot.media_command_runtime = media_command_runtime.snapshot().clone();

        let prior_peer_event_sequence = next.snapshot.event_sequence;
        let resulting_peer_event_sequence = prior_peer_event_sequence
            .checked_add(1)
            .ok_or(ManifoldPeerRuntimeHostError::EventSequenceExhausted)?;
        let platform_cleanup_pending = !cleanup_obligations.is_empty();
        let receipt = ManifoldPeerRuntimeBrokerLeaseRevocationConvergenceReceipt {
            schema_id: schema(PEER_RUNTIME_BROKER_LEASE_REVOCATION_CONVERGENCE_RECEIPT_SCHEMA),
            convergence_id: request.convergence_id.clone(),
            peer_host_id: next.snapshot.host_id.clone(),
            peer_provider_epoch_id: next.snapshot.provider_epoch_id.clone(),
            broker_lifecycle_receipt: broker_receipt.clone(),
            outer_control_lease_tombstone: tombstone.clone(),
            inner_runtime_lease_revocation_receipt,
            prior_peer_event_sequence,
            resulting_peer_event_sequence,
            converged_at_ms: request.converged_at_ms,
            prior_media_authority_revision,
            resulting_media_authority_revision,
            prior_direct_lane_authority_revision,
            resulting_direct_lane_authority_revision,
            affected_broker_admission_use_ids: affected_admission_use_ids.into_iter().collect(),
            removed_inner_runtime_lease_ids: removed_inner_runtime_lease_ids.into_iter().collect(),
            revoked_media_decision_ids,
            revoked_direct_lane_lease_ids,
            cleanup_obligations,
            platform_cleanup_pending,
            applied: true,
        };
        next.snapshot
            .broker_lease_revocation_convergences
            .push(receipt.clone());
        next.record(
            ManifoldPeerRuntimeAuditKind::BrokerLeaseRevocationConvergence,
            request.convergence_id.clone(),
            application.from_authority_revision,
            tombstone.revoked_authority_revision,
            true,
            None,
        )?;
        validate_snapshot(&next.snapshot)?;
        validate_live_broker_restoration(&next.snapshot, &broker_evidence)?;
        *self = next;
        Ok(receipt)
    }

    /// Retains terminal platform cleanup evidence for one exact Broker
    /// revocation convergence.
    ///
    /// This closes only when the request names every retained cleanup
    /// obligation exactly. The platform evidence digest remains an explicit
    /// deployment-owner attestation; this source-only host never claims to
    /// inspect platform cleanup itself.
    ///
    /// # Errors
    ///
    /// Returns a host error for replay, stale peer state, incomplete
    /// obligations, malformed evidence, or a live Broker mismatch.
    pub fn complete_broker_lease_revocation_cleanup(
        &mut self,
        broker_runtime: &ManifoldBrokerRuntime,
        request: &ManifoldPeerRuntimeBrokerLeaseRevocationCleanupCompletionRequest,
    ) -> Result<
        ManifoldPeerRuntimeBrokerLeaseRevocationCleanupCompletionReceipt,
        ManifoldPeerRuntimeHostError,
    > {
        self.ensure_family_enabled(ManifoldPeerRuntimeAuthorityFamily::MediaSession)?;
        self.ensure_event_capacity()?;
        if request.schema_id.as_str()
            != PEER_RUNTIME_BROKER_LEASE_REVOCATION_CLEANUP_COMPLETION_REQUEST_SCHEMA
            || !strictly_sorted_unique(request.completed_session_decision_ids.iter())
            || !valid_sha256(&request.platform_cleanup_receipt_sha256)
        {
            return Err(ManifoldPeerRuntimeHostError::Authority(
                "broker revocation cleanup completion request mismatch".to_owned(),
            ));
        }
        if self
            .snapshot
            .broker_lease_revocation_cleanup_completions
            .iter()
            .any(|receipt| {
                receipt.completion_id == request.completion_id
                    || receipt.convergence_id == request.convergence_id
            })
        {
            return Err(ManifoldPeerRuntimeHostError::ReplayedMutation(
                request.completion_id.clone(),
            ));
        }
        if request.expected_peer_event_sequence != self.snapshot.event_sequence {
            return Err(ManifoldPeerRuntimeHostError::Authority(
                "stale broker revocation cleanup completion request".to_owned(),
            ));
        }
        let convergence = self
            .snapshot
            .broker_lease_revocation_convergences
            .iter()
            .find(|receipt| receipt.convergence_id == request.convergence_id)
            .ok_or_else(|| {
                ManifoldPeerRuntimeHostError::Authority(
                    "broker revocation convergence not found".to_owned(),
                )
            })?;
        let expected_session_decision_ids = convergence
            .cleanup_obligations
            .iter()
            .map(|obligation| obligation.session_decision_id.clone())
            .collect::<Vec<_>>();
        if request.completed_session_decision_ids != expected_session_decision_ids {
            return Err(ManifoldPeerRuntimeHostError::Authority(
                "terminal cleanup does not close every retained obligation".to_owned(),
            ));
        }
        let broker_evidence = broker_runtime.evidence();
        validate_live_broker_restoration(&self.snapshot, &broker_evidence)?;

        let prior_peer_event_sequence = self.snapshot.event_sequence;
        let resulting_peer_event_sequence = prior_peer_event_sequence
            .checked_add(1)
            .ok_or(ManifoldPeerRuntimeHostError::EventSequenceExhausted)?;
        let receipt = ManifoldPeerRuntimeBrokerLeaseRevocationCleanupCompletionReceipt {
            schema_id: schema(
                PEER_RUNTIME_BROKER_LEASE_REVOCATION_CLEANUP_COMPLETION_RECEIPT_SCHEMA,
            ),
            completion_id: request.completion_id.clone(),
            convergence_id: request.convergence_id.clone(),
            peer_host_id: self.snapshot.host_id.clone(),
            peer_provider_epoch_id: self.snapshot.provider_epoch_id.clone(),
            prior_peer_event_sequence,
            resulting_peer_event_sequence,
            completed_obligations: convergence.cleanup_obligations.clone(),
            platform_cleanup_receipt_sha256: request.platform_cleanup_receipt_sha256.clone(),
            completed: true,
        };
        let mut next = self.clone();
        next.snapshot
            .broker_lease_revocation_cleanup_completions
            .push(receipt.clone());
        next.record(
            ManifoldPeerRuntimeAuditKind::BrokerLeaseRevocationCleanupCompletion,
            request.completion_id.clone(),
            convergence.resulting_media_authority_revision,
            convergence.resulting_media_authority_revision,
            true,
            None,
        )?;
        validate_snapshot(&next.snapshot)?;
        validate_live_broker_restoration(&next.snapshot, &broker_evidence)?;
        *self = next;
        Ok(receipt)
    }

    /// Generates the deterministic Broker retaining-consumer acknowledgement
    /// only from durable terminal cleanup evidence.
    ///
    /// # Errors
    ///
    /// Returns a host error until every cleanup obligation is complete or when
    /// the retained peer evidence no longer joins the current live Broker
    /// barrier exactly.
    pub fn broker_revocation_consumer_acknowledgement(
        &self,
        broker_runtime: &ManifoldBrokerRuntime,
        convergence_id: &DottedId,
    ) -> Result<
        ManifoldBrokerControlLeaseRevocationConsumerAcknowledgement,
        ManifoldPeerRuntimeHostError,
    > {
        let broker_evidence = broker_runtime.evidence();
        validate_live_broker_restoration(&self.snapshot, &broker_evidence)?;
        let convergence = self
            .snapshot
            .broker_lease_revocation_convergences
            .iter()
            .find(|receipt| &receipt.convergence_id == convergence_id)
            .ok_or_else(|| {
                ManifoldPeerRuntimeHostError::Authority(
                    "broker revocation convergence not found".to_owned(),
                )
            })?;
        let completion = self
            .snapshot
            .broker_lease_revocation_cleanup_completions
            .iter()
            .find(|receipt| &receipt.convergence_id == convergence_id)
            .ok_or_else(|| {
                ManifoldPeerRuntimeHostError::Authority(
                    "terminal platform cleanup is still pending".to_owned(),
                )
            })?;
        let application_id = &convergence
            .inner_runtime_lease_revocation_receipt
            .upstream_revocation_application_id;
        let lease_id = &convergence
            .outer_control_lease_tombstone
            .revoked_lease
            .lease_id;
        let barrier = broker_evidence
            .control_lease_revocation_barriers
            .iter()
            .find(|barrier| {
                barrier.lease_id == *lease_id
                    && barrier.revocation_application_id == *application_id
                    && barrier.state == ManifoldBrokerControlLeaseRevocationBarrierState::Converged
            })
            .ok_or_else(|| {
                ManifoldPeerRuntimeHostError::Authority(
                    "live Broker revocation barrier differs from peer completion".to_owned(),
                )
            })?;
        let acknowledgement = ManifoldBrokerControlLeaseRevocationConsumerAcknowledgement {
            schema_id: schema(BROKER_CONTROL_LEASE_REVOCATION_CONSUMER_ACKNOWLEDGEMENT_SCHEMA),
            acknowledgement_id: derived("acknowledgement.peer-runtime", &completion.completion_id),
            provider_epoch_id: self.snapshot.provider_epoch_id.clone(),
            barrier_id: barrier.barrier_id.clone(),
            revocation_application_id: application_id.clone(),
            lease_id: lease_id.clone(),
            consumer_kind: ManifoldBrokerControlLeaseRevocationConsumerKind::PeerRuntimeHost,
            consumer_id: self.snapshot.host_id.clone(),
            consumer_convergence_receipt_sha256: domain_separated_digest(
                PEER_RUNTIME_CONVERGENCE_RECEIPT_DIGEST_DOMAIN,
                convergence,
            )?,
            terminal_cleanup_receipt_sha256: domain_separated_digest(
                PEER_RUNTIME_TERMINAL_CLEANUP_RECEIPT_DIGEST_DOMAIN,
                completion,
            )?,
        };
        if let Some(retained) = broker_evidence
            .control_lease_revocation_consumer_acknowledgements
            .iter()
            .find(|retained| {
                retained.barrier_id == acknowledgement.barrier_id
                    && retained.consumer_kind == acknowledgement.consumer_kind
            })
        {
            if retained != &acknowledgement {
                return Err(ManifoldPeerRuntimeHostError::Authority(
                    "live Broker retained a different peer consumer acknowledgement".to_owned(),
                ));
            }
        }
        Ok(acknowledgement)
    }

    /// Advances this peer host across one exact drained Broker epoch rollover.
    ///
    /// The caller supplies the immutable Broker evidence captured immediately
    /// before rollover, the exact Broker rollover receipt, and the resulting
    /// live Broker runtime. The peer retains all historical joins and replay
    /// guards, checkpoints their source-epoch digest and the complete audit
    /// prefix, then advances to the Broker's fresh provider epoch atomically.
    ///
    /// # Errors
    ///
    /// Returns without mutation unless the source peer/Broker join is current,
    /// every source-epoch convergence has terminal Broker acknowledgement, the
    /// Broker receipt closes over the exact source/result evidence, and the
    /// resulting peer snapshot restores against the fresh Broker epoch.
    pub fn rollover_drained_broker_provider_epoch(
        &mut self,
        source_broker_evidence: &ManifoldBrokerRuntimeEvidence,
        broker_rollover_receipt: &ManifoldBrokerRuntimeEpochRolloverReceipt,
        resulting_broker_runtime: &ManifoldBrokerRuntime,
    ) -> Result<ManifoldPeerRuntimeBrokerEpochRolloverReceipt, ManifoldPeerRuntimeHostError> {
        self.ensure_event_capacity()?;
        let resulting_broker_evidence = resulting_broker_runtime.evidence();
        validate_live_broker_restoration(&self.snapshot, source_broker_evidence)?;
        validate_broker_epoch_rollover_checkpoint(
            source_broker_evidence,
            broker_rollover_receipt,
            &resulting_broker_evidence,
        )?;
        if self.snapshot.provider_epoch_id != broker_rollover_receipt.source_provider_epoch_id
            || self.snapshot.broker_epoch_rollovers.iter().any(|receipt| {
                receipt.broker_rollover_receipt == *broker_rollover_receipt
                    || receipt.resulting_provider_epoch_id
                        == broker_rollover_receipt.resulting_provider_epoch_id
            })
            || self.snapshot.media_sessions.sessions.iter().any(|session| {
                session.lifecycle_status == ManifoldMediaSessionLifecycleStatus::Current
            })
        {
            return Err(ManifoldPeerRuntimeHostError::Authority(
                "peer Broker epoch rollover is stale, replayed, or not drained".to_owned(),
            ));
        }
        validate_source_epoch_consumer_acknowledgements(&self.snapshot, source_broker_evidence)?;

        let source_provider_epoch_id = self.snapshot.provider_epoch_id.clone();
        let resulting_provider_epoch_id =
            broker_rollover_receipt.resulting_provider_epoch_id.clone();
        let rollover_id = derived(
            "rollover.peer-runtime",
            &broker_rollover_receipt.resulting_provider_epoch_id,
        );
        self.ensure_mutation_source_unused(
            &ManifoldPeerRuntimeAuditKind::BrokerEpochRollover,
            &rollover_id,
        )?;
        let (
            checkpointed_peer_broker_state_sha256,
            checkpointed_broker_lease_admission_count,
            checkpointed_revocation_convergence_count,
            checkpointed_cleanup_completion_count,
        ) = peer_broker_epoch_state_checkpoint(&self.snapshot, &source_provider_epoch_id)?;
        let checkpointed_peer_audit_event_count = self.snapshot.audit_events.len();
        let checkpointed_peer_audit_prefix_sha256 = domain_separated_digest(
            PEER_RUNTIME_BROKER_EPOCH_AUDIT_DIGEST_DOMAIN,
            &self.snapshot.audit_events,
        )?;
        let prior_peer_event_sequence = self.snapshot.event_sequence;
        let resulting_peer_event_sequence = prior_peer_event_sequence
            .checked_add(1)
            .ok_or(ManifoldPeerRuntimeHostError::EventSequenceExhausted)?;
        let receipt = ManifoldPeerRuntimeBrokerEpochRolloverReceipt {
            schema_id: schema(PEER_RUNTIME_BROKER_EPOCH_ROLLOVER_RECEIPT_SCHEMA),
            rollover_id: rollover_id.clone(),
            peer_host_id: self.snapshot.host_id.clone(),
            source_provider_epoch_id,
            resulting_provider_epoch_id: resulting_provider_epoch_id.clone(),
            broker_rollover_receipt: broker_rollover_receipt.clone(),
            checkpointed_peer_broker_state_sha256,
            checkpointed_broker_lease_admission_count,
            checkpointed_revocation_convergence_count,
            checkpointed_cleanup_completion_count,
            checkpointed_peer_audit_prefix_sha256,
            checkpointed_peer_audit_event_count,
            prior_peer_event_sequence,
            resulting_peer_event_sequence,
            applied: true,
        };

        let mut next = self.clone();
        next.snapshot.provider_epoch_id = resulting_provider_epoch_id;
        next.snapshot.broker_epoch_rollovers.push(receipt.clone());
        let unchanged_revision = next.snapshot.media_command_runtime.authority_revision;
        next.record(
            ManifoldPeerRuntimeAuditKind::BrokerEpochRollover,
            rollover_id,
            unchanged_revision,
            unchanged_revision,
            true,
            None,
        )?;
        validate_snapshot(&next.snapshot)?;
        validate_live_broker_restoration(&next.snapshot, &resulting_broker_evidence)?;
        *self = next;
        Ok(receipt)
    }

    /// Applies an exact Runtime Host accepted stop/revoke command.
    ///
    /// # Errors
    ///
    /// Returns a host error for disabled authority, exhausted capacity, or a
    /// rejected command-bound media lifecycle mutation.
    pub fn review_media_session_termination(
        &mut self,
        request: &ManifoldMediaSessionTerminationRequest,
        command_request: &ManifoldRuntimeCommandRequest,
        now_ms: u64,
    ) -> Result<ManifoldMediaSessionMutationReceipt, ManifoldPeerRuntimeHostError> {
        self.ensure_runtime_lease_does_not_require_live_broker(
            self.media_runtime_lease_for_decision(Some(&request.decision_id)),
            "media-session termination",
        )?;
        self.review_media_session_termination_inner(request, command_request, now_ms)
    }

    /// Applies a media termination after rejoining any Broker-derived session
    /// lease to current live Broker evidence.
    ///
    /// # Errors
    ///
    /// Returns a host error when the outer Broker lease is no longer current
    /// or when normal media termination review fails.
    pub fn review_media_session_termination_with_live_broker_runtime(
        &mut self,
        broker_runtime: &ManifoldBrokerRuntime,
        request: &ManifoldMediaSessionTerminationRequest,
        command_request: &ManifoldRuntimeCommandRequest,
        now_ms: u64,
    ) -> Result<ManifoldMediaSessionMutationReceipt, ManifoldPeerRuntimeHostError> {
        self.validate_runtime_lease_against_live_broker(
            broker_runtime,
            self.media_runtime_lease_for_decision(Some(&request.decision_id)),
        )?;
        self.review_media_session_termination_inner(request, command_request, now_ms)
    }

    fn review_media_session_termination_inner(
        &mut self,
        request: &ManifoldMediaSessionTerminationRequest,
        command_request: &ManifoldRuntimeCommandRequest,
        now_ms: u64,
    ) -> Result<ManifoldMediaSessionMutationReceipt, ManifoldPeerRuntimeHostError> {
        self.ensure_family_enabled(ManifoldPeerRuntimeAuthorityFamily::MediaSession)?;
        self.ensure_event_capacity()?;
        let mut runtime =
            ManifoldRuntimeHost::from_snapshot(self.snapshot.media_command_runtime.clone())
                .map_err(|error| ManifoldPeerRuntimeHostError::Authority(error.to_string()))?;
        let dispatch = runtime.review_command(command_request, now_ms);
        let application = runtime.apply_dispatch(command_request, &dispatch, now_ms);
        self.snapshot.media_command_runtime = runtime.snapshot().clone();
        let context = ManifoldMediaSessionRuntimeCommandContext {
            runtime_host_id: &self.snapshot.media_command_runtime.host_id,
            live_provider_epoch_id: &self.snapshot.provider_epoch_id,
            client_grants: &self.snapshot.trust_policy.media_client_grants,
            trusted_revoker_ids: &self.snapshot.trust_policy.trusted_media_revoker_ids,
            command_request,
            dispatch: &dispatch,
            application: &application,
        };
        let (next, receipt) = review_and_apply_media_session_termination(
            &self.snapshot.media_sessions,
            request,
            context,
            now_ms,
        );
        self.snapshot.media_sessions = next;
        self.record(
            ManifoldPeerRuntimeAuditKind::MediaSessionTermination,
            request.request_id.clone(),
            receipt.prior_authority_revision,
            receipt.resulting_authority_revision,
            receipt.applied,
            rejection_code(receipt.rejection_reason.as_ref()),
        )?;
        Ok(receipt)
    }

    /// Expires current media decisions whose subject deadlines passed.
    ///
    /// # Errors
    ///
    /// Returns a host error for disabled authority, exhausted capacity, or a
    /// rejected expiry sweep.
    pub fn expire_media_sessions(
        &mut self,
        sweep_id: DottedId,
        expected_authority_revision: Revision,
        now_ms: u64,
    ) -> Result<ManifoldMediaSessionMutationReceipt, ManifoldPeerRuntimeHostError> {
        self.ensure_family_enabled(ManifoldPeerRuntimeAuthorityFamily::MediaSession)?;
        self.ensure_event_capacity()?;
        let (next, receipt) = expire_media_sessions(
            &self.snapshot.media_sessions,
            sweep_id.clone(),
            expected_authority_revision,
            now_ms,
        );
        self.snapshot.media_sessions = next;
        self.record(
            ManifoldPeerRuntimeAuditKind::MediaSessionExpiry,
            sweep_id,
            receipt.prior_authority_revision,
            receipt.resulting_authority_revision,
            receipt.applied,
            rejection_code(receipt.rejection_reason.as_ref()),
        )?;
        Ok(receipt)
    }

    /// Emits the exact current subject-scoped media validation receipt used by
    /// Quest/platform adoption. Unrelated media mutations do not stale it.
    #[must_use]
    pub fn validate_media_session(
        &self,
        decision_id: &DottedId,
        now_ms: u64,
    ) -> ManifoldMediaSessionCurrentReceipt {
        let mut receipt = validate_current_media_session(
            &self.snapshot.media_sessions,
            decision_id,
            &self.snapshot.provider_epoch_id,
            now_ms,
        );
        if receipt.current
            && receipt.session.as_ref().is_some_and(|session| {
                self.active_broker_admission_for_runtime_lease(&session.runtime_lease_id)
                    .is_some()
            })
        {
            receipt.current = false;
            receipt.rejection_reason = Some(
                rusty_manifold_media_session::ManifoldMediaSessionAcceptanceRejectionReason::SessionNotCurrent,
            );
        }
        receipt
    }

    /// Emits a current media-session receipt after rejoining a
    /// Broker-derived Runtime Host lease to current live Broker evidence.
    ///
    /// # Errors
    ///
    /// Returns a host error when a Broker-derived lease is no longer current.
    pub fn validate_media_session_with_live_broker_runtime(
        &self,
        broker_runtime: &ManifoldBrokerRuntime,
        decision_id: &DottedId,
        now_ms: u64,
    ) -> Result<ManifoldMediaSessionCurrentReceipt, ManifoldPeerRuntimeHostError> {
        let receipt = validate_current_media_session(
            &self.snapshot.media_sessions,
            decision_id,
            &self.snapshot.provider_epoch_id,
            now_ms,
        );
        if let Some(session) = receipt.session.as_ref().filter(|_| receipt.current) {
            self.validate_runtime_lease_against_live_broker(
                broker_runtime,
                Some(&session.runtime_lease_id),
            )?;
        }
        Ok(receipt)
    }

    /// Emits a subject-scoped current peer-session/topology receipt after
    /// rechecking live peer status, signer keys, reciprocal receipt, expiry,
    /// and revocation. Unrelated authority mutations do not stale the subject.
    #[must_use]
    pub fn validate_peer_session(
        &self,
        session_id: &DottedId,
        now_ms: u64,
    ) -> ManifoldPeerSessionCurrentReceipt {
        validate_current_peer_session(
            &self.snapshot.accepted_peers,
            &self.snapshot.enrollment,
            &self.snapshot.rendezvous,
            &self.snapshot.peer_sessions,
            &self.snapshot.signed_topology_authorizations,
            session_id,
            now_ms,
        )
    }

    /// Expires mesh members through the pure mesh mutation authority.
    ///
    /// # Errors
    ///
    /// Returns a host error for a replayed sweep, mesh failure, or exhausted
    /// audit sequence.
    pub fn expire_peer_mesh(
        &mut self,
        sweep_id: DottedId,
        now_ms: u64,
    ) -> Result<ManifoldPeerMeshMutationReceipt, ManifoldPeerRuntimeHostError> {
        self.ensure_family_enabled(ManifoldPeerRuntimeAuthorityFamily::PeerMesh)?;
        self.ensure_mutation_source_unused(
            &ManifoldPeerRuntimeAuditKind::PeerMeshExpiry,
            &sweep_id,
        )?;
        self.ensure_event_capacity()?;
        let prior = self.snapshot.peer_mesh.authority_revision;
        match expire_peer_mesh_members(&self.snapshot.peer_mesh, sweep_id.clone(), now_ms) {
            Ok((next, receipt)) => {
                self.snapshot.peer_mesh = next;
                self.record(
                    ManifoldPeerRuntimeAuditKind::PeerMeshExpiry,
                    sweep_id,
                    prior,
                    receipt.resulting_authority_revision,
                    receipt.applied,
                    None,
                )?;
                Ok(receipt)
            }
            Err(reason) => {
                self.record(
                    ManifoldPeerRuntimeAuditKind::PeerMeshExpiry,
                    sweep_id,
                    prior,
                    prior,
                    false,
                    Some(reason.clone()),
                )?;
                Err(ManifoldPeerRuntimeHostError::Authority(reason))
            }
        }
    }

    /// Revokes one current mesh member through the pure mesh authority.
    ///
    /// # Errors
    ///
    /// Returns a host error for replay, stale revision, missing member,
    /// authority failure, or event-sequence exhaustion.
    pub fn revoke_peer_mesh_member(
        &mut self,
        request: &ManifoldPeerMeshRevocation,
    ) -> Result<ManifoldPeerMeshMutationReceipt, ManifoldPeerRuntimeHostError> {
        self.ensure_family_enabled(ManifoldPeerRuntimeAuthorityFamily::PeerMesh)?;
        self.ensure_mutation_source_unused(
            &ManifoldPeerRuntimeAuditKind::PeerMeshRevocation,
            &request.revocation_id,
        )?;
        self.ensure_event_capacity()?;
        let prior = self.snapshot.peer_mesh.authority_revision;
        match revoke_peer_mesh_member(&self.snapshot.peer_mesh, request) {
            Ok((next, receipt)) => {
                self.snapshot.peer_mesh = next;
                self.record(
                    ManifoldPeerRuntimeAuditKind::PeerMeshRevocation,
                    request.revocation_id.clone(),
                    prior,
                    receipt.resulting_authority_revision,
                    receipt.applied,
                    None,
                )?;
                Ok(receipt)
            }
            Err(reason) => {
                self.record(
                    ManifoldPeerRuntimeAuditKind::PeerMeshRevocation,
                    request.revocation_id.clone(),
                    prior,
                    prior,
                    false,
                    Some(reason.clone()),
                )?;
                Err(ManifoldPeerRuntimeHostError::Authority(reason))
            }
        }
    }

    /// Issues a direct-lane lease using only host-owned current authorities.
    /// Media scope resolves only the host-retained accepted media decision;
    /// callers cannot supply a descriptor or widen authority at lease time.
    ///
    /// # Errors
    ///
    /// Returns a host error when the session has no retained signed topology
    /// authorization or the audit sequence is exhausted.
    pub fn review_direct_lane_lease(
        &mut self,
        request: &ManifoldDirectLaneLeaseRequest,
        command_request: &ManifoldRuntimeCommandRequest,
        now_ms: u64,
    ) -> Result<ManifoldDirectLaneLeaseReceipt, ManifoldPeerRuntimeHostError> {
        self.ensure_runtime_lease_does_not_require_live_broker(
            command_request.lease_id.as_ref(),
            "direct-lane issuance",
        )?;
        self.ensure_runtime_lease_does_not_require_live_broker(
            self.media_runtime_lease_for_decision(request.media_session_decision_id.as_ref()),
            "media-derived direct-lane issuance",
        )?;
        self.review_direct_lane_lease_inner(request, command_request, now_ms)
    }

    /// Issues a direct-lane lease after rejoining any Broker-derived Runtime
    /// Host lease to current live Broker evidence.
    ///
    /// # Errors
    ///
    /// Returns a host error when the Broker-derived lease is no longer current
    /// or when normal direct-lane review fails.
    pub fn review_direct_lane_lease_with_live_broker_runtime(
        &mut self,
        broker_runtime: &ManifoldBrokerRuntime,
        request: &ManifoldDirectLaneLeaseRequest,
        command_request: &ManifoldRuntimeCommandRequest,
        now_ms: u64,
    ) -> Result<ManifoldDirectLaneLeaseReceipt, ManifoldPeerRuntimeHostError> {
        self.validate_runtime_lease_against_live_broker(
            broker_runtime,
            command_request.lease_id.as_ref(),
        )?;
        self.validate_runtime_lease_against_live_broker(
            broker_runtime,
            self.media_runtime_lease_for_decision(request.media_session_decision_id.as_ref()),
        )?;
        self.review_direct_lane_lease_inner(request, command_request, now_ms)
    }

    fn review_direct_lane_lease_inner(
        &mut self,
        request: &ManifoldDirectLaneLeaseRequest,
        command_request: &ManifoldRuntimeCommandRequest,
        now_ms: u64,
    ) -> Result<ManifoldDirectLaneLeaseReceipt, ManifoldPeerRuntimeHostError> {
        self.ensure_family_enabled(ManifoldPeerRuntimeAuthorityFamily::DirectLane)?;
        self.ensure_event_capacity()?;
        let mut runtime =
            ManifoldRuntimeHost::from_snapshot(self.snapshot.media_command_runtime.clone())
                .map_err(|error| ManifoldPeerRuntimeHostError::Authority(error.to_string()))?;
        let dispatch = runtime.review_command(command_request, now_ms);
        let application = runtime.apply_dispatch(command_request, &dispatch, now_ms);
        self.snapshot.media_command_runtime = runtime.snapshot().clone();
        let topology = self
            .topology_for_session(&request.peer_session_id)
            .cloned()
            .ok_or_else(|| {
                ManifoldPeerRuntimeHostError::MissingTopology(request.peer_session_id.clone())
            })?;
        let authority = ManifoldDirectLaneLeaseAuthorityContext {
            accepted_peers: &self.snapshot.accepted_peers,
            enrollment: &self.snapshot.enrollment,
            rendezvous: &self.snapshot.rendezvous,
            mesh: &self.snapshot.peer_mesh,
            peer_sessions: &self.snapshot.peer_sessions,
            topology: &topology,
            media_sessions: &self.snapshot.media_sessions,
            live_provider_epoch_id: &self.snapshot.provider_epoch_id,
            client_grants: &self.snapshot.trust_policy.direct_lane_client_grants,
        };
        let (next, receipt) = review_and_apply_direct_lane_lease(
            &self.snapshot.direct_lane_leases,
            &authority,
            request,
            ManifoldDirectLaneRuntimeCommandContext {
                runtime_host_id: &self.snapshot.media_command_runtime.host_id,
                command_request,
                dispatch: &dispatch,
                application: &application,
            },
            now_ms,
        );
        self.snapshot.direct_lane_leases = next;
        self.record(
            ManifoldPeerRuntimeAuditKind::DirectLaneLease,
            request.request_id.clone(),
            receipt.prior_authority_revision,
            receipt.resulting_authority_revision,
            receipt.applied,
            rejection_code(receipt.rejection_reason.as_ref()),
        )?;
        Ok(receipt)
    }

    /// Revalidates one stored direct-lane lease against every current source
    /// authority revision.
    ///
    /// # Errors
    ///
    /// Returns the pure direct-lane rejection when the lease is missing,
    /// revoked, expired, stale, or no longer topology-authorized.
    pub fn validate_direct_lane_lease(
        &mut self,
        request: &ManifoldDirectLaneLeaseUseRequest,
        command_request: &ManifoldRuntimeCommandRequest,
        now_ms: u64,
    ) -> Result<ManifoldDirectLaneLeaseCurrentReceipt, ManifoldDirectLaneLeaseRejectionReason> {
        let lease = self
            .snapshot
            .direct_lane_leases
            .leases
            .iter()
            .find(|candidate| candidate.lease_id == request.lease_id);
        let holder_requires_live_broker = lease.is_some_and(|lease| {
            self.active_broker_admission_for_runtime_lease(&lease.holder_runtime_lease_id)
                .is_some()
        });
        let media_requires_live_broker = lease
            .and_then(|lease| lease.media_session_decision_id.as_ref())
            .and_then(|decision_id| self.media_runtime_lease_for_decision(Some(decision_id)))
            .is_some_and(|lease_id| {
                self.active_broker_admission_for_runtime_lease(lease_id)
                    .is_some()
            });
        if holder_requires_live_broker || media_requires_live_broker {
            return Err(ManifoldDirectLaneLeaseRejectionReason::ClientNotAuthorized);
        }
        self.validate_direct_lane_lease_inner(request, command_request, now_ms)
    }

    /// Revalidates a direct-lane lease after rejoining any Broker-derived
    /// Runtime Host lease to current live Broker evidence.
    ///
    /// # Errors
    ///
    /// Returns the closed direct-lane denial when the Broker-derived lease is
    /// no longer current or normal direct-lane validation fails.
    pub fn validate_direct_lane_lease_with_live_broker_runtime(
        &mut self,
        broker_runtime: &ManifoldBrokerRuntime,
        request: &ManifoldDirectLaneLeaseUseRequest,
        command_request: &ManifoldRuntimeCommandRequest,
        now_ms: u64,
    ) -> Result<ManifoldDirectLaneLeaseCurrentReceipt, ManifoldDirectLaneLeaseRejectionReason> {
        let lease = self
            .snapshot
            .direct_lane_leases
            .leases
            .iter()
            .find(|candidate| candidate.lease_id == request.lease_id);
        self.validate_runtime_lease_against_live_broker(
            broker_runtime,
            lease.map(|lease| &lease.holder_runtime_lease_id),
        )
        .map_err(|_| ManifoldDirectLaneLeaseRejectionReason::ClientNotAuthorized)?;
        self.validate_runtime_lease_against_live_broker(
            broker_runtime,
            lease
                .and_then(|lease| lease.media_session_decision_id.as_ref())
                .and_then(|decision_id| self.media_runtime_lease_for_decision(Some(decision_id))),
        )
        .map_err(|_| ManifoldDirectLaneLeaseRejectionReason::ClientNotAuthorized)?;
        self.validate_direct_lane_lease_inner(request, command_request, now_ms)
    }

    fn validate_direct_lane_lease_inner(
        &mut self,
        request: &ManifoldDirectLaneLeaseUseRequest,
        command_request: &ManifoldRuntimeCommandRequest,
        now_ms: u64,
    ) -> Result<ManifoldDirectLaneLeaseCurrentReceipt, ManifoldDirectLaneLeaseRejectionReason> {
        if !self
            .snapshot
            .trust_policy
            .enabled_authority_families
            .contains(&ManifoldPeerRuntimeAuthorityFamily::DirectLane)
        {
            return Err(ManifoldDirectLaneLeaseRejectionReason::ClientNotAuthorized);
        }
        let mut runtime =
            ManifoldRuntimeHost::from_snapshot(self.snapshot.media_command_runtime.clone())
                .map_err(|_| ManifoldDirectLaneLeaseRejectionReason::ClientNotAuthorized)?;
        let dispatch = runtime.review_command(command_request, now_ms);
        let application = runtime.apply_dispatch(command_request, &dispatch, now_ms);
        self.snapshot.media_command_runtime = runtime.snapshot().clone();
        let lease = self
            .snapshot
            .direct_lane_leases
            .leases
            .iter()
            .find(|candidate| candidate.lease_id == request.lease_id)
            .ok_or(ManifoldDirectLaneLeaseRejectionReason::TopologyNotAuthorized)?;
        let topology = self
            .topology_for_session(&lease.peer_session_id)
            .ok_or(ManifoldDirectLaneLeaseRejectionReason::TopologyNotAuthorized)?;
        validate_current_direct_lane_lease(
            &self.snapshot.direct_lane_leases,
            &ManifoldDirectLaneLeaseAuthorityContext {
                accepted_peers: &self.snapshot.accepted_peers,
                enrollment: &self.snapshot.enrollment,
                rendezvous: &self.snapshot.rendezvous,
                mesh: &self.snapshot.peer_mesh,
                peer_sessions: &self.snapshot.peer_sessions,
                topology,
                media_sessions: &self.snapshot.media_sessions,
                live_provider_epoch_id: &self.snapshot.provider_epoch_id,
                client_grants: &self.snapshot.trust_policy.direct_lane_client_grants,
            },
            request,
            ManifoldDirectLaneRuntimeCommandContext {
                runtime_host_id: &self.snapshot.media_command_runtime.host_id,
                command_request,
                dispatch: &dispatch,
                application: &application,
            },
            now_ms,
        )
    }

    /// Revokes one direct-lane lease and records the exact lease revision.
    ///
    /// # Errors
    ///
    /// Returns a host error for authority failure or event-sequence exhaustion.
    pub fn revoke_direct_lane_lease(
        &mut self,
        request: &ManifoldDirectLaneLeaseRevocation,
        command_request: &ManifoldRuntimeCommandRequest,
        now_ms: u64,
    ) -> Result<Revision, ManifoldPeerRuntimeHostError> {
        let lease = self
            .snapshot
            .direct_lane_leases
            .leases
            .iter()
            .find(|lease| lease.lease_id == request.lease_id);
        self.ensure_runtime_lease_does_not_require_live_broker(
            lease.map(|lease| &lease.holder_runtime_lease_id),
            "direct-lane revocation",
        )?;
        self.ensure_runtime_lease_does_not_require_live_broker(
            lease
                .and_then(|lease| lease.media_session_decision_id.as_ref())
                .and_then(|decision_id| self.media_runtime_lease_for_decision(Some(decision_id))),
            "media-derived direct-lane revocation",
        )?;
        self.revoke_direct_lane_lease_inner(request, command_request, now_ms)
    }

    /// Revokes a direct-lane lease after rejoining any Broker-derived
    /// authority lineage to current live Broker evidence.
    ///
    /// # Errors
    ///
    /// Returns a host error when a Broker-derived lease is no longer current
    /// or when normal direct-lane revocation fails.
    pub fn revoke_direct_lane_lease_with_live_broker_runtime(
        &mut self,
        broker_runtime: &ManifoldBrokerRuntime,
        request: &ManifoldDirectLaneLeaseRevocation,
        command_request: &ManifoldRuntimeCommandRequest,
        now_ms: u64,
    ) -> Result<Revision, ManifoldPeerRuntimeHostError> {
        let lease = self
            .snapshot
            .direct_lane_leases
            .leases
            .iter()
            .find(|lease| lease.lease_id == request.lease_id);
        self.validate_runtime_lease_against_live_broker(
            broker_runtime,
            lease.map(|lease| &lease.holder_runtime_lease_id),
        )?;
        self.validate_runtime_lease_against_live_broker(
            broker_runtime,
            lease
                .and_then(|lease| lease.media_session_decision_id.as_ref())
                .and_then(|decision_id| self.media_runtime_lease_for_decision(Some(decision_id))),
        )?;
        self.revoke_direct_lane_lease_inner(request, command_request, now_ms)
    }

    fn revoke_direct_lane_lease_inner(
        &mut self,
        request: &ManifoldDirectLaneLeaseRevocation,
        command_request: &ManifoldRuntimeCommandRequest,
        now_ms: u64,
    ) -> Result<Revision, ManifoldPeerRuntimeHostError> {
        self.ensure_family_enabled(ManifoldPeerRuntimeAuthorityFamily::DirectLane)?;
        self.ensure_event_capacity()?;
        let mut runtime =
            ManifoldRuntimeHost::from_snapshot(self.snapshot.media_command_runtime.clone())
                .map_err(|error| ManifoldPeerRuntimeHostError::Authority(error.to_string()))?;
        let dispatch = runtime.review_command(command_request, now_ms);
        let application = runtime.apply_dispatch(command_request, &dispatch, now_ms);
        self.snapshot.media_command_runtime = runtime.snapshot().clone();
        let prior = self.snapshot.direct_lane_leases.authority_revision;
        match revoke_direct_lane_lease(
            &self.snapshot.direct_lane_leases,
            request,
            ManifoldDirectLaneRuntimeCommandContext {
                runtime_host_id: &self.snapshot.media_command_runtime.host_id,
                command_request,
                dispatch: &dispatch,
                application: &application,
            },
            &self.snapshot.trust_policy.direct_lane_client_grants,
            &self.snapshot.trust_policy.trusted_direct_lane_revoker_ids,
        ) {
            Ok(next) => {
                let resulting = next.authority_revision;
                self.snapshot.direct_lane_leases = next;
                self.record(
                    ManifoldPeerRuntimeAuditKind::DirectLaneLeaseRevocation,
                    request.revocation_id.clone(),
                    prior,
                    resulting,
                    true,
                    None,
                )?;
                Ok(resulting)
            }
            Err(reason) => {
                self.record(
                    ManifoldPeerRuntimeAuditKind::DirectLaneLeaseRevocation,
                    request.revocation_id.clone(),
                    prior,
                    prior,
                    false,
                    Some(reason.clone()),
                )?;
                Err(ManifoldPeerRuntimeHostError::Authority(reason))
            }
        }
    }

    /// Consumes one replay-protected direct-lane expiry sweep.
    ///
    /// # Errors
    ///
    /// Returns a host error for authority failure or event-sequence exhaustion.
    pub fn expire_direct_lane_leases(
        &mut self,
        sweep_id: DottedId,
        now_ms: u64,
    ) -> Result<Revision, ManifoldPeerRuntimeHostError> {
        self.ensure_family_enabled(ManifoldPeerRuntimeAuthorityFamily::DirectLane)?;
        self.ensure_event_capacity()?;
        let prior = self.snapshot.direct_lane_leases.authority_revision;
        match expire_direct_lane_leases(&self.snapshot.direct_lane_leases, sweep_id.clone(), now_ms)
        {
            Ok(next) => {
                let resulting = next.authority_revision;
                self.snapshot.direct_lane_leases = next;
                self.record(
                    ManifoldPeerRuntimeAuditKind::DirectLaneLeaseExpiry,
                    sweep_id,
                    prior,
                    resulting,
                    true,
                    None,
                )?;
                Ok(resulting)
            }
            Err(reason) => {
                self.record(
                    ManifoldPeerRuntimeAuditKind::DirectLaneLeaseExpiry,
                    sweep_id,
                    prior,
                    prior,
                    false,
                    Some(reason.clone()),
                )?;
                Err(ManifoldPeerRuntimeHostError::Authority(reason))
            }
        }
    }

    fn topology_for_session(
        &self,
        session_id: &DottedId,
    ) -> Option<&ManifoldSignedPeerTopologyAuthorization> {
        let decision_id = self
            .snapshot
            .peer_sessions
            .sessions
            .iter()
            .find(|session| session.proposal.session_id == *session_id && !session.revoked)
            .map(|session| &session.decision_id)?;
        self.snapshot
            .signed_topology_authorizations
            .iter()
            .find(|topology| {
                topology.topology_authorization.decision_id == *decision_id
                    && topology.topology_authorization.session_id == *session_id
            })
    }

    fn active_broker_admission_for_runtime_lease(
        &self,
        runtime_lease_id: &DottedId,
    ) -> Option<&ManifoldPeerRuntimeBrokerLeaseAdmission> {
        self.snapshot
            .broker_lease_admissions
            .iter()
            .find(|admission| {
                admission.released_at_ms.is_none()
                    && admission.runtime_lease.lease_id == *runtime_lease_id
            })
    }

    fn media_runtime_lease_for_decision(
        &self,
        media_session_decision_id: Option<&DottedId>,
    ) -> Option<&DottedId> {
        let decision_id = media_session_decision_id?;
        self.snapshot
            .media_sessions
            .sessions
            .iter()
            .find(|session| session.decision_id == *decision_id)
            .map(|session| &session.runtime_lease_id)
    }

    fn ensure_runtime_lease_does_not_require_live_broker(
        &self,
        runtime_lease_id: Option<&DottedId>,
        operation: &str,
    ) -> Result<(), ManifoldPeerRuntimeHostError> {
        if runtime_lease_id.is_some_and(|lease_id| {
            self.active_broker_admission_for_runtime_lease(lease_id)
                .is_some()
        }) {
            return Err(ManifoldPeerRuntimeHostError::Authority(format!(
                "live Broker join required for Broker-derived {operation}"
            )));
        }
        Ok(())
    }

    fn validate_runtime_lease_against_live_broker(
        &self,
        broker_runtime: &ManifoldBrokerRuntime,
        runtime_lease_id: Option<&DottedId>,
    ) -> Result<(), ManifoldPeerRuntimeHostError> {
        let Some(admission) = runtime_lease_id
            .and_then(|lease_id| self.active_broker_admission_for_runtime_lease(lease_id))
        else {
            return Ok(());
        };
        let evidence = broker_runtime.evidence();
        if evidence.provider_epoch_id != self.snapshot.provider_epoch_id {
            return Err(ManifoldPeerRuntimeHostError::Authority(
                "peer and Broker provider epochs diverge".to_owned(),
            ));
        }
        validate_active_broker_admission(&self.snapshot, admission, &evidence)
            .map_err(|error| ManifoldPeerRuntimeHostError::Authority(error.to_string()))
    }

    fn ensure_family_enabled(
        &self,
        family: ManifoldPeerRuntimeAuthorityFamily,
    ) -> Result<(), ManifoldPeerRuntimeHostError> {
        if self
            .snapshot
            .trust_policy
            .enabled_authority_families
            .contains(&family)
        {
            Ok(())
        } else {
            Err(ManifoldPeerRuntimeHostError::Authority(format!(
                "authority family disabled by product lock: {family:?}"
            )))
        }
    }

    fn ensure_event_capacity(&self) -> Result<(), ManifoldPeerRuntimeHostError> {
        if self.snapshot.audit_events.len() >= MAX_PEER_RUNTIME_HOST_EVENTS
            || authority_record_lengths(&self.snapshot)
                .into_iter()
                .any(|length| length > MAX_PEER_RUNTIME_AUTHORITY_RECORDS.saturating_sub(2))
        {
            return Err(ManifoldPeerRuntimeHostError::AuthorityCapacityExhausted);
        }
        self.snapshot
            .event_sequence
            .checked_add(1)
            .map(|_| ())
            .ok_or(ManifoldPeerRuntimeHostError::EventSequenceExhausted)
    }

    fn ensure_mutation_source_unused(
        &self,
        kind: &ManifoldPeerRuntimeAuditKind,
        source_id: &DottedId,
    ) -> Result<(), ManifoldPeerRuntimeHostError> {
        if self
            .snapshot
            .audit_events
            .iter()
            .any(|event| &event.event_kind == kind && &event.source_id == source_id)
        {
            return Err(ManifoldPeerRuntimeHostError::ReplayedMutation(
                source_id.clone(),
            ));
        }
        Ok(())
    }

    fn record(
        &mut self,
        event_kind: ManifoldPeerRuntimeAuditKind,
        source_id: DottedId,
        prior_authority_revision: Revision,
        resulting_authority_revision: Revision,
        applied: bool,
        rejection_code: Option<String>,
    ) -> Result<(), ManifoldPeerRuntimeHostError> {
        let sequence = self
            .snapshot
            .event_sequence
            .checked_add(1)
            .ok_or(ManifoldPeerRuntimeHostError::EventSequenceExhausted)?;
        self.snapshot.event_sequence = sequence;
        self.snapshot
            .audit_events
            .push(ManifoldPeerRuntimeAuditEvent {
                schema_id: schema(PEER_RUNTIME_HOST_AUDIT_SCHEMA),
                sequence,
                event_id: audit_id(sequence),
                event_kind,
                source_id,
                prior_authority_revision,
                resulting_authority_revision,
                applied,
                rejection_code,
            });
        Ok(())
    }
}

/// Peer Runtime Host construction, restart, or mutation failure.
#[derive(Debug)]
pub enum ManifoldPeerRuntimeHostError {
    /// Snapshot JSON could not be decoded.
    Deserialize(serde_json::Error),
    /// Snapshot JSON could not be encoded.
    Serialize(serde_json::Error),
    /// A durable snapshot invariant failed.
    InvalidSnapshot(String),
    /// Unified audit sequence cannot advance.
    EventSequenceExhausted,
    /// A durable history/replay collection reached its explicit fail-closed cap.
    AuthorityCapacityExhausted,
    /// A mutation-only sweep/revocation id was already consumed by the host.
    ReplayedMutation(DottedId),
    /// A peer session has no retained signed topology authorization.
    MissingTopology(DottedId),
    /// A pure authority mutation returned an error.
    Authority(String),
}

impl fmt::Display for ManifoldPeerRuntimeHostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Deserialize(error) => {
                write!(formatter, "peer runtime snapshot decode failed: {error}")
            }
            Self::Serialize(error) => {
                write!(formatter, "peer runtime snapshot encode failed: {error}")
            }
            Self::InvalidSnapshot(reason) => {
                write!(formatter, "peer runtime snapshot invalid: {reason}")
            }
            Self::EventSequenceExhausted => {
                formatter.write_str("peer runtime audit sequence exhausted")
            }
            Self::AuthorityCapacityExhausted => {
                formatter.write_str("peer runtime authority history capacity exhausted")
            }
            Self::ReplayedMutation(source_id) => {
                write!(formatter, "peer runtime mutation replay: {source_id}")
            }
            Self::MissingTopology(session_id) => {
                write!(
                    formatter,
                    "peer runtime signed topology missing: {session_id}"
                )
            }
            Self::Authority(reason) => {
                write!(formatter, "peer authority mutation failed: {reason}")
            }
        }
    }
}

impl std::error::Error for ManifoldPeerRuntimeHostError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Deserialize(error) | Self::Serialize(error) => Some(error),
            Self::InvalidSnapshot(_)
            | Self::EventSequenceExhausted
            | Self::AuthorityCapacityExhausted
            | Self::ReplayedMutation(_)
            | Self::MissingTopology(_)
            | Self::Authority(_) => None,
        }
    }
}

impl From<ManifoldBrokerRuntimeStateError> for ManifoldPeerRuntimeHostError {
    fn from(error: ManifoldBrokerRuntimeStateError) -> Self {
        Self::Authority(format!(
            "live broker transaction reconstruction failed: {error}"
        ))
    }
}

fn migrate_legacy_embedded_runtime_host_and_derivative_bindings(
    snapshot: &mut ManifoldPeerRuntimeHostSnapshot,
) -> Result<(), ManifoldPeerRuntimeHostError> {
    let mut runtime_value = serde_json::to_value(&snapshot.media_command_runtime)
        .map_err(ManifoldPeerRuntimeHostError::Serialize)?;
    let runtime_schema = snapshot.media_command_runtime.schema_id.as_str();
    if matches!(
        runtime_schema,
        rusty_manifold_runtime_host::LEGACY_HOST_SNAPSHOT_V2_SCHEMA
            | rusty_manifold_runtime_host::LEGACY_HOST_SNAPSHOT_V3_SCHEMA
    ) {
        let object = runtime_value
            .as_object_mut()
            .ok_or_else(|| invalid_snapshot("embedded Runtime Host migration shape"))?;
        object.remove("reviewed_derivative_lease_revocation_ids");
        if runtime_schema == rusty_manifold_runtime_host::LEGACY_HOST_SNAPSHOT_V2_SCHEMA {
            object.remove("reviewed_control_lease_adoption_ids");
        }
    }
    let runtime_json =
        serde_json::to_string(&runtime_value).map_err(ManifoldPeerRuntimeHostError::Serialize)?;
    let (runtime, _) = ManifoldRuntimeHost::restart_from_json_with_migration(&runtime_json)
        .map_err(|error| {
            ManifoldPeerRuntimeHostError::Authority(format!(
                "embedded Runtime Host migration failed: {error}"
            ))
        })?;
    snapshot.media_command_runtime = runtime.snapshot().clone();

    let expected = snapshot
        .broker_lease_admissions
        .iter()
        .map(|admission| {
            let upstream_control_lease_id =
                broker_outer_lease_id_for_admission(snapshot, admission)
                    .cloned()
                    .ok_or_else(|| {
                        invalid_snapshot("legacy broker admission lacks exact derivative lineage")
                    })?;
            Ok((
                admission.runtime_lease.lease_id.clone(),
                admission.released_at_ms.is_none(),
                broker_runtime_derivative_binding(
                    &admission.broker_receipt.provider_epoch_id,
                    &upstream_control_lease_id,
                    &admission.broker_receipt.admission_use_request_id,
                ),
            ))
        })
        .collect::<Result<Vec<_>, ManifoldPeerRuntimeHostError>>()?;
    for (index, (runtime_lease_id, active, binding)) in expected.into_iter().enumerate() {
        let admission = &mut snapshot.broker_lease_admissions[index];
        if admission
            .runtime_lease
            .derivative_binding
            .as_ref()
            .is_some_and(|retained| retained != &binding)
        {
            return Err(invalid_snapshot(
                "legacy broker admission derivative binding mismatch",
            ));
        }
        admission.runtime_lease.derivative_binding = Some(binding.clone());
        if active {
            let matching_runtime_leases = snapshot
                .media_command_runtime
                .leases
                .iter_mut()
                .filter(|lease| lease.lease_id == runtime_lease_id)
                .collect::<Vec<_>>();
            if matching_runtime_leases.len() != 1 {
                return Err(invalid_snapshot(
                    "legacy active derivative lease is missing or ambiguous",
                ));
            }
            let runtime_lease = matching_runtime_leases
                .into_iter()
                .next()
                .expect("one exact runtime lease");
            if runtime_lease.scope != admission.runtime_lease.scope
                || runtime_lease.holder_id != admission.runtime_lease.holder_id
                || runtime_lease.expires_at_ms != admission.runtime_lease.expires_at_ms
                || runtime_lease
                    .derivative_binding
                    .as_ref()
                    .is_some_and(|retained| retained != &binding)
            {
                return Err(invalid_snapshot(
                    "legacy active derivative lease object mismatch",
                ));
            }
            runtime_lease.derivative_binding = Some(binding);
        }
    }
    ManifoldRuntimeHost::from_snapshot(snapshot.media_command_runtime.clone()).map_err(
        |error| {
            ManifoldPeerRuntimeHostError::Authority(format!(
                "migrated embedded Runtime Host invalid: {error}"
            ))
        },
    )?;
    Ok(())
}

fn decode_peer_runtime_snapshot_with_migration(
    json: &str,
) -> Result<
    (
        ManifoldPeerRuntimeHostSnapshot,
        ManifoldPeerRuntimeHostSnapshotMigrationReceipt,
    ),
    ManifoldPeerRuntimeHostError,
> {
    let probe: PeerRuntimeHostSnapshotSchemaProbe =
        serde_json::from_str(json).map_err(ManifoldPeerRuntimeHostError::Deserialize)?;
    let source_schema_id = probe.schema_id;
    let (mut snapshot, migrated) = match source_schema_id.as_str() {
        PEER_RUNTIME_HOST_SNAPSHOT_SCHEMA => (
            serde_json::from_str(json).map_err(ManifoldPeerRuntimeHostError::Deserialize)?,
            false,
        ),
        LEGACY_PEER_RUNTIME_HOST_SNAPSHOT_V2_SCHEMA => {
            let legacy: LegacyManifoldPeerRuntimeHostSnapshotV2 =
                serde_json::from_str(json).map_err(ManifoldPeerRuntimeHostError::Deserialize)?;
            if legacy.schema_id != source_schema_id {
                return Err(invalid_snapshot(
                    "peer Runtime Host migration schema probe mismatch",
                ));
            }
            (
                ManifoldPeerRuntimeHostSnapshot {
                    schema_id: schema(PEER_RUNTIME_HOST_SNAPSHOT_SCHEMA),
                    host_id: legacy.host_id,
                    trust_policy: legacy.trust_policy,
                    provider_epoch_id: legacy.provider_epoch_id,
                    event_sequence: legacy.event_sequence,
                    accepted_peers: legacy.accepted_peers,
                    enrollment: legacy.enrollment,
                    rendezvous: legacy.rendezvous,
                    reciprocal_ed25519: legacy.reciprocal_ed25519,
                    peer_sessions: legacy.peer_sessions,
                    peer_mesh: legacy.peer_mesh,
                    media_sessions: legacy.media_sessions,
                    media_command_runtime: legacy.media_command_runtime,
                    broker_lease_admissions: legacy.broker_lease_admissions,
                    broker_lease_revocation_convergences: legacy
                        .broker_lease_revocation_convergences,
                    broker_lease_revocation_cleanup_completions: legacy
                        .broker_lease_revocation_cleanup_completions,
                    broker_epoch_rollovers: Vec::new(),
                    direct_lane_leases: legacy.direct_lane_leases,
                    signed_topology_authorizations: legacy.signed_topology_authorizations,
                    audit_events: legacy.audit_events,
                },
                true,
            )
        }
        LEGACY_PEER_RUNTIME_HOST_SNAPSHOT_V1_SCHEMA => {
            let legacy: LegacyManifoldPeerRuntimeHostSnapshotV1 =
                serde_json::from_str(json).map_err(ManifoldPeerRuntimeHostError::Deserialize)?;
            if legacy.schema_id != source_schema_id {
                return Err(invalid_snapshot(
                    "peer Runtime Host migration schema probe mismatch",
                ));
            }
            (
                ManifoldPeerRuntimeHostSnapshot {
                    schema_id: schema(PEER_RUNTIME_HOST_SNAPSHOT_SCHEMA),
                    host_id: legacy.host_id,
                    trust_policy: legacy.trust_policy,
                    provider_epoch_id: legacy.provider_epoch_id,
                    event_sequence: legacy.event_sequence,
                    accepted_peers: legacy.accepted_peers,
                    enrollment: legacy.enrollment,
                    rendezvous: legacy.rendezvous,
                    reciprocal_ed25519: legacy.reciprocal_ed25519,
                    peer_sessions: legacy.peer_sessions,
                    peer_mesh: legacy.peer_mesh,
                    media_sessions: legacy.media_sessions,
                    media_command_runtime: legacy.media_command_runtime,
                    broker_lease_admissions: legacy.broker_lease_admissions,
                    broker_lease_revocation_convergences: Vec::new(),
                    broker_lease_revocation_cleanup_completions: Vec::new(),
                    broker_epoch_rollovers: Vec::new(),
                    direct_lane_leases: legacy.direct_lane_leases,
                    signed_topology_authorizations: legacy.signed_topology_authorizations,
                    audit_events: legacy.audit_events,
                },
                true,
            )
        }
        _ => {
            return Err(invalid_snapshot(
                "unsupported peer Runtime Host snapshot schema",
            ))
        }
    };
    if migrated {
        migrate_legacy_embedded_runtime_host_and_derivative_bindings(&mut snapshot)?;
    }
    validate_snapshot(&snapshot)?;
    let receipt = ManifoldPeerRuntimeHostSnapshotMigrationReceipt {
        schema_id: schema(PEER_RUNTIME_HOST_SNAPSHOT_MIGRATION_RECEIPT_SCHEMA),
        source_schema_id,
        resulting_schema_id: snapshot.schema_id.clone(),
        migrated,
        host_id: snapshot.host_id.clone(),
        provider_epoch_id: snapshot.provider_epoch_id.clone(),
        preserved_event_sequence: snapshot.event_sequence,
        preserved_broker_lease_admission_count: snapshot.broker_lease_admissions.len(),
    };
    Ok((snapshot, receipt))
}

#[allow(clippy::too_many_lines)]
fn validated_live_broker_revocation<'evidence>(
    evidence: &'evidence ManifoldBrokerRuntimeEvidence,
    request: &ManifoldPeerRuntimeBrokerLeaseRevocationConvergenceRequest,
) -> Result<
    (
        &'evidence ManifoldBrokerControlLeaseLifecycleReceipt,
        &'evidence rusty_manifold_model::ManifoldControlLeaseRevocationAuthorityApplication,
        &'evidence ManifoldControlLeaseRevocationTombstone,
    ),
    ManifoldPeerRuntimeHostError,
> {
    if evidence.provider_epoch_id != request.expected_broker_provider_epoch_id
        || evidence
            .control_lease_authority
            .current_authority_snapshot
            .authority_revision
            != request.expected_broker_control_lease_authority_revision
        || evidence.host_snapshot.authority_revision
            != request.expected_broker_runtime_host_revision
    {
        return Err(ManifoldPeerRuntimeHostError::Authority(
            "stale live Broker revocation convergence request".to_owned(),
        ));
    }
    let receipt = evidence
        .control_lease_lifecycle_receipts
        .iter()
        .find(|receipt| receipt.lifecycle_request_id == request.broker_lifecycle_request_id)
        .ok_or_else(|| {
            ManifoldPeerRuntimeHostError::Authority(
                "live Broker revocation lifecycle receipt not found".to_owned(),
            )
        })?;
    if receipt.provider_epoch_id != evidence.provider_epoch_id
        || receipt.operation_kind != ManifoldBrokerControlLeaseLifecycleOperationKind::Revocation
        || receipt.outcome != ManifoldBrokerControlLeaseLifecycleOutcome::AcceptedAndAdopted
        || !receipt.applied
        || receipt.rejection_reason.is_some()
        || !receipt.admission_use_consumed
        || receipt
            .lifecycle_use
            .as_ref()
            .and_then(|use_binding| use_binding.lease_id.as_ref())
            != Some(&request.outer_control_lease_id)
    {
        return Err(ManifoldPeerRuntimeHostError::Authority(
            "live Broker lifecycle evidence is not an applied exact revocation".to_owned(),
        ));
    }
    let transition = receipt.authority_transition.as_ref().ok_or_else(|| {
        ManifoldPeerRuntimeHostError::Authority(
            "live Broker revocation authority transition missing".to_owned(),
        )
    })?;
    let ManifoldBrokerControlLeaseTransitionApplication::Revocation(application) =
        &transition.application
    else {
        return Err(ManifoldPeerRuntimeHostError::Authority(
            "live Broker transition application kind mismatch".to_owned(),
        ));
    };
    application
        .validate_against_snapshot(&transition.prior_authority_snapshot)
        .map_err(|error| {
            ManifoldPeerRuntimeHostError::Authority(format!(
                "live Broker revocation lineage invalid: {error}"
            ))
        })?;
    let applied_snapshot = application.applied_snapshot.as_ref().ok_or_else(|| {
        ManifoldPeerRuntimeHostError::Authority(
            "live Broker revocation applied snapshot missing".to_owned(),
        )
    })?;
    let tombstone = application.tombstone.as_ref().ok_or_else(|| {
        ManifoldPeerRuntimeHostError::Authority(
            "live Broker revocation tombstone missing".to_owned(),
        )
    })?;
    if application.outcome
        != ManifoldControlLeaseRevocationAuthorityApplicationOutcome::LeaseRevocationApplied
        || application.lease_id != request.outer_control_lease_id
        || tombstone.revoked_lease.lease_id != request.outer_control_lease_id
        || applied_snapshot
            .active_leases
            .iter()
            .any(|lease| lease.lease_id == request.outer_control_lease_id)
        || !applied_snapshot
            .revoked_control_lease_tombstones
            .iter()
            .any(|candidate| candidate == tombstone)
        || evidence
            .control_lease_authority
            .current_authority_snapshot
            .active_leases
            .iter()
            .any(|lease| lease.lease_id == request.outer_control_lease_id)
        || !evidence
            .control_lease_authority
            .current_authority_snapshot
            .revoked_control_lease_tombstones
            .iter()
            .any(|candidate| candidate == tombstone)
        || evidence
            .host_snapshot
            .leases
            .iter()
            .any(|lease| lease.lease_id == request.outer_control_lease_id)
    {
        return Err(ManifoldPeerRuntimeHostError::Authority(
            "live Broker revocation accepted-state closure mismatch".to_owned(),
        ));
    }
    let adoption = receipt.host_adoption.as_ref().ok_or_else(|| {
        ManifoldPeerRuntimeHostError::Authority(
            "live Broker revocation Runtime Host adoption missing".to_owned(),
        )
    })?;
    if !adoption.applied
        || adoption.rejection_reason.is_some()
        || adoption.manifold_application_id != application.application_id
        || adoption.manifold_authority_id != application.authority_id
        || adoption.prior_manifold_authority_revision != application.from_authority_revision
        || adoption.resulting_manifold_authority_revision != applied_snapshot.authority_revision
        || !adoption.added_lease_ids.is_empty()
        || !adoption.renewed_lease_ids.is_empty()
        || adoption.removed_lease_ids != vec![request.outer_control_lease_id.clone()]
        || adoption.resulting_host_authority_revision > evidence.host_snapshot.authority_revision
        || applied_snapshot.authority_revision
            > evidence
                .control_lease_authority
                .current_authority_snapshot
                .authority_revision
    {
        return Err(ManifoldPeerRuntimeHostError::Authority(
            "live Broker revocation Runtime Host adoption mismatch".to_owned(),
        ));
    }
    let barrier = evidence
        .control_lease_revocation_barriers
        .iter()
        .find(|barrier| barrier.lease_id == request.outer_control_lease_id)
        .ok_or_else(|| {
            ManifoldPeerRuntimeHostError::Authority(
                "live Broker revocation barrier missing".to_owned(),
            )
        })?;
    if barrier.provider_epoch_id != evidence.provider_epoch_id
        || barrier.lifecycle_request_id != receipt.lifecycle_request_id
        || barrier.revocation_application_id != application.application_id
        || barrier.authority_transition != *transition
        || barrier.host_adoption.as_ref() != Some(adoption)
        || barrier.state != ManifoldBrokerControlLeaseRevocationBarrierState::Converged
    {
        return Err(ManifoldPeerRuntimeHostError::Authority(
            "live Broker revocation barrier has not converged".to_owned(),
        ));
    }
    Ok((receipt, application, tombstone))
}

fn validate_active_broker_admission(
    snapshot: &ManifoldPeerRuntimeHostSnapshot,
    admission: &ManifoldPeerRuntimeBrokerLeaseAdmission,
    evidence: &ManifoldBrokerRuntimeEvidence,
) -> Result<(), ManifoldPeerRuntimeHostError> {
    let outer_lease_id = broker_outer_lease_id_for_admission(snapshot, admission)
        .ok_or_else(|| invalid_snapshot("broker admission outer lease lineage missing"))?;
    let admission_use_request_id = &admission.broker_receipt.admission_use_request_id;
    if admission.broker_receipt.provider_epoch_id != evidence.provider_epoch_id
        || !evidence
            .committed_mutation_receipts
            .iter()
            .any(|receipt| receipt == &admission.broker_receipt)
        || !evidence
            .consumed_bounded_use_ids
            .contains(admission_use_request_id)
        || !evidence
            .admission_snapshot
            .consumed_use_request_ids
            .contains(admission_use_request_id)
        || evidence
            .pending_bounded_uses
            .iter()
            .any(|bounded_use| bounded_use.admission_use_request_id == *admission_use_request_id)
    {
        return Err(invalid_snapshot(
            "active peer admission use is absent from live Broker evidence",
        ));
    }
    if evidence
        .control_lease_revocation_barriers
        .iter()
        .any(|barrier| barrier.lease_id == *outer_lease_id)
        || !evidence
            .control_lease_authority
            .current_authority_snapshot
            .active_leases
            .iter()
            .any(|lease| &lease.lease_id == outer_lease_id)
        || !evidence
            .host_snapshot
            .leases
            .iter()
            .any(|lease| &lease.lease_id == outer_lease_id)
    {
        return Err(invalid_snapshot(
            "stale active peer admission disagrees with live Broker",
        ));
    }
    Ok(())
}

fn broker_evidence_binding(
    domain: &str,
    evidence: &ManifoldBrokerRuntimeEvidence,
) -> Result<(String, u64), ManifoldPeerRuntimeHostError> {
    let serialized =
        serde_json::to_vec(evidence).map_err(ManifoldPeerRuntimeHostError::Serialize)?;
    let size = u64::try_from(serialized.len()).map_err(|_| {
        ManifoldPeerRuntimeHostError::Authority(
            "Broker epoch rollover evidence size exceeds u64".to_owned(),
        )
    })?;
    let mut framed = Vec::with_capacity(domain.len().saturating_add(serialized.len() + 1));
    framed.extend_from_slice(domain.as_bytes());
    framed.push(0);
    framed.extend_from_slice(&serialized);
    Ok((packaged_product_lock_sha256(&framed), size))
}

fn validate_broker_epoch_rollover_result(
    receipt: &ManifoldBrokerRuntimeEpochRolloverReceipt,
    resulting: &ManifoldBrokerRuntimeEvidence,
) -> Result<(), ManifoldPeerRuntimeHostError> {
    let (resulting_sha256, resulting_size) =
        broker_evidence_binding(EPOCH_ROLLOVER_RESULT_DIGEST_DOMAIN, resulting)?;
    if receipt.schema_id.as_str() != BROKER_RUNTIME_EPOCH_ROLLOVER_RECEIPT_SCHEMA
        || receipt.source_provider_epoch_id == receipt.resulting_provider_epoch_id
        || receipt.resulting_provider_epoch_id != resulting.provider_epoch_id
        || receipt.resulting_evidence_sha256 != resulting_sha256
        || receipt.resulting_evidence_size_bytes != resulting_size
        || receipt.manifold_authority_id
            != resulting
                .control_lease_authority
                .current_authority_snapshot
                .authority_id
        || receipt.manifold_authority_revision
            != resulting
                .control_lease_authority
                .current_authority_snapshot
                .authority_revision
        || receipt.clock_domain != resulting.control_lease_authority.current_clock.clock_domain
        || receipt.clock_epoch_id
            != resulting
                .control_lease_authority
                .current_clock
                .clock_epoch_id
        || receipt.clock_sequence != resulting.control_lease_authority.current_clock.sequence
        || receipt.authority_host_id != resulting.host_snapshot.host_id
        || receipt.host_authority_revision != resulting.host_snapshot.authority_revision
        || receipt.checkpointed_control_lease_request_count
            != resulting.compacted_control_lease_request_ids.len()
        || !resulting.control_lease_authority.transitions.is_empty()
        || !resulting.control_lease_lifecycle_receipts.is_empty()
        || !resulting.control_lease_revocation_barriers.is_empty()
        || !resulting
            .control_lease_revocation_consumer_acknowledgements
            .is_empty()
        || !resulting.committed_mutation_receipts.is_empty()
    {
        return Err(invalid_snapshot(
            "live Broker rollover result checkpoint mismatch",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_broker_epoch_rollover_checkpoint(
    source: &ManifoldBrokerRuntimeEvidence,
    receipt: &ManifoldBrokerRuntimeEpochRolloverReceipt,
    resulting: &ManifoldBrokerRuntimeEvidence,
) -> Result<(), ManifoldPeerRuntimeHostError> {
    validate_broker_epoch_rollover_result(receipt, resulting)?;
    let (source_sha256, source_size) =
        broker_evidence_binding(EPOCH_ROLLOVER_SOURCE_DIGEST_DOMAIN, source)?;
    let mut invalidated_token_ids = source
        .admission_snapshot
        .active_tokens
        .iter()
        .map(|token| token.token_id.clone())
        .collect::<Vec<_>>();
    invalidated_token_ids.sort();
    let source_closure = [
        (
            "provider_epoch",
            receipt.source_provider_epoch_id == source.provider_epoch_id,
        ),
        (
            "source_digest",
            receipt.source_evidence_sha256 == source_sha256,
        ),
        (
            "source_size",
            receipt.source_evidence_size_bytes == source_size,
        ),
        (
            "authority_id",
            receipt.manifold_authority_id
                == source
                    .control_lease_authority
                    .current_authority_snapshot
                    .authority_id,
        ),
        (
            "authority_revision",
            receipt.manifold_authority_revision
                == source
                    .control_lease_authority
                    .current_authority_snapshot
                    .authority_revision,
        ),
        (
            "clock",
            receipt.clock_domain == source.control_lease_authority.current_clock.clock_domain
                && receipt.clock_epoch_id
                    == source.control_lease_authority.current_clock.clock_epoch_id
                && receipt.clock_sequence == source.control_lease_authority.current_clock.sequence,
        ),
        (
            "host",
            receipt.authority_host_id == source.host_snapshot.host_id
                && receipt.host_authority_revision == source.host_snapshot.authority_revision,
        ),
        (
            "transition_count",
            receipt.compacted_owner_transition_count
                == source.control_lease_authority.transitions.len(),
        ),
        (
            "lifecycle_count",
            receipt.checkpointed_lifecycle_receipt_count
                == source.control_lease_lifecycle_receipts.len(),
        ),
        (
            "barrier_count",
            receipt.checkpointed_revocation_barrier_count
                == source.control_lease_revocation_barriers.len(),
        ),
        (
            "acknowledgement_count",
            receipt.checkpointed_revocation_consumer_acknowledgement_count
                == source
                    .control_lease_revocation_consumer_acknowledgements
                    .len(),
        ),
        (
            "mutation_count",
            receipt.checkpointed_mutation_receipt_count == source.committed_mutation_receipts.len(),
        ),
        (
            "consumed_use_count",
            receipt.checkpointed_consumed_use_count == source.consumed_bounded_use_ids.len(),
        ),
        (
            "invalidated_tokens",
            receipt.invalidated_admission_token_ids == invalidated_token_ids,
        ),
        (
            "host_preservation",
            source.host_snapshot == resulting.host_snapshot,
        ),
        (
            "authority_preservation",
            source.control_lease_authority.current_authority_snapshot
                == resulting.control_lease_authority.current_authority_snapshot,
        ),
        (
            "clock_preservation",
            source.control_lease_authority.current_clock
                == resulting.control_lease_authority.current_clock,
        ),
        (
            "source_host_drained",
            source.host_snapshot.leases.is_empty(),
        ),
        (
            "pending_uses_drained",
            source.pending_bounded_uses.is_empty(),
        ),
        (
            "pending_lifecycle_uses_drained",
            source.pending_control_lease_lifecycle_uses.is_empty(),
        ),
    ];
    if let Some((field, _)) = source_closure.iter().find(|(_, closes)| !closes) {
        return Err(ManifoldPeerRuntimeHostError::Authority(format!(
            "Broker epoch rollover source checkpoint mismatch: {field}"
        )));
    }
    Ok(())
}

fn peer_broker_epoch_state_checkpoint(
    snapshot: &ManifoldPeerRuntimeHostSnapshot,
    provider_epoch_id: &DottedId,
) -> Result<(String, usize, usize, usize), ManifoldPeerRuntimeHostError> {
    let admissions = snapshot
        .broker_lease_admissions
        .iter()
        .filter(|admission| admission.broker_receipt.provider_epoch_id == *provider_epoch_id)
        .collect::<Vec<_>>();
    let convergences = snapshot
        .broker_lease_revocation_convergences
        .iter()
        .filter(|receipt| receipt.peer_provider_epoch_id == *provider_epoch_id)
        .collect::<Vec<_>>();
    let completions = snapshot
        .broker_lease_revocation_cleanup_completions
        .iter()
        .filter(|receipt| receipt.peer_provider_epoch_id == *provider_epoch_id)
        .collect::<Vec<_>>();
    let digest = domain_separated_digest(
        PEER_RUNTIME_BROKER_EPOCH_STATE_DIGEST_DOMAIN,
        &(
            provider_epoch_id,
            admissions.as_slice(),
            convergences.as_slice(),
            completions.as_slice(),
        ),
    )?;
    Ok((
        digest,
        admissions.len(),
        convergences.len(),
        completions.len(),
    ))
}

fn provider_epoch_is_checkpointed(
    snapshot: &ManifoldPeerRuntimeHostSnapshot,
    provider_epoch_id: &DottedId,
) -> bool {
    snapshot
        .broker_epoch_rollovers
        .iter()
        .any(|receipt| &receipt.source_provider_epoch_id == provider_epoch_id)
}

fn validate_source_epoch_consumer_acknowledgements(
    snapshot: &ManifoldPeerRuntimeHostSnapshot,
    source: &ManifoldBrokerRuntimeEvidence,
) -> Result<(), ManifoldPeerRuntimeHostError> {
    for convergence in snapshot
        .broker_lease_revocation_convergences
        .iter()
        .filter(|receipt| receipt.peer_provider_epoch_id == snapshot.provider_epoch_id)
    {
        let completion = snapshot
            .broker_lease_revocation_cleanup_completions
            .iter()
            .find(|receipt| receipt.convergence_id == convergence.convergence_id)
            .ok_or_else(|| {
                ManifoldPeerRuntimeHostError::Authority(
                    "source-epoch convergence lacks terminal cleanup".to_owned(),
                )
            })?;
        let application_id = &convergence
            .inner_runtime_lease_revocation_receipt
            .upstream_revocation_application_id;
        let lease_id = &convergence
            .outer_control_lease_tombstone
            .revoked_lease
            .lease_id;
        let barrier = source
            .control_lease_revocation_barriers
            .iter()
            .find(|barrier| {
                barrier.provider_epoch_id == snapshot.provider_epoch_id
                    && barrier.revocation_application_id == *application_id
                    && barrier.lease_id == *lease_id
                    && barrier.state == ManifoldBrokerControlLeaseRevocationBarrierState::Converged
            })
            .ok_or_else(|| {
                ManifoldPeerRuntimeHostError::Authority(
                    "source-epoch convergence lacks exact Broker barrier".to_owned(),
                )
            })?;
        let expected = ManifoldBrokerControlLeaseRevocationConsumerAcknowledgement {
            schema_id: schema(BROKER_CONTROL_LEASE_REVOCATION_CONSUMER_ACKNOWLEDGEMENT_SCHEMA),
            acknowledgement_id: derived("acknowledgement.peer-runtime", &completion.completion_id),
            provider_epoch_id: snapshot.provider_epoch_id.clone(),
            barrier_id: barrier.barrier_id.clone(),
            revocation_application_id: application_id.clone(),
            lease_id: lease_id.clone(),
            consumer_kind: ManifoldBrokerControlLeaseRevocationConsumerKind::PeerRuntimeHost,
            consumer_id: snapshot.host_id.clone(),
            consumer_convergence_receipt_sha256: domain_separated_digest(
                PEER_RUNTIME_CONVERGENCE_RECEIPT_DIGEST_DOMAIN,
                convergence,
            )?,
            terminal_cleanup_receipt_sha256: domain_separated_digest(
                PEER_RUNTIME_TERMINAL_CLEANUP_RECEIPT_DIGEST_DOMAIN,
                completion,
            )?,
        };
        if !source
            .control_lease_revocation_consumer_acknowledgements
            .contains(&expected)
        {
            return Err(ManifoldPeerRuntimeHostError::Authority(
                "source-epoch peer acknowledgement is absent from Broker checkpoint".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_live_broker_restoration(
    snapshot: &ManifoldPeerRuntimeHostSnapshot,
    evidence: &ManifoldBrokerRuntimeEvidence,
) -> Result<(), ManifoldPeerRuntimeHostError> {
    if evidence.provider_epoch_id != snapshot.provider_epoch_id {
        return Err(invalid_snapshot("live Broker provider epoch mismatch"));
    }
    for admission in snapshot
        .broker_lease_admissions
        .iter()
        .filter(|admission| admission.released_at_ms.is_none())
    {
        validate_active_broker_admission(snapshot, admission, evidence)?;
    }
    for retained in &snapshot.broker_lease_revocation_convergences {
        if retained.peer_provider_epoch_id != snapshot.provider_epoch_id {
            if provider_epoch_is_checkpointed(snapshot, &retained.peer_provider_epoch_id) {
                continue;
            }
            return Err(invalid_snapshot(
                "retained convergence provider epoch is not checkpointed",
            ));
        }
        let request = ManifoldPeerRuntimeBrokerLeaseRevocationConvergenceRequest {
            schema_id: schema(PEER_RUNTIME_BROKER_LEASE_REVOCATION_CONVERGENCE_REQUEST_SCHEMA),
            convergence_id: retained.convergence_id.clone(),
            expected_peer_event_sequence: retained.prior_peer_event_sequence,
            expected_peer_provider_epoch_id: snapshot.provider_epoch_id.clone(),
            expected_broker_provider_epoch_id: evidence.provider_epoch_id.clone(),
            broker_lifecycle_request_id: retained
                .broker_lifecycle_receipt
                .lifecycle_request_id
                .clone(),
            outer_control_lease_id: retained
                .outer_control_lease_tombstone
                .revoked_lease
                .lease_id
                .clone(),
            expected_broker_control_lease_authority_revision: evidence
                .control_lease_authority
                .current_authority_snapshot
                .authority_revision,
            expected_broker_runtime_host_revision: evidence.host_snapshot.authority_revision,
            converged_at_ms: retained.converged_at_ms,
        };
        let (live_receipt, _, live_tombstone) =
            validated_live_broker_revocation(evidence, &request)
                .map_err(|_| invalid_snapshot("retained convergence is not current in Broker"))?;
        if live_receipt != &retained.broker_lifecycle_receipt
            || live_tombstone != &retained.outer_control_lease_tombstone
        {
            return Err(invalid_snapshot(
                "retained convergence differs from live Broker evidence",
            ));
        }
    }
    Ok(())
}

fn validate_snapshot(
    snapshot: &ManifoldPeerRuntimeHostSnapshot,
) -> Result<(), ManifoldPeerRuntimeHostError> {
    validate_snapshot_schemas(snapshot)?;
    validate_snapshot_capacity(snapshot)?;
    validate_trust_policy(&snapshot.trust_policy)?;
    validate_broker_epoch_rollovers(snapshot)?;
    validate_media_command_runtime(snapshot)?;
    validate_broker_lease_revocation_convergences(snapshot)?;
    validate_broker_lease_revocation_cleanup_completions(snapshot)?;
    validate_peer_and_enrollment_state(snapshot)?;
    validate_rendezvous_and_session_state(snapshot)?;
    validate_mesh_and_lease_state(snapshot)?;
    validate_topology_and_audit_state(snapshot)
}

fn validate_snapshot_capacity(
    snapshot: &ManifoldPeerRuntimeHostSnapshot,
) -> Result<(), ManifoldPeerRuntimeHostError> {
    if snapshot.audit_events.len() > MAX_PEER_RUNTIME_HOST_EVENTS
        || authority_record_lengths(snapshot)
            .into_iter()
            .any(|length| length > MAX_PEER_RUNTIME_AUTHORITY_RECORDS)
    {
        return Err(invalid_snapshot("authority history capacity exceeded"));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_broker_epoch_rollovers(
    snapshot: &ManifoldPeerRuntimeHostSnapshot,
) -> Result<(), ManifoldPeerRuntimeHostError> {
    if snapshot.broker_epoch_rollovers.is_empty() {
        return Ok(());
    }
    if !unique_ids(
        snapshot
            .broker_epoch_rollovers
            .iter()
            .map(|receipt| &receipt.rollover_id),
    ) || !unique_ids(
        snapshot
            .broker_epoch_rollovers
            .iter()
            .map(|receipt| &receipt.source_provider_epoch_id),
    ) || !unique_ids(
        snapshot
            .broker_epoch_rollovers
            .iter()
            .map(|receipt| &receipt.resulting_provider_epoch_id),
    ) {
        return Err(invalid_snapshot("Broker epoch rollover replay state"));
    }
    for (index, receipt) in snapshot.broker_epoch_rollovers.iter().enumerate() {
        let expected_source = index
            .checked_sub(1)
            .and_then(|prior| snapshot.broker_epoch_rollovers.get(prior))
            .map(|prior| &prior.resulting_provider_epoch_id);
        let (state_sha256, admission_count, convergence_count, cleanup_completion_count) =
            peer_broker_epoch_state_checkpoint(snapshot, &receipt.source_provider_epoch_id)?;
        let audit_prefix = snapshot
            .audit_events
            .get(..receipt.checkpointed_peer_audit_event_count)
            .ok_or_else(|| invalid_snapshot("Broker epoch rollover audit prefix bounds"))?;
        let audit_sha256 =
            domain_separated_digest(PEER_RUNTIME_BROKER_EPOCH_AUDIT_DIGEST_DOMAIN, &audit_prefix)?;
        let audit = snapshot.audit_events.iter().find(|event| {
            event.sequence == receipt.resulting_peer_event_sequence
                && event.source_id == receipt.rollover_id
        });
        if receipt.schema_id.as_str() != PEER_RUNTIME_BROKER_EPOCH_ROLLOVER_RECEIPT_SCHEMA
            || receipt.peer_host_id != snapshot.host_id
            || receipt.source_provider_epoch_id == receipt.resulting_provider_epoch_id
            || expected_source.is_some_and(|epoch| epoch != &receipt.source_provider_epoch_id)
            || receipt.rollover_id
                != derived(
                    "rollover.peer-runtime",
                    &receipt.resulting_provider_epoch_id,
                )
            || receipt.broker_rollover_receipt.schema_id.as_str()
                != BROKER_RUNTIME_EPOCH_ROLLOVER_RECEIPT_SCHEMA
            || receipt.broker_rollover_receipt.source_provider_epoch_id
                != receipt.source_provider_epoch_id
            || receipt.broker_rollover_receipt.resulting_provider_epoch_id
                != receipt.resulting_provider_epoch_id
            || !valid_sha256(&receipt.broker_rollover_receipt.source_evidence_sha256)
            || !valid_sha256(&receipt.broker_rollover_receipt.resulting_evidence_sha256)
            || receipt.checkpointed_peer_broker_state_sha256 != state_sha256
            || receipt.checkpointed_broker_lease_admission_count != admission_count
            || receipt.checkpointed_revocation_convergence_count != convergence_count
            || receipt.checkpointed_cleanup_completion_count != cleanup_completion_count
            || receipt.checkpointed_peer_audit_prefix_sha256 != audit_sha256
            || receipt.checkpointed_peer_audit_event_count
                != usize::try_from(receipt.prior_peer_event_sequence).unwrap_or(usize::MAX)
            || receipt.resulting_peer_event_sequence
                != receipt.prior_peer_event_sequence.saturating_add(1)
            || !receipt.applied
            || audit.map_or(true, |event| {
                event.event_kind != ManifoldPeerRuntimeAuditKind::BrokerEpochRollover
                    || !event.applied
                    || event.rejection_code.is_some()
            })
        {
            return Err(invalid_snapshot("Broker epoch rollover checkpoint"));
        }
    }
    if snapshot
        .broker_epoch_rollovers
        .last()
        .map_or(true, |receipt| {
            receipt.resulting_provider_epoch_id != snapshot.provider_epoch_id
        })
    {
        return Err(invalid_snapshot("Broker epoch rollover current epoch"));
    }
    let historical_epochs = snapshot
        .broker_epoch_rollovers
        .iter()
        .map(|receipt| &receipt.source_provider_epoch_id)
        .collect::<BTreeSet<_>>();
    if snapshot.broker_lease_admissions.iter().any(|admission| {
        admission.broker_receipt.provider_epoch_id != snapshot.provider_epoch_id
            && (!historical_epochs.contains(&admission.broker_receipt.provider_epoch_id)
                || admission.released_at_ms.is_none())
    }) || snapshot
        .broker_lease_revocation_convergences
        .iter()
        .any(|receipt| {
            receipt.peer_provider_epoch_id != snapshot.provider_epoch_id
                && !historical_epochs.contains(&receipt.peer_provider_epoch_id)
        })
        || snapshot
            .broker_lease_revocation_cleanup_completions
            .iter()
            .any(|receipt| {
                receipt.peer_provider_epoch_id != snapshot.provider_epoch_id
                    && !historical_epochs.contains(&receipt.peer_provider_epoch_id)
            })
    {
        return Err(invalid_snapshot(
            "Broker-derived record provider epoch is not checkpointed",
        ));
    }
    Ok(())
}

fn authority_record_lengths(snapshot: &ManifoldPeerRuntimeHostSnapshot) -> Vec<usize> {
    vec![
        snapshot.accepted_peers.peers.len(),
        snapshot.accepted_peers.applied_proposal_ids.len(),
        snapshot.enrollment.credentials.len(),
        snapshot.enrollment.applied_request_ids.len(),
        snapshot.rendezvous.applied_request_ids.len(),
        snapshot.rendezvous.consumed_evidence_ids.len(),
        snapshot.rendezvous.consumed_nonce_sha256.len(),
        snapshot.rendezvous.accepted_receipts.len(),
        snapshot.reciprocal_ed25519.applied_request_ids.len(),
        snapshot.reciprocal_ed25519.consumed_correlation_ids.len(),
        snapshot.reciprocal_ed25519.consumed_context_sha256.len(),
        snapshot.reciprocal_ed25519.consumed_nonce_sha256.len(),
        snapshot.reciprocal_ed25519.accepted_receipts.len(),
        snapshot.peer_sessions.sessions.len(),
        snapshot.peer_sessions.applied_proposal_ids.len(),
        snapshot.peer_sessions.revoked_session_ids.len(),
        snapshot.peer_mesh.members.len(),
        snapshot.peer_mesh.selected_routes.len(),
        snapshot.peer_mesh.applied_proposal_ids.len(),
        snapshot.peer_mesh.revoked_peer_ids.len(),
        snapshot.media_sessions.sessions.len(),
        snapshot.media_sessions.applied_request_ids.len(),
        snapshot.broker_lease_admissions.len(),
        snapshot.broker_lease_revocation_convergences.len(),
        snapshot.broker_lease_revocation_cleanup_completions.len(),
        snapshot.broker_epoch_rollovers.len(),
        snapshot.direct_lane_leases.leases.len(),
        snapshot.direct_lane_leases.applied_request_ids.len(),
        snapshot.signed_topology_authorizations.len(),
        snapshot.media_command_runtime.applied_request_ids.len(),
        snapshot.media_command_runtime.audit_events.len(),
    ]
}

fn validate_snapshot_schemas(
    snapshot: &ManifoldPeerRuntimeHostSnapshot,
) -> Result<(), ManifoldPeerRuntimeHostError> {
    if snapshot.schema_id.as_str() != PEER_RUNTIME_HOST_SNAPSHOT_SCHEMA
        || snapshot.accepted_peers.schema_id.as_str() != PEER_SNAPSHOT_SCHEMA
        || snapshot.enrollment.schema_id.as_str() != PEER_ENROLLMENT_STATE_SCHEMA
        || snapshot.rendezvous.schema_id.as_str() != RENDEZVOUS_AUTHORITY_STATE_SCHEMA
        || snapshot.reciprocal_ed25519.schema_id.as_str() != RECIPROCAL_ED25519_STATE_SCHEMA
        || snapshot.peer_sessions.schema_id.as_str() != PEER_SESSION_SNAPSHOT_SCHEMA
        || snapshot.peer_mesh.schema_id.as_str() != PEER_MESH_STATE_SCHEMA
        || snapshot.media_sessions.schema_id.as_str()
            != MANIFOLD_MEDIA_SESSION_ACCEPTANCE_STATE_SCHEMA
        || snapshot.media_command_runtime.schema_id.as_str() != HOST_SNAPSHOT_SCHEMA
        || snapshot.direct_lane_leases.schema_id.as_str() != DIRECT_LANE_LEASE_STATE_SCHEMA
    {
        return Err(invalid_snapshot("authority schema mismatch"));
    }
    Ok(())
}

fn validate_peer_and_enrollment_state(
    snapshot: &ManifoldPeerRuntimeHostSnapshot,
) -> Result<(), ManifoldPeerRuntimeHostError> {
    if !strictly_sorted_unique(
        snapshot
            .accepted_peers
            .peers
            .iter()
            .map(|peer| &peer.identity.peer_id),
    ) || snapshot
        .accepted_peers
        .peers
        .iter()
        .any(|peer| peer.identity.peer_id != peer.status.peer_id)
        || !unique_ids(snapshot.accepted_peers.applied_proposal_ids.iter())
    {
        return Err(invalid_snapshot("accepted peer identity/replay state"));
    }
    if !enrollment_state_is_well_formed(&snapshot.enrollment)
        || !unique_ids(snapshot.enrollment.applied_request_ids.iter())
        || !unique_ids(
            snapshot
                .enrollment
                .credentials
                .iter()
                .map(|credential| &credential.credential_id),
        )
        || !unique_ids(
            snapshot
                .enrollment
                .credentials
                .iter()
                .map(|credential| &credential.key_id),
        )
        || snapshot
            .enrollment
            .credentials
            .iter()
            .any(|credential| credential.schema_id.as_str() != PEER_CREDENTIAL_SCHEMA)
    {
        return Err(invalid_snapshot("enrollment identity/replay state"));
    }
    Ok(())
}

fn validate_rendezvous_and_session_state(
    snapshot: &ManifoldPeerRuntimeHostSnapshot,
) -> Result<(), ManifoldPeerRuntimeHostError> {
    if !unique_ids(snapshot.rendezvous.applied_request_ids.iter())
        || !unique_ids(snapshot.rendezvous.consumed_evidence_ids.iter())
        || !unique_strings(snapshot.rendezvous.consumed_nonce_sha256.iter())
        || !strictly_sorted_unique(
            snapshot
                .rendezvous
                .accepted_receipts
                .iter()
                .map(|receipt| &receipt.receipt_id),
        )
        || snapshot.rendezvous.accepted_receipts.iter().any(|receipt| {
            receipt.schema_id.as_str() != RENDEZVOUS_RECEIPT_SCHEMA
                || !receipt.accepted
                || receipt.rejection_reason.is_some()
        })
    {
        return Err(invalid_snapshot("signed rendezvous identity/replay state"));
    }
    if !unique_ids(snapshot.reciprocal_ed25519.applied_request_ids.iter())
        || !unique_ids(snapshot.reciprocal_ed25519.consumed_correlation_ids.iter())
        || !unique_strings(snapshot.reciprocal_ed25519.consumed_context_sha256.iter())
        || !unique_strings(snapshot.reciprocal_ed25519.consumed_nonce_sha256.iter())
        || snapshot
            .reciprocal_ed25519
            .accepted_receipts
            .windows(2)
            .any(|pair| pair[0].receipt_id >= pair[1].receipt_id)
        || snapshot
            .reciprocal_ed25519
            .accepted_receipts
            .iter()
            .any(|receipt| {
                !receipt.accepted
                    || receipt.rejection_reason.is_some()
                    || receipt.trust_policy_id != snapshot.trust_policy.policy_id
                    || receipt.trust_policy_revision != snapshot.trust_policy.revision
                    || !snapshot
                        .rendezvous
                        .accepted_receipts
                        .iter()
                        .any(|candidate| {
                            candidate == &reciprocal_ed25519_compatibility_receipt(receipt)
                        })
            })
    {
        return Err(invalid_snapshot(
            "reciprocal Ed25519 v2 authority/projection state",
        ));
    }
    if !unique_ids(snapshot.peer_sessions.applied_proposal_ids.iter())
        || !unique_ids(snapshot.peer_sessions.revoked_session_ids.iter())
        || !unique_ids(
            snapshot
                .peer_sessions
                .sessions
                .iter()
                .map(|session| &session.proposal.session_id),
        )
        || snapshot.peer_sessions.sessions.iter().any(|session| {
            session.proposal.schema_id.as_str() != PEER_SESSION_PROPOSAL_SCHEMA
                || !snapshot
                    .peer_sessions
                    .applied_proposal_ids
                    .contains(&session.proposal.proposal_id)
        })
    {
        return Err(invalid_snapshot("peer-session identity/replay state"));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_mesh_and_lease_state(
    snapshot: &ManifoldPeerRuntimeHostSnapshot,
) -> Result<(), ManifoldPeerRuntimeHostError> {
    if !validate_media_session_acceptance_state(&snapshot.media_sessions) {
        return Err(invalid_snapshot("media-session acceptance state"));
    }
    if !unique_ids(snapshot.peer_mesh.applied_proposal_ids.iter())
        || !unique_ids(snapshot.peer_mesh.revoked_peer_ids.iter())
        || !strictly_sorted_unique(
            snapshot
                .peer_mesh
                .members
                .iter()
                .map(|member| &member.peer_id),
        )
        || !unique_ids(
            snapshot
                .peer_mesh
                .selected_routes
                .iter()
                .map(|route| &route.candidate_id),
        )
        || snapshot.peer_mesh.selected_routes.iter().any(|route| {
            !route.direct_media_lane_eligible
                || route.evidence_expires_at_ms == 0
                || route.first_peer_id >= route.second_peer_id
                || route.pair_authority_epoch == 0
                || !valid_sha256(&route.pair_evidence_sha256)
                || route.signer_key_ids.len() != 2
                || route.signer_key_ids[0] >= route.signer_key_ids[1]
                || !snapshot.rendezvous.accepted_receipts.iter().any(|receipt| {
                    receipt.receipt_id == route.pair_evidence_receipt_id
                        && receipt.peer_ids
                            == vec![route.first_peer_id.clone(), route.second_peer_id.clone()]
                        && receipt.signer_key_ids == route.signer_key_ids
                        && receipt.nonce_sha256 == route.pair_evidence_sha256
                        && receipt.resulting_authority_revision == route.pair_authority_revision
                        && receipt.coordinator_epoch == route.pair_authority_epoch
                        && receipt.expires_at_ms == route.evidence_expires_at_ms
                })
        })
        || match (
            &snapshot.peer_mesh.mesh_id,
            snapshot.peer_mesh.authority_epoch,
            &snapshot.peer_mesh.coordinator_peer_id,
        ) {
            (None, 0, None) => {
                !snapshot.peer_mesh.members.is_empty()
                    || !snapshot.peer_mesh.selected_routes.is_empty()
            }
            (Some(_), epoch, Some(coordinator)) if epoch > 0 => {
                !(MIN_MESH_PEERS..=MAX_MESH_PEERS).contains(&snapshot.peer_mesh.members.len())
                    || !snapshot
                        .peer_mesh
                        .members
                        .iter()
                        .any(|member| &member.peer_id == coordinator)
                    || snapshot.peer_mesh.selected_routes.iter().any(|route| {
                        !snapshot
                            .peer_mesh
                            .members
                            .iter()
                            .any(|member| member.peer_id == route.first_peer_id)
                            || !snapshot
                                .peer_mesh
                                .members
                                .iter()
                                .any(|member| member.peer_id == route.second_peer_id)
                    })
            }
            _ => true,
        }
    {
        return Err(invalid_snapshot("peer-mesh membership/replay state"));
    }
    if !direct_lane_state_is_well_formed(&snapshot.direct_lane_leases)
        || snapshot.direct_lane_leases.leases.iter().any(|lease| {
            !snapshot
                .trust_policy
                .direct_lane_client_grants
                .iter()
                .any(|grant| {
                    grant.runtime_host_id == lease.runtime_authority_host_id
                        && grant.client_id == lease.holder_client_id
                        && grant.runtime_lease_id == lease.holder_runtime_lease_id
                        && grant.product_id == lease.product_id
                        && grant.feature_lock_id == lease.feature_lock_id
                        && grant.feature_lock_fingerprint == lease.feature_lock_fingerprint
                        && grant.admission_grant_id == lease.admission_grant_id
                        && match lease.scope {
                            rusty_manifold_peer::ManifoldDirectLaneLeaseScope::PeerSession => {
                                grant.peer_session_capability_id.as_ref()
                                    == Some(&lease.capability_id)
                            }
                            rusty_manifold_peer::ManifoldDirectLaneLeaseScope::MediaSession => {
                                grant.media_session_capability_id.as_ref()
                                    == Some(&lease.capability_id)
                            }
                        }
                })
        })
    {
        return Err(invalid_snapshot("direct-lane lease identity/replay state"));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_trust_policy(
    policy: &ManifoldPeerRuntimeTrustPolicy,
) -> Result<(), ManifoldPeerRuntimeHostError> {
    let enabled = &policy.enabled_authority_families;
    let selected = |family| enabled.contains(&family);
    let enrollment = selected(ManifoldPeerRuntimeAuthorityFamily::Enrollment);
    let rendezvous = selected(ManifoldPeerRuntimeAuthorityFamily::Rendezvous);
    let mesh = selected(ManifoldPeerRuntimeAuthorityFamily::PeerMesh);
    let media = selected(ManifoldPeerRuntimeAuthorityFamily::MediaSession);
    let direct = selected(ManifoldPeerRuntimeAuthorityFamily::DirectLane);
    if policy.schema_id.as_str() != PEER_RUNTIME_HOST_TRUST_POLICY_SCHEMA
        || enabled.is_empty()
        || enabled.windows(2).any(|pair| pair[0] >= pair[1])
        || (rendezvous
            && (!enrollment || !selected(ManifoldPeerRuntimeAuthorityFamily::PeerStatus)))
        || (mesh && !rendezvous)
        || (direct && !mesh)
        || (enrollment == policy.trusted_operator_ids.is_empty())
        || (selected(ManifoldPeerRuntimeAuthorityFamily::PeerStatus)
            == policy.trusted_key_fingerprints.is_empty())
        || (rendezvous == policy.trusted_adapter_ids.is_empty())
        || (mesh == policy.trusted_mesh_proposer_ids.is_empty())
        || (media == policy.media_client_grants.is_empty())
        || (media == policy.trusted_media_revoker_ids.is_empty())
        || (direct == policy.direct_lane_client_grants.is_empty())
        || (direct == policy.trusted_direct_lane_revoker_ids.is_empty())
        || (media
            && direct
            && policy.media_runtime_lease_scope_id == policy.direct_lane_runtime_lease_scope_id)
        || !strictly_sorted_unique(policy.trusted_operator_ids.iter())
        || !strictly_sorted_unique(policy.trusted_key_fingerprints.iter())
        || !strictly_sorted_unique(policy.trusted_adapter_ids.iter())
        || !strictly_sorted_unique(policy.trusted_mesh_proposer_ids.iter())
        || !strictly_sorted_unique(policy.trusted_media_revoker_ids.iter())
        || !strictly_sorted_unique(policy.trusted_direct_lane_revoker_ids.iter())
        || policy
            .media_client_grants
            .windows(2)
            .any(|pair| pair[0].client_id >= pair[1].client_id)
        || !unique_ids(
            policy
                .media_client_grants
                .iter()
                .map(|grant| &grant.lease_id),
        )
        || !unique_ids(
            policy
                .media_client_grants
                .iter()
                .map(|grant| &grant.broker_runtime_lease_id),
        )
        || !unique_ids(
            policy
                .media_client_grants
                .iter()
                .map(|grant| &grant.broker_client_lock_id),
        )
        || !unique_strings(
            policy
                .media_client_grants
                .iter()
                .map(|grant| &grant.broker_client_lock_fingerprint),
        )
        || !unique_ids(
            policy
                .media_client_grants
                .iter()
                .map(|grant| &grant.feature_lock_id),
        )
        || !unique_strings(
            policy
                .media_client_grants
                .iter()
                .map(|grant| &grant.feature_lock_fingerprint),
        )
        || !unique_ids(
            policy
                .media_client_grants
                .iter()
                .map(|grant| &grant.admission_grant_id),
        )
        || !unique_ids(
            policy
                .media_client_grants
                .iter()
                .map(|grant| &grant.allowed_session_id),
        )
        || !unique_strings(
            policy
                .media_client_grants
                .iter()
                .map(|grant| &grant.broker_client_identity.platform_subject),
        )
        || policy.media_client_grants.iter().any(|grant| {
            !valid_sha256(&grant.feature_lock_fingerprint)
                || !valid_sha256(&grant.broker_product_lock_sha256)
                || !valid_sha256(&grant.broker_client_lock_fingerprint)
                || !valid_semantic_product_fingerprint(&grant.broker_product_lock_fingerprint)
                || !valid_sha256(&grant.broker_client_identity.signing_fingerprint)
                || grant
                    .broker_client_identity
                    .platform_subject
                    .trim()
                    .is_empty()
                || grant.broker_client_identity.client_id != grant.client_id
                || grant.broker_client_lock_id == grant.feature_lock_id
                || grant.broker_client_lock_fingerprint == grant.feature_lock_fingerprint
                || grant.broker_product_lock_id == grant.broker_client_lock_id
                || grant.broker_product_lock_sha256 == grant.broker_client_lock_fingerprint
                || grant.broker_product_lock_sha256 == grant.feature_lock_fingerprint
                || grant.runtime_host_id != policy.media_runtime_host_id
                || grant.allowed_descriptor_canonical_sha256.is_empty()
                || grant
                    .allowed_descriptor_canonical_sha256
                    .iter()
                    .any(|digest| !valid_sha256(digest))
                || grant
                    .allowed_descriptor_canonical_sha256
                    .windows(2)
                    .any(|pair| pair[0] >= pair[1])
                || grant.allowed_resource_ids.is_empty()
                || grant
                    .allowed_resource_ids
                    .windows(2)
                    .any(|pair| pair[0] >= pair[1])
        })
        || policy
            .direct_lane_client_grants
            .windows(2)
            .any(|pair| pair[0].client_id >= pair[1].client_id)
        || !unique_ids(
            policy
                .direct_lane_client_grants
                .iter()
                .map(|grant| &grant.runtime_lease_id),
        )
        || !unique_ids(
            policy
                .direct_lane_client_grants
                .iter()
                .map(|grant| &grant.admission_grant_id),
        )
        || policy.direct_lane_client_grants.iter().any(|grant| {
            !valid_sha256(&grant.feature_lock_fingerprint)
                || grant.runtime_host_id != policy.media_runtime_host_id
                || (grant.peer_session_capability_id.is_none()
                    && grant.media_session_capability_id.is_none())
                || (!media && grant.media_session_capability_id.is_some())
        })
    {
        return Err(invalid_snapshot("trust policy schema/canonical roots"));
    }
    Ok(())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_semantic_product_fingerprint(value: &str) -> bool {
    value.len() == 24
        && value.starts_with("fnv1a64-")
        && value[8..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[allow(clippy::too_many_lines)]
fn validate_media_command_runtime(
    snapshot: &ManifoldPeerRuntimeHostSnapshot,
) -> Result<(), ManifoldPeerRuntimeHostError> {
    ManifoldRuntimeHost::from_snapshot(snapshot.media_command_runtime.clone())
        .map_err(|error| invalid_snapshot(&format!("media Runtime Host state: {error}")))?;
    let policy = &snapshot.trust_policy;
    let mut expected_commands = BTreeSet::new();
    if policy
        .enabled_authority_families
        .contains(&ManifoldPeerRuntimeAuthorityFamily::MediaSession)
    {
        expected_commands.extend([
            MANIFOLD_MEDIA_SESSION_ACCEPT_COMMAND,
            MANIFOLD_MEDIA_SESSION_STOP_COMMAND,
            MANIFOLD_MEDIA_SESSION_REVOKE_COMMAND,
        ]);
    }
    if policy
        .enabled_authority_families
        .contains(&ManifoldPeerRuntimeAuthorityFamily::DirectLane)
    {
        expected_commands.extend([
            DIRECT_LANE_LEASE_ISSUE_COMMAND,
            DIRECT_LANE_LEASE_USE_COMMAND,
            DIRECT_LANE_LEASE_REVOKE_COMMAND,
        ]);
    }
    let actual_commands = snapshot
        .media_command_runtime
        .commands
        .iter()
        .map(|command| command.command_id.as_str())
        .collect::<BTreeSet<_>>();
    if snapshot.media_command_runtime.host_id != policy.media_runtime_host_id
        || actual_commands != expected_commands
        || snapshot
            .media_command_runtime
            .commands
            .iter()
            .any(|command| {
                let expected_scope = match command.command_id.as_str() {
                    MANIFOLD_MEDIA_SESSION_ACCEPT_COMMAND
                    | MANIFOLD_MEDIA_SESSION_STOP_COMMAND
                    | MANIFOLD_MEDIA_SESSION_REVOKE_COMMAND => &policy.media_runtime_lease_scope_id,
                    DIRECT_LANE_LEASE_ISSUE_COMMAND
                    | DIRECT_LANE_LEASE_USE_COMMAND
                    | DIRECT_LANE_LEASE_REVOKE_COMMAND => {
                        &policy.direct_lane_runtime_lease_scope_id
                    }
                    _ => return true,
                };
                command.required_lease_scope.as_ref() != Some(expected_scope)
            })
        || snapshot.media_command_runtime.leases.iter().any(|lease| {
            let media_lease = lease.scope == policy.media_runtime_lease_scope_id
                && (policy.media_client_grants.iter().any(|grant| {
                    grant.client_id == lease.holder_id && grant.lease_id == lease.lease_id
                }) || policy.trusted_media_revoker_ids.contains(&lease.holder_id));
            let direct_lease = lease.scope == policy.direct_lane_runtime_lease_scope_id
                && (policy.direct_lane_client_grants.iter().any(|grant| {
                    grant.client_id == lease.holder_id && grant.runtime_lease_id == lease.lease_id
                }) || policy
                    .trusted_direct_lane_revoker_ids
                    .contains(&lease.holder_id));
            !media_lease && !direct_lease
        })
        || snapshot.media_sessions.sessions.iter().any(|session| {
            session.lifecycle_status
                == rusty_manifold_media_session::ManifoldMediaSessionLifecycleStatus::Current
                && (session.provider_epoch_id != snapshot.provider_epoch_id
                    || !snapshot.media_command_runtime.leases.iter().any(|lease| {
                        lease.lease_id == session.runtime_lease_id
                            && lease.holder_id == session.runtime_client_id
                            && lease.scope == policy.media_runtime_lease_scope_id
                    }))
        })
    {
        return Err(invalid_snapshot("media Runtime Host policy binding"));
    }
    if !unique_ids(
        snapshot
            .broker_lease_admissions
            .iter()
            .map(|admission| &admission.broker_receipt.admission_use_request_id),
    ) || !unique_ids(
        snapshot
            .broker_lease_admissions
            .iter()
            .filter_map(|admission| admission.release_id.as_ref()),
    ) || snapshot
        .broker_lease_admissions
        .iter()
        .any(|admission| !broker_lease_admission_is_well_formed(snapshot, admission))
        || snapshot
            .media_command_runtime
            .leases
            .iter()
            .filter(|lease| lease.derivative_binding.is_some())
            .any(|lease| {
                snapshot
                    .broker_lease_admissions
                    .iter()
                    .filter(|admission| {
                        admission.released_at_ms.is_none() && admission.runtime_lease == *lease
                    })
                    .count()
                    != 1
            })
        || snapshot
            .broker_lease_admissions
            .iter()
            .enumerate()
            .any(|(index, admission)| {
                admission.released_at_ms.is_none()
                    && snapshot.broker_lease_admissions[..index]
                        .iter()
                        .any(|prior| {
                            prior.released_at_ms.is_none()
                                && prior.runtime_lease.lease_id == admission.runtime_lease.lease_id
                        })
            })
    {
        return Err(invalid_snapshot("broker media lease admission binding"));
    }
    Ok(())
}

fn broker_lease_admission_is_well_formed(
    snapshot: &ManifoldPeerRuntimeHostSnapshot,
    admission: &ManifoldPeerRuntimeBrokerLeaseAdmission,
) -> bool {
    let receipt = &admission.broker_receipt;
    let Some(bounded_use) = receipt.bounded_use.as_ref() else {
        return false;
    };
    let Some(adapter) = receipt.adapter_receipt.as_ref() else {
        return false;
    };
    let Some(grant) = snapshot
        .trust_policy
        .media_client_grants
        .iter()
        .find(|grant| {
            grant.broker_adapter_id == adapter.adapter_id
                && grant.broker_runtime_host_id == adapter.authority_host_id
                && grant.broker_product_lock_id == adapter.product_lock_id
                && grant.broker_product_lock_fingerprint == adapter.product_lock_fingerprint
                && grant.broker_product_lock_sha256 == adapter.product_lock_sha256
                && grant.broker_command_id == adapter.dispatch.command_id
                && grant.broker_client_identity == bounded_use.identity
                && grant.broker_client_lock_id == bounded_use.client_lock_id
                && grant.broker_client_lock_fingerprint == bounded_use.client_lock_fingerprint
                && grant.admission_grant_id == bounded_use.admission_grant_id
                && grant.broker_capability_id == bounded_use.capability_id
                && grant.lease_id == admission.runtime_lease.lease_id
        })
    else {
        return false;
    };
    let active_lease = snapshot.media_command_runtime.leases.iter().any(|lease| {
        lease == &admission.runtime_lease
            && lease.scope == snapshot.trust_policy.media_runtime_lease_scope_id
            && lease.holder_id == grant.client_id
    });
    let release_tuple_valid = match (&admission.released_at_ms, &admission.release_id) {
        (None, None) => active_lease,
        (Some(released_at_ms), Some(_)) => *released_at_ms >= admission.admitted_at_ms,
        _ => false,
    };
    let provider_epoch_valid = receipt.provider_epoch_id == snapshot.provider_epoch_id
        || (admission.released_at_ms.is_some()
            && provider_epoch_is_checkpointed(snapshot, &receipt.provider_epoch_id));
    let derivative_binding_valid = admission
        .runtime_lease
        .derivative_binding
        .as_ref()
        .is_some_and(|binding| {
            binding.schema_id.as_str() == HOST_DERIVATIVE_LEASE_BINDING_SCHEMA
                && binding.binding_id
                    == derived("binding.runtime_lease", &receipt.admission_use_request_id)
                && binding.provider_epoch_id == receipt.provider_epoch_id
                && binding.upstream_control_lease_id == grant.broker_runtime_lease_id
                && binding.source_authorization_id == receipt.admission_use_request_id
        });
    admission.schema_id.as_str() == PEER_RUNTIME_BROKER_LEASE_ADMISSION_SCHEMA
        && receipt.schema_id.as_str() == BROKER_MUTATION_RECEIPT_SCHEMA
        && bounded_use.schema_id.as_str() == BROKER_BOUNDED_USE_SCHEMA
        && adapter.schema_id.as_str() == BROKER_ADAPTER_RECEIPT_SCHEMA
        && provider_epoch_valid
        && receipt.admission_use_request_id == bounded_use.admission_use_request_id
        && receipt.applied
        && receipt.admission_applied
        && receipt.admission_rejection_reason.is_none()
        && !receipt.local_acceptance_rules
        && receipt.authority_owner_id.as_str() == RUNTIME_HOST_AUTHORITY_OWNER
        && receipt.command_selected
        && adapter.authority_owner_id.as_str() == RUNTIME_HOST_AUTHORITY_OWNER
        && matches!(
            (&adapter.mode, &adapter.adapter_role),
            (
                ManifoldBrokerAdapterMode::Standalone,
                ManifoldBrokerAdapterRole::ProcessTransportAdapter
            ) | (
                ManifoldBrokerAdapterMode::Embedded,
                ManifoldBrokerAdapterRole::InProcessAdapter
            )
        )
        && adapter.dispatch.schema_id.as_str() == HOST_DISPATCH_RECEIPT_SCHEMA
        && adapter.application.schema_id.as_str() == HOST_APPLICATION_RECEIPT_SCHEMA
        && adapter.dispatch.authority_host_id == adapter.authority_host_id
        && adapter.application.authority_host_id == adapter.authority_host_id
        && adapter.dispatch.request_id == adapter.application.request_id
        && adapter.dispatch.dispatch_id == adapter.application.dispatch_id
        && adapter.dispatch.params_digest == adapter.application.params_digest
        && adapter.dispatch.outcome == ManifoldRuntimeDispatchOutcome::Ready
        && adapter.dispatch.rejection_reason.is_none()
        && adapter.application.applied
        && adapter.application.rejection_reason.is_none()
        && adapter.application.prior_authority_revision
            == adapter.dispatch.reviewed_authority_revision
        && bounded_use.identity.client_id == grant.client_id
        && bounded_use.expires_at_ms > admission.admitted_at_ms
        && admission.runtime_lease.scope == snapshot.trust_policy.media_runtime_lease_scope_id
        && admission.runtime_lease.holder_id == grant.client_id
        && derivative_binding_valid
        && admission.runtime_lease.expires_at_ms
            == bounded_use
                .expires_at_ms
                .min(admission.admitted_at_ms.saturating_add(120_000))
        && release_tuple_valid
}

fn broker_outer_lease_id_for_admission<'snapshot>(
    snapshot: &'snapshot ManifoldPeerRuntimeHostSnapshot,
    admission: &ManifoldPeerRuntimeBrokerLeaseAdmission,
) -> Option<&'snapshot DottedId> {
    let receipt = &admission.broker_receipt;
    let bounded_use = receipt.bounded_use.as_ref()?;
    let adapter = receipt.adapter_receipt.as_ref()?;
    snapshot
        .trust_policy
        .media_client_grants
        .iter()
        .find(|grant| {
            grant.broker_adapter_id == adapter.adapter_id
                && grant.broker_runtime_host_id == adapter.authority_host_id
                && grant.broker_product_lock_id == adapter.product_lock_id
                && grant.broker_product_lock_fingerprint == adapter.product_lock_fingerprint
                && grant.broker_product_lock_sha256 == adapter.product_lock_sha256
                && grant.broker_command_id == adapter.dispatch.command_id
                && grant.broker_client_identity == bounded_use.identity
                && grant.broker_client_lock_id == bounded_use.client_lock_id
                && grant.broker_client_lock_fingerprint == bounded_use.client_lock_fingerprint
                && grant.admission_grant_id == bounded_use.admission_grant_id
                && grant.broker_capability_id == bounded_use.capability_id
                && grant.lease_id == admission.runtime_lease.lease_id
        })
        .map(|grant| &grant.broker_runtime_lease_id)
}

#[allow(clippy::too_many_lines)]
fn validate_broker_lease_revocation_convergences(
    snapshot: &ManifoldPeerRuntimeHostSnapshot,
) -> Result<(), ManifoldPeerRuntimeHostError> {
    if !unique_ids(
        snapshot
            .broker_lease_revocation_convergences
            .iter()
            .map(|receipt| &receipt.convergence_id),
    ) || !unique_ids(
        snapshot
            .broker_lease_revocation_convergences
            .iter()
            .map(|receipt| &receipt.broker_lifecycle_receipt.lifecycle_request_id),
    ) {
        return Err(invalid_snapshot(
            "broker revocation convergence identity/replay state",
        ));
    }
    for receipt in &snapshot.broker_lease_revocation_convergences {
        let lifecycle = &receipt.broker_lifecycle_receipt;
        let transition = lifecycle
            .authority_transition
            .as_ref()
            .ok_or_else(|| invalid_snapshot("broker revocation convergence transition missing"))?;
        let ManifoldBrokerControlLeaseTransitionApplication::Revocation(application) =
            &transition.application
        else {
            return Err(invalid_snapshot(
                "broker revocation convergence transition kind",
            ));
        };
        application
            .validate_against_snapshot(&transition.prior_authority_snapshot)
            .map_err(|_| invalid_snapshot("broker revocation convergence application lineage"))?;
        let expected_upstream_proof =
            ManifoldRuntimeUpstreamRevocationProof::from_accepted_application(
                receipt.peer_provider_epoch_id.clone(),
                transition.prior_authority_snapshot.clone(),
                application.as_ref().clone(),
            )
            .map_err(|_| invalid_snapshot("broker revocation convergence upstream proof"))?;
        let applied_snapshot = application
            .applied_snapshot
            .as_ref()
            .ok_or_else(|| invalid_snapshot("broker revocation convergence accepted state"))?;
        let tombstone = application
            .tombstone
            .as_ref()
            .ok_or_else(|| invalid_snapshot("broker revocation convergence tombstone"))?;
        let broker_revoked_at_ms =
            u64::try_from(tombstone.recorded_clock.wall_unix_ms).map_err(|_| {
                invalid_snapshot("broker revocation convergence clock predates Unix epoch")
            })?;
        let adoption = lifecycle
            .host_adoption
            .as_ref()
            .ok_or_else(|| invalid_snapshot("broker revocation convergence host adoption"))?;
        receipt
            .inner_runtime_lease_revocation_receipt
            .validate_against_snapshot(&snapshot.media_command_runtime)
            .map_err(|_| {
                invalid_snapshot("broker revocation convergence inner Runtime Host receipt")
            })?;
        let provider_epoch_valid = receipt.peer_provider_epoch_id == snapshot.provider_epoch_id
            || provider_epoch_is_checkpointed(snapshot, &receipt.peer_provider_epoch_id);
        if receipt.schema_id.as_str()
            != PEER_RUNTIME_BROKER_LEASE_REVOCATION_CONVERGENCE_RECEIPT_SCHEMA
            || receipt.peer_host_id != snapshot.host_id
            || !provider_epoch_valid
            || receipt.converged_at_ms < broker_revoked_at_ms
            || lifecycle.provider_epoch_id != receipt.peer_provider_epoch_id
            || lifecycle.operation_kind
                != ManifoldBrokerControlLeaseLifecycleOperationKind::Revocation
            || lifecycle.outcome != ManifoldBrokerControlLeaseLifecycleOutcome::AcceptedAndAdopted
            || !lifecycle.applied
            || lifecycle.rejection_reason.is_some()
            || !lifecycle.admission_use_consumed
            || application.outcome
                != ManifoldControlLeaseRevocationAuthorityApplicationOutcome::LeaseRevocationApplied
            || tombstone != &receipt.outer_control_lease_tombstone
            || application.lease_id != tombstone.revoked_lease.lease_id
            || !applied_snapshot
                .revoked_control_lease_tombstones
                .iter()
                .any(|candidate| candidate == tombstone)
            || applied_snapshot
                .active_leases
                .iter()
                .any(|lease| lease.lease_id == tombstone.revoked_lease.lease_id)
            || !adoption.applied
            || adoption.rejection_reason.is_some()
            || adoption.manifold_application_id != application.application_id
            || adoption.removed_lease_ids != vec![tombstone.revoked_lease.lease_id.clone()]
            || receipt
                .inner_runtime_lease_revocation_receipt
                .authority_host_id
                != snapshot.media_command_runtime.host_id
            || receipt.inner_runtime_lease_revocation_receipt.revocation_id
                != derived("revocation.runtime", &receipt.convergence_id)
            || receipt
                .inner_runtime_lease_revocation_receipt
                .convergence_id
                != receipt.convergence_id
            || receipt
                .inner_runtime_lease_revocation_receipt
                .provider_epoch_id
                != receipt.peer_provider_epoch_id
            || receipt
                .inner_runtime_lease_revocation_receipt
                .upstream_revocation_application_id
                != application.application_id
            || receipt
                .inner_runtime_lease_revocation_receipt
                .upstream_revocation_proof
                != expected_upstream_proof
            || !receipt.inner_runtime_lease_revocation_receipt.applied
            || !receipt.applied
            || receipt.resulting_peer_event_sequence
                != receipt.prior_peer_event_sequence.saturating_add(1)
            || receipt.resulting_peer_event_sequence > snapshot.event_sequence
            || receipt.platform_cleanup_pending == receipt.cleanup_obligations.is_empty()
            || !strictly_sorted_unique(receipt.affected_broker_admission_use_ids.iter())
            || !strictly_sorted_unique(receipt.removed_inner_runtime_lease_ids.iter())
            || !strictly_sorted_unique(receipt.revoked_media_decision_ids.iter())
            || !strictly_sorted_unique(receipt.revoked_direct_lane_lease_ids.iter())
            || !strictly_sorted_unique(
                receipt
                    .cleanup_obligations
                    .iter()
                    .map(|obligation| &obligation.session_decision_id),
            )
        {
            return Err(invalid_snapshot(
                "broker revocation convergence receipt shape",
            ));
        }

        let affected_admissions = snapshot
            .broker_lease_admissions
            .iter()
            .filter(|admission| admission.release_id.as_ref() == Some(&receipt.convergence_id))
            .collect::<Vec<_>>();
        let actual_admission_use_ids = affected_admissions
            .iter()
            .map(|admission| admission.broker_receipt.admission_use_request_id.clone())
            .collect::<BTreeSet<_>>();
        let actual_inner_lease_ids = affected_admissions
            .iter()
            .map(|admission| admission.runtime_lease.lease_id.clone())
            .collect::<BTreeSet<_>>();
        let mut actual_inner_leases = affected_admissions
            .iter()
            .map(|admission| admission.runtime_lease.clone())
            .collect::<Vec<_>>();
        actual_inner_leases.sort_by(|left, right| left.lease_id.cmp(&right.lease_id));
        if affected_admissions.is_empty()
            || actual_admission_use_ids
                != receipt
                    .affected_broker_admission_use_ids
                    .iter()
                    .cloned()
                    .collect()
            || actual_inner_lease_ids
                != receipt
                    .removed_inner_runtime_lease_ids
                    .iter()
                    .cloned()
                    .collect()
            || receipt
                .inner_runtime_lease_revocation_receipt
                .requested_leases
                != actual_inner_leases
            || receipt
                .inner_runtime_lease_revocation_receipt
                .removed_leases
                != actual_inner_leases
            || receipt
                .inner_runtime_lease_revocation_receipt
                .removed_lease_ids
                != receipt.removed_inner_runtime_lease_ids
            || affected_admissions.iter().any(|admission| {
                broker_outer_lease_id_for_admission(snapshot, admission)
                    != Some(&tombstone.revoked_lease.lease_id)
                    || admission.released_at_ms != Some(receipt.converged_at_ms)
            })
            || snapshot.media_command_runtime.leases.iter().any(|lease| {
                receipt
                    .removed_inner_runtime_lease_ids
                    .contains(&lease.lease_id)
            })
        {
            return Err(invalid_snapshot(
                "broker revocation convergence admission tombstone",
            ));
        }

        for decision_id in &receipt.revoked_media_decision_ids {
            let session = snapshot
                .media_sessions
                .sessions
                .iter()
                .find(|session| &session.decision_id == decision_id)
                .ok_or_else(|| {
                    invalid_snapshot("broker revocation convergence media decision missing")
                })?;
            let obligation = receipt
                .cleanup_obligations
                .iter()
                .find(|obligation| &obligation.session_decision_id == decision_id)
                .ok_or_else(|| {
                    invalid_snapshot("broker revocation convergence cleanup obligation missing")
                })?;
            let descriptor = &session.product_binding.descriptor;
            if session.lifecycle_status != ManifoldMediaSessionLifecycleStatus::Revoked
                || session.ended_by_id.as_ref() != Some(&receipt.convergence_id)
                || session.ended_at_ms != Some(receipt.converged_at_ms)
                || receipt.converged_at_ms < session.accepted_at_ms
                || !receipt
                    .removed_inner_runtime_lease_ids
                    .contains(&session.runtime_lease_id)
                || obligation.schema_id.as_str() != PEER_RUNTIME_MEDIA_CLEANUP_OBLIGATION_SCHEMA
                || obligation.session_id != session.session_id
                || obligation.platform_runtime_spec_id != session.platform_runtime_spec_id
                || obligation.source_ids != descriptor.source_ids
                || obligation.processor_ids != descriptor.processor_ids
                || obligation.route_ids != descriptor.route_ids
                || obligation.sink_ids != descriptor.sink_ids
                || obligation.stream_ids != descriptor.stream_ids
            {
                return Err(invalid_snapshot(
                    "broker revocation convergence media cleanup closure",
                ));
            }
        }
        if receipt.cleanup_obligations.len() != receipt.revoked_media_decision_ids.len()
            || receipt.cleanup_obligations.iter().any(|obligation| {
                !strictly_sorted_unique(obligation.source_ids.iter())
                    || !strictly_sorted_unique(obligation.processor_ids.iter())
                    || !strictly_sorted_unique(obligation.route_ids.iter())
                    || !strictly_sorted_unique(obligation.sink_ids.iter())
                    || !strictly_sorted_unique(obligation.stream_ids.iter())
            })
            || receipt
                .revoked_direct_lane_lease_ids
                .iter()
                .any(|lease_id| {
                    !snapshot.direct_lane_leases.leases.iter().any(|lease| {
                        &lease.lease_id == lease_id
                            && lease.revoked
                            && lease.valid_from_ms <= receipt.converged_at_ms
                            && (receipt
                                .removed_inner_runtime_lease_ids
                                .contains(&lease.holder_runtime_lease_id)
                                || lease.media_session_decision_id.as_ref().is_some_and(
                                    |decision_id| {
                                        receipt.revoked_media_decision_ids.contains(decision_id)
                                    },
                                ))
                    })
                })
        {
            return Err(invalid_snapshot(
                "broker revocation convergence derivative closure",
            ));
        }
        let expected_media_decision_ids = snapshot
            .media_sessions
            .sessions
            .iter()
            .filter(|session| {
                session.lifecycle_status == ManifoldMediaSessionLifecycleStatus::Revoked
                    && session.ended_by_id.as_ref() == Some(&receipt.convergence_id)
            })
            .map(|session| session.decision_id.clone())
            .collect::<BTreeSet<_>>();
        let expected_cleanup_decision_ids = receipt
            .cleanup_obligations
            .iter()
            .map(|obligation| obligation.session_decision_id.clone())
            .collect::<BTreeSet<_>>();
        let expected_direct_lane_lease_ids = snapshot
            .direct_lane_leases
            .leases
            .iter()
            .filter(|lease| {
                receipt
                    .removed_inner_runtime_lease_ids
                    .contains(&lease.holder_runtime_lease_id)
                    || lease
                        .media_session_decision_id
                        .as_ref()
                        .is_some_and(|decision_id| {
                            receipt.revoked_media_decision_ids.contains(decision_id)
                        })
            })
            .map(|lease| lease.lease_id.clone())
            .collect::<BTreeSet<_>>();
        if expected_media_decision_ids
            != receipt.revoked_media_decision_ids.iter().cloned().collect()
            || expected_cleanup_decision_ids != expected_media_decision_ids
            || expected_direct_lane_lease_ids
                != receipt
                    .revoked_direct_lane_lease_ids
                    .iter()
                    .cloned()
                    .collect()
        {
            return Err(invalid_snapshot(
                "broker revocation convergence incomplete derivative set",
            ));
        }
    }
    Ok(())
}

fn validate_broker_lease_revocation_cleanup_completions(
    snapshot: &ManifoldPeerRuntimeHostSnapshot,
) -> Result<(), ManifoldPeerRuntimeHostError> {
    if !unique_ids(
        snapshot
            .broker_lease_revocation_cleanup_completions
            .iter()
            .map(|receipt| &receipt.completion_id),
    ) || !unique_ids(
        snapshot
            .broker_lease_revocation_cleanup_completions
            .iter()
            .map(|receipt| &receipt.convergence_id),
    ) {
        return Err(invalid_snapshot(
            "broker revocation cleanup completion replay state",
        ));
    }
    for receipt in &snapshot.broker_lease_revocation_cleanup_completions {
        let convergence = snapshot
            .broker_lease_revocation_convergences
            .iter()
            .find(|convergence| convergence.convergence_id == receipt.convergence_id)
            .ok_or_else(|| {
                invalid_snapshot("broker revocation cleanup completion convergence missing")
            })?;
        let audit = snapshot.audit_events.iter().find(|event| {
            event.sequence == receipt.resulting_peer_event_sequence
                && event.source_id == receipt.completion_id
        });
        if receipt.schema_id.as_str()
            != PEER_RUNTIME_BROKER_LEASE_REVOCATION_CLEANUP_COMPLETION_RECEIPT_SCHEMA
            || receipt.peer_host_id != snapshot.host_id
            || receipt.peer_provider_epoch_id != convergence.peer_provider_epoch_id
            || (receipt.peer_provider_epoch_id != snapshot.provider_epoch_id
                && !provider_epoch_is_checkpointed(snapshot, &receipt.peer_provider_epoch_id))
            || !receipt.completed
            || receipt.completed_obligations != convergence.cleanup_obligations
            || !valid_sha256(&receipt.platform_cleanup_receipt_sha256)
            || receipt.resulting_peer_event_sequence
                != receipt.prior_peer_event_sequence.saturating_add(1)
            || receipt.resulting_peer_event_sequence > snapshot.event_sequence
            || audit.map_or(true, |event| {
                event.event_kind
                    != ManifoldPeerRuntimeAuditKind::BrokerLeaseRevocationCleanupCompletion
                    || !event.applied
                    || event.rejection_code.is_some()
                    || event.prior_authority_revision
                        != convergence.resulting_media_authority_revision
                    || event.resulting_authority_revision
                        != convergence.resulting_media_authority_revision
            })
        {
            return Err(invalid_snapshot(
                "broker revocation cleanup completion receipt mismatch",
            ));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_topology_and_audit_state(
    snapshot: &ManifoldPeerRuntimeHostSnapshot,
) -> Result<(), ManifoldPeerRuntimeHostError> {
    if !unique_ids(
        snapshot
            .signed_topology_authorizations
            .iter()
            .map(|topology| &topology.topology_authorization.decision_id),
    ) || snapshot
        .signed_topology_authorizations
        .iter()
        .any(|topology| {
            topology.schema_id.as_str() != SIGNED_PEER_TOPOLOGY_AUTHORIZATION_SCHEMA
                || topology.topology_authorization.schema_id.as_str()
                    != PEER_TOPOLOGY_AUTHORIZATION_SCHEMA
                || !snapshot.peer_sessions.sessions.iter().any(|session| {
                    session.decision_id == topology.topology_authorization.decision_id
                        && session.proposal.session_id == topology.topology_authorization.session_id
                })
                || !snapshot
                    .rendezvous
                    .accepted_receipts
                    .iter()
                    .any(|receipt| receipt.receipt_id == topology.rendezvous_receipt_id)
        })
    {
        return Err(invalid_snapshot("signed topology provenance"));
    }
    if snapshot.event_sequence != snapshot.audit_events.len() as u64 {
        return Err(invalid_snapshot("audit sequence/count mismatch"));
    }
    for (index, event) in snapshot.audit_events.iter().enumerate() {
        let sequence = (index as u64) + 1;
        if event.schema_id.as_str() != PEER_RUNTIME_HOST_AUDIT_SCHEMA
            || event.sequence != sequence
            || event.event_id != audit_id(sequence)
            || (event.applied && event.rejection_code.is_some())
        {
            return Err(invalid_snapshot("audit event continuity"));
        }
    }
    let broker_admission_sources = snapshot
        .audit_events
        .iter()
        .filter(|event| {
            event.event_kind == ManifoldPeerRuntimeAuditKind::BrokerLeaseAdmission && event.applied
        })
        .map(|event| event.source_id.clone())
        .collect::<BTreeSet<_>>();
    let expected_broker_admission_sources = snapshot
        .broker_lease_admissions
        .iter()
        .map(|admission| admission.broker_receipt.admission_use_request_id.clone())
        .collect::<BTreeSet<_>>();
    let all_broker_admission_sources = snapshot
        .audit_events
        .iter()
        .filter(|event| event.event_kind == ManifoldPeerRuntimeAuditKind::BrokerLeaseAdmission)
        .map(|event| event.source_id.clone())
        .collect::<BTreeSet<_>>();
    let all_broker_admission_count = snapshot
        .audit_events
        .iter()
        .filter(|event| event.event_kind == ManifoldPeerRuntimeAuditKind::BrokerLeaseAdmission)
        .count();
    let broker_release_sources = snapshot
        .audit_events
        .iter()
        .filter(|event| event.event_kind == ManifoldPeerRuntimeAuditKind::BrokerLeaseRelease)
        .map(|event| event.source_id.clone())
        .collect::<BTreeSet<_>>();
    let expected_broker_convergence_sources = snapshot
        .broker_lease_revocation_convergences
        .iter()
        .map(|receipt| receipt.convergence_id.clone())
        .collect::<BTreeSet<_>>();
    let expected_broker_release_sources = snapshot
        .broker_lease_admissions
        .iter()
        .filter_map(|admission| admission.release_id.clone())
        .filter(|release_id| !expected_broker_convergence_sources.contains(release_id))
        .collect::<BTreeSet<_>>();
    let broker_convergence_sources = snapshot
        .audit_events
        .iter()
        .filter(|event| {
            event.event_kind == ManifoldPeerRuntimeAuditKind::BrokerLeaseRevocationConvergence
                && event.applied
        })
        .map(|event| event.source_id.clone())
        .collect::<BTreeSet<_>>();
    if broker_admission_sources != expected_broker_admission_sources
        || broker_release_sources != expected_broker_release_sources
        || broker_convergence_sources != expected_broker_convergence_sources
        || all_broker_admission_count != all_broker_admission_sources.len()
        || snapshot.audit_events.iter().any(|event| {
            event.event_kind == ManifoldPeerRuntimeAuditKind::BrokerLeaseAdmission
                && !event.applied
                && event.rejection_code.is_none()
        })
        || snapshot
            .audit_events
            .iter()
            .filter(|event| event.event_kind == ManifoldPeerRuntimeAuditKind::BrokerLeaseRelease)
            .count()
            != expected_broker_release_sources.len()
        || snapshot
            .audit_events
            .iter()
            .filter(|event| {
                event.event_kind == ManifoldPeerRuntimeAuditKind::BrokerLeaseRevocationConvergence
            })
            .count()
            != expected_broker_convergence_sources.len()
        || snapshot
            .broker_lease_revocation_convergences
            .iter()
            .any(|receipt| {
                !snapshot.audit_events.iter().any(|event| {
                    event.event_kind
                        == ManifoldPeerRuntimeAuditKind::BrokerLeaseRevocationConvergence
                        && event.source_id == receipt.convergence_id
                        && event.sequence == receipt.resulting_peer_event_sequence
                        && event.prior_authority_revision
                            == receipt
                                .outer_control_lease_tombstone
                                .prior_authority_revision
                        && event.resulting_authority_revision
                            == receipt
                                .outer_control_lease_tombstone
                                .revoked_authority_revision
                        && event.applied
                })
            })
    {
        return Err(invalid_snapshot("broker lease audit provenance/replay"));
    }
    Ok(())
}

fn invalid_snapshot(reason: &str) -> ManifoldPeerRuntimeHostError {
    ManifoldPeerRuntimeHostError::InvalidSnapshot(reason.to_owned())
}

fn unique_ids<'a>(values: impl Iterator<Item = &'a DottedId>) -> bool {
    let values = values.collect::<Vec<_>>();
    values.iter().copied().collect::<BTreeSet<_>>().len() == values.len()
}

fn strictly_sorted_unique<'a>(values: impl Iterator<Item = &'a DottedId>) -> bool {
    let values = values.collect::<Vec<_>>();
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn unique_strings<'a>(values: impl Iterator<Item = &'a String>) -> bool {
    let values = values.collect::<Vec<_>>();
    values.iter().copied().collect::<BTreeSet<_>>().len() == values.len()
}

fn rejection_code<T: Serialize>(value: Option<&T>) -> Option<String> {
    value.and_then(|reason| {
        serde_json::to_value(reason)
            .ok()
            .and_then(|encoded| encoded.as_str().map(str::to_owned))
    })
}

fn broker_lease_attempt(
    outcome: ManifoldPeerRuntimeBrokerLeaseAttemptOutcome,
    broker_receipt: ManifoldBrokerMutationReceipt,
    lease_admission: Option<ManifoldPeerRuntimeBrokerLeaseAdmission>,
    peer_rejection_code: Option<String>,
) -> ManifoldPeerRuntimeBrokerLeaseAttempt {
    ManifoldPeerRuntimeBrokerLeaseAttempt {
        schema_id: schema(PEER_RUNTIME_BROKER_LEASE_ATTEMPT_SCHEMA),
        outcome,
        broker_receipt,
        lease_admission,
        peer_rejection_code,
    }
}

fn schema(value: &str) -> SchemaId {
    SchemaId::new(value).expect("static peer Runtime Host schema")
}

fn derived(prefix: &str, source_id: &DottedId) -> DottedId {
    DottedId::new(format!("{prefix}.{}", source_id.as_str())).expect("derived peer Runtime Host id")
}

fn broker_runtime_derivative_binding(
    provider_epoch_id: &DottedId,
    upstream_control_lease_id: &DottedId,
    source_authorization_id: &DottedId,
) -> ManifoldRuntimeDerivativeLeaseBinding {
    ManifoldRuntimeDerivativeLeaseBinding {
        schema_id: schema(HOST_DERIVATIVE_LEASE_BINDING_SCHEMA),
        binding_id: derived("binding.runtime_lease", source_authorization_id),
        provider_epoch_id: provider_epoch_id.clone(),
        upstream_control_lease_id: upstream_control_lease_id.clone(),
        source_authorization_id: source_authorization_id.clone(),
    }
}

fn domain_separated_digest<T: Serialize>(
    domain: &str,
    value: &T,
) -> Result<String, ManifoldPeerRuntimeHostError> {
    let serialized = serde_json::to_vec(value).map_err(ManifoldPeerRuntimeHostError::Serialize)?;
    let mut framed = Vec::with_capacity(domain.len().saturating_add(serialized.len() + 1));
    framed.extend_from_slice(domain.as_bytes());
    framed.push(0);
    framed.extend_from_slice(&serialized);
    Ok(packaged_product_lock_sha256(&framed))
}

fn audit_id(sequence: u64) -> DottedId {
    DottedId::new(format!("audit.peer-runtime.{sequence:020}"))
        .expect("derived peer Runtime Host audit id")
}

#[cfg(test)]
mod tests;
