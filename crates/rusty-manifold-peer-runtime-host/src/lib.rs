//! Compile-time-selected source-only Runtime Host extension for peer authority.
//!
//! `rusty-manifold-peer` remains the pure decision layer. This crate owns the
//! durable composition, current-state routing, restart snapshot, and unified
//! audit sequence. It deliberately contains no sockets, platform APIs,
//! sidecars, codecs, or media payloads.

use std::collections::BTreeSet;
use std::fmt;

use rusty_manifold_broker_adapter::{
    ManifoldBrokerAdapterMode, ManifoldBrokerAdapterRole, ManifoldBrokerMutationReceipt,
    ManifoldBrokerMutationRequest, ManifoldBrokerRuntime, ManifoldBrokerRuntimeEvidence,
    BROKER_ADAPTER_RECEIPT_SCHEMA, BROKER_BOUNDED_USE_SCHEMA, BROKER_MUTATION_RECEIPT_SCHEMA,
    BROKER_MUTATION_REQUEST_SCHEMA, BROKER_RUNTIME_EVIDENCE_SCHEMA, RUNTIME_HOST_AUTHORITY_OWNER,
};
use rusty_manifold_media_session::{
    expire_media_sessions, review_and_apply_media_session_acceptance,
    review_and_apply_media_session_termination, validate_current_media_session,
    validate_media_session_acceptance_state, ManifoldMediaSessionAcceptanceReceipt,
    ManifoldMediaSessionAcceptanceRequest, ManifoldMediaSessionAcceptanceState,
    ManifoldMediaSessionClientGrant, ManifoldMediaSessionCurrentReceipt,
    ManifoldMediaSessionMutationReceipt, ManifoldMediaSessionRuntimeCommandContext,
    ManifoldMediaSessionTerminationRequest, MANIFOLD_MEDIA_SESSION_ACCEPTANCE_STATE_SCHEMA,
    MANIFOLD_MEDIA_SESSION_ACCEPT_COMMAND, MANIFOLD_MEDIA_SESSION_REVOKE_COMMAND,
    MANIFOLD_MEDIA_SESSION_STOP_COMMAND,
};
use rusty_manifold_model::{DottedId, Revision, SchemaId};
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
    ManifoldRuntimeCommandRequest, ManifoldRuntimeDispatchOutcome, ManifoldRuntimeHost,
    ManifoldRuntimeHostSnapshot, ManifoldRuntimeLease, HOST_APPLICATION_RECEIPT_SCHEMA,
    HOST_COMMAND_REQUEST_SCHEMA, HOST_DISPATCH_RECEIPT_SCHEMA, HOST_SNAPSHOT_SCHEMA,
};
use serde::{Deserialize, Serialize};

/// Durable peer Runtime Host snapshot schema.
pub const PEER_RUNTIME_HOST_SNAPSHOT_SCHEMA: &str = "rusty.manifold.peer.runtime_host.snapshot.v1";
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
        let snapshot =
            serde_json::from_str(json).map_err(ManifoldPeerRuntimeHostError::Deserialize)?;
        Self::from_snapshot(snapshot, expected_trust_policy, expected_provider_epoch_id)
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

    /// Atomically consumes one bounded use in the owning live `BrokerRuntime`
    /// and mints the corresponding short-lived inner media Runtime Host lease.
    /// A caller-supplied/deserialized mutation receipt is never accepted as
    /// authority. Both candidate states commit only after the complete live
    /// broker result and current evidence have been revalidated.
    ///
    /// # Errors
    ///
    /// Returns a host error without committing either candidate when family,
    /// capacity, replay, broker, provenance, command, or current-state gates
    /// reject.
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

        let mut preview_broker = broker_runtime.clone();
        let preview = preview_broker.handle_mutation(request, now_ms);
        if !preview.admission_applied {
            return Ok(broker_lease_attempt(
                ManifoldPeerRuntimeBrokerLeaseAttemptOutcome::BrokerAdmissionRejected,
                preview,
                None,
                None,
            ));
        }

        let mut next_broker = broker_runtime.clone();
        let receipt = next_broker.handle_mutation(request, now_ms);
        if receipt != preview {
            return Err(ManifoldPeerRuntimeHostError::Authority(
                "live broker mutation differed from pure preview".to_owned(),
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
            *self = next_host;
            *broker_runtime = next_broker;
            return Ok(broker_lease_attempt(
                ManifoldPeerRuntimeBrokerLeaseAttemptOutcome::BrokerCommandRejected,
                receipt,
                None,
                Some(rejection),
            ));
        }

        let broker_evidence = next_broker.evidence();
        let mut admitted_host = next_host.clone();
        let admission = admitted_host.admit_live_broker_media_receipt(
            request,
            &receipt,
            &broker_evidence,
            now_ms,
        );
        match admission {
            Ok(admission) => {
                validate_snapshot(&admitted_host.snapshot)?;
                *self = admitted_host;
                *broker_runtime = next_broker;
                Ok(broker_lease_attempt(
                    ManifoldPeerRuntimeBrokerLeaseAttemptOutcome::LeaseAdmitted,
                    receipt,
                    Some(admission),
                    None,
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
                *self = next_host;
                *broker_runtime = next_broker;
                Ok(broker_lease_attempt(
                    ManifoldPeerRuntimeBrokerLeaseAttemptOutcome::PeerLeaseRejected,
                    receipt,
                    None,
                    Some(rejection),
                ))
            }
        }
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
        validate_current_media_session(
            &self.snapshot.media_sessions,
            decision_id,
            &self.snapshot.provider_epoch_id,
            now_ms,
        )
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

fn validate_snapshot(
    snapshot: &ManifoldPeerRuntimeHostSnapshot,
) -> Result<(), ManifoldPeerRuntimeHostError> {
    validate_snapshot_schemas(snapshot)?;
    validate_snapshot_capacity(snapshot)?;
    validate_trust_policy(&snapshot.trust_policy)?;
    validate_media_command_runtime(snapshot)?;
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
    admission.schema_id.as_str() == PEER_RUNTIME_BROKER_LEASE_ADMISSION_SCHEMA
        && receipt.schema_id.as_str() == BROKER_MUTATION_RECEIPT_SCHEMA
        && bounded_use.schema_id.as_str() == BROKER_BOUNDED_USE_SCHEMA
        && adapter.schema_id.as_str() == BROKER_ADAPTER_RECEIPT_SCHEMA
        && receipt.provider_epoch_id == snapshot.provider_epoch_id
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
        && admission.runtime_lease.expires_at_ms
            == bounded_use
                .expires_at_ms
                .min(admission.admitted_at_ms.saturating_add(120_000))
        && release_tuple_valid
}

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
    let expected_broker_release_sources = snapshot
        .broker_lease_admissions
        .iter()
        .filter_map(|admission| admission.release_id.clone())
        .collect::<BTreeSet<_>>();
    if broker_admission_sources != expected_broker_admission_sources
        || broker_release_sources != expected_broker_release_sources
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

fn audit_id(sequence: u64) -> DottedId {
    DottedId::new(format!("audit.peer-runtime.{sequence:020}"))
        .expect("derived peer Runtime Host audit id")
}

#[cfg(test)]
mod tests;
