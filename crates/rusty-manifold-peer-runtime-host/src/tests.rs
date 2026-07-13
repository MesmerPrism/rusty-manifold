use std::fmt::Write as _;

use ed25519_dalek::{Signer, SigningKey};
use rusty_manifold_admission::{
    ManifoldAdmissionGrant, ManifoldAdmissionRequest, ManifoldAdmissionSnapshot,
    ManifoldAdmissionUseRequest, ManifoldClientIdentity, ADMISSION_REQUEST_SCHEMA,
    ADMISSION_SNAPSHOT_SCHEMA, ADMISSION_USE_REQUEST_SCHEMA,
};
use rusty_manifold_broker_adapter::{
    command_capability, packaged_product_lock_sha256, ManifoldBrokerAdapter,
    ManifoldBrokerAdapterConfig, ManifoldBrokerAdapterMode, ManifoldBrokerMutationRequest,
    ManifoldBrokerRuntime, BROKER_ADAPTER_CONFIG_SCHEMA, BROKER_MUTATION_REQUEST_SCHEMA,
};
use rusty_manifold_broker_product::{
    resolve_broker_product, ManifoldBrokerFeature, ManifoldBrokerProductSpec,
    BROKER_PRODUCT_SPEC_SCHEMA,
};
use rusty_manifold_media_session::{
    canonical_media_session_sha256, media_session_acceptance_params_digest,
    media_session_termination_params_digest, ManifoldMediaSessionAcceptanceRequest,
    ManifoldMediaSessionProductBinding, ManifoldMediaSessionTerminationAction,
    ManifoldMediaSessionTerminationRequest, MANIFOLD_MEDIA_SESSION_ACCEPTANCE_REQUEST_SCHEMA,
    MANIFOLD_MEDIA_SESSION_ACCEPT_COMMAND, MANIFOLD_MEDIA_SESSION_BINDING_SCHEMA,
    MANIFOLD_MEDIA_SESSION_REVOKE_COMMAND, MANIFOLD_MEDIA_SESSION_STOP_COMMAND,
    MANIFOLD_MEDIA_SESSION_TERMINATION_REQUEST_SCHEMA,
};
use rusty_manifold_model::{
    DottedId, ManifoldMediaSessionDescriptor, Revision, SchemaId, MANIFOLD_BINARY_MEDIA_PLANE,
    MANIFOLD_MEDIA_SESSION_SCHEMA,
};
use rusty_manifold_peer::{
    direct_lane_lease_issue_params_digest, direct_lane_lease_use_params_digest,
    reciprocal_ed25519_context_sha256, reciprocal_ed25519_context_signing_bytes,
    rendezvous_signing_bytes, ManifoldDirectLaneClientGrant, ManifoldDirectLaneLeaseCurrentReceipt,
    ManifoldDirectLaneLeaseRejectionReason, ManifoldDirectLaneLeaseRequest,
    ManifoldDirectLaneLeaseScope, ManifoldDirectLaneLeaseUseRequest,
    ManifoldPeerCredentialAlgorithm, ManifoldPeerCredentialRecord, ManifoldPeerCredentialStatus,
    ManifoldPeerEnrollmentAction, ManifoldPeerEnrollmentRejectionReason,
    ManifoldPeerEnrollmentRequest, ManifoldPeerMeshProposal, ManifoldPeerMeshRejectionReason,
    ManifoldPeerMeshReviewCase, ManifoldPeerSessionProposal, ManifoldPeerSessionRejectionReason,
    ManifoldPeerSessionReviewCase, ManifoldReciprocalEd25519Context,
    ManifoldReciprocalEd25519PeerBinding, ManifoldReciprocalEd25519ReviewRequest,
    ManifoldReciprocalEd25519Revisions, ManifoldReciprocalEd25519Signature,
    ManifoldRendezvousRejectionReason, ManifoldRendezvousReviewRequest, ManifoldRendezvousRole,
    ManifoldSignedRendezvousEvidence, PeerRendezvousTransport, DIRECT_LANE_LEASE_ISSUE_COMMAND,
    DIRECT_LANE_LEASE_REQUEST_SCHEMA, DIRECT_LANE_LEASE_REVOKE_COMMAND,
    DIRECT_LANE_LEASE_USE_COMMAND, DIRECT_LANE_LEASE_USE_REQUEST_SCHEMA,
    DIRECT_LANE_MEDIA_SESSION_CAPABILITY, DIRECT_LANE_PEER_SESSION_CAPABILITY,
    PEER_CREDENTIAL_SCHEMA, PEER_ENROLLMENT_REQUEST_SCHEMA, PRODUCT_WIFI_DIRECT_TOPOLOGY_CONTRACT,
    RECIPROCAL_ED25519_CONTEXT_SCHEMA, RECIPROCAL_ED25519_REVIEW_SCHEMA,
    RECIPROCAL_ED25519_SIGNATURE_SCHEMA, RENDEZVOUS_REVIEW_REQUEST_SCHEMA,
    SIGNED_RENDEZVOUS_EVIDENCE_SCHEMA,
};
use rusty_manifold_runtime_host::{
    ManifoldRuntimeCommandDescriptor, ManifoldRuntimeLease, HOST_COMMAND_REQUEST_SCHEMA,
};
use sha2::{Digest, Sha256};

use super::*;

const OPERATOR_ID: &str = "operator.peer.enrollment";
const TRUSTED_ADAPTER_ID: &str = "adapter.quest.ble-rendezvous";
const TRUSTED_MESH_PROPOSER_ID: &str = "adapter.quest.peer-mesh";
const TRUSTED_MEDIA_PROPOSER_ID: &str = "client.quest.media-test";
const MEDIA_RUNTIME_HOST_ID: &str = "host.runtime.media-test";
const MEDIA_RUNTIME_LEASE_SCOPE_ID: &str = "scope.media.session.authority";
const DIRECT_RUNTIME_LEASE_SCOPE_ID: &str = "scope.direct-lane.authority";
const PROVIDER_EPOCH_ID: &str = "provider.epoch.quest-test.001";

fn media_descriptor(session_revision: u64) -> ManifoldMediaSessionDescriptor {
    ManifoldMediaSessionDescriptor {
        schema_id: schema_id(MANIFOLD_MEDIA_SESSION_SCHEMA),
        session_id: id("session.media.quest-pair.001"),
        authority_revision: Revision::new(session_revision).expect("session revision"),
        platform_runtime_spec_id: id("runtime.quest.direct-p2p"),
        source_ids: vec![id("source.quest.camera.alpha")],
        processor_ids: vec![id("processor.quest.layout.passthrough")],
        route_ids: vec![id("route.alpha-beta.fast")],
        sink_ids: vec![id("sink.quest.beta")],
        stream_ids: vec![id("stream.quest.camera.alpha-beta")],
        payload_plane: MANIFOLD_BINARY_MEDIA_PLANE.to_owned(),
        inline_media_payloads_allowed: false,
        remote_camera_compatibility: false,
    }
}

fn media_resource_ids() -> Vec<DottedId> {
    let descriptor = media_descriptor(6);
    let mut ids = descriptor
        .source_ids
        .into_iter()
        .chain(descriptor.processor_ids)
        .chain(descriptor.route_ids)
        .chain(descriptor.sink_ids)
        .chain(descriptor.stream_ids)
        .collect::<Vec<_>>();
    ids.sort();
    ids
}

fn trust_policy() -> ManifoldPeerRuntimeTrustPolicy {
    ManifoldPeerRuntimeTrustPolicy {
        schema_id: schema_id(PEER_RUNTIME_HOST_TRUST_POLICY_SCHEMA),
        policy_id: id("policy.peer-runtime.test"),
        revision: Revision::INITIAL,
        enabled_authority_families: vec![
            ManifoldPeerRuntimeAuthorityFamily::PeerStatus,
            ManifoldPeerRuntimeAuthorityFamily::Enrollment,
            ManifoldPeerRuntimeAuthorityFamily::Rendezvous,
            ManifoldPeerRuntimeAuthorityFamily::PeerMesh,
            ManifoldPeerRuntimeAuthorityFamily::MediaSession,
            ManifoldPeerRuntimeAuthorityFamily::DirectLane,
        ],
        trusted_operator_ids: vec![id(OPERATOR_ID)],
        trusted_key_fingerprints: vec![id("fingerprint.bootstrap.test")],
        trusted_adapter_ids: vec![id(TRUSTED_ADAPTER_ID)],
        trusted_mesh_proposer_ids: vec![id(TRUSTED_MESH_PROPOSER_ID)],
        media_client_grants: vec![ManifoldMediaSessionClientGrant {
            broker_adapter_id: id("adapter.broker.media-test"),
            broker_runtime_host_id: id("host.broker.media-test"),
            broker_product_lock_id: id("lock.broker.media-test"),
            broker_product_lock_fingerprint: "fnv1a64-0011223344556677".to_owned(),
            broker_product_lock_sha256: format!("sha256:{}", "d1".repeat(32)),
            broker_capability_id: id("capability.command.media.session.start"),
            broker_command_id: id("command.media.session.start"),
            broker_runtime_lease_id: id("lease.broker.media-test"),
            broker_client_identity: ManifoldClientIdentity {
                client_id: id(TRUSTED_MEDIA_PROPOSER_ID),
                platform_subject: "org.rustyquest.media_test".to_owned(),
                signing_fingerprint: format!("sha256:{}", "a1".repeat(32)),
            },
            broker_client_lock_id: id("lock.client.media-test"),
            broker_client_lock_fingerprint: format!("sha256:{}", "c1".repeat(32)),
            runtime_host_id: id(MEDIA_RUNTIME_HOST_ID),
            client_id: id(TRUSTED_MEDIA_PROPOSER_ID),
            lease_id: id("lease.runtime.media-test"),
            product_id: id("product.quest.media-test"),
            feature_lock_id: id("lock.quest.media-test"),
            feature_lock_fingerprint: format!("sha256:{}", "ab".repeat(32)),
            capability_id: id("capability.media.session.accept"),
            admission_grant_id: id("grant.quest.media-test"),
            allowed_session_id: id("session.media.quest-pair.001"),
            allowed_platform_runtime_spec_id: id("runtime.quest.direct-p2p"),
            allowed_descriptor_canonical_sha256: {
                let mut digests = [6, 7]
                    .into_iter()
                    .map(|revision| {
                        canonical_media_session_sha256(&media_descriptor(revision))
                            .expect("descriptor digest")
                    })
                    .collect::<Vec<_>>();
                digests.sort();
                digests
            },
            allowed_resource_ids: media_resource_ids(),
        }],
        trusted_media_revoker_ids: vec![id("operator.media-revoker")],
        direct_lane_client_grants: vec![ManifoldDirectLaneClientGrant {
            runtime_host_id: id(MEDIA_RUNTIME_HOST_ID),
            client_id: id(TRUSTED_MEDIA_PROPOSER_ID),
            runtime_lease_id: id("lease.runtime.direct-lane-test"),
            product_id: id("product.quest.media-test"),
            feature_lock_id: id("lock.quest.media-test"),
            feature_lock_fingerprint: format!("sha256:{}", "ab".repeat(32)),
            peer_session_capability_id: Some(id(DIRECT_LANE_PEER_SESSION_CAPABILITY)),
            media_session_capability_id: Some(id(DIRECT_LANE_MEDIA_SESSION_CAPABILITY)),
            admission_grant_id: id("grant.quest.direct-lane"),
        }],
        trusted_direct_lane_revoker_ids: vec![id("operator.direct-lane-revoker")],
        media_runtime_host_id: id(MEDIA_RUNTIME_HOST_ID),
        media_runtime_lease_scope_id: id(MEDIA_RUNTIME_LEASE_SCOPE_ID),
        direct_lane_runtime_lease_scope_id: id(DIRECT_RUNTIME_LEASE_SCOPE_ID),
    }
}

fn media_command_runtime() -> ManifoldRuntimeHostSnapshot {
    let media_scope = id(MEDIA_RUNTIME_LEASE_SCOPE_ID);
    let direct_scope = id(DIRECT_RUNTIME_LEASE_SCOPE_ID);
    ManifoldRuntimeHostSnapshot {
        schema_id: schema_id(HOST_SNAPSHOT_SCHEMA),
        host_id: id(MEDIA_RUNTIME_HOST_ID),
        authority_revision: Revision::INITIAL,
        commands: [
            MANIFOLD_MEDIA_SESSION_ACCEPT_COMMAND,
            MANIFOLD_MEDIA_SESSION_REVOKE_COMMAND,
            MANIFOLD_MEDIA_SESSION_STOP_COMMAND,
            DIRECT_LANE_LEASE_ISSUE_COMMAND,
            DIRECT_LANE_LEASE_USE_COMMAND,
            DIRECT_LANE_LEASE_REVOKE_COMMAND,
        ]
        .into_iter()
        .map(|command| ManifoldRuntimeCommandDescriptor {
            command_id: id(command),
            required_lease_scope: Some(if command.starts_with("rusty.manifold.peer.direct_lane") {
                direct_scope.clone()
            } else {
                media_scope.clone()
            }),
        })
        .collect(),
        leases: vec![
            ManifoldRuntimeLease {
                lease_id: id("lease.runtime.media-test"),
                scope: media_scope,
                holder_id: id(TRUSTED_MEDIA_PROPOSER_ID),
                expires_at_ms: 100_000,
            },
            ManifoldRuntimeLease {
                lease_id: id("lease.runtime.direct-lane-test"),
                scope: direct_scope,
                holder_id: id(TRUSTED_MEDIA_PROPOSER_ID),
                expires_at_ms: 100_000,
            },
        ],
        applied_request_ids: Vec::new(),
        reviewed_sweep_ids: Vec::new(),
        audit_events: Vec::new(),
    }
}

fn broker_media_mutation(
    broker: &mut ManifoldBrokerRuntime,
    grant: &ManifoldMediaSessionClientGrant,
    suffix: &str,
    entropy: u8,
    now_ms: u64,
) -> ManifoldBrokerMutationRequest {
    let issue = broker.issue_token(
        &ManifoldAdmissionRequest {
            schema_id: schema_id(ADMISSION_REQUEST_SCHEMA),
            request_id: id(&format!("request.media.dynamic.{suffix}.issue")),
            expected_authority_revision: broker.admission_snapshot().authority_revision,
            identity: grant.broker_client_identity.clone(),
            requested_capabilities: vec![grant.broker_capability_id.clone()],
            issued_at_ms: now_ms,
            expires_at_ms: now_ms.saturating_add(30_000),
            requested_token_ttl_ms: 20_000,
        },
        [entropy; 32],
        now_ms,
    );
    assert!(issue.applied);
    let token = issue.token.expect("opaque token");
    let use_id = id(&format!("request.media.dynamic.{suffix}.use"));
    let use_receipt = broker.authorize_use(
        &ManifoldAdmissionUseRequest {
            schema_id: schema_id(ADMISSION_USE_REQUEST_SCHEMA),
            request_id: use_id.clone(),
            expected_authority_revision: issue.resulting_authority_revision,
            token_id: token.token_id.clone(),
            identity: grant.broker_client_identity.clone(),
            capability_id: grant.broker_capability_id.clone(),
            issued_at_ms: now_ms.saturating_add(1),
            expires_at_ms: now_ms.saturating_add(15_000),
        },
        now_ms.saturating_add(1),
    );
    assert!(use_receipt.applied);
    ManifoldBrokerMutationRequest {
        schema_id: schema_id(BROKER_MUTATION_REQUEST_SCHEMA),
        provider_epoch_id: id(PROVIDER_EPOCH_ID),
        admission_use_request_id: use_id,
        token_id: token.token_id,
        expected_admission_authority_revision: use_receipt.resulting_authority_revision,
        command: ManifoldRuntimeCommandRequest {
            schema_id: schema_id(HOST_COMMAND_REQUEST_SCHEMA),
            request_id: id(&format!("request.media.dynamic.{suffix}.outer-command")),
            expected_authority_revision: broker.host_snapshot().authority_revision,
            requester_id: grant.client_id.clone(),
            command_id: grant.broker_command_id.clone(),
            lease_id: Some(grant.broker_runtime_lease_id.clone()),
            params_digest: None,
            issued_at_ms: now_ms.saturating_add(2),
            expires_at_ms: now_ms.saturating_add(10_000),
        },
    }
}

fn id(value: &str) -> DottedId {
    DottedId::new(value).expect("test id")
}

fn schema_id(value: &str) -> SchemaId {
    SchemaId::new(value).expect("test schema")
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn encode_lower_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("String writes cannot fail");
    }
    output
}

fn credential(
    peer_id: &str,
    key_id: &str,
    generation: u64,
    signing_key: &SigningKey,
) -> ManifoldPeerCredentialRecord {
    let public_key = signing_key.verifying_key().to_bytes();
    ManifoldPeerCredentialRecord {
        schema_id: schema_id(PEER_CREDENTIAL_SCHEMA),
        credential_id: id(&format!("credential.{peer_id}.{generation}")),
        peer_id: id(peer_id),
        trust_domain: id("trust.morphospace.peer"),
        key_id: id(key_id),
        key_generation: generation,
        algorithm: ManifoldPeerCredentialAlgorithm::Ed25519,
        public_key_hex: encode_lower_hex(&public_key),
        public_key_sha256: format!("sha256:{}", encode_lower_hex(&Sha256::digest(public_key))),
        valid_from_ms: 1_000,
        expires_at_ms: 100_000,
        status: ManifoldPeerCredentialStatus::Active,
        replaced_by_key_id: None,
    }
}

fn enrollment_request(
    request_id: &str,
    revision: Revision,
    action: ManifoldPeerEnrollmentAction,
) -> ManifoldPeerEnrollmentRequest {
    ManifoldPeerEnrollmentRequest {
        schema_id: schema_id(PEER_ENROLLMENT_REQUEST_SCHEMA),
        request_id: id(request_id),
        expected_authority_revision: revision,
        operator_id: id(OPERATOR_ID),
        issued_at_ms: 1_000,
        action,
    }
}

fn fixture_host() -> ManifoldPeerRuntimeHost {
    let mesh_case: ManifoldPeerMeshReviewCase = serde_json::from_str(include_str!(
        "../../../fixtures/peer-mesh/three-peer.pass.json"
    ))
    .expect("mesh fixture");
    let session_case: ManifoldPeerSessionReviewCase = serde_json::from_str(include_str!(
        "../../../fixtures/peer-session/authenticated-ble.pass.json"
    ))
    .expect("session fixture");
    let mut host = ManifoldPeerRuntimeHost::new(
        id("host.peer-runtime.test"),
        trust_policy(),
        id(PROVIDER_EPOCH_ID),
        media_command_runtime(),
    )
    .expect("host");
    let mut accepted = mesh_case.accepted_peers;
    for peer in &mut accepted.peers {
        if let Some(session_peer) = session_case
            .accepted_peers
            .peers
            .iter()
            .find(|candidate| candidate.identity.peer_id == peer.identity.peer_id)
        {
            peer.status.capability_ids = session_peer.status.capability_ids.clone();
        }
    }
    host.snapshot.accepted_peers = accepted;
    let expected_policy = host.snapshot.trust_policy.clone();
    let expected_epoch = host.snapshot.provider_epoch_id.clone();
    ManifoldPeerRuntimeHost::from_snapshot(host.snapshot, &expected_policy, &expected_epoch)
        .expect("fixture host validates")
}

fn enroll_pair(host: &mut ManifoldPeerRuntimeHost) -> (SigningKey, SigningKey) {
    let alpha_key = key(7);
    let beta_key = key(11);
    let alpha = enrollment_request(
        "request.enroll.alpha.001",
        host.snapshot().enrollment.authority_revision,
        ManifoldPeerEnrollmentAction::Enroll {
            credential: credential("peer.alpha", "key.peer.alpha.001", 1, &alpha_key),
        },
    );
    assert!(
        host.review_enrollment(&alpha, 2_000)
            .expect("alpha enrollment")
            .applied
    );
    let beta = enrollment_request(
        "request.enroll.beta.001",
        host.snapshot().enrollment.authority_revision,
        ManifoldPeerEnrollmentAction::Enroll {
            credential: credential("peer.beta", "key.peer.beta.001", 1, &beta_key),
        },
    );
    assert!(
        host.review_enrollment(&beta, 2_000)
            .expect("beta enrollment")
            .applied
    );
    (alpha_key, beta_key)
}

fn signed_evidence(
    suffix: &str,
    signer_peer_id: &str,
    signer_key_id: &str,
    counterparty_peer_id: &str,
    role: ManifoldRendezvousRole,
    signing_key: &SigningKey,
    nonce_seed: u8,
) -> ManifoldSignedRendezvousEvidence {
    let mut evidence = ManifoldSignedRendezvousEvidence {
        schema_id: schema_id(SIGNED_RENDEZVOUS_EVIDENCE_SCHEMA),
        evidence_id: id(&format!("evidence.rendezvous.{suffix}")),
        signer_peer_id: id(signer_peer_id),
        signer_key_id: id(signer_key_id),
        counterparty_peer_id: id(counterparty_peer_id),
        nonce_hex: format!("{nonce_seed:02x}").repeat(32),
        coordinator_epoch: u64::from(nonce_seed),
        role,
        topology_contract_id: id(PRODUCT_WIFI_DIRECT_TOPOLOGY_CONTRACT),
        issued_at_ms: 2_000,
        expires_at_ms: 60_000,
        signature_hex: String::new(),
    };
    evidence.signature_hex = encode_lower_hex(
        &signing_key
            .sign(&rendezvous_signing_bytes(&evidence))
            .to_bytes(),
    );
    evidence
}

fn rendezvous_request(
    host: &ManifoldPeerRuntimeHost,
    suffix: &str,
    alpha_key_id: &str,
    alpha_key: &SigningKey,
    beta_key: &SigningKey,
    nonce_seed: u8,
) -> ManifoldRendezvousReviewRequest {
    ManifoldRendezvousReviewRequest {
        schema_id: schema_id(RENDEZVOUS_REVIEW_REQUEST_SCHEMA),
        request_id: id(&format!("request.rendezvous.{suffix}")),
        expected_authority_revision: host.snapshot().rendezvous.authority_revision,
        expected_enrollment_authority_revision: host.snapshot().enrollment.authority_revision,
        first: signed_evidence(
            &format!("alpha.{suffix}"),
            "peer.alpha",
            alpha_key_id,
            "peer.beta",
            ManifoldRendezvousRole::GroupOwner,
            alpha_key,
            nonce_seed,
        ),
        second: signed_evidence(
            &format!("beta.{suffix}"),
            "peer.beta",
            "key.peer.beta.001",
            "peer.alpha",
            ManifoldRendezvousRole::Client,
            beta_key,
            nonce_seed,
        ),
    }
}

fn session_proposal(
    host: &ManifoldPeerRuntimeHost,
    proposal_id: &str,
    session_id: &str,
) -> ManifoldPeerSessionProposal {
    let mut case: ManifoldPeerSessionReviewCase = serde_json::from_str(include_str!(
        "../../../fixtures/peer-session/authenticated-ble.pass.json"
    ))
    .expect("session fixture");
    case.proposal.proposal_id = id(proposal_id);
    case.proposal.session_id = id(session_id);
    case.proposal.expected_authority_revision = host.snapshot().peer_sessions.authority_revision;
    case.proposal
}

fn accept_session(
    host: &mut ManifoldPeerRuntimeHost,
    receipt: ManifoldRendezvousReceipt,
    proposal_id: &str,
    session_id: &str,
) -> ManifoldPeerSessionProposal {
    let proposal = session_proposal(host, proposal_id, session_id);
    let (decision, topology) = host
        .review_signed_peer_session(proposal.clone(), receipt, 3_000)
        .expect("session review");
    assert!(decision.applied);
    assert!(topology.topology_authorization.authorized);
    proposal
}

fn mesh_proposal(host: &ManifoldPeerRuntimeHost) -> ManifoldPeerMeshProposal {
    let mut case: ManifoldPeerMeshReviewCase = serde_json::from_str(include_str!(
        "../../../fixtures/peer-mesh/three-peer.pass.json"
    ))
    .expect("mesh fixture");
    case.proposal.expected_authority_revision = host.snapshot().peer_mesh.authority_revision;
    if let Some(receipt) = host
        .snapshot()
        .signed_topology_authorizations
        .last()
        .and_then(|topology| {
            host.snapshot()
                .rendezvous
                .accepted_receipts
                .iter()
                .find(|receipt| receipt.receipt_id == topology.rendezvous_receipt_id)
        })
    {
        case.proposal.authority_epoch = receipt.coordinator_epoch;
        case.proposal.coordinator_peer_id = receipt
            .group_owner_peer_id
            .clone()
            .expect("accepted rendezvous group owner");
        case.proposal
            .route_candidates
            .retain(|candidate| candidate.candidate_id.as_str() != "route.beta-gamma");
        for candidate in &mut case.proposal.route_candidates {
            if candidate.source_peer_id.as_str() == "peer.alpha"
                && candidate.target_peer_id.as_str() == "peer.beta"
            {
                candidate.pair_evidence_receipt_id = Some(receipt.receipt_id.clone());
                candidate.evidence_expires_at_ms = receipt.expires_at_ms;
            }
        }
    }
    case.proposal
}

fn accept_mesh(host: &mut ManifoldPeerRuntimeHost) {
    let decision = host
        .review_peer_mesh(mesh_proposal(host), 3_000)
        .expect("mesh review");
    assert!(decision.applied);
}

fn lease_request(
    host: &ManifoldPeerRuntimeHost,
    request_id: &str,
    session_id: &str,
) -> ManifoldDirectLaneLeaseRequest {
    ManifoldDirectLaneLeaseRequest {
        schema_id: schema_id(DIRECT_LANE_LEASE_REQUEST_SCHEMA),
        request_id: id(request_id),
        expected_lease_authority_revision: host.snapshot().direct_lane_leases.authority_revision,
        expected_peer_authority_revision: host.snapshot().accepted_peers.authority_revision,
        expected_mesh_authority_revision: host.snapshot().peer_mesh.authority_revision,
        expected_mesh_authority_epoch: host.snapshot().peer_mesh.authority_epoch,
        expected_mesh_coordinator_peer_id: host
            .snapshot()
            .peer_mesh
            .coordinator_peer_id
            .clone()
            .expect("mesh coordinator"),
        expected_enrollment_authority_revision: host.snapshot().enrollment.authority_revision,
        expected_rendezvous_authority_revision: host.snapshot().rendezvous.authority_revision,
        expected_peer_session_authority_revision: host.snapshot().peer_sessions.authority_revision,
        first_peer_status_revision: host
            .snapshot()
            .peer_mesh
            .members
            .iter()
            .find(|member| member.peer_id.as_str() == "peer.alpha")
            .expect("alpha member")
            .status_revision,
        second_peer_status_revision: host
            .snapshot()
            .peer_mesh
            .members
            .iter()
            .find(|member| member.peer_id.as_str() == "peer.beta")
            .expect("beta member")
            .status_revision,
        pair_evidence_receipt_id: host.snapshot().peer_mesh.selected_routes[0]
            .pair_evidence_receipt_id
            .clone(),
        pair_evidence_sha256: host.snapshot().peer_mesh.selected_routes[0]
            .pair_evidence_sha256
            .clone(),
        pair_authority_revision: host.snapshot().peer_mesh.selected_routes[0]
            .pair_authority_revision,
        pair_authority_epoch: host.snapshot().peer_mesh.selected_routes[0].pair_authority_epoch,
        pair_signer_key_ids: host.snapshot().peer_mesh.selected_routes[0]
            .signer_key_ids
            .clone(),
        expected_media_session_authority_revision: None,
        expected_media_acceptance_authority_revision: None,
        mesh_id: host.snapshot().peer_mesh.mesh_id.clone().expect("mesh id"),
        selected_route_id: id("route.alpha-beta.fast"),
        first_peer_id: id("peer.alpha"),
        second_peer_id: id("peer.beta"),
        peer_session_id: id(session_id),
        media_session_id: None,
        media_session_decision_id: None,
        media_session_descriptor_canonical_sha256: None,
        media_session_provider_epoch_id: None,
        media_session_platform_runtime_spec_id: None,
        product_id: id("product.quest.media-test"),
        feature_lock_id: id("lock.quest.media-test"),
        feature_lock_fingerprint: format!("sha256:{}", "ab".repeat(32)),
        capability_id: id(DIRECT_LANE_PEER_SESSION_CAPABILITY),
        admission_grant_id: id("grant.quest.direct-lane"),
        scope: ManifoldDirectLaneLeaseScope::PeerSession,
        expires_at_ms: 50_000,
    }
}

fn media_acceptance_request(
    host: &ManifoldPeerRuntimeHost,
    request_id: &str,
    session_revision: u64,
    provider_epoch_id: &str,
) -> ManifoldMediaSessionAcceptanceRequest {
    let descriptor = media_descriptor(session_revision);
    ManifoldMediaSessionAcceptanceRequest {
        schema_id: schema_id(MANIFOLD_MEDIA_SESSION_ACCEPTANCE_REQUEST_SCHEMA),
        request_id: id(request_id),
        expected_authority_revision: host.snapshot().media_sessions.authority_revision,
        runtime_command_request_id: id(&format!("runtime.{request_id}")),
        expected_provider_epoch_id: id(provider_epoch_id),
        product_id: id("product.quest.media-test"),
        feature_lock_id: id("lock.quest.media-test"),
        feature_lock_fingerprint: format!("sha256:{}", "ab".repeat(32)),
        capability_id: id("capability.media.session.accept"),
        admission_grant_id: id("grant.quest.media-test"),
        expires_at_ms: 60_000,
        product_binding: ManifoldMediaSessionProductBinding {
            schema_id: MANIFOLD_MEDIA_SESSION_BINDING_SCHEMA.to_owned(),
            descriptor_canonical_sha256: canonical_media_session_sha256(&descriptor)
                .expect("descriptor digest"),
            descriptor,
        },
    }
}

fn media_accept_command(
    host: &ManifoldPeerRuntimeHost,
    request: &ManifoldMediaSessionAcceptanceRequest,
) -> ManifoldRuntimeCommandRequest {
    ManifoldRuntimeCommandRequest {
        schema_id: schema_id(HOST_COMMAND_REQUEST_SCHEMA),
        request_id: request.runtime_command_request_id.clone(),
        expected_authority_revision: host.snapshot().media_command_runtime.authority_revision,
        requester_id: id(TRUSTED_MEDIA_PROPOSER_ID),
        command_id: id(MANIFOLD_MEDIA_SESSION_ACCEPT_COMMAND),
        lease_id: Some(id("lease.runtime.media-test")),
        params_digest: Some(media_session_acceptance_params_digest(request).expect("params")),
        issued_at_ms: 3_000,
        expires_at_ms: 10_000,
    }
}

fn direct_command(
    host: &ManifoldPeerRuntimeHost,
    request_id: DottedId,
    command_id: &str,
    params_digest: rusty_manifold_runtime_host::ManifoldRuntimeTypedParamsDigest,
    now_ms: u64,
) -> ManifoldRuntimeCommandRequest {
    ManifoldRuntimeCommandRequest {
        schema_id: schema_id(HOST_COMMAND_REQUEST_SCHEMA),
        request_id,
        expected_authority_revision: host.snapshot().media_command_runtime.authority_revision,
        requester_id: id(TRUSTED_MEDIA_PROPOSER_ID),
        command_id: id(command_id),
        lease_id: Some(id("lease.runtime.direct-lane-test")),
        params_digest: Some(params_digest),
        issued_at_ms: now_ms.saturating_sub(1),
        expires_at_ms: now_ms.saturating_add(1_000),
    }
}

fn issue_direct(
    host: &mut ManifoldPeerRuntimeHost,
    request: &ManifoldDirectLaneLeaseRequest,
    now_ms: u64,
) -> ManifoldDirectLaneLeaseReceipt {
    let command = direct_command(
        host,
        id(&format!("runtime.{}", request.request_id.as_str())),
        DIRECT_LANE_LEASE_ISSUE_COMMAND,
        direct_lane_lease_issue_params_digest(request).expect("params"),
        now_ms,
    );
    host.review_direct_lane_lease(request, &command, now_ms)
        .expect("direct-lane review")
}

fn use_direct(
    host: &mut ManifoldPeerRuntimeHost,
    lease_id: DottedId,
    request_id: &str,
    now_ms: u64,
) -> Result<ManifoldDirectLaneLeaseCurrentReceipt, ManifoldDirectLaneLeaseRejectionReason> {
    let request = ManifoldDirectLaneLeaseUseRequest {
        schema_id: schema_id(DIRECT_LANE_LEASE_USE_REQUEST_SCHEMA),
        request_id: id(request_id),
        expected_authority_revision: host.snapshot().direct_lane_leases.authority_revision,
        lease_id,
    };
    let command = direct_command(
        host,
        request.request_id.clone(),
        DIRECT_LANE_LEASE_USE_COMMAND,
        direct_lane_lease_use_params_digest(&request).expect("params"),
        now_ms,
    );
    host.validate_direct_lane_lease(&request, &command, now_ms)
}

fn ready_host() -> (
    ManifoldPeerRuntimeHost,
    ManifoldDirectLaneLeaseRequest,
    DottedId,
) {
    let mut host = fixture_host();
    let (alpha_key, beta_key) = enroll_pair(&mut host);
    let request = rendezvous_request(
        &host,
        "alpha-beta.001",
        "key.peer.alpha.001",
        &alpha_key,
        &beta_key,
        9,
    );
    let receipt = host
        .review_signed_rendezvous(&request, 3_000)
        .expect("rendezvous");
    assert!(receipt.accepted);
    accept_session(
        &mut host,
        receipt,
        "proposal.peer-session.host.001",
        "session.peer.host.001",
    );
    accept_mesh(&mut host);
    let request = lease_request(
        &host,
        "request.direct-lane.host.001",
        "session.peer.host.001",
    );
    let receipt = issue_direct(&mut host, &request, 4_000);
    assert!(receipt.applied);
    let lease_id = receipt.lease.expect("real lease").lease_id;
    (host, request, lease_id)
}

fn reciprocal_request(
    host: &ManifoldPeerRuntimeHost,
    alpha_key: &SigningKey,
    beta_key: &SigningKey,
) -> ManifoldReciprocalEd25519ReviewRequest {
    let alpha = host
        .snapshot()
        .enrollment
        .credentials
        .iter()
        .find(|credential| credential.peer_id.as_str() == "peer.alpha")
        .expect("alpha credential");
    let beta = host
        .snapshot()
        .enrollment
        .credentials
        .iter()
        .find(|credential| credential.peer_id.as_str() == "peer.beta")
        .expect("beta credential");
    let context = ManifoldReciprocalEd25519Context {
        schema_id: schema_id(RECIPROCAL_ED25519_CONTEXT_SCHEMA),
        runtime_host_id: host.snapshot().host_id.clone(),
        trust_policy_id: host.snapshot().trust_policy.policy_id.clone(),
        trust_policy_revision: host.snapshot().trust_policy.revision,
        correlation_id: id("run.peer-runtime.reciprocal.001"),
        revisions: ManifoldReciprocalEd25519Revisions {
            peer_authority_revision: host.snapshot().accepted_peers.authority_revision,
            enrollment_authority_revision: host.snapshot().enrollment.authority_revision,
            rendezvous_authority_revision: host.snapshot().rendezvous.authority_revision,
            reciprocal_authority_revision: host.snapshot().reciprocal_ed25519.authority_revision,
            peer_session_authority_revision: host.snapshot().peer_sessions.authority_revision,
            peer_mesh_authority_revision: host.snapshot().peer_mesh.authority_revision,
            direct_lane_lease_authority_revision: host
                .snapshot()
                .direct_lane_leases
                .authority_revision,
        },
        group_owner: ManifoldReciprocalEd25519PeerBinding {
            peer_id: alpha.peer_id.clone(),
            key_id: alpha.key_id.clone(),
            key_generation: alpha.key_generation,
            public_key_sha256: alpha.public_key_sha256.clone(),
            role: ManifoldRendezvousRole::GroupOwner,
            device_nonce_hex: "31".repeat(32),
        },
        client: ManifoldReciprocalEd25519PeerBinding {
            peer_id: beta.peer_id.clone(),
            key_id: beta.key_id.clone(),
            key_generation: beta.key_generation,
            public_key_sha256: beta.public_key_sha256.clone(),
            role: ManifoldRendezvousRole::Client,
            device_nonce_hex: "47".repeat(32),
        },
        topology_contract_id: id(PRODUCT_WIFI_DIRECT_TOPOLOGY_CONTRACT),
        coordinator_epoch: 17,
        issued_at_ms: 2_500,
        expires_at_ms: 60_000,
    };
    let bytes = reciprocal_ed25519_context_signing_bytes(&context);
    let digest = reciprocal_ed25519_context_sha256(&context);
    let signature = |binding: &ManifoldReciprocalEd25519PeerBinding, key: &SigningKey| {
        ManifoldReciprocalEd25519Signature {
            schema_id: schema_id(RECIPROCAL_ED25519_SIGNATURE_SCHEMA),
            signer_peer_id: binding.peer_id.clone(),
            signer_key_id: binding.key_id.clone(),
            context_sha256: digest.clone(),
            signature_hex: encode_lower_hex(&key.sign(&bytes).to_bytes()),
        }
    };
    ManifoldReciprocalEd25519ReviewRequest {
        schema_id: schema_id(RECIPROCAL_ED25519_REVIEW_SCHEMA),
        request_id: id("request.peer-runtime.reciprocal.001"),
        group_owner_signature: signature(&context.group_owner, alpha_key),
        client_signature: signature(&context.client, beta_key),
        context,
    }
}

#[test]
fn reciprocal_ed25519_advances_host_and_only_signed_session_consumes_it() {
    let mut host = fixture_host();
    let (alpha_key, beta_key) = enroll_pair(&mut host);
    let request = reciprocal_request(&host, &alpha_key, &beta_key);
    let receipt = host
        .review_reciprocal_ed25519(&request, 3_000)
        .expect("reciprocal review");
    assert!(receipt.accepted);
    assert_eq!(
        host.snapshot().reciprocal_ed25519.authority_revision,
        host.snapshot().rendezvous.authority_revision
    );
    let compatibility = reciprocal_ed25519_compatibility_receipt(&receipt);
    assert!(host
        .snapshot()
        .rendezvous
        .accepted_receipts
        .contains(&compatibility));

    let mut proposal = session_proposal(
        &host,
        "proposal.peer-session.reciprocal.001",
        "session.peer.reciprocal.001",
    );
    proposal.authentication.transport = PeerRendezvousTransport::ReciprocalEd25519;
    proposal.authentication.authenticated_messages = 2;
    proposal.authentication.role_swap_completed = false;
    proposal.authentication.reconnects_completed = 0;
    proposal.authentication.evidence_digest =
        id(&receipt.context_sha256.replacen("sha256:", "sha256.", 1));
    let (decision, topology) = host
        .review_signed_peer_session(proposal, compatibility, 3_100)
        .expect("signed reciprocal session");
    assert!(
        decision.applied,
        "reciprocal session rejected: {:?}",
        decision.rejection_reason
    );
    assert!(topology.topology_authorization.authorized);

    let restarted = ManifoldPeerRuntimeHost::restart_from_json(
        &host.snapshot_json().expect("snapshot"),
        &host.snapshot().trust_policy,
        &host.snapshot().provider_epoch_id,
    )
    .expect("restart");
    assert_eq!(restarted.snapshot(), host.snapshot());
}

#[test]
fn legacy_then_v2_rendezvous_preserves_independent_monotonic_revision_domains() {
    let mut host = fixture_host();
    let (alpha_key, beta_key) = enroll_pair(&mut host);
    let legacy = rendezvous_request(
        &host,
        "mixed.legacy.001",
        "key.peer.alpha.001",
        &alpha_key,
        &beta_key,
        7,
    );
    assert!(
        host.review_signed_rendezvous(&legacy, 3_000)
            .expect("legacy rendezvous")
            .accepted
    );
    assert_eq!(host.snapshot().rendezvous.authority_revision.get(), 2);
    assert_eq!(
        host.snapshot().reciprocal_ed25519.authority_revision.get(),
        1
    );

    let v2 = reciprocal_request(&host, &alpha_key, &beta_key);
    let receipt = host
        .review_reciprocal_ed25519(&v2, 3_100)
        .expect("v2 rendezvous");
    assert!(receipt.accepted);
    assert_eq!(receipt.prior_authority_revision.get(), 1);
    assert_eq!(receipt.resulting_authority_revision.get(), 2);
    assert_eq!(receipt.compatibility_prior_authority_revision.get(), 2);
    assert_eq!(receipt.compatibility_resulting_authority_revision.get(), 3);
    assert_eq!(
        host.snapshot().reciprocal_ed25519.authority_revision.get(),
        2
    );
    assert_eq!(host.snapshot().rendezvous.authority_revision.get(), 3);
    assert_eq!(
        receipt.trust_policy_id,
        host.snapshot().trust_policy.policy_id
    );
    assert_eq!(
        receipt.trust_policy_revision,
        host.snapshot().trust_policy.revision
    );
}

#[test]
fn restart_preserves_current_revisions_real_lease_audit_and_replay_guards() {
    let (mut host, mut replay, lease_id) = ready_host();
    use_direct(
        &mut host,
        lease_id.clone(),
        "request.direct.use.restart.pre",
        4_100,
    )
    .expect("current lease");
    let json = host.snapshot_json().expect("snapshot json");
    let mut restarted = ManifoldPeerRuntimeHost::restart_from_json(
        &json,
        &host.snapshot().trust_policy,
        &host.snapshot().provider_epoch_id,
    )
    .expect("restart");
    assert_eq!(restarted.snapshot(), host.snapshot());
    use_direct(
        &mut restarted,
        lease_id,
        "request.direct.use.restart.post",
        4_200,
    )
    .expect("lease survives restart");

    replay.expected_lease_authority_revision =
        restarted.snapshot().direct_lane_leases.authority_revision;
    let prior = restarted.snapshot().direct_lane_leases.authority_revision;
    let receipt = issue_direct(&mut restarted, &replay, 4_300);
    assert!(!receipt.applied);
    assert_eq!(
        receipt.rejection_reason,
        Some(ManifoldDirectLaneLeaseRejectionReason::ReplayedRequest)
    );
    assert_eq!(
        restarted.snapshot().direct_lane_leases.authority_revision,
        prior
    );
    assert_eq!(
        restarted.snapshot().event_sequence,
        restarted.snapshot().audit_events.len() as u64
    );
}

#[test]
fn key_rotation_recovers_with_fresh_signatures_and_revoke_invalidates_lease() {
    let mut host = fixture_host();
    let (alpha_key, beta_key) = enroll_pair(&mut host);
    let old_request = rendezvous_request(
        &host,
        "rotation.old",
        "key.peer.alpha.001",
        &alpha_key,
        &beta_key,
        12,
    );
    let old_receipt = host
        .review_signed_rendezvous(&old_request, 3_000)
        .expect("old receipt");
    assert!(old_receipt.accepted);

    let next_alpha_key = key(19);
    let rotate = enrollment_request(
        "request.rotate.alpha.002",
        host.snapshot().enrollment.authority_revision,
        ManifoldPeerEnrollmentAction::Rotate {
            prior_key_id: id("key.peer.alpha.001"),
            credential: credential("peer.alpha", "key.peer.alpha.002", 2, &next_alpha_key),
        },
    );
    assert!(
        host.review_enrollment(&rotate, 3_100)
            .expect("rotation")
            .applied
    );

    let stale_proposal = session_proposal(
        &host,
        "proposal.peer-session.rotation.stale",
        "session.peer.rotation.stale",
    );
    let (stale, _) = host
        .review_signed_peer_session(stale_proposal, old_receipt, 3_200)
        .expect("stale signed session decision");
    assert_eq!(
        stale.rejection_reason,
        Some(ManifoldPeerSessionRejectionReason::SignedRendezvousMismatch)
    );

    let fresh_request = rendezvous_request(
        &host,
        "rotation.fresh",
        "key.peer.alpha.002",
        &next_alpha_key,
        &beta_key,
        13,
    );
    let fresh_receipt = host
        .review_signed_rendezvous(&fresh_request, 3_300)
        .expect("fresh receipt");
    assert!(fresh_receipt.accepted);
    accept_session(
        &mut host,
        fresh_receipt,
        "proposal.peer-session.rotation.fresh",
        "session.peer.rotation.fresh",
    );
    accept_mesh(&mut host);
    let lease_request = lease_request(
        &host,
        "request.direct-lane.rotation.001",
        "session.peer.rotation.fresh",
    );
    let lease_receipt = issue_direct(&mut host, &lease_request, 4_000);
    assert!(
        lease_receipt.applied,
        "rotation lease rejected: {:?}",
        lease_receipt.rejection_reason
    );
    let lease = lease_receipt.lease.expect("issued lease");

    let revoke = enrollment_request(
        "request.revoke.alpha.002",
        host.snapshot().enrollment.authority_revision,
        ManifoldPeerEnrollmentAction::Revoke {
            key_id: id("key.peer.alpha.002"),
            reason_id: id("reason.operator.compromise"),
        },
    );
    assert!(
        host.review_enrollment(&revoke, 4_100)
            .expect("revocation")
            .applied
    );
    assert_eq!(
        use_direct(
            &mut host,
            lease.lease_id,
            "request.direct.use.rotated",
            4_200,
        ),
        Err(ManifoldDirectLaneLeaseRejectionReason::TopologyNotAuthorized)
    );
}

#[test]
fn stale_revision_session_replay_and_rendezvous_replay_fail_without_lane_mutation() {
    let mut host = fixture_host();
    let (alpha_key, beta_key) = enroll_pair(&mut host);
    let stale = enrollment_request(
        "request.enroll.stale.001",
        Revision::INITIAL,
        ManifoldPeerEnrollmentAction::Enroll {
            credential: credential("peer.gamma", "key.peer.gamma.001", 1, &key(23)),
        },
    );
    let enrollment_revision = host.snapshot().enrollment.authority_revision;
    let stale_receipt = host
        .review_enrollment(&stale, 3_000)
        .expect("stale receipt");
    assert_eq!(
        stale_receipt.rejection_reason,
        Some(ManifoldPeerEnrollmentRejectionReason::StaleAuthorityRevision)
    );
    assert_eq!(
        host.snapshot().enrollment.authority_revision,
        enrollment_revision
    );

    let request = rendezvous_request(
        &host,
        "replay.001",
        "key.peer.alpha.001",
        &alpha_key,
        &beta_key,
        21,
    );
    let receipt = host
        .review_signed_rendezvous(&request, 3_100)
        .expect("rendezvous");
    let rendezvous_revision = host.snapshot().rendezvous.authority_revision;
    let mut replay_request = request;
    replay_request.expected_authority_revision = rendezvous_revision;
    let replay = host
        .review_signed_rendezvous(&replay_request, 3_200)
        .expect("rendezvous replay");
    assert_eq!(
        replay.rejection_reason,
        Some(ManifoldRendezvousRejectionReason::Replay)
    );
    assert_eq!(
        host.snapshot().rendezvous.authority_revision,
        rendezvous_revision
    );

    let proposal = accept_session(
        &mut host,
        receipt.clone(),
        "proposal.peer-session.replay.001",
        "session.peer.replay.001",
    );
    let session_revision = host.snapshot().peer_sessions.authority_revision;
    let mut replay_proposal = proposal;
    replay_proposal.expected_authority_revision = session_revision;
    let (decision, _) = host
        .review_signed_peer_session(replay_proposal, receipt, 3_300)
        .expect("session replay decision");
    assert_eq!(
        decision.rejection_reason,
        Some(ManifoldPeerSessionRejectionReason::ReplayedProposal)
    );
    assert_eq!(
        host.snapshot().peer_sessions.authority_revision,
        session_revision
    );
}

#[test]
fn split_brain_and_expiry_fail_closed_with_replay_protected_sweeps() {
    let (mut host, _, lease_id) = ready_host();
    let mesh_revision = host.snapshot().peer_mesh.authority_revision;
    let mut split = mesh_proposal(&host);
    split.proposal_id = id("proposal.peer-mesh.split-brain.001");
    split.authority_epoch = host.snapshot().peer_mesh.authority_epoch;
    split.coordinator_peer_id = id("peer.beta");
    split.member_peer_ids = vec![id("peer.beta"), id("peer.delta"), id("peer.gamma")];
    let decision = host
        .review_peer_mesh(split, 4_500)
        .expect("split-brain decision");
    assert_eq!(
        decision.rejection_reason,
        Some(ManifoldPeerMeshRejectionReason::SplitBrain)
    );
    assert_eq!(host.snapshot().peer_mesh.authority_revision, mesh_revision);

    let lease_revision = host
        .expire_direct_lane_leases(id("sweep.direct-lane.host.001"), 50_000)
        .expect("lease expiry");
    assert_eq!(
        lease_revision,
        host.snapshot().direct_lane_leases.authority_revision
    );
    assert!(use_direct(&mut host, lease_id, "request.direct.use.expired", 50_000,).is_err());
    let replay = host.expire_direct_lane_leases(id("sweep.direct-lane.host.001"), 50_100);
    assert!(matches!(
        replay,
        Err(ManifoldPeerRuntimeHostError::Authority(_))
    ));

    let sweep_id = id("sweep.peer-mesh.host.001");
    let receipt = host
        .expire_peer_mesh(sweep_id.clone(), 61_000)
        .expect("mesh expiry");
    assert!(receipt.applied);
    assert!(host.snapshot().peer_mesh.members.is_empty());
    assert!(matches!(
        host.expire_peer_mesh(sweep_id, 61_100),
        Err(ManifoldPeerRuntimeHostError::ReplayedMutation(_))
    ));
}

#[test]
fn retained_media_decision_is_required_and_revalidated_by_direct_lease() {
    let (mut host, _, _) = ready_host();
    let acceptance_request = media_acceptance_request(
        &host,
        "request.media.accept.quest-pair.001",
        6,
        PROVIDER_EPOCH_ID,
    );
    let acceptance_command = media_accept_command(&host, &acceptance_request);
    let acceptance = host
        .review_media_session_acceptance(&acceptance_request, &acceptance_command, 4_000)
        .expect("media acceptance review");
    assert!(acceptance.accepted);
    let accepted = acceptance.accepted_session.expect("accepted media record");

    let mut forged = lease_request(
        &host,
        "request.direct-lane.media.forged",
        "session.peer.host.001",
    );
    forged.scope = ManifoldDirectLaneLeaseScope::MediaSession;
    forged.capability_id = id(DIRECT_LANE_MEDIA_SESSION_CAPABILITY);
    forged.expected_media_session_authority_revision = Some(accepted.session_authority_revision);
    forged.expected_media_acceptance_authority_revision =
        Some(host.snapshot().media_sessions.authority_revision);
    forged.media_session_id = Some(accepted.session_id.clone());
    forged.media_session_decision_id = Some(accepted.decision_id.clone());
    forged.media_session_descriptor_canonical_sha256 = Some(format!("sha256:{}", "00".repeat(32)));
    forged.media_session_provider_epoch_id = Some(accepted.provider_epoch_id.clone());
    forged.media_session_platform_runtime_spec_id = Some(accepted.platform_runtime_spec_id.clone());
    let rejected = issue_direct(&mut host, &forged, 4_100);
    assert_eq!(
        rejected.rejection_reason,
        Some(ManifoldDirectLaneLeaseRejectionReason::MediaSessionNotAccepted)
    );

    let mut valid = forged;
    valid.request_id = id("request.direct-lane.media.accepted");
    valid.media_session_descriptor_canonical_sha256 =
        Some(accepted.product_descriptor_canonical_sha256.clone());
    let lease_receipt = issue_direct(&mut host, &valid, 4_100);
    assert!(lease_receipt.applied);
    let lease = lease_receipt.lease.expect("media lease");
    assert_eq!(lease.media_session_decision_id, Some(accepted.decision_id));
    assert_eq!(
        lease.media_session_descriptor_canonical_sha256,
        Some(accepted.product_descriptor_canonical_sha256)
    );
    use_direct(
        &mut host,
        lease.lease_id.clone(),
        "request.direct.use.media.current",
        4_200,
    )
    .expect("current retained media lease");
    let current = host.validate_media_session(
        lease.media_session_decision_id.as_ref().expect("decision"),
        4_200,
    );
    assert!(current.current);
    assert_eq!(
        current
            .session
            .as_ref()
            .expect("current session")
            .runtime_client_id,
        id(TRUSTED_MEDIA_PROPOSER_ID)
    );

    let replacement = media_acceptance_request(
        &host,
        "request.media.accept.quest-pair.002",
        7,
        PROVIDER_EPOCH_ID,
    );
    let replacement_command = media_accept_command(&host, &replacement);
    assert!(
        host.review_media_session_acceptance(&replacement, &replacement_command, 4_250)
            .expect("replacement acceptance")
            .accepted
    );
    assert_eq!(
        use_direct(
            &mut host,
            lease.lease_id,
            "request.direct.use.media.superseded",
            4_300,
        ),
        Err(ManifoldDirectLaneLeaseRejectionReason::MediaSessionNotAccepted)
    );

    let json = host.snapshot_json().expect("snapshot");
    let restarted = ManifoldPeerRuntimeHost::restart_from_json(
        &json,
        &host.snapshot().trust_policy,
        &host.snapshot().provider_epoch_id,
    )
    .expect("media authority restart");
    assert_eq!(restarted.snapshot(), host.snapshot());
}

#[test]
fn restart_rejects_damaged_audit_and_cross_authority_provenance() {
    let (host, _, _) = ready_host();
    let mut damaged = host.snapshot().clone();
    damaged.event_sequence += 1;
    assert!(matches!(
        ManifoldPeerRuntimeHost::from_snapshot(
            damaged,
            &host.snapshot().trust_policy,
            &host.snapshot().provider_epoch_id,
        ),
        Err(ManifoldPeerRuntimeHostError::InvalidSnapshot(_))
    ));

    let mut damaged = host.snapshot().clone();
    damaged.signed_topology_authorizations[0].rendezvous_receipt_id =
        id("receipt.peer.rendezvous.missing");
    assert!(matches!(
        ManifoldPeerRuntimeHost::from_snapshot(
            damaged,
            &host.snapshot().trust_policy,
            &host.snapshot().provider_epoch_id,
        ),
        Err(ManifoldPeerRuntimeHostError::InvalidSnapshot(_))
    ));
}

#[test]
fn trust_policy_is_canonical_external_restart_authority_not_mutation_input() {
    let mut unsorted = trust_policy();
    unsorted.trusted_operator_ids = vec![id("operator.z"), id("operator.a")];
    assert!(matches!(
        ManifoldPeerRuntimeHost::new(
            id("host.peer-runtime.unsorted"),
            unsorted,
            id(PROVIDER_EPOCH_ID),
            media_command_runtime(),
        ),
        Err(ManifoldPeerRuntimeHostError::InvalidSnapshot(_))
    ));

    let mut mislabeled_lock = trust_policy();
    mislabeled_lock.media_client_grants[0].feature_lock_id = mislabeled_lock.media_client_grants[0]
        .broker_client_lock_id
        .clone();
    mislabeled_lock.media_client_grants[0].feature_lock_fingerprint = mislabeled_lock
        .media_client_grants[0]
        .broker_client_lock_fingerprint
        .clone();
    assert!(matches!(
        ManifoldPeerRuntimeHost::new(
            id("host.peer-runtime.mislabeled-lock"),
            mislabeled_lock,
            id(PROVIDER_EPOCH_ID),
            media_command_runtime(),
        ),
        Err(ManifoldPeerRuntimeHostError::InvalidSnapshot(_))
    ));

    let mut duplicate = trust_policy();
    duplicate.trusted_adapter_ids.push(id(TRUSTED_ADAPTER_ID));
    assert!(matches!(
        ManifoldPeerRuntimeHost::new(
            id("host.peer-runtime.duplicate"),
            duplicate,
            id(PROVIDER_EPOCH_ID),
            media_command_runtime(),
        ),
        Err(ManifoldPeerRuntimeHostError::InvalidSnapshot(_))
    ));

    let mut duplicate_client_lock = trust_policy();
    let mut second = duplicate_client_lock.media_client_grants[0].clone();
    second.client_id = id("client.quest.media-z");
    second.broker_client_identity.client_id = second.client_id.clone();
    second.broker_client_identity.platform_subject = "org.rustyquest.media_z".to_owned();
    second.lease_id = id("lease.runtime.media-z");
    second.broker_runtime_lease_id = id("lease.broker.media-z");
    second.feature_lock_id = id("lock.quest.media-z");
    second.feature_lock_fingerprint = format!("sha256:{}", "ac".repeat(32));
    second.admission_grant_id = id("grant.quest.media-z");
    second.allowed_session_id = id("session.media.quest-z");
    duplicate_client_lock
        .media_client_grants
        .push(second.clone());
    assert!(ManifoldPeerRuntimeHost::new(
        id("host.peer-runtime.duplicate-client-lock"),
        duplicate_client_lock,
        id(PROVIDER_EPOCH_ID),
        media_command_runtime(),
    )
    .is_err());

    second.broker_client_lock_id = id("lock.client.media-z");
    let mut duplicate_client_digest = trust_policy();
    duplicate_client_digest.media_client_grants.push(second);
    assert!(ManifoldPeerRuntimeHost::new(
        id("host.peer-runtime.duplicate-client-digest"),
        duplicate_client_digest,
        id(PROVIDER_EPOCH_ID),
        media_command_runtime(),
    )
    .is_err());

    let host = fixture_host();
    let expected = host.snapshot().trust_policy.clone();
    let mut substituted = host.snapshot().clone();
    substituted.trust_policy.policy_id = id("policy.peer-runtime.substituted");
    substituted.trust_policy.trusted_operator_ids = vec![id("operator.attacker")];
    assert!(matches!(
        ManifoldPeerRuntimeHost::from_snapshot(
            substituted,
            &expected,
            &host.snapshot().provider_epoch_id,
        ),
        Err(ManifoldPeerRuntimeHostError::InvalidSnapshot(_))
    ));
}

#[test]
fn peer_only_and_enrollment_only_product_locks_need_no_fake_media_module() {
    let inert_runtime = || {
        let mut runtime = media_command_runtime();
        runtime.commands.clear();
        runtime.leases.clear();
        runtime
    };

    let mut peer_only = trust_policy();
    peer_only.enabled_authority_families = vec![ManifoldPeerRuntimeAuthorityFamily::PeerStatus];
    peer_only.trusted_operator_ids.clear();
    peer_only.trusted_adapter_ids.clear();
    peer_only.trusted_mesh_proposer_ids.clear();
    peer_only.media_client_grants.clear();
    peer_only.trusted_media_revoker_ids.clear();
    peer_only.direct_lane_client_grants.clear();
    peer_only.trusted_direct_lane_revoker_ids.clear();
    ManifoldPeerRuntimeHost::new(
        id("host.peer-only"),
        peer_only.clone(),
        id("provider.epoch.peer-only.001"),
        inert_runtime(),
    )
    .expect("peer-only host");

    let mut enrollment_only = peer_only.clone();
    enrollment_only.enabled_authority_families =
        vec![ManifoldPeerRuntimeAuthorityFamily::Enrollment];
    enrollment_only.trusted_key_fingerprints.clear();
    enrollment_only.trusted_operator_ids = vec![id(OPERATOR_ID)];
    ManifoldPeerRuntimeHost::new(
        id("host.enrollment-only"),
        enrollment_only,
        id("provider.epoch.enrollment-only.001"),
        inert_runtime(),
    )
    .expect("enrollment-only host");

    let mut damaged_runtime = inert_runtime();
    damaged_runtime
        .commands
        .push(ManifoldRuntimeCommandDescriptor {
            command_id: id(MANIFOLD_MEDIA_SESSION_ACCEPT_COMMAND),
            required_lease_scope: Some(id(MEDIA_RUNTIME_LEASE_SCOPE_ID)),
        });
    assert!(ManifoldPeerRuntimeHost::new(
        id("host.peer-only.damaged"),
        peer_only,
        id("provider.epoch.peer-only.damaged"),
        damaged_runtime,
    )
    .is_err());
}

#[test]
#[allow(clippy::too_many_lines)]
fn live_broker_mutation_atomically_mints_uses_releases_and_restores_media_lease() {
    let product_lock = resolve_broker_product(&ManifoldBrokerProductSpec {
        schema_id: schema_id(BROKER_PRODUCT_SPEC_SCHEMA),
        product_id: id("broker.runtime.media-test"),
        standalone_enabled: true,
        embedded_enabled: false,
        requested_features: vec![ManifoldBrokerFeature::MediaSession],
    })
    .expect("outer product lock");
    let packaged_product_lock = serde_json::to_vec(&product_lock).expect("serialize product lock");
    let product_lock_sha256 = packaged_product_lock_sha256(&packaged_product_lock);
    let mut policy = trust_policy();
    policy.media_client_grants[0].broker_product_lock_id = product_lock.lock_id.clone();
    policy.media_client_grants[0].broker_product_lock_fingerprint =
        product_lock.spec_fingerprint.clone();
    policy.media_client_grants[0].broker_product_lock_sha256 = product_lock_sha256.clone();
    let grant = policy.media_client_grants[0].clone();
    let mut inner_runtime = media_command_runtime();
    inner_runtime
        .leases
        .retain(|lease| lease.scope.as_str() != MEDIA_RUNTIME_LEASE_SCOPE_ID);
    let mut host = ManifoldPeerRuntimeHost::new(
        id("host.peer-runtime.dynamic-media"),
        policy.clone(),
        id(PROVIDER_EPOCH_ID),
        inner_runtime,
    )
    .expect("peer host without ambient media lease");

    let broker_adapter = ManifoldBrokerAdapter::new(
        ManifoldBrokerAdapterConfig {
            schema_id: schema_id(BROKER_ADAPTER_CONFIG_SCHEMA),
            adapter_id: grant.broker_adapter_id.clone(),
            mode: ManifoldBrokerAdapterMode::Standalone,
            product_lock_id: product_lock.lock_id.clone(),
            product_lock_fingerprint: product_lock.spec_fingerprint.clone(),
            product_lock_sha256,
            authority_host_id: grant.broker_runtime_host_id.clone(),
            authority_owner_id: id(RUNTIME_HOST_AUTHORITY_OWNER),
        },
        &packaged_product_lock,
        vec![ManifoldRuntimeLease {
            lease_id: grant.broker_runtime_lease_id.clone(),
            scope: id("lease.media.session"),
            holder_id: grant.client_id.clone(),
            expires_at_ms: 100_000,
        }],
    )
    .expect("outer broker adapter");
    let outer_capability = command_capability(&grant.broker_command_id);
    assert_eq!(outer_capability, grant.broker_capability_id);
    let admission_snapshot = ManifoldAdmissionSnapshot {
        schema_id: schema_id(ADMISSION_SNAPSHOT_SCHEMA),
        authority_id: id("authority.admission.media-test"),
        authority_revision: Revision::INITIAL,
        grants: vec![ManifoldAdmissionGrant {
            grant_id: grant.admission_grant_id.clone(),
            client_lock_id: grant.broker_client_lock_id.clone(),
            client_lock_fingerprint: grant.broker_client_lock_fingerprint.clone(),
            identity: grant.broker_client_identity.clone(),
            capabilities: vec![outer_capability.clone()],
            expires_at_ms: 100_000,
            revoked: false,
        }],
        active_tokens: Vec::new(),
        revoked_token_ids: Vec::new(),
        consumed_request_ids: Vec::new(),
        consumed_use_request_ids: Vec::new(),
        reviewed_sweep_ids: Vec::new(),
        audit_events: Vec::new(),
        max_token_ttl_ms: 30_000,
    };
    let mut broker =
        ManifoldBrokerRuntime::new(id(PROVIDER_EPOCH_ID), broker_adapter, admission_snapshot)
            .expect("outer broker runtime");
    let rejected_after_admission =
        broker_media_mutation(&mut broker, &grant, "consume-rejected", 29, 2_000);

    let mut rejected = rejected_after_admission.clone();
    rejected.command.command_id = id("command.media.session.stop");
    let unchanged_host = host.clone();
    let unchanged_broker = broker.clone();
    assert!(host
        .apply_broker_media_command_and_admit_runtime_lease(&mut broker, &rejected, 4_000)
        .is_err());
    assert_eq!(host, unchanged_host);
    assert_eq!(broker, unchanged_broker);

    let mut rejected_after_admission = rejected_after_admission;
    rejected_after_admission.command.expected_authority_revision = broker
        .host_snapshot()
        .authority_revision
        .next()
        .expect("different Runtime Host revision");
    let rejected_attempt = host
        .apply_broker_media_command_and_admit_runtime_lease(
            &mut broker,
            &rejected_after_admission,
            3_000,
        )
        .expect("typed post-admission broker-command rejection");
    assert_eq!(
        rejected_attempt.outcome,
        ManifoldPeerRuntimeBrokerLeaseAttemptOutcome::BrokerCommandRejected
    );
    assert!(rejected_attempt.broker_receipt.admission_applied);
    assert!(!rejected_attempt.broker_receipt.applied);
    assert!(rejected_attempt.lease_admission.is_none());
    assert!(broker
        .evidence()
        .consumed_bounded_use_ids
        .contains(&rejected_after_admission.admission_use_request_id));
    assert!(host.snapshot().broker_lease_admissions.is_empty());
    let consumed_host = host.clone();
    let consumed_broker = broker.clone();
    assert!(host
        .apply_broker_media_command_and_admit_runtime_lease(
            &mut broker,
            &rejected_after_admission,
            3_100,
        )
        .is_err());
    assert_eq!(host, consumed_host);
    assert_eq!(broker, consumed_broker);

    let mutation = broker_media_mutation(&mut broker, &grant, "first", 30, 3_200);
    let attempt = host
        .apply_broker_media_command_and_admit_runtime_lease(&mut broker, &mutation, 4_000)
        .expect("outer consume and inner lease mint");
    assert_eq!(
        attempt.outcome,
        ManifoldPeerRuntimeBrokerLeaseAttemptOutcome::LeaseAdmitted
    );
    let admission = attempt.lease_admission.expect("inner lease admission");
    assert_eq!(admission.runtime_lease.lease_id, grant.lease_id);
    assert!(broker
        .evidence()
        .consumed_bounded_use_ids
        .contains(&mutation.admission_use_request_id));
    let committed_host = host.clone();
    let committed_broker = broker.clone();
    assert!(matches!(
        host.apply_broker_media_command_and_admit_runtime_lease(&mut broker, &mutation, 4_100),
        Err(ManifoldPeerRuntimeHostError::ReplayedMutation(_))
    ));
    assert_eq!(host, committed_host);
    assert_eq!(broker, committed_broker);

    let acceptance = media_acceptance_request(
        &host,
        "request.media.accept.dynamic.001",
        6,
        PROVIDER_EPOCH_ID,
    );
    let acceptance_command = media_accept_command(&host, &acceptance);
    let accepted = host
        .review_media_session_acceptance(&acceptance, &acceptance_command, 4_250)
        .expect("inner media acceptance");
    assert!(accepted.accepted);
    let termination = ManifoldMediaSessionTerminationRequest {
        schema_id: schema_id(MANIFOLD_MEDIA_SESSION_TERMINATION_REQUEST_SCHEMA),
        request_id: id("request.media.dynamic.stop"),
        expected_authority_revision: host.snapshot().media_sessions.authority_revision,
        runtime_command_request_id: id("runtime.request.media.dynamic.stop"),
        decision_id: accepted.decision_id,
        session_id: acceptance.product_binding.descriptor.session_id.clone(),
        expected_provider_epoch_id: id(PROVIDER_EPOCH_ID),
        action: ManifoldMediaSessionTerminationAction::Stop,
    };
    let termination_command = ManifoldRuntimeCommandRequest {
        schema_id: schema_id(HOST_COMMAND_REQUEST_SCHEMA),
        request_id: termination.runtime_command_request_id.clone(),
        expected_authority_revision: host.snapshot().media_command_runtime.authority_revision,
        requester_id: grant.client_id.clone(),
        command_id: id(MANIFOLD_MEDIA_SESSION_STOP_COMMAND),
        lease_id: Some(grant.lease_id.clone()),
        params_digest: Some(
            media_session_termination_params_digest(&termination).expect("termination params"),
        ),
        issued_at_ms: 4_300,
        expires_at_ms: 10_000,
    };
    assert!(
        host.review_media_session_termination(&termination, &termination_command, 4_300)
            .expect("media stop")
            .applied
    );
    host.release_media_runtime_lease(&grant.lease_id, id("request.media.dynamic.release"), 4_400)
        .expect("inner lease release");
    assert!(!host
        .snapshot()
        .media_command_runtime
        .leases
        .iter()
        .any(|lease| lease.lease_id == grant.lease_id));

    let second_mutation = broker_media_mutation(&mut broker, &grant, "second", 31, 4_500);
    let second_attempt = host
        .apply_broker_media_command_and_admit_runtime_lease(&mut broker, &second_mutation, 4_700)
        .expect("fresh start after stop/release");
    assert_eq!(
        second_attempt.outcome,
        ManifoldPeerRuntimeBrokerLeaseAttemptOutcome::LeaseAdmitted
    );
    assert_eq!(host.snapshot().broker_lease_admissions.len(), 2);
    assert_eq!(
        host.snapshot()
            .broker_lease_admissions
            .iter()
            .filter(|admission| admission.released_at_ms.is_none())
            .count(),
        1
    );
    let second_acceptance = media_acceptance_request(
        &host,
        "request.media.accept.dynamic.002",
        7,
        PROVIDER_EPOCH_ID,
    );
    let second_acceptance_command = media_accept_command(&host, &second_acceptance);
    assert!(host
        .review_media_session_acceptance(
            &second_acceptance,
            &second_acceptance_command,
            4_800,
        )
        .expect("second media acceptance")
        .accepted);

    let restarted = ManifoldPeerRuntimeHost::restart_from_json(
        &host.snapshot_json().expect("dynamic snapshot"),
        &policy,
        &id(PROVIDER_EPOCH_ID),
    )
    .expect("dynamic bridge restart");
    assert_eq!(restarted, host);
    let stable = host.clone();
    assert!(matches!(
        host.release_media_runtime_lease(
            &grant.lease_id,
            id("request.media.dynamic.release"),
            4_500,
        ),
        Err(ManifoldPeerRuntimeHostError::ReplayedMutation(_))
    ));
    assert_eq!(host, stable);

    let mut damaged = host.snapshot().clone();
    damaged.broker_lease_admissions[0]
        .broker_receipt
        .adapter_receipt
        .as_mut()
        .expect("adapter receipt")
        .authority_host_id = id("host.broker.substituted");
    assert!(
        ManifoldPeerRuntimeHost::from_snapshot(damaged, &policy, &id(PROVIDER_EPOCH_ID),).is_err()
    );
}
