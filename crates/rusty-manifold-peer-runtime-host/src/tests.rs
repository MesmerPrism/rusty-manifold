use std::fmt::Write as _;

use ed25519_dalek::{Signer, SigningKey};
use rusty_manifold_admission::{
    ManifoldAdmissionGrant, ManifoldAdmissionRequest, ManifoldAdmissionSnapshot,
    ManifoldAdmissionUseRequest, ManifoldClientIdentity, ADMISSION_REQUEST_SCHEMA,
    ADMISSION_SNAPSHOT_SCHEMA, ADMISSION_USE_REQUEST_SCHEMA,
};
use rusty_manifold_broker_adapter::{
    command_capability, control_lease_lifecycle_capability, packaged_product_lock_sha256,
    ManifoldBrokerAdapter, ManifoldBrokerAdapterConfig, ManifoldBrokerAdapterMode,
    ManifoldBrokerControlLeaseAuthority, ManifoldBrokerControlLeaseLifecycleOperation,
    ManifoldBrokerControlLeaseLifecycleOperationKind, ManifoldBrokerControlLeaseLifecycleReceipt,
    ManifoldBrokerControlLeaseLifecycleRequest, ManifoldBrokerControlLeaseSource,
    ManifoldBrokerMutationRequest, ManifoldBrokerRuntime, BROKER_ADAPTER_CONFIG_SCHEMA,
    BROKER_CONTROL_LEASE_LIFECYCLE_REQUEST_SCHEMA, BROKER_CONTROL_LEASE_SOURCE_SCHEMA,
    BROKER_MUTATION_REQUEST_SCHEMA,
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
    DottedId, ManifoldAuthoritySnapshot, ManifoldClockSnapshot, ManifoldControlLeaseRequest,
    ManifoldMediaRouteLegDescriptor, ManifoldMediaSessionDescriptor, Revision, SafetyClass,
    SchemaId, MANIFOLD_BINARY_MEDIA_PLANE, MANIFOLD_MEDIA_ROUTE_LEG_SCHEMA,
    MANIFOLD_MEDIA_SESSION_SCHEMA,
};
use rusty_manifold_peer::{
    direct_lane_lease_issue_params_digest, direct_lane_lease_use_params_digest,
    pair_media_route_cleanup_params_digest, pair_media_route_issue_params_digest,
    pair_media_route_termination_params_digest, reciprocal_ed25519_context_sha256,
    reciprocal_ed25519_context_signing_bytes, rendezvous_signing_bytes,
    ManifoldDirectLaneClientGrant, ManifoldDirectLaneLeaseCurrentReceipt,
    ManifoldDirectLaneLeaseRejectionReason, ManifoldDirectLaneLeaseRequest,
    ManifoldDirectLaneLeaseScope, ManifoldDirectLaneLeaseUseRequest,
    ManifoldPairMediaRouteCleanupCompletionRequest, ManifoldPairMediaRouteCleanupStatus,
    ManifoldPairMediaRouteLifecycleStatus, ManifoldPairMediaRouteReceipt,
    ManifoldPairMediaRouteRequest, ManifoldPairMediaRouteTerminationAction,
    ManifoldPairMediaRouteTerminationRequest, ManifoldPeerCredentialAlgorithm,
    ManifoldPeerCredentialRecord, ManifoldPeerCredentialStatus, ManifoldPeerEnrollmentAction,
    ManifoldPeerEnrollmentRejectionReason, ManifoldPeerEnrollmentRequest, ManifoldPeerMeshProposal,
    ManifoldPeerMeshRejectionReason, ManifoldPeerMeshReviewCase, ManifoldPeerMeshRevocation,
    ManifoldPeerSessionProposal, ManifoldPeerSessionRejectionReason, ManifoldPeerSessionReviewCase,
    ManifoldPeerSessionRevocation, ManifoldReciprocalEd25519Context,
    ManifoldReciprocalEd25519PeerBinding, ManifoldReciprocalEd25519ReviewRequest,
    ManifoldReciprocalEd25519Revisions, ManifoldReciprocalEd25519Signature,
    ManifoldRendezvousRejectionReason, ManifoldRendezvousReviewRequest, ManifoldRendezvousRole,
    ManifoldSignedRendezvousEvidence, PeerRendezvousTransport, DIRECT_LANE_LEASE_ISSUE_COMMAND,
    DIRECT_LANE_LEASE_REQUEST_SCHEMA, DIRECT_LANE_LEASE_REVOKE_COMMAND,
    DIRECT_LANE_LEASE_USE_COMMAND, DIRECT_LANE_LEASE_USE_REQUEST_SCHEMA,
    DIRECT_LANE_MEDIA_SESSION_CAPABILITY, DIRECT_LANE_PEER_SESSION_CAPABILITY,
    MAX_PAIR_MEDIA_ROUTE_REQUEST_IDS, PAIR_MEDIA_ROUTE_CLEANUP_COMMAND,
    PAIR_MEDIA_ROUTE_CLEANUP_REQUEST_SCHEMA, PAIR_MEDIA_ROUTE_ISSUE_COMMAND,
    PAIR_MEDIA_ROUTE_REQUEST_SCHEMA, PAIR_MEDIA_ROUTE_REVOKE_COMMAND,
    PAIR_MEDIA_ROUTE_STATE_SCHEMA, PAIR_MEDIA_ROUTE_STOP_COMMAND,
    PAIR_MEDIA_ROUTE_TERMINATION_REQUEST_SCHEMA, PEER_CREDENTIAL_SCHEMA,
    PEER_ENROLLMENT_REQUEST_SCHEMA, PEER_SESSION_REVOCATION_SCHEMA, PEER_SESSION_SNAPSHOT_SCHEMA,
    PRODUCT_WIFI_DIRECT_TOPOLOGY_CONTRACT, RECIPROCAL_ED25519_CONTEXT_SCHEMA,
    RECIPROCAL_ED25519_REVIEW_SCHEMA, RECIPROCAL_ED25519_SIGNATURE_SCHEMA,
    RECIPROCAL_ED25519_STATE_SCHEMA, RENDEZVOUS_REVIEW_REQUEST_SCHEMA,
    SIGNED_RENDEZVOUS_EVIDENCE_SCHEMA,
};
use rusty_manifold_runtime_host::{
    ManifoldRuntimeCommandDescriptor, ManifoldRuntimeLease, ManifoldRuntimeRejectionReason,
    HOST_COMMAND_REQUEST_SCHEMA, LEGACY_HOST_AUDIT_EVENT_V3_SCHEMA, LEGACY_HOST_SNAPSHOT_V3_SCHEMA,
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

fn wifi_route(
    route: &ManifoldAcceptedPairMediaRouteV2,
) -> &rusty_manifold_peer::ManifoldAcceptedPairMediaRoute {
    match route {
        ManifoldAcceptedPairMediaRouteV2::WifiDirect(route) => route,
        ManifoldAcceptedPairMediaRouteV2::CommonLan(_) => panic!("expected Wi-Fi route"),
    }
}

fn wifi_route_mut(
    route: &mut ManifoldAcceptedPairMediaRouteV2,
) -> &mut rusty_manifold_peer::ManifoldAcceptedPairMediaRoute {
    match route {
        ManifoldAcceptedPairMediaRouteV2::WifiDirect(route) => route,
        ManifoldAcceptedPairMediaRouteV2::CommonLan(_) => panic!("expected Wi-Fi route"),
    }
}

fn wifi_topology_mut(
    topology: &mut ManifoldSignedPeerTopologyAuthorizationV2,
) -> &mut ManifoldSignedPeerTopologyAuthorization {
    match topology {
        ManifoldSignedPeerTopologyAuthorizationV2::WifiDirect(topology) => topology,
        ManifoldSignedPeerTopologyAuthorizationV2::CommonLan(_) => {
            panic!("expected Wi-Fi topology")
        }
    }
}

fn unwrap_tagged_array(value: &mut serde_json::Value, field: &str) {
    let Some(items) = value
        .get_mut(field)
        .and_then(serde_json::Value::as_array_mut)
    else {
        return;
    };
    for item in items {
        if let Some(record) = item.get_mut("record").map(std::mem::take) {
            *item = record;
        }
    }
}

fn convert_current_snapshot_value_to_legacy(value: &mut serde_json::Value) {
    unwrap_tagged_array(&mut value["reciprocal_ed25519"], "accepted_receipts");
    unwrap_tagged_array(&mut value["peer_sessions"], "sessions");
    unwrap_tagged_array(value, "signed_topology_authorizations");
    unwrap_tagged_array(&mut value["pair_media_routes"], "routes");
    unwrap_tagged_array(&mut value["pair_media_routes"], "cleanup_receipts");
    value["reciprocal_ed25519"]["$schema"] =
        serde_json::Value::String(RECIPROCAL_ED25519_STATE_SCHEMA.to_owned());
    value["peer_sessions"]["$schema"] =
        serde_json::Value::String(PEER_SESSION_SNAPSHOT_SCHEMA.to_owned());
    value["pair_media_routes"]["$schema"] =
        serde_json::Value::String(PAIR_MEDIA_ROUTE_STATE_SCHEMA.to_owned());
}

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
            PAIR_MEDIA_ROUTE_ISSUE_COMMAND,
            PAIR_MEDIA_ROUTE_STOP_COMMAND,
            PAIR_MEDIA_ROUTE_REVOKE_COMMAND,
            PAIR_MEDIA_ROUTE_CLEANUP_COMMAND,
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
                derivative_binding: None,
            },
            ManifoldRuntimeLease {
                lease_id: id("lease.runtime.direct-lane-test"),
                scope: direct_scope,
                holder_id: id(TRUSTED_MEDIA_PROPOSER_ID),
                expires_at_ms: 100_000,
                derivative_binding: None,
            },
            ManifoldRuntimeLease {
                lease_id: id("lease.runtime.media-revoker"),
                scope: id(MEDIA_RUNTIME_LEASE_SCOPE_ID),
                holder_id: id("operator.media-revoker"),
                expires_at_ms: 100_000,
                derivative_binding: None,
            },
        ],
        applied_request_ids: Vec::new(),
        reviewed_sweep_ids: Vec::new(),
        reviewed_control_lease_adoption_ids: Vec::new(),
        reviewed_derivative_lease_revocation_ids: Vec::new(),
        audit_events: Vec::new(),
    }
}

fn remove_pair_route_commands(runtime: &mut ManifoldRuntimeHostSnapshot) {
    runtime.commands.retain(|command| {
        !matches!(
            command.command_id.as_str(),
            PAIR_MEDIA_ROUTE_ISSUE_COMMAND
                | PAIR_MEDIA_ROUTE_STOP_COMMAND
                | PAIR_MEDIA_ROUTE_REVOKE_COMMAND
                | PAIR_MEDIA_ROUTE_CLEANUP_COMMAND
        )
    });
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

fn revoke_broker_control_lease(
    broker: &mut ManifoldBrokerRuntime,
    grant: &ManifoldMediaSessionClientGrant,
    suffix: &str,
    entropy: u8,
) -> ManifoldBrokerControlLeaseLifecycleReceipt {
    let capability = control_lease_lifecycle_capability(
        ManifoldBrokerControlLeaseLifecycleOperationKind::Revocation,
    );
    let now_ms = u64::try_from(
        broker
            .evidence()
            .control_lease_authority
            .current_clock
            .wall_unix_ms,
    )
    .expect("positive Broker authority clock");
    let issue = broker.issue_token(
        &ManifoldAdmissionRequest {
            schema_id: schema_id(ADMISSION_REQUEST_SCHEMA),
            request_id: id(&format!("request.media.dynamic.{suffix}.revoke-token")),
            expected_authority_revision: broker.admission_snapshot().authority_revision,
            identity: grant.broker_client_identity.clone(),
            requested_capabilities: vec![capability.clone()],
            issued_at_ms: now_ms,
            expires_at_ms: now_ms.saturating_add(25_000),
            requested_token_ttl_ms: 20_000,
        },
        [entropy; 32],
        now_ms,
    );
    assert!(issue.applied, "{issue:?}");
    let token = issue.token.expect("revocation lifecycle token");
    let use_request = ManifoldAdmissionUseRequest {
        schema_id: schema_id(ADMISSION_USE_REQUEST_SCHEMA),
        request_id: id(&format!("request.media.dynamic.{suffix}.revoke-use")),
        expected_authority_revision: issue.resulting_authority_revision,
        token_id: token.token_id.clone(),
        identity: grant.broker_client_identity.clone(),
        capability_id: capability,
        issued_at_ms: now_ms,
        expires_at_ms: now_ms.saturating_add(15_000),
    };
    let operation = ManifoldBrokerControlLeaseLifecycleOperation::Revocation {
        request_id: id(&format!("request.media.dynamic.{suffix}.revocation")),
        lease_id: grant.broker_runtime_lease_id.clone(),
        expected_authority_revision: broker.control_lease_authority_snapshot().authority_revision,
        revocation_reason: id("reason.operator.security-revocation"),
        requested_at_ms: now_ms,
    };
    let lifecycle_request = ManifoldBrokerControlLeaseLifecycleRequest {
        schema_id: schema_id(BROKER_CONTROL_LEASE_LIFECYCLE_REQUEST_SCHEMA),
        provider_epoch_id: broker.provider_epoch_id().clone(),
        admission_use_request_id: use_request.request_id.clone(),
        token_id: token.token_id,
        expected_admission_authority_revision: use_request.expected_authority_revision,
        operation,
    };
    let authorization =
        broker.authorize_control_lease_lifecycle_use(&use_request, &lifecycle_request, now_ms);
    assert!(authorization.applied, "{authorization:?}");
    let mut clock = broker.evidence().control_lease_authority.current_clock;
    clock.sequence += 1;
    clock.monotonic_elapsed_ns += 1_000_000;
    clock.wall_unix_ms += 1;
    broker
        .commit_control_lease_lifecycle(
            &lifecycle_request,
            clock,
            vec![id("evidence.peer-runtime.live-broker-revocation")],
            |receipt, _| receipt.clone(),
        )
        .expect("Broker revocation lifecycle commit")
}

fn id(value: &str) -> DottedId {
    DottedId::new(value).expect("test id")
}

fn schema_id(value: &str) -> SchemaId {
    SchemaId::new(value).expect("test schema")
}

fn broker_control_lease_authority(
    lease: &ManifoldRuntimeLease,
) -> ManifoldBrokerControlLeaseAuthority {
    let mut prior: ManifoldAuthoritySnapshot = serde_json::from_str(include_str!(
        "../../../fixtures/authority/synthetic-authority-snapshot.json"
    ))
    .expect("prior authority snapshot");
    let clock: ManifoldClockSnapshot = serde_json::from_str(include_str!(
        "../../../fixtures/clock/synthetic-command-review-clock.json"
    ))
    .expect("projection clock");
    let capability = id("capability.broker.peer-runtime.test");
    prior.host_manifest.capabilities.push(capability.clone());
    let suffix = lease
        .lease_id
        .as_str()
        .strip_prefix("lease.")
        .expect("lease id");
    let review = prior
        .review_lease_request(
            ManifoldControlLeaseRequest {
                schema_id: schema_id("rusty.manifold.command.lease_request.v1"),
                request_id: id(&format!("request.{suffix}")),
                holder_id: lease.holder_id.clone(),
                scope: lease.scope.clone(),
                expected_revision: prior.authority_revision,
                requested_ttl_ms: 30_000,
                required_capability: capability,
                safety_class: SafetyClass::BoundedMutation,
            },
            clock.clone(),
            vec![id("evidence.broker.peer-runtime.test.lease")],
        )
        .expect("lease review");
    let application = prior
        .apply_control_lease_authority_review(review)
        .expect("lease application");
    let current = application
        .applied_snapshot
        .clone()
        .expect("applied snapshot");
    ManifoldBrokerControlLeaseAuthority::from_caller_attested_retained_authority_state(
        current,
        clock,
        vec![ManifoldBrokerControlLeaseSource {
            schema_id: schema_id(BROKER_CONTROL_LEASE_SOURCE_SCHEMA),
            prior_authority_snapshot: prior,
            application,
        }],
    )
    .expect("control-lease authority")
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
                .find(|receipt| {
                    receipt.receipt_id
                        == topology
                            .as_wifi_direct()
                            .expect("Wi-Fi topology")
                            .rendezvous_receipt_id
                })
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

#[allow(clippy::too_many_arguments)]
fn pair_route_request(
    host: &ManifoldPeerRuntimeHost,
    request_id: &str,
    command_request_id: &str,
    leg_id: &str,
    leg_revision: u64,
    source_peer_id: &str,
    sink_peer_id: &str,
    peer_session_id: &str,
    media_decision_id: DottedId,
    expires_at_ms: u64,
) -> ManifoldPairMediaRouteRequest {
    let media = host
        .snapshot()
        .media_sessions
        .sessions
        .iter()
        .find(|media| media.decision_id == media_decision_id)
        .expect("accepted media decision");
    let runtime_lease_expires_at_ms = host
        .snapshot()
        .media_command_runtime
        .leases
        .iter()
        .find(|lease| lease.lease_id == media.runtime_lease_id)
        .expect("media runtime lease")
        .expires_at_ms;
    ManifoldPairMediaRouteRequest {
        schema_id: schema_id(PAIR_MEDIA_ROUTE_REQUEST_SCHEMA),
        request_id: id(request_id),
        expected_authority_revision: host.snapshot().pair_media_routes.authority_revision,
        expected_peer_session_authority_revision: host.snapshot().peer_sessions.authority_revision,
        expected_media_acceptance_authority_revision: host
            .snapshot()
            .media_sessions
            .authority_revision,
        runtime_command_request_id: id(command_request_id),
        expected_runtime_lease_expires_at_ms: runtime_lease_expires_at_ms,
        peer_session_id: id(peer_session_id),
        media_session_decision_id: media_decision_id,
        route_leg: ManifoldMediaRouteLegDescriptor {
            schema_id: schema_id(MANIFOLD_MEDIA_ROUTE_LEG_SCHEMA),
            leg_id: id(leg_id),
            leg_revision: Revision::new(leg_revision).expect("leg revision"),
            source_peer_id: id(source_peer_id),
            sink_peer_id: id(sink_peer_id),
            source_id: id("source.quest.camera.alpha"),
            processor_ids: vec![id("processor.quest.layout.passthrough")],
            route_id: id("route.alpha-beta.fast"),
            sink_id: id("sink.quest.beta"),
            stream_ids: vec![id("stream.quest.camera.alpha-beta")],
        },
        expires_at_ms,
    }
}

fn media_command(
    host: &ManifoldPeerRuntimeHost,
    request_id: DottedId,
    command_id: &str,
    params_digest: rusty_manifold_runtime_host::ManifoldRuntimeTypedParamsDigest,
    requester_id: &str,
    lease_id: &str,
    now_ms: u64,
) -> ManifoldRuntimeCommandRequest {
    ManifoldRuntimeCommandRequest {
        schema_id: schema_id(HOST_COMMAND_REQUEST_SCHEMA),
        request_id,
        expected_authority_revision: host.snapshot().media_command_runtime.authority_revision,
        requester_id: id(requester_id),
        command_id: id(command_id),
        lease_id: Some(id(lease_id)),
        params_digest: Some(params_digest),
        issued_at_ms: now_ms.saturating_sub(1),
        expires_at_ms: now_ms.saturating_add(1_000),
    }
}

fn issue_pair_route(
    host: &mut ManifoldPeerRuntimeHost,
    request: &ManifoldPairMediaRouteRequest,
    now_ms: u64,
) -> ManifoldPairMediaRouteReceipt {
    let command = media_command(
        host,
        request.runtime_command_request_id.clone(),
        PAIR_MEDIA_ROUTE_ISSUE_COMMAND,
        pair_media_route_issue_params_digest(request).expect("pair route params"),
        TRUSTED_MEDIA_PROPOSER_ID,
        "lease.runtime.media-test",
        now_ms,
    );
    host.review_pair_media_route(request, &command, now_ms)
        .expect("pair route review")
}

#[allow(clippy::needless_pass_by_value)]
fn terminate_pair_route(
    host: &mut ManifoldPeerRuntimeHost,
    grant_id: DottedId,
    action: ManifoldPairMediaRouteTerminationAction,
    suffix: &str,
    requester_id: &str,
    lease_id: &str,
    now_ms: u64,
) {
    let request = ManifoldPairMediaRouteTerminationRequest {
        schema_id: schema_id(PAIR_MEDIA_ROUTE_TERMINATION_REQUEST_SCHEMA),
        request_id: id(&format!("request.pair-route.{suffix}")),
        expected_authority_revision: host.snapshot().pair_media_routes.authority_revision,
        runtime_command_request_id: id(&format!("runtime.request.pair-route.{suffix}")),
        grant_id,
        action: action.clone(),
    };
    let command_id = match action {
        ManifoldPairMediaRouteTerminationAction::Stop => PAIR_MEDIA_ROUTE_STOP_COMMAND,
        ManifoldPairMediaRouteTerminationAction::Revoke => PAIR_MEDIA_ROUTE_REVOKE_COMMAND,
    };
    let command = media_command(
        host,
        request.runtime_command_request_id.clone(),
        command_id,
        pair_media_route_termination_params_digest(&request).expect("termination params"),
        requester_id,
        lease_id,
        now_ms,
    );
    assert!(
        host.review_pair_media_route_termination(&request, &command, now_ms)
            .expect("pair route termination")
            .applied
    );
}

fn cleanup_pair_route_as_operator(
    host: &mut ManifoldPeerRuntimeHost,
    grant_id: DottedId,
    suffix: &str,
    now_ms: u64,
) {
    let request = ManifoldPairMediaRouteCleanupCompletionRequest {
        schema_id: schema_id(PAIR_MEDIA_ROUTE_CLEANUP_REQUEST_SCHEMA),
        request_id: id(&format!("request.pair-route.cleanup.{suffix}")),
        expected_authority_revision: host.snapshot().pair_media_routes.authority_revision,
        runtime_command_request_id: id(&format!("runtime.request.pair-route.cleanup.{suffix}")),
        grant_id,
        effect_receipt_id: id(&format!("effect.pair-route.cleanup.{suffix}")),
        effect_receipt_sha256: format!("sha256:{}", "93".repeat(32)),
    };
    let command = media_command(
        host,
        request.runtime_command_request_id.clone(),
        PAIR_MEDIA_ROUTE_CLEANUP_COMMAND,
        pair_media_route_cleanup_params_digest(&request).expect("cleanup params"),
        "operator.media-revoker",
        "lease.runtime.media-revoker",
        now_ms,
    );
    host.complete_pair_media_route_cleanup(&request, &command, now_ms)
        .expect("operator cleanup");
}

fn restart_host(host: &ManifoldPeerRuntimeHost) -> ManifoldPeerRuntimeHost {
    ManifoldPeerRuntimeHost::from_snapshot(
        host.snapshot().clone(),
        &host.snapshot().trust_policy,
        &host.snapshot().provider_epoch_id,
    )
    .expect("peer Runtime Host snapshot restores")
}

fn issue_lifecycle_pair_route(
    host: &mut ManifoldPeerRuntimeHost,
    media_decision_id: DottedId,
    suffix: &str,
    expires_at_ms: u64,
) -> DottedId {
    let request = pair_route_request(
        host,
        &format!("request.pair-route.source-end.{suffix}"),
        &format!("runtime.request.pair-route.source-end.{suffix}"),
        &format!("leg.source-end.{suffix}"),
        1,
        "peer.alpha",
        "peer.beta",
        "session.peer.pair-only.001",
        media_decision_id,
        expires_at_ms,
    );
    issue_pair_route(host, &request, 4_100)
        .accepted_route
        .expect("source-end route accepted")
        .grant_id
}

#[allow(clippy::needless_pass_by_value)]
fn finish_pair_route_after_source_end(
    host: &mut ManifoldPeerRuntimeHost,
    grant_id: DottedId,
    suffix: &str,
    termination_at_ms: u64,
    route_expired: bool,
) {
    *host = restart_host(host);
    assert!(
        !host
            .validate_pair_media_route(&grant_id, termination_at_ms)
            .current,
        "retained route must not become live authority after {suffix}"
    );
    if route_expired {
        host.expire_pair_media_routes(
            id(&format!("sweep.pair-route.{suffix}")),
            host.snapshot().pair_media_routes.authority_revision,
            termination_at_ms,
        )
        .expect("expired pair route terminalizes");
    } else {
        terminate_pair_route(
            host,
            grant_id.clone(),
            ManifoldPairMediaRouteTerminationAction::Stop,
            &format!("stop-after-{suffix}"),
            TRUSTED_MEDIA_PROPOSER_ID,
            "lease.runtime.media-test",
            termination_at_ms,
        );
    }
    *host = restart_host(host);
    let terminal = host
        .snapshot()
        .pair_media_routes
        .routes
        .iter()
        .find(|route| route.grant_id() == &grant_id)
        .expect("terminal route retained");
    assert_eq!(
        *terminal.cleanup_status(),
        ManifoldPairMediaRouteCleanupStatus::Pending
    );
    cleanup_pair_route_as_operator(
        host,
        grant_id.clone(),
        &format!("after-{suffix}"),
        termination_at_ms + 1,
    );
    *host = restart_host(host);
    let completed = host
        .snapshot()
        .pair_media_routes
        .routes
        .iter()
        .find(|route| route.grant_id() == &grant_id)
        .expect("cleaned route retained");
    assert_eq!(
        *completed.cleanup_status(),
        ManifoldPairMediaRouteCleanupStatus::Completed
    );
}

fn pair_host_without_mesh() -> (ManifoldPeerRuntimeHost, DottedId) {
    let mut host = fixture_host();
    let (alpha_key, beta_key) = enroll_pair(&mut host);
    let rendezvous = rendezvous_request(
        &host,
        "pair-only.001",
        "key.peer.alpha.001",
        &alpha_key,
        &beta_key,
        9,
    );
    let rendezvous_receipt = host
        .review_signed_rendezvous(&rendezvous, 3_000)
        .expect("pair rendezvous");
    assert!(rendezvous_receipt.accepted);
    accept_session(
        &mut host,
        rendezvous_receipt,
        "proposal.peer-session.pair-only.001",
        "session.peer.pair-only.001",
    );
    assert!(host.snapshot().peer_mesh.members.is_empty());
    let acceptance_request = media_acceptance_request(
        &host,
        "request.media.accept.pair-only.001",
        6,
        PROVIDER_EPOCH_ID,
    );
    let acceptance_command = media_accept_command(&host, &acceptance_request);
    let acceptance = host
        .review_media_session_acceptance(&acceptance_request, &acceptance_command, 4_000)
        .expect("pair media acceptance");
    assert!(acceptance.accepted);
    (
        host,
        acceptance
            .accepted_session
            .expect("accepted pair media")
            .decision_id,
    )
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
#[allow(clippy::too_many_lines)]
fn pair_route_lifecycle_is_two_peer_directional_replay_safe_and_restartable() {
    let (mut host, media_decision_id) = pair_host_without_mesh();
    let signed_topology = host.snapshot().signed_topology_authorizations[0].clone();
    host.snapshot.enrollment.authority_revision = host
        .snapshot
        .enrollment
        .authority_revision
        .next()
        .expect("unrelated enrollment revision");
    host.snapshot.rendezvous.authority_revision = host
        .snapshot
        .rendezvous
        .authority_revision
        .next()
        .expect("unrelated rendezvous revision");
    host.snapshot.peer_sessions.authority_revision = host
        .snapshot
        .peer_sessions
        .authority_revision
        .next()
        .expect("unrelated pair acceptance revision");
    let first = pair_route_request(
        &host,
        "request.pair-route.alpha-beta.001",
        "runtime.request.pair-route.alpha-beta.001",
        "leg.camera.alpha-beta",
        1,
        "peer.alpha",
        "peer.beta",
        "session.peer.pair-only.001",
        media_decision_id.clone(),
        20_000,
    );
    let issued = issue_pair_route(&mut host, &first, 4_100);
    assert!(issued.accepted, "{issued:?}");
    let first_route = issued.accepted_route.expect("accepted first route");
    assert_eq!(first_route.authority_host_id, id(MEDIA_RUNTIME_HOST_ID));
    assert_eq!(
        first_route.authority_provider_epoch_id,
        id(PROVIDER_EPOCH_ID)
    );
    assert_eq!(
        first_route.authority_client_id,
        id(TRUSTED_MEDIA_PROPOSER_ID)
    );
    assert_ne!(
        first_route.authority_host_id,
        first_route.authority_client_id
    );
    assert_eq!(
        first_route.source_topology_role,
        rusty_manifold_peer::PeerTopologyRole::GroupOwner
    );
    assert_eq!(
        first_route.peer_session_authority_revision,
        signed_topology
            .as_wifi_direct()
            .expect("Wi-Fi topology")
            .topology_authorization
            .authority_revision
    );
    assert_eq!(
        first_route.peer_session_acceptance_authority_revision,
        host.snapshot().peer_sessions.authority_revision
    );
    assert_eq!(
        first_route.rendezvous_authority_revision,
        signed_topology
            .as_wifi_direct()
            .expect("Wi-Fi topology")
            .rendezvous_authority_revision
    );
    assert_eq!(
        first_route.enrollment_authority_revision,
        signed_topology
            .as_wifi_direct()
            .expect("Wi-Fi topology")
            .enrollment_authority_revision
    );
    assert_eq!(
        first_route.sink_topology_role,
        rusty_manifold_peer::PeerTopologyRole::Client
    );
    let current_route = host.validate_pair_media_route(&first_route.grant_id, 4_200);
    assert!(current_route.current, "{current_route:?}");
    let mut mismatched_live_topology = host.clone();
    let next_rendezvous_revision = host.snapshot().signed_topology_authorizations[0]
        .as_wifi_direct()
        .expect("Wi-Fi topology")
        .rendezvous_authority_revision
        .next()
        .expect("mismatched live topology revision");
    wifi_topology_mut(
        &mut mismatched_live_topology
            .snapshot
            .signed_topology_authorizations[0],
    )
    .rendezvous_authority_revision = next_rendezvous_revision;
    assert!(
        !mismatched_live_topology
            .validate_pair_media_route(&first_route.grant_id, 4_200)
            .current
    );
    let mut damaged_current = host.clone();
    wifi_route_mut(&mut damaged_current.snapshot.pair_media_routes.routes[0])
        .peer_session_decision_id = id("decision.peer-session.damaged");
    assert!(
        !damaged_current
            .validate_pair_media_route(&first_route.grant_id, 4_200)
            .current
    );

    let replay = issue_pair_route(&mut host, &first, 4_200);
    assert!(!replay.accepted);
    assert_eq!(
        replay.rejection_reason,
        Some(rusty_manifold_peer::ManifoldPairMediaRouteRejectionReason::ReplayedRequest)
    );

    let reverse_collision = pair_route_request(
        &host,
        "request.pair-route.reverse-collision",
        "runtime.request.pair-route.reverse-collision",
        "leg.camera.alpha-beta",
        2,
        "peer.beta",
        "peer.alpha",
        "session.peer.pair-only.001",
        media_decision_id.clone(),
        20_000,
    );
    let reverse_collision_receipt = issue_pair_route(&mut host, &reverse_collision, 4_250);
    assert_eq!(
        reverse_collision_receipt.rejection_reason,
        Some(rusty_manifold_peer::ManifoldPairMediaRouteRejectionReason::DirectionMismatch)
    );

    let reverse = pair_route_request(
        &host,
        "request.pair-route.beta-alpha.001",
        "runtime.request.pair-route.beta-alpha.001",
        "leg.camera.beta-alpha",
        1,
        "peer.beta",
        "peer.alpha",
        "session.peer.pair-only.001",
        media_decision_id.clone(),
        20_000,
    );
    let reverse_receipt = issue_pair_route(&mut host, &reverse, 4_300);
    assert!(reverse_receipt.accepted, "{reverse_receipt:?}");
    let reverse_route = reverse_receipt.accepted_route.expect("reverse route");
    assert_eq!(
        reverse_route.source_topology_role,
        rusty_manifold_peer::PeerTopologyRole::Client
    );
    assert_eq!(
        reverse_route.sink_topology_role,
        rusty_manifold_peer::PeerTopologyRole::GroupOwner
    );

    let replacement = pair_route_request(
        &host,
        "request.pair-route.alpha-beta.002",
        "runtime.request.pair-route.alpha-beta.002",
        "leg.camera.alpha-beta",
        2,
        "peer.alpha",
        "peer.beta",
        "session.peer.pair-only.001",
        media_decision_id.clone(),
        21_000,
    );
    let replacement_receipt = issue_pair_route(&mut host, &replacement, 4_400);
    assert!(replacement_receipt.accepted, "{replacement_receipt:?}");
    let replacement_route = replacement_receipt
        .accepted_route
        .expect("replacement route");
    let superseded = host
        .snapshot()
        .pair_media_routes
        .routes
        .iter()
        .find(|route| route.grant_id() == &first_route.grant_id)
        .expect("superseded retained route");
    assert_eq!(
        *superseded.lifecycle_status(),
        ManifoldPairMediaRouteLifecycleStatus::Superseded
    );
    assert_eq!(
        *superseded.cleanup_status(),
        ManifoldPairMediaRouteCleanupStatus::Pending
    );

    let stop = ManifoldPairMediaRouteTerminationRequest {
        schema_id: schema_id(PAIR_MEDIA_ROUTE_TERMINATION_REQUEST_SCHEMA),
        request_id: id("request.pair-route.stop.001"),
        expected_authority_revision: host.snapshot().pair_media_routes.authority_revision,
        runtime_command_request_id: id("runtime.request.pair-route.stop.001"),
        grant_id: replacement_route.grant_id.clone(),
        action: ManifoldPairMediaRouteTerminationAction::Stop,
    };
    let stop_command = media_command(
        &host,
        stop.runtime_command_request_id.clone(),
        PAIR_MEDIA_ROUTE_STOP_COMMAND,
        pair_media_route_termination_params_digest(&stop).expect("stop params"),
        TRUSTED_MEDIA_PROPOSER_ID,
        "lease.runtime.media-test",
        4_500,
    );
    let stopped = host
        .review_pair_media_route_termination(&stop, &stop_command, 4_500)
        .expect("stop route");
    assert!(stopped.applied, "{stopped:?}");
    assert!(
        !host
            .validate_pair_media_route(&replacement_route.grant_id, 4_501)
            .current
    );

    let cleanup = ManifoldPairMediaRouteCleanupCompletionRequest {
        schema_id: schema_id(PAIR_MEDIA_ROUTE_CLEANUP_REQUEST_SCHEMA),
        request_id: id("request.pair-route.cleanup.001"),
        expected_authority_revision: host.snapshot().pair_media_routes.authority_revision,
        runtime_command_request_id: id("runtime.request.pair-route.cleanup.001"),
        grant_id: replacement_route.grant_id.clone(),
        effect_receipt_id: id("effect.route.release.001"),
        effect_receipt_sha256: format!("sha256:{}", "42".repeat(32)),
    };
    let cleanup_command = media_command(
        &host,
        cleanup.runtime_command_request_id.clone(),
        PAIR_MEDIA_ROUTE_CLEANUP_COMMAND,
        pair_media_route_cleanup_params_digest(&cleanup).expect("cleanup params"),
        "operator.media-revoker",
        "lease.runtime.media-revoker",
        4_600,
    );
    let cleanup_receipt = host
        .complete_pair_media_route_cleanup(&cleanup, &cleanup_command, 4_600)
        .expect("complete cleanup");
    assert_eq!(cleanup_receipt.grant_id, replacement_route.grant_id);

    let assert_damaged_rejected = |damaged: ManifoldPeerRuntimeHostSnapshot| {
        assert!(matches!(
            ManifoldPeerRuntimeHost::from_snapshot(
                damaged,
                &host.snapshot().trust_policy,
                &host.snapshot().provider_epoch_id,
            ),
            Err(ManifoldPeerRuntimeHostError::InvalidSnapshot(_))
        ));
    };
    let completed_index = host
        .snapshot()
        .pair_media_routes
        .routes
        .iter()
        .position(|route| route.grant_id() == &replacement_route.grant_id)
        .expect("completed route index");
    let cleanup_index = host
        .snapshot()
        .pair_media_routes
        .cleanup_receipts
        .iter()
        .position(|receipt| receipt.request_id() == &cleanup.request_id)
        .expect("cleanup receipt index");

    let mut damaged = host.snapshot().clone();
    wifi_route_mut(&mut damaged.pair_media_routes.routes[completed_index]).runtime_dispatch_id =
        id("dispatch.damaged");
    assert_damaged_rejected(damaged);
    let mut damaged = host.snapshot().clone();
    wifi_route_mut(&mut damaged.pair_media_routes.routes[completed_index])
        .runtime_application_receipt_id = id("receipt.damaged");
    assert_damaged_rejected(damaged);
    let mut damaged = host.snapshot().clone();
    wifi_route_mut(&mut damaged.pair_media_routes.routes[completed_index])
        .runtime_params_digest
        .canonical_sha256 = format!("sha256:{}", "aa".repeat(32));
    assert_damaged_rejected(damaged);
    let mut damaged = host.snapshot().clone();
    wifi_route_mut(&mut damaged.pair_media_routes.routes[completed_index])
        .runtime_resulting_authority_revision = Revision::INITIAL;
    assert_damaged_rejected(damaged);
    let mut damaged = host.snapshot().clone();
    wifi_route_mut(&mut damaged.pair_media_routes.routes[completed_index]).lifecycle_status =
        ManifoldPairMediaRouteLifecycleStatus::Revoked;
    assert_damaged_rejected(damaged);
    let mut damaged = host.snapshot().clone();
    wifi_route_mut(&mut damaged.pair_media_routes.routes[completed_index])
        .termination_runtime_binding
        .as_mut()
        .expect("termination binding")
        .requester_id = id("client.wrong");
    assert_damaged_rejected(damaged);
    let mut damaged = host.snapshot().clone();
    *match &mut damaged.pair_media_routes.cleanup_receipts[cleanup_index] {
        ManifoldPairMediaRouteCleanupReceiptV2::WifiDirect(value)
        | ManifoldPairMediaRouteCleanupReceiptV2::CommonLan(value) => &mut value.effect_receipt_id,
    } = id("effect.damaged");
    assert_damaged_rejected(damaged);
    let mut damaged = host.snapshot().clone();
    let issue_request_id = wifi_route(&damaged.pair_media_routes.routes[completed_index])
        .runtime_command_request_id
        .clone();
    match &mut damaged.pair_media_routes.cleanup_receipts[cleanup_index] {
        ManifoldPairMediaRouteCleanupReceiptV2::WifiDirect(value)
        | ManifoldPairMediaRouteCleanupReceiptV2::CommonLan(value) => {
            value.runtime_binding.request_id = issue_request_id;
        }
    }
    assert_damaged_rejected(damaged);
    let mut damaged = host.snapshot().clone();
    wifi_route_mut(&mut damaged.pair_media_routes.routes[completed_index]).ended_at_ms = Some(1);
    assert_damaged_rejected(damaged);
    let mut damaged = host.snapshot().clone();
    match &mut damaged.pair_media_routes.cleanup_receipts[cleanup_index] {
        ManifoldPairMediaRouteCleanupReceiptV2::WifiDirect(value)
        | ManifoldPairMediaRouteCleanupReceiptV2::CommonLan(value) => value.completed_at_ms = 1,
    }
    assert_damaged_rejected(damaged);
    let mut damaged = host.snapshot().clone();
    damaged
        .audit_events
        .iter_mut()
        .find(|event| {
            event.event_kind == ManifoldPeerRuntimeAuditKind::PairMediaRoute
                && event.source_id == replacement.request_id
                && event.applied
        })
        .expect("accepted issue audit")
        .event_kind = ManifoldPeerRuntimeAuditKind::PairMediaRouteExpiry;
    assert_damaged_rejected(damaged);

    let json = host.snapshot_json().expect("pair route snapshot");
    let mut restarted = ManifoldPeerRuntimeHost::restart_from_json(
        &json,
        &host.snapshot().trust_policy,
        &host.snapshot().provider_epoch_id,
    )
    .expect("pair route restart");
    assert_eq!(restarted.snapshot(), host.snapshot());

    let pending_cleanup = ManifoldPairMediaRouteCleanupCompletionRequest {
        schema_id: schema_id(PAIR_MEDIA_ROUTE_CLEANUP_REQUEST_SCHEMA),
        request_id: id("request.pair-route.cleanup-after-restart.001"),
        expected_authority_revision: restarted.snapshot().pair_media_routes.authority_revision,
        runtime_command_request_id: id("runtime.request.pair-route.cleanup-after-restart.001"),
        grant_id: first_route.grant_id,
        effect_receipt_id: id("effect.route.release-after-restart.001"),
        effect_receipt_sha256: format!("sha256:{}", "43".repeat(32)),
    };
    let pending_cleanup_command = media_command(
        &restarted,
        pending_cleanup.runtime_command_request_id.clone(),
        PAIR_MEDIA_ROUTE_CLEANUP_COMMAND,
        pair_media_route_cleanup_params_digest(&pending_cleanup).expect("cleanup params"),
        TRUSTED_MEDIA_PROPOSER_ID,
        "lease.runtime.media-test",
        4_700,
    );
    restarted
        .complete_pair_media_route_cleanup(&pending_cleanup, &pending_cleanup_command, 4_700)
        .expect("pending replacement cleanup survives restart");

    let mut damaged = restarted.snapshot().clone();
    wifi_route_mut(&mut damaged.pair_media_routes.routes[0]).authority_provider_epoch_id =
        id("epoch.unowned");
    assert!(matches!(
        ManifoldPeerRuntimeHost::from_snapshot(
            damaged,
            &restarted.snapshot().trust_policy,
            &restarted.snapshot().provider_epoch_id,
        ),
        Err(ManifoldPeerRuntimeHostError::InvalidSnapshot(_))
    ));
}

#[test]
#[allow(clippy::too_many_lines)]
fn pair_route_expiry_revocation_and_mesh_three_to_two_are_independent() {
    let (mut host, _, _) = ready_host();
    let acceptance_request = media_acceptance_request(
        &host,
        "request.media.accept.mesh-transition.001",
        6,
        PROVIDER_EPOCH_ID,
    );
    let acceptance_command = media_accept_command(&host, &acceptance_request);
    let acceptance = host
        .review_media_session_acceptance(&acceptance_request, &acceptance_command, 4_000)
        .expect("transition media acceptance");
    let media_decision_id = acceptance
        .accepted_session
        .expect("transition media accepted")
        .decision_id;
    let expiring = pair_route_request(
        &host,
        "request.pair-route.transition.001",
        "runtime.request.pair-route.transition.001",
        "leg.transition.alpha-beta",
        1,
        "peer.alpha",
        "peer.beta",
        "session.peer.host.001",
        media_decision_id.clone(),
        5_000,
    );
    let expiring_receipt = issue_pair_route(&mut host, &expiring, 4_100);
    let expiring_grant = expiring_receipt
        .accepted_route
        .expect("expiring route")
        .grant_id;
    let mesh_mutation = host
        .revoke_peer_mesh_member(&ManifoldPeerMeshRevocation {
            revocation_id: id("request.mesh.remove.gamma.001"),
            peer_id: id("peer.gamma"),
            expected_authority_revision: host.snapshot().peer_mesh.authority_revision,
        })
        .expect("explicit three-to-two transition");
    assert!(mesh_mutation.applied);
    assert!(!mesh_mutation.mesh_active);
    assert!(host.snapshot().peer_mesh.members.is_empty());
    assert!(
        host.validate_pair_media_route(&expiring_grant, 4_200)
            .current
    );

    let expiry = host
        .expire_pair_media_routes(
            id("sweep.pair-route.expiry.001"),
            host.snapshot().pair_media_routes.authority_revision,
            5_000,
        )
        .expect("pair route expiry");
    assert!(expiry.applied);
    assert!(
        !host
            .validate_pair_media_route(&expiring_grant, 5_000)
            .current
    );

    let revocable = pair_route_request(
        &host,
        "request.pair-route.revocable.001",
        "runtime.request.pair-route.revocable.001",
        "leg.revocable.alpha-beta",
        1,
        "peer.alpha",
        "peer.beta",
        "session.peer.host.001",
        media_decision_id,
        20_000,
    );
    let revocable_receipt = issue_pair_route(&mut host, &revocable, 5_100);
    let revocable_grant = revocable_receipt
        .accepted_route
        .expect("revocable route")
        .grant_id;
    let revoke = ManifoldPairMediaRouteTerminationRequest {
        schema_id: schema_id(PAIR_MEDIA_ROUTE_TERMINATION_REQUEST_SCHEMA),
        request_id: id("request.pair-route.revoke.001"),
        expected_authority_revision: host.snapshot().pair_media_routes.authority_revision,
        runtime_command_request_id: id("runtime.request.pair-route.revoke.001"),
        grant_id: revocable_grant.clone(),
        action: ManifoldPairMediaRouteTerminationAction::Revoke,
    };
    let revoke_command = media_command(
        &host,
        revoke.runtime_command_request_id.clone(),
        PAIR_MEDIA_ROUTE_REVOKE_COMMAND,
        pair_media_route_termination_params_digest(&revoke).expect("revoke params"),
        "operator.media-revoker",
        "lease.runtime.media-revoker",
        5_200,
    );
    let revoked = host
        .review_pair_media_route_termination(&revoke, &revoke_command, 5_200)
        .expect("revoke route");
    assert!(revoked.applied, "{revoked:?}");
    assert_eq!(
        host.snapshot()
            .pair_media_routes
            .routes
            .iter()
            .find(|route| route.grant_id() == &revocable_grant)
            .expect("revoked retained route")
            .lifecycle_status(),
        &ManifoldPairMediaRouteLifecycleStatus::Revoked
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn pair_route_teardown_remains_reachable_after_its_source_authority_ends() {
    let (mut stopped_host, stopped_media_id) = pair_host_without_mesh();
    let stopped_grant = issue_lifecycle_pair_route(
        &mut stopped_host,
        stopped_media_id.clone(),
        "media-stop",
        20_000,
    );
    let media_stop = ManifoldMediaSessionTerminationRequest {
        schema_id: schema_id(MANIFOLD_MEDIA_SESSION_TERMINATION_REQUEST_SCHEMA),
        request_id: id("request.media.source-end.stop"),
        expected_authority_revision: stopped_host.snapshot().media_sessions.authority_revision,
        runtime_command_request_id: id("runtime.request.media.source-end.stop"),
        decision_id: stopped_media_id,
        session_id: id("session.media.quest-pair.001"),
        expected_provider_epoch_id: id(PROVIDER_EPOCH_ID),
        action: ManifoldMediaSessionTerminationAction::Stop,
    };
    let media_stop_command = media_command(
        &stopped_host,
        media_stop.runtime_command_request_id.clone(),
        MANIFOLD_MEDIA_SESSION_STOP_COMMAND,
        media_session_termination_params_digest(&media_stop).expect("media stop params"),
        TRUSTED_MEDIA_PROPOSER_ID,
        "lease.runtime.media-test",
        4_200,
    );
    assert!(
        stopped_host
            .review_media_session_termination(&media_stop, &media_stop_command, 4_200)
            .expect("source media stop")
            .applied
    );
    finish_pair_route_after_source_end(
        &mut stopped_host,
        stopped_grant,
        "media-stop",
        4_300,
        false,
    );

    let (mut superseded_host, superseded_media_id) = pair_host_without_mesh();
    let superseded_grant = issue_lifecycle_pair_route(
        &mut superseded_host,
        superseded_media_id,
        "media-supersession",
        20_000,
    );
    let replacement = media_acceptance_request(
        &superseded_host,
        "request.media.source-end.supersession",
        7,
        PROVIDER_EPOCH_ID,
    );
    let replacement_command = media_accept_command(&superseded_host, &replacement);
    assert!(
        superseded_host
            .review_media_session_acceptance(&replacement, &replacement_command, 4_200)
            .expect("source media supersession")
            .accepted
    );
    finish_pair_route_after_source_end(
        &mut superseded_host,
        superseded_grant,
        "media-supersession",
        4_300,
        false,
    );

    let (mut expired_host, expired_media_id) = pair_host_without_mesh();
    let expired_grant =
        issue_lifecycle_pair_route(&mut expired_host, expired_media_id, "media-expiry", 60_000);
    assert!(
        expired_host
            .expire_media_sessions(
                id("sweep.media.source-end.expiry"),
                expired_host.snapshot().media_sessions.authority_revision,
                60_000,
            )
            .expect("source media expiry")
            .applied
    );
    finish_pair_route_after_source_end(
        &mut expired_host,
        expired_grant,
        "media-expiry",
        60_000,
        true,
    );

    let (mut revoked_peer_host, revoked_peer_media_id) = pair_host_without_mesh();
    let revoked_peer_grant = issue_lifecycle_pair_route(
        &mut revoked_peer_host,
        revoked_peer_media_id,
        "peer-revocation",
        20_000,
    );
    revoked_peer_host
        .revoke_peer_session(
            &ManifoldPeerSessionRevocation {
                schema_id: schema_id(PEER_SESSION_REVOCATION_SCHEMA),
                revocation_id: id("request.peer-session.source-end.revoke"),
                session_id: id("session.peer.pair-only.001"),
                expected_authority_revision: revoked_peer_host
                    .snapshot()
                    .peer_sessions
                    .authority_revision,
            },
            4_200,
        )
        .expect("source peer-session revocation");
    assert_eq!(
        revoked_peer_host
            .snapshot()
            .signed_topology_authorizations
            .len(),
        1,
        "accepted topology remains immutable route provenance after session revocation"
    );
    finish_pair_route_after_source_end(
        &mut revoked_peer_host,
        revoked_peer_grant,
        "peer-revocation",
        4_300,
        false,
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn pair_route_caps_expiry_at_runtime_lease_and_rejects_broker_command_leases() {
    let (mut host, media_decision_id) = pair_host_without_mesh();
    host.snapshot
        .media_command_runtime
        .leases
        .iter_mut()
        .find(|lease| lease.lease_id == id("lease.runtime.media-test"))
        .expect("media lease")
        .expires_at_ms = 6_000;
    let boundary = pair_route_request(
        &host,
        "request.pair-route.lease-boundary",
        "runtime.request.pair-route.lease-boundary",
        "leg.lease-boundary",
        1,
        "peer.alpha",
        "peer.beta",
        "session.peer.pair-only.001",
        media_decision_id.clone(),
        6_000,
    );
    let boundary_receipt = issue_pair_route(&mut host, &boundary, 4_100);
    assert!(boundary_receipt.accepted, "{boundary_receipt:?}");
    let grant_id = boundary_receipt
        .accepted_route
        .expect("boundary route")
        .grant_id;
    let one_past = pair_route_request(
        &host,
        "request.pair-route.lease-one-past",
        "runtime.request.pair-route.lease-one-past",
        "leg.lease-one-past",
        1,
        "peer.alpha",
        "peer.beta",
        "session.peer.pair-only.001",
        media_decision_id.clone(),
        6_001,
    );
    let one_past_receipt = issue_pair_route(&mut host, &one_past, 4_200);
    assert_eq!(
        one_past_receipt.rejection_reason,
        Some(rusty_manifold_peer::ManifoldPairMediaRouteRejectionReason::InvalidExpiry)
    );

    let broker_command_lease = ManifoldRuntimeLease {
        lease_id: id("lease.runtime.synthetic-broker-command"),
        scope: id(MEDIA_RUNTIME_LEASE_SCOPE_ID),
        holder_id: id(TRUSTED_MEDIA_PROPOSER_ID),
        expires_at_ms: 100_000,
        derivative_binding: Some(broker_runtime_derivative_binding(
            &id(PROVIDER_EPOCH_ID),
            &id("lease.runtime.synthetic-upstream"),
            &id("authorization.synthetic-broker-command"),
        )),
    };
    host.snapshot
        .media_command_runtime
        .leases
        .push(broker_command_lease.clone());
    host.snapshot
        .media_command_runtime
        .leases
        .sort_by(|a, b| a.lease_id.cmp(&b.lease_id));
    let blocked_stop = ManifoldPairMediaRouteTerminationRequest {
        schema_id: schema_id(PAIR_MEDIA_ROUTE_TERMINATION_REQUEST_SCHEMA),
        request_id: id("request.pair-route.blocked-broker-stop"),
        expected_authority_revision: host.snapshot().pair_media_routes.authority_revision,
        runtime_command_request_id: id("runtime.request.pair-route.blocked-broker-stop"),
        grant_id: grant_id.clone(),
        action: ManifoldPairMediaRouteTerminationAction::Stop,
    };
    let blocked_stop_command = media_command(
        &host,
        blocked_stop.runtime_command_request_id.clone(),
        PAIR_MEDIA_ROUTE_STOP_COMMAND,
        pair_media_route_termination_params_digest(&blocked_stop).expect("stop params"),
        TRUSTED_MEDIA_PROPOSER_ID,
        broker_command_lease.lease_id.as_str(),
        4_300,
    );
    assert!(host
        .review_pair_media_route_termination(&blocked_stop, &blocked_stop_command, 4_300)
        .is_err());
    assert!(host.validate_pair_media_route(&grant_id, 4_301).current);
    host.snapshot
        .media_command_runtime
        .leases
        .retain(|lease| lease.lease_id != broker_command_lease.lease_id);

    let stop = ManifoldPairMediaRouteTerminationRequest {
        schema_id: schema_id(PAIR_MEDIA_ROUTE_TERMINATION_REQUEST_SCHEMA),
        request_id: id("request.pair-route.allowed-stop"),
        expected_authority_revision: host.snapshot().pair_media_routes.authority_revision,
        runtime_command_request_id: id("runtime.request.pair-route.allowed-stop"),
        grant_id: grant_id.clone(),
        action: ManifoldPairMediaRouteTerminationAction::Stop,
    };
    let stop_command = media_command(
        &host,
        stop.runtime_command_request_id.clone(),
        PAIR_MEDIA_ROUTE_STOP_COMMAND,
        pair_media_route_termination_params_digest(&stop).expect("stop params"),
        TRUSTED_MEDIA_PROPOSER_ID,
        "lease.runtime.media-test",
        4_400,
    );
    assert!(
        host.review_pair_media_route_termination(&stop, &stop_command, 4_400)
            .expect("ordinary stop")
            .applied
    );
    host.snapshot
        .media_command_runtime
        .leases
        .push(broker_command_lease.clone());
    host.snapshot
        .media_command_runtime
        .leases
        .sort_by(|a, b| a.lease_id.cmp(&b.lease_id));
    let blocked_cleanup = ManifoldPairMediaRouteCleanupCompletionRequest {
        schema_id: schema_id(PAIR_MEDIA_ROUTE_CLEANUP_REQUEST_SCHEMA),
        request_id: id("request.pair-route.blocked-broker-cleanup"),
        expected_authority_revision: host.snapshot().pair_media_routes.authority_revision,
        runtime_command_request_id: id("runtime.request.pair-route.blocked-broker-cleanup"),
        grant_id: grant_id.clone(),
        effect_receipt_id: id("effect.blocked-broker-cleanup"),
        effect_receipt_sha256: format!("sha256:{}", "91".repeat(32)),
    };
    let blocked_cleanup_command = media_command(
        &host,
        blocked_cleanup.runtime_command_request_id.clone(),
        PAIR_MEDIA_ROUTE_CLEANUP_COMMAND,
        pair_media_route_cleanup_params_digest(&blocked_cleanup).expect("cleanup params"),
        TRUSTED_MEDIA_PROPOSER_ID,
        broker_command_lease.lease_id.as_str(),
        4_500,
    );
    assert!(host
        .complete_pair_media_route_cleanup(&blocked_cleanup, &blocked_cleanup_command, 4_500)
        .is_err());
    assert_eq!(
        host.snapshot()
            .pair_media_routes
            .routes
            .iter()
            .find(|route| route.grant_id() == &grant_id)
            .expect("pending route")
            .cleanup_status(),
        &ManifoldPairMediaRouteCleanupStatus::Pending
    );
    host.snapshot
        .media_command_runtime
        .leases
        .retain(|lease| lease.lease_id != broker_command_lease.lease_id);

    let expiring = pair_route_request(
        &host,
        "request.pair-route.expiry-at-client-lease",
        "runtime.request.pair-route.expiry-at-client-lease",
        "leg.expiry-at-client-lease",
        1,
        "peer.alpha",
        "peer.beta",
        "session.peer.pair-only.001",
        media_decision_id,
        6_000,
    );
    let expiring_grant = issue_pair_route(&mut host, &expiring, 4_600)
        .accepted_route
        .expect("route capped at client lease")
        .grant_id;
    host.expire_pair_media_routes(
        id("sweep.pair-route.client-lease-boundary"),
        host.snapshot().pair_media_routes.authority_revision,
        6_000,
    )
    .expect("expire at exact original client lease deadline");

    let cleanup_request = |host: &ManifoldPeerRuntimeHost, suffix: &str| {
        ManifoldPairMediaRouteCleanupCompletionRequest {
            schema_id: schema_id(PAIR_MEDIA_ROUTE_CLEANUP_REQUEST_SCHEMA),
            request_id: id(&format!("request.pair-route.expired-cleanup.{suffix}")),
            expected_authority_revision: host.snapshot().pair_media_routes.authority_revision,
            runtime_command_request_id: id(&format!(
                "runtime.request.pair-route.expired-cleanup.{suffix}"
            )),
            grant_id: expiring_grant.clone(),
            effect_receipt_id: id(&format!("effect.expired-cleanup.{suffix}")),
            effect_receipt_sha256: format!("sha256:{}", "92".repeat(32)),
        }
    };
    let untrusted = cleanup_request(&host, "untrusted");
    let untrusted_command = media_command(
        &host,
        untrusted.runtime_command_request_id.clone(),
        PAIR_MEDIA_ROUTE_CLEANUP_COMMAND,
        pair_media_route_cleanup_params_digest(&untrusted).expect("cleanup params"),
        "client.untrusted",
        "lease.runtime.media-test",
        6_001,
    );
    assert!(host
        .complete_pair_media_route_cleanup(&untrusted, &untrusted_command, 6_001)
        .is_err());
    let wrong_scope = cleanup_request(&host, "wrong-scope");
    let wrong_scope_command = media_command(
        &host,
        wrong_scope.runtime_command_request_id.clone(),
        PAIR_MEDIA_ROUTE_CLEANUP_COMMAND,
        pair_media_route_cleanup_params_digest(&wrong_scope).expect("cleanup params"),
        TRUSTED_MEDIA_PROPOSER_ID,
        "lease.runtime.direct-lane-test",
        6_002,
    );
    assert!(host
        .complete_pair_media_route_cleanup(&wrong_scope, &wrong_scope_command, 6_002)
        .is_err());
    let operator_cleanup = cleanup_request(&host, "trusted-operator");
    let operator_command = media_command(
        &host,
        operator_cleanup.runtime_command_request_id.clone(),
        PAIR_MEDIA_ROUTE_CLEANUP_COMMAND,
        pair_media_route_cleanup_params_digest(&operator_cleanup).expect("cleanup params"),
        "operator.media-revoker",
        "lease.runtime.media-revoker",
        6_003,
    );
    host.complete_pair_media_route_cleanup(&operator_cleanup, &operator_command, 6_003)
        .expect("trusted operator closes delayed cleanup");
    ManifoldPeerRuntimeHost::from_snapshot(
        host.snapshot().clone(),
        &host.snapshot().trust_policy,
        &host.snapshot().provider_epoch_id,
    )
    .expect("operator cleanup restores");
}

#[test]
#[allow(clippy::too_many_lines)]
fn pair_route_reserves_capacity_and_revisions_for_terminal_cleanup() {
    let (mut host, media_decision_id) = pair_host_without_mesh();
    host.snapshot.pair_media_routes.applied_request_ids = (0..MAX_PAIR_MEDIA_ROUTE_REQUEST_IDS - 3)
        .map(|index| id(&format!("request.reserved.{index:04}")))
        .collect();
    host.snapshot.pair_media_routes.last_observed_at_ms = Some(4_000);
    let seed_audit = host
        .snapshot
        .audit_events
        .last()
        .cloned()
        .expect("host fixture has audit evidence");
    host.snapshot
        .audit_events
        .resize(MAX_PEER_RUNTIME_HOST_EVENTS - 4, seed_audit);
    host.snapshot.event_sequence =
        u64::try_from(host.snapshot.audit_events.len()).expect("bounded host audit length");

    let last_safe = pair_route_request(
        &host,
        "request.zzz.last-safe-route",
        "runtime.request.zzz.last-safe-route",
        "leg.capacity.alpha-beta",
        1,
        "peer.alpha",
        "peer.beta",
        "session.peer.pair-only.001",
        media_decision_id.clone(),
        20_000,
    );
    let last_safe_receipt = issue_pair_route(&mut host, &last_safe, 4_100);
    assert!(last_safe_receipt.accepted, "{last_safe_receipt:?}");
    let grant_id = last_safe_receipt
        .accepted_route
        .expect("last safe route")
        .grant_id;

    let stranded = pair_route_request(
        &host,
        "request.zzz.stranded-route",
        "runtime.request.zzz.stranded-route",
        "leg.capacity.second",
        1,
        "peer.alpha",
        "peer.beta",
        "session.peer.pair-only.001",
        media_decision_id,
        20_000,
    );
    let stranded_receipt = issue_pair_route(&mut host, &stranded, 4_200);
    assert_eq!(
        stranded_receipt.rejection_reason,
        Some(rusty_manifold_peer::ManifoldPairMediaRouteRejectionReason::CapacityExceeded)
    );

    let stop = ManifoldPairMediaRouteTerminationRequest {
        schema_id: schema_id(PAIR_MEDIA_ROUTE_TERMINATION_REQUEST_SCHEMA),
        request_id: id("request.zzz.last-safe-stop"),
        expected_authority_revision: host.snapshot().pair_media_routes.authority_revision,
        runtime_command_request_id: id("runtime.request.zzz.last-safe-stop"),
        grant_id: grant_id.clone(),
        action: ManifoldPairMediaRouteTerminationAction::Stop,
    };
    let stop_command = media_command(
        &host,
        stop.runtime_command_request_id.clone(),
        PAIR_MEDIA_ROUTE_STOP_COMMAND,
        pair_media_route_termination_params_digest(&stop).expect("stop params"),
        TRUSTED_MEDIA_PROPOSER_ID,
        "lease.runtime.media-test",
        4_300,
    );
    assert!(
        host.review_pair_media_route_termination(&stop, &stop_command, 4_300)
            .expect("reserved stop slot")
            .applied
    );
    let cleanup = ManifoldPairMediaRouteCleanupCompletionRequest {
        schema_id: schema_id(PAIR_MEDIA_ROUTE_CLEANUP_REQUEST_SCHEMA),
        request_id: id("request.zzz.last-safe-cleanup"),
        expected_authority_revision: host.snapshot().pair_media_routes.authority_revision,
        runtime_command_request_id: id("runtime.request.zzz.last-safe-cleanup"),
        grant_id,
        effect_receipt_id: id("effect.capacity.cleanup"),
        effect_receipt_sha256: format!("sha256:{}", "73".repeat(32)),
    };
    let cleanup_command = media_command(
        &host,
        cleanup.runtime_command_request_id.clone(),
        PAIR_MEDIA_ROUTE_CLEANUP_COMMAND,
        pair_media_route_cleanup_params_digest(&cleanup).expect("cleanup params"),
        TRUSTED_MEDIA_PROPOSER_ID,
        "lease.runtime.media-test",
        4_400,
    );
    host.complete_pair_media_route_cleanup(&cleanup, &cleanup_command, 4_400)
        .expect("reserved cleanup slot");
    assert_eq!(
        host.snapshot().pair_media_routes.applied_request_ids.len(),
        MAX_PAIR_MEDIA_ROUTE_REQUEST_IDS
    );
    assert_eq!(
        host.snapshot().audit_events.len(),
        MAX_PEER_RUNTIME_HOST_EVENTS
    );

    let (mut revision_host, media_decision_id) = pair_host_without_mesh();
    revision_host.snapshot.pair_media_routes.authority_revision =
        Revision::new(u64::MAX - 2).expect("near-terminal revision");
    let revision_limited = pair_route_request(
        &revision_host,
        "request.route.revision-cap",
        "runtime.request.route.revision-cap",
        "leg.revision.alpha-beta",
        1,
        "peer.alpha",
        "peer.beta",
        "session.peer.pair-only.001",
        media_decision_id,
        20_000,
    );
    let receipt = issue_pair_route(&mut revision_host, &revision_limited, 4_100);
    assert_eq!(
        receipt.rejection_reason,
        Some(rusty_manifold_peer::ManifoldPairMediaRouteRejectionReason::RevisionExhausted)
    );
    assert!(revision_host.snapshot().pair_media_routes.routes.is_empty());
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
    wifi_topology_mut(&mut damaged.signed_topology_authorizations[0]).rendezvous_receipt_id =
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
#[allow(clippy::too_many_lines)]
fn released_v1_snapshot_migrates_explicitly_without_synthesizing_convergence() {
    let host = fixture_host();
    let mut legacy = serde_json::to_value(host.snapshot()).expect("snapshot value");
    convert_current_snapshot_value_to_legacy(&mut legacy);
    let object = legacy.as_object_mut().expect("snapshot object");
    object.insert(
        "$schema".to_owned(),
        serde_json::Value::String(LEGACY_PEER_RUNTIME_HOST_SNAPSHOT_V1_SCHEMA.to_owned()),
    );
    object.remove("broker_lease_revocation_convergences");
    object.remove("broker_lease_revocation_cleanup_completions");
    object.remove("broker_epoch_rollovers");
    object.remove("pair_media_routes");
    legacy["media_command_runtime"]["commands"]
        .as_array_mut()
        .expect("legacy Runtime Host commands")
        .retain(|command| {
            !command["command_id"]
                .as_str()
                .is_some_and(|id| id.contains("pair_media_route"))
        });
    legacy["media_command_runtime"]["$schema"] =
        serde_json::Value::String(LEGACY_HOST_SNAPSHOT_V3_SCHEMA.to_owned());
    legacy["media_command_runtime"]
        .as_object_mut()
        .expect("embedded Runtime Host")
        .remove("reviewed_derivative_lease_revocation_ids");
    for event in legacy["media_command_runtime"]["audit_events"]
        .as_array_mut()
        .expect("embedded Runtime Host audit")
    {
        event["$schema"] = serde_json::Value::String(LEGACY_HOST_AUDIT_EVENT_V3_SCHEMA.to_owned());
        event
            .as_object_mut()
            .expect("Runtime Host audit event")
            .remove("derivative_lease_revocation");
    }
    let legacy_json = serde_json::to_string_pretty(&legacy).expect("legacy snapshot JSON");
    let (migrated, receipt) = ManifoldPeerRuntimeHost::restart_from_json_with_migration(
        &legacy_json,
        &host.snapshot().trust_policy,
        &host.snapshot().provider_epoch_id,
    )
    .expect("explicit v1 migration");
    assert!(receipt.migrated);
    assert_eq!(
        receipt.source_schema_id.as_str(),
        LEGACY_PEER_RUNTIME_HOST_SNAPSHOT_V1_SCHEMA
    );
    assert_eq!(
        receipt.resulting_schema_id.as_str(),
        PEER_RUNTIME_HOST_SNAPSHOT_SCHEMA
    );
    assert_eq!(
        receipt.preserved_event_sequence,
        host.snapshot().event_sequence
    );
    assert!(migrated
        .snapshot()
        .broker_lease_revocation_convergences
        .is_empty());
    let mut expected = host.snapshot().clone();
    expected.schema_id = schema_id(PEER_RUNTIME_HOST_SNAPSHOT_SCHEMA);
    remove_pair_route_commands(&mut expected.media_command_runtime);
    expected.pair_media_routes = ManifoldPairMediaRouteAuthorityStateV2::empty();
    assert_eq!(migrated.snapshot(), &expected);

    let (_, current_receipt) = ManifoldPeerRuntimeHost::restart_from_json_with_migration(
        &migrated.snapshot_json().expect("current snapshot JSON"),
        &host.snapshot().trust_policy,
        &host.snapshot().provider_epoch_id,
    )
    .expect("current snapshot restart");
    assert!(!current_receipt.migrated);

    let mut legacy_v2 = serde_json::to_value(host.snapshot()).expect("snapshot value");
    convert_current_snapshot_value_to_legacy(&mut legacy_v2);
    let object = legacy_v2.as_object_mut().expect("snapshot object");
    object.insert(
        "$schema".to_owned(),
        serde_json::Value::String(LEGACY_PEER_RUNTIME_HOST_SNAPSHOT_V2_SCHEMA.to_owned()),
    );
    object.remove("broker_epoch_rollovers");
    object.remove("pair_media_routes");
    legacy_v2["media_command_runtime"]["commands"]
        .as_array_mut()
        .expect("legacy Runtime Host commands")
        .retain(|command| {
            !command["command_id"]
                .as_str()
                .is_some_and(|id| id.contains("pair_media_route"))
        });
    let legacy_v2_json = serde_json::to_string_pretty(&legacy_v2).expect("legacy v2 snapshot JSON");
    let (migrated_v2, receipt_v2) = ManifoldPeerRuntimeHost::restart_from_json_with_migration(
        &legacy_v2_json,
        &host.snapshot().trust_policy,
        &host.snapshot().provider_epoch_id,
    )
    .expect("explicit v2 migration");
    assert!(receipt_v2.migrated);
    assert_eq!(
        receipt_v2.source_schema_id.as_str(),
        LEGACY_PEER_RUNTIME_HOST_SNAPSHOT_V2_SCHEMA
    );
    assert!(migrated_v2.snapshot().broker_epoch_rollovers.is_empty());
    assert_eq!(migrated_v2.snapshot(), &expected);

    let mut legacy_v3 = serde_json::to_value(host.snapshot()).expect("snapshot value");
    convert_current_snapshot_value_to_legacy(&mut legacy_v3);
    let object = legacy_v3.as_object_mut().expect("snapshot object");
    object.insert(
        "$schema".to_owned(),
        serde_json::Value::String(LEGACY_PEER_RUNTIME_HOST_SNAPSHOT_V3_SCHEMA.to_owned()),
    );
    object.remove("pair_media_routes");
    let smuggled_v3_json =
        serde_json::to_string_pretty(&legacy_v3).expect("legacy v3 smuggled snapshot JSON");
    assert!(matches!(
        ManifoldPeerRuntimeHost::restart_from_json_with_migration(
            &smuggled_v3_json,
            &host.snapshot().trust_policy,
            &host.snapshot().provider_epoch_id,
        ),
        Err(ManifoldPeerRuntimeHostError::InvalidSnapshot(_))
    ));
    legacy_v3["media_command_runtime"]["commands"]
        .as_array_mut()
        .expect("legacy Runtime Host commands")
        .retain(|command| {
            !command["command_id"]
                .as_str()
                .is_some_and(|id| id.contains("pair_media_route"))
        });
    let legacy_v3_json = serde_json::to_string_pretty(&legacy_v3).expect("legacy v3 snapshot JSON");
    let (migrated_v3, receipt_v3) = ManifoldPeerRuntimeHost::restart_from_json_with_migration(
        &legacy_v3_json,
        &host.snapshot().trust_policy,
        &host.snapshot().provider_epoch_id,
    )
    .expect("explicit v3 migration");
    assert!(receipt_v3.migrated);
    assert_eq!(
        receipt_v3.source_schema_id.as_str(),
        LEGACY_PEER_RUNTIME_HOST_SNAPSHOT_V3_SCHEMA
    );
    assert!(migrated_v3.snapshot().pair_media_routes.routes.is_empty());
    assert_eq!(migrated_v3.snapshot(), &expected);
}

#[test]
fn legacy_v3_migration_preserves_commands_and_does_not_enable_pair_routes() {
    let (host, media_decision_id) = pair_host_without_mesh();
    let mut legacy = host.snapshot().clone();
    legacy.schema_id = schema_id(LEGACY_PEER_RUNTIME_HOST_SNAPSHOT_V3_SCHEMA);
    remove_pair_route_commands(&mut legacy.media_command_runtime);
    let expected_commands = legacy.media_command_runtime.commands.clone();
    let mut value = serde_json::to_value(&legacy).expect("legacy v3 value");
    convert_current_snapshot_value_to_legacy(&mut value);
    value
        .as_object_mut()
        .expect("legacy v3 object")
        .remove("pair_media_routes");
    let json = serde_json::to_string_pretty(&value).expect("legacy v3 JSON");
    let (mut migrated, receipt) = ManifoldPeerRuntimeHost::restart_from_json_with_migration(
        &json,
        &host.snapshot().trust_policy,
        &host.snapshot().provider_epoch_id,
    )
    .expect("legacy v3 migration");
    assert!(receipt.migrated);
    assert_eq!(
        migrated.snapshot().media_command_runtime.commands,
        expected_commands
    );
    assert_eq!(
        migrated.snapshot().pair_media_routes,
        ManifoldPairMediaRouteAuthorityStateV2::empty()
    );

    let request = pair_route_request(
        &migrated,
        "request.pair-route.migrated-disabled.001",
        "runtime.request.pair-route.migrated-disabled.001",
        "leg.migrated-disabled.alpha-beta",
        1,
        "peer.alpha",
        "peer.beta",
        "session.peer.pair-only.001",
        media_decision_id,
        20_000,
    );
    let command = media_command(
        &migrated,
        request.runtime_command_request_id.clone(),
        PAIR_MEDIA_ROUTE_ISSUE_COMMAND,
        pair_media_route_issue_params_digest(&request).expect("pair params"),
        TRUSTED_MEDIA_PROPOSER_ID,
        "lease.runtime.media-test",
        4_100,
    );
    let denied = migrated
        .review_pair_media_route(&request, &command, 4_100)
        .expect("disabled pair command yields a closed receipt");
    assert_eq!(
        denied.rejection_reason,
        Some(rusty_manifold_peer::ManifoldPairMediaRouteRejectionReason::RuntimeCommandNotAccepted)
    );
    assert!(migrated.snapshot().pair_media_routes.routes.is_empty());
}

#[test]
#[allow(clippy::too_many_lines)]
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

    let mut pair_disabled_runtime = media_command_runtime();
    remove_pair_route_commands(&mut pair_disabled_runtime);
    ManifoldPeerRuntimeHost::new(
        id("host.peer-runtime.pair-disabled-v4"),
        trust_policy(),
        id(PROVIDER_EPOCH_ID),
        pair_disabled_runtime,
    )
    .expect("explicit v4 may omit the complete pair command bundle");

    let mut partial_pair_bundle = media_command_runtime();
    partial_pair_bundle
        .commands
        .retain(|command| command.command_id.as_str() != PAIR_MEDIA_ROUTE_CLEANUP_COMMAND);
    assert!(ManifoldPeerRuntimeHost::new(
        id("host.peer-runtime.partial-pair-bundle"),
        trust_policy(),
        id(PROVIDER_EPOCH_ID),
        partial_pair_bundle,
    )
    .is_err());

    let mut wrong_pair_scope = media_command_runtime();
    wrong_pair_scope
        .commands
        .iter_mut()
        .find(|command| command.command_id.as_str() == PAIR_MEDIA_ROUTE_STOP_COMMAND)
        .expect("pair stop command")
        .required_lease_scope = Some(id("lease.scope.wrong"));
    assert!(ManifoldPeerRuntimeHost::new(
        id("host.peer-runtime.wrong-pair-scope"),
        trust_policy(),
        id(PROVIDER_EPOCH_ID),
        wrong_pair_scope,
    )
    .is_err());

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
fn live_broker_mutation_consumes_once_mints_releases_and_restores_media_lease() {
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
    let (ready, _, _) = ready_host();
    let mut dynamic_snapshot = ready.snapshot().clone();
    dynamic_snapshot.trust_policy = policy.clone();
    dynamic_snapshot
        .media_command_runtime
        .leases
        .retain(|lease| lease.scope.as_str() != MEDIA_RUNTIME_LEASE_SCOPE_ID);
    dynamic_snapshot
        .media_command_runtime
        .leases
        .push(ManifoldRuntimeLease {
            lease_id: id("lease.runtime.media-revoker"),
            scope: id(MEDIA_RUNTIME_LEASE_SCOPE_ID),
            holder_id: id("operator.media-revoker"),
            expires_at_ms: 2_000_000_000_000,
            derivative_binding: None,
        });
    let mut host =
        ManifoldPeerRuntimeHost::from_snapshot(dynamic_snapshot, &policy, &id(PROVIDER_EPOCH_ID))
            .expect("peer host without ambient media lease");

    let broker_lease = ManifoldRuntimeLease {
        lease_id: grant.broker_runtime_lease_id.clone(),
        scope: id("lease.media.session"),
        holder_id: grant.client_id.clone(),
        expires_at_ms: 100_000,
        derivative_binding: None,
    };
    let control_lease_authority = broker_control_lease_authority(&broker_lease);
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
        &control_lease_authority,
    )
    .expect("outer broker adapter");
    let outer_capability = command_capability(&grant.broker_command_id);
    let revoke_capability = control_lease_lifecycle_capability(
        ManifoldBrokerControlLeaseLifecycleOperationKind::Revocation,
    );
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
            capabilities: vec![outer_capability.clone(), revoke_capability],
            expires_at_ms: 2_000_000_000_000,
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
    let fresh_admission_snapshot = admission_snapshot.clone();
    let second_fresh_admission_snapshot = admission_snapshot.clone();
    let mut broker = ManifoldBrokerRuntime::new(
        id(PROVIDER_EPOCH_ID),
        broker_adapter,
        control_lease_authority,
        admission_snapshot,
    )
    .expect("outer broker runtime");
    let rejected_after_admission =
        broker_media_mutation(&mut broker, &grant, "consume-rejected", 29, 2_000);

    let mut rejected = rejected_after_admission.clone();
    rejected.command.command_id = id("command.media.session.stop");
    let unchanged_host = host.clone();
    let unchanged_broker = broker.evidence();
    assert!(host
        .apply_broker_media_command_and_admit_runtime_lease(&mut broker, &rejected, 4_000)
        .is_err());
    assert_eq!(host, unchanged_host);
    assert_eq!(broker.evidence(), unchanged_broker);

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
    let consumed_broker = broker.evidence();
    assert!(host
        .apply_broker_media_command_and_admit_runtime_lease(
            &mut broker,
            &rejected_after_admission,
            3_100,
        )
        .is_err());
    assert_eq!(host, consumed_host);
    assert_eq!(broker.evidence(), consumed_broker);

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
    let derivative_binding = admission
        .runtime_lease
        .derivative_binding
        .as_ref()
        .expect("accepted derivative binding");
    assert_eq!(derivative_binding.provider_epoch_id, id(PROVIDER_EPOCH_ID));
    assert_eq!(
        derivative_binding.upstream_control_lease_id,
        grant.broker_runtime_lease_id
    );
    assert_eq!(
        derivative_binding.source_authorization_id,
        mutation.admission_use_request_id
    );
    let mut substituted_binding = host.snapshot().clone();
    substituted_binding
        .media_command_runtime
        .leases
        .iter_mut()
        .find(|lease| lease.lease_id == grant.lease_id)
        .expect("live derivative lease")
        .derivative_binding
        .as_mut()
        .expect("live derivative binding")
        .upstream_control_lease_id = id("lease.outer.substituted");
    substituted_binding.broker_lease_admissions[0]
        .runtime_lease
        .derivative_binding
        .as_mut()
        .expect("retained derivative binding")
        .upstream_control_lease_id = id("lease.outer.substituted");
    assert!(ManifoldPeerRuntimeHost::from_snapshot(
        substituted_binding,
        &policy,
        &id(PROVIDER_EPOCH_ID),
    )
    .is_err());
    let mut legacy_active_admission =
        serde_json::to_value(host.snapshot()).expect("active peer snapshot");
    convert_current_snapshot_value_to_legacy(&mut legacy_active_admission);
    legacy_active_admission["$schema"] =
        serde_json::Value::String(LEGACY_PEER_RUNTIME_HOST_SNAPSHOT_V1_SCHEMA.to_owned());
    let legacy_object = legacy_active_admission
        .as_object_mut()
        .expect("legacy peer object");
    legacy_object.remove("broker_lease_revocation_convergences");
    legacy_object.remove("broker_lease_revocation_cleanup_completions");
    legacy_object.remove("broker_epoch_rollovers");
    legacy_object.remove("pair_media_routes");
    legacy_active_admission["media_command_runtime"]["commands"]
        .as_array_mut()
        .expect("legacy Runtime Host commands")
        .retain(|command| {
            !command["command_id"]
                .as_str()
                .is_some_and(|id| id.contains("pair_media_route"))
        });
    legacy_active_admission["media_command_runtime"]["$schema"] =
        serde_json::Value::String(LEGACY_HOST_SNAPSHOT_V3_SCHEMA.to_owned());
    legacy_active_admission["media_command_runtime"]
        .as_object_mut()
        .expect("legacy embedded Runtime Host")
        .remove("reviewed_derivative_lease_revocation_ids");
    for lease in legacy_active_admission["media_command_runtime"]["leases"]
        .as_array_mut()
        .expect("legacy Runtime Host leases")
    {
        lease
            .as_object_mut()
            .expect("legacy Runtime Host lease")
            .remove("derivative_binding");
    }
    for event in legacy_active_admission["media_command_runtime"]["audit_events"]
        .as_array_mut()
        .expect("legacy Runtime Host audit")
    {
        event["$schema"] = serde_json::Value::String(LEGACY_HOST_AUDIT_EVENT_V3_SCHEMA.to_owned());
        event
            .as_object_mut()
            .expect("legacy Runtime Host audit event")
            .remove("derivative_lease_revocation");
    }
    for retained in legacy_active_admission["broker_lease_admissions"]
        .as_array_mut()
        .expect("legacy Broker admissions")
    {
        retained["runtime_lease"]
            .as_object_mut()
            .expect("legacy admitted lease")
            .remove("derivative_binding");
    }
    let legacy_active_admission =
        serde_json::to_string(&legacy_active_admission).expect("legacy active admission");
    let (migrated_active_admission, migration_receipt) =
        ManifoldPeerRuntimeHost::restart_from_json_with_live_broker_runtime(
            &legacy_active_admission,
            &policy,
            &id(PROVIDER_EPOCH_ID),
            &broker,
        )
        .expect("legacy active derivative binding backfill");
    assert!(migration_receipt.migrated);
    let mut expected_migrated = host.clone();
    remove_pair_route_commands(&mut expected_migrated.snapshot.media_command_runtime);
    expected_migrated.snapshot.pair_media_routes = ManifoldPairMediaRouteAuthorityStateV2::empty();
    assert_eq!(migrated_active_admission, expected_migrated);
    assert!(broker
        .evidence()
        .consumed_bounded_use_ids
        .contains(&mutation.admission_use_request_id));
    let committed_host = host.clone();
    let committed_broker = broker.evidence();
    assert!(matches!(
        host.apply_broker_media_command_and_admit_runtime_lease(&mut broker, &mutation, 4_100),
        Err(ManifoldPeerRuntimeHostError::ReplayedMutation(_))
    ));
    assert_eq!(host, committed_host);
    assert_eq!(broker.evidence(), committed_broker);

    let acceptance = media_acceptance_request(
        &host,
        "request.media.accept.dynamic.001",
        6,
        PROVIDER_EPOCH_ID,
    );
    let acceptance_command = media_accept_command(&host, &acceptance);
    let before_unjoined_acceptance = host.clone();
    assert!(host
        .review_media_session_acceptance(&acceptance, &acceptance_command, 4_250)
        .is_err());
    assert_eq!(host, before_unjoined_acceptance);
    let accepted = host
        .review_media_session_acceptance_with_live_broker_runtime(
            &broker,
            &acceptance,
            &acceptance_command,
            4_250,
        )
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
    let before_unjoined_termination = host.clone();
    assert!(host
        .review_media_session_termination(&termination, &termination_command, 4_300)
        .is_err());
    assert_eq!(host, before_unjoined_termination);
    assert!(
        host.review_media_session_termination_with_live_broker_runtime(
            &broker,
            &termination,
            &termination_command,
            4_300,
        )
        .expect("media stop")
        .applied
    );
    let before_unjoined_release = host.clone();
    assert!(host
        .release_media_runtime_lease(&grant.lease_id, id("request.media.dynamic.release"), 4_400,)
        .is_err());
    assert_eq!(host, before_unjoined_release);
    host.release_media_runtime_lease_with_live_broker_runtime(
        &broker,
        &grant.lease_id,
        id("request.media.dynamic.release"),
        4_400,
    )
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
    let second_accepted = host
        .review_media_session_acceptance_with_live_broker_runtime(
            &broker,
            &second_acceptance,
            &second_acceptance_command,
            4_800,
        )
        .expect("second media acceptance");
    assert!(second_accepted.accepted);
    let second_session = second_accepted
        .accepted_session
        .expect("second retained media session");
    let common_reciprocal_request = common_lan_reciprocal_request(&host, &key(7), &key(11));
    let common_reciprocal = match host
        .review_reciprocal_ed25519_v3(
            &ManifoldReciprocalEd25519ReviewRequestV3::CommonLan(common_reciprocal_request),
            4_801,
        )
        .expect("live Broker common-LAN reciprocal")
    {
        ManifoldReciprocalEd25519ReceiptV3::CommonLan(receipt) if receipt.accepted => receipt,
        other => panic!("live Broker common-LAN reciprocal rejected: {other:?}"),
    };
    let common_session_proposal = ManifoldCommonLanPeerSessionProposal {
        schema_id: schema_id(rusty_manifold_peer::COMMON_LAN_PEER_SESSION_PROPOSAL_SCHEMA),
        proposal_id: id("proposal.peer-session.dynamic-common-lan.001"),
        session_id: id("session.peer.dynamic-common-lan.001"),
        expected_authority_revision: host.snapshot().peer_sessions.authority_revision,
        subject_peer_id: id("peer.alpha"),
        candidate_peer_id: id("peer.beta"),
        initiator_peer_id: id("peer.alpha"),
        responder_peer_id: id("peer.beta"),
        requested_capability_ids: session_proposal(
            &host,
            "proposal.unused.dynamic-common-lan",
            "session.unused.dynamic-common-lan",
        )
        .requested_capability_ids,
        transport: common_lan_transport(),
        expires_at_ms: 60_000,
    };
    let (common_session_decision, _) = host
        .review_common_lan_peer_session(&common_session_proposal, &common_reciprocal, 4_802)
        .expect("live Broker common-LAN session");
    assert!(common_session_decision.applied);
    let pair_route_expires_at_ms = host
        .snapshot()
        .media_command_runtime
        .leases
        .iter()
        .find(|lease| lease.lease_id == grant.lease_id)
        .expect("second derivative lease")
        .expires_at_ms;
    let pair_route = ManifoldCommonLanPairMediaRouteRequest {
        request: pair_route_request(
            &host,
            "request.pair-route.dynamic-media.001",
            "runtime.request.pair-route.dynamic-media.001",
            "leg.dynamic-media.alpha-beta",
            1,
            "peer.alpha",
            "peer.beta",
            "session.peer.dynamic-common-lan.001",
            second_session.decision_id.clone(),
            pair_route_expires_at_ms,
        ),
        transport: common_lan_transport(),
    };
    let pair_route_command = media_command(
        &host,
        pair_route.request.runtime_command_request_id.clone(),
        PAIR_MEDIA_ROUTE_ISSUE_COMMAND,
        rusty_manifold_peer::pair_media_route_issue_params_digest_v2(&pair_route)
            .expect("dynamic common-LAN route params"),
        grant.client_id.as_str(),
        grant.lease_id.as_str(),
        4_850,
    );
    let before_unjoined_route = host.clone();
    assert!(host
        .review_pair_media_route_v2(
            &ManifoldPairMediaRouteRequestV2::CommonLan(pair_route.clone()),
            &pair_route_command,
            4_850,
        )
        .is_err());
    assert_eq!(host, before_unjoined_route);
    let pair_route_receipt = host
        .review_pair_media_route_v2_with_live_broker_runtime(
            &broker,
            &ManifoldPairMediaRouteRequestV2::CommonLan(pair_route),
            &pair_route_command,
            4_850,
        )
        .expect("live Broker pair-route issue");
    let pair_route_grant_id = match pair_route_receipt {
        ManifoldPairMediaRouteReceiptV2::CommonLan(receipt) => {
            let rejection = receipt.rejection_reason.clone();
            receipt
                .route
                .unwrap_or_else(|| panic!("live Broker common-LAN route rejected: {rejection:?}"))
                .grant_id
        }
        ManifoldPairMediaRouteReceiptV2::WifiDirect(_) => panic!("unexpected Wi-Fi receipt"),
    };
    let legacy_common_current = host.validate_pair_media_route(&pair_route_grant_id, 4_875);
    assert!(!legacy_common_current.current);
    assert_eq!(
        legacy_common_current.rejection_reason,
        Some(ManifoldPairMediaRouteRejectionReason::SchemaMismatch)
    );
    assert!(
        !host
            .validate_pair_media_route_v2(&pair_route_grant_id, 4_875)
            .current
    );
    assert!(
        host.validate_pair_media_route_v2_with_live_broker_runtime(
            &broker,
            &pair_route_grant_id,
            4_875,
        )
        .expect("live Broker pair-route current join")
        .current
    );
    let mut missing_admission = host.clone();
    missing_admission
        .snapshot
        .broker_lease_admissions
        .iter_mut()
        .find(|admission| {
            admission.runtime_lease.lease_id == grant.lease_id && admission.released_at_ms.is_none()
        })
        .expect("active derivative admission")
        .released_at_ms = Some(4_876);
    assert!(
        missing_admission
            .validate_pair_media_route_v2_with_live_broker_runtime(
                &broker,
                &pair_route_grant_id,
                4_876,
            )
            .is_err()
    );
    let mut media_lane = lease_request(
        &host,
        "request.direct-lane.dynamic-media.accepted",
        "session.peer.host.001",
    );
    media_lane.scope = ManifoldDirectLaneLeaseScope::MediaSession;
    media_lane.capability_id = id(DIRECT_LANE_MEDIA_SESSION_CAPABILITY);
    media_lane.expected_media_session_authority_revision =
        Some(second_session.session_authority_revision);
    media_lane.expected_media_acceptance_authority_revision =
        Some(host.snapshot().media_sessions.authority_revision);
    media_lane.media_session_id = Some(second_session.session_id.clone());
    media_lane.media_session_decision_id = Some(second_session.decision_id.clone());
    media_lane.media_session_descriptor_canonical_sha256 =
        Some(second_session.product_descriptor_canonical_sha256.clone());
    media_lane.media_session_provider_epoch_id = Some(second_session.provider_epoch_id.clone());
    media_lane.media_session_platform_runtime_spec_id =
        Some(second_session.platform_runtime_spec_id.clone());
    let media_lane_command = direct_command(
        &host,
        id(&format!("runtime.{}", media_lane.request_id.as_str())),
        DIRECT_LANE_LEASE_ISSUE_COMMAND,
        direct_lane_lease_issue_params_digest(&media_lane).expect("params"),
        4_900,
    );
    let before_unjoined_lane = host.clone();
    assert!(host
        .review_direct_lane_lease(&media_lane, &media_lane_command, 4_900)
        .is_err());
    assert_eq!(host, before_unjoined_lane);
    let media_lane = host
        .review_direct_lane_lease_with_live_broker_runtime(
            &broker,
            &media_lane,
            &media_lane_command,
            4_900,
        )
        .expect("live Broker direct-lane review")
        .lease
        .expect("media-derived direct lane");
    assert!(
        !host
            .validate_media_session(&second_session.decision_id, 4_950)
            .current
    );
    assert!(
        host.validate_media_session_with_live_broker_runtime(
            &broker,
            &second_session.decision_id,
            4_950,
        )
        .expect("live Broker media validation")
        .current
    );

    let stale_old_peer_json = host.snapshot_json().expect("old peer snapshot");
    let broker_revocation = revoke_broker_control_lease(&mut broker, &grant, "outer-lease", 41);
    assert!(broker_revocation.applied, "{broker_revocation:?}");
    let blocked_acceptance = media_acceptance_request(
        &host,
        "request.media.accept.dynamic.blocked",
        8,
        PROVIDER_EPOCH_ID,
    );
    let blocked_acceptance_command = media_accept_command(&host, &blocked_acceptance);
    let before_pending_convergence = host.clone();
    assert!(host
        .review_media_session_acceptance_with_live_broker_runtime(
            &broker,
            &blocked_acceptance,
            &blocked_acceptance_command,
            4_975,
        )
        .is_err());
    assert!(
        !host
            .validate_media_session(&second_session.decision_id, 4_975)
            .current
    );
    assert!(host
        .validate_media_session_with_live_broker_runtime(
            &broker,
            &second_session.decision_id,
            4_975,
        )
        .is_err());
    let lane_use = ManifoldDirectLaneLeaseUseRequest {
        schema_id: schema_id(DIRECT_LANE_LEASE_USE_REQUEST_SCHEMA),
        request_id: id("request.direct-lane.dynamic-media.blocked-use"),
        expected_authority_revision: host.snapshot().direct_lane_leases.authority_revision,
        lease_id: media_lane.lease_id.clone(),
    };
    let lane_use_command = direct_command(
        &host,
        lane_use.request_id.clone(),
        DIRECT_LANE_LEASE_USE_COMMAND,
        direct_lane_lease_use_params_digest(&lane_use).expect("params"),
        4_975,
    );
    assert_eq!(
        host.validate_direct_lane_lease(&lane_use, &lane_use_command, 4_975),
        Err(ManifoldDirectLaneLeaseRejectionReason::ClientNotAuthorized)
    );
    assert_eq!(
        host.validate_direct_lane_lease_with_live_broker_runtime(
            &broker,
            &lane_use,
            &lane_use_command,
            4_975,
        ),
        Err(ManifoldDirectLaneLeaseRejectionReason::ClientNotAuthorized)
    );
    assert_eq!(host, before_pending_convergence);
    assert!(
        ManifoldPeerRuntimeHost::restart_from_json_with_live_broker_runtime(
            &stale_old_peer_json,
            &policy,
            &id(PROVIDER_EPOCH_ID),
            &broker,
        )
        .is_err(),
        "a pre-revocation peer snapshot cannot restore against revoked live Broker state"
    );
    let broker_evidence = broker.evidence();
    let broker_revoked_at_ms = match &broker_revocation
        .authority_transition
        .as_ref()
        .expect("revocation transition")
        .application
    {
        ManifoldBrokerControlLeaseTransitionApplication::Revocation(application) => u64::try_from(
            application
                .tombstone
                .as_ref()
                .expect("revocation tombstone")
                .recorded_clock
                .wall_unix_ms,
        )
        .expect("positive Broker wall clock"),
        _ => panic!("expected Broker revocation transition"),
    };
    let convergence_request = ManifoldPeerRuntimeBrokerLeaseRevocationConvergenceRequest {
        schema_id: schema_id(PEER_RUNTIME_BROKER_LEASE_REVOCATION_CONVERGENCE_REQUEST_SCHEMA),
        convergence_id: id("convergence.peer-runtime.outer-lease.001"),
        expected_peer_event_sequence: host.snapshot().event_sequence,
        expected_peer_provider_epoch_id: id(PROVIDER_EPOCH_ID),
        expected_broker_provider_epoch_id: broker_evidence.provider_epoch_id.clone(),
        broker_lifecycle_request_id: broker_revocation.lifecycle_request_id.clone(),
        outer_control_lease_id: grant.broker_runtime_lease_id.clone(),
        expected_broker_control_lease_authority_revision: broker_evidence
            .control_lease_authority
            .current_authority_snapshot
            .authority_revision,
        expected_broker_runtime_host_revision: broker_evidence.host_snapshot.authority_revision,
        converged_at_ms: broker_revoked_at_ms,
    };
    let prior_inner_runtime_revision = host.snapshot().media_command_runtime.authority_revision;
    let convergence = host
        .converge_live_broker_control_lease_revocation(&broker, &convergence_request)
        .expect("live Broker revocation convergence");
    assert_eq!(
        convergence.affected_broker_admission_use_ids,
        vec![second_mutation.admission_use_request_id.clone()]
    );
    assert_eq!(
        convergence.removed_inner_runtime_lease_ids,
        vec![grant.lease_id.clone()]
    );
    assert_eq!(
        convergence
            .inner_runtime_lease_revocation_receipt
            .prior_host_authority_revision,
        prior_inner_runtime_revision
    );
    assert_eq!(
        convergence
            .inner_runtime_lease_revocation_receipt
            .resulting_host_authority_revision,
        prior_inner_runtime_revision
            .next()
            .expect("revision advances")
    );
    assert_eq!(
        convergence
            .inner_runtime_lease_revocation_receipt
            .removed_lease_ids,
        vec![grant.lease_id.clone()]
    );
    assert_eq!(
        convergence.revoked_media_decision_ids,
        vec![second_session.decision_id.clone()]
    );
    assert_eq!(
        convergence.revoked_direct_lane_lease_ids,
        vec![media_lane.lease_id.clone()]
    );
    assert_eq!(convergence.cleanup_obligations.len(), 1);
    assert!(convergence.platform_cleanup_pending);
    assert_eq!(
        convergence.cleanup_obligations[0].stream_ids,
        second_session.product_binding.descriptor.stream_ids
    );
    assert!(!host
        .snapshot()
        .media_command_runtime
        .leases
        .iter()
        .any(|lease| lease.lease_id == grant.lease_id));
    assert!(host
        .snapshot()
        .media_sessions
        .sessions
        .iter()
        .any(|session| {
            session.decision_id == second_session.decision_id
                && session.lifecycle_status == ManifoldMediaSessionLifecycleStatus::Revoked
                && session.ended_by_id.as_ref() == Some(&convergence_request.convergence_id)
        }));
    assert!(host
        .snapshot()
        .direct_lane_leases
        .leases
        .iter()
        .any(|lease| lease.lease_id == media_lane.lease_id && lease.revoked));
    let converged_route = host
        .snapshot()
        .pair_media_routes
        .routes
        .iter()
        .find(|route| route.grant_id() == &pair_route_grant_id)
        .expect("Broker-revoked route retained");
    assert_eq!(
        *converged_route.lifecycle_status(),
        ManifoldPairMediaRouteLifecycleStatus::Revoked
    );
    assert_eq!(
        *converged_route.cleanup_status(),
        ManifoldPairMediaRouteCleanupStatus::Pending
    );
    assert_eq!(
        converged_route.ended_by_id(),
        Some(&convergence_request.convergence_id)
    );
    assert!(converged_route.termination_runtime_binding().is_none());

    let wrong_target_cleanup = ManifoldPairMediaRouteCleanupCompletionRequestV2 {
        schema_id: schema_id(PAIR_MEDIA_ROUTE_CLEANUP_REQUEST_V2_SCHEMA),
        request_id: id("request.pair-route.dynamic.cleanup.wrong-target"),
        expected_authority_revision: host.snapshot().pair_media_routes.authority_revision,
        runtime_command_request_id: id("runtime.request.pair-route.dynamic.cleanup.wrong-target"),
        grant_id: pair_route_grant_id.clone(),
        expected_authority_provider_epoch_id: id("provider.epoch.wrong"),
        expected_platform_runtime_spec_id: second_session.platform_runtime_spec_id.clone(),
        effect_receipt_id: id("effect.pair-route.dynamic.cleanup.wrong-target"),
        effect_receipt_sha256: format!("sha256:{}", "91".repeat(32)),
    };
    let wrong_target_command = media_command(
        &host,
        wrong_target_cleanup.runtime_command_request_id.clone(),
        PAIR_MEDIA_ROUTE_CLEANUP_COMMAND,
        rusty_manifold_peer::pair_media_route_cleanup_params_digest_v2(&wrong_target_cleanup)
            .expect("wrong-target cleanup params"),
        "operator.media-revoker",
        "lease.runtime.media-revoker",
        broker_revoked_at_ms + 1,
    );
    let pair_revision_before_wrong_target = host.snapshot().pair_media_routes.authority_revision;
    assert!(host
        .complete_pair_media_route_cleanup_v2(
            &wrong_target_cleanup,
            &wrong_target_command,
            broker_revoked_at_ms + 1,
        )
        .is_err());
    assert_eq!(
        host.snapshot().pair_media_routes.authority_revision,
        pair_revision_before_wrong_target
    );
    assert_eq!(
        *host
            .snapshot()
            .pair_media_routes
            .routes
            .iter()
            .find(|route| route.grant_id() == &pair_route_grant_id)
            .expect("wrong-target route retained")
            .cleanup_status(),
        ManifoldPairMediaRouteCleanupStatus::Pending
    );

    let cleanup_route = ManifoldPairMediaRouteCleanupCompletionRequestV2 {
        schema_id: schema_id(PAIR_MEDIA_ROUTE_CLEANUP_REQUEST_V2_SCHEMA),
        request_id: id("request.pair-route.dynamic.cleanup.revoker"),
        expected_authority_revision: host.snapshot().pair_media_routes.authority_revision,
        runtime_command_request_id: id("runtime.request.pair-route.dynamic.cleanup.revoker"),
        grant_id: pair_route_grant_id.clone(),
        expected_authority_provider_epoch_id: id(PROVIDER_EPOCH_ID),
        expected_platform_runtime_spec_id: second_session.platform_runtime_spec_id.clone(),
        effect_receipt_id: id("effect.pair-route.dynamic.cleanup.revoker"),
        effect_receipt_sha256: format!("sha256:{}", "92".repeat(32)),
    };
    let cleanup_route_command = media_command(
        &host,
        cleanup_route.runtime_command_request_id.clone(),
        PAIR_MEDIA_ROUTE_CLEANUP_COMMAND,
        rusty_manifold_peer::pair_media_route_cleanup_params_digest_v2(&cleanup_route)
            .expect("revoker cleanup params"),
        "operator.media-revoker",
        "lease.runtime.media-revoker",
        broker_revoked_at_ms + 2,
    );
    assert!(matches!(
        host.complete_pair_media_route_cleanup_v2(
            &cleanup_route,
            &cleanup_route_command,
            broker_revoked_at_ms + 2,
        )
        .expect("fresh trusted revoker cleanup after source lease revocation"),
        ManifoldPairMediaRouteCleanupReceiptV2::CommonLan(_)
    ));
    assert_eq!(
        *host
            .snapshot()
            .pair_media_routes
            .routes
            .iter()
            .find(|route| route.grant_id() == &pair_route_grant_id)
            .expect("cleaned route retained")
            .cleanup_status(),
        ManifoldPairMediaRouteCleanupStatus::Completed
    );
    let stale_inner_command_review =
        ManifoldRuntimeHost::from_snapshot(host.snapshot().media_command_runtime.clone())
            .expect("converged inner Runtime Host")
            .review_command(&blocked_acceptance_command, 5_000);
    assert_eq!(
        stale_inner_command_review.rejection_reason,
        Some(ManifoldRuntimeRejectionReason::StaleAuthorityRevision)
    );
    let converged_host = host.clone();
    assert!(matches!(
        host.converge_live_broker_control_lease_revocation(&broker, &convergence_request),
        Err(ManifoldPeerRuntimeHostError::ReplayedMutation(_))
    ));
    assert_eq!(host, converged_host);
    let mut stale_peer_request = convergence_request.clone();
    stale_peer_request.convergence_id = id("convergence.peer-runtime.outer-lease.stale");
    assert!(host
        .converge_live_broker_control_lease_revocation(&broker, &stale_peer_request)
        .is_err());
    assert_eq!(host, converged_host);
    assert!(host
        .broker_revocation_consumer_acknowledgement(&broker, &convergence_request.convergence_id,)
        .is_err());
    let cleanup_request = ManifoldPeerRuntimeBrokerLeaseRevocationCleanupCompletionRequest {
        schema_id: schema_id(
            PEER_RUNTIME_BROKER_LEASE_REVOCATION_CLEANUP_COMPLETION_REQUEST_SCHEMA,
        ),
        completion_id: id("completion.peer-runtime.outer-lease.001"),
        convergence_id: convergence_request.convergence_id.clone(),
        expected_peer_event_sequence: host.snapshot().event_sequence,
        completed_session_decision_ids: vec![second_session.decision_id.clone()],
        platform_cleanup_receipt_sha256: format!("sha256:{}", "a".repeat(64)),
    };
    let cleanup = host
        .complete_broker_lease_revocation_cleanup(&broker, &cleanup_request)
        .expect("terminal platform cleanup completion");
    assert!(cleanup.completed);
    assert_eq!(
        cleanup.completed_obligations,
        convergence.cleanup_obligations
    );
    let consumer_acknowledgement = host
        .broker_revocation_consumer_acknowledgement(&broker, &convergence_request.convergence_id)
        .expect("peer consumer acknowledgement");
    assert_eq!(
        consumer_acknowledgement.consumer_kind,
        ManifoldBrokerControlLeaseRevocationConsumerKind::PeerRuntimeHost
    );
    assert!(consumer_acknowledgement
        .consumer_convergence_receipt_sha256
        .starts_with("sha256:"));
    assert!(consumer_acknowledgement
        .terminal_cleanup_receipt_sha256
        .starts_with("sha256:"));
    broker
        .acknowledge_control_lease_revocation_consumer(consumer_acknowledgement.clone())
        .expect("Broker retains peer consumer acknowledgement");
    assert!(broker
        .evidence()
        .control_lease_revocation_consumer_acknowledgements
        .contains(&consumer_acknowledgement));
    let cleanup_complete_host = host.clone();
    assert!(matches!(
        host.complete_broker_lease_revocation_cleanup(&broker, &cleanup_request),
        Err(ManifoldPeerRuntimeHostError::ReplayedMutation(_))
    ));
    assert_eq!(host, cleanup_complete_host);

    let (restarted, migration) =
        ManifoldPeerRuntimeHost::restart_from_json_with_live_broker_runtime(
            &host.snapshot_json().expect("dynamic snapshot"),
            &policy,
            &id(PROVIDER_EPOCH_ID),
            &broker,
        )
        .expect("dynamic bridge restart");
    assert!(!migration.migrated);
    assert_eq!(restarted, host);
    let stable = host.clone();
    assert!(matches!(
        host.release_media_runtime_lease_with_live_broker_runtime(
            &broker,
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

    let old_peer_json = host.snapshot_json().expect("old-epoch peer snapshot");
    let source_broker_evidence = broker.evidence();
    let resulting_epoch = id("provider.epoch.quest-test.002");
    let broker_rollover = broker
        .rollover_drained_provider_epoch(resulting_epoch.clone(), fresh_admission_snapshot)
        .expect("drained Broker epoch rollover");
    assert!(
        ManifoldPeerRuntimeHost::restart_from_json_with_live_broker_runtime(
            &old_peer_json,
            &policy,
            &id(PROVIDER_EPOCH_ID),
            &broker,
        )
        .is_err(),
        "old peer epoch cannot silently join the fresh Broker epoch"
    );
    let mut forged_broker_rollover = broker_rollover.clone();
    forged_broker_rollover.resulting_evidence_sha256 = format!("sha256:{}", "c".repeat(64));
    let before_forged_rollover = host.clone();
    assert!(host
        .rollover_drained_broker_provider_epoch(
            &source_broker_evidence,
            &forged_broker_rollover,
            &broker,
        )
        .is_err());
    assert_eq!(host, before_forged_rollover);
    let peer_rollover = host
        .rollover_drained_broker_provider_epoch(&source_broker_evidence, &broker_rollover, &broker)
        .expect("peer joins exact Broker rollover");
    assert_eq!(
        peer_rollover.source_provider_epoch_id,
        id(PROVIDER_EPOCH_ID)
    );
    assert_eq!(peer_rollover.resulting_provider_epoch_id, resulting_epoch);
    assert_eq!(peer_rollover.broker_rollover_receipt, broker_rollover);
    assert_eq!(peer_rollover.checkpointed_revocation_convergence_count, 1);
    assert_eq!(peer_rollover.checkpointed_cleanup_completion_count, 1);
    assert_eq!(host.snapshot().provider_epoch_id, resulting_epoch);
    assert_eq!(host.snapshot().broker_epoch_rollovers.len(), 1);
    assert_eq!(
        host.snapshot().broker_lease_revocation_convergences,
        vec![convergence.clone()]
    );
    assert_eq!(
        host.snapshot()
            .audit_events
            .last()
            .expect("rollover audit")
            .event_kind,
        ManifoldPeerRuntimeAuditKind::BrokerEpochRollover
    );

    let restarted_after_rollover =
        ManifoldPeerRuntimeHost::restart_from_json_with_live_broker_runtime(
            &host.snapshot_json().expect("rolled peer snapshot"),
            &policy,
            &resulting_epoch,
            &broker,
        )
        .expect("checkpointed old-epoch joins restore against fresh Broker");
    assert_eq!(restarted_after_rollover.0, host);
    assert!(matches!(
        host.converge_live_broker_control_lease_revocation(&broker, &convergence_request),
        Err(ManifoldPeerRuntimeHostError::ReplayedMutation(_))
    ));

    let mut damaged_checkpoint = host.snapshot().clone();
    damaged_checkpoint.broker_epoch_rollovers[0].checkpointed_peer_broker_state_sha256 =
        format!("sha256:{}", "b".repeat(64));
    assert!(
        ManifoldPeerRuntimeHost::from_snapshot_with_live_broker_runtime(
            damaged_checkpoint,
            &policy,
            &resulting_epoch,
            &broker,
        )
        .is_err()
    );

    let second_source_broker_evidence = broker.evidence();
    let third_epoch = id("provider.epoch.quest-test.003");
    let second_broker_rollover = broker
        .rollover_drained_provider_epoch(third_epoch.clone(), second_fresh_admission_snapshot)
        .expect("second drained Broker epoch rollover");
    let second_peer_rollover = host
        .rollover_drained_broker_provider_epoch(
            &second_source_broker_evidence,
            &second_broker_rollover,
            &broker,
        )
        .expect("peer joins second exact Broker rollover");
    assert_eq!(
        second_peer_rollover.source_provider_epoch_id,
        resulting_epoch
    );
    assert_eq!(
        second_peer_rollover.resulting_provider_epoch_id,
        third_epoch
    );
    assert_eq!(
        second_peer_rollover.checkpointed_revocation_convergence_count,
        0
    );
    assert_eq!(host.snapshot().broker_epoch_rollovers.len(), 2);
    assert_eq!(
        host.snapshot().broker_lease_revocation_convergences,
        vec![convergence]
    );
    ManifoldPeerRuntimeHost::restart_from_json_with_live_broker_runtime(
        &host.snapshot_json().expect("twice-rolled peer snapshot"),
        &policy,
        &third_epoch,
        &broker,
    )
    .expect("ordered checkpoint chain restores historical joins");
}

fn common_lan_transport() -> rusty_manifold_peer::ManifoldCommonLanTransportBinding {
    rusty_manifold_peer::ManifoldCommonLanTransportBinding {
        topology_contract_id: id(rusty_manifold_peer::COMMON_LAN_PAIR_TOPOLOGY_CONTRACT_ID),
        transport_contract_id: id(rusty_manifold_peer::COMMON_LAN_TCP_TRANSPORT_CONTRACT_ID),
        network_scope_id: id("network.scope.runtime-host-test"),
        endpoints: vec![
            rusty_manifold_peer::ManifoldCommonLanEndpointBinding {
                peer_id: id("peer.alpha"),
                endpoint_id: id("endpoint.alpha.media"),
                listen_ip_address: "192.168.49.2".to_owned(),
                listen_port: 46_000,
            },
            rusty_manifold_peer::ManifoldCommonLanEndpointBinding {
                peer_id: id("peer.beta"),
                endpoint_id: id("endpoint.beta.media"),
                listen_ip_address: "192.168.49.3".to_owned(),
                listen_port: 46_001,
            },
        ],
        route_configuration_sha256: format!("sha256:{}", "51".repeat(32)),
    }
}

fn common_lan_reciprocal_request(
    host: &ManifoldPeerRuntimeHost,
    alpha_key: &SigningKey,
    beta_key: &SigningKey,
) -> rusty_manifold_peer::ManifoldCommonLanReciprocalEd25519ReviewRequest {
    let credential = |peer: &str| {
        host.snapshot()
            .enrollment
            .credentials
            .iter()
            .find(|credential| credential.peer_id.as_str() == peer)
            .expect("credential")
    };
    let alpha = credential("peer.alpha");
    let beta = credential("peer.beta");
    let context = rusty_manifold_peer::ManifoldCommonLanReciprocalEd25519Context {
        schema_id: schema_id(rusty_manifold_peer::COMMON_LAN_RECIPROCAL_ED25519_CONTEXT_SCHEMA),
        runtime_host_id: host.snapshot().host_id.clone(),
        trust_policy_id: host.snapshot().trust_policy.policy_id.clone(),
        trust_policy_revision: host.snapshot().trust_policy.revision,
        correlation_id: id("correlation.runtime-host.common-lan.001"),
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
        initiator: rusty_manifold_peer::ManifoldCommonLanReciprocalEd25519PeerBinding {
            peer_id: alpha.peer_id.clone(),
            key_id: alpha.key_id.clone(),
            key_generation: alpha.key_generation,
            public_key_sha256: alpha.public_key_sha256.clone(),
            role: rusty_manifold_peer::ManifoldCommonLanPairRole::Initiator,
            device_nonce_hex: "61".repeat(32),
        },
        responder: rusty_manifold_peer::ManifoldCommonLanReciprocalEd25519PeerBinding {
            peer_id: beta.peer_id.clone(),
            key_id: beta.key_id.clone(),
            key_generation: beta.key_generation,
            public_key_sha256: beta.public_key_sha256.clone(),
            role: rusty_manifold_peer::ManifoldCommonLanPairRole::Responder,
            device_nonce_hex: "72".repeat(32),
        },
        transport: common_lan_transport(),
        coordinator_epoch: 23,
        issued_at_ms: 2_500,
        expires_at_ms: 60_000,
    };
    let bytes = rusty_manifold_peer::common_lan_reciprocal_ed25519_context_signing_bytes(&context);
    let digest = rusty_manifold_peer::common_lan_reciprocal_ed25519_context_sha256(&context);
    let signature =
        |binding: &rusty_manifold_peer::ManifoldCommonLanReciprocalEd25519PeerBinding,
         key: &SigningKey| {
            rusty_manifold_peer::ManifoldCommonLanReciprocalEd25519Signature {
                schema_id: schema_id(
                    rusty_manifold_peer::COMMON_LAN_RECIPROCAL_ED25519_SIGNATURE_SCHEMA,
                ),
                signer_peer_id: binding.peer_id.clone(),
                signer_key_id: binding.key_id.clone(),
                context_sha256: digest.clone(),
                signature_hex: encode_lower_hex(&key.sign(&bytes).to_bytes()),
            }
        };
    rusty_manifold_peer::ManifoldCommonLanReciprocalEd25519ReviewRequest {
        schema_id: schema_id(rusty_manifold_peer::COMMON_LAN_RECIPROCAL_ED25519_REVIEW_SCHEMA),
        request_id: id("request.runtime-host.common-lan.reciprocal.001"),
        initiator_signature: signature(&context.initiator, alpha_key),
        responder_signature: signature(&context.responder, beta_key),
        context,
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn common_lan_route_is_mixed_restartable_and_legacy_current_fails_closed() {
    let mut host = fixture_host();
    let (alpha_key, beta_key) = enroll_pair(&mut host);
    let wifi_rendezvous = rendezvous_request(
        &host,
        "mixed-before-common-lan.001",
        "key.peer.alpha.001",
        &alpha_key,
        &beta_key,
        11,
    );
    let wifi_receipt = host
        .review_signed_rendezvous(&wifi_rendezvous, 2_600)
        .expect("Wi-Fi rendezvous before common LAN");
    assert!(wifi_receipt.accepted);
    accept_session(
        &mut host,
        wifi_receipt,
        "proposal.peer-session.mixed-wifi.001",
        "session.peer.mixed-wifi.001",
    );
    let reciprocal_request = common_lan_reciprocal_request(&host, &alpha_key, &beta_key);
    let reciprocal = host
        .review_reciprocal_ed25519_v3(
            &ManifoldReciprocalEd25519ReviewRequestV3::CommonLan(reciprocal_request),
            3_000,
        )
        .expect("common-LAN reciprocal");
    let reciprocal = match reciprocal {
        ManifoldReciprocalEd25519ReceiptV3::CommonLan(receipt) if receipt.accepted => receipt,
        other => panic!("common-LAN reciprocal rejected: {other:?}"),
    };
    let requested_capability_ids = session_proposal(
        &host,
        "proposal.unused.common-lan",
        "session.unused.common-lan",
    )
    .requested_capability_ids;
    let proposal = ManifoldCommonLanPeerSessionProposal {
        schema_id: schema_id(rusty_manifold_peer::COMMON_LAN_PEER_SESSION_PROPOSAL_SCHEMA),
        proposal_id: id("proposal.runtime-host.common-lan.001"),
        session_id: id("session.runtime-host.common-lan.001"),
        expected_authority_revision: host.snapshot().peer_sessions.authority_revision,
        subject_peer_id: id("peer.alpha"),
        candidate_peer_id: id("peer.beta"),
        initiator_peer_id: id("peer.alpha"),
        responder_peer_id: id("peer.beta"),
        requested_capability_ids,
        transport: common_lan_transport(),
        expires_at_ms: 60_000,
    };
    let (decision, _) = host
        .review_common_lan_peer_session(&proposal, &reciprocal, 3_100)
        .expect("common-LAN session");
    assert!(decision.applied, "{decision:?}");
    assert_eq!(host.snapshot().peer_sessions.sessions.len(), 2);
    assert!(matches!(
        host.snapshot().peer_sessions.sessions[0],
        ManifoldAcceptedPeerSessionV2::WifiDirect(_)
    ));
    assert!(matches!(
        host.snapshot().peer_sessions.sessions[1],
        ManifoldAcceptedPeerSessionV2::CommonLan(_)
    ));
    let acceptance_request = media_acceptance_request(
        &host,
        "request.media.accept.common-lan.001",
        6,
        PROVIDER_EPOCH_ID,
    );
    let acceptance_command = media_accept_command(&host, &acceptance_request);
    let accepted = host
        .review_media_session_acceptance(&acceptance_request, &acceptance_command, 4_000)
        .expect("common-LAN media acceptance");
    let media_decision_id = accepted
        .accepted_session
        .expect("accepted media")
        .decision_id;
    let request = ManifoldCommonLanPairMediaRouteRequest {
        request: pair_route_request(
            &host,
            "request.route.common-lan.001",
            "runtime.request.route.common-lan.001",
            "leg.common-lan.alpha-beta",
            1,
            "peer.alpha",
            "peer.beta",
            "session.runtime-host.common-lan.001",
            media_decision_id.clone(),
            20_000,
        ),
        transport: common_lan_transport(),
    };
    let command = media_command(
        &host,
        request.request.runtime_command_request_id.clone(),
        PAIR_MEDIA_ROUTE_ISSUE_COMMAND,
        rusty_manifold_peer::pair_media_route_issue_params_digest_v2(&request).expect("params"),
        TRUSTED_MEDIA_PROPOSER_ID,
        "lease.runtime.media-test",
        4_100,
    );
    let receipt = host
        .review_pair_media_route_v2(
            &ManifoldPairMediaRouteRequestV2::CommonLan(request),
            &command,
            4_100,
        )
        .expect("common-LAN route");
    let grant_id = match receipt {
        ManifoldPairMediaRouteReceiptV2::CommonLan(receipt) => {
            receipt.route.expect("accepted route").grant_id
        }
        other @ ManifoldPairMediaRouteReceiptV2::WifiDirect(_) => {
            panic!("wrong route receipt: {other:?}")
        }
    };
    assert!(host.validate_pair_media_route_v2(&grant_id, 4_200).current);
    let legacy = host.validate_pair_media_route(&grant_id, 4_200);
    assert!(!legacy.current);
    assert_eq!(
        legacy.rejection_reason,
        Some(ManifoldPairMediaRouteRejectionReason::SchemaMismatch)
    );
    let mut restarted = restart_host(&host);
    assert!(
        restarted
            .validate_pair_media_route_v2(&grant_id, 4_200)
            .current
    );
    let mut damaged = restarted.snapshot().clone();
    let ManifoldAcceptedPairMediaRouteV2::CommonLan(route) =
        &mut damaged.pair_media_routes.routes[0]
    else {
        panic!("common route");
    };
    route.transport.endpoints[0].listen_port += 1;
    assert!(ManifoldPeerRuntimeHost::from_snapshot(
        damaged,
        &restarted.snapshot().trust_policy,
        &restarted.snapshot().provider_epoch_id,
    )
    .is_err());
    let mut missing_topology = restarted.snapshot().clone();
    missing_topology
        .signed_topology_authorizations
        .retain(|topology| topology.session_id().as_str() != "session.runtime-host.common-lan.001");
    assert!(ManifoldPeerRuntimeHost::from_snapshot(
        missing_topology,
        &restarted.snapshot().trust_policy,
        &restarted.snapshot().provider_epoch_id,
    )
    .is_err());

    let wifi_v2_request = pair_route_request(
        &restarted,
        "request.route.mixed.wifi-v2.001",
        "runtime.request.route.mixed.wifi-v2.001",
        "leg.mixed.wifi-v2",
        1,
        "peer.alpha",
        "peer.beta",
        "session.peer.mixed-wifi.001",
        media_decision_id.clone(),
        20_000,
    );
    let wifi_v2_grant = issue_pair_route(&mut restarted, &wifi_v2_request, 4_201)
        .accepted_route
        .expect("first mixed Wi-Fi route")
        .grant_id;
    let wifi_v1_request = pair_route_request(
        &restarted,
        "request.route.mixed.wifi-v1.001",
        "runtime.request.route.mixed.wifi-v1.001",
        "leg.mixed.wifi-v1",
        1,
        "peer.alpha",
        "peer.beta",
        "session.peer.mixed-wifi.001",
        media_decision_id,
        20_000,
    );
    let wifi_v1_grant = issue_pair_route(&mut restarted, &wifi_v1_request, 4_202)
        .accepted_route
        .expect("second mixed Wi-Fi route")
        .grant_id;

    let damage_common_route = |host: &ManifoldPeerRuntimeHost| {
        let mut damaged = host.clone();
        let common = damaged
            .snapshot
            .pair_media_routes
            .routes
            .iter_mut()
            .find_map(|route| match route {
                ManifoldAcceptedPairMediaRouteV2::CommonLan(route) => Some(route),
                ManifoldAcceptedPairMediaRouteV2::WifiDirect(_) => None,
            })
            .expect("retained common-LAN route");
        common.transport.route_configuration_sha256 = format!("sha256:{}", "00".repeat(32));
        damaged
    };
    let damaged_for_current = damage_common_route(&restarted);
    let before_damaged_current = damaged_for_current.clone();
    assert!(
        !damaged_for_current
            .validate_pair_media_route(&wifi_v1_grant, 4_205)
            .current
    );
    assert_eq!(damaged_for_current, before_damaged_current);

    let wifi_v2_stop = ManifoldPairMediaRouteTerminationRequestV2 {
        schema_id: schema_id(rusty_manifold_peer::PAIR_MEDIA_ROUTE_TERMINATION_REQUEST_V2_SCHEMA),
        request_id: id("request.route.mixed.wifi-v2.stop.001"),
        expected_authority_revision: restarted.snapshot().pair_media_routes.authority_revision,
        runtime_command_request_id: id("runtime.request.route.mixed.wifi-v2.stop.001"),
        grant_id: wifi_v2_grant.clone(),
        expected_authority_provider_epoch_id: id(PROVIDER_EPOCH_ID),
        expected_platform_runtime_spec_id: id("runtime.quest.direct-p2p"),
        action: ManifoldPairMediaRouteTerminationAction::Stop,
    };
    let wifi_v2_stop_command = media_command(
        &restarted,
        wifi_v2_stop.runtime_command_request_id.clone(),
        PAIR_MEDIA_ROUTE_STOP_COMMAND,
        rusty_manifold_peer::pair_media_route_termination_params_digest_v2(&wifi_v2_stop)
            .expect("Wi-Fi v2 stop params"),
        TRUSTED_MEDIA_PROPOSER_ID,
        "lease.runtime.media-test",
        4_210,
    );
    assert!(
        restarted
            .review_pair_media_route_termination_v2(&wifi_v2_stop, &wifi_v2_stop_command, 4_210,)
            .expect("Wi-Fi v2 stop")
            .applied
    );
    let wifi_v2_cleanup = ManifoldPairMediaRouteCleanupCompletionRequestV2 {
        schema_id: schema_id(rusty_manifold_peer::PAIR_MEDIA_ROUTE_CLEANUP_REQUEST_V2_SCHEMA),
        request_id: id("request.route.mixed.wifi-v2.cleanup.001"),
        expected_authority_revision: restarted.snapshot().pair_media_routes.authority_revision,
        runtime_command_request_id: id("runtime.request.route.mixed.wifi-v2.cleanup.001"),
        grant_id: wifi_v2_grant,
        expected_authority_provider_epoch_id: id(PROVIDER_EPOCH_ID),
        expected_platform_runtime_spec_id: id("runtime.quest.direct-p2p"),
        effect_receipt_id: id("effect.route.mixed.wifi-v2.cleanup.001"),
        effect_receipt_sha256: format!("sha256:{}", "84".repeat(32)),
    };
    let wifi_v2_cleanup_command = media_command(
        &restarted,
        wifi_v2_cleanup.runtime_command_request_id.clone(),
        PAIR_MEDIA_ROUTE_CLEANUP_COMMAND,
        rusty_manifold_peer::pair_media_route_cleanup_params_digest_v2(&wifi_v2_cleanup)
            .expect("Wi-Fi v2 cleanup params"),
        TRUSTED_MEDIA_PROPOSER_ID,
        "lease.runtime.media-test",
        4_220,
    );
    assert!(matches!(
        restarted
            .complete_pair_media_route_cleanup_v2(
                &wifi_v2_cleanup,
                &wifi_v2_cleanup_command,
                4_220,
            )
            .expect("Wi-Fi v2 cleanup"),
        ManifoldPairMediaRouteCleanupReceiptV2::WifiDirect(_)
    ));

    let wifi_v1_stop = ManifoldPairMediaRouteTerminationRequest {
        schema_id: schema_id(PAIR_MEDIA_ROUTE_TERMINATION_REQUEST_SCHEMA),
        request_id: id("request.route.mixed.wifi-v1.stop.001"),
        expected_authority_revision: restarted.snapshot().pair_media_routes.authority_revision,
        runtime_command_request_id: id("runtime.request.route.mixed.wifi-v1.stop.001"),
        grant_id: wifi_v1_grant.clone(),
        action: ManifoldPairMediaRouteTerminationAction::Stop,
    };
    let wifi_v1_stop_command = media_command(
        &restarted,
        wifi_v1_stop.runtime_command_request_id.clone(),
        PAIR_MEDIA_ROUTE_STOP_COMMAND,
        pair_media_route_termination_params_digest(&wifi_v1_stop).expect("Wi-Fi v1 stop params"),
        TRUSTED_MEDIA_PROPOSER_ID,
        "lease.runtime.media-test",
        4_230,
    );
    let mut damaged_for_v1_stop = damage_common_route(&restarted);
    let before_damaged_v1_stop = damaged_for_v1_stop.clone();
    assert!(damaged_for_v1_stop
        .review_pair_media_route_termination(&wifi_v1_stop, &wifi_v1_stop_command, 4_230)
        .is_err());
    assert_eq!(damaged_for_v1_stop, before_damaged_v1_stop);
    assert!(
        restarted
            .review_pair_media_route_termination(&wifi_v1_stop, &wifi_v1_stop_command, 4_230)
            .expect("Wi-Fi v1 stop")
            .applied
    );
    let wifi_v1_cleanup = ManifoldPairMediaRouteCleanupCompletionRequest {
        schema_id: schema_id(PAIR_MEDIA_ROUTE_CLEANUP_REQUEST_SCHEMA),
        request_id: id("request.route.mixed.wifi-v1.cleanup.001"),
        expected_authority_revision: restarted.snapshot().pair_media_routes.authority_revision,
        runtime_command_request_id: id("runtime.request.route.mixed.wifi-v1.cleanup.001"),
        grant_id: wifi_v1_grant,
        effect_receipt_id: id("effect.route.mixed.wifi-v1.cleanup.001"),
        effect_receipt_sha256: format!("sha256:{}", "85".repeat(32)),
    };
    let wifi_v1_cleanup_command = media_command(
        &restarted,
        wifi_v1_cleanup.runtime_command_request_id.clone(),
        PAIR_MEDIA_ROUTE_CLEANUP_COMMAND,
        pair_media_route_cleanup_params_digest(&wifi_v1_cleanup).expect("Wi-Fi v1 cleanup params"),
        TRUSTED_MEDIA_PROPOSER_ID,
        "lease.runtime.media-test",
        4_240,
    );
    let mut damaged_for_v1_cleanup = damage_common_route(&restarted);
    let before_damaged_v1_cleanup = damaged_for_v1_cleanup.clone();
    assert!(damaged_for_v1_cleanup
        .complete_pair_media_route_cleanup(&wifi_v1_cleanup, &wifi_v1_cleanup_command, 4_240,)
        .is_err());
    assert_eq!(damaged_for_v1_cleanup, before_damaged_v1_cleanup);
    restarted
        .complete_pair_media_route_cleanup(&wifi_v1_cleanup, &wifi_v1_cleanup_command, 4_240)
        .expect("Wi-Fi v1 cleanup");
    restarted = restart_host(&restarted);
    assert!(
        restarted
            .validate_pair_media_route_v2(&grant_id, 4_250)
            .current
    );

    let stop = ManifoldPairMediaRouteTerminationRequestV2 {
        schema_id: schema_id(rusty_manifold_peer::PAIR_MEDIA_ROUTE_TERMINATION_REQUEST_V2_SCHEMA),
        request_id: id("request.route.common-lan.stop.001"),
        expected_authority_revision: restarted.snapshot().pair_media_routes.authority_revision,
        runtime_command_request_id: id("runtime.request.route.common-lan.stop.001"),
        grant_id: grant_id.clone(),
        expected_authority_provider_epoch_id: id(PROVIDER_EPOCH_ID),
        expected_platform_runtime_spec_id: id("runtime.quest.direct-p2p"),
        action: ManifoldPairMediaRouteTerminationAction::Stop,
    };
    let stop_command = media_command(
        &restarted,
        stop.runtime_command_request_id.clone(),
        PAIR_MEDIA_ROUTE_STOP_COMMAND,
        rusty_manifold_peer::pair_media_route_termination_params_digest_v2(&stop)
            .expect("stop params"),
        TRUSTED_MEDIA_PROPOSER_ID,
        "lease.runtime.media-test",
        4_300,
    );
    assert!(
        restarted
            .review_pair_media_route_termination_v2(&stop, &stop_command, 4_300)
            .expect("common-LAN stop")
            .applied
    );
    let cleanup = ManifoldPairMediaRouteCleanupCompletionRequestV2 {
        schema_id: schema_id(rusty_manifold_peer::PAIR_MEDIA_ROUTE_CLEANUP_REQUEST_V2_SCHEMA),
        request_id: id("request.route.common-lan.cleanup.client.001"),
        expected_authority_revision: restarted.snapshot().pair_media_routes.authority_revision,
        runtime_command_request_id: id("runtime.request.route.common-lan.cleanup.client.001"),
        grant_id: grant_id.clone(),
        expected_authority_provider_epoch_id: id(PROVIDER_EPOCH_ID),
        expected_platform_runtime_spec_id: id("runtime.quest.direct-p2p"),
        effect_receipt_id: id("effect.route.common-lan.cleanup.client.001"),
        effect_receipt_sha256: format!("sha256:{}", "83".repeat(32)),
    };
    let cleanup_command = media_command(
        &restarted,
        cleanup.runtime_command_request_id.clone(),
        PAIR_MEDIA_ROUTE_CLEANUP_COMMAND,
        rusty_manifold_peer::pair_media_route_cleanup_params_digest_v2(&cleanup)
            .expect("cleanup params"),
        TRUSTED_MEDIA_PROPOSER_ID,
        "lease.runtime.media-test",
        4_400,
    );
    assert!(matches!(
        restarted
            .complete_pair_media_route_cleanup_v2(&cleanup, &cleanup_command, 4_400)
            .expect("original client cleanup"),
        ManifoldPairMediaRouteCleanupReceiptV2::CommonLan(_)
    ));
    assert_eq!(
        *restarted.snapshot().pair_media_routes.routes[0].cleanup_status(),
        ManifoldPairMediaRouteCleanupStatus::Completed
    );
}
