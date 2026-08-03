use super::*;
use rusty_manifold_admission::{
    ManifoldAdmissionAuthority, ManifoldAdmissionGrant, ManifoldAdmissionRequest,
    ManifoldAdmissionSnapshot, ManifoldAdmissionUseRequest, ADMISSION_REQUEST_SCHEMA,
    ADMISSION_SNAPSHOT_SCHEMA, ADMISSION_USE_REQUEST_SCHEMA,
};

fn digest(byte: &str) -> String {
    format!("sha256:{}", byte.repeat(64))
}

fn identity() -> ManifoldClientIdentity {
    ManifoldClientIdentity {
        client_id: id("client.media-player"),
        platform_subject: "synthetic.media.player".to_owned(),
        signing_fingerprint: digest("a"),
    }
}

fn policy() -> ManifoldConnectionHubPolicy {
    ManifoldConnectionHubPolicy {
        schema_id: schema(POLICY_SCHEMA),
        authority_id: id("authority.connection-hub.synthetic"),
        trusted_operator_evidence_ids: vec![id("evidence.operator.wearer-action")],
        allowed_controller_capabilities: vec![
            id("capability.player.pause"),
            id("capability.player.play"),
        ],
        provider_grants: vec![ManifoldConnectionHubProviderGrant {
            client_id: identity().client_id,
            client_lock_id: id("client-lock.media-player"),
            client_lock_sha256: digest("b"),
            allowed_command_ids: vec![id("command.player.pause"), id("command.player.play")],
        }],
        max_controller_ttl_ms: 100_000,
        max_session_ttl_ms: 80_000,
        max_surface_lease_ttl_ms: 60_000,
    }
}

fn request(
    host: &ManifoldConnectionHubAuthority,
    name: &str,
    now: u64,
    operation: ManifoldConnectionHubOperationRequest,
) -> ManifoldConnectionHubRequest {
    ManifoldConnectionHubRequest {
        schema_id: schema(REQUEST_SCHEMA),
        request_id: id(name),
        expected_authority_revision: host.snapshot().state.authority_revision,
        requested_at_ms: now,
        operation,
    }
}

fn trust(host: &mut ManifoldConnectionHubAuthority) -> ManifoldConnectionHubRequest {
    let request = request(
        host,
        "request.hub.trust-controller.1",
        1_000,
        ManifoldConnectionHubOperationRequest::TrustController {
            controller_id: id("controller.friend-phone"),
            public_identity_sha256: digest("c"),
            capabilities: vec![id("capability.player.pause"), id("capability.player.play")],
            operator_evidence_id: id("evidence.operator.wearer-action"),
            requested_ttl_ms: 90_000,
        },
    );
    assert!(host.trust_controller(&request).applied);
    request
}

fn open_session(host: &mut ManifoldConnectionHubAuthority) {
    let request = request(
        host,
        "request.hub.open-session.1",
        1_100,
        ManifoldConnectionHubOperationRequest::OpenSession {
            session_id: id("session.friend-phone.primary"),
            controller_id: id("controller.friend-phone"),
            public_identity_sha256: digest("c"),
            transport: ManifoldConnectionHubTransportBinding {
                transport_id: id("transport.websocket.first"),
                evidence_id: id("evidence.transport.first"),
                attached_at_ms: 1_100,
            },
            requested_ttl_ms: 70_000,
        },
    );
    let receipt = host.open_session(&request);
    assert!(receipt.applied);
    assert_eq!(receipt.session.unwrap().transport_epoch, 1);
}

fn admission() -> ManifoldAdmissionAuthority {
    let mut authority = ManifoldAdmissionAuthority::from_snapshot(ManifoldAdmissionSnapshot {
        schema_id: schema(ADMISSION_SNAPSHOT_SCHEMA),
        authority_id: id("authority.admission.synthetic"),
        authority_revision: Revision::INITIAL,
        grants: vec![ManifoldAdmissionGrant {
            grant_id: id("grant.media-player"),
            client_lock_id: id("client-lock.media-player"),
            client_lock_fingerprint: digest("b"),
            identity: identity(),
            capabilities: vec![id(PROVIDER_REGISTER_CAPABILITY)],
            expires_at_ms: 200_000,
            revoked: false,
        }],
        active_tokens: Vec::new(),
        revoked_token_ids: Vec::new(),
        consumed_request_ids: Vec::new(),
        consumed_use_request_ids: Vec::new(),
        reviewed_sweep_ids: Vec::new(),
        audit_events: Vec::new(),
        max_token_ttl_ms: 150_000,
    })
    .unwrap();
    let issued = authority.issue_token(
        &ManifoldAdmissionRequest {
            schema_id: schema(ADMISSION_REQUEST_SCHEMA),
            request_id: id("request.admission.issue-provider"),
            expected_authority_revision: Revision::INITIAL,
            identity: identity(),
            requested_capabilities: vec![id(PROVIDER_REGISTER_CAPABILITY)],
            issued_at_ms: 1_000,
            expires_at_ms: 2_000,
            requested_token_ttl_ms: 100_000,
        },
        [7; 32],
        1_000,
    );
    assert!(issued.applied);
    let token = issued.token.unwrap();
    let use_receipt = authority.authorize_use(
        &ManifoldAdmissionUseRequest {
            schema_id: schema(ADMISSION_USE_REQUEST_SCHEMA),
            request_id: id("request.admission.use-provider-register"),
            expected_authority_revision: Revision::new(2).unwrap(),
            token_id: token.token_id,
            identity: identity(),
            capability_id: id(PROVIDER_REGISTER_CAPABILITY),
            issued_at_ms: 1_150,
            expires_at_ms: 2_000,
        },
        1_150,
    );
    assert!(use_receipt.applied);
    authority
}

fn register_provider_and_surface(host: &mut ManifoldConnectionHubAuthority) {
    let admission = admission();
    let register = request(
        host,
        "request.hub.register-provider.1",
        1_200,
        ManifoldConnectionHubOperationRequest::RegisterProvider {
            provider_id: id("provider.media-player"),
            provider_instance_id: id("provider-instance.media-player.1"),
            admission_use_request_id: id("request.admission.use-provider-register"),
        },
    );
    assert!(
        host.register_provider(admission.snapshot(), &register)
            .applied
    );
    let surface = ManifoldConnectionHubSurface {
        schema_id: schema(SURFACE_SCHEMA),
        surface_id: id("surface.media-player.controls"),
        provider_id: id("provider.media-player"),
        provider_instance_id: id("provider-instance.media-player.1"),
        display_label: "Media Player".to_owned(),
        description: "Playback controls".to_owned(),
        surface_contract_sha256: digest("d"),
        commands: vec![
            ManifoldConnectionHubSurfaceCommand {
                command_id: id("command.player.pause"),
                required_controller_capability: id("capability.player.pause"),
            },
            ManifoldConnectionHubSurfaceCommand {
                command_id: id("command.player.play"),
                required_controller_capability: id("capability.player.play"),
            },
        ],
        registered_at_ms: 1_300,
    };
    let register_surface = request(
        host,
        "request.hub.register-surface.1",
        1_300,
        ManifoldConnectionHubOperationRequest::RegisterSurface { surface },
    );
    assert!(host.apply_lifecycle(&register_surface).applied);
}

fn acquire_lease(host: &mut ManifoldConnectionHubAuthority, epoch: u64) {
    let acquire = request(
        host,
        "request.hub.acquire-surface.1",
        1_400,
        ManifoldConnectionHubOperationRequest::AcquireSurfaceLease {
            lease_id: id("lease.surface.media-player.friend"),
            session_id: id("session.friend-phone.primary"),
            expected_transport_epoch: epoch,
            surface_id: id("surface.media-player.controls"),
            requested_ttl_ms: 50_000,
        },
    );
    assert!(host.apply_lifecycle(&acquire).applied);
}

#[test]
fn logical_session_survives_transport_replacement_and_replay_stays_closed() {
    let mut host = ManifoldConnectionHubAuthority::new(policy()).unwrap();
    let trust_request = trust(&mut host);
    open_session(&mut host);
    let replace = request(
        &host,
        "request.hub.replace-transport.1",
        1_200,
        ManifoldConnectionHubOperationRequest::ReplaceTransport {
            session_id: id("session.friend-phone.primary"),
            expected_transport_epoch: 1,
            transport: ManifoldConnectionHubTransportBinding {
                transport_id: id("transport.websocket.second"),
                evidence_id: id("evidence.transport.second"),
                attached_at_ms: 1_200,
            },
        },
    );
    let receipt = host.replace_transport(&replace);
    assert!(receipt.applied);
    let session = receipt.session.unwrap();
    assert_eq!(session.session_id, id("session.friend-phone.primary"));
    assert_eq!(session.transport_epoch, 2);

    let before = host.snapshot_json().unwrap();
    let replay = host.trust_controller(&trust_request);
    assert!(!replay.applied);
    assert_eq!(
        replay.rejection_reason,
        Some(ManifoldConnectionHubRejectionReason::Replay)
    );
    assert_eq!(host.snapshot_json().unwrap(), before);

    let stale = request(
        &host,
        "request.hub.replace-transport.stale",
        1_300,
        ManifoldConnectionHubOperationRequest::ReplaceTransport {
            session_id: id("session.friend-phone.primary"),
            expected_transport_epoch: 1,
            transport: ManifoldConnectionHubTransportBinding {
                transport_id: id("transport.websocket.third"),
                evidence_id: id("evidence.transport.third"),
                attached_at_ms: 1_300,
            },
        },
    );
    assert_eq!(
        host.replace_transport(&stale).rejection_reason,
        Some(ManifoldConnectionHubRejectionReason::TransportEpochMismatch)
    );
}

#[test]
fn provider_surface_lease_command_and_provider_death_flow_is_closed() {
    let mut host = ManifoldConnectionHubAuthority::new(policy()).unwrap();
    trust(&mut host);
    open_session(&mut host);
    register_provider_and_surface(&mut host);
    acquire_lease(&mut host, 1);

    let replace = request(
        &host,
        "request.hub.replace-transport.after-lease",
        1_500,
        ManifoldConnectionHubOperationRequest::ReplaceTransport {
            session_id: id("session.friend-phone.primary"),
            expected_transport_epoch: 1,
            transport: ManifoldConnectionHubTransportBinding {
                transport_id: id("transport.websocket.reconnected"),
                evidence_id: id("evidence.transport.reconnected"),
                attached_at_ms: 1_500,
            },
        },
    );
    assert!(host.replace_transport(&replace).applied);
    assert_eq!(host.snapshot().state.surface_leases.len(), 1);

    let stale_command = request(
        &host,
        "request.hub.command.stale-epoch",
        1_600,
        ManifoldConnectionHubOperationRequest::AuthorizeSurfaceCommand {
            session_id: id("session.friend-phone.primary"),
            expected_transport_epoch: 1,
            lease_id: id("lease.surface.media-player.friend"),
            command_id: id("command.player.play"),
        },
    );
    assert_eq!(
        host.apply_lifecycle(&stale_command).rejection_reason,
        Some(ManifoldConnectionHubRejectionReason::TransportEpochMismatch)
    );
    let command = request(
        &host,
        "request.hub.command.current-epoch",
        1_600,
        ManifoldConnectionHubOperationRequest::AuthorizeSurfaceCommand {
            session_id: id("session.friend-phone.primary"),
            expected_transport_epoch: 2,
            lease_id: id("lease.surface.media-player.friend"),
            command_id: id("command.player.play"),
        },
    );
    let receipt = host.apply_lifecycle(&command);
    assert!(receipt.applied);
    let authorization = receipt.command_authorization.unwrap();
    assert!(!authorization.proves_application_effect);
    assert_eq!(authorization.transport_epoch, 2);

    let death = request(
        &host,
        "request.hub.provider-died.1",
        1_700,
        ManifoldConnectionHubOperationRequest::UnregisterProvider {
            provider_id: id("provider.media-player"),
            provider_instance_id: id("provider-instance.media-player.1"),
            reason: id("provider-died"),
        },
    );
    let receipt = host.apply_lifecycle(&death);
    assert!(receipt.applied);
    assert!(host.snapshot().state.providers.is_empty());
    assert!(host.snapshot().state.surfaces.is_empty());
    assert!(host.snapshot().state.surface_leases.is_empty());
    assert!(receipt
        .cleaned_subject_ids
        .contains(&id("surface.media-player.controls")));
    assert!(receipt
        .cleaned_subject_ids
        .contains(&id("lease.surface.media-player.friend")));

    let admission = admission();
    let reuse = request(
        &host,
        "request.hub.register-provider.reused-admission",
        1_800,
        ManifoldConnectionHubOperationRequest::RegisterProvider {
            provider_id: id("provider.media-player"),
            provider_instance_id: id("provider-instance.media-player.2"),
            admission_use_request_id: id("request.admission.use-provider-register"),
        },
    );
    let before = host.snapshot_json().unwrap();
    assert_eq!(
        host.register_provider(admission.snapshot(), &reuse)
            .rejection_reason,
        Some(ManifoldConnectionHubRejectionReason::Replay)
    );
    assert_eq!(host.snapshot_json().unwrap(), before);
}

#[test]
fn restart_is_byte_stable_and_rejects_unknown_fields_and_lineage_damage() {
    let mut host = ManifoldConnectionHubAuthority::new(policy()).unwrap();
    trust(&mut host);
    open_session(&mut host);
    let bytes = host.snapshot_json().unwrap();
    let restarted = ManifoldConnectionHubAuthority::restart_from_json(&bytes).unwrap();
    assert_eq!(restarted.snapshot_json().unwrap(), bytes);

    let mut request_value = serde_json::to_value(request(
        &host,
        "request.hub.damage.unknown",
        1_300,
        ManifoldConnectionHubOperationRequest::Expire,
    ))
    .unwrap();
    request_value["shell"] = serde_json::json!("forbidden");
    assert!(serde_json::from_value::<ManifoldConnectionHubRequest>(request_value).is_err());

    let mut snapshot = restarted.snapshot().clone();
    snapshot.state.sessions[0].transport_epoch = 0;
    let json = serde_json::to_string(&snapshot).unwrap();
    assert!(ManifoldConnectionHubAuthority::restart_from_json(&json).is_err());

    let mut snapshot = restarted.snapshot().clone();
    snapshot.audit_events[0].request_sha256 = digest("f");
    let json = serde_json::to_string(&snapshot).unwrap();
    assert!(ManifoldConnectionHubAuthority::restart_from_json(&json).is_err());
}

#[test]
fn identity_capability_and_provider_admission_substitution_fail_without_mutation() {
    let mut host = ManifoldConnectionHubAuthority::new(policy()).unwrap();
    trust(&mut host);
    let before = host.snapshot_json().unwrap();
    let wrong_identity = request(
        &host,
        "request.hub.open-session.wrong-identity",
        1_100,
        ManifoldConnectionHubOperationRequest::OpenSession {
            session_id: id("session.substituted"),
            controller_id: id("controller.friend-phone"),
            public_identity_sha256: digest("e"),
            transport: ManifoldConnectionHubTransportBinding {
                transport_id: id("transport.substituted"),
                evidence_id: id("evidence.transport.substituted"),
                attached_at_ms: 1_100,
            },
            requested_ttl_ms: 10_000,
        },
    );
    assert_eq!(
        host.open_session(&wrong_identity).rejection_reason,
        Some(ManifoldConnectionHubRejectionReason::ControllerNotTrusted)
    );
    assert_eq!(host.snapshot_json().unwrap(), before);

    let mut damaged_admission = admission().snapshot().clone();
    damaged_admission
        .audit_events
        .last_mut()
        .unwrap()
        .use_authorization
        .as_mut()
        .unwrap()
        .token
        .client_lock_fingerprint = digest("e");
    let register = request(
        &host,
        "request.hub.register-provider.damaged",
        1_200,
        ManifoldConnectionHubOperationRequest::RegisterProvider {
            provider_id: id("provider.media-player"),
            provider_instance_id: id("provider-instance.media-player.damage"),
            admission_use_request_id: id("request.admission.use-provider-register"),
        },
    );
    assert_eq!(
        host.register_provider(&damaged_admission, &register)
            .rejection_reason,
        Some(ManifoldConnectionHubRejectionReason::ProviderAdmissionRejected)
    );
    assert_eq!(host.snapshot_json().unwrap(), before);
}

#[test]
fn explicit_session_revoke_and_expiry_remove_derivative_state() {
    let mut host = ManifoldConnectionHubAuthority::new(policy()).unwrap();
    trust(&mut host);
    open_session(&mut host);
    register_provider_and_surface(&mut host);
    acquire_lease(&mut host, 1);
    let revoke = request(
        &host,
        "request.hub.revoke-session.1",
        2_000,
        ManifoldConnectionHubOperationRequest::RevokeSession {
            session_id: id("session.friend-phone.primary"),
            reason: id("wearer-revoked"),
        },
    );
    let receipt = host.apply_lifecycle(&revoke);
    assert!(receipt.applied);
    assert!(host.snapshot().state.sessions.is_empty());
    assert!(host.snapshot().state.surface_leases.is_empty());

    let mut expiring = ManifoldConnectionHubAuthority::new(policy()).unwrap();
    trust(&mut expiring);
    let expire = request(
        &expiring,
        "request.hub.expire-controller.1",
        91_001,
        ManifoldConnectionHubOperationRequest::Expire,
    );
    let receipt = expiring.apply_lifecycle(&expire);
    assert!(receipt.applied);
    assert!(expiring.snapshot().state.trusted_controllers.is_empty());
    assert!(receipt
        .cleaned_subject_ids
        .contains(&id("controller.friend-phone")));
}

#[test]
fn deterministic_request_and_snapshot_bytes_are_stable() {
    let host = ManifoldConnectionHubAuthority::new(policy()).unwrap();
    let request = request(
        &host,
        "request.hub.stable.1",
        1_000,
        ManifoldConnectionHubOperationRequest::Expire,
    );
    assert_eq!(
        serde_json::to_string(&request).unwrap(),
        r#"{"$schema":"rusty.manifold.connection_hub.request.v1","request_id":"request.hub.stable.1","expected_authority_revision":1,"requested_at_ms":1000,"operation":{"type":"expire"}}"#
    );
    let bytes = host.snapshot_json().unwrap();
    assert_eq!(
        ManifoldConnectionHubAuthority::restart_from_json(&bytes)
            .unwrap()
            .snapshot_json()
            .unwrap(),
        bytes
    );
}

#[test]
fn committed_fixtures_match_types_and_unknown_field_damage_rejects() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let fixture_policy: ManifoldConnectionHubPolicy = serde_json::from_str(
        &std::fs::read_to_string(root.join("fixtures/connection-hub/policy.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(fixture_policy, policy());
    let initial =
        std::fs::read_to_string(root.join("fixtures/connection-hub/initial-snapshot.json"))
            .unwrap();
    let host = ManifoldConnectionHubAuthority::restart_from_json(&initial).unwrap();
    assert_eq!(host.snapshot_json().unwrap(), initial);
    let request: ManifoldConnectionHubRequest = serde_json::from_str(
        &std::fs::read_to_string(
            root.join("fixtures/connection-hub/trust-controller-request.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(
        ManifoldConnectionHubAuthority::new(fixture_policy)
            .unwrap()
            .trust_controller(&request)
            .applied
    );
    let damaged = std::fs::read_to_string(
        root.join("fixtures/connection-hub/trust-controller-request.unknown-field.damaged.json"),
    )
    .unwrap();
    assert!(serde_json::from_str::<ManifoldConnectionHubRequest>(&damaged).is_err());
}
