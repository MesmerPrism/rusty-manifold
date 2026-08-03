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
            provider_id: id("provider.media-player"),
            client_id: identity().client_id,
            client_lock_id: id("client-lock.media-player"),
            client_lock_sha256: digest("b"),
            surface_contract_sha256: digest("d"),
            allowed_commands: vec![
                ManifoldConnectionHubSurfaceCommand {
                    command_id: id("command.player.pause"),
                    required_controller_capability: id("capability.player.pause"),
                },
                ManifoldConnectionHubSurfaceCommand {
                    command_id: id("command.player.play"),
                    required_controller_capability: id("capability.player.play"),
                },
            ],
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

fn lifecycle_context(
    request: &ManifoldConnectionHubRequest,
) -> ManifoldConnectionHubOwnerContext<'_> {
    ManifoldConnectionHubOwnerContext::lifecycle(request.requested_at_ms)
}

fn operator_context(
    request: &ManifoldConnectionHubRequest,
) -> ManifoldConnectionHubOwnerContext<'_> {
    let (ManifoldConnectionHubOperationRequest::TrustController {
        operator_evidence_id,
        ..
    }
    | ManifoldConnectionHubOperationRequest::ForgetController {
        operator_evidence_id,
        ..
    }) = &request.operation
    else {
        panic!("operator context requested for non-operator operation");
    };
    ManifoldConnectionHubOwnerContext::operator_decision(
        request.requested_at_ms,
        operator_evidence_id,
    )
}

fn provider_context<'a>(
    request: &ManifoldConnectionHubRequest,
    admission: &'a ManifoldAdmissionSnapshot,
) -> ManifoldConnectionHubOwnerContext<'a> {
    ManifoldConnectionHubOwnerContext::provider_admission(request.requested_at_ms, admission)
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
    assert!(
        host.trust_controller(&request, operator_context(&request))
            .applied
    );
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
    let receipt = host.open_session(&request, lifecycle_context(&request));
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
        host.register_provider(&register, provider_context(&register, admission.snapshot()))
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
    assert!(
        host.apply_lifecycle(&register_surface, lifecycle_context(&register_surface))
            .applied
    );
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
    assert!(
        host.apply_lifecycle(&acquire, lifecycle_context(&acquire))
            .applied
    );
}

fn host_with_surface_lease() -> ManifoldConnectionHubAuthority {
    let mut host = ManifoldConnectionHubAuthority::new(policy()).unwrap();
    trust(&mut host);
    open_session(&mut host);
    register_provider_and_surface(&mut host);
    acquire_lease(&mut host, 1);
    host
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
    let receipt = host.replace_transport(&replace, lifecycle_context(&replace));
    assert!(receipt.applied);
    let session = receipt.session.unwrap();
    assert_eq!(session.session_id, id("session.friend-phone.primary"));
    assert_eq!(session.transport_epoch, 2);

    let before = host.snapshot_json().unwrap();
    let replay = host.trust_controller(&trust_request, operator_context(&trust_request));
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
        host.replace_transport(&stale, lifecycle_context(&stale))
            .rejection_reason,
        Some(ManifoldConnectionHubRejectionReason::TransportEpochMismatch)
    );
}

#[test]
#[allow(clippy::too_many_lines)]
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
    assert!(
        host.replace_transport(&replace, lifecycle_context(&replace))
            .applied
    );
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
            typed_params_sha256: digest("1"),
        },
    );
    assert_eq!(
        host.apply_lifecycle(&stale_command, lifecycle_context(&stale_command))
            .rejection_reason,
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
            typed_params_sha256: digest("1"),
        },
    );
    let receipt = host.apply_lifecycle(&command, lifecycle_context(&command));
    assert!(receipt.applied);
    let authorization = receipt.command_authorization.unwrap();
    assert!(!authorization.proves_application_effect);
    assert_eq!(authorization.transport_epoch, 2);
    assert_eq!(authorization.provider_id, id("provider.media-player"));
    assert_eq!(authorization.surface_contract_sha256, digest("d"));
    assert_eq!(
        authorization.required_controller_capability,
        id("capability.player.play")
    );
    assert_eq!(authorization.typed_params_sha256, digest("1"));

    let mut relabel = command.clone();
    relabel.expected_authority_revision = host.snapshot().state.authority_revision;
    let ManifoldConnectionHubOperationRequest::AuthorizeSurfaceCommand {
        typed_params_sha256,
        ..
    } = &mut relabel.operation
    else {
        panic!("command request");
    };
    *typed_params_sha256 = digest("2");
    let before = host.snapshot_json().unwrap();
    assert_eq!(
        host.apply_lifecycle(&relabel, lifecycle_context(&relabel))
            .rejection_reason,
        Some(ManifoldConnectionHubRejectionReason::Replay)
    );
    assert_eq!(host.snapshot_json().unwrap(), before);

    let distinct_params = request(
        &host,
        "request.hub.command.distinct-params",
        1_650,
        ManifoldConnectionHubOperationRequest::AuthorizeSurfaceCommand {
            session_id: id("session.friend-phone.primary"),
            expected_transport_epoch: 2,
            lease_id: id("lease.surface.media-player.friend"),
            command_id: id("command.player.play"),
            typed_params_sha256: digest("2"),
        },
    );
    let distinct_receipt =
        host.apply_lifecycle(&distinct_params, lifecycle_context(&distinct_params));
    assert!(distinct_receipt.applied);
    let distinct_authorization = distinct_receipt.command_authorization.unwrap();
    assert_eq!(distinct_authorization.typed_params_sha256, digest("2"));
    assert_ne!(
        distinct_authorization.authorization_id,
        authorization.authorization_id
    );

    let invalid_digest = request(
        &host,
        "request.hub.command.invalid-digest",
        1_675,
        ManifoldConnectionHubOperationRequest::AuthorizeSurfaceCommand {
            session_id: id("session.friend-phone.primary"),
            expected_transport_epoch: 2,
            lease_id: id("lease.surface.media-player.friend"),
            command_id: id("command.player.play"),
            typed_params_sha256: "sha256:ABC".to_owned(),
        },
    );
    let before = host.snapshot_json().unwrap();
    assert_eq!(
        host.apply_lifecycle(&invalid_digest, lifecycle_context(&invalid_digest))
            .rejection_reason,
        Some(ManifoldConnectionHubRejectionReason::InvalidTypedParamsDigest)
    );
    assert_eq!(host.snapshot_json().unwrap(), before);

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
    let receipt = host.apply_lifecycle(&death, lifecycle_context(&death));
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
        host.register_provider(&reuse, provider_context(&reuse, admission.snapshot()))
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
        host.open_session(&wrong_identity, lifecycle_context(&wrong_identity))
            .rejection_reason,
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
        host.register_provider(&register, provider_context(&register, &damaged_admission),)
            .rejection_reason,
        Some(ManifoldConnectionHubRejectionReason::ProviderAdmissionRejected)
    );
    assert_eq!(host.snapshot_json().unwrap(), before);
}

#[test]
fn serialized_time_operator_claims_and_missing_owner_admission_never_authorize() {
    let mut host = ManifoldConnectionHubAuthority::new(policy()).unwrap();
    let trust_request = request(
        &host,
        "request.hub.owner-context.trust",
        1_000,
        ManifoldConnectionHubOperationRequest::TrustController {
            controller_id: id("controller.owner-context"),
            public_identity_sha256: digest("c"),
            capabilities: vec![id("capability.player.play")],
            operator_evidence_id: id("evidence.operator.wearer-action"),
            requested_ttl_ms: 10_000,
        },
    );
    let before = host.snapshot_json().unwrap();
    let trusted_evidence = id("evidence.operator.wearer-action");
    let wrong_time = ManifoldConnectionHubOwnerContext::operator_decision(999, &trusted_evidence);
    assert_eq!(
        host.trust_controller(&trust_request, wrong_time)
            .rejection_reason,
        Some(ManifoldConnectionHubRejectionReason::OwnerContextMismatch)
    );
    assert_eq!(host.snapshot_json().unwrap(), before);

    let wrong_evidence = id("evidence.operator.remote-claim");
    let wrong_operator = ManifoldConnectionHubOwnerContext::operator_decision(
        trust_request.requested_at_ms,
        &wrong_evidence,
    );
    assert_eq!(
        host.trust_controller(&trust_request, wrong_operator)
            .rejection_reason,
        Some(ManifoldConnectionHubRejectionReason::OwnerContextMismatch)
    );
    assert_eq!(host.snapshot_json().unwrap(), before);

    let admitted = admission();
    let register = request(
        &host,
        "request.hub.owner-context.provider",
        1_200,
        ManifoldConnectionHubOperationRequest::RegisterProvider {
            provider_id: id("provider.media-player"),
            provider_instance_id: id("provider-instance.media-player.owner-context"),
            admission_use_request_id: id("request.admission.use-provider-register"),
        },
    );
    assert_eq!(
        host.register_provider(&register, lifecycle_context(&register))
            .rejection_reason,
        Some(ManifoldConnectionHubRejectionReason::OwnerContextMismatch)
    );
    assert_eq!(host.snapshot_json().unwrap(), before);

    assert!(
        host.register_provider(&register, provider_context(&register, admitted.snapshot()),)
            .applied
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn provider_grant_binds_provider_contract_and_controller_capability() {
    let mut host = ManifoldConnectionHubAuthority::new(policy()).unwrap();
    let admitted = admission();
    let wrong_provider = request(
        &host,
        "request.hub.register-provider.wrong-family",
        1_200,
        ManifoldConnectionHubOperationRequest::RegisterProvider {
            provider_id: id("provider.substituted"),
            provider_instance_id: id("provider-instance.substituted.1"),
            admission_use_request_id: id("request.admission.use-provider-register"),
        },
    );
    let before = host.snapshot_json().unwrap();
    assert_eq!(
        host.register_provider(
            &wrong_provider,
            provider_context(&wrong_provider, admitted.snapshot()),
        )
        .rejection_reason,
        Some(ManifoldConnectionHubRejectionReason::ProviderAdmissionRejected)
    );
    assert_eq!(host.snapshot_json().unwrap(), before);

    let register = request(
        &host,
        "request.hub.register-provider.bound-family",
        1_200,
        ManifoldConnectionHubOperationRequest::RegisterProvider {
            provider_id: id("provider.media-player"),
            provider_instance_id: id("provider-instance.media-player.bound"),
            admission_use_request_id: id("request.admission.use-provider-register"),
        },
    );
    assert!(
        host.register_provider(&register, provider_context(&register, admitted.snapshot()))
            .applied
    );

    let exact_commands = policy().provider_grants[0].allowed_commands.clone();
    let surface = |registered_at_ms| ManifoldConnectionHubSurface {
        schema_id: schema(SURFACE_SCHEMA),
        surface_id: id("surface.media-player.bound"),
        provider_id: id("provider.media-player"),
        provider_instance_id: id("provider-instance.media-player.bound"),
        display_label: "Media Player".to_owned(),
        description: "Bound playback controls".to_owned(),
        surface_contract_sha256: digest("d"),
        commands: exact_commands.clone(),
        registered_at_ms,
    };

    let mut wrong_contract_surface = surface(1_300);
    wrong_contract_surface.surface_contract_sha256 = digest("e");
    let wrong_contract = request(
        &host,
        "request.hub.register-surface.wrong-contract",
        1_300,
        ManifoldConnectionHubOperationRequest::RegisterSurface {
            surface: wrong_contract_surface,
        },
    );
    let before = host.snapshot_json().unwrap();
    assert_eq!(
        host.apply_lifecycle(&wrong_contract, lifecycle_context(&wrong_contract))
            .rejection_reason,
        Some(ManifoldConnectionHubRejectionReason::SurfaceNotAllowed)
    );
    assert_eq!(host.snapshot_json().unwrap(), before);

    let mut lowered_capability_surface = surface(1_301);
    lowered_capability_surface.commands[1].required_controller_capability =
        id("capability.player.pause");
    let lowered_capability = request(
        &host,
        "request.hub.register-surface.lowered-capability",
        1_301,
        ManifoldConnectionHubOperationRequest::RegisterSurface {
            surface: lowered_capability_surface,
        },
    );
    assert_eq!(
        host.apply_lifecycle(&lowered_capability, lifecycle_context(&lowered_capability),)
            .rejection_reason,
        Some(ManifoldConnectionHubRejectionReason::SurfaceNotAllowed)
    );
    assert_eq!(host.snapshot_json().unwrap(), before);

    let exact = request(
        &host,
        "request.hub.register-surface.exact-grant",
        1_302,
        ManifoldConnectionHubOperationRequest::RegisterSurface {
            surface: surface(1_302),
        },
    );
    assert!(
        host.apply_lifecycle(&exact, lifecycle_context(&exact))
            .applied
    );
    let provider = &host.snapshot().state.providers[0];
    assert_eq!(provider.provider_id, id("provider.media-player"));
    assert_eq!(provider.surface_contract_sha256, digest("d"));
    assert_eq!(provider.allowed_commands, exact_commands);

    let mut damaged = host.snapshot().clone();
    damaged.policy.provider_grants[0].provider_id = id("provider.substituted");
    assert!(ManifoldConnectionHubAuthority::restart_from_json(
        &serde_json::to_string(&damaged).unwrap()
    )
    .is_err());

    let mut damaged = host.snapshot().clone();
    damaged.policy.provider_grants[0].surface_contract_sha256 = digest("e");
    assert!(ManifoldConnectionHubAuthority::restart_from_json(
        &serde_json::to_string(&damaged).unwrap()
    )
    .is_err());

    let mut damaged = host.snapshot().clone();
    damaged.policy.provider_grants[0].allowed_commands[1].required_controller_capability =
        id("capability.player.pause");
    assert!(ManifoldConnectionHubAuthority::restart_from_json(
        &serde_json::to_string(&damaged).unwrap()
    )
    .is_err());
}

#[test]
fn command_spam_cannot_consume_terminal_cleanup_capacity_or_weaken_replay() {
    let mut host = host_with_surface_lease();
    let mut first_command = None;
    while host.snapshot().audit_events.len() < MAX_ORDINARY_AUDIT_EVENTS {
        let sequence = host.snapshot().audit_events.len();
        let command = request(
            &host,
            &format!("request.hub.command.spam.{sequence}"),
            2_000 + sequence as u64,
            ManifoldConnectionHubOperationRequest::AuthorizeSurfaceCommand {
                session_id: id("session.friend-phone.primary"),
                expected_transport_epoch: 1,
                lease_id: id("lease.surface.media-player.friend"),
                command_id: id("command.player.play"),
                typed_params_sha256: typed_sha256(&sequence),
            },
        );
        if first_command.is_none() {
            first_command = Some(command.clone());
        }
        assert!(
            host.apply_lifecycle(&command, lifecycle_context(&command))
                .applied
        );
    }
    assert_eq!(
        host.snapshot().applied_request_ids.len(),
        MAX_ORDINARY_AUDIT_EVENTS
    );
    assert_eq!(
        host.snapshot().applied_request_sha256.len(),
        MAX_ORDINARY_AUDIT_EVENTS
    );

    let blocked = request(
        &host,
        "request.hub.command.after-ordinary-capacity",
        6_000,
        ManifoldConnectionHubOperationRequest::AuthorizeSurfaceCommand {
            session_id: id("session.friend-phone.primary"),
            expected_transport_epoch: 1,
            lease_id: id("lease.surface.media-player.friend"),
            command_id: id("command.player.play"),
            typed_params_sha256: digest("f"),
        },
    );
    let before_cleanup = host.snapshot_json().unwrap();
    assert_eq!(
        host.apply_lifecycle(&blocked, lifecycle_context(&blocked))
            .rejection_reason,
        Some(ManifoldConnectionHubRejectionReason::CapacityExceeded)
    );
    assert_eq!(host.snapshot_json().unwrap(), before_cleanup);

    let revoke = request(
        &host,
        "request.hub.revoke-after-command-capacity",
        6_001,
        ManifoldConnectionHubOperationRequest::RevokeSession {
            session_id: id("session.friend-phone.primary"),
            reason: id("capacity-cleanup"),
        },
    );
    let receipt = host.apply_lifecycle(&revoke, lifecycle_context(&revoke));
    assert!(receipt.applied);
    assert_eq!(
        host.snapshot().applied_request_ids.len(),
        MAX_ORDINARY_AUDIT_EVENTS + 1
    );
    assert!(host.snapshot().state.sessions.is_empty());
    assert!(host.snapshot().state.surface_leases.is_empty());

    let first_command = first_command.unwrap();
    let replay = host.apply_lifecycle(&first_command, lifecycle_context(&first_command));
    assert_eq!(
        replay.rejection_reason,
        Some(ManifoldConnectionHubRejectionReason::Replay)
    );
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
    let receipt = host.apply_lifecycle(&revoke, lifecycle_context(&revoke));
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
    let receipt = expiring.apply_lifecycle(&expire, lifecycle_context(&expire));
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
            .trust_controller(&request, operator_context(&request))
            .applied
    );
    let damaged = std::fs::read_to_string(
        root.join("fixtures/connection-hub/trust-controller-request.unknown-field.damaged.json"),
    )
    .unwrap();
    assert!(serde_json::from_str::<ManifoldConnectionHubRequest>(&damaged).is_err());

    let command_json = std::fs::read_to_string(
        root.join("fixtures/connection-hub/authorize-command-request.json"),
    )
    .unwrap();
    let command: ManifoldConnectionHubRequest = serde_json::from_str(&command_json).unwrap();
    let mut command_host = host_with_surface_lease();
    let receipt = command_host.apply_lifecycle(&command, lifecycle_context(&command));
    assert!(receipt.applied);
    assert_eq!(
        receipt.command_authorization.unwrap().typed_params_sha256,
        digest("1")
    );

    let damaged_digest_json = std::fs::read_to_string(
        root.join("fixtures/connection-hub/authorize-command-request.bad-digest.damaged.json"),
    )
    .unwrap();
    let damaged_digest: ManifoldConnectionHubRequest =
        serde_json::from_str(&damaged_digest_json).unwrap();
    let mut damaged_host = host_with_surface_lease();
    assert_eq!(
        damaged_host
            .apply_lifecycle(&damaged_digest, lifecycle_context(&damaged_digest))
            .rejection_reason,
        Some(ManifoldConnectionHubRejectionReason::InvalidTypedParamsDigest)
    );

    let mut inline_params: serde_json::Value = serde_json::from_str(&command_json).unwrap();
    inline_params["operation"]["details"]["params"] =
        serde_json::json!({"high_rate_bytes": [1, 2, 3]});
    assert!(serde_json::from_value::<ManifoldConnectionHubRequest>(inline_params).is_err());
}
