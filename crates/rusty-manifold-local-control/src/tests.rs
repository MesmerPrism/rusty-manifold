use super::*;
use rusty_manifold_admission::{
    ManifoldAdmissionGrant, ManifoldAdmissionSnapshot, ADMISSION_SNAPSHOT_SCHEMA,
};
use rusty_manifold_model::{
    AuthorityRole, ClockHealth, EndpointDescriptor, EndpointSecurity, EndpointTransport,
    EndpointVisibility, ManifoldCommandDescriptor, ManifoldHostManifest,
    ManifoldStreamRegistrySnapshot,
};
use rusty_manifold_runtime_host::{
    ManifoldRuntimeCommandDescriptor, ManifoldRuntimeHostSnapshot, HOST_SNAPSHOT_SCHEMA,
};

fn id(value: &str) -> DottedId {
    DottedId::new(value).expect("id")
}

fn schema(value: &str) -> SchemaId {
    SchemaId::new(value).expect("schema")
}

fn identity() -> ManifoldClientIdentity {
    ManifoldClientIdentity {
        client_id: id("adapter.quest.trusted_local_http"),
        platform_subject: "io.github.mesmerprism.rustyquest.localcontrol".to_owned(),
        signing_fingerprint: format!("sha256:{}", "a1".repeat(32)),
    }
}

fn clock(sequence: u64, wall_ms: u64) -> ManifoldClockSnapshot {
    ManifoldClockSnapshot {
        schema_id: schema("rusty.manifold.clock.snapshot.v1"),
        clock_domain: id("clock.quest.monotonic"),
        clock_epoch_id: id("clock_epoch.quest.local_control"),
        sequence,
        monotonic_elapsed_ns: wall_ms * 1_000_000,
        wall_unix_ms: i64::try_from(wall_ms).expect("test wall"),
        read_uncertainty_ns: 1_000,
        health: ClockHealth::Healthy,
        wall_clock_adjustment_count: 0,
    }
}

fn commands() -> Vec<ManifoldLocalControlCommandDescriptor> {
    vec![
        ManifoldLocalControlCommandDescriptor {
            command_id: id("command.local.describe"),
            capability_id: id("capability.local.describe"),
            required_lease_scope: None,
            params_type_id: None,
            safety_class: SafetyClass::ReadOnly,
        },
        ManifoldLocalControlCommandDescriptor {
            command_id: id("command.local.pause"),
            capability_id: id("capability.local.pause"),
            required_lease_scope: Some(id("scope.local.player")),
            params_type_id: None,
            safety_class: SafetyClass::BoundedMutation,
        },
        ManifoldLocalControlCommandDescriptor {
            command_id: id("command.local.play"),
            capability_id: id("capability.local.play"),
            required_lease_scope: Some(id("scope.local.player")),
            params_type_id: None,
            safety_class: SafetyClass::BoundedMutation,
        },
        ManifoldLocalControlCommandDescriptor {
            command_id: id("command.local.select_video"),
            capability_id: id("capability.local.select_video"),
            required_lease_scope: Some(id("scope.local.player")),
            params_type_id: Some(id("params.local.video_selection")),
            safety_class: SafetyClass::BoundedMutation,
        },
    ]
}

fn policy(max_commands_per_window: u16) -> ManifoldLocalControlPolicy {
    ManifoldLocalControlPolicy {
        schema_id: schema(LOCAL_CONTROL_POLICY_SCHEMA),
        authority_id: id("authority.quest.local_control"),
        trusted_adapter_id: id("adapter.quest.trusted_local_http"),
        adapter_identity: identity(),
        controller_id: id("controller.apple.collaborator"),
        controller_lease_scope: id("scope.local.player"),
        controller_lease_capability_id: id("capability.local.controller"),
        commands: commands(),
        max_window_ttl_ms: 60_000,
        max_session_ttl_ms: 10_000,
        idle_timeout_ms: 2_000,
        rate_window_ms: 1_000,
        max_commands_per_window,
    }
}

fn admission(policy: &ManifoldLocalControlPolicy) -> ManifoldAdmissionAuthority {
    ManifoldAdmissionAuthority::from_snapshot(ManifoldAdmissionSnapshot {
        schema_id: schema(ADMISSION_SNAPSHOT_SCHEMA),
        authority_id: id("authority.quest.local_control.admission"),
        authority_revision: Revision::INITIAL,
        grants: vec![ManifoldAdmissionGrant {
            grant_id: id("grant.quest.local_controller"),
            client_lock_id: id("lock.quest.local_controller"),
            client_lock_fingerprint: format!("sha256:{}", "b2".repeat(32)),
            identity: policy.adapter_identity.clone(),
            capabilities: command_capabilities(policy),
            expires_at_ms: 60_000,
            revoked: false,
        }],
        active_tokens: Vec::new(),
        revoked_token_ids: Vec::new(),
        consumed_request_ids: Vec::new(),
        consumed_use_request_ids: Vec::new(),
        reviewed_sweep_ids: Vec::new(),
        audit_events: Vec::new(),
        max_token_ttl_ms: policy.max_session_ttl_ms,
    })
    .expect("admission")
}

fn lease_authority(policy: &ManifoldLocalControlPolicy) -> ManifoldAuthoritySnapshot {
    let descriptors = policy
        .commands
        .iter()
        .map(|command| ManifoldCommandDescriptor {
            schema_id: schema("rusty.manifold.command.descriptor.v1"),
            command_id: command.command_id.clone(),
            target_scope: id("target.quest.video_player"),
            input_schema: schema("rusty.manifold.command.input.local_control.v1"),
            required_capability: command.capability_id.clone(),
            required_lease_scope: command.required_lease_scope.clone(),
            safety_class: command.safety_class,
            operator_confirmation_required: false,
        })
        .collect::<Vec<_>>();
    let mut capabilities = command_capabilities(policy);
    capabilities.sort();
    ManifoldAuthoritySnapshot {
        schema_id: schema("rusty.manifold.authority.snapshot.v2"),
        authority_id: policy.authority_id.clone(),
        authority_revision: Revision::INITIAL,
        host_manifest: ManifoldHostManifest {
            schema_id: schema("rusty.manifold.host.manifest.v1"),
            host_id: id("host.quest.local_control"),
            authority_role: AuthorityRole::Primary,
            host_category: Some(id("host.quest.local_control")),
            clock_domain: id("clock.quest.monotonic"),
            endpoints: vec![EndpointDescriptor {
                endpoint_id: id("endpoint.local_control.in_process"),
                visibility: EndpointVisibility::Loopback,
                transport: EndpointTransport::InProcess,
                security: EndpointSecurity::LocalProcess,
            }],
            capabilities,
            supported_backends: Vec::new(),
            permissions: Vec::new(),
            lifecycle_limits: Vec::new(),
            missing_requirements: Vec::new(),
        },
        clock_snapshot: clock(1, 1_000),
        stream_registry: ManifoldStreamRegistrySnapshot {
            schema_id: schema("rusty.manifold.stream.registry_snapshot.v1"),
            registry_revision: Revision::INITIAL,
            streams: Vec::new(),
        },
        module_runtime_states: Vec::new(),
        command_ids: policy
            .commands
            .iter()
            .map(|command| command.command_id.clone())
            .collect(),
        command_descriptors: descriptors,
        active_leases: Vec::new(),
        revoked_control_lease_tombstones: Vec::new(),
        active_stream_subscriptions: Vec::new(),
    }
}

fn runtime_host(policy: &ManifoldLocalControlPolicy) -> ManifoldRuntimeHost {
    ManifoldRuntimeHost::from_snapshot(ManifoldRuntimeHostSnapshot {
        schema_id: schema(HOST_SNAPSHOT_SCHEMA),
        host_id: id("host.quest.local_control"),
        authority_revision: Revision::INITIAL,
        commands: policy
            .commands
            .iter()
            .map(|command| ManifoldRuntimeCommandDescriptor {
                command_id: command.command_id.clone(),
                required_lease_scope: command.required_lease_scope.clone(),
            })
            .collect(),
        leases: Vec::new(),
        applied_request_ids: Vec::new(),
        reviewed_sweep_ids: Vec::new(),
        reviewed_control_lease_adoption_ids: Vec::new(),
        reviewed_derivative_lease_revocation_ids: Vec::new(),
        audit_events: Vec::new(),
    })
    .expect("runtime host")
}

fn authority(max_commands_per_window: u16) -> ManifoldLocalControlAuthority {
    let policy = policy(max_commands_per_window);
    ManifoldLocalControlAuthority::new(
        policy.clone(),
        admission(&policy),
        lease_authority(&policy),
        runtime_host(&policy),
    )
    .expect("local control")
}

fn open_window(authority: &mut ManifoldLocalControlAuthority) {
    let receipt = authority.open_pairing_window(&ManifoldLocalControlWindowRequest {
        schema_id: schema(LOCAL_CONTROL_WINDOW_REQUEST_SCHEMA),
        request_id: id("request.local.window.open"),
        window_id: id("window.local.one"),
        expected_local_revision: Revision::INITIAL,
        opened_at_ms: 1_000,
        expires_at_ms: 10_000,
        wearer_evidence_id: id("evidence.wearer.window.open"),
    });
    assert!(receipt.opened, "{receipt:#?}");
}

fn admit(authority: &mut ManifoldLocalControlAuthority) -> ManifoldLocalControlAdmissionReceipt {
    authority.admit_controller(
        &ManifoldLocalControlAdmissionRequest {
            schema_id: schema(LOCAL_CONTROL_ADMISSION_REQUEST_SCHEMA),
            request_id: id("request.local.controller.admit"),
            expected_local_revision: Revision::new(2).expect("revision"),
            expected_admission_revision: Revision::INITIAL,
            expected_lease_authority_revision: Revision::INITIAL,
            expected_host_revision: Revision::INITIAL,
            evidence: ManifoldLocalControllerEvidence {
                schema_id: schema(LOCAL_CONTROL_CONTROLLER_EVIDENCE_SCHEMA),
                evidence_id: id("evidence.local.code.verified"),
                adapter_id: id("adapter.quest.trusted_local_http"),
                window_id: id("window.local.one"),
                controller_id: id("controller.apple.collaborator"),
                presentation: ManifoldLocalControlPairingPresentation::ManualEntry,
                pairing_code_verified: true,
                observed_at_ms: 1_100,
                expires_at_ms: 9_000,
            },
            requested_at_ms: 1_200,
            requested_session_ttl_ms: 5_000,
        },
        [7; 32],
        clock(2, 1_200),
    )
}

fn command_request(
    request_id: &str,
    command_id: &str,
    token_id: DottedId,
    local_revision: u64,
    admission_revision: u64,
    host_revision: u64,
    issued_at_ms: u64,
) -> ManifoldLocalControlCommandRequest {
    ManifoldLocalControlCommandRequest {
        schema_id: schema(LOCAL_CONTROL_COMMAND_REQUEST_SCHEMA),
        request_id: id(request_id),
        expected_local_revision: Revision::new(local_revision).expect("revision"),
        expected_admission_revision: Revision::new(admission_revision).expect("revision"),
        expected_host_revision: Revision::new(host_revision).expect("revision"),
        token_id,
        command_id: id(command_id),
        params_digest: None,
        issued_at_ms,
        expires_at_ms: issued_at_ms + 500,
    }
}

#[test]
fn disabled_open_admit_accept_and_revoke_preserve_authority_boundaries() {
    let mut authority = authority(8);
    assert_eq!(
        authority.safe_status().state,
        ManifoldLocalControlState::Disabled
    );
    open_window(&mut authority);
    assert_eq!(
        authority.safe_status().state,
        ManifoldLocalControlState::PairingWindowOpen
    );

    let admission = admit(&mut authority);
    assert!(admission.admitted);
    let token_id = admission
        .admission
        .as_ref()
        .and_then(|receipt| receipt.token.as_ref())
        .expect("token")
        .token_id
        .clone();
    let status = authority.safe_status();
    assert_eq!(status.state, ManifoldLocalControlState::ControllerActive);
    assert_eq!(
        status.controller_id,
        Some(id("controller.apple.collaborator"))
    );
    let status_json = serde_json::to_string(&status).expect("status json");
    assert!(!status_json.contains("token.session"));
    assert!(!status_json.contains("pairing"));

    let command = authority.accept_command(
        &command_request(
            "request.local.command.play",
            "command.local.play",
            token_id,
            3,
            2,
            2,
            2_000,
        ),
        2_000,
    );
    assert!(command.command_accepted);
    assert!(!command.proves_application_effect);
    assert!(command
        .admission_use
        .as_ref()
        .is_some_and(|item| item.applied));
    assert!(command
        .application
        .as_ref()
        .is_some_and(|item| item.applied));

    let revoke = authority.revoke_controller(
        &ManifoldLocalControlRevocationRequest {
            schema_id: schema(LOCAL_CONTROL_REVOCATION_REQUEST_SCHEMA),
            request_id: id("request.local.controller.revoke"),
            expected_local_revision: Revision::new(4).expect("revision"),
            expected_admission_revision: Revision::new(3).expect("revision"),
            expected_lease_authority_revision: Revision::new(2).expect("revision"),
            expected_host_revision: Revision::new(3).expect("revision"),
            reason: id("reason.wearer.revoked"),
            requested_at_ms: 2_100,
            evidence_id: id("evidence.wearer.revoke"),
        },
        clock(3, 2_100),
    );
    assert!(revoke.revoked, "{revoke:#?}");
    assert!(revoke
        .admission_revocation
        .as_ref()
        .is_some_and(|item| item.applied));
    assert!(revoke
        .host_adoption
        .as_ref()
        .is_some_and(|item| item.applied));
    assert_eq!(
        authority.safe_status().state,
        ManifoldLocalControlState::Disabled
    );
}

#[test]
fn pairing_evidence_is_exact_and_manual_code_verification_is_mandatory() {
    let mut authority = authority(8);
    open_window(&mut authority);
    let mut request = ManifoldLocalControlAdmissionRequest {
        schema_id: schema(LOCAL_CONTROL_ADMISSION_REQUEST_SCHEMA),
        request_id: id("request.local.controller.bad-evidence"),
        expected_local_revision: Revision::new(2).expect("revision"),
        expected_admission_revision: Revision::INITIAL,
        expected_lease_authority_revision: Revision::INITIAL,
        expected_host_revision: Revision::INITIAL,
        evidence: ManifoldLocalControllerEvidence {
            schema_id: schema(LOCAL_CONTROL_CONTROLLER_EVIDENCE_SCHEMA),
            evidence_id: id("evidence.local.code.unverified"),
            adapter_id: id("adapter.quest.trusted_local_http"),
            window_id: id("window.local.one"),
            controller_id: id("controller.apple.collaborator"),
            presentation: ManifoldLocalControlPairingPresentation::QrConvenience,
            pairing_code_verified: false,
            observed_at_ms: 1_100,
            expires_at_ms: 9_000,
        },
        requested_at_ms: 1_200,
        requested_session_ttl_ms: 5_000,
    };
    let rejected = authority.admit_controller(&request, [1; 32], clock(2, 1_200));
    assert_eq!(
        rejected.rejection_reason,
        Some(ManifoldLocalControlRejectionReason::PairingEvidenceInvalid)
    );
    request.evidence.pairing_code_verified = true;
    request.evidence.adapter_id = id("adapter.quest.substitute");
    let rejected = authority.admit_controller(&request, [2; 32], clock(2, 1_200));
    assert_eq!(
        rejected.rejection_reason,
        Some(ManifoldLocalControlRejectionReason::ReplayedRequest)
    );
    request.request_id = id("request.local.controller.substituted-adapter");
    let rejected = authority.admit_controller(&request, [3; 32], clock(2, 1_200));
    assert_eq!(
        rejected.rejection_reason,
        Some(ManifoldLocalControlRejectionReason::PairingEvidenceInvalid)
    );
}

#[test]
fn listener_failure_can_close_an_unadmitted_window() {
    let mut authority = authority(8);
    open_window(&mut authority);
    let request = ManifoldLocalControlDisableRequest {
        schema_id: schema(LOCAL_CONTROL_DISABLE_REQUEST_SCHEMA),
        request_id: id("request.local.disable.listener_failure"),
        expected_local_revision: Revision::new(2).expect("revision"),
        expected_admission_revision: Revision::INITIAL,
        expected_lease_authority_revision: Revision::INITIAL,
        expected_host_revision: Revision::INITIAL,
        reason: id("reason.listener.start_failed"),
        requested_at_ms: 1_010,
        evidence_id: id("evidence.listener.start_failed"),
    };
    let receipt = authority.disable(&request, clock(2, 1_010));
    assert!(receipt.disabled);
    assert_eq!(
        receipt.prior_state,
        ManifoldLocalControlState::PairingWindowOpen
    );
    assert!(receipt.revocation.is_none());
    assert_eq!(
        authority.safe_status().state,
        ManifoldLocalControlState::Disabled
    );
    assert_eq!(
        authority
            .disable(&request, clock(2, 1_010))
            .rejection_reason,
        Some(ManifoldLocalControlRejectionReason::ReplayedRequest)
    );
}

#[test]
fn request_replay_closed_registry_typed_payload_and_rate_limit_fail_closed() {
    let mut authority = authority(2);
    open_window(&mut authority);
    let admission = admit(&mut authority);
    let token_id = admission
        .admission
        .and_then(|receipt| receipt.token)
        .expect("token")
        .token_id;

    let first_request = command_request(
        "request.local.command.first",
        "command.local.play",
        token_id.clone(),
        3,
        2,
        2,
        2_000,
    );
    assert!(
        authority
            .accept_command(&first_request, 2_000)
            .command_accepted
    );
    let mut replay = first_request;
    replay.expected_local_revision = Revision::new(4).expect("revision");
    replay.expected_admission_revision = Revision::new(3).expect("revision");
    replay.expected_host_revision = Revision::new(3).expect("revision");
    assert_eq!(
        authority.accept_command(&replay, 2_001).rejection_reason,
        Some(ManifoldLocalControlRejectionReason::ReplayedRequest)
    );

    let second = command_request(
        "request.local.command.second",
        "command.local.pause",
        token_id.clone(),
        4,
        3,
        3,
        2_002,
    );
    assert!(authority.accept_command(&second, 2_002).command_accepted);
    let third = command_request(
        "request.local.command.third",
        "command.local.play",
        token_id.clone(),
        5,
        4,
        4,
        2_003,
    );
    assert_eq!(
        authority.accept_command(&third, 2_003).rejection_reason,
        Some(ManifoldLocalControlRejectionReason::RateLimited)
    );

    let unknown = command_request(
        "request.local.command.unknown",
        "command.local.raw_shell",
        token_id.clone(),
        5,
        4,
        4,
        4_000,
    );
    assert_eq!(
        authority.accept_command(&unknown, 4_000).rejection_reason,
        Some(ManifoldLocalControlRejectionReason::UnknownCommand)
    );
    let missing_params = command_request(
        "request.local.command.select",
        "command.local.select_video",
        token_id,
        5,
        4,
        4,
        4_001,
    );
    assert_eq!(
        authority
            .accept_command(&missing_params, 4_001)
            .rejection_reason,
        Some(ManifoldLocalControlRejectionReason::InvalidTypedParams)
    );
}

#[test]
fn admission_change_on_host_rejection_advances_composite_revision() {
    let mut authority = authority(8);
    open_window(&mut authority);
    let admission = admit(&mut authority);
    let token_id = admission
        .admission
        .and_then(|receipt| receipt.token)
        .expect("token")
        .token_id;
    let prior = authority.revision_tuple();
    let mut request = command_request(
        "request.local.command.invalid-digest",
        "command.local.select_video",
        token_id,
        3,
        2,
        2,
        2_000,
    );
    request.params_digest = Some(ManifoldRuntimeTypedParamsDigest {
        schema_id: schema("rusty.manifold.runtime_host.typed_params_digest.v1"),
        params_type_id: id("params.local.video_selection"),
        canonical_sha256: "sha256:invalid".to_owned(),
        canonical_size_bytes: 10,
    });

    let receipt = authority.accept_command(&request, 2_000);
    assert!(!receipt.command_accepted);
    assert!(receipt
        .admission_use
        .as_ref()
        .is_some_and(|item| item.applied));
    assert!(receipt
        .application
        .as_ref()
        .is_some_and(|item| !item.applied));
    let resulting = authority.revision_tuple();
    assert_eq!(
        resulting.local_revision.get(),
        prior.local_revision.get() + 1
    );
    assert_eq!(
        resulting.admission_revision.get(),
        prior.admission_revision.get() + 1
    );
    assert_eq!(resulting.host_revision, prior.host_revision);
    assert_eq!(receipt.resulting_revisions, resulting);
}

#[test]
fn explicit_idle_expiry_uses_terminal_authority_revocation() {
    let mut authority = authority(8);
    open_window(&mut authority);
    assert!(admit(&mut authority).admitted);
    let early = authority.expire_controller(
        &ManifoldLocalControlExpiryRequest {
            schema_id: schema(LOCAL_CONTROL_EXPIRY_REQUEST_SCHEMA),
            request_id: id("request.local.expiry.early"),
            expected_local_revision: Revision::new(3).expect("revision"),
            expected_admission_revision: Revision::new(2).expect("revision"),
            expected_lease_authority_revision: Revision::new(2).expect("revision"),
            expected_host_revision: Revision::new(2).expect("revision"),
            requested_at_ms: 2_000,
            evidence_id: id("evidence.timer.early"),
        },
        clock(3, 2_000),
    );
    assert_eq!(
        early.rejection_reason,
        Some(ManifoldLocalControlRejectionReason::NotExpired)
    );

    let expired = authority.expire_controller(
        &ManifoldLocalControlExpiryRequest {
            schema_id: schema(LOCAL_CONTROL_EXPIRY_REQUEST_SCHEMA),
            request_id: id("request.local.expiry.idle"),
            expected_local_revision: Revision::new(3).expect("revision"),
            expected_admission_revision: Revision::new(2).expect("revision"),
            expected_lease_authority_revision: Revision::new(2).expect("revision"),
            expected_host_revision: Revision::new(2).expect("revision"),
            requested_at_ms: 3_201,
            evidence_id: id("evidence.timer.idle"),
        },
        clock(4, 3_201),
    );
    assert!(expired.expired, "{expired:#?}");
    assert!(expired.revocation.as_ref().is_some_and(|item| item.revoked));
    assert_eq!(
        authority.safe_status().state,
        ManifoldLocalControlState::Disabled
    );
}

#[test]
fn public_contract_fixtures_are_strict_and_secret_free() {
    let policy_json =
        include_str!("../../../fixtures/trusted-local-http-v1/local-control-policy.json");
    let policy: ManifoldLocalControlPolicy =
        serde_json::from_str(policy_json).expect("policy fixture");
    assert_eq!(
        policy.adapter_identity.client_id,
        id("adapter.quest.trusted_local_http")
    );
    assert_eq!(
        policy.controller_id,
        id("controller.browser.synthetic_primary")
    );

    let evidence_json =
        include_str!("../../../fixtures/trusted-local-http-v1/controller-evidence.json");
    let _: ManifoldLocalControllerEvidence =
        serde_json::from_str(evidence_json).expect("evidence fixture");
    assert!(!evidence_json.contains("pairing_code\":"));

    let command_json = include_str!("../../../fixtures/trusted-local-http-v1/command-request.json");
    let _: ManifoldLocalControlCommandRequest =
        serde_json::from_str(command_json).expect("command fixture");
    let status_json = include_str!("../../../fixtures/trusted-local-http-v1/safe-status.json");
    let _: ManifoldLocalControlSafeStatus =
        serde_json::from_str(status_json).expect("status fixture");
    assert!(!status_json.contains("token.session"));
    assert!(!status_json.contains("signing_fingerprint"));

    let damaged = status_json.replace(
        "\"state\": \"controller_active\",",
        "\"state\": \"controller_active\", \"pairing_code\": \"123456\",",
    );
    assert!(serde_json::from_str::<ManifoldLocalControlSafeStatus>(&damaged).is_err());
}
