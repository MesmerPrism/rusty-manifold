use super::*;

#[test]
fn coordination_plan_accepts_receiver_first_sequence() {
    let plan = coordination_plan(CoordinationSessionMode::SameNetworkQuestToQuest);
    let log = coordination_log("log.coordination.q2q", &plan.session_id);

    let scorecard = plan.simulate_message_log(&log).unwrap();

    assert_eq!(scorecard.status, ValidationStatus::Pass);
    assert!(!scorecard.runtime_execution_performed);
    assert!(!scorecard.media_payloads_seen);
    assert_eq!(scorecard.gate_results.len(), plan.gates.len());
    assert!(scorecard
        .gate_results
        .iter()
        .all(|gate| gate.status == ValidationStatus::Pass));
}

#[test]
fn coordination_rejects_sender_before_receiver_ready() {
    let plan = coordination_plan(CoordinationSessionMode::SameNetworkQuestToQuest);
    let mut log = coordination_log("log.coordination.q2q.sender_early", &plan.session_id);
    let sender_index = log
        .messages
        .iter()
        .position(|message| {
            message.message_kind.as_str() == "coordination.message.sender_start_authorized"
        })
        .expect("sender authorization message exists");
    let sender_message = log.messages.remove(sender_index);
    log.messages.insert(4, sender_message);

    let error = plan.simulate_message_log(&log).unwrap_err();

    assert_eq!(
        error.kind(),
        CoordinationValidationErrorKind::SenderBeforeReceiverReady
    );
    assert_eq!(error.rejection_code(), "sender_before_receiver_ready");
}

#[test]
fn coordination_rejects_peer_gossip_authorizing_sender() {
    let plan = coordination_plan(CoordinationSessionMode::SameNetworkQuestToQuest);
    let mut log = coordination_log("log.coordination.q2q.gossip_authorizes", &plan.session_id);
    let sender = log
        .messages
        .iter_mut()
        .find(|message| {
            message.message_kind.as_str() == "coordination.message.sender_start_authorized"
        })
        .expect("sender authorization message exists");
    sender.payload_class = CoordinationPayloadClass::AdvisoryStatus;
    sender.message_kind = id("coordination.message.peer_gossip_status");

    let error = plan.simulate_message_log(&log).unwrap_err();

    assert_eq!(
        error.kind(),
        CoordinationValidationErrorKind::AdvisoryStatusCannotAuthorize
    );
    assert_eq!(error.rejection_code(), "advisory_status_cannot_authorize");
}

#[test]
fn coordination_rejects_high_rate_payloads() {
    let plan = coordination_plan(CoordinationSessionMode::SameNetworkQuestToQuest);
    let mut log = coordination_log("log.coordination.q2q.high_rate", &plan.session_id);
    log.messages[0].payload_class = CoordinationPayloadClass::MediaPayload;
    log.messages[0].payload_size_bytes = 1_048_576;

    let error = plan.simulate_message_log(&log).unwrap_err();

    assert_eq!(
        error.kind(),
        CoordinationValidationErrorKind::MediaPayloadInControl
    );
    assert_eq!(error.rejection_code(), "media_payload_in_control");
}

fn coordination_plan(mode: CoordinationSessionMode) -> ManifoldCoordinationSessionPlan {
    let session_id = match mode {
        CoordinationSessionMode::SameNetworkQuestToQuest => id("session.remote_camera.q2q_lan"),
        CoordinationSessionMode::SameNetworkQuestToPhone => {
            id("session.remote_camera.quest_phone_lan")
        }
        CoordinationSessionMode::RemoteRelayTwoWay => id("session.remote_camera.relay_two_way"),
        CoordinationSessionMode::Fixture => id("session.coordination.fixture"),
    };

    ManifoldCoordinationSessionPlan {
        schema_id: schema("rusty.manifold.coordination.session_plan.v1"),
        session_id,
        session_revision: Revision::INITIAL,
        authority_id: id("authority.manifold.coordination"),
        mode,
        participants: vec![
            CoordinationParticipant {
                participant_id: id("participant.coordinator"),
                role: CoordinationParticipantRole::Coordinator,
                host_profile_id: Some(id("host.desktop.coordinator")),
                required_capabilities: vec![id("manifold.coordination.control")],
                advisory_only: false,
            },
            CoordinationParticipant {
                participant_id: id("participant.quest_a"),
                role: CoordinationParticipantRole::QuestHeadset,
                host_profile_id: Some(id("host.quest.a")),
                required_capabilities: vec![id("quest.remote_camera.outside_stereo")],
                advisory_only: false,
            },
            CoordinationParticipant {
                participant_id: id("participant.quest_b"),
                role: match mode {
                    CoordinationSessionMode::SameNetworkQuestToPhone => {
                        CoordinationParticipantRole::AndroidPhone
                    }
                    _ => CoordinationParticipantRole::QuestHeadset,
                },
                host_profile_id: Some(match mode {
                    CoordinationSessionMode::SameNetworkQuestToPhone => id("host.android_phone.b"),
                    _ => id("host.quest.b"),
                }),
                required_capabilities: vec![id("remote_camera.h264.receive")],
                advisory_only: false,
            },
        ],
        transports: vec![
            CoordinationTransport {
                transport_id: id("transport.coordination.control"),
                transport_kind: id("transport.kind.control_inbox"),
                payload_policy: CoordinationPayloadPolicy::MediaPayloadForbidden,
                authoritative: true,
                advisory_only: false,
                same_network_only: mode != CoordinationSessionMode::RemoteRelayTwoWay,
                remote_relay: mode == CoordinationSessionMode::RemoteRelayTwoWay,
                bidirectional: true,
                operator_review_required: mode != CoordinationSessionMode::Fixture,
            },
            CoordinationTransport {
                transport_id: id("transport.coordination.peer_gossip"),
                transport_kind: id("transport.kind.peer_status_gossip"),
                payload_policy: CoordinationPayloadPolicy::AdvisoryStatusOnly,
                authoritative: false,
                advisory_only: true,
                same_network_only: true,
                remote_relay: false,
                bidirectional: true,
                operator_review_required: true,
            },
        ],
        inboxes: vec![
            CoordinationInbox {
                inbox_id: id("inbox.quest_a.control"),
                owner_participant_id: id("participant.quest_a"),
                transport_id: id("transport.coordination.control"),
                lease_id: Some(id("lease.coordination.quest_a.control")),
                channel_id: id("channel.control"),
                heartbeat_ttl_ms: 30_000,
            },
            CoordinationInbox {
                inbox_id: id("inbox.quest_b.control"),
                owner_participant_id: id("participant.quest_b"),
                transport_id: id("transport.coordination.control"),
                lease_id: Some(id("lease.coordination.quest_b.control")),
                channel_id: id("channel.control"),
                heartbeat_ttl_ms: 30_000,
            },
        ],
        gates: coordination_gates(),
        allowed_message_kinds: coordination_message_kinds(),
        command_refs: vec![
            id("command.remote_camera.start_receiver"),
            id("command.remote_camera.start_sender"),
            id("command.remote_camera.get_status"),
            id("command.remote_camera.stop"),
        ],
        media_stream_refs: vec![
            id("stream.remote_camera.left_h264"),
            id("stream.remote_camera.right_h264"),
        ],
        safety: CoordinationSafetyPolicy {
            max_control_payload_bytes: 16 * 1024,
            high_rate_payloads_forbidden: true,
            peer_gossip_can_authorize_commands: false,
            operator_review_required_for_live_routes: true,
        },
    }
}

fn coordination_gates() -> Vec<CoordinationGate> {
    vec![
        gate(
            "gate.participants_identified",
            "coordination.phase.identify",
            &[],
            &["participant.quest_a", "participant.quest_b"],
            &["coordination.message.participant_online"],
            None,
            false,
        ),
        gate(
            "gate.control_inboxes_armed",
            "coordination.phase.arm_control",
            &["gate.participants_identified"],
            &["participant.quest_a", "participant.quest_b"],
            &["coordination.message.inbox_armed"],
            None,
            false,
        ),
        gate(
            "gate.platform_preflight_passed",
            "coordination.phase.platform_preflight",
            &["gate.control_inboxes_armed"],
            &["participant.quest_a", "participant.quest_b"],
            &["coordination.message.platform_readiness_report"],
            None,
            false,
        ),
        gate(
            "gate.advisory_peer_status",
            "coordination.phase.advisory_status",
            &["gate.platform_preflight_passed"],
            &["participant.quest_a", "participant.quest_b"],
            &["coordination.message.peer_gossip_status"],
            None,
            false,
        ),
        gate(
            "gate.media_receivers_armed",
            "coordination.phase.arm_receivers",
            &["gate.platform_preflight_passed"],
            &["participant.quest_a", "participant.quest_b"],
            &["coordination.message.media_receiver_armed"],
            Some("command.remote_camera.start_receiver"),
            true,
        ),
        gate(
            "gate.receiver_ready_announced",
            "coordination.phase.receiver_ready",
            &["gate.media_receivers_armed"],
            &["participant.quest_a", "participant.quest_b"],
            &["coordination.message.receiver_ready_announced"],
            None,
            true,
        ),
        gate(
            "gate.sender_start_authorized",
            "coordination.phase.authorize_sender",
            &["gate.receiver_ready_announced"],
            &["participant.coordinator"],
            &["coordination.message.sender_start_authorized"],
            Some("command.remote_camera.start_sender"),
            false,
        ),
        gate(
            "gate.active_status_captured",
            "coordination.phase.status_capture",
            &["gate.sender_start_authorized"],
            &["participant.quest_a", "participant.quest_b"],
            &["coordination.message.stream_status_report"],
            Some("command.remote_camera.get_status"),
            false,
        ),
        gate(
            "gate.scorecard_captured",
            "coordination.phase.scorecard",
            &["gate.active_status_captured"],
            &["participant.coordinator"],
            &["coordination.message.scorecard_capture_completed"],
            None,
            false,
        ),
        gate(
            "gate.stopped",
            "coordination.phase.stop",
            &["gate.scorecard_captured"],
            &["participant.quest_a", "participant.quest_b"],
            &["coordination.message.stopped"],
            Some("command.remote_camera.stop"),
            false,
        ),
        gate(
            "gate.cleanup_verified",
            "coordination.phase.cleanup",
            &["gate.stopped"],
            &["participant.coordinator"],
            &["coordination.message.cleanup_completed"],
            None,
            false,
        ),
    ]
}

fn coordination_message_kinds() -> Vec<DottedId> {
    [
        "coordination.message.participant_online",
        "coordination.message.inbox_armed",
        "coordination.message.platform_readiness_report",
        "coordination.message.peer_gossip_status",
        "coordination.message.media_receiver_armed",
        "coordination.message.receiver_ready_announced",
        "coordination.message.sender_start_authorized",
        "coordination.message.stream_status_report",
        "coordination.message.scorecard_capture_completed",
        "coordination.message.stopped",
        "coordination.message.cleanup_completed",
    ]
    .into_iter()
    .map(id)
    .collect()
}

#[allow(clippy::too_many_arguments)]
fn gate(
    gate_id: &str,
    phase: &str,
    depends_on_gate_ids: &[&str],
    required_participant_ids: &[&str],
    required_message_kinds: &[&str],
    authorizes_command_id: Option<&str>,
    required_before_sender_start: bool,
) -> CoordinationGate {
    CoordinationGate {
        gate_id: id(gate_id),
        phase: id(phase),
        depends_on_gate_ids: depends_on_gate_ids.iter().copied().map(id).collect(),
        required_participant_ids: required_participant_ids.iter().copied().map(id).collect(),
        required_message_kinds: required_message_kinds.iter().copied().map(id).collect(),
        authorizes_command_id: authorizes_command_id.map(id),
        required_before_sender_start,
    }
}

fn coordination_log(log_id: &str, session_id: &DottedId) -> ManifoldCoordinationMessageLog {
    let mut messages = vec![
        message(
            session_id,
            "participant.quest_a",
            "coordination.message.participant_online",
            1,
            0,
            Some("gate.participants_identified"),
            CoordinationPayloadClass::Control,
        ),
        message(
            session_id,
            "participant.quest_b",
            "coordination.message.participant_online",
            1,
            10,
            Some("gate.participants_identified"),
            CoordinationPayloadClass::Control,
        ),
        message(
            session_id,
            "participant.quest_a",
            "coordination.message.inbox_armed",
            2,
            20,
            Some("gate.control_inboxes_armed"),
            CoordinationPayloadClass::Control,
        ),
        message(
            session_id,
            "participant.quest_b",
            "coordination.message.inbox_armed",
            2,
            30,
            Some("gate.control_inboxes_armed"),
            CoordinationPayloadClass::Control,
        ),
        message(
            session_id,
            "participant.quest_a",
            "coordination.message.platform_readiness_report",
            3,
            40,
            Some("gate.platform_preflight_passed"),
            CoordinationPayloadClass::Control,
        ),
        message(
            session_id,
            "participant.quest_b",
            "coordination.message.platform_readiness_report",
            3,
            50,
            Some("gate.platform_preflight_passed"),
            CoordinationPayloadClass::Control,
        ),
        message(
            session_id,
            "participant.quest_a",
            "coordination.message.media_receiver_armed",
            5,
            80,
            Some("gate.media_receivers_armed"),
            CoordinationPayloadClass::Control,
        ),
        message(
            session_id,
            "participant.quest_b",
            "coordination.message.media_receiver_armed",
            5,
            90,
            Some("gate.media_receivers_armed"),
            CoordinationPayloadClass::Control,
        ),
        message(
            session_id,
            "participant.quest_a",
            "coordination.message.receiver_ready_announced",
            6,
            100,
            Some("gate.receiver_ready_announced"),
            CoordinationPayloadClass::Control,
        ),
        message(
            session_id,
            "participant.quest_b",
            "coordination.message.receiver_ready_announced",
            6,
            110,
            Some("gate.receiver_ready_announced"),
            CoordinationPayloadClass::Control,
        ),
        message(
            session_id,
            "participant.coordinator",
            "coordination.message.sender_start_authorized",
            1,
            120,
            Some("gate.sender_start_authorized"),
            CoordinationPayloadClass::Control,
        ),
        message(
            session_id,
            "participant.quest_a",
            "coordination.message.stream_status_report",
            7,
            130,
            Some("gate.active_status_captured"),
            CoordinationPayloadClass::ArtifactReference,
        ),
        message(
            session_id,
            "participant.quest_b",
            "coordination.message.stream_status_report",
            7,
            140,
            Some("gate.active_status_captured"),
            CoordinationPayloadClass::ArtifactReference,
        ),
        message(
            session_id,
            "participant.coordinator",
            "coordination.message.scorecard_capture_completed",
            2,
            150,
            Some("gate.scorecard_captured"),
            CoordinationPayloadClass::ArtifactReference,
        ),
        message(
            session_id,
            "participant.quest_a",
            "coordination.message.stopped",
            8,
            160,
            Some("gate.stopped"),
            CoordinationPayloadClass::Control,
        ),
        message(
            session_id,
            "participant.quest_b",
            "coordination.message.stopped",
            8,
            170,
            Some("gate.stopped"),
            CoordinationPayloadClass::Control,
        ),
        message(
            session_id,
            "participant.coordinator",
            "coordination.message.cleanup_completed",
            3,
            180,
            Some("gate.cleanup_verified"),
            CoordinationPayloadClass::ArtifactReference,
        ),
    ];

    messages.insert(
        6,
        message(
            session_id,
            "participant.quest_a",
            "coordination.message.peer_gossip_status",
            4,
            60,
            Some("gate.advisory_peer_status"),
            CoordinationPayloadClass::AdvisoryStatus,
        ),
    );
    messages.insert(
        7,
        message(
            session_id,
            "participant.quest_b",
            "coordination.message.peer_gossip_status",
            4,
            70,
            Some("gate.advisory_peer_status"),
            CoordinationPayloadClass::AdvisoryStatus,
        ),
    );

    ManifoldCoordinationMessageLog {
        schema_id: schema("rusty.manifold.coordination.message_log.v1"),
        log_id: id(log_id),
        session_id: session_id.clone(),
        messages,
    }
}

fn message(
    session_id: &DottedId,
    participant_id: &str,
    message_kind: &str,
    sequence: u64,
    offset_ms: u64,
    gate_id: Option<&str>,
    payload_class: CoordinationPayloadClass,
) -> ManifoldCoordinationMessage {
    ManifoldCoordinationMessage {
        schema_id: schema("rusty.manifold.coordination.message.v1"),
        message_id: id(&format!("message.{}.{}", participant_id, offset_ms)),
        session_id: session_id.clone(),
        participant_id: id(participant_id),
        message_kind: id(message_kind),
        sequence,
        created_at_ms: 1_765_000_000_000 + offset_ms,
        expires_at_ms: 1_765_000_030_000 + offset_ms,
        idempotency_key: id(&format!("idempotency.{}.{}", participant_id, offset_ms)),
        depends_on_message_ids: Vec::new(),
        gate_id: gate_id.map(id),
        transport_id: Some(match payload_class {
            CoordinationPayloadClass::AdvisoryStatus => id("transport.coordination.peer_gossip"),
            CoordinationPayloadClass::Control | CoordinationPayloadClass::ArtifactReference => {
                id("transport.coordination.control")
            }
            CoordinationPayloadClass::MediaPayload => id("transport.coordination.control"),
        }),
        payload_class,
        sensitivity: SensitivityLevel::Synthetic,
        payload_size_bytes: 512,
        inline_binary_payload: false,
        artifact_refs: Vec::new(),
    }
}
