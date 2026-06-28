use super::*;

fn condition(
    condition_id: &str,
    scope: ManifoldBridgeConditionScope,
    kind: ManifoldBridgeConditionKind,
    required_state: ManifoldBridgeConditionState,
    check_ref: &str,
) -> ManifoldBridgeConditionRequirement {
    ManifoldBridgeConditionRequirement {
        condition_id: id(condition_id),
        scope,
        kind,
        required_state,
        check_ref: id(check_ref),
        issue_codes: vec![id("issue.bridge_route.condition_unmet")],
        remediation: Some(ManifoldBridgeConditionRemediation {
            action_ref: id("remediation.bridge_route.prepare_environment"),
            operator_label: "Prepare route environment".to_owned(),
        }),
    }
}

fn websocket_conditions() -> Vec<ManifoldBridgeConditionRequirement> {
    vec![
        condition(
            "condition.host.firewall.websocket_inbound",
            ManifoldBridgeConditionScope::Security,
            ManifoldBridgeConditionKind::HostFirewallInboundAllowed,
            ManifoldBridgeConditionState::Allowed,
            "check.host.firewall.websocket_inbound",
        ),
        condition(
            "condition.runtime.websocket_subscriber",
            ManifoldBridgeConditionScope::Runtime,
            ManifoldBridgeConditionKind::RuntimeSubscriberActive,
            ManifoldBridgeConditionState::Active,
            "check.runtime.websocket_subscriber",
        ),
    ]
}

fn lsl_conditions() -> Vec<ManifoldBridgeConditionRequirement> {
    vec![
        condition(
            "condition.tooling.lsl.native_library",
            ManifoldBridgeConditionScope::Tooling,
            ManifoldBridgeConditionKind::NativeLibraryAvailable,
            ManifoldBridgeConditionState::Available,
            "check.tooling.lsl.native_library",
        ),
        condition(
            "condition.network.multicast_allowed",
            ManifoldBridgeConditionScope::Network,
            ManifoldBridgeConditionKind::MulticastAllowed,
            ManifoldBridgeConditionState::Allowed,
            "check.network.multicast_allowed",
        ),
    ]
}

fn zeromq_conditions() -> Vec<ManifoldBridgeConditionRequirement> {
    vec![
        condition(
            "condition.tooling.zeromq.library",
            ManifoldBridgeConditionScope::Tooling,
            ManifoldBridgeConditionKind::ProtocolLibraryAvailable,
            ManifoldBridgeConditionState::Available,
            "check.tooling.zeromq.library",
        ),
        condition(
            "condition.host.zeromq.endpoint",
            ManifoldBridgeConditionScope::Host,
            ManifoldBridgeConditionKind::TcpEndpointReachable,
            ManifoldBridgeConditionState::Reachable,
            "check.host.zeromq.endpoint",
        ),
    ]
}

fn timing(
    rtt_strategy: ManifoldBridgeRttStrategy,
    parallel_clock_route_id: Option<&str>,
) -> ManifoldBridgeTimingPolicy {
    ManifoldBridgeTimingPolicy {
        rtt_strategy,
        clock_domain: id("clock.host_monotonic"),
        parallel_clock_route_id: parallel_clock_route_id.map(id),
        min_round_trips: 8,
        timeout_ms: 5_000,
        warmup_ms: 250,
        reported_metrics: vec![
            ManifoldBridgeTimingMetric::RttMs,
            ManifoldBridgeTimingMetric::JitterMs,
        ],
    }
}

fn websocket_command_route() -> ManifoldBridgeRouteDescriptor {
    ManifoldBridgeRouteDescriptor {
        schema_id: schema("rusty.manifold.bridge.route_descriptor.v1"),
        route_id: id("bridge_route.command.websocket.applied"),
        route_kind: ManifoldBridgeRouteKind::Command,
        plane: ManifoldBridgePlane::Control,
        transport_family: ManifoldBridgeTransportFamily::WebSocket,
        delivery: ManifoldBridgeDeliverySemantics::AppliedReceiptRequired,
        payload_class: ManifoldBridgePayloadClass::CommandEnvelope,
        rate_class: StreamRateClass::Event,
        authority_role: ManifoldBridgeAuthorityRole::Authority,
        required_evidence_stages: vec![
            ManifoldBridgeEvidenceStage::Sent,
            ManifoldBridgeEvidenceStage::TransportOk,
            ManifoldBridgeEvidenceStage::AuthorityAccepted,
            ManifoldBridgeEvidenceStage::RuntimeAccepted,
            ManifoldBridgeEvidenceStage::Applied,
        ],
        fallback_route_ids: vec![id("bridge_route.command.file_hotload.applied")],
        issue_codes: vec![id("issue.bridge_route.timeout")],
        required_conditions: websocket_conditions(),
        timing: Some(timing(ManifoldBridgeRttStrategy::AppliedReceiptEcho, None)),
        zeromq: None,
        lsl: None,
    }
}

fn lsl_clock_echo_route() -> ManifoldBridgeRouteDescriptor {
    ManifoldBridgeRouteDescriptor {
        schema_id: schema("rusty.manifold.bridge.route_descriptor.v1"),
        route_id: id("bridge_route.clock.lsl.roundtrip_echo"),
        route_kind: ManifoldBridgeRouteKind::StreamBridge,
        plane: ManifoldBridgePlane::Telemetry,
        transport_family: ManifoldBridgeTransportFamily::Lsl,
        delivery: ManifoldBridgeDeliverySemantics::Ordered,
        payload_class: ManifoldBridgePayloadClass::StreamPacket,
        rate_class: StreamRateClass::Event,
        authority_role: ManifoldBridgeAuthorityRole::Adapter,
        required_evidence_stages: vec![
            ManifoldBridgeEvidenceStage::Sent,
            ManifoldBridgeEvidenceStage::TransportOk,
            ManifoldBridgeEvidenceStage::Observed,
        ],
        fallback_route_ids: Vec::new(),
        issue_codes: vec![
            id("issue.bridge_route.lsl_native_unavailable"),
            id("issue.bridge_route.clock_uncorrelated"),
        ],
        required_conditions: lsl_conditions(),
        timing: Some(timing(ManifoldBridgeRttStrategy::NativeRoundTrip, None)),
        zeromq: None,
        lsl: Some(ManifoldLslRouteProfile {
            stream_name: "ClockEcho".to_owned(),
            stream_type: "clock.echo".to_owned(),
            source_id: Some("clock.echo.source".to_owned()),
            endpoint_role: ManifoldLslEndpointRole::RoundTrip,
            resolve_policy: ManifoldLslResolvePolicy::NameAndType,
            channel_count: 1,
            channel_format: ManifoldLslChannelFormat::String,
            channel_labels: vec!["clock_alignment_echo".to_owned()],
            sample_rate_policy: ManifoldLslSampleRatePolicy::Irregular,
            clock_policy: ManifoldLslClockPolicy::RoundTripOffset,
            resolve_timeout_ms: 5_000,
            sample_timeout_ms: 2_000,
            warmup_ms: 250,
            min_samples: 8,
        }),
    }
}

fn zeromq_pub_sub_route() -> ManifoldBridgeRouteDescriptor {
    ManifoldBridgeRouteDescriptor {
        schema_id: schema("rusty.manifold.bridge.route_descriptor.v1"),
        route_id: id("bridge_route.stream.zeromq.pub_sub"),
        route_kind: ManifoldBridgeRouteKind::StreamBridge,
        plane: ManifoldBridgePlane::Data,
        transport_family: ManifoldBridgeTransportFamily::ZeroMq,
        delivery: ManifoldBridgeDeliverySemantics::BestEffort,
        payload_class: ManifoldBridgePayloadClass::StreamPacket,
        rate_class: StreamRateClass::Periodic,
        authority_role: ManifoldBridgeAuthorityRole::Adapter,
        required_evidence_stages: vec![
            ManifoldBridgeEvidenceStage::Sent,
            ManifoldBridgeEvidenceStage::TransportOk,
            ManifoldBridgeEvidenceStage::Observed,
        ],
        fallback_route_ids: vec![id("bridge_route.stream.websocket.ordered")],
        issue_codes: vec![
            id("issue.bridge_route.packet_loss"),
            id("issue.bridge_route.decode_error"),
        ],
        required_conditions: zeromq_conditions(),
        timing: Some(timing(
            ManifoldBridgeRttStrategy::ParallelLslClockEcho,
            Some("bridge_route.clock.lsl.roundtrip_echo"),
        )),
        zeromq: Some(ManifoldZeroMqRouteProfile {
            socket_pattern: ManifoldZeroMqSocketPattern::PubSub,
            endpoint_open_mode: ManifoldZeroMqEndpointOpenMode::Connect,
            endpoint_url: "tcp://127.0.0.1:5570".to_owned(),
            topic_prefix: "rusty.manifold.qcl084".to_owned(),
            payload_encoding: ManifoldZeroMqPayloadEncoding::Json,
            max_message_bytes: 4096,
            high_water_mark: 16,
            queue_policy: ManifoldQueueDropPolicy::DropOldest,
        }),
        lsl: None,
    }
}

fn stage_report(stage: ManifoldBridgeEvidenceStage) -> ManifoldBridgeEvidenceStageReport {
    ManifoldBridgeEvidenceStageReport {
        stage,
        status: ValidationStatus::Pass,
        observed_at_ms: Some(1_765_000_000_000),
        evidence_refs: vec![id("evidence.bridge_route.synthetic")],
        issue_codes: Vec::new(),
    }
}

#[test]
fn bridge_route_accepts_applied_websocket_command_evidence() {
    let route = websocket_command_route();
    let evidence = ManifoldBridgeRouteEvidence {
        schema_id: schema("rusty.manifold.bridge.route_evidence.v1"),
        evidence_id: id("evidence.bridge_route.command.websocket.applied"),
        route_id: route.route_id.clone(),
        status: ValidationStatus::Pass,
        started_at_ms: 1_765_000_000_000,
        ended_at_ms: 1_765_000_000_250,
        stage_reports: route
            .required_evidence_stages
            .iter()
            .copied()
            .map(stage_report)
            .collect(),
        artifact_refs: vec![id("artifact.command_receipt")],
        issues: Vec::new(),
    };

    assert_eq!(route.validate_shape(), Ok(()));
    assert_eq!(route.validate_evidence_summary(&evidence), Ok(()));
}

#[test]
fn bridge_route_rejects_transport_only_evidence_for_applied_command() {
    let route = websocket_command_route();
    let evidence = ManifoldBridgeRouteEvidence {
        schema_id: schema("rusty.manifold.bridge.route_evidence.v1"),
        evidence_id: id("evidence.bridge_route.command.websocket.transport_only"),
        route_id: route.route_id.clone(),
        status: ValidationStatus::Pass,
        started_at_ms: 1_765_000_000_000,
        ended_at_ms: 1_765_000_000_050,
        stage_reports: vec![
            stage_report(ManifoldBridgeEvidenceStage::Sent),
            stage_report(ManifoldBridgeEvidenceStage::TransportOk),
            stage_report(ManifoldBridgeEvidenceStage::AuthorityAccepted),
        ],
        artifact_refs: vec![id("artifact.transport_ack")],
        issues: Vec::new(),
    };

    let error = route.validate_evidence_summary(&evidence).unwrap_err();
    assert_eq!(error.rejection_code(), "missing_required_evidence");
}

#[test]
fn bridge_route_rejects_media_frame_on_control_plane() {
    let mut route = websocket_command_route();
    route.route_id = id("bridge_route.media.invalid_control");
    route.payload_class = ManifoldBridgePayloadClass::MediaFrame;

    let error = route.validate_shape().unwrap_err();
    assert_eq!(error.rejection_code(), "plane_payload_mismatch");
}

#[test]
fn bridge_route_rejects_operational_route_without_required_conditions() {
    let mut route = websocket_command_route();
    route.required_conditions.clear();

    let error = route.validate_shape().unwrap_err();
    assert_eq!(error.rejection_code(), "missing_required_condition");
}

#[test]
fn bridge_route_rejects_operational_route_without_timing_policy() {
    let mut route = websocket_command_route();
    route.timing = None;

    let error = route.validate_shape().unwrap_err();
    assert_eq!(error.rejection_code(), "missing_timing_policy");
}

#[test]
fn bridge_route_rejects_parallel_lsl_timing_without_clock_route() {
    let mut route = zeromq_pub_sub_route();
    route
        .timing
        .as_mut()
        .expect("route has timing")
        .parallel_clock_route_id = None;

    let error = route.validate_shape().unwrap_err();
    assert_eq!(error.rejection_code(), "invalid_timing_policy");
}

#[test]
fn bridge_route_accepts_generic_zeromq_pub_sub_profile() {
    let route = zeromq_pub_sub_route();

    assert_eq!(route.validate_shape(), Ok(()));
}

#[test]
fn bridge_route_accepts_generic_lsl_roundtrip_profile() {
    let route = lsl_clock_echo_route();

    assert_eq!(route.validate_shape(), Ok(()));
}

#[test]
fn bridge_route_rejects_lsl_without_profile() {
    let mut route = lsl_clock_echo_route();
    route.lsl = None;

    let error = route.validate_shape().unwrap_err();
    assert_eq!(error.rejection_code(), "missing_transport_profile");
}

#[test]
fn bridge_route_rejects_lsl_profile_on_non_lsl_transport() {
    let mut route = lsl_clock_echo_route();
    route.transport_family = ManifoldBridgeTransportFamily::Udp;

    let error = route.validate_shape().unwrap_err();
    assert_eq!(error.rejection_code(), "transport_profile_mismatch");
}

#[test]
fn bridge_route_rejects_lsl_channel_label_mismatch() {
    let mut route = lsl_clock_echo_route();
    route
        .lsl
        .as_mut()
        .expect("route has profile")
        .channel_labels = vec!["a".to_owned(), "b".to_owned()];

    let error = route.validate_shape().unwrap_err();
    assert_eq!(error.rejection_code(), "invalid_transport_profile");
}

#[test]
fn bridge_route_rejects_zeromq_without_profile() {
    let mut route = zeromq_pub_sub_route();
    route.zeromq = None;

    let error = route.validate_shape().unwrap_err();
    assert_eq!(error.rejection_code(), "missing_transport_profile");
}

#[test]
fn bridge_route_rejects_zeromq_profile_on_non_zeromq_transport() {
    let mut route = zeromq_pub_sub_route();
    route.transport_family = ManifoldBridgeTransportFamily::Udp;

    let error = route.validate_shape().unwrap_err();
    assert_eq!(error.rejection_code(), "transport_profile_mismatch");
}

#[test]
fn bridge_route_rejects_ambiguous_zeromq_runtime_open_mode() {
    let mut route = zeromq_pub_sub_route();
    route
        .zeromq
        .as_mut()
        .expect("route has profile")
        .endpoint_open_mode = ManifoldZeroMqEndpointOpenMode::Either;

    let error = route.validate_shape().unwrap_err();
    assert_eq!(error.rejection_code(), "invalid_transport_profile");
}
