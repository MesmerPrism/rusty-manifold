use super::*;

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
