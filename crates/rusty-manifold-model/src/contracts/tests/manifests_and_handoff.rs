use super::*;

#[test]
fn host_endpoint_security_rejects_public_relay_without_policy() {
    let endpoint = EndpointDescriptor {
        endpoint_id: id("endpoint.public_without_policy"),
        visibility: EndpointVisibility::PublicRelay,
        transport: EndpointTransport::Http,
        security: EndpointSecurity::None,
    };

    let error = endpoint.validate_security().unwrap_err();
    assert_eq!(error.rejection_code(), "endpoint_security_mismatch");
}

#[test]
fn graph_manifest_rejects_unknown_module_link() {
    let manifest = ManifoldGraphManifest {
        schema_id: schema("rusty.manifold.graph.manifest.v1"),
        graph_id: id("graph.synthetic_wave_pipeline"),
        graph_revision: Revision::INITIAL,
        nodes: vec![ManifoldGraphNode {
            node_id: id("node.unknown"),
            module_id: id("module.not_registered"),
        }],
        edges: Vec::new(),
        required_capabilities: vec![id("manifold.graph.run")],
    };

    let error = manifest
        .validate_links(&[id("module.synthetic_wave_provider")])
        .unwrap_err();

    assert_eq!(error.rejection_code(), "unknown_module_link");
}

#[test]
fn stream_registry_rejects_unknown_source_module() {
    let snapshot = ManifoldStreamRegistrySnapshot {
        schema_id: schema("rusty.manifold.stream.registry_snapshot.v1"),
        registry_revision: Revision::INITIAL,
        streams: vec![ManifoldStreamManifest {
            schema_id: schema("rusty.manifold.stream.manifest.v1"),
            stream_id: id("stream.orphaned"),
            source_module_id: id("module.not_registered"),
            semantic_family: id("synthetic.scalar"),
            sample_schema: schema("rusty.manifold.sample.scalar_f32.v1"),
            rate_class: StreamRateClass::Periodic,
            timestamp_domains: vec![id("clock.host_monotonic")],
            retention: RetentionPolicyDescriptor {
                policy: RetentionPolicy::Ephemeral,
            },
            sensitivity: SensitivityLevel::Synthetic,
            transport_offers: Vec::new(),
            subscription: SubscriptionPolicy {
                ui_subscribable: false,
                max_subscribers: None,
            },
        }],
    };

    let error = snapshot
        .validate_source_modules(&[id("module.synthetic_wave_provider")])
        .unwrap_err();

    assert_eq!(error.rejection_code(), "unknown_module_link");
}

#[test]
fn module_manifest_can_describe_synthetic_provider() {
    let manifest = ManifoldModuleManifest {
        schema_id: schema("rusty.manifold.module.manifest.v1"),
        module_id: id("module.synthetic_wave_provider"),
        module_kind: ModuleKind::Provider,
        label: "Synthetic Wave Provider".to_owned(),
        version: "0.1.0".to_owned(),
        lifecycle_states: vec![
            ModuleLifecycleState::Available,
            ModuleLifecycleState::Running,
            ModuleLifecycleState::Stopped,
        ],
        provides_streams: vec![id("stream.synthetic_wave")],
        consumes_streams: Vec::new(),
        accepted_commands: vec![id("command.module.start")],
        required_capabilities: vec![id("manifold.module.control")],
        clock_policy: ClockPolicy {
            source_domain: id("clock.host_monotonic"),
            correlation_required: false,
        },
        retention: RetentionPolicyDescriptor {
            policy: RetentionPolicy::Ephemeral,
        },
        sensitivity: SensitivityLevel::Synthetic,
        platform_support: vec![id("backend.synthetic")],
        issue_codes: vec![id("issue.synthetic_stopped")],
    };

    assert_eq!(manifest.module_kind, ModuleKind::Provider);
    assert_eq!(
        manifest.provides_streams[0].as_str(),
        "stream.synthetic_wave"
    );
}

#[test]
fn shell_handoff_rejects_unknown_stream_binding() {
    let registry = ManifoldStreamRegistrySnapshot {
        schema_id: schema("rusty.manifold.stream.registry_snapshot.v1"),
        registry_revision: Revision::INITIAL,
        streams: Vec::new(),
    };
    let handoff = ManifoldShellHandoffManifest {
        schema_id: schema("rusty.manifold.shell.handoff.v1"),
        handoff_id: id("shell_handoff.test"),
        handoff_revision: Revision::INITIAL,
        target_host_profile: id("host.headset"),
        shell_app_id: id("app.host_shell.headset"),
        validation_slot_id: id("host_run.slot.synthetic_smoke"),
        stream_bindings: vec![ManifoldShellStreamBinding {
            stream_id: id("stream.not_registered"),
            direction: ShellStreamDirection::Subscribe,
            role: id("shell.stream.source_input"),
            required: true,
        }],
        command_ids: vec![id("command.module.start")],
        transport_offers: Vec::new(),
        expected_scorecard_id: id("scorecard.host_run.synthetic_smoke"),
    };

    let error = handoff
        .validate_links(
            &registry,
            &[id("command.module.start")],
            &[id("endpoint.headset_loopback")],
            &[id("host_run.slot.synthetic_smoke")],
        )
        .unwrap_err();

    assert_eq!(error.rejection_code(), "unknown_stream");
}

#[test]
fn shell_handoff_review_receipt_is_link_checked_and_review_only() {
    let registry = ManifoldStreamRegistrySnapshot {
        schema_id: schema("rusty.manifold.stream.registry_snapshot.v1"),
        registry_revision: Revision::INITIAL,
        streams: vec![ManifoldStreamManifest {
            schema_id: schema("rusty.manifold.stream.manifest.v1"),
            stream_id: id("stream.synthetic_wave"),
            source_module_id: id("module.synthetic_wave_provider"),
            semantic_family: id("synthetic.scalar"),
            sample_schema: schema("rusty.manifold.sample.scalar_f32.v1"),
            rate_class: StreamRateClass::Periodic,
            timestamp_domains: vec![id("clock.host_monotonic")],
            retention: RetentionPolicyDescriptor {
                policy: RetentionPolicy::Ephemeral,
            },
            sensitivity: SensitivityLevel::Synthetic,
            transport_offers: Vec::new(),
            subscription: SubscriptionPolicy {
                ui_subscribable: false,
                max_subscribers: None,
            },
        }],
    };
    let handoff = ManifoldShellHandoffManifest {
        schema_id: schema("rusty.manifold.shell.handoff.v1"),
        handoff_id: id("shell_handoff.test"),
        handoff_revision: Revision::INITIAL,
        target_host_profile: id("host.headset"),
        shell_app_id: id("app.host_shell.headset"),
        validation_slot_id: id("host_run.slot.synthetic_smoke"),
        stream_bindings: vec![ManifoldShellStreamBinding {
            stream_id: id("stream.synthetic_wave"),
            direction: ShellStreamDirection::Subscribe,
            role: id("shell.stream.source_input"),
            required: true,
        }],
        command_ids: vec![id("command.module.start")],
        transport_offers: vec![TransportOffer {
            transport_id: id("transport.shell_loopback"),
            transport: EndpointTransport::Http,
            endpoint_id: Some(id("endpoint.headset_loopback")),
        }],
        expected_scorecard_id: id("scorecard.host_run.synthetic_smoke"),
    };

    let receipt = handoff.review_receipt(
        &registry,
        &[id("command.module.start")],
        &[id("endpoint.headset_loopback")],
        &[id("host_run.slot.synthetic_smoke")],
    );

    assert_eq!(receipt.status, ValidationStatus::Pass);
    assert_eq!(receipt.manifold_authority, id("authority.manifold"));
    assert!(!receipt.runtime_execution_performed);
    assert!(!receipt.platform_execution_performed);
    assert!(!receipt.launch_started);
    assert!(!receipt.command_session_started);
    assert!(!receipt.legacy_app_dependency_used);
    assert!(receipt.issues.is_empty());
    assert_eq!(receipt.validate_against_handoff(&handoff), Ok(()));
}
