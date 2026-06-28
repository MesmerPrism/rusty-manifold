use super::*;

mod bridge_route;
mod clock;
mod command_dispatch;
mod coordination;
mod expiry;
mod host_manifest;
mod leases;
mod lineage;
mod manifests_and_handoff;
mod module_runtime;
mod samples;
mod streams;

fn id(value: &str) -> DottedId {
    DottedId::new(value).unwrap()
}

fn schema(value: &str) -> SchemaId {
    SchemaId::new(value).unwrap()
}

fn assert_authority_validation_kind(
    label: &str,
    result: Result<(), ManifoldAuthorityValidationError>,
    expected: ManifoldAuthorityValidationErrorKind,
) {
    let error = result.unwrap_err();
    assert_eq!(error.kind(), expected, "{label}: {error}");
}

fn command_descriptor() -> ManifoldCommandDescriptor {
    ManifoldCommandDescriptor {
        schema_id: schema("rusty.manifold.command.descriptor.v1"),
        command_id: id("command.module.start"),
        target_scope: id("module.synthetic_wave_provider"),
        input_schema: schema("rusty.manifold.command.input.empty.v1"),
        required_capability: id("manifold.module.control"),
        required_lease_scope: Some(id("module.synthetic_wave_provider")),
        safety_class: SafetyClass::BoundedMutation,
        operator_confirmation_required: false,
    }
}

fn command_envelope() -> ManifoldCommandEnvelope {
    ManifoldCommandEnvelope {
        schema_id: schema("rusty.manifold.command.envelope.v1"),
        request_id: id("request.start.synthetic_wave"),
        command_id: id("command.module.start"),
        target_id: id("module.synthetic_wave_provider"),
        target_scope: id("module.synthetic_wave_provider"),
        input_schema: schema("rusty.manifold.command.input.empty.v1"),
        expected_revision: Some(Revision::INITIAL),
        required_capability: id("manifold.module.control"),
        lease_id: Some(id("lease.synthetic_module")),
        preconditions: Vec::new(),
        safety_class: SafetyClass::BoundedMutation,
        requested_at_ms: 1_765_000_000_000,
        holder_id: id("holder.test_agent"),
    }
}

fn active_lease() -> ManifoldControlLease {
    ManifoldControlLease {
        schema_id: schema("rusty.manifold.command.control_lease.v1"),
        lease_id: id("lease.synthetic_module"),
        holder_id: id("holder.test_agent"),
        scope: id("module.synthetic_wave_provider"),
        state: LeaseState::Active,
        granted_revision: Revision::INITIAL,
        expires_at_ms: 1_765_000_030_000,
        required_capability: id("manifold.module.control"),
    }
}

fn active_registry_lease() -> ManifoldControlLease {
    ManifoldControlLease {
        schema_id: schema("rusty.manifold.command.control_lease.v1"),
        lease_id: id("lease.synthetic_stream_registry"),
        holder_id: id("holder.test_agent"),
        scope: id("manifold.stream_registry"),
        state: LeaseState::Active,
        granted_revision: Revision::INITIAL,
        expires_at_ms: 1_765_000_030_000,
        required_capability: id("manifold.stream_registry.update"),
    }
}

fn active_host_manifest_lease() -> ManifoldControlLease {
    ManifoldControlLease {
        schema_id: schema("rusty.manifold.command.control_lease.v1"),
        lease_id: id("lease.synthetic_host_manifest"),
        holder_id: id("holder.test_agent"),
        scope: id("manifold.host_manifest"),
        state: LeaseState::Active,
        granted_revision: Revision::INITIAL,
        expires_at_ms: 1_765_000_030_000,
        required_capability: id("manifold.host_manifest.update"),
    }
}

fn active_clock_lease() -> ManifoldControlLease {
    ManifoldControlLease {
        schema_id: schema("rusty.manifold.command.control_lease.v1"),
        lease_id: id("lease.synthetic_clock"),
        holder_id: id("holder.test_agent"),
        scope: id("manifold.clock"),
        state: LeaseState::Active,
        granted_revision: Revision::INITIAL,
        expires_at_ms: 1_765_000_030_000,
        required_capability: id("manifold.clock.update"),
    }
}

fn synthetic_stream(max_subscribers: u32) -> ManifoldStreamManifest {
    ManifoldStreamManifest {
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
        transport_offers: vec![TransportOffer {
            transport_id: id("transport.in_process"),
            transport: EndpointTransport::InProcess,
            endpoint_id: None,
        }],
        subscription: SubscriptionPolicy {
            ui_subscribable: true,
            max_subscribers: Some(max_subscribers),
        },
    }
}

fn clock_snapshot(sequence: u64) -> ManifoldClockSnapshot {
    ManifoldClockSnapshot {
        schema_id: schema("rusty.manifold.clock.snapshot.v1"),
        clock_domain: id("clock.host_monotonic"),
        clock_epoch_id: id("clock_epoch.synthetic_1"),
        sequence,
        monotonic_elapsed_ns: 1_234_567_890,
        wall_unix_ms: 1_765_000_000_000,
        read_uncertainty_ns: 250_000,
        health: ClockHealth::Healthy,
        wall_clock_adjustment_count: 0,
    }
}

fn next_clock_snapshot() -> ManifoldClockSnapshot {
    ManifoldClockSnapshot {
        schema_id: schema("rusty.manifold.clock.snapshot.v1"),
        clock_domain: id("clock.host_monotonic"),
        clock_epoch_id: id("clock_epoch.synthetic_1"),
        sequence: 43,
        monotonic_elapsed_ns: 1_234_567_990,
        wall_unix_ms: 1_765_000_000_100,
        read_uncertainty_ns: 250_000,
        health: ClockHealth::Degraded,
        wall_clock_adjustment_count: 0,
    }
}

fn authority_snapshot() -> ManifoldAuthoritySnapshot {
    ManifoldAuthoritySnapshot {
        schema_id: schema("rusty.manifold.authority.snapshot.v1"),
        authority_id: id("authority.synthetic"),
        authority_revision: Revision::INITIAL,
        host_manifest: ManifoldHostManifest {
            schema_id: schema("rusty.manifold.host.manifest.v1"),
            host_id: id("host.synthetic"),
            authority_role: AuthorityRole::Primary,
            host_category: Some(id("host.synthetic")),
            clock_domain: id("clock.host_monotonic"),
            endpoints: Vec::new(),
            capabilities: vec![
                id("manifold.module.control"),
                id("manifold.graph.run"),
                id("manifold.host_manifest.update"),
                id("manifold.clock.update"),
            ],
            supported_backends: vec![id("backend.synthetic")],
            permissions: Vec::new(),
            lifecycle_limits: Vec::new(),
            missing_requirements: Vec::new(),
        },
        clock_snapshot: clock_snapshot(42),
        stream_registry: ManifoldStreamRegistrySnapshot {
            schema_id: schema("rusty.manifold.stream.registry_snapshot.v1"),
            registry_revision: Revision::INITIAL,
            streams: Vec::new(),
        },
        module_runtime_states: vec![ManifoldModuleRuntimeState {
            schema_id: schema("rusty.manifold.module.runtime_state.v1"),
            module_id: id("module.synthetic_wave_provider"),
            runtime_revision: Revision::INITIAL,
            lifecycle: ModuleLifecycleState::Running,
            health: HealthLevel::Healthy,
            selected_backend: Some(id("backend.synthetic")),
            active_streams: Vec::new(),
            active_commands: vec![id("command.module.start")],
            issues: Vec::new(),
        }],
        command_ids: vec![id("command.module.start")],
        command_descriptors: vec![command_descriptor()],
        active_leases: vec![
            active_lease(),
            active_host_manifest_lease(),
            active_clock_lease(),
        ],
        active_stream_subscriptions: Vec::new(),
    }
}

fn stream_authority_snapshot() -> ManifoldAuthoritySnapshot {
    let mut snapshot = authority_snapshot();
    snapshot
        .host_manifest
        .capabilities
        .push(id("manifold.stream_registry.update"));
    snapshot
        .host_manifest
        .capabilities
        .push(id("manifold.stream.subscribe"));
    snapshot.stream_registry = ManifoldStreamRegistrySnapshot {
        schema_id: schema("rusty.manifold.stream.registry_snapshot.v1"),
        registry_revision: Revision::INITIAL,
        streams: vec![synthetic_stream(8)],
    };
    snapshot.module_runtime_states[0].active_streams = vec![id("stream.synthetic_wave")];
    snapshot.active_leases.push(active_registry_lease());
    snapshot
}

fn accepted_command_audit_event() -> ManifoldCommandAuthorityAuditEvent {
    ManifoldCommandAuthorityAuditEvent {
        schema_id: schema("rusty.manifold.authority.command_audit_event.v1"),
        event_id: id("audit.command.start.synthetic_wave.accepted"),
        authority_id: id("authority.synthetic"),
        prior_authority_revision: Revision::INITIAL,
        event_kind: ManifoldCommandAuthorityAuditEventKind::CommandAccepted,
        envelope: command_envelope(),
        accepted: Some(ManifoldCommandAck {
            schema_id: schema("rusty.manifold.command.ack.v1"),
            request_id: id("request.start.synthetic_wave"),
            accepted_revision: Revision::new(2).unwrap(),
            lease_id: Some(id("lease.synthetic_module")),
            authority_id: id("authority.synthetic"),
            accepted_at_ms: 1_765_000_000_100,
        }),
        rejection: None,
        lease: Some(active_lease()),
        recorded_clock: clock_snapshot(43),
        evidence_refs: vec![id("evidence.command.start.synthetic_wave")],
    }
}

fn command_review_clock() -> ManifoldClockSnapshot {
    clock_snapshot(43)
}

fn lease_request() -> ManifoldControlLeaseRequest {
    ManifoldControlLeaseRequest {
        schema_id: schema("rusty.manifold.command.lease_request.v1"),
        request_id: id("request.synthetic_lease_1"),
        holder_id: id("holder.test_agent"),
        scope: id("manifold.graph"),
        expected_revision: Revision::INITIAL,
        requested_ttl_ms: 30_000,
        required_capability: id("manifold.graph.run"),
        safety_class: SafetyClass::BoundedMutation,
    }
}

fn stream_registry_change_request() -> ManifoldStreamRegistryChangeRequest {
    ManifoldStreamRegistryChangeRequest {
        schema_id: schema("rusty.manifold.stream.registry_change_request.v1"),
        request_id: id("request.stream_registry.synthetic_wave_subscription"),
        holder_id: id("holder.test_agent"),
        expected_authority_revision: Revision::INITIAL,
        lease_id: Some(id("lease.synthetic_stream_registry")),
        required_capability: id("manifold.stream_registry.update"),
        diff: ManifoldStreamRegistryDiff {
            schema_id: schema("rusty.manifold.stream.registry_diff.v1"),
            from_revision: Revision::INITIAL,
            to_revision: Revision::new(2).unwrap(),
            added_streams: Vec::new(),
            removed_streams: Vec::new(),
            changed_streams: vec![ManifoldStreamChange {
                stream_id: id("stream.synthetic_wave"),
                before: synthetic_stream(8),
                after: synthetic_stream(4),
            }],
        },
    }
}

fn stream_subscription_request() -> ManifoldStreamSubscriptionRequest {
    ManifoldStreamSubscriptionRequest {
        schema_id: schema("rusty.manifold.stream.subscription_request.v1"),
        request_id: id("request.stream_subscription.synthetic_wave_ui"),
        subscriber_id: id("subscriber.ui.synthetic_dashboard"),
        subscriber_kind: ManifoldStreamSubscriberKind::Ui,
        expected_authority_revision: Revision::INITIAL,
        expected_registry_revision: Revision::INITIAL,
        stream_id: id("stream.synthetic_wave"),
        transport_id: id("transport.in_process"),
        requested_ttl_ms: 30_000,
        required_capability: id("manifold.stream.subscribe"),
        requested_at_ms: 1_765_000_000_000,
    }
}

fn module_runtime_state_change_request() -> ManifoldModuleRuntimeStateChangeRequest {
    ManifoldModuleRuntimeStateChangeRequest {
        schema_id: schema("rusty.manifold.module.runtime_state_change_request.v1"),
        request_id: id("request.module_runtime.stop.synthetic_wave_provider"),
        holder_id: id("holder.test_agent"),
        expected_authority_revision: Revision::INITIAL,
        lease_id: Some(id("lease.synthetic_module")),
        required_capability: id("manifold.module.control"),
        module_id: id("module.synthetic_wave_provider"),
        from_runtime_revision: Revision::INITIAL,
        proposed_state: ManifoldModuleRuntimeState {
            schema_id: schema("rusty.manifold.module.runtime_state.v1"),
            module_id: id("module.synthetic_wave_provider"),
            runtime_revision: Revision::new(2).unwrap(),
            lifecycle: ModuleLifecycleState::Stopped,
            health: HealthLevel::Healthy,
            selected_backend: Some(id("backend.synthetic")),
            active_streams: Vec::new(),
            active_commands: vec![id("command.module.start")],
            issues: vec![ManifoldIssue {
                issue_code: id("issue.synthetic_stopped"),
                severity: IssueSeverity::Info,
                message: "Synthetic provider stopped cleanly.".to_owned(),
            }],
        },
    }
}

fn host_manifest_change_request() -> ManifoldHostManifestChangeRequest {
    let mut proposed_manifest = authority_snapshot().host_manifest;
    proposed_manifest.permissions = vec![id("permission.synthetic_diagnostics")];
    ManifoldHostManifestChangeRequest {
        schema_id: schema("rusty.manifold.host.manifest_change_request.v1"),
        request_id: id("request.host_manifest.synthetic_permissions"),
        holder_id: id("holder.test_agent"),
        expected_authority_revision: Revision::INITIAL,
        lease_id: Some(id("lease.synthetic_host_manifest")),
        required_capability: id("manifold.host_manifest.update"),
        proposed_manifest,
    }
}

fn clock_snapshot_change_request() -> ManifoldClockSnapshotChangeRequest {
    ManifoldClockSnapshotChangeRequest {
        schema_id: schema("rusty.manifold.clock.snapshot_change_request.v1"),
        request_id: id("request.clock.synthetic_tick"),
        holder_id: id("holder.test_agent"),
        expected_authority_revision: Revision::INITIAL,
        lease_id: Some(id("lease.synthetic_clock")),
        required_capability: id("manifold.clock.update"),
        from_clock_epoch_id: id("clock_epoch.synthetic_1"),
        from_clock_sequence: 42,
        proposed_snapshot: next_clock_snapshot(),
    }
}
