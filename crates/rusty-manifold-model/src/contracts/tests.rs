use super::*;

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

#[test]
fn command_envelope_accepts_matching_descriptor_revision_and_lease() {
    let result = command_envelope().validate_request(
        &command_descriptor(),
        Revision::INITIAL,
        Some(&active_lease()),
    );

    assert_eq!(result, Ok(()));
}

#[test]
fn command_envelope_rejects_stale_revision() {
    let current_revision = Revision::new(2).unwrap();
    let error = command_envelope()
        .validate_request(
            &command_descriptor(),
            current_revision,
            Some(&active_lease()),
        )
        .unwrap_err();

    assert_eq!(error.kind(), CommandValidationErrorKind::StaleRevision);
    assert_eq!(error.rejection_code(), "stale_revision");
}

#[test]
fn command_envelope_rejects_missing_required_lease() {
    let error = command_envelope()
        .validate_request(&command_descriptor(), Revision::INITIAL, None)
        .unwrap_err();

    assert_eq!(error.kind(), CommandValidationErrorKind::MissingLease);
    assert_eq!(error.rejection_code(), "missing_lease");
}

#[test]
fn authority_snapshot_validates_command_stream_host_clock_and_leases() {
    let snapshot = authority_snapshot();

    assert_eq!(snapshot.validate_authority_links(), Ok(()));
}

#[test]
fn command_authority_audit_event_validates_accepted_command() {
    let snapshot = authority_snapshot();
    let event = accepted_command_audit_event();

    assert_eq!(event.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn command_authority_review_accepts_valid_command() {
    let snapshot = authority_snapshot();
    let envelope = command_envelope();
    let review = snapshot
        .review_command(
            envelope,
            command_review_clock(),
            vec![id(
                "evidence.command_authority.request.start.synthetic_wave",
            )],
        )
        .unwrap();

    assert_eq!(
        review.outcome,
        ManifoldCommandAuthorityReviewOutcome::CommandAccepted
    );
    assert!(review.accepted.is_some());
    assert!(review.rejection.is_none());
    assert_eq!(review.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn command_authority_audit_event_rejects_skipped_acceptance_revision() {
    let snapshot = authority_snapshot();
    let mut event = accepted_command_audit_event();
    event
        .accepted
        .as_mut()
        .expect("accepted fixture is present")
        .accepted_revision = Revision::new(3).unwrap();

    let error = event.validate_against_snapshot(&snapshot).unwrap_err();

    assert_eq!(error.rejection_code(), "acceptance_revision_mismatch");
}

#[test]
fn command_dispatch_receipt_prepares_accepted_review() {
    let snapshot = authority_snapshot();
    let review = snapshot
        .review_command(
            command_envelope(),
            command_review_clock(),
            vec![id(
                "evidence.command_authority.request.start.synthetic_wave",
            )],
        )
        .unwrap();
    let receipt = snapshot.prepare_command_dispatch(review.clone()).unwrap();

    assert_eq!(
        receipt.outcome,
        ManifoldCommandDispatchReceiptOutcome::CommandDispatchReady
    );
    assert_eq!(receipt.ack, review.accepted);
    assert!(receipt.rejection.is_none());
    assert_eq!(receipt.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn command_dispatch_receipt_rejects_review_from_different_authority_revision() {
    let snapshot = authority_snapshot();
    let review = snapshot
        .review_command(
            command_envelope(),
            command_review_clock(),
            vec![id(
                "evidence.command_authority.request.start.synthetic_wave",
            )],
        )
        .unwrap();
    let mut next_snapshot = snapshot.clone();
    next_snapshot.authority_revision = Revision::new(2).unwrap();

    let error = next_snapshot.prepare_command_dispatch(review).unwrap_err();

    assert_eq!(error.rejection_code(), "authority_revision_mismatch");
}

#[test]
fn command_dispatch_receipt_rejects_receipt_review_request_mismatch() {
    let snapshot = authority_snapshot();
    let review = snapshot
        .review_command(
            command_envelope(),
            command_review_clock(),
            vec![id(
                "evidence.command_authority.request.start.synthetic_wave",
            )],
        )
        .unwrap();
    let mut receipt = snapshot.prepare_command_dispatch(review).unwrap();
    receipt.request_id = id("request.command_dispatch.lineage_mismatch");

    let error = receipt.validate_against_snapshot(&snapshot).unwrap_err();

    assert_eq!(error.rejection_code(), "request_id_mismatch");
}

#[test]
fn command_authority_audit_event_rejects_unknown_command() {
    let snapshot = authority_snapshot();
    let mut event = accepted_command_audit_event();
    event.envelope.command_id = id("command.module.not_registered");

    let error = event.validate_against_snapshot(&snapshot).unwrap_err();

    assert_eq!(error.rejection_code(), "unknown_command");
}

#[test]
fn command_authority_review_rejects_missing_lease() {
    let snapshot = authority_snapshot();
    let mut envelope = command_envelope();
    envelope.request_id = id("request.missing_lease.synthetic_wave");
    envelope.lease_id = None;
    let review = snapshot
        .review_command(
            envelope,
            command_review_clock(),
            vec![id(
                "evidence.command_authority.request.missing_lease.synthetic_wave",
            )],
        )
        .unwrap();

    assert_eq!(
        review.outcome,
        ManifoldCommandAuthorityReviewOutcome::CommandRejected
    );
    assert_eq!(
        review.rejection.as_ref().unwrap().rejection_code.as_str(),
        "missing_lease"
    );
    assert_eq!(review.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn command_dispatch_receipt_rejects_rejected_review() {
    let snapshot = authority_snapshot();
    let mut envelope = command_envelope();
    envelope.request_id = id("request.missing_lease.synthetic_wave");
    envelope.lease_id = None;
    let review = snapshot
        .review_command(
            envelope,
            command_review_clock(),
            vec![id(
                "evidence.command_authority.request.missing_lease.synthetic_wave",
            )],
        )
        .unwrap();
    let receipt = snapshot.prepare_command_dispatch(review).unwrap();

    assert_eq!(
        receipt.outcome,
        ManifoldCommandDispatchReceiptOutcome::CommandDispatchRejected
    );
    assert!(receipt.ack.is_none());
    assert_eq!(
        receipt
            .rejection
            .as_ref()
            .expect("dispatch rejection is present")
            .rejection_code
            .as_str(),
        "review_rejected"
    );
    assert_eq!(receipt.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn lease_authority_review_accepts_available_scope() {
    let snapshot = authority_snapshot();
    let request = lease_request();
    let review = snapshot
        .review_lease_request(
            request,
            command_review_clock(),
            vec![id("evidence.lease_authority.request.synthetic_lease_1")],
        )
        .unwrap();

    assert_eq!(
        review.outcome,
        ManifoldControlLeaseAuthorityReviewOutcome::LeaseAccepted
    );
    assert!(review.accepted.is_some());
    assert!(review.rejection.is_none());
    assert_eq!(review.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn lease_authority_application_advances_snapshot() {
    let snapshot = authority_snapshot();
    let review = snapshot
        .review_lease_request(
            lease_request(),
            command_review_clock(),
            vec![id("evidence.lease_authority.request.synthetic_lease_1")],
        )
        .unwrap();
    let application = snapshot
        .apply_control_lease_authority_review(review)
        .unwrap();

    assert_eq!(
        application.outcome,
        ManifoldControlLeaseAuthorityApplicationOutcome::LeaseApplied
    );
    assert!(application.rejection.is_none());
    let applied = application.applied_snapshot.as_ref().unwrap();
    assert_eq!(applied.authority_revision, Revision::new(2).unwrap());
    assert_eq!(
        applied.active_leases.len(),
        snapshot.active_leases.len() + 1
    );
    let accepted_lease = applied.active_leases.last().unwrap();
    assert_eq!(accepted_lease.lease_id.as_str(), "lease.synthetic_lease_1");
    assert_eq!(accepted_lease.scope.as_str(), "manifold.graph");
    assert_eq!(accepted_lease.granted_revision, Revision::INITIAL);
    assert_eq!(application.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn lease_authority_application_rejects_rejected_review() {
    let snapshot = authority_snapshot();
    let mut request = lease_request();
    request.request_id = id("request.lease.stale_graph");
    request.expected_revision = Revision::new(2).unwrap();
    let review = snapshot
        .review_lease_request(
            request,
            command_review_clock(),
            vec![id("evidence.lease_authority.request.lease.stale_graph")],
        )
        .unwrap();
    let application = snapshot
        .apply_control_lease_authority_review(review)
        .unwrap();

    assert_eq!(
        application.outcome,
        ManifoldControlLeaseAuthorityApplicationOutcome::LeaseApplicationRejected
    );
    assert!(application.applied_snapshot.is_none());
    assert_eq!(
        application
            .rejection
            .as_ref()
            .unwrap()
            .rejection_code
            .as_str(),
        "review_rejected"
    );
    assert_eq!(application.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn lease_release_authority_application_removes_active_lease() {
    let snapshot = authority_snapshot();
    let lease_review = snapshot
        .review_lease_request(
            lease_request(),
            command_review_clock(),
            vec![id("evidence.lease_authority.request.synthetic_lease_1")],
        )
        .unwrap();
    let lease_application = snapshot
        .apply_control_lease_authority_review(lease_review)
        .unwrap();
    let active_snapshot = lease_application.applied_snapshot.unwrap();
    let lease = active_snapshot.active_leases.last().unwrap().clone();
    let release_request = ManifoldControlLeaseReleaseRequest {
        schema_id: control_lease_release_request_schema_id(),
        request_id: id("request.lease_release.synthetic_lease_1"),
        lease_id: lease.lease_id.clone(),
        holder_id: lease.holder_id.clone(),
        expected_authority_revision: active_snapshot.authority_revision,
        scope: lease.scope.clone(),
        release_reason: id("holder.done"),
        requested_at_ms: 1_765_000_000_200,
    };
    let release_review = active_snapshot
        .review_control_lease_release(
            release_request,
            command_review_clock(),
            vec![id(
                "evidence.lease_release_authority.request.synthetic_lease_1",
            )],
        )
        .unwrap();

    assert_eq!(
        release_review.outcome,
        ManifoldControlLeaseReleaseAuthorityReviewOutcome::LeaseReleased
    );
    assert_eq!(release_review.released.as_ref(), Some(&lease));
    assert_eq!(
        release_review.validate_against_snapshot(&active_snapshot),
        Ok(())
    );

    let release_application = active_snapshot
        .apply_control_lease_release_authority_review(release_review)
        .unwrap();

    assert_eq!(
        release_application.outcome,
        ManifoldControlLeaseReleaseAuthorityApplicationOutcome::LeaseReleaseApplied
    );
    assert!(release_application.rejection.is_none());
    let applied = release_application.applied_snapshot.as_ref().unwrap();
    assert_eq!(applied.authority_revision, Revision::new(3).unwrap());
    assert_eq!(
        applied.active_leases.len(),
        active_snapshot.active_leases.len() - 1
    );
    assert!(!applied
        .active_leases
        .iter()
        .any(|active| active.lease_id == lease.lease_id));
    assert_eq!(
        release_application.validate_against_snapshot(&active_snapshot),
        Ok(())
    );
}

#[test]
fn lease_renewal_authority_application_replaces_active_lease() {
    let snapshot = authority_snapshot();
    let lease_review = snapshot
        .review_lease_request(
            lease_request(),
            command_review_clock(),
            vec![id("evidence.lease_authority.request.synthetic_lease_1")],
        )
        .unwrap();
    let lease_application = snapshot
        .apply_control_lease_authority_review(lease_review)
        .unwrap();
    let active_snapshot = lease_application.applied_snapshot.unwrap();
    let lease = active_snapshot.active_leases.last().unwrap().clone();
    let old_expires_at_ms = lease.expires_at_ms;
    let renewal_request = ManifoldControlLeaseRenewalRequest {
        schema_id: control_lease_renewal_request_schema_id(),
        request_id: id("request.lease_renewal.synthetic_lease_1"),
        lease_id: lease.lease_id.clone(),
        holder_id: lease.holder_id.clone(),
        expected_authority_revision: active_snapshot.authority_revision,
        scope: lease.scope.clone(),
        requested_ttl_ms: 60_000,
        renewal_reason: id("holder.needs_more_time"),
        requested_at_ms: 1_765_000_000_200,
    };
    let renewal_review = active_snapshot
        .review_control_lease_renewal(
            renewal_request,
            command_review_clock(),
            vec![id(
                "evidence.lease_renewal_authority.request.synthetic_lease_1",
            )],
        )
        .unwrap();

    assert_eq!(
        renewal_review.outcome,
        ManifoldControlLeaseRenewalAuthorityReviewOutcome::LeaseRenewed
    );
    let renewed = renewal_review.renewed.as_ref().unwrap();
    assert_eq!(renewed.lease_id, lease.lease_id);
    assert!(renewed.expires_at_ms > old_expires_at_ms);
    assert_eq!(
        renewal_review.validate_against_snapshot(&active_snapshot),
        Ok(())
    );

    let renewal_application = active_snapshot
        .apply_control_lease_renewal_authority_review(renewal_review)
        .unwrap();

    assert_eq!(
        renewal_application.outcome,
        ManifoldControlLeaseRenewalAuthorityApplicationOutcome::LeaseRenewalApplied
    );
    assert!(renewal_application.rejection.is_none());
    let applied = renewal_application.applied_snapshot.as_ref().unwrap();
    assert_eq!(applied.authority_revision, Revision::new(3).unwrap());
    assert_eq!(
        applied.active_leases.len(),
        active_snapshot.active_leases.len()
    );
    let renewed_lease = applied
        .active_leases
        .iter()
        .find(|active| active.lease_id == lease.lease_id)
        .unwrap();
    assert!(renewed_lease.expires_at_ms > old_expires_at_ms);
    assert_eq!(renewed_lease.granted_revision, Revision::new(2).unwrap());
    assert_eq!(
        renewal_application.validate_against_snapshot(&active_snapshot),
        Ok(())
    );
}

#[test]
fn lease_authority_review_rejects_busy_scope() {
    let snapshot = authority_snapshot();
    let mut request = lease_request();
    request.request_id = id("request.lease.busy_module");
    request.holder_id = id("holder.other_agent");
    request.scope = id("module.synthetic_wave_provider");
    request.required_capability = id("manifold.module.control");
    let review = snapshot
        .review_lease_request(
            request,
            command_review_clock(),
            vec![id("evidence.lease_authority.request.lease.busy_module")],
        )
        .unwrap();

    assert_eq!(
        review.outcome,
        ManifoldControlLeaseAuthorityReviewOutcome::LeaseRejected
    );
    assert_eq!(
        review.rejection.as_ref().unwrap().rejection_code.as_str(),
        "lease_scope_busy"
    );
    assert_eq!(
        review
            .rejection
            .as_ref()
            .unwrap()
            .conflicting_lease_id
            .as_ref()
            .unwrap()
            .as_str(),
        "lease.synthetic_module"
    );
    assert_eq!(review.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn stream_registry_authority_review_accepts_metadata_change() {
    let snapshot = stream_authority_snapshot();
    let request = stream_registry_change_request();
    let review = snapshot
        .review_stream_registry_change(
            request,
            command_review_clock(),
            vec![id(
                "evidence.stream_registry_authority.request.synthetic_wave_subscription",
            )],
        )
        .unwrap();

    assert_eq!(
        review.outcome,
        ManifoldStreamRegistryAuthorityReviewOutcome::RegistryAccepted
    );
    assert_eq!(
        review
            .accepted
            .as_ref()
            .unwrap()
            .streams
            .first()
            .unwrap()
            .subscription
            .max_subscribers,
        Some(4)
    );
    assert_eq!(review.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn stream_registry_authority_review_rejects_active_stream_removal() {
    let snapshot = stream_authority_snapshot();
    let mut request = stream_registry_change_request();
    request.request_id = id("request.stream_registry.remove_active_wave");
    request.diff.changed_streams.clear();
    request.diff.removed_streams = vec![synthetic_stream(8)];
    let review = snapshot
        .review_stream_registry_change(
            request,
            command_review_clock(),
            vec![id(
                "evidence.stream_registry_authority.request.remove_active_wave",
            )],
        )
        .unwrap();

    assert_eq!(
        review.outcome,
        ManifoldStreamRegistryAuthorityReviewOutcome::RegistryRejected
    );
    assert_eq!(
        review.rejection.as_ref().unwrap().rejection_code.as_str(),
        "active_stream_conflict"
    );
    assert_eq!(review.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn stream_registry_authority_application_advances_snapshot() {
    let snapshot = stream_authority_snapshot();
    let review = snapshot
        .review_stream_registry_change(
            stream_registry_change_request(),
            command_review_clock(),
            vec![id(
                "evidence.stream_registry_authority.request.synthetic_wave_subscription",
            )],
        )
        .unwrap();
    let application = snapshot
        .apply_stream_registry_authority_review(review)
        .unwrap();

    assert_eq!(
        application.outcome,
        ManifoldStreamRegistryAuthorityApplicationOutcome::RegistrySnapshotApplied
    );
    assert!(application.rejection.is_none());
    let applied = application.applied_snapshot.as_ref().unwrap();
    assert_eq!(applied.authority_revision, Revision::new(2).unwrap());
    assert_eq!(
        applied.stream_registry.registry_revision,
        Revision::new(2).unwrap()
    );
    assert_eq!(
        applied.stream_registry.streams[0]
            .subscription
            .max_subscribers,
        Some(4)
    );
    assert_eq!(application.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn stream_registry_authority_application_rejects_rejected_review() {
    let snapshot = stream_authority_snapshot();
    let mut request = stream_registry_change_request();
    request.request_id = id("request.stream_registry.stale_revision");
    request.expected_authority_revision = Revision::new(2).unwrap();
    let review = snapshot
        .review_stream_registry_change(
            request,
            command_review_clock(),
            vec![id(
                "evidence.stream_registry_authority.request.stale_revision",
            )],
        )
        .unwrap();
    let application = snapshot
        .apply_stream_registry_authority_review(review)
        .unwrap();

    assert_eq!(
        application.outcome,
        ManifoldStreamRegistryAuthorityApplicationOutcome::RegistryApplicationRejected
    );
    assert!(application.applied_snapshot.is_none());
    assert_eq!(
        application
            .rejection
            .as_ref()
            .unwrap()
            .rejection_code
            .as_str(),
        "review_rejected"
    );
    assert_eq!(application.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn stream_subscription_authority_review_accepts_ui_subscriber() {
    let snapshot = stream_authority_snapshot();
    let request = stream_subscription_request();
    let review = snapshot
        .review_stream_subscription(
            request,
            command_review_clock(),
            vec![id(
                "evidence.stream_subscription_authority.request.synthetic_wave_ui",
            )],
        )
        .unwrap();

    assert_eq!(
        review.outcome,
        ManifoldStreamSubscriptionAuthorityReviewOutcome::SubscriptionAccepted
    );
    let accepted = review.accepted.as_ref().unwrap();
    assert_eq!(accepted.stream_id, id("stream.synthetic_wave"));
    assert_eq!(accepted.transport_id, id("transport.in_process"));
    assert_eq!(accepted.accepted_authority_revision, Revision::INITIAL);
    assert_eq!(review.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn stream_subscription_authority_review_rejects_stale_registry() {
    let snapshot = stream_authority_snapshot();
    let mut request = stream_subscription_request();
    request.request_id = id("request.stream_subscription.stale_registry");
    request.expected_registry_revision = Revision::new(2).unwrap();
    let review = snapshot
        .review_stream_subscription(
            request,
            command_review_clock(),
            vec![id(
                "evidence.stream_subscription_authority.request.stale_registry",
            )],
        )
        .unwrap();

    assert_eq!(
        review.outcome,
        ManifoldStreamSubscriptionAuthorityReviewOutcome::SubscriptionRejected
    );
    assert_eq!(
        review.rejection.as_ref().unwrap().rejection_code.as_str(),
        "registry_revision_mismatch"
    );
    assert_eq!(review.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn stream_subscription_authority_review_rejects_subscriber_limit() {
    let mut snapshot = stream_authority_snapshot();
    snapshot.stream_registry.streams[0]
        .subscription
        .max_subscribers = Some(1);
    let review = snapshot
        .review_stream_subscription(
            stream_subscription_request(),
            command_review_clock(),
            vec![id(
                "evidence.stream_subscription_authority.request.synthetic_wave_ui",
            )],
        )
        .unwrap();
    let first_subscription = review.accepted.clone().unwrap();
    snapshot
        .active_stream_subscriptions
        .push(first_subscription);
    let mut second_request = stream_subscription_request();
    second_request.request_id = id("request.stream_subscription.second_ui");
    second_request.subscriber_id = id("subscriber.ui.second_dashboard");
    let review = snapshot
        .review_stream_subscription(
            second_request,
            command_review_clock(),
            vec![id(
                "evidence.stream_subscription_authority.request.second_ui",
            )],
        )
        .unwrap();

    assert_eq!(
        review.outcome,
        ManifoldStreamSubscriptionAuthorityReviewOutcome::SubscriptionRejected
    );
    assert_eq!(
        review.rejection.as_ref().unwrap().rejection_code.as_str(),
        "subscriber_limit_reached"
    );
    assert_eq!(review.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn stream_subscription_authority_application_appends_subscription() {
    let snapshot = stream_authority_snapshot();
    let review = snapshot
        .review_stream_subscription(
            stream_subscription_request(),
            command_review_clock(),
            vec![id(
                "evidence.stream_subscription_authority.request.synthetic_wave_ui",
            )],
        )
        .unwrap();
    let application = snapshot
        .apply_stream_subscription_authority_review(review)
        .unwrap();

    assert_eq!(
        application.outcome,
        ManifoldStreamSubscriptionAuthorityApplicationOutcome::SubscriptionApplied
    );
    assert!(application.rejection.is_none());
    let applied = application.applied_snapshot.as_ref().unwrap();
    assert_eq!(applied.authority_revision, Revision::new(2).unwrap());
    assert_eq!(applied.active_stream_subscriptions.len(), 1);
    assert_eq!(application.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn stream_subscription_release_application_removes_subscription() {
    let snapshot = stream_authority_snapshot();
    let subscription_review = snapshot
        .review_stream_subscription(
            stream_subscription_request(),
            command_review_clock(),
            vec![id(
                "evidence.stream_subscription_authority.request.synthetic_wave_ui",
            )],
        )
        .unwrap();
    let subscription_application = snapshot
        .apply_stream_subscription_authority_review(subscription_review)
        .unwrap();
    let active_snapshot = subscription_application.applied_snapshot.unwrap();
    let subscription = active_snapshot.active_stream_subscriptions[0].clone();
    let release_request = ManifoldStreamSubscriptionReleaseRequest {
        schema_id: stream_subscription_release_request_schema_id(),
        request_id: id("request.stream_subscription_release.synthetic_wave_ui"),
        subscription_id: subscription.subscription_id.clone(),
        subscriber_id: subscription.subscriber_id.clone(),
        expected_authority_revision: active_snapshot.authority_revision,
        expected_registry_revision: active_snapshot.stream_registry.registry_revision,
        stream_id: subscription.stream_id.clone(),
        release_reason: id("subscriber.closed"),
        requested_at_ms: 1_765_000_000_200,
    };
    let release_review = active_snapshot
        .review_stream_subscription_release(
            release_request,
            command_review_clock(),
            vec![id(
                "evidence.stream_subscription_release_authority.request.synthetic_wave_ui",
            )],
        )
        .unwrap();

    assert_eq!(
        release_review.outcome,
        ManifoldStreamSubscriptionReleaseAuthorityReviewOutcome::SubscriptionReleased
    );
    assert_eq!(release_review.released.as_ref(), Some(&subscription));
    assert_eq!(
        release_review.validate_against_snapshot(&active_snapshot),
        Ok(())
    );

    let release_application = active_snapshot
        .apply_stream_subscription_release_authority_review(release_review)
        .unwrap();

    assert_eq!(
        release_application.outcome,
        ManifoldStreamSubscriptionReleaseAuthorityApplicationOutcome::SubscriptionReleaseApplied
    );
    assert!(release_application.rejection.is_none());
    let applied = release_application.applied_snapshot.as_ref().unwrap();
    assert_eq!(applied.authority_revision, Revision::new(3).unwrap());
    assert!(applied.active_stream_subscriptions.is_empty());
    assert_eq!(
        release_application.validate_against_snapshot(&active_snapshot),
        Ok(())
    );
}

#[test]
fn stream_subscription_renewal_application_replaces_subscription() {
    let snapshot = stream_authority_snapshot();
    let subscription_review = snapshot
        .review_stream_subscription(
            stream_subscription_request(),
            command_review_clock(),
            vec![id(
                "evidence.stream_subscription_authority.request.synthetic_wave_ui",
            )],
        )
        .unwrap();
    let subscription_application = snapshot
        .apply_stream_subscription_authority_review(subscription_review)
        .unwrap();
    let active_snapshot = subscription_application.applied_snapshot.unwrap();
    let subscription = active_snapshot.active_stream_subscriptions[0].clone();
    let old_expires_at_ms = subscription.expires_at_ms;
    let renewal_request = ManifoldStreamSubscriptionRenewalRequest {
        schema_id: stream_subscription_renewal_request_schema_id(),
        request_id: id("request.stream_subscription_renewal.synthetic_wave_ui"),
        subscription_id: subscription.subscription_id.clone(),
        subscriber_id: subscription.subscriber_id.clone(),
        expected_authority_revision: active_snapshot.authority_revision,
        expected_registry_revision: active_snapshot.stream_registry.registry_revision,
        stream_id: subscription.stream_id.clone(),
        transport_id: subscription.transport_id.clone(),
        requested_ttl_ms: 60_000,
        renewal_reason: id("subscriber.needs_more_time"),
        requested_at_ms: 1_765_000_000_200,
    };
    let renewal_review = active_snapshot
        .review_stream_subscription_renewal(
            renewal_request,
            command_review_clock(),
            vec![id(
                "evidence.stream_subscription_renewal_authority.request.synthetic_wave_ui",
            )],
        )
        .unwrap();

    assert_eq!(
        renewal_review.outcome,
        ManifoldStreamSubscriptionRenewalAuthorityReviewOutcome::SubscriptionRenewed
    );
    let renewed = renewal_review.renewed.as_ref().unwrap();
    assert_eq!(renewed.subscription_id, subscription.subscription_id);
    assert!(renewed.expires_at_ms > old_expires_at_ms);
    assert_eq!(
        renewal_review.validate_against_snapshot(&active_snapshot),
        Ok(())
    );

    let renewal_application = active_snapshot
        .apply_stream_subscription_renewal_authority_review(renewal_review)
        .unwrap();

    assert_eq!(
        renewal_application.outcome,
        ManifoldStreamSubscriptionRenewalAuthorityApplicationOutcome::SubscriptionRenewalApplied
    );
    assert!(renewal_application.rejection.is_none());
    let applied = renewal_application.applied_snapshot.as_ref().unwrap();
    assert_eq!(applied.authority_revision, Revision::new(3).unwrap());
    assert_eq!(
        applied.active_stream_subscriptions.len(),
        active_snapshot.active_stream_subscriptions.len()
    );
    let renewed_subscription = applied
        .active_stream_subscriptions
        .iter()
        .find(|active| active.subscription_id == subscription.subscription_id)
        .unwrap();
    assert!(renewed_subscription.expires_at_ms > old_expires_at_ms);
    assert_eq!(
        renewed_subscription.accepted_authority_revision,
        Revision::new(2).unwrap()
    );
    assert_eq!(
        renewal_application.validate_against_snapshot(&active_snapshot),
        Ok(())
    );
}

#[test]
fn authority_expiry_sweep_application_removes_expired_state() {
    let snapshot = stream_authority_snapshot();
    let subscription_review = snapshot
        .review_stream_subscription(
            stream_subscription_request(),
            command_review_clock(),
            vec![id(
                "evidence.stream_subscription_authority.request.synthetic_wave_ui",
            )],
        )
        .unwrap();
    let subscription_application = snapshot
        .apply_stream_subscription_authority_review(subscription_review)
        .unwrap();
    let active_snapshot = subscription_application.applied_snapshot.unwrap();
    let mut expired_clock = command_review_clock();
    expired_clock.sequence = 44;
    expired_clock.monotonic_elapsed_ns = 3_334_567_990;
    expired_clock.wall_unix_ms = 1_765_000_030_200;
    let request = ManifoldAuthorityExpirySweepRequest {
        schema_id: authority_expiry_sweep_request_schema_id(),
        request_id: id("request.expiry_sweep.synthetic"),
        requester_id: id("authority.synthetic"),
        expected_authority_revision: active_snapshot.authority_revision,
        expected_registry_revision: active_snapshot.stream_registry.registry_revision,
        sweep_reason: id("maintenance.ttl_expired"),
        requested_at_ms: 1_765_000_030_200,
    };

    let review = active_snapshot
        .review_authority_expiry_sweep(
            request,
            expired_clock,
            vec![id("evidence.expiry_sweep.synthetic")],
        )
        .unwrap();

    assert_eq!(
        review.outcome,
        ManifoldAuthorityExpirySweepAuthorityReviewOutcome::ExpiredStateAccepted
    );
    assert_eq!(
        review.expired_leases.len(),
        active_snapshot.active_leases.len()
    );
    assert_eq!(
        review.expired_stream_subscriptions.len(),
        active_snapshot.active_stream_subscriptions.len()
    );
    assert_eq!(review.validate_against_snapshot(&active_snapshot), Ok(()));

    let application = active_snapshot
        .apply_authority_expiry_sweep_review(review)
        .unwrap();

    assert_eq!(
        application.outcome,
        ManifoldAuthorityExpirySweepAuthorityApplicationOutcome::ExpiredStateApplied
    );
    assert!(application.rejection.is_none());
    let applied = application.applied_snapshot.as_ref().unwrap();
    assert_eq!(applied.authority_revision, Revision::new(3).unwrap());
    assert!(applied.active_leases.is_empty());
    assert!(applied.active_stream_subscriptions.is_empty());
    assert_eq!(
        application.validate_against_snapshot(&active_snapshot),
        Ok(())
    );
}

#[test]
fn module_runtime_state_authority_review_accepts_stop_transition() {
    let snapshot = stream_authority_snapshot();
    let request = module_runtime_state_change_request();
    let review = snapshot
        .review_module_runtime_state_change(
            request,
            command_review_clock(),
            vec![id(
                "evidence.module_runtime_state_authority.request.stop.synthetic_wave_provider",
            )],
        )
        .unwrap();

    assert_eq!(
        review.outcome,
        ManifoldModuleRuntimeStateAuthorityReviewOutcome::RuntimeStateAccepted
    );
    assert_eq!(
        review.accepted.as_ref().unwrap().lifecycle,
        ModuleLifecycleState::Stopped
    );
    assert_eq!(
        review.transition.as_ref().unwrap().deactivated_streams,
        vec![id("stream.synthetic_wave")]
    );
    assert_eq!(review.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn module_runtime_state_authority_review_rejects_unknown_stream() {
    let snapshot = stream_authority_snapshot();
    let mut request = module_runtime_state_change_request();
    request.request_id = id("request.module_runtime.unknown_stream");
    request.proposed_state.lifecycle = ModuleLifecycleState::Running;
    request.proposed_state.active_streams = vec![id("stream.not_registered")];
    let review = snapshot
        .review_module_runtime_state_change(
            request,
            command_review_clock(),
            vec![id(
                "evidence.module_runtime_state_authority.request.unknown_stream",
            )],
        )
        .unwrap();

    assert_eq!(
        review.outcome,
        ManifoldModuleRuntimeStateAuthorityReviewOutcome::RuntimeStateRejected
    );
    assert_eq!(
        review.rejection.as_ref().unwrap().rejection_code.as_str(),
        "unknown_stream"
    );
    assert_eq!(review.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn module_runtime_state_authority_application_advances_snapshot() {
    let snapshot = stream_authority_snapshot();
    let review = snapshot
        .review_module_runtime_state_change(
            module_runtime_state_change_request(),
            command_review_clock(),
            vec![id(
                "evidence.module_runtime_state_authority.request.stop.synthetic_wave_provider",
            )],
        )
        .unwrap();
    let application = snapshot
        .apply_module_runtime_state_authority_review(review)
        .unwrap();

    assert_eq!(
        application.outcome,
        ManifoldModuleRuntimeStateAuthorityApplicationOutcome::RuntimeStateApplied
    );
    assert!(application.rejection.is_none());
    let applied = application.applied_snapshot.as_ref().unwrap();
    assert_eq!(applied.authority_revision, Revision::new(2).unwrap());
    let runtime_state = applied
        .module_runtime_state(&id("module.synthetic_wave_provider"))
        .unwrap();
    assert_eq!(runtime_state.lifecycle, ModuleLifecycleState::Stopped);
    assert_eq!(runtime_state.runtime_revision, Revision::new(2).unwrap());
    assert!(runtime_state.active_streams.is_empty());
    assert_eq!(application.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn module_runtime_state_authority_application_rejects_rejected_review() {
    let snapshot = stream_authority_snapshot();
    let mut request = module_runtime_state_change_request();
    request.request_id = id("request.module_runtime.stale_revision");
    request.expected_authority_revision = Revision::new(2).unwrap();
    let review = snapshot
        .review_module_runtime_state_change(
            request,
            command_review_clock(),
            vec![id(
                "evidence.module_runtime_state_authority.request.stale_revision",
            )],
        )
        .unwrap();
    let application = snapshot
        .apply_module_runtime_state_authority_review(review)
        .unwrap();

    assert_eq!(
        application.outcome,
        ManifoldModuleRuntimeStateAuthorityApplicationOutcome::RuntimeStateApplicationRejected
    );
    assert!(application.applied_snapshot.is_none());
    assert_eq!(
        application
            .rejection
            .as_ref()
            .unwrap()
            .rejection_code
            .as_str(),
        "review_rejected"
    );
    assert_eq!(application.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn host_manifest_authority_review_accepts_permission_change() {
    let snapshot = authority_snapshot();
    let request = host_manifest_change_request();
    let review = snapshot
        .review_host_manifest_change(
            request,
            command_review_clock(),
            vec![id(
                "evidence.host_manifest_authority.request.synthetic_permissions",
            )],
        )
        .unwrap();

    assert_eq!(
        review.outcome,
        ManifoldHostManifestAuthorityReviewOutcome::HostManifestAccepted
    );
    assert_eq!(
        review.accepted.as_ref().unwrap().permissions,
        vec![id("permission.synthetic_diagnostics")]
    );
    assert_eq!(review.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn host_manifest_authority_review_rejects_missing_authority_role() {
    let snapshot = authority_snapshot();
    let mut request = host_manifest_change_request();
    request.request_id = id("request.host_manifest.missing_authority_role");
    request.proposed_manifest.authority_role = AuthorityRole::None;
    let review = snapshot
        .review_host_manifest_change(
            request,
            command_review_clock(),
            vec![id(
                "evidence.host_manifest_authority.request.missing_authority_role",
            )],
        )
        .unwrap();

    assert_eq!(
        review.outcome,
        ManifoldHostManifestAuthorityReviewOutcome::HostManifestRejected
    );
    assert_eq!(
        review.rejection.as_ref().unwrap().rejection_code.as_str(),
        "missing_authority_role"
    );
    assert_eq!(review.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn host_manifest_authority_review_rejects_backend_in_use_removal() {
    let snapshot = authority_snapshot();
    let mut request = host_manifest_change_request();
    request.request_id = id("request.host_manifest.remove_backend");
    request.proposed_manifest.supported_backends.clear();
    let review = snapshot
        .review_host_manifest_change(
            request,
            command_review_clock(),
            vec![id(
                "evidence.host_manifest_authority.request.remove_backend",
            )],
        )
        .unwrap();

    assert_eq!(
        review.outcome,
        ManifoldHostManifestAuthorityReviewOutcome::HostManifestRejected
    );
    assert_eq!(
        review.rejection.as_ref().unwrap().rejection_code.as_str(),
        "backend_in_use"
    );
    assert_eq!(review.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn host_manifest_authority_application_advances_snapshot() {
    let snapshot = authority_snapshot();
    let review = snapshot
        .review_host_manifest_change(
            host_manifest_change_request(),
            command_review_clock(),
            vec![id(
                "evidence.host_manifest_authority.request.synthetic_permissions",
            )],
        )
        .unwrap();
    let application = snapshot
        .apply_host_manifest_authority_review(review)
        .unwrap();

    assert_eq!(
        application.outcome,
        ManifoldHostManifestAuthorityApplicationOutcome::HostManifestApplied
    );
    assert!(application.rejection.is_none());
    let applied = application.applied_snapshot.as_ref().unwrap();
    assert_eq!(applied.authority_revision, Revision::new(2).unwrap());
    assert_eq!(
        applied.host_manifest.permissions,
        vec![id("permission.synthetic_diagnostics")]
    );
    assert_eq!(application.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn host_manifest_authority_application_rejects_rejected_review() {
    let snapshot = authority_snapshot();
    let mut request = host_manifest_change_request();
    request.request_id = id("request.host_manifest.stale_revision");
    request.expected_authority_revision = Revision::new(2).unwrap();
    let review = snapshot
        .review_host_manifest_change(
            request,
            command_review_clock(),
            vec![id(
                "evidence.host_manifest_authority.request.stale_revision",
            )],
        )
        .unwrap();
    let application = snapshot
        .apply_host_manifest_authority_review(review)
        .unwrap();

    assert_eq!(
        application.outcome,
        ManifoldHostManifestAuthorityApplicationOutcome::HostManifestApplicationRejected
    );
    assert!(application.applied_snapshot.is_none());
    assert_eq!(
        application
            .rejection
            .as_ref()
            .unwrap()
            .rejection_code
            .as_str(),
        "review_rejected"
    );
    assert_eq!(application.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn clock_snapshot_authority_review_accepts_next_tick() {
    let snapshot = authority_snapshot();
    let request = clock_snapshot_change_request();
    let review = snapshot
        .review_clock_snapshot_change(
            request,
            command_review_clock(),
            vec![id(
                "evidence.clock_snapshot_authority.request.synthetic_tick",
            )],
        )
        .unwrap();

    assert_eq!(
        review.outcome,
        ManifoldClockSnapshotAuthorityReviewOutcome::ClockSnapshotAccepted
    );
    assert_eq!(review.accepted.as_ref().unwrap().sequence, 43);
    assert_eq!(
        review.accepted.as_ref().unwrap().health,
        ClockHealth::Degraded
    );
    assert_eq!(review.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn clock_snapshot_authority_application_advances_snapshot() {
    let snapshot = authority_snapshot();
    let review = snapshot
        .review_clock_snapshot_change(
            clock_snapshot_change_request(),
            command_review_clock(),
            vec![id(
                "evidence.clock_snapshot_authority.request.synthetic_tick",
            )],
        )
        .unwrap();
    let application = snapshot
        .apply_clock_snapshot_authority_review(review)
        .unwrap();

    assert_eq!(
        application.outcome,
        ManifoldClockSnapshotAuthorityApplicationOutcome::ClockSnapshotApplied
    );
    assert!(application.rejection.is_none());
    let applied = application.applied_snapshot.as_ref().unwrap();
    assert_eq!(applied.authority_revision, Revision::new(2).unwrap());
    assert_eq!(applied.clock_snapshot.sequence, 43);
    assert_eq!(
        applied.clock_snapshot.clock_epoch_id,
        snapshot.clock_snapshot.clock_epoch_id
    );
    assert_eq!(applied.clock_snapshot.health, ClockHealth::Degraded);
    assert_eq!(application.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn clock_snapshot_authority_application_rejects_rejected_review() {
    let snapshot = authority_snapshot();
    let mut request = clock_snapshot_change_request();
    request.request_id = id("request.clock.stale_revision");
    request.expected_authority_revision = Revision::new(2).unwrap();
    let review = snapshot
        .review_clock_snapshot_change(
            request,
            command_review_clock(),
            vec![id(
                "evidence.clock_snapshot_authority.request.stale_revision",
            )],
        )
        .unwrap();
    let application = snapshot
        .apply_clock_snapshot_authority_review(review)
        .unwrap();

    assert_eq!(
        application.outcome,
        ManifoldClockSnapshotAuthorityApplicationOutcome::ClockSnapshotApplicationRejected
    );
    assert!(application.applied_snapshot.is_none());
    assert_eq!(
        application
            .rejection
            .as_ref()
            .unwrap()
            .rejection_code
            .as_str(),
        "review_rejected"
    );
    assert_eq!(application.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn clock_snapshot_authority_review_rejects_sequence_gap() {
    let snapshot = authority_snapshot();
    let mut request = clock_snapshot_change_request();
    request.request_id = id("request.clock.sequence_gap");
    request.proposed_snapshot.sequence = 44;
    let review = snapshot
        .review_clock_snapshot_change(
            request,
            command_review_clock(),
            vec![id("evidence.clock_snapshot_authority.request.sequence_gap")],
        )
        .unwrap();

    assert_eq!(
        review.outcome,
        ManifoldClockSnapshotAuthorityReviewOutcome::ClockSnapshotRejected
    );
    assert_eq!(
        review.rejection.as_ref().unwrap().rejection_code.as_str(),
        "clock_sequence_mismatch"
    );
    assert_eq!(review.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn clock_snapshot_authority_review_rejects_monotonic_regression() {
    let snapshot = authority_snapshot();
    let mut request = clock_snapshot_change_request();
    request.request_id = id("request.clock.monotonic_regression");
    request.proposed_snapshot.monotonic_elapsed_ns = snapshot.clock_snapshot.monotonic_elapsed_ns;
    let review = snapshot
        .review_clock_snapshot_change(
            request,
            command_review_clock(),
            vec![id(
                "evidence.clock_snapshot_authority.request.monotonic_regression",
            )],
        )
        .unwrap();

    assert_eq!(
        review.outcome,
        ManifoldClockSnapshotAuthorityReviewOutcome::ClockSnapshotRejected
    );
    assert_eq!(
        review.rejection.as_ref().unwrap().rejection_code.as_str(),
        "monotonic_time_regression"
    );
    assert_eq!(review.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn authority_application_lineage_matrix_rejects_mutated_review_revision_and_counts() {
    {
        let snapshot = authority_snapshot();
        let review = snapshot
            .review_command(
                command_envelope(),
                command_review_clock(),
                vec![id(
                    "evidence.command_authority.request.start.synthetic_wave",
                )],
            )
            .unwrap();
        let receipt = snapshot.prepare_command_dispatch(review).unwrap();
        assert_eq!(receipt.validate_against_snapshot(&snapshot), Ok(()));

        let mut mismatched_review = receipt.clone();
        mismatched_review.review.review_id = id("command_review.request.command.lineage_mismatch");
        assert_authority_validation_kind(
            "command dispatch review id lineage",
            mismatched_review.validate_against_snapshot(&snapshot),
            ManifoldAuthorityValidationErrorKind::RequestIdMismatch,
        );

        let mut mismatched_revision = receipt;
        mismatched_revision.authority_revision = Revision::new(2).unwrap();
        assert_authority_validation_kind(
            "command dispatch authority revision",
            mismatched_revision.validate_against_snapshot(&snapshot),
            ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
        );
    }

    {
        let snapshot = authority_snapshot();
        let review = snapshot
            .review_lease_request(
                lease_request(),
                command_review_clock(),
                vec![id("evidence.lease_authority.request.synthetic_lease_1")],
            )
            .unwrap();
        let application = snapshot
            .apply_control_lease_authority_review(review)
            .unwrap();
        assert_eq!(application.validate_against_snapshot(&snapshot), Ok(()));

        let mut mismatched_review = application.clone();
        mismatched_review.review.review_id = id("lease_review.request.lease.lineage_mismatch");
        assert_authority_validation_kind(
            "lease application review id lineage",
            mismatched_review.validate_against_snapshot(&snapshot),
            ManifoldAuthorityValidationErrorKind::RequestIdMismatch,
        );

        let mut mismatched_revision = application.clone();
        mismatched_revision.from_authority_revision = Revision::new(2).unwrap();
        assert_authority_validation_kind(
            "lease application authority revision",
            mismatched_revision.validate_against_snapshot(&snapshot),
            ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
        );

        let mut mismatched_count = application;
        mismatched_count.from_active_lease_count += 1;
        assert_authority_validation_kind(
            "lease application active lease count",
            mismatched_count.validate_against_snapshot(&snapshot),
            ManifoldAuthorityValidationErrorKind::LeaseMismatch,
        );
    }

    {
        let snapshot = authority_snapshot();
        let lease_review = snapshot
            .review_lease_request(
                lease_request(),
                command_review_clock(),
                vec![id("evidence.lease_authority.request.synthetic_lease_1")],
            )
            .unwrap();
        let lease_application = snapshot
            .apply_control_lease_authority_review(lease_review)
            .unwrap();
        let active_snapshot = lease_application.applied_snapshot.unwrap();
        let lease = active_snapshot.active_leases.last().unwrap().clone();
        let release_request = ManifoldControlLeaseReleaseRequest {
            schema_id: control_lease_release_request_schema_id(),
            request_id: id("request.lease_release.synthetic_lease_1"),
            lease_id: lease.lease_id.clone(),
            holder_id: lease.holder_id.clone(),
            expected_authority_revision: active_snapshot.authority_revision,
            scope: lease.scope.clone(),
            release_reason: id("holder.done"),
            requested_at_ms: 1_765_000_000_200,
        };
        let release_review = active_snapshot
            .review_control_lease_release(
                release_request,
                command_review_clock(),
                vec![id(
                    "evidence.lease_release_authority.request.synthetic_lease_1",
                )],
            )
            .unwrap();
        let application = active_snapshot
            .apply_control_lease_release_authority_review(release_review)
            .unwrap();
        assert_eq!(
            application.validate_against_snapshot(&active_snapshot),
            Ok(())
        );

        let mut mismatched_review = application.clone();
        mismatched_review.review.review_id =
            id("lease_release_review.request.lease_release.lineage_mismatch");
        assert_authority_validation_kind(
            "lease release application review id lineage",
            mismatched_review.validate_against_snapshot(&active_snapshot),
            ManifoldAuthorityValidationErrorKind::RequestIdMismatch,
        );

        let mut mismatched_revision = application.clone();
        mismatched_revision.from_authority_revision = Revision::INITIAL;
        assert_authority_validation_kind(
            "lease release application authority revision",
            mismatched_revision.validate_against_snapshot(&active_snapshot),
            ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
        );

        let mut mismatched_count = application;
        mismatched_count.from_active_lease_count += 1;
        assert_authority_validation_kind(
            "lease release application active lease count",
            mismatched_count.validate_against_snapshot(&active_snapshot),
            ManifoldAuthorityValidationErrorKind::LeaseMismatch,
        );
    }

    {
        let snapshot = authority_snapshot();
        let lease_review = snapshot
            .review_lease_request(
                lease_request(),
                command_review_clock(),
                vec![id("evidence.lease_authority.request.synthetic_lease_1")],
            )
            .unwrap();
        let lease_application = snapshot
            .apply_control_lease_authority_review(lease_review)
            .unwrap();
        let active_snapshot = lease_application.applied_snapshot.unwrap();
        let lease = active_snapshot.active_leases.last().unwrap().clone();
        let renewal_request = ManifoldControlLeaseRenewalRequest {
            schema_id: control_lease_renewal_request_schema_id(),
            request_id: id("request.lease_renewal.synthetic_lease_1"),
            lease_id: lease.lease_id.clone(),
            holder_id: lease.holder_id.clone(),
            expected_authority_revision: active_snapshot.authority_revision,
            scope: lease.scope.clone(),
            requested_ttl_ms: 60_000,
            renewal_reason: id("holder.needs_more_time"),
            requested_at_ms: 1_765_000_000_200,
        };
        let renewal_review = active_snapshot
            .review_control_lease_renewal(
                renewal_request,
                command_review_clock(),
                vec![id(
                    "evidence.lease_renewal_authority.request.synthetic_lease_1",
                )],
            )
            .unwrap();
        let application = active_snapshot
            .apply_control_lease_renewal_authority_review(renewal_review)
            .unwrap();
        assert_eq!(
            application.validate_against_snapshot(&active_snapshot),
            Ok(())
        );

        let mut mismatched_review = application.clone();
        mismatched_review.review.review_id =
            id("lease_renewal_review.request.lease_renewal.lineage_mismatch");
        assert_authority_validation_kind(
            "lease renewal application review id lineage",
            mismatched_review.validate_against_snapshot(&active_snapshot),
            ManifoldAuthorityValidationErrorKind::RequestIdMismatch,
        );

        let mut mismatched_revision = application.clone();
        mismatched_revision.from_authority_revision = Revision::INITIAL;
        assert_authority_validation_kind(
            "lease renewal application authority revision",
            mismatched_revision.validate_against_snapshot(&active_snapshot),
            ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
        );

        let mut mismatched_count = application;
        mismatched_count.from_active_lease_count += 1;
        assert_authority_validation_kind(
            "lease renewal application active lease count",
            mismatched_count.validate_against_snapshot(&active_snapshot),
            ManifoldAuthorityValidationErrorKind::LeaseMismatch,
        );
    }

    {
        let snapshot = stream_authority_snapshot();
        let review = snapshot
            .review_stream_registry_change(
                stream_registry_change_request(),
                command_review_clock(),
                vec![id(
                    "evidence.stream_registry_authority.request.synthetic_wave_subscription",
                )],
            )
            .unwrap();
        let application = snapshot
            .apply_stream_registry_authority_review(review)
            .unwrap();
        assert_eq!(application.validate_against_snapshot(&snapshot), Ok(()));

        let mut mismatched_review = application.clone();
        mismatched_review.review.review_id =
            id("stream_registry_review.request.stream_registry.lineage_mismatch");
        assert_authority_validation_kind(
            "stream registry application review id lineage",
            mismatched_review.validate_against_snapshot(&snapshot),
            ManifoldAuthorityValidationErrorKind::RequestIdMismatch,
        );

        let mut mismatched_revision = application.clone();
        mismatched_revision.from_authority_revision = Revision::new(2).unwrap();
        assert_authority_validation_kind(
            "stream registry application authority revision",
            mismatched_revision.validate_against_snapshot(&snapshot),
            ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
        );

        let mut mismatched_registry_revision = application;
        mismatched_registry_revision.from_registry_revision = Revision::new(2).unwrap();
        assert_authority_validation_kind(
            "stream registry application registry revision",
            mismatched_registry_revision.validate_against_snapshot(&snapshot),
            ManifoldAuthorityValidationErrorKind::RegistryRevisionMismatch,
        );
    }

    {
        let snapshot = stream_authority_snapshot();
        let review = snapshot
            .review_stream_subscription(
                stream_subscription_request(),
                command_review_clock(),
                vec![id(
                    "evidence.stream_subscription_authority.request.synthetic_wave_ui",
                )],
            )
            .unwrap();
        let application = snapshot
            .apply_stream_subscription_authority_review(review)
            .unwrap();
        assert_eq!(application.validate_against_snapshot(&snapshot), Ok(()));

        let mut mismatched_review = application.clone();
        mismatched_review.review.review_id =
            id("stream_subscription_review.request.stream_subscription.lineage_mismatch");
        assert_authority_validation_kind(
            "stream subscription application review id lineage",
            mismatched_review.validate_against_snapshot(&snapshot),
            ManifoldAuthorityValidationErrorKind::RequestIdMismatch,
        );

        let mut mismatched_revision = application.clone();
        mismatched_revision.from_authority_revision = Revision::new(2).unwrap();
        assert_authority_validation_kind(
            "stream subscription application authority revision",
            mismatched_revision.validate_against_snapshot(&snapshot),
            ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
        );

        let mut mismatched_count = application;
        mismatched_count.from_active_subscriber_count += 1;
        assert_authority_validation_kind(
            "stream subscription application active subscriber count",
            mismatched_count.validate_against_snapshot(&snapshot),
            ManifoldAuthorityValidationErrorKind::SubscriptionMismatch,
        );
    }

    {
        let snapshot = stream_authority_snapshot();
        let subscription_review = snapshot
            .review_stream_subscription(
                stream_subscription_request(),
                command_review_clock(),
                vec![id(
                    "evidence.stream_subscription_authority.request.synthetic_wave_ui",
                )],
            )
            .unwrap();
        let subscription_application = snapshot
            .apply_stream_subscription_authority_review(subscription_review)
            .unwrap();
        let active_snapshot = subscription_application.applied_snapshot.unwrap();
        let subscription = active_snapshot.active_stream_subscriptions[0].clone();
        let release_request = ManifoldStreamSubscriptionReleaseRequest {
            schema_id: stream_subscription_release_request_schema_id(),
            request_id: id("request.stream_subscription_release.synthetic_wave_ui"),
            subscription_id: subscription.subscription_id.clone(),
            subscriber_id: subscription.subscriber_id.clone(),
            expected_authority_revision: active_snapshot.authority_revision,
            expected_registry_revision: active_snapshot.stream_registry.registry_revision,
            stream_id: subscription.stream_id.clone(),
            release_reason: id("subscriber.closed"),
            requested_at_ms: 1_765_000_000_200,
        };
        let release_review = active_snapshot
            .review_stream_subscription_release(
                release_request,
                command_review_clock(),
                vec![id(
                    "evidence.stream_subscription_release_authority.request.synthetic_wave_ui",
                )],
            )
            .unwrap();
        let application = active_snapshot
            .apply_stream_subscription_release_authority_review(release_review)
            .unwrap();
        assert_eq!(
            application.validate_against_snapshot(&active_snapshot),
            Ok(())
        );

        let mut mismatched_review = application.clone();
        mismatched_review.review.review_id = id(
            "stream_subscription_release_review.request.stream_subscription_release.lineage_mismatch",
        );
        assert_authority_validation_kind(
            "stream subscription release application review id lineage",
            mismatched_review.validate_against_snapshot(&active_snapshot),
            ManifoldAuthorityValidationErrorKind::RequestIdMismatch,
        );

        let mut mismatched_revision = application.clone();
        mismatched_revision.from_authority_revision = Revision::INITIAL;
        assert_authority_validation_kind(
            "stream subscription release application authority revision",
            mismatched_revision.validate_against_snapshot(&active_snapshot),
            ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
        );

        let mut mismatched_count = application;
        mismatched_count.from_active_subscriber_count += 1;
        assert_authority_validation_kind(
            "stream subscription release application active subscriber count",
            mismatched_count.validate_against_snapshot(&active_snapshot),
            ManifoldAuthorityValidationErrorKind::SubscriptionMismatch,
        );
    }

    {
        let snapshot = stream_authority_snapshot();
        let subscription_review = snapshot
            .review_stream_subscription(
                stream_subscription_request(),
                command_review_clock(),
                vec![id(
                    "evidence.stream_subscription_authority.request.synthetic_wave_ui",
                )],
            )
            .unwrap();
        let subscription_application = snapshot
            .apply_stream_subscription_authority_review(subscription_review)
            .unwrap();
        let active_snapshot = subscription_application.applied_snapshot.unwrap();
        let subscription = active_snapshot.active_stream_subscriptions[0].clone();
        let renewal_request = ManifoldStreamSubscriptionRenewalRequest {
            schema_id: stream_subscription_renewal_request_schema_id(),
            request_id: id("request.stream_subscription_renewal.synthetic_wave_ui"),
            subscription_id: subscription.subscription_id.clone(),
            subscriber_id: subscription.subscriber_id.clone(),
            expected_authority_revision: active_snapshot.authority_revision,
            expected_registry_revision: active_snapshot.stream_registry.registry_revision,
            stream_id: subscription.stream_id.clone(),
            transport_id: subscription.transport_id.clone(),
            requested_ttl_ms: 60_000,
            renewal_reason: id("subscriber.needs_more_time"),
            requested_at_ms: 1_765_000_000_200,
        };
        let renewal_review = active_snapshot
            .review_stream_subscription_renewal(
                renewal_request,
                command_review_clock(),
                vec![id(
                    "evidence.stream_subscription_renewal_authority.request.synthetic_wave_ui",
                )],
            )
            .unwrap();
        let application = active_snapshot
            .apply_stream_subscription_renewal_authority_review(renewal_review)
            .unwrap();
        assert_eq!(
            application.validate_against_snapshot(&active_snapshot),
            Ok(())
        );

        let mut mismatched_review = application.clone();
        mismatched_review.review.review_id = id(
            "stream_subscription_renewal_review.request.stream_subscription_renewal.lineage_mismatch",
        );
        assert_authority_validation_kind(
            "stream subscription renewal application review id lineage",
            mismatched_review.validate_against_snapshot(&active_snapshot),
            ManifoldAuthorityValidationErrorKind::RequestIdMismatch,
        );

        let mut mismatched_revision = application.clone();
        mismatched_revision.from_authority_revision = Revision::INITIAL;
        assert_authority_validation_kind(
            "stream subscription renewal application authority revision",
            mismatched_revision.validate_against_snapshot(&active_snapshot),
            ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
        );

        let mut mismatched_count = application;
        mismatched_count.from_active_subscriber_count += 1;
        assert_authority_validation_kind(
            "stream subscription renewal application active subscriber count",
            mismatched_count.validate_against_snapshot(&active_snapshot),
            ManifoldAuthorityValidationErrorKind::SubscriptionMismatch,
        );
    }

    {
        let snapshot = stream_authority_snapshot();
        let subscription_review = snapshot
            .review_stream_subscription(
                stream_subscription_request(),
                command_review_clock(),
                vec![id(
                    "evidence.stream_subscription_authority.request.synthetic_wave_ui",
                )],
            )
            .unwrap();
        let subscription_application = snapshot
            .apply_stream_subscription_authority_review(subscription_review)
            .unwrap();
        let active_snapshot = subscription_application.applied_snapshot.unwrap();
        let mut expired_clock = command_review_clock();
        expired_clock.sequence = 44;
        expired_clock.monotonic_elapsed_ns = 3_334_567_990;
        expired_clock.wall_unix_ms = 1_765_000_030_200;
        let request = ManifoldAuthorityExpirySweepRequest {
            schema_id: authority_expiry_sweep_request_schema_id(),
            request_id: id("request.expiry_sweep.synthetic"),
            requester_id: id("authority.synthetic"),
            expected_authority_revision: active_snapshot.authority_revision,
            expected_registry_revision: active_snapshot.stream_registry.registry_revision,
            sweep_reason: id("maintenance.ttl_expired"),
            requested_at_ms: 1_765_000_030_200,
        };
        let review = active_snapshot
            .review_authority_expiry_sweep(
                request,
                expired_clock,
                vec![id("evidence.expiry_sweep.synthetic")],
            )
            .unwrap();
        let application = active_snapshot
            .apply_authority_expiry_sweep_review(review)
            .unwrap();
        assert_eq!(
            application.validate_against_snapshot(&active_snapshot),
            Ok(())
        );

        let mut mismatched_review = application.clone();
        mismatched_review.review.review_id =
            id("expiry_sweep_review.request.expiry_sweep.lineage_mismatch");
        assert_authority_validation_kind(
            "expiry sweep application review id lineage",
            mismatched_review.validate_against_snapshot(&active_snapshot),
            ManifoldAuthorityValidationErrorKind::RequestIdMismatch,
        );

        let mut mismatched_revision = application.clone();
        mismatched_revision.from_authority_revision = Revision::INITIAL;
        assert_authority_validation_kind(
            "expiry sweep application authority revision",
            mismatched_revision.validate_against_snapshot(&active_snapshot),
            ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
        );

        let mut mismatched_count = application;
        mismatched_count.from_active_lease_count += 1;
        assert_authority_validation_kind(
            "expiry sweep application active lease count",
            mismatched_count.validate_against_snapshot(&active_snapshot),
            ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
        );
    }

    {
        let snapshot = stream_authority_snapshot();
        let review = snapshot
            .review_module_runtime_state_change(
                module_runtime_state_change_request(),
                command_review_clock(),
                vec![id(
                    "evidence.module_runtime_state_authority.request.stop.synthetic_wave_provider",
                )],
            )
            .unwrap();
        let application = snapshot
            .apply_module_runtime_state_authority_review(review)
            .unwrap();
        assert_eq!(application.validate_against_snapshot(&snapshot), Ok(()));

        let mut mismatched_review = application.clone();
        mismatched_review.review.review_id =
            id("module_runtime_state_review.request.module_runtime.lineage_mismatch");
        assert_authority_validation_kind(
            "module runtime application review id lineage",
            mismatched_review.validate_against_snapshot(&snapshot),
            ManifoldAuthorityValidationErrorKind::RequestIdMismatch,
        );

        let mut mismatched_revision = application.clone();
        mismatched_revision.from_authority_revision = Revision::new(2).unwrap();
        assert_authority_validation_kind(
            "module runtime application authority revision",
            mismatched_revision.validate_against_snapshot(&snapshot),
            ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
        );

        let mut mismatched_runtime_revision = application;
        mismatched_runtime_revision.from_runtime_revision = Some(Revision::new(2).unwrap());
        assert_authority_validation_kind(
            "module runtime application runtime revision",
            mismatched_runtime_revision.validate_against_snapshot(&snapshot),
            ManifoldAuthorityValidationErrorKind::RuntimeRevisionMismatch,
        );
    }

    {
        let snapshot = authority_snapshot();
        let review = snapshot
            .review_host_manifest_change(
                host_manifest_change_request(),
                command_review_clock(),
                vec![id(
                    "evidence.host_manifest_authority.request.synthetic_permissions",
                )],
            )
            .unwrap();
        let application = snapshot
            .apply_host_manifest_authority_review(review)
            .unwrap();
        assert_eq!(application.validate_against_snapshot(&snapshot), Ok(()));

        let mut mismatched_review = application.clone();
        mismatched_review.review.review_id =
            id("host_manifest_review.request.host_manifest.lineage_mismatch");
        assert_authority_validation_kind(
            "host manifest application review id lineage",
            mismatched_review.validate_against_snapshot(&snapshot),
            ManifoldAuthorityValidationErrorKind::RequestIdMismatch,
        );

        let mut mismatched_revision = application.clone();
        mismatched_revision.from_authority_revision = Revision::new(2).unwrap();
        assert_authority_validation_kind(
            "host manifest application authority revision",
            mismatched_revision.validate_against_snapshot(&snapshot),
            ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
        );

        let mut mismatched_host = application;
        mismatched_host.host_id = id("host.other");
        assert_authority_validation_kind(
            "host manifest application host id",
            mismatched_host.validate_against_snapshot(&snapshot),
            ManifoldAuthorityValidationErrorKind::HostIdMismatch,
        );
    }

    {
        let snapshot = authority_snapshot();
        let review = snapshot
            .review_clock_snapshot_change(
                clock_snapshot_change_request(),
                command_review_clock(),
                vec![id(
                    "evidence.clock_snapshot_authority.request.synthetic_tick",
                )],
            )
            .unwrap();
        let application = snapshot
            .apply_clock_snapshot_authority_review(review)
            .unwrap();
        assert_eq!(application.validate_against_snapshot(&snapshot), Ok(()));

        let mut mismatched_review = application.clone();
        mismatched_review.review.review_id =
            id("clock_snapshot_review.request.clock.lineage_mismatch");
        assert_authority_validation_kind(
            "clock application review id lineage",
            mismatched_review.validate_against_snapshot(&snapshot),
            ManifoldAuthorityValidationErrorKind::RequestIdMismatch,
        );

        let mut mismatched_revision = application.clone();
        mismatched_revision.from_authority_revision = Revision::new(2).unwrap();
        assert_authority_validation_kind(
            "clock application authority revision",
            mismatched_revision.validate_against_snapshot(&snapshot),
            ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
        );

        let mut mismatched_clock_sequence = application;
        mismatched_clock_sequence.from_clock_sequence += 1;
        assert_authority_validation_kind(
            "clock application source sequence",
            mismatched_clock_sequence.validate_against_snapshot(&snapshot),
            ManifoldAuthorityValidationErrorKind::ClockSnapshotMismatch,
        );
    }
}

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
