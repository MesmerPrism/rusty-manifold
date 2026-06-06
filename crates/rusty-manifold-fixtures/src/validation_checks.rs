use super::*;

pub(super) fn validate_repo(repo_root: &Path) -> Result<ValidationReport, CliError> {
    let fixtures = FixtureSet::load(repo_root)?;
    let mut checks = Vec::new();
    let module_ids = fixtures
        .module_manifests
        .iter()
        .map(|module| module.module_id.clone())
        .collect::<Vec<_>>();
    let endpoint_ids = fixtures.endpoint_ids();

    push_valid_checks(&mut checks, &fixtures, &module_ids, &endpoint_ids);
    push_damaged_checks(
        repo_root,
        &mut checks,
        &fixtures,
        &module_ids,
        &endpoint_ids,
    )?;

    let failed = checks.iter().any(|check| check.status == "fail");
    Ok(ValidationReport {
        schema_id: "rusty.manifold.validation.fixture_report.v1".to_owned(),
        status: if failed { "fail" } else { "pass" }.to_owned(),
        checks,
    })
}

fn push_valid_checks(
    checks: &mut Vec<ValidationCheckReport>,
    fixtures: &FixtureSet,
    module_ids: &[DottedId],
    endpoint_ids: &[DottedId],
) {
    checks.push(pass(
        "validation.check.valid_fixture_deserialize",
        "valid fixtures deserialize into typed contract models",
    ));

    push_result(
        checks,
        "validation.check.host_endpoint_security",
        fixtures.valid_host.validate_endpoint_security(),
        "valid host endpoint visibility and security pairing accepted",
    );

    for host in &fixtures.platform_hosts {
        let check_id = format!("validation.check.{}_endpoint_security", host.host_id);
        push_result(
            checks,
            &check_id,
            host.validate_endpoint_security(),
            "platform host endpoint visibility and security pairing accepted",
        );
    }

    push_result(
        checks,
        "validation.check.graph_links",
        fixtures.valid_graph.validate_links(module_ids),
        "graph nodes and edges reference known modules and graph nodes",
    );

    push_result(
        checks,
        "validation.check.stream_registry_links",
        fixtures.valid_registry.validate_source_modules(module_ids),
        "stream registry source modules are known",
    );

    push_result(
        checks,
        "validation.check.stream_registry_transport_endpoints",
        fixtures
            .valid_registry
            .validate_transport_endpoints(endpoint_ids),
        "endpoint-bound stream transport offers reference advertised host endpoints",
    );

    push_result(
        checks,
        "validation.check.command_accept",
        fixtures.valid_envelope.validate_request(
            &fixtures.command_descriptor,
            Revision::INITIAL,
            Some(&fixtures.control_lease),
        ),
        "command envelope matches descriptor, revision, holder, and lease",
    );

    push_result(
        checks,
        "validation.check.authority_snapshot_links",
        fixtures.authority_snapshot.validate_authority_links(),
        "authority snapshot aligns host, clock, stream registry, module runtime, commands, and leases",
    );

    push_result(
        checks,
        "validation.check.command_authority_audit_event",
        fixtures
            .command_authority_audit_event
            .validate_against_snapshot(&fixtures.authority_snapshot),
        "command authority audit event matches the accepted envelope, ack, lease, clock, and snapshot",
    );

    push_result(
        checks,
        "validation.check.command_authority_review_accepted",
        command_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.valid_envelope,
            &fixtures.command_review_clock,
            &fixtures.accepted_command_review,
        ),
        "command authority evaluator deterministically accepts a valid leased command",
    );

    push_result(
        checks,
        "validation.check.command_authority_review_stale_revision",
        command_review_matches_fixture(
            &fixtures.authority_snapshot_v2,
            &fixtures.damaged_stale_command,
            &fixtures.command_review_clock,
            &fixtures.stale_revision_command_review,
        ),
        "command authority evaluator deterministically rejects stale command revisions",
    );

    push_result(
        checks,
        "validation.check.command_authority_review_expired_lease",
        command_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.valid_envelope,
            &fixtures.expired_command_review_clock,
            &fixtures.expired_lease_command_review,
        ),
        "command authority evaluator deterministically rejects leases expired at the review clock",
    );

    push_result(
        checks,
        "validation.check.command_authority_review_missing_lease",
        command_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.damaged_missing_lease_command,
            &fixtures.command_review_clock,
            &fixtures.missing_lease_command_review,
        ),
        "command authority evaluator deterministically rejects commands missing a required lease",
    );

    push_result(
        checks,
        "validation.check.command_authority_review_unknown_command",
        command_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.unknown_command_review_envelope,
            &fixtures.command_review_clock,
            &fixtures.unknown_command_review,
        ),
        "command authority evaluator deterministically rejects commands absent from the authority snapshot",
    );

    push_result(
        checks,
        "validation.check.command_authority_review_unknown_lease",
        command_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.unknown_lease_review_envelope,
            &fixtures.command_review_clock,
            &fixtures.unknown_lease_command_review,
        ),
        "command authority evaluator deterministically rejects commands carrying an unknown lease",
    );

    push_result(
        checks,
        "validation.check.command_authority_review_capability_mismatch",
        command_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.capability_mismatch_review_envelope,
            &fixtures.command_review_clock,
            &fixtures.capability_mismatch_command_review,
        ),
        "command authority evaluator deterministically rejects capability mismatches",
    );

    push_result(
        checks,
        "validation.check.command_dispatch_rejection_fixture",
        if fixtures.command_dispatch_rejection.rejection_code.as_str() == "review_rejected"
            && fixtures.command_dispatch_rejection.retryable
            && fixtures
                .command_dispatch_rejection
                .current_authority_revision
                == Revision::INITIAL
        {
            Ok(())
        } else {
            Err("standalone command dispatch rejection fixture is not the expected review-rejected rejection".to_owned())
        },
        "standalone command dispatch rejection fixture is a review-rejected rejection",
    );

    push_result(
        checks,
        "validation.check.command_dispatch_receipt_ready",
        command_dispatch_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.accepted_command_review,
            &fixtures.accepted_command_dispatch,
        ),
        "command dispatch receipt deterministically prepares an accepted review without executing it",
    );

    push_result(
        checks,
        "validation.check.command_dispatch_receipt_rejected",
        command_dispatch_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.missing_lease_command_review,
            &fixtures.rejected_command_dispatch,
        ),
        "command dispatch receipt deterministically rejects rejected command reviews",
    );

    push_result(
        checks,
        "validation.check.command_dispatch_rejects_snapshot_revision_mismatch",
        command_dispatch_rejects_snapshot_revision_mismatch(
            &fixtures.authority_snapshot_v2,
            &fixtures.accepted_command_review,
        ),
        "command dispatch preparation rejects command reviews from a different authority snapshot revision",
    );

    push_result(
        checks,
        "validation.check.command_dispatch_receipt_rejects_request_lineage_mismatch",
        command_dispatch_receipt_rejects_request_lineage_mismatch(
            &fixtures.authority_snapshot,
            &fixtures.accepted_command_dispatch,
        ),
        "command dispatch receipt validation rejects top-level request ids that diverge from the embedded review",
    );

    push_result(
        checks,
        "validation.check.lease_authority_audit_event",
        fixtures
            .lease_authority_audit_event
            .validate_against_snapshot(&fixtures.authority_snapshot),
        "lease authority audit event matches the accepted request, lease, clock, and snapshot",
    );

    push_result(
        checks,
        "validation.check.lease_authority_rejection_fixture",
        if fixtures.lease_rejection.rejection_code.as_str() == "stale_revision"
            && fixtures.lease_rejection.retryable
            && fixtures.lease_rejection.current_revision == Revision::INITIAL
            && fixtures.lease_rejection.conflicting_lease_id.is_none()
        {
            Ok(())
        } else {
            Err(
                "standalone lease rejection fixture is not the expected stale-revision rejection"
                    .to_owned(),
            )
        },
        "standalone lease rejection fixture is a non-conflict stale-revision rejection",
    );

    push_result(
        checks,
        "validation.check.lease_authority_review_accepted",
        lease_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.lease_request,
            &fixtures.command_review_clock,
            &fixtures.accepted_lease_review,
        ),
        "lease authority evaluator deterministically accepts an available graph lease",
    );

    push_result(
        checks,
        "validation.check.lease_authority_review_stale_revision",
        lease_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.stale_lease_request,
            &fixtures.command_review_clock,
            &fixtures.stale_revision_lease_review,
        ),
        "lease authority evaluator deterministically rejects stale lease revisions",
    );

    push_result(
        checks,
        "validation.check.lease_authority_review_zero_ttl",
        lease_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.zero_ttl_lease_request,
            &fixtures.command_review_clock,
            &fixtures.zero_ttl_lease_review,
        ),
        "lease authority evaluator deterministically rejects zero-duration leases",
    );

    push_result(
        checks,
        "validation.check.lease_authority_review_missing_capability",
        lease_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.missing_capability_lease_request,
            &fixtures.command_review_clock,
            &fixtures.missing_capability_lease_review,
        ),
        "lease authority evaluator deterministically rejects unadvertised capabilities",
    );

    push_result(
        checks,
        "validation.check.lease_authority_review_busy_scope",
        lease_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.busy_scope_lease_request,
            &fixtures.command_review_clock,
            &fixtures.busy_scope_lease_review,
        ),
        "lease authority evaluator deterministically rejects active-lease scope conflicts",
    );

    push_result(
        checks,
        "validation.check.lease_authority_application_rejection_fixture",
        if fixtures.lease_application_rejection.rejection_code.as_str() == "review_rejected"
            && fixtures
                .lease_application_rejection
                .current_authority_revision
                == Revision::INITIAL
        {
            Ok(())
        } else {
            Err("standalone lease application rejection fixture is not the expected review-rejected rejection"
                .to_owned())
        },
        "standalone lease application rejection fixture is a review-rejected rejection",
    );

    push_result(
        checks,
        "validation.check.lease_authority_application_accepted",
        lease_application_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.accepted_lease_review,
            &fixtures.accepted_lease_application,
        ),
        "lease authority application deterministically advances accepted lease state",
    );

    push_result(
        checks,
        "validation.check.lease_authority_application_rejected",
        lease_application_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.stale_revision_lease_review,
            &fixtures.rejected_lease_application,
        ),
        "lease authority application deterministically rejects rejected lease reviews",
    );

    let lease_release_authority_revision = Revision::new(2).expect("revision literal is valid");
    push_result(
        checks,
        "validation.check.lease_release_authority_snapshot",
        fixtures
            .lease_active_authority_snapshot
            .validate_authority_links(),
        "lease release authority snapshot has the accepted active lease from lease application",
    );

    push_result(
        checks,
        "validation.check.lease_release_request_fixture",
        if fixtures
            .lease_active_authority_snapshot
            .active_leases
            .iter()
            .any(|lease| {
                lease.lease_id == fixtures.lease_release_request.lease_id
                    && lease.holder_id == fixtures.lease_release_request.holder_id
                    && lease.scope == fixtures.lease_release_request.scope
            })
            && fixtures.lease_release_request.expected_authority_revision
                == fixtures.lease_active_authority_snapshot.authority_revision
        {
            Ok(())
        } else {
            Err("lease release request does not target the active lease snapshot".to_owned())
        },
        "lease release request targets an accepted active lease",
    );

    push_result(
        checks,
        "validation.check.lease_release_rejection_fixture",
        if fixtures.lease_release_rejection.rejection_code.as_str() == "stale_revision"
            && fixtures.lease_release_rejection.retryable
            && fixtures.lease_release_rejection.current_revision == lease_release_authority_revision
            && fixtures.lease_release_rejection.active_lease_count
                == fixtures.lease_active_authority_snapshot.active_leases.len()
        {
            Ok(())
        } else {
            Err("standalone lease release rejection fixture is not the expected stale-revision rejection".to_owned())
        },
        "standalone lease release rejection fixture is a stale-revision rejection",
    );

    push_result(
        checks,
        "validation.check.lease_release_authority_audit_event",
        fixtures
            .lease_release_authority_audit_event
            .validate_against_snapshot(&fixtures.lease_active_authority_snapshot),
        "lease release authority audit event matches the accepted request, clock, and active snapshot",
    );

    push_result(
        checks,
        "validation.check.lease_release_authority_review_accepted",
        lease_release_review_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.lease_release_request,
            &fixtures.command_review_clock,
            &fixtures.accepted_lease_release_review,
        ),
        "lease release authority evaluator deterministically accepts active lease release",
    );

    push_result(
        checks,
        "validation.check.lease_release_authority_review_expired_lease",
        lease_release_review_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.lease_release_request,
            &fixtures.expired_command_review_clock,
            &fixtures.expired_lease_release_review,
        ),
        "lease release authority evaluator deterministically rejects leases expired at the review clock",
    );

    push_result(
        checks,
        "validation.check.lease_release_authority_review_stale_revision",
        lease_release_review_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.stale_lease_release_request,
            &fixtures.command_review_clock,
            &fixtures.stale_lease_release_review,
        ),
        "lease release authority evaluator deterministically rejects stale authority revisions",
    );

    push_result(
        checks,
        "validation.check.lease_release_authority_review_unknown_lease",
        lease_release_review_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.unknown_lease_release_request,
            &fixtures.command_review_clock,
            &fixtures.unknown_lease_release_review,
        ),
        "lease release authority evaluator deterministically rejects unknown leases",
    );

    push_result(
        checks,
        "validation.check.lease_release_authority_review_holder_mismatch",
        lease_release_review_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.holder_mismatch_lease_release_request,
            &fixtures.command_review_clock,
            &fixtures.holder_mismatch_lease_release_review,
        ),
        "lease release authority evaluator deterministically rejects holder mismatches",
    );

    push_result(
        checks,
        "validation.check.lease_release_authority_review_scope_mismatch",
        lease_release_review_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.scope_mismatch_lease_release_request,
            &fixtures.command_review_clock,
            &fixtures.scope_mismatch_lease_release_review,
        ),
        "lease release authority evaluator deterministically rejects scope mismatches",
    );

    push_result(
        checks,
        "validation.check.lease_release_authority_application_rejection_fixture",
        if fixtures
            .lease_release_application_rejection
            .rejection_code
            .as_str()
            == "review_rejected"
            && fixtures
                .lease_release_application_rejection
                .current_authority_revision
                == lease_release_authority_revision
        {
            Ok(())
        } else {
            Err("standalone lease release application rejection fixture is not the expected review-rejected rejection"
                .to_owned())
        },
        "standalone lease release application rejection fixture is a review-rejected rejection",
    );

    push_result(
        checks,
        "validation.check.lease_release_authority_application_accepted",
        lease_release_application_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.accepted_lease_release_review,
            &fixtures.accepted_lease_release_application,
        ),
        "lease release authority application deterministically removes accepted active lease state",
    );

    push_result(
        checks,
        "validation.check.lease_release_authority_application_rejected",
        lease_release_application_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.stale_lease_release_review,
            &fixtures.rejected_lease_release_application,
        ),
        "lease release authority application deterministically rejects rejected release reviews",
    );

    let lease_renewal_expected_expires_at_ms =
        u64::try_from(fixtures.command_review_clock.wall_unix_ms)
            .unwrap_or_default()
            .saturating_add(fixtures.lease_renewal_request.requested_ttl_ms);
    push_result(
        checks,
        "validation.check.lease_renewal_request_fixture",
        match fixtures
            .lease_active_authority_snapshot
            .active_leases
            .iter()
            .find(|lease| {
                lease.lease_id == fixtures.lease_renewal_request.lease_id
                    && lease.holder_id == fixtures.lease_renewal_request.holder_id
                    && lease.scope == fixtures.lease_renewal_request.scope
            }) {
            Some(lease)
                if fixtures.lease_renewal_request.expected_authority_revision
                    == fixtures.lease_active_authority_snapshot.authority_revision
                    && fixtures.lease_renewal_request.requested_ttl_ms > 0
                    && lease_renewal_expected_expires_at_ms > lease.expires_at_ms =>
            {
                Ok(())
            }
            _ => Err("lease renewal request does not extend the active lease snapshot".to_owned()),
        },
        "lease renewal request targets and extends an accepted active lease",
    );

    push_result(
        checks,
        "validation.check.lease_renewal_rejection_fixture",
        if fixtures.lease_renewal_rejection.rejection_code.as_str() == "stale_revision"
            && fixtures.lease_renewal_rejection.retryable
            && fixtures.lease_renewal_rejection.current_revision == lease_release_authority_revision
            && fixtures.lease_renewal_rejection.active_lease_count
                == fixtures.lease_active_authority_snapshot.active_leases.len()
            && fixtures
                .lease_renewal_rejection
                .current_expires_at_ms
                .is_none()
        {
            Ok(())
        } else {
            Err("standalone lease renewal rejection fixture is not the expected stale-revision rejection".to_owned())
        },
        "standalone lease renewal rejection fixture is a stale-revision rejection",
    );

    push_result(
        checks,
        "validation.check.lease_renewal_authority_audit_event",
        fixtures
            .lease_renewal_authority_audit_event
            .validate_against_snapshot(&fixtures.lease_active_authority_snapshot),
        "lease renewal authority audit event matches the accepted request, clock, and active snapshot",
    );

    push_result(
        checks,
        "validation.check.lease_renewal_authority_review_accepted",
        lease_renewal_review_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.lease_renewal_request,
            &fixtures.command_review_clock,
            &fixtures.accepted_lease_renewal_review,
        ),
        "lease renewal authority evaluator deterministically accepts active lease renewal",
    );

    push_result(
        checks,
        "validation.check.lease_renewal_authority_review_stale_revision",
        lease_renewal_review_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.stale_lease_renewal_request,
            &fixtures.command_review_clock,
            &fixtures.stale_lease_renewal_review,
        ),
        "lease renewal authority evaluator deterministically rejects stale authority revisions",
    );

    push_result(
        checks,
        "validation.check.lease_renewal_authority_review_unknown_lease",
        lease_renewal_review_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.unknown_lease_renewal_request,
            &fixtures.command_review_clock,
            &fixtures.unknown_lease_renewal_review,
        ),
        "lease renewal authority evaluator deterministically rejects unknown leases",
    );

    push_result(
        checks,
        "validation.check.lease_renewal_authority_review_holder_mismatch",
        lease_renewal_review_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.holder_mismatch_lease_renewal_request,
            &fixtures.command_review_clock,
            &fixtures.holder_mismatch_lease_renewal_review,
        ),
        "lease renewal authority evaluator deterministically rejects holder mismatches",
    );

    push_result(
        checks,
        "validation.check.lease_renewal_authority_review_scope_mismatch",
        lease_renewal_review_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.scope_mismatch_lease_renewal_request,
            &fixtures.command_review_clock,
            &fixtures.scope_mismatch_lease_renewal_review,
        ),
        "lease renewal authority evaluator deterministically rejects scope mismatches",
    );

    push_result(
        checks,
        "validation.check.lease_renewal_authority_review_zero_ttl",
        lease_renewal_review_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.zero_ttl_lease_renewal_request,
            &fixtures.command_review_clock,
            &fixtures.zero_ttl_lease_renewal_review,
        ),
        "lease renewal authority evaluator deterministically rejects zero-duration renewals",
    );

    push_result(
        checks,
        "validation.check.lease_renewal_authority_review_non_extending",
        lease_renewal_review_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.non_extending_lease_renewal_request,
            &fixtures.command_review_clock,
            &fixtures.non_extending_lease_renewal_review,
        ),
        "lease renewal authority evaluator deterministically rejects non-extending renewals",
    );

    push_result(
        checks,
        "validation.check.lease_renewal_authority_review_expired_lease",
        lease_renewal_review_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.lease_renewal_request,
            &fixtures.expired_command_review_clock,
            &fixtures.expired_lease_renewal_review,
        ),
        "lease renewal authority evaluator deterministically rejects leases expired at the review clock",
    );

    push_result(
        checks,
        "validation.check.lease_renewal_authority_application_rejection_fixture",
        if fixtures
            .lease_renewal_application_rejection
            .rejection_code
            .as_str()
            == "review_rejected"
            && fixtures
                .lease_renewal_application_rejection
                .current_authority_revision
                == lease_release_authority_revision
        {
            Ok(())
        } else {
            Err("standalone lease renewal application rejection fixture is not the expected review-rejected rejection"
                .to_owned())
        },
        "standalone lease renewal application rejection fixture is a review-rejected rejection",
    );

    push_result(
        checks,
        "validation.check.lease_renewal_authority_application_accepted",
        lease_renewal_application_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.accepted_lease_renewal_review,
            &fixtures.accepted_lease_renewal_application,
        ),
        "lease renewal authority application deterministically replaces accepted active lease state",
    );

    push_result(
        checks,
        "validation.check.lease_renewal_authority_application_rejected",
        lease_renewal_application_matches_fixture(
            &fixtures.lease_active_authority_snapshot,
            &fixtures.stale_lease_renewal_review,
            &fixtures.rejected_lease_renewal_application,
        ),
        "lease renewal authority application deterministically rejects rejected renewal reviews",
    );

    push_result(
        checks,
        "validation.check.stream_registry_diff_fixture",
        if fixtures.stream_registry_change_request.diff == fixtures.stream_registry_diff {
            Ok(())
        } else {
            Err(
                "stream registry change request does not embed the standalone diff fixture"
                    .to_owned(),
            )
        },
        "stream registry change request embeds the standalone diff fixture",
    );

    push_result(
        checks,
        "validation.check.stream_registry_lease_fixture",
        if fixtures.stream_registry_lease.scope.as_str() == "manifold.stream_registry"
            && fixtures.stream_registry_lease.holder_id
                == fixtures.stream_registry_change_request.holder_id
            && fixtures.stream_registry_change_request.lease_id.as_ref()
                == Some(&fixtures.stream_registry_lease.lease_id)
        {
            Ok(())
        } else {
            Err(
                "stream registry lease fixture does not authorize the registry change request"
                    .to_owned(),
            )
        },
        "stream registry lease fixture authorizes the accepted registry request",
    );

    push_result(
        checks,
        "validation.check.stream_registry_authority_audit_event",
        fixtures
            .stream_registry_authority_audit_event
            .validate_against_snapshot(&fixtures.authority_snapshot),
        "stream registry authority audit event matches the accepted request, lease, clock, and snapshot",
    );

    push_result(
        checks,
        "validation.check.stream_registry_rejection_fixture",
        if fixtures.stream_registry_rejection.rejection_code.as_str() == "stale_revision"
            && fixtures.stream_registry_rejection.retryable
            && fixtures
                .stream_registry_rejection
                .current_authority_revision
                == Revision::INITIAL
            && fixtures.stream_registry_rejection.current_registry_revision == Revision::INITIAL
        {
            Ok(())
        } else {
            Err("standalone stream registry rejection fixture is not the expected stale-revision rejection"
                .to_owned())
        },
        "standalone stream registry rejection fixture is a stale-revision rejection",
    );

    push_result(
        checks,
        "validation.check.stream_registry_authority_review_accepted",
        stream_registry_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.stream_registry_change_request,
            &fixtures.command_review_clock,
            &fixtures.accepted_stream_registry_review,
        ),
        "stream registry authority evaluator deterministically accepts a lease-scoped metadata change",
    );

    push_result(
        checks,
        "validation.check.stream_registry_authority_review_expired_lease",
        stream_registry_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.stream_registry_change_request,
            &fixtures.expired_command_review_clock,
            &fixtures.expired_lease_stream_registry_review,
        ),
        "stream registry authority evaluator deterministically rejects leases expired at the review clock",
    );

    push_result(
        checks,
        "validation.check.stream_registry_authority_review_stale_revision",
        stream_registry_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.stale_stream_registry_request,
            &fixtures.command_review_clock,
            &fixtures.stale_stream_registry_review,
        ),
        "stream registry authority evaluator deterministically rejects stale authority revisions",
    );

    push_result(
        checks,
        "validation.check.stream_registry_authority_review_missing_lease",
        stream_registry_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.missing_lease_stream_registry_request,
            &fixtures.command_review_clock,
            &fixtures.missing_lease_stream_registry_review,
        ),
        "stream registry authority evaluator deterministically rejects missing registry leases",
    );

    push_result(
        checks,
        "validation.check.stream_registry_authority_review_active_stream_conflict",
        stream_registry_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.active_stream_registry_request,
            &fixtures.command_review_clock,
            &fixtures.active_stream_registry_review,
        ),
        "stream registry authority evaluator deterministically rejects active-stream removals",
    );

    push_result(
        checks,
        "validation.check.stream_registry_authority_review_active_subscription_transport_conflict",
        stream_registry_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.remove_active_transport_stream_registry_request,
            &fixtures.command_review_clock,
            &fixtures.remove_active_transport_stream_registry_review,
        ),
        "stream registry authority evaluator deterministically rejects removing transport offers used by active subscriptions",
    );

    push_result(
        checks,
        "validation.check.stream_registry_authority_review_active_subscription_ui_policy_conflict",
        stream_registry_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.disable_active_ui_stream_registry_request,
            &fixtures.command_review_clock,
            &fixtures.disable_active_ui_stream_registry_review,
        ),
        "stream registry authority evaluator deterministically rejects disabling UI subscriptions while UI subscriptions are active",
    );

    push_result(
        checks,
        "validation.check.stream_registry_authority_review_active_subscription_limit_conflict",
        stream_registry_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.lower_active_subscriber_limit_stream_registry_request,
            &fixtures.command_review_clock,
            &fixtures.lower_active_subscriber_limit_stream_registry_review,
        ),
        "stream registry authority evaluator deterministically rejects subscriber limits below active subscriptions",
    );

    push_result(
        checks,
        "validation.check.stream_registry_authority_review_unknown_module",
        stream_registry_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.unknown_module_stream_registry_request,
            &fixtures.command_review_clock,
            &fixtures.unknown_module_stream_registry_review,
        ),
        "stream registry authority evaluator deterministically rejects unknown source modules",
    );

    push_result(
        checks,
        "validation.check.stream_registry_authority_review_unknown_endpoint",
        stream_registry_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.unknown_endpoint_stream_registry_request,
            &fixtures.command_review_clock,
            &fixtures.unknown_endpoint_stream_registry_review,
        ),
        "stream registry authority evaluator deterministically rejects unknown transport endpoints",
    );

    push_result(
        checks,
        "validation.check.stream_registry_authority_application_rejection_fixture",
        if fixtures
            .stream_registry_application_rejection
            .rejection_code
            .as_str()
            == "review_rejected"
            && fixtures
                .stream_registry_application_rejection
                .current_authority_revision
                == Revision::INITIAL
        {
            Ok(())
        } else {
            Err("standalone stream registry application rejection fixture is not the expected review-rejected rejection"
                .to_owned())
        },
        "standalone stream registry application rejection fixture is a review-rejected rejection",
    );

    push_result(
        checks,
        "validation.check.stream_registry_authority_application_accepted",
        stream_registry_application_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.accepted_stream_registry_review,
            &fixtures.accepted_stream_registry_application,
        ),
        "stream registry authority application deterministically advances accepted registry state",
    );

    push_result(
        checks,
        "validation.check.stream_registry_authority_application_rejected",
        stream_registry_application_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.stale_stream_registry_review,
            &fixtures.rejected_stream_registry_application,
        ),
        "stream registry authority application deterministically rejects rejected registry reviews",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_authority_snapshot",
        fixtures
            .stream_subscription_authority_snapshot
            .validate_authority_links(),
        "stream subscription authority snapshot carries subscribe capability and valid stream links",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_fixture",
        if fixtures
            .accepted_stream_subscription_review
            .accepted
            .as_ref()
            == Some(&fixtures.stream_subscription)
        {
            Ok(())
        } else {
            Err(
                "standalone stream subscription fixture does not match the accepted review"
                    .to_owned(),
            )
        },
        "standalone stream subscription fixture matches the accepted review state",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_rejection_fixture",
        if fixtures
            .stream_subscription_rejection
            .rejection_code
            .as_str()
            == "stale_revision"
            && fixtures.stream_subscription_rejection.retryable
            && fixtures
                .stream_subscription_rejection
                .current_authority_revision
                == Revision::INITIAL
            && fixtures
                .stream_subscription_rejection
                .current_registry_revision
                == Revision::INITIAL
        {
            Ok(())
        } else {
            Err("standalone stream subscription rejection fixture is not the expected stale-revision rejection"
                .to_owned())
        },
        "standalone stream subscription rejection fixture is a stale-revision rejection",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_authority_audit_event",
        fixtures
            .stream_subscription_authority_audit_event
            .validate_against_snapshot(&fixtures.stream_subscription_authority_snapshot),
        "stream subscription authority audit event matches the accepted request, clock, and snapshot",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_authority_review_accepted",
        stream_subscription_review_matches_fixture(
            &fixtures.stream_subscription_authority_snapshot,
            &fixtures.stream_subscription_request,
            &fixtures.command_review_clock,
            &fixtures.accepted_stream_subscription_review,
        ),
        "stream subscription authority evaluator deterministically accepts a UI subscriber for an advertised transport",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_authority_review_zero_ttl",
        stream_subscription_review_matches_fixture(
            &fixtures.stream_subscription_authority_snapshot,
            &fixtures.zero_ttl_stream_subscription_request,
            &fixtures.command_review_clock,
            &fixtures.zero_ttl_stream_subscription_review,
        ),
        "stream subscription authority evaluator deterministically rejects zero-duration subscriptions",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_authority_review_missing_capability",
        stream_subscription_review_matches_fixture(
            &fixtures.stream_subscription_authority_snapshot,
            &fixtures.missing_capability_stream_subscription_request,
            &fixtures.command_review_clock,
            &fixtures.missing_capability_stream_subscription_review,
        ),
        "stream subscription authority evaluator deterministically rejects unadvertised subscribe capabilities",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_authority_review_stale_revision",
        stream_subscription_review_matches_fixture(
            &fixtures.stream_subscription_authority_snapshot,
            &fixtures.stale_stream_subscription_request,
            &fixtures.command_review_clock,
            &fixtures.stale_stream_subscription_review,
        ),
        "stream subscription authority evaluator deterministically rejects stale authority revisions",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_authority_review_stale_registry",
        stream_subscription_review_matches_fixture(
            &fixtures.stream_subscription_authority_snapshot,
            &fixtures.stale_registry_stream_subscription_request,
            &fixtures.command_review_clock,
            &fixtures.stale_registry_stream_subscription_review,
        ),
        "stream subscription authority evaluator deterministically rejects stale registry revisions",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_authority_review_unknown_stream",
        stream_subscription_review_matches_fixture(
            &fixtures.stream_subscription_authority_snapshot,
            &fixtures.unknown_stream_subscription_request,
            &fixtures.command_review_clock,
            &fixtures.unknown_stream_subscription_review,
        ),
        "stream subscription authority evaluator deterministically rejects unknown streams",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_authority_review_unknown_transport",
        stream_subscription_review_matches_fixture(
            &fixtures.stream_subscription_authority_snapshot,
            &fixtures.unknown_transport_stream_subscription_request,
            &fixtures.command_review_clock,
            &fixtures.unknown_transport_stream_subscription_review,
        ),
        "stream subscription authority evaluator deterministically rejects unknown transport offers",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_authority_review_subscriber_limit",
        stream_subscription_review_matches_fixture(
            &fixtures.subscriber_limit_stream_subscription_authority_snapshot,
            &fixtures.subscriber_limit_stream_subscription_request,
            &fixtures.command_review_clock,
            &fixtures.subscriber_limit_stream_subscription_review,
        ),
        "stream subscription authority evaluator deterministically rejects subscriptions beyond the stream subscriber limit",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_authority_review_ui_disabled",
        stream_subscription_review_matches_fixture(
            &fixtures.ui_disabled_stream_subscription_authority_snapshot,
            &fixtures.ui_disabled_stream_subscription_request,
            &fixtures.command_review_clock,
            &fixtures.ui_disabled_stream_subscription_review,
        ),
        "stream subscription authority evaluator deterministically rejects UI subscribers when stream policy disables UI subscriptions",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_authority_application_rejection_fixture",
        if fixtures
            .stream_subscription_application_rejection
            .rejection_code
            .as_str()
            == "review_rejected"
            && fixtures
                .stream_subscription_application_rejection
                .current_authority_revision
                == Revision::INITIAL
        {
            Ok(())
        } else {
            Err("standalone stream subscription application rejection fixture is not the expected review-rejected rejection"
                .to_owned())
        },
        "standalone stream subscription application rejection fixture is a review-rejected rejection",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_authority_application_accepted",
        stream_subscription_application_matches_fixture(
            &fixtures.stream_subscription_authority_snapshot,
            &fixtures.accepted_stream_subscription_review,
            &fixtures.accepted_stream_subscription_application,
        ),
        "stream subscription authority application deterministically appends accepted subscription state",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_authority_application_rejected",
        stream_subscription_application_matches_fixture(
            &fixtures.stream_subscription_authority_snapshot,
            &fixtures.stale_stream_subscription_review,
            &fixtures.rejected_stream_subscription_application,
        ),
        "stream subscription authority application deterministically rejects rejected subscription reviews",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_release_authority_snapshot",
        fixtures
            .stream_subscription_active_authority_snapshot
            .validate_authority_links(),
        "stream subscription release authority snapshot has one accepted active subscription",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_release_request_fixture",
        if fixtures
            .stream_subscription_active_authority_snapshot
            .active_stream_subscriptions
            .iter()
            .any(|subscription| {
                subscription.subscription_id
                    == fixtures.stream_subscription_release_request.subscription_id
                    && subscription.subscriber_id
                        == fixtures.stream_subscription_release_request.subscriber_id
                    && subscription.stream_id
                        == fixtures.stream_subscription_release_request.stream_id
            })
            && fixtures
                .stream_subscription_release_request
                .expected_authority_revision
                == fixtures
                    .stream_subscription_active_authority_snapshot
                    .authority_revision
            && fixtures
                .stream_subscription_release_request
                .expected_registry_revision
                == fixtures
                    .stream_subscription_active_authority_snapshot
                    .stream_registry
                    .registry_revision
        {
            Ok(())
        } else {
            Err("stream subscription release request does not target the active subscription snapshot"
                .to_owned())
        },
        "stream subscription release request targets the accepted active subscription",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_release_rejection_fixture",
        if fixtures
            .stream_subscription_release_rejection
            .rejection_code
            .as_str()
            == "stale_revision"
            && fixtures.stream_subscription_release_rejection.retryable
            && fixtures
                .stream_subscription_release_rejection
                .current_authority_revision
                == Revision::new(2).expect("revision literal is valid")
        {
            Ok(())
        } else {
            Err("standalone stream subscription release rejection fixture is not the expected stale-revision rejection"
                .to_owned())
        },
        "standalone stream subscription release rejection fixture is a stale-revision rejection",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_release_authority_audit_event",
        fixtures
            .stream_subscription_release_authority_audit_event
            .validate_against_snapshot(&fixtures.stream_subscription_active_authority_snapshot),
        "stream subscription release authority audit event matches the accepted request, clock, and active snapshot",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_release_authority_review_accepted",
        stream_subscription_release_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.stream_subscription_release_request,
            &fixtures.command_review_clock,
            &fixtures.accepted_stream_subscription_release_review,
        ),
        "stream subscription release authority evaluator deterministically accepts active subscription release",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_release_authority_review_expired_subscription",
        stream_subscription_release_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.stream_subscription_release_request,
            &fixtures.expired_command_review_clock,
            &fixtures.expired_stream_subscription_release_review,
        ),
        "stream subscription release authority evaluator deterministically rejects subscriptions expired at the review clock",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_release_authority_review_stale_revision",
        stream_subscription_release_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.stale_stream_subscription_release_request,
            &fixtures.command_review_clock,
            &fixtures.stale_stream_subscription_release_review,
        ),
        "stream subscription release authority evaluator deterministically rejects stale authority revisions",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_release_authority_review_stale_registry",
        stream_subscription_release_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.stale_registry_stream_subscription_release_request,
            &fixtures.command_review_clock,
            &fixtures.stale_registry_stream_subscription_release_review,
        ),
        "stream subscription release authority evaluator deterministically rejects stale stream registries",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_release_authority_review_unknown_subscription",
        stream_subscription_release_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.unknown_stream_subscription_release_request,
            &fixtures.command_review_clock,
            &fixtures.unknown_stream_subscription_release_review,
        ),
        "stream subscription release authority evaluator deterministically rejects unknown subscriptions",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_release_authority_review_subscriber_mismatch",
        stream_subscription_release_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.subscriber_mismatch_stream_subscription_release_request,
            &fixtures.command_review_clock,
            &fixtures.subscriber_mismatch_stream_subscription_release_review,
        ),
        "stream subscription release authority evaluator deterministically rejects subscriber mismatches",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_release_authority_review_stream_mismatch",
        stream_subscription_release_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.stream_mismatch_stream_subscription_release_request,
            &fixtures.command_review_clock,
            &fixtures.stream_mismatch_stream_subscription_release_review,
        ),
        "stream subscription release authority evaluator deterministically rejects stream mismatches",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_release_authority_application_rejection_fixture",
        if fixtures
            .stream_subscription_release_application_rejection
            .rejection_code
            .as_str()
            == "review_rejected"
            && fixtures
                .stream_subscription_release_application_rejection
                .current_authority_revision
                == Revision::new(2).expect("revision literal is valid")
        {
            Ok(())
        } else {
            Err("standalone stream subscription release application rejection fixture is not the expected review-rejected rejection"
                .to_owned())
        },
        "standalone stream subscription release application rejection fixture is a review-rejected rejection",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_release_authority_application_accepted",
        stream_subscription_release_application_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.accepted_stream_subscription_release_review,
            &fixtures.accepted_stream_subscription_release_application,
        ),
        "stream subscription release authority application deterministically removes accepted active subscription state",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_release_authority_application_rejected",
        stream_subscription_release_application_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.stale_stream_subscription_release_review,
            &fixtures.rejected_stream_subscription_release_application,
        ),
        "stream subscription release authority application deterministically rejects rejected release reviews",
    );

    let stream_subscription_renewal_expected_expires_at_ms =
        u64::try_from(fixtures.command_review_clock.wall_unix_ms)
            .unwrap_or_default()
            .saturating_add(
                fixtures
                    .stream_subscription_renewal_request
                    .requested_ttl_ms,
            );
    push_result(
        checks,
        "validation.check.stream_subscription_renewal_request_fixture",
        match fixtures
            .stream_subscription_active_authority_snapshot
            .active_stream_subscriptions
            .iter()
            .find(|subscription| {
                subscription.subscription_id
                    == fixtures.stream_subscription_renewal_request.subscription_id
                    && subscription.subscriber_id
                        == fixtures.stream_subscription_renewal_request.subscriber_id
                    && subscription.stream_id
                        == fixtures.stream_subscription_renewal_request.stream_id
                    && subscription.transport_id
                        == fixtures.stream_subscription_renewal_request.transport_id
            }) {
            Some(subscription)
                if fixtures
                    .stream_subscription_renewal_request
                    .expected_authority_revision
                    == fixtures
                        .stream_subscription_active_authority_snapshot
                        .authority_revision
                    && fixtures
                        .stream_subscription_renewal_request
                        .expected_registry_revision
                        == fixtures
                            .stream_subscription_active_authority_snapshot
                            .stream_registry
                            .registry_revision
                    && fixtures.stream_subscription_renewal_request.requested_ttl_ms > 0
                    && stream_subscription_renewal_expected_expires_at_ms
                        > subscription.expires_at_ms =>
            {
                Ok(())
            }
            _ => Err(
                "stream subscription renewal request does not extend the active subscription snapshot"
                    .to_owned(),
            ),
        },
        "stream subscription renewal request targets and extends the accepted active subscription",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_renewal_rejection_fixture",
        if fixtures
            .stream_subscription_renewal_rejection
            .rejection_code
            .as_str()
            == "stale_revision"
            && fixtures.stream_subscription_renewal_rejection.retryable
            && fixtures
                .stream_subscription_renewal_rejection
                .current_authority_revision
                == Revision::new(2).expect("revision literal is valid")
            && fixtures
                .stream_subscription_renewal_rejection
                .current_registry_revision
                == Revision::INITIAL
            && fixtures
                .stream_subscription_renewal_rejection
                .active_subscriber_count
                == u32::try_from(
                    fixtures
                        .stream_subscription_active_authority_snapshot
                        .active_stream_subscriptions
                        .len(),
                )
                .expect("fixture active subscription count fits in u32")
            && fixtures
                .stream_subscription_renewal_rejection
                .current_expires_at_ms
                .is_none()
        {
            Ok(())
        } else {
            Err("standalone stream subscription renewal rejection fixture is not the expected stale-revision rejection"
                .to_owned())
        },
        "standalone stream subscription renewal rejection fixture is a stale-revision rejection",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_renewal_authority_audit_event",
        fixtures
            .stream_subscription_renewal_authority_audit_event
            .validate_against_snapshot(&fixtures.stream_subscription_active_authority_snapshot),
        "stream subscription renewal authority audit event matches the accepted request, clock, and active snapshot",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_renewal_authority_review_accepted",
        stream_subscription_renewal_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.stream_subscription_renewal_request,
            &fixtures.command_review_clock,
            &fixtures.accepted_stream_subscription_renewal_review,
        ),
        "stream subscription renewal authority evaluator deterministically accepts active subscription renewal",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_renewal_authority_review_stale_revision",
        stream_subscription_renewal_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.stale_stream_subscription_renewal_request,
            &fixtures.command_review_clock,
            &fixtures.stale_stream_subscription_renewal_review,
        ),
        "stream subscription renewal authority evaluator deterministically rejects stale authority revisions",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_renewal_authority_review_stale_registry",
        stream_subscription_renewal_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.stale_registry_stream_subscription_renewal_request,
            &fixtures.command_review_clock,
            &fixtures.stale_registry_stream_subscription_renewal_review,
        ),
        "stream subscription renewal authority evaluator deterministically rejects stale stream registries",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_renewal_authority_review_unknown_subscription",
        stream_subscription_renewal_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.unknown_stream_subscription_renewal_request,
            &fixtures.command_review_clock,
            &fixtures.unknown_stream_subscription_renewal_review,
        ),
        "stream subscription renewal authority evaluator deterministically rejects unknown subscriptions",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_renewal_authority_review_subscriber_mismatch",
        stream_subscription_renewal_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.subscriber_mismatch_stream_subscription_renewal_request,
            &fixtures.command_review_clock,
            &fixtures.subscriber_mismatch_stream_subscription_renewal_review,
        ),
        "stream subscription renewal authority evaluator deterministically rejects subscriber mismatches",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_renewal_authority_review_stream_mismatch",
        stream_subscription_renewal_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.stream_mismatch_stream_subscription_renewal_request,
            &fixtures.command_review_clock,
            &fixtures.stream_mismatch_stream_subscription_renewal_review,
        ),
        "stream subscription renewal authority evaluator deterministically rejects stream mismatches",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_renewal_authority_review_transport_mismatch",
        stream_subscription_renewal_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.transport_mismatch_stream_subscription_renewal_request,
            &fixtures.command_review_clock,
            &fixtures.transport_mismatch_stream_subscription_renewal_review,
        ),
        "stream subscription renewal authority evaluator deterministically rejects transport mismatches",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_renewal_authority_review_zero_ttl",
        stream_subscription_renewal_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.zero_ttl_stream_subscription_renewal_request,
            &fixtures.command_review_clock,
            &fixtures.zero_ttl_stream_subscription_renewal_review,
        ),
        "stream subscription renewal authority evaluator deterministically rejects zero-duration renewals",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_renewal_authority_review_non_extending",
        stream_subscription_renewal_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.non_extending_stream_subscription_renewal_request,
            &fixtures.command_review_clock,
            &fixtures.non_extending_stream_subscription_renewal_review,
        ),
        "stream subscription renewal authority evaluator deterministically rejects non-extending renewals",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_renewal_authority_review_expired_subscription",
        stream_subscription_renewal_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.stream_subscription_renewal_request,
            &fixtures.expired_command_review_clock,
            &fixtures.expired_stream_subscription_renewal_review,
        ),
        "stream subscription renewal authority evaluator deterministically rejects subscriptions expired at the review clock",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_renewal_authority_application_rejection_fixture",
        if fixtures
            .stream_subscription_renewal_application_rejection
            .rejection_code
            .as_str()
            == "review_rejected"
            && fixtures
                .stream_subscription_renewal_application_rejection
                .current_authority_revision
                == Revision::new(2).expect("revision literal is valid")
        {
            Ok(())
        } else {
            Err("standalone stream subscription renewal application rejection fixture is not the expected review-rejected rejection"
                .to_owned())
        },
        "standalone stream subscription renewal application rejection fixture is a review-rejected rejection",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_renewal_authority_application_accepted",
        stream_subscription_renewal_application_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.accepted_stream_subscription_renewal_review,
            &fixtures.accepted_stream_subscription_renewal_application,
        ),
        "stream subscription renewal authority application deterministically replaces accepted active subscription state",
    );

    push_result(
        checks,
        "validation.check.stream_subscription_renewal_authority_application_rejected",
        stream_subscription_renewal_application_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.stale_stream_subscription_renewal_review,
            &fixtures.rejected_stream_subscription_renewal_application,
        ),
        "stream subscription renewal authority application deterministically rejects rejected renewal reviews",
    );

    let expired_lease_count = fixtures
        .stream_subscription_active_authority_snapshot
        .active_leases
        .iter()
        .filter(|lease| {
            u64::try_from(fixtures.expired_command_review_clock.wall_unix_ms).unwrap_or_default()
                >= lease.expires_at_ms
        })
        .count();
    let expired_subscription_count = fixtures
        .stream_subscription_active_authority_snapshot
        .active_stream_subscriptions
        .iter()
        .filter(|subscription| {
            u64::try_from(fixtures.expired_command_review_clock.wall_unix_ms).unwrap_or_default()
                >= subscription.expires_at_ms
        })
        .count();
    push_result(
        checks,
        "validation.check.authority_expiry_sweep_request_fixture",
        if fixtures
            .authority_expiry_sweep_request
            .expected_authority_revision
            == fixtures
                .stream_subscription_active_authority_snapshot
                .authority_revision
            && fixtures
                .authority_expiry_sweep_request
                .expected_registry_revision
                == fixtures
                    .stream_subscription_active_authority_snapshot
                    .stream_registry
                    .registry_revision
            && expired_lease_count > 0
            && expired_subscription_count > 0
        {
            Ok(())
        } else {
            Err("authority expiry sweep request does not target the active authority snapshot with expired state"
                .to_owned())
        },
        "authority expiry sweep request targets active accepted state with expired leases and subscriptions",
    );

    push_result(
        checks,
        "validation.check.authority_expiry_sweep_rejection_fixture",
        if fixtures
            .authority_expiry_sweep_rejection
            .rejection_code
            .as_str()
            == "stale_revision"
            && fixtures.authority_expiry_sweep_rejection.retryable
            && fixtures
                .authority_expiry_sweep_rejection
                .current_authority_revision
                == fixtures
                    .stream_subscription_active_authority_snapshot
                    .authority_revision
            && fixtures
                .authority_expiry_sweep_rejection
                .current_registry_revision
                == fixtures
                    .stream_subscription_active_authority_snapshot
                    .stream_registry
                    .registry_revision
            && fixtures
                .authority_expiry_sweep_rejection
                .expired_lease_count
                == expired_lease_count
            && fixtures
                .authority_expiry_sweep_rejection
                .expired_subscription_count
                == expired_subscription_count
        {
            Ok(())
        } else {
            Err("standalone authority expiry sweep rejection fixture is not the expected stale-revision rejection"
                .to_owned())
        },
        "standalone authority expiry sweep rejection fixture is a stale-revision rejection",
    );

    push_result(
        checks,
        "validation.check.authority_expiry_sweep_authority_audit_event",
        fixtures
            .authority_expiry_sweep_authority_audit_event
            .validate_against_snapshot(&fixtures.stream_subscription_active_authority_snapshot),
        "authority expiry sweep audit event matches the accepted request, clock, and active snapshot",
    );

    push_result(
        checks,
        "validation.check.authority_expiry_sweep_authority_review_accepted",
        authority_expiry_sweep_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.authority_expiry_sweep_request,
            &fixtures.expired_command_review_clock,
            &fixtures.accepted_authority_expiry_sweep_review,
        ),
        "authority expiry sweep evaluator deterministically accepts expired active leases and stream subscriptions",
    );

    push_result(
        checks,
        "validation.check.authority_expiry_sweep_authority_review_stale_revision",
        authority_expiry_sweep_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.stale_authority_expiry_sweep_request,
            &fixtures.expired_command_review_clock,
            &fixtures.stale_authority_expiry_sweep_review,
        ),
        "authority expiry sweep evaluator deterministically rejects stale authority revisions",
    );

    push_result(
        checks,
        "validation.check.authority_expiry_sweep_authority_review_registry_mismatch",
        authority_expiry_sweep_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.registry_mismatch_authority_expiry_sweep_request,
            &fixtures.expired_command_review_clock,
            &fixtures.registry_mismatch_authority_expiry_sweep_review,
        ),
        "authority expiry sweep evaluator deterministically rejects stale registry revisions",
    );

    push_result(
        checks,
        "validation.check.authority_expiry_sweep_authority_review_no_expired",
        authority_expiry_sweep_review_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.authority_expiry_sweep_request,
            &fixtures.command_review_clock,
            &fixtures.no_expired_authority_expiry_sweep_review,
        ),
        "authority expiry sweep evaluator deterministically rejects sweeps with no expired active state",
    );

    push_result(
        checks,
        "validation.check.authority_expiry_sweep_authority_application_rejection_fixture",
        if fixtures
            .authority_expiry_sweep_application_rejection
            .rejection_code
            .as_str()
            == "review_rejected"
            && fixtures
                .authority_expiry_sweep_application_rejection
                .current_authority_revision
                == fixtures
                    .stream_subscription_active_authority_snapshot
                    .authority_revision
        {
            Ok(())
        } else {
            Err("standalone authority expiry sweep application rejection fixture is not the expected review-rejected rejection"
                .to_owned())
        },
        "standalone authority expiry sweep application rejection fixture is a review-rejected rejection",
    );

    push_result(
        checks,
        "validation.check.authority_expiry_sweep_authority_application_accepted",
        authority_expiry_sweep_application_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.accepted_authority_expiry_sweep_review,
            &fixtures.accepted_authority_expiry_sweep_application,
        ),
        "authority expiry sweep application deterministically removes expired accepted state",
    );

    push_result(
        checks,
        "validation.check.authority_expiry_sweep_authority_application_rejected",
        authority_expiry_sweep_application_matches_fixture(
            &fixtures.stream_subscription_active_authority_snapshot,
            &fixtures.stale_authority_expiry_sweep_review,
            &fixtures.rejected_authority_expiry_sweep_application,
        ),
        "authority expiry sweep application deterministically rejects rejected sweep reviews",
    );

    push_result(
        checks,
        "validation.check.module_runtime_state_request_fixture",
        if fixtures.module_runtime_state_change_request.proposed_state
            == fixtures.next_provider_runtime
        {
            Ok(())
        } else {
            Err(
                "module runtime-state change request does not embed the v2 provider state fixture"
                    .to_owned(),
            )
        },
        "module runtime-state change request embeds the accepted provider runtime-state fixture",
    );

    push_result(
        checks,
        "validation.check.module_runtime_state_authority_audit_event",
        fixtures
            .module_runtime_state_authority_audit_event
            .validate_against_snapshot(&fixtures.authority_snapshot),
        "module runtime-state authority audit event matches the accepted request, lease, clock, and snapshot",
    );

    push_result(
        checks,
        "validation.check.module_runtime_state_rejection_fixture",
        if fixtures
            .module_runtime_state_rejection
            .rejection_code
            .as_str()
            == "stale_revision"
            && fixtures.module_runtime_state_rejection.retryable
            && fixtures
                .module_runtime_state_rejection
                .current_authority_revision
                == Revision::INITIAL
            && fixtures
                .module_runtime_state_rejection
                .current_runtime_revision
                == Some(Revision::INITIAL)
        {
            Ok(())
        } else {
            Err("standalone module runtime-state rejection fixture is not the expected stale-revision rejection"
                .to_owned())
        },
        "standalone module runtime-state rejection fixture is a stale-revision rejection",
    );

    push_result(
        checks,
        "validation.check.module_runtime_state_authority_review_accepted",
        module_runtime_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.module_runtime_state_change_request,
            &fixtures.command_review_clock,
            &fixtures.accepted_module_runtime_review,
        ),
        "module runtime-state authority evaluator deterministically accepts a lease-scoped stop transition",
    );

    push_result(
        checks,
        "validation.check.module_runtime_state_authority_review_expired_lease",
        module_runtime_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.module_runtime_state_change_request,
            &fixtures.expired_command_review_clock,
            &fixtures.expired_lease_module_runtime_review,
        ),
        "module runtime-state authority evaluator deterministically rejects leases expired at the review clock",
    );

    push_result(
        checks,
        "validation.check.module_runtime_state_authority_review_stale_revision",
        module_runtime_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.stale_module_runtime_request,
            &fixtures.command_review_clock,
            &fixtures.stale_module_runtime_review,
        ),
        "module runtime-state authority evaluator deterministically rejects stale authority revisions",
    );

    push_result(
        checks,
        "validation.check.module_runtime_state_authority_review_missing_lease",
        module_runtime_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.missing_lease_module_runtime_request,
            &fixtures.command_review_clock,
            &fixtures.missing_lease_module_runtime_review,
        ),
        "module runtime-state authority evaluator deterministically rejects missing module leases",
    );

    push_result(
        checks,
        "validation.check.module_runtime_state_authority_review_unknown_stream",
        module_runtime_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.unknown_stream_module_runtime_request,
            &fixtures.command_review_clock,
            &fixtures.unknown_stream_module_runtime_review,
        ),
        "module runtime-state authority evaluator deterministically rejects unknown active streams",
    );

    push_result(
        checks,
        "validation.check.module_runtime_state_authority_review_missing_backend",
        module_runtime_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.missing_backend_module_runtime_request,
            &fixtures.command_review_clock,
            &fixtures.missing_backend_module_runtime_review,
        ),
        "module runtime-state authority evaluator deterministically rejects unsupported backends",
    );

    push_result(
        checks,
        "validation.check.module_runtime_state_authority_application_rejection_fixture",
        if fixtures
            .module_runtime_application_rejection
            .rejection_code
            .as_str()
            == "review_rejected"
            && fixtures
                .module_runtime_application_rejection
                .current_authority_revision
                == Revision::INITIAL
        {
            Ok(())
        } else {
            Err("standalone module runtime-state application rejection fixture is not the expected review-rejected rejection"
                .to_owned())
        },
        "standalone module runtime-state application rejection fixture is a review-rejected rejection",
    );

    push_result(
        checks,
        "validation.check.module_runtime_state_authority_application_accepted",
        module_runtime_application_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.accepted_module_runtime_review,
            &fixtures.accepted_module_runtime_application,
        ),
        "module runtime-state authority application deterministically advances accepted runtime state",
    );

    push_result(
        checks,
        "validation.check.module_runtime_state_authority_application_rejected",
        module_runtime_application_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.stale_module_runtime_review,
            &fixtures.rejected_module_runtime_application,
        ),
        "module runtime-state authority application deterministically rejects rejected runtime-state reviews",
    );

    push_result(
        checks,
        "validation.check.host_manifest_lease_fixture",
        if fixtures.host_manifest_lease.scope.as_str() == "manifold.host_manifest"
            && fixtures.host_manifest_lease.holder_id
                == fixtures.host_manifest_change_request.holder_id
            && fixtures.host_manifest_change_request.lease_id.as_ref()
                == Some(&fixtures.host_manifest_lease.lease_id)
        {
            Ok(())
        } else {
            Err(
                "host manifest lease fixture does not authorize the host manifest request"
                    .to_owned(),
            )
        },
        "host manifest lease fixture authorizes the accepted host manifest request",
    );

    push_result(
        checks,
        "validation.check.host_manifest_authority_audit_event",
        fixtures
            .host_manifest_authority_audit_event
            .validate_against_snapshot(&fixtures.authority_snapshot),
        "host manifest authority audit event matches the accepted request, lease, clock, and snapshot",
    );

    push_result(
        checks,
        "validation.check.host_manifest_rejection_fixture",
        if fixtures.host_manifest_rejection.rejection_code.as_str() == "stale_revision"
            && fixtures.host_manifest_rejection.retryable
            && fixtures.host_manifest_rejection.current_authority_revision == Revision::INITIAL
        {
            Ok(())
        } else {
            Err(
                "standalone host manifest rejection fixture is not the expected stale-revision rejection"
                    .to_owned(),
            )
        },
        "standalone host manifest rejection fixture is a stale-revision rejection",
    );

    push_result(
        checks,
        "validation.check.host_manifest_authority_review_accepted",
        host_manifest_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.host_manifest_change_request,
            &fixtures.command_review_clock,
            &fixtures.accepted_host_manifest_review,
        ),
        "host manifest authority evaluator deterministically accepts a lease-scoped permission change",
    );

    push_result(
        checks,
        "validation.check.host_manifest_authority_review_expired_lease",
        host_manifest_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.host_manifest_change_request,
            &fixtures.expired_command_review_clock,
            &fixtures.expired_lease_host_manifest_review,
        ),
        "host manifest authority evaluator deterministically rejects leases expired at the review clock",
    );

    push_result(
        checks,
        "validation.check.host_manifest_authority_review_stale_revision",
        host_manifest_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.stale_host_manifest_request,
            &fixtures.command_review_clock,
            &fixtures.stale_host_manifest_review,
        ),
        "host manifest authority evaluator deterministically rejects stale authority revisions",
    );

    push_result(
        checks,
        "validation.check.host_manifest_authority_review_missing_authority_role",
        host_manifest_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.missing_authority_role_host_manifest_request,
            &fixtures.command_review_clock,
            &fixtures.missing_authority_role_host_manifest_review,
        ),
        "host manifest authority evaluator deterministically rejects missing authority roles",
    );

    push_result(
        checks,
        "validation.check.host_manifest_authority_review_endpoint_mismatch",
        host_manifest_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.endpoint_mismatch_host_manifest_request,
            &fixtures.command_review_clock,
            &fixtures.endpoint_mismatch_host_manifest_review,
        ),
        "host manifest authority evaluator deterministically rejects unsafe endpoint pairings",
    );

    push_result(
        checks,
        "validation.check.host_manifest_authority_review_remove_capability",
        host_manifest_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.remove_capability_host_manifest_request,
            &fixtures.command_review_clock,
            &fixtures.remove_capability_host_manifest_review,
        ),
        "host manifest authority evaluator deterministically rejects capability removal while active leases or commands use it",
    );

    push_result(
        checks,
        "validation.check.host_manifest_authority_review_remove_backend",
        host_manifest_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.remove_backend_host_manifest_request,
            &fixtures.command_review_clock,
            &fixtures.remove_backend_host_manifest_review,
        ),
        "host manifest authority evaluator deterministically rejects backend removal while active modules use it",
    );

    push_result(
        checks,
        "validation.check.host_manifest_authority_application_rejection_fixture",
        if fixtures
            .host_manifest_application_rejection
            .rejection_code
            .as_str()
            == "review_rejected"
            && fixtures
                .host_manifest_application_rejection
                .current_authority_revision
                == Revision::INITIAL
        {
            Ok(())
        } else {
            Err("standalone host manifest application rejection fixture is not the expected review-rejected rejection"
                .to_owned())
        },
        "standalone host manifest application rejection fixture is a review-rejected rejection",
    );

    push_result(
        checks,
        "validation.check.host_manifest_authority_application_accepted",
        host_manifest_application_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.accepted_host_manifest_review,
            &fixtures.accepted_host_manifest_application,
        ),
        "host manifest authority application deterministically advances accepted host state",
    );

    push_result(
        checks,
        "validation.check.host_manifest_authority_application_rejected",
        host_manifest_application_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.stale_host_manifest_review,
            &fixtures.rejected_host_manifest_application,
        ),
        "host manifest authority application deterministically rejects rejected host manifest reviews",
    );

    push_result(
        checks,
        "validation.check.clock_lease_fixture",
        if fixtures.clock_lease.scope.as_str() == "manifold.clock"
            && fixtures.clock_lease.holder_id == fixtures.clock_change_request.holder_id
            && fixtures.clock_change_request.lease_id.as_ref()
                == Some(&fixtures.clock_lease.lease_id)
        {
            Ok(())
        } else {
            Err("clock lease fixture does not authorize the clock request".to_owned())
        },
        "clock lease fixture authorizes the accepted clock request",
    );

    push_result(
        checks,
        "validation.check.clock_authority_audit_event",
        fixtures
            .clock_authority_audit_event
            .validate_against_snapshot(&fixtures.authority_snapshot),
        "clock authority audit event matches the accepted request, lease, clock, and snapshot",
    );

    push_result(
        checks,
        "validation.check.clock_rejection_fixture",
        if fixtures.clock_rejection.rejection_code.as_str() == "stale_revision"
            && fixtures.clock_rejection.retryable
            && fixtures.clock_rejection.current_authority_revision == Revision::INITIAL
            && fixtures.clock_rejection.current_clock_sequence == 42
        {
            Ok(())
        } else {
            Err(
                "standalone clock rejection fixture is not the expected stale-revision rejection"
                    .to_owned(),
            )
        },
        "standalone clock rejection fixture is a stale-revision rejection",
    );

    push_result(
        checks,
        "validation.check.clock_authority_review_accepted",
        clock_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.clock_change_request,
            &fixtures.command_review_clock,
            &fixtures.accepted_clock_review,
        ),
        "clock authority evaluator deterministically accepts a lease-scoped clock tick",
    );

    push_result(
        checks,
        "validation.check.clock_authority_review_expired_lease",
        clock_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.clock_change_request,
            &fixtures.expired_command_review_clock,
            &fixtures.expired_lease_clock_review,
        ),
        "clock authority evaluator deterministically rejects leases expired at the review clock",
    );

    push_result(
        checks,
        "validation.check.clock_authority_review_stale_revision",
        clock_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.stale_clock_request,
            &fixtures.command_review_clock,
            &fixtures.stale_clock_review,
        ),
        "clock authority evaluator deterministically rejects stale authority revisions",
    );

    push_result(
        checks,
        "validation.check.clock_authority_review_missing_lease",
        clock_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.missing_lease_clock_request,
            &fixtures.command_review_clock,
            &fixtures.missing_lease_clock_review,
        ),
        "clock authority evaluator deterministically rejects missing clock leases",
    );

    push_result(
        checks,
        "validation.check.clock_authority_review_domain_mismatch",
        clock_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.domain_mismatch_clock_request,
            &fixtures.command_review_clock,
            &fixtures.domain_mismatch_clock_review,
        ),
        "clock authority evaluator deterministically rejects clock-domain mismatches",
    );

    push_result(
        checks,
        "validation.check.clock_authority_review_sequence_gap",
        clock_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.sequence_gap_clock_request,
            &fixtures.command_review_clock,
            &fixtures.sequence_gap_clock_review,
        ),
        "clock authority evaluator deterministically rejects skipped clock sequences",
    );

    push_result(
        checks,
        "validation.check.clock_authority_review_monotonic_regression",
        clock_review_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.monotonic_regression_clock_request,
            &fixtures.command_review_clock,
            &fixtures.monotonic_regression_clock_review,
        ),
        "clock authority evaluator deterministically rejects monotonic time regressions",
    );

    push_result(
        checks,
        "validation.check.clock_authority_application_rejection_fixture",
        if fixtures.clock_application_rejection.rejection_code.as_str() == "review_rejected"
            && fixtures
                .clock_application_rejection
                .current_authority_revision
                == Revision::INITIAL
        {
            Ok(())
        } else {
            Err("standalone clock application rejection fixture is not the expected review-rejected rejection"
                .to_owned())
        },
        "standalone clock application rejection fixture is a review-rejected rejection",
    );

    push_result(
        checks,
        "validation.check.clock_authority_application_accepted",
        clock_application_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.accepted_clock_review,
            &fixtures.accepted_clock_application,
        ),
        "clock authority application deterministically advances accepted clock state",
    );

    push_result(
        checks,
        "validation.check.clock_authority_application_rejected",
        clock_application_matches_fixture(
            &fixtures.authority_snapshot,
            &fixtures.stale_clock_review,
            &fixtures.rejected_clock_application,
        ),
        "clock authority application deterministically rejects rejected clock reviews",
    );

    let selection_result = match fixtures.deployment_manifest.selection_snapshot(
        &fixtures.package_manifest,
        &fixtures.module_manifests,
        &fixtures.valid_host,
    ) {
        Ok(snapshot) if snapshot == fixtures.deployment_selection => Ok(()),
        Ok(_) => Err("deployment selection snapshot mismatch".to_owned()),
        Err(error) => Err(error.to_string()),
    };
    push_result(
        checks,
        "validation.check.deployment_selection",
        selection_result,
        "deployment selection resolves package, modules, host, endpoint, and backends",
    );

    let host_run_result = if !fixtures
        .host_run_profiles
        .iter()
        .any(|profile| profile.host_profile == fixtures.host_run_bundle.target_host_profile)
    {
        Err("host-run bundle target host profile missing".to_owned())
    } else if fixtures.host_run_bundle.validation_slot_id != fixtures.host_run_slot.slot_id
        || fixtures.host_run_command.validation_slot_id != fixtures.host_run_slot.slot_id
        || fixtures.host_run_evidence.validation_slot_id != fixtures.host_run_slot.slot_id
    {
        Err("host-run slot ids do not align".to_owned())
    } else if fixtures.host_run_evidence.bundle_id != fixtures.host_run_bundle.bundle_id {
        Err("host-run evidence does not reference the run bundle".to_owned())
    } else if fixtures.host_run_evidence.status != rusty_manifold_model::ValidationStatus::Pass {
        Err("host-run evidence fixture did not pass".to_owned())
    } else {
        Ok(())
    };
    push_result(
        checks,
        "validation.check.host_run_bundle_links",
        host_run_result,
        "host-run bundle, command envelope, validation slot, profiles, and evidence align",
    );

    push_result(
        checks,
        "validation.check.shell_handoff_links",
        fixtures.shell_handoff.validate_links(
            &fixtures.valid_registry,
            &fixtures.package_manifest.exports.commands,
            endpoint_ids,
            std::slice::from_ref(&fixtures.host_run_slot.slot_id),
        ),
        "shell handoff streams, commands, endpoint, and validation slot resolve",
    );

    push_result(
        checks,
        "validation.check.shell_handoff_review_receipt",
        fixtures
            .shell_handoff_review
            .validate_against_handoff(&fixtures.shell_handoff),
        "shell handoff review receipt matches the handoff and stays review-only",
    );
}

fn push_damaged_checks(
    repo_root: &Path,
    checks: &mut Vec<ValidationCheckReport>,
    fixtures: &FixtureSet,
    module_ids: &[DottedId],
    endpoint_ids: &[DottedId],
) -> Result<(), CliError> {
    push_damaged(
        checks,
        "validation.check.damaged_endpoint_security",
        expected_rejection(repo_root, "fixtures/damaged/invalid-endpoint-security.json")?,
        fixtures
            .damaged_endpoint_host
            .validate_endpoint_security()
            .map_err(|error| error.rejection_code().to_owned()),
        "public relay endpoint without security policy is rejected",
    );

    push_damaged(
        checks,
        "validation.check.damaged_stale_revision",
        expected_rejection(repo_root, "fixtures/damaged/stale-revision-command.json")?,
        fixtures
            .damaged_stale_command
            .validate_request(
                &fixtures.command_descriptor,
                Revision::new(2).expect("literal is non-zero"),
                Some(&fixtures.control_lease),
            )
            .map_err(|error| error.rejection_code().to_owned()),
        "stale command revision is rejected",
    );

    push_damaged(
        checks,
        "validation.check.damaged_missing_lease",
        expected_rejection(
            repo_root,
            "fixtures/damaged/missing-lease-scope-command.json",
        )?,
        fixtures
            .damaged_missing_lease_command
            .validate_request(&fixtures.command_descriptor, Revision::INITIAL, None)
            .map_err(|error| error.rejection_code().to_owned()),
        "command requiring a lease is rejected when the lease is missing",
    );

    push_damaged(
        checks,
        "validation.check.damaged_authority_audit_unknown_command",
        expected_rejection(
            repo_root,
            "fixtures/damaged/authority-audit-unknown-command.json",
        )?,
        fixtures
            .damaged_command_authority_audit_event
            .validate_against_snapshot(&fixtures.authority_snapshot)
            .map_err(|error| error.rejection_code().to_owned()),
        "command authority audit event cannot accept a command absent from the authority model",
    );

    let bad_timestamp_path = repo_root.join("fixtures/damaged/bad-timestamp-domain.json");
    let bad_timestamp = read_model::<ManifoldStreamManifest>(&bad_timestamp_path);
    push_deserialize_rejection(
        checks,
        "validation.check.damaged_bad_timestamp_domain",
        expected_rejection(repo_root, "fixtures/damaged/bad-timestamp-domain.json")?,
        bad_timestamp,
        "invalid timestamp-domain id is rejected during deserialization",
    );

    push_damaged(
        checks,
        "validation.check.damaged_unknown_stream_module",
        expected_rejection(repo_root, "fixtures/damaged/unknown-module-link.json")?,
        fixtures
            .damaged_unknown_stream_module
            .validate_source_modules(module_ids)
            .map_err(|error| error.rejection_code().to_owned()),
        "stream registry referencing an unknown module is rejected",
    );

    push_damaged(
        checks,
        "validation.check.damaged_shell_handoff_missing_stream",
        expected_rejection(
            repo_root,
            "fixtures/damaged/shell-handoff-missing-stream.json",
        )?,
        fixtures
            .damaged_shell_handoff
            .validate_links(
                &fixtures.valid_registry,
                &fixtures.package_manifest.exports.commands,
                endpoint_ids,
                std::slice::from_ref(&fixtures.host_run_slot.slot_id),
            )
            .map_err(|error| error.rejection_code().to_owned()),
        "shell handoff referencing an unknown stream is rejected",
    );

    push_damaged(
        checks,
        "validation.check.damaged_shell_handoff_review_runtime_started",
        expected_rejection(
            repo_root,
            "fixtures/damaged/shell-handoff-review-runtime-started.json",
        )?,
        fixtures
            .damaged_shell_handoff_review
            .validate_against_handoff(&fixtures.shell_handoff)
            .map_err(|error| error.rejection_code().to_owned()),
        "shell handoff review receipt claiming runtime work is rejected",
    );

    push_damaged(
        checks,
        "validation.check.damaged_unknown_graph_module",
        expected_rejection(repo_root, "fixtures/damaged/unknown-graph-module-link.json")?,
        fixtures
            .damaged_unknown_graph_module
            .validate_links(module_ids)
            .map_err(|error| error.rejection_code().to_owned()),
        "graph node referencing an unknown module is rejected",
    );

    push_damaged(
        checks,
        "validation.check.damaged_unknown_graph_node",
        expected_rejection(repo_root, "fixtures/damaged/unknown-graph-node-link.json")?,
        fixtures
            .damaged_unknown_graph_node
            .validate_links(module_ids)
            .map_err(|error| error.rejection_code().to_owned()),
        "graph edge referencing an unknown node is rejected",
    );

    push_damaged(
        checks,
        "validation.check.damaged_unavailable_deployment_backend",
        expected_rejection(
            repo_root,
            "fixtures/damaged/unavailable-deployment-backend.json",
        )?,
        fixtures
            .damaged_unavailable_deployment
            .validate_selection(
                &fixtures.package_manifest,
                &fixtures.module_manifests,
                &fixtures.valid_host,
            )
            .map_err(|error| error.rejection_code().to_owned()),
        "deployment selecting an unavailable backend is rejected",
    );

    Ok(())
}

#[derive(Serialize)]
pub(super) struct ValidationReport {
    #[serde(rename = "$schema")]
    pub(super) schema_id: String,
    pub(super) status: String,
    pub(super) checks: Vec<ValidationCheckReport>,
}

#[derive(Serialize)]
pub(super) struct ValidationCheckReport {
    pub(super) check_id: String,
    pub(super) status: String,
    pub(super) evidence: String,
    pub(super) rejection_code: Option<String>,
}

fn push_result<T, E>(
    checks: &mut Vec<ValidationCheckReport>,
    check_id: &str,
    result: Result<T, E>,
    evidence: &str,
) where
    E: fmt::Display,
{
    match result {
        Ok(_) => checks.push(pass(check_id, evidence)),
        Err(error) => checks.push(fail(check_id, error.to_string(), None)),
    }
}

fn push_damaged<T>(
    checks: &mut Vec<ValidationCheckReport>,
    check_id: &str,
    expected_rejection: String,
    result: Result<T, String>,
    evidence: &str,
) {
    match result {
        Ok(_) => checks.push(fail(
            check_id,
            format!("damaged input was accepted; expected {expected_rejection}"),
            Some(expected_rejection),
        )),
        Err(rejection_code) if rejection_code == expected_rejection => {
            checks.push(pass_with_rejection(check_id, evidence, rejection_code));
        }
        Err(rejection_code) => checks.push(fail(
            check_id,
            format!("expected {expected_rejection}, got {rejection_code}"),
            Some(rejection_code),
        )),
    }
}

fn push_deserialize_rejection<T>(
    checks: &mut Vec<ValidationCheckReport>,
    check_id: &str,
    expected_rejection: String,
    result: Result<T, CliError>,
    evidence: &str,
) {
    match result {
        Ok(_) => checks.push(fail(
            check_id,
            format!("damaged input was accepted; expected {expected_rejection}"),
            Some(expected_rejection),
        )),
        Err(CliError::Json { .. }) if expected_rejection == "invalid_dotted_id" => {
            checks.push(pass_with_rejection(check_id, evidence, expected_rejection));
        }
        Err(error) => checks.push(fail(check_id, error.to_string(), Some(expected_rejection))),
    }
}

fn pass(check_id: &str, evidence: &str) -> ValidationCheckReport {
    ValidationCheckReport {
        check_id: check_id.to_owned(),
        status: "pass".to_owned(),
        evidence: evidence.to_owned(),
        rejection_code: None,
    }
}

fn pass_with_rejection(
    check_id: &str,
    evidence: &str,
    rejection_code: String,
) -> ValidationCheckReport {
    ValidationCheckReport {
        check_id: check_id.to_owned(),
        status: "pass".to_owned(),
        evidence: evidence.to_owned(),
        rejection_code: Some(rejection_code),
    }
}

fn fail(check_id: &str, evidence: String, rejection_code: Option<String>) -> ValidationCheckReport {
    ValidationCheckReport {
        check_id: check_id.to_owned(),
        status: "fail".to_owned(),
        evidence,
        rejection_code,
    }
}

fn expected_rejection(repo_root: &Path, relative_path: &str) -> Result<String, CliError> {
    let path = repo_root.join(relative_path);
    let text = read_text(&path)?;
    let value: serde_json::Value =
        serde_json::from_str(&text).map_err(|source| CliError::Json {
            path: path.clone(),
            source,
        })?;
    value
        .get("expected_rejection")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or(CliError::MissingExpectedRejection { path })
}
