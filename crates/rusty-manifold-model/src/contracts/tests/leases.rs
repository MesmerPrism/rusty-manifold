use super::*;

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
fn lease_authority_review_rejects_substituted_derived_lineage_ids() {
    let snapshot = authority_snapshot();
    let review = snapshot
        .review_lease_request(
            lease_request(),
            command_review_clock(),
            vec![id("evidence.lease_authority.request.synthetic_lease_1")],
        )
        .unwrap();

    let mut substituted_review = review.clone();
    substituted_review.review_id = id("lease_review.substituted");
    assert!(substituted_review
        .validate_against_snapshot(&snapshot)
        .is_err());

    let mut substituted_audit = review.clone();
    substituted_audit.audit_event.event_id = id("audit.lease.substituted");
    assert!(substituted_audit
        .validate_against_snapshot(&snapshot)
        .is_err());

    let mut substituted_lease = review;
    let lease_id = id("lease.substituted");
    substituted_lease
        .accepted
        .as_mut()
        .unwrap()
        .lease_id
        .clone_from(&lease_id);
    substituted_lease
        .audit_event
        .accepted
        .as_mut()
        .unwrap()
        .lease_id = lease_id;
    assert!(substituted_lease
        .validate_against_snapshot(&snapshot)
        .is_err());
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
fn lease_revocation_is_authority_owned_and_emits_terminal_tombstone() {
    let snapshot = authority_snapshot();
    let lease = snapshot.active_leases[0].clone();
    let request = ManifoldControlLeaseRevocationRequest {
        schema_id: control_lease_revocation_request_schema_id(),
        request_id: id("request.lease_revocation.synthetic_module"),
        authority_id: snapshot.authority_id.clone(),
        lease_id: lease.lease_id.clone(),
        expected_authority_revision: snapshot.authority_revision,
        scope: lease.scope.clone(),
        revocation_reason: id("authority.security_policy"),
        requested_at_ms: 1_765_000_000_200,
    };
    let review = snapshot
        .review_control_lease_revocation(
            request,
            command_review_clock(),
            vec![id("evidence.lease_revocation_authority.synthetic_module")],
        )
        .unwrap();

    assert_eq!(
        review.outcome,
        ManifoldControlLeaseRevocationAuthorityReviewOutcome::LeaseRevoked
    );
    assert_eq!(review.revoked.as_ref(), Some(&lease));
    assert_eq!(review.validate_against_snapshot(&snapshot), Ok(()));

    let application = snapshot
        .apply_control_lease_revocation_authority_review(review)
        .unwrap();
    assert_eq!(
        application.outcome,
        ManifoldControlLeaseRevocationAuthorityApplicationOutcome::LeaseRevocationApplied
    );
    assert!(application.rejection.is_none());
    let applied = application.applied_snapshot.as_ref().unwrap();
    assert_eq!(applied.authority_revision, Revision::new(2).unwrap());
    assert!(!applied
        .active_leases
        .iter()
        .any(|active| active.lease_id == lease.lease_id));

    let tombstone = application.tombstone.as_ref().unwrap();
    assert_eq!(tombstone.revoked_lease, lease);
    assert_eq!(tombstone.prior_authority_revision, Revision::INITIAL);
    assert_eq!(
        tombstone.revoked_authority_revision,
        Revision::new(2).unwrap()
    );
    assert_eq!(
        tombstone.revocation_reason.as_str(),
        "authority.security_policy"
    );
    assert_eq!(
        tombstone.validate_against_review(&application.review),
        Ok(())
    );
    assert_eq!(application.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn lease_revocation_accepts_expired_retained_lease_for_terminal_cleanup() {
    let mut snapshot = authority_snapshot();
    let clock = command_review_clock();
    snapshot.active_leases[0].expires_at_ms = u64::try_from(clock.wall_unix_ms).unwrap();
    let lease = snapshot.active_leases[0].clone();
    let review = snapshot
        .review_control_lease_revocation(
            ManifoldControlLeaseRevocationRequest {
                schema_id: control_lease_revocation_request_schema_id(),
                request_id: id("request.lease_revocation.expired_module"),
                authority_id: snapshot.authority_id.clone(),
                lease_id: lease.lease_id.clone(),
                expected_authority_revision: snapshot.authority_revision,
                scope: lease.scope.clone(),
                revocation_reason: id("authority.compromised"),
                requested_at_ms: 1_765_000_000_200,
            },
            clock,
            vec![id("evidence.lease_revocation_authority.expired_module")],
        )
        .unwrap();

    assert_eq!(
        review.outcome,
        ManifoldControlLeaseRevocationAuthorityReviewOutcome::LeaseRevoked
    );
    let application = snapshot
        .apply_control_lease_revocation_authority_review(review)
        .unwrap();
    assert_eq!(application.tombstone.as_ref().unwrap().revoked_lease, lease);
}

#[test]
fn lease_revocation_rejects_substituted_authority_without_mutation() {
    let snapshot = authority_snapshot();
    let lease = snapshot.active_leases[0].clone();
    let review = snapshot
        .review_control_lease_revocation(
            ManifoldControlLeaseRevocationRequest {
                schema_id: control_lease_revocation_request_schema_id(),
                request_id: id("request.lease_revocation.wrong_authority"),
                authority_id: id("authority.substituted"),
                lease_id: lease.lease_id,
                expected_authority_revision: snapshot.authority_revision,
                scope: lease.scope,
                revocation_reason: id("authority.security_policy"),
                requested_at_ms: 1_765_000_000_200,
            },
            command_review_clock(),
            vec![id("evidence.lease_revocation_authority.wrong_authority")],
        )
        .unwrap();

    assert_eq!(
        review.outcome,
        ManifoldControlLeaseRevocationAuthorityReviewOutcome::LeaseRevocationRejected
    );
    assert_eq!(
        review.rejection.as_ref().unwrap().rejection_code.as_str(),
        "authority_id_mismatch"
    );
    let application = snapshot
        .apply_control_lease_revocation_authority_review(review)
        .unwrap();
    assert_eq!(
        application.outcome,
        ManifoldControlLeaseRevocationAuthorityApplicationOutcome::
            LeaseRevocationApplicationRejected
    );
    assert!(application.applied_snapshot.is_none());
    assert!(application.tombstone.is_none());
    assert_eq!(application.validate_against_snapshot(&snapshot), Ok(()));
}

#[test]
fn lease_revocation_validation_rejects_tombstone_substitution() {
    let snapshot = authority_snapshot();
    let lease = snapshot.active_leases[0].clone();
    let review = snapshot
        .review_control_lease_revocation(
            ManifoldControlLeaseRevocationRequest {
                schema_id: control_lease_revocation_request_schema_id(),
                request_id: id("request.lease_revocation.tombstone_lineage"),
                authority_id: snapshot.authority_id.clone(),
                lease_id: lease.lease_id,
                expected_authority_revision: snapshot.authority_revision,
                scope: lease.scope,
                revocation_reason: id("authority.security_policy"),
                requested_at_ms: 1_765_000_000_200,
            },
            command_review_clock(),
            vec![id("evidence.lease_revocation_authority.tombstone_lineage")],
        )
        .unwrap();
    let mut application = snapshot
        .apply_control_lease_revocation_authority_review(review)
        .unwrap();
    application.tombstone.as_mut().unwrap().revocation_reason = id("authority.substituted_reason");

    assert!(application.validate_against_snapshot(&snapshot).is_err());
}

#[test]
fn revoked_lease_identity_cannot_be_reissued() {
    let snapshot = authority_snapshot();
    let lease = snapshot.active_leases[0].clone();
    let revocation = snapshot
        .review_control_lease_revocation(
            ManifoldControlLeaseRevocationRequest {
                schema_id: control_lease_revocation_request_schema_id(),
                request_id: id("request.lease_revocation.block_reissue"),
                authority_id: snapshot.authority_id.clone(),
                lease_id: lease.lease_id,
                expected_authority_revision: snapshot.authority_revision,
                scope: lease.scope.clone(),
                revocation_reason: id("authority.security_policy"),
                requested_at_ms: 1_765_000_000_200,
            },
            command_review_clock(),
            vec![id("evidence.lease_revocation_authority.block_reissue")],
        )
        .unwrap();
    let revoked_snapshot = snapshot
        .apply_control_lease_revocation_authority_review(revocation)
        .unwrap()
        .applied_snapshot
        .unwrap();

    let review = revoked_snapshot
        .review_lease_request(
            ManifoldControlLeaseRequest {
                schema_id: schema("rusty.manifold.command.lease_request.v1"),
                request_id: id("request.synthetic_module"),
                holder_id: id("holder.replacement"),
                scope: lease.scope,
                expected_revision: revoked_snapshot.authority_revision,
                requested_ttl_ms: 30_000,
                required_capability: id("manifold.module.control"),
                safety_class: SafetyClass::BoundedMutation,
            },
            command_review_clock(),
            vec![id("evidence.lease_authority.reissue_revoked")],
        )
        .unwrap();

    assert_eq!(
        review.outcome,
        ManifoldControlLeaseAuthorityReviewOutcome::LeaseRejected
    );
    assert_eq!(
        review.rejection.as_ref().unwrap().rejection_code.as_str(),
        "revoked_lease_id"
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
}

#[test]
fn lease_lifecycle_applications_preserve_revocation_tombstones() {
    let snapshot = authority_snapshot();
    let lease = snapshot.active_leases[0].clone();
    let revocation = snapshot
        .review_control_lease_revocation(
            ManifoldControlLeaseRevocationRequest {
                schema_id: control_lease_revocation_request_schema_id(),
                request_id: id("request.lease_revocation.retention"),
                authority_id: snapshot.authority_id.clone(),
                lease_id: lease.lease_id,
                expected_authority_revision: snapshot.authority_revision,
                scope: lease.scope,
                revocation_reason: id("authority.security_policy"),
                requested_at_ms: 1_765_000_000_200,
            },
            command_review_clock(),
            vec![id("evidence.lease_revocation_authority.retention")],
        )
        .unwrap();
    let revoked_snapshot = snapshot
        .apply_control_lease_revocation_authority_review(revocation)
        .unwrap()
        .applied_snapshot
        .unwrap();
    let expected_tombstones = revoked_snapshot.revoked_control_lease_tombstones.clone();

    let issue = revoked_snapshot
        .review_lease_request(
            ManifoldControlLeaseRequest {
                schema_id: schema("rusty.manifold.command.lease_request.v1"),
                request_id: id("request.after_revocation"),
                holder_id: id("holder.test_agent"),
                scope: id("manifold.graph"),
                expected_revision: revoked_snapshot.authority_revision,
                requested_ttl_ms: 30_000,
                required_capability: id("manifold.graph.run"),
                safety_class: SafetyClass::BoundedMutation,
            },
            command_review_clock(),
            vec![id("evidence.lease_authority.after_revocation")],
        )
        .unwrap();
    let issued = revoked_snapshot
        .apply_control_lease_authority_review(issue)
        .unwrap();
    assert_eq!(
        issued
            .applied_snapshot
            .as_ref()
            .unwrap()
            .revoked_control_lease_tombstones,
        expected_tombstones
    );

    let release_lease = revoked_snapshot.active_leases[0].clone();
    let release = revoked_snapshot
        .review_control_lease_release(
            ManifoldControlLeaseReleaseRequest {
                schema_id: control_lease_release_request_schema_id(),
                request_id: id("request.lease_release.after_revocation"),
                lease_id: release_lease.lease_id,
                holder_id: release_lease.holder_id,
                expected_authority_revision: revoked_snapshot.authority_revision,
                scope: release_lease.scope,
                release_reason: id("holder.done"),
                requested_at_ms: 1_765_000_000_200,
            },
            command_review_clock(),
            vec![id("evidence.lease_release_authority.after_revocation")],
        )
        .unwrap();
    let released = revoked_snapshot
        .apply_control_lease_release_authority_review(release)
        .unwrap();
    assert_eq!(
        released
            .applied_snapshot
            .as_ref()
            .unwrap()
            .revoked_control_lease_tombstones,
        expected_tombstones
    );

    let renewal_lease = revoked_snapshot.active_leases[1].clone();
    let renewal = revoked_snapshot
        .review_control_lease_renewal(
            ManifoldControlLeaseRenewalRequest {
                schema_id: control_lease_renewal_request_schema_id(),
                request_id: id("request.lease_renewal.after_revocation"),
                lease_id: renewal_lease.lease_id,
                holder_id: renewal_lease.holder_id,
                expected_authority_revision: revoked_snapshot.authority_revision,
                scope: renewal_lease.scope,
                requested_ttl_ms: 60_000,
                renewal_reason: id("holder.needs_more_time"),
                requested_at_ms: 1_765_000_000_200,
            },
            command_review_clock(),
            vec![id("evidence.lease_renewal_authority.after_revocation")],
        )
        .unwrap();
    let renewed = revoked_snapshot
        .apply_control_lease_renewal_authority_review(renewal)
        .unwrap();
    assert_eq!(
        renewed
            .applied_snapshot
            .as_ref()
            .unwrap()
            .revoked_control_lease_tombstones,
        expected_tombstones
    );

    let mut expiry_snapshot = revoked_snapshot.clone();
    let expiry_clock = command_review_clock();
    expiry_snapshot.active_leases[0].expires_at_ms =
        u64::try_from(expiry_clock.wall_unix_ms).unwrap();
    let expiry = expiry_snapshot
        .review_authority_expiry_sweep(
            ManifoldAuthorityExpirySweepRequest {
                schema_id: authority_expiry_sweep_request_schema_id(),
                request_id: id("request.expiry_sweep.after_revocation"),
                requester_id: expiry_snapshot.authority_id.clone(),
                expected_authority_revision: expiry_snapshot.authority_revision,
                expected_registry_revision: expiry_snapshot.stream_registry.registry_revision,
                sweep_reason: id("maintenance.ttl_expired"),
                requested_at_ms: 1_765_000_000_200,
            },
            expiry_clock,
            vec![id("evidence.expiry_sweep.after_revocation")],
        )
        .unwrap();
    let expired = expiry_snapshot
        .apply_authority_expiry_sweep_review(expiry)
        .unwrap();
    assert_eq!(
        expired
            .applied_snapshot
            .as_ref()
            .unwrap()
            .revoked_control_lease_tombstones,
        expected_tombstones
    );
}

#[test]
fn authority_snapshot_rejects_noncanonical_or_resurrected_tombstones() {
    let snapshot = authority_snapshot();
    let first_lease = snapshot.active_leases[0].clone();
    let first = snapshot
        .review_control_lease_revocation(
            ManifoldControlLeaseRevocationRequest {
                schema_id: control_lease_revocation_request_schema_id(),
                request_id: id("request.lease_revocation.canonical_first"),
                authority_id: snapshot.authority_id.clone(),
                lease_id: first_lease.lease_id,
                expected_authority_revision: snapshot.authority_revision,
                scope: first_lease.scope,
                revocation_reason: id("authority.security_policy"),
                requested_at_ms: 1_765_000_000_200,
            },
            command_review_clock(),
            vec![id("evidence.lease_revocation_authority.canonical_first")],
        )
        .unwrap();
    let first_snapshot = snapshot
        .apply_control_lease_revocation_authority_review(first)
        .unwrap()
        .applied_snapshot
        .unwrap();
    let second_lease = first_snapshot.active_leases[0].clone();
    let second = first_snapshot
        .review_control_lease_revocation(
            ManifoldControlLeaseRevocationRequest {
                schema_id: control_lease_revocation_request_schema_id(),
                request_id: id("request.lease_revocation.canonical_second"),
                authority_id: first_snapshot.authority_id.clone(),
                lease_id: second_lease.lease_id,
                expected_authority_revision: first_snapshot.authority_revision,
                scope: second_lease.scope,
                revocation_reason: id("authority.security_policy"),
                requested_at_ms: 1_765_000_000_300,
            },
            command_review_clock(),
            vec![id("evidence.lease_revocation_authority.canonical_second")],
        )
        .unwrap();
    let canonical = first_snapshot
        .apply_control_lease_revocation_authority_review(second)
        .unwrap()
        .applied_snapshot
        .unwrap();
    assert_eq!(canonical.validate_authority_links(), Ok(()));

    let mut noncanonical = canonical.clone();
    noncanonical.revoked_control_lease_tombstones.reverse();
    assert!(noncanonical.validate_authority_links().is_err());

    let mut duplicated = canonical.clone();
    duplicated
        .revoked_control_lease_tombstones
        .push(duplicated.revoked_control_lease_tombstones[1].clone());
    assert!(duplicated.validate_authority_links().is_err());

    let mut duplicate_request = canonical.clone();
    duplicate_request.revoked_control_lease_tombstones[1].revocation_request_id = duplicate_request
        .revoked_control_lease_tombstones[0]
        .revocation_request_id
        .clone();
    duplicate_request.revoked_control_lease_tombstones[1].tombstone_id = duplicate_request
        .revoked_control_lease_tombstones[0]
        .tombstone_id
        .clone();
    assert!(duplicate_request.validate_authority_links().is_err());

    let mut damaged_clock = canonical.clone();
    damaged_clock.revoked_control_lease_tombstones[0]
        .recorded_clock
        .schema_id = schema("rusty.manifold.clock.snapshot.v9");
    assert!(damaged_clock.validate_authority_links().is_err());

    let mut resurrected = canonical;
    resurrected.active_leases.push(
        resurrected.revoked_control_lease_tombstones[0]
            .revoked_lease
            .clone(),
    );
    assert!(resurrected.validate_authority_links().is_err());
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
