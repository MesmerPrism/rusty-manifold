use super::*;

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
