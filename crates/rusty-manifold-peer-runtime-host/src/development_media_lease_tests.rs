//! Real Broker admission into the private derivative-lease producer and validator.
use super::*;

const HORIZON: u64 = 2_592_000_000;
const NOW: u64 = 4_000;
const OUTER_EXPIRY: u64 = 2_592_003_000;

fn fixture(
    selected: bool,
    use_expiry: u64,
) -> (
    Box<ManifoldPeerRuntimeHost>,
    ManifoldBrokerRuntime,
    ManifoldBrokerMutationRequest,
) {
    let product = resolve_broker_product(&ManifoldBrokerProductSpec {
        schema_id: schema_id(BROKER_PRODUCT_SPEC_SCHEMA),
        product_id: id("broker.runtime.media-test"),
        standalone_enabled: true,
        embedded_enabled: false,
        requested_features: vec![ManifoldBrokerFeature::MediaSession],
    })
    .unwrap();
    let packaged = serde_json::to_vec(&product).unwrap();
    let mut trust = trust_policy();
    let grant = &mut trust.media_client_grants[0];
    grant.broker_product_lock_id = product.lock_id.clone();
    grant.broker_product_lock_fingerprint = product.spec_fingerprint.clone();
    grant.broker_product_lock_sha256 = packaged_product_lock_sha256(&packaged);
    let grant = grant.clone();
    if selected {
        trust.schema_id = schema_id(DEVELOPMENT_PEER_TRUST_POLICY_SCHEMA);
    }
    let mut inner = media_command_runtime();
    inner
        .leases
        .retain(|lease| lease.scope.as_str() != MEDIA_RUNTIME_LEASE_SCOPE_ID);
    let host = Box::new(
        if selected {
            ManifoldPeerRuntimeHost::new_with_lifetime_policy(
                id("host.development.media-lease"),
                trust.clone(),
                id(PROVIDER_EPOCH_ID),
                inner,
                rusty_manifold_admission::ManifoldDevelopmentLifetimePolicy::source_owned_v1(),
            )
        } else {
            ManifoldPeerRuntimeHost::new(
                id("host.development.media-lease"),
                trust.clone(),
                id(PROVIDER_EPOCH_ID),
                inner,
            )
        }
        .unwrap(),
    );

    // Issue the actual outer control lease through review/application/projector;
    // no fabricated Runtime Host lease collection is accepted by the Broker.
    let mut prior: ManifoldAuthoritySnapshot = serde_json::from_str(include_str!(
        "../../../fixtures/authority/synthetic-authority-snapshot.json"
    ))
    .unwrap();
    let mut clock: ManifoldClockSnapshot = serde_json::from_str(include_str!(
        "../../../fixtures/clock/synthetic-command-review-clock.json"
    ))
    .unwrap();
    prior.clock_snapshot.wall_unix_ms = 2_900;
    clock.wall_unix_ms = 3_000;
    let capability = id("capability.broker.peer-runtime.test");
    prior.host_manifest.capabilities.push(capability.clone());
    let review = prior
        .review_lease_request(
            ManifoldControlLeaseRequest {
                schema_id: schema_id("rusty.manifold.command.lease_request.v1"),
                request_id: id("request.broker.media.development.outer"),
                holder_id: grant.client_id.clone(),
                scope: id("lease.media.session"),
                expected_revision: prior.authority_revision,
                requested_ttl_ms: HORIZON,
                required_capability: capability,
                safety_class: SafetyClass::BoundedMutation,
            },
            clock.clone(),
            vec![id("evidence.broker.peer-runtime.test.lease")],
        )
        .unwrap();
    let application = prior.apply_control_lease_authority_review(review).unwrap();
    let current = application.applied_snapshot.clone().unwrap();
    // The review derives the lease id from its request identity.
    let actual = current.active_leases.last().unwrap();
    assert_eq!(actual.expires_at_ms, OUTER_EXPIRY);
    let mut trust = trust;
    trust.media_client_grants[0].broker_runtime_lease_id = actual.lease_id.clone();
    let mut host = host;
    host.snapshot.trust_policy = trust.clone();
    let grant = trust.media_client_grants[0].clone();
    let authority =
        ManifoldBrokerControlLeaseAuthority::from_caller_attested_retained_authority_state(
            current,
            clock,
            vec![ManifoldBrokerControlLeaseSource {
                schema_id: schema_id(BROKER_CONTROL_LEASE_SOURCE_SCHEMA),
                prior_authority_snapshot: prior,
                application,
            }],
        )
        .unwrap();
    let adapter = ManifoldBrokerAdapter::new(
        ManifoldBrokerAdapterConfig {
            schema_id: schema_id(BROKER_ADAPTER_CONFIG_SCHEMA),
            adapter_id: grant.broker_adapter_id.clone(),
            mode: ManifoldBrokerAdapterMode::Standalone,
            product_lock_id: product.lock_id,
            product_lock_fingerprint: product.spec_fingerprint,
            product_lock_sha256: packaged_product_lock_sha256(&packaged),
            authority_host_id: grant.broker_runtime_host_id.clone(),
            authority_owner_id: id(RUNTIME_HOST_AUTHORITY_OWNER),
        },
        &packaged,
        &authority,
    )
    .unwrap();
    let admission = ManifoldAdmissionSnapshot {
        history_checkpoint: None,
        root_renewal_policies: Vec::new(),
        schema_id: schema_id(if selected {
            rusty_manifold_admission::DEVELOPMENT_ADMISSION_SNAPSHOT_SCHEMA
        } else {
            ADMISSION_SNAPSHOT_SCHEMA
        }),
        authority_id: id("authority.admission.media-test"),
        authority_revision: Revision::INITIAL,
        grants: vec![ManifoldAdmissionGrant {
            grant_id: grant.admission_grant_id.clone(),
            client_lock_id: grant.broker_client_lock_id.clone(),
            client_lock_fingerprint: grant.broker_client_lock_fingerprint.clone(),
            identity: grant.broker_client_identity.clone(),
            capabilities: vec![grant.broker_capability_id.clone()],
            expires_at_ms: OUTER_EXPIRY,
            revoked: false,
        }],
        active_tokens: Vec::new(),
        revoked_token_ids: Vec::new(),
        consumed_request_ids: Vec::new(),
        consumed_use_request_ids: Vec::new(),
        reviewed_sweep_ids: Vec::new(),
        audit_events: Vec::new(),
        max_token_ttl_ms: HORIZON,
    };
    let mut broker = if selected {
        ManifoldBrokerRuntime::new_with_lifetime_policy(
            id(PROVIDER_EPOCH_ID),
            adapter,
            authority,
            admission,
            rusty_manifold_admission::ManifoldDevelopmentLifetimePolicy::source_owned_v1(),
        )
    } else {
        ManifoldBrokerRuntime::new(id(PROVIDER_EPOCH_ID), adapter, authority, admission)
    }
    .unwrap();
    assert_eq!(broker.host_snapshot().leases[0].expires_at_ms, OUTER_EXPIRY);
    let issued = broker.issue_token(
        &ManifoldAdmissionRequest {
            schema_id: schema_id(ADMISSION_REQUEST_SCHEMA),
            request_id: id("request.development.media.issue"),
            expected_authority_revision: broker.admission_snapshot().authority_revision,
            identity: grant.broker_client_identity.clone(),
            requested_capabilities: vec![grant.broker_capability_id.clone()],
            issued_at_ms: 3_200,
            expires_at_ms: 3_300,
            requested_token_ttl_ms: HORIZON,
        },
        [71; 32],
        3_200,
    );
    assert!(issued.applied, "{issued:?}");
    let token = issued.token.unwrap();
    let use_id = id("request.development.media.use");
    let used = broker.authorize_use(
        &ManifoldAdmissionUseRequest {
            schema_id: schema_id(ADMISSION_USE_REQUEST_SCHEMA),
            request_id: use_id.clone(),
            expected_authority_revision: issued.resulting_authority_revision,
            token_id: token.token_id.clone(),
            identity: grant.broker_client_identity,
            capability_id: grant.broker_capability_id,
            issued_at_ms: 3_201,
            expires_at_ms: use_expiry,
        },
        3_201,
    );
    assert!(used.applied, "{used:?}");
    let mutation = ManifoldBrokerMutationRequest {
        schema_id: schema_id(BROKER_MUTATION_REQUEST_SCHEMA),
        provider_epoch_id: id(PROVIDER_EPOCH_ID),
        admission_use_request_id: use_id,
        token_id: token.token_id,
        expected_admission_authority_revision: used.resulting_authority_revision,
        command: ManifoldRuntimeCommandRequest {
            schema_id: schema_id(HOST_COMMAND_REQUEST_SCHEMA),
            request_id: id("request.development.media.outer-command"),
            expected_authority_revision: broker.host_snapshot().authority_revision,
            requester_id: grant.client_id,
            command_id: grant.broker_command_id,
            lease_id: Some(grant.broker_runtime_lease_id),
            params_digest: None,
            issued_at_ms: 3_202,
            expires_at_ms: 10_000,
        },
    };
    (host, broker, mutation)
}

fn admit(selected: bool, use_expiry: u64) -> (Box<ManifoldPeerRuntimeHost>, ManifoldBrokerRuntime) {
    let (mut host, mut broker, mutation) = fixture(selected, use_expiry);
    let before_host = host.snapshot_json().unwrap();
    let before_broker = broker.evidence();
    host.preflight_broker_media_runtime_lease(&broker, &mutation, NOW)
        .unwrap();
    assert_eq!(host.snapshot_json().unwrap(), before_host);
    assert_eq!(
        broker.evidence(),
        before_broker,
        "preflight must not consume the outer use"
    );
    let receipt = broker.handle_mutation(&mutation, NOW);
    assert!(receipt.applied, "{receipt:?}");
    host.admit_live_broker_media_receipt(&mutation, &receipt, &broker.evidence(), NOW)
        .unwrap();
    (host, broker)
}

#[test]
fn development_media_lease_admission_keeps_actual_thirty_day_outer_bound() {
    let (host, broker) = admit(true, OUTER_EXPIRY);
    assert_eq!(
        host.snapshot().broker_lease_admissions[0]
            .runtime_lease
            .expires_at_ms,
        OUTER_EXPIRY
    );
    assert_eq!(
        host.snapshot()
            .media_command_runtime
            .leases
            .iter()
            .find(|l| l.derivative_binding.is_some())
            .unwrap()
            .expires_at_ms,
        OUTER_EXPIRY
    );
    let raw = host.snapshot_json().unwrap();
    let restored =
        ManifoldPeerRuntimeHost::restart_from_json_with_live_broker_runtime_and_lifetime_policy(
            &raw,
            &host.snapshot().trust_policy,
            &id(PROVIDER_EPOCH_ID),
            &broker,
            rusty_manifold_admission::ManifoldDevelopmentLifetimePolicy::source_owned_v1(),
        )
        .unwrap()
        .0;
    assert_eq!(restored.snapshot_json().unwrap(), raw);
}

#[test]
fn development_media_lease_admission_keeps_short_upstream_bound_and_finite_control() {
    let mut trust = trust_policy();
    assert_eq!(
        broker_media_runtime_lease_expiry(&trust, OUTER_EXPIRY, NOW),
        124_000
    );
    trust.schema_id = schema_id(DEVELOPMENT_PEER_TRUST_POLICY_SCHEMA);
    assert_eq!(
        broker_media_runtime_lease_expiry(&trust, OUTER_EXPIRY, NOW),
        OUTER_EXPIRY
    );
    assert_eq!(
        broker_media_runtime_lease_expiry(&trust, 12_000, NOW),
        12_000
    );
    assert_eq!(
        broker_media_runtime_lease_expiry(&trust, u64::MAX, u64::MAX - 10),
        u64::MAX
    );
    for (selected, outer_bound, expected) in
        [(true, 12_000, 12_000), (false, OUTER_EXPIRY, 124_000)]
    {
        let (host, _) = admit(selected, outer_bound);
        assert_eq!(
            host.snapshot().broker_lease_admissions[0]
                .runtime_lease
                .expires_at_ms,
            expected
        );
    }
}

#[test]
fn development_media_lease_legacy_exact_record_restores_without_extending_and_rejects_inflation() {
    // The finite producer reproduces the old exact 120-second derivation. The
    // selected trust schema models an accepted pre-fix development record.
    let (host, broker) = admit(false, OUTER_EXPIRY);
    let mut old = host.snapshot().clone();
    old.trust_policy.schema_id = schema_id(DEVELOPMENT_PEER_TRUST_POLICY_SCHEMA);
    let trust = old.trust_policy.clone();
    let policy = rusty_manifold_admission::ManifoldDevelopmentLifetimePolicy::source_owned_v1();
    assert_eq!(
        old.broker_lease_admissions[0].runtime_lease.expires_at_ms,
        124_000
    );
    let raw = serde_json::to_string_pretty(&old).unwrap();
    let restored =
        ManifoldPeerRuntimeHost::restart_from_json_with_live_broker_runtime_and_lifetime_policy(
            &raw,
            &trust,
            &id(PROVIDER_EPOCH_ID),
            &broker,
            policy,
        )
        .unwrap()
        .0;
    assert_eq!(restored.snapshot_json().unwrap(), raw);
    assert_eq!(
        restored.snapshot().broker_lease_admissions[0]
            .runtime_lease
            .expires_at_ms,
        124_000
    );
    for inflated in [124_001, OUTER_EXPIRY + 1] {
        let mut damaged = old.clone();
        damaged.broker_lease_admissions[0]
            .runtime_lease
            .expires_at_ms = inflated;
        damaged
            .media_command_runtime
            .leases
            .iter_mut()
            .find(|l| l.derivative_binding.is_some())
            .unwrap()
            .expires_at_ms = inflated;
        assert!(
            ManifoldPeerRuntimeHost::from_snapshot_with_live_broker_runtime_and_lifetime_policy(
                damaged,
                &trust,
                &id(PROVIDER_EPOCH_ID),
                &broker,
                policy
            )
            .is_err()
        );
    }
}
