//! Causal source controls, unrun preparation. Native graph facts remain modeled here.
use super::*;
use rusty_manifold_peer::*;

fn setup_policy() -> ManifoldFreshPairSetupPolicy {
    ManifoldFreshPairSetupPolicy {
        schema_id: schema_id("rusty.manifold.peer.fresh_pair_setup_policy.v2"),
        policy_id: id("policy.test.fresh-setup"),
        revision: Revision::INITIAL,
        authorization: ManifoldFreshPairSetupAuthorization::SourceBound,
        initial_status: ManifoldFreshPairSetupInitialStatusTemplate {
            schema_id: schema_id("rusty.manifold.peer.fresh_pair_setup_initial_status_template.v1"),
            trust_domain: credential("peer.alpha", "key.peer.alpha.001", 1, &key(7)).trust_domain,
            roles: vec![ManifoldPeerRole::Observer, ManifoldPeerRole::Rendezvous],
            capability_ids: vec![id("capability.test.status")],
        },
        credential_validity_ms: 300_000,
    }
}

fn setup_host(local: &str, ongoing: bool) -> ManifoldPeerRuntimeHost {
    setup_host_with_status_prefix(local, ongoing, 2)
}

fn setup_host_with_status_prefix(
    local: &str,
    ongoing: bool,
    status_count: usize,
) -> ManifoldPeerRuntimeHost {
    setup_host_with_lifetime_policy(local, ongoing, status_count, None)
}

fn setup_host_with_lifetime_policy(
    local: &str,
    ongoing: bool,
    status_count: usize,
    lifetime: Option<rusty_manifold_admission::ManifoldDevelopmentLifetimePolicy>,
) -> ManifoldPeerRuntimeHost {
    let mut policy = trust_policy();
    policy.fresh_setup_policy = Some(setup_policy());
    if let Some(selected) = &lifetime {
        policy
            .fresh_setup_policy
            .as_mut()
            .unwrap()
            .credential_validity_ms = selected.delegated_authority_horizon_ms;
    }
    policy.development_lifetime_policy = lifetime;
    policy.fresh_setup_local_peer_id = Some(id(local));
    let selection = setup_enrollment_selection();
    policy
        .trusted_key_fingerprints
        .extend(selection.keys.iter().map(|k| k.key_fingerprint.clone()));
    policy.trusted_key_fingerprints.sort();
    policy.trusted_key_fingerprints.dedup();
    policy.fresh_setup_enrollment_selection = Some(selection);
    let mut host = ManifoldPeerRuntimeHost::new_with_fresh_pair_setup(
        id("host.peer-runtime.test"),
        policy,
        id(PROVIDER_EPOCH_ID),
        media_command_runtime(),
    )
    .unwrap();
    assert!(ongoing, "fresh setup is ongoing-only");
    // Positive enrollment and accepted status both go through their real writers.
    let seeded = fixture_host();
    for (index, (peer, key_name, seed)) in [
        ("peer.alpha", "key.peer.alpha.001", 7),
        ("peer.beta", "key.peer.beta.001", 11),
    ]
    .into_iter()
    .enumerate()
    {
        let credential = credential(peer, key_name, 1, &key(seed));
        let suffix = id(&format!("request.fresh-fixture.enroll.{peer}"));
        let mut enrollment = enrollment_request(
            suffix.as_str(),
            host.snapshot.enrollment.authority_revision,
            ManifoldPeerEnrollmentAction::Enroll {
                credential: credential.clone(),
            },
        );
        enrollment.request_id = host.current_runtime_history_request_id(&suffix).unwrap();
        assert!(host.review_enrollment(&enrollment, 2_000).unwrap().applied);
        if index >= status_count {
            continue;
        }
        let mut accepted = seeded
            .snapshot
            .accepted_peers
            .peers
            .iter()
            .find(|p| p.identity.peer_id.as_str() == peer)
            .unwrap()
            .clone();
        accepted.identity.key_fingerprint =
            id(&credential
                .public_key_sha256
                .replacen("sha256:", "fingerprint.", 1));
        accepted.status.status_revision = Revision::INITIAL;
        accepted.status.observed_at_ms = 2_000;
        accepted.status.expires_at_ms = 100_000;
        let proposal_id = host
            .current_runtime_history_request_id(&id(&format!(
                "proposal.fresh-fixture.status.{peer}"
            )))
            .unwrap();
        let (_, application) = host
            .review_peer_status(
                ManifoldPeerStatusProposal {
                    schema_id: schema_id(PEER_PROPOSAL_SCHEMA),
                    proposal_id,
                    expected_authority_revision: host.snapshot.accepted_peers.authority_revision,
                    proposer_id: id(OPERATOR_ID),
                    identity: accepted.identity,
                    status: accepted.status,
                    payload_class: ManifoldPeerPayloadClass::LowRateDescriptor,
                },
                2_000,
            )
            .unwrap();
        assert!(application.applied);
    }
    host
}

fn resign(request: &mut ManifoldFreshPairSetupRequest) {
    request.context.request_id = fresh_pair_setup_transaction_id(&request.context).unwrap();
    let bytes = fresh_pair_setup_signing_bytes(&request.context).unwrap();
    request.signatures = [
        ("peer.alpha", "key.peer.alpha.001", 7),
        ("peer.beta", "key.peer.beta.001", 11),
    ]
    .iter()
    .map(|(peer, name, seed)| ManifoldFreshPairSetupSignature {
        schema_id: schema_id("rusty.manifold.peer.fresh_pair_setup_signature.v3"),
        signer_peer_id: id(peer),
        signer_key_id: id(name),
        signature_hex: encode_lower_hex(&key(*seed).sign(&bytes).to_bytes()),
    })
    .collect();
}

fn setup_request(
    alpha: &ManifoldPeerRuntimeHost,
    beta: &ManifoldPeerRuntimeHost,
    now: u64,
    suffix: &str,
) -> ManifoldFreshPairSetupRequest {
    let peers = vec![id("peer.alpha"), id("peer.beta")];
    let operation = format!("sha256:{}", "a2".repeat(32));
    let eligibility = format!("sha256:{}", "b3".repeat(32));
    let mut request = ManifoldFreshPairSetupRequest {
        schema_id: schema_id("rusty.manifold.peer.fresh_pair_setup_request.v3"),
        context: ManifoldFreshPairSetupContext {
            schema_id: schema_id("rusty.manifold.peer.fresh_pair_setup_context.v3"),
            request_id: id(suffix),
            native_setup_request_id: id("ceremony.duplex.native-fixture"),
            native_phase_id: id(suffix),
            policy: setup_policy(),
            peer_ids: peers.clone(),
            views: vec![
                alpha
                    .fresh_pair_setup_view(&peers[0], &peers, &operation, &eligibility, now)
                    .unwrap(),
                beta.fresh_pair_setup_view(&peers[1], &peers, &operation, &eligibility, now)
                    .unwrap(),
            ],
            issued_at_ms: now,
        },
        signatures: Vec::new(),
    };
    resign(&mut request);
    request
}

fn common_after(
    host: &ManifoldPeerRuntimeHost,
    now: u64,
    suffix: &str,
) -> ManifoldCommonLanReciprocalEd25519ReviewRequest {
    let mut request = common_lan_reciprocal_request(host, &key(7), &key(11));
    request.context.issued_at_ms = now;
    request.context.expires_at_ms = now + 60_000;
    request.request_id = host
        .current_signed_history_request_id(&id(&format!("request.common.{suffix}")))
        .unwrap();
    request.context.correlation_id = host
        .current_signed_history_request_id(&id(&format!("correlation.common.{suffix}")))
        .unwrap();
    request.context.initiator.device_nonce_hex = if suffix == "before" {
        "91".repeat(32)
    } else {
        "93".repeat(32)
    };
    request.context.responder.device_nonce_hex = if suffix == "before" {
        "92".repeat(32)
    } else {
        "94".repeat(32)
    };
    let bytes = common_lan_reciprocal_ed25519_context_signing_bytes(&request.context);
    let digest = common_lan_reciprocal_ed25519_context_sha256(&request.context);
    request.initiator_signature.context_sha256 = digest.clone();
    request.responder_signature.context_sha256 = digest;
    request.initiator_signature.signature_hex = encode_lower_hex(&key(7).sign(&bytes).to_bytes());
    request.responder_signature.signature_hex = encode_lower_hex(&key(11).sign(&bytes).to_bytes());
    request
}

#[test]
fn development_fresh_setup_retains_long_status_parent_and_restore_validation() {
    let policy =
        rusty_manifold_admission::ManifoldDevelopmentLifetimePolicy::source_owned_v1().clone();
    let mut alpha = setup_host_with_lifetime_policy("peer.alpha", true, 2, Some(policy.clone()));
    let mut beta = setup_host_with_lifetime_policy("peer.beta", true, 2, Some(policy.clone()));
    let mut request = setup_request(&alpha, &beta, 110_000, "ceremony.duplex.development");
    request.context.policy = alpha
        .snapshot
        .trust_policy
        .fresh_setup_policy
        .clone()
        .unwrap();
    resign(&mut request);
    for host in [&mut alpha, &mut beta] {
        let receipt = host.apply_fresh_pair_setup(&request, 110_000).unwrap();
        assert!(validate_fresh_pair_setup_receipt(&receipt).is_err());
        validate_fresh_pair_setup_receipt_with_lifetime_policy(&receipt, Some(&policy)).unwrap();
        let expiry = 110_000 + policy.delegated_authority_horizon_ms;
        assert!(host
            .snapshot
            .enrollment
            .credentials
            .iter()
            .all(|c| c.expires_at_ms == expiry));
        assert!(host
            .snapshot
            .accepted_peers
            .peers
            .iter()
            .all(|p| p.status.expires_at_ms == expiry));
        validate_snapshot(&host.snapshot).unwrap();
    }
}

#[test]
fn fresh_setup_after_expiry_updates_same_keys_and_statuses_then_ordinary_proof() {
    let mut alpha = setup_host("peer.alpha", true);
    let mut beta = setup_host("peer.beta", true);
    let before_alpha = alpha.snapshot.clone();
    let before_beta = beta.snapshot.clone();
    let request = setup_request(&alpha, &beta, 110_000, "ceremony.duplex.fresh01");
    let a = alpha.apply_fresh_pair_setup(&request, 110_000).unwrap();
    let b = beta.apply_fresh_pair_setup(&request, 110_000).unwrap();
    validate_fresh_pair_setup_receipt(&a).unwrap();
    validate_fresh_pair_setup_receipt(&b).unwrap();
    assert_eq!(
        a.prior_authority_revision,
        before_alpha.enrollment.authority_revision
    );
    assert_eq!(
        b.prior_authority_revision,
        before_beta.enrollment.authority_revision
    );
    for host in [&alpha, &beta] {
        assert!(host
            .snapshot
            .enrollment
            .credentials
            .iter()
            .all(|c| c.expires_at_ms == 410_000));
        assert!(host
            .snapshot
            .accepted_peers
            .peers
            .iter()
            .all(|p| p.status.observed_at_ms == 110_000));
        validate_snapshot(&host.snapshot).unwrap();
    }
    let ordinary = alpha
        .review_reciprocal_ed25519_v3(
            &ManifoldReciprocalEd25519ReviewRequestV3::CommonLan(common_after(
                &alpha, 110_001, "after",
            )),
            110_001,
        )
        .unwrap();
    assert!(
        matches!(ordinary, ManifoldReciprocalEd25519ReceiptV3::CommonLan(ref r) if r.accepted && r.enrollment_authority_revision == a.resulting_authority_revision)
    );
    let post = alpha.snapshot.clone();
    assert_eq!(alpha.apply_fresh_pair_setup(&request, 900_000).unwrap(), a);
    assert_eq!(
        alpha.snapshot, post,
        "historical exact retry cannot freshen state"
    );
}

#[test]
fn fresh_floor_invalidates_still_unexpired_retained_proof_without_erasing_history() {
    let mut alpha = setup_host("peer.alpha", true);
    let beta = setup_host("peer.beta", true);
    let prior = alpha
        .review_reciprocal_ed25519_v3(
            &ManifoldReciprocalEd25519ReviewRequestV3::CommonLan(common_after(
                &alpha, 3_000, "before",
            )),
            3_000,
        )
        .unwrap();
    assert!(matches!(prior, ManifoldReciprocalEd25519ReceiptV3::CommonLan(ref r) if r.accepted));
    validate_current_reciprocal_ed25519_receipt_v3(
        &alpha.snapshot.reciprocal_ed25519,
        &alpha.snapshot.enrollment,
        &prior,
        &id("peer.alpha"),
        &id("peer.beta"),
        4_000,
    )
    .unwrap();
    let request = setup_request(&alpha, &beta, 4_000, "ceremony.duplex.floor01");
    let receipt = alpha.apply_fresh_pair_setup(&request, 4_000).unwrap();
    assert!(alpha
        .snapshot
        .reciprocal_ed25519
        .accepted_receipts
        .contains(&prior));
    assert_eq!(
        validate_current_reciprocal_ed25519_receipt_v3(
            &alpha.snapshot.reciprocal_ed25519,
            &alpha.snapshot.enrollment,
            &prior,
            &id("peer.alpha"),
            &id("peer.beta"),
            4_001
        ),
        Err(ManifoldReciprocalEd25519RejectionReason::CredentialNotCurrent)
    );
    assert_eq!(
        receipt.fence.minimum_enrollment_authority_revision,
        alpha.snapshot.enrollment.authority_revision
    );
}

#[test]
fn repeated_fresh_setup_advances_floor_and_changed_retry_is_not_a_new_authorization() {
    let mut alpha = setup_host("peer.alpha", true);
    let mut beta = setup_host("peer.beta", true);
    let first = setup_request(&alpha, &beta, 110_000, "ceremony.duplex.first01");
    let first_receipt = alpha.apply_fresh_pair_setup(&first, 110_000).unwrap();
    beta.apply_fresh_pair_setup(&first, 110_000).unwrap();
    let second = setup_request(&alpha, &beta, 120_000, "ceremony.duplex.second01");
    let second_receipt = alpha.apply_fresh_pair_setup(&second, 120_000).unwrap();
    assert_eq!(second_receipt.fence.setup_epoch, 2);
    assert_eq!(
        first_receipt.resulting_authority_revision.next(),
        Some(second_receipt.resulting_authority_revision)
    );
    assert_eq!(
        alpha
            .snapshot
            .fresh_pair_setup
            .as_ref()
            .unwrap()
            .receipts
            .len(),
        2
    );
    let mut changed_retry = first.clone();
    changed_retry.context.issued_at_ms += 1;
    resign_same_identity(&mut changed_retry);
    let source = alpha.snapshot.clone();
    assert!(alpha
        .apply_fresh_pair_setup(&changed_retry, 120_001)
        .unwrap_err()
        .to_string()
        .contains("retry changed bytes"));
    assert_eq!(alpha.snapshot, source);
    validate_snapshot(&alpha.snapshot).unwrap();
}

#[test]
fn actual_accepted_media_is_a_setup_refusal_not_a_floor_cleanup_shortcut() {
    let mut alpha = setup_host("peer.alpha", true);
    let beta = setup_host("peer.beta", true);
    let request = setup_request(&alpha, &beta, 4_000, "ceremony.duplex.active01");
    let mut acceptance =
        media_acceptance_request(&alpha, "request.media.setup-active", 6, PROVIDER_EPOCH_ID);
    acceptance.request_id = alpha
        .current_runtime_history_request_id(&acceptance.request_id)
        .unwrap();
    acceptance.runtime_command_request_id = alpha
        .current_media_history_request_id(&acceptance.runtime_command_request_id)
        .unwrap();
    let command = media_accept_command(&alpha, &acceptance);
    assert!(alpha
        .review_media_session_acceptance(&acceptance, &command, 4_000)
        .unwrap()
        .accepted_session
        .is_some());
    validate_snapshot(&alpha.snapshot).unwrap();
    let source = alpha.snapshot.clone();
    let error = alpha
        .apply_fresh_pair_setup(&request, 4_001)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("cannot invalidate active media or pending route cleanup"),
        "{error}"
    );
    assert_eq!(alpha.snapshot, source);
}

#[test]
fn queued_old_context_cannot_be_accepted_after_setup() {
    let mut alpha = setup_host("peer.alpha", true);
    let beta = setup_host("peer.beta", true);
    let queued = common_after(&alpha, 4_000, "before");
    let request = setup_request(&alpha, &beta, 4_000, "ceremony.duplex.queue01");
    alpha.apply_fresh_pair_setup(&request, 4_000).unwrap();
    let before = alpha.snapshot.reciprocal_ed25519.clone();
    let result = alpha
        .review_reciprocal_ed25519_v3(
            &ManifoldReciprocalEd25519ReviewRequestV3::CommonLan(queued),
            4_001,
        )
        .unwrap();
    assert!(matches!(result, ManifoldReciprocalEd25519ReceiptV3::CommonLan(ref r) if !r.accepted));
    assert_eq!(alpha.snapshot.reciprocal_ed25519, before);
}

#[test]
fn both_signatures_and_exact_current_preimages_are_required_atomically() {
    for damage in [
        "missing",
        "signature",
        "swapped",
        "schema",
        "policy",
        "native",
        "preimage",
        "future",
    ] {
        let mut alpha = setup_host("peer.alpha", true);
        let beta = setup_host("peer.beta", true);
        let mut request = setup_request(&alpha, &beta, 110_000, "ceremony.duplex.refusal01");
        match damage {
            "missing" => {
                request.signatures.pop();
            }
            "signature" => request.signatures[1].signature_hex = "00".repeat(64),
            "swapped" => request.signatures.swap(0, 1),
            "schema" => {
                request.context.views[0].schema_id = schema_id("rusty.manifold.peer.identity.v1");
                resign(&mut request);
            }
            "policy" => {
                request.context.policy.policy_id = id("policy.foreign");
                resign(&mut request);
            }
            "native" => {
                request.context.views[0].native_eligibility_sha256 = "not-a-digest".into();
                resign(&mut request);
            }
            "preimage" => {
                request.context.views[0].prior_credentials[0].expires_at_ms -= 1;
                resign(&mut request);
            }
            "future" => {
                request.context.issued_at_ms = 110_001;
                resign(&mut request);
            }
            _ => unreachable!(),
        }
        let before = alpha.snapshot.clone();
        assert!(
            alpha.apply_fresh_pair_setup(&request, 110_000).is_err(),
            "{damage}"
        );
        assert_eq!(alpha.snapshot, before, "{damage} moved accepted state");
    }
}

#[test]
fn revoked_or_rotated_current_key_refuses_even_with_previously_valid_setup_signatures() {
    for rotate in [false, true] {
        let mut alpha = setup_host("peer.alpha", true);
        let beta = setup_host("peer.beta", true);
        let request = setup_request(&alpha, &beta, 4_000, "ceremony.duplex.key01");
        let action = if rotate {
            ManifoldPeerEnrollmentAction::Rotate {
                prior_key_id: id("key.peer.alpha.001"),
                credential: credential("peer.alpha", "key.peer.alpha.002", 2, &key(13)),
            }
        } else {
            ManifoldPeerEnrollmentAction::Revoke {
                key_id: id("key.peer.alpha.001"),
                reason_id: id("reason.test.revoked"),
            }
        };
        let mut change = enrollment_request(
            "request.setup.key-change",
            alpha.snapshot.enrollment.authority_revision,
            action,
        );
        change.issued_at_ms = 4_000;
        change.request_id = alpha
            .current_runtime_history_request_id(&change.request_id)
            .unwrap();
        assert!(alpha.review_enrollment(&change, 4_000).unwrap().applied);
        let before = alpha.snapshot.clone();
        assert!(alpha.apply_fresh_pair_setup(&request, 4_001).is_err());
        assert_eq!(alpha.snapshot, before);
    }
}

#[test]
fn selected_storage_requires_receipts_and_floor_with_exact_restore_policy() {
    let mut alpha = setup_host("peer.alpha", true);
    let beta = setup_host("peer.beta", true);
    let request = setup_request(&alpha, &beta, 110_000, "ceremony.duplex.restore01");
    alpha.apply_fresh_pair_setup(&request, 110_000).unwrap();
    let snapshot = alpha.snapshot.clone();
    let policy = snapshot.trust_policy.clone();
    let epoch = snapshot.provider_epoch_id.clone();
    validate_snapshot(&snapshot).unwrap();
    alpha.snapshot_json().unwrap();
    assert!(
        ManifoldPeerRuntimeHost::from_snapshot(snapshot.clone(), &policy, &epoch)
            .unwrap_err()
            .to_string()
            .contains("independent owner seal")
    );
    for damage in [
        "state",
        "receipts",
        "floor",
        "floor-revision",
        "receipt-signature",
        "schema",
        "policy",
    ] {
        let mut bad = snapshot.clone();
        match damage {
            "state" => bad.fresh_pair_setup = None,
            "receipts" => bad.fresh_pair_setup.as_mut().unwrap().receipts.clear(),
            "floor" => bad.reciprocal_ed25519.fresh_setup_fences.clear(),
            "floor-revision" => {
                bad.reciprocal_ed25519.fresh_setup_fences[0].minimum_enrollment_authority_revision =
                    Revision::INITIAL
            }
            "receipt-signature" => {
                bad.fresh_pair_setup.as_mut().unwrap().receipts[0]
                    .request
                    .signatures[0]
                    .signature_hex = "00".repeat(64)
            }
            "schema" => bad.schema_id = schema_id(PEER_RUNTIME_HOST_SNAPSHOT_SCHEMA),
            "policy" => {
                bad.trust_policy.fresh_setup_policy = None;
                bad.trust_policy.fresh_setup_local_peer_id = None;
            }
            _ => unreachable!(),
        }
        assert!(validate_snapshot(&bad).is_err(), "{damage}");
    }
    assert_eq!(alpha.snapshot, snapshot);
}

#[test]
fn ongoing_floor_uses_same_actual_owner_rejects_clone_and_stale_plan_and_survives_checkpoint_plan()
{
    let mut alpha = setup_host("peer.alpha", true);
    let beta = setup_host("peer.beta", true);
    let request = setup_request(&alpha, &beta, 110_000, "ceremony.duplex.owner01");
    let old_plan = alpha
        .signed_history_owner
        .as_ref()
        .unwrap()
        .plan_fresh_pair_setup_fence(
            &request,
            &alpha.snapshot.enrollment,
            &id("peer.alpha"),
            110_000,
        )
        .unwrap();
    let before = alpha.snapshot.clone();
    let mut observer = alpha.clone();
    assert!(observer.selected_fresh_pair_setup_policy().is_none());
    assert!(observer.snapshot_json().is_err());
    assert!(observer.apply_fresh_pair_setup(&request, 110_000).is_err());
    assert_eq!(alpha.snapshot, before);
    let actual_owner = &**alpha.signed_history_owner.as_ref().unwrap() as *const _;
    alpha.apply_fresh_pair_setup(&request, 110_000).unwrap();
    assert_eq!(
        &**alpha.signed_history_owner.as_ref().unwrap() as *const _,
        actual_owner
    );
    assert!(alpha
        .signed_history_owner
        .as_mut()
        .unwrap()
        .commit(old_plan)
        .is_err());
    assert_eq!(
        alpha.signed_history_owner.as_ref().unwrap().state(),
        &alpha.snapshot.reciprocal_ed25519
    );
    let ordinary = common_after(&alpha, 110_001, "after");
    let result = alpha
        .review_reciprocal_ed25519_v3(
            &ManifoldReciprocalEd25519ReviewRequestV3::CommonLan(ordinary),
            110_001,
        )
        .unwrap();
    assert!(matches!(result, ManifoldReciprocalEd25519ReceiptV3::CommonLan(ref r) if r.accepted));
    let checkpoint = alpha
        .signed_history_owner
        .as_ref()
        .unwrap()
        .plan_checkpoint(&[])
        .unwrap();
    assert_eq!(
        checkpoint.state().fresh_setup_fences,
        alpha.snapshot.reciprocal_ed25519.fresh_setup_fences
    );
    assert_eq!(
        alpha.snapshot.schema_id.as_str(),
        PEER_FRESH_SETUP_ONGOING_SNAPSHOT_SCHEMA
    );
    validate_snapshot(&alpha.snapshot).unwrap();
}

#[test]
fn remote_receipt_shape_validation_refuses_forged_result_and_status_without_minting_authority() {
    let mut alpha = setup_host("peer.alpha", true);
    let beta = setup_host("peer.beta", true);
    let request = setup_request(&alpha, &beta, 110_000, "ceremony.duplex.remote01");
    let receipt = alpha.apply_fresh_pair_setup(&request, 110_000).unwrap();
    validate_fresh_pair_setup_receipt(&receipt).unwrap();
    for kind in ["result", "fence", "status", "request", "credential"] {
        let mut bad = receipt.clone();
        match kind {
            "result" => {
                bad.resulting_authority_revision = bad.resulting_authority_revision.next().unwrap()
            }
            "fence" => bad.fence.context_sha256 = format!("sha256:{}", "ff".repeat(32)),
            "status" => bad.renewed_peers[0].status.observed_at_ms += 1,
            "request" => bad.request_id = id("request.foreign"),
            "credential" => bad.renewed_credentials[0].key_generation += 1,
            _ => unreachable!(),
        }
        assert!(validate_fresh_pair_setup_receipt(&bad).is_err(), "{kind}");
    }
}

#[test]
fn fresh_pair_floor_does_not_spread_to_unrelated_pair_or_default_zero_contract() {
    let mut fences = Vec::new();
    assert!(fresh_pair_setup_floor_allows(
        &fences,
        &[id("peer.alpha"), id("peer.beta")],
        Revision::INITIAL
    ));
    advance_fresh_pair_setup_fence(
        &mut fences,
        ManifoldPairSetupFence {
            schema_id: schema_id("rusty.manifold.peer.pair_setup_fence.v1"),
            peer_ids: vec![id("peer.alpha"), id("peer.beta")],
            setup_epoch: 1,
            minimum_enrollment_authority_revision: Revision::new(4).unwrap(),
            setup_request_id: id("request.setup.001"),
            context_sha256: format!("sha256:{}", "aa".repeat(32)),
        },
    )
    .unwrap();
    assert!(!fresh_pair_setup_floor_allows(
        &fences,
        &[id("peer.alpha"), id("peer.beta")],
        Revision::new(3).unwrap()
    ));
    assert!(fresh_pair_setup_floor_allows(
        &fences,
        &[id("peer.alpha"), id("peer.beta")],
        Revision::new(4).unwrap()
    ));
    assert!(fresh_pair_setup_floor_allows(
        &fences,
        &[id("peer.alpha"), id("peer.gamma")],
        Revision::INITIAL
    ));
}

#[test]
fn released_finite_baseline_stays_unchanged_and_cannot_select_or_apply_fresh_setup() {
    let mut finite = fixture_host();
    assert!(finite.snapshot.trust_policy.fresh_setup_policy.is_none());
    let original = finite.snapshot_json().unwrap();
    assert!(
        !original.contains("fresh_setup_policy")
            && !original.contains("fresh_pair_setup")
            && !original.contains("fresh_setup_fences")
    );
    let alpha = setup_host("peer.alpha", true);
    let beta = setup_host("peer.beta", true);
    let request = setup_request(&alpha, &beta, 110_000, "ceremony.duplex.finite-refusal");
    let before = finite.snapshot.clone();
    assert!(finite
        .apply_fresh_pair_setup(&request, 110_000)
        .unwrap_err()
        .to_string()
        .contains("actual non-cloneable ongoing-v2 owner"));
    assert_eq!(finite.snapshot, before);
    let mut policy = trust_policy();
    policy.fresh_setup_policy = Some(setup_policy());
    policy.fresh_setup_local_peer_id = Some(id("peer.alpha"));
    policy.fresh_setup_enrollment_selection = Some(setup_enrollment_selection());
    policy.trusted_key_fingerprints.extend(
        setup_enrollment_selection()
            .keys
            .iter()
            .map(|k| k.key_fingerprint.clone()),
    );
    policy.trusted_key_fingerprints.sort();
    policy.trusted_key_fingerprints.dedup();
    assert!(ManifoldPeerRuntimeHost::new(
        id("host.peer-runtime.test"),
        policy,
        id(PROVIDER_EPOCH_ID),
        media_command_runtime()
    )
    .unwrap_err()
    .to_string()
    .contains("finite constructor cannot select fresh setup"));
}

#[test]
fn actual_owner_receipt_query_preserves_old_outcome_after_later_phase() {
    let mut alpha = setup_host("peer.alpha", true);
    let mut beta = setup_host("peer.beta", true);
    let first = setup_request(&alpha, &beta, 110_000, "ceremony.duplex.query-phase01");
    assert!(alpha
        .current_fresh_pair_setup_receipt(&first.context.request_id)
        .unwrap()
        .is_none());
    let retained = alpha.apply_fresh_pair_setup(&first, 110_000).unwrap();
    beta.apply_fresh_pair_setup(&first, 110_000).unwrap();
    let second = setup_request(&alpha, &beta, 120_000, "ceremony.duplex.query-phase02");
    alpha.apply_fresh_pair_setup(&second, 120_000).unwrap();
    let before = alpha.snapshot.clone();
    assert_eq!(
        alpha
            .current_fresh_pair_setup_receipt(&first.context.request_id)
            .unwrap(),
        Some(retained)
    );
    assert_eq!(
        alpha.snapshot, before,
        "a receipt query must never refresh credentials/status/floor"
    );
    assert!(alpha
        .current_fresh_pair_setup_receipt(&id("ceremony.duplex.query-foreign"))
        .unwrap()
        .is_none());
}

#[test]
fn receipt_query_absence_does_not_erase_partial_or_complete_prime_state() {
    let alpha = setup_host("peer.alpha", true); // actual ordinary positive enrollment/status writers
    let before = alpha.snapshot.clone();
    assert!(!before.enrollment.credentials.is_empty());
    assert!(!before.accepted_peers.peers.is_empty());
    assert!(alpha
        .current_fresh_pair_setup_receipt(&id("ceremony.duplex.not-committed"))
        .unwrap()
        .is_none());
    assert_eq!(alpha.snapshot, before);
}

#[test]
fn receipt_query_requires_actual_owner_not_clone_or_legacy_finite_host() {
    let alpha = setup_host("peer.alpha", true);
    let observer = alpha.clone();
    assert!(observer
        .current_fresh_pair_setup_receipt(&id("ceremony.duplex.observer"))
        .is_err());
    let finite = fixture_host();
    assert!(finite
        .current_fresh_pair_setup_receipt(&id("ceremony.duplex.finite"))
        .is_err());
}

#[test]
fn receipt_query_rejects_damaged_retained_transaction() {
    let mut alpha = setup_host("peer.alpha", true);
    let beta = setup_host("peer.beta", true);
    let request = setup_request(&alpha, &beta, 110_000, "ceremony.duplex.query-damage");
    alpha.apply_fresh_pair_setup(&request, 110_000).unwrap();
    alpha.snapshot.fresh_pair_setup.as_mut().unwrap().receipts[0].context_sha256 =
        format!("sha256:{}", "ff".repeat(32));
    assert!(alpha
        .current_fresh_pair_setup_receipt(&request.context.request_id)
        .is_err());
}

#[test]
fn receipt_query_rejects_removed_receipt_behind_retained_floor() {
    let mut alpha = setup_host("peer.alpha", true);
    let beta = setup_host("peer.beta", true);
    let request = setup_request(&alpha, &beta, 110_000, "ceremony.duplex.query-omitted");
    alpha.apply_fresh_pair_setup(&request, 110_000).unwrap();
    alpha
        .snapshot
        .fresh_pair_setup
        .as_mut()
        .unwrap()
        .receipts
        .clear();
    assert!(alpha
        .current_fresh_pair_setup_receipt(&request.context.request_id)
        .is_err());
}

// Authored UNRUN actual-owner/writer controls for the explicit v2 contract.
#[test]
fn source_bound_unchanged_signed_preimages_survive_elapsed_audit_time() {
    let mut alpha = setup_host("peer.alpha", true);
    let mut beta = setup_host("peer.beta", true);
    let request = setup_request(&alpha, &beta, 4_000, "ceremony.duplex.source-bound-delayed");
    let a = alpha.apply_fresh_pair_setup(&request, 1_000_000).unwrap();
    let b = beta.apply_fresh_pair_setup(&request, 1_000_001).unwrap();
    assert_eq!(a.request.context.issued_at_ms, 4_000);
    assert!(a
        .renewed_credentials
        .iter()
        .all(|c| c.expires_at_ms == 1_300_000));
    assert!(b
        .renewed_credentials
        .iter()
        .all(|c| c.expires_at_ms == 1_300_001));
    validate_fresh_pair_setup_receipt(&a).unwrap();
    validate_fresh_pair_setup_receipt(&b).unwrap();
    validate_snapshot(&alpha.snapshot).unwrap();
    validate_snapshot(&beta.snapshot).unwrap();
}

#[test]
fn source_bound_same_clock_next_phase_advances_real_revision_and_floor_without_fake_margin() {
    let mut alpha = setup_host("peer.alpha", true);
    let mut beta = setup_host("peer.beta", true);
    let first = setup_request(&alpha, &beta, 4_000, "ceremony.duplex.same-clock-one");
    let a = alpha.apply_fresh_pair_setup(&first, 4_000).unwrap();
    beta.apply_fresh_pair_setup(&first, 4_000).unwrap();
    let second = setup_request(&alpha, &beta, 4_000, "ceremony.duplex.same-clock-two");
    let b = alpha.apply_fresh_pair_setup(&second, 4_000).unwrap();
    assert_eq!(a.renewed_credentials, b.renewed_credentials);
    assert_eq!(
        a.resulting_authority_revision.next(),
        Some(b.resulting_authority_revision)
    );
    assert_eq!(b.fence.setup_epoch, a.fence.setup_epoch + 1);
    assert_eq!(
        alpha
            .snapshot
            .fresh_pair_setup
            .as_ref()
            .unwrap()
            .receipts
            .len(),
        2
    );
    validate_fresh_pair_setup_receipt(&b).unwrap();
    validate_snapshot(&alpha.snapshot).unwrap();
}

#[test]
fn source_bound_missing_initial_status_uses_actual_keys_template_and_real_status_writers() {
    for count in [0, 1] {
        let mut alpha = setup_host_with_status_prefix("peer.alpha", true, count);
        let beta = setup_host_with_status_prefix("peer.beta", true, 0);
        let existing = alpha.snapshot.accepted_peers.peers.clone();
        let request = setup_request(
            &alpha,
            &beta,
            110_000,
            &format!("ceremony.duplex.missing-status-{count}"),
        );
        assert_eq!(request.context.views[0].accepted_peers, existing);
        let receipt = alpha.apply_fresh_pair_setup(&request, 110_000).unwrap();
        assert_eq!(receipt.status_receipts.len(), 2);
        assert!(receipt.status_receipts.iter().all(|r| r.applied));
        for old in existing {
            let current = alpha
                .snapshot
                .accepted_peers
                .peers
                .iter()
                .find(|p| p.identity.peer_id == old.identity.peer_id)
                .unwrap();
            assert_eq!(current.identity, old.identity);
            assert_eq!(current.status.capability_ids, old.status.capability_ids);
            assert_eq!(
                old.status.status_revision.next(),
                Some(current.status.status_revision)
            );
        }
        for peer in alpha.snapshot.accepted_peers.peers.iter().filter(|p| {
            !request.context.views[0]
                .accepted_peers
                .iter()
                .any(|old| old.identity.peer_id == p.identity.peer_id)
        }) {
            assert_eq!(peer.status.status_revision, Revision::INITIAL);
            assert_eq!(
                peer.identity.roles,
                request.context.policy.initial_status.roles
            );
            assert_eq!(
                peer.status.capability_ids,
                request.context.policy.initial_status.capability_ids
            );
        }
        validate_fresh_pair_setup_receipt(&receipt).unwrap();
        validate_snapshot(&alpha.snapshot).unwrap();
    }
}

#[test]
fn source_bound_template_substitution_cannot_authorize_caller_roles_even_with_two_signatures() {
    let mut alpha = setup_host_with_status_prefix("peer.alpha", true, 0);
    let beta = setup_host_with_status_prefix("peer.beta", true, 0);
    let mut request = setup_request(
        &alpha,
        &beta,
        110_000,
        "ceremony.duplex.template-substitution",
    );
    request
        .context
        .policy
        .initial_status
        .roles
        .push(ManifoldPeerRole::BrokerConsumer);
    resign(&mut request);
    let before = alpha.snapshot.clone();
    assert!(alpha
        .apply_fresh_pair_setup(&request, 110_000)
        .unwrap_err()
        .to_string()
        .contains("policy differs"));
    assert_eq!(alpha.snapshot, before);
}

#[test]
fn source_bound_existing_not_ready_status_is_not_repaired_as_missing() {
    let mut alpha = setup_host("peer.alpha", true);
    let beta = setup_host("peer.beta", true);
    let old = alpha.snapshot.accepted_peers.peers[0].clone();
    let mut status = old.status;
    status.status_revision = status.status_revision.next().unwrap();
    status.availability = ManifoldPeerAvailability::Unavailable;
    status.observed_at_ms = 3_000;
    status.expires_at_ms = 50_000;
    let proposal = ManifoldPeerStatusProposal {
        schema_id: schema_id(PEER_PROPOSAL_SCHEMA),
        proposal_id: alpha
            .current_runtime_history_request_id(&id("proposal.fresh-fixture.not-ready"))
            .unwrap(),
        expected_authority_revision: alpha.snapshot.accepted_peers.authority_revision,
        proposer_id: id(OPERATOR_ID),
        identity: old.identity,
        status,
        payload_class: ManifoldPeerPayloadClass::LowRateDescriptor,
    };
    assert!(alpha.review_peer_status(proposal, 3_000).unwrap().1.applied);
    let before = alpha.snapshot.clone();
    let peers = vec![id("peer.alpha"), id("peer.beta")];
    let hash = format!("sha256:{}", "aa".repeat(32));
    assert!(alpha
        .fresh_pair_setup_view(&peers[0], &peers, &hash, &hash, 4_000)
        .is_err());
    assert_eq!(alpha.snapshot, before);
    let _ = beta;
}

#[test]
fn source_bound_missing_enrollment_still_refuses_without_reprime_or_fabricated_peer() {
    let mut policy = trust_policy();
    policy.fresh_setup_policy = Some(setup_policy());
    policy.fresh_setup_local_peer_id = Some(id("peer.alpha"));
    policy.fresh_setup_enrollment_selection = Some(setup_enrollment_selection());
    policy.trusted_key_fingerprints.extend(
        setup_enrollment_selection()
            .keys
            .iter()
            .map(|k| k.key_fingerprint.clone()),
    );
    policy.trusted_key_fingerprints.sort();
    policy.trusted_key_fingerprints.dedup();
    let alpha = ManifoldPeerRuntimeHost::new_with_fresh_pair_setup(
        id("host.peer-runtime.empty"),
        policy,
        id(PROVIDER_EPOCH_ID),
        media_command_runtime(),
    )
    .unwrap();
    let before = alpha.snapshot.clone();
    let peers = vec![id("peer.alpha"), id("peer.beta")];
    let hash = format!("sha256:{}", "aa".repeat(32));
    assert!(alpha
        .fresh_pair_setup_view(&peers[0], &peers, &hash, &hash, 4_000)
        .is_err());
    assert_eq!(alpha.snapshot, before);
}

#[test]
fn source_bound_expiry_fields_and_legacy_boolean_authorization_are_closed_schema_damage() {
    let alpha = setup_host("peer.alpha", true);
    let beta = setup_host("peer.beta", true);
    let request = setup_request(&alpha, &beta, 4_000, "ceremony.duplex.closed-source-bound");
    for field in ["authorization_expires_at_ms", "credential_expires_at_ms"] {
        let mut value = serde_json::to_value(&request).unwrap();
        value["context"][field] = serde_json::json!(9_999_999);
        assert!(serde_json::from_value::<ManifoldFreshPairSetupRequest>(value).is_err());
    }
    let mut value = serde_json::to_value(&request).unwrap();
    value["context"]["policy"]["authorization"] = serde_json::json!(true);
    assert!(serde_json::from_value::<ManifoldFreshPairSetupRequest>(value).is_err());
    let mut old = request;
    old.context.schema_id = schema_id("rusty.manifold.peer.fresh_pair_setup_context.v1");
    resign(&mut old);
    assert!(verify_fresh_pair_setup_request(&old).is_err());
}

#[test]
fn source_bound_ordinary_status_mutation_invalidates_prior_signed_view_atomically() {
    let mut alpha = setup_host("peer.alpha", true);
    let beta = setup_host("peer.beta", true);
    let request = setup_request(&alpha, &beta, 4_000, "ceremony.duplex.status-preimage");
    let old = alpha.snapshot.accepted_peers.peers[0].clone();
    let mut status = old.status;
    status.status_revision = status.status_revision.next().unwrap();
    status.observed_at_ms = 4_000;
    status.expires_at_ms = 50_000;
    let proposal = ManifoldPeerStatusProposal {
        schema_id: schema_id(PEER_PROPOSAL_SCHEMA),
        proposal_id: alpha
            .current_runtime_history_request_id(&id("proposal.fresh-fixture.changed-ready"))
            .unwrap(),
        expected_authority_revision: alpha.snapshot.accepted_peers.authority_revision,
        proposer_id: id(OPERATOR_ID),
        identity: old.identity,
        status,
        payload_class: ManifoldPeerPayloadClass::LowRateDescriptor,
    };
    assert!(alpha.review_peer_status(proposal, 4_000).unwrap().1.applied);
    let before = alpha.snapshot.clone();
    assert!(alpha.apply_fresh_pair_setup(&request, 1_000_000).is_err());
    assert_eq!(alpha.snapshot, before);
}

// M04 additional causal controls. All use actual selected owner constructors,
// actual ordinary enrollment writer and actual signed phase transaction.
fn setup_enrollment_selection() -> ManifoldFreshPairSetupEnrollmentSelection {
    ManifoldFreshPairSetupEnrollmentSelection {
        schema_id: schema_id("rusty.manifold.peer.fresh_setup_enrollment_selection.v1"),
        operator_id: id(OPERATOR_ID),
        keys: [
            ("peer.alpha", "key.peer.alpha.001", 7),
            ("peer.beta", "key.peer.beta.001", 11),
        ]
        .iter()
        .map(|(peer, name, seed)| {
            let c = credential(peer, name, 1, &key(*seed));
            ManifoldFreshPairSetupEnrollmentKey {
                schema_id: schema_id("rusty.manifold.peer.fresh_setup_enrollment_key.v1"),
                peer_id: c.peer_id,
                credential_id: c.credential_id,
                trust_domain: c.trust_domain,
                key_id: c.key_id,
                key_generation: c.key_generation,
                algorithm: c.algorithm,
                public_key_hex: c.public_key_hex,
                key_fingerprint: id(&c.public_key_sha256.replacen("sha256:", "fingerprint.", 1)),
                public_key_sha256: c.public_key_sha256,
            }
        })
        .collect(),
    }
}

fn prime_partial_host(local: &str, count: usize) -> ManifoldPeerRuntimeHost {
    let mut policy = trust_policy();
    policy.fresh_setup_policy = Some(setup_policy());
    policy.fresh_setup_local_peer_id = Some(id(local));
    let selection = setup_enrollment_selection();
    policy
        .trusted_key_fingerprints
        .extend(selection.keys.iter().map(|k| k.key_fingerprint.clone()));
    policy.trusted_key_fingerprints.sort();
    policy.trusted_key_fingerprints.dedup();
    policy.fresh_setup_enrollment_selection = Some(selection.clone());
    let mut host = ManifoldPeerRuntimeHost::new_with_fresh_pair_setup(
        id("host.peer-runtime.test"),
        policy,
        id(PROVIDER_EPOCH_ID),
        media_command_runtime(),
    )
    .unwrap();
    for k in selection.keys.iter().take(count) {
        let suffix = id(&format!("request.partial-prime.{}", k.peer_id.as_str()));
        let request = ManifoldPeerEnrollmentRequest {
            schema_id: schema_id(PEER_ENROLLMENT_REQUEST_SCHEMA),
            request_id: host.current_runtime_history_request_id(&suffix).unwrap(),
            expected_authority_revision: host.snapshot.enrollment.authority_revision,
            operator_id: selection.operator_id.clone(),
            issued_at_ms: 2_000,
            action: ManifoldPeerEnrollmentAction::Enroll {
                credential: k.credential(2_000, 302_000),
            },
        };
        assert!(host.review_enrollment(&request, 2_000).unwrap().applied);
    }
    host
}

fn resign_phase(request: &mut ManifoldFreshPhasePrepareRequest) {
    request.context.request_id = fresh_phase_prepare_transaction_id(&request.context).unwrap();
    let bytes = fresh_phase_prepare_signing_bytes(&request.context).unwrap();
    request.signatures = [
        ("peer.alpha", "key.peer.alpha.001", 7),
        ("peer.beta", "key.peer.beta.001", 11),
    ]
    .iter()
    .map(|(peer, name, seed)| ManifoldFreshPairSetupSignature {
        schema_id: schema_id("rusty.manifold.peer.fresh_pair_setup_signature.v3"),
        signer_peer_id: id(peer),
        signer_key_id: id(name),
        signature_hex: encode_lower_hex(&key(*seed).sign(&bytes).to_bytes()),
    })
    .collect();
}

fn phase_request(
    a: &ManifoldPeerRuntimeHost,
    b: &ManifoldPeerRuntimeHost,
    suffix: &str,
) -> ManifoldFreshPhasePrepareRequest {
    phase_request_at(a, b, suffix, 4_000)
}
fn phase_request_at(
    a: &ManifoldPeerRuntimeHost,
    b: &ManifoldPeerRuntimeHost,
    suffix: &str,
    now: u64,
) -> ManifoldFreshPhasePrepareRequest {
    let selection = setup_enrollment_selection();
    let operation = format!("sha256:{}", "a1".repeat(32));
    let eligibility = format!("sha256:{}", "b2".repeat(32));
    let views = [a, b]
        .iter()
        .map(|host| {
            let missing = selection
                .keys
                .iter()
                .filter(|k| {
                    !host
                        .snapshot
                        .enrollment
                        .credentials
                        .iter()
                        .any(|c| c.peer_id == k.peer_id)
                })
                .map(|k| k.peer_id.clone())
                .collect::<Vec<_>>();
            host.fresh_phase_prepare_view(&missing, &operation, &eligibility, now)
                .unwrap()
        })
        .collect();
    let mut r = ManifoldFreshPhasePrepareRequest {
        schema_id: schema_id("rusty.manifold.peer.fresh_phase_prepare_request.v2"),
        context: ManifoldFreshPhasePrepareContext {
            schema_id: schema_id("rusty.manifold.peer.fresh_phase_prepare_context.v2"),
            request_id: id(suffix),
            setup_request_id: id("ceremony.duplex.native-original"),
            native_phase_id: id(suffix),
            policy: setup_policy(),
            selection: selection.clone(),
            peer_ids: selection.keys.iter().map(|k| k.peer_id.clone()).collect(),
            views,
            issued_at_ms: now,
        },
        signatures: Vec::new(),
    };
    resign_phase(&mut r);
    r
}

#[test]
fn phase_prepare_real_partial_enrollments_after_delay_then_ordinary_fresh_setup() {
    let mut a = prime_partial_host("peer.alpha", 1);
    let mut b = prime_partial_host("peer.beta", 0);
    let retained = a
        .snapshot
        .fresh_pair_setup
        .as_ref()
        .unwrap()
        .prime_enrollments[0]
        .clone();
    let request = phase_request(&a, &b, "phase.prepare.delayed");
    let ra = a.apply_fresh_phase_prepare(&request, 900_000).unwrap();
    let rb = b.apply_fresh_phase_prepare(&request, 900_000).unwrap();
    assert_eq!(ra.enrollments.len(), 1);
    assert_eq!(rb.enrollments.len(), 2);
    assert_eq!(
        a.current_fresh_prime_enrollment_receipt(&retained.request.request_id)
            .unwrap(),
        Some(retained)
    );
    for entry in ra.enrollments.iter().chain(&rb.enrollments) {
        assert_eq!(entry.applied_at_ms, 900_000);
        assert_eq!(entry.request.issued_at_ms, 900_000);
        let ManifoldPeerEnrollmentAction::Enroll { credential } = &entry.request.action else {
            panic!("new actual Enroll required")
        };
        assert_eq!(credential.expires_at_ms, 1_200_000);
    }
    let fresh = setup_request(&a, &b, 900_000, "ceremony.duplex.after-prepare");
    assert!(a.apply_fresh_pair_setup(&fresh, 900_000).is_ok());
    assert!(b.apply_fresh_pair_setup(&fresh, 900_000).is_ok());
}

#[test]
fn phase_prepare_asymmetric_complete_side_is_explicit_signed_no_enrollment() {
    let mut a = prime_partial_host("peer.alpha", 2);
    let mut b = prime_partial_host("peer.beta", 1);
    let request = phase_request(&a, &b, "phase.prepare.asymmetric");
    let prior = a.snapshot.enrollment.clone();
    assert!(a
        .apply_fresh_phase_prepare(&request, 5_000)
        .unwrap()
        .enrollments
        .is_empty());
    assert_eq!(a.snapshot.enrollment, prior);
    assert_eq!(
        b.apply_fresh_phase_prepare(&request, 5_000)
            .unwrap()
            .enrollments
            .len(),
        1
    );
}

#[test]
fn interrupted_return_lookup_is_actual_record_and_none_is_not_missing_permission() {
    let a = prime_partial_host("peer.alpha", 1);
    let b = prime_partial_host("peer.beta", 0);
    let entry = a
        .snapshot
        .fresh_pair_setup
        .as_ref()
        .unwrap()
        .prime_enrollments[0]
        .clone();
    assert_eq!(
        a.current_fresh_prime_enrollment_receipt(&entry.request.request_id)
            .unwrap(),
        Some(entry.clone())
    );
    assert!(a
        .current_fresh_prime_enrollment_receipt(&id("request.never-entered"))
        .unwrap()
        .is_none());
    assert!(a
        .fresh_phase_prepare_view(
            &[entry.receipt.peer_id.unwrap()],
            &format!("sha256:{}", "a1".repeat(32)),
            &format!("sha256:{}", "b2".repeat(32)),
            4_000
        )
        .is_err());
    assert!(a
        .clone()
        .current_fresh_prime_enrollment_receipt(&entry.request.request_id)
        .is_err());
    assert!(
        phase_request(&a, &b, "phase.prepare.lookup").context.views[0]
            .prime_enrollments
            .len()
            == 1
    );
}

#[test]
fn phase_prepare_key_substitution_bad_signature_and_changed_source_are_atomic() {
    let mut a = prime_partial_host("peer.alpha", 1);
    let b = prime_partial_host("peer.beta", 0);
    let request = phase_request(&a, &b, "phase.prepare.refusals");
    let before = a.snapshot.clone();
    let mut bad = request.clone();
    bad.signatures[1].signature_hex = "00".repeat(64);
    assert!(a.apply_fresh_phase_prepare(&bad, 5_000).is_err());
    assert_eq!(a.snapshot, before);
    let mut bad = request.clone();
    bad.context.selection.keys[1].key_id = id("key.substituted");
    resign_phase(&mut bad);
    assert!(a.apply_fresh_phase_prepare(&bad, 5_000).is_err());
    assert_eq!(a.snapshot, before);
    let mut bad = request;
    bad.context.views[0].source_snapshot_sha256 = format!("sha256:{}", "ff".repeat(32));
    resign_phase(&mut bad);
    assert!(a.apply_fresh_phase_prepare(&bad, 5_000).is_err());
    assert_eq!(a.snapshot, before);
}

#[test]
fn phase_prepare_retry_returns_old_receipt_and_changed_retry_refuses() {
    let mut a = prime_partial_host("peer.alpha", 1);
    let b = prime_partial_host("peer.beta", 0);
    let request = phase_request(&a, &b, "phase.prepare.retry");
    let receipt = a.apply_fresh_phase_prepare(&request, 5_000).unwrap();
    let after = a.snapshot.clone();
    assert_eq!(
        a.apply_fresh_phase_prepare(&request, 9_000_000).unwrap(),
        receipt
    );
    assert_eq!(a.snapshot, after);
    let mut changed = request;
    changed.context.issued_at_ms += 1;
    resign_phase_same_identity(&mut changed);
    assert!(a.apply_fresh_phase_prepare(&changed, 9_000_000).is_err());
    assert_eq!(a.snapshot, after);
}

#[test]
fn phase_prepare_ledger_source_byte_damage_and_receipt_omission_refuse() {
    let a = prime_partial_host("peer.alpha", 1);
    let mut damaged = a.snapshot.clone();
    damaged.fresh_pair_setup.as_mut().unwrap().prime_enrollments[0].source_after
        ["event_sequence"] = serde_json::json!(33);
    assert!(validate_snapshot(&damaged).is_err());
    let mut damaged = a.snapshot.clone();
    damaged
        .fresh_pair_setup
        .as_mut()
        .unwrap()
        .prime_enrollments
        .clear();
    assert!(validate_snapshot(&damaged).is_err());
}

#[test]
fn selected_prime_preserves_ordinary_request_age_and_does_not_commit_a_failed_stage() {
    let mut a = prime_partial_host("peer.alpha", 0);
    let selection = setup_enrollment_selection();
    let request = ManifoldPeerEnrollmentRequest {
        schema_id: schema_id(PEER_ENROLLMENT_REQUEST_SCHEMA),
        request_id: a
            .current_runtime_history_request_id(&id("request.stale.ordinary"))
            .unwrap(),
        expected_authority_revision: a.snapshot.enrollment.authority_revision,
        operator_id: selection.operator_id,
        issued_at_ms: 1_000,
        action: ManifoldPeerEnrollmentAction::Enroll {
            credential: selection.keys[0].credential(1_000, 900_000),
        },
    };
    let result = a.review_enrollment(&request, 600_000).unwrap();
    assert!(!result.applied);
    assert_eq!(
        result.rejection_reason,
        Some(ManifoldPeerEnrollmentRejectionReason::StaleRequest)
    );
    assert!(a
        .snapshot
        .fresh_pair_setup
        .as_ref()
        .unwrap()
        .prime_enrollments
        .is_empty());
    let before = a.snapshot.clone();
    let mut changed = request;
    changed.request_id = a
        .current_runtime_history_request_id(&id("request.wrong-key.ordinary"))
        .unwrap();
    let ManifoldPeerEnrollmentAction::Enroll { credential } = &mut changed.action else {
        unreachable!()
    };
    credential.key_id = id("key.arbitrary");
    assert!(a.review_enrollment(&changed, 600_000).is_err());
    assert_eq!(a.snapshot, before);
}

#[test]
fn phase_prepare_interrupted_return_getter_is_exact_actual_owner_and_historical() {
    let mut a = prime_partial_host("peer.alpha", 1);
    let b = prime_partial_host("peer.beta", 0);
    let request = phase_request(&a, &b, "phase.prepare.getter");
    assert!(a
        .current_fresh_phase_prepare_receipt(&request.context.request_id)
        .unwrap()
        .is_none());
    let receipt = a.apply_fresh_phase_prepare(&request, 5_000).unwrap();
    let source = a.snapshot.clone();
    assert_eq!(
        a.current_fresh_phase_prepare_receipt(&request.context.request_id)
            .unwrap(),
        Some(receipt)
    );
    assert_eq!(a.snapshot, source);
    assert!(a
        .clone()
        .current_fresh_phase_prepare_receipt(&request.context.request_id)
        .is_err());
    assert!(a
        .current_fresh_phase_prepare_receipt(&id("phase.prepare.foreign"))
        .unwrap()
        .is_none());
    let mut damaged = a.snapshot.clone();
    damaged
        .fresh_pair_setup
        .as_mut()
        .unwrap()
        .phase_preparations[0]
        .applied_at_ms += 1;
    assert!(validate_snapshot(&damaged).is_err());
}

// Archive06 controls: actual M owner/plan/commit/getters; app custody signature
// source and physical native/Java journals are explicitly modeled here. Their
// real fsync/readback/old-phase bridge needs separate owning Java controls.
fn resign_same_identity(request: &mut ManifoldFreshPairSetupRequest) {
    let bytes = fresh_pair_setup_signing_bytes(&request.context).unwrap();
    for (signature, seed) in request.signatures.iter_mut().zip([7, 11]) {
        signature.signature_hex = encode_lower_hex(&key(seed).sign(&bytes).to_bytes());
    }
}
fn resign_phase_same_identity(request: &mut ManifoldFreshPhasePrepareRequest) {
    let bytes = fresh_phase_prepare_signing_bytes(&request.context).unwrap();
    for (signature, seed) in request.signatures.iter_mut().zip([7, 11]) {
        signature.signature_hex = encode_lower_hex(&key(seed).sign(&bytes).to_bytes());
    }
}
fn archive_operation(
    receipt: &ManifoldFreshPairSetupReceipt,
) -> ManifoldFreshArchiveOperationBinding {
    ManifoldFreshArchiveOperationBinding {
        schema_id: "rusty.quest.embedded_duplex.fresh_phase_operation_binding.v1".into(),
        native_request_id: receipt.request.context.native_setup_request_id.clone(),
        phase_request_id: receipt.request.context.native_phase_id.clone(),
        manifold_transaction_id: receipt.request_id.clone(),
        kind: ManifoldFreshArchiveOperationKind::PairSetup,
        context_sha256: receipt.context_sha256.clone(),
        app_process_generation: 1,
        app_record_sha256: "ab".repeat(32),
        native_executor_generation: 1,
        config_sha256: "cd".repeat(32),
        original_binding: if receipt.local_peer_id.as_str() == "peer.alpha" {
            ManifoldFreshArchiveOriginalBinding::Operator {
                original_id: "12".repeat(16),
            }
        } else {
            ManifoldFreshArchiveOriginalBinding::IncomingFreshSetup {
                native_request_id: receipt.request.context.native_setup_request_id.clone(),
            }
        },
    }
}
fn modeled_custody_ack(body: &ManifoldFreshHistoryArchiveBody) -> ManifoldFreshHistoryCustodyAck {
    let raw = fresh_history_canonical(body).unwrap();
    let hash = fresh_history_body_sha256(&raw);
    let prior = body.prior_cursor.as_ref().map(|p| p.history_sha256.clone());
    let context = ManifoldFreshHistoryCustodyContext {
        schema_id: schema_id("rusty.manifold.peer.fresh_history_durable_context.v1"),
        archive_ordinal: body.archive_ordinal,
        archive_body_sha256: hash.clone(),
        prior_history_sha256: prior.clone(),
        history_sha256: fresh_history_chain_sha256(prior.as_deref(), body.archive_ordinal, &hash)
            .unwrap(),
        checkpoint_sha256: fresh_history_body_checkpoint_sha256(body, &hash).unwrap(),
        host_id: body.host_id.clone(),
        provider_epoch_id: body.provider_epoch_id.clone(),
        local_peer_id: body.local_peer_id.clone(),
        source_snapshot_sha256: body.source_snapshot_sha256.clone(),
        operation_binding: body.operation_binding.clone(),
        storage_identity: format!("modeled.app.private.archive.{}", body.archive_ordinal),
        signer_key_id: if body.local_peer_id.as_str() == "peer.alpha" {
            id("key.peer.alpha.001")
        } else {
            id("key.peer.beta.001")
        },
    };
    let seed = if body.local_peer_id.as_str() == "peer.alpha" {
        7
    } else {
        11
    };
    let signature_hex = encode_lower_hex(
        &key(seed)
            .sign(&fresh_history_custody_signing_bytes(&context).unwrap())
            .to_bytes(),
    );
    ManifoldFreshHistoryCustodyAck {
        schema_id: schema_id("rusty.manifold.peer.fresh_history_durable_ack.v1"),
        context,
        signature_hex,
    }
}
fn apply_fixture_setup(
    a: &mut ManifoldPeerRuntimeHost,
    b: &mut ManifoldPeerRuntimeHost,
    now: u64,
    suffix: &str,
) -> ManifoldFreshPairSetupReceipt {
    let request = setup_request(a, b, now, suffix);
    let receipt = a.apply_fresh_pair_setup(&request, now).unwrap();
    b.apply_fresh_pair_setup(&request, now).unwrap();
    receipt
}
#[test]
fn archive_actual_owner_compacts_receipts_audits_ids_and_preserves_floor_counters() {
    let mut a = setup_host("peer.alpha", true);
    let mut b = setup_host("peer.beta", true);
    let receipt = apply_fixture_setup(&mut a, &mut b, 4_000, "native.phase.archive01");
    let before = a.snapshot.clone();
    let plan = a
        .plan_fresh_history_archive(archive_operation(&receipt))
        .unwrap();
    let body = plan.body().clone();
    assert_eq!(
        plan.canonical_body(),
        fresh_history_canonical(&body).unwrap()
    );
    let ack = modeled_custody_ack(&body);
    let cursor = plan.commit(ack.clone()).unwrap();
    assert_eq!(cursor.total, 1);
    assert_eq!(cursor.setup_receipts, 1);
    let state = a.snapshot.fresh_pair_setup.as_ref().unwrap();
    assert!(state.receipts.is_empty());
    assert!(state.phase_preparations.is_empty());
    assert_eq!(
        a.snapshot.reciprocal_ed25519.fresh_setup_fences,
        before.reciprocal_ed25519.fresh_setup_fences
    );
    assert_eq!(
        a.snapshot.enrollment.authority_revision,
        before.enrollment.authority_revision
    );
    assert_eq!(
        a.snapshot.accepted_peers.authority_revision,
        before.accepted_peers.authority_revision
    );
    assert_eq!(a.snapshot.event_sequence, before.event_sequence);
    assert_eq!(state.prime_enrollments.len(), 2);
    assert!(!a
        .snapshot
        .audit_events
        .iter()
        .any(|e| e.source_id == receipt.local_request_id));
    assert!(
        a.current_fresh_pair_setup_receipt(&receipt.request_id)
            .is_err(),
        "archived history must not become None/noeffect"
    );
    let result = a
        .begin_fresh_history_lookup(&receipt.request_id, &body, &ack)
        .unwrap()
        .finish()
        .unwrap();
    assert_eq!(result, ManifoldFreshHistoricalReceipt::Setup(receipt));
    validate_snapshot(&a.snapshot).unwrap();
}
#[test]
fn archive_failure_drop_changed_ack_and_unselected_signature_do_not_mutate_actual_owner() {
    let mut a = setup_host("peer.alpha", true);
    let mut b = setup_host("peer.beta", true);
    let receipt = apply_fixture_setup(&mut a, &mut b, 4_000, "native.phase.archive-refusal");
    let before = a.snapshot.clone();
    {
        let plan = a
            .plan_fresh_history_archive(archive_operation(&receipt))
            .unwrap();
        assert!(!plan.canonical_body().is_empty());
    }
    assert_eq!(
        a.snapshot, before,
        "storage refusal/decline drops a plan, not history"
    );
    let plan = a
        .plan_fresh_history_archive(archive_operation(&receipt))
        .unwrap();
    let mut ack = modeled_custody_ack(plan.body());
    ack.context.storage_identity.push_str(".changed");
    assert!(plan.commit(ack).is_err());
    assert_eq!(a.snapshot, before);
    let plan = a
        .plan_fresh_history_archive(archive_operation(&receipt))
        .unwrap();
    let mut ack = modeled_custody_ack(plan.body());
    ack.signature_hex = "00".repeat(64);
    assert!(plan.commit(ack).is_err());
    assert_eq!(a.snapshot, before);
    assert!(a
        .clone()
        .plan_fresh_history_archive(archive_operation(&receipt))
        .is_err());
}
#[test]
fn archive_lost_custody_reply_can_recover_exact_body_without_double_compaction() {
    let mut a = setup_host("peer.alpha", true);
    let mut b = setup_host("peer.beta", true);
    let receipt = apply_fixture_setup(&mut a, &mut b, 4_000, "native.phase.lost-archive-reply");
    let before = a.snapshot.clone();
    let (raw, ack) = {
        let plan = a
            .plan_fresh_history_archive(archive_operation(&receipt))
            .unwrap();
        (
            plan.canonical_body().to_vec(),
            modeled_custody_ack(plan.body()),
        )
    };
    assert_eq!(a.snapshot, before);
    let plan = a
        .plan_fresh_history_archive(archive_operation(&receipt))
        .unwrap();
    assert_eq!(plan.canonical_body(), raw);
    plan.commit(ack).unwrap();
    let after = a.snapshot.clone();
    assert!(a
        .plan_fresh_history_archive(archive_operation(&receipt))
        .is_err());
    assert_eq!(a.snapshot, after);
}
#[test]
fn archive_current_cursor_damage_and_old_ack_reuse_refuse() {
    let mut a = setup_host("peer.alpha", true);
    let mut b = setup_host("peer.beta", true);
    let r1 = apply_fixture_setup(&mut a, &mut b, 4_000, "native.phase.archive-old");
    let p = a
        .plan_fresh_history_archive(archive_operation(&r1))
        .unwrap();
    let ack1 = modeled_custody_ack(p.body());
    p.commit(ack1.clone()).unwrap();
    let r2 = apply_fixture_setup(&mut a, &mut b, 5_000, "native.phase.archive-new");
    let before = a.snapshot.clone();
    let p = a
        .plan_fresh_history_archive(archive_operation(&r2))
        .unwrap();
    assert!(p.commit(ack1).is_err());
    assert_eq!(a.snapshot, before);
    let mut damaged = a.snapshot.clone();
    damaged
        .fresh_pair_setup
        .as_mut()
        .unwrap()
        .archive
        .as_mut()
        .unwrap()
        .credential_checkpoint[0]
        .expires_at_ms += 1;
    assert!(validate_snapshot(&damaged).is_err());
}
#[test]
fn archive_requires_actual_inactive_graph_and_latest_owned_phase() {
    let mut a = setup_host("peer.alpha", true);
    let mut b = setup_host("peer.beta", true);
    let first = apply_fixture_setup(&mut a, &mut b, 4_000, "native.phase.old-operation");
    let _second = apply_fixture_setup(&mut a, &mut b, 5_000, "native.phase.latest-operation");
    let before = a.snapshot.clone();
    assert!(a
        .plan_fresh_history_archive(archive_operation(&first))
        .is_err());
    assert_eq!(a.snapshot, before);
    let latest = a
        .snapshot
        .fresh_pair_setup
        .as_ref()
        .unwrap()
        .receipts
        .last()
        .unwrap()
        .clone();
    let mut acceptance =
        media_acceptance_request(&a, "request.media.archive-active", 6, PROVIDER_EPOCH_ID);
    acceptance.request_id = a
        .current_runtime_history_request_id(&acceptance.request_id)
        .unwrap();
    acceptance.runtime_command_request_id = a
        .current_media_history_request_id(&acceptance.runtime_command_request_id)
        .unwrap();
    let command = media_accept_command(&a, &acceptance);
    assert!(a
        .review_media_session_acceptance(&acceptance, &command, 5_000)
        .unwrap()
        .accepted_session
        .is_some());
    let before = a.snapshot.clone();
    assert!(a
        .plan_fresh_history_archive(archive_operation(&latest))
        .is_err());
    assert_eq!(a.snapshot, before);
}
#[test]
fn archive_streaming_historical_lookup_requires_exact_full_chain_and_requested_body() {
    let mut a = setup_host("peer.alpha", true);
    let mut b = setup_host("peer.beta", true);
    let r1 = apply_fixture_setup(&mut a, &mut b, 4_000, "native.phase.chain-first");
    let p = a
        .plan_fresh_history_archive(archive_operation(&r1))
        .unwrap();
    let body1 = p.body().clone();
    let ack1 = modeled_custody_ack(&body1);
    p.commit(ack1.clone()).unwrap();
    let r2 = apply_fixture_setup(&mut a, &mut b, 5_000, "native.phase.chain-second");
    let p = a
        .plan_fresh_history_archive(archive_operation(&r2))
        .unwrap();
    let body2 = p.body().clone();
    let ack2 = modeled_custody_ack(&body2);
    p.commit(ack2.clone()).unwrap();
    assert!(a
        .begin_fresh_history_lookup(&r1.request_id, &body1, &ack1)
        .unwrap()
        .finish()
        .is_err());
    let mut lookup = a
        .begin_fresh_history_lookup(&r1.request_id, &body1, &ack1)
        .unwrap();
    assert!(lookup.push_ack(&ack1).is_err());
    lookup.push_ack(&ack2).unwrap();
    assert_eq!(
        lookup.finish().unwrap(),
        ManifoldFreshHistoricalReceipt::Setup(r1.clone())
    );
    assert!(a
        .begin_fresh_history_lookup(&r1.request_id, &body2, &ack2)
        .is_err());
    let mut damaged = body1;
    damaged.receipts[0].applied_at_ms += 1;
    assert!(a
        .begin_fresh_history_lookup(&r1.request_id, &damaged, &ack1)
        .is_err());
}
#[test]
fn archive_repeated_real_transactions_have_constant_live_array_shape_and_no_replay_reset() {
    let mut a = setup_host("peer.alpha", true);
    let mut b = setup_host("peer.beta", true);
    let mut first = None;
    for n in 0..12 {
        let request = setup_request(&a, &b, 4_000 + n, &format!("native.phase.repeat{n}"));
        if first.is_none() {
            first = Some(request.clone());
        }
        let r = a.apply_fresh_pair_setup(&request, 4_000 + n).unwrap();
        let br = b.apply_fresh_pair_setup(&request, 4_000 + n).unwrap();
        let p = a.plan_fresh_history_archive(archive_operation(&r)).unwrap();
        let ack = modeled_custody_ack(p.body());
        let cursor = p.commit(ack).unwrap();
        assert_eq!(cursor.total, n + 1);
        assert_eq!(cursor.setup_receipts, n + 1);
        let state = a.snapshot.fresh_pair_setup.as_ref().unwrap();
        assert!(state.receipts.is_empty());
        assert!(state.phase_preparations.is_empty());
        assert_eq!(state.prime_enrollments.len(), 2);
        assert!(a.snapshot.audit_events.len() <= 8);
        assert!(a.snapshot.enrollment.applied_request_ids.len() <= 2);
        let p = b
            .plan_fresh_history_archive(archive_operation(&br))
            .unwrap();
        let ack = modeled_custody_ack(p.body());
        p.commit(ack).unwrap();
        assert!(b
            .snapshot
            .fresh_pair_setup
            .as_ref()
            .unwrap()
            .receipts
            .is_empty());
        assert!(b.snapshot.audit_events.len() <= 8);
    }
    let before = a.snapshot.clone();
    assert!(a
        .apply_fresh_pair_setup(&first.unwrap(), 9_000_000)
        .is_err());
    assert_eq!(a.snapshot, before);
    assert_eq!(
        a.snapshot.reciprocal_ed25519.fresh_setup_fences[0].setup_epoch,
        12
    );
}
#[test]
fn content_id_acyclic_preimage_excludes_self_and_refuses_changed_source_or_reused_id() {
    let mut a = setup_host("peer.alpha", true);
    let b = setup_host("peer.beta", true);
    let request = setup_request(&a, &b, 4_000, "native.phase.id-control");
    let expected = request.context.request_id.clone();
    let mut c = request.context.clone();
    c.request_id = id("ignored.placeholder");
    assert_eq!(fresh_pair_setup_transaction_id(&c).unwrap(), expected);
    c.native_phase_id = id("native.phase.changed");
    assert_ne!(fresh_pair_setup_transaction_id(&c).unwrap(), expected);
    let mut changed = request;
    changed.context.views[0].source_snapshot_sha256 = format!("sha256:{}", "cc".repeat(32));
    let bytes = fresh_pair_setup_signing_bytes(&changed.context).unwrap();
    for (signature, seed) in changed.signatures.iter_mut().zip([7, 11]) {
        signature.signature_hex = encode_lower_hex(&key(seed).sign(&bytes).to_bytes());
    }
    let before = a.snapshot.clone();
    assert_eq!(
        verify_fresh_pair_setup_request(&changed),
        Err("fresh setup content-bound transaction ID differs")
    );
    assert!(a.apply_fresh_pair_setup(&changed, 4_000).is_err());
    assert_eq!(a.snapshot, before);
}
#[test]
fn preparation_content_id_excludes_self_binds_native_phase_and_rejects_reused_id() {
    let mut a = prime_partial_host("peer.alpha", 1);
    let b = prime_partial_host("peer.beta", 0);
    let request = phase_request(&a, &b, "native.phase.preparation-id");
    let expected = request.context.request_id.clone();
    let mut context = request.context.clone();
    context.request_id = id("ignored.preparation.placeholder");
    assert_eq!(
        fresh_phase_prepare_transaction_id(&context).unwrap(),
        expected
    );
    context.native_phase_id = id("native.phase.different-preparation");
    assert_ne!(
        fresh_phase_prepare_transaction_id(&context).unwrap(),
        expected
    );
    let mut changed = request;
    changed.context.views[0].source_snapshot_sha256 = format!("sha256:{}", "ee".repeat(32));
    resign_phase_same_identity(&mut changed);
    assert_eq!(
        verify_fresh_phase_prepare_request(&changed),
        Err("phase prepare content-bound transaction ID differs")
    );
    let before = a.snapshot.clone();
    assert!(a.apply_fresh_phase_prepare(&changed, 5_000).is_err());
    assert_eq!(a.snapshot, before);
}
#[test]
fn archive_parent_checkpoint_does_not_fake_media_adoption_or_reset_phase_sequence() {
    let mut a = prime_partial_host("peer.alpha", 1);
    let b = prime_partial_host("peer.beta", 0);
    let request = phase_request(&a, &b, "native.phase.preparation-archive");
    let r = a.apply_fresh_phase_prepare(&request, 5_000).unwrap();
    let op = ManifoldFreshArchiveOperationBinding {
        schema_id: "rusty.quest.embedded_duplex.fresh_phase_operation_binding.v1".into(),
        native_request_id: request.context.setup_request_id.clone(),
        phase_request_id: request.context.native_phase_id.clone(),
        manifold_transaction_id: request.context.request_id.clone(),
        kind: ManifoldFreshArchiveOperationKind::EnrollmentPreparation,
        context_sha256: r.context_sha256.clone(),
        app_process_generation: 1,
        app_record_sha256: "ab".repeat(32),
        native_executor_generation: 1,
        config_sha256: "cd".repeat(32),
        original_binding: ManifoldFreshArchiveOriginalBinding::IncomingFreshSetup {
            native_request_id: request.context.setup_request_id.clone(),
        },
    };
    let p = a.plan_fresh_history_archive(op).unwrap();
    let body = p.body().clone();
    let ack = modeled_custody_ack(&body);
    p.commit(ack.clone()).unwrap();
    let parent = a.snapshot.runtime_history_checkpoint.as_ref().unwrap();
    assert_eq!(
        parent.schema_id.as_str(),
        "rusty.manifold.peer.runtime_history_checkpoint.v2"
    );
    assert!(parent.adopted_media_checkpoint_sha256.is_none());
    assert_eq!(
        a.snapshot
            .fresh_pair_setup
            .as_ref()
            .unwrap()
            .archive
            .as_ref()
            .unwrap()
            .phase_receipts,
        1
    );
    assert!(a
        .current_fresh_phase_prepare_receipt(&request.context.request_id)
        .is_err());
    assert_eq!(
        a.begin_fresh_history_lookup(&request.context.request_id, &body, &ack)
            .unwrap()
            .finish()
            .unwrap(),
        ManifoldFreshHistoricalReceipt::Preparation(r)
    );
    let next = phase_request_at(&a, &b, "native.phase.preparation-after-archive", 6_000);
    let next_receipt = a.apply_fresh_phase_prepare(&next, 6_000).unwrap();
    assert_eq!(next_receipt.prepare_sequence, 2);
    assert!(next_receipt.enrollments.is_empty());
    assert!(matches!(
        a.fresh_history_receipt_location(
            &next.context.request_id,
            ManifoldFreshArchiveOperationKind::EnrollmentPreparation
        )
        .unwrap(),
        ManifoldFreshReceiptLocation::Live { .. }
    ));
    assert!(matches!(
        a.fresh_history_receipt_location(
            &request.context.request_id,
            ManifoldFreshArchiveOperationKind::EnrollmentPreparation
        )
        .unwrap(),
        ManifoldFreshReceiptLocation::NotRetained {
            archive_cursor: Some(_)
        }
    ));
}
#[test]
fn archive_canonical_vectors_match_fixed_java_rules_and_refuse_noninteger_or_nonascii_keys() {
    let value = serde_json::json!({"z":"a/é›ª\n","a":[null,true,-3,9223372036854775807i64]});
    assert_eq!(
        String::from_utf8(fresh_history_canonical(&value).unwrap()).unwrap(),
        "{\"a\":[null,true,-3,9223372036854775807],\"z\":\"a/é›ª\\n\"}"
    );
    assert!(fresh_history_canonical(&serde_json::json!({"a":1.25})).is_err());
    assert!(fresh_history_canonical(&serde_json::json!({"é›ª":1})).is_err());
    assert!(fresh_history_canonical(&serde_json::json!({"a":18446744073709551615u64})).is_err());
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../rusty-manifold-peer/src/fresh_history_canonical_vectors.json"
    ))
    .unwrap();
    for row in vectors["vectors"].as_array().unwrap() {
        let raw = fresh_history_canonical(&row["value"]).unwrap();
        assert_eq!(
            std::str::from_utf8(&raw).unwrap(),
            row["canonical_utf8"].as_str().unwrap()
        );
        assert_eq!(
            fresh_history_body_sha256(&raw),
            format!("sha256:{}", row["canonical_sha256"].as_str().unwrap())
        );
        assert_eq!(
            fresh_history_digest(
                "rusty.manifold.peer.fresh_history_archive_source.v1",
                &row["value"]
            )
            .unwrap(),
            row["archive_source_sha256"].as_str().unwrap()
        );
    }
}
