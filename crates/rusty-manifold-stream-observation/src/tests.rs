use super::*;
use std::fs;
use std::path::Path;

fn id(value: &str) -> DottedId {
    DottedId::new(value).unwrap()
}

fn observation() -> ManifoldStreamObservation {
    ManifoldStreamObservation {
        schema_id: schema(OBSERVATION_SCHEMA),
        descriptor_type: id("lsl.stream-info"),
        channel_format: id("float32"),
        channel_count: 8,
        nominal_rate_millihz: Some(100_000),
        native_descriptor_sha256: Some(format!("sha256:{}", "ab".repeat(32))),
    }
}

fn proposal(host: &ManifoldStreamObservationAuthorityHost) -> ManifoldStreamObservationProposal {
    let observation = observation();
    ManifoldStreamObservationProposal {
        schema_id: schema(PROPOSAL_SCHEMA),
        proposal_id: id("proposal.alpha.1"),
        proposer_id: id("adapter.rusty-lsl"),
        source_id: id("source.alpha"),
        stream_id: id("stream.alpha"),
        content_sha256: observation_content_sha256(&observation),
        observed_at_ms: 900,
        expires_at_ms: 2_000,
        expected_authority_revision: host.snapshot().accepted_state.authority_revision,
        observation,
    }
}

fn policy() -> ManifoldStreamObservationReviewPolicy {
    ManifoldStreamObservationReviewPolicy {
        schema_id: schema(POLICY_SCHEMA),
        policy_id: id("policy.stream-observation.default"),
        allowed_bindings: vec![ManifoldStreamObservationBinding {
            proposer_id: id("adapter.rusty-lsl"),
            source_id: id("source.alpha"),
            stream_id: id("stream.alpha"),
        }],
    }
}

#[test]
fn review_is_non_mutating_and_apply_advances_exactly_once() {
    let mut host = ManifoldStreamObservationAuthorityHost::new();
    let before = host.snapshot_json().unwrap();
    let proposal = proposal(&host);
    let decision = host.review(&policy(), &proposal, 1_000);
    assert_eq!(host.snapshot_json().unwrap(), before);
    assert_eq!(
        decision.outcome,
        ManifoldStreamObservationReviewOutcome::Accepted
    );

    let receipt = host.apply(&policy(), &proposal, &decision, 1_000);
    assert!(receipt.applied);
    assert_eq!(host.snapshot().accepted_state.authority_revision.get(), 2);
    let after = host.snapshot_json().unwrap();
    let duplicate = host.apply(&policy(), &proposal, &decision, 1_000);
    assert!(!duplicate.applied);
    assert_eq!(
        duplicate.rejection.unwrap().reason,
        ManifoldStreamObservationRejectionReason::DuplicateApplication
    );
    assert_eq!(host.snapshot_json().unwrap(), after);
}

#[test]
fn stale_expired_digest_and_identity_damage_leave_state_byte_equal() {
    type ProposalDamage = Box<dyn Fn(&mut ManifoldStreamObservationProposal)>;
    let cases: Vec<ProposalDamage> = vec![
        Box::new(|value| value.expected_authority_revision = Revision::new(2).unwrap()),
        Box::new(|value| value.expires_at_ms = 1_000),
        Box::new(|value| value.content_sha256 = format!("sha256:{}", "00".repeat(32))),
        Box::new(|value| value.proposer_id = id("adapter.substituted")),
        Box::new(|value| value.source_id = id("source.substituted")),
        Box::new(|value| value.stream_id = id("stream.substituted")),
    ];
    for damage in cases {
        let mut host = ManifoldStreamObservationAuthorityHost::new();
        let before = host.snapshot_json().unwrap();
        let mut proposal = proposal(&host);
        damage(&mut proposal);
        let decision = host.review(&policy(), &proposal, 1_000);
        let receipt = host.apply(&policy(), &proposal, &decision, 1_000);
        assert!(!receipt.applied);
        assert_eq!(host.snapshot_json().unwrap(), before);
    }
}

#[test]
fn proposal_and_decision_substitution_fail_closed() {
    let mut host = ManifoldStreamObservationAuthorityHost::new();
    let proposal = proposal(&host);
    let mut decision = host.review(&policy(), &proposal, 1_000);
    let before = host.snapshot_json().unwrap();
    decision.proposal_sha256 = format!("sha256:{}", "11".repeat(32));
    let receipt = host.apply(&policy(), &proposal, &decision, 1_000);
    assert_eq!(
        receipt.rejection.unwrap().reason,
        ManifoldStreamObservationRejectionReason::DecisionMismatch
    );
    assert_eq!(host.snapshot_json().unwrap(), before);
}

#[test]
fn post_review_proposal_and_same_id_policy_substitution_fail_closed() {
    let mut host = ManifoldStreamObservationAuthorityHost::new();
    let proposal = proposal(&host);
    let policy = policy();
    let decision = host.review(&policy, &proposal, 1_000);
    let before = host.snapshot_json().unwrap();

    let mut changed_proposal = proposal.clone();
    changed_proposal.observation.channel_count = 9;
    changed_proposal.content_sha256 = observation_content_sha256(&changed_proposal.observation);
    let receipt = host.apply(&policy, &changed_proposal, &decision, 1_000);
    assert_eq!(
        receipt.rejection.unwrap().reason,
        ManifoldStreamObservationRejectionReason::DecisionMismatch
    );
    assert_eq!(host.snapshot_json().unwrap(), before);

    let mut changed_policy = policy.clone();
    changed_policy
        .allowed_bindings
        .push(ManifoldStreamObservationBinding {
            proposer_id: id("adapter.other"),
            source_id: id("source.other"),
            stream_id: id("stream.other"),
        });
    let receipt = host.apply(&changed_policy, &proposal, &decision, 1_000);
    assert_eq!(receipt.reviewed_policy_sha256, policy_sha256(&policy));
    assert_eq!(
        receipt.application_policy_sha256,
        policy_sha256(&changed_policy)
    );
    assert_ne!(
        receipt.reviewed_policy_sha256,
        receipt.application_policy_sha256
    );
    assert_eq!(
        receipt.rejection.unwrap().reason,
        ManifoldStreamObservationRejectionReason::DecisionMismatch
    );
    assert_eq!(host.snapshot_json().unwrap(), before);
}

#[test]
fn artifact_ids_distinguish_material_attempts_and_repeat_identical_inputs() {
    let mut host = ManifoldStreamObservationAuthorityHost::new();
    let proposal = proposal(&host);
    let accepted = host.review(&policy(), &proposal, 1_000);
    let identical = host.review(&policy(), &proposal, 1_000);
    assert_eq!(accepted.decision_id, identical.decision_id);
    assert_eq!(
        accepted.audit_event.event_id,
        identical.audit_event.event_id
    );

    let expired = host.review(&policy(), &proposal, 2_000);
    assert_ne!(accepted.decision_id, expired.decision_id);
    assert_ne!(accepted.audit_event.event_id, expired.audit_event.event_id);

    let applied = host.apply(&policy(), &proposal, &accepted, 1_000);
    let duplicate = host.apply(&policy(), &proposal, &accepted, 1_001);
    assert_ne!(applied.receipt_id, duplicate.receipt_id);
    assert_ne!(applied.audit_event.event_id, duplicate.audit_event.event_id);
}

#[test]
fn intervening_application_makes_an_older_decision_stale() {
    let mut host = ManifoldStreamObservationAuthorityHost::new();
    let first = proposal(&host);
    let first_decision = host.review(&policy(), &first, 1_000);
    let mut second = first.clone();
    second.proposal_id = id("proposal.alpha.2");
    let second_decision = host.review(&policy(), &second, 1_000);
    assert!(
        host.apply(&policy(), &first, &first_decision, 1_000)
            .applied
    );
    let before = host.snapshot_json().unwrap();
    let receipt = host.apply(&policy(), &second, &second_decision, 1_000);
    assert!(!receipt.applied);
    assert_eq!(host.snapshot_json().unwrap(), before);
}

#[test]
fn restart_preserves_state_replay_audit_and_deterministic_bytes() {
    let mut host = ManifoldStreamObservationAuthorityHost::new();
    let proposal = proposal(&host);
    let decision = host.review(&policy(), &proposal, 1_000);
    assert!(host.apply(&policy(), &proposal, &decision, 1_000).applied);
    let bytes = host.snapshot_json().unwrap();
    let restarted = ManifoldStreamObservationAuthorityHost::restart_from_json(&bytes).unwrap();
    assert_eq!(restarted.snapshot_json().unwrap(), bytes);
    assert_eq!(restarted.snapshot().audit_events.len(), 1);
    assert_eq!(restarted.snapshot().applied_proposal_ids.len(), 1);
}

#[test]
fn damaged_snapshot_replay_audit_and_stream_correlation_rejects() {
    let mut host = ManifoldStreamObservationAuthorityHost::new();
    let proposal = proposal(&host);
    let decision = host.review(&policy(), &proposal, 1_000);
    assert!(host.apply(&policy(), &proposal, &decision, 1_000).applied);
    let snapshot = host.snapshot().clone();

    let mut cases = Vec::new();
    let mut wrong_id = snapshot.clone();
    wrong_id.applied_proposal_ids[0] = id("proposal.substituted");
    cases.push(wrong_id);
    let mut wrong_digest = snapshot.clone();
    wrong_digest.applied_proposal_sha256[0] = format!("sha256:{}", "00".repeat(32));
    cases.push(wrong_digest);
    let mut duplicate_audit_id = snapshot.clone();
    duplicate_audit_id
        .audit_events
        .push(duplicate_audit_id.audit_events[0].clone());
    duplicate_audit_id.accepted_state.authority_revision = Revision::new(3).unwrap();
    cases.push(duplicate_audit_id);
    let mut damaged_stream = snapshot;
    damaged_stream.accepted_state.streams[0]
        .observation
        .channel_count = 9;
    damaged_stream.accepted_state.streams[0].content_sha256 =
        observation_content_sha256(&damaged_stream.accepted_state.streams[0].observation);
    cases.push(damaged_stream);

    for damaged in cases {
        let json = serde_json::to_string(&damaged).unwrap();
        assert!(ManifoldStreamObservationAuthorityHost::restart_from_json(&json).is_err());
    }
}

#[test]
fn conformance_rejects_wrong_schema_and_correlation_damaged_snapshot() {
    let host = ManifoldStreamObservationAuthorityHost::new();
    let mut case = ManifoldStreamObservationConformanceCase {
        schema_id: schema(CONFORMANCE_SCHEMA),
        snapshot: host.snapshot().clone(),
        policy: policy(),
        proposal: proposal(&host),
        now_ms: 1_000,
    };
    assert!(run_conformance_case(&case).is_ok());
    case.schema_id = schema("rusty.manifold.stream.wrong_case.v1");
    assert!(run_conformance_case(&case).is_err());

    let mut applied_host = ManifoldStreamObservationAuthorityHost::new();
    let applied_proposal = proposal(&applied_host);
    let decision = applied_host.review(&policy(), &applied_proposal, 1_000);
    assert!(
        applied_host
            .apply(&policy(), &applied_proposal, &decision, 1_000)
            .applied
    );
    case.schema_id = schema(CONFORMANCE_SCHEMA);
    case.snapshot = applied_host.snapshot().clone();
    case.snapshot.applied_proposal_ids[0] = id("proposal.correlation.damage");
    assert!(run_conformance_case(&case).is_err());
}

#[test]
fn snapshot_rejects_tampered_unique_application_event_id() {
    let mut host = ManifoldStreamObservationAuthorityHost::new();
    let proposal = proposal(&host);
    let decision = host.review(&policy(), &proposal, 1_000);
    assert!(host.apply(&policy(), &proposal, &decision, 1_000).applied);
    let mut snapshot = host.snapshot().clone();
    snapshot.audit_events[0].event_id = id("audit.stream-observation.application.unique-tamper");
    let json = serde_json::to_string(&snapshot).unwrap();
    assert!(ManifoldStreamObservationAuthorityHost::restart_from_json(&json).is_err());
}

#[test]
fn restart_rejects_tampered_older_event_after_same_stream_overwrite() {
    let mut host = ManifoldStreamObservationAuthorityHost::new();
    let first = proposal(&host);
    let first_decision = host.review(&policy(), &first, 1_000);
    assert!(
        host.apply(&policy(), &first, &first_decision, 1_000)
            .applied
    );

    let mut second = first.clone();
    second.proposal_id = id("proposal.alpha.2");
    second.expected_authority_revision = Revision::new(2).unwrap();
    second.observed_at_ms = 1_100;
    second.expires_at_ms = 2_100;
    let second_decision = host.review(&policy(), &second, 1_200);
    assert!(
        host.apply(&policy(), &second, &second_decision, 1_200)
            .applied
    );

    let mut snapshot = host.snapshot().clone();
    snapshot.audit_events[0].proposer_id = id("adapter.historical-tamper");
    snapshot.audit_events[0].content_sha256 = format!("sha256:{}", "22".repeat(32));
    let json = serde_json::to_string(&snapshot).unwrap();
    assert!(ManifoldStreamObservationAuthorityHost::restart_from_json(&json).is_err());
}

#[test]
fn receipt_id_changes_with_explicit_carried_identity() {
    let first_host = ManifoldStreamObservationAuthorityHost::new();
    let first = proposal(&first_host);
    let first_decision = first_host.review(&policy(), &first, 1_000);
    let mut first_apply_host = first_host.clone();
    let first_receipt = first_apply_host.apply(&policy(), &first, &first_decision, 1_000);

    let second_host = ManifoldStreamObservationAuthorityHost::new();
    let mut second = proposal(&second_host);
    second.source_id = id("source.beta");
    let mut second_policy = policy();
    second_policy.allowed_bindings[0].source_id = second.source_id.clone();
    let second_decision = second_host.review(&second_policy, &second, 1_000);
    let mut second_apply_host = second_host;
    let second_receipt = second_apply_host.apply(&second_policy, &second, &second_decision, 1_000);
    assert!(first_receipt.applied && second_receipt.applied);
    assert_ne!(first_receipt.source_id, second_receipt.source_id);
    assert_ne!(first_receipt.receipt_id, second_receipt.receipt_id);
}

#[test]
fn forbidden_effect_fields_are_structurally_rejected() {
    let host = ManifoldStreamObservationAuthorityHost::new();
    let proposal = proposal(&host);
    let case = ManifoldStreamObservationConformanceCase {
        schema_id: schema(CONFORMANCE_SCHEMA),
        snapshot: host.snapshot().clone(),
        policy: policy(),
        proposal,
        now_ms: 1_000,
    };
    let baseline: ManifoldStreamObservationConformanceCase =
        serde_json::from_value(serde_json::to_value(&case).unwrap()).unwrap();
    assert!(run_conformance_case(&baseline).is_ok());
    let mut value = serde_json::to_value(case).unwrap();
    for field in [
        "control",
        "command",
        "accepted_authority_revision",
        "accepted_state",
        "samples",
        "chunks",
        "route",
        "endpoint",
        "endpoints",
        "permission",
        "permissions",
        "media",
        "product_lock",
        "platform_lock",
    ] {
        value["proposal"][field] = serde_json::json!({"forbidden": true});
        assert!(
            serde_json::from_value::<ManifoldStreamObservationConformanceCase>(value.clone())
                .is_err()
        );
        value["proposal"].as_object_mut().unwrap().remove(field);
    }
    for field in ["samples", "chunks", "media", "route", "permissions"] {
        value["proposal"]["observation"][field] = serde_json::json!([]);
        assert!(
            serde_json::from_value::<ManifoldStreamObservationConformanceCase>(value.clone())
                .is_err()
        );
        value["proposal"]["observation"]
            .as_object_mut()
            .unwrap()
            .remove(field);
    }
}

#[test]
fn committed_conformance_fixtures_match_and_control_is_the_only_damage() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for (input, expected) in [
        (
            "fixtures/stream-observation/synthetic-conformance-case.json",
            "fixtures/stream-observation/synthetic-accepted-conformance-result.json",
        ),
        (
            "fixtures/stream-observation/synthetic-expired-conformance-case.json",
            "fixtures/stream-observation/synthetic-rejected-conformance-result.json",
        ),
    ] {
        let case: ManifoldStreamObservationConformanceCase =
            serde_json::from_str(&fs::read_to_string(root.join(input)).unwrap()).unwrap();
        let actual = serde_json::to_value(run_conformance_case(&case).unwrap()).unwrap();
        let expected: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(root.join(expected)).unwrap()).unwrap();
        assert_eq!(actual, expected);
    }

    let mut damaged: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(
            root.join("fixtures/damaged/stream-observation-forbidden-control.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(
        serde_json::from_value::<ManifoldStreamObservationConformanceCase>(damaged.clone())
            .is_err()
    );
    damaged["proposal"]
        .as_object_mut()
        .unwrap()
        .remove("control");
    let repaired: ManifoldStreamObservationConformanceCase =
        serde_json::from_value(damaged).unwrap();
    assert!(run_conformance_case(&repaired).is_ok());
}
