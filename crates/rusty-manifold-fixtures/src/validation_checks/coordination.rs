use super::*;

struct CoordinationFixture {
    check_id: &'static str,
    plan_path: &'static str,
    messages_path: &'static str,
    scorecard_path: &'static str,
    evidence: &'static str,
}

const VALID_COORDINATION_FIXTURES: &[CoordinationFixture] = &[
    CoordinationFixture {
        check_id: "validation.check.coordination_q2q_lan",
        plan_path: "fixtures/coordination/remote-camera-q2q-lan-plan.json",
        messages_path: "fixtures/coordination/remote-camera-q2q-lan-messages.json",
        scorecard_path: "fixtures/coordination/remote-camera-q2q-lan-scorecard.json",
        evidence: "Quest-to-Quest LAN coordination gates receivers before sender start",
    },
    CoordinationFixture {
        check_id: "validation.check.coordination_quest_phone_lan",
        plan_path: "fixtures/coordination/remote-camera-quest-phone-lan-plan.json",
        messages_path: "fixtures/coordination/remote-camera-quest-phone-lan-messages.json",
        scorecard_path: "fixtures/coordination/remote-camera-quest-phone-lan-scorecard.json",
        evidence: "Quest-to-phone LAN coordination uses the same Manifold timing gates",
    },
    CoordinationFixture {
        check_id: "validation.check.coordination_remote_relay_two_way",
        plan_path: "fixtures/coordination/remote-camera-remote-relay-two-way-plan.json",
        messages_path: "fixtures/coordination/remote-camera-remote-relay-two-way-messages.json",
        scorecard_path: "fixtures/coordination/remote-camera-remote-relay-two-way-scorecard.json",
        evidence:
            "remote relay two-way coordination keeps relay status out of media/control payloads",
    },
];

struct DamagedCoordinationFixture {
    check_id: &'static str,
    path: &'static str,
    evidence: &'static str,
}

const DAMAGED_COORDINATION_FIXTURES: &[DamagedCoordinationFixture] = &[
    DamagedCoordinationFixture {
        check_id: "validation.check.damaged_coordination_sender_before_receiver",
        path: "fixtures/damaged/coordination-sender-before-receiver.json",
        evidence: "sender start before receiver readiness is rejected",
    },
    DamagedCoordinationFixture {
        check_id: "validation.check.damaged_coordination_peer_gossip_authorizes_sender",
        path: "fixtures/damaged/coordination-peer-gossip-authorizes-sender.json",
        evidence: "advisory peer gossip cannot satisfy command-authorizing gates",
    },
    DamagedCoordinationFixture {
        check_id: "validation.check.damaged_coordination_high_rate_payload",
        path: "fixtures/damaged/coordination-high-rate-payload.json",
        evidence: "coordination messages cannot carry high-rate media payloads",
    },
];

pub(super) fn push_coordination_checks(
    repo_root: &Path,
    checks: &mut Vec<ValidationCheckReport>,
) -> Result<(), CliError> {
    for fixture in VALID_COORDINATION_FIXTURES {
        push_result(
            checks,
            fixture.check_id,
            coordination_scorecard_matches_fixture(
                repo_root,
                fixture.plan_path,
                fixture.messages_path,
                fixture.scorecard_path,
            ),
            fixture.evidence,
        );
    }

    for fixture in DAMAGED_COORDINATION_FIXTURES {
        push_damaged(
            checks,
            fixture.check_id,
            expected_rejection(repo_root, fixture.path)?,
            damaged_coordination_rejection(repo_root, fixture.path),
            fixture.evidence,
        );
    }

    Ok(())
}

fn coordination_scorecard_matches_fixture(
    repo_root: &Path,
    plan_path: &str,
    messages_path: &str,
    scorecard_path: &str,
) -> Result<(), CliError> {
    let scorecard =
        simulate_coordination_session(repo_root, Path::new(plan_path), Path::new(messages_path))?;
    let expected = read_model::<ManifoldCoordinationScorecard>(repo_root.join(scorecard_path))?;
    if scorecard == expected {
        Ok(())
    } else {
        Err(CliError::ValidationFailed(format!(
            "coordination scorecard fixture mismatch for {scorecard_path}"
        )))
    }
}

fn damaged_coordination_rejection(repo_root: &Path, damaged_path: &str) -> Result<(), String> {
    let fixture = read_model::<DamagedCoordinationSession>(repo_root.join(damaged_path))
        .map_err(|error| error.to_string())?;
    let plan = read_model::<ManifoldCoordinationSessionPlan>(repo_root.join(&fixture.plan_path))
        .map_err(|error| error.to_string())?;
    fixture
        .message_log
        .session_id
        .eq(&plan.session_id)
        .then_some(())
        .ok_or_else(|| "session_mismatch".to_owned())?;
    plan.simulate_message_log(&fixture.message_log)
        .map(|_| ())
        .map_err(|error| error.rejection_code().to_owned())
}

#[derive(serde::Deserialize)]
struct DamagedCoordinationSession {
    #[allow(dead_code)]
    expected_rejection: String,
    plan_path: String,
    message_log: ManifoldCoordinationMessageLog,
}
