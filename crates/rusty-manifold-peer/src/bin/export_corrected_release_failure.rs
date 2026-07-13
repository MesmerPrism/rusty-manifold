//! Executes corrected-release peer authority transitions and exports the exact
//! typed state/receipt evidence. No phase fact is synthesized by a shell
//! adapter; the PowerShell wrapper only binds source/run metadata and hashes.

use std::error::Error;
use std::fs;
use std::path::PathBuf;

use ed25519_dalek::{Signer, SigningKey};
use rusty_manifold_model::{DottedId, Revision, SchemaId};
use rusty_manifold_peer::{
    rendezvous_signing_bytes, review_and_apply_peer_enrollment, review_and_apply_signed_rendezvous,
    ManifoldPeerCredentialAlgorithm, ManifoldPeerCredentialRecord, ManifoldPeerCredentialStatus,
    ManifoldPeerEnrollmentAction, ManifoldPeerEnrollmentReceipt, ManifoldPeerEnrollmentRequest,
    ManifoldPeerEnrollmentState, ManifoldRendezvousAuthorityState, ManifoldRendezvousReceipt,
    ManifoldRendezvousRejectionReason, ManifoldRendezvousReviewRequest, ManifoldRendezvousRole,
    ManifoldSignedRendezvousEvidence, PEER_CREDENTIAL_SCHEMA, PEER_ENROLLMENT_REQUEST_SCHEMA,
    PRODUCT_WIFI_DIRECT_TOPOLOGY_CONTRACT, RENDEZVOUS_REVIEW_REQUEST_SCHEMA,
    SIGNED_RENDEZVOUS_EVIDENCE_SCHEMA,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

const EXPORT_SCHEMA: &str = "rusty.manifold.corrected_release.failure_transition_evidence.v1";
const PHASE_SCHEMA: &str = "rusty.manifold.corrected_release.failure_transition_phase.v1";
const OPERATOR_ID: &str = "operator.peer.enrollment";

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct FailureTransitionEvidence {
    #[serde(rename = "$schema")]
    schema_id: String,
    criterion_id: String,
    test_id: String,
    before: FailureTransitionPhase,
    failure: FailureTransitionPhase,
    recovery: FailureTransitionPhase,
    facts: FailureTransitionFacts,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct FailureTransitionPhase {
    #[serde(rename = "$schema")]
    schema_id: String,
    phase: &'static str,
    observed_state: &'static str,
    transition_complete: bool,
    authority_revision: Revision,
    enrollment_state: ManifoldPeerEnrollmentState,
    rendezvous_state: ManifoldRendezvousAuthorityState,
    enrollment_receipt: Option<ManifoldPeerEnrollmentReceipt>,
    rendezvous_receipt: Option<ManifoldRendezvousReceipt>,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum FailureTransitionFacts {
    CredentialRotation {
        old_generation: u64,
        new_generation: u64,
        old_rejection: ManifoldRendezvousRejectionReason,
        new_accepted: bool,
    },
    CredentialRevoke {
        revoked_generation: u64,
        revoked_status: ManifoldPeerCredentialStatus,
        revoked_rejection: ManifoldRendezvousRejectionReason,
        revoked_peer_active_credential_count: usize,
    },
    Replay {
        first_accepted: bool,
        replay_rejection: ManifoldRendezvousRejectionReason,
        state_unchanged_after_replay: bool,
    },
}

fn main() -> Result<(), Box<dyn Error>> {
    let (criterion, output) = parse_args()?;
    let evidence = match criterion.as_str() {
        "credential_rotation" => rotation_evidence()?,
        "credential_revoke" => revoke_evidence()?,
        "replay" => replay_evidence()?,
        _ => return Err(format!("unsupported criterion: {criterion}").into()),
    };
    let encoded = serde_json::to_string_pretty(&evidence)? + "\n";
    if let Some(path) = output {
        fs::write(path, encoded)?;
    } else {
        print!("{encoded}");
    }
    Ok(())
}

fn parse_args() -> Result<(String, Option<PathBuf>), Box<dyn Error>> {
    let mut criterion = None;
    let mut output = None;
    let mut args = std::env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--criterion" => criterion = args.next(),
            "--output" => output = args.next().map(PathBuf::from),
            _ => return Err(format!("unknown argument: {argument}").into()),
        }
    }
    Ok((criterion.ok_or("--criterion is required")?, output))
}

fn rotation_evidence() -> Result<FailureTransitionEvidence, Box<dyn Error>> {
    let (enrollment, alpha_key, beta_key) = enrolled_pair()?;
    let before = phase(
        "before",
        "generation_one_current",
        true,
        enrollment.authority_revision,
        enrollment.clone(),
        ManifoldRendezvousAuthorityState::empty(),
        None,
        None,
    );
    let next_alpha_key = key(19);
    let (rotated, rotation) = review_and_apply_peer_enrollment(
        &enrollment,
        &enrollment_request(
            "request.rotate.alpha.002",
            enrollment.authority_revision,
            ManifoldPeerEnrollmentAction::Rotate {
                prior_key_id: id("key.peer.alpha.001"),
                credential: credential("peer.alpha", "key.peer.alpha.002", 2, &next_alpha_key),
            },
        ),
        &[id(OPERATOR_ID)],
        3_000,
    );
    ensure(rotation.applied, "rotation did not apply")?;
    let empty = ManifoldRendezvousAuthorityState::empty();
    let old_request = rendezvous_request(
        "rotation-old",
        empty.authority_revision,
        rotated.authority_revision,
        "key.peer.alpha.001",
        &alpha_key,
        &beta_key,
        0xab,
    );
    let (old_state, old_receipt) =
        review_and_apply_signed_rendezvous(&empty, &rotated, &old_request, 3_100);
    ensure(
        old_state == empty,
        "old credential changed rendezvous state",
    )?;
    let old_rejection = old_receipt
        .rejection_reason
        .clone()
        .ok_or("old credential unexpectedly accepted")?;
    let failure = phase(
        "failure",
        "credential_rotated_old_generation_rejected",
        true,
        rotated.authority_revision,
        rotated.clone(),
        old_state,
        Some(rotation),
        Some(old_receipt),
    );
    let current_request = rendezvous_request(
        "rotation-current",
        empty.authority_revision,
        rotated.authority_revision,
        "key.peer.alpha.002",
        &next_alpha_key,
        &beta_key,
        0xbc,
    );
    let (current_state, current_receipt) =
        review_and_apply_signed_rendezvous(&empty, &rotated, &current_request, 3_200);
    ensure(current_receipt.accepted, "new credential did not recover")?;
    let old_generation = credential_generation(&rotated, "key.peer.alpha.001")?;
    let new_generation = credential_generation(&rotated, "key.peer.alpha.002")?;
    let new_accepted = current_receipt.accepted;
    let rotated_revision = rotated.authority_revision;
    let recovery = phase(
        "recovery",
        "fresh_generation_accepted",
        true,
        rotated_revision,
        rotated,
        current_state,
        None,
        Some(current_receipt),
    );
    Ok(export(
        "credential_rotation",
        before,
        failure,
        recovery,
        FailureTransitionFacts::CredentialRotation {
            old_generation,
            new_generation,
            old_rejection,
            new_accepted,
        },
    ))
}

fn revoke_evidence() -> Result<FailureTransitionEvidence, Box<dyn Error>> {
    let (enrollment, alpha_key, beta_key) = enrolled_pair()?;
    let empty = ManifoldRendezvousAuthorityState::empty();
    let initial_request = rendezvous_request(
        "revoke-before",
        empty.authority_revision,
        enrollment.authority_revision,
        "key.peer.alpha.001",
        &alpha_key,
        &beta_key,
        0xcd,
    );
    let (accepted_state, accepted_receipt) =
        review_and_apply_signed_rendezvous(&empty, &enrollment, &initial_request, 3_000);
    ensure(
        accepted_receipt.accepted,
        "pre-revoke rendezvous did not accept",
    )?;
    let before = phase(
        "before",
        "credential_current_and_rendezvous_accepted",
        true,
        enrollment.authority_revision,
        enrollment.clone(),
        accepted_state.clone(),
        None,
        Some(accepted_receipt),
    );
    let (revoked, revocation) = review_and_apply_peer_enrollment(
        &enrollment,
        &enrollment_request(
            "request.revoke.alpha.001",
            enrollment.authority_revision,
            ManifoldPeerEnrollmentAction::Revoke {
                key_id: id("key.peer.alpha.001"),
                reason_id: id("reason.operator.compromise"),
            },
        ),
        &[id(OPERATOR_ID)],
        4_000,
    );
    ensure(revocation.applied, "revocation did not apply")?;
    let failure = phase(
        "failure",
        "credential_revoked",
        true,
        revoked.authority_revision,
        revoked.clone(),
        accepted_state.clone(),
        Some(revocation),
        None,
    );
    let revoked_request = rendezvous_request(
        "revoke-after",
        accepted_state.authority_revision,
        revoked.authority_revision,
        "key.peer.alpha.001",
        &alpha_key,
        &beta_key,
        0xde,
    );
    let (rejected_state, rejected_receipt) =
        review_and_apply_signed_rendezvous(&accepted_state, &revoked, &revoked_request, 4_100);
    ensure(
        rejected_state == accepted_state,
        "revoked credential changed rendezvous state",
    )?;
    let revoked_rejection = rejected_receipt
        .rejection_reason
        .clone()
        .ok_or("revoked credential unexpectedly accepted")?;
    let revoked_record = revoked
        .credentials
        .iter()
        .find(|record| record.key_id.as_str() == "key.peer.alpha.001")
        .ok_or("revoked credential missing")?;
    let facts = FailureTransitionFacts::CredentialRevoke {
        revoked_generation: revoked_record.key_generation,
        revoked_status: revoked_record.status.clone(),
        revoked_rejection,
        revoked_peer_active_credential_count: revoked
            .credentials
            .iter()
            .filter(|record| {
                record.peer_id.as_str() == "peer.alpha"
                    && record.status == ManifoldPeerCredentialStatus::Active
            })
            .count(),
    };
    let recovery = phase(
        "recovery",
        "revoked_credential_rejected_without_state_change",
        true,
        revoked.authority_revision,
        revoked,
        rejected_state,
        None,
        Some(rejected_receipt),
    );
    Ok(export(
        "credential_revoke",
        before,
        failure,
        recovery,
        facts,
    ))
}

fn replay_evidence() -> Result<FailureTransitionEvidence, Box<dyn Error>> {
    let (enrollment, alpha_key, beta_key) = enrolled_pair()?;
    let empty = ManifoldRendezvousAuthorityState::empty();
    let before = phase(
        "before",
        "rendezvous_evidence_unused",
        true,
        empty.authority_revision,
        enrollment.clone(),
        empty.clone(),
        None,
        None,
    );
    let request = rendezvous_request(
        "replay",
        empty.authority_revision,
        enrollment.authority_revision,
        "key.peer.alpha.001",
        &alpha_key,
        &beta_key,
        0xef,
    );
    let (accepted, first_receipt) =
        review_and_apply_signed_rendezvous(&empty, &enrollment, &request, 3_000);
    ensure(first_receipt.accepted, "first rendezvous did not accept")?;
    let first_accepted = first_receipt.accepted;
    let failure = phase(
        "failure",
        "rendezvous_evidence_consumed",
        true,
        accepted.authority_revision,
        enrollment.clone(),
        accepted.clone(),
        None,
        Some(first_receipt),
    );
    let mut replay = request;
    replay.request_id = id("request.rendezvous.replay.second");
    replay.expected_authority_revision = accepted.authority_revision;
    let (after_replay, replay_receipt) =
        review_and_apply_signed_rendezvous(&accepted, &enrollment, &replay, 3_100);
    let state_unchanged_after_replay = after_replay == accepted;
    ensure(
        state_unchanged_after_replay,
        "replay changed accepted state",
    )?;
    let replay_rejection = replay_receipt
        .rejection_reason
        .clone()
        .ok_or("replay unexpectedly accepted")?;
    let recovery = phase(
        "recovery",
        "replay_rejected_without_state_change",
        true,
        after_replay.authority_revision,
        enrollment,
        after_replay,
        None,
        Some(replay_receipt),
    );
    Ok(export(
        "replay",
        before,
        failure,
        recovery,
        FailureTransitionFacts::Replay {
            first_accepted,
            replay_rejection,
            state_unchanged_after_replay,
        },
    ))
}

fn export(
    criterion: &str,
    before: FailureTransitionPhase,
    failure: FailureTransitionPhase,
    recovery: FailureTransitionPhase,
    facts: FailureTransitionFacts,
) -> FailureTransitionEvidence {
    FailureTransitionEvidence {
        schema_id: EXPORT_SCHEMA.to_owned(),
        criterion_id: criterion.to_owned(),
        test_id: format!("rusty.manifold.corrected_release.{criterion}"),
        before,
        failure,
        recovery,
        facts,
    }
}

#[allow(clippy::too_many_arguments)]
fn phase(
    name: &'static str,
    observed_state: &'static str,
    transition_complete: bool,
    authority_revision: Revision,
    enrollment_state: ManifoldPeerEnrollmentState,
    rendezvous_state: ManifoldRendezvousAuthorityState,
    enrollment_receipt: Option<ManifoldPeerEnrollmentReceipt>,
    rendezvous_receipt: Option<ManifoldRendezvousReceipt>,
) -> FailureTransitionPhase {
    FailureTransitionPhase {
        schema_id: PHASE_SCHEMA.to_owned(),
        phase: name,
        observed_state,
        transition_complete,
        authority_revision,
        enrollment_state,
        rendezvous_state,
        enrollment_receipt,
        rendezvous_receipt,
    }
}

fn enrolled_pair() -> Result<(ManifoldPeerEnrollmentState, SigningKey, SigningKey), Box<dyn Error>>
{
    let alpha_key = key(7);
    let beta_key = key(11);
    let trusted = [id(OPERATOR_ID)];
    let (state, alpha) = review_and_apply_peer_enrollment(
        &ManifoldPeerEnrollmentState::empty(),
        &enrollment_request(
            "request.enroll.alpha.001",
            Revision::INITIAL,
            ManifoldPeerEnrollmentAction::Enroll {
                credential: credential("peer.alpha", "key.peer.alpha.001", 1, &alpha_key),
            },
        ),
        &trusted,
        2_000,
    );
    ensure(alpha.applied, "alpha enrollment did not apply")?;
    let revision = state.authority_revision;
    let (state, beta) = review_and_apply_peer_enrollment(
        &state,
        &enrollment_request(
            "request.enroll.beta.001",
            revision,
            ManifoldPeerEnrollmentAction::Enroll {
                credential: credential("peer.beta", "key.peer.beta.001", 1, &beta_key),
            },
        ),
        &trusted,
        2_000,
    );
    ensure(beta.applied, "beta enrollment did not apply")?;
    Ok((state, alpha_key, beta_key))
}

fn rendezvous_request(
    suffix: &str,
    rendezvous_revision: Revision,
    enrollment_revision: Revision,
    alpha_key_id: &str,
    alpha_key: &SigningKey,
    beta_key: &SigningKey,
    nonce_seed: u8,
) -> ManifoldRendezvousReviewRequest {
    ManifoldRendezvousReviewRequest {
        schema_id: schema(RENDEZVOUS_REVIEW_REQUEST_SCHEMA),
        request_id: id(&format!("request.rendezvous.{suffix}")),
        expected_authority_revision: rendezvous_revision,
        expected_enrollment_authority_revision: enrollment_revision,
        first: evidence(
            &format!("evidence.rendezvous.{suffix}.alpha"),
            "peer.alpha",
            alpha_key_id,
            "peer.beta",
            ManifoldRendezvousRole::GroupOwner,
            alpha_key,
            nonce_seed,
        ),
        second: evidence(
            &format!("evidence.rendezvous.{suffix}.beta"),
            "peer.beta",
            "key.peer.beta.001",
            "peer.alpha",
            ManifoldRendezvousRole::Client,
            beta_key,
            nonce_seed,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn evidence(
    evidence_id: &str,
    signer_peer_id: &str,
    signer_key_id: &str,
    counterparty_peer_id: &str,
    role: ManifoldRendezvousRole,
    signing_key: &SigningKey,
    nonce_seed: u8,
) -> ManifoldSignedRendezvousEvidence {
    let mut value = ManifoldSignedRendezvousEvidence {
        schema_id: schema(SIGNED_RENDEZVOUS_EVIDENCE_SCHEMA),
        evidence_id: id(evidence_id),
        signer_peer_id: id(signer_peer_id),
        signer_key_id: id(signer_key_id),
        counterparty_peer_id: id(counterparty_peer_id),
        nonce_hex: format!("{nonce_seed:02x}").repeat(32),
        coordinator_epoch: 9,
        role,
        topology_contract_id: id(PRODUCT_WIFI_DIRECT_TOPOLOGY_CONTRACT),
        issued_at_ms: 2_000,
        expires_at_ms: 32_000,
        signature_hex: String::new(),
    };
    value.signature_hex = encode_lower_hex(
        &signing_key
            .sign(&rendezvous_signing_bytes(&value))
            .to_bytes(),
    );
    value
}

fn credential(
    peer_id: &str,
    key_id: &str,
    generation: u64,
    signing_key: &SigningKey,
) -> ManifoldPeerCredentialRecord {
    let public_key = signing_key.verifying_key().to_bytes();
    ManifoldPeerCredentialRecord {
        schema_id: schema(PEER_CREDENTIAL_SCHEMA),
        credential_id: id(&format!("credential.{peer_id}.{generation}")),
        peer_id: id(peer_id),
        trust_domain: id("trust.morphospace.peer"),
        key_id: id(key_id),
        key_generation: generation,
        algorithm: ManifoldPeerCredentialAlgorithm::Ed25519,
        public_key_hex: encode_lower_hex(&public_key),
        public_key_sha256: format!("sha256:{}", encode_lower_hex(&Sha256::digest(public_key))),
        valid_from_ms: 1_000,
        expires_at_ms: 100_000,
        status: ManifoldPeerCredentialStatus::Active,
        replaced_by_key_id: None,
    }
}

fn enrollment_request(
    request_id: &str,
    revision: Revision,
    action: ManifoldPeerEnrollmentAction,
) -> ManifoldPeerEnrollmentRequest {
    ManifoldPeerEnrollmentRequest {
        schema_id: schema(PEER_ENROLLMENT_REQUEST_SCHEMA),
        request_id: id(request_id),
        expected_authority_revision: revision,
        operator_id: id(OPERATOR_ID),
        issued_at_ms: 1_000,
        action,
    }
}

fn credential_generation(
    state: &ManifoldPeerEnrollmentState,
    key_id: &str,
) -> Result<u64, Box<dyn Error>> {
    state
        .credentials
        .iter()
        .find(|record| record.key_id.as_str() == key_id)
        .map(|record| record.key_generation)
        .ok_or_else(|| format!("credential missing: {key_id}").into())
}

fn ensure(condition: bool, reason: &str) -> Result<(), Box<dyn Error>> {
    if condition {
        Ok(())
    } else {
        Err(reason.to_owned().into())
    }
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn id(value: &str) -> DottedId {
    DottedId::new(value).expect("exporter id")
}

fn schema(value: &str) -> SchemaId {
    SchemaId::new(value).expect("exporter schema")
}

fn encode_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
