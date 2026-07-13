//! Exports a deterministic admission lifecycle and rejection fixtures.

use rusty_manifold_admission::*;
use rusty_manifold_model::{DottedId, Revision, SchemaId};
use serde::Serialize;
use std::fs;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out = output_dir()?;
    fs::create_dir_all(&out)?;
    let initial = initial_snapshot();
    write(&out, "initial-snapshot.json", &initial)?;
    let mut authority = ManifoldAdmissionAuthority::from_snapshot(initial)?;

    let issue = issue_request(1, "request.admission.issue");
    let issued = authority.issue_token(&issue, [7; 32], 2_000);
    let token = issued.token.clone().expect("issued token");
    write(&out, "issue-request.json", &issue)?;
    write(&out, "issue-receipt.json", &issued)?;

    let use_request = ManifoldAdmissionUseRequest {
        schema_id: schema(ADMISSION_USE_REQUEST_SCHEMA),
        request_id: id("request.admission.use"),
        expected_authority_revision: revision(2),
        token_id: token.token_id.clone(),
        identity: identity(),
        capability_id: id("capability.command.session.list"),
        issued_at_ms: 2_000,
        expires_at_ms: 6_000,
    };
    let used = authority.authorize_use(&use_request, 3_000);
    write(&out, "use-request.json", &use_request)?;
    write(&out, "use-receipt.json", &used)?;

    let mut replay = use_request.clone();
    replay.expected_authority_revision = revision(3);
    let replayed = authority.authorize_use(&replay, 3_000);
    write(&out, "replay-use-request.damaged.json", &replay)?;
    write(&out, "replay-use-receipt.json", &replayed)?;

    let revoke = ManifoldAdmissionRevocationRequest {
        schema_id: schema(ADMISSION_REVOCATION_REQUEST_SCHEMA),
        request_id: id("request.admission.revoke"),
        expected_authority_revision: revision(3),
        token_id: token.token_id.clone(),
        identity: identity(),
        reason: id("reason.client.completed"),
    };
    let revoked = authority.revoke_token(&revoke);
    write(&out, "revoke-request.json", &revoke)?;
    write(&out, "revoke-receipt.json", &revoked)?;

    let mut after_revoke = use_request;
    after_revoke.request_id = id("request.admission.after-revoke");
    after_revoke.expected_authority_revision = revision(4);
    let rejected_after_revoke = authority.authorize_use(&after_revoke, 4_000);
    write(&out, "after-revoke-use-request.damaged.json", &after_revoke)?;
    write(
        &out,
        "after-revoke-use-receipt.json",
        &rejected_after_revoke,
    )?;
    write(&out, "final-snapshot.json", authority.snapshot())?;

    let mut wrong_identity = issue_request(1, "request.admission.wrong-identity");
    wrong_identity.identity.signing_fingerprint = format!("sha256:{}", "b2".repeat(32));
    let mut damaged_authority = ManifoldAdmissionAuthority::from_snapshot(initial_snapshot())?;
    let wrong_identity_receipt = damaged_authority.issue_token(&wrong_identity, [8; 32], 2_000);
    write(&out, "wrong-identity-request.damaged.json", &wrong_identity)?;
    write(&out, "wrong-identity-receipt.json", &wrong_identity_receipt)?;

    let mut escalation = issue_request(1, "request.admission.escalation");
    escalation
        .requested_capabilities
        .push(id("capability.command.admin"));
    let escalation_receipt = damaged_authority.issue_token(&escalation, [9; 32], 2_000);
    write(
        &out,
        "capability-escalation-request.damaged.json",
        &escalation,
    )?;
    write(
        &out,
        "capability-escalation-receipt.json",
        &escalation_receipt,
    )?;

    println!("wrote {}", out.display());
    Ok(())
}

fn initial_snapshot() -> ManifoldAdmissionSnapshot {
    ManifoldAdmissionSnapshot {
        schema_id: schema(ADMISSION_SNAPSHOT_SCHEMA),
        authority_id: id("authority.admission.quest"),
        authority_revision: revision(1),
        grants: vec![ManifoldAdmissionGrant {
            grant_id: id("grant.quest.authorized"),
            client_lock_id: id("lock.client.quest.authorized"),
            client_lock_fingerprint: format!("sha256:{}", "c1".repeat(32)),
            identity: identity(),
            capabilities: vec![id("capability.command.session.list")],
            expires_at_ms: 100_000,
            revoked: false,
        }],
        active_tokens: Vec::new(),
        revoked_token_ids: Vec::new(),
        consumed_request_ids: Vec::new(),
        consumed_use_request_ids: Vec::new(),
        reviewed_sweep_ids: Vec::new(),
        audit_events: Vec::new(),
        max_token_ttl_ms: 30_000,
    }
}

fn issue_request(expected: u64, request_id: &str) -> ManifoldAdmissionRequest {
    ManifoldAdmissionRequest {
        schema_id: schema(ADMISSION_REQUEST_SCHEMA),
        request_id: id(request_id),
        expected_authority_revision: revision(expected),
        identity: identity(),
        requested_capabilities: vec![id("capability.command.session.list")],
        issued_at_ms: 1_000,
        expires_at_ms: 5_000,
        requested_token_ttl_ms: 20_000,
    }
}

fn identity() -> ManifoldClientIdentity {
    ManifoldClientIdentity {
        client_id: id("client.quest.authorized"),
        platform_subject: "io.github.mesmerprism.rustymanifold.admission.client".to_owned(),
        signing_fingerprint: format!("sha256:{}", "a1".repeat(32)),
    }
}

fn output_dir() -> Result<PathBuf, String> {
    let mut args = std::env::args().skip(1);
    match (args.next().as_deref(), args.next(), args.next()) {
        (Some("--out"), Some(path), None) => Ok(PathBuf::from(path)),
        _ => Err("usage: export_admission_fixtures --out <directory>".to_owned()),
    }
}

fn write(
    out: &std::path::Path,
    name: &str,
    value: &impl Serialize,
) -> Result<(), Box<dyn std::error::Error>> {
    fs::write(
        out.join(name),
        format!("{}\n", serde_json::to_string_pretty(value)?),
    )?;
    Ok(())
}

fn id(value: &str) -> DottedId {
    DottedId::new(value).expect("static id")
}

fn schema(value: &str) -> SchemaId {
    SchemaId::new(value).expect("static schema")
}

fn revision(value: u64) -> Revision {
    Revision::new(value).expect("revision")
}
