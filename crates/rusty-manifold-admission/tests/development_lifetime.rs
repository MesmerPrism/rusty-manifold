//! Actual selected admission construction and finite/altered negative controls.
use rusty_manifold_admission::ManifoldAdmissionAuthority;
use serde_json::{json, Value};

fn snapshot() -> Value {
    json!({
        "$schema":"rusty.manifold.admission.snapshot.v2",
        "authority_id":"authority.development.test","authority_revision":1,
        "grants":[{"grant_id":"grant.development.test","client_lock_id":"lock.client.test",
            "client_lock_fingerprint":format!("sha256:{}", "ab".repeat(32)),
            "identity":{"client_id":"client.development.test","platform_subject":"test.development.app",
                "signing_fingerprint":format!("sha256:{}", "cd".repeat(32))},
            "capabilities":["capability.command.session.list"],"expires_at_ms":2_592_001_000u64,"revoked":false}],
        "active_tokens":[],"revoked_token_ids":[],"consumed_request_ids":[],
        "consumed_use_request_ids":[],"reviewed_sweep_ids":[],"audit_events":[],
        "max_token_ttl_ms":2_592_000_000u64,
        "root_renewal_policies":[{"grant_id":"grant.development.test","horizon_ms":2_592_000_000u64}]
    })
}

fn selected() -> Value {
    let mut value = snapshot();
    value["development_lifetime_policy"] = json!({
        "$schema":"rusty.manifold.development.lifetime_policy.v1",
        "policy_id":"policy.manifold.development-lifetime.v1",
        "delegated_authority_horizon_ms":2_592_000_000u64
    });
    value
}

#[test]
fn selected_development_policy_accepts_real_long_root_and_survives_restart() {
    let owner = ManifoldAdmissionAuthority::restart_from_json(&selected().to_string())
        .expect("source-selected development lifetime must survive the actual admission validator");
    let stored = owner.snapshot_json().unwrap();
    let restarted = ManifoldAdmissionAuthority::restart_from_json(&stored).unwrap();
    assert_eq!(stored, restarted.snapshot_json().unwrap());
}

#[test]
fn finite_omission_does_not_gain_development_horizon() {
    assert!(ManifoldAdmissionAuthority::restart_from_json(&snapshot().to_string()).is_err());
}

#[test]
fn altered_policy_or_longer_child_does_not_gain_authority() {
    let mut changed = selected();
    changed["development_lifetime_policy"]["delegated_authority_horizon_ms"] =
        json!(2_592_000_001u64);
    assert!(ManifoldAdmissionAuthority::restart_from_json(&changed.to_string()).is_err());
    let mut changed = selected();
    changed["root_renewal_policies"][0]["horizon_ms"] = json!(2_592_060_000u64);
    assert!(ManifoldAdmissionAuthority::restart_from_json(&changed.to_string()).is_err());
}
