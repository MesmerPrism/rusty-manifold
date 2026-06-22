use super::*;

#[test]
fn validation_passes_for_repo_fixtures() {
    let report = validate_repo(&default_repo_root()).unwrap();

    assert_eq!(report.status, "pass");
    assert!(report.checks.len() >= 10);
}

#[test]
fn simulation_snapshot_is_deterministic() {
    let snapshot = simulate_synthetic_topology(&default_repo_root()).unwrap();
    let output = to_pretty_json(&snapshot).unwrap();
    let expected =
        read_text(&default_repo_root().join("fixtures/simulator/synthetic-topology-summary.json"))
            .unwrap();

    assert_eq!(expected.trim_end(), output.trim_end());
}

#[test]
fn diff_snapshot_is_deterministic() {
    let snapshot = diff_synthetic_contracts(&default_repo_root()).unwrap();
    let output = to_pretty_json(&snapshot).unwrap();
    let expected =
        read_text(&default_repo_root().join("fixtures/diff/synthetic-contract-diff.json")).unwrap();

    assert_eq!(expected.trim_end(), output.trim_end());
}

#[test]
fn synthetic_scalar_oscillator_output_is_deterministic() {
    let output = run(vec![
        "emit-synthetic-scalar".to_string(),
        "--check".to_string(),
        "--expected".to_string(),
        "fixtures/synthetic/synthetic-scalar-oscillator-samples.jsonl".to_string(),
    ])
    .unwrap();

    assert_eq!(output, "synthetic scalar samples match fixture");
}

#[test]
fn shell_handoff_review_receipt_is_generated_from_handoff() {
    let handoff_path =
        default_repo_root().join("fixtures/shell-handoff/synthetic-loopback-shell.json");

    let receipt = review_shell_handoff(&default_repo_root(), &handoff_path).unwrap();

    assert_eq!(receipt.status, rusty_manifold_model::ValidationStatus::Pass);
    assert_eq!(
        receipt.handoff_id.to_string(),
        "shell_handoff.synthetic_wave.loopback"
    );
    assert!(!receipt.runtime_execution_performed);
    assert!(!receipt.launch_started);
    assert!(!receipt.command_session_started);
}

#[test]
fn shell_handoff_review_command_writes_receipt() {
    let output_path = default_repo_root().join("target/test-shell-handoff-review.json");
    let _ = fs::remove_file(&output_path);

    let output = run(vec![
        "review-shell-handoff".to_string(),
        "--handoff".to_string(),
        default_repo_root()
            .join("fixtures/shell-handoff/synthetic-loopback-shell.json")
            .display()
            .to_string(),
        "--output".to_string(),
        output_path.display().to_string(),
    ])
    .unwrap();

    assert!(output.contains("\"$schema\": \"rusty.manifold.shell.handoff_review_receipt.v1\""));
    assert!(output_path.is_file());
    let written = read_text(&output_path).unwrap();
    assert_eq!(written.trim_end(), output.trim_end());
}

#[test]
fn command_authority_review_command_matches_fixture() {
    let output = run(vec![
        "review-command".to_string(),
        "--snapshot".to_string(),
        "fixtures/authority/synthetic-authority-snapshot.json".to_string(),
        "--envelope".to_string(),
        "fixtures/command/synthetic-command-envelope.json".to_string(),
        "--clock".to_string(),
        "fixtures/clock/synthetic-command-review-clock.json".to_string(),
    ])
    .unwrap();
    let expected = read_text(
        &default_repo_root()
            .join("fixtures/authority-review/synthetic-command-accepted-review.json"),
    )
    .unwrap();

    assert!(output.contains("\"$schema\": \"rusty.manifold.authority.command_review.v1\""));
    assert_eq!(expected.trim_end(), output.trim_end());
}

#[test]
fn command_dispatch_receipt_command_matches_fixture() {
    let output = run(vec![
        "prepare-command-dispatch".to_string(),
        "--snapshot".to_string(),
        "fixtures/authority/synthetic-authority-snapshot.json".to_string(),
        "--review".to_string(),
        "fixtures/authority-review/synthetic-command-accepted-review.json".to_string(),
    ])
    .unwrap();
    let expected = read_text(
        &default_repo_root()
            .join("fixtures/command-dispatch/synthetic-command-dispatch-ready-receipt.json"),
    )
    .unwrap();

    assert!(
        output.contains("\"$schema\": \"rusty.manifold.authority.command_dispatch_receipt.v1\"")
    );
    assert_eq!(expected.trim_end(), output.trim_end());
}

#[test]
fn lease_authority_review_command_matches_fixture() {
    let output = run(vec![
        "review-lease".to_string(),
        "--snapshot".to_string(),
        "fixtures/authority/synthetic-authority-snapshot.json".to_string(),
        "--request".to_string(),
        "fixtures/command/synthetic-lease-request.json".to_string(),
        "--clock".to_string(),
        "fixtures/clock/synthetic-command-review-clock.json".to_string(),
    ])
    .unwrap();
    let expected = read_text(
        &default_repo_root().join("fixtures/lease-review/synthetic-lease-accepted-review.json"),
    )
    .unwrap();

    assert!(output.contains("\"$schema\": \"rusty.manifold.authority.lease_review.v1\""));
    assert_eq!(expected.trim_end(), output.trim_end());
}

#[test]
fn lease_authority_application_command_matches_fixture() {
    let output = run(vec![
        "apply-lease-review".to_string(),
        "--snapshot".to_string(),
        "fixtures/authority/synthetic-authority-snapshot.json".to_string(),
        "--review".to_string(),
        "fixtures/lease-review/synthetic-lease-accepted-review.json".to_string(),
    ])
    .unwrap();
    let expected = read_text(
        &default_repo_root()
            .join("fixtures/authority-application/synthetic-lease-accepted-application.json"),
    )
    .unwrap();

    assert!(output.contains("\"$schema\": \"rusty.manifold.authority.lease_application.v1\""));
    assert_eq!(expected.trim_end(), output.trim_end());
}

#[test]
fn lease_release_authority_review_command_matches_fixture() {
    let output = run(vec![
        "review-lease-release".to_string(),
        "--snapshot".to_string(),
        "fixtures/authority/synthetic-lease-active-authority-snapshot.json".to_string(),
        "--request".to_string(),
        "fixtures/command/synthetic-lease-release-request.json".to_string(),
        "--clock".to_string(),
        "fixtures/clock/synthetic-command-review-clock.json".to_string(),
    ])
    .unwrap();
    let expected = read_text(
        &default_repo_root()
            .join("fixtures/lease-release-review/synthetic-lease-release-accepted-review.json"),
    )
    .unwrap();

    assert!(output.contains("\"$schema\": \"rusty.manifold.authority.lease_release_review.v1\""));
    assert_eq!(expected.trim_end(), output.trim_end());
}

#[test]
fn lease_release_authority_application_command_matches_fixture() {
    let output = run(vec![
        "apply-lease-release-review".to_string(),
        "--snapshot".to_string(),
        "fixtures/authority/synthetic-lease-active-authority-snapshot.json".to_string(),
        "--review".to_string(),
        "fixtures/lease-release-review/synthetic-lease-release-accepted-review.json".to_string(),
    ])
    .unwrap();
    let expected =
        read_text(&default_repo_root().join(
            "fixtures/authority-application/synthetic-lease-release-accepted-application.json",
        ))
        .unwrap();

    assert!(
        output.contains("\"$schema\": \"rusty.manifold.authority.lease_release_application.v1\"")
    );
    assert_eq!(expected.trim_end(), output.trim_end());
}

#[test]
fn lease_renewal_authority_review_command_matches_fixture() {
    let output = run(vec![
        "review-lease-renewal".to_string(),
        "--snapshot".to_string(),
        "fixtures/authority/synthetic-lease-active-authority-snapshot.json".to_string(),
        "--request".to_string(),
        "fixtures/command/synthetic-lease-renewal-request.json".to_string(),
        "--clock".to_string(),
        "fixtures/clock/synthetic-command-review-clock.json".to_string(),
    ])
    .unwrap();
    let expected = read_text(
        &default_repo_root()
            .join("fixtures/lease-renewal-review/synthetic-lease-renewal-accepted-review.json"),
    )
    .unwrap();

    assert!(output.contains("\"$schema\": \"rusty.manifold.authority.lease_renewal_review.v1\""));
    assert_eq!(expected.trim_end(), output.trim_end());
}

#[test]
fn lease_renewal_authority_application_command_matches_fixture() {
    let output = run(vec![
        "apply-lease-renewal-review".to_string(),
        "--snapshot".to_string(),
        "fixtures/authority/synthetic-lease-active-authority-snapshot.json".to_string(),
        "--review".to_string(),
        "fixtures/lease-renewal-review/synthetic-lease-renewal-accepted-review.json".to_string(),
    ])
    .unwrap();
    let expected =
        read_text(&default_repo_root().join(
            "fixtures/authority-application/synthetic-lease-renewal-accepted-application.json",
        ))
        .unwrap();

    assert!(
        output.contains("\"$schema\": \"rusty.manifold.authority.lease_renewal_application.v1\"")
    );
    assert_eq!(expected.trim_end(), output.trim_end());
}

#[test]
fn stream_registry_authority_review_command_matches_fixture() {
    let output = run(vec![
        "review-stream-registry".to_string(),
        "--snapshot".to_string(),
        "fixtures/authority/synthetic-authority-snapshot.json".to_string(),
        "--request".to_string(),
        "fixtures/stream/synthetic-stream-registry-change-request.json".to_string(),
        "--clock".to_string(),
        "fixtures/clock/synthetic-command-review-clock.json".to_string(),
    ])
    .unwrap();
    let expected = read_text(
        &default_repo_root()
            .join("fixtures/stream-registry-review/synthetic-stream-registry-accepted-review.json"),
    )
    .unwrap();

    assert!(output.contains("\"$schema\": \"rusty.manifold.authority.stream_registry_review.v1\""));
    assert_eq!(expected.trim_end(), output.trim_end());
}

#[test]
fn stream_registry_authority_application_command_matches_fixture() {
    let output = run(vec![
        "apply-stream-registry-review".to_string(),
        "--snapshot".to_string(),
        "fixtures/authority/synthetic-authority-snapshot.json".to_string(),
        "--review".to_string(),
        "fixtures/stream-registry-review/synthetic-stream-registry-accepted-review.json"
            .to_string(),
    ])
    .unwrap();
    let expected = read_text(&default_repo_root().join(
        "fixtures/authority-application/synthetic-stream-registry-accepted-application.json",
    ))
    .unwrap();

    assert!(
        output.contains("\"$schema\": \"rusty.manifold.authority.stream_registry_application.v1\"")
    );
    assert_eq!(expected.trim_end(), output.trim_end());
}

#[test]
fn stream_subscription_authority_review_command_matches_fixture() {
    let output = run(vec![
        "review-stream-subscription".to_string(),
        "--snapshot".to_string(),
        "fixtures/authority/synthetic-stream-subscription-authority-snapshot.json".to_string(),
        "--request".to_string(),
        "fixtures/stream-subscription/synthetic-stream-subscription-request.json".to_string(),
        "--clock".to_string(),
        "fixtures/clock/synthetic-command-review-clock.json".to_string(),
    ])
    .unwrap();
    let expected = read_text(&default_repo_root().join(
        "fixtures/stream-subscription-review/synthetic-stream-subscription-accepted-review.json",
    ))
    .unwrap();

    assert!(
        output.contains("\"$schema\": \"rusty.manifold.authority.stream_subscription_review.v1\"")
    );
    assert_eq!(expected.trim_end(), output.trim_end());
}

#[test]
fn stream_subscription_authority_application_command_matches_fixture() {
    let output = run(vec![
        "apply-stream-subscription-review".to_string(),
        "--snapshot".to_string(),
        "fixtures/authority/synthetic-stream-subscription-authority-snapshot.json".to_string(),
        "--review".to_string(),
        "fixtures/stream-subscription-review/synthetic-stream-subscription-accepted-review.json"
            .to_string(),
    ])
    .unwrap();
    let expected = read_text(&default_repo_root().join(
        "fixtures/authority-application/synthetic-stream-subscription-accepted-application.json",
    ))
    .unwrap();

    assert!(output
        .contains("\"$schema\": \"rusty.manifold.authority.stream_subscription_application.v1\""));
    assert_eq!(expected.trim_end(), output.trim_end());
}

#[test]
fn stream_subscription_release_authority_review_command_matches_fixture() {
    let output = run(vec![
        "review-stream-subscription-release".to_string(),
        "--snapshot".to_string(),
        "fixtures/authority/synthetic-stream-subscription-active-authority-snapshot.json"
            .to_string(),
        "--request".to_string(),
        "fixtures/stream-subscription/synthetic-stream-subscription-release-request.json"
            .to_string(),
        "--clock".to_string(),
        "fixtures/clock/synthetic-command-review-clock.json".to_string(),
    ])
    .unwrap();
    let expected = read_text(&default_repo_root().join(
            "fixtures/stream-subscription-release-review/synthetic-stream-subscription-release-accepted-review.json",
        ))
        .unwrap();

    assert!(output.contains(
        "\"$schema\": \"rusty.manifold.authority.stream_subscription_release_review.v1\""
    ));
    assert_eq!(expected.trim_end(), output.trim_end());
}

#[test]
fn stream_subscription_release_authority_application_command_matches_fixture() {
    let output = run(vec![
            "apply-stream-subscription-release-review".to_string(),
            "--snapshot".to_string(),
            "fixtures/authority/synthetic-stream-subscription-active-authority-snapshot.json"
                .to_string(),
            "--review".to_string(),
            "fixtures/stream-subscription-release-review/synthetic-stream-subscription-release-accepted-review.json"
                .to_string(),
        ])
        .unwrap();
    let expected = read_text(&default_repo_root().join(
            "fixtures/authority-application/synthetic-stream-subscription-release-accepted-application.json",
        ))
        .unwrap();

    assert!(output.contains(
        "\"$schema\": \"rusty.manifold.authority.stream_subscription_release_application.v1\""
    ));
    assert_eq!(expected.trim_end(), output.trim_end());
}

#[test]
fn stream_subscription_renewal_authority_review_command_matches_fixture() {
    let output = run(vec![
        "review-stream-subscription-renewal".to_string(),
        "--snapshot".to_string(),
        "fixtures/authority/synthetic-stream-subscription-active-authority-snapshot.json"
            .to_string(),
        "--request".to_string(),
        "fixtures/stream-subscription/synthetic-stream-subscription-renewal-request.json"
            .to_string(),
        "--clock".to_string(),
        "fixtures/clock/synthetic-command-review-clock.json".to_string(),
    ])
    .unwrap();
    let expected = read_text(&default_repo_root().join(
            "fixtures/stream-subscription-renewal-review/synthetic-stream-subscription-renewal-accepted-review.json",
        ))
        .unwrap();

    assert!(output.contains(
        "\"$schema\": \"rusty.manifold.authority.stream_subscription_renewal_review.v1\""
    ));
    assert_eq!(expected.trim_end(), output.trim_end());
}

#[test]
fn stream_subscription_renewal_authority_application_command_matches_fixture() {
    let output = run(vec![
            "apply-stream-subscription-renewal-review".to_string(),
            "--snapshot".to_string(),
            "fixtures/authority/synthetic-stream-subscription-active-authority-snapshot.json"
                .to_string(),
            "--review".to_string(),
            "fixtures/stream-subscription-renewal-review/synthetic-stream-subscription-renewal-accepted-review.json"
                .to_string(),
        ])
        .unwrap();
    let expected = read_text(&default_repo_root().join(
            "fixtures/authority-application/synthetic-stream-subscription-renewal-accepted-application.json",
        ))
        .unwrap();

    assert!(output.contains(
        "\"$schema\": \"rusty.manifold.authority.stream_subscription_renewal_application.v1\""
    ));
    assert_eq!(expected.trim_end(), output.trim_end());
}

#[test]
fn authority_expiry_sweep_authority_review_command_matches_fixture() {
    let output = run(vec![
        "review-authority-expiry-sweep".to_string(),
        "--snapshot".to_string(),
        "fixtures/authority/synthetic-stream-subscription-active-authority-snapshot.json"
            .to_string(),
        "--request".to_string(),
        "fixtures/authority-expiry/synthetic-authority-expiry-sweep-request.json".to_string(),
        "--clock".to_string(),
        "fixtures/clock/synthetic-expired-command-review-clock.json".to_string(),
    ])
    .unwrap();
    let expected = read_text(&default_repo_root().join(
        "fixtures/authority-expiry-review/synthetic-authority-expiry-sweep-accepted-review.json",
    ))
    .unwrap();

    assert!(output.contains("\"$schema\": \"rusty.manifold.authority.expiry_sweep_review.v1\""));
    assert_eq!(expected.trim_end(), output.trim_end());
}

#[test]
fn authority_expiry_sweep_authority_application_command_matches_fixture() {
    let output = run(vec![
        "apply-authority-expiry-sweep-review".to_string(),
        "--snapshot".to_string(),
        "fixtures/authority/synthetic-stream-subscription-active-authority-snapshot.json"
            .to_string(),
        "--review".to_string(),
        "fixtures/authority-expiry-review/synthetic-authority-expiry-sweep-accepted-review.json"
            .to_string(),
    ])
    .unwrap();
    let expected = read_text(&default_repo_root().join(
        "fixtures/authority-application/synthetic-authority-expiry-sweep-accepted-application.json",
    ))
    .unwrap();

    assert!(
        output.contains("\"$schema\": \"rusty.manifold.authority.expiry_sweep_application.v1\"")
    );
    assert_eq!(expected.trim_end(), output.trim_end());
}

#[test]
fn module_runtime_state_authority_review_command_matches_fixture() {
    let output = run(vec![
        "review-module-runtime".to_string(),
        "--snapshot".to_string(),
        "fixtures/authority/synthetic-authority-snapshot.json".to_string(),
        "--request".to_string(),
        "fixtures/module/synthetic-runtime-state-change-request.json".to_string(),
        "--clock".to_string(),
        "fixtures/clock/synthetic-command-review-clock.json".to_string(),
    ])
    .unwrap();
    let expected = read_text(
        &default_repo_root()
            .join("fixtures/module-runtime-review/synthetic-module-runtime-accepted-review.json"),
    )
    .unwrap();

    assert!(
        output.contains("\"$schema\": \"rusty.manifold.authority.module_runtime_state_review.v1\"")
    );
    assert_eq!(expected.trim_end(), output.trim_end());
}

#[test]
fn module_runtime_state_authority_application_command_matches_fixture() {
    let output = run(vec![
        "apply-module-runtime-review".to_string(),
        "--snapshot".to_string(),
        "fixtures/authority/synthetic-authority-snapshot.json".to_string(),
        "--review".to_string(),
        "fixtures/module-runtime-review/synthetic-module-runtime-accepted-review.json".to_string(),
    ])
    .unwrap();
    let expected =
        read_text(&default_repo_root().join(
            "fixtures/authority-application/synthetic-module-runtime-accepted-application.json",
        ))
        .unwrap();

    assert!(output
        .contains("\"$schema\": \"rusty.manifold.authority.module_runtime_state_application.v1\""));
    assert_eq!(expected.trim_end(), output.trim_end());
}

#[test]
fn host_manifest_authority_review_command_matches_fixture() {
    let output = run(vec![
        "review-host-manifest".to_string(),
        "--snapshot".to_string(),
        "fixtures/authority/synthetic-authority-snapshot.json".to_string(),
        "--request".to_string(),
        "fixtures/host/synthetic-host-manifest-change-request.json".to_string(),
        "--clock".to_string(),
        "fixtures/clock/synthetic-command-review-clock.json".to_string(),
    ])
    .unwrap();
    let expected = read_text(
        &default_repo_root()
            .join("fixtures/host-manifest-review/synthetic-host-manifest-accepted-review.json"),
    )
    .unwrap();

    assert!(output.contains("\"$schema\": \"rusty.manifold.authority.host_manifest_review.v1\""));
    assert_eq!(expected.trim_end(), output.trim_end());
}

#[test]
fn host_manifest_authority_application_command_matches_fixture() {
    let output = run(vec![
        "apply-host-manifest-review".to_string(),
        "--snapshot".to_string(),
        "fixtures/authority/synthetic-authority-snapshot.json".to_string(),
        "--review".to_string(),
        "fixtures/host-manifest-review/synthetic-host-manifest-accepted-review.json".to_string(),
    ])
    .unwrap();
    let expected =
        read_text(&default_repo_root().join(
            "fixtures/authority-application/synthetic-host-manifest-accepted-application.json",
        ))
        .unwrap();

    assert!(
        output.contains("\"$schema\": \"rusty.manifold.authority.host_manifest_application.v1\"")
    );
    assert_eq!(expected.trim_end(), output.trim_end());
}

#[test]
fn clock_authority_review_command_matches_fixture() {
    let output = run(vec![
        "review-clock".to_string(),
        "--snapshot".to_string(),
        "fixtures/authority/synthetic-authority-snapshot.json".to_string(),
        "--request".to_string(),
        "fixtures/clock/synthetic-clock-change-request.json".to_string(),
        "--clock".to_string(),
        "fixtures/clock/synthetic-command-review-clock.json".to_string(),
    ])
    .unwrap();
    let expected = read_text(
        &default_repo_root().join("fixtures/clock-review/synthetic-clock-accepted-review.json"),
    )
    .unwrap();

    assert!(output.contains("\"$schema\": \"rusty.manifold.authority.clock_snapshot_review.v1\""));
    assert_eq!(expected.trim_end(), output.trim_end());
}

#[test]
fn clock_authority_application_command_matches_fixture() {
    let output = run(vec![
        "apply-clock-review".to_string(),
        "--snapshot".to_string(),
        "fixtures/authority/synthetic-authority-snapshot.json".to_string(),
        "--review".to_string(),
        "fixtures/clock-review/synthetic-clock-accepted-review.json".to_string(),
    ])
    .unwrap();
    let expected = read_text(
        &default_repo_root()
            .join("fixtures/authority-application/synthetic-clock-accepted-application.json"),
    )
    .unwrap();

    assert!(
        output.contains("\"$schema\": \"rusty.manifold.authority.clock_snapshot_application.v1\"")
    );
    assert_eq!(expected.trim_end(), output.trim_end());
}
