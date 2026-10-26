use rusty_manifold_runtime_host::*;

#[test]
fn finite_initial_construction_preserves_exact_runtime_state_and_wire() {
    let expected = ManifoldRuntimeHost::restart_from_json(include_str!(
        "../../../fixtures/runtime-host/synthetic-runtime-host-snapshot.json"
    ))
    .unwrap()
    .snapshot()
    .clone();
    let actual = ManifoldRuntimeHostSnapshot::initial(
        expected.host_id.clone(),
        expected.commands.clone(),
        expected.leases.clone(),
    );
    assert_eq!(actual, expected);
    assert_eq!(
        serde_json::to_vec(&actual).unwrap(),
        serde_json::to_vec(&expected).unwrap()
    );
    assert_eq!(
        ManifoldRuntimeHost::from_snapshot(actual)
            .unwrap()
            .snapshot(),
        &expected
    );
}

#[test]
fn finite_initial_data_does_not_bypass_runtime_validation() {
    let mut expected = ManifoldRuntimeHost::restart_from_json(include_str!(
        "../../../fixtures/runtime-host/synthetic-runtime-host-snapshot.json"
    ))
    .unwrap()
    .snapshot()
    .clone();
    expected.commands.push(expected.commands[0].clone());
    let invalid =
        ManifoldRuntimeHostSnapshot::initial(expected.host_id, expected.commands, expected.leases);
    assert!(ManifoldRuntimeHost::from_snapshot(invalid).is_err());
}
