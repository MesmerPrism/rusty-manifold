use rusty_manifold_admission::*;

#[test]
fn finite_initial_construction_preserves_exact_admission_state_and_wire() {
    let mut expected: ManifoldAdmissionSnapshot = serde_json::from_str(include_str!(
        "../../../fixtures/admission/initial-snapshot.json"
    ))
    .unwrap();
    expected
        .root_renewal_policies
        .push(ManifoldAdmissionRootRenewalPolicy {
            grant_id: expected.grants[0].grant_id.clone(),
            horizon_ms: 600_000,
        });
    let actual = ManifoldAdmissionSnapshot::initial(
        expected.authority_id.clone(),
        expected.grants.clone(),
        expected.root_renewal_policies.clone(),
        expected.max_token_ttl_ms,
    );
    assert_eq!(actual, expected);
    assert_eq!(
        serde_json::to_vec(&actual).unwrap(),
        serde_json::to_vec(&expected).unwrap()
    );
    assert_eq!(
        ManifoldAdmissionAuthority::from_snapshot(actual)
            .unwrap()
            .snapshot(),
        &expected
    );
}

#[test]
fn finite_initial_data_does_not_bypass_admission_validation() {
    let expected: ManifoldAdmissionSnapshot = serde_json::from_str(include_str!(
        "../../../fixtures/admission/initial-snapshot.json"
    ))
    .unwrap();
    let invalid = ManifoldAdmissionSnapshot::initial(
        expected.authority_id,
        expected.grants,
        expected.root_renewal_policies,
        0,
    );
    assert!(ManifoldAdmissionAuthority::from_snapshot(invalid).is_err());
}
