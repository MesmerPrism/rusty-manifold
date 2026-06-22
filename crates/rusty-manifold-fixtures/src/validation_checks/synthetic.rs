use super::*;

pub(super) fn push_synthetic_checks(
    repo_root: &Path,
    checks: &mut Vec<ValidationCheckReport>,
) -> Result<(), CliError> {
    let profile_path =
        repo_root.join("fixtures/synthetic/synthetic-scalar-oscillator-profile.json");
    let profile = read_model::<ManifoldSyntheticScalarOscillatorProfile>(&profile_path)?;
    push_result(
        checks,
        "validation.check.synthetic_scalar_oscillator_profile",
        profile.validate(),
        "synthetic scalar oscillator profile is bounded, finite, and contract-shaped",
    );

    let generated = profile.generate_samples();
    push_result(
        checks,
        "validation.check.synthetic_scalar_oscillator_samples",
        generated
            .as_ref()
            .map(|samples| {
                if samples.iter().all(|sample| sample.validate().is_ok()) {
                    Ok(())
                } else {
                    Err("generated sample failed scalar_f32 validation".to_owned())
                }
            })
            .unwrap_or_else(|error| Err(error.to_string())),
        "synthetic scalar oscillator emits valid scalar_f32 samples",
    );

    let expected_path =
        repo_root.join("fixtures/synthetic/synthetic-scalar-oscillator-samples.jsonl");
    let expected = read_text(&expected_path)?;
    let output = to_json_lines(&generated?)?;
    push_result(
        checks,
        "validation.check.synthetic_scalar_oscillator_snapshot",
        if expected.trim_end() == output.trim_end() {
            Ok(())
        } else {
            Err(format!(
                "synthetic scalar samples do not match {}",
                expected_path.display()
            ))
        },
        "synthetic scalar oscillator JSONL output matches the committed fixture",
    );

    Ok(())
}
