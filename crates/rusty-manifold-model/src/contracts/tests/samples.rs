use super::*;

fn oscillator_profile() -> ManifoldSyntheticScalarOscillatorProfile {
    ManifoldSyntheticScalarOscillatorProfile {
        schema_id: schema("rusty.manifold.synthetic.scalar_oscillator_profile.v1"),
        profile_id: id("profile.synthetic_quest_driver_wave"),
        stream_id: id("stream.synthetic_wave"),
        source_module_id: id("module.synthetic_wave_provider"),
        timestamp_domain: id("clock.host_monotonic"),
        sample_count: 5,
        sample_rate_hz: 4.0,
        frequency_hz: 1.0,
        phase_offset_radians: 0.0,
        amplitude: 0.4,
        offset: 0.5,
        value_min: 0.0,
        value_max: 1.0,
        start_timestamp_ms: 100_000,
        units: "normalized".to_owned(),
        quality: ManifoldSampleQuality::Synthetic,
    }
}

#[test]
fn synthetic_scalar_oscillator_generates_bounded_samples() {
    let samples = oscillator_profile().generate_samples().unwrap();

    assert_eq!(samples.len(), 5);
    assert_eq!(samples[0].value01, 0.5);
    assert_eq!(samples[1].value01, 0.9);
    assert_eq!(samples[2].value01, 0.5);
    assert_eq!(samples[3].value01, 0.1);
    assert_eq!(samples[4].timestamp_ms, 101_000);
    assert!(samples.iter().all(|sample| sample.validate().is_ok()));
}

#[test]
fn synthetic_scalar_oscillator_rejects_range_escape() {
    let mut profile = oscillator_profile();
    profile.amplitude = 0.75;

    let error = profile.generate_samples().unwrap_err();
    assert_eq!(
        error.kind(),
        ManifoldSampleValidationErrorKind::OscillatorLeavesDeclaredRange
    );
}

#[test]
fn scalar_sample_rejects_out_of_range_normalized_value() {
    let mut sample = oscillator_profile().generate_samples().unwrap().remove(0);
    sample.value01 = 1.25;

    let error = sample.validate().unwrap_err();
    assert_eq!(
        error.kind(),
        ManifoldSampleValidationErrorKind::NormalizedValueOutOfRange
    );
}
