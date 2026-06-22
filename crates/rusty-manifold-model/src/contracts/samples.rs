use super::*;

/// One scalar `f32` stream sample with both raw and normalized value channels.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, PartialEq)]
pub struct ManifoldScalarF32Sample {
    /// Schema identifier for this sample.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stream that produced the sample.
    pub stream_id: DottedId,
    /// Source module that emitted the sample.
    pub source_module_id: DottedId,
    /// Monotonic sequence number within this stream.
    pub sequence_id: u64,
    /// Timestamp clock domain.
    pub timestamp_domain: DottedId,
    /// Timestamp in milliseconds within the selected domain.
    pub timestamp_ms: u64,
    /// Raw scalar value in the sample's declared units.
    pub value: f32,
    /// Normalized scalar value for bounded clients.
    pub value01: f32,
    /// Display-safe units for `value`.
    pub units: String,
    /// Producer quality class.
    pub quality: ManifoldSampleQuality,
}

impl ManifoldScalarF32Sample {
    /// Validates scalar sample bounds and finite payload values.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldSampleValidationError`] when the sample carries the
    /// wrong schema id, non-finite floats, or an out-of-range normalized value.
    pub fn validate(&self) -> Result<(), ManifoldSampleValidationError> {
        if self.schema_id.as_str() != "rusty.manifold.sample.scalar_f32.v1" {
            return Err(ManifoldSampleValidationError::new(
                self.stream_id.clone(),
                self.schema_id.to_string(),
                ManifoldSampleValidationErrorKind::UnsupportedSchema,
            ));
        }
        if !self.value.is_finite() {
            return Err(ManifoldSampleValidationError::new(
                self.stream_id.clone(),
                self.value.to_string(),
                ManifoldSampleValidationErrorKind::NonFiniteValue,
            ));
        }
        if !self.value01.is_finite() || !(0.0..=1.0).contains(&self.value01) {
            return Err(ManifoldSampleValidationError::new(
                self.stream_id.clone(),
                self.value01.to_string(),
                ManifoldSampleValidationErrorKind::NormalizedValueOutOfRange,
            ));
        }
        if self.units.trim().is_empty() {
            return Err(ManifoldSampleValidationError::new(
                self.stream_id.clone(),
                self.units.clone(),
                ManifoldSampleValidationErrorKind::EmptyUnits,
            ));
        }

        Ok(())
    }
}

/// Deterministic synthetic scalar oscillator profile.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, PartialEq)]
pub struct ManifoldSyntheticScalarOscillatorProfile {
    /// Schema identifier for this profile.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable profile id.
    pub profile_id: DottedId,
    /// Stream emitted by this source.
    pub stream_id: DottedId,
    /// Source module that owns the synthetic stream.
    pub source_module_id: DottedId,
    /// Timestamp clock domain used by generated samples.
    pub timestamp_domain: DottedId,
    /// Number of samples to emit for deterministic fixture checks.
    pub sample_count: u32,
    /// Sample rate in hertz.
    pub sample_rate_hz: f32,
    /// Oscillator frequency in hertz.
    pub frequency_hz: f32,
    /// Phase offset in radians.
    pub phase_offset_radians: f32,
    /// Sine amplitude in raw units.
    pub amplitude: f32,
    /// Sine center offset in raw units.
    pub offset: f32,
    /// Minimum value used to derive `value01`.
    pub value_min: f32,
    /// Maximum value used to derive `value01`.
    pub value_max: f32,
    /// Timestamp for the first sample.
    pub start_timestamp_ms: u64,
    /// Raw value units.
    pub units: String,
    /// Producer quality class for generated samples.
    pub quality: ManifoldSampleQuality,
}

impl ManifoldSyntheticScalarOscillatorProfile {
    /// Generates deterministic scalar samples.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldSampleValidationError`] when the profile is invalid or
    /// generated samples would leave the declared raw or normalized bounds.
    pub fn generate_samples(
        &self,
    ) -> Result<Vec<ManifoldScalarF32Sample>, ManifoldSampleValidationError> {
        self.validate()?;
        let mut samples = Vec::with_capacity(self.sample_count as usize);
        let interval_ms = 1_000.0 / self.sample_rate_hz;

        for sequence_id in 0..self.sample_count {
            let time_seconds = sequence_id as f32 / self.sample_rate_hz;
            let phase = self.phase_offset_radians
                + core::f32::consts::TAU * self.frequency_hz * time_seconds;
            let value = round_f32(self.offset + self.amplitude * phase.sin(), 6);
            let value01 = round_f32(
                (value - self.value_min) / (self.value_max - self.value_min),
                6,
            );
            let timestamp_ms =
                self.start_timestamp_ms + round_f32(sequence_id as f32 * interval_ms, 0) as u64;
            let sample = ManifoldScalarF32Sample {
                schema_id: SchemaId::new("rusty.manifold.sample.scalar_f32.v1")
                    .expect("schema literal is valid"),
                stream_id: self.stream_id.clone(),
                source_module_id: self.source_module_id.clone(),
                sequence_id: u64::from(sequence_id),
                timestamp_domain: self.timestamp_domain.clone(),
                timestamp_ms,
                value,
                value01,
                units: self.units.clone(),
                quality: self.quality,
            };
            sample.validate()?;
            samples.push(sample);
        }

        Ok(samples)
    }

    /// Validates the profile without generating samples.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldSampleValidationError`] for invalid schema, timing,
    /// finite-value, or declared bound settings.
    pub fn validate(&self) -> Result<(), ManifoldSampleValidationError> {
        if self.schema_id.as_str() != "rusty.manifold.synthetic.scalar_oscillator_profile.v1" {
            return Err(ManifoldSampleValidationError::new(
                self.profile_id.clone(),
                self.schema_id.to_string(),
                ManifoldSampleValidationErrorKind::UnsupportedSchema,
            ));
        }
        if self.sample_count == 0 {
            return Err(ManifoldSampleValidationError::new(
                self.profile_id.clone(),
                self.sample_count.to_string(),
                ManifoldSampleValidationErrorKind::InvalidSampleCount,
            ));
        }
        if !self.sample_rate_hz.is_finite() || self.sample_rate_hz <= 0.0 {
            return Err(ManifoldSampleValidationError::new(
                self.profile_id.clone(),
                self.sample_rate_hz.to_string(),
                ManifoldSampleValidationErrorKind::InvalidSampleRate,
            ));
        }
        for (label, value) in [
            ("frequency_hz", self.frequency_hz),
            ("phase_offset_radians", self.phase_offset_radians),
            ("amplitude", self.amplitude),
            ("offset", self.offset),
            ("value_min", self.value_min),
            ("value_max", self.value_max),
        ] {
            if !value.is_finite() {
                return Err(ManifoldSampleValidationError::new(
                    self.profile_id.clone(),
                    format!("{label}={value}"),
                    ManifoldSampleValidationErrorKind::NonFiniteValue,
                ));
            }
        }
        if self.frequency_hz < 0.0 || self.amplitude < 0.0 {
            return Err(ManifoldSampleValidationError::new(
                self.profile_id.clone(),
                format!(
                    "frequency_hz={}, amplitude={}",
                    self.frequency_hz, self.amplitude
                ),
                ManifoldSampleValidationErrorKind::NegativeOscillatorParameter,
            ));
        }
        if self.value_min >= self.value_max {
            return Err(ManifoldSampleValidationError::new(
                self.profile_id.clone(),
                format!("{}..{}", self.value_min, self.value_max),
                ManifoldSampleValidationErrorKind::InvalidValueRange,
            ));
        }
        if self.offset - self.amplitude < self.value_min
            || self.offset + self.amplitude > self.value_max
        {
            return Err(ManifoldSampleValidationError::new(
                self.profile_id.clone(),
                format!(
                    "offset={} amplitude={} range={}..{}",
                    self.offset, self.amplitude, self.value_min, self.value_max
                ),
                ManifoldSampleValidationErrorKind::OscillatorLeavesDeclaredRange,
            ));
        }
        if self.units.trim().is_empty() {
            return Err(ManifoldSampleValidationError::new(
                self.profile_id.clone(),
                self.units.clone(),
                ManifoldSampleValidationErrorKind::EmptyUnits,
            ));
        }

        Ok(())
    }
}

/// Sample producer quality class.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldSampleQuality {
    /// Synthetic source used for deterministic testing and adapter bring-up.
    Synthetic,
    /// Live sensor or transport source.
    Live,
    /// Replay source from a recorded stream.
    Replay,
}

/// Scalar sample or synthetic-source validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldSampleValidationError {
    subject_id: DottedId,
    rejected_value: String,
    kind: ManifoldSampleValidationErrorKind,
}

impl ManifoldSampleValidationError {
    fn new(
        subject_id: DottedId,
        rejected_value: String,
        kind: ManifoldSampleValidationErrorKind,
    ) -> Self {
        Self {
            subject_id,
            rejected_value,
            kind,
        }
    }

    /// Returns the affected stream or profile id.
    #[must_use]
    pub fn subject_id(&self) -> &DottedId {
        &self.subject_id
    }

    /// Returns the rejected value.
    #[must_use]
    pub fn rejected_value(&self) -> &str {
        &self.rejected_value
    }

    /// Returns the validation failure kind.
    #[must_use]
    pub const fn kind(&self) -> ManifoldSampleValidationErrorKind {
        self.kind
    }

    /// Returns a stable rejection code.
    #[must_use]
    pub const fn rejection_code(&self) -> &'static str {
        match self.kind {
            ManifoldSampleValidationErrorKind::UnsupportedSchema => "unsupported_schema",
            ManifoldSampleValidationErrorKind::NonFiniteValue => "non_finite_value",
            ManifoldSampleValidationErrorKind::NormalizedValueOutOfRange => {
                "normalized_value_out_of_range"
            }
            ManifoldSampleValidationErrorKind::EmptyUnits => "empty_units",
            ManifoldSampleValidationErrorKind::InvalidSampleCount => "invalid_sample_count",
            ManifoldSampleValidationErrorKind::InvalidSampleRate => "invalid_sample_rate",
            ManifoldSampleValidationErrorKind::NegativeOscillatorParameter => {
                "negative_oscillator_parameter"
            }
            ManifoldSampleValidationErrorKind::InvalidValueRange => "invalid_value_range",
            ManifoldSampleValidationErrorKind::OscillatorLeavesDeclaredRange => {
                "oscillator_leaves_declared_range"
            }
        }
    }
}

impl fmt::Display for ManifoldSampleValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "sample validation {} rejected {}: {:?}",
            self.subject_id, self.rejected_value, self.kind
        )
    }
}

impl std::error::Error for ManifoldSampleValidationError {}

/// Scalar sample or synthetic-source validation failure kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldSampleValidationErrorKind {
    /// Schema id is not supported by this validator.
    UnsupportedSchema,
    /// A sample or profile float is NaN or infinite.
    NonFiniteValue,
    /// The normalized value is outside `0..=1`.
    NormalizedValueOutOfRange,
    /// Units string is empty.
    EmptyUnits,
    /// Sample count is zero.
    InvalidSampleCount,
    /// Sample rate is zero, negative, NaN, or infinite.
    InvalidSampleRate,
    /// Oscillator frequency or amplitude is negative.
    NegativeOscillatorParameter,
    /// Declared raw value range is empty or inverted.
    InvalidValueRange,
    /// Oscillator min or max would leave the declared raw value range.
    OscillatorLeavesDeclaredRange,
}

fn round_f32(value: f32, decimal_places: i32) -> f32 {
    let scale = 10_f32.powi(decimal_places);
    (value * scale).round() / scale
}
