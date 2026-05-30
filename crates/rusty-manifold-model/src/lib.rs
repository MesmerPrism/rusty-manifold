//! Core model primitives for Rusty Manifold contracts.
//!
//! This crate starts with the smallest shared vocabulary that other Manifold
//! crates can build on: stable identifiers, schema identifiers, and revisions.

mod contracts;

use core::fmt;
use core::str::FromStr;

pub use contracts::*;

/// A lowercase dotted identifier used for stable Manifold ids.
///
/// Each segment must start and end with an ASCII lowercase letter or digit.
/// Interior characters may also include `_` or `-`.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DottedId(String);

impl DottedId {
    /// Parses and validates a dotted identifier.
    ///
    /// # Errors
    ///
    /// Returns [`IdError`] when the value does not match the dotted-id grammar.
    pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
        let value = value.into();
        validate_dotted_id(&value)?;
        Ok(Self(value))
    }

    /// Returns the identifier as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DottedId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for DottedId {
    type Err = IdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for DottedId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for DottedId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// A schema identifier following `rusty.manifold.<family>.<name>.v<major>`.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SchemaId(DottedId);

impl SchemaId {
    /// Parses and validates a Manifold schema identifier.
    ///
    /// # Errors
    ///
    /// Returns [`SchemaIdError`] when the value is not a valid Manifold schema id.
    pub fn new(value: impl Into<String>) -> Result<Self, SchemaIdError> {
        let value = value.into();
        let dotted = DottedId::new(value.clone()).map_err(SchemaIdError::InvalidId)?;
        let parts: Vec<&str> = value.split('.').collect();

        if parts.len() < 5 || parts[0] != "rusty" || parts[1] != "manifold" {
            return Err(SchemaIdError::InvalidPrefix(value));
        }

        let version = parts.last().copied().unwrap_or_default();
        let digits = version.strip_prefix('v').unwrap_or_default();
        if digits.is_empty()
            || digits.starts_with('0')
            || !digits.chars().all(|c| c.is_ascii_digit())
        {
            return Err(SchemaIdError::InvalidVersion(value));
        }

        Ok(Self(dotted))
    }

    /// Returns the schema identifier as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for SchemaId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for SchemaId {
    type Err = SchemaIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for SchemaId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for SchemaId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// A monotonically increasing revision number.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Revision(u64);

impl Revision {
    /// The first accepted revision in a sequence.
    pub const INITIAL: Self = Self(1);

    /// Creates a non-zero revision.
    #[must_use]
    pub fn new(value: u64) -> Option<Self> {
        (value != 0).then_some(Self(value))
    }

    /// Returns the raw revision number.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Returns the next revision, or `None` on overflow.
    #[must_use]
    pub fn next(self) -> Option<Self> {
        self.0.checked_add(1).map(Self)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Revision {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u64(self.get())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Revision {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        Self::new(value).ok_or_else(|| serde::de::Error::custom("revision must be non-zero"))
    }
}

/// Identifier validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdError {
    value: String,
    reason: IdErrorReason,
}

impl IdError {
    /// Returns the rejected value.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Returns the rejection reason.
    #[must_use]
    pub const fn reason(&self) -> IdErrorReason {
        self.reason
    }
}

impl fmt::Display for IdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid dotted id {:?}: {:?}",
            self.value, self.reason
        )
    }
}

impl std::error::Error for IdError {}

/// Machine-readable identifier rejection reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdErrorReason {
    /// The full identifier is empty.
    Empty,
    /// One segment is empty.
    EmptySegment,
    /// A segment does not start or end with an ASCII lowercase letter or digit.
    InvalidStartOrEnd,
    /// A character is not allowed by the identifier grammar.
    InvalidCharacter,
}

/// Schema identifier validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SchemaIdError {
    /// The underlying dotted identifier is invalid.
    InvalidId(IdError),
    /// The required `rusty.manifold` prefix is missing.
    InvalidPrefix(String),
    /// The final `.v<major>` segment is invalid.
    InvalidVersion(String),
}

impl fmt::Display for SchemaIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidId(error) => write!(formatter, "{error}"),
            Self::InvalidPrefix(value) => {
                write!(
                    formatter,
                    "schema id {value:?} must start with rusty.manifold"
                )
            }
            Self::InvalidVersion(value) => {
                write!(
                    formatter,
                    "schema id {value:?} must end with a non-zero v<major>"
                )
            }
        }
    }
}

impl std::error::Error for SchemaIdError {}

fn validate_dotted_id(value: &str) -> Result<(), IdError> {
    if value.is_empty() {
        return Err(id_error(value, IdErrorReason::Empty));
    }

    for segment in value.split('.') {
        validate_segment(value, segment)?;
    }

    Ok(())
}

fn validate_segment(full_value: &str, segment: &str) -> Result<(), IdError> {
    if segment.is_empty() {
        return Err(id_error(full_value, IdErrorReason::EmptySegment));
    }

    let mut chars = segment.chars();
    let first = chars.next().expect("segment is non-empty");
    let last = segment.chars().last().expect("segment is non-empty");
    if !is_edge_char(first) || !is_edge_char(last) {
        return Err(id_error(full_value, IdErrorReason::InvalidStartOrEnd));
    }

    if !segment.chars().all(is_body_char) {
        return Err(id_error(full_value, IdErrorReason::InvalidCharacter));
    }

    Ok(())
}

fn id_error(value: &str, reason: IdErrorReason) -> IdError {
    IdError {
        value: value.to_owned(),
        reason,
    }
}

fn is_edge_char(character: char) -> bool {
    character.is_ascii_lowercase() || character.is_ascii_digit()
}

fn is_body_char(character: char) -> bool {
    is_edge_char(character) || character == '_' || character == '-'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dotted_id_accepts_expected_shapes() {
        for value in [
            "module.synthetic_provider",
            "stream.wave-1",
            "clock.host_monotonic",
            "transport.loopback",
        ] {
            assert_eq!(DottedId::new(value).unwrap().as_str(), value);
        }
    }

    #[test]
    fn dotted_id_rejects_invalid_shapes() {
        for value in [
            "",
            ".stream",
            "stream.",
            "stream..wave",
            "Stream.wave",
            "stream.wave!",
            "stream.-wave",
            "stream.wave_",
        ] {
            assert!(DottedId::new(value).is_err(), "{value}");
        }
    }

    #[test]
    fn schema_id_requires_manifold_prefix_and_major_version() {
        assert_eq!(
            SchemaId::new("rusty.manifold.host.manifest.v1")
                .unwrap()
                .as_str(),
            "rusty.manifold.host.manifest.v1"
        );
        assert!(SchemaId::new("rusty.other.host.manifest.v1").is_err());
        assert!(SchemaId::new("rusty.manifold.host.manifest.v0").is_err());
        assert!(SchemaId::new("rusty.manifold.host.manifest.v01").is_err());
    }

    #[test]
    fn revision_starts_at_one_and_advances() {
        assert_eq!(Revision::new(0), None);
        assert_eq!(Revision::INITIAL.get(), 1);
        assert_eq!(Revision::INITIAL.next().unwrap().get(), 2);
    }
}
