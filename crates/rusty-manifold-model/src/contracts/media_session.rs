//! Source-neutral accepted media-session binding.

use std::collections::BTreeSet;

use crate::{DottedId, Revision, SchemaId};

/// Accepted source-neutral media-session descriptor schema.
pub const MANIFOLD_MEDIA_SESSION_SCHEMA: &str = "rusty.manifold.media.session_descriptor.v1";
/// Required plane for high-rate media carried outside Manifold JSON.
pub const MANIFOLD_BINARY_MEDIA_PLANE: &str = "binary-media";

/// Manifold-owned binding between accepted session/stream state and one
/// platform runtime spec. It contains references only and never media bytes.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldMediaSessionDescriptor {
    /// Schema identifier.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Accepted Manifold session identity.
    pub session_id: DottedId,
    /// Accepted authority revision that owns this descriptor.
    pub authority_revision: Revision,
    /// Platform runtime spec selected by the accepted application.
    pub platform_runtime_spec_id: DottedId,
    /// Source descriptor references.
    pub source_ids: Vec<DottedId>,
    /// Processor descriptor references.
    pub processor_ids: Vec<DottedId>,
    /// Route descriptor references.
    pub route_ids: Vec<DottedId>,
    /// Sink descriptor references.
    pub sink_ids: Vec<DottedId>,
    /// Accepted Manifold stream identities.
    pub stream_ids: Vec<DottedId>,
    /// High-rate payload plane; must be `binary-media`.
    pub payload_plane: String,
    /// Inline media is forbidden in the low-rate descriptor.
    pub inline_media_payloads_allowed: bool,
    /// Whether a legacy remote-camera contract is projected through an
    /// explicit compatibility adapter.
    pub remote_camera_compatibility: bool,
}

/// Validation failure for a source-neutral media-session descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldMediaSessionValidationError {
    /// Display-safe validation message.
    pub message: String,
}

impl ManifoldMediaSessionValidationError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl ManifoldMediaSessionDescriptor {
    /// Validate reference completeness, uniqueness, and the control/data-plane boundary.
    pub fn validate(&self) -> Result<(), Vec<ManifoldMediaSessionValidationError>> {
        let mut errors = Vec::new();
        if self.schema_id.as_str() != MANIFOLD_MEDIA_SESSION_SCHEMA {
            errors.push(ManifoldMediaSessionValidationError::new(
                "unsupported Manifold media-session schema",
            ));
        }
        for (label, values) in [
            ("source_ids", &self.source_ids),
            ("processor_ids", &self.processor_ids),
            ("route_ids", &self.route_ids),
            ("sink_ids", &self.sink_ids),
            ("stream_ids", &self.stream_ids),
        ] {
            if values.is_empty() {
                errors.push(ManifoldMediaSessionValidationError::new(format!(
                    "{label} must not be empty"
                )));
            }
            let unique = values.iter().collect::<BTreeSet<_>>();
            if unique.len() != values.len() {
                errors.push(ManifoldMediaSessionValidationError::new(format!(
                    "{label} must not contain duplicates"
                )));
            }
        }
        if self.payload_plane != MANIFOLD_BINARY_MEDIA_PLANE {
            errors.push(ManifoldMediaSessionValidationError::new(
                "media sessions must reference the binary-media data plane",
            ));
        }
        if self.inline_media_payloads_allowed {
            errors.push(ManifoldMediaSessionValidationError::new(
                "Manifold media-session descriptors must not carry inline media payloads",
            ));
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: &str) -> DottedId {
        DottedId::new(value).expect("valid id")
    }

    fn descriptor() -> ManifoldMediaSessionDescriptor {
        ManifoldMediaSessionDescriptor {
            schema_id: SchemaId::new(MANIFOLD_MEDIA_SESSION_SCHEMA).expect("valid schema"),
            session_id: id("session.media.example"),
            authority_revision: Revision::new(4).expect("revision"),
            platform_runtime_spec_id: id("runtime.media.example"),
            source_ids: vec![id("source.camera.left"), id("source.camera.right")],
            processor_ids: vec![id("processor.dual-lane")],
            route_ids: vec![id("route.direct-p2p.left"), id("route.direct-p2p.right")],
            sink_ids: vec![id("sink.native-openxr")],
            stream_ids: vec![id("stream.media.left"), id("stream.media.right")],
            payload_plane: MANIFOLD_BINARY_MEDIA_PLANE.to_string(),
            inline_media_payloads_allowed: false,
            remote_camera_compatibility: false,
        }
    }

    #[test]
    fn source_neutral_descriptor_validates() {
        descriptor().validate().expect("descriptor validates");
    }

    #[test]
    fn inline_media_and_duplicate_refs_fail_closed() {
        let mut value = descriptor();
        value.inline_media_payloads_allowed = true;
        value.source_ids.push(value.source_ids[0].clone());
        let errors = value.validate().expect_err("damaged descriptor rejects");
        assert!(errors
            .iter()
            .any(|error| error.message.contains("inline media")));
        assert!(errors
            .iter()
            .any(|error| error.message.contains("duplicates")));
    }
}
