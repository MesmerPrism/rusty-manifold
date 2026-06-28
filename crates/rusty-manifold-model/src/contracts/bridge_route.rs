use core::fmt;

use super::*;

/// Static descriptor for one low-rate or high-rate bridge route.
///
/// A bridge route names what kind of truth a transport is allowed to carry.
/// It does not open sockets, publish samples, execute commands, contact hosts,
/// or adopt media frames.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldBridgeRouteDescriptor {
    /// Schema identifier for this descriptor.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable bridge-route id.
    pub route_id: DottedId,
    /// Intent of the route.
    pub route_kind: ManifoldBridgeRouteKind,
    /// Plane this route belongs to.
    pub plane: ManifoldBridgePlane,
    /// Transport family selected by an adapter.
    pub transport_family: ManifoldBridgeTransportFamily,
    /// Delivery semantics the route can claim.
    pub delivery: ManifoldBridgeDeliverySemantics,
    /// Payload class carried by this route.
    pub payload_class: ManifoldBridgePayloadClass,
    /// Expected rate class for this route.
    pub rate_class: StreamRateClass,
    /// Authority role of this route.
    pub authority_role: ManifoldBridgeAuthorityRole,
    /// Evidence stages required before the route result can be accepted.
    pub required_evidence_stages: Vec<ManifoldBridgeEvidenceStage>,
    /// Fallback route ids, if any.
    #[cfg_attr(feature = "serde", serde(default))]
    pub fallback_route_ids: Vec<DottedId>,
    /// Machine-readable issue codes this route may emit.
    #[cfg_attr(feature = "serde", serde(default))]
    pub issue_codes: Vec<DottedId>,
}

impl ManifoldBridgeRouteDescriptor {
    /// Validates the static route shape.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldBridgeRouteValidationError`] when the descriptor
    /// schema, plane/payload pairing, or required evidence policy is invalid.
    pub fn validate_shape(&self) -> Result<(), ManifoldBridgeRouteValidationError> {
        if self.schema_id.as_str() != "rusty.manifold.bridge.route_descriptor.v1" {
            return Err(ManifoldBridgeRouteValidationError::new(
                self.route_id.clone(),
                self.schema_id.to_string(),
                ManifoldBridgeRouteValidationErrorKind::UnsupportedSchema,
            ));
        }

        if self.required_evidence_stages.is_empty() {
            return Err(ManifoldBridgeRouteValidationError::new(
                self.route_id.clone(),
                "required_evidence_stages".to_owned(),
                ManifoldBridgeRouteValidationErrorKind::MissingRequiredEvidence,
            ));
        }

        if self.payload_class == ManifoldBridgePayloadClass::MediaFrame
            && self.plane == ManifoldBridgePlane::Control
        {
            return Err(ManifoldBridgeRouteValidationError::new(
                self.route_id.clone(),
                "media_frame_on_control_plane".to_owned(),
                ManifoldBridgeRouteValidationErrorKind::PlanePayloadMismatch,
            ));
        }

        if self.delivery == ManifoldBridgeDeliverySemantics::AppliedReceiptRequired
            && (!self
                .required_evidence_stages
                .contains(&ManifoldBridgeEvidenceStage::RuntimeAccepted)
                || !self
                    .required_evidence_stages
                    .contains(&ManifoldBridgeEvidenceStage::Applied))
        {
            return Err(ManifoldBridgeRouteValidationError::new(
                self.route_id.clone(),
                "applied_receipt_required".to_owned(),
                ManifoldBridgeRouteValidationErrorKind::MissingRequiredEvidence,
            ));
        }

        Ok(())
    }

    /// Validates evidence collected for this bridge route.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldBridgeRouteValidationError`] when the evidence does
    /// not match this route or does not satisfy the route's required evidence stages.
    pub fn validate_evidence_summary(
        &self,
        evidence: &ManifoldBridgeRouteEvidence,
    ) -> Result<(), ManifoldBridgeRouteValidationError> {
        self.validate_shape()?;

        if evidence.schema_id.as_str() != "rusty.manifold.bridge.route_evidence.v1" {
            return Err(ManifoldBridgeRouteValidationError::new(
                self.route_id.clone(),
                evidence.schema_id.to_string(),
                ManifoldBridgeRouteValidationErrorKind::UnsupportedSchema,
            ));
        }

        if evidence.route_id != self.route_id {
            return Err(ManifoldBridgeRouteValidationError::new(
                self.route_id.clone(),
                evidence.route_id.to_string(),
                ManifoldBridgeRouteValidationErrorKind::RouteMismatch,
            ));
        }

        for required_stage in &self.required_evidence_stages {
            if !evidence.stage_passed(*required_stage) {
                return Err(ManifoldBridgeRouteValidationError::new(
                    self.route_id.clone(),
                    format!("{required_stage:?}").to_ascii_lowercase(),
                    ManifoldBridgeRouteValidationErrorKind::MissingRequiredEvidence,
                ));
            }
        }

        let failed_stage_count = evidence
            .stage_reports
            .iter()
            .filter(|stage| stage.status == ValidationStatus::Fail)
            .count();
        let status_consistent = match evidence.status {
            ValidationStatus::Pass => failed_stage_count == 0 && evidence.issues.is_empty(),
            ValidationStatus::Warn => failed_stage_count == 0,
            ValidationStatus::Fail => failed_stage_count > 0 || !evidence.issues.is_empty(),
        };
        if !status_consistent {
            return Err(ManifoldBridgeRouteValidationError::new(
                self.route_id.clone(),
                evidence.evidence_id.to_string(),
                ManifoldBridgeRouteValidationErrorKind::StatusMismatch,
            ));
        }

        Ok(())
    }
}

/// Evidence summary for one bridge-route run or captured fixture.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldBridgeRouteEvidence {
    /// Schema identifier for this evidence summary.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable evidence id.
    pub evidence_id: DottedId,
    /// Route this evidence belongs to.
    pub route_id: DottedId,
    /// Overall route status.
    pub status: ValidationStatus,
    /// Timestamp when collection started.
    pub started_at_ms: u64,
    /// Timestamp when collection ended.
    pub ended_at_ms: u64,
    /// Per-stage evidence reports.
    pub stage_reports: Vec<ManifoldBridgeEvidenceStageReport>,
    /// Artifact ids or relative artifact refs collected by the adapter.
    #[cfg_attr(feature = "serde", serde(default))]
    pub artifact_refs: Vec<DottedId>,
    /// Issues found while collecting or interpreting evidence.
    #[cfg_attr(feature = "serde", serde(default))]
    pub issues: Vec<ManifoldIssue>,
}

impl ManifoldBridgeRouteEvidence {
    fn stage_passed(&self, stage: ManifoldBridgeEvidenceStage) -> bool {
        self.stage_reports
            .iter()
            .any(|report| report.stage == stage && report.status != ValidationStatus::Fail)
    }
}

/// Evidence for one bridge-route lifecycle stage.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldBridgeEvidenceStageReport {
    /// Bridge route stage.
    pub stage: ManifoldBridgeEvidenceStage,
    /// Stage status.
    pub status: ValidationStatus,
    /// Stage observation timestamp, when known.
    pub observed_at_ms: Option<u64>,
    /// Evidence refs backing this stage.
    #[cfg_attr(feature = "serde", serde(default))]
    pub evidence_refs: Vec<DottedId>,
    /// Issue codes attached to this stage.
    #[cfg_attr(feature = "serde", serde(default))]
    pub issue_codes: Vec<DottedId>,
}

/// Intent class for a bridge route.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldBridgeRouteKind {
    /// Mutating or read command that should produce command feedback.
    Command,
    /// Runtime settings or hotload proposal.
    RuntimeSettings,
    /// Study, experiment, or synchronization marker.
    Marker,
    /// Low-rate telemetry or state.
    Telemetry,
    /// Host/device management operation.
    DeviceManagement,
    /// Media session start, stop, or status command.
    MediaSessionControl,
    /// High-rate media payload route.
    MediaPayload,
    /// Artifact or diagnostics evidence route.
    ArtifactEvidence,
    /// App panel, questionnaire, or small operator panel interaction.
    PanelInteraction,
}

/// Plane used by a bridge route.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldBridgePlane {
    /// Low-rate command/control.
    Control,
    /// Low-rate telemetry.
    Telemetry,
    /// Generic data plane.
    Data,
    /// High-rate media data plane.
    MediaData,
    /// Render adoption or applied visual state.
    RenderAdoption,
    /// Evidence/artifact plane.
    Evidence,
    /// Feedback and health plane.
    Feedback,
}

/// Transport family used by an adapter.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldBridgeTransportFamily {
    /// In-process call path.
    InProcess,
    /// Standard input/output.
    Stdio,
    /// HTTP request/response.
    Http,
    /// WebSocket route.
    WebSocket,
    /// UDP datagram route.
    Udp,
    /// OSC over datagram transport.
    Osc,
    /// Lab Streaming Layer route.
    Lsl,
    /// ADB or compatible device-management route.
    Adb,
    /// File, app-private staging, or hotload-file route.
    File,
    /// Dedicated high-rate media data plane.
    MediaDataPlane,
    /// Externally managed platform tooling.
    PlatformTooling,
    /// Manual operator action.
    Manual,
}

/// Delivery semantics a route can claim.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldBridgeDeliverySemantics {
    /// Message may be dropped or arrive out of order.
    BestEffort,
    /// Transport preserves ordering for accepted messages.
    Ordered,
    /// Transport returns an acknowledgement.
    TransportAcknowledged,
    /// Manifold authority review is required.
    AuthorityReviewed,
    /// Runtime applied receipt is required.
    AppliedReceiptRequired,
    /// Artifact capture and integrity evidence are required.
    ArtifactCaptured,
}

/// Payload class carried by a bridge route.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldBridgePayloadClass {
    /// Manifold command envelope or compatible command message.
    CommandEnvelope,
    /// Runtime settings profile, hotload, or proposal.
    RuntimeSettings,
    /// Scalar or low-rate sample.
    ScalarSample,
    /// Marker or synchronization event.
    Marker,
    /// Host or device-management command.
    DeviceCommand,
    /// Media session control message.
    MediaControl,
    /// Encoded or raw media frame.
    MediaFrame,
    /// Artifact manifest or evidence pointer.
    ArtifactManifest,
    /// Panel, questionnaire, or UI command.
    PanelCommand,
}

/// Authority role of the bridge route.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldBridgeAuthorityRole {
    /// Route carries Manifold authority decisions.
    Authority,
    /// Route adapts to an authority owned elsewhere.
    Adapter,
    /// Route observes state only.
    Observer,
    /// Route captures evidence only.
    EvidenceOnly,
}

/// Stage in a bridge-route evidence chain.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldBridgeEvidenceStage {
    /// Adapter attempted to send or publish the payload.
    Sent,
    /// Transport accepted or acknowledged the payload.
    TransportOk,
    /// Manifold or another declared authority accepted the request.
    AuthorityAccepted,
    /// Runtime consumer accepted the request.
    RuntimeAccepted,
    /// Runtime consumer reported the value or command as applied.
    Applied,
    /// Independent observation confirmed the expected state.
    Observed,
    /// Runtime, authority, or adapter rejected the request.
    Rejected,
    /// Evidence was stale or outside the route TTL.
    Stale,
    /// Artifact was captured and referenced.
    ArtifactCaptured,
}

/// Bridge-route descriptor or evidence validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldBridgeRouteValidationError {
    route_id: DottedId,
    rejected_value: String,
    kind: ManifoldBridgeRouteValidationErrorKind,
}

impl ManifoldBridgeRouteValidationError {
    fn new(
        route_id: DottedId,
        rejected_value: String,
        kind: ManifoldBridgeRouteValidationErrorKind,
    ) -> Self {
        Self {
            route_id,
            rejected_value,
            kind,
        }
    }

    /// Returns the affected bridge-route id.
    #[must_use]
    pub fn route_id(&self) -> &DottedId {
        &self.route_id
    }

    /// Returns the rejected value.
    #[must_use]
    pub fn rejected_value(&self) -> &str {
        &self.rejected_value
    }

    /// Returns the failure kind.
    #[must_use]
    pub const fn kind(&self) -> ManifoldBridgeRouteValidationErrorKind {
        self.kind
    }

    /// Returns a stable rejection code.
    #[must_use]
    pub const fn rejection_code(&self) -> &'static str {
        match self.kind {
            ManifoldBridgeRouteValidationErrorKind::UnsupportedSchema => "unsupported_schema",
            ManifoldBridgeRouteValidationErrorKind::RouteMismatch => "route_mismatch",
            ManifoldBridgeRouteValidationErrorKind::MissingRequiredEvidence => {
                "missing_required_evidence"
            }
            ManifoldBridgeRouteValidationErrorKind::StatusMismatch => "status_mismatch",
            ManifoldBridgeRouteValidationErrorKind::PlanePayloadMismatch => {
                "plane_payload_mismatch"
            }
        }
    }
}

impl fmt::Display for ManifoldBridgeRouteValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "bridge route {} rejected {}: {:?}",
            self.route_id, self.rejected_value, self.kind
        )
    }
}

impl std::error::Error for ManifoldBridgeRouteValidationError {}

/// Bridge-route descriptor or evidence validation failure kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldBridgeRouteValidationErrorKind {
    /// The schema id is not supported.
    UnsupportedSchema,
    /// Evidence references a different route.
    RouteMismatch,
    /// Required route evidence is missing or failed.
    MissingRequiredEvidence,
    /// Evidence status, stages, and issues disagree.
    StatusMismatch,
    /// Payload class is not valid for the selected plane.
    PlanePayloadMismatch,
}
