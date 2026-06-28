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
    /// Environment, device, runtime, and dependency state required before this
    /// route can produce meaningful evidence.
    #[cfg_attr(feature = "serde", serde(default))]
    pub required_conditions: Vec<ManifoldBridgeConditionRequirement>,
    /// Timing and latency evidence policy for this route.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub timing: Option<ManifoldBridgeTimingPolicy>,
    /// ZeroMQ-specific route profile when `transport_family` is `zeromq`.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub zeromq: Option<ManifoldZeroMqRouteProfile>,
    /// LSL-specific route profile when `transport_family` is `lsl`.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub lsl: Option<ManifoldLslRouteProfile>,
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

        match (&self.transport_family, &self.zeromq, &self.lsl) {
            (ManifoldBridgeTransportFamily::ZeroMq, Some(profile), None) => {
                profile.validate_shape(&self.route_id)?;
            }
            (ManifoldBridgeTransportFamily::ZeroMq, None, _) => {
                return Err(ManifoldBridgeRouteValidationError::new(
                    self.route_id.clone(),
                    "zeromq".to_owned(),
                    ManifoldBridgeRouteValidationErrorKind::MissingTransportProfile,
                ));
            }
            (ManifoldBridgeTransportFamily::Lsl, None, Some(profile)) => {
                profile.validate_shape(&self.route_id)?;
            }
            (ManifoldBridgeTransportFamily::Lsl, _, None) => {
                return Err(ManifoldBridgeRouteValidationError::new(
                    self.route_id.clone(),
                    "lsl".to_owned(),
                    ManifoldBridgeRouteValidationErrorKind::MissingTransportProfile,
                ));
            }
            (_, Some(_), _) => {
                return Err(ManifoldBridgeRouteValidationError::new(
                    self.route_id.clone(),
                    "zeromq".to_owned(),
                    ManifoldBridgeRouteValidationErrorKind::TransportProfileMismatch,
                ));
            }
            (_, _, Some(_)) => {
                return Err(ManifoldBridgeRouteValidationError::new(
                    self.route_id.clone(),
                    "lsl".to_owned(),
                    ManifoldBridgeRouteValidationErrorKind::TransportProfileMismatch,
                ));
            }
            (_, None, None) => {}
        }

        if self.requires_operational_context() && self.required_conditions.is_empty() {
            return Err(ManifoldBridgeRouteValidationError::new(
                self.route_id.clone(),
                "required_conditions".to_owned(),
                ManifoldBridgeRouteValidationErrorKind::MissingRequiredCondition,
            ));
        }

        for condition in &self.required_conditions {
            condition.validate_shape(&self.route_id)?;
        }

        if self.requires_operational_context() && self.timing.is_none() {
            return Err(ManifoldBridgeRouteValidationError::new(
                self.route_id.clone(),
                "timing".to_owned(),
                ManifoldBridgeRouteValidationErrorKind::MissingTimingPolicy,
            ));
        }

        if let Some(timing) = &self.timing {
            timing.validate_shape(&self.route_id)?;
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

    fn requires_operational_context(&self) -> bool {
        matches!(
            self.transport_family,
            ManifoldBridgeTransportFamily::Http
                | ManifoldBridgeTransportFamily::WebSocket
                | ManifoldBridgeTransportFamily::Udp
                | ManifoldBridgeTransportFamily::Osc
                | ManifoldBridgeTransportFamily::Lsl
                | ManifoldBridgeTransportFamily::ZeroMq
                | ManifoldBridgeTransportFamily::BluetoothRfcomm
                | ManifoldBridgeTransportFamily::BluetoothGatt
                | ManifoldBridgeTransportFamily::Adb
                | ManifoldBridgeTransportFamily::File
                | ManifoldBridgeTransportFamily::MediaDataPlane
                | ManifoldBridgeTransportFamily::PlatformTooling
        )
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
    /// Stream packet bridge to another data protocol.
    StreamBridge,
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
    /// ZeroMQ socket route.
    #[cfg_attr(feature = "serde", serde(rename = "zeromq"))]
    ZeroMq,
    /// Bluetooth Classic RFCOMM socket route.
    BluetoothRfcomm,
    /// Bluetooth Low Energy GATT route.
    BluetoothGatt,
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
    /// Bounded stream packet or message payload.
    StreamPacket,
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

/// Required condition for a bridge-route test environment.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldBridgeConditionRequirement {
    /// Stable condition id used by readiness reports and UI panels.
    pub condition_id: DottedId,
    /// Area that owns or observes this condition.
    pub scope: ManifoldBridgeConditionScope,
    /// Kind of state that must be checked.
    pub kind: ManifoldBridgeConditionKind,
    /// Required state before the test can be interpreted.
    pub required_state: ManifoldBridgeConditionState,
    /// Stable check id that an adapter or readiness module should run.
    pub check_ref: DottedId,
    /// Optional issue codes emitted when the condition is not met.
    #[cfg_attr(feature = "serde", serde(default))]
    pub issue_codes: Vec<DottedId>,
    /// Optional remediation action shown by operator UIs.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub remediation: Option<ManifoldBridgeConditionRemediation>,
}

impl ManifoldBridgeConditionRequirement {
    fn validate_shape(
        &self,
        route_id: &DottedId,
    ) -> Result<(), ManifoldBridgeRouteValidationError> {
        if let Some(remediation) = &self.remediation {
            if remediation.operator_label.trim().is_empty() {
                return Err(ManifoldBridgeRouteValidationError::new(
                    route_id.clone(),
                    self.condition_id.to_string(),
                    ManifoldBridgeRouteValidationErrorKind::InvalidRequiredCondition,
                ));
            }
        }

        Ok(())
    }
}

/// Remediation action for an unmet route condition.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldBridgeConditionRemediation {
    /// Stable remediation action id.
    pub action_ref: DottedId,
    /// Human-facing action label for UI rendering.
    pub operator_label: String,
}

/// Scope of a bridge-route required condition.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldBridgeConditionScope {
    /// PC or host state.
    Host,
    /// Quest, phone, sensor, or other device state.
    Device,
    /// LAN, Wi-Fi, USB tunnel, or radio topology.
    Network,
    /// Runtime app, broker, or subscriber state.
    Runtime,
    /// CLI, native library, package, or SDK dependency.
    Tooling,
    /// Broker route or message bus state.
    Broker,
    /// Firewall, permission, pairing, or authorization state.
    Security,
    /// Protocol-specific readiness not owned by one host.
    Protocol,
    /// Operator-supplied setup or fixture condition.
    Operator,
}

/// Kind of state that a route condition requires.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldBridgeConditionKind {
    /// Host-side executable, SDK, DLL, or shared library is installed.
    HostDependencyInstalled,
    /// Protocol library is loadable by the process that will run the adapter.
    ProtocolLibraryAvailable,
    /// Native device/runtime library is loadable on the target device.
    NativeLibraryAvailable,
    /// Host port can be bound by the service under test.
    HostPortAvailable,
    /// Host firewall allows inbound traffic for the program and port.
    HostFirewallInboundAllowed,
    /// Host firewall allows outbound traffic for the program and port.
    HostFirewallOutboundAllowed,
    /// Host network profile is trusted/private for the intended test.
    NetworkProfileTrusted,
    /// Host and device are on the same reachable LAN.
    SameLanReachable,
    /// Multicast or broadcast discovery is allowed by the topology.
    MulticastAllowed,
    /// A TCP endpoint can be reached.
    TcpEndpointReachable,
    /// A UDP datagram can reach the opposite endpoint.
    UdpDatagramReachable,
    /// WebSocket endpoint can connect and complete handshake.
    WebSocketEndpointReachable,
    /// ADB sees the device as online.
    AdbDeviceOnline,
    /// ADB forward or reverse route is active.
    AdbForwardActive,
    /// Android package is installed.
    AndroidPackageInstalled,
    /// Android permission is granted.
    AndroidPermissionGranted,
    /// App-private or diagnostic storage is writable.
    StorageWritable,
    /// Broker route exists and is ready.
    BrokerRouteReady,
    /// Runtime subscriber, echo service, or consumer is active.
    RuntimeSubscriberActive,
    /// Bluetooth host adapter is enabled.
    BluetoothAdapterEnabled,
    /// Bluetooth device is paired or bonded.
    BluetoothDevicePaired,
    /// BLE GATT service is visible.
    BluetoothGattServiceAvailable,
    /// BLE GATT characteristic is visible and has the expected properties.
    BluetoothCharacteristicAvailable,
    /// Bluetooth Classic RFCOMM channel is available.
    BluetoothRfcommChannelAvailable,
    /// Media codec or media-plane dependency is available.
    MediaCodecAvailable,
    /// Parallel timing route is available for clock alignment.
    ClockReferenceRouteAvailable,
}

/// Required state for a route condition.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldBridgeConditionState {
    /// Dependency or object exists.
    Present,
    /// Endpoint or device can be reached.
    Reachable,
    /// Feature, service, or adapter is enabled.
    Enabled,
    /// Security policy permits the route.
    Allowed,
    /// Package or dependency is installed.
    Installed,
    /// Runtime path is active.
    Active,
    /// Port, listener, or endpoint is bound.
    Bound,
    /// Bluetooth peer is paired or bonded.
    Paired,
    /// Resource is available for the test window.
    Available,
}

/// Timing and latency evidence policy for a bridge route.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldBridgeTimingPolicy {
    /// How this route should produce round-trip or clock-alignment evidence.
    pub rtt_strategy: ManifoldBridgeRttStrategy,
    /// Clock domain used for timestamps in this route's evidence.
    pub clock_domain: DottedId,
    /// Optional LSL clock route used in parallel with this protocol.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub parallel_clock_route_id: Option<DottedId>,
    /// Minimum completed round trips expected when RTT is possible.
    pub min_round_trips: u32,
    /// Timeout for the timing probe.
    pub timeout_ms: u32,
    /// Optional warmup window before timing samples are scored.
    pub warmup_ms: u32,
    /// Metrics the adapter must report when evidence is collected.
    #[cfg_attr(feature = "serde", serde(default))]
    pub reported_metrics: Vec<ManifoldBridgeTimingMetric>,
}

impl ManifoldBridgeTimingPolicy {
    fn validate_shape(
        &self,
        route_id: &DottedId,
    ) -> Result<(), ManifoldBridgeRouteValidationError> {
        if self.rtt_strategy == ManifoldBridgeRttStrategy::NotAvailable {
            if self.min_round_trips != 0
                || self.timeout_ms != 0
                || self.parallel_clock_route_id.is_some()
                || !self.reported_metrics.is_empty()
            {
                return Err(ManifoldBridgeRouteValidationError::new(
                    route_id.clone(),
                    "rtt_strategy=not_available".to_owned(),
                    ManifoldBridgeRouteValidationErrorKind::InvalidTimingPolicy,
                ));
            }
            return Ok(());
        }

        if self.min_round_trips == 0 || self.timeout_ms == 0 || self.reported_metrics.is_empty() {
            return Err(ManifoldBridgeRouteValidationError::new(
                route_id.clone(),
                format!(
                    "min_round_trips={} timeout_ms={} reported_metrics={}",
                    self.min_round_trips,
                    self.timeout_ms,
                    self.reported_metrics.len()
                ),
                ManifoldBridgeRouteValidationErrorKind::InvalidTimingPolicy,
            ));
        }

        if self.rtt_strategy == ManifoldBridgeRttStrategy::ParallelLslClockEcho
            && self.parallel_clock_route_id.is_none()
        {
            return Err(ManifoldBridgeRouteValidationError::new(
                route_id.clone(),
                "parallel_clock_route_id".to_owned(),
                ManifoldBridgeRouteValidationErrorKind::InvalidTimingPolicy,
            ));
        }

        if self.rtt_strategy != ManifoldBridgeRttStrategy::ParallelLslClockEcho
            && self.parallel_clock_route_id.is_some()
        {
            return Err(ManifoldBridgeRouteValidationError::new(
                route_id.clone(),
                "parallel_clock_route_id".to_owned(),
                ManifoldBridgeRouteValidationErrorKind::InvalidTimingPolicy,
            ));
        }

        Ok(())
    }
}

/// Route RTT or clock-alignment strategy.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldBridgeRttStrategy {
    /// RTT is not meaningful for this route.
    NotAvailable,
    /// Transport-level echo or ping is used.
    TransportEcho,
    /// Command or settings applied receipt is used as the echo.
    AppliedReceiptEcho,
    /// Protocol-native time-correction or clock-sync report is used.
    ProtocolClockCorrection,
    /// Runtime app echoes the payload through the same protocol.
    NativeRoundTrip,
    /// A parallel LSL clock echo route supplies timing alignment.
    ParallelLslClockEcho,
}

/// Timing metrics a route adapter should report.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldBridgeTimingMetric {
    /// Round-trip latency in milliseconds.
    RttMs,
    /// One-way latency estimate in milliseconds.
    OneWayEstimateMs,
    /// Clock offset estimate in milliseconds.
    ClockOffsetMs,
    /// Clock correction uncertainty in milliseconds.
    ClockUncertaintyMs,
    /// Inter-sample or inter-packet jitter in milliseconds.
    JitterMs,
    /// Samples or packets lost in the scored window.
    SampleLoss,
    /// Queueing delay in milliseconds.
    QueueDelayMs,
}

/// LSL-specific route metadata for stream adapters.
///
/// This is still a descriptor. It does not load `liblsl`, resolve streams,
/// create inlets/outlets, publish samples, or allocate runtime buffers.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldLslRouteProfile {
    /// LSL stream name.
    pub stream_name: String,
    /// LSL stream type.
    pub stream_type: String,
    /// Optional LSL source id when the producer can provide one.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub source_id: Option<String>,
    /// Which side of the route this profile describes.
    pub endpoint_role: ManifoldLslEndpointRole,
    /// How a runtime should resolve the stream.
    pub resolve_policy: ManifoldLslResolvePolicy,
    /// Number of LSL channels.
    pub channel_count: u32,
    /// Channel format.
    pub channel_format: ManifoldLslChannelFormat,
    /// Optional channel labels, in channel order.
    #[cfg_attr(feature = "serde", serde(default))]
    pub channel_labels: Vec<String>,
    /// Sample-rate policy. `Irregular` maps to LSL nominal sample rate 0.
    pub sample_rate_policy: ManifoldLslSampleRatePolicy,
    /// Timestamp/time-correction policy expected from the adapter.
    pub clock_policy: ManifoldLslClockPolicy,
    /// Maximum expected discovery time before the route is considered blocked.
    pub resolve_timeout_ms: u32,
    /// Maximum expected sample pull/push wait for diagnostics.
    pub sample_timeout_ms: u32,
    /// Optional warmup window before pass/fail sample collection begins.
    pub warmup_ms: u32,
    /// Minimum sample count expected in the validation window.
    pub min_samples: u32,
}

impl ManifoldLslRouteProfile {
    fn validate_shape(
        &self,
        route_id: &DottedId,
    ) -> Result<(), ManifoldBridgeRouteValidationError> {
        if self.stream_name.trim().is_empty() || self.stream_type.trim().is_empty() {
            return Err(ManifoldBridgeRouteValidationError::new(
                route_id.clone(),
                format!("{} / {}", self.stream_name, self.stream_type),
                ManifoldBridgeRouteValidationErrorKind::InvalidTransportProfile,
            ));
        }

        if self.channel_count == 0 {
            return Err(ManifoldBridgeRouteValidationError::new(
                route_id.clone(),
                "channel_count=0".to_owned(),
                ManifoldBridgeRouteValidationErrorKind::InvalidTransportProfile,
            ));
        }

        if !self.channel_labels.is_empty()
            && self.channel_labels.len() != self.channel_count as usize
        {
            return Err(ManifoldBridgeRouteValidationError::new(
                route_id.clone(),
                format!(
                    "channel_labels={} channel_count={}",
                    self.channel_labels.len(),
                    self.channel_count
                ),
                ManifoldBridgeRouteValidationErrorKind::InvalidTransportProfile,
            ));
        }

        if self.resolve_timeout_ms == 0 || self.sample_timeout_ms == 0 {
            return Err(ManifoldBridgeRouteValidationError::new(
                route_id.clone(),
                format!(
                    "resolve_timeout_ms={} sample_timeout_ms={}",
                    self.resolve_timeout_ms, self.sample_timeout_ms
                ),
                ManifoldBridgeRouteValidationErrorKind::InvalidTransportProfile,
            ));
        }

        if self.min_samples == 0 {
            return Err(ManifoldBridgeRouteValidationError::new(
                route_id.clone(),
                "min_samples=0".to_owned(),
                ManifoldBridgeRouteValidationErrorKind::InvalidTransportProfile,
            ));
        }

        Ok(())
    }
}

/// LSL endpoint role described by a route profile.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldLslEndpointRole {
    /// Local adapter creates an LSL outlet.
    Outlet,
    /// Local adapter resolves and reads an LSL inlet.
    Inlet,
    /// Route evidence composes an outlet and matching echo/inlet.
    RoundTrip,
}

/// LSL stream resolution policy.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldLslResolvePolicy {
    /// Resolve by stream name.
    Name,
    /// Resolve by stream type.
    StreamType,
    /// Resolve by source id.
    SourceId,
    /// Resolve by name and type.
    NameAndType,
    /// Adapter supplies a predicate.
    Predicate,
}

/// LSL channel format.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldLslChannelFormat {
    /// 32-bit floating-point channel.
    Float32,
    /// 64-bit floating-point channel.
    Double64,
    /// 32-bit signed integer channel.
    Int32,
    /// 16-bit signed integer channel.
    Int16,
    /// 8-bit signed integer channel.
    Int8,
    /// UTF-8 string channel.
    String,
}

/// LSL sample-rate policy.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldLslSampleRatePolicy {
    /// Irregular/event stream, LSL nominal sample rate 0.
    Irregular,
    /// Event stream with no steady-rate claim.
    Event,
    /// Periodic stream with a separate adapter-owned rate claim.
    Periodic,
}

/// LSL clock/timestamp policy expected from the adapter.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldLslClockPolicy {
    /// Use raw sample timestamps only.
    RawSampleTimestamp,
    /// Capture LSL time-correction offset and uncertainty.
    TimeCorrection,
    /// Estimate round-trip offset from probe/echo samples.
    RoundTripOffset,
    /// Timestamp policy is unknown and route evidence must not claim alignment.
    Unknown,
}

/// ZeroMQ-specific route metadata for socket adapters.
///
/// This is still a descriptor. It does not bind, connect, subscribe, publish,
/// allocate queues, or link a ZeroMQ runtime.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldZeroMqRouteProfile {
    /// Socket pattern the adapter is allowed to use.
    pub socket_pattern: ManifoldZeroMqSocketPattern,
    /// Whether the local adapter binds or connects the endpoint.
    pub endpoint_open_mode: ManifoldZeroMqEndpointOpenMode,
    /// Transport endpoint URL such as `tcp://127.0.0.1:5570`.
    pub endpoint_url: String,
    /// Topic prefix for PUB/SUB routes. Empty means subscribe to all topics.
    pub topic_prefix: String,
    /// Payload encoding declared by this route.
    pub payload_encoding: ManifoldZeroMqPayloadEncoding,
    /// Maximum allowed ZeroMQ message size.
    pub max_message_bytes: u32,
    /// Bounded receiver queue size.
    pub high_water_mark: u32,
    /// Queue pressure behavior expected from the adapter.
    pub queue_policy: ManifoldQueueDropPolicy,
}

impl ManifoldZeroMqRouteProfile {
    fn validate_shape(
        &self,
        route_id: &DottedId,
    ) -> Result<(), ManifoldBridgeRouteValidationError> {
        if self.endpoint_url.trim().is_empty() || !self.endpoint_url.contains("://") {
            return Err(ManifoldBridgeRouteValidationError::new(
                route_id.clone(),
                self.endpoint_url.clone(),
                ManifoldBridgeRouteValidationErrorKind::InvalidTransportProfile,
            ));
        }
        if self.max_message_bytes == 0 || self.high_water_mark == 0 {
            return Err(ManifoldBridgeRouteValidationError::new(
                route_id.clone(),
                format!(
                    "max_message_bytes={} high_water_mark={}",
                    self.max_message_bytes, self.high_water_mark
                ),
                ManifoldBridgeRouteValidationErrorKind::InvalidTransportProfile,
            ));
        }
        if self.socket_pattern == ManifoldZeroMqSocketPattern::PubSub
            && self.endpoint_open_mode == ManifoldZeroMqEndpointOpenMode::Either
        {
            return Err(ManifoldBridgeRouteValidationError::new(
                route_id.clone(),
                "endpoint_open_mode=either".to_owned(),
                ManifoldBridgeRouteValidationErrorKind::InvalidTransportProfile,
            ));
        }

        Ok(())
    }
}

/// ZeroMQ socket pattern.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldZeroMqSocketPattern {
    /// PUB/SUB topic fan-out.
    PubSub,
    /// PUSH/PULL pipeline handoff.
    PushPull,
    /// REQ/REP bounded request/reply.
    ReqRep,
    /// PAIR socket. Use sparingly; external profiles may adapt this into a generic route.
    Pair,
}

/// Whether a ZeroMQ runtime endpoint binds or connects.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldZeroMqEndpointOpenMode {
    /// Adapter binds the endpoint.
    Bind,
    /// Adapter connects to an endpoint owned elsewhere.
    Connect,
    /// Manifest is descriptive only; runtime adapters must resolve a concrete mode.
    Either,
}

/// ZeroMQ payload encoding.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldZeroMqPayloadEncoding {
    /// UTF-8 JSON message.
    Json,
    /// UTF-8 text message.
    Utf8Text,
    /// Opaque bytes.
    Binary,
}

/// Queue pressure behavior for transport adapters.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldQueueDropPolicy {
    /// Drop the oldest queued message when the queue is full.
    DropOldest,
    /// Drop the newest incoming message when the queue is full.
    DropNewest,
    /// Backpressure or block until space exists.
    Backpressure,
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
            ManifoldBridgeRouteValidationErrorKind::MissingTransportProfile => {
                "missing_transport_profile"
            }
            ManifoldBridgeRouteValidationErrorKind::TransportProfileMismatch => {
                "transport_profile_mismatch"
            }
            ManifoldBridgeRouteValidationErrorKind::InvalidTransportProfile => {
                "invalid_transport_profile"
            }
            ManifoldBridgeRouteValidationErrorKind::MissingRequiredCondition => {
                "missing_required_condition"
            }
            ManifoldBridgeRouteValidationErrorKind::InvalidRequiredCondition => {
                "invalid_required_condition"
            }
            ManifoldBridgeRouteValidationErrorKind::MissingTimingPolicy => "missing_timing_policy",
            ManifoldBridgeRouteValidationErrorKind::InvalidTimingPolicy => "invalid_timing_policy",
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
    /// The transport family requires a profile that is absent.
    MissingTransportProfile,
    /// A transport-specific profile is attached to a different family.
    TransportProfileMismatch,
    /// The transport-specific profile has invalid bounds or endpoint mode.
    InvalidTransportProfile,
    /// An operational transport route lacks required environment conditions.
    MissingRequiredCondition,
    /// A required environment condition is malformed.
    InvalidRequiredCondition,
    /// An operational transport route lacks a timing policy.
    MissingTimingPolicy,
    /// A timing policy is internally inconsistent.
    InvalidTimingPolicy,
}
