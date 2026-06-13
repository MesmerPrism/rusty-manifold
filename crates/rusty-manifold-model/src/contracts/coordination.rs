use std::collections::{BTreeMap, BTreeSet};

use super::*;

const COORDINATION_SESSION_PLAN_SCHEMA: &str = "rusty.manifold.coordination.session_plan.v1";
const COORDINATION_MESSAGE_LOG_SCHEMA: &str = "rusty.manifold.coordination.message_log.v1";
const COORDINATION_MESSAGE_SCHEMA: &str = "rusty.manifold.coordination.message.v1";
const COORDINATION_SCORECARD_SCHEMA: &str = "rusty.manifold.coordination.scorecard.v1";
const SENDER_START_AUTHORIZED_KIND: &str = "coordination.message.sender_start_authorized";
const MAX_CONTROL_PAYLOAD_BYTES: u64 = 16 * 1024;

/// A source-only coordination session plan for multi-agent runtime timing.
///
/// The plan describes participants, low-rate coordination transports, inboxes,
/// gates, and evidence requirements. It does not open sockets, start cameras,
/// execute ADB, relay media, or mutate runtime state.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldCoordinationSessionPlan {
    /// Schema identifier for this session plan.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable coordination session id.
    pub session_id: DottedId,
    /// Revision of the coordination plan.
    pub session_revision: Revision,
    /// Manifold authority that accepts the session state.
    pub authority_id: DottedId,
    /// Intended operating mode, such as LAN or remote relay.
    pub mode: CoordinationSessionMode,
    /// Session participants.
    pub participants: Vec<CoordinationParticipant>,
    /// Low-rate coordination transports. Media transports are represented only
    /// by artifact or stream references, not by live payloads.
    pub transports: Vec<CoordinationTransport>,
    /// Per-participant control inboxes.
    pub inboxes: Vec<CoordinationInbox>,
    /// Accepted gate sequence.
    pub gates: Vec<CoordinationGate>,
    /// Message kinds accepted by this session.
    pub allowed_message_kinds: Vec<DottedId>,
    /// Commands that this coordination session may authorize or evidence.
    #[cfg_attr(feature = "serde", serde(default))]
    pub command_refs: Vec<DottedId>,
    /// Media stream descriptors referenced by the session. These are metadata
    /// references only.
    #[cfg_attr(feature = "serde", serde(default))]
    pub media_stream_refs: Vec<DottedId>,
    /// Safety and boundary policy for the session.
    pub safety: CoordinationSafetyPolicy,
}

impl ManifoldCoordinationSessionPlan {
    /// Validates the static shape of a coordination session plan.
    ///
    /// # Errors
    ///
    /// Returns [`CoordinationValidationError`] when the plan is internally
    /// inconsistent or tries to make coordination transports carry media.
    pub fn validate_static(&self) -> Result<(), CoordinationValidationError> {
        if self.schema_id.as_str() != COORDINATION_SESSION_PLAN_SCHEMA {
            return Err(CoordinationValidationError::new(
                self.session_id.clone(),
                CoordinationValidationErrorKind::UnsupportedSchema,
                "coordination session plan schema is not supported",
            ));
        }

        if self.participants.len() < 2 {
            return Err(CoordinationValidationError::new(
                self.session_id.clone(),
                CoordinationValidationErrorKind::MissingParticipant,
                "coordination session needs at least two participants",
            ));
        }

        if self.allowed_message_kinds.is_empty() {
            return Err(CoordinationValidationError::new(
                self.session_id.clone(),
                CoordinationValidationErrorKind::MissingRequiredMessageKind,
                "coordination session needs at least one allowed message kind",
            ));
        }

        let participant_ids = unique_ids(
            self.participants
                .iter()
                .map(|participant| &participant.participant_id),
            CoordinationValidationErrorKind::DuplicateParticipant,
        )?;
        let transport_ids = unique_ids(
            self.transports
                .iter()
                .map(|transport| &transport.transport_id),
            CoordinationValidationErrorKind::DuplicateTransport,
        )?;
        let inbox_ids = unique_ids(
            self.inboxes.iter().map(|inbox| &inbox.inbox_id),
            CoordinationValidationErrorKind::DuplicateInbox,
        )?;
        let gate_ids = unique_ids(
            self.gates.iter().map(|gate| &gate.gate_id),
            CoordinationValidationErrorKind::DuplicateGate,
        )?;

        if self.transports.is_empty() {
            return Err(CoordinationValidationError::new(
                self.session_id.clone(),
                CoordinationValidationErrorKind::UnknownTransport,
                "coordination session needs at least one low-rate transport",
            ));
        }

        for transport in &self.transports {
            if transport.advisory_only && transport.authoritative {
                return Err(CoordinationValidationError::new(
                    transport.transport_id.clone(),
                    CoordinationValidationErrorKind::AuthorityBoundaryViolation,
                    "advisory-only transport cannot be authoritative",
                ));
            }
            if transport.payload_policy == CoordinationPayloadPolicy::MediaPayloadAllowed {
                return Err(CoordinationValidationError::new(
                    transport.transport_id.clone(),
                    CoordinationValidationErrorKind::MediaPayloadInControl,
                    "coordination transports cannot carry media payloads",
                ));
            }
        }

        for inbox in &self.inboxes {
            if !participant_ids.contains(&inbox.owner_participant_id) {
                return Err(CoordinationValidationError::new(
                    inbox.owner_participant_id.clone(),
                    CoordinationValidationErrorKind::UnknownParticipant,
                    "inbox references an unknown owner participant",
                ));
            }
            if !transport_ids.contains(&inbox.transport_id) {
                return Err(CoordinationValidationError::new(
                    inbox.transport_id.clone(),
                    CoordinationValidationErrorKind::UnknownTransport,
                    "inbox references an unknown transport",
                ));
            }
            if inbox.heartbeat_ttl_ms == 0 {
                return Err(CoordinationValidationError::new(
                    inbox.inbox_id.clone(),
                    CoordinationValidationErrorKind::InvalidTtl,
                    "inbox heartbeat ttl must be greater than zero",
                ));
            }
        }

        for participant in &self.participants {
            if participant.required_capabilities.is_empty() {
                return Err(CoordinationValidationError::new(
                    participant.participant_id.clone(),
                    CoordinationValidationErrorKind::MissingCapability,
                    "participant must declare at least one required capability",
                ));
            }
        }

        for gate in &self.gates {
            if gate.required_message_kinds.is_empty() {
                return Err(CoordinationValidationError::new(
                    gate.gate_id.clone(),
                    CoordinationValidationErrorKind::MissingRequiredMessageKind,
                    "gate must require at least one message kind",
                ));
            }
            for participant_id in &gate.required_participant_ids {
                if !participant_ids.contains(participant_id) {
                    return Err(CoordinationValidationError::new(
                        participant_id.clone(),
                        CoordinationValidationErrorKind::UnknownParticipant,
                        "gate references an unknown participant",
                    ));
                }
            }
            for dependency in &gate.depends_on_gate_ids {
                if !gate_ids.contains(dependency) {
                    return Err(CoordinationValidationError::new(
                        dependency.clone(),
                        CoordinationValidationErrorKind::UnknownGate,
                        "gate references an unknown dependency",
                    ));
                }
            }
            for message_kind in &gate.required_message_kinds {
                if !self
                    .allowed_message_kinds
                    .iter()
                    .any(|allowed| allowed == message_kind)
                {
                    return Err(CoordinationValidationError::new(
                        message_kind.clone(),
                        CoordinationValidationErrorKind::UnknownMessageKind,
                        "gate requires a message kind not allowed by the plan",
                    ));
                }
            }
        }

        if self.safety.max_control_payload_bytes == 0
            || self.safety.max_control_payload_bytes > MAX_CONTROL_PAYLOAD_BYTES
        {
            return Err(CoordinationValidationError::new(
                self.session_id.clone(),
                CoordinationValidationErrorKind::InvalidPayloadPolicy,
                "control payload limit must be between 1 and 16384 bytes",
            ));
        }

        if self.safety.peer_gossip_can_authorize_commands {
            return Err(CoordinationValidationError::new(
                self.session_id.clone(),
                CoordinationValidationErrorKind::AuthorityBoundaryViolation,
                "peer gossip cannot authorize commands",
            ));
        }

        if !self.safety.high_rate_payloads_forbidden {
            return Err(CoordinationValidationError::new(
                self.session_id.clone(),
                CoordinationValidationErrorKind::MediaPayloadInControl,
                "coordination sessions must forbid high-rate payloads",
            ));
        }

        let _ = inbox_ids;
        Ok(())
    }

    /// Simulates a low-rate coordination message log and returns a deterministic scorecard.
    ///
    /// # Errors
    ///
    /// Returns [`CoordinationValidationError`] when the log violates the plan,
    /// gate order, payload policy, or authority boundary.
    pub fn simulate_message_log(
        &self,
        log: &ManifoldCoordinationMessageLog,
    ) -> Result<ManifoldCoordinationScorecard, CoordinationValidationError> {
        self.validate_static()?;
        if log.schema_id.as_str() != COORDINATION_MESSAGE_LOG_SCHEMA {
            return Err(CoordinationValidationError::new(
                log.log_id.clone(),
                CoordinationValidationErrorKind::UnsupportedSchema,
                "coordination message log schema is not supported",
            ));
        }
        if log.session_id != self.session_id {
            return Err(CoordinationValidationError::new(
                log.session_id.clone(),
                CoordinationValidationErrorKind::SessionMismatch,
                "message log session does not match plan",
            ));
        }

        let participant_ids = self
            .participants
            .iter()
            .map(|participant| participant.participant_id.clone())
            .collect::<BTreeSet<_>>();
        let transports_by_id = self
            .transports
            .iter()
            .map(|transport| (transport.transport_id.clone(), transport))
            .collect::<BTreeMap<_, _>>();
        let gate_ids = self
            .gates
            .iter()
            .map(|gate| gate.gate_id.clone())
            .collect::<BTreeSet<_>>();
        let allowed_message_kinds = self
            .allowed_message_kinds
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();

        let mut accepted_messages = Vec::new();
        let mut message_ids = BTreeSet::new();
        let mut idempotency_keys = BTreeSet::new();
        let mut last_sequence_by_participant = BTreeMap::<DottedId, u64>::new();
        let mut gate_states = evaluate_gates(self, &accepted_messages);

        for message in &log.messages {
            validate_message_shape(
                self,
                message,
                &participant_ids,
                &transports_by_id,
                &gate_ids,
                &allowed_message_kinds,
                &mut message_ids,
                &mut idempotency_keys,
                &mut last_sequence_by_participant,
            )?;

            if message.message_kind.as_str() == SENDER_START_AUTHORIZED_KIND {
                for gate in &self.gates {
                    if gate.required_before_sender_start
                        && gate_states
                            .get(&gate.gate_id)
                            .map(|state| !state.passed)
                            .unwrap_or(true)
                    {
                        return Err(CoordinationValidationError::new(
                            message.message_id.clone(),
                            CoordinationValidationErrorKind::SenderBeforeReceiverReady,
                            "sender start was authorized before receiver readiness gates passed",
                        ));
                    }
                }
            }

            if let Some(gate_id) = &message.gate_id {
                let gate = self
                    .gates
                    .iter()
                    .find(|candidate| candidate.gate_id == *gate_id)
                    .ok_or_else(|| {
                        CoordinationValidationError::new(
                            gate_id.clone(),
                            CoordinationValidationErrorKind::UnknownGate,
                            "message references an unknown gate",
                        )
                    })?;
                let advisory_transport = message
                    .transport_id
                    .as_ref()
                    .and_then(|transport_id| transports_by_id.get(transport_id))
                    .map(|transport| transport.advisory_only)
                    .unwrap_or(false);
                if gate.authorizes_command_id.is_some()
                    && (message.payload_class == CoordinationPayloadClass::AdvisoryStatus
                        || advisory_transport)
                {
                    return Err(CoordinationValidationError::new(
                        message.message_id.clone(),
                        CoordinationValidationErrorKind::AdvisoryStatusCannotAuthorize,
                        "advisory status messages cannot satisfy command-authorizing gates",
                    ));
                }
            }

            accepted_messages.push(message.clone());
            gate_states = evaluate_gates(self, &accepted_messages);
        }

        let gate_results = self
            .gates
            .iter()
            .map(|gate| {
                let state = gate_states
                    .get(&gate.gate_id)
                    .expect("all gates receive states");
                CoordinationGateResult {
                    gate_id: gate.gate_id.clone(),
                    status: if state.passed {
                        ValidationStatus::Pass
                    } else {
                        ValidationStatus::Fail
                    },
                    satisfied_at_ms: state.satisfied_at_ms,
                    message_ids: state.message_ids.clone(),
                    evidence: if state.passed {
                        "gate satisfied by accepted coordination messages".to_owned()
                    } else {
                        "gate was not satisfied by the message log".to_owned()
                    },
                    issue_codes: if state.passed {
                        Vec::new()
                    } else {
                        vec![DottedId::new("issue.coordination.gate_not_satisfied")
                            .expect("issue code literal is valid")]
                    },
                }
            })
            .collect::<Vec<_>>();

        let failed = gate_results
            .iter()
            .any(|result| result.status == ValidationStatus::Fail);

        Ok(ManifoldCoordinationScorecard {
            schema_id: SchemaId::new(COORDINATION_SCORECARD_SCHEMA)
                .expect("schema literal is valid"),
            scorecard_id: DottedId::new(format!("scorecard.{}", log.log_id.as_str()))
                .expect("derived scorecard id is valid"),
            session_id: self.session_id.clone(),
            mode: self.mode,
            status: if failed {
                ValidationStatus::Fail
            } else {
                ValidationStatus::Pass
            },
            accepted_message_ids: accepted_messages
                .iter()
                .map(|message| message.message_id.clone())
                .collect(),
            gate_results,
            rejected_messages: Vec::new(),
            advisory_message_ids: accepted_messages
                .iter()
                .filter(|message| message.payload_class == CoordinationPayloadClass::AdvisoryStatus)
                .map(|message| message.message_id.clone())
                .collect(),
            media_payloads_seen: false,
            runtime_execution_performed: false,
        })
    }
}

/// Intended coordination operating mode.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoordinationSessionMode {
    /// Same-network Quest-to-Quest coordination.
    SameNetworkQuestToQuest,
    /// Same-network Quest-to-phone coordination.
    SameNetworkQuestToPhone,
    /// Remote relay mediated two-way coordination.
    RemoteRelayTwoWay,
    /// Source-only fixture or simulator mode.
    Fixture,
}

/// Participant in a coordination session.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoordinationParticipant {
    /// Stable participant id.
    pub participant_id: DottedId,
    /// Participant role.
    pub role: CoordinationParticipantRole,
    /// Host or device profile id, if known.
    #[cfg_attr(feature = "serde", serde(default))]
    pub host_profile_id: Option<DottedId>,
    /// Capabilities the participant must provide for this session.
    pub required_capabilities: Vec<DottedId>,
    /// Whether this participant can only provide advisory status.
    pub advisory_only: bool,
}

/// Participant role.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoordinationParticipantRole {
    /// Manifold/agent coordinator.
    Coordinator,
    /// Quest headset endpoint.
    QuestHeadset,
    /// Android phone endpoint.
    AndroidPhone,
    /// Remote relay service or bridge.
    Relay,
    /// Termux sidecar status participant.
    TermuxSidecar,
}

/// Low-rate coordination transport descriptor.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoordinationTransport {
    /// Stable transport id.
    pub transport_id: DottedId,
    /// Transport family.
    pub transport_kind: DottedId,
    /// Payload policy.
    pub payload_policy: CoordinationPayloadPolicy,
    /// Whether this transport can carry accepted command coordination.
    pub authoritative: bool,
    /// Whether this transport is advisory status only.
    pub advisory_only: bool,
    /// Whether the route is same-network only.
    pub same_network_only: bool,
    /// Whether the route is remote relay mediated.
    pub remote_relay: bool,
    /// Whether the transport is bidirectional.
    pub bidirectional: bool,
    /// Whether operator review is required before a live adapter uses it.
    pub operator_review_required: bool,
}

/// Payload policy for low-rate coordination transports.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoordinationPayloadPolicy {
    /// Control messages and artifact refs only; media payloads are forbidden.
    MediaPayloadForbidden,
    /// Advisory status messages only.
    AdvisoryStatusOnly,
    /// Artifact references only.
    ArtifactReferencesOnly,
    /// Invalid for Manifold coordination sessions; used by damaged fixtures.
    MediaPayloadAllowed,
}

/// Per-participant inbox descriptor.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoordinationInbox {
    /// Stable inbox id.
    pub inbox_id: DottedId,
    /// Participant that owns this inbox.
    pub owner_participant_id: DottedId,
    /// Transport carrying this inbox.
    pub transport_id: DottedId,
    /// Lease id guarding inbox ownership.
    #[cfg_attr(feature = "serde", serde(default))]
    pub lease_id: Option<DottedId>,
    /// Channel id such as `control`.
    pub channel_id: DottedId,
    /// Heartbeat TTL in milliseconds.
    pub heartbeat_ttl_ms: u64,
}

/// Coordination gate.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoordinationGate {
    /// Stable gate id.
    pub gate_id: DottedId,
    /// Gate phase.
    pub phase: DottedId,
    /// Gate dependencies.
    #[cfg_attr(feature = "serde", serde(default))]
    pub depends_on_gate_ids: Vec<DottedId>,
    /// Participants required to provide this gate evidence. If empty, the gate
    /// is satisfied by any participant with the required message kind.
    #[cfg_attr(feature = "serde", serde(default))]
    pub required_participant_ids: Vec<DottedId>,
    /// Message kinds that satisfy this gate.
    pub required_message_kinds: Vec<DottedId>,
    /// Command this gate authorizes, if any.
    #[cfg_attr(feature = "serde", serde(default))]
    pub authorizes_command_id: Option<DottedId>,
    /// Whether this gate must pass before sender start can be authorized.
    pub required_before_sender_start: bool,
}

/// Safety policy for a coordination session.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoordinationSafetyPolicy {
    /// Maximum low-rate control payload size.
    pub max_control_payload_bytes: u64,
    /// High-rate payloads must be rejected.
    pub high_rate_payloads_forbidden: bool,
    /// Peer gossip is advisory only.
    pub peer_gossip_can_authorize_commands: bool,
    /// Whether live operator review is required before platform adapters run.
    pub operator_review_required_for_live_routes: bool,
}

/// A log of source-only coordination messages.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldCoordinationMessageLog {
    /// Schema identifier for this log.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable log id.
    pub log_id: DottedId,
    /// Session id.
    pub session_id: DottedId,
    /// Messages in observed order.
    pub messages: Vec<ManifoldCoordinationMessage>,
}

/// One low-rate coordination message.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldCoordinationMessage {
    /// Schema identifier for this message.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable message id.
    pub message_id: DottedId,
    /// Session id.
    pub session_id: DottedId,
    /// Participant sending or reporting this message.
    pub participant_id: DottedId,
    /// Message kind.
    pub message_kind: DottedId,
    /// Participant-local monotonic sequence.
    pub sequence: u64,
    /// Wall-clock creation time in milliseconds.
    pub created_at_ms: u64,
    /// Expiration time in milliseconds.
    pub expires_at_ms: u64,
    /// Idempotency key.
    pub idempotency_key: DottedId,
    /// Prior message ids or gate evidence this message depends on.
    #[cfg_attr(feature = "serde", serde(default))]
    pub depends_on_message_ids: Vec<DottedId>,
    /// Gate this message is intended to evidence.
    #[cfg_attr(feature = "serde", serde(default))]
    pub gate_id: Option<DottedId>,
    /// Transport that carried the message, if known.
    #[cfg_attr(feature = "serde", serde(default))]
    pub transport_id: Option<DottedId>,
    /// Payload class.
    pub payload_class: CoordinationPayloadClass,
    /// Sensitivity label.
    pub sensitivity: SensitivityLevel,
    /// Payload size in bytes. This is metadata only.
    pub payload_size_bytes: u64,
    /// Whether the message carried inline binary bytes.
    pub inline_binary_payload: bool,
    /// Artifact references backing the message.
    #[cfg_attr(feature = "serde", serde(default))]
    pub artifact_refs: Vec<DottedId>,
}

/// Message payload class.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoordinationPayloadClass {
    /// Authoritative low-rate control.
    Control,
    /// Advisory status gossip.
    AdvisoryStatus,
    /// Artifact references without embedded payload.
    ArtifactReference,
    /// Invalid for control messages; used by damaged fixtures.
    MediaPayload,
}

/// Deterministic coordination scorecard.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldCoordinationScorecard {
    /// Schema identifier for this scorecard.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable scorecard id.
    pub scorecard_id: DottedId,
    /// Session id.
    pub session_id: DottedId,
    /// Operating mode.
    pub mode: CoordinationSessionMode,
    /// Overall validation status.
    pub status: ValidationStatus,
    /// Accepted message ids.
    pub accepted_message_ids: Vec<DottedId>,
    /// Gate outcomes.
    pub gate_results: Vec<CoordinationGateResult>,
    /// Rejected messages. Source-only valid runs should be empty.
    #[cfg_attr(feature = "serde", serde(default))]
    pub rejected_messages: Vec<CoordinationRejectedMessage>,
    /// Advisory message ids accepted as status only.
    #[cfg_attr(feature = "serde", serde(default))]
    pub advisory_message_ids: Vec<DottedId>,
    /// Whether any media payload was seen.
    pub media_payloads_seen: bool,
    /// Whether this source-only simulation executed runtime work.
    pub runtime_execution_performed: bool,
}

/// Result for one coordination gate.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoordinationGateResult {
    /// Gate id.
    pub gate_id: DottedId,
    /// Gate status.
    pub status: ValidationStatus,
    /// Time this gate was satisfied, if any.
    pub satisfied_at_ms: Option<u64>,
    /// Message ids that satisfied this gate.
    pub message_ids: Vec<DottedId>,
    /// Display-safe evidence.
    pub evidence: String,
    /// Issue codes when failed.
    #[cfg_attr(feature = "serde", serde(default))]
    pub issue_codes: Vec<DottedId>,
}

/// Rejected coordination message summary.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoordinationRejectedMessage {
    /// Message id.
    pub message_id: DottedId,
    /// Rejection code.
    pub rejection_code: DottedId,
    /// Display-safe reason.
    pub message: String,
    /// Whether retry is safe.
    pub retryable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GateEvaluationState {
    passed: bool,
    satisfied_at_ms: Option<u64>,
    message_ids: Vec<DottedId>,
}

fn validate_message_shape(
    plan: &ManifoldCoordinationSessionPlan,
    message: &ManifoldCoordinationMessage,
    participant_ids: &BTreeSet<DottedId>,
    transports_by_id: &BTreeMap<DottedId, &CoordinationTransport>,
    gate_ids: &BTreeSet<DottedId>,
    allowed_message_kinds: &BTreeSet<DottedId>,
    message_ids: &mut BTreeSet<DottedId>,
    idempotency_keys: &mut BTreeSet<DottedId>,
    last_sequence_by_participant: &mut BTreeMap<DottedId, u64>,
) -> Result<(), CoordinationValidationError> {
    if message.schema_id.as_str() != COORDINATION_MESSAGE_SCHEMA {
        return Err(CoordinationValidationError::new(
            message.message_id.clone(),
            CoordinationValidationErrorKind::UnsupportedSchema,
            "coordination message schema is not supported",
        ));
    }
    if message.session_id != plan.session_id {
        return Err(CoordinationValidationError::new(
            message.message_id.clone(),
            CoordinationValidationErrorKind::SessionMismatch,
            "message session does not match plan",
        ));
    }
    if !participant_ids.contains(&message.participant_id) {
        return Err(CoordinationValidationError::new(
            message.participant_id.clone(),
            CoordinationValidationErrorKind::UnknownParticipant,
            "message references an unknown participant",
        ));
    }
    if let Some(transport_id) = &message.transport_id {
        let transport = transports_by_id.get(transport_id).ok_or_else(|| {
            CoordinationValidationError::new(
                transport_id.clone(),
                CoordinationValidationErrorKind::UnknownTransport,
                "message references an unknown transport",
            )
        })?;
        match transport.payload_policy {
            CoordinationPayloadPolicy::MediaPayloadForbidden => {}
            CoordinationPayloadPolicy::AdvisoryStatusOnly => {
                if message.payload_class != CoordinationPayloadClass::AdvisoryStatus {
                    return Err(CoordinationValidationError::new(
                        message.message_id.clone(),
                        CoordinationValidationErrorKind::InvalidPayloadPolicy,
                        "advisory-only transport carried a non-advisory message",
                    ));
                }
            }
            CoordinationPayloadPolicy::ArtifactReferencesOnly => {
                if message.payload_class != CoordinationPayloadClass::ArtifactReference {
                    return Err(CoordinationValidationError::new(
                        message.message_id.clone(),
                        CoordinationValidationErrorKind::InvalidPayloadPolicy,
                        "artifact-reference transport carried a non-artifact message",
                    ));
                }
            }
            CoordinationPayloadPolicy::MediaPayloadAllowed => {
                return Err(CoordinationValidationError::new(
                    message.message_id.clone(),
                    CoordinationValidationErrorKind::MediaPayloadInControl,
                    "coordination transports cannot allow media payloads",
                ));
            }
        }
    }
    if let Some(gate_id) = &message.gate_id {
        if !gate_ids.contains(gate_id) {
            return Err(CoordinationValidationError::new(
                gate_id.clone(),
                CoordinationValidationErrorKind::UnknownGate,
                "message references an unknown gate",
            ));
        }
    }
    if !allowed_message_kinds.contains(&message.message_kind) {
        return Err(CoordinationValidationError::new(
            message.message_kind.clone(),
            CoordinationValidationErrorKind::UnknownMessageKind,
            "message kind is not allowed by plan",
        ));
    }
    if !message_ids.insert(message.message_id.clone()) {
        return Err(CoordinationValidationError::new(
            message.message_id.clone(),
            CoordinationValidationErrorKind::DuplicateMessage,
            "duplicate coordination message id",
        ));
    }
    if !idempotency_keys.insert(message.idempotency_key.clone()) {
        return Err(CoordinationValidationError::new(
            message.idempotency_key.clone(),
            CoordinationValidationErrorKind::DuplicateIdempotencyKey,
            "duplicate idempotency key",
        ));
    }
    if message.sequence == 0 {
        return Err(CoordinationValidationError::new(
            message.message_id.clone(),
            CoordinationValidationErrorKind::SequenceRegression,
            "message sequence must be greater than zero",
        ));
    }
    if let Some(previous) = last_sequence_by_participant.get(&message.participant_id) {
        if message.sequence <= *previous {
            return Err(CoordinationValidationError::new(
                message.message_id.clone(),
                CoordinationValidationErrorKind::SequenceRegression,
                "participant message sequence regressed",
            ));
        }
    }
    last_sequence_by_participant.insert(message.participant_id.clone(), message.sequence);

    if message.expires_at_ms <= message.created_at_ms {
        return Err(CoordinationValidationError::new(
            message.message_id.clone(),
            CoordinationValidationErrorKind::MessageExpired,
            "message expiration must be after creation time",
        ));
    }
    if message.inline_binary_payload
        || message.payload_class == CoordinationPayloadClass::MediaPayload
        || message.payload_size_bytes > plan.safety.max_control_payload_bytes
    {
        return Err(CoordinationValidationError::new(
            message.message_id.clone(),
            CoordinationValidationErrorKind::MediaPayloadInControl,
            "coordination messages cannot carry high-rate or inline media payloads",
        ));
    }

    Ok(())
}

fn evaluate_gates(
    plan: &ManifoldCoordinationSessionPlan,
    messages: &[ManifoldCoordinationMessage],
) -> BTreeMap<DottedId, GateEvaluationState> {
    let mut states = BTreeMap::<DottedId, GateEvaluationState>::new();
    for gate in &plan.gates {
        states.insert(
            gate.gate_id.clone(),
            GateEvaluationState {
                passed: false,
                satisfied_at_ms: None,
                message_ids: Vec::new(),
            },
        );
    }

    let mut changed = true;
    while changed {
        changed = false;
        for gate in &plan.gates {
            let dependencies_passed = gate.depends_on_gate_ids.iter().all(|dependency| {
                states
                    .get(dependency)
                    .map(|state| state.passed)
                    .unwrap_or(false)
            });
            if !dependencies_passed {
                continue;
            }

            let Some(satisfied) = gate_satisfaction(gate, messages) else {
                continue;
            };

            let state = states
                .get_mut(&gate.gate_id)
                .expect("state exists for every gate");
            if !state.passed {
                state.passed = true;
                state.satisfied_at_ms = Some(satisfied.satisfied_at_ms);
                state.message_ids = satisfied.message_ids;
                changed = true;
            }
        }
    }

    states
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GateSatisfaction {
    satisfied_at_ms: u64,
    message_ids: Vec<DottedId>,
}

fn gate_satisfaction(
    gate: &CoordinationGate,
    messages: &[ManifoldCoordinationMessage],
) -> Option<GateSatisfaction> {
    let mut selected = Vec::<&ManifoldCoordinationMessage>::new();

    if gate.required_participant_ids.is_empty() {
        for message_kind in &gate.required_message_kinds {
            let message = messages
                .iter()
                .find(|message| message.message_kind == *message_kind)?;
            selected.push(message);
        }
    } else {
        for participant_id in &gate.required_participant_ids {
            let message = messages.iter().find(|message| {
                message.participant_id == *participant_id
                    && gate
                        .required_message_kinds
                        .iter()
                        .any(|kind| *kind == message.message_kind)
            })?;
            selected.push(message);
        }
    }

    let satisfied_at_ms = selected
        .iter()
        .map(|message| message.created_at_ms)
        .max()
        .unwrap_or(0);
    let message_ids = selected
        .iter()
        .map(|message| message.message_id.clone())
        .collect();

    Some(GateSatisfaction {
        satisfied_at_ms,
        message_ids,
    })
}

fn unique_ids<'a>(
    ids: impl Iterator<Item = &'a DottedId>,
    duplicate_kind: CoordinationValidationErrorKind,
) -> Result<BTreeSet<DottedId>, CoordinationValidationError> {
    let mut seen = BTreeSet::new();
    for id in ids {
        if !seen.insert(id.clone()) {
            return Err(CoordinationValidationError::new(
                id.clone(),
                duplicate_kind,
                "duplicate id in coordination session plan",
            ));
        }
    }
    Ok(seen)
}

/// Coordination validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoordinationValidationError {
    rejected_id: DottedId,
    kind: CoordinationValidationErrorKind,
    message: String,
}

impl CoordinationValidationError {
    fn new(
        rejected_id: DottedId,
        kind: CoordinationValidationErrorKind,
        message: impl Into<String>,
    ) -> Self {
        Self {
            rejected_id,
            kind,
            message: message.into(),
        }
    }

    /// Returns a machine-readable rejection code.
    #[must_use]
    pub fn rejection_code(&self) -> &'static str {
        match self.kind {
            CoordinationValidationErrorKind::UnsupportedSchema => "unsupported_schema",
            CoordinationValidationErrorKind::SessionMismatch => "session_mismatch",
            CoordinationValidationErrorKind::DuplicateParticipant => "duplicate_participant",
            CoordinationValidationErrorKind::DuplicateTransport => "duplicate_transport",
            CoordinationValidationErrorKind::DuplicateInbox => "duplicate_inbox",
            CoordinationValidationErrorKind::DuplicateGate => "duplicate_gate",
            CoordinationValidationErrorKind::DuplicateMessage => "duplicate_message",
            CoordinationValidationErrorKind::DuplicateIdempotencyKey => "duplicate_idempotency_key",
            CoordinationValidationErrorKind::UnknownParticipant => "unknown_participant",
            CoordinationValidationErrorKind::UnknownTransport => "unknown_transport",
            CoordinationValidationErrorKind::UnknownGate => "unknown_gate",
            CoordinationValidationErrorKind::UnknownMessageKind => "unknown_message_kind",
            CoordinationValidationErrorKind::MissingParticipant => "missing_participant",
            CoordinationValidationErrorKind::MissingCapability => "missing_capability",
            CoordinationValidationErrorKind::MissingRequiredMessageKind => {
                "missing_required_message_kind"
            }
            CoordinationValidationErrorKind::InvalidTtl => "invalid_ttl",
            CoordinationValidationErrorKind::InvalidPayloadPolicy => "invalid_payload_policy",
            CoordinationValidationErrorKind::MessageExpired => "message_expired",
            CoordinationValidationErrorKind::SequenceRegression => "sequence_regression",
            CoordinationValidationErrorKind::MediaPayloadInControl => "media_payload_in_control",
            CoordinationValidationErrorKind::SenderBeforeReceiverReady => {
                "sender_before_receiver_ready"
            }
            CoordinationValidationErrorKind::AdvisoryStatusCannotAuthorize => {
                "advisory_status_cannot_authorize"
            }
            CoordinationValidationErrorKind::AuthorityBoundaryViolation => {
                "authority_boundary_violation"
            }
        }
    }

    /// Returns the error kind.
    #[must_use]
    pub const fn kind(&self) -> CoordinationValidationErrorKind {
        self.kind
    }

    /// Returns the rejected identifier.
    #[must_use]
    pub const fn rejected_id(&self) -> &DottedId {
        &self.rejected_id
    }
}

impl fmt::Display for CoordinationValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} rejected {}: {}",
            self.rejection_code(),
            self.rejected_id,
            self.message
        )
    }
}

impl std::error::Error for CoordinationValidationError {}

/// Machine-readable coordination validation error kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoordinationValidationErrorKind {
    /// Unsupported schema id.
    UnsupportedSchema,
    /// Session ids do not match.
    SessionMismatch,
    /// Duplicate participant id.
    DuplicateParticipant,
    /// Duplicate transport id.
    DuplicateTransport,
    /// Duplicate inbox id.
    DuplicateInbox,
    /// Duplicate gate id.
    DuplicateGate,
    /// Duplicate message id.
    DuplicateMessage,
    /// Duplicate idempotency key.
    DuplicateIdempotencyKey,
    /// Unknown participant id.
    UnknownParticipant,
    /// Unknown transport id.
    UnknownTransport,
    /// Unknown gate id.
    UnknownGate,
    /// Unknown message kind.
    UnknownMessageKind,
    /// Missing participant.
    MissingParticipant,
    /// Missing required capability.
    MissingCapability,
    /// Missing required message kind.
    MissingRequiredMessageKind,
    /// Invalid TTL.
    InvalidTtl,
    /// Invalid payload policy.
    InvalidPayloadPolicy,
    /// Message was expired or non-expiring in the wrong direction.
    MessageExpired,
    /// Participant-local sequence regressed.
    SequenceRegression,
    /// Control/advisory message carried media or high-rate payload.
    MediaPayloadInControl,
    /// Sender start was authorized before receiver readiness.
    SenderBeforeReceiverReady,
    /// Advisory peer status tried to authorize a command.
    AdvisoryStatusCannotAuthorize,
    /// Authority boundary violation.
    AuthorityBoundaryViolation,
}
