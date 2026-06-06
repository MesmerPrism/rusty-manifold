use super::*;

/// Mutating command descriptor.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldCommandDescriptor {
    /// Schema identifier for this descriptor.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable command id.
    pub command_id: DottedId,
    /// Target scope for the command.
    pub target_scope: DottedId,
    /// Input schema id.
    pub input_schema: SchemaId,
    /// Required capability.
    pub required_capability: DottedId,
    /// Required lease scope, if this command is exclusive.
    pub required_lease_scope: Option<DottedId>,
    /// Safety class.
    pub safety_class: SafetyClass,
    /// Whether operator confirmation is required.
    pub operator_confirmation_required: bool,
}

/// Command request envelope sent to Manifold authority.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldCommandEnvelope {
    /// Schema identifier for this envelope.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Request id.
    pub request_id: DottedId,
    /// Command id.
    pub command_id: DottedId,
    /// Target id.
    pub target_id: DottedId,
    /// Target scope.
    pub target_scope: DottedId,
    /// Input schema id.
    pub input_schema: SchemaId,
    /// Expected authority revision.
    pub expected_revision: Option<Revision>,
    /// Capability presented with the request.
    pub required_capability: DottedId,
    /// Lease id presented with the request.
    pub lease_id: Option<DottedId>,
    /// Preconditions declared by the client.
    pub preconditions: Vec<CommandPrecondition>,
    /// Safety class.
    pub safety_class: SafetyClass,
    /// Request timestamp in milliseconds in the holder's chosen clock domain.
    pub requested_at_ms: u64,
    /// Holder id.
    pub holder_id: DottedId,
}

impl ManifoldCommandEnvelope {
    /// Validates the envelope against a descriptor, current revision, and optional lease.
    ///
    /// # Errors
    ///
    /// Returns [`CommandValidationError`] when the envelope does not match the
    /// descriptor, revision, required capability, or required lease.
    pub fn validate_request(
        &self,
        descriptor: &ManifoldCommandDescriptor,
        current_revision: Revision,
        active_lease: Option<&ManifoldControlLease>,
    ) -> Result<(), CommandValidationError> {
        if self.command_id != descriptor.command_id {
            return Err(CommandValidationError::new(
                CommandValidationErrorKind::CommandMismatch,
                "command id does not match descriptor",
            ));
        }

        if self.target_scope != descriptor.target_scope {
            return Err(CommandValidationError::new(
                CommandValidationErrorKind::TargetScopeMismatch,
                "target scope does not match descriptor",
            ));
        }

        if self.required_capability != descriptor.required_capability {
            return Err(CommandValidationError::new(
                CommandValidationErrorKind::CapabilityMismatch,
                "required capability does not match descriptor",
            ));
        }

        if let Some(expected_revision) = self.expected_revision {
            if expected_revision != current_revision {
                return Err(CommandValidationError::new(
                    CommandValidationErrorKind::StaleRevision,
                    "expected revision does not match current revision",
                ));
            }
        }

        if let Some(required_scope) = &descriptor.required_lease_scope {
            let lease = active_lease.ok_or_else(|| {
                CommandValidationError::new(
                    CommandValidationErrorKind::MissingLease,
                    "command requires an active lease",
                )
            })?;

            if lease.state != LeaseState::Active {
                return Err(CommandValidationError::new(
                    CommandValidationErrorKind::InactiveLease,
                    "lease is not active",
                ));
            }

            if lease.scope != *required_scope {
                return Err(CommandValidationError::new(
                    CommandValidationErrorKind::LeaseScopeMismatch,
                    "lease scope does not match command scope",
                ));
            }

            if self.lease_id.as_ref() != Some(&lease.lease_id) {
                return Err(CommandValidationError::new(
                    CommandValidationErrorKind::LeaseIdMismatch,
                    "envelope lease id does not match active lease",
                ));
            }

            if lease.holder_id != self.holder_id {
                return Err(CommandValidationError::new(
                    CommandValidationErrorKind::LeaseHolderMismatch,
                    "lease holder does not match request holder",
                ));
            }

            if lease.granted_revision != current_revision {
                return Err(CommandValidationError::new(
                    CommandValidationErrorKind::LeaseRevisionMismatch,
                    "lease revision does not match current revision",
                ));
            }
        }

        Ok(())
    }
}

/// Accepted command result.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldCommandAck {
    /// Schema identifier for this acknowledgement.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Request id being acknowledged.
    pub request_id: DottedId,
    /// Revision accepted by authority.
    pub accepted_revision: Revision,
    /// Lease used for acceptance, if any.
    pub lease_id: Option<DottedId>,
    /// Authority id.
    pub authority_id: DottedId,
    /// Acceptance timestamp in milliseconds.
    pub accepted_at_ms: u64,
}

/// Rejected command result.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldCommandRejection {
    /// Schema identifier for this rejection.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Request id being rejected.
    pub request_id: DottedId,
    /// Machine-readable rejection code.
    pub rejection_code: DottedId,
    /// Display-safe explanation.
    pub message: String,
    /// Whether retry is safe without operator intervention.
    pub retryable: bool,
    /// Current authority revision, when applicable.
    pub current_revision: Option<Revision>,
}

/// Command authority audit event kind.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldCommandAuthorityAuditEventKind {
    /// Authority accepted a command request.
    CommandAccepted,
    /// Authority rejected a command request.
    CommandRejected,
}

/// Command authority review outcome.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldCommandAuthorityReviewOutcome {
    /// Authority accepted the command request.
    CommandAccepted,
    /// Authority rejected the command request.
    CommandRejected,
}

impl From<ManifoldCommandAuthorityReviewOutcome> for ManifoldCommandAuthorityAuditEventKind {
    fn from(outcome: ManifoldCommandAuthorityReviewOutcome) -> Self {
        match outcome {
            ManifoldCommandAuthorityReviewOutcome::CommandAccepted => Self::CommandAccepted,
            ManifoldCommandAuthorityReviewOutcome::CommandRejected => Self::CommandRejected,
        }
    }
}

/// Audit event for one command authority decision.
///
/// The event carries the request envelope plus exactly one accepted or rejected
/// result. It records enough local authority context for deterministic
/// validation without depending on the legacy broker runtime.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldCommandAuthorityAuditEvent {
    /// Schema identifier for this audit event.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable event id.
    pub event_id: DottedId,
    /// Authority that made the decision.
    pub authority_id: DottedId,
    /// Authority revision observed before the decision.
    pub prior_authority_revision: Revision,
    /// Event kind.
    pub event_kind: ManifoldCommandAuthorityAuditEventKind,
    /// Command request reviewed by authority.
    pub envelope: ManifoldCommandEnvelope,
    /// Accepted result. Present only for accepted events.
    pub accepted: Option<ManifoldCommandAck>,
    /// Rejected result. Present only for rejected events.
    pub rejection: Option<ManifoldCommandRejection>,
    /// Lease recorded with the decision, when a lease was presented.
    pub lease: Option<ManifoldControlLease>,
    /// Clock snapshot recorded with the decision.
    pub recorded_clock: ManifoldClockSnapshot,
    /// Stable ids for fixtures, scorecards, or logs backing the event.
    pub evidence_refs: Vec<DottedId>,
}

/// Deterministic review result for one command authority decision.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldCommandAuthorityReview {
    /// Schema identifier for this review.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable review id.
    pub review_id: DottedId,
    /// Authority that reviewed the command.
    pub authority_id: DottedId,
    /// Authority revision used by this review.
    pub authority_revision: Revision,
    /// Review outcome.
    pub outcome: ManifoldCommandAuthorityReviewOutcome,
    /// Accepted command result. Present only for accepted reviews.
    pub accepted: Option<ManifoldCommandAck>,
    /// Rejected command result. Present only for rejected reviews.
    pub rejection: Option<ManifoldCommandRejection>,
    /// Audit event for the same command decision.
    pub audit_event: ManifoldCommandAuthorityAuditEvent,
}

impl ManifoldCommandAuthorityReview {
    /// Validates that this review matches the supplied authority snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when review fields and the
    /// nested audit event disagree, or when the event is not valid for the snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str() != "rusty.manifold.authority.command_review.v1" {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.schema_id.to_string(),
                ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
            ));
        }

        if self.authority_id != snapshot.authority_id
            || self.authority_id != self.audit_event.authority_id
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.authority_id.to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityIdMismatch,
            ));
        }

        if self.authority_revision != snapshot.authority_revision
            || self.authority_revision != self.audit_event.prior_authority_revision
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.authority_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
            ));
        }

        match self.outcome {
            ManifoldCommandAuthorityReviewOutcome::CommandAccepted => {
                if self.accepted.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.review_id.clone(),
                        "accepted".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
            ManifoldCommandAuthorityReviewOutcome::CommandRejected => {
                if self.accepted.is_some() || self.rejection.is_none() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.review_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
        }

        if self.accepted != self.audit_event.accepted
            || self.rejection != self.audit_event.rejection
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.audit_event.event_id.to_string(),
                ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
            ));
        }

        if ManifoldCommandAuthorityAuditEventKind::from(self.outcome) != self.audit_event.event_kind
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.audit_event.event_id.to_string(),
                ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
            ));
        }

        self.audit_event.validate_against_snapshot(snapshot)
    }
}

impl ManifoldCommandAuthorityAuditEvent {
    /// Validates this event against the authority snapshot it claims to use.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the event is not a
    /// consistent command acceptance or rejection for the supplied snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str() != "rusty.manifold.authority.command_audit_event.v1" {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.schema_id.to_string(),
                ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
            ));
        }

        snapshot.validate_authority_links()?;

        if self.authority_id != snapshot.authority_id {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.authority_id.to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityIdMismatch,
            ));
        }

        if self.prior_authority_revision != snapshot.authority_revision {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.prior_authority_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
            ));
        }

        if self.recorded_clock.clock_domain != snapshot.clock_snapshot.clock_domain
            || self.recorded_clock.clock_epoch_id != snapshot.clock_snapshot.clock_epoch_id
            || self.recorded_clock.sequence < snapshot.clock_snapshot.sequence
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.recorded_clock.clock_domain.to_string(),
                ManifoldAuthorityValidationErrorKind::ClockSnapshotMismatch,
            ));
        }

        if self.evidence_refs.is_empty() {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                "evidence_refs".to_owned(),
                ManifoldAuthorityValidationErrorKind::MissingEvidence,
            ));
        }

        match self.event_kind {
            ManifoldCommandAuthorityAuditEventKind::CommandAccepted => {
                if self.accepted.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        "accepted".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
            ManifoldCommandAuthorityAuditEventKind::CommandRejected => {
                if self.accepted.is_some() || self.rejection.is_none() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
        }

        let snapshot_lease = self
            .envelope
            .lease_id
            .as_ref()
            .and_then(|id| snapshot.active_lease(id));
        if let Some(recorded_lease) = &self.lease {
            if self.envelope.lease_id.as_ref() != Some(&recorded_lease.lease_id) {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    recorded_lease.lease_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::LeaseMismatch,
                ));
            }

            let Some(snapshot_lease) = snapshot_lease else {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    recorded_lease.lease_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::UnknownLease,
                ));
            };

            if snapshot_lease != recorded_lease {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    recorded_lease.lease_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::LeaseMismatch,
                ));
            }
        }

        let expected_decision =
            snapshot.command_authority_decision(&self.envelope, &self.recorded_clock);

        if let Some(accepted) = &self.accepted {
            if let CommandAuthorityDecision::Rejected { rejection_code, .. } = &expected_decision {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    (*rejection_code).to_owned(),
                    authority_error_kind_for_rejection_code(rejection_code),
                ));
            }

            if accepted.request_id != self.envelope.request_id {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    accepted.request_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::RequestIdMismatch,
                ));
            }

            if accepted.authority_id != self.authority_id {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    accepted.authority_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::AuthorityIdMismatch,
                ));
            }

            let expected_accepted_revision =
                self.prior_authority_revision.next().ok_or_else(|| {
                    ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        self.prior_authority_revision.get().to_string(),
                        ManifoldAuthorityValidationErrorKind::AcceptanceRevisionMismatch,
                    )
                })?;
            if accepted.accepted_revision != expected_accepted_revision {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    accepted.accepted_revision.get().to_string(),
                    ManifoldAuthorityValidationErrorKind::AcceptanceRevisionMismatch,
                ));
            }

            if accepted.lease_id != self.envelope.lease_id {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    "accepted.lease_id".to_owned(),
                    ManifoldAuthorityValidationErrorKind::LeaseMismatch,
                ));
            }
        }

        if let Some(rejection) = &self.rejection {
            let CommandAuthorityDecision::Rejected {
                rejection_code,
                message,
                retryable,
            } = &expected_decision
            else {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    self.envelope.command_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                ));
            };

            if rejection.request_id != self.envelope.request_id {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejection.request_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::RequestIdMismatch,
                ));
            }

            if rejection.current_revision != Some(self.prior_authority_revision) {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejection
                        .current_revision
                        .map(|revision| revision.get().to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    ManifoldAuthorityValidationErrorKind::RejectionRevisionMismatch,
                ));
            }

            if rejection.rejection_code.as_str() != *rejection_code
                || rejection.message != *message
                || rejection.retryable != *retryable
            {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejection.rejection_code.to_string(),
                    ManifoldAuthorityValidationErrorKind::RejectionMismatch,
                ));
            }
        }

        Ok(())
    }
}

/// Command request validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandValidationError {
    kind: CommandValidationErrorKind,
    message: &'static str,
}

impl CommandValidationError {
    fn new(kind: CommandValidationErrorKind, message: &'static str) -> Self {
        Self { kind, message }
    }

    /// Returns the failure kind.
    #[must_use]
    pub const fn kind(&self) -> CommandValidationErrorKind {
        self.kind
    }

    /// Returns the display-safe message.
    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }

    /// Returns a stable rejection code.
    #[must_use]
    pub const fn rejection_code(&self) -> &'static str {
        match self.kind {
            CommandValidationErrorKind::CommandMismatch => "command_mismatch",
            CommandValidationErrorKind::TargetScopeMismatch => "target_scope_mismatch",
            CommandValidationErrorKind::CapabilityMismatch => "capability_mismatch",
            CommandValidationErrorKind::StaleRevision => "stale_revision",
            CommandValidationErrorKind::MissingLease => "missing_lease",
            CommandValidationErrorKind::InactiveLease => "inactive_lease",
            CommandValidationErrorKind::LeaseScopeMismatch => "lease_scope_mismatch",
            CommandValidationErrorKind::LeaseIdMismatch => "lease_id_mismatch",
            CommandValidationErrorKind::LeaseHolderMismatch => "lease_holder_mismatch",
            CommandValidationErrorKind::LeaseRevisionMismatch => "lease_revision_mismatch",
        }
    }
}

impl fmt::Display for CommandValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for CommandValidationError {}

/// Command validation failure kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandValidationErrorKind {
    /// Command id does not match the descriptor.
    CommandMismatch,
    /// Target scope does not match the descriptor.
    TargetScopeMismatch,
    /// Capability does not match the descriptor.
    CapabilityMismatch,
    /// Expected revision is stale.
    StaleRevision,
    /// A required lease is missing.
    MissingLease,
    /// The lease is not active.
    InactiveLease,
    /// The lease scope does not match.
    LeaseScopeMismatch,
    /// The lease id does not match.
    LeaseIdMismatch,
    /// The lease holder does not match.
    LeaseHolderMismatch,
    /// The lease revision does not match.
    LeaseRevisionMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CommandAuthorityDecision {
    Accepted,
    Rejected {
        rejection_code: &'static str,
        message: String,
        retryable: bool,
    },
}

impl ManifoldAuthoritySnapshot {
    /// Deterministically reviews one command envelope against this authority snapshot.
    ///
    /// The review is source-only: it does not execute the command, mutate runtime
    /// state, open transports, or contact a host. Accepted reviews advance the
    /// reported authority revision by one; rejected reviews keep the current
    /// authority revision in the rejection.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the authority snapshot
    /// itself is invalid, the review clock is inconsistent, or evidence refs are empty.
    pub fn review_command(
        &self,
        envelope: ManifoldCommandEnvelope,
        recorded_clock: ManifoldClockSnapshot,
        evidence_refs: Vec<DottedId>,
    ) -> Result<ManifoldCommandAuthorityReview, ManifoldAuthorityValidationError> {
        self.validate_authority_links()?;

        if recorded_clock.clock_domain != self.clock_snapshot.clock_domain
            || recorded_clock.clock_epoch_id != self.clock_snapshot.clock_epoch_id
            || recorded_clock.sequence < self.clock_snapshot.sequence
        {
            return Err(ManifoldAuthorityValidationError::new(
                envelope.request_id.clone(),
                recorded_clock.clock_domain.to_string(),
                ManifoldAuthorityValidationErrorKind::ClockSnapshotMismatch,
            ));
        }

        if evidence_refs.is_empty() {
            return Err(ManifoldAuthorityValidationError::new(
                envelope.request_id.clone(),
                "evidence_refs".to_owned(),
                ManifoldAuthorityValidationErrorKind::MissingEvidence,
            ));
        }

        let decision = self.command_authority_decision(&envelope, &recorded_clock);
        let lease = envelope
            .lease_id
            .as_ref()
            .and_then(|lease_id| self.active_lease(lease_id))
            .cloned();
        let (outcome, accepted, rejection) = match decision {
            CommandAuthorityDecision::Accepted => {
                let accepted_revision = self.authority_revision.next().ok_or_else(|| {
                    ManifoldAuthorityValidationError::new(
                        envelope.request_id.clone(),
                        self.authority_revision.get().to_string(),
                        ManifoldAuthorityValidationErrorKind::AcceptanceRevisionMismatch,
                    )
                })?;
                (
                    ManifoldCommandAuthorityReviewOutcome::CommandAccepted,
                    Some(ManifoldCommandAck {
                        schema_id: command_ack_schema_id(),
                        request_id: envelope.request_id.clone(),
                        accepted_revision,
                        lease_id: envelope.lease_id.clone(),
                        authority_id: self.authority_id.clone(),
                        accepted_at_ms: wall_unix_ms_u64(&recorded_clock),
                    }),
                    None,
                )
            }
            CommandAuthorityDecision::Rejected {
                rejection_code,
                message,
                retryable,
            } => (
                ManifoldCommandAuthorityReviewOutcome::CommandRejected,
                None,
                Some(ManifoldCommandRejection {
                    schema_id: command_rejection_schema_id(),
                    request_id: envelope.request_id.clone(),
                    rejection_code: DottedId::new(rejection_code)
                        .expect("rejection code literal is a valid dotted id"),
                    message,
                    retryable,
                    current_revision: Some(self.authority_revision),
                }),
            ),
        };

        let audit_event = ManifoldCommandAuthorityAuditEvent {
            schema_id: command_authority_audit_event_schema_id(),
            event_id: command_authority_audit_event_id(&envelope.request_id, outcome),
            authority_id: self.authority_id.clone(),
            prior_authority_revision: self.authority_revision,
            event_kind: outcome.into(),
            envelope,
            accepted: accepted.clone(),
            rejection: rejection.clone(),
            lease,
            recorded_clock,
            evidence_refs,
        };

        let review = ManifoldCommandAuthorityReview {
            schema_id: command_authority_review_schema_id(),
            review_id: command_authority_review_id(&audit_event.envelope.request_id),
            authority_id: self.authority_id.clone(),
            authority_revision: self.authority_revision,
            outcome,
            accepted,
            rejection,
            audit_event,
        };
        review.validate_against_snapshot(self)?;
        Ok(review)
    }

    /// Prepares one accepted command review for downstream dispatch.
    ///
    /// The receipt is source-only. It confirms that a command authority review
    /// is valid for this snapshot and is ready for a downstream transport or
    /// executor to consume, but it does not execute the command, mutate
    /// accepted authority state, open transports, or contact a host.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when this snapshot is
    /// invalid or the supplied review does not match this authority snapshot.
    pub fn prepare_command_dispatch(
        &self,
        review: ManifoldCommandAuthorityReview,
    ) -> Result<ManifoldCommandDispatchReceipt, ManifoldAuthorityValidationError> {
        self.validate_authority_links()?;
        review.validate_against_snapshot(self)?;

        let dispatch_id = command_dispatch_receipt_id(&review.review_id);
        let command_id = review.audit_event.envelope.command_id.clone();
        let request_id = review.audit_event.envelope.request_id.clone();

        let (outcome, ack, rejection) =
            if review.outcome == ManifoldCommandAuthorityReviewOutcome::CommandRejected {
                (
                    ManifoldCommandDispatchReceiptOutcome::CommandDispatchRejected,
                    None,
                    Some(ManifoldCommandDispatchRejection {
                        schema_id: command_dispatch_rejection_schema_id(),
                        dispatch_id: dispatch_id.clone(),
                        rejection_code: DottedId::new("review_rejected")
                            .expect("rejection code literal is valid"),
                        message: "command review did not accept a command".to_owned(),
                        retryable: review
                            .rejection
                            .as_ref()
                            .map(|rejection| rejection.retryable)
                            .unwrap_or(false),
                        current_authority_revision: self.authority_revision,
                    }),
                )
            } else {
                let ack = review.accepted.clone().ok_or_else(|| {
                    ManifoldAuthorityValidationError::new(
                        review.review_id.clone(),
                        "accepted".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    )
                })?;
                (
                    ManifoldCommandDispatchReceiptOutcome::CommandDispatchReady,
                    Some(ack),
                    None,
                )
            };

        let receipt = ManifoldCommandDispatchReceipt {
            schema_id: command_dispatch_receipt_schema_id(),
            dispatch_id,
            authority_id: self.authority_id.clone(),
            authority_revision: self.authority_revision,
            command_id,
            request_id,
            outcome,
            ack,
            rejection,
            review,
        };
        receipt.validate_against_snapshot(self)?;
        Ok(receipt)
    }

    fn command_descriptor(&self, command_id: &DottedId) -> Option<&ManifoldCommandDescriptor> {
        self.command_descriptors
            .iter()
            .find(|descriptor| &descriptor.command_id == command_id)
    }

    fn command_authority_decision(
        &self,
        envelope: &ManifoldCommandEnvelope,
        recorded_clock: &ManifoldClockSnapshot,
    ) -> CommandAuthorityDecision {
        let Some(descriptor) = self.command_descriptor(&envelope.command_id) else {
            return CommandAuthorityDecision::Rejected {
                rejection_code: "unknown_command",
                message: "command is not advertised by this authority".to_owned(),
                retryable: false,
            };
        };

        let active_lease = if let Some(lease_id) = &envelope.lease_id {
            let Some(lease) = self.active_lease(lease_id) else {
                return CommandAuthorityDecision::Rejected {
                    rejection_code: "unknown_lease",
                    message: "command references an unknown lease".to_owned(),
                    retryable: true,
                };
            };
            Some(lease)
        } else {
            None
        };

        if let Some(lease) = active_lease {
            if lease_expired_at(lease, recorded_clock) {
                return CommandAuthorityDecision::Rejected {
                    rejection_code: "expired_lease",
                    message: "command references a lease expired at the review clock".to_owned(),
                    retryable: true,
                };
            }
        }

        match envelope.validate_request(descriptor, self.authority_revision, active_lease) {
            Ok(()) => CommandAuthorityDecision::Accepted,
            Err(error) => CommandAuthorityDecision::Rejected {
                rejection_code: error.rejection_code(),
                message: error.message().to_owned(),
                retryable: command_validation_retryable(error.kind()),
            },
        }
    }
}

/// Rejection for a command dispatch receipt.
///
/// Dispatch rejection is distinct from command authority rejection. It reports
/// why a reviewed command was not handed to downstream transport or execution,
/// without mutating authority state or running the command.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldCommandDispatchRejection {
    /// Schema identifier for this dispatch rejection.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Dispatch receipt id this rejection belongs to.
    pub dispatch_id: DottedId,
    /// Stable rejection code.
    pub rejection_code: DottedId,
    /// Human-readable explanation.
    pub message: String,
    /// Whether retrying after refreshing authority state may help.
    pub retryable: bool,
    /// Current authority revision.
    pub current_authority_revision: Revision,
}

/// Source-only receipt preparing a reviewed command for downstream dispatch.
///
/// This is a handoff contract between Manifold authority and a later transport
/// or executor. It confirms ack/rejection shape and review provenance without
/// opening a transport, contacting a host, executing the command, or mutating
/// accepted authority state.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldCommandDispatchReceipt {
    /// Schema identifier for this dispatch receipt.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable dispatch receipt id.
    pub dispatch_id: DottedId,
    /// Authority that prepared the dispatch receipt.
    pub authority_id: DottedId,
    /// Authority revision used by this receipt.
    pub authority_revision: Revision,
    /// Command id being prepared for dispatch.
    pub command_id: DottedId,
    /// Command request id being prepared for dispatch.
    pub request_id: DottedId,
    /// Dispatch receipt outcome.
    pub outcome: ManifoldCommandDispatchReceiptOutcome,
    /// Accepted command ack. Present only for ready receipts.
    pub ack: Option<ManifoldCommandAck>,
    /// Dispatch rejection. Present only for rejected receipts.
    pub rejection: Option<ManifoldCommandDispatchRejection>,
    /// Command authority review being handed off.
    pub review: ManifoldCommandAuthorityReview,
}

impl ManifoldCommandDispatchReceipt {
    /// Validates that this dispatch receipt matches the supplied snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the receipt does not
    /// represent a deterministic command dispatch handoff for the supplied
    /// authority snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str() != "rusty.manifold.authority.command_dispatch_receipt.v1" {
            return Err(ManifoldAuthorityValidationError::new(
                self.dispatch_id.clone(),
                self.schema_id.to_string(),
                ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
            ));
        }

        validate_derived_authority_id(
            &self.dispatch_id,
            &self.dispatch_id,
            command_dispatch_receipt_id(&self.review.review_id),
        )?;

        if self.authority_id != snapshot.authority_id
            || self.authority_id != self.review.authority_id
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.dispatch_id.clone(),
                self.authority_id.to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityIdMismatch,
            ));
        }

        if self.authority_revision != snapshot.authority_revision
            || self.authority_revision != self.review.authority_revision
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.dispatch_id.clone(),
                self.authority_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
            ));
        }

        if self.command_id != self.review.audit_event.envelope.command_id
            || self.request_id != self.review.audit_event.envelope.request_id
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.dispatch_id.clone(),
                self.command_id.to_string(),
                ManifoldAuthorityValidationErrorKind::RequestIdMismatch,
            ));
        }

        self.review.validate_against_snapshot(snapshot)?;

        match self.outcome {
            ManifoldCommandDispatchReceiptOutcome::CommandDispatchReady => {
                if self.ack.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.dispatch_id.clone(),
                        "ack".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                if self.review.outcome != ManifoldCommandAuthorityReviewOutcome::CommandAccepted {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.dispatch_id.clone(),
                        self.review.review_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                let ack = self.ack.as_ref().expect("ack presence checked");
                if Some(ack) != self.review.accepted.as_ref() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.dispatch_id.clone(),
                        self.request_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                let expected_accepted_revision =
                    snapshot.authority_revision.next().ok_or_else(|| {
                        ManifoldAuthorityValidationError::new(
                            self.dispatch_id.clone(),
                            snapshot.authority_revision.get().to_string(),
                            ManifoldAuthorityValidationErrorKind::AcceptanceRevisionMismatch,
                        )
                    })?;
                if ack.accepted_revision != expected_accepted_revision {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.dispatch_id.clone(),
                        ack.accepted_revision.get().to_string(),
                        ManifoldAuthorityValidationErrorKind::AcceptanceRevisionMismatch,
                    ));
                }

                Ok(())
            }
            ManifoldCommandDispatchReceiptOutcome::CommandDispatchRejected => {
                if self.ack.is_some() || self.rejection.is_none() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.dispatch_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                if self.review.outcome != ManifoldCommandAuthorityReviewOutcome::CommandRejected {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.dispatch_id.clone(),
                        self.review.review_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                let rejection = self
                    .rejection
                    .as_ref()
                    .expect("dispatch rejection presence checked");
                if rejection.schema_id.as_str()
                    != "rusty.manifold.authority.command_dispatch_rejection.v1"
                    || rejection.dispatch_id != self.dispatch_id
                    || rejection.current_authority_revision != snapshot.authority_revision
                    || rejection.rejection_code.as_str() != "review_rejected"
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.dispatch_id.clone(),
                        rejection.rejection_code.to_string(),
                        ManifoldAuthorityValidationErrorKind::RejectionMismatch,
                    ));
                }

                Ok(())
            }
        }
    }
}

/// Command dispatch receipt outcome.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldCommandDispatchReceiptOutcome {
    /// Accepted command review is ready for downstream dispatch.
    CommandDispatchReady,
    /// Command review was not accepted for downstream dispatch.
    CommandDispatchRejected,
}
