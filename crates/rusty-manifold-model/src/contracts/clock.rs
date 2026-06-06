use super::*;

/// Clock snapshot at one read.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldClockSnapshot {
    /// Schema identifier for this snapshot.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Clock domain id.
    pub clock_domain: DottedId,
    /// Clock epoch id.
    pub clock_epoch_id: DottedId,
    /// Monotonic sequence number.
    pub sequence: u64,
    /// Monotonic elapsed nanoseconds.
    pub monotonic_elapsed_ns: u64,
    /// Wall Unix time in milliseconds for export labels.
    pub wall_unix_ms: i64,
    /// Read uncertainty in nanoseconds.
    pub read_uncertainty_ns: u64,
    /// Clock health.
    pub health: ClockHealth,
    /// Number of wall-clock adjustments observed by this epoch.
    pub wall_clock_adjustment_count: u64,
}

/// Request to change the accepted clock snapshot under Manifold authority.
///
/// The request proposes contract state only. It does not read a live clock,
/// change OS time, start a clock service, or open any host adapter.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldClockSnapshotChangeRequest {
    /// Schema identifier for this request.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable request id.
    pub request_id: DottedId,
    /// Holder requesting the clock snapshot change.
    pub holder_id: DottedId,
    /// Authority revision the requester observed.
    pub expected_authority_revision: Revision,
    /// Lease id proving authority to change the clock snapshot.
    pub lease_id: Option<DottedId>,
    /// Capability required for clock mutation.
    pub required_capability: DottedId,
    /// Clock epoch id the requester observed before the proposed change.
    pub from_clock_epoch_id: DottedId,
    /// Clock sequence the requester observed before the proposed change.
    pub from_clock_sequence: u64,
    /// Proposed accepted clock snapshot after the change.
    pub proposed_snapshot: ManifoldClockSnapshot,
}

/// Rejection for a clock snapshot change request.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldClockSnapshotRejection {
    /// Schema identifier for this rejection.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Request that was rejected.
    pub request_id: DottedId,
    /// Stable rejection code.
    pub rejection_code: DottedId,
    /// Display-safe rejection message.
    pub message: String,
    /// Whether retrying after refreshing state may help.
    pub retryable: bool,
    /// Current authority revision observed by the reviewer.
    pub current_authority_revision: Revision,
    /// Current clock epoch id observed by the reviewer.
    pub current_clock_epoch_id: DottedId,
    /// Current clock sequence observed by the reviewer.
    pub current_clock_sequence: u64,
}

/// Audit event for one clock snapshot authority decision.
///
/// The event carries the clock snapshot change request plus exactly one
/// accepted snapshot or rejected result. It records enough authority context
/// for deterministic validation without reading or mutating a live clock.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldClockSnapshotAuthorityAuditEvent {
    /// Schema identifier for this audit event.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable event id.
    pub event_id: DottedId,
    /// Authority that made the decision.
    pub authority_id: DottedId,
    /// Authority revision observed before the decision.
    pub prior_authority_revision: Revision,
    /// Accepted clock snapshot observed before the decision.
    pub prior_clock_snapshot: ManifoldClockSnapshot,
    /// Event kind.
    pub event_kind: ManifoldClockSnapshotAuthorityAuditEventKind,
    /// Clock snapshot change request reviewed by authority.
    pub request: ManifoldClockSnapshotChangeRequest,
    /// Accepted clock snapshot. Present only for accepted events.
    pub accepted: Option<ManifoldClockSnapshot>,
    /// Rejected clock snapshot result. Present only for rejected events.
    pub rejection: Option<ManifoldClockSnapshotRejection>,
    /// Lease recorded with the decision, when a lease was presented.
    pub lease: Option<ManifoldControlLease>,
    /// Clock snapshot recorded with the decision.
    pub recorded_clock: ManifoldClockSnapshot,
    /// Stable ids for fixtures, scorecards, or logs backing the event.
    pub evidence_refs: Vec<DottedId>,
}

/// Deterministic review result for one clock snapshot authority decision.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldClockSnapshotAuthorityReview {
    /// Schema identifier for this review.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable review id.
    pub review_id: DottedId,
    /// Authority that reviewed the clock snapshot change.
    pub authority_id: DottedId,
    /// Authority revision used by this review.
    pub authority_revision: Revision,
    /// Clock domain used by this review.
    pub clock_domain: DottedId,
    /// Clock epoch used by this review.
    pub clock_epoch_id: DottedId,
    /// Clock sequence used by this review.
    pub clock_sequence: u64,
    /// Review outcome.
    pub outcome: ManifoldClockSnapshotAuthorityReviewOutcome,
    /// Accepted clock snapshot. Present only for accepted reviews.
    pub accepted: Option<ManifoldClockSnapshot>,
    /// Rejected clock snapshot result. Present only for rejected reviews.
    pub rejection: Option<ManifoldClockSnapshotRejection>,
    /// Audit event for the same clock snapshot decision.
    pub audit_event: ManifoldClockSnapshotAuthorityAuditEvent,
}

impl ManifoldClockSnapshotAuthorityReview {
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
        if self.schema_id.as_str() != "rusty.manifold.authority.clock_snapshot_review.v1" {
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

        if self.clock_domain != snapshot.clock_snapshot.clock_domain
            || self.clock_domain != self.audit_event.prior_clock_snapshot.clock_domain
            || self.clock_epoch_id != snapshot.clock_snapshot.clock_epoch_id
            || self.clock_epoch_id != self.audit_event.prior_clock_snapshot.clock_epoch_id
            || self.clock_sequence != snapshot.clock_snapshot.sequence
            || self.clock_sequence != self.audit_event.prior_clock_snapshot.sequence
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.clock_domain.to_string(),
                ManifoldAuthorityValidationErrorKind::ClockSnapshotMismatch,
            ));
        }

        match self.outcome {
            ManifoldClockSnapshotAuthorityReviewOutcome::ClockSnapshotAccepted => {
                if self.accepted.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.review_id.clone(),
                        "accepted".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
            ManifoldClockSnapshotAuthorityReviewOutcome::ClockSnapshotRejected => {
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

        if ManifoldClockSnapshotAuthorityAuditEventKind::from(self.outcome)
            != self.audit_event.event_kind
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

/// Deterministic application result for one clock snapshot authority review.
///
/// This records the bridge from review-time clock authority to accepted
/// authority state without reading live time, mutating host time, or owning a
/// platform clock adapter.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldClockSnapshotAuthorityApplication {
    /// Schema identifier for this application receipt.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable application id.
    pub application_id: DottedId,
    /// Authority that attempted the application.
    pub authority_id: DottedId,
    /// Authority revision before applying the review.
    pub from_authority_revision: Revision,
    /// Clock epoch before applying the review.
    pub from_clock_epoch_id: DottedId,
    /// Clock sequence before applying the review.
    pub from_clock_sequence: u64,
    /// Application outcome.
    pub outcome: ManifoldClockSnapshotAuthorityApplicationOutcome,
    /// Next accepted authority snapshot. Present only for applied outcomes.
    pub applied_snapshot: Option<ManifoldAuthoritySnapshot>,
    /// Rejection. Present only for rejected application outcomes.
    pub rejection: Option<ManifoldAuthoritySnapshotApplicationRejection>,
    /// Review that was applied or rejected for application.
    pub review: ManifoldClockSnapshotAuthorityReview,
}

impl ManifoldClockSnapshotAuthorityApplication {
    /// Validates that this application receipt matches the supplied prior snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the receipt does not
    /// represent a deterministic state transition or deterministic application
    /// rejection for the supplied prior authority snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str() != "rusty.manifold.authority.clock_snapshot_application.v1" {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.schema_id.to_string(),
                ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
            ));
        }

        if self.authority_id != snapshot.authority_id
            || self.authority_id != self.review.authority_id
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.authority_id.to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityIdMismatch,
            ));
        }

        if self.from_authority_revision != snapshot.authority_revision
            || self.from_authority_revision != self.review.authority_revision
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.from_authority_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
            ));
        }

        if self.from_clock_epoch_id != snapshot.clock_snapshot.clock_epoch_id
            || self.from_clock_epoch_id != self.review.clock_epoch_id
            || self.from_clock_sequence != snapshot.clock_snapshot.sequence
            || self.from_clock_sequence != self.review.clock_sequence
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.from_clock_epoch_id.to_string(),
                ManifoldAuthorityValidationErrorKind::ClockSnapshotMismatch,
            ));
        }

        self.review.validate_against_snapshot(snapshot)?;

        match self.outcome {
            ManifoldClockSnapshotAuthorityApplicationOutcome::ClockSnapshotApplied => {
                if self.applied_snapshot.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        "applied_snapshot".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                if self.review.outcome
                    != ManifoldClockSnapshotAuthorityReviewOutcome::ClockSnapshotAccepted
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        self.review.review_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                let applied = self
                    .applied_snapshot
                    .as_ref()
                    .expect("applied snapshot presence checked");
                let expected_authority_revision =
                    snapshot.authority_revision.next().ok_or_else(|| {
                        ManifoldAuthorityValidationError::new(
                            self.application_id.clone(),
                            snapshot.authority_revision.get().to_string(),
                            ManifoldAuthorityValidationErrorKind::AcceptanceRevisionMismatch,
                        )
                    })?;

                if applied.authority_revision != expected_authority_revision {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        applied.authority_revision.get().to_string(),
                        ManifoldAuthorityValidationErrorKind::AcceptanceRevisionMismatch,
                    ));
                }

                if applied.authority_id != snapshot.authority_id
                    || applied.host_manifest != snapshot.host_manifest
                    || applied.stream_registry != snapshot.stream_registry
                    || applied.module_runtime_states != snapshot.module_runtime_states
                    || applied.command_ids != snapshot.command_ids
                    || applied.command_descriptors != snapshot.command_descriptors
                    || applied.active_leases != snapshot.active_leases
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        applied.authority_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::ClockSnapshotMismatch,
                    ));
                }

                if applied.clock_snapshot
                    != self.review.accepted.clone().ok_or_else(|| {
                        ManifoldAuthorityValidationError::new(
                            self.application_id.clone(),
                            "accepted".to_owned(),
                            ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                        )
                    })?
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        applied.clock_snapshot.clock_domain.to_string(),
                        ManifoldAuthorityValidationErrorKind::ClockSnapshotMismatch,
                    ));
                }

                applied.validate_authority_links()
            }
            ManifoldClockSnapshotAuthorityApplicationOutcome::ClockSnapshotApplicationRejected => {
                if self.applied_snapshot.is_some() || self.rejection.is_none() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                let rejection = self
                    .rejection
                    .as_ref()
                    .expect("application rejection presence checked");
                if rejection.schema_id.as_str()
                    != "rusty.manifold.authority.snapshot_application_rejection.v1"
                    || rejection.application_id != self.application_id
                    || rejection.current_authority_revision != snapshot.authority_revision
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        rejection.rejection_code.to_string(),
                        ManifoldAuthorityValidationErrorKind::RejectionMismatch,
                    ));
                }

                if self.review.outcome
                    == ManifoldClockSnapshotAuthorityReviewOutcome::ClockSnapshotRejected
                    && rejection.rejection_code.as_str() != "review_rejected"
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        rejection.rejection_code.to_string(),
                        ManifoldAuthorityValidationErrorKind::RejectionMismatch,
                    ));
                }

                Ok(())
            }
        }
    }
}

impl ManifoldClockSnapshotAuthorityAuditEvent {
    /// Validates this event against the authority snapshot it claims to use.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the event is not a
    /// consistent clock snapshot acceptance or rejection for the supplied snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str() != "rusty.manifold.authority.clock_snapshot_audit_event.v1" {
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

        if self.prior_clock_snapshot != snapshot.clock_snapshot {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.prior_clock_snapshot.clock_domain.to_string(),
                ManifoldAuthorityValidationErrorKind::ClockSnapshotMismatch,
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
            ManifoldClockSnapshotAuthorityAuditEventKind::ClockSnapshotAccepted => {
                if self.accepted.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        "accepted".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
            ManifoldClockSnapshotAuthorityAuditEventKind::ClockSnapshotRejected => {
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
            .request
            .lease_id
            .as_ref()
            .and_then(|id| snapshot.active_lease(id));
        if let Some(recorded_lease) = &self.lease {
            if self.request.lease_id.as_ref() != Some(&recorded_lease.lease_id) {
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
            snapshot.clock_snapshot_authority_decision(&self.request, &self.recorded_clock);

        if let Some(accepted) = &self.accepted {
            let ClockSnapshotAuthorityDecision::Accepted(expected_snapshot) = &expected_decision
            else {
                let rejected_value = match &expected_decision {
                    ClockSnapshotAuthorityDecision::Rejected { rejection_code, .. } => {
                        rejection_code.clone()
                    }
                    ClockSnapshotAuthorityDecision::Accepted(_) => "accepted".to_owned(),
                };
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejected_value.clone(),
                    authority_error_kind_for_clock_snapshot_rejection_code(&rejected_value),
                ));
            };

            if accepted != expected_snapshot {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    accepted.clock_domain.to_string(),
                    ManifoldAuthorityValidationErrorKind::ClockSnapshotMismatch,
                ));
            }
        }

        if let Some(rejection) = &self.rejection {
            let ClockSnapshotAuthorityDecision::Rejected {
                rejection_code,
                message,
                retryable,
            } = &expected_decision
            else {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    self.request.request_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                ));
            };

            if rejection.request_id != self.request.request_id {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejection.request_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::RequestIdMismatch,
                ));
            }

            if rejection.current_authority_revision != self.prior_authority_revision
                || rejection.current_clock_epoch_id != self.prior_clock_snapshot.clock_epoch_id
                || rejection.current_clock_sequence != self.prior_clock_snapshot.sequence
            {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejection.current_clock_epoch_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::RejectionRevisionMismatch,
                ));
            }

            if rejection.rejection_code.as_str() != rejection_code
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

/// Clock snapshot authority audit event kind.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldClockSnapshotAuthorityAuditEventKind {
    /// Authority accepted a clock snapshot change request.
    ClockSnapshotAccepted,
    /// Authority rejected a clock snapshot change request.
    ClockSnapshotRejected,
}

/// Clock snapshot authority review outcome.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldClockSnapshotAuthorityReviewOutcome {
    /// Authority accepted the clock snapshot change request.
    ClockSnapshotAccepted,
    /// Authority rejected the clock snapshot change request.
    ClockSnapshotRejected,
}

/// Clock snapshot authority application outcome.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldClockSnapshotAuthorityApplicationOutcome {
    /// Accepted clock snapshot review was applied to the authority snapshot.
    ClockSnapshotApplied,
    /// Clock snapshot review could not be applied to accepted authority state.
    ClockSnapshotApplicationRejected,
}

impl From<ManifoldClockSnapshotAuthorityReviewOutcome>
    for ManifoldClockSnapshotAuthorityAuditEventKind
{
    fn from(outcome: ManifoldClockSnapshotAuthorityReviewOutcome) -> Self {
        match outcome {
            ManifoldClockSnapshotAuthorityReviewOutcome::ClockSnapshotAccepted => {
                Self::ClockSnapshotAccepted
            }
            ManifoldClockSnapshotAuthorityReviewOutcome::ClockSnapshotRejected => {
                Self::ClockSnapshotRejected
            }
        }
    }
}

/// Clock health.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockHealth {
    /// Healthy.
    Healthy,
    /// Degraded.
    Degraded,
    /// Unavailable.
    Unavailable,
}
