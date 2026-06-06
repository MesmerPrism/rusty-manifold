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

        validate_derived_authority_id(
            &self.application_id,
            &self.application_id,
            clock_snapshot_authority_application_id(&self.review.review_id),
        )?;

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

#[derive(Clone, Debug, Eq, PartialEq)]
enum ClockSnapshotAuthorityDecision {
    Accepted(ManifoldClockSnapshot),
    Rejected {
        rejection_code: String,
        message: String,
        retryable: bool,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ClockSnapshotRejection {
    rejection_code: String,
    message: String,
    retryable: bool,
}

impl ClockSnapshotRejection {
    fn new(rejection_code: impl Into<String>, message: impl Into<String>, retryable: bool) -> Self {
        Self {
            rejection_code: rejection_code.into(),
            message: message.into(),
            retryable,
        }
    }
}

impl ManifoldAuthoritySnapshot {
    /// Deterministically reviews one clock snapshot change request.
    ///
    /// The review is source-only: it accepts or rejects proposed contract state
    /// and does not read a live clock, alter host time, start a clock service,
    /// or contact a platform adapter.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the authority snapshot
    /// itself is invalid, the review clock is inconsistent, or evidence refs are empty.
    pub fn review_clock_snapshot_change(
        &self,
        request: ManifoldClockSnapshotChangeRequest,
        recorded_clock: ManifoldClockSnapshot,
        evidence_refs: Vec<DottedId>,
    ) -> Result<ManifoldClockSnapshotAuthorityReview, ManifoldAuthorityValidationError> {
        self.validate_authority_links()?;

        if recorded_clock.clock_domain != self.clock_snapshot.clock_domain
            || recorded_clock.clock_epoch_id != self.clock_snapshot.clock_epoch_id
            || recorded_clock.sequence < self.clock_snapshot.sequence
        {
            return Err(ManifoldAuthorityValidationError::new(
                request.request_id.clone(),
                recorded_clock.clock_domain.to_string(),
                ManifoldAuthorityValidationErrorKind::ClockSnapshotMismatch,
            ));
        }

        if evidence_refs.is_empty() {
            return Err(ManifoldAuthorityValidationError::new(
                request.request_id.clone(),
                "evidence_refs".to_owned(),
                ManifoldAuthorityValidationErrorKind::MissingEvidence,
            ));
        }

        let decision = self.clock_snapshot_authority_decision(&request, &recorded_clock);
        let lease = request
            .lease_id
            .as_ref()
            .and_then(|lease_id| self.active_lease(lease_id))
            .cloned();
        let (outcome, accepted, rejection) = match decision {
            ClockSnapshotAuthorityDecision::Accepted(snapshot) => (
                ManifoldClockSnapshotAuthorityReviewOutcome::ClockSnapshotAccepted,
                Some(snapshot),
                None,
            ),
            ClockSnapshotAuthorityDecision::Rejected {
                rejection_code,
                message,
                retryable,
            } => (
                ManifoldClockSnapshotAuthorityReviewOutcome::ClockSnapshotRejected,
                None,
                Some(ManifoldClockSnapshotRejection {
                    schema_id: clock_snapshot_rejection_schema_id(),
                    request_id: request.request_id.clone(),
                    rejection_code: DottedId::new(rejection_code)
                        .expect("rejection code is a valid dotted id"),
                    message,
                    retryable,
                    current_authority_revision: self.authority_revision,
                    current_clock_epoch_id: self.clock_snapshot.clock_epoch_id.clone(),
                    current_clock_sequence: self.clock_snapshot.sequence,
                }),
            ),
        };

        let audit_event = ManifoldClockSnapshotAuthorityAuditEvent {
            schema_id: clock_snapshot_authority_audit_event_schema_id(),
            event_id: clock_snapshot_authority_audit_event_id(&request.request_id, outcome),
            authority_id: self.authority_id.clone(),
            prior_authority_revision: self.authority_revision,
            prior_clock_snapshot: self.clock_snapshot.clone(),
            event_kind: outcome.into(),
            request,
            accepted: accepted.clone(),
            rejection: rejection.clone(),
            lease,
            recorded_clock,
            evidence_refs,
        };

        let review = ManifoldClockSnapshotAuthorityReview {
            schema_id: clock_snapshot_authority_review_schema_id(),
            review_id: clock_snapshot_authority_review_id(&audit_event.request.request_id),
            authority_id: self.authority_id.clone(),
            authority_revision: self.authority_revision,
            clock_domain: audit_event.prior_clock_snapshot.clock_domain.clone(),
            clock_epoch_id: audit_event.prior_clock_snapshot.clock_epoch_id.clone(),
            clock_sequence: audit_event.prior_clock_snapshot.sequence,
            outcome,
            accepted,
            rejection,
            audit_event,
        };
        review.validate_against_snapshot(self)?;
        Ok(review)
    }

    /// Deterministically applies one clock snapshot authority review to this snapshot.
    ///
    /// Accepted clock reviews produce a new `ManifoldAuthoritySnapshot` with
    /// the authority revision advanced by one and the accepted clock snapshot
    /// installed. Rejected reviews produce a machine-readable application
    /// rejection and leave accepted state unchanged. This is source-only: it
    /// does not read a live clock, alter host time, start a clock service, or
    /// contact a platform adapter.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when this authority snapshot
    /// itself is invalid.
    pub fn apply_clock_snapshot_authority_review(
        &self,
        review: ManifoldClockSnapshotAuthorityReview,
    ) -> Result<ManifoldClockSnapshotAuthorityApplication, ManifoldAuthorityValidationError> {
        self.validate_authority_links()?;

        let application_id = clock_snapshot_authority_application_id(&review.review_id);
        let from_authority_revision = self.authority_revision;
        let from_clock_epoch_id = self.clock_snapshot.clock_epoch_id.clone();
        let from_clock_sequence = self.clock_snapshot.sequence;

        let (outcome, applied_snapshot, rejection) =
            match review.validate_against_snapshot(self) {
                Err(error) => (
                    ManifoldClockSnapshotAuthorityApplicationOutcome::ClockSnapshotApplicationRejected,
                    None,
                    Some(ManifoldAuthoritySnapshotApplicationRejection {
                        schema_id: authority_snapshot_application_rejection_schema_id(),
                        application_id: application_id.clone(),
                        rejection_code: DottedId::new(error.rejection_code())
                            .expect("authority rejection code is a valid dotted id"),
                        message: format!(
                            "clock snapshot review does not match authority snapshot: {error}"
                        ),
                        retryable: authority_application_validation_retryable(error.kind()),
                        current_authority_revision: self.authority_revision,
                    }),
                ),
                Ok(()) if review.outcome
                    == ManifoldClockSnapshotAuthorityReviewOutcome::ClockSnapshotRejected =>
                {
                    (
                        ManifoldClockSnapshotAuthorityApplicationOutcome::ClockSnapshotApplicationRejected,
                        None,
                        Some(ManifoldAuthoritySnapshotApplicationRejection {
                            schema_id: authority_snapshot_application_rejection_schema_id(),
                            application_id: application_id.clone(),
                            rejection_code: DottedId::new("review_rejected")
                                .expect("rejection code literal is valid"),
                            message: "clock snapshot review did not accept a clock snapshot"
                                .to_owned(),
                            retryable: review
                                .rejection
                                .as_ref()
                                .map(|rejection| rejection.retryable)
                                .unwrap_or(false),
                            current_authority_revision: self.authority_revision,
                        }),
                    )
                }
                Ok(()) => {
                    let Some(next_authority_revision) = self.authority_revision.next() else {
                        return Err(ManifoldAuthorityValidationError::new(
                            review.review_id.clone(),
                            self.authority_revision.get().to_string(),
                            ManifoldAuthorityValidationErrorKind::AcceptanceRevisionMismatch,
                        ));
                    };
                    let accepted_clock = review.accepted.clone().ok_or_else(|| {
                        ManifoldAuthorityValidationError::new(
                            review.review_id.clone(),
                            "accepted".to_owned(),
                            ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                        )
                    })?;
                    let mut next_snapshot = self.clone();
                    next_snapshot.authority_revision = next_authority_revision;
                    next_snapshot.clock_snapshot = accepted_clock;
                    next_snapshot.validate_authority_links()?;
                    (
                        ManifoldClockSnapshotAuthorityApplicationOutcome::ClockSnapshotApplied,
                        Some(next_snapshot),
                        None,
                    )
                }
            };

        let application = ManifoldClockSnapshotAuthorityApplication {
            schema_id: clock_snapshot_authority_application_schema_id(),
            application_id,
            authority_id: self.authority_id.clone(),
            from_authority_revision,
            from_clock_epoch_id,
            from_clock_sequence,
            outcome,
            applied_snapshot,
            rejection,
            review,
        };
        application.validate_against_snapshot(self)?;
        Ok(application)
    }

    fn clock_snapshot_authority_decision(
        &self,
        request: &ManifoldClockSnapshotChangeRequest,
        recorded_clock: &ManifoldClockSnapshot,
    ) -> ClockSnapshotAuthorityDecision {
        if request.schema_id != clock_snapshot_change_request_schema_id() {
            return ClockSnapshotAuthorityDecision::Rejected {
                rejection_code: "unsupported_schema".to_owned(),
                message: "clock snapshot request schema is not supported".to_owned(),
                retryable: false,
            };
        }

        if request.expected_authority_revision != self.authority_revision {
            return ClockSnapshotAuthorityDecision::Rejected {
                rejection_code: "stale_revision".to_owned(),
                message:
                    "clock snapshot request expected authority revision does not match current revision"
                        .to_owned(),
                retryable: true,
            };
        }

        if !self
            .host_manifest
            .capabilities
            .iter()
            .any(|capability| capability == &request.required_capability)
        {
            return ClockSnapshotAuthorityDecision::Rejected {
                rejection_code: "capability_not_advertised".to_owned(),
                message:
                    "clock snapshot request capability is not advertised by the authority host"
                        .to_owned(),
                retryable: false,
            };
        }

        let Some(lease_id) = &request.lease_id else {
            return ClockSnapshotAuthorityDecision::Rejected {
                rejection_code: "missing_lease".to_owned(),
                message: "clock snapshot change requires an active clock lease".to_owned(),
                retryable: true,
            };
        };

        let Some(lease) = self.active_lease(lease_id) else {
            return ClockSnapshotAuthorityDecision::Rejected {
                rejection_code: "unknown_lease".to_owned(),
                message: "clock snapshot request references an unknown lease".to_owned(),
                retryable: true,
            };
        };

        if lease.state != LeaseState::Active {
            return ClockSnapshotAuthorityDecision::Rejected {
                rejection_code: "inactive_lease".to_owned(),
                message: "clock snapshot lease is not active".to_owned(),
                retryable: true,
            };
        }

        if lease_expired_at(lease, recorded_clock) {
            return ClockSnapshotAuthorityDecision::Rejected {
                rejection_code: "expired_lease".to_owned(),
                message: "clock snapshot lease is expired at the review clock".to_owned(),
                retryable: true,
            };
        }

        if lease.granted_revision > self.authority_revision {
            return ClockSnapshotAuthorityDecision::Rejected {
                rejection_code: "lease_revision_ahead".to_owned(),
                message: "clock snapshot lease was granted after this authority revision"
                    .to_owned(),
                retryable: true,
            };
        }

        if lease.holder_id != request.holder_id
            || lease.scope != clock_snapshot_lease_scope()
            || lease.required_capability != request.required_capability
        {
            return ClockSnapshotAuthorityDecision::Rejected {
                rejection_code: "lease_mismatch".to_owned(),
                message: "clock snapshot request does not match the active lease".to_owned(),
                retryable: true,
            };
        }

        match self.validate_proposed_clock_snapshot(request) {
            Ok(()) => ClockSnapshotAuthorityDecision::Accepted(request.proposed_snapshot.clone()),
            Err(rejection) => ClockSnapshotAuthorityDecision::Rejected {
                rejection_code: rejection.rejection_code,
                message: rejection.message,
                retryable: rejection.retryable,
            },
        }
    }

    fn validate_proposed_clock_snapshot(
        &self,
        request: &ManifoldClockSnapshotChangeRequest,
    ) -> Result<(), ClockSnapshotRejection> {
        let proposed = &request.proposed_snapshot;
        if proposed.schema_id != clock_snapshot_schema_id() {
            return Err(ClockSnapshotRejection::new(
                "unsupported_schema",
                "clock snapshot schema is not supported",
                false,
            ));
        }

        if request.from_clock_epoch_id != self.clock_snapshot.clock_epoch_id
            || request.from_clock_sequence != self.clock_snapshot.sequence
        {
            return Err(ClockSnapshotRejection::new(
                "clock_precondition_mismatch",
                "clock snapshot request precondition does not match the accepted clock snapshot",
                true,
            ));
        }

        if proposed.clock_domain != self.clock_snapshot.clock_domain
            || proposed.clock_domain != self.host_manifest.clock_domain
        {
            return Err(ClockSnapshotRejection::new(
                "clock_domain_mismatch",
                "clock snapshot proposal clock domain does not match the authority clock domain",
                true,
            ));
        }

        if proposed.clock_epoch_id != self.clock_snapshot.clock_epoch_id {
            return Err(ClockSnapshotRejection::new(
                "clock_epoch_mismatch",
                "clock snapshot proposal changes the clock epoch without an epoch transition contract",
                true,
            ));
        }

        let Some(next_sequence) = self.clock_snapshot.sequence.checked_add(1) else {
            return Err(ClockSnapshotRejection::new(
                "clock_sequence_mismatch",
                "accepted clock sequence cannot advance",
                false,
            ));
        };
        if proposed.sequence != next_sequence {
            return Err(ClockSnapshotRejection::new(
                "clock_sequence_mismatch",
                "clock snapshot proposal must advance the clock sequence by one",
                true,
            ));
        }

        if proposed.monotonic_elapsed_ns <= self.clock_snapshot.monotonic_elapsed_ns {
            return Err(ClockSnapshotRejection::new(
                "monotonic_time_regression",
                "clock snapshot proposal must advance monotonic elapsed time",
                true,
            ));
        }

        if proposed.wall_clock_adjustment_count < self.clock_snapshot.wall_clock_adjustment_count {
            return Err(ClockSnapshotRejection::new(
                "wall_clock_adjustment_regression",
                "clock snapshot proposal cannot reduce the wall-clock adjustment count",
                true,
            ));
        }

        Ok(())
    }
}
