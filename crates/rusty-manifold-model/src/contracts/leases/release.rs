use super::*;

/// Request to release one accepted active control lease.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldControlLeaseReleaseRequest {
    /// Schema identifier for this request.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Request id.
    pub request_id: DottedId,
    /// Lease to release.
    pub lease_id: DottedId,
    /// Holder expected to own the lease.
    pub holder_id: DottedId,
    /// Expected authority revision.
    pub expected_authority_revision: Revision,
    /// Lease scope expected by the requester.
    pub scope: DottedId,
    /// Machine-readable reason for releasing the lease.
    pub release_reason: DottedId,
    /// Request timestamp in milliseconds in the holder's chosen clock domain.
    pub requested_at_ms: u64,
}

/// Rejected control lease release request result.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldControlLeaseReleaseRejection {
    /// Schema identifier for this release rejection.
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
    /// Current authority revision.
    pub current_revision: Revision,
    /// Active lease count observed before the release decision.
    pub active_lease_count: usize,
}

/// Control lease release authority audit event kind.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldControlLeaseReleaseAuthorityAuditEventKind {
    /// Authority accepted a lease release request.
    LeaseReleased,
    /// Authority rejected a lease release request.
    LeaseReleaseRejected,
}

/// Control lease release authority review outcome.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldControlLeaseReleaseAuthorityReviewOutcome {
    /// Authority accepted the lease release request.
    LeaseReleased,
    /// Authority rejected the lease release request.
    LeaseReleaseRejected,
}

/// Control lease release authority application outcome.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldControlLeaseReleaseAuthorityApplicationOutcome {
    /// Accepted lease release review was applied to the authority snapshot.
    LeaseReleaseApplied,
    /// Lease release review could not be applied to accepted authority state.
    LeaseReleaseApplicationRejected,
}

impl From<ManifoldControlLeaseReleaseAuthorityReviewOutcome>
    for ManifoldControlLeaseReleaseAuthorityAuditEventKind
{
    fn from(outcome: ManifoldControlLeaseReleaseAuthorityReviewOutcome) -> Self {
        match outcome {
            ManifoldControlLeaseReleaseAuthorityReviewOutcome::LeaseReleased => Self::LeaseReleased,
            ManifoldControlLeaseReleaseAuthorityReviewOutcome::LeaseReleaseRejected => {
                Self::LeaseReleaseRejected
            }
        }
    }
}

/// Audit event for one control lease release authority decision.
///
/// The event carries the lease release request plus exactly one released lease
/// or rejected result. It records enough local authority context for
/// deterministic validation without owning timers or runtime mutation.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldControlLeaseReleaseAuthorityAuditEvent {
    /// Schema identifier for this audit event.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable event id.
    pub event_id: DottedId,
    /// Authority that made the decision.
    pub authority_id: DottedId,
    /// Authority revision observed before the decision.
    pub prior_authority_revision: Revision,
    /// Active lease count observed before the decision.
    pub active_lease_count: usize,
    /// Event kind.
    pub event_kind: ManifoldControlLeaseReleaseAuthorityAuditEventKind,
    /// Lease release request reviewed by authority.
    pub request: ManifoldControlLeaseReleaseRequest,
    /// Released lease. Present only for released events.
    pub released: Option<ManifoldControlLease>,
    /// Rejected lease release result. Present only for rejected events.
    pub rejection: Option<ManifoldControlLeaseReleaseRejection>,
    /// Clock snapshot recorded with the decision.
    pub recorded_clock: ManifoldClockSnapshot,
    /// Stable ids for fixtures, scorecards, or logs backing the event.
    pub evidence_refs: Vec<DottedId>,
}

/// Deterministic review result for one control lease release authority decision.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldControlLeaseReleaseAuthorityReview {
    /// Schema identifier for this review.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable review id.
    pub review_id: DottedId,
    /// Authority that reviewed the lease release request.
    pub authority_id: DottedId,
    /// Authority revision used by this review.
    pub authority_revision: Revision,
    /// Review outcome.
    pub outcome: ManifoldControlLeaseReleaseAuthorityReviewOutcome,
    /// Released lease. Present only for accepted release reviews.
    pub released: Option<ManifoldControlLease>,
    /// Rejected lease release result. Present only for rejected release reviews.
    pub rejection: Option<ManifoldControlLeaseReleaseRejection>,
    /// Audit event for the same lease release decision.
    pub audit_event: ManifoldControlLeaseReleaseAuthorityAuditEvent,
}

impl ManifoldControlLeaseReleaseAuthorityReview {
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
        if self.schema_id.as_str() != "rusty.manifold.authority.lease_release_review.v1" {
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
            ManifoldControlLeaseReleaseAuthorityReviewOutcome::LeaseReleased => {
                if self.released.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.review_id.clone(),
                        "released".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
            ManifoldControlLeaseReleaseAuthorityReviewOutcome::LeaseReleaseRejected => {
                if self.released.is_some() || self.rejection.is_none() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.review_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
        }

        if self.released != self.audit_event.released
            || self.rejection != self.audit_event.rejection
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.audit_event.event_id.to_string(),
                ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
            ));
        }

        if ManifoldControlLeaseReleaseAuthorityAuditEventKind::from(self.outcome)
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

impl ManifoldControlLeaseReleaseAuthorityAuditEvent {
    /// Validates this event against the authority snapshot it claims to use.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the event is not a
    /// consistent lease release or rejection for the supplied snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str() != "rusty.manifold.authority.lease_release_audit_event.v1" {
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

        if self.active_lease_count != snapshot.active_leases.len() {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.active_lease_count.to_string(),
                ManifoldAuthorityValidationErrorKind::LeaseMismatch,
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
            ManifoldControlLeaseReleaseAuthorityAuditEventKind::LeaseReleased => {
                if self.released.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        "released".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
            ManifoldControlLeaseReleaseAuthorityAuditEventKind::LeaseReleaseRejected => {
                if self.released.is_some() || self.rejection.is_none() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
        }

        let expected_decision =
            snapshot.lease_release_authority_decision(&self.request, &self.recorded_clock);

        if let Some(released) = &self.released {
            let LeaseReleaseAuthorityDecision::Released(expected_lease) = &expected_decision else {
                let rejected_value = match &expected_decision {
                    LeaseReleaseAuthorityDecision::Rejected { rejection_code, .. } => {
                        rejection_code.clone()
                    }
                    LeaseReleaseAuthorityDecision::Released(_) => "released".to_owned(),
                };
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejected_value.clone(),
                    authority_error_kind_for_lease_release_rejection_code(&rejected_value),
                ));
            };

            if released != expected_lease {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    released.lease_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::LeaseMismatch,
                ));
            }
        }

        if let Some(rejection) = &self.rejection {
            let LeaseReleaseAuthorityDecision::Rejected {
                rejection_code,
                message,
                retryable,
                active_lease_count,
            } = &expected_decision
            else {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    self.request.lease_id.to_string(),
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

            if rejection.current_revision != self.prior_authority_revision {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejection.current_revision.get().to_string(),
                    ManifoldAuthorityValidationErrorKind::RejectionRevisionMismatch,
                ));
            }

            if rejection.active_lease_count != *active_lease_count
                || rejection.rejection_code.as_str() != rejection_code
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

/// Deterministic application result for one control lease release authority review.
///
/// This records the bridge from review-time lease release authority to
/// accepted authority state without owning command execution, lease renewal
/// timers, or host/runtime mutation.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldControlLeaseReleaseAuthorityApplication {
    /// Schema identifier for this application receipt.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable application id.
    pub application_id: DottedId,
    /// Authority that attempted the application.
    pub authority_id: DottedId,
    /// Authority revision before applying the review.
    pub from_authority_revision: Revision,
    /// Lease released by the reviewed request.
    pub lease_id: DottedId,
    /// Lease scope released.
    pub lease_scope: DottedId,
    /// Number of active leases before applying the review.
    pub from_active_lease_count: usize,
    /// Application outcome.
    pub outcome: ManifoldControlLeaseReleaseAuthorityApplicationOutcome,
    /// Next accepted authority snapshot. Present only for applied outcomes.
    pub applied_snapshot: Option<ManifoldAuthoritySnapshot>,
    /// Rejection. Present only for rejected application outcomes.
    pub rejection: Option<ManifoldAuthoritySnapshotApplicationRejection>,
    /// Review that was applied or rejected for application.
    pub review: ManifoldControlLeaseReleaseAuthorityReview,
}

impl ManifoldControlLeaseReleaseAuthorityApplication {
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
        if self.schema_id.as_str() != "rusty.manifold.authority.lease_release_application.v1" {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.schema_id.to_string(),
                ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
            ));
        }

        validate_derived_authority_id(
            &self.application_id,
            &self.application_id,
            control_lease_release_authority_application_id(&self.review.review_id),
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

        if self.lease_id != self.review.audit_event.request.lease_id
            || self.lease_scope != self.review.audit_event.request.scope
            || self.from_active_lease_count != snapshot.active_leases.len()
            || self.from_active_lease_count != self.review.audit_event.active_lease_count
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.lease_id.to_string(),
                ManifoldAuthorityValidationErrorKind::LeaseMismatch,
            ));
        }

        self.review.validate_against_snapshot(snapshot)?;

        match self.outcome {
            ManifoldControlLeaseReleaseAuthorityApplicationOutcome::LeaseReleaseApplied => {
                if self.applied_snapshot.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        "applied_snapshot".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                if self.review.outcome
                    != ManifoldControlLeaseReleaseAuthorityReviewOutcome::LeaseReleased
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
                    || applied.clock_snapshot != snapshot.clock_snapshot
                    || applied.stream_registry != snapshot.stream_registry
                    || applied.module_runtime_states != snapshot.module_runtime_states
                    || applied.command_ids != snapshot.command_ids
                    || applied.command_descriptors != snapshot.command_descriptors
                    || applied.active_stream_subscriptions != snapshot.active_stream_subscriptions
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        applied.authority_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::LeaseMismatch,
                    ));
                }

                let released_lease = self.review.released.clone().ok_or_else(|| {
                    ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        "released".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    )
                })?;
                let mut expected_leases = snapshot.active_leases.clone();
                let Some(position) = expected_leases
                    .iter()
                    .position(|lease| lease.lease_id == released_lease.lease_id)
                else {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        released_lease.lease_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::UnknownLease,
                    ));
                };
                let removed = expected_leases.remove(position);
                if removed != released_lease || applied.active_leases != expected_leases {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        self.lease_scope.to_string(),
                        ManifoldAuthorityValidationErrorKind::LeaseMismatch,
                    ));
                }

                applied.validate_authority_links()
            }
            ManifoldControlLeaseReleaseAuthorityApplicationOutcome::LeaseReleaseApplicationRejected => {
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
                    == ManifoldControlLeaseReleaseAuthorityReviewOutcome::LeaseReleaseRejected
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

#[derive(Clone, Debug, Eq, PartialEq)]
enum LeaseReleaseAuthorityDecision {
    Released(ManifoldControlLease),
    Rejected {
        rejection_code: String,
        message: String,
        retryable: bool,
        active_lease_count: usize,
    },
}

impl ManifoldAuthoritySnapshot {
    /// Deterministically reviews one active control lease release request.
    ///
    /// The review is source-only: it verifies release preconditions against
    /// accepted authority state and records the lease to remove, but it does
    /// not cancel timers, execute commands, contact hosts, or notify runtimes.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the authority snapshot
    /// itself is invalid, the review clock is inconsistent, or evidence refs are empty.
    pub fn review_control_lease_release(
        &self,
        request: ManifoldControlLeaseReleaseRequest,
        recorded_clock: ManifoldClockSnapshot,
        evidence_refs: Vec<DottedId>,
    ) -> Result<ManifoldControlLeaseReleaseAuthorityReview, ManifoldAuthorityValidationError> {
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

        let decision = self.lease_release_authority_decision(&request, &recorded_clock);
        let active_lease_count = self.active_leases.len();
        let (outcome, released, rejection) = match decision {
            LeaseReleaseAuthorityDecision::Released(lease) => (
                ManifoldControlLeaseReleaseAuthorityReviewOutcome::LeaseReleased,
                Some(lease),
                None,
            ),
            LeaseReleaseAuthorityDecision::Rejected {
                rejection_code,
                message,
                retryable,
                active_lease_count,
            } => (
                ManifoldControlLeaseReleaseAuthorityReviewOutcome::LeaseReleaseRejected,
                None,
                Some(ManifoldControlLeaseReleaseRejection {
                    schema_id: control_lease_release_rejection_schema_id(),
                    request_id: request.request_id.clone(),
                    rejection_code: DottedId::new(rejection_code)
                        .expect("rejection code is a valid dotted id"),
                    message,
                    retryable,
                    current_revision: self.authority_revision,
                    active_lease_count,
                }),
            ),
        };

        let audit_event = ManifoldControlLeaseReleaseAuthorityAuditEvent {
            schema_id: control_lease_release_authority_audit_event_schema_id(),
            event_id: control_lease_release_authority_audit_event_id(&request.request_id, outcome),
            authority_id: self.authority_id.clone(),
            prior_authority_revision: self.authority_revision,
            active_lease_count,
            event_kind: outcome.into(),
            request,
            released: released.clone(),
            rejection: rejection.clone(),
            recorded_clock,
            evidence_refs,
        };

        let review = ManifoldControlLeaseReleaseAuthorityReview {
            schema_id: control_lease_release_authority_review_schema_id(),
            review_id: control_lease_release_authority_review_id(&audit_event.request.request_id),
            authority_id: self.authority_id.clone(),
            authority_revision: self.authority_revision,
            outcome,
            released,
            rejection,
            audit_event,
        };
        review.validate_against_snapshot(self)?;
        Ok(review)
    }

    /// Deterministically applies one control lease release authority review.
    ///
    /// Accepted release reviews produce a new `ManifoldAuthoritySnapshot` with
    /// the authority revision advanced by one and the released lease removed
    /// from the active set. Rejected reviews produce a machine-readable
    /// application rejection and leave accepted state unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when this authority snapshot
    /// itself is invalid.
    pub fn apply_control_lease_release_authority_review(
        &self,
        review: ManifoldControlLeaseReleaseAuthorityReview,
    ) -> Result<ManifoldControlLeaseReleaseAuthorityApplication, ManifoldAuthorityValidationError>
    {
        self.validate_authority_links()?;

        let application_id = control_lease_release_authority_application_id(&review.review_id);
        let from_authority_revision = self.authority_revision;
        let lease_id = review.audit_event.request.lease_id.clone();
        let lease_scope = review.audit_event.request.scope.clone();
        let from_active_lease_count = self.active_leases.len();

        let (outcome, applied_snapshot, rejection) = match review.validate_against_snapshot(self) {
            Err(error) => (
                ManifoldControlLeaseReleaseAuthorityApplicationOutcome::LeaseReleaseApplicationRejected,
                None,
                Some(ManifoldAuthoritySnapshotApplicationRejection {
                    schema_id: authority_snapshot_application_rejection_schema_id(),
                    application_id: application_id.clone(),
                    rejection_code: DottedId::new(error.rejection_code())
                        .expect("authority rejection code is a valid dotted id"),
                    message: format!(
                        "control lease release review does not match authority snapshot: {error}"
                    ),
                    retryable: authority_application_validation_retryable(error.kind()),
                    current_authority_revision: self.authority_revision,
                }),
            ),
            Ok(())
                if review.outcome
                    == ManifoldControlLeaseReleaseAuthorityReviewOutcome::LeaseReleaseRejected =>
            {
                (
                    ManifoldControlLeaseReleaseAuthorityApplicationOutcome::LeaseReleaseApplicationRejected,
                    None,
                    Some(ManifoldAuthoritySnapshotApplicationRejection {
                        schema_id: authority_snapshot_application_rejection_schema_id(),
                        application_id: application_id.clone(),
                        rejection_code: DottedId::new("review_rejected")
                            .expect("rejection code literal is valid"),
                        message: "control lease release review did not release a lease".to_owned(),
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
                let released_lease = review.released.clone().ok_or_else(|| {
                    ManifoldAuthorityValidationError::new(
                        review.review_id.clone(),
                        "released".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    )
                })?;
                let mut next_snapshot = self.clone();
                next_snapshot.authority_revision = next_authority_revision;
                let Some(position) = next_snapshot
                    .active_leases
                    .iter()
                    .position(|lease| lease.lease_id == released_lease.lease_id)
                else {
                    return Err(ManifoldAuthorityValidationError::new(
                        review.review_id.clone(),
                        released_lease.lease_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::UnknownLease,
                    ));
                };
                next_snapshot.active_leases.remove(position);
                next_snapshot.validate_authority_links()?;
                (
                    ManifoldControlLeaseReleaseAuthorityApplicationOutcome::LeaseReleaseApplied,
                    Some(next_snapshot),
                    None,
                )
            }
        };

        let application = ManifoldControlLeaseReleaseAuthorityApplication {
            schema_id: control_lease_release_authority_application_schema_id(),
            application_id,
            authority_id: self.authority_id.clone(),
            from_authority_revision,
            lease_id,
            lease_scope,
            from_active_lease_count,
            outcome,
            applied_snapshot,
            rejection,
            review,
        };
        application.validate_against_snapshot(self)?;
        Ok(application)
    }

    fn lease_release_authority_decision(
        &self,
        request: &ManifoldControlLeaseReleaseRequest,
        recorded_clock: &ManifoldClockSnapshot,
    ) -> LeaseReleaseAuthorityDecision {
        if request.schema_id != control_lease_release_request_schema_id() {
            return LeaseReleaseAuthorityDecision::Rejected {
                rejection_code: "unsupported_schema".to_owned(),
                message: "control lease release request schema is not supported".to_owned(),
                retryable: false,
                active_lease_count: self.active_leases.len(),
            };
        }

        if request.expected_authority_revision != self.authority_revision {
            return LeaseReleaseAuthorityDecision::Rejected {
                rejection_code: "stale_revision".to_owned(),
                message:
                    "control lease release request expected authority revision does not match current revision"
                        .to_owned(),
                retryable: true,
                active_lease_count: self.active_leases.len(),
            };
        }

        let Some(lease) = self.active_lease(&request.lease_id) else {
            return LeaseReleaseAuthorityDecision::Rejected {
                rejection_code: "unknown_lease".to_owned(),
                message: "control lease release request references an unknown active lease"
                    .to_owned(),
                retryable: true,
                active_lease_count: self.active_leases.len(),
            };
        };

        if lease.state != LeaseState::Active {
            return LeaseReleaseAuthorityDecision::Rejected {
                rejection_code: "inactive_lease".to_owned(),
                message: "control lease release request references a non-active lease".to_owned(),
                retryable: true,
                active_lease_count: self.active_leases.len(),
            };
        }

        if lease_expired_at(lease, recorded_clock) {
            return LeaseReleaseAuthorityDecision::Rejected {
                rejection_code: "expired_lease".to_owned(),
                message: "control lease release request references an expired lease".to_owned(),
                retryable: true,
                active_lease_count: self.active_leases.len(),
            };
        }

        if lease.holder_id != request.holder_id {
            return LeaseReleaseAuthorityDecision::Rejected {
                rejection_code: "lease_holder_mismatch".to_owned(),
                message: "control lease release request holder does not own the lease".to_owned(),
                retryable: false,
                active_lease_count: self.active_leases.len(),
            };
        }

        if lease.scope != request.scope {
            return LeaseReleaseAuthorityDecision::Rejected {
                rejection_code: "lease_scope_mismatch".to_owned(),
                message: "control lease release request scope does not match the active lease"
                    .to_owned(),
                retryable: true,
                active_lease_count: self.active_leases.len(),
            };
        }

        LeaseReleaseAuthorityDecision::Released(lease.clone())
    }
}
