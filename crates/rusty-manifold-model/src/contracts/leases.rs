use super::*;

mod release;
mod renewal;

pub use self::release::*;
pub use self::renewal::*;

/// Lease request descriptor used by tests and fixtures.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldControlLeaseRequest {
    /// Schema identifier for this request.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Request id.
    pub request_id: DottedId,
    /// Holder id.
    pub holder_id: DottedId,
    /// Requested lease scope.
    pub scope: DottedId,
    /// Expected authority revision.
    pub expected_revision: Revision,
    /// Requested time-to-live in milliseconds.
    pub requested_ttl_ms: u64,
    /// Capability required for the lease.
    pub required_capability: DottedId,
    /// Safety class for the lease request.
    pub safety_class: SafetyClass,
}

/// Accepted control lease.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldControlLease {
    /// Schema identifier for this lease.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Lease id.
    pub lease_id: DottedId,
    /// Holder id.
    pub holder_id: DottedId,
    /// Lease scope.
    pub scope: DottedId,
    /// Lease state.
    pub state: LeaseState,
    /// Authority revision at which the lease was granted.
    pub granted_revision: Revision,
    /// Expiration timestamp in milliseconds.
    pub expires_at_ms: u64,
    /// Capability used to grant the lease.
    pub required_capability: DottedId,
}

/// Rejected control lease request result.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldControlLeaseRejection {
    /// Schema identifier for this lease rejection.
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
    /// Conflicting lease id, when a held lease blocks the request.
    pub conflicting_lease_id: Option<DottedId>,
}

/// Control lease authority audit event kind.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldControlLeaseAuthorityAuditEventKind {
    /// Authority accepted a lease request.
    LeaseAccepted,
    /// Authority rejected a lease request.
    LeaseRejected,
}

/// Control lease authority review outcome.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldControlLeaseAuthorityReviewOutcome {
    /// Authority accepted the lease request.
    LeaseAccepted,
    /// Authority rejected the lease request.
    LeaseRejected,
}

/// Control lease authority application outcome.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldControlLeaseAuthorityApplicationOutcome {
    /// Accepted lease review was applied to the authority snapshot.
    LeaseApplied,
    /// Lease review could not be applied to accepted authority state.
    LeaseApplicationRejected,
}

impl From<ManifoldControlLeaseAuthorityReviewOutcome>
    for ManifoldControlLeaseAuthorityAuditEventKind
{
    fn from(outcome: ManifoldControlLeaseAuthorityReviewOutcome) -> Self {
        match outcome {
            ManifoldControlLeaseAuthorityReviewOutcome::LeaseAccepted => Self::LeaseAccepted,
            ManifoldControlLeaseAuthorityReviewOutcome::LeaseRejected => Self::LeaseRejected,
        }
    }
}

/// Audit event for one control lease authority decision.
///
/// The event carries the lease request plus exactly one accepted or rejected
/// result. It records enough local authority context for deterministic
/// validation without owning runtime mutation.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldControlLeaseAuthorityAuditEvent {
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
    pub event_kind: ManifoldControlLeaseAuthorityAuditEventKind,
    /// Lease request reviewed by authority.
    pub request: ManifoldControlLeaseRequest,
    /// Accepted lease. Present only for accepted events.
    pub accepted: Option<ManifoldControlLease>,
    /// Rejected lease result. Present only for rejected events.
    pub rejection: Option<ManifoldControlLeaseRejection>,
    /// Clock snapshot recorded with the decision.
    pub recorded_clock: ManifoldClockSnapshot,
    /// Stable ids for fixtures, scorecards, or logs backing the event.
    pub evidence_refs: Vec<DottedId>,
}

/// Deterministic review result for one control lease authority decision.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldControlLeaseAuthorityReview {
    /// Schema identifier for this review.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable review id.
    pub review_id: DottedId,
    /// Authority that reviewed the lease request.
    pub authority_id: DottedId,
    /// Authority revision used by this review.
    pub authority_revision: Revision,
    /// Review outcome.
    pub outcome: ManifoldControlLeaseAuthorityReviewOutcome,
    /// Accepted lease. Present only for accepted reviews.
    pub accepted: Option<ManifoldControlLease>,
    /// Rejected lease result. Present only for rejected reviews.
    pub rejection: Option<ManifoldControlLeaseRejection>,
    /// Audit event for the same lease decision.
    pub audit_event: ManifoldControlLeaseAuthorityAuditEvent,
}

impl ManifoldControlLeaseAuthorityReview {
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
        if self.schema_id.as_str() != "rusty.manifold.authority.lease_review.v1" {
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
            ManifoldControlLeaseAuthorityReviewOutcome::LeaseAccepted => {
                if self.accepted.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.review_id.clone(),
                        "accepted".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
            ManifoldControlLeaseAuthorityReviewOutcome::LeaseRejected => {
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

        if ManifoldControlLeaseAuthorityAuditEventKind::from(self.outcome)
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

/// Deterministic application result for one control-lease authority review.
///
/// This records the bridge from review-time lease authority to accepted
/// authority state without owning command execution, lease renewal timers, or
/// host/runtime mutation.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldControlLeaseAuthorityApplication {
    /// Schema identifier for this application receipt.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable application id.
    pub application_id: DottedId,
    /// Authority that attempted the application.
    pub authority_id: DottedId,
    /// Authority revision before applying the review.
    pub from_authority_revision: Revision,
    /// Lease request reviewed by authority.
    pub request_id: DottedId,
    /// Lease scope requested.
    pub lease_scope: DottedId,
    /// Number of active leases before applying the review.
    pub from_active_lease_count: usize,
    /// Application outcome.
    pub outcome: ManifoldControlLeaseAuthorityApplicationOutcome,
    /// Next accepted authority snapshot. Present only for applied outcomes.
    pub applied_snapshot: Option<ManifoldAuthoritySnapshot>,
    /// Rejection. Present only for rejected application outcomes.
    pub rejection: Option<ManifoldAuthoritySnapshotApplicationRejection>,
    /// Review that was applied or rejected for application.
    pub review: ManifoldControlLeaseAuthorityReview,
}

impl ManifoldControlLeaseAuthorityApplication {
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
        if self.schema_id.as_str() != "rusty.manifold.authority.lease_application.v1" {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.schema_id.to_string(),
                ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
            ));
        }

        validate_derived_authority_id(
            &self.application_id,
            &self.application_id,
            control_lease_authority_application_id(&self.review.review_id),
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

        if self.request_id != self.review.audit_event.request.request_id
            || self.lease_scope != self.review.audit_event.request.scope
            || self.from_active_lease_count != snapshot.active_leases.len()
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.lease_scope.to_string(),
                ManifoldAuthorityValidationErrorKind::LeaseMismatch,
            ));
        }

        self.review.validate_against_snapshot(snapshot)?;

        match self.outcome {
            ManifoldControlLeaseAuthorityApplicationOutcome::LeaseApplied => {
                if self.applied_snapshot.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        "applied_snapshot".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                if self.review.outcome != ManifoldControlLeaseAuthorityReviewOutcome::LeaseAccepted
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

                let accepted_lease = self.review.accepted.clone().ok_or_else(|| {
                    ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        "accepted".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    )
                })?;
                let mut expected_leases = snapshot.active_leases.clone();
                expected_leases.push(accepted_lease);
                if applied.active_leases != expected_leases {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        self.lease_scope.to_string(),
                        ManifoldAuthorityValidationErrorKind::LeaseMismatch,
                    ));
                }

                applied.validate_authority_links()
            }
            ManifoldControlLeaseAuthorityApplicationOutcome::LeaseApplicationRejected => {
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

                if self.review.outcome == ManifoldControlLeaseAuthorityReviewOutcome::LeaseRejected
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

impl ManifoldControlLeaseAuthorityAuditEvent {
    /// Validates this event against the authority snapshot it claims to use.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the event is not a
    /// consistent lease acceptance or rejection for the supplied snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str() != "rusty.manifold.authority.lease_audit_event.v1" {
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
            ManifoldControlLeaseAuthorityAuditEventKind::LeaseAccepted => {
                if self.accepted.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        "accepted".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
            ManifoldControlLeaseAuthorityAuditEventKind::LeaseRejected => {
                if self.accepted.is_some() || self.rejection.is_none() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
        }

        let expected_decision = snapshot.lease_authority_decision(&self.request);

        if let Some(accepted) = &self.accepted {
            if let LeaseAuthorityDecision::Rejected { rejection_code, .. } = &expected_decision {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    (*rejection_code).to_owned(),
                    authority_error_kind_for_lease_rejection_code(rejection_code),
                ));
            }

            if accepted.holder_id != self.request.holder_id
                || accepted.scope != self.request.scope
                || accepted.required_capability != self.request.required_capability
                || accepted.state != LeaseState::Active
                || accepted.granted_revision != self.prior_authority_revision
            {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    accepted.lease_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::LeaseMismatch,
                ));
            }

            let expected_expires_at_ms = wall_unix_ms_u64(&self.recorded_clock)
                .saturating_add(self.request.requested_ttl_ms);
            if accepted.expires_at_ms != expected_expires_at_ms {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    accepted.expires_at_ms.to_string(),
                    ManifoldAuthorityValidationErrorKind::LeaseMismatch,
                ));
            }
        }

        if let Some(rejection) = &self.rejection {
            let LeaseAuthorityDecision::Rejected {
                rejection_code,
                message,
                retryable,
                conflicting_lease_id,
            } = &expected_decision
            else {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    self.request.scope.to_string(),
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

            if rejection.rejection_code.as_str() != *rejection_code
                || rejection.message != *message
                || rejection.retryable != *retryable
                || rejection.conflicting_lease_id != *conflicting_lease_id
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

#[derive(Clone, Debug, Eq, PartialEq)]
enum LeaseAuthorityDecision {
    Accepted,
    Rejected {
        rejection_code: &'static str,
        message: String,
        retryable: bool,
        conflicting_lease_id: Option<DottedId>,
    },
}

impl ManifoldAuthoritySnapshot {
    /// Deterministically reviews one control lease request against this authority snapshot.
    ///
    /// The review is source-only: it does not mutate the accepted lease set,
    /// renew leases, execute commands, or contact a host.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the authority snapshot
    /// itself is invalid, the review clock is inconsistent, or evidence refs are empty.
    pub fn review_lease_request(
        &self,
        request: ManifoldControlLeaseRequest,
        recorded_clock: ManifoldClockSnapshot,
        evidence_refs: Vec<DottedId>,
    ) -> Result<ManifoldControlLeaseAuthorityReview, ManifoldAuthorityValidationError> {
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

        let decision = self.lease_authority_decision(&request);
        let (outcome, accepted, rejection) = match decision {
            LeaseAuthorityDecision::Accepted => (
                ManifoldControlLeaseAuthorityReviewOutcome::LeaseAccepted,
                Some(ManifoldControlLease {
                    schema_id: control_lease_schema_id(),
                    lease_id: control_lease_id(&request.request_id),
                    holder_id: request.holder_id.clone(),
                    scope: request.scope.clone(),
                    state: LeaseState::Active,
                    granted_revision: self.authority_revision,
                    expires_at_ms: wall_unix_ms_u64(&recorded_clock)
                        .saturating_add(request.requested_ttl_ms),
                    required_capability: request.required_capability.clone(),
                }),
                None,
            ),
            LeaseAuthorityDecision::Rejected {
                rejection_code,
                message,
                retryable,
                conflicting_lease_id,
            } => (
                ManifoldControlLeaseAuthorityReviewOutcome::LeaseRejected,
                None,
                Some(ManifoldControlLeaseRejection {
                    schema_id: control_lease_rejection_schema_id(),
                    request_id: request.request_id.clone(),
                    rejection_code: DottedId::new(rejection_code)
                        .expect("rejection code literal is a valid dotted id"),
                    message,
                    retryable,
                    current_revision: self.authority_revision,
                    conflicting_lease_id,
                }),
            ),
        };

        let audit_event = ManifoldControlLeaseAuthorityAuditEvent {
            schema_id: control_lease_authority_audit_event_schema_id(),
            event_id: control_lease_authority_audit_event_id(&request.request_id, outcome),
            authority_id: self.authority_id.clone(),
            prior_authority_revision: self.authority_revision,
            event_kind: outcome.into(),
            request,
            accepted: accepted.clone(),
            rejection: rejection.clone(),
            recorded_clock,
            evidence_refs,
        };

        let review = ManifoldControlLeaseAuthorityReview {
            schema_id: control_lease_authority_review_schema_id(),
            review_id: control_lease_authority_review_id(&audit_event.request.request_id),
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

    /// Deterministically applies one control-lease authority review to this snapshot.
    ///
    /// Accepted lease reviews produce a new `ManifoldAuthoritySnapshot` with
    /// the authority revision advanced by one and the accepted active lease
    /// appended. Rejected reviews produce a machine-readable application
    /// rejection and leave accepted state unchanged. This is source-only: it
    /// does not renew leases, execute commands, mutate runtime state, open
    /// transports, or contact a host.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when this authority snapshot
    /// itself is invalid.
    pub fn apply_control_lease_authority_review(
        &self,
        review: ManifoldControlLeaseAuthorityReview,
    ) -> Result<ManifoldControlLeaseAuthorityApplication, ManifoldAuthorityValidationError> {
        self.validate_authority_links()?;

        let application_id = control_lease_authority_application_id(&review.review_id);
        let from_authority_revision = self.authority_revision;
        let request_id = review.audit_event.request.request_id.clone();
        let lease_scope = review.audit_event.request.scope.clone();
        let from_active_lease_count = self.active_leases.len();

        let (outcome, applied_snapshot, rejection) = match review.validate_against_snapshot(self) {
            Err(error) => (
                ManifoldControlLeaseAuthorityApplicationOutcome::LeaseApplicationRejected,
                None,
                Some(ManifoldAuthoritySnapshotApplicationRejection {
                    schema_id: authority_snapshot_application_rejection_schema_id(),
                    application_id: application_id.clone(),
                    rejection_code: DottedId::new(error.rejection_code())
                        .expect("authority rejection code is a valid dotted id"),
                    message: format!(
                        "control lease review does not match authority snapshot: {error}"
                    ),
                    retryable: authority_application_validation_retryable(error.kind()),
                    current_authority_revision: self.authority_revision,
                }),
            ),
            Ok(())
                if review.outcome == ManifoldControlLeaseAuthorityReviewOutcome::LeaseRejected =>
            {
                (
                    ManifoldControlLeaseAuthorityApplicationOutcome::LeaseApplicationRejected,
                    None,
                    Some(ManifoldAuthoritySnapshotApplicationRejection {
                        schema_id: authority_snapshot_application_rejection_schema_id(),
                        application_id: application_id.clone(),
                        rejection_code: DottedId::new("review_rejected")
                            .expect("rejection code literal is valid"),
                        message: "control lease review did not accept a lease".to_owned(),
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
                let accepted_lease = review.accepted.clone().ok_or_else(|| {
                    ManifoldAuthorityValidationError::new(
                        review.review_id.clone(),
                        "accepted".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    )
                })?;
                let mut next_snapshot = self.clone();
                next_snapshot.authority_revision = next_authority_revision;
                next_snapshot.active_leases.push(accepted_lease);
                next_snapshot.validate_authority_links()?;
                (
                    ManifoldControlLeaseAuthorityApplicationOutcome::LeaseApplied,
                    Some(next_snapshot),
                    None,
                )
            }
        };

        let application = ManifoldControlLeaseAuthorityApplication {
            schema_id: control_lease_authority_application_schema_id(),
            application_id,
            authority_id: self.authority_id.clone(),
            from_authority_revision,
            request_id,
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

    fn lease_authority_decision(
        &self,
        request: &ManifoldControlLeaseRequest,
    ) -> LeaseAuthorityDecision {
        if request.expected_revision != self.authority_revision {
            return LeaseAuthorityDecision::Rejected {
                rejection_code: "stale_revision",
                message: "lease request expected revision does not match current revision"
                    .to_owned(),
                retryable: true,
                conflicting_lease_id: None,
            };
        }

        if request.requested_ttl_ms == 0 {
            return LeaseAuthorityDecision::Rejected {
                rejection_code: "invalid_ttl",
                message: "lease request ttl must be greater than zero".to_owned(),
                retryable: false,
                conflicting_lease_id: None,
            };
        }

        if !self
            .host_manifest
            .capabilities
            .iter()
            .any(|capability| capability == &request.required_capability)
        {
            return LeaseAuthorityDecision::Rejected {
                rejection_code: "capability_not_advertised",
                message: "lease request capability is not advertised by the authority host"
                    .to_owned(),
                retryable: false,
                conflicting_lease_id: None,
            };
        }

        if let Some(conflicting_lease) = self
            .active_leases
            .iter()
            .find(|lease| lease.scope == request.scope && lease.state == LeaseState::Active)
        {
            return LeaseAuthorityDecision::Rejected {
                rejection_code: "lease_scope_busy",
                message: "lease request scope is already held by an active lease".to_owned(),
                retryable: true,
                conflicting_lease_id: Some(conflicting_lease.lease_id.clone()),
            };
        }

        LeaseAuthorityDecision::Accepted
    }
}
