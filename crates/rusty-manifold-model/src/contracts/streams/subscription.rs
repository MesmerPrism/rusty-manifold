use super::*;

/// Audit event for one stream subscription authority decision.
///
/// The event carries the subscription request plus exactly one accepted
/// subscription or rejected result. It records enough authority context for
/// deterministic validation without opening transports or notifying subscribers.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamSubscriptionAuthorityAuditEvent {
    /// Schema identifier for this audit event.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable event id.
    pub event_id: DottedId,
    /// Authority that made the decision.
    pub authority_id: DottedId,
    /// Authority revision observed before the decision.
    pub prior_authority_revision: Revision,
    /// Stream-registry revision observed before the decision.
    pub prior_registry_revision: Revision,
    /// Active subscriber count observed for the requested stream.
    pub active_subscriber_count: u32,
    /// Event kind.
    pub event_kind: ManifoldStreamSubscriptionAuthorityAuditEventKind,
    /// Subscription request reviewed by authority.
    pub request: ManifoldStreamSubscriptionRequest,
    /// Accepted subscription. Present only for accepted events.
    pub accepted: Option<ManifoldStreamSubscription>,
    /// Rejected subscription result. Present only for rejected events.
    pub rejection: Option<ManifoldStreamSubscriptionRejection>,
    /// Clock snapshot recorded with the decision.
    pub recorded_clock: ManifoldClockSnapshot,
    /// Stable ids for fixtures, scorecards, or logs backing the event.
    pub evidence_refs: Vec<DottedId>,
}

/// Deterministic review result for one stream subscription authority decision.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamSubscriptionAuthorityReview {
    /// Schema identifier for this review.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable review id.
    pub review_id: DottedId,
    /// Authority that reviewed the subscription request.
    pub authority_id: DottedId,
    /// Authority revision used by this review.
    pub authority_revision: Revision,
    /// Stream-registry revision used by this review.
    pub registry_revision: Revision,
    /// Review outcome.
    pub outcome: ManifoldStreamSubscriptionAuthorityReviewOutcome,
    /// Accepted subscription. Present only for accepted reviews.
    pub accepted: Option<ManifoldStreamSubscription>,
    /// Rejected subscription result. Present only for rejected reviews.
    pub rejection: Option<ManifoldStreamSubscriptionRejection>,
    /// Audit event for the same subscription decision.
    pub audit_event: ManifoldStreamSubscriptionAuthorityAuditEvent,
}

impl ManifoldStreamSubscriptionAuthorityReview {
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
        if self.schema_id.as_str() != "rusty.manifold.authority.stream_subscription_review.v1" {
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

        if self.registry_revision != snapshot.stream_registry.registry_revision
            || self.registry_revision != self.audit_event.prior_registry_revision
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.registry_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::RegistryRevisionMismatch,
            ));
        }

        match self.outcome {
            ManifoldStreamSubscriptionAuthorityReviewOutcome::SubscriptionAccepted => {
                if self.accepted.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.review_id.clone(),
                        "accepted".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
            ManifoldStreamSubscriptionAuthorityReviewOutcome::SubscriptionRejected => {
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

        if ManifoldStreamSubscriptionAuthorityAuditEventKind::from(self.outcome)
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

impl ManifoldStreamSubscriptionAuthorityAuditEvent {
    /// Validates this event against the authority snapshot it claims to use.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the event is not a
    /// consistent subscription acceptance or rejection for the supplied snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str() != "rusty.manifold.authority.stream_subscription_audit_event.v1"
        {
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

        if self.prior_registry_revision != snapshot.stream_registry.registry_revision {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.prior_registry_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::RegistryRevisionMismatch,
            ));
        }

        if self.active_subscriber_count
            != snapshot.active_subscription_count(&self.request.stream_id)
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.active_subscriber_count.to_string(),
                ManifoldAuthorityValidationErrorKind::SubscriptionMismatch,
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
            ManifoldStreamSubscriptionAuthorityAuditEventKind::SubscriptionAccepted => {
                if self.accepted.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        "accepted".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
            ManifoldStreamSubscriptionAuthorityAuditEventKind::SubscriptionRejected => {
                if self.accepted.is_some() || self.rejection.is_none() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
        }

        let expected_decision =
            snapshot.stream_subscription_authority_decision(&self.request, &self.recorded_clock);

        if let Some(accepted) = &self.accepted {
            let StreamSubscriptionAuthorityDecision::Accepted(expected_subscription) =
                &expected_decision
            else {
                let rejected_value = match &expected_decision {
                    StreamSubscriptionAuthorityDecision::Rejected { rejection_code, .. } => {
                        rejection_code.clone()
                    }
                    StreamSubscriptionAuthorityDecision::Accepted(_) => "accepted".to_owned(),
                };
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejected_value.clone(),
                    authority_error_kind_for_stream_subscription_rejection_code(&rejected_value),
                ));
            };

            if accepted != expected_subscription {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    accepted.subscription_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::SubscriptionMismatch,
                ));
            }
        }

        if let Some(rejection) = &self.rejection {
            let StreamSubscriptionAuthorityDecision::Rejected {
                rejection_code,
                message,
                retryable,
                active_subscriber_count,
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
                || rejection.current_registry_revision != self.prior_registry_revision
            {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejection.current_registry_revision.get().to_string(),
                    ManifoldAuthorityValidationErrorKind::RejectionRevisionMismatch,
                ));
            }

            if rejection.active_subscriber_count != *active_subscriber_count
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

/// Deterministic application result for one stream subscription authority review.
///
/// This records the bridge from review-time subscription authority to accepted
/// authority state without owning live transport, callbacks, or provider runtime
/// work.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamSubscriptionAuthorityApplication {
    /// Schema identifier for this application receipt.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable application id.
    pub application_id: DottedId,
    /// Authority that attempted the application.
    pub authority_id: DottedId,
    /// Authority revision before applying the review.
    pub from_authority_revision: Revision,
    /// Stream-registry revision before applying the review.
    pub from_registry_revision: Revision,
    /// Stream whose subscriber set was reviewed.
    pub stream_id: DottedId,
    /// Active subscriber count before applying the review.
    pub from_active_subscriber_count: u32,
    /// Application outcome.
    pub outcome: ManifoldStreamSubscriptionAuthorityApplicationOutcome,
    /// Next accepted authority snapshot. Present only for applied outcomes.
    pub applied_snapshot: Option<ManifoldAuthoritySnapshot>,
    /// Rejection. Present only for rejected application outcomes.
    pub rejection: Option<ManifoldAuthoritySnapshotApplicationRejection>,
    /// Review that was applied or rejected for application.
    pub review: ManifoldStreamSubscriptionAuthorityReview,
}

impl ManifoldStreamSubscriptionAuthorityApplication {
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
        if self.schema_id.as_str() != "rusty.manifold.authority.stream_subscription_application.v1"
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.schema_id.to_string(),
                ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
            ));
        }

        validate_derived_authority_id(
            &self.application_id,
            &self.application_id,
            stream_subscription_authority_application_id(&self.review.review_id),
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

        if self.from_registry_revision != snapshot.stream_registry.registry_revision
            || self.from_registry_revision != self.review.registry_revision
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.from_registry_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::RegistryRevisionMismatch,
            ));
        }

        if self.stream_id != self.review.audit_event.request.stream_id {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.stream_id.to_string(),
                ManifoldAuthorityValidationErrorKind::SubscriptionMismatch,
            ));
        }

        let snapshot_active_count = snapshot.active_subscription_count(&self.stream_id);
        if self.from_active_subscriber_count != snapshot_active_count
            || self.from_active_subscriber_count != self.review.audit_event.active_subscriber_count
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.from_active_subscriber_count.to_string(),
                ManifoldAuthorityValidationErrorKind::SubscriptionMismatch,
            ));
        }

        self.review.validate_against_snapshot(snapshot)?;

        match self.outcome {
            ManifoldStreamSubscriptionAuthorityApplicationOutcome::SubscriptionApplied => {
                if self.applied_snapshot.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        "applied_snapshot".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                if self.review.outcome
                    != ManifoldStreamSubscriptionAuthorityReviewOutcome::SubscriptionAccepted
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
                    || applied.active_leases != snapshot.active_leases
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        applied.authority_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::SubscriptionMismatch,
                    ));
                }

                let accepted_subscription = self.review.accepted.clone().ok_or_else(|| {
                    ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        "accepted".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    )
                })?;
                let mut expected_subscriptions = snapshot.active_stream_subscriptions.clone();
                expected_subscriptions.push(accepted_subscription);
                if applied.active_stream_subscriptions != expected_subscriptions {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        self.stream_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::SubscriptionMismatch,
                    ));
                }

                applied.validate_authority_links()
            }
            ManifoldStreamSubscriptionAuthorityApplicationOutcome::SubscriptionApplicationRejected => {
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
                    == ManifoldStreamSubscriptionAuthorityReviewOutcome::SubscriptionRejected
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
enum StreamSubscriptionAuthorityDecision {
    Accepted(ManifoldStreamSubscription),
    Rejected {
        rejection_code: String,
        message: String,
        retryable: bool,
        active_subscriber_count: u32,
    },
}

impl ManifoldAuthoritySnapshot {
    /// Deterministically reviews one stream subscription request.
    ///
    /// The review is source-only: it admits or rejects a subscriber against the
    /// accepted stream manifest and host capability state, but it does not open
    /// transports, notify subscribers, or contact runtime providers.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the authority snapshot
    /// itself is invalid, the review clock is inconsistent, or evidence refs are empty.
    pub fn review_stream_subscription(
        &self,
        request: ManifoldStreamSubscriptionRequest,
        recorded_clock: ManifoldClockSnapshot,
        evidence_refs: Vec<DottedId>,
    ) -> Result<ManifoldStreamSubscriptionAuthorityReview, ManifoldAuthorityValidationError> {
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

        let decision = self.stream_subscription_authority_decision(&request, &recorded_clock);
        let active_subscriber_count = self.active_subscription_count(&request.stream_id);
        let (outcome, accepted, rejection) = match decision {
            StreamSubscriptionAuthorityDecision::Accepted(subscription) => (
                ManifoldStreamSubscriptionAuthorityReviewOutcome::SubscriptionAccepted,
                Some(subscription),
                None,
            ),
            StreamSubscriptionAuthorityDecision::Rejected {
                rejection_code,
                message,
                retryable,
                active_subscriber_count,
            } => (
                ManifoldStreamSubscriptionAuthorityReviewOutcome::SubscriptionRejected,
                None,
                Some(ManifoldStreamSubscriptionRejection {
                    schema_id: stream_subscription_rejection_schema_id(),
                    request_id: request.request_id.clone(),
                    rejection_code: DottedId::new(rejection_code)
                        .expect("rejection code is a valid dotted id"),
                    message,
                    retryable,
                    current_authority_revision: self.authority_revision,
                    current_registry_revision: self.stream_registry.registry_revision,
                    active_subscriber_count,
                }),
            ),
        };

        let audit_event = ManifoldStreamSubscriptionAuthorityAuditEvent {
            schema_id: stream_subscription_authority_audit_event_schema_id(),
            event_id: stream_subscription_authority_audit_event_id(&request.request_id, outcome),
            authority_id: self.authority_id.clone(),
            prior_authority_revision: self.authority_revision,
            prior_registry_revision: self.stream_registry.registry_revision,
            active_subscriber_count,
            event_kind: outcome.into(),
            request,
            accepted: accepted.clone(),
            rejection: rejection.clone(),
            recorded_clock,
            evidence_refs,
        };

        let review = ManifoldStreamSubscriptionAuthorityReview {
            schema_id: stream_subscription_authority_review_schema_id(),
            review_id: stream_subscription_authority_review_id(&audit_event.request.request_id),
            authority_id: self.authority_id.clone(),
            authority_revision: self.authority_revision,
            registry_revision: self.stream_registry.registry_revision,
            outcome,
            accepted,
            rejection,
            audit_event,
        };
        review.validate_against_snapshot(self)?;
        Ok(review)
    }

    /// Deterministically applies one stream subscription authority review.
    ///
    /// Accepted subscription reviews produce a new `ManifoldAuthoritySnapshot`
    /// with the authority revision advanced by one and the accepted active
    /// subscription appended. Rejected reviews produce a machine-readable
    /// application rejection and leave accepted state unchanged. This is
    /// source-only: it does not open transports, notify subscribers, or contact
    /// runtime providers.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when this authority snapshot
    /// itself is invalid.
    pub fn apply_stream_subscription_authority_review(
        &self,
        review: ManifoldStreamSubscriptionAuthorityReview,
    ) -> Result<ManifoldStreamSubscriptionAuthorityApplication, ManifoldAuthorityValidationError>
    {
        self.validate_authority_links()?;

        let application_id = stream_subscription_authority_application_id(&review.review_id);
        let from_authority_revision = self.authority_revision;
        let from_registry_revision = self.stream_registry.registry_revision;
        let stream_id = review.audit_event.request.stream_id.clone();
        let from_active_subscriber_count = self.active_subscription_count(&stream_id);

        let (outcome, applied_snapshot, rejection) = match review.validate_against_snapshot(self) {
            Err(error) => (
                ManifoldStreamSubscriptionAuthorityApplicationOutcome::SubscriptionApplicationRejected,
                None,
                Some(ManifoldAuthoritySnapshotApplicationRejection {
                    schema_id: authority_snapshot_application_rejection_schema_id(),
                    application_id: application_id.clone(),
                    rejection_code: DottedId::new(error.rejection_code())
                        .expect("authority rejection code is a valid dotted id"),
                    message: format!(
                        "stream subscription review does not match authority snapshot: {error}"
                    ),
                    retryable: authority_application_validation_retryable(error.kind()),
                    current_authority_revision: self.authority_revision,
                }),
            ),
            Ok(())
                if review.outcome
                    == ManifoldStreamSubscriptionAuthorityReviewOutcome::SubscriptionRejected =>
            {
                (
                    ManifoldStreamSubscriptionAuthorityApplicationOutcome::SubscriptionApplicationRejected,
                    None,
                    Some(ManifoldAuthoritySnapshotApplicationRejection {
                        schema_id: authority_snapshot_application_rejection_schema_id(),
                        application_id: application_id.clone(),
                        rejection_code: DottedId::new("review_rejected")
                            .expect("rejection code literal is valid"),
                        message: "stream subscription review did not accept a subscription"
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
                let accepted_subscription = review.accepted.clone().ok_or_else(|| {
                    ManifoldAuthorityValidationError::new(
                        review.review_id.clone(),
                        "accepted".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    )
                })?;
                let mut next_snapshot = self.clone();
                next_snapshot.authority_revision = next_authority_revision;
                next_snapshot
                    .active_stream_subscriptions
                    .push(accepted_subscription);
                next_snapshot.validate_authority_links()?;
                (
                    ManifoldStreamSubscriptionAuthorityApplicationOutcome::SubscriptionApplied,
                    Some(next_snapshot),
                    None,
                )
            }
        };

        let application = ManifoldStreamSubscriptionAuthorityApplication {
            schema_id: stream_subscription_authority_application_schema_id(),
            application_id,
            authority_id: self.authority_id.clone(),
            from_authority_revision,
            from_registry_revision,
            stream_id,
            from_active_subscriber_count,
            outcome,
            applied_snapshot,
            rejection,
            review,
        };
        application.validate_against_snapshot(self)?;
        Ok(application)
    }

    fn stream_subscription_authority_decision(
        &self,
        request: &ManifoldStreamSubscriptionRequest,
        recorded_clock: &ManifoldClockSnapshot,
    ) -> StreamSubscriptionAuthorityDecision {
        if request.schema_id != stream_subscription_request_schema_id() {
            return StreamSubscriptionAuthorityDecision::Rejected {
                rejection_code: "unsupported_schema".to_owned(),
                message: "stream subscription request schema is not supported".to_owned(),
                retryable: false,
                active_subscriber_count: self.active_subscription_count(&request.stream_id),
            };
        }

        if request.expected_authority_revision != self.authority_revision {
            return StreamSubscriptionAuthorityDecision::Rejected {
                rejection_code: "stale_revision".to_owned(),
                message:
                    "stream subscription request expected authority revision does not match current revision"
                        .to_owned(),
                retryable: true,
                active_subscriber_count: self.active_subscription_count(&request.stream_id),
            };
        }

        if request.expected_registry_revision != self.stream_registry.registry_revision {
            return StreamSubscriptionAuthorityDecision::Rejected {
                rejection_code: "registry_revision_mismatch".to_owned(),
                message:
                    "stream subscription request expected registry revision does not match current registry"
                        .to_owned(),
                retryable: true,
                active_subscriber_count: self.active_subscription_count(&request.stream_id),
            };
        }

        if request.requested_ttl_ms == 0 {
            return StreamSubscriptionAuthorityDecision::Rejected {
                rejection_code: "invalid_ttl".to_owned(),
                message: "stream subscription ttl must be greater than zero".to_owned(),
                retryable: false,
                active_subscriber_count: self.active_subscription_count(&request.stream_id),
            };
        }

        if !self
            .host_manifest
            .capabilities
            .iter()
            .any(|capability| capability == &request.required_capability)
        {
            return StreamSubscriptionAuthorityDecision::Rejected {
                rejection_code: "capability_not_advertised".to_owned(),
                message:
                    "stream subscription request capability is not advertised by the authority host"
                        .to_owned(),
                retryable: false,
                active_subscriber_count: self.active_subscription_count(&request.stream_id),
            };
        }

        let active_subscriber_count = self.active_subscription_count(&request.stream_id);
        let Some(stream) = self.stream_manifest(&request.stream_id) else {
            return StreamSubscriptionAuthorityDecision::Rejected {
                rejection_code: "unknown_stream".to_owned(),
                message: "stream subscription request references an unknown stream".to_owned(),
                retryable: true,
                active_subscriber_count,
            };
        };

        if request.subscriber_kind == ManifoldStreamSubscriberKind::Ui
            && !stream.subscription.ui_subscribable
        {
            return StreamSubscriptionAuthorityDecision::Rejected {
                rejection_code: "subscription_not_allowed".to_owned(),
                message: "stream manifest does not allow direct UI subscriptions".to_owned(),
                retryable: false,
                active_subscriber_count,
            };
        }

        if let Some(max_subscribers) = stream.subscription.max_subscribers {
            if active_subscriber_count >= max_subscribers {
                return StreamSubscriptionAuthorityDecision::Rejected {
                    rejection_code: "subscriber_limit_reached".to_owned(),
                    message: "stream subscription would exceed the stream subscriber limit"
                        .to_owned(),
                    retryable: true,
                    active_subscriber_count,
                };
            }
        }

        let Some(offer) = stream
            .transport_offers
            .iter()
            .find(|offer| offer.transport_id == request.transport_id)
        else {
            return StreamSubscriptionAuthorityDecision::Rejected {
                rejection_code: "unknown_transport".to_owned(),
                message: "stream subscription request selected an unknown transport offer"
                    .to_owned(),
                retryable: true,
                active_subscriber_count,
            };
        };

        if let Some(endpoint_id) = &offer.endpoint_id {
            if !self
                .host_manifest
                .endpoints
                .iter()
                .any(|endpoint| &endpoint.endpoint_id == endpoint_id)
            {
                return StreamSubscriptionAuthorityDecision::Rejected {
                    rejection_code: "unknown_transport_endpoint".to_owned(),
                    message:
                        "stream subscription request selected a transport with an unknown endpoint"
                            .to_owned(),
                    retryable: false,
                    active_subscriber_count,
                };
            }
        }

        StreamSubscriptionAuthorityDecision::Accepted(ManifoldStreamSubscription {
            schema_id: stream_subscription_schema_id(),
            subscription_id: stream_subscription_id(&request.request_id),
            request_id: request.request_id.clone(),
            subscriber_id: request.subscriber_id.clone(),
            subscriber_kind: request.subscriber_kind,
            stream_id: request.stream_id.clone(),
            transport_id: request.transport_id.clone(),
            endpoint_id: offer.endpoint_id.clone(),
            state: ManifoldStreamSubscriptionState::Active,
            accepted_authority_revision: self.authority_revision,
            accepted_registry_revision: self.stream_registry.registry_revision,
            accepted_at_ms: wall_unix_ms_u64(recorded_clock),
            expires_at_ms: wall_unix_ms_u64(recorded_clock)
                .saturating_add(request.requested_ttl_ms),
            required_capability: request.required_capability.clone(),
        })
    }
}
