use super::*;

/// Stream subscription release authority audit event.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamSubscriptionReleaseAuthorityAuditEvent {
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
    pub event_kind: ManifoldStreamSubscriptionReleaseAuthorityAuditEventKind,
    /// Release request reviewed by authority.
    pub request: ManifoldStreamSubscriptionReleaseRequest,
    /// Released subscription. Present only for released events.
    pub released: Option<ManifoldStreamSubscription>,
    /// Rejected release result. Present only for rejected events.
    pub rejection: Option<ManifoldStreamSubscriptionReleaseRejection>,
    /// Clock snapshot recorded with the decision.
    pub recorded_clock: ManifoldClockSnapshot,
    /// Stable ids for fixtures, scorecards, or logs backing the event.
    pub evidence_refs: Vec<DottedId>,
}

/// Deterministic review result for one stream subscription release authority decision.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamSubscriptionReleaseAuthorityReview {
    /// Schema identifier for this review.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable review id.
    pub review_id: DottedId,
    /// Authority that reviewed the release request.
    pub authority_id: DottedId,
    /// Authority revision used by this review.
    pub authority_revision: Revision,
    /// Stream-registry revision used by this review.
    pub registry_revision: Revision,
    /// Review outcome.
    pub outcome: ManifoldStreamSubscriptionReleaseAuthorityReviewOutcome,
    /// Released subscription. Present only for accepted release reviews.
    pub released: Option<ManifoldStreamSubscription>,
    /// Rejected release result. Present only for rejected release reviews.
    pub rejection: Option<ManifoldStreamSubscriptionReleaseRejection>,
    /// Audit event for the same release decision.
    pub audit_event: ManifoldStreamSubscriptionReleaseAuthorityAuditEvent,
}

impl ManifoldStreamSubscriptionReleaseAuthorityReview {
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
        if self.schema_id.as_str()
            != "rusty.manifold.authority.stream_subscription_release_review.v1"
        {
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
            ManifoldStreamSubscriptionReleaseAuthorityReviewOutcome::SubscriptionReleased => {
                if self.released.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.review_id.clone(),
                        "released".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
            ManifoldStreamSubscriptionReleaseAuthorityReviewOutcome::SubscriptionReleaseRejected => {
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

        if ManifoldStreamSubscriptionReleaseAuthorityAuditEventKind::from(self.outcome)
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

impl ManifoldStreamSubscriptionReleaseAuthorityAuditEvent {
    /// Validates this event against the authority snapshot it claims to use.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the event is not a
    /// consistent subscription release or rejection for the supplied snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str()
            != "rusty.manifold.authority.stream_subscription_release_audit_event.v1"
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
            ManifoldStreamSubscriptionReleaseAuthorityAuditEventKind::SubscriptionReleased => {
                if self.released.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        "released".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
            ManifoldStreamSubscriptionReleaseAuthorityAuditEventKind::SubscriptionReleaseRejected => {
                if self.released.is_some() || self.rejection.is_none() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
        }

        let expected_decision = snapshot
            .stream_subscription_release_authority_decision(&self.request, &self.recorded_clock);

        if let Some(released) = &self.released {
            let StreamSubscriptionReleaseAuthorityDecision::Released(expected_subscription) =
                &expected_decision
            else {
                let rejected_value = match &expected_decision {
                    StreamSubscriptionReleaseAuthorityDecision::Rejected {
                        rejection_code, ..
                    } => rejection_code.clone(),
                    StreamSubscriptionReleaseAuthorityDecision::Released(_) => {
                        "released".to_owned()
                    }
                };
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejected_value.clone(),
                    authority_error_kind_for_stream_subscription_release_rejection_code(
                        &rejected_value,
                    ),
                ));
            };

            if released != expected_subscription {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    released.subscription_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::SubscriptionMismatch,
                ));
            }
        }

        if let Some(rejection) = &self.rejection {
            let StreamSubscriptionReleaseAuthorityDecision::Rejected {
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

/// Deterministic application result for one stream subscription release authority review.
///
/// This records the bridge from review-time release authority to accepted
/// authority state without owning live transport teardown, callbacks, or
/// provider runtime work.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamSubscriptionReleaseAuthorityApplication {
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
    /// Subscription released by the reviewed request.
    pub subscription_id: DottedId,
    /// Active subscriber count before applying the review.
    pub from_active_subscriber_count: u32,
    /// Application outcome.
    pub outcome: ManifoldStreamSubscriptionReleaseAuthorityApplicationOutcome,
    /// Next accepted authority snapshot. Present only for applied outcomes.
    pub applied_snapshot: Option<ManifoldAuthoritySnapshot>,
    /// Rejection. Present only for rejected application outcomes.
    pub rejection: Option<ManifoldAuthoritySnapshotApplicationRejection>,
    /// Review that was applied or rejected for application.
    pub review: ManifoldStreamSubscriptionReleaseAuthorityReview,
}

impl ManifoldStreamSubscriptionReleaseAuthorityApplication {
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
        if self.schema_id.as_str()
            != "rusty.manifold.authority.stream_subscription_release_application.v1"
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
            stream_subscription_release_authority_application_id(&self.review.review_id),
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

        if self.stream_id != self.review.audit_event.request.stream_id
            || self.subscription_id != self.review.audit_event.request.subscription_id
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.subscription_id.to_string(),
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
            ManifoldStreamSubscriptionReleaseAuthorityApplicationOutcome::SubscriptionReleaseApplied => {
                if self.applied_snapshot.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        "applied_snapshot".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                if self.review.outcome
                    != ManifoldStreamSubscriptionReleaseAuthorityReviewOutcome::SubscriptionReleased
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

                let released_subscription = self.review.released.clone().ok_or_else(|| {
                    ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        "released".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    )
                })?;
                let mut expected_subscriptions = snapshot.active_stream_subscriptions.clone();
                let Some(position) = expected_subscriptions.iter().position(|subscription| {
                    subscription.subscription_id == released_subscription.subscription_id
                }) else {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        released_subscription.subscription_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::UnknownSubscription,
                    ));
                };
                let removed = expected_subscriptions.remove(position);
                if removed != released_subscription
                    || applied.active_stream_subscriptions != expected_subscriptions
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        self.stream_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::SubscriptionMismatch,
                    ));
                }

                applied.validate_authority_links()
            }
            ManifoldStreamSubscriptionReleaseAuthorityApplicationOutcome::SubscriptionReleaseApplicationRejected => {
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
                    == ManifoldStreamSubscriptionReleaseAuthorityReviewOutcome::SubscriptionReleaseRejected
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
enum StreamSubscriptionReleaseAuthorityDecision {
    Released(ManifoldStreamSubscription),
    Rejected {
        rejection_code: String,
        message: String,
        retryable: bool,
        active_subscriber_count: u32,
    },
}

impl ManifoldAuthoritySnapshot {
    /// Deterministically reviews one active stream subscription release request.
    ///
    /// The review is source-only: it verifies the release preconditions against
    /// accepted authority state and records the subscription to remove, but it
    /// does not close transports, notify subscribers, or contact providers.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the authority snapshot
    /// itself is invalid, the review clock is inconsistent, or evidence refs are empty.
    pub fn review_stream_subscription_release(
        &self,
        request: ManifoldStreamSubscriptionReleaseRequest,
        recorded_clock: ManifoldClockSnapshot,
        evidence_refs: Vec<DottedId>,
    ) -> Result<ManifoldStreamSubscriptionReleaseAuthorityReview, ManifoldAuthorityValidationError>
    {
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

        let decision =
            self.stream_subscription_release_authority_decision(&request, &recorded_clock);
        let active_subscriber_count = self.active_subscription_count(&request.stream_id);
        let (outcome, released, rejection) = match decision {
            StreamSubscriptionReleaseAuthorityDecision::Released(subscription) => (
                ManifoldStreamSubscriptionReleaseAuthorityReviewOutcome::SubscriptionReleased,
                Some(subscription),
                None,
            ),
            StreamSubscriptionReleaseAuthorityDecision::Rejected {
                rejection_code,
                message,
                retryable,
                active_subscriber_count,
            } => (
                ManifoldStreamSubscriptionReleaseAuthorityReviewOutcome::SubscriptionReleaseRejected,
                None,
                Some(ManifoldStreamSubscriptionReleaseRejection {
                    schema_id: stream_subscription_release_rejection_schema_id(),
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

        let audit_event = ManifoldStreamSubscriptionReleaseAuthorityAuditEvent {
            schema_id: stream_subscription_release_authority_audit_event_schema_id(),
            event_id: stream_subscription_release_authority_audit_event_id(
                &request.request_id,
                outcome,
            ),
            authority_id: self.authority_id.clone(),
            prior_authority_revision: self.authority_revision,
            prior_registry_revision: self.stream_registry.registry_revision,
            active_subscriber_count,
            event_kind: outcome.into(),
            request,
            released: released.clone(),
            rejection: rejection.clone(),
            recorded_clock,
            evidence_refs,
        };

        let review = ManifoldStreamSubscriptionReleaseAuthorityReview {
            schema_id: stream_subscription_release_authority_review_schema_id(),
            review_id: stream_subscription_release_authority_review_id(
                &audit_event.request.request_id,
            ),
            authority_id: self.authority_id.clone(),
            authority_revision: self.authority_revision,
            registry_revision: self.stream_registry.registry_revision,
            outcome,
            released,
            rejection,
            audit_event,
        };
        review.validate_against_snapshot(self)?;
        Ok(review)
    }

    /// Deterministically applies one stream subscription release authority review.
    ///
    /// Accepted release reviews produce a new `ManifoldAuthoritySnapshot` with
    /// the authority revision advanced by one and the released subscription
    /// removed from the active set. Rejected reviews produce a machine-readable
    /// application rejection and leave accepted state unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when this authority snapshot
    /// itself is invalid.
    pub fn apply_stream_subscription_release_authority_review(
        &self,
        review: ManifoldStreamSubscriptionReleaseAuthorityReview,
    ) -> Result<
        ManifoldStreamSubscriptionReleaseAuthorityApplication,
        ManifoldAuthorityValidationError,
    > {
        self.validate_authority_links()?;

        let application_id =
            stream_subscription_release_authority_application_id(&review.review_id);
        let from_authority_revision = self.authority_revision;
        let from_registry_revision = self.stream_registry.registry_revision;
        let stream_id = review.audit_event.request.stream_id.clone();
        let subscription_id = review.audit_event.request.subscription_id.clone();
        let from_active_subscriber_count = self.active_subscription_count(&stream_id);

        let (outcome, applied_snapshot, rejection) = match review.validate_against_snapshot(self) {
            Err(error) => (
                ManifoldStreamSubscriptionReleaseAuthorityApplicationOutcome::SubscriptionReleaseApplicationRejected,
                None,
                Some(ManifoldAuthoritySnapshotApplicationRejection {
                    schema_id: authority_snapshot_application_rejection_schema_id(),
                    application_id: application_id.clone(),
                    rejection_code: DottedId::new(error.rejection_code())
                        .expect("authority rejection code is a valid dotted id"),
                    message: format!(
                        "stream subscription release review does not match authority snapshot: {error}"
                    ),
                    retryable: authority_application_validation_retryable(error.kind()),
                    current_authority_revision: self.authority_revision,
                }),
            ),
            Ok(())
                if review.outcome
                    == ManifoldStreamSubscriptionReleaseAuthorityReviewOutcome::SubscriptionReleaseRejected =>
            {
                (
                    ManifoldStreamSubscriptionReleaseAuthorityApplicationOutcome::SubscriptionReleaseApplicationRejected,
                    None,
                    Some(ManifoldAuthoritySnapshotApplicationRejection {
                        schema_id: authority_snapshot_application_rejection_schema_id(),
                        application_id: application_id.clone(),
                        rejection_code: DottedId::new("review_rejected")
                            .expect("rejection code literal is valid"),
                        message: "stream subscription release review did not release a subscription"
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
                let released_subscription = review.released.clone().ok_or_else(|| {
                    ManifoldAuthorityValidationError::new(
                        review.review_id.clone(),
                        "released".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    )
                })?;
                let mut next_snapshot = self.clone();
                next_snapshot.authority_revision = next_authority_revision;
                let Some(position) = next_snapshot
                    .active_stream_subscriptions
                    .iter()
                    .position(|subscription| {
                        subscription.subscription_id == released_subscription.subscription_id
                    })
                else {
                    return Err(ManifoldAuthorityValidationError::new(
                        review.review_id.clone(),
                        released_subscription.subscription_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::UnknownSubscription,
                    ));
                };
                next_snapshot.active_stream_subscriptions.remove(position);
                next_snapshot.validate_authority_links()?;
                (
                    ManifoldStreamSubscriptionReleaseAuthorityApplicationOutcome::SubscriptionReleaseApplied,
                    Some(next_snapshot),
                    None,
                )
            }
        };

        let application = ManifoldStreamSubscriptionReleaseAuthorityApplication {
            schema_id: stream_subscription_release_authority_application_schema_id(),
            application_id,
            authority_id: self.authority_id.clone(),
            from_authority_revision,
            from_registry_revision,
            stream_id,
            subscription_id,
            from_active_subscriber_count,
            outcome,
            applied_snapshot,
            rejection,
            review,
        };
        application.validate_against_snapshot(self)?;
        Ok(application)
    }

    fn stream_subscription_release_authority_decision(
        &self,
        request: &ManifoldStreamSubscriptionReleaseRequest,
        recorded_clock: &ManifoldClockSnapshot,
    ) -> StreamSubscriptionReleaseAuthorityDecision {
        if request.schema_id != stream_subscription_release_request_schema_id() {
            return StreamSubscriptionReleaseAuthorityDecision::Rejected {
                rejection_code: "unsupported_schema".to_owned(),
                message: "stream subscription release request schema is not supported".to_owned(),
                retryable: false,
                active_subscriber_count: self.active_subscription_count(&request.stream_id),
            };
        }

        if request.expected_authority_revision != self.authority_revision {
            return StreamSubscriptionReleaseAuthorityDecision::Rejected {
                rejection_code: "stale_revision".to_owned(),
                message:
                    "stream subscription release request expected authority revision does not match current revision"
                        .to_owned(),
                retryable: true,
                active_subscriber_count: self.active_subscription_count(&request.stream_id),
            };
        }

        if request.expected_registry_revision != self.stream_registry.registry_revision {
            return StreamSubscriptionReleaseAuthorityDecision::Rejected {
                rejection_code: "registry_revision_mismatch".to_owned(),
                message:
                    "stream subscription release request expected registry revision does not match current registry"
                        .to_owned(),
                retryable: true,
                active_subscriber_count: self.active_subscription_count(&request.stream_id),
            };
        }

        let Some(subscription) = self.active_stream_subscription(&request.subscription_id) else {
            return StreamSubscriptionReleaseAuthorityDecision::Rejected {
                rejection_code: "unknown_subscription".to_owned(),
                message:
                    "stream subscription release request references an unknown active subscription"
                        .to_owned(),
                retryable: true,
                active_subscriber_count: self.active_subscription_count(&request.stream_id),
            };
        };

        if subscription.state != ManifoldStreamSubscriptionState::Active {
            return StreamSubscriptionReleaseAuthorityDecision::Rejected {
                rejection_code: "inactive_subscription".to_owned(),
                message: "stream subscription release request references a non-active subscription"
                    .to_owned(),
                retryable: true,
                active_subscriber_count: self.active_subscription_count(&subscription.stream_id),
            };
        }

        if stream_subscription_expired_at(subscription, recorded_clock) {
            return StreamSubscriptionReleaseAuthorityDecision::Rejected {
                rejection_code: "expired_subscription".to_owned(),
                message: "stream subscription release request references an expired subscription"
                    .to_owned(),
                retryable: true,
                active_subscriber_count: self.active_subscription_count(&subscription.stream_id),
            };
        }

        if subscription.subscriber_id != request.subscriber_id {
            return StreamSubscriptionReleaseAuthorityDecision::Rejected {
                rejection_code: "subscriber_mismatch".to_owned(),
                message:
                    "stream subscription release request subscriber does not own the subscription"
                        .to_owned(),
                retryable: false,
                active_subscriber_count: self.active_subscription_count(&subscription.stream_id),
            };
        }

        if subscription.stream_id != request.stream_id {
            return StreamSubscriptionReleaseAuthorityDecision::Rejected {
                rejection_code: "stream_mismatch".to_owned(),
                message:
                    "stream subscription release request stream does not match the active subscription"
                        .to_owned(),
                retryable: true,
                active_subscriber_count: self.active_subscription_count(&subscription.stream_id),
            };
        }

        StreamSubscriptionReleaseAuthorityDecision::Released(subscription.clone())
    }
}
