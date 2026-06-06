use super::*;

/// Request to sweep expired accepted authority state.
///
/// The request is source-only authority maintenance. It asks Manifold to
/// classify active leases and active stream subscriptions by the supplied
/// review clock and prepare an auditable accepted-state transition; it does
/// not start timers, close transports, notify holders, or contact runtimes.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldAuthorityExpirySweepRequest {
    /// Schema identifier for this request.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable request id.
    pub request_id: DottedId,
    /// Actor requesting the sweep.
    pub requester_id: DottedId,
    /// Authority revision the requester observed.
    pub expected_authority_revision: Revision,
    /// Stream-registry revision the requester observed.
    pub expected_registry_revision: Revision,
    /// Machine-readable reason for the sweep.
    pub sweep_reason: DottedId,
    /// Request timestamp in milliseconds in the requester clock domain.
    pub requested_at_ms: u64,
}

/// Rejection for an authority expiry sweep request.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldAuthorityExpirySweepRejection {
    /// Schema identifier for this rejection.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Request id being rejected.
    pub request_id: DottedId,
    /// Machine-readable rejection code.
    pub rejection_code: DottedId,
    /// Display-safe explanation.
    pub message: String,
    /// Whether retrying after refreshing state or time may help.
    pub retryable: bool,
    /// Current authority revision observed by the reviewer.
    pub current_authority_revision: Revision,
    /// Current accepted stream-registry revision observed by the reviewer.
    pub current_registry_revision: Revision,
    /// Expired active lease count at the review clock.
    pub expired_lease_count: usize,
    /// Expired active stream subscription count at the review clock.
    pub expired_subscription_count: usize,
}

/// Authority expiry sweep audit event kind.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldAuthorityExpirySweepAuthorityAuditEventKind {
    /// Authority accepted expired state for removal.
    ExpiredStateAccepted,
    /// Authority rejected an expiry sweep request.
    ExpirySweepRejected,
}

/// Authority expiry sweep review outcome.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldAuthorityExpirySweepAuthorityReviewOutcome {
    /// Authority accepted expired state for removal.
    ExpiredStateAccepted,
    /// Authority rejected the expiry sweep request.
    ExpirySweepRejected,
}

impl From<ManifoldAuthorityExpirySweepAuthorityReviewOutcome>
    for ManifoldAuthorityExpirySweepAuthorityAuditEventKind
{
    fn from(outcome: ManifoldAuthorityExpirySweepAuthorityReviewOutcome) -> Self {
        match outcome {
            ManifoldAuthorityExpirySweepAuthorityReviewOutcome::ExpiredStateAccepted => {
                Self::ExpiredStateAccepted
            }
            ManifoldAuthorityExpirySweepAuthorityReviewOutcome::ExpirySweepRejected => {
                Self::ExpirySweepRejected
            }
        }
    }
}

/// Authority expiry sweep application outcome.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldAuthorityExpirySweepAuthorityApplicationOutcome {
    /// Accepted expiry sweep review was applied to the authority snapshot.
    ExpiredStateApplied,
    /// Expiry sweep review could not be applied to accepted authority state.
    ExpirySweepApplicationRejected,
}

/// Audit event for one authority expiry sweep decision.
///
/// The event carries the sweep request plus exactly one accepted expired-state
/// set or rejected result. It records enough authority context to validate
/// cleanup deterministically without owning timers, transports, or callbacks.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldAuthorityExpirySweepAuthorityAuditEvent {
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
    /// Event kind.
    pub event_kind: ManifoldAuthorityExpirySweepAuthorityAuditEventKind,
    /// Sweep request reviewed by authority.
    pub request: ManifoldAuthorityExpirySweepRequest,
    /// Expired active leases found at the review clock. Present only for accepted events.
    pub expired_leases: Vec<ManifoldControlLease>,
    /// Expired active stream subscriptions found at the review clock. Present only for accepted events.
    pub expired_stream_subscriptions: Vec<ManifoldStreamSubscription>,
    /// Rejected sweep result. Present only for rejected events.
    pub rejection: Option<ManifoldAuthorityExpirySweepRejection>,
    /// Clock snapshot recorded with the decision.
    pub recorded_clock: ManifoldClockSnapshot,
    /// Stable ids for fixtures, scorecards, or logs backing the event.
    pub evidence_refs: Vec<DottedId>,
}

/// Deterministic review result for one authority expiry sweep decision.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldAuthorityExpirySweepAuthorityReview {
    /// Schema identifier for this review.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable review id.
    pub review_id: DottedId,
    /// Authority that reviewed the sweep.
    pub authority_id: DottedId,
    /// Authority revision used by this review.
    pub authority_revision: Revision,
    /// Stream-registry revision used by this review.
    pub registry_revision: Revision,
    /// Review outcome.
    pub outcome: ManifoldAuthorityExpirySweepAuthorityReviewOutcome,
    /// Expired active leases accepted for removal.
    pub expired_leases: Vec<ManifoldControlLease>,
    /// Expired active stream subscriptions accepted for removal.
    pub expired_stream_subscriptions: Vec<ManifoldStreamSubscription>,
    /// Rejected sweep result. Present only for rejected reviews.
    pub rejection: Option<ManifoldAuthorityExpirySweepRejection>,
    /// Audit event for the same sweep decision.
    pub audit_event: ManifoldAuthorityExpirySweepAuthorityAuditEvent,
}

impl ManifoldAuthorityExpirySweepAuthorityReview {
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
        if self.schema_id.as_str() != "rusty.manifold.authority.expiry_sweep_review.v1" {
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
            ManifoldAuthorityExpirySweepAuthorityReviewOutcome::ExpiredStateAccepted => {
                if (self.expired_leases.is_empty() && self.expired_stream_subscriptions.is_empty())
                    || self.rejection.is_some()
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.review_id.clone(),
                        "expired_state".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
            ManifoldAuthorityExpirySweepAuthorityReviewOutcome::ExpirySweepRejected => {
                if !self.expired_leases.is_empty()
                    || !self.expired_stream_subscriptions.is_empty()
                    || self.rejection.is_none()
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.review_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
        }

        if self.expired_leases != self.audit_event.expired_leases
            || self.expired_stream_subscriptions != self.audit_event.expired_stream_subscriptions
            || self.rejection != self.audit_event.rejection
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.audit_event.event_id.to_string(),
                ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
            ));
        }

        if ManifoldAuthorityExpirySweepAuthorityAuditEventKind::from(self.outcome)
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

impl ManifoldAuthorityExpirySweepAuthorityAuditEvent {
    /// Validates this event against the authority snapshot it claims to use.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the event is not a
    /// consistent expiry sweep acceptance or rejection for the supplied snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str() != "rusty.manifold.authority.expiry_sweep_audit_event.v1" {
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
            ManifoldAuthorityExpirySweepAuthorityAuditEventKind::ExpiredStateAccepted => {
                if (self.expired_leases.is_empty() && self.expired_stream_subscriptions.is_empty())
                    || self.rejection.is_some()
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        "expired_state".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
            ManifoldAuthorityExpirySweepAuthorityAuditEventKind::ExpirySweepRejected => {
                if !self.expired_leases.is_empty()
                    || !self.expired_stream_subscriptions.is_empty()
                    || self.rejection.is_none()
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
        }

        let expected_decision =
            snapshot.authority_expiry_sweep_decision(&self.request, &self.recorded_clock);

        match (&self.event_kind, expected_decision) {
            (
                ManifoldAuthorityExpirySweepAuthorityAuditEventKind::ExpiredStateAccepted,
                AuthorityExpirySweepDecision::Accepted {
                    expired_leases,
                    expired_stream_subscriptions,
                },
            ) => {
                if self.expired_leases != expired_leases
                    || self.expired_stream_subscriptions != expired_stream_subscriptions
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        self.request.request_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::LeaseMismatch,
                    ));
                }
            }
            (
                ManifoldAuthorityExpirySweepAuthorityAuditEventKind::ExpirySweepRejected,
                AuthorityExpirySweepDecision::Rejected {
                    rejection_code,
                    message,
                    retryable,
                    expired_lease_count,
                    expired_subscription_count,
                },
            ) => {
                let rejection = self.rejection.as_ref().expect("rejection presence checked");
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
                        rejection.current_authority_revision.get().to_string(),
                        ManifoldAuthorityValidationErrorKind::RejectionRevisionMismatch,
                    ));
                }

                if rejection.rejection_code.as_str() != rejection_code
                    || rejection.message != message
                    || rejection.retryable != retryable
                    || rejection.expired_lease_count != expired_lease_count
                    || rejection.expired_subscription_count != expired_subscription_count
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        rejection.rejection_code.to_string(),
                        authority_error_kind_for_expiry_sweep_rejection_code(&rejection_code),
                    ));
                }
            }
            (_, AuthorityExpirySweepDecision::Accepted { .. }) => {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    self.request.request_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                ));
            }
            (_, AuthorityExpirySweepDecision::Rejected { rejection_code, .. }) => {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejection_code.clone(),
                    authority_error_kind_for_expiry_sweep_rejection_code(&rejection_code),
                ));
            }
        }

        Ok(())
    }
}

/// Deterministic application result for one authority expiry sweep review.
///
/// This records the bridge from review-time expiry authority to accepted
/// authority state without owning live timer, holder, subscriber, transport,
/// provider, or host behavior.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldAuthorityExpirySweepAuthorityApplication {
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
    /// Request applied or rejected.
    pub request_id: DottedId,
    /// Number of active leases before applying the review.
    pub from_active_lease_count: usize,
    /// Number of active stream subscriptions before applying the review.
    pub from_active_subscription_count: usize,
    /// Number of leases removed by an accepted application.
    pub expired_lease_count: usize,
    /// Number of stream subscriptions removed by an accepted application.
    pub expired_subscription_count: usize,
    /// Application outcome.
    pub outcome: ManifoldAuthorityExpirySweepAuthorityApplicationOutcome,
    /// Next accepted authority snapshot. Present only for applied outcomes.
    pub applied_snapshot: Option<ManifoldAuthoritySnapshot>,
    /// Rejection. Present only for rejected application outcomes.
    pub rejection: Option<ManifoldAuthoritySnapshotApplicationRejection>,
    /// Review that was applied or rejected for application.
    pub review: ManifoldAuthorityExpirySweepAuthorityReview,
}

impl ManifoldAuthorityExpirySweepAuthorityApplication {
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
        if self.schema_id.as_str() != "rusty.manifold.authority.expiry_sweep_application.v1" {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.schema_id.to_string(),
                ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
            ));
        }

        validate_derived_authority_id(
            &self.application_id,
            &self.application_id,
            authority_expiry_sweep_authority_application_id(&self.review.review_id),
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

        if self.request_id != self.review.audit_event.request.request_id
            || self.from_active_lease_count != snapshot.active_leases.len()
            || self.from_active_subscription_count != snapshot.active_stream_subscriptions.len()
            || self.expired_lease_count != self.review.expired_leases.len()
            || self.expired_subscription_count != self.review.expired_stream_subscriptions.len()
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.request_id.to_string(),
                ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
            ));
        }

        self.review.validate_against_snapshot(snapshot)?;

        match self.outcome {
            ManifoldAuthorityExpirySweepAuthorityApplicationOutcome::ExpiredStateApplied => {
                if self.applied_snapshot.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        "applied_snapshot".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                if self.review.outcome
                    != ManifoldAuthorityExpirySweepAuthorityReviewOutcome::ExpiredStateAccepted
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
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        applied.authority_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                let expired_lease_ids = self
                    .review
                    .expired_leases
                    .iter()
                    .map(|lease| lease.lease_id.clone())
                    .collect::<Vec<_>>();
                let mut expected_leases = snapshot.active_leases.clone();
                expected_leases
                    .retain(|lease| !expired_lease_ids.iter().any(|id| id == &lease.lease_id));
                if applied.active_leases != expected_leases {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        self.request_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::LeaseMismatch,
                    ));
                }

                let expired_subscription_ids = self
                    .review
                    .expired_stream_subscriptions
                    .iter()
                    .map(|subscription| subscription.subscription_id.clone())
                    .collect::<Vec<_>>();
                let mut expected_subscriptions = snapshot.active_stream_subscriptions.clone();
                expected_subscriptions.retain(|subscription| {
                    !expired_subscription_ids
                        .iter()
                        .any(|id| id == &subscription.subscription_id)
                });
                if applied.active_stream_subscriptions != expected_subscriptions {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        self.request_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::SubscriptionMismatch,
                    ));
                }

                applied.validate_authority_links()
            }
            ManifoldAuthorityExpirySweepAuthorityApplicationOutcome::ExpirySweepApplicationRejected => {
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
                    == ManifoldAuthorityExpirySweepAuthorityReviewOutcome::ExpirySweepRejected
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
enum AuthorityExpirySweepDecision {
    Accepted {
        expired_leases: Vec<ManifoldControlLease>,
        expired_stream_subscriptions: Vec<ManifoldStreamSubscription>,
    },
    Rejected {
        rejection_code: String,
        message: String,
        retryable: bool,
        expired_lease_count: usize,
        expired_subscription_count: usize,
    },
}

impl ManifoldAuthoritySnapshot {
    /// Deterministically reviews one authority expiry sweep request.
    ///
    /// The review is source-only: it classifies accepted active leases and
    /// active stream subscriptions as expired at the supplied review clock and
    /// records exactly which accepted-state entries should be removed. It does
    /// not start timers, execute commands, close transports, contact hosts, or
    /// notify holders/subscribers.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the authority snapshot
    /// itself is invalid, the review clock is inconsistent, or evidence refs are empty.
    pub fn review_authority_expiry_sweep(
        &self,
        request: ManifoldAuthorityExpirySweepRequest,
        recorded_clock: ManifoldClockSnapshot,
        evidence_refs: Vec<DottedId>,
    ) -> Result<ManifoldAuthorityExpirySweepAuthorityReview, ManifoldAuthorityValidationError> {
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

        let decision = self.authority_expiry_sweep_decision(&request, &recorded_clock);
        let (outcome, expired_leases, expired_stream_subscriptions, rejection) = match decision {
            AuthorityExpirySweepDecision::Accepted {
                expired_leases,
                expired_stream_subscriptions,
            } => (
                ManifoldAuthorityExpirySweepAuthorityReviewOutcome::ExpiredStateAccepted,
                expired_leases,
                expired_stream_subscriptions,
                None,
            ),
            AuthorityExpirySweepDecision::Rejected {
                rejection_code,
                message,
                retryable,
                expired_lease_count,
                expired_subscription_count,
            } => (
                ManifoldAuthorityExpirySweepAuthorityReviewOutcome::ExpirySweepRejected,
                Vec::new(),
                Vec::new(),
                Some(ManifoldAuthorityExpirySweepRejection {
                    schema_id: authority_expiry_sweep_rejection_schema_id(),
                    request_id: request.request_id.clone(),
                    rejection_code: DottedId::new(rejection_code)
                        .expect("rejection code is a valid dotted id"),
                    message,
                    retryable,
                    current_authority_revision: self.authority_revision,
                    current_registry_revision: self.stream_registry.registry_revision,
                    expired_lease_count,
                    expired_subscription_count,
                }),
            ),
        };

        let audit_event = ManifoldAuthorityExpirySweepAuthorityAuditEvent {
            schema_id: authority_expiry_sweep_authority_audit_event_schema_id(),
            event_id: authority_expiry_sweep_authority_audit_event_id(&request.request_id, outcome),
            authority_id: self.authority_id.clone(),
            prior_authority_revision: self.authority_revision,
            prior_registry_revision: self.stream_registry.registry_revision,
            event_kind: outcome.into(),
            request,
            expired_leases: expired_leases.clone(),
            expired_stream_subscriptions: expired_stream_subscriptions.clone(),
            rejection: rejection.clone(),
            recorded_clock,
            evidence_refs,
        };

        let review = ManifoldAuthorityExpirySweepAuthorityReview {
            schema_id: authority_expiry_sweep_authority_review_schema_id(),
            review_id: authority_expiry_sweep_authority_review_id(&audit_event.request.request_id),
            authority_id: self.authority_id.clone(),
            authority_revision: self.authority_revision,
            registry_revision: self.stream_registry.registry_revision,
            outcome,
            expired_leases,
            expired_stream_subscriptions,
            rejection,
            audit_event,
        };
        review.validate_against_snapshot(self)?;
        Ok(review)
    }

    /// Deterministically applies one authority expiry sweep review.
    ///
    /// Accepted sweep reviews produce a new `ManifoldAuthoritySnapshot` with
    /// the authority revision advanced by one and exactly the reviewed expired
    /// leases/subscriptions removed from accepted state. Rejected reviews
    /// produce a machine-readable application rejection and leave accepted
    /// state unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when this authority snapshot
    /// itself is invalid.
    pub fn apply_authority_expiry_sweep_review(
        &self,
        review: ManifoldAuthorityExpirySweepAuthorityReview,
    ) -> Result<ManifoldAuthorityExpirySweepAuthorityApplication, ManifoldAuthorityValidationError>
    {
        self.validate_authority_links()?;

        let application_id = authority_expiry_sweep_authority_application_id(&review.review_id);
        let from_authority_revision = self.authority_revision;
        let from_registry_revision = self.stream_registry.registry_revision;
        let from_active_lease_count = self.active_leases.len();
        let from_active_subscription_count = self.active_stream_subscriptions.len();

        let (outcome, applied_snapshot, rejection) = match review.validate_against_snapshot(self) {
            Err(error) => (
                ManifoldAuthorityExpirySweepAuthorityApplicationOutcome::ExpirySweepApplicationRejected,
                None,
                Some(ManifoldAuthoritySnapshotApplicationRejection {
                    schema_id: authority_snapshot_application_rejection_schema_id(),
                    application_id: application_id.clone(),
                    rejection_code: DottedId::new(error.rejection_code())
                        .expect("authority rejection code is a valid dotted id"),
                    message: format!(
                        "authority expiry sweep review does not match authority snapshot: {error}"
                    ),
                    retryable: authority_application_validation_retryable(error.kind()),
                    current_authority_revision: self.authority_revision,
                }),
            ),
            Ok(())
                if review.outcome
                    == ManifoldAuthorityExpirySweepAuthorityReviewOutcome::ExpirySweepRejected =>
            {
                (
                    ManifoldAuthorityExpirySweepAuthorityApplicationOutcome::ExpirySweepApplicationRejected,
                    None,
                    Some(ManifoldAuthoritySnapshotApplicationRejection {
                        schema_id: authority_snapshot_application_rejection_schema_id(),
                        application_id: application_id.clone(),
                        rejection_code: DottedId::new("review_rejected")
                            .expect("rejection code literal is valid"),
                        message: "authority expiry sweep review did not accept expired state"
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

                let expired_lease_ids = review
                    .expired_leases
                    .iter()
                    .map(|lease| lease.lease_id.clone())
                    .collect::<Vec<_>>();
                let expired_subscription_ids = review
                    .expired_stream_subscriptions
                    .iter()
                    .map(|subscription| subscription.subscription_id.clone())
                    .collect::<Vec<_>>();

                let mut next_snapshot = self.clone();
                next_snapshot.authority_revision = next_authority_revision;
                next_snapshot
                    .active_leases
                    .retain(|lease| !expired_lease_ids.iter().any(|id| id == &lease.lease_id));
                next_snapshot
                    .active_stream_subscriptions
                    .retain(|subscription| {
                        !expired_subscription_ids
                            .iter()
                            .any(|id| id == &subscription.subscription_id)
                    });
                next_snapshot.validate_authority_links()?;
                (
                    ManifoldAuthorityExpirySweepAuthorityApplicationOutcome::ExpiredStateApplied,
                    Some(next_snapshot),
                    None,
                )
            }
        };

        let application = ManifoldAuthorityExpirySweepAuthorityApplication {
            schema_id: authority_expiry_sweep_authority_application_schema_id(),
            application_id,
            authority_id: self.authority_id.clone(),
            from_authority_revision,
            from_registry_revision,
            request_id: review.audit_event.request.request_id.clone(),
            from_active_lease_count,
            from_active_subscription_count,
            expired_lease_count: review.expired_leases.len(),
            expired_subscription_count: review.expired_stream_subscriptions.len(),
            outcome,
            applied_snapshot,
            rejection,
            review,
        };
        application.validate_against_snapshot(self)?;
        Ok(application)
    }

    fn authority_expiry_sweep_decision(
        &self,
        request: &ManifoldAuthorityExpirySweepRequest,
        recorded_clock: &ManifoldClockSnapshot,
    ) -> AuthorityExpirySweepDecision {
        let expired_leases = self
            .active_leases
            .iter()
            .filter(|lease| lease_expired_at(lease, recorded_clock))
            .cloned()
            .collect::<Vec<_>>();
        let expired_stream_subscriptions = self
            .active_stream_subscriptions
            .iter()
            .filter(|subscription| stream_subscription_expired_at(subscription, recorded_clock))
            .cloned()
            .collect::<Vec<_>>();
        let expired_lease_count = expired_leases.len();
        let expired_subscription_count = expired_stream_subscriptions.len();

        if request.schema_id != authority_expiry_sweep_request_schema_id() {
            return AuthorityExpirySweepDecision::Rejected {
                rejection_code: "unsupported_schema".to_owned(),
                message: "authority expiry sweep request schema is not supported".to_owned(),
                retryable: false,
                expired_lease_count,
                expired_subscription_count,
            };
        }

        if request.expected_authority_revision != self.authority_revision {
            return AuthorityExpirySweepDecision::Rejected {
                rejection_code: "stale_revision".to_owned(),
                message:
                    "authority expiry sweep request expected authority revision does not match current revision"
                        .to_owned(),
                retryable: true,
                expired_lease_count,
                expired_subscription_count,
            };
        }

        if request.expected_registry_revision != self.stream_registry.registry_revision {
            return AuthorityExpirySweepDecision::Rejected {
                rejection_code: "registry_revision_mismatch".to_owned(),
                message:
                    "authority expiry sweep request expected registry revision does not match current registry"
                        .to_owned(),
                retryable: true,
                expired_lease_count,
                expired_subscription_count,
            };
        }

        if expired_leases.is_empty() && expired_stream_subscriptions.is_empty() {
            return AuthorityExpirySweepDecision::Rejected {
                rejection_code: "no_expired_state".to_owned(),
                message:
                    "authority expiry sweep found no expired active leases or stream subscriptions"
                        .to_owned(),
                retryable: true,
                expired_lease_count,
                expired_subscription_count,
            };
        }

        AuthorityExpirySweepDecision::Accepted {
            expired_leases,
            expired_stream_subscriptions,
        }
    }
}
