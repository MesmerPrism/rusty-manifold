use super::*;

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

/// Request to renew one accepted active control lease.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldControlLeaseRenewalRequest {
    /// Schema identifier for this request.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Request id.
    pub request_id: DottedId,
    /// Lease to renew.
    pub lease_id: DottedId,
    /// Holder expected to own the lease.
    pub holder_id: DottedId,
    /// Expected authority revision.
    pub expected_authority_revision: Revision,
    /// Lease scope expected by the requester.
    pub scope: DottedId,
    /// Requested lease duration from the review clock wall time.
    pub requested_ttl_ms: u64,
    /// Machine-readable reason for renewing the lease.
    pub renewal_reason: DottedId,
    /// Request timestamp in milliseconds in the holder's chosen clock domain.
    pub requested_at_ms: u64,
}

/// Rejected control lease renewal request result.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldControlLeaseRenewalRejection {
    /// Schema identifier for this renewal rejection.
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
    /// Active lease count observed before the renewal decision.
    pub active_lease_count: usize,
    /// Current expiration, when the referenced active lease was known.
    pub current_expires_at_ms: Option<u64>,
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

/// Control lease renewal authority audit event kind.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldControlLeaseRenewalAuthorityAuditEventKind {
    /// Authority accepted a lease renewal request.
    LeaseRenewed,
    /// Authority rejected a lease renewal request.
    LeaseRenewalRejected,
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

/// Control lease renewal authority review outcome.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldControlLeaseRenewalAuthorityReviewOutcome {
    /// Authority accepted the lease renewal request.
    LeaseRenewed,
    /// Authority rejected the lease renewal request.
    LeaseRenewalRejected,
}

/// Control lease renewal authority application outcome.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldControlLeaseRenewalAuthorityApplicationOutcome {
    /// Accepted lease renewal review was applied to the authority snapshot.
    LeaseRenewalApplied,
    /// Lease renewal review could not be applied to accepted authority state.
    LeaseRenewalApplicationRejected,
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

impl From<ManifoldControlLeaseRenewalAuthorityReviewOutcome>
    for ManifoldControlLeaseRenewalAuthorityAuditEventKind
{
    fn from(outcome: ManifoldControlLeaseRenewalAuthorityReviewOutcome) -> Self {
        match outcome {
            ManifoldControlLeaseRenewalAuthorityReviewOutcome::LeaseRenewed => Self::LeaseRenewed,
            ManifoldControlLeaseRenewalAuthorityReviewOutcome::LeaseRenewalRejected => {
                Self::LeaseRenewalRejected
            }
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

/// Audit event for one control lease renewal authority decision.
///
/// The event carries the lease renewal request plus exactly one renewed lease
/// or rejected result. It records enough local authority context for
/// deterministic validation without owning timers or runtime mutation.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldControlLeaseRenewalAuthorityAuditEvent {
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
    pub event_kind: ManifoldControlLeaseRenewalAuthorityAuditEventKind,
    /// Lease renewal request reviewed by authority.
    pub request: ManifoldControlLeaseRenewalRequest,
    /// Renewed lease. Present only for renewed events.
    pub renewed: Option<ManifoldControlLease>,
    /// Rejected lease renewal result. Present only for rejected events.
    pub rejection: Option<ManifoldControlLeaseRenewalRejection>,
    /// Clock snapshot recorded with the decision.
    pub recorded_clock: ManifoldClockSnapshot,
    /// Stable ids for fixtures, scorecards, or logs backing the event.
    pub evidence_refs: Vec<DottedId>,
}

/// Deterministic review result for one control lease renewal authority decision.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldControlLeaseRenewalAuthorityReview {
    /// Schema identifier for this review.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable review id.
    pub review_id: DottedId,
    /// Authority that reviewed the lease renewal request.
    pub authority_id: DottedId,
    /// Authority revision used by this review.
    pub authority_revision: Revision,
    /// Review outcome.
    pub outcome: ManifoldControlLeaseRenewalAuthorityReviewOutcome,
    /// Renewed lease. Present only for accepted renewal reviews.
    pub renewed: Option<ManifoldControlLease>,
    /// Rejected lease renewal result. Present only for rejected renewal reviews.
    pub rejection: Option<ManifoldControlLeaseRenewalRejection>,
    /// Audit event for the same lease renewal decision.
    pub audit_event: ManifoldControlLeaseRenewalAuthorityAuditEvent,
}

impl ManifoldControlLeaseRenewalAuthorityReview {
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
        if self.schema_id.as_str() != "rusty.manifold.authority.lease_renewal_review.v1" {
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
            ManifoldControlLeaseRenewalAuthorityReviewOutcome::LeaseRenewed => {
                if self.renewed.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.review_id.clone(),
                        "renewed".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
            ManifoldControlLeaseRenewalAuthorityReviewOutcome::LeaseRenewalRejected => {
                if self.renewed.is_some() || self.rejection.is_none() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.review_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
        }

        if self.renewed != self.audit_event.renewed || self.rejection != self.audit_event.rejection
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.audit_event.event_id.to_string(),
                ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
            ));
        }

        if ManifoldControlLeaseRenewalAuthorityAuditEventKind::from(self.outcome)
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

impl ManifoldControlLeaseRenewalAuthorityAuditEvent {
    /// Validates this event against the authority snapshot it claims to use.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the event is not a
    /// consistent lease renewal or rejection for the supplied snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str() != "rusty.manifold.authority.lease_renewal_audit_event.v1" {
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
            ManifoldControlLeaseRenewalAuthorityAuditEventKind::LeaseRenewed => {
                if self.renewed.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        "renewed".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
            ManifoldControlLeaseRenewalAuthorityAuditEventKind::LeaseRenewalRejected => {
                if self.renewed.is_some() || self.rejection.is_none() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
        }

        let expected_decision =
            snapshot.lease_renewal_authority_decision(&self.request, &self.recorded_clock);

        if let Some(renewed) = &self.renewed {
            let LeaseRenewalAuthorityDecision::Renewed(expected_lease) = &expected_decision else {
                let rejected_value = match &expected_decision {
                    LeaseRenewalAuthorityDecision::Rejected { rejection_code, .. } => {
                        rejection_code.clone()
                    }
                    LeaseRenewalAuthorityDecision::Renewed(_) => "renewed".to_owned(),
                };
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejected_value.clone(),
                    authority_error_kind_for_lease_renewal_rejection_code(&rejected_value),
                ));
            };

            if renewed != expected_lease {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    renewed.lease_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::LeaseMismatch,
                ));
            }
        }

        if let Some(rejection) = &self.rejection {
            let LeaseRenewalAuthorityDecision::Rejected {
                rejection_code,
                message,
                retryable,
                active_lease_count,
                current_expires_at_ms,
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

            if rejection.rejection_code.as_str() != rejection_code
                || rejection.message != *message
                || rejection.retryable != *retryable
                || rejection.active_lease_count != *active_lease_count
                || rejection.current_expires_at_ms != *current_expires_at_ms
            {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejection.rejection_code.to_string(),
                    authority_error_kind_for_lease_renewal_rejection_code(rejection_code),
                ));
            }
        }

        Ok(())
    }
}

/// Deterministic application result for one control lease renewal authority review.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldControlLeaseRenewalAuthorityApplication {
    /// Schema identifier for this application receipt.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable application id.
    pub application_id: DottedId,
    /// Authority that attempted the application.
    pub authority_id: DottedId,
    /// Authority revision before applying the review.
    pub from_authority_revision: Revision,
    /// Lease renewed by the reviewed request.
    pub lease_id: DottedId,
    /// Lease scope renewed.
    pub lease_scope: DottedId,
    /// Number of active leases before applying the review.
    pub from_active_lease_count: usize,
    /// Application outcome.
    pub outcome: ManifoldControlLeaseRenewalAuthorityApplicationOutcome,
    /// Next accepted authority snapshot. Present only for applied outcomes.
    pub applied_snapshot: Option<ManifoldAuthoritySnapshot>,
    /// Rejection. Present only for rejected application outcomes.
    pub rejection: Option<ManifoldAuthoritySnapshotApplicationRejection>,
    /// Review that was applied or rejected for application.
    pub review: ManifoldControlLeaseRenewalAuthorityReview,
}

impl ManifoldControlLeaseRenewalAuthorityApplication {
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
        if self.schema_id.as_str() != "rusty.manifold.authority.lease_renewal_application.v1" {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.schema_id.to_string(),
                ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
            ));
        }

        validate_derived_authority_id(
            &self.application_id,
            &self.application_id,
            control_lease_renewal_authority_application_id(&self.review.review_id),
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
            ManifoldControlLeaseRenewalAuthorityApplicationOutcome::LeaseRenewalApplied => {
                if self.applied_snapshot.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        "applied_snapshot".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                if self.review.outcome
                    != ManifoldControlLeaseRenewalAuthorityReviewOutcome::LeaseRenewed
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

                let renewed_lease = self.review.renewed.clone().ok_or_else(|| {
                    ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        "renewed".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    )
                })?;
                let mut expected_leases = snapshot.active_leases.clone();
                let Some(position) = expected_leases
                    .iter()
                    .position(|lease| lease.lease_id == renewed_lease.lease_id)
                else {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        renewed_lease.lease_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::UnknownLease,
                    ));
                };
                expected_leases[position] = renewed_lease;
                if applied.active_leases != expected_leases {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        self.lease_scope.to_string(),
                        ManifoldAuthorityValidationErrorKind::LeaseMismatch,
                    ));
                }

                applied.validate_authority_links()
            }
            ManifoldControlLeaseRenewalAuthorityApplicationOutcome::LeaseRenewalApplicationRejected => {
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
                    == ManifoldControlLeaseRenewalAuthorityReviewOutcome::LeaseRenewalRejected
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
enum LeaseAuthorityDecision {
    Accepted,
    Rejected {
        rejection_code: &'static str,
        message: String,
        retryable: bool,
        conflicting_lease_id: Option<DottedId>,
    },
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

#[derive(Clone, Debug, Eq, PartialEq)]
enum LeaseRenewalAuthorityDecision {
    Renewed(ManifoldControlLease),
    Rejected {
        rejection_code: String,
        message: String,
        retryable: bool,
        active_lease_count: usize,
        current_expires_at_ms: Option<u64>,
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

    /// Deterministically reviews one active control lease renewal request.
    ///
    /// The review is source-only: it verifies renewal preconditions against
    /// accepted active lease state and produces a renewed lease candidate or
    /// machine-readable rejection. It does not start timers, execute commands,
    /// contact a host, or mutate accepted authority state.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the authority snapshot
    /// itself is invalid, the review clock is inconsistent, or evidence refs are empty.
    pub fn review_control_lease_renewal(
        &self,
        request: ManifoldControlLeaseRenewalRequest,
        recorded_clock: ManifoldClockSnapshot,
        evidence_refs: Vec<DottedId>,
    ) -> Result<ManifoldControlLeaseRenewalAuthorityReview, ManifoldAuthorityValidationError> {
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

        let active_lease_count = self.active_leases.len();
        let decision = self.lease_renewal_authority_decision(&request, &recorded_clock);
        let (outcome, renewed, rejection) = match decision {
            LeaseRenewalAuthorityDecision::Renewed(lease) => (
                ManifoldControlLeaseRenewalAuthorityReviewOutcome::LeaseRenewed,
                Some(lease),
                None,
            ),
            LeaseRenewalAuthorityDecision::Rejected {
                rejection_code,
                message,
                retryable,
                active_lease_count,
                current_expires_at_ms,
            } => (
                ManifoldControlLeaseRenewalAuthorityReviewOutcome::LeaseRenewalRejected,
                None,
                Some(ManifoldControlLeaseRenewalRejection {
                    schema_id: control_lease_renewal_rejection_schema_id(),
                    request_id: request.request_id.clone(),
                    rejection_code: DottedId::new(rejection_code)
                        .expect("rejection code is a valid dotted id"),
                    message,
                    retryable,
                    current_revision: self.authority_revision,
                    active_lease_count,
                    current_expires_at_ms,
                }),
            ),
        };

        let audit_event = ManifoldControlLeaseRenewalAuthorityAuditEvent {
            schema_id: control_lease_renewal_authority_audit_event_schema_id(),
            event_id: control_lease_renewal_authority_audit_event_id(&request.request_id, outcome),
            authority_id: self.authority_id.clone(),
            prior_authority_revision: self.authority_revision,
            active_lease_count,
            event_kind: outcome.into(),
            request,
            renewed: renewed.clone(),
            rejection: rejection.clone(),
            recorded_clock,
            evidence_refs,
        };

        let review = ManifoldControlLeaseRenewalAuthorityReview {
            schema_id: control_lease_renewal_authority_review_schema_id(),
            review_id: control_lease_renewal_authority_review_id(&audit_event.request.request_id),
            authority_id: self.authority_id.clone(),
            authority_revision: self.authority_revision,
            outcome,
            renewed,
            rejection,
            audit_event,
        };
        review.validate_against_snapshot(self)?;
        Ok(review)
    }

    /// Deterministically applies one control lease renewal authority review.
    ///
    /// Accepted renewal reviews produce a new `ManifoldAuthoritySnapshot` with
    /// the authority revision advanced by one and the reviewed lease replaced
    /// by its renewed candidate. Rejected reviews produce a machine-readable
    /// application rejection and leave accepted state unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when this authority snapshot
    /// itself is invalid.
    pub fn apply_control_lease_renewal_authority_review(
        &self,
        review: ManifoldControlLeaseRenewalAuthorityReview,
    ) -> Result<ManifoldControlLeaseRenewalAuthorityApplication, ManifoldAuthorityValidationError>
    {
        self.validate_authority_links()?;

        let application_id = control_lease_renewal_authority_application_id(&review.review_id);
        let from_authority_revision = self.authority_revision;
        let lease_id = review.audit_event.request.lease_id.clone();
        let lease_scope = review.audit_event.request.scope.clone();
        let from_active_lease_count = self.active_leases.len();

        let (outcome, applied_snapshot, rejection) = match review.validate_against_snapshot(self) {
            Err(error) => (
                ManifoldControlLeaseRenewalAuthorityApplicationOutcome::LeaseRenewalApplicationRejected,
                None,
                Some(ManifoldAuthoritySnapshotApplicationRejection {
                    schema_id: authority_snapshot_application_rejection_schema_id(),
                    application_id: application_id.clone(),
                    rejection_code: DottedId::new(error.rejection_code())
                        .expect("authority rejection code is a valid dotted id"),
                    message: format!(
                        "control lease renewal review does not match authority snapshot: {error}"
                    ),
                    retryable: authority_application_validation_retryable(error.kind()),
                    current_authority_revision: self.authority_revision,
                }),
            ),
            Ok(())
                if review.outcome
                    == ManifoldControlLeaseRenewalAuthorityReviewOutcome::LeaseRenewalRejected =>
            {
                (
                    ManifoldControlLeaseRenewalAuthorityApplicationOutcome::LeaseRenewalApplicationRejected,
                    None,
                    Some(ManifoldAuthoritySnapshotApplicationRejection {
                        schema_id: authority_snapshot_application_rejection_schema_id(),
                        application_id: application_id.clone(),
                        rejection_code: DottedId::new("review_rejected")
                            .expect("rejection code literal is valid"),
                        message: "control lease renewal review did not renew a lease".to_owned(),
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
                let renewed_lease = review.renewed.clone().ok_or_else(|| {
                    ManifoldAuthorityValidationError::new(
                        review.review_id.clone(),
                        "renewed".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    )
                })?;
                let mut next_snapshot = self.clone();
                next_snapshot.authority_revision = next_authority_revision;
                let Some(position) = next_snapshot
                    .active_leases
                    .iter()
                    .position(|lease| lease.lease_id == renewed_lease.lease_id)
                else {
                    return Err(ManifoldAuthorityValidationError::new(
                        review.review_id.clone(),
                        renewed_lease.lease_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::UnknownLease,
                    ));
                };
                next_snapshot.active_leases[position] = renewed_lease;
                next_snapshot.validate_authority_links()?;
                (
                    ManifoldControlLeaseRenewalAuthorityApplicationOutcome::LeaseRenewalApplied,
                    Some(next_snapshot),
                    None,
                )
            }
        };

        let application = ManifoldControlLeaseRenewalAuthorityApplication {
            schema_id: control_lease_renewal_authority_application_schema_id(),
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

    fn lease_renewal_authority_decision(
        &self,
        request: &ManifoldControlLeaseRenewalRequest,
        recorded_clock: &ManifoldClockSnapshot,
    ) -> LeaseRenewalAuthorityDecision {
        if request.schema_id != control_lease_renewal_request_schema_id() {
            return LeaseRenewalAuthorityDecision::Rejected {
                rejection_code: "unsupported_schema".to_owned(),
                message: "control lease renewal request schema is not supported".to_owned(),
                retryable: false,
                active_lease_count: self.active_leases.len(),
                current_expires_at_ms: None,
            };
        }

        if request.expected_authority_revision != self.authority_revision {
            return LeaseRenewalAuthorityDecision::Rejected {
                rejection_code: "stale_revision".to_owned(),
                message:
                    "control lease renewal request expected authority revision does not match current revision"
                        .to_owned(),
                retryable: true,
                active_lease_count: self.active_leases.len(),
                current_expires_at_ms: None,
            };
        }

        if request.requested_ttl_ms == 0 {
            return LeaseRenewalAuthorityDecision::Rejected {
                rejection_code: "invalid_ttl".to_owned(),
                message: "control lease renewal request ttl must be greater than zero".to_owned(),
                retryable: false,
                active_lease_count: self.active_leases.len(),
                current_expires_at_ms: None,
            };
        }

        let Some(lease) = self.active_lease(&request.lease_id) else {
            return LeaseRenewalAuthorityDecision::Rejected {
                rejection_code: "unknown_lease".to_owned(),
                message: "control lease renewal request references an unknown active lease"
                    .to_owned(),
                retryable: true,
                active_lease_count: self.active_leases.len(),
                current_expires_at_ms: None,
            };
        };

        if lease.state != LeaseState::Active {
            return LeaseRenewalAuthorityDecision::Rejected {
                rejection_code: "inactive_lease".to_owned(),
                message: "control lease renewal request references a non-active lease".to_owned(),
                retryable: true,
                active_lease_count: self.active_leases.len(),
                current_expires_at_ms: Some(lease.expires_at_ms),
            };
        }

        if lease_expired_at(lease, recorded_clock) {
            return LeaseRenewalAuthorityDecision::Rejected {
                rejection_code: "expired_lease".to_owned(),
                message: "control lease renewal request references an expired lease".to_owned(),
                retryable: true,
                active_lease_count: self.active_leases.len(),
                current_expires_at_ms: Some(lease.expires_at_ms),
            };
        }

        if lease.holder_id != request.holder_id {
            return LeaseRenewalAuthorityDecision::Rejected {
                rejection_code: "lease_holder_mismatch".to_owned(),
                message: "control lease renewal request holder does not own the lease".to_owned(),
                retryable: false,
                active_lease_count: self.active_leases.len(),
                current_expires_at_ms: Some(lease.expires_at_ms),
            };
        }

        if lease.scope != request.scope {
            return LeaseRenewalAuthorityDecision::Rejected {
                rejection_code: "lease_scope_mismatch".to_owned(),
                message: "control lease renewal request scope does not match the active lease"
                    .to_owned(),
                retryable: true,
                active_lease_count: self.active_leases.len(),
                current_expires_at_ms: Some(lease.expires_at_ms),
            };
        }

        let renewed_expires_at_ms =
            wall_unix_ms_u64(recorded_clock).saturating_add(request.requested_ttl_ms);
        if renewed_expires_at_ms <= lease.expires_at_ms {
            return LeaseRenewalAuthorityDecision::Rejected {
                rejection_code: "non_extending_renewal".to_owned(),
                message: "control lease renewal request does not extend the active lease"
                    .to_owned(),
                retryable: true,
                active_lease_count: self.active_leases.len(),
                current_expires_at_ms: Some(lease.expires_at_ms),
            };
        }

        LeaseRenewalAuthorityDecision::Renewed(ManifoldControlLease {
            schema_id: control_lease_schema_id(),
            lease_id: lease.lease_id.clone(),
            holder_id: lease.holder_id.clone(),
            scope: lease.scope.clone(),
            state: LeaseState::Active,
            granted_revision: self.authority_revision,
            expires_at_ms: renewed_expires_at_ms,
            required_capability: lease.required_capability.clone(),
        })
    }
}
