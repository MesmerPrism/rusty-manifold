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
