use super::*;

/// Authority request to terminally revoke one accepted control lease.
///
/// Unlike holder release, revocation is bound to the current Manifold
/// authority identity and does not require or impersonate the lease holder.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldControlLeaseRevocationRequest {
    /// Schema identifier for this request.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Idempotency identity retained by the authority owner.
    pub request_id: DottedId,
    /// Authority that is requesting revocation.
    pub authority_id: DottedId,
    /// Lease to revoke.
    pub lease_id: DottedId,
    /// Expected authority revision.
    pub expected_authority_revision: Revision,
    /// Exact scope expected by the authority.
    pub scope: DottedId,
    /// Machine-readable reason for revocation.
    pub revocation_reason: DottedId,
    /// Request timestamp in the requester's chosen clock domain.
    pub requested_at_ms: u64,
}

/// Rejected control-lease revocation request.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldControlLeaseRevocationRejection {
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
    /// Current authority revision.
    pub current_revision: Revision,
    /// Active lease count observed before the decision.
    pub active_lease_count: usize,
}

/// Durable terminal evidence for one applied control-lease revocation.
///
/// The tombstone is carried by the application receipt rather than inserted
/// into the v1 authority snapshot. Durable authority owners must retain it
/// with the accepted transition so the revoked identity cannot be reconstructed
/// as a current lease from older issuance evidence.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldControlLeaseRevocationTombstone {
    /// Schema identifier for this tombstone.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable tombstone identity derived from the revocation request.
    pub tombstone_id: DottedId,
    /// Authority that applied revocation.
    pub authority_id: DottedId,
    /// Exact lease that was terminally revoked.
    pub revoked_lease: ManifoldControlLease,
    /// Revocation request that produced this tombstone.
    pub revocation_request_id: DottedId,
    /// Authority revision immediately before revocation.
    pub prior_authority_revision: Revision,
    /// Authority revision at which revocation became accepted state.
    pub revoked_authority_revision: Revision,
    /// Machine-readable reason retained for audit and policy consumers.
    pub revocation_reason: DottedId,
    /// Trusted authority clock recorded with the revocation decision.
    pub recorded_clock: ManifoldClockSnapshot,
}

/// Control-lease revocation authority audit event kind.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldControlLeaseRevocationAuthorityAuditEventKind {
    /// Authority accepted a lease revocation request.
    LeaseRevoked,
    /// Authority rejected a lease revocation request.
    LeaseRevocationRejected,
}

/// Control-lease revocation authority review outcome.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldControlLeaseRevocationAuthorityReviewOutcome {
    /// Authority accepted the lease revocation request.
    LeaseRevoked,
    /// Authority rejected the lease revocation request.
    LeaseRevocationRejected,
}

/// Control-lease revocation authority application outcome.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldControlLeaseRevocationAuthorityApplicationOutcome {
    /// Accepted lease revocation was applied and a terminal tombstone emitted.
    LeaseRevocationApplied,
    /// Lease revocation could not be applied to accepted authority state.
    LeaseRevocationApplicationRejected,
}

impl From<ManifoldControlLeaseRevocationAuthorityReviewOutcome>
    for ManifoldControlLeaseRevocationAuthorityAuditEventKind
{
    fn from(outcome: ManifoldControlLeaseRevocationAuthorityReviewOutcome) -> Self {
        match outcome {
            ManifoldControlLeaseRevocationAuthorityReviewOutcome::LeaseRevoked => {
                Self::LeaseRevoked
            }
            ManifoldControlLeaseRevocationAuthorityReviewOutcome::LeaseRevocationRejected => {
                Self::LeaseRevocationRejected
            }
        }
    }
}

/// Audit event for one control-lease revocation decision.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldControlLeaseRevocationAuthorityAuditEvent {
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
    pub event_kind: ManifoldControlLeaseRevocationAuthorityAuditEventKind,
    /// Revocation request reviewed by authority.
    pub request: ManifoldControlLeaseRevocationRequest,
    /// Lease selected for revocation. Present only for accepted reviews.
    pub revoked: Option<ManifoldControlLease>,
    /// Rejection. Present only for rejected reviews.
    pub rejection: Option<ManifoldControlLeaseRevocationRejection>,
    /// Trusted clock snapshot recorded with the decision.
    pub recorded_clock: ManifoldClockSnapshot,
    /// Stable ids for evidence backing the decision.
    pub evidence_refs: Vec<DottedId>,
}

/// Deterministic review of one control-lease revocation request.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldControlLeaseRevocationAuthorityReview {
    /// Schema identifier for this review.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable review id.
    pub review_id: DottedId,
    /// Authority that reviewed the request.
    pub authority_id: DottedId,
    /// Authority revision used by the review.
    pub authority_revision: Revision,
    /// Review outcome.
    pub outcome: ManifoldControlLeaseRevocationAuthorityReviewOutcome,
    /// Lease selected for revocation.
    pub revoked: Option<ManifoldControlLease>,
    /// Rejected revocation result.
    pub rejection: Option<ManifoldControlLeaseRevocationRejection>,
    /// Audit event for the same decision.
    pub audit_event: ManifoldControlLeaseRevocationAuthorityAuditEvent,
}

/// Deterministic application of one control-lease revocation review.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldControlLeaseRevocationAuthorityApplication {
    /// Schema identifier for this application receipt.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable application id.
    pub application_id: DottedId,
    /// Authority that attempted application.
    pub authority_id: DottedId,
    /// Authority revision before applying the review.
    pub from_authority_revision: Revision,
    /// Lease targeted by the reviewed request.
    pub lease_id: DottedId,
    /// Exact lease scope targeted by the reviewed request.
    pub lease_scope: DottedId,
    /// Active lease count before applying the review.
    pub from_active_lease_count: usize,
    /// Application outcome.
    pub outcome: ManifoldControlLeaseRevocationAuthorityApplicationOutcome,
    /// Terminal tombstone emitted only when revocation applied.
    pub tombstone: Option<ManifoldControlLeaseRevocationTombstone>,
    /// Next accepted authority snapshot, present only when applied.
    pub applied_snapshot: Option<ManifoldAuthoritySnapshot>,
    /// Application rejection, present only when not applied.
    pub rejection: Option<ManifoldAuthoritySnapshotApplicationRejection>,
    /// Exact review applied or rejected.
    pub review: ManifoldControlLeaseRevocationAuthorityReview,
}

impl ManifoldControlLeaseRevocationTombstone {
    /// Validates this terminal record against its accepted revocation review.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when any identity,
    /// revision, reason, lease, or clock field diverges from the review.
    pub fn validate_against_review(
        &self,
        review: &ManifoldControlLeaseRevocationAuthorityReview,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        let Some(revoked_lease) = review.revoked.as_ref() else {
            return Err(ManifoldAuthorityValidationError::new(
                self.tombstone_id.clone(),
                "revoked".to_owned(),
                ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
            ));
        };
        let Some(revoked_authority_revision) = review.authority_revision.next() else {
            return Err(ManifoldAuthorityValidationError::new(
                self.tombstone_id.clone(),
                review.authority_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::AcceptanceRevisionMismatch,
            ));
        };
        let request = &review.audit_event.request;
        if self.schema_id != control_lease_revocation_tombstone_schema_id() {
            return Err(ManifoldAuthorityValidationError::new(
                self.tombstone_id.clone(),
                self.schema_id.to_string(),
                ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
            ));
        }
        validate_derived_authority_id(
            &self.tombstone_id,
            &self.tombstone_id,
            control_lease_revocation_tombstone_id(&request.request_id),
        )?;
        if self.authority_id != review.authority_id
            || self.revoked_lease != *revoked_lease
            || self.revocation_request_id != request.request_id
            || self.prior_authority_revision != review.authority_revision
            || self.revoked_authority_revision != revoked_authority_revision
            || self.revocation_reason != request.revocation_reason
            || self.recorded_clock != review.audit_event.recorded_clock
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.tombstone_id.clone(),
                self.revoked_lease.lease_id.to_string(),
                ManifoldAuthorityValidationErrorKind::LeaseMismatch,
            ));
        }
        Ok(())
    }
}

impl ManifoldControlLeaseRevocationAuthorityAuditEvent {
    /// Validates this audit event against the authority snapshot it reviewed.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the event is not the
    /// deterministic revocation decision for the supplied snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id != control_lease_revocation_authority_audit_event_schema_id() {
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
        let outcome = match self.event_kind {
            ManifoldControlLeaseRevocationAuthorityAuditEventKind::LeaseRevoked => {
                ManifoldControlLeaseRevocationAuthorityReviewOutcome::LeaseRevoked
            }
            ManifoldControlLeaseRevocationAuthorityAuditEventKind::LeaseRevocationRejected => {
                ManifoldControlLeaseRevocationAuthorityReviewOutcome::LeaseRevocationRejected
            }
        };
        validate_derived_authority_id(
            &self.event_id,
            &self.event_id,
            control_lease_revocation_authority_audit_event_id(&self.request.request_id, outcome),
        )?;
        let expected = snapshot.build_control_lease_revocation_review(
            self.request.clone(),
            self.recorded_clock.clone(),
            self.evidence_refs.clone(),
        )?;
        if expected.audit_event == *self {
            Ok(())
        } else {
            let rejected_value = self
                .rejection
                .as_ref()
                .map_or("revoked", |rejection| rejection.rejection_code.as_str());
            Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                rejected_value.to_owned(),
                authority_error_kind_for_lease_revocation_rejection_code(rejected_value),
            ))
        }
    }
}

impl ManifoldControlLeaseRevocationAuthorityReview {
    /// Validates this review against the supplied authority snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when review or audit
    /// lineage differs from the deterministic authority decision.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id != control_lease_revocation_authority_review_schema_id() {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.schema_id.to_string(),
                ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
            ));
        }
        validate_derived_authority_id(
            &self.review_id,
            &self.review_id,
            control_lease_revocation_authority_review_id(&self.audit_event.request.request_id),
        )?;
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
        self.audit_event.validate_against_snapshot(snapshot)?;
        let expected = snapshot.build_control_lease_revocation_review(
            self.audit_event.request.clone(),
            self.audit_event.recorded_clock.clone(),
            self.audit_event.evidence_refs.clone(),
        )?;
        if expected == *self {
            Ok(())
        } else {
            Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.audit_event.request.lease_id.to_string(),
                ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
            ))
        }
    }
}

impl ManifoldControlLeaseRevocationAuthorityApplication {
    /// Validates this application against its exact prior authority snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when application,
    /// tombstone, review, or next-state lineage differs from the deterministic
    /// revocation transition.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id != control_lease_revocation_authority_application_schema_id() {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.schema_id.to_string(),
                ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
            ));
        }
        validate_derived_authority_id(
            &self.application_id,
            &self.application_id,
            control_lease_revocation_authority_application_id(&self.review.review_id),
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
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.lease_id.to_string(),
                ManifoldAuthorityValidationErrorKind::LeaseMismatch,
            ));
        }
        self.review.validate_against_snapshot(snapshot)?;
        match self.outcome {
            ManifoldControlLeaseRevocationAuthorityApplicationOutcome::LeaseRevocationApplied => {
                if self.applied_snapshot.is_none()
                    || self.tombstone.is_none()
                    || self.rejection.is_some()
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        "applied_snapshot".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
                self.tombstone
                    .as_ref()
                    .expect("tombstone presence checked")
                    .validate_against_review(&self.review)?;
            }
            ManifoldControlLeaseRevocationAuthorityApplicationOutcome::LeaseRevocationApplicationRejected => {
                if self.applied_snapshot.is_some()
                    || self.tombstone.is_some()
                    || self.rejection.is_none()
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
        }
        let expected = snapshot.build_control_lease_revocation_application(self.review.clone())?;
        if expected == *self {
            Ok(())
        } else {
            Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.lease_id.to_string(),
                ManifoldAuthorityValidationErrorKind::LeaseMismatch,
            ))
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum LeaseRevocationAuthorityDecision {
    Revoked(ManifoldControlLease),
    Rejected {
        rejection_code: String,
        message: String,
        retryable: bool,
    },
}

impl ManifoldAuthoritySnapshot {
    /// Deterministically reviews one authority-owned lease revocation.
    ///
    /// Revocation deliberately accepts an expired lease that remains in the
    /// accepted active set: the terminal tombstone is stronger evidence than
    /// silently routing that security decision through ordinary expiry.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the snapshot, clock,
    /// evidence, or derived decision lineage is invalid.
    pub fn review_control_lease_revocation(
        &self,
        request: ManifoldControlLeaseRevocationRequest,
        recorded_clock: ManifoldClockSnapshot,
        evidence_refs: Vec<DottedId>,
    ) -> Result<ManifoldControlLeaseRevocationAuthorityReview, ManifoldAuthorityValidationError>
    {
        let review =
            self.build_control_lease_revocation_review(request, recorded_clock, evidence_refs)?;
        review.validate_against_snapshot(self)?;
        Ok(review)
    }

    /// Applies one accepted lease revocation and emits its terminal tombstone.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when review or application
    /// lineage does not match the exact prior snapshot.
    pub fn apply_control_lease_revocation_authority_review(
        &self,
        review: ManifoldControlLeaseRevocationAuthorityReview,
    ) -> Result<ManifoldControlLeaseRevocationAuthorityApplication, ManifoldAuthorityValidationError>
    {
        let application = self.build_control_lease_revocation_application(review)?;
        application.validate_against_snapshot(self)?;
        Ok(application)
    }

    fn build_control_lease_revocation_review(
        &self,
        request: ManifoldControlLeaseRevocationRequest,
        recorded_clock: ManifoldClockSnapshot,
        evidence_refs: Vec<DottedId>,
    ) -> Result<ManifoldControlLeaseRevocationAuthorityReview, ManifoldAuthorityValidationError>
    {
        self.validate_authority_links()?;
        if recorded_clock.schema_id.as_str() != "rusty.manifold.clock.snapshot.v1"
            || recorded_clock.clock_domain != self.clock_snapshot.clock_domain
            || recorded_clock.clock_epoch_id != self.clock_snapshot.clock_epoch_id
            || recorded_clock.sequence < self.clock_snapshot.sequence
            || recorded_clock.monotonic_elapsed_ns < self.clock_snapshot.monotonic_elapsed_ns
            || recorded_clock.wall_clock_adjustment_count
                < self.clock_snapshot.wall_clock_adjustment_count
            || (recorded_clock.sequence == self.clock_snapshot.sequence
                && recorded_clock != self.clock_snapshot)
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
        let (outcome, revoked, rejection) = match self.control_lease_revocation_decision(&request) {
            LeaseRevocationAuthorityDecision::Revoked(lease) => (
                ManifoldControlLeaseRevocationAuthorityReviewOutcome::LeaseRevoked,
                Some(lease),
                None,
            ),
            LeaseRevocationAuthorityDecision::Rejected {
                rejection_code,
                message,
                retryable,
            } => (
                ManifoldControlLeaseRevocationAuthorityReviewOutcome::LeaseRevocationRejected,
                None,
                Some(ManifoldControlLeaseRevocationRejection {
                    schema_id: control_lease_revocation_rejection_schema_id(),
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
        let audit_event = ManifoldControlLeaseRevocationAuthorityAuditEvent {
            schema_id: control_lease_revocation_authority_audit_event_schema_id(),
            event_id: control_lease_revocation_authority_audit_event_id(
                &request.request_id,
                outcome,
            ),
            authority_id: self.authority_id.clone(),
            prior_authority_revision: self.authority_revision,
            active_lease_count,
            event_kind: outcome.into(),
            request,
            revoked: revoked.clone(),
            rejection: rejection.clone(),
            recorded_clock,
            evidence_refs,
        };
        Ok(ManifoldControlLeaseRevocationAuthorityReview {
            schema_id: control_lease_revocation_authority_review_schema_id(),
            review_id: control_lease_revocation_authority_review_id(
                &audit_event.request.request_id,
            ),
            authority_id: self.authority_id.clone(),
            authority_revision: self.authority_revision,
            outcome,
            revoked,
            rejection,
            audit_event,
        })
    }

    fn build_control_lease_revocation_application(
        &self,
        review: ManifoldControlLeaseRevocationAuthorityReview,
    ) -> Result<ManifoldControlLeaseRevocationAuthorityApplication, ManifoldAuthorityValidationError>
    {
        self.validate_authority_links()?;
        let application_id = control_lease_revocation_authority_application_id(&review.review_id);
        let lease_id = review.audit_event.request.lease_id.clone();
        let lease_scope = review.audit_event.request.scope.clone();
        let from_active_lease_count = self.active_leases.len();
        let (outcome, tombstone, applied_snapshot, rejection) =
            match review.validate_against_snapshot(self) {
                Err(error) => (
                    ManifoldControlLeaseRevocationAuthorityApplicationOutcome::LeaseRevocationApplicationRejected,
                    None,
                    None,
                    Some(ManifoldAuthoritySnapshotApplicationRejection {
                        schema_id: authority_snapshot_application_rejection_schema_id(),
                        application_id: application_id.clone(),
                        rejection_code: DottedId::new(error.rejection_code())
                            .expect("authority rejection code is a valid dotted id"),
                        message: format!(
                            "control lease revocation review does not match authority snapshot: {error}"
                        ),
                        retryable: authority_application_validation_retryable(error.kind()),
                        current_authority_revision: self.authority_revision,
                    }),
                ),
                Ok(())
                    if review.outcome
                        == ManifoldControlLeaseRevocationAuthorityReviewOutcome::LeaseRevocationRejected =>
                {
                    (
                        ManifoldControlLeaseRevocationAuthorityApplicationOutcome::LeaseRevocationApplicationRejected,
                        None,
                        None,
                        Some(ManifoldAuthoritySnapshotApplicationRejection {
                            schema_id: authority_snapshot_application_rejection_schema_id(),
                            application_id: application_id.clone(),
                            rejection_code: DottedId::new("review_rejected")
                                .expect("rejection code literal is valid"),
                            message: "control lease revocation review did not revoke a lease"
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
                    let revoked_lease = review.revoked.clone().ok_or_else(|| {
                        ManifoldAuthorityValidationError::new(
                            review.review_id.clone(),
                            "revoked".to_owned(),
                            ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                        )
                    })?;
                    let mut next_snapshot = self.clone();
                    next_snapshot.schema_id =
                        SchemaId::new("rusty.manifold.authority.snapshot.v2")
                            .expect("snapshot v2 schema literal is valid");
                    next_snapshot.authority_revision = next_authority_revision;
                    let Some(position) = next_snapshot
                        .active_leases
                        .iter()
                        .position(|lease| lease.lease_id == revoked_lease.lease_id)
                    else {
                        return Err(ManifoldAuthorityValidationError::new(
                            review.review_id.clone(),
                            revoked_lease.lease_id.to_string(),
                            ManifoldAuthorityValidationErrorKind::UnknownLease,
                        ));
                    };
                    next_snapshot.active_leases.remove(position);
                    next_snapshot.validate_authority_links()?;
                    let tombstone = ManifoldControlLeaseRevocationTombstone {
                        schema_id: control_lease_revocation_tombstone_schema_id(),
                        tombstone_id: control_lease_revocation_tombstone_id(
                            &review.audit_event.request.request_id,
                        ),
                        authority_id: self.authority_id.clone(),
                        revoked_lease,
                        revocation_request_id: review.audit_event.request.request_id.clone(),
                        prior_authority_revision: self.authority_revision,
                        revoked_authority_revision: next_authority_revision,
                        revocation_reason: review.audit_event.request.revocation_reason.clone(),
                        recorded_clock: review.audit_event.recorded_clock.clone(),
                    };
                    next_snapshot
                        .revoked_control_lease_tombstones
                        .push(tombstone.clone());
                    next_snapshot.revoked_control_lease_tombstones.sort_by(
                        |left, right| {
                            left.revoked_lease
                                .lease_id
                                .cmp(&right.revoked_lease.lease_id)
                        },
                    );
                    next_snapshot.validate_authority_links()?;
                    (
                        ManifoldControlLeaseRevocationAuthorityApplicationOutcome::LeaseRevocationApplied,
                        Some(tombstone),
                        Some(next_snapshot),
                        None,
                    )
                }
            };
        Ok(ManifoldControlLeaseRevocationAuthorityApplication {
            schema_id: control_lease_revocation_authority_application_schema_id(),
            application_id,
            authority_id: self.authority_id.clone(),
            from_authority_revision: self.authority_revision,
            lease_id,
            lease_scope,
            from_active_lease_count,
            outcome,
            tombstone,
            applied_snapshot,
            rejection,
            review,
        })
    }

    fn control_lease_revocation_decision(
        &self,
        request: &ManifoldControlLeaseRevocationRequest,
    ) -> LeaseRevocationAuthorityDecision {
        let rejected = |rejection_code: &str, message: &str, retryable| {
            LeaseRevocationAuthorityDecision::Rejected {
                rejection_code: rejection_code.to_owned(),
                message: message.to_owned(),
                retryable,
            }
        };
        if request.schema_id != control_lease_revocation_request_schema_id() {
            return rejected(
                "unsupported_schema",
                "control lease revocation request schema is not supported",
                false,
            );
        }
        if request.authority_id != self.authority_id {
            return rejected(
                "authority_id_mismatch",
                "control lease revocation request authority does not own this snapshot",
                false,
            );
        }
        if request.expected_authority_revision != self.authority_revision {
            return rejected(
                "stale_revision",
                "control lease revocation request expected revision does not match current authority",
                true,
            );
        }
        let Some(lease) = self.active_lease(&request.lease_id) else {
            return rejected(
                "unknown_lease",
                "control lease revocation request references an unknown active lease",
                true,
            );
        };
        if lease.state != LeaseState::Active {
            return rejected(
                "inactive_lease",
                "control lease revocation request references a non-active lease",
                true,
            );
        }
        if lease.scope != request.scope {
            return rejected(
                "lease_scope_mismatch",
                "control lease revocation request scope does not match the active lease",
                true,
            );
        }
        LeaseRevocationAuthorityDecision::Revoked(lease.clone())
    }
}
