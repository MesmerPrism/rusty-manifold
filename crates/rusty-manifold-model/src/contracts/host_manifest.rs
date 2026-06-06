use super::*;

/// Host advertisement manifest.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldHostManifest {
    /// Schema identifier for this manifest.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Host id.
    pub host_id: DottedId,
    /// Authority role advertised by this host.
    pub authority_role: AuthorityRole,
    /// Generic host category, when advertised.
    #[cfg_attr(feature = "serde", serde(default))]
    pub host_category: Option<DottedId>,
    /// Host clock domain.
    pub clock_domain: DottedId,
    /// Advertised endpoints.
    pub endpoints: Vec<EndpointDescriptor>,
    /// Advertised capabilities.
    pub capabilities: Vec<DottedId>,
    /// Supported backend families.
    #[cfg_attr(feature = "serde", serde(default))]
    pub supported_backends: Vec<DottedId>,
    /// Permissions or operator grants available to this host.
    #[cfg_attr(feature = "serde", serde(default))]
    pub permissions: Vec<DottedId>,
    /// Lifecycle limits that deployment selection must account for.
    #[cfg_attr(feature = "serde", serde(default))]
    pub lifecycle_limits: Vec<DottedId>,
    /// Missing requirements that prevent selected modules or backends.
    #[cfg_attr(feature = "serde", serde(default))]
    pub missing_requirements: Vec<DottedId>,
}

impl ManifoldHostManifest {
    /// Validates endpoint visibility and security pairings.
    ///
    /// # Errors
    ///
    /// Returns [`EndpointSecurityError`] when any endpoint advertises a
    /// visibility/security pairing that is not accepted by Manifold policy.
    pub fn validate_endpoint_security(&self) -> Result<(), EndpointSecurityError> {
        for endpoint in &self.endpoints {
            endpoint.validate_security()?;
        }

        Ok(())
    }
}

/// Request to change the accepted host manifest under Manifold authority.
///
/// The request proposes contract state only. It does not start host services,
/// open endpoints, probe platform permissions, or execute adapter code.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldHostManifestChangeRequest {
    /// Schema identifier for this request.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable request id.
    pub request_id: DottedId,
    /// Holder requesting the host manifest change.
    pub holder_id: DottedId,
    /// Authority revision the requester observed.
    pub expected_authority_revision: Revision,
    /// Lease id proving authority to change the host manifest.
    pub lease_id: Option<DottedId>,
    /// Capability required for host manifest mutation.
    pub required_capability: DottedId,
    /// Proposed accepted host manifest after the change.
    pub proposed_manifest: ManifoldHostManifest,
}

/// Rejection for a host manifest change request.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldHostManifestRejection {
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
}

/// Audit event for one host manifest authority decision.
///
/// The event carries the host manifest change request plus exactly one accepted
/// manifest or rejected result. It records enough authority context for
/// deterministic validation without probing or mutating a host.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldHostManifestAuthorityAuditEvent {
    /// Schema identifier for this audit event.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable event id.
    pub event_id: DottedId,
    /// Authority that made the decision.
    pub authority_id: DottedId,
    /// Authority revision observed before the decision.
    pub prior_authority_revision: Revision,
    /// Host whose manifest was reviewed.
    pub host_id: DottedId,
    /// Event kind.
    pub event_kind: ManifoldHostManifestAuthorityAuditEventKind,
    /// Host manifest change request reviewed by authority.
    pub request: ManifoldHostManifestChangeRequest,
    /// Accepted host manifest. Present only for accepted events.
    pub accepted: Option<ManifoldHostManifest>,
    /// Rejected host manifest result. Present only for rejected events.
    pub rejection: Option<ManifoldHostManifestRejection>,
    /// Lease recorded with the decision, when a lease was presented.
    pub lease: Option<ManifoldControlLease>,
    /// Clock snapshot recorded with the decision.
    pub recorded_clock: ManifoldClockSnapshot,
    /// Stable ids for fixtures, scorecards, or logs backing the event.
    pub evidence_refs: Vec<DottedId>,
}

/// Deterministic review result for one host manifest authority decision.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldHostManifestAuthorityReview {
    /// Schema identifier for this review.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable review id.
    pub review_id: DottedId,
    /// Authority that reviewed the host manifest change.
    pub authority_id: DottedId,
    /// Authority revision used by this review.
    pub authority_revision: Revision,
    /// Host whose manifest was reviewed.
    pub host_id: DottedId,
    /// Review outcome.
    pub outcome: ManifoldHostManifestAuthorityReviewOutcome,
    /// Accepted host manifest. Present only for accepted reviews.
    pub accepted: Option<ManifoldHostManifest>,
    /// Rejected host manifest result. Present only for rejected reviews.
    pub rejection: Option<ManifoldHostManifestRejection>,
    /// Audit event for the same host manifest decision.
    pub audit_event: ManifoldHostManifestAuthorityAuditEvent,
}

impl ManifoldHostManifestAuthorityReview {
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
        if self.schema_id.as_str() != "rusty.manifold.authority.host_manifest_review.v1" {
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

        if self.host_id != snapshot.host_manifest.host_id
            || self.host_id != self.audit_event.host_id
            || self.host_id != self.audit_event.request.proposed_manifest.host_id
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.host_id.to_string(),
                ManifoldAuthorityValidationErrorKind::HostIdMismatch,
            ));
        }

        match self.outcome {
            ManifoldHostManifestAuthorityReviewOutcome::HostManifestAccepted => {
                if self.accepted.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.review_id.clone(),
                        "accepted".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
            ManifoldHostManifestAuthorityReviewOutcome::HostManifestRejected => {
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

        if ManifoldHostManifestAuthorityAuditEventKind::from(self.outcome)
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

/// Deterministic application result for one host manifest authority review.
///
/// This records the bridge from review-time host manifest authority to accepted
/// authority state without owning host service startup, endpoint opening, or
/// permission probing.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldHostManifestAuthorityApplication {
    /// Schema identifier for this application receipt.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable application id.
    pub application_id: DottedId,
    /// Authority that attempted the application.
    pub authority_id: DottedId,
    /// Authority revision before applying the review.
    pub from_authority_revision: Revision,
    /// Host whose manifest was reviewed.
    pub host_id: DottedId,
    /// Application outcome.
    pub outcome: ManifoldHostManifestAuthorityApplicationOutcome,
    /// Next accepted authority snapshot. Present only for applied outcomes.
    pub applied_snapshot: Option<ManifoldAuthoritySnapshot>,
    /// Rejection. Present only for rejected application outcomes.
    pub rejection: Option<ManifoldAuthoritySnapshotApplicationRejection>,
    /// Review that was applied or rejected for application.
    pub review: ManifoldHostManifestAuthorityReview,
}

impl ManifoldHostManifestAuthorityApplication {
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
        if self.schema_id.as_str() != "rusty.manifold.authority.host_manifest_application.v1" {
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

        if self.host_id != snapshot.host_manifest.host_id
            || self.host_id != self.review.host_id
            || self.host_id != self.review.audit_event.host_id
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.host_id.to_string(),
                ManifoldAuthorityValidationErrorKind::HostIdMismatch,
            ));
        }

        self.review.validate_against_snapshot(snapshot)?;

        match self.outcome {
            ManifoldHostManifestAuthorityApplicationOutcome::HostManifestApplied => {
                if self.applied_snapshot.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        "applied_snapshot".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                if self.review.outcome
                    != ManifoldHostManifestAuthorityReviewOutcome::HostManifestAccepted
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
                    || applied.clock_snapshot != snapshot.clock_snapshot
                    || applied.stream_registry != snapshot.stream_registry
                    || applied.module_runtime_states != snapshot.module_runtime_states
                    || applied.command_ids != snapshot.command_ids
                    || applied.command_descriptors != snapshot.command_descriptors
                    || applied.active_leases != snapshot.active_leases
                    || applied.active_stream_subscriptions != snapshot.active_stream_subscriptions
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        applied.authority_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::HostManifestMismatch,
                    ));
                }

                if applied.host_manifest
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
                        applied.host_manifest.host_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::HostManifestMismatch,
                    ));
                }

                applied.validate_authority_links()
            }
            ManifoldHostManifestAuthorityApplicationOutcome::HostManifestApplicationRejected => {
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
                    == ManifoldHostManifestAuthorityReviewOutcome::HostManifestRejected
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

impl ManifoldHostManifestAuthorityAuditEvent {
    /// Validates this event against the authority snapshot it claims to use.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the event is not a
    /// consistent host manifest acceptance or rejection for the supplied snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str() != "rusty.manifold.authority.host_manifest_audit_event.v1" {
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

        if self.host_id != snapshot.host_manifest.host_id
            || self.host_id != self.request.proposed_manifest.host_id
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.host_id.to_string(),
                ManifoldAuthorityValidationErrorKind::HostIdMismatch,
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
            ManifoldHostManifestAuthorityAuditEventKind::HostManifestAccepted => {
                if self.accepted.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        "accepted".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
            ManifoldHostManifestAuthorityAuditEventKind::HostManifestRejected => {
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
            snapshot.host_manifest_authority_decision(&self.request, &self.recorded_clock);

        if let Some(accepted) = &self.accepted {
            let HostManifestAuthorityDecision::Accepted(expected_manifest) = &expected_decision
            else {
                let rejected_value = match &expected_decision {
                    HostManifestAuthorityDecision::Rejected { rejection_code, .. } => {
                        rejection_code.clone()
                    }
                    HostManifestAuthorityDecision::Accepted(_) => "accepted".to_owned(),
                };
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejected_value.clone(),
                    authority_error_kind_for_host_manifest_rejection_code(&rejected_value),
                ));
            };

            if accepted != expected_manifest {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    accepted.host_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::HostManifestMismatch,
                ));
            }
        }

        if let Some(rejection) = &self.rejection {
            let HostManifestAuthorityDecision::Rejected {
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

            if rejection.current_authority_revision != self.prior_authority_revision {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejection.current_authority_revision.get().to_string(),
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

/// Endpoint descriptor.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointDescriptor {
    /// Endpoint id.
    pub endpoint_id: DottedId,
    /// Endpoint visibility.
    pub visibility: EndpointVisibility,
    /// Transport kind.
    pub transport: EndpointTransport,
    /// Security mechanism.
    pub security: EndpointSecurity,
}

impl EndpointDescriptor {
    /// Validates that visibility and security are paired safely.
    ///
    /// # Errors
    ///
    /// Returns [`EndpointSecurityError`] when this endpoint advertises a
    /// visibility/security pairing that is not accepted by Manifold policy.
    pub fn validate_security(&self) -> Result<(), EndpointSecurityError> {
        let valid = match self.visibility {
            EndpointVisibility::Loopback => {
                matches!(
                    self.security,
                    EndpointSecurity::LocalProcess | EndpointSecurity::PairingToken
                )
            }
            EndpointVisibility::PairedLan => {
                matches!(
                    self.security,
                    EndpointSecurity::PairingToken | EndpointSecurity::MutualAuth
                )
            }
            EndpointVisibility::PublicRelay => {
                matches!(
                    self.security,
                    EndpointSecurity::MutualAuth | EndpointSecurity::ExternalPolicy
                )
            }
        };

        if valid {
            Ok(())
        } else {
            Err(EndpointSecurityError {
                endpoint_id: self.endpoint_id.clone(),
                visibility: self.visibility,
                security: self.security,
            })
        }
    }
}

/// Host manifest authority audit event kind.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldHostManifestAuthorityAuditEventKind {
    /// Authority accepted a host manifest change request.
    HostManifestAccepted,
    /// Authority rejected a host manifest change request.
    HostManifestRejected,
}

/// Host manifest authority review outcome.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldHostManifestAuthorityReviewOutcome {
    /// Authority accepted the host manifest change request.
    HostManifestAccepted,
    /// Authority rejected the host manifest change request.
    HostManifestRejected,
}

/// Host manifest authority application outcome.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldHostManifestAuthorityApplicationOutcome {
    /// Accepted host manifest review was applied to the authority snapshot.
    HostManifestApplied,
    /// Host manifest review could not be applied to accepted authority state.
    HostManifestApplicationRejected,
}

impl From<ManifoldHostManifestAuthorityReviewOutcome>
    for ManifoldHostManifestAuthorityAuditEventKind
{
    fn from(outcome: ManifoldHostManifestAuthorityReviewOutcome) -> Self {
        match outcome {
            ManifoldHostManifestAuthorityReviewOutcome::HostManifestAccepted => {
                Self::HostManifestAccepted
            }
            ManifoldHostManifestAuthorityReviewOutcome::HostManifestRejected => {
                Self::HostManifestRejected
            }
        }
    }
}

/// Host authority role.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityRole {
    /// No authority role.
    None,
    /// Read-only observer.
    Observer,
    /// Secondary authority candidate.
    Secondary,
    /// Primary authority.
    Primary,
}

/// Endpoint visibility class.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointVisibility {
    /// Loopback-only endpoint.
    Loopback,
    /// Paired local network endpoint.
    PairedLan,
    /// Externally managed relay endpoint.
    PublicRelay,
}

/// Endpoint transport kind.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointTransport {
    /// In-process call path.
    InProcess,
    /// Standard input/output.
    Stdio,
    /// HTTP endpoint.
    Http,
}

/// Endpoint security mechanism.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointSecurity {
    /// No security mechanism.
    None,
    /// Local process boundary only.
    LocalProcess,
    /// Pairing token required.
    PairingToken,
    /// Mutual authentication required.
    MutualAuth,
    /// External relay or security policy owns access.
    ExternalPolicy,
}

/// Endpoint security validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointSecurityError {
    endpoint_id: DottedId,
    visibility: EndpointVisibility,
    security: EndpointSecurity,
}

impl EndpointSecurityError {
    /// Returns the affected endpoint id.
    #[must_use]
    pub fn endpoint_id(&self) -> &DottedId {
        &self.endpoint_id
    }

    /// Returns the machine-readable rejection code.
    #[must_use]
    pub fn rejection_code(&self) -> &'static str {
        "endpoint_security_mismatch"
    }

    /// Returns the endpoint visibility.
    #[must_use]
    pub const fn visibility(&self) -> EndpointVisibility {
        self.visibility
    }

    /// Returns the endpoint security mechanism.
    #[must_use]
    pub const fn security(&self) -> EndpointSecurity {
        self.security
    }
}

impl fmt::Display for EndpointSecurityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "endpoint {} has incompatible visibility {:?} and security {:?}",
            self.endpoint_id, self.visibility, self.security
        )
    }
}

impl std::error::Error for EndpointSecurityError {}
