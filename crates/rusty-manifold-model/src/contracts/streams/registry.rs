use super::*;

/// Stream descriptor.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamManifest {
    /// Schema identifier for this manifest.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable stream id.
    pub stream_id: DottedId,
    /// Module that provides the stream.
    pub source_module_id: DottedId,
    /// Semantic stream family.
    pub semantic_family: DottedId,
    /// Schema id for samples on the stream.
    pub sample_schema: SchemaId,
    /// Stream rate class.
    pub rate_class: StreamRateClass,
    /// Timestamp domains carried by stream events.
    pub timestamp_domains: Vec<DottedId>,
    /// Retention policy.
    pub retention: RetentionPolicyDescriptor,
    /// Sensitivity label.
    pub sensitivity: SensitivityLevel,
    /// Transport offers available for this stream.
    pub transport_offers: Vec<TransportOffer>,
    /// Subscription policy.
    pub subscription: SubscriptionPolicy,
}

/// Registry snapshot at one topology revision.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamRegistrySnapshot {
    /// Schema identifier for this snapshot.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Accepted registry revision.
    pub registry_revision: Revision,
    /// Streams visible at this revision.
    pub streams: Vec<ManifoldStreamManifest>,
}

impl ManifoldStreamRegistrySnapshot {
    /// Validates that every stream points to a known source module id.
    ///
    /// # Errors
    ///
    /// Returns [`StreamRegistryValidationError`] when a stream references an
    /// unknown source module.
    pub fn validate_source_modules(
        &self,
        module_ids: &[DottedId],
    ) -> Result<(), StreamRegistryValidationError> {
        for stream in &self.streams {
            if !module_ids
                .iter()
                .any(|module_id| module_id == &stream.source_module_id)
            {
                return Err(StreamRegistryValidationError {
                    stream_id: stream.stream_id.clone(),
                    rejected_id: stream.source_module_id.clone(),
                    kind: StreamRegistryValidationErrorKind::UnknownModuleLink,
                });
            }
        }

        Ok(())
    }

    /// Validates that endpoint-bound transport offers reference known endpoint ids.
    ///
    /// # Errors
    ///
    /// Returns [`StreamRegistryValidationError`] when a stream transport offer
    /// points at an endpoint that the selected host does not advertise.
    pub fn validate_transport_endpoints(
        &self,
        endpoint_ids: &[DottedId],
    ) -> Result<(), StreamRegistryValidationError> {
        for stream in &self.streams {
            for offer in &stream.transport_offers {
                if let Some(endpoint_id) = &offer.endpoint_id {
                    if !endpoint_ids.iter().any(|known| known == endpoint_id) {
                        return Err(StreamRegistryValidationError {
                            stream_id: stream.stream_id.clone(),
                            rejected_id: endpoint_id.clone(),
                            kind: StreamRegistryValidationErrorKind::UnknownTransportEndpoint,
                        });
                    }
                }
            }
        }

        Ok(())
    }

    /// Returns a stream-registry diff from an earlier snapshot to this snapshot.
    ///
    /// # Panics
    ///
    /// Panics only if the built-in stream-registry-diff schema id literal is invalid.
    #[must_use]
    pub fn diff_from(&self, previous: &Self) -> ManifoldStreamRegistryDiff {
        ManifoldStreamRegistryDiff {
            schema_id: SchemaId::new("rusty.manifold.stream.registry_diff.v1")
                .expect("schema literal is valid"),
            from_revision: previous.registry_revision,
            to_revision: self.registry_revision,
            added_streams: added_by_key(&self.streams, &previous.streams, |stream| {
                &stream.stream_id
            }),
            removed_streams: added_by_key(&previous.streams, &self.streams, |stream| {
                &stream.stream_id
            }),
            changed_streams: changed_streams(previous, self),
        }
    }
}

/// Stream-registry diff between two registry revisions.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamRegistryDiff {
    /// Schema identifier for this diff.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Earlier registry revision.
    pub from_revision: Revision,
    /// Later registry revision.
    pub to_revision: Revision,
    /// Streams present only in the later snapshot.
    pub added_streams: Vec<ManifoldStreamManifest>,
    /// Streams present only in the earlier snapshot.
    pub removed_streams: Vec<ManifoldStreamManifest>,
    /// Streams with the same id but changed metadata.
    pub changed_streams: Vec<ManifoldStreamChange>,
}

/// Request to change the accepted stream registry.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamRegistryChangeRequest {
    /// Schema identifier for this request.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Request id.
    pub request_id: DottedId,
    /// Holder id.
    pub holder_id: DottedId,
    /// Expected authority revision.
    pub expected_authority_revision: Revision,
    /// Lease id authorizing registry mutation.
    pub lease_id: Option<DottedId>,
    /// Capability required for the registry change.
    pub required_capability: DottedId,
    /// Proposed registry diff.
    pub diff: ManifoldStreamRegistryDiff,
}

/// Rejected stream-registry change result.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamRegistryRejection {
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
    pub current_authority_revision: Revision,
    /// Current accepted stream-registry revision.
    pub current_registry_revision: Revision,
}

/// Changed stream descriptor.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamChange {
    /// Stable stream id.
    pub stream_id: DottedId,
    /// Earlier stream descriptor.
    pub before: ManifoldStreamManifest,
    /// Later stream descriptor.
    pub after: ManifoldStreamManifest,
}

/// Audit event for one stream-registry authority decision.
///
/// The event carries the registry change request plus exactly one accepted
/// snapshot or rejected result. It records enough authority context for
/// deterministic validation without publishing streams or opening transports.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamRegistryAuthorityAuditEvent {
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
    pub event_kind: ManifoldStreamRegistryAuthorityAuditEventKind,
    /// Registry change request reviewed by authority.
    pub request: ManifoldStreamRegistryChangeRequest,
    /// Accepted registry snapshot. Present only for accepted events.
    pub accepted: Option<ManifoldStreamRegistrySnapshot>,
    /// Rejected registry result. Present only for rejected events.
    pub rejection: Option<ManifoldStreamRegistryRejection>,
    /// Lease recorded with the decision, when a lease was presented.
    pub lease: Option<ManifoldControlLease>,
    /// Clock snapshot recorded with the decision.
    pub recorded_clock: ManifoldClockSnapshot,
    /// Stable ids for fixtures, scorecards, or logs backing the event.
    pub evidence_refs: Vec<DottedId>,
}

/// Deterministic review result for one stream-registry authority decision.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamRegistryAuthorityReview {
    /// Schema identifier for this review.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable review id.
    pub review_id: DottedId,
    /// Authority that reviewed the registry change.
    pub authority_id: DottedId,
    /// Authority revision used by this review.
    pub authority_revision: Revision,
    /// Stream-registry revision used by this review.
    pub registry_revision: Revision,
    /// Review outcome.
    pub outcome: ManifoldStreamRegistryAuthorityReviewOutcome,
    /// Accepted registry snapshot. Present only for accepted reviews.
    pub accepted: Option<ManifoldStreamRegistrySnapshot>,
    /// Rejected registry result. Present only for rejected reviews.
    pub rejection: Option<ManifoldStreamRegistryRejection>,
    /// Audit event for the same registry decision.
    pub audit_event: ManifoldStreamRegistryAuthorityAuditEvent,
}

impl ManifoldStreamRegistryAuthorityReview {
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
        if self.schema_id.as_str() != "rusty.manifold.authority.stream_registry_review.v1" {
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
            ManifoldStreamRegistryAuthorityReviewOutcome::RegistryAccepted => {
                if self.accepted.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.review_id.clone(),
                        "accepted".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
            ManifoldStreamRegistryAuthorityReviewOutcome::RegistryRejected => {
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

        if ManifoldStreamRegistryAuthorityAuditEventKind::from(self.outcome)
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

/// Deterministic application result for one stream-registry authority review.
///
/// This records the bridge from review-time authority to accepted authority
/// state without owning live publication, transport, or runtime mutation.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamRegistryAuthorityApplication {
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
    /// Application outcome.
    pub outcome: ManifoldStreamRegistryAuthorityApplicationOutcome,
    /// Next accepted authority snapshot. Present only for applied outcomes.
    pub applied_snapshot: Option<ManifoldAuthoritySnapshot>,
    /// Rejection. Present only for rejected application outcomes.
    pub rejection: Option<ManifoldAuthoritySnapshotApplicationRejection>,
    /// Review that was applied or rejected for application.
    pub review: ManifoldStreamRegistryAuthorityReview,
}

impl ManifoldStreamRegistryAuthorityApplication {
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
        if self.schema_id.as_str() != "rusty.manifold.authority.stream_registry_application.v1" {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.schema_id.to_string(),
                ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
            ));
        }

        validate_derived_authority_id(
            &self.application_id,
            &self.application_id,
            stream_registry_authority_application_id(&self.review.review_id),
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

        self.review.validate_against_snapshot(snapshot)?;

        match self.outcome {
            ManifoldStreamRegistryAuthorityApplicationOutcome::RegistrySnapshotApplied => {
                if self.applied_snapshot.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        "applied_snapshot".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                if self.review.outcome
                    != ManifoldStreamRegistryAuthorityReviewOutcome::RegistryAccepted
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
                    || applied.module_runtime_states != snapshot.module_runtime_states
                    || applied.command_ids != snapshot.command_ids
                    || applied.command_descriptors != snapshot.command_descriptors
                    || applied.active_leases != snapshot.active_leases
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        applied.authority_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::RegistryMismatch,
                    ));
                }

                if applied.stream_registry
                    != self
                        .review
                        .accepted
                        .clone()
                        .unwrap_or_else(|| snapshot.stream_registry.clone())
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        applied.stream_registry.registry_revision.get().to_string(),
                        ManifoldAuthorityValidationErrorKind::RegistryMismatch,
                    ));
                }

                applied.validate_authority_links()
            }
            ManifoldStreamRegistryAuthorityApplicationOutcome::RegistryApplicationRejected => {
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
                    == ManifoldStreamRegistryAuthorityReviewOutcome::RegistryRejected
                {
                    if rejection.rejection_code.as_str() != "review_rejected" {
                        return Err(ManifoldAuthorityValidationError::new(
                            self.application_id.clone(),
                            rejection.rejection_code.to_string(),
                            ManifoldAuthorityValidationErrorKind::RejectionMismatch,
                        ));
                    }
                }

                Ok(())
            }
        }
    }
}

impl ManifoldStreamRegistryAuthorityAuditEvent {
    /// Validates this event against the authority snapshot it claims to use.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the event is not a
    /// consistent registry acceptance or rejection for the supplied snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str() != "rusty.manifold.authority.stream_registry_audit_event.v1" {
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
            ManifoldStreamRegistryAuthorityAuditEventKind::RegistryAccepted => {
                if self.accepted.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        "accepted".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
            ManifoldStreamRegistryAuthorityAuditEventKind::RegistryRejected => {
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
            snapshot.stream_registry_authority_decision(&self.request, &self.recorded_clock);

        if let Some(accepted) = &self.accepted {
            let StreamRegistryAuthorityDecision::Accepted(expected_snapshot) = &expected_decision
            else {
                let rejected_value = match &expected_decision {
                    StreamRegistryAuthorityDecision::Rejected { rejection_code, .. } => {
                        rejection_code.clone()
                    }
                    StreamRegistryAuthorityDecision::Accepted(_) => "accepted".to_owned(),
                };
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejected_value.clone(),
                    authority_error_kind_for_stream_registry_rejection_code(&rejected_value),
                ));
            };

            if accepted != expected_snapshot {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    accepted.registry_revision.get().to_string(),
                    ManifoldAuthorityValidationErrorKind::RegistryMismatch,
                ));
            }
        }

        if let Some(rejection) = &self.rejection {
            let StreamRegistryAuthorityDecision::Rejected {
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
                || rejection.current_registry_revision != self.prior_registry_revision
            {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejection.current_registry_revision.get().to_string(),
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

/// Stream-registry authority audit event kind.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldStreamRegistryAuthorityAuditEventKind {
    /// Authority accepted a registry change request.
    RegistryAccepted,
    /// Authority rejected a registry change request.
    RegistryRejected,
}

/// Stream-registry authority review outcome.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldStreamRegistryAuthorityReviewOutcome {
    /// Authority accepted the registry change request.
    RegistryAccepted,
    /// Authority rejected the registry change request.
    RegistryRejected,
}

impl From<ManifoldStreamRegistryAuthorityReviewOutcome>
    for ManifoldStreamRegistryAuthorityAuditEventKind
{
    fn from(outcome: ManifoldStreamRegistryAuthorityReviewOutcome) -> Self {
        match outcome {
            ManifoldStreamRegistryAuthorityReviewOutcome::RegistryAccepted => {
                Self::RegistryAccepted
            }
            ManifoldStreamRegistryAuthorityReviewOutcome::RegistryRejected => {
                Self::RegistryRejected
            }
        }
    }
}

/// Stream-registry authority application outcome.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldStreamRegistryAuthorityApplicationOutcome {
    /// Accepted stream-registry review was applied to the authority snapshot.
    RegistrySnapshotApplied,
    /// Stream-registry review could not be applied to accepted authority state.
    RegistryApplicationRejected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum StreamRegistryAuthorityDecision {
    Accepted(ManifoldStreamRegistrySnapshot),
    Rejected {
        rejection_code: String,
        message: String,
        retryable: bool,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StreamRegistryDiffRejection {
    rejection_code: String,
    message: String,
    retryable: bool,
}

impl StreamRegistryDiffRejection {
    fn new(rejection_code: impl Into<String>, message: impl Into<String>, retryable: bool) -> Self {
        Self {
            rejection_code: rejection_code.into(),
            message: message.into(),
            retryable,
        }
    }
}

impl ManifoldAuthoritySnapshot {
    /// Deterministically reviews one stream-registry change request against this authority snapshot.
    ///
    /// The review is source-only: it applies the proposed diff to contract data
    /// only and does not publish streams, open transports, start modules, or
    /// mutate a runtime registry.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the authority snapshot
    /// itself is invalid, the review clock is inconsistent, or evidence refs are empty.
    pub fn review_stream_registry_change(
        &self,
        request: ManifoldStreamRegistryChangeRequest,
        recorded_clock: ManifoldClockSnapshot,
        evidence_refs: Vec<DottedId>,
    ) -> Result<ManifoldStreamRegistryAuthorityReview, ManifoldAuthorityValidationError> {
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

        let decision = self.stream_registry_authority_decision(&request, &recorded_clock);
        let lease = request
            .lease_id
            .as_ref()
            .and_then(|lease_id| self.active_lease(lease_id))
            .cloned();
        let (outcome, accepted, rejection) = match decision {
            StreamRegistryAuthorityDecision::Accepted(snapshot) => (
                ManifoldStreamRegistryAuthorityReviewOutcome::RegistryAccepted,
                Some(snapshot),
                None,
            ),
            StreamRegistryAuthorityDecision::Rejected {
                rejection_code,
                message,
                retryable,
            } => (
                ManifoldStreamRegistryAuthorityReviewOutcome::RegistryRejected,
                None,
                Some(ManifoldStreamRegistryRejection {
                    schema_id: stream_registry_rejection_schema_id(),
                    request_id: request.request_id.clone(),
                    rejection_code: DottedId::new(rejection_code)
                        .expect("rejection code is a valid dotted id"),
                    message,
                    retryable,
                    current_authority_revision: self.authority_revision,
                    current_registry_revision: self.stream_registry.registry_revision,
                }),
            ),
        };

        let audit_event = ManifoldStreamRegistryAuthorityAuditEvent {
            schema_id: stream_registry_authority_audit_event_schema_id(),
            event_id: stream_registry_authority_audit_event_id(&request.request_id, outcome),
            authority_id: self.authority_id.clone(),
            prior_authority_revision: self.authority_revision,
            prior_registry_revision: self.stream_registry.registry_revision,
            event_kind: outcome.into(),
            request,
            accepted: accepted.clone(),
            rejection: rejection.clone(),
            lease,
            recorded_clock,
            evidence_refs,
        };

        let review = ManifoldStreamRegistryAuthorityReview {
            schema_id: stream_registry_authority_review_schema_id(),
            review_id: stream_registry_authority_review_id(&audit_event.request.request_id),
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

    /// Deterministically applies one stream-registry authority review to this snapshot.
    ///
    /// Accepted registry reviews produce a new `ManifoldAuthoritySnapshot` with
    /// the authority revision advanced by one and the accepted stream registry
    /// installed. Rejected reviews produce a machine-readable application
    /// rejection and leave accepted state unchanged. This is source-only: it
    /// does not publish streams, open transports, notify subscribers, or
    /// mutate a runtime registry.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when this authority snapshot
    /// itself is invalid.
    pub fn apply_stream_registry_authority_review(
        &self,
        review: ManifoldStreamRegistryAuthorityReview,
    ) -> Result<ManifoldStreamRegistryAuthorityApplication, ManifoldAuthorityValidationError> {
        self.validate_authority_links()?;

        let application_id = stream_registry_authority_application_id(&review.review_id);
        let from_authority_revision = self.authority_revision;
        let from_registry_revision = self.stream_registry.registry_revision;

        let (outcome, applied_snapshot, rejection) = match review.validate_against_snapshot(self) {
            Err(error) => (
                ManifoldStreamRegistryAuthorityApplicationOutcome::RegistryApplicationRejected,
                None,
                Some(ManifoldAuthoritySnapshotApplicationRejection {
                    schema_id: authority_snapshot_application_rejection_schema_id(),
                    application_id: application_id.clone(),
                    rejection_code: DottedId::new(error.rejection_code())
                        .expect("authority rejection code is a valid dotted id"),
                    message: format!(
                        "stream registry review does not match authority snapshot: {error}"
                    ),
                    retryable: authority_application_validation_retryable(error.kind()),
                    current_authority_revision: self.authority_revision,
                }),
            ),
            Ok(())
                if review.outcome
                    == ManifoldStreamRegistryAuthorityReviewOutcome::RegistryRejected =>
            {
                (
                    ManifoldStreamRegistryAuthorityApplicationOutcome::RegistryApplicationRejected,
                    None,
                    Some(ManifoldAuthoritySnapshotApplicationRejection {
                        schema_id: authority_snapshot_application_rejection_schema_id(),
                        application_id: application_id.clone(),
                        rejection_code: DottedId::new("review_rejected")
                            .expect("rejection code literal is valid"),
                        message: "stream registry review did not accept a registry snapshot"
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
                let mut next_snapshot = self.clone();
                next_snapshot.authority_revision = next_authority_revision;
                next_snapshot.stream_registry = review.accepted.clone().ok_or_else(|| {
                    ManifoldAuthorityValidationError::new(
                        review.review_id.clone(),
                        "accepted".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    )
                })?;
                next_snapshot.validate_authority_links()?;
                (
                    ManifoldStreamRegistryAuthorityApplicationOutcome::RegistrySnapshotApplied,
                    Some(next_snapshot),
                    None,
                )
            }
        };

        let application = ManifoldStreamRegistryAuthorityApplication {
            schema_id: stream_registry_authority_application_schema_id(),
            application_id,
            authority_id: self.authority_id.clone(),
            from_authority_revision,
            from_registry_revision,
            outcome,
            applied_snapshot,
            rejection,
            review,
        };
        application.validate_against_snapshot(self)?;
        Ok(application)
    }

    fn stream_registry_authority_decision(
        &self,
        request: &ManifoldStreamRegistryChangeRequest,
        recorded_clock: &ManifoldClockSnapshot,
    ) -> StreamRegistryAuthorityDecision {
        if request.schema_id != stream_registry_change_request_schema_id() {
            return StreamRegistryAuthorityDecision::Rejected {
                rejection_code: "unsupported_schema".to_owned(),
                message: "stream registry request schema is not supported".to_owned(),
                retryable: false,
            };
        }

        if request.expected_authority_revision != self.authority_revision {
            return StreamRegistryAuthorityDecision::Rejected {
                rejection_code: "stale_revision".to_owned(),
                message: "stream registry request expected authority revision does not match current revision"
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
            return StreamRegistryAuthorityDecision::Rejected {
                rejection_code: "capability_not_advertised".to_owned(),
                message:
                    "stream registry request capability is not advertised by the authority host"
                        .to_owned(),
                retryable: false,
            };
        }

        let Some(lease_id) = &request.lease_id else {
            return StreamRegistryAuthorityDecision::Rejected {
                rejection_code: "missing_lease".to_owned(),
                message: "stream registry change requires an active registry lease".to_owned(),
                retryable: true,
            };
        };

        let Some(lease) = self.active_lease(lease_id) else {
            return StreamRegistryAuthorityDecision::Rejected {
                rejection_code: "unknown_lease".to_owned(),
                message: "stream registry request references an unknown lease".to_owned(),
                retryable: true,
            };
        };

        if lease.state != LeaseState::Active {
            return StreamRegistryAuthorityDecision::Rejected {
                rejection_code: "inactive_lease".to_owned(),
                message: "stream registry lease is not active".to_owned(),
                retryable: true,
            };
        }

        if lease_expired_at(lease, recorded_clock) {
            return StreamRegistryAuthorityDecision::Rejected {
                rejection_code: "expired_lease".to_owned(),
                message: "stream registry lease is expired at the review clock".to_owned(),
                retryable: true,
            };
        }

        if lease.granted_revision > self.authority_revision {
            return StreamRegistryAuthorityDecision::Rejected {
                rejection_code: "lease_revision_ahead".to_owned(),
                message: "stream registry lease was granted after this authority revision"
                    .to_owned(),
                retryable: true,
            };
        }

        if lease.holder_id != request.holder_id
            || lease.scope != registry_lease_scope()
            || lease.required_capability != request.required_capability
        {
            return StreamRegistryAuthorityDecision::Rejected {
                rejection_code: "lease_mismatch".to_owned(),
                message: "stream registry request does not match the active lease".to_owned(),
                retryable: true,
            };
        }

        match self.apply_stream_registry_diff(&request.diff) {
            Ok(snapshot) => StreamRegistryAuthorityDecision::Accepted(snapshot),
            Err(rejection) => StreamRegistryAuthorityDecision::Rejected {
                rejection_code: rejection.rejection_code,
                message: rejection.message,
                retryable: rejection.retryable,
            },
        }
    }

    fn apply_stream_registry_diff(
        &self,
        diff: &ManifoldStreamRegistryDiff,
    ) -> Result<ManifoldStreamRegistrySnapshot, StreamRegistryDiffRejection> {
        if diff.schema_id != stream_registry_diff_schema_id() {
            return Err(StreamRegistryDiffRejection::new(
                "unsupported_schema",
                "stream registry diff schema is not supported",
                false,
            ));
        }

        if diff.from_revision != self.stream_registry.registry_revision {
            return Err(StreamRegistryDiffRejection::new(
                "registry_revision_mismatch",
                "stream registry diff from_revision does not match current registry revision",
                true,
            ));
        }

        let Some(next_revision) = self.stream_registry.registry_revision.next() else {
            return Err(StreamRegistryDiffRejection::new(
                "registry_revision_mismatch",
                "stream registry revision cannot advance",
                false,
            ));
        };
        if diff.to_revision != next_revision {
            return Err(StreamRegistryDiffRejection::new(
                "registry_revision_mismatch",
                "stream registry diff to_revision must advance by one",
                true,
            ));
        }

        if diff.added_streams.is_empty()
            && diff.removed_streams.is_empty()
            && diff.changed_streams.is_empty()
        {
            return Err(StreamRegistryDiffRejection::new(
                "empty_registry_diff",
                "stream registry diff has no changes",
                false,
            ));
        }

        let mut streams = self.stream_registry.streams.clone();

        for removed in &diff.removed_streams {
            if self.active_stream_id(&removed.stream_id) {
                return Err(StreamRegistryDiffRejection::new(
                    "active_stream_conflict",
                    "stream registry diff removes a stream still active in module runtime state",
                    true,
                ));
            }

            if self.active_subscription_count(&removed.stream_id) > 0 {
                return Err(StreamRegistryDiffRejection::new(
                    "active_subscription_conflict",
                    "stream registry diff removes a stream with active subscriptions",
                    true,
                ));
            }

            let Some(index) = streams
                .iter()
                .position(|stream| stream.stream_id == removed.stream_id)
            else {
                return Err(StreamRegistryDiffRejection::new(
                    "unknown_stream",
                    "stream registry diff removes a stream absent from the current registry",
                    true,
                ));
            };

            if streams[index] != *removed {
                return Err(StreamRegistryDiffRejection::new(
                    "stream_diff_mismatch",
                    "stream registry diff remove entry does not match the current stream",
                    true,
                ));
            }

            streams.remove(index);
        }

        for change in &diff.changed_streams {
            if change.before.stream_id != change.stream_id
                || change.after.stream_id != change.stream_id
            {
                return Err(StreamRegistryDiffRejection::new(
                    "stream_diff_mismatch",
                    "stream registry diff change entry has mismatched stream ids",
                    false,
                ));
            }

            let Some(index) = streams
                .iter()
                .position(|stream| stream.stream_id == change.stream_id)
            else {
                return Err(StreamRegistryDiffRejection::new(
                    "unknown_stream",
                    "stream registry diff changes a stream absent from the current registry",
                    true,
                ));
            };

            if streams[index] != change.before {
                return Err(StreamRegistryDiffRejection::new(
                    "stream_diff_mismatch",
                    "stream registry diff before entry does not match the current stream",
                    true,
                ));
            }

            if change.after.source_module_id != change.before.source_module_id
                && self.active_stream_id(&change.stream_id)
            {
                return Err(StreamRegistryDiffRejection::new(
                    "active_stream_conflict",
                    "stream registry diff changes the source module for an active stream",
                    true,
                ));
            }

            let active_subscription_count = self.active_subscription_count(&change.stream_id);
            if active_subscription_count > 0 {
                for subscription in self
                    .active_stream_subscriptions
                    .iter()
                    .filter(|subscription| subscription.stream_id == change.stream_id)
                {
                    let offer_still_available = change.after.transport_offers.iter().any(|offer| {
                        offer.transport_id == subscription.transport_id
                            && offer.endpoint_id == subscription.endpoint_id
                    });
                    if !offer_still_available {
                        return Err(StreamRegistryDiffRejection::new(
                            "active_subscription_conflict",
                            "stream registry diff removes a transport offer used by an active subscription",
                            true,
                        ));
                    }

                    if subscription.subscriber_kind == ManifoldStreamSubscriberKind::Ui
                        && !change.after.subscription.ui_subscribable
                    {
                        return Err(StreamRegistryDiffRejection::new(
                            "active_subscription_conflict",
                            "stream registry diff disables UI subscription policy while UI subscriptions are active",
                            true,
                        ));
                    }
                }

                if let Some(max_subscribers) = change.after.subscription.max_subscribers {
                    if active_subscription_count > max_subscribers {
                        return Err(StreamRegistryDiffRejection::new(
                            "active_subscription_conflict",
                            "stream registry diff lowers the subscriber limit below active subscriptions",
                            true,
                        ));
                    }
                }
            }

            streams[index] = change.after.clone();
        }

        for added in &diff.added_streams {
            if streams
                .iter()
                .any(|stream| stream.stream_id == added.stream_id)
            {
                return Err(StreamRegistryDiffRejection::new(
                    "stream_already_exists",
                    "stream registry diff adds a stream id that already exists",
                    true,
                ));
            }
            streams.push(added.clone());
        }

        if let Some(stream_id) = duplicate_stream_id(&streams) {
            return Err(StreamRegistryDiffRejection::new(
                "duplicate_stream",
                format!("stream registry contains duplicate stream id {stream_id}"),
                false,
            ));
        }

        let snapshot = ManifoldStreamRegistrySnapshot {
            schema_id: stream_registry_snapshot_schema_id(),
            registry_revision: diff.to_revision,
            streams,
        };
        let module_ids = self
            .module_runtime_states
            .iter()
            .map(|state| state.module_id.clone())
            .collect::<Vec<_>>();
        if let Err(error) = snapshot.validate_source_modules(&module_ids) {
            return Err(StreamRegistryDiffRejection::new(
                error.rejection_code(),
                format!(
                    "stream registry diff references unknown source module {}",
                    error.rejected_id()
                ),
                false,
            ));
        }

        let endpoint_ids = self
            .host_manifest
            .endpoints
            .iter()
            .map(|endpoint| endpoint.endpoint_id.clone())
            .collect::<Vec<_>>();
        if let Err(error) = snapshot.validate_transport_endpoints(&endpoint_ids) {
            return Err(StreamRegistryDiffRejection::new(
                error.rejection_code(),
                format!(
                    "stream registry diff references unknown transport endpoint {}",
                    error.rejected_id()
                ),
                false,
            ));
        }

        Ok(snapshot)
    }
}
