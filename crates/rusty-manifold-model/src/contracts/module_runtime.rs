use super::*;

/// Live module state at one authority revision.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldModuleRuntimeState {
    /// Schema identifier for this snapshot.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Module this state describes.
    pub module_id: DottedId,
    /// Runtime revision that accepted this state.
    pub runtime_revision: Revision,
    /// Current lifecycle state.
    pub lifecycle: ModuleLifecycleState,
    /// Current health level.
    pub health: HealthLevel,
    /// Selected backend, when one has been selected.
    pub selected_backend: Option<DottedId>,
    /// Active streams owned by this module.
    pub active_streams: Vec<DottedId>,
    /// Active command surfaces owned by this module.
    pub active_commands: Vec<DottedId>,
    /// Current issues.
    pub issues: Vec<ManifoldIssue>,
}

impl ManifoldModuleRuntimeState {
    /// Returns the state transition from an earlier runtime snapshot to this snapshot.
    ///
    /// # Panics
    ///
    /// Panics only if the built-in runtime-transition schema id literal is invalid.
    #[must_use]
    pub fn transition_from(&self, previous: &Self) -> ManifoldModuleRuntimeTransition {
        ManifoldModuleRuntimeTransition {
            schema_id: SchemaId::new("rusty.manifold.module.runtime_transition.v1")
                .expect("schema literal is valid"),
            module_id: self.module_id.clone(),
            from_revision: previous.runtime_revision,
            to_revision: self.runtime_revision,
            lifecycle_change: (previous.lifecycle != self.lifecycle).then_some(
                ModuleLifecycleChange {
                    from: previous.lifecycle,
                    to: self.lifecycle,
                },
            ),
            health_change: (previous.health != self.health).then_some(ModuleHealthChange {
                from: previous.health,
                to: self.health,
            }),
            backend_change: (previous.selected_backend != self.selected_backend).then_some(
                ModuleBackendChange {
                    from: previous.selected_backend.clone(),
                    to: self.selected_backend.clone(),
                },
            ),
            activated_streams: added_ids(&self.active_streams, &previous.active_streams),
            deactivated_streams: added_ids(&previous.active_streams, &self.active_streams),
            activated_commands: added_ids(&self.active_commands, &previous.active_commands),
            deactivated_commands: added_ids(&previous.active_commands, &self.active_commands),
            added_issues: added_by_key(&self.issues, &previous.issues, |issue| &issue.issue_code),
            resolved_issues: added_by_key(&previous.issues, &self.issues, |issue| {
                &issue.issue_code
            }),
        }
    }
}

/// Runtime-state transition for one module.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldModuleRuntimeTransition {
    /// Schema identifier for this transition.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Module being compared.
    pub module_id: DottedId,
    /// Earlier runtime revision.
    pub from_revision: Revision,
    /// Later runtime revision.
    pub to_revision: Revision,
    /// Lifecycle change, if any.
    pub lifecycle_change: Option<ModuleLifecycleChange>,
    /// Health change, if any.
    pub health_change: Option<ModuleHealthChange>,
    /// Selected backend change, if any.
    pub backend_change: Option<ModuleBackendChange>,
    /// Streams active only in the later snapshot.
    pub activated_streams: Vec<DottedId>,
    /// Streams active only in the earlier snapshot.
    pub deactivated_streams: Vec<DottedId>,
    /// Commands active only in the later snapshot.
    pub activated_commands: Vec<DottedId>,
    /// Commands active only in the earlier snapshot.
    pub deactivated_commands: Vec<DottedId>,
    /// Issues present only in the later snapshot.
    pub added_issues: Vec<ManifoldIssue>,
    /// Issues present only in the earlier snapshot.
    pub resolved_issues: Vec<ManifoldIssue>,
}

/// Request to change one module runtime-state snapshot under Manifold authority.
///
/// The request proposes contract state only. It does not start or stop a
/// process, load a module, open a transport, or claim platform lifecycle work.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldModuleRuntimeStateChangeRequest {
    /// Schema identifier for this request.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable request id.
    pub request_id: DottedId,
    /// Holder requesting the state transition.
    pub holder_id: DottedId,
    /// Authority revision the requester observed.
    pub expected_authority_revision: Revision,
    /// Lease id proving authority to change this module state.
    pub lease_id: Option<DottedId>,
    /// Capability required for this runtime-state transition.
    pub required_capability: DottedId,
    /// Module whose state is being changed.
    pub module_id: DottedId,
    /// Runtime revision expected before the transition.
    pub from_runtime_revision: Revision,
    /// Proposed accepted module state after the transition.
    pub proposed_state: ManifoldModuleRuntimeState,
}

/// Rejection for a module runtime-state change request.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldModuleRuntimeStateRejection {
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
    /// Current runtime revision for the requested module, if known.
    pub current_runtime_revision: Option<Revision>,
}

/// Lifecycle field change.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModuleLifecycleChange {
    /// Earlier lifecycle.
    pub from: ModuleLifecycleState,
    /// Later lifecycle.
    pub to: ModuleLifecycleState,
}

/// Health field change.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModuleHealthChange {
    /// Earlier health.
    pub from: HealthLevel,
    /// Later health.
    pub to: HealthLevel,
}

/// Selected backend field change.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModuleBackendChange {
    /// Earlier selected backend.
    pub from: Option<DottedId>,
    /// Later selected backend.
    pub to: Option<DottedId>,
}

/// Deterministic application result for one module runtime-state authority review.
///
/// This records the bridge from review-time runtime-state authority to accepted
/// authority state without owning process lifecycle, module loading, or runtime
/// signaling.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldModuleRuntimeStateAuthorityApplication {
    /// Schema identifier for this application receipt.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable application id.
    pub application_id: DottedId,
    /// Authority that attempted the application.
    pub authority_id: DottedId,
    /// Authority revision before applying the review.
    pub from_authority_revision: Revision,
    /// Module whose runtime state was reviewed.
    pub module_id: DottedId,
    /// Runtime revision before applying the review, if the module is known.
    pub from_runtime_revision: Option<Revision>,
    /// Application outcome.
    pub outcome: ManifoldModuleRuntimeStateAuthorityApplicationOutcome,
    /// Next accepted authority snapshot. Present only for applied outcomes.
    pub applied_snapshot: Option<ManifoldAuthoritySnapshot>,
    /// Rejection. Present only for rejected application outcomes.
    pub rejection: Option<ManifoldAuthoritySnapshotApplicationRejection>,
    /// Review that was applied or rejected for application.
    pub review: ManifoldModuleRuntimeStateAuthorityReview,
}

impl ManifoldModuleRuntimeStateAuthorityApplication {
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
        if self.schema_id.as_str() != "rusty.manifold.authority.module_runtime_state_application.v1"
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
            module_runtime_state_authority_application_id(&self.review.review_id),
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

        let snapshot_runtime_revision = snapshot
            .module_runtime_state(&self.module_id)
            .map(|state| state.runtime_revision);
        if self.module_id != self.review.module_id
            || self.module_id != self.review.audit_event.module_id
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.module_id.to_string(),
                ManifoldAuthorityValidationErrorKind::ModuleIdMismatch,
            ));
        }

        if self.from_runtime_revision != snapshot_runtime_revision
            || self.from_runtime_revision != self.review.runtime_revision
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.from_runtime_revision
                    .map(|revision| revision.get().to_string())
                    .unwrap_or_else(|| "none".to_owned()),
                ManifoldAuthorityValidationErrorKind::RuntimeRevisionMismatch,
            ));
        }

        self.review.validate_against_snapshot(snapshot)?;

        match self.outcome {
            ManifoldModuleRuntimeStateAuthorityApplicationOutcome::RuntimeStateApplied => {
                if self.applied_snapshot.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        "applied_snapshot".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                if self.review.outcome
                    != ManifoldModuleRuntimeStateAuthorityReviewOutcome::RuntimeStateAccepted
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
                    || applied.command_ids != snapshot.command_ids
                    || applied.command_descriptors != snapshot.command_descriptors
                    || applied.active_leases != snapshot.active_leases
                    || applied.active_stream_subscriptions
                        != snapshot.active_stream_subscriptions
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        applied.authority_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::ModuleRuntimeMismatch,
                    ));
                }

                let accepted = self.review.accepted.clone().ok_or_else(|| {
                    ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        "accepted".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    )
                })?;
                let mut expected_runtime_states = snapshot.module_runtime_states.clone();
                let Some(runtime_state) = expected_runtime_states
                    .iter_mut()
                    .find(|state| state.module_id == accepted.module_id)
                else {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        accepted.module_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::UnknownModule,
                    ));
                };
                *runtime_state = accepted;

                if applied.module_runtime_states != expected_runtime_states {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        self.module_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::ModuleRuntimeMismatch,
                    ));
                }

                applied.validate_authority_links()
            }
            ManifoldModuleRuntimeStateAuthorityApplicationOutcome::RuntimeStateApplicationRejected => {
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
                    == ManifoldModuleRuntimeStateAuthorityReviewOutcome::RuntimeStateRejected
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

/// Audit event for one module runtime-state authority decision.
///
/// The event carries the runtime-state change request plus exactly one accepted
/// state/transition pair or rejected result. It records enough authority
/// context for deterministic validation without performing lifecycle work.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldModuleRuntimeStateAuthorityAuditEvent {
    /// Schema identifier for this audit event.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable event id.
    pub event_id: DottedId,
    /// Authority that made the decision.
    pub authority_id: DottedId,
    /// Authority revision observed before the decision.
    pub prior_authority_revision: Revision,
    /// Module being reviewed.
    pub module_id: DottedId,
    /// Runtime revision observed before the decision, if the module is known.
    pub prior_runtime_revision: Option<Revision>,
    /// Event kind.
    pub event_kind: ManifoldModuleRuntimeStateAuthorityAuditEventKind,
    /// Runtime-state change request reviewed by authority.
    pub request: ManifoldModuleRuntimeStateChangeRequest,
    /// Accepted runtime-state snapshot. Present only for accepted events.
    pub accepted: Option<ManifoldModuleRuntimeState>,
    /// Computed transition. Present only for accepted events.
    pub transition: Option<ManifoldModuleRuntimeTransition>,
    /// Rejected runtime-state result. Present only for rejected events.
    pub rejection: Option<ManifoldModuleRuntimeStateRejection>,
    /// Lease recorded with the decision, when a lease was presented.
    pub lease: Option<ManifoldControlLease>,
    /// Clock snapshot recorded with the decision.
    pub recorded_clock: ManifoldClockSnapshot,
    /// Stable ids for fixtures, scorecards, or logs backing the event.
    pub evidence_refs: Vec<DottedId>,
}

/// Deterministic review result for one module runtime-state authority decision.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldModuleRuntimeStateAuthorityReview {
    /// Schema identifier for this review.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable review id.
    pub review_id: DottedId,
    /// Authority that reviewed the runtime-state change.
    pub authority_id: DottedId,
    /// Authority revision used by this review.
    pub authority_revision: Revision,
    /// Module being reviewed.
    pub module_id: DottedId,
    /// Runtime revision used by this review, if the module is known.
    pub runtime_revision: Option<Revision>,
    /// Review outcome.
    pub outcome: ManifoldModuleRuntimeStateAuthorityReviewOutcome,
    /// Accepted runtime-state snapshot. Present only for accepted reviews.
    pub accepted: Option<ManifoldModuleRuntimeState>,
    /// Computed transition. Present only for accepted reviews.
    pub transition: Option<ManifoldModuleRuntimeTransition>,
    /// Rejected runtime-state result. Present only for rejected reviews.
    pub rejection: Option<ManifoldModuleRuntimeStateRejection>,
    /// Audit event for the same runtime-state decision.
    pub audit_event: ManifoldModuleRuntimeStateAuthorityAuditEvent,
}

impl ManifoldModuleRuntimeStateAuthorityReview {
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
        if self.schema_id.as_str() != "rusty.manifold.authority.module_runtime_state_review.v1" {
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

        let snapshot_runtime_revision = snapshot
            .module_runtime_state(&self.module_id)
            .map(|state| state.runtime_revision);
        if self.module_id != self.audit_event.module_id
            || self.module_id != self.audit_event.request.module_id
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.module_id.to_string(),
                ManifoldAuthorityValidationErrorKind::ModuleIdMismatch,
            ));
        }

        if self.runtime_revision != snapshot_runtime_revision
            || self.runtime_revision != self.audit_event.prior_runtime_revision
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.runtime_revision
                    .map(|revision| revision.get().to_string())
                    .unwrap_or_else(|| "none".to_owned()),
                ManifoldAuthorityValidationErrorKind::RuntimeRevisionMismatch,
            ));
        }

        match self.outcome {
            ManifoldModuleRuntimeStateAuthorityReviewOutcome::RuntimeStateAccepted => {
                if self.accepted.is_none() || self.transition.is_none() || self.rejection.is_some()
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.review_id.clone(),
                        "accepted".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
            ManifoldModuleRuntimeStateAuthorityReviewOutcome::RuntimeStateRejected => {
                if self.accepted.is_some() || self.transition.is_some() || self.rejection.is_none()
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.review_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
        }

        if self.accepted != self.audit_event.accepted
            || self.transition != self.audit_event.transition
            || self.rejection != self.audit_event.rejection
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.audit_event.event_id.to_string(),
                ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
            ));
        }

        if ManifoldModuleRuntimeStateAuthorityAuditEventKind::from(self.outcome)
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

impl ManifoldModuleRuntimeStateAuthorityAuditEvent {
    /// Validates this event against the authority snapshot it claims to use.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the event is not a
    /// consistent runtime-state acceptance or rejection for the supplied snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str() != "rusty.manifold.authority.module_runtime_state_audit_event.v1"
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

        if self.module_id != self.request.module_id {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.module_id.to_string(),
                ManifoldAuthorityValidationErrorKind::ModuleIdMismatch,
            ));
        }

        let snapshot_runtime_revision = snapshot
            .module_runtime_state(&self.module_id)
            .map(|state| state.runtime_revision);
        if self.prior_runtime_revision != snapshot_runtime_revision {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.prior_runtime_revision
                    .map(|revision| revision.get().to_string())
                    .unwrap_or_else(|| "none".to_owned()),
                ManifoldAuthorityValidationErrorKind::RuntimeRevisionMismatch,
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
            ManifoldModuleRuntimeStateAuthorityAuditEventKind::RuntimeStateAccepted => {
                if self.accepted.is_none() || self.transition.is_none() || self.rejection.is_some()
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        "accepted".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
            ManifoldModuleRuntimeStateAuthorityAuditEventKind::RuntimeStateRejected => {
                if self.accepted.is_some() || self.transition.is_some() || self.rejection.is_none()
                {
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
            snapshot.module_runtime_state_authority_decision(&self.request, &self.recorded_clock);

        if let Some(accepted) = &self.accepted {
            let ModuleRuntimeStateAuthorityDecision::Accepted { state, transition } =
                &expected_decision
            else {
                let rejected_value = match &expected_decision {
                    ModuleRuntimeStateAuthorityDecision::Rejected { rejection_code, .. } => {
                        rejection_code.clone()
                    }
                    ModuleRuntimeStateAuthorityDecision::Accepted { .. } => "accepted".to_owned(),
                };
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejected_value.clone(),
                    authority_error_kind_for_module_runtime_rejection_code(&rejected_value),
                ));
            };

            if accepted != state {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    accepted.module_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::ModuleRuntimeMismatch,
                ));
            }

            if self.transition.as_ref() != Some(transition) {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    accepted.module_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::ModuleRuntimeMismatch,
                ));
            }
        }

        if let Some(rejection) = &self.rejection {
            let ModuleRuntimeStateAuthorityDecision::Rejected {
                rejection_code,
                message,
                retryable,
                current_runtime_revision,
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
                || rejection.current_runtime_revision != *current_runtime_revision
            {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejection
                        .current_runtime_revision
                        .map(|revision| revision.get().to_string())
                        .unwrap_or_else(|| "none".to_owned()),
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

/// Module runtime-state authority audit event kind.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldModuleRuntimeStateAuthorityAuditEventKind {
    /// Authority accepted a runtime-state change request.
    RuntimeStateAccepted,
    /// Authority rejected a runtime-state change request.
    RuntimeStateRejected,
}

/// Module runtime-state authority application outcome.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldModuleRuntimeStateAuthorityApplicationOutcome {
    /// Accepted runtime-state review was applied to the authority snapshot.
    RuntimeStateApplied,
    /// Runtime-state review could not be applied to accepted authority state.
    RuntimeStateApplicationRejected,
}

/// Module runtime-state authority review outcome.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldModuleRuntimeStateAuthorityReviewOutcome {
    /// Authority accepted the runtime-state change request.
    RuntimeStateAccepted,
    /// Authority rejected the runtime-state change request.
    RuntimeStateRejected,
}

impl From<ManifoldModuleRuntimeStateAuthorityReviewOutcome>
    for ManifoldModuleRuntimeStateAuthorityAuditEventKind
{
    fn from(outcome: ManifoldModuleRuntimeStateAuthorityReviewOutcome) -> Self {
        match outcome {
            ManifoldModuleRuntimeStateAuthorityReviewOutcome::RuntimeStateAccepted => {
                Self::RuntimeStateAccepted
            }
            ManifoldModuleRuntimeStateAuthorityReviewOutcome::RuntimeStateRejected => {
                Self::RuntimeStateRejected
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ModuleRuntimeStateAuthorityDecision {
    Accepted {
        state: ManifoldModuleRuntimeState,
        transition: ManifoldModuleRuntimeTransition,
    },
    Rejected {
        rejection_code: String,
        message: String,
        retryable: bool,
        current_runtime_revision: Option<Revision>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ModuleRuntimeStateRejection {
    rejection_code: String,
    message: String,
    retryable: bool,
}

impl ModuleRuntimeStateRejection {
    fn new(rejection_code: impl Into<String>, message: impl Into<String>, retryable: bool) -> Self {
        Self {
            rejection_code: rejection_code.into(),
            message: message.into(),
            retryable,
        }
    }
}

impl ManifoldAuthoritySnapshot {
    /// Deterministically reviews one module runtime-state change request.
    ///
    /// The review is source-only: it accepts or rejects proposed contract state
    /// and computes the resulting transition without starting, stopping, or
    /// contacting a runtime module.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the authority snapshot
    /// itself is invalid, the review clock is inconsistent, or evidence refs are empty.
    pub fn review_module_runtime_state_change(
        &self,
        request: ManifoldModuleRuntimeStateChangeRequest,
        recorded_clock: ManifoldClockSnapshot,
        evidence_refs: Vec<DottedId>,
    ) -> Result<ManifoldModuleRuntimeStateAuthorityReview, ManifoldAuthorityValidationError> {
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

        let decision = self.module_runtime_state_authority_decision(&request, &recorded_clock);
        let lease = request
            .lease_id
            .as_ref()
            .and_then(|lease_id| self.active_lease(lease_id))
            .cloned();
        let runtime_revision = self
            .module_runtime_state(&request.module_id)
            .map(|state| state.runtime_revision);
        let (outcome, accepted, transition, rejection) = match decision {
            ModuleRuntimeStateAuthorityDecision::Accepted { state, transition } => (
                ManifoldModuleRuntimeStateAuthorityReviewOutcome::RuntimeStateAccepted,
                Some(state),
                Some(transition),
                None,
            ),
            ModuleRuntimeStateAuthorityDecision::Rejected {
                rejection_code,
                message,
                retryable,
                current_runtime_revision,
            } => (
                ManifoldModuleRuntimeStateAuthorityReviewOutcome::RuntimeStateRejected,
                None,
                None,
                Some(ManifoldModuleRuntimeStateRejection {
                    schema_id: module_runtime_state_rejection_schema_id(),
                    request_id: request.request_id.clone(),
                    rejection_code: DottedId::new(rejection_code)
                        .expect("rejection code is a valid dotted id"),
                    message,
                    retryable,
                    current_authority_revision: self.authority_revision,
                    current_runtime_revision,
                }),
            ),
        };

        let audit_event = ManifoldModuleRuntimeStateAuthorityAuditEvent {
            schema_id: module_runtime_state_authority_audit_event_schema_id(),
            event_id: module_runtime_state_authority_audit_event_id(&request.request_id, outcome),
            authority_id: self.authority_id.clone(),
            prior_authority_revision: self.authority_revision,
            module_id: request.module_id.clone(),
            prior_runtime_revision: runtime_revision,
            event_kind: outcome.into(),
            request,
            accepted: accepted.clone(),
            transition: transition.clone(),
            rejection: rejection.clone(),
            lease,
            recorded_clock,
            evidence_refs,
        };

        let review = ManifoldModuleRuntimeStateAuthorityReview {
            schema_id: module_runtime_state_authority_review_schema_id(),
            review_id: module_runtime_state_authority_review_id(&audit_event.request.request_id),
            authority_id: self.authority_id.clone(),
            authority_revision: self.authority_revision,
            module_id: audit_event.module_id.clone(),
            runtime_revision,
            outcome,
            accepted,
            transition,
            rejection,
            audit_event,
        };
        review.validate_against_snapshot(self)?;
        Ok(review)
    }

    /// Deterministically applies one module runtime-state authority review to this snapshot.
    ///
    /// Accepted runtime-state reviews produce a new `ManifoldAuthoritySnapshot`
    /// with the authority revision advanced by one and the accepted module
    /// runtime state installed. Rejected reviews produce a machine-readable
    /// application rejection and leave accepted state unchanged. This is
    /// source-only: it does not start, stop, load, unload, signal, or contact a
    /// runtime module.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when this authority snapshot
    /// itself is invalid.
    pub fn apply_module_runtime_state_authority_review(
        &self,
        review: ManifoldModuleRuntimeStateAuthorityReview,
    ) -> Result<ManifoldModuleRuntimeStateAuthorityApplication, ManifoldAuthorityValidationError>
    {
        self.validate_authority_links()?;

        let application_id = module_runtime_state_authority_application_id(&review.review_id);
        let from_authority_revision = self.authority_revision;
        let module_id = review.module_id.clone();
        let from_runtime_revision = self
            .module_runtime_state(&module_id)
            .map(|state| state.runtime_revision);

        let (outcome, applied_snapshot, rejection) =
            match review.validate_against_snapshot(self) {
                Err(error) => (
                    ManifoldModuleRuntimeStateAuthorityApplicationOutcome::RuntimeStateApplicationRejected,
                    None,
                    Some(ManifoldAuthoritySnapshotApplicationRejection {
                        schema_id: authority_snapshot_application_rejection_schema_id(),
                        application_id: application_id.clone(),
                        rejection_code: DottedId::new(error.rejection_code())
                            .expect("authority rejection code is a valid dotted id"),
                        message: format!(
                            "module runtime-state review does not match authority snapshot: {error}"
                        ),
                        retryable: authority_application_validation_retryable(error.kind()),
                        current_authority_revision: self.authority_revision,
                    }),
                ),
                Ok(()) if review.outcome
                    == ManifoldModuleRuntimeStateAuthorityReviewOutcome::RuntimeStateRejected =>
                {
                    (
                        ManifoldModuleRuntimeStateAuthorityApplicationOutcome::RuntimeStateApplicationRejected,
                        None,
                        Some(ManifoldAuthoritySnapshotApplicationRejection {
                            schema_id: authority_snapshot_application_rejection_schema_id(),
                            application_id: application_id.clone(),
                            rejection_code: DottedId::new("review_rejected")
                                .expect("rejection code literal is valid"),
                            message: "module runtime-state review did not accept runtime state"
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
                    let accepted_state = review.accepted.clone().ok_or_else(|| {
                        ManifoldAuthorityValidationError::new(
                            review.review_id.clone(),
                            "accepted".to_owned(),
                            ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                        )
                    })?;
                    let mut next_snapshot = self.clone();
                    next_snapshot.authority_revision = next_authority_revision;
                    let Some(state) = next_snapshot
                        .module_runtime_states
                        .iter_mut()
                        .find(|state| state.module_id == accepted_state.module_id)
                    else {
                        return Err(ManifoldAuthorityValidationError::new(
                            review.review_id.clone(),
                            accepted_state.module_id.to_string(),
                            ManifoldAuthorityValidationErrorKind::UnknownModule,
                        ));
                    };
                    *state = accepted_state;
                    next_snapshot.validate_authority_links()?;
                    (
                        ManifoldModuleRuntimeStateAuthorityApplicationOutcome::RuntimeStateApplied,
                        Some(next_snapshot),
                        None,
                    )
                }
            };

        let application = ManifoldModuleRuntimeStateAuthorityApplication {
            schema_id: module_runtime_state_authority_application_schema_id(),
            application_id,
            authority_id: self.authority_id.clone(),
            from_authority_revision,
            module_id,
            from_runtime_revision,
            outcome,
            applied_snapshot,
            rejection,
            review,
        };
        application.validate_against_snapshot(self)?;
        Ok(application)
    }

    fn module_runtime_state_authority_decision(
        &self,
        request: &ManifoldModuleRuntimeStateChangeRequest,
        recorded_clock: &ManifoldClockSnapshot,
    ) -> ModuleRuntimeStateAuthorityDecision {
        if request.schema_id != module_runtime_state_change_request_schema_id() {
            return ModuleRuntimeStateAuthorityDecision::Rejected {
                rejection_code: "unsupported_schema".to_owned(),
                message: "module runtime-state request schema is not supported".to_owned(),
                retryable: false,
                current_runtime_revision: self
                    .module_runtime_state(&request.module_id)
                    .map(|state| state.runtime_revision),
            };
        }

        if request.expected_authority_revision != self.authority_revision {
            return ModuleRuntimeStateAuthorityDecision::Rejected {
                rejection_code: "stale_revision".to_owned(),
                message: "module runtime-state request expected authority revision does not match current revision"
                    .to_owned(),
                retryable: true,
                current_runtime_revision: self
                    .module_runtime_state(&request.module_id)
                    .map(|state| state.runtime_revision),
            };
        }

        if !self
            .host_manifest
            .capabilities
            .iter()
            .any(|capability| capability == &request.required_capability)
        {
            return ModuleRuntimeStateAuthorityDecision::Rejected {
                rejection_code: "capability_not_advertised".to_owned(),
                message:
                    "module runtime-state request capability is not advertised by the authority host"
                        .to_owned(),
                retryable: false,
                current_runtime_revision: self
                    .module_runtime_state(&request.module_id)
                    .map(|state| state.runtime_revision),
            };
        }

        if request.proposed_state.module_id != request.module_id {
            return ModuleRuntimeStateAuthorityDecision::Rejected {
                rejection_code: "module_id_mismatch".to_owned(),
                message: "module runtime-state request module id does not match proposed state"
                    .to_owned(),
                retryable: false,
                current_runtime_revision: self
                    .module_runtime_state(&request.module_id)
                    .map(|state| state.runtime_revision),
            };
        }

        let Some(current_state) = self.module_runtime_state(&request.module_id) else {
            return ModuleRuntimeStateAuthorityDecision::Rejected {
                rejection_code: "unknown_module".to_owned(),
                message:
                    "module runtime-state request targets a module absent from authority state"
                        .to_owned(),
                retryable: true,
                current_runtime_revision: None,
            };
        };

        let Some(lease_id) = &request.lease_id else {
            return ModuleRuntimeStateAuthorityDecision::Rejected {
                rejection_code: "missing_lease".to_owned(),
                message: "module runtime-state change requires an active module lease".to_owned(),
                retryable: true,
                current_runtime_revision: Some(current_state.runtime_revision),
            };
        };

        let Some(lease) = self.active_lease(lease_id) else {
            return ModuleRuntimeStateAuthorityDecision::Rejected {
                rejection_code: "unknown_lease".to_owned(),
                message: "module runtime-state request references an unknown lease".to_owned(),
                retryable: true,
                current_runtime_revision: Some(current_state.runtime_revision),
            };
        };

        if lease.state != LeaseState::Active {
            return ModuleRuntimeStateAuthorityDecision::Rejected {
                rejection_code: "inactive_lease".to_owned(),
                message: "module runtime-state lease is not active".to_owned(),
                retryable: true,
                current_runtime_revision: Some(current_state.runtime_revision),
            };
        }

        if lease_expired_at(lease, recorded_clock) {
            return ModuleRuntimeStateAuthorityDecision::Rejected {
                rejection_code: "expired_lease".to_owned(),
                message: "module runtime-state lease is expired at the review clock".to_owned(),
                retryable: true,
                current_runtime_revision: Some(current_state.runtime_revision),
            };
        }

        if lease.granted_revision > self.authority_revision {
            return ModuleRuntimeStateAuthorityDecision::Rejected {
                rejection_code: "lease_revision_ahead".to_owned(),
                message: "module runtime-state lease was granted after this authority revision"
                    .to_owned(),
                retryable: true,
                current_runtime_revision: Some(current_state.runtime_revision),
            };
        }

        if lease.holder_id != request.holder_id
            || lease.scope != request.module_id
            || lease.required_capability != request.required_capability
        {
            return ModuleRuntimeStateAuthorityDecision::Rejected {
                rejection_code: "lease_mismatch".to_owned(),
                message: "module runtime-state request does not match the active lease".to_owned(),
                retryable: true,
                current_runtime_revision: Some(current_state.runtime_revision),
            };
        }

        match self.validate_proposed_module_runtime_state(current_state, &request.proposed_state) {
            Ok(transition) => ModuleRuntimeStateAuthorityDecision::Accepted {
                state: request.proposed_state.clone(),
                transition,
            },
            Err(rejection) => ModuleRuntimeStateAuthorityDecision::Rejected {
                rejection_code: rejection.rejection_code,
                message: rejection.message,
                retryable: rejection.retryable,
                current_runtime_revision: Some(current_state.runtime_revision),
            },
        }
    }

    fn validate_proposed_module_runtime_state(
        &self,
        current_state: &ManifoldModuleRuntimeState,
        proposed_state: &ManifoldModuleRuntimeState,
    ) -> Result<ManifoldModuleRuntimeTransition, ModuleRuntimeStateRejection> {
        if proposed_state.schema_id != module_runtime_state_schema_id() {
            return Err(ModuleRuntimeStateRejection::new(
                "unsupported_schema",
                "module runtime-state schema is not supported",
                false,
            ));
        }

        if proposed_state.module_id != current_state.module_id {
            return Err(ModuleRuntimeStateRejection::new(
                "module_id_mismatch",
                "module runtime-state proposal targets a different module",
                false,
            ));
        }

        if proposed_state.runtime_revision
            != current_state.runtime_revision.next().ok_or_else(|| {
                ModuleRuntimeStateRejection::new(
                    "runtime_revision_mismatch",
                    "module runtime revision cannot advance",
                    false,
                )
            })?
        {
            return Err(ModuleRuntimeStateRejection::new(
                "runtime_revision_mismatch",
                "module runtime-state proposal must advance the runtime revision by one",
                true,
            ));
        }

        if let Some(backend) = &proposed_state.selected_backend {
            if !self
                .host_manifest
                .supported_backends
                .iter()
                .any(|known| known == backend)
            {
                return Err(ModuleRuntimeStateRejection::new(
                    "missing_backend",
                    "module runtime-state proposal selects a backend absent from the authority host",
                    false,
                ));
            }
        }

        if proposed_state.lifecycle == ModuleLifecycleState::Stopped
            && !proposed_state.active_streams.is_empty()
        {
            return Err(ModuleRuntimeStateRejection::new(
                "lifecycle_state_conflict",
                "stopped module runtime-state cannot report active streams",
                true,
            ));
        }

        for stream_id in &proposed_state.active_streams {
            let Some(stream) = self
                .stream_registry
                .streams
                .iter()
                .find(|stream| &stream.stream_id == stream_id)
            else {
                return Err(ModuleRuntimeStateRejection::new(
                    "unknown_stream",
                    "module runtime-state proposal references an unknown active stream",
                    true,
                ));
            };

            if stream.source_module_id != proposed_state.module_id {
                return Err(ModuleRuntimeStateRejection::new(
                    "stream_owner_mismatch",
                    "module runtime-state proposal claims a stream owned by another module",
                    false,
                ));
            }
        }

        for command_id in &proposed_state.active_commands {
            if !self.command_ids.iter().any(|known| known == command_id) {
                return Err(ModuleRuntimeStateRejection::new(
                    "unknown_command",
                    "module runtime-state proposal references an unknown active command",
                    true,
                ));
            }
        }

        let transition = proposed_state.transition_from(current_state);
        if module_runtime_transition_is_empty(&transition) {
            return Err(ModuleRuntimeStateRejection::new(
                "empty_runtime_transition",
                "module runtime-state proposal has no lifecycle, health, backend, stream, command, or issue changes",
                false,
            ));
        }

        Ok(transition)
    }
}
