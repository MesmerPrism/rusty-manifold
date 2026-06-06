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

/// Request to subscribe to one accepted stream transport offer.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamSubscriptionRequest {
    /// Schema identifier for this request.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Request id.
    pub request_id: DottedId,
    /// Subscriber id.
    pub subscriber_id: DottedId,
    /// Subscriber class used for manifest policy checks.
    pub subscriber_kind: ManifoldStreamSubscriberKind,
    /// Expected authority revision.
    pub expected_authority_revision: Revision,
    /// Expected stream-registry revision.
    pub expected_registry_revision: Revision,
    /// Stream to subscribe to.
    pub stream_id: DottedId,
    /// Transport offer selected by the subscriber.
    pub transport_id: DottedId,
    /// Requested time-to-live in milliseconds.
    pub requested_ttl_ms: u64,
    /// Capability required to admit this subscription.
    pub required_capability: DottedId,
    /// Request timestamp in milliseconds in the subscriber's chosen clock domain.
    pub requested_at_ms: u64,
}

/// Accepted stream subscription.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamSubscription {
    /// Schema identifier for this subscription.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable subscription id.
    pub subscription_id: DottedId,
    /// Request id that created this subscription.
    pub request_id: DottedId,
    /// Subscriber id.
    pub subscriber_id: DottedId,
    /// Subscriber class admitted by policy.
    pub subscriber_kind: ManifoldStreamSubscriberKind,
    /// Stream being subscribed to.
    pub stream_id: DottedId,
    /// Transport offer selected for the subscription.
    pub transport_id: DottedId,
    /// Endpoint used by the transport offer, when endpoint-bound.
    pub endpoint_id: Option<DottedId>,
    /// Subscription state.
    pub state: ManifoldStreamSubscriptionState,
    /// Authority revision at which the subscription was accepted.
    pub accepted_authority_revision: Revision,
    /// Registry revision at which the stream offer was accepted.
    pub accepted_registry_revision: Revision,
    /// Acceptance timestamp in milliseconds.
    pub accepted_at_ms: u64,
    /// Expiration timestamp in milliseconds.
    pub expires_at_ms: u64,
    /// Capability used to admit the subscription.
    pub required_capability: DottedId,
}

/// Rejected stream subscription request result.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamSubscriptionRejection {
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
    /// Active subscriber count observed for the requested stream.
    pub active_subscriber_count: u32,
}

/// Request to release one accepted active stream subscription.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamSubscriptionReleaseRequest {
    /// Schema identifier for this request.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Request id.
    pub request_id: DottedId,
    /// Subscription to release.
    pub subscription_id: DottedId,
    /// Subscriber id expected to own the subscription.
    pub subscriber_id: DottedId,
    /// Expected authority revision.
    pub expected_authority_revision: Revision,
    /// Expected stream-registry revision.
    pub expected_registry_revision: Revision,
    /// Stream expected to own the subscription.
    pub stream_id: DottedId,
    /// Machine-readable reason for releasing the subscription.
    pub release_reason: DottedId,
    /// Request timestamp in milliseconds in the subscriber's chosen clock domain.
    pub requested_at_ms: u64,
}

/// Rejected stream subscription release request result.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamSubscriptionReleaseRejection {
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
    /// Active subscriber count observed for the requested stream.
    pub active_subscriber_count: u32,
}

/// Request to renew one accepted active stream subscription.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamSubscriptionRenewalRequest {
    /// Schema identifier for this request.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Request id.
    pub request_id: DottedId,
    /// Subscription to renew.
    pub subscription_id: DottedId,
    /// Subscriber id expected to own the subscription.
    pub subscriber_id: DottedId,
    /// Expected authority revision.
    pub expected_authority_revision: Revision,
    /// Expected stream-registry revision.
    pub expected_registry_revision: Revision,
    /// Stream expected to own the subscription.
    pub stream_id: DottedId,
    /// Transport offer expected by the subscriber.
    pub transport_id: DottedId,
    /// Requested subscription duration from the review clock wall time.
    pub requested_ttl_ms: u64,
    /// Machine-readable reason for renewing the subscription.
    pub renewal_reason: DottedId,
    /// Request timestamp in milliseconds in the subscriber's chosen clock domain.
    pub requested_at_ms: u64,
}

/// Rejected stream subscription renewal request result.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamSubscriptionRenewalRejection {
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
    /// Active subscriber count observed for the requested stream.
    pub active_subscriber_count: u32,
    /// Current expiration, when the referenced active subscription was known.
    pub current_expires_at_ms: Option<u64>,
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

/// Machine-readable rejection for applying an authority review to accepted state.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldAuthoritySnapshotApplicationRejection {
    /// Schema identifier for this rejection.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Application that was rejected.
    pub application_id: DottedId,
    /// Stable rejection code.
    pub rejection_code: DottedId,
    /// Display-safe rejection message.
    pub message: String,
    /// Whether retrying after refreshing state may help.
    pub retryable: bool,
    /// Current authority revision observed by the application attempt.
    pub current_authority_revision: Revision,
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

/// Stream subscription renewal authority audit event.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamSubscriptionRenewalAuthorityAuditEvent {
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
    pub event_kind: ManifoldStreamSubscriptionRenewalAuthorityAuditEventKind,
    /// Renewal request reviewed by authority.
    pub request: ManifoldStreamSubscriptionRenewalRequest,
    /// Renewed subscription. Present only for accepted renewal events.
    pub renewed: Option<ManifoldStreamSubscription>,
    /// Rejected renewal result. Present only for rejected events.
    pub rejection: Option<ManifoldStreamSubscriptionRenewalRejection>,
    /// Clock snapshot recorded with the decision.
    pub recorded_clock: ManifoldClockSnapshot,
    /// Stable ids for fixtures, scorecards, or logs backing the event.
    pub evidence_refs: Vec<DottedId>,
}

/// Deterministic review result for one stream subscription renewal authority decision.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamSubscriptionRenewalAuthorityReview {
    /// Schema identifier for this review.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable review id.
    pub review_id: DottedId,
    /// Authority that reviewed the renewal request.
    pub authority_id: DottedId,
    /// Authority revision used by this review.
    pub authority_revision: Revision,
    /// Stream-registry revision used by this review.
    pub registry_revision: Revision,
    /// Review outcome.
    pub outcome: ManifoldStreamSubscriptionRenewalAuthorityReviewOutcome,
    /// Renewed subscription. Present only for accepted renewal reviews.
    pub renewed: Option<ManifoldStreamSubscription>,
    /// Rejected renewal result. Present only for rejected renewal reviews.
    pub rejection: Option<ManifoldStreamSubscriptionRenewalRejection>,
    /// Audit event for the same renewal decision.
    pub audit_event: ManifoldStreamSubscriptionRenewalAuthorityAuditEvent,
}

impl ManifoldStreamSubscriptionRenewalAuthorityReview {
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
            != "rusty.manifold.authority.stream_subscription_renewal_review.v1"
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
            ManifoldStreamSubscriptionRenewalAuthorityReviewOutcome::SubscriptionRenewed => {
                if self.renewed.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.review_id.clone(),
                        "renewed".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
            ManifoldStreamSubscriptionRenewalAuthorityReviewOutcome::SubscriptionRenewalRejected => {
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

        if ManifoldStreamSubscriptionRenewalAuthorityAuditEventKind::from(self.outcome)
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

impl ManifoldStreamSubscriptionRenewalAuthorityAuditEvent {
    /// Validates this event against the authority snapshot it claims to use.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the event is not a
    /// consistent subscription renewal or rejection for the supplied snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str()
            != "rusty.manifold.authority.stream_subscription_renewal_audit_event.v1"
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
            ManifoldStreamSubscriptionRenewalAuthorityAuditEventKind::SubscriptionRenewed => {
                if self.renewed.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        "renewed".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
            ManifoldStreamSubscriptionRenewalAuthorityAuditEventKind::SubscriptionRenewalRejected => {
                if self.renewed.is_some() || self.rejection.is_none() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
        }

        let expected_decision = snapshot
            .stream_subscription_renewal_authority_decision(&self.request, &self.recorded_clock);

        if let Some(renewed) = &self.renewed {
            let StreamSubscriptionRenewalAuthorityDecision::Renewed(expected_subscription) =
                &expected_decision
            else {
                let rejected_value = match &expected_decision {
                    StreamSubscriptionRenewalAuthorityDecision::Rejected {
                        rejection_code, ..
                    } => rejection_code.clone(),
                    StreamSubscriptionRenewalAuthorityDecision::Renewed(_) => "renewed".to_owned(),
                };
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejected_value.clone(),
                    authority_error_kind_for_stream_subscription_renewal_rejection_code(
                        &rejected_value,
                    ),
                ));
            };

            if renewed != expected_subscription {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    renewed.subscription_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::SubscriptionMismatch,
                ));
            }
        }

        if let Some(rejection) = &self.rejection {
            let StreamSubscriptionRenewalAuthorityDecision::Rejected {
                rejection_code,
                message,
                retryable,
                active_subscriber_count,
                current_expires_at_ms,
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
                || rejection.current_expires_at_ms != *current_expires_at_ms
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

/// Deterministic application result for one stream subscription renewal authority review.
///
/// This records the bridge from review-time renewal authority to accepted
/// authority state without owning live transport setup, callbacks, or provider
/// runtime work.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamSubscriptionRenewalAuthorityApplication {
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
    /// Subscription renewed by the reviewed request.
    pub subscription_id: DottedId,
    /// Active subscriber count before applying the review.
    pub from_active_subscriber_count: u32,
    /// Application outcome.
    pub outcome: ManifoldStreamSubscriptionRenewalAuthorityApplicationOutcome,
    /// Next accepted authority snapshot. Present only for applied outcomes.
    pub applied_snapshot: Option<ManifoldAuthoritySnapshot>,
    /// Rejection. Present only for rejected application outcomes.
    pub rejection: Option<ManifoldAuthoritySnapshotApplicationRejection>,
    /// Review that was applied or rejected for application.
    pub review: ManifoldStreamSubscriptionRenewalAuthorityReview,
}

impl ManifoldStreamSubscriptionRenewalAuthorityApplication {
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
            != "rusty.manifold.authority.stream_subscription_renewal_application.v1"
        {
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
            ManifoldStreamSubscriptionRenewalAuthorityApplicationOutcome::SubscriptionRenewalApplied => {
                if self.applied_snapshot.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        "applied_snapshot".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                if self.review.outcome
                    != ManifoldStreamSubscriptionRenewalAuthorityReviewOutcome::SubscriptionRenewed
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

                let renewed_subscription = self.review.renewed.clone().ok_or_else(|| {
                    ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        "renewed".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    )
                })?;
                let mut expected_subscriptions = snapshot.active_stream_subscriptions.clone();
                let Some(position) = expected_subscriptions.iter().position(|subscription| {
                    subscription.subscription_id == renewed_subscription.subscription_id
                }) else {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        renewed_subscription.subscription_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::UnknownSubscription,
                    ));
                };
                expected_subscriptions[position] = renewed_subscription;
                if applied.active_stream_subscriptions != expected_subscriptions {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        self.stream_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::SubscriptionMismatch,
                    ));
                }

                applied.validate_authority_links()
            }
            ManifoldStreamSubscriptionRenewalAuthorityApplicationOutcome::SubscriptionRenewalApplicationRejected => {
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
                    == ManifoldStreamSubscriptionRenewalAuthorityReviewOutcome::SubscriptionRenewalRejected
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

/// A stream transport offer.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportOffer {
    /// Transport id.
    pub transport_id: DottedId,
    /// Transport kind.
    pub transport: EndpointTransport,
    /// Endpoint id, if the offer is endpoint-bound.
    pub endpoint_id: Option<DottedId>,
}

/// Stream subscription policy.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubscriptionPolicy {
    /// Whether UI or dashboard clients may subscribe directly.
    pub ui_subscribable: bool,
    /// Maximum subscribers, if bounded.
    pub max_subscribers: Option<u32>,
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

/// Stream subscription authority audit event kind.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldStreamSubscriptionAuthorityAuditEventKind {
    /// Authority accepted a subscription request.
    SubscriptionAccepted,
    /// Authority rejected a subscription request.
    SubscriptionRejected,
}

/// Stream subscription release authority audit event kind.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldStreamSubscriptionReleaseAuthorityAuditEventKind {
    /// Authority accepted a subscription release request.
    SubscriptionReleased,
    /// Authority rejected a subscription release request.
    SubscriptionReleaseRejected,
}

/// Stream subscription renewal authority audit event kind.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldStreamSubscriptionRenewalAuthorityAuditEventKind {
    /// Authority accepted a subscription renewal request.
    SubscriptionRenewed,
    /// Authority rejected a subscription renewal request.
    SubscriptionRenewalRejected,
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

/// Stream subscription authority review outcome.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldStreamSubscriptionAuthorityReviewOutcome {
    /// Authority accepted the subscription request.
    SubscriptionAccepted,
    /// Authority rejected the subscription request.
    SubscriptionRejected,
}

impl From<ManifoldStreamSubscriptionAuthorityReviewOutcome>
    for ManifoldStreamSubscriptionAuthorityAuditEventKind
{
    fn from(outcome: ManifoldStreamSubscriptionAuthorityReviewOutcome) -> Self {
        match outcome {
            ManifoldStreamSubscriptionAuthorityReviewOutcome::SubscriptionAccepted => {
                Self::SubscriptionAccepted
            }
            ManifoldStreamSubscriptionAuthorityReviewOutcome::SubscriptionRejected => {
                Self::SubscriptionRejected
            }
        }
    }
}

/// Stream subscription authority application outcome.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldStreamSubscriptionAuthorityApplicationOutcome {
    /// Accepted stream subscription review was applied to the authority snapshot.
    SubscriptionApplied,
    /// Stream subscription review could not be applied to accepted authority state.
    SubscriptionApplicationRejected,
}

/// Stream subscription release authority review outcome.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldStreamSubscriptionReleaseAuthorityReviewOutcome {
    /// Authority accepted the subscription release request.
    SubscriptionReleased,
    /// Authority rejected the subscription release request.
    SubscriptionReleaseRejected,
}

impl From<ManifoldStreamSubscriptionReleaseAuthorityReviewOutcome>
    for ManifoldStreamSubscriptionReleaseAuthorityAuditEventKind
{
    fn from(outcome: ManifoldStreamSubscriptionReleaseAuthorityReviewOutcome) -> Self {
        match outcome {
            ManifoldStreamSubscriptionReleaseAuthorityReviewOutcome::SubscriptionReleased => {
                Self::SubscriptionReleased
            }
            ManifoldStreamSubscriptionReleaseAuthorityReviewOutcome::SubscriptionReleaseRejected => {
                Self::SubscriptionReleaseRejected
            }
        }
    }
}

/// Stream subscription release authority application outcome.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldStreamSubscriptionReleaseAuthorityApplicationOutcome {
    /// Accepted stream subscription release review was applied to the authority snapshot.
    SubscriptionReleaseApplied,
    /// Stream subscription release review could not be applied to accepted authority state.
    SubscriptionReleaseApplicationRejected,
}

/// Stream subscription renewal authority review outcome.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldStreamSubscriptionRenewalAuthorityReviewOutcome {
    /// Authority accepted the subscription renewal request.
    SubscriptionRenewed,
    /// Authority rejected the subscription renewal request.
    SubscriptionRenewalRejected,
}

impl From<ManifoldStreamSubscriptionRenewalAuthorityReviewOutcome>
    for ManifoldStreamSubscriptionRenewalAuthorityAuditEventKind
{
    fn from(outcome: ManifoldStreamSubscriptionRenewalAuthorityReviewOutcome) -> Self {
        match outcome {
            ManifoldStreamSubscriptionRenewalAuthorityReviewOutcome::SubscriptionRenewed => {
                Self::SubscriptionRenewed
            }
            ManifoldStreamSubscriptionRenewalAuthorityReviewOutcome::SubscriptionRenewalRejected => {
                Self::SubscriptionRenewalRejected
            }
        }
    }
}

/// Stream subscription renewal authority application outcome.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldStreamSubscriptionRenewalAuthorityApplicationOutcome {
    /// Accepted stream subscription renewal review was applied to the authority snapshot.
    SubscriptionRenewalApplied,
    /// Stream subscription renewal review could not be applied to accepted authority state.
    SubscriptionRenewalApplicationRejected,
}

/// Stream subscriber kind.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldStreamSubscriberKind {
    /// UI or dashboard subscriber.
    Ui,
    /// Runtime module subscriber.
    Runtime,
    /// Agent or CLI subscriber.
    Agent,
}

/// Accepted stream subscription state.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldStreamSubscriptionState {
    /// Subscription is active and counts against the stream limit.
    Active,
    /// Subscription was released by the subscriber or authority.
    Released,
    /// Subscription expired by TTL.
    Expired,
}

/// Stream registry validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamRegistryValidationError {
    stream_id: DottedId,
    rejected_id: DottedId,
    kind: StreamRegistryValidationErrorKind,
}

impl StreamRegistryValidationError {
    /// Returns the affected stream id.
    #[must_use]
    pub fn stream_id(&self) -> &DottedId {
        &self.stream_id
    }

    /// Returns the missing or invalid source module id.
    #[must_use]
    pub fn source_module_id(&self) -> &DottedId {
        &self.rejected_id
    }

    /// Returns the rejected module or endpoint id.
    #[must_use]
    pub fn rejected_id(&self) -> &DottedId {
        &self.rejected_id
    }

    /// Returns the failure kind.
    #[must_use]
    pub const fn kind(&self) -> StreamRegistryValidationErrorKind {
        self.kind
    }

    /// Returns a stable rejection code.
    #[must_use]
    pub const fn rejection_code(&self) -> &'static str {
        match self.kind {
            StreamRegistryValidationErrorKind::UnknownModuleLink => "unknown_module_link",
            StreamRegistryValidationErrorKind::UnknownTransportEndpoint => {
                "unknown_transport_endpoint"
            }
        }
    }
}

impl fmt::Display for StreamRegistryValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "stream {} contains invalid reference {}: {:?}",
            self.stream_id, self.rejected_id, self.kind
        )
    }
}

impl std::error::Error for StreamRegistryValidationError {}

/// Stream registry validation failure kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamRegistryValidationErrorKind {
    /// A stream references a source module that is not known to the registry.
    UnknownModuleLink,
    /// A transport offer references an endpoint not advertised by the host.
    UnknownTransportEndpoint,
}
