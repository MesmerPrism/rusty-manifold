use super::*;

mod registry;
mod subscription;
mod subscription_release;
mod subscription_renewal;

pub use self::registry::*;
pub use self::subscription::*;
pub use self::subscription_release::*;
pub use self::subscription_renewal::*;

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
enum StreamSubscriptionAuthorityDecision {
    Accepted(ManifoldStreamSubscription),
    Rejected {
        rejection_code: String,
        message: String,
        retryable: bool,
        active_subscriber_count: u32,
    },
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

#[derive(Clone, Debug, Eq, PartialEq)]
enum StreamSubscriptionRenewalAuthorityDecision {
    Renewed(ManifoldStreamSubscription),
    Rejected {
        rejection_code: String,
        message: String,
        retryable: bool,
        active_subscriber_count: u32,
        current_expires_at_ms: Option<u64>,
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

    /// Deterministically reviews one active stream subscription renewal request.
    ///
    /// The review is source-only: it verifies renewal preconditions against
    /// accepted authority state and records the renewed subscription, but it
    /// does not open transports, notify subscribers, or contact providers.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the authority snapshot
    /// itself is invalid, the review clock is inconsistent, or evidence refs are empty.
    pub fn review_stream_subscription_renewal(
        &self,
        request: ManifoldStreamSubscriptionRenewalRequest,
        recorded_clock: ManifoldClockSnapshot,
        evidence_refs: Vec<DottedId>,
    ) -> Result<ManifoldStreamSubscriptionRenewalAuthorityReview, ManifoldAuthorityValidationError>
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
            self.stream_subscription_renewal_authority_decision(&request, &recorded_clock);
        let active_subscriber_count = self.active_subscription_count(&request.stream_id);
        let (outcome, renewed, rejection) = match decision {
            StreamSubscriptionRenewalAuthorityDecision::Renewed(subscription) => (
                ManifoldStreamSubscriptionRenewalAuthorityReviewOutcome::SubscriptionRenewed,
                Some(subscription),
                None,
            ),
            StreamSubscriptionRenewalAuthorityDecision::Rejected {
                rejection_code,
                message,
                retryable,
                active_subscriber_count,
                current_expires_at_ms,
            } => (
                ManifoldStreamSubscriptionRenewalAuthorityReviewOutcome::SubscriptionRenewalRejected,
                None,
                Some(ManifoldStreamSubscriptionRenewalRejection {
                    schema_id: stream_subscription_renewal_rejection_schema_id(),
                    request_id: request.request_id.clone(),
                    rejection_code: DottedId::new(rejection_code)
                        .expect("rejection code is a valid dotted id"),
                    message,
                    retryable,
                    current_authority_revision: self.authority_revision,
                    current_registry_revision: self.stream_registry.registry_revision,
                    active_subscriber_count,
                    current_expires_at_ms,
                }),
            ),
        };

        let audit_event = ManifoldStreamSubscriptionRenewalAuthorityAuditEvent {
            schema_id: stream_subscription_renewal_authority_audit_event_schema_id(),
            event_id: stream_subscription_renewal_authority_audit_event_id(
                &request.request_id,
                outcome,
            ),
            authority_id: self.authority_id.clone(),
            prior_authority_revision: self.authority_revision,
            prior_registry_revision: self.stream_registry.registry_revision,
            active_subscriber_count,
            event_kind: outcome.into(),
            request,
            renewed: renewed.clone(),
            rejection: rejection.clone(),
            recorded_clock,
            evidence_refs,
        };

        let review = ManifoldStreamSubscriptionRenewalAuthorityReview {
            schema_id: stream_subscription_renewal_authority_review_schema_id(),
            review_id: stream_subscription_renewal_authority_review_id(
                &audit_event.request.request_id,
            ),
            authority_id: self.authority_id.clone(),
            authority_revision: self.authority_revision,
            registry_revision: self.stream_registry.registry_revision,
            outcome,
            renewed,
            rejection,
            audit_event,
        };
        review.validate_against_snapshot(self)?;
        Ok(review)
    }

    /// Deterministically applies one stream subscription renewal authority review.
    ///
    /// Accepted renewal reviews produce a new `ManifoldAuthoritySnapshot` with
    /// the authority revision advanced by one and the renewed subscription
    /// replacing the matching active subscription. Rejected reviews produce a
    /// machine-readable application rejection and leave accepted state unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when this authority snapshot
    /// itself is invalid.
    pub fn apply_stream_subscription_renewal_authority_review(
        &self,
        review: ManifoldStreamSubscriptionRenewalAuthorityReview,
    ) -> Result<
        ManifoldStreamSubscriptionRenewalAuthorityApplication,
        ManifoldAuthorityValidationError,
    > {
        self.validate_authority_links()?;

        let application_id =
            stream_subscription_renewal_authority_application_id(&review.review_id);
        let from_authority_revision = self.authority_revision;
        let from_registry_revision = self.stream_registry.registry_revision;
        let stream_id = review.audit_event.request.stream_id.clone();
        let subscription_id = review.audit_event.request.subscription_id.clone();
        let from_active_subscriber_count = self.active_subscription_count(&stream_id);

        let (outcome, applied_snapshot, rejection) = match review.validate_against_snapshot(self) {
            Err(error) => (
                ManifoldStreamSubscriptionRenewalAuthorityApplicationOutcome::SubscriptionRenewalApplicationRejected,
                None,
                Some(ManifoldAuthoritySnapshotApplicationRejection {
                    schema_id: authority_snapshot_application_rejection_schema_id(),
                    application_id: application_id.clone(),
                    rejection_code: DottedId::new(error.rejection_code())
                        .expect("authority rejection code is a valid dotted id"),
                    message: format!(
                        "stream subscription renewal review does not match authority snapshot: {error}"
                    ),
                    retryable: authority_application_validation_retryable(error.kind()),
                    current_authority_revision: self.authority_revision,
                }),
            ),
            Ok(())
                if review.outcome
                    == ManifoldStreamSubscriptionRenewalAuthorityReviewOutcome::SubscriptionRenewalRejected =>
            {
                (
                    ManifoldStreamSubscriptionRenewalAuthorityApplicationOutcome::SubscriptionRenewalApplicationRejected,
                    None,
                    Some(ManifoldAuthoritySnapshotApplicationRejection {
                        schema_id: authority_snapshot_application_rejection_schema_id(),
                        application_id: application_id.clone(),
                        rejection_code: DottedId::new("review_rejected")
                            .expect("rejection code literal is valid"),
                        message: "stream subscription renewal review did not renew a subscription"
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
                let renewed_subscription = review.renewed.clone().ok_or_else(|| {
                    ManifoldAuthorityValidationError::new(
                        review.review_id.clone(),
                        "renewed".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    )
                })?;
                let mut next_snapshot = self.clone();
                next_snapshot.authority_revision = next_authority_revision;
                let Some(position) =
                    next_snapshot
                        .active_stream_subscriptions
                        .iter()
                        .position(|subscription| {
                            subscription.subscription_id == renewed_subscription.subscription_id
                        })
                else {
                    return Err(ManifoldAuthorityValidationError::new(
                        review.review_id.clone(),
                        renewed_subscription.subscription_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::UnknownSubscription,
                    ));
                };
                next_snapshot.active_stream_subscriptions[position] = renewed_subscription;
                next_snapshot.validate_authority_links()?;
                (
                    ManifoldStreamSubscriptionRenewalAuthorityApplicationOutcome::SubscriptionRenewalApplied,
                    Some(next_snapshot),
                    None,
                )
            }
        };

        let application = ManifoldStreamSubscriptionRenewalAuthorityApplication {
            schema_id: stream_subscription_renewal_authority_application_schema_id(),
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

    fn stream_subscription_renewal_authority_decision(
        &self,
        request: &ManifoldStreamSubscriptionRenewalRequest,
        recorded_clock: &ManifoldClockSnapshot,
    ) -> StreamSubscriptionRenewalAuthorityDecision {
        if request.schema_id != stream_subscription_renewal_request_schema_id() {
            return StreamSubscriptionRenewalAuthorityDecision::Rejected {
                rejection_code: "unsupported_schema".to_owned(),
                message: "stream subscription renewal request schema is not supported".to_owned(),
                retryable: false,
                active_subscriber_count: self.active_subscription_count(&request.stream_id),
                current_expires_at_ms: None,
            };
        }

        if request.expected_authority_revision != self.authority_revision {
            return StreamSubscriptionRenewalAuthorityDecision::Rejected {
                rejection_code: "stale_revision".to_owned(),
                message:
                    "stream subscription renewal request expected authority revision does not match current revision"
                        .to_owned(),
                retryable: true,
                active_subscriber_count: self.active_subscription_count(&request.stream_id),
                current_expires_at_ms: None,
            };
        }

        if request.expected_registry_revision != self.stream_registry.registry_revision {
            return StreamSubscriptionRenewalAuthorityDecision::Rejected {
                rejection_code: "registry_revision_mismatch".to_owned(),
                message:
                    "stream subscription renewal request expected registry revision does not match current registry"
                        .to_owned(),
                retryable: true,
                active_subscriber_count: self.active_subscription_count(&request.stream_id),
                current_expires_at_ms: None,
            };
        }

        if request.requested_ttl_ms == 0 {
            return StreamSubscriptionRenewalAuthorityDecision::Rejected {
                rejection_code: "invalid_ttl".to_owned(),
                message: "stream subscription renewal ttl must be greater than zero".to_owned(),
                retryable: false,
                active_subscriber_count: self.active_subscription_count(&request.stream_id),
                current_expires_at_ms: None,
            };
        }

        let Some(subscription) = self.active_stream_subscription(&request.subscription_id) else {
            return StreamSubscriptionRenewalAuthorityDecision::Rejected {
                rejection_code: "unknown_subscription".to_owned(),
                message:
                    "stream subscription renewal request references an unknown active subscription"
                        .to_owned(),
                retryable: true,
                active_subscriber_count: self.active_subscription_count(&request.stream_id),
                current_expires_at_ms: None,
            };
        };

        if subscription.state != ManifoldStreamSubscriptionState::Active {
            return StreamSubscriptionRenewalAuthorityDecision::Rejected {
                rejection_code: "inactive_subscription".to_owned(),
                message: "stream subscription renewal request references a non-active subscription"
                    .to_owned(),
                retryable: true,
                active_subscriber_count: self.active_subscription_count(&subscription.stream_id),
                current_expires_at_ms: Some(subscription.expires_at_ms),
            };
        }

        if stream_subscription_expired_at(subscription, recorded_clock) {
            return StreamSubscriptionRenewalAuthorityDecision::Rejected {
                rejection_code: "expired_subscription".to_owned(),
                message: "stream subscription renewal request references an expired subscription"
                    .to_owned(),
                retryable: true,
                active_subscriber_count: self.active_subscription_count(&subscription.stream_id),
                current_expires_at_ms: Some(subscription.expires_at_ms),
            };
        }

        if subscription.subscriber_id != request.subscriber_id {
            return StreamSubscriptionRenewalAuthorityDecision::Rejected {
                rejection_code: "subscriber_mismatch".to_owned(),
                message:
                    "stream subscription renewal request subscriber does not own the subscription"
                        .to_owned(),
                retryable: false,
                active_subscriber_count: self.active_subscription_count(&subscription.stream_id),
                current_expires_at_ms: Some(subscription.expires_at_ms),
            };
        }

        if subscription.stream_id != request.stream_id {
            return StreamSubscriptionRenewalAuthorityDecision::Rejected {
                rejection_code: "stream_mismatch".to_owned(),
                message:
                    "stream subscription renewal request stream does not match the active subscription"
                        .to_owned(),
                retryable: true,
                active_subscriber_count: self.active_subscription_count(&subscription.stream_id),
                current_expires_at_ms: Some(subscription.expires_at_ms),
            };
        }

        if subscription.transport_id != request.transport_id {
            return StreamSubscriptionRenewalAuthorityDecision::Rejected {
                rejection_code: "transport_mismatch".to_owned(),
                message:
                    "stream subscription renewal request transport does not match the active subscription"
                        .to_owned(),
                retryable: true,
                active_subscriber_count: self.active_subscription_count(&subscription.stream_id),
                current_expires_at_ms: Some(subscription.expires_at_ms),
            };
        }

        let renewed_expires_at_ms =
            wall_unix_ms_u64(recorded_clock).saturating_add(request.requested_ttl_ms);
        if renewed_expires_at_ms <= subscription.expires_at_ms {
            return StreamSubscriptionRenewalAuthorityDecision::Rejected {
                rejection_code: "non_extending_renewal".to_owned(),
                message:
                    "stream subscription renewal request does not extend the active subscription"
                        .to_owned(),
                retryable: false,
                active_subscriber_count: self.active_subscription_count(&subscription.stream_id),
                current_expires_at_ms: Some(subscription.expires_at_ms),
            };
        }

        StreamSubscriptionRenewalAuthorityDecision::Renewed(ManifoldStreamSubscription {
            schema_id: stream_subscription_schema_id(),
            subscription_id: subscription.subscription_id.clone(),
            request_id: subscription.request_id.clone(),
            subscriber_id: subscription.subscriber_id.clone(),
            subscriber_kind: subscription.subscriber_kind,
            stream_id: subscription.stream_id.clone(),
            transport_id: subscription.transport_id.clone(),
            endpoint_id: subscription.endpoint_id.clone(),
            state: ManifoldStreamSubscriptionState::Active,
            accepted_authority_revision: self.authority_revision,
            accepted_registry_revision: subscription.accepted_registry_revision,
            accepted_at_ms: wall_unix_ms_u64(recorded_clock),
            expires_at_ms: renewed_expires_at_ms,
            required_capability: subscription.required_capability.clone(),
        })
    }

    fn active_stream_id(&self, stream_id: &DottedId) -> bool {
        self.module_runtime_states.iter().any(|state| {
            state
                .active_streams
                .iter()
                .any(|active| active == stream_id)
        })
    }
}
