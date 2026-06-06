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

impl ManifoldAuthoritySnapshot {
    fn active_stream_id(&self, stream_id: &DottedId) -> bool {
        self.module_runtime_states.iter().any(|state| {
            state
                .active_streams
                .iter()
                .any(|active| active == stream_id)
        })
    }
}
