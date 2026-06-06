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
