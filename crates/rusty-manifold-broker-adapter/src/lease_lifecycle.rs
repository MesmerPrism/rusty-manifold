//! Broker control-lease lifecycle transport contracts.

use crate::{
    ManifoldBrokerAdapterMode, ManifoldBrokerBoundedUse, ManifoldBrokerControlLeaseTransition,
};
use rusty_manifold_admission::ManifoldAdmissionReceipt;
use rusty_manifold_model::{DottedId, Revision, SafetyClass, SchemaId};
use rusty_manifold_runtime_host::ManifoldRuntimeControlLeaseAdoptionReceipt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Broker control-lease lifecycle request schema.
pub const BROKER_CONTROL_LEASE_LIFECYCLE_REQUEST_SCHEMA: &str =
    "rusty.manifold.broker.control_lease_lifecycle_request.v1";
/// Exact one-use lifecycle binding schema.
pub const BROKER_CONTROL_LEASE_LIFECYCLE_USE_SCHEMA: &str =
    "rusty.manifold.broker.control_lease_lifecycle_use.v1";
/// Broker lifecycle-use authorization receipt schema.
pub const BROKER_CONTROL_LEASE_LIFECYCLE_AUTHORIZATION_RECEIPT_SCHEMA: &str =
    "rusty.manifold.broker.control_lease_lifecycle_authorization_receipt.v1";
/// Broker control-lease lifecycle receipt schema.
pub const BROKER_CONTROL_LEASE_LIFECYCLE_RECEIPT_SCHEMA: &str =
    "rusty.manifold.broker.control_lease_lifecycle_receipt.v1";
/// Domain for an exact compact lifecycle request digest.
pub const BROKER_CONTROL_LEASE_LIFECYCLE_REQUEST_DIGEST_DOMAIN: &str =
    "rusty.manifold.broker.control_lease_lifecycle_request.v1";

/// Requested control-lease lifecycle operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "request")]
pub enum ManifoldBrokerControlLeaseLifecycleOperation {
    /// Issue a new product-scoped lease.
    Issue {
        /// Idempotency identity.
        request_id: DottedId,
        /// Manifold authority revision observed by the caller.
        expected_authority_revision: Revision,
        /// Requested product lease scope.
        scope: DottedId,
        /// Requested duration.
        requested_ttl_ms: u64,
        /// Generic Manifold host capability required to grant the lease.
        required_capability: DottedId,
        /// Generic Manifold safety class.
        safety_class: SafetyClass,
    },
    /// Renew one current Broker-owned lease.
    Renewal {
        /// Idempotency identity.
        request_id: DottedId,
        /// Exact current lease identity.
        lease_id: DottedId,
        /// Manifold authority revision observed by the caller.
        expected_authority_revision: Revision,
        /// Requested duration from the trusted review clock.
        requested_ttl_ms: u64,
        /// Stable renewal reason.
        renewal_reason: DottedId,
        /// Caller-observed request time.
        requested_at_ms: u64,
    },
    /// Release one current Broker-owned lease.
    Release {
        /// Idempotency identity.
        request_id: DottedId,
        /// Exact current lease identity.
        lease_id: DottedId,
        /// Manifold authority revision observed by the caller.
        expected_authority_revision: Revision,
        /// Stable holder release reason.
        release_reason: DottedId,
        /// Caller-observed request time.
        requested_at_ms: u64,
    },
    /// Explicitly apply eligible control-lease expiry.
    Expiry {
        /// Idempotency identity.
        request_id: DottedId,
        /// Exact canonically ordered Broker-owned lease identities expected to expire.
        lease_ids: Vec<DottedId>,
        /// Manifold authority revision observed by the caller.
        expected_authority_revision: Revision,
        /// Stable sweep reason.
        sweep_reason: DottedId,
        /// Caller-observed request time.
        requested_at_ms: u64,
    },
}

impl ManifoldBrokerControlLeaseLifecycleOperation {
    /// Returns the stable lifecycle operation kind.
    #[must_use]
    pub const fn kind(&self) -> ManifoldBrokerControlLeaseLifecycleOperationKind {
        match self {
            Self::Issue { .. } => ManifoldBrokerControlLeaseLifecycleOperationKind::Issue,
            Self::Renewal { .. } => ManifoldBrokerControlLeaseLifecycleOperationKind::Renewal,
            Self::Release { .. } => ManifoldBrokerControlLeaseLifecycleOperationKind::Release,
            Self::Expiry { .. } => ManifoldBrokerControlLeaseLifecycleOperationKind::Expiry,
        }
    }

    /// Returns the exact lifecycle request identity.
    #[must_use]
    pub const fn request_id(&self) -> &DottedId {
        match self {
            Self::Issue { request_id, .. }
            | Self::Renewal { request_id, .. }
            | Self::Release { request_id, .. }
            | Self::Expiry { request_id, .. } => request_id,
        }
    }

    /// Returns the caller-observed Manifold authority revision.
    #[must_use]
    pub const fn expected_authority_revision(&self) -> Revision {
        match self {
            Self::Issue {
                expected_authority_revision,
                ..
            }
            | Self::Renewal {
                expected_authority_revision,
                ..
            }
            | Self::Release {
                expected_authority_revision,
                ..
            }
            | Self::Expiry {
                expected_authority_revision,
                ..
            } => *expected_authority_revision,
        }
    }

    /// Returns a targeted lease identity for renewal or release.
    #[must_use]
    pub const fn lease_id(&self) -> Option<&DottedId> {
        match self {
            Self::Renewal { lease_id, .. } | Self::Release { lease_id, .. } => Some(lease_id),
            Self::Issue { .. } | Self::Expiry { .. } => None,
        }
    }

    /// Returns the requested issue scope.
    #[must_use]
    pub const fn issue_scope(&self) -> Option<&DottedId> {
        match self {
            Self::Issue { scope, .. } => Some(scope),
            Self::Renewal { .. } | Self::Release { .. } | Self::Expiry { .. } => None,
        }
    }

    /// Returns the exact product lease set bound by an expiry request.
    #[must_use]
    pub fn expiry_lease_ids(&self) -> Option<&[DottedId]> {
        match self {
            Self::Expiry { lease_ids, .. } => Some(lease_ids),
            Self::Issue { .. } | Self::Renewal { .. } | Self::Release { .. } => None,
        }
    }
}

/// Closed lifecycle operation vocabulary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldBrokerControlLeaseLifecycleOperationKind {
    /// Issue.
    Issue,
    /// Renewal.
    Renewal,
    /// Holder release.
    Release,
    /// Explicit eligible expiry.
    Expiry,
}

/// One lifecycle request guarded by an already authorized admission use.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerControlLeaseLifecycleRequest {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Exact live Broker provider epoch.
    pub provider_epoch_id: DottedId,
    /// One-time admission-use identity.
    pub admission_use_request_id: DottedId,
    /// Token that authorized the one-time use.
    pub token_id: DottedId,
    /// Admission revision that created the exact use.
    pub expected_admission_authority_revision: Revision,
    /// Closed lifecycle operation.
    pub operation: ManifoldBrokerControlLeaseLifecycleOperation,
}

/// Exact operation-bound use retained until one lifecycle attempt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerControlLeaseLifecycleUse {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Exact accepted generic admission use.
    pub bounded_use: ManifoldBrokerBoundedUse,
    /// Closed lifecycle operation kind.
    pub operation_kind: ManifoldBrokerControlLeaseLifecycleOperationKind,
    /// Exact lifecycle request identity.
    pub lifecycle_request_id: DottedId,
    /// Domain-separated SHA-256 of the exact compact lifecycle request.
    pub lifecycle_request_sha256: String,
    /// Admission revision against which the generic one-use request was authorized.
    pub authorized_from_admission_authority_revision: Revision,
    /// Exact Manifold authority revision bound during authorization.
    pub expected_control_lease_authority_revision: Revision,
    /// Target lease for renewal or release.
    pub lease_id: Option<DottedId>,
    /// Product scope requested during issuance.
    pub issue_scope: Option<DottedId>,
    /// Canonical product lease set expected to be removed by expiry.
    pub expiry_lease_ids: Vec<DottedId>,
}

/// Admission plus exact lifecycle-request binding result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerControlLeaseLifecycleAuthorizationReceipt {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Exact provider epoch.
    pub provider_epoch_id: DottedId,
    /// Exact lifecycle request identity.
    pub lifecycle_request_id: DottedId,
    /// Exact compact request digest.
    pub lifecycle_request_sha256: String,
    /// Generic admission receipt when admission review was reached.
    pub admission_receipt: Option<ManifoldAdmissionReceipt>,
    /// Exact bound lifecycle use when authorization succeeded.
    pub lifecycle_use: Option<ManifoldBrokerControlLeaseLifecycleUse>,
    /// Stable binding rejection before or after generic admission.
    pub rejection_reason: Option<ManifoldBrokerControlLeaseLifecycleRejectionReason>,
    /// True only when admission applied and the exact lifecycle binding was retained.
    pub applied: bool,
}

/// Lifecycle attempt outcome.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldBrokerControlLeaseLifecycleOutcome {
    /// Generic Manifold authority rejected the request and retained its audit.
    AuthorityRejected,
    /// Manifold accepted and Runtime Host atomically adopted the transition.
    AcceptedAndAdopted,
    /// Generic expiry selected a delta outside the exact Broker product lease set.
    UnsupportedAuthorityExpiryDelta,
    /// The one-use permit was consumed but owner/Host composition could not commit.
    CompositionFailedAfterPermitConsumption,
    /// Request failed before a one-use permit was consumed.
    PreflightRejected,
}

/// Stable Broker lifecycle rejection vocabulary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldBrokerControlLeaseLifecycleRejectionReason {
    /// Request schema differs from the supported contract.
    SchemaMismatch,
    /// Request targets another provider epoch.
    ProviderEpochMismatch,
    /// No exact operation-bound admission use exists.
    UnknownLifecycleUse,
    /// The exact operation-bound use was already consumed.
    ReplayedLifecycleUse,
    /// Token differs from the use binding.
    AdmissionTokenMismatch,
    /// Admission revision differs from the use binding.
    StaleAdmissionRevision,
    /// The operation-bound use expired.
    LifecycleUseExpired,
    /// Request bytes differ from the authorized request digest.
    LifecycleRequestMismatch,
    /// Admission capability differs from the lifecycle operation.
    CapabilityMismatch,
    /// Issue scope is outside the immutable product command closure.
    ProductScopeMismatch,
    /// Holder/requester identity differs from signature-scoped admission identity.
    IdentityMismatch,
    /// Manifold authority revision differs from the authorized revision.
    StaleControlLeaseAuthorityRevision,
    /// Renewal or release targeted a lease outside this Broker product.
    UnrelatedLease,
    /// Request identity was already retained by lifecycle authority.
    ReplayedLifecycleRequest,
    /// Strict authority clock lineage, health, or uncertainty validation failed.
    InvalidAuthorityClock,
    /// Issue or renewal reached the cleanup-reserved ledger suffix.
    CleanupCapacityReserved,
    /// Lifecycle retention capacity was exhausted.
    AuthorityCapacityExhausted,
    /// Generic expiry selected subscriptions, unrelated leases, or another lease set.
    UnsupportedAuthorityExpiryDelta,
    /// Owner transition and Runtime Host adoption could not commit together.
    OwnerHostCompositionFailed,
    /// Model/application lineage failed deterministic validation.
    AuthorityLineageInvalid,
}

/// Integrated Broker owner/Runtime Host lifecycle receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerControlLeaseLifecycleReceipt {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Exact provider epoch.
    pub provider_epoch_id: DottedId,
    /// Exact adapter identity.
    pub adapter_id: DottedId,
    /// Process placement; never an authority label.
    pub mode: ManifoldBrokerAdapterMode,
    /// Exact immutable product lock.
    pub product_lock_id: DottedId,
    /// Exact packaged product-lock SHA-256.
    pub product_lock_sha256: String,
    /// Exact lifecycle request identity.
    pub lifecycle_request_id: DottedId,
    /// Exact authorized lifecycle request digest.
    pub lifecycle_request_sha256: String,
    /// Closed operation kind.
    pub operation_kind: ManifoldBrokerControlLeaseLifecycleOperationKind,
    /// Whether an operation-bound admission use was consumed.
    pub admission_use_consumed: bool,
    /// Exact consumed use when admission closed.
    pub lifecycle_use: Option<ManifoldBrokerControlLeaseLifecycleUse>,
    /// High-level atomic outcome.
    pub outcome: ManifoldBrokerControlLeaseLifecycleOutcome,
    /// Exact generic authority transition, including nested review/application/audit.
    pub authority_transition: Option<ManifoldBrokerControlLeaseTransition>,
    /// Exact Runtime Host adoption receipt when adoption was attempted.
    pub host_adoption: Option<ManifoldRuntimeControlLeaseAdoptionReceipt>,
    /// Stable rejection or invariant-failure reason.
    pub rejection_reason: Option<ManifoldBrokerControlLeaseLifecycleRejectionReason>,
    /// True only when Manifold accepted and Runtime Host adopted atomically.
    pub applied: bool,
}

/// Returns the exact admission capability required by an operation.
///
/// # Panics
///
/// Panics only if one of the static capability identifiers is invalid.
#[must_use]
pub fn control_lease_lifecycle_capability(
    kind: ManifoldBrokerControlLeaseLifecycleOperationKind,
) -> DottedId {
    let value = match kind {
        ManifoldBrokerControlLeaseLifecycleOperationKind::Issue => {
            "capability.manifold.control_lease.issue"
        }
        ManifoldBrokerControlLeaseLifecycleOperationKind::Renewal => {
            "capability.manifold.control_lease.renew"
        }
        ManifoldBrokerControlLeaseLifecycleOperationKind::Release => {
            "capability.manifold.control_lease.release"
        }
        ManifoldBrokerControlLeaseLifecycleOperationKind::Expiry => {
            "capability.manifold.control_lease.expire"
        }
    };
    DottedId::new(value).expect("static lifecycle capability is valid")
}

/// Computes the exact compact request digest used by one lifecycle permit.
///
/// Framing is the UTF-8 domain, one NUL byte, then compact typed JSON.
///
/// # Panics
///
/// Panics only if a serializable in-memory request unexpectedly fails compact
/// JSON serialization.
#[must_use]
pub fn control_lease_lifecycle_request_sha256(
    request: &ManifoldBrokerControlLeaseLifecycleRequest,
) -> String {
    let bytes = serde_json::to_vec(request).expect("lifecycle request serializes");
    let mut hasher = Sha256::new();
    hasher.update(BROKER_CONTROL_LEASE_LIFECYCLE_REQUEST_DIGEST_DOMAIN.as_bytes());
    hasher.update([0]);
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(71);
    encoded.push_str("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("String writes cannot fail");
    }
    encoded
}
