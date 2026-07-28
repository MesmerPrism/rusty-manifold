//! Source-only Manifold Runtime Host with deterministic review and application.

use rusty_manifold_model::{
    DottedId, ManifoldAuthorityExpirySweepAuthorityApplication,
    ManifoldAuthorityExpirySweepAuthorityApplicationOutcome, ManifoldAuthoritySnapshot,
    ManifoldControlLease, ManifoldControlLeaseAuthorityApplication,
    ManifoldControlLeaseAuthorityApplicationOutcome,
    ManifoldControlLeaseReleaseAuthorityApplication,
    ManifoldControlLeaseReleaseAuthorityApplicationOutcome,
    ManifoldControlLeaseRenewalAuthorityApplication,
    ManifoldControlLeaseRenewalAuthorityApplicationOutcome,
    ManifoldControlLeaseRevocationAuthorityApplication,
    ManifoldControlLeaseRevocationAuthorityApplicationOutcome, Revision, SchemaId,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

/// Legacy Runtime Host snapshot schema accepted only by the migration API.
pub const LEGACY_HOST_SNAPSHOT_V1_SCHEMA: &str = "rusty.manifold.runtime_host.snapshot.v1";
/// Legacy Runtime Host snapshot schema accepted only by the migration API.
pub const LEGACY_HOST_SNAPSHOT_V2_SCHEMA: &str = "rusty.manifold.runtime_host.snapshot.v2";
/// Legacy Runtime Host snapshot schema accepted only by the migration API.
pub const LEGACY_HOST_SNAPSHOT_V3_SCHEMA: &str = "rusty.manifold.runtime_host.snapshot.v3";
/// Runtime Host snapshot schema with derivative-lease convergence lineage.
pub const HOST_SNAPSHOT_SCHEMA: &str = "rusty.manifold.runtime_host.snapshot.v4";
/// Runtime host command request schema.
pub const HOST_COMMAND_REQUEST_SCHEMA: &str = "rusty.manifold.runtime_host.command_request.v1";
/// Runtime host typed-parameter digest schema.
pub const HOST_TYPED_PARAMS_DIGEST_SCHEMA: &str =
    "rusty.manifold.runtime_host.typed_params_digest.v1";
/// Legacy dispatch receipt schema accepted only by evidence migration.
pub const LEGACY_HOST_DISPATCH_RECEIPT_V1_SCHEMA: &str =
    "rusty.manifold.runtime_host.dispatch_receipt.v1";
/// Runtime Host dispatch receipt schema bound to an exact authority host.
pub const HOST_DISPATCH_RECEIPT_SCHEMA: &str = "rusty.manifold.runtime_host.dispatch_receipt.v2";
/// Legacy application receipt schema accepted only by evidence migration.
pub const LEGACY_HOST_APPLICATION_RECEIPT_V1_SCHEMA: &str =
    "rusty.manifold.runtime_host.application_receipt.v1";
/// Runtime Host application receipt schema bound to an exact authority host.
pub const HOST_APPLICATION_RECEIPT_SCHEMA: &str =
    "rusty.manifold.runtime_host.application_receipt.v2";
/// Runtime Host lease-expiry receipt schema.
pub const HOST_LEASE_EXPIRY_RECEIPT_SCHEMA: &str =
    "rusty.manifold.runtime_host.lease_expiry_receipt.v2";
/// Legacy Runtime Host control-lease adoption request schema.
///
/// Requests are transient and are not retained in a Runtime Host snapshot.
/// Broker evidence that persisted a v1 receipt owns its explicit evidence
/// migration rather than treating Runtime Host restart as a lease decision.
pub const LEGACY_HOST_CONTROL_LEASE_ADOPTION_REQUEST_V1_SCHEMA: &str =
    "rusty.manifold.runtime_host.control_lease_adoption_request.v1";
/// Runtime Host request to adopt a validated Manifold control-lease application.
pub const HOST_CONTROL_LEASE_ADOPTION_REQUEST_SCHEMA: &str =
    "rusty.manifold.runtime_host.control_lease_adoption_request.v2";
/// Legacy Runtime Host control-lease adoption receipt schema.
///
/// Adoption receipts are returned to and retained by their composing owner;
/// they are not embedded in the Runtime Host snapshot.
pub const LEGACY_HOST_CONTROL_LEASE_ADOPTION_RECEIPT_V1_SCHEMA: &str =
    "rusty.manifold.runtime_host.control_lease_adoption_receipt.v1";
/// Runtime Host receipt for adopting a validated Manifold control-lease application.
pub const HOST_CONTROL_LEASE_ADOPTION_RECEIPT_SCHEMA: &str =
    "rusty.manifold.runtime_host.control_lease_adoption_receipt.v2";
/// Runtime Host derivative-lease revocation convergence request schema.
pub const HOST_DERIVATIVE_LEASE_REVOCATION_REQUEST_SCHEMA: &str =
    "rusty.manifold.runtime_host.derivative_lease_revocation_request.v1";
/// Revalidated upstream authority proof for derivative-lease revocation.
pub const HOST_UPSTREAM_REVOCATION_PROOF_SCHEMA: &str =
    "rusty.manifold.runtime_host.upstream_revocation_proof.v1";
/// Accepted coordinator binding from one derivative lease to its upstream lease.
pub const HOST_DERIVATIVE_LEASE_BINDING_SCHEMA: &str =
    "rusty.manifold.runtime_host.derivative_lease_binding.v1";
/// Runtime Host derivative-lease revocation convergence receipt schema.
pub const HOST_DERIVATIVE_LEASE_REVOCATION_RECEIPT_SCHEMA: &str =
    "rusty.manifold.runtime_host.derivative_lease_revocation_receipt.v1";
/// Runtime Host derivative-lease revocation audit binding schema.
pub const HOST_DERIVATIVE_LEASE_REVOCATION_AUDIT_BINDING_SCHEMA: &str =
    "rusty.manifold.runtime_host.derivative_lease_revocation_audit_binding.v1";
/// Legacy Runtime Host audit schema accepted only during snapshot migration.
pub const LEGACY_HOST_AUDIT_EVENT_V1_SCHEMA: &str = "rusty.manifold.runtime_host.audit_event.v1";
/// Legacy Runtime Host audit schema accepted only during snapshot migration.
pub const LEGACY_HOST_AUDIT_EVENT_V2_SCHEMA: &str = "rusty.manifold.runtime_host.audit_event.v2";
/// Legacy Runtime Host audit schema accepted only during snapshot migration.
pub const LEGACY_HOST_AUDIT_EVENT_V3_SCHEMA: &str = "rusty.manifold.runtime_host.audit_event.v3";
/// Runtime Host audit-event schema with derivative-lease convergence bindings.
pub const HOST_AUDIT_EVENT_SCHEMA: &str = "rusty.manifold.runtime_host.audit_event.v4";
/// Explicit Runtime Host snapshot migration receipt schema.
pub const HOST_MIGRATION_RECEIPT_SCHEMA: &str =
    "rusty.manifold.runtime_host.snapshot_migration_receipt.v1";
/// Maximum canonical low-rate parameter document accepted by Runtime Host.
pub const MAX_TYPED_PARAMS_CANONICAL_BYTES: u32 = 4_096;
/// Maximum durable command/sweep audit attempts retained by one host snapshot.
pub const MAX_RUNTIME_AUDIT_EVENTS: usize = 8_192;
/// Maximum entries in static and replay collections.
pub const MAX_RUNTIME_SNAPSHOT_RECORDS: usize = 4_096;
/// Maximum exact leases removed by one derivative convergence operation.
pub const MAX_RUNTIME_DERIVATIVE_LEASE_REVOCATION_LEASES: usize = 64;

/// Registered low-rate command descriptor.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldRuntimeCommandDescriptor {
    /// Stable command identifier.
    pub command_id: DottedId,
    /// Required lease scope, when the command mutates scoped state.
    pub required_lease_scope: Option<DottedId>,
}

/// Accepted coordinator lineage for one derivative Runtime Host lease.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldRuntimeDerivativeLeaseBinding {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Stable binding identity retained with accepted Runtime Host state.
    pub binding_id: DottedId,
    /// Exact upstream provider epoch that admitted the derivative lease.
    pub provider_epoch_id: DottedId,
    /// Exact upstream control lease from which this lease was derived.
    pub upstream_control_lease_id: DottedId,
    /// Exact accepted authorization that caused derivative lease admission.
    pub source_authorization_id: DottedId,
}

/// Accepted runtime-host lease.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldRuntimeLease {
    /// Stable lease identifier.
    pub lease_id: DottedId,
    /// Lease scope.
    pub scope: DottedId,
    /// Holder identity.
    pub holder_id: DottedId,
    /// Absolute expiry in the review time domain.
    pub expires_at_ms: u64,
    /// Accepted coordinator lineage when this lease derives from an upstream lease.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derivative_binding: Option<ManifoldRuntimeDerivativeLeaseBinding>,
}

/// Canonical typed-parameter identity bound through review and application.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldRuntimeTypedParamsDigest {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Exact parameter contract/type identifier.
    pub params_type_id: DottedId,
    /// SHA-256 of canonical UTF-8 JSON, formatted as `sha256:<lowercase-hex>`.
    pub canonical_sha256: String,
    /// Canonical UTF-8 byte length.
    pub canonical_size_bytes: u32,
}

/// Durable accepted runtime-host snapshot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldRuntimeHostSnapshot {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Stable host identity.
    pub host_id: DottedId,
    /// Accepted authority revision.
    pub authority_revision: Revision,
    /// Registered command descriptors.
    pub commands: Vec<ManifoldRuntimeCommandDescriptor>,
    /// Active accepted leases.
    pub leases: Vec<ManifoldRuntimeLease>,
    /// Successfully applied request ids retained for replay rejection.
    pub applied_request_ids: Vec<DottedId>,
    /// First-seen lease-expiry sweep identities retained against replay.
    #[serde(default)]
    pub reviewed_sweep_ids: Vec<DottedId>,
    /// First-seen control-lease adoption identities retained against replay.
    #[serde(default)]
    pub reviewed_control_lease_adoption_ids: Vec<DottedId>,
    /// First-seen derivative-lease revocation identities retained against replay.
    #[serde(default)]
    pub reviewed_derivative_lease_revocation_ids: Vec<DottedId>,
    /// Append-only runtime-host audit records.
    pub audit_events: Vec<ManifoldRuntimeAuditEvent>,
}

/// Revisioned low-rate command request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldRuntimeCommandRequest {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Idempotency identity.
    pub request_id: DottedId,
    /// Authority revision expected by the requester.
    pub expected_authority_revision: Revision,
    /// Requester identity.
    pub requester_id: DottedId,
    /// Registered command identifier.
    pub command_id: DottedId,
    /// Lease identity when required.
    pub lease_id: Option<DottedId>,
    /// Canonical typed parameters when the command carries platform effects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params_digest: Option<ManifoldRuntimeTypedParamsDigest>,
    /// Issued time.
    pub issued_at_ms: u64,
    /// Request expiry time.
    pub expires_at_ms: u64,
}

/// Dispatch review result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldRuntimeDispatchOutcome {
    /// Request is ready for application.
    Ready,
    /// Request is rejected and must not mutate accepted state.
    Rejected,
}

/// Stable runtime-host rejection reason.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldRuntimeRejectionReason {
    /// Request schema is wrong.
    SchemaMismatch,
    /// Request expected a different authority revision.
    StaleAuthorityRevision,
    /// Request was already applied.
    ReplayedRequest,
    /// Request is not currently fresh.
    ExpiredRequest,
    /// Command is absent from the registry.
    UnknownCommand,
    /// Command requires a lease.
    MissingLease,
    /// Lease id is absent from accepted state.
    UnknownLease,
    /// Lease is expired.
    ExpiredLease,
    /// Lease holder differs from requester.
    LeaseHolderMismatch,
    /// Lease scope differs from command scope.
    LeaseScopeMismatch,
    /// Typed-parameter digest schema, hash, or length is malformed.
    InvalidTypedParamsDigest,
    /// Canonical typed parameters exceed the low-rate command bound.
    TypedParamsTooLarge,
    /// Dispatch receipt and request do not match.
    DispatchMismatch,
    /// Dispatch was reviewed against an older snapshot.
    DispatchRevisionMismatch,
    /// Expiry sweep found no expired leases.
    NoExpiredLeases,
    /// Lease-expiry sweep identity was already reviewed.
    ReplayedSweep,
    /// Control-lease adoption identity was already reviewed.
    ReplayedControlLeaseAdoption,
    /// Derivative-lease revocation identity was already reviewed.
    ReplayedDerivativeLeaseRevocation,
    /// Derivative-lease revocation request shape or canonical order is invalid.
    InvalidDerivativeLeaseRevocationRequest,
    /// One or more supplied derivative leases differ from current Host state.
    DerivativeLeaseDeltaMismatch,
    /// Supplied Manifold authority application is damaged or does not match its exact prior state.
    InvalidControlLeaseAuthorityApplication,
    /// Supplied Manifold authority application records a rejected state transition.
    RejectedControlLeaseAuthorityApplication,
    /// Valid Manifold application cannot be composed with the Runtime Host's accepted lease state.
    ControlLeaseDeltaMismatch,
    /// Expiry application also removes subscriptions and must be applied by its owning coordinator.
    CoupledSubscriptionExpiry,
    /// Durable audit/history capacity was reached.
    AuthorityCapacityExhausted,
}

/// Source-only dispatch receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldRuntimeDispatchReceipt {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Exact Runtime Host that performed review.
    pub authority_host_id: DottedId,
    /// Derived dispatch identity.
    pub dispatch_id: DottedId,
    /// Reviewed request identity.
    pub request_id: DottedId,
    /// Reviewed command identity.
    pub command_id: DottedId,
    /// Exact typed-parameter digest reviewed with the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params_digest: Option<ManifoldRuntimeTypedParamsDigest>,
    /// Reviewed authority revision.
    pub reviewed_authority_revision: Revision,
    /// Outcome.
    pub outcome: ManifoldRuntimeDispatchOutcome,
    /// Rejection when not ready.
    pub rejection_reason: Option<ManifoldRuntimeRejectionReason>,
}

/// Application receipt proving whether accepted state advanced.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldRuntimeApplicationReceipt {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Exact Runtime Host that applied or rejected the dispatch.
    pub authority_host_id: DottedId,
    /// Derived receipt identity.
    pub receipt_id: DottedId,
    /// Dispatch identity.
    pub dispatch_id: DottedId,
    /// Request identity.
    pub request_id: DottedId,
    /// Exact typed-parameter digest applied with the dispatch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params_digest: Option<ManifoldRuntimeTypedParamsDigest>,
    /// Whether the command was applied.
    pub applied: bool,
    /// Prior authority revision.
    pub prior_authority_revision: Revision,
    /// Resulting authority revision.
    pub resulting_authority_revision: Revision,
    /// Rejection when not applied.
    pub rejection_reason: Option<ManifoldRuntimeRejectionReason>,
}

/// Explicit lease-expiry application receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldRuntimeLeaseExpiryReceipt {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Sweep identity.
    pub sweep_id: DottedId,
    /// Whether accepted state changed.
    pub applied: bool,
    /// Removed lease ids.
    pub removed_lease_ids: Vec<DottedId>,
    /// Prior authority revision.
    pub prior_authority_revision: Revision,
    /// Resulting authority revision.
    pub resulting_authority_revision: Revision,
    /// Rejection when not applied.
    pub rejection_reason: Option<ManifoldRuntimeRejectionReason>,
}

/// Exact upstream authority transition admitted to derivative cleanup.
///
/// Fields are private so callers must use [`Self::from_accepted_application`].
/// Runtime Host revalidates the proof again immediately before mutation and
/// retains it in audit state; construction alone is not an acceptance bypass.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldRuntimeUpstreamRevocationProof {
    #[serde(rename = "$schema")]
    schema_id: SchemaId,
    provider_epoch_id: DottedId,
    prior_authority_snapshot: Box<ManifoldAuthoritySnapshot>,
    accepted_application: Box<ManifoldControlLeaseRevocationAuthorityApplication>,
}

impl ManifoldRuntimeUpstreamRevocationProof {
    /// Builds a proof only from one exact, applied generic authority transition.
    ///
    /// # Errors
    ///
    /// Returns when the application, review, tombstone, or next-state lineage
    /// does not validate against the supplied prior authority snapshot.
    pub fn from_accepted_application(
        provider_epoch_id: DottedId,
        prior_authority_snapshot: ManifoldAuthoritySnapshot,
        accepted_application: ManifoldControlLeaseRevocationAuthorityApplication,
    ) -> Result<Self, ManifoldRuntimeHostError> {
        let proof = Self {
            schema_id: schema_id(HOST_UPSTREAM_REVOCATION_PROOF_SCHEMA),
            provider_epoch_id,
            prior_authority_snapshot: Box::new(prior_authority_snapshot),
            accepted_application: Box::new(accepted_application),
        };
        proof.validate()?;
        Ok(proof)
    }

    /// Exact Broker/provider epoch authenticated by the convergence coordinator.
    #[must_use]
    pub const fn provider_epoch_id(&self) -> &DottedId {
        &self.provider_epoch_id
    }

    /// Exact accepted upstream application identity.
    #[must_use]
    pub const fn application_id(&self) -> &DottedId {
        &self.accepted_application.application_id
    }

    /// Exact upstream control lease removed by the accepted application.
    #[must_use]
    pub const fn revoked_control_lease_id(&self) -> &DottedId {
        &self.accepted_application.lease_id
    }

    fn validate(&self) -> Result<(), ManifoldRuntimeHostError> {
        if self.schema_id.as_str() != HOST_UPSTREAM_REVOCATION_PROOF_SCHEMA
            || self.accepted_application.outcome
                != ManifoldControlLeaseRevocationAuthorityApplicationOutcome::LeaseRevocationApplied
            || self.accepted_application.tombstone.is_none()
            || self.accepted_application.applied_snapshot.is_none()
        {
            return Err(ManifoldRuntimeHostError::InvalidSnapshot(
                "upstream_revocation_proof_shape",
            ));
        }
        self.accepted_application
            .validate_against_snapshot(&self.prior_authority_snapshot)
            .map_err(|_| {
                ManifoldRuntimeHostError::InvalidSnapshot("upstream_revocation_proof_application")
            })
    }
}

fn derivative_lease_binding_matches_proof(
    lease: &ManifoldRuntimeLease,
    proof: &ManifoldRuntimeUpstreamRevocationProof,
) -> bool {
    lease.derivative_binding.as_ref().is_some_and(|binding| {
        binding.schema_id.as_str() == HOST_DERIVATIVE_LEASE_BINDING_SCHEMA
            && binding.provider_epoch_id == *proof.provider_epoch_id()
            && binding.upstream_control_lease_id == *proof.revoked_control_lease_id()
    })
}

/// Exact derivative leases to revoke after an upstream authority revocation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldRuntimeDerivativeLeaseRevocationRequest {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// One-shot Runtime Host recovery/adoption identity.
    pub revocation_id: DottedId,
    /// Upstream convergence transaction identity.
    pub convergence_id: DottedId,
    /// Runtime Host revision expected by the convergence coordinator.
    pub expected_host_authority_revision: Revision,
    /// Revalidated exact upstream provider/application/tombstone lineage.
    pub upstream_revocation_proof: ManifoldRuntimeUpstreamRevocationProof,
    /// Nonempty, lease-id-ordered exact current Runtime Host lease objects.
    pub exact_leases: Vec<ManifoldRuntimeLease>,
}

/// Typed audit binding retained with a derivative-lease revocation attempt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldRuntimeDerivativeLeaseRevocationAuditBinding {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// One-shot Runtime Host recovery/adoption identity.
    pub revocation_id: DottedId,
    /// Upstream convergence transaction identity.
    pub convergence_id: DottedId,
    /// Upstream provider epoch.
    pub provider_epoch_id: DottedId,
    /// Exact accepted upstream revocation application.
    pub upstream_revocation_application_id: DottedId,
    /// Revalidated exact upstream provider/application/tombstone lineage.
    pub upstream_revocation_proof: ManifoldRuntimeUpstreamRevocationProof,
    /// Exact request lease objects, including rejected malformed or substituted attempts.
    pub exact_leases: Vec<ManifoldRuntimeLease>,
}

/// Runtime Host derivative-lease revocation convergence receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldRuntimeDerivativeLeaseRevocationReceipt {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Exact Runtime Host.
    pub authority_host_id: DottedId,
    /// One-shot Runtime Host recovery/adoption identity.
    pub revocation_id: DottedId,
    /// Upstream convergence transaction identity.
    pub convergence_id: DottedId,
    /// Upstream provider epoch.
    pub provider_epoch_id: DottedId,
    /// Exact accepted upstream revocation application.
    pub upstream_revocation_application_id: DottedId,
    /// Revalidated exact upstream provider/application/tombstone lineage.
    pub upstream_revocation_proof: ManifoldRuntimeUpstreamRevocationProof,
    /// Whether all exact derivative leases were removed atomically.
    pub applied: bool,
    /// Complete exact leases supplied by the convergence coordinator.
    pub requested_leases: Vec<ManifoldRuntimeLease>,
    /// Canonical identities of the exact removed leases.
    pub removed_lease_ids: Vec<DottedId>,
    /// Complete exact removed lease objects.
    pub removed_leases: Vec<ManifoldRuntimeLease>,
    /// Runtime Host revision before convergence.
    pub prior_host_authority_revision: Revision,
    /// Runtime Host revision after convergence.
    pub resulting_host_authority_revision: Revision,
    /// Stable rejection when convergence was not applied.
    pub rejection_reason: Option<ManifoldRuntimeRejectionReason>,
    /// Canonical audit sequence, absent only when capacity rejected before audit.
    pub audit_sequence: Option<u64>,
    /// Canonical audit identity, absent only when capacity rejected before audit.
    pub audit_event_id: Option<DottedId>,
}

/// Kind of validated Manifold control-lease transition adopted by Runtime Host.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldRuntimeControlLeaseAdoptionOperation {
    /// Adopt an accepted control-lease issue application.
    Issue,
    /// Adopt an accepted control-lease renewal application.
    Renewal,
    /// Adopt an accepted control-lease release application.
    Release,
    /// Adopt an accepted authority-owned control-lease revocation application.
    Revocation,
    /// Adopt an accepted authority expiry application containing lease removals only.
    Expiry,
}

/// Validated Manifold authority application accepted as Runtime Host input.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "operation", content = "application", rename_all = "snake_case")]
pub enum ManifoldRuntimeControlLeaseAuthorityApplication {
    /// Control-lease issue application.
    Issue(ManifoldControlLeaseAuthorityApplication),
    /// Control-lease renewal application.
    Renewal(ManifoldControlLeaseRenewalAuthorityApplication),
    /// Control-lease release application.
    Release(ManifoldControlLeaseReleaseAuthorityApplication),
    /// Authority-owned control-lease revocation application.
    Revocation(Box<ManifoldControlLeaseRevocationAuthorityApplication>),
    /// Authority expiry application.
    Expiry(ManifoldAuthorityExpirySweepAuthorityApplication),
}

impl ManifoldRuntimeControlLeaseAuthorityApplication {
    fn operation(&self) -> ManifoldRuntimeControlLeaseAdoptionOperation {
        match self {
            Self::Issue(_) => ManifoldRuntimeControlLeaseAdoptionOperation::Issue,
            Self::Renewal(_) => ManifoldRuntimeControlLeaseAdoptionOperation::Renewal,
            Self::Release(_) => ManifoldRuntimeControlLeaseAdoptionOperation::Release,
            Self::Revocation(_) => ManifoldRuntimeControlLeaseAdoptionOperation::Revocation,
            Self::Expiry(_) => ManifoldRuntimeControlLeaseAdoptionOperation::Expiry,
        }
    }

    fn authority_id(&self) -> &DottedId {
        match self {
            Self::Issue(application) => &application.authority_id,
            Self::Renewal(application) => &application.authority_id,
            Self::Release(application) => &application.authority_id,
            Self::Revocation(application) => &application.authority_id,
            Self::Expiry(application) => &application.authority_id,
        }
    }

    fn application_id(&self) -> &DottedId {
        match self {
            Self::Issue(application) => &application.application_id,
            Self::Renewal(application) => &application.application_id,
            Self::Release(application) => &application.application_id,
            Self::Revocation(application) => &application.application_id,
            Self::Expiry(application) => &application.application_id,
        }
    }

    fn prior_authority_revision(&self) -> Revision {
        match self {
            Self::Issue(application) => application.from_authority_revision,
            Self::Renewal(application) => application.from_authority_revision,
            Self::Release(application) => application.from_authority_revision,
            Self::Revocation(application) => application.from_authority_revision,
            Self::Expiry(application) => application.from_authority_revision,
        }
    }

    fn resulting_authority_revision(&self) -> Revision {
        match self {
            Self::Issue(application) => application
                .applied_snapshot
                .as_ref()
                .map_or(application.from_authority_revision, |snapshot| {
                    snapshot.authority_revision
                }),
            Self::Renewal(application) => application
                .applied_snapshot
                .as_ref()
                .map_or(application.from_authority_revision, |snapshot| {
                    snapshot.authority_revision
                }),
            Self::Release(application) => application
                .applied_snapshot
                .as_ref()
                .map_or(application.from_authority_revision, |snapshot| {
                    snapshot.authority_revision
                }),
            Self::Revocation(application) => application
                .applied_snapshot
                .as_ref()
                .map_or(application.from_authority_revision, |snapshot| {
                    snapshot.authority_revision
                }),
            Self::Expiry(application) => application
                .applied_snapshot
                .as_ref()
                .map_or(application.from_authority_revision, |snapshot| {
                    snapshot.authority_revision
                }),
        }
    }
}

/// Request to compose one validated Manifold lease application into Runtime Host state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldRuntimeControlLeaseAdoptionRequest {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Idempotency identity for this host-side composition attempt.
    pub adoption_id: DottedId,
    /// Runtime Host revision expected by the caller.
    pub expected_host_authority_revision: Revision,
    /// Exact Manifold authority snapshot preceding the supplied application.
    pub prior_authority_snapshot: ManifoldAuthoritySnapshot,
    /// Typed Manifold application to validate and compose.
    pub application: ManifoldRuntimeControlLeaseAuthorityApplication,
}

/// Receipt for one Runtime Host control-lease adoption attempt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldRuntimeControlLeaseAdoptionReceipt {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Exact Runtime Host that attempted adoption.
    pub authority_host_id: DottedId,
    /// Idempotency identity supplied by the caller.
    pub adoption_id: DottedId,
    /// Manifold transition kind.
    pub operation: ManifoldRuntimeControlLeaseAdoptionOperation,
    /// Exact Manifold authority that produced the application.
    pub manifold_authority_id: DottedId,
    /// Exact validated Manifold application identity.
    pub manifold_application_id: DottedId,
    /// Manifold authority revision before the application.
    pub prior_manifold_authority_revision: Revision,
    /// Manifold authority revision resulting from the application.
    pub resulting_manifold_authority_revision: Revision,
    /// Whether Runtime Host state changed.
    pub applied: bool,
    /// Lease ids added by the composition.
    pub added_lease_ids: Vec<DottedId>,
    /// Lease ids renewed in place by the composition.
    pub renewed_lease_ids: Vec<DottedId>,
    /// Lease ids removed by the composition.
    pub removed_lease_ids: Vec<DottedId>,
    /// Runtime Host revision before adoption.
    pub prior_host_authority_revision: Revision,
    /// Runtime Host revision after adoption.
    pub resulting_host_authority_revision: Revision,
    /// Rejection when the transition was not adopted.
    pub rejection_reason: Option<ManifoldRuntimeRejectionReason>,
}

/// Append-only runtime-host audit record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldRuntimeAuditEvent {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Strictly increasing host-local attempt sequence.
    pub sequence: u64,
    /// Stable event identity.
    pub event_id: DottedId,
    /// Event kind.
    pub event_kind: ManifoldRuntimeAuditKind,
    /// Source request or sweep identity.
    pub source_id: DottedId,
    /// Prior authority revision.
    pub prior_authority_revision: Revision,
    /// Resulting authority revision.
    pub resulting_authority_revision: Revision,
    /// Whether accepted state changed.
    pub applied: bool,
    /// Rejection reason when applicable.
    pub rejection_reason: Option<ManifoldRuntimeRejectionReason>,
    /// Exact derivative-lease revocation input when this is that event kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derivative_lease_revocation: Option<ManifoldRuntimeDerivativeLeaseRevocationAuditBinding>,
}

/// Runtime-host audit event kind.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldRuntimeAuditKind {
    /// Command dispatch/application result.
    CommandApplication,
    /// Explicit lease-expiry sweep result.
    LeaseExpiry,
    /// Validated Manifold control-lease application adoption result.
    ControlLeaseAdoption,
    /// Upstream-revocation-driven derivative lease convergence result.
    DerivativeLeaseRevocation,
}

/// Durable evidence that a Runtime Host restart either consumed current v4
/// state directly or migrated a validated legacy v1/v2/v3 snapshot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldRuntimeHostMigrationReceipt {
    /// Receipt schema.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Source snapshot schema observed in the supplied JSON.
    pub source_schema_id: SchemaId,
    /// Resulting snapshot schema.
    pub resulting_schema_id: SchemaId,
    /// Whether legacy state was migrated.
    pub migrated: bool,
    /// Exact restarted Runtime Host.
    pub authority_host_id: DottedId,
    /// Resulting accepted authority revision.
    pub resulting_authority_revision: Revision,
    /// Number of legacy audit records assigned or rewritten to canonical v4 form.
    pub migrated_audit_event_count: usize,
    /// First-seen legacy sweep ids retained against replay.
    pub reviewed_sweep_ids: Vec<DottedId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum LegacyRuntimeAuditKind {
    CommandApplication,
    LeaseExpiry,
}

impl From<LegacyRuntimeAuditKind> for ManifoldRuntimeAuditKind {
    fn from(kind: LegacyRuntimeAuditKind) -> Self {
        match kind {
            LegacyRuntimeAuditKind::CommandApplication => Self::CommandApplication,
            LegacyRuntimeAuditKind::LeaseExpiry => Self::LeaseExpiry,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum LegacyRuntimeRejectionReason {
    SchemaMismatch,
    StaleAuthorityRevision,
    ReplayedRequest,
    ExpiredRequest,
    UnknownCommand,
    MissingLease,
    UnknownLease,
    ExpiredLease,
    LeaseHolderMismatch,
    LeaseScopeMismatch,
    InvalidTypedParamsDigest,
    TypedParamsTooLarge,
    DispatchMismatch,
    DispatchRevisionMismatch,
    NoExpiredLeases,
    ReplayedSweep,
    AuthorityCapacityExhausted,
}

impl From<LegacyRuntimeRejectionReason> for ManifoldRuntimeRejectionReason {
    fn from(reason: LegacyRuntimeRejectionReason) -> Self {
        match reason {
            LegacyRuntimeRejectionReason::SchemaMismatch => Self::SchemaMismatch,
            LegacyRuntimeRejectionReason::StaleAuthorityRevision => Self::StaleAuthorityRevision,
            LegacyRuntimeRejectionReason::ReplayedRequest => Self::ReplayedRequest,
            LegacyRuntimeRejectionReason::ExpiredRequest => Self::ExpiredRequest,
            LegacyRuntimeRejectionReason::UnknownCommand => Self::UnknownCommand,
            LegacyRuntimeRejectionReason::MissingLease => Self::MissingLease,
            LegacyRuntimeRejectionReason::UnknownLease => Self::UnknownLease,
            LegacyRuntimeRejectionReason::ExpiredLease => Self::ExpiredLease,
            LegacyRuntimeRejectionReason::LeaseHolderMismatch => Self::LeaseHolderMismatch,
            LegacyRuntimeRejectionReason::LeaseScopeMismatch => Self::LeaseScopeMismatch,
            LegacyRuntimeRejectionReason::InvalidTypedParamsDigest => {
                Self::InvalidTypedParamsDigest
            }
            LegacyRuntimeRejectionReason::TypedParamsTooLarge => Self::TypedParamsTooLarge,
            LegacyRuntimeRejectionReason::DispatchMismatch => Self::DispatchMismatch,
            LegacyRuntimeRejectionReason::DispatchRevisionMismatch => {
                Self::DispatchRevisionMismatch
            }
            LegacyRuntimeRejectionReason::NoExpiredLeases => Self::NoExpiredLeases,
            LegacyRuntimeRejectionReason::ReplayedSweep => Self::ReplayedSweep,
            LegacyRuntimeRejectionReason::AuthorityCapacityExhausted => {
                Self::AuthorityCapacityExhausted
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct LegacyRuntimeAuditEventV1 {
    #[serde(rename = "$schema")]
    schema_id: SchemaId,
    event_id: DottedId,
    event_kind: LegacyRuntimeAuditKind,
    source_id: DottedId,
    prior_authority_revision: Revision,
    resulting_authority_revision: Revision,
    applied: bool,
    rejection_reason: Option<LegacyRuntimeRejectionReason>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct LegacyRuntimeHostSnapshotV1 {
    #[serde(rename = "$schema")]
    schema_id: SchemaId,
    host_id: DottedId,
    authority_revision: Revision,
    commands: Vec<ManifoldRuntimeCommandDescriptor>,
    leases: Vec<ManifoldRuntimeLease>,
    applied_request_ids: Vec<DottedId>,
    audit_events: Vec<LegacyRuntimeAuditEventV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct LegacyRuntimeAuditEventV2 {
    #[serde(rename = "$schema")]
    schema_id: SchemaId,
    sequence: u64,
    event_id: DottedId,
    event_kind: LegacyRuntimeAuditKind,
    source_id: DottedId,
    prior_authority_revision: Revision,
    resulting_authority_revision: Revision,
    applied: bool,
    rejection_reason: Option<LegacyRuntimeRejectionReason>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct LegacyRuntimeHostSnapshotV2 {
    #[serde(rename = "$schema")]
    schema_id: SchemaId,
    host_id: DottedId,
    authority_revision: Revision,
    commands: Vec<ManifoldRuntimeCommandDescriptor>,
    leases: Vec<ManifoldRuntimeLease>,
    applied_request_ids: Vec<DottedId>,
    #[serde(default)]
    reviewed_sweep_ids: Vec<DottedId>,
    audit_events: Vec<LegacyRuntimeAuditEventV2>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct LegacyRuntimeHostSnapshotV3 {
    #[serde(rename = "$schema")]
    schema_id: SchemaId,
    host_id: DottedId,
    authority_revision: Revision,
    commands: Vec<ManifoldRuntimeCommandDescriptor>,
    leases: Vec<ManifoldRuntimeLease>,
    applied_request_ids: Vec<DottedId>,
    reviewed_sweep_ids: Vec<DottedId>,
    reviewed_control_lease_adoption_ids: Vec<DottedId>,
    audit_events: Vec<ManifoldRuntimeAuditEvent>,
}

#[derive(Deserialize)]
struct SchemaProbe {
    #[serde(rename = "$schema")]
    schema_id: SchemaId,
}

/// Source-only runtime host.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldRuntimeHost {
    snapshot: ManifoldRuntimeHostSnapshot,
}

impl ManifoldRuntimeHost {
    /// Creates a runtime host from a validated snapshot.
    pub fn from_snapshot(
        snapshot: ManifoldRuntimeHostSnapshot,
    ) -> Result<Self, ManifoldRuntimeHostError> {
        validate_snapshot(&snapshot)?;
        Ok(Self { snapshot })
    }

    /// Restarts a host from deterministic JSON snapshot state.
    pub fn restart_from_json(json: &str) -> Result<Self, ManifoldRuntimeHostError> {
        Self::restart_from_json_with_migration(json).map(|(host, _)| host)
    }

    /// Restarts current v4 state or migrates a validated v1/v2/v3 snapshot while
    /// returning explicit schema/audit migration evidence.
    ///
    /// # Errors
    ///
    /// Returns an error when source JSON, legacy lineage, or resulting v4
    /// snapshot invariants fail.
    pub fn restart_from_json_with_migration(
        json: &str,
    ) -> Result<(Self, ManifoldRuntimeHostMigrationReceipt), ManifoldRuntimeHostError> {
        let probe: SchemaProbe =
            serde_json::from_str(json).map_err(ManifoldRuntimeHostError::Deserialize)?;
        if probe.schema_id.as_str() == HOST_SNAPSHOT_SCHEMA {
            let snapshot: ManifoldRuntimeHostSnapshot =
                serde_json::from_str(json).map_err(ManifoldRuntimeHostError::Deserialize)?;
            let host = Self::from_snapshot(snapshot)?;
            let receipt =
                runtime_host_migration_receipt(probe.schema_id, host.snapshot(), false, 0);
            return Ok((host, receipt));
        }
        if probe.schema_id.as_str() == LEGACY_HOST_SNAPSHOT_V3_SCHEMA {
            let legacy: LegacyRuntimeHostSnapshotV3 =
                serde_json::from_str(json).map_err(ManifoldRuntimeHostError::Deserialize)?;
            return migrate_legacy_runtime_host_snapshot_v3(legacy);
        }
        if probe.schema_id.as_str() == LEGACY_HOST_SNAPSHOT_V2_SCHEMA {
            let legacy: LegacyRuntimeHostSnapshotV2 =
                serde_json::from_str(json).map_err(ManifoldRuntimeHostError::Deserialize)?;
            return migrate_legacy_runtime_host_snapshot_v2(legacy);
        }
        if probe.schema_id.as_str() != LEGACY_HOST_SNAPSHOT_V1_SCHEMA {
            return Err(ManifoldRuntimeHostError::InvalidSnapshot(
                "unsupported_snapshot_schema",
            ));
        }
        let legacy: LegacyRuntimeHostSnapshotV1 =
            serde_json::from_str(json).map_err(ManifoldRuntimeHostError::Deserialize)?;
        migrate_legacy_runtime_host_snapshot_v1(legacy)
    }

    /// Serializes the accepted snapshot for durable restart.
    pub fn snapshot_json(&self) -> Result<String, ManifoldRuntimeHostError> {
        serde_json::to_string_pretty(&self.snapshot).map_err(ManifoldRuntimeHostError::Serialize)
    }

    /// Returns the accepted snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> &ManifoldRuntimeHostSnapshot {
        &self.snapshot
    }

    /// Reviews a command without mutating accepted state.
    #[must_use]
    pub fn review_command(
        &self,
        request: &ManifoldRuntimeCommandRequest,
        now_ms: u64,
    ) -> ManifoldRuntimeDispatchReceipt {
        let rejection = validate_request(&self.snapshot, request, now_ms).err();
        ManifoldRuntimeDispatchReceipt {
            schema_id: schema_id(HOST_DISPATCH_RECEIPT_SCHEMA),
            authority_host_id: self.snapshot.host_id.clone(),
            dispatch_id: derived_id("dispatch.runtime", &request.request_id),
            request_id: request.request_id.clone(),
            command_id: request.command_id.clone(),
            params_digest: request.params_digest.clone(),
            reviewed_authority_revision: self.snapshot.authority_revision,
            outcome: if rejection.is_none() {
                ManifoldRuntimeDispatchOutcome::Ready
            } else {
                ManifoldRuntimeDispatchOutcome::Rejected
            },
            rejection_reason: rejection,
        }
    }

    /// Applies a reviewed dispatch exactly once and emits an audit record.
    pub fn apply_dispatch(
        &mut self,
        request: &ManifoldRuntimeCommandRequest,
        dispatch: &ManifoldRuntimeDispatchReceipt,
        now_ms: u64,
    ) -> ManifoldRuntimeApplicationReceipt {
        let prior = self.snapshot.authority_revision;
        if self.snapshot.audit_events.len() >= MAX_RUNTIME_AUDIT_EVENTS {
            return application_receipt(
                request,
                &self.snapshot.host_id,
                &derived_id("dispatch.runtime", &request.request_id),
                prior,
                prior,
                false,
                Some(ManifoldRuntimeRejectionReason::AuthorityCapacityExhausted),
            );
        }
        let current_review = self.review_command(request, now_ms);
        let identity_mismatch = dispatch.schema_id.as_str() != HOST_DISPATCH_RECEIPT_SCHEMA
            || dispatch.authority_host_id != self.snapshot.host_id
            || dispatch.dispatch_id != derived_id("dispatch.runtime", &request.request_id)
            || dispatch.request_id != request.request_id
            || dispatch.command_id != request.command_id
            || dispatch.params_digest != request.params_digest;
        let stale_dispatch = dispatch.reviewed_authority_revision != prior;
        let mut rejection = if identity_mismatch {
            Some(ManifoldRuntimeRejectionReason::DispatchMismatch)
        } else if stale_dispatch {
            Some(ManifoldRuntimeRejectionReason::DispatchRevisionMismatch)
        } else if current_review.outcome == ManifoldRuntimeDispatchOutcome::Rejected {
            current_review.rejection_reason.clone()
        } else if dispatch != &current_review {
            Some(ManifoldRuntimeRejectionReason::DispatchMismatch)
        } else {
            None
        };
        let mut applied =
            dispatch.outcome == ManifoldRuntimeDispatchOutcome::Ready && rejection.is_none();
        if applied && self.snapshot.applied_request_ids.len() >= MAX_RUNTIME_SNAPSHOT_RECORDS {
            rejection = Some(ManifoldRuntimeRejectionReason::AuthorityCapacityExhausted);
            applied = false;
        }
        if applied {
            self.snapshot.authority_revision =
                prior.next().expect("authority revision must advance");
            self.snapshot
                .applied_request_ids
                .push(request.request_id.clone());
            self.snapshot.applied_request_ids.sort();
        }
        let resulting = self.snapshot.authority_revision;
        let event = audit_event(
            (self.snapshot.audit_events.len() as u64) + 1,
            ManifoldRuntimeAuditKind::CommandApplication,
            &request.request_id,
            prior,
            resulting,
            applied,
            rejection.clone(),
        );
        self.snapshot.audit_events.push(event);
        application_receipt(
            request,
            &dispatch.authority_host_id,
            &dispatch.dispatch_id,
            prior,
            resulting,
            applied,
            rejection,
        )
    }

    /// Adopts one validated Manifold control-lease transition into host state.
    ///
    /// Runtime Host revalidates the typed application against the exact prior
    /// Manifold authority snapshot and derives its own narrow lease delta. The
    /// caller cannot supply a replacement lease set.
    ///
    /// # Panics
    ///
    /// Panics only if an accepted host revision is already at the maximum
    /// representable revision after all capacity checks have passed.
    pub fn apply_control_lease_adoption(
        &mut self,
        request: &ManifoldRuntimeControlLeaseAdoptionRequest,
    ) -> ManifoldRuntimeControlLeaseAdoptionReceipt {
        let prior = self.snapshot.authority_revision;
        if self.snapshot.audit_events.len() >= MAX_RUNTIME_AUDIT_EVENTS {
            return control_lease_adoption_receipt(
                &self.snapshot,
                request,
                prior,
                prior,
                false,
                &ControlLeaseDelta::None,
                Some(ManifoldRuntimeRejectionReason::AuthorityCapacityExhausted),
            );
        }
        let replayed = self
            .snapshot
            .reviewed_control_lease_adoption_ids
            .contains(&request.adoption_id);
        if !replayed
            && self.snapshot.reviewed_control_lease_adoption_ids.len()
                >= MAX_RUNTIME_SNAPSHOT_RECORDS
        {
            return control_lease_adoption_receipt(
                &self.snapshot,
                request,
                prior,
                prior,
                false,
                &ControlLeaseDelta::None,
                Some(ManifoldRuntimeRejectionReason::AuthorityCapacityExhausted),
            );
        }

        let result = if replayed {
            Err(ManifoldRuntimeRejectionReason::ReplayedControlLeaseAdoption)
        } else if request.schema_id.as_str() != HOST_CONTROL_LEASE_ADOPTION_REQUEST_SCHEMA {
            Err(ManifoldRuntimeRejectionReason::SchemaMismatch)
        } else if request.expected_host_authority_revision != prior {
            Err(ManifoldRuntimeRejectionReason::StaleAuthorityRevision)
        } else {
            derive_control_lease_delta(&self.snapshot, request)
        };

        if !replayed {
            self.snapshot
                .reviewed_control_lease_adoption_ids
                .push(request.adoption_id.clone());
            self.snapshot.reviewed_control_lease_adoption_ids.sort();
        }

        let (delta, rejection) = match result {
            Ok(delta) => (delta, None),
            Err(rejection) => (ControlLeaseDelta::None, Some(rejection)),
        };
        let applied = rejection.is_none();
        if applied {
            apply_control_lease_delta(&mut self.snapshot.leases, &delta);
            self.snapshot.authority_revision =
                prior.next().expect("authority revision must advance");
        }
        let resulting = self.snapshot.authority_revision;
        self.snapshot.audit_events.push(audit_event(
            (self.snapshot.audit_events.len() as u64) + 1,
            ManifoldRuntimeAuditKind::ControlLeaseAdoption,
            &request.adoption_id,
            prior,
            resulting,
            applied,
            rejection.clone(),
        ));
        control_lease_adoption_receipt(
            &self.snapshot,
            request,
            prior,
            resulting,
            applied,
            &delta,
            rejection,
        )
    }

    /// Atomically removes exact derivative leases after accepted upstream revocation.
    ///
    /// The upstream coordinator supplies complete current lease objects, never
    /// replacement state. Runtime Host compares every object byte-for-byte,
    /// removes the complete set in one revision, and retains the first-seen
    /// recovery identity and exact upstream convergence binding across restart.
    ///
    /// # Panics
    ///
    /// Panics only if an accepted Host revision is already at the maximum
    /// representable revision after all capacity checks have passed.
    #[allow(clippy::too_many_lines)]
    pub fn apply_derivative_lease_revocation(
        &mut self,
        request: &ManifoldRuntimeDerivativeLeaseRevocationRequest,
    ) -> ManifoldRuntimeDerivativeLeaseRevocationReceipt {
        let prior = self.snapshot.authority_revision;
        if self.snapshot.audit_events.len() >= MAX_RUNTIME_AUDIT_EVENTS
            || request.exact_leases.len() > MAX_RUNTIME_DERIVATIVE_LEASE_REVOCATION_LEASES
        {
            return derivative_lease_revocation_receipt(
                &self.snapshot,
                request,
                prior,
                prior,
                false,
                Vec::new(),
                Some(ManifoldRuntimeRejectionReason::AuthorityCapacityExhausted),
                None,
            );
        }
        let replayed = self
            .snapshot
            .reviewed_derivative_lease_revocation_ids
            .contains(&request.revocation_id);
        if !replayed
            && self.snapshot.reviewed_derivative_lease_revocation_ids.len()
                >= MAX_RUNTIME_SNAPSHOT_RECORDS
        {
            return derivative_lease_revocation_receipt(
                &self.snapshot,
                request,
                prior,
                prior,
                false,
                Vec::new(),
                Some(ManifoldRuntimeRejectionReason::AuthorityCapacityExhausted),
                None,
            );
        }

        let canonical = !request.exact_leases.is_empty()
            && request
                .exact_leases
                .windows(2)
                .all(|pair| pair[0].lease_id < pair[1].lease_id);
        let mut accepted_derivative_leases = self
            .snapshot
            .leases
            .iter()
            .filter(|lease| {
                derivative_lease_binding_matches_proof(lease, &request.upstream_revocation_proof)
            })
            .cloned()
            .collect::<Vec<_>>();
        accepted_derivative_leases.sort_by(|left, right| left.lease_id.cmp(&right.lease_id));
        let result = if replayed {
            Err(ManifoldRuntimeRejectionReason::ReplayedDerivativeLeaseRevocation)
        } else if request.schema_id.as_str() != HOST_DERIVATIVE_LEASE_REVOCATION_REQUEST_SCHEMA {
            Err(ManifoldRuntimeRejectionReason::SchemaMismatch)
        } else if request.expected_host_authority_revision != prior {
            Err(ManifoldRuntimeRejectionReason::StaleAuthorityRevision)
        } else if request.upstream_revocation_proof.validate().is_err()
            || request.revocation_id == request.convergence_id
            || !canonical
        {
            Err(ManifoldRuntimeRejectionReason::InvalidDerivativeLeaseRevocationRequest)
        } else if accepted_derivative_leases.is_empty()
            || request.exact_leases != accepted_derivative_leases
        {
            Err(ManifoldRuntimeRejectionReason::DerivativeLeaseDeltaMismatch)
        } else if request.exact_leases.iter().any(|expected| {
            self.snapshot
                .leases
                .iter()
                .find(|current| current.lease_id == expected.lease_id)
                != Some(expected)
        }) {
            Err(ManifoldRuntimeRejectionReason::DerivativeLeaseDeltaMismatch)
        } else {
            Ok(request.exact_leases.clone())
        };

        if !replayed {
            self.snapshot
                .reviewed_derivative_lease_revocation_ids
                .push(request.revocation_id.clone());
            self.snapshot
                .reviewed_derivative_lease_revocation_ids
                .sort();
        }
        let (removed_leases, rejection) = match result {
            Ok(leases) => (leases, None),
            Err(rejection) => (Vec::new(), Some(rejection)),
        };
        let applied = rejection.is_none();
        if applied {
            let removed_ids = removed_leases
                .iter()
                .map(|lease| lease.lease_id.clone())
                .collect::<BTreeSet<_>>();
            self.snapshot
                .leases
                .retain(|lease| !removed_ids.contains(&lease.lease_id));
            self.snapshot.authority_revision =
                prior.next().expect("authority revision must advance");
        }
        let resulting = self.snapshot.authority_revision;
        let sequence = (self.snapshot.audit_events.len() as u64) + 1;
        let event_id = runtime_audit_id(sequence);
        self.snapshot.audit_events.push(ManifoldRuntimeAuditEvent {
            schema_id: schema_id(HOST_AUDIT_EVENT_SCHEMA),
            sequence,
            event_id: event_id.clone(),
            event_kind: ManifoldRuntimeAuditKind::DerivativeLeaseRevocation,
            source_id: request.revocation_id.clone(),
            prior_authority_revision: prior,
            resulting_authority_revision: resulting,
            applied,
            rejection_reason: rejection.clone(),
            derivative_lease_revocation: Some(
                ManifoldRuntimeDerivativeLeaseRevocationAuditBinding {
                    schema_id: schema_id(HOST_DERIVATIVE_LEASE_REVOCATION_AUDIT_BINDING_SCHEMA),
                    revocation_id: request.revocation_id.clone(),
                    convergence_id: request.convergence_id.clone(),
                    provider_epoch_id: request
                        .upstream_revocation_proof
                        .provider_epoch_id()
                        .clone(),
                    upstream_revocation_application_id: request
                        .upstream_revocation_proof
                        .application_id()
                        .clone(),
                    upstream_revocation_proof: request.upstream_revocation_proof.clone(),
                    exact_leases: request.exact_leases.clone(),
                },
            ),
        });
        derivative_lease_revocation_receipt(
            &self.snapshot,
            request,
            prior,
            resulting,
            applied,
            removed_leases,
            rejection,
            Some((sequence, event_id)),
        )
    }

    /// Performs an explicit revision-guarded lease expiry sweep.
    pub fn expire_leases(
        &mut self,
        sweep_id: DottedId,
        expected_revision: Revision,
        now_ms: u64,
    ) -> ManifoldRuntimeLeaseExpiryReceipt {
        let prior = self.snapshot.authority_revision;
        if self.snapshot.audit_events.len() >= MAX_RUNTIME_AUDIT_EVENTS {
            return ManifoldRuntimeLeaseExpiryReceipt {
                schema_id: schema_id(HOST_LEASE_EXPIRY_RECEIPT_SCHEMA),
                sweep_id,
                applied: false,
                removed_lease_ids: Vec::new(),
                prior_authority_revision: prior,
                resulting_authority_revision: prior,
                rejection_reason: Some(ManifoldRuntimeRejectionReason::AuthorityCapacityExhausted),
            };
        }
        if !self.snapshot.reviewed_sweep_ids.contains(&sweep_id)
            && self.snapshot.reviewed_sweep_ids.len() >= MAX_RUNTIME_SNAPSHOT_RECORDS
        {
            return ManifoldRuntimeLeaseExpiryReceipt {
                schema_id: schema_id(HOST_LEASE_EXPIRY_RECEIPT_SCHEMA),
                sweep_id,
                applied: false,
                removed_lease_ids: Vec::new(),
                prior_authority_revision: prior,
                resulting_authority_revision: prior,
                rejection_reason: Some(ManifoldRuntimeRejectionReason::AuthorityCapacityExhausted),
            };
        }
        let mut removed = Vec::new();
        let replayed = self.snapshot.reviewed_sweep_ids.contains(&sweep_id);
        let rejection = if replayed {
            Some(ManifoldRuntimeRejectionReason::ReplayedSweep)
        } else if expected_revision != prior {
            Some(ManifoldRuntimeRejectionReason::StaleAuthorityRevision)
        } else {
            removed = self
                .snapshot
                .leases
                .iter()
                .filter(|lease| lease.expires_at_ms <= now_ms)
                .map(|lease| lease.lease_id.clone())
                .collect();
            if removed.is_empty() {
                Some(ManifoldRuntimeRejectionReason::NoExpiredLeases)
            } else {
                None
            }
        };
        if !replayed {
            self.snapshot.reviewed_sweep_ids.push(sweep_id.clone());
            self.snapshot.reviewed_sweep_ids.sort();
        }
        let applied = rejection.is_none();
        if applied {
            self.snapshot
                .leases
                .retain(|lease| !removed.contains(&lease.lease_id));
            self.snapshot.authority_revision =
                prior.next().expect("authority revision must advance");
        }
        let resulting = self.snapshot.authority_revision;
        self.snapshot.audit_events.push(audit_event(
            (self.snapshot.audit_events.len() as u64) + 1,
            ManifoldRuntimeAuditKind::LeaseExpiry,
            &sweep_id,
            prior,
            resulting,
            applied,
            rejection.clone(),
        ));
        ManifoldRuntimeLeaseExpiryReceipt {
            schema_id: schema_id(HOST_LEASE_EXPIRY_RECEIPT_SCHEMA),
            sweep_id,
            applied,
            removed_lease_ids: removed,
            prior_authority_revision: prior,
            resulting_authority_revision: resulting,
            rejection_reason: rejection,
        }
    }
}

enum ControlLeaseDelta {
    None,
    Issue(ManifoldRuntimeLease),
    Renewal(ManifoldRuntimeLease),
    Remove(Vec<ManifoldRuntimeLease>),
}

fn runtime_lease(lease: &ManifoldControlLease) -> ManifoldRuntimeLease {
    ManifoldRuntimeLease {
        lease_id: lease.lease_id.clone(),
        scope: lease.scope.clone(),
        holder_id: lease.holder_id.clone(),
        expires_at_ms: lease.expires_at_ms,
        derivative_binding: None,
    }
}

#[allow(clippy::too_many_lines)]
fn derive_control_lease_delta(
    snapshot: &ManifoldRuntimeHostSnapshot,
    request: &ManifoldRuntimeControlLeaseAdoptionRequest,
) -> Result<ControlLeaseDelta, ManifoldRuntimeRejectionReason> {
    let invalid = ManifoldRuntimeRejectionReason::InvalidControlLeaseAuthorityApplication;
    let mismatch = ManifoldRuntimeRejectionReason::ControlLeaseDeltaMismatch;
    match &request.application {
        ManifoldRuntimeControlLeaseAuthorityApplication::Issue(application) => {
            application
                .validate_against_snapshot(&request.prior_authority_snapshot)
                .map_err(|_| invalid.clone())?;
            if application.outcome != ManifoldControlLeaseAuthorityApplicationOutcome::LeaseApplied
            {
                return Err(
                    ManifoldRuntimeRejectionReason::RejectedControlLeaseAuthorityApplication,
                );
            }
            let lease = runtime_lease(application.review.accepted.as_ref().ok_or(invalid)?);
            if snapshot
                .leases
                .iter()
                .any(|candidate| candidate.lease_id == lease.lease_id)
            {
                return Err(mismatch);
            }
            Ok(ControlLeaseDelta::Issue(lease))
        }
        ManifoldRuntimeControlLeaseAuthorityApplication::Renewal(application) => {
            application
                .validate_against_snapshot(&request.prior_authority_snapshot)
                .map_err(|_| invalid.clone())?;
            if application.outcome
                != ManifoldControlLeaseRenewalAuthorityApplicationOutcome::LeaseRenewalApplied
            {
                return Err(
                    ManifoldRuntimeRejectionReason::RejectedControlLeaseAuthorityApplication,
                );
            }
            let renewed = runtime_lease(application.review.renewed.as_ref().ok_or(invalid)?);
            let prior_lease = request
                .prior_authority_snapshot
                .active_leases
                .iter()
                .find(|lease| lease.lease_id == renewed.lease_id)
                .map(runtime_lease)
                .ok_or_else(|| mismatch.clone())?;
            if application.lease_id != renewed.lease_id
                || snapshot
                    .leases
                    .iter()
                    .find(|lease| lease.lease_id == renewed.lease_id)
                    != Some(&prior_lease)
            {
                return Err(mismatch);
            }
            Ok(ControlLeaseDelta::Renewal(renewed))
        }
        ManifoldRuntimeControlLeaseAuthorityApplication::Release(application) => {
            application
                .validate_against_snapshot(&request.prior_authority_snapshot)
                .map_err(|_| invalid.clone())?;
            if application.outcome
                != ManifoldControlLeaseReleaseAuthorityApplicationOutcome::LeaseReleaseApplied
            {
                return Err(
                    ManifoldRuntimeRejectionReason::RejectedControlLeaseAuthorityApplication,
                );
            }
            let released = runtime_lease(application.review.released.as_ref().ok_or(invalid)?);
            if snapshot
                .leases
                .iter()
                .find(|lease| lease.lease_id == released.lease_id)
                != Some(&released)
            {
                return Err(mismatch);
            }
            Ok(ControlLeaseDelta::Remove(vec![released]))
        }
        ManifoldRuntimeControlLeaseAuthorityApplication::Revocation(application) => {
            application
                .validate_against_snapshot(&request.prior_authority_snapshot)
                .map_err(|_| invalid.clone())?;
            if application.outcome
                != ManifoldControlLeaseRevocationAuthorityApplicationOutcome::LeaseRevocationApplied
            {
                return Err(
                    ManifoldRuntimeRejectionReason::RejectedControlLeaseAuthorityApplication,
                );
            }
            let revoked = runtime_lease(application.review.revoked.as_ref().ok_or(invalid)?);
            if application.lease_id != revoked.lease_id
                || snapshot
                    .leases
                    .iter()
                    .find(|lease| lease.lease_id == revoked.lease_id)
                    != Some(&revoked)
            {
                return Err(mismatch);
            }
            Ok(ControlLeaseDelta::Remove(vec![revoked]))
        }
        ManifoldRuntimeControlLeaseAuthorityApplication::Expiry(application) => {
            application
                .validate_against_snapshot(&request.prior_authority_snapshot)
                .map_err(|_| invalid)?;
            if application.outcome
                != ManifoldAuthorityExpirySweepAuthorityApplicationOutcome::ExpiredStateApplied
            {
                return Err(
                    ManifoldRuntimeRejectionReason::RejectedControlLeaseAuthorityApplication,
                );
            }
            if !application.review.expired_stream_subscriptions.is_empty() {
                return Err(ManifoldRuntimeRejectionReason::CoupledSubscriptionExpiry);
            }
            let mut removed = Vec::new();
            for lease in &application.review.expired_leases {
                let expected = runtime_lease(lease);
                if let Some(current) = snapshot
                    .leases
                    .iter()
                    .find(|candidate| candidate.lease_id == expected.lease_id)
                {
                    if current != &expected {
                        return Err(mismatch);
                    }
                    removed.push(expected);
                }
            }
            if removed.is_empty() {
                return Err(mismatch);
            }
            Ok(ControlLeaseDelta::Remove(removed))
        }
    }
}

fn apply_control_lease_delta(leases: &mut Vec<ManifoldRuntimeLease>, delta: &ControlLeaseDelta) {
    match delta {
        ControlLeaseDelta::None => {}
        ControlLeaseDelta::Issue(lease) => leases.push(lease.clone()),
        ControlLeaseDelta::Renewal(renewed) => {
            let lease = leases
                .iter_mut()
                .find(|lease| lease.lease_id == renewed.lease_id)
                .expect("validated renewal lease must exist");
            *lease = renewed.clone();
        }
        ControlLeaseDelta::Remove(removed) => leases.retain(|lease| !removed.contains(lease)),
    }
    leases.sort_by(|left, right| left.lease_id.cmp(&right.lease_id));
}

fn control_lease_adoption_receipt(
    snapshot: &ManifoldRuntimeHostSnapshot,
    request: &ManifoldRuntimeControlLeaseAdoptionRequest,
    prior: Revision,
    resulting: Revision,
    applied: bool,
    delta: &ControlLeaseDelta,
    rejection_reason: Option<ManifoldRuntimeRejectionReason>,
) -> ManifoldRuntimeControlLeaseAdoptionReceipt {
    let (added_lease_ids, renewed_lease_ids, removed_lease_ids) = match delta {
        ControlLeaseDelta::None => (Vec::new(), Vec::new(), Vec::new()),
        ControlLeaseDelta::Issue(lease) => (vec![lease.lease_id.clone()], Vec::new(), Vec::new()),
        ControlLeaseDelta::Renewal(lease) => (Vec::new(), vec![lease.lease_id.clone()], Vec::new()),
        ControlLeaseDelta::Remove(leases) => (
            Vec::new(),
            Vec::new(),
            leases.iter().map(|lease| lease.lease_id.clone()).collect(),
        ),
    };
    ManifoldRuntimeControlLeaseAdoptionReceipt {
        schema_id: schema_id(HOST_CONTROL_LEASE_ADOPTION_RECEIPT_SCHEMA),
        authority_host_id: snapshot.host_id.clone(),
        adoption_id: request.adoption_id.clone(),
        operation: request.application.operation(),
        manifold_authority_id: request.application.authority_id().clone(),
        manifold_application_id: request.application.application_id().clone(),
        prior_manifold_authority_revision: request.application.prior_authority_revision(),
        resulting_manifold_authority_revision: request.application.resulting_authority_revision(),
        applied,
        added_lease_ids,
        renewed_lease_ids,
        removed_lease_ids,
        prior_host_authority_revision: prior,
        resulting_host_authority_revision: resulting,
        rejection_reason,
    }
}

#[allow(clippy::too_many_arguments)]
fn derivative_lease_revocation_receipt(
    snapshot: &ManifoldRuntimeHostSnapshot,
    request: &ManifoldRuntimeDerivativeLeaseRevocationRequest,
    prior: Revision,
    resulting: Revision,
    applied: bool,
    removed_leases: Vec<ManifoldRuntimeLease>,
    rejection_reason: Option<ManifoldRuntimeRejectionReason>,
    audit: Option<(u64, DottedId)>,
) -> ManifoldRuntimeDerivativeLeaseRevocationReceipt {
    let removed_lease_ids = removed_leases
        .iter()
        .map(|lease| lease.lease_id.clone())
        .collect();
    let (audit_sequence, audit_event_id) = audit.map_or((None, None), |(sequence, event_id)| {
        (Some(sequence), Some(event_id))
    });
    ManifoldRuntimeDerivativeLeaseRevocationReceipt {
        schema_id: schema_id(HOST_DERIVATIVE_LEASE_REVOCATION_RECEIPT_SCHEMA),
        authority_host_id: snapshot.host_id.clone(),
        revocation_id: request.revocation_id.clone(),
        convergence_id: request.convergence_id.clone(),
        provider_epoch_id: request
            .upstream_revocation_proof
            .provider_epoch_id()
            .clone(),
        upstream_revocation_application_id: request
            .upstream_revocation_proof
            .application_id()
            .clone(),
        upstream_revocation_proof: request.upstream_revocation_proof.clone(),
        applied,
        requested_leases: request.exact_leases.clone(),
        removed_lease_ids,
        removed_leases,
        prior_host_authority_revision: prior,
        resulting_host_authority_revision: resulting,
        rejection_reason,
        audit_sequence,
        audit_event_id,
    }
}

impl ManifoldRuntimeDerivativeLeaseRevocationReceipt {
    /// Validates this receipt against durable restarted Runtime Host state.
    ///
    /// # Errors
    ///
    /// Returns when snapshot lineage or any Host/upstream/request/lease/audit
    /// binding differs from this receipt.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldRuntimeHostSnapshot,
    ) -> Result<(), ManifoldRuntimeHostError> {
        validate_snapshot(snapshot)?;
        let canonical_requested = !self.requested_leases.is_empty()
            && self.requested_leases.len() <= MAX_RUNTIME_DERIVATIVE_LEASE_REVOCATION_LEASES
            && self
                .requested_leases
                .windows(2)
                .all(|pair| pair[0].lease_id < pair[1].lease_id);
        let expected_removed_ids = self
            .removed_leases
            .iter()
            .map(|lease| lease.lease_id.clone())
            .collect::<Vec<_>>();
        let (Some(audit_sequence), Some(audit_event_id)) =
            (self.audit_sequence, self.audit_event_id.as_ref())
        else {
            return Err(ManifoldRuntimeHostError::InvalidSnapshot(
                "derivative_revocation_receipt_missing_audit",
            ));
        };
        let Some(event) = snapshot
            .audit_events
            .iter()
            .find(|event| event.sequence == audit_sequence && &event.event_id == audit_event_id)
        else {
            return Err(ManifoldRuntimeHostError::InvalidSnapshot(
                "derivative_revocation_receipt_unknown_audit",
            ));
        };
        let expected_binding = ManifoldRuntimeDerivativeLeaseRevocationAuditBinding {
            schema_id: schema_id(HOST_DERIVATIVE_LEASE_REVOCATION_AUDIT_BINDING_SCHEMA),
            revocation_id: self.revocation_id.clone(),
            convergence_id: self.convergence_id.clone(),
            provider_epoch_id: self.provider_epoch_id.clone(),
            upstream_revocation_application_id: self.upstream_revocation_application_id.clone(),
            upstream_revocation_proof: self.upstream_revocation_proof.clone(),
            exact_leases: self.requested_leases.clone(),
        };
        let applied_shape = self.applied
            && self.rejection_reason.is_none()
            && self.upstream_revocation_proof.validate().is_ok()
            && canonical_requested
            && self.requested_leases.iter().all(|lease| {
                derivative_lease_binding_matches_proof(lease, &self.upstream_revocation_proof)
            })
            && self.removed_leases == self.requested_leases
            && self.removed_lease_ids == expected_removed_ids
            && self
                .prior_host_authority_revision
                .next()
                .is_some_and(|revision| revision == self.resulting_host_authority_revision)
            && self.removed_lease_ids.iter().all(|removed_id| {
                !snapshot
                    .leases
                    .iter()
                    .any(|lease| &lease.lease_id == removed_id)
            });
        let rejected_shape = !self.applied
            && self.rejection_reason.is_some()
            && self.removed_leases.is_empty()
            && self.removed_lease_ids.is_empty()
            && self.prior_host_authority_revision == self.resulting_host_authority_revision;
        if self.schema_id.as_str() != HOST_DERIVATIVE_LEASE_REVOCATION_RECEIPT_SCHEMA
            || self.authority_host_id != snapshot.host_id
            || self.provider_epoch_id != *self.upstream_revocation_proof.provider_epoch_id()
            || self.upstream_revocation_application_id
                != *self.upstream_revocation_proof.application_id()
            || !snapshot
                .reviewed_derivative_lease_revocation_ids
                .contains(&self.revocation_id)
            || event.event_kind != ManifoldRuntimeAuditKind::DerivativeLeaseRevocation
            || event.source_id != self.revocation_id
            || event.prior_authority_revision != self.prior_host_authority_revision
            || event.resulting_authority_revision != self.resulting_host_authority_revision
            || event.applied != self.applied
            || event.rejection_reason != self.rejection_reason
            || event.derivative_lease_revocation.as_ref() != Some(&expected_binding)
            || (!applied_shape && !rejected_shape)
        {
            return Err(ManifoldRuntimeHostError::InvalidSnapshot(
                "derivative_revocation_receipt_mismatch",
            ));
        }
        Ok(())
    }
}

fn migrate_legacy_runtime_host_snapshot_v1(
    legacy: LegacyRuntimeHostSnapshotV1,
) -> Result<(ManifoldRuntimeHost, ManifoldRuntimeHostMigrationReceipt), ManifoldRuntimeHostError> {
    validate_legacy_runtime_host_snapshot(&legacy)?;
    let mut reviewed_sweep_ids = legacy
        .audit_events
        .iter()
        .filter(|event| event.event_kind == LegacyRuntimeAuditKind::LeaseExpiry)
        .map(|event| event.source_id.clone())
        .collect::<Vec<_>>();
    reviewed_sweep_ids.sort();
    reviewed_sweep_ids.dedup();
    let audit_events = legacy
        .audit_events
        .iter()
        .enumerate()
        .map(|(index, event)| {
            let sequence = (index as u64) + 1;
            ManifoldRuntimeAuditEvent {
                schema_id: schema_id(HOST_AUDIT_EVENT_SCHEMA),
                sequence,
                event_id: runtime_audit_id(sequence),
                event_kind: event.event_kind.clone().into(),
                source_id: event.source_id.clone(),
                prior_authority_revision: event.prior_authority_revision,
                resulting_authority_revision: event.resulting_authority_revision,
                applied: event.applied,
                rejection_reason: event.rejection_reason.clone().map(Into::into),
                derivative_lease_revocation: None,
            }
        })
        .collect::<Vec<_>>();
    let source_schema_id = legacy.schema_id;
    let migrated_audit_event_count = audit_events.len();
    let snapshot = ManifoldRuntimeHostSnapshot {
        schema_id: schema_id(HOST_SNAPSHOT_SCHEMA),
        host_id: legacy.host_id,
        authority_revision: legacy.authority_revision,
        commands: legacy.commands,
        leases: legacy.leases,
        applied_request_ids: legacy.applied_request_ids,
        reviewed_sweep_ids,
        reviewed_control_lease_adoption_ids: Vec::new(),
        reviewed_derivative_lease_revocation_ids: Vec::new(),
        audit_events,
    };
    let host = ManifoldRuntimeHost::from_snapshot(snapshot)?;
    let receipt = runtime_host_migration_receipt(
        source_schema_id,
        host.snapshot(),
        true,
        migrated_audit_event_count,
    );
    Ok((host, receipt))
}

fn migrate_legacy_runtime_host_snapshot_v2(
    legacy: LegacyRuntimeHostSnapshotV2,
) -> Result<(ManifoldRuntimeHost, ManifoldRuntimeHostMigrationReceipt), ManifoldRuntimeHostError> {
    if legacy.schema_id.as_str() != LEGACY_HOST_SNAPSHOT_V2_SCHEMA
        || legacy
            .audit_events
            .iter()
            .any(|event| event.schema_id.as_str() != LEGACY_HOST_AUDIT_EVENT_V2_SCHEMA)
    {
        return Err(ManifoldRuntimeHostError::InvalidSnapshot(
            "legacy_v2_schema_mismatch",
        ));
    }
    let source_schema_id = legacy.schema_id;
    let migrated_audit_event_count = legacy.audit_events.len();
    let snapshot = ManifoldRuntimeHostSnapshot {
        schema_id: schema_id(HOST_SNAPSHOT_SCHEMA),
        host_id: legacy.host_id,
        authority_revision: legacy.authority_revision,
        commands: legacy.commands,
        leases: legacy.leases,
        applied_request_ids: legacy.applied_request_ids,
        reviewed_sweep_ids: legacy.reviewed_sweep_ids,
        reviewed_control_lease_adoption_ids: Vec::new(),
        reviewed_derivative_lease_revocation_ids: Vec::new(),
        audit_events: legacy
            .audit_events
            .into_iter()
            .map(|event| ManifoldRuntimeAuditEvent {
                schema_id: schema_id(HOST_AUDIT_EVENT_SCHEMA),
                sequence: event.sequence,
                event_id: event.event_id,
                event_kind: event.event_kind.into(),
                source_id: event.source_id,
                prior_authority_revision: event.prior_authority_revision,
                resulting_authority_revision: event.resulting_authority_revision,
                applied: event.applied,
                rejection_reason: event.rejection_reason.map(Into::into),
                derivative_lease_revocation: None,
            })
            .collect(),
    };
    let host = ManifoldRuntimeHost::from_snapshot(snapshot)?;
    let receipt = runtime_host_migration_receipt(
        source_schema_id,
        host.snapshot(),
        true,
        migrated_audit_event_count,
    );
    Ok((host, receipt))
}

fn migrate_legacy_runtime_host_snapshot_v3(
    legacy: LegacyRuntimeHostSnapshotV3,
) -> Result<(ManifoldRuntimeHost, ManifoldRuntimeHostMigrationReceipt), ManifoldRuntimeHostError> {
    if legacy.schema_id.as_str() != LEGACY_HOST_SNAPSHOT_V3_SCHEMA
        || legacy.audit_events.iter().any(|event| {
            event.schema_id.as_str() != LEGACY_HOST_AUDIT_EVENT_V3_SCHEMA
                || event.event_kind == ManifoldRuntimeAuditKind::DerivativeLeaseRevocation
                || event.derivative_lease_revocation.is_some()
                || event.rejection_reason.as_ref().is_some_and(|reason| {
                    matches!(
                        reason,
                        ManifoldRuntimeRejectionReason::ReplayedDerivativeLeaseRevocation
                            | ManifoldRuntimeRejectionReason::
                                InvalidDerivativeLeaseRevocationRequest
                            | ManifoldRuntimeRejectionReason::DerivativeLeaseDeltaMismatch
                    )
                })
        })
    {
        return Err(ManifoldRuntimeHostError::InvalidSnapshot(
            "legacy_v3_schema_mismatch",
        ));
    }
    let source_schema_id = legacy.schema_id;
    let migrated_audit_event_count = legacy.audit_events.len();
    let snapshot = ManifoldRuntimeHostSnapshot {
        schema_id: schema_id(HOST_SNAPSHOT_SCHEMA),
        host_id: legacy.host_id,
        authority_revision: legacy.authority_revision,
        commands: legacy.commands,
        leases: legacy.leases,
        applied_request_ids: legacy.applied_request_ids,
        reviewed_sweep_ids: legacy.reviewed_sweep_ids,
        reviewed_control_lease_adoption_ids: legacy.reviewed_control_lease_adoption_ids,
        reviewed_derivative_lease_revocation_ids: Vec::new(),
        audit_events: legacy
            .audit_events
            .into_iter()
            .map(|mut event| {
                event.schema_id = schema_id(HOST_AUDIT_EVENT_SCHEMA);
                event
            })
            .collect(),
    };
    let host = ManifoldRuntimeHost::from_snapshot(snapshot)?;
    let receipt = runtime_host_migration_receipt(
        source_schema_id,
        host.snapshot(),
        true,
        migrated_audit_event_count,
    );
    Ok((host, receipt))
}

fn validate_legacy_runtime_host_snapshot(
    snapshot: &LegacyRuntimeHostSnapshotV1,
) -> Result<(), ManifoldRuntimeHostError> {
    if snapshot.schema_id.as_str() != LEGACY_HOST_SNAPSHOT_V1_SCHEMA
        || snapshot.commands.len() > MAX_RUNTIME_SNAPSHOT_RECORDS
        || snapshot.leases.len() > MAX_RUNTIME_SNAPSHOT_RECORDS
        || snapshot.applied_request_ids.len() > MAX_RUNTIME_SNAPSHOT_RECORDS
        || snapshot.audit_events.len() > MAX_RUNTIME_AUDIT_EVENTS
    {
        return Err(ManifoldRuntimeHostError::InvalidSnapshot(
            "legacy_schema_or_capacity",
        ));
    }
    if snapshot
        .commands
        .iter()
        .map(|command| &command.command_id)
        .collect::<BTreeSet<_>>()
        .len()
        != snapshot.commands.len()
        || snapshot
            .leases
            .iter()
            .map(|lease| &lease.lease_id)
            .collect::<BTreeSet<_>>()
            .len()
            != snapshot.leases.len()
        || snapshot
            .applied_request_ids
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != snapshot.applied_request_ids.len()
        || snapshot
            .audit_events
            .iter()
            .map(|event| &event.event_id)
            .collect::<BTreeSet<_>>()
            .len()
            != snapshot.audit_events.len()
    {
        return Err(ManifoldRuntimeHostError::InvalidSnapshot(
            "legacy_duplicate_identity",
        ));
    }
    let applied_sources = snapshot
        .audit_events
        .iter()
        .filter(|event| {
            event.event_kind == LegacyRuntimeAuditKind::CommandApplication && event.applied
        })
        .map(|event| event.source_id.clone())
        .collect::<BTreeSet<_>>();
    if applied_sources
        != snapshot
            .applied_request_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
    {
        return Err(ManifoldRuntimeHostError::InvalidSnapshot(
            "legacy_audit_replay_set",
        ));
    }
    let mut rolling_revision = Revision::INITIAL;
    let mut seen_applied_commands = BTreeSet::new();
    let mut seen_sweeps = BTreeSet::new();
    for event in &snapshot.audit_events {
        let semantic_valid = match event.event_kind {
            LegacyRuntimeAuditKind::CommandApplication if event.applied => {
                seen_applied_commands.insert(event.source_id.clone())
            }
            LegacyRuntimeAuditKind::CommandApplication => {
                event.rejection_reason.is_some()
                    && (event.rejection_reason
                        != Some(LegacyRuntimeRejectionReason::ReplayedRequest)
                        || seen_applied_commands.contains(&event.source_id))
            }
            LegacyRuntimeAuditKind::LeaseExpiry => {
                seen_sweeps.insert(event.source_id.clone())
                    && event.applied == event.rejection_reason.is_none()
            }
        };
        if event.schema_id.as_str() != LEGACY_HOST_AUDIT_EVENT_V1_SCHEMA
            || event.event_id != derived_id("audit.runtime", &event.source_id)
            || event.prior_authority_revision != rolling_revision
            || (event.applied
                && event.prior_authority_revision.next()
                    != Some(event.resulting_authority_revision))
            || (!event.applied
                && event.prior_authority_revision != event.resulting_authority_revision)
            || event.resulting_authority_revision > snapshot.authority_revision
            || !semantic_valid
        {
            return Err(ManifoldRuntimeHostError::InvalidSnapshot(
                "legacy_audit_lineage",
            ));
        }
        rolling_revision = event.resulting_authority_revision;
    }
    if rolling_revision != snapshot.authority_revision {
        return Err(ManifoldRuntimeHostError::InvalidSnapshot(
            "legacy_audit_final_revision",
        ));
    }
    Ok(())
}

fn runtime_host_migration_receipt(
    source_schema_id: SchemaId,
    snapshot: &ManifoldRuntimeHostSnapshot,
    migrated: bool,
    migrated_audit_event_count: usize,
) -> ManifoldRuntimeHostMigrationReceipt {
    ManifoldRuntimeHostMigrationReceipt {
        schema_id: schema_id(HOST_MIGRATION_RECEIPT_SCHEMA),
        source_schema_id,
        resulting_schema_id: snapshot.schema_id.clone(),
        migrated,
        authority_host_id: snapshot.host_id.clone(),
        resulting_authority_revision: snapshot.authority_revision,
        migrated_audit_event_count,
        reviewed_sweep_ids: snapshot.reviewed_sweep_ids.clone(),
    }
}

fn validate_snapshot(
    snapshot: &ManifoldRuntimeHostSnapshot,
) -> Result<(), ManifoldRuntimeHostError> {
    if snapshot.schema_id.as_str() != HOST_SNAPSHOT_SCHEMA {
        return Err(ManifoldRuntimeHostError::InvalidSnapshot("schema_mismatch"));
    }
    if snapshot.commands.len() > MAX_RUNTIME_SNAPSHOT_RECORDS
        || snapshot.leases.len() > MAX_RUNTIME_SNAPSHOT_RECORDS
        || snapshot.applied_request_ids.len() > MAX_RUNTIME_SNAPSHOT_RECORDS
        || snapshot.reviewed_sweep_ids.len() > MAX_RUNTIME_SNAPSHOT_RECORDS
        || snapshot.reviewed_control_lease_adoption_ids.len() > MAX_RUNTIME_SNAPSHOT_RECORDS
        || snapshot.reviewed_derivative_lease_revocation_ids.len() > MAX_RUNTIME_SNAPSHOT_RECORDS
        || snapshot.audit_events.len() > MAX_RUNTIME_AUDIT_EVENTS
    {
        return Err(ManifoldRuntimeHostError::InvalidSnapshot(
            "snapshot_capacity_exceeded",
        ));
    }
    let command_ids = snapshot
        .commands
        .iter()
        .map(|command| &command.command_id)
        .collect::<BTreeSet<_>>();
    if command_ids.len() != snapshot.commands.len() {
        return Err(ManifoldRuntimeHostError::InvalidSnapshot(
            "duplicate_command",
        ));
    }
    let lease_ids = snapshot
        .leases
        .iter()
        .map(|lease| &lease.lease_id)
        .collect::<BTreeSet<_>>();
    if lease_ids.len() != snapshot.leases.len() {
        return Err(ManifoldRuntimeHostError::InvalidSnapshot("duplicate_lease"));
    }
    let derivative_bindings = snapshot
        .leases
        .iter()
        .filter_map(|lease| lease.derivative_binding.as_ref())
        .collect::<Vec<_>>();
    let derivative_binding_ids = derivative_bindings
        .iter()
        .map(|binding| &binding.binding_id)
        .collect::<BTreeSet<_>>();
    let derivative_binding_sources = derivative_bindings
        .iter()
        .map(|binding| (&binding.provider_epoch_id, &binding.source_authorization_id))
        .collect::<BTreeSet<_>>();
    if derivative_binding_ids.len() != derivative_bindings.len()
        || derivative_binding_sources.len() != derivative_bindings.len()
        || derivative_bindings
            .iter()
            .any(|binding| binding.schema_id.as_str() != HOST_DERIVATIVE_LEASE_BINDING_SCHEMA)
    {
        return Err(ManifoldRuntimeHostError::InvalidSnapshot(
            "invalid_derivative_lease_binding",
        ));
    }
    let request_ids = snapshot.applied_request_ids.iter().collect::<BTreeSet<_>>();
    if request_ids.len() != snapshot.applied_request_ids.len() {
        return Err(ManifoldRuntimeHostError::InvalidSnapshot(
            "duplicate_applied_request",
        ));
    }
    let sweep_ids = snapshot.reviewed_sweep_ids.iter().collect::<BTreeSet<_>>();
    if sweep_ids.len() != snapshot.reviewed_sweep_ids.len() {
        return Err(ManifoldRuntimeHostError::InvalidSnapshot(
            "duplicate_reviewed_sweep",
        ));
    }
    let adoption_ids = snapshot
        .reviewed_control_lease_adoption_ids
        .iter()
        .collect::<BTreeSet<_>>();
    if adoption_ids.len() != snapshot.reviewed_control_lease_adoption_ids.len() {
        return Err(ManifoldRuntimeHostError::InvalidSnapshot(
            "duplicate_reviewed_control_lease_adoption",
        ));
    }
    let derivative_revocation_ids = snapshot
        .reviewed_derivative_lease_revocation_ids
        .iter()
        .collect::<BTreeSet<_>>();
    if derivative_revocation_ids.len() != snapshot.reviewed_derivative_lease_revocation_ids.len() {
        return Err(ManifoldRuntimeHostError::InvalidSnapshot(
            "duplicate_reviewed_derivative_lease_revocation",
        ));
    }
    let audit_ids = snapshot
        .audit_events
        .iter()
        .map(|event| &event.event_id)
        .collect::<BTreeSet<_>>();
    if audit_ids.len() != snapshot.audit_events.len() {
        return Err(ManifoldRuntimeHostError::InvalidSnapshot(
            "duplicate_audit_event",
        ));
    }
    let applied_command_sources = snapshot
        .audit_events
        .iter()
        .filter(|event| {
            event.event_kind == ManifoldRuntimeAuditKind::CommandApplication && event.applied
        })
        .map(|event| event.source_id.clone())
        .collect::<BTreeSet<_>>();
    let retained_applied_sources = snapshot
        .applied_request_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let reviewed_sweep_sources = snapshot
        .audit_events
        .iter()
        .filter(|event| event.event_kind == ManifoldRuntimeAuditKind::LeaseExpiry)
        .map(|event| event.source_id.clone())
        .collect::<BTreeSet<_>>();
    let retained_sweep_sources = snapshot
        .reviewed_sweep_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let reviewed_adoption_sources = snapshot
        .audit_events
        .iter()
        .filter(|event| event.event_kind == ManifoldRuntimeAuditKind::ControlLeaseAdoption)
        .map(|event| event.source_id.clone())
        .collect::<BTreeSet<_>>();
    let retained_adoption_sources = snapshot
        .reviewed_control_lease_adoption_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let reviewed_derivative_revocation_sources = snapshot
        .audit_events
        .iter()
        .filter(|event| event.event_kind == ManifoldRuntimeAuditKind::DerivativeLeaseRevocation)
        .map(|event| event.source_id.clone())
        .collect::<BTreeSet<_>>();
    let retained_derivative_revocation_sources = snapshot
        .reviewed_derivative_lease_revocation_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if applied_command_sources != retained_applied_sources
        || reviewed_sweep_sources != retained_sweep_sources
        || reviewed_adoption_sources != retained_adoption_sources
        || reviewed_derivative_revocation_sources != retained_derivative_revocation_sources
    {
        return Err(ManifoldRuntimeHostError::InvalidSnapshot(
            "audit_replay_set_mismatch",
        ));
    }
    let mut rolling_revision = Revision::INITIAL;
    let mut seen_applied_commands = BTreeSet::new();
    let mut seen_sweeps = BTreeSet::new();
    let mut seen_adoptions = BTreeSet::new();
    let mut seen_derivative_revocations = BTreeSet::new();
    for (index, event) in snapshot.audit_events.iter().enumerate() {
        let sequence = (index as u64) + 1;
        let semantic_valid = match event.event_kind {
            ManifoldRuntimeAuditKind::CommandApplication if event.applied => {
                event.rejection_reason.is_none()
                    && seen_applied_commands.insert(event.source_id.clone())
            }
            ManifoldRuntimeAuditKind::CommandApplication => {
                event.rejection_reason.is_some()
                    && (event.rejection_reason
                        != Some(ManifoldRuntimeRejectionReason::ReplayedRequest)
                        || seen_applied_commands.contains(&event.source_id))
            }
            ManifoldRuntimeAuditKind::LeaseExpiry
                if seen_sweeps.insert(event.source_id.clone()) =>
            {
                event.applied == event.rejection_reason.is_none()
            }
            ManifoldRuntimeAuditKind::LeaseExpiry => {
                !event.applied
                    && event.rejection_reason == Some(ManifoldRuntimeRejectionReason::ReplayedSweep)
            }
            ManifoldRuntimeAuditKind::ControlLeaseAdoption
                if seen_adoptions.insert(event.source_id.clone()) =>
            {
                event.applied == event.rejection_reason.is_none()
            }
            ManifoldRuntimeAuditKind::ControlLeaseAdoption => {
                !event.applied
                    && event.rejection_reason
                        == Some(ManifoldRuntimeRejectionReason::ReplayedControlLeaseAdoption)
            }
            ManifoldRuntimeAuditKind::DerivativeLeaseRevocation
                if seen_derivative_revocations.insert(event.source_id.clone()) =>
            {
                event.applied == event.rejection_reason.is_none()
            }
            ManifoldRuntimeAuditKind::DerivativeLeaseRevocation => {
                !event.applied
                    && event.rejection_reason
                        == Some(ManifoldRuntimeRejectionReason::ReplayedDerivativeLeaseRevocation)
            }
        };
        let derivative_binding_valid = match (
            &event.event_kind,
            event.derivative_lease_revocation.as_ref(),
        ) {
            (ManifoldRuntimeAuditKind::DerivativeLeaseRevocation, Some(binding)) => {
                binding.schema_id.as_str() == HOST_DERIVATIVE_LEASE_REVOCATION_AUDIT_BINDING_SCHEMA
                    && binding.revocation_id == event.source_id
                    && binding.provider_epoch_id
                        == *binding.upstream_revocation_proof.provider_epoch_id()
                    && binding.upstream_revocation_application_id
                        == *binding.upstream_revocation_proof.application_id()
                    && binding.exact_leases.len() <= MAX_RUNTIME_DERIVATIVE_LEASE_REVOCATION_LEASES
                    && (!event.applied
                        || (binding.upstream_revocation_proof.validate().is_ok()
                            && binding.revocation_id != binding.convergence_id
                            && !binding.exact_leases.is_empty()
                            && binding.exact_leases.iter().all(|lease| {
                                derivative_lease_binding_matches_proof(
                                    lease,
                                    &binding.upstream_revocation_proof,
                                )
                            })
                            && binding
                                .exact_leases
                                .windows(2)
                                .all(|pair| pair[0].lease_id < pair[1].lease_id)
                            && binding.exact_leases.iter().all(|removed| {
                                !snapshot
                                    .leases
                                    .iter()
                                    .any(|lease| lease.lease_id == removed.lease_id)
                            })))
            }
            (ManifoldRuntimeAuditKind::DerivativeLeaseRevocation, None) | (_, Some(_)) => false,
            (_, None) => true,
        };
        if event.schema_id.as_str() != HOST_AUDIT_EVENT_SCHEMA
            || event.sequence != sequence
            || event.event_id != runtime_audit_id(sequence)
            || event.prior_authority_revision != rolling_revision
            || (event.applied
                && event.prior_authority_revision.next()
                    != Some(event.resulting_authority_revision))
            || (!event.applied
                && event.prior_authority_revision != event.resulting_authority_revision)
            || event.resulting_authority_revision > snapshot.authority_revision
            || (event.event_kind == ManifoldRuntimeAuditKind::LeaseExpiry
                && !snapshot.reviewed_sweep_ids.contains(&event.source_id))
            || (event.event_kind == ManifoldRuntimeAuditKind::ControlLeaseAdoption
                && !snapshot
                    .reviewed_control_lease_adoption_ids
                    .contains(&event.source_id))
            || (event.event_kind == ManifoldRuntimeAuditKind::DerivativeLeaseRevocation
                && !snapshot
                    .reviewed_derivative_lease_revocation_ids
                    .contains(&event.source_id))
            || !derivative_binding_valid
            || !semantic_valid
        {
            return Err(ManifoldRuntimeHostError::InvalidSnapshot("audit_lineage"));
        }
        rolling_revision = event.resulting_authority_revision;
    }
    if rolling_revision != snapshot.authority_revision {
        return Err(ManifoldRuntimeHostError::InvalidSnapshot(
            "audit_final_revision_mismatch",
        ));
    }
    Ok(())
}

fn validate_request(
    snapshot: &ManifoldRuntimeHostSnapshot,
    request: &ManifoldRuntimeCommandRequest,
    now_ms: u64,
) -> Result<(), ManifoldRuntimeRejectionReason> {
    if request.schema_id.as_str() != HOST_COMMAND_REQUEST_SCHEMA {
        return Err(ManifoldRuntimeRejectionReason::SchemaMismatch);
    }
    if let Some(params) = &request.params_digest {
        if params.schema_id.as_str() != HOST_TYPED_PARAMS_DIGEST_SCHEMA
            || params.canonical_size_bytes == 0
            || !valid_sha256_digest(&params.canonical_sha256)
        {
            return Err(ManifoldRuntimeRejectionReason::InvalidTypedParamsDigest);
        }
        if params.canonical_size_bytes > MAX_TYPED_PARAMS_CANONICAL_BYTES {
            return Err(ManifoldRuntimeRejectionReason::TypedParamsTooLarge);
        }
    }
    if request.expected_authority_revision != snapshot.authority_revision {
        return Err(ManifoldRuntimeRejectionReason::StaleAuthorityRevision);
    }
    if snapshot.applied_request_ids.contains(&request.request_id) {
        return Err(ManifoldRuntimeRejectionReason::ReplayedRequest);
    }
    if request.issued_at_ms > now_ms || request.expires_at_ms <= now_ms {
        return Err(ManifoldRuntimeRejectionReason::ExpiredRequest);
    }
    let command = snapshot
        .commands
        .iter()
        .find(|command| command.command_id == request.command_id)
        .ok_or(ManifoldRuntimeRejectionReason::UnknownCommand)?;
    if let Some(required_scope) = &command.required_lease_scope {
        let lease_id = request
            .lease_id
            .as_ref()
            .ok_or(ManifoldRuntimeRejectionReason::MissingLease)?;
        let lease = snapshot
            .leases
            .iter()
            .find(|lease| &lease.lease_id == lease_id)
            .ok_or(ManifoldRuntimeRejectionReason::UnknownLease)?;
        if lease.expires_at_ms <= now_ms {
            return Err(ManifoldRuntimeRejectionReason::ExpiredLease);
        }
        if lease.holder_id != request.requester_id {
            return Err(ManifoldRuntimeRejectionReason::LeaseHolderMismatch);
        }
        if &lease.scope != required_scope {
            return Err(ManifoldRuntimeRejectionReason::LeaseScopeMismatch);
        }
    }
    Ok(())
}

fn valid_sha256_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn audit_event(
    sequence: u64,
    kind: ManifoldRuntimeAuditKind,
    source_id: &DottedId,
    prior: Revision,
    resulting: Revision,
    applied: bool,
    rejection: Option<ManifoldRuntimeRejectionReason>,
) -> ManifoldRuntimeAuditEvent {
    ManifoldRuntimeAuditEvent {
        schema_id: schema_id(HOST_AUDIT_EVENT_SCHEMA),
        sequence,
        event_id: runtime_audit_id(sequence),
        event_kind: kind,
        source_id: source_id.clone(),
        prior_authority_revision: prior,
        resulting_authority_revision: resulting,
        applied,
        rejection_reason: rejection,
        derivative_lease_revocation: None,
    }
}

fn application_receipt(
    request: &ManifoldRuntimeCommandRequest,
    authority_host_id: &DottedId,
    dispatch_id: &DottedId,
    prior_authority_revision: Revision,
    resulting_authority_revision: Revision,
    applied: bool,
    rejection_reason: Option<ManifoldRuntimeRejectionReason>,
) -> ManifoldRuntimeApplicationReceipt {
    ManifoldRuntimeApplicationReceipt {
        schema_id: schema_id(HOST_APPLICATION_RECEIPT_SCHEMA),
        authority_host_id: authority_host_id.clone(),
        receipt_id: derived_id("receipt.runtime", &request.request_id),
        dispatch_id: dispatch_id.clone(),
        request_id: request.request_id.clone(),
        params_digest: request.params_digest.clone(),
        applied,
        prior_authority_revision,
        resulting_authority_revision,
        rejection_reason,
    }
}

fn runtime_audit_id(sequence: u64) -> DottedId {
    DottedId::new(format!("audit.runtime.{sequence:020}"))
        .expect("derived runtime audit identity must be valid")
}

fn schema_id(value: &str) -> SchemaId {
    SchemaId::new(value).expect("static schema id must be valid")
}

fn derived_id(prefix: &str, source_id: &DottedId) -> DottedId {
    DottedId::new(format!("{prefix}.{}", source_id.as_str())).expect("derived id must be valid")
}

/// Runtime-host persistence or snapshot validation error.
#[derive(Debug)]
pub enum ManifoldRuntimeHostError {
    /// JSON snapshot could not be decoded.
    Deserialize(serde_json::Error),
    /// JSON snapshot could not be encoded.
    Serialize(serde_json::Error),
    /// Snapshot invariant failed.
    InvalidSnapshot(&'static str),
}

impl fmt::Display for ManifoldRuntimeHostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Deserialize(error) => {
                write!(formatter, "runtime host snapshot decode failed: {error}")
            }
            Self::Serialize(error) => {
                write!(formatter, "runtime host snapshot encode failed: {error}")
            }
            Self::InvalidSnapshot(reason) => {
                write!(formatter, "runtime host snapshot invalid: {reason}")
            }
        }
    }
}

impl std::error::Error for ManifoldRuntimeHostError {}

#[cfg(test)]
mod tests {
    use super::*;
    use rusty_manifold_model::ManifoldControlLeaseRevocationRequest;

    fn fixture<T: serde::de::DeserializeOwned>(path: &str) -> T {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(path);
        serde_json::from_str(&std::fs::read_to_string(root).expect("fixture must load"))
            .expect("fixture must deserialize")
    }

    fn host_fixture(path: &str) -> ManifoldRuntimeHostSnapshot {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(path);
        let json = std::fs::read_to_string(root).expect("fixture must load");
        ManifoldRuntimeHost::restart_from_json(&json)
            .expect("fixture must migrate")
            .snapshot()
            .clone()
    }

    fn typed_params_digest(size: u32) -> ManifoldRuntimeTypedParamsDigest {
        ManifoldRuntimeTypedParamsDigest {
            schema_id: schema_id(HOST_TYPED_PARAMS_DIGEST_SCHEMA),
            params_type_id: DottedId::new("rusty.quest.broker.effect_params.v1")
                .expect("params type"),
            canonical_sha256: format!("sha256:{}", "ab".repeat(32)),
            canonical_size_bytes: size,
        }
    }

    fn control_lease_revocation_application(
        prior: &ManifoldAuthoritySnapshot,
        request_id: &str,
        lease_id: &DottedId,
        scope: &DottedId,
    ) -> ManifoldControlLeaseRevocationAuthorityApplication {
        let request = ManifoldControlLeaseRevocationRequest {
            schema_id: schema_id("rusty.manifold.command.lease_revocation_request.v1"),
            request_id: DottedId::new(request_id).expect("request id"),
            authority_id: prior.authority_id.clone(),
            lease_id: lease_id.clone(),
            expected_authority_revision: prior.authority_revision,
            scope: scope.clone(),
            revocation_reason: DottedId::new("reason.security.revoke").expect("reason"),
            requested_at_ms: 1,
        };
        let review = prior
            .review_control_lease_revocation(
                request,
                prior.clock_snapshot.clone(),
                vec![DottedId::new("evidence.runtime.revoke").expect("evidence")],
            )
            .expect("revocation review");
        prior
            .apply_control_lease_revocation_authority_review(review)
            .expect("revocation application")
    }

    fn revocation_host_and_request(
        request_id: &str,
        adoption_id: &str,
    ) -> (
        ManifoldRuntimeHost,
        ManifoldRuntimeControlLeaseAdoptionRequest,
    ) {
        let prior: ManifoldAuthoritySnapshot =
            fixture("fixtures/authority/synthetic-authority-snapshot.json");
        let target = prior.active_leases[0].clone();
        let application = control_lease_revocation_application(
            &prior,
            request_id,
            &target.lease_id,
            &target.scope,
        );
        let mut snapshot =
            host_fixture("fixtures/runtime-host/synthetic-runtime-host-snapshot.json");
        snapshot.leases = vec![runtime_lease(&target)];
        let host = ManifoldRuntimeHost::from_snapshot(snapshot).expect("revocation host");
        let request = ManifoldRuntimeControlLeaseAdoptionRequest {
            schema_id: schema_id(HOST_CONTROL_LEASE_ADOPTION_REQUEST_SCHEMA),
            adoption_id: DottedId::new(adoption_id).expect("adoption id"),
            expected_host_authority_revision: host.snapshot().authority_revision,
            prior_authority_snapshot: prior,
            application: ManifoldRuntimeControlLeaseAuthorityApplication::Revocation(Box::new(
                application,
            )),
        };
        (host, request)
    }

    fn derivative_lease_revocation_request(
        host: &ManifoldRuntimeHost,
        revocation_id: &str,
        exact_leases: Vec<ManifoldRuntimeLease>,
    ) -> ManifoldRuntimeDerivativeLeaseRevocationRequest {
        let prior: ManifoldAuthoritySnapshot =
            fixture("fixtures/authority/synthetic-authority-snapshot.json");
        let target = prior.active_leases[0].clone();
        let application = control_lease_revocation_application(
            &prior,
            "request.peer.derivative_revocation",
            &target.lease_id,
            &target.scope,
        );
        ManifoldRuntimeDerivativeLeaseRevocationRequest {
            schema_id: schema_id(HOST_DERIVATIVE_LEASE_REVOCATION_REQUEST_SCHEMA),
            revocation_id: DottedId::new(revocation_id).expect("revocation id"),
            convergence_id: DottedId::new(format!("convergence.{revocation_id}"))
                .expect("convergence id"),
            expected_host_authority_revision: host.snapshot().authority_revision,
            upstream_revocation_proof:
                ManifoldRuntimeUpstreamRevocationProof::from_accepted_application(
                    DottedId::new("epoch.peer.provider.001").expect("epoch"),
                    prior,
                    application,
                )
                .expect("accepted upstream revocation proof"),
            exact_leases,
        }
    }

    fn derivative_host(mut snapshot: ManifoldRuntimeHostSnapshot) -> ManifoldRuntimeHost {
        let prior: ManifoldAuthoritySnapshot =
            fixture("fixtures/authority/synthetic-authority-snapshot.json");
        let upstream_control_lease_id = prior.active_leases[0].lease_id.clone();
        for lease in &mut snapshot.leases {
            lease.derivative_binding = Some(ManifoldRuntimeDerivativeLeaseBinding {
                schema_id: schema_id(HOST_DERIVATIVE_LEASE_BINDING_SCHEMA),
                binding_id: DottedId::new(format!("binding.derivative.{}", lease.lease_id))
                    .expect("binding id"),
                provider_epoch_id: DottedId::new("epoch.peer.provider.001").expect("epoch"),
                upstream_control_lease_id: upstream_control_lease_id.clone(),
                source_authorization_id: DottedId::new(format!(
                    "authorization.derivative.{}",
                    lease.lease_id
                ))
                .expect("source authorization"),
            });
        }
        ManifoldRuntimeHost::from_snapshot(snapshot).expect("derivative host")
    }

    #[test]
    fn dispatch_application_and_restart_preserve_revision_replay_and_audit() {
        let snapshot = host_fixture("fixtures/runtime-host/synthetic-runtime-host-snapshot.json");
        let request = fixture("fixtures/runtime-host/synthetic-runtime-command-request.json");
        let mut host = ManifoldRuntimeHost::from_snapshot(snapshot).expect("snapshot");
        let dispatch = host.review_command(&request, 2_000);
        assert_eq!(dispatch.outcome, ManifoldRuntimeDispatchOutcome::Ready);
        let applied = host.apply_dispatch(&request, &dispatch, 2_000);
        assert!(applied.applied);
        assert_eq!(host.snapshot().authority_revision.get(), 2);
        let json = host.snapshot_json().expect("snapshot json");
        let restarted = ManifoldRuntimeHost::restart_from_json(&json).expect("restart");
        assert_eq!(restarted.snapshot(), host.snapshot());
        let expected =
            host_fixture("fixtures/runtime-host/synthetic-runtime-host-restarted-snapshot.json");
        assert_eq!(restarted.snapshot(), &expected);
        let mut replay_request = request;
        replay_request.expected_authority_revision = Revision::new(2).expect("revision");
        let replay = restarted.review_command(&replay_request, 2_000);
        assert_eq!(
            replay.rejection_reason,
            Some(ManifoldRuntimeRejectionReason::ReplayedRequest)
        );
        assert_eq!(restarted.snapshot().audit_events.len(), 1);
    }

    #[test]
    fn legacy_v1_restart_migrates_canonical_audit_and_emits_receipt() {
        let json = include_str!("../../../fixtures/runtime-host/legacy-v1-restarted-snapshot.json");
        let (host, receipt) = ManifoldRuntimeHost::restart_from_json_with_migration(json)
            .expect("legacy Runtime Host migration");
        assert!(receipt.migrated);
        assert_eq!(
            receipt.source_schema_id.as_str(),
            LEGACY_HOST_SNAPSHOT_V1_SCHEMA
        );
        assert_eq!(receipt.resulting_schema_id.as_str(), HOST_SNAPSHOT_SCHEMA);
        assert_eq!(receipt.migrated_audit_event_count, 1);
        assert_eq!(receipt.authority_host_id, host.snapshot().host_id);
        assert_eq!(host.snapshot().audit_events[0].sequence, 1);
        assert_eq!(
            host.snapshot().audit_events[0].event_id,
            DottedId::new("audit.runtime.00000000000000000001").expect("id")
        );
        let v2_json = host.snapshot_json().expect("migrated snapshot");
        let (restarted, current_receipt) =
            ManifoldRuntimeHost::restart_from_json_with_migration(&v2_json)
                .expect("current restart");
        assert!(!current_receipt.migrated);
        assert_eq!(restarted, host);

        let damaged = json.replace(
            "\"prior_authority_revision\": 1",
            "\"prior_authority_revision\": 2",
        );
        assert!(ManifoldRuntimeHost::restart_from_json_with_migration(&damaged).is_err());
    }

    #[test]
    fn legacy_v2_restart_preserves_command_lineage_and_initializes_adoptions() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("fixtures/runtime-host/synthetic-runtime-host-restarted-snapshot.json");
        let json = std::fs::read_to_string(root).expect("fixture must load");
        let (host, receipt) =
            ManifoldRuntimeHost::restart_from_json_with_migration(&json).expect("v2 migration");
        assert!(receipt.migrated);
        assert_eq!(
            receipt.source_schema_id.as_str(),
            LEGACY_HOST_SNAPSHOT_V2_SCHEMA
        );
        assert_eq!(host.snapshot().schema_id.as_str(), HOST_SNAPSHOT_SCHEMA);
        assert_eq!(host.snapshot().applied_request_ids.len(), 1);
        assert_eq!(host.snapshot().audit_events.len(), 1);
        assert!(host
            .snapshot()
            .reviewed_control_lease_adoption_ids
            .is_empty());
    }

    #[test]
    fn validated_issue_adoption_advances_once_replays_and_stales_prior_command_review() {
        let snapshot = host_fixture("fixtures/runtime-host/synthetic-runtime-host-snapshot.json");
        let command: ManifoldRuntimeCommandRequest =
            fixture("fixtures/runtime-host/synthetic-runtime-command-request.json");
        let prior: ManifoldAuthoritySnapshot =
            fixture("fixtures/authority/synthetic-authority-snapshot.json");
        let application: ManifoldControlLeaseAuthorityApplication =
            fixture("fixtures/authority-application/synthetic-lease-accepted-application.json");
        let mut host = ManifoldRuntimeHost::from_snapshot(snapshot).expect("snapshot");
        let prior_dispatch = host.review_command(&command, 2_000);
        let request = ManifoldRuntimeControlLeaseAdoptionRequest {
            schema_id: schema_id(HOST_CONTROL_LEASE_ADOPTION_REQUEST_SCHEMA),
            adoption_id: DottedId::new("adoption.runtime.lease.issue.001").expect("id"),
            expected_host_authority_revision: host.snapshot().authority_revision,
            prior_authority_snapshot: prior,
            application: ManifoldRuntimeControlLeaseAuthorityApplication::Issue(application),
        };
        let receipt = host.apply_control_lease_adoption(&request);
        assert!(receipt.applied);
        assert_eq!(receipt.added_lease_ids.len(), 1);
        assert_eq!(host.snapshot().authority_revision.get(), 2);
        assert!(host
            .snapshot()
            .leases
            .iter()
            .any(|lease| lease.lease_id.as_str() == "lease.synthetic_lease_1"));

        let stale = host.apply_dispatch(&command, &prior_dispatch, 2_000);
        assert_eq!(
            stale.rejection_reason,
            Some(ManifoldRuntimeRejectionReason::DispatchRevisionMismatch)
        );
        let revision = host.snapshot().authority_revision;
        let replay = host.apply_control_lease_adoption(&request);
        assert_eq!(
            replay.rejection_reason,
            Some(ManifoldRuntimeRejectionReason::ReplayedControlLeaseAdoption)
        );
        assert_eq!(host.snapshot().authority_revision, revision);
        let restarted =
            ManifoldRuntimeHost::restart_from_json(&host.snapshot_json().expect("json"))
                .expect("restart");
        assert_eq!(restarted.snapshot(), host.snapshot());
    }

    #[test]
    fn damaged_issue_application_is_audited_without_lease_or_revision_change() {
        let snapshot = host_fixture("fixtures/runtime-host/synthetic-runtime-host-snapshot.json");
        let prior: ManifoldAuthoritySnapshot =
            fixture("fixtures/authority/synthetic-authority-snapshot.json");
        let mut application: ManifoldControlLeaseAuthorityApplication =
            fixture("fixtures/authority-application/synthetic-lease-accepted-application.json");
        application.authority_id = DottedId::new("authority.damaged").expect("id");
        let mut host = ManifoldRuntimeHost::from_snapshot(snapshot).expect("snapshot");
        let leases = host.snapshot().leases.clone();
        let request = ManifoldRuntimeControlLeaseAdoptionRequest {
            schema_id: schema_id(HOST_CONTROL_LEASE_ADOPTION_REQUEST_SCHEMA),
            adoption_id: DottedId::new("adoption.runtime.lease.damaged.001").expect("id"),
            expected_host_authority_revision: host.snapshot().authority_revision,
            prior_authority_snapshot: prior,
            application: ManifoldRuntimeControlLeaseAuthorityApplication::Issue(application),
        };
        let receipt = host.apply_control_lease_adoption(&request);
        assert_eq!(
            receipt.rejection_reason,
            Some(ManifoldRuntimeRejectionReason::InvalidControlLeaseAuthorityApplication)
        );
        assert_eq!(host.snapshot().authority_revision, Revision::INITIAL);
        assert_eq!(host.snapshot().leases, leases);
        assert_eq!(host.snapshot().audit_events.len(), 1);
    }

    #[test]
    fn validated_revocation_adoption_removes_exact_lease_and_restarts() {
        let (mut host, request) = revocation_host_and_request(
            "request.runtime.lease.revoke.accepted.001",
            "adoption.runtime.lease.revoke.accepted.001",
        );
        let target_id = host.snapshot().leases[0].lease_id.clone();
        let receipt = host.apply_control_lease_adoption(&request);

        assert!(receipt.applied);
        assert_eq!(
            receipt.operation,
            ManifoldRuntimeControlLeaseAdoptionOperation::Revocation
        );
        assert_eq!(receipt.removed_lease_ids, vec![target_id]);
        assert!(receipt.added_lease_ids.is_empty());
        assert!(receipt.renewed_lease_ids.is_empty());
        assert!(host.snapshot().leases.is_empty());
        assert_eq!(host.snapshot().authority_revision.get(), 2);
        assert_eq!(host.snapshot().audit_events.len(), 1);

        let restarted =
            ManifoldRuntimeHost::restart_from_json(&host.snapshot_json().expect("snapshot"))
                .expect("revocation restart");
        assert_eq!(restarted.snapshot(), host.snapshot());
    }

    #[test]
    fn damaged_or_substituted_revocation_rejects_without_state_change() {
        let (mut damaged_host, mut damaged_request) = revocation_host_and_request(
            "request.runtime.lease.revoke.damaged.001",
            "adoption.runtime.lease.revoke.damaged.001",
        );
        let ManifoldRuntimeControlLeaseAuthorityApplication::Revocation(application) =
            &mut damaged_request.application
        else {
            panic!("revocation application expected");
        };
        application.authority_id = DottedId::new("authority.substituted").expect("authority");
        let prior_damaged = damaged_host.snapshot().clone();
        let damaged = damaged_host.apply_control_lease_adoption(&damaged_request);
        assert_eq!(
            damaged.rejection_reason,
            Some(ManifoldRuntimeRejectionReason::InvalidControlLeaseAuthorityApplication)
        );
        assert_eq!(damaged_host.snapshot().leases, prior_damaged.leases);
        assert_eq!(
            damaged_host.snapshot().authority_revision,
            prior_damaged.authority_revision
        );

        let (mut substituted_host, substituted_request) = revocation_host_and_request(
            "request.runtime.lease.revoke.substituted.001",
            "adoption.runtime.lease.revoke.substituted.001",
        );
        substituted_host.snapshot.leases[0].holder_id =
            DottedId::new("holder.substituted").expect("holder");
        let prior_substituted = substituted_host.snapshot().clone();
        let substituted = substituted_host.apply_control_lease_adoption(&substituted_request);
        assert_eq!(
            substituted.rejection_reason,
            Some(ManifoldRuntimeRejectionReason::ControlLeaseDeltaMismatch)
        );
        assert_eq!(substituted_host.snapshot().leases, prior_substituted.leases);
        assert_eq!(
            substituted_host.snapshot().authority_revision,
            prior_substituted.authority_revision
        );
    }

    #[test]
    fn revocation_adoption_replay_is_retained_across_restart() {
        let (mut host, request) = revocation_host_and_request(
            "request.runtime.lease.revoke.replay.001",
            "adoption.runtime.lease.revoke.replay.001",
        );
        assert!(host.apply_control_lease_adoption(&request).applied);
        let replay = host.apply_control_lease_adoption(&request);
        assert_eq!(
            replay.rejection_reason,
            Some(ManifoldRuntimeRejectionReason::ReplayedControlLeaseAdoption)
        );
        assert_eq!(host.snapshot().authority_revision.get(), 2);

        let mut restarted =
            ManifoldRuntimeHost::restart_from_json(&host.snapshot_json().expect("snapshot"))
                .expect("restart");
        let replay_after_restart = restarted.apply_control_lease_adoption(&request);
        assert_eq!(
            replay_after_restart.rejection_reason,
            Some(ManifoldRuntimeRejectionReason::ReplayedControlLeaseAdoption)
        );
        assert_eq!(restarted.snapshot().authority_revision.get(), 2);
    }

    #[test]
    fn stale_host_revision_rejects_revocation_before_removal() {
        let (mut host, mut request) = revocation_host_and_request(
            "request.runtime.lease.revoke.stale.001",
            "adoption.runtime.lease.revoke.stale.001",
        );
        request.expected_host_authority_revision = request
            .expected_host_authority_revision
            .next()
            .expect("revision");
        let prior = host.snapshot().clone();
        let receipt = host.apply_control_lease_adoption(&request);
        assert_eq!(
            receipt.rejection_reason,
            Some(ManifoldRuntimeRejectionReason::StaleAuthorityRevision)
        );
        assert_eq!(host.snapshot().leases, prior.leases);
        assert_eq!(host.snapshot().authority_revision, prior.authority_revision);
        assert!(host
            .snapshot()
            .reviewed_control_lease_adoption_ids
            .contains(&request.adoption_id));
    }

    #[test]
    fn rejected_generic_revocation_application_is_not_adopted() {
        let prior: ManifoldAuthoritySnapshot =
            fixture("fixtures/authority/synthetic-authority-snapshot.json");
        let unknown_lease = DottedId::new("lease.unknown").expect("lease");
        let unknown_scope = DottedId::new("scope.unknown").expect("scope");
        let application = control_lease_revocation_application(
            &prior,
            "request.runtime.lease.revoke.rejected.001",
            &unknown_lease,
            &unknown_scope,
        );
        assert_eq!(
            application.outcome,
            ManifoldControlLeaseRevocationAuthorityApplicationOutcome::
                LeaseRevocationApplicationRejected
        );
        let mut snapshot =
            host_fixture("fixtures/runtime-host/synthetic-runtime-host-snapshot.json");
        snapshot.leases = vec![runtime_lease(&prior.active_leases[0])];
        let mut host = ManifoldRuntimeHost::from_snapshot(snapshot).expect("host");
        let request = ManifoldRuntimeControlLeaseAdoptionRequest {
            schema_id: schema_id(HOST_CONTROL_LEASE_ADOPTION_REQUEST_SCHEMA),
            adoption_id: DottedId::new("adoption.runtime.lease.revoke.rejected.001")
                .expect("adoption"),
            expected_host_authority_revision: host.snapshot().authority_revision,
            prior_authority_snapshot: prior,
            application: ManifoldRuntimeControlLeaseAuthorityApplication::Revocation(Box::new(
                application,
            )),
        };
        let prior_host = host.snapshot().clone();
        let receipt = host.apply_control_lease_adoption(&request);
        assert_eq!(
            receipt.rejection_reason,
            Some(ManifoldRuntimeRejectionReason::RejectedControlLeaseAuthorityApplication)
        );
        assert_eq!(host.snapshot().leases, prior_host.leases);
        assert_eq!(
            host.snapshot().authority_revision,
            prior_host.authority_revision
        );
    }

    #[test]
    fn derivative_lease_revocation_applies_atomically_and_validates_after_restart() {
        let snapshot = host_fixture("fixtures/runtime-host/synthetic-runtime-host-snapshot.json");
        let mut host = derivative_host(snapshot);
        let request = derivative_lease_revocation_request(
            &host,
            "revoke.derivative.accepted.001",
            host.snapshot().leases.clone(),
        );
        let removed = request.exact_leases.clone();
        let receipt = host.apply_derivative_lease_revocation(&request);

        assert!(receipt.applied);
        assert_eq!(receipt.removed_leases, removed);
        assert!(host.snapshot().leases.is_empty());
        assert_eq!(host.snapshot().authority_revision.get(), 2);
        assert_eq!(
            host.snapshot().audit_events[0].event_kind,
            ManifoldRuntimeAuditKind::DerivativeLeaseRevocation
        );
        receipt
            .validate_against_snapshot(host.snapshot())
            .expect("live receipt closure");

        let restarted =
            ManifoldRuntimeHost::restart_from_json(&host.snapshot_json().expect("snapshot"))
                .expect("restart");
        receipt
            .validate_against_snapshot(restarted.snapshot())
            .expect("restarted receipt closure");
    }

    #[test]
    fn derivative_lease_revocation_stale_revision_is_audited_without_removal() {
        let snapshot = host_fixture("fixtures/runtime-host/synthetic-runtime-host-snapshot.json");
        let mut host = derivative_host(snapshot);
        let mut request = derivative_lease_revocation_request(
            &host,
            "revoke.derivative.stale.001",
            host.snapshot().leases.clone(),
        );
        request.expected_host_authority_revision = request
            .expected_host_authority_revision
            .next()
            .expect("revision");
        let prior = host.snapshot().clone();
        let receipt = host.apply_derivative_lease_revocation(&request);

        assert_eq!(
            receipt.rejection_reason,
            Some(ManifoldRuntimeRejectionReason::StaleAuthorityRevision)
        );
        assert_eq!(host.snapshot().leases, prior.leases);
        assert_eq!(host.snapshot().authority_revision, prior.authority_revision);
        receipt
            .validate_against_snapshot(host.snapshot())
            .expect("stale receipt closure");
    }

    #[test]
    fn derivative_lease_revocation_replay_is_retained_across_restart() {
        let snapshot = host_fixture("fixtures/runtime-host/synthetic-runtime-host-snapshot.json");
        let mut host = derivative_host(snapshot);
        let request = derivative_lease_revocation_request(
            &host,
            "revoke.derivative.replay.001",
            host.snapshot().leases.clone(),
        );
        let accepted = host.apply_derivative_lease_revocation(&request);
        assert!(accepted.applied);
        let replay = host.apply_derivative_lease_revocation(&request);
        assert_eq!(
            replay.rejection_reason,
            Some(ManifoldRuntimeRejectionReason::ReplayedDerivativeLeaseRevocation)
        );
        replay
            .validate_against_snapshot(host.snapshot())
            .expect("replay receipt closure");

        let restarted =
            ManifoldRuntimeHost::restart_from_json(&host.snapshot_json().expect("snapshot"))
                .expect("restart");
        replay
            .validate_against_snapshot(restarted.snapshot())
            .expect("restarted replay closure");
    }

    #[test]
    fn derivative_lease_revocation_rejects_exact_object_substitution() {
        let snapshot = host_fixture("fixtures/runtime-host/synthetic-runtime-host-snapshot.json");
        let mut host = derivative_host(snapshot);
        let mut substituted = host.snapshot().leases.clone();
        substituted[0].holder_id = DottedId::new("client.substituted").expect("holder");
        let request = derivative_lease_revocation_request(
            &host,
            "revoke.derivative.substituted.001",
            substituted,
        );
        let prior = host.snapshot().clone();
        let receipt = host.apply_derivative_lease_revocation(&request);

        assert_eq!(
            receipt.rejection_reason,
            Some(ManifoldRuntimeRejectionReason::DerivativeLeaseDeltaMismatch)
        );
        assert_eq!(host.snapshot().leases, prior.leases);
        assert_eq!(host.snapshot().authority_revision, prior.authority_revision);
        receipt
            .validate_against_snapshot(host.snapshot())
            .expect("substitution receipt closure");
    }

    #[test]
    fn derivative_lease_revocation_rejects_fabricated_upstream_lineage() {
        let snapshot = host_fixture("fixtures/runtime-host/synthetic-runtime-host-snapshot.json");
        let mut host = derivative_host(snapshot);
        let mut request = derivative_lease_revocation_request(
            &host,
            "revoke.derivative.fabricated_upstream.001",
            host.snapshot().leases.clone(),
        );
        request
            .upstream_revocation_proof
            .accepted_application
            .application_id =
            DottedId::new("lease_revocation_application.fabricated").expect("application");
        let prior = host.snapshot().clone();
        let receipt = host.apply_derivative_lease_revocation(&request);

        assert_eq!(
            receipt.rejection_reason,
            Some(ManifoldRuntimeRejectionReason::InvalidDerivativeLeaseRevocationRequest)
        );
        assert_eq!(host.snapshot().leases, prior.leases);
        assert_eq!(host.snapshot().authority_revision, prior.authority_revision);
        receipt
            .validate_against_snapshot(host.snapshot())
            .expect("fabricated proof rejection remains exact");
        ManifoldRuntimeHost::restart_from_json(&host.snapshot_json().expect("snapshot"))
            .expect("fabricated proof rejection restart");
    }

    #[test]
    fn derivative_lease_revocation_rejects_unrelated_exact_accepted_lease() {
        let mut snapshot =
            host_fixture("fixtures/runtime-host/synthetic-runtime-host-snapshot.json");
        let mut unrelated = snapshot.leases[0].clone();
        unrelated.lease_id = DottedId::new("lease.peer.unrelated").expect("lease");
        snapshot.leases.push(unrelated);
        snapshot
            .leases
            .sort_by(|left, right| left.lease_id.cmp(&right.lease_id));
        let bound = derivative_host(snapshot);
        let mut differently_bound = bound.snapshot().clone();
        let unrelated = differently_bound
            .leases
            .iter_mut()
            .find(|lease| lease.lease_id.as_str() == "lease.peer.unrelated")
            .expect("unrelated lease");
        unrelated
            .derivative_binding
            .as_mut()
            .expect("derivative binding")
            .upstream_control_lease_id =
            DottedId::new("lease.outer.unrelated").expect("outer lease");
        let mut host =
            ManifoldRuntimeHost::from_snapshot(differently_bound).expect("mixed lineage host");
        let unrelated = host
            .snapshot()
            .leases
            .iter()
            .find(|lease| lease.lease_id.as_str() == "lease.peer.unrelated")
            .expect("unrelated lease")
            .clone();
        let request = derivative_lease_revocation_request(
            &host,
            "revoke.derivative.unrelated.001",
            vec![unrelated],
        );
        let prior = host.snapshot().clone();
        let receipt = host.apply_derivative_lease_revocation(&request);

        assert_eq!(
            receipt.rejection_reason,
            Some(ManifoldRuntimeRejectionReason::DerivativeLeaseDeltaMismatch)
        );
        assert_eq!(host.snapshot().leases, prior.leases);
        receipt
            .validate_against_snapshot(host.snapshot())
            .expect("unrelated exact lease rejection closure");
    }

    #[test]
    fn derivative_lease_revocation_rejects_partial_matching_lineage_set() {
        let mut snapshot =
            host_fixture("fixtures/runtime-host/synthetic-runtime-host-snapshot.json");
        let mut second = snapshot.leases[0].clone();
        second.lease_id = DottedId::new("lease.peer.beta").expect("lease");
        snapshot.leases.push(second);
        snapshot
            .leases
            .sort_by(|left, right| left.lease_id.cmp(&right.lease_id));
        let mut host = derivative_host(snapshot);
        let request = derivative_lease_revocation_request(
            &host,
            "revoke.derivative.partial.001",
            vec![host.snapshot().leases[0].clone()],
        );
        let prior = host.snapshot().clone();
        let receipt = host.apply_derivative_lease_revocation(&request);

        assert_eq!(
            receipt.rejection_reason,
            Some(ManifoldRuntimeRejectionReason::DerivativeLeaseDeltaMismatch)
        );
        assert_eq!(host.snapshot().leases, prior.leases);
        assert_eq!(host.snapshot().authority_revision, prior.authority_revision);
        receipt
            .validate_against_snapshot(host.snapshot())
            .expect("partial matching lineage rejection closure");
    }

    #[test]
    fn derivative_lease_revocation_rejects_noncanonical_order_and_restarts() {
        let mut snapshot =
            host_fixture("fixtures/runtime-host/synthetic-runtime-host-snapshot.json");
        let mut second = snapshot.leases[0].clone();
        second.lease_id = DottedId::new("lease.peer.beta").expect("lease");
        snapshot.leases.push(second);
        snapshot
            .leases
            .sort_by(|left, right| left.lease_id.cmp(&right.lease_id));
        let mut host = derivative_host(snapshot);
        let mut reversed = host.snapshot().leases.clone();
        reversed.reverse();
        let request =
            derivative_lease_revocation_request(&host, "revoke.derivative.order.001", reversed);
        let prior = host.snapshot().clone();
        let receipt = host.apply_derivative_lease_revocation(&request);

        assert_eq!(
            receipt.rejection_reason,
            Some(ManifoldRuntimeRejectionReason::InvalidDerivativeLeaseRevocationRequest)
        );
        assert_eq!(host.snapshot().leases, prior.leases);
        receipt
            .validate_against_snapshot(host.snapshot())
            .expect("order rejection closure");
        let restarted =
            ManifoldRuntimeHost::restart_from_json(&host.snapshot_json().expect("snapshot"))
                .expect("rejected restart");
        receipt
            .validate_against_snapshot(restarted.snapshot())
            .expect("restarted order closure");
    }

    #[test]
    fn legacy_v3_snapshot_migrates_explicitly_to_v4() {
        let snapshot = host_fixture("fixtures/runtime-host/synthetic-runtime-host-snapshot.json");
        let mut value = serde_json::to_value(snapshot).expect("snapshot value");
        value["$schema"] = serde_json::Value::String(LEGACY_HOST_SNAPSHOT_V3_SCHEMA.to_owned());
        value
            .as_object_mut()
            .expect("snapshot object")
            .remove("reviewed_derivative_lease_revocation_ids");
        for event in value["audit_events"].as_array_mut().expect("audit array") {
            event["$schema"] =
                serde_json::Value::String(LEGACY_HOST_AUDIT_EVENT_V3_SCHEMA.to_owned());
        }
        let json = serde_json::to_string(&value).expect("legacy json");
        let (migrated, receipt) =
            ManifoldRuntimeHost::restart_from_json_with_migration(&json).expect("v3 migration");
        assert!(receipt.migrated);
        assert_eq!(
            receipt.source_schema_id.as_str(),
            LEGACY_HOST_SNAPSHOT_V3_SCHEMA
        );
        assert_eq!(migrated.snapshot().schema_id.as_str(), HOST_SNAPSHOT_SCHEMA);
        assert!(migrated
            .snapshot()
            .reviewed_derivative_lease_revocation_ids
            .is_empty());
    }

    #[test]
    fn applied_replay_repeated_rejection_and_repeated_sweep_restart_cleanly() {
        let snapshot = host_fixture("fixtures/runtime-host/synthetic-runtime-host-snapshot.json");
        let request: ManifoldRuntimeCommandRequest =
            fixture("fixtures/runtime-host/synthetic-runtime-command-request.json");
        let mut host = ManifoldRuntimeHost::from_snapshot(snapshot).expect("snapshot");
        let dispatch = host.review_command(&request, 2_000);
        assert!(host.apply_dispatch(&request, &dispatch, 2_000).applied);

        let mut replay = request.clone();
        replay.expected_authority_revision = host.snapshot().authority_revision;
        for _ in 0..2 {
            let rejected = host.review_command(&replay, 2_100);
            let receipt = host.apply_dispatch(&replay, &rejected, 2_100);
            assert_eq!(
                receipt.rejection_reason,
                Some(ManifoldRuntimeRejectionReason::ReplayedRequest)
            );
        }

        let unknown: ManifoldRuntimeCommandRequest =
            fixture("fixtures/damaged/runtime-host-unknown-command.json");
        for _ in 0..2 {
            let rejected = host.review_command(&unknown, 2_200);
            let receipt = host.apply_dispatch(&unknown, &rejected, 2_200);
            assert_eq!(
                receipt.rejection_reason,
                Some(ManifoldRuntimeRejectionReason::StaleAuthorityRevision)
            );
        }

        let sweep_id = DottedId::new("sweep.runtime.repeated.001").expect("id");
        let first = host.expire_leases(sweep_id.clone(), host.snapshot().authority_revision, 1_000);
        assert_eq!(
            first.rejection_reason,
            Some(ManifoldRuntimeRejectionReason::NoExpiredLeases)
        );
        let repeated = host.expire_leases(sweep_id, host.snapshot().authority_revision, 1_000);
        assert_eq!(
            repeated.rejection_reason,
            Some(ManifoldRuntimeRejectionReason::ReplayedSweep)
        );

        let json = host.snapshot_json().expect("snapshot json");
        let restarted = ManifoldRuntimeHost::restart_from_json(&json).expect("restart");
        assert_eq!(restarted.snapshot(), host.snapshot());
        assert!(restarted
            .snapshot()
            .audit_events
            .windows(2)
            .all(|pair| pair[0].sequence + 1 == pair[1].sequence));
    }

    #[test]
    fn restart_rejects_gapped_reordered_or_forged_audit_identity() {
        let snapshot = host_fixture("fixtures/runtime-host/synthetic-runtime-host-snapshot.json");
        let request: ManifoldRuntimeCommandRequest =
            fixture("fixtures/runtime-host/synthetic-runtime-command-request.json");
        let mut host = ManifoldRuntimeHost::from_snapshot(snapshot).expect("snapshot");
        let dispatch = host.review_command(&request, 2_000);
        assert!(host.apply_dispatch(&request, &dispatch, 2_000).applied);
        let mut damaged = host.snapshot().clone();
        damaged.audit_events[0].sequence = 2;
        assert!(ManifoldRuntimeHost::from_snapshot(damaged).is_err());
        let mut damaged = host.snapshot().clone();
        damaged.audit_events[0].event_id =
            DottedId::new("audit.runtime.00000000000000000999").expect("id");
        assert!(ManifoldRuntimeHost::from_snapshot(damaged).is_err());
    }

    #[test]
    fn capacity_exhaustion_receipt_preserves_authority_provenance_and_restorable_state() {
        let mut command_snapshot =
            host_fixture("fixtures/runtime-host/synthetic-runtime-host-snapshot.json");
        command_snapshot.leases.clear();
        let mut host = ManifoldRuntimeHost::from_snapshot(command_snapshot).expect("snapshot");
        for index in 0..MAX_RUNTIME_SNAPSHOT_RECORDS {
            let request = ManifoldRuntimeCommandRequest {
                schema_id: schema_id(HOST_COMMAND_REQUEST_SCHEMA),
                request_id: DottedId::new(format!("request.runtime.cap.{index:04}")).expect("id"),
                expected_authority_revision: host.snapshot().authority_revision,
                requester_id: DottedId::new("client.operator").expect("id"),
                command_id: DottedId::new("command.status.get").expect("id"),
                lease_id: None,
                params_digest: None,
                issued_at_ms: 1,
                expires_at_ms: 100_000,
            };
            let dispatch = host.review_command(&request, 2_000);
            assert!(host.apply_dispatch(&request, &dispatch, 2_000).applied);
        }
        for index in MAX_RUNTIME_SNAPSHOT_RECORDS..MAX_RUNTIME_AUDIT_EVENTS {
            let request = ManifoldRuntimeCommandRequest {
                schema_id: schema_id(HOST_COMMAND_REQUEST_SCHEMA),
                request_id: DottedId::new(format!("request.runtime.audit.cap.{index:04}"))
                    .expect("id"),
                expected_authority_revision: host.snapshot().authority_revision,
                requester_id: DottedId::new("client.operator").expect("id"),
                command_id: DottedId::new("command.unknown").expect("id"),
                lease_id: None,
                params_digest: None,
                issued_at_ms: 1,
                expires_at_ms: 100_000,
            };
            let dispatch = host.review_command(&request, 2_000);
            assert!(!host.apply_dispatch(&request, &dispatch, 2_000).applied);
        }
        let overflow = ManifoldRuntimeCommandRequest {
            schema_id: schema_id(HOST_COMMAND_REQUEST_SCHEMA),
            request_id: DottedId::new("request.runtime.cap.overflow").expect("id"),
            expected_authority_revision: host.snapshot().authority_revision,
            requester_id: DottedId::new("client.operator").expect("id"),
            command_id: DottedId::new("command.status.get").expect("id"),
            lease_id: None,
            params_digest: None,
            issued_at_ms: 1,
            expires_at_ms: 100_000,
        };
        let authority_host_id = host.snapshot().host_id.clone();
        let expected_dispatch_id = derived_id("dispatch.runtime", &overflow.request_id);
        let prior_revision = host.snapshot().authority_revision;
        let audit_count = host.snapshot().audit_events.len();
        let mut forged_dispatch = host.review_command(&overflow, 2_000);
        forged_dispatch.authority_host_id =
            DottedId::new("runtime.host.forged").expect("forged host id");
        forged_dispatch.dispatch_id =
            DottedId::new("dispatch.runtime.forged").expect("forged dispatch id");
        let receipt = host.apply_dispatch(&overflow, &forged_dispatch, 2_000);
        assert_eq!(
            receipt.rejection_reason,
            Some(ManifoldRuntimeRejectionReason::AuthorityCapacityExhausted)
        );
        assert_eq!(receipt.authority_host_id, authority_host_id);
        assert_eq!(receipt.dispatch_id, expected_dispatch_id);
        assert_eq!(receipt.prior_authority_revision, prior_revision);
        assert_eq!(receipt.resulting_authority_revision, prior_revision);
        assert_eq!(host.snapshot().authority_revision, prior_revision);
        assert_eq!(host.snapshot().audit_events.len(), audit_count);
        assert_eq!(
            host.snapshot().applied_request_ids.len(),
            MAX_RUNTIME_SNAPSHOT_RECORDS
        );
        ManifoldRuntimeHost::restart_from_json(&host.snapshot_json().expect("json"))
            .expect("command-cap snapshot remains restorable");

        let mut sweep_snapshot =
            host_fixture("fixtures/runtime-host/synthetic-runtime-host-snapshot.json");
        sweep_snapshot.leases.clear();
        let mut host = ManifoldRuntimeHost::from_snapshot(sweep_snapshot).expect("snapshot");
        for index in 0..MAX_RUNTIME_SNAPSHOT_RECORDS {
            let receipt = host.expire_leases(
                DottedId::new(format!("sweep.runtime.cap.{index:04}")).expect("id"),
                host.snapshot().authority_revision,
                2_000,
            );
            assert_eq!(
                receipt.rejection_reason,
                Some(ManifoldRuntimeRejectionReason::NoExpiredLeases)
            );
        }
        let audit_count = host.snapshot().audit_events.len();
        let receipt = host.expire_leases(
            DottedId::new("sweep.runtime.cap.overflow").expect("id"),
            host.snapshot().authority_revision,
            2_000,
        );
        assert_eq!(
            receipt.rejection_reason,
            Some(ManifoldRuntimeRejectionReason::AuthorityCapacityExhausted)
        );
        assert_eq!(host.snapshot().audit_events.len(), audit_count);
        ManifoldRuntimeHost::restart_from_json(&host.snapshot_json().expect("json"))
            .expect("sweep-cap snapshot remains restorable");
    }

    #[test]
    fn unknown_command_and_missing_or_expired_leases_reject_without_revision_change() {
        let snapshot = host_fixture("fixtures/runtime-host/synthetic-runtime-host-snapshot.json");
        let mut host = ManifoldRuntimeHost::from_snapshot(snapshot).expect("snapshot");
        for path in [
            "fixtures/damaged/runtime-host-unknown-command.json",
            "fixtures/damaged/runtime-host-missing-lease.json",
            "fixtures/damaged/runtime-host-expired-lease.json",
        ] {
            let request = fixture(path);
            let dispatch = host.review_command(&request, 70_000);
            assert_eq!(
                dispatch.outcome,
                ManifoldRuntimeDispatchOutcome::Rejected,
                "{path}"
            );
            let receipt = host.apply_dispatch(&request, &dispatch, 70_000);
            assert!(!receipt.applied, "{path}");
            assert_eq!(host.snapshot().authority_revision.get(), 1, "{path}");
        }
    }

    #[test]
    fn explicit_lease_expiry_advances_once_and_stale_sweep_rejects() {
        let snapshot = host_fixture("fixtures/runtime-host/synthetic-runtime-host-snapshot.json");
        let mut host = ManifoldRuntimeHost::from_snapshot(snapshot).expect("snapshot");
        let sweep = host.expire_leases(
            DottedId::new("sweep.runtime.001").expect("id"),
            Revision::new(1).expect("revision"),
            70_000,
        );
        assert!(sweep.applied);
        assert_eq!(sweep.removed_lease_ids.len(), 1);
        assert_eq!(host.snapshot().authority_revision.get(), 2);
        let stale = host.expire_leases(
            DottedId::new("sweep.runtime.002").expect("id"),
            Revision::new(1).expect("revision"),
            80_000,
        );
        assert!(!stale.applied);
        assert_eq!(
            stale.rejection_reason,
            Some(ManifoldRuntimeRejectionReason::StaleAuthorityRevision)
        );
        assert_eq!(host.snapshot().authority_revision.get(), 2);
    }

    #[test]
    fn runtime_host_receipt_fixtures_deserialize() {
        let _: ManifoldRuntimeDispatchReceipt =
            fixture("fixtures/runtime-host/synthetic-runtime-dispatch-receipt.json");
        let _: ManifoldRuntimeApplicationReceipt =
            fixture("fixtures/runtime-host/synthetic-runtime-application-receipt.json");
        let _: ManifoldRuntimeLeaseExpiryReceipt =
            fixture("fixtures/runtime-host/synthetic-runtime-lease-expiry-receipt.json");
        let _: ManifoldRuntimeAuditEvent =
            fixture("fixtures/runtime-host/synthetic-runtime-audit-event.json");
    }

    #[test]
    fn forged_dispatch_identity_rejects_without_revision_change() {
        let snapshot = host_fixture("fixtures/runtime-host/synthetic-runtime-host-snapshot.json");
        let request = fixture("fixtures/runtime-host/synthetic-runtime-command-request.json");
        let mut host = ManifoldRuntimeHost::from_snapshot(snapshot).expect("snapshot");
        let mut dispatch = host.review_command(&request, 2_000);
        dispatch.dispatch_id = DottedId::new("dispatch.runtime.forged").expect("id");
        let receipt = host.apply_dispatch(&request, &dispatch, 2_000);
        assert!(!receipt.applied);
        assert_eq!(
            receipt.rejection_reason,
            Some(ManifoldRuntimeRejectionReason::DispatchMismatch)
        );
        assert_eq!(host.snapshot().authority_revision.get(), 1);
    }

    #[test]
    fn fabricated_ready_expiry_and_state_change_are_revalidated_at_apply() {
        let snapshot = host_fixture("fixtures/runtime-host/synthetic-runtime-host-snapshot.json");

        let unknown: ManifoldRuntimeCommandRequest =
            fixture("fixtures/damaged/runtime-host-unknown-command.json");
        let mut forged_host =
            ManifoldRuntimeHost::from_snapshot(snapshot.clone()).expect("snapshot");
        let mut fabricated = forged_host.review_command(&unknown, 2_000);
        fabricated.outcome = ManifoldRuntimeDispatchOutcome::Ready;
        fabricated.rejection_reason = None;
        let rejected = forged_host.apply_dispatch(&unknown, &fabricated, 2_000);
        assert_eq!(
            rejected.rejection_reason,
            Some(ManifoldRuntimeRejectionReason::UnknownCommand)
        );
        assert_eq!(forged_host.snapshot().authority_revision, Revision::INITIAL);

        let request: ManifoldRuntimeCommandRequest =
            fixture("fixtures/runtime-host/synthetic-runtime-command-request.json");
        let mut expiry_host =
            ManifoldRuntimeHost::from_snapshot(snapshot.clone()).expect("snapshot");
        let dispatch = expiry_host.review_command(&request, 2_000);
        let expired = expiry_host.apply_dispatch(&request, &dispatch, request.expires_at_ms);
        assert_eq!(
            expired.rejection_reason,
            Some(ManifoldRuntimeRejectionReason::ExpiredRequest)
        );
        assert_eq!(expiry_host.snapshot().authority_revision, Revision::INITIAL);

        let mut state_host = ManifoldRuntimeHost::from_snapshot(snapshot).expect("snapshot");
        let mut second = request.clone();
        second.request_id = DottedId::new("request.runtime.second").expect("id");
        let second_dispatch = state_host.review_command(&second, 2_000);
        let first_dispatch = state_host.review_command(&request, 2_000);
        assert!(
            state_host
                .apply_dispatch(&request, &first_dispatch, 2_000)
                .applied
        );
        let stale = state_host.apply_dispatch(&second, &second_dispatch, 2_000);
        assert_eq!(
            stale.rejection_reason,
            Some(ManifoldRuntimeRejectionReason::DispatchRevisionMismatch)
        );
        assert_eq!(state_host.snapshot().authority_revision.get(), 2);
    }

    #[test]
    fn typed_params_digest_is_bound_through_dispatch_and_application() {
        let snapshot = host_fixture("fixtures/runtime-host/synthetic-runtime-host-snapshot.json");
        let mut request: ManifoldRuntimeCommandRequest =
            fixture("fixtures/runtime-host/synthetic-runtime-command-request.json");
        request.params_digest = Some(typed_params_digest(128));
        let mut host = ManifoldRuntimeHost::from_snapshot(snapshot).expect("snapshot");
        let dispatch = host.review_command(&request, 2_000);
        assert_eq!(dispatch.params_digest, request.params_digest);
        assert_eq!(dispatch.outcome, ManifoldRuntimeDispatchOutcome::Ready);
        let application = host.apply_dispatch(&request, &dispatch, 2_000);
        assert!(application.applied);
        assert_eq!(application.params_digest, request.params_digest);
    }

    #[test]
    fn typed_params_tamper_and_oversize_reject_without_state_advance() {
        let snapshot = host_fixture("fixtures/runtime-host/synthetic-runtime-host-snapshot.json");
        let mut request: ManifoldRuntimeCommandRequest =
            fixture("fixtures/runtime-host/synthetic-runtime-command-request.json");
        request.params_digest = Some(typed_params_digest(128));
        let mut host = ManifoldRuntimeHost::from_snapshot(snapshot.clone()).expect("snapshot");
        let dispatch = host.review_command(&request, 2_000);
        request
            .params_digest
            .as_mut()
            .expect("digest")
            .canonical_sha256 = format!("sha256:{}", "cd".repeat(32));
        let tampered = host.apply_dispatch(&request, &dispatch, 2_000);
        assert_eq!(
            tampered.rejection_reason,
            Some(ManifoldRuntimeRejectionReason::DispatchMismatch)
        );
        assert_eq!(host.snapshot().authority_revision.get(), 1);

        let mut oversize: ManifoldRuntimeCommandRequest =
            fixture("fixtures/runtime-host/synthetic-runtime-command-request.json");
        oversize.params_digest = Some(typed_params_digest(MAX_TYPED_PARAMS_CANONICAL_BYTES + 1));
        let oversize_host = ManifoldRuntimeHost::from_snapshot(snapshot.clone()).expect("snapshot");
        let oversize_dispatch = oversize_host.review_command(&oversize, 2_000);
        assert_eq!(
            oversize_dispatch.rejection_reason,
            Some(ManifoldRuntimeRejectionReason::TypedParamsTooLarge)
        );

        let mut malformed: ManifoldRuntimeCommandRequest =
            fixture("fixtures/runtime-host/synthetic-runtime-command-request.json");
        malformed.params_digest = Some(typed_params_digest(128));
        malformed
            .params_digest
            .as_mut()
            .expect("digest")
            .canonical_sha256 = "sha256:NOT-CANONICAL".to_owned();
        let malformed_host = ManifoldRuntimeHost::from_snapshot(snapshot).expect("snapshot");
        let malformed_dispatch = malformed_host.review_command(&malformed, 2_000);
        assert_eq!(
            malformed_dispatch.rejection_reason,
            Some(ManifoldRuntimeRejectionReason::InvalidTypedParamsDigest)
        );
    }
}
