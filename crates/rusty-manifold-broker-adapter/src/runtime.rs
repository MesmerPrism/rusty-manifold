//! Stateful product broker runtime binding admission to Runtime Host mutation.

use crate::{
    control_lease_lifecycle_capability, control_lease_lifecycle_request_sha256,
    ManifoldBrokerAdapter, ManifoldBrokerAdapterConfig, ManifoldBrokerAdapterReceipt,
    ManifoldBrokerControlLeaseAuthority, ManifoldBrokerControlLeaseAuthorityError,
    ManifoldBrokerControlLeaseAuthorityEvidence, ManifoldBrokerControlLeaseAuthorityEvidenceV2,
    ManifoldBrokerControlLeaseLifecycleAuthorizationReceipt,
    ManifoldBrokerControlLeaseLifecycleOperation, ManifoldBrokerControlLeaseLifecycleOperationKind,
    ManifoldBrokerControlLeaseLifecycleOutcome, ManifoldBrokerControlLeaseLifecycleReceipt,
    ManifoldBrokerControlLeaseLifecycleRejectionReason, ManifoldBrokerControlLeaseLifecycleRequest,
    ManifoldBrokerControlLeaseLifecycleUse, ManifoldBrokerControlLeaseTransition,
    ManifoldBrokerControlLeaseTransitionApplication, ManifoldBrokerControlLeaseTransitionKind,
    BROKER_CONTROL_LEASE_AUTHORITY_EVIDENCE_V3_SCHEMA,
    BROKER_CONTROL_LEASE_CLEANUP_TRANSITION_RESERVE,
    BROKER_CONTROL_LEASE_LIFECYCLE_AUTHORIZATION_RECEIPT_SCHEMA,
    BROKER_CONTROL_LEASE_LIFECYCLE_RECEIPT_SCHEMA, BROKER_CONTROL_LEASE_LIFECYCLE_REQUEST_SCHEMA,
    BROKER_CONTROL_LEASE_LIFECYCLE_USE_SCHEMA,
    LEGACY_BROKER_CONTROL_LEASE_AUTHORITY_EVIDENCE_V2_SCHEMA,
    LEGACY_BROKER_CONTROL_LEASE_LIFECYCLE_RECEIPT_V1_SCHEMA,
    LEGACY_BROKER_CONTROL_LEASE_LIFECYCLE_USE_V1_SCHEMA,
    LEGACY_BROKER_CONTROL_LEASE_TRANSITION_V1_SCHEMA, MAX_BROKER_CONTROL_LEASE_TRANSITIONS,
    RUNTIME_HOST_AUTHORITY_OWNER,
};
use rusty_manifold_admission::{
    ManifoldAdmissionAuthority, ManifoldAdmissionLegacyClientLockBinding,
    ManifoldAdmissionMigrationReceipt, ManifoldAdmissionOperation, ManifoldAdmissionReceipt,
    ManifoldAdmissionRejectionReason, ManifoldAdmissionRequest, ManifoldAdmissionRevocationRequest,
    ManifoldAdmissionSnapshot, ManifoldAdmissionToken, ManifoldAdmissionUseRequest,
    ManifoldClientIdentity,
};
use rusty_manifold_broker_product::ManifoldBrokerFeature;
use rusty_manifold_model::{
    DottedId, ManifoldAuthorityExpirySweepRequest, ManifoldClockSnapshot,
    ManifoldControlLeaseReleaseRequest, ManifoldControlLeaseRenewalRequest,
    ManifoldControlLeaseRequest, ManifoldControlLeaseRevocationRequest, Revision, SchemaId,
};
use rusty_manifold_runtime_host::{
    ManifoldRuntimeAuditKind, ManifoldRuntimeCommandRequest,
    ManifoldRuntimeControlLeaseAdoptionOperation, ManifoldRuntimeControlLeaseAdoptionReceipt,
    ManifoldRuntimeControlLeaseAdoptionRequest, ManifoldRuntimeControlLeaseAuthorityApplication,
    ManifoldRuntimeHost, ManifoldRuntimeHostError, ManifoldRuntimeHostMigrationReceipt,
    ManifoldRuntimeHostSnapshot, HOST_APPLICATION_RECEIPT_SCHEMA,
    HOST_CONTROL_LEASE_ADOPTION_RECEIPT_SCHEMA, HOST_CONTROL_LEASE_ADOPTION_REQUEST_SCHEMA,
    HOST_DISPATCH_RECEIPT_SCHEMA, LEGACY_HOST_CONTROL_LEASE_ADOPTION_RECEIPT_V1_SCHEMA,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{self, Write};

/// Stateful broker mutation request schema.
pub const BROKER_MUTATION_REQUEST_SCHEMA: &str = "rusty.manifold.broker.mutation_request.v1";
/// Stateful broker mutation receipt schema with exact bounded-use provenance.
pub const BROKER_MUTATION_RECEIPT_SCHEMA: &str = "rusty.manifold.broker.mutation_receipt.v2";
/// Released mutation receipt retained only as a historical read model.
pub const LEGACY_BROKER_MUTATION_RECEIPT_V1_SCHEMA: &str =
    "rusty.manifold.broker.mutation_receipt.v1";
/// Legacy one-use permit schema accepted only during runtime-evidence migration.
pub const LEGACY_BROKER_BOUNDED_USE_V1_SCHEMA: &str = "rusty.manifold.broker.bounded_use.v1";
/// One-use admission permit schema with exact identity/grant/client-lock closure.
pub const BROKER_BOUNDED_USE_SCHEMA: &str = "rusty.manifold.broker.bounded_use.v2";
/// Legacy broker runtime evidence schema accepted only during migration.
pub const LEGACY_BROKER_RUNTIME_EVIDENCE_V1_SCHEMA: &str =
    "rusty.manifold.broker.runtime_evidence.v1";
/// Legacy integrated broker runtime evidence accepted only by migration.
pub const LEGACY_BROKER_RUNTIME_EVIDENCE_V2_SCHEMA: &str =
    "rusty.manifold.broker.runtime_evidence.v2";
/// Legacy integrated broker runtime evidence with synchronized owner adoption.
pub const LEGACY_BROKER_RUNTIME_EVIDENCE_V3_SCHEMA: &str =
    "rusty.manifold.broker.runtime_evidence.v3";
/// Legacy integrated broker runtime evidence with synchronized lease lifecycle.
pub const LEGACY_BROKER_RUNTIME_EVIDENCE_V4_SCHEMA: &str =
    "rusty.manifold.broker.runtime_evidence.v4";
/// Integrated broker runtime evidence with fail-closed revocation barriers.
pub const BROKER_RUNTIME_EVIDENCE_SCHEMA: &str = "rusty.manifold.broker.runtime_evidence.v5";
/// Explicit legacy broker runtime-evidence migration receipt schema.
pub const BROKER_RUNTIME_MIGRATION_RECEIPT_SCHEMA: &str =
    "rusty.manifold.broker.runtime_evidence_migration_receipt.v1";
/// Explicit v2-to-v3 authority-adoption migration receipt schema.
pub const BROKER_RUNTIME_AUTHORITY_MIGRATION_RECEIPT_SCHEMA: &str =
    "rusty.manifold.broker.runtime_evidence_authority_migration_receipt.v1";
/// Explicit v3-to-v4 owner/Host lifecycle migration receipt schema.
pub const BROKER_RUNTIME_LIFECYCLE_MIGRATION_RECEIPT_SCHEMA: &str =
    "rusty.manifold.broker.runtime_evidence_lifecycle_migration_receipt.v1";
/// Explicit v4-to-v5 administrative-revocation migration receipt schema.
pub const BROKER_RUNTIME_REVOCATION_MIGRATION_RECEIPT_SCHEMA: &str =
    "rusty.manifold.broker.runtime_evidence_revocation_migration_receipt.v1";
/// Durable fail-closed administrative control-lease revocation barrier schema.
pub const BROKER_CONTROL_LEASE_REVOCATION_BARRIER_SCHEMA: &str =
    "rusty.manifold.broker.control_lease_revocation_barrier.v1";
/// Typed invalidation of a pending lifecycle use caused by revocation.
pub const BROKER_CONTROL_LEASE_REVOCATION_USE_INVALIDATION_SCHEMA: &str =
    "rusty.manifold.broker.control_lease_revocation_use_invalidation.v1";
/// Exact recovery request for one pending Host revocation barrier.
pub const BROKER_CONTROL_LEASE_REVOCATION_RECOVERY_REQUEST_SCHEMA: &str =
    "rusty.manifold.broker.control_lease_revocation_recovery_request.v1";
/// Durable recovery receipt for one pending Host revocation barrier.
pub const BROKER_CONTROL_LEASE_REVOCATION_RECOVERY_RECEIPT_SCHEMA: &str =
    "rusty.manifold.broker.control_lease_revocation_recovery_receipt.v1";
/// Terminal retaining-consumer acknowledgement schema.
pub const BROKER_CONTROL_LEASE_REVOCATION_CONSUMER_ACKNOWLEDGEMENT_SCHEMA: &str =
    "rusty.manifold.broker.control_lease_revocation_consumer_acknowledgement.v1";
/// Released drained provider-epoch rollover receipt schema.
pub const LEGACY_BROKER_RUNTIME_EPOCH_ROLLOVER_RECEIPT_V1_SCHEMA: &str =
    "rusty.manifold.broker.runtime_epoch_rollover_receipt.v1";
/// Drained provider-epoch rollover receipt with revocation checkpoints.
pub const BROKER_RUNTIME_EPOCH_ROLLOVER_RECEIPT_SCHEMA: &str =
    "rusty.manifold.broker.runtime_epoch_rollover_receipt.v2";
/// Non-command bounded capability consumption receipt schema.
pub const BROKER_CAPABILITY_USE_RECEIPT_SCHEMA: &str =
    "rusty.manifold.broker.capability_use_receipt.v1";
/// Maximum pending/consumed bounded uses per provider epoch.
pub const MAX_BROKER_BOUNDED_USES: usize = 4_096;
/// Maximum replay identities retained across drained provider-epoch rollovers.
pub const MAX_BROKER_COMPACTED_CONTROL_LEASE_REQUEST_IDS: usize = 32_768;
/// Maximum serialized current or legacy Broker runtime evidence.
pub const MAX_BROKER_RUNTIME_EVIDENCE_BYTES: usize = 64 * 1024 * 1024;

/// Digest domain for exact source JSON in a v2-to-v3 authority migration.
pub const MIGRATION_SOURCE_JSON_DIGEST_DOMAIN: &str =
    "rusty.manifold.broker.migration.v2_to_v3.source_json.v1";
/// Digest domain for compact typed v2 source evidence.
pub const MIGRATION_SOURCE_TYPED_DIGEST_DOMAIN: &str =
    "rusty.manifold.broker.migration.v2_to_v3.source_typed.v1";
/// Digest domain for compact typed v3 result evidence.
pub const MIGRATION_RESULT_DIGEST_DOMAIN: &str =
    "rusty.manifold.broker.migration.v2_to_v3.result.v1";
/// Digest domain for adopted compact typed owner evidence.
pub const MIGRATION_AUTHORITY_DIGEST_DOMAIN: &str =
    "rusty.manifold.broker.migration.v2_to_v3.authority.v1";
/// Digest domain for the compact typed Runtime Host snapshot.
pub const MIGRATION_HOST_DIGEST_DOMAIN: &str = "rusty.manifold.broker.migration.v2_to_v3.host.v1";
/// Digest domain for the complete canonical Runtime Host lease set.
pub const MIGRATION_HOST_LEASE_SET_DIGEST_DOMAIN: &str =
    "rusty.manifold.broker.migration.v2_to_v3.host_lease_set.v1";
/// Digest domain for the complete source evidence of a drained epoch rollover.
pub const EPOCH_ROLLOVER_SOURCE_DIGEST_DOMAIN: &str =
    "rusty.manifold.broker.epoch_rollover.source_evidence.v1";
/// Digest domain for the complete resulting evidence of a drained epoch rollover.
pub const EPOCH_ROLLOVER_RESULT_DIGEST_DOMAIN: &str =
    "rusty.manifold.broker.epoch_rollover.result_evidence.v1";
/// Digest domain for exact released v4 JSON in a v4-to-v5 migration.
pub const REVOCATION_MIGRATION_SOURCE_JSON_DIGEST_DOMAIN: &str =
    "rusty.manifold.broker.migration.v4_to_v5.source_json.v1";
/// Digest domain for compact typed v5 result evidence.
pub const REVOCATION_MIGRATION_RESULT_DIGEST_DOMAIN: &str =
    "rusty.manifold.broker.migration.v4_to_v5.result.v1";

/// One accepted admission use retained until exactly one mutation attempt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerBoundedUse {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// One-time admission-use request identity.
    pub admission_use_request_id: DottedId,
    /// Opaque token identity used at the signature-scoped admission boundary.
    pub token_id: DottedId,
    /// Exact platform-verified identity bound by the token.
    pub identity: ManifoldClientIdentity,
    /// Exact admission grant that issued the token.
    pub admission_grant_id: DottedId,
    /// Exact packaged broker client-lock identity inherited from the grant.
    pub client_lock_id: DottedId,
    /// SHA-256 of the exact packaged broker client-lock bytes.
    pub client_lock_fingerprint: String,
    /// Exact capability authorized for this use.
    pub capability_id: DottedId,
    /// Admission revision resulting from the accepted use authorization.
    pub admission_authority_revision: Revision,
    /// Absolute use expiry.
    pub expires_at_ms: u64,
}

/// Applied/rejected non-command bounded capability consumption receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerCapabilityUseReceipt {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Exact live broker provider epoch.
    pub provider_epoch_id: DottedId,
    /// Whether the accepted bounded use was consumed.
    pub applied: bool,
    /// Exact consumed bounded use when applied.
    pub bounded_use: Option<ManifoldBrokerBoundedUse>,
    /// Stable rejection when not applied.
    pub rejection_reason: Option<ManifoldBrokerMutationRejectionReason>,
}

/// One broker mutation guarded by an already accepted bounded use.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerMutationRequest {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Exact live provider epoch.
    pub provider_epoch_id: DottedId,
    /// One-time admitted use to consume.
    pub admission_use_request_id: DottedId,
    /// Opaque token that produced the admitted use.
    pub token_id: DottedId,
    /// Admission revision that created the exact bounded use.
    pub expected_admission_authority_revision: Revision,
    /// Runtime Host command request.
    pub command: ManifoldRuntimeCommandRequest,
}

/// Rejection before a bounded use may reach Runtime Host review/application.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldBrokerMutationRejectionReason {
    /// Mutation schema differs from the supported contract.
    SchemaMismatch,
    /// Request targets an older or different provider process epoch.
    ProviderEpochMismatch,
    /// Request does not present the revision that created the exact bounded use.
    StaleAdmissionRevision,
    /// No accepted admission use exists for the supplied identity.
    UnknownAdmissionUse,
    /// Supplied token differs from the opaque token that produced the use.
    AdmissionTokenMismatch,
    /// The admitted use already guarded a prior mutation attempt.
    ReplayedAdmissionUse,
    /// The admitted use expired before mutation review.
    AdmissionUseExpired,
    /// Runtime requester differs from the signature-bound client.
    CrossClientUse,
    /// Admitted capability differs from the exact command capability.
    CapabilityMismatch,
    /// An accepted administrative revocation is waiting for Runtime Host convergence.
    PendingRevocationConvergence,
    /// Command targets a control lease behind an administrative revocation barrier.
    RevokedControlLease,
    /// Provider bounded-use retention reached its explicit cap.
    AuthorityCapacityExhausted,
}

/// Integrated admission and Runtime Host mutation receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct ManifoldBrokerMutationReceipt {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Live provider epoch.
    pub provider_epoch_id: DottedId,
    /// One-time admission-use request identity.
    pub admission_use_request_id: DottedId,
    /// Admission revision observed during the mutation attempt.
    pub admission_authority_revision: Revision,
    /// Explicit proof that no transport-local acceptance rules exist.
    pub local_acceptance_rules: bool,
    /// Sole accepted-state decision owner.
    pub authority_owner_id: DottedId,
    /// Whether the command was selected by the immutable product lock.
    pub command_selected: bool,
    /// Whether bounded admission passed and was consumed.
    pub admission_applied: bool,
    /// Admission gate rejection, if Runtime Host was not reached.
    pub admission_rejection_reason: Option<ManifoldBrokerMutationRejectionReason>,
    /// Exact Runtime Host adapter receipt when admission passed.
    pub adapter_receipt: Option<ManifoldBrokerAdapterReceipt>,
    /// Exact bounded use consumed by this mutation attempt.
    pub bounded_use: Option<ManifoldBrokerBoundedUse>,
    /// True only when admission passed and Runtime Host application applied.
    pub applied: bool,
}

/// Released v1 mutation receipt retained as a historical read model.
///
/// It predates the exact bounded-use object embedded by v2 and is not accepted
/// as current mutation evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct LegacyManifoldBrokerMutationReceiptV1 {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Live provider epoch.
    pub provider_epoch_id: DottedId,
    /// One-time admission-use request identity.
    pub admission_use_request_id: DottedId,
    /// Admission revision observed during the mutation attempt.
    pub admission_authority_revision: Revision,
    /// Explicit proof that no transport-local acceptance rules exist.
    pub local_acceptance_rules: bool,
    /// Sole accepted-state decision owner.
    pub authority_owner_id: DottedId,
    /// Whether the command was selected by the immutable product lock.
    pub command_selected: bool,
    /// Whether bounded admission passed and was consumed.
    pub admission_applied: bool,
    /// Admission gate rejection, if Runtime Host was not reached.
    pub admission_rejection_reason: Option<ManifoldBrokerMutationRejectionReason>,
    /// Exact Runtime Host adapter receipt when admission passed.
    pub adapter_receipt: Option<ManifoldBrokerAdapterReceipt>,
    /// True only when admission passed and Runtime Host application applied.
    pub applied: bool,
}

/// Durable disposition of an authority-accepted administrative revocation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldBrokerControlLeaseRevocationBarrierState {
    /// Generic authority accepted revocation, but Runtime Host has not converged.
    PendingHostConvergence,
    /// Broker owner and Runtime Host atomically adopted the revocation.
    Converged,
}

/// Typed terminal invalidation of one previously authorized lifecycle use.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerControlLeaseRevocationUseInvalidation {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Exact invalidated admission-use identity.
    pub admission_use_request_id: DottedId,
    /// Exact lifecycle request that established the barrier.
    pub revocation_lifecycle_request_id: DottedId,
    /// Exact generic revocation application.
    pub revocation_application_id: DottedId,
    /// Exact terminally barred control lease.
    pub lease_id: DottedId,
}

/// Durable fail-closed barrier installed for every accepted revocation.
///
/// A pending barrier is authoritative for command rejection even when an
/// unexpected Runtime Host composition failure prevented owner/Host commit.
/// Downstream consumers join the exact converged barrier before cleaning up
/// lease-derived state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerControlLeaseRevocationBarrier {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Stable barrier identity derived from the generic application.
    pub barrier_id: DottedId,
    /// Provider epoch that established the barrier.
    pub provider_epoch_id: DottedId,
    /// Exact lifecycle request identity.
    pub lifecycle_request_id: DottedId,
    /// Exact generic revocation application identity.
    pub revocation_application_id: DottedId,
    /// Exact terminally barred control lease.
    pub lease_id: DottedId,
    /// Exact accepted generic authority transition.
    pub authority_transition: ManifoldBrokerControlLeaseTransition,
    /// Host adoption when the synchronized owner/Host commit converged.
    pub host_adoption: Option<ManifoldRuntimeControlLeaseAdoptionReceipt>,
    /// Canonical lifecycle uses invalidated by this barrier.
    pub invalidated_lifecycle_use_ids: Vec<DottedId>,
    /// Current durable convergence disposition.
    pub state: ManifoldBrokerControlLeaseRevocationBarrierState,
}

/// CAS-bound deployment-owner request to recover one pending Host barrier.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerControlLeaseRevocationRecoveryRequest {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Replay-protected recovery identity.
    pub recovery_id: DottedId,
    /// Exact live provider epoch.
    pub provider_epoch_id: DottedId,
    /// Exact retained barrier identity.
    pub barrier_id: DottedId,
    /// Expected current Broker owner revision.
    pub expected_control_lease_authority_revision: Revision,
    /// Expected current Runtime Host revision.
    pub expected_host_authority_revision: Revision,
}

/// Durable result of one exact pending-barrier recovery attempt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerControlLeaseRevocationRecoveryReceipt {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Exact provider epoch.
    pub provider_epoch_id: DottedId,
    /// Replay-protected recovery identity.
    pub recovery_id: DottedId,
    /// Exact retained barrier identity.
    pub barrier_id: DottedId,
    /// Original revocation lifecycle request.
    pub lifecycle_request_id: DottedId,
    /// Exact generic revocation application.
    pub revocation_application_id: DottedId,
    /// Exact barred lease.
    pub lease_id: DottedId,
    /// Broker owner revision before recovery.
    pub prior_control_lease_authority_revision: Revision,
    /// Broker owner revision after recovery.
    pub resulting_control_lease_authority_revision: Revision,
    /// Runtime Host revision before recovery.
    pub prior_host_authority_revision: Revision,
    /// Runtime Host revision after recovery.
    pub resulting_host_authority_revision: Revision,
    /// Exact owner transition adopted during recovery.
    pub authority_transition: Option<ManifoldBrokerControlLeaseTransition>,
    /// Exact Host adoption attempted during recovery.
    pub host_adoption: Option<ManifoldRuntimeControlLeaseAdoptionReceipt>,
    /// True only when the original barrier converged.
    pub applied: bool,
    /// Stable failure classification.
    pub rejection_reason: Option<ManifoldBrokerControlLeaseLifecycleRejectionReason>,
}

/// Retaining consumer that must converge before a revocation barrier can be compacted.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldBrokerControlLeaseRevocationConsumerKind {
    /// Peer Runtime Host retaining sessions, routes, streams, or derivative leases.
    PeerRuntimeHost,
}

/// Terminal acknowledgement from one revocation-retaining consumer.
///
/// The deployment owner supplies this only after the named consumer has
/// durably joined the exact Broker barrier and completed every cleanup
/// obligation. Broker retains the exact consumer and terminal receipt digests
/// until a drained epoch rollover checkpoints the complete source evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerControlLeaseRevocationConsumerAcknowledgement {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Replay-protected acknowledgement identity.
    pub acknowledgement_id: DottedId,
    /// Exact live provider epoch.
    pub provider_epoch_id: DottedId,
    /// Exact converged Broker barrier.
    pub barrier_id: DottedId,
    /// Exact accepted generic revocation application.
    pub revocation_application_id: DottedId,
    /// Exact revoked control lease.
    pub lease_id: DottedId,
    /// Retaining consumer family.
    pub consumer_kind: ManifoldBrokerControlLeaseRevocationConsumerKind,
    /// Stable consumer instance identity.
    pub consumer_id: DottedId,
    /// Domain-separated SHA-256 of the consumer convergence receipt.
    pub consumer_convergence_receipt_sha256: String,
    /// Domain-separated SHA-256 of terminal cleanup completion evidence.
    pub terminal_cleanup_receipt_sha256: String,
}

/// Read-only evidence for one live provider process.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerRuntimeEvidence {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Explicit live process epoch.
    pub provider_epoch_id: DottedId,
    /// Current Runtime Host state.
    pub host_snapshot: ManifoldRuntimeHostSnapshot,
    /// Synchronized generic control-lease owner state and source lineage.
    pub control_lease_authority: ManifoldBrokerControlLeaseAuthorityEvidenceV2,
    /// Current admission state.
    pub admission_snapshot: ManifoldAdmissionSnapshot,
    /// Accepted uses not yet consumed by a mutation attempt.
    pub pending_bounded_uses: Vec<ManifoldBrokerBoundedUse>,
    /// Immutable successful generic-use authorizations retained until epoch rollover.
    pub authorized_bounded_uses: Vec<ManifoldBrokerBoundedUse>,
    /// Immutable full token objects observed by this Broker epoch.
    pub admission_token_history: Vec<ManifoldAdmissionToken>,
    /// Generic-use authorizations terminally invalidated before consumption.
    pub invalidated_bounded_use_ids: Vec<DottedId>,
    /// Exact lifecycle-bound uses not yet consumed by a lifecycle attempt.
    pub pending_control_lease_lifecycle_uses: Vec<ManifoldBrokerControlLeaseLifecycleUse>,
    /// Immutable successful lifecycle authorizations retained until epoch rollover.
    pub authorized_control_lease_lifecycle_uses: Vec<ManifoldBrokerControlLeaseLifecycleUse>,
    /// Authorized lifecycle uses terminally invalidated by token revocation or expiry.
    pub invalidated_control_lease_lifecycle_use_ids: Vec<DottedId>,
    /// Exact revocation-caused lifecycle-use invalidation provenance.
    #[serde(default)]
    pub control_lease_revocation_use_invalidations:
        Vec<ManifoldBrokerControlLeaseRevocationUseInvalidation>,
    /// Canonical fail-closed barriers for accepted administrative revocations.
    #[serde(default)]
    pub control_lease_revocation_barriers: Vec<ManifoldBrokerControlLeaseRevocationBarrier>,
    /// Replay-ordered recovery receipts for pending Host barriers.
    #[serde(default)]
    pub control_lease_revocation_recovery_receipts:
        Vec<ManifoldBrokerControlLeaseRevocationRecoveryReceipt>,
    /// Terminal acknowledgements from downstream revocation-retaining consumers.
    #[serde(default)]
    pub control_lease_revocation_consumer_acknowledgements:
        Vec<ManifoldBrokerControlLeaseRevocationConsumerAcknowledgement>,
    /// Exact mutation receipts retained for downstream provenance joins.
    #[serde(default)]
    pub committed_mutation_receipts: Vec<ManifoldBrokerMutationReceipt>,
    /// Exact accepted non-command capability-use receipts.
    #[serde(default)]
    pub committed_capability_use_receipts: Vec<ManifoldBrokerCapabilityUseReceipt>,
    /// Generic control-lease request identities retained across epoch compaction.
    #[serde(default)]
    pub compacted_control_lease_request_ids: Vec<DottedId>,
    /// Bounded uses already consumed by mutation attempts.
    pub consumed_bounded_use_ids: Vec<DottedId>,
    /// Committed lifecycle attempt receipts retained across restart.
    pub control_lease_lifecycle_receipts: Vec<ManifoldBrokerControlLeaseLifecycleReceipt>,
}

/// Released v4 runtime evidence accepted only by explicit v4-to-v5 migration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyManifoldBrokerRuntimeEvidenceV4 {
    /// Released schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Explicit live process epoch.
    pub provider_epoch_id: DottedId,
    /// Released Runtime Host v3 state.
    pub host_snapshot: ManifoldRuntimeHostSnapshot,
    /// Released owner v2 evidence.
    pub control_lease_authority: ManifoldBrokerControlLeaseAuthorityEvidenceV2,
    /// Admission state.
    pub admission_snapshot: ManifoldAdmissionSnapshot,
    /// Pending generic bounded uses.
    pub pending_bounded_uses: Vec<ManifoldBrokerBoundedUse>,
    /// Pending lifecycle-bound uses.
    pub pending_control_lease_lifecycle_uses: Vec<ManifoldBrokerControlLeaseLifecycleUse>,
    /// Immutable lifecycle authorizations.
    pub authorized_control_lease_lifecycle_uses: Vec<ManifoldBrokerControlLeaseLifecycleUse>,
    /// Released terminal invalidation identities.
    pub invalidated_control_lease_lifecycle_use_ids: Vec<DottedId>,
    /// Consumed one-use identities.
    pub consumed_bounded_use_ids: Vec<DottedId>,
    /// Released lifecycle receipts.
    pub control_lease_lifecycle_receipts: Vec<ManifoldBrokerControlLeaseLifecycleReceipt>,
}

/// Released v3 runtime evidence retained for explicit v3-to-v4 migration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyManifoldBrokerRuntimeEvidenceV3 {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Explicit live process epoch.
    pub provider_epoch_id: DottedId,
    /// Released Runtime Host v2 state.
    pub host_snapshot: serde_json::Value,
    /// Released issuance-only control-lease owner evidence.
    pub control_lease_authority: ManifoldBrokerControlLeaseAuthorityEvidence,
    /// Current admission state.
    pub admission_snapshot: ManifoldAdmissionSnapshot,
    /// Accepted command/capability uses not yet consumed.
    pub pending_bounded_uses: Vec<ManifoldBrokerBoundedUse>,
    /// Bounded uses already consumed by mutation attempts.
    pub consumed_bounded_use_ids: Vec<DottedId>,
}

/// Explicit receipt for released v3 to current v4 lifecycle migration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerRuntimeLifecycleMigrationReceipt {
    /// Receipt schema.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Released source schema.
    pub source_schema_id: SchemaId,
    /// Current resulting schema.
    pub resulting_schema_id: SchemaId,
    /// Exact provider epoch.
    pub provider_epoch_id: DottedId,
    /// Runtime Host v2-to-v3 migration evidence.
    pub runtime_host_migration: ManifoldRuntimeHostMigrationReceipt,
    /// Exact command/capability pending-use IDs preserved without reinterpretation.
    pub preserved_pending_bounded_use_ids: Vec<DottedId>,
    /// Existing consumed-use IDs preserved against replay.
    pub preserved_consumed_bounded_use_ids: Vec<DottedId>,
    /// Lifecycle uses synthesized by migration; always empty.
    pub synthesized_lifecycle_use_ids: Vec<DottedId>,
    /// Lifecycle receipts synthesized by migration; always empty.
    pub synthesized_lifecycle_receipt_ids: Vec<DottedId>,
}

/// Exact receipt for released v4 to revocation-aware v5 migration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerRuntimeRevocationMigrationReceipt {
    /// Receipt schema.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Released source schema.
    pub source_schema_id: SchemaId,
    /// Current resulting schema.
    pub resulting_schema_id: SchemaId,
    /// Preserved provider epoch.
    pub provider_epoch_id: DottedId,
    /// Exact Runtime Host v3-to-v4 migration evidence.
    pub runtime_host_migration: ManifoldRuntimeHostMigrationReceipt,
    /// Digest of the exact released v4 JSON bytes.
    pub source_json_sha256: String,
    /// Exact released v4 JSON byte count.
    pub source_json_size_bytes: u64,
    /// Digest of compact typed v5 evidence.
    pub resulting_evidence_sha256: String,
    /// Exact compact typed v5 evidence byte count.
    pub resulting_evidence_size_bytes: u64,
    /// Preserved Runtime Host identity.
    pub authority_host_id: DottedId,
    /// Preserved Runtime Host revision.
    pub host_authority_revision: Revision,
    /// Exact owner transition request identities preserved one-to-one.
    pub preserved_owner_transition_request_ids: Vec<DottedId>,
    /// Exact lifecycle request identities preserved one-to-one.
    pub preserved_lifecycle_request_ids: Vec<DottedId>,
    /// Exact authorized lifecycle-use identities preserved one-to-one.
    pub preserved_authorized_lifecycle_use_ids: Vec<DottedId>,
    /// Administrative revocation barriers synthesized by migration; always empty.
    pub synthesized_revocation_barrier_ids: Vec<DottedId>,
}

impl ManifoldBrokerRuntimeRevocationMigrationReceipt {
    /// Recomputes all v4-to-v5 migration bindings.
    ///
    /// # Errors
    ///
    /// Returns when source/result state is not a structural, decision-free
    /// migration or any receipt field was substituted.
    pub fn validate_against(
        &self,
        source_json: &str,
        resulting_evidence: &ManifoldBrokerRuntimeEvidence,
    ) -> Result<(), ManifoldBrokerRuntimeStateError> {
        let expected = expected_revocation_migration_receipt(source_json, resulting_evidence)?;
        if self == &expected {
            Ok(())
        } else {
            Err(ManifoldBrokerRuntimeStateError::InvalidEvidence(
                "revocation_migration_receipt_binding",
            ))
        }
    }
}

/// Exact checkpoint evidence for a drained provider-epoch rollover.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerRuntimeEpochRolloverReceipt {
    /// Receipt schema.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Drained source provider epoch.
    pub source_provider_epoch_id: DottedId,
    /// Fresh fenced provider epoch.
    pub resulting_provider_epoch_id: DottedId,
    /// Domain-separated digest of complete source runtime evidence.
    pub source_evidence_sha256: String,
    /// Exact source evidence size.
    pub source_evidence_size_bytes: u64,
    /// Domain-separated digest of complete resulting runtime evidence.
    pub resulting_evidence_sha256: String,
    /// Exact resulting evidence size.
    pub resulting_evidence_size_bytes: u64,
    /// Preserved generic authority identity.
    pub manifold_authority_id: DottedId,
    /// Preserved generic authority revision.
    pub manifold_authority_revision: Revision,
    /// Preserved owner clock domain.
    pub clock_domain: DottedId,
    /// Preserved owner clock epoch.
    pub clock_epoch_id: DottedId,
    /// Preserved owner clock sequence.
    pub clock_sequence: u64,
    /// Preserved Runtime Host identity.
    pub authority_host_id: DottedId,
    /// Preserved Runtime Host revision.
    pub host_authority_revision: Revision,
    /// Validated chronological owner transitions compacted after drain.
    pub compacted_owner_transition_count: usize,
    /// Historical lifecycle receipts checkpointed by the source digest.
    pub checkpointed_lifecycle_receipt_count: usize,
    /// Revocation barriers checkpointed after terminal consumer convergence.
    pub checkpointed_revocation_barrier_count: usize,
    /// Terminal consumer acknowledgements checkpointed by the source digest.
    pub checkpointed_revocation_consumer_acknowledgement_count: usize,
    /// Exact mutation receipts checkpointed by the source digest.
    pub checkpointed_mutation_receipt_count: usize,
    /// Exact non-command capability receipts checkpointed by the source digest.
    pub checkpointed_capability_use_receipt_count: usize,
    /// Generic authorization invalidations checkpointed by the source digest.
    pub checkpointed_invalidated_bounded_use_count: usize,
    /// Exact issued-token provenance records checkpointed by the source digest.
    pub checkpointed_admission_token_history_count: usize,
    /// Generic request replay identities retained in the resulting epoch.
    pub checkpointed_control_lease_request_count: usize,
    /// Old-epoch consumed-use tombstones checkpointed by the source digest.
    pub checkpointed_consumed_use_count: usize,
    /// Active old-epoch admission tokens invalidated by the new admission epoch.
    pub invalidated_admission_token_ids: Vec<DottedId>,
}

/// Explicit receipt for a v1 broker runtime-evidence restart.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerRuntimeMigrationReceipt {
    /// Receipt schema.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Source broker runtime-evidence schema.
    pub source_schema_id: SchemaId,
    /// Resulting broker runtime-evidence schema.
    pub resulting_schema_id: SchemaId,
    /// Exact provider process epoch.
    pub provider_epoch_id: DottedId,
    /// Nested admission migration evidence.
    pub admission_migration: ManifoldAdmissionMigrationReceipt,
    /// Nested Runtime Host migration evidence.
    pub runtime_host_migration: ManifoldRuntimeHostMigrationReceipt,
    /// Pending bounded-use ids rebound through exact token/grant/client-lock closure.
    pub migrated_pending_bounded_use_ids: Vec<DottedId>,
    /// Already-consumed one-use ids preserved against replay.
    pub preserved_consumed_bounded_use_ids: Vec<DottedId>,
}

/// Explicit evidence that released v2 Broker state adopted an exact
/// synchronized Manifold control-lease owner without reconstructing authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerRuntimeAuthorityMigrationReceipt {
    /// Receipt schema.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Released source evidence schema.
    pub source_schema_id: SchemaId,
    /// Resulting current evidence schema.
    pub resulting_schema_id: SchemaId,
    /// Exact provider process epoch.
    pub provider_epoch_id: DottedId,
    /// Domain-separated SHA-256 binding over the exact released v2 JSON bytes.
    pub source_json_sha256: String,
    /// Exact released v2 JSON byte count.
    pub source_json_size_bytes: u64,
    /// Domain-separated SHA-256 of the compact typed v2 evidence.
    pub source_typed_evidence_sha256: String,
    /// Domain-separated SHA-256 binding over compact typed v3 evidence.
    pub resulting_evidence_json_sha256: String,
    /// Exact compact typed v3 evidence byte count.
    pub resulting_evidence_json_size_bytes: u64,
    /// Exact adapter identity joined during migration.
    pub adapter_id: DottedId,
    /// Exact immutable product-lock identity.
    pub product_lock_id: DottedId,
    /// SHA-256 of the exact packaged product-lock bytes.
    pub product_lock_sha256: String,
    /// Runtime Host identity that owns accepted command state.
    pub authority_host_id: DottedId,
    /// Adopted synchronized owner-evidence schema.
    pub control_lease_authority_schema_id: SchemaId,
    /// Exact Manifold authority identity supplied separately for adoption.
    pub control_lease_authority_id: DottedId,
    /// Exact retained Manifold authority revision supplied for adoption.
    pub control_lease_authority_revision: Revision,
    /// Exact retained authority clock domain.
    pub control_lease_clock_domain: DottedId,
    /// Exact retained authority clock epoch.
    pub control_lease_clock_epoch_id: DottedId,
    /// Exact retained authority clock sequence.
    pub control_lease_clock_sequence: u64,
    /// Domain-separated SHA-256 binding over compact typed owner evidence.
    pub source_lineage_sha256: String,
    /// Domain-separated SHA-256 binding over the compact typed legacy host.
    pub host_snapshot_sha256: String,
    /// Domain-separated SHA-256 binding over the complete canonical lease set.
    pub host_lease_set_sha256: String,
    /// Exact host lease identities closed over retained source lineage.
    pub migrated_lease_ids: Vec<DottedId>,
    /// Fixed result reached only after exact owner/host closure succeeds.
    pub outcome: ManifoldBrokerRuntimeAuthorityMigrationOutcome,
}

/// Authority-adoption outcome emitted only by a successful v2-to-v3 migration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldBrokerRuntimeAuthorityMigrationOutcome {
    /// Existing owner state closed over the legacy host without a new decision.
    ExistingAuthorityAdoptedWithoutNewLeaseDecision,
}

impl ManifoldBrokerRuntimeAuthorityMigrationReceipt {
    /// Recomputes every receipt binding against the source, adapter, adopted
    /// owner evidence, and resulting current evidence.
    ///
    /// A deserialized receipt is raw evidence until this method succeeds.
    ///
    /// # Errors
    ///
    /// Returns when any context is invalid or any serialized receipt field was
    /// substituted.
    pub fn validate_against(
        &self,
        source_json: &str,
        adapter_config: &ManifoldBrokerAdapterConfig,
        authority_evidence: &ManifoldBrokerControlLeaseAuthorityEvidence,
        resulting_evidence: &ManifoldBrokerRuntimeEvidence,
    ) -> Result<(), ManifoldBrokerRuntimeStateError> {
        let expected = expected_authority_migration_receipt(
            source_json,
            adapter_config,
            authority_evidence,
            resulting_evidence,
        )?;
        if self == &expected {
            Ok(())
        } else {
            Err(ManifoldBrokerRuntimeStateError::InvalidEvidence(
                "authority_migration_receipt_binding",
            ))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct LegacyBrokerBoundedUseV1 {
    #[serde(rename = "$schema")]
    schema_id: SchemaId,
    admission_use_request_id: DottedId,
    token_id: DottedId,
    client_id: DottedId,
    capability_id: DottedId,
    admission_authority_revision: Revision,
    expires_at_ms: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct LegacyBrokerRuntimeEvidenceV1 {
    #[serde(rename = "$schema")]
    schema_id: SchemaId,
    provider_epoch_id: DottedId,
    host_snapshot: serde_json::Value,
    admission_snapshot: serde_json::Value,
    pending_bounded_uses: Vec<LegacyBrokerBoundedUseV1>,
    consumed_bounded_use_ids: Vec<DottedId>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LegacyBrokerRuntimeEvidenceV2 {
    #[serde(rename = "$schema")]
    schema_id: SchemaId,
    provider_epoch_id: DottedId,
    host_snapshot: serde_json::Value,
    admission_snapshot: ManifoldAdmissionSnapshot,
    pending_bounded_uses: Vec<ManifoldBrokerBoundedUse>,
    consumed_bounded_use_ids: Vec<DottedId>,
}

/// One stateful Rust broker authority for a live standalone or embedded provider.
#[derive(Debug)]
pub struct ManifoldBrokerRuntime {
    provider_epoch_id: DottedId,
    adapter: ManifoldBrokerAdapter,
    control_lease_authority: ManifoldBrokerControlLeaseAuthority,
    admission: ManifoldAdmissionAuthority,
    pending_bounded_uses: BTreeMap<DottedId, ManifoldBrokerBoundedUse>,
    authorized_bounded_uses: BTreeMap<DottedId, ManifoldBrokerBoundedUse>,
    admission_token_history: BTreeMap<DottedId, ManifoldAdmissionToken>,
    invalidated_bounded_use_ids: BTreeSet<DottedId>,
    pending_control_lease_lifecycle_uses:
        BTreeMap<DottedId, ManifoldBrokerControlLeaseLifecycleUse>,
    authorized_control_lease_lifecycle_uses:
        BTreeMap<DottedId, ManifoldBrokerControlLeaseLifecycleUse>,
    invalidated_control_lease_lifecycle_use_ids: BTreeSet<DottedId>,
    control_lease_revocation_use_invalidations:
        BTreeMap<DottedId, ManifoldBrokerControlLeaseRevocationUseInvalidation>,
    control_lease_revocation_barriers:
        BTreeMap<DottedId, ManifoldBrokerControlLeaseRevocationBarrier>,
    control_lease_revocation_recovery_receipts:
        Vec<ManifoldBrokerControlLeaseRevocationRecoveryReceipt>,
    control_lease_revocation_consumer_acknowledgements:
        BTreeMap<DottedId, ManifoldBrokerControlLeaseRevocationConsumerAcknowledgement>,
    committed_mutation_receipts: Vec<ManifoldBrokerMutationReceipt>,
    committed_capability_use_receipts: Vec<ManifoldBrokerCapabilityUseReceipt>,
    compacted_control_lease_request_ids: BTreeSet<DottedId>,
    consumed_bounded_use_ids: BTreeSet<DottedId>,
    control_lease_lifecycle_receipts: Vec<ManifoldBrokerControlLeaseLifecycleReceipt>,
}

impl ManifoldBrokerRuntime {
    /// Returns the immutable live adapter/product provenance binding.
    #[must_use]
    pub const fn adapter_config(&self) -> &ManifoldBrokerAdapterConfig {
        self.adapter.config()
    }

    /// Creates a fresh provider epoch over one exact product adapter and grant state.
    ///
    /// # Trust boundary
    ///
    /// Only the deployment authority owner may construct a runtime. It must
    /// allocate and externally fence one writable owner per provider epoch.
    ///
    /// # Errors
    ///
    /// Returns a state error when adapter leases, control-lease owner state, or
    /// admission state do not form one closed provider.
    pub fn new(
        provider_epoch_id: DottedId,
        adapter: ManifoldBrokerAdapter,
        control_lease_authority: ManifoldBrokerControlLeaseAuthority,
        admission_snapshot: ManifoldAdmissionSnapshot,
    ) -> Result<Self, ManifoldBrokerRuntimeStateError> {
        control_lease_authority
            .validate_host_snapshot(adapter.host_snapshot())
            .map_err(ManifoldBrokerRuntimeStateError::ControlLeaseAuthority)?;
        let admission_token_history = admission_snapshot
            .active_tokens
            .iter()
            .map(|token| (token.token_id.clone(), token.clone()))
            .collect();
        let runtime = Self {
            provider_epoch_id,
            adapter,
            control_lease_authority,
            admission: ManifoldAdmissionAuthority::from_snapshot(admission_snapshot)
                .map_err(ManifoldBrokerRuntimeStateError::Admission)?,
            pending_bounded_uses: BTreeMap::new(),
            authorized_bounded_uses: BTreeMap::new(),
            admission_token_history,
            invalidated_bounded_use_ids: BTreeSet::new(),
            pending_control_lease_lifecycle_uses: BTreeMap::new(),
            authorized_control_lease_lifecycle_uses: BTreeMap::new(),
            invalidated_control_lease_lifecycle_use_ids: BTreeSet::new(),
            control_lease_revocation_use_invalidations: BTreeMap::new(),
            control_lease_revocation_barriers: BTreeMap::new(),
            control_lease_revocation_recovery_receipts: Vec::new(),
            control_lease_revocation_consumer_acknowledgements: BTreeMap::new(),
            committed_mutation_receipts: Vec::new(),
            committed_capability_use_receipts: Vec::new(),
            compacted_control_lease_request_ids: BTreeSet::new(),
            consumed_bounded_use_ids: BTreeSet::new(),
            control_lease_lifecycle_receipts: Vec::new(),
        };
        validate_runtime_evidence_size(&runtime.evidence())?;
        Ok(runtime)
    }

    /// Restores pending/consumed bounded-use state around an already restored
    /// adapter and revalidates exact admission/Runtime Host joins.
    ///
    /// # Trust boundary
    ///
    /// The caller is the deployment authority owner and must guarantee one
    /// writable runtime per provider epoch across processes and storage. This
    /// function validates evidence closure; it cannot prove exclusive durable
    /// ownership or absence of another restored writer.
    ///
    /// # Errors
    ///
    /// Returns when serialized capacity, schema, owner/host/admission joins,
    /// ordering, or bounded-use replay evidence is invalid.
    #[allow(clippy::too_many_lines)]
    pub fn restore_from_caller_attested_exclusive_evidence(
        adapter: ManifoldBrokerAdapter,
        control_lease_authority: ManifoldBrokerControlLeaseAuthority,
        evidence: ManifoldBrokerRuntimeEvidence,
    ) -> Result<Self, ManifoldBrokerRuntimeStateError> {
        validate_runtime_evidence_size(&evidence)?;
        if evidence.schema_id.as_str() != BROKER_RUNTIME_EVIDENCE_SCHEMA
            || adapter.host_snapshot() != &evidence.host_snapshot
            || !control_lease_authority.is_refresh_of(&evidence.control_lease_authority)
            || evidence
                .pending_bounded_uses
                .len()
                .saturating_add(evidence.pending_control_lease_lifecycle_uses.len())
                > MAX_BROKER_BOUNDED_USES
            || evidence.authorized_bounded_uses.len() > MAX_BROKER_BOUNDED_USES
            || evidence.admission_token_history.len() > MAX_BROKER_BOUNDED_USES
            || evidence.invalidated_bounded_use_ids.len() > MAX_BROKER_BOUNDED_USES
            || evidence.authorized_control_lease_lifecycle_uses.len() > MAX_BROKER_BOUNDED_USES
            || evidence.invalidated_control_lease_lifecycle_use_ids.len() > MAX_BROKER_BOUNDED_USES
            || evidence.control_lease_revocation_use_invalidations.len() > MAX_BROKER_BOUNDED_USES
            || evidence.control_lease_revocation_barriers.len()
                > MAX_BROKER_CONTROL_LEASE_TRANSITIONS
            || evidence.control_lease_revocation_recovery_receipts.len()
                > MAX_BROKER_CONTROL_LEASE_TRANSITIONS
            || evidence
                .control_lease_revocation_consumer_acknowledgements
                .len()
                > MAX_BROKER_CONTROL_LEASE_TRANSITIONS
            || evidence.committed_mutation_receipts.len() > MAX_BROKER_BOUNDED_USES
            || evidence.committed_capability_use_receipts.len() > MAX_BROKER_BOUNDED_USES
            || evidence.compacted_control_lease_request_ids.len()
                > MAX_BROKER_COMPACTED_CONTROL_LEASE_REQUEST_IDS
            || evidence.consumed_bounded_use_ids.len() > MAX_BROKER_BOUNDED_USES
            || evidence.control_lease_lifecycle_receipts.len()
                > MAX_BROKER_CONTROL_LEASE_TRANSITIONS
            || evidence
                .pending_bounded_uses
                .windows(2)
                .any(|pair| pair[0].admission_use_request_id >= pair[1].admission_use_request_id)
            || evidence
                .authorized_bounded_uses
                .windows(2)
                .any(|pair| pair[0].admission_use_request_id >= pair[1].admission_use_request_id)
            || evidence
                .admission_token_history
                .windows(2)
                .any(|pair| pair[0].token_id >= pair[1].token_id)
            || evidence
                .invalidated_bounded_use_ids
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || evidence
                .pending_control_lease_lifecycle_uses
                .windows(2)
                .any(|pair| {
                    pair[0].bounded_use.admission_use_request_id
                        >= pair[1].bounded_use.admission_use_request_id
                })
            || evidence
                .authorized_control_lease_lifecycle_uses
                .windows(2)
                .any(|pair| {
                    pair[0].bounded_use.admission_use_request_id
                        >= pair[1].bounded_use.admission_use_request_id
                })
            || evidence
                .invalidated_control_lease_lifecycle_use_ids
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || evidence
                .control_lease_revocation_use_invalidations
                .windows(2)
                .any(|pair| pair[0].admission_use_request_id >= pair[1].admission_use_request_id)
            || evidence
                .control_lease_revocation_barriers
                .windows(2)
                .any(|pair| pair[0].lease_id >= pair[1].lease_id)
            || evidence
                .control_lease_revocation_consumer_acknowledgements
                .windows(2)
                .any(|pair| pair[0].acknowledgement_id >= pair[1].acknowledgement_id)
            || evidence
                .compacted_control_lease_request_ids
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || evidence
                .consumed_bounded_use_ids
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(ManifoldBrokerRuntimeStateError::InvalidEvidence(
                "schema_host_or_capacity",
            ));
        }
        control_lease_authority
            .validate_host_snapshot(adapter.host_snapshot())
            .map_err(ManifoldBrokerRuntimeStateError::ControlLeaseAuthority)?;
        let admission =
            ManifoldAdmissionAuthority::from_snapshot(evidence.admission_snapshot.clone())
                .map_err(ManifoldBrokerRuntimeStateError::Admission)?;
        let consumed = evidence
            .consumed_bounded_use_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let pending = evidence
            .pending_bounded_uses
            .iter()
            .map(|use_| (use_.admission_use_request_id.clone(), use_.clone()))
            .collect::<BTreeMap<_, _>>();
        let authorized = evidence
            .authorized_bounded_uses
            .iter()
            .map(|use_| (use_.admission_use_request_id.clone(), use_.clone()))
            .collect::<BTreeMap<_, _>>();
        let admission_token_history = evidence
            .admission_token_history
            .iter()
            .map(|token| (token.token_id.clone(), token.clone()))
            .collect::<BTreeMap<_, _>>();
        let invalidated = evidence
            .invalidated_bounded_use_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let pending_lifecycle = evidence
            .pending_control_lease_lifecycle_uses
            .iter()
            .map(|use_| {
                (
                    use_.bounded_use.admission_use_request_id.clone(),
                    use_.clone(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let authorized_lifecycle = evidence
            .authorized_control_lease_lifecycle_uses
            .iter()
            .map(|use_| {
                (
                    use_.bounded_use.admission_use_request_id.clone(),
                    use_.clone(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let invalidated_lifecycle = evidence
            .invalidated_control_lease_lifecycle_use_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let revocation_use_invalidations = evidence
            .control_lease_revocation_use_invalidations
            .iter()
            .map(|invalidation| {
                (
                    invalidation.admission_use_request_id.clone(),
                    invalidation.clone(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let revocation_barriers = evidence
            .control_lease_revocation_barriers
            .iter()
            .map(|barrier| (barrier.lease_id.clone(), barrier.clone()))
            .collect::<BTreeMap<_, _>>();
        let pending_revocation_barrier_count = revocation_barriers
            .values()
            .filter(|barrier| {
                barrier.state
                    == ManifoldBrokerControlLeaseRevocationBarrierState::PendingHostConvergence
            })
            .count();
        let revocation_consumer_acknowledgements = evidence
            .control_lease_revocation_consumer_acknowledgements
            .iter()
            .map(|acknowledgement| {
                (
                    acknowledgement.acknowledgement_id.clone(),
                    acknowledgement.clone(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let compacted_control_lease_request_ids = evidence
            .compacted_control_lease_request_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let receipt_lifecycle_use_ids = evidence
            .control_lease_lifecycle_receipts
            .iter()
            .filter_map(|receipt| {
                receipt
                    .lifecycle_use
                    .as_ref()
                    .map(|use_| use_.bounded_use.admission_use_request_id.clone())
            })
            .collect::<BTreeSet<_>>();
        let classified_lifecycle_use_ids = pending_lifecycle
            .keys()
            .cloned()
            .chain(receipt_lifecycle_use_ids.iter().cloned())
            .chain(invalidated_lifecycle.iter().cloned())
            .collect::<BTreeSet<_>>();
        let mutation_use_ids = evidence
            .committed_mutation_receipts
            .iter()
            .filter_map(|receipt| {
                receipt
                    .bounded_use
                    .as_ref()
                    .map(|use_| use_.admission_use_request_id.clone())
            })
            .collect::<BTreeSet<_>>();
        let capability_use_ids = evidence
            .committed_capability_use_receipts
            .iter()
            .filter_map(|receipt| {
                receipt
                    .bounded_use
                    .as_ref()
                    .map(|use_| use_.admission_use_request_id.clone())
            })
            .collect::<BTreeSet<_>>();
        let classified_generic_use_ids = pending
            .keys()
            .cloned()
            .chain(invalidated.iter().cloned())
            .chain(mutation_use_ids.iter().cloned())
            .chain(capability_use_ids.iter().cloned())
            .collect::<BTreeSet<_>>();
        let pending_lifecycle_request_ids = pending_lifecycle
            .values()
            .map(|use_| use_.lifecycle_request_id.clone())
            .collect::<BTreeSet<_>>();
        let authorized_lifecycle_request_ids = authorized_lifecycle
            .values()
            .map(|use_| use_.lifecycle_request_id.clone())
            .collect::<BTreeSet<_>>();
        let retained_lifecycle_request_ids = evidence
            .control_lease_lifecycle_receipts
            .iter()
            .map(|receipt| receipt.lifecycle_request_id.clone())
            .chain(
                evidence
                    .control_lease_authority
                    .baseline
                    .lease_sources
                    .iter()
                    .map(|source| source.application.request_id.clone()),
            )
            .chain(
                evidence
                    .control_lease_authority
                    .transitions
                    .iter()
                    .map(|transition| transition.application.request_id().clone()),
            )
            .collect::<BTreeSet<_>>();
        let all_use_ids = pending
            .keys()
            .cloned()
            .chain(pending_lifecycle.keys().cloned())
            .chain(consumed.iter().cloned())
            .collect::<BTreeSet<_>>();
        let admission_use_ids = admission
            .snapshot()
            .consumed_use_request_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        if pending.keys().any(|id| consumed.contains(id))
            || pending_lifecycle.keys().any(|id| consumed.contains(id))
            || pending.keys().any(|id| pending_lifecycle.contains_key(id))
            || authorized.len() != evidence.authorized_bounded_uses.len()
            || admission_token_history.len() != evidence.admission_token_history.len()
            || invalidated.len() != evidence.invalidated_bounded_use_ids.len()
            || authorized_lifecycle.len() != evidence.authorized_control_lease_lifecycle_uses.len()
            || pending
                .iter()
                .any(|(id, use_)| authorized.get(id) != Some(use_))
            || authorized.keys().any(|id| !admission_use_ids.contains(id))
            || authorized.iter().any(|(use_id, use_)| {
                !bounded_use_admission_revision_closes(
                    use_,
                    admission.snapshot(),
                    &admission_token_history,
                    !pending.contains_key(use_id),
                )
            })
            || admission_token_history
                .values()
                .any(|token| !admission_token_history_entry_closes(token, admission.snapshot()))
            || invalidated.iter().any(|id| !consumed.contains(id))
            || mutation_use_ids.len() != evidence.committed_mutation_receipts.len()
            || capability_use_ids.len() != evidence.committed_capability_use_receipts.len()
            || classified_generic_use_ids.len()
                != pending
                    .len()
                    .saturating_add(invalidated.len())
                    .saturating_add(mutation_use_ids.len())
                    .saturating_add(capability_use_ids.len())
            || classified_generic_use_ids != authorized.keys().cloned().collect::<BTreeSet<_>>()
            || receipt_lifecycle_use_ids.len() != evidence.control_lease_lifecycle_receipts.len()
            || invalidated_lifecycle
                .iter()
                .any(|id| !consumed.contains(id))
            || receipt_lifecycle_use_ids
                .iter()
                .any(|id| !consumed.contains(id) || invalidated_lifecycle.contains(id))
            || pending_lifecycle
                .keys()
                .any(|id| invalidated_lifecycle.contains(id))
            || classified_lifecycle_use_ids.len()
                != pending_lifecycle
                    .len()
                    .saturating_add(receipt_lifecycle_use_ids.len())
                    .saturating_add(invalidated_lifecycle.len())
            || classified_lifecycle_use_ids
                != authorized_lifecycle
                    .keys()
                    .cloned()
                    .collect::<BTreeSet<_>>()
            || pending_lifecycle
                .iter()
                .any(|(id, use_)| authorized_lifecycle.get(id) != Some(use_))
            || evidence
                .control_lease_lifecycle_receipts
                .iter()
                .any(|receipt| {
                    receipt.lifecycle_use.as_ref().map_or(true, |use_| {
                        authorized_lifecycle.get(&use_.bounded_use.admission_use_request_id)
                            != Some(use_)
                    })
                })
            || pending_lifecycle_request_ids.len() != pending_lifecycle.len()
            || authorized_lifecycle_request_ids.len() != authorized_lifecycle.len()
            || pending_lifecycle_request_ids
                .iter()
                .any(|id| retained_lifecycle_request_ids.contains(id))
            || invalidated_lifecycle.iter().any(|use_id| {
                authorized_lifecycle.get(use_id).map_or(true, |use_| {
                    retained_lifecycle_request_ids.contains(&use_.lifecycle_request_id)
                })
            })
            || all_use_ids != admission_use_ids
            || pending.values().any(|use_| {
                use_.schema_id.as_str() != BROKER_BOUNDED_USE_SCHEMA
                    || !admission.snapshot().active_tokens.iter().any(|token| {
                        token.token_id == use_.token_id
                            && token.identity == use_.identity
                            && token.grant_id == use_.admission_grant_id
                            && token.client_lock_id == use_.client_lock_id
                            && token.client_lock_fingerprint == use_.client_lock_fingerprint
                            && token.capabilities.contains(&use_.capability_id)
                            && token.expires_at_ms >= use_.expires_at_ms
                    })
                    || use_.admission_authority_revision > admission.snapshot().authority_revision
            })
            || pending_lifecycle.values().any(|use_| {
                use_.schema_id.as_str() != BROKER_CONTROL_LEASE_LIFECYCLE_USE_SCHEMA
                    || use_.bounded_use.schema_id.as_str() != BROKER_BOUNDED_USE_SCHEMA
                    || use_.bounded_use.capability_id
                        != control_lease_lifecycle_capability(use_.operation_kind)
                    || use_.authorized_from_admission_authority_revision
                        >= use_.bounded_use.admission_authority_revision
                    || !lifecycle_admission_revision_closes(use_, admission.snapshot())
                    || match use_.operation_kind {
                        ManifoldBrokerControlLeaseLifecycleOperationKind::Issue => {
                            use_.issue_scope.is_none()
                                || use_.lease_id.is_some()
                                || !use_.expiry_lease_ids.is_empty()
                        }
                        ManifoldBrokerControlLeaseLifecycleOperationKind::Renewal
                        | ManifoldBrokerControlLeaseLifecycleOperationKind::Release
                        | ManifoldBrokerControlLeaseLifecycleOperationKind::Revocation => {
                            use_.lease_id.is_none()
                                || use_.issue_scope.is_some()
                                || !use_.expiry_lease_ids.is_empty()
                        }
                        ManifoldBrokerControlLeaseLifecycleOperationKind::Expiry => {
                            use_.lease_id.is_some()
                                || use_.issue_scope.is_some()
                                || use_.expiry_lease_ids.is_empty()
                                || use_
                                    .expiry_lease_ids
                                    .windows(2)
                                    .any(|pair| pair[0] >= pair[1])
                                || use_.expiry_lease_ids.iter().any(|lease_id| {
                                    !control_lease_authority
                                        .runtime_leases()
                                        .iter()
                                        .any(|lease| &lease.lease_id == lease_id)
                                })
                        }
                    }
                    || use_.lifecycle_request_sha256.len() != 71
                    || !use_.lifecycle_request_sha256.starts_with("sha256:")
                    || !admission.snapshot().active_tokens.iter().any(|token| {
                        token.token_id == use_.bounded_use.token_id
                            && token.identity == use_.bounded_use.identity
                            && token.grant_id == use_.bounded_use.admission_grant_id
                            && token.client_lock_id == use_.bounded_use.client_lock_id
                            && token.client_lock_fingerprint
                                == use_.bounded_use.client_lock_fingerprint
                            && token.capabilities.contains(&use_.bounded_use.capability_id)
                            && token.expires_at_ms >= use_.bounded_use.expires_at_ms
                    })
                    || use_.bounded_use.admission_authority_revision
                        > admission.snapshot().authority_revision
            })
            || authorized_lifecycle.values().any(|use_| {
                use_.schema_id.as_str() != BROKER_CONTROL_LEASE_LIFECYCLE_USE_SCHEMA
                    || use_.bounded_use.schema_id.as_str() != BROKER_BOUNDED_USE_SCHEMA
                    || use_.bounded_use.capability_id
                        != control_lease_lifecycle_capability(use_.operation_kind)
                    || use_.authorized_from_admission_authority_revision
                        >= use_.bounded_use.admission_authority_revision
                    || !lifecycle_admission_revision_closes(use_, admission.snapshot())
                    || !admission.snapshot().grants.iter().any(|grant| {
                        grant.grant_id == use_.bounded_use.admission_grant_id
                            && grant.identity == use_.bounded_use.identity
                            && grant.client_lock_id == use_.bounded_use.client_lock_id
                            && grant.client_lock_fingerprint
                                == use_.bounded_use.client_lock_fingerprint
                            && grant.capabilities.contains(&use_.bounded_use.capability_id)
                    })
                    || match use_.operation_kind {
                        ManifoldBrokerControlLeaseLifecycleOperationKind::Issue => {
                            use_.issue_scope.is_none()
                                || use_.lease_id.is_some()
                                || !use_.expiry_lease_ids.is_empty()
                        }
                        ManifoldBrokerControlLeaseLifecycleOperationKind::Renewal
                        | ManifoldBrokerControlLeaseLifecycleOperationKind::Release
                        | ManifoldBrokerControlLeaseLifecycleOperationKind::Revocation => {
                            use_.lease_id.is_none()
                                || use_.issue_scope.is_some()
                                || !use_.expiry_lease_ids.is_empty()
                        }
                        ManifoldBrokerControlLeaseLifecycleOperationKind::Expiry => {
                            use_.lease_id.is_some()
                                || use_.issue_scope.is_some()
                                || use_.expiry_lease_ids.is_empty()
                                || use_
                                    .expiry_lease_ids
                                    .windows(2)
                                    .any(|pair| pair[0] >= pair[1])
                        }
                    }
                    || use_.lifecycle_request_sha256.len() != 71
                    || !use_.lifecycle_request_sha256.starts_with("sha256:")
            })
            || revocation_use_invalidations.len()
                != evidence.control_lease_revocation_use_invalidations.len()
            || revocation_barriers.len() != evidence.control_lease_revocation_barriers.len()
            || (pending_revocation_barrier_count > 0
                && evidence.control_lease_revocation_recovery_receipts.len()
                    > MAX_BROKER_CONTROL_LEASE_TRANSITIONS
                        .saturating_sub(pending_revocation_barrier_count))
            || revocation_consumer_acknowledgements.len()
                != evidence
                    .control_lease_revocation_consumer_acknowledgements
                    .len()
            || compacted_control_lease_request_ids.len()
                != evidence.compacted_control_lease_request_ids.len()
            || compacted_control_lease_request_ids
                .iter()
                .any(|request_id| retained_lifecycle_request_ids.contains(request_id))
            || revocation_use_invalidations
                .iter()
                .any(|(use_id, invalidation)| {
                    invalidation.schema_id.as_str()
                        != BROKER_CONTROL_LEASE_REVOCATION_USE_INVALIDATION_SCHEMA
                        || !invalidated_lifecycle.contains(use_id)
                        || authorized_lifecycle.get(use_id).map_or(true, |use_| {
                            use_.lease_id.as_ref() != Some(&invalidation.lease_id)
                                && !use_.expiry_lease_ids.contains(&invalidation.lease_id)
                        })
                        || revocation_barriers
                            .get(&invalidation.lease_id)
                            .map_or(true, |barrier| {
                                barrier.lifecycle_request_id
                                    != invalidation.revocation_lifecycle_request_id
                                    || barrier.revocation_application_id
                                        != invalidation.revocation_application_id
                                    || !barrier.invalidated_lifecycle_use_ids.contains(use_id)
                            })
                })
            || !revocation_barriers_close(
                &evidence.control_lease_revocation_barriers,
                &evidence.provider_epoch_id,
                &evidence.control_lease_authority,
                &evidence.host_snapshot,
                &revocation_use_invalidations,
                &evidence.control_lease_lifecycle_receipts,
                &evidence.control_lease_revocation_recovery_receipts,
            )
            || !revocation_consumer_acknowledgements_close(
                &evidence.control_lease_revocation_consumer_acknowledgements,
                &evidence.provider_epoch_id,
                &evidence.control_lease_revocation_barriers,
                adapter.product_features(),
            )
            || !committed_mutation_receipts_close(
                &evidence.committed_mutation_receipts,
                &evidence.provider_epoch_id,
                adapter.config(),
                &evidence.host_snapshot,
                &consumed,
                &authorized,
                &evidence.admission_snapshot,
                &admission_token_history,
            )
            || !committed_capability_use_receipts_close(
                &evidence.committed_capability_use_receipts,
                &evidence.provider_epoch_id,
                &evidence.host_snapshot,
                &consumed,
                &authorized,
                &evidence.admission_snapshot,
                &admission_token_history,
            )
            || !lifecycle_receipts_close(
                &evidence.control_lease_lifecycle_receipts,
                &evidence.provider_epoch_id,
                adapter.config(),
                &consumed,
                &evidence.control_lease_authority,
                &evidence.host_snapshot,
                &evidence.admission_snapshot,
                &evidence.control_lease_revocation_recovery_receipts,
            )
        {
            return Err(ManifoldBrokerRuntimeStateError::InvalidEvidence(
                "bounded_use_admission_join",
            ));
        }
        Ok(Self {
            provider_epoch_id: evidence.provider_epoch_id,
            adapter,
            control_lease_authority,
            admission,
            pending_bounded_uses: pending,
            authorized_bounded_uses: authorized,
            admission_token_history,
            invalidated_bounded_use_ids: invalidated,
            pending_control_lease_lifecycle_uses: pending_lifecycle,
            authorized_control_lease_lifecycle_uses: authorized_lifecycle,
            invalidated_control_lease_lifecycle_use_ids: invalidated_lifecycle,
            control_lease_revocation_use_invalidations: revocation_use_invalidations,
            control_lease_revocation_barriers: revocation_barriers,
            control_lease_revocation_recovery_receipts: evidence
                .control_lease_revocation_recovery_receipts,
            control_lease_revocation_consumer_acknowledgements:
                revocation_consumer_acknowledgements,
            committed_mutation_receipts: evidence.committed_mutation_receipts,
            committed_capability_use_receipts: evidence.committed_capability_use_receipts,
            compacted_control_lease_request_ids,
            consumed_bounded_use_ids: consumed,
            control_lease_lifecycle_receipts: evidence.control_lease_lifecycle_receipts,
        })
    }

    /// Restores current v4 evidence from bounded JSON after the adapter and
    /// separately supplied owner view have each been restored.
    ///
    /// # Trust boundary
    ///
    /// The caller must enforce the same cross-process/storage single-writer
    /// guarantee described by the typed exclusive-evidence restore.
    ///
    /// # Errors
    ///
    /// Returns before deserialization when JSON exceeds the runtime evidence
    /// byte budget, or when decoded state fails normal closure.
    pub fn restore_from_caller_attested_exclusive_evidence_json(
        adapter: ManifoldBrokerAdapter,
        control_lease_authority: ManifoldBrokerControlLeaseAuthority,
        evidence_json: &str,
    ) -> Result<Self, ManifoldBrokerRuntimeStateError> {
        validate_runtime_evidence_json_size(evidence_json)?;
        let evidence = serde_json::from_str(evidence_json)
            .map_err(ManifoldBrokerRuntimeStateError::Deserialize)?;
        Self::restore_from_caller_attested_exclusive_evidence(
            adapter,
            control_lease_authority,
            evidence,
        )
    }

    /// Explicitly migrates released v2 runtime evidence by joining its exact
    /// host lease set to separately supplied, freshly validated Manifold
    /// control-lease authority state.
    ///
    /// This migration never derives authority from the legacy host snapshot.
    /// Every non-empty legacy host lease must already close exactly over the
    /// supplied authority's retained source lineage.
    ///
    /// The caller is also responsible for exclusive writable ownership of the
    /// migrated provider epoch across processes and storage.
    ///
    /// # Errors
    ///
    /// Returns an error when JSON, schema, capacity, ordering, adapter/host
    /// closure, admission state, or supplied control-lease authority is invalid.
    pub fn from_legacy_v2_evidence_json(
        adapter: ManifoldBrokerAdapter,
        control_lease_authority: ManifoldBrokerControlLeaseAuthority,
        legacy_json: &str,
    ) -> Result<
        (Self, ManifoldBrokerRuntimeAuthorityMigrationReceipt),
        ManifoldBrokerRuntimeStateError,
    > {
        validate_runtime_evidence_json_size(legacy_json)?;
        let legacy: LegacyBrokerRuntimeEvidenceV2 = serde_json::from_str(legacy_json)
            .map_err(ManifoldBrokerRuntimeStateError::Deserialize)?;
        if legacy.schema_id.as_str() != LEGACY_BROKER_RUNTIME_EVIDENCE_V2_SCHEMA {
            return Err(ManifoldBrokerRuntimeStateError::InvalidEvidence(
                "legacy_v2_schema",
            ));
        }
        let host_json = serde_json::to_string(&legacy.host_snapshot)
            .map_err(ManifoldBrokerRuntimeStateError::SerializeMigrationArtifact)?;
        let (migrated_host, _) = ManifoldRuntimeHost::restart_from_json_with_migration(&host_json)
            .map_err(ManifoldBrokerRuntimeStateError::RuntimeHost)?;
        if migrated_host.snapshot() != adapter.host_snapshot() {
            return Err(ManifoldBrokerRuntimeStateError::InvalidEvidence(
                "legacy_v2_runtime_host_adapter_join",
            ));
        }
        control_lease_authority
            .validate_host_snapshot(migrated_host.snapshot())
            .map_err(ManifoldBrokerRuntimeStateError::ControlLeaseAuthority)?;
        let authority_evidence = control_lease_authority.evidence();
        let evidence = ManifoldBrokerRuntimeEvidence {
            schema_id: schema_id(BROKER_RUNTIME_EVIDENCE_SCHEMA),
            provider_epoch_id: legacy.provider_epoch_id.clone(),
            host_snapshot: migrated_host.snapshot().clone(),
            control_lease_authority: authority_evidence.clone(),
            admission_token_history: legacy.admission_snapshot.active_tokens.clone(),
            admission_snapshot: legacy.admission_snapshot,
            authorized_bounded_uses: legacy.pending_bounded_uses.clone(),
            invalidated_bounded_use_ids: Vec::new(),
            pending_bounded_uses: legacy.pending_bounded_uses,
            pending_control_lease_lifecycle_uses: Vec::new(),
            authorized_control_lease_lifecycle_uses: Vec::new(),
            invalidated_control_lease_lifecycle_use_ids: Vec::new(),
            control_lease_revocation_use_invalidations: Vec::new(),
            control_lease_revocation_barriers: Vec::new(),
            control_lease_revocation_recovery_receipts: Vec::new(),
            control_lease_revocation_consumer_acknowledgements: Vec::new(),
            committed_mutation_receipts: Vec::new(),
            committed_capability_use_receipts: Vec::new(),
            compacted_control_lease_request_ids: Vec::new(),
            consumed_bounded_use_ids: legacy.consumed_bounded_use_ids,
            control_lease_lifecycle_receipts: Vec::new(),
        };
        validate_runtime_evidence_size(&evidence)?;
        let config = adapter.config().clone();
        let receipt = expected_authority_migration_receipt(
            legacy_json,
            &config,
            &authority_evidence.baseline,
            &evidence,
        )?;
        let runtime = Self::restore_from_caller_attested_exclusive_evidence(
            adapter,
            control_lease_authority,
            evidence,
        )?;
        Ok((runtime, receipt))
    }

    /// Explicitly migrates released v3 evidence into the synchronized
    /// lifecycle evidence model.
    ///
    /// Existing command/capability uses remain generic pending uses. Migration
    /// never promotes them into lifecycle authority, and it synthesizes no
    /// lifecycle receipt or transition.
    ///
    /// # Errors
    ///
    /// Returns when the released source, nested Runtime Host migration,
    /// immutable owner baseline, admission closure, ordering, capacity, or
    /// restored adapter join is invalid.
    pub fn from_legacy_v3_evidence_json(
        adapter: ManifoldBrokerAdapter,
        control_lease_authority: ManifoldBrokerControlLeaseAuthority,
        legacy_json: &str,
    ) -> Result<
        (Self, ManifoldBrokerRuntimeLifecycleMigrationReceipt),
        ManifoldBrokerRuntimeStateError,
    > {
        validate_runtime_evidence_json_size(legacy_json)?;
        let legacy: LegacyManifoldBrokerRuntimeEvidenceV3 = serde_json::from_str(legacy_json)
            .map_err(ManifoldBrokerRuntimeStateError::Deserialize)?;
        if legacy.schema_id.as_str() != LEGACY_BROKER_RUNTIME_EVIDENCE_V3_SCHEMA
            || legacy.pending_bounded_uses.len() > MAX_BROKER_BOUNDED_USES
            || legacy.consumed_bounded_use_ids.len() > MAX_BROKER_BOUNDED_USES
            || legacy
                .pending_bounded_uses
                .windows(2)
                .any(|pair| pair[0].admission_use_request_id >= pair[1].admission_use_request_id)
            || legacy
                .consumed_bounded_use_ids
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(ManifoldBrokerRuntimeStateError::InvalidEvidence(
                "legacy_v3_schema_order_or_capacity",
            ));
        }
        let host_json = serde_json::to_string(&legacy.host_snapshot)
            .map_err(ManifoldBrokerRuntimeStateError::SerializeMigrationArtifact)?;
        let (migrated_host, runtime_host_migration) =
            ManifoldRuntimeHost::restart_from_json_with_migration(&host_json)
                .map_err(ManifoldBrokerRuntimeStateError::RuntimeHost)?;
        if migrated_host.snapshot() != adapter.host_snapshot() {
            return Err(ManifoldBrokerRuntimeStateError::InvalidEvidence(
                "legacy_v3_runtime_host_adapter_join",
            ));
        }
        let owner_evidence = control_lease_authority.evidence();
        if owner_evidence.schema_id.as_str() != BROKER_CONTROL_LEASE_AUTHORITY_EVIDENCE_V3_SCHEMA
            || owner_evidence.baseline != legacy.control_lease_authority
            || !owner_evidence.transitions.is_empty()
            || owner_evidence.current_authority_snapshot
                != owner_evidence.baseline.current_authority_snapshot
            || owner_evidence.current_clock != owner_evidence.baseline.current_clock
        {
            return Err(ManifoldBrokerRuntimeStateError::InvalidEvidence(
                "legacy_v3_owner_baseline_join",
            ));
        }
        control_lease_authority
            .validate_host_snapshot(migrated_host.snapshot())
            .map_err(ManifoldBrokerRuntimeStateError::ControlLeaseAuthority)?;

        let preserved_pending_bounded_use_ids = legacy
            .pending_bounded_uses
            .iter()
            .map(|use_| use_.admission_use_request_id.clone())
            .collect::<Vec<_>>();
        let evidence = ManifoldBrokerRuntimeEvidence {
            schema_id: schema_id(BROKER_RUNTIME_EVIDENCE_SCHEMA),
            provider_epoch_id: legacy.provider_epoch_id.clone(),
            host_snapshot: migrated_host.snapshot().clone(),
            control_lease_authority: owner_evidence,
            admission_token_history: legacy.admission_snapshot.active_tokens.clone(),
            admission_snapshot: legacy.admission_snapshot,
            authorized_bounded_uses: legacy.pending_bounded_uses.clone(),
            invalidated_bounded_use_ids: Vec::new(),
            pending_bounded_uses: legacy.pending_bounded_uses,
            pending_control_lease_lifecycle_uses: Vec::new(),
            authorized_control_lease_lifecycle_uses: Vec::new(),
            invalidated_control_lease_lifecycle_use_ids: Vec::new(),
            control_lease_revocation_use_invalidations: Vec::new(),
            control_lease_revocation_barriers: Vec::new(),
            control_lease_revocation_recovery_receipts: Vec::new(),
            control_lease_revocation_consumer_acknowledgements: Vec::new(),
            committed_mutation_receipts: Vec::new(),
            committed_capability_use_receipts: Vec::new(),
            compacted_control_lease_request_ids: Vec::new(),
            consumed_bounded_use_ids: legacy.consumed_bounded_use_ids.clone(),
            control_lease_lifecycle_receipts: Vec::new(),
        };
        let runtime = Self::restore_from_caller_attested_exclusive_evidence(
            adapter,
            control_lease_authority,
            evidence,
        )?;
        let receipt = ManifoldBrokerRuntimeLifecycleMigrationReceipt {
            schema_id: schema_id(BROKER_RUNTIME_LIFECYCLE_MIGRATION_RECEIPT_SCHEMA),
            source_schema_id: legacy.schema_id,
            resulting_schema_id: schema_id(BROKER_RUNTIME_EVIDENCE_SCHEMA),
            provider_epoch_id: legacy.provider_epoch_id,
            runtime_host_migration,
            preserved_pending_bounded_use_ids,
            preserved_consumed_bounded_use_ids: legacy.consumed_bounded_use_ids,
            synthesized_lifecycle_use_ids: Vec::new(),
            synthesized_lifecycle_receipt_ids: Vec::new(),
        };
        Ok((runtime, receipt))
    }

    /// Explicitly migrates released v4 lifecycle evidence into revocation-aware v5.
    ///
    /// The migration widens only versioned schema vocabularies. It preserves
    /// owner transitions, Host state/audit, admission records, lifecycle uses,
    /// receipts, digests, and replay identities without creating a lease
    /// decision, revocation barrier, or authority revision.
    ///
    /// # Errors
    ///
    /// Returns when source size/schema/closure is invalid, released evidence
    /// attempts to carry revocation state, or the supplied adapter differs
    /// from the exact released Host snapshot.
    #[allow(clippy::too_many_lines)]
    pub fn migrate_v4_evidence_json(
        adapter: ManifoldBrokerAdapter,
        legacy_json: &str,
    ) -> Result<
        (Self, ManifoldBrokerRuntimeRevocationMigrationReceipt),
        ManifoldBrokerRuntimeStateError,
    > {
        validate_runtime_evidence_json_size(legacy_json)?;
        let legacy: LegacyManifoldBrokerRuntimeEvidenceV4 = serde_json::from_str(legacy_json)
            .map_err(ManifoldBrokerRuntimeStateError::Deserialize)?;
        let (migrated_host_snapshot, _) = migrated_v4_host_snapshot(legacy_json)?;
        if legacy.schema_id.as_str() != LEGACY_BROKER_RUNTIME_EVIDENCE_V4_SCHEMA
            || adapter.host_snapshot() != &migrated_host_snapshot
            || legacy_v4_contains_revocation(&legacy)
        {
            return Err(ManifoldBrokerRuntimeStateError::InvalidEvidence(
                "legacy_v4_schema_host_or_revocation",
            ));
        }

        let mut owner_evidence = legacy.control_lease_authority.clone();
        owner_evidence.schema_id = schema_id(BROKER_CONTROL_LEASE_AUTHORITY_EVIDENCE_V3_SCHEMA);
        for transition in &mut owner_evidence.transitions {
            transition.schema_id = schema_id(crate::BROKER_CONTROL_LEASE_TRANSITION_SCHEMA);
        }
        let control_lease_authority =
            ManifoldBrokerControlLeaseAuthority::refresh_from_v2_evidence(
                owner_evidence.clone(),
                owner_evidence.current_authority_snapshot.clone(),
                owner_evidence.current_clock.clone(),
            )
            .map_err(ManifoldBrokerRuntimeStateError::ControlLeaseAuthority)?;

        let mut pending_lifecycle = legacy.pending_control_lease_lifecycle_uses.clone();
        let mut authorized_lifecycle = legacy.authorized_control_lease_lifecycle_uses.clone();
        for use_ in pending_lifecycle
            .iter_mut()
            .chain(authorized_lifecycle.iter_mut())
        {
            use_.schema_id = schema_id(BROKER_CONTROL_LEASE_LIFECYCLE_USE_SCHEMA);
        }
        let mut lifecycle_receipts = legacy.control_lease_lifecycle_receipts.clone();
        for receipt in &mut lifecycle_receipts {
            receipt.schema_id = schema_id(BROKER_CONTROL_LEASE_LIFECYCLE_RECEIPT_SCHEMA);
            if let Some(use_) = &mut receipt.lifecycle_use {
                use_.schema_id = schema_id(BROKER_CONTROL_LEASE_LIFECYCLE_USE_SCHEMA);
            }
            if let Some(transition) = &mut receipt.authority_transition {
                transition.schema_id = schema_id(crate::BROKER_CONTROL_LEASE_TRANSITION_SCHEMA);
            }
            if let Some(adoption) = &mut receipt.host_adoption {
                adoption.schema_id = schema_id(HOST_CONTROL_LEASE_ADOPTION_RECEIPT_SCHEMA);
            }
        }
        let evidence = ManifoldBrokerRuntimeEvidence {
            schema_id: schema_id(BROKER_RUNTIME_EVIDENCE_SCHEMA),
            provider_epoch_id: legacy.provider_epoch_id,
            host_snapshot: migrated_host_snapshot,
            control_lease_authority: owner_evidence,
            admission_token_history: legacy.admission_snapshot.active_tokens.clone(),
            admission_snapshot: legacy.admission_snapshot,
            authorized_bounded_uses: legacy.pending_bounded_uses.clone(),
            invalidated_bounded_use_ids: Vec::new(),
            pending_bounded_uses: legacy.pending_bounded_uses,
            pending_control_lease_lifecycle_uses: pending_lifecycle,
            authorized_control_lease_lifecycle_uses: authorized_lifecycle,
            invalidated_control_lease_lifecycle_use_ids: legacy
                .invalidated_control_lease_lifecycle_use_ids,
            control_lease_revocation_use_invalidations: Vec::new(),
            control_lease_revocation_barriers: Vec::new(),
            control_lease_revocation_recovery_receipts: Vec::new(),
            control_lease_revocation_consumer_acknowledgements: Vec::new(),
            committed_mutation_receipts: Vec::new(),
            committed_capability_use_receipts: Vec::new(),
            compacted_control_lease_request_ids: Vec::new(),
            consumed_bounded_use_ids: legacy.consumed_bounded_use_ids,
            control_lease_lifecycle_receipts: lifecycle_receipts,
        };
        let runtime = Self::restore_from_caller_attested_exclusive_evidence(
            adapter,
            control_lease_authority,
            evidence,
        )?;
        let receipt = expected_revocation_migration_receipt(legacy_json, &runtime.evidence())?;
        Ok((runtime, receipt))
    }

    /// Restores released v1 broker runtime evidence by explicitly migrating
    /// its nested admission/Runtime Host snapshots and deriving each old
    /// client-id-only bounded use from the exact migrated active token.
    ///
    /// The caller is the deployment authority owner and must enforce exclusive
    /// writable ownership of the migrated provider epoch.
    ///
    /// # Errors
    ///
    /// Returns an error when JSON, nested migration, exact token/grant/client
    /// binding, replay sets, provider epoch, or restored adapter closure fails.
    #[allow(clippy::too_many_lines)]
    pub fn from_legacy_evidence_json(
        adapter: ManifoldBrokerAdapter,
        control_lease_authority: ManifoldBrokerControlLeaseAuthority,
        legacy_json: &str,
        admission_bindings: &[ManifoldAdmissionLegacyClientLockBinding],
    ) -> Result<(Self, ManifoldBrokerRuntimeMigrationReceipt), ManifoldBrokerRuntimeStateError>
    {
        validate_runtime_evidence_json_size(legacy_json)?;
        let legacy: LegacyBrokerRuntimeEvidenceV1 = serde_json::from_str(legacy_json)
            .map_err(ManifoldBrokerRuntimeStateError::Deserialize)?;
        if legacy.schema_id.as_str() != LEGACY_BROKER_RUNTIME_EVIDENCE_V1_SCHEMA
            || legacy.pending_bounded_uses.len() > MAX_BROKER_BOUNDED_USES
            || legacy.consumed_bounded_use_ids.len() > MAX_BROKER_BOUNDED_USES
            || legacy
                .pending_bounded_uses
                .windows(2)
                .any(|pair| pair[0].admission_use_request_id >= pair[1].admission_use_request_id)
            || legacy
                .consumed_bounded_use_ids
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || legacy
                .pending_bounded_uses
                .iter()
                .any(|use_| use_.schema_id.as_str() != LEGACY_BROKER_BOUNDED_USE_V1_SCHEMA)
        {
            return Err(ManifoldBrokerRuntimeStateError::InvalidEvidence(
                "legacy_schema_order_or_capacity",
            ));
        }
        let host_json = serde_json::to_string(&legacy.host_snapshot)
            .map_err(ManifoldBrokerRuntimeStateError::SerializeMigrationArtifact)?;
        let (migrated_host, runtime_host_migration) =
            ManifoldRuntimeHost::restart_from_json_with_migration(&host_json)
                .map_err(ManifoldBrokerRuntimeStateError::RuntimeHost)?;
        if migrated_host.snapshot() != adapter.host_snapshot() {
            return Err(ManifoldBrokerRuntimeStateError::InvalidEvidence(
                "legacy_runtime_host_adapter_join",
            ));
        }
        let admission_json = serde_json::to_string(&legacy.admission_snapshot)
            .map_err(ManifoldBrokerRuntimeStateError::SerializeMigrationArtifact)?;
        let (migrated_admission, admission_migration) =
            ManifoldAdmissionAuthority::restart_from_json_with_migration(
                &admission_json,
                admission_bindings,
            )
            .map_err(ManifoldBrokerRuntimeStateError::Admission)?;
        let pending_bounded_uses = legacy
            .pending_bounded_uses
            .iter()
            .map(|use_| {
                let token = migrated_admission
                    .snapshot()
                    .active_tokens
                    .iter()
                    .find(|token| token.token_id == use_.token_id)
                    .ok_or(ManifoldBrokerRuntimeStateError::InvalidEvidence(
                        "legacy_bounded_use_token",
                    ))?;
                if token.identity.client_id != use_.client_id
                    || !token.capabilities.contains(&use_.capability_id)
                    || token.expires_at_ms < use_.expires_at_ms
                    || use_.admission_authority_revision
                        > migrated_admission.snapshot().authority_revision
                {
                    return Err(ManifoldBrokerRuntimeStateError::InvalidEvidence(
                        "legacy_bounded_use_binding",
                    ));
                }
                Ok(ManifoldBrokerBoundedUse {
                    schema_id: schema_id(BROKER_BOUNDED_USE_SCHEMA),
                    admission_use_request_id: use_.admission_use_request_id.clone(),
                    token_id: use_.token_id.clone(),
                    identity: token.identity.clone(),
                    admission_grant_id: token.grant_id.clone(),
                    client_lock_id: token.client_lock_id.clone(),
                    client_lock_fingerprint: token.client_lock_fingerprint.clone(),
                    capability_id: use_.capability_id.clone(),
                    admission_authority_revision: use_.admission_authority_revision,
                    expires_at_ms: use_.expires_at_ms,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut migrated_pending_bounded_use_ids = pending_bounded_uses
            .iter()
            .map(|use_| use_.admission_use_request_id.clone())
            .collect::<Vec<_>>();
        migrated_pending_bounded_use_ids.sort();
        let evidence = ManifoldBrokerRuntimeEvidence {
            schema_id: schema_id(BROKER_RUNTIME_EVIDENCE_SCHEMA),
            provider_epoch_id: legacy.provider_epoch_id.clone(),
            host_snapshot: migrated_host.snapshot().clone(),
            control_lease_authority: control_lease_authority.evidence(),
            admission_token_history: migrated_admission.snapshot().active_tokens.clone(),
            admission_snapshot: migrated_admission.snapshot().clone(),
            authorized_bounded_uses: pending_bounded_uses.clone(),
            invalidated_bounded_use_ids: Vec::new(),
            pending_bounded_uses,
            pending_control_lease_lifecycle_uses: Vec::new(),
            authorized_control_lease_lifecycle_uses: Vec::new(),
            invalidated_control_lease_lifecycle_use_ids: Vec::new(),
            control_lease_revocation_use_invalidations: Vec::new(),
            control_lease_revocation_barriers: Vec::new(),
            control_lease_revocation_recovery_receipts: Vec::new(),
            control_lease_revocation_consumer_acknowledgements: Vec::new(),
            committed_mutation_receipts: Vec::new(),
            committed_capability_use_receipts: Vec::new(),
            compacted_control_lease_request_ids: Vec::new(),
            consumed_bounded_use_ids: legacy.consumed_bounded_use_ids.clone(),
            control_lease_lifecycle_receipts: Vec::new(),
        };
        let runtime = Self::restore_from_caller_attested_exclusive_evidence(
            adapter,
            control_lease_authority,
            evidence,
        )?;
        let receipt = ManifoldBrokerRuntimeMigrationReceipt {
            schema_id: schema_id(BROKER_RUNTIME_MIGRATION_RECEIPT_SCHEMA),
            source_schema_id: legacy.schema_id,
            resulting_schema_id: schema_id(BROKER_RUNTIME_EVIDENCE_SCHEMA),
            provider_epoch_id: legacy.provider_epoch_id,
            admission_migration,
            runtime_host_migration,
            migrated_pending_bounded_use_ids,
            preserved_consumed_bounded_use_ids: legacy.consumed_bounded_use_ids,
        };
        Ok((runtime, receipt))
    }

    /// Returns the current live provider epoch.
    #[must_use]
    pub const fn provider_epoch_id(&self) -> &DottedId {
        &self.provider_epoch_id
    }

    /// Returns the current Runtime Host snapshot.
    #[must_use]
    pub const fn host_snapshot(&self) -> &ManifoldRuntimeHostSnapshot {
        self.adapter.host_snapshot()
    }

    /// Returns the synchronized generic control-lease authority snapshot.
    #[must_use]
    pub const fn control_lease_authority_snapshot(
        &self,
    ) -> &rusty_manifold_model::ManifoldAuthoritySnapshot {
        self.control_lease_authority.authority_snapshot()
    }

    /// Returns the current admission snapshot.
    #[must_use]
    pub const fn admission_snapshot(&self) -> &ManifoldAdmissionSnapshot {
        self.admission.snapshot()
    }

    /// Issues a token through Manifold admission.
    pub fn issue_token(
        &mut self,
        request: &ManifoldAdmissionRequest,
        entropy: [u8; 32],
        now_ms: u64,
    ) -> ManifoldAdmissionReceipt {
        let receipt = self.admission.issue_token(request, entropy, now_ms);
        if let Some(token) = receipt.token.as_ref() {
            self.admission_token_history
                .insert(token.token_id.clone(), token.clone());
        }
        receipt
    }

    /// Authorizes one bounded capability use and retains its exact client binding.
    ///
    /// # Panics
    ///
    /// Panics only if admission reports an applied use without retaining the
    /// exact token/grant/client-lock binding that it just validated.
    pub fn authorize_use(
        &mut self,
        request: &ManifoldAdmissionUseRequest,
        now_ms: u64,
    ) -> ManifoldAdmissionReceipt {
        let retained_use_count = self
            .pending_bounded_uses
            .len()
            .saturating_add(self.pending_control_lease_lifecycle_uses.len())
            .saturating_add(self.consumed_bounded_use_ids.len());
        if retained_use_count
            >= MAX_BROKER_BOUNDED_USES
                .saturating_sub(BROKER_CONTROL_LEASE_CLEANUP_TRANSITION_RESERVE)
        {
            let revision = self.admission.snapshot().authority_revision;
            return ManifoldAdmissionReceipt {
                schema_id: schema_id("rusty.manifold.admission.receipt.v1"),
                operation: ManifoldAdmissionOperation::AuthorizeUse,
                request_id: request.request_id.clone(),
                applied: false,
                prior_authority_revision: revision,
                resulting_authority_revision: revision,
                token: None,
                removed_token_ids: Vec::new(),
                rejection_reason: Some(
                    ManifoldAdmissionRejectionReason::AuthorityCapacityExhausted,
                ),
            };
        }
        let token_binding = self
            .admission
            .snapshot()
            .active_tokens
            .iter()
            .find(|token| token.token_id == request.token_id)
            .map(|token| {
                (
                    token.expires_at_ms,
                    token.grant_id.clone(),
                    token.client_lock_id.clone(),
                    token.client_lock_fingerprint.clone(),
                )
            });
        let receipt = self.admission.authorize_use(request, now_ms);
        if receipt.applied {
            let bounded_use = ManifoldBrokerBoundedUse {
                schema_id: schema_id(BROKER_BOUNDED_USE_SCHEMA),
                admission_use_request_id: request.request_id.clone(),
                token_id: request.token_id.clone(),
                identity: request.identity.clone(),
                admission_grant_id: token_binding
                    .as_ref()
                    .map(|(_, grant_id, _, _)| grant_id.clone())
                    .expect("applied use retains source token"),
                client_lock_id: token_binding
                    .as_ref()
                    .map(|(_, _, client_lock_id, _)| client_lock_id.clone())
                    .expect("applied use retains client lock"),
                client_lock_fingerprint: token_binding
                    .as_ref()
                    .map(|(_, _, _, fingerprint)| fingerprint.clone())
                    .expect("applied use retains client-lock fingerprint"),
                capability_id: request.capability_id.clone(),
                admission_authority_revision: receipt.resulting_authority_revision,
                expires_at_ms: token_binding
                    .map_or(request.expires_at_ms, |(expires_at_ms, _, _, _)| {
                        expires_at_ms
                    })
                    .min(request.expires_at_ms),
            };
            self.pending_bounded_uses
                .insert(request.request_id.clone(), bounded_use.clone());
            self.authorized_bounded_uses
                .insert(request.request_id.clone(), bounded_use);
        }
        receipt
    }

    /// Authorizes one admission use and binds it to exact lifecycle request bytes.
    ///
    /// # Panics
    ///
    /// Panics only if Manifold admission reports an applied use without
    /// retaining the exact source token that it just validated.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn authorize_control_lease_lifecycle_use(
        &mut self,
        admission_request: &ManifoldAdmissionUseRequest,
        lifecycle_request: &ManifoldBrokerControlLeaseLifecycleRequest,
        now_ms: u64,
    ) -> ManifoldBrokerControlLeaseLifecycleAuthorizationReceipt {
        let request_sha256 = control_lease_lifecycle_request_sha256(lifecycle_request);
        let operation_kind = lifecycle_request.operation.kind();
        let cleanup_operation = matches!(
            operation_kind,
            ManifoldBrokerControlLeaseLifecycleOperationKind::Release
                | ManifoldBrokerControlLeaseLifecycleOperationKind::Revocation
                | ManifoldBrokerControlLeaseLifecycleOperationKind::Expiry
        );
        let lifecycle_retention_limit = if cleanup_operation {
            MAX_BROKER_CONTROL_LEASE_TRANSITIONS
        } else {
            MAX_BROKER_CONTROL_LEASE_TRANSITIONS
                .saturating_sub(BROKER_CONTROL_LEASE_CLEANUP_TRANSITION_RESERVE)
        };
        let bounded_use_retention_limit = if cleanup_operation {
            MAX_BROKER_BOUNDED_USES
        } else {
            MAX_BROKER_BOUNDED_USES.saturating_sub(BROKER_CONTROL_LEASE_CLEANUP_TRANSITION_RESERVE)
        };
        let rejection = if lifecycle_request.schema_id.as_str()
            != BROKER_CONTROL_LEASE_LIFECYCLE_REQUEST_SCHEMA
        {
            Some(ManifoldBrokerControlLeaseLifecycleRejectionReason::SchemaMismatch)
        } else if lifecycle_request.provider_epoch_id != self.provider_epoch_id {
            Some(ManifoldBrokerControlLeaseLifecycleRejectionReason::ProviderEpochMismatch)
        } else if self.has_pending_revocation_barrier() {
            Some(ManifoldBrokerControlLeaseLifecycleRejectionReason::PendingRevocationConvergence)
        } else if lifecycle_request.admission_use_request_id != admission_request.request_id
            || lifecycle_request.token_id != admission_request.token_id
            || lifecycle_request.expected_admission_authority_revision
                != admission_request.expected_authority_revision
        {
            Some(ManifoldBrokerControlLeaseLifecycleRejectionReason::LifecycleRequestMismatch)
        } else if admission_request.capability_id
            != control_lease_lifecycle_capability(operation_kind)
        {
            Some(ManifoldBrokerControlLeaseLifecycleRejectionReason::CapabilityMismatch)
        } else if self
            .authorized_control_lease_lifecycle_uses
            .values()
            .any(|use_| use_.lifecycle_request_id == *lifecycle_request.operation.request_id())
            || self
                .compacted_control_lease_request_ids
                .contains(lifecycle_request.operation.request_id())
            || self
                .control_lease_authority
                .ensure_request_not_replayed(lifecycle_request.operation.request_id())
                .is_err()
        {
            Some(ManifoldBrokerControlLeaseLifecycleRejectionReason::ReplayedLifecycleRequest)
        } else if lifecycle_request.operation.expected_authority_revision()
            != self
                .control_lease_authority
                .authority_snapshot()
                .authority_revision
        {
            Some(
                ManifoldBrokerControlLeaseLifecycleRejectionReason::
                    StaleControlLeaseAuthorityRevision,
            )
        } else if lifecycle_request
            .operation
            .issue_scope()
            .is_some_and(|scope| !self.adapter.supports_control_lease_scope(scope))
        {
            Some(ManifoldBrokerControlLeaseLifecycleRejectionReason::ProductScopeMismatch)
        } else if lifecycle_request
            .operation
            .lease_id()
            .is_some_and(|lease_id| {
                self.control_lease_revocation_barriers
                    .contains_key(lease_id)
            })
        {
            Some(ManifoldBrokerControlLeaseLifecycleRejectionReason::RevokedLease)
        } else if lifecycle_request
            .operation
            .lease_id()
            .is_some_and(|lease_id| {
                !self
                    .control_lease_authority
                    .runtime_leases()
                    .iter()
                    .any(|lease| {
                        &lease.lease_id == lease_id
                            && (operation_kind
                                == ManifoldBrokerControlLeaseLifecycleOperationKind::Revocation
                                || lease.holder_id == admission_request.identity.client_id)
                    })
                    || self
                        .pending_control_lease_lifecycle_uses
                        .values()
                        .any(|use_| use_.lease_id.as_ref() == Some(lease_id))
                        && operation_kind
                            != ManifoldBrokerControlLeaseLifecycleOperationKind::Revocation
            })
        {
            Some(ManifoldBrokerControlLeaseLifecycleRejectionReason::UnrelatedLease)
        } else if lifecycle_request
            .operation
            .expiry_lease_ids()
            .is_some_and(|lease_ids| {
                lease_ids.is_empty()
                    || lease_ids.windows(2).any(|pair| pair[0] >= pair[1])
                    || lease_ids.iter().any(|lease_id| {
                        !self
                            .control_lease_authority
                            .runtime_leases()
                            .iter()
                            .any(|lease| &lease.lease_id == lease_id)
                    })
                    || self
                        .pending_control_lease_lifecycle_uses
                        .values()
                        .flat_map(|use_| use_.expiry_lease_ids.iter())
                        .any(|pending| lease_ids.contains(pending))
            })
        {
            Some(
                ManifoldBrokerControlLeaseLifecycleRejectionReason::UnsupportedAuthorityExpiryDelta,
            )
        } else if self
            .control_lease_lifecycle_receipts
            .len()
            .saturating_add(self.pending_control_lease_lifecycle_uses.len())
            >= lifecycle_retention_limit
        {
            Some(ManifoldBrokerControlLeaseLifecycleRejectionReason::AuthorityCapacityExhausted)
        } else if let Err(error) = self
            .control_lease_authority
            .ensure_transition_capacity(transition_kind(operation_kind))
        {
            Some(control_lease_authority_rejection(&error))
        } else if self
            .pending_bounded_uses
            .len()
            .saturating_add(self.pending_control_lease_lifecycle_uses.len())
            .saturating_add(self.consumed_bounded_use_ids.len())
            >= bounded_use_retention_limit
        {
            Some(ManifoldBrokerControlLeaseLifecycleRejectionReason::AuthorityCapacityExhausted)
        } else {
            None
        };
        if let Some(reason) = rejection {
            return lifecycle_authorization_receipt(
                &self.provider_epoch_id,
                lifecycle_request.operation.request_id(),
                request_sha256,
                None,
                None,
                Some(reason),
            );
        }

        let token_binding = self
            .admission
            .snapshot()
            .active_tokens
            .iter()
            .find(|token| token.token_id == admission_request.token_id)
            .map(|token| {
                (
                    token.expires_at_ms,
                    token.grant_id.clone(),
                    token.client_lock_id.clone(),
                    token.client_lock_fingerprint.clone(),
                )
            });
        let admission_receipt = self.admission.authorize_use(admission_request, now_ms);
        if !admission_receipt.applied {
            return lifecycle_authorization_receipt(
                &self.provider_epoch_id,
                lifecycle_request.operation.request_id(),
                request_sha256,
                Some(admission_receipt),
                None,
                Some(ManifoldBrokerControlLeaseLifecycleRejectionReason::CapabilityMismatch),
            );
        }
        let token_binding = token_binding.expect("applied admission retains source token");
        let bounded_use = ManifoldBrokerBoundedUse {
            schema_id: schema_id(BROKER_BOUNDED_USE_SCHEMA),
            admission_use_request_id: admission_request.request_id.clone(),
            token_id: admission_request.token_id.clone(),
            identity: admission_request.identity.clone(),
            admission_grant_id: token_binding.1,
            client_lock_id: token_binding.2,
            client_lock_fingerprint: token_binding.3,
            capability_id: admission_request.capability_id.clone(),
            admission_authority_revision: admission_receipt.resulting_authority_revision,
            expires_at_ms: token_binding.0.min(admission_request.expires_at_ms),
        };
        let lifecycle_use = ManifoldBrokerControlLeaseLifecycleUse {
            schema_id: schema_id(BROKER_CONTROL_LEASE_LIFECYCLE_USE_SCHEMA),
            bounded_use,
            operation_kind,
            lifecycle_request_id: lifecycle_request.operation.request_id().clone(),
            lifecycle_request_sha256: request_sha256.clone(),
            authorized_from_admission_authority_revision: admission_request
                .expected_authority_revision,
            expected_control_lease_authority_revision: lifecycle_request
                .operation
                .expected_authority_revision(),
            lease_id: lifecycle_request.operation.lease_id().cloned(),
            issue_scope: lifecycle_request.operation.issue_scope().cloned(),
            expiry_lease_ids: lifecycle_request
                .operation
                .expiry_lease_ids()
                .unwrap_or_default()
                .to_vec(),
        };
        self.pending_control_lease_lifecycle_uses
            .insert(admission_request.request_id.clone(), lifecycle_use.clone());
        self.authorized_control_lease_lifecycle_uses
            .insert(admission_request.request_id.clone(), lifecycle_use.clone());
        lifecycle_authorization_receipt(
            &self.provider_epoch_id,
            lifecycle_request.operation.request_id(),
            request_sha256,
            Some(admission_receipt),
            Some(lifecycle_use),
            None,
        )
    }

    /// Revokes a token and invalidates every pending use derived from it.
    pub fn revoke_token(
        &mut self,
        request: &ManifoldAdmissionRevocationRequest,
    ) -> ManifoldAdmissionReceipt {
        let receipt = self.admission.revoke_token(request);
        if receipt.applied {
            let invalidated_generic = self
                .pending_bounded_uses
                .values()
                .filter(|use_| use_.token_id == request.token_id)
                .map(|use_| use_.admission_use_request_id.clone())
                .collect::<Vec<_>>();
            let invalidated_lifecycle = self
                .pending_control_lease_lifecycle_uses
                .values()
                .filter(|use_| use_.bounded_use.token_id == request.token_id)
                .map(|use_| use_.bounded_use.admission_use_request_id.clone())
                .collect::<Vec<_>>();
            self.pending_bounded_uses
                .retain(|_, use_| use_.token_id != request.token_id);
            self.pending_control_lease_lifecycle_uses
                .retain(|_, use_| use_.bounded_use.token_id != request.token_id);
            self.invalidated_bounded_use_ids
                .extend(invalidated_generic.iter().cloned());
            self.consumed_bounded_use_ids.extend(invalidated_generic);
            self.consumed_bounded_use_ids
                .extend(invalidated_lifecycle.iter().cloned());
            self.invalidated_control_lease_lifecycle_use_ids
                .extend(invalidated_lifecycle);
        }
        receipt
    }

    /// Explicitly expires tokens and invalidates their pending bounded uses.
    pub fn expire_tokens(
        &mut self,
        sweep_id: DottedId,
        expected_revision: Revision,
        now_ms: u64,
    ) -> ManifoldAdmissionReceipt {
        let receipt = self
            .admission
            .expire_tokens(sweep_id, expected_revision, now_ms);
        if receipt.applied {
            let invalidated_generic = self
                .pending_bounded_uses
                .values()
                .filter(|use_| receipt.removed_token_ids.contains(&use_.token_id))
                .map(|use_| use_.admission_use_request_id.clone())
                .collect::<Vec<_>>();
            let invalidated_lifecycle = self
                .pending_control_lease_lifecycle_uses
                .values()
                .filter(|use_| {
                    receipt
                        .removed_token_ids
                        .contains(&use_.bounded_use.token_id)
                })
                .map(|use_| use_.bounded_use.admission_use_request_id.clone())
                .collect::<Vec<_>>();
            self.pending_bounded_uses
                .retain(|_, use_| !receipt.removed_token_ids.contains(&use_.token_id));
            self.pending_control_lease_lifecycle_uses.retain(|_, use_| {
                !receipt
                    .removed_token_ids
                    .contains(&use_.bounded_use.token_id)
            });
            self.invalidated_bounded_use_ids
                .extend(invalidated_generic.iter().cloned());
            self.consumed_bounded_use_ids.extend(invalidated_generic);
            self.consumed_bounded_use_ids
                .extend(invalidated_lifecycle.iter().cloned());
            self.invalidated_control_lease_lifecycle_use_ids
                .extend(invalidated_lifecycle);
        }
        receipt
    }

    /// Consumes one bounded admission use, then reviews and applies through Runtime Host.
    ///
    /// # Panics
    ///
    /// Panics only if a bounded use disappears after the same mutable runtime
    /// validated it and immediately before its single-writer removal.
    #[must_use]
    pub fn handle_mutation(
        &mut self,
        request: &ManifoldBrokerMutationRequest,
        now_ms: u64,
    ) -> ManifoldBrokerMutationReceipt {
        let admission_revision = self.admission.snapshot().authority_revision;
        let command_selected = self
            .adapter
            .host_snapshot()
            .commands
            .iter()
            .any(|descriptor| descriptor.command_id == request.command.command_id);
        let bounded_use = self
            .pending_bounded_uses
            .get(&request.admission_use_request_id);
        let rejection = if request.schema_id.as_str() != BROKER_MUTATION_REQUEST_SCHEMA {
            Some(ManifoldBrokerMutationRejectionReason::SchemaMismatch)
        } else if request.provider_epoch_id != self.provider_epoch_id {
            Some(ManifoldBrokerMutationRejectionReason::ProviderEpochMismatch)
        } else if self.has_pending_revocation_barrier() {
            Some(ManifoldBrokerMutationRejectionReason::PendingRevocationConvergence)
        } else if self
            .consumed_bounded_use_ids
            .contains(&request.admission_use_request_id)
        {
            Some(ManifoldBrokerMutationRejectionReason::ReplayedAdmissionUse)
        } else if bounded_use.is_none() {
            Some(ManifoldBrokerMutationRejectionReason::UnknownAdmissionUse)
        } else if bounded_use.map(|use_| &use_.token_id) != Some(&request.token_id) {
            Some(ManifoldBrokerMutationRejectionReason::AdmissionTokenMismatch)
        } else if bounded_use.map(|use_| use_.admission_authority_revision)
            != Some(request.expected_admission_authority_revision)
        {
            Some(ManifoldBrokerMutationRejectionReason::StaleAdmissionRevision)
        } else if bounded_use.is_some_and(|use_| use_.expires_at_ms <= now_ms) {
            Some(ManifoldBrokerMutationRejectionReason::AdmissionUseExpired)
        } else if bounded_use.map(|use_| &use_.identity.client_id)
            != Some(&request.command.requester_id)
        {
            Some(ManifoldBrokerMutationRejectionReason::CrossClientUse)
        } else if bounded_use.map(|use_| &use_.capability_id)
            != Some(&command_capability(&request.command.command_id))
        {
            Some(ManifoldBrokerMutationRejectionReason::CapabilityMismatch)
        } else if request.command.lease_id.as_ref().is_some_and(|lease_id| {
            self.control_lease_revocation_barriers
                .contains_key(lease_id)
        }) {
            Some(ManifoldBrokerMutationRejectionReason::RevokedControlLease)
        } else if self.consumed_bounded_use_ids.len() >= MAX_BROKER_BOUNDED_USES
            || self.committed_mutation_receipts.len() >= MAX_BROKER_BOUNDED_USES
        {
            Some(ManifoldBrokerMutationRejectionReason::AuthorityCapacityExhausted)
        } else {
            None
        };

        if let Some(reason) = rejection {
            return mutation_receipt(
                &self.provider_epoch_id,
                &request.admission_use_request_id,
                admission_revision,
                command_selected,
                false,
                Some(reason),
                None,
                None,
            );
        }

        let consumed_use = self
            .pending_bounded_uses
            .remove(&request.admission_use_request_id)
            .expect("validated bounded use");
        self.consumed_bounded_use_ids
            .insert(request.admission_use_request_id.clone());
        let adapter_receipt = self.adapter.handle_command(&request.command, now_ms);
        let receipt = mutation_receipt(
            &self.provider_epoch_id,
            &request.admission_use_request_id,
            admission_revision,
            command_selected,
            true,
            None,
            Some(adapter_receipt),
            Some(consumed_use),
        );
        self.committed_mutation_receipts.push(receipt.clone());
        receipt
    }

    /// Consumes one accepted bounded use for a non-command capability such as
    /// canonical `manifold.stream.subscribe`. The caller identity is a
    /// platform-verified adapter input; no transport-local acceptance exists.
    ///
    /// # Panics
    ///
    /// Panics only if a bounded use disappears after the same mutable runtime
    /// validated it and immediately before its single-writer removal.
    #[must_use]
    pub fn consume_capability_use(
        &mut self,
        admission_use_request_id: &DottedId,
        token_id: &DottedId,
        expected_admission_authority_revision: Revision,
        identity: &ManifoldClientIdentity,
        capability_id: &DottedId,
        now_ms: u64,
    ) -> ManifoldBrokerCapabilityUseReceipt {
        let use_ = self.pending_bounded_uses.get(admission_use_request_id);
        let rejection = if self.has_pending_revocation_barrier() {
            Some(ManifoldBrokerMutationRejectionReason::PendingRevocationConvergence)
        } else if self
            .consumed_bounded_use_ids
            .contains(admission_use_request_id)
        {
            Some(ManifoldBrokerMutationRejectionReason::ReplayedAdmissionUse)
        } else if use_.is_none() {
            Some(ManifoldBrokerMutationRejectionReason::UnknownAdmissionUse)
        } else if use_.map(|value| &value.token_id) != Some(token_id) {
            Some(ManifoldBrokerMutationRejectionReason::AdmissionTokenMismatch)
        } else if use_.map(|value| value.admission_authority_revision)
            != Some(expected_admission_authority_revision)
        {
            Some(ManifoldBrokerMutationRejectionReason::StaleAdmissionRevision)
        } else if use_.is_some_and(|value| value.expires_at_ms <= now_ms) {
            Some(ManifoldBrokerMutationRejectionReason::AdmissionUseExpired)
        } else if use_.map(|value| &value.identity) != Some(identity) {
            Some(ManifoldBrokerMutationRejectionReason::CrossClientUse)
        } else if use_.map(|value| &value.capability_id) != Some(capability_id) {
            Some(ManifoldBrokerMutationRejectionReason::CapabilityMismatch)
        } else if self
            .adapter
            .host_snapshot()
            .commands
            .iter()
            .any(|descriptor| command_capability(&descriptor.command_id) == *capability_id)
        {
            Some(ManifoldBrokerMutationRejectionReason::CapabilityMismatch)
        } else if self.consumed_bounded_use_ids.len() >= MAX_BROKER_BOUNDED_USES
            || self.committed_capability_use_receipts.len() >= MAX_BROKER_BOUNDED_USES
        {
            Some(ManifoldBrokerMutationRejectionReason::AuthorityCapacityExhausted)
        } else {
            None
        };
        if let Some(reason) = rejection {
            return ManifoldBrokerCapabilityUseReceipt {
                schema_id: schema_id(BROKER_CAPABILITY_USE_RECEIPT_SCHEMA),
                provider_epoch_id: self.provider_epoch_id.clone(),
                applied: false,
                bounded_use: None,
                rejection_reason: Some(reason),
            };
        }
        let bounded_use = self
            .pending_bounded_uses
            .remove(admission_use_request_id)
            .expect("validated bounded use");
        self.consumed_bounded_use_ids
            .insert(admission_use_request_id.clone());
        let receipt = ManifoldBrokerCapabilityUseReceipt {
            schema_id: schema_id(BROKER_CAPABILITY_USE_RECEIPT_SCHEMA),
            provider_epoch_id: self.provider_epoch_id.clone(),
            applied: true,
            bounded_use: Some(bounded_use),
            rejection_reason: None,
        };
        self.committed_capability_use_receipts.push(receipt.clone());
        receipt
    }

    /// Returns a read-only state/evidence projection for rebind and restart tests.
    #[must_use]
    pub fn evidence(&self) -> ManifoldBrokerRuntimeEvidence {
        ManifoldBrokerRuntimeEvidence {
            schema_id: schema_id(BROKER_RUNTIME_EVIDENCE_SCHEMA),
            provider_epoch_id: self.provider_epoch_id.clone(),
            host_snapshot: self.adapter.host_snapshot().clone(),
            control_lease_authority: self.control_lease_authority.evidence(),
            admission_snapshot: self.admission.snapshot().clone(),
            pending_bounded_uses: self.pending_bounded_uses.values().cloned().collect(),
            authorized_bounded_uses: self.authorized_bounded_uses.values().cloned().collect(),
            admission_token_history: self.admission_token_history.values().cloned().collect(),
            invalidated_bounded_use_ids: self.invalidated_bounded_use_ids.iter().cloned().collect(),
            pending_control_lease_lifecycle_uses: self
                .pending_control_lease_lifecycle_uses
                .values()
                .cloned()
                .collect(),
            authorized_control_lease_lifecycle_uses: self
                .authorized_control_lease_lifecycle_uses
                .values()
                .cloned()
                .collect(),
            invalidated_control_lease_lifecycle_use_ids: self
                .invalidated_control_lease_lifecycle_use_ids
                .iter()
                .cloned()
                .collect(),
            control_lease_revocation_use_invalidations: self
                .control_lease_revocation_use_invalidations
                .values()
                .cloned()
                .collect(),
            control_lease_revocation_barriers: self
                .control_lease_revocation_barriers
                .values()
                .cloned()
                .collect(),
            control_lease_revocation_recovery_receipts: self
                .control_lease_revocation_recovery_receipts
                .clone(),
            control_lease_revocation_consumer_acknowledgements: self
                .control_lease_revocation_consumer_acknowledgements
                .values()
                .cloned()
                .collect(),
            committed_mutation_receipts: self.committed_mutation_receipts.clone(),
            committed_capability_use_receipts: self.committed_capability_use_receipts.clone(),
            compacted_control_lease_request_ids: self
                .compacted_control_lease_request_ids
                .iter()
                .cloned()
                .collect(),
            consumed_bounded_use_ids: self.consumed_bounded_use_ids.iter().cloned().collect(),
            control_lease_lifecycle_receipts: self.control_lease_lifecycle_receipts.clone(),
        }
    }

    /// Retains one terminal downstream revocation acknowledgement.
    ///
    /// # Trust boundary
    ///
    /// The deployment owner must verify the named consumer's exact
    /// convergence and terminal cleanup receipts before supplying their
    /// domain-separated digests. This method binds them to the live converged
    /// Broker barrier; it does not reinterpret consumer-owned evidence.
    ///
    /// # Errors
    ///
    /// Returns when the acknowledgement is malformed, replayed, unexpected for
    /// the packaged product, or does not bind one exact converged barrier.
    pub fn acknowledge_control_lease_revocation_consumer(
        &mut self,
        acknowledgement: ManifoldBrokerControlLeaseRevocationConsumerAcknowledgement,
    ) -> Result<(), ManifoldBrokerRuntimeStateError> {
        let duplicate_barrier_consumer = self
            .control_lease_revocation_consumer_acknowledgements
            .values()
            .any(|retained| {
                retained.barrier_id == acknowledgement.barrier_id
                    && retained.consumer_kind == acknowledgement.consumer_kind
            });
        if self
            .control_lease_revocation_consumer_acknowledgements
            .contains_key(&acknowledgement.acknowledgement_id)
            || duplicate_barrier_consumer
            || self
                .control_lease_revocation_consumer_acknowledgements
                .len()
                >= MAX_BROKER_CONTROL_LEASE_TRANSITIONS
            || !revocation_consumer_acknowledgements_close(
                std::slice::from_ref(&acknowledgement),
                &self.provider_epoch_id,
                &self
                    .control_lease_revocation_barriers
                    .values()
                    .cloned()
                    .collect::<Vec<_>>(),
                self.adapter.product_features(),
            )
        {
            return Err(ManifoldBrokerRuntimeStateError::InvalidEvidence(
                "revocation_consumer_acknowledgement",
            ));
        }
        let mut candidate = self.staged_copy()?;
        candidate
            .control_lease_revocation_consumer_acknowledgements
            .insert(acknowledgement.acknowledgement_id.clone(), acknowledgement);
        validate_runtime_evidence_size(&candidate.evidence())?;
        *self = candidate;
        Ok(())
    }

    fn revocation_barriers_ready_for_rollover(&self) -> bool {
        let peer_required =
            product_requires_peer_runtime_host_acknowledgement(self.adapter.product_features());
        self.control_lease_revocation_barriers
            .values()
            .all(|barrier| {
                barrier.state == ManifoldBrokerControlLeaseRevocationBarrierState::Converged
                    && (!peer_required
                        || self
                            .control_lease_revocation_consumer_acknowledgements
                            .values()
                            .any(|acknowledgement| {
                                acknowledgement.consumer_kind
                                    == ManifoldBrokerControlLeaseRevocationConsumerKind::
                                        PeerRuntimeHost
                                    && acknowledgement.barrier_id == barrier.barrier_id
                                    && acknowledgement.revocation_application_id
                                        == barrier.revocation_application_id
                                    && acknowledgement.lease_id == barrier.lease_id
                            }))
            })
    }

    /// Compacts a fully drained owner into a fresh fenced provider epoch.
    ///
    /// This is the terminal cleanup path for bounded ledgers. It is available
    /// without appending another owner transition. The Runtime Host snapshot,
    /// generic authority identity/revision/snapshot, and clock lineage remain
    /// exact. The complete prior evidence is checkpointed by digest, while the
    /// fresh admission snapshot invalidates old-epoch tokens and replay state.
    ///
    /// # Errors
    ///
    /// Returns unless every product lease and pending use has been drained,
    /// the new epoch differs, fresh admission contains no live/replay state, or
    /// the compact owner/resulting runtime fails normal closure.
    pub fn rollover_drained_provider_epoch(
        &mut self,
        resulting_provider_epoch_id: DottedId,
        fresh_admission_snapshot: ManifoldAdmissionSnapshot,
    ) -> Result<ManifoldBrokerRuntimeEpochRolloverReceipt, ManifoldBrokerRuntimeStateError> {
        if resulting_provider_epoch_id == self.provider_epoch_id
            || !self.adapter.host_snapshot().leases.is_empty()
            || !self.control_lease_authority.runtime_leases().is_empty()
            || !self.pending_bounded_uses.is_empty()
            || !self.pending_control_lease_lifecycle_uses.is_empty()
            || !self.revocation_barriers_ready_for_rollover()
        {
            return Err(ManifoldBrokerRuntimeStateError::InvalidEvidence(
                "epoch_rollover_not_drained",
            ));
        }
        if !fresh_admission_snapshot.active_tokens.is_empty()
            || !fresh_admission_snapshot.revoked_token_ids.is_empty()
            || !fresh_admission_snapshot.consumed_request_ids.is_empty()
            || !fresh_admission_snapshot.consumed_use_request_ids.is_empty()
            || !fresh_admission_snapshot.reviewed_sweep_ids.is_empty()
            || !fresh_admission_snapshot.audit_events.is_empty()
        {
            return Err(ManifoldBrokerRuntimeStateError::InvalidEvidence(
                "epoch_rollover_admission_not_fresh",
            ));
        }

        let source_evidence = self.evidence();
        let source_json = serialize_migration_artifact(&source_evidence)?;
        let owner_snapshot = self.control_lease_authority.authority_snapshot().clone();
        let owner_clock = self.control_lease_authority.current_clock().clone();
        let compact_owner =
            ManifoldBrokerControlLeaseAuthority::from_caller_attested_retained_authority_state(
                owner_snapshot.clone(),
                owner_clock.clone(),
                Vec::new(),
            )
            .map_err(ManifoldBrokerRuntimeStateError::ControlLeaseAuthority)?;
        let mut compacted_control_lease_request_ids =
            self.compacted_control_lease_request_ids.clone();
        compacted_control_lease_request_ids.extend(
            source_evidence
                .control_lease_authority
                .baseline
                .lease_sources
                .iter()
                .map(|source| source.application.request_id.clone()),
        );
        compacted_control_lease_request_ids.extend(
            source_evidence
                .control_lease_authority
                .transitions
                .iter()
                .map(|transition| transition.application.request_id().clone()),
        );
        compacted_control_lease_request_ids.extend(
            source_evidence
                .control_lease_lifecycle_receipts
                .iter()
                .map(|receipt| receipt.lifecycle_request_id.clone()),
        );
        compacted_control_lease_request_ids.extend(
            source_evidence
                .authorized_control_lease_lifecycle_uses
                .iter()
                .map(|use_| use_.lifecycle_request_id.clone()),
        );
        if compacted_control_lease_request_ids.len()
            > MAX_BROKER_COMPACTED_CONTROL_LEASE_REQUEST_IDS
        {
            return Err(ManifoldBrokerRuntimeStateError::InvalidEvidence(
                "epoch_rollover_replay_capacity",
            ));
        }
        let mut candidate = Self::new(
            resulting_provider_epoch_id.clone(),
            self.adapter.clone(),
            compact_owner,
            fresh_admission_snapshot,
        )?;
        candidate.compacted_control_lease_request_ids = compacted_control_lease_request_ids;
        let resulting_evidence = candidate.evidence();
        validate_runtime_evidence_size(&resulting_evidence)?;
        let resulting_json = serialize_migration_artifact(&resulting_evidence)?;
        let mut invalidated_admission_token_ids = source_evidence
            .admission_snapshot
            .active_tokens
            .iter()
            .map(|token| token.token_id.clone())
            .collect::<Vec<_>>();
        invalidated_admission_token_ids.sort();
        let receipt = ManifoldBrokerRuntimeEpochRolloverReceipt {
            schema_id: schema_id(BROKER_RUNTIME_EPOCH_ROLLOVER_RECEIPT_SCHEMA),
            source_provider_epoch_id: self.provider_epoch_id.clone(),
            resulting_provider_epoch_id,
            source_evidence_sha256: sha256_binding(
                EPOCH_ROLLOVER_SOURCE_DIGEST_DOMAIN,
                &source_json,
            ),
            source_evidence_size_bytes: bounded_evidence_len_u64(source_json.len())?,
            resulting_evidence_sha256: sha256_binding(
                EPOCH_ROLLOVER_RESULT_DIGEST_DOMAIN,
                &resulting_json,
            ),
            resulting_evidence_size_bytes: bounded_evidence_len_u64(resulting_json.len())?,
            manifold_authority_id: owner_snapshot.authority_id,
            manifold_authority_revision: owner_snapshot.authority_revision,
            clock_domain: owner_clock.clock_domain,
            clock_epoch_id: owner_clock.clock_epoch_id,
            clock_sequence: owner_clock.sequence,
            authority_host_id: source_evidence.host_snapshot.host_id.clone(),
            host_authority_revision: source_evidence.host_snapshot.authority_revision,
            compacted_owner_transition_count: source_evidence
                .control_lease_authority
                .transitions
                .len(),
            checkpointed_lifecycle_receipt_count: source_evidence
                .control_lease_lifecycle_receipts
                .len(),
            checkpointed_revocation_barrier_count: source_evidence
                .control_lease_revocation_barriers
                .len(),
            checkpointed_revocation_consumer_acknowledgement_count: source_evidence
                .control_lease_revocation_consumer_acknowledgements
                .len(),
            checkpointed_mutation_receipt_count: source_evidence.committed_mutation_receipts.len(),
            checkpointed_capability_use_receipt_count: source_evidence
                .committed_capability_use_receipts
                .len(),
            checkpointed_invalidated_bounded_use_count: source_evidence
                .invalidated_bounded_use_ids
                .len(),
            checkpointed_admission_token_history_count: source_evidence
                .admission_token_history
                .len(),
            checkpointed_control_lease_request_count: resulting_evidence
                .compacted_control_lease_request_ids
                .len(),
            checkpointed_consumed_use_count: source_evidence.consumed_bounded_use_ids.len(),
            invalidated_admission_token_ids,
        };
        *self = candidate;
        Ok(receipt)
    }

    /// Runs one mutation against an isolated candidate, commits that candidate,
    /// then exposes the immutable receipt/evidence to an observer.
    ///
    /// The candidate never crosses this API boundary, so a second live runtime
    /// with the same provider epoch cannot escape. Commit occurs before the
    /// observer runs, so a valid one-use decision cannot become a rollback
    /// oracle even when the observer returns an error-like value or panics.
    ///
    /// # Errors
    ///
    /// Returns without changing the live runtime only when isolated candidate
    /// reconstruction fails before mutation review.
    pub fn commit_mutation<T>(
        &mut self,
        request: &ManifoldBrokerMutationRequest,
        now_ms: u64,
        observe: impl FnOnce(&ManifoldBrokerMutationReceipt, &ManifoldBrokerRuntimeEvidence) -> T,
    ) -> Result<T, ManifoldBrokerRuntimeStateError> {
        let mut candidate = self.staged_copy()?;
        let receipt = candidate.handle_mutation(request, now_ms);
        let evidence = candidate.evidence();
        *self = candidate;
        Ok(observe(&receipt, &evidence))
    }

    /// Consumes one exact lifecycle-bound use and atomically commits Manifold
    /// owner state with the matching Runtime Host adoption.
    ///
    /// Authority rejection commits the consumed use and exact rejected generic
    /// application without changing accepted owner/Host state. A Host
    /// composition failure commits only the consumed-use tombstone and failure
    /// receipt from the original live state. The immutable observer runs only
    /// after the selected state has committed.
    ///
    /// # Errors
    ///
    /// Returns only when private candidate reconstruction or durable evidence
    /// validation fails before a selectable committed outcome exists.
    ///
    /// # Panics
    ///
    /// Panics only if a validated private candidate loses the exact lifecycle
    /// use before its immediately following single-writer removal.
    #[allow(clippy::too_many_lines)]
    pub fn commit_control_lease_lifecycle<T>(
        &mut self,
        request: &ManifoldBrokerControlLeaseLifecycleRequest,
        recorded_clock: ManifoldClockSnapshot,
        evidence_refs: Vec<DottedId>,
        observe: impl FnOnce(
            &ManifoldBrokerControlLeaseLifecycleReceipt,
            &ManifoldBrokerRuntimeEvidence,
        ) -> T,
    ) -> Result<T, ManifoldBrokerRuntimeStateError> {
        if let Some(reason) =
            self.control_lease_lifecycle_preflight(request, &recorded_clock, &evidence_refs)
        {
            let receipt = lifecycle_receipt(
                &self.provider_epoch_id,
                self.adapter.config(),
                request,
                None,
                ManifoldBrokerControlLeaseLifecycleOutcome::PreflightRejected,
                None,
                None,
                Some(reason),
            );
            let evidence = self.evidence();
            return Ok(observe(&receipt, &evidence));
        }

        let mut consumed_candidate = self.staged_copy()?;
        let mut transition_candidate = consumed_candidate.staged_copy()?;
        let lifecycle_use = consumed_candidate
            .pending_control_lease_lifecycle_uses
            .remove(&request.admission_use_request_id)
            .expect("preflight validated lifecycle use");
        consumed_candidate
            .consumed_bounded_use_ids
            .insert(request.admission_use_request_id.clone());
        transition_candidate
            .pending_control_lease_lifecycle_uses
            .remove(&request.admission_use_request_id)
            .expect("preflight validated lifecycle use in transition candidate");
        transition_candidate
            .consumed_bounded_use_ids
            .insert(request.admission_use_request_id.clone());
        let transition_result = transition_candidate.apply_control_lease_operation(
            &request.operation,
            &lifecycle_use.bounded_use.identity,
            recorded_clock,
            evidence_refs,
        );

        let transition = match transition_result {
            Ok(transition) => transition,
            Err(error) => {
                let reason = control_lease_authority_rejection(&error);
                let outcome = if matches!(
                    error,
                    ManifoldBrokerControlLeaseAuthorityError::UnsupportedExpiryDelta
                ) {
                    ManifoldBrokerControlLeaseLifecycleOutcome::UnsupportedAuthorityExpiryDelta
                } else {
                    ManifoldBrokerControlLeaseLifecycleOutcome::
                        CompositionFailedAfterPermitConsumption
                };
                let receipt = lifecycle_receipt(
                    &consumed_candidate.provider_epoch_id,
                    consumed_candidate.adapter.config(),
                    request,
                    Some(lifecycle_use),
                    outcome,
                    None,
                    None,
                    Some(reason),
                );
                consumed_candidate
                    .control_lease_lifecycle_receipts
                    .push(receipt.clone());
                let evidence = consumed_candidate.evidence();
                validate_runtime_evidence_size(&evidence)?;
                *self = consumed_candidate;
                return Ok(observe(&receipt, &evidence));
            }
        };

        if !control_lease_transition_applied(&transition) {
            let receipt = lifecycle_receipt(
                &transition_candidate.provider_epoch_id,
                transition_candidate.adapter.config(),
                request,
                Some(lifecycle_use),
                ManifoldBrokerControlLeaseLifecycleOutcome::AuthorityRejected,
                Some(transition),
                None,
                None,
            );
            transition_candidate
                .control_lease_lifecycle_receipts
                .push(receipt.clone());
            let evidence = transition_candidate.evidence();
            validate_runtime_evidence_size(&evidence)?;
            *self = transition_candidate;
            return Ok(observe(&receipt, &evidence));
        }

        let adoption_request = control_lease_adoption_request(
            transition_candidate
                .adapter
                .host_snapshot()
                .authority_revision,
            &transition,
        );
        let host_adoption = transition_candidate.adapter.apply_control_lease_adoption(
            &adoption_request,
            &transition_candidate.control_lease_authority,
        );
        match host_adoption {
            Ok(host_adoption) if host_adoption.applied => {
                if matches!(
                    &transition.application,
                    ManifoldBrokerControlLeaseTransitionApplication::Revocation(_)
                ) {
                    transition_candidate.install_control_lease_revocation_barrier(
                        &transition,
                        Some(host_adoption.clone()),
                        ManifoldBrokerControlLeaseRevocationBarrierState::Converged,
                    )?;
                }
                let receipt = lifecycle_receipt(
                    &transition_candidate.provider_epoch_id,
                    transition_candidate.adapter.config(),
                    request,
                    Some(lifecycle_use),
                    ManifoldBrokerControlLeaseLifecycleOutcome::AcceptedAndAdopted,
                    Some(transition),
                    Some(host_adoption),
                    None,
                );
                transition_candidate
                    .control_lease_lifecycle_receipts
                    .push(receipt.clone());
                let evidence = transition_candidate.evidence();
                validate_runtime_evidence_size(&evidence)?;
                *self = transition_candidate;
                Ok(observe(&receipt, &evidence))
            }
            Ok(host_adoption) => {
                if matches!(
                    &transition.application,
                    ManifoldBrokerControlLeaseTransitionApplication::Revocation(_)
                ) {
                    consumed_candidate.install_control_lease_revocation_barrier(
                        &transition,
                        None,
                        ManifoldBrokerControlLeaseRevocationBarrierState::PendingHostConvergence,
                    )?;
                }
                let receipt = lifecycle_receipt(
                    &consumed_candidate.provider_epoch_id,
                    consumed_candidate.adapter.config(),
                    request,
                    Some(lifecycle_use),
                    ManifoldBrokerControlLeaseLifecycleOutcome::
                        CompositionFailedAfterPermitConsumption,
                    Some(transition),
                    Some(host_adoption),
                    Some(
                        ManifoldBrokerControlLeaseLifecycleRejectionReason::
                            OwnerHostCompositionFailed,
                    ),
                );
                consumed_candidate
                    .control_lease_lifecycle_receipts
                    .push(receipt.clone());
                let evidence = consumed_candidate.evidence();
                validate_runtime_evidence_size(&evidence)?;
                *self = consumed_candidate;
                Ok(observe(&receipt, &evidence))
            }
            Err(_) => {
                if matches!(
                    &transition.application,
                    ManifoldBrokerControlLeaseTransitionApplication::Revocation(_)
                ) {
                    consumed_candidate.install_control_lease_revocation_barrier(
                        &transition,
                        None,
                        ManifoldBrokerControlLeaseRevocationBarrierState::PendingHostConvergence,
                    )?;
                }
                let receipt = lifecycle_receipt(
                    &consumed_candidate.provider_epoch_id,
                    consumed_candidate.adapter.config(),
                    request,
                    Some(lifecycle_use),
                    ManifoldBrokerControlLeaseLifecycleOutcome::
                        CompositionFailedAfterPermitConsumption,
                    Some(transition),
                    None,
                    Some(
                        ManifoldBrokerControlLeaseLifecycleRejectionReason::
                            OwnerHostCompositionFailed,
                    ),
                );
                consumed_candidate
                    .control_lease_lifecycle_receipts
                    .push(receipt.clone());
                let evidence = consumed_candidate.evidence();
                validate_runtime_evidence_size(&evidence)?;
                *self = consumed_candidate;
                Ok(observe(&receipt, &evidence))
            }
        }
    }

    /// Retries the exact retained transition behind one pending Host barrier.
    ///
    /// This deployment-owner recovery path accepts no replacement lease,
    /// reason, clock, application, or transition. It reuses the immutable
    /// generic application that established the barrier and atomically commits
    /// the owner plus Runtime Host only when both still match its prior state.
    ///
    /// # Errors
    ///
    /// Returns only when private candidate reconstruction or durable evidence
    /// validation fails. Ordinary CAS, replay, or Host rejection is returned
    /// as a typed non-applied recovery receipt.
    pub fn recover_pending_control_lease_revocation(
        &mut self,
        request: &ManifoldBrokerControlLeaseRevocationRecoveryRequest,
    ) -> Result<ManifoldBrokerControlLeaseRevocationRecoveryReceipt, ManifoldBrokerRuntimeStateError>
    {
        let prior_owner_revision = self
            .control_lease_authority
            .authority_snapshot()
            .authority_revision;
        let prior_host_revision = self.adapter.host_snapshot().authority_revision;
        let barrier = self
            .control_lease_revocation_barriers
            .values()
            .find(|barrier| barrier.barrier_id == request.barrier_id)
            .cloned();
        let rejection = if request.schema_id.as_str()
            != BROKER_CONTROL_LEASE_REVOCATION_RECOVERY_REQUEST_SCHEMA
        {
            Some(ManifoldBrokerControlLeaseLifecycleRejectionReason::SchemaMismatch)
        } else if request.provider_epoch_id != self.provider_epoch_id {
            Some(ManifoldBrokerControlLeaseLifecycleRejectionReason::ProviderEpochMismatch)
        } else if self
            .control_lease_revocation_recovery_receipts
            .iter()
            .any(|receipt| receipt.recovery_id == request.recovery_id)
        {
            Some(ManifoldBrokerControlLeaseLifecycleRejectionReason::ReplayedLifecycleRequest)
        } else if barrier.is_none()
            || barrier.as_ref().is_some_and(|barrier| {
                barrier.state
                    != ManifoldBrokerControlLeaseRevocationBarrierState::PendingHostConvergence
            })
        {
            Some(ManifoldBrokerControlLeaseLifecycleRejectionReason::RevokedLease)
        } else if request.expected_control_lease_authority_revision != prior_owner_revision {
            Some(
                ManifoldBrokerControlLeaseLifecycleRejectionReason::
                    StaleControlLeaseAuthorityRevision,
            )
        } else if request.expected_host_authority_revision != prior_host_revision {
            Some(ManifoldBrokerControlLeaseLifecycleRejectionReason::OwnerHostCompositionFailed)
        } else if self.control_lease_revocation_recovery_receipts.len()
            >= MAX_BROKER_CONTROL_LEASE_TRANSITIONS
        {
            Some(ManifoldBrokerControlLeaseLifecycleRejectionReason::AuthorityCapacityExhausted)
        } else {
            None
        };
        let Some(barrier) = barrier else {
            return Ok(revocation_recovery_receipt(
                &self.provider_epoch_id,
                request,
                None,
                prior_owner_revision,
                prior_host_revision,
                None,
                None,
                rejection,
            ));
        };
        if let Some(reason) = rejection {
            let receipt = revocation_recovery_receipt(
                &self.provider_epoch_id,
                request,
                Some(&barrier),
                prior_owner_revision,
                prior_host_revision,
                None,
                None,
                Some(reason),
            );
            let retainable = request.schema_id.as_str()
                == BROKER_CONTROL_LEASE_REVOCATION_RECOVERY_REQUEST_SCHEMA
                && request.provider_epoch_id == self.provider_epoch_id
                && barrier.state
                    == ManifoldBrokerControlLeaseRevocationBarrierState::PendingHostConvergence
                && !self
                    .control_lease_revocation_recovery_receipts
                    .iter()
                    .any(|retained| retained.recovery_id == request.recovery_id)
                && self.control_lease_revocation_recovery_receipts.len()
                    < self.revocation_recovery_rejection_capacity();
            return if retainable {
                self.retain_revocation_recovery_receipt(receipt)
            } else {
                Ok(receipt)
            };
        }

        let mut candidate = self.staged_copy()?;
        if candidate
            .control_lease_authority
            .adopt_retained_revocation_transition(&barrier.authority_transition)
            .is_err()
        {
            let receipt = revocation_recovery_receipt(
                &self.provider_epoch_id,
                request,
                Some(&barrier),
                prior_owner_revision,
                prior_host_revision,
                None,
                None,
                Some(ManifoldBrokerControlLeaseLifecycleRejectionReason::AuthorityLineageInvalid),
            );
            return self.retain_revocation_recovery_receipt(receipt);
        }
        let adoption_request =
            control_lease_adoption_request(prior_host_revision, &barrier.authority_transition);
        let adoption = candidate
            .adapter
            .apply_control_lease_adoption(&adoption_request, &candidate.control_lease_authority);
        let Ok(host_adoption) = adoption else {
            let receipt = revocation_recovery_receipt(
                &self.provider_epoch_id,
                request,
                Some(&barrier),
                prior_owner_revision,
                prior_host_revision,
                Some(barrier.authority_transition.clone()),
                None,
                Some(
                    ManifoldBrokerControlLeaseLifecycleRejectionReason::OwnerHostCompositionFailed,
                ),
            );
            return self.retain_revocation_recovery_receipt(receipt);
        };
        if !host_adoption.applied {
            let receipt = revocation_recovery_receipt(
                &self.provider_epoch_id,
                request,
                Some(&barrier),
                prior_owner_revision,
                prior_host_revision,
                Some(barrier.authority_transition.clone()),
                Some(host_adoption),
                Some(
                    ManifoldBrokerControlLeaseLifecycleRejectionReason::OwnerHostCompositionFailed,
                ),
            );
            return self.retain_revocation_recovery_receipt(receipt);
        }
        let Some(recovered_barrier) = candidate
            .control_lease_revocation_barriers
            .get_mut(&barrier.lease_id)
        else {
            return Err(ManifoldBrokerRuntimeStateError::InvalidEvidence(
                "revocation_barrier_missing_during_recovery",
            ));
        };
        recovered_barrier.state = ManifoldBrokerControlLeaseRevocationBarrierState::Converged;
        recovered_barrier.host_adoption = Some(host_adoption.clone());
        let receipt = revocation_recovery_receipt(
            &candidate.provider_epoch_id,
            request,
            Some(recovered_barrier),
            prior_owner_revision,
            prior_host_revision,
            Some(barrier.authority_transition),
            Some(host_adoption),
            None,
        );
        candidate
            .control_lease_revocation_recovery_receipts
            .push(receipt.clone());
        let evidence = candidate.evidence();
        validate_runtime_evidence_size(&evidence)?;
        *self = candidate;
        Ok(receipt)
    }

    fn retain_revocation_recovery_receipt(
        &mut self,
        receipt: ManifoldBrokerControlLeaseRevocationRecoveryReceipt,
    ) -> Result<ManifoldBrokerControlLeaseRevocationRecoveryReceipt, ManifoldBrokerRuntimeStateError>
    {
        if !receipt.applied
            && self.control_lease_revocation_recovery_receipts.len()
                >= self.revocation_recovery_rejection_capacity()
        {
            return Ok(receipt);
        }
        let mut candidate = self.staged_copy()?;
        candidate
            .control_lease_revocation_recovery_receipts
            .push(receipt.clone());
        validate_runtime_evidence_size(&candidate.evidence())?;
        *self = candidate;
        Ok(receipt)
    }

    fn revocation_recovery_rejection_capacity(&self) -> usize {
        let pending_barrier_count = self
            .control_lease_revocation_barriers
            .values()
            .filter(|barrier| {
                barrier.state
                    == ManifoldBrokerControlLeaseRevocationBarrierState::PendingHostConvergence
            })
            .count();
        MAX_BROKER_CONTROL_LEASE_TRANSITIONS.saturating_sub(pending_barrier_count)
    }

    fn has_pending_revocation_barrier(&self) -> bool {
        self.control_lease_revocation_barriers
            .values()
            .any(|barrier| {
                barrier.state
                    == ManifoldBrokerControlLeaseRevocationBarrierState::PendingHostConvergence
            })
    }

    fn control_lease_lifecycle_preflight(
        &self,
        request: &ManifoldBrokerControlLeaseLifecycleRequest,
        recorded_clock: &ManifoldClockSnapshot,
        evidence_refs: &[DottedId],
    ) -> Option<ManifoldBrokerControlLeaseLifecycleRejectionReason> {
        let use_ = self
            .pending_control_lease_lifecycle_uses
            .get(&request.admission_use_request_id);
        if request.schema_id.as_str() != BROKER_CONTROL_LEASE_LIFECYCLE_REQUEST_SCHEMA {
            Some(ManifoldBrokerControlLeaseLifecycleRejectionReason::SchemaMismatch)
        } else if request.provider_epoch_id != self.provider_epoch_id {
            Some(ManifoldBrokerControlLeaseLifecycleRejectionReason::ProviderEpochMismatch)
        } else if self.has_pending_revocation_barrier() {
            Some(ManifoldBrokerControlLeaseLifecycleRejectionReason::PendingRevocationConvergence)
        } else if self
            .compacted_control_lease_request_ids
            .contains(request.operation.request_id())
        {
            Some(ManifoldBrokerControlLeaseLifecycleRejectionReason::ReplayedLifecycleRequest)
        } else if request.operation.lease_id().is_some_and(|lease_id| {
            self.control_lease_revocation_barriers
                .contains_key(lease_id)
        }) {
            Some(ManifoldBrokerControlLeaseLifecycleRejectionReason::RevokedLease)
        } else if self
            .consumed_bounded_use_ids
            .contains(&request.admission_use_request_id)
        {
            Some(ManifoldBrokerControlLeaseLifecycleRejectionReason::ReplayedLifecycleUse)
        } else if use_.is_none() {
            Some(ManifoldBrokerControlLeaseLifecycleRejectionReason::UnknownLifecycleUse)
        } else if use_.map(|value| &value.bounded_use.token_id) != Some(&request.token_id) {
            Some(ManifoldBrokerControlLeaseLifecycleRejectionReason::AdmissionTokenMismatch)
        } else if use_.map(|value| value.authorized_from_admission_authority_revision)
            != Some(request.expected_admission_authority_revision)
        {
            Some(ManifoldBrokerControlLeaseLifecycleRejectionReason::StaleAdmissionRevision)
        } else if use_.is_some_and(|value| {
            value.bounded_use.expires_at_ms
                <= u64::try_from(recorded_clock.wall_unix_ms).unwrap_or(0)
        }) {
            Some(ManifoldBrokerControlLeaseLifecycleRejectionReason::LifecycleUseExpired)
        } else if use_.map(|value| value.operation_kind) != Some(request.operation.kind())
            || use_.map(|value| &value.lifecycle_request_id) != Some(request.operation.request_id())
            || use_.map(|value| &value.lifecycle_request_sha256)
                != Some(&control_lease_lifecycle_request_sha256(request))
            || use_.map(|value| value.expected_control_lease_authority_revision)
                != Some(request.operation.expected_authority_revision())
            || use_.and_then(|value| value.lease_id.as_ref()) != request.operation.lease_id()
            || use_.and_then(|value| value.issue_scope.as_ref()) != request.operation.issue_scope()
            || use_.map(|value| value.expiry_lease_ids.as_slice())
                != Some(request.operation.expiry_lease_ids().unwrap_or_default())
        {
            Some(ManifoldBrokerControlLeaseLifecycleRejectionReason::LifecycleRequestMismatch)
        } else if request.operation.expected_authority_revision()
            != self
                .control_lease_authority
                .authority_snapshot()
                .authority_revision
        {
            Some(
                ManifoldBrokerControlLeaseLifecycleRejectionReason::
                    StaleControlLeaseAuthorityRevision,
            )
        } else if evidence_refs.is_empty() {
            Some(ManifoldBrokerControlLeaseLifecycleRejectionReason::AuthorityLineageInvalid)
        } else if self.control_lease_lifecycle_receipts.len()
            >= MAX_BROKER_CONTROL_LEASE_TRANSITIONS
        {
            Some(ManifoldBrokerControlLeaseLifecycleRejectionReason::AuthorityCapacityExhausted)
        } else if let Err(error) = self
            .control_lease_authority
            .ensure_transition_capacity(transition_kind(request.operation.kind()))
        {
            Some(control_lease_authority_rejection(&error))
        } else if request.operation.kind()
            == ManifoldBrokerControlLeaseLifecycleOperationKind::Revocation
        {
            self.revocation_commit_preview_rejection(
                request,
                recorded_clock,
                evidence_refs,
                use_.expect("validated lifecycle use"),
            )
        } else {
            self.cleanup_reserve_preview_rejection(
                request,
                recorded_clock,
                evidence_refs,
                use_.expect("validated lifecycle use"),
            )
        }
    }

    fn revocation_commit_preview_rejection(
        &self,
        request: &ManifoldBrokerControlLeaseLifecycleRequest,
        recorded_clock: &ManifoldClockSnapshot,
        evidence_refs: &[DottedId],
        lifecycle_use: &ManifoldBrokerControlLeaseLifecycleUse,
    ) -> Option<ManifoldBrokerControlLeaseLifecycleRejectionReason> {
        let Ok(mut consumed_candidate) = self.staged_copy() else {
            return Some(
                ManifoldBrokerControlLeaseLifecycleRejectionReason::AuthorityCapacityExhausted,
            );
        };
        let Ok(mut transition_candidate) = consumed_candidate.staged_copy() else {
            return Some(
                ManifoldBrokerControlLeaseLifecycleRejectionReason::AuthorityCapacityExhausted,
            );
        };
        for candidate in [&mut consumed_candidate, &mut transition_candidate] {
            candidate
                .pending_control_lease_lifecycle_uses
                .remove(&request.admission_use_request_id);
            candidate
                .consumed_bounded_use_ids
                .insert(request.admission_use_request_id.clone());
        }
        let Ok(transition) = transition_candidate.apply_control_lease_operation(
            &request.operation,
            &lifecycle_use.bounded_use.identity,
            recorded_clock.clone(),
            evidence_refs.to_vec(),
        ) else {
            return None;
        };
        if !control_lease_transition_applied(&transition) {
            return None;
        }
        let adoption_request = control_lease_adoption_request(
            transition_candidate
                .adapter
                .host_snapshot()
                .authority_revision,
            &transition,
        );
        let host_adoption = transition_candidate.adapter.apply_control_lease_adoption(
            &adoption_request,
            &transition_candidate.control_lease_authority,
        );
        let evidence = match host_adoption {
            Ok(adoption) if adoption.applied => {
                if transition_candidate
                    .install_control_lease_revocation_barrier(
                        &transition,
                        Some(adoption.clone()),
                        ManifoldBrokerControlLeaseRevocationBarrierState::Converged,
                    )
                    .is_err()
                {
                    return Some(
                        ManifoldBrokerControlLeaseLifecycleRejectionReason::
                            AuthorityCapacityExhausted,
                    );
                }
                let receipt = lifecycle_receipt(
                    &transition_candidate.provider_epoch_id,
                    transition_candidate.adapter.config(),
                    request,
                    Some(lifecycle_use.clone()),
                    ManifoldBrokerControlLeaseLifecycleOutcome::AcceptedAndAdopted,
                    Some(transition),
                    Some(adoption),
                    None,
                );
                transition_candidate
                    .control_lease_lifecycle_receipts
                    .push(receipt);
                transition_candidate.evidence()
            }
            Ok(adoption) => {
                if consumed_candidate
                    .install_control_lease_revocation_barrier(
                        &transition,
                        None,
                        ManifoldBrokerControlLeaseRevocationBarrierState::PendingHostConvergence,
                    )
                    .is_err()
                {
                    return Some(
                        ManifoldBrokerControlLeaseLifecycleRejectionReason::
                            AuthorityCapacityExhausted,
                    );
                }
                let receipt = lifecycle_receipt(
                    &consumed_candidate.provider_epoch_id,
                    consumed_candidate.adapter.config(),
                    request,
                    Some(lifecycle_use.clone()),
                    ManifoldBrokerControlLeaseLifecycleOutcome::
                        CompositionFailedAfterPermitConsumption,
                    Some(transition),
                    Some(adoption),
                    Some(
                        ManifoldBrokerControlLeaseLifecycleRejectionReason::
                            OwnerHostCompositionFailed,
                    ),
                );
                consumed_candidate
                    .control_lease_lifecycle_receipts
                    .push(receipt);
                consumed_candidate.evidence()
            }
            Err(_) => {
                if consumed_candidate
                    .install_control_lease_revocation_barrier(
                        &transition,
                        None,
                        ManifoldBrokerControlLeaseRevocationBarrierState::PendingHostConvergence,
                    )
                    .is_err()
                {
                    return Some(
                        ManifoldBrokerControlLeaseLifecycleRejectionReason::
                            AuthorityCapacityExhausted,
                    );
                }
                let receipt = lifecycle_receipt(
                    &consumed_candidate.provider_epoch_id,
                    consumed_candidate.adapter.config(),
                    request,
                    Some(lifecycle_use.clone()),
                    ManifoldBrokerControlLeaseLifecycleOutcome::
                        CompositionFailedAfterPermitConsumption,
                    Some(transition),
                    None,
                    Some(
                        ManifoldBrokerControlLeaseLifecycleRejectionReason::
                            OwnerHostCompositionFailed,
                    ),
                );
                consumed_candidate
                    .control_lease_lifecycle_receipts
                    .push(receipt);
                consumed_candidate.evidence()
            }
        };
        validate_runtime_evidence_size(&evidence)
            .err()
            .map(|_| ManifoldBrokerControlLeaseLifecycleRejectionReason::AuthorityCapacityExhausted)
    }

    fn cleanup_reserve_preview_rejection(
        &self,
        request: &ManifoldBrokerControlLeaseLifecycleRequest,
        recorded_clock: &ManifoldClockSnapshot,
        evidence_refs: &[DottedId],
        lifecycle_use: &ManifoldBrokerControlLeaseLifecycleUse,
    ) -> Option<ManifoldBrokerControlLeaseLifecycleRejectionReason> {
        let cleanup_operation = matches!(
            request.operation.kind(),
            ManifoldBrokerControlLeaseLifecycleOperationKind::Release
                | ManifoldBrokerControlLeaseLifecycleOperationKind::Revocation
                | ManifoldBrokerControlLeaseLifecycleOperationKind::Expiry
        );
        let reserve_active = self.control_lease_lifecycle_receipts.len()
            >= MAX_BROKER_CONTROL_LEASE_TRANSITIONS
                .saturating_sub(BROKER_CONTROL_LEASE_CLEANUP_TRANSITION_RESERVE)
            || self.consumed_bounded_use_ids.len()
                >= MAX_BROKER_BOUNDED_USES
                    .saturating_sub(BROKER_CONTROL_LEASE_CLEANUP_TRANSITION_RESERVE)
            || self.control_lease_authority.evidence().transitions.len()
                >= MAX_BROKER_CONTROL_LEASE_TRANSITIONS
                    .saturating_sub(BROKER_CONTROL_LEASE_CLEANUP_TRANSITION_RESERVE);
        if !cleanup_operation || !reserve_active {
            return None;
        }
        let Ok(mut preview) = self.staged_copy() else {
            return Some(
                ManifoldBrokerControlLeaseLifecycleRejectionReason::AuthorityCapacityExhausted,
            );
        };
        let transition = match preview.apply_control_lease_operation(
            &request.operation,
            &lifecycle_use.bounded_use.identity,
            recorded_clock.clone(),
            evidence_refs.to_vec(),
        ) {
            Ok(transition) if control_lease_transition_applied(&transition) => transition,
            Ok(_) => {
                return Some(
                    ManifoldBrokerControlLeaseLifecycleRejectionReason::AuthorityLineageInvalid,
                );
            }
            Err(error) => return Some(control_lease_authority_rejection(&error)),
        };
        let adoption_request = control_lease_adoption_request(
            preview.adapter.host_snapshot().authority_revision,
            &transition,
        );
        match preview
            .adapter
            .apply_control_lease_adoption(&adoption_request, &preview.control_lease_authority)
        {
            Ok(receipt) if receipt.applied => None,
            Ok(_) | Err(_) => {
                Some(ManifoldBrokerControlLeaseLifecycleRejectionReason::OwnerHostCompositionFailed)
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn apply_control_lease_operation(
        &mut self,
        operation: &ManifoldBrokerControlLeaseLifecycleOperation,
        identity: &ManifoldClientIdentity,
        recorded_clock: ManifoldClockSnapshot,
        evidence_refs: Vec<DottedId>,
    ) -> Result<ManifoldBrokerControlLeaseTransition, ManifoldBrokerControlLeaseAuthorityError>
    {
        match operation {
            ManifoldBrokerControlLeaseLifecycleOperation::Issue {
                request_id,
                expected_authority_revision,
                scope,
                requested_ttl_ms,
                required_capability,
                safety_class,
            } => self.control_lease_authority.issue_control_lease(
                ManifoldControlLeaseRequest {
                    schema_id: schema_id("rusty.manifold.command.lease_request.v1"),
                    request_id: request_id.clone(),
                    holder_id: identity.client_id.clone(),
                    scope: scope.clone(),
                    expected_revision: *expected_authority_revision,
                    requested_ttl_ms: *requested_ttl_ms,
                    required_capability: required_capability.clone(),
                    safety_class: *safety_class,
                },
                recorded_clock,
                evidence_refs,
            ),
            ManifoldBrokerControlLeaseLifecycleOperation::Renewal {
                request_id,
                lease_id,
                expected_authority_revision,
                requested_ttl_ms,
                renewal_reason,
                requested_at_ms,
            } => {
                let lease = self
                    .control_lease_authority
                    .authority_snapshot()
                    .active_leases
                    .iter()
                    .find(|lease| &lease.lease_id == lease_id)
                    .ok_or(ManifoldBrokerControlLeaseAuthorityError::UnrelatedLease)?;
                self.control_lease_authority.renew_control_lease(
                    ManifoldControlLeaseRenewalRequest {
                        schema_id: schema_id("rusty.manifold.command.lease_renewal_request.v1"),
                        request_id: request_id.clone(),
                        lease_id: lease_id.clone(),
                        holder_id: identity.client_id.clone(),
                        expected_authority_revision: *expected_authority_revision,
                        scope: lease.scope.clone(),
                        requested_ttl_ms: *requested_ttl_ms,
                        renewal_reason: renewal_reason.clone(),
                        requested_at_ms: *requested_at_ms,
                    },
                    recorded_clock,
                    evidence_refs,
                )
            }
            ManifoldBrokerControlLeaseLifecycleOperation::Release {
                request_id,
                lease_id,
                expected_authority_revision,
                release_reason,
                requested_at_ms,
            } => {
                let lease = self
                    .control_lease_authority
                    .authority_snapshot()
                    .active_leases
                    .iter()
                    .find(|lease| &lease.lease_id == lease_id)
                    .ok_or(ManifoldBrokerControlLeaseAuthorityError::UnrelatedLease)?;
                self.control_lease_authority.release_control_lease(
                    ManifoldControlLeaseReleaseRequest {
                        schema_id: schema_id("rusty.manifold.command.lease_release_request.v1"),
                        request_id: request_id.clone(),
                        lease_id: lease_id.clone(),
                        holder_id: identity.client_id.clone(),
                        expected_authority_revision: *expected_authority_revision,
                        scope: lease.scope.clone(),
                        release_reason: release_reason.clone(),
                        requested_at_ms: *requested_at_ms,
                    },
                    recorded_clock,
                    evidence_refs,
                )
            }
            ManifoldBrokerControlLeaseLifecycleOperation::Revocation {
                request_id,
                lease_id,
                expected_authority_revision,
                revocation_reason,
                requested_at_ms,
            } => {
                let authority = self.control_lease_authority.authority_snapshot();
                let lease = authority
                    .active_leases
                    .iter()
                    .find(|lease| &lease.lease_id == lease_id)
                    .ok_or(ManifoldBrokerControlLeaseAuthorityError::UnrelatedLease)?;
                self.control_lease_authority.revoke_control_lease(
                    ManifoldControlLeaseRevocationRequest {
                        schema_id: schema_id("rusty.manifold.command.lease_revocation_request.v1"),
                        request_id: request_id.clone(),
                        authority_id: authority.authority_id.clone(),
                        lease_id: lease_id.clone(),
                        expected_authority_revision: *expected_authority_revision,
                        scope: lease.scope.clone(),
                        revocation_reason: revocation_reason.clone(),
                        requested_at_ms: *requested_at_ms,
                    },
                    recorded_clock,
                    evidence_refs,
                )
            }
            ManifoldBrokerControlLeaseLifecycleOperation::Expiry {
                request_id,
                lease_ids,
                expected_authority_revision,
                sweep_reason,
                requested_at_ms,
            } => self.control_lease_authority.expire_control_leases(
                ManifoldAuthorityExpirySweepRequest {
                    schema_id: schema_id("rusty.manifold.authority.expiry_sweep_request.v1"),
                    request_id: request_id.clone(),
                    requester_id: identity.client_id.clone(),
                    expected_authority_revision: *expected_authority_revision,
                    expected_registry_revision: self
                        .control_lease_authority
                        .authority_snapshot()
                        .stream_registry
                        .registry_revision,
                    sweep_reason: sweep_reason.clone(),
                    requested_at_ms: *requested_at_ms,
                },
                lease_ids,
                recorded_clock,
                evidence_refs,
            ),
        }
    }

    fn install_control_lease_revocation_barrier(
        &mut self,
        transition: &ManifoldBrokerControlLeaseTransition,
        host_adoption: Option<ManifoldRuntimeControlLeaseAdoptionReceipt>,
        state: ManifoldBrokerControlLeaseRevocationBarrierState,
    ) -> Result<(), ManifoldBrokerRuntimeStateError> {
        let ManifoldBrokerControlLeaseTransitionApplication::Revocation(application) =
            &transition.application
        else {
            return Err(ManifoldBrokerRuntimeStateError::InvalidEvidence(
                "revocation_barrier_transition_kind",
            ));
        };
        let lease_id = application.lease_id.clone();
        if self
            .control_lease_revocation_barriers
            .contains_key(&lease_id)
        {
            return Err(ManifoldBrokerRuntimeStateError::InvalidEvidence(
                "revocation_barrier_replay",
            ));
        }
        let lifecycle_request_id = application.review.audit_event.request.request_id.clone();
        let application_id = application.application_id.clone();
        let invalidated = self
            .pending_control_lease_lifecycle_uses
            .iter()
            .filter(|(_, use_)| {
                use_.lease_id.as_ref() == Some(&lease_id)
                    || use_.expiry_lease_ids.contains(&lease_id)
            })
            .map(|(use_id, _)| use_id.clone())
            .collect::<Vec<_>>();
        if self
            .control_lease_revocation_use_invalidations
            .len()
            .saturating_add(invalidated.len())
            > MAX_BROKER_BOUNDED_USES
            || self.control_lease_revocation_barriers.len() >= MAX_BROKER_CONTROL_LEASE_TRANSITIONS
        {
            return Err(ManifoldBrokerRuntimeStateError::InvalidEvidence(
                "revocation_barrier_capacity",
            ));
        }
        for use_id in &invalidated {
            self.pending_control_lease_lifecycle_uses.remove(use_id);
            self.invalidated_control_lease_lifecycle_use_ids
                .insert(use_id.clone());
            self.consumed_bounded_use_ids.insert(use_id.clone());
            self.control_lease_revocation_use_invalidations.insert(
                use_id.clone(),
                ManifoldBrokerControlLeaseRevocationUseInvalidation {
                    schema_id: schema_id(BROKER_CONTROL_LEASE_REVOCATION_USE_INVALIDATION_SCHEMA),
                    admission_use_request_id: use_id.clone(),
                    revocation_lifecycle_request_id: lifecycle_request_id.clone(),
                    revocation_application_id: application_id.clone(),
                    lease_id: lease_id.clone(),
                },
            );
        }
        let barrier = ManifoldBrokerControlLeaseRevocationBarrier {
            schema_id: schema_id(BROKER_CONTROL_LEASE_REVOCATION_BARRIER_SCHEMA),
            barrier_id: control_lease_revocation_barrier_id(&application_id),
            provider_epoch_id: self.provider_epoch_id.clone(),
            lifecycle_request_id,
            revocation_application_id: application_id,
            lease_id: lease_id.clone(),
            authority_transition: transition.clone(),
            host_adoption,
            invalidated_lifecycle_use_ids: invalidated,
            state,
        };
        self.control_lease_revocation_barriers
            .insert(lease_id, barrier);
        Ok(())
    }

    fn staged_copy(&self) -> Result<Self, ManifoldBrokerRuntimeStateError> {
        let evidence = self.evidence();
        let control_lease_authority =
            ManifoldBrokerControlLeaseAuthority::refresh_from_v2_evidence(
                evidence.control_lease_authority.clone(),
                evidence
                    .control_lease_authority
                    .current_authority_snapshot
                    .clone(),
                evidence.control_lease_authority.current_clock.clone(),
            )
            .map_err(ManifoldBrokerRuntimeStateError::ControlLeaseAuthority)?;
        Self::restore_from_caller_attested_exclusive_evidence(
            self.adapter.clone(),
            control_lease_authority,
            evidence,
        )
    }
}

const fn transition_kind(
    kind: ManifoldBrokerControlLeaseLifecycleOperationKind,
) -> ManifoldBrokerControlLeaseTransitionKind {
    match kind {
        ManifoldBrokerControlLeaseLifecycleOperationKind::Issue => {
            ManifoldBrokerControlLeaseTransitionKind::Issue
        }
        ManifoldBrokerControlLeaseLifecycleOperationKind::Renewal => {
            ManifoldBrokerControlLeaseTransitionKind::Renewal
        }
        ManifoldBrokerControlLeaseLifecycleOperationKind::Release => {
            ManifoldBrokerControlLeaseTransitionKind::Release
        }
        ManifoldBrokerControlLeaseLifecycleOperationKind::Revocation => {
            ManifoldBrokerControlLeaseTransitionKind::Revocation
        }
        ManifoldBrokerControlLeaseLifecycleOperationKind::Expiry => {
            ManifoldBrokerControlLeaseTransitionKind::Expiry
        }
    }
}

fn control_lease_authority_rejection(
    error: &ManifoldBrokerControlLeaseAuthorityError,
) -> ManifoldBrokerControlLeaseLifecycleRejectionReason {
    match error {
        ManifoldBrokerControlLeaseAuthorityError::TransitionReplay => {
            ManifoldBrokerControlLeaseLifecycleRejectionReason::ReplayedLifecycleRequest
        }
        ManifoldBrokerControlLeaseAuthorityError::UnrelatedLease => {
            ManifoldBrokerControlLeaseLifecycleRejectionReason::UnrelatedLease
        }
        ManifoldBrokerControlLeaseAuthorityError::UnsupportedExpiryDelta => {
            ManifoldBrokerControlLeaseLifecycleRejectionReason::UnsupportedAuthorityExpiryDelta
        }
        ManifoldBrokerControlLeaseAuthorityError::InvalidClock
        | ManifoldBrokerControlLeaseAuthorityError::ExpiredLease
        | ManifoldBrokerControlLeaseAuthorityError::ClockLineageMismatch
        | ManifoldBrokerControlLeaseAuthorityError::ClockRegression => {
            ManifoldBrokerControlLeaseLifecycleRejectionReason::InvalidAuthorityClock
        }
        ManifoldBrokerControlLeaseAuthorityError::CleanupCapacityReserved => {
            ManifoldBrokerControlLeaseLifecycleRejectionReason::CleanupCapacityReserved
        }
        ManifoldBrokerControlLeaseAuthorityError::CapacityExceeded
        | ManifoldBrokerControlLeaseAuthorityError::TransitionCapacityExceeded
        | ManifoldBrokerControlLeaseAuthorityError::EvidenceTooLarge => {
            ManifoldBrokerControlLeaseLifecycleRejectionReason::AuthorityCapacityExhausted
        }
        ManifoldBrokerControlLeaseAuthorityError::SchemaMismatch
        | ManifoldBrokerControlLeaseAuthorityError::DuplicateLeaseId
        | ManifoldBrokerControlLeaseAuthorityError::TransitionLineage
        | ManifoldBrokerControlLeaseAuthorityError::Projection(_)
        | ManifoldBrokerControlLeaseAuthorityError::AuthorityRegression
        | ManifoldBrokerControlLeaseAuthorityError::HostLeaseSetMismatch => {
            ManifoldBrokerControlLeaseLifecycleRejectionReason::AuthorityLineageInvalid
        }
    }
}

fn lifecycle_authorization_receipt(
    provider_epoch_id: &DottedId,
    lifecycle_request_id: &DottedId,
    lifecycle_request_sha256: String,
    admission_receipt: Option<ManifoldAdmissionReceipt>,
    lifecycle_use: Option<ManifoldBrokerControlLeaseLifecycleUse>,
    rejection_reason: Option<ManifoldBrokerControlLeaseLifecycleRejectionReason>,
) -> ManifoldBrokerControlLeaseLifecycleAuthorizationReceipt {
    let applied = lifecycle_use.is_some() && rejection_reason.is_none();
    ManifoldBrokerControlLeaseLifecycleAuthorizationReceipt {
        schema_id: schema_id(BROKER_CONTROL_LEASE_LIFECYCLE_AUTHORIZATION_RECEIPT_SCHEMA),
        provider_epoch_id: provider_epoch_id.clone(),
        lifecycle_request_id: lifecycle_request_id.clone(),
        lifecycle_request_sha256,
        admission_receipt,
        lifecycle_use,
        rejection_reason,
        applied,
    }
}

#[allow(clippy::too_many_arguments)]
fn lifecycle_receipt(
    provider_epoch_id: &DottedId,
    config: &ManifoldBrokerAdapterConfig,
    request: &ManifoldBrokerControlLeaseLifecycleRequest,
    lifecycle_use: Option<ManifoldBrokerControlLeaseLifecycleUse>,
    outcome: ManifoldBrokerControlLeaseLifecycleOutcome,
    authority_transition: Option<ManifoldBrokerControlLeaseTransition>,
    host_adoption: Option<rusty_manifold_runtime_host::ManifoldRuntimeControlLeaseAdoptionReceipt>,
    rejection_reason: Option<ManifoldBrokerControlLeaseLifecycleRejectionReason>,
) -> ManifoldBrokerControlLeaseLifecycleReceipt {
    let admission_use_consumed = lifecycle_use.is_some();
    let applied = outcome == ManifoldBrokerControlLeaseLifecycleOutcome::AcceptedAndAdopted
        && authority_transition
            .as_ref()
            .is_some_and(control_lease_transition_applied)
        && host_adoption
            .as_ref()
            .is_some_and(|receipt| receipt.applied)
        && rejection_reason.is_none();
    ManifoldBrokerControlLeaseLifecycleReceipt {
        schema_id: schema_id(BROKER_CONTROL_LEASE_LIFECYCLE_RECEIPT_SCHEMA),
        provider_epoch_id: provider_epoch_id.clone(),
        adapter_id: config.adapter_id.clone(),
        mode: config.mode.clone(),
        product_lock_id: config.product_lock_id.clone(),
        product_lock_sha256: config.product_lock_sha256.clone(),
        lifecycle_request_id: request.operation.request_id().clone(),
        lifecycle_request_sha256: control_lease_lifecycle_request_sha256(request),
        operation_kind: request.operation.kind(),
        admission_use_consumed,
        lifecycle_use,
        outcome,
        authority_transition,
        host_adoption,
        rejection_reason,
        applied,
    }
}

#[allow(clippy::too_many_arguments)]
fn revocation_recovery_receipt(
    provider_epoch_id: &DottedId,
    request: &ManifoldBrokerControlLeaseRevocationRecoveryRequest,
    barrier: Option<&ManifoldBrokerControlLeaseRevocationBarrier>,
    prior_owner_revision: Revision,
    prior_host_revision: Revision,
    authority_transition: Option<ManifoldBrokerControlLeaseTransition>,
    host_adoption: Option<ManifoldRuntimeControlLeaseAdoptionReceipt>,
    rejection_reason: Option<ManifoldBrokerControlLeaseLifecycleRejectionReason>,
) -> ManifoldBrokerControlLeaseRevocationRecoveryReceipt {
    let applied = barrier.is_some_and(|barrier| {
        barrier.state == ManifoldBrokerControlLeaseRevocationBarrierState::Converged
    }) && authority_transition.is_some()
        && host_adoption
            .as_ref()
            .is_some_and(|adoption| adoption.applied)
        && rejection_reason.is_none();
    ManifoldBrokerControlLeaseRevocationRecoveryReceipt {
        schema_id: schema_id(BROKER_CONTROL_LEASE_REVOCATION_RECOVERY_RECEIPT_SCHEMA),
        provider_epoch_id: provider_epoch_id.clone(),
        recovery_id: request.recovery_id.clone(),
        barrier_id: request.barrier_id.clone(),
        lifecycle_request_id: barrier.map_or_else(
            || request.barrier_id.clone(),
            |value| value.lifecycle_request_id.clone(),
        ),
        revocation_application_id: barrier.map_or_else(
            || request.barrier_id.clone(),
            |value| value.revocation_application_id.clone(),
        ),
        lease_id: barrier.map_or_else(
            || request.barrier_id.clone(),
            |value| value.lease_id.clone(),
        ),
        prior_control_lease_authority_revision: prior_owner_revision,
        resulting_control_lease_authority_revision: if applied {
            authority_transition
                .as_ref()
                .and_then(|transition| transition.application.applied_snapshot())
                .map_or(prior_owner_revision, |snapshot| snapshot.authority_revision)
        } else {
            prior_owner_revision
        },
        prior_host_authority_revision: prior_host_revision,
        resulting_host_authority_revision: if applied {
            host_adoption
                .as_ref()
                .map_or(prior_host_revision, |adoption| {
                    adoption.resulting_host_authority_revision
                })
        } else {
            prior_host_revision
        },
        authority_transition,
        host_adoption,
        applied,
        rejection_reason,
    }
}

fn control_lease_transition_applied(transition: &ManifoldBrokerControlLeaseTransition) -> bool {
    match &transition.application {
        ManifoldBrokerControlLeaseTransitionApplication::Issue(application) => {
            application.applied_snapshot.is_some()
        }
        ManifoldBrokerControlLeaseTransitionApplication::Renewal(application) => {
            application.applied_snapshot.is_some()
        }
        ManifoldBrokerControlLeaseTransitionApplication::Release(application) => {
            application.applied_snapshot.is_some()
        }
        ManifoldBrokerControlLeaseTransitionApplication::Revocation(application) => {
            application.applied_snapshot.is_some()
        }
        ManifoldBrokerControlLeaseTransitionApplication::Expiry(application) => {
            application.applied_snapshot.is_some()
        }
    }
}

fn control_lease_adoption_request(
    expected_host_authority_revision: Revision,
    transition: &ManifoldBrokerControlLeaseTransition,
) -> ManifoldRuntimeControlLeaseAdoptionRequest {
    let application = match &transition.application {
        ManifoldBrokerControlLeaseTransitionApplication::Issue(application) => {
            ManifoldRuntimeControlLeaseAuthorityApplication::Issue(application.clone())
        }
        ManifoldBrokerControlLeaseTransitionApplication::Renewal(application) => {
            ManifoldRuntimeControlLeaseAuthorityApplication::Renewal(application.clone())
        }
        ManifoldBrokerControlLeaseTransitionApplication::Release(application) => {
            ManifoldRuntimeControlLeaseAuthorityApplication::Release(application.clone())
        }
        ManifoldBrokerControlLeaseTransitionApplication::Revocation(application) => {
            ManifoldRuntimeControlLeaseAuthorityApplication::Revocation(application.clone())
        }
        ManifoldBrokerControlLeaseTransitionApplication::Expiry(application) => {
            ManifoldRuntimeControlLeaseAuthorityApplication::Expiry(application.clone())
        }
    };
    ManifoldRuntimeControlLeaseAdoptionRequest {
        schema_id: schema_id(HOST_CONTROL_LEASE_ADOPTION_REQUEST_SCHEMA),
        adoption_id: DottedId::new(format!("adoption.{}", transition.application.request_id()))
            .expect("validated lifecycle request id derives a valid adoption id"),
        expected_host_authority_revision,
        prior_authority_snapshot: transition.prior_authority_snapshot.clone(),
        application,
    }
}

fn control_lease_revocation_barrier_id(application_id: &DottedId) -> DottedId {
    DottedId::new(format!("revocation_barrier.{application_id}"))
        .expect("validated application id derives a valid barrier id")
}

fn product_requires_peer_runtime_host_acknowledgement(features: &[ManifoldBrokerFeature]) -> bool {
    features.iter().any(|feature| {
        matches!(
            feature,
            ManifoldBrokerFeature::MediaSession
                | ManifoldBrokerFeature::CameraMedia
                | ManifoldBrokerFeature::DirectP2p
                | ManifoldBrokerFeature::BleRendezvous
        )
    })
}

fn valid_sha256_binding(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn revocation_consumer_acknowledgements_close(
    acknowledgements: &[ManifoldBrokerControlLeaseRevocationConsumerAcknowledgement],
    provider_epoch_id: &DottedId,
    barriers: &[ManifoldBrokerControlLeaseRevocationBarrier],
    product_features: &[ManifoldBrokerFeature],
) -> bool {
    let peer_required = product_requires_peer_runtime_host_acknowledgement(product_features);
    let mut barrier_consumers = BTreeSet::new();
    acknowledgements.iter().all(|acknowledgement| {
        let consumer_required = match acknowledgement.consumer_kind {
            ManifoldBrokerControlLeaseRevocationConsumerKind::PeerRuntimeHost => peer_required,
        };
        consumer_required
            && acknowledgement.schema_id.as_str()
                == BROKER_CONTROL_LEASE_REVOCATION_CONSUMER_ACKNOWLEDGEMENT_SCHEMA
            && &acknowledgement.provider_epoch_id == provider_epoch_id
            && valid_sha256_binding(&acknowledgement.consumer_convergence_receipt_sha256)
            && valid_sha256_binding(&acknowledgement.terminal_cleanup_receipt_sha256)
            && barrier_consumers.insert((
                acknowledgement.barrier_id.clone(),
                acknowledgement.consumer_kind,
            ))
            && barriers.iter().any(|barrier| {
                barrier.state == ManifoldBrokerControlLeaseRevocationBarrierState::Converged
                    && barrier.barrier_id == acknowledgement.barrier_id
                    && barrier.revocation_application_id
                        == acknowledgement.revocation_application_id
                    && barrier.lease_id == acknowledgement.lease_id
            })
    })
}

fn committed_mutation_receipts_close(
    receipts: &[ManifoldBrokerMutationReceipt],
    provider_epoch_id: &DottedId,
    config: &ManifoldBrokerAdapterConfig,
    host_snapshot: &ManifoldRuntimeHostSnapshot,
    consumed_use_ids: &BTreeSet<DottedId>,
    authorized_uses: &BTreeMap<DottedId, ManifoldBrokerBoundedUse>,
    admission_snapshot: &ManifoldAdmissionSnapshot,
    admission_token_history: &BTreeMap<DottedId, ManifoldAdmissionToken>,
) -> bool {
    let mut retained_use_ids = BTreeSet::new();
    receipts.iter().all(|receipt| {
        let (Some(bounded_use), Some(adapter_receipt)) =
            (&receipt.bounded_use, &receipt.adapter_receipt)
        else {
            return false;
        };
        let dispatch = &adapter_receipt.dispatch;
        let application = &adapter_receipt.application;
        let command_selected = host_snapshot
            .commands
            .iter()
            .any(|descriptor| descriptor.command_id == dispatch.command_id);
        let audit_closes = host_snapshot.audit_events.iter().any(|event| {
            event.event_kind == ManifoldRuntimeAuditKind::CommandApplication
                && event.source_id == application.request_id
                && event.prior_authority_revision == application.prior_authority_revision
                && event.resulting_authority_revision == application.resulting_authority_revision
                && event.applied == application.applied
                && event.rejection_reason == application.rejection_reason
        });
        receipt.schema_id.as_str() == BROKER_MUTATION_RECEIPT_SCHEMA
            && &receipt.provider_epoch_id == provider_epoch_id
            && receipt.admission_use_request_id == bounded_use.admission_use_request_id
            && retained_use_ids.insert(receipt.admission_use_request_id.clone())
            && consumed_use_ids.contains(&receipt.admission_use_request_id)
            && authorized_uses.get(&receipt.admission_use_request_id) == Some(bounded_use)
            && bounded_use_admission_revision_closes(
                bounded_use,
                admission_snapshot,
                admission_token_history,
                true,
            )
            && bounded_use.schema_id.as_str() == BROKER_BOUNDED_USE_SCHEMA
            && bounded_use.capability_id == command_capability(&dispatch.command_id)
            && !receipt.local_acceptance_rules
            && receipt.authority_owner_id.as_str() == RUNTIME_HOST_AUTHORITY_OWNER
            && receipt.command_selected == command_selected
            && receipt.admission_applied
            && receipt.admission_rejection_reason.is_none()
            && receipt.applied == application.applied
            && adapter_receipt.schema_id.as_str() == crate::BROKER_ADAPTER_RECEIPT_SCHEMA
            && adapter_receipt.adapter_id == config.adapter_id
            && adapter_receipt.mode == config.mode
            && adapter_receipt.product_lock_id == config.product_lock_id
            && adapter_receipt.product_lock_fingerprint == config.product_lock_fingerprint
            && adapter_receipt.product_lock_sha256 == config.product_lock_sha256
            && adapter_receipt.authority_host_id == config.authority_host_id
            && adapter_receipt.authority_owner_id == config.authority_owner_id
            && dispatch.schema_id.as_str() == HOST_DISPATCH_RECEIPT_SCHEMA
            && dispatch.authority_host_id == host_snapshot.host_id
            && application.schema_id.as_str() == HOST_APPLICATION_RECEIPT_SCHEMA
            && application.authority_host_id == host_snapshot.host_id
            && application.dispatch_id == dispatch.dispatch_id
            && application.request_id == dispatch.request_id
            && application.params_digest == dispatch.params_digest
            && audit_closes
    })
}

fn committed_capability_use_receipts_close(
    receipts: &[ManifoldBrokerCapabilityUseReceipt],
    provider_epoch_id: &DottedId,
    host_snapshot: &ManifoldRuntimeHostSnapshot,
    consumed_use_ids: &BTreeSet<DottedId>,
    authorized_uses: &BTreeMap<DottedId, ManifoldBrokerBoundedUse>,
    admission_snapshot: &ManifoldAdmissionSnapshot,
    admission_token_history: &BTreeMap<DottedId, ManifoldAdmissionToken>,
) -> bool {
    let command_capabilities = host_snapshot
        .commands
        .iter()
        .map(|descriptor| command_capability(&descriptor.command_id))
        .collect::<BTreeSet<_>>();
    let mut retained_use_ids = BTreeSet::new();
    receipts.iter().all(|receipt| {
        let Some(bounded_use) = receipt.bounded_use.as_ref() else {
            return false;
        };
        receipt.schema_id.as_str() == BROKER_CAPABILITY_USE_RECEIPT_SCHEMA
            && &receipt.provider_epoch_id == provider_epoch_id
            && receipt.applied
            && receipt.rejection_reason.is_none()
            && retained_use_ids.insert(bounded_use.admission_use_request_id.clone())
            && consumed_use_ids.contains(&bounded_use.admission_use_request_id)
            && authorized_uses.get(&bounded_use.admission_use_request_id) == Some(bounded_use)
            && !command_capabilities.contains(&bounded_use.capability_id)
            && bounded_use_admission_revision_closes(
                bounded_use,
                admission_snapshot,
                admission_token_history,
                true,
            )
    })
}

fn bounded_use_admission_revision_closes(
    use_: &ManifoldBrokerBoundedUse,
    admission_snapshot: &ManifoldAdmissionSnapshot,
    admission_token_history: &BTreeMap<DottedId, ManifoldAdmissionToken>,
    require_exact_audit_binding: bool,
) -> bool {
    let exact_grant = admission_snapshot.grants.iter().any(|grant| {
        grant.grant_id == use_.admission_grant_id
            && grant.identity == use_.identity
            && grant.client_lock_id == use_.client_lock_id
            && grant.client_lock_fingerprint == use_.client_lock_fingerprint
            && grant.capabilities.contains(&use_.capability_id)
            && use_.expires_at_ms <= grant.expires_at_ms
    });
    let exact_token = admission_token_history
        .get(&use_.token_id)
        .is_some_and(|token| {
            token.token_id == use_.token_id
                && token.identity == use_.identity
                && token.grant_id == use_.admission_grant_id
                && token.client_lock_id == use_.client_lock_id
                && token.client_lock_fingerprint == use_.client_lock_fingerprint
                && token.capabilities.contains(&use_.capability_id)
                && use_.expires_at_ms <= token.expires_at_ms
                && (admission_snapshot
                    .active_tokens
                    .iter()
                    .any(|active| active == token)
                    || admission_snapshot
                        .revoked_token_ids
                        .contains(&token.token_id))
        });
    let exact_authorization_audit = admission_snapshot.audit_events.iter().any(|event| {
        let base_closes = event.operation == ManifoldAdmissionOperation::AuthorizeUse
            && event.request_id == use_.admission_use_request_id
            && event.applied
            && event.rejection_reason.is_none()
            && event.resulting_authority_revision == use_.admission_authority_revision
            && event.prior_authority_revision.next() == Some(use_.admission_authority_revision);
        if !base_closes {
            return false;
        }
        let Some(binding) = event.use_authorization.as_ref() else {
            return !require_exact_audit_binding;
        };
        let Some(history_token) = admission_token_history.get(&use_.token_id) else {
            return false;
        };
        binding.token == *history_token
            && binding.request.request_id == use_.admission_use_request_id
            && binding.request.token_id == use_.token_id
            && binding.request.identity == use_.identity
            && binding.request.capability_id == use_.capability_id
            && binding
                .request
                .expires_at_ms
                .min(binding.token.expires_at_ms)
                == use_.expires_at_ms
    });
    use_.schema_id.as_str() == BROKER_BOUNDED_USE_SCHEMA
        && exact_grant
        && exact_token
        && exact_authorization_audit
}

fn admission_token_history_entry_closes(
    token: &ManifoldAdmissionToken,
    admission_snapshot: &ManifoldAdmissionSnapshot,
) -> bool {
    let exact_grant = admission_snapshot.grants.iter().any(|grant| {
        grant.grant_id == token.grant_id
            && grant.identity == token.identity
            && grant.client_lock_id == token.client_lock_id
            && grant.client_lock_fingerprint == token.client_lock_fingerprint
            && token
                .capabilities
                .iter()
                .all(|capability| grant.capabilities.contains(capability))
            && token.expires_at_ms <= grant.expires_at_ms
    });
    let exact_issue_audit = admission_snapshot.audit_events.iter().any(|event| {
        event.operation == ManifoldAdmissionOperation::IssueToken
            && event.applied
            && event.rejection_reason.is_none()
            && event.resulting_authority_revision == token.issued_authority_revision
            && event.prior_authority_revision.next() == Some(token.issued_authority_revision)
    });
    token.schema_id.as_str() == rusty_manifold_admission::ADMISSION_TOKEN_SCHEMA
        && exact_grant
        && exact_issue_audit
        && (admission_snapshot
            .active_tokens
            .iter()
            .any(|active| active == token)
            || admission_snapshot
                .revoked_token_ids
                .contains(&token.token_id))
}

fn revocation_barriers_close(
    barriers: &[ManifoldBrokerControlLeaseRevocationBarrier],
    provider_epoch_id: &DottedId,
    authority_evidence: &ManifoldBrokerControlLeaseAuthorityEvidenceV2,
    host_snapshot: &ManifoldRuntimeHostSnapshot,
    invalidations: &BTreeMap<DottedId, ManifoldBrokerControlLeaseRevocationUseInvalidation>,
    lifecycle_receipts: &[ManifoldBrokerControlLeaseLifecycleReceipt],
    recovery_receipts: &[ManifoldBrokerControlLeaseRevocationRecoveryReceipt],
) -> bool {
    let mut lifecycle_request_ids = BTreeSet::new();
    let mut application_ids = BTreeSet::new();
    let barriers_close = barriers.iter().all(|barrier| {
        let ManifoldBrokerControlLeaseTransitionApplication::Revocation(application) =
            &barrier.authority_transition.application
        else {
            return false;
        };
        let Some(tombstone) = application.tombstone.as_ref() else {
            return false;
        };
        let expected_invalidated_ids = invalidations
            .values()
            .filter(|invalidation| {
                invalidation.lease_id == barrier.lease_id
                    && invalidation.revocation_lifecycle_request_id == barrier.lifecycle_request_id
                    && invalidation.revocation_application_id == barrier.revocation_application_id
            })
            .map(|invalidation| invalidation.admission_use_request_id.clone())
            .collect::<Vec<_>>();
        let matching_receipts = lifecycle_receipts
            .iter()
            .filter(|receipt| receipt.lifecycle_request_id == barrier.lifecycle_request_id)
            .collect::<Vec<_>>();
        let receipt_closes = matching_receipts.len() == 1
            && matching_receipts[0].operation_kind
                == ManifoldBrokerControlLeaseLifecycleOperationKind::Revocation
            && matching_receipts[0].authority_transition.as_ref()
                == Some(&barrier.authority_transition);
        let matching_recoveries = recovery_receipts
            .iter()
            .filter(|receipt| receipt.barrier_id == barrier.barrier_id)
            .collect::<Vec<_>>();
        let recovery_sequence_closes =
            matching_receipts.first().is_some_and(|receipt| {
                match receipt.outcome {
                ManifoldBrokerControlLeaseLifecycleOutcome::AcceptedAndAdopted => {
                    matching_recoveries.is_empty()
                }
                ManifoldBrokerControlLeaseLifecycleOutcome::
                    CompositionFailedAfterPermitConsumption => match barrier.state {
                        ManifoldBrokerControlLeaseRevocationBarrierState::
                            PendingHostConvergence => {
                            matching_recoveries.iter().all(|recovery| !recovery.applied)
                        }
                        ManifoldBrokerControlLeaseRevocationBarrierState::Converged => {
                            matching_recoveries
                                .last()
                                .is_some_and(|recovery| recovery.applied)
                                && matching_recoveries
                                    .iter()
                                    .filter(|recovery| recovery.applied)
                                    .count()
                                    == 1
                                && matching_recoveries[..matching_recoveries.len() - 1]
                                    .iter()
                                    .all(|recovery| !recovery.applied)
                        }
                    },
                ManifoldBrokerControlLeaseLifecycleOutcome::AuthorityRejected
                | ManifoldBrokerControlLeaseLifecycleOutcome::
                    UnsupportedAuthorityExpiryDelta
                | ManifoldBrokerControlLeaseLifecycleOutcome::PreflightRejected => false,
            }
            });
        let state_closes = match barrier.state {
            ManifoldBrokerControlLeaseRevocationBarrierState::PendingHostConvergence => {
                barrier.host_adoption.is_none()
                    && matching_recoveries.iter().all(|receipt| !receipt.applied)
                    && !authority_evidence
                        .transitions
                        .contains(&barrier.authority_transition)
                    && host_snapshot
                        .leases
                        .iter()
                        .any(|lease| lease.lease_id == barrier.lease_id)
                    && matching_receipts.first().is_some_and(|receipt| {
                        receipt.outcome
                            == ManifoldBrokerControlLeaseLifecycleOutcome::
                                CompositionFailedAfterPermitConsumption
                            && !receipt.applied
                    })
            }
            ManifoldBrokerControlLeaseRevocationBarrierState::Converged => {
                authority_evidence
                    .transitions
                    .contains(&barrier.authority_transition)
                    && barrier.host_adoption.as_ref().is_some_and(|adoption| {
                        control_lease_host_adoption_closes(
                            adoption,
                            &barrier.authority_transition,
                            host_snapshot,
                        )
                    })
                    && !host_snapshot
                        .leases
                        .iter()
                        .any(|lease| lease.lease_id == barrier.lease_id)
                    && authority_evidence
                        .current_authority_snapshot
                        .revoked_control_lease_tombstones
                        .contains(tombstone)
                    && (matching_receipts.first().is_some_and(|receipt| {
                        receipt.outcome
                            == ManifoldBrokerControlLeaseLifecycleOutcome::AcceptedAndAdopted
                            && receipt.applied
                            && receipt.host_adoption.as_ref() == barrier.host_adoption.as_ref()
                    }) || (matching_recoveries
                        .last()
                        .is_some_and(|receipt| receipt.applied)
                        && matching_recoveries
                            .last()
                            .and_then(|receipt| receipt.authority_transition.as_ref())
                            == Some(&barrier.authority_transition)
                        && matching_recoveries
                            .last()
                            .and_then(|receipt| receipt.host_adoption.as_ref())
                            == barrier.host_adoption.as_ref()))
            }
        };
        barrier.schema_id.as_str() == BROKER_CONTROL_LEASE_REVOCATION_BARRIER_SCHEMA
            && &barrier.provider_epoch_id == provider_epoch_id
            && barrier.barrier_id
                == control_lease_revocation_barrier_id(&application.application_id)
            && barrier.lifecycle_request_id
                == application.review.audit_event.request.request_id
            && barrier.revocation_application_id == application.application_id
            && barrier.lease_id == application.lease_id
            && application.outcome
                == rusty_manifold_model::
                    ManifoldControlLeaseRevocationAuthorityApplicationOutcome::
                    LeaseRevocationApplied
            && application
                .validate_against_snapshot(&barrier.authority_transition.prior_authority_snapshot)
                .is_ok()
            && barrier.invalidated_lifecycle_use_ids == expected_invalidated_ids
            && barrier
                .invalidated_lifecycle_use_ids
                .windows(2)
                .all(|pair| pair[0] < pair[1])
            && receipt_closes
            && recovery_sequence_closes
            && state_closes
            && lifecycle_request_ids.insert(barrier.lifecycle_request_id.clone())
            && application_ids.insert(barrier.revocation_application_id.clone())
    });
    let accepted_revocation_receipts = lifecycle_receipts
        .iter()
        .filter_map(|receipt| {
            let transition = receipt.authority_transition.as_ref()?;
            let ManifoldBrokerControlLeaseTransitionApplication::Revocation(application) =
                &transition.application
            else {
                return None;
            };
            control_lease_transition_applied(transition).then_some((
                receipt.lifecycle_request_id.clone(),
                application.application_id.clone(),
            ))
        })
        .collect::<BTreeSet<_>>();
    let mut recovery_ids = BTreeSet::new();
    let recoveries_close = recovery_receipts.iter().all(|receipt| {
        receipt.schema_id.as_str() == BROKER_CONTROL_LEASE_REVOCATION_RECOVERY_RECEIPT_SCHEMA
            && &receipt.provider_epoch_id == provider_epoch_id
            && recovery_ids.insert(receipt.recovery_id.clone())
            && barriers.iter().any(|barrier| {
                let expected_prior_owner_revision = barrier
                    .authority_transition
                    .prior_authority_snapshot
                    .authority_revision;
                let expected_resulting_owner_revision = barrier
                    .authority_transition
                    .application
                    .applied_snapshot()
                    .map(|snapshot| snapshot.authority_revision);
                let expected_prior_host_revision = barrier
                    .host_adoption
                    .as_ref()
                    .map_or(host_snapshot.authority_revision, |adoption| {
                        adoption.prior_host_authority_revision
                    });
                let rejected_host_adoption_closes =
                    receipt.host_adoption.as_ref().map_or(true, |adoption| {
                        adoption.schema_id.as_str() == HOST_CONTROL_LEASE_ADOPTION_RECEIPT_SCHEMA
                            && adoption.operation
                                == ManifoldRuntimeControlLeaseAdoptionOperation::Revocation
                            && adoption.manifold_application_id == barrier.revocation_application_id
                            && adoption.prior_manifold_authority_revision
                                == expected_prior_owner_revision
                            && Some(adoption.resulting_manifold_authority_revision)
                                == expected_resulting_owner_revision
                            && adoption.prior_host_authority_revision
                                == receipt.prior_host_authority_revision
                            && adoption.resulting_host_authority_revision
                                == receipt.prior_host_authority_revision
                            && !adoption.applied
                            && adoption.added_lease_ids.is_empty()
                            && adoption.renewed_lease_ids.is_empty()
                            && adoption.removed_lease_ids.is_empty()
                            && adoption.rejection_reason.is_some()
                    });
                let disposition_closes = if receipt.applied {
                    barrier.state == ManifoldBrokerControlLeaseRevocationBarrierState::Converged
                        && receipt.prior_control_lease_authority_revision
                            == expected_prior_owner_revision
                        && Some(receipt.resulting_control_lease_authority_revision)
                            == expected_resulting_owner_revision
                        && receipt.prior_host_authority_revision == expected_prior_host_revision
                        && barrier.host_adoption.as_ref().is_some_and(|adoption| {
                            receipt.resulting_host_authority_revision
                                == adoption.resulting_host_authority_revision
                        })
                        && receipt.authority_transition.as_ref()
                            == Some(&barrier.authority_transition)
                        && receipt.host_adoption.as_ref() == barrier.host_adoption.as_ref()
                        && receipt.rejection_reason.is_none()
                } else {
                    receipt.prior_control_lease_authority_revision == expected_prior_owner_revision
                        && receipt.resulting_control_lease_authority_revision
                            == receipt.prior_control_lease_authority_revision
                        && receipt.prior_host_authority_revision == expected_prior_host_revision
                        && receipt.resulting_host_authority_revision
                            == receipt.prior_host_authority_revision
                        && receipt
                            .authority_transition
                            .as_ref()
                            .map_or(true, |transition| {
                                transition == &barrier.authority_transition
                            })
                        && rejected_host_adoption_closes
                        && receipt.rejection_reason.is_some()
                };
                receipt.barrier_id == barrier.barrier_id
                    && receipt.lifecycle_request_id == barrier.lifecycle_request_id
                    && receipt.revocation_application_id == barrier.revocation_application_id
                    && receipt.lease_id == barrier.lease_id
                    && lifecycle_receipts.iter().any(|lifecycle| {
                        lifecycle.lifecycle_request_id == barrier.lifecycle_request_id
                            && lifecycle.outcome
                                == ManifoldBrokerControlLeaseLifecycleOutcome::
                                    CompositionFailedAfterPermitConsumption
                            && lifecycle.authority_transition.as_ref()
                                == Some(&barrier.authority_transition)
                    })
                    && disposition_closes
            })
    });
    barriers_close
        && recoveries_close
        && accepted_revocation_receipts.len() == barriers.len()
        && accepted_revocation_receipts
            .iter()
            .map(|(request_id, _)| request_id)
            .cloned()
            .collect::<BTreeSet<_>>()
            == lifecycle_request_ids
        && accepted_revocation_receipts
            .iter()
            .map(|(_, application_id)| application_id)
            .cloned()
            .collect::<BTreeSet<_>>()
            == application_ids
}

#[allow(clippy::too_many_lines)]
fn lifecycle_receipts_close(
    receipts: &[ManifoldBrokerControlLeaseLifecycleReceipt],
    provider_epoch_id: &DottedId,
    config: &ManifoldBrokerAdapterConfig,
    consumed_use_ids: &BTreeSet<DottedId>,
    authority_evidence: &ManifoldBrokerControlLeaseAuthorityEvidenceV2,
    host_snapshot: &ManifoldRuntimeHostSnapshot,
    admission_snapshot: &ManifoldAdmissionSnapshot,
    recovery_receipts: &[ManifoldBrokerControlLeaseRevocationRecoveryReceipt],
) -> bool {
    let mut request_ids = BTreeSet::new();
    let mut lifecycle_use_ids = BTreeSet::new();
    let mut accepted_adoption_ids = BTreeSet::new();
    let receipts_close = receipts.iter().all(|receipt| {
        let shape_closes = match receipt.outcome {
            ManifoldBrokerControlLeaseLifecycleOutcome::AcceptedAndAdopted => {
                receipt.applied
                    && receipt.admission_use_consumed
                    && receipt
                        .authority_transition
                        .as_ref()
                        .is_some_and(control_lease_transition_applied)
                    && receipt.host_adoption.as_ref().is_some_and(|value| value.applied)
                    && receipt.rejection_reason.is_none()
                    && receipt.authority_transition.as_ref().is_some_and(|transition| {
                        authority_evidence.transitions.contains(transition)
                    })
                    && receipt.authority_transition.as_ref().is_some_and(|transition| {
                        receipt.host_adoption.as_ref().is_some_and(|adoption| {
                            control_lease_host_adoption_closes(
                                adoption,
                                transition,
                                host_snapshot,
                            ) && accepted_adoption_ids.insert(adoption.adoption_id.clone())
                        })
                    })
            }
            ManifoldBrokerControlLeaseLifecycleOutcome::AuthorityRejected => {
                !receipt.applied
                    && receipt.admission_use_consumed
                    && receipt
                        .authority_transition
                        .as_ref()
                        .is_some_and(|transition| !control_lease_transition_applied(transition))
                    && receipt.host_adoption.is_none()
                    && receipt.authority_transition.as_ref().is_some_and(|transition| {
                        !authority_evidence.transitions.contains(transition)
                    })
            }
            ManifoldBrokerControlLeaseLifecycleOutcome::
                UnsupportedAuthorityExpiryDelta => {
                !receipt.applied
                    && receipt.admission_use_consumed
                    && receipt.authority_transition.is_none()
                    && receipt.host_adoption.is_none()
                    && receipt.rejection_reason
                        == Some(
                            ManifoldBrokerControlLeaseLifecycleRejectionReason::
                                UnsupportedAuthorityExpiryDelta,
                        )
            }
            ManifoldBrokerControlLeaseLifecycleOutcome::
                CompositionFailedAfterPermitConsumption => {
                let exact_applied_recovery_count = receipt
                    .authority_transition
                    .as_ref()
                    .map_or(0, |transition| {
                        recovery_receipts
                            .iter()
                            .filter(|recovery| {
                                recovery.applied
                                    && recovery.lifecycle_request_id
                                        == receipt.lifecycle_request_id
                                    && recovery.authority_transition.as_ref()
                                        == Some(transition)
                                    && recovery.host_adoption.as_ref().is_some_and(
                                        |adoption| {
                                            control_lease_host_adoption_closes(
                                                adoption,
                                                transition,
                                                host_snapshot,
                                            )
                                        },
                                    )
                            })
                            .count()
                    });
                !receipt.applied
                    && receipt.admission_use_consumed
                    && receipt.rejection_reason.is_some()
                    && receipt
                        .authority_transition
                        .as_ref()
                        .map_or(true, |transition| {
                            if authority_evidence.transitions.contains(transition) {
                                exact_applied_recovery_count == 1
                            } else {
                                exact_applied_recovery_count == 0
                            }
                        })
                    && receipt.host_adoption.as_ref().map_or(true, |adoption| {
                        !host_snapshot
                            .reviewed_control_lease_adoption_ids
                            .contains(&adoption.adoption_id)
                            || (exact_applied_recovery_count == 1 && !adoption.applied)
                    })
            }
            ManifoldBrokerControlLeaseLifecycleOutcome::PreflightRejected => false,
        };
        let use_closes = receipt.lifecycle_use.as_ref().is_some_and(|use_| {
            use_.schema_id.as_str() == BROKER_CONTROL_LEASE_LIFECYCLE_USE_SCHEMA
                && use_.bounded_use.schema_id.as_str() == BROKER_BOUNDED_USE_SCHEMA
                && use_.lifecycle_request_id == receipt.lifecycle_request_id
                && use_.lifecycle_request_sha256 == receipt.lifecycle_request_sha256
                && use_.operation_kind == receipt.operation_kind
                && use_.authorized_from_admission_authority_revision
                    < use_.bounded_use.admission_authority_revision
                && consumed_use_ids.contains(&use_.bounded_use.admission_use_request_id)
                && lifecycle_admission_revision_closes(use_, admission_snapshot)
                && lifecycle_use_ids.insert(use_.bounded_use.admission_use_request_id.clone())
        });
        let transition_closes = receipt
            .authority_transition
            .as_ref()
            .map_or(true, |transition| {
                let expiry_delta_closes = match &transition.application {
                    ManifoldBrokerControlLeaseTransitionApplication::Expiry(application) => {
                        let mut expired = application
                            .review
                            .expired_leases
                            .iter()
                            .map(|lease| lease.lease_id.clone())
                            .collect::<Vec<_>>();
                        expired.sort();
                        receipt
                            .lifecycle_use
                            .as_ref()
                            .is_some_and(|use_| use_.expiry_lease_ids == expired)
                    }
                    ManifoldBrokerControlLeaseTransitionApplication::Issue(_)
                    | ManifoldBrokerControlLeaseTransitionApplication::Renewal(_)
                    | ManifoldBrokerControlLeaseTransitionApplication::Release(_)
                    | ManifoldBrokerControlLeaseTransitionApplication::Revocation(_) => true,
                };
                transition.schema_id.as_str() == crate::BROKER_CONTROL_LEASE_TRANSITION_SCHEMA
                    && transition.application.request_id() == &receipt.lifecycle_request_id
                    && transition.application.kind() == transition_kind(receipt.operation_kind)
                    && expiry_delta_closes
                    && transition
                        .application
                        .validate_against_snapshot(&transition.prior_authority_snapshot)
                        .is_ok()
            });
        receipt.schema_id.as_str() == BROKER_CONTROL_LEASE_LIFECYCLE_RECEIPT_SCHEMA
            && &receipt.provider_epoch_id == provider_epoch_id
            && receipt.adapter_id == config.adapter_id
            && receipt.mode == config.mode
            && receipt.product_lock_id == config.product_lock_id
            && receipt.product_lock_sha256 == config.product_lock_sha256
            && receipt.lifecycle_request_sha256.len() == 71
            && receipt.lifecycle_request_sha256.starts_with("sha256:")
            && receipt.admission_use_consumed == receipt.lifecycle_use.is_some()
            && use_closes
            && transition_closes
            && shape_closes
            && request_ids.insert(receipt.lifecycle_request_id.clone())
    });
    receipts_close
        && authority_evidence.transitions.iter().all(|transition| {
            receipts
                .iter()
                .filter(|receipt| {
                    receipt.outcome
                        == ManifoldBrokerControlLeaseLifecycleOutcome::AcceptedAndAdopted
                        && receipt.applied
                        && receipt.authority_transition.as_ref() == Some(transition)
                })
                .count()
                .saturating_add(
                    recovery_receipts
                        .iter()
                        .filter(|receipt| {
                            receipt.applied
                                && receipt.authority_transition.as_ref() == Some(transition)
                        })
                        .count(),
                )
                == 1
        })
        && accepted_adoption_ids.len().saturating_add(
            recovery_receipts
                .iter()
                .filter(|receipt| receipt.applied)
                .count(),
        ) == authority_evidence.transitions.len()
}

#[allow(clippy::too_many_lines)]
fn control_lease_host_adoption_closes(
    adoption: &ManifoldRuntimeControlLeaseAdoptionReceipt,
    transition: &ManifoldBrokerControlLeaseTransition,
    host_snapshot: &ManifoldRuntimeHostSnapshot,
) -> bool {
    let (
        expected_operation,
        authority_id,
        application_id,
        prior_manifold_revision,
        resulting_manifold_revision,
        added_lease_ids,
        renewed_lease_ids,
        removed_lease_ids,
    ) = match &transition.application {
        ManifoldBrokerControlLeaseTransitionApplication::Issue(application) => (
            ManifoldRuntimeControlLeaseAdoptionOperation::Issue,
            &application.authority_id,
            &application.application_id,
            application.from_authority_revision,
            application
                .applied_snapshot
                .as_ref()
                .map_or(application.from_authority_revision, |snapshot| {
                    snapshot.authority_revision
                }),
            application
                .review
                .accepted
                .iter()
                .map(|lease| lease.lease_id.clone())
                .collect::<Vec<_>>(),
            Vec::new(),
            Vec::new(),
        ),
        ManifoldBrokerControlLeaseTransitionApplication::Renewal(application) => (
            ManifoldRuntimeControlLeaseAdoptionOperation::Renewal,
            &application.authority_id,
            &application.application_id,
            application.from_authority_revision,
            application
                .applied_snapshot
                .as_ref()
                .map_or(application.from_authority_revision, |snapshot| {
                    snapshot.authority_revision
                }),
            Vec::new(),
            application
                .review
                .renewed
                .iter()
                .map(|lease| lease.lease_id.clone())
                .collect::<Vec<_>>(),
            Vec::new(),
        ),
        ManifoldBrokerControlLeaseTransitionApplication::Release(application) => (
            ManifoldRuntimeControlLeaseAdoptionOperation::Release,
            &application.authority_id,
            &application.application_id,
            application.from_authority_revision,
            application
                .applied_snapshot
                .as_ref()
                .map_or(application.from_authority_revision, |snapshot| {
                    snapshot.authority_revision
                }),
            Vec::new(),
            Vec::new(),
            application
                .review
                .released
                .iter()
                .map(|lease| lease.lease_id.clone())
                .collect::<Vec<_>>(),
        ),
        ManifoldBrokerControlLeaseTransitionApplication::Revocation(application) => (
            ManifoldRuntimeControlLeaseAdoptionOperation::Revocation,
            &application.authority_id,
            &application.application_id,
            application.from_authority_revision,
            application
                .applied_snapshot
                .as_ref()
                .map_or(application.from_authority_revision, |snapshot| {
                    snapshot.authority_revision
                }),
            Vec::new(),
            Vec::new(),
            application
                .review
                .revoked
                .iter()
                .map(|lease| lease.lease_id.clone())
                .collect::<Vec<_>>(),
        ),
        ManifoldBrokerControlLeaseTransitionApplication::Expiry(application) => (
            ManifoldRuntimeControlLeaseAdoptionOperation::Expiry,
            &application.authority_id,
            &application.application_id,
            application.from_authority_revision,
            application
                .applied_snapshot
                .as_ref()
                .map_or(application.from_authority_revision, |snapshot| {
                    snapshot.authority_revision
                }),
            Vec::new(),
            Vec::new(),
            application
                .review
                .expired_leases
                .iter()
                .map(|lease| lease.lease_id.clone())
                .collect::<Vec<_>>(),
        ),
    };
    let expected_adoption_id =
        DottedId::new(format!("adoption.{}", transition.application.request_id()))
            .expect("validated lifecycle request id derives a valid adoption id");
    let host_revision_closes = adoption
        .prior_host_authority_revision
        .next()
        .is_some_and(|revision| revision == adoption.resulting_host_authority_revision);
    let exact_audit_events = host_snapshot
        .audit_events
        .iter()
        .filter(|event| {
            event.event_kind == ManifoldRuntimeAuditKind::ControlLeaseAdoption
                && event.source_id == adoption.adoption_id
                && event.prior_authority_revision == adoption.prior_host_authority_revision
                && event.resulting_authority_revision == adoption.resulting_host_authority_revision
                && event.applied
                && event.rejection_reason.is_none()
        })
        .count();

    adoption.schema_id.as_str() == HOST_CONTROL_LEASE_ADOPTION_RECEIPT_SCHEMA
        && adoption.authority_host_id == host_snapshot.host_id
        && adoption.adoption_id == expected_adoption_id
        && adoption.operation == expected_operation
        && &adoption.manifold_authority_id == authority_id
        && &adoption.manifold_application_id == application_id
        && adoption.prior_manifold_authority_revision == prior_manifold_revision
        && adoption.resulting_manifold_authority_revision == resulting_manifold_revision
        && adoption.applied
        && adoption.added_lease_ids == added_lease_ids
        && adoption.renewed_lease_ids == renewed_lease_ids
        && adoption.removed_lease_ids == removed_lease_ids
        && host_revision_closes
        && adoption.rejection_reason.is_none()
        && host_snapshot
            .reviewed_control_lease_adoption_ids
            .contains(&adoption.adoption_id)
        && exact_audit_events == 1
}

fn lifecycle_admission_revision_closes(
    use_: &ManifoldBrokerControlLeaseLifecycleUse,
    admission_snapshot: &ManifoldAdmissionSnapshot,
) -> bool {
    use_.authorized_from_admission_authority_revision
        .next()
        .is_some_and(|revision| revision == use_.bounded_use.admission_authority_revision)
        && admission_snapshot.audit_events.iter().any(|event| {
            event.operation == ManifoldAdmissionOperation::AuthorizeUse
                && event.request_id == use_.bounded_use.admission_use_request_id
                && event.applied
                && event.rejection_reason.is_none()
                && event.prior_authority_revision
                    == use_.authorized_from_admission_authority_revision
                && event.resulting_authority_revision
                    == use_.bounded_use.admission_authority_revision
        })
}

fn validate_runtime_evidence_json_size(
    evidence_json: &str,
) -> Result<(), ManifoldBrokerRuntimeStateError> {
    if evidence_json.len() > MAX_BROKER_RUNTIME_EVIDENCE_BYTES {
        Err(ManifoldBrokerRuntimeStateError::InvalidEvidence(
            "runtime_evidence_byte_capacity",
        ))
    } else {
        Ok(())
    }
}

fn validate_runtime_evidence_size(
    evidence: &ManifoldBrokerRuntimeEvidence,
) -> Result<(), ManifoldBrokerRuntimeStateError> {
    let mut writer = LimitedRuntimeEvidenceWriter::new(MAX_BROKER_RUNTIME_EVIDENCE_BYTES);
    serde_json::to_writer(&mut writer, evidence).map_err(|_| {
        ManifoldBrokerRuntimeStateError::InvalidEvidence("runtime_evidence_byte_capacity")
    })
}

fn legacy_v4_contains_revocation(legacy: &LegacyManifoldBrokerRuntimeEvidenceV4) -> bool {
    let owner = &legacy.control_lease_authority;
    let snapshots_are_revocation_free = owner
        .baseline
        .lease_sources
        .iter()
        .flat_map(|source| {
            [
                &source.prior_authority_snapshot,
                source
                    .application
                    .applied_snapshot
                    .as_ref()
                    .unwrap_or(&source.prior_authority_snapshot),
            ]
        })
        .chain([
            &owner.baseline.current_authority_snapshot,
            &owner.current_authority_snapshot,
        ])
        .chain(owner.transitions.iter().flat_map(|transition| {
            [
                &transition.prior_authority_snapshot,
                transition
                    .application
                    .applied_snapshot()
                    .unwrap_or(&transition.prior_authority_snapshot),
            ]
        }))
        .all(|snapshot| snapshot.revoked_control_lease_tombstones.is_empty());
    !snapshots_are_revocation_free
        || owner.schema_id.as_str() != LEGACY_BROKER_CONTROL_LEASE_AUTHORITY_EVIDENCE_V2_SCHEMA
        || owner.transitions.iter().any(|transition| {
            transition.schema_id.as_str() != LEGACY_BROKER_CONTROL_LEASE_TRANSITION_V1_SCHEMA
                || matches!(
                    &transition.application,
                    ManifoldBrokerControlLeaseTransitionApplication::Revocation(_)
                )
        })
        || legacy
            .pending_control_lease_lifecycle_uses
            .iter()
            .chain(legacy.authorized_control_lease_lifecycle_uses.iter())
            .any(|use_| {
                use_.schema_id.as_str() != LEGACY_BROKER_CONTROL_LEASE_LIFECYCLE_USE_V1_SCHEMA
                    || use_.operation_kind
                        == ManifoldBrokerControlLeaseLifecycleOperationKind::Revocation
            })
        || legacy
            .control_lease_lifecycle_receipts
            .iter()
            .any(|receipt| {
                receipt.schema_id.as_str()
                    != LEGACY_BROKER_CONTROL_LEASE_LIFECYCLE_RECEIPT_V1_SCHEMA
                    || receipt.operation_kind
                        == ManifoldBrokerControlLeaseLifecycleOperationKind::Revocation
                    || receipt.lifecycle_use.as_ref().is_some_and(|use_| {
                        use_.schema_id.as_str()
                            != LEGACY_BROKER_CONTROL_LEASE_LIFECYCLE_USE_V1_SCHEMA
                            || use_.operation_kind
                                == ManifoldBrokerControlLeaseLifecycleOperationKind::Revocation
                    })
                    || receipt
                        .authority_transition
                        .as_ref()
                        .is_some_and(|transition| {
                            transition.schema_id.as_str()
                                != LEGACY_BROKER_CONTROL_LEASE_TRANSITION_V1_SCHEMA
                                || matches!(
                                    &transition.application,
                                    ManifoldBrokerControlLeaseTransitionApplication::Revocation(_)
                                )
                        })
                    || receipt.host_adoption.as_ref().is_some_and(|adoption| {
                        adoption.schema_id.as_str()
                            != LEGACY_HOST_CONTROL_LEASE_ADOPTION_RECEIPT_V1_SCHEMA
                            || adoption.operation
                                == ManifoldRuntimeControlLeaseAdoptionOperation::Revocation
                    })
            })
}

fn normalized_v5_evidence_from_v4(
    mut legacy: LegacyManifoldBrokerRuntimeEvidenceV4,
    migrated_host_snapshot: ManifoldRuntimeHostSnapshot,
) -> ManifoldBrokerRuntimeEvidence {
    legacy.control_lease_authority.schema_id =
        schema_id(BROKER_CONTROL_LEASE_AUTHORITY_EVIDENCE_V3_SCHEMA);
    for transition in &mut legacy.control_lease_authority.transitions {
        transition.schema_id = schema_id(crate::BROKER_CONTROL_LEASE_TRANSITION_SCHEMA);
    }
    for use_ in legacy
        .pending_control_lease_lifecycle_uses
        .iter_mut()
        .chain(legacy.authorized_control_lease_lifecycle_uses.iter_mut())
    {
        use_.schema_id = schema_id(BROKER_CONTROL_LEASE_LIFECYCLE_USE_SCHEMA);
    }
    for receipt in &mut legacy.control_lease_lifecycle_receipts {
        receipt.schema_id = schema_id(BROKER_CONTROL_LEASE_LIFECYCLE_RECEIPT_SCHEMA);
        if let Some(use_) = &mut receipt.lifecycle_use {
            use_.schema_id = schema_id(BROKER_CONTROL_LEASE_LIFECYCLE_USE_SCHEMA);
        }
        if let Some(transition) = &mut receipt.authority_transition {
            transition.schema_id = schema_id(crate::BROKER_CONTROL_LEASE_TRANSITION_SCHEMA);
        }
        if let Some(adoption) = &mut receipt.host_adoption {
            adoption.schema_id = schema_id(HOST_CONTROL_LEASE_ADOPTION_RECEIPT_SCHEMA);
        }
    }
    ManifoldBrokerRuntimeEvidence {
        schema_id: schema_id(BROKER_RUNTIME_EVIDENCE_SCHEMA),
        provider_epoch_id: legacy.provider_epoch_id,
        host_snapshot: migrated_host_snapshot,
        control_lease_authority: legacy.control_lease_authority,
        admission_token_history: legacy.admission_snapshot.active_tokens.clone(),
        admission_snapshot: legacy.admission_snapshot,
        authorized_bounded_uses: legacy.pending_bounded_uses.clone(),
        invalidated_bounded_use_ids: Vec::new(),
        pending_bounded_uses: legacy.pending_bounded_uses,
        pending_control_lease_lifecycle_uses: legacy.pending_control_lease_lifecycle_uses,
        authorized_control_lease_lifecycle_uses: legacy.authorized_control_lease_lifecycle_uses,
        invalidated_control_lease_lifecycle_use_ids: legacy
            .invalidated_control_lease_lifecycle_use_ids,
        control_lease_revocation_use_invalidations: Vec::new(),
        control_lease_revocation_barriers: Vec::new(),
        control_lease_revocation_recovery_receipts: Vec::new(),
        control_lease_revocation_consumer_acknowledgements: Vec::new(),
        committed_mutation_receipts: Vec::new(),
        committed_capability_use_receipts: Vec::new(),
        compacted_control_lease_request_ids: Vec::new(),
        consumed_bounded_use_ids: legacy.consumed_bounded_use_ids,
        control_lease_lifecycle_receipts: legacy.control_lease_lifecycle_receipts,
    }
}

fn migrated_v4_host_snapshot(
    source_json: &str,
) -> Result<
    (
        ManifoldRuntimeHostSnapshot,
        ManifoldRuntimeHostMigrationReceipt,
    ),
    ManifoldBrokerRuntimeStateError,
> {
    let source_value: serde_json::Value =
        serde_json::from_str(source_json).map_err(ManifoldBrokerRuntimeStateError::Deserialize)?;
    let host_value = source_value.get("host_snapshot").ok_or(
        ManifoldBrokerRuntimeStateError::InvalidEvidence("revocation_migration_host_snapshot"),
    )?;
    let host_json = serde_json::to_string(host_value)
        .map_err(ManifoldBrokerRuntimeStateError::SerializeMigrationArtifact)?;
    let (host, receipt) = ManifoldRuntimeHost::restart_from_json_with_migration(&host_json)
        .map_err(ManifoldBrokerRuntimeStateError::RuntimeHost)?;
    Ok((host.snapshot().clone(), receipt))
}

fn expected_revocation_migration_receipt(
    source_json: &str,
    resulting_evidence: &ManifoldBrokerRuntimeEvidence,
) -> Result<ManifoldBrokerRuntimeRevocationMigrationReceipt, ManifoldBrokerRuntimeStateError> {
    validate_runtime_evidence_json_size(source_json)?;
    validate_runtime_evidence_size(resulting_evidence)?;
    let legacy: LegacyManifoldBrokerRuntimeEvidenceV4 =
        serde_json::from_str(source_json).map_err(ManifoldBrokerRuntimeStateError::Deserialize)?;
    let (migrated_host_snapshot, runtime_host_migration) = migrated_v4_host_snapshot(source_json)?;
    if legacy.schema_id.as_str() != LEGACY_BROKER_RUNTIME_EVIDENCE_V4_SCHEMA
        || legacy_v4_contains_revocation(&legacy)
        || normalized_v5_evidence_from_v4(legacy.clone(), migrated_host_snapshot)
            != *resulting_evidence
    {
        return Err(ManifoldBrokerRuntimeStateError::InvalidEvidence(
            "revocation_migration_context",
        ));
    }
    let resulting_json = serialize_migration_artifact(resulting_evidence)?;
    Ok(ManifoldBrokerRuntimeRevocationMigrationReceipt {
        schema_id: schema_id(BROKER_RUNTIME_REVOCATION_MIGRATION_RECEIPT_SCHEMA),
        source_schema_id: legacy.schema_id,
        resulting_schema_id: resulting_evidence.schema_id.clone(),
        provider_epoch_id: legacy.provider_epoch_id,
        runtime_host_migration,
        source_json_sha256: sha256_binding(
            REVOCATION_MIGRATION_SOURCE_JSON_DIGEST_DOMAIN,
            source_json.as_bytes(),
        ),
        source_json_size_bytes: bounded_evidence_len_u64(source_json.len())?,
        resulting_evidence_sha256: sha256_binding(
            REVOCATION_MIGRATION_RESULT_DIGEST_DOMAIN,
            &resulting_json,
        ),
        resulting_evidence_size_bytes: bounded_evidence_len_u64(resulting_json.len())?,
        authority_host_id: resulting_evidence.host_snapshot.host_id.clone(),
        host_authority_revision: resulting_evidence.host_snapshot.authority_revision,
        preserved_owner_transition_request_ids: resulting_evidence
            .control_lease_authority
            .transitions
            .iter()
            .map(|transition| transition.application.request_id().clone())
            .collect(),
        preserved_lifecycle_request_ids: resulting_evidence
            .control_lease_lifecycle_receipts
            .iter()
            .map(|receipt| receipt.lifecycle_request_id.clone())
            .collect(),
        preserved_authorized_lifecycle_use_ids: resulting_evidence
            .authorized_control_lease_lifecycle_uses
            .iter()
            .map(|use_| use_.bounded_use.admission_use_request_id.clone())
            .collect(),
        synthesized_revocation_barrier_ids: Vec::new(),
    })
}

fn authority_migration_context_closes(
    source: &LegacyBrokerRuntimeEvidenceV2,
    adapter_config: &ManifoldBrokerAdapterConfig,
    authority_evidence: &ManifoldBrokerControlLeaseAuthorityEvidence,
    resulting_evidence: &ManifoldBrokerRuntimeEvidence,
) -> bool {
    let migrated_host = serde_json::to_string(&source.host_snapshot)
        .ok()
        .and_then(|json| ManifoldRuntimeHost::restart_from_json_with_migration(&json).ok());
    let migrated_host_closes = migrated_host
        .as_ref()
        .is_some_and(|(host, _)| host.snapshot() == &resulting_evidence.host_snapshot);
    source.schema_id.as_str() == LEGACY_BROKER_RUNTIME_EVIDENCE_V2_SCHEMA
        && resulting_evidence.schema_id.as_str() == BROKER_RUNTIME_EVIDENCE_SCHEMA
        && source.provider_epoch_id == resulting_evidence.provider_epoch_id
        && migrated_host_closes
        && source.admission_snapshot == resulting_evidence.admission_snapshot
        && source.pending_bounded_uses == resulting_evidence.pending_bounded_uses
        && source.consumed_bounded_use_ids == resulting_evidence.consumed_bounded_use_ids
        && resulting_evidence
            .pending_control_lease_lifecycle_uses
            .is_empty()
        && resulting_evidence
            .control_lease_lifecycle_receipts
            .is_empty()
        && authority_evidence == &resulting_evidence.control_lease_authority.baseline
        && resulting_evidence
            .control_lease_authority
            .transitions
            .is_empty()
        && migrated_host
            .as_ref()
            .is_some_and(|(host, _)| adapter_config.authority_host_id == host.snapshot().host_id)
}

#[allow(clippy::too_many_lines)]
fn expected_authority_migration_receipt(
    source_json: &str,
    adapter_config: &ManifoldBrokerAdapterConfig,
    authority_evidence: &ManifoldBrokerControlLeaseAuthorityEvidence,
    resulting_evidence: &ManifoldBrokerRuntimeEvidence,
) -> Result<ManifoldBrokerRuntimeAuthorityMigrationReceipt, ManifoldBrokerRuntimeStateError> {
    validate_runtime_evidence_json_size(source_json)?;
    validate_runtime_evidence_size(resulting_evidence)?;
    let source: LegacyBrokerRuntimeEvidenceV2 =
        serde_json::from_str(source_json).map_err(ManifoldBrokerRuntimeStateError::Deserialize)?;
    if !authority_migration_context_closes(
        &source,
        adapter_config,
        authority_evidence,
        resulting_evidence,
    ) {
        return Err(ManifoldBrokerRuntimeStateError::InvalidEvidence(
            "authority_migration_context_join",
        ));
    }
    let authority =
        ManifoldBrokerControlLeaseAuthority::from_caller_attested_retained_authority_state(
            authority_evidence.current_authority_snapshot.clone(),
            authority_evidence.current_clock.clone(),
            authority_evidence.lease_sources.clone(),
        )
        .map_err(ManifoldBrokerRuntimeStateError::ControlLeaseAuthority)?;
    let host_json = serde_json::to_string(&source.host_snapshot)
        .map_err(ManifoldBrokerRuntimeStateError::SerializeMigrationArtifact)?;
    let (migrated_host, _) = ManifoldRuntimeHost::restart_from_json_with_migration(&host_json)
        .map_err(ManifoldBrokerRuntimeStateError::RuntimeHost)?;
    authority
        .validate_host_snapshot(migrated_host.snapshot())
        .map_err(ManifoldBrokerRuntimeStateError::ControlLeaseAuthority)?;

    let mut canonical_leases = migrated_host.snapshot().leases.clone();
    canonical_leases.sort_by(|left, right| left.lease_id.cmp(&right.lease_id));
    if canonical_leases
        .windows(2)
        .any(|pair| pair[0].lease_id == pair[1].lease_id)
    {
        return Err(ManifoldBrokerRuntimeStateError::InvalidEvidence(
            "legacy_v2_duplicate_lease",
        ));
    }
    let migrated_lease_ids = canonical_leases
        .iter()
        .map(|lease| lease.lease_id.clone())
        .collect();
    let source_typed_json = serialize_migration_artifact(&source)?;
    let resulting_evidence_json = serialize_migration_artifact(resulting_evidence)?;
    let source_lineage_json = serialize_migration_artifact(authority_evidence)?;
    let host_snapshot_json = serialize_migration_artifact(&source.host_snapshot)?;
    let host_lease_set_json = serialize_migration_artifact(&canonical_leases)?;

    Ok(ManifoldBrokerRuntimeAuthorityMigrationReceipt {
        schema_id: schema_id(BROKER_RUNTIME_AUTHORITY_MIGRATION_RECEIPT_SCHEMA),
        source_schema_id: source.schema_id,
        resulting_schema_id: schema_id(BROKER_RUNTIME_EVIDENCE_SCHEMA),
        provider_epoch_id: source.provider_epoch_id,
        source_json_sha256: sha256_binding(
            MIGRATION_SOURCE_JSON_DIGEST_DOMAIN,
            source_json.as_bytes(),
        ),
        source_json_size_bytes: bounded_evidence_len_u64(source_json.len())?,
        source_typed_evidence_sha256: sha256_binding(
            MIGRATION_SOURCE_TYPED_DIGEST_DOMAIN,
            &source_typed_json,
        ),
        resulting_evidence_json_sha256: sha256_binding(
            MIGRATION_RESULT_DIGEST_DOMAIN,
            &resulting_evidence_json,
        ),
        resulting_evidence_json_size_bytes: bounded_evidence_len_u64(
            resulting_evidence_json.len(),
        )?,
        adapter_id: adapter_config.adapter_id.clone(),
        product_lock_id: adapter_config.product_lock_id.clone(),
        product_lock_sha256: adapter_config.product_lock_sha256.clone(),
        authority_host_id: adapter_config.authority_host_id.clone(),
        control_lease_authority_schema_id: schema_id(
            crate::BROKER_CONTROL_LEASE_AUTHORITY_EVIDENCE_SCHEMA,
        ),
        control_lease_authority_id: authority_evidence
            .current_authority_snapshot
            .authority_id
            .clone(),
        control_lease_authority_revision: authority_evidence
            .current_authority_snapshot
            .authority_revision,
        control_lease_clock_domain: authority_evidence.current_clock.clock_domain.clone(),
        control_lease_clock_epoch_id: authority_evidence.current_clock.clock_epoch_id.clone(),
        control_lease_clock_sequence: authority_evidence.current_clock.sequence,
        source_lineage_sha256: sha256_binding(
            MIGRATION_AUTHORITY_DIGEST_DOMAIN,
            &source_lineage_json,
        ),
        host_snapshot_sha256: sha256_binding(
            MIGRATION_HOST_DIGEST_DOMAIN,
            &host_snapshot_json,
        ),
        host_lease_set_sha256: sha256_binding(
            MIGRATION_HOST_LEASE_SET_DIGEST_DOMAIN,
            &host_lease_set_json,
        ),
        migrated_lease_ids,
        outcome: ManifoldBrokerRuntimeAuthorityMigrationOutcome::
            ExistingAuthorityAdoptedWithoutNewLeaseDecision,
    })
}

fn sha256_binding(domain: &str, bytes: &[u8]) -> String {
    broker_runtime_authority_migration_digest(domain, bytes)
}

/// Computes a versioned authority-migration digest.
///
/// The exact framing is UTF-8 domain bytes, one zero byte, then the exact
/// artifact bytes. The result is lower-case `sha256:<hex>`. Callers should use
/// one of the public `MIGRATION_*_DIGEST_DOMAIN` constants.
#[must_use]
pub fn broker_runtime_authority_migration_digest(domain: &str, bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher.update(bytes);
    let digest = hasher.finalize();
    format!("sha256:{digest:x}")
}

fn bounded_evidence_len_u64(value: usize) -> Result<u64, ManifoldBrokerRuntimeStateError> {
    u64::try_from(value).map_err(|_| {
        ManifoldBrokerRuntimeStateError::InvalidEvidence("runtime_evidence_byte_capacity")
    })
}

fn serialize_migration_artifact<T: Serialize>(
    value: &T,
) -> Result<Vec<u8>, ManifoldBrokerRuntimeStateError> {
    let mut writer = LimitedMigrationArtifactWriter::new(MAX_BROKER_RUNTIME_EVIDENCE_BYTES);
    let result = serde_json::to_writer(&mut writer, value);
    if writer.exceeded {
        return Err(ManifoldBrokerRuntimeStateError::InvalidEvidence(
            "runtime_evidence_byte_capacity",
        ));
    }
    result.map_err(ManifoldBrokerRuntimeStateError::SerializeMigrationArtifact)?;
    Ok(writer.output)
}

struct LimitedMigrationArtifactWriter {
    output: Vec<u8>,
    limit: usize,
    exceeded: bool,
}

impl LimitedMigrationArtifactWriter {
    const fn new(limit: usize) -> Self {
        Self {
            output: Vec::new(),
            limit,
            exceeded: false,
        }
    }
}

impl Write for LimitedMigrationArtifactWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let remaining = self.limit.saturating_sub(self.output.len());
        if buffer.len() > remaining {
            self.exceeded = true;
            return Err(io::Error::other(
                "serialized migration artifact byte limit exceeded",
            ));
        }
        self.output.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct LimitedRuntimeEvidenceWriter {
    written: usize,
    limit: usize,
}

impl LimitedRuntimeEvidenceWriter {
    const fn new(limit: usize) -> Self {
        Self { written: 0, limit }
    }
}

impl Write for LimitedRuntimeEvidenceWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let remaining = self.limit.saturating_sub(self.written);
        if buffer.len() > remaining {
            return Err(io::Error::other(
                "serialized runtime evidence byte limit exceeded",
            ));
        }
        self.written += buffer.len();
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Broker runtime durable evidence restoration failure.
#[derive(Debug)]
pub enum ManifoldBrokerRuntimeStateError {
    /// Legacy broker runtime evidence JSON failed to decode.
    Deserialize(serde_json::Error),
    /// Nested legacy JSON value could not be encoded for its owner migration.
    SerializeMigrationArtifact(serde_json::Error),
    /// Admission snapshot failed its own durable validation.
    Admission(rusty_manifold_admission::ManifoldAdmissionError),
    /// Runtime Host snapshot failed its owner migration/validation.
    RuntimeHost(ManifoldRuntimeHostError),
    /// Control-lease owner state and Runtime Host projection did not close.
    ControlLeaseAuthority(ManifoldBrokerControlLeaseAuthorityError),
    /// Cross-authority broker evidence join failed.
    InvalidEvidence(&'static str),
}

impl fmt::Display for ManifoldBrokerRuntimeStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Deserialize(error) => {
                write!(formatter, "broker runtime evidence decode failed: {error}")
            }
            Self::SerializeMigrationArtifact(error) => {
                write!(
                    formatter,
                    "broker migration artifact encode failed: {error}"
                )
            }
            Self::Admission(error) => write!(formatter, "broker admission state invalid: {error}"),
            Self::RuntimeHost(error) => write!(formatter, "broker Runtime Host invalid: {error}"),
            Self::ControlLeaseAuthority(error) => {
                write!(formatter, "broker control-lease authority invalid: {error}")
            }
            Self::InvalidEvidence(reason) => {
                write!(formatter, "broker runtime evidence invalid: {reason}")
            }
        }
    }
}

impl std::error::Error for ManifoldBrokerRuntimeStateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Deserialize(error) | Self::SerializeMigrationArtifact(error) => Some(error),
            Self::Admission(error) => Some(error),
            Self::RuntimeHost(error) => Some(error),
            Self::ControlLeaseAuthority(error) => Some(error),
            Self::InvalidEvidence(_) => None,
        }
    }
}

/// Returns the exact capability required to attempt one command.
///
/// # Panics
///
/// Panics only if a valid dotted command identifier cannot be prefixed with
/// the static `capability.command` namespace.
#[must_use]
pub fn command_capability(command_id: &DottedId) -> DottedId {
    let suffix = command_id
        .as_str()
        .strip_prefix("command.")
        .unwrap_or(command_id.as_str());
    DottedId::new(format!("capability.command.{suffix}"))
        .expect("command-derived capability is valid")
}

#[allow(clippy::too_many_arguments)]
fn mutation_receipt(
    provider_epoch_id: &DottedId,
    admission_use_request_id: &DottedId,
    admission_authority_revision: Revision,
    command_selected: bool,
    admission_applied: bool,
    admission_rejection_reason: Option<ManifoldBrokerMutationRejectionReason>,
    adapter_receipt: Option<ManifoldBrokerAdapterReceipt>,
    bounded_use: Option<ManifoldBrokerBoundedUse>,
) -> ManifoldBrokerMutationReceipt {
    let applied = adapter_receipt
        .as_ref()
        .is_some_and(|receipt| receipt.application.applied);
    ManifoldBrokerMutationReceipt {
        schema_id: schema_id(BROKER_MUTATION_RECEIPT_SCHEMA),
        provider_epoch_id: provider_epoch_id.clone(),
        admission_use_request_id: admission_use_request_id.clone(),
        admission_authority_revision,
        local_acceptance_rules: false,
        authority_owner_id: DottedId::new(RUNTIME_HOST_AUTHORITY_OWNER)
            .expect("static authority owner is valid"),
        command_selected,
        admission_applied,
        admission_rejection_reason,
        adapter_receipt,
        bounded_use,
        applied,
    }
}

fn schema_id(value: &str) -> SchemaId {
    SchemaId::new(value).expect("static schema id is valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        packaged_product_lock_sha256, ManifoldBrokerAdapterConfig, ManifoldBrokerAdapterMode,
        BROKER_ADAPTER_CONFIG_SCHEMA,
    };
    use rusty_manifold_admission::{
        ManifoldAdmissionGrant, ManifoldAdmissionRejectionReason, ManifoldClientIdentity,
        ADMISSION_REQUEST_SCHEMA, ADMISSION_REVOCATION_REQUEST_SCHEMA, ADMISSION_SNAPSHOT_SCHEMA,
        ADMISSION_USE_REQUEST_SCHEMA,
    };
    use rusty_manifold_broker_product::{
        resolve_broker_product, ManifoldBrokerFeature, ManifoldBrokerProductLock,
        ManifoldBrokerProductSpec, BROKER_PRODUCT_SPEC_SCHEMA,
    };
    use rusty_manifold_model::{
        ManifoldAuthoritySnapshot, ManifoldClockSnapshot, ManifoldControlLeaseRequest, SafetyClass,
    };
    use rusty_manifold_runtime_host::{
        ManifoldRuntimeLease, ManifoldRuntimeRejectionReason, HOST_COMMAND_REQUEST_SCHEMA,
        MAX_RUNTIME_AUDIT_EVENTS,
    };

    fn id(value: &str) -> DottedId {
        DottedId::new(value).expect("id")
    }

    fn adapter_for_legacy_v4(
        legacy: &LegacyManifoldBrokerRuntimeEvidenceV4,
    ) -> ManifoldBrokerAdapter {
        let mut owner_evidence = legacy.control_lease_authority.clone();
        owner_evidence.schema_id = schema_id(BROKER_CONTROL_LEASE_AUTHORITY_EVIDENCE_V3_SCHEMA);
        for transition in &mut owner_evidence.transitions {
            transition.schema_id = schema_id(crate::BROKER_CONTROL_LEASE_TRANSITION_SCHEMA);
        }
        let authority = ManifoldBrokerControlLeaseAuthority::refresh_from_v2_evidence(
            owner_evidence.clone(),
            owner_evidence.current_authority_snapshot.clone(),
            owner_evidence.current_clock.clone(),
        )
        .expect("migratable v4 owner");
        let config: ManifoldBrokerAdapterConfig = serde_json::from_str(include_str!(
            "../../../fixtures/broker-adapter/standalone-config.json"
        ))
        .expect("committed adapter config");
        ManifoldBrokerAdapter::new(
            config,
            include_bytes!("../../../fixtures/broker-adapter/standalone-product-lock.json"),
            &authority,
        )
        .expect("migratable v4 adapter")
    }

    fn identity(client: &str) -> ManifoldClientIdentity {
        ManifoldClientIdentity {
            client_id: id(client),
            platform_subject: format!("example.{client}"),
            signing_fingerprint: format!("sha256:{}", "a1".repeat(32)),
        }
    }

    fn lock(features: Vec<ManifoldBrokerFeature>) -> ManifoldBrokerProductLock {
        resolve_broker_product(&ManifoldBrokerProductSpec {
            schema_id: schema_id(BROKER_PRODUCT_SPEC_SCHEMA),
            product_id: id("broker.runtime.test"),
            standalone_enabled: true,
            embedded_enabled: false,
            requested_features: features,
        })
        .expect("lock")
    }

    fn control_lease_authority(
        leases: &[ManifoldRuntimeLease],
        retain_unrelated_leases: bool,
    ) -> ManifoldBrokerControlLeaseAuthority {
        assert!(leases.len() <= 1, "bounded test authority");
        let mut prior: ManifoldAuthoritySnapshot = serde_json::from_str(include_str!(
            "../../../fixtures/authority/synthetic-authority-snapshot.json"
        ))
        .expect("prior authority snapshot");
        if !retain_unrelated_leases {
            prior.active_leases.clear();
        }
        let clock: ManifoldClockSnapshot = serde_json::from_str(include_str!(
            "../../../fixtures/clock/synthetic-command-review-clock.json"
        ))
        .expect("projection clock");
        let mut sources = Vec::new();
        let current = if let Some(lease) = leases.first() {
            let capability = id("capability.broker.runtime.test");
            prior.host_manifest.capabilities.push(capability.clone());
            let suffix = lease
                .lease_id
                .as_str()
                .strip_prefix("lease.")
                .expect("test lease id");
            let review = prior
                .review_lease_request(
                    ManifoldControlLeaseRequest {
                        schema_id: schema_id("rusty.manifold.command.lease_request.v1"),
                        request_id: id(&format!("request.{suffix}")),
                        holder_id: lease.holder_id.clone(),
                        scope: lease.scope.clone(),
                        expected_revision: prior.authority_revision,
                        requested_ttl_ms: 30_000,
                        required_capability: capability,
                        safety_class: SafetyClass::BoundedMutation,
                    },
                    clock.clone(),
                    vec![id("evidence.broker.runtime.test.lease")],
                )
                .expect("lease review");
            let application = prior
                .apply_control_lease_authority_review(review)
                .expect("lease application");
            let current = application
                .applied_snapshot
                .clone()
                .expect("applied snapshot");
            sources.push(crate::ManifoldBrokerControlLeaseSource {
                schema_id: schema_id(crate::BROKER_CONTROL_LEASE_SOURCE_SCHEMA),
                prior_authority_snapshot: prior.clone(),
                application,
            });
            current
        } else {
            prior
        };
        ManifoldBrokerControlLeaseAuthority::from_caller_attested_retained_authority_state(
            current, clock, sources,
        )
        .expect("control-lease authority")
    }

    fn runtime(
        features: Vec<ManifoldBrokerFeature>,
        capabilities: Vec<DottedId>,
        leases: Vec<ManifoldRuntimeLease>,
        epoch: &str,
    ) -> ManifoldBrokerRuntime {
        runtime_with_authority_policy(features, capabilities, leases, epoch, false)
    }

    fn runtime_with_authority_policy(
        features: Vec<ManifoldBrokerFeature>,
        mut capabilities: Vec<DottedId>,
        leases: Vec<ManifoldRuntimeLease>,
        epoch: &str,
        retain_unrelated_leases: bool,
    ) -> ManifoldBrokerRuntime {
        capabilities.sort();
        capabilities.dedup();
        let lock = lock(features);
        let config = ManifoldBrokerAdapterConfig {
            schema_id: schema_id(BROKER_ADAPTER_CONFIG_SCHEMA),
            adapter_id: id("adapter.runtime.test"),
            mode: ManifoldBrokerAdapterMode::Standalone,
            product_lock_id: lock.lock_id.clone(),
            product_lock_fingerprint: lock.spec_fingerprint.clone(),
            product_lock_sha256: packaged_product_lock_sha256(
                &serde_json::to_vec(&lock).expect("serialize lock"),
            ),
            authority_host_id: id("host.runtime.test"),
            authority_owner_id: id(RUNTIME_HOST_AUTHORITY_OWNER),
        };
        let packaged_lock = serde_json::to_vec(&lock).expect("serialize packaged lock");
        let control_lease_authority = control_lease_authority(&leases, retain_unrelated_leases);
        let adapter = ManifoldBrokerAdapter::new(config, &packaged_lock, &control_lease_authority)
            .expect("adapter");
        let admission = ManifoldAdmissionSnapshot {
            schema_id: schema_id(ADMISSION_SNAPSHOT_SCHEMA),
            authority_id: id("authority.admission.runtime.test"),
            authority_revision: Revision::new(1).expect("revision"),
            grants: vec![ManifoldAdmissionGrant {
                grant_id: id("grant.runtime.test"),
                client_lock_id: id("lock.client.runtime.test"),
                client_lock_fingerprint: format!("sha256:{}", "c1".repeat(32)),
                identity: identity("client.runtime.test"),
                capabilities,
                expires_at_ms: 2_000_000_000_000,
                revoked: false,
            }],
            active_tokens: Vec::new(),
            revoked_token_ids: Vec::new(),
            consumed_request_ids: Vec::new(),
            consumed_use_request_ids: Vec::new(),
            reviewed_sweep_ids: Vec::new(),
            audit_events: Vec::new(),
            max_token_ttl_ms: 30_000,
        };
        ManifoldBrokerRuntime::new(id(epoch), adapter, control_lease_authority, admission)
            .expect("runtime")
    }

    fn assert_runtime_evidence_rejected_after_json(
        runtime: &ManifoldBrokerRuntime,
        damaged: &ManifoldBrokerRuntimeEvidence,
    ) {
        let damaged_json = serde_json::to_string(damaged).expect("damaged evidence JSON");
        let damaged: ManifoldBrokerRuntimeEvidence =
            serde_json::from_str(&damaged_json).expect("damaged evidence round trip");
        let owner = ManifoldBrokerControlLeaseAuthority::refresh_from_v2_evidence(
            damaged.control_lease_authority.clone(),
            damaged
                .control_lease_authority
                .current_authority_snapshot
                .clone(),
            damaged.control_lease_authority.current_clock.clone(),
        )
        .expect("owner restore");
        assert!(
            ManifoldBrokerRuntime::restore_from_caller_attested_exclusive_evidence(
                runtime.adapter.clone(),
                owner,
                damaged,
            )
            .is_err()
        );
    }

    fn two_client_runtime(command: &str, epoch: &str) -> ManifoldBrokerRuntime {
        let product_lock = lock(Vec::new());
        let config = ManifoldBrokerAdapterConfig {
            schema_id: schema_id(BROKER_ADAPTER_CONFIG_SCHEMA),
            adapter_id: id("adapter.runtime.two_client"),
            mode: ManifoldBrokerAdapterMode::Standalone,
            product_lock_id: product_lock.lock_id.clone(),
            product_lock_fingerprint: product_lock.spec_fingerprint.clone(),
            product_lock_sha256: packaged_product_lock_sha256(
                &serde_json::to_vec(&product_lock).expect("serialize lock"),
            ),
            authority_host_id: id("host.runtime.two_client"),
            authority_owner_id: id(RUNTIME_HOST_AUTHORITY_OWNER),
        };
        let packaged_lock =
            serde_json::to_vec(&product_lock).expect("serialize packaged product lock");
        let control_lease_authority = control_lease_authority(&[], false);
        let adapter = ManifoldBrokerAdapter::new(config, &packaged_lock, &control_lease_authority)
            .expect("adapter");
        let capability = command_capability(&id(command));
        let admission = ManifoldAdmissionSnapshot {
            schema_id: schema_id(ADMISSION_SNAPSHOT_SCHEMA),
            authority_id: id("authority.admission.runtime.two_client"),
            authority_revision: Revision::new(1).expect("revision"),
            grants: ["client.runtime.alpha", "client.runtime.beta"]
                .into_iter()
                .enumerate()
                .map(|(index, client)| ManifoldAdmissionGrant {
                    grant_id: id(&format!("grant.{client}")),
                    client_lock_id: id(&format!("lock.{client}")),
                    client_lock_fingerprint: format!(
                        "sha256:{}",
                        if index == 0 { "c2" } else { "c3" }.repeat(32)
                    ),
                    identity: identity(client),
                    capabilities: vec![capability.clone()],
                    expires_at_ms: 100_000,
                    revoked: false,
                })
                .collect(),
            active_tokens: Vec::new(),
            revoked_token_ids: Vec::new(),
            consumed_request_ids: Vec::new(),
            consumed_use_request_ids: Vec::new(),
            reviewed_sweep_ids: Vec::new(),
            audit_events: Vec::new(),
            max_token_ttl_ms: 30_000,
        };
        ManifoldBrokerRuntime::new(id(epoch), adapter, control_lease_authority, admission)
            .expect("runtime")
    }

    fn admit_for_client(
        runtime: &mut ManifoldBrokerRuntime,
        command: &str,
        client: &str,
        suffix: &str,
        expected_revision: u64,
        entropy: u8,
        token_ttl_ms: u64,
    ) -> (DottedId, DottedId, Revision) {
        let issue = runtime.issue_token(
            &ManifoldAdmissionRequest {
                schema_id: schema_id(ADMISSION_REQUEST_SCHEMA),
                request_id: id(&format!("request.runtime.{suffix}.issue")),
                expected_authority_revision: Revision::new(expected_revision).expect("revision"),
                identity: identity(client),
                requested_capabilities: vec![command_capability(&id(command))],
                issued_at_ms: 1_000,
                expires_at_ms: 50_000,
                requested_token_ttl_ms: token_ttl_ms,
            },
            [entropy; 32],
            2_000,
        );
        assert!(issue.applied);
        let token = issue.token.expect("token");
        let use_id = id(&format!("request.runtime.{suffix}.use"));
        let use_receipt = runtime.authorize_use(
            &ManifoldAdmissionUseRequest {
                schema_id: schema_id(ADMISSION_USE_REQUEST_SCHEMA),
                request_id: use_id.clone(),
                expected_authority_revision: issue.resulting_authority_revision,
                token_id: token.token_id.clone(),
                identity: identity(client),
                capability_id: command_capability(&id(command)),
                issued_at_ms: 2_000,
                expires_at_ms: 40_000,
            },
            3_000,
        );
        assert!(use_receipt.applied);
        (
            use_id,
            token.token_id,
            use_receipt.resulting_authority_revision,
        )
    }

    fn client_command(
        command_id: &str,
        client: &str,
        request_suffix: &str,
        expected_host_revision: u64,
    ) -> ManifoldRuntimeCommandRequest {
        ManifoldRuntimeCommandRequest {
            schema_id: schema_id(HOST_COMMAND_REQUEST_SCHEMA),
            request_id: id(&format!("request.runtime.command.{request_suffix}")),
            expected_authority_revision: Revision::new(expected_host_revision).expect("revision"),
            requester_id: id(client),
            command_id: id(command_id),
            lease_id: None,
            params_digest: None,
            issued_at_ms: 3_000,
            expires_at_ms: 40_000,
        }
    }

    fn client_mutation(
        epoch: &str,
        use_id: DottedId,
        token_id: DottedId,
        admission_revision: Revision,
        command: ManifoldRuntimeCommandRequest,
    ) -> ManifoldBrokerMutationRequest {
        ManifoldBrokerMutationRequest {
            schema_id: schema_id(BROKER_MUTATION_REQUEST_SCHEMA),
            provider_epoch_id: id(epoch),
            admission_use_request_id: use_id,
            token_id,
            expected_admission_authority_revision: admission_revision,
            command,
        }
    }

    fn admit(runtime: &mut ManifoldBrokerRuntime, command: &str) -> (DottedId, DottedId) {
        let issue = ManifoldAdmissionRequest {
            schema_id: schema_id(ADMISSION_REQUEST_SCHEMA),
            request_id: id("request.runtime.issue"),
            expected_authority_revision: Revision::new(1).expect("revision"),
            identity: identity("client.runtime.test"),
            requested_capabilities: vec![command_capability(&id(command))],
            issued_at_ms: 1_000,
            expires_at_ms: 10_000,
            requested_token_ttl_ms: 20_000,
        };
        let token = runtime
            .issue_token(&issue, [7; 32], 2_000)
            .token
            .expect("token");
        let use_id = id("request.runtime.use");
        let use_receipt = runtime.authorize_use(
            &ManifoldAdmissionUseRequest {
                schema_id: schema_id(ADMISSION_USE_REQUEST_SCHEMA),
                request_id: use_id.clone(),
                expected_authority_revision: Revision::new(2).expect("revision"),
                token_id: token.token_id.clone(),
                identity: identity("client.runtime.test"),
                capability_id: command_capability(&id(command)),
                issued_at_ms: 2_000,
                expires_at_ms: 9_000,
            },
            3_000,
        );
        assert!(use_receipt.applied);
        (use_id, token.token_id)
    }

    fn next_control_lease_clock(
        runtime: &ManifoldBrokerRuntime,
        wall_advance_ms: i64,
    ) -> ManifoldClockSnapshot {
        let mut clock = runtime.control_lease_authority.current_clock().clone();
        clock.sequence += 1;
        clock.monotonic_elapsed_ns += 1_000_000;
        clock.wall_unix_ms += wall_advance_ms;
        clock
    }

    fn authorize_lifecycle(
        runtime: &mut ManifoldBrokerRuntime,
        operation: ManifoldBrokerControlLeaseLifecycleOperation,
        suffix: &str,
        entropy: u8,
        now_ms_override: Option<u64>,
    ) -> ManifoldBrokerControlLeaseLifecycleRequest {
        let capability = control_lease_lifecycle_capability(operation.kind());
        let now_ms = now_ms_override.unwrap_or_else(|| {
            u64::try_from(runtime.control_lease_authority.current_clock().wall_unix_ms)
                .expect("positive test wall clock")
        });
        let issue = runtime.issue_token(
            &ManifoldAdmissionRequest {
                schema_id: schema_id(ADMISSION_REQUEST_SCHEMA),
                request_id: id(&format!("request.lifecycle.{suffix}.token")),
                expected_authority_revision: runtime.admission_snapshot().authority_revision,
                identity: identity("client.runtime.test"),
                requested_capabilities: vec![capability.clone()],
                issued_at_ms: now_ms,
                expires_at_ms: now_ms + 25_000,
                requested_token_ttl_ms: 20_000,
            },
            [entropy; 32],
            now_ms,
        );
        assert!(issue.applied);
        let token = issue.token.expect("lifecycle token");
        let use_request = ManifoldAdmissionUseRequest {
            schema_id: schema_id(ADMISSION_USE_REQUEST_SCHEMA),
            request_id: id(&format!("request.lifecycle.{suffix}.use")),
            expected_authority_revision: issue.resulting_authority_revision,
            token_id: token.token_id.clone(),
            identity: identity("client.runtime.test"),
            capability_id: capability,
            issued_at_ms: now_ms,
            expires_at_ms: now_ms + 15_000,
        };
        let lifecycle_request = ManifoldBrokerControlLeaseLifecycleRequest {
            schema_id: schema_id(BROKER_CONTROL_LEASE_LIFECYCLE_REQUEST_SCHEMA),
            provider_epoch_id: runtime.provider_epoch_id().clone(),
            admission_use_request_id: use_request.request_id.clone(),
            token_id: token.token_id,
            expected_admission_authority_revision: use_request.expected_authority_revision,
            operation,
        };
        let receipt =
            runtime.authorize_control_lease_lifecycle_use(&use_request, &lifecycle_request, now_ms);
        assert!(receipt.applied, "{receipt:?}");
        assert_eq!(
            receipt.lifecycle_request_sha256,
            control_lease_lifecycle_request_sha256(&lifecycle_request)
        );
        lifecycle_request
    }

    fn command(command: &str, lease: Option<&str>) -> ManifoldRuntimeCommandRequest {
        ManifoldRuntimeCommandRequest {
            schema_id: schema_id(HOST_COMMAND_REQUEST_SCHEMA),
            request_id: id("request.runtime.command"),
            expected_authority_revision: Revision::new(1).expect("revision"),
            requester_id: id("client.runtime.test"),
            command_id: id(command),
            lease_id: lease.map(id),
            params_digest: None,
            issued_at_ms: 2_000,
            expires_at_ms: 9_000,
        }
    }

    fn mutation(
        epoch: &str,
        use_id: DottedId,
        token_id: DottedId,
        command: ManifoldRuntimeCommandRequest,
    ) -> ManifoldBrokerMutationRequest {
        ManifoldBrokerMutationRequest {
            schema_id: schema_id(BROKER_MUTATION_REQUEST_SCHEMA),
            provider_epoch_id: id(epoch),
            admission_use_request_id: use_id,
            token_id,
            expected_admission_authority_revision: Revision::new(3).expect("revision"),
            command,
        }
    }

    #[test]
    fn accepted_bounded_use_reaches_one_runtime_host_application() {
        let command_id = "command.media.session.start";
        let lease = ManifoldRuntimeLease {
            lease_id: id("lease.media.session.runtime.test"),
            scope: id("lease.media.session"),
            holder_id: id("client.runtime.test"),
            expires_at_ms: 60_000,
            derivative_binding: None,
        };
        let capability = command_capability(&id(command_id));
        let mut runtime = runtime(
            vec![ManifoldBrokerFeature::MediaSession],
            vec![capability],
            vec![lease],
            "epoch.runtime.one",
        );
        let (use_id, token_id) = admit(&mut runtime, command_id);
        let receipt = runtime.handle_mutation(
            &mutation(
                "epoch.runtime.one",
                use_id,
                token_id,
                command(command_id, Some("lease.media.session.runtime.test")),
            ),
            4_000,
        );
        assert!(receipt.admission_applied && receipt.applied);
        assert!(receipt.command_selected);
        assert_eq!(runtime.host_snapshot().authority_revision.get(), 2);
        assert_eq!(runtime.admission_snapshot().authority_revision.get(), 3);
        let evidence = runtime.evidence();
        assert_eq!(evidence.committed_mutation_receipts, vec![receipt]);
        runtime.staged_copy().expect("retained mutation restart");
        let mut damaged = evidence.clone();
        damaged.committed_mutation_receipts[0]
            .adapter_receipt
            .as_mut()
            .expect("adapter receipt")
            .application
            .applied = false;
        assert_runtime_evidence_rejected_after_json(&runtime, &damaged);

        let mut provenance_substitutions = Vec::new();
        for substitute in 0..10 {
            let mut damaged = evidence.clone();
            let bounded_use = damaged.committed_mutation_receipts[0]
                .bounded_use
                .as_mut()
                .expect("committed bounded use");
            match substitute {
                0 => bounded_use.schema_id = schema_id("rusty.manifold.broker.bounded_use.v999"),
                1 => bounded_use.admission_use_request_id = id("request.runtime.use.substituted"),
                2 => bounded_use.token_id = id("token.runtime.substituted"),
                3 => bounded_use.identity = identity("client.runtime.substituted"),
                4 => bounded_use.admission_grant_id = id("grant.runtime.substituted"),
                5 => bounded_use.client_lock_id = id("lock.runtime.substituted"),
                6 => bounded_use.client_lock_fingerprint = format!("sha256:{}", "ab".repeat(32)),
                7 => bounded_use.capability_id = id("capability.runtime.substituted"),
                8 => {
                    bounded_use.admission_authority_revision = bounded_use
                        .admission_authority_revision
                        .next()
                        .expect("revision")
                }
                9 => bounded_use.expires_at_ms += 1,
                _ => unreachable!(),
            }
            provenance_substitutions.push(damaged);
        }
        for damaged in provenance_substitutions {
            assert_runtime_evidence_rejected_after_json(&runtime, &damaged);
        }
        let mut missing_receipt = evidence;
        missing_receipt.committed_mutation_receipts.clear();
        assert_runtime_evidence_rejected_after_json(&runtime, &missing_receipt);
    }

    #[test]
    fn retired_admission_tokens_cannot_substitute_for_exact_committed_provenance() {
        let command_id = "command.session.list";
        let capability = command_capability(&id(command_id));
        let mut runtime = runtime(
            Vec::new(),
            vec![capability.clone()],
            Vec::new(),
            "epoch.runtime.retired_token_provenance",
        );
        let (use_id, first_token_id) = admit(&mut runtime, command_id);
        let mutation_receipt = runtime.handle_mutation(
            &mutation(
                "epoch.runtime.retired_token_provenance",
                use_id,
                first_token_id.clone(),
                command(command_id, None),
            ),
            4_000,
        );
        assert!(mutation_receipt.applied);

        let second_token = runtime
            .issue_token(
                &ManifoldAdmissionRequest {
                    schema_id: schema_id(ADMISSION_REQUEST_SCHEMA),
                    request_id: id("request.runtime.retired_token.second.issue"),
                    expected_authority_revision: runtime.admission_snapshot().authority_revision,
                    identity: identity("client.runtime.test"),
                    requested_capabilities: vec![capability],
                    issued_at_ms: 1_000,
                    expires_at_ms: 10_000,
                    requested_token_ttl_ms: 20_000,
                },
                [8; 32],
                4_500,
            )
            .token
            .expect("second token");
        assert_ne!(first_token_id, second_token.token_id);
        let first_revocation = runtime.revoke_token(&ManifoldAdmissionRevocationRequest {
            schema_id: schema_id(ADMISSION_REVOCATION_REQUEST_SCHEMA),
            request_id: id("request.runtime.retired_token.first.revoke"),
            expected_authority_revision: runtime.admission_snapshot().authority_revision,
            token_id: first_token_id,
            identity: identity("client.runtime.test"),
            reason: id("reason.runtime.retired_token.test"),
        });
        assert!(first_revocation.applied);
        let second_revocation = runtime.revoke_token(&ManifoldAdmissionRevocationRequest {
            schema_id: schema_id(ADMISSION_REVOCATION_REQUEST_SCHEMA),
            request_id: id("request.runtime.retired_token.second.revoke"),
            expected_authority_revision: runtime.admission_snapshot().authority_revision,
            token_id: second_token.token_id.clone(),
            identity: identity("client.runtime.test"),
            reason: id("reason.runtime.retired_token.test"),
        });
        assert!(second_revocation.applied);
        runtime
            .staged_copy()
            .expect("two retired tokens retain exact provenance");

        let mut substituted = runtime.evidence();
        substituted.authorized_bounded_uses[0].token_id = second_token.token_id.clone();
        substituted.committed_mutation_receipts[0]
            .bounded_use
            .as_mut()
            .expect("committed bounded use")
            .token_id = second_token.token_id;
        assert_runtime_evidence_rejected_after_json(&runtime, &substituted);
    }

    #[test]
    fn non_command_consumption_retains_one_exact_receipt_and_rejects_commands() {
        let stream_capability = id("manifold.stream.subscribe");
        let command_capability_id = command_capability(&id("command.session.list"));
        let mut runtime = runtime(
            Vec::new(),
            vec![stream_capability.clone(), command_capability_id.clone()],
            Vec::new(),
            "epoch.runtime.capability_receipt",
        );
        let stream_token = runtime
            .issue_token(
                &ManifoldAdmissionRequest {
                    schema_id: schema_id(ADMISSION_REQUEST_SCHEMA),
                    request_id: id("request.runtime.stream.issue"),
                    expected_authority_revision: runtime.admission_snapshot().authority_revision,
                    identity: identity("client.runtime.test"),
                    requested_capabilities: vec![stream_capability.clone()],
                    issued_at_ms: 1_000,
                    expires_at_ms: 10_000,
                    requested_token_ttl_ms: 20_000,
                },
                [9; 32],
                2_000,
            )
            .token
            .expect("stream token");
        let stream_use_id = id("request.runtime.stream.use");
        let stream_use = runtime.authorize_use(
            &ManifoldAdmissionUseRequest {
                schema_id: schema_id(ADMISSION_USE_REQUEST_SCHEMA),
                request_id: stream_use_id.clone(),
                expected_authority_revision: runtime.admission_snapshot().authority_revision,
                token_id: stream_token.token_id.clone(),
                identity: identity("client.runtime.test"),
                capability_id: stream_capability.clone(),
                issued_at_ms: 2_000,
                expires_at_ms: 9_000,
            },
            3_000,
        );
        assert!(stream_use.applied);
        let stream_receipt = runtime.consume_capability_use(
            &stream_use_id,
            &stream_token.token_id,
            stream_use.resulting_authority_revision,
            &identity("client.runtime.test"),
            &stream_capability,
            4_000,
        );
        assert!(stream_receipt.applied);

        let command_token = runtime
            .issue_token(
                &ManifoldAdmissionRequest {
                    schema_id: schema_id(ADMISSION_REQUEST_SCHEMA),
                    request_id: id("request.runtime.command_capability.issue"),
                    expected_authority_revision: runtime.admission_snapshot().authority_revision,
                    identity: identity("client.runtime.test"),
                    requested_capabilities: vec![command_capability_id.clone()],
                    issued_at_ms: 1_000,
                    expires_at_ms: 10_000,
                    requested_token_ttl_ms: 20_000,
                },
                [10; 32],
                4_100,
            )
            .token
            .expect("command token");
        let command_use_id = id("request.runtime.command_capability.use");
        let command_use = runtime.authorize_use(
            &ManifoldAdmissionUseRequest {
                schema_id: schema_id(ADMISSION_USE_REQUEST_SCHEMA),
                request_id: command_use_id.clone(),
                expected_authority_revision: runtime.admission_snapshot().authority_revision,
                token_id: command_token.token_id.clone(),
                identity: identity("client.runtime.test"),
                capability_id: command_capability_id.clone(),
                issued_at_ms: 4_100,
                expires_at_ms: 9_000,
            },
            4_200,
        );
        assert!(command_use.applied);
        let command_rejection = runtime.consume_capability_use(
            &command_use_id,
            &command_token.token_id,
            command_use.resulting_authority_revision,
            &identity("client.runtime.test"),
            &command_capability_id,
            4_300,
        );
        assert!(!command_rejection.applied);
        assert_eq!(
            command_rejection.rejection_reason,
            Some(ManifoldBrokerMutationRejectionReason::CapabilityMismatch)
        );

        let evidence = runtime.evidence();
        assert_eq!(
            evidence.committed_capability_use_receipts,
            vec![stream_receipt]
        );
        assert!(evidence
            .pending_bounded_uses
            .iter()
            .any(|use_| use_.admission_use_request_id == command_use_id));
        runtime
            .staged_copy()
            .expect("capability receipt and pending command survive restart");
        let mut missing_receipt = evidence;
        missing_receipt.committed_capability_use_receipts.clear();
        assert_runtime_evidence_rejected_after_json(&runtime, &missing_receipt);
    }

    #[test]
    fn observer_rejection_cannot_roll_back_a_one_use_mutation() {
        let command_id = "command.media.session.start";
        let lease = ManifoldRuntimeLease {
            lease_id: id("lease.media.session.runtime.observer"),
            scope: id("lease.media.session"),
            holder_id: id("client.runtime.test"),
            expires_at_ms: 60_000,
            derivative_binding: None,
        };
        let mut runtime = runtime(
            vec![ManifoldBrokerFeature::MediaSession],
            vec![command_capability(&id(command_id))],
            vec![lease],
            "epoch.runtime.observer",
        );
        let (use_id, token_id) = admit(&mut runtime, command_id);
        let request = mutation(
            "epoch.runtime.observer",
            use_id,
            token_id,
            command(command_id, Some("lease.media.session.runtime.observer")),
        );
        let observed = runtime
            .commit_mutation(&request, 4_000, |receipt, _| {
                assert!(receipt.admission_applied && receipt.applied);
                Err::<(), _>("downstream rejected")
            })
            .expect("candidate reconstruction");
        assert_eq!(observed, Err("downstream rejected"));

        let replay = runtime.handle_mutation(&request, 4_100);
        assert_eq!(
            replay.admission_rejection_reason,
            Some(ManifoldBrokerMutationRejectionReason::ReplayedAdmissionUse)
        );
        assert_eq!(runtime.host_snapshot().authority_revision.get(), 2);
    }

    #[test]
    fn two_clients_keep_independent_pending_uses_across_global_revision_advances() {
        let command_id = "command.session.list";
        let epoch = "epoch.runtime.two_client.advance";
        let mut runtime = two_client_runtime(command_id, epoch);
        let (alpha_use, alpha_token, alpha_revision) = admit_for_client(
            &mut runtime,
            command_id,
            "client.runtime.alpha",
            "alpha",
            1,
            11,
            20_000,
        );
        let (beta_use, beta_token, beta_revision) = admit_for_client(
            &mut runtime,
            command_id,
            "client.runtime.beta",
            "beta",
            3,
            22,
            20_000,
        );
        assert_eq!(alpha_revision.get(), 3);
        assert_eq!(beta_revision.get(), 5);
        assert_eq!(runtime.admission_snapshot().authority_revision.get(), 5);

        let alpha = runtime.handle_mutation(
            &client_mutation(
                epoch,
                alpha_use,
                alpha_token,
                alpha_revision,
                client_command(command_id, "client.runtime.alpha", "alpha", 1),
            ),
            4_000,
        );
        assert!(alpha.applied);
        assert_eq!(alpha.admission_authority_revision.get(), 5);

        let beta = runtime.handle_mutation(
            &client_mutation(
                epoch,
                beta_use,
                beta_token,
                beta_revision,
                client_command(command_id, "client.runtime.beta", "beta", 2),
            ),
            4_000,
        );
        assert!(beta.applied);
        assert_eq!(runtime.host_snapshot().authority_revision.get(), 3);
    }

    #[test]
    fn legacy_runtime_evidence_rebinds_pending_use_through_exact_migrated_token() {
        let seed = runtime(
            Vec::new(),
            vec![id("capability.command.session.list")],
            Vec::new(),
            "provider.runtime.seed.001",
        );
        let adapter = seed.adapter;
        let control_lease_authority = seed.control_lease_authority;
        let json = include_str!("../../../fixtures/broker-adapter/legacy-v1-runtime-evidence.json");
        let binding = ManifoldAdmissionLegacyClientLockBinding {
            grant_id: id("grant.runtime.test"),
            client_lock_id: id("lock.client.runtime.test"),
            client_lock_fingerprint: format!("sha256:{}", "c1".repeat(32)),
        };
        let (restored_runtime, receipt) = ManifoldBrokerRuntime::from_legacy_evidence_json(
            adapter,
            control_lease_authority,
            json,
            std::slice::from_ref(&binding),
        )
        .expect("legacy broker runtime migration");
        assert_eq!(
            receipt.source_schema_id.as_str(),
            LEGACY_BROKER_RUNTIME_EVIDENCE_V1_SCHEMA
        );
        assert!(receipt.admission_migration.migrated);
        assert!(receipt.runtime_host_migration.migrated);
        assert_eq!(receipt.migrated_pending_bounded_use_ids.len(), 1);
        let pending = &restored_runtime.evidence().pending_bounded_uses[0];
        assert_eq!(pending.schema_id.as_str(), BROKER_BOUNDED_USE_SCHEMA);
        assert_eq!(pending.identity.client_id, id("client.runtime.test"));
        assert_eq!(pending.admission_grant_id, binding.grant_id);
        assert_eq!(pending.client_lock_id, binding.client_lock_id);
        assert_eq!(
            pending.client_lock_fingerprint,
            binding.client_lock_fingerprint
        );

        let seed = runtime(
            Vec::new(),
            vec![id("capability.command.session.list")],
            Vec::new(),
            "provider.runtime.seed.002",
        );
        let mut damaged: serde_json::Value = serde_json::from_str(json).expect("legacy evidence");
        damaged["pending_bounded_uses"][0]["client_id"] =
            serde_json::Value::String("client.runtime.forged".to_owned());
        let damaged = serde_json::to_string(&damaged).expect("damaged legacy evidence");
        assert!(ManifoldBrokerRuntime::from_legacy_evidence_json(
            seed.adapter,
            seed.control_lease_authority,
            &damaged,
            &[binding],
        )
        .is_err());
    }

    #[test]
    fn v3_restart_requires_fresh_owner_and_exact_host_lease_closure() {
        let lease = ManifoldRuntimeLease {
            lease_id: id("lease.media.session.runtime.restart"),
            scope: id("lease.media.session"),
            holder_id: id("client.runtime.test"),
            expires_at_ms: 60_000,
            derivative_binding: None,
        };
        let runtime = runtime(
            vec![ManifoldBrokerFeature::MediaSession],
            vec![command_capability(&id("command.media.session.start"))],
            vec![lease],
            "provider.runtime.v3.restart",
        );
        let evidence = runtime.evidence();
        assert_eq!(evidence.schema_id.as_str(), BROKER_RUNTIME_EVIDENCE_SCHEMA);
        let encoded = serde_json::to_string(&evidence).expect("runtime evidence");
        let decoded: ManifoldBrokerRuntimeEvidence =
            serde_json::from_str(&encoded).expect("runtime evidence round-trip");
        let config = runtime.adapter.config.clone();
        let packaged_lock =
            serde_json::to_vec(&runtime.adapter.product_lock).expect("packaged lock");
        let host_json = runtime.adapter.snapshot_json().expect("host snapshot");

        let retained = evidence
            .control_lease_authority
            .current_authority_snapshot
            .clone();
        let mut fresh_clock = evidence.control_lease_authority.current_clock.clone();
        fresh_clock.sequence += 1;
        fresh_clock.monotonic_elapsed_ns += 1;
        fresh_clock.wall_unix_ms += 1;
        let authority = ManifoldBrokerControlLeaseAuthority::refresh_from_v2_evidence(
            evidence.control_lease_authority.clone(),
            retained.clone(),
            fresh_clock.clone(),
        )
        .expect("fresh authority");
        let adapter = ManifoldBrokerAdapter::restart_from_json(
            config.clone(),
            &packaged_lock,
            &host_json,
            &authority,
        )
        .expect("authority-closed adapter restart");
        let restored = ManifoldBrokerRuntime::restore_from_caller_attested_exclusive_evidence(
            adapter, authority, decoded,
        )
        .expect("v3 restart");
        assert_eq!(
            restored
                .evidence()
                .control_lease_authority
                .current_clock
                .sequence,
            fresh_clock.sequence
        );

        let mut legacy_v2 = evidence.clone();
        legacy_v2.schema_id = schema_id(LEGACY_BROKER_RUNTIME_EVIDENCE_V2_SCHEMA);
        let authority = ManifoldBrokerControlLeaseAuthority::refresh_from_v2_evidence(
            evidence.control_lease_authority.clone(),
            retained.clone(),
            fresh_clock.clone(),
        )
        .expect("fresh authority");
        let adapter = ManifoldBrokerAdapter::restart_from_json(
            config.clone(),
            &packaged_lock,
            &host_json,
            &authority,
        )
        .expect("adapter");
        assert!(matches!(
            ManifoldBrokerRuntime::restore_from_caller_attested_exclusive_evidence(
                adapter, authority, legacy_v2,
            ),
            Err(ManifoldBrokerRuntimeStateError::InvalidEvidence(
                "schema_host_or_capacity"
            ))
        ));

        let mut damaged_host = evidence.host_snapshot;
        damaged_host.leases[0].holder_id = id("holder.host_only.substitution");
        let damaged_json = serde_json::to_string(&damaged_host).expect("damaged host");
        let authority = ManifoldBrokerControlLeaseAuthority::refresh_from_v2_evidence(
            evidence.control_lease_authority,
            retained,
            fresh_clock,
        )
        .expect("fresh authority");
        assert!(matches!(
            ManifoldBrokerAdapter::restart_from_json(
                config,
                &packaged_lock,
                &damaged_json,
                &authority,
            ),
            Err(crate::ManifoldBrokerAdapterError::ControlLeaseAuthority(
                ManifoldBrokerControlLeaseAuthorityError::HostLeaseSetMismatch
            ))
        ));
    }

    #[test]
    fn released_v4_runtime_evidence_requires_exact_revocation_migration() {
        let evidence_json =
            include_str!("../../../fixtures/broker-adapter/runtime-evidence-v4.json");
        let legacy: LegacyManifoldBrokerRuntimeEvidenceV4 =
            serde_json::from_str(evidence_json).expect("committed v4 evidence");
        let adapter = adapter_for_legacy_v4(&legacy);
        let (runtime, receipt) =
            ManifoldBrokerRuntime::migrate_v4_evidence_json(adapter, evidence_json)
                .expect("explicit v4 revocation migration");
        let evidence = runtime.evidence();
        receipt
            .validate_against(evidence_json, &evidence)
            .expect("migration receipt binding");
        assert_eq!(evidence.schema_id.as_str(), BROKER_RUNTIME_EVIDENCE_SCHEMA);
        assert!(evidence.control_lease_revocation_barriers.is_empty());
        assert!(receipt.synthesized_revocation_barrier_ids.is_empty());
        assert_eq!(
            receipt.source_schema_id.as_str(),
            LEGACY_BROKER_RUNTIME_EVIDENCE_V4_SCHEMA
        );
    }

    #[test]
    fn released_v3_migration_preserves_generic_uses_without_lifecycle_promotion() {
        let legacy_json = include_str!("../../../fixtures/broker-adapter/runtime-evidence-v3.json");
        let legacy: LegacyManifoldBrokerRuntimeEvidenceV3 =
            serde_json::from_str(legacy_json).expect("released v3 evidence");
        let current: LegacyManifoldBrokerRuntimeEvidenceV4 = serde_json::from_str(include_str!(
            "../../../fixtures/broker-adapter/runtime-evidence-v4.json"
        ))
        .expect("current v4 evidence");
        let authority = ManifoldBrokerControlLeaseAuthority::migrate_v1_evidence(
            legacy.control_lease_authority.clone(),
            legacy
                .control_lease_authority
                .current_authority_snapshot
                .clone(),
            legacy.control_lease_authority.current_clock.clone(),
        )
        .expect("v1 owner migration");
        let adapter = adapter_for_legacy_v4(&current);
        let (runtime, receipt) =
            ManifoldBrokerRuntime::from_legacy_v3_evidence_json(adapter, authority, legacy_json)
                .expect("v3 lifecycle migration");
        let migrated = runtime.evidence();
        assert_eq!(
            receipt.source_schema_id.as_str(),
            LEGACY_BROKER_RUNTIME_EVIDENCE_V3_SCHEMA
        );
        assert_eq!(
            receipt.resulting_schema_id.as_str(),
            BROKER_RUNTIME_EVIDENCE_SCHEMA
        );
        assert_eq!(migrated.pending_bounded_uses, legacy.pending_bounded_uses);
        assert!(migrated.pending_control_lease_lifecycle_uses.is_empty());
        assert!(migrated.control_lease_lifecycle_receipts.is_empty());
        assert!(receipt.synthesized_lifecycle_use_ids.is_empty());
        assert!(receipt.synthesized_lifecycle_receipt_ids.is_empty());
    }

    #[test]
    fn synchronized_issue_renew_release_survives_restart_and_consumes_each_use_once() {
        let lifecycle_capabilities = [
            ManifoldBrokerControlLeaseLifecycleOperationKind::Issue,
            ManifoldBrokerControlLeaseLifecycleOperationKind::Renewal,
            ManifoldBrokerControlLeaseLifecycleOperationKind::Release,
        ]
        .into_iter()
        .map(control_lease_lifecycle_capability)
        .collect();
        let mut runtime = runtime(
            vec![ManifoldBrokerFeature::MediaSession],
            lifecycle_capabilities,
            Vec::new(),
            "provider.runtime.lifecycle",
        );

        let issue_authority_revision = runtime
            .control_lease_authority_snapshot()
            .authority_revision;
        let issue = authorize_lifecycle(
            &mut runtime,
            ManifoldBrokerControlLeaseLifecycleOperation::Issue {
                request_id: id("request.lifecycle.issue"),
                expected_authority_revision: issue_authority_revision,
                scope: id("lease.media.session"),
                requested_ttl_ms: 30_000,
                required_capability: id("manifold.command.request"),
                safety_class: SafetyClass::BoundedMutation,
            },
            "issue",
            11,
            None,
        );
        let pending_evidence = runtime.evidence();
        for damage_resulting_revision in [false, true] {
            let mut damaged = pending_evidence.clone();
            let use_ = &mut damaged.pending_control_lease_lifecycle_uses[0];
            if damage_resulting_revision {
                use_.bounded_use.admission_authority_revision =
                    use_.authorized_from_admission_authority_revision;
            } else {
                use_.authorized_from_admission_authority_revision =
                    use_.bounded_use.admission_authority_revision;
            }
            let owner = ManifoldBrokerControlLeaseAuthority::refresh_from_v2_evidence(
                pending_evidence.control_lease_authority.clone(),
                pending_evidence
                    .control_lease_authority
                    .current_authority_snapshot
                    .clone(),
                pending_evidence
                    .control_lease_authority
                    .current_clock
                    .clone(),
            )
            .expect("owner restore");
            assert!(
                ManifoldBrokerRuntime::restore_from_caller_attested_exclusive_evidence(
                    runtime.adapter.clone(),
                    owner,
                    damaged,
                )
                .is_err()
            );
        }
        let issue_clock = next_control_lease_clock(&runtime, 100);
        let (issue_receipt, issue_evidence) = runtime
            .commit_control_lease_lifecycle(
                &issue,
                issue_clock,
                vec![id("evidence.lifecycle.issue")],
                |receipt, evidence| (receipt.clone(), evidence.clone()),
            )
            .expect("issue commit");
        assert!(issue_receipt.applied, "{issue_receipt:?}");
        assert_eq!(issue_evidence.host_snapshot.leases.len(), 1);
        assert_eq!(issue_evidence.control_lease_authority.transitions.len(), 1);
        let issue_replay = runtime
            .commit_control_lease_lifecycle(
                &issue,
                next_control_lease_clock(&runtime, 1),
                vec![id("evidence.lifecycle.issue.replay")],
                |receipt, _| receipt.clone(),
            )
            .expect("issue replay receipt");
        assert_eq!(
            issue_replay.rejection_reason,
            Some(ManifoldBrokerControlLeaseLifecycleRejectionReason::ReplayedLifecycleUse)
        );

        runtime = runtime.staged_copy().expect("restart after issue");
        let lease_id = runtime.host_snapshot().leases[0].lease_id.clone();
        let prior_expiry = runtime.host_snapshot().leases[0].expires_at_ms;
        let renewal_authority_revision = runtime
            .control_lease_authority_snapshot()
            .authority_revision;
        let renewal_requested_at_ms =
            u64::try_from(runtime.control_lease_authority.current_clock().wall_unix_ms)
                .expect("wall clock");
        let renewal = authorize_lifecycle(
            &mut runtime,
            ManifoldBrokerControlLeaseLifecycleOperation::Renewal {
                request_id: id("request.lifecycle.renewal"),
                lease_id: lease_id.clone(),
                expected_authority_revision: renewal_authority_revision,
                requested_ttl_ms: 45_000,
                renewal_reason: id("reason.lifecycle.renewal"),
                requested_at_ms: renewal_requested_at_ms,
            },
            "renewal",
            12,
            None,
        );
        let renewal_receipt = runtime
            .commit_control_lease_lifecycle(
                &renewal,
                next_control_lease_clock(&runtime, 100),
                vec![id("evidence.lifecycle.renewal")],
                |receipt, _| receipt.clone(),
            )
            .expect("renewal commit");
        assert!(renewal_receipt.applied);
        assert_eq!(runtime.host_snapshot().leases[0].lease_id, lease_id);
        assert!(runtime.host_snapshot().leases[0].expires_at_ms > prior_expiry);

        runtime = runtime.staged_copy().expect("restart after renewal");
        let release_authority_revision = runtime
            .control_lease_authority_snapshot()
            .authority_revision;
        let release_requested_at_ms =
            u64::try_from(runtime.control_lease_authority.current_clock().wall_unix_ms)
                .expect("wall clock");
        let release = authorize_lifecycle(
            &mut runtime,
            ManifoldBrokerControlLeaseLifecycleOperation::Release {
                request_id: id("request.lifecycle.release"),
                lease_id,
                expected_authority_revision: release_authority_revision,
                release_reason: id("reason.lifecycle.release"),
                requested_at_ms: release_requested_at_ms,
            },
            "release",
            13,
            None,
        );
        let (release_receipt, final_evidence) = runtime
            .commit_control_lease_lifecycle(
                &release,
                next_control_lease_clock(&runtime, 100),
                vec![id("evidence.lifecycle.release")],
                |receipt, evidence| (receipt.clone(), evidence.clone()),
            )
            .expect("release commit");
        assert!(release_receipt.applied);
        assert!(final_evidence.host_snapshot.leases.is_empty());
        assert_eq!(final_evidence.control_lease_authority.transitions.len(), 3);
        assert_eq!(final_evidence.control_lease_lifecycle_receipts.len(), 3);
        runtime.staged_copy().expect("final lifecycle restart");

        let prior_host_revision = runtime.host_snapshot().authority_revision;
        let prior_host_audit_count = runtime.host_snapshot().audit_events.len();
        let mut fresh_admission = runtime.admission_snapshot().clone();
        fresh_admission.authority_id = id("authority.admission.runtime.rollover");
        fresh_admission.authority_revision = Revision::INITIAL;
        fresh_admission.active_tokens.clear();
        fresh_admission.revoked_token_ids.clear();
        fresh_admission.consumed_request_ids.clear();
        fresh_admission.consumed_use_request_ids.clear();
        fresh_admission.reviewed_sweep_ids.clear();
        fresh_admission.audit_events.clear();
        let rollover = runtime
            .rollover_drained_provider_epoch(id("provider.runtime.lifecycle.next"), fresh_admission)
            .expect("drained epoch rollover");
        assert_eq!(
            rollover.compacted_owner_transition_count,
            final_evidence.control_lease_authority.transitions.len()
        );
        assert_eq!(
            rollover.checkpointed_lifecycle_receipt_count,
            final_evidence.control_lease_lifecycle_receipts.len()
        );
        assert_eq!(
            runtime.provider_epoch_id().as_str(),
            "provider.runtime.lifecycle.next"
        );
        assert_eq!(
            rollover.checkpointed_control_lease_request_count,
            final_evidence.control_lease_lifecycle_receipts.len()
        );
        assert!(runtime
            .evidence()
            .control_lease_authority
            .transitions
            .is_empty());
        assert!(runtime.evidence().consumed_bounded_use_ids.is_empty());
        assert!(runtime
            .evidence()
            .compacted_control_lease_request_ids
            .contains(release.operation.request_id()));
        assert_eq!(
            runtime.host_snapshot().authority_revision,
            prior_host_revision
        );
        assert_eq!(
            runtime.host_snapshot().audit_events.len(),
            prior_host_audit_count
        );
        let old_epoch_replay = runtime
            .commit_control_lease_lifecycle(
                &release,
                next_control_lease_clock(&runtime, 1),
                vec![id("evidence.lifecycle.old_epoch")],
                |receipt, _| receipt.clone(),
            )
            .expect("old epoch rejection");
        assert_eq!(
            old_epoch_replay.rejection_reason,
            Some(ManifoldBrokerControlLeaseLifecycleRejectionReason::ProviderEpochMismatch)
        );

        let mut compacted_replay = release.clone();
        compacted_replay.provider_epoch_id = runtime.provider_epoch_id().clone();
        compacted_replay.admission_use_request_id = id("request.lifecycle.compacted_replay.use");
        compacted_replay.token_id = id("token.lifecycle.compacted_replay");
        compacted_replay.expected_admission_authority_revision =
            runtime.admission_snapshot().authority_revision;
        if let ManifoldBrokerControlLeaseLifecycleOperation::Release {
            expected_authority_revision,
            ..
        } = &mut compacted_replay.operation
        {
            *expected_authority_revision = runtime
                .control_lease_authority_snapshot()
                .authority_revision;
        }
        let compacted_replay_authorization = runtime.authorize_control_lease_lifecycle_use(
            &ManifoldAdmissionUseRequest {
                schema_id: schema_id(ADMISSION_USE_REQUEST_SCHEMA),
                request_id: compacted_replay.admission_use_request_id.clone(),
                expected_authority_revision: runtime.admission_snapshot().authority_revision,
                token_id: compacted_replay.token_id.clone(),
                identity: identity("client.runtime.test"),
                capability_id: control_lease_lifecycle_capability(
                    ManifoldBrokerControlLeaseLifecycleOperationKind::Release,
                ),
                issued_at_ms: 1,
                expires_at_ms: 2,
            },
            &compacted_replay,
            1,
        );
        assert_eq!(
            compacted_replay_authorization.rejection_reason,
            Some(ManifoldBrokerControlLeaseLifecycleRejectionReason::ReplayedLifecycleRequest)
        );
    }

    #[test]
    fn administrative_revocation_by_non_holder_converges_owner_host_and_restart() {
        let lease_id = id("lease.media.session.lifecycle.revocation.admin");
        let mut runtime = runtime(
            vec![ManifoldBrokerFeature::MediaSession],
            vec![control_lease_lifecycle_capability(
                ManifoldBrokerControlLeaseLifecycleOperationKind::Revocation,
            )],
            vec![ManifoldRuntimeLease {
                lease_id: lease_id.clone(),
                scope: id("lease.media.session"),
                holder_id: id("holder.runtime.revocation"),
                expires_at_ms: 60_000,
                derivative_binding: None,
            }],
            "provider.runtime.lifecycle.revocation.admin",
        );
        let authority_revision = runtime
            .control_lease_authority_snapshot()
            .authority_revision;
        let requested_at_ms =
            u64::try_from(runtime.control_lease_authority.current_clock().wall_unix_ms)
                .expect("wall clock");
        let request = authorize_lifecycle(
            &mut runtime,
            ManifoldBrokerControlLeaseLifecycleOperation::Revocation {
                request_id: id("request.lifecycle.revocation.admin"),
                lease_id: lease_id.clone(),
                expected_authority_revision: authority_revision,
                revocation_reason: id("reason.security.operator_revocation"),
                requested_at_ms,
            },
            "revocation.admin",
            41,
            None,
        );
        let receipt = runtime
            .commit_control_lease_lifecycle(
                &request,
                next_control_lease_clock(&runtime, 100),
                vec![id("evidence.lifecycle.revocation.admin")],
                |receipt, _| receipt.clone(),
            )
            .expect("administrative revocation");
        assert!(receipt.applied, "{receipt:?}");
        assert_eq!(
            receipt.operation_kind,
            ManifoldBrokerControlLeaseLifecycleOperationKind::Revocation
        );
        assert!(runtime.host_snapshot().leases.is_empty());
        assert!(runtime
            .control_lease_authority_snapshot()
            .active_leases
            .is_empty());
        let evidence = runtime.evidence();
        assert_eq!(evidence.control_lease_revocation_barriers.len(), 1);
        let barrier = evidence.control_lease_revocation_barriers[0].clone();
        assert_eq!(barrier.lease_id, lease_id);
        assert_eq!(
            barrier.state,
            ManifoldBrokerControlLeaseRevocationBarrierState::Converged
        );
        assert!(barrier
            .host_adoption
            .as_ref()
            .is_some_and(|value| value.applied));
        assert_eq!(
            evidence
                .control_lease_authority
                .current_authority_snapshot
                .schema_id
                .as_str(),
            "rusty.manifold.authority.snapshot.v2"
        );
        assert_eq!(
            evidence
                .control_lease_authority
                .current_authority_snapshot
                .revoked_control_lease_tombstones
                .len(),
            1
        );
        runtime.staged_copy().expect("revocation restart");

        let fake_recovery_request = ManifoldBrokerControlLeaseRevocationRecoveryRequest {
            schema_id: schema_id(BROKER_CONTROL_LEASE_REVOCATION_RECOVERY_REQUEST_SCHEMA),
            recovery_id: id("recovery.revocation.admin.forged"),
            provider_epoch_id: runtime.provider_epoch_id().clone(),
            barrier_id: barrier.barrier_id.clone(),
            expected_control_lease_authority_revision: runtime
                .control_lease_authority_snapshot()
                .authority_revision,
            expected_host_authority_revision: runtime.host_snapshot().authority_revision,
        };
        let prior_owner_revision = barrier
            .authority_transition
            .prior_authority_snapshot
            .authority_revision;
        let prior_host_revision = barrier
            .host_adoption
            .as_ref()
            .expect("direct Host adoption")
            .prior_host_authority_revision;
        let mut forged_applied_recovery = evidence.clone();
        forged_applied_recovery
            .control_lease_revocation_recovery_receipts
            .push(revocation_recovery_receipt(
                runtime.provider_epoch_id(),
                &fake_recovery_request,
                Some(&barrier),
                prior_owner_revision,
                prior_host_revision,
                Some(barrier.authority_transition.clone()),
                barrier.host_adoption.clone(),
                None,
            ));
        assert_runtime_evidence_rejected_after_json(&runtime, &forged_applied_recovery);

        let mut forged_rejected_recovery = evidence;
        forged_rejected_recovery
            .control_lease_revocation_recovery_receipts
            .push(revocation_recovery_receipt(
                runtime.provider_epoch_id(),
                &fake_recovery_request,
                Some(&barrier),
                prior_owner_revision,
                prior_host_revision,
                None,
                None,
                Some(ManifoldBrokerControlLeaseLifecycleRejectionReason::RevokedLease),
            ));
        assert_runtime_evidence_rejected_after_json(&runtime, &forged_rejected_recovery);

        let replay = runtime
            .commit_control_lease_lifecycle(
                &request,
                next_control_lease_clock(&runtime, 1),
                vec![id("evidence.lifecycle.revocation.admin.replay")],
                |receipt, _| receipt.clone(),
            )
            .expect("replay receipt");
        assert_eq!(
            replay.rejection_reason,
            Some(ManifoldBrokerControlLeaseLifecycleRejectionReason::RevokedLease)
        );

        let mut fresh_admission = runtime.admission_snapshot().clone();
        fresh_admission.authority_id = id("authority.admission.revocation.rollover");
        fresh_admission.authority_revision = Revision::INITIAL;
        fresh_admission.active_tokens.clear();
        fresh_admission.revoked_token_ids.clear();
        fresh_admission.consumed_request_ids.clear();
        fresh_admission.consumed_use_request_ids.clear();
        fresh_admission.reviewed_sweep_ids.clear();
        fresh_admission.audit_events.clear();
        assert!(runtime
            .rollover_drained_provider_epoch(
                id("provider.runtime.lifecycle.revocation.unacknowledged"),
                fresh_admission.clone(),
            )
            .is_err());

        runtime
            .acknowledge_control_lease_revocation_consumer(
                ManifoldBrokerControlLeaseRevocationConsumerAcknowledgement {
                    schema_id: schema_id(
                        BROKER_CONTROL_LEASE_REVOCATION_CONSUMER_ACKNOWLEDGEMENT_SCHEMA,
                    ),
                    acknowledgement_id: id("ack.revocation.admin.peer_runtime_host"),
                    provider_epoch_id: runtime.provider_epoch_id().clone(),
                    barrier_id: barrier.barrier_id.clone(),
                    revocation_application_id: barrier.revocation_application_id.clone(),
                    lease_id: barrier.lease_id.clone(),
                    consumer_kind:
                        ManifoldBrokerControlLeaseRevocationConsumerKind::PeerRuntimeHost,
                    consumer_id: id("peer_runtime_host.revocation.admin"),
                    consumer_convergence_receipt_sha256: format!("sha256:{}", "11".repeat(32)),
                    terminal_cleanup_receipt_sha256: format!("sha256:{}", "22".repeat(32)),
                },
            )
            .expect("terminal peer acknowledgement");
        runtime
            .staged_copy()
            .expect("acknowledged revocation restart");
        let rollover = runtime
            .rollover_drained_provider_epoch(
                id("provider.runtime.lifecycle.revocation.next"),
                fresh_admission,
            )
            .expect("acknowledged revocation rollover");
        assert_eq!(rollover.checkpointed_revocation_barrier_count, 1);
        assert_eq!(
            rollover.checkpointed_revocation_consumer_acknowledgement_count,
            1
        );
        let rolled = runtime.evidence();
        assert!(rolled.control_lease_revocation_barriers.is_empty());
        assert!(rolled
            .control_lease_revocation_consumer_acknowledgements
            .is_empty());
        assert_eq!(
            rolled
                .control_lease_authority
                .current_authority_snapshot
                .revoked_control_lease_tombstones
                .len(),
            1
        );
    }

    #[test]
    fn revocation_invalidates_same_lease_uses_and_blocks_prepared_commands() {
        let command_id = "command.media.session.start";
        let lease_id = id("lease.media.session.lifecycle.revocation.block");
        let capabilities = vec![
            command_capability(&id(command_id)),
            control_lease_lifecycle_capability(
                ManifoldBrokerControlLeaseLifecycleOperationKind::Renewal,
            ),
            control_lease_lifecycle_capability(
                ManifoldBrokerControlLeaseLifecycleOperationKind::Revocation,
            ),
        ];
        let mut runtime = runtime(
            vec![ManifoldBrokerFeature::MediaSession],
            capabilities,
            vec![ManifoldRuntimeLease {
                lease_id: lease_id.clone(),
                scope: id("lease.media.session"),
                holder_id: id("client.runtime.test"),
                expires_at_ms: 60_000,
                derivative_binding: None,
            }],
            "provider.runtime.lifecycle.revocation.block",
        );
        let (command_use_id, command_token_id) = admit(&mut runtime, command_id);
        let authority_revision = runtime
            .control_lease_authority_snapshot()
            .authority_revision;
        let requested_at_ms =
            u64::try_from(runtime.control_lease_authority.current_clock().wall_unix_ms)
                .expect("wall clock");
        let pending_renewal = authorize_lifecycle(
            &mut runtime,
            ManifoldBrokerControlLeaseLifecycleOperation::Renewal {
                request_id: id("request.lifecycle.revocation.pending_renewal"),
                lease_id: lease_id.clone(),
                expected_authority_revision: authority_revision,
                requested_ttl_ms: 45_000,
                renewal_reason: id("reason.lifecycle.pending_renewal"),
                requested_at_ms,
            },
            "revocation.pending_renewal",
            42,
            None,
        );
        let revocation = authorize_lifecycle(
            &mut runtime,
            ManifoldBrokerControlLeaseLifecycleOperation::Revocation {
                request_id: id("request.lifecycle.revocation.block"),
                lease_id: lease_id.clone(),
                expected_authority_revision: authority_revision,
                revocation_reason: id("reason.security.block"),
                requested_at_ms,
            },
            "revocation.block",
            43,
            None,
        );
        let receipt = runtime
            .commit_control_lease_lifecycle(
                &revocation,
                next_control_lease_clock(&runtime, 100),
                vec![id("evidence.lifecycle.revocation.block")],
                |receipt, _| receipt.clone(),
            )
            .expect("revocation");
        assert!(receipt.applied);
        let evidence = runtime.evidence();
        assert_eq!(evidence.control_lease_revocation_use_invalidations.len(), 1);
        assert_eq!(
            evidence.control_lease_revocation_use_invalidations[0].admission_use_request_id,
            pending_renewal.admission_use_request_id
        );
        assert!(evidence
            .invalidated_control_lease_lifecycle_use_ids
            .contains(&pending_renewal.admission_use_request_id));

        let blocked_renewal = runtime
            .commit_control_lease_lifecycle(
                &pending_renewal,
                next_control_lease_clock(&runtime, 1),
                vec![id("evidence.lifecycle.revocation.pending_renewal")],
                |receipt, _| receipt.clone(),
            )
            .expect("blocked renewal");
        assert_eq!(
            blocked_renewal.rejection_reason,
            Some(ManifoldBrokerControlLeaseLifecycleRejectionReason::RevokedLease)
        );

        let blocked_command = runtime.handle_mutation(
            &mutation(
                "provider.runtime.lifecycle.revocation.block",
                command_use_id.clone(),
                command_token_id,
                command(command_id, Some(lease_id.as_str())),
            ),
            4_000,
        );
        assert_eq!(
            blocked_command.admission_rejection_reason,
            Some(ManifoldBrokerMutationRejectionReason::RevokedControlLease)
        );
        assert!(runtime.pending_bounded_uses.contains_key(&command_use_id));
        runtime.staged_copy().expect("barrier restart");

        let mut missing_barrier = evidence.clone();
        missing_barrier.control_lease_revocation_barriers.clear();
        assert_runtime_evidence_rejected_after_json(&runtime, &missing_barrier);
        let mut missing_invalidation = evidence;
        missing_invalidation
            .control_lease_revocation_use_invalidations
            .clear();
        assert_runtime_evidence_rejected_after_json(&runtime, &missing_invalidation);
    }

    #[test]
    fn synchronized_expiry_removes_only_product_leases_and_rejects_replay() {
        let mut runtime = runtime(
            vec![ManifoldBrokerFeature::MediaSession],
            vec![control_lease_lifecycle_capability(
                ManifoldBrokerControlLeaseLifecycleOperationKind::Expiry,
            )],
            vec![ManifoldRuntimeLease {
                lease_id: id("lease.media.session.lifecycle.expiry"),
                scope: id("lease.media.session"),
                holder_id: id("client.runtime.test"),
                expires_at_ms: 60_000,
                derivative_binding: None,
            }],
            "provider.runtime.lifecycle.expiry",
        );
        let expiry_wall = runtime.host_snapshot().leases[0].expires_at_ms + 1;
        let expiry_authority_revision = runtime
            .control_lease_authority_snapshot()
            .authority_revision;
        let expiry_lease_id = runtime.host_snapshot().leases[0].lease_id.clone();
        let expiry = authorize_lifecycle(
            &mut runtime,
            ManifoldBrokerControlLeaseLifecycleOperation::Expiry {
                request_id: id("request.lifecycle.expiry"),
                lease_ids: vec![expiry_lease_id],
                expected_authority_revision: expiry_authority_revision,
                sweep_reason: id("reason.lifecycle.expiry"),
                requested_at_ms: expiry_wall,
            },
            "expiry",
            14,
            Some(expiry_wall.saturating_sub(1_000)),
        );
        let mut expiry_clock = next_control_lease_clock(&runtime, 1);
        expiry_clock.wall_unix_ms = i64::try_from(expiry_wall).expect("wall clock");
        let receipt = runtime
            .commit_control_lease_lifecycle(
                &expiry,
                expiry_clock,
                vec![id("evidence.lifecycle.expiry")],
                |receipt, _| receipt.clone(),
            )
            .expect("expiry commit");
        assert!(receipt.applied, "{receipt:?}");
        assert!(runtime.host_snapshot().leases.is_empty());
        assert!(runtime
            .control_lease_authority_snapshot()
            .active_leases
            .is_empty());
        let replay = runtime.authorize_control_lease_lifecycle_use(
            &ManifoldAdmissionUseRequest {
                schema_id: schema_id(ADMISSION_USE_REQUEST_SCHEMA),
                request_id: id("request.lifecycle.expiry.replay.use"),
                expected_authority_revision: runtime.admission_snapshot().authority_revision,
                token_id: id("token.lifecycle.expiry.replay"),
                identity: identity("client.runtime.test"),
                capability_id: control_lease_lifecycle_capability(
                    ManifoldBrokerControlLeaseLifecycleOperationKind::Expiry,
                ),
                issued_at_ms: expiry_wall,
                expires_at_ms: expiry_wall + 1,
            },
            &ManifoldBrokerControlLeaseLifecycleRequest {
                schema_id: schema_id(BROKER_CONTROL_LEASE_LIFECYCLE_REQUEST_SCHEMA),
                provider_epoch_id: runtime.provider_epoch_id().clone(),
                admission_use_request_id: id("request.lifecycle.expiry.replay.use"),
                token_id: id("token.lifecycle.expiry.replay"),
                expected_admission_authority_revision: runtime
                    .admission_snapshot()
                    .authority_revision,
                operation: ManifoldBrokerControlLeaseLifecycleOperation::Expiry {
                    request_id: id("request.lifecycle.expiry"),
                    lease_ids: Vec::new(),
                    expected_authority_revision: runtime
                        .control_lease_authority_snapshot()
                        .authority_revision,
                    sweep_reason: id("reason.lifecycle.expiry.replay"),
                    requested_at_ms: expiry_wall,
                },
            },
            expiry_wall,
        );
        assert_eq!(
            replay.rejection_reason,
            Some(ManifoldBrokerControlLeaseLifecycleRejectionReason::ReplayedLifecycleRequest)
        );
    }

    #[test]
    fn restore_rejects_reused_lifecycle_use_and_swapped_host_adoption() {
        let capabilities = [
            ManifoldBrokerControlLeaseLifecycleOperationKind::Issue,
            ManifoldBrokerControlLeaseLifecycleOperationKind::Release,
        ]
        .into_iter()
        .map(control_lease_lifecycle_capability)
        .collect();
        let mut runtime = runtime(
            vec![ManifoldBrokerFeature::MediaSession],
            capabilities,
            Vec::new(),
            "provider.runtime.lifecycle.restore_damage",
        );

        for (index, suffix) in ["alpha", "beta"].into_iter().enumerate() {
            let issue_authority_revision = runtime
                .control_lease_authority_snapshot()
                .authority_revision;
            let issue = authorize_lifecycle(
                &mut runtime,
                ManifoldBrokerControlLeaseLifecycleOperation::Issue {
                    request_id: id(&format!("request.lifecycle.restore_damage.{suffix}.issue")),
                    expected_authority_revision: issue_authority_revision,
                    scope: id("lease.media.session"),
                    requested_ttl_ms: 30_000,
                    required_capability: id("manifold.command.request"),
                    safety_class: SafetyClass::BoundedMutation,
                },
                &format!("restore_damage.{suffix}.issue"),
                u8::try_from(21 + index).expect("entropy"),
                None,
            );
            let issue_receipt = runtime
                .commit_control_lease_lifecycle(
                    &issue,
                    next_control_lease_clock(&runtime, 100),
                    vec![id(&format!(
                        "evidence.lifecycle.restore_damage.{suffix}.issue"
                    ))],
                    |receipt, _| receipt.clone(),
                )
                .expect("issue commit");
            assert!(issue_receipt.applied);
            let lease_id = runtime.host_snapshot().leases[0].lease_id.clone();
            let requested_at_ms =
                u64::try_from(runtime.control_lease_authority.current_clock().wall_unix_ms)
                    .expect("wall clock");
            let release_authority_revision = runtime
                .control_lease_authority_snapshot()
                .authority_revision;
            let release = authorize_lifecycle(
                &mut runtime,
                ManifoldBrokerControlLeaseLifecycleOperation::Release {
                    request_id: id(&format!(
                        "request.lifecycle.restore_damage.{suffix}.release"
                    )),
                    lease_id,
                    expected_authority_revision: release_authority_revision,
                    release_reason: id("reason.lifecycle.restore_damage"),
                    requested_at_ms,
                },
                &format!("restore_damage.{suffix}.release"),
                u8::try_from(31 + index).expect("entropy"),
                None,
            );
            let release_receipt = runtime
                .commit_control_lease_lifecycle(
                    &release,
                    next_control_lease_clock(&runtime, 100),
                    vec![id(&format!(
                        "evidence.lifecycle.restore_damage.{suffix}.release"
                    ))],
                    |receipt, _| receipt.clone(),
                )
                .expect("release commit");
            assert!(release_receipt.applied);
        }

        runtime.staged_copy().expect("undamaged restart");
        let evidence = runtime.evidence();
        let issue_indices = evidence
            .control_lease_lifecycle_receipts
            .iter()
            .enumerate()
            .filter_map(|(index, receipt)| {
                (receipt.operation_kind == ManifoldBrokerControlLeaseLifecycleOperationKind::Issue)
                    .then_some(index)
            })
            .collect::<Vec<_>>();
        assert_eq!(issue_indices.len(), 2);

        let mut reused_use = evidence.clone();
        let first_use = reused_use.control_lease_lifecycle_receipts[issue_indices[0]]
            .lifecycle_use
            .clone()
            .expect("first lifecycle use");
        let second_use = reused_use.control_lease_lifecycle_receipts[issue_indices[1]]
            .lifecycle_use
            .as_mut()
            .expect("second lifecycle use");
        second_use.bounded_use = first_use.bounded_use;
        second_use.authorized_from_admission_authority_revision =
            first_use.authorized_from_admission_authority_revision;
        assert_runtime_evidence_rejected_after_json(&runtime, &reused_use);

        let mut missing_receipt = evidence.clone();
        missing_receipt
            .control_lease_lifecycle_receipts
            .remove(issue_indices[0]);
        assert_runtime_evidence_rejected_after_json(&runtime, &missing_receipt);

        let mut swapped_adoptions = evidence;
        let first_adoption = swapped_adoptions.control_lease_lifecycle_receipts[issue_indices[0]]
            .host_adoption
            .take();
        let second_adoption = swapped_adoptions.control_lease_lifecycle_receipts[issue_indices[1]]
            .host_adoption
            .take();
        swapped_adoptions.control_lease_lifecycle_receipts[issue_indices[0]].host_adoption =
            second_adoption;
        swapped_adoptions.control_lease_lifecycle_receipts[issue_indices[1]].host_adoption =
            first_adoption;
        assert_runtime_evidence_rejected_after_json(&runtime, &swapped_adoptions);
    }

    #[test]
    fn invalidated_lifecycle_authorization_remains_classified_across_restart() {
        let mut runtime = runtime(
            vec![ManifoldBrokerFeature::MediaSession],
            vec![control_lease_lifecycle_capability(
                ManifoldBrokerControlLeaseLifecycleOperationKind::Issue,
            )],
            Vec::new(),
            "provider.runtime.lifecycle.invalidated",
        );
        let owner_revision = runtime
            .control_lease_authority_snapshot()
            .authority_revision;
        let lifecycle_request = authorize_lifecycle(
            &mut runtime,
            ManifoldBrokerControlLeaseLifecycleOperation::Issue {
                request_id: id("request.lifecycle.invalidated.issue"),
                expected_authority_revision: owner_revision,
                scope: id("lease.media.session"),
                requested_ttl_ms: 30_000,
                required_capability: id("manifold.command.request"),
                safety_class: SafetyClass::BoundedMutation,
            },
            "invalidated.issue",
            41,
            None,
        );
        let admission_revision = runtime.admission_snapshot().authority_revision;
        let revoke = runtime.revoke_token(&ManifoldAdmissionRevocationRequest {
            schema_id: schema_id(ADMISSION_REVOCATION_REQUEST_SCHEMA),
            request_id: id("request.lifecycle.invalidated.revoke"),
            expected_authority_revision: admission_revision,
            token_id: lifecycle_request.token_id,
            identity: identity("client.runtime.test"),
            reason: id("reason.lifecycle.invalidated"),
        });
        assert!(revoke.applied);
        let evidence = runtime.evidence();
        assert!(evidence.pending_control_lease_lifecycle_uses.is_empty());
        assert_eq!(evidence.authorized_control_lease_lifecycle_uses.len(), 1);
        assert_eq!(
            evidence.invalidated_control_lease_lifecycle_use_ids.len(),
            1
        );
        assert!(evidence.control_lease_lifecycle_receipts.is_empty());
        runtime
            .staged_copy()
            .expect("invalidated lifecycle restart");

        let mut damaged = evidence;
        damaged.invalidated_control_lease_lifecycle_use_ids.clear();
        assert_runtime_evidence_rejected_after_json(&runtime, &damaged);
    }

    #[test]
    fn coupled_unrelated_expiry_consumes_once_without_owner_or_host_advance() {
        let mut runtime = runtime_with_authority_policy(
            vec![ManifoldBrokerFeature::MediaSession],
            vec![control_lease_lifecycle_capability(
                ManifoldBrokerControlLeaseLifecycleOperationKind::Expiry,
            )],
            vec![ManifoldRuntimeLease {
                lease_id: id("lease.media.session.lifecycle.coupled"),
                scope: id("lease.media.session"),
                holder_id: id("client.runtime.test"),
                expires_at_ms: 60_000,
                derivative_binding: None,
            }],
            "provider.runtime.lifecycle.coupled",
            true,
        );
        let product_lease = runtime.host_snapshot().leases[0].clone();
        let prior_owner_revision = runtime
            .control_lease_authority_snapshot()
            .authority_revision;
        let prior_host = runtime.host_snapshot().clone();
        let expiry_wall = product_lease.expires_at_ms + 1;
        let request = authorize_lifecycle(
            &mut runtime,
            ManifoldBrokerControlLeaseLifecycleOperation::Expiry {
                request_id: id("request.lifecycle.coupled"),
                lease_ids: vec![product_lease.lease_id],
                expected_authority_revision: prior_owner_revision,
                sweep_reason: id("reason.lifecycle.coupled"),
                requested_at_ms: expiry_wall,
            },
            "coupled",
            15,
            Some(expiry_wall.saturating_sub(1_000)),
        );
        let mut expiry_clock = next_control_lease_clock(&runtime, 1);
        expiry_clock.wall_unix_ms = i64::try_from(expiry_wall).expect("wall clock");
        let receipt = runtime
            .commit_control_lease_lifecycle(
                &request,
                expiry_clock,
                vec![id("evidence.lifecycle.coupled")],
                |receipt, _| receipt.clone(),
            )
            .expect("coupled expiry result");
        assert_eq!(
            receipt.outcome,
            ManifoldBrokerControlLeaseLifecycleOutcome::UnsupportedAuthorityExpiryDelta
        );
        assert!(receipt.admission_use_consumed);
        assert!(receipt.authority_transition.is_none());
        assert!(receipt.host_adoption.is_none());
        assert_eq!(
            runtime
                .control_lease_authority_snapshot()
                .authority_revision,
            prior_owner_revision
        );
        assert_eq!(runtime.host_snapshot(), &prior_host);
        let restarted = runtime.staged_copy().expect("coupled failure restart");
        assert_eq!(
            restarted.evidence().control_lease_lifecycle_receipts,
            runtime.evidence().control_lease_lifecycle_receipts
        );
    }

    #[test]
    fn host_rejection_discards_accepted_owner_candidate_but_consumes_use() {
        let mut runtime = runtime(
            vec![ManifoldBrokerFeature::MediaSession],
            vec![control_lease_lifecycle_capability(
                ManifoldBrokerControlLeaseLifecycleOperationKind::Issue,
            )],
            Vec::new(),
            "provider.runtime.lifecycle.host_reject",
        );
        let host_revision = runtime.host_snapshot().authority_revision;
        for index in 0..MAX_RUNTIME_AUDIT_EVENTS {
            runtime.adapter.handle_command(
                &ManifoldRuntimeCommandRequest {
                    schema_id: schema_id(HOST_COMMAND_REQUEST_SCHEMA),
                    request_id: id(&format!("request.host.capacity.{index}")),
                    expected_authority_revision: host_revision,
                    requester_id: id("client.runtime.test"),
                    command_id: id("command.unknown"),
                    lease_id: None,
                    params_digest: None,
                    issued_at_ms: 1,
                    expires_at_ms: 2_000_000_000_000,
                },
                1,
            );
        }
        assert_eq!(
            runtime.host_snapshot().audit_events.len(),
            MAX_RUNTIME_AUDIT_EVENTS
        );
        let prior_owner = runtime.control_lease_authority.evidence();
        let prior_host = runtime.host_snapshot().clone();
        let owner_revision = prior_owner.current_authority_snapshot.authority_revision;
        let request = authorize_lifecycle(
            &mut runtime,
            ManifoldBrokerControlLeaseLifecycleOperation::Issue {
                request_id: id("request.lifecycle.host_reject"),
                expected_authority_revision: owner_revision,
                scope: id("lease.media.session"),
                requested_ttl_ms: 30_000,
                required_capability: id("manifold.command.request"),
                safety_class: SafetyClass::BoundedMutation,
            },
            "host_reject",
            16,
            None,
        );
        let receipt = runtime
            .commit_control_lease_lifecycle(
                &request,
                next_control_lease_clock(&runtime, 100),
                vec![id("evidence.lifecycle.host_reject")],
                |receipt, _| receipt.clone(),
            )
            .expect("Host rejection result");
        assert_eq!(
            receipt.outcome,
            ManifoldBrokerControlLeaseLifecycleOutcome::CompositionFailedAfterPermitConsumption,
            "{receipt:?}"
        );
        assert!(receipt.admission_use_consumed);
        assert!(receipt
            .authority_transition
            .as_ref()
            .is_some_and(control_lease_transition_applied));
        assert!(receipt.host_adoption.as_ref().is_some_and(|value| {
            !value.applied
                && value.rejection_reason
                    == Some(ManifoldRuntimeRejectionReason::AuthorityCapacityExhausted)
        }));
        assert_eq!(runtime.control_lease_authority.evidence(), prior_owner);
        assert_eq!(runtime.host_snapshot(), &prior_host);
        runtime.staged_copy().expect("Host rejection restart");
    }

    #[test]
    fn revocation_host_failure_installs_durable_fail_closed_barrier() {
        let lease_id = id("lease.media.session.lifecycle.revocation.host_failure");
        let command_id = "command.media.session.start";
        let stream_capability = id("manifold.stream.subscribe");
        let mut runtime = runtime(
            vec![ManifoldBrokerFeature::MediaSession],
            vec![
                control_lease_lifecycle_capability(
                    ManifoldBrokerControlLeaseLifecycleOperationKind::Revocation,
                ),
                command_capability(&id(command_id)),
                stream_capability.clone(),
            ],
            vec![ManifoldRuntimeLease {
                lease_id: lease_id.clone(),
                scope: id("lease.media.session"),
                holder_id: id("client.runtime.test"),
                expires_at_ms: 60_000,
                derivative_binding: None,
            }],
            "provider.runtime.lifecycle.revocation.host_failure",
        );
        let issue = runtime.issue_token(
            &ManifoldAdmissionRequest {
                schema_id: schema_id(ADMISSION_REQUEST_SCHEMA),
                request_id: id("request.revocation.host_failure.pending_uses.issue"),
                expected_authority_revision: runtime.admission_snapshot().authority_revision,
                identity: identity("client.runtime.test"),
                requested_capabilities: vec![
                    command_capability(&id(command_id)),
                    stream_capability.clone(),
                ],
                issued_at_ms: 1_000,
                expires_at_ms: 50_000,
                requested_token_ttl_ms: 20_000,
            },
            [45; 32],
            2_000,
        );
        assert!(issue.applied);
        let token = issue.token.expect("pending-use token");
        let command_use_id = id("request.revocation.host_failure.command_use");
        let command_use = runtime.authorize_use(
            &ManifoldAdmissionUseRequest {
                schema_id: schema_id(ADMISSION_USE_REQUEST_SCHEMA),
                request_id: command_use_id.clone(),
                expected_authority_revision: issue.resulting_authority_revision,
                token_id: token.token_id.clone(),
                identity: identity("client.runtime.test"),
                capability_id: command_capability(&id(command_id)),
                issued_at_ms: 2_000,
                expires_at_ms: 40_000,
            },
            3_000,
        );
        assert!(command_use.applied);
        let stream_use_id = id("request.revocation.host_failure.stream_use");
        let stream_use = runtime.authorize_use(
            &ManifoldAdmissionUseRequest {
                schema_id: schema_id(ADMISSION_USE_REQUEST_SCHEMA),
                request_id: stream_use_id.clone(),
                expected_authority_revision: command_use.resulting_authority_revision,
                token_id: token.token_id.clone(),
                identity: identity("client.runtime.test"),
                capability_id: stream_capability.clone(),
                issued_at_ms: 2_001,
                expires_at_ms: 40_000,
            },
            3_001,
        );
        assert!(stream_use.applied);
        let recoverable_host_snapshot = runtime.host_snapshot().clone();
        let host_revision = runtime.host_snapshot().authority_revision;
        for index in 0..MAX_RUNTIME_AUDIT_EVENTS {
            runtime.adapter.handle_command(
                &ManifoldRuntimeCommandRequest {
                    schema_id: schema_id(HOST_COMMAND_REQUEST_SCHEMA),
                    request_id: id(&format!("request.host.revoke_capacity.{index}")),
                    expected_authority_revision: host_revision,
                    requester_id: id("client.runtime.test"),
                    command_id: id("command.unknown"),
                    lease_id: None,
                    params_digest: None,
                    issued_at_ms: 1,
                    expires_at_ms: 2_000_000_000_000,
                },
                1,
            );
        }
        runtime
            .staged_copy()
            .expect("pre-revocation saturated Host state remains restorable");
        let prior_owner = runtime.control_lease_authority.evidence();
        let prior_host = runtime.host_snapshot().clone();
        let requested_at_ms =
            u64::try_from(runtime.control_lease_authority.current_clock().wall_unix_ms)
                .expect("wall clock");
        let request = authorize_lifecycle(
            &mut runtime,
            ManifoldBrokerControlLeaseLifecycleOperation::Revocation {
                request_id: id("request.lifecycle.revocation.host_failure"),
                lease_id: lease_id.clone(),
                expected_authority_revision: prior_owner
                    .current_authority_snapshot
                    .authority_revision,
                revocation_reason: id("reason.security.host_failure"),
                requested_at_ms,
            },
            "revocation.host_failure",
            44,
            None,
        );
        let receipt = runtime
            .commit_control_lease_lifecycle(
                &request,
                next_control_lease_clock(&runtime, 100),
                vec![id("evidence.lifecycle.revocation.host_failure")],
                |receipt, _| receipt.clone(),
            )
            .expect("failed Host convergence");
        assert_eq!(
            receipt.outcome,
            ManifoldBrokerControlLeaseLifecycleOutcome::CompositionFailedAfterPermitConsumption,
            "{receipt:?}"
        );
        assert_eq!(runtime.control_lease_authority.evidence(), prior_owner);
        assert_eq!(runtime.host_snapshot(), &prior_host);
        let evidence = runtime.evidence();
        assert_eq!(evidence.control_lease_revocation_barriers.len(), 1);
        assert_eq!(
            evidence.control_lease_revocation_barriers[0].state,
            ManifoldBrokerControlLeaseRevocationBarrierState::PendingHostConvergence
        );
        assert!(evidence.control_lease_revocation_barriers[0]
            .host_adoption
            .is_none());
        let blocked_mutation = runtime.handle_mutation(
            &ManifoldBrokerMutationRequest {
                schema_id: schema_id(BROKER_MUTATION_REQUEST_SCHEMA),
                provider_epoch_id: runtime.provider_epoch_id().clone(),
                admission_use_request_id: command_use_id.clone(),
                token_id: token.token_id.clone(),
                expected_admission_authority_revision: command_use.resulting_authority_revision,
                command: client_command(
                    command_id,
                    "client.runtime.test",
                    "revocation.host_failure.blocked",
                    runtime.host_snapshot().authority_revision.get(),
                ),
            },
            4_000,
        );
        assert!(!blocked_mutation.applied);
        assert_eq!(
            blocked_mutation.admission_rejection_reason,
            Some(ManifoldBrokerMutationRejectionReason::PendingRevocationConvergence)
        );
        let blocked_stream = runtime.consume_capability_use(
            &stream_use_id,
            &token.token_id,
            stream_use.resulting_authority_revision,
            &identity("client.runtime.test"),
            &stream_capability,
            4_000,
        );
        assert!(!blocked_stream.applied);
        assert_eq!(
            blocked_stream.rejection_reason,
            Some(ManifoldBrokerMutationRejectionReason::PendingRevocationConvergence)
        );
        let frozen_evidence = runtime.evidence();
        assert!(frozen_evidence
            .pending_bounded_uses
            .iter()
            .any(|use_| use_.admission_use_request_id == command_use_id));
        assert!(frozen_evidence
            .pending_bounded_uses
            .iter()
            .any(|use_| use_.admission_use_request_id == stream_use_id));
        runtime.staged_copy().expect("pending barrier restart");
        let recovery_request = ManifoldBrokerControlLeaseRevocationRecoveryRequest {
            schema_id: schema_id(BROKER_CONTROL_LEASE_REVOCATION_RECOVERY_REQUEST_SCHEMA),
            recovery_id: id("recovery.lifecycle.revocation.host_failure"),
            provider_epoch_id: runtime.provider_epoch_id().clone(),
            barrier_id: evidence.control_lease_revocation_barriers[0]
                .barrier_id
                .clone(),
            expected_control_lease_authority_revision: runtime
                .control_lease_authority_snapshot()
                .authority_revision,
            expected_host_authority_revision: runtime.host_snapshot().authority_revision,
        };
        let recovery = runtime
            .recover_pending_control_lease_revocation(&recovery_request)
            .expect("durable recovery rejection");
        assert!(!recovery.applied);
        assert_eq!(
            recovery.rejection_reason,
            Some(ManifoldBrokerControlLeaseLifecycleRejectionReason::OwnerHostCompositionFailed)
        );
        assert_eq!(
            runtime
                .evidence()
                .control_lease_revocation_recovery_receipts
                .len(),
            1
        );
        runtime
            .staged_copy()
            .expect("rejected recovery survives restart");
        let replayed_recovery = runtime
            .recover_pending_control_lease_revocation(&recovery_request)
            .expect("typed recovery replay");
        assert_eq!(
            replayed_recovery.rejection_reason,
            Some(ManifoldBrokerControlLeaseLifecycleRejectionReason::ReplayedLifecycleRequest)
        );
        assert_eq!(
            runtime
                .evidence()
                .control_lease_revocation_recovery_receipts
                .len(),
            1
        );

        let mut second = request.clone();
        second.admission_use_request_id =
            id("request.lifecycle.revocation.host_failure.second.use");
        second.operation = ManifoldBrokerControlLeaseLifecycleOperation::Issue {
            request_id: id("request.lifecycle.revocation.host_failure.blocked_issue"),
            expected_authority_revision: runtime
                .control_lease_authority_snapshot()
                .authority_revision,
            scope: id("lease.media.session"),
            requested_ttl_ms: 30_000,
            required_capability: id("manifold.command.request"),
            safety_class: SafetyClass::BoundedMutation,
        };
        let second_receipt = runtime
            .commit_control_lease_lifecycle(
                &second,
                next_control_lease_clock(&runtime, 1),
                vec![id("evidence.lifecycle.revocation.host_failure.second")],
                |receipt, _| receipt.clone(),
            )
            .expect("barrier rejection");
        assert_eq!(
            second_receipt.rejection_reason,
            Some(ManifoldBrokerControlLeaseLifecycleRejectionReason::PendingRevocationConvergence)
        );

        let mut stale_recovery_request = recovery_request.clone();
        stale_recovery_request.recovery_id = id("recovery.lifecycle.revocation.host_failure.stale");
        stale_recovery_request.expected_control_lease_authority_revision = stale_recovery_request
            .expected_control_lease_authority_revision
            .next()
            .expect("stale revision");
        let filler = runtime
            .recover_pending_control_lease_revocation(&stale_recovery_request)
            .expect("retained stale recovery");
        assert!(!filler.applied);
        while runtime.control_lease_revocation_recovery_receipts.len()
            < runtime.revocation_recovery_rejection_capacity()
        {
            let mut retained = filler.clone();
            retained.recovery_id = id(&format!(
                "recovery.lifecycle.revocation.host_failure.fill.{}",
                runtime.control_lease_revocation_recovery_receipts.len()
            ));
            runtime
                .control_lease_revocation_recovery_receipts
                .push(retained);
        }
        assert_eq!(
            runtime.control_lease_revocation_recovery_receipts.len(),
            MAX_BROKER_CONTROL_LEASE_TRANSITIONS - 1
        );
        runtime
            .staged_copy()
            .expect("rejected recovery ledger preserves success reserve");

        runtime.adapter.host = ManifoldRuntimeHost::from_snapshot(recoverable_host_snapshot)
            .expect("recoverable equivalent Host state");
        runtime
            .staged_copy()
            .expect("pending barrier accepts recoverable equivalent Host state");
        let mut successful_recovery_request = recovery_request;
        successful_recovery_request.recovery_id =
            id("recovery.lifecycle.revocation.host_failure.final");
        let successful = runtime
            .recover_pending_control_lease_revocation(&successful_recovery_request)
            .expect("reserved successful recovery");
        assert!(successful.applied, "{successful:?}");
        assert_eq!(
            runtime.control_lease_revocation_recovery_receipts.len(),
            MAX_BROKER_CONTROL_LEASE_TRANSITIONS
        );
        let recovered_evidence = runtime.evidence();
        let recovered_invalidations = recovered_evidence
            .control_lease_revocation_use_invalidations
            .iter()
            .map(|invalidation| {
                (
                    invalidation.admission_use_request_id.clone(),
                    invalidation.clone(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        assert!(revocation_barriers_close(
            &recovered_evidence.control_lease_revocation_barriers,
            &recovered_evidence.provider_epoch_id,
            &recovered_evidence.control_lease_authority,
            &recovered_evidence.host_snapshot,
            &recovered_invalidations,
            &recovered_evidence.control_lease_lifecycle_receipts,
            &recovered_evidence.control_lease_revocation_recovery_receipts,
        ));
        let recovered_consumed = recovered_evidence
            .consumed_bounded_use_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        assert!(lifecycle_receipts_close(
            &recovered_evidence.control_lease_lifecycle_receipts,
            &recovered_evidence.provider_epoch_id,
            runtime.adapter.config(),
            &recovered_consumed,
            &recovered_evidence.control_lease_authority,
            &recovered_evidence.host_snapshot,
            &recovered_evidence.admission_snapshot,
            &recovered_evidence.control_lease_revocation_recovery_receipts,
        ));
        let recovery_count = recovered_evidence
            .control_lease_revocation_recovery_receipts
            .len();
        let mut duplicated_applied_recovery = recovered_evidence.clone();
        let mut duplicate = duplicated_applied_recovery
            .control_lease_revocation_recovery_receipts
            .last()
            .expect("applied recovery")
            .clone();
        duplicate.recovery_id = id("recovery.lifecycle.revocation.host_failure.duplicate_applied");
        duplicated_applied_recovery.control_lease_revocation_recovery_receipts[0] = duplicate;
        assert_runtime_evidence_rejected_after_json(&runtime, &duplicated_applied_recovery);

        let mut rejected_after_success = recovered_evidence;
        rejected_after_success
            .control_lease_revocation_recovery_receipts
            .swap(recovery_count - 2, recovery_count - 1);
        assert_runtime_evidence_rejected_after_json(&runtime, &rejected_after_success);
        runtime
            .staged_copy()
            .expect("successful recovery at reserved capacity restarts");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn v2_runtime_evidence_requires_explicit_authority_adoption_migration() {
        let legacy_v4_json =
            include_str!("../../../fixtures/broker-adapter/runtime-evidence-v4.json");
        let legacy_v4: LegacyManifoldBrokerRuntimeEvidenceV4 =
            serde_json::from_str(legacy_v4_json).expect("committed v4 evidence");
        let current_adapter = adapter_for_legacy_v4(&legacy_v4);
        let (current_runtime, _) =
            ManifoldBrokerRuntime::migrate_v4_evidence_json(current_adapter, legacy_v4_json)
                .expect("v4 migration");
        let evidence = current_runtime.evidence();
        let legacy_v2 = serde_json::json!({
            "$schema": LEGACY_BROKER_RUNTIME_EVIDENCE_V2_SCHEMA,
            "provider_epoch_id": evidence.provider_epoch_id.clone(),
            "host_snapshot": evidence.host_snapshot.clone(),
            "admission_snapshot": evidence.admission_snapshot.clone(),
            "pending_bounded_uses": evidence.pending_bounded_uses.clone(),
            "consumed_bounded_use_ids": evidence.consumed_bounded_use_ids.clone(),
        });
        let legacy_json = serde_json::to_string(&legacy_v2).expect("legacy v2");
        let config: ManifoldBrokerAdapterConfig = serde_json::from_str(include_str!(
            "../../../fixtures/broker-adapter/standalone-config.json"
        ))
        .expect("adapter config");
        let packaged_lock =
            include_bytes!("../../../fixtures/broker-adapter/standalone-product-lock.json");
        let authority = ManifoldBrokerControlLeaseAuthority::refresh_from_v2_evidence(
            evidence.control_lease_authority.clone(),
            evidence
                .control_lease_authority
                .current_authority_snapshot
                .clone(),
            evidence.control_lease_authority.current_clock.clone(),
        )
        .expect("authority");
        let host_json = serde_json::to_string(&evidence.host_snapshot).expect("host snapshot");
        let adapter = ManifoldBrokerAdapter::restart_from_json(
            config.clone(),
            packaged_lock,
            &host_json,
            &authority,
        )
        .expect("adapter");
        let (migrated, receipt) =
            ManifoldBrokerRuntime::from_legacy_v2_evidence_json(adapter, authority, &legacy_json)
                .expect("explicit v2 authority adoption");
        assert_eq!(
            migrated.evidence().schema_id.as_str(),
            BROKER_RUNTIME_EVIDENCE_SCHEMA
        );
        assert_eq!(
            receipt.source_schema_id.as_str(),
            LEGACY_BROKER_RUNTIME_EVIDENCE_V2_SCHEMA
        );
        assert_eq!(
            receipt.resulting_schema_id.as_str(),
            BROKER_RUNTIME_EVIDENCE_SCHEMA
        );
        assert_eq!(receipt.migrated_lease_ids.len(), 1);
        assert_eq!(
            receipt.outcome,
            ManifoldBrokerRuntimeAuthorityMigrationOutcome::
                ExistingAuthorityAdoptedWithoutNewLeaseDecision
        );
        assert_eq!(
            receipt.source_json_sha256,
            sha256_binding(MIGRATION_SOURCE_JSON_DIGEST_DOMAIN, legacy_json.as_bytes())
        );
        assert_eq!(
            receipt.source_json_size_bytes,
            u64::try_from(legacy_json.len()).expect("fixture byte count")
        );
        let resulting_evidence_json =
            serde_json::to_vec(&migrated.evidence()).expect("resulting evidence");
        assert_eq!(
            receipt.resulting_evidence_json_sha256,
            sha256_binding(MIGRATION_RESULT_DIGEST_DOMAIN, &resulting_evidence_json)
        );
        assert_eq!(
            receipt.resulting_evidence_json_size_bytes,
            u64::try_from(resulting_evidence_json.len()).expect("fixture byte count")
        );
        assert_eq!(receipt.adapter_id.as_str(), "adapter.broker.standalone");
        assert_eq!(
            receipt.control_lease_authority_id,
            migrated
                .evidence()
                .control_lease_authority
                .current_authority_snapshot
                .authority_id
        );
        assert_eq!(
            receipt.control_lease_authority_revision,
            migrated
                .evidence()
                .control_lease_authority
                .current_authority_snapshot
                .authority_revision
        );
        assert_eq!(
            receipt.control_lease_clock_sequence,
            migrated
                .evidence()
                .control_lease_authority
                .current_clock
                .sequence
        );
        let typed_legacy: LegacyBrokerRuntimeEvidenceV2 =
            serde_json::from_str(&legacy_json).expect("typed legacy");
        let typed_legacy_host_json =
            serde_json::to_string(&typed_legacy.host_snapshot).expect("legacy host JSON");
        let (typed_legacy_host, _) =
            ManifoldRuntimeHost::restart_from_json_with_migration(&typed_legacy_host_json)
                .expect("legacy host migration");
        assert_eq!(
            receipt.host_lease_set_sha256,
            sha256_binding(
                MIGRATION_HOST_LEASE_SET_DIGEST_DOMAIN,
                &serde_json::to_vec(&typed_legacy_host.snapshot().leases).expect("host leases")
            )
        );
        assert_eq!(
            receipt.source_typed_evidence_sha256,
            sha256_binding(
                MIGRATION_SOURCE_TYPED_DIGEST_DOMAIN,
                &serde_json::to_vec(&typed_legacy).expect("typed legacy JSON")
            )
        );
        assert_eq!(
            receipt.host_snapshot_sha256,
            sha256_binding(
                MIGRATION_HOST_DIGEST_DOMAIN,
                &serde_json::to_vec(&typed_legacy.host_snapshot).expect("host JSON")
            )
        );
        assert_eq!(
            receipt.source_lineage_sha256,
            sha256_binding(
                MIGRATION_AUTHORITY_DIGEST_DOMAIN,
                &serde_json::to_vec(&migrated.evidence().control_lease_authority.baseline)
                    .expect("authority JSON")
            )
        );

        let mut substituted = migrated.evidence();
        substituted.admission_snapshot.authority_revision = substituted
            .admission_snapshot
            .authority_revision
            .next()
            .expect("revision");
        assert_ne!(
            receipt.resulting_evidence_json_sha256,
            sha256_binding(
                MIGRATION_RESULT_DIGEST_DOMAIN,
                &serde_json::to_vec(&substituted).expect("substituted evidence")
            )
        );
        assert!(receipt
            .validate_against(
                &legacy_json,
                &config,
                &substituted.control_lease_authority.baseline,
                &substituted,
            )
            .is_err());

        let resulting_evidence = migrated.evidence();
        receipt
            .validate_against(
                &legacy_json,
                &config,
                &resulting_evidence.control_lease_authority.baseline,
                &resulting_evidence,
            )
            .expect("receipt validation");
        let receipt_value = serde_json::to_value(&receipt).expect("receipt JSON");
        let fields = receipt_value
            .as_object()
            .expect("receipt object")
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        for field in fields {
            let mut substituted_receipt = receipt_value.clone();
            let value = substituted_receipt
                .as_object_mut()
                .expect("receipt object")
                .get_mut(&field)
                .expect("receipt field");
            match value {
                serde_json::Value::String(text) => text.push_str(".damaged"),
                serde_json::Value::Number(number) => {
                    *value = serde_json::json!(number.as_u64().expect("unsigned") + 1);
                }
                serde_json::Value::Array(values) => values.clear(),
                _ => panic!("receipt field shape is covered"),
            }
            let rejected =
                serde_json::from_value::<ManifoldBrokerRuntimeAuthorityMigrationReceipt>(
                    substituted_receipt,
                )
                .map_or(true, |candidate| {
                    candidate
                        .validate_against(
                            &legacy_json,
                            &config,
                            &resulting_evidence.control_lease_authority.baseline,
                            &resulting_evidence,
                        )
                        .is_err()
                });
            assert!(rejected, "substituted receipt field {field}");
        }
        substituted = migrated.evidence();
        substituted.control_lease_authority.current_clock.sequence += 1;
        assert_ne!(
            receipt.resulting_evidence_json_sha256,
            sha256_binding(
                MIGRATION_RESULT_DIGEST_DOMAIN,
                &serde_json::to_vec(&substituted).expect("substituted evidence")
            )
        );
        assert!(receipt
            .validate_against(
                &legacy_json,
                &config,
                &substituted.control_lease_authority.baseline,
                &substituted,
            )
            .is_err());
        substituted = migrated.evidence();
        substituted.host_snapshot.authority_revision = substituted
            .host_snapshot
            .authority_revision
            .next()
            .expect("revision");
        assert_ne!(
            receipt.resulting_evidence_json_sha256,
            sha256_binding(
                MIGRATION_RESULT_DIGEST_DOMAIN,
                &serde_json::to_vec(&substituted).expect("substituted evidence")
            )
        );
        assert!(receipt
            .validate_against(
                &legacy_json,
                &config,
                &substituted.control_lease_authority.baseline,
                &substituted,
            )
            .is_err());
    }

    #[test]
    fn runtime_evidence_json_budget_rejects_before_decode() {
        let oversized = " ".repeat(MAX_BROKER_RUNTIME_EVIDENCE_BYTES + 1);
        assert!(matches!(
            validate_runtime_evidence_json_size(&oversized),
            Err(ManifoldBrokerRuntimeStateError::InvalidEvidence(
                "runtime_evidence_byte_capacity"
            ))
        ));
    }

    #[test]
    fn revoke_and_expiry_invalidate_only_uses_derived_from_removed_tokens() {
        let command_id = "command.session.list";
        let revoke_epoch = "epoch.runtime.two_client.revoke";
        let mut revoked_runtime = two_client_runtime(command_id, revoke_epoch);
        let (alpha_use, alpha_token, alpha_revision) = admit_for_client(
            &mut revoked_runtime,
            command_id,
            "client.runtime.alpha",
            "revoke_alpha",
            1,
            31,
            20_000,
        );
        let (beta_use, beta_token, beta_revision) = admit_for_client(
            &mut revoked_runtime,
            command_id,
            "client.runtime.beta",
            "revoke_beta",
            3,
            32,
            20_000,
        );
        let revoked = revoked_runtime.revoke_token(&ManifoldAdmissionRevocationRequest {
            schema_id: schema_id(ADMISSION_REVOCATION_REQUEST_SCHEMA),
            request_id: id("request.runtime.revoke_alpha.token"),
            expected_authority_revision: Revision::new(5).expect("revision"),
            token_id: alpha_token.clone(),
            identity: identity("client.runtime.alpha"),
            reason: id("reason.runtime.client_shutdown"),
        });
        assert!(revoked.applied);
        let alpha_after_revoke = revoked_runtime.handle_mutation(
            &client_mutation(
                revoke_epoch,
                alpha_use,
                alpha_token,
                alpha_revision,
                client_command(command_id, "client.runtime.alpha", "revoke_alpha", 1),
            ),
            4_000,
        );
        assert_eq!(
            alpha_after_revoke.admission_rejection_reason,
            Some(ManifoldBrokerMutationRejectionReason::ReplayedAdmissionUse)
        );
        let beta_after_revoke = revoked_runtime.handle_mutation(
            &client_mutation(
                revoke_epoch,
                beta_use,
                beta_token,
                beta_revision,
                client_command(command_id, "client.runtime.beta", "revoke_beta", 1),
            ),
            4_000,
        );
        assert!(beta_after_revoke.applied);
        assert_eq!(beta_after_revoke.admission_authority_revision.get(), 6);

        let expiry_epoch = "epoch.runtime.two_client.expiry";
        let mut expired_runtime = two_client_runtime(command_id, expiry_epoch);
        let (short_use, short_token, short_revision) = admit_for_client(
            &mut expired_runtime,
            command_id,
            "client.runtime.alpha",
            "expiry_alpha",
            1,
            41,
            3_000,
        );
        let (long_use, long_token, long_revision) = admit_for_client(
            &mut expired_runtime,
            command_id,
            "client.runtime.beta",
            "expiry_beta",
            3,
            42,
            20_000,
        );
        let expired = expired_runtime.expire_tokens(
            id("sweep.runtime.two_client.expiry"),
            Revision::new(5).expect("revision"),
            6_000,
        );
        assert!(expired.applied);
        assert_eq!(expired.removed_token_ids, vec![short_token.clone()]);
        let short_after_expiry = expired_runtime.handle_mutation(
            &client_mutation(
                expiry_epoch,
                short_use,
                short_token,
                short_revision,
                client_command(command_id, "client.runtime.alpha", "expiry_alpha", 1),
            ),
            6_000,
        );
        assert_eq!(
            short_after_expiry.admission_rejection_reason,
            Some(ManifoldBrokerMutationRejectionReason::ReplayedAdmissionUse)
        );
        let long_after_expiry = expired_runtime.handle_mutation(
            &client_mutation(
                expiry_epoch,
                long_use,
                long_token,
                long_revision,
                client_command(command_id, "client.runtime.beta", "expiry_beta", 1),
            ),
            6_000,
        );
        assert!(long_after_expiry.applied);
        assert_eq!(long_after_expiry.admission_authority_revision.get(), 6);
    }

    #[test]
    fn bounded_use_rejects_stale_cross_client_capability_and_replay() {
        let command_id = "command.session.list";
        let mut runtime = runtime(
            Vec::new(),
            vec![command_capability(&id(command_id))],
            Vec::new(),
            "epoch.runtime.gates",
        );
        let (use_id, token_id) = admit(&mut runtime, command_id);
        let mut request = mutation(
            "epoch.runtime.gates",
            use_id.clone(),
            token_id,
            command(command_id, None),
        );
        request.expected_admission_authority_revision = Revision::new(2).expect("revision");
        assert_eq!(
            runtime
                .handle_mutation(&request, 4_000)
                .admission_rejection_reason,
            Some(ManifoldBrokerMutationRejectionReason::StaleAdmissionRevision)
        );
        request.expected_admission_authority_revision = Revision::new(3).expect("revision");
        let token_id = request.token_id.clone();
        request.token_id = id("token.session.substituted");
        assert_eq!(
            runtime
                .handle_mutation(&request, 4_000)
                .admission_rejection_reason,
            Some(ManifoldBrokerMutationRejectionReason::AdmissionTokenMismatch)
        );
        request.token_id = token_id;
        request.command.requester_id = id("client.other");
        assert_eq!(
            runtime
                .handle_mutation(&request, 4_000)
                .admission_rejection_reason,
            Some(ManifoldBrokerMutationRejectionReason::CrossClientUse)
        );
        request.command.requester_id = id("client.runtime.test");
        request.command.command_id = id("command.peer.status.get");
        assert_eq!(
            runtime
                .handle_mutation(&request, 4_000)
                .admission_rejection_reason,
            Some(ManifoldBrokerMutationRejectionReason::CapabilityMismatch)
        );
        request.command.command_id = id(command_id);
        assert!(runtime.handle_mutation(&request, 4_000).applied);
        assert_eq!(
            runtime
                .handle_mutation(&request, 4_000)
                .admission_rejection_reason,
            Some(ManifoldBrokerMutationRejectionReason::ReplayedAdmissionUse)
        );
    }

    #[test]
    fn unknown_unselected_and_unleased_reach_host_and_fail_without_platform_apply() {
        for (features, command_id, selected, expected) in [
            (
                Vec::new(),
                "command.never.registered",
                false,
                ManifoldRuntimeRejectionReason::UnknownCommand,
            ),
            (
                Vec::new(),
                "command.media.session.start",
                false,
                ManifoldRuntimeRejectionReason::UnknownCommand,
            ),
            (
                vec![ManifoldBrokerFeature::MediaSession],
                "command.media.session.start",
                true,
                ManifoldRuntimeRejectionReason::MissingLease,
            ),
        ] {
            let mut runtime = runtime(
                features,
                vec![command_capability(&id(command_id))],
                Vec::new(),
                "epoch.runtime.damage",
            );
            let (use_id, token_id) = admit(&mut runtime, command_id);
            let receipt = runtime.handle_mutation(
                &mutation(
                    "epoch.runtime.damage",
                    use_id,
                    token_id,
                    command(command_id, None),
                ),
                4_000,
            );
            assert!(receipt.admission_applied);
            assert!(!receipt.applied);
            assert_eq!(receipt.command_selected, selected);
            assert_eq!(
                receipt
                    .adapter_receipt
                    .expect("host receipt")
                    .application
                    .rejection_reason,
                Some(expected)
            );
            assert_eq!(runtime.host_snapshot().authority_revision.get(), 1);
        }
    }

    #[test]
    fn same_runtime_preserves_state_and_fresh_provider_epoch_rejects_old_claims() {
        let command_id = "command.session.list";
        let capability = command_capability(&id(command_id));
        let mut first = runtime(
            Vec::new(),
            vec![capability.clone()],
            Vec::new(),
            "epoch.runtime.first",
        );
        let (use_id, token_id) = admit(&mut first, command_id);
        let old_request = mutation(
            "epoch.runtime.first",
            use_id,
            token_id,
            command(command_id, None),
        );
        assert!(first.handle_mutation(&old_request, 4_000).applied);
        assert_eq!(first.evidence().host_snapshot.authority_revision.get(), 2);

        let mut restarted = runtime(
            Vec::new(),
            vec![capability],
            Vec::new(),
            "epoch.runtime.second",
        );
        assert_eq!(restarted.host_snapshot().authority_revision.get(), 1);
        assert_eq!(
            restarted
                .handle_mutation(&old_request, 4_000)
                .admission_rejection_reason,
            Some(ManifoldBrokerMutationRejectionReason::ProviderEpochMismatch)
        );
        assert_eq!(restarted.host_snapshot().authority_revision.get(), 1);
    }

    #[test]
    fn revocation_invalidates_pending_bounded_use() {
        let command_id = "command.session.list";
        let mut runtime = runtime(
            Vec::new(),
            vec![command_capability(&id(command_id))],
            Vec::new(),
            "epoch.runtime.revoke",
        );
        let (use_id, token_id) = admit(&mut runtime, command_id);
        let revoke = runtime.revoke_token(&ManifoldAdmissionRevocationRequest {
            schema_id: schema_id(ADMISSION_REVOCATION_REQUEST_SCHEMA),
            request_id: id("request.runtime.revoke"),
            expected_authority_revision: Revision::new(3).expect("revision"),
            token_id: token_id.clone(),
            identity: identity("client.runtime.test"),
            reason: id("reason.runtime.test"),
        });
        assert!(revoke.applied);
        let mut request = mutation(
            "epoch.runtime.revoke",
            use_id,
            token_id,
            command(command_id, None),
        );
        request.expected_admission_authority_revision = Revision::new(4).expect("revision");
        assert_eq!(
            runtime
                .handle_mutation(&request, 4_000)
                .admission_rejection_reason,
            Some(ManifoldBrokerMutationRejectionReason::ReplayedAdmissionUse)
        );
        assert_eq!(
            runtime.admission_snapshot().revoked_token_ids.len(),
            1,
            "revocation remains Manifold-owned"
        );
        assert_ne!(
            revoke.rejection_reason,
            Some(ManifoldAdmissionRejectionReason::TokenRevoked)
        );
    }
}
