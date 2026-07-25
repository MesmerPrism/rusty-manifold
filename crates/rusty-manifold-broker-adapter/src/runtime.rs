//! Stateful product broker runtime binding admission to Runtime Host mutation.

use crate::{
    ManifoldBrokerAdapter, ManifoldBrokerAdapterConfig, ManifoldBrokerAdapterReceipt,
    ManifoldBrokerControlLeaseAuthority, ManifoldBrokerControlLeaseAuthorityError,
    ManifoldBrokerControlLeaseAuthorityEvidence, RUNTIME_HOST_AUTHORITY_OWNER,
};
use rusty_manifold_admission::{
    ManifoldAdmissionAuthority, ManifoldAdmissionLegacyClientLockBinding,
    ManifoldAdmissionMigrationReceipt, ManifoldAdmissionReceipt, ManifoldAdmissionRequest,
    ManifoldAdmissionRevocationRequest, ManifoldAdmissionSnapshot, ManifoldAdmissionUseRequest,
    ManifoldClientIdentity,
};
use rusty_manifold_model::{DottedId, Revision, SchemaId};
use rusty_manifold_runtime_host::{
    ManifoldRuntimeCommandRequest, ManifoldRuntimeHost, ManifoldRuntimeHostError,
    ManifoldRuntimeHostMigrationReceipt, ManifoldRuntimeHostSnapshot,
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
/// Integrated broker runtime evidence with synchronized control-lease ownership.
pub const BROKER_RUNTIME_EVIDENCE_SCHEMA: &str = "rusty.manifold.broker.runtime_evidence.v3";
/// Explicit legacy broker runtime-evidence migration receipt schema.
pub const BROKER_RUNTIME_MIGRATION_RECEIPT_SCHEMA: &str =
    "rusty.manifold.broker.runtime_evidence_migration_receipt.v1";
/// Explicit v2-to-v3 authority-adoption migration receipt schema.
pub const BROKER_RUNTIME_AUTHORITY_MIGRATION_RECEIPT_SCHEMA: &str =
    "rusty.manifold.broker.runtime_evidence_authority_migration_receipt.v1";
/// Non-command bounded capability consumption receipt schema.
pub const BROKER_CAPABILITY_USE_RECEIPT_SCHEMA: &str =
    "rusty.manifold.broker.capability_use_receipt.v1";
/// Maximum pending/consumed bounded uses per provider epoch.
pub const MAX_BROKER_BOUNDED_USES: usize = 4_096;
/// Maximum serialized current or legacy Broker runtime evidence.
pub const MAX_BROKER_RUNTIME_EVIDENCE_BYTES: usize = 16 * 1024 * 1024;

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
    pub control_lease_authority: ManifoldBrokerControlLeaseAuthorityEvidence,
    /// Current admission state.
    pub admission_snapshot: ManifoldAdmissionSnapshot,
    /// Accepted uses not yet consumed by a mutation attempt.
    pub pending_bounded_uses: Vec<ManifoldBrokerBoundedUse>,
    /// Bounded uses already consumed by mutation attempts.
    pub consumed_bounded_use_ids: Vec<DottedId>,
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
    /// owner evidence, and resulting v3 evidence.
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
    host_snapshot: ManifoldRuntimeHostSnapshot,
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
    consumed_bounded_use_ids: BTreeSet<DottedId>,
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
        let runtime = Self {
            provider_epoch_id,
            adapter,
            control_lease_authority,
            admission: ManifoldAdmissionAuthority::from_snapshot(admission_snapshot)
                .map_err(ManifoldBrokerRuntimeStateError::Admission)?,
            pending_bounded_uses: BTreeMap::new(),
            consumed_bounded_use_ids: BTreeSet::new(),
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
    pub fn restore_from_caller_attested_exclusive_evidence(
        adapter: ManifoldBrokerAdapter,
        control_lease_authority: ManifoldBrokerControlLeaseAuthority,
        evidence: ManifoldBrokerRuntimeEvidence,
    ) -> Result<Self, ManifoldBrokerRuntimeStateError> {
        validate_runtime_evidence_size(&evidence)?;
        if evidence.schema_id.as_str() != BROKER_RUNTIME_EVIDENCE_SCHEMA
            || adapter.host_snapshot() != &evidence.host_snapshot
            || !control_lease_authority.is_refresh_of(&evidence.control_lease_authority)
            || evidence.pending_bounded_uses.len() > MAX_BROKER_BOUNDED_USES
            || evidence.consumed_bounded_use_ids.len() > MAX_BROKER_BOUNDED_USES
            || evidence
                .pending_bounded_uses
                .windows(2)
                .any(|pair| pair[0].admission_use_request_id >= pair[1].admission_use_request_id)
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
        let all_use_ids = pending
            .keys()
            .cloned()
            .chain(consumed.iter().cloned())
            .collect::<BTreeSet<_>>();
        let admission_use_ids = admission
            .snapshot()
            .consumed_use_request_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        if pending.keys().any(|id| consumed.contains(id))
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
            consumed_bounded_use_ids: consumed,
        })
    }

    /// Restores current v3 evidence from bounded JSON after the adapter and
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
        if legacy.schema_id.as_str() != LEGACY_BROKER_RUNTIME_EVIDENCE_V2_SCHEMA
            || &legacy.host_snapshot != adapter.host_snapshot()
        {
            return Err(ManifoldBrokerRuntimeStateError::InvalidEvidence(
                "legacy_v2_schema_or_host",
            ));
        }
        control_lease_authority
            .validate_host_snapshot(&legacy.host_snapshot)
            .map_err(ManifoldBrokerRuntimeStateError::ControlLeaseAuthority)?;
        let authority_evidence = control_lease_authority.evidence();
        let evidence = ManifoldBrokerRuntimeEvidence {
            schema_id: schema_id(BROKER_RUNTIME_EVIDENCE_SCHEMA),
            provider_epoch_id: legacy.provider_epoch_id.clone(),
            host_snapshot: legacy.host_snapshot,
            control_lease_authority: authority_evidence.clone(),
            admission_snapshot: legacy.admission_snapshot,
            pending_bounded_uses: legacy.pending_bounded_uses,
            consumed_bounded_use_ids: legacy.consumed_bounded_use_ids,
        };
        validate_runtime_evidence_size(&evidence)?;
        let config = adapter.config().clone();
        let receipt = expected_authority_migration_receipt(
            legacy_json,
            &config,
            &authority_evidence,
            &evidence,
        )?;
        let runtime = Self::restore_from_caller_attested_exclusive_evidence(
            adapter,
            control_lease_authority,
            evidence,
        )?;
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
            admission_snapshot: migrated_admission.snapshot().clone(),
            pending_bounded_uses,
            consumed_bounded_use_ids: legacy.consumed_bounded_use_ids.clone(),
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
        self.admission.issue_token(request, entropy, now_ms)
    }

    /// Authorizes one bounded capability use and retains its exact client binding.
    pub fn authorize_use(
        &mut self,
        request: &ManifoldAdmissionUseRequest,
        now_ms: u64,
    ) -> ManifoldAdmissionReceipt {
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
                    .map(|(expires_at_ms, _, _, _)| expires_at_ms)
                    .unwrap_or(request.expires_at_ms)
                    .min(request.expires_at_ms),
            };
            self.pending_bounded_uses
                .insert(request.request_id.clone(), bounded_use);
        }
        receipt
    }

    /// Revokes a token and invalidates every pending use derived from it.
    pub fn revoke_token(
        &mut self,
        request: &ManifoldAdmissionRevocationRequest,
    ) -> ManifoldAdmissionReceipt {
        let receipt = self.admission.revoke_token(request);
        if receipt.applied {
            let invalidated = self
                .pending_bounded_uses
                .values()
                .filter(|use_| use_.token_id == request.token_id)
                .map(|use_| use_.admission_use_request_id.clone())
                .collect::<Vec<_>>();
            self.pending_bounded_uses
                .retain(|_, use_| use_.token_id != request.token_id);
            self.consumed_bounded_use_ids.extend(invalidated);
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
            let invalidated = self
                .pending_bounded_uses
                .values()
                .filter(|use_| receipt.removed_token_ids.contains(&use_.token_id))
                .map(|use_| use_.admission_use_request_id.clone())
                .collect::<Vec<_>>();
            self.pending_bounded_uses
                .retain(|_, use_| !receipt.removed_token_ids.contains(&use_.token_id));
            self.consumed_bounded_use_ids.extend(invalidated);
        }
        receipt
    }

    /// Consumes one bounded admission use, then reviews and applies through Runtime Host.
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
        } else if self.consumed_bounded_use_ids.len() >= MAX_BROKER_BOUNDED_USES {
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
        mutation_receipt(
            &self.provider_epoch_id,
            &request.admission_use_request_id,
            admission_revision,
            command_selected,
            true,
            None,
            Some(adapter_receipt),
            Some(consumed_use),
        )
    }

    /// Consumes one accepted bounded use for a non-command capability such as
    /// canonical `manifold.stream.subscribe`. The caller identity is a
    /// platform-verified adapter input; no transport-local acceptance exists.
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
        let rejection = if self
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
        } else if self.consumed_bounded_use_ids.len() >= MAX_BROKER_BOUNDED_USES {
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
        ManifoldBrokerCapabilityUseReceipt {
            schema_id: schema_id(BROKER_CAPABILITY_USE_RECEIPT_SCHEMA),
            provider_epoch_id: self.provider_epoch_id.clone(),
            applied: true,
            bounded_use: Some(bounded_use),
            rejection_reason: None,
        }
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
            consumed_bounded_use_ids: self.consumed_bounded_use_ids.iter().cloned().collect(),
        }
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

    fn staged_copy(&self) -> Result<Self, ManifoldBrokerRuntimeStateError> {
        let evidence = self.evidence();
        let control_lease_authority =
            ManifoldBrokerControlLeaseAuthority::from_caller_attested_retained_authority_state(
                evidence
                    .control_lease_authority
                    .current_authority_snapshot
                    .clone(),
                evidence.control_lease_authority.current_clock.clone(),
                evidence.control_lease_authority.lease_sources.clone(),
            )
            .map_err(ManifoldBrokerRuntimeStateError::ControlLeaseAuthority)?;
        Self::restore_from_caller_attested_exclusive_evidence(
            self.adapter.clone(),
            control_lease_authority,
            evidence,
        )
    }
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

fn authority_migration_context_closes(
    source: &LegacyBrokerRuntimeEvidenceV2,
    adapter_config: &ManifoldBrokerAdapterConfig,
    authority_evidence: &ManifoldBrokerControlLeaseAuthorityEvidence,
    resulting_evidence: &ManifoldBrokerRuntimeEvidence,
) -> bool {
    source.schema_id.as_str() == LEGACY_BROKER_RUNTIME_EVIDENCE_V2_SCHEMA
        && resulting_evidence.schema_id.as_str() == BROKER_RUNTIME_EVIDENCE_SCHEMA
        && source.provider_epoch_id == resulting_evidence.provider_epoch_id
        && source.host_snapshot == resulting_evidence.host_snapshot
        && source.admission_snapshot == resulting_evidence.admission_snapshot
        && source.pending_bounded_uses == resulting_evidence.pending_bounded_uses
        && source.consumed_bounded_use_ids == resulting_evidence.consumed_bounded_use_ids
        && authority_evidence == &resulting_evidence.control_lease_authority
        && adapter_config.authority_host_id == source.host_snapshot.host_id
}

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
    authority
        .validate_host_snapshot(&source.host_snapshot)
        .map_err(ManifoldBrokerRuntimeStateError::ControlLeaseAuthority)?;

    let mut canonical_leases = source.host_snapshot.leases.clone();
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
    };

    fn id(value: &str) -> DottedId {
        DottedId::new(value).expect("id")
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
    ) -> ManifoldBrokerControlLeaseAuthority {
        assert!(leases.len() <= 1, "bounded test authority");
        let mut prior: ManifoldAuthoritySnapshot = serde_json::from_str(include_str!(
            "../../../fixtures/authority/synthetic-authority-snapshot.json"
        ))
        .expect("prior authority snapshot");
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
        let control_lease_authority = control_lease_authority(&leases);
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
                expires_at_ms: 100_000,
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
        let control_lease_authority = control_lease_authority(&[]);
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
    }

    #[test]
    fn observer_rejection_cannot_roll_back_a_one_use_mutation() {
        let command_id = "command.media.session.start";
        let lease = ManifoldRuntimeLease {
            lease_id: id("lease.media.session.runtime.observer"),
            scope: id("lease.media.session"),
            holder_id: id("client.runtime.test"),
            expires_at_ms: 60_000,
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
        let authority = ManifoldBrokerControlLeaseAuthority::refresh_from_evidence(
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
        let authority = ManifoldBrokerControlLeaseAuthority::refresh_from_evidence(
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
        let authority = ManifoldBrokerControlLeaseAuthority::refresh_from_evidence(
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
    fn committed_v3_runtime_evidence_closes_owner_host_and_admission_state() {
        let evidence_json =
            include_str!("../../../fixtures/broker-adapter/runtime-evidence-v3.json");
        let evidence: ManifoldBrokerRuntimeEvidence =
            serde_json::from_str(evidence_json).expect("committed v3 evidence");
        let config: ManifoldBrokerAdapterConfig = serde_json::from_str(include_str!(
            "../../../fixtures/broker-adapter/standalone-config.json"
        ))
        .expect("committed adapter config");
        let authority = ManifoldBrokerControlLeaseAuthority::refresh_from_evidence(
            evidence.control_lease_authority.clone(),
            evidence
                .control_lease_authority
                .current_authority_snapshot
                .clone(),
            evidence.control_lease_authority.current_clock.clone(),
        )
        .expect("committed control-lease authority");
        let host_json = serde_json::to_string(&evidence.host_snapshot).expect("host snapshot");
        let adapter = ManifoldBrokerAdapter::restart_from_json(
            config,
            include_bytes!("../../../fixtures/broker-adapter/standalone-product-lock.json"),
            &host_json,
            &authority,
        )
        .expect("committed adapter restart");
        let runtime = ManifoldBrokerRuntime::restore_from_caller_attested_exclusive_evidence_json(
            adapter,
            authority,
            evidence_json,
        )
        .expect("committed runtime restart");
        assert_eq!(runtime.evidence(), evidence);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn v2_runtime_evidence_requires_explicit_authority_adoption_migration() {
        let evidence: ManifoldBrokerRuntimeEvidence = serde_json::from_str(include_str!(
            "../../../fixtures/broker-adapter/runtime-evidence-v3.json"
        ))
        .expect("committed v3 evidence");
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
        let authority = ManifoldBrokerControlLeaseAuthority::refresh_from_evidence(
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
        assert_eq!(
            receipt.host_lease_set_sha256,
            sha256_binding(
                MIGRATION_HOST_LEASE_SET_DIGEST_DOMAIN,
                &serde_json::to_vec(&typed_legacy.host_snapshot.leases).expect("host leases")
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
                &serde_json::to_vec(&migrated.evidence().control_lease_authority)
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
                &substituted.control_lease_authority,
                &substituted,
            )
            .is_err());

        let resulting_evidence = migrated.evidence();
        receipt
            .validate_against(
                &legacy_json,
                &config,
                &resulting_evidence.control_lease_authority,
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
                            &resulting_evidence.control_lease_authority,
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
                &substituted.control_lease_authority,
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
                &substituted.control_lease_authority,
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
