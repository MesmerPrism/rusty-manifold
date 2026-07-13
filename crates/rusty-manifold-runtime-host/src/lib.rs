//! Source-only Manifold Runtime Host with deterministic review and application.

use rusty_manifold_model::{DottedId, Revision, SchemaId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

/// Legacy Runtime Host snapshot schema accepted only by the migration API.
pub const LEGACY_HOST_SNAPSHOT_V1_SCHEMA: &str = "rusty.manifold.runtime_host.snapshot.v1";
/// Runtime Host snapshot schema with closed replay/audit lineage.
pub const HOST_SNAPSHOT_SCHEMA: &str = "rusty.manifold.runtime_host.snapshot.v2";
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
/// Legacy Runtime Host audit schema accepted only during snapshot migration.
pub const LEGACY_HOST_AUDIT_EVENT_V1_SCHEMA: &str = "rusty.manifold.runtime_host.audit_event.v1";
/// Runtime Host audit-event schema with canonical sequence identities.
pub const HOST_AUDIT_EVENT_SCHEMA: &str = "rusty.manifold.runtime_host.audit_event.v2";
/// Explicit Runtime Host snapshot migration receipt schema.
pub const HOST_MIGRATION_RECEIPT_SCHEMA: &str =
    "rusty.manifold.runtime_host.snapshot_migration_receipt.v1";
/// Maximum canonical low-rate parameter document accepted by Runtime Host.
pub const MAX_TYPED_PARAMS_CANONICAL_BYTES: u32 = 4_096;
/// Maximum durable command/sweep audit attempts retained by one host snapshot.
pub const MAX_RUNTIME_AUDIT_EVENTS: usize = 8_192;
/// Maximum entries in static and replay collections.
pub const MAX_RUNTIME_SNAPSHOT_RECORDS: usize = 4_096;

/// Registered low-rate command descriptor.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldRuntimeCommandDescriptor {
    /// Stable command identifier.
    pub command_id: DottedId,
    /// Required lease scope, when the command mutates scoped state.
    pub required_lease_scope: Option<DottedId>,
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
}

/// Runtime-host audit event kind.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldRuntimeAuditKind {
    /// Command dispatch/application result.
    CommandApplication,
    /// Explicit lease-expiry sweep result.
    LeaseExpiry,
}

/// Durable evidence that a Runtime Host restart either consumed current v2
/// state directly or migrated a validated legacy v1 snapshot.
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
    /// Number of legacy audit records assigned canonical v2 sequence ids.
    pub migrated_audit_event_count: usize,
    /// First-seen legacy sweep ids retained against replay.
    pub reviewed_sweep_ids: Vec<DottedId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct LegacyRuntimeAuditEventV1 {
    #[serde(rename = "$schema")]
    schema_id: SchemaId,
    event_id: DottedId,
    event_kind: ManifoldRuntimeAuditKind,
    source_id: DottedId,
    prior_authority_revision: Revision,
    resulting_authority_revision: Revision,
    applied: bool,
    rejection_reason: Option<ManifoldRuntimeRejectionReason>,
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

    /// Restarts current v2 state or migrates a validated v1 snapshot while
    /// returning explicit schema/audit migration evidence.
    ///
    /// # Errors
    ///
    /// Returns an error when source JSON, legacy lineage, or resulting v2
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
        if probe.schema_id.as_str() != LEGACY_HOST_SNAPSHOT_V1_SCHEMA {
            return Err(ManifoldRuntimeHostError::InvalidSnapshot(
                "unsupported_snapshot_schema",
            ));
        }
        let legacy: LegacyRuntimeHostSnapshotV1 =
            serde_json::from_str(json).map_err(ManifoldRuntimeHostError::Deserialize)?;
        migrate_legacy_runtime_host_snapshot(legacy)
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
                dispatch,
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
        application_receipt(request, dispatch, prior, resulting, applied, rejection)
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

fn migrate_legacy_runtime_host_snapshot(
    legacy: LegacyRuntimeHostSnapshotV1,
) -> Result<(ManifoldRuntimeHost, ManifoldRuntimeHostMigrationReceipt), ManifoldRuntimeHostError> {
    validate_legacy_runtime_host_snapshot(&legacy)?;
    let mut reviewed_sweep_ids = legacy
        .audit_events
        .iter()
        .filter(|event| event.event_kind == ManifoldRuntimeAuditKind::LeaseExpiry)
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
                event_kind: event.event_kind.clone(),
                source_id: event.source_id.clone(),
                prior_authority_revision: event.prior_authority_revision,
                resulting_authority_revision: event.resulting_authority_revision,
                applied: event.applied,
                rejection_reason: event.rejection_reason.clone(),
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
            event.event_kind == ManifoldRuntimeAuditKind::CommandApplication && event.applied
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
            ManifoldRuntimeAuditKind::CommandApplication if event.applied => {
                seen_applied_commands.insert(event.source_id.clone())
            }
            ManifoldRuntimeAuditKind::CommandApplication => {
                event.rejection_reason.is_some()
                    && (event.rejection_reason
                        != Some(ManifoldRuntimeRejectionReason::ReplayedRequest)
                        || seen_applied_commands.contains(&event.source_id))
            }
            ManifoldRuntimeAuditKind::LeaseExpiry => {
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
    if applied_command_sources != retained_applied_sources
        || reviewed_sweep_sources != retained_sweep_sources
    {
        return Err(ManifoldRuntimeHostError::InvalidSnapshot(
            "audit_replay_set_mismatch",
        ));
    }
    let mut rolling_revision = Revision::INITIAL;
    let mut seen_applied_commands = BTreeSet::new();
    let mut seen_sweeps = BTreeSet::new();
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
    }
}

fn application_receipt(
    request: &ManifoldRuntimeCommandRequest,
    dispatch: &ManifoldRuntimeDispatchReceipt,
    prior_authority_revision: Revision,
    resulting_authority_revision: Revision,
    applied: bool,
    rejection_reason: Option<ManifoldRuntimeRejectionReason>,
) -> ManifoldRuntimeApplicationReceipt {
    ManifoldRuntimeApplicationReceipt {
        schema_id: schema_id(HOST_APPLICATION_RECEIPT_SCHEMA),
        authority_host_id: dispatch.authority_host_id.clone(),
        receipt_id: derived_id("receipt.runtime", &request.request_id),
        dispatch_id: dispatch.dispatch_id.clone(),
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

    fn fixture<T: serde::de::DeserializeOwned>(path: &str) -> T {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(path);
        serde_json::from_str(&std::fs::read_to_string(root).expect("fixture must load"))
            .expect("fixture must deserialize")
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

    #[test]
    fn dispatch_application_and_restart_preserve_revision_replay_and_audit() {
        let snapshot = fixture("fixtures/runtime-host/synthetic-runtime-host-snapshot.json");
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
        let expected: ManifoldRuntimeHostSnapshot =
            fixture("fixtures/runtime-host/synthetic-runtime-host-restarted-snapshot.json");
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
    fn applied_replay_repeated_rejection_and_repeated_sweep_restart_cleanly() {
        let snapshot = fixture("fixtures/runtime-host/synthetic-runtime-host-snapshot.json");
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
        let snapshot = fixture("fixtures/runtime-host/synthetic-runtime-host-snapshot.json");
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
    fn command_and_sweep_caps_reject_before_creating_unrestorable_state() {
        let mut command_snapshot: ManifoldRuntimeHostSnapshot =
            fixture("fixtures/runtime-host/synthetic-runtime-host-snapshot.json");
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
        let dispatch = host.review_command(&overflow, 2_000);
        let receipt = host.apply_dispatch(&overflow, &dispatch, 2_000);
        assert_eq!(
            receipt.rejection_reason,
            Some(ManifoldRuntimeRejectionReason::AuthorityCapacityExhausted)
        );
        assert_eq!(
            host.snapshot().applied_request_ids.len(),
            MAX_RUNTIME_SNAPSHOT_RECORDS
        );
        ManifoldRuntimeHost::restart_from_json(&host.snapshot_json().expect("json"))
            .expect("command-cap snapshot remains restorable");

        let mut sweep_snapshot: ManifoldRuntimeHostSnapshot =
            fixture("fixtures/runtime-host/synthetic-runtime-host-snapshot.json");
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
        let snapshot = fixture("fixtures/runtime-host/synthetic-runtime-host-snapshot.json");
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
        let snapshot = fixture("fixtures/runtime-host/synthetic-runtime-host-snapshot.json");
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
        let snapshot = fixture("fixtures/runtime-host/synthetic-runtime-host-snapshot.json");
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
        let snapshot: ManifoldRuntimeHostSnapshot =
            fixture("fixtures/runtime-host/synthetic-runtime-host-snapshot.json");

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
        let snapshot = fixture("fixtures/runtime-host/synthetic-runtime-host-snapshot.json");
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
        let snapshot: ManifoldRuntimeHostSnapshot =
            fixture("fixtures/runtime-host/synthetic-runtime-host-snapshot.json");
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
