//! Source-only Manifold Runtime Host with deterministic review and application.

use rusty_manifold_model::{DottedId, Revision, SchemaId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

/// Runtime host snapshot schema.
pub const HOST_SNAPSHOT_SCHEMA: &str = "rusty.manifold.runtime_host.snapshot.v1";
/// Runtime host command request schema.
pub const HOST_COMMAND_REQUEST_SCHEMA: &str = "rusty.manifold.runtime_host.command_request.v1";
/// Runtime host dispatch receipt schema.
pub const HOST_DISPATCH_RECEIPT_SCHEMA: &str = "rusty.manifold.runtime_host.dispatch_receipt.v1";
/// Runtime host application receipt schema.
pub const HOST_APPLICATION_RECEIPT_SCHEMA: &str =
    "rusty.manifold.runtime_host.application_receipt.v1";
/// Runtime host lease-expiry receipt schema.
pub const HOST_LEASE_EXPIRY_RECEIPT_SCHEMA: &str =
    "rusty.manifold.runtime_host.lease_expiry_receipt.v1";
/// Runtime host audit-event schema.
pub const HOST_AUDIT_EVENT_SCHEMA: &str = "rusty.manifold.runtime_host.audit_event.v1";

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
    /// Dispatch receipt and request do not match.
    DispatchMismatch,
    /// Dispatch was reviewed against an older snapshot.
    DispatchRevisionMismatch,
    /// Expiry sweep found no expired leases.
    NoExpiredLeases,
}

/// Source-only dispatch receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldRuntimeDispatchReceipt {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Derived dispatch identity.
    pub dispatch_id: DottedId,
    /// Reviewed request identity.
    pub request_id: DottedId,
    /// Reviewed command identity.
    pub command_id: DottedId,
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
    /// Derived receipt identity.
    pub receipt_id: DottedId,
    /// Dispatch identity.
    pub dispatch_id: DottedId,
    /// Request identity.
    pub request_id: DottedId,
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
        let snapshot = serde_json::from_str(json).map_err(ManifoldRuntimeHostError::Deserialize)?;
        Self::from_snapshot(snapshot)
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
            dispatch_id: derived_id("dispatch.runtime", &request.request_id),
            request_id: request.request_id.clone(),
            command_id: request.command_id.clone(),
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
    ) -> ManifoldRuntimeApplicationReceipt {
        let prior = self.snapshot.authority_revision;
        let mismatch = dispatch.schema_id.as_str() != HOST_DISPATCH_RECEIPT_SCHEMA
            || dispatch.dispatch_id != derived_id("dispatch.runtime", &request.request_id)
            || dispatch.request_id != request.request_id
            || dispatch.command_id != request.command_id;
        let stale_dispatch = dispatch.reviewed_authority_revision != prior;
        let rejection = if mismatch {
            Some(ManifoldRuntimeRejectionReason::DispatchMismatch)
        } else if stale_dispatch {
            Some(ManifoldRuntimeRejectionReason::DispatchRevisionMismatch)
        } else {
            dispatch.rejection_reason.clone()
        };
        let applied =
            dispatch.outcome == ManifoldRuntimeDispatchOutcome::Ready && rejection.is_none();
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
            ManifoldRuntimeAuditKind::CommandApplication,
            &request.request_id,
            prior,
            resulting,
            applied,
            rejection.clone(),
        );
        self.snapshot.audit_events.push(event);
        ManifoldRuntimeApplicationReceipt {
            schema_id: schema_id(HOST_APPLICATION_RECEIPT_SCHEMA),
            receipt_id: derived_id("receipt.runtime", &request.request_id),
            dispatch_id: dispatch.dispatch_id.clone(),
            request_id: request.request_id.clone(),
            applied,
            prior_authority_revision: prior,
            resulting_authority_revision: resulting,
            rejection_reason: rejection,
        }
    }

    /// Performs an explicit revision-guarded lease expiry sweep.
    pub fn expire_leases(
        &mut self,
        sweep_id: DottedId,
        expected_revision: Revision,
        now_ms: u64,
    ) -> ManifoldRuntimeLeaseExpiryReceipt {
        let prior = self.snapshot.authority_revision;
        let mut removed = Vec::new();
        let rejection = if expected_revision != prior {
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

fn validate_snapshot(
    snapshot: &ManifoldRuntimeHostSnapshot,
) -> Result<(), ManifoldRuntimeHostError> {
    if snapshot.schema_id.as_str() != HOST_SNAPSHOT_SCHEMA {
        return Err(ManifoldRuntimeHostError::InvalidSnapshot("schema_mismatch"));
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
    for event in &snapshot.audit_events {
        if event.schema_id.as_str() != HOST_AUDIT_EVENT_SCHEMA
            || (event.applied
                && event.prior_authority_revision.next()
                    != Some(event.resulting_authority_revision))
            || (!event.applied
                && event.prior_authority_revision != event.resulting_authority_revision)
            || event.resulting_authority_revision > snapshot.authority_revision
        {
            return Err(ManifoldRuntimeHostError::InvalidSnapshot("audit_lineage"));
        }
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

fn audit_event(
    kind: ManifoldRuntimeAuditKind,
    source_id: &DottedId,
    prior: Revision,
    resulting: Revision,
    applied: bool,
    rejection: Option<ManifoldRuntimeRejectionReason>,
) -> ManifoldRuntimeAuditEvent {
    ManifoldRuntimeAuditEvent {
        schema_id: schema_id(HOST_AUDIT_EVENT_SCHEMA),
        event_id: derived_id("audit.runtime", source_id),
        event_kind: kind,
        source_id: source_id.clone(),
        prior_authority_revision: prior,
        resulting_authority_revision: resulting,
        applied,
        rejection_reason: rejection,
    }
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

    #[test]
    fn dispatch_application_and_restart_preserve_revision_replay_and_audit() {
        let snapshot = fixture("fixtures/runtime-host/synthetic-runtime-host-snapshot.json");
        let request = fixture("fixtures/runtime-host/synthetic-runtime-command-request.json");
        let mut host = ManifoldRuntimeHost::from_snapshot(snapshot).expect("snapshot");
        let dispatch = host.review_command(&request, 2_000);
        assert_eq!(dispatch.outcome, ManifoldRuntimeDispatchOutcome::Ready);
        let applied = host.apply_dispatch(&request, &dispatch);
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
            let receipt = host.apply_dispatch(&request, &dispatch);
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
        let receipt = host.apply_dispatch(&request, &dispatch);
        assert!(!receipt.applied);
        assert_eq!(
            receipt.rejection_reason,
            Some(ManifoldRuntimeRejectionReason::DispatchMismatch)
        );
        assert_eq!(host.snapshot().authority_revision.get(), 1);
    }
}
