//! Additive complete v6 Broker persistence and pre-Start cleanup registrations.
//!
//! Existing v5 evidence is a core projection only when pins exist. R5b must
//! switch every real persistence/restore join to complete v6 before Start.
//! Registration verifies Broker provenance and separately trusted deployment
//! inputs. Its Peer route projection is caller-attested: no Start is permitted
//! until the actual Peer owner derives/checks it. There is no completion API.

use super::{
    schema_id, serialize_migration_artifact, sha256_binding, validate_runtime_evidence_json_size,
    ManifoldBrokerRuntime, ManifoldBrokerRuntimeEvidence, ManifoldBrokerRuntimeStateError,
};
use crate::{
    ManifoldBrokerAdapter, ManifoldBrokerControlLeaseAuthority,
    ManifoldBrokerControlLeaseAuthorityEvidenceV2,
};
use crate::{
    ManifoldBrokerCleanupAuthority, ManifoldBrokerCleanupAuthorization,
    ManifoldBrokerCleanupBinding, ManifoldBrokerCleanupChallenge, ManifoldBrokerCleanupCredential,
    ManifoldBrokerCleanupSnapshot, ManifoldBrokerCleanupTrust,
};
use rusty_manifold_admission::{ManifoldAdmissionGrant, ManifoldClientIdentity};
use rusty_manifold_model::{ClockHealth, DottedId, ManifoldClockSnapshot, SchemaId};
use rusty_manifold_runtime_host::ManifoldRuntimeLease;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Complete opt-in persistence envelope with cleanup pins and Pending history.
pub const BROKER_RUNTIME_EVIDENCE_V6_SCHEMA: &str = "rusty.manifold.broker.runtime_evidence.v6";
/// Explicit decision-free v5 core to complete v6 migration receipt.
pub const BROKER_RUNTIME_CLEANUP_MIGRATION_SCHEMA: &str =
    "rusty.manifold.broker.runtime_evidence_cleanup_migration_receipt.v1";
/// Fixed registry cap for this source slice; no continuous-service capacity proof.
pub const MAX_BROKER_CLEANUP_REGISTRATIONS: usize = 64;
/// Closed released v5 core transport, retained unchanged for explicit migration.
/// This transport is incomplete for a cleanup-enabled deployment.
pub type LegacyManifoldBrokerRuntimeEvidenceV5 = ManifoldBrokerRuntimeEvidence;
const COMPLETE_DOMAIN: &str = "rusty.manifold.broker.cleanup_complete_evidence.v6";
const REGISTRATION_DOMAIN: &str = "rusty.manifold.broker.cleanup_registration.v1";
const MIGRATION_SOURCE_DOMAIN: &str = "rusty.manifold.broker.cleanup_migration.v5_to_v6.source.v1";
const MIGRATION_RESULT_DOMAIN: &str = "rusty.manifold.broker.cleanup_migration.v5_to_v6.result.v1";

/// Explicit deployment inputs obtained independently of the registration request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerCleanupDeploymentInputs {
    /// Issuer/audience pinned by the deployment owner before Start.
    pub trust: ManifoldBrokerCleanupTrust,
    /// Sole cleanup revoker.
    pub revoker_principal: String,
    /// App-owned feature lock, distinct from Broker client lock provenance.
    pub feature_lock_id: String,
    /// Exact packaged app feature lock digest.
    pub feature_lock_sha256: String,
    /// Full separately platform-verified original client identity.
    pub original_identity: ManifoldClientIdentity,
}

/// Expected immutable pin supplied from independently trusted deployment storage.
/// Reading this from the same untrusted snapshot is not continuity validation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerCleanupExpectedRegistration {
    /// Replay-protected registration identity.
    pub registration_id: DottedId,
    /// Exact original target and pinned trust.
    pub binding: ManifoldBrokerCleanupBinding,
    /// Independent installed-product/identity inputs.
    pub deployment_inputs: ManifoldBrokerCleanupDeploymentInputs,
    /// Caller-attested digest of original accepted Peer route projection.
    /// Actual Peer owner verification is required before any Start.
    pub peer_route_projection_sha256: String,
}

/// Immutable Broker registration plus durable challenge/Pending snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerCleanupRegistration {
    expected: ManifoldBrokerCleanupExpectedRegistration,
    original_grant: ManifoldAdmissionGrant,
    original_lease: ManifoldRuntimeLease,
    registered_clock: ManifoldClockSnapshot,
    owner_authority_id: DottedId,
    owner_authority_revision: rusty_manifold_model::Revision,
    registration_audit_sha256: String,
    cleanup_snapshot: ManifoldBrokerCleanupSnapshot,
}
impl ManifoldBrokerCleanupRegistration {
    /// Immutable independently retained pin to require on future restores.
    #[must_use]
    pub fn expected(&self) -> &ManifoldBrokerCleanupExpectedRegistration {
        &self.expected
    }
    /// Pending cleanup evidence, never a terminal effect receipt.
    #[must_use]
    pub fn cleanup_snapshot(&self) -> &ManifoldBrokerCleanupSnapshot {
        &self.cleanup_snapshot
    }
    /// Immutable registration audit digest.
    #[must_use]
    pub fn registration_audit_sha256(&self) -> &str {
        &self.registration_audit_sha256
    }
    fn audit(&self) -> Result<String, ManifoldBrokerRuntimeStateError> {
        hash_typed(
            REGISTRATION_DOMAIN,
            &(
                &self.expected,
                &self.original_grant,
                &self.original_lease,
                &self.registered_clock,
                &self.owner_authority_id,
                self.owner_authority_revision,
            ),
        )
    }
}

/// Complete persistence transport. Nested v5 retains exactly its old meanings.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerRuntimeEvidenceV6 {
    /// Complete envelope version; v5 JSON cannot decode as this transport.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Closed v5 core projection, not a complete cleanup-enabled snapshot.
    pub core_evidence: ManifoldBrokerRuntimeEvidence,
    /// Strictly sorted immutable cleanup targets and durable Pending ledgers.
    pub cleanup_registrations: Vec<ManifoldBrokerCleanupRegistration>,
    /// Latest honest clock observed by cleanup authority in this epoch.
    pub cleanup_clock: Option<ManifoldClockSnapshot>,
}
impl ManifoldBrokerRuntimeEvidenceV6 {
    /// Complete digest to commit in independently trusted journal/storage.
    /// # Errors
    /// Rejects serialization or the overall Broker evidence byte budget.
    pub fn anchor_sha256(&self) -> Result<String, ManifoldBrokerRuntimeStateError> {
        hash_typed(COMPLETE_DOMAIN, self)
    }
}

/// Decision-free migration evidence. No registration or authority is synthesized.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerRuntimeCleanupMigrationReceipt {
    /// Receipt version.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Exact released source JSON digest.
    pub source_json_sha256: String,
    /// Complete typed result digest.
    pub resulting_evidence_sha256: String,
    /// Source bytes retained unchanged by migration.
    pub source_size_bytes: usize,
    /// Number of synthesized pins, always zero.
    pub synthesized_registration_count: usize,
}

/// Independently supplied deployment continuity requirements, not snapshot fields.
#[derive(Clone, Debug)]
pub struct ManifoldBrokerCleanupRestoreRequirements {
    /// Exact expected registrations from trusted committed deployment state.
    pub expected_registrations: Vec<ManifoldBrokerCleanupExpectedRegistration>,
    /// Complete v6 digest from independent durable storage.
    pub complete_anchor_sha256: String,
    /// Fresh honest non-regressing clock read in the retained owner epoch.
    pub clock: ManifoldClockSnapshot,
}

impl ManifoldBrokerRuntime {
    /// Complete opt-in snapshot for cleanup-enabled persistence. Every R5b
    /// persistence join must use this before Start; `evidence()` is core-only.
    #[must_use]
    pub fn complete_evidence_v6(&self) -> ManifoldBrokerRuntimeEvidenceV6 {
        ManifoldBrokerRuntimeEvidenceV6 {
            schema_id: schema_id(BROKER_RUNTIME_EVIDENCE_V6_SCHEMA),
            core_evidence: self.evidence(),
            cleanup_registrations: self.cleanup_registrations.values().cloned().collect(),
            cleanup_clock: self.cleanup_clock.clone(),
        }
    }
    pub(super) fn validate_complete_cleanup_size(
        &self,
    ) -> Result<(), ManifoldBrokerRuntimeStateError> {
        serialize_migration_artifact(&self.complete_evidence_v6()).map(|_| ())
    }
    /// Register an immutable retained target before platform Start. Broker grant,
    /// full projected identity, lease and exact lock provenance are checked;
    /// Peer route/effect projection remains caller-attested until Peer integration.
    /// Deployment must independently obtain inputs, fence one writer and persist
    /// complete v6 plus its anchor before observing a registration as durable.
    /// # Errors
    /// Rejects mismatched provenance, expiry, invalid clock, replay or capacity.
    pub fn register_cleanup_before_start(
        &mut self,
        expected: ManifoldBrokerCleanupExpectedRegistration,
        trusted_inputs: &ManifoldBrokerCleanupDeploymentInputs,
        clock: ManifoldClockSnapshot,
    ) -> Result<ManifoldBrokerCleanupRegistration, ManifoldBrokerRuntimeStateError> {
        if self.cleanup_registrations.len() >= MAX_BROKER_CLEANUP_REGISTRATIONS
            || expected.registration_id.as_str().len() > 256
            || self
                .cleanup_registrations
                .contains_key(&expected.registration_id)
            || self.cleanup_registrations.values().any(|r| {
                r.expected.binding.target.route_grant_id == expected.binding.target.route_grant_id
            })
            || &expected.deployment_inputs != trusted_inputs
        {
            return Err(invalid("cleanup_registration_replay_or_inputs"));
        }
        let now = self.check_cleanup_clock(&clock)?;
        let binding = &expected.binding;
        let target = &binding.target;
        let grant = self
            .admission
            .snapshot()
            .grants
            .iter()
            .find(|g| g.grant_id.as_str() == target.admission_id)
            .ok_or_else(|| invalid("cleanup_original_grant"))?;
        let lease = self
            .adapter
            .host_snapshot()
            .leases
            .iter()
            .find(|l| l.lease_id.as_str() == target.lease_id)
            .ok_or_else(|| invalid("cleanup_original_lease"))?;
        if grant.revoked
            || now >= grant.expires_at_ms
            || now >= lease.expires_at_ms
            || grant.identity != trusted_inputs.original_identity
            || target.original_principal != grant.identity.client_id.as_str()
            || target.admission_expires_at_ms != grant.expires_at_ms
            || target.client_lock_id != grant.client_lock_id.as_str()
            || target.client_lock_sha256 != grant.client_lock_fingerprint
            || target.lease_expires_at_ms != lease.expires_at_ms
            || lease.holder_id != grant.identity.client_id
            || lease.scope.as_str() != "lease.media.session"
            || !self
                .control_lease_authority
                .runtime_leases()
                .contains(lease)
            || self
                .control_lease_revocation_barriers
                .contains_key(&lease.lease_id)
            || self.has_pending_revocation_barrier()
            || !binding_matches_runtime(self, &expected)
            || !canonical_sha(&expected.peer_route_projection_sha256)
        {
            return Err(invalid("cleanup_registration_provenance"));
        }
        let authority = ManifoldBrokerCleanupAuthority::pin_before_start(binding.clone(), now)
            .map_err(|_| invalid("cleanup_binding"))?;
        let mut record = ManifoldBrokerCleanupRegistration {
            expected,
            original_grant: grant.clone(),
            original_lease: lease.clone(),
            registered_clock: clock.clone(),
            owner_authority_id: self
                .control_lease_authority
                .authority_snapshot()
                .authority_id
                .clone(),
            owner_authority_revision: self
                .control_lease_authority
                .authority_snapshot()
                .authority_revision,
            registration_audit_sha256: String::new(),
            cleanup_snapshot: authority.snapshot(),
        };
        record.registration_audit_sha256 = record.audit()?;
        let mut candidate = self.staged_copy()?;
        candidate
            .cleanup_registrations
            .insert(record.expected.registration_id.clone(), record.clone());
        candidate.cleanup_clock = Some(clock);
        candidate.validate_complete_cleanup_size()?;
        *self = candidate;
        Ok(record)
    }
    /// Create a fresh challenge only for the retained registered target.
    /// # Errors
    /// Rejects missing registration, Pending, clock failure or verifier capacity.
    pub fn challenge_registered_cleanup(
        &mut self,
        registration_id: &DottedId,
        clock: ManifoldClockSnapshot,
    ) -> Result<ManifoldBrokerCleanupChallenge, ManifoldBrokerRuntimeStateError> {
        let now = self.check_cleanup_clock(&clock)?;
        let mut candidate = self.staged_copy()?;
        let record = candidate
            .cleanup_registrations
            .get_mut(registration_id)
            .ok_or_else(|| invalid("cleanup_registration_missing"))?;
        let mut authority = restore_held_record(record, now)?;
        let challenge = authority
            .challenge(&clock.clock_epoch_id.to_string(), now)
            .map_err(|_| invalid("cleanup_challenge"))?;
        record.cleanup_snapshot = authority.snapshot();
        candidate.cleanup_clock = Some(clock);
        candidate.validate_complete_cleanup_size()?;
        *self = candidate;
        Ok(challenge)
    }
    /// Consume a fresh credential into Pending for the exact registered target.
    /// No ordinary token/lease or terminal Peer receipt is produced.
    /// # Errors
    /// Rejects signature/binding/request/clock/replay or persistence capacity.
    pub fn authorize_registered_cleanup(
        &mut self,
        registration_id: &DottedId,
        credential: &ManifoldBrokerCleanupCredential,
        request_id: &str,
        clock: ManifoldClockSnapshot,
    ) -> Result<ManifoldBrokerCleanupAuthorization, ManifoldBrokerRuntimeStateError> {
        let now = self.check_cleanup_clock(&clock)?;
        let mut candidate = self.staged_copy()?;
        let record = candidate
            .cleanup_registrations
            .get_mut(registration_id)
            .ok_or_else(|| invalid("cleanup_registration_missing"))?;
        let mut authority = restore_held_record(record, now)?;
        let authorization = authority
            .authorize(
                credential,
                request_id,
                &clock.clock_epoch_id.to_string(),
                now,
            )
            .map_err(|_| invalid("cleanup_authorization"))?;
        record.cleanup_snapshot = authority.snapshot();
        candidate.cleanup_clock = Some(clock);
        candidate.validate_complete_cleanup_size()?;
        *self = candidate;
        Ok(authorization)
    }
    /// Restore complete v6 only against independently supplied exact pins,
    /// complete anchor, honest owner clock and externally exclusive deployment.
    /// Core-only v5 restoration is not safe for a cleanup-enabled deployment.
    /// # Errors
    /// Rejects downgrade, missing pins, altered registry/core, bad closure or clock.
    #[allow(clippy::too_many_lines)] // One closed restore transaction; no partial state escapes.
    pub fn restore_complete_evidence_v6(
        adapter: ManifoldBrokerAdapter,
        owner: ManifoldBrokerControlLeaseAuthority,
        evidence: ManifoldBrokerRuntimeEvidenceV6,
        requirements: &ManifoldBrokerCleanupRestoreRequirements,
    ) -> Result<Self, ManifoldBrokerRuntimeStateError> {
        serialize_migration_artifact(&evidence)?;
        if evidence.schema_id.as_str() != BROKER_RUNTIME_EVIDENCE_V6_SCHEMA
            || evidence.cleanup_registrations.len() > MAX_BROKER_CLEANUP_REGISTRATIONS
            || evidence.anchor_sha256()? != requirements.complete_anchor_sha256
            || evidence.cleanup_registrations.len() != requirements.expected_registrations.len()
            || evidence
                .cleanup_registrations
                .windows(2)
                .any(|w| w[0].expected.registration_id >= w[1].expected.registration_id)
            || requirements
                .expected_registrations
                .windows(2)
                .any(|w| w[0].registration_id >= w[1].registration_id)
            || evidence
                .cleanup_registrations
                .iter()
                .zip(&requirements.expected_registrations)
                .any(|(r, e)| &r.expected != e)
            || evidence.cleanup_clock.is_some() == evidence.cleanup_registrations.is_empty()
        {
            return Err(invalid("cleanup_complete_anchor_or_pins"));
        }
        let mut runtime = Self::restore_from_caller_attested_exclusive_evidence(
            adapter,
            owner,
            evidence.core_evidence,
        )?;
        check_clock(
            runtime.control_lease_authority.current_clock(),
            &requirements.clock,
        )?;
        if let Some(retained) = &evidence.cleanup_clock {
            check_clock(retained, &requirements.clock)?;
        }
        let now = clock_ms(&requirements.clock)?;
        let retained_cleanup_clock = evidence.cleanup_clock.as_ref();
        let mut grants = BTreeSet::new();
        for record in evidence.cleanup_registrations {
            let expected = &record.expected;
            if !grants.insert(expected.binding.target.route_grant_id.clone())
                || !binding_matches_runtime(&runtime, expected)
                || !canonical_sha(&expected.peer_route_projection_sha256)
                || record.registration_audit_sha256 != record.audit()?
                || record.original_grant.identity != expected.deployment_inputs.original_identity
                || !runtime
                    .admission
                    .snapshot()
                    .grants
                    .contains(&record.original_grant)
                || !original_lease_retained(
                    &runtime.control_lease_authority.evidence(),
                    &record.original_lease,
                    record.owner_authority_revision,
                )
                || record.owner_authority_id
                    != runtime
                        .control_lease_authority
                        .authority_snapshot()
                        .authority_id
                || record.owner_authority_revision
                    > runtime
                        .control_lease_authority
                        .authority_snapshot()
                        .authority_revision
                || record.original_grant.grant_id.as_str() != expected.binding.target.admission_id
                || record.original_grant.expires_at_ms
                    != expected.binding.target.admission_expires_at_ms
                || record.original_grant.client_lock_id.as_str()
                    != expected.binding.target.client_lock_id
                || record.original_grant.client_lock_fingerprint
                    != expected.binding.target.client_lock_sha256
                || record.original_lease.lease_id.as_str() != expected.binding.target.lease_id
                || record.original_lease.holder_id.as_str()
                    != expected.binding.target.original_principal
                || record.original_lease.expires_at_ms
                    != expected.binding.target.lease_expires_at_ms
                || record.original_lease.scope.as_str() != "lease.media.session"
                || record.original_grant.revoked
                || clock_ms(&record.registered_clock)? >= record.original_grant.expires_at_ms
                || clock_ms(&record.registered_clock)? >= record.original_lease.expires_at_ms
            {
                return Err(invalid("cleanup_registration_closure"));
            }
            check_clock(&record.registered_clock, &requirements.clock)?;
            let retained =
                retained_cleanup_clock.ok_or_else(|| invalid("cleanup_clock_missing"))?;
            check_clock(&record.registered_clock, retained)?;
            if clock_ms(retained)? < record.cleanup_snapshot.last_ms() {
                return Err(invalid("cleanup_clock_snapshot_join"));
            }
            // Independently anchored complete evidence authenticates this exact
            // retained sub-snapshot; its own self-digest is not the trust source.
            let held = restore_held_record(&record, now)?;
            if held.snapshot().binding() != &expected.binding
                || record.cleanup_snapshot.initial_ms() != clock_ms(&record.registered_clock)?
            {
                return Err(invalid("cleanup_snapshot_registration_join"));
            }
            runtime
                .cleanup_registrations
                .insert(expected.registration_id.clone(), record);
        }
        if !runtime.cleanup_registrations.is_empty() {
            runtime.cleanup_clock = Some(requirements.clock.clone());
        }
        runtime.validate_complete_cleanup_size()?;
        Ok(runtime)
    }
    /// Bounded JSON entrypoint; old v5 JSON is rejected before resumable state.
    /// # Errors
    /// Rejects over-budget JSON, wrong transport, pins, anchor or owner closure.
    pub fn restore_complete_evidence_v6_json(
        adapter: ManifoldBrokerAdapter,
        owner: ManifoldBrokerControlLeaseAuthority,
        json: &str,
        requirements: &ManifoldBrokerCleanupRestoreRequirements,
    ) -> Result<Self, ManifoldBrokerRuntimeStateError> {
        validate_runtime_evidence_json_size(json)?;
        let evidence =
            serde_json::from_str(json).map_err(ManifoldBrokerRuntimeStateError::Deserialize)?;
        Self::restore_complete_evidence_v6(adapter, owner, evidence, requirements)
    }
    /// Explicit decision-free migration from released v5 JSON. Separately
    /// supplied expected pins must be empty: old evidence cannot recover them.
    /// Existing v5 bytes and admission/lease decisions are left unchanged.
    /// # Errors
    /// Rejects wrong version, malformed core or any expected cleanup pins.
    pub fn migrate_v5_to_complete_v6_json(
        adapter: ManifoldBrokerAdapter,
        owner: ManifoldBrokerControlLeaseAuthority,
        json: &str,
        expected_pins: &[ManifoldBrokerCleanupExpectedRegistration],
    ) -> Result<(Self, ManifoldBrokerRuntimeCleanupMigrationReceipt), ManifoldBrokerRuntimeStateError>
    {
        validate_runtime_evidence_json_size(json)?;
        if !expected_pins.is_empty() {
            return Err(invalid("cleanup_migration_cannot_synthesize_pins"));
        }
        let core: LegacyManifoldBrokerRuntimeEvidenceV5 =
            serde_json::from_str(json).map_err(ManifoldBrokerRuntimeStateError::Deserialize)?;
        let runtime = Self::restore_from_caller_attested_exclusive_evidence(adapter, owner, core)?;
        let complete = runtime.complete_evidence_v6();
        let receipt = ManifoldBrokerRuntimeCleanupMigrationReceipt {
            schema_id: schema_id(BROKER_RUNTIME_CLEANUP_MIGRATION_SCHEMA),
            source_json_sha256: sha256_binding(MIGRATION_SOURCE_DOMAIN, json.as_bytes()),
            resulting_evidence_sha256: hash_typed(MIGRATION_RESULT_DOMAIN, &complete)?,
            source_size_bytes: json.len(),
            synthesized_registration_count: 0,
        };
        Ok((runtime, receipt))
    }
    fn check_cleanup_clock(
        &self,
        clock: &ManifoldClockSnapshot,
    ) -> Result<u64, ManifoldBrokerRuntimeStateError> {
        check_clock(self.control_lease_authority.current_clock(), clock)?;
        if let Some(retained) = &self.cleanup_clock {
            check_clock(retained, clock)?;
        }
        clock_ms(clock)
    }
}
fn invalid(reason: &'static str) -> ManifoldBrokerRuntimeStateError {
    ManifoldBrokerRuntimeStateError::InvalidEvidence(reason)
}
fn canonical_sha(s: &str) -> bool {
    s.len() == 71
        && s.starts_with("sha256:")
        && s.as_bytes()[7..]
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}
fn hash_typed<T: Serialize>(
    domain: &str,
    value: &T,
) -> Result<String, ManifoldBrokerRuntimeStateError> {
    Ok(sha256_binding(
        domain,
        &serialize_migration_artifact(value)?,
    ))
}
fn clock_ms(clock: &ManifoldClockSnapshot) -> Result<u64, ManifoldBrokerRuntimeStateError> {
    u64::try_from(clock.wall_unix_ms).map_err(|_| invalid("cleanup_negative_clock"))
}
fn check_clock(
    retained: &ManifoldClockSnapshot,
    clock: &ManifoldClockSnapshot,
) -> Result<(), ManifoldBrokerRuntimeStateError> {
    if clock.schema_id != retained.schema_id
        || clock.clock_domain != retained.clock_domain
        || clock.clock_epoch_id != retained.clock_epoch_id
        || clock.health != ClockHealth::Healthy
        || clock.read_uncertainty_ns > crate::MAX_BROKER_RUNTIME_LEASE_CLOCK_UNCERTAINTY_NS
        || clock.sequence < retained.sequence
        || clock.monotonic_elapsed_ns < retained.monotonic_elapsed_ns
        || clock.wall_unix_ms < retained.wall_unix_ms
        || clock.wall_clock_adjustment_count != retained.wall_clock_adjustment_count
    {
        return Err(invalid("cleanup_clock_continuity"));
    }
    Ok(())
}
fn binding_matches_runtime(
    runtime: &ManifoldBrokerRuntime,
    expected: &ManifoldBrokerCleanupExpectedRegistration,
) -> bool {
    let binding = &expected.binding;
    let target = &binding.target;
    let deployment = &expected.deployment_inputs;
    let config = runtime.adapter.config();
    binding.trust == deployment.trust
        && binding.revoker_principal == deployment.revoker_principal
        && target.feature_lock_id == deployment.feature_lock_id
        && target.feature_lock_sha256 == deployment.feature_lock_sha256
        && target.original_principal == deployment.original_identity.client_id.as_str()
        && target.authority_host == config.authority_host_id.as_str()
        && target.provider_epoch == runtime.provider_epoch_id.as_str()
        && target.product_lock_id == config.product_lock_id.as_str()
        && target.product_lock_fingerprint == config.product_lock_fingerprint
        && target.product_lock_sha256 == config.product_lock_sha256
        && binding.clock_epoch
            == runtime
                .control_lease_authority
                .current_clock()
                .clock_epoch_id
                .as_str()
}
fn restore_held_record(
    record: &ManifoldBrokerCleanupRegistration,
    now: u64,
) -> Result<ManifoldBrokerCleanupAuthority, ManifoldBrokerRuntimeStateError> {
    ManifoldBrokerCleanupAuthority::restore(
        record.cleanup_snapshot.clone(),
        &record.expected.binding,
        &record.cleanup_snapshot.anchor_sha256(),
        &record.expected.binding.clock_epoch,
        now,
    )
    .map_err(|_| invalid("cleanup_snapshot_closure"))
}
fn original_lease_retained(
    owner: &ManifoldBrokerControlLeaseAuthorityEvidenceV2,
    lease: &ManifoldRuntimeLease,
    registration_revision: rusty_manifold_model::Revision,
) -> bool {
    // Owner validation already replayed these snapshots. Preserve the exact
    // accepted generic lease even after normal expiry removes it from Host.
    let matches = |s: &rusty_manifold_model::ManifoldAuthoritySnapshot| {
        s.authority_revision == registration_revision
            && s.active_leases.iter().any(|l| {
                l.lease_id == lease.lease_id
                    && l.holder_id == lease.holder_id
                    && l.scope == lease.scope
                    && l.expires_at_ms == lease.expires_at_ms
            })
    };
    matches(&owner.baseline.current_authority_snapshot)
        || matches(&owner.current_authority_snapshot)
        || owner
            .transitions
            .iter()
            .any(|t| matches(&t.prior_authority_snapshot))
}

#[cfg(test)]
mod tests {
    use super::super::{
        control_lease_lifecycle_capability, ManifoldBrokerControlLeaseLifecycleOperation,
        ManifoldBrokerControlLeaseLifecycleOperationKind,
    };
    use super::*;
    use crate::{
        broker_cleanup_signing_bytes, ManifoldBrokerCleanupAction, ManifoldBrokerCleanupStatement,
        ManifoldBrokerCleanupTarget,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use rusty_manifold_broker_product::ManifoldBrokerFeature;

    fn id(s: &str) -> DottedId {
        DottedId::new(s).unwrap()
    }
    fn sha(byte: &str) -> String {
        format!("sha256:{}", byte.repeat(32))
    }
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
    fn setup() -> (
        ManifoldBrokerRuntime,
        ManifoldBrokerCleanupExpectedRegistration,
        SigningKey,
    ) {
        let runtime = super::super::tests::runtime(
            vec![ManifoldBrokerFeature::MediaSession],
            vec![control_lease_lifecycle_capability(
                ManifoldBrokerControlLeaseLifecycleOperationKind::Expiry,
            )],
            vec![ManifoldRuntimeLease {
                lease_id: id("lease.media.session.cleanup"),
                scope: id("lease.media.session"),
                holder_id: id("client.runtime.test"),
                expires_at_ms: 60_000,
                derivative_binding: None,
            }],
            "provider.cleanup.test",
        );
        let key = SigningKey::from_bytes(&[27; 32]);
        let trust = ManifoldBrokerCleanupTrust {
            issuer: "issuer.cleanup.test".into(),
            public_key_hex: hex(&key.verifying_key().to_bytes()),
            audience: "audience.cleanup.test".into(),
        };
        let grant = &runtime.admission.snapshot().grants[0];
        let lease = &runtime.adapter.host_snapshot().leases[0];
        let config = runtime.adapter.config();
        let inputs = ManifoldBrokerCleanupDeploymentInputs {
            trust: trust.clone(),
            revoker_principal: "revoker.cleanup.test".into(),
            feature_lock_id: "lock.feature.cleanup.test".into(),
            feature_lock_sha256: sha("d2"),
            original_identity: grant.identity.clone(),
        };
        let binding = ManifoldBrokerCleanupBinding {
            trust,
            revoker_principal: inputs.revoker_principal.clone(),
            clock_epoch: runtime
                .control_lease_authority
                .current_clock()
                .clock_epoch_id
                .to_string(),
            target: ManifoldBrokerCleanupTarget {
                authority_host: config.authority_host_id.to_string(),
                provider_epoch: runtime.provider_epoch_id.to_string(),
                original_principal: grant.identity.client_id.to_string(),
                admission_id: grant.grant_id.to_string(),
                admission_expires_at_ms: grant.expires_at_ms,
                lease_id: lease.lease_id.to_string(),
                lease_expires_at_ms: lease.expires_at_ms,
                product_lock_id: config.product_lock_id.to_string(),
                product_lock_fingerprint: config.product_lock_fingerprint.clone(),
                product_lock_sha256: config.product_lock_sha256.clone(),
                client_lock_id: grant.client_lock_id.to_string(),
                client_lock_sha256: grant.client_lock_fingerprint.clone(),
                feature_lock_id: inputs.feature_lock_id.clone(),
                feature_lock_sha256: inputs.feature_lock_sha256.clone(),
                route_grant_id: "grant.pair.cleanup.test".into(),
                route_revision: 7,
                platform_runtime: "platform.cleanup.test".into(),
                effect_target_sha256: sha("e3"),
            },
        };
        (
            runtime,
            ManifoldBrokerCleanupExpectedRegistration {
                registration_id: id("registration.cleanup.test"),
                binding,
                deployment_inputs: inputs,
                peer_route_projection_sha256: sha("f4"),
            },
            key,
        )
    }
    fn register(
        runtime: &mut ManifoldBrokerRuntime,
        expected: &ManifoldBrokerCleanupExpectedRegistration,
    ) {
        let clock = runtime.control_lease_authority.current_clock().clone();
        runtime
            .register_cleanup_before_start(expected.clone(), &expected.deployment_inputs, clock)
            .unwrap();
    }
    fn owner(runtime: &ManifoldBrokerRuntime) -> ManifoldBrokerControlLeaseAuthority {
        let evidence = runtime.control_lease_authority.evidence();
        ManifoldBrokerControlLeaseAuthority::refresh_from_v2_evidence(
            evidence.clone(),
            evidence.current_authority_snapshot,
            evidence.current_clock,
        )
        .unwrap()
    }
    fn requirements(runtime: &ManifoldBrokerRuntime) -> ManifoldBrokerCleanupRestoreRequirements {
        let evidence = runtime.complete_evidence_v6();
        ManifoldBrokerCleanupRestoreRequirements {
            expected_registrations: evidence
                .cleanup_registrations
                .iter()
                .map(|r| r.expected.clone())
                .collect(),
            complete_anchor_sha256: evidence.anchor_sha256().unwrap(),
            clock: runtime
                .cleanup_clock
                .as_ref()
                .unwrap_or(runtime.control_lease_authority.current_clock())
                .clone(),
        }
    }
    fn credential(
        runtime: &mut ManifoldBrokerRuntime,
        expected: &ManifoldBrokerCleanupExpectedRegistration,
        key: &SigningKey,
        clock: &ManifoldClockSnapshot,
    ) -> ManifoldBrokerCleanupCredential {
        let challenge = runtime
            .challenge_registered_cleanup(&expected.registration_id, clock.clone())
            .unwrap();
        let now = clock_ms(clock).unwrap();
        let statement = ManifoldBrokerCleanupStatement {
            issuer: expected.binding.trust.issuer.clone(),
            audience: expected.binding.trust.audience.clone(),
            target: expected.binding.target.clone(),
            revoker_principal: expected.binding.revoker_principal.clone(),
            action: ManifoldBrokerCleanupAction::AcknowledgeRetainedPairRouteCleanup,
            challenge,
            request_id: "request.cleanup.test".into(),
            issued_at_ms: now,
            expires_at_ms: now + 1000,
        };
        let signature_hex = hex(&key
            .sign(&broker_cleanup_signing_bytes(&statement))
            .to_bytes());
        ManifoldBrokerCleanupCredential {
            statement,
            signature_hex,
        }
    }
    fn later(clock: &ManifoldClockSnapshot, now_ms: u64) -> ManifoldClockSnapshot {
        let mut next = clock.clone();
        let elapsed = now_ms - clock_ms(clock).unwrap();
        next.sequence += 1;
        next.monotonic_elapsed_ns += elapsed * 1_000_000;
        next.wall_unix_ms = i64::try_from(now_ms).unwrap();
        next
    }
    #[test]
    fn registration_checks_broker_provenance_and_independent_inputs() {
        let (mut runtime, expected, _) = setup();
        let clock = runtime.control_lease_authority.current_clock().clone();
        let trusted = expected.deployment_inputs.clone();
        for field in [
            "authority_host",
            "provider_epoch",
            "original_principal",
            "admission_id",
            "lease_id",
            "product_lock_id",
            "product_lock_fingerprint",
            "product_lock_sha256",
            "client_lock_id",
            "client_lock_sha256",
            "feature_lock_id",
            "feature_lock_sha256",
            "admission_expires_at_ms",
            "lease_expires_at_ms",
        ] {
            let mut value = serde_json::to_value(&expected).unwrap();
            let old = &value["binding"]["target"][field];
            value["binding"]["target"][field] = if let Some(n) = old.as_u64() {
                serde_json::json!(n + 1)
            } else {
                serde_json::json!("wrong.provenance")
            };
            let wrong = serde_json::from_value(value).unwrap();
            assert!(
                runtime
                    .register_cleanup_before_start(wrong, &trusted, clock.clone())
                    .is_err(),
                "{field}"
            );
        }
        let mut wrong = expected.clone();
        wrong.binding.trust.issuer = "issuer.other".into();
        assert!(runtime
            .register_cleanup_before_start(wrong, &trusted, clock.clone())
            .is_err());
        let mut wrong = expected.clone();
        wrong.deployment_inputs.original_identity.platform_subject = "package.other".into();
        let matching_wrong_inputs = wrong.deployment_inputs.clone();
        assert!(runtime
            .register_cleanup_before_start(wrong, &matching_wrong_inputs, clock.clone())
            .is_err());
        let mut wrong = expected.clone();
        wrong.binding.clock_epoch = "clock_epoch.other".into();
        assert!(runtime
            .register_cleanup_before_start(wrong, &trusted, clock.clone())
            .is_err());
        let record = runtime
            .register_cleanup_before_start(expected.clone(), &trusted, clock.clone())
            .unwrap();
        assert_eq!(record.expected(), &expected);
        assert!(runtime
            .register_cleanup_before_start(expected, &trusted, clock)
            .is_err());
    }
    #[test]
    fn complete_restore_retains_pins_pending_and_rejects_damage_or_downgrade() {
        let (mut runtime, expected, key) = setup();
        register(&mut runtime, &expected);
        let clock = runtime.control_lease_authority.current_clock().clone();
        let credential = credential(&mut runtime, &expected, &key, &clock);
        runtime
            .authorize_registered_cleanup(
                &expected.registration_id,
                &credential,
                "request.cleanup.test",
                clock.clone(),
            )
            .unwrap();
        let evidence = runtime.complete_evidence_v6();
        let req = requirements(&runtime);
        let mut restored = ManifoldBrokerRuntime::restore_complete_evidence_v6(
            runtime.adapter.clone(),
            owner(&runtime),
            evidence.clone(),
            &req,
        )
        .unwrap();
        assert_eq!(restored.complete_evidence_v6(), evidence);
        assert!(restored
            .authorize_registered_cleanup(
                &expected.registration_id,
                &credential,
                "request.cleanup.test",
                clock
            )
            .is_err());
        let staged = restored.staged_copy().unwrap();
        assert_eq!(
            staged.complete_evidence_v6(),
            restored.complete_evidence_v6()
        );
        let v5_json = serde_json::to_string(&runtime.evidence()).unwrap();
        assert!(ManifoldBrokerRuntime::restore_complete_evidence_v6_json(
            runtime.adapter.clone(),
            owner(&runtime),
            &v5_json,
            &req
        )
        .is_err());
        let mut damaged = vec![];
        let mut v = evidence.clone();
        v.cleanup_registrations.clear();
        v.cleanup_clock = None;
        damaged.push(v);
        let mut v = evidence.clone();
        v.cleanup_registrations[0].registration_audit_sha256 = sha("00");
        damaged.push(v);
        let mut v = evidence.clone();
        v.cleanup_registrations[0].expected.binding.trust.audience = "audience.other".into();
        damaged.push(v);
        let mut v = evidence.clone();
        v.cleanup_registrations[0].original_lease.expires_at_ms += 1;
        damaged.push(v);
        let mut v = evidence.clone();
        v.cleanup_clock.as_mut().unwrap().clock_epoch_id = id("clock_epoch.other");
        damaged.push(v);
        let mut v = evidence.clone();
        v.cleanup_registrations
            .push(v.cleanup_registrations[0].clone());
        damaged.push(v);
        let mut v = serde_json::to_value(&evidence).unwrap();
        v["cleanup_registrations"][0]["cleanup_snapshot"]["pending"] = serde_json::Value::Null;
        damaged.push(serde_json::from_value(v).unwrap());
        for v in damaged {
            assert!(ManifoldBrokerRuntime::restore_complete_evidence_v6(
                runtime.adapter.clone(),
                owner(&runtime),
                v.clone(),
                &req
            )
            .is_err());
            let mut newly_anchored = req.clone();
            newly_anchored.complete_anchor_sha256 = v.anchor_sha256().unwrap();
            assert!(ManifoldBrokerRuntime::restore_complete_evidence_v6(
                runtime.adapter.clone(),
                owner(&runtime),
                v,
                &newly_anchored
            )
            .is_err());
        }
        let mut regressed = req.clone();
        regressed.clock.sequence -= 1;
        assert!(ManifoldBrokerRuntime::restore_complete_evidence_v6(
            runtime.adapter.clone(),
            owner(&runtime),
            evidence,
            &regressed
        )
        .is_err());
    }
    #[test]
    fn decision_free_v5_migration_is_empty_and_cannot_satisfy_expected_pins() {
        let (runtime, expected, _) = setup();
        let source = runtime.evidence();
        let json = serde_json::to_string(&source).unwrap();
        let (migrated, receipt) = ManifoldBrokerRuntime::migrate_v5_to_complete_v6_json(
            runtime.adapter.clone(),
            owner(&runtime),
            &json,
            &[],
        )
        .unwrap();
        assert_eq!(migrated.evidence(), source);
        assert_eq!(
            receipt.source_json_sha256,
            sha256_binding(MIGRATION_SOURCE_DOMAIN, json.as_bytes())
        );
        assert_eq!(receipt.synthesized_registration_count, 0);
        assert!(migrated
            .complete_evidence_v6()
            .cleanup_registrations
            .is_empty());
        assert!(ManifoldBrokerRuntime::migrate_v5_to_complete_v6_json(
            runtime.adapter.clone(),
            owner(&runtime),
            &json,
            &[expected.clone()]
        )
        .is_err());
        let v6 = migrated.complete_evidence_v6();
        let req = ManifoldBrokerCleanupRestoreRequirements {
            expected_registrations: vec![expected],
            complete_anchor_sha256: v6.anchor_sha256().unwrap(),
            clock: runtime.control_lease_authority.current_clock().clone(),
        };
        assert!(ManifoldBrokerRuntime::restore_complete_evidence_v6(
            runtime.adapter.clone(),
            owner(&runtime),
            v6,
            &req
        )
        .is_err());
        let mut value = serde_json::to_value(&source).unwrap();
        value["cleanup_registrations"] = serde_json::json!([]);
        assert!(
            serde_json::from_value::<ManifoldBrokerRuntimeEvidence>(value).is_err(),
            "released v5 transport stays closed"
        );
    }
    #[test]
    fn released_v5_fixture_keeps_exact_typed_serialization_bytes() {
        let bytes = include_str!("../../../../fixtures/broker-adapter/runtime-evidence-v5.json");
        let legacy: LegacyManifoldBrokerRuntimeEvidenceV5 = serde_json::from_str(bytes).unwrap();
        assert_eq!(
            legacy.schema_id.as_str(),
            crate::BROKER_RUNTIME_EVIDENCE_SCHEMA
        );
        assert_eq!(
            format!("{}\n", serde_json::to_string_pretty(&legacy).unwrap()),
            bytes
        );
    }
    #[test]
    fn ordinary_expiry_keeps_registration_and_fresh_pending_blocks_drained_rollover() {
        let (mut runtime, expected, key) = setup();
        register(&mut runtime, &expected);
        let expiry_wall = runtime.host_snapshot().leases[0].expires_at_ms + 1;
        let revision = runtime
            .control_lease_authority_snapshot()
            .authority_revision;
        let lease = runtime.host_snapshot().leases[0].lease_id.clone();
        let request = super::super::tests::authorize_lifecycle(
            &mut runtime,
            ManifoldBrokerControlLeaseLifecycleOperation::Expiry {
                request_id: id("request.cleanup.original.expiry"),
                lease_ids: vec![lease],
                expected_authority_revision: revision,
                sweep_reason: id("reason.cleanup.original.expiry"),
                requested_at_ms: expiry_wall,
            },
            "cleanup.original.expiry",
            14,
            Some(expiry_wall - 1000),
        );
        let mut clock = super::super::tests::next_control_lease_clock(&runtime, 1);
        clock.wall_unix_ms = i64::try_from(expiry_wall).unwrap();
        let receipt = runtime
            .commit_control_lease_lifecycle(
                &request,
                clock,
                vec![id("evidence.cleanup.original.expiry")],
                |receipt, _| receipt.clone(),
            )
            .unwrap();
        assert!(receipt.applied, "{receipt:?}");
        assert!(runtime.host_snapshot().leases.is_empty());
        assert_eq!(
            runtime.complete_evidence_v6().cleanup_registrations[0].expected,
            expected
        );
        let expired_time = expected.binding.target.admission_expires_at_ms + 1;
        let clock = later(
            runtime.control_lease_authority.current_clock(),
            expired_time,
        );
        let sweep = runtime.expire_tokens(
            id("sweep.cleanup.original.expired"),
            runtime.admission_snapshot().authority_revision,
            expired_time,
        );
        assert!(sweep.applied, "{sweep:?}");
        let credential = credential(&mut runtime, &expected, &key, &clock);
        runtime
            .authorize_registered_cleanup(
                &expected.registration_id,
                &credential,
                "request.cleanup.test",
                clock.clone(),
            )
            .unwrap();
        assert!(runtime.complete_evidence_v6().cleanup_registrations[0]
            .cleanup_snapshot
            .pending()
            .is_some());
        let req = requirements(&runtime);
        let snapshot = runtime.complete_evidence_v6();
        ManifoldBrokerRuntime::restore_complete_evidence_v6(
            runtime.adapter.clone(),
            owner(&runtime),
            snapshot,
            &req,
        )
        .unwrap();
        let mut fresh = runtime.admission_snapshot().clone();
        fresh.active_tokens.clear();
        fresh.revoked_token_ids.clear();
        fresh.consumed_request_ids.clear();
        fresh.consumed_use_request_ids.clear();
        fresh.reviewed_sweep_ids.clear();
        fresh.audit_events.clear();
        assert!(
            runtime
                .rollover_drained_provider_epoch(id("provider.cleanup.next"), fresh)
                .is_err(),
            "only retained cleanup pins now prevent rollover"
        );
    }
}
