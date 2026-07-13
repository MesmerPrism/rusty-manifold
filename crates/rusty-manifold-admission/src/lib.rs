//! Revisioned cross-app grants and short-lived opaque token authority.

use rusty_manifold_model::{DottedId, Revision, SchemaId};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Legacy admission snapshot schema accepted only by the migration API.
pub const LEGACY_ADMISSION_SNAPSHOT_V1_SCHEMA: &str = "rusty.manifold.admission.snapshot.v1";
/// Admission snapshot schema with exact packaged client-lock provenance.
pub const ADMISSION_SNAPSHOT_SCHEMA: &str = "rusty.manifold.admission.snapshot.v2";
/// Admission request schema.
pub const ADMISSION_REQUEST_SCHEMA: &str = "rusty.manifold.admission.request.v1";
/// Token use request schema.
pub const ADMISSION_USE_REQUEST_SCHEMA: &str = "rusty.manifold.admission.use_request.v1";
/// Token revocation request schema.
pub const ADMISSION_REVOCATION_REQUEST_SCHEMA: &str =
    "rusty.manifold.admission.revocation_request.v1";
/// Legacy admission token schema accepted only during snapshot migration.
pub const LEGACY_ADMISSION_TOKEN_V1_SCHEMA: &str = "rusty.manifold.admission.token.v1";
/// Admission token schema with exact packaged client-lock provenance.
pub const ADMISSION_TOKEN_SCHEMA: &str = "rusty.manifold.admission.token.v2";
/// Unified admission receipt schema.
pub const ADMISSION_RECEIPT_SCHEMA: &str = "rusty.manifold.admission.receipt.v2";
/// Legacy admission audit schema accepted only during snapshot migration.
pub const LEGACY_ADMISSION_AUDIT_V1_SCHEMA: &str = "rusty.manifold.admission.audit_event.v1";
/// Admission audit event schema with canonical sequence identities.
pub const ADMISSION_AUDIT_SCHEMA: &str = "rusty.manifold.admission.audit_event.v2";
/// Explicit v1-to-v2 admission snapshot migration receipt schema.
pub const ADMISSION_MIGRATION_RECEIPT_SCHEMA: &str =
    "rusty.manifold.admission.snapshot_migration_receipt.v1";
/// Maximum durable records in any replay/token collection.
pub const MAX_ADMISSION_RECORDS: usize = 4_096;
/// Maximum durable admission audit attempts.
pub const MAX_ADMISSION_AUDIT_EVENTS: usize = 8_192;

/// Stable client identity after platform UID/package/signature projection.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldClientIdentity {
    /// Stable logical client id.
    pub client_id: DottedId,
    /// Platform subject, such as an Android package name.
    pub platform_subject: String,
    /// Lowercase SHA-256 signing-certificate fingerprint.
    pub signing_fingerprint: String,
}

/// Operator/product-approved capability grant.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldAdmissionGrant {
    /// Stable grant identity.
    pub grant_id: DottedId,
    /// Exact packaged broker client-lock identity.
    pub client_lock_id: DottedId,
    /// SHA-256 of the exact packaged broker client-lock bytes.
    pub client_lock_fingerprint: String,
    /// Exact trusted client identity.
    pub identity: ManifoldClientIdentity,
    /// Sorted allowed capabilities.
    pub capabilities: Vec<DottedId>,
    /// Absolute grant expiry.
    pub expires_at_ms: u64,
    /// Explicit revocation state.
    pub revoked: bool,
}

/// Short-lived opaque bearer token retained in accepted state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldAdmissionToken {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Opaque 256-bit random token id.
    pub token_id: DottedId,
    /// Bound client identity.
    pub identity: ManifoldClientIdentity,
    /// Source grant.
    pub grant_id: DottedId,
    /// Exact packaged broker client-lock identity inherited from the grant.
    pub client_lock_id: DottedId,
    /// Exact packaged broker client-lock SHA-256 inherited from the grant.
    pub client_lock_fingerprint: String,
    /// Exact granted capability subset.
    pub capabilities: Vec<DottedId>,
    /// Token issue time.
    pub issued_at_ms: u64,
    /// Token expiry time.
    pub expires_at_ms: u64,
    /// Authority revision that issued the token.
    pub issued_authority_revision: Revision,
}

/// Request for a token from an already platform-verified identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldAdmissionRequest {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Idempotency identity.
    pub request_id: DottedId,
    /// Expected admission authority revision.
    pub expected_authority_revision: Revision,
    /// Platform-verified identity.
    pub identity: ManifoldClientIdentity,
    /// Requested capability subset.
    pub requested_capabilities: Vec<DottedId>,
    /// Request issue time.
    pub issued_at_ms: u64,
    /// Request expiry time.
    pub expires_at_ms: u64,
    /// Requested token lifetime, bounded by authority policy and grant expiry.
    pub requested_token_ttl_ms: u64,
}

/// Capability use request guarded by a token and one-time request id.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldAdmissionUseRequest {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// One-time use request identity.
    pub request_id: DottedId,
    /// Expected admission authority revision.
    pub expected_authority_revision: Revision,
    /// Opaque token id.
    pub token_id: DottedId,
    /// Platform-verified calling identity.
    pub identity: ManifoldClientIdentity,
    /// Capability required by the downstream command.
    pub capability_id: DottedId,
    /// Request issue time.
    pub issued_at_ms: u64,
    /// Request expiry time.
    pub expires_at_ms: u64,
}

/// Explicit token revocation request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldAdmissionRevocationRequest {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// One-time revocation request identity.
    pub request_id: DottedId,
    /// Expected admission authority revision.
    pub expected_authority_revision: Revision,
    /// Opaque token id.
    pub token_id: DottedId,
    /// Platform-verified calling identity.
    pub identity: ManifoldClientIdentity,
    /// Stable low-sensitivity reason.
    pub reason: DottedId,
}

/// Admission operation recorded by receipts and audit.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldAdmissionOperation {
    /// Token issue.
    IssueToken,
    /// One-time capability use authorization.
    AuthorizeUse,
    /// Explicit token revocation.
    RevokeToken,
    /// Explicit expired-token sweep.
    ExpireTokens,
}

/// Stable rejection vocabulary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldAdmissionRejectionReason {
    /// Contract schema mismatch.
    SchemaMismatch,
    /// Request expected an older/newer authority revision.
    StaleAuthorityRevision,
    /// Request is future-issued or expired.
    ExpiredRequest,
    /// Request id has already been consumed.
    ReplayedRequest,
    /// Client id is not granted.
    UntrustedClient,
    /// Package/signature identity differs from the grant or token.
    IdentityMismatch,
    /// Matching grant is expired.
    GrantExpired,
    /// Matching grant is revoked.
    GrantRevoked,
    /// Requested capability is outside the grant.
    CapabilityEscalation,
    /// Requested token lifetime is zero or above policy.
    InvalidTokenLifetime,
    /// Random token id already exists or was revoked.
    TokenCollision,
    /// Token id is unknown.
    UnknownToken,
    /// Token has expired.
    TokenExpired,
    /// Token does not grant the requested capability.
    CapabilityDenied,
    /// Token is already revoked.
    TokenRevoked,
    /// Expiry sweep found no expired tokens.
    NoExpiredTokens,
    /// Expiry sweep identity was already reviewed.
    ReplayedSweep,
    /// Durable authority/replay capacity was reached.
    AuthorityCapacityExhausted,
    /// Authority revision cannot advance.
    RevisionExhausted,
}

/// Applied or rejected admission operation receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldAdmissionReceipt {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Stable operation.
    pub operation: ManifoldAdmissionOperation,
    /// Source request or sweep id.
    pub request_id: DottedId,
    /// Whether accepted state advanced.
    pub applied: bool,
    /// Prior authority revision.
    pub prior_authority_revision: Revision,
    /// Resulting authority revision.
    pub resulting_authority_revision: Revision,
    /// Token returned by successful issue.
    pub token: Option<ManifoldAdmissionToken>,
    /// Token ids removed by revocation/expiry.
    pub removed_token_ids: Vec<DottedId>,
    /// Rejection reason when not applied.
    pub rejection_reason: Option<ManifoldAdmissionRejectionReason>,
}

/// Append-only admission audit event.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldAdmissionAuditEvent {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Strictly increasing host-local attempt sequence.
    pub sequence: u64,
    /// Stable event identity.
    pub event_id: DottedId,
    /// Operation.
    pub operation: ManifoldAdmissionOperation,
    /// Source request/sweep identity.
    pub request_id: DottedId,
    /// Applied state.
    pub applied: bool,
    /// Prior authority revision.
    pub prior_authority_revision: Revision,
    /// Resulting authority revision.
    pub resulting_authority_revision: Revision,
    /// Rejection when applicable.
    pub rejection_reason: Option<ManifoldAdmissionRejectionReason>,
}

/// Durable accepted admission state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldAdmissionSnapshot {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Stable authority identity.
    pub authority_id: DottedId,
    /// Accepted revision.
    pub authority_revision: Revision,
    /// Trusted product/operator grants.
    pub grants: Vec<ManifoldAdmissionGrant>,
    /// Active issued tokens.
    pub active_tokens: Vec<ManifoldAdmissionToken>,
    /// Revoked token ids retained against reuse.
    pub revoked_token_ids: Vec<DottedId>,
    /// Consumed issue/revocation request ids.
    pub consumed_request_ids: Vec<DottedId>,
    /// Consumed capability-use request ids.
    pub consumed_use_request_ids: Vec<DottedId>,
    /// First-seen expiry sweep ids retained against replay.
    #[serde(default)]
    pub reviewed_sweep_ids: Vec<DottedId>,
    /// Append-only audit events.
    pub audit_events: Vec<ManifoldAdmissionAuditEvent>,
    /// Maximum token lifetime.
    pub max_token_ttl_ms: u64,
}

/// Caller-supplied exact packaged client-lock binding required to migrate one
/// legacy v1 grant. Migration never invents a lock identity or digest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldAdmissionLegacyClientLockBinding {
    /// Legacy grant receiving the exact packaged lock binding.
    pub grant_id: DottedId,
    /// Exact packaged broker client-lock identity.
    pub client_lock_id: DottedId,
    /// SHA-256 of the exact packaged broker client-lock bytes.
    pub client_lock_fingerprint: String,
}

/// Durable receipt for a current restart or explicit v1-to-v2 migration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldAdmissionMigrationReceipt {
    /// Receipt schema.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Source snapshot schema observed in the supplied JSON.
    pub source_schema_id: SchemaId,
    /// Resulting durable snapshot schema.
    pub resulting_schema_id: SchemaId,
    /// Whether a legacy snapshot was migrated.
    pub migrated: bool,
    /// Exact authority that was restarted.
    pub authority_id: DottedId,
    /// Resulting accepted authority revision.
    pub resulting_authority_revision: Revision,
    /// Grants explicitly rebound to packaged client locks.
    pub rebound_grant_ids: Vec<DottedId>,
    /// Active tokens that inherited their source grant's exact binding.
    pub migrated_token_ids: Vec<DottedId>,
    /// Number of legacy audit events assigned canonical v2 sequence ids.
    pub migrated_audit_event_count: usize,
    /// First-seen legacy sweep ids retained against replay.
    pub reviewed_sweep_ids: Vec<DottedId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct LegacyAdmissionGrantV1 {
    grant_id: DottedId,
    identity: ManifoldClientIdentity,
    capabilities: Vec<DottedId>,
    expires_at_ms: u64,
    revoked: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct LegacyAdmissionTokenV1 {
    #[serde(rename = "$schema")]
    schema_id: SchemaId,
    token_id: DottedId,
    identity: ManifoldClientIdentity,
    grant_id: DottedId,
    capabilities: Vec<DottedId>,
    issued_at_ms: u64,
    expires_at_ms: u64,
    issued_authority_revision: Revision,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct LegacyAdmissionAuditEventV1 {
    #[serde(rename = "$schema")]
    schema_id: SchemaId,
    event_id: DottedId,
    operation: ManifoldAdmissionOperation,
    request_id: DottedId,
    applied: bool,
    prior_authority_revision: Revision,
    resulting_authority_revision: Revision,
    rejection_reason: Option<ManifoldAdmissionRejectionReason>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct LegacyAdmissionSnapshotV1 {
    #[serde(rename = "$schema")]
    schema_id: SchemaId,
    authority_id: DottedId,
    authority_revision: Revision,
    grants: Vec<LegacyAdmissionGrantV1>,
    active_tokens: Vec<LegacyAdmissionTokenV1>,
    revoked_token_ids: Vec<DottedId>,
    consumed_request_ids: Vec<DottedId>,
    consumed_use_request_ids: Vec<DottedId>,
    audit_events: Vec<LegacyAdmissionAuditEventV1>,
    max_token_ttl_ms: u64,
}

#[derive(Deserialize)]
struct SchemaProbe {
    #[serde(rename = "$schema")]
    schema_id: SchemaId,
}

/// Admission authority over one durable snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldAdmissionAuthority {
    snapshot: ManifoldAdmissionSnapshot,
}

impl ManifoldAdmissionAuthority {
    /// Constructs and validates the durable state.
    pub fn from_snapshot(
        snapshot: ManifoldAdmissionSnapshot,
    ) -> Result<Self, ManifoldAdmissionError> {
        validate_snapshot(&snapshot)?;
        Ok(Self { snapshot })
    }

    /// Restarts from deterministic JSON.
    pub fn restart_from_json(json: &str) -> Result<Self, ManifoldAdmissionError> {
        let probe: SchemaProbe =
            serde_json::from_str(json).map_err(ManifoldAdmissionError::Deserialize)?;
        if probe.schema_id.as_str() == LEGACY_ADMISSION_SNAPSHOT_V1_SCHEMA {
            return Err(ManifoldAdmissionError::LegacyClientBindingsRequired);
        }
        let snapshot = serde_json::from_str(json).map_err(ManifoldAdmissionError::Deserialize)?;
        Self::from_snapshot(snapshot)
    }

    /// Restarts v2 state or explicitly migrates a v1 snapshot using an exact,
    /// complete grant-to-packaged-client-lock binding set.
    ///
    /// # Errors
    ///
    /// Returns an error when JSON, legacy lineage, binding completeness, or
    /// resulting v2 snapshot invariants fail.
    pub fn restart_from_json_with_migration(
        json: &str,
        legacy_bindings: &[ManifoldAdmissionLegacyClientLockBinding],
    ) -> Result<(Self, ManifoldAdmissionMigrationReceipt), ManifoldAdmissionError> {
        let probe: SchemaProbe =
            serde_json::from_str(json).map_err(ManifoldAdmissionError::Deserialize)?;
        if probe.schema_id.as_str() == ADMISSION_SNAPSHOT_SCHEMA {
            if !legacy_bindings.is_empty() {
                return Err(ManifoldAdmissionError::InvalidSnapshot(
                    "unexpected_legacy_bindings",
                ));
            }
            let authority = Self::restart_from_json(json)?;
            let receipt = admission_migration_receipt(
                probe.schema_id,
                authority.snapshot(),
                false,
                Vec::new(),
                Vec::new(),
                0,
            );
            return Ok((authority, receipt));
        }
        if probe.schema_id.as_str() != LEGACY_ADMISSION_SNAPSHOT_V1_SCHEMA {
            return Err(ManifoldAdmissionError::InvalidSnapshot(
                "unsupported_snapshot_schema",
            ));
        }
        let legacy: LegacyAdmissionSnapshotV1 =
            serde_json::from_str(json).map_err(ManifoldAdmissionError::Deserialize)?;
        migrate_legacy_admission_snapshot(legacy, legacy_bindings)
    }

    /// Returns accepted state.
    #[must_use]
    pub const fn snapshot(&self) -> &ManifoldAdmissionSnapshot {
        &self.snapshot
    }

    /// Serializes accepted state.
    pub fn snapshot_json(&self) -> Result<String, ManifoldAdmissionError> {
        serde_json::to_string(&self.snapshot).map_err(ManifoldAdmissionError::Serialize)
    }

    /// Issues a short-lived token using caller-supplied cryptographic entropy.
    pub fn issue_token(
        &mut self,
        request: &ManifoldAdmissionRequest,
        entropy: [u8; 32],
        now_ms: u64,
    ) -> ManifoldAdmissionReceipt {
        let prior = self.snapshot.authority_revision;
        if self.snapshot.audit_events.len() >= MAX_ADMISSION_AUDIT_EVENTS {
            return terminal_rejection(
                ManifoldAdmissionOperation::IssueToken,
                request.request_id.clone(),
                prior,
                ManifoldAdmissionRejectionReason::AuthorityCapacityExhausted,
            );
        }
        let grant = self
            .snapshot
            .grants
            .iter()
            .find(|grant| grant.identity.client_id == request.identity.client_id);
        let token_id = token_id(entropy);
        let rejection = validate_common(
            request.schema_id.as_str(),
            ADMISSION_REQUEST_SCHEMA,
            request.expected_authority_revision,
            prior,
            &request.request_id,
            &self.snapshot.consumed_request_ids,
            request.issued_at_ms,
            request.expires_at_ms,
            now_ms,
        )
        .err()
        .or_else(|| validate_grant(grant, request, now_ms).err())
        .or_else(|| {
            (request.requested_token_ttl_ms == 0
                || request.requested_token_ttl_ms > self.snapshot.max_token_ttl_ms)
                .then_some(ManifoldAdmissionRejectionReason::InvalidTokenLifetime)
        })
        .or_else(|| {
            (self
                .snapshot
                .active_tokens
                .iter()
                .any(|token| token.token_id == token_id)
                || self.snapshot.revoked_token_ids.contains(&token_id))
            .then_some(ManifoldAdmissionRejectionReason::TokenCollision)
        })
        .or_else(|| {
            (self.snapshot.active_tokens.len() >= MAX_ADMISSION_RECORDS
                || self.snapshot.consumed_request_ids.len() >= MAX_ADMISSION_RECORDS)
                .then_some(ManifoldAdmissionRejectionReason::AuthorityCapacityExhausted)
        })
        .or_else(|| {
            prior
                .next()
                .is_none()
                .then_some(ManifoldAdmissionRejectionReason::RevisionExhausted)
        });
        let mut token = None;
        if rejection.is_none() {
            let grant = grant.expect("validated grant exists");
            let expires_at_ms = now_ms
                .saturating_add(request.requested_token_ttl_ms)
                .min(grant.expires_at_ms);
            let issued = ManifoldAdmissionToken {
                schema_id: schema_id(ADMISSION_TOKEN_SCHEMA),
                token_id,
                identity: request.identity.clone(),
                grant_id: grant.grant_id.clone(),
                client_lock_id: grant.client_lock_id.clone(),
                client_lock_fingerprint: grant.client_lock_fingerprint.clone(),
                capabilities: sorted_ids(&request.requested_capabilities),
                issued_at_ms: now_ms,
                expires_at_ms,
                issued_authority_revision: prior.next().unwrap_or(prior),
            };
            self.snapshot.active_tokens.push(issued.clone());
            self.snapshot
                .active_tokens
                .sort_by(|left, right| left.token_id.cmp(&right.token_id));
            self.snapshot
                .consumed_request_ids
                .push(request.request_id.clone());
            self.snapshot.consumed_request_ids.sort();
            self.snapshot.authority_revision = prior.next().unwrap_or(prior);
            token = Some(issued);
        }
        self.finish(
            ManifoldAdmissionOperation::IssueToken,
            request.request_id.clone(),
            prior,
            token,
            Vec::new(),
            rejection,
        )
    }

    /// Authorizes one capability use and consumes its request id against replay.
    pub fn authorize_use(
        &mut self,
        request: &ManifoldAdmissionUseRequest,
        now_ms: u64,
    ) -> ManifoldAdmissionReceipt {
        let prior = self.snapshot.authority_revision;
        if self.snapshot.audit_events.len() >= MAX_ADMISSION_AUDIT_EVENTS {
            return terminal_rejection(
                ManifoldAdmissionOperation::AuthorizeUse,
                request.request_id.clone(),
                prior,
                ManifoldAdmissionRejectionReason::AuthorityCapacityExhausted,
            );
        }
        let token = self
            .snapshot
            .active_tokens
            .iter()
            .find(|token| token.token_id == request.token_id);
        let rejection = validate_common(
            request.schema_id.as_str(),
            ADMISSION_USE_REQUEST_SCHEMA,
            request.expected_authority_revision,
            prior,
            &request.request_id,
            &self.snapshot.consumed_use_request_ids,
            request.issued_at_ms,
            request.expires_at_ms,
            now_ms,
        )
        .err()
        .or_else(|| validate_token(token, request, &self.snapshot.revoked_token_ids, now_ms).err())
        .or_else(|| {
            (self.snapshot.consumed_use_request_ids.len() >= MAX_ADMISSION_RECORDS)
                .then_some(ManifoldAdmissionRejectionReason::AuthorityCapacityExhausted)
        })
        .or_else(|| {
            prior
                .next()
                .is_none()
                .then_some(ManifoldAdmissionRejectionReason::RevisionExhausted)
        });
        if rejection.is_none() {
            self.snapshot
                .consumed_use_request_ids
                .push(request.request_id.clone());
            self.snapshot.consumed_use_request_ids.sort();
            self.snapshot.authority_revision = prior.next().unwrap_or(prior);
        }
        self.finish(
            ManifoldAdmissionOperation::AuthorizeUse,
            request.request_id.clone(),
            prior,
            None,
            Vec::new(),
            rejection,
        )
    }

    /// Revokes a token owned by the exact calling identity.
    pub fn revoke_token(
        &mut self,
        request: &ManifoldAdmissionRevocationRequest,
    ) -> ManifoldAdmissionReceipt {
        let prior = self.snapshot.authority_revision;
        if self.snapshot.audit_events.len() >= MAX_ADMISSION_AUDIT_EVENTS {
            return terminal_rejection(
                ManifoldAdmissionOperation::RevokeToken,
                request.request_id.clone(),
                prior,
                ManifoldAdmissionRejectionReason::AuthorityCapacityExhausted,
            );
        }
        let token = self
            .snapshot
            .active_tokens
            .iter()
            .find(|token| token.token_id == request.token_id);
        let rejection = if request.schema_id.as_str() != ADMISSION_REVOCATION_REQUEST_SCHEMA {
            Some(ManifoldAdmissionRejectionReason::SchemaMismatch)
        } else if request.expected_authority_revision != prior {
            Some(ManifoldAdmissionRejectionReason::StaleAuthorityRevision)
        } else if self
            .snapshot
            .consumed_request_ids
            .contains(&request.request_id)
        {
            Some(ManifoldAdmissionRejectionReason::ReplayedRequest)
        } else if self.snapshot.revoked_token_ids.contains(&request.token_id) {
            Some(ManifoldAdmissionRejectionReason::TokenRevoked)
        } else if token.is_none() {
            Some(ManifoldAdmissionRejectionReason::UnknownToken)
        } else if token.map(|token| &token.identity) != Some(&request.identity) {
            Some(ManifoldAdmissionRejectionReason::IdentityMismatch)
        } else if self.snapshot.revoked_token_ids.len() >= MAX_ADMISSION_RECORDS
            || self.snapshot.consumed_request_ids.len() >= MAX_ADMISSION_RECORDS
        {
            Some(ManifoldAdmissionRejectionReason::AuthorityCapacityExhausted)
        } else if prior.next().is_none() {
            Some(ManifoldAdmissionRejectionReason::RevisionExhausted)
        } else {
            None
        };
        let mut removed = Vec::new();
        if rejection.is_none() {
            self.snapshot
                .active_tokens
                .retain(|token| token.token_id != request.token_id);
            self.snapshot
                .revoked_token_ids
                .push(request.token_id.clone());
            self.snapshot.revoked_token_ids.sort();
            self.snapshot
                .consumed_request_ids
                .push(request.request_id.clone());
            self.snapshot.consumed_request_ids.sort();
            self.snapshot.authority_revision = prior.next().unwrap_or(prior);
            removed.push(request.token_id.clone());
        }
        self.finish(
            ManifoldAdmissionOperation::RevokeToken,
            request.request_id.clone(),
            prior,
            None,
            removed,
            rejection,
        )
    }

    /// Explicitly expires tokens and advances revision only when state changes.
    pub fn expire_tokens(
        &mut self,
        sweep_id: DottedId,
        expected_revision: Revision,
        now_ms: u64,
    ) -> ManifoldAdmissionReceipt {
        let prior = self.snapshot.authority_revision;
        if self.snapshot.audit_events.len() >= MAX_ADMISSION_AUDIT_EVENTS {
            return terminal_rejection(
                ManifoldAdmissionOperation::ExpireTokens,
                sweep_id,
                prior,
                ManifoldAdmissionRejectionReason::AuthorityCapacityExhausted,
            );
        }
        if !self.snapshot.reviewed_sweep_ids.contains(&sweep_id)
            && self.snapshot.reviewed_sweep_ids.len() >= MAX_ADMISSION_RECORDS
        {
            return terminal_rejection(
                ManifoldAdmissionOperation::ExpireTokens,
                sweep_id,
                prior,
                ManifoldAdmissionRejectionReason::AuthorityCapacityExhausted,
            );
        }
        let mut removed = self
            .snapshot
            .active_tokens
            .iter()
            .filter(|token| token.expires_at_ms <= now_ms)
            .map(|token| token.token_id.clone())
            .collect::<Vec<_>>();
        removed.sort();
        let replayed = self.snapshot.reviewed_sweep_ids.contains(&sweep_id);
        let rejection = if replayed {
            Some(ManifoldAdmissionRejectionReason::ReplayedSweep)
        } else if expected_revision != prior {
            Some(ManifoldAdmissionRejectionReason::StaleAuthorityRevision)
        } else if removed.is_empty() {
            Some(ManifoldAdmissionRejectionReason::NoExpiredTokens)
        } else if self
            .snapshot
            .revoked_token_ids
            .len()
            .saturating_add(removed.len())
            > MAX_ADMISSION_RECORDS
        {
            Some(ManifoldAdmissionRejectionReason::AuthorityCapacityExhausted)
        } else if prior.next().is_none() {
            Some(ManifoldAdmissionRejectionReason::RevisionExhausted)
        } else {
            None
        };
        if !replayed {
            self.snapshot.reviewed_sweep_ids.push(sweep_id.clone());
            self.snapshot.reviewed_sweep_ids.sort();
        }
        if rejection.is_none() {
            self.snapshot
                .active_tokens
                .retain(|token| !removed.contains(&token.token_id));
            self.snapshot.revoked_token_ids.extend(removed.clone());
            self.snapshot.revoked_token_ids.sort();
            self.snapshot.revoked_token_ids.dedup();
            self.snapshot.authority_revision = prior.next().unwrap_or(prior);
        } else {
            removed.clear();
        }
        self.finish(
            ManifoldAdmissionOperation::ExpireTokens,
            sweep_id,
            prior,
            None,
            removed,
            rejection,
        )
    }

    fn finish(
        &mut self,
        operation: ManifoldAdmissionOperation,
        request_id: DottedId,
        prior: Revision,
        token: Option<ManifoldAdmissionToken>,
        removed_token_ids: Vec<DottedId>,
        rejection: Option<ManifoldAdmissionRejectionReason>,
    ) -> ManifoldAdmissionReceipt {
        let resulting = self.snapshot.authority_revision;
        let audit_sequence = self.snapshot.audit_events.len() + 1;
        self.snapshot
            .audit_events
            .push(ManifoldAdmissionAuditEvent {
                schema_id: schema_id(ADMISSION_AUDIT_SCHEMA),
                sequence: audit_sequence as u64,
                event_id: admission_audit_id(audit_sequence as u64),
                operation: operation.clone(),
                request_id: request_id.clone(),
                applied: rejection.is_none(),
                prior_authority_revision: prior,
                resulting_authority_revision: resulting,
                rejection_reason: rejection.clone(),
            });
        ManifoldAdmissionReceipt {
            schema_id: schema_id(ADMISSION_RECEIPT_SCHEMA),
            operation,
            request_id,
            applied: rejection.is_none(),
            prior_authority_revision: prior,
            resulting_authority_revision: resulting,
            token,
            removed_token_ids,
            rejection_reason: rejection,
        }
    }
}

fn migrate_legacy_admission_snapshot(
    legacy: LegacyAdmissionSnapshotV1,
    bindings: &[ManifoldAdmissionLegacyClientLockBinding],
) -> Result<
    (
        ManifoldAdmissionAuthority,
        ManifoldAdmissionMigrationReceipt,
    ),
    ManifoldAdmissionError,
> {
    validate_legacy_admission_snapshot(&legacy)?;
    if bindings.len() != legacy.grants.len()
        || bindings
            .iter()
            .map(|binding| &binding.grant_id)
            .collect::<BTreeSet<_>>()
            .len()
            != bindings.len()
        || bindings
            .iter()
            .map(|binding| &binding.client_lock_id)
            .collect::<BTreeSet<_>>()
            .len()
            != bindings.len()
        || bindings
            .iter()
            .any(|binding| !valid_sha256(&binding.client_lock_fingerprint))
    {
        return Err(ManifoldAdmissionError::InvalidSnapshot(
            "legacy_client_bindings",
        ));
    }
    let binding_by_grant = bindings
        .iter()
        .map(|binding| (binding.grant_id.clone(), binding))
        .collect::<BTreeMap<_, _>>();
    if legacy
        .grants
        .iter()
        .any(|grant| !binding_by_grant.contains_key(&grant.grant_id))
        || bindings.iter().any(|binding| {
            !legacy
                .grants
                .iter()
                .any(|grant| grant.grant_id == binding.grant_id)
        })
    {
        return Err(ManifoldAdmissionError::InvalidSnapshot(
            "legacy_client_binding_coverage",
        ));
    }

    let grants = legacy
        .grants
        .iter()
        .map(|grant| {
            let binding = binding_by_grant
                .get(&grant.grant_id)
                .expect("binding coverage checked");
            ManifoldAdmissionGrant {
                grant_id: grant.grant_id.clone(),
                client_lock_id: binding.client_lock_id.clone(),
                client_lock_fingerprint: binding.client_lock_fingerprint.clone(),
                identity: grant.identity.clone(),
                capabilities: grant.capabilities.clone(),
                expires_at_ms: grant.expires_at_ms,
                revoked: grant.revoked,
            }
        })
        .collect::<Vec<_>>();
    let active_tokens = legacy
        .active_tokens
        .iter()
        .map(|token| {
            let binding = binding_by_grant
                .get(&token.grant_id)
                .expect("legacy token grant validated");
            ManifoldAdmissionToken {
                schema_id: schema_id(ADMISSION_TOKEN_SCHEMA),
                token_id: token.token_id.clone(),
                identity: token.identity.clone(),
                grant_id: token.grant_id.clone(),
                client_lock_id: binding.client_lock_id.clone(),
                client_lock_fingerprint: binding.client_lock_fingerprint.clone(),
                capabilities: token.capabilities.clone(),
                issued_at_ms: token.issued_at_ms,
                expires_at_ms: token.expires_at_ms,
                issued_authority_revision: token.issued_authority_revision,
            }
        })
        .collect::<Vec<_>>();
    let mut reviewed_sweep_ids = legacy
        .audit_events
        .iter()
        .filter(|event| event.operation == ManifoldAdmissionOperation::ExpireTokens)
        .map(|event| event.request_id.clone())
        .collect::<Vec<_>>();
    reviewed_sweep_ids.sort();
    reviewed_sweep_ids.dedup();
    let audit_events = legacy
        .audit_events
        .iter()
        .enumerate()
        .map(|(index, event)| {
            let sequence = (index as u64) + 1;
            ManifoldAdmissionAuditEvent {
                schema_id: schema_id(ADMISSION_AUDIT_SCHEMA),
                sequence,
                event_id: admission_audit_id(sequence),
                operation: event.operation.clone(),
                request_id: event.request_id.clone(),
                applied: event.applied,
                prior_authority_revision: event.prior_authority_revision,
                resulting_authority_revision: event.resulting_authority_revision,
                rejection_reason: event.rejection_reason.clone(),
            }
        })
        .collect::<Vec<_>>();
    let source_schema_id = legacy.schema_id.clone();
    let mut rebound_grant_ids = grants
        .iter()
        .map(|grant| grant.grant_id.clone())
        .collect::<Vec<_>>();
    rebound_grant_ids.sort();
    let mut migrated_token_ids = active_tokens
        .iter()
        .map(|token| token.token_id.clone())
        .collect::<Vec<_>>();
    migrated_token_ids.sort();
    let snapshot = ManifoldAdmissionSnapshot {
        schema_id: schema_id(ADMISSION_SNAPSHOT_SCHEMA),
        authority_id: legacy.authority_id,
        authority_revision: legacy.authority_revision,
        grants,
        active_tokens,
        revoked_token_ids: legacy.revoked_token_ids,
        consumed_request_ids: legacy.consumed_request_ids,
        consumed_use_request_ids: legacy.consumed_use_request_ids,
        reviewed_sweep_ids,
        audit_events,
        max_token_ttl_ms: legacy.max_token_ttl_ms,
    };
    let authority = ManifoldAdmissionAuthority::from_snapshot(snapshot)?;
    let receipt = admission_migration_receipt(
        source_schema_id,
        authority.snapshot(),
        true,
        rebound_grant_ids,
        migrated_token_ids,
        legacy.audit_events.len(),
    );
    Ok((authority, receipt))
}

fn validate_legacy_admission_snapshot(
    snapshot: &LegacyAdmissionSnapshotV1,
) -> Result<(), ManifoldAdmissionError> {
    if snapshot.schema_id.as_str() != LEGACY_ADMISSION_SNAPSHOT_V1_SCHEMA
        || snapshot.max_token_ttl_ms == 0
        || snapshot.grants.len() > MAX_ADMISSION_RECORDS
        || snapshot.active_tokens.len() > MAX_ADMISSION_RECORDS
        || snapshot.revoked_token_ids.len() > MAX_ADMISSION_RECORDS
        || snapshot.consumed_request_ids.len() > MAX_ADMISSION_RECORDS
        || snapshot.consumed_use_request_ids.len() > MAX_ADMISSION_RECORDS
        || snapshot.audit_events.len() > MAX_ADMISSION_AUDIT_EVENTS
    {
        return Err(ManifoldAdmissionError::InvalidSnapshot(
            "legacy_schema_ttl_or_capacity",
        ));
    }
    unique(
        snapshot.grants.iter().map(|grant| &grant.grant_id),
        "legacy_grant",
    )?;
    unique(
        snapshot
            .grants
            .iter()
            .map(|grant| &grant.identity.client_id),
        "legacy_client",
    )?;
    unique(
        snapshot.active_tokens.iter().map(|token| &token.token_id),
        "legacy_active_token",
    )?;
    unique(snapshot.revoked_token_ids.iter(), "legacy_revoked_token")?;
    unique(snapshot.consumed_request_ids.iter(), "legacy_request")?;
    unique(
        snapshot.consumed_use_request_ids.iter(),
        "legacy_use_request",
    )?;
    unique(
        snapshot.audit_events.iter().map(|event| &event.event_id),
        "legacy_audit",
    )?;
    for grant in &snapshot.grants {
        validate_identity(&grant.identity)?;
        if grant.capabilities.is_empty()
            || sorted_ids(&grant.capabilities) != grant.capabilities
            || grant.capabilities.iter().collect::<BTreeSet<_>>().len() != grant.capabilities.len()
        {
            return Err(ManifoldAdmissionError::InvalidSnapshot(
                "legacy_grant_capabilities",
            ));
        }
    }
    for token in &snapshot.active_tokens {
        let grant = snapshot
            .grants
            .iter()
            .find(|grant| grant.grant_id == token.grant_id);
        if token.schema_id.as_str() != LEGACY_ADMISSION_TOKEN_V1_SCHEMA
            || snapshot.revoked_token_ids.contains(&token.token_id)
            || token.capabilities.is_empty()
            || sorted_ids(&token.capabilities) != token.capabilities
            || token.issued_at_ms >= token.expires_at_ms
            || token.issued_authority_revision > snapshot.authority_revision
            || grant.is_none()
            || grant.is_some_and(|grant| {
                grant.revoked
                    || grant.identity != token.identity
                    || token.expires_at_ms > grant.expires_at_ms
                    || token
                        .capabilities
                        .iter()
                        .any(|capability| !grant.capabilities.contains(capability))
            })
        {
            return Err(ManifoldAdmissionError::InvalidSnapshot("legacy_token"));
        }
    }
    let applied_request_sources = snapshot
        .audit_events
        .iter()
        .filter(|event| {
            event.applied
                && matches!(
                    event.operation,
                    ManifoldAdmissionOperation::IssueToken
                        | ManifoldAdmissionOperation::RevokeToken
                )
        })
        .map(|event| event.request_id.clone())
        .collect::<BTreeSet<_>>();
    let applied_use_sources = snapshot
        .audit_events
        .iter()
        .filter(|event| {
            event.applied && event.operation == ManifoldAdmissionOperation::AuthorizeUse
        })
        .map(|event| event.request_id.clone())
        .collect::<BTreeSet<_>>();
    if applied_request_sources
        != snapshot
            .consumed_request_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
        || applied_use_sources
            != snapshot
                .consumed_use_request_ids
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>()
    {
        return Err(ManifoldAdmissionError::InvalidSnapshot(
            "legacy_audit_replay_sets",
        ));
    }
    let mut rolling_revision = Revision::INITIAL;
    let mut seen_sweeps = BTreeSet::new();
    for (index, event) in snapshot.audit_events.iter().enumerate() {
        let sequence = (index as u64) + 1;
        let expected_id = DottedId::new(format!(
            "audit.admission.{sequence}.{}",
            event.request_id.as_str()
        ))
        .map_err(|_| ManifoldAdmissionError::InvalidSnapshot("legacy_audit_identity"))?;
        if event.schema_id.as_str() != LEGACY_ADMISSION_AUDIT_V1_SCHEMA
            || event.event_id != expected_id
            || event.prior_authority_revision != rolling_revision
            || (event.applied
                && event.prior_authority_revision.next()
                    != Some(event.resulting_authority_revision))
            || (!event.applied
                && event.prior_authority_revision != event.resulting_authority_revision)
            || event.resulting_authority_revision > snapshot.authority_revision
            || event.applied != event.rejection_reason.is_none()
            || (event.operation == ManifoldAdmissionOperation::ExpireTokens
                && !seen_sweeps.insert(event.request_id.clone()))
        {
            return Err(ManifoldAdmissionError::InvalidSnapshot(
                "legacy_audit_lineage",
            ));
        }
        rolling_revision = event.resulting_authority_revision;
    }
    if rolling_revision != snapshot.authority_revision {
        return Err(ManifoldAdmissionError::InvalidSnapshot(
            "legacy_audit_final_revision",
        ));
    }
    Ok(())
}

fn admission_migration_receipt(
    source_schema_id: SchemaId,
    snapshot: &ManifoldAdmissionSnapshot,
    migrated: bool,
    rebound_grant_ids: Vec<DottedId>,
    migrated_token_ids: Vec<DottedId>,
    migrated_audit_event_count: usize,
) -> ManifoldAdmissionMigrationReceipt {
    ManifoldAdmissionMigrationReceipt {
        schema_id: schema_id(ADMISSION_MIGRATION_RECEIPT_SCHEMA),
        source_schema_id,
        resulting_schema_id: snapshot.schema_id.clone(),
        migrated,
        authority_id: snapshot.authority_id.clone(),
        resulting_authority_revision: snapshot.authority_revision,
        rebound_grant_ids,
        migrated_token_ids,
        migrated_audit_event_count,
        reviewed_sweep_ids: snapshot.reviewed_sweep_ids.clone(),
    }
}

fn terminal_rejection(
    operation: ManifoldAdmissionOperation,
    request_id: DottedId,
    revision: Revision,
    reason: ManifoldAdmissionRejectionReason,
) -> ManifoldAdmissionReceipt {
    ManifoldAdmissionReceipt {
        schema_id: schema_id(ADMISSION_RECEIPT_SCHEMA),
        operation,
        request_id,
        applied: false,
        prior_authority_revision: revision,
        resulting_authority_revision: revision,
        token: None,
        removed_token_ids: Vec::new(),
        rejection_reason: Some(reason),
    }
}

fn admission_audit_id(sequence: u64) -> DottedId {
    DottedId::new(format!("audit.admission.{sequence:020}")).expect("derived admission audit id")
}

fn validate_common(
    actual_schema: &str,
    expected_schema: &str,
    expected_revision: Revision,
    current_revision: Revision,
    request_id: &DottedId,
    consumed: &[DottedId],
    issued_at_ms: u64,
    expires_at_ms: u64,
    now_ms: u64,
) -> Result<(), ManifoldAdmissionRejectionReason> {
    if actual_schema != expected_schema {
        return Err(ManifoldAdmissionRejectionReason::SchemaMismatch);
    }
    if expected_revision != current_revision {
        return Err(ManifoldAdmissionRejectionReason::StaleAuthorityRevision);
    }
    if consumed.contains(request_id) {
        return Err(ManifoldAdmissionRejectionReason::ReplayedRequest);
    }
    if issued_at_ms > now_ms || expires_at_ms <= now_ms {
        return Err(ManifoldAdmissionRejectionReason::ExpiredRequest);
    }
    Ok(())
}

fn validate_grant(
    grant: Option<&ManifoldAdmissionGrant>,
    request: &ManifoldAdmissionRequest,
    now_ms: u64,
) -> Result<(), ManifoldAdmissionRejectionReason> {
    let grant = grant.ok_or(ManifoldAdmissionRejectionReason::UntrustedClient)?;
    if grant.identity != request.identity {
        return Err(ManifoldAdmissionRejectionReason::IdentityMismatch);
    }
    if grant.revoked {
        return Err(ManifoldAdmissionRejectionReason::GrantRevoked);
    }
    if grant.expires_at_ms <= now_ms {
        return Err(ManifoldAdmissionRejectionReason::GrantExpired);
    }
    if request.requested_capabilities.is_empty()
        || request
            .requested_capabilities
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != request.requested_capabilities.len()
        || request
            .requested_capabilities
            .iter()
            .any(|capability| !grant.capabilities.contains(capability))
    {
        return Err(ManifoldAdmissionRejectionReason::CapabilityEscalation);
    }
    Ok(())
}

fn validate_token(
    token: Option<&ManifoldAdmissionToken>,
    request: &ManifoldAdmissionUseRequest,
    revoked: &[DottedId],
    now_ms: u64,
) -> Result<(), ManifoldAdmissionRejectionReason> {
    if revoked.contains(&request.token_id) {
        return Err(ManifoldAdmissionRejectionReason::TokenRevoked);
    }
    let token = token.ok_or(ManifoldAdmissionRejectionReason::UnknownToken)?;
    if token.identity != request.identity {
        return Err(ManifoldAdmissionRejectionReason::IdentityMismatch);
    }
    if token.expires_at_ms <= now_ms {
        return Err(ManifoldAdmissionRejectionReason::TokenExpired);
    }
    if !token.capabilities.contains(&request.capability_id) {
        return Err(ManifoldAdmissionRejectionReason::CapabilityDenied);
    }
    Ok(())
}

fn validate_snapshot(snapshot: &ManifoldAdmissionSnapshot) -> Result<(), ManifoldAdmissionError> {
    if snapshot.schema_id.as_str() != ADMISSION_SNAPSHOT_SCHEMA || snapshot.max_token_ttl_ms == 0 {
        return Err(ManifoldAdmissionError::InvalidSnapshot("schema_or_ttl"));
    }
    if snapshot.grants.len() > MAX_ADMISSION_RECORDS
        || snapshot.active_tokens.len() > MAX_ADMISSION_RECORDS
        || snapshot.revoked_token_ids.len() > MAX_ADMISSION_RECORDS
        || snapshot.consumed_request_ids.len() > MAX_ADMISSION_RECORDS
        || snapshot.consumed_use_request_ids.len() > MAX_ADMISSION_RECORDS
        || snapshot.reviewed_sweep_ids.len() > MAX_ADMISSION_RECORDS
        || snapshot.audit_events.len() > MAX_ADMISSION_AUDIT_EVENTS
    {
        return Err(ManifoldAdmissionError::InvalidSnapshot("capacity"));
    }
    unique(snapshot.grants.iter().map(|grant| &grant.grant_id), "grant")?;
    unique(
        snapshot
            .grants
            .iter()
            .map(|grant| &grant.identity.client_id),
        "client",
    )?;
    unique(
        snapshot.grants.iter().map(|grant| &grant.client_lock_id),
        "client_lock",
    )?;
    if snapshot
        .grants
        .iter()
        .map(|grant| &grant.client_lock_fingerprint)
        .collect::<BTreeSet<_>>()
        .len()
        != snapshot.grants.len()
    {
        return Err(ManifoldAdmissionError::InvalidSnapshot(
            "client_lock_fingerprint",
        ));
    }
    unique(
        snapshot.active_tokens.iter().map(|token| &token.token_id),
        "active_token",
    )?;
    unique(snapshot.revoked_token_ids.iter(), "revoked_token")?;
    unique(snapshot.consumed_request_ids.iter(), "request")?;
    unique(snapshot.consumed_use_request_ids.iter(), "use_request")?;
    unique(snapshot.reviewed_sweep_ids.iter(), "reviewed_sweep")?;
    unique(
        snapshot.audit_events.iter().map(|event| &event.event_id),
        "audit",
    )?;
    for grant in &snapshot.grants {
        validate_identity(&grant.identity)?;
        if !valid_sha256(&grant.client_lock_fingerprint)
            || grant.capabilities.is_empty()
            || sorted_ids(&grant.capabilities) != grant.capabilities
            || grant.capabilities.iter().collect::<BTreeSet<_>>().len() != grant.capabilities.len()
        {
            return Err(ManifoldAdmissionError::InvalidSnapshot(
                "grant_capabilities",
            ));
        }
    }
    for token in &snapshot.active_tokens {
        let grant = snapshot
            .grants
            .iter()
            .find(|grant| grant.grant_id == token.grant_id);
        if token.schema_id.as_str() != ADMISSION_TOKEN_SCHEMA
            || snapshot.revoked_token_ids.contains(&token.token_id)
            || token.capabilities.is_empty()
            || sorted_ids(&token.capabilities) != token.capabilities
            || token.issued_at_ms >= token.expires_at_ms
            || token.issued_authority_revision > snapshot.authority_revision
            || grant.is_none()
            || grant.is_some_and(|grant| {
                grant.revoked
                    || grant.identity != token.identity
                    || grant.client_lock_id != token.client_lock_id
                    || grant.client_lock_fingerprint != token.client_lock_fingerprint
                    || token.expires_at_ms > grant.expires_at_ms
                    || token
                        .capabilities
                        .iter()
                        .any(|capability| !grant.capabilities.contains(capability))
            })
        {
            return Err(ManifoldAdmissionError::InvalidSnapshot("token"));
        }
    }
    let applied_request_sources = snapshot
        .audit_events
        .iter()
        .filter(|event| {
            event.applied
                && matches!(
                    event.operation,
                    ManifoldAdmissionOperation::IssueToken
                        | ManifoldAdmissionOperation::RevokeToken
                )
        })
        .map(|event| event.request_id.clone())
        .collect::<BTreeSet<_>>();
    let applied_use_sources = snapshot
        .audit_events
        .iter()
        .filter(|event| {
            event.applied && event.operation == ManifoldAdmissionOperation::AuthorizeUse
        })
        .map(|event| event.request_id.clone())
        .collect::<BTreeSet<_>>();
    let sweep_sources = snapshot
        .audit_events
        .iter()
        .filter(|event| event.operation == ManifoldAdmissionOperation::ExpireTokens)
        .map(|event| event.request_id.clone())
        .collect::<BTreeSet<_>>();
    if applied_request_sources
        != snapshot
            .consumed_request_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
        || applied_use_sources
            != snapshot
                .consumed_use_request_ids
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>()
        || sweep_sources
            != snapshot
                .reviewed_sweep_ids
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>()
    {
        return Err(ManifoldAdmissionError::InvalidSnapshot("audit_replay_sets"));
    }
    let mut rolling_revision = Revision::INITIAL;
    let mut seen_sweeps = BTreeSet::new();
    let mut seen_applied_requests = BTreeSet::new();
    let mut seen_applied_uses = BTreeSet::new();
    for (index, event) in snapshot.audit_events.iter().enumerate() {
        let sequence = (index as u64) + 1;
        let operation_valid = match event.operation {
            ManifoldAdmissionOperation::IssueToken | ManifoldAdmissionOperation::RevokeToken
                if event.applied =>
            {
                seen_applied_requests.insert(event.request_id.clone())
            }
            ManifoldAdmissionOperation::AuthorizeUse if event.applied => {
                seen_applied_uses.insert(event.request_id.clone())
            }
            ManifoldAdmissionOperation::ExpireTokens
                if !seen_sweeps.insert(event.request_id.clone()) =>
            {
                !event.applied
                    && event.rejection_reason
                        == Some(ManifoldAdmissionRejectionReason::ReplayedSweep)
            }
            _ => true,
        };
        if event.schema_id.as_str() != ADMISSION_AUDIT_SCHEMA
            || event.sequence != sequence
            || event.event_id != admission_audit_id(sequence)
            || event.prior_authority_revision != rolling_revision
            || (event.applied
                && event.prior_authority_revision.next()
                    != Some(event.resulting_authority_revision))
            || (!event.applied
                && event.prior_authority_revision != event.resulting_authority_revision)
            || event.resulting_authority_revision > snapshot.authority_revision
            || event.applied != event.rejection_reason.is_none()
            || !operation_valid
        {
            return Err(ManifoldAdmissionError::InvalidSnapshot("audit_lineage"));
        }
        rolling_revision = event.resulting_authority_revision;
    }
    if rolling_revision != snapshot.authority_revision {
        return Err(ManifoldAdmissionError::InvalidSnapshot(
            "audit_final_revision",
        ));
    }
    Ok(())
}

fn validate_identity(identity: &ManifoldClientIdentity) -> Result<(), ManifoldAdmissionError> {
    if identity.platform_subject.trim().is_empty() || !valid_sha256(&identity.signing_fingerprint) {
        return Err(ManifoldAdmissionError::InvalidSnapshot("client_identity"));
    }
    Ok(())
}

fn valid_sha256(value: &str) -> bool {
    let fingerprint = value.as_bytes();
    fingerprint.len() == 71
        && value.starts_with("sha256:")
        && fingerprint[7..]
            .iter()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn unique<'a>(
    values: impl Iterator<Item = &'a DottedId>,
    reason: &'static str,
) -> Result<(), ManifoldAdmissionError> {
    let values = values.collect::<Vec<_>>();
    if values.iter().copied().collect::<BTreeSet<_>>().len() != values.len() {
        Err(ManifoldAdmissionError::InvalidSnapshot(reason))
    } else {
        Ok(())
    }
}

fn sorted_ids(values: &[DottedId]) -> Vec<DottedId> {
    let mut result = values.to_vec();
    result.sort();
    result
}

fn token_id(entropy: [u8; 32]) -> DottedId {
    let hex = entropy
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    DottedId::new(format!("token.session.{hex}")).expect("entropy token id")
}

fn schema_id(value: &str) -> SchemaId {
    SchemaId::new(value).expect("static schema id")
}

/// Admission state construction failure.
#[derive(Debug)]
pub enum ManifoldAdmissionError {
    /// Snapshot JSON decode failed.
    Deserialize(serde_json::Error),
    /// Snapshot JSON encode failed.
    Serialize(serde_json::Error),
    /// Snapshot invariant failed.
    InvalidSnapshot(&'static str),
    /// A v1 snapshot cannot acquire exact packaged client-lock authority
    /// without an explicit complete binding set.
    LegacyClientBindingsRequired,
}

impl fmt::Display for ManifoldAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Deserialize(error) => {
                write!(formatter, "admission snapshot decode failed: {error}")
            }
            Self::Serialize(error) => {
                write!(formatter, "admission snapshot encode failed: {error}")
            }
            Self::InvalidSnapshot(reason) => {
                write!(formatter, "admission snapshot invalid: {reason}")
            }
            Self::LegacyClientBindingsRequired => write!(
                formatter,
                "legacy admission snapshot requires explicit packaged client-lock bindings"
            ),
        }
    }
}

impl std::error::Error for ManifoldAdmissionError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: &str) -> DottedId {
        DottedId::new(value).expect("id")
    }

    fn identity() -> ManifoldClientIdentity {
        ManifoldClientIdentity {
            client_id: id("client.quest.authorized"),
            platform_subject: "io.github.mesmerprism.rustymanifold.admission.client".to_owned(),
            signing_fingerprint: format!("sha256:{}", "a1".repeat(32)),
        }
    }

    fn authority() -> ManifoldAdmissionAuthority {
        ManifoldAdmissionAuthority::from_snapshot(ManifoldAdmissionSnapshot {
            schema_id: schema_id(ADMISSION_SNAPSHOT_SCHEMA),
            authority_id: id("authority.admission.quest"),
            authority_revision: Revision::new(1).expect("revision"),
            grants: vec![ManifoldAdmissionGrant {
                grant_id: id("grant.quest.authorized"),
                client_lock_id: id("lock.client.quest.authorized"),
                client_lock_fingerprint: format!("sha256:{}", "c1".repeat(32)),
                identity: identity(),
                capabilities: vec![id("capability.command.session.list")],
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
        })
        .expect("authority")
    }

    fn admission(expected: u64) -> ManifoldAdmissionRequest {
        ManifoldAdmissionRequest {
            schema_id: schema_id(ADMISSION_REQUEST_SCHEMA),
            request_id: id("request.admission.issue"),
            expected_authority_revision: Revision::new(expected).expect("revision"),
            identity: identity(),
            requested_capabilities: vec![id("capability.command.session.list")],
            issued_at_ms: 1_000,
            expires_at_ms: 5_000,
            requested_token_ttl_ms: 20_000,
        }
    }

    #[test]
    fn issue_use_replay_revoke_and_post_revoke_reject() {
        let mut authority = authority();
        let issued = authority.issue_token(&admission(1), [7; 32], 2_000);
        assert!(issued.applied);
        let token = issued.token.expect("token");
        assert_eq!(token.token_id.as_str().len(), "token.session.".len() + 64);
        let use_request = ManifoldAdmissionUseRequest {
            schema_id: schema_id(ADMISSION_USE_REQUEST_SCHEMA),
            request_id: id("request.admission.use"),
            expected_authority_revision: Revision::new(2).expect("revision"),
            token_id: token.token_id.clone(),
            identity: identity(),
            capability_id: id("capability.command.session.list"),
            issued_at_ms: 2_000,
            expires_at_ms: 6_000,
        };
        assert!(authority.authorize_use(&use_request, 3_000).applied);
        let mut replay = use_request.clone();
        replay.expected_authority_revision = Revision::new(3).expect("revision");
        assert_eq!(
            authority.authorize_use(&replay, 3_000).rejection_reason,
            Some(ManifoldAdmissionRejectionReason::ReplayedRequest)
        );
        let revoke = ManifoldAdmissionRevocationRequest {
            schema_id: schema_id(ADMISSION_REVOCATION_REQUEST_SCHEMA),
            request_id: id("request.admission.revoke"),
            expected_authority_revision: Revision::new(3).expect("revision"),
            token_id: token.token_id.clone(),
            identity: identity(),
            reason: id("reason.client.completed"),
        };
        assert!(authority.revoke_token(&revoke).applied);
        let mut after = use_request;
        after.request_id = id("request.admission.after-revoke");
        after.expected_authority_revision = Revision::new(4).expect("revision");
        assert_eq!(
            authority.authorize_use(&after, 4_000).rejection_reason,
            Some(ManifoldAdmissionRejectionReason::TokenRevoked)
        );
        assert_eq!(authority.snapshot().authority_revision.get(), 4);
    }

    #[test]
    fn identity_and_capability_escalation_reject_without_revision_change() {
        let mut authority = authority();
        let mut wrong = admission(1);
        wrong.identity.signing_fingerprint = format!("sha256:{}", "b2".repeat(32));
        assert_eq!(
            authority
                .issue_token(&wrong, [1; 32], 2_000)
                .rejection_reason,
            Some(ManifoldAdmissionRejectionReason::IdentityMismatch)
        );
        let mut escalation = admission(1);
        escalation.request_id = id("request.admission.escalation");
        escalation
            .requested_capabilities
            .push(id("capability.command.admin"));
        assert_eq!(
            authority
                .issue_token(&escalation, [2; 32], 2_000)
                .rejection_reason,
            Some(ManifoldAdmissionRejectionReason::CapabilityEscalation)
        );
        assert_eq!(authority.snapshot().authority_revision.get(), 1);
    }

    #[test]
    fn distinct_clients_cannot_share_packaged_client_lock_identity_or_digest() {
        let authority = authority();
        let mut duplicate = authority.snapshot().grants[0].clone();
        duplicate.grant_id = id("grant.quest.second");
        duplicate.identity.client_id = id("client.quest.second");
        duplicate.identity.platform_subject = "example.client.quest.second".to_owned();
        let mut damaged = authority.snapshot().clone();
        damaged.grants.push(duplicate.clone());
        assert!(ManifoldAdmissionAuthority::from_snapshot(damaged).is_err());

        duplicate.client_lock_id = id("lock.client.quest.second");
        let mut damaged = authority.snapshot().clone();
        damaged.grants.push(duplicate);
        assert!(ManifoldAdmissionAuthority::from_snapshot(damaged).is_err());
    }

    #[test]
    fn token_collision_and_expiry_sweep_fail_closed() {
        let mut authority = authority();
        let first = authority.issue_token(&admission(1), [3; 32], 2_000);
        assert!(first.applied);
        let mut second = admission(2);
        second.request_id = id("request.admission.issue.second");
        assert_eq!(
            authority
                .issue_token(&second, [3; 32], 3_000)
                .rejection_reason,
            Some(ManifoldAdmissionRejectionReason::TokenCollision)
        );
        let sweep = authority.expire_tokens(
            id("sweep.admission.expired"),
            Revision::new(2).expect("revision"),
            23_000,
        );
        assert!(sweep.applied);
        assert_eq!(sweep.removed_token_ids.len(), 1);
        assert_eq!(authority.snapshot().authority_revision.get(), 3);
    }

    #[test]
    fn restart_preserves_tokens_replay_revocation_and_audit() {
        let mut authority = authority();
        authority.issue_token(&admission(1), [4; 32], 2_000);
        let json = authority.snapshot_json().expect("json");
        let restarted = ManifoldAdmissionAuthority::restart_from_json(&json).expect("restart");
        assert_eq!(restarted.snapshot(), authority.snapshot());
        assert_eq!(restarted.snapshot().audit_events.len(), 1);

        let mut damaged = authority.snapshot().clone();
        damaged.active_tokens[0].client_lock_fingerprint = format!("sha256:{}", "d2".repeat(32));
        assert!(matches!(
            ManifoldAdmissionAuthority::from_snapshot(damaged),
            Err(ManifoldAdmissionError::InvalidSnapshot("token"))
        ));

        let mut damaged = authority.snapshot().clone();
        damaged.grants[0].client_lock_fingerprint = "sha256:invalid".to_owned();
        assert!(matches!(
            ManifoldAdmissionAuthority::from_snapshot(damaged),
            Err(ManifoldAdmissionError::InvalidSnapshot(
                "grant_capabilities"
            ))
        ));
    }

    #[test]
    fn legacy_v1_restart_requires_exact_binding_and_emits_migration_receipt() {
        let json = include_str!("../../../fixtures/admission/legacy-v1-active-token-snapshot.json");
        assert!(matches!(
            ManifoldAdmissionAuthority::restart_from_json(json),
            Err(ManifoldAdmissionError::LegacyClientBindingsRequired)
        ));
        let binding = ManifoldAdmissionLegacyClientLockBinding {
            grant_id: id("grant.quest.authorized"),
            client_lock_id: id("lock.client.quest.authorized"),
            client_lock_fingerprint: format!("sha256:{}", "c1".repeat(32)),
        };
        let (authority, receipt) =
            ManifoldAdmissionAuthority::restart_from_json_with_migration(json, &[binding.clone()])
                .expect("explicit legacy migration");
        assert!(receipt.migrated);
        assert_eq!(
            receipt.source_schema_id.as_str(),
            LEGACY_ADMISSION_SNAPSHOT_V1_SCHEMA
        );
        assert_eq!(
            receipt.resulting_schema_id.as_str(),
            ADMISSION_SNAPSHOT_SCHEMA
        );
        assert_eq!(receipt.rebound_grant_ids, vec![binding.grant_id.clone()]);
        assert_eq!(receipt.migrated_token_ids.len(), 1);
        assert_eq!(receipt.migrated_audit_event_count, 1);
        let token = &authority.snapshot().active_tokens[0];
        assert_eq!(token.schema_id.as_str(), ADMISSION_TOKEN_SCHEMA);
        assert_eq!(token.client_lock_id, binding.client_lock_id);
        assert_eq!(
            token.client_lock_fingerprint,
            binding.client_lock_fingerprint
        );
        assert_eq!(authority.snapshot().audit_events[0].sequence, 1);
        assert_eq!(
            authority.snapshot().audit_events[0].event_id,
            id("audit.admission.00000000000000000001")
        );
        let restarted = ManifoldAdmissionAuthority::restart_from_json(
            &authority.snapshot_json().expect("migrated v2 snapshot"),
        )
        .expect("v2 restart");
        assert_eq!(restarted, authority);

        assert!(ManifoldAdmissionAuthority::restart_from_json_with_migration(json, &[]).is_err());
        let mut malformed = binding;
        malformed.client_lock_fingerprint = "sha256:not-exact".to_owned();
        assert!(
            ManifoldAdmissionAuthority::restart_from_json_with_migration(json, &[malformed])
                .is_err()
        );
    }

    #[test]
    fn committed_lifecycle_receipts_preserve_revision_and_rejections() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("fixtures/admission");
        let receipt = |name: &str| -> ManifoldAdmissionReceipt {
            serde_json::from_str(
                &std::fs::read_to_string(root.join(name)).expect("fixture must load"),
            )
            .expect("receipt fixture")
        };
        let issued = receipt("issue-receipt.json");
        let used = receipt("use-receipt.json");
        let replay = receipt("replay-use-receipt.json");
        let revoked = receipt("revoke-receipt.json");
        let post_revoke = receipt("after-revoke-use-receipt.json");
        assert!(issued.applied && used.applied && revoked.applied);
        assert_eq!(issued.resulting_authority_revision.get(), 2);
        assert_eq!(used.resulting_authority_revision.get(), 3);
        assert_eq!(revoked.resulting_authority_revision.get(), 4);
        assert_eq!(
            replay.rejection_reason,
            Some(ManifoldAdmissionRejectionReason::ReplayedRequest)
        );
        assert_eq!(
            replay.prior_authority_revision,
            replay.resulting_authority_revision
        );
        assert_eq!(
            post_revoke.rejection_reason,
            Some(ManifoldAdmissionRejectionReason::TokenRevoked)
        );
        assert_eq!(
            post_revoke.prior_authority_revision,
            post_revoke.resulting_authority_revision
        );
        let final_snapshot: ManifoldAdmissionSnapshot = serde_json::from_str(
            &std::fs::read_to_string(root.join("final-snapshot.json"))
                .expect("final snapshot fixture"),
        )
        .expect("final snapshot");
        ManifoldAdmissionAuthority::from_snapshot(final_snapshot)
            .expect("final snapshot must restart with unique audit lineage");
    }
}
