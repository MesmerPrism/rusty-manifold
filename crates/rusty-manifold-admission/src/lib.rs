//! Revisioned cross-app grants and short-lived opaque token authority.

use rusty_manifold_model::{DottedId, Revision, SchemaId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

/// Admission snapshot schema.
pub const ADMISSION_SNAPSHOT_SCHEMA: &str = "rusty.manifold.admission.snapshot.v1";
/// Admission request schema.
pub const ADMISSION_REQUEST_SCHEMA: &str = "rusty.manifold.admission.request.v1";
/// Token use request schema.
pub const ADMISSION_USE_REQUEST_SCHEMA: &str = "rusty.manifold.admission.use_request.v1";
/// Token revocation request schema.
pub const ADMISSION_REVOCATION_REQUEST_SCHEMA: &str =
    "rusty.manifold.admission.revocation_request.v1";
/// Admission token schema.
pub const ADMISSION_TOKEN_SCHEMA: &str = "rusty.manifold.admission.token.v1";
/// Unified admission receipt schema.
pub const ADMISSION_RECEIPT_SCHEMA: &str = "rusty.manifold.admission.receipt.v1";
/// Admission audit event schema.
pub const ADMISSION_AUDIT_SCHEMA: &str = "rusty.manifold.admission.audit_event.v1";

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
    /// Append-only audit events.
    pub audit_events: Vec<ManifoldAdmissionAuditEvent>,
    /// Maximum token lifetime.
    pub max_token_ttl_ms: u64,
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
        let snapshot = serde_json::from_str(json).map_err(ManifoldAdmissionError::Deserialize)?;
        Self::from_snapshot(snapshot)
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
                capabilities: sorted_ids(&request.requested_capabilities),
                issued_at_ms: now_ms,
                expires_at_ms,
                issued_authority_revision: prior.next().expect("revision"),
            };
            self.snapshot.active_tokens.push(issued.clone());
            self.snapshot
                .active_tokens
                .sort_by(|left, right| left.token_id.cmp(&right.token_id));
            self.snapshot
                .consumed_request_ids
                .push(request.request_id.clone());
            self.snapshot.consumed_request_ids.sort();
            self.snapshot.authority_revision = prior.next().expect("revision");
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
        .or_else(|| validate_token(token, request, &self.snapshot.revoked_token_ids, now_ms).err());
        if rejection.is_none() {
            self.snapshot
                .consumed_use_request_ids
                .push(request.request_id.clone());
            self.snapshot.consumed_use_request_ids.sort();
            self.snapshot.authority_revision = prior.next().expect("revision");
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
            self.snapshot.authority_revision = prior.next().expect("revision");
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
        let mut removed = self
            .snapshot
            .active_tokens
            .iter()
            .filter(|token| token.expires_at_ms <= now_ms)
            .map(|token| token.token_id.clone())
            .collect::<Vec<_>>();
        removed.sort();
        let rejection = if expected_revision != prior {
            Some(ManifoldAdmissionRejectionReason::StaleAuthorityRevision)
        } else if removed.is_empty() {
            Some(ManifoldAdmissionRejectionReason::NoExpiredTokens)
        } else {
            None
        };
        if rejection.is_none() {
            self.snapshot
                .active_tokens
                .retain(|token| !removed.contains(&token.token_id));
            self.snapshot.revoked_token_ids.extend(removed.clone());
            self.snapshot.revoked_token_ids.sort();
            self.snapshot.revoked_token_ids.dedup();
            self.snapshot.authority_revision = prior.next().expect("revision");
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
                event_id: DottedId::new(format!(
                    "audit.admission.{}.{}",
                    audit_sequence,
                    request_id.as_str()
                ))
                .expect("derived audit id"),
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
    unique(snapshot.grants.iter().map(|grant| &grant.grant_id), "grant")?;
    unique(
        snapshot
            .grants
            .iter()
            .map(|grant| &grant.identity.client_id),
        "client",
    )?;
    unique(
        snapshot.active_tokens.iter().map(|token| &token.token_id),
        "active_token",
    )?;
    unique(snapshot.revoked_token_ids.iter(), "revoked_token")?;
    unique(snapshot.consumed_request_ids.iter(), "request")?;
    unique(snapshot.consumed_use_request_ids.iter(), "use_request")?;
    unique(
        snapshot.audit_events.iter().map(|event| &event.event_id),
        "audit",
    )?;
    for grant in &snapshot.grants {
        validate_identity(&grant.identity)?;
        if grant.capabilities.is_empty()
            || sorted_ids(&grant.capabilities) != grant.capabilities
            || grant.capabilities.iter().collect::<BTreeSet<_>>().len() != grant.capabilities.len()
        {
            return Err(ManifoldAdmissionError::InvalidSnapshot(
                "grant_capabilities",
            ));
        }
    }
    for token in &snapshot.active_tokens {
        if token.schema_id.as_str() != ADMISSION_TOKEN_SCHEMA
            || snapshot.revoked_token_ids.contains(&token.token_id)
            || token.capabilities.is_empty()
            || sorted_ids(&token.capabilities) != token.capabilities
        {
            return Err(ManifoldAdmissionError::InvalidSnapshot("token"));
        }
    }
    for event in &snapshot.audit_events {
        if event.schema_id.as_str() != ADMISSION_AUDIT_SCHEMA
            || (event.applied
                && event.prior_authority_revision.next()
                    != Some(event.resulting_authority_revision))
            || (!event.applied
                && event.prior_authority_revision != event.resulting_authority_revision)
            || event.resulting_authority_revision > snapshot.authority_revision
        {
            return Err(ManifoldAdmissionError::InvalidSnapshot("audit_lineage"));
        }
    }
    Ok(())
}

fn validate_identity(identity: &ManifoldClientIdentity) -> Result<(), ManifoldAdmissionError> {
    let fingerprint = identity.signing_fingerprint.as_bytes();
    if identity.platform_subject.trim().is_empty()
        || fingerprint.len() != 71
        || !identity.signing_fingerprint.starts_with("sha256:")
        || !fingerprint[7..]
            .iter()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ManifoldAdmissionError::InvalidSnapshot("client_identity"));
    }
    Ok(())
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
                identity: identity(),
                capabilities: vec![id("capability.command.session.list")],
                expires_at_ms: 100_000,
                revoked: false,
            }],
            active_tokens: Vec::new(),
            revoked_token_ids: Vec::new(),
            consumed_request_ids: Vec::new(),
            consumed_use_request_ids: Vec::new(),
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
