//! Canonical packaged binding for an accepted source-neutral media session.
//!
//! This crate owns no media bytes, sockets, codecs, capture APIs, or platform
//! lifecycle. It proves that a product selected one validated, canonical
//! [`ManifoldMediaSessionDescriptor`] and retained its exact canonical digest.

use std::collections::BTreeSet;

use rusty_manifold_admission::ManifoldClientIdentity;
use rusty_manifold_model::{DottedId, ManifoldMediaSessionDescriptor, Revision, SchemaId};
use rusty_manifold_runtime_host::{
    ManifoldRuntimeApplicationReceipt, ManifoldRuntimeCommandRequest,
    ManifoldRuntimeDispatchOutcome, ManifoldRuntimeDispatchReceipt,
    ManifoldRuntimeTypedParamsDigest, HOST_APPLICATION_RECEIPT_SCHEMA, HOST_COMMAND_REQUEST_SCHEMA,
    HOST_DISPATCH_RECEIPT_SCHEMA, HOST_TYPED_PARAMS_DIGEST_SCHEMA,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Canonical packaged media-session binding schema.
pub const MANIFOLD_MEDIA_SESSION_BINDING_SCHEMA: &str =
    "rusty.manifold.media.session_product_binding.v1";
/// Revisioned media-session acceptance-state schema.
pub const MANIFOLD_MEDIA_SESSION_ACCEPTANCE_STATE_SCHEMA: &str =
    "rusty.manifold.media.session_acceptance_state.v1";
/// Media-session acceptance request schema.
pub const MANIFOLD_MEDIA_SESSION_ACCEPTANCE_REQUEST_SCHEMA: &str =
    "rusty.manifold.media.session_acceptance_request.v1";
/// Current accepted media-session record schema.
pub const MANIFOLD_ACCEPTED_MEDIA_SESSION_SCHEMA: &str = "rusty.manifold.media.accepted_session.v1";
/// Media-session acceptance receipt schema.
pub const MANIFOLD_MEDIA_SESSION_ACCEPTANCE_RECEIPT_SCHEMA: &str =
    "rusty.manifold.media.session_acceptance_receipt.v1";
/// Media-session termination request schema.
pub const MANIFOLD_MEDIA_SESSION_TERMINATION_REQUEST_SCHEMA: &str =
    "rusty.manifold.media.session_termination_request.v1";
/// Media-session lifecycle mutation receipt schema.
pub const MANIFOLD_MEDIA_SESSION_MUTATION_RECEIPT_SCHEMA: &str =
    "rusty.manifold.media.session_mutation_receipt.v1";
/// Current media-session validation receipt schema.
pub const MANIFOLD_MEDIA_SESSION_CURRENT_RECEIPT_SCHEMA: &str =
    "rusty.manifold.media.session_current_receipt.v1";
/// Exact Runtime Host command that may accept a media session.
pub const MANIFOLD_MEDIA_SESSION_ACCEPT_COMMAND: &str = "rusty.manifold.media.session.accept";
/// Exact Runtime Host command that may stop a media session.
pub const MANIFOLD_MEDIA_SESSION_STOP_COMMAND: &str = "rusty.manifold.media.session.stop";
/// Exact Runtime Host command that may revoke a media session.
pub const MANIFOLD_MEDIA_SESSION_REVOKE_COMMAND: &str = "rusty.manifold.media.session.revoke";
/// Exact typed-parameter identity for media-session acceptance.
pub const MANIFOLD_MEDIA_SESSION_ACCEPT_PARAMS_TYPE: &str =
    "rusty.manifold.media.session_acceptance_params.v1";
/// Exact typed-parameter identity for media-session termination.
pub const MANIFOLD_MEDIA_SESSION_TERMINATION_PARAMS_TYPE: &str =
    "rusty.manifold.media.session_termination_params.v1";

const MAX_MEDIA_SESSION_TTL_MS: u64 = 600_000;

/// One accepted descriptor plus its canonical SHA-256 binding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldMediaSessionProductBinding {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: String,
    /// Accepted source-neutral descriptor.
    pub descriptor: ManifoldMediaSessionDescriptor,
    /// `sha256:<lowercase hex>` of canonical typed descriptor JSON.
    pub descriptor_canonical_sha256: String,
}

/// Closed product-binding rejection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManifoldMediaSessionBindingError {
    /// Binding schema differs from v1.
    SchemaMismatch,
    /// Descriptor validation failed.
    DescriptorInvalid,
    /// Reference vectors are not strict canonical sorted sets.
    DescriptorNotCanonical,
    /// Canonical descriptor serialization failed.
    EncodeFailed,
    /// Declared digest differs from the canonical typed descriptor.
    DigestMismatch,
}

impl std::fmt::Display for ManifoldMediaSessionBindingError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::SchemaMismatch => "media-session product binding schema mismatch",
            Self::DescriptorInvalid => "media-session descriptor invalid",
            Self::DescriptorNotCanonical => {
                "media-session descriptor references are not canonical sorted sets"
            }
            Self::EncodeFailed => "media-session descriptor canonical encoding failed",
            Self::DigestMismatch => "media-session descriptor canonical digest mismatch",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ManifoldMediaSessionBindingError {}

impl ManifoldMediaSessionProductBinding {
    /// Validates schema, descriptor, canonical ordering, and exact digest.
    ///
    /// # Errors
    ///
    /// Returns the first closed binding rejection without mutating state.
    pub fn validate(&self) -> Result<(), ManifoldMediaSessionBindingError> {
        if self.schema_id != MANIFOLD_MEDIA_SESSION_BINDING_SCHEMA {
            return Err(ManifoldMediaSessionBindingError::SchemaMismatch);
        }
        self.descriptor
            .validate()
            .map_err(|_| ManifoldMediaSessionBindingError::DescriptorInvalid)?;
        for values in [
            &self.descriptor.source_ids,
            &self.descriptor.processor_ids,
            &self.descriptor.route_ids,
            &self.descriptor.sink_ids,
            &self.descriptor.stream_ids,
        ] {
            if !values.windows(2).all(|pair| pair[0] < pair[1]) {
                return Err(ManifoldMediaSessionBindingError::DescriptorNotCanonical);
            }
        }
        let expected = canonical_media_session_sha256(&self.descriptor)?;
        if self.descriptor_canonical_sha256 != expected {
            return Err(ManifoldMediaSessionBindingError::DigestMismatch);
        }
        Ok(())
    }
}

/// Request for Manifold to accept one exact product-bound media descriptor.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldMediaSessionAcceptanceRequest {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Replay-protected media-authority request identity.
    pub request_id: DottedId,
    /// Exact acceptance-state revision consumed by this request.
    pub expected_authority_revision: Revision,
    /// Runtime Host request that must have applied this exact acceptance.
    pub runtime_command_request_id: DottedId,
    /// Host-owned provider epoch expected by the caller.
    pub expected_provider_epoch_id: DottedId,
    /// Exact admitted product identity.
    pub product_id: DottedId,
    /// Exact selected feature-lock identity.
    pub feature_lock_id: DottedId,
    /// Exact `sha256:<lowerhex>` feature-lock fingerprint.
    pub feature_lock_fingerprint: String,
    /// Exact admitted capability identity.
    pub capability_id: DottedId,
    /// Exact admission grant identity.
    pub admission_grant_id: DottedId,
    /// Session authority expiry.
    pub expires_at_ms: u64,
    /// Exact canonical product descriptor proposed for acceptance.
    pub product_binding: ManifoldMediaSessionProductBinding,
}

/// Lifecycle state of one retained media-session decision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldMediaSessionLifecycleStatus {
    /// Current and lease-eligible until expiry.
    Current,
    /// Explicitly stopped by an accepted Runtime Host command.
    Stopped,
    /// Explicitly revoked by an accepted Runtime Host command.
    Revoked,
    /// Expired by the media authority clock.
    Expired,
    /// Replaced by a strictly newer revision of the same session.
    Superseded,
}

/// Current or historical Manifold media-session decision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldAcceptedMediaSession {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Stable decision identity derived from the accepted request.
    pub decision_id: DottedId,
    /// Media-authority request that produced this decision.
    pub request_id: DottedId,
    /// Exact generic media-session identity.
    pub session_id: DottedId,
    /// Subject-scoped descriptor/session revision.
    pub session_authority_revision: Revision,
    /// Exact canonical product descriptor digest.
    pub product_descriptor_canonical_sha256: String,
    /// Host-owned provider-process epoch.
    pub provider_epoch_id: DottedId,
    /// Exact platform runtime specification.
    pub platform_runtime_spec_id: DottedId,
    /// Exact admitted product identity.
    pub product_id: DottedId,
    /// Exact selected feature-lock identity.
    pub feature_lock_id: DottedId,
    /// Exact feature-lock fingerprint.
    pub feature_lock_fingerprint: String,
    /// Exact admitted capability identity.
    pub capability_id: DottedId,
    /// Exact admission grant identity.
    pub admission_grant_id: DottedId,
    /// Runtime Host that applied the accepting command.
    pub runtime_authority_host_id: DottedId,
    /// Accepted Runtime Host command request.
    pub runtime_command_request_id: DottedId,
    /// Exact accepted command.
    pub runtime_command_id: DottedId,
    /// Exact accepted client/requester.
    pub runtime_client_id: DottedId,
    /// Exact accepted lease.
    pub runtime_lease_id: DottedId,
    /// Exact accepted typed-parameter digest.
    pub runtime_params_digest: ManifoldRuntimeTypedParamsDigest,
    /// Runtime dispatch identity.
    pub runtime_dispatch_id: DottedId,
    /// Runtime application receipt identity.
    pub runtime_application_receipt_id: DottedId,
    /// Runtime authority revision resulting from the accepted command.
    pub runtime_resulting_authority_revision: Revision,
    /// Current lifecycle status.
    pub lifecycle_status: ManifoldMediaSessionLifecycleStatus,
    /// Acceptance time.
    pub accepted_at_ms: u64,
    /// Authority expiry.
    pub expires_at_ms: u64,
    /// Stop/revoke/expiry/supersession time when no longer current.
    pub ended_at_ms: Option<u64>,
    /// Request or sweep that ended the decision.
    pub ended_by_id: Option<DottedId>,
    /// Complete canonical product binding retained for route checks.
    pub product_binding: ManifoldMediaSessionProductBinding,
}

/// Revisioned media-session acceptance authority with subject-scoped history.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldMediaSessionAcceptanceState {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Global mutation-CAS revision; not a subject freshness token.
    pub authority_revision: Revision,
    /// Current and historical decisions sorted by decision id.
    pub sessions: Vec<ManifoldAcceptedMediaSession>,
    /// Applied media request/sweep identities retained against replay.
    pub applied_request_ids: Vec<DottedId>,
}

/// Immutable host-owned closure from one admitted client/lease to its exact
/// product, feature lock, capability, and admission grant.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldMediaSessionClientGrant {
    /// Exact outer broker adapter selected by the product lock.
    pub broker_adapter_id: DottedId,
    /// Exact outer broker Runtime Host that consumed admission.
    pub broker_runtime_host_id: DottedId,
    /// Exact outer broker product lock.
    pub broker_product_lock_id: DottedId,
    /// Exact outer broker product-lock fingerprint.
    pub broker_product_lock_fingerprint: String,
    /// SHA-256 of the exact packaged outer broker product-lock bytes.
    pub broker_product_lock_sha256: String,
    /// Exact outer admitted capability that may mint the inner lease.
    pub broker_capability_id: DottedId,
    /// Exact outer broker command that must consume the bounded use.
    pub broker_command_id: DottedId,
    /// Exact outer Runtime Host lease required by that broker command.
    pub broker_runtime_lease_id: DottedId,
    /// Complete platform-verified outer client identity.
    pub broker_client_identity: ManifoldClientIdentity,
    /// Exact packaged broker client-lock identity.
    pub broker_client_lock_id: DottedId,
    /// SHA-256 of the exact packaged broker client-lock bytes.
    pub broker_client_lock_fingerprint: String,
    /// Exact Runtime Host that owns media lifecycle commands.
    pub runtime_host_id: DottedId,
    /// Exact Runtime Host requester/client.
    pub client_id: DottedId,
    /// Exact Runtime Host lease held by the client.
    pub lease_id: DottedId,
    /// Exact admitted product.
    pub product_id: DottedId,
    /// Exact selected feature lock.
    pub feature_lock_id: DottedId,
    /// Exact feature-lock fingerprint.
    pub feature_lock_fingerprint: String,
    /// Exact admitted capability.
    pub capability_id: DottedId,
    /// Exact admission grant.
    pub admission_grant_id: DottedId,
    /// Exact media-session subject allowed by this grant.
    pub allowed_session_id: DottedId,
    /// Exact platform runtime specification allowed by this grant.
    pub allowed_platform_runtime_spec_id: DottedId,
    /// Canonical descriptor allowlist (and therefore exact resource graphs)
    /// admitted by this grant. Values must be sorted and unique.
    pub allowed_descriptor_canonical_sha256: Vec<String>,
    /// Exact sorted resource identities allowed by this grant. This closes the
    /// source/processor/route/sink/stream namespace even if a caller damages a
    /// descriptor and recomputes its digest.
    pub allowed_resource_ids: Vec<DottedId>,
}

impl ManifoldMediaSessionAcceptanceState {
    /// Creates an empty revision-one media-session authority.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            schema_id: schema(MANIFOLD_MEDIA_SESSION_ACCEPTANCE_STATE_SCHEMA),
            authority_revision: Revision::INITIAL,
            sessions: Vec::new(),
            applied_request_ids: Vec::new(),
        }
    }
}

/// Runtime Host proof constructed by the composing authority after application.
#[derive(Clone, Copy, Debug)]
pub struct ManifoldMediaSessionRuntimeCommandContext<'a> {
    /// Runtime Host identity that owns the accepted command state.
    pub runtime_host_id: &'a DottedId,
    /// Host-owned live provider epoch.
    pub live_provider_epoch_id: &'a DottedId,
    /// Immutable client/product/feature-lock/capability/grant closures.
    pub client_grants: &'a [ManifoldMediaSessionClientGrant],
    /// Separate immutable operator identities allowed to revoke any session.
    pub trusted_revoker_ids: &'a [DottedId],
    /// Exact command request reviewed by Runtime Host.
    pub command_request: &'a ManifoldRuntimeCommandRequest,
    /// Exact current-state dispatch review.
    pub dispatch: &'a ManifoldRuntimeDispatchReceipt,
    /// Exact application receipt emitted by Runtime Host.
    pub application: &'a ManifoldRuntimeApplicationReceipt,
}

/// Closed media-session rejection family.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldMediaSessionAcceptanceRejectionReason {
    /// Request or state schema differs from the accepted contract.
    SchemaMismatch,
    /// Supplied current state violates a durable invariant.
    InvalidAuthorityState,
    /// Request expected an old or future global mutation revision.
    StaleAuthorityRevision,
    /// Request identity was already applied.
    ReplayedRequest,
    /// Product binding is malformed, non-canonical, or digest-damaged.
    InvalidProductBinding,
    /// Existing subject decision has the same or newer session revision.
    StaleSessionRevision,
    /// Runtime Host did not apply the exact command/client/lease/params digest.
    RuntimeCommandNotAccepted,
    /// Runtime requester is outside immutable trusted media proposers.
    UntrustedProposer,
    /// An existing session subject belongs to another product/feature-lock/client lineage.
    SubjectLineageMismatch,
    /// Caller/provider record differs from the host-owned live epoch.
    ProviderEpochMismatch,
    /// Session expiry is empty, stale, or beyond the maximum authority window.
    InvalidExpiry,
    /// Named session decision is absent or no longer current.
    SessionNotCurrent,
    /// Expiry sweep found no current expired sessions.
    NoExpiredSessions,
    /// Authority revision cannot advance.
    RevisionExhausted,
}

/// Acceptance decision and exact retained product/runtime binding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldMediaSessionAcceptanceReceipt {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Stable decision identity derived from the request.
    pub decision_id: DottedId,
    /// Reviewed request identity.
    pub request_id: DottedId,
    /// Whether the binding became current authority.
    pub accepted: bool,
    /// Closed rejection reason when not accepted.
    pub rejection_reason: Option<ManifoldMediaSessionAcceptanceRejectionReason>,
    /// Exact record retained when accepted.
    pub accepted_session: Option<ManifoldAcceptedMediaSession>,
    /// Global mutation revision before review.
    pub prior_authority_revision: Revision,
    /// Global mutation revision after review.
    pub resulting_authority_revision: Revision,
}

/// Explicit stop or revoke action.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldMediaSessionTerminationAction {
    /// Graceful lifecycle stop.
    Stop,
    /// Authority revocation.
    Revoke,
}

/// Runtime-command-bound stop or revoke request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldMediaSessionTerminationRequest {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Replay-protected media mutation id.
    pub request_id: DottedId,
    /// Expected global mutation revision.
    pub expected_authority_revision: Revision,
    /// Runtime Host request that applied the action.
    pub runtime_command_request_id: DottedId,
    /// Exact decision being ended.
    pub decision_id: DottedId,
    /// Exact session identity.
    pub session_id: DottedId,
    /// Host-owned provider epoch expected by the caller.
    pub expected_provider_epoch_id: DottedId,
    /// Explicit lifecycle action.
    pub action: ManifoldMediaSessionTerminationAction,
}

/// Stop/revoke/expiry mutation receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldMediaSessionMutationReceipt {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Request or sweep identity.
    pub source_id: DottedId,
    /// Whether state changed.
    pub applied: bool,
    /// Closed rejection reason.
    pub rejection_reason: Option<ManifoldMediaSessionAcceptanceRejectionReason>,
    /// Decisions whose lifecycle ended.
    pub affected_decision_ids: Vec<DottedId>,
    /// Global mutation revision before review.
    pub prior_authority_revision: Revision,
    /// Global mutation revision after review.
    pub resulting_authority_revision: Revision,
}

/// Non-mutating subject-current validation receipt for platform adoption.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldMediaSessionCurrentReceipt {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Validated decision identity.
    pub decision_id: DottedId,
    /// Current global mutation revision observed during validation.
    pub acceptance_state_authority_revision: Revision,
    /// Whether the exact subject record is current and usable.
    pub current: bool,
    /// Closed denial reason when not current.
    pub rejection_reason: Option<ManifoldMediaSessionAcceptanceRejectionReason>,
    /// Exact retained subject record, including command/client/lease/digest.
    pub session: Option<ManifoldAcceptedMediaSession>,
    /// Validation time.
    pub validated_at_ms: u64,
}

/// Reviews and retains one exact media product binding after a Runtime Host
/// command was accepted and applied by the composing authority.
#[must_use]
pub fn review_and_apply_media_session_acceptance(
    state: &ManifoldMediaSessionAcceptanceState,
    request: &ManifoldMediaSessionAcceptanceRequest,
    runtime: ManifoldMediaSessionRuntimeCommandContext<'_>,
    now_ms: u64,
) -> (
    ManifoldMediaSessionAcceptanceState,
    ManifoldMediaSessionAcceptanceReceipt,
) {
    let prior = state.authority_revision;
    let rejection = validate_acceptance_request(state, request, runtime, now_ms)
        .err()
        .or_else(|| {
            prior
                .next()
                .is_none()
                .then_some(ManifoldMediaSessionAcceptanceRejectionReason::RevisionExhausted)
        });
    if let Some(reason) = rejection {
        return (
            state.clone(),
            acceptance_receipt(request, false, Some(reason), None, prior, prior),
        );
    }

    let descriptor = &request.product_binding.descriptor;
    let command = runtime.command_request;
    let dispatch = runtime.dispatch;
    let application = runtime.application;
    let accepted = ManifoldAcceptedMediaSession {
        schema_id: schema(MANIFOLD_ACCEPTED_MEDIA_SESSION_SCHEMA),
        decision_id: derived("decision.media-session", &request.request_id),
        request_id: request.request_id.clone(),
        session_id: descriptor.session_id.clone(),
        session_authority_revision: descriptor.authority_revision,
        product_descriptor_canonical_sha256: request
            .product_binding
            .descriptor_canonical_sha256
            .clone(),
        provider_epoch_id: runtime.live_provider_epoch_id.clone(),
        platform_runtime_spec_id: descriptor.platform_runtime_spec_id.clone(),
        product_id: request.product_id.clone(),
        feature_lock_id: request.feature_lock_id.clone(),
        feature_lock_fingerprint: request.feature_lock_fingerprint.clone(),
        capability_id: request.capability_id.clone(),
        admission_grant_id: request.admission_grant_id.clone(),
        runtime_authority_host_id: runtime.runtime_host_id.clone(),
        runtime_command_request_id: command.request_id.clone(),
        runtime_command_id: command.command_id.clone(),
        runtime_client_id: command.requester_id.clone(),
        runtime_lease_id: command.lease_id.clone().expect("validated lease"),
        runtime_params_digest: command.params_digest.clone().expect("validated params"),
        runtime_dispatch_id: dispatch.dispatch_id.clone(),
        runtime_application_receipt_id: application.receipt_id.clone(),
        runtime_resulting_authority_revision: application.resulting_authority_revision,
        lifecycle_status: ManifoldMediaSessionLifecycleStatus::Current,
        accepted_at_ms: now_ms,
        expires_at_ms: request.expires_at_ms,
        ended_at_ms: None,
        ended_by_id: None,
        product_binding: request.product_binding.clone(),
    };
    let resulting = prior.next().unwrap_or(prior);
    let mut next = state.clone();
    next.authority_revision = resulting;
    for current in &mut next.sessions {
        if current.session_id == accepted.session_id
            && current.lifecycle_status == ManifoldMediaSessionLifecycleStatus::Current
        {
            current.lifecycle_status = ManifoldMediaSessionLifecycleStatus::Superseded;
            current.ended_at_ms = Some(now_ms);
            current.ended_by_id = Some(request.request_id.clone());
        }
    }
    next.sessions.push(accepted.clone());
    next.sessions
        .sort_by(|left, right| left.decision_id.cmp(&right.decision_id));
    next.applied_request_ids.push(request.request_id.clone());
    next.applied_request_ids.sort();
    (
        next,
        acceptance_receipt(request, true, None, Some(accepted), prior, resulting),
    )
}

/// Applies an accepted Runtime Host stop/revoke command.
#[must_use]
pub fn review_and_apply_media_session_termination(
    state: &ManifoldMediaSessionAcceptanceState,
    request: &ManifoldMediaSessionTerminationRequest,
    runtime: ManifoldMediaSessionRuntimeCommandContext<'_>,
    now_ms: u64,
) -> (
    ManifoldMediaSessionAcceptanceState,
    ManifoldMediaSessionMutationReceipt,
) {
    let prior = state.authority_revision;
    let expected_command = match request.action {
        ManifoldMediaSessionTerminationAction::Stop => MANIFOLD_MEDIA_SESSION_STOP_COMMAND,
        ManifoldMediaSessionTerminationAction::Revoke => MANIFOLD_MEDIA_SESSION_REVOKE_COMMAND,
    };
    let expected_params = media_session_termination_params_digest(request).ok();
    let rejection =
        if request.schema_id.as_str() != MANIFOLD_MEDIA_SESSION_TERMINATION_REQUEST_SCHEMA {
            Some(ManifoldMediaSessionAcceptanceRejectionReason::SchemaMismatch)
        } else if !validate_media_session_acceptance_state(state) {
            Some(ManifoldMediaSessionAcceptanceRejectionReason::InvalidAuthorityState)
        } else if request.expected_authority_revision != state.authority_revision {
            Some(ManifoldMediaSessionAcceptanceRejectionReason::StaleAuthorityRevision)
        } else if state.applied_request_ids.contains(&request.request_id) {
            Some(ManifoldMediaSessionAcceptanceRejectionReason::ReplayedRequest)
        } else if request.expected_provider_epoch_id != *runtime.live_provider_epoch_id {
            Some(ManifoldMediaSessionAcceptanceRejectionReason::ProviderEpochMismatch)
        } else if validate_runtime_command(
            runtime,
            &request.runtime_command_request_id,
            expected_command,
            expected_params.as_ref(),
        )
        .is_err()
        {
            Some(ManifoldMediaSessionAcceptanceRejectionReason::RuntimeCommandNotAccepted)
        } else if !state.sessions.iter().any(|session| {
            session.decision_id == request.decision_id
                && session.session_id == request.session_id
                && session.provider_epoch_id == request.expected_provider_epoch_id
                && session.lifecycle_status == ManifoldMediaSessionLifecycleStatus::Current
                && session.expires_at_ms > now_ms
        }) {
            Some(ManifoldMediaSessionAcceptanceRejectionReason::SessionNotCurrent)
        } else if state.sessions.iter().any(|session| {
            session.decision_id == request.decision_id
                && match request.action {
                    ManifoldMediaSessionTerminationAction::Stop => {
                        runtime.command_request.requester_id != session.runtime_client_id
                            || runtime.command_request.lease_id.as_ref()
                                != Some(&session.runtime_lease_id)
                    }
                    ManifoldMediaSessionTerminationAction::Revoke => !runtime
                        .trusted_revoker_ids
                        .contains(&runtime.command_request.requester_id),
                }
        }) {
            Some(ManifoldMediaSessionAcceptanceRejectionReason::UntrustedProposer)
        } else if prior.next().is_none() {
            Some(ManifoldMediaSessionAcceptanceRejectionReason::RevisionExhausted)
        } else {
            None
        };
    if let Some(reason) = rejection {
        return (
            state.clone(),
            mutation_receipt(
                request.request_id.clone(),
                false,
                Some(reason),
                Vec::new(),
                prior,
                prior,
            ),
        );
    }
    let mut next = state.clone();
    let status = match request.action {
        ManifoldMediaSessionTerminationAction::Stop => ManifoldMediaSessionLifecycleStatus::Stopped,
        ManifoldMediaSessionTerminationAction::Revoke => {
            ManifoldMediaSessionLifecycleStatus::Revoked
        }
    };
    for session in &mut next.sessions {
        if session.decision_id == request.decision_id {
            session.lifecycle_status = status.clone();
            session.ended_at_ms = Some(now_ms);
            session.ended_by_id = Some(request.request_id.clone());
        }
    }
    next.authority_revision = prior.next().unwrap_or(prior);
    next.applied_request_ids.push(request.request_id.clone());
    next.applied_request_ids.sort();
    (
        next.clone(),
        mutation_receipt(
            request.request_id.clone(),
            true,
            None,
            vec![request.decision_id.clone()],
            prior,
            next.authority_revision,
        ),
    )
}

/// Expires every current session whose retained deadline has passed.
#[must_use]
pub fn expire_media_sessions(
    state: &ManifoldMediaSessionAcceptanceState,
    sweep_id: DottedId,
    expected_authority_revision: Revision,
    now_ms: u64,
) -> (
    ManifoldMediaSessionAcceptanceState,
    ManifoldMediaSessionMutationReceipt,
) {
    let prior = state.authority_revision;
    let reason = if !validate_media_session_acceptance_state(state) {
        Some(ManifoldMediaSessionAcceptanceRejectionReason::InvalidAuthorityState)
    } else if expected_authority_revision != prior {
        Some(ManifoldMediaSessionAcceptanceRejectionReason::StaleAuthorityRevision)
    } else if state.applied_request_ids.contains(&sweep_id) {
        Some(ManifoldMediaSessionAcceptanceRejectionReason::ReplayedRequest)
    } else if !state.sessions.iter().any(|session| {
        session.lifecycle_status == ManifoldMediaSessionLifecycleStatus::Current
            && session.expires_at_ms <= now_ms
    }) {
        Some(ManifoldMediaSessionAcceptanceRejectionReason::NoExpiredSessions)
    } else if prior.next().is_none() {
        Some(ManifoldMediaSessionAcceptanceRejectionReason::RevisionExhausted)
    } else {
        None
    };
    if let Some(reason) = reason {
        return (
            state.clone(),
            mutation_receipt(sweep_id, false, Some(reason), Vec::new(), prior, prior),
        );
    }
    let mut next = state.clone();
    let mut affected = Vec::new();
    for session in &mut next.sessions {
        if session.lifecycle_status == ManifoldMediaSessionLifecycleStatus::Current
            && session.expires_at_ms <= now_ms
        {
            session.lifecycle_status = ManifoldMediaSessionLifecycleStatus::Expired;
            session.ended_at_ms = Some(now_ms);
            session.ended_by_id = Some(sweep_id.clone());
            affected.push(session.decision_id.clone());
        }
    }
    affected.sort();
    next.authority_revision = prior.next().unwrap_or(prior);
    next.applied_request_ids.push(sweep_id.clone());
    next.applied_request_ids.sort();
    (
        next.clone(),
        mutation_receipt(
            sweep_id,
            true,
            None,
            affected,
            prior,
            next.authority_revision,
        ),
    )
}

/// Emits an exact non-mutating current-state receipt for one subject decision.
#[must_use]
pub fn validate_current_media_session(
    state: &ManifoldMediaSessionAcceptanceState,
    decision_id: &DottedId,
    live_provider_epoch_id: &DottedId,
    now_ms: u64,
) -> ManifoldMediaSessionCurrentReceipt {
    let session = state
        .sessions
        .iter()
        .find(|session| &session.decision_id == decision_id)
        .cloned();
    let rejection_reason = if !validate_media_session_acceptance_state(state) {
        Some(ManifoldMediaSessionAcceptanceRejectionReason::InvalidAuthorityState)
    } else if session.as_ref().is_none_or(|value| {
        value.lifecycle_status != ManifoldMediaSessionLifecycleStatus::Current
            || value.provider_epoch_id != *live_provider_epoch_id
            || value.accepted_at_ms > now_ms
            || value.expires_at_ms <= now_ms
    }) {
        Some(ManifoldMediaSessionAcceptanceRejectionReason::SessionNotCurrent)
    } else {
        None
    };
    ManifoldMediaSessionCurrentReceipt {
        schema_id: schema(MANIFOLD_MEDIA_SESSION_CURRENT_RECEIPT_SCHEMA),
        decision_id: decision_id.clone(),
        acceptance_state_authority_revision: state.authority_revision,
        current: rejection_reason.is_none(),
        rejection_reason,
        session,
        validated_at_ms: now_ms,
    }
}

/// Validates durable media-session authority state and provenance closure.
#[must_use]
pub fn validate_media_session_acceptance_state(
    state: &ManifoldMediaSessionAcceptanceState,
) -> bool {
    let request_ids = state.applied_request_ids.iter().collect::<BTreeSet<_>>();
    let decision_ids = state
        .sessions
        .iter()
        .map(|value| &value.decision_id)
        .collect::<BTreeSet<_>>();
    let current_session_ids = state
        .sessions
        .iter()
        .filter(|value| value.lifecycle_status == ManifoldMediaSessionLifecycleStatus::Current)
        .map(|value| &value.session_id)
        .collect::<BTreeSet<_>>();
    state.schema_id.as_str() == MANIFOLD_MEDIA_SESSION_ACCEPTANCE_STATE_SCHEMA
        && request_ids.len() == state.applied_request_ids.len()
        && decision_ids.len() == state.sessions.len()
        && current_session_ids.len()
            == state
                .sessions
                .iter()
                .filter(|value| {
                    value.lifecycle_status == ManifoldMediaSessionLifecycleStatus::Current
                })
                .count()
        && state
            .sessions
            .windows(2)
            .all(|pair| pair[0].decision_id < pair[1].decision_id)
        && state.sessions.iter().all(valid_session_record)
}

fn validate_acceptance_request(
    state: &ManifoldMediaSessionAcceptanceState,
    request: &ManifoldMediaSessionAcceptanceRequest,
    runtime: ManifoldMediaSessionRuntimeCommandContext<'_>,
    now_ms: u64,
) -> Result<(), ManifoldMediaSessionAcceptanceRejectionReason> {
    if state.schema_id.as_str() != MANIFOLD_MEDIA_SESSION_ACCEPTANCE_STATE_SCHEMA
        || request.schema_id.as_str() != MANIFOLD_MEDIA_SESSION_ACCEPTANCE_REQUEST_SCHEMA
    {
        return Err(ManifoldMediaSessionAcceptanceRejectionReason::SchemaMismatch);
    }
    if !validate_media_session_acceptance_state(state) {
        return Err(ManifoldMediaSessionAcceptanceRejectionReason::InvalidAuthorityState);
    }
    if request.expected_authority_revision != state.authority_revision {
        return Err(ManifoldMediaSessionAcceptanceRejectionReason::StaleAuthorityRevision);
    }
    if state.applied_request_ids.contains(&request.request_id) {
        return Err(ManifoldMediaSessionAcceptanceRejectionReason::ReplayedRequest);
    }
    if request.product_binding.validate().is_err() {
        return Err(ManifoldMediaSessionAcceptanceRejectionReason::InvalidProductBinding);
    }
    if !valid_sha256(&request.feature_lock_fingerprint) {
        return Err(ManifoldMediaSessionAcceptanceRejectionReason::InvalidProductBinding);
    }
    if request.expected_provider_epoch_id != *runtime.live_provider_epoch_id {
        return Err(ManifoldMediaSessionAcceptanceRejectionReason::ProviderEpochMismatch);
    }
    if request.expires_at_ms <= now_ms
        || request.expires_at_ms.saturating_sub(now_ms) > MAX_MEDIA_SESSION_TTL_MS
    {
        return Err(ManifoldMediaSessionAcceptanceRejectionReason::InvalidExpiry);
    }
    let expected_params = media_session_acceptance_params_digest(request)
        .map_err(|_| ManifoldMediaSessionAcceptanceRejectionReason::RuntimeCommandNotAccepted)?;
    validate_runtime_command(
        runtime,
        &request.runtime_command_request_id,
        MANIFOLD_MEDIA_SESSION_ACCEPT_COMMAND,
        Some(&expected_params),
    )?;
    let command = runtime.command_request;
    let lease_id = command
        .lease_id
        .as_ref()
        .ok_or(ManifoldMediaSessionAcceptanceRejectionReason::RuntimeCommandNotAccepted)?;
    let grant = runtime.client_grants.iter().find(|grant| {
        valid_semantic_product_fingerprint(&grant.broker_product_lock_fingerprint)
            && valid_sha256(&grant.broker_product_lock_sha256)
            && valid_sha256(&grant.broker_client_lock_fingerprint)
            && valid_sha256(&grant.feature_lock_fingerprint)
            && grant.broker_product_lock_id != grant.broker_client_lock_id
            && grant.broker_client_lock_id != grant.feature_lock_id
            && grant.broker_product_lock_sha256 != grant.broker_client_lock_fingerprint
            && grant.broker_product_lock_sha256 != grant.feature_lock_fingerprint
            && grant.broker_client_lock_fingerprint != grant.feature_lock_fingerprint
            && grant.runtime_host_id == *runtime.runtime_host_id
            && grant.client_id == command.requester_id
            && &grant.lease_id == lease_id
            && grant.product_id == request.product_id
            && grant.feature_lock_id == request.feature_lock_id
            && grant.feature_lock_fingerprint == request.feature_lock_fingerprint
            && grant.capability_id == request.capability_id
            && grant.admission_grant_id == request.admission_grant_id
    });
    let Some(grant) = grant else {
        return Err(ManifoldMediaSessionAcceptanceRejectionReason::UntrustedProposer);
    };
    let descriptor = &request.product_binding.descriptor;
    let mut resource_ids = descriptor
        .source_ids
        .iter()
        .chain(&descriptor.processor_ids)
        .chain(&descriptor.route_ids)
        .chain(&descriptor.sink_ids)
        .chain(&descriptor.stream_ids)
        .cloned()
        .collect::<Vec<_>>();
    resource_ids.sort();
    if grant.allowed_session_id != descriptor.session_id
        || grant.allowed_platform_runtime_spec_id != descriptor.platform_runtime_spec_id
        || !grant
            .allowed_descriptor_canonical_sha256
            .iter()
            .any(|digest| digest == &request.product_binding.descriptor_canonical_sha256)
        || grant.allowed_descriptor_canonical_sha256.is_empty()
        || grant
            .allowed_descriptor_canonical_sha256
            .iter()
            .any(|digest| !valid_sha256(digest))
        || grant
            .allowed_descriptor_canonical_sha256
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || grant.allowed_resource_ids != resource_ids
        || grant.allowed_resource_ids.is_empty()
        || grant
            .allowed_resource_ids
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err(ManifoldMediaSessionAcceptanceRejectionReason::UntrustedProposer);
    }
    if state.sessions.iter().any(|current| {
        current.session_id == descriptor.session_id
            && (current.product_id != request.product_id
                || current.feature_lock_id != request.feature_lock_id
                || current.feature_lock_fingerprint != request.feature_lock_fingerprint
                || current.runtime_client_id != command.requester_id)
    }) {
        return Err(ManifoldMediaSessionAcceptanceRejectionReason::SubjectLineageMismatch);
    }
    if state.sessions.iter().any(|current| {
        current.session_id == descriptor.session_id
            && current.session_authority_revision >= descriptor.authority_revision
    }) {
        return Err(ManifoldMediaSessionAcceptanceRejectionReason::StaleSessionRevision);
    }
    Ok(())
}

fn validate_runtime_command(
    runtime: ManifoldMediaSessionRuntimeCommandContext<'_>,
    expected_request_id: &DottedId,
    expected_command_id: &str,
    expected_params: Option<&ManifoldRuntimeTypedParamsDigest>,
) -> Result<(), ManifoldMediaSessionAcceptanceRejectionReason> {
    let command = runtime.command_request;
    let dispatch = runtime.dispatch;
    let application = runtime.application;
    if command.schema_id.as_str() != HOST_COMMAND_REQUEST_SCHEMA
        || command.request_id != *expected_request_id
        || command.command_id.as_str() != expected_command_id
        || command.lease_id.is_none()
        || command.params_digest.as_ref() != expected_params
        || dispatch.schema_id.as_str() != HOST_DISPATCH_RECEIPT_SCHEMA
        || dispatch.authority_host_id != *runtime.runtime_host_id
        || dispatch.dispatch_id != derived("dispatch.runtime", &command.request_id)
        || dispatch.request_id != command.request_id
        || dispatch.command_id != command.command_id
        || dispatch.params_digest != command.params_digest
        || dispatch.reviewed_authority_revision != command.expected_authority_revision
        || dispatch.outcome != ManifoldRuntimeDispatchOutcome::Ready
        || dispatch.rejection_reason.is_some()
        || application.schema_id.as_str() != HOST_APPLICATION_RECEIPT_SCHEMA
        || application.authority_host_id != *runtime.runtime_host_id
        || application.receipt_id != derived("receipt.runtime", &command.request_id)
        || application.dispatch_id != dispatch.dispatch_id
        || application.request_id != command.request_id
        || application.params_digest != command.params_digest
        || !application.applied
        || application.rejection_reason.is_some()
        || application.prior_authority_revision != dispatch.reviewed_authority_revision
        || application.resulting_authority_revision
            != application
                .prior_authority_revision
                .next()
                .unwrap_or(application.prior_authority_revision)
    {
        return Err(ManifoldMediaSessionAcceptanceRejectionReason::RuntimeCommandNotAccepted);
    }
    Ok(())
}

fn valid_session_record(session: &ManifoldAcceptedMediaSession) -> bool {
    let lifecycle_valid = match session.lifecycle_status {
        ManifoldMediaSessionLifecycleStatus::Current => {
            session.ended_at_ms.is_none() && session.ended_by_id.is_none()
        }
        _ => session.ended_at_ms.is_some() && session.ended_by_id.is_some(),
    };
    session.schema_id.as_str() == MANIFOLD_ACCEPTED_MEDIA_SESSION_SCHEMA
        && session.decision_id == derived("decision.media-session", &session.request_id)
        && session.product_binding.validate().is_ok()
        && session.session_id == session.product_binding.descriptor.session_id
        && session.session_authority_revision
            == session.product_binding.descriptor.authority_revision
        && session.product_descriptor_canonical_sha256
            == session.product_binding.descriptor_canonical_sha256
        && session.platform_runtime_spec_id
            == session.product_binding.descriptor.platform_runtime_spec_id
        && session.runtime_command_id.as_str() == MANIFOLD_MEDIA_SESSION_ACCEPT_COMMAND
        && valid_sha256(&session.feature_lock_fingerprint)
        && session.runtime_params_digest.schema_id.as_str() == HOST_TYPED_PARAMS_DIGEST_SCHEMA
        && session.runtime_lease_id.as_str().len() > 1
        && session.accepted_at_ms < session.expires_at_ms
        && lifecycle_valid
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_semantic_product_fingerprint(value: &str) -> bool {
    value.len() == 24
        && value.starts_with("fnv1a64-")
        && value[8..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Canonical typed params digest for one acceptance request.
pub fn media_session_acceptance_params_digest(
    request: &ManifoldMediaSessionAcceptanceRequest,
) -> Result<ManifoldRuntimeTypedParamsDigest, ManifoldMediaSessionBindingError> {
    typed_params_digest(MANIFOLD_MEDIA_SESSION_ACCEPT_PARAMS_TYPE, request)
}

/// Canonical typed params digest for one stop/revoke request.
pub fn media_session_termination_params_digest(
    request: &ManifoldMediaSessionTerminationRequest,
) -> Result<ManifoldRuntimeTypedParamsDigest, ManifoldMediaSessionBindingError> {
    typed_params_digest(MANIFOLD_MEDIA_SESSION_TERMINATION_PARAMS_TYPE, request)
}

fn typed_params_digest<T: Serialize>(
    params_type_id: &str,
    value: &T,
) -> Result<ManifoldRuntimeTypedParamsDigest, ManifoldMediaSessionBindingError> {
    let canonical =
        serde_json::to_vec(value).map_err(|_| ManifoldMediaSessionBindingError::EncodeFailed)?;
    let canonical_size_bytes = u32::try_from(canonical.len())
        .map_err(|_| ManifoldMediaSessionBindingError::EncodeFailed)?;
    Ok(ManifoldRuntimeTypedParamsDigest {
        schema_id: schema(HOST_TYPED_PARAMS_DIGEST_SCHEMA),
        params_type_id: DottedId::new(params_type_id)
            .map_err(|_| ManifoldMediaSessionBindingError::EncodeFailed)?,
        canonical_sha256: format!("sha256:{}", encode_lower_hex(&Sha256::digest(canonical))),
        canonical_size_bytes,
    })
}

fn acceptance_receipt(
    request: &ManifoldMediaSessionAcceptanceRequest,
    accepted: bool,
    rejection_reason: Option<ManifoldMediaSessionAcceptanceRejectionReason>,
    accepted_session: Option<ManifoldAcceptedMediaSession>,
    prior_authority_revision: Revision,
    resulting_authority_revision: Revision,
) -> ManifoldMediaSessionAcceptanceReceipt {
    ManifoldMediaSessionAcceptanceReceipt {
        schema_id: schema(MANIFOLD_MEDIA_SESSION_ACCEPTANCE_RECEIPT_SCHEMA),
        decision_id: derived("decision.media-session", &request.request_id),
        request_id: request.request_id.clone(),
        accepted,
        rejection_reason,
        accepted_session,
        prior_authority_revision,
        resulting_authority_revision,
    }
}

fn mutation_receipt(
    source_id: DottedId,
    applied: bool,
    rejection_reason: Option<ManifoldMediaSessionAcceptanceRejectionReason>,
    affected_decision_ids: Vec<DottedId>,
    prior_authority_revision: Revision,
    resulting_authority_revision: Revision,
) -> ManifoldMediaSessionMutationReceipt {
    ManifoldMediaSessionMutationReceipt {
        schema_id: schema(MANIFOLD_MEDIA_SESSION_MUTATION_RECEIPT_SCHEMA),
        source_id,
        applied,
        rejection_reason,
        affected_decision_ids,
        prior_authority_revision,
        resulting_authority_revision,
    }
}

fn schema(value: &str) -> SchemaId {
    SchemaId::new(value).expect("static media-session authority schema")
}

fn derived(prefix: &str, source_id: &DottedId) -> DottedId {
    DottedId::new(format!("{prefix}.{}", source_id.as_str()))
        .expect("derived media-session authority id")
}

fn encode_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

/// Returns `sha256:<lowercase hex>` for canonical typed descriptor JSON.
///
/// # Errors
///
/// Returns [`ManifoldMediaSessionBindingError::EncodeFailed`] when the typed
/// descriptor cannot be serialized.
pub fn canonical_media_session_sha256(
    descriptor: &ManifoldMediaSessionDescriptor,
) -> Result<String, ManifoldMediaSessionBindingError> {
    let canonical = serde_json::to_vec(descriptor)
        .map_err(|_| ManifoldMediaSessionBindingError::EncodeFailed)?;
    let digest = Sha256::digest(canonical)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(format!("sha256:{digest}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusty_manifold_runtime_host::{
        ManifoldRuntimeCommandDescriptor, ManifoldRuntimeHost, ManifoldRuntimeHostSnapshot,
        ManifoldRuntimeLease, HOST_SNAPSHOT_SCHEMA,
    };

    fn descriptor() -> ManifoldMediaSessionDescriptor {
        serde_json::from_str(include_str!(
            "../../../fixtures/media-session/generic-media-session.pass.json"
        ))
        .expect("descriptor")
    }

    fn binding() -> ManifoldMediaSessionProductBinding {
        let descriptor = descriptor();
        ManifoldMediaSessionProductBinding {
            schema_id: MANIFOLD_MEDIA_SESSION_BINDING_SCHEMA.to_owned(),
            descriptor_canonical_sha256: canonical_media_session_sha256(&descriptor)
                .expect("digest"),
            descriptor,
        }
    }

    fn id(value: &str) -> DottedId {
        DottedId::new(value).expect("id")
    }

    fn acceptance_request(
        request_id: &str,
        authority_revision: Revision,
        product_binding: ManifoldMediaSessionProductBinding,
    ) -> ManifoldMediaSessionAcceptanceRequest {
        ManifoldMediaSessionAcceptanceRequest {
            schema_id: schema(MANIFOLD_MEDIA_SESSION_ACCEPTANCE_REQUEST_SCHEMA),
            request_id: id(request_id),
            expected_authority_revision: authority_revision,
            runtime_command_request_id: id(&format!("runtime.{request_id}")),
            expected_provider_epoch_id: id("provider.epoch.quest.001"),
            product_id: id("product.quest.media-test"),
            feature_lock_id: id("lock.quest.media-test"),
            feature_lock_fingerprint: format!("sha256:{}", "ab".repeat(32)),
            capability_id: id("capability.media.session.accept"),
            admission_grant_id: id("grant.quest.media-test"),
            expires_at_ms: 60_000,
            product_binding,
        }
    }

    struct RuntimeProof {
        runtime_host_id: DottedId,
        provider_epoch_id: DottedId,
        grants: Vec<ManifoldMediaSessionClientGrant>,
        revokers: Vec<DottedId>,
        command: ManifoldRuntimeCommandRequest,
        dispatch: ManifoldRuntimeDispatchReceipt,
        application: ManifoldRuntimeApplicationReceipt,
    }

    impl RuntimeProof {
        fn context(&self) -> ManifoldMediaSessionRuntimeCommandContext<'_> {
            ManifoldMediaSessionRuntimeCommandContext {
                runtime_host_id: &self.runtime_host_id,
                live_provider_epoch_id: &self.provider_epoch_id,
                client_grants: &self.grants,
                trusted_revoker_ids: &self.revokers,
                command_request: &self.command,
                dispatch: &self.dispatch,
                application: &self.application,
            }
        }
    }

    fn acceptance_proof(
        request: &ManifoldMediaSessionAcceptanceRequest,
        requester_id: &str,
    ) -> RuntimeProof {
        let runtime_host_id = id("host.runtime.media-test");
        let requester = id(requester_id);
        let lease_id = id("lease.runtime.media-test");
        let scope = id("scope.media.session.authority");
        let snapshot = ManifoldRuntimeHostSnapshot {
            schema_id: schema(HOST_SNAPSHOT_SCHEMA),
            host_id: runtime_host_id.clone(),
            authority_revision: Revision::INITIAL,
            commands: vec![ManifoldRuntimeCommandDescriptor {
                command_id: id(MANIFOLD_MEDIA_SESSION_ACCEPT_COMMAND),
                required_lease_scope: Some(scope.clone()),
            }],
            leases: vec![ManifoldRuntimeLease {
                lease_id: lease_id.clone(),
                scope,
                holder_id: requester.clone(),
                expires_at_ms: 100_000,
            }],
            applied_request_ids: Vec::new(),
            reviewed_sweep_ids: Vec::new(),
            audit_events: Vec::new(),
        };
        let command = ManifoldRuntimeCommandRequest {
            schema_id: schema(HOST_COMMAND_REQUEST_SCHEMA),
            request_id: request.runtime_command_request_id.clone(),
            expected_authority_revision: Revision::INITIAL,
            requester_id: requester.clone(),
            command_id: id(MANIFOLD_MEDIA_SESSION_ACCEPT_COMMAND),
            lease_id: Some(lease_id.clone()),
            params_digest: Some(media_session_acceptance_params_digest(request).expect("params")),
            issued_at_ms: 1_000,
            expires_at_ms: 10_000,
        };
        let mut host = ManifoldRuntimeHost::from_snapshot(snapshot).expect("runtime host");
        let dispatch = host.review_command(&command, 2_000);
        let application = host.apply_dispatch(&command, &dispatch, 2_000);
        let grant = ManifoldMediaSessionClientGrant {
            broker_adapter_id: id("adapter.broker.media-test"),
            broker_runtime_host_id: id("host.broker.media-test"),
            broker_product_lock_id: id("lock.broker.media-test"),
            broker_product_lock_fingerprint: "fnv1a64-0011223344556677".to_owned(),
            broker_product_lock_sha256: format!("sha256:{}", "d1".repeat(32)),
            broker_capability_id: id("capability.command.media.session.start"),
            broker_command_id: id("command.media.session.start"),
            broker_runtime_lease_id: id("lease.broker.media-test"),
            broker_client_identity: ManifoldClientIdentity {
                client_id: requester.clone(),
                platform_subject: "org.rustyquest.media_test".to_owned(),
                signing_fingerprint: format!("sha256:{}", "a1".repeat(32)),
            },
            broker_client_lock_id: id("lock.client.media-test"),
            broker_client_lock_fingerprint: format!("sha256:{}", "c1".repeat(32)),
            runtime_host_id: runtime_host_id.clone(),
            client_id: requester.clone(),
            lease_id: lease_id.clone(),
            product_id: request.product_id.clone(),
            feature_lock_id: request.feature_lock_id.clone(),
            feature_lock_fingerprint: request.feature_lock_fingerprint.clone(),
            capability_id: request.capability_id.clone(),
            admission_grant_id: request.admission_grant_id.clone(),
            allowed_session_id: request.product_binding.descriptor.session_id.clone(),
            allowed_platform_runtime_spec_id: request
                .product_binding
                .descriptor
                .platform_runtime_spec_id
                .clone(),
            allowed_descriptor_canonical_sha256: vec![request
                .product_binding
                .descriptor_canonical_sha256
                .clone()],
            allowed_resource_ids: {
                let descriptor = &request.product_binding.descriptor;
                let mut ids = descriptor
                    .source_ids
                    .iter()
                    .chain(&descriptor.processor_ids)
                    .chain(&descriptor.route_ids)
                    .chain(&descriptor.sink_ids)
                    .chain(&descriptor.stream_ids)
                    .cloned()
                    .collect::<Vec<_>>();
                ids.sort();
                ids
            },
        };
        RuntimeProof {
            runtime_host_id,
            provider_epoch_id: id("provider.epoch.quest.001"),
            grants: vec![grant],
            revokers: vec![id("operator.media-revoker")],
            command,
            dispatch,
            application,
        }
    }

    #[test]
    fn canonical_descriptor_binding_validates() {
        binding().validate().expect("binding");
    }

    #[test]
    fn digest_and_reference_order_damage_reject() {
        let mut damaged = binding();
        damaged.descriptor_canonical_sha256 = format!("sha256:{}", "00".repeat(32));
        assert_eq!(
            damaged.validate(),
            Err(ManifoldMediaSessionBindingError::DigestMismatch)
        );

        let mut reordered = binding();
        reordered.descriptor.source_ids.reverse();
        reordered.descriptor_canonical_sha256 =
            canonical_media_session_sha256(&reordered.descriptor).expect("digest");
        assert_eq!(
            reordered.validate(),
            Err(ManifoldMediaSessionBindingError::DescriptorNotCanonical)
        );
    }

    #[test]
    fn acceptance_retains_decision_digest_revision_runtime_and_provider_epoch() {
        let request = acceptance_request("request.media.accept.001", Revision::INITIAL, binding());
        let proof = acceptance_proof(&request, "client.quest.media-test");
        let (state, receipt) = review_and_apply_media_session_acceptance(
            &ManifoldMediaSessionAcceptanceState::empty(),
            &request,
            proof.context(),
            2_000,
        );
        assert!(receipt.accepted);
        let accepted = receipt.accepted_session.expect("accepted session");
        assert_eq!(
            accepted.decision_id,
            id("decision.media-session.request.media.accept.001")
        );
        assert_eq!(
            accepted.session_authority_revision,
            request.product_binding.descriptor.authority_revision
        );
        assert_eq!(
            accepted.product_descriptor_canonical_sha256,
            request.product_binding.descriptor_canonical_sha256
        );
        assert_eq!(
            accepted.provider_epoch_id,
            request.expected_provider_epoch_id
        );
        assert_eq!(accepted.runtime_client_id, id("client.quest.media-test"));
        assert_eq!(accepted.runtime_lease_id, id("lease.runtime.media-test"));
        assert_eq!(accepted.product_id, request.product_id);
        assert_eq!(
            accepted.platform_runtime_spec_id,
            request.product_binding.descriptor.platform_runtime_spec_id
        );
        assert!(validate_media_session_acceptance_state(&state));
    }

    #[test]
    fn replay_stale_revision_and_forged_digest_never_advance() {
        let first = acceptance_request("request.media.accept.001", Revision::INITIAL, binding());
        let proof = acceptance_proof(&first, "client.quest.media-test");
        let (state, _) = review_and_apply_media_session_acceptance(
            &ManifoldMediaSessionAcceptanceState::empty(),
            &first,
            proof.context(),
            2_000,
        );
        let mut replay = first;
        replay.expected_authority_revision = state.authority_revision;
        let (unchanged, replay_receipt) =
            review_and_apply_media_session_acceptance(&state, &replay, proof.context(), 2_100);
        assert_eq!(unchanged, state);
        assert_eq!(
            replay_receipt.rejection_reason,
            Some(ManifoldMediaSessionAcceptanceRejectionReason::ReplayedRequest)
        );

        let stale = acceptance_request("request.media.accept.stale", Revision::INITIAL, binding());
        let (unchanged, stale_receipt) =
            review_and_apply_media_session_acceptance(&state, &stale, proof.context(), 2_100);
        assert_eq!(unchanged, state);
        assert_eq!(
            stale_receipt.rejection_reason,
            Some(ManifoldMediaSessionAcceptanceRejectionReason::StaleAuthorityRevision)
        );

        let mut forged_binding = binding();
        forged_binding.descriptor_canonical_sha256 = format!("sha256:{}", "00".repeat(32));
        let forged = acceptance_request(
            "request.media.accept.forged",
            state.authority_revision,
            forged_binding,
        );
        let (unchanged, forged_receipt) =
            review_and_apply_media_session_acceptance(&state, &forged, proof.context(), 2_100);
        assert_eq!(unchanged, state);
        assert_eq!(
            forged_receipt.rejection_reason,
            Some(ManifoldMediaSessionAcceptanceRejectionReason::InvalidProductBinding)
        );
    }

    #[test]
    fn forged_runtime_proof_provider_epoch_and_untrusted_client_reject() {
        let request = acceptance_request("request.media.accept.002", Revision::INITIAL, binding());
        let mut proof = acceptance_proof(&request, "client.quest.media-test");
        proof.application.applied = false;
        let (_, receipt) = review_and_apply_media_session_acceptance(
            &ManifoldMediaSessionAcceptanceState::empty(),
            &request,
            proof.context(),
            2_000,
        );
        assert_eq!(
            receipt.rejection_reason,
            Some(ManifoldMediaSessionAcceptanceRejectionReason::RuntimeCommandNotAccepted)
        );

        let mut proof = acceptance_proof(&request, "client.quest.media-test");
        proof.provider_epoch_id = id("provider.epoch.quest.other");
        let (_, receipt) = review_and_apply_media_session_acceptance(
            &ManifoldMediaSessionAcceptanceState::empty(),
            &request,
            proof.context(),
            2_000,
        );
        assert_eq!(
            receipt.rejection_reason,
            Some(ManifoldMediaSessionAcceptanceRejectionReason::ProviderEpochMismatch)
        );

        let mut proof = acceptance_proof(&request, "client.quest.media-test");
        proof.grants[0].client_id = id("client.quest.other");
        let (_, receipt) = review_and_apply_media_session_acceptance(
            &ManifoldMediaSessionAcceptanceState::empty(),
            &request,
            proof.context(),
            2_000,
        );
        assert_eq!(
            receipt.rejection_reason,
            Some(ManifoldMediaSessionAcceptanceRejectionReason::UntrustedProposer)
        );
    }

    #[test]
    fn independent_subjects_remain_current_and_cross_product_collision_rejects() {
        let first = acceptance_request("request.media.subject.first", Revision::INITIAL, binding());
        let first_proof = acceptance_proof(&first, "client.quest.media-test");
        let (state, first_receipt) = review_and_apply_media_session_acceptance(
            &ManifoldMediaSessionAcceptanceState::empty(),
            &first,
            first_proof.context(),
            2_000,
        );
        assert!(first_receipt.accepted);
        let first_decision = first_receipt
            .accepted_session
            .as_ref()
            .expect("first")
            .decision_id
            .clone();

        let mut second_binding = binding();
        second_binding.descriptor.session_id = id("session.media.independent-second");
        second_binding.descriptor_canonical_sha256 =
            canonical_media_session_sha256(&second_binding.descriptor).expect("digest");
        let second = acceptance_request(
            "request.media.subject.second",
            state.authority_revision,
            second_binding,
        );
        let second_proof = acceptance_proof(&second, "client.quest.media-test");
        let (state, second_receipt) = review_and_apply_media_session_acceptance(
            &state,
            &second,
            second_proof.context(),
            2_100,
        );
        assert!(second_receipt.accepted);
        assert!(
            validate_current_media_session(
                &state,
                &first_decision,
                &id("provider.epoch.quest.001"),
                2_200,
            )
            .current
        );

        let mut collision_binding = binding();
        collision_binding.descriptor.authority_revision = Revision::new(5).expect("revision");
        collision_binding.descriptor_canonical_sha256 =
            canonical_media_session_sha256(&collision_binding.descriptor).expect("digest");
        let mut collision = acceptance_request(
            "request.media.subject.cross-product-collision",
            state.authority_revision,
            collision_binding,
        );
        collision.product_id = id("product.quest.other-app");
        collision.feature_lock_id = id("lock.quest.other-app");
        collision.admission_grant_id = id("grant.quest.other-app");
        let collision_proof = acceptance_proof(&collision, "client.quest.other-app");
        let (unchanged, receipt) = review_and_apply_media_session_acceptance(
            &state,
            &collision,
            collision_proof.context(),
            2_300,
        );
        assert_eq!(unchanged, state);
        assert_eq!(
            receipt.rejection_reason,
            Some(ManifoldMediaSessionAcceptanceRejectionReason::SubjectLineageMismatch)
        );
    }
}
