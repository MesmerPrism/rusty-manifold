//! Operator-mediated peer credentials and signed rendezvous authority.
//!
//! Platform, Termux, and sidecar adapters may transport signed evidence. They
//! do not enroll peers, decide whether a key is current, consume nonces, or
//! authorize topology. Those decisions stay in this deterministic Manifold
//! authority layer.

use std::collections::BTreeSet;

use ed25519_dalek::{Signature, VerifyingKey};
use rusty_manifold_model::{DottedId, Revision, SchemaId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::peer_session::PRODUCT_WIFI_DIRECT_TOPOLOGY_CONTRACT;

/// Accepted enrollment state schema.
pub const PEER_ENROLLMENT_STATE_SCHEMA: &str = "rusty.manifold.peer.enrollment_state.v1";
/// Peer credential record schema.
pub const PEER_CREDENTIAL_SCHEMA: &str = "rusty.manifold.peer.credential_record.v1";
/// Enrollment mutation request schema.
pub const PEER_ENROLLMENT_REQUEST_SCHEMA: &str = "rusty.manifold.peer.enrollment_request.v1";
/// Enrollment application receipt schema.
pub const PEER_ENROLLMENT_RECEIPT_SCHEMA: &str = "rusty.manifold.peer.enrollment_receipt.v1";
/// Signed rendezvous evidence schema.
pub const SIGNED_RENDEZVOUS_EVIDENCE_SCHEMA: &str =
    "rusty.manifold.peer.signed_rendezvous_evidence.v1";
/// Rendezvous review request schema.
pub const RENDEZVOUS_REVIEW_REQUEST_SCHEMA: &str =
    "rusty.manifold.peer.rendezvous_review_request.v1";
/// Accepted rendezvous authority state schema.
pub const RENDEZVOUS_AUTHORITY_STATE_SCHEMA: &str =
    "rusty.manifold.peer.rendezvous_authority_state.v1";
/// Signed rendezvous decision receipt schema.
pub const RENDEZVOUS_RECEIPT_SCHEMA: &str = "rusty.manifold.peer.rendezvous_receipt.v1";
const MAX_ENROLLMENT_REQUEST_AGE_MS: u64 = 300_000;
const MAX_RENDEZVOUS_TTL_MS: u64 = 60_000;
const RENDEZVOUS_DOMAIN: &[u8] = b"rusty.manifold.peer.signed_rendezvous_evidence.v1\0";

/// Supported credential algorithm.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldPeerCredentialAlgorithm {
    /// RFC 8032 Ed25519 verification with strict weak-key rejection.
    Ed25519,
}

/// Credential lifecycle state owned by Manifold.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldPeerCredentialStatus {
    /// Current credential for new signed evidence.
    Active,
    /// Superseded by a later generation and no longer accepted.
    Rotated,
    /// Explicitly revoked and no longer accepted.
    Revoked,
}

/// Operator-enrolled public credential. Private key material is never stored.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPeerCredentialRecord {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Stable credential record id.
    pub credential_id: DottedId,
    /// Stable peer identity.
    pub peer_id: DottedId,
    /// Trust domain selected by the operator.
    pub trust_domain: DottedId,
    /// Stable key id, independent of platform/ADB identity.
    pub key_id: DottedId,
    /// Monotonic key generation for this peer.
    pub key_generation: u64,
    /// Verification algorithm.
    pub algorithm: ManifoldPeerCredentialAlgorithm,
    /// Canonical lowercase-hex Ed25519 public key.
    pub public_key_hex: String,
    /// Canonical `sha256:<lowercase hex>` digest of the public key bytes.
    pub public_key_sha256: String,
    /// Enrollment validity start.
    pub valid_from_ms: u64,
    /// Enrollment validity end.
    pub expires_at_ms: u64,
    /// Current lifecycle state.
    pub status: ManifoldPeerCredentialStatus,
    /// Replacement key id for a rotated record.
    pub replaced_by_key_id: Option<DottedId>,
}

/// Accepted operator-mediated enrollment state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPeerEnrollmentState {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Current enrollment authority revision.
    pub authority_revision: Revision,
    /// Credential records, sorted by peer/generation/key id after application.
    pub credentials: Vec<ManifoldPeerCredentialRecord>,
    /// Applied request ids retained for replay rejection.
    pub applied_request_ids: Vec<DottedId>,
}

impl ManifoldPeerEnrollmentState {
    /// Creates an empty revision-one enrollment authority.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            schema_id: schema(PEER_ENROLLMENT_STATE_SCHEMA),
            authority_revision: Revision::INITIAL,
            credentials: Vec::new(),
            applied_request_ids: Vec::new(),
        }
    }
}

/// Enrollment mutation selected by an operator route.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum ManifoldPeerEnrollmentAction {
    /// Enroll the first credential for a peer.
    Enroll {
        /// Proposed active credential.
        credential: ManifoldPeerCredentialRecord,
    },
    /// Replace one active credential with its next generation.
    Rotate {
        /// Current active key id.
        prior_key_id: DottedId,
        /// Proposed replacement credential.
        credential: ManifoldPeerCredentialRecord,
    },
    /// Revoke a current or historical credential.
    Revoke {
        /// Key being revoked.
        key_id: DottedId,
        /// Stable operator-selected reason id.
        reason_id: DottedId,
    },
}

/// Revision-bound operator enrollment request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPeerEnrollmentRequest {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Replay-protected request id.
    pub request_id: DottedId,
    /// Expected enrollment authority revision.
    pub expected_authority_revision: Revision,
    /// Operator route identity.
    pub operator_id: DottedId,
    /// Request creation time.
    pub issued_at_ms: u64,
    /// Requested mutation.
    #[serde(flatten)]
    pub action: ManifoldPeerEnrollmentAction,
}

/// Stable enrollment rejection reason.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldPeerEnrollmentRejectionReason {
    /// A schema id did not match the declared contract.
    SchemaMismatch,
    /// Request expected a different authority revision.
    StaleAuthorityRevision,
    /// Request id was already applied.
    ReplayedRequest,
    /// Operator route was not trusted.
    UntrustedOperator,
    /// Request timestamp was in the future or outside the bounded window.
    StaleRequest,
    /// Credential encoding, fingerprint, validity, or lifecycle was invalid.
    InvalidCredential,
    /// Peer already has an active credential.
    ActiveCredentialExists,
    /// Requested key was not found.
    CredentialNotFound,
    /// Requested key was not current and active.
    CredentialNotActive,
    /// Rotation changed peer/trust identity or skipped a key generation.
    InvalidRotation,
    /// Credential/key/peer identity collided with an existing record.
    IdentityCollision,
    /// Authority revision could not advance.
    RevisionExhausted,
    /// Supplied accepted state violated credential or replay invariants.
    InvalidAuthorityState,
}

/// Audit-bearing enrollment application receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPeerEnrollmentReceipt {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Derived receipt identity.
    pub receipt_id: DottedId,
    /// Reviewed request identity.
    pub request_id: DottedId,
    /// Operator route identity.
    pub operator_id: DottedId,
    /// Peer affected when it could be resolved.
    pub peer_id: Option<DottedId>,
    /// Key affected when it could be resolved.
    pub key_id: Option<DottedId>,
    /// Whether accepted state changed.
    pub applied: bool,
    /// Stable rejection reason when not applied.
    pub rejection_reason: Option<ManifoldPeerEnrollmentRejectionReason>,
    /// Prior authority revision.
    pub prior_authority_revision: Revision,
    /// Resulting authority revision.
    pub resulting_authority_revision: Revision,
}

/// Review and apply one enrollment mutation. Rejections leave state unchanged.
#[must_use]
pub fn review_and_apply_peer_enrollment(
    state: &ManifoldPeerEnrollmentState,
    request: &ManifoldPeerEnrollmentRequest,
    trusted_operator_ids: &[DottedId],
    now_ms: u64,
) -> (ManifoldPeerEnrollmentState, ManifoldPeerEnrollmentReceipt) {
    let prior = state.authority_revision;
    let identity = enrollment_action_identity(&request.action, state);
    let rejection = validate_enrollment_request(state, request, trusted_operator_ids, now_ms)
        .err()
        .or_else(|| {
            prior
                .next()
                .is_none()
                .then_some(ManifoldPeerEnrollmentRejectionReason::RevisionExhausted)
        });
    if let Some(reason) = rejection {
        return (
            state.clone(),
            enrollment_receipt(request, identity, false, Some(reason), prior, prior),
        );
    }

    let resulting_revision = prior.next().unwrap_or(prior);
    let mut next = state.clone();
    next.authority_revision = resulting_revision;
    match &request.action {
        ManifoldPeerEnrollmentAction::Enroll { credential } => {
            next.credentials.push(credential.clone());
        }
        ManifoldPeerEnrollmentAction::Rotate {
            prior_key_id,
            credential,
        } => {
            let Some(prior_record) = next
                .credentials
                .iter_mut()
                .find(|record| &record.key_id == prior_key_id)
            else {
                return (
                    state.clone(),
                    enrollment_receipt(
                        request,
                        identity,
                        false,
                        Some(ManifoldPeerEnrollmentRejectionReason::InvalidAuthorityState),
                        prior,
                        prior,
                    ),
                );
            };
            prior_record.status = ManifoldPeerCredentialStatus::Rotated;
            prior_record.replaced_by_key_id = Some(credential.key_id.clone());
            next.credentials.push(credential.clone());
        }
        ManifoldPeerEnrollmentAction::Revoke { key_id, .. } => {
            let Some(record) = next
                .credentials
                .iter_mut()
                .find(|record| &record.key_id == key_id)
            else {
                return (
                    state.clone(),
                    enrollment_receipt(
                        request,
                        identity,
                        false,
                        Some(ManifoldPeerEnrollmentRejectionReason::InvalidAuthorityState),
                        prior,
                        prior,
                    ),
                );
            };
            record.status = ManifoldPeerCredentialStatus::Revoked;
        }
    }
    next.credentials.sort_by(|left, right| {
        (&left.peer_id, left.key_generation, &left.key_id).cmp(&(
            &right.peer_id,
            right.key_generation,
            &right.key_id,
        ))
    });
    next.applied_request_ids.push(request.request_id.clone());
    (
        next,
        enrollment_receipt(request, identity, true, None, prior, resulting_revision),
    )
}

fn validate_enrollment_request(
    state: &ManifoldPeerEnrollmentState,
    request: &ManifoldPeerEnrollmentRequest,
    trusted_operator_ids: &[DottedId],
    now_ms: u64,
) -> Result<(), ManifoldPeerEnrollmentRejectionReason> {
    if state.schema_id.as_str() != PEER_ENROLLMENT_STATE_SCHEMA
        || request.schema_id.as_str() != PEER_ENROLLMENT_REQUEST_SCHEMA
    {
        return Err(ManifoldPeerEnrollmentRejectionReason::SchemaMismatch);
    }
    if !enrollment_state_is_well_formed(state) {
        return Err(ManifoldPeerEnrollmentRejectionReason::InvalidAuthorityState);
    }
    if request.expected_authority_revision != state.authority_revision {
        return Err(ManifoldPeerEnrollmentRejectionReason::StaleAuthorityRevision);
    }
    if state.applied_request_ids.contains(&request.request_id) {
        return Err(ManifoldPeerEnrollmentRejectionReason::ReplayedRequest);
    }
    if !trusted_operator_ids.contains(&request.operator_id) {
        return Err(ManifoldPeerEnrollmentRejectionReason::UntrustedOperator);
    }
    if request.issued_at_ms > now_ms
        || now_ms.saturating_sub(request.issued_at_ms) > MAX_ENROLLMENT_REQUEST_AGE_MS
    {
        return Err(ManifoldPeerEnrollmentRejectionReason::StaleRequest);
    }

    match &request.action {
        ManifoldPeerEnrollmentAction::Enroll { credential } => {
            validate_new_credential(credential, now_ms)?;
            if credential.key_generation != 1 {
                return Err(ManifoldPeerEnrollmentRejectionReason::InvalidCredential);
            }
            if state.credentials.iter().any(|record| {
                record.peer_id == credential.peer_id
                    && record.status == ManifoldPeerCredentialStatus::Active
            }) {
                return Err(ManifoldPeerEnrollmentRejectionReason::ActiveCredentialExists);
            }
            validate_identity_collision(state, credential)?;
        }
        ManifoldPeerEnrollmentAction::Rotate {
            prior_key_id,
            credential,
        } => {
            validate_new_credential(credential, now_ms)?;
            let prior = state
                .credentials
                .iter()
                .find(|record| &record.key_id == prior_key_id)
                .ok_or(ManifoldPeerEnrollmentRejectionReason::CredentialNotFound)?;
            if prior.status != ManifoldPeerCredentialStatus::Active {
                return Err(ManifoldPeerEnrollmentRejectionReason::CredentialNotActive);
            }
            if credential.peer_id != prior.peer_id
                || credential.trust_domain != prior.trust_domain
                || prior.key_generation.checked_add(1) != Some(credential.key_generation)
                || credential.key_id == prior.key_id
            {
                return Err(ManifoldPeerEnrollmentRejectionReason::InvalidRotation);
            }
            validate_identity_collision(state, credential)?;
        }
        ManifoldPeerEnrollmentAction::Revoke { key_id, .. } => {
            let record = state
                .credentials
                .iter()
                .find(|record| &record.key_id == key_id)
                .ok_or(ManifoldPeerEnrollmentRejectionReason::CredentialNotFound)?;
            if record.status == ManifoldPeerCredentialStatus::Revoked {
                return Err(ManifoldPeerEnrollmentRejectionReason::CredentialNotActive);
            }
        }
    }
    Ok(())
}

fn validate_new_credential(
    credential: &ManifoldPeerCredentialRecord,
    now_ms: u64,
) -> Result<(), ManifoldPeerEnrollmentRejectionReason> {
    if credential.schema_id.as_str() != PEER_CREDENTIAL_SCHEMA
        || credential.key_generation == 0
        || credential.status != ManifoldPeerCredentialStatus::Active
        || credential.replaced_by_key_id.is_some()
        || credential.valid_from_ms > now_ms
        || credential.expires_at_ms <= now_ms
        || credential.valid_from_ms >= credential.expires_at_ms
    {
        return Err(ManifoldPeerEnrollmentRejectionReason::InvalidCredential);
    }
    let public_key = decode_hex_array::<32>(&credential.public_key_hex)
        .ok_or(ManifoldPeerEnrollmentRejectionReason::InvalidCredential)?;
    let expected = format!("sha256:{}", encode_lower_hex(&Sha256::digest(public_key)));
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| ManifoldPeerEnrollmentRejectionReason::InvalidCredential)?;
    if credential.public_key_sha256 != expected || verifying_key.is_weak() {
        return Err(ManifoldPeerEnrollmentRejectionReason::InvalidCredential);
    }
    Ok(())
}

fn validate_identity_collision(
    state: &ManifoldPeerEnrollmentState,
    credential: &ManifoldPeerCredentialRecord,
) -> Result<(), ManifoldPeerEnrollmentRejectionReason> {
    if state.credentials.iter().any(|record| {
        record.credential_id == credential.credential_id
            || record.key_id == credential.key_id
            || record.public_key_sha256 == credential.public_key_sha256
    }) {
        Err(ManifoldPeerEnrollmentRejectionReason::IdentityCollision)
    } else {
        Ok(())
    }
}

fn enrollment_action_identity(
    action: &ManifoldPeerEnrollmentAction,
    state: &ManifoldPeerEnrollmentState,
) -> (Option<DottedId>, Option<DottedId>) {
    match action {
        ManifoldPeerEnrollmentAction::Enroll { credential }
        | ManifoldPeerEnrollmentAction::Rotate { credential, .. } => (
            Some(credential.peer_id.clone()),
            Some(credential.key_id.clone()),
        ),
        ManifoldPeerEnrollmentAction::Revoke { key_id, .. } => (
            state
                .credentials
                .iter()
                .find(|record| &record.key_id == key_id)
                .map(|record| record.peer_id.clone()),
            Some(key_id.clone()),
        ),
    }
}

fn enrollment_receipt(
    request: &ManifoldPeerEnrollmentRequest,
    identity: (Option<DottedId>, Option<DottedId>),
    applied: bool,
    rejection_reason: Option<ManifoldPeerEnrollmentRejectionReason>,
    prior_authority_revision: Revision,
    resulting_authority_revision: Revision,
) -> ManifoldPeerEnrollmentReceipt {
    ManifoldPeerEnrollmentReceipt {
        schema_id: schema(PEER_ENROLLMENT_RECEIPT_SCHEMA),
        receipt_id: derived("receipt.peer.enrollment", &request.request_id),
        request_id: request.request_id.clone(),
        operator_id: request.operator_id.clone(),
        peer_id: identity.0,
        key_id: identity.1,
        applied,
        rejection_reason,
        prior_authority_revision,
        resulting_authority_revision,
    }
}

/// Topology role proven by one signed rendezvous statement.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldRendezvousRole {
    /// Wi-Fi Direct group-owner candidate.
    GroupOwner,
    /// Wi-Fi Direct client candidate.
    Client,
}

/// One peer's signed rendezvous statement.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldSignedRendezvousEvidence {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Replay-protected evidence identity.
    pub evidence_id: DottedId,
    /// Signing peer.
    pub signer_peer_id: DottedId,
    /// Enrolled key used to sign.
    pub signer_key_id: DottedId,
    /// Other peer in the pair.
    pub counterparty_peer_id: DottedId,
    /// Canonical 32-byte lowercase-hex nonce shared by both statements.
    pub nonce_hex: String,
    /// Coordinator epoch the pair is proposing.
    pub coordinator_epoch: u64,
    /// Pair role claimed by this signer.
    pub role: ManifoldRendezvousRole,
    /// Exact topology contract proposed for later platform adoption.
    pub topology_contract_id: DottedId,
    /// Evidence creation time.
    pub issued_at_ms: u64,
    /// Evidence expiry time.
    pub expires_at_ms: u64,
    /// Canonical lowercase-hex Ed25519 signature over the domain-separated fields.
    pub signature_hex: String,
}

/// Revision-bound review of reciprocal signed pair evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldRendezvousReviewRequest {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Replay-protected request id.
    pub request_id: DottedId,
    /// Expected rendezvous authority revision.
    pub expected_authority_revision: Revision,
    /// Exact enrollment authority revision whose active keys may sign.
    pub expected_enrollment_authority_revision: Revision,
    /// First signed statement.
    pub first: ManifoldSignedRendezvousEvidence,
    /// Reciprocal signed statement.
    pub second: ManifoldSignedRendezvousEvidence,
}

/// Accepted rendezvous review state. It stores hashes, not adapter payloads.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldRendezvousAuthorityState {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Current authority revision.
    pub authority_revision: Revision,
    /// Applied review ids.
    pub applied_request_ids: Vec<DottedId>,
    /// Consumed signed evidence ids.
    pub consumed_evidence_ids: Vec<DottedId>,
    /// Consumed nonce digests.
    pub consumed_nonce_sha256: Vec<String>,
    /// Accepted receipts retained as authority provenance, sorted by id.
    pub accepted_receipts: Vec<ManifoldRendezvousReceipt>,
}

impl ManifoldRendezvousAuthorityState {
    /// Creates an empty revision-one rendezvous authority.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            schema_id: schema(RENDEZVOUS_AUTHORITY_STATE_SCHEMA),
            authority_revision: Revision::INITIAL,
            applied_request_ids: Vec::new(),
            consumed_evidence_ids: Vec::new(),
            consumed_nonce_sha256: Vec::new(),
            accepted_receipts: Vec::new(),
        }
    }
}

/// Stable signed-rendezvous rejection reason.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldRendezvousRejectionReason {
    /// A schema id did not match.
    SchemaMismatch,
    /// Request expected another authority revision.
    StaleAuthorityRevision,
    /// Request named a different enrollment authority revision.
    StaleEnrollmentAuthority,
    /// Request, evidence, or nonce was already consumed.
    Replay,
    /// Pair identities were duplicated, unknown, or not reciprocal.
    InvalidPair,
    /// Topology roles were not reciprocal.
    InvalidRoles,
    /// Epoch was absent or inconsistent.
    InvalidEpoch,
    /// Contract was absent, inconsistent, or outside policy.
    InvalidContract,
    /// Nonce/signature/key encoding was non-canonical.
    InvalidEncoding,
    /// Evidence timing or TTL was invalid.
    ExpiredEvidence,
    /// Key was unknown, rotated, revoked, not yet valid, or expired.
    CredentialNotCurrent,
    /// Credential did not belong to the claimed signer.
    CredentialIdentityMismatch,
    /// Signature failed strict Ed25519 verification.
    InvalidSignature,
    /// Authority revision could not advance.
    RevisionExhausted,
    /// Supplied accepted state violated provenance or replay invariants.
    InvalidAuthorityState,
}

/// Failure to consume a rendezvous receipt against current authority state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldRendezvousReceiptValidationError {
    /// State or receipt schema did not match.
    SchemaMismatch,
    /// Receipt was not retained exactly by accepted rendezvous state.
    ReceiptNotRetained,
    /// Enrollment or rendezvous authority has advanced.
    StaleAuthorityRevision,
    /// Receipt pair, roles, contract, digest, or validity was malformed.
    InvalidReceipt,
    /// One of the signing credentials is no longer current.
    CredentialNotCurrent,
}

/// Audit-bearing signed rendezvous receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldRendezvousReceipt {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Derived receipt id.
    pub receipt_id: DottedId,
    /// Reviewed request id.
    pub request_id: DottedId,
    /// Whether both signatures and all authority checks were accepted.
    pub accepted: bool,
    /// Stable rejection reason.
    pub rejection_reason: Option<ManifoldRendezvousRejectionReason>,
    /// Canonically sorted peer pair.
    pub peer_ids: Vec<DottedId>,
    /// Peer whose signature accepted the group-owner role.
    pub group_owner_peer_id: Option<DottedId>,
    /// Peer whose signature accepted the client role.
    pub client_peer_id: Option<DottedId>,
    /// Enrolled key ids that signed the evidence.
    pub signer_key_ids: Vec<DottedId>,
    /// Reviewed evidence ids.
    pub evidence_ids: Vec<DottedId>,
    /// SHA-256 digest of the consumed nonce.
    pub nonce_sha256: String,
    /// Accepted coordinator epoch.
    pub coordinator_epoch: u64,
    /// Accepted topology contract.
    pub topology_contract_id: DottedId,
    /// Enrollment revision whose current keys signed this receipt.
    pub enrollment_authority_revision: Revision,
    /// Prior authority revision.
    pub prior_authority_revision: Revision,
    /// Resulting authority revision.
    pub resulting_authority_revision: Revision,
    /// Receipt validity end, zero on early structural rejection.
    pub expires_at_ms: u64,
}

/// Review reciprocal signed evidence and consume it only when fully accepted.
#[must_use]
pub fn review_and_apply_signed_rendezvous(
    state: &ManifoldRendezvousAuthorityState,
    enrollment: &ManifoldPeerEnrollmentState,
    request: &ManifoldRendezvousReviewRequest,
    now_ms: u64,
) -> (ManifoldRendezvousAuthorityState, ManifoldRendezvousReceipt) {
    let prior = state.authority_revision;
    let nonce_sha256 = nonce_digest(&request.first.nonce_hex).unwrap_or_default();
    let rejection = validate_signed_rendezvous(state, enrollment, request, now_ms)
        .err()
        .or_else(|| {
            prior
                .next()
                .is_none()
                .then_some(ManifoldRendezvousRejectionReason::RevisionExhausted)
        });
    if let Some(reason) = rejection {
        return (
            state.clone(),
            rendezvous_receipt(
                request,
                enrollment.authority_revision,
                false,
                Some(reason),
                nonce_sha256,
                prior,
                prior,
            ),
        );
    }

    let resulting_revision = prior.next().unwrap_or(prior);
    let accepted_receipt = rendezvous_receipt(
        request,
        enrollment.authority_revision,
        true,
        None,
        nonce_sha256.clone(),
        prior,
        resulting_revision,
    );
    let mut next = state.clone();
    next.authority_revision = resulting_revision;
    next.applied_request_ids.push(request.request_id.clone());
    next.consumed_evidence_ids.extend([
        request.first.evidence_id.clone(),
        request.second.evidence_id.clone(),
    ]);
    next.consumed_evidence_ids.sort();
    next.consumed_nonce_sha256.push(nonce_sha256.clone());
    next.consumed_nonce_sha256.sort();
    next.accepted_receipts.push(accepted_receipt.clone());
    next.accepted_receipts
        .sort_by(|left, right| left.receipt_id.cmp(&right.receipt_id));
    (next, accepted_receipt)
}

fn validate_signed_rendezvous(
    state: &ManifoldRendezvousAuthorityState,
    enrollment: &ManifoldPeerEnrollmentState,
    request: &ManifoldRendezvousReviewRequest,
    now_ms: u64,
) -> Result<(), ManifoldRendezvousRejectionReason> {
    if state.schema_id.as_str() != RENDEZVOUS_AUTHORITY_STATE_SCHEMA
        || enrollment.schema_id.as_str() != PEER_ENROLLMENT_STATE_SCHEMA
        || request.schema_id.as_str() != RENDEZVOUS_REVIEW_REQUEST_SCHEMA
        || request.first.schema_id.as_str() != SIGNED_RENDEZVOUS_EVIDENCE_SCHEMA
        || request.second.schema_id.as_str() != SIGNED_RENDEZVOUS_EVIDENCE_SCHEMA
    {
        return Err(ManifoldRendezvousRejectionReason::SchemaMismatch);
    }
    if !enrollment_state_is_well_formed(enrollment) || !rendezvous_state_is_well_formed(state) {
        return Err(ManifoldRendezvousRejectionReason::InvalidAuthorityState);
    }
    if request.expected_authority_revision != state.authority_revision {
        return Err(ManifoldRendezvousRejectionReason::StaleAuthorityRevision);
    }
    if request.expected_enrollment_authority_revision != enrollment.authority_revision {
        return Err(ManifoldRendezvousRejectionReason::StaleEnrollmentAuthority);
    }
    let nonce_sha256 = nonce_digest(&request.first.nonce_hex).unwrap_or_default();
    if state.applied_request_ids.contains(&request.request_id)
        || state
            .consumed_evidence_ids
            .contains(&request.first.evidence_id)
        || state
            .consumed_evidence_ids
            .contains(&request.second.evidence_id)
        || (!nonce_sha256.is_empty() && state.consumed_nonce_sha256.contains(&nonce_sha256))
        || request.first.evidence_id == request.second.evidence_id
    {
        return Err(ManifoldRendezvousRejectionReason::Replay);
    }
    if request.first.signer_peer_id == request.second.signer_peer_id
        || request.first.signer_peer_id != request.second.counterparty_peer_id
        || request.second.signer_peer_id != request.first.counterparty_peer_id
    {
        return Err(ManifoldRendezvousRejectionReason::InvalidPair);
    }
    if !matches!(
        (&request.first.role, &request.second.role),
        (
            ManifoldRendezvousRole::GroupOwner,
            ManifoldRendezvousRole::Client
        ) | (
            ManifoldRendezvousRole::Client,
            ManifoldRendezvousRole::GroupOwner
        )
    ) {
        return Err(ManifoldRendezvousRejectionReason::InvalidRoles);
    }
    if request.first.coordinator_epoch == 0
        || request.first.coordinator_epoch != request.second.coordinator_epoch
    {
        return Err(ManifoldRendezvousRejectionReason::InvalidEpoch);
    }
    if request.first.topology_contract_id != request.second.topology_contract_id
        || request.first.topology_contract_id.as_str() != PRODUCT_WIFI_DIRECT_TOPOLOGY_CONTRACT
    {
        return Err(ManifoldRendezvousRejectionReason::InvalidContract);
    }
    if request.first.nonce_hex != request.second.nonce_hex
        || decode_hex_array::<32>(&request.first.nonce_hex).is_none()
    {
        return Err(ManifoldRendezvousRejectionReason::InvalidEncoding);
    }
    if request.first.issued_at_ms != request.second.issued_at_ms
        || request.first.expires_at_ms != request.second.expires_at_ms
        || request.first.issued_at_ms > now_ms
        || request.first.expires_at_ms <= now_ms
        || request.first.issued_at_ms >= request.first.expires_at_ms
        || request
            .first
            .expires_at_ms
            .saturating_sub(request.first.issued_at_ms)
            > MAX_RENDEZVOUS_TTL_MS
    {
        return Err(ManifoldRendezvousRejectionReason::ExpiredEvidence);
    }
    verify_signed_statement(enrollment, &request.first, now_ms)?;
    verify_signed_statement(enrollment, &request.second, now_ms)?;
    Ok(())
}

fn verify_signed_statement(
    enrollment: &ManifoldPeerEnrollmentState,
    evidence: &ManifoldSignedRendezvousEvidence,
    now_ms: u64,
) -> Result<(), ManifoldRendezvousRejectionReason> {
    let credential = enrollment
        .credentials
        .iter()
        .find(|record| record.key_id == evidence.signer_key_id)
        .ok_or(ManifoldRendezvousRejectionReason::CredentialNotCurrent)?;
    if credential.status != ManifoldPeerCredentialStatus::Active
        || credential.valid_from_ms > now_ms
        || credential.expires_at_ms <= now_ms
    {
        return Err(ManifoldRendezvousRejectionReason::CredentialNotCurrent);
    }
    if credential.peer_id != evidence.signer_peer_id {
        return Err(ManifoldRendezvousRejectionReason::CredentialIdentityMismatch);
    }
    let public_key = decode_hex_array::<32>(&credential.public_key_hex)
        .ok_or(ManifoldRendezvousRejectionReason::InvalidEncoding)?;
    let signature_bytes = decode_hex_array::<64>(&evidence.signature_hex)
        .ok_or(ManifoldRendezvousRejectionReason::InvalidEncoding)?;
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| ManifoldRendezvousRejectionReason::InvalidEncoding)?;
    if verifying_key.is_weak() {
        return Err(ManifoldRendezvousRejectionReason::CredentialNotCurrent);
    }
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify_strict(&rendezvous_signing_bytes(evidence), &signature)
        .map_err(|_| ManifoldRendezvousRejectionReason::InvalidSignature)
}

/// Validate that an accepted rendezvous receipt is exact, retained provenance
/// under the current authorities, and still backed by both active credentials.
///
/// # Errors
///
/// Returns a typed error when schema, provenance, revision, receipt shape, or
/// current credential checks fail.
pub fn validate_current_rendezvous_receipt(
    state: &ManifoldRendezvousAuthorityState,
    enrollment: &ManifoldPeerEnrollmentState,
    receipt: &ManifoldRendezvousReceipt,
    group_owner_peer_id: &DottedId,
    client_peer_id: &DottedId,
    now_ms: u64,
) -> Result<(), ManifoldRendezvousReceiptValidationError> {
    if state.schema_id.as_str() != RENDEZVOUS_AUTHORITY_STATE_SCHEMA
        || enrollment.schema_id.as_str() != PEER_ENROLLMENT_STATE_SCHEMA
        || receipt.schema_id.as_str() != RENDEZVOUS_RECEIPT_SCHEMA
    {
        return Err(ManifoldRendezvousReceiptValidationError::SchemaMismatch);
    }
    if !enrollment_state_is_well_formed(enrollment) || !rendezvous_state_is_well_formed(state) {
        return Err(ManifoldRendezvousReceiptValidationError::InvalidReceipt);
    }
    if !state
        .accepted_receipts
        .iter()
        .any(|accepted| accepted == receipt)
    {
        return Err(ManifoldRendezvousReceiptValidationError::ReceiptNotRetained);
    }
    let mut expected_peer_ids = vec![group_owner_peer_id.clone(), client_peer_id.clone()];
    expected_peer_ids.sort();
    let canonical_signer_keys = is_strictly_sorted_pair(&receipt.signer_key_ids);
    let canonical_evidence_ids = is_strictly_sorted_pair(&receipt.evidence_ids);
    if group_owner_peer_id == client_peer_id
        || !receipt.accepted
        || receipt.rejection_reason.is_some()
        || receipt.peer_ids != expected_peer_ids
        || receipt.group_owner_peer_id.as_ref() != Some(group_owner_peer_id)
        || receipt.client_peer_id.as_ref() != Some(client_peer_id)
        || !canonical_signer_keys
        || !canonical_evidence_ids
        || !is_canonical_sha256(&receipt.nonce_sha256)
        || receipt.coordinator_epoch == 0
        || receipt.topology_contract_id.as_str() != PRODUCT_WIFI_DIRECT_TOPOLOGY_CONTRACT
        || receipt.expires_at_ms <= now_ms
    {
        return Err(ManifoldRendezvousReceiptValidationError::InvalidReceipt);
    }

    let mut expected_key_ids = Vec::with_capacity(2);
    for peer_id in [group_owner_peer_id, client_peer_id] {
        let credential = enrollment
            .credentials
            .iter()
            .find(|credential| {
                &credential.peer_id == peer_id
                    && credential.status == ManifoldPeerCredentialStatus::Active
                    && credential.valid_from_ms <= now_ms
                    && credential.expires_at_ms > now_ms
            })
            .ok_or(ManifoldRendezvousReceiptValidationError::CredentialNotCurrent)?;
        expected_key_ids.push(credential.key_id.clone());
    }
    expected_key_ids.sort();
    if receipt.signer_key_ids != expected_key_ids {
        return Err(ManifoldRendezvousReceiptValidationError::CredentialNotCurrent);
    }
    Ok(())
}

/// Canonical domain-separated bytes signed by a rendezvous peer.
///
/// The signature field itself is deliberately excluded. Every string is
/// length-prefixed, which makes concatenation unambiguous without depending on
/// JSON key order or serializer behavior.
#[must_use]
pub fn rendezvous_signing_bytes(evidence: &ManifoldSignedRendezvousEvidence) -> Vec<u8> {
    let mut output = RENDEZVOUS_DOMAIN.to_vec();
    for value in [
        evidence.evidence_id.as_str(),
        evidence.signer_peer_id.as_str(),
        evidence.signer_key_id.as_str(),
        evidence.counterparty_peer_id.as_str(),
        evidence.nonce_hex.as_str(),
        match evidence.role {
            ManifoldRendezvousRole::GroupOwner => "group_owner",
            ManifoldRendezvousRole::Client => "client",
        },
        evidence.topology_contract_id.as_str(),
    ] {
        append_field(&mut output, value.as_bytes());
    }
    output.extend_from_slice(&evidence.coordinator_epoch.to_be_bytes());
    output.extend_from_slice(&evidence.issued_at_ms.to_be_bytes());
    output.extend_from_slice(&evidence.expires_at_ms.to_be_bytes());
    output
}

fn rendezvous_receipt(
    request: &ManifoldRendezvousReviewRequest,
    enrollment_authority_revision: Revision,
    accepted: bool,
    rejection_reason: Option<ManifoldRendezvousRejectionReason>,
    nonce_sha256: String,
    prior_authority_revision: Revision,
    resulting_authority_revision: Revision,
) -> ManifoldRendezvousReceipt {
    let mut peer_ids = vec![
        request.first.signer_peer_id.clone(),
        request.second.signer_peer_id.clone(),
    ];
    peer_ids.sort();
    let mut signer_key_ids = vec![
        request.first.signer_key_id.clone(),
        request.second.signer_key_id.clone(),
    ];
    signer_key_ids.sort();
    let mut evidence_ids = vec![
        request.first.evidence_id.clone(),
        request.second.evidence_id.clone(),
    ];
    evidence_ids.sort();
    let group_owner_peer_id = [request.first.clone(), request.second.clone()]
        .into_iter()
        .find(|evidence| evidence.role == ManifoldRendezvousRole::GroupOwner)
        .map(|evidence| evidence.signer_peer_id);
    let client_peer_id = [request.first.clone(), request.second.clone()]
        .into_iter()
        .find(|evidence| evidence.role == ManifoldRendezvousRole::Client)
        .map(|evidence| evidence.signer_peer_id);
    ManifoldRendezvousReceipt {
        schema_id: schema(RENDEZVOUS_RECEIPT_SCHEMA),
        receipt_id: derived("receipt.peer.rendezvous", &request.request_id),
        request_id: request.request_id.clone(),
        accepted,
        rejection_reason,
        peer_ids,
        group_owner_peer_id,
        client_peer_id,
        signer_key_ids,
        evidence_ids,
        nonce_sha256,
        coordinator_epoch: request.first.coordinator_epoch,
        topology_contract_id: request.first.topology_contract_id.clone(),
        enrollment_authority_revision,
        prior_authority_revision,
        resulting_authority_revision,
        expires_at_ms: if accepted {
            request.first.expires_at_ms
        } else {
            0
        },
    }
}

fn nonce_digest(nonce_hex: &str) -> Option<String> {
    let nonce = decode_hex_array::<32>(nonce_hex)?;
    Some(format!(
        "sha256:{}",
        encode_lower_hex(&Sha256::digest(nonce))
    ))
}

/// Validates the complete enrollment snapshot, including strict Ed25519 key,
/// fingerprint, generation, replacement-chain, and active-key invariants.
#[must_use]
pub fn enrollment_state_is_well_formed(state: &ManifoldPeerEnrollmentState) -> bool {
    let mut credential_ids = BTreeSet::new();
    let mut key_ids = BTreeSet::new();
    let mut fingerprints = BTreeSet::new();
    let mut peer_generations = BTreeSet::new();
    let mut active_peers = BTreeSet::new();
    let unique_requests = state.applied_request_ids.iter().collect::<BTreeSet<_>>();
    if unique_requests.len() != state.applied_request_ids.len() {
        return false;
    }
    for credential in &state.credentials {
        let Some(public_key) = decode_hex_array::<32>(&credential.public_key_hex) else {
            return false;
        };
        let Ok(verifying_key) = VerifyingKey::from_bytes(&public_key) else {
            return false;
        };
        let expected_fingerprint =
            format!("sha256:{}", encode_lower_hex(&Sha256::digest(public_key)));
        if credential.schema_id.as_str() != PEER_CREDENTIAL_SCHEMA
            || credential.key_generation == 0
            || credential.valid_from_ms >= credential.expires_at_ms
            || verifying_key.is_weak()
            || credential.public_key_sha256 != expected_fingerprint
            || !credential_ids.insert(&credential.credential_id)
            || !key_ids.insert(&credential.key_id)
            || !fingerprints.insert(&credential.public_key_sha256)
            || !peer_generations.insert((&credential.peer_id, credential.key_generation))
            || (credential.status == ManifoldPeerCredentialStatus::Active
                && (credential.replaced_by_key_id.is_some()
                    || !active_peers.insert(&credential.peer_id)))
            || (credential.status == ManifoldPeerCredentialStatus::Rotated
                && credential.replaced_by_key_id.is_none())
            || (credential.status == ManifoldPeerCredentialStatus::Revoked
                && credential.replaced_by_key_id.is_some())
        {
            return false;
        }
    }
    state.credentials.iter().all(|credential| {
        let Some(replacement_id) = credential.replaced_by_key_id.as_ref() else {
            return true;
        };
        let Some(replacement) = state
            .credentials
            .iter()
            .find(|candidate| &candidate.key_id == replacement_id)
        else {
            return false;
        };
        credential.status == ManifoldPeerCredentialStatus::Rotated
            && replacement.peer_id == credential.peer_id
            && replacement.trust_domain == credential.trust_domain
            && credential.key_generation.checked_add(1) == Some(replacement.key_generation)
            && replacement.valid_from_ms >= credential.valid_from_ms
    })
}

fn rendezvous_state_is_well_formed(state: &ManifoldRendezvousAuthorityState) -> bool {
    let unique_requests = state.applied_request_ids.iter().collect::<BTreeSet<_>>();
    let unique_evidence = state.consumed_evidence_ids.iter().collect::<BTreeSet<_>>();
    let unique_nonces = state.consumed_nonce_sha256.iter().collect::<BTreeSet<_>>();
    let receipt_ids = state
        .accepted_receipts
        .iter()
        .map(|receipt| &receipt.receipt_id)
        .collect::<BTreeSet<_>>();
    unique_requests.len() == state.applied_request_ids.len()
        && unique_evidence.len() == state.consumed_evidence_ids.len()
        && unique_nonces.len() == state.consumed_nonce_sha256.len()
        && state
            .consumed_nonce_sha256
            .iter()
            .all(|digest| is_canonical_sha256(digest))
        && receipt_ids.len() == state.accepted_receipts.len()
        && state.accepted_receipts.iter().all(|receipt| {
            receipt.schema_id.as_str() == RENDEZVOUS_RECEIPT_SCHEMA
                && receipt.accepted
                && receipt.rejection_reason.is_none()
                && state.applied_request_ids.contains(&receipt.request_id)
                && receipt
                    .evidence_ids
                    .iter()
                    .all(|id| state.consumed_evidence_ids.contains(id))
                && state.consumed_nonce_sha256.contains(&receipt.nonce_sha256)
        })
}

fn is_strictly_sorted_pair(values: &[DottedId]) -> bool {
    values.len() == 2 && values[0] < values[1]
}

fn is_canonical_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value.as_bytes()[7..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn append_field(output: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("bounded rendezvous field length");
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
}

fn decode_hex_array<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2
        || value
            .as_bytes()
            .iter()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(byte))
    {
        return None;
    }
    let mut output = [0_u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Some(output)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
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

fn schema(value: &str) -> SchemaId {
    SchemaId::new(value).expect("static enrollment schema")
}

fn derived(prefix: &str, suffix: &DottedId) -> DottedId {
    DottedId::new(format!("{prefix}.{}", suffix.as_str())).expect("derived enrollment id")
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    fn id(value: &str) -> DottedId {
        DottedId::new(value).expect("test id")
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn credential(
        peer_id: &str,
        key_id: &str,
        generation: u64,
        signing_key: &SigningKey,
    ) -> ManifoldPeerCredentialRecord {
        let public_key = signing_key.verifying_key().to_bytes();
        ManifoldPeerCredentialRecord {
            schema_id: schema(PEER_CREDENTIAL_SCHEMA),
            credential_id: id(&format!("credential.{peer_id}.{generation}")),
            peer_id: id(peer_id),
            trust_domain: id("trust.morphospace.peer"),
            key_id: id(key_id),
            key_generation: generation,
            algorithm: ManifoldPeerCredentialAlgorithm::Ed25519,
            public_key_hex: encode_lower_hex(&public_key),
            public_key_sha256: format!("sha256:{}", encode_lower_hex(&Sha256::digest(public_key))),
            valid_from_ms: 1_000,
            expires_at_ms: 100_000,
            status: ManifoldPeerCredentialStatus::Active,
            replaced_by_key_id: None,
        }
    }

    fn enrollment_request(
        request_id: &str,
        revision: Revision,
        action: ManifoldPeerEnrollmentAction,
    ) -> ManifoldPeerEnrollmentRequest {
        ManifoldPeerEnrollmentRequest {
            schema_id: schema(PEER_ENROLLMENT_REQUEST_SCHEMA),
            request_id: id(request_id),
            expected_authority_revision: revision,
            operator_id: id("operator.peer.enrollment"),
            issued_at_ms: 1_000,
            action,
        }
    }

    fn enrolled_pair() -> (ManifoldPeerEnrollmentState, SigningKey, SigningKey) {
        let alpha_key = key(7);
        let beta_key = key(11);
        let trusted = [id("operator.peer.enrollment")];
        let (state, alpha) = review_and_apply_peer_enrollment(
            &ManifoldPeerEnrollmentState::empty(),
            &enrollment_request(
                "request.enroll.alpha.001",
                Revision::INITIAL,
                ManifoldPeerEnrollmentAction::Enroll {
                    credential: credential("peer.alpha", "key.peer.alpha.001", 1, &alpha_key),
                },
            ),
            &trusted,
            2_000,
        );
        assert!(alpha.applied);
        let revision = state.authority_revision;
        let (state, beta) = review_and_apply_peer_enrollment(
            &state,
            &enrollment_request(
                "request.enroll.beta.001",
                revision,
                ManifoldPeerEnrollmentAction::Enroll {
                    credential: credential("peer.beta", "key.peer.beta.001", 1, &beta_key),
                },
            ),
            &trusted,
            2_000,
        );
        assert!(beta.applied);
        (state, alpha_key, beta_key)
    }

    fn evidence(
        evidence_id: &str,
        signer_peer_id: &str,
        signer_key_id: &str,
        counterparty_peer_id: &str,
        role: ManifoldRendezvousRole,
        signing_key: &SigningKey,
    ) -> ManifoldSignedRendezvousEvidence {
        let mut value = ManifoldSignedRendezvousEvidence {
            schema_id: schema(SIGNED_RENDEZVOUS_EVIDENCE_SCHEMA),
            evidence_id: id(evidence_id),
            signer_peer_id: id(signer_peer_id),
            signer_key_id: id(signer_key_id),
            counterparty_peer_id: id(counterparty_peer_id),
            nonce_hex: "ab".repeat(32),
            coordinator_epoch: 9,
            role,
            topology_contract_id: id(PRODUCT_WIFI_DIRECT_TOPOLOGY_CONTRACT),
            issued_at_ms: 2_000,
            expires_at_ms: 32_000,
            signature_hex: String::new(),
        };
        value.signature_hex = encode_lower_hex(
            &signing_key
                .sign(&rendezvous_signing_bytes(&value))
                .to_bytes(),
        );
        value
    }

    fn review_request(
        request_id: &str,
        revision: Revision,
        alpha_key: &SigningKey,
        beta_key: &SigningKey,
    ) -> ManifoldRendezvousReviewRequest {
        ManifoldRendezvousReviewRequest {
            schema_id: schema(RENDEZVOUS_REVIEW_REQUEST_SCHEMA),
            request_id: id(request_id),
            expected_authority_revision: revision,
            expected_enrollment_authority_revision: Revision::new(3).expect("revision"),
            first: evidence(
                "evidence.rendezvous.alpha.001",
                "peer.alpha",
                "key.peer.alpha.001",
                "peer.beta",
                ManifoldRendezvousRole::GroupOwner,
                alpha_key,
            ),
            second: evidence(
                "evidence.rendezvous.beta.001",
                "peer.beta",
                "key.peer.beta.001",
                "peer.alpha",
                ManifoldRendezvousRole::Client,
                beta_key,
            ),
        }
    }

    fn resign(value: &mut ManifoldSignedRendezvousEvidence, signing_key: &SigningKey) {
        value.signature_hex = encode_lower_hex(
            &signing_key
                .sign(&rendezvous_signing_bytes(value))
                .to_bytes(),
        );
    }

    #[test]
    fn operator_enrollment_and_reciprocal_signatures_advance_authority() {
        let (enrollment, alpha_key, beta_key) = enrolled_pair();
        let state = ManifoldRendezvousAuthorityState::empty();
        let request = review_request(
            "request.rendezvous.alpha-beta.001",
            state.authority_revision,
            &alpha_key,
            &beta_key,
        );
        let (accepted, receipt) =
            review_and_apply_signed_rendezvous(&state, &enrollment, &request, 3_000);
        assert!(receipt.accepted);
        assert_eq!(accepted.authority_revision.get(), 2);
        assert_eq!(receipt.peer_ids, [id("peer.alpha"), id("peer.beta")]);
        assert_eq!(receipt.coordinator_epoch, 9);
        assert_eq!(receipt.expires_at_ms, 32_000);

        let mut replay = request;
        replay.request_id = id("request.rendezvous.alpha-beta.replay");
        replay.expected_authority_revision = accepted.authority_revision;
        let (unchanged, rejected) =
            review_and_apply_signed_rendezvous(&accepted, &enrollment, &replay, 3_100);
        assert_eq!(unchanged, accepted);
        assert_eq!(
            rejected.rejection_reason,
            Some(ManifoldRendezvousRejectionReason::Replay)
        );
    }

    #[test]
    fn key_rotation_and_revocation_fail_closed_for_signed_evidence() {
        let (enrollment, alpha_key, beta_key) = enrolled_pair();
        let next_alpha_key = key(19);
        let trusted = [id("operator.peer.enrollment")];
        let revision = enrollment.authority_revision;
        let (rotated, rotation) = review_and_apply_peer_enrollment(
            &enrollment,
            &enrollment_request(
                "request.rotate.alpha.002",
                revision,
                ManifoldPeerEnrollmentAction::Rotate {
                    prior_key_id: id("key.peer.alpha.001"),
                    credential: credential("peer.alpha", "key.peer.alpha.002", 2, &next_alpha_key),
                },
            ),
            &trusted,
            3_000,
        );
        assert!(rotation.applied);

        let mut old_request = review_request(
            "request.rendezvous.old-key",
            Revision::INITIAL,
            &alpha_key,
            &beta_key,
        );
        old_request.expected_enrollment_authority_revision = rotated.authority_revision;
        let (_, old_rejection) = review_and_apply_signed_rendezvous(
            &ManifoldRendezvousAuthorityState::empty(),
            &rotated,
            &old_request,
            3_000,
        );
        assert_eq!(
            old_rejection.rejection_reason,
            Some(ManifoldRendezvousRejectionReason::CredentialNotCurrent)
        );

        let mut current_request = review_request(
            "request.rendezvous.current-key",
            Revision::INITIAL,
            &next_alpha_key,
            &beta_key,
        );
        current_request.expected_enrollment_authority_revision = rotated.authority_revision;
        current_request.first.signer_key_id = id("key.peer.alpha.002");
        resign(&mut current_request.first, &next_alpha_key);
        let (_, current_receipt) = review_and_apply_signed_rendezvous(
            &ManifoldRendezvousAuthorityState::empty(),
            &rotated,
            &current_request,
            3_000,
        );
        assert!(current_receipt.accepted);

        let revision = rotated.authority_revision;
        let (revoked, revocation) = review_and_apply_peer_enrollment(
            &rotated,
            &enrollment_request(
                "request.revoke.alpha.002",
                revision,
                ManifoldPeerEnrollmentAction::Revoke {
                    key_id: id("key.peer.alpha.002"),
                    reason_id: id("reason.operator.compromise"),
                },
            ),
            &trusted,
            4_000,
        );
        assert!(revocation.applied);
        current_request.expected_enrollment_authority_revision = revoked.authority_revision;
        let (_, revoked_rejection) = review_and_apply_signed_rendezvous(
            &ManifoldRendezvousAuthorityState::empty(),
            &revoked,
            &current_request,
            4_000,
        );
        assert_eq!(
            revoked_rejection.rejection_reason,
            Some(ManifoldRendezvousRejectionReason::CredentialNotCurrent)
        );
    }

    #[test]
    fn damaged_signature_timing_roles_contract_and_unenrolled_peer_reject() {
        let (enrollment, alpha_key, beta_key) = enrolled_pair();
        let baseline = review_request(
            "request.rendezvous.damage",
            Revision::INITIAL,
            &alpha_key,
            &beta_key,
        );
        let cases = [
            {
                let mut value = baseline.clone();
                value.first.signature_hex.replace_range(0..2, "00");
                (
                    value,
                    ManifoldRendezvousRejectionReason::InvalidSignature,
                    3_000,
                )
            },
            {
                let mut value = baseline.clone();
                value.first.role = ManifoldRendezvousRole::Client;
                resign(&mut value.first, &alpha_key);
                (
                    value,
                    ManifoldRendezvousRejectionReason::InvalidRoles,
                    3_000,
                )
            },
            {
                let mut value = baseline.clone();
                value.second.topology_contract_id = id("rusty.quest.other_topology.v1");
                resign(&mut value.second, &beta_key);
                (
                    value,
                    ManifoldRendezvousRejectionReason::InvalidContract,
                    3_000,
                )
            },
            {
                let mut value = baseline.clone();
                value.first.expires_at_ms = 3_000;
                value.second.expires_at_ms = 3_000;
                resign(&mut value.first, &alpha_key);
                resign(&mut value.second, &beta_key);
                (
                    value,
                    ManifoldRendezvousRejectionReason::ExpiredEvidence,
                    3_000,
                )
            },
            {
                let mut value = baseline;
                value.second.signer_peer_id = id("peer.gamma");
                value.first.counterparty_peer_id = id("peer.gamma");
                resign(&mut value.first, &alpha_key);
                resign(&mut value.second, &beta_key);
                (
                    value,
                    ManifoldRendezvousRejectionReason::CredentialIdentityMismatch,
                    3_000,
                )
            },
        ];
        for (request, expected, now_ms) in cases {
            let state = ManifoldRendezvousAuthorityState::empty();
            let (unchanged, receipt) =
                review_and_apply_signed_rendezvous(&state, &enrollment, &request, now_ms);
            assert_eq!(unchanged, state);
            assert_eq!(receipt.rejection_reason, Some(expected));
        }
    }

    #[test]
    fn enrollment_rejects_untrusted_stale_colliding_and_noncanonical_keys() {
        let signing_key = key(31);
        let credential = credential("peer.alpha", "key.peer.alpha.001", 1, &signing_key);
        let request = enrollment_request(
            "request.enroll.alpha.damage",
            Revision::INITIAL,
            ManifoldPeerEnrollmentAction::Enroll {
                credential: credential.clone(),
            },
        );
        let state = ManifoldPeerEnrollmentState::empty();
        let (_, untrusted) = review_and_apply_peer_enrollment(&state, &request, &[], 2_000);
        assert_eq!(
            untrusted.rejection_reason,
            Some(ManifoldPeerEnrollmentRejectionReason::UntrustedOperator)
        );

        let trusted = [id("operator.peer.enrollment")];
        let (accepted, receipt) =
            review_and_apply_peer_enrollment(&state, &request, &trusted, 2_000);
        assert!(receipt.applied);
        let mut collision = request;
        collision.request_id = id("request.enroll.collision");
        collision.expected_authority_revision = accepted.authority_revision;
        let (_, collision_receipt) =
            review_and_apply_peer_enrollment(&accepted, &collision, &trusted, 2_000);
        assert_eq!(
            collision_receipt.rejection_reason,
            Some(ManifoldPeerEnrollmentRejectionReason::ActiveCredentialExists)
        );

        let mut bad_credential = credential;
        bad_credential.peer_id = id("peer.beta");
        bad_credential.key_id = id("key.peer.beta.001");
        bad_credential.credential_id = id("credential.peer.beta.1");
        bad_credential.public_key_hex.make_ascii_uppercase();
        let bad_request = enrollment_request(
            "request.enroll.noncanonical",
            accepted.authority_revision,
            ManifoldPeerEnrollmentAction::Enroll {
                credential: bad_credential,
            },
        );
        let (_, bad_receipt) =
            review_and_apply_peer_enrollment(&accepted, &bad_request, &trusted, 2_000);
        assert_eq!(
            bad_receipt.rejection_reason,
            Some(ManifoldPeerEnrollmentRejectionReason::InvalidCredential)
        );
    }

    #[test]
    fn weak_keys_and_generation_overflow_reject_without_state_change() {
        let trusted = [id("operator.peer.enrollment")];
        let weak_public_key = {
            let mut bytes = [0_u8; 32];
            bytes[0] = 1;
            bytes
        };
        let verifying_key = VerifyingKey::from_bytes(&weak_public_key).expect("encoded weak key");
        assert!(verifying_key.is_weak());
        let mut weak = credential("peer.weak", "key.peer.weak.001", 1, &key(29));
        weak.public_key_hex = encode_lower_hex(&weak_public_key);
        weak.public_key_sha256 = format!(
            "sha256:{}",
            encode_lower_hex(&Sha256::digest(weak_public_key))
        );
        let empty = ManifoldPeerEnrollmentState::empty();
        let (unchanged, receipt) = review_and_apply_peer_enrollment(
            &empty,
            &enrollment_request(
                "request.enroll.weak",
                empty.authority_revision,
                ManifoldPeerEnrollmentAction::Enroll { credential: weak },
            ),
            &trusted,
            2_000,
        );
        assert_eq!(unchanged, empty);
        assert_eq!(
            receipt.rejection_reason,
            Some(ManifoldPeerEnrollmentRejectionReason::InvalidCredential)
        );

        let prior_key = key(31);
        let mut prior = credential("peer.alpha", "key.peer.alpha.max", u64::MAX, &prior_key);
        prior.credential_id = id("credential.peer.alpha.max");
        let state = ManifoldPeerEnrollmentState {
            schema_id: schema(PEER_ENROLLMENT_STATE_SCHEMA),
            authority_revision: Revision::new(2).expect("revision"),
            credentials: vec![prior],
            applied_request_ids: Vec::new(),
        };
        let mut replacement =
            credential("peer.alpha", "key.peer.alpha.after-max", u64::MAX, &key(37));
        replacement.credential_id = id("credential.peer.alpha.after-max");
        let (unchanged, receipt) = review_and_apply_peer_enrollment(
            &state,
            &enrollment_request(
                "request.rotate.alpha.after-max",
                state.authority_revision,
                ManifoldPeerEnrollmentAction::Rotate {
                    prior_key_id: id("key.peer.alpha.max"),
                    credential: replacement,
                },
            ),
            &trusted,
            2_000,
        );
        assert_eq!(unchanged, state);
        assert_eq!(
            receipt.rejection_reason,
            Some(ManifoldPeerEnrollmentRejectionReason::InvalidRotation)
        );
    }

    #[test]
    fn nonce_digest_hashes_nonce_bytes_and_receipt_requires_current_provenance() {
        let (enrollment, alpha_key, beta_key) = enrolled_pair();
        let state = ManifoldRendezvousAuthorityState::empty();
        let request = review_request(
            "request.rendezvous.digest",
            state.authority_revision,
            &alpha_key,
            &beta_key,
        );
        let (accepted, receipt) =
            review_and_apply_signed_rendezvous(&state, &enrollment, &request, 3_000);
        let expected = format!(
            "sha256:{}",
            encode_lower_hex(&Sha256::digest([0xab_u8; 32]))
        );
        let ascii_hex_digest = format!(
            "sha256:{}",
            encode_lower_hex(&Sha256::digest("ab".repeat(32).as_bytes()))
        );
        assert_eq!(receipt.nonce_sha256, expected);
        assert_ne!(receipt.nonce_sha256, ascii_hex_digest);
        validate_current_rendezvous_receipt(
            &accepted,
            &enrollment,
            &receipt,
            &id("peer.alpha"),
            &id("peer.beta"),
            3_000,
        )
        .expect("current retained receipt");

        let mut unretained = accepted.clone();
        unretained.accepted_receipts.clear();
        assert_eq!(
            validate_current_rendezvous_receipt(
                &unretained,
                &enrollment,
                &receipt,
                &id("peer.alpha"),
                &id("peer.beta"),
                3_000,
            ),
            Err(ManifoldRendezvousReceiptValidationError::ReceiptNotRetained)
        );

        let trusted = [id("operator.peer.enrollment")];
        let (rotated, _) = review_and_apply_peer_enrollment(
            &enrollment,
            &enrollment_request(
                "request.rotate.alpha.provenance",
                enrollment.authority_revision,
                ManifoldPeerEnrollmentAction::Rotate {
                    prior_key_id: id("key.peer.alpha.001"),
                    credential: credential("peer.alpha", "key.peer.alpha.002", 2, &key(41)),
                },
            ),
            &trusted,
            3_100,
        );
        assert_eq!(
            validate_current_rendezvous_receipt(
                &accepted,
                &rotated,
                &receipt,
                &id("peer.alpha"),
                &id("peer.beta"),
                3_100,
            ),
            Err(ManifoldRendezvousReceiptValidationError::CredentialNotCurrent)
        );
    }

    #[test]
    fn rendezvous_review_binds_exact_enrollment_revision() {
        let (enrollment, alpha_key, beta_key) = enrolled_pair();
        let state = ManifoldRendezvousAuthorityState::empty();
        let mut request = review_request(
            "request.rendezvous.stale-enrollment",
            state.authority_revision,
            &alpha_key,
            &beta_key,
        );
        request.expected_enrollment_authority_revision = Revision::new(2).expect("revision");
        let (unchanged, receipt) =
            review_and_apply_signed_rendezvous(&state, &enrollment, &request, 3_000);
        assert_eq!(unchanged, state);
        assert_eq!(
            receipt.rejection_reason,
            Some(ManifoldRendezvousRejectionReason::StaleEnrollmentAuthority)
        );
    }

    #[test]
    fn contracts_remain_low_rate_and_private_key_free() {
        let (enrollment, alpha_key, beta_key) = enrolled_pair();
        let request = review_request(
            "request.rendezvous.shape",
            Revision::INITIAL,
            &alpha_key,
            &beta_key,
        );
        let text = serde_json::to_string(&(enrollment, request)).expect("serialize contracts");
        assert!(!text.contains("private_key"));
        assert!(!text.contains("media_payload"));
        assert!(!text.contains("command_text"));
        assert!(!text.contains("adb"));
    }
}
