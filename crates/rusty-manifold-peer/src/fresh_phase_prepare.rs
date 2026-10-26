//! Explicit initial-enrollment preparation; never expired ordinary request replay.
use crate::*;
use ed25519_dalek::{Signature, VerifyingKey};
use rusty_manifold_model::{DottedId, Revision, SchemaId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldFreshPairSetupEnrollmentKey {
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    pub peer_id: DottedId,
    pub credential_id: DottedId,
    pub trust_domain: DottedId,
    pub key_id: DottedId,
    pub key_generation: u64,
    pub algorithm: ManifoldPeerCredentialAlgorithm,
    pub public_key_hex: String,
    pub public_key_sha256: String,
    pub key_fingerprint: DottedId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldFreshPairSetupEnrollmentSelection {
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    pub operator_id: DottedId,
    pub keys: Vec<ManifoldFreshPairSetupEnrollmentKey>,
}

impl ManifoldFreshPairSetupEnrollmentKey {
    /// Validity is derived by the owning new transaction at actual apply.
    pub fn credential(&self, now: u64, expires: u64) -> ManifoldPeerCredentialRecord {
        ManifoldPeerCredentialRecord {
            schema_id: SchemaId::new(crate::PEER_CREDENTIAL_SCHEMA).expect("literal schema"),
            credential_id: self.credential_id.clone(),
            peer_id: self.peer_id.clone(),
            trust_domain: self.trust_domain.clone(),
            key_id: self.key_id.clone(),
            key_generation: self.key_generation,
            algorithm: self.algorithm.clone(),
            public_key_hex: self.public_key_hex.clone(),
            public_key_sha256: self.public_key_sha256.clone(),
            valid_from_ms: now,
            expires_at_ms: expires,
            status: ManifoldPeerCredentialStatus::Active,
            replaced_by_key_id: None,
        }
    }
    pub fn matches(&self, key: &ManifoldPeerCredentialRecord) -> bool {
        self.credential(key.valid_from_ms, key.expires_at_ms) == *key
    }
}

fn hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut out = [0; N];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

pub fn fresh_setup_enrollment_selection_is_well_formed(
    s: &ManifoldFreshPairSetupEnrollmentSelection,
) -> bool {
    s.schema_id.as_str() == "rusty.manifold.peer.fresh_setup_enrollment_selection.v1"
        && s.keys.len() == 2
        && s.keys[0].peer_id < s.keys[1].peer_id
        && s.keys[0].credential_id != s.keys[1].credential_id
        && s.keys[0].key_id != s.keys[1].key_id
        && s.keys[0].public_key_sha256 != s.keys[1].public_key_sha256
        && s.keys.iter().all(|k| {
            let Some(public) = hex::<32>(&k.public_key_hex) else {
                return false;
            };
            let hash = format!("{:x}", Sha256::digest(public));
            k.schema_id.as_str() == "rusty.manifold.peer.fresh_setup_enrollment_key.v1"
                && k.key_generation == 1
                && k.algorithm == ManifoldPeerCredentialAlgorithm::Ed25519
                && k.public_key_sha256 == format!("sha256:{hash}")
                && k.key_fingerprint.as_str() == format!("fingerprint.{hash}")
                && VerifyingKey::from_bytes(&public).is_ok_and(|key| !key.is_weak())
        })
}

/// Exact outcome retained by the actual selected writer, not caller history.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldFreshPrimeEnrollmentEntry {
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    pub ordinal: u64,
    pub request: ManifoldPeerEnrollmentRequest,
    pub applied_at_ms: u64,
    pub receipt: ManifoldPeerEnrollmentReceipt,
    pub source_before_sha256: String,
    pub source_after_sha256: String,
    pub source_before: serde_json::Value,
    pub source_after: serde_json::Value,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldFreshPrimeOrigin {
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    pub source_snapshot_sha256: String,
    pub host_id: DottedId,
    pub provider_epoch_id: DottedId,
    pub enrollment: ManifoldPeerEnrollmentState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldFreshPhasePrepareView {
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    pub local_peer_id: DottedId,
    pub runtime_host_id: DottedId,
    pub provider_epoch_id: DottedId,
    pub trust_policy_id: DottedId,
    pub trust_policy_revision: Revision,
    pub source_snapshot_sha256: String,
    pub origin: ManifoldFreshPrimeOrigin,
    pub enrollment: ManifoldPeerEnrollmentState,
    pub prime_enrollments: Vec<ManifoldFreshPrimeEnrollmentEntry>,
    pub prior_prepare_sequence: u64,
    /// Exact finite missing-peer set attested under the native guarded signer.
    /// Manifold does not itself certify native entry/cleanup/transport facts.
    pub unentered_peer_ids: Vec<DottedId>,
    pub native_operation_sha256: String,
    pub native_eligibility_sha256: String,
    pub observed_at_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldFreshPhasePrepareContext {
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    pub request_id: DottedId,
    pub setup_request_id: DottedId,
    pub native_phase_id: DottedId,
    pub policy: ManifoldFreshPairSetupPolicy,
    pub selection: ManifoldFreshPairSetupEnrollmentSelection,
    pub peer_ids: Vec<DottedId>,
    pub views: Vec<ManifoldFreshPhasePrepareView>,
    pub issued_at_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldFreshPhasePrepareRequest {
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    pub context: ManifoldFreshPhasePrepareContext,
    pub signatures: Vec<ManifoldFreshPairSetupSignature>,
}

pub fn fresh_phase_prepare_signing_bytes(
    c: &ManifoldFreshPhasePrepareContext,
) -> Result<Vec<u8>, &'static str> {
    let mut bytes = b"rusty.manifold.peer.fresh_phase_prepare_authorization.v2\0".to_vec();
    bytes.extend(serde_json::to_vec(c).map_err(|_| "phase prepare serialization")?);
    Ok(bytes)
}

pub fn verify_fresh_phase_prepare_request(
    r: &ManifoldFreshPhasePrepareRequest,
) -> Result<(), &'static str> {
    let c = &r.context;
    if r.schema_id.as_str() != "rusty.manifold.peer.fresh_phase_prepare_request.v2"
        || c.schema_id.as_str() != "rusty.manifold.peer.fresh_phase_prepare_context.v2"
        || !fresh_pair_setup_policy_is_well_formed(&c.policy)
        || !fresh_setup_enrollment_selection_is_well_formed(&c.selection)
        || c.peer_ids
            != c.selection
                .keys
                .iter()
                .map(|k| k.peer_id.clone())
                .collect::<Vec<_>>()
        || c.views.len() != 2
        || r.signatures.len() != 2
        || c.views.iter().all(|v| v.unentered_peer_ids.is_empty())
    {
        return Err("phase prepare closed context");
    }
    if c.request_id != crate::fresh_phase_prepare_transaction_id(c)? {
        return Err("phase prepare content-bound transaction ID differs");
    }
    let bytes = fresh_phase_prepare_signing_bytes(c)?;
    for (i, (view, signature)) in c.views.iter().zip(&r.signatures).enumerate() {
        let key = &c.selection.keys[i];
        let mut enrollment = ManifoldPeerEnrollmentState::empty();
        let mut enrolled = std::collections::BTreeSet::new();
        if view.origin.schema_id.as_str() != "rusty.manifold.peer.fresh_prime_origin.v1"
            || view.origin.host_id != view.runtime_host_id
            || view.origin.provider_epoch_id != view.provider_epoch_id
            || view.origin.enrollment != enrollment
            || !fresh_pair_setup_sha256_is_valid(&view.origin.source_snapshot_sha256)
            || view.prime_enrollments.len() > 2
        {
            return Err("phase prepare origin");
        }
        for (ordinal, entry) in view.prime_enrollments.iter().enumerate() {
            let ManifoldPeerEnrollmentAction::Enroll { credential } = &entry.request.action else {
                return Err("phase prepare prefix not Enroll");
            };
            let (next, receipt) = review_and_apply_peer_enrollment(
                &enrollment,
                &entry.request,
                &[c.selection.operator_id.clone()],
                entry.applied_at_ms,
            );
            if entry.schema_id.as_str() != "rusty.manifold.peer.fresh_prime_enrollment_entry.v1"
                || entry.ordinal != u64::try_from(ordinal).map_err(|_| "phase prepare ordinal")? + 1
                || !receipt.applied
                || receipt != entry.receipt
                || entry.applied_at_ms > view.observed_at_ms
                || !enrolled.insert(&credential.peer_id)
                || !c.selection.keys.iter().any(|k| k.matches(credential))
                || entry.source_before_sha256
                    != fresh_pair_setup_digest(
                        "rusty.manifold.peer.fresh_prime_source.v1",
                        &entry.source_before,
                    )?
                || entry.source_after_sha256
                    != fresh_pair_setup_digest(
                        "rusty.manifold.peer.fresh_prime_source.v1",
                        &entry.source_after,
                    )?
            {
                return Err("phase prepare retained prefix");
            }
            enrollment = next;
        }
        let missing = c
            .selection
            .keys
            .iter()
            .filter(|k| {
                !enrollment
                    .credentials
                    .iter()
                    .any(|e| e.peer_id == k.peer_id)
            })
            .map(|k| k.peer_id.clone())
            .collect::<Vec<_>>();
        if view.schema_id.as_str() != "rusty.manifold.peer.fresh_phase_prepare_view.v1"
            || view.local_peer_id != c.peer_ids[i]
            || view.observed_at_ms > c.issued_at_ms
            || !fresh_pair_setup_sha256_is_valid(&view.source_snapshot_sha256)
            || !fresh_pair_setup_sha256_is_valid(&view.native_operation_sha256)
            || !fresh_pair_setup_sha256_is_valid(&view.native_eligibility_sha256)
            || !view.unentered_peer_ids.windows(2).all(|w| w[0] < w[1])
            || view
                .unentered_peer_ids
                .iter()
                .any(|p| !c.peer_ids.contains(p))
            || view.enrollment != enrollment
            || missing != view.unentered_peer_ids
            || signature.schema_id.as_str() != "rusty.manifold.peer.fresh_pair_setup_signature.v3"
            || signature.signer_peer_id != key.peer_id
            || signature.signer_key_id != key.key_id
        {
            return Err("phase prepare view or signer");
        }
        let public = hex::<32>(&key.public_key_hex).ok_or("phase prepare public key")?;
        let signature = hex::<64>(&signature.signature_hex).ok_or("phase prepare signature")?;
        VerifyingKey::from_bytes(&public)
            .map_err(|_| "phase prepare public key")?
            .verify_strict(&bytes, &Signature::from_bytes(&signature))
            .map_err(|_| "phase prepare signature verification")?;
    }
    Ok(())
}
