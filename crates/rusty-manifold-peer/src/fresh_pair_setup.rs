//! Fresh, two-key setup authorization. This is not expired reciprocal renewal.
use crate::{
    ManifoldAcceptedPeer, ManifoldPeerAvailability, ManifoldPeerCredentialRecord,
    ManifoldPeerCredentialStatus, ManifoldPeerIdentity, ManifoldPeerRole, ManifoldPeerStatus,
};
use ed25519_dalek::{Signature, VerifyingKey};
use rusty_manifold_model::{DottedId, Revision, SchemaId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Fresh-only authorization remains current by exact source preimages and the
/// actual owning gate, not an estimated elapsed authorization window.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldFreshPairSetupAuthorization {
    SourceBound,
}

/// Product-selected data used only for a genuinely missing initial status.
/// Existing accepted identity/roles/capabilities are never replaced by it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldFreshPairSetupInitialStatusTemplate {
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    pub trust_domain: DottedId,
    pub roles: Vec<ManifoldPeerRole>,
    pub capability_ids: Vec<DottedId>,
}

/// Immutable product-selected policy. Ordinary credential validity stays real.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldFreshPairSetupPolicy {
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    pub policy_id: DottedId,
    pub revision: Revision,
    pub authorization: ManifoldFreshPairSetupAuthorization,
    pub initial_status: ManifoldFreshPairSetupInitialStatusTemplate,
    pub credential_validity_ms: u64,
}

/// Durable invalidation of older accepted and queued reciprocal contexts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldPairSetupFence {
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    pub peer_ids: Vec<DottedId>,
    pub setup_epoch: u64,
    pub minimum_enrollment_authority_revision: Revision,
    pub setup_request_id: DottedId,
    pub context_sha256: String,
}

/// Actual local retained preimage, obtained before either owner signs the context.
/// Native digests are signed bindings, not Manifold assertions of platform cleanup.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldFreshPairSetupPeerView {
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    pub local_peer_id: DottedId,
    pub runtime_host_id: DottedId,
    pub provider_epoch_id: DottedId,
    pub trust_policy_id: DottedId,
    pub trust_policy_revision: Revision,
    pub source_snapshot_sha256: String,
    pub enrollment_authority_revision: Revision,
    pub prior_setup_epoch: u64,
    pub prior_fence: Option<ManifoldPairSetupFence>,
    pub prior_credentials: Vec<ManifoldPeerCredentialRecord>,
    pub accepted_peers: Vec<ManifoldAcceptedPeer>,
    pub native_operation_sha256: String,
    pub native_eligibility_sha256: String,
    pub observed_at_ms: u64,
}

/// One shared domain and exact two views; independent local revisions need not equal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldFreshPairSetupContext {
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    pub request_id: DottedId,
    pub native_setup_request_id: DottedId,
    pub native_phase_id: DottedId,
    pub policy: ManifoldFreshPairSetupPolicy,
    pub peer_ids: Vec<DottedId>,
    pub views: Vec<ManifoldFreshPairSetupPeerView>,
    pub issued_at_ms: u64,
    // Audit time only; exact current source preimages authorize application.
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldFreshPairSetupSignature {
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    pub signer_peer_id: DottedId,
    pub signer_key_id: DottedId,
    pub signature_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldFreshPairSetupRequest {
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    pub context: ManifoldFreshPairSetupContext,
    pub signatures: Vec<ManifoldFreshPairSetupSignature>,
}

pub fn fresh_pair_setup_policy_is_well_formed(policy: &ManifoldFreshPairSetupPolicy) -> bool {
    policy.schema_id.as_str() == "rusty.manifold.peer.fresh_pair_setup_policy.v2"
        && policy.authorization == ManifoldFreshPairSetupAuthorization::SourceBound
        && policy.credential_validity_ms > 0
        && policy.initial_status.schema_id.as_str()
            == "rusty.manifold.peer.fresh_pair_setup_initial_status_template.v1"
        && !policy.initial_status.roles.is_empty()
        && policy.initial_status.roles.len() <= 3
        && policy
            .initial_status
            .roles
            .iter()
            .enumerate()
            .all(|(i, r)| !policy.initial_status.roles[..i].contains(r))
        && !policy.initial_status.capability_ids.is_empty()
        && policy.initial_status.capability_ids.len() <= crate::MAX_CAPABILITIES
        && policy
            .initial_status
            .capability_ids
            .windows(2)
            .all(|p| p[0] < p[1])
}

pub fn fresh_pair_setup_digest<T: Serialize>(
    domain: &str,
    value: &T,
) -> Result<String, &'static str> {
    let mut hash = Sha256::new();
    hash.update(domain.as_bytes());
    hash.update([0]);
    hash.update(serde_json::to_vec(value).map_err(|_| "fresh setup serialization")?);
    Ok(format!("sha256:{:x}", hash.finalize()))
}

pub fn fresh_pair_setup_signing_bytes(
    context: &ManifoldFreshPairSetupContext,
) -> Result<Vec<u8>, &'static str> {
    let mut bytes = b"rusty.manifold.peer.fresh_pair_setup_authorization.v3\0".to_vec();
    bytes.extend(serde_json::to_vec(context).map_err(|_| "fresh setup serialization")?);
    Ok(bytes)
}

fn hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut out = [0; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

pub fn fresh_pair_setup_sha256_is_valid(value: &str) -> bool {
    value.strip_prefix("sha256:").and_then(hex::<32>).is_some()
}

/// Validates signed intent and both exact public key identities before any owner mutation.
/// Expiry of an enrolled Active key is deliberately not a key-revocation predicate here.
/// No other signing domain, old receipt, status JSON, or one signature authorizes setup.
pub fn verify_fresh_pair_setup_request(
    request: &ManifoldFreshPairSetupRequest,
) -> Result<(), &'static str> {
    let c = &request.context;
    if request.schema_id.as_str() != "rusty.manifold.peer.fresh_pair_setup_request.v3"
        || c.schema_id.as_str() != "rusty.manifold.peer.fresh_pair_setup_context.v3"
        || !fresh_pair_setup_policy_is_well_formed(&c.policy)
        || c.peer_ids.len() != 2
        || c.peer_ids[0] >= c.peer_ids[1]
        || c.views.len() != 2
        || request.signatures.len() != 2
    {
        return Err("fresh setup context shape");
    }
    if c.request_id != crate::fresh_pair_setup_transaction_id(c)? {
        return Err("fresh setup content-bound transaction ID differs");
    }
    let bytes = fresh_pair_setup_signing_bytes(c)?;
    for (index, peer) in c.peer_ids.iter().enumerate() {
        let view = &c.views[index];
        let signature = &request.signatures[index];
        if view.schema_id.as_str() != "rusty.manifold.peer.fresh_pair_setup_peer_view.v2"
            || &view.local_peer_id != peer
            || view.observed_at_ms > c.issued_at_ms
            || !fresh_pair_setup_sha256_is_valid(&view.source_snapshot_sha256)
            || !fresh_pair_setup_sha256_is_valid(&view.native_operation_sha256)
            || !fresh_pair_setup_sha256_is_valid(&view.native_eligibility_sha256)
            || view.prior_fence.as_ref().map_or(0, |f| f.setup_epoch) != view.prior_setup_epoch
            || view.prior_fence.as_ref().is_some_and(|f| {
                f.peer_ids != c.peer_ids || !fresh_pair_setup_fence_is_well_formed(f)
            })
            || view.prior_credentials.len() != 2
            || view.accepted_peers.len() > 2
            || !view
                .accepted_peers
                .windows(2)
                .all(|p| p[0].identity.peer_id < p[1].identity.peer_id)
            || view
                .accepted_peers
                .iter()
                .any(|p| !c.peer_ids.contains(&p.identity.peer_id))
            || signature.schema_id.as_str() != "rusty.manifold.peer.fresh_pair_setup_signature.v3"
            || &signature.signer_peer_id != peer
        {
            return Err("fresh setup signed view");
        }
        for (j, member) in c.peer_ids.iter().enumerate() {
            let credential = &view.prior_credentials[j];
            if &credential.peer_id != member
                || credential.schema_id.as_str() != crate::PEER_CREDENTIAL_SCHEMA
                || credential.status != ManifoldPeerCredentialStatus::Active
                || credential.replaced_by_key_id.is_some()
                || credential.valid_from_ms > view.observed_at_ms
                || credential.trust_domain != c.policy.initial_status.trust_domain
            {
                return Err("fresh setup current key and identity");
            }
            if let Some(accepted) = view
                .accepted_peers
                .iter()
                .find(|p| &p.identity.peer_id == member)
            {
                let fingerprint = credential
                    .public_key_sha256
                    .strip_prefix("sha256:")
                    .map(|hash| format!("fingerprint.{hash}"))
                    .ok_or("fresh setup key digest")?;
                if accepted.identity.schema_id.as_str() != crate::PEER_IDENTITY_SCHEMA
                    || accepted.status.schema_id.as_str() != crate::PEER_STATUS_SCHEMA
                    || accepted.status.peer_id != *member
                    || accepted.identity.trust_domain != credential.trust_domain
                    || accepted.identity.key_fingerprint.as_str() != fingerprint
                    || accepted.status.availability != ManifoldPeerAvailability::Ready
                    || accepted.status.observed_at_ms > view.observed_at_ms
                {
                    return Err("fresh setup retained identity not ready or changed");
                }
            }
            let other = &c.views[1 - index].prior_credentials;
            if other.len() != 2 {
                return Err("fresh setup remote keys absent");
            }
            let mut same_key = credential.clone();
            same_key.valid_from_ms = other[j].valid_from_ms;
            same_key.expires_at_ms = other[j].expires_at_ms;
            if same_key != other[j] {
                return Err("fresh setup enrolled key disagreement");
            }
        }
        let key = &view.prior_credentials[index];
        if signature.signer_key_id != key.key_id {
            return Err("fresh setup signer key identity");
        }
        let public = hex::<32>(&key.public_key_hex).ok_or("fresh setup public key encoding")?;
        if format!("sha256:{:x}", Sha256::digest(public)) != key.public_key_sha256 {
            return Err("fresh setup public key digest");
        }
        let signature_bytes =
            hex::<64>(&signature.signature_hex).ok_or("fresh setup signature encoding")?;
        let verifying = VerifyingKey::from_bytes(&public).map_err(|_| "fresh setup public key")?;
        if verifying.is_weak() {
            return Err("fresh setup weak public key");
        }
        verifying
            .verify_strict(&bytes, &Signature::from_bytes(&signature_bytes))
            .map_err(|_| "fresh setup signature verification")?;
    }
    Ok(())
}

pub fn fresh_pair_setup_fence_is_well_formed(f: &ManifoldPairSetupFence) -> bool {
    f.schema_id.as_str() == "rusty.manifold.peer.pair_setup_fence.v1"
        && f.peer_ids.len() == 2
        && f.peer_ids[0] < f.peer_ids[1]
        && f.setup_epoch > 0
        && fresh_pair_setup_sha256_is_valid(&f.context_sha256)
}

pub fn fresh_pair_setup_fences_are_well_formed(fences: &[ManifoldPairSetupFence]) -> bool {
    fences.iter().all(fresh_pair_setup_fence_is_well_formed)
        && fences
            .windows(2)
            .all(|pair| pair[0].peer_ids < pair[1].peer_ids)
}

/// Replaces a single canonical pair's floor monotonically, retaining every other pair.
pub fn advance_fresh_pair_setup_fence(
    fences: &mut Vec<ManifoldPairSetupFence>,
    next: ManifoldPairSetupFence,
) -> Result<(), &'static str> {
    if !fresh_pair_setup_fences_are_well_formed(fences)
        || !fresh_pair_setup_fence_is_well_formed(&next)
    {
        return Err("fresh setup fence shape");
    }
    if let Some(old) = fences.iter_mut().find(|f| f.peer_ids == next.peer_ids) {
        if old.setup_epoch.checked_add(1) != Some(next.setup_epoch)
            || old.minimum_enrollment_authority_revision
                >= next.minimum_enrollment_authority_revision
            || old.setup_request_id == next.setup_request_id
        {
            return Err("fresh setup fence did not advance");
        }
        *old = next;
    } else {
        if next.setup_epoch != 1 {
            return Err("fresh setup initial epoch");
        }
        fences.push(next);
        fences.sort_by(|a, b| a.peer_ids.cmp(&b.peer_ids));
    }
    Ok(())
}

/// Missing floor means the original contract. No current proof can cross a raised floor.
pub fn fresh_pair_setup_floor_allows(
    fences: &[ManifoldPairSetupFence],
    peers: &[DottedId],
    revision: Revision,
) -> bool {
    fences
        .iter()
        .find(|f| f.peer_ids == peers)
        .map_or(true, |f| {
            revision >= f.minimum_enrollment_authority_revision
        })
}

/// Builds only the status proposal data. The real accepted-status writer must
/// still review/apply it, and both signed views/policy/current enrolled keys
/// must have validated before this helper is reached.
pub fn fresh_pair_setup_expected_peer(
    view: &ManifoldFreshPairSetupPeerView,
    peer: &DottedId,
    policy: &ManifoldFreshPairSetupPolicy,
    applied_at_ms: u64,
    credential_expires_at_ms: u64,
    status_ttl_ms: u64,
) -> Result<ManifoldAcceptedPeer, &'static str> {
    let mut accepted = if let Some(old) = view
        .accepted_peers
        .iter()
        .find(|p| &p.identity.peer_id == peer)
    {
        if old.status.availability != ManifoldPeerAvailability::Ready {
            return Err("fresh setup cannot repair not-ready status");
        }
        let mut next = old.clone();
        next.status.status_revision = next
            .status
            .status_revision
            .next()
            .ok_or("fresh setup status revision exhausted")?;
        next
    } else {
        let credential = view
            .prior_credentials
            .iter()
            .find(|c| &c.peer_id == peer)
            .ok_or("fresh setup missing enrolled key")?;
        if !fresh_pair_setup_policy_is_well_formed(policy)
            || credential.trust_domain != policy.initial_status.trust_domain
            || credential.status != ManifoldPeerCredentialStatus::Active
            || credential.replaced_by_key_id.is_some()
        {
            return Err("fresh setup initial status source differs");
        }
        let hash = credential
            .public_key_sha256
            .strip_prefix("sha256:")
            .ok_or("fresh setup enrolled key digest")?;
        ManifoldAcceptedPeer {
            identity: ManifoldPeerIdentity {
                schema_id: SchemaId::new(crate::PEER_IDENTITY_SCHEMA)
                    .map_err(|_| "identity schema")?,
                peer_id: peer.clone(),
                key_fingerprint: DottedId::new(format!("fingerprint.{hash}"))
                    .map_err(|_| "key fingerprint")?,
                trust_domain: policy.initial_status.trust_domain.clone(),
                roles: policy.initial_status.roles.clone(),
            },
            status: ManifoldPeerStatus {
                schema_id: SchemaId::new(crate::PEER_STATUS_SCHEMA).map_err(|_| "status schema")?,
                peer_id: peer.clone(),
                status_revision: Revision::INITIAL,
                observed_at_ms: applied_at_ms,
                expires_at_ms: credential_expires_at_ms,
                availability: ManifoldPeerAvailability::Ready,
                capability_ids: policy.initial_status.capability_ids.clone(),
            },
        }
    };
    accepted.status.observed_at_ms = applied_at_ms;
    accepted.status.expires_at_ms = credential_expires_at_ms.min(
        applied_at_ms
            .checked_add(status_ttl_ms)
            .ok_or("fresh setup status expiry overflow")?,
    );
    Ok(accepted)
}
