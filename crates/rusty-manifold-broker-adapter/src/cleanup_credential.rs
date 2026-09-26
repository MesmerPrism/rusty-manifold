//! Cleanup-only credentials for a trusted retained pair-route target.
//!
//! This independent source slice does not integrate Broker runtime evidence or
//! Peer terminal receipts. A Pending authorization proves neither teardown nor
//! acknowledgement. Deployment must pin trust before Start, retain the original
//! target, persist every mutation before observation, externally fence one writer,
//! and store snapshot anchors independently. No ordinary admission or lease is issued.

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const SIGNING_DOMAIN: &[u8] = b"rusty.manifold.broker.cleanup_credential.v1\0";
const CHALLENGE_DOMAIN: &[u8] = b"rusty.manifold.broker.cleanup_challenge.v1\0";
const SNAPSHOT_DOMAIN: &[u8] = b"rusty.manifold.broker.cleanup_snapshot.v1\0";
/// Maximum retained events; no compaction can erase consumed request identities.
pub const BROKER_CLEANUP_MAX_EVENTS: usize = 128;
/// Maximum credential and challenge lifetime in the retained monotonic epoch.
pub const BROKER_CLEANUP_MAX_VALIDITY_MS: u64 = 60_000;

/// Trusted issuer/audience pinned by deployment before the original Start.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerCleanupTrust {
    /// Issuer identity.
    pub issuer: String,
    /// Exact canonical lowercase Ed25519 public key.
    pub public_key_hex: String,
    /// Sole product audience.
    pub audience: String,
}

/// Immutable original target supplied from trusted retained owner state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerCleanupTarget {
    /// Original authority host.
    pub authority_host: String,
    /// Original externally fenced provider epoch.
    pub provider_epoch: String,
    /// Original principal; the revoker is independently pinned in the binding.
    pub original_principal: String,
    /// Original admission identity.
    pub admission_id: String,
    /// Original admission deadline (evidence, never renewed).
    pub admission_expires_at_ms: u64,
    /// Original lease identity.
    pub lease_id: String,
    /// Original lease deadline (evidence, never renewed).
    pub lease_expires_at_ms: u64,
    /// Packaged product identity.
    pub product_lock_id: String,
    /// Semantic product closure fingerprint, separate from packaged bytes.
    pub product_lock_fingerprint: String,
    /// Exact packaged product bytes digest.
    pub product_lock_sha256: String,
    /// Packaged client identity.
    pub client_lock_id: String,
    /// Exact packaged client bytes digest.
    pub client_lock_sha256: String,
    /// Packaged application feature identity.
    pub feature_lock_id: String,
    /// Exact packaged feature bytes digest.
    pub feature_lock_sha256: String,
    /// Immutable pair route grant.
    pub route_grant_id: String,
    /// Expected retained route revision.
    pub route_revision: u64,
    /// Original platform effect runtime.
    pub platform_runtime: String,
    /// Exact original effect target digest; not a terminal receipt.
    pub effect_target_sha256: String,
}

/// Trusted pre-Start binding. Construction is a deployment-owner API, not proof
/// that arbitrary caller state was ever accepted by Broker or Peer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerCleanupBinding {
    /// Pre-pinned trust root.
    pub trust: ManifoldBrokerCleanupTrust,
    /// Exact retained original target.
    pub target: ManifoldBrokerCleanupTarget,
    /// Sole allowed fresh cleanup revoker principal.
    pub revoker_principal: String,
    /// Clock epoch retained across restart. A reboot needs separate continuity.
    pub clock_epoch: String,
}

/// Sole signed action. This vocabulary contains no Issue, Start or renewal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldBrokerCleanupAction {
    /// Authorize pending acknowledgement of cleanup for the retained pair route.
    AcknowledgeRetainedPairRouteCleanup,
}

/// Authority-derived one-use target challenge, also used as the signed nonce.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerCleanupChallenge {
    /// Sequence is the ledger revision after challenge issuance.
    pub revision: u64,
    /// Derived challenge identity, canonical SHA-256.
    pub nonce_sha256: String,
    /// Clock epoch.
    pub clock_epoch: String,
    /// Challenge issuance time.
    pub issued_at_ms: u64,
    /// Exclusive expiry.
    pub expires_at_ms: u64,
}

/// All signed fields, canonicalized in declaration order as typed JSON.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerCleanupStatement {
    /// Exact issuer.
    pub issuer: String,
    /// Exact audience.
    pub audience: String,
    /// Exact target.
    pub target: ManifoldBrokerCleanupTarget,
    /// Independently pinned cleanup revoker.
    pub revoker_principal: String,
    /// Closed cleanup action.
    pub action: ManifoldBrokerCleanupAction,
    /// Fresh authority challenge and expected cleanup revision.
    pub challenge: ManifoldBrokerCleanupChallenge,
    /// Unique request identity, consumed durably.
    pub request_id: String,
    /// Signed validity start.
    pub issued_at_ms: u64,
    /// Exclusive signed validity end.
    pub expires_at_ms: u64,
}

/// Signed credential; possession alone confers no authorization.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerCleanupCredential {
    /// Complete signed statement.
    pub statement: ManifoldBrokerCleanupStatement,
    /// Strict canonical lowercase 64-byte Ed25519 signature.
    pub signature_hex: String,
}

/// Deterministic domain-separated signing bytes. Length framing prevents domain
/// and payload concatenation ambiguity; there are no maps or floats.
#[must_use]
pub fn broker_cleanup_signing_bytes(statement: &ManifoldBrokerCleanupStatement) -> Vec<u8> {
    framed(SIGNING_DOMAIN, statement)
}

/// Cleanup verifier rejection; no rejection changes accepted state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldBrokerCleanupError {
    /// Invalid, oversized or noncanonical input.
    Invalid,
    /// Signed identity or target differs from trusted retention.
    Binding,
    /// Invalid signature or weak issuer key.
    Signature,
    /// Epoch change, regression, future statement or expired validity.
    Clock,
    /// Missing, stale or already consumed challenge/request/target.
    Replay,
    /// Durable history is full; it cannot be silently truncated.
    Capacity,
    /// Snapshot anchor, replay, tombstone or audit closure mismatch.
    Snapshot,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum Event {
    Challenge(ManifoldBrokerCleanupChallenge),
    Pending {
        credential: Box<ManifoldBrokerCleanupCredential>,
        authorized_at_ms: u64,
    },
}

/// Durable consumption tombstone. Pending is never effective cleanup.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerCleanupPending {
    /// Accepted cleanup revision.
    pub revision: u64,
    /// Consumed request identity.
    pub request_id: String,
    /// Consumed nonce identity.
    pub nonce_sha256: String,
    /// Signed credential digest.
    pub credential_sha256: String,
}

/// Opaque, non-Clone source-only authorization. It cannot be converted into a
/// token, lease or terminal receipt. Runtime integration is a separate slice.
#[derive(Debug)]
pub struct ManifoldBrokerCleanupAuthorization {
    pending: ManifoldBrokerCleanupPending,
}
impl ManifoldBrokerCleanupAuthorization {
    /// Read pending evidence only; it does not prove a platform effect.
    #[must_use]
    pub fn pending(&self) -> &ManifoldBrokerCleanupPending {
        &self.pending
    }
}

/// Durable state transport. Private fields enforce use through authority APIs;
/// deserialized snapshots remain untrusted until anchored restore succeeds.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerCleanupSnapshot {
    binding: ManifoldBrokerCleanupBinding,
    initial_ms: u64,
    last_ms: u64,
    revision: u64,
    events: Vec<Event>,
    challenge: Option<ManifoldBrokerCleanupChallenge>,
    pending: Option<ManifoldBrokerCleanupPending>,
    audit_sha256: Vec<String>,
}
impl ManifoldBrokerCleanupSnapshot {
    /// Anchor to persist in independently trusted owner storage after commit.
    #[must_use]
    pub fn anchor_sha256(&self) -> String {
        digest(SNAPSHOT_DOMAIN, self)
    }
    /// Current accepted revision.
    #[must_use]
    pub fn revision(&self) -> u64 {
        self.revision
    }
    /// Durable pending tombstone, if the credential was consumed.
    #[must_use]
    pub fn pending(&self) -> Option<&ManifoldBrokerCleanupPending> {
        self.pending.as_ref()
    }
}

/// Mutable authority for one immutable retained cleanup target, externally
/// fenced and persisted by deployment. No completion operation exists here.
#[derive(Debug)]
pub struct ManifoldBrokerCleanupAuthority {
    state: ManifoldBrokerCleanupSnapshot,
}
impl ManifoldBrokerCleanupAuthority {
    /// Pin the exact trusted binding before Start. Callers must retain it beside
    /// the original route; this constructor cannot attest caller provenance.
    ///
    /// # Errors
    /// Rejects malformed identities, digests or issuer keys.
    pub fn pin_before_start(
        binding: ManifoldBrokerCleanupBinding,
        now_ms: u64,
    ) -> Result<Self, ManifoldBrokerCleanupError> {
        validate_binding(&binding)?;
        Ok(Self {
            state: ManifoldBrokerCleanupSnapshot {
                binding,
                initial_ms: now_ms,
                last_ms: now_ms,
                revision: 0,
                events: vec![],
                challenge: None,
                pending: None,
                audit_sha256: vec![],
            },
        })
    }
    /// Exact state to persist atomically before exposing an authorization.
    #[must_use]
    pub fn snapshot(&self) -> ManifoldBrokerCleanupSnapshot {
        self.state.clone()
    }

    /// Restore against independently trusted exact binding and committed digest.
    /// Replays every accepted event to reconstruct nonce/tombstone/audit closure.
    /// Pending authorizations stay consumed and cannot be re-created on restart.
    ///
    /// # Errors
    /// Rejects missing/tampered state, capacity violations or clock regression.
    pub fn restore(
        mut snapshot: ManifoldBrokerCleanupSnapshot,
        trusted_binding: &ManifoldBrokerCleanupBinding,
        trusted_anchor: &str,
        clock_epoch: &str,
        now_ms: u64,
    ) -> Result<Self, ManifoldBrokerCleanupError> {
        if snapshot.events.len() > BROKER_CLEANUP_MAX_EVENTS
            || &snapshot.binding != trusted_binding
            || snapshot.anchor_sha256() != trusted_anchor
        {
            return Err(ManifoldBrokerCleanupError::Snapshot);
        }
        let mut rebuilt = Self::pin_before_start(trusted_binding.clone(), snapshot.initial_ms)?;
        for event in &snapshot.events {
            match event {
                Event::Challenge(c) => {
                    let actual = rebuilt.challenge(&c.clock_epoch, c.issued_at_ms)?;
                    if actual != *c {
                        return Err(ManifoldBrokerCleanupError::Snapshot);
                    }
                }
                Event::Pending {
                    credential,
                    authorized_at_ms,
                } => {
                    rebuilt.authorize(
                        credential,
                        &credential.statement.request_id,
                        &trusted_binding.clock_epoch,
                        *authorized_at_ms,
                    )?;
                }
            }
        }
        if snapshot.last_ms < rebuilt.state.last_ms {
            return Err(ManifoldBrokerCleanupError::Snapshot);
        }
        rebuilt.state.last_ms = snapshot.last_ms;
        if rebuilt.state != snapshot {
            return Err(ManifoldBrokerCleanupError::Snapshot);
        }
        rebuilt.check_clock(clock_epoch, now_ms)?;
        // Retain the supplied current clock so later operations cannot regress
        // behind the restore observation even before another accepted event.
        snapshot.last_ms = now_ms;
        Ok(Self { state: snapshot })
    }
    /// Generate a fresh target-bound nonce from retained binding, revision and
    /// monotonic time. Freshness requires the externally fenced single writer;
    /// this nonce is not a secret or a replacement for signature verification.
    ///
    /// # Errors
    /// Rejects Pending, exhausted history, changed epochs or regressing time.
    pub fn challenge(
        &mut self,
        clock_epoch: &str,
        now_ms: u64,
    ) -> Result<ManifoldBrokerCleanupChallenge, ManifoldBrokerCleanupError> {
        self.check_clock(clock_epoch, now_ms)?;
        if self.state.pending.is_some() {
            return Err(ManifoldBrokerCleanupError::Replay);
        }
        self.capacity(BROKER_CLEANUP_MAX_EVENTS - 1)?;
        let revision = self
            .state
            .revision
            .checked_add(1)
            .ok_or(ManifoldBrokerCleanupError::Capacity)?;
        let expires_at_ms = now_ms
            .checked_add(BROKER_CLEANUP_MAX_VALIDITY_MS)
            .ok_or(ManifoldBrokerCleanupError::Clock)?;
        let c = ManifoldBrokerCleanupChallenge {
            revision,
            nonce_sha256: digest(CHALLENGE_DOMAIN, &(&self.state.binding, revision, now_ms)),
            clock_epoch: clock_epoch.to_owned(),
            issued_at_ms: now_ms,
            expires_at_ms,
        };
        self.state.challenge = Some(c.clone());
        self.append(Event::Challenge(c.clone()), now_ms);
        Ok(c)
    }
    /// Verify and consume a credential exactly once, retaining Pending evidence.
    /// The original admission and lease deadlines impose no validity on fresh
    /// cleanup authority; they remain immutable signed provenance.
    ///
    /// # Errors
    /// Rejects any identity/target/challenge/signature/time mismatch or replay.
    pub fn authorize(
        &mut self,
        credential: &ManifoldBrokerCleanupCredential,
        request_id: &str,
        clock_epoch: &str,
        now_ms: u64,
    ) -> Result<ManifoldBrokerCleanupAuthorization, ManifoldBrokerCleanupError> {
        self.check_clock(clock_epoch, now_ms)?;
        self.capacity(BROKER_CLEANUP_MAX_EVENTS)?;
        let s = &credential.statement;
        let b = &self.state.binding;
        if s.request_id != request_id {
            return Err(ManifoldBrokerCleanupError::Binding);
        }
        if s.issuer != b.trust.issuer
            || s.audience != b.trust.audience
            || s.target != b.target
            || s.revoker_principal != b.revoker_principal
        {
            return Err(ManifoldBrokerCleanupError::Binding);
        }
        if !identity(&s.request_id) {
            return Err(ManifoldBrokerCleanupError::Invalid);
        }
        if self.state.pending.is_some()
            || self.state.challenge.as_ref() != Some(&s.challenge)
            || s.challenge.revision != self.state.revision
        {
            return Err(ManifoldBrokerCleanupError::Replay);
        }
        if s.challenge.clock_epoch != clock_epoch
            || s.issued_at_ms < s.challenge.issued_at_ms
            || s.issued_at_ms > now_ms
            || now_ms >= s.expires_at_ms
            || now_ms >= s.challenge.expires_at_ms
            || s.expires_at_ms > s.challenge.expires_at_ms
            || s.expires_at_ms <= s.issued_at_ms
            || s.expires_at_ms - s.issued_at_ms > BROKER_CLEANUP_MAX_VALIDITY_MS
        {
            return Err(ManifoldBrokerCleanupError::Clock);
        }
        let key_bytes =
            decode::<32>(&b.trust.public_key_hex).ok_or(ManifoldBrokerCleanupError::Invalid)?;
        let key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|_| ManifoldBrokerCleanupError::Signature)?;
        let sig = Signature::from_bytes(
            &decode::<64>(&credential.signature_hex).ok_or(ManifoldBrokerCleanupError::Invalid)?,
        );
        key.verify_strict(&broker_cleanup_signing_bytes(s), &sig)
            .map_err(|_| ManifoldBrokerCleanupError::Signature)?;
        let pending = ManifoldBrokerCleanupPending {
            revision: self.state.revision + 1,
            request_id: s.request_id.clone(),
            nonce_sha256: s.challenge.nonce_sha256.clone(),
            credential_sha256: digest(SIGNING_DOMAIN, credential),
        };
        self.state.pending = Some(pending.clone());
        self.state.challenge = None;
        self.append(
            Event::Pending {
                credential: Box::new(credential.clone()),
                authorized_at_ms: now_ms,
            },
            now_ms,
        );
        Ok(ManifoldBrokerCleanupAuthorization { pending })
    }
    fn check_clock(&self, epoch: &str, now_ms: u64) -> Result<(), ManifoldBrokerCleanupError> {
        if epoch != self.state.binding.clock_epoch || now_ms < self.state.last_ms {
            return Err(ManifoldBrokerCleanupError::Clock);
        }
        Ok(())
    }
    fn capacity(&self, limit: usize) -> Result<(), ManifoldBrokerCleanupError> {
        // Reserve a terminal Pending slot whenever issuing a challenge.
        if self.state.events.len() >= limit {
            return Err(ManifoldBrokerCleanupError::Capacity);
        }
        Ok(())
    }
    fn append(&mut self, event: Event, now_ms: u64) {
        let previous = self.state.audit_sha256.last().cloned();
        self.state.revision += 1;
        self.state.audit_sha256.push(digest(
            SNAPSHOT_DOMAIN,
            &(&self.state.binding, self.state.revision, previous, &event),
        ));
        self.state.events.push(event);
        self.state.last_ms = now_ms;
    }
}
fn framed<T: Serialize>(domain: &[u8], value: &T) -> Vec<u8> {
    let payload = serde_json::to_vec(value).expect("closed typed cleanup records serialize");
    let mut bytes = domain.to_vec();
    bytes.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    bytes.extend(payload);
    bytes
}
fn digest<T: Serialize>(domain: &[u8], value: &T) -> String {
    format!("sha256:{}", hex(&Sha256::digest(framed(domain, value))))
}
fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(char::from(HEX[usize::from(byte >> 4)]));
        result.push(char::from(HEX[usize::from(byte & 15)]));
    }
    result
}
fn decode<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut result = [0; N];
    for (i, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(result)
}
fn identity(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
}
fn validate_binding(b: &ManifoldBrokerCleanupBinding) -> Result<(), ManifoldBrokerCleanupError> {
    let t = &b.target;
    let ids = [
        &b.trust.issuer,
        &b.trust.audience,
        &b.revoker_principal,
        &b.clock_epoch,
        &t.authority_host,
        &t.provider_epoch,
        &t.original_principal,
        &t.admission_id,
        &t.lease_id,
        &t.product_lock_id,
        &t.product_lock_fingerprint,
        &t.client_lock_id,
        &t.feature_lock_id,
        &t.route_grant_id,
        &t.platform_runtime,
    ];
    let digests = [
        &t.product_lock_sha256,
        &t.client_lock_sha256,
        &t.feature_lock_sha256,
        &t.effect_target_sha256,
    ];
    if !ids.iter().all(|s| identity(s))
        || !digests
            .iter()
            .all(|s| s.strip_prefix("sha256:").and_then(decode::<32>).is_some())
    {
        return Err(ManifoldBrokerCleanupError::Invalid);
    }
    let bytes = decode::<32>(&b.trust.public_key_hex).ok_or(ManifoldBrokerCleanupError::Invalid)?;
    let key =
        VerifyingKey::from_bytes(&bytes).map_err(|_| ManifoldBrokerCleanupError::Signature)?;
    if key.is_weak() {
        return Err(ManifoldBrokerCleanupError::Signature);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn setup() -> (ManifoldBrokerCleanupAuthority, SigningKey) {
        let key = SigningKey::from_bytes(&[19; 32]);
        let sha = format!("sha256:{}", "12".repeat(32));
        let target = ManifoldBrokerCleanupTarget {
            authority_host: "host.original".into(),
            provider_epoch: "epoch.original".into(),
            original_principal: "client.original".into(),
            admission_id: "admission.original".into(),
            admission_expires_at_ms: 20,
            lease_id: "lease.original".into(),
            lease_expires_at_ms: 30,
            product_lock_id: "lock.product".into(),
            product_lock_fingerprint: "closure.original".into(),
            product_lock_sha256: sha.clone(),
            client_lock_id: "lock.client".into(),
            client_lock_sha256: sha.clone(),
            feature_lock_id: "lock.feature".into(),
            feature_lock_sha256: sha.clone(),
            route_grant_id: "route.original".into(),
            route_revision: 7,
            platform_runtime: "platform.original".into(),
            effect_target_sha256: sha,
        };
        let binding = ManifoldBrokerCleanupBinding {
            trust: ManifoldBrokerCleanupTrust {
                issuer: "issuer.pinned".into(),
                public_key_hex: hex(&key.verifying_key().to_bytes()),
                audience: "product.pinned".into(),
            },
            target,
            revoker_principal: "revoker.pinned".into(),
            clock_epoch: "clock.original".into(),
        };
        (
            ManifoldBrokerCleanupAuthority::pin_before_start(binding, 10).unwrap(),
            key,
        )
    }
    fn credential(
        a: &mut ManifoldBrokerCleanupAuthority,
        key: &SigningKey,
    ) -> ManifoldBrokerCleanupCredential {
        let challenge = a.challenge("clock.original", 100).unwrap();
        let b = &a.state.binding;
        let statement = ManifoldBrokerCleanupStatement {
            issuer: b.trust.issuer.clone(),
            audience: b.trust.audience.clone(),
            target: b.target.clone(),
            revoker_principal: b.revoker_principal.clone(),
            action: ManifoldBrokerCleanupAction::AcknowledgeRetainedPairRouteCleanup,
            challenge,
            request_id: "request.cleanup".into(),
            issued_at_ms: 100,
            expires_at_ms: 200,
        };
        let signature_hex = hex(&key
            .sign(&broker_cleanup_signing_bytes(&statement))
            .to_bytes());
        ManifoldBrokerCleanupCredential {
            statement,
            signature_hex,
        }
    }
    fn resign(c: &mut ManifoldBrokerCleanupCredential, key: &SigningKey) {
        c.signature_hex = hex(&key
            .sign(&broker_cleanup_signing_bytes(&c.statement))
            .to_bytes());
    }
    #[test]
    fn expired_original_authority_allows_only_fresh_pending_cleanup() {
        let (mut a, key) = setup();
        let c = credential(&mut a, &key);
        let authorized = a
            .authorize(&c, "request.cleanup", "clock.original", 150)
            .unwrap();
        assert_eq!(authorized.pending().revision, 2);
        assert!(a.snapshot().pending().is_some());
        assert_eq!(
            a.authorize(&c, "request.cleanup", "clock.original", 150)
                .unwrap_err(),
            ManifoldBrokerCleanupError::Replay
        );
        assert_eq!(
            a.challenge("clock.original", 160).unwrap_err(),
            ManifoldBrokerCleanupError::Replay
        );
        let s = a.snapshot();
        let mut restored = ManifoldBrokerCleanupAuthority::restore(
            s.clone(),
            &s.binding,
            &s.anchor_sha256(),
            "clock.original",
            160,
        )
        .unwrap();
        assert_eq!(
            restored
                .authorize(&c, "request.cleanup", "clock.original", 160)
                .unwrap_err(),
            ManifoldBrokerCleanupError::Replay
        );
        let next = restored.snapshot();
        ManifoldBrokerCleanupAuthority::restore(
            next.clone(),
            &next.binding,
            &next.anchor_sha256(),
            "clock.original",
            170,
        )
        .unwrap();
    }
    #[test]
    fn every_signed_field_is_bound_and_wrong_trusted_target_rejects() {
        let (mut a, key) = setup();
        let c = credential(&mut a, &key);
        let value = serde_json::to_value(&c.statement).unwrap();
        // Mutate each scalar recursively, including every target/challenge field.
        fn paths(v: &serde_json::Value, p: Vec<String>, out: &mut Vec<Vec<String>>) {
            if let Some(map) = v.as_object() {
                for (k, child) in map {
                    let mut next = p.clone();
                    next.push(k.clone());
                    paths(child, next, out);
                }
            } else {
                out.push(p);
            }
        }
        let mut fields = vec![];
        paths(&value, vec![], &mut fields);
        for path in fields {
            let mut changed = value.clone();
            let mut leaf = &mut changed;
            for p in &path {
                leaf = leaf.get_mut(p).unwrap();
            }
            *leaf = if let Some(n) = leaf.as_u64() {
                serde_json::json!(n + 1)
            } else {
                serde_json::json!(format!("{}.changed", leaf.as_str().unwrap()))
            };
            if let Ok(statement) = serde_json::from_value(changed) {
                let damaged = ManifoldBrokerCleanupCredential {
                    statement,
                    signature_hex: c.signature_hex.clone(),
                };
                assert!(
                    a.authorize(&damaged, "request.cleanup", "clock.original", 150)
                        .is_err(),
                    "unsigned mutation: {path:?}"
                );
            }
        }
        let mut wrong = c.clone();
        wrong.statement.target.feature_lock_sha256 = format!("sha256:{}", "13".repeat(32));
        resign(&mut wrong, &key);
        assert_eq!(
            a.authorize(&wrong, "request.cleanup", "clock.original", 150)
                .unwrap_err(),
            ManifoldBrokerCleanupError::Binding
        );
        let mut wrong = c.clone();
        wrong.statement.revoker_principal = "revoker.other".into();
        resign(&mut wrong, &key);
        assert_eq!(
            a.authorize(&wrong, "request.cleanup", "clock.original", 150)
                .unwrap_err(),
            ManifoldBrokerCleanupError::Binding
        );
        let mut wrong = c.clone();
        resign(&mut wrong, &SigningKey::from_bytes(&[20; 32]));
        assert_eq!(
            a.authorize(&wrong, "request.cleanup", "clock.original", 150)
                .unwrap_err(),
            ManifoldBrokerCleanupError::Signature
        );
        assert!(a.snapshot().pending().is_none());
        assert_eq!(
            a.authorize(&c, "request.other", "clock.original", 150)
                .unwrap_err(),
            ManifoldBrokerCleanupError::Binding
        );
        for field in ["issuer", "audience", "revoker_principal"] {
            let mut value = serde_json::to_value(&c).unwrap();
            value["statement"][field] = serde_json::json!("identity.other");
            let mut changed: ManifoldBrokerCleanupCredential =
                serde_json::from_value(value).unwrap();
            resign(&mut changed, &key);
            assert_eq!(
                a.authorize(&changed, "request.cleanup", "clock.original", 150)
                    .unwrap_err(),
                ManifoldBrokerCleanupError::Binding
            );
        }
        let target = serde_json::to_value(&c.statement.target).unwrap();
        for (field, value) in target.as_object().unwrap() {
            let mut changed = serde_json::to_value(&c).unwrap();
            changed["statement"]["target"][field] = if let Some(n) = value.as_u64() {
                serde_json::json!(n + 1)
            } else {
                serde_json::json!("target.other")
            };
            let mut changed: ManifoldBrokerCleanupCredential =
                serde_json::from_value(changed).unwrap();
            resign(&mut changed, &key);
            assert_eq!(
                a.authorize(&changed, "request.cleanup", "clock.original", 150)
                    .unwrap_err(),
                ManifoldBrokerCleanupError::Binding,
                "target {field}"
            );
        }
        for field in [
            "revision",
            "nonce_sha256",
            "clock_epoch",
            "issued_at_ms",
            "expires_at_ms",
        ] {
            let mut changed = serde_json::to_value(&c).unwrap();
            let value = &changed["statement"]["challenge"][field];
            changed["statement"]["challenge"][field] = if let Some(n) = value.as_u64() {
                serde_json::json!(n + 1)
            } else {
                serde_json::json!("challenge.other")
            };
            let mut changed: ManifoldBrokerCleanupCredential =
                serde_json::from_value(changed).unwrap();
            resign(&mut changed, &key);
            assert_eq!(
                a.authorize(&changed, "request.cleanup", "clock.original", 150)
                    .unwrap_err(),
                ManifoldBrokerCleanupError::Replay,
                "challenge {field}"
            );
        }
    }
    #[test]
    fn stale_future_expired_epoch_and_regression_reject() {
        let (mut a, key) = setup();
        let c = credential(&mut a, &key);
        assert_eq!(
            a.authorize(&c, "request.cleanup", "clock.other", 150)
                .unwrap_err(),
            ManifoldBrokerCleanupError::Clock
        );
        assert_eq!(
            a.authorize(&c, "request.cleanup", "clock.original", 99)
                .unwrap_err(),
            ManifoldBrokerCleanupError::Clock
        );
        assert_eq!(
            a.authorize(&c, "request.cleanup", "clock.original", 200)
                .unwrap_err(),
            ManifoldBrokerCleanupError::Clock
        );
        let mut future = c.clone();
        future.statement.issued_at_ms = 160;
        resign(&mut future, &key);
        assert_eq!(
            a.authorize(&future, "request.cleanup", "clock.original", 150)
                .unwrap_err(),
            ManifoldBrokerCleanupError::Clock
        );
        let mut long = c.clone();
        long.statement.expires_at_ms = 70_000;
        resign(&mut long, &key);
        assert_eq!(
            a.authorize(&long, "request.cleanup", "clock.original", 150)
                .unwrap_err(),
            ManifoldBrokerCleanupError::Clock
        );
        a.challenge("clock.original", 150).unwrap();
        assert_eq!(
            a.authorize(&c, "request.cleanup", "clock.original", 150)
                .unwrap_err(),
            ManifoldBrokerCleanupError::Replay
        );
        let s = a.snapshot();
        assert!(ManifoldBrokerCleanupAuthority::restore(
            s.clone(),
            &s.binding,
            &s.anchor_sha256(),
            "clock.original",
            149
        )
        .is_err());
    }
    #[test]
    fn anchored_restore_checks_audit_replay_tombstones_and_missing_records() {
        let (mut a, key) = setup();
        let c = credential(&mut a, &key);
        a.authorize(&c, "request.cleanup", "clock.original", 150)
            .unwrap();
        let s = a.snapshot();
        let mut damaged = vec![];
        let mut v = s.clone();
        v.pending = None;
        damaged.push(v);
        let mut v = s.clone();
        v.events.pop();
        damaged.push(v);
        let mut v = s.clone();
        v.audit_sha256.clear();
        damaged.push(v);
        let mut v = s.clone();
        v.revision += 1;
        damaged.push(v);
        let mut v = s.clone();
        v.last_ms = 149;
        damaged.push(v);
        let mut v = s.clone();
        v.challenge = Some(c.statement.challenge.clone());
        damaged.push(v);
        for v in damaged {
            assert!(ManifoldBrokerCleanupAuthority::restore(
                v.clone(),
                &s.binding,
                &s.anchor_sha256(),
                "clock.original",
                160
            )
            .is_err());
            // Even a supplied matching digest cannot repair inconsistent closure.
            assert!(ManifoldBrokerCleanupAuthority::restore(
                v.clone(),
                &s.binding,
                &v.anchor_sha256(),
                "clock.original",
                160
            )
            .is_err());
        }
    }
    #[test]
    fn bounded_capacity_preserves_last_pending_slot() {
        let (mut a, key) = setup();
        for _ in 0..BROKER_CLEANUP_MAX_EVENTS - 2 {
            a.challenge("clock.original", 100).unwrap();
        }
        let c = credential(&mut a, &key);
        assert_eq!(
            a.challenge("clock.original", 100).unwrap_err(),
            ManifoldBrokerCleanupError::Capacity
        );
        a.authorize(&c, "request.cleanup", "clock.original", 150)
            .unwrap();
        assert_eq!(a.snapshot().events.len(), BROKER_CLEANUP_MAX_EVENTS);
        let s = a.snapshot();
        ManifoldBrokerCleanupAuthority::restore(
            s.clone(),
            &s.binding,
            &s.anchor_sha256(),
            "clock.original",
            150,
        )
        .unwrap();
    }
    #[test]
    fn strict_encoding_unknown_action_and_oversized_input_reject() {
        let (mut a, key) = setup();
        let mut c = credential(&mut a, &key);
        c.signature_hex = c.signature_hex.to_uppercase();
        assert!(a
            .authorize(&c, "request.cleanup", "clock.original", 150)
            .is_err());
        let mut v = serde_json::to_value(&c).unwrap();
        v["statement"]["action"] = serde_json::json!("start");
        assert!(serde_json::from_value::<ManifoldBrokerCleanupCredential>(v).is_err());
        let mut b = a.state.binding.clone();
        b.target.authority_host = "a".repeat(257);
        assert!(ManifoldBrokerCleanupAuthority::pin_before_start(b, 10).is_err());
    }
}
