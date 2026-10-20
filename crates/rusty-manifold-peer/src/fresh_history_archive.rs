//! Closed fresh-history custody data. No filesystem or platform authority.
use crate::*;
use ed25519_dalek::{Signature, VerifyingKey};
use rusty_manifold_model::{DottedId, SchemaId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ManifoldFreshArchiveOriginalBinding {
    Operator { original_id: String },
    IncomingFreshSetup { native_request_id: DottedId },
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldFreshArchiveOperationKind {
    EnrollmentPreparation,
    PairSetup,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldFreshArchiveOperationBinding {
    // Exact external product/transport DATA tag, not a Manifold schema namespace.
    // verify_fresh_history_custody_ack still requires the one closed literal.
    #[serde(rename = "$schema")]
    pub schema_id: String,
    pub native_request_id: DottedId,
    pub phase_request_id: DottedId,
    pub manifold_transaction_id: DottedId,
    pub kind: ManifoldFreshArchiveOperationKind,
    pub context_sha256: String,
    pub app_process_generation: u64,
    pub app_record_sha256: String,
    pub native_executor_generation: u64,
    pub config_sha256: String,
    pub original_binding: ManifoldFreshArchiveOriginalBinding,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldFreshHistoryCustodyContext {
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    pub archive_ordinal: u64,
    pub archive_body_sha256: String,
    pub prior_history_sha256: Option<String>,
    pub history_sha256: String,
    pub checkpoint_sha256: String,
    pub host_id: DottedId,
    pub provider_epoch_id: DottedId,
    pub local_peer_id: DottedId,
    pub source_snapshot_sha256: String,
    pub operation_binding: ManifoldFreshArchiveOperationBinding,
    pub storage_identity: String,
    pub signer_key_id: DottedId,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldFreshHistoryCustodyAck {
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    pub context: ManifoldFreshHistoryCustodyContext,
    pub signature_hex: String,
}

pub fn fresh_history_canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, &'static str> {
    let value = serde_json::to_value(value).map_err(|_| "fresh archive serialization")?;
    fn integer_json(v: &serde_json::Value) -> bool {
        match v {
            serde_json::Value::Number(n) => n.as_i64().is_some(),
            serde_json::Value::Array(a) => a.iter().all(integer_json),
            serde_json::Value::Object(o) => {
                o.keys()
                    .all(|k| !k.is_empty() && k.bytes().all(|b| (0x20..=0x7e).contains(&b)))
                    && o.values().all(integer_json)
            }
            _ => true,
        }
    }
    if !integer_json(&value) {
        return Err("fresh archive canonical integer data required");
    }
    // serde_json's default ordered map and Java's fixed canonical serializer
    // use sorted UTF8 keys; the closed schemas contain only ASCII field names.
    serde_json::to_vec(&value).map_err(|_| "fresh archive canonical serialization")
}
pub fn fresh_history_body_sha256(raw: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(raw))
}
pub fn fresh_history_digest<T: Serialize>(domain: &str, value: &T) -> Result<String, &'static str> {
    let mut h = Sha256::new();
    h.update(domain.as_bytes());
    h.update([0]);
    h.update(fresh_history_canonical(value)?);
    Ok(format!("sha256:{:x}", h.finalize()))
}
pub fn fresh_history_chain_sha256(
    prior: Option<&str>,
    ordinal: u64,
    body: &str,
) -> Result<String, &'static str> {
    fresh_history_digest(
        "rusty.manifold.peer.fresh_history_chain.v1",
        &serde_json::json!({"prior_history_sha256":prior,"archive_ordinal":ordinal,"archive_body_sha256":body}),
    )
}
pub fn fresh_history_custody_signing_bytes(
    c: &ManifoldFreshHistoryCustodyContext,
) -> Result<Vec<u8>, &'static str> {
    let mut out = b"rusty.manifold.peer.fresh_history_durable_custody.v1\0".to_vec();
    out.extend(fresh_history_canonical(c)?);
    Ok(out)
}
fn hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut bytes = [0; N];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(bytes)
}
pub fn verify_fresh_history_custody_ack(
    a: &ManifoldFreshHistoryCustodyAck,
    key: &ManifoldFreshPairSetupEnrollmentKey,
) -> Result<(), &'static str> {
    let c = &a.context;
    let b = &c.operation_binding;
    let actor_hex = |s: &str| s.len() == 64 && hex::<32>(s).is_some();
    if a.schema_id.as_str() != "rusty.manifold.peer.fresh_history_durable_ack.v1"
        || c.schema_id.as_str() != "rusty.manifold.peer.fresh_history_durable_context.v1"
        || c.archive_ordinal == 0
        || !fresh_pair_setup_sha256_is_valid(&c.archive_body_sha256)
        || !fresh_pair_setup_sha256_is_valid(&c.source_snapshot_sha256)
        || !fresh_pair_setup_sha256_is_valid(&c.checkpoint_sha256)
        || c.prior_history_sha256
            .as_ref()
            .is_some_and(|s| !fresh_pair_setup_sha256_is_valid(s))
        || (c.archive_ordinal == 1) != c.prior_history_sha256.is_none()
        || c.history_sha256
            != fresh_history_chain_sha256(
                c.prior_history_sha256.as_deref(),
                c.archive_ordinal,
                &c.archive_body_sha256,
            )?
        || c.signer_key_id != key.key_id
        || c.local_peer_id != key.peer_id
        || c.storage_identity.is_empty()
        || b.schema_id.as_str() != "rusty.quest.embedded_duplex.fresh_phase_operation_binding.v1"
        || b.app_process_generation == 0
        || b.native_executor_generation == 0
        || !actor_hex(&b.app_record_sha256)
        || !actor_hex(&b.config_sha256)
        || !fresh_pair_setup_sha256_is_valid(&b.context_sha256)
        || match &b.original_binding {
            ManifoldFreshArchiveOriginalBinding::Operator { original_id } => {
                original_id.len() != 32 || hex::<16>(original_id).is_none()
            }
            ManifoldFreshArchiveOriginalBinding::IncomingFreshSetup { native_request_id } => {
                native_request_id != &b.native_request_id
            }
        }
    {
        return Err("fresh history closed custody ACK");
    }
    let public = hex::<32>(&key.public_key_hex).ok_or("fresh archive key")?;
    let signature = hex::<64>(&a.signature_hex).ok_or("fresh archive signature")?;
    let verifying = VerifyingKey::from_bytes(&public).map_err(|_| "fresh archive key")?;
    if verifying.is_weak() {
        return Err("fresh archive weak key");
    }
    verifying
        .verify_strict(
            &fresh_history_custody_signing_bytes(c)?,
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| "fresh archive custody signature")
}

/// Canonical ID excludes its own ID and all signatures/derived context hashes.
pub fn fresh_pair_setup_transaction_id(
    c: &ManifoldFreshPairSetupContext,
) -> Result<DottedId, &'static str> {
    let preimage = serde_json::json!({"$schema":"rusty.manifold.peer.fresh_transaction_preimage.v1","kind":"pair_setup",
        "native_setup_request_id":c.native_setup_request_id,"native_phase_id":c.native_phase_id,
        "policy":c.policy,"peer_ids":c.peer_ids,"views":c.views,"issued_at_ms":c.issued_at_ms});
    let hash = fresh_history_digest("rusty.manifold.peer.fresh_transaction_id.v1", &preimage)?;
    DottedId::new(format!(
        "ceremony.duplex.{}",
        hash.strip_prefix("sha256:")
            .ok_or("fresh transaction digest")?
    ))
    .map_err(|_| "fresh transaction id")
}
pub fn fresh_phase_prepare_transaction_id(
    c: &ManifoldFreshPhasePrepareContext,
) -> Result<DottedId, &'static str> {
    let preimage = serde_json::json!({"$schema":"rusty.manifold.peer.fresh_transaction_preimage.v1","kind":"enrollment_preparation",
        "native_setup_request_id":c.setup_request_id,"native_phase_id":c.native_phase_id,"policy":c.policy,"selection":c.selection,
        "peer_ids":c.peer_ids,"views":c.views,"issued_at_ms":c.issued_at_ms});
    let hash = fresh_history_digest("rusty.manifold.peer.fresh_transaction_id.v1", &preimage)?;
    DottedId::new(format!(
        "ceremony.duplex.{}",
        hash.strip_prefix("sha256:")
            .ok_or("fresh transaction digest")?
    ))
    .map_err(|_| "fresh transaction id")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    fn id(s: &str) -> DottedId {
        DottedId::new(s).unwrap()
    }
    fn schema(s: &str) -> SchemaId {
        SchemaId::new(s).unwrap()
    }
    fn signed_ack(
        tag: &str,
    ) -> (
        ManifoldFreshHistoryCustodyAck,
        ManifoldFreshPairSetupEnrollmentKey,
    ) {
        let signing = SigningKey::from_bytes(&[7; 32]);
        let public = signing.verifying_key().to_bytes();
        let public_hash = format!("{:x}", Sha256::digest(public));
        let key = ManifoldFreshPairSetupEnrollmentKey {
            schema_id: schema("rusty.manifold.peer.fresh_setup_enrollment_key.v1"),
            peer_id: id("peer.fixture"),
            credential_id: id("credential.fixture"),
            trust_domain: id("trust.fixture"),
            key_id: id("key.fixture"),
            key_generation: 1,
            algorithm: ManifoldPeerCredentialAlgorithm::Ed25519,
            public_key_hex: public.iter().map(|b| format!("{b:02x}")).collect(),
            public_key_sha256: format!("sha256:{public_hash}"),
            key_fingerprint: id(&format!("fingerprint.{public_hash}")),
        };
        let body = format!("sha256:{}", "aa".repeat(32));
        let context = ManifoldFreshHistoryCustodyContext {
            schema_id: schema("rusty.manifold.peer.fresh_history_durable_context.v1"),
            archive_ordinal: 1,
            archive_body_sha256: body.clone(),
            prior_history_sha256: None,
            history_sha256: fresh_history_chain_sha256(None, 1, &body).unwrap(),
            checkpoint_sha256: body.clone(),
            host_id: id("host.fixture"),
            provider_epoch_id: id("epoch.fixture"),
            local_peer_id: key.peer_id.clone(),
            source_snapshot_sha256: body.clone(),
            storage_identity: "fixture.private.archive".into(),
            signer_key_id: key.key_id.clone(),
            operation_binding: ManifoldFreshArchiveOperationBinding {
                schema_id: tag.into(),
                native_request_id: id("ceremony.duplex.fixture"),
                phase_request_id: id("phase.fixture"),
                manifold_transaction_id: id("ceremony.duplex.transaction"),
                kind: ManifoldFreshArchiveOperationKind::PairSetup,
                context_sha256: body,
                app_process_generation: 1,
                app_record_sha256: "ab".repeat(32),
                native_executor_generation: 2,
                config_sha256: "cd".repeat(32),
                original_binding: ManifoldFreshArchiveOriginalBinding::Operator {
                    original_id: "11".repeat(16),
                },
            },
        };
        let signature_hex = signing
            .sign(&fresh_history_custody_signing_bytes(&context).unwrap())
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        (
            ManifoldFreshHistoryCustodyAck {
                schema_id: schema("rusty.manifold.peer.fresh_history_durable_ack.v1"),
                context,
                signature_hex,
            },
            key,
        )
    }
    #[test]
    fn external_product_tag_stays_closed_even_under_valid_selected_key_signature() {
        let tag = "rusty.quest.embedded_duplex.fresh_phase_operation_binding.v1";
        assert!(
            SchemaId::new(tag).is_err(),
            "Manifold namespace must remain closed"
        );
        let (ack, key) = signed_ack(tag);
        verify_fresh_history_custody_ack(&ack, &key).unwrap();
        let raw = serde_json::to_vec(&ack).unwrap();
        let restored: ManifoldFreshHistoryCustodyAck = serde_json::from_slice(&raw).unwrap();
        assert_eq!(restored, ack);
        assert_eq!(restored.context.operation_binding.schema_id, tag);
        for wrong in [
            "",
            "rusty.quest.embedded_duplex.fresh_phase_operation_binding.v2",
            "rusty.manifold.peer.fresh_phase_operation_binding.v1",
        ] {
            let (ack, key) = signed_ack(wrong);
            assert!(verify_fresh_history_custody_ack(&ack, &key).is_err());
        }
    }
    #[test]
    fn canonical_vectors_preserve_original_utf8_raw_and_domain_pins() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("fresh_history_canonical_vectors.json")).unwrap();
        for row in vectors["vectors"].as_array().unwrap() {
            let raw = fresh_history_canonical(&row["value"]).unwrap();
            assert_eq!(
                std::str::from_utf8(&raw).unwrap(),
                row["canonical_utf8"].as_str().unwrap()
            );
            assert_eq!(
                fresh_history_body_sha256(&raw),
                format!("sha256:{}", row["canonical_sha256"].as_str().unwrap())
            );
            assert_eq!(
                fresh_history_digest(
                    "rusty.manifold.peer.fresh_history_archive_source.v1",
                    &row["value"]
                )
                .unwrap(),
                row["archive_source_sha256"].as_str().unwrap()
            );
        }
        for row in vectors["refusal_values"].as_array().unwrap() {
            assert!(fresh_history_canonical(row).is_err());
        }
    }
}
