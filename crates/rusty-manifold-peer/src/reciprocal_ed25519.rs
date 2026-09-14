//! Additive carrier-independent reciprocal Ed25519 rendezvous authority.

use std::{collections::BTreeSet, net::IpAddr};

use ed25519_dalek::{Signature, VerifyingKey};
use rusty_manifold_model::{DottedId, Revision, SchemaId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    ManifoldPeerCredentialRecord, ManifoldPeerCredentialStatus, ManifoldPeerEnrollmentState,
    ManifoldRendezvousReceipt, ManifoldRendezvousRole, PEER_ENROLLMENT_STATE_SCHEMA,
    RENDEZVOUS_RECEIPT_SCHEMA,
};

/// Carrier-independent reciprocal-signature context schema.
pub const RECIPROCAL_ED25519_CONTEXT_SCHEMA: &str =
    "rusty.manifold.peer.reciprocal_ed25519_context.v2";
/// One device signature over the exact reciprocal context.
pub const RECIPROCAL_ED25519_SIGNATURE_SCHEMA: &str =
    "rusty.manifold.peer.reciprocal_ed25519_signature.v2";
/// Runtime Host review request schema.
pub const RECIPROCAL_ED25519_REVIEW_SCHEMA: &str =
    "rusty.manifold.peer.reciprocal_ed25519_review.v2";
/// Accepted/rejected reciprocal context receipt schema.
pub const RECIPROCAL_ED25519_RECEIPT_SCHEMA: &str =
    "rusty.manifold.peer.reciprocal_ed25519_receipt.v2";
/// Current reciprocal authority state schema.
pub const RECIPROCAL_ED25519_STATE_SCHEMA: &str = "rusty.manifold.peer.reciprocal_ed25519_state.v2";
/// Active mixed-topology reciprocal authority state.
pub const RECIPROCAL_ED25519_STATE_V3_SCHEMA: &str =
    "rusty.manifold.peer.reciprocal_ed25519_state.v3";
/// Explicit common-LAN pair topology contract.
pub const COMMON_LAN_PAIR_TOPOLOGY_CONTRACT_ID: &str =
    "rusty.manifold.peer.common_lan_pair_topology.v1";
/// Explicit common-LAN TCP carrier contract.
pub const COMMON_LAN_TCP_TRANSPORT_CONTRACT_ID: &str =
    "rusty.manifold.peer.common_lan_tcp_transport.v1";
/// Common-LAN reciprocal context schema.
pub const COMMON_LAN_RECIPROCAL_ED25519_CONTEXT_SCHEMA: &str =
    "rusty.manifold.peer.common_lan_reciprocal_ed25519_context.v1";
/// Common-LAN reciprocal signature schema.
pub const COMMON_LAN_RECIPROCAL_ED25519_SIGNATURE_SCHEMA: &str =
    "rusty.manifold.peer.common_lan_reciprocal_ed25519_signature.v1";
/// Common-LAN reciprocal review schema.
pub const COMMON_LAN_RECIPROCAL_ED25519_REVIEW_SCHEMA: &str =
    "rusty.manifold.peer.common_lan_reciprocal_ed25519_review.v1";
/// Common-LAN reciprocal receipt schema.
pub const COMMON_LAN_RECIPROCAL_ED25519_RECEIPT_SCHEMA: &str =
    "rusty.manifold.peer.common_lan_reciprocal_ed25519_receipt.v1";

const CONTEXT_DOMAIN: &[u8] = b"rusty.manifold.peer.reciprocal_ed25519_context.v2\0";
const COMMON_LAN_CONTEXT_DOMAIN: &[u8] =
    b"rusty.manifold.peer.common_lan_reciprocal_ed25519_context.v1\0";
const MAX_CONTEXT_TTL_MS: u64 = 120_000;
const MAX_RECIPROCAL_RECEIPTS: usize = 4_096;

/// Exact current Runtime Host revisions signed by both enrolled devices.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldReciprocalEd25519Revisions {
    /// Accepted low-rate peer authority revision.
    pub peer_authority_revision: Revision,
    /// Operator enrollment authority revision.
    pub enrollment_authority_revision: Revision,
    /// Legacy/BLE-compatible rendezvous projection revision.
    pub rendezvous_authority_revision: Revision,
    /// Reciprocal Ed25519 v2 authority revision.
    pub reciprocal_authority_revision: Revision,
    /// Peer-session authority revision.
    pub peer_session_authority_revision: Revision,
    /// Mesh authority revision.
    pub peer_mesh_authority_revision: Revision,
    /// Direct-lane lease authority revision.
    pub direct_lane_lease_authority_revision: Revision,
}

#[cfg(test)]
mod mixed_authority_tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn id(value: &str) -> DottedId {
        DottedId::new(value).expect("id")
    }
    fn revision(value: u64) -> Revision {
        Revision::new(value).expect("revision")
    }

    fn binding(
        peer: &str,
        role: ManifoldCommonLanPairRole,
        nonce: char,
    ) -> ManifoldCommonLanReciprocalEd25519PeerBinding {
        ManifoldCommonLanReciprocalEd25519PeerBinding {
            peer_id: id(peer),
            key_id: id(&format!("key.{peer}.001")),
            key_generation: 1,
            public_key_sha256: format!("sha256:{}", "1".repeat(64)),
            role,
            device_nonce_hex: nonce.to_string().repeat(64),
        }
    }

    fn context() -> ManifoldCommonLanReciprocalEd25519Context {
        ManifoldCommonLanReciprocalEd25519Context {
            schema_id: schema(COMMON_LAN_RECIPROCAL_ED25519_CONTEXT_SCHEMA),
            runtime_host_id: id("host.peer.test"),
            trust_policy_id: id("policy.peer.test"),
            trust_policy_revision: revision(1),
            correlation_id: id("correlation.common-lan.001"),
            revisions: ManifoldReciprocalEd25519Revisions {
                peer_authority_revision: revision(1),
                enrollment_authority_revision: revision(1),
                rendezvous_authority_revision: revision(1),
                reciprocal_authority_revision: revision(1),
                peer_session_authority_revision: revision(1),
                peer_mesh_authority_revision: revision(1),
                direct_lane_lease_authority_revision: revision(1),
            },
            initiator: binding("peer.alpha", ManifoldCommonLanPairRole::Initiator, 'a'),
            responder: binding("peer.beta", ManifoldCommonLanPairRole::Responder, 'b'),
            transport: ManifoldCommonLanTransportBinding {
                topology_contract_id: id(COMMON_LAN_PAIR_TOPOLOGY_CONTRACT_ID),
                transport_contract_id: id(COMMON_LAN_TCP_TRANSPORT_CONTRACT_ID),
                network_scope_id: id("network.scope.lab"),
                endpoints: vec![
                    ManifoldCommonLanEndpointBinding {
                        peer_id: id("peer.alpha"),
                        endpoint_id: id("endpoint.alpha.video"),
                        listen_ip_address: "192.168.49.2".into(),
                        listen_port: 46000,
                    },
                    ManifoldCommonLanEndpointBinding {
                        peer_id: id("peer.beta"),
                        endpoint_id: id("endpoint.beta.video"),
                        listen_ip_address: "192.168.49.3".into(),
                        listen_port: 46000,
                    },
                ],
                route_configuration_sha256: format!("sha256:{}", "2".repeat(64)),
            },
            coordinator_epoch: 1,
            issued_at_ms: 1000,
            expires_at_ms: 2000,
        }
    }

    fn signed_common(
        enrollment: &ManifoldPeerEnrollmentState,
        state: &ManifoldReciprocalEd25519AuthorityStateV3,
        alpha: &SigningKey,
        beta: &SigningKey,
        suffix: &str,
    ) -> ManifoldCommonLanReciprocalEd25519ReviewRequest {
        let mut context = context();
        context.correlation_id = id(&format!("correlation.common-lan.{suffix}"));
        context.revisions.peer_authority_revision = revision(4);
        context.revisions.enrollment_authority_revision = enrollment.authority_revision;
        context.revisions.reciprocal_authority_revision = state.authority_revision;
        context.expires_at_ms = 60_000;
        context.initiator.device_nonce_hex =
            format!("{:064x}", state.authority_revision.get() * 2 + 1);
        context.responder.device_nonce_hex =
            format!("{:064x}", state.authority_revision.get() * 2 + 2);
        for (binding, credential) in [
            (&mut context.initiator, &enrollment.credentials[0]),
            (&mut context.responder, &enrollment.credentials[1]),
        ] {
            binding.key_id = credential.key_id.clone();
            binding.key_generation = credential.key_generation;
            binding.public_key_sha256 = credential.public_key_sha256.clone();
        }
        let bytes = common_lan_reciprocal_ed25519_context_signing_bytes(&context);
        let hash = common_lan_reciprocal_ed25519_context_sha256(&context);
        let signature = |binding: &ManifoldCommonLanReciprocalEd25519PeerBinding,
                         key: &SigningKey| {
            ManifoldCommonLanReciprocalEd25519Signature {
                schema_id: schema(COMMON_LAN_RECIPROCAL_ED25519_SIGNATURE_SCHEMA),
                signer_peer_id: binding.peer_id.clone(),
                signer_key_id: binding.key_id.clone(),
                context_sha256: hash.clone(),
                signature_hex: encode_lower_hex(&key.sign(&bytes).to_bytes()),
            }
        };
        ManifoldCommonLanReciprocalEd25519ReviewRequest {
            schema_id: schema(COMMON_LAN_RECIPROCAL_ED25519_REVIEW_SCHEMA),
            request_id: id(&format!("request.common-lan.{suffix}")),
            initiator_signature: signature(&context.initiator, alpha),
            responder_signature: signature(&context.responder, beta),
            context,
        }
    }

    #[test]
    fn legacy_empty_migration_preserves_shared_guards() {
        let legacy = ManifoldReciprocalEd25519AuthorityState::empty();
        let mixed = migrate_reciprocal_ed25519_state_v2_to_v3(legacy.clone());
        assert_eq!(mixed.authority_revision, legacy.authority_revision);
        assert!(mixed.accepted_receipts.is_empty());
        assert!(reciprocal_ed25519_state_v3_is_well_formed(&mixed));

        let alpha = SigningKey::from_bytes(&[7; 32]);
        let beta = SigningKey::from_bytes(&[11; 32]);
        let enrollment = super::tests::enrollment(&alpha, &beta);
        let request = super::tests::signed(super::tests::context(&enrollment), &alpha, &beta);
        let host = id("host.peer.test");
        let policy = id("policy.peer.test");
        let (legacy, receipt) = review_and_apply_reciprocal_ed25519(
            &ManifoldReciprocalEd25519AuthorityState::empty(),
            &request,
            super::tests::runtime(&host, &policy, &enrollment),
            2_000,
        );
        assert!(receipt.accepted);
        let mixed = migrate_reciprocal_ed25519_state_v2_to_v3(legacy.clone());
        let ManifoldReciprocalEd25519ReceiptV3::WifiDirect(migrated) = &mixed.accepted_receipts[0]
        else {
            panic!("wifi migration")
        };
        assert_eq!(
            serde_json::to_value(migrated).unwrap(),
            serde_json::to_value(&legacy.accepted_receipts[0]).unwrap()
        );
        assert!(reciprocal_ed25519_state_v3_is_well_formed(&mixed));
    }

    #[test]
    fn signed_common_lan_bytes_bind_every_endpoint_and_reject_extra_tag_fields() {
        let original = context();
        let mut damaged = original.clone();
        damaged.transport.endpoints[0].listen_port += 1;
        assert_ne!(
            common_lan_reciprocal_ed25519_context_signing_bytes(&original),
            common_lan_reciprocal_ed25519_context_signing_bytes(&damaged)
        );
        let request = ManifoldReciprocalEd25519ReviewRequestV3::CommonLan(
            ManifoldCommonLanReciprocalEd25519ReviewRequest {
                schema_id: schema(COMMON_LAN_RECIPROCAL_ED25519_REVIEW_SCHEMA),
                request_id: id("request.common-lan.001"),
                context: original,
                initiator_signature: ManifoldCommonLanReciprocalEd25519Signature {
                    schema_id: schema(COMMON_LAN_RECIPROCAL_ED25519_SIGNATURE_SCHEMA),
                    signer_peer_id: id("peer.alpha"),
                    signer_key_id: id("key.peer.alpha.001"),
                    context_sha256: "sha256:x".into(),
                    signature_hex: "0".repeat(128),
                },
                responder_signature: ManifoldCommonLanReciprocalEd25519Signature {
                    schema_id: schema(COMMON_LAN_RECIPROCAL_ED25519_SIGNATURE_SCHEMA),
                    signer_peer_id: id("peer.beta"),
                    signer_key_id: id("key.peer.beta.001"),
                    context_sha256: "sha256:x".into(),
                    signature_hex: "0".repeat(128),
                },
            },
        );
        let mut value = serde_json::to_value(request).expect("json");
        value
            .as_object_mut()
            .expect("object")
            .insert("extra".into(), serde_json::json!(true));
        assert!(serde_json::from_value::<ManifoldReciprocalEd25519ReviewRequestV3>(value).is_err());
        assert!(
            serde_json::from_str::<ManifoldReciprocalEd25519ReviewRequestV3>(
                r#"{"topology_kind":"future","record":{}}"#
            )
            .is_err()
        );
    }

    #[test]
    fn common_lan_review_rejects_tampered_signed_fields_without_mutation() {
        let alpha = SigningKey::from_bytes(&[7; 32]);
        let beta = SigningKey::from_bytes(&[11; 32]);
        let enrollment = super::tests::enrollment(&alpha, &beta);
        let state = ManifoldReciprocalEd25519AuthorityStateV3::empty();
        let host = id("host.peer.test");
        let policy = id("policy.peer.test");
        let mutations: [fn(&mut ManifoldCommonLanReciprocalEd25519ReviewRequest); 7] = [
            |r| r.context.schema_id = schema("rusty.manifold.peer.wrong.v1"),
            |r| r.context.initiator.role = ManifoldCommonLanPairRole::Responder,
            |r| r.context.responder.device_nonce_hex = r.context.initiator.device_nonce_hex.clone(),
            |r| r.context.expires_at_ms = 2_000,
            |r| r.context.transport.endpoints[0].listen_port += 1,
            |r| r.context.initiator.key_id = id("key.peer.alpha.wrong"),
            |r| r.initiator_signature.signature_hex = "00".repeat(64),
        ];
        for (index, mutate) in mutations.into_iter().enumerate() {
            let mut request = signed_common(
                &enrollment,
                &state,
                &alpha,
                &beta,
                &format!("damage-{index}"),
            );
            mutate(&mut request);
            let (next, receipt) = review_and_apply_reciprocal_ed25519_v3(
                &state,
                &ManifoldReciprocalEd25519ReviewRequestV3::CommonLan(request),
                super::tests::runtime(&host, &policy, &enrollment),
                2_000,
            );
            assert_eq!(next, state, "damage case {index} mutated authority");
            assert!(
                matches!(receipt, ManifoldReciprocalEd25519ReceiptV3::CommonLan(value) if !value.accepted)
            );
        }

        let request = signed_common(&enrollment, &state, &alpha, &beta, "replay");
        let (next, receipt) = review_and_apply_reciprocal_ed25519_v3(
            &state,
            &ManifoldReciprocalEd25519ReviewRequestV3::CommonLan(request.clone()),
            super::tests::runtime(&host, &policy, &enrollment),
            2_000,
        );
        assert!(
            matches!(receipt, ManifoldReciprocalEd25519ReceiptV3::CommonLan(value) if value.accepted)
        );
        let (replayed, receipt) = review_and_apply_reciprocal_ed25519_v3(
            &next,
            &ManifoldReciprocalEd25519ReviewRequestV3::CommonLan(request),
            super::tests::runtime(&host, &policy, &enrollment),
            2_000,
        );
        assert_eq!(replayed, next);
        assert!(
            matches!(receipt, ManifoldReciprocalEd25519ReceiptV3::CommonLan(value)
            if value.rejection_reason == Some(ManifoldReciprocalEd25519RejectionReason::Replay))
        );
    }

    #[test]
    fn wifi_lan_wifi_uses_one_contiguous_shared_revision_history() {
        let alpha = SigningKey::from_bytes(&[7; 32]);
        let beta = SigningKey::from_bytes(&[11; 32]);
        let enrollment = super::tests::enrollment(&alpha, &beta);
        let host = id("host.peer.test");
        let policy = id("policy.peer.test");
        let mut state = ManifoldReciprocalEd25519AuthorityStateV3::empty();
        let first = super::tests::signed(super::tests::context(&enrollment), &alpha, &beta);
        let (next, first_receipt) = review_and_apply_reciprocal_ed25519_v3(
            &state,
            &ManifoldReciprocalEd25519ReviewRequestV3::WifiDirect(first),
            super::tests::runtime(&host, &policy, &enrollment),
            2_000,
        );
        assert!(matches!(
            first_receipt,
            ManifoldReciprocalEd25519ReceiptV3::WifiDirect(_)
        ));
        state = next;

        let mut lan = context();
        lan.trust_policy_revision = Revision::INITIAL;
        lan.revisions.peer_authority_revision = revision(4);
        lan.revisions.enrollment_authority_revision = enrollment.authority_revision;
        lan.revisions.reciprocal_authority_revision = state.authority_revision;
        lan.expires_at_ms = 60_000;
        for (binding, credential) in [
            (&mut lan.initiator, &enrollment.credentials[0]),
            (&mut lan.responder, &enrollment.credentials[1]),
        ] {
            binding.key_id = credential.key_id.clone();
            binding.key_generation = credential.key_generation;
            binding.public_key_sha256 = credential.public_key_sha256.clone();
        }
        let bytes = common_lan_reciprocal_ed25519_context_signing_bytes(&lan);
        let hash = common_lan_reciprocal_ed25519_context_sha256(&lan);
        let signature = |binding: &ManifoldCommonLanReciprocalEd25519PeerBinding,
                         key: &SigningKey| {
            ManifoldCommonLanReciprocalEd25519Signature {
                schema_id: schema(COMMON_LAN_RECIPROCAL_ED25519_SIGNATURE_SCHEMA),
                signer_peer_id: binding.peer_id.clone(),
                signer_key_id: binding.key_id.clone(),
                context_sha256: hash.clone(),
                signature_hex: encode_lower_hex(&key.sign(&bytes).to_bytes()),
            }
        };
        let request = ManifoldCommonLanReciprocalEd25519ReviewRequest {
            schema_id: schema(COMMON_LAN_RECIPROCAL_ED25519_REVIEW_SCHEMA),
            request_id: id("request.common-lan.mixed"),
            initiator_signature: signature(&lan.initiator, &alpha),
            responder_signature: signature(&lan.responder, &beta),
            context: lan,
        };
        let (next, lan_receipt) = review_and_apply_reciprocal_ed25519_v3(
            &state,
            &ManifoldReciprocalEd25519ReviewRequestV3::CommonLan(request),
            super::tests::runtime(&host, &policy, &enrollment),
            2_000,
        );
        assert!(
            matches!(lan_receipt, ManifoldReciprocalEd25519ReceiptV3::CommonLan(ref v) if v.accepted)
        );
        state = next;

        let mut third_context = super::tests::context(&enrollment);
        third_context.correlation_id = id("run.peer.test.003");
        third_context.group_owner.device_nonce_hex = "33".repeat(32);
        third_context.client.device_nonce_hex = "44".repeat(32);
        third_context.revisions.reciprocal_authority_revision = state.authority_revision;
        third_context.revisions.rendezvous_authority_revision = revision(2);
        let third = super::tests::signed(third_context, &alpha, &beta);
        let mut runtime = super::tests::runtime(&host, &policy, &enrollment);
        runtime.rendezvous_authority_revision = revision(2);
        let (state, third_receipt) = review_and_apply_reciprocal_ed25519_v3(
            &state,
            &ManifoldReciprocalEd25519ReviewRequestV3::WifiDirect(third),
            runtime,
            2_000,
        );
        assert!(
            matches!(third_receipt, ManifoldReciprocalEd25519ReceiptV3::WifiDirect(ref v) if v.accepted)
        );
        assert_eq!(state.authority_revision, revision(4));
        assert!(reciprocal_ed25519_state_v3_is_well_formed(&state));

        let mut damaged = state.clone();
        if let ManifoldReciprocalEd25519ReceiptV3::CommonLan(receipt) =
            &mut damaged.accepted_receipts[1]
        {
            receipt.transport.route_configuration_sha256 = "sha256:truncated".to_string();
        }
        assert!(!reciprocal_ed25519_state_v3_is_well_formed(&damaged));
        let mut damaged = state.clone();
        if let ManifoldReciprocalEd25519ReceiptV3::WifiDirect(receipt) =
            &mut damaged.accepted_receipts[0]
        {
            receipt.accepted = false;
        }
        assert!(!reciprocal_ed25519_state_v3_is_well_formed(&damaged));
    }

    #[test]
    fn lan_wifi_lan_uses_one_contiguous_shared_revision_history() {
        let alpha = SigningKey::from_bytes(&[7; 32]);
        let beta = SigningKey::from_bytes(&[11; 32]);
        let enrollment = super::tests::enrollment(&alpha, &beta);
        let host = id("host.peer.test");
        let policy = id("policy.peer.test");
        let mut state = ManifoldReciprocalEd25519AuthorityStateV3::empty();
        for step in 0..3 {
            let request = if step == 1 {
                let mut context = super::tests::context(&enrollment);
                context.correlation_id = id("run.peer.reverse.002");
                context.group_owner.device_nonce_hex = "55".repeat(32);
                context.client.device_nonce_hex = "66".repeat(32);
                context.revisions.reciprocal_authority_revision = state.authority_revision;
                ManifoldReciprocalEd25519ReviewRequestV3::WifiDirect(super::tests::signed(
                    context, &alpha, &beta,
                ))
            } else {
                ManifoldReciprocalEd25519ReviewRequestV3::CommonLan(signed_common(
                    &enrollment,
                    &state,
                    &alpha,
                    &beta,
                    &format!("reverse-{step}"),
                ))
            };
            let (next, receipt) = review_and_apply_reciprocal_ed25519_v3(
                &state,
                &request,
                super::tests::runtime(&host, &policy, &enrollment),
                2_000,
            );
            assert!(match receipt {
                ManifoldReciprocalEd25519ReceiptV3::WifiDirect(value) => value.accepted,
                ManifoldReciprocalEd25519ReceiptV3::CommonLan(value) => value.accepted,
            });
            state = next;
        }
        assert_eq!(state.authority_revision, revision(4));
        assert!(reciprocal_ed25519_state_v3_is_well_formed(&state));
    }

    #[test]
    fn common_lan_capacity_rejects_before_effect() {
        let alpha = SigningKey::from_bytes(&[7; 32]);
        let beta = SigningKey::from_bytes(&[11; 32]);
        let enrollment = super::tests::enrollment(&alpha, &beta);
        let host = id("host.peer.test");
        let policy = id("policy.peer.test");
        let empty = ManifoldReciprocalEd25519AuthorityStateV3::empty();
        let seed_request = signed_common(&enrollment, &empty, &alpha, &beta, "capacity-seed");
        let (_, seed) = review_and_apply_reciprocal_ed25519_v3(
            &empty,
            &ManifoldReciprocalEd25519ReviewRequestV3::CommonLan(seed_request),
            super::tests::runtime(&host, &policy, &enrollment),
            2_000,
        );
        let ManifoldReciprocalEd25519ReceiptV3::CommonLan(seed) = seed else {
            panic!("common receipt")
        };
        let mut full = ManifoldReciprocalEd25519AuthorityStateV3::empty();
        for index in 0..MAX_RECIPROCAL_RECEIPTS {
            let mut receipt = seed.clone();
            receipt.request_id = id(&format!("request.capacity.{index:04}"));
            receipt.receipt_id =
                derived("receipt.common-lan-reciprocal-ed25519", &receipt.request_id);
            receipt.correlation_id = id(&format!("correlation.capacity.{index:04}"));
            receipt.context_sha256 = format!("sha256:{index:064x}");
            receipt.device_nonce_sha256 = vec![
                format!("sha256:{:064x}", index * 2 + 1),
                format!("sha256:{:064x}", index * 2 + 2),
            ];
            receipt.prior_authority_revision = revision(index as u64 + 1);
            receipt.resulting_authority_revision = revision(index as u64 + 2);
            full.applied_request_ids.push(receipt.request_id.clone());
            full.consumed_correlation_ids
                .push(receipt.correlation_id.clone());
            full.consumed_context_sha256
                .push(receipt.context_sha256.clone());
            full.consumed_nonce_sha256
                .extend(receipt.device_nonce_sha256.clone());
            full.accepted_receipts
                .push(ManifoldReciprocalEd25519ReceiptV3::CommonLan(receipt));
        }
        full.authority_revision = revision(MAX_RECIPROCAL_RECEIPTS as u64 + 1);
        assert!(reciprocal_ed25519_state_v3_is_well_formed(&full));
        let request = signed_common(&enrollment, &full, &alpha, &beta, "capacity-overflow");
        let (next, receipt) = review_and_apply_reciprocal_ed25519_v3(
            &full,
            &ManifoldReciprocalEd25519ReviewRequestV3::CommonLan(request),
            super::tests::runtime(&host, &policy, &enrollment),
            2_000,
        );
        assert_eq!(next, full);
        assert!(
            matches!(receipt, ManifoldReciprocalEd25519ReceiptV3::CommonLan(value)
            if value.rejection_reason == Some(ManifoldReciprocalEd25519RejectionReason::CapacityExceeded))
        );
    }
}

/// One enrolled peer and its distinct device-generated nonce.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldReciprocalEd25519PeerBinding {
    /// Enrolled peer identity.
    pub peer_id: DottedId,
    /// Current enrolled key identity.
    pub key_id: DottedId,
    /// Monotonic enrolled key generation.
    pub key_generation: u64,
    /// Exact current enrolled public-key hash (`sha256:<lowerhex>`).
    pub public_key_sha256: String,
    /// Role signed by this peer.
    pub role: ManifoldRendezvousRole,
    /// Distinct 32-byte device-generated nonce as lowercase hex.
    pub device_nonce_hex: String,
}

/// Canonical context signed by both devices under their current enrolled keys.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldReciprocalEd25519Context {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Stable Runtime Host identity.
    pub runtime_host_id: DottedId,
    /// Exact immutable Runtime Host trust-policy identity.
    pub trust_policy_id: DottedId,
    /// Exact immutable Runtime Host trust-policy revision.
    pub trust_policy_revision: Revision,
    /// Run/correlation identity; replay is rejected across contexts.
    pub correlation_id: DottedId,
    /// Exact current authority revisions.
    pub revisions: ManifoldReciprocalEd25519Revisions,
    /// Group-owner peer binding.
    pub group_owner: ManifoldReciprocalEd25519PeerBinding,
    /// Client peer binding.
    pub client: ManifoldReciprocalEd25519PeerBinding,
    /// Exact topology contract proposed for platform adoption.
    pub topology_contract_id: DottedId,
    /// Coordinator epoch selected for this pair/context.
    pub coordinator_epoch: u64,
    /// Context creation time.
    pub issued_at_ms: u64,
    /// Context expiry time.
    pub expires_at_ms: u64,
}

/// One current enrolled device signature over the canonical context bytes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldReciprocalEd25519Signature {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Signing peer.
    pub signer_peer_id: DottedId,
    /// Exact enrolled key used to sign.
    pub signer_key_id: DottedId,
    /// SHA-256 of the canonical context bytes.
    pub context_sha256: String,
    /// Canonical lowercase-hex Ed25519 signature.
    pub signature_hex: String,
}

/// Revision-bound Runtime Host request for reciprocal signature review.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldReciprocalEd25519ReviewRequest {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Replay-protected request identity.
    pub request_id: DottedId,
    /// Exact signed context.
    pub context: ManifoldReciprocalEd25519Context,
    /// Group-owner signature.
    pub group_owner_signature: ManifoldReciprocalEd25519Signature,
    /// Client signature.
    pub client_signature: ManifoldReciprocalEd25519Signature,
}

/// Stable rejection reason for reciprocal Ed25519 review.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldReciprocalEd25519RejectionReason {
    /// Schema or canonical field shape mismatched.
    SchemaMismatch,
    /// Runtime Host identity or an authority revision mismatched.
    CrossContext,
    /// Request, context, or either device nonce was already consumed.
    Replay,
    /// Pair was self-referential or roles were not exact and reciprocal.
    InvalidPeerPair,
    /// Nonce was malformed, duplicated, or not device-distinct.
    InvalidNonce,
    /// Context was future-dated, expired, empty, or overlong.
    InvalidLifetime,
    /// One key was absent, rotated, revoked, expired, or generation-downgraded.
    CredentialNotCurrent,
    /// Signature identity/hash did not bind the exact context.
    SignatureBindingMismatch,
    /// Ed25519 verification failed.
    SignatureInvalid,
    /// Authority revision could not advance.
    RevisionExhausted,
    /// Active mixed replay or receipt storage is full.
    CapacityExceeded,
    /// Supplied current authority state was internally inconsistent.
    InvalidAuthorityState,
}

/// Accepted or rejected receipt for one exact reciprocal context.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldReciprocalEd25519Receipt {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Derived receipt identity.
    pub receipt_id: DottedId,
    /// Reviewed request identity.
    pub request_id: DottedId,
    /// Signed correlation identity.
    pub correlation_id: DottedId,
    /// Immutable trust-policy identity signed by both peers.
    pub trust_policy_id: DottedId,
    /// Immutable trust-policy revision signed by both peers.
    pub trust_policy_revision: Revision,
    /// SHA-256 of canonical signed context bytes.
    pub context_sha256: String,
    /// Exact sorted device-nonce digests consumed by this receipt.
    pub device_nonce_sha256: Vec<String>,
    /// Whether both current enrolled signatures were accepted.
    pub accepted: bool,
    /// Stable rejection reason.
    pub rejection_reason: Option<ManifoldReciprocalEd25519RejectionReason>,
    /// Exact canonical peer pair.
    pub peer_ids: Vec<DottedId>,
    /// Group-owner peer.
    pub group_owner_peer_id: DottedId,
    /// Client peer.
    pub client_peer_id: DottedId,
    /// Current signer key identities.
    pub signer_key_ids: Vec<DottedId>,
    /// Exact topology contract.
    pub topology_contract_id: DottedId,
    /// Coordinator epoch.
    pub coordinator_epoch: u64,
    /// Enrollment revision used for signature verification.
    pub enrollment_authority_revision: Revision,
    /// Prior reciprocal authority revision.
    pub prior_authority_revision: Revision,
    /// Resulting reciprocal authority revision.
    pub resulting_authority_revision: Revision,
    /// Prior generic rendezvous projection revision owned independently from
    /// the reciprocal v2 authority.
    pub compatibility_prior_authority_revision: Revision,
    /// Resulting generic rendezvous projection revision.
    pub compatibility_resulting_authority_revision: Revision,
    /// Receipt expiry.
    pub expires_at_ms: u64,
}

/// Current replay-protected reciprocal Ed25519 authority state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldReciprocalEd25519AuthorityState {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Current authority revision.
    pub authority_revision: Revision,
    /// Applied request identities.
    pub applied_request_ids: Vec<DottedId>,
    /// Consumed correlation identities.
    pub consumed_correlation_ids: Vec<DottedId>,
    /// Consumed canonical context hashes.
    pub consumed_context_sha256: Vec<String>,
    /// Consumed device nonce hashes.
    pub consumed_nonce_sha256: Vec<String>,
    /// Retained accepted receipts, sorted by receipt identity.
    pub accepted_receipts: Vec<ManifoldReciprocalEd25519Receipt>,
}

impl ManifoldReciprocalEd25519AuthorityState {
    /// Creates an empty revision-one authority.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            schema_id: schema(RECIPROCAL_ED25519_STATE_SCHEMA),
            authority_revision: Revision::INITIAL,
            applied_request_ids: Vec::new(),
            consumed_correlation_ids: Vec::new(),
            consumed_context_sha256: Vec::new(),
            consumed_nonce_sha256: Vec::new(),
            accepted_receipts: Vec::new(),
        }
    }
}

/// Carrier-neutral consent role for a fixed common-LAN pair.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldCommonLanPairRole {
    /// Peer that initiated this signed authority exchange.
    Initiator,
    /// Peer that answered this signed authority exchange.
    Responder,
}

/// One peer's advertised listening transport endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldCommonLanEndpointBinding {
    /// Enrolled peer owning the endpoint.
    pub peer_id: DottedId,
    /// Stable endpoint identity selected by the product.
    pub endpoint_id: DottedId,
    /// Canonical numeric unicast address.
    pub listen_ip_address: String,
    /// Nonzero listening port.
    pub listen_port: u16,
}

/// Exact peer-agreed fixed common-LAN carrier configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldCommonLanTransportBinding {
    /// Common-LAN topology contract.
    pub topology_contract_id: DottedId,
    /// TCP transport contract.
    pub transport_contract_id: DottedId,
    /// Opaque peer-agreed configuration identity, not OS evidence.
    pub network_scope_id: DottedId,
    /// Exactly two endpoints sorted by peer identity.
    pub endpoints: Vec<ManifoldCommonLanEndpointBinding>,
    /// Digest of the accepted packaged endpoint/route configuration.
    pub route_configuration_sha256: String,
}

/// One enrolled peer binding in a common-LAN reciprocal context.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldCommonLanReciprocalEd25519PeerBinding {
    /// Enrolled peer.
    pub peer_id: DottedId,
    /// Current enrolled key.
    pub key_id: DottedId,
    /// Current key generation.
    pub key_generation: u64,
    /// Current public-key digest.
    pub public_key_sha256: String,
    /// Neutral pair-consent role.
    pub role: ManifoldCommonLanPairRole,
    /// Distinct decoded 32-byte nonce in lowercase hex.
    pub device_nonce_hex: String,
}

/// Canonical common-LAN context signed by both enrolled peers.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldCommonLanReciprocalEd25519Context {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Stable Runtime Host.
    pub runtime_host_id: DottedId,
    /// Exact trust policy.
    pub trust_policy_id: DottedId,
    /// Exact trust-policy revision.
    pub trust_policy_revision: Revision,
    /// Replay-protected correlation.
    pub correlation_id: DottedId,
    /// Exact current authority revisions.
    pub revisions: ManifoldReciprocalEd25519Revisions,
    /// Initiating enrolled peer.
    pub initiator: ManifoldCommonLanReciprocalEd25519PeerBinding,
    /// Responding enrolled peer.
    pub responder: ManifoldCommonLanReciprocalEd25519PeerBinding,
    /// Exact carrier configuration.
    pub transport: ManifoldCommonLanTransportBinding,
    /// Pair coordinator epoch.
    pub coordinator_epoch: u64,
    /// Creation time.
    pub issued_at_ms: u64,
    /// Expiry time.
    pub expires_at_ms: u64,
}

/// One common-LAN peer signature.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldCommonLanReciprocalEd25519Signature {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Signing peer.
    pub signer_peer_id: DottedId,
    /// Signing key.
    pub signer_key_id: DottedId,
    /// Exact context digest.
    pub context_sha256: String,
    /// Canonical Ed25519 signature.
    pub signature_hex: String,
}

/// Review request containing both current signatures.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldCommonLanReciprocalEd25519ReviewRequest {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Replay-protected request.
    pub request_id: DottedId,
    /// Signed context.
    pub context: ManifoldCommonLanReciprocalEd25519Context,
    /// Initiator signature.
    pub initiator_signature: ManifoldCommonLanReciprocalEd25519Signature,
    /// Responder signature.
    pub responder_signature: ManifoldCommonLanReciprocalEd25519Signature,
}

/// Accepted common-LAN reciprocal authority receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldCommonLanReciprocalEd25519Receipt {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Stable receipt identity.
    pub receipt_id: DottedId,
    /// Reviewed request.
    pub request_id: DottedId,
    /// Signed correlation.
    pub correlation_id: DottedId,
    /// Trust-policy identity.
    pub trust_policy_id: DottedId,
    /// Trust-policy revision.
    pub trust_policy_revision: Revision,
    /// Canonical context digest.
    pub context_sha256: String,
    /// Consumed nonce digests.
    pub device_nonce_sha256: Vec<String>,
    /// Whether both signatures were accepted.
    pub accepted: bool,
    /// Closed rejection reason.
    pub rejection_reason: Option<ManifoldReciprocalEd25519RejectionReason>,
    /// Canonical peer pair.
    pub peer_ids: Vec<DottedId>,
    /// Initiator peer.
    pub initiator_peer_id: DottedId,
    /// Responder peer.
    pub responder_peer_id: DottedId,
    /// Current signer keys.
    pub signer_key_ids: Vec<DottedId>,
    /// Exact signed transport.
    pub transport: ManifoldCommonLanTransportBinding,
    /// Coordinator epoch.
    pub coordinator_epoch: u64,
    /// Enrollment revision.
    pub enrollment_authority_revision: Revision,
    /// Prior shared revision.
    pub prior_authority_revision: Revision,
    /// Resulting shared revision.
    pub resulting_authority_revision: Revision,
    /// Receipt expiry.
    pub expires_at_ms: u64,
}

/// Closed mixed reciprocal review input.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "topology_kind",
    content = "record",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ManifoldReciprocalEd25519ReviewRequestV3 {
    /// Exact legacy Wi-Fi Direct request.
    WifiDirect(ManifoldReciprocalEd25519ReviewRequest),
    /// Fixed common-LAN request.
    CommonLan(ManifoldCommonLanReciprocalEd25519ReviewRequest),
}

/// Closed mixed reciprocal receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "topology_kind",
    content = "record",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ManifoldReciprocalEd25519ReceiptV3 {
    /// Exact legacy Wi-Fi Direct receipt payload.
    WifiDirect(ManifoldReciprocalEd25519Receipt),
    /// Common-LAN receipt payload.
    CommonLan(ManifoldCommonLanReciprocalEd25519Receipt),
}

/// Active mixed reciprocal authority with one revision and replay history.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldReciprocalEd25519AuthorityStateV3 {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Shared authority revision.
    pub authority_revision: Revision,
    /// Shared request replay guard.
    pub applied_request_ids: Vec<DottedId>,
    /// Shared correlation replay guard.
    pub consumed_correlation_ids: Vec<DottedId>,
    /// Shared context replay guard.
    pub consumed_context_sha256: Vec<String>,
    /// Shared decoded-nonce replay guard.
    pub consumed_nonce_sha256: Vec<String>,
    /// Accepted mixed receipts.
    pub accepted_receipts: Vec<ManifoldReciprocalEd25519ReceiptV3>,
}

impl ManifoldReciprocalEd25519AuthorityStateV3 {
    /// Empty mixed authority.
    #[must_use]
    pub fn empty() -> Self {
        migrate_reciprocal_ed25519_state_v2_to_v3(ManifoldReciprocalEd25519AuthorityState::empty())
    }
}

/// Lossless migration from standalone v2 into active mixed v3.
#[must_use]
pub fn migrate_reciprocal_ed25519_state_v2_to_v3(
    legacy: ManifoldReciprocalEd25519AuthorityState,
) -> ManifoldReciprocalEd25519AuthorityStateV3 {
    ManifoldReciprocalEd25519AuthorityStateV3 {
        schema_id: schema(RECIPROCAL_ED25519_STATE_V3_SCHEMA),
        authority_revision: legacy.authority_revision,
        applied_request_ids: legacy.applied_request_ids,
        consumed_correlation_ids: legacy.consumed_correlation_ids,
        consumed_context_sha256: legacy.consumed_context_sha256,
        consumed_nonce_sha256: legacy.consumed_nonce_sha256,
        accepted_receipts: legacy
            .accepted_receipts
            .into_iter()
            .map(ManifoldReciprocalEd25519ReceiptV3::WifiDirect)
            .collect(),
    }
}

/// Exact Runtime Host context that must match the signed revision closure.
#[derive(Clone, Copy, Debug)]
pub struct ManifoldReciprocalEd25519RuntimeContext<'a> {
    /// Stable Runtime Host identity.
    pub runtime_host_id: &'a DottedId,
    /// Immutable Runtime Host trust-policy identity.
    pub trust_policy_id: &'a DottedId,
    /// Immutable Runtime Host trust-policy revision.
    pub trust_policy_revision: Revision,
    /// Accepted low-rate peer authority revision.
    pub peer_authority_revision: Revision,
    /// Current operator enrollment state.
    pub enrollment: &'a ManifoldPeerEnrollmentState,
    /// Current legacy/BLE-compatible rendezvous projection revision.
    pub rendezvous_authority_revision: Revision,
    /// Current peer-session authority revision.
    pub peer_session_authority_revision: Revision,
    /// Current mesh authority revision.
    pub peer_mesh_authority_revision: Revision,
    /// Current direct-lane lease authority revision.
    pub direct_lane_lease_authority_revision: Revision,
}

/// Canonical domain-separated bytes signed by both enrolled devices.
#[must_use]
pub fn reciprocal_ed25519_context_signing_bytes(
    context: &ManifoldReciprocalEd25519Context,
) -> Vec<u8> {
    let mut output = CONTEXT_DOMAIN.to_vec();
    for value in [
        context.schema_id.as_str(),
        context.runtime_host_id.as_str(),
        context.trust_policy_id.as_str(),
        context.correlation_id.as_str(),
        context.topology_contract_id.as_str(),
    ] {
        append_field(&mut output, value.as_bytes());
    }
    output.extend_from_slice(&context.trust_policy_revision.get().to_be_bytes());
    for revision in [
        context.revisions.peer_authority_revision,
        context.revisions.enrollment_authority_revision,
        context.revisions.rendezvous_authority_revision,
        context.revisions.reciprocal_authority_revision,
        context.revisions.peer_session_authority_revision,
        context.revisions.peer_mesh_authority_revision,
        context.revisions.direct_lane_lease_authority_revision,
    ] {
        output.extend_from_slice(&revision.get().to_be_bytes());
    }
    append_peer_binding(&mut output, &context.group_owner);
    append_peer_binding(&mut output, &context.client);
    output.extend_from_slice(&context.coordinator_epoch.to_be_bytes());
    output.extend_from_slice(&context.issued_at_ms.to_be_bytes());
    output.extend_from_slice(&context.expires_at_ms.to_be_bytes());
    output
}

/// SHA-256 identifier for the canonical context bytes.
#[must_use]
pub fn reciprocal_ed25519_context_sha256(context: &ManifoldReciprocalEd25519Context) -> String {
    format!(
        "sha256:{}",
        encode_lower_hex(&Sha256::digest(reciprocal_ed25519_context_signing_bytes(
            context
        )))
    )
}

/// Reviews and applies one exact reciprocal-signature context.
#[must_use]
pub fn review_and_apply_reciprocal_ed25519(
    state: &ManifoldReciprocalEd25519AuthorityState,
    request: &ManifoldReciprocalEd25519ReviewRequest,
    runtime: ManifoldReciprocalEd25519RuntimeContext<'_>,
    now_ms: u64,
) -> (
    ManifoldReciprocalEd25519AuthorityState,
    ManifoldReciprocalEd25519Receipt,
) {
    let context_sha256 = reciprocal_ed25519_context_sha256(&request.context);
    let nonce_hashes = nonce_hashes(&request.context);
    let rejection = validate_review(
        state,
        request,
        runtime,
        now_ms,
        &context_sha256,
        &nonce_hashes,
    )
    .err();
    let prior = state.authority_revision;
    let resulting = if rejection.is_none() {
        prior.next().unwrap_or(prior)
    } else {
        prior
    };
    let compatibility_prior = runtime.rendezvous_authority_revision;
    let compatibility_resulting = if rejection.is_none() {
        compatibility_prior.next().unwrap_or(compatibility_prior)
    } else {
        compatibility_prior
    };
    let rejection = if rejection.is_none()
        && (resulting == prior || compatibility_resulting == compatibility_prior)
    {
        Some(ManifoldReciprocalEd25519RejectionReason::RevisionExhausted)
    } else {
        rejection
    };
    let receipt = receipt(
        request,
        &context_sha256,
        prior,
        resulting,
        compatibility_prior,
        compatibility_resulting,
        rejection.clone(),
    );
    if rejection.is_some() {
        return (state.clone(), receipt);
    }
    let mut next = state.clone();
    next.authority_revision = resulting;
    next.applied_request_ids.push(request.request_id.clone());
    next.consumed_correlation_ids
        .push(request.context.correlation_id.clone());
    next.consumed_context_sha256.push(context_sha256);
    next.consumed_nonce_sha256.extend(nonce_hashes);
    next.accepted_receipts.push(receipt.clone());
    next.accepted_receipts
        .sort_by(|left, right| left.receipt_id.cmp(&right.receipt_id));
    (next, receipt)
}

/// Validates that a receipt is retained by the current reciprocal authority
/// and still uses the current enrolled keys.
pub fn validate_current_reciprocal_ed25519_receipt(
    state: &ManifoldReciprocalEd25519AuthorityState,
    enrollment: &ManifoldPeerEnrollmentState,
    receipt: &ManifoldReciprocalEd25519Receipt,
    now_ms: u64,
) -> Result<(), ManifoldReciprocalEd25519RejectionReason> {
    validate_state(state)?;
    if receipt.schema_id.as_str() != RECIPROCAL_ED25519_RECEIPT_SCHEMA
        || !receipt.accepted
        || receipt.rejection_reason.is_some()
        || receipt.expires_at_ms <= now_ms
        || !state
            .accepted_receipts
            .iter()
            .any(|candidate| candidate == receipt)
    {
        return Err(ManifoldReciprocalEd25519RejectionReason::CrossContext);
    }
    let mut current = Vec::new();
    for peer_id in &receipt.peer_ids {
        let credential = current_credential(enrollment, peer_id, now_ms)?;
        current.push(credential.key_id.clone());
    }
    current.sort();
    if current != receipt.signer_key_ids {
        return Err(ManifoldReciprocalEd25519RejectionReason::CredentialNotCurrent);
    }
    Ok(())
}

/// Projects one accepted v2 receipt into the existing generic rendezvous
/// receipt consumed by peer-session/direct-lane authority. The v2 receipt and
/// state remain the acceptance authority; this projection carries no new
/// decision fields.
#[must_use]
pub fn reciprocal_ed25519_compatibility_receipt(
    receipt: &ManifoldReciprocalEd25519Receipt,
) -> ManifoldRendezvousReceipt {
    let mut evidence_ids = vec![
        derived(
            "evidence.reciprocal-ed25519.group-owner",
            &receipt.correlation_id,
        ),
        derived(
            "evidence.reciprocal-ed25519.client",
            &receipt.correlation_id,
        ),
    ];
    evidence_ids.sort();
    ManifoldRendezvousReceipt {
        schema_id: schema(RENDEZVOUS_RECEIPT_SCHEMA),
        receipt_id: receipt.receipt_id.clone(),
        request_id: receipt.request_id.clone(),
        accepted: receipt.accepted,
        rejection_reason: None,
        peer_ids: receipt.peer_ids.clone(),
        group_owner_peer_id: Some(receipt.group_owner_peer_id.clone()),
        client_peer_id: Some(receipt.client_peer_id.clone()),
        signer_key_ids: receipt.signer_key_ids.clone(),
        evidence_ids,
        nonce_sha256: receipt.context_sha256.clone(),
        coordinator_epoch: receipt.coordinator_epoch,
        topology_contract_id: receipt.topology_contract_id.clone(),
        enrollment_authority_revision: receipt.enrollment_authority_revision,
        prior_authority_revision: receipt.compatibility_prior_authority_revision,
        resulting_authority_revision: receipt.compatibility_resulting_authority_revision,
        expires_at_ms: receipt.expires_at_ms,
    }
}

fn validate_review(
    state: &ManifoldReciprocalEd25519AuthorityState,
    request: &ManifoldReciprocalEd25519ReviewRequest,
    runtime: ManifoldReciprocalEd25519RuntimeContext<'_>,
    now_ms: u64,
    context_sha256: &str,
    nonce_hashes: &[String; 2],
) -> Result<(), ManifoldReciprocalEd25519RejectionReason> {
    validate_state(state)?;
    validate_wifi_review_fields(
        state.authority_revision,
        &state.applied_request_ids,
        &state.consumed_correlation_ids,
        &state.consumed_context_sha256,
        &state.consumed_nonce_sha256,
        request,
        runtime,
        now_ms,
        context_sha256,
        nonce_hashes,
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_wifi_review_fields(
    authority_revision: Revision,
    applied_request_ids: &[DottedId],
    consumed_correlation_ids: &[DottedId],
    consumed_context_sha256: &[String],
    consumed_nonce_sha256: &[String],
    request: &ManifoldReciprocalEd25519ReviewRequest,
    runtime: ManifoldReciprocalEd25519RuntimeContext<'_>,
    now_ms: u64,
    context_sha256: &str,
    nonce_hashes: &[String; 2],
) -> Result<(), ManifoldReciprocalEd25519RejectionReason> {
    let context = &request.context;
    if request.schema_id.as_str() != RECIPROCAL_ED25519_REVIEW_SCHEMA
        || context.schema_id.as_str() != RECIPROCAL_ED25519_CONTEXT_SCHEMA
        || request.group_owner_signature.schema_id.as_str() != RECIPROCAL_ED25519_SIGNATURE_SCHEMA
        || request.client_signature.schema_id.as_str() != RECIPROCAL_ED25519_SIGNATURE_SCHEMA
    {
        return Err(ManifoldReciprocalEd25519RejectionReason::SchemaMismatch);
    }
    if applied_request_ids.contains(&request.request_id)
        || consumed_correlation_ids.contains(&context.correlation_id)
        || consumed_context_sha256
            .iter()
            .any(|value| value == context_sha256)
        || nonce_hashes.iter().any(|nonce| {
            consumed_nonce_sha256
                .iter()
                .any(|consumed| consumed == nonce)
        })
    {
        return Err(ManifoldReciprocalEd25519RejectionReason::Replay);
    }
    if context.runtime_host_id != *runtime.runtime_host_id
        || context.trust_policy_id != *runtime.trust_policy_id
        || context.trust_policy_revision != runtime.trust_policy_revision
        || context.revisions.peer_authority_revision != runtime.peer_authority_revision
        || context.revisions.enrollment_authority_revision != runtime.enrollment.authority_revision
        || context.revisions.rendezvous_authority_revision != runtime.rendezvous_authority_revision
        || context.revisions.reciprocal_authority_revision != authority_revision
        || context.revisions.peer_session_authority_revision
            != runtime.peer_session_authority_revision
        || context.revisions.peer_mesh_authority_revision != runtime.peer_mesh_authority_revision
        || context.revisions.direct_lane_lease_authority_revision
            != runtime.direct_lane_lease_authority_revision
    {
        return Err(ManifoldReciprocalEd25519RejectionReason::CrossContext);
    }
    if context.group_owner.peer_id == context.client.peer_id
        || context.group_owner.key_id == context.client.key_id
        || context.coordinator_epoch == 0
        || context.group_owner.role != ManifoldRendezvousRole::GroupOwner
        || context.client.role != ManifoldRendezvousRole::Client
    {
        return Err(ManifoldReciprocalEd25519RejectionReason::InvalidPeerPair);
    }
    if !valid_nonce(&context.group_owner.device_nonce_hex)
        || !valid_nonce(&context.client.device_nonce_hex)
        || context.group_owner.device_nonce_hex == context.client.device_nonce_hex
    {
        return Err(ManifoldReciprocalEd25519RejectionReason::InvalidNonce);
    }
    if context.issued_at_ms > now_ms
        || context.expires_at_ms <= now_ms
        || context.expires_at_ms <= context.issued_at_ms
        || context.expires_at_ms.saturating_sub(context.issued_at_ms) > MAX_CONTEXT_TTL_MS
    {
        return Err(ManifoldReciprocalEd25519RejectionReason::InvalidLifetime);
    }
    let group_owner = validate_binding(runtime.enrollment, &context.group_owner, now_ms)?;
    let client = validate_binding(runtime.enrollment, &context.client, now_ms)?;
    verify_signature(
        &request.group_owner_signature,
        &context.group_owner,
        group_owner,
        context_sha256,
        context,
    )?;
    verify_signature(
        &request.client_signature,
        &context.client,
        client,
        context_sha256,
        context,
    )
}

fn validate_binding<'a>(
    enrollment: &'a ManifoldPeerEnrollmentState,
    binding: &ManifoldReciprocalEd25519PeerBinding,
    now_ms: u64,
) -> Result<&'a ManifoldPeerCredentialRecord, ManifoldReciprocalEd25519RejectionReason> {
    let credential = current_credential(enrollment, &binding.peer_id, now_ms)?;
    if credential.key_id != binding.key_id
        || credential.key_generation != binding.key_generation
        || credential.public_key_sha256 != binding.public_key_sha256
    {
        return Err(ManifoldReciprocalEd25519RejectionReason::CredentialNotCurrent);
    }
    Ok(credential)
}

fn current_credential<'a>(
    enrollment: &'a ManifoldPeerEnrollmentState,
    peer_id: &DottedId,
    now_ms: u64,
) -> Result<&'a ManifoldPeerCredentialRecord, ManifoldReciprocalEd25519RejectionReason> {
    if enrollment.schema_id.as_str() != PEER_ENROLLMENT_STATE_SCHEMA {
        return Err(ManifoldReciprocalEd25519RejectionReason::InvalidAuthorityState);
    }
    enrollment
        .credentials
        .iter()
        .find(|credential| {
            &credential.peer_id == peer_id
                && credential.status == ManifoldPeerCredentialStatus::Active
                && credential.valid_from_ms <= now_ms
                && credential.expires_at_ms > now_ms
        })
        .ok_or(ManifoldReciprocalEd25519RejectionReason::CredentialNotCurrent)
}

fn verify_signature(
    signature: &ManifoldReciprocalEd25519Signature,
    binding: &ManifoldReciprocalEd25519PeerBinding,
    credential: &ManifoldPeerCredentialRecord,
    context_sha256: &str,
    context: &ManifoldReciprocalEd25519Context,
) -> Result<(), ManifoldReciprocalEd25519RejectionReason> {
    if signature.signer_peer_id != binding.peer_id
        || signature.signer_key_id != binding.key_id
        || signature.context_sha256 != context_sha256
    {
        return Err(ManifoldReciprocalEd25519RejectionReason::SignatureBindingMismatch);
    }
    let public_key = decode_fixed_hex::<32>(&credential.public_key_hex)
        .ok_or(ManifoldReciprocalEd25519RejectionReason::CredentialNotCurrent)?;
    let signature_bytes = decode_fixed_hex::<64>(&signature.signature_hex)
        .ok_or(ManifoldReciprocalEd25519RejectionReason::SignatureInvalid)?;
    let key = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| ManifoldReciprocalEd25519RejectionReason::CredentialNotCurrent)?;
    key.verify_strict(
        &reciprocal_ed25519_context_signing_bytes(context),
        &Signature::from_bytes(&signature_bytes),
    )
    .map_err(|_| ManifoldReciprocalEd25519RejectionReason::SignatureInvalid)
}

fn validate_state(
    state: &ManifoldReciprocalEd25519AuthorityState,
) -> Result<(), ManifoldReciprocalEd25519RejectionReason> {
    let request_ids = state
        .accepted_receipts
        .iter()
        .map(|receipt| receipt.request_id.clone())
        .collect::<BTreeSet<_>>();
    let correlations = state
        .accepted_receipts
        .iter()
        .map(|receipt| receipt.correlation_id.clone())
        .collect::<BTreeSet<_>>();
    let contexts = state
        .accepted_receipts
        .iter()
        .map(|receipt| receipt.context_sha256.clone())
        .collect::<BTreeSet<_>>();
    let nonces = state
        .accepted_receipts
        .iter()
        .flat_map(|receipt| receipt.device_nonce_sha256.iter().cloned())
        .collect::<BTreeSet<_>>();
    let stored_request_ids = state
        .applied_request_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let stored_correlations = state
        .consumed_correlation_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let stored_contexts = state
        .consumed_context_sha256
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let stored_nonces = state
        .consumed_nonce_sha256
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut revisions = state.accepted_receipts.iter().collect::<Vec<_>>();
    revisions.sort_by_key(|receipt| receipt.resulting_authority_revision);
    if state.schema_id.as_str() != RECIPROCAL_ED25519_STATE_SCHEMA
        || !unique(&state.applied_request_ids)
        || !unique(&state.consumed_correlation_ids)
        || !unique(&state.consumed_context_sha256)
        || !unique(&state.consumed_nonce_sha256)
        || !state
            .accepted_receipts
            .windows(2)
            .all(|pair| pair[0].receipt_id < pair[1].receipt_id)
        || request_ids != stored_request_ids
        || correlations != stored_correlations
        || contexts != stored_contexts
        || nonces != stored_nonces
        || state.accepted_receipts.len()
            != usize::try_from(state.authority_revision.get().saturating_sub(1))
                .unwrap_or(usize::MAX)
        || revisions.iter().enumerate().any(|(index, receipt)| {
            let prior = Revision::new((index as u64) + 1).expect("nonzero revision");
            receipt.prior_authority_revision != prior
                || receipt.resulting_authority_revision != prior.next().unwrap_or(prior)
        })
        || state.accepted_receipts.iter().any(|receipt| {
            receipt.schema_id.as_str() != RECIPROCAL_ED25519_RECEIPT_SCHEMA
                || !receipt.accepted
                || receipt.rejection_reason.is_some()
                || receipt.resulting_authority_revision > state.authority_revision
                || receipt.receipt_id != derived("receipt.reciprocal-ed25519", &receipt.request_id)
                || receipt.peer_ids.len() != 2
                || receipt.peer_ids[0] >= receipt.peer_ids[1]
                || receipt.signer_key_ids.len() != 2
                || receipt.signer_key_ids[0] >= receipt.signer_key_ids[1]
                || receipt.device_nonce_sha256.len() != 2
                || receipt.device_nonce_sha256[0] >= receipt.device_nonce_sha256[1]
                || !valid_sha256(&receipt.context_sha256)
                || receipt
                    .device_nonce_sha256
                    .iter()
                    .any(|digest| !valid_sha256(digest))
                || receipt.compatibility_resulting_authority_revision
                    != receipt
                        .compatibility_prior_authority_revision
                        .next()
                        .unwrap_or(receipt.compatibility_prior_authority_revision)
        })
    {
        return Err(ManifoldReciprocalEd25519RejectionReason::InvalidAuthorityState);
    }
    Ok(())
}

fn receipt(
    request: &ManifoldReciprocalEd25519ReviewRequest,
    context_sha256: &str,
    prior: Revision,
    resulting: Revision,
    compatibility_prior: Revision,
    compatibility_resulting: Revision,
    rejection_reason: Option<ManifoldReciprocalEd25519RejectionReason>,
) -> ManifoldReciprocalEd25519Receipt {
    let context = &request.context;
    let mut device_nonce_sha256 = nonce_hashes(context).to_vec();
    device_nonce_sha256.sort();
    let mut peer_ids = vec![
        context.group_owner.peer_id.clone(),
        context.client.peer_id.clone(),
    ];
    peer_ids.sort();
    let mut signer_key_ids = vec![
        context.group_owner.key_id.clone(),
        context.client.key_id.clone(),
    ];
    signer_key_ids.sort();
    ManifoldReciprocalEd25519Receipt {
        schema_id: schema(RECIPROCAL_ED25519_RECEIPT_SCHEMA),
        receipt_id: derived("receipt.reciprocal-ed25519", &request.request_id),
        request_id: request.request_id.clone(),
        correlation_id: context.correlation_id.clone(),
        trust_policy_id: context.trust_policy_id.clone(),
        trust_policy_revision: context.trust_policy_revision,
        context_sha256: context_sha256.to_owned(),
        device_nonce_sha256,
        accepted: rejection_reason.is_none(),
        rejection_reason,
        peer_ids,
        group_owner_peer_id: context.group_owner.peer_id.clone(),
        client_peer_id: context.client.peer_id.clone(),
        signer_key_ids,
        topology_contract_id: context.topology_contract_id.clone(),
        coordinator_epoch: context.coordinator_epoch,
        enrollment_authority_revision: context.revisions.enrollment_authority_revision,
        prior_authority_revision: prior,
        resulting_authority_revision: resulting,
        compatibility_prior_authority_revision: compatibility_prior,
        compatibility_resulting_authority_revision: compatibility_resulting,
        expires_at_ms: context.expires_at_ms,
    }
}

/// Canonical domain-separated common-LAN context bytes.
#[must_use]
pub fn common_lan_reciprocal_ed25519_context_signing_bytes(
    context: &ManifoldCommonLanReciprocalEd25519Context,
) -> Vec<u8> {
    let mut output = COMMON_LAN_CONTEXT_DOMAIN.to_vec();
    for value in [
        context.schema_id.as_str(),
        context.runtime_host_id.as_str(),
        context.trust_policy_id.as_str(),
        context.correlation_id.as_str(),
    ] {
        append_field(&mut output, value.as_bytes());
    }
    output.extend_from_slice(&context.trust_policy_revision.get().to_be_bytes());
    for revision in [
        context.revisions.peer_authority_revision,
        context.revisions.enrollment_authority_revision,
        context.revisions.rendezvous_authority_revision,
        context.revisions.reciprocal_authority_revision,
        context.revisions.peer_session_authority_revision,
        context.revisions.peer_mesh_authority_revision,
        context.revisions.direct_lane_lease_authority_revision,
    ] {
        output.extend_from_slice(&revision.get().to_be_bytes());
    }
    for peer in [&context.initiator, &context.responder] {
        for value in [
            peer.peer_id.as_str(),
            peer.key_id.as_str(),
            &peer.public_key_sha256,
            &peer.device_nonce_hex,
        ] {
            append_field(&mut output, value.as_bytes());
        }
        output.extend_from_slice(&peer.key_generation.to_be_bytes());
        output.push(match peer.role {
            ManifoldCommonLanPairRole::Initiator => 1,
            ManifoldCommonLanPairRole::Responder => 2,
        });
    }
    for value in [
        context.transport.topology_contract_id.as_str(),
        context.transport.transport_contract_id.as_str(),
        context.transport.network_scope_id.as_str(),
        &context.transport.route_configuration_sha256,
    ] {
        append_field(&mut output, value.as_bytes());
    }
    for endpoint in &context.transport.endpoints {
        for value in [
            endpoint.peer_id.as_str(),
            endpoint.endpoint_id.as_str(),
            &endpoint.listen_ip_address,
        ] {
            append_field(&mut output, value.as_bytes());
        }
        output.extend_from_slice(&endpoint.listen_port.to_be_bytes());
    }
    output.extend_from_slice(&context.coordinator_epoch.to_be_bytes());
    output.extend_from_slice(&context.issued_at_ms.to_be_bytes());
    output.extend_from_slice(&context.expires_at_ms.to_be_bytes());
    output
}

/// SHA-256 of the exact common-LAN signed context.
#[must_use]
pub fn common_lan_reciprocal_ed25519_context_sha256(
    context: &ManifoldCommonLanReciprocalEd25519Context,
) -> String {
    format!(
        "sha256:{}",
        encode_lower_hex(&Sha256::digest(
            common_lan_reciprocal_ed25519_context_signing_bytes(context)
        ))
    )
}

/// Reviews either topology against one genuine shared revision/replay history.
#[must_use]
pub fn review_and_apply_reciprocal_ed25519_v3(
    state: &ManifoldReciprocalEd25519AuthorityStateV3,
    request: &ManifoldReciprocalEd25519ReviewRequestV3,
    runtime: ManifoldReciprocalEd25519RuntimeContext<'_>,
    now_ms: u64,
) -> (
    ManifoldReciprocalEd25519AuthorityStateV3,
    ManifoldReciprocalEd25519ReceiptV3,
) {
    match request {
        ManifoldReciprocalEd25519ReviewRequestV3::WifiDirect(request) => {
            let context_sha256 = reciprocal_ed25519_context_sha256(&request.context);
            let nonce_hashes = nonce_hashes(&request.context);
            let rejection = if reciprocal_ed25519_state_v3_is_well_formed(state) {
                validate_wifi_review_fields(
                    state.authority_revision,
                    &state.applied_request_ids,
                    &state.consumed_correlation_ids,
                    &state.consumed_context_sha256,
                    &state.consumed_nonce_sha256,
                    request,
                    runtime,
                    now_ms,
                    &context_sha256,
                    &nonce_hashes,
                )
                .err()
            } else {
                Some(ManifoldReciprocalEd25519RejectionReason::InvalidAuthorityState)
            };
            let prior = state.authority_revision;
            let resulting = rejection
                .is_none()
                .then(|| prior.next())
                .flatten()
                .unwrap_or(prior);
            let compatibility_prior = runtime.rendezvous_authority_revision;
            let compatibility_resulting = rejection
                .is_none()
                .then(|| compatibility_prior.next())
                .flatten()
                .unwrap_or(compatibility_prior);
            let mut rejection = rejection;
            if rejection.is_none() && resulting == prior {
                rejection = Some(ManifoldReciprocalEd25519RejectionReason::RevisionExhausted);
            }
            let receipt = receipt(
                request,
                &context_sha256,
                prior,
                resulting,
                compatibility_prior,
                compatibility_resulting,
                rejection.clone(),
            );
            let mixed = ManifoldReciprocalEd25519ReceiptV3::WifiDirect(receipt.clone());
            if rejection.is_some() {
                return (state.clone(), mixed);
            }
            apply_v3_receipt(
                state,
                request.request_id.clone(),
                request.context.correlation_id.clone(),
                context_sha256,
                nonce_hashes.to_vec(),
                mixed,
                resulting,
            )
        }
        ManifoldReciprocalEd25519ReviewRequestV3::CommonLan(request) => {
            review_and_apply_common_lan_reciprocal(state, request, runtime, now_ms)
        }
    }
}

fn review_and_apply_common_lan_reciprocal(
    state: &ManifoldReciprocalEd25519AuthorityStateV3,
    request: &ManifoldCommonLanReciprocalEd25519ReviewRequest,
    runtime: ManifoldReciprocalEd25519RuntimeContext<'_>,
    now_ms: u64,
) -> (
    ManifoldReciprocalEd25519AuthorityStateV3,
    ManifoldReciprocalEd25519ReceiptV3,
) {
    let hash = common_lan_reciprocal_ed25519_context_sha256(&request.context);
    let mut nonce_hashes = [
        decoded_nonce_sha256(&request.context.initiator.device_nonce_hex),
        decoded_nonce_sha256(&request.context.responder.device_nonce_hex),
    ];
    nonce_hashes.sort();
    let rejection =
        validate_common_lan_review(state, request, runtime, now_ms, &hash, &nonce_hashes).err();
    let prior = state.authority_revision;
    let resulting = rejection
        .is_none()
        .then(|| prior.next())
        .flatten()
        .unwrap_or(prior);
    let context = &request.context;
    let mut peer_ids = vec![
        context.initiator.peer_id.clone(),
        context.responder.peer_id.clone(),
    ];
    peer_ids.sort();
    let mut signer_key_ids = vec![
        context.initiator.key_id.clone(),
        context.responder.key_id.clone(),
    ];
    signer_key_ids.sort();
    let receipt = ManifoldCommonLanReciprocalEd25519Receipt {
        schema_id: schema(COMMON_LAN_RECIPROCAL_ED25519_RECEIPT_SCHEMA),
        receipt_id: derived("receipt.common-lan-reciprocal-ed25519", &request.request_id),
        request_id: request.request_id.clone(),
        correlation_id: context.correlation_id.clone(),
        trust_policy_id: context.trust_policy_id.clone(),
        trust_policy_revision: context.trust_policy_revision,
        context_sha256: hash.clone(),
        device_nonce_sha256: nonce_hashes.to_vec(),
        accepted: rejection.is_none(),
        rejection_reason: rejection.clone(),
        peer_ids,
        initiator_peer_id: context.initiator.peer_id.clone(),
        responder_peer_id: context.responder.peer_id.clone(),
        signer_key_ids,
        transport: context.transport.clone(),
        coordinator_epoch: context.coordinator_epoch,
        enrollment_authority_revision: context.revisions.enrollment_authority_revision,
        prior_authority_revision: prior,
        resulting_authority_revision: resulting,
        expires_at_ms: context.expires_at_ms,
    };
    let mixed = ManifoldReciprocalEd25519ReceiptV3::CommonLan(receipt);
    if rejection.is_some() {
        return (state.clone(), mixed);
    }
    apply_v3_receipt(
        state,
        request.request_id.clone(),
        context.correlation_id.clone(),
        hash,
        nonce_hashes.to_vec(),
        mixed,
        resulting,
    )
}

fn apply_v3_receipt(
    state: &ManifoldReciprocalEd25519AuthorityStateV3,
    request_id: DottedId,
    correlation_id: DottedId,
    context_sha256: String,
    nonce_hashes: Vec<String>,
    receipt: ManifoldReciprocalEd25519ReceiptV3,
    resulting: Revision,
) -> (
    ManifoldReciprocalEd25519AuthorityStateV3,
    ManifoldReciprocalEd25519ReceiptV3,
) {
    let mut next = state.clone();
    next.authority_revision = resulting;
    next.applied_request_ids.push(request_id);
    next.consumed_correlation_ids.push(correlation_id);
    next.consumed_context_sha256.push(context_sha256);
    next.consumed_nonce_sha256.extend(nonce_hashes);
    next.accepted_receipts.push(receipt.clone());
    (next, receipt)
}

fn validate_common_lan_review(
    state: &ManifoldReciprocalEd25519AuthorityStateV3,
    request: &ManifoldCommonLanReciprocalEd25519ReviewRequest,
    runtime: ManifoldReciprocalEd25519RuntimeContext<'_>,
    now_ms: u64,
    hash: &str,
    nonce_hashes: &[String; 2],
) -> Result<(), ManifoldReciprocalEd25519RejectionReason> {
    if !reciprocal_ed25519_state_v3_is_well_formed(state) {
        return Err(ManifoldReciprocalEd25519RejectionReason::InvalidAuthorityState);
    }
    let context = &request.context;
    if request.schema_id.as_str() != COMMON_LAN_RECIPROCAL_ED25519_REVIEW_SCHEMA
        || context.schema_id.as_str() != COMMON_LAN_RECIPROCAL_ED25519_CONTEXT_SCHEMA
        || request.initiator_signature.schema_id.as_str()
            != COMMON_LAN_RECIPROCAL_ED25519_SIGNATURE_SCHEMA
        || request.responder_signature.schema_id.as_str()
            != COMMON_LAN_RECIPROCAL_ED25519_SIGNATURE_SCHEMA
    {
        return Err(ManifoldReciprocalEd25519RejectionReason::SchemaMismatch);
    }
    if state.applied_request_ids.contains(&request.request_id)
        || state
            .consumed_correlation_ids
            .contains(&context.correlation_id)
        || state
            .consumed_context_sha256
            .iter()
            .any(|value| value == hash)
        || nonce_hashes
            .iter()
            .any(|value| state.consumed_nonce_sha256.contains(value))
    {
        return Err(ManifoldReciprocalEd25519RejectionReason::Replay);
    }
    if state.accepted_receipts.len() >= MAX_RECIPROCAL_RECEIPTS
        || state.applied_request_ids.len() >= MAX_RECIPROCAL_RECEIPTS
        || state.consumed_correlation_ids.len() >= MAX_RECIPROCAL_RECEIPTS
        || state.consumed_context_sha256.len() >= MAX_RECIPROCAL_RECEIPTS
        || state.consumed_nonce_sha256.len() > MAX_RECIPROCAL_RECEIPTS * 2 - 2
    {
        return Err(ManifoldReciprocalEd25519RejectionReason::CapacityExceeded);
    }
    if context.runtime_host_id != *runtime.runtime_host_id
        || context.trust_policy_id != *runtime.trust_policy_id
        || context.trust_policy_revision != runtime.trust_policy_revision
        || context.revisions.peer_authority_revision != runtime.peer_authority_revision
        || context.revisions.enrollment_authority_revision != runtime.enrollment.authority_revision
        || context.revisions.rendezvous_authority_revision != runtime.rendezvous_authority_revision
        || context.revisions.reciprocal_authority_revision != state.authority_revision
        || context.revisions.peer_session_authority_revision
            != runtime.peer_session_authority_revision
        || context.revisions.peer_mesh_authority_revision != runtime.peer_mesh_authority_revision
        || context.revisions.direct_lane_lease_authority_revision
            != runtime.direct_lane_lease_authority_revision
    {
        return Err(ManifoldReciprocalEd25519RejectionReason::CrossContext);
    }
    if context.initiator.role != ManifoldCommonLanPairRole::Initiator
        || context.responder.role != ManifoldCommonLanPairRole::Responder
        || context.initiator.peer_id == context.responder.peer_id
        || context.initiator.key_id == context.responder.key_id
        || context.coordinator_epoch == 0
        || !common_lan_transport_is_valid(&context.transport)
        || context
            .transport
            .endpoints
            .iter()
            .map(|v| &v.peer_id)
            .collect::<BTreeSet<_>>()
            != [&context.initiator.peer_id, &context.responder.peer_id]
                .into_iter()
                .collect()
    {
        return Err(ManifoldReciprocalEd25519RejectionReason::InvalidPeerPair);
    }
    if !valid_nonce(&context.initiator.device_nonce_hex)
        || !valid_nonce(&context.responder.device_nonce_hex)
        || context.initiator.device_nonce_hex == context.responder.device_nonce_hex
    {
        return Err(ManifoldReciprocalEd25519RejectionReason::InvalidNonce);
    }
    if context.issued_at_ms > now_ms
        || context.expires_at_ms <= now_ms
        || context.expires_at_ms.saturating_sub(context.issued_at_ms) > MAX_CONTEXT_TTL_MS
    {
        return Err(ManifoldReciprocalEd25519RejectionReason::InvalidLifetime);
    }
    let initiator = validate_common_binding(runtime.enrollment, &context.initiator, now_ms)?;
    let responder = validate_common_binding(runtime.enrollment, &context.responder, now_ms)?;
    verify_common_signature(
        &request.initiator_signature,
        &context.initiator,
        initiator,
        hash,
        context,
    )?;
    verify_common_signature(
        &request.responder_signature,
        &context.responder,
        responder,
        hash,
        context,
    )
}

fn validate_common_binding<'a>(
    enrollment: &'a ManifoldPeerEnrollmentState,
    binding: &ManifoldCommonLanReciprocalEd25519PeerBinding,
    now_ms: u64,
) -> Result<&'a ManifoldPeerCredentialRecord, ManifoldReciprocalEd25519RejectionReason> {
    let credential = current_credential(enrollment, &binding.peer_id, now_ms)?;
    (credential.key_id == binding.key_id
        && credential.key_generation == binding.key_generation
        && credential.public_key_sha256 == binding.public_key_sha256)
        .then_some(credential)
        .ok_or(ManifoldReciprocalEd25519RejectionReason::CredentialNotCurrent)
}

fn verify_common_signature(
    signature: &ManifoldCommonLanReciprocalEd25519Signature,
    binding: &ManifoldCommonLanReciprocalEd25519PeerBinding,
    credential: &ManifoldPeerCredentialRecord,
    hash: &str,
    context: &ManifoldCommonLanReciprocalEd25519Context,
) -> Result<(), ManifoldReciprocalEd25519RejectionReason> {
    if signature.signer_peer_id != binding.peer_id
        || signature.signer_key_id != binding.key_id
        || signature.context_sha256 != hash
    {
        return Err(ManifoldReciprocalEd25519RejectionReason::SignatureBindingMismatch);
    }
    let public_key = decode_fixed_hex::<32>(&credential.public_key_hex)
        .ok_or(ManifoldReciprocalEd25519RejectionReason::CredentialNotCurrent)?;
    let signature_bytes = decode_fixed_hex::<64>(&signature.signature_hex)
        .ok_or(ManifoldReciprocalEd25519RejectionReason::SignatureInvalid)?;
    VerifyingKey::from_bytes(&public_key)
        .map_err(|_| ManifoldReciprocalEd25519RejectionReason::CredentialNotCurrent)?
        .verify_strict(
            &common_lan_reciprocal_ed25519_context_signing_bytes(context),
            &Signature::from_bytes(&signature_bytes),
        )
        .map_err(|_| ManifoldReciprocalEd25519RejectionReason::SignatureInvalid)
}

/// Revalidates one retained mixed receipt and both current enrolled keys.
pub fn validate_current_reciprocal_ed25519_receipt_v3(
    state: &ManifoldReciprocalEd25519AuthorityStateV3,
    enrollment: &ManifoldPeerEnrollmentState,
    receipt: &ManifoldReciprocalEd25519ReceiptV3,
    first_peer_id: &DottedId,
    second_peer_id: &DottedId,
    now_ms: u64,
) -> Result<(), ManifoldReciprocalEd25519RejectionReason> {
    if !reciprocal_ed25519_state_v3_is_well_formed(state)
        || !state.accepted_receipts.contains(receipt)
    {
        return Err(ManifoldReciprocalEd25519RejectionReason::InvalidAuthorityState);
    }
    let (accepted, rejection, expires, peers, keys) = match receipt {
        ManifoldReciprocalEd25519ReceiptV3::WifiDirect(value) => (
            value.accepted,
            value.rejection_reason.as_ref(),
            value.expires_at_ms,
            &value.peer_ids,
            &value.signer_key_ids,
        ),
        ManifoldReciprocalEd25519ReceiptV3::CommonLan(value) => (
            value.accepted,
            value.rejection_reason.as_ref(),
            value.expires_at_ms,
            &value.peer_ids,
            &value.signer_key_ids,
        ),
    };
    let mut expected = vec![first_peer_id.clone(), second_peer_id.clone()];
    expected.sort();
    if !accepted || rejection.is_some() || expires <= now_ms || peers != &expected {
        return Err(ManifoldReciprocalEd25519RejectionReason::CrossContext);
    }
    let mut current = expected
        .iter()
        .map(|peer| current_credential(enrollment, peer, now_ms).map(|value| value.key_id.clone()))
        .collect::<Result<Vec<_>, _>>()?;
    current.sort();
    (current == *keys)
        .then_some(())
        .ok_or(ManifoldReciprocalEd25519RejectionReason::CredentialNotCurrent)
}

fn decoded_nonce_sha256(value: &str) -> String {
    decode_fixed_hex::<32>(value).map_or_else(
        || "sha256:invalid".to_string(),
        |decoded| format!("sha256:{}", encode_lower_hex(&Sha256::digest(decoded))),
    )
}

/// Validates active mixed-state structural and shared-revision invariants.
#[must_use]
pub fn reciprocal_ed25519_state_v3_is_well_formed(
    state: &ManifoldReciprocalEd25519AuthorityStateV3,
) -> bool {
    if state.schema_id.as_str() != RECIPROCAL_ED25519_STATE_V3_SCHEMA
        || !unique(&state.applied_request_ids)
        || !unique(&state.consumed_correlation_ids)
        || !unique(&state.consumed_context_sha256)
        || !unique(&state.consumed_nonce_sha256)
        || state.accepted_receipts.len()
            != usize::try_from(state.authority_revision.get().saturating_sub(1))
                .unwrap_or(usize::MAX)
        || state.accepted_receipts.len() > MAX_RECIPROCAL_RECEIPTS
        || state.applied_request_ids.len() > MAX_RECIPROCAL_RECEIPTS
        || state.consumed_correlation_ids.len() > MAX_RECIPROCAL_RECEIPTS
        || state.consumed_context_sha256.len() > MAX_RECIPROCAL_RECEIPTS
        || state.consumed_nonce_sha256.len() > MAX_RECIPROCAL_RECEIPTS * 2
    {
        return false;
    }
    let mut revisions = state
        .accepted_receipts
        .iter()
        .map(|receipt| match receipt {
            ManifoldReciprocalEd25519ReceiptV3::WifiDirect(value) => (
                value.request_id.clone(),
                value.correlation_id.clone(),
                value.context_sha256.clone(),
                value.device_nonce_sha256.clone(),
                value.prior_authority_revision,
                value.resulting_authority_revision,
            ),
            ManifoldReciprocalEd25519ReceiptV3::CommonLan(value) => (
                value.request_id.clone(),
                value.correlation_id.clone(),
                value.context_sha256.clone(),
                value.device_nonce_sha256.clone(),
                value.prior_authority_revision,
                value.resulting_authority_revision,
            ),
        })
        .collect::<Vec<_>>();
    revisions.sort_by_key(|value| value.5);
    let request_ids = revisions
        .iter()
        .map(|v| v.0.clone())
        .collect::<BTreeSet<_>>();
    let correlations = revisions
        .iter()
        .map(|v| v.1.clone())
        .collect::<BTreeSet<_>>();
    let contexts = revisions
        .iter()
        .map(|v| v.2.clone())
        .collect::<BTreeSet<_>>();
    let nonces = revisions
        .iter()
        .flat_map(|v| v.3.iter().cloned())
        .collect::<BTreeSet<_>>();
    let records_valid = state.accepted_receipts.iter().all(|receipt| match receipt {
        ManifoldReciprocalEd25519ReceiptV3::WifiDirect(value) => {
            value.schema_id.as_str() == RECIPROCAL_ED25519_RECEIPT_SCHEMA
                && value.receipt_id == derived("receipt.reciprocal-ed25519", &value.request_id)
                && value.accepted
                && value.rejection_reason.is_none()
                && value.peer_ids.len() == 2
                && value.peer_ids[0] < value.peer_ids[1]
                && value.signer_key_ids.len() == 2
                && value.signer_key_ids[0] < value.signer_key_ids[1]
                && value.device_nonce_sha256.len() == 2
                && value.device_nonce_sha256[0] < value.device_nonce_sha256[1]
                && valid_sha256(&value.context_sha256)
                && value
                    .device_nonce_sha256
                    .iter()
                    .all(|digest| valid_sha256(digest))
                && value.group_owner_peer_id != value.client_peer_id
                && value.peer_ids.contains(&value.group_owner_peer_id)
                && value.peer_ids.contains(&value.client_peer_id)
                && value.compatibility_resulting_authority_revision
                    == value
                        .compatibility_prior_authority_revision
                        .next()
                        .unwrap_or(value.compatibility_prior_authority_revision)
        }
        ManifoldReciprocalEd25519ReceiptV3::CommonLan(value) => {
            value.schema_id.as_str() == COMMON_LAN_RECIPROCAL_ED25519_RECEIPT_SCHEMA
                && value.receipt_id
                    == derived("receipt.common-lan-reciprocal-ed25519", &value.request_id)
                && value.accepted
                && value.rejection_reason.is_none()
                && value.peer_ids.len() == 2
                && value.peer_ids[0] < value.peer_ids[1]
                && value.signer_key_ids.len() == 2
                && value.signer_key_ids[0] < value.signer_key_ids[1]
                && value.device_nonce_sha256.len() == 2
                && value.device_nonce_sha256[0] < value.device_nonce_sha256[1]
                && valid_sha256(&value.context_sha256)
                && value
                    .device_nonce_sha256
                    .iter()
                    .all(|digest| valid_sha256(digest))
                && value.initiator_peer_id != value.responder_peer_id
                && value.peer_ids.contains(&value.initiator_peer_id)
                && value.peer_ids.contains(&value.responder_peer_id)
                && common_lan_transport_is_valid(&value.transport)
        }
    });
    records_valid
        && request_ids == state.applied_request_ids.iter().cloned().collect()
        && correlations == state.consumed_correlation_ids.iter().cloned().collect()
        && contexts == state.consumed_context_sha256.iter().cloned().collect()
        && nonces == state.consumed_nonce_sha256.iter().cloned().collect()
        && revisions.iter().enumerate().all(|(index, value)| {
            let prior = Revision::new(index as u64 + 1).expect("nonzero revision");
            value.4 == prior && value.5 == prior.next().unwrap_or(prior)
        })
}

fn common_lan_transport_is_valid(binding: &ManifoldCommonLanTransportBinding) -> bool {
    binding.topology_contract_id.as_str() == COMMON_LAN_PAIR_TOPOLOGY_CONTRACT_ID
        && binding.transport_contract_id.as_str() == COMMON_LAN_TCP_TRANSPORT_CONTRACT_ID
        && valid_sha256(&binding.route_configuration_sha256)
        && binding.endpoints.len() == 2
        && binding.endpoints[0].peer_id < binding.endpoints[1].peer_id
        && binding.endpoints.iter().all(|endpoint| {
            endpoint.listen_port != 0
                && endpoint
                    .listen_ip_address
                    .parse::<IpAddr>()
                    .ok()
                    .is_some_and(|address| {
                        address.to_string() == endpoint.listen_ip_address
                            && !address.is_unspecified()
                            && !address.is_loopback()
                            && !address.is_multicast()
                    })
        })
}

fn nonce_hashes(context: &ManifoldReciprocalEd25519Context) -> [String; 2] {
    [
        format!(
            "sha256:{}",
            encode_lower_hex(&Sha256::digest(
                decode_fixed_hex::<32>(&context.group_owner.device_nonce_hex).unwrap_or([0; 32])
            ))
        ),
        format!(
            "sha256:{}",
            encode_lower_hex(&Sha256::digest(
                decode_fixed_hex::<32>(&context.client.device_nonce_hex).unwrap_or([0; 32])
            ))
        ),
    ]
}

fn append_peer_binding(output: &mut Vec<u8>, binding: &ManifoldReciprocalEd25519PeerBinding) {
    for value in [
        binding.peer_id.as_str(),
        binding.key_id.as_str(),
        binding.public_key_sha256.as_str(),
        match binding.role {
            ManifoldRendezvousRole::GroupOwner => "group_owner",
            ManifoldRendezvousRole::Client => "client",
        },
    ] {
        append_field(output, value.as_bytes());
    }
    output.extend_from_slice(&binding.key_generation.to_be_bytes());
    if let Some(nonce) = decode_fixed_hex::<32>(&binding.device_nonce_hex) {
        output.extend_from_slice(&nonce);
    } else {
        append_field(output, binding.device_nonce_hex.as_bytes());
    }
}

fn append_field(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}

fn valid_nonce(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn decode_fixed_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 {
        return None;
    }
    let mut output = [0_u8; N];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(chunk[0])? << 4) | hex_nibble(chunk[1])?;
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

fn unique<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1]) || {
        let mut refs = values.iter().collect::<Vec<_>>();
        refs.sort();
        refs.dedup();
        refs.len() == values.len()
    }
}

fn schema(value: &str) -> SchemaId {
    SchemaId::new(value).expect("static reciprocal Ed25519 schema")
}

fn derived(prefix: &str, source: &DottedId) -> DottedId {
    DottedId::new(format!("{prefix}.{}", source.as_str())).expect("derived reciprocal id")
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;
    use crate::{
        ManifoldPeerCredentialAlgorithm, ManifoldPeerCredentialStatus, PEER_CREDENTIAL_SCHEMA,
    };

    fn id(value: &str) -> DottedId {
        DottedId::new(value).expect("test id")
    }

    fn revision(value: u64) -> Revision {
        Revision::new(value).expect("test revision")
    }

    fn credential(
        peer_id: &str,
        key_id: &str,
        generation: u64,
        key: &SigningKey,
        status: ManifoldPeerCredentialStatus,
    ) -> ManifoldPeerCredentialRecord {
        let public = key.verifying_key().to_bytes();
        ManifoldPeerCredentialRecord {
            schema_id: schema(PEER_CREDENTIAL_SCHEMA),
            credential_id: id(&format!("credential.{peer_id}.{generation}")),
            peer_id: id(peer_id),
            trust_domain: id("trust.morphospace.peer"),
            key_id: id(key_id),
            key_generation: generation,
            algorithm: ManifoldPeerCredentialAlgorithm::Ed25519,
            public_key_hex: encode_lower_hex(&public),
            public_key_sha256: format!("sha256:{}", encode_lower_hex(&Sha256::digest(public))),
            valid_from_ms: 1,
            expires_at_ms: 100_000,
            status,
            replaced_by_key_id: None,
        }
    }

    pub(super) fn enrollment(alpha: &SigningKey, beta: &SigningKey) -> ManifoldPeerEnrollmentState {
        ManifoldPeerEnrollmentState {
            schema_id: schema(PEER_ENROLLMENT_STATE_SCHEMA),
            authority_revision: revision(3),
            credentials: vec![
                credential(
                    "peer.alpha",
                    "key.peer.alpha.001",
                    1,
                    alpha,
                    ManifoldPeerCredentialStatus::Active,
                ),
                credential(
                    "peer.beta",
                    "key.peer.beta.001",
                    1,
                    beta,
                    ManifoldPeerCredentialStatus::Active,
                ),
            ],
            applied_request_ids: vec![id("request.enroll.alpha"), id("request.enroll.beta")],
        }
    }

    pub(super) fn context(
        enrollment: &ManifoldPeerEnrollmentState,
    ) -> ManifoldReciprocalEd25519Context {
        let alpha = &enrollment.credentials[0];
        let beta = &enrollment.credentials[1];
        ManifoldReciprocalEd25519Context {
            schema_id: schema(RECIPROCAL_ED25519_CONTEXT_SCHEMA),
            runtime_host_id: id("host.peer.test"),
            trust_policy_id: id("policy.peer.test"),
            trust_policy_revision: Revision::INITIAL,
            correlation_id: id("run.peer.test.001"),
            revisions: ManifoldReciprocalEd25519Revisions {
                peer_authority_revision: revision(4),
                enrollment_authority_revision: enrollment.authority_revision,
                rendezvous_authority_revision: Revision::INITIAL,
                reciprocal_authority_revision: Revision::INITIAL,
                peer_session_authority_revision: Revision::INITIAL,
                peer_mesh_authority_revision: Revision::INITIAL,
                direct_lane_lease_authority_revision: Revision::INITIAL,
            },
            group_owner: ManifoldReciprocalEd25519PeerBinding {
                peer_id: alpha.peer_id.clone(),
                key_id: alpha.key_id.clone(),
                key_generation: alpha.key_generation,
                public_key_sha256: alpha.public_key_sha256.clone(),
                role: ManifoldRendezvousRole::GroupOwner,
                device_nonce_hex: "11".repeat(32),
            },
            client: ManifoldReciprocalEd25519PeerBinding {
                peer_id: beta.peer_id.clone(),
                key_id: beta.key_id.clone(),
                key_generation: beta.key_generation,
                public_key_sha256: beta.public_key_sha256.clone(),
                role: ManifoldRendezvousRole::Client,
                device_nonce_hex: "22".repeat(32),
            },
            topology_contract_id: id(crate::PRODUCT_WIFI_DIRECT_TOPOLOGY_CONTRACT),
            coordinator_epoch: 7,
            issued_at_ms: 1_000,
            expires_at_ms: 60_000,
        }
    }

    pub(super) fn signed(
        context: ManifoldReciprocalEd25519Context,
        alpha: &SigningKey,
        beta: &SigningKey,
    ) -> ManifoldReciprocalEd25519ReviewRequest {
        let bytes = reciprocal_ed25519_context_signing_bytes(&context);
        let digest = reciprocal_ed25519_context_sha256(&context);
        let signature = |binding: &ManifoldReciprocalEd25519PeerBinding, key: &SigningKey| {
            ManifoldReciprocalEd25519Signature {
                schema_id: schema(RECIPROCAL_ED25519_SIGNATURE_SCHEMA),
                signer_peer_id: binding.peer_id.clone(),
                signer_key_id: binding.key_id.clone(),
                context_sha256: digest.clone(),
                signature_hex: encode_lower_hex(&key.sign(&bytes).to_bytes()),
            }
        };
        ManifoldReciprocalEd25519ReviewRequest {
            schema_id: schema(RECIPROCAL_ED25519_REVIEW_SCHEMA),
            request_id: id(&format!("request.{}", context.correlation_id.as_str())),
            group_owner_signature: signature(&context.group_owner, alpha),
            client_signature: signature(&context.client, beta),
            context,
        }
    }

    pub(super) fn runtime<'a>(
        host_id: &'a DottedId,
        trust_policy_id: &'a DottedId,
        enrollment: &'a ManifoldPeerEnrollmentState,
    ) -> ManifoldReciprocalEd25519RuntimeContext<'a> {
        ManifoldReciprocalEd25519RuntimeContext {
            runtime_host_id: host_id,
            trust_policy_id,
            trust_policy_revision: Revision::INITIAL,
            peer_authority_revision: revision(4),
            enrollment,
            rendezvous_authority_revision: Revision::INITIAL,
            peer_session_authority_revision: Revision::INITIAL,
            peer_mesh_authority_revision: Revision::INITIAL,
            direct_lane_lease_authority_revision: Revision::INITIAL,
        }
    }

    #[test]
    fn reciprocal_current_keys_accept_and_replay_does_not_advance() {
        let alpha = SigningKey::from_bytes(&[7; 32]);
        let beta = SigningKey::from_bytes(&[11; 32]);
        let enrollment = enrollment(&alpha, &beta);
        let host_id = id("host.peer.test");
        let trust_policy_id = id("policy.peer.test");
        let request = signed(context(&enrollment), &alpha, &beta);
        let (state, receipt) = review_and_apply_reciprocal_ed25519(
            &ManifoldReciprocalEd25519AuthorityState::empty(),
            &request,
            runtime(&host_id, &trust_policy_id, &enrollment),
            2_000,
        );
        assert!(receipt.accepted);
        assert_eq!(state.authority_revision, revision(2));

        let mut replay = request;
        replay.request_id = id("request.run.peer.test.replay");
        replay.context.revisions.reciprocal_authority_revision = state.authority_revision;
        let (unchanged, rejected) = review_and_apply_reciprocal_ed25519(
            &state,
            &replay,
            ManifoldReciprocalEd25519RuntimeContext {
                rendezvous_authority_revision: revision(2),
                ..runtime(&host_id, &trust_policy_id, &enrollment)
            },
            2_100,
        );
        assert_eq!(
            rejected.rejection_reason,
            Some(ManifoldReciprocalEd25519RejectionReason::Replay)
        );
        assert_eq!(unchanged, state);
    }

    #[test]
    fn cross_context_swapped_signature_nonce_and_expiry_reject() {
        let alpha = SigningKey::from_bytes(&[7; 32]);
        let beta = SigningKey::from_bytes(&[11; 32]);
        let enrollment = enrollment(&alpha, &beta);
        let host_id = id("host.peer.test");
        let trust_policy_id = id("policy.peer.test");
        let base = signed(context(&enrollment), &alpha, &beta);
        let cases = [
            {
                let mut value = base.clone();
                value.context.runtime_host_id = id("host.peer.other");
                value
            },
            {
                let mut value = base.clone();
                std::mem::swap(
                    &mut value.group_owner_signature,
                    &mut value.client_signature,
                );
                value
            },
            {
                let mut value = base.clone();
                value.context.client.device_nonce_hex =
                    value.context.group_owner.device_nonce_hex.clone();
                value
            },
            {
                let mut value = base;
                value.context.expires_at_ms = 1_500;
                value
            },
        ];
        for request in cases {
            let (_, receipt) = review_and_apply_reciprocal_ed25519(
                &ManifoldReciprocalEd25519AuthorityState::empty(),
                &request,
                runtime(&host_id, &trust_policy_id, &enrollment),
                2_000,
            );
            assert!(!receipt.accepted);
        }
    }

    #[test]
    fn old_generation_after_rotation_rejects_even_with_valid_old_signatures() {
        let alpha = SigningKey::from_bytes(&[7; 32]);
        let beta = SigningKey::from_bytes(&[11; 32]);
        let mut enrollment = enrollment(&alpha, &beta);
        enrollment.credentials[0].status = ManifoldPeerCredentialStatus::Rotated;
        enrollment.credentials[0].replaced_by_key_id = Some(id("key.peer.alpha.002"));
        let next = SigningKey::from_bytes(&[19; 32]);
        enrollment.credentials.push(credential(
            "peer.alpha",
            "key.peer.alpha.002",
            2,
            &next,
            ManifoldPeerCredentialStatus::Active,
        ));
        enrollment.authority_revision = revision(4);
        let mut old_context = context(&enrollment);
        old_context.group_owner.key_id = id("key.peer.alpha.001");
        old_context.group_owner.key_generation = 1;
        old_context.group_owner.public_key_sha256 =
            enrollment.credentials[0].public_key_sha256.clone();
        let request = signed(old_context, &alpha, &beta);
        let host_id = id("host.peer.test");
        let trust_policy_id = id("policy.peer.test");
        let (_, receipt) = review_and_apply_reciprocal_ed25519(
            &ManifoldReciprocalEd25519AuthorityState::empty(),
            &request,
            runtime(&host_id, &trust_policy_id, &enrollment),
            2_000,
        );
        assert_eq!(
            receipt.rejection_reason,
            Some(ManifoldReciprocalEd25519RejectionReason::CredentialNotCurrent)
        );
    }
}
