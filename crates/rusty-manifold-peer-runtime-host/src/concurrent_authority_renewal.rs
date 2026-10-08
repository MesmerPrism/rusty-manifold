//! Retained deadline transitions authorized by accepted current-key reciprocal proof.
use super::*;
use rusty_manifold_peer::{ManifoldAcceptedCommonLanPeerSession, ManifoldPeerCredentialRecord};

/// Actual two-current-key refresh and accepted status transitions.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldConcurrentPairCredentialRefreshReceipt {
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    pub request_id: DottedId,
    pub applied: bool,
    pub peer_ids: Vec<DottedId>,
    pub key_ids: Vec<DottedId>,
    pub prior_authority_revision: Revision,
    pub resulting_authority_revision: Revision,
    pub expires_at_ms: u64,
    pub observed_at_ms: u64,
    pub reciprocal: ManifoldCommonLanReciprocalEd25519Receipt,
    pub prior_credentials: Vec<ManifoldPeerCredentialRecord>,
    pub renewed_credentials: Vec<ManifoldPeerCredentialRecord>,
    pub status_receipts: Vec<ManifoldPeerApplicationReceipt>,
}

/// Accepted same-session renewal; its original decision and all source identities remain stable.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldConcurrentPairSessionRenewalReceipt {
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    pub request_id: DottedId,
    pub applied: bool,
    pub session_id: DottedId,
    pub decision_id: DottedId,
    pub prior_authority_revision: Revision,
    pub resulting_authority_revision: Revision,
    pub prior_expires_at_ms: u64,
    pub expires_at_ms: u64,
    pub observed_at_ms: u64,
    pub prior_session: ManifoldAcceptedCommonLanPeerSession,
    pub renewed_session: ManifoldAcceptedCommonLanPeerSession,
    pub renewal_proposal: ManifoldCommonLanPeerSessionProposal,
    pub reciprocal: ManifoldCommonLanReciprocalEd25519Receipt,
    pub prior_topology: ManifoldCommonLanSignedPeerTopologyAuthorization,
    pub topology: ManifoldCommonLanSignedPeerTopologyAuthorization,
}

impl ManifoldPeerRuntimeHost {
    /// Refreshes only the two current keys authenticated by a fresh retained reciprocal exchange.
    /// No key generation, peer role, capability or carrier can change through this operation.
    pub fn refresh_concurrent_pair_credentials(
        &mut self,
        proof: &ManifoldCommonLanReciprocalEd25519Receipt,
        now_ms: u64,
    ) -> Result<ManifoldConcurrentPairCredentialRefreshReceipt, ManifoldPeerRuntimeHostError> {
        self.ensure_family_enabled(ManifoldPeerRuntimeAuthorityFamily::Enrollment)?;
        self.ensure_family_enabled(ManifoldPeerRuntimeAuthorityFamily::PeerStatus)?;
        self.ensure_event_capacity()?;
        if let Some(existing) = self
            .snapshot
            .concurrent_credential_refreshes
            .iter()
            .find(|receipt| receipt.reciprocal.receipt_id == proof.receipt_id)
        {
            if existing.reciprocal == *proof {
                return Ok(existing.clone());
            }
            return Err(invalid_snapshot(
                "credential refresh proof replay changed bytes",
            ));
        }
        if self.snapshot.concurrent_credential_refreshes.len() >= 64
            || self.snapshot.trust_policy.trusted_operator_ids.len() != 1
            || proof.peer_ids.len() != 2
            || proof.signer_key_ids.len() != 2
        {
            return Err(invalid_snapshot(
                "credential refresh bounds or enrolled operator",
            ));
        }
        rusty_manifold_peer::validate_current_reciprocal_ed25519_receipt_v3(
            &self.snapshot.reciprocal_ed25519,
            &self.snapshot.enrollment,
            &rusty_manifold_peer::ManifoldReciprocalEd25519ReceiptV3::CommonLan(proof.clone()),
            &proof.initiator_peer_id,
            &proof.responder_peer_id,
            now_ms,
        )
        .map_err(|_| invalid_snapshot("credential refresh requires current accepted signatures"))?;
        let expiry = now_ms
            .checked_add(300_000)
            .ok_or_else(|| invalid_snapshot("credential refresh expiry overflow"))?;
        let prior = self.snapshot.enrollment.authority_revision;
        let next_revision = prior
            .next()
            .ok_or_else(|| invalid_snapshot("credential refresh revision exhausted"))?;
        let request_id = derived("request.concurrent.credentials", &proof.receipt_id);
        if self
            .snapshot
            .enrollment
            .applied_request_ids
            .contains(&request_id)
        {
            return Err(invalid_snapshot("credential refresh unbound replay"));
        }
        let mut candidate = self.clone();
        let mut old_keys = Vec::new();
        let mut new_keys = Vec::new();
        for peer_id in &proof.peer_ids {
            let records: Vec<_> = candidate
                .snapshot
                .enrollment
                .credentials
                .iter_mut()
                .filter(|key| {
                    &key.peer_id == peer_id
                        && key.status == rusty_manifold_peer::ManifoldPeerCredentialStatus::Active
                })
                .collect();
            if records.len() != 1 {
                return Err(invalid_snapshot("credential refresh ambiguous current key"));
            }
            let key = records.into_iter().next().expect("one key");
            if !proof.signer_key_ids.contains(&key.key_id)
                || key.expires_at_ms <= now_ms
                || key.valid_from_ms > now_ms
                || expiry <= key.expires_at_ms
            {
                return Err(invalid_snapshot(
                    "credential refresh key not current or expiry did not advance",
                ));
            }
            old_keys.push(key.clone());
            key.expires_at_ms = expiry;
            new_keys.push(key.clone());
        }
        candidate.snapshot.enrollment.authority_revision = next_revision;
        candidate
            .snapshot
            .enrollment
            .applied_request_ids
            .push(request_id.clone());
        let mut status_receipts = Vec::new();
        for peer_id in &proof.peer_ids {
            let old = candidate
                .snapshot
                .accepted_peers
                .peers
                .iter()
                .find(|peer| &peer.identity.peer_id == peer_id)
                .ok_or_else(|| invalid_snapshot("credential refresh peer status missing"))?
                .clone();
            if old.status.availability != rusty_manifold_peer::ManifoldPeerAvailability::Ready
                || old.status.observed_at_ms > now_ms
                || old.status.expires_at_ms <= now_ms
            {
                return Err(invalid_snapshot(
                    "credential refresh peer not observed current",
                ));
            }
            let mut status = old.status.clone();
            status.status_revision = status
                .status_revision
                .next()
                .ok_or_else(|| invalid_snapshot("status revision exhausted"))?;
            status.observed_at_ms = now_ms;
            status.expires_at_ms = expiry;
            let (_, application) = candidate.review_peer_status(
                ManifoldPeerStatusProposal {
                    schema_id: schema(rusty_manifold_peer::PEER_PROPOSAL_SCHEMA),
                    proposal_id: derived(
                        "proposal.concurrent.status",
                        &DottedId::new(format!(
                            "{}.{}",
                            proof.receipt_id.as_str(),
                            peer_id.as_str()
                        ))
                        .map_err(|_| invalid_snapshot("status request id"))?,
                    ),
                    expected_authority_revision: candidate
                        .snapshot
                        .accepted_peers
                        .authority_revision,
                    proposer_id: candidate.snapshot.trust_policy.trusted_operator_ids[0].clone(),
                    identity: old.identity,
                    status,
                    payload_class: rusty_manifold_peer::ManifoldPeerPayloadClass::LowRateDescriptor,
                },
                now_ms,
            )?;
            if !application.applied {
                return Err(invalid_snapshot("credential refresh status owner rejected"));
            }
            status_receipts.push(application);
        }
        let receipt = ManifoldConcurrentPairCredentialRefreshReceipt {
            schema_id: schema("rusty.manifold.peer.concurrent_credential_refresh_receipt.v1"),
            request_id: request_id.clone(),
            applied: true,
            peer_ids: proof.peer_ids.clone(),
            key_ids: proof.signer_key_ids.clone(),
            prior_authority_revision: prior,
            resulting_authority_revision: next_revision,
            expires_at_ms: expiry,
            observed_at_ms: now_ms,
            reciprocal: proof.clone(),
            prior_credentials: old_keys,
            renewed_credentials: new_keys,
            status_receipts,
        };
        candidate
            .snapshot
            .concurrent_credential_refreshes
            .push(receipt.clone());
        candidate.record(
            ManifoldPeerRuntimeAuditKind::Enrollment,
            request_id,
            prior,
            next_revision,
            true,
            None,
        )?;
        self.snapshot = candidate.snapshot;
        Ok(receipt)
    }

    /// Applies a fresh same-session signed expiry transition without dropping active media resources.
    pub fn apply_common_lan_session_renewal(
        &mut self,
        proposal: &ManifoldCommonLanPeerSessionProposal,
        reciprocal: &ManifoldCommonLanReciprocalEd25519Receipt,
        now_ms: u64,
    ) -> Result<ManifoldConcurrentPairSessionRenewalReceipt, ManifoldPeerRuntimeHostError> {
        self.ensure_family_enabled(ManifoldPeerRuntimeAuthorityFamily::Rendezvous)?;
        self.ensure_event_capacity()?;
        if let Some(existing) = self
            .snapshot
            .concurrent_session_renewals
            .iter()
            .find(|receipt| receipt.request_id == proposal.proposal_id)
        {
            if existing.renewal_proposal == *proposal && existing.reciprocal == *reciprocal {
                return Ok(existing.clone());
            }
            return Err(invalid_snapshot("session renewal replay changed bytes"));
        }
        if self.snapshot.concurrent_session_renewals.len() >= 64 {
            return Err(invalid_snapshot("session renewal capacity"));
        }
        let prior_session = self
            .snapshot
            .peer_sessions
            .sessions
            .iter()
            .find_map(|session| match session {
                ManifoldAcceptedPeerSessionV2::CommonLan(session)
                    if session.proposal.session_id == proposal.session_id =>
                {
                    Some(session.clone())
                }
                _ => None,
            })
            .ok_or_else(|| invalid_snapshot("session renewal current session missing"))?;
        let prior_topology = self
            .snapshot
            .signed_topology_authorizations
            .iter()
            .find_map(|topology| match topology {
                ManifoldSignedPeerTopologyAuthorizationV2::CommonLan(topology)
                    if topology.decision_id == prior_session.decision_id =>
                {
                    Some(topology.clone())
                }
                _ => None,
            })
            .ok_or_else(|| invalid_snapshot("session renewal current topology missing"))?;
        let (next, decision, topology) =
            rusty_manifold_peer::review_and_apply_common_lan_session_renewal(
                &self.snapshot.peer_sessions,
                ManifoldCommonLanSignedPeerSessionReviewCase {
                    accepted_peers: &self.snapshot.accepted_peers,
                    current_state: &self.snapshot.peer_sessions,
                    proposal,
                    reciprocal_receipt: reciprocal,
                    current_enrollment: &self.snapshot.enrollment,
                    current_reciprocal_state: &self.snapshot.reciprocal_ed25519,
                    now_ms,
                },
            );
        let (
            ManifoldPeerSessionDecisionV2::CommonLan(decision),
            ManifoldSignedPeerTopologyAuthorizationV2::CommonLan(topology),
        ) = (decision, topology)
        else {
            return Err(invalid_snapshot("session renewal wrong variant"));
        };
        if !decision.applied {
            return Err(ManifoldPeerRuntimeHostError::Authority(format!(
                "session renewal rejected: {:?}",
                decision.rejection_reason
            )));
        }
        let renewed_session = next
            .sessions
            .iter()
            .find_map(|session| match session {
                ManifoldAcceptedPeerSessionV2::CommonLan(session)
                    if session.proposal.session_id == proposal.session_id =>
                {
                    Some(session.clone())
                }
                _ => None,
            })
            .ok_or_else(|| invalid_snapshot("session renewal result missing"))?;
        let receipt = ManifoldConcurrentPairSessionRenewalReceipt {
            schema_id: schema("rusty.manifold.peer.concurrent_session_renewal_receipt.v1"),
            request_id: proposal.proposal_id.clone(),
            applied: true,
            session_id: proposal.session_id.clone(),
            decision_id: prior_session.decision_id.clone(),
            prior_authority_revision: decision.prior_authority_revision,
            resulting_authority_revision: decision.resulting_authority_revision,
            prior_expires_at_ms: prior_session.proposal.expires_at_ms,
            expires_at_ms: proposal.expires_at_ms,
            observed_at_ms: now_ms,
            prior_session,
            renewed_session,
            renewal_proposal: proposal.clone(),
            reciprocal: reciprocal.clone(),
            prior_topology,
            topology: topology.clone(),
        };
        self.record(
            ManifoldPeerRuntimeAuditKind::SignedPeerSession,
            proposal.proposal_id.clone(),
            decision.prior_authority_revision,
            decision.resulting_authority_revision,
            true,
            None,
        )?;
        self.snapshot.peer_sessions = next;
        let slot = self
            .snapshot
            .signed_topology_authorizations
            .iter_mut()
            .find(|entry| entry.decision_id() == &receipt.decision_id)
            .expect("current topology checked before mutation");
        *slot = ManifoldSignedPeerTopologyAuthorizationV2::CommonLan(topology);
        self.snapshot
            .concurrent_session_renewals
            .push(receipt.clone());
        Ok(receipt)
    }
}

pub(super) fn validate_concurrent_pair_renewals(
    snapshot: &ManifoldPeerRuntimeHostSnapshot,
) -> Result<(), ManifoldPeerRuntimeHostError> {
    if snapshot.concurrent_credential_refreshes.len() > 64
        || snapshot.concurrent_session_renewals.len() > 64
    {
        return Err(invalid_snapshot("concurrent renewal capacity"));
    }
    let mut requests = BTreeSet::new();
    for receipt in &snapshot.concurrent_credential_refreshes {
        if receipt.schema_id.as_str()
            != "rusty.manifold.peer.concurrent_credential_refresh_receipt.v1"
            || !receipt.applied
            || !requests.insert(&receipt.request_id)
            || receipt.peer_ids.len() != 2
            || receipt.key_ids.len() != 2
            || receipt.prior_credentials.len() != 2
            || receipt.renewed_credentials.len() != 2
            || receipt.status_receipts.len() != 2
            || receipt.status_receipts.iter().any(|entry| !entry.applied)
            || receipt.prior_authority_revision.next() != Some(receipt.resulting_authority_revision)
            || receipt.observed_at_ms.checked_add(300_000) != Some(receipt.expires_at_ms)
            || !snapshot
                .enrollment
                .applied_request_ids
                .contains(&receipt.request_id)
            || !snapshot.reciprocal_ed25519.accepted_receipts.contains(
                &rusty_manifold_peer::ManifoldReciprocalEd25519ReceiptV3::CommonLan(
                    receipt.reciprocal.clone(),
                ),
            )
        {
            return Err(invalid_snapshot("credential refresh retained owner joins"));
        }
        for (old, new) in receipt
            .prior_credentials
            .iter()
            .zip(&receipt.renewed_credentials)
        {
            let mut expected = old.clone();
            expected.expires_at_ms = receipt.expires_at_ms;
            if expected != *new
                || old.expires_at_ms <= receipt.observed_at_ms
                || old.expires_at_ms >= new.expires_at_ms
                || !receipt.key_ids.contains(&old.key_id)
                || !receipt.peer_ids.contains(&old.peer_id)
            {
                return Err(invalid_snapshot(
                    "credential refresh changed key or nonadvancing expiry",
                ));
            }
        }
    }
    for receipt in &snapshot.concurrent_session_renewals {
        let old = &receipt.prior_session;
        let new = &receipt.renewed_session;
        if receipt.schema_id.as_str() != "rusty.manifold.peer.concurrent_session_renewal_receipt.v1"
            || !receipt.applied
            || !requests.insert(&receipt.request_id)
            || old.revoked
            || new.revoked
            || old.decision_id != new.decision_id
            || new.decision_id != receipt.decision_id
            || old.proposal.session_id != new.proposal.session_id
            || new.proposal.session_id != receipt.session_id
            || old.proposal.subject_peer_id != new.proposal.subject_peer_id
            || old.proposal.candidate_peer_id != new.proposal.candidate_peer_id
            || old.proposal.initiator_peer_id != new.proposal.initiator_peer_id
            || old.proposal.responder_peer_id != new.proposal.responder_peer_id
            || old.proposal.requested_capability_ids != new.proposal.requested_capability_ids
            || old.proposal.transport != new.proposal.transport
            || receipt.prior_expires_at_ms != old.proposal.expires_at_ms
            || receipt.expires_at_ms != new.proposal.expires_at_ms
            || receipt.prior_expires_at_ms <= receipt.observed_at_ms
            || receipt.expires_at_ms <= receipt.prior_expires_at_ms
            || receipt.expires_at_ms > receipt.reciprocal.expires_at_ms
            || receipt.renewal_proposal.proposal_id != receipt.request_id
            || old.proposal.proposal_id != new.proposal.proposal_id
            || receipt.renewal_proposal.session_id != receipt.session_id
            || receipt.renewal_proposal.expires_at_ms != receipt.expires_at_ms
            || !snapshot
                .peer_sessions
                .applied_proposal_ids
                .contains(&receipt.request_id)
            || receipt.prior_authority_revision.next() != Some(receipt.resulting_authority_revision)
            || !snapshot.reciprocal_ed25519.accepted_receipts.contains(
                &rusty_manifold_peer::ManifoldReciprocalEd25519ReceiptV3::CommonLan(
                    receipt.reciprocal.clone(),
                ),
            )
        {
            return Err(invalid_snapshot("session renewal retained owner joins"));
        }
    }
    Ok(())
}
