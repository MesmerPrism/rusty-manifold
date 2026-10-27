//! Owner-held admission checkpoints. A digest is a commitment, never restore authority.
use super::*;
use sha2::{Digest, Sha256};

/// Explicit ongoing admission storage; finite v2 remains the default.
pub const ONGOING_ADMISSION_SNAPSHOT_SCHEMA: &str = "rusty.manifold.admission.snapshot.v3";

/// Constant-size checkpoint plus the bounded set of still-live baseline tokens.
/// No source histories or previous checkpoint bodies are recursively retained.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldAdmissionHistoryCheckpoint {
    /// Versioned storage contract.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Request/token namespace; advances without resetting authority revision.
    pub request_epoch: u64,
    /// Last audit sequence included in this checkpoint.
    pub audit_sequence: u64,
    /// Accepted revision at the checkpoint boundary.
    pub authority_revision: Revision,
    /// Exact accepted grants at that boundary, including unchanged scoped horizons.
    pub grants: Vec<ManifoldAdmissionGrant>,
    /// Exact retained tokens at that boundary; checkpointing neither expires nor reissues them.
    pub active_tokens: Vec<ManifoldAdmissionToken>,
    /// Exact accepted use proofs pinned by still-live downstream obligations.
    /// They authorize no new use and carry no recursive checkpoint body.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retained_use_authorizations: Vec<ManifoldAdmissionAuditEvent>,
    /// Commitment to the previous checkpoint, never its recursively growing body.
    pub prior_checkpoint_sha256: Option<String>,
    /// Commitment to the complete accepted source state before compaction.
    pub source_snapshot_sha256: String,
}

/// Borrowed same-process restore anchor. Target JSON cannot construct this type.
#[derive(Debug)]
pub struct ManifoldAdmissionHistoryRestoreAnchor<'owner> {
    owner: &'owner ManifoldAdmissionAuthority,
    source_sha256: String,
}

fn digest<T: Serialize>(value: &T) -> Result<String, ManifoldAdmissionError> {
    let bytes = serde_json::to_vec(value).map_err(ManifoldAdmissionError::Serialize)?;
    let mut hash = Sha256::new();
    hash.update(b"rusty.manifold.admission.ongoing_history.sha256.v1\0");
    hash.update(bytes);
    Ok(format!("sha256:{:x}", hash.finalize()))
}

pub(super) fn audit_base(snapshot: &ManifoldAdmissionSnapshot) -> u64 {
    snapshot
        .history_checkpoint
        .as_ref()
        .map_or(0, |c| c.audit_sequence)
}

pub(super) fn audit_capacity_exhausted(
    snapshot: &ManifoldAdmissionSnapshot,
    reserve: usize,
) -> bool {
    snapshot
        .audit_events
        .len()
        .checked_add(reserve)
        .map_or(true, |n| n > MAX_ADMISSION_AUDIT_EVENTS)
        || u64::try_from(snapshot.audit_events.len())
            .ok()
            .and_then(|n| audit_base(snapshot).checked_add(n))
            .and_then(|n| n.checked_add(reserve as u64))
            .is_none()
}

pub(super) fn request_matches(snapshot: &ManifoldAdmissionSnapshot, id: &DottedId) -> bool {
    snapshot.history_checkpoint.as_ref().map_or(true, |c| {
        id.as_str()
            .strip_prefix(&format!("history.{}.", c.request_epoch))
            .is_some_and(|suffix| !suffix.is_empty() && !suffix.starts_with("history."))
    })
}

pub(super) fn validate_checkpoint(
    snapshot: &ManifoldAdmissionSnapshot,
) -> Result<(), ManifoldAdmissionError> {
    let Some(c) = &snapshot.history_checkpoint else {
        return if snapshot.schema_id.as_str() == ADMISSION_SNAPSHOT_SCHEMA {
            Ok(())
        } else {
            Err(ManifoldAdmissionError::InvalidSnapshot(
                "history_policy_schema",
            ))
        };
    };
    if snapshot.schema_id.as_str() != ONGOING_ADMISSION_SNAPSHOT_SCHEMA
        || c.schema_id.as_str() != "rusty.manifold.admission.history_checkpoint.v1"
        || c.request_epoch == 0
        || c.audit_sequence < c.request_epoch.saturating_sub(1)
        || (c.request_epoch > 1) != c.prior_checkpoint_sha256.is_some()
        || !valid_sha256(&c.source_snapshot_sha256)
        || c.prior_checkpoint_sha256
            .as_ref()
            .is_some_and(|h| !valid_sha256(h))
        || c.authority_revision > snapshot.authority_revision
        || c.grants.len() != snapshot.grants.len()
        || c.active_tokens.len() > MAX_ADMISSION_RECORDS
        || c.retained_use_authorizations.len() > MAX_ADMISSION_RECORDS
        || c.retained_use_authorizations
            .windows(2)
            .any(|w| w[0].request_id >= w[1].request_id)
        || c.retained_use_authorizations.iter().any(|event| {
            event.schema_id.as_str() != ADMISSION_AUDIT_SCHEMA
                || !event.applied
                || event.operation != ManifoldAdmissionOperation::AuthorizeUse
                || event.sequence > c.audit_sequence
                || event.event_id != admission_audit_id(event.sequence)
                || event.resulting_authority_revision > c.authority_revision
                || event.prior_authority_revision.next() != Some(event.resulting_authority_revision)
                || event.rejection_reason.is_some()
                || event.grant_renewal.is_some()
                || event.grant_reestablishment.is_some()
                || event.use_authorization.as_ref().map_or(true, |binding| {
                    binding.request.request_id != event.request_id
                        || binding.request.expected_authority_revision
                            != event.prior_authority_revision
                        || binding.request.token_id != binding.token.token_id
                        || binding.request.identity != binding.token.identity
                        || !binding
                            .token
                            .capabilities
                            .contains(&binding.request.capability_id)
                })
        })
        || c.active_tokens
            .windows(2)
            .any(|w| w[0].token_id >= w[1].token_id)
        || c.active_tokens
            .iter()
            .any(|token| token.issued_authority_revision > c.authority_revision)
    {
        return Err(ManifoldAdmissionError::InvalidSnapshot(
            "history_checkpoint_shape",
        ));
    }
    // Baseline grants are accepted owner data. Their exact current join is
    // checked by the existing root-renewal validator starting from this map.
    Ok(())
}

impl ManifoldAdmissionAuthority {
    /// Selects prospective ongoing storage before the first mutable admission action.
    /// This does not change grants, deadlines, token TTLs or accepted revision.
    pub fn enable_ongoing_history(&mut self) -> Result<(), ManifoldAdmissionError> {
        validate_snapshot(&self.snapshot)?;
        if self.snapshot.history_checkpoint.is_some() {
            return Ok(());
        }
        if self.snapshot.authority_revision != Revision::INITIAL
            || !self.snapshot.audit_events.is_empty()
            || !self.snapshot.active_tokens.is_empty()
            || !self.snapshot.revoked_token_ids.is_empty()
            || !self.snapshot.consumed_request_ids.is_empty()
            || !self.snapshot.consumed_use_request_ids.is_empty()
            || !self.snapshot.reviewed_sweep_ids.is_empty()
        {
            return Err(ManifoldAdmissionError::InvalidSnapshot(
                "ongoing_history_requires_fresh_owner",
            ));
        }
        let source_snapshot_sha256 = digest(&self.snapshot)?;
        let mut candidate = self.clone();
        candidate.snapshot.history_checkpoint = Some(ManifoldAdmissionHistoryCheckpoint {
            schema_id: schema_id("rusty.manifold.admission.history_checkpoint.v1"),
            request_epoch: 1,
            audit_sequence: 0,
            authority_revision: self.snapshot.authority_revision,
            grants: self.snapshot.grants.clone(),
            active_tokens: Vec::new(),
            retained_use_authorizations: Vec::new(),
            prior_checkpoint_sha256: None,
            source_snapshot_sha256,
        });
        candidate.snapshot.schema_id = schema_id(ONGOING_ADMISSION_SNAPSHOT_SCHEMA);
        validate_snapshot(&candidate.snapshot)?;
        *self = candidate;
        Ok(())
    }

    /// Qualifies a new request identity with the actual owner's current epoch.
    /// Existing requests must retain their identity when retrying a pending action.
    pub fn current_history_request_id(
        &self,
        suffix: &DottedId,
    ) -> Result<DottedId, ManifoldAdmissionError> {
        if suffix.as_str().starts_with("history.") {
            return Err(ManifoldAdmissionError::InvalidSnapshot(
                "history_request_already_qualified",
            ));
        }
        Ok(self.snapshot.history_checkpoint.as_ref().map_or_else(
            || suffix.clone(),
            |c| {
                DottedId::new(format!("history.{}.{}", c.request_epoch, suffix))
                    .expect("qualified dotted id")
            },
        ))
    }

    /// Compacts only this actual accepted owner. The embedding composition must
    /// additionally finish any pending uses before checkpointing its own evidence.
    /// No grants, tokens, expiry, authority revision or platform resources change.
    pub fn checkpoint_ongoing_history(
        &mut self,
    ) -> Result<ManifoldAdmissionHistoryCheckpoint, ManifoldAdmissionError> {
        self.checkpoint_ongoing_history_with_retained_uses(&[])
    }

    /// Retains exact already accepted uses required by live downstream owners.
    /// An id selects existing evidence only; callers cannot supply a proof body.
    pub fn checkpoint_ongoing_history_with_retained_uses(
        &mut self,
        retained_use_ids: &[DottedId],
    ) -> Result<ManifoldAdmissionHistoryCheckpoint, ManifoldAdmissionError> {
        validate_snapshot(&self.snapshot)?;
        let prior = self.snapshot.history_checkpoint.as_ref().ok_or(
            ManifoldAdmissionError::InvalidSnapshot("ongoing_history_not_selected"),
        )?;
        if retained_use_ids.len() > MAX_ADMISSION_RECORDS
            || retained_use_ids.windows(2).any(|w| w[0] >= w[1])
        {
            return Err(ManifoldAdmissionError::InvalidSnapshot(
                "history_retained_use_set",
            ));
        }
        let retained_use_authorizations = retained_use_ids
            .iter()
            .map(|id| {
                if !self.snapshot.consumed_use_request_ids.contains(id) {
                    return Err(ManifoldAdmissionError::InvalidSnapshot(
                        "history_retained_use_missing",
                    ));
                }
                self.snapshot
                    .audit_events
                    .iter()
                    .chain(prior.retained_use_authorizations.iter())
                    .find(|event| {
                        event.applied
                            && event.operation == ManifoldAdmissionOperation::AuthorizeUse
                            && event.request_id == *id
                    })
                    .cloned()
                    .ok_or(ManifoldAdmissionError::InvalidSnapshot(
                        "history_retained_use_missing",
                    ))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if self.snapshot.audit_events.is_empty()
            && retained_use_authorizations == prior.retained_use_authorizations
        {
            return Ok(prior.clone());
        }
        let request_epoch =
            prior
                .request_epoch
                .checked_add(1)
                .ok_or(ManifoldAdmissionError::InvalidSnapshot(
                    "history_epoch_exhausted",
                ))?;
        let audit_sequence = prior
            .audit_sequence
            .checked_add(self.snapshot.audit_events.len() as u64)
            .ok_or(ManifoldAdmissionError::InvalidSnapshot(
                "history_audit_sequence_exhausted",
            ))?;
        let checkpoint = ManifoldAdmissionHistoryCheckpoint {
            schema_id: schema_id("rusty.manifold.admission.history_checkpoint.v1"),
            request_epoch,
            audit_sequence,
            authority_revision: self.snapshot.authority_revision,
            grants: self.snapshot.grants.clone(),
            active_tokens: self.snapshot.active_tokens.clone(),
            retained_use_authorizations,
            prior_checkpoint_sha256: Some(digest(prior)?),
            source_snapshot_sha256: digest(&self.snapshot)?,
        };
        let mut candidate = self.clone();
        candidate.snapshot.history_checkpoint = Some(checkpoint.clone());
        candidate.snapshot.audit_events.clear();
        candidate.snapshot.consumed_request_ids.clear();
        candidate.snapshot.consumed_use_request_ids = retained_use_ids.to_vec();
        candidate.snapshot.reviewed_sweep_ids.clear();
        // Removed tokens cannot be minted again: future entropy is qualified by
        // the new epoch. Unknown old tokens stay unusable without a live record.
        candidate.snapshot.revoked_token_ids.clear();
        validate_snapshot(&candidate.snapshot)?;
        *self = candidate;
        Ok(checkpoint)
    }

    /// Validates the already held mutable owner, without admitting detached data.
    pub fn validate_owned_history(&self) -> Result<(), ManifoldAdmissionError> {
        validate_snapshot(&self.snapshot)
    }

    /// Seals current state under a borrowed live-owner anchor, not a caller hash.
    pub fn seal_ongoing_history(
        &self,
    ) -> Result<ManifoldAdmissionHistoryRestoreAnchor<'_>, ManifoldAdmissionError> {
        if self.snapshot.history_checkpoint.is_none() {
            return Err(ManifoldAdmissionError::InvalidSnapshot(
                "ongoing_history_not_selected",
            ));
        }
        validate_snapshot(&self.snapshot)?;
        Ok(ManifoldAdmissionHistoryRestoreAnchor {
            owner: self,
            source_sha256: digest(&self.snapshot)?,
        })
    }

    /// Restores only the exact current state independently held by this owner.
    /// Process-death recovery needs an authenticated deployment-owner storage
    /// anchor; a deserialized checkpoint alone is deliberately insufficient.
    pub fn restore_ongoing_history(
        json: &str,
        anchor: &ManifoldAdmissionHistoryRestoreAnchor<'_>,
    ) -> Result<Self, ManifoldAdmissionError> {
        let snapshot: ManifoldAdmissionSnapshot =
            serde_json::from_str(json).map_err(ManifoldAdmissionError::Deserialize)?;
        if snapshot.history_checkpoint.is_none()
            || digest(&snapshot)? != anchor.source_sha256
            || digest(&anchor.owner.snapshot)? != anchor.source_sha256
        {
            return Err(ManifoldAdmissionError::InvalidSnapshot(
                "ongoing_restore_requires_live_owner",
            ));
        }
        validate_snapshot(&snapshot)?;
        Ok(Self {
            snapshot,
            source_bound_root_owner: anchor.owner.source_bound_root_owner.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn id(s: &str) -> DottedId {
        DottedId::new(s).unwrap()
    }
    fn owner() -> ManifoldAdmissionAuthority {
        let mut owner = ManifoldAdmissionAuthority::from_snapshot(ManifoldAdmissionSnapshot {
            development_lifetime_policy: None,
            schema_id: schema_id(ADMISSION_SNAPSHOT_SCHEMA),
            history_checkpoint: None,
            authority_id: id("authority.ongoing"),
            authority_revision: Revision::INITIAL,
            grants: vec![ManifoldAdmissionGrant {
                grant_id: id("grant.ongoing"),
                client_lock_id: id("lock.ongoing"),
                client_lock_fingerprint: format!("sha256:{}", "a".repeat(64)),
                identity: ManifoldClientIdentity {
                    client_id: id("client.ongoing"),
                    platform_subject: "org.example.owner".into(),
                    signing_fingerprint: format!("sha256:{}", "b".repeat(64)),
                },
                capabilities: vec![id("capability.manifold.control_lease.renew")],
                expires_at_ms: 100_000,
                revoked: false,
            }],
            active_tokens: vec![],
            revoked_token_ids: vec![],
            consumed_request_ids: vec![],
            consumed_use_request_ids: vec![],
            reviewed_sweep_ids: vec![],
            audit_events: vec![],
            root_renewal_policies: vec![],
            max_token_ttl_ms: 30_000,
        })
        .unwrap();
        owner.enable_ongoing_history().unwrap();
        owner
    }
    fn issue(
        owner: &mut ManifoldAdmissionAuthority,
        entropy: u8,
        now: u64,
    ) -> ManifoldAdmissionReceipt {
        let request = ManifoldAdmissionRequest {
            schema_id: schema_id(ADMISSION_REQUEST_SCHEMA),
            request_id: owner
                .current_history_request_id(&id("request.issue"))
                .unwrap(),
            expected_authority_revision: owner.snapshot.authority_revision,
            identity: owner.snapshot.grants[0].identity.clone(),
            requested_capabilities: owner.snapshot.grants[0].capabilities.clone(),
            issued_at_ms: now,
            expires_at_ms: now + 1000,
            requested_token_ttl_ms: 20_000,
        };
        owner.issue_token(&request, [entropy; 32], now)
    }
    fn use_request(
        owner: &ManifoldAdmissionAuthority,
        token: &ManifoldAdmissionToken,
        suffix: &str,
        now: u64,
    ) -> ManifoldAdmissionUseRequest {
        ManifoldAdmissionUseRequest {
            schema_id: schema_id(ADMISSION_USE_REQUEST_SCHEMA),
            request_id: owner.current_history_request_id(&id(suffix)).unwrap(),
            expected_authority_revision: owner.snapshot.authority_revision,
            token_id: token.token_id.clone(),
            identity: token.identity.clone(),
            capability_id: token.capabilities[0].clone(),
            issued_at_ms: now,
            expires_at_ms: now + 1000,
        }
    }
    #[test]
    fn ongoing_owner_5000_real_root_renewals_retain_live_token_and_scoped_deadlines() {
        let mut owner = owner();
        let original_grant = owner.snapshot.grants[0].clone();
        let original_ttl = owner.snapshot.max_token_ttl_ms;
        let token = issue(&mut owner, 7, 2000).token.unwrap();
        let initial_token = token.clone();
        let mut first_request = None;
        let mut old_json: Option<String> = None;
        for cycle in 0..5000 {
            let now = 3000 + cycle;
            let authorization = use_request(&owner, &token, &format!("request.use.r{cycle}"), now);
            let request = ManifoldAdmissionGrantRenewalRequest {
                schema_id: schema_id("rusty.manifold.admission.grant_renewal_request.v1"),
                request_id: owner
                    .current_history_request_id(&id(&format!("request.renew.r{cycle}")))
                    .unwrap(),
                authorization,
                grant_id: original_grant.grant_id.clone(),
                prior_expires_at_ms: owner.snapshot.grants[0].expires_at_ms,
                expires_at_ms: now + 300_000,
                accepted_evidence_id: id(&format!("receipt.accepted.r{cycle}")),
                accepted_evidence_sha256: format!("sha256:{}", "c".repeat(64)),
            };
            assert!(
                owner
                    .renew_current_grant(&request, now)
                    .unwrap()
                    .application
                    .applied
            );
            if first_request.is_none() {
                first_request = Some(request);
            }
            if cycle % 16 == 15 {
                let before = owner.snapshot.clone();
                let checkpoint = owner.checkpoint_ongoing_history().unwrap();
                assert_eq!(owner.snapshot.authority_revision, before.authority_revision);
                assert_eq!(owner.snapshot.grants, before.grants);
                assert_eq!(owner.snapshot.active_tokens, before.active_tokens);
                assert_eq!(owner.snapshot.active_tokens[0], initial_token);
                assert_eq!(owner.snapshot.max_token_ttl_ms, original_ttl);
                assert!(owner.snapshot.audit_events.is_empty());
                assert!(owner.snapshot.consumed_request_ids.is_empty());
                assert!(owner.snapshot.consumed_use_request_ids.is_empty());
                assert_eq!(checkpoint.audit_sequence, 1 + 2 * (cycle + 1));
                assert_eq!(checkpoint.request_epoch, 2 + cycle / 16);
                let json = owner.snapshot_json().unwrap();
                assert!(ManifoldAdmissionAuthority::restart_from_json(&json).is_err());
                let anchor = owner.seal_ongoing_history().unwrap();
                let restored =
                    ManifoldAdmissionAuthority::restore_ongoing_history(&json, &anchor).unwrap();
                assert_eq!(restored, owner);
                if let Some(old) = &old_json {
                    assert!(
                        ManifoldAdmissionAuthority::restore_ongoing_history(old, &anchor).is_err()
                    );
                }
                old_json = Some(json);
                let mut replay = first_request.clone().unwrap();
                replay.authorization.expected_authority_revision =
                    owner.snapshot.authority_revision;
                replay.prior_expires_at_ms = owner.snapshot.grants[0].expires_at_ms;
                replay.expires_at_ms = now + 300_001;
                let saved = owner.clone();
                assert!(owner.renew_current_grant(&replay, now).is_err());
                assert_eq!(owner, saved);
            }
            owner.validate_owned_history().unwrap();
            assert!(owner.snapshot.audit_events.len() <= 33);
        }
        let current_grant = &owner.snapshot.grants[0];
        assert_eq!(current_grant.identity, original_grant.identity);
        assert_eq!(current_grant.client_lock_id, original_grant.client_lock_id);
        assert_eq!(current_grant.capabilities, original_grant.capabilities);
        assert_eq!(
            current_grant.client_lock_fingerprint,
            original_grant.client_lock_fingerprint
        );
        assert!(!current_grant.revoked);
        assert_eq!(owner.snapshot.authority_revision.get(), 10_002);
        assert_eq!(
            owner
                .snapshot
                .history_checkpoint
                .as_ref()
                .unwrap()
                .request_epoch,
            313
        );
        assert!(owner.snapshot_json().unwrap().len() < 65_536);
    }
    #[test]
    fn ongoing_checkpoint_denies_old_ids_entropy_reuse_and_detached_or_damaged_restore() {
        let mut owner = owner();
        let token = issue(&mut owner, 7, 2000).token.unwrap();
        let old_use = use_request(&owner, &token, "request.use", 2100);
        assert!(owner.authorize_use(&old_use, 2100).applied);
        let old_snapshot = owner.snapshot.clone();
        owner.checkpoint_ongoing_history().unwrap();
        let mut replay = old_use.clone();
        replay.expected_authority_revision = owner.snapshot.authority_revision;
        assert_eq!(
            owner.authorize_use(&replay, 2200).rejection_reason,
            Some(ManifoldAdmissionRejectionReason::ReplayedRequest)
        );
        let fresh = issue(&mut owner, 7, 2200).token.unwrap();
        assert_ne!(fresh.token_id, token.token_id);
        let json = owner.snapshot_json().unwrap();
        let anchor = owner.seal_ongoing_history().unwrap();
        assert!(ManifoldAdmissionAuthority::from_snapshot(owner.snapshot.clone()).is_err());
        assert!(ManifoldAdmissionAuthority::restore_ongoing_history(
            &serde_json::to_string(&old_snapshot).unwrap(),
            &anchor
        )
        .is_err());
        let mut damaged = owner.snapshot.clone();
        damaged.grants[0].expires_at_ms += 1;
        assert!(ManifoldAdmissionAuthority::restore_ongoing_history(
            &serde_json::to_string(&damaged).unwrap(),
            &anchor
        )
        .is_err());
        let mut damaged = owner.snapshot.clone();
        damaged.history_checkpoint.as_mut().unwrap().request_epoch += 1;
        assert!(ManifoldAdmissionAuthority::restore_ongoing_history(
            &serde_json::to_string(&damaged).unwrap(),
            &anchor
        )
        .is_err());
        assert_eq!(
            ManifoldAdmissionAuthority::restore_ongoing_history(&json, &anchor).unwrap(),
            owner
        );
        let revoke = ManifoldAdmissionRevocationRequest {
            schema_id: schema_id(ADMISSION_REVOCATION_REQUEST_SCHEMA),
            request_id: owner
                .current_history_request_id(&id("request.revoke"))
                .unwrap(),
            expected_authority_revision: owner.snapshot.authority_revision,
            token_id: token.token_id.clone(),
            identity: token.identity.clone(),
            reason: id("reason.stop"),
        };
        assert!(owner.revoke_token(&revoke).applied);
        owner.checkpoint_ongoing_history().unwrap();
        let rejected = use_request(&owner, &token, "request.after", 2300);
        assert_eq!(
            owner.authorize_use(&rejected, 2300).rejection_reason,
            Some(ManifoldAdmissionRejectionReason::UnknownToken)
        );
        owner.validate_owned_history().unwrap();
        let expiry = owner
            .current_history_request_id(&id("sweep.expire"))
            .unwrap();
        assert!(
            owner
                .expire_tokens(expiry, owner.snapshot.authority_revision, 30_000)
                .applied
        );
        owner.checkpoint_ongoing_history().unwrap();
        assert!(owner.snapshot.active_tokens.is_empty());
        owner.validate_owned_history().unwrap();
    }
    #[test]
    fn ongoing_actual_epoch_and_audit_overflow_refuse_without_accepted_change() {
        let mut owner = owner();
        let c = owner.snapshot.history_checkpoint.as_mut().unwrap();
        c.request_epoch = u64::MAX;
        c.audit_sequence = u64::MAX - 1;
        c.prior_checkpoint_sha256 = Some(format!("sha256:{}", "d".repeat(64)));
        assert!(issue(&mut owner, 7, 2000).applied);
        let before = owner.clone();
        assert!(owner.checkpoint_ongoing_history().is_err());
        assert_eq!(owner, before);
        assert_eq!(
            issue(&mut owner, 8, 2000).rejection_reason,
            Some(ManifoldAdmissionRejectionReason::AuthorityCapacityExhausted)
        );
        assert_eq!(owner, before);
    }

    #[test]
    fn ongoing_checkpoint_pins_only_actual_accepted_live_obligation_use_proof() {
        let mut owner = owner();
        let token = issue(&mut owner, 7, 2000).token.unwrap();
        let original = use_request(&owner, &token, "request.original_start", 2100);
        assert!(owner.authorize_use(&original, 2100).applied);
        let original_event = owner.snapshot.audit_events.last().unwrap().clone();
        let pins = vec![original.request_id.clone()];
        for cycle in 0..100 {
            let current = use_request(&owner, &token, &format!("request.current.r{cycle}"), 2200);
            assert!(owner.authorize_use(&current, 2200).applied);
            owner
                .checkpoint_ongoing_history_with_retained_uses(&pins)
                .unwrap();
            assert_eq!(owner.snapshot.consumed_use_request_ids, pins);
            assert_eq!(
                owner
                    .snapshot
                    .history_checkpoint
                    .as_ref()
                    .unwrap()
                    .retained_use_authorizations,
                vec![original_event.clone()]
            );
            owner.validate_owned_history().unwrap();
        }
        let saved = owner.clone();
        assert!(owner
            .checkpoint_ongoing_history_with_retained_uses(&[id("request.forged")])
            .is_err());
        assert_eq!(owner, saved);
        assert!(owner
            .checkpoint_ongoing_history_with_retained_uses(&[pins[0].clone(), pins[0].clone()])
            .is_err());
        assert_eq!(owner, saved);
        let mut old = original;
        old.expected_authority_revision = owner.snapshot.authority_revision;
        assert_eq!(
            owner.authorize_use(&old, 2300).rejection_reason,
            Some(ManifoldAdmissionRejectionReason::ReplayedRequest)
        );
        let sweep = owner
            .current_history_request_id(&id("sweep.actual_expiry"))
            .unwrap();
        assert!(
            owner
                .expire_tokens(sweep, owner.snapshot.authority_revision, 30_000)
                .applied
        );
        owner
            .checkpoint_ongoing_history_with_retained_uses(&pins)
            .unwrap();
        assert!(owner.snapshot.active_tokens.is_empty());
        assert_eq!(
            owner
                .snapshot
                .history_checkpoint
                .as_ref()
                .unwrap()
                .retained_use_authorizations,
            vec![original_event]
        );
        owner.validate_owned_history().unwrap();
        // Once the actual downstream obligation closes, its historical proof is removable.
        owner
            .checkpoint_ongoing_history_with_retained_uses(&[])
            .unwrap();
        assert!(owner.snapshot.consumed_use_request_ids.is_empty());
        assert!(owner
            .snapshot
            .history_checkpoint
            .as_ref()
            .unwrap()
            .retained_use_authorizations
            .is_empty());
    }
}
