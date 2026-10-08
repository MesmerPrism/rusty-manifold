//! Current grant deadline renewal authorized before expiry by its actual scoped token.
use super::*;

/// Exact current grant and accepted paired proof selected by the owning product composition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldAdmissionGrantRenewalRequest {
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    pub request_id: DottedId,
    pub authorization: ManifoldAdmissionUseRequest,
    pub grant_id: DottedId,
    pub prior_expires_at_ms: u64,
    pub expires_at_ms: u64,
    pub accepted_evidence_id: DottedId,
    pub accepted_evidence_sha256: String,
}

/// Retained exact identity and lock-preserving grant deadline transition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldAdmissionGrantRenewalBinding {
    pub request: ManifoldAdmissionGrantRenewalRequest,
    pub observed_at_ms: u64,
    pub prior_grant: ManifoldAdmissionGrant,
    pub renewed_grant: ManifoldAdmissionGrant,
    pub use_authorization: ManifoldAdmissionReceipt,
}

/// Actual admission owner application with its scoped authorization receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldAdmissionGrantRenewalReceipt {
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    pub binding: ManifoldAdmissionGrantRenewalBinding,
    pub application: ManifoldAdmissionReceipt,
}

impl ManifoldAdmissionAuthority {
    /// Renews a still-current grant without changing its authenticated package, lock or capabilities.
    /// The retained owner caller must first validate the referenced proof in its own authority.
    pub fn renew_current_grant(
        &mut self,
        request: &ManifoldAdmissionGrantRenewalRequest,
        now_ms: u64,
    ) -> Result<ManifoldAdmissionGrantRenewalReceipt, ManifoldAdmissionError> {
        self.renew_current_grant_inner(request, now_ms, None)
    }
    /// Joins the exact scoped use already accepted and retained by this admission owner.
    pub fn renew_current_grant_after_authorized_use(
        &mut self,
        request: &ManifoldAdmissionGrantRenewalRequest,
        authorization: &ManifoldAdmissionReceipt,
        now_ms: u64,
    ) -> Result<ManifoldAdmissionGrantRenewalReceipt, ManifoldAdmissionError> {
        self.renew_current_grant_inner(request, now_ms, Some(authorization))
    }
    fn renew_current_grant_inner(
        &mut self,
        request: &ManifoldAdmissionGrantRenewalRequest,
        now_ms: u64,
        retained_authorization: Option<&ManifoldAdmissionReceipt>,
    ) -> Result<ManifoldAdmissionGrantRenewalReceipt, ManifoldAdmissionError> {
        if let Some(event) = self.snapshot.audit_events.iter().find(|event| {
            event.operation == ManifoldAdmissionOperation::RenewGrant
                && event.request_id == request.request_id
        }) {
            let binding =
                event
                    .grant_renewal
                    .as_ref()
                    .ok_or(ManifoldAdmissionError::InvalidSnapshot(
                        "renewal_replay_without_binding",
                    ))?;
            if binding.request != *request {
                return Err(ManifoldAdmissionError::InvalidSnapshot(
                    "renewal_replay_changed_bytes",
                ));
            }
            return Ok(ManifoldAdmissionGrantRenewalReceipt {
                schema_id: schema_id("rusty.manifold.admission.grant_renewal_receipt.v1"),
                binding: binding.clone(),
                application: ManifoldAdmissionReceipt {
                    schema_id: schema_id(ADMISSION_RECEIPT_SCHEMA),
                    operation: ManifoldAdmissionOperation::RenewGrant,
                    request_id: event.request_id.clone(),
                    applied: event.applied,
                    prior_authority_revision: event.prior_authority_revision,
                    resulting_authority_revision: event.resulting_authority_revision,
                    token: None,
                    removed_token_ids: Vec::new(),
                    rejection_reason: event.rejection_reason.clone(),
                },
            });
        }
        let prior_grant = self
            .snapshot
            .grants
            .iter()
            .find(|grant| grant.grant_id == request.grant_id)
            .ok_or(ManifoldAdmissionError::InvalidSnapshot(
                "grant_renewal_missing_grant",
            ))?
            .clone();
        if request.schema_id.as_str() != "rusty.manifold.admission.grant_renewal_request.v1"
            || request.authorization.capability_id.as_str()
                != "capability.manifold.control_lease.renew"
            || request.authorization.identity != prior_grant.identity
            || prior_grant.revoked
            || request.prior_expires_at_ms != prior_grant.expires_at_ms
            || prior_grant.expires_at_ms <= now_ms
            || request.expires_at_ms <= prior_grant.expires_at_ms
            || request
                .expires_at_ms
                .checked_sub(now_ms)
                .map_or(true, |ttl| ttl == 0 || ttl > 300_000)
            || !valid_sha256(&request.accepted_evidence_sha256)
            || self
                .snapshot
                .consumed_request_ids
                .contains(&request.request_id)
            || self.snapshot.audit_events.len().saturating_add(2) > MAX_ADMISSION_AUDIT_EVENTS
            || self
                .snapshot
                .authority_revision
                .next()
                .and_then(|revision| revision.next())
                .is_none()
        {
            return Err(ManifoldAdmissionError::InvalidSnapshot(
                "grant_renewal_not_current_scoped_advancing",
            ));
        }
        let token = self
            .snapshot
            .active_tokens
            .iter()
            .find(|token| token.token_id == request.authorization.token_id)
            .ok_or(ManifoldAdmissionError::InvalidSnapshot(
                "grant_renewal_token_missing",
            ))?;
        if token.grant_id != prior_grant.grant_id {
            return Err(ManifoldAdmissionError::InvalidSnapshot(
                "grant_renewal_foreign_token",
            ));
        }
        let authorization = if let Some(retained) = retained_authorization {
            if !retained.applied
                || retained.operation != ManifoldAdmissionOperation::AuthorizeUse
                || retained.request_id != request.authorization.request_id
                || retained.resulting_authority_revision != self.snapshot.authority_revision
                || !self.snapshot.audit_events.iter().any(|event| {
                    event.operation == ManifoldAdmissionOperation::AuthorizeUse
                        && event.applied
                        && event.request_id == retained.request_id
                        && event.resulting_authority_revision
                            == retained.resulting_authority_revision
                        && event.use_authorization.as_ref().is_some_and(|binding| {
                            binding.request == request.authorization
                                && binding.token.grant_id == request.grant_id
                        })
                })
            {
                return Err(ManifoldAdmissionError::InvalidSnapshot(
                    "grant_renewal_retained_authorization_mismatch",
                ));
            }
            retained.clone()
        } else {
            self.authorize_use(&request.authorization, now_ms)
        };
        if !authorization.applied {
            return Err(ManifoldAdmissionError::InvalidSnapshot(
                "grant_renewal_authorization_rejected",
            ));
        }
        let prior = self.snapshot.authority_revision;
        let resulting = prior.next().ok_or(ManifoldAdmissionError::InvalidSnapshot(
            "grant_renewal_revision_exhausted",
        ))?;
        let mut renewed_grant = prior_grant.clone();
        renewed_grant.expires_at_ms = request.expires_at_ms;
        *self
            .snapshot
            .grants
            .iter_mut()
            .find(|grant| grant.grant_id == request.grant_id)
            .expect("grant checked") = renewed_grant.clone();
        self.snapshot.authority_revision = resulting;
        self.snapshot
            .consumed_request_ids
            .push(request.request_id.clone());
        let application = self.finish(
            ManifoldAdmissionOperation::RenewGrant,
            request.request_id.clone(),
            prior,
            None,
            Vec::new(),
            None,
            None,
        );
        let binding = ManifoldAdmissionGrantRenewalBinding {
            request: request.clone(),
            observed_at_ms: now_ms,
            prior_grant,
            renewed_grant,
            use_authorization: authorization,
        };
        self.snapshot
            .audit_events
            .last_mut()
            .expect("renewal audit appended")
            .grant_renewal = Some(binding.clone());
        Ok(ManifoldAdmissionGrantRenewalReceipt {
            schema_id: schema_id("rusty.manifold.admission.grant_renewal_receipt.v1"),
            binding,
            application,
        })
    }
}

pub(super) fn validate_grant_renewal_history(
    snapshot: &ManifoldAdmissionSnapshot,
) -> Result<(), ManifoldAdmissionError> {
    let mut latest = BTreeMap::new();
    for event in &snapshot.audit_events {
        match (&event.operation, event.applied, &event.grant_renewal) {
            (ManifoldAdmissionOperation::RenewGrant, true, Some(binding)) => {
                let request = &binding.request;
                let mut expected = binding.prior_grant.clone();
                expected.expires_at_ms = request.expires_at_ms;
                let prior_use = snapshot.audit_events.iter().find(|use_| {
                    use_.operation == ManifoldAdmissionOperation::AuthorizeUse
                        && use_.request_id == request.authorization.request_id
                        && use_.applied
                });
                if expected != binding.renewed_grant
                    || binding.prior_grant.revoked
                    || binding.prior_grant.grant_id != request.grant_id
                    || binding.prior_grant.identity != request.authorization.identity
                    || binding.prior_grant.expires_at_ms != request.prior_expires_at_ms
                    || request.prior_expires_at_ms <= binding.observed_at_ms
                    || request.expires_at_ms <= request.prior_expires_at_ms
                    || request
                        .expires_at_ms
                        .checked_sub(binding.observed_at_ms)
                        .map_or(true, |ttl| ttl == 0 || ttl > 300_000)
                    || request.authorization.capability_id.as_str()
                        != "capability.manifold.control_lease.renew"
                    || !valid_sha256(&request.accepted_evidence_sha256)
                    || prior_use.map_or(true, |use_| {
                        use_.resulting_authority_revision != event.prior_authority_revision
                            || use_.use_authorization.as_ref().map_or(true, |actual| {
                                actual.request != request.authorization
                                    || actual.token.grant_id != request.grant_id
                            })
                    })
                    || !binding.use_authorization.applied
                    || binding.use_authorization.operation
                        != ManifoldAdmissionOperation::AuthorizeUse
                    || binding.use_authorization.request_id != request.authorization.request_id
                    || binding.use_authorization.resulting_authority_revision
                        != event.prior_authority_revision
                    || latest
                        .get(&request.grant_id)
                        .is_some_and(|old| *old != &binding.prior_grant)
                {
                    return Err(ManifoldAdmissionError::InvalidSnapshot(
                        "grant_renewal_history_binding",
                    ));
                }
                latest.insert(request.grant_id.clone(), &binding.renewed_grant);
            }
            (ManifoldAdmissionOperation::RenewGrant, _, _) => {
                return Err(ManifoldAdmissionError::InvalidSnapshot(
                    "grant_renewal_missing_binding",
                ))
            }
            (_, _, Some(_)) => {
                return Err(ManifoldAdmissionError::InvalidSnapshot(
                    "grant_renewal_wrong_operation",
                ))
            }
            _ => {}
        }
    }
    for (id, grant) in latest {
        if snapshot.grants.iter().find(|actual| actual.grant_id == id) != Some(grant) {
            return Err(ManifoldAdmissionError::InvalidSnapshot(
                "grant_renewal_current_join",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn id(value: &str) -> DottedId {
        DottedId::new(value).unwrap()
    }
    #[test]
    fn scoped_current_grant_renewal_retains_22_real_token_uses_and_rejects_tampering() {
        let identity = ManifoldClientIdentity {
            client_id: id("client.renewal"),
            platform_subject: "test.actual.authority".to_owned(),
            signing_fingerprint: format!("sha256:{}", "a".repeat(64)),
        };
        let capability = id("capability.manifold.control_lease.renew");
        let mut owner = ManifoldAdmissionAuthority::from_snapshot(ManifoldAdmissionSnapshot {
            schema_id: schema_id(ADMISSION_SNAPSHOT_SCHEMA),
            authority_id: id("authority.renewal"),
            authority_revision: Revision::INITIAL,
            grants: vec![ManifoldAdmissionGrant {
                grant_id: id("grant.renewal"),
                client_lock_id: id("lock.renewal"),
                client_lock_fingerprint: format!("sha256:{}", "b".repeat(64)),
                identity: identity.clone(),
                capabilities: vec![capability.clone()],
                expires_at_ms: 100000,
                revoked: false,
            }],
            active_tokens: Vec::new(),
            revoked_token_ids: Vec::new(),
            consumed_request_ids: Vec::new(),
            consumed_use_request_ids: Vec::new(),
            reviewed_sweep_ids: Vec::new(),
            audit_events: Vec::new(),
            max_token_ttl_ms: 5000,
        })
        .unwrap();
        for cycle in 0..22u64 {
            let now = 2000 + ((cycle / 2) * 120000) + (cycle % 2);
            let issued = owner.issue_token(
                &ManifoldAdmissionRequest {
                    schema_id: schema_id(ADMISSION_REQUEST_SCHEMA),
                    request_id: id(&format!("request.token.r{cycle}")),
                    expected_authority_revision: owner.snapshot().authority_revision,
                    identity: identity.clone(),
                    requested_capabilities: vec![capability.clone()],
                    issued_at_ms: now,
                    expires_at_ms: now + 5000,
                    requested_token_ttl_ms: 5000,
                },
                [cycle as u8; 32],
                now,
            );
            assert!(issued.applied);
            let request = ManifoldAdmissionGrantRenewalRequest {
                schema_id: schema_id("rusty.manifold.admission.grant_renewal_request.v1"),
                request_id: id(&format!("request.grant.r{cycle}")),
                authorization: ManifoldAdmissionUseRequest {
                    schema_id: schema_id(ADMISSION_USE_REQUEST_SCHEMA),
                    request_id: id(&format!("request.use.r{cycle}")),
                    expected_authority_revision: owner.snapshot().authority_revision,
                    token_id: issued.token.unwrap().token_id,
                    identity: identity.clone(),
                    capability_id: capability.clone(),
                    issued_at_ms: now,
                    expires_at_ms: now + 5000,
                },
                grant_id: id("grant.renewal"),
                prior_expires_at_ms: owner.snapshot().grants[0].expires_at_ms,
                expires_at_ms: now + 300000,
                accepted_evidence_id: id(&format!("receipt.signed.r{cycle}")),
                accepted_evidence_sha256: format!("sha256:{}", "c".repeat(64)),
            };
            let mut bad = request.clone();
            bad.authorization.identity.signing_fingerprint = format!("sha256:{}", "d".repeat(64));
            let prior = owner.clone();
            assert!(owner.renew_current_grant(&bad, now).is_err());
            assert_eq!(owner, prior);
            let receipt = owner.renew_current_grant(&request, now).unwrap();
            assert!(receipt.application.applied);
            assert_eq!(owner.renew_current_grant(&request, now).unwrap(), receipt);
            let json = owner.snapshot_json().unwrap();
            assert!(ManifoldAdmissionAuthority::restart_from_json(&json).is_ok());
            let mut malformed = owner.snapshot().clone();
            malformed.grants[0].expires_at_ms += 1;
            assert!(ManifoldAdmissionAuthority::from_snapshot(malformed).is_err());
        }
        assert_eq!(
            owner
                .snapshot()
                .audit_events
                .iter()
                .filter(|event| event.operation == ManifoldAdmissionOperation::RenewGrant)
                .count(),
            22
        );
    }
}
