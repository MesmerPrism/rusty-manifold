//! Exact selected-owner re-establishment, distinct from expired-v1 renewal.
use super::*;
use rusty_manifold_model::ManifoldSourceBoundRootEvidence;
use rusty_manifold_runtime_host::{ManifoldSourceBoundRootPermit, ManifoldSourceBoundRootVerifier};
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldSourceBoundGrantReestablishmentRequest {
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    pub request_id: DottedId,
    pub expected_authority_revision: Revision,
    pub prior_grant: ManifoldAdmissionGrant,
    pub expires_at_ms: u64,
    pub authority: ManifoldSourceBoundRootEvidence,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldSourceBoundGrantReestablishmentBinding {
    pub request: ManifoldSourceBoundGrantReestablishmentRequest,
    pub observed_at_ms: u64,
    pub root_renewal_horizon_ms: u64,
    pub resulting_grant: ManifoldAdmissionGrant,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldSourceBoundGrantReestablishmentReceipt {
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    pub binding: ManifoldSourceBoundGrantReestablishmentBinding,
    pub application: ManifoldAdmissionReceipt,
}
fn invalid(message: &'static str) -> ManifoldAdmissionError {
    ManifoldAdmissionError::InvalidSnapshot(message)
}
impl ManifoldAdmissionAuthority {
    /// Initial deployment joins the actual selected M owner exactly once, before
    /// tokens/uses/history exist. No serialized snapshot selects or restores it.
    pub fn register_source_bound_root_owner(
        &mut self,
        verifier: ManifoldSourceBoundRootVerifier,
        grant_id: DottedId,
        lease_id: DottedId,
        now: u64,
    ) -> Result<(), ManifoldAdmissionError> {
        if self.snapshot.history_checkpoint.is_none()
            || self.source_bound_root_owner.is_some()
            || !self.snapshot.audit_events.is_empty()
            || !self.snapshot.active_tokens.is_empty()
            || !self.snapshot.consumed_request_ids.is_empty()
            || !self.snapshot.consumed_use_request_ids.is_empty()
            || self.snapshot.authority_revision != Revision::INITIAL
            || self
                .snapshot
                .grants
                .iter()
                .find(|g| g.grant_id == grant_id)
                .map_or(true, |g| g.revoked || g.expires_at_ms <= now)
        {
            return Err(invalid("root owner registration not pristine/current"));
        }
        self.source_bound_root_owner = Some((verifier, grant_id, lease_id));
        Ok(())
    }
    pub fn source_bound_root_target(&self) -> Option<(&DottedId, &DottedId)> {
        self.source_bound_root_owner
            .as_ref()
            .map(|(_, grant, lease)| (grant, lease))
    }
    pub fn validate_source_bound_root_permit(
        &self,
        permit: &ManifoldSourceBoundRootPermit<'_>,
        now: u64,
    ) -> Result<(), ManifoldAdmissionError> {
        let (verifier, grant, lease) = self
            .source_bound_root_owner
            .as_ref()
            .ok_or(invalid("root owner not initially selected"))?;
        let evidence = verifier.verify(permit, now).map_err(invalid)?;
        if grant != &evidence.grant_id || lease != &evidence.lease_id {
            return Err(invalid("root registered identity differs"));
        }
        Ok(())
    }
    pub fn reestablish_source_bound_grant(
        &mut self,
        permit: &ManifoldSourceBoundRootPermit<'_>,
        request: &ManifoldSourceBoundGrantReestablishmentRequest,
        now: u64,
    ) -> Result<ManifoldSourceBoundGrantReestablishmentReceipt, ManifoldAdmissionError> {
        let (verifier, grant_id, lease_id) = self
            .source_bound_root_owner
            .as_ref()
            .ok_or(invalid("root owner not initially selected"))?;
        let authority = verifier.verify(permit, now).map_err(invalid)?;
        if authority != &request.authority
            || grant_id != &request.prior_grant.grant_id
            || lease_id != &authority.lease_id
        {
            return Err(invalid("root owner source/scope mismatch"));
        }
        // Same native exact Original queries retained results rather than minting
        // a second permit. Changed bytes for a consumed request always refuse.
        if let Some(event) = self
            .snapshot
            .audit_events
            .iter()
            .find(|e| e.request_id == request.request_id)
        {
            let b = event
                .grant_reestablishment
                .as_ref()
                .ok_or(invalid("root request conflicts with prior operation"))?;
            if b.request != *request {
                return Err(invalid("root request replay changed bytes"));
            }
            return Ok(ManifoldSourceBoundGrantReestablishmentReceipt {
                schema_id: schema_id(
                    "rusty.manifold.admission.source_bound_grant_reestablishment_receipt.v1",
                ),
                binding: b.clone(),
                application: ManifoldAdmissionReceipt {
                    schema_id: schema_id(ADMISSION_RECEIPT_SCHEMA),
                    operation: ManifoldAdmissionOperation::ReestablishGrant,
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
        validate_request(
            request,
            now,
            self.snapshot
                .root_renewal_horizon_ms(&request.prior_grant.grant_id),
        )?;
        if request.expected_authority_revision != self.snapshot.authority_revision
            || !ongoing_history::request_matches(&self.snapshot, &request.request_id)
            || self
                .snapshot
                .grants
                .iter()
                .find(|g| g.grant_id == request.prior_grant.grant_id)
                != Some(&request.prior_grant)
            || self
                .snapshot
                .consumed_request_ids
                .contains(&request.request_id)
            || ongoing_history::audit_capacity_exhausted(&self.snapshot, 1)
        {
            return Err(invalid("root grant source/replay/capacity"));
        }
        let resulting = self
            .snapshot
            .authority_revision
            .next()
            .ok_or(invalid("root grant revision exhausted"))?;
        let mut grant = request.prior_grant.clone();
        grant.expires_at_ms = request.expires_at_ms;
        let binding = ManifoldSourceBoundGrantReestablishmentBinding {
            request: request.clone(),
            observed_at_ms: now,
            root_renewal_horizon_ms: self.snapshot.root_renewal_horizon_ms(&grant.grant_id),
            resulting_grant: grant.clone(),
        };
        let mut candidate = self.clone();
        *candidate
            .snapshot
            .grants
            .iter_mut()
            .find(|g| g.grant_id == request.prior_grant.grant_id)
            .ok_or(invalid("root grant vanished"))? = grant;
        let prior = candidate.snapshot.authority_revision;
        candidate.snapshot.authority_revision = resulting;
        candidate
            .snapshot
            .consumed_request_ids
            .push(request.request_id.clone());
        let application = candidate.finish(
            ManifoldAdmissionOperation::ReestablishGrant,
            request.request_id.clone(),
            prior,
            None,
            Vec::new(),
            None,
            None,
        );
        candidate
            .snapshot
            .audit_events
            .last_mut()
            .ok_or(invalid("root audit absent"))?
            .grant_reestablishment = Some(binding.clone());
        validate_snapshot(&candidate.snapshot)?;
        *self = candidate;
        Ok(ManifoldSourceBoundGrantReestablishmentReceipt {
            schema_id: schema_id(
                "rusty.manifold.admission.source_bound_grant_reestablishment_receipt.v1",
            ),
            binding,
            application,
        })
    }
}
fn validate_request(
    request: &ManifoldSourceBoundGrantReestablishmentRequest,
    now: u64,
    horizon: u64,
) -> Result<(), ManifoldAdmissionError> {
    request.authority.validate_at(now).map_err(invalid)?;
    if request.schema_id.as_str()
        != "rusty.manifold.admission.source_bound_grant_reestablishment_request.v1"
        || request.prior_grant.revoked
        || request.prior_grant.expires_at_ms > now
        || request.authority.grant_id != request.prior_grant.grant_id
        || request.expires_at_ms <= now
        || request.expires_at_ms <= request.prior_grant.expires_at_ms
        || request.expires_at_ms > request.authority.actual_authority_expires_at_ms
        || request
            .expires_at_ms
            .checked_sub(now)
            .map_or(true, |n| n == 0 || n > horizon)
    {
        return Err(invalid("root grant identity/current authority/horizon"));
    }
    Ok(())
}
pub(super) fn validate_source_bound_root_history_event<'a>(
    event: &'a ManifoldAdmissionAuditEvent,
    snapshot: &ManifoldAdmissionSnapshot,
) -> Result<Option<&'a ManifoldSourceBoundGrantReestablishmentBinding>, ManifoldAdmissionError> {
    if snapshot.history_checkpoint.is_none() && event.grant_reestablishment.is_some() {
        return Err(invalid(
            "root lineage cannot select finite or restored owner",
        ));
    }
    match (
        &event.operation,
        event.applied,
        event.grant_reestablishment.as_ref(),
    ) {
        (ManifoldAdmissionOperation::ReestablishGrant, true, Some(binding)) => {
            validate_request(
                &binding.request,
                binding.observed_at_ms,
                binding.root_renewal_horizon_ms,
            )?;
            let mut expected = binding.request.prior_grant.clone();
            expected.expires_at_ms = binding.request.expires_at_ms;
            if binding.root_renewal_horizon_ms
                != snapshot.root_renewal_horizon_ms(&expected.grant_id)
                || binding.request.expected_authority_revision != event.prior_authority_revision
                || binding.request.request_id != event.request_id
                || expected != binding.resulting_grant
                || event.grant_renewal.is_some()
                || event.use_authorization.is_some()
                || event.rejection_reason.is_some()
                || event.prior_authority_revision.next() != Some(event.resulting_authority_revision)
            {
                return Err(invalid("root grant historical exact binding"));
            }
            Ok(Some(binding))
        }
        (ManifoldAdmissionOperation::ReestablishGrant, _, _) | (_, _, Some(_)) => {
            Err(invalid("root grant missing/wrong operation binding"))
        }
        _ => Ok(None),
    }
}

/// Historical DATA derivation from the already validated actual ledger/checkpoint.
/// This returns no mutation permit and does not validate supplied receipt authority.
pub fn source_bound_grant_at_revision(
    snapshot: &ManifoldAdmissionSnapshot,
    id: &DottedId,
    revision: Revision,
) -> Result<ManifoldAdmissionGrant, ManifoldAdmissionError> {
    let base = snapshot
        .history_checkpoint
        .as_ref()
        .map_or(Revision::INITIAL, |c| c.authority_revision);
    if revision < base || revision > snapshot.authority_revision {
        return Err(invalid("root historical admission revision outside suffix"));
    }
    let mut value = snapshot
        .grants
        .iter()
        .find(|g| &g.grant_id == id)
        .cloned()
        .ok_or(invalid("root historical grant absent"))?;
    for event in snapshot
        .audit_events
        .iter()
        .rev()
        .filter(|e| e.applied && e.resulting_authority_revision > revision)
    {
        if let Some(b) = &event.grant_renewal {
            if &b.request.grant_id == id {
                if value != b.renewed_grant {
                    return Err(invalid("root historical ordinary grant chain"));
                }
                value = b.prior_grant.clone();
            }
        }
        if let Some(b) = &event.grant_reestablishment {
            if &b.request.prior_grant.grant_id == id {
                if value != b.resulting_grant {
                    return Err(invalid("root historical reestablishment grant chain"));
                }
                value = b.request.prior_grant.clone();
            }
        }
    }
    Ok(value)
}
