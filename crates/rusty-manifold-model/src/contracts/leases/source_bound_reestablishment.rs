//! New source-bound root operation. Ordinary v1 lease renewal stays unchanged.
use super::*;

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(deny_unknown_fields, rename_all = "snake_case")
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManifoldSourceBoundPeerDisposition {
    NeverStarted,
    FullyStopped,
}
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldSourceBoundRootEvidence {
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    pub request_id: DottedId,
    pub sequence: u64,
    pub peer_host_id: DottedId,
    pub provider_epoch_id: DottedId,
    pub native_setup_request_id: DottedId,
    pub native_phase_id: DottedId,
    pub grant_id: DottedId,
    pub lease_id: DottedId,
    pub peer_disposition: ManifoldSourceBoundPeerDisposition,
    pub lifetime_ordinal: u64,
    pub prior_start_sha256: Option<String>,
    pub terminal_stop_sha256: Option<String>,
    pub native_lifecycle_sha256: String,
    pub native_actor_sha256: String,
    pub runtime_configuration_sha256: String,
    pub arm_binding_sha256: String,
    pub selected_policy_sha256: String,
    pub source_peer_snapshot_sha256: String,
    pub fresh_setup_receipt_sha256: String,
    pub current_pair_sha256: String,
    pub current_floor_sha256: String,
    pub observed_at_ms: u64,
    pub actual_authority_expires_at_ms: u64,
}
fn root_sha(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|s| {
        s.len() == 64
            && s.bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    })
}
impl ManifoldSourceBoundRootEvidence {
    pub fn validate_at(&self, now: u64) -> Result<(), &'static str> {
        if self.schema_id.as_str() != "rusty.manifold.authority.source_bound_root.v1"
            || self.sequence == 0
            || self.observed_at_ms > now
            || self.actual_authority_expires_at_ms <= now
        {
            return Err("source-bound root identity/time");
        }
        for s in [
            &self.native_lifecycle_sha256,
            &self.native_actor_sha256,
            &self.runtime_configuration_sha256,
            &self.arm_binding_sha256,
            &self.selected_policy_sha256,
            &self.source_peer_snapshot_sha256,
            &self.fresh_setup_receipt_sha256,
            &self.current_pair_sha256,
            &self.current_floor_sha256,
        ] {
            if !root_sha(s) {
                return Err("source-bound root exact digest");
            }
        }
        match self.peer_disposition {
            ManifoldSourceBoundPeerDisposition::NeverStarted
                if self.lifetime_ordinal == 0
                    && self.prior_start_sha256.is_none()
                    && self.terminal_stop_sha256.is_none() => {}
            ManifoldSourceBoundPeerDisposition::FullyStopped
                if self.lifetime_ordinal > 0
                    && self.prior_start_sha256.as_deref().is_some_and(root_sha)
                    && self.terminal_stop_sha256.as_deref().is_some_and(root_sha) => {}
            _ => return Err("source-bound root earned Peer disposition"),
        }
        Ok(())
    }
}
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldSourceBoundControlLeaseReestablishmentRequest {
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    pub request_id: DottedId,
    pub expected_authority_revision: Revision,
    pub prior_lease: ManifoldControlLease,
    pub expires_at_ms: u64,
    pub authority: ManifoldSourceBoundRootEvidence,
}
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldSourceBoundControlLeaseReestablishmentApplication {
    pub authority_id: DottedId,
    pub application_id: DottedId,
    pub from_authority_revision: Revision,
    pub lease_id: DottedId,
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    pub request: ManifoldSourceBoundControlLeaseReestablishmentRequest,
    pub recorded_clock: ManifoldClockSnapshot,
    pub renewed_lease: ManifoldControlLease,
    pub applied_snapshot: Option<ManifoldAuthoritySnapshot>,
}
impl ManifoldAuthoritySnapshot {
    /// Pure owning model review/application; actual Broker accepts it only under
    /// a permit from its initially registered selected M owner, never this data alone.
    pub fn apply_source_bound_control_lease_reestablishment(
        &self,
        request: ManifoldSourceBoundControlLeaseReestablishmentRequest,
        clock: ManifoldClockSnapshot,
    ) -> Result<ManifoldSourceBoundControlLeaseReestablishmentApplication, &'static str> {
        self.validate_authority_links()
            .map_err(|_| "root source links")?;
        let now = wall_unix_ms_u64(&clock);
        request.authority.validate_at(now)?;
        if request.schema_id.as_str()
            != "rusty.manifold.authority.source_bound_control_lease_reestablishment_request.v1"
            || request.expected_authority_revision != self.authority_revision
            || request.authority.lease_id != request.prior_lease.lease_id
            || request.expires_at_ms <= now
            || request.expires_at_ms <= request.prior_lease.expires_at_ms
            || request.expires_at_ms > request.authority.actual_authority_expires_at_ms
            || clock.clock_domain != self.clock_snapshot.clock_domain
            || clock.clock_epoch_id != self.clock_snapshot.clock_epoch_id
            || clock.sequence < self.clock_snapshot.sequence
            || clock.monotonic_elapsed_ns < self.clock_snapshot.monotonic_elapsed_ns
            || clock.wall_unix_ms < self.clock_snapshot.wall_unix_ms
            || clock.wall_clock_adjustment_count != self.clock_snapshot.wall_clock_adjustment_count
            || clock.health != ClockHealth::Healthy
            || request.prior_lease.state != LeaseState::Active
            || request.prior_lease.expires_at_ms > now
            || self.active_lease(&request.prior_lease.lease_id) != Some(&request.prior_lease)
            || self
                .revoked_control_lease_tombstones
                .iter()
                .any(|r| r.revoked_lease.lease_id == request.prior_lease.lease_id)
        {
            return Err("root lease exact preimage/current authority");
        }
        let mut renewed = request.prior_lease.clone();
        renewed.expires_at_ms = request.expires_at_ms;
        let mut target = self.clone();
        target.authority_revision = self
            .authority_revision
            .next()
            .ok_or("root revision exhausted")?;
        target.clock_snapshot = clock.clone();
        *target
            .active_leases
            .iter_mut()
            .find(|r| r.lease_id == renewed.lease_id)
            .ok_or("root lease missing")? = renewed.clone();
        target
            .validate_authority_links()
            .map_err(|_| "root result links")?;
        Ok(ManifoldSourceBoundControlLeaseReestablishmentApplication{authority_id:self.authority_id.clone(),application_id:DottedId::new(format!("{}.source-bound-root-applied",request.request_id)).map_err(|_|"root application identity")?,from_authority_revision:self.authority_revision,lease_id:renewed.lease_id.clone(),schema_id:SchemaId::new("rusty.manifold.authority.source_bound_control_lease_reestablishment_application.v1").map_err(|_|"static root schema")?,request,recorded_clock:clock,renewed_lease:renewed,applied_snapshot:Some(target)})
    }
}
impl ManifoldSourceBoundControlLeaseReestablishmentApplication {
    pub fn validate_against_snapshot(
        &self,
        source: &ManifoldAuthoritySnapshot,
    ) -> Result<(), &'static str> {
        if self
            != &source.apply_source_bound_control_lease_reestablishment(
                self.request.clone(),
                self.recorded_clock.clone(),
            )?
        {
            return Err("root application full delta mismatch");
        }
        Ok(())
    }
}
