//! Typed construction of initial finite admission data.
use super::*;

impl ManifoldAdmissionSnapshot {
    /// Builds initial finite snapshot data with the caller's exact grants and policy.
    ///
    /// This creates no accepted authority or token. `ManifoldAdmissionAuthority::from_snapshot`
    /// still validates the snapshot before it can own decisions.
    pub fn initial(
        authority_id: DottedId,
        grants: Vec<ManifoldAdmissionGrant>,
        root_renewal_policies: Vec<ManifoldAdmissionRootRenewalPolicy>,
        max_token_ttl_ms: u64,
    ) -> Self {
        Self {
            development_lifetime_policy: None,
            schema_id: schema_id(ADMISSION_SNAPSHOT_SCHEMA),
            authority_id,
            authority_revision: Revision::INITIAL,
            history_checkpoint: None,
            grants,
            active_tokens: Vec::new(),
            revoked_token_ids: Vec::new(),
            consumed_request_ids: Vec::new(),
            consumed_use_request_ids: Vec::new(),
            reviewed_sweep_ids: Vec::new(),
            audit_events: Vec::new(),
            root_renewal_policies,
            max_token_ttl_ms,
        }
    }
}
