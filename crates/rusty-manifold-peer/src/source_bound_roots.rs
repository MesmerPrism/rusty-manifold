//! Borrowed initialization and proof custody of the EXISTING signed owner.
use super::*;
use rusty_manifold_runtime_host::{
    ManifoldSourceBoundRootIssuer, ManifoldSourceBoundRootPermit, ManifoldSourceBoundRootVerifier,
};
pub struct ManifoldSourceBoundRootRegistration<'owner> {
    owner: &'owner mut ManifoldReciprocalHistoryOwner,
    issuer: ManifoldSourceBoundRootIssuer,
    verifier: ManifoldSourceBoundRootVerifier,
}
impl ManifoldReciprocalHistoryOwner {
    pub fn prepare_source_bound_root_registration(
        &mut self,
    ) -> Result<ManifoldSourceBoundRootRegistration<'_>, &'static str> {
        if self.source_bound_root_issuer.is_some()
            || self.state().authority_revision != Revision::INITIAL
        {
            return Err("root signed owner registration not pristine");
        }
        let (issuer, verifier) = ManifoldSourceBoundRootIssuer::new_selected_owner();
        Ok(ManifoldSourceBoundRootRegistration {
            owner: self,
            issuer,
            verifier,
        })
    }
    pub fn matches_committed_source_bound_root_receipt(&self, sequence: u64, digest: &str) -> bool {
        self.source_bound_root_issuer
            .as_ref()
            .is_some_and(|i| i.matches_committed_receipt(sequence, digest))
    }
    pub fn next_source_bound_root_sequence(&self) -> Result<u64, &'static str> {
        self.source_bound_root_issuer
            .as_ref()
            .ok_or("root issuer not initially selected")?
            .next_sequence()
    }
    pub fn borrow_source_bound_root_permit(
        &mut self,
        evidence: rusty_manifold_model::ManifoldSourceBoundRootEvidence,
        now: u64,
    ) -> Result<ManifoldSourceBoundRootPermit<'_>, &'static str> {
        self.source_bound_root_issuer
            .as_mut()
            .ok_or("root issuer not initially selected")?
            .borrow_current(evidence, now)
    }
}
impl ManifoldSourceBoundRootRegistration<'_> {
    pub fn verifier(&self) -> ManifoldSourceBoundRootVerifier {
        self.verifier.clone()
    }
    /// All Broker initial checks precede this infallible same-owner installation.
    pub fn commit(self) {
        self.owner.source_bound_root_issuer = Some(self.issuer);
    }
}
