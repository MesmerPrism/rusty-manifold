//! Process-local source custody for the deliberately selected root transaction.
//! Evidence is serializable; this permit and its issuer are not. No old snapshot
//! or receipt can recreate the actual registered writable owner's custody.
use rusty_manifold_model::ManifoldSourceBoundRootEvidence;
use std::sync::Arc;

#[derive(Debug)]
pub struct ManifoldSourceBoundRootIssuer {
    identity: Arc<()>,
    committed_sequence: u64,
    stopped: bool,
    committed_receipt_sha256: Option<String>,
}
#[derive(Clone, Debug)]
pub struct ManifoldSourceBoundRootVerifier {
    identity: Arc<()>,
}
pub struct ManifoldSourceBoundRootPermit<'owner> {
    issuer: &'owner mut ManifoldSourceBoundRootIssuer,
    evidence: ManifoldSourceBoundRootEvidence,
}
impl PartialEq for ManifoldSourceBoundRootIssuer {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.identity, &other.identity)
            && self.committed_sequence == other.committed_sequence
            && self.stopped == other.stopped
            && self.committed_receipt_sha256 == other.committed_receipt_sha256
    }
}
impl Eq for ManifoldSourceBoundRootIssuer {}
impl PartialEq for ManifoldSourceBoundRootVerifier {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.identity, &other.identity)
    }
}
impl Eq for ManifoldSourceBoundRootVerifier {}
impl ManifoldSourceBoundRootIssuer {
    /// Deployment construction only: move issuer immediately into the newly
    /// created actual selected M owner and verifier into its SAME pristine Broker.
    /// Neither component exposes the stored issuer, and later registration refuses.
    pub fn new_selected_owner() -> (Self, ManifoldSourceBoundRootVerifier) {
        let identity = Arc::new(());
        (
            Self {
                identity: identity.clone(),
                committed_sequence: 0,
                stopped: false,
                committed_receipt_sha256: None,
            },
            ManifoldSourceBoundRootVerifier { identity },
        )
    }
    pub fn next_sequence(&self) -> Result<u64, &'static str> {
        if self.stopped {
            return Err("root issuer explicitly stopped");
        }
        self.committed_sequence
            .checked_add(1)
            .ok_or("root sequence exhausted")
    }
    /// Actual M owner calls only after deriving and joining current selected
    /// source/key/floor/pair evidence and actual no-live-Peer graph. This routine
    /// does not turn supplied evidence into physical cleanup or key authority.
    pub fn borrow_current(
        &mut self,
        evidence: ManifoldSourceBoundRootEvidence,
        now_ms: u64,
    ) -> Result<ManifoldSourceBoundRootPermit<'_>, &'static str> {
        evidence.validate_at(now_ms)?;
        if evidence.sequence != self.next_sequence()? {
            return Err("root issuer sequence mismatch");
        }
        Ok(ManifoldSourceBoundRootPermit {
            issuer: self,
            evidence,
        })
    }
    /// This is the latest real publication, never reconstructed from a snapshot.
    pub fn matches_committed_receipt(&self, sequence: u64, digest: &str) -> bool {
        !self.stopped
            && self.committed_sequence == sequence
            && self.committed_receipt_sha256.as_deref() == Some(digest)
    }
    pub fn stop(&mut self) {
        self.stopped = true;
    }
}
impl ManifoldSourceBoundRootVerifier {
    pub fn verify<'a>(
        &self,
        permit: &'a ManifoldSourceBoundRootPermit<'_>,
        now_ms: u64,
    ) -> Result<&'a ManifoldSourceBoundRootEvidence, &'static str> {
        if !Arc::ptr_eq(&self.identity, &permit.issuer.identity)
            || permit.issuer.stopped
            || permit.issuer.committed_sequence.checked_add(1) != Some(permit.evidence.sequence)
        {
            return Err("foreign, stale or stopped root permit");
        }
        permit.evidence.validate_at(now_ms)?;
        Ok(&permit.evidence)
    }
}
impl ManifoldSourceBoundRootPermit<'_> {
    pub fn evidence(&self) -> &ManifoldSourceBoundRootEvidence {
        &self.evidence
    }
    /// Call only after every exact-current owner check has finished and the
    /// enclosing borrowed plan can publish all states without another fallible call.
    pub fn commit(self) {
        self.issuer.committed_sequence = self.evidence.sequence;
        self.issuer.committed_receipt_sha256 = None;
    }
    /// Enclosing owner qualifies this exact complete typed result before commit.
    /// Only one digest is retained; earned durable custody owns previous bodies.
    pub fn commit_with_receipt_digest(self, digest: String) {
        self.issuer.committed_sequence = self.evidence.sequence;
        self.issuer.committed_receipt_sha256 = Some(digest);
    }
}

#[cfg(test)]
mod controls {
    use super::*;
    fn evidence(sequence: u64) -> ManifoldSourceBoundRootEvidence {
        let sha = format!("sha256:{}", "a1".repeat(32));
        serde_json::from_value(serde_json::json!({"$schema":"rusty.manifold.authority.source_bound_root.v1",
        "request_id":"request.root.control","sequence":sequence,"peer_host_id":"host.root.control","provider_epoch_id":"epoch.root.control",
        "native_setup_request_id":"ceremony.duplex.control","native_phase_id":"ceremony.duplex.control-phase","grant_id":"grant.root.control","lease_id":"lease.root.control",
        "peer_disposition":"never_started","lifetime_ordinal":0,"prior_start_sha256":null,"terminal_stop_sha256":null,
        "native_lifecycle_sha256":sha,"native_actor_sha256":sha,"runtime_configuration_sha256":sha,"arm_binding_sha256":sha,
        "selected_policy_sha256":sha,"source_peer_snapshot_sha256":sha,"fresh_setup_receipt_sha256":sha,"current_pair_sha256":sha,"current_floor_sha256":sha,
        "observed_at_ms":100,"actual_authority_expires_at_ms":200})).unwrap()
    }
    #[test]
    fn supplied_evidence_cannot_cross_registered_owner_and_old_sequence_cannot_replay() {
        let (mut owner, verifier) = ManifoldSourceBoundRootIssuer::new_selected_owner();
        let (mut foreign, _) = ManifoldSourceBoundRootIssuer::new_selected_owner();
        {
            let p = foreign.borrow_current(evidence(1), 100).unwrap();
            assert!(verifier.verify(&p, 100).is_err());
        }
        {
            let p = owner.borrow_current(evidence(1), 100).unwrap();
            assert_eq!(verifier.verify(&p, 100).unwrap().sequence, 1);
            p.commit();
        }
        assert!(owner.borrow_current(evidence(1), 100).is_err());
        assert_eq!(owner.next_sequence().unwrap(), 2);
    }
    #[test]
    fn actual_expiry_and_explicit_owner_stop_remain_strict() {
        let (mut owner, verifier) = ManifoldSourceBoundRootIssuer::new_selected_owner();
        {
            let p = owner.borrow_current(evidence(1), 100).unwrap();
            assert!(verifier.verify(&p, 200).is_err());
        }
        owner.stop();
        assert!(owner.borrow_current(evidence(1), 100).is_err());
    }
    #[test]
    fn dropping_unpublished_permit_keeps_actual_sequence_and_reborrow_exact() {
        let (mut owner, verifier) = ManifoldSourceBoundRootIssuer::new_selected_owner();
        {
            let p = owner.borrow_current(evidence(1), 100).unwrap();
            assert!(verifier.verify(&p, 100).is_ok());
        }
        assert_eq!(owner.next_sequence().unwrap(), 1);
        let p = owner.borrow_current(evidence(1), 100).unwrap();
        p.commit();
        assert_eq!(owner.next_sequence().unwrap(), 2);
    }
}
