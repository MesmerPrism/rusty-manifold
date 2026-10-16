//! Actual nested Runtime Host retention for checkpoint-enabled composition.
use super::*;
use rusty_manifold_runtime_host::ManifoldRuntimeAcceptedDerivativeProjection as Projection;

impl ManifoldPeerRuntimeHost {
    /// Qualifies a fresh embedded command against its actual command owner epoch.
    pub fn current_media_history_request_id(
        &self,
        suffix: &DottedId,
    ) -> Result<DottedId, ManifoldPeerRuntimeHostError> {
        self.media_runtime_copy()?
            .current_history_request_id(suffix)
            .map_err(|e| invalid_snapshot(&format!("media request identity: {e}")))
    }
    pub(super) fn ensure_media_history_request(
        &self,
        id: &DottedId,
    ) -> Result<(), ManifoldPeerRuntimeHostError> {
        self.validate_media_runtime_owner()?;
        if self
            .snapshot
            .media_command_runtime
            .history_checkpoint
            .as_ref()
            .map_or(true, |c| {
                id.as_str()
                    .strip_prefix(&format!("history.{}.", c.request_epoch))
                    .is_some_and(|suffix| !suffix.is_empty() && !suffix.starts_with("history."))
            })
        {
            Ok(())
        } else {
            Err(ManifoldPeerRuntimeHostError::ReplayedMutation(id.clone()))
        }
    }
    /// Only the prospective actual Peer owner may select its nested storage.
    pub(super) fn enable_owned_media_runtime_history(
        &mut self,
    ) -> Result<(), ManifoldPeerRuntimeHostError> {
        if self.media_runtime_owner.is_some() {
            return self.validate_media_runtime_owner();
        }
        let mut runtime =
            ManifoldRuntimeHost::from_snapshot(self.snapshot.media_command_runtime.clone())
                .map_err(|e| {
                    invalid_snapshot(&format!("owned media Runtime Host selection: {e}"))
                })?;
        runtime
            .enable_ongoing_history()
            .map_err(|e| invalid_snapshot(&format!("owned media history: {e}")))?;
        self.snapshot.media_command_runtime = runtime.snapshot().clone();
        self.media_runtime_owner = Some(Box::new(runtime));
        Ok(())
    }
    pub(super) fn validate_media_runtime_owner(&self) -> Result<(), ManifoldPeerRuntimeHostError> {
        if let Some(owner) = &self.media_runtime_owner {
            if owner.snapshot() != &self.snapshot.media_command_runtime {
                return Err(invalid_snapshot("actual nested media owner differs"));
            }
            owner
                .validate_owned_history()
                .map_err(|e| invalid_snapshot(&format!("actual nested media owner: {e}")))?;
        } else if self
            .snapshot
            .media_command_runtime
            .history_checkpoint
            .is_some()
        {
            return Err(invalid_snapshot(
                "ongoing nested snapshot has no actual owner",
            ));
        }
        Ok(())
    }
    pub(super) fn media_runtime_copy(
        &self,
    ) -> Result<ManifoldRuntimeHost, ManifoldPeerRuntimeHostError> {
        self.validate_media_runtime_owner()?;
        if let Some(owner) = &self.media_runtime_owner {
            Ok(owner.as_ref().clone())
        } else {
            ManifoldRuntimeHost::from_snapshot(self.snapshot.media_command_runtime.clone())
                .map_err(|e| invalid_snapshot(&format!("media Runtime Host: {e}")))
        }
    }
    pub(super) fn retain_media_runtime(&mut self, runtime: ManifoldRuntimeHost) {
        self.snapshot.media_command_runtime = runtime.snapshot().clone();
        if self.media_runtime_owner.is_some() {
            self.media_runtime_owner = Some(Box::new(runtime));
        }
    }
    /// The caller is an existing accepted Peer/Broker mutation gate. Only its
    /// accepted derivative lease projection may differ; whole snapshot import,
    /// command/replay/audit changes and replacement bindings are forbidden.
    pub(super) fn project_media_runtime_snapshot(
        &mut self,
        next: ManifoldRuntimeHostSnapshot,
        now_ms: u64,
    ) -> Result<(), ManifoldPeerRuntimeHostError> {
        let Some(actual) = &self.media_runtime_owner else {
            ManifoldRuntimeHost::validate_snapshot_shape(&next)
                .map_err(|e| invalid_snapshot(&format!("media projection: {e}")))?;
            self.snapshot.media_command_runtime = next;
            return Ok(());
        };
        let mut expected = actual.snapshot().clone();
        expected.leases = next.leases.clone();
        if expected != next {
            return Err(invalid_snapshot(
                "accepted projection changed non-lease state",
            ));
        }
        let prior = actual.snapshot().leases.clone();
        let mut runtime = actual.as_ref().clone();
        for lease in &prior {
            let projection = match next.leases.iter().find(|v| v.lease_id == lease.lease_id) {
                None => Some(Projection::Release(lease.clone())),
                Some(renewed) if renewed != lease => Some(Projection::Renew {
                    prior: lease.clone(),
                    renewed: renewed.clone(),
                }),
                _ => None,
            };
            if let Some(projection) = projection {
                runtime
                    .project_accepted_derivative_lease(
                        runtime.snapshot().authority_revision,
                        &projection,
                        now_ms,
                    )
                    .map_err(|e| {
                        invalid_snapshot(&format!("accepted derivative projection: {e}"))
                    })?;
            }
        }
        for lease in next
            .leases
            .iter()
            .filter(|v| !prior.iter().any(|p| p.lease_id == v.lease_id))
        {
            runtime
                .project_accepted_derivative_lease(
                    runtime.snapshot().authority_revision,
                    &Projection::Admit(lease.clone()),
                    now_ms,
                )
                .map_err(|e| invalid_snapshot(&format!("accepted derivative projection: {e}")))?;
        }
        if runtime.snapshot() != &next {
            return Err(invalid_snapshot("accepted derivative projection differs"));
        }
        self.retain_media_runtime(runtime);
        Ok(())
    }
}
