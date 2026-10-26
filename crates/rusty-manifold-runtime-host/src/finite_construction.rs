//! Typed construction of initial finite command-host data.
use super::*;

impl ManifoldRuntimeHostSnapshot {
    /// Builds initial finite snapshot data from the caller's exact commands and leases.
    ///
    /// This does not issue or admit a lease. `ManifoldRuntimeHost::from_snapshot`
    /// retains its ordinary validation and adoption requirements.
    pub fn initial(
        host_id: DottedId,
        commands: Vec<ManifoldRuntimeCommandDescriptor>,
        leases: Vec<ManifoldRuntimeLease>,
    ) -> Self {
        Self {
            schema_id: SchemaId::new(HOST_SNAPSHOT_SCHEMA).expect("static snapshot schema"),
            host_id,
            authority_revision: Revision::INITIAL,
            commands,
            leases,
            applied_request_ids: Vec::new(),
            reviewed_sweep_ids: Vec::new(),
            reviewed_control_lease_adoption_ids: Vec::new(),
            reviewed_derivative_lease_revocation_ids: Vec::new(),
            audit_events: Vec::new(),
        }
    }
}
