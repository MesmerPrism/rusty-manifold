//! Provenance-preserving projection from accepted control leases to Runtime Host leases.

use rusty_manifold_model::{
    ClockHealth, DottedId, LeaseState, ManifoldAuthoritySnapshot, ManifoldClockSnapshot,
    ManifoldControlLease, ManifoldControlLeaseAuthorityApplication,
    ManifoldControlLeaseAuthorityApplicationOutcome, Revision, SchemaId,
};
use rusty_manifold_runtime_host::ManifoldRuntimeLease;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::io::{self, Write};

/// Schema for a provenance-preserving Runtime Host lease projection.
pub const BROKER_RUNTIME_LEASE_PROJECTION_SCHEMA: &str =
    "rusty.manifold.broker.runtime_lease_projection.v1";
/// Maximum exact typed-JSON bytes hashed for one provenance document.
pub const MAX_BROKER_RUNTIME_LEASE_PROVENANCE_BYTES: usize = 4 * 1024 * 1024;
/// Maximum accepted clock-read uncertainty for a Runtime Host lease projection.
pub const MAX_BROKER_RUNTIME_LEASE_CLOCK_UNCERTAINTY_NS: u64 = 1_000_000_000;

const PRIOR_SNAPSHOT_DIGEST_DOMAIN: &[u8] =
    b"rusty.manifold.broker.runtime_lease_projection.prior_snapshot.v1\0";
const RESULTING_SNAPSHOT_DIGEST_DOMAIN: &[u8] =
    b"rusty.manifold.broker.runtime_lease_projection.resulting_snapshot.v1\0";
const CURRENT_SNAPSHOT_DIGEST_DOMAIN: &[u8] =
    b"rusty.manifold.broker.runtime_lease_projection.current_snapshot.v1\0";
const APPLICATION_DIGEST_DOMAIN: &[u8] =
    b"rusty.manifold.broker.runtime_lease_projection.application.v1\0";
const PROJECTION_ID_DOMAIN: &[u8] = b"rusty.manifold.broker.runtime_lease_projection.id.v1\0";

/// Serialized evidence for a one-to-one projection of one accepted control lease.
///
/// Fields are intentionally private. Deserialization produces evidence only,
/// not authority that may be consumed by Runtime Host. Call
/// [`ManifoldBrokerRuntimeLeaseProjector::validate_projection`] with the
/// retained authority state before accessing the projected lease.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerRuntimeLeaseProjection {
    #[serde(rename = "$schema")]
    schema_id: SchemaId,
    projection_id: DottedId,
    authority_id: DottedId,
    from_authority_revision: Revision,
    resulting_authority_revision: Revision,
    current_authority_revision: Revision,
    clock_domain: DottedId,
    clock_epoch_id: DottedId,
    projected_clock_sequence: u64,
    projected_at_ms: u64,
    expiry_check_at_ms: u64,
    clock_read_uncertainty_ns: u64,
    lease_review_id: DottedId,
    lease_application_id: DottedId,
    lease_audit_event_id: DottedId,
    prior_authority_snapshot_sha256: String,
    resulting_authority_snapshot_sha256: String,
    current_authority_snapshot_sha256: String,
    lease_application_sha256: String,
    source_lease: ManifoldControlLease,
    runtime_lease: ManifoldRuntimeLease,
}

impl ManifoldBrokerRuntimeLeaseProjection {
    /// Returns the stable receipt identity.
    #[must_use]
    pub const fn projection_id(&self) -> &DottedId {
        &self.projection_id
    }

    /// Returns the authority revision against which currentness was checked.
    #[must_use]
    pub const fn current_authority_revision(&self) -> Revision {
        self.current_authority_revision
    }
}

/// A projection that was validated against retained authority and clock state.
///
/// This wrapper is not deserializable. Runtime Host consumers obtain a lease
/// only through this validated form.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedManifoldBrokerRuntimeLeaseProjection {
    receipt: ManifoldBrokerRuntimeLeaseProjection,
}

impl ValidatedManifoldBrokerRuntimeLeaseProjection {
    /// Returns the serializable provenance receipt.
    #[must_use]
    pub const fn receipt(&self) -> &ManifoldBrokerRuntimeLeaseProjection {
        &self.receipt
    }

    /// Returns the exact validated Runtime Host lease projection.
    #[must_use]
    pub const fn runtime_lease(&self) -> &ManifoldRuntimeLease {
        &self.receipt.runtime_lease
    }

    /// Consumes the validation wrapper and returns the serializable receipt.
    #[must_use]
    pub fn into_receipt(self) -> ManifoldBrokerRuntimeLeaseProjection {
        self.receipt
    }
}

/// Borrowed one-shot retained-state boundary for Runtime Host lease projection.
///
/// The authority owner must construct this value from its retained current
/// `ManifoldAuthoritySnapshot` and owner-supplied current clock. Construction
/// validates structural state but cannot authenticate an arbitrary caller's
/// fabricated snapshot or clock. This type must therefore remain behind the
/// authority-owning Broker/runtime boundary. It is not cloneable, and
/// projection consumes it; the borrowed owner state cannot be mutated while
/// the projection is in flight. The source-only API cannot prove that a caller
/// did not construct a fresh projector over stale cloned state; mandatory
/// synchronized construction belongs to the Broker adoption boundary.
#[derive(Debug)]
pub struct ManifoldBrokerRuntimeLeaseProjector<'owner> {
    current_authority_snapshot: &'owner ManifoldAuthoritySnapshot,
    current_clock: &'owner ManifoldClockSnapshot,
}

impl<'owner> ManifoldBrokerRuntimeLeaseProjector<'owner> {
    /// Creates a borrowed one-shot projection boundary from retained state.
    ///
    /// # Errors
    ///
    /// Returns a typed rejection when current authority state is invalid or
    /// the current clock has the wrong lineage, unhealthy state, excessive
    /// uncertainty, regression, or an unrepresentable time.
    pub fn from_retained_authority_state(
        current_authority_snapshot: &'owner ManifoldAuthoritySnapshot,
        current_clock: &'owner ManifoldClockSnapshot,
    ) -> Result<Self, ManifoldBrokerRuntimeLeaseProjectionError> {
        digest_typed_json(CURRENT_SNAPSHOT_DIGEST_DOMAIN, current_authority_snapshot)?;
        current_authority_snapshot
            .validate_authority_links()
            .map_err(|_| {
                projection_error(
                    ManifoldBrokerRuntimeLeaseProjectionRejectionReason::InvalidRetainedAuthorityState,
                )
            })?;
        validate_current_clock(&current_authority_snapshot.clock_snapshot, current_clock)?;
        Ok(Self {
            current_authority_snapshot,
            current_clock,
        })
    }

    /// Projects one already reviewed and applied Manifold control lease.
    ///
    /// The application is validated against its exact prior snapshot. The same
    /// lease must remain active and byte-for-byte equal in the projector's
    /// retained current authority state. Release, renewal, expiry, revocation,
    /// or substitution therefore invalidates the older application.
    ///
    /// # Errors
    ///
    /// Returns a typed rejection when authority lineage, current retained
    /// state, clock policy, expiry, or bounded provenance hashing is invalid.
    pub fn project(
        self,
        prior_snapshot: &ManifoldAuthoritySnapshot,
        application: &ManifoldControlLeaseAuthorityApplication,
    ) -> Result<
        ValidatedManifoldBrokerRuntimeLeaseProjection,
        ManifoldBrokerRuntimeLeaseProjectionError,
    > {
        let receipt = self.build_projection(prior_snapshot, application)?;
        Ok(ValidatedManifoldBrokerRuntimeLeaseProjection { receipt })
    }

    /// Revalidates a deserialized projection against retained authority state.
    ///
    /// Every serialized field is compared with a freshly rebuilt projection.
    /// The raw receipt cannot expose a Runtime Host lease until this succeeds.
    ///
    /// # Errors
    ///
    /// Returns a typed rejection when source authority validation fails,
    /// currentness changes, or any receipt field was substituted.
    pub fn validate_projection(
        self,
        projection: ManifoldBrokerRuntimeLeaseProjection,
        prior_snapshot: &ManifoldAuthoritySnapshot,
        application: &ManifoldControlLeaseAuthorityApplication,
    ) -> Result<
        ValidatedManifoldBrokerRuntimeLeaseProjection,
        ManifoldBrokerRuntimeLeaseProjectionError,
    > {
        let expected = self.build_projection(prior_snapshot, application)?;
        if projection != expected {
            return Err(projection_error(
                ManifoldBrokerRuntimeLeaseProjectionRejectionReason::ProjectionReceiptMismatch,
            ));
        }
        Ok(ValidatedManifoldBrokerRuntimeLeaseProjection {
            receipt: projection,
        })
    }

    fn build_projection(
        &self,
        prior_snapshot: &ManifoldAuthoritySnapshot,
        application: &ManifoldControlLeaseAuthorityApplication,
    ) -> Result<ManifoldBrokerRuntimeLeaseProjection, ManifoldBrokerRuntimeLeaseProjectionError>
    {
        let prior_authority_snapshot_sha256 =
            digest_typed_json(PRIOR_SNAPSHOT_DIGEST_DOMAIN, prior_snapshot)?;
        let lease_application_sha256 = digest_typed_json(APPLICATION_DIGEST_DOMAIN, application)?;
        application
            .validate_against_snapshot(prior_snapshot)
            .map_err(|_| {
                projection_error(
                    ManifoldBrokerRuntimeLeaseProjectionRejectionReason::InvalidAuthorityLineage,
                )
            })?;
        if application.outcome != ManifoldControlLeaseAuthorityApplicationOutcome::LeaseApplied {
            return Err(projection_error(
                ManifoldBrokerRuntimeLeaseProjectionRejectionReason::LeaseApplicationRejected,
            ));
        }
        let resulting_snapshot = application.applied_snapshot.as_ref().ok_or_else(|| {
            projection_error(
                ManifoldBrokerRuntimeLeaseProjectionRejectionReason::MissingAcceptedState,
            )
        })?;
        let resulting_authority_snapshot_sha256 =
            digest_typed_json(RESULTING_SNAPSHOT_DIGEST_DOMAIN, resulting_snapshot)?;
        let current_authority_snapshot_sha256 = digest_typed_json(
            CURRENT_SNAPSHOT_DIGEST_DOMAIN,
            self.current_authority_snapshot,
        )?;
        let source_lease = self.current_source_lease(application, resulting_snapshot)?;

        validate_current_clock(
            &application.review.audit_event.recorded_clock,
            self.current_clock,
        )?;
        let projected_at_ms = u64::try_from(self.current_clock.wall_unix_ms).map_err(|_| {
            projection_error(
                ManifoldBrokerRuntimeLeaseProjectionRejectionReason::InvalidProjectionTime,
            )
        })?;
        let uncertainty_ms = self.current_clock.read_uncertainty_ns.div_ceil(1_000_000);
        let expiry_check_at_ms = projected_at_ms.checked_add(uncertainty_ms).ok_or_else(|| {
            projection_error(
                ManifoldBrokerRuntimeLeaseProjectionRejectionReason::InvalidProjectionTime,
            )
        })?;
        if source_lease.expires_at_ms <= expiry_check_at_ms {
            return Err(projection_error(
                ManifoldBrokerRuntimeLeaseProjectionRejectionReason::ExpiredLease,
            ));
        }

        let runtime_lease = ManifoldRuntimeLease {
            lease_id: source_lease.lease_id.clone(),
            scope: source_lease.scope.clone(),
            holder_id: source_lease.holder_id.clone(),
            expires_at_ms: source_lease.expires_at_ms,
            derivative_binding: None,
        };
        let projection_id = derived_projection_id(
            application,
            source_lease,
            &lease_application_sha256,
            &current_authority_snapshot_sha256,
            self.current_clock,
            expiry_check_at_ms,
        );

        Ok(ManifoldBrokerRuntimeLeaseProjection {
            schema_id: schema_id(BROKER_RUNTIME_LEASE_PROJECTION_SCHEMA),
            projection_id,
            authority_id: application.authority_id.clone(),
            from_authority_revision: application.from_authority_revision,
            resulting_authority_revision: resulting_snapshot.authority_revision,
            current_authority_revision: self.current_authority_snapshot.authority_revision,
            clock_domain: self.current_clock.clock_domain.clone(),
            clock_epoch_id: self.current_clock.clock_epoch_id.clone(),
            projected_clock_sequence: self.current_clock.sequence,
            projected_at_ms,
            expiry_check_at_ms,
            clock_read_uncertainty_ns: self.current_clock.read_uncertainty_ns,
            lease_review_id: application.review.review_id.clone(),
            lease_application_id: application.application_id.clone(),
            lease_audit_event_id: application.review.audit_event.event_id.clone(),
            prior_authority_snapshot_sha256,
            resulting_authority_snapshot_sha256,
            current_authority_snapshot_sha256,
            lease_application_sha256,
            source_lease: source_lease.clone(),
            runtime_lease,
        })
    }

    fn current_source_lease<'application>(
        &self,
        application: &'application ManifoldControlLeaseAuthorityApplication,
        resulting_snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<&'application ManifoldControlLease, ManifoldBrokerRuntimeLeaseProjectionError> {
        let source_lease = application.review.accepted.as_ref().ok_or_else(|| {
            projection_error(
                ManifoldBrokerRuntimeLeaseProjectionRejectionReason::MissingAcceptedState,
            )
        })?;
        if source_lease.state != LeaseState::Active
            || source_lease.granted_revision != application.from_authority_revision
        {
            return Err(projection_error(
                ManifoldBrokerRuntimeLeaseProjectionRejectionReason::LeaseProjectionMismatch,
            ));
        }
        if self.current_authority_snapshot.authority_id != application.authority_id
            || self.current_authority_snapshot.authority_revision
                < resulting_snapshot.authority_revision
        {
            return Err(projection_error(
                ManifoldBrokerRuntimeLeaseProjectionRejectionReason::InvalidRetainedAuthorityState,
            ));
        }

        let mut matching_count = 0_u8;
        let mut current_lease_matches = false;
        for lease in &self.current_authority_snapshot.active_leases {
            if lease.lease_id == source_lease.lease_id {
                matching_count = matching_count.saturating_add(1);
                current_lease_matches = lease == source_lease;
            }
        }
        if matching_count != 1 || !current_lease_matches {
            return Err(projection_error(
                ManifoldBrokerRuntimeLeaseProjectionRejectionReason::LeaseNoLongerCurrent,
            ));
        }
        Ok(source_lease)
    }
}

/// Stable reason a control-lease projection was rejected.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldBrokerRuntimeLeaseProjectionRejectionReason {
    /// The authority-owner-retained snapshot did not validate.
    InvalidRetainedAuthorityState,
    /// The review/application/audit transition did not validate against the prior snapshot.
    InvalidAuthorityLineage,
    /// The authority application did not apply a lease.
    LeaseApplicationRejected,
    /// The applied receipt omitted its accepted lease or resulting snapshot.
    MissingAcceptedState,
    /// The accepted source lease was not an active one-to-one projection.
    LeaseProjectionMismatch,
    /// The accepted lease was released, renewed, expired, revoked, or replaced in current state.
    LeaseNoLongerCurrent,
    /// The current clock used a different schema, domain, or epoch.
    ClockLineageMismatch,
    /// The current clock regressed sequence, monotonic time, wall time, or adjustments.
    ClockRegression,
    /// The current clock is not healthy.
    UnhealthyClock,
    /// The current clock exceeds the projection uncertainty bound.
    ExcessiveClockUncertainty,
    /// The projection or uncertainty-adjusted time is not representable.
    InvalidProjectionTime,
    /// The accepted lease was no longer current at the conservative expiry bound.
    ExpiredLease,
    /// A provenance document exceeded its deterministic byte bound.
    ProvenanceLimitExceeded,
    /// Deterministic provenance serialization failed.
    ProvenanceSerializationFailed,
    /// A deserialized projection did not match the freshly rebuilt receipt.
    ProjectionReceiptMismatch,
}

/// Failure to project one already accepted Manifold control lease.
#[derive(Debug)]
pub struct ManifoldBrokerRuntimeLeaseProjectionError {
    reason: ManifoldBrokerRuntimeLeaseProjectionRejectionReason,
    source: Option<serde_json::Error>,
}

impl ManifoldBrokerRuntimeLeaseProjectionError {
    /// Returns the stable machine-readable rejection reason.
    #[must_use]
    pub const fn reason(&self) -> ManifoldBrokerRuntimeLeaseProjectionRejectionReason {
        self.reason
    }
}

impl fmt::Display for ManifoldBrokerRuntimeLeaseProjectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Runtime Host lease projection rejected: {:?}",
            self.reason
        )
    }
}

impl std::error::Error for ManifoldBrokerRuntimeLeaseProjectionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|source| source as &(dyn std::error::Error + 'static))
    }
}

fn validate_current_clock(
    baseline: &ManifoldClockSnapshot,
    current: &ManifoldClockSnapshot,
) -> Result<(), ManifoldBrokerRuntimeLeaseProjectionError> {
    if current.schema_id.as_str() != "rusty.manifold.clock.snapshot.v1"
        || current.clock_domain != baseline.clock_domain
        || current.clock_epoch_id != baseline.clock_epoch_id
    {
        return Err(projection_error(
            ManifoldBrokerRuntimeLeaseProjectionRejectionReason::ClockLineageMismatch,
        ));
    }
    if current.health != ClockHealth::Healthy {
        return Err(projection_error(
            ManifoldBrokerRuntimeLeaseProjectionRejectionReason::UnhealthyClock,
        ));
    }
    if current.read_uncertainty_ns > MAX_BROKER_RUNTIME_LEASE_CLOCK_UNCERTAINTY_NS {
        return Err(projection_error(
            ManifoldBrokerRuntimeLeaseProjectionRejectionReason::ExcessiveClockUncertainty,
        ));
    }
    if current.sequence < baseline.sequence
        || current.monotonic_elapsed_ns < baseline.monotonic_elapsed_ns
        || current.wall_unix_ms < baseline.wall_unix_ms
        || current.wall_clock_adjustment_count < baseline.wall_clock_adjustment_count
    {
        return Err(projection_error(
            ManifoldBrokerRuntimeLeaseProjectionRejectionReason::ClockRegression,
        ));
    }
    u64::try_from(current.wall_unix_ms).map_err(|_| {
        projection_error(ManifoldBrokerRuntimeLeaseProjectionRejectionReason::InvalidProjectionTime)
    })?;
    Ok(())
}

fn digest_typed_json<T: Serialize>(
    domain: &[u8],
    value: &T,
) -> Result<String, ManifoldBrokerRuntimeLeaseProjectionError> {
    let mut writer = BoundedSha256Writer::new(MAX_BROKER_RUNTIME_LEASE_PROVENANCE_BYTES);
    writer
        .write_all(domain)
        .expect("static digest domain fits provenance bound");
    let serialization = serde_json::to_writer(&mut writer, value);
    if writer.limit_exceeded {
        return Err(projection_error(
            ManifoldBrokerRuntimeLeaseProjectionRejectionReason::ProvenanceLimitExceeded,
        ));
    }
    serialization.map_err(|source| ManifoldBrokerRuntimeLeaseProjectionError {
        reason: ManifoldBrokerRuntimeLeaseProjectionRejectionReason::ProvenanceSerializationFailed,
        source: Some(source),
    })?;
    Ok(format!("sha256:{}", hex_digest(writer.hasher.finalize())))
}

fn derived_projection_id(
    application: &ManifoldControlLeaseAuthorityApplication,
    lease: &ManifoldControlLease,
    application_sha256: &str,
    current_snapshot_sha256: &str,
    clock: &ManifoldClockSnapshot,
    expiry_check_at_ms: u64,
) -> DottedId {
    let mut digest = Sha256::new();
    digest.update(PROJECTION_ID_DOMAIN);
    for value in [
        application.application_id.as_str(),
        lease.lease_id.as_str(),
        application_sha256,
        current_snapshot_sha256,
        clock.clock_epoch_id.as_str(),
        &clock.sequence.to_string(),
        &clock.wall_unix_ms.to_string(),
        &clock.read_uncertainty_ns.to_string(),
        &expiry_check_at_ms.to_string(),
    ] {
        digest.update(value.as_bytes());
        digest.update([0]);
    }
    DottedId::new(format!(
        "projection.runtime_lease.{}",
        hex_digest(digest.finalize())
    ))
    .expect("derived Runtime Host lease projection id is valid")
}

fn projection_error(
    reason: ManifoldBrokerRuntimeLeaseProjectionRejectionReason,
) -> ManifoldBrokerRuntimeLeaseProjectionError {
    ManifoldBrokerRuntimeLeaseProjectionError {
        reason,
        source: None,
    }
}

struct BoundedSha256Writer {
    hasher: Sha256,
    written: usize,
    limit: usize,
    limit_exceeded: bool,
}

impl BoundedSha256Writer {
    fn new(limit: usize) -> Self {
        Self {
            hasher: Sha256::new(),
            written: 0,
            limit,
            limit_exceeded: false,
        }
    }
}

impl Write for BoundedSha256Writer {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let Some(next) = self.written.checked_add(buffer.len()) else {
            self.limit_exceeded = true;
            return Err(io::Error::other("provenance byte count overflow"));
        };
        if next > self.limit {
            self.limit_exceeded = true;
            return Err(io::Error::other("provenance byte limit exceeded"));
        }
        self.hasher.update(buffer);
        self.written = next;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn hex_digest(bytes: impl AsRef<[u8]>) -> String {
    let bytes = bytes.as_ref();
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("String writes cannot fail");
    }
    encoded
}

fn schema_id(value: &str) -> SchemaId {
    SchemaId::new(value).expect("static schema id is valid")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prior_snapshot() -> ManifoldAuthoritySnapshot {
        serde_json::from_str(include_str!(
            "../../../fixtures/authority/synthetic-authority-snapshot.json"
        ))
        .expect("prior authority snapshot fixture")
    }

    fn accepted_application() -> ManifoldControlLeaseAuthorityApplication {
        serde_json::from_str(include_str!(
            "../../../fixtures/authority-application/synthetic-lease-accepted-application.json"
        ))
        .expect("accepted lease application fixture")
    }

    fn rejected_application() -> ManifoldControlLeaseAuthorityApplication {
        serde_json::from_str(include_str!(
            "../../../fixtures/authority-application/synthetic-lease-rejected-application.json"
        ))
        .expect("rejected lease application fixture")
    }

    fn current_snapshot() -> ManifoldAuthoritySnapshot {
        accepted_application()
            .applied_snapshot
            .expect("accepted resulting snapshot")
    }

    fn projection_clock() -> ManifoldClockSnapshot {
        serde_json::from_str(include_str!(
            "../../../fixtures/clock/synthetic-command-review-clock.json"
        ))
        .expect("projection clock fixture")
    }

    struct TestProjectionOwner {
        current_authority_snapshot: ManifoldAuthoritySnapshot,
        current_clock: ManifoldClockSnapshot,
    }

    impl TestProjectionOwner {
        fn projector(&self) -> ManifoldBrokerRuntimeLeaseProjector<'_> {
            ManifoldBrokerRuntimeLeaseProjector::from_retained_authority_state(
                &self.current_authority_snapshot,
                &self.current_clock,
            )
            .expect("retained authority projector")
        }
    }

    fn projection_owner() -> TestProjectionOwner {
        TestProjectionOwner {
            current_authority_snapshot: current_snapshot(),
            current_clock: projection_clock(),
        }
    }

    #[test]
    fn applied_control_lease_projects_one_to_one_with_current_provenance() {
        let application = accepted_application();
        let validated = projection_owner()
            .projector()
            .project(&prior_snapshot(), &application)
            .expect("accepted current lease projects");
        let projection = validated.receipt();

        assert_eq!(
            projection.schema_id.as_str(),
            BROKER_RUNTIME_LEASE_PROJECTION_SCHEMA
        );
        assert_eq!(projection.authority_id, application.authority_id);
        assert_eq!(
            projection.resulting_authority_revision,
            Revision::new(2).expect("revision")
        );
        assert_eq!(
            projection.current_authority_revision,
            Revision::new(2).expect("revision")
        );
        assert_eq!(
            projection.source_lease.lease_id,
            projection.runtime_lease.lease_id
        );
        assert_eq!(
            projection.source_lease.scope,
            projection.runtime_lease.scope
        );
        assert_eq!(
            projection.source_lease.holder_id,
            projection.runtime_lease.holder_id
        );
        assert_eq!(
            projection.source_lease.expires_at_ms,
            projection.runtime_lease.expires_at_ms
        );
        assert_eq!(validated.runtime_lease(), &projection.runtime_lease);
        assert_eq!(
            projection.prior_authority_snapshot_sha256,
            "sha256:27465914a30f78fc273ae166f36f61aa0fb3f52d1c59b2a0b9303eaa1d9e2072"
        );
        assert_eq!(
            projection.resulting_authority_snapshot_sha256,
            "sha256:45755ee271ce78feb2f97a930cd6b4075cf7353eeb0c8c96ae3be4af038fc9e2"
        );
        assert_eq!(
            projection.lease_application_sha256,
            "sha256:bfb6a92e27ab0626a7b8f001a83e5ffbcc9548905d0074403a6efbd67d64622d"
        );
    }

    #[test]
    fn rejected_application_cannot_project_a_runtime_lease() {
        let error = projection_owner()
            .projector()
            .project(&prior_snapshot(), &rejected_application())
            .expect_err("rejected authority application must not project");
        assert_eq!(
            error.reason(),
            ManifoldBrokerRuntimeLeaseProjectionRejectionReason::LeaseApplicationRejected
        );
    }

    #[test]
    fn arbitrary_inserted_or_substituted_lease_fails_lineage_validation() {
        let prior = prior_snapshot();
        let mut inserted = accepted_application();
        let accepted = inserted
            .review
            .accepted
            .as_ref()
            .expect("accepted lease")
            .clone();
        inserted
            .applied_snapshot
            .as_mut()
            .expect("applied snapshot")
            .active_leases
            .push(accepted);
        assert_eq!(
            projection_owner()
                .projector()
                .project(&prior, &inserted)
                .expect_err("arbitrary inserted lease must fail")
                .reason(),
            ManifoldBrokerRuntimeLeaseProjectionRejectionReason::InvalidAuthorityLineage
        );

        for mutation in ["holder", "scope", "expiry", "audit", "revision"] {
            let mut damaged = accepted_application();
            match mutation {
                "holder" => {
                    damaged.review.accepted.as_mut().expect("lease").holder_id =
                        DottedId::new("holder.substituted").expect("id");
                }
                "scope" => {
                    damaged.review.accepted.as_mut().expect("lease").scope =
                        DottedId::new("manifold.substituted").expect("id");
                }
                "expiry" => {
                    damaged
                        .review
                        .accepted
                        .as_mut()
                        .expect("lease")
                        .expires_at_ms += 1;
                }
                "audit" => {
                    damaged.review.audit_event.event_id =
                        DottedId::new("audit.lease.substituted").expect("id");
                }
                "revision" => {
                    damaged.from_authority_revision = Revision::new(2).expect("revision");
                }
                _ => unreachable!("bounded mutation list"),
            }
            assert_eq!(
                projection_owner()
                    .projector()
                    .project(&prior, &damaged)
                    .expect_err("substituted lineage must fail")
                    .reason(),
                ManifoldBrokerRuntimeLeaseProjectionRejectionReason::InvalidAuthorityLineage,
                "{mutation}"
            );
        }
    }

    #[test]
    fn released_or_renewed_lease_is_not_current() {
        let application = accepted_application();
        let source = application.review.accepted.as_ref().expect("lease");

        let mut released = current_snapshot();
        released.authority_revision = Revision::new(3).expect("revision");
        released
            .active_leases
            .retain(|lease| lease.lease_id != source.lease_id);
        let released_clock = projection_clock();
        let released_projector =
            ManifoldBrokerRuntimeLeaseProjector::from_retained_authority_state(
                &released,
                &released_clock,
            )
            .expect("released current state");
        assert_eq!(
            released_projector
                .project(&prior_snapshot(), &application)
                .expect_err("released lease must not project")
                .reason(),
            ManifoldBrokerRuntimeLeaseProjectionRejectionReason::LeaseNoLongerCurrent
        );

        let mut renewed = current_snapshot();
        renewed.authority_revision = Revision::new(3).expect("revision");
        renewed
            .active_leases
            .iter_mut()
            .find(|lease| lease.lease_id == source.lease_id)
            .expect("lease")
            .expires_at_ms += 30_000;
        let renewed_clock = projection_clock();
        let renewed_projector = ManifoldBrokerRuntimeLeaseProjector::from_retained_authority_state(
            &renewed,
            &renewed_clock,
        )
        .expect("renewed current state");
        assert_eq!(
            renewed_projector
                .project(&prior_snapshot(), &application)
                .expect_err("old lease application must not project after renewal")
                .reason(),
            ManifoldBrokerRuntimeLeaseProjectionRejectionReason::LeaseNoLongerCurrent
        );
    }

    #[test]
    fn projection_clock_health_uncertainty_regression_and_expiry_fail_closed() {
        let current = current_snapshot();

        for lineage_mutation in ["domain", "epoch"] {
            let mut mismatched = projection_clock();
            match lineage_mutation {
                "domain" => {
                    mismatched.clock_domain =
                        DottedId::new("clock.domain.substituted").expect("id");
                }
                "epoch" => {
                    mismatched.clock_epoch_id =
                        DottedId::new("clock_epoch.substituted").expect("id");
                }
                _ => unreachable!("bounded lineage mutation list"),
            }
            assert_eq!(
                ManifoldBrokerRuntimeLeaseProjector::from_retained_authority_state(
                    &current,
                    &mismatched,
                )
                .expect_err("mismatched clock lineage")
                .reason(),
                ManifoldBrokerRuntimeLeaseProjectionRejectionReason::ClockLineageMismatch,
                "{lineage_mutation}"
            );
        }

        let mut unavailable = projection_clock();
        unavailable.health = ClockHealth::Unavailable;
        assert_eq!(
            ManifoldBrokerRuntimeLeaseProjector::from_retained_authority_state(
                &current,
                &unavailable,
            )
            .expect_err("unavailable clock")
            .reason(),
            ManifoldBrokerRuntimeLeaseProjectionRejectionReason::UnhealthyClock
        );

        let mut uncertain = projection_clock();
        uncertain.read_uncertainty_ns = MAX_BROKER_RUNTIME_LEASE_CLOCK_UNCERTAINTY_NS + 1;
        assert_eq!(
            ManifoldBrokerRuntimeLeaseProjector::from_retained_authority_state(
                &current, &uncertain,
            )
            .expect_err("excessive uncertainty")
            .reason(),
            ManifoldBrokerRuntimeLeaseProjectionRejectionReason::ExcessiveClockUncertainty
        );

        let mut regressed = projection_clock();
        regressed.sequence = regressed.sequence.saturating_sub(2);
        assert_eq!(
            ManifoldBrokerRuntimeLeaseProjector::from_retained_authority_state(
                &current, &regressed,
            )
            .expect_err("regressed clock")
            .reason(),
            ManifoldBrokerRuntimeLeaseProjectionRejectionReason::ClockRegression
        );

        let application = accepted_application();
        let mut expired = projection_clock();
        expired.sequence += 1;
        expired.monotonic_elapsed_ns += 1;
        expired.wall_unix_ms = i64::try_from(
            application
                .review
                .accepted
                .as_ref()
                .expect("accepted lease")
                .expires_at_ms,
        )
        .expect("fixture expiry fits i64");
        let expired_projector =
            ManifoldBrokerRuntimeLeaseProjector::from_retained_authority_state(&current, &expired)
                .expect("current clock structurally valid");
        assert_eq!(
            expired_projector
                .project(&prior_snapshot(), &application)
                .expect_err("expired lease")
                .reason(),
            ManifoldBrokerRuntimeLeaseProjectionRejectionReason::ExpiredLease
        );
    }

    #[test]
    fn every_serialized_field_requires_revalidation() {
        let prior = prior_snapshot();
        let application = accepted_application();
        let owner = projection_owner();
        let receipt = owner
            .projector()
            .project(&prior, &application)
            .expect("projection")
            .into_receipt();
        let original = serde_json::to_value(&receipt).expect("projection value");
        let mutations = [
            (
                "/$schema",
                serde_json::json!("rusty.manifold.broker.other.v1"),
            ),
            (
                "/projection_id",
                serde_json::json!("projection.substituted"),
            ),
            ("/authority_id", serde_json::json!("authority.substituted")),
            ("/from_authority_revision", serde_json::json!(2)),
            ("/resulting_authority_revision", serde_json::json!(3)),
            ("/current_authority_revision", serde_json::json!(3)),
            ("/clock_domain", serde_json::json!("clock.substituted")),
            (
                "/clock_epoch_id",
                serde_json::json!("clock_epoch.substituted"),
            ),
            ("/projected_clock_sequence", serde_json::json!(44)),
            ("/projected_at_ms", serde_json::json!(1_765_000_000_101_u64)),
            (
                "/expiry_check_at_ms",
                serde_json::json!(1_765_000_000_102_u64),
            ),
            ("/clock_read_uncertainty_ns", serde_json::json!(250_001)),
            (
                "/lease_review_id",
                serde_json::json!("lease_review.substituted"),
            ),
            (
                "/lease_application_id",
                serde_json::json!("lease_application.substituted"),
            ),
            (
                "/lease_audit_event_id",
                serde_json::json!("audit.lease.substituted"),
            ),
            (
                "/prior_authority_snapshot_sha256",
                serde_json::json!(format!("sha256:{}", "0".repeat(64))),
            ),
            (
                "/resulting_authority_snapshot_sha256",
                serde_json::json!(format!("sha256:{}", "1".repeat(64))),
            ),
            (
                "/current_authority_snapshot_sha256",
                serde_json::json!(format!("sha256:{}", "2".repeat(64))),
            ),
            (
                "/lease_application_sha256",
                serde_json::json!(format!("sha256:{}", "3".repeat(64))),
            ),
            (
                "/source_lease/holder_id",
                serde_json::json!("holder.substituted"),
            ),
            (
                "/runtime_lease/expires_at_ms",
                serde_json::json!(1_765_000_030_101_u64),
            ),
        ];
        for (path, replacement) in mutations {
            let mut damaged = original.clone();
            *damaged
                .pointer_mut(path)
                .unwrap_or_else(|| panic!("fixture path {path}")) = replacement;
            let raw: ManifoldBrokerRuntimeLeaseProjection =
                serde_json::from_value(damaged).expect("damaged receipt remains typed");
            assert_eq!(
                owner
                    .projector()
                    .validate_projection(raw, &prior, &application)
                    .expect_err("substituted receipt must not validate")
                    .reason(),
                ManifoldBrokerRuntimeLeaseProjectionRejectionReason::ProjectionReceiptMismatch,
                "{path}"
            );
        }
    }

    #[test]
    fn provenance_hashing_is_bounded() {
        let mut oversized = prior_snapshot();
        oversized.command_ids = (0..300_000)
            .map(|index| DottedId::new(format!("command.oversized.{index}")).expect("bounded id"))
            .collect();
        assert_eq!(
            projection_owner()
                .projector()
                .project(&oversized, &accepted_application())
                .expect_err("oversized provenance must fail")
                .reason(),
            ManifoldBrokerRuntimeLeaseProjectionRejectionReason::ProvenanceLimitExceeded
        );
    }

    #[test]
    fn committed_projection_fixture_matches_current_contract_after_validation() {
        let raw: ManifoldBrokerRuntimeLeaseProjection = serde_json::from_str(include_str!(
            "../../../fixtures/broker-adapter/runtime-lease-projection.json"
        ))
        .expect("committed projection fixture");
        let validated = projection_owner()
            .projector()
            .validate_projection(raw, &prior_snapshot(), &accepted_application())
            .expect("committed projection validates");
        assert_eq!(
            validated.receipt(),
            projection_owner()
                .projector()
                .project(&prior_snapshot(), &accepted_application())
                .expect("generated projection")
                .receipt()
        );
    }
}
