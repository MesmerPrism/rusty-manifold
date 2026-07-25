//! Broker-owned control-lease authority state and Runtime Host projection closure.

use crate::{
    ManifoldBrokerRuntimeLeaseProjection, ManifoldBrokerRuntimeLeaseProjectionError,
    ManifoldBrokerRuntimeLeaseProjector,
};
use rusty_manifold_model::{
    ManifoldAuthoritySnapshot, ManifoldClockSnapshot, ManifoldControlLeaseAuthorityApplication,
    SchemaId,
};
use rusty_manifold_runtime_host::{ManifoldRuntimeHostSnapshot, ManifoldRuntimeLease};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::{self, Write};

/// Durable source-lineage schema for one Broker-owned control lease.
pub const BROKER_CONTROL_LEASE_SOURCE_SCHEMA: &str =
    "rusty.manifold.broker.control_lease_source.v1";
/// Durable synchronized control-lease authority evidence schema.
pub const BROKER_CONTROL_LEASE_AUTHORITY_EVIDENCE_SCHEMA: &str =
    "rusty.manifold.broker.control_lease_authority_evidence.v1";
/// Maximum projected control leases retained by one Broker product authority.
pub const MAX_BROKER_CONTROL_LEASES: usize = 256;
/// Maximum serialized owner evidence accepted by one Broker runtime.
pub const MAX_BROKER_CONTROL_LEASE_AUTHORITY_EVIDENCE_BYTES: usize = 8 * 1024 * 1024;

/// Exact source lineage required to reproduce one Runtime Host lease projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerControlLeaseSource {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Exact authority state against which the lease application was reviewed.
    pub prior_authority_snapshot: ManifoldAuthoritySnapshot,
    /// Exact accepted control-lease application.
    pub application: ManifoldControlLeaseAuthorityApplication,
}

/// Durable Broker authority state from which Runtime Host leases are reproduced.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerControlLeaseAuthorityEvidence {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Last synchronized retained authority state.
    pub current_authority_snapshot: ManifoldAuthoritySnapshot,
    /// Last synchronized authority-owner clock view.
    pub current_clock: ManifoldClockSnapshot,
    /// Canonically lease-id-ordered source lineage for projected leases.
    pub lease_sources: Vec<ManifoldBrokerControlLeaseSource>,
}

/// Exclusive synchronized control-lease owner retained by a Broker runtime.
///
/// Construction validates every projected lease against one supplied retained
/// authority/clock view. Fields are private and the type is not cloneable, so
/// normal Broker construction cannot receive ambient Runtime Host leases.
#[derive(Debug)]
pub struct ManifoldBrokerControlLeaseAuthority {
    evidence: ManifoldBrokerControlLeaseAuthorityEvidence,
    runtime_leases: Vec<ManifoldRuntimeLease>,
    projection_receipts: Vec<ManifoldBrokerRuntimeLeaseProjection>,
}

impl ManifoldBrokerControlLeaseAuthority {
    /// Builds one synchronized owner from a caller-attested retained view.
    ///
    /// Unrelated active Manifold leases may remain outside this Broker product,
    /// but every Runtime Host lease produced here must have exact source
    /// lineage and remain current in the supplied authority snapshot.
    ///
    /// # Errors
    ///
    /// Returns a typed error when state, clock, lineage, ordering, capacity, or
    /// one-to-one projected lease closure is invalid.
    pub fn from_caller_attested_retained_authority_state(
        current_authority_snapshot: ManifoldAuthoritySnapshot,
        current_clock: ManifoldClockSnapshot,
        lease_sources: Vec<ManifoldBrokerControlLeaseSource>,
    ) -> Result<Self, ManifoldBrokerControlLeaseAuthorityError> {
        if lease_sources.len() > MAX_BROKER_CONTROL_LEASES {
            return Err(ManifoldBrokerControlLeaseAuthorityError::CapacityExceeded);
        }
        let mut evidence = ManifoldBrokerControlLeaseAuthorityEvidence {
            schema_id: schema_id(BROKER_CONTROL_LEASE_AUTHORITY_EVIDENCE_SCHEMA),
            current_authority_snapshot,
            current_clock,
            lease_sources,
        };
        validate_evidence_size(&evidence)?;

        ManifoldBrokerRuntimeLeaseProjector::from_retained_authority_state(
            &evidence.current_authority_snapshot,
            &evidence.current_clock,
        )
        .map_err(ManifoldBrokerControlLeaseAuthorityError::Projection)?;

        let mut projected = std::mem::take(&mut evidence.lease_sources)
            .into_iter()
            .map(|source| {
                if source.schema_id.as_str() != BROKER_CONTROL_LEASE_SOURCE_SCHEMA {
                    return Err(ManifoldBrokerControlLeaseAuthorityError::SchemaMismatch);
                }
                let projection =
                    ManifoldBrokerRuntimeLeaseProjector::from_retained_authority_state(
                        &evidence.current_authority_snapshot,
                        &evidence.current_clock,
                    )
                    .map_err(ManifoldBrokerControlLeaseAuthorityError::Projection)?
                    .project(&source.prior_authority_snapshot, &source.application)
                    .map_err(ManifoldBrokerControlLeaseAuthorityError::Projection)?;
                let runtime_lease = projection.runtime_lease().clone();
                Ok((
                    runtime_lease.lease_id.clone(),
                    source,
                    runtime_lease,
                    projection.into_receipt(),
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;
        projected.sort_by(|left, right| left.0.cmp(&right.0));
        if projected.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(ManifoldBrokerControlLeaseAuthorityError::DuplicateLeaseId);
        }

        let mut canonical_sources = Vec::with_capacity(projected.len());
        let mut runtime_leases = Vec::with_capacity(projected.len());
        let mut projection_receipts = Vec::with_capacity(projected.len());
        for (_, source, runtime_lease, receipt) in projected {
            runtime_leases.push(runtime_lease);
            canonical_sources.push(source);
            projection_receipts.push(receipt);
        }
        evidence.lease_sources = canonical_sources;
        validate_evidence_size(&evidence)?;

        Ok(Self {
            evidence,
            runtime_leases,
            projection_receipts,
        })
    }

    /// Restores source lineage while requiring a freshly supplied owner view.
    ///
    /// The durable snapshot and clock are rollback anchors only. The supplied
    /// current view must use the same authority and clock lineage without
    /// revision or time regression, and every source lease is reprojected
    /// against that supplied view before any host can be restored.
    ///
    /// # Errors
    ///
    /// Returns a typed error when durable evidence, the fresh owner view, or
    /// the reproduced projection set fails validation.
    pub fn refresh_from_evidence(
        evidence: ManifoldBrokerControlLeaseAuthorityEvidence,
        current_authority_snapshot: ManifoldAuthoritySnapshot,
        current_clock: ManifoldClockSnapshot,
    ) -> Result<Self, ManifoldBrokerControlLeaseAuthorityError> {
        if evidence.schema_id.as_str() != BROKER_CONTROL_LEASE_AUTHORITY_EVIDENCE_SCHEMA {
            return Err(ManifoldBrokerControlLeaseAuthorityError::SchemaMismatch);
        }
        if evidence.lease_sources.len() > MAX_BROKER_CONTROL_LEASES {
            return Err(ManifoldBrokerControlLeaseAuthorityError::CapacityExceeded);
        }
        validate_evidence_size(&evidence)?;
        Self::from_caller_attested_retained_authority_state(
            evidence.current_authority_snapshot.clone(),
            evidence.current_clock.clone(),
            evidence.lease_sources.clone(),
        )?;
        if current_authority_snapshot.authority_id
            != evidence.current_authority_snapshot.authority_id
            || current_authority_snapshot.authority_revision
                < evidence.current_authority_snapshot.authority_revision
        {
            return Err(ManifoldBrokerControlLeaseAuthorityError::AuthorityRegression);
        }
        if current_clock.schema_id != evidence.current_clock.schema_id
            || current_clock.clock_domain != evidence.current_clock.clock_domain
            || current_clock.clock_epoch_id != evidence.current_clock.clock_epoch_id
        {
            return Err(ManifoldBrokerControlLeaseAuthorityError::ClockLineageMismatch);
        }
        if current_clock.sequence < evidence.current_clock.sequence
            || current_clock.monotonic_elapsed_ns < evidence.current_clock.monotonic_elapsed_ns
            || current_clock.wall_unix_ms < evidence.current_clock.wall_unix_ms
            || current_clock.wall_clock_adjustment_count
                < evidence.current_clock.wall_clock_adjustment_count
        {
            return Err(ManifoldBrokerControlLeaseAuthorityError::ClockRegression);
        }
        Self::from_caller_attested_retained_authority_state(
            current_authority_snapshot,
            current_clock,
            evidence.lease_sources,
        )
    }

    /// Returns the current retained Manifold authority snapshot.
    #[must_use]
    pub const fn authority_snapshot(&self) -> &ManifoldAuthoritySnapshot {
        &self.evidence.current_authority_snapshot
    }

    /// Returns the current retained authority-owner clock view.
    #[must_use]
    pub const fn current_clock(&self) -> &ManifoldClockSnapshot {
        &self.evidence.current_clock
    }

    /// Returns durable source lineage and current owner-state evidence.
    #[must_use]
    pub fn evidence(&self) -> ManifoldBrokerControlLeaseAuthorityEvidence {
        self.evidence.clone()
    }

    /// Returns the freshly reproduced projection receipts.
    #[must_use]
    pub fn projection_receipts(&self) -> &[ManifoldBrokerRuntimeLeaseProjection] {
        &self.projection_receipts
    }

    pub(crate) fn runtime_leases(&self) -> &[ManifoldRuntimeLease] {
        &self.runtime_leases
    }

    pub(crate) fn validate_host_snapshot(
        &self,
        snapshot: &ManifoldRuntimeHostSnapshot,
    ) -> Result<(), ManifoldBrokerControlLeaseAuthorityError> {
        let mut host_leases = snapshot.leases.clone();
        host_leases.sort_by(|left, right| left.lease_id.cmp(&right.lease_id));
        if host_leases == self.runtime_leases {
            Ok(())
        } else {
            Err(ManifoldBrokerControlLeaseAuthorityError::HostLeaseSetMismatch)
        }
    }

    pub(crate) fn is_refresh_of(
        &self,
        evidence: &ManifoldBrokerControlLeaseAuthorityEvidence,
    ) -> bool {
        self.evidence.lease_sources == evidence.lease_sources
            && self.evidence.current_authority_snapshot.authority_id
                == evidence.current_authority_snapshot.authority_id
            && self.evidence.current_authority_snapshot.authority_revision
                >= evidence.current_authority_snapshot.authority_revision
            && self.evidence.current_clock.schema_id == evidence.current_clock.schema_id
            && self.evidence.current_clock.clock_domain == evidence.current_clock.clock_domain
            && self.evidence.current_clock.clock_epoch_id == evidence.current_clock.clock_epoch_id
            && self.evidence.current_clock.sequence >= evidence.current_clock.sequence
            && self.evidence.current_clock.monotonic_elapsed_ns
                >= evidence.current_clock.monotonic_elapsed_ns
            && self.evidence.current_clock.wall_unix_ms >= evidence.current_clock.wall_unix_ms
            && self.evidence.current_clock.wall_clock_adjustment_count
                >= evidence.current_clock.wall_clock_adjustment_count
    }
}

/// Failure to close Broker-owned control-lease state over Runtime Host state.
#[derive(Debug)]
pub enum ManifoldBrokerControlLeaseAuthorityError {
    /// A durable source or authority-evidence schema is unsupported.
    SchemaMismatch,
    /// Retained projected lease capacity was exceeded.
    CapacityExceeded,
    /// Durable source lineage exceeds the serialized evidence budget.
    EvidenceTooLarge,
    /// Two retained source applications derive the same lease identity.
    DuplicateLeaseId,
    /// A source lease or owner view failed projection validation.
    Projection(ManifoldBrokerRuntimeLeaseProjectionError),
    /// The refreshed authority identity or revision regressed.
    AuthorityRegression,
    /// The refreshed clock uses a different schema, domain, or epoch.
    ClockLineageMismatch,
    /// The refreshed clock sequence or time regressed.
    ClockRegression,
    /// Runtime Host leases differ from the owner-derived projection set.
    HostLeaseSetMismatch,
}

impl fmt::Display for ManifoldBrokerControlLeaseAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SchemaMismatch => formatter.write_str("control-lease schema mismatch"),
            Self::CapacityExceeded => formatter.write_str("control-lease capacity exceeded"),
            Self::EvidenceTooLarge => {
                formatter.write_str("control-lease authority evidence exceeds byte budget")
            }
            Self::DuplicateLeaseId => formatter.write_str("duplicate projected lease id"),
            Self::Projection(error) => {
                write!(formatter, "control-lease projection failed: {error}")
            }
            Self::AuthorityRegression => {
                formatter.write_str("control-lease authority identity or revision regressed")
            }
            Self::ClockLineageMismatch => {
                formatter.write_str("control-lease authority clock lineage changed")
            }
            Self::ClockRegression => formatter.write_str("control-lease authority clock regressed"),
            Self::HostLeaseSetMismatch => {
                formatter.write_str("Runtime Host lease set differs from control-lease authority")
            }
        }
    }
}

impl std::error::Error for ManifoldBrokerControlLeaseAuthorityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Projection(error) => Some(error),
            _ => None,
        }
    }
}

fn schema_id(value: &str) -> SchemaId {
    SchemaId::new(value).expect("static schema id is valid")
}

fn validate_evidence_size(
    evidence: &ManifoldBrokerControlLeaseAuthorityEvidence,
) -> Result<(), ManifoldBrokerControlLeaseAuthorityError> {
    let mut writer = LimitedWriter::new(MAX_BROKER_CONTROL_LEASE_AUTHORITY_EVIDENCE_BYTES);
    serde_json::to_writer(&mut writer, evidence)
        .map_err(|_| ManifoldBrokerControlLeaseAuthorityError::EvidenceTooLarge)
}

struct LimitedWriter {
    written: usize,
    limit: usize,
}

impl LimitedWriter {
    const fn new(limit: usize) -> Self {
        Self { written: 0, limit }
    }
}

impl Write for LimitedWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let remaining = self.limit.saturating_sub(self.written);
        if buffer.len() > remaining {
            return Err(io::Error::other("serialized evidence byte limit exceeded"));
        }
        self.written += buffer.len();
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusty_manifold_model::DottedId;

    fn accepted_source() -> ManifoldBrokerControlLeaseSource {
        ManifoldBrokerControlLeaseSource {
            schema_id: schema_id(BROKER_CONTROL_LEASE_SOURCE_SCHEMA),
            prior_authority_snapshot: serde_json::from_str(include_str!(
                "../../../fixtures/authority/synthetic-authority-snapshot.json"
            ))
            .expect("prior snapshot"),
            application: serde_json::from_str(include_str!(
                "../../../fixtures/authority-application/synthetic-lease-accepted-application.json"
            ))
            .expect("accepted application"),
        }
    }

    fn current_snapshot() -> ManifoldAuthoritySnapshot {
        accepted_source()
            .application
            .applied_snapshot
            .expect("current snapshot")
    }

    fn current_clock() -> ManifoldClockSnapshot {
        serde_json::from_str(include_str!(
            "../../../fixtures/clock/synthetic-command-review-clock.json"
        ))
        .expect("current clock")
    }

    #[test]
    fn source_lineage_reproduces_exact_host_lease_set() {
        let authority =
            ManifoldBrokerControlLeaseAuthority::from_caller_attested_retained_authority_state(
                current_snapshot(),
                current_clock(),
                vec![accepted_source()],
            )
            .expect("authority");
        assert_eq!(authority.runtime_leases.len(), 1);
        assert_eq!(
            authority.runtime_leases[0].lease_id,
            DottedId::new("lease.synthetic_lease_1").expect("id")
        );
        assert_eq!(authority.projection_receipts.len(), 1);
    }

    #[test]
    fn refresh_rejects_authority_clock_and_lease_regression() {
        let authority =
            ManifoldBrokerControlLeaseAuthority::from_caller_attested_retained_authority_state(
                current_snapshot(),
                current_clock(),
                vec![accepted_source()],
            )
            .expect("authority");
        let evidence = authority.evidence();

        let mut regressed_snapshot = current_snapshot();
        regressed_snapshot.authority_revision = rusty_manifold_model::Revision::INITIAL;
        assert!(matches!(
            ManifoldBrokerControlLeaseAuthority::refresh_from_evidence(
                evidence.clone(),
                regressed_snapshot,
                current_clock(),
            ),
            Err(ManifoldBrokerControlLeaseAuthorityError::AuthorityRegression)
        ));

        let mut regressed_clock = current_clock();
        regressed_clock.sequence = regressed_clock.sequence.saturating_sub(1);
        assert!(matches!(
            ManifoldBrokerControlLeaseAuthority::refresh_from_evidence(
                evidence.clone(),
                current_snapshot(),
                regressed_clock,
            ),
            Err(ManifoldBrokerControlLeaseAuthorityError::ClockRegression)
        ));

        let mut released = current_snapshot();
        released.authority_revision = rusty_manifold_model::Revision::new(3).expect("revision");
        released
            .active_leases
            .retain(|lease| lease.lease_id.as_str() != "lease.synthetic_lease_1");
        assert!(matches!(
            ManifoldBrokerControlLeaseAuthority::refresh_from_evidence(
                evidence,
                released,
                current_clock(),
            ),
            Err(ManifoldBrokerControlLeaseAuthorityError::Projection(_))
        ));
    }

    #[test]
    fn duplicate_source_and_host_only_lease_fail_closed() {
        assert!(matches!(
            ManifoldBrokerControlLeaseAuthority::from_caller_attested_retained_authority_state(
                current_snapshot(),
                current_clock(),
                vec![accepted_source(), accepted_source()],
            ),
            Err(ManifoldBrokerControlLeaseAuthorityError::DuplicateLeaseId)
        ));

        let authority =
            ManifoldBrokerControlLeaseAuthority::from_caller_attested_retained_authority_state(
                current_snapshot(),
                current_clock(),
                vec![accepted_source()],
            )
            .expect("authority");
        let mut snapshot = ManifoldRuntimeHostSnapshot {
            schema_id: schema_id("rusty.manifold.runtime_host.snapshot.v2"),
            host_id: DottedId::new("host.test").expect("id"),
            authority_revision: rusty_manifold_model::Revision::INITIAL,
            commands: Vec::new(),
            leases: authority.runtime_leases().to_vec(),
            applied_request_ids: Vec::new(),
            reviewed_sweep_ids: Vec::new(),
            audit_events: Vec::new(),
        };
        snapshot.leases.push(ManifoldRuntimeLease {
            lease_id: DottedId::new("lease.host_only").expect("id"),
            scope: DottedId::new("scope.host_only").expect("id"),
            holder_id: DottedId::new("holder.host_only").expect("id"),
            expires_at_ms: u64::MAX,
        });
        assert!(matches!(
            authority.validate_host_snapshot(&snapshot),
            Err(ManifoldBrokerControlLeaseAuthorityError::HostLeaseSetMismatch)
        ));
    }

    #[test]
    fn authority_evidence_writer_and_product_lease_count_are_bounded() {
        let mut writer = LimitedWriter::new(4);
        assert!(serde_json::to_writer(&mut writer, "oversized").is_err());

        assert!(matches!(
            ManifoldBrokerControlLeaseAuthority::from_caller_attested_retained_authority_state(
                current_snapshot(),
                current_clock(),
                vec![accepted_source(); MAX_BROKER_CONTROL_LEASES + 1],
            ),
            Err(ManifoldBrokerControlLeaseAuthorityError::CapacityExceeded)
        ));
    }
}
