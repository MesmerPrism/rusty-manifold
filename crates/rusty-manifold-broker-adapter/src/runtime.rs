//! Stateful product broker runtime binding admission to Runtime Host mutation.

use crate::{ManifoldBrokerAdapter, ManifoldBrokerAdapterReceipt, RUNTIME_HOST_AUTHORITY_OWNER};
use rusty_manifold_admission::{
    ManifoldAdmissionAuthority, ManifoldAdmissionReceipt, ManifoldAdmissionRequest,
    ManifoldAdmissionRevocationRequest, ManifoldAdmissionSnapshot, ManifoldAdmissionUseRequest,
};
use rusty_manifold_model::{DottedId, Revision, SchemaId};
use rusty_manifold_runtime_host::{ManifoldRuntimeCommandRequest, ManifoldRuntimeHostSnapshot};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Stateful broker mutation request schema.
pub const BROKER_MUTATION_REQUEST_SCHEMA: &str = "rusty.manifold.broker.mutation_request.v1";
/// Stateful broker mutation receipt schema.
pub const BROKER_MUTATION_RECEIPT_SCHEMA: &str = "rusty.manifold.broker.mutation_receipt.v1";
/// One-use admission permit schema.
pub const BROKER_BOUNDED_USE_SCHEMA: &str = "rusty.manifold.broker.bounded_use.v1";
/// Integrated broker runtime evidence schema.
pub const BROKER_RUNTIME_EVIDENCE_SCHEMA: &str = "rusty.manifold.broker.runtime_evidence.v1";

/// One accepted admission use retained until exactly one mutation attempt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerBoundedUse {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// One-time admission-use request identity.
    pub admission_use_request_id: DottedId,
    /// Opaque token identity used at the signature-scoped admission boundary.
    pub token_id: DottedId,
    /// Exact client bound by the accepted token and platform identity.
    pub client_id: DottedId,
    /// Exact capability authorized for this use.
    pub capability_id: DottedId,
    /// Admission revision resulting from the accepted use authorization.
    pub admission_authority_revision: Revision,
    /// Absolute use expiry.
    pub expires_at_ms: u64,
}

/// One broker mutation guarded by an already accepted bounded use.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerMutationRequest {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Exact live provider epoch.
    pub provider_epoch_id: DottedId,
    /// One-time admitted use to consume.
    pub admission_use_request_id: DottedId,
    /// Opaque token that produced the admitted use.
    pub token_id: DottedId,
    /// Admission revision that created the exact bounded use.
    pub expected_admission_authority_revision: Revision,
    /// Runtime Host command request.
    pub command: ManifoldRuntimeCommandRequest,
}

/// Rejection before a bounded use may reach Runtime Host review/application.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldBrokerMutationRejectionReason {
    /// Mutation schema differs from the supported contract.
    SchemaMismatch,
    /// Request targets an older or different provider process epoch.
    ProviderEpochMismatch,
    /// Request does not present the revision that created the exact bounded use.
    StaleAdmissionRevision,
    /// No accepted admission use exists for the supplied identity.
    UnknownAdmissionUse,
    /// Supplied token differs from the opaque token that produced the use.
    AdmissionTokenMismatch,
    /// The admitted use already guarded a prior mutation attempt.
    ReplayedAdmissionUse,
    /// The admitted use expired before mutation review.
    AdmissionUseExpired,
    /// Runtime requester differs from the signature-bound client.
    CrossClientUse,
    /// Admitted capability differs from the exact command capability.
    CapabilityMismatch,
}

/// Integrated admission and Runtime Host mutation receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct ManifoldBrokerMutationReceipt {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Live provider epoch.
    pub provider_epoch_id: DottedId,
    /// One-time admission-use request identity.
    pub admission_use_request_id: DottedId,
    /// Admission revision observed during the mutation attempt.
    pub admission_authority_revision: Revision,
    /// Explicit proof that no transport-local acceptance rules exist.
    pub local_acceptance_rules: bool,
    /// Sole accepted-state decision owner.
    pub authority_owner_id: DottedId,
    /// Whether the command was selected by the immutable product lock.
    pub command_selected: bool,
    /// Whether bounded admission passed and was consumed.
    pub admission_applied: bool,
    /// Admission gate rejection, if Runtime Host was not reached.
    pub admission_rejection_reason: Option<ManifoldBrokerMutationRejectionReason>,
    /// Exact Runtime Host adapter receipt when admission passed.
    pub adapter_receipt: Option<ManifoldBrokerAdapterReceipt>,
    /// True only when admission passed and Runtime Host application applied.
    pub applied: bool,
}

/// Read-only evidence for one live provider process.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerRuntimeEvidence {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Explicit live process epoch.
    pub provider_epoch_id: DottedId,
    /// Current Runtime Host state.
    pub host_snapshot: ManifoldRuntimeHostSnapshot,
    /// Current admission state.
    pub admission_snapshot: ManifoldAdmissionSnapshot,
    /// Accepted uses not yet consumed by a mutation attempt.
    pub pending_bounded_uses: Vec<ManifoldBrokerBoundedUse>,
    /// Bounded uses already consumed by mutation attempts.
    pub consumed_bounded_use_ids: Vec<DottedId>,
}

/// One stateful Rust broker authority for a live standalone or embedded provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldBrokerRuntime {
    provider_epoch_id: DottedId,
    adapter: ManifoldBrokerAdapter,
    admission: ManifoldAdmissionAuthority,
    pending_bounded_uses: BTreeMap<DottedId, ManifoldBrokerBoundedUse>,
    consumed_bounded_use_ids: BTreeSet<DottedId>,
}

impl ManifoldBrokerRuntime {
    /// Creates a fresh provider epoch over one exact product adapter and grant state.
    ///
    /// # Errors
    ///
    /// Returns the admission snapshot validation error when its durable state is invalid.
    pub fn new(
        provider_epoch_id: DottedId,
        adapter: ManifoldBrokerAdapter,
        admission_snapshot: ManifoldAdmissionSnapshot,
    ) -> Result<Self, rusty_manifold_admission::ManifoldAdmissionError> {
        Ok(Self {
            provider_epoch_id,
            adapter,
            admission: ManifoldAdmissionAuthority::from_snapshot(admission_snapshot)?,
            pending_bounded_uses: BTreeMap::new(),
            consumed_bounded_use_ids: BTreeSet::new(),
        })
    }

    /// Returns the current live provider epoch.
    #[must_use]
    pub const fn provider_epoch_id(&self) -> &DottedId {
        &self.provider_epoch_id
    }

    /// Returns the current Runtime Host snapshot.
    #[must_use]
    pub const fn host_snapshot(&self) -> &ManifoldRuntimeHostSnapshot {
        self.adapter.host_snapshot()
    }

    /// Returns the current admission snapshot.
    #[must_use]
    pub const fn admission_snapshot(&self) -> &ManifoldAdmissionSnapshot {
        self.admission.snapshot()
    }

    /// Issues a token through Manifold admission.
    pub fn issue_token(
        &mut self,
        request: &ManifoldAdmissionRequest,
        entropy: [u8; 32],
        now_ms: u64,
    ) -> ManifoldAdmissionReceipt {
        self.admission.issue_token(request, entropy, now_ms)
    }

    /// Authorizes one bounded capability use and retains its exact client binding.
    pub fn authorize_use(
        &mut self,
        request: &ManifoldAdmissionUseRequest,
        now_ms: u64,
    ) -> ManifoldAdmissionReceipt {
        let token_expiry = self
            .admission
            .snapshot()
            .active_tokens
            .iter()
            .find(|token| token.token_id == request.token_id)
            .map(|token| token.expires_at_ms);
        let receipt = self.admission.authorize_use(request, now_ms);
        if receipt.applied {
            let bounded_use = ManifoldBrokerBoundedUse {
                schema_id: schema_id(BROKER_BOUNDED_USE_SCHEMA),
                admission_use_request_id: request.request_id.clone(),
                token_id: request.token_id.clone(),
                client_id: request.identity.client_id.clone(),
                capability_id: request.capability_id.clone(),
                admission_authority_revision: receipt.resulting_authority_revision,
                expires_at_ms: token_expiry
                    .unwrap_or(request.expires_at_ms)
                    .min(request.expires_at_ms),
            };
            self.pending_bounded_uses
                .insert(request.request_id.clone(), bounded_use);
        }
        receipt
    }

    /// Revokes a token and invalidates every pending use derived from it.
    pub fn revoke_token(
        &mut self,
        request: &ManifoldAdmissionRevocationRequest,
    ) -> ManifoldAdmissionReceipt {
        let receipt = self.admission.revoke_token(request);
        if receipt.applied {
            self.pending_bounded_uses
                .retain(|_, use_| use_.token_id != request.token_id);
        }
        receipt
    }

    /// Explicitly expires tokens and invalidates their pending bounded uses.
    pub fn expire_tokens(
        &mut self,
        sweep_id: DottedId,
        expected_revision: Revision,
        now_ms: u64,
    ) -> ManifoldAdmissionReceipt {
        let receipt = self
            .admission
            .expire_tokens(sweep_id, expected_revision, now_ms);
        if receipt.applied {
            self.pending_bounded_uses
                .retain(|_, use_| !receipt.removed_token_ids.contains(&use_.token_id));
        }
        receipt
    }

    /// Consumes one bounded admission use, then reviews and applies through Runtime Host.
    #[must_use]
    pub fn handle_mutation(
        &mut self,
        request: &ManifoldBrokerMutationRequest,
        now_ms: u64,
    ) -> ManifoldBrokerMutationReceipt {
        let admission_revision = self.admission.snapshot().authority_revision;
        let command_selected = self
            .adapter
            .host_snapshot()
            .commands
            .iter()
            .any(|descriptor| descriptor.command_id == request.command.command_id);
        let bounded_use = self
            .pending_bounded_uses
            .get(&request.admission_use_request_id);
        let rejection = if request.schema_id.as_str() != BROKER_MUTATION_REQUEST_SCHEMA {
            Some(ManifoldBrokerMutationRejectionReason::SchemaMismatch)
        } else if request.provider_epoch_id != self.provider_epoch_id {
            Some(ManifoldBrokerMutationRejectionReason::ProviderEpochMismatch)
        } else if self
            .consumed_bounded_use_ids
            .contains(&request.admission_use_request_id)
        {
            Some(ManifoldBrokerMutationRejectionReason::ReplayedAdmissionUse)
        } else if bounded_use.is_none() {
            Some(ManifoldBrokerMutationRejectionReason::UnknownAdmissionUse)
        } else if bounded_use.map(|use_| &use_.token_id) != Some(&request.token_id) {
            Some(ManifoldBrokerMutationRejectionReason::AdmissionTokenMismatch)
        } else if bounded_use.map(|use_| use_.admission_authority_revision)
            != Some(request.expected_admission_authority_revision)
        {
            Some(ManifoldBrokerMutationRejectionReason::StaleAdmissionRevision)
        } else if bounded_use.is_some_and(|use_| use_.expires_at_ms <= now_ms) {
            Some(ManifoldBrokerMutationRejectionReason::AdmissionUseExpired)
        } else if bounded_use.map(|use_| &use_.client_id) != Some(&request.command.requester_id) {
            Some(ManifoldBrokerMutationRejectionReason::CrossClientUse)
        } else if bounded_use.map(|use_| &use_.capability_id)
            != Some(&command_capability(&request.command.command_id))
        {
            Some(ManifoldBrokerMutationRejectionReason::CapabilityMismatch)
        } else {
            None
        };

        if let Some(reason) = rejection {
            return mutation_receipt(
                &self.provider_epoch_id,
                &request.admission_use_request_id,
                admission_revision,
                command_selected,
                false,
                Some(reason),
                None,
            );
        }

        self.pending_bounded_uses
            .remove(&request.admission_use_request_id);
        self.consumed_bounded_use_ids
            .insert(request.admission_use_request_id.clone());
        let adapter_receipt = self.adapter.handle_command(&request.command, now_ms);
        mutation_receipt(
            &self.provider_epoch_id,
            &request.admission_use_request_id,
            admission_revision,
            command_selected,
            true,
            None,
            Some(adapter_receipt),
        )
    }

    /// Returns a read-only state/evidence projection for rebind and restart tests.
    #[must_use]
    pub fn evidence(&self) -> ManifoldBrokerRuntimeEvidence {
        ManifoldBrokerRuntimeEvidence {
            schema_id: schema_id(BROKER_RUNTIME_EVIDENCE_SCHEMA),
            provider_epoch_id: self.provider_epoch_id.clone(),
            host_snapshot: self.adapter.host_snapshot().clone(),
            admission_snapshot: self.admission.snapshot().clone(),
            pending_bounded_uses: self.pending_bounded_uses.values().cloned().collect(),
            consumed_bounded_use_ids: self.consumed_bounded_use_ids.iter().cloned().collect(),
        }
    }
}

/// Returns the exact capability required to attempt one command.
///
/// # Panics
///
/// Panics only if a valid dotted command identifier cannot be prefixed with
/// the static `capability.command` namespace.
#[must_use]
pub fn command_capability(command_id: &DottedId) -> DottedId {
    let suffix = command_id
        .as_str()
        .strip_prefix("command.")
        .unwrap_or(command_id.as_str());
    DottedId::new(format!("capability.command.{suffix}"))
        .expect("command-derived capability is valid")
}

fn mutation_receipt(
    provider_epoch_id: &DottedId,
    admission_use_request_id: &DottedId,
    admission_authority_revision: Revision,
    command_selected: bool,
    admission_applied: bool,
    admission_rejection_reason: Option<ManifoldBrokerMutationRejectionReason>,
    adapter_receipt: Option<ManifoldBrokerAdapterReceipt>,
) -> ManifoldBrokerMutationReceipt {
    let applied = adapter_receipt
        .as_ref()
        .is_some_and(|receipt| receipt.application.applied);
    ManifoldBrokerMutationReceipt {
        schema_id: schema_id(BROKER_MUTATION_RECEIPT_SCHEMA),
        provider_epoch_id: provider_epoch_id.clone(),
        admission_use_request_id: admission_use_request_id.clone(),
        admission_authority_revision,
        local_acceptance_rules: false,
        authority_owner_id: DottedId::new(RUNTIME_HOST_AUTHORITY_OWNER)
            .expect("static authority owner is valid"),
        command_selected,
        admission_applied,
        admission_rejection_reason,
        adapter_receipt,
        applied,
    }
}

fn schema_id(value: &str) -> SchemaId {
    SchemaId::new(value).expect("static schema id is valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ManifoldBrokerAdapterConfig, ManifoldBrokerAdapterMode, BROKER_ADAPTER_CONFIG_SCHEMA,
    };
    use rusty_manifold_admission::{
        ManifoldAdmissionGrant, ManifoldAdmissionRejectionReason, ManifoldClientIdentity,
        ADMISSION_REQUEST_SCHEMA, ADMISSION_REVOCATION_REQUEST_SCHEMA, ADMISSION_SNAPSHOT_SCHEMA,
        ADMISSION_USE_REQUEST_SCHEMA,
    };
    use rusty_manifold_broker_product::{
        resolve_broker_product, ManifoldBrokerFeature, ManifoldBrokerProductLock,
        ManifoldBrokerProductSpec, BROKER_PRODUCT_SPEC_SCHEMA,
    };
    use rusty_manifold_runtime_host::{
        ManifoldRuntimeLease, ManifoldRuntimeRejectionReason, HOST_COMMAND_REQUEST_SCHEMA,
    };

    fn id(value: &str) -> DottedId {
        DottedId::new(value).expect("id")
    }

    fn identity(client: &str) -> ManifoldClientIdentity {
        ManifoldClientIdentity {
            client_id: id(client),
            platform_subject: format!("example.{client}"),
            signing_fingerprint: format!("sha256:{}", "a1".repeat(32)),
        }
    }

    fn lock(features: Vec<ManifoldBrokerFeature>) -> ManifoldBrokerProductLock {
        resolve_broker_product(&ManifoldBrokerProductSpec {
            schema_id: schema_id(BROKER_PRODUCT_SPEC_SCHEMA),
            product_id: id("broker.runtime.test"),
            standalone_enabled: true,
            embedded_enabled: false,
            requested_features: features,
        })
        .expect("lock")
    }

    fn runtime(
        features: Vec<ManifoldBrokerFeature>,
        capabilities: Vec<DottedId>,
        leases: Vec<ManifoldRuntimeLease>,
        epoch: &str,
    ) -> ManifoldBrokerRuntime {
        let lock = lock(features);
        let config = ManifoldBrokerAdapterConfig {
            schema_id: schema_id(BROKER_ADAPTER_CONFIG_SCHEMA),
            adapter_id: id("adapter.runtime.test"),
            mode: ManifoldBrokerAdapterMode::Standalone,
            product_lock_id: lock.lock_id.clone(),
            product_lock_fingerprint: lock.spec_fingerprint.clone(),
            authority_host_id: id("host.runtime.test"),
            authority_owner_id: id(RUNTIME_HOST_AUTHORITY_OWNER),
        };
        let adapter = ManifoldBrokerAdapter::new(config, lock, leases).expect("adapter");
        let admission = ManifoldAdmissionSnapshot {
            schema_id: schema_id(ADMISSION_SNAPSHOT_SCHEMA),
            authority_id: id("authority.admission.runtime.test"),
            authority_revision: Revision::new(1).expect("revision"),
            grants: vec![ManifoldAdmissionGrant {
                grant_id: id("grant.runtime.test"),
                identity: identity("client.runtime.test"),
                capabilities,
                expires_at_ms: 100_000,
                revoked: false,
            }],
            active_tokens: Vec::new(),
            revoked_token_ids: Vec::new(),
            consumed_request_ids: Vec::new(),
            consumed_use_request_ids: Vec::new(),
            audit_events: Vec::new(),
            max_token_ttl_ms: 30_000,
        };
        ManifoldBrokerRuntime::new(id(epoch), adapter, admission).expect("runtime")
    }

    fn two_client_runtime(command: &str, epoch: &str) -> ManifoldBrokerRuntime {
        let product_lock = lock(Vec::new());
        let config = ManifoldBrokerAdapterConfig {
            schema_id: schema_id(BROKER_ADAPTER_CONFIG_SCHEMA),
            adapter_id: id("adapter.runtime.two_client"),
            mode: ManifoldBrokerAdapterMode::Standalone,
            product_lock_id: product_lock.lock_id.clone(),
            product_lock_fingerprint: product_lock.spec_fingerprint.clone(),
            authority_host_id: id("host.runtime.two_client"),
            authority_owner_id: id(RUNTIME_HOST_AUTHORITY_OWNER),
        };
        let adapter =
            ManifoldBrokerAdapter::new(config, product_lock, Vec::new()).expect("adapter");
        let capability = command_capability(&id(command));
        let admission = ManifoldAdmissionSnapshot {
            schema_id: schema_id(ADMISSION_SNAPSHOT_SCHEMA),
            authority_id: id("authority.admission.runtime.two_client"),
            authority_revision: Revision::new(1).expect("revision"),
            grants: ["client.runtime.alpha", "client.runtime.beta"]
                .into_iter()
                .map(|client| ManifoldAdmissionGrant {
                    grant_id: id(&format!("grant.{client}")),
                    identity: identity(client),
                    capabilities: vec![capability.clone()],
                    expires_at_ms: 100_000,
                    revoked: false,
                })
                .collect(),
            active_tokens: Vec::new(),
            revoked_token_ids: Vec::new(),
            consumed_request_ids: Vec::new(),
            consumed_use_request_ids: Vec::new(),
            audit_events: Vec::new(),
            max_token_ttl_ms: 30_000,
        };
        ManifoldBrokerRuntime::new(id(epoch), adapter, admission).expect("runtime")
    }

    fn admit_for_client(
        runtime: &mut ManifoldBrokerRuntime,
        command: &str,
        client: &str,
        suffix: &str,
        expected_revision: u64,
        entropy: u8,
        token_ttl_ms: u64,
    ) -> (DottedId, DottedId, Revision) {
        let issue = runtime.issue_token(
            &ManifoldAdmissionRequest {
                schema_id: schema_id(ADMISSION_REQUEST_SCHEMA),
                request_id: id(&format!("request.runtime.{suffix}.issue")),
                expected_authority_revision: Revision::new(expected_revision).expect("revision"),
                identity: identity(client),
                requested_capabilities: vec![command_capability(&id(command))],
                issued_at_ms: 1_000,
                expires_at_ms: 50_000,
                requested_token_ttl_ms: token_ttl_ms,
            },
            [entropy; 32],
            2_000,
        );
        assert!(issue.applied);
        let token = issue.token.expect("token");
        let use_id = id(&format!("request.runtime.{suffix}.use"));
        let use_receipt = runtime.authorize_use(
            &ManifoldAdmissionUseRequest {
                schema_id: schema_id(ADMISSION_USE_REQUEST_SCHEMA),
                request_id: use_id.clone(),
                expected_authority_revision: issue.resulting_authority_revision,
                token_id: token.token_id.clone(),
                identity: identity(client),
                capability_id: command_capability(&id(command)),
                issued_at_ms: 2_000,
                expires_at_ms: 40_000,
            },
            3_000,
        );
        assert!(use_receipt.applied);
        (
            use_id,
            token.token_id,
            use_receipt.resulting_authority_revision,
        )
    }

    fn client_command(
        command_id: &str,
        client: &str,
        request_suffix: &str,
        expected_host_revision: u64,
    ) -> ManifoldRuntimeCommandRequest {
        ManifoldRuntimeCommandRequest {
            schema_id: schema_id(HOST_COMMAND_REQUEST_SCHEMA),
            request_id: id(&format!("request.runtime.command.{request_suffix}")),
            expected_authority_revision: Revision::new(expected_host_revision).expect("revision"),
            requester_id: id(client),
            command_id: id(command_id),
            lease_id: None,
            params_digest: None,
            issued_at_ms: 3_000,
            expires_at_ms: 40_000,
        }
    }

    fn client_mutation(
        epoch: &str,
        use_id: DottedId,
        token_id: DottedId,
        admission_revision: Revision,
        command: ManifoldRuntimeCommandRequest,
    ) -> ManifoldBrokerMutationRequest {
        ManifoldBrokerMutationRequest {
            schema_id: schema_id(BROKER_MUTATION_REQUEST_SCHEMA),
            provider_epoch_id: id(epoch),
            admission_use_request_id: use_id,
            token_id,
            expected_admission_authority_revision: admission_revision,
            command,
        }
    }

    fn admit(runtime: &mut ManifoldBrokerRuntime, command: &str) -> (DottedId, DottedId) {
        let issue = ManifoldAdmissionRequest {
            schema_id: schema_id(ADMISSION_REQUEST_SCHEMA),
            request_id: id("request.runtime.issue"),
            expected_authority_revision: Revision::new(1).expect("revision"),
            identity: identity("client.runtime.test"),
            requested_capabilities: vec![command_capability(&id(command))],
            issued_at_ms: 1_000,
            expires_at_ms: 10_000,
            requested_token_ttl_ms: 20_000,
        };
        let token = runtime
            .issue_token(&issue, [7; 32], 2_000)
            .token
            .expect("token");
        let use_id = id("request.runtime.use");
        let use_receipt = runtime.authorize_use(
            &ManifoldAdmissionUseRequest {
                schema_id: schema_id(ADMISSION_USE_REQUEST_SCHEMA),
                request_id: use_id.clone(),
                expected_authority_revision: Revision::new(2).expect("revision"),
                token_id: token.token_id.clone(),
                identity: identity("client.runtime.test"),
                capability_id: command_capability(&id(command)),
                issued_at_ms: 2_000,
                expires_at_ms: 9_000,
            },
            3_000,
        );
        assert!(use_receipt.applied);
        (use_id, token.token_id)
    }

    fn command(command: &str, lease: Option<&str>) -> ManifoldRuntimeCommandRequest {
        ManifoldRuntimeCommandRequest {
            schema_id: schema_id(HOST_COMMAND_REQUEST_SCHEMA),
            request_id: id("request.runtime.command"),
            expected_authority_revision: Revision::new(1).expect("revision"),
            requester_id: id("client.runtime.test"),
            command_id: id(command),
            lease_id: lease.map(id),
            params_digest: None,
            issued_at_ms: 2_000,
            expires_at_ms: 9_000,
        }
    }

    fn mutation(
        epoch: &str,
        use_id: DottedId,
        token_id: DottedId,
        command: ManifoldRuntimeCommandRequest,
    ) -> ManifoldBrokerMutationRequest {
        ManifoldBrokerMutationRequest {
            schema_id: schema_id(BROKER_MUTATION_REQUEST_SCHEMA),
            provider_epoch_id: id(epoch),
            admission_use_request_id: use_id,
            token_id,
            expected_admission_authority_revision: Revision::new(3).expect("revision"),
            command,
        }
    }

    #[test]
    fn accepted_bounded_use_reaches_one_runtime_host_application() {
        let command_id = "command.media.session.start";
        let lease = ManifoldRuntimeLease {
            lease_id: id("lease.media.session.runtime.test"),
            scope: id("lease.media.session"),
            holder_id: id("client.runtime.test"),
            expires_at_ms: 60_000,
        };
        let capability = command_capability(&id(command_id));
        let mut runtime = runtime(
            vec![ManifoldBrokerFeature::MediaSession],
            vec![capability],
            vec![lease],
            "epoch.runtime.one",
        );
        let (use_id, token_id) = admit(&mut runtime, command_id);
        let receipt = runtime.handle_mutation(
            &mutation(
                "epoch.runtime.one",
                use_id,
                token_id,
                command(command_id, Some("lease.media.session.runtime.test")),
            ),
            4_000,
        );
        assert!(receipt.admission_applied && receipt.applied);
        assert!(receipt.command_selected);
        assert_eq!(runtime.host_snapshot().authority_revision.get(), 2);
        assert_eq!(runtime.admission_snapshot().authority_revision.get(), 3);
    }

    #[test]
    fn two_clients_keep_independent_pending_uses_across_global_revision_advances() {
        let command_id = "command.session.list";
        let epoch = "epoch.runtime.two_client.advance";
        let mut runtime = two_client_runtime(command_id, epoch);
        let (alpha_use, alpha_token, alpha_revision) = admit_for_client(
            &mut runtime,
            command_id,
            "client.runtime.alpha",
            "alpha",
            1,
            11,
            20_000,
        );
        let (beta_use, beta_token, beta_revision) = admit_for_client(
            &mut runtime,
            command_id,
            "client.runtime.beta",
            "beta",
            3,
            22,
            20_000,
        );
        assert_eq!(alpha_revision.get(), 3);
        assert_eq!(beta_revision.get(), 5);
        assert_eq!(runtime.admission_snapshot().authority_revision.get(), 5);

        let alpha = runtime.handle_mutation(
            &client_mutation(
                epoch,
                alpha_use,
                alpha_token,
                alpha_revision,
                client_command(command_id, "client.runtime.alpha", "alpha", 1),
            ),
            4_000,
        );
        assert!(alpha.applied);
        assert_eq!(alpha.admission_authority_revision.get(), 5);

        let beta = runtime.handle_mutation(
            &client_mutation(
                epoch,
                beta_use,
                beta_token,
                beta_revision,
                client_command(command_id, "client.runtime.beta", "beta", 2),
            ),
            4_000,
        );
        assert!(beta.applied);
        assert_eq!(runtime.host_snapshot().authority_revision.get(), 3);
    }

    #[test]
    fn revoke_and_expiry_invalidate_only_uses_derived_from_removed_tokens() {
        let command_id = "command.session.list";
        let revoke_epoch = "epoch.runtime.two_client.revoke";
        let mut revoked_runtime = two_client_runtime(command_id, revoke_epoch);
        let (alpha_use, alpha_token, alpha_revision) = admit_for_client(
            &mut revoked_runtime,
            command_id,
            "client.runtime.alpha",
            "revoke_alpha",
            1,
            31,
            20_000,
        );
        let (beta_use, beta_token, beta_revision) = admit_for_client(
            &mut revoked_runtime,
            command_id,
            "client.runtime.beta",
            "revoke_beta",
            3,
            32,
            20_000,
        );
        let revoked = revoked_runtime.revoke_token(&ManifoldAdmissionRevocationRequest {
            schema_id: schema_id(ADMISSION_REVOCATION_REQUEST_SCHEMA),
            request_id: id("request.runtime.revoke_alpha.token"),
            expected_authority_revision: Revision::new(5).expect("revision"),
            token_id: alpha_token.clone(),
            identity: identity("client.runtime.alpha"),
            reason: id("reason.runtime.client_shutdown"),
        });
        assert!(revoked.applied);
        let alpha_after_revoke = revoked_runtime.handle_mutation(
            &client_mutation(
                revoke_epoch,
                alpha_use,
                alpha_token,
                alpha_revision,
                client_command(command_id, "client.runtime.alpha", "revoke_alpha", 1),
            ),
            4_000,
        );
        assert_eq!(
            alpha_after_revoke.admission_rejection_reason,
            Some(ManifoldBrokerMutationRejectionReason::UnknownAdmissionUse)
        );
        let beta_after_revoke = revoked_runtime.handle_mutation(
            &client_mutation(
                revoke_epoch,
                beta_use,
                beta_token,
                beta_revision,
                client_command(command_id, "client.runtime.beta", "revoke_beta", 1),
            ),
            4_000,
        );
        assert!(beta_after_revoke.applied);
        assert_eq!(beta_after_revoke.admission_authority_revision.get(), 6);

        let expiry_epoch = "epoch.runtime.two_client.expiry";
        let mut expired_runtime = two_client_runtime(command_id, expiry_epoch);
        let (short_use, short_token, short_revision) = admit_for_client(
            &mut expired_runtime,
            command_id,
            "client.runtime.alpha",
            "expiry_alpha",
            1,
            41,
            3_000,
        );
        let (long_use, long_token, long_revision) = admit_for_client(
            &mut expired_runtime,
            command_id,
            "client.runtime.beta",
            "expiry_beta",
            3,
            42,
            20_000,
        );
        let expired = expired_runtime.expire_tokens(
            id("sweep.runtime.two_client.expiry"),
            Revision::new(5).expect("revision"),
            6_000,
        );
        assert!(expired.applied);
        assert_eq!(expired.removed_token_ids, vec![short_token.clone()]);
        let short_after_expiry = expired_runtime.handle_mutation(
            &client_mutation(
                expiry_epoch,
                short_use,
                short_token,
                short_revision,
                client_command(command_id, "client.runtime.alpha", "expiry_alpha", 1),
            ),
            6_000,
        );
        assert_eq!(
            short_after_expiry.admission_rejection_reason,
            Some(ManifoldBrokerMutationRejectionReason::UnknownAdmissionUse)
        );
        let long_after_expiry = expired_runtime.handle_mutation(
            &client_mutation(
                expiry_epoch,
                long_use,
                long_token,
                long_revision,
                client_command(command_id, "client.runtime.beta", "expiry_beta", 1),
            ),
            6_000,
        );
        assert!(long_after_expiry.applied);
        assert_eq!(long_after_expiry.admission_authority_revision.get(), 6);
    }

    #[test]
    fn bounded_use_rejects_stale_cross_client_capability_and_replay() {
        let command_id = "command.session.list";
        let mut runtime = runtime(
            Vec::new(),
            vec![command_capability(&id(command_id))],
            Vec::new(),
            "epoch.runtime.gates",
        );
        let (use_id, token_id) = admit(&mut runtime, command_id);
        let mut request = mutation(
            "epoch.runtime.gates",
            use_id.clone(),
            token_id,
            command(command_id, None),
        );
        request.expected_admission_authority_revision = Revision::new(2).expect("revision");
        assert_eq!(
            runtime
                .handle_mutation(&request, 4_000)
                .admission_rejection_reason,
            Some(ManifoldBrokerMutationRejectionReason::StaleAdmissionRevision)
        );
        request.expected_admission_authority_revision = Revision::new(3).expect("revision");
        let token_id = request.token_id.clone();
        request.token_id = id("token.session.substituted");
        assert_eq!(
            runtime
                .handle_mutation(&request, 4_000)
                .admission_rejection_reason,
            Some(ManifoldBrokerMutationRejectionReason::AdmissionTokenMismatch)
        );
        request.token_id = token_id;
        request.command.requester_id = id("client.other");
        assert_eq!(
            runtime
                .handle_mutation(&request, 4_000)
                .admission_rejection_reason,
            Some(ManifoldBrokerMutationRejectionReason::CrossClientUse)
        );
        request.command.requester_id = id("client.runtime.test");
        request.command.command_id = id("command.peer.status.get");
        assert_eq!(
            runtime
                .handle_mutation(&request, 4_000)
                .admission_rejection_reason,
            Some(ManifoldBrokerMutationRejectionReason::CapabilityMismatch)
        );
        request.command.command_id = id(command_id);
        assert!(runtime.handle_mutation(&request, 4_000).applied);
        assert_eq!(
            runtime
                .handle_mutation(&request, 4_000)
                .admission_rejection_reason,
            Some(ManifoldBrokerMutationRejectionReason::ReplayedAdmissionUse)
        );
    }

    #[test]
    fn unknown_unselected_and_unleased_reach_host_and_fail_without_platform_apply() {
        for (features, command_id, selected, expected) in [
            (
                Vec::new(),
                "command.never.registered",
                false,
                ManifoldRuntimeRejectionReason::UnknownCommand,
            ),
            (
                Vec::new(),
                "command.media.session.start",
                false,
                ManifoldRuntimeRejectionReason::UnknownCommand,
            ),
            (
                vec![ManifoldBrokerFeature::MediaSession],
                "command.media.session.start",
                true,
                ManifoldRuntimeRejectionReason::MissingLease,
            ),
        ] {
            let mut runtime = runtime(
                features,
                vec![command_capability(&id(command_id))],
                Vec::new(),
                "epoch.runtime.damage",
            );
            let (use_id, token_id) = admit(&mut runtime, command_id);
            let receipt = runtime.handle_mutation(
                &mutation(
                    "epoch.runtime.damage",
                    use_id,
                    token_id,
                    command(command_id, None),
                ),
                4_000,
            );
            assert!(receipt.admission_applied);
            assert!(!receipt.applied);
            assert_eq!(receipt.command_selected, selected);
            assert_eq!(
                receipt
                    .adapter_receipt
                    .expect("host receipt")
                    .application
                    .rejection_reason,
                Some(expected)
            );
            assert_eq!(runtime.host_snapshot().authority_revision.get(), 1);
        }
    }

    #[test]
    fn same_runtime_preserves_state_and_fresh_provider_epoch_rejects_old_claims() {
        let command_id = "command.session.list";
        let capability = command_capability(&id(command_id));
        let mut first = runtime(
            Vec::new(),
            vec![capability.clone()],
            Vec::new(),
            "epoch.runtime.first",
        );
        let (use_id, token_id) = admit(&mut first, command_id);
        let old_request = mutation(
            "epoch.runtime.first",
            use_id,
            token_id,
            command(command_id, None),
        );
        assert!(first.handle_mutation(&old_request, 4_000).applied);
        assert_eq!(first.evidence().host_snapshot.authority_revision.get(), 2);

        let mut restarted = runtime(
            Vec::new(),
            vec![capability],
            Vec::new(),
            "epoch.runtime.second",
        );
        assert_eq!(restarted.host_snapshot().authority_revision.get(), 1);
        assert_eq!(
            restarted
                .handle_mutation(&old_request, 4_000)
                .admission_rejection_reason,
            Some(ManifoldBrokerMutationRejectionReason::ProviderEpochMismatch)
        );
        assert_eq!(restarted.host_snapshot().authority_revision.get(), 1);
    }

    #[test]
    fn revocation_invalidates_pending_bounded_use() {
        let command_id = "command.session.list";
        let mut runtime = runtime(
            Vec::new(),
            vec![command_capability(&id(command_id))],
            Vec::new(),
            "epoch.runtime.revoke",
        );
        let (use_id, token_id) = admit(&mut runtime, command_id);
        let revoke = runtime.revoke_token(&ManifoldAdmissionRevocationRequest {
            schema_id: schema_id(ADMISSION_REVOCATION_REQUEST_SCHEMA),
            request_id: id("request.runtime.revoke"),
            expected_authority_revision: Revision::new(3).expect("revision"),
            token_id: token_id.clone(),
            identity: identity("client.runtime.test"),
            reason: id("reason.runtime.test"),
        });
        assert!(revoke.applied);
        let mut request = mutation(
            "epoch.runtime.revoke",
            use_id,
            token_id,
            command(command_id, None),
        );
        request.expected_admission_authority_revision = Revision::new(4).expect("revision");
        assert_eq!(
            runtime
                .handle_mutation(&request, 4_000)
                .admission_rejection_reason,
            Some(ManifoldBrokerMutationRejectionReason::UnknownAdmissionUse)
        );
        assert_eq!(
            runtime.admission_snapshot().revoked_token_ids.len(),
            1,
            "revocation remains Manifold-owned"
        );
        assert_ne!(
            revoke.rejection_reason,
            Some(ManifoldAdmissionRejectionReason::TokenRevoked)
        );
    }
}
