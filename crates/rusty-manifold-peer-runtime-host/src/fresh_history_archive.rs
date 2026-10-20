//! Actual-owner archive plans; durable I/O stays in the pinned app-owned bridge.
use super::*;
use rusty_manifold_peer::*;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldFreshHistoryArchiveCursor {
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    pub total: u64,
    pub setup_receipts: u64,
    pub phase_receipts: u64,
    pub first_body_sha256: String,
    pub last_body_sha256: String,
    pub history_sha256: String,
    pub last_ack: ManifoldFreshHistoryCustodyAck,
    pub floor_checkpoint: Vec<ManifoldPairSetupFence>,
    pub credential_checkpoint: Vec<ManifoldPeerCredentialRecord>,
    pub enrollment_authority_revision: Revision,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldFreshHistoryArchiveBody {
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    pub host_id: DottedId,
    pub provider_epoch_id: DottedId,
    pub local_peer_id: DottedId,
    pub trust_policy_id: DottedId,
    pub trust_policy_revision: Revision,
    pub policy: ManifoldFreshPairSetupPolicy,
    pub selection: ManifoldFreshPairSetupEnrollmentSelection,
    pub archive_ordinal: u64,
    pub source_snapshot_sha256: String,
    pub operation_binding: ManifoldFreshArchiveOperationBinding,
    pub prior_cursor: Option<ManifoldFreshHistoryArchiveCursor>,
    pub prime_origin: ManifoldFreshPrimeOrigin,
    pub prime_enrollments: Vec<ManifoldFreshPrimeEnrollmentEntry>,
    pub receipts: Vec<ManifoldFreshPairSetupReceipt>,
    pub phase_preparations: Vec<ManifoldFreshPhasePrepareReceipt>,
    pub floor_checkpoint: Vec<ManifoldPairSetupFence>,
    pub credential_checkpoint: Vec<ManifoldPeerCredentialRecord>,
    pub enrollment_authority_revision: Revision,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldFreshHistoryParentCheckpoint {
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    pub archive_ordinal: u64,
    pub archive_body_sha256: String,
    pub history_sha256: String,
}

/// A borrowed plan cannot be cloned, deserialized, or used beside another writer.
pub struct ManifoldFreshHistoryArchivePlan<'a> {
    owner: &'a mut ManifoldPeerRuntimeHost,
    body: ManifoldFreshHistoryArchiveBody,
    canonical_body: Vec<u8>,
}

fn digest<T: Serialize>(domain: &str, value: &T) -> Result<String, ManifoldPeerRuntimeHostError> {
    fresh_history_digest(domain, value).map_err(invalid_snapshot)
}
pub fn fresh_history_source_sha256(
    snapshot: &ManifoldPeerRuntimeHostSnapshot,
) -> Result<String, ManifoldPeerRuntimeHostError> {
    digest(
        "rusty.manifold.peer.fresh_history_archive_source.v1",
        snapshot,
    )
}
fn local_key<'a>(
    selection: &'a ManifoldFreshPairSetupEnrollmentSelection,
    local: &DottedId,
) -> Result<&'a ManifoldFreshPairSetupEnrollmentKey, ManifoldPeerRuntimeHostError> {
    selection
        .keys
        .iter()
        .find(|k| &k.peer_id == local)
        .ok_or_else(|| invalid_snapshot("archive local selected key"))
}
fn expected_operation(
    body: &ManifoldFreshHistoryArchiveBody,
) -> Result<(), ManifoldPeerRuntimeHostError> {
    let op = &body.operation_binding;
    let matches = match op.kind {
        ManifoldFreshArchiveOperationKind::PairSetup => body.receipts.iter().any(|r| {
            r.request_id == op.manifold_transaction_id
                && r.context_sha256 == op.context_sha256
                && r.request.context.native_setup_request_id == op.native_request_id
                && r.request.context.native_phase_id == op.phase_request_id
        }),
        ManifoldFreshArchiveOperationKind::EnrollmentPreparation => {
            body.phase_preparations.iter().any(|r| {
                r.request.context.request_id == op.manifold_transaction_id
                    && r.context_sha256 == op.context_sha256
                    && r.request.context.setup_request_id == op.native_request_id
                    && r.request.context.native_phase_id == op.phase_request_id
            })
        }
    };
    if !matches {
        return Err(invalid_snapshot(
            "archive actual retained phase operation differs",
        ));
    }
    Ok(())
}
fn validate_body(
    body: &ManifoldFreshHistoryArchiveBody,
) -> Result<(), ManifoldPeerRuntimeHostError> {
    if body.schema_id.as_str() != "rusty.manifold.peer.fresh_history_archive_body.v1"
        || body.archive_ordinal == 0
        || body.archive_ordinal
            != body
                .prior_cursor
                .as_ref()
                .map_or(Some(1), |c| c.total.checked_add(1))
                .ok_or_else(|| invalid_snapshot("archive ordinal overflow"))?
        || !fresh_pair_setup_policy_is_well_formed(&body.policy)
        || !fresh_setup_enrollment_selection_is_well_formed(&body.selection)
        || !fresh_pair_setup_sha256_is_valid(&body.source_snapshot_sha256)
        || (body.receipts.is_empty() && body.phase_preparations.is_empty())
        || body.prime_enrollments.len() > 2
        || body.credential_checkpoint.len() > 2
        || body.floor_checkpoint.len() > 1
    {
        return Err(invalid_snapshot("archive closed body"));
    }
    expected_operation(body)?;
    if let Some(prior) = &body.prior_cursor {
        verify_fresh_history_custody_ack(
            &prior.last_ack,
            local_key(&body.selection, &body.local_peer_id)?,
        )
        .map_err(invalid_snapshot)?;
        if prior.last_ack.context.checkpoint_sha256 != cursor_checkpoint_sha256(prior)?
            || prior.last_ack.context.host_id != body.host_id
            || prior.last_ack.context.provider_epoch_id != body.provider_epoch_id
            || prior.last_ack.context.local_peer_id != body.local_peer_id
            || prior.total != prior.last_ack.context.archive_ordinal
        {
            return Err(invalid_snapshot("archive prior cursor custody differs"));
        }
    }
    let mut floors = body
        .prior_cursor
        .as_ref()
        .map_or_else(Vec::new, |c| c.floor_checkpoint.clone());
    for receipt in &body.receipts {
        validate_fresh_pair_setup_receipt(receipt)?;
        if receipt.local_peer_id != body.local_peer_id
            || receipt.request.context.policy != body.policy
        {
            return Err(invalid_snapshot("archive setup owner/policy differs"));
        }
        advance_fresh_pair_setup_fence(&mut floors, receipt.fence.clone())
            .map_err(invalid_snapshot)?;
    }
    if floors != body.floor_checkpoint {
        return Err(invalid_snapshot("archive floor checkpoint differs"));
    }
    let base = body.prior_cursor.as_ref().map_or(0, |c| c.phase_receipts);
    for (i, receipt) in body.phase_preparations.iter().enumerate() {
        validate_fresh_phase_prepare_receipt(receipt)?;
        if receipt.local_peer_id != body.local_peer_id
            || receipt.request.context.selection != body.selection
            || receipt.prepare_sequence
                != base
                    .checked_add(
                        u64::try_from(i).map_err(|_| invalid_snapshot("archive phase index"))?,
                    )
                    .and_then(|n| n.checked_add(1))
                    .ok_or_else(|| invalid_snapshot("archive phase counter overflow"))?
        {
            return Err(invalid_snapshot(
                "archive preparation owner/sequence differs",
            ));
        }
    }
    Ok(())
}
fn verify_body_ack(
    body: &ManifoldFreshHistoryArchiveBody,
    ack: &ManifoldFreshHistoryCustodyAck,
) -> Result<(), ManifoldPeerRuntimeHostError> {
    validate_body(body)?;
    let raw = fresh_history_canonical(body).map_err(invalid_snapshot)?;
    verify_fresh_history_custody_ack(ack, local_key(&body.selection, &body.local_peer_id)?)
        .map_err(invalid_snapshot)?;
    let c = &ack.context;
    if c.archive_ordinal != body.archive_ordinal
        || c.archive_body_sha256 != fresh_history_body_sha256(&raw)
        || c.host_id != body.host_id
        || c.provider_epoch_id != body.provider_epoch_id
        || c.local_peer_id != body.local_peer_id
        || c.source_snapshot_sha256 != body.source_snapshot_sha256
        || c.operation_binding != body.operation_binding
        || c.checkpoint_sha256
            != fresh_history_body_checkpoint_sha256(body, &c.archive_body_sha256)?
        || c.prior_history_sha256 != body.prior_cursor.as_ref().map(|a| a.history_sha256.clone())
    {
        return Err(invalid_snapshot("archive exact app custody/body differs"));
    }
    Ok(())
}

pub fn fresh_history_body_checkpoint_sha256(
    body: &ManifoldFreshHistoryArchiveBody,
    body_sha: &str,
) -> Result<String, ManifoldPeerRuntimeHostError> {
    let prior = body.prior_cursor.as_ref();
    let setups = prior
        .map_or(0, |p| p.setup_receipts)
        .checked_add(
            u64::try_from(body.receipts.len())
                .map_err(|_| invalid_snapshot("archive setup count"))?,
        )
        .ok_or_else(|| invalid_snapshot("archive setup count overflow"))?;
    let phases = prior
        .map_or(0, |p| p.phase_receipts)
        .checked_add(
            u64::try_from(body.phase_preparations.len())
                .map_err(|_| invalid_snapshot("archive phase count"))?,
        )
        .ok_or_else(|| invalid_snapshot("archive phase count overflow"))?;
    digest(
        "rusty.manifold.peer.fresh_history_cursor.v1",
        &serde_json::json!({
        "total":body.archive_ordinal,"setup_receipts":setups,"phase_receipts":phases,
        "first_body_sha256":prior.map_or(body_sha,|p|p.first_body_sha256.as_str()),"last_body_sha256":body_sha,
        "history_sha256":fresh_history_chain_sha256(prior.map(|p|p.history_sha256.as_str()),body.archive_ordinal,body_sha).map_err(invalid_snapshot)?,
        "floor_checkpoint":body.floor_checkpoint,"credential_checkpoint":body.credential_checkpoint,
        "enrollment_authority_revision":body.enrollment_authority_revision}),
    )
}
fn cursor_checkpoint_sha256(
    c: &ManifoldFreshHistoryArchiveCursor,
) -> Result<String, ManifoldPeerRuntimeHostError> {
    digest(
        "rusty.manifold.peer.fresh_history_cursor.v1",
        &serde_json::json!({
        "total":c.total,"setup_receipts":c.setup_receipts,"phase_receipts":c.phase_receipts,
        "first_body_sha256":c.first_body_sha256,"last_body_sha256":c.last_body_sha256,"history_sha256":c.history_sha256,
        "floor_checkpoint":c.floor_checkpoint,"credential_checkpoint":c.credential_checkpoint,
        "enrollment_authority_revision":c.enrollment_authority_revision}),
    )
}

impl ManifoldPeerRuntimeHost {
    pub fn plan_fresh_history_archive(
        &mut self,
        operation_binding: ManifoldFreshArchiveOperationBinding,
    ) -> Result<ManifoldFreshHistoryArchivePlan<'_>, ManifoldPeerRuntimeHostError> {
        self.require_actual_fresh_setup_owner()?;
        validate_snapshot(&self.snapshot)?;
        super::fresh_pair_setup::no_live_graph(&self.snapshot)?;
        let state = self
            .snapshot
            .fresh_pair_setup
            .as_ref()
            .ok_or_else(|| invalid_snapshot("archive fresh state absent"))?;
        let selection = self
            .snapshot
            .trust_policy
            .fresh_setup_enrollment_selection
            .as_ref()
            .ok_or_else(|| invalid_snapshot("archive selection absent"))?;
        let body = ManifoldFreshHistoryArchiveBody {
            schema_id: schema("rusty.manifold.peer.fresh_history_archive_body.v1"),
            host_id: self.snapshot.host_id.clone(),
            provider_epoch_id: self.snapshot.provider_epoch_id.clone(),
            local_peer_id: self
                .snapshot
                .trust_policy
                .fresh_setup_local_peer_id
                .clone()
                .ok_or_else(|| invalid_snapshot("archive local identity"))?,
            trust_policy_id: self.snapshot.trust_policy.policy_id.clone(),
            trust_policy_revision: self.snapshot.trust_policy.revision,
            policy: self
                .snapshot
                .trust_policy
                .fresh_setup_policy
                .clone()
                .ok_or_else(|| invalid_snapshot("archive policy absent"))?,
            selection: selection.clone(),
            archive_ordinal: state
                .archive
                .as_ref()
                .map_or(Some(1), |c| c.total.checked_add(1))
                .ok_or_else(|| invalid_snapshot("archive ordinal exhausted"))?,
            source_snapshot_sha256: fresh_history_source_sha256(&self.snapshot)?,
            operation_binding,
            prior_cursor: state.archive.clone(),
            prime_origin: state
                .prime_origin
                .clone()
                .ok_or_else(|| invalid_snapshot("archive prime origin absent"))?,
            prime_enrollments: state.prime_enrollments.clone(),
            receipts: state.receipts.clone(),
            phase_preparations: state.phase_preparations.clone(),
            floor_checkpoint: self.snapshot.reciprocal_ed25519.fresh_setup_fences.clone(),
            credential_checkpoint: self
                .snapshot
                .enrollment
                .credentials
                .iter()
                .filter(|c| selection.keys.iter().any(|k| k.key_id == c.key_id))
                .cloned()
                .collect(),
            enrollment_authority_revision: self.snapshot.enrollment.authority_revision,
        };
        validate_body(&body)?;
        let actual_ids = body
            .receipts
            .iter()
            .map(|r| (&r.request_id, &r.local_request_id))
            .chain(
                body.phase_preparations
                    .iter()
                    .map(|r| (&r.request.context.request_id, &r.local_request_id)),
            )
            .collect::<Vec<_>>();
        let latest = self
            .snapshot
            .audit_events
            .iter()
            .filter(|e| actual_ids.iter().any(|(_, local)| *local == &e.source_id))
            .max_by_key(|e| e.sequence)
            .ok_or_else(|| invalid_snapshot("archive latest actual transaction audit absent"))?;
        if !actual_ids.iter().any(|(id, local)| {
            *id == &body.operation_binding.manifold_transaction_id && *local == &latest.source_id
        }) {
            return Err(invalid_snapshot(
                "archive operation is not latest retained actual phase",
            ));
        }
        // The app bridge must independently join the actual stored Native phase
        // archive authority_snapshot, exact operation journal and terminal task
        // handoff before writing and signing. This plan makes no filesystem claim.
        let canonical_body = fresh_history_canonical(&body).map_err(invalid_snapshot)?;
        Ok(ManifoldFreshHistoryArchivePlan {
            owner: self,
            body,
            canonical_body,
        })
    }
}
impl ManifoldFreshHistoryArchivePlan<'_> {
    pub fn body(&self) -> &ManifoldFreshHistoryArchiveBody {
        &self.body
    }
    pub fn canonical_body(&self) -> &[u8] {
        &self.canonical_body
    }
    pub fn commit(
        self,
        ack: ManifoldFreshHistoryCustodyAck,
    ) -> Result<ManifoldFreshHistoryArchiveCursor, ManifoldPeerRuntimeHostError> {
        self.owner.require_actual_fresh_setup_owner()?;
        if fresh_history_source_sha256(&self.owner.snapshot)? != self.body.source_snapshot_sha256 {
            return Err(invalid_snapshot("archive actual owner source changed"));
        }
        verify_body_ack(&self.body, &ack)?;
        let prior = self.body.prior_cursor.as_ref();
        let cursor = ManifoldFreshHistoryArchiveCursor {
            schema_id: schema("rusty.manifold.peer.fresh_history_archive_cursor.v1"),
            total: self.body.archive_ordinal,
            setup_receipts: prior
                .map_or(0, |p| p.setup_receipts)
                .checked_add(
                    u64::try_from(self.body.receipts.len())
                        .map_err(|_| invalid_snapshot("archive setup count"))?,
                )
                .ok_or_else(|| invalid_snapshot("archive setup count exhausted"))?,
            phase_receipts: prior
                .map_or(0, |p| p.phase_receipts)
                .checked_add(
                    u64::try_from(self.body.phase_preparations.len())
                        .map_err(|_| invalid_snapshot("archive phase count"))?,
                )
                .ok_or_else(|| invalid_snapshot("archive phase count exhausted"))?,
            first_body_sha256: prior.map_or_else(
                || ack.context.archive_body_sha256.clone(),
                |p| p.first_body_sha256.clone(),
            ),
            last_body_sha256: ack.context.archive_body_sha256.clone(),
            history_sha256: ack.context.history_sha256.clone(),
            last_ack: ack,
            floor_checkpoint: self.body.floor_checkpoint.clone(),
            credential_checkpoint: self.body.credential_checkpoint.clone(),
            enrollment_authority_revision: self.body.enrollment_authority_revision,
        };
        let mut candidate = self.owner.copy_for_transaction();
        let mut archived = BTreeSet::new();
        let mut proposals = BTreeSet::new();
        for receipt in &self.body.receipts {
            archived.insert(receipt.local_request_id.clone());
            proposals.extend(
                receipt
                    .status_receipts
                    .iter()
                    .map(|r| r.proposal_id.clone()),
            );
        }
        archived.extend(
            self.body
                .phase_preparations
                .iter()
                .map(|r| r.local_request_id.clone()),
        );
        candidate
            .snapshot
            .audit_events
            .retain(|e| !archived.contains(&e.source_id) && !proposals.contains(&e.source_id));
        candidate
            .snapshot
            .enrollment
            .applied_request_ids
            .retain(|id| !archived.contains(id));
        candidate
            .snapshot
            .accepted_peers
            .applied_proposal_ids
            .retain(|id| !proposals.contains(id));
        let state = candidate
            .snapshot
            .fresh_pair_setup
            .as_mut()
            .expect("selected state");
        state.receipts.clear();
        state.phase_preparations.clear();
        state.archive = Some(cursor.clone());
        let previous = candidate
            .snapshot
            .runtime_history_checkpoint
            .as_ref()
            .ok_or_else(|| invalid_snapshot("archive parent checkpoint absent"))?;
        let mut retained_event_ids = candidate
            .snapshot
            .audit_events
            .iter()
            .map(|e| e.event_id.clone())
            .collect::<Vec<_>>();
        retained_event_ids.sort();
        candidate.snapshot.runtime_history_checkpoint =
            Some(Box::new(ManifoldPeerRuntimeHistoryCheckpoint {
                schema_id: schema("rusty.manifold.peer.runtime_history_checkpoint.v2"),
                request_epoch: previous
                    .request_epoch
                    .checked_add(1)
                    .ok_or_else(|| invalid_snapshot("archive parent epoch exhausted"))?,
                event_sequence: candidate.snapshot.event_sequence,
                pair_route_authority_revision: candidate
                    .snapshot
                    .pair_media_routes
                    .authority_revision,
                retained_event_ids,
                source_snapshot_sha256: self.body.source_snapshot_sha256.clone(),
                prior_checkpoint_sha256: Some(domain_separated_digest(
                    "rusty.manifold.peer.runtime_history.sha256.v1",
                    previous,
                )?),
                adopted_media_checkpoint_sha256: previous.adopted_media_checkpoint_sha256.clone(),
                fresh_history_archive: Some(ManifoldFreshHistoryParentCheckpoint {
                    schema_id: schema("rusty.manifold.peer.fresh_history_parent_checkpoint.v1"),
                    archive_ordinal: cursor.total,
                    archive_body_sha256: cursor.last_body_sha256.clone(),
                    history_sha256: cursor.history_sha256.clone(),
                }),
            }));
        validate_snapshot(&candidate.snapshot)?;
        self.owner.commit_transaction_candidate(candidate)?;
        Ok(cursor)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    content = "receipt",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ManifoldFreshHistoricalReceipt {
    Setup(ManifoldFreshPairSetupReceipt),
    Preparation(ManifoldFreshPhasePrepareReceipt),
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ManifoldFreshReceiptLocation {
    Live {
        receipt: ManifoldFreshHistoricalReceipt,
    },
    /// No absence/noeffects/replay permission. Resolve through owned archive IO.
    NotRetained {
        archive_cursor: Option<ManifoldFreshHistoryArchiveCursor>,
    },
}
/// Streaming proof retains one target receipt and one chain root, never a list
/// of archive descriptors. The borrowed actual owner cannot mutate mid-proof.
pub struct ManifoldFreshHistoryLookup<'a> {
    owner: &'a ManifoldPeerRuntimeHost,
    ordinal: u64,
    root: String,
    result: ManifoldFreshHistoricalReceipt,
}
impl ManifoldPeerRuntimeHost {
    pub fn fresh_history_receipt_location(
        &self,
        request_id: &DottedId,
        kind: ManifoldFreshArchiveOperationKind,
    ) -> Result<ManifoldFreshReceiptLocation, ManifoldPeerRuntimeHostError> {
        self.require_actual_fresh_setup_owner()?;
        validate_snapshot(&self.snapshot)?;
        let state = self
            .snapshot
            .fresh_pair_setup
            .as_ref()
            .ok_or_else(|| invalid_snapshot("history location state absent"))?;
        let receipt = match kind {
            ManifoldFreshArchiveOperationKind::PairSetup => state
                .receipts
                .iter()
                .find(|r| &r.request_id == request_id)
                .cloned()
                .map(ManifoldFreshHistoricalReceipt::Setup),
            ManifoldFreshArchiveOperationKind::EnrollmentPreparation => state
                .phase_preparations
                .iter()
                .find(|r| &r.request.context.request_id == request_id)
                .cloned()
                .map(ManifoldFreshHistoricalReceipt::Preparation),
        };
        Ok(match receipt {
            Some(receipt) => ManifoldFreshReceiptLocation::Live { receipt },
            None => ManifoldFreshReceiptLocation::NotRetained {
                archive_cursor: state.archive.clone(),
            },
        })
    }
    pub fn begin_fresh_history_lookup(
        &self,
        request_id: &DottedId,
        body: &ManifoldFreshHistoryArchiveBody,
        ack: &ManifoldFreshHistoryCustodyAck,
    ) -> Result<ManifoldFreshHistoryLookup<'_>, ManifoldPeerRuntimeHostError> {
        self.require_actual_fresh_setup_owner()?;
        validate_snapshot(&self.snapshot)?;
        verify_body_ack(body, ack)?;
        let state = self
            .snapshot
            .fresh_pair_setup
            .as_ref()
            .ok_or_else(|| invalid_snapshot("history lookup state absent"))?;
        let cursor = state
            .archive
            .as_ref()
            .ok_or_else(|| invalid_snapshot("no committed archive cursor"))?;
        if body.host_id != self.snapshot.host_id
            || body.provider_epoch_id != self.snapshot.provider_epoch_id
            || body.trust_policy_id != self.snapshot.trust_policy.policy_id
            || body.trust_policy_revision != self.snapshot.trust_policy.revision
            || Some(&body.local_peer_id)
                != self
                    .snapshot
                    .trust_policy
                    .fresh_setup_local_peer_id
                    .as_ref()
            || Some(&body.selection)
                != self
                    .snapshot
                    .trust_policy
                    .fresh_setup_enrollment_selection
                    .as_ref()
            || Some(&body.policy) != self.snapshot.trust_policy.fresh_setup_policy.as_ref()
            || body.archive_ordinal > cursor.total
        {
            return Err(invalid_snapshot("archive lookup actual owner differs"));
        }
        let result = if let Some(r) = body.receipts.iter().find(|r| &r.request_id == request_id) {
            ManifoldFreshHistoricalReceipt::Setup(r.clone())
        } else if let Some(r) = body
            .phase_preparations
            .iter()
            .find(|r| &r.request.context.request_id == request_id)
        {
            ManifoldFreshHistoricalReceipt::Preparation(r.clone())
        } else {
            return Err(invalid_snapshot(
                "requested transaction absent from supplied archive; no absence grant",
            ));
        };
        Ok(ManifoldFreshHistoryLookup {
            owner: self,
            ordinal: ack.context.archive_ordinal,
            root: ack.context.history_sha256.clone(),
            result,
        })
    }
}
impl ManifoldFreshHistoryLookup<'_> {
    pub fn push_ack(
        &mut self,
        ack: &ManifoldFreshHistoryCustodyAck,
    ) -> Result<(), ManifoldPeerRuntimeHostError> {
        let policy = &self.owner.snapshot.trust_policy;
        let selection = policy
            .fresh_setup_enrollment_selection
            .as_ref()
            .ok_or_else(|| invalid_snapshot("history lookup selection"))?;
        let local = policy
            .fresh_setup_local_peer_id
            .as_ref()
            .ok_or_else(|| invalid_snapshot("history lookup local"))?;
        verify_fresh_history_custody_ack(ack, local_key(selection, local)?)
            .map_err(invalid_snapshot)?;
        if ack.context.archive_ordinal
            != self
                .ordinal
                .checked_add(1)
                .ok_or_else(|| invalid_snapshot("history lookup ordinal overflow"))?
            || ack.context.prior_history_sha256.as_ref() != Some(&self.root)
            || ack.context.host_id != self.owner.snapshot.host_id
            || ack.context.provider_epoch_id != self.owner.snapshot.provider_epoch_id
            || &ack.context.local_peer_id != local
        {
            return Err(invalid_snapshot("archive chain missing/reordered/foreign"));
        }
        self.ordinal = ack.context.archive_ordinal;
        self.root = ack.context.history_sha256.clone();
        Ok(())
    }
    pub fn finish(self) -> Result<ManifoldFreshHistoricalReceipt, ManifoldPeerRuntimeHostError> {
        let cursor = self
            .owner
            .snapshot
            .fresh_pair_setup
            .as_ref()
            .and_then(|s| s.archive.as_ref())
            .ok_or_else(|| invalid_snapshot("history cursor absent"))?;
        if self.ordinal != cursor.total || self.root != cursor.history_sha256 {
            return Err(invalid_snapshot(
                "archive chain does not reach actual current cursor",
            ));
        }
        Ok(self.result)
    }
}

pub(super) fn validate_archive_cursor(
    snapshot: &ManifoldPeerRuntimeHostSnapshot,
) -> Result<(), ManifoldPeerRuntimeHostError> {
    let Some(state) = &snapshot.fresh_pair_setup else {
        return Ok(());
    };
    let Some(c) = &state.archive else {
        return Ok(());
    };
    let selection = snapshot
        .trust_policy
        .fresh_setup_enrollment_selection
        .as_ref()
        .ok_or_else(|| invalid_snapshot("archive selection"))?;
    let local = snapshot
        .trust_policy
        .fresh_setup_local_peer_id
        .as_ref()
        .ok_or_else(|| invalid_snapshot("archive local"))?;
    verify_fresh_history_custody_ack(&c.last_ack, local_key(selection, local)?)
        .map_err(invalid_snapshot)?;
    if c.schema_id.as_str() != "rusty.manifold.peer.fresh_history_archive_cursor.v1"
        || c.total == 0
        || c.last_ack.context.archive_ordinal != c.total
        || c.last_ack.context.archive_body_sha256 != c.last_body_sha256
        || c.last_ack.context.history_sha256 != c.history_sha256
        || c.last_ack.context.host_id != snapshot.host_id
        || c.last_ack.context.checkpoint_sha256 != cursor_checkpoint_sha256(c)?
        || c.last_ack.context.provider_epoch_id != snapshot.provider_epoch_id
        || &c.last_ack.context.local_peer_id != local
        || !fresh_pair_setup_sha256_is_valid(&c.first_body_sha256)
        || c.credential_checkpoint.len() > 2
        || c.floor_checkpoint.len() > 1
        || c.enrollment_authority_revision > snapshot.enrollment.authority_revision
        || c.setup_receipts != c.floor_checkpoint.first().map_or(0, |f| f.setup_epoch)
    {
        return Err(invalid_snapshot("archive bounded cursor drift"));
    }
    for floor in &c.floor_checkpoint {
        if !fresh_pair_setup_fence_is_well_formed(floor) {
            return Err(invalid_snapshot("archive floor shape"));
        }
    }
    for credential in &c.credential_checkpoint {
        let key = selection
            .keys
            .iter()
            .find(|k| k.key_id == credential.key_id)
            .ok_or_else(|| invalid_snapshot("archive checkpoint foreign key"))?;
        let mut expected = key.credential(credential.valid_from_ms, credential.expires_at_ms);
        expected.status = credential.status.clone();
        expected.replaced_by_key_id = credential.replaced_by_key_id.clone();
        if expected != *credential {
            return Err(invalid_snapshot("archive checkpoint key identity changed"));
        }
    }
    Ok(())
}

pub(super) fn validate_fresh_parent_checkpoint(
    snapshot: &ManifoldPeerRuntimeHostSnapshot,
) -> Result<(), ManifoldPeerRuntimeHostError> {
    let Some(parent) = &snapshot.runtime_history_checkpoint else {
        return Ok(());
    };
    let Some(binding) = &parent.fresh_history_archive else {
        return Ok(());
    };
    let cursor = snapshot
        .fresh_pair_setup
        .as_ref()
        .and_then(|s| s.archive.as_ref())
        .ok_or_else(|| invalid_snapshot("fresh parent archive cursor absent"))?;
    if parent.schema_id.as_str() != "rusty.manifold.peer.runtime_history_checkpoint.v2"
        || binding.schema_id.as_str() != "rusty.manifold.peer.fresh_history_parent_checkpoint.v1"
        || binding.archive_ordinal != cursor.total
        || binding.archive_body_sha256 != cursor.last_body_sha256
        || binding.history_sha256 != cursor.history_sha256
        || parent.source_snapshot_sha256 != cursor.last_ack.context.source_snapshot_sha256
    {
        return Err(invalid_snapshot(
            "fresh parent durable archive checkpoint differs",
        ));
    }
    Ok(())
}
