//! Live Broker and signed-pair deadline adoption while retaining the existing media resource graph.
use super::*;
use std::collections::BTreeMap;
use rusty_manifold_media_session::ManifoldAcceptedMediaSession;
use rusty_manifold_peer::ManifoldAcceptedCommonLanPairMediaRoute;

/// Actual coupled owner adoption; no platform resource is created, stopped or replaced.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldConcurrentMediaAuthorityRenewalReceipt {
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    pub request_id: DottedId,
    pub applied: bool,
    pub provider_epoch_id: DottedId,
    pub observed_at_ms: u64,
    pub expires_at_ms: u64,
    pub broker_lifecycle_receipt: ManifoldBrokerControlLeaseLifecycleReceipt,
    pub paired_session_receipt: ManifoldConcurrentPairSessionRenewalReceipt,
    pub prior_inner_lease: ManifoldRuntimeLease,
    pub renewed_inner_lease: ManifoldRuntimeLease,
    pub prior_media: ManifoldAcceptedMediaSession,
    pub renewed_media: ManifoldAcceptedMediaSession,
    pub prior_routes: Vec<ManifoldAcceptedCommonLanPairMediaRoute>,
    pub renewed_routes: Vec<ManifoldAcceptedCommonLanPairMediaRoute>,
}

impl ManifoldPeerRuntimeHost {
    /// Adopts an actual successful live Broker renewal and retained same-session signed proof.
    pub fn adopt_concurrent_media_authority_renewal_with_live_broker_runtime(
        &mut self, broker: &ManifoldBrokerRuntime,
        paired: &ManifoldConcurrentPairSessionRenewalReceipt,
        lifecycle: &ManifoldBrokerControlLeaseLifecycleReceipt, now_ms: u64,
    ) -> Result<ManifoldConcurrentMediaAuthorityRenewalReceipt, ManifoldPeerRuntimeHostError> {
        self.ensure_family_enabled(ManifoldPeerRuntimeAuthorityFamily::MediaSession)?;
        self.ensure_event_capacity()?;
        let request_id=derived("request.concurrent.media-renewal",&lifecycle.lifecycle_request_id);
        if let Some(retained)=self.snapshot.concurrent_media_renewals.iter().find(|r|r.request_id==request_id) {
            if retained.broker_lifecycle_receipt==*lifecycle && retained.paired_session_receipt==*paired {return Ok(retained.clone());}
            return Err(invalid_snapshot("coupled renewal replay changed source receipt"));
        }
        if self.snapshot.concurrent_media_renewals.len()>=32 || !paired.applied
            || !self.snapshot.concurrent_session_renewals.contains(paired)
            || !self.snapshot.signed_topology_authorizations.contains(&ManifoldSignedPeerTopologyAuthorizationV2::CommonLan(paired.topology.clone()))
            || paired.expires_at_ms<=now_ms || paired.observed_at_ms>now_ms {
            return Err(invalid_snapshot("coupled renewal current signed owner proof"));
        }
        let evidence=broker.evidence();
        if lifecycle.provider_epoch_id != self.snapshot.provider_epoch_id
            || evidence.provider_epoch_id != self.snapshot.provider_epoch_id
            || !evidence.control_lease_lifecycle_receipts.contains(lifecycle)
            || !lifecycle.applied || lifecycle.outcome!=ManifoldBrokerControlLeaseLifecycleOutcome::AcceptedAndAdopted
            || lifecycle.operation_kind!=ManifoldBrokerControlLeaseLifecycleOperationKind::Renewal {
            return Err(invalid_snapshot("coupled renewal requires actual accepted live Broker application"));
        }
        let use_=lifecycle.lifecycle_use.as_ref().ok_or_else(||invalid_snapshot("coupled renewal use missing"))?;
        let outer_id=use_.lease_id.as_ref().ok_or_else(||invalid_snapshot("coupled renewal outer lease missing"))?;
        let outer=evidence.host_snapshot.leases.iter().find(|lease| &lease.lease_id==outer_id)
            .ok_or_else(||invalid_snapshot("coupled renewal outer lease not adopted"))?;
        let admissions:Vec<_>=self.snapshot.broker_lease_admissions.iter().filter(|admission|admission.released_at_ms.is_none()
            && broker_outer_lease_id_for_admission(&self.snapshot,admission)==Some(outer_id)).collect();
        if admissions.len()!=1 {return Err(invalid_snapshot("coupled renewal unique current admitted derivative"));}
        let admission=admissions[0];
        validate_active_broker_admission(&self.snapshot,admission,&evidence)?;
        let lease=self.snapshot.media_command_runtime.leases.iter().find(|lease|lease.lease_id==admission.runtime_lease.lease_id)
            .ok_or_else(||invalid_snapshot("coupled renewal current inner lease missing"))?.clone();
        if lease.expires_at_ms<=now_ms || outer.expires_at_ms<=now_ms || outer.holder_id!=lease.holder_id
            || use_.bounded_use.identity.client_id!=lease.holder_id
            || use_.bounded_use.capability_id.as_str()!="capability.manifold.control_lease.renew" {
            return Err(invalid_snapshot("coupled renewal current scoped client/lease"));
        }
        let medias:Vec<_>=self.snapshot.media_sessions.sessions.iter().filter(|media|media.runtime_lease_id==lease.lease_id
            && media.lifecycle_status==ManifoldMediaSessionLifecycleStatus::Current).collect();
        if medias.len()!=1 {return Err(invalid_snapshot("coupled renewal unique active media decision"));}
        let media=medias[0].clone();
        let routes:Vec<_>=self.snapshot.pair_media_routes.routes.iter().filter_map(|route|match route {
            ManifoldAcceptedPairMediaRouteV2::CommonLan(route) if route.media_session_decision_id==media.decision_id
                && route.lifecycle_status==rusty_manifold_peer::ManifoldPairMediaRouteLifecycleStatus::Current=>Some(route.clone()),_=>None,
        }).collect();
        if routes.is_empty() || routes.len()>4 || media.expires_at_ms<=now_ms || routes.iter().any(|route|
            route.expires_at_ms<=now_ms || route.peer_session_id!=paired.session_id || route.peer_session_decision_id!=paired.decision_id
                || route.transport!=paired.topology.transport || route.authority_runtime_lease_id!=lease.lease_id) {
            return Err(invalid_snapshot("coupled renewal current exact active route graph"));
        }
        let expiry=outer.expires_at_ms.min(paired.expires_at_ms).min(now_ms.checked_add(235000).ok_or_else(||invalid_snapshot("coupled renewal expiry overflow"))?);
        let route_expiry=expiry.min(now_ms.checked_add(180000).ok_or_else(||invalid_snapshot("route renewal expiry overflow"))?);
        if expiry<=lease.expires_at_ms || expiry<=media.expires_at_ms || routes.iter().any(|route|route_expiry<=route.expires_at_ms) {
            return Err(invalid_snapshot("coupled renewal deadlines must advance"));
        }
        let mut renewed_lease=lease.clone();renewed_lease.expires_at_ms=expiry;
        let mut renewed_media=media.clone();renewed_media.expires_at_ms=expiry;
        let renewed_routes:Vec<_>=routes.iter().map(|route|renew_route_deadline(route,paired,&renewed_lease,route_expiry,now_ms)).collect();
        let receipt=ManifoldConcurrentMediaAuthorityRenewalReceipt {
            schema_id:schema("rusty.manifold.peer.concurrent_media_authority_renewal_receipt.v1"),request_id:request_id.clone(),applied:true,
            provider_epoch_id:self.snapshot.provider_epoch_id.clone(),observed_at_ms:now_ms,expires_at_ms:route_expiry,
            broker_lifecycle_receipt:lifecycle.clone(),paired_session_receipt:paired.clone(),prior_inner_lease:lease,renewed_inner_lease:renewed_lease.clone(),
            prior_media:media,renewed_media:renewed_media.clone(),prior_routes:routes,renewed_routes:renewed_routes.clone(),
        };
        let mut candidate=self.clone();
        *candidate.snapshot.media_command_runtime.leases.iter_mut().find(|lease|lease.lease_id==renewed_lease.lease_id).expect("checked lease")=renewed_lease.clone();
        *candidate.snapshot.media_sessions.sessions.iter_mut().find(|media|media.decision_id==renewed_media.decision_id).expect("checked media")=renewed_media.clone();
        for renewed in renewed_routes {
            *candidate.snapshot.pair_media_routes.routes.iter_mut().find(|route|route.grant_id()==&renewed.grant_id).expect("checked route")=ManifoldAcceptedPairMediaRouteV2::CommonLan(renewed.clone());
        }
        candidate.snapshot.pair_media_routes.last_observed_at_ms=Some(now_ms);
        candidate.snapshot.concurrent_media_renewals.push(receipt.clone());
        candidate.record(ManifoldPeerRuntimeAuditKind::ConcurrentMediaAuthorityRenewal,request_id,
            candidate.snapshot.media_command_runtime.authority_revision,candidate.snapshot.media_command_runtime.authority_revision,true,None)?;
        validate_snapshot(&candidate.snapshot)?;
        self.snapshot=candidate.snapshot;
        Ok(receipt)
    }
}

fn renew_route_deadline(route:&ManifoldAcceptedCommonLanPairMediaRoute, paired:&ManifoldConcurrentPairSessionRenewalReceipt,
    lease:&ManifoldRuntimeLease,expiry:u64,observed_at_ms:u64)->ManifoldAcceptedCommonLanPairMediaRoute {
    let mut renewed=route.clone();renewed.renewed_at_ms=Some(observed_at_ms);renewed.expires_at_ms=expiry;renewed.authority_runtime_lease_expires_at_ms=lease.expires_at_ms;
    renewed.signed_topology_evidence=paired.topology.clone();renewed.peer_session_authority_revision=paired.topology.authority_revision;
    renewed.peer_session_acceptance_authority_revision=paired.resulting_authority_revision;
    renewed.reciprocal_receipt_id=paired.topology.reciprocal_receipt_id.clone();renewed.reciprocal_authority_revision=paired.topology.reciprocal_authority_revision;
    renewed.enrollment_authority_revision=paired.topology.enrollment_authority_revision;
    renewed
}

pub(super) fn original_common_lan_route<'a>(snapshot:&'a ManifoldPeerRuntimeHostSnapshot, route:&'a ManifoldAcceptedCommonLanPairMediaRoute)->&'a ManifoldAcceptedCommonLanPairMediaRoute {
    snapshot.concurrent_media_renewals.iter().flat_map(|renewal|&renewal.prior_routes).find(|prior|prior.grant_id==route.grant_id).unwrap_or(route)
}

pub(super) fn effective_admitted_lease<'a>(snapshot:&'a ManifoldPeerRuntimeHostSnapshot,admission:&'a ManifoldPeerRuntimeBrokerLeaseAdmission)->&'a ManifoldRuntimeLease {
    snapshot.concurrent_media_renewals.iter().rev().find(|renewal|renewal.prior_inner_lease.derivative_binding==admission.runtime_lease.derivative_binding)
        .map_or(&admission.runtime_lease,|renewal|&renewal.renewed_inner_lease)
}

pub(super) fn validate_concurrent_media_renewals(snapshot:&ManifoldPeerRuntimeHostSnapshot)->Result<(),ManifoldPeerRuntimeHostError> {
    if snapshot.concurrent_media_renewals.len()>32 {return Err(invalid_snapshot("coupled renewal capacity"));}
    let mut seen=BTreeSet::new();let mut latest=BTreeMap::new();
    for receipt in &snapshot.concurrent_media_renewals {
        let mut lease=receipt.prior_inner_lease.clone();lease.expires_at_ms=receipt.renewed_inner_lease.expires_at_ms;
        let mut media=receipt.prior_media.clone();media.expires_at_ms=receipt.renewed_media.expires_at_ms;
        let lifecycle=&receipt.broker_lifecycle_receipt;let paired=&receipt.paired_session_receipt;
        let transition=lifecycle.authority_transition.as_ref().ok_or_else(||invalid_snapshot("renewal owner transition missing"))?;
        let ManifoldBrokerControlLeaseTransitionApplication::Renewal(application)=&transition.application else{return Err(invalid_snapshot("renewal owner transition not renewal"));};
        application.validate_against_snapshot(&transition.prior_authority_snapshot).map_err(|_|invalid_snapshot("renewal generic application lineage"))?;
        let resulting=application.applied_snapshot.as_ref().ok_or_else(||invalid_snapshot("renewal generic application not applied"))?;
        let use_=lifecycle.lifecycle_use.as_ref().ok_or_else(||invalid_snapshot("renewal scoped use missing"))?;
        let outer_id=use_.lease_id.as_ref().ok_or_else(||invalid_snapshot("renewal scoped lease missing"))?;
        let outer=resulting.active_leases.iter().find(|lease|&lease.lease_id==outer_id).ok_or_else(||invalid_snapshot("renewal applied lease missing"))?;
        if receipt.schema_id.as_str()!="rusty.manifold.peer.concurrent_media_authority_renewal_receipt.v1" || !receipt.applied
            || !seen.insert(&receipt.request_id) || receipt.provider_epoch_id!=lifecycle.provider_epoch_id
            || !lifecycle.applied || lifecycle.outcome!=ManifoldBrokerControlLeaseLifecycleOutcome::AcceptedAndAdopted
            || lifecycle.operation_kind!=ManifoldBrokerControlLeaseLifecycleOperationKind::Renewal
            || !snapshot.concurrent_session_renewals.contains(paired) || !paired.applied
            || receipt.prior_inner_lease.expires_at_ms<=receipt.observed_at_ms || receipt.renewed_inner_lease.expires_at_ms<=receipt.prior_inner_lease.expires_at_ms
            || lease!=receipt.renewed_inner_lease || media!=receipt.renewed_media
            || receipt.renewed_inner_lease.expires_at_ms>outer.expires_at_ms || receipt.renewed_inner_lease.expires_at_ms>paired.expires_at_ms
            || receipt.renewed_media.expires_at_ms!=receipt.renewed_inner_lease.expires_at_ms
            || use_.bounded_use.identity.client_id!=lease.holder_id || outer.holder_id!=lease.holder_id
            || use_.bounded_use.capability_id.as_str()!="capability.manifold.control_lease.renew"
            || receipt.prior_routes.is_empty() || receipt.prior_routes.len()!=receipt.renewed_routes.len()
            || latest.get(&lease.lease_id).is_some_and(|previous:&&ManifoldConcurrentMediaAuthorityRenewalReceipt|
                previous.renewed_inner_lease!=receipt.prior_inner_lease || previous.renewed_media!=receipt.prior_media || previous.renewed_routes!=receipt.prior_routes) {
            return Err(invalid_snapshot("coupled renewal changed identity, graph or authority lineage"));
        }
        for (old,new) in receipt.prior_routes.iter().zip(&receipt.renewed_routes) {
            if old.expires_at_ms<=receipt.observed_at_ms || new.expires_at_ms<=old.expires_at_ms || new.expires_at_ms!=receipt.expires_at_ms
                || new.expires_at_ms>receipt.observed_at_ms.saturating_add(180000)
                || *new!=renew_route_deadline(old,paired,&receipt.renewed_inner_lease,new.expires_at_ms,receipt.observed_at_ms) {
                return Err(invalid_snapshot("coupled route renewal exact graph binding"));
            }
        }
        latest.insert(lease.lease_id.clone(),receipt);
    }
    for receipt in latest.values() {
        if let Some(current)=snapshot.media_command_runtime.leases.iter().find(|lease|lease.lease_id==receipt.renewed_inner_lease.lease_id && lease.derivative_binding==receipt.renewed_inner_lease.derivative_binding) {
            if current!=&receipt.renewed_inner_lease {return Err(invalid_snapshot("current inner lease differs from accepted renewal"));}
        } else if !snapshot.broker_lease_admissions.iter().any(|admission|admission.runtime_lease.derivative_binding==receipt.renewed_inner_lease.derivative_binding && admission.released_at_ms.is_some() && admission.release_id.is_some()) {
            return Err(invalid_snapshot("renewed inner lease missing without retained release"));
        }
        let current=snapshot.media_sessions.sessions.iter().find(|media|media.decision_id==receipt.renewed_media.decision_id).ok_or_else(||invalid_snapshot("renewed media missing"))?;
        let mut expected=receipt.renewed_media.clone();
        expected.lifecycle_status=current.lifecycle_status.clone();expected.ended_at_ms=current.ended_at_ms;expected.ended_by_id=current.ended_by_id.clone();
        if current!=&expected {return Err(invalid_snapshot("current media differs from accepted renewal"));}
        for renewed in &receipt.renewed_routes {
            let current=snapshot.pair_media_routes.routes.iter().find_map(|route|match route {ManifoldAcceptedPairMediaRouteV2::CommonLan(value) if value.grant_id==renewed.grant_id=>Some(value),_=>None}).ok_or_else(||invalid_snapshot("renewed route missing"))?;
            let mut expected=renewed.clone();expected.lifecycle_status=current.lifecycle_status.clone();expected.cleanup_status=current.cleanup_status.clone();expected.ended_at_ms=current.ended_at_ms;expected.ended_by_id=current.ended_by_id.clone();expected.termination_action=current.termination_action.clone();expected.termination_runtime_binding=current.termination_runtime_binding.clone();expected.cleanup_receipt_id=current.cleanup_receipt_id.clone();
            if current!=&expected {return Err(invalid_snapshot("current route differs from accepted renewal"));}
        }
    }
    for tagged in &snapshot.pair_media_routes.routes {
        if let ManifoldAcceptedPairMediaRouteV2::CommonLan(route)=tagged {
            if route.renewed_at_ms.is_some() && !snapshot.concurrent_media_renewals.iter().any(|receipt|receipt.renewed_routes.iter().any(|renewed|renewed.grant_id==route.grant_id && renewed.renewed_at_ms==route.renewed_at_ms)) {
                return Err(invalid_snapshot("route renewal observation lacks accepted owner receipt"));
            }
        }
    }
    Ok(())
}
