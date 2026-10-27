//! Compile-only exact public literal shapes from the pre-policy f012 source.
//! No runtime authority, platform effects or wire compatibility is inferred.
#![allow(dead_code)]

fn old_manifoldadmissionsnapshot(
    seed: rusty_manifold_admission::ManifoldAdmissionSnapshot,
) -> rusty_manifold_admission::ManifoldAdmissionSnapshot {
    rusty_manifold_admission::ManifoldAdmissionSnapshot {
        schema_id: seed.schema_id,
        authority_id: seed.authority_id,
        authority_revision: seed.authority_revision,
        history_checkpoint: seed.history_checkpoint,
        grants: seed.grants,
        active_tokens: seed.active_tokens,
        revoked_token_ids: seed.revoked_token_ids,
        consumed_request_ids: seed.consumed_request_ids,
        consumed_use_request_ids: seed.consumed_use_request_ids,
        reviewed_sweep_ids: seed.reviewed_sweep_ids,
        audit_events: seed.audit_events,
        root_renewal_policies: seed.root_renewal_policies,
        max_token_ttl_ms: seed.max_token_ttl_ms,
    }
}

fn old_manifoldpeerruntimetrustpolicy(
    seed: rusty_manifold_peer_runtime_host::ManifoldPeerRuntimeTrustPolicy,
) -> rusty_manifold_peer_runtime_host::ManifoldPeerRuntimeTrustPolicy {
    rusty_manifold_peer_runtime_host::ManifoldPeerRuntimeTrustPolicy {
        schema_id: seed.schema_id,
        policy_id: seed.policy_id,
        revision: seed.revision,
        enabled_authority_families: seed.enabled_authority_families,
        trusted_operator_ids: seed.trusted_operator_ids,
        trusted_key_fingerprints: seed.trusted_key_fingerprints,
        trusted_adapter_ids: seed.trusted_adapter_ids,
        trusted_mesh_proposer_ids: seed.trusted_mesh_proposer_ids,
        media_client_grants: seed.media_client_grants,
        trusted_media_revoker_ids: seed.trusted_media_revoker_ids,
        direct_lane_client_grants: seed.direct_lane_client_grants,
        trusted_direct_lane_revoker_ids: seed.trusted_direct_lane_revoker_ids,
        media_runtime_host_id: seed.media_runtime_host_id,
        media_runtime_lease_scope_id: seed.media_runtime_lease_scope_id,
        direct_lane_runtime_lease_scope_id: seed.direct_lane_runtime_lease_scope_id,
        fresh_setup_policy: seed.fresh_setup_policy,
        fresh_setup_local_peer_id: seed.fresh_setup_local_peer_id,
        fresh_setup_enrollment_selection: seed.fresh_setup_enrollment_selection,
    }
}

fn old_manifoldreciprocaled25519runtimecontext<'a>(
    seed: rusty_manifold_peer::ManifoldReciprocalEd25519RuntimeContext<'a>,
) -> rusty_manifold_peer::ManifoldReciprocalEd25519RuntimeContext<'a> {
    rusty_manifold_peer::ManifoldReciprocalEd25519RuntimeContext {
        runtime_host_id: seed.runtime_host_id,
        trust_policy_id: seed.trust_policy_id,
        trust_policy_revision: seed.trust_policy_revision,
        peer_authority_revision: seed.peer_authority_revision,
        enrollment: seed.enrollment,
        rendezvous_authority_revision: seed.rendezvous_authority_revision,
        peer_session_authority_revision: seed.peer_session_authority_revision,
        peer_mesh_authority_revision: seed.peer_mesh_authority_revision,
        direct_lane_lease_authority_revision: seed.direct_lane_lease_authority_revision,
    }
}

fn old_manifoldpairmediarouteruntimecontext<'a>(
    seed: rusty_manifold_peer::ManifoldPairMediaRouteRuntimeContext<'a>,
) -> rusty_manifold_peer::ManifoldPairMediaRouteRuntimeContext<'a> {
    rusty_manifold_peer::ManifoldPairMediaRouteRuntimeContext {
        authority_host_id: seed.authority_host_id,
        live_authority_provider_epoch_id: seed.live_authority_provider_epoch_id,
        media_client_grants: seed.media_client_grants,
        trusted_media_revoker_ids: seed.trusted_media_revoker_ids,
        command_request: seed.command_request,
        runtime_lease: seed.runtime_lease,
        required_runtime_lease_scope_id: seed.required_runtime_lease_scope_id,
        dispatch: seed.dispatch,
        application: seed.application,
    }
}

fn old_manifoldmediasessionruntimecommandcontext<'a>(
    seed: rusty_manifold_media_session::ManifoldMediaSessionRuntimeCommandContext<'a>,
) -> rusty_manifold_media_session::ManifoldMediaSessionRuntimeCommandContext<'a> {
    rusty_manifold_media_session::ManifoldMediaSessionRuntimeCommandContext {
        runtime_host_id: seed.runtime_host_id,
        live_provider_epoch_id: seed.live_provider_epoch_id,
        client_grants: seed.client_grants,
        trusted_revoker_ids: seed.trusted_revoker_ids,
        command_request: seed.command_request,
        dispatch: seed.dispatch,
        application: seed.application,
    }
}
