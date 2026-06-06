use super::*;

pub(super) fn wall_unix_ms_u64(clock: &ManifoldClockSnapshot) -> u64 {
    u64::try_from(clock.wall_unix_ms).unwrap_or_default()
}

pub(super) fn lease_expired_at(
    lease: &ManifoldControlLease,
    clock: &ManifoldClockSnapshot,
) -> bool {
    wall_unix_ms_u64(clock) >= lease.expires_at_ms
}

pub(super) fn stream_subscription_expired_at(
    subscription: &ManifoldStreamSubscription,
    clock: &ManifoldClockSnapshot,
) -> bool {
    wall_unix_ms_u64(clock) >= subscription.expires_at_ms
}

pub(super) fn module_runtime_transition_is_empty(
    transition: &ManifoldModuleRuntimeTransition,
) -> bool {
    transition.lifecycle_change.is_none()
        && transition.health_change.is_none()
        && transition.backend_change.is_none()
        && transition.activated_streams.is_empty()
        && transition.deactivated_streams.is_empty()
        && transition.activated_commands.is_empty()
        && transition.deactivated_commands.is_empty()
        && transition.added_issues.is_empty()
        && transition.resolved_issues.is_empty()
}

pub(super) fn duplicate_stream_id(streams: &[ManifoldStreamManifest]) -> Option<DottedId> {
    streams.iter().enumerate().find_map(|(index, stream)| {
        streams
            .iter()
            .skip(index + 1)
            .any(|other| other.stream_id == stream.stream_id)
            .then(|| stream.stream_id.clone())
    })
}

pub(super) fn duplicate_endpoint_id(endpoints: &[EndpointDescriptor]) -> Option<DottedId> {
    endpoints.iter().enumerate().find_map(|(index, endpoint)| {
        endpoints
            .iter()
            .skip(index + 1)
            .any(|other| other.endpoint_id == endpoint.endpoint_id)
            .then(|| endpoint.endpoint_id.clone())
    })
}

pub(super) fn duplicate_id(ids: &[DottedId]) -> Option<DottedId> {
    ids.iter().enumerate().find_map(|(index, id)| {
        ids.iter()
            .skip(index + 1)
            .any(|other| other == id)
            .then(|| id.clone())
    })
}

pub(super) fn duplicate_subscription_id(
    subscriptions: &[ManifoldStreamSubscription],
) -> Option<DottedId> {
    subscriptions
        .iter()
        .enumerate()
        .find_map(|(index, subscription)| {
            subscriptions
                .iter()
                .skip(index + 1)
                .any(|other| other.subscription_id == subscription.subscription_id)
                .then(|| subscription.subscription_id.clone())
        })
}

pub(super) fn validate_derived_authority_id(
    subject_id: &DottedId,
    actual_id: &DottedId,
    expected_id: DottedId,
) -> Result<(), ManifoldAuthorityValidationError> {
    if actual_id == &expected_id {
        Ok(())
    } else {
        Err(ManifoldAuthorityValidationError::new(
            subject_id.clone(),
            actual_id.to_string(),
            ManifoldAuthorityValidationErrorKind::RequestIdMismatch,
        ))
    }
}

pub(super) fn command_validation_retryable(kind: CommandValidationErrorKind) -> bool {
    matches!(
        kind,
        CommandValidationErrorKind::StaleRevision
            | CommandValidationErrorKind::MissingLease
            | CommandValidationErrorKind::InactiveLease
            | CommandValidationErrorKind::LeaseRevisionMismatch
    )
}

pub(super) fn authority_application_validation_retryable(
    kind: ManifoldAuthorityValidationErrorKind,
) -> bool {
    matches!(
        kind,
        ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch
            | ManifoldAuthorityValidationErrorKind::RegistryRevisionMismatch
            | ManifoldAuthorityValidationErrorKind::ClockSnapshotMismatch
            | ManifoldAuthorityValidationErrorKind::MissingEvidence
            | ManifoldAuthorityValidationErrorKind::UnknownLease
            | ManifoldAuthorityValidationErrorKind::InactiveLease
            | ManifoldAuthorityValidationErrorKind::LeaseRevisionAhead
            | ManifoldAuthorityValidationErrorKind::LeaseMismatch
            | ManifoldAuthorityValidationErrorKind::UnknownSubscription
    )
}

pub(super) fn authority_error_kind_for_rejection_code(
    rejection_code: &str,
) -> ManifoldAuthorityValidationErrorKind {
    match rejection_code {
        "unknown_command" => ManifoldAuthorityValidationErrorKind::UnknownCommand,
        "unknown_lease" => ManifoldAuthorityValidationErrorKind::UnknownLease,
        "expired_lease" => ManifoldAuthorityValidationErrorKind::InactiveLease,
        _ => ManifoldAuthorityValidationErrorKind::CommandValidationFailed,
    }
}

pub(super) fn authority_error_kind_for_lease_rejection_code(
    rejection_code: &str,
) -> ManifoldAuthorityValidationErrorKind {
    match rejection_code {
        "unsupported_schema" => ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
        "stale_revision" => ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
        "invalid_ttl" => ManifoldAuthorityValidationErrorKind::InvalidLeaseTtl,
        "capability_not_advertised" => {
            ManifoldAuthorityValidationErrorKind::CapabilityNotAdvertised
        }
        "lease_scope_busy" => ManifoldAuthorityValidationErrorKind::LeaseScopeBusy,
        _ => ManifoldAuthorityValidationErrorKind::LeaseRequestValidationFailed,
    }
}

pub(super) fn authority_error_kind_for_lease_release_rejection_code(
    rejection_code: &str,
) -> ManifoldAuthorityValidationErrorKind {
    match rejection_code {
        "unsupported_schema" => ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
        "stale_revision" => ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
        "unknown_lease" => ManifoldAuthorityValidationErrorKind::UnknownLease,
        "inactive_lease" | "expired_lease" => ManifoldAuthorityValidationErrorKind::InactiveLease,
        "lease_holder_mismatch" | "lease_scope_mismatch" => {
            ManifoldAuthorityValidationErrorKind::LeaseMismatch
        }
        _ => ManifoldAuthorityValidationErrorKind::LeaseRequestValidationFailed,
    }
}

pub(super) fn authority_error_kind_for_lease_renewal_rejection_code(
    rejection_code: &str,
) -> ManifoldAuthorityValidationErrorKind {
    match rejection_code {
        "unsupported_schema" => ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
        "stale_revision" => ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
        "unknown_lease" => ManifoldAuthorityValidationErrorKind::UnknownLease,
        "inactive_lease" | "expired_lease" => ManifoldAuthorityValidationErrorKind::InactiveLease,
        "invalid_ttl" => ManifoldAuthorityValidationErrorKind::InvalidLeaseTtl,
        "lease_holder_mismatch" | "lease_scope_mismatch" | "non_extending_renewal" => {
            ManifoldAuthorityValidationErrorKind::LeaseMismatch
        }
        _ => ManifoldAuthorityValidationErrorKind::LeaseRequestValidationFailed,
    }
}

pub(super) fn authority_error_kind_for_stream_registry_rejection_code(
    rejection_code: &str,
) -> ManifoldAuthorityValidationErrorKind {
    match rejection_code {
        "stale_revision" => ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
        "capability_not_advertised" => {
            ManifoldAuthorityValidationErrorKind::CapabilityNotAdvertised
        }
        "missing_lease" | "lease_mismatch" => ManifoldAuthorityValidationErrorKind::LeaseMismatch,
        "unknown_lease" => ManifoldAuthorityValidationErrorKind::UnknownLease,
        "inactive_lease" | "expired_lease" => ManifoldAuthorityValidationErrorKind::InactiveLease,
        "lease_revision_ahead" => ManifoldAuthorityValidationErrorKind::LeaseRevisionAhead,
        "registry_revision_mismatch" => {
            ManifoldAuthorityValidationErrorKind::RegistryRevisionMismatch
        }
        "unknown_module_link"
        | "unknown_transport_endpoint"
        | "active_stream_conflict"
        | "active_subscription_conflict"
        | "stream_already_exists"
        | "duplicate_stream"
        | "empty_registry_diff"
        | "unknown_stream" => ManifoldAuthorityValidationErrorKind::StreamRegistryValidationFailed,
        "stream_diff_mismatch" => ManifoldAuthorityValidationErrorKind::StreamDiffMismatch,
        _ => ManifoldAuthorityValidationErrorKind::StreamRegistryValidationFailed,
    }
}

pub(super) fn authority_error_kind_for_stream_subscription_rejection_code(
    rejection_code: &str,
) -> ManifoldAuthorityValidationErrorKind {
    match rejection_code {
        "unsupported_schema" => ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
        "stale_revision" => ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
        "registry_revision_mismatch" => {
            ManifoldAuthorityValidationErrorKind::RegistryRevisionMismatch
        }
        "invalid_ttl" => ManifoldAuthorityValidationErrorKind::InvalidSubscriptionTtl,
        "capability_not_advertised" => {
            ManifoldAuthorityValidationErrorKind::CapabilityNotAdvertised
        }
        "unknown_stream" => ManifoldAuthorityValidationErrorKind::UnknownStream,
        "subscription_not_allowed" => ManifoldAuthorityValidationErrorKind::SubscriptionNotAllowed,
        "subscriber_limit_reached" => {
            ManifoldAuthorityValidationErrorKind::SubscriptionLimitReached
        }
        "unknown_transport" | "unknown_transport_endpoint" => {
            ManifoldAuthorityValidationErrorKind::UnknownTransport
        }
        _ => ManifoldAuthorityValidationErrorKind::StreamSubscriptionValidationFailed,
    }
}

pub(super) fn authority_error_kind_for_stream_subscription_release_rejection_code(
    rejection_code: &str,
) -> ManifoldAuthorityValidationErrorKind {
    match rejection_code {
        "unsupported_schema" => ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
        "stale_revision" => ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
        "registry_revision_mismatch" => {
            ManifoldAuthorityValidationErrorKind::RegistryRevisionMismatch
        }
        "unknown_subscription" => ManifoldAuthorityValidationErrorKind::UnknownSubscription,
        "inactive_subscription" | "expired_subscription" => {
            ManifoldAuthorityValidationErrorKind::SubscriptionMismatch
        }
        "subscriber_mismatch" | "stream_mismatch" => {
            ManifoldAuthorityValidationErrorKind::SubscriptionMismatch
        }
        _ => ManifoldAuthorityValidationErrorKind::StreamSubscriptionValidationFailed,
    }
}

pub(super) fn authority_error_kind_for_stream_subscription_renewal_rejection_code(
    rejection_code: &str,
) -> ManifoldAuthorityValidationErrorKind {
    match rejection_code {
        "unsupported_schema" => ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
        "stale_revision" => ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
        "registry_revision_mismatch" => {
            ManifoldAuthorityValidationErrorKind::RegistryRevisionMismatch
        }
        "invalid_ttl" => ManifoldAuthorityValidationErrorKind::InvalidSubscriptionTtl,
        "unknown_subscription" => ManifoldAuthorityValidationErrorKind::UnknownSubscription,
        "inactive_subscription"
        | "expired_subscription"
        | "subscriber_mismatch"
        | "stream_mismatch"
        | "transport_mismatch"
        | "non_extending_renewal" => ManifoldAuthorityValidationErrorKind::SubscriptionMismatch,
        _ => ManifoldAuthorityValidationErrorKind::StreamSubscriptionValidationFailed,
    }
}

pub(super) fn authority_error_kind_for_expiry_sweep_rejection_code(
    rejection_code: &str,
) -> ManifoldAuthorityValidationErrorKind {
    match rejection_code {
        "unsupported_schema" => ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
        "stale_revision" => ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
        "registry_revision_mismatch" => {
            ManifoldAuthorityValidationErrorKind::RegistryRevisionMismatch
        }
        "no_expired_state" => ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
        _ => ManifoldAuthorityValidationErrorKind::RejectionMismatch,
    }
}

pub(super) fn authority_error_kind_for_module_runtime_rejection_code(
    rejection_code: &str,
) -> ManifoldAuthorityValidationErrorKind {
    match rejection_code {
        "unsupported_schema" => ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
        "stale_revision" => ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
        "capability_not_advertised" => {
            ManifoldAuthorityValidationErrorKind::CapabilityNotAdvertised
        }
        "missing_lease" | "lease_mismatch" => ManifoldAuthorityValidationErrorKind::LeaseMismatch,
        "unknown_lease" => ManifoldAuthorityValidationErrorKind::UnknownLease,
        "inactive_lease" | "expired_lease" => ManifoldAuthorityValidationErrorKind::InactiveLease,
        "lease_revision_ahead" => ManifoldAuthorityValidationErrorKind::LeaseRevisionAhead,
        "unknown_module" => ManifoldAuthorityValidationErrorKind::UnknownModule,
        "module_id_mismatch" => ManifoldAuthorityValidationErrorKind::ModuleIdMismatch,
        "runtime_revision_mismatch" => {
            ManifoldAuthorityValidationErrorKind::RuntimeRevisionMismatch
        }
        "unknown_stream" => ManifoldAuthorityValidationErrorKind::UnknownModuleStream,
        "unknown_command" => ManifoldAuthorityValidationErrorKind::UnknownModuleCommand,
        _ => ManifoldAuthorityValidationErrorKind::ModuleRuntimeValidationFailed,
    }
}

pub(super) fn authority_error_kind_for_host_manifest_rejection_code(
    rejection_code: &str,
) -> ManifoldAuthorityValidationErrorKind {
    match rejection_code {
        "unsupported_schema" => ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
        "stale_revision" => ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
        "capability_not_advertised" => {
            ManifoldAuthorityValidationErrorKind::CapabilityNotAdvertised
        }
        "missing_lease" | "lease_mismatch" => ManifoldAuthorityValidationErrorKind::LeaseMismatch,
        "unknown_lease" => ManifoldAuthorityValidationErrorKind::UnknownLease,
        "inactive_lease" | "expired_lease" => ManifoldAuthorityValidationErrorKind::InactiveLease,
        "lease_revision_ahead" => ManifoldAuthorityValidationErrorKind::LeaseRevisionAhead,
        "host_id_mismatch" => ManifoldAuthorityValidationErrorKind::HostIdMismatch,
        "missing_authority_role" => ManifoldAuthorityValidationErrorKind::HostHasNoAuthority,
        "clock_domain_mismatch" => ManifoldAuthorityValidationErrorKind::ClockDomainMismatch,
        "endpoint_security_mismatch" => {
            ManifoldAuthorityValidationErrorKind::HostEndpointSecurityMismatch
        }
        "endpoint_in_use" => ManifoldAuthorityValidationErrorKind::HostEndpointInUse,
        "capability_in_use" => ManifoldAuthorityValidationErrorKind::HostCapabilityInUse,
        "backend_in_use" => ManifoldAuthorityValidationErrorKind::HostBackendInUse,
        _ => ManifoldAuthorityValidationErrorKind::HostManifestValidationFailed,
    }
}

pub(super) fn authority_error_kind_for_clock_snapshot_rejection_code(
    rejection_code: &str,
) -> ManifoldAuthorityValidationErrorKind {
    match rejection_code {
        "unsupported_schema" => ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
        "stale_revision" => ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
        "capability_not_advertised" => {
            ManifoldAuthorityValidationErrorKind::CapabilityNotAdvertised
        }
        "missing_lease" | "lease_mismatch" => ManifoldAuthorityValidationErrorKind::LeaseMismatch,
        "unknown_lease" => ManifoldAuthorityValidationErrorKind::UnknownLease,
        "inactive_lease" => ManifoldAuthorityValidationErrorKind::InactiveLease,
        "lease_revision_ahead" => ManifoldAuthorityValidationErrorKind::LeaseRevisionAhead,
        "clock_domain_mismatch" => ManifoldAuthorityValidationErrorKind::ClockDomainMismatch,
        _ => ManifoldAuthorityValidationErrorKind::ClockSnapshotMismatch,
    }
}

pub(super) fn added_ids(current: &[DottedId], previous: &[DottedId]) -> Vec<DottedId> {
    added_by_key(current, previous, |id| id)
}

pub(super) fn added_by_key<T, F>(current: &[T], previous: &[T], key: F) -> Vec<T>
where
    T: Clone,
    F: Fn(&T) -> &DottedId,
{
    current
        .iter()
        .filter(|item| {
            !previous
                .iter()
                .any(|previous_item| key(previous_item) == key(item))
        })
        .cloned()
        .collect()
}

pub(super) fn changed_graph_nodes(
    previous: &ManifoldGraphManifest,
    current: &ManifoldGraphManifest,
) -> Vec<ManifoldGraphNodeChange> {
    current
        .nodes
        .iter()
        .filter_map(|node| {
            let previous_node = previous
                .nodes
                .iter()
                .find(|previous_node| previous_node.node_id == node.node_id)?;
            (previous_node.module_id != node.module_id).then(|| ManifoldGraphNodeChange {
                node_id: node.node_id.clone(),
                before_module_id: previous_node.module_id.clone(),
                after_module_id: node.module_id.clone(),
            })
        })
        .collect()
}

pub(super) fn changed_graph_edges(
    previous: &ManifoldGraphManifest,
    current: &ManifoldGraphManifest,
) -> Vec<ManifoldGraphEdgeChange> {
    current
        .edges
        .iter()
        .filter_map(|edge| {
            let previous_edge = previous
                .edges
                .iter()
                .find(|previous_edge| previous_edge.edge_id == edge.edge_id)?;
            (previous_edge != edge).then(|| ManifoldGraphEdgeChange {
                edge_id: edge.edge_id.clone(),
                before: previous_edge.clone(),
                after: edge.clone(),
            })
        })
        .collect()
}

pub(super) fn changed_streams(
    previous: &ManifoldStreamRegistrySnapshot,
    current: &ManifoldStreamRegistrySnapshot,
) -> Vec<ManifoldStreamChange> {
    current
        .streams
        .iter()
        .filter_map(|stream| {
            let previous_stream = previous
                .streams
                .iter()
                .find(|previous_stream| previous_stream.stream_id == stream.stream_id)?;
            (previous_stream != stream).then(|| ManifoldStreamChange {
                stream_id: stream.stream_id.clone(),
                before: previous_stream.clone(),
                after: stream.clone(),
            })
        })
        .collect()
}
