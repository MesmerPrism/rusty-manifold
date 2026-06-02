//! First-slice contract models for Manifold manifests and snapshots.

use core::fmt;

use crate::{DottedId, Revision, SchemaId};

/// A package-level manifest for a distributable Manifold contract package.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldPackageManifest {
    /// Schema identifier for this manifest.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable package identifier.
    pub package_id: DottedId,
    /// Package version string.
    pub version: String,
    /// SPDX license expression.
    pub license: String,
    /// Exported contract ids.
    pub exports: PackageExports,
    /// Validation commands advertised by the package.
    pub validation_commands: Vec<ValidationCommandDescriptor>,
    /// Provenance manifest ids or references required to interpret this package.
    #[cfg_attr(feature = "serde", serde(default))]
    pub provenance_refs: Vec<DottedId>,
    /// Notice ids required when publishing or presenting this package.
    #[cfg_attr(feature = "serde", serde(default))]
    pub notice_refs: Vec<DottedId>,
    /// Package safety flags.
    pub safety: PackageSafetyFlags,
}

/// Static graph manifest connecting module nodes and stream edges.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldGraphManifest {
    /// Schema identifier for this manifest.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable graph id.
    pub graph_id: DottedId,
    /// Accepted graph revision.
    pub graph_revision: Revision,
    /// Module nodes in the graph.
    pub nodes: Vec<ManifoldGraphNode>,
    /// Stream edges between nodes.
    pub edges: Vec<ManifoldGraphEdge>,
    /// Capabilities required to run or mutate this graph.
    pub required_capabilities: Vec<DottedId>,
}

impl ManifoldGraphManifest {
    /// Validates that graph nodes reference known module ids and edges reference known nodes.
    ///
    /// # Errors
    ///
    /// Returns [`GraphValidationError`] when a node references an unknown module
    /// or an edge references an unknown graph node.
    pub fn validate_links(&self, module_ids: &[DottedId]) -> Result<(), GraphValidationError> {
        for node in &self.nodes {
            if !module_ids
                .iter()
                .any(|module_id| module_id == &node.module_id)
            {
                return Err(GraphValidationError {
                    graph_id: self.graph_id.clone(),
                    link_id: node.module_id.clone(),
                    kind: GraphValidationErrorKind::UnknownModuleLink,
                });
            }
        }

        for edge in &self.edges {
            if !self
                .nodes
                .iter()
                .any(|node| node.node_id == edge.source_node_id)
            {
                return Err(GraphValidationError {
                    graph_id: self.graph_id.clone(),
                    link_id: edge.source_node_id.clone(),
                    kind: GraphValidationErrorKind::UnknownNodeLink,
                });
            }

            if !self
                .nodes
                .iter()
                .any(|node| node.node_id == edge.target_node_id)
            {
                return Err(GraphValidationError {
                    graph_id: self.graph_id.clone(),
                    link_id: edge.target_node_id.clone(),
                    kind: GraphValidationErrorKind::UnknownNodeLink,
                });
            }
        }

        Ok(())
    }

    /// Returns a structural diff from an earlier graph revision to this graph.
    ///
    /// # Panics
    ///
    /// Panics only if the built-in graph-diff schema id literal is invalid.
    #[must_use]
    pub fn diff_from(&self, previous: &Self) -> ManifoldGraphDiff {
        ManifoldGraphDiff {
            schema_id: SchemaId::new("rusty.manifold.graph.diff.v1")
                .expect("schema literal is valid"),
            graph_id: self.graph_id.clone(),
            from_revision: previous.graph_revision,
            to_revision: self.graph_revision,
            added_nodes: added_by_key(&self.nodes, &previous.nodes, |node| &node.node_id),
            removed_nodes: added_by_key(&previous.nodes, &self.nodes, |node| &node.node_id),
            changed_nodes: changed_graph_nodes(previous, self),
            added_edges: added_by_key(&self.edges, &previous.edges, |edge| &edge.edge_id),
            removed_edges: added_by_key(&previous.edges, &self.edges, |edge| &edge.edge_id),
            changed_edges: changed_graph_edges(previous, self),
        }
    }
}

/// A module node in a graph manifest.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldGraphNode {
    /// Stable graph-local node id.
    pub node_id: DottedId,
    /// Module id used by this node.
    pub module_id: DottedId,
}

/// A stream edge in a graph manifest.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldGraphEdge {
    /// Stable graph-local edge id.
    pub edge_id: DottedId,
    /// Source node id.
    pub source_node_id: DottedId,
    /// Stream id produced by the source node.
    pub source_stream_id: DottedId,
    /// Target node id.
    pub target_node_id: DottedId,
    /// Target input id or stream id consumed by the target.
    pub target_input_id: DottedId,
}

/// Structural graph diff between two graph revisions.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldGraphDiff {
    /// Schema identifier for this diff.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Graph being compared.
    pub graph_id: DottedId,
    /// Earlier graph revision.
    pub from_revision: Revision,
    /// Later graph revision.
    pub to_revision: Revision,
    /// Nodes present only in the later graph.
    pub added_nodes: Vec<ManifoldGraphNode>,
    /// Nodes present only in the earlier graph.
    pub removed_nodes: Vec<ManifoldGraphNode>,
    /// Nodes with the same id but changed module binding.
    pub changed_nodes: Vec<ManifoldGraphNodeChange>,
    /// Edges present only in the later graph.
    pub added_edges: Vec<ManifoldGraphEdge>,
    /// Edges present only in the earlier graph.
    pub removed_edges: Vec<ManifoldGraphEdge>,
    /// Edges with the same id but changed endpoints or stream ids.
    pub changed_edges: Vec<ManifoldGraphEdgeChange>,
}

/// Changed graph-node binding.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldGraphNodeChange {
    /// Stable graph-local node id.
    pub node_id: DottedId,
    /// Earlier module id.
    pub before_module_id: DottedId,
    /// Later module id.
    pub after_module_id: DottedId,
}

/// Changed graph-edge binding.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldGraphEdgeChange {
    /// Stable graph-local edge id.
    pub edge_id: DottedId,
    /// Earlier edge descriptor.
    pub before: ManifoldGraphEdge,
    /// Later edge descriptor.
    pub after: ManifoldGraphEdge,
}

/// Deterministic execution report for a static graph run.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldGraphExecutionReport {
    /// Schema identifier for this report.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Graph being executed.
    pub graph_id: DottedId,
    /// Graph revision being executed.
    pub graph_revision: Revision,
    /// Runtime implementation path that produced this report.
    pub runtime_path: DottedId,
    /// Modules selected by the caller.
    pub selected_module_ids: Vec<DottedId>,
    /// Nodes materialized after dependency resolution.
    pub resolved_node_ids: Vec<DottedId>,
    /// Overall status.
    pub status: ValidationStatus,
    /// Per-node execution reports.
    pub node_reports: Vec<ManifoldGraphNodeExecutionReport>,
    /// Output stream ids materialized by the run.
    pub output_stream_ids: Vec<DottedId>,
    /// Issues found during graph execution.
    pub issues: Vec<ManifoldIssue>,
}

/// Execution report for one graph node.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldGraphNodeExecutionReport {
    /// Graph-local node id.
    pub node_id: DottedId,
    /// Module id bound to the node.
    pub module_id: DottedId,
    /// Node status.
    pub status: ValidationStatus,
    /// Dependency nodes required before this node ran.
    pub dependency_node_ids: Vec<DottedId>,
    /// Input stream ids consumed by the node.
    pub input_stream_ids: Vec<DottedId>,
    /// Output stream ids produced by the node.
    pub output_stream_ids: Vec<DottedId>,
    /// Deterministic sample-count facts reported by the node.
    pub sample_counts: Vec<ManifoldGraphSampleCount>,
    /// Machine-readable issue codes for this node.
    pub issue_codes: Vec<DottedId>,
}

/// Named sample-count fact in a graph execution report.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldGraphSampleCount {
    /// Sample-count id, usually graph/module local.
    pub count_id: DottedId,
    /// Count value.
    pub value: u64,
}

/// Exported ids in a package manifest.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PackageExports {
    /// Module ids exported by this package.
    pub modules: Vec<DottedId>,
    /// Stream ids exported by this package.
    pub streams: Vec<DottedId>,
    /// Command ids exported by this package.
    pub commands: Vec<DottedId>,
}

/// A package validation command descriptor.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidationCommandDescriptor {
    /// Stable validation command id.
    pub command_id: DottedId,
    /// Human-readable command text.
    pub command: String,
}

/// Package-level safety flags.
#[allow(clippy::struct_excessive_bools)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PackageSafetyFlags {
    /// Whether the package uses network access.
    pub uses_network: bool,
    /// Whether the package starts subprocesses.
    pub uses_subprocess: bool,
    /// Whether the package includes native code.
    pub uses_native_code: bool,
    /// Whether the package uses device APIs.
    pub uses_device_api: bool,
    /// Whether the package carries generated or binary payloads.
    pub carries_binary_payloads: bool,
}

/// Declared module capability surface.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldModuleManifest {
    /// Schema identifier for this manifest.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable module id.
    pub module_id: DottedId,
    /// Module kind.
    pub module_kind: ModuleKind,
    /// Display label.
    pub label: String,
    /// Module version string.
    pub version: String,
    /// Lifecycle states this module can report.
    pub lifecycle_states: Vec<ModuleLifecycleState>,
    /// Streams this module can provide.
    pub provides_streams: Vec<DottedId>,
    /// Streams this module can consume.
    pub consumes_streams: Vec<DottedId>,
    /// Commands accepted by this module.
    pub accepted_commands: Vec<DottedId>,
    /// Capabilities required to run or control this module.
    pub required_capabilities: Vec<DottedId>,
    /// Clock and timestamp policy.
    pub clock_policy: ClockPolicy,
    /// Retention policy for direct outputs.
    pub retention: RetentionPolicyDescriptor,
    /// Data sensitivity label.
    pub sensitivity: SensitivityLevel,
    /// Host/backend families this module can run on.
    pub platform_support: Vec<DottedId>,
    /// Machine-readable issue codes the module may report.
    pub issue_codes: Vec<DottedId>,
}

/// Live module state at one authority revision.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldModuleRuntimeState {
    /// Schema identifier for this snapshot.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Module this state describes.
    pub module_id: DottedId,
    /// Runtime revision that accepted this state.
    pub runtime_revision: Revision,
    /// Current lifecycle state.
    pub lifecycle: ModuleLifecycleState,
    /// Current health level.
    pub health: HealthLevel,
    /// Selected backend, when one has been selected.
    pub selected_backend: Option<DottedId>,
    /// Active streams owned by this module.
    pub active_streams: Vec<DottedId>,
    /// Active command surfaces owned by this module.
    pub active_commands: Vec<DottedId>,
    /// Current issues.
    pub issues: Vec<ManifoldIssue>,
}

impl ManifoldModuleRuntimeState {
    /// Returns the state transition from an earlier runtime snapshot to this snapshot.
    ///
    /// # Panics
    ///
    /// Panics only if the built-in runtime-transition schema id literal is invalid.
    #[must_use]
    pub fn transition_from(&self, previous: &Self) -> ManifoldModuleRuntimeTransition {
        ManifoldModuleRuntimeTransition {
            schema_id: SchemaId::new("rusty.manifold.module.runtime_transition.v1")
                .expect("schema literal is valid"),
            module_id: self.module_id.clone(),
            from_revision: previous.runtime_revision,
            to_revision: self.runtime_revision,
            lifecycle_change: (previous.lifecycle != self.lifecycle).then_some(
                ModuleLifecycleChange {
                    from: previous.lifecycle,
                    to: self.lifecycle,
                },
            ),
            health_change: (previous.health != self.health).then_some(ModuleHealthChange {
                from: previous.health,
                to: self.health,
            }),
            backend_change: (previous.selected_backend != self.selected_backend).then_some(
                ModuleBackendChange {
                    from: previous.selected_backend.clone(),
                    to: self.selected_backend.clone(),
                },
            ),
            activated_streams: added_ids(&self.active_streams, &previous.active_streams),
            deactivated_streams: added_ids(&previous.active_streams, &self.active_streams),
            activated_commands: added_ids(&self.active_commands, &previous.active_commands),
            deactivated_commands: added_ids(&previous.active_commands, &self.active_commands),
            added_issues: added_by_key(&self.issues, &previous.issues, |issue| &issue.issue_code),
            resolved_issues: added_by_key(&previous.issues, &self.issues, |issue| {
                &issue.issue_code
            }),
        }
    }
}

/// Runtime-state transition for one module.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldModuleRuntimeTransition {
    /// Schema identifier for this transition.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Module being compared.
    pub module_id: DottedId,
    /// Earlier runtime revision.
    pub from_revision: Revision,
    /// Later runtime revision.
    pub to_revision: Revision,
    /// Lifecycle change, if any.
    pub lifecycle_change: Option<ModuleLifecycleChange>,
    /// Health change, if any.
    pub health_change: Option<ModuleHealthChange>,
    /// Selected backend change, if any.
    pub backend_change: Option<ModuleBackendChange>,
    /// Streams active only in the later snapshot.
    pub activated_streams: Vec<DottedId>,
    /// Streams active only in the earlier snapshot.
    pub deactivated_streams: Vec<DottedId>,
    /// Commands active only in the later snapshot.
    pub activated_commands: Vec<DottedId>,
    /// Commands active only in the earlier snapshot.
    pub deactivated_commands: Vec<DottedId>,
    /// Issues present only in the later snapshot.
    pub added_issues: Vec<ManifoldIssue>,
    /// Issues present only in the earlier snapshot.
    pub resolved_issues: Vec<ManifoldIssue>,
}

/// Lifecycle field change.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModuleLifecycleChange {
    /// Earlier lifecycle.
    pub from: ModuleLifecycleState,
    /// Later lifecycle.
    pub to: ModuleLifecycleState,
}

/// Health field change.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModuleHealthChange {
    /// Earlier health.
    pub from: HealthLevel,
    /// Later health.
    pub to: HealthLevel,
}

/// Selected backend field change.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModuleBackendChange {
    /// Earlier selected backend.
    pub from: Option<DottedId>,
    /// Later selected backend.
    pub to: Option<DottedId>,
}

/// Stream descriptor.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamManifest {
    /// Schema identifier for this manifest.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable stream id.
    pub stream_id: DottedId,
    /// Module that provides the stream.
    pub source_module_id: DottedId,
    /// Semantic stream family.
    pub semantic_family: DottedId,
    /// Schema id for samples on the stream.
    pub sample_schema: SchemaId,
    /// Stream rate class.
    pub rate_class: StreamRateClass,
    /// Timestamp domains carried by stream events.
    pub timestamp_domains: Vec<DottedId>,
    /// Retention policy.
    pub retention: RetentionPolicyDescriptor,
    /// Sensitivity label.
    pub sensitivity: SensitivityLevel,
    /// Transport offers available for this stream.
    pub transport_offers: Vec<TransportOffer>,
    /// Subscription policy.
    pub subscription: SubscriptionPolicy,
}

/// Registry snapshot at one topology revision.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamRegistrySnapshot {
    /// Schema identifier for this snapshot.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Accepted registry revision.
    pub registry_revision: Revision,
    /// Streams visible at this revision.
    pub streams: Vec<ManifoldStreamManifest>,
}

impl ManifoldStreamRegistrySnapshot {
    /// Validates that every stream points to a known source module id.
    ///
    /// # Errors
    ///
    /// Returns [`StreamRegistryValidationError`] when a stream references an
    /// unknown source module.
    pub fn validate_source_modules(
        &self,
        module_ids: &[DottedId],
    ) -> Result<(), StreamRegistryValidationError> {
        for stream in &self.streams {
            if !module_ids
                .iter()
                .any(|module_id| module_id == &stream.source_module_id)
            {
                return Err(StreamRegistryValidationError {
                    stream_id: stream.stream_id.clone(),
                    source_module_id: stream.source_module_id.clone(),
                    kind: StreamRegistryValidationErrorKind::UnknownModuleLink,
                });
            }
        }

        Ok(())
    }

    /// Returns a stream-registry diff from an earlier snapshot to this snapshot.
    ///
    /// # Panics
    ///
    /// Panics only if the built-in stream-registry-diff schema id literal is invalid.
    #[must_use]
    pub fn diff_from(&self, previous: &Self) -> ManifoldStreamRegistryDiff {
        ManifoldStreamRegistryDiff {
            schema_id: SchemaId::new("rusty.manifold.stream.registry_diff.v1")
                .expect("schema literal is valid"),
            from_revision: previous.registry_revision,
            to_revision: self.registry_revision,
            added_streams: added_by_key(&self.streams, &previous.streams, |stream| {
                &stream.stream_id
            }),
            removed_streams: added_by_key(&previous.streams, &self.streams, |stream| {
                &stream.stream_id
            }),
            changed_streams: changed_streams(previous, self),
        }
    }
}

/// Stream-registry diff between two registry revisions.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamRegistryDiff {
    /// Schema identifier for this diff.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Earlier registry revision.
    pub from_revision: Revision,
    /// Later registry revision.
    pub to_revision: Revision,
    /// Streams present only in the later snapshot.
    pub added_streams: Vec<ManifoldStreamManifest>,
    /// Streams present only in the earlier snapshot.
    pub removed_streams: Vec<ManifoldStreamManifest>,
    /// Streams with the same id but changed metadata.
    pub changed_streams: Vec<ManifoldStreamChange>,
}

/// Changed stream descriptor.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamChange {
    /// Stable stream id.
    pub stream_id: DottedId,
    /// Earlier stream descriptor.
    pub before: ManifoldStreamManifest,
    /// Later stream descriptor.
    pub after: ManifoldStreamManifest,
}

/// Mutating command descriptor.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldCommandDescriptor {
    /// Schema identifier for this descriptor.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable command id.
    pub command_id: DottedId,
    /// Target scope for the command.
    pub target_scope: DottedId,
    /// Input schema id.
    pub input_schema: SchemaId,
    /// Required capability.
    pub required_capability: DottedId,
    /// Required lease scope, if this command is exclusive.
    pub required_lease_scope: Option<DottedId>,
    /// Safety class.
    pub safety_class: SafetyClass,
    /// Whether operator confirmation is required.
    pub operator_confirmation_required: bool,
}

/// Command request envelope sent to Manifold authority.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldCommandEnvelope {
    /// Schema identifier for this envelope.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Request id.
    pub request_id: DottedId,
    /// Command id.
    pub command_id: DottedId,
    /// Target id.
    pub target_id: DottedId,
    /// Target scope.
    pub target_scope: DottedId,
    /// Input schema id.
    pub input_schema: SchemaId,
    /// Expected authority revision.
    pub expected_revision: Option<Revision>,
    /// Capability presented with the request.
    pub required_capability: DottedId,
    /// Lease id presented with the request.
    pub lease_id: Option<DottedId>,
    /// Preconditions declared by the client.
    pub preconditions: Vec<CommandPrecondition>,
    /// Safety class.
    pub safety_class: SafetyClass,
    /// Request timestamp in milliseconds in the holder's chosen clock domain.
    pub requested_at_ms: u64,
    /// Holder id.
    pub holder_id: DottedId,
}

impl ManifoldCommandEnvelope {
    /// Validates the envelope against a descriptor, current revision, and optional lease.
    ///
    /// # Errors
    ///
    /// Returns [`CommandValidationError`] when the envelope does not match the
    /// descriptor, revision, required capability, or required lease.
    pub fn validate_request(
        &self,
        descriptor: &ManifoldCommandDescriptor,
        current_revision: Revision,
        active_lease: Option<&ManifoldControlLease>,
    ) -> Result<(), CommandValidationError> {
        if self.command_id != descriptor.command_id {
            return Err(CommandValidationError::new(
                CommandValidationErrorKind::CommandMismatch,
                "command id does not match descriptor",
            ));
        }

        if self.target_scope != descriptor.target_scope {
            return Err(CommandValidationError::new(
                CommandValidationErrorKind::TargetScopeMismatch,
                "target scope does not match descriptor",
            ));
        }

        if self.required_capability != descriptor.required_capability {
            return Err(CommandValidationError::new(
                CommandValidationErrorKind::CapabilityMismatch,
                "required capability does not match descriptor",
            ));
        }

        if let Some(expected_revision) = self.expected_revision {
            if expected_revision != current_revision {
                return Err(CommandValidationError::new(
                    CommandValidationErrorKind::StaleRevision,
                    "expected revision does not match current revision",
                ));
            }
        }

        if let Some(required_scope) = &descriptor.required_lease_scope {
            let lease = active_lease.ok_or_else(|| {
                CommandValidationError::new(
                    CommandValidationErrorKind::MissingLease,
                    "command requires an active lease",
                )
            })?;

            if lease.state != LeaseState::Active {
                return Err(CommandValidationError::new(
                    CommandValidationErrorKind::InactiveLease,
                    "lease is not active",
                ));
            }

            if lease.scope != *required_scope {
                return Err(CommandValidationError::new(
                    CommandValidationErrorKind::LeaseScopeMismatch,
                    "lease scope does not match command scope",
                ));
            }

            if self.lease_id.as_ref() != Some(&lease.lease_id) {
                return Err(CommandValidationError::new(
                    CommandValidationErrorKind::LeaseIdMismatch,
                    "envelope lease id does not match active lease",
                ));
            }

            if lease.holder_id != self.holder_id {
                return Err(CommandValidationError::new(
                    CommandValidationErrorKind::LeaseHolderMismatch,
                    "lease holder does not match request holder",
                ));
            }

            if lease.granted_revision != current_revision {
                return Err(CommandValidationError::new(
                    CommandValidationErrorKind::LeaseRevisionMismatch,
                    "lease revision does not match current revision",
                ));
            }
        }

        Ok(())
    }
}

/// Accepted command result.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldCommandAck {
    /// Schema identifier for this acknowledgement.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Request id being acknowledged.
    pub request_id: DottedId,
    /// Revision accepted by authority.
    pub accepted_revision: Revision,
    /// Lease used for acceptance, if any.
    pub lease_id: Option<DottedId>,
    /// Authority id.
    pub authority_id: DottedId,
    /// Acceptance timestamp in milliseconds.
    pub accepted_at_ms: u64,
}

/// Rejected command result.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldCommandRejection {
    /// Schema identifier for this rejection.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Request id being rejected.
    pub request_id: DottedId,
    /// Machine-readable rejection code.
    pub rejection_code: DottedId,
    /// Display-safe explanation.
    pub message: String,
    /// Whether retry is safe without operator intervention.
    pub retryable: bool,
    /// Current authority revision, when applicable.
    pub current_revision: Option<Revision>,
}

/// Lease request descriptor used by tests and fixtures.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldControlLeaseRequest {
    /// Schema identifier for this request.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Request id.
    pub request_id: DottedId,
    /// Holder id.
    pub holder_id: DottedId,
    /// Requested lease scope.
    pub scope: DottedId,
    /// Expected authority revision.
    pub expected_revision: Revision,
    /// Requested time-to-live in milliseconds.
    pub requested_ttl_ms: u64,
    /// Capability required for the lease.
    pub required_capability: DottedId,
    /// Safety class for the lease request.
    pub safety_class: SafetyClass,
}

/// Accepted control lease.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldControlLease {
    /// Schema identifier for this lease.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Lease id.
    pub lease_id: DottedId,
    /// Holder id.
    pub holder_id: DottedId,
    /// Lease scope.
    pub scope: DottedId,
    /// Lease state.
    pub state: LeaseState,
    /// Authority revision at which the lease was granted.
    pub granted_revision: Revision,
    /// Expiration timestamp in milliseconds.
    pub expires_at_ms: u64,
    /// Capability used to grant the lease.
    pub required_capability: DottedId,
}

/// Host advertisement manifest.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldHostManifest {
    /// Schema identifier for this manifest.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Host id.
    pub host_id: DottedId,
    /// Authority role advertised by this host.
    pub authority_role: AuthorityRole,
    /// Generic host category, when advertised.
    #[cfg_attr(feature = "serde", serde(default))]
    pub host_category: Option<DottedId>,
    /// Host clock domain.
    pub clock_domain: DottedId,
    /// Advertised endpoints.
    pub endpoints: Vec<EndpointDescriptor>,
    /// Advertised capabilities.
    pub capabilities: Vec<DottedId>,
    /// Supported backend families.
    #[cfg_attr(feature = "serde", serde(default))]
    pub supported_backends: Vec<DottedId>,
    /// Permissions or operator grants available to this host.
    #[cfg_attr(feature = "serde", serde(default))]
    pub permissions: Vec<DottedId>,
    /// Lifecycle limits that deployment selection must account for.
    #[cfg_attr(feature = "serde", serde(default))]
    pub lifecycle_limits: Vec<DottedId>,
    /// Missing requirements that prevent selected modules or backends.
    #[cfg_attr(feature = "serde", serde(default))]
    pub missing_requirements: Vec<DottedId>,
}

impl ManifoldHostManifest {
    /// Validates endpoint visibility and security pairings.
    ///
    /// # Errors
    ///
    /// Returns [`EndpointSecurityError`] when any endpoint advertises a
    /// visibility/security pairing that is not accepted by Manifold policy.
    pub fn validate_endpoint_security(&self) -> Result<(), EndpointSecurityError> {
        for endpoint in &self.endpoints {
            endpoint.validate_security()?;
        }

        Ok(())
    }
}

/// Deployment placement manifest.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldDeploymentManifest {
    /// Schema identifier for this manifest.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Deployment id.
    pub deployment_id: DottedId,
    /// Target host id.
    pub target_host_id: DottedId,
    /// Selected package id.
    pub package_id: DottedId,
    /// Selected module ids.
    pub selected_modules: Vec<DottedId>,
    /// Selected backend for each module, if pinned by the deployment.
    #[cfg_attr(feature = "serde", serde(default))]
    pub selected_backends: Vec<SelectedModuleBackend>,
    /// Selected endpoint id.
    pub endpoint_id: DottedId,
    /// Security policy id.
    pub security_policy: DottedId,
    /// Artifact policy id.
    pub artifact_policy: DottedId,
    /// Session output policy id.
    pub session_output_policy: DottedId,
}

impl ManifoldDeploymentManifest {
    /// Computes the host/module availability snapshot for this deployment.
    ///
    /// # Errors
    ///
    /// Returns [`DeploymentSelectionError`] when the deployment points at the
    /// wrong host/package, an unknown endpoint, or an unknown selected module.
    ///
    /// # Panics
    ///
    /// Panics only if the built-in deployment-selection schema id literal is invalid.
    pub fn selection_snapshot(
        &self,
        package: &ManifoldPackageManifest,
        modules: &[ManifoldModuleManifest],
        host: &ManifoldHostManifest,
    ) -> Result<ManifoldDeploymentSelectionSnapshot, DeploymentSelectionError> {
        if self.target_host_id != host.host_id {
            return Err(DeploymentSelectionError::new(
                self.deployment_id.clone(),
                self.target_host_id.clone(),
                DeploymentSelectionErrorKind::HostMismatch,
            ));
        }

        if self.package_id != package.package_id {
            return Err(DeploymentSelectionError::new(
                self.deployment_id.clone(),
                self.package_id.clone(),
                DeploymentSelectionErrorKind::PackageMismatch,
            ));
        }

        if !host
            .endpoints
            .iter()
            .any(|endpoint| endpoint.endpoint_id == self.endpoint_id)
        {
            return Err(DeploymentSelectionError::new(
                self.deployment_id.clone(),
                self.endpoint_id.clone(),
                DeploymentSelectionErrorKind::UnknownEndpoint,
            ));
        }

        let mut module_availability = Vec::new();
        for module_id in &self.selected_modules {
            let Some(module) = modules.iter().find(|module| module.module_id == *module_id) else {
                return Err(DeploymentSelectionError::new(
                    self.deployment_id.clone(),
                    module_id.clone(),
                    DeploymentSelectionErrorKind::UnknownModule,
                ));
            };

            if !package
                .exports
                .modules
                .iter()
                .any(|exported| exported == module_id)
            {
                return Err(DeploymentSelectionError::new(
                    self.deployment_id.clone(),
                    module_id.clone(),
                    DeploymentSelectionErrorKind::UnknownModule,
                ));
            }

            module_availability.push(self.module_availability(module, host));
        }

        let status = if module_availability
            .iter()
            .all(|module| module.status == ModuleAvailabilityStatus::Available)
        {
            ValidationStatus::Pass
        } else {
            ValidationStatus::Fail
        };

        Ok(ManifoldDeploymentSelectionSnapshot {
            schema_id: SchemaId::new("rusty.manifold.deployment.selection_snapshot.v1")
                .expect("schema literal is valid"),
            deployment_id: self.deployment_id.clone(),
            host_id: host.host_id.clone(),
            package_id: package.package_id.clone(),
            status,
            modules: module_availability,
        })
    }

    /// Validates that all selected modules are currently available on the host.
    ///
    /// # Errors
    ///
    /// Returns [`DeploymentSelectionError`] when deployment selection is invalid
    /// or at least one selected module cannot run on the host.
    pub fn validate_selection(
        &self,
        package: &ManifoldPackageManifest,
        modules: &[ManifoldModuleManifest],
        host: &ManifoldHostManifest,
    ) -> Result<ManifoldDeploymentSelectionSnapshot, DeploymentSelectionError> {
        let snapshot = self.selection_snapshot(package, modules, host)?;
        if let Some(module) = snapshot
            .modules
            .iter()
            .find(|module| module.status == ModuleAvailabilityStatus::Unavailable)
        {
            let kind = if !module.missing_capabilities.is_empty() {
                DeploymentSelectionErrorKind::MissingCapability
            } else if !module.missing_backends.is_empty() {
                DeploymentSelectionErrorKind::MissingBackend
            } else {
                DeploymentSelectionErrorKind::MissingRequirement
            };
            return Err(DeploymentSelectionError::new(
                self.deployment_id.clone(),
                module.module_id.clone(),
                kind,
            ));
        }

        Ok(snapshot)
    }

    fn module_availability(
        &self,
        module: &ManifoldModuleManifest,
        host: &ManifoldHostManifest,
    ) -> ManifoldModuleAvailability {
        let selected_backend = self.selected_backend(module, host);
        let missing_capabilities = added_ids(&module.required_capabilities, &host.capabilities);
        let missing_backends = match &selected_backend {
            Some(backend)
                if host.supported_backends.iter().any(|item| item == backend)
                    && module.platform_support.iter().any(|item| item == backend) =>
            {
                Vec::new()
            }
            Some(backend) => vec![backend.clone()],
            None => module.platform_support.clone(),
        };
        let missing_requirements = module
            .required_capabilities
            .iter()
            .chain(selected_backend.iter())
            .filter(|requirement| {
                host.missing_requirements
                    .iter()
                    .any(|item| item == *requirement)
            })
            .cloned()
            .collect::<Vec<_>>();
        let available = missing_capabilities.is_empty()
            && missing_backends.is_empty()
            && missing_requirements.is_empty();

        ManifoldModuleAvailability {
            module_id: module.module_id.clone(),
            status: if available {
                ModuleAvailabilityStatus::Available
            } else {
                ModuleAvailabilityStatus::Unavailable
            },
            selected_backend,
            missing_capabilities,
            missing_backends,
            missing_requirements,
        }
    }

    fn selected_backend(
        &self,
        module: &ManifoldModuleManifest,
        host: &ManifoldHostManifest,
    ) -> Option<DottedId> {
        if let Some(selection) = self
            .selected_backends
            .iter()
            .find(|selection| selection.module_id == module.module_id)
        {
            return Some(selection.backend_id.clone());
        }

        module
            .platform_support
            .iter()
            .find(|backend| host.supported_backends.iter().any(|item| item == *backend))
            .cloned()
    }
}

/// Selected backend binding for one deployed module.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedModuleBackend {
    /// Selected module id.
    pub module_id: DottedId,
    /// Backend selected for the module.
    pub backend_id: DottedId,
}

/// Snapshot answering which selected modules can run on a host now.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldDeploymentSelectionSnapshot {
    /// Schema identifier for this snapshot.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Deployment being evaluated.
    pub deployment_id: DottedId,
    /// Host being evaluated.
    pub host_id: DottedId,
    /// Package being evaluated.
    pub package_id: DottedId,
    /// Overall selection status.
    pub status: ValidationStatus,
    /// Per-module availability rows.
    pub modules: Vec<ManifoldModuleAvailability>,
}

/// Availability row for a selected module.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldModuleAvailability {
    /// Selected module id.
    pub module_id: DottedId,
    /// Module availability status.
    pub status: ModuleAvailabilityStatus,
    /// Backend selected or inferred for this module.
    pub selected_backend: Option<DottedId>,
    /// Required capabilities absent from the host manifest.
    pub missing_capabilities: Vec<DottedId>,
    /// Required or selected backends absent from the host manifest.
    pub missing_backends: Vec<DottedId>,
    /// Requirements the host explicitly reports as missing.
    pub missing_requirements: Vec<DottedId>,
}

/// Clock snapshot at one read.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldClockSnapshot {
    /// Schema identifier for this snapshot.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Clock domain id.
    pub clock_domain: DottedId,
    /// Clock epoch id.
    pub clock_epoch_id: DottedId,
    /// Monotonic sequence number.
    pub sequence: u64,
    /// Monotonic elapsed nanoseconds.
    pub monotonic_elapsed_ns: u64,
    /// Wall Unix time in milliseconds for export labels.
    pub wall_unix_ms: i64,
    /// Read uncertainty in nanoseconds.
    pub read_uncertainty_ns: u64,
    /// Clock health.
    pub health: ClockHealth,
    /// Number of wall-clock adjustments observed by this epoch.
    pub wall_clock_adjustment_count: u64,
}

/// Validation scorecard for one local validation slot.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldValidationScorecard {
    /// Schema identifier for this scorecard.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Scorecard id.
    pub scorecard_id: DottedId,
    /// Target id being validated.
    pub target_id: DottedId,
    /// Target revision, when the target is revisioned.
    pub target_revision: Option<Revision>,
    /// Overall status.
    pub status: ValidationStatus,
    /// Individual checks.
    pub checks: Vec<ValidationCheck>,
    /// Issues found during validation.
    pub issues: Vec<ManifoldIssue>,
}

/// Install, launch, and command-bridge profile consumed by host shells.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldHostRunInstallLaunchProfile {
    /// Schema identifier for this profile.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable profile id.
    pub profile_id: DottedId,
    /// Target host profile, such as desktop, mobile, or headset.
    pub host_profile: DottedId,
    /// Host shell app id.
    pub app_id: DottedId,
    /// How the app is installed or updated.
    pub install_route: DottedId,
    /// How the app is launched.
    pub launch_route: DottedId,
    /// How commands are delivered.
    pub command_bridge: DottedId,
    /// Required permissions or grants for this profile.
    pub required_permissions: Vec<DottedId>,
    /// How evidence is pulled or exported.
    pub evidence_pull_route: DottedId,
}

/// Named validation slot that a host shell can execute.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldHostRunValidationSlot {
    /// Schema identifier for this slot.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable validation slot id.
    pub slot_id: DottedId,
    /// Validation slot kind.
    pub slot_kind: HostRunValidationSlotKind,
    /// Package ids required by this slot.
    pub required_packages: Vec<DottedId>,
    /// Stream ids expected from this slot.
    pub expected_streams: Vec<DottedId>,
    /// Command ids this slot may issue.
    pub command_ids: Vec<DottedId>,
    /// Scorecard id expected from this slot.
    pub expected_scorecard_id: DottedId,
    /// Safety class for running this slot.
    pub safety_class: SafetyClass,
}

/// Bundle of manifests, fixtures, and slot selection for one host run.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldHostRunBundle {
    /// Schema identifier for this bundle.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable bundle id.
    pub bundle_id: DottedId,
    /// Bundle revision.
    pub bundle_revision: Revision,
    /// Target host profile.
    pub target_host_profile: DottedId,
    /// Validation slot selected for the run.
    pub validation_slot_id: DottedId,
    /// Package catalog id or digest id.
    pub package_catalog_id: DottedId,
    /// Package ids included in the bundle.
    pub package_ids: Vec<DottedId>,
    /// Deployment ids included in the bundle.
    pub deployment_ids: Vec<DottedId>,
    /// Graph ids included in the bundle.
    pub graph_ids: Vec<DottedId>,
    /// Evidence policy id.
    pub evidence_policy: DottedId,
}

/// Host-shell command wrapper carrying a Manifold command envelope.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldHostRunCommandEnvelope {
    /// Schema identifier for this envelope.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Host-shell command request id.
    pub host_run_request_id: DottedId,
    /// Target host shell app id.
    pub target_app_id: DottedId,
    /// Target host profile.
    pub target_host_profile: DottedId,
    /// Run bundle id.
    pub bundle_id: DottedId,
    /// Validation slot id.
    pub validation_slot_id: DottedId,
    /// Manifold command envelope to validate and route.
    pub manifold_command: ManifoldCommandEnvelope,
}

/// Evidence manifest produced after one host-shell run.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldHostRunEvidence {
    /// Schema identifier for this evidence document.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable run id.
    pub run_id: DottedId,
    /// Bundle used for the run.
    pub bundle_id: DottedId,
    /// Validation slot executed.
    pub validation_slot_id: DottedId,
    /// Host profile that produced this evidence.
    pub host_profile: DottedId,
    /// Host shell app id.
    pub app_id: DottedId,
    /// Package ids observed during the run.
    pub package_ids: Vec<DottedId>,
    /// Overall status.
    pub status: ValidationStatus,
    /// Start timestamp in milliseconds.
    pub started_at_ms: u64,
    /// End timestamp in milliseconds.
    pub ended_at_ms: u64,
    /// Evidence artifact ids or relative paths.
    pub evidence_artifacts: Vec<DottedId>,
    /// Final scorecard for this run.
    pub scorecard: ManifoldValidationScorecard,
}

/// Endpoint descriptor.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointDescriptor {
    /// Endpoint id.
    pub endpoint_id: DottedId,
    /// Endpoint visibility.
    pub visibility: EndpointVisibility,
    /// Transport kind.
    pub transport: EndpointTransport,
    /// Security mechanism.
    pub security: EndpointSecurity,
}

impl EndpointDescriptor {
    /// Validates that visibility and security are paired safely.
    ///
    /// # Errors
    ///
    /// Returns [`EndpointSecurityError`] when this endpoint advertises a
    /// visibility/security pairing that is not accepted by Manifold policy.
    pub fn validate_security(&self) -> Result<(), EndpointSecurityError> {
        let valid = match self.visibility {
            EndpointVisibility::Loopback => {
                matches!(
                    self.security,
                    EndpointSecurity::LocalProcess | EndpointSecurity::PairingToken
                )
            }
            EndpointVisibility::PairedLan => {
                matches!(
                    self.security,
                    EndpointSecurity::PairingToken | EndpointSecurity::MutualAuth
                )
            }
            EndpointVisibility::PublicRelay => {
                matches!(
                    self.security,
                    EndpointSecurity::MutualAuth | EndpointSecurity::ExternalPolicy
                )
            }
        };

        if valid {
            Ok(())
        } else {
            Err(EndpointSecurityError {
                endpoint_id: self.endpoint_id.clone(),
                visibility: self.visibility,
                security: self.security,
            })
        }
    }
}

/// Clock policy for module outputs.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClockPolicy {
    /// Source timestamp domain.
    pub source_domain: DottedId,
    /// Whether a correlation window is required before use.
    pub correlation_required: bool,
}

/// Retention policy descriptor.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetentionPolicyDescriptor {
    /// Retention policy.
    pub policy: RetentionPolicy,
}

/// A stream transport offer.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportOffer {
    /// Transport id.
    pub transport_id: DottedId,
    /// Transport kind.
    pub transport: EndpointTransport,
    /// Endpoint id, if the offer is endpoint-bound.
    pub endpoint_id: Option<DottedId>,
}

/// Stream subscription policy.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubscriptionPolicy {
    /// Whether UI or dashboard clients may subscribe directly.
    pub ui_subscribable: bool,
    /// Maximum subscribers, if bounded.
    pub max_subscribers: Option<u32>,
}

/// Command precondition.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandPrecondition {
    /// Precondition kind.
    pub kind: DottedId,
    /// Expected value encoded as a small display-safe string.
    pub expected_value: String,
}

/// Structured issue.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldIssue {
    /// Machine-readable issue code.
    pub issue_code: DottedId,
    /// Issue severity.
    pub severity: IssueSeverity,
    /// Display-safe message.
    pub message: String,
}

/// One validation check row.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidationCheck {
    /// Check id.
    pub check_id: DottedId,
    /// Check status.
    pub status: ValidationStatus,
    /// Compact evidence summary.
    pub evidence: String,
    /// Issue codes associated with this row.
    pub issue_codes: Vec<DottedId>,
}

/// Module class.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModuleKind {
    /// Produces source streams or metadata.
    Provider,
    /// Consumes streams and produces derived streams.
    Processor,
    /// Records, exports, or forwards selected streams.
    Sink,
    /// Maps Manifold surfaces to an external protocol.
    Bridge,
    /// Exposes bounded command/control integrations.
    ControlAdapter,
    /// Reports health, timing, validation, or evidence.
    Diagnostic,
    /// Watches lifecycle, recovery, or policy state.
    Supervisor,
}

/// Module lifecycle.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModuleLifecycleState {
    /// Declared but not yet available.
    Declared,
    /// Available for selection.
    Available,
    /// Starting.
    Starting,
    /// Running.
    Running,
    /// Running with degraded behavior.
    Degraded,
    /// Stopping.
    Stopping,
    /// Stopped.
    Stopped,
    /// Failed.
    Failed,
}

/// Health level.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HealthLevel {
    /// Health is unknown.
    Unknown,
    /// Healthy.
    Healthy,
    /// Degraded but usable.
    Degraded,
    /// Unhealthy.
    Unhealthy,
}

/// Stream rate class.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamRateClass {
    /// Event-driven stream.
    Event,
    /// Periodic stream.
    Periodic,
    /// Burst stream.
    Burst,
    /// On-demand stream.
    OnDemand,
}

/// Retention policy.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetentionPolicy {
    /// Retained only while live.
    Ephemeral,
    /// Retained for a session.
    Session,
    /// Persisted by an owning sink or host.
    Persisted,
    /// Stored elsewhere and referenced.
    ExternalReference,
}

/// Sensitivity label.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SensitivityLevel {
    /// Synthetic or generated data.
    Synthetic,
    /// Public data.
    Public,
    /// Internal data.
    Internal,
    /// Sensitive data.
    Sensitive,
}

/// Command safety class.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SafetyClass {
    /// Read-only command.
    ReadOnly,
    /// Bounded mutation guarded by revisions and leases.
    BoundedMutation,
    /// Requires an explicit operator confirmation.
    OperatorConfirmed,
}

/// Control lease state.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeaseState {
    /// Requested but not granted.
    Requested,
    /// Active.
    Active,
    /// Released.
    Released,
    /// Expired.
    Expired,
    /// Rejected.
    Rejected,
}

/// Host authority role.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityRole {
    /// No authority role.
    None,
    /// Read-only observer.
    Observer,
    /// Secondary authority candidate.
    Secondary,
    /// Primary authority.
    Primary,
}

/// Endpoint visibility class.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointVisibility {
    /// Loopback-only endpoint.
    Loopback,
    /// Paired local network endpoint.
    PairedLan,
    /// Externally managed relay endpoint.
    PublicRelay,
}

/// Endpoint transport kind.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointTransport {
    /// In-process call path.
    InProcess,
    /// Standard input/output.
    Stdio,
    /// HTTP endpoint.
    Http,
}

/// Endpoint security mechanism.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointSecurity {
    /// No security mechanism.
    None,
    /// Local process boundary only.
    LocalProcess,
    /// Pairing token required.
    PairingToken,
    /// Mutual authentication required.
    MutualAuth,
    /// External relay or security policy owns access.
    ExternalPolicy,
}

/// Clock health.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockHealth {
    /// Healthy.
    Healthy,
    /// Degraded.
    Degraded,
    /// Unavailable.
    Unavailable,
}

/// Validation status.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationStatus {
    /// Passed.
    Pass,
    /// Passed with warnings.
    Warn,
    /// Failed.
    Fail,
}

/// Module availability status for deployment selection.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModuleAvailabilityStatus {
    /// The selected module can run on the host now.
    Available,
    /// The selected module is declared but cannot run on the host now.
    Unavailable,
}

/// Host-shell validation slot class.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostRunValidationSlotKind {
    /// App installed, launchable, writable, and command bridge alive.
    HostReadiness,
    /// Package catalog loads and schema versions match.
    PackageCatalogReadiness,
    /// Synthetic package graph runs without device APIs.
    SyntheticPackageRun,
    /// Replay fixtures drive the same streams and processors.
    ReplayPackageRun,
    /// Platform permissions and capabilities are observed.
    PlatformCapabilityProbe,
    /// One bounded live adapter route.
    LiveSmoke,
    /// Explicit release/acquire run for a single-owner resource.
    HandoffSmoke,
}

/// Issue severity.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IssueSeverity {
    /// Informational.
    Info,
    /// Warning.
    Warning,
    /// Error.
    Error,
}

/// Endpoint security validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointSecurityError {
    endpoint_id: DottedId,
    visibility: EndpointVisibility,
    security: EndpointSecurity,
}

impl EndpointSecurityError {
    /// Returns the affected endpoint id.
    #[must_use]
    pub fn endpoint_id(&self) -> &DottedId {
        &self.endpoint_id
    }

    /// Returns the machine-readable rejection code.
    #[must_use]
    pub fn rejection_code(&self) -> &'static str {
        "endpoint_security_mismatch"
    }

    /// Returns the endpoint visibility.
    #[must_use]
    pub const fn visibility(&self) -> EndpointVisibility {
        self.visibility
    }

    /// Returns the endpoint security mechanism.
    #[must_use]
    pub const fn security(&self) -> EndpointSecurity {
        self.security
    }
}

impl fmt::Display for EndpointSecurityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "endpoint {} has incompatible visibility {:?} and security {:?}",
            self.endpoint_id, self.visibility, self.security
        )
    }
}

impl std::error::Error for EndpointSecurityError {}

/// Graph validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraphValidationError {
    graph_id: DottedId,
    link_id: DottedId,
    kind: GraphValidationErrorKind,
}

impl GraphValidationError {
    /// Returns the affected graph id.
    #[must_use]
    pub fn graph_id(&self) -> &DottedId {
        &self.graph_id
    }

    /// Returns the missing or invalid link id.
    #[must_use]
    pub fn link_id(&self) -> &DottedId {
        &self.link_id
    }

    /// Returns the failure kind.
    #[must_use]
    pub const fn kind(&self) -> GraphValidationErrorKind {
        self.kind
    }

    /// Returns a stable rejection code.
    #[must_use]
    pub const fn rejection_code(&self) -> &'static str {
        match self.kind {
            GraphValidationErrorKind::UnknownModuleLink => "unknown_module_link",
            GraphValidationErrorKind::UnknownNodeLink => "unknown_node_link",
        }
    }
}

impl fmt::Display for GraphValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "graph {} contains invalid link {}: {:?}",
            self.graph_id, self.link_id, self.kind
        )
    }
}

impl std::error::Error for GraphValidationError {}

/// Graph validation failure kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GraphValidationErrorKind {
    /// A node references an unknown module.
    UnknownModuleLink,
    /// An edge references an unknown node.
    UnknownNodeLink,
}

/// Stream registry validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamRegistryValidationError {
    stream_id: DottedId,
    source_module_id: DottedId,
    kind: StreamRegistryValidationErrorKind,
}

impl StreamRegistryValidationError {
    /// Returns the affected stream id.
    #[must_use]
    pub fn stream_id(&self) -> &DottedId {
        &self.stream_id
    }

    /// Returns the missing or invalid source module id.
    #[must_use]
    pub fn source_module_id(&self) -> &DottedId {
        &self.source_module_id
    }

    /// Returns the failure kind.
    #[must_use]
    pub const fn kind(&self) -> StreamRegistryValidationErrorKind {
        self.kind
    }

    /// Returns a stable rejection code.
    #[must_use]
    pub const fn rejection_code(&self) -> &'static str {
        match self.kind {
            StreamRegistryValidationErrorKind::UnknownModuleLink => "unknown_module_link",
        }
    }
}

impl fmt::Display for StreamRegistryValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "stream {} references unknown source module {}",
            self.stream_id, self.source_module_id
        )
    }
}

impl std::error::Error for StreamRegistryValidationError {}

/// Stream registry validation failure kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamRegistryValidationErrorKind {
    /// A stream references a source module that is not known to the registry.
    UnknownModuleLink,
}

/// Deployment selection validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeploymentSelectionError {
    deployment_id: DottedId,
    rejected_id: DottedId,
    kind: DeploymentSelectionErrorKind,
}

impl DeploymentSelectionError {
    fn new(
        deployment_id: DottedId,
        rejected_id: DottedId,
        kind: DeploymentSelectionErrorKind,
    ) -> Self {
        Self {
            deployment_id,
            rejected_id,
            kind,
        }
    }

    /// Returns the affected deployment id.
    #[must_use]
    pub fn deployment_id(&self) -> &DottedId {
        &self.deployment_id
    }

    /// Returns the rejected id.
    #[must_use]
    pub fn rejected_id(&self) -> &DottedId {
        &self.rejected_id
    }

    /// Returns the failure kind.
    #[must_use]
    pub const fn kind(&self) -> DeploymentSelectionErrorKind {
        self.kind
    }

    /// Returns a stable rejection code.
    #[must_use]
    pub const fn rejection_code(&self) -> &'static str {
        match self.kind {
            DeploymentSelectionErrorKind::HostMismatch => "host_mismatch",
            DeploymentSelectionErrorKind::PackageMismatch => "package_mismatch",
            DeploymentSelectionErrorKind::UnknownEndpoint => "unknown_endpoint",
            DeploymentSelectionErrorKind::UnknownModule => "unknown_module",
            DeploymentSelectionErrorKind::MissingCapability => "missing_capability",
            DeploymentSelectionErrorKind::MissingBackend => "missing_backend",
            DeploymentSelectionErrorKind::MissingRequirement => "missing_requirement",
        }
    }
}

impl fmt::Display for DeploymentSelectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "deployment {} rejected {}: {:?}",
            self.deployment_id, self.rejected_id, self.kind
        )
    }
}

impl std::error::Error for DeploymentSelectionError {}

/// Deployment selection validation failure kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeploymentSelectionErrorKind {
    /// Deployment targets a different host.
    HostMismatch,
    /// Deployment targets a different package.
    PackageMismatch,
    /// Deployment selects an endpoint not advertised by the host.
    UnknownEndpoint,
    /// Deployment selects a module not exported by the package.
    UnknownModule,
    /// Host lacks a capability required by the selected module.
    MissingCapability,
    /// Host lacks a backend required by the selected module.
    MissingBackend,
    /// Host explicitly reports a required item as missing.
    MissingRequirement,
}

/// Command request validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandValidationError {
    kind: CommandValidationErrorKind,
    message: &'static str,
}

impl CommandValidationError {
    fn new(kind: CommandValidationErrorKind, message: &'static str) -> Self {
        Self { kind, message }
    }

    /// Returns the failure kind.
    #[must_use]
    pub const fn kind(&self) -> CommandValidationErrorKind {
        self.kind
    }

    /// Returns the display-safe message.
    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }

    /// Returns a stable rejection code.
    #[must_use]
    pub const fn rejection_code(&self) -> &'static str {
        match self.kind {
            CommandValidationErrorKind::CommandMismatch => "command_mismatch",
            CommandValidationErrorKind::TargetScopeMismatch => "target_scope_mismatch",
            CommandValidationErrorKind::CapabilityMismatch => "capability_mismatch",
            CommandValidationErrorKind::StaleRevision => "stale_revision",
            CommandValidationErrorKind::MissingLease => "missing_lease",
            CommandValidationErrorKind::InactiveLease => "inactive_lease",
            CommandValidationErrorKind::LeaseScopeMismatch => "lease_scope_mismatch",
            CommandValidationErrorKind::LeaseIdMismatch => "lease_id_mismatch",
            CommandValidationErrorKind::LeaseHolderMismatch => "lease_holder_mismatch",
            CommandValidationErrorKind::LeaseRevisionMismatch => "lease_revision_mismatch",
        }
    }
}

impl fmt::Display for CommandValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for CommandValidationError {}

/// Command validation failure kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandValidationErrorKind {
    /// Command id does not match the descriptor.
    CommandMismatch,
    /// Target scope does not match the descriptor.
    TargetScopeMismatch,
    /// Capability does not match the descriptor.
    CapabilityMismatch,
    /// Expected revision is stale.
    StaleRevision,
    /// A required lease is missing.
    MissingLease,
    /// The lease is not active.
    InactiveLease,
    /// The lease scope does not match.
    LeaseScopeMismatch,
    /// The lease id does not match.
    LeaseIdMismatch,
    /// The lease holder does not match.
    LeaseHolderMismatch,
    /// The lease revision does not match.
    LeaseRevisionMismatch,
}

fn added_ids(current: &[DottedId], previous: &[DottedId]) -> Vec<DottedId> {
    added_by_key(current, previous, |id| id)
}

fn added_by_key<T, F>(current: &[T], previous: &[T], key: F) -> Vec<T>
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

fn changed_graph_nodes(
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

fn changed_graph_edges(
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

fn changed_streams(
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

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: &str) -> DottedId {
        DottedId::new(value).unwrap()
    }

    fn schema(value: &str) -> SchemaId {
        SchemaId::new(value).unwrap()
    }

    fn command_descriptor() -> ManifoldCommandDescriptor {
        ManifoldCommandDescriptor {
            schema_id: schema("rusty.manifold.command.descriptor.v1"),
            command_id: id("command.module.start"),
            target_scope: id("module.synthetic_wave_provider"),
            input_schema: schema("rusty.manifold.command.input.empty.v1"),
            required_capability: id("manifold.module.control"),
            required_lease_scope: Some(id("module.synthetic_wave_provider")),
            safety_class: SafetyClass::BoundedMutation,
            operator_confirmation_required: false,
        }
    }

    fn command_envelope() -> ManifoldCommandEnvelope {
        ManifoldCommandEnvelope {
            schema_id: schema("rusty.manifold.command.envelope.v1"),
            request_id: id("request.start.synthetic_wave"),
            command_id: id("command.module.start"),
            target_id: id("module.synthetic_wave_provider"),
            target_scope: id("module.synthetic_wave_provider"),
            input_schema: schema("rusty.manifold.command.input.empty.v1"),
            expected_revision: Some(Revision::INITIAL),
            required_capability: id("manifold.module.control"),
            lease_id: Some(id("lease.synthetic_module")),
            preconditions: Vec::new(),
            safety_class: SafetyClass::BoundedMutation,
            requested_at_ms: 1_765_000_000_000,
            holder_id: id("holder.test_agent"),
        }
    }

    fn active_lease() -> ManifoldControlLease {
        ManifoldControlLease {
            schema_id: schema("rusty.manifold.command.control_lease.v1"),
            lease_id: id("lease.synthetic_module"),
            holder_id: id("holder.test_agent"),
            scope: id("module.synthetic_wave_provider"),
            state: LeaseState::Active,
            granted_revision: Revision::INITIAL,
            expires_at_ms: 1_765_000_030_000,
            required_capability: id("manifold.module.control"),
        }
    }

    #[test]
    fn command_envelope_accepts_matching_descriptor_revision_and_lease() {
        let result = command_envelope().validate_request(
            &command_descriptor(),
            Revision::INITIAL,
            Some(&active_lease()),
        );

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn command_envelope_rejects_stale_revision() {
        let current_revision = Revision::new(2).unwrap();
        let error = command_envelope()
            .validate_request(
                &command_descriptor(),
                current_revision,
                Some(&active_lease()),
            )
            .unwrap_err();

        assert_eq!(error.kind(), CommandValidationErrorKind::StaleRevision);
        assert_eq!(error.rejection_code(), "stale_revision");
    }

    #[test]
    fn command_envelope_rejects_missing_required_lease() {
        let error = command_envelope()
            .validate_request(&command_descriptor(), Revision::INITIAL, None)
            .unwrap_err();

        assert_eq!(error.kind(), CommandValidationErrorKind::MissingLease);
        assert_eq!(error.rejection_code(), "missing_lease");
    }

    #[test]
    fn host_endpoint_security_rejects_public_relay_without_policy() {
        let endpoint = EndpointDescriptor {
            endpoint_id: id("endpoint.public_without_policy"),
            visibility: EndpointVisibility::PublicRelay,
            transport: EndpointTransport::Http,
            security: EndpointSecurity::None,
        };

        let error = endpoint.validate_security().unwrap_err();
        assert_eq!(error.rejection_code(), "endpoint_security_mismatch");
    }

    #[test]
    fn graph_manifest_rejects_unknown_module_link() {
        let manifest = ManifoldGraphManifest {
            schema_id: schema("rusty.manifold.graph.manifest.v1"),
            graph_id: id("graph.synthetic_wave_pipeline"),
            graph_revision: Revision::INITIAL,
            nodes: vec![ManifoldGraphNode {
                node_id: id("node.unknown"),
                module_id: id("module.not_registered"),
            }],
            edges: Vec::new(),
            required_capabilities: vec![id("manifold.graph.run")],
        };

        let error = manifest
            .validate_links(&[id("module.synthetic_wave_provider")])
            .unwrap_err();

        assert_eq!(error.rejection_code(), "unknown_module_link");
    }

    #[test]
    fn stream_registry_rejects_unknown_source_module() {
        let snapshot = ManifoldStreamRegistrySnapshot {
            schema_id: schema("rusty.manifold.stream.registry_snapshot.v1"),
            registry_revision: Revision::INITIAL,
            streams: vec![ManifoldStreamManifest {
                schema_id: schema("rusty.manifold.stream.manifest.v1"),
                stream_id: id("stream.orphaned"),
                source_module_id: id("module.not_registered"),
                semantic_family: id("synthetic.scalar"),
                sample_schema: schema("rusty.manifold.sample.scalar_f32.v1"),
                rate_class: StreamRateClass::Periodic,
                timestamp_domains: vec![id("clock.host_monotonic")],
                retention: RetentionPolicyDescriptor {
                    policy: RetentionPolicy::Ephemeral,
                },
                sensitivity: SensitivityLevel::Synthetic,
                transport_offers: Vec::new(),
                subscription: SubscriptionPolicy {
                    ui_subscribable: false,
                    max_subscribers: None,
                },
            }],
        };

        let error = snapshot
            .validate_source_modules(&[id("module.synthetic_wave_provider")])
            .unwrap_err();

        assert_eq!(error.rejection_code(), "unknown_module_link");
    }

    #[test]
    fn module_manifest_can_describe_synthetic_provider() {
        let manifest = ManifoldModuleManifest {
            schema_id: schema("rusty.manifold.module.manifest.v1"),
            module_id: id("module.synthetic_wave_provider"),
            module_kind: ModuleKind::Provider,
            label: "Synthetic Wave Provider".to_owned(),
            version: "0.1.0".to_owned(),
            lifecycle_states: vec![
                ModuleLifecycleState::Available,
                ModuleLifecycleState::Running,
                ModuleLifecycleState::Stopped,
            ],
            provides_streams: vec![id("stream.synthetic_wave")],
            consumes_streams: Vec::new(),
            accepted_commands: vec![id("command.module.start")],
            required_capabilities: vec![id("manifold.module.control")],
            clock_policy: ClockPolicy {
                source_domain: id("clock.host_monotonic"),
                correlation_required: false,
            },
            retention: RetentionPolicyDescriptor {
                policy: RetentionPolicy::Ephemeral,
            },
            sensitivity: SensitivityLevel::Synthetic,
            platform_support: vec![id("backend.synthetic")],
            issue_codes: vec![id("issue.synthetic_stopped")],
        };

        assert_eq!(manifest.module_kind, ModuleKind::Provider);
        assert_eq!(
            manifest.provides_streams[0].as_str(),
            "stream.synthetic_wave"
        );
    }
}

#[cfg(all(test, feature = "serde"))]
mod serde_fixture_tests {
    use super::*;
    use serde::de::DeserializeOwned;

    fn fixture<T: DeserializeOwned>(json: &str) -> T {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn valid_fixtures_deserialize_into_contract_models() {
        fixture::<ManifoldPackageManifest>(include_str!(
            "../../../fixtures/package/synthetic-package.json"
        ));
        fixture::<ManifoldGraphManifest>(include_str!(
            "../../../fixtures/graph/synthetic-wave-pipeline.json"
        ));
        fixture::<ManifoldGraphExecutionReport>(include_str!(
            "../../../fixtures/graph/synthetic-graph-execution-report.json"
        ));
        fixture::<ManifoldModuleManifest>(include_str!(
            "../../../fixtures/module/synthetic-wave-provider.json"
        ));
        fixture::<ManifoldModuleManifest>(include_str!(
            "../../../fixtures/module/synthetic-wave-processor.json"
        ));
        fixture::<ManifoldModuleRuntimeState>(include_str!(
            "../../../fixtures/module/synthetic-wave-runtime-state.json"
        ));
        fixture::<ManifoldModuleRuntimeState>(include_str!(
            "../../../fixtures/module/synthetic-processor-runtime-state.json"
        ));
        fixture::<ManifoldStreamManifest>(include_str!(
            "../../../fixtures/stream/synthetic-wave-stream.json"
        ));
        fixture::<ManifoldStreamManifest>(include_str!(
            "../../../fixtures/stream/synthetic-rms-stream.json"
        ));
        fixture::<ManifoldStreamRegistrySnapshot>(include_str!(
            "../../../fixtures/stream/synthetic-stream-registry.json"
        ));
        fixture::<ManifoldCommandDescriptor>(include_str!(
            "../../../fixtures/command/synthetic-command-descriptor.json"
        ));
        fixture::<ManifoldCommandEnvelope>(include_str!(
            "../../../fixtures/command/synthetic-command-envelope.json"
        ));
        fixture::<ManifoldCommandAck>(include_str!(
            "../../../fixtures/command/synthetic-command-ack.json"
        ));
        fixture::<ManifoldCommandRejection>(include_str!(
            "../../../fixtures/command/synthetic-command-rejection.json"
        ));
        fixture::<ManifoldControlLeaseRequest>(include_str!(
            "../../../fixtures/command/synthetic-lease-request.json"
        ));
        fixture::<ManifoldControlLease>(include_str!(
            "../../../fixtures/command/synthetic-control-lease.json"
        ));
        fixture::<ManifoldHostManifest>(include_str!("../../../fixtures/host/synthetic-host.json"));
        fixture::<ManifoldHostManifest>(include_str!("../../../fixtures/host/desktop-local.json"));
        fixture::<ManifoldHostManifest>(include_str!("../../../fixtures/host/mobile-device.json"));
        fixture::<ManifoldHostManifest>(include_str!("../../../fixtures/host/headset-device.json"));
        fixture::<ManifoldDeploymentManifest>(include_str!(
            "../../../fixtures/deployment/synthetic-deployment.json"
        ));
        fixture::<ManifoldClockSnapshot>(include_str!(
            "../../../fixtures/clock/synthetic-clock-snapshot.json"
        ));
        fixture::<ManifoldValidationScorecard>(include_str!(
            "../../../fixtures/validation/synthetic-scorecard.json"
        ));
        fixture::<ManifoldHostRunInstallLaunchProfile>(include_str!(
            "../../../fixtures/host-run/install-profile-desktop.json"
        ));
        fixture::<ManifoldHostRunInstallLaunchProfile>(include_str!(
            "../../../fixtures/host-run/install-profile-mobile.json"
        ));
        fixture::<ManifoldHostRunInstallLaunchProfile>(include_str!(
            "../../../fixtures/host-run/install-profile-headset.json"
        ));
        fixture::<ManifoldHostRunValidationSlot>(include_str!(
            "../../../fixtures/host-run/slot-live-smoke.json"
        ));
        fixture::<ManifoldHostRunBundle>(include_str!(
            "../../../fixtures/host-run/run-bundle-live-smoke.json"
        ));
        fixture::<ManifoldHostRunCommandEnvelope>(include_str!(
            "../../../fixtures/host-run/command-envelope-run-live.json"
        ));
        fixture::<ManifoldHostRunEvidence>(include_str!(
            "../../../fixtures/host-run/run-evidence-live-smoke.json"
        ));
    }

    #[test]
    fn damaged_endpoint_security_fixture_has_expected_rejection() {
        let manifest = fixture::<ManifoldHostManifest>(include_str!(
            "../../../fixtures/damaged/invalid-endpoint-security.json"
        ));
        let error = manifest.validate_endpoint_security().unwrap_err();

        assert_eq!(error.rejection_code(), "endpoint_security_mismatch");
    }

    #[test]
    fn damaged_stale_revision_fixture_rejects_against_current_revision() {
        let descriptor = fixture::<ManifoldCommandDescriptor>(include_str!(
            "../../../fixtures/command/synthetic-command-descriptor.json"
        ));
        let envelope = fixture::<ManifoldCommandEnvelope>(include_str!(
            "../../../fixtures/damaged/stale-revision-command.json"
        ));
        let lease = fixture::<ManifoldControlLease>(include_str!(
            "../../../fixtures/command/synthetic-control-lease.json"
        ));
        let current_revision = Revision::new(2).unwrap();
        let error = envelope
            .validate_request(&descriptor, current_revision, Some(&lease))
            .unwrap_err();

        assert_eq!(error.rejection_code(), "stale_revision");
    }

    #[test]
    fn damaged_missing_lease_fixture_rejects_required_lease() {
        let descriptor = fixture::<ManifoldCommandDescriptor>(include_str!(
            "../../../fixtures/command/synthetic-command-descriptor.json"
        ));
        let envelope = fixture::<ManifoldCommandEnvelope>(include_str!(
            "../../../fixtures/damaged/missing-lease-scope-command.json"
        ));
        let error = envelope
            .validate_request(&descriptor, Revision::INITIAL, None)
            .unwrap_err();

        assert_eq!(error.rejection_code(), "missing_lease");
    }

    #[test]
    fn damaged_bad_timestamp_domain_fixture_rejects_invalid_id() {
        let result = serde_json::from_str::<ManifoldStreamManifest>(include_str!(
            "../../../fixtures/damaged/bad-timestamp-domain.json"
        ));

        assert!(result.is_err());
    }

    #[test]
    fn damaged_unknown_module_link_fixture_rejects_registry_topology() {
        let snapshot = fixture::<ManifoldStreamRegistrySnapshot>(include_str!(
            "../../../fixtures/damaged/unknown-module-link.json"
        ));
        let error = snapshot
            .validate_source_modules(&[DottedId::new("module.synthetic_wave_provider").unwrap()])
            .unwrap_err();

        assert_eq!(error.rejection_code(), "unknown_module_link");
    }
}
